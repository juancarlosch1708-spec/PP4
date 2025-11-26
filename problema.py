# problema_mongo.py
import os
import io
import csv
import uuid
import base64
import re
import sys
from datetime import datetime, date
from collections import Counter

from flask import (
    Flask, render_template, request, redirect, url_for, send_file,
    flash, abort, jsonify
)
from werkzeug.utils import secure_filename

# MongoDB
from pymongo import MongoClient
from pymongo.server_api import ServerApi
from pymongo import errors
from bson.objectid import ObjectId

# Cryptography
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

# PDF extractor
from PyPDF2 import PdfReader

# -----------------------
# CONFIGURACIÓN GENERAL
# -----------------------
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_DIR = os.path.join(BASE_DIR, "curriculums")
KEYS_DIR = os.path.join(BASE_DIR, "keys")
PRIVATE_KEY_PATH = os.path.join(KEYS_DIR, "private_key.pem")
PUBLIC_KEY_PATH = os.path.join(KEYS_DIR, "public_key.pem")
SECRET_KEY_PATH = os.path.join(BASE_DIR, "secret_key.txt")
ALLOWED_EXTENSIONS = {"pdf"}
MAX_CONTENT_LENGTH = 10 * 1024 * 1024  # 10 MB máx

os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(KEYS_DIR, exist_ok=True)

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH
app.config['UPLOAD_FOLDER'] = UPLOAD_DIR

# SECRET_KEY (para flash y forms)
def ensure_secret_key():
    if not os.path.exists(SECRET_KEY_PATH):
        with open(SECRET_KEY_PATH, "w") as f:
            f.write(base64.urlsafe_b64encode(os.urandom(32)).decode())
    with open(SECRET_KEY_PATH, "r") as f:
        app.config['SECRET_KEY'] = f.read().strip()

ensure_secret_key()

# ------------------------
# CONEXIÓN A MONGO
# ------------------------
MONGO_URI = os.environ.get("MONGO_URI") or os.environ.get("MONGODB_URI") or "mongodb://localhost:27017"

try:
    if MONGO_URI.startswith("mongodb+srv://"):
        client = MongoClient(MONGO_URI, server_api=ServerApi('1'), serverSelectionTimeoutMS=5000)
    else:
        client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)

    client.admin.command('ping')
    print("✅ Conexión a MongoDB exitosa.", file=sys.stderr)

except errors.ConfigurationError as e:
    print(f"❌ ERROR CRÍTICO DE CONFIGURACIÓN DE MONGO: {e}", file=sys.stderr)
    print("Asegúrate de que la variable MONGO_URI (o MONGODB_URI) sea correcta y que la red esté permitida.", file=sys.stderr)
    sys.exit(1)
except Exception as e:
    print(f"❌ ERROR CRÍTICO DE CONEXIÓN DE MONGO: {e}", file=sys.stderr)
    sys.exit(1)

db = client["reclutamiento_db"]
ofertas_col = db["ofertas"]
postulantes_col = db["postulantes"]

# ------------------------
# CLAVES Y CIFRADO
# ------------------------
def ensure_keys():
    """Genera claves RSA si no existen."""
    if not (os.path.exists(PRIVATE_KEY_PATH) and os.path.exists(PUBLIC_KEY_PATH)):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        with open(PRIVATE_KEY_PATH, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        public_key = private_key.public_key()
        with open(PUBLIC_KEY_PATH, "wb") as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

def load_public_key():
    with open(PUBLIC_KEY_PATH, "rb") as f:
        return serialization.load_pem_public_key(f.read(), backend=default_backend())

def load_private_key():
    with open(PRIVATE_KEY_PATH, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())

def base64_b64encode_str(b: bytes) -> str:
    return base64.b64encode(b).decode("utf-8")

def base64_b64decode_bytes(s: str) -> bytes:
    return base64.b64decode(s.encode("utf-8"))

def hybrid_encrypt_text(plaintext: str):
    """Cifra texto combinando Fernet (simétrico) y RSA (asimétrico)."""
    fkey = Fernet.generate_key()
    f = Fernet(fkey)
    ct = f.encrypt(plaintext.encode("utf-8"))
    public_key = load_public_key()
    key_ct = public_key.encrypt(
        fkey,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    return {"ciphertext_b64": base64_b64encode_str(ct), "key_encrypted_b64": base64_b64encode_str(key_ct)}

def rsa_encrypt_string(plaintext: str) -> str:
    """Cifra un string corto usando RSA directamente."""
    public_key = load_public_key()
    ct = public_key.encrypt(
        plaintext.encode("utf-8"),
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    return base64_b64encode_str(ct)

def rsa_decrypt_string(b64_cipher: str) -> str:
    """Descifra un string RSA (útil para pruebas locales)."""
    priv = load_private_key()
    ct = base64_b64decode_bytes(b64_cipher)
    pt = priv.decrypt(
        ct,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    return pt.decode("utf-8")

# ------------------------
# EXTRACCIÓN DE TEXTO Y UTILIDADES
# ------------------------
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def extract_text_from_pdf(path):
    """Extrae texto del PDF para cifrarlo junto con los datos."""
    try:
        reader = PdfReader(path)
        text = ""
        for page in reader.pages:
            text += page.extract_text() or ""
        return text.strip()
    except Exception:
        return ""

def calculate_age(born: date) -> int:
    today = date.today()
    return today.year - born.year - ((today.month, today.day) < (born.month, born.day))

# ------------------------
# LOGICA DETERMINISTICA DE "RNA" GUIADA POR PALABRAS CLAVE
# ------------------------
STOPWORDS = {
    "de","la","el","y","en","a","los","las","con","para","por","un","una","es","se","su",
    "que","al","del","como","los","las","empleo","puesto","experiencia"
}

def extract_keywords(text, min_len=4):
    """Extrae keywords simples desde un texto (sin librerías externas). Determinístico."""
    text = re.sub(r"[^\w\s]", " ", text.lower())
    tokens = [t for t in text.split() if len(t) >= min_len and t not in STOPWORDS and not t.isnumeric()]
    counts = Counter(tokens)
    keywords = [w for w, c in counts.most_common(20)]
    return keywords

def get_neural_network_match_score(oferta_title: str, oferta_desc: str, resumen: str, cv_text: str) -> int:
    """
    Función determinista que calcula un score (0-100) basado en la presencia de palabras clave
    extraídas de la oferta (título + descripción). No usa random.
    """
    source = f"{oferta_title} {oferta_desc}"
    keywords = extract_keywords(source)
    if not keywords:
        keywords = ["python", "javascript", "sql", "java", "aws", "docker", "flask", "django"]

    resumen_l = (resumen or "").lower()
    cv_l = (cv_text or "").lower()
    score_raw = 0.0
    max_possible = 0.0

    for kw in keywords:
        max_possible += 1.0
        count_cv = cv_l.count(kw)
        count_res = resumen_l.count(kw)
        contrib = min(3, count_cv) * 0.7 + min(2, count_res) * 0.3
        score_raw += contrib / 3.0

    if max_possible <= 0:
        normalized = 0.0
    else:
        normalized = (score_raw / (max_possible * ( (0.7*3 + 0.3*2) / 3.0 ))) * 100.0

    length_bonus = min(10, max(0, len(resumen_l) // 100))
    final_score = int(max(0, min(100, round(normalized) + length_bonus)))

    return final_score

# ------------------------
# FUNCIONES AUXILIARES (BORRADO SEGURO)
# ------------------------
def _delete_offer_and_postulants_by_id_string(oferta_id_str: str):
    """
    Elimina oferta + postulantes asociados. Maneja casos donde oferta_id fue guardado
    como ObjectId o como string.
    """
    # Primero intentamos interpretar como ObjectId
    oferta = None
    oid = None
    try:
        oid = ObjectId(oferta_id_str)
        oferta = ofertas_col.find_one({"_id": oid})
    except Exception:
        oid = None

    if not oferta:
        # intentamos buscar por string en _id o por campo 'oferta_id' (si guardaste como string)
        oferta = ofertas_col.find_one({"_id": oferta_id_str}) or ofertas_col.find_one({"titulo": {"$regex": re.escape(oferta_id_str), "$options": "i"}})

    if not oferta:
        return False, "Oferta no encontrada"

    oferta_real_id = oferta.get("_id")
    # Buscar postulantes asociados (buscar por campo oferta_id que puede ser string u ObjectId)
    postulantes = list(postulantes_col.find({"$or": [{"oferta_id": str(oferta_real_id)}, {"oferta_id": oferta_id_str}, {"oferta_id": oferta_real_id}] }))

    # Eliminar archivos físicos
    for p in postulantes:
        filename = p.get("curriculum_stored_name")
        if filename:
            file_path = os.path.join(UPLOAD_DIR, filename)
            if os.path.exists(file_path):
                try:
                    os.remove(file_path)
                except OSError as e:
                    app.logger.warning(f"No se pudo eliminar {file_path}: {e}")

    # Eliminar registros
    postulantes_col.delete_many({"$or": [{"oferta_id": str(oferta_real_id)}, {"oferta_id": oferta_id_str}, {"oferta_id": oferta_real_id}] })
    ofertas_col.delete_one({"_id": oferta_real_id})

    return True, None

# ------------------------
# RUTAS (CON TRAILING SLASH)
# ------------------------
@app.route("/")
def index():
    return render_template("index.html", title="Inicio | ReclutaJusto")

@app.route("/ofertas/")
def listar_ofertas():
    ofertas_cursor = ofertas_col.find().sort("_created", -1)
    ofertas = []
    for o in ofertas_cursor:
        o["_id_str"] = str(o["_id"])
        ofertas.append(o)
    return render_template("ofertas.html", ofertas=ofertas, title="Ofertas Disponibles")

@app.route("/crear_oferta/", methods=["GET", "POST"])
def crear_oferta():
    if request.method == "POST":
        titulo = request.form.get("titulo", "").strip()
        descripcion = request.form.get("descripcion", "").strip()
        empresa = request.form.get("empresa", "").strip()
        if not titulo or not descripcion or not empresa:
            flash("Por favor completa todos los campos", "danger")
            return redirect(url_for("crear_oferta"))

        nueva = {
            "titulo": titulo,
            "descripcion": descripcion,
            "empresa": empresa,
            "_created": datetime.utcnow()
        }
        ofertas_col.insert_one(nueva)
        flash("Oferta creada correctamente", "success")
        return redirect(url_for("listar_ofertas"))

    return render_template("crear_oferta.html", title="Crear Oferta")

# RUTA de BORRADO que acepta POST sin id en la URL (fallback para formularios mal formados)
@app.route("/eliminar_oferta/", methods=["POST"])
def eliminar_oferta_sin_id():
    # Buscamos oferta_id en form/data/json
    oferta_id = request.form.get("oferta_id") or request.form.get("id")
    if not oferta_id:
        # Si no lo encontramos, intentamos extraer JSON
        try:
            data = request.get_json(silent=True) or {}
            oferta_id = data.get("oferta_id") or data.get("id")
        except Exception:
            oferta_id = None

    if not oferta_id:
        flash("No se especificó la oferta a eliminar.", "warning")
        return redirect(url_for("listar_ofertas"))

    ok, err = _delete_offer_and_postulants_by_id_string(oferta_id)
    if not ok:
        flash(f"No se pudo eliminar la oferta: {err}", "danger")
    else:
        flash("Oferta y sus postulantes eliminados", "success")
    return redirect(url_for("listar_ofertas"))

# RUTA original (con id en la URL)
@app.route("/eliminar_oferta/<oferta_id>", methods=["POST"])
def eliminar_oferta(oferta_id):
    ok, err = _delete_offer_and_postulants_by_id_string(oferta_id)
    if not ok:
        abort(404)
    flash("Oferta y sus postulantes eliminados", "success")
    return redirect(url_for("listar_ofertas"))

# RUTA DE CAPTURA: /postular/ (sin id) para evitar 404 en render/frontend
@app.route("/postular/")
def postular_sin_id():
    flash("No se especificó una oferta para postular.", "warning")
    return redirect(url_for("listar_ofertas"))

@app.route("/postular/<oferta_id>/", methods=["GET", "POST"])
def postular(oferta_id):
    # Lógica para manejar IDs tipo ObjectId o string
    try:
        oid = ObjectId(oferta_id)
        oferta = ofertas_col.find_one({"_id": oid})
    except Exception:
        oferta = ofertas_col.find_one({"_id": oferta_id})

    if not oferta:
        abort(404)

    if request.method == "POST":
        nombre = request.form.get("nombre", "").strip()
        correo = request.form.get("correo", "").strip()
        resumen = request.form.get("resumen", "").strip()
        fecha_nac_str = request.form.get("fecha_nacimiento", "").strip()
        file = request.files.get("curriculum")

        if not nombre or not correo or not fecha_nac_str or not file:
            flash("Faltan campos obligatorios", "danger")
            return redirect(url_for("postular", oferta_id=oferta_id))

        try:
            fecha_nac = datetime.strptime(fecha_nac_str, "%Y-%m-%d").date()
        except ValueError:
            flash("Formato de fecha incorrecto", "danger")
            return redirect(url_for("postular", oferta_id=oferta_id))

        if calculate_age(fecha_nac) < 18:
            flash("Debes ser mayor de edad para postular", "danger")
            return redirect(url_for("postular", oferta_id=oferta_id))

        if not allowed_file(file.filename):
            flash("Solo se permite archivo PDF", "danger")
            return redirect(url_for("postular", oferta_id=oferta_id))

        orig_filename = secure_filename(file.filename)
        unique_name = f"{uuid.uuid4().hex}.pdf"
        save_path = os.path.join(UPLOAD_DIR, unique_name)
        file.save(save_path)

        extracted_text = extract_text_from_pdf(save_path)

        titulo = oferta.get("titulo", "")
        descripcion = oferta.get("descripcion", "")
        match_score = get_neural_network_match_score(titulo, descripcion, resumen, extracted_text)

        ensure_keys()
        hybrid = hybrid_encrypt_text(extracted_text or "Sin texto extraído")
        filename_enc = rsa_encrypt_string(orig_filename)
        nombre_enc = rsa_encrypt_string(nombre)
        correo_enc = rsa_encrypt_string(correo)
        resumen_enc = rsa_encrypt_string(resumen or "")

        nuevo = {
            "nombre_enc": nombre_enc,
            "correo_enc": correo_enc,
            "resumen_enc": resumen_enc,
            "fecha_nacimiento": fecha_nac.isoformat(),
            "curriculum_stored_name": unique_name,
            "curriculum_filename_enc": filename_enc,
            "curriculum_ciphertext_b64": hybrid["ciphertext_b64"],
            "curriculum_key_encrypted_b64": hybrid["key_encrypted_b64"],
            "match_score": match_score,
            "oferta_id": oferta_id,
            "_created": datetime.utcnow()
        }
        postulantes_col.insert_one(nuevo)
        flash("Postulación enviada correctamente", "success")
        return redirect(url_for("listar_ofertas"))

    return render_template("postular.html", oferta=oferta, title=f"Postular a {oferta.get('titulo', '')}")

# RUTA DE CAPTURA: /postulantes/ (sin id) para evitar 404 en render/frontend
@app.route("/postulantes/")
def ver_postulantes_sin_id():
    flash("No se especificó una oferta para ver postulantes.", "warning")
    return redirect(url_for("listar_ofertas"))

@app.route("/postulantes/<oferta_id>/")
def ver_postulantes(oferta_id):
    try:
        oid = ObjectId(oferta_id)
        oferta = ofertas_col.find_one({"_id": oid})
    except Exception:
        oferta = ofertas_col.find_one({"_id": oferta_id})

    if not oferta:
        abort(404)

    postulantes_cursor = postulantes_col.find({"oferta_id": oferta_id}).sort("_created", -1)
    postulantes = []
    for p in postulantes_cursor:
        p["_id_str"] = str(p["_id"])
        postulantes.append(p)
    return render_template("postulantes.html", oferta=oferta, postulantes=postulantes, title="Postulantes")

@app.route("/descargar_cv/<filename>")
def descargar_cv(filename):
    if ".." in filename or filename.startswith("/"):
        abort(400)
    file_path = os.path.join(UPLOAD_DIR, filename)
    if not os.path.exists(file_path):
        abort(404)
    return send_file(file_path, as_attachment=True, download_name=filename)

@app.route("/exportar_csv_con_datos_cifrados/<oferta_id>")
def exportar_csv_con_datos_cifrados(oferta_id):
    try:
        oid = ObjectId(oferta_id)
        oferta = ofertas_col.find_one({"_id": oid})
    except Exception:
        oferta = ofertas_col.find_one({"_id": oferta_id})

    if not oferta:
        abort(404)

    postulantes = list(postulantes_col.find({"oferta_id": oferta_id}))

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "id_postulante", "nombre_enc_b64", "correo_enc_b64", "resumen_enc_b64",
        "fecha_nacimiento", "curriculum_filename_enc_b64",
        "curriculum_ciphertext_b64", "curriculum_key_encrypted_b64",
        "match_score"
    ])

    for p in postulantes:
        writer.writerow([
            str(p.get("_id")),
            p.get("nombre_enc"),
            p.get("correo_enc"),
            p.get("resumen_enc"),
            p.get("fecha_nacimiento"),
            p.get("curriculum_filename_enc"),
            p.get("curriculum_ciphertext_b64"),
            p.get("curriculum_key_encrypted_b64"),
            p.get("match_score")
        ])

    csv_data = output.getvalue().encode("utf-8")
    filename_base = re.sub(r'[^a-zA-Z0-9_-]', '_', oferta.get("titulo", "oferta"))
    download_name = f"postulantes_{filename_base}_cifrados.csv"

    return send_file(
        io.BytesIO(csv_data),
        mimetype="text/csv",
        as_attachment=True,
        download_name=download_name
    )

# ------------------------
# INICIALIZACIÓN GLOBAL
# ------------------------
ensure_keys()
try:
    ofertas_col.create_index("titulo")
    postulantes_col.create_index("oferta_id")
except Exception as e:
    print(f"Advertencia: No se pudieron crear los índices de MongoDB. Error: {e}", file=sys.stderr)

# ------------------------
# MODO LOCAL
# ------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)

