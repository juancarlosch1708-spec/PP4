# problema_mongo.py
import os
import io
import uuid
import base64
import re
import sys
import logging
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
from bson.objectid import ObjectId

# Cryptography
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

# PDF extractor
from PyPDF2 import PdfReader

# -----------------------------------------------------
# CONFIGURACIÓN GENERAL
# -----------------------------------------------------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_DIR = os.path.join(BASE_DIR, "curriculums")
KEYS_DIR = os.path.join(BASE_DIR, "keys")
PRIVATE_KEY_PATH = os.path.join(KEYS_DIR, "private_key.pem")
PUBLIC_KEY_PATH = os.path.join(KEYS_DIR, "public_key.pem")
SECRET_KEY_PATH = os.path.join(BASE_DIR, "secret_key.txt")
ALLOWED_EXTENSIONS = {"pdf"}
MAX_CONTENT_LENGTH = 10 * 1024 * 1024  # 10MB

os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(KEYS_DIR, exist_ok=True)
os.makedirs(os.path.join(BASE_DIR, "templates"), exist_ok=True)  # no hace daño

app = Flask(__name__)
app.url_map.strict_slashes = False

app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH
app.config['UPLOAD_FOLDER'] = UPLOAD_DIR

# SECRET KEY
def ensure_secret_key():
    if not os.path.exists(SECRET_KEY_PATH):
        with open(SECRET_KEY_PATH, "w") as f:
            f.write(base64.urlsafe_b64encode(os.urandom(32)).decode())
    with open(SECRET_KEY_PATH, "r") as f:
        app.config['SECRET_KEY'] = f.read().strip()

ensure_secret_key()

# -----------------------------------------------------
# MONGO BD
# -----------------------------------------------------
MONGO_URI = os.environ.get("MONGO_URI") or os.environ.get("MONGODB_URI") or "mongodb://localhost:27017"

try:
    if MONGO_URI.startswith("mongodb+srv://"):
        client = MongoClient(MONGO_URI, server_api=ServerApi('1'), serverSelectionTimeoutMS=5000)
    else:
        client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
    client.admin.command('ping')
    logger.info("Conectado a MongoDB correctamente.")
except Exception as e:
    logger.exception("Error conectando a MongoDB: %s", e)
    raise SystemExit("No se pudo conectar a MongoDB. Revisa MONGO_URI y que el servidor esté en ejecución.") from e

db = client["reclutamiento_db"]
ofertas_col = db["ofertas"]
postulantes_col = db["postulantes"]

# -----------------------------------------------------
# CIFRADO
# -----------------------------------------------------
def ensure_keys():
    """
    Crea un par de llaves RSA si no existen.
    """
    if not (os.path.exists(PRIVATE_KEY_PATH) and os.path.exists(PUBLIC_KEY_PATH)):
        logger.info("Generando par de llaves RSA...")
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
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
        logger.info("Llaves RSA generadas.")

def load_public_key():
    if not os.path.exists(PUBLIC_KEY_PATH):
        ensure_keys()
    with open(PUBLIC_KEY_PATH, "rb") as f:
        return serialization.load_pem_public_key(f.read())

def load_private_key():
    if not os.path.exists(PRIVATE_KEY_PATH):
        ensure_keys()
    with open(PRIVATE_KEY_PATH, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def rsa_encrypt_string(s: str) -> str:
    pub = load_public_key()
    ct = pub.encrypt(
        s.encode("utf-8"),
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                     algorithm=hashes.SHA256(),
                     label=None)
    )
    return base64.b64encode(ct).decode()

def rsa_decrypt_string(b64_ct: str) -> str:
    priv = load_private_key()
    try:
        ct = base64.b64decode(b64_ct)
        pt = priv.decrypt(
            ct,
            padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                         algorithm=hashes.SHA256(),
                         label=None)
        )
        return pt.decode("utf-8")
    except Exception as e:
        logger.debug("No se pudo desencriptar (posible texto no cifrado o error): %s", e)
        raise

# -----------------------------------------------------
# UTILIDADES
# -----------------------------------------------------
def allowed_file(filename):
    return bool(filename) and '.' in filename and filename.rsplit(".",1)[1].lower() in ALLOWED_EXTENSIONS

def extract_text_from_pdf(path):
    try:
        reader = PdfReader(path)
        text = []
        for p in reader.pages:
            try:
                page_text = p.extract_text()
            except Exception:
                page_text = ""
            text.append(page_text or "")
        return "".join(text).strip()
    except Exception as e:
        logger.exception("Error extrayendo texto de PDF %s: %s", path, e)
        return ""

def calculate_age(born: date):
    today = datetime.utcnow().date()
    return today.year - born.year - ((today.month, today.day) < (born.month, born.day))

STOPWORDS = {"de","la","el","y","en","a","los","las","con","para","por","un","una","es","se","su","que","al","del"}

def extract_keywords(text, min_len=4):
    text = re.sub(r"[^\w\s]", " ", (text or "").lower())
    tokens = [t for t in text.split() if len(t)>=min_len and t not in STOPWORDS]
    freq = Counter(tokens)
    return [w for w,c in freq.most_common(20)]

def get_neural_network_match_score(t, d, r, cv):
    kws = extract_keywords((t or "")+" "+(d or "")+" "+(r or "")+" "+(cv or "")) or ["python","sql","docker"]
    score=0
    for kw in kws:
        score += (t or "").lower().count(kw) + (d or "").lower().count(kw) + (r or "").lower().count(kw) + (cv or "").lower().count(kw)
    return min(100, score*5)

# -----------------------------------------------------
# BORRAR OFERTA + POSTULANTES
# -----------------------------------------------------
def _delete_offer_and_postulants_by_id_string(oferta_id):
    try:
        postulantes_col.delete_many({"oferta_id": oferta_id})
        ofertas_col.delete_one({"_id": ObjectId(oferta_id)})
        return True, None
    except Exception as e:
        logger.exception("Error al eliminar oferta/postulantes: %s", e)
        return False, str(e)

# -----------------------------------------------------
# RUTAS
# -----------------------------------------------------
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/ofertas/")
def listar_ofertas():
    ofertas = []
    try:
        cursor = ofertas_col.find().sort("_created", -1)
        for o in cursor:
            o["_id_str"] = str(o["_id"])
            ofertas.append(o)
    except Exception as e:
        logger.exception("Error listando ofertas: %s", e)
        flash("Error al listar ofertas.", "danger")
    return render_template("ofertas.html", ofertas=ofertas)

@app.route("/crear_oferta/", methods=["GET","POST"])
def crear_oferta():
    if request.method == "POST":
        titulo = request.form.get("titulo", "").strip()
        descripcion = request.form.get("descripcion", "").strip()
        empresa = request.form.get("empresa", "").strip()

        if not titulo or not descripcion or not empresa:
            flash("Completa todos los campos.", "danger")
            return redirect(url_for("crear_oferta"))

        nueva = {
            "titulo": titulo,
            "descripcion": descripcion,
            "empresa": empresa,
            "_created": datetime.utcnow()
        }
        try:
            ofertas_col.insert_one(nueva)
            flash("Oferta creada", "success")
        except Exception as e:
            logger.exception("Error creando oferta: %s", e)
            flash("No se pudo crear la oferta.", "danger")
        return redirect(url_for("listar_ofertas"))
    return render_template("crear_oferta.html")

@app.route("/eliminar_oferta/<oferta_id>", methods=["POST"])
def eliminar_oferta(oferta_id):
    ok, err = _delete_offer_and_postulants_by_id_string(oferta_id)
    if ok:
        flash("Oferta eliminada", "success")
    else:
        flash(f"Error eliminando oferta: {err}", "danger")
    return redirect(url_for("listar_ofertas"))

# Si alguien llega a /postular/ sin id por GET -> redirigir a listar_ofertas
@app.route("/postular/", methods=["GET", "POST"])
def postular_root():
    """
    Este endpoint acepta POSTs cuando el formulario
    envía a /postular/ (sin id). Espera un campo hidden 'oferta_id'
    para reenviar al endpoint con id, o procesa si se prefiere.
    Si llega por GET redirige a listar_ofertas.
    """
    if request.method == "GET":
        flash("Selecciona una oferta antes de postular.", "warning")
        return redirect(url_for("listar_ofertas"))

    # POST: intentar tomar oferta_id desde form y redirigir al endpoint correcto
    oferta_id = request.form.get("oferta_id") or request.args.get("oferta_id")
    if not oferta_id:
        # no tenemos id: devolver 400/redirect
        flash("No se recibió el identificador de la oferta.", "danger")
        return redirect(url_for("listar_ofertas"))
    # reenviar la petición POST al endpoint con id:
    return redirect(url_for("postular", oferta_id=oferta_id), code=307)
    # code=307 preserva método POST en la redirección para que la ruta
    # /postular/<oferta_id> lo procese como POST.

# -----------------------------------------------------
# POSTULAR
# -----------------------------------------------------
@app.route("/postular/<oferta_id>", methods=["GET","POST"])
def postular(oferta_id):

    try:
        oferta = ofertas_col.find_one({"_id": ObjectId(oferta_id)})
    except Exception as e:
        logger.exception("ID oferta inválido: %s", e)
        oferta = None

    if not oferta:
        abort(404)

    if request.method == "POST":
        nombre = request.form.get("nombre", "").strip()
        correo = request.form.get("correo", "").strip()
        resumen = request.form.get("resumen", "").strip()
        f_nac = request.form.get("fecha_nacimiento", "").strip()
        archivo = request.files.get("curriculum")

        if not nombre or not correo or not resumen or not f_nac:
            flash("Completa todos los campos requeridos.", "danger")
            return redirect(url_for("postular", oferta_id=oferta_id))

        try:
            fecha_nac = datetime.strptime(f_nac, "%Y-%m-%d").date()
        except Exception:
            flash("Formato de fecha inválido. Usa YYYY-MM-DD.", "danger")
            return redirect(url_for("postular", oferta_id=oferta_id))

        if calculate_age(fecha_nac) < 18:
            flash("Debes ser mayor de edad para postular", "danger")
            return redirect(url_for("postular", oferta_id=oferta_id))

        if archivo is None or not archivo.filename:
            flash("Adjunta tu curriculum en formato PDF.", "danger")
            return redirect(url_for("postular", oferta_id=oferta_id))

        if not allowed_file(archivo.filename):
            flash("Solo se permiten archivos PDF.", "danger")
            return redirect(url_for("postular", oferta_id=oferta_id))

        original_filename = secure_filename(archivo.filename)
        unique_name = f"{uuid.uuid4().hex}.pdf"
        path = os.path.join(UPLOAD_DIR, unique_name)
        try:
            archivo.save(path)
        except Exception as e:
            logger.exception("Error guardando archivo: %s", e)
            flash("Error guardando el curriculum.", "danger")
            return redirect(url_for("postular", oferta_id=oferta_id))

        extracted = extract_text_from_pdf(path)
        score = get_neural_network_match_score(
            oferta.get("titulo", ""), oferta.get("descripcion", ""), resumen, extracted
        )

        try:
            ensure_keys()
        except Exception as e:
            logger.exception("Error al asegurar llaves: %s", e)
            flash("Error interno (llaves de cifrado).", "danger")
            return redirect(url_for("postular", oferta_id=oferta_id))

        try:
            nuevo = {
                "nombre_enc": rsa_encrypt_string(nombre),
                "correo_enc": rsa_encrypt_string(correo),
                "resumen_enc": rsa_encrypt_string(resumen),
                "fecha_nacimiento": fecha_nac.isoformat(),
                "curriculum_stored_name": unique_name,
                "curriculum_filename_enc": rsa_encrypt_string(original_filename),
                "match_score": score,
                "oferta_id": oferta_id,
                "_created": datetime.utcnow()
            }

            postulantes_col.insert_one(nuevo)
            flash("Postulación enviada correctamente", "success")
            return redirect(url_for("listar_ofertas"))
        except Exception as e:
            logger.exception("Error insertando postulante: %s", e)
            flash("No se pudo guardar la postulación.", "danger")
            try:
                if os.path.exists(path):
                    os.remove(path)
            except Exception:
                pass
            return redirect(url_for("postular", oferta_id=oferta_id))

    return render_template("postular.html", oferta=oferta)

# -----------------------------------------------------
# LISTA DE POSTULANTES
# -----------------------------------------------------
@app.route("/postulantes/<oferta_id>/")
def ver_postulantes(oferta_id):

    try:
        oferta = ofertas_col.find_one({"_id": ObjectId(oferta_id)})
    except Exception as e:
        logger.exception("ID oferta inválido al ver postulantes: %s", e)
        oferta = None

    if not oferta:
        abort(404)

    postulantes = []
    try:
        cursor = postulantes_col.find({"oferta_id": oferta_id}).sort("_created", -1)
        for p in cursor:
            p["_id_str"] = str(p["_id"])
            postulantes.append(p)
    except Exception as e:
        logger.exception("Error listando postulantes: %s", e)
        flash("Error al obtener postulantes.", "danger")

    return render_template("postulantes.html", oferta=oferta, postulantes=postulantes)

# -----------------------------------------------------
# EXPORTAR CSV (desencripta cuando es posible)
# -----------------------------------------------------
@app.route("/exportar_csv_con_datos_cifrados/<oferta_id>/")
def exportar_csv_con_datos_cifrados(oferta_id):
    try:
        oferta = ofertas_col.find_one({"_id": ObjectId(oferta_id)})
    except Exception as e:
        logger.exception("ID oferta inválido en exportar CSV: %s", e)
        oferta = None

    if not oferta:
        abort(404)

    # construir CSV en memoria
    output = io.StringIO()
    try:
        cursor = postulantes_col.find({"oferta_id": oferta_id}).sort("_created", -1)
        headers = ["nombre", "correo", "resumen", "fecha_nacimiento", "curriculum_stored_name", "match_score", "_created", "_id"]
        import csv
        writer = csv.writer(output)
        writer.writerow(headers)
        for p in cursor:
            def try_decrypt(val):
                if not val:
                    return ""
                try:
                    return rsa_decrypt_string(val)
                except Exception:
                    return val or ""
            nombre = try_decrypt(p.get("nombre_enc"))
            correo = try_decrypt(p.get("correo_enc"))
            resumen = try_decrypt(p.get("resumen_enc"))
            fecha_nac = p.get("fecha_nacimiento", "")
            curriculum_stored = p.get("curriculum_stored_name", "")
            match = p.get("match_score", "")
            created = p.get("_created", "")
            _id = str(p.get("_id", ""))
            writer.writerow([nombre, correo, resumen, fecha_nac, curriculum_stored, match, created, _id])
    except Exception as e:
        logger.exception("Error generando CSV: %s", e)
        flash("Error al generar CSV.", "danger")
        return redirect(url_for("ver_postulantes", oferta_id=oferta_id))

    mem = io.BytesIO()
    mem.write(output.getvalue().encode("utf-8"))
    mem.seek(0)
    filename = f"postulantes_oferta_{oferta_id}.csv"
    return send_file(mem, mimetype="text/csv", as_attachment=True, download_name=filename)

# -----------------------------------------------------
if __name__ == "__main__":
    try:
        ensure_keys()
    except Exception as e:
        logger.exception("Error generando/cargando llaves: %s", e)
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port, debug=True)

