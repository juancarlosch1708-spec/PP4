# problema.py
import os
import io
import csv
import uuid
import base64
import re
import random
from datetime import datetime, date

from flask import (
    Flask, render_template, request, redirect, url_for, send_file,
    flash, abort, jsonify
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename

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
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(BASE_DIR, 'reclutamiento.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
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

db = SQLAlchemy(app)

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

# --- Cifrado híbrido RSA + Fernet ---
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
# INTEGRACIÓN DE RNA / PLN (SIMULADA)
# ------------------------
def get_neural_network_match_score(oferta_desc: str, resumen: str, cv_text: str) -> int:
    """
    Función SIMULADA de Red Neuronal para generar un score de 0 a 100.
    """
    if "python" in cv_text.lower() or "flask" in cv_text.lower() or "django" in cv_text.lower():
        base_score = random.randint(70, 95)
    else:
        base_score = random.randint(30, 65)
    # Pequeña mezcla con longitud del resumen/oferta
    length_bonus = min(10, max(0, len(resumen) // 50))
    return min(100, base_score + length_bonus)

# ------------------------
# MODELOS DE BASE DE DATOS
# ------------------------
class Oferta(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    titulo = db.Column(db.String(120), nullable=False)
    descripcion = db.Column(db.Text, nullable=False)
    empresa = db.Column(db.String(100), nullable=False)
    postulantes = db.relationship('Postulante', backref='oferta', cascade="all, delete-orphan")

class Postulante(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nombre_enc = db.Column(db.Text, nullable=False)
    correo_enc = db.Column(db.Text, nullable=False)
    resumen_enc = db.Column(db.Text, nullable=True)
    fecha_nacimiento = db.Column(db.Date, nullable=False)
    curriculum_stored_name = db.Column(db.String(200), nullable=False)
    curriculum_filename_enc = db.Column(db.Text, nullable=False)
    curriculum_ciphertext_b64 = db.Column(db.Text, nullable=False)
    curriculum_key_encrypted_b64 = db.Column(db.Text, nullable=False)
    match_score = db.Column(db.Integer, nullable=True)
    oferta_id = db.Column(db.Integer, db.ForeignKey('oferta.id'), nullable=False)

# ------------------------
# UTILIDADES
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
# RUTAS
# ------------------------
@app.route("/")
def index():
    return render_template("index.html", title="Inicio | ReclutaJusto")

@app.route("/ofertas")
def listar_ofertas():
    ofertas = Oferta.query.order_by(Oferta.id.desc()).all()
    return render_template("ofertas.html", ofertas=ofertas, title="Ofertas Disponibles")

@app.route("/crear_oferta", methods=["GET", "POST"])
def crear_oferta():
    if request.method == "POST":
        titulo = request.form.get("titulo", "").strip()
        descripcion = request.form.get("descripcion", "").strip()
        empresa = request.form.get("empresa", "").strip()
        if not titulo or not descripcion or not empresa:
            flash("Por favor completa todos los campos", "danger")
            return redirect(url_for("crear_oferta"))

        nueva = Oferta(titulo=titulo, descripcion=descripcion, empresa=empresa)
        db.session.add(nueva)
        db.session.commit()
        flash("Oferta creada correctamente", "success")
        return redirect(url_for("listar_ofertas"))

    return render_template("crear_oferta.html", title="Crear Oferta")

@app.route("/eliminar_oferta/<int:oferta_id>", methods=["POST"])
def eliminar_oferta(oferta_id):
    oferta = Oferta.query.get_or_404(oferta_id)
    files_to_delete = [p.curriculum_stored_name for p in Postulante.query.filter_by(oferta_id=oferta_id).all()]
    db.session.delete(oferta)
    db.session.commit()

    for filename in files_to_delete:
        file_path = os.path.join(UPLOAD_DIR, filename)
        if os.path.exists(file_path):
            try:
                os.remove(file_path)
            except OSError as e:
                app.logger.warning(f"No se pudo eliminar {file_path}: {e}")

    flash("Oferta y sus postulantes eliminados", "success")
    return redirect(url_for("listar_ofertas"))

@app.route("/postular/<int:oferta_id>", methods=["GET", "POST"])
def postular(oferta_id):
    oferta = Oferta.query.get_or_404(oferta_id)

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

        # --- Lógica de la Red Neuronal (simulada) ---
        match_score = get_neural_network_match_score(oferta.descripcion, resumen, extracted_text)

        # --- Cifrado e inserción ---
        ensure_keys()
        hybrid = hybrid_encrypt_text(extracted_text or "Sin texto extraído")
        filename_enc = rsa_encrypt_string(orig_filename)
        nombre_enc = rsa_encrypt_string(nombre)
        correo_enc = rsa_encrypt_string(correo)
        resumen_enc = rsa_encrypt_string(resumen or "")

        nuevo = Postulante(
            nombre_enc=nombre_enc,
            correo_enc=correo_enc,
            resumen_enc=resumen_enc,
            fecha_nacimiento=fecha_nac,
            curriculum_stored_name=unique_name,
            curriculum_filename_enc=filename_enc,
            curriculum_ciphertext_b64=hybrid["ciphertext_b64"],
            curriculum_key_encrypted_b64=hybrid["key_encrypted_b64"],
            match_score=match_score,
            oferta_id=oferta.id
        )
        db.session.add(nuevo)
        db.session.commit()
        flash("Postulación enviada correctamente", "success")
        return redirect(url_for("listar_ofertas"))

    return render_template("postular.html", oferta=oferta, title=f"Postular a {oferta.titulo}")

@app.route("/postulantes/<int:oferta_id>")
def ver_postulantes(oferta_id):
    oferta = Oferta.query.get_or_404(oferta_id)
    postulantes = Postulante.query.filter_by(oferta_id=oferta.id).all()
    # Para mostrar datos no cifrados, necesitarías descifrarlos con la clave privada (solo local)
    return render_template("postulantes.html", oferta=oferta, postulantes=postulantes, title="Postulantes")

@app.route("/descargar_cv/<filename>")
def descargar_cv(filename):
    # Seguridad: evitar path traversal
    if ".." in filename or filename.startswith("/"):
        abort(400)
    file_path = os.path.join(UPLOAD_DIR, filename)
    if not os.path.exists(file_path):
        abort(404)
    return send_file(file_path, as_attachment=True, download_name=filename)

@app.route("/exportar_csv_con_datos_cifrados/<int:oferta_id>")
def exportar_csv_con_datos_cifrados(oferta_id):
    oferta = Oferta.query.get_or_404(oferta_id)
    postulantes = Postulante.query.filter_by(oferta_id=oferta.id).all()

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
            p.id, p.nombre_enc, p.correo_enc, p.resumen_enc,
            p.fecha_nacimiento.isoformat(), p.curriculum_filename_enc,
            p.curriculum_ciphertext_b64, p.curriculum_key_encrypted_b64,
            p.match_score
        ])

    csv_data = output.getvalue().encode("utf-8")
    filename_base = re.sub(r'[^a-zA-Z0-9_-]', '_', oferta.titulo)
    download_name = f"postulantes_{filename_base}_cifrados.csv"

    return send_file(
        io.BytesIO(csv_data),
        mimetype="text/csv",
        as_attachment=True,
        download_name=download_name
    )

# ------------------------
# INICIALIZACIÓN GLOBAL (se ejecuta con Gunicorn también)
# ------------------------
# Aseguramos llaves y tablas SIEMPRE al arrancar la app (importante para Render)
ensure_keys()
with app.app_context():
    db.create_all()

# ------------------------
# MODO LOCAL
# ------------------------
if __name__ == "__main__":
    # Solo para desarrollo local
    app.run(host="0.0.0.0", port=8080, debug=True)
