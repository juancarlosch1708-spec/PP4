# problema_mongo.py
import os
import io
import csv
import uuid
import base64
import re
import sys
import logging
from datetime import datetime, date
from collections import Counter

from flask import (
    Flask, render_template, request, redirect, url_for, send_file,
    flash, abort
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

# -------------------------
# CONFIG
# -------------------------
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
os.makedirs(os.path.join(BASE_DIR, "templates"), exist_ok=True)

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

# -------------------------
# MONGO
# -------------------------
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
    raise SystemExit("No se pudo conectar a MongoDB.") from e

db = client["reclutamiento_db"]
ofertas_col = db["ofertas"]
postulantes_col = db["postulantes"]

# -------------------------
# KEYS / RSA
# -------------------------
def ensure_keys():
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

def load_public_key():
    with open(PUBLIC_KEY_PATH, "rb") as f:
        return serialization.load_pem_public_key(f.read())

def load_private_key():
    with open(PRIVATE_KEY_PATH, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def rsa_encrypt_string(s: str) -> str:
    pub = load_public_key()
    ct = pub.encrypt(
        s.encode("utf-8"),
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(ct).decode()

def rsa_decrypt_string(b64_ct: str) -> str:
    priv = load_private_key()
    ct = base64.b64decode(b64_ct)
    pt = priv.decrypt(
        ct,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return pt.decode("utf-8")

# -------------------------
# UTIL
# -------------------------
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
    except Exception:
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

# -------------------------
# HELPERS
# -------------------------
def _delete_offer_and_postulants_by_id_string(oferta_id):
    try:
        postulantes_col.delete_many({"oferta_id": oferta_id})
        ofertas_col.delete_one({"_id": ObjectId(oferta_id)})
        return True, None
    except Exception as e:
        return False, str(e)

# -------------------------
# ROUTES
# -------------------------

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/ofertas/")
def listar_ofertas():
    ofertas = []
    cursor = ofertas_col.find().sort("_created", -1)
    for o in cursor:
        o["_id_str"] = str(o["_id"])
        ofertas.append(o)
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

        ofertas_col.insert_one(nueva)
        flash("Oferta creada", "success")
        return redirect(url_for("listar_ofertas"))

    return render_template("crear_oferta.html")

@app.route("/eliminar_oferta/<oferta_id>", methods=["POST"])
def eliminar_oferta(oferta_id):
    ok, err = _delete_offer_and_postulants_by_id_string(oferta_id)
    flash("Oferta eliminada" if ok else f"Error: {err}", "danger" if not ok else "success")
    return redirect(url_for("listar_ofertas"))

# 🔥 CORREGIDO: mantiene el POST correctamente
@app.route("/postular/", methods=["POST"])
def postular_root():
    oferta_id = request.form.get("oferta_id")
    if not oferta_id:
        flash("No se recibió la oferta.", "danger")
        return redirect(url_for("listar_ofertas"))
    return redirect(url_for("postular", oferta_id=oferta_id), code=307)

@app.route("/postular/<oferta_id>", methods=["GET","POST"])
def postular(oferta_id):
    try:
        oferta = ofertas_col.find_one({"_id": ObjectId(oferta_id)})
    except:
        oferta = None

    if not oferta:
        abort(404)

    if request.method == "POST":
        nombre = request.form.get("nombre", "").strip()
        correo = request.form.get("correo", "").strip()
        resumen = request.form.get("resumen", "").strip()
        f_nac = request.form.get("fecha_nacimiento", "").strip()
        archivo = request.files.get("curriculum")

        if not (nombre and correo and resumen and f_nac):
            flash("Completa todos los campos", "danger")
            return redirect(url_for("postular", oferta_id=oferta_id))

        try:
            fecha_nac = datetime.strptime(f_nac, "%Y-%m-%d").date()
        except:
            flash("Fecha inválida", "danger")
            return redirect(url_for("postular", oferta_id=oferta_id))

        if calculate_age(fecha_nac) < 18:
            flash("Debes ser mayor de edad", "danger")
            return redirect(url_for("postular", oferta_id=oferta_id))

        if not archivo or not allowed_file(archivo.filename):
            flash("Adjunta un PDF válido", "danger")
            return redirect(url_for("postular", oferta_id=oferta_id))

        original_filename = secure_filename(archivo.filename)
        unique_name = f"{uuid.uuid4().hex}.pdf"
        path = os.path.join(UPLOAD_DIR, unique_name)
        archivo.save(path)

        extracted = extract_text_from_pdf(path)
        score = get_neural_network_match_score(
            oferta["titulo"], oferta["descripcion"], resumen, extracted
        )

        ensure_keys()

        # 🔥 CORREGIDO — SE GUARDA BIEN
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

        flash("Postulación enviada", "success")
        return redirect(url_for("listar_ofertas"))

    return render_template("postular.html", oferta=oferta)

@app.route("/postulantes/<oferta_id>/")
def ver_postulantes(oferta_id):
    oferta = ofertas_col.find_one({"_id": ObjectId(oferta_id)})
    if not oferta:
        abort(404)

    postulantes = list(postulantes_col.find({"oferta_id": oferta_id}).sort("_created", -1))
    return render_template("postulantes.html", oferta=oferta, postulantes=postulantes)

@app.route("/descargar_cv/<postulante_id>")
def descargar_cv(postulante_id):
    p = postulantes_col.find_one({"_id": ObjectId(postulante_id)})
    if not p:
        abort(404)

    filename = p["curriculum_stored_name"]
    path = os.path.join(UPLOAD_DIR, filename)

    if not os.path.exists(path):
        abort(404)

    return send_file(path, as_attachment=True, download_name=filename)

# -------------------------
# START
# -------------------------
if __name__ == "__main__":
    ensure_keys()
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port)
