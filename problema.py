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
from bson.objectid import ObjectId

# Cryptography
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.fernet import Fernet

# PDF extractor
from PyPDF2 import PdfReader

# -----------------------------------------------------
# CONFIGURACIÓN GENERAL
# -----------------------------------------------------
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
except:
    sys.exit(1)

db = client["reclutamiento_db"]
ofertas_col = db["ofertas"]
postulantes_col = db["postulantes"]

# -----------------------------------------------------
# CIFRADO
# -----------------------------------------------------
def ensure_keys():
    if not (os.path.exists(PRIVATE_KEY_PATH) and os.path.exists(PUBLIC_KEY_PATH)):
        private_key = rsa.generate_private_key("65537", key_size=2048)
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

def rsa_encrypt_string(s: str) -> str:
    pub = load_public_key()
    ct = pub.encrypt(
        s.encode("utf-8"),
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                     algorithm=hashes.SHA256(),
                     label=None)
    )
    return base64.b64encode(ct).decode()

# -----------------------------------------------------
# UTILIDADES
# -----------------------------------------------------
def allowed_file(filename):
    return filename and '.' in filename and filename.rsplit(".",1)[1].lower() in ALLOWED_EXTENSIONS

def extract_text_from_pdf(path):
    try:
        reader = PdfReader(path)
        return "".join((p.extract_text() or "") for p in reader.pages).strip()
    except:
        return ""

def calculate_age(born: date):
    today = datetime.utcnow().date()  # evitar zona horaria Render
    return today.year - born.year - ((today.month, today.day) < (born.month, born.day))

STOPWORDS = {"de","la","el","y","en","a","los","las","con","para","por","un","una","es","se","su","que","al","del"}

def extract_keywords(text, min_len=4):
    text = re.sub(r"[^\w\s]", " ", text.lower())
    tokens = [t for t in text.split() if len(t)>=min_len and t not in STOPWORDS]
    freq = Counter(tokens)
    return [w for w,c in freq.most_common(20)]

def get_neural_network_match_score(t, d, r, cv):
    kws = extract_keywords(t+" "+d) or ["python","sql","docker"]
    score=0
    for kw in kws:
        score+=cv.lower().count(kw)+r.lower().count(kw)
    return min(100, score*5)

# -----------------------------------------------------
# BORRAR OFERTA + POSTULANTES
# -----------------------------------------------------
def _delete_offer_and_postulants_by_id_string(oferta_id):
    postulantes_col.delete_many({"oferta_id": oferta_id})
    ofertas_col.delete_one({"_id": ObjectId(oferta_id)})
    return True, None

# -----------------------------------------------------
# RUTAS
# -----------------------------------------------------
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/ofertas/")
def listar_ofertas():
    ofertas = []
    for o in ofertas_col.find().sort("_created",-1):
        o["_id_str"]=str(o["_id"])
        ofertas.append(o)
    return render_template("ofertas.html", ofertas=ofertas)

@app.route("/crear_oferta/", methods=["GET","POST"])
def crear_oferta():
    if request.method=="POST":
        nueva={
            "titulo": request.form["titulo"],
            "descripcion": request.form["descripcion"],
            "empresa": request.form["empresa"],
            "_created": datetime.utcnow()
        }
        ofertas_col.insert_one(nueva)
        flash("Oferta creada","success")
        return redirect(url_for("listar_ofertas"))
    return render_template("crear_oferta.html")

@app.route("/eliminar_oferta/<oferta_id>", methods=["POST"])
def eliminar_oferta(oferta_id):
    _delete_offer_and_postulants_by_id_string(oferta_id)
    flash("Oferta eliminada","success")
    return redirect(url_for("listar_ofertas"))

# -----------------------------------------------------
# POSTULAR
# -----------------------------------------------------
@app.route("/postular/<oferta_id>", methods=["GET","POST"])
def postular(oferta_id):

    oferta = ofertas_col.find_one({"_id": ObjectId(oferta_id)})
    if not oferta:
        abort(404)

    if request.method == "POST":

        nombre=request.form["nombre"].strip()
        correo=request.form["correo"].strip()
        resumen=request.form["resumen"].strip()
        f_nac=request.form["fecha_nacimiento"]
        archivo=request.files["curriculum"]

        fecha_nac=datetime.strptime(f_nac,"%Y-%m-%d").date()

        if calculate_age(fecha_nac) < 18:
            flash("Debes ser mayor de edad para postular", "danger")
            return redirect(url_for("postular", oferta_id=oferta_id))

        if not allowed_file(archivo.filename):
            flash("Solo PDF permitido", "danger")
            return redirect(url_for("postular", oferta_id=oferta_id))

        unique_name=f"{uuid.uuid4().hex}.pdf"
        path=os.path.join(UPLOAD_DIR,unique_name)
        archivo.save(path)

        extracted = extract_text_from_pdf(path)
        score = get_neural_network_match_score(
            oferta["titulo"], oferta["descripcion"], resumen, extracted
        )

        ensure_keys()
        nuevo={
            "nombre_enc": rsa_encrypt_string(nombre),
            "correo_enc": rsa_encrypt_string(correo),
            "resumen_enc": rsa_encrypt_string(resumen),
            "fecha_nacimiento": fecha_nac.isoformat(),
            "curriculum_stored_name": unique_name,
            "curriculum_filename_enc": rsa_encrypt_string(archivo.filename),
            "match_score": score,
            "oferta_id": oferta_id,
            "_created": datetime.utcnow()
        }

        postulantes_col.insert_one(nuevo)
        flash("Postulación enviada correctamente","success")
        return redirect(url_for("listar_ofertas"))

    return render_template("postular.html", oferta=oferta)

# -----------------------------------------------------
# LISTA DE POSTULANTES
# -----------------------------------------------------
@app.route("/postulantes/<oferta_id>/")
def ver_postulantes(oferta_id):

    oferta = ofertas_col.find_one({"_id": ObjectId(oferta_id)})
    if not oferta:
        abort(404)

    postulantes = []
    for p in postulantes_col.find({"oferta_id": oferta_id}).sort("_created", -1):
        p["_id_str"]=str(p["_id"])
        postulantes.append(p)

    return render_template("postulantes.html", oferta=oferta, postulantes=postulantes)

# -----------------------------------------------------
if __name__ == "__main__":
    ensure_keys()
    app.run(host="0.0.0.0", port=8080, debug=True)
