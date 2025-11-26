from pymongo import MongoClient
import os

# URI para Atlas — se recomienda usar variables de entorno
MONGO_URI = os.getenv("MONGO_URI")

if not MONGO_URI:
    raise ValueError("❌ ERROR: La variable de entorno MONGO_URI no está configurada.")

# Conexión al cluster Atlas
client = MongoClient(MONGO_URI)

# Nombre de la base de datos
db = client["base_reclutajusto"]  # Cambia el nombre si quieres
