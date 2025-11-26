from pymongo import MongoClient
import os

uri = os.getenv("MONGO_URI")

print("DEBUG URI:", uri)  # ← agrega esto para ver qué recibe Render

client = MongoClient(uri)
db = client["test"]  # o la base que uses


