import bcrypt
from pymongo import MongoClient

# Connexion MongoDB
client = MongoClient("mongodb://localhost:27017")
db = client["cyberform"]
collection = db.users

# Mot de passe unique
plain_password = "ambems123"
hashed = bcrypt.hashpw(plain_password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

# Mise à jour du bon champ basic_info.password
result = collection.update_many(
    {},
    {"$set": {"basic_info.password": hashed}}
)

print(f"{result.modified_count} utilisateurs mis à jour avec le mot de passe commun.")
