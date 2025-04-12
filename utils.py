import json
import os
import base64
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# 📂 File name where data will be saved
DATA_FILE = "data.json"

# 📤 Load data from JSON file
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as file:
            return json.load(file)
    return {}

# 💾 Save data to JSON file
def save_data(data):
    with open(DATA_FILE, "w") as file:
        json.dump(data, file, indent=4)

# 🔐 Generate encryption key from passkey
def generate_key(passkey: str) -> bytes:
    salt = b'\x00' * 16  # 📌 Static salt for demo (use random salt in secure version)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),  # Use the correct way to reference SHA256
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(passkey.encode()))

# ✨ Encrypt text
def encrypt_text(text: str, passkey: str) -> str:
    key = generate_key(passkey)
    fernet = Fernet(key)
    return fernet.encrypt(text.encode()).decode()

# 🔓 Decrypt encrypted text
def decrypt_text(encrypted_text: str, passkey: str) -> str:
    key = generate_key(passkey)
    fernet = Fernet(key)
    return fernet.decrypt(encrypted_text.encode()).decode()

# 🔒 Hash passkey securely
def hash_passkey(passkey: str) -> str:
    return hashlib.sha256(passkey.encode()).hexdigest()

# ✅ Verify passkey hash
def verify_passkey(input_passkey: str, hashed_passkey: str) -> bool:
    return hash_passkey(input_passkey) == hashed_passkey
