
from cryptography.fernet import Fernet
import os

def load_or_create_key():
    key_file = "secret.key"

    if not os.path.exists(key_file):
        key = Fernet.generate_key()
        with open(key_file, "wb") as f:
            f.write(key)
    else:
        with open(key_file, "rb") as f:
            key = f.read()

    return key
