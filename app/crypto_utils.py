from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import os
import base64

# --- Key Loading and Generation ---

def generate_key():
    return Fernet.generate_key()

def load_key(key_path="secret.key"):
    with open(key_path, "rb") as key_file:
        key_data = key_file.read()
    
    # Check for the salted key format
    if key_data.startswith(b"salted_key_format::"):
        parts = key_data.split(b"::")
        if len(parts) == 3:
            # The actual key is the third part
            return parts[2]
        else:
            raise ValueError("Invalid salted key file format.")
    else:
        # Assume it's a raw Fernet key
        return key_data

def derive_key_from_password(password: str, salt: bytes):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

# --- Text Encryption/Decryption ---

def encrypt_text(text: str, key: bytes):
    f = Fernet(key)
    return f.encrypt(text.encode()).decode()

def decrypt_text(encrypted_text: str, key: bytes):
    f = Fernet(key)
    return f.decrypt(encrypted_text.encode()).decode()

# --- Generic File/Stream Encryption ---

def _encrypt_stream(in_stream, out_stream, key):
    f = Fernet(key)
    file_data = in_stream.read()
    encrypted_data = f.encrypt(file_data)
    out_stream.write(encrypted_data)

def _decrypt_stream(in_stream, out_stream, key):
    f = Fernet(key)
    encrypted_data = in_stream.read()
    decrypted_data = f.decrypt(encrypted_data)
    out_stream.write(decrypted_data)

# --- Single File Encryption/Decryption (using direct key) ---

def encrypt_file(file_path: str, key: bytes):
    with open(file_path, "rb") as in_f, open(file_path + ".enc", "wb") as out_f:
        _encrypt_stream(in_f, out_f, key)

def decrypt_file(file_path: str, key: bytes):
    output_path = os.path.splitext(file_path)[0]
    with open(file_path, "rb") as in_f, open(output_path, "wb") as out_f:
        _decrypt_stream(in_f, out_f, key)

# --- Password-Based File/Stream Encryption ---

def encrypt_file_with_password(in_stream, password: str, out_stream):
    salt = os.urandom(16)
    key = derive_key_from_password(password, salt)
    f = Fernet(key)
    file_data = in_stream.read()
    encrypted_data = f.encrypt(file_data)
    out_stream.write(salt + encrypted_data)

def decrypt_file_with_password(in_stream, password: str, out_stream):
    data = in_stream.read()
    salt, encrypted_data = data[:16], data[16:]
    key = derive_key_from_password(password, salt)
    f = Fernet(key)
    decrypted_data = f.decrypt(encrypted_data)
    out_stream.write(decrypted_data)

# --- Batch (Folder) Encryption/Decryption ---

def encrypt_folder(folder_path: str, key: bytes):
    for root, _, files in os.walk(folder_path):
        for filename in files:
            if not filename.endswith('.enc'):
                file_path = os.path.join(root, filename)
                encrypt_file(file_path, key)
                os.remove(file_path)

def decrypt_folder(folder_path: str, key: bytes):
    for root, _, files in os.walk(folder_path):
        for filename in files:
            if filename.endswith('.enc'):
                file_path = os.path.join(root, filename)
                decrypt_file(file_path, key)
                os.remove(file_path)

def encrypt_folder_with_password(folder_path: str, password: str):
    for root, _, files in os.walk(folder_path):
        for filename in files:
            if not filename.endswith('.enc'):
                file_path = os.path.join(root, filename)
                with open(file_path, "rb") as in_f, open(file_path + ".enc", "wb") as out_f:
                    encrypt_file_with_password(in_f, password, out_f)
                os.remove(file_path)

def decrypt_folder_with_password(folder_path: str, password: str):
    for root, _, files in os.walk(folder_path):
        for filename in files:
            if filename.endswith('.enc'):
                file_path = os.path.join(root, filename)
                output_path = os.path.splitext(file_path)[0]
                try:
                    with open(file_path, "rb") as in_f, open(output_path, "wb") as out_f:
                        decrypt_file_with_password(in_f, password, out_f)
                    os.remove(file_path)
                except Exception as e:
                    print(f"Failed to decrypt {filename}: {e}")
                    # Clean up the partially created empty file
                    if os.path.exists(output_path) and os.path.getsize(output_path) == 0:
                        os.remove(output_path)

# --- Caesar Cipher (for demonstration) ---

def caesar_cipher(text, shift, encrypt=True):
    result = ""
    for char in text:
        if char.isalpha():
            start = ord('a') if char.islower() else ord('A')
            offset = (ord(char) - start + (shift if encrypt else -shift)) % 26
            result += chr(start + offset)
        else:
            result += char
    return result
