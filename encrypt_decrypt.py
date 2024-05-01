import os
import sys
import tkinter as tk
from tkinter import filedialog
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import padding

def derive_key(password: bytes, salt: bytes) -> bytes:
    """Derive a cryptographic key from a password."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password)

def encrypt(file_path: str, password: str) -> bytes:
    """Encrypt a file using AES encryption."""
    try:
        salt = os.urandom(16)
        key = derive_key(password.encode(), salt)
        
        with open(file_path, "rb") as file:
            plaintext = file.read()
        
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_plaintext = padder.update(plaintext) + padder.finalize()
        
        iv = os.urandom(12)
        encryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(iv),
            backend=default_backend()
        ).encryptor()
        
        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
        return salt + iv + ciphertext + encryptor.tag
    except Exception as e:
        print(f"Error: {e}")
        return None

def decrypt(ciphertext: bytes, password: str, output_path: str) -> None:
    """Decrypt a file encrypted by the above function."""
    try:
        salt = ciphertext[:16]
        iv = ciphertext[16:28]
        tag = ciphertext[-16:]
        encrypted_message = ciphertext[28:-16]
        key = derive_key(password.encode(), salt)
        
        decryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(iv, tag),
            backend=default_backend()
        ).decryptor()
        
        padded_plaintext = decryptor.update(encrypted_message) + decryptor.finalize()
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        
        with open(output_path, 'wb') as f:
            f.write(plaintext)
        print(f"Decrypted file saved as {output_path}")
    except Exception as e:
        print(f"Error: {e}")

def load_file(entry):
    filepath = filedialog.askopenfilename()
    entry.delete(0, tk.END)
    entry.insert(0, filepath)

def encrypt_file(path_entry, password_entry):
    file_path = path_entry.get()
    password = password_entry.get()
    encrypted_data = encrypt(file_path, password)
    if encrypted_data:
        encrypted_file_path = file_path + ".enc"
        with open(encrypted_file_path, 'wb') as f:
            f.write(encrypted_data)
        print(f"Encrypted file saved as {encrypted_file_path}")

def decrypt_file(path_entry, password_entry):
    file_path = path_entry.get()
    password = password_entry.get()
    output_file = file_path.rstrip(".enc") + ".dec"  # Default output file name if none provided
    with open(file_path, 'rb') as f:
        encrypted_data = f.read()
    decrypt(encrypted_data, password, output_file)

def create_gui():
    app = tk.Tk()
    app.title('File Encryption Tool')

    tk.Label(app, text="File Path:").pack()
    file_path_entry = tk.Entry(app, width=50)
    file_path_entry.pack()

    tk.Button(app, text="Browse", command=lambda: load_file(file_path_entry)).pack()
    password_label = tk.Label(app, text="Password:")
    password_label.pack()
    password_entry = tk.Entry(app, show='*', width=30)
    password_entry.pack()

    tk.Button(app, text="Encrypt", command=lambda: encrypt_file(file_path_entry, password_entry)).pack()
    tk.Button(app, text="Decrypt", command=lambda: decrypt_file(file_path_entry, password_entry)).pack()

    app.mainloop()

if __name__ == "__main__":
    create_gui()
