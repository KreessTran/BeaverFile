import os
import sys
import hashlib
from PyQt5.QtWidgets import (QApplication, QWidget, QVBoxLayout, QPushButton, QLabel, QLineEdit, QFileDialog, QMessageBox)
from PyQt5.QtGui import QFont, QDragEnterEvent, QDropEvent
from PyQt5.QtCore import Qt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from argon2.low_level import hash_secret_raw, Type

SALT_LENGTH = 16
IV_LENGTH = 12
TAG_LENGTH = 16
AES_KEY_LENGTH = 32

class FileEncryptionTool(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle('File Encryption Tool')
        self.setGeometry(100, 100, 500, 300)
        self.setStyleSheet("background-color: #2e2e2e; color: white;")
        self.setAcceptDrops(True)  # Enable drag-and-drop

        layout = QVBoxLayout()

        self.instruction_label = QLabel("Browse or drag and drop a file to encrypt/decrypt")
        self.instruction_label.setFont(QFont('Arial', 12))
        self.instruction_label.setStyleSheet("color: white;")
        self.instruction_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.instruction_label)

        self.file_label = QLabel("File Path:")
        self.file_label.setFont(QFont('Arial', 12))
        self.file_label.setStyleSheet("color: white;")
        layout.addWidget(self.file_label)

        self.file_path_entry = QLineEdit()
        self.file_path_entry.setFont(QFont('Arial', 12))
        self.file_path_entry.setStyleSheet("background-color: #4d4d4d; color: white; border-radius: 5px; padding: 5px;")
        layout.addWidget(self.file_path_entry)

        self.browse_button = QPushButton("Browse")
        self.browse_button.setFont(QFont('Arial', 10, QFont.Bold))
        self.browse_button.setStyleSheet("""
            QPushButton {
                background-color: #b3b3b3;
                color: white;
                border-radius: 5px;
                padding: 6px;
            }
            QPushButton:hover {
                background-color: #2b70f0;
            }
        """)
        self.browse_button.clicked.connect(self.load_file)
        layout.addWidget(self.browse_button)

        self.password_label = QLabel("Password:")
        self.password_label.setFont(QFont('Arial', 12))
        self.password_label.setStyleSheet("color: white;")
        layout.addWidget(self.password_label)

        self.password_entry = QLineEdit()
        self.password_entry.setFont(QFont('Arial', 12))
        self.password_entry.setEchoMode(QLineEdit.Password)
        self.password_entry.setStyleSheet("background-color: #4d4d4d; color: white; border-radius: 5px; padding: 5px;")
        layout.addWidget(self.password_entry)

        self.encrypt_button = QPushButton("Encrypt")
        self.encrypt_button.setFont(QFont('Arial', 10, QFont.Bold))
        self.encrypt_button.setStyleSheet("""
            QPushButton {
                background-color: #b3b3b3;
                color: white;
                border-radius: 5px;
                padding: 6px;
            }
            QPushButton:hover {
                background-color: #2b70f0;
            }
        """)
        self.encrypt_button.clicked.connect(self.encrypt_file)
        layout.addWidget(self.encrypt_button)

        self.decrypt_button = QPushButton("Decrypt")
        self.decrypt_button.setFont(QFont('Arial', 10, QFont.Bold))
        self.decrypt_button.setStyleSheet("""
            QPushButton {
                background-color: #b3b3b3;
                color: white;
                border-radius: 5px;
                padding: 6px;
            }
            QPushButton:hover {
                background-color: #2b70f0;
            }
        """)
        self.decrypt_button.clicked.connect(self.decrypt_file)
        layout.addWidget(self.decrypt_button)

        self.quit_button = QPushButton("Quit")
        self.quit_button.setFont(QFont('Arial', 10, QFont.Bold))
        self.quit_button.setStyleSheet("""
            QPushButton {
                background-color: #b3b3b3;
                color: white;
                border-radius: 5px;
                padding: 6px;
            }
            QPushButton:hover {
                background-color: #2b70f0;
            }
        """)
        self.quit_button.clicked.connect(self.close)
        layout.addWidget(self.quit_button)

        self.setLayout(layout)

    def dragEnterEvent(self, event: QDragEnterEvent):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
            self.file_path_entry.setStyleSheet("background-color: #d3d3d3; color: black; border-radius: 5px; padding: 5px;")  # Change appearance

    def dragLeaveEvent(self, event):
        self.file_path_entry.setStyleSheet("background-color: #4d4d4d; color: white; border-radius: 5px; padding: 5px;")  # Revert appearance

    def dropEvent(self, event: QDropEvent):
        self.file_path_entry.setStyleSheet("background-color: #4d4d4d; color: white; border-radius: 5px; padding: 5px;")  # Revert appearance
        for url in event.mimeData().urls():
            file_path = url.toLocalFile()
            self.file_path_entry.setText(file_path)

    def load_file(self):
        options = QFileDialog.Options()
        file_name, _ = QFileDialog.getOpenFileName(self, "Select a File", "", "All Files (*);;Python Files (*.py)", options=options)
        if file_name:
            self.file_path_entry.setText(file_name)

    def encrypt_file(self):
        file_path = self.file_path_entry.text()
        password = self.password_entry.text()
        if not self.validate_password(password):
            QMessageBox.warning(self, "Weak Password", "Please use a stronger password.")
            return
        encrypted_data = self.encrypt(file_path, password)
        if encrypted_data:
            encrypted_file_path = file_path + ".enc"
            with open(encrypted_file_path, 'wb') as f:
                f.write(encrypted_data)
            QMessageBox.information(self, "Success", f"Encrypted file saved as {encrypted_file_path}")
        self.password_entry.clear()
        self.file_path_entry.clear()  # Clear the file path entry

    def decrypt_file(self):
        file_path = self.file_path_entry.text()
        password = self.password_entry.text()
        output_file = file_path.rstrip(".enc") + ".dec"
        try:
            with open(file_path, 'rb') as f:
                encrypted_data = f.read()
            
            # Attempt to decrypt the data
            self.decrypt(encrypted_data, password, output_file)
            
            # Clear entries after successful decryption
            self.password_entry.clear()
            self.file_path_entry.clear()
            
            QMessageBox.information(self, "Success", f"Decrypted file saved as {output_file}")
        except Exception as e:
            # Clear entries on failure
            self.password_entry.clear()
            self.file_path_entry.clear()
            
            # Show error message if decryption fails
            QMessageBox.warning(self, "Decryption Failed", "Incorrect password or corrupted file.")

    def validate_password(self, password: str) -> bool:
        """Validate the strength of the password."""
        if len(password) < 8:
            return False
        if not any(char.isdigit() for char in password):
            return False
        if not any(char.isupper() for char in password):
            return False
        if not any(char.islower() for char in password):
            return False
        if not any(char in '!@#$%^&*()_+' for char in password):
            return False
        return True

    def derive_key(self, password: bytes, salt: bytes) -> bytes:
        return hash_secret_raw(
            password,
            salt,
            time_cost=2,
            memory_cost=102400,
            parallelism=8,
            hash_len=AES_KEY_LENGTH,
            type=Type.I
        )

    def encrypt(self, file_path: str, password: str) -> bytes:
        try:
            salt = os.urandom(SALT_LENGTH)
            key = self.derive_key(password.encode(), salt)
            
            with open(file_path, "rb") as file:
                plaintext = file.read()

            # Calculate file hash before encryption
            file_hash = hashlib.sha256(plaintext).hexdigest()
            
            padder = padding.PKCS7(algorithms.AES.block_size).padder()
            padded_plaintext = padder.update(plaintext) + padder.finalize()
            
            iv = os.urandom(IV_LENGTH)
            encryptor = Cipher(
                algorithms.AES(key),
                modes.GCM(iv),
                backend=default_backend()
            ).encryptor()
            
            ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
            return salt + iv + ciphertext + encryptor.tag + file_hash.encode('utf-8')
        except Exception as e:
            print(f"Encryption Error: {e}")
            return None

    def decrypt(self, ciphertext: bytes, password: str, output_path: str) -> None:
        try:
            salt = ciphertext[:SALT_LENGTH]
            iv = ciphertext[SALT_LENGTH:SALT_LENGTH + IV_LENGTH]
            tag = ciphertext[-TAG_LENGTH-64:-64]
            file_hash = ciphertext[-64:].decode('utf-8')
            encrypted_message = ciphertext[SALT_LENGTH + IV_LENGTH:-TAG_LENGTH-64]
            key = self.derive_key(password.encode(), salt)
            
            decryptor = Cipher(
                algorithms.AES(key),
                modes.GCM(iv, tag),
                backend=default_backend()
            ).decryptor()
            
            padded_plaintext = decryptor.update(encrypted_message) + decryptor.finalize()
            unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
            plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

            # Verify file integrity
            if hashlib.sha256(plaintext).hexdigest() != file_hash:
                raise ValueError("File integrity check failed")
            
            with open(output_path, 'wb') as f:
                f.write(plaintext)
            print(f"Decrypted file saved as {output_path}")
        except Exception as e:
            # Print decryption error for debugging
            print(f"Decryption Error: {e}")
            raise

def main():
    app = QApplication(sys.argv)
    ex = FileEncryptionTool()
    ex.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()
