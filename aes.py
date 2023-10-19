import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

# Function to generate a random AES key of a specific size in bits
def generate_aes_key(key_size_bits):
    if key_size_bits % 8 != 0:
        raise ValueError("Key size must be a multiple of 8 bits")
    key = os.urandom(key_size_bits // 8)
    return key

# Function to generate a random initialization vector (IV)
def generate_iv():
    return os.urandom(16)  # 16 bytes for AES

# User input for AES key size
key_size_bits = int(input("Enter AES key size (128, 192, or 256 bits): "))

# Validate and set the AES key size
if key_size_bits not in [128, 192, 256]:
    print("Invalid key size. Please choose 128, 192, or 256 bits.")
else:
    key = generate_aes_key(key_size_bits)
    iv = generate_iv()

    # Create an AES cipher object with CBC mode and the generated IV
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)

    # Encrypt the plaintext with PKCS7 padding
    plaintext = b'Hello, AES!'
    padder = padding.PKCS7(128).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    # Decrypt the ciphertext
    decryptor = cipher.decryptor()
    decrypted_padded_text = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    decrypted_text = unpadder.update(decrypted_padded_text) + unpadder.finalize()

    print("Plaintext:", plaintext)
    print("Ciphertext:", ciphertext)
    print("Decrypted text:", decrypted_text.decode('utf-8'))
