from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64

def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    public_key = private_key.public_key()

    return private_key, public_key

def generate_aes_key():
    return get_random_bytes(32)

def encrypt_string(input_string, key):
    cipher = AES.new(key, AES.MODE_CBC)
    padded_data = pad(input_string.encode(), AES.block_size)
    encrypted = cipher.encrypt(padded_data)
    encrypted_data = cipher.iv + encrypted

    return base64.b64encode(encrypted_data).decode()

def decrypt_string(encrypted_string, key):
    encrypted_data = base64.b64decode(encrypted_string)
    
    iv = encrypted_data[:16]
    encrypted_data = encrypted_data[16:]

    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
    return decrypted_data.decode()

def export_public_key(public_key):
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return public_key_pem

def import_public_key(public_key_pem):
    public_key = serialization.load_pem_public_key(public_key_pem)
    return public_key

if __name__ == "__main__":
    private_key, public_key = generate_rsa_keys()
    print("Chiave privata RSA generata!")
    print("Chiave pubblica RSA generata!")

    aes_key = generate_aes_key()
    print("Chiave AES generata!")

    print(f"Chiave AES (esadecimale): {aes_key.hex()}")
