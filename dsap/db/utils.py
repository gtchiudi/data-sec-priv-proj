from cryptography.fernet import Fernet
from django.conf import settings
import cryptography
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad


FERNET_KEY = settings.FERNET_KEY
cipher_suite = Fernet(FERNET_KEY)
# Functions to encrypt and decrypt data


def decrypt_bool(encrypted_data):
    try:
        decrypted_data = cipher_suite.decrypt(bytes.fromhex(encrypted_data))
        return bool.from_bytes(decrypted_data, byteorder='big')
    except cryptography.fernet.InvalidToken:
        raise ValueError("Invalid encrypted data or incorrect key")


def decrypt_int(encrypted_data):
    try:
        decrypted_data = cipher_suite.decrypt(bytes.fromhex(encrypted_data))
        return int.from_bytes(decrypted_data, byteorder='big')
    except cryptography.fernet.InvalidToken:
        raise ValueError("Invalid encrypted data or incorrect key")


def encrypt(data):
    if type(data) == bool:
        bytes_data = data.to_bytes(1, byteorder='big')
    elif type(data) == int:
        bytes_data = data.to_bytes(4, byteorder='big')
    else:
        raise ValueError("Invalid data type")
    encrypted_data = cipher_suite.encrypt(bytes_data).hex()
    return encrypted_data


def encrypt_aes(key, data):
    cipher = AES.new(key, AES.MODE_CBC)
    cipherText = cipher.encrypt(pad(data, AES.block_size))
    iv = cipher.iv
    return cipherText, iv
