import base64
import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import algorithms, Cipher, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


def get_key_and_iv(password, salt, algorithm=hashes.MD5):
    """
    Python implementation of EVP_BytesToKey

    Based on https://gist.github.com/tly1980/b6c2cc10bb35cb4446fb6ccf5ee5efbc
    """
    if isinstance(password, str):
        password = password.encode()
    if isinstance(salt, str):
        salt = salt.encode()

    def mdf(data):
        """Shortcut for hash using Cryptograph"""
        digest = hashes.Hash(algorithm())
        digest.update(data)
        return digest.finalize()

    keyiv = mdf(password + salt)
    tmp = [keyiv]
    while len(tmp) < 48:
        tmp.append(mdf(tmp[-1] + password + salt))
        keyiv += tmp[-1]
    return keyiv[:32], keyiv[32:48]


def get_key(password, salt):
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=32,  # This is a low number of iterations, but it's what DBX uses...
        r=8,
        p=1,
        backend=default_backend(),
    )
    return kdf.derive(password)


def encrypt_dbconnect(secret_key, plaintext, salt=None, legacy=False):
    if legacy:
        return encrypt_dbconnect_legacy(secret_key, plaintext, salt)
    else:
        return encrypt_dbconnect_new(secret_key, plaintext, salt)


def decrypt_dbconnect(secret_key, ciphertext):
    ciphertext = base64.b64decode(ciphertext)

    if ciphertext.startswith(b"Salted__"):
        return decrypt_dbconnect_legacy(secret_key, ciphertext)
    else:
        return decrypt_dbconnect_new(secret_key, ciphertext)


def decrypt_dbconnect_new(secret_key, ciphertext):
    """Implement AES GCM decryption as used in newer versions of dbconnect"""

    # Get salt and actual ciphertext from input
    salt, iv, ciphertext = ciphertext[:16], ciphertext[16:28], ciphertext[28:]

    # Derive key using Scrypt
    key = get_key(secret_key, salt)

    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(iv, ciphertext, None)
    return plaintext.decode("utf-8")


def decrypt_dbconnect_legacy(secret_key, ciphertext):
    """Implement `openssl aes-256-cbc` encryption as used in older versions of dbconnect"""

    # Get salt and actual ciphertext from input
    salt, ciphertext = ciphertext[8:16], ciphertext[16:]

    # Use OpenSSL EVP_BytesToKey (with md5) to derive key and iv
    key, iv = get_key_and_iv(secret_key, salt, algorithm=hashes.MD5)  # pylint: disable=invalid-name

    # Decrypt
    algorithm = algorithms.AES(key)
    cipher = Cipher(algorithm, mode=modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext)

    # Unpad the plaintext
    unpadder = PKCS7(128).unpadder()
    unpadded_data = unpadder.update(plaintext)
    unpadded_data += unpadder.finalize()

    # Return string result
    return unpadded_data.decode()


def encrypt_dbconnect_new(secret_key, plaintext, salt=None):
    """Implement `openssl aes-256-gcm` encryption as used in newer versions of dbconnect"""
    if salt is None:
        salt = os.urandom(16)

    # Derive key using Scrypt
    key = get_key(secret_key, salt)

    # Generate random IV
    iv = os.urandom(12)

    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(iv, plaintext.encode("utf-8"), None)

    result = salt + iv + ciphertext
    return base64.b64encode(result).decode("utf-8")


def encrypt_dbconnect_legacy(secret_key, plaintext, salt=None):
    """Implement `openssl aes-256-cbc` decryption as used in older versions of dbconnect"""

    # Use a random salt unless one is provided
    if salt is None:
        salt = os.urandom(8)

    # Use OpenSSL EVP_BytesToKey (with md5) to derive key and iv
    key, iv = get_key_and_iv(secret_key, salt, algorithm=hashes.MD5)  # pylint: disable=invalid-name

    # Pad the plaintext to 16 bytes
    plaintext = plaintext.encode()
    padder = PKCS7(128).padder()
    padded_data = padder.update(plaintext)
    padded_data += padder.finalize()

    # Encrypt
    algorithm = algorithms.AES(key)
    cipher = Cipher(algorithm, mode=modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    # Base64 result
    return base64.b64encode(b"Salted__" + salt + ciphertext).decode()
