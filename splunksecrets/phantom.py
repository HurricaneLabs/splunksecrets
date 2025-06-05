import base64
import struct

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import algorithms, Cipher, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.padding import PKCS7


def to_bytes(num, size, byte_order):
    """Function to convert a number to bytes"""
    fmt = ">" if byte_order.lower() == "big" else "<"
    fmt += "B" * int(size)
    num = bin(num)[2:].zfill(size * 8)
    args = [int(num[i:i+8], 2) for i in range(0, len(num), 8)]

    return struct.pack(fmt, *args)  # pylint: disable=no-member


def encrypt_phantom(private_key, secret_key, plaintext, asset_id):
    """Use AES 256 CBC to encrypt credentials in Phantom"""

    # Get the public key bytes from the private key
    private_key = serialization.load_pem_private_key(private_key, password=None)
    public_key = private_key.public_key()
    public_key_bytes = to_bytes(
        public_key.public_numbers().n,
        int(public_key.key_size / 8),
        byte_order="big"
    )

    # Ensure the secret_key is bytes
    if isinstance(secret_key, str):
        secret_key = secret_key.encode()

    # Get SHA256(public_key_bytes + secret_key)
    digest = hashes.Hash(hashes.SHA256())
    digest.update(public_key_bytes)
    digest.update(secret_key)
    key = digest.finalize()

    # Get the iv from asset_id
    digest = hashes.Hash(hashes.SHA1())
    digest.update(str(asset_id).encode())
    iv = digest.finalize()[:16]  # pylint: disable=invalid-name

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
    return base64.b64encode(ciphertext).decode()


def decrypt_phantom(private_key, secret_key, ciphertext, asset_id):
    """Use AES 256 CBC to decrypt credentials in Phantom"""
    # Get the public key bytes from the private key
    private_key = serialization.load_pem_private_key(private_key, password=None)
    public_key = private_key.public_key()
    public_key_bytes = to_bytes(
        public_key.public_numbers().n,
        int(public_key.key_size / 8),
        byte_order="big"
    )

    # Ensure the secret_key is bytes
    if isinstance(secret_key, str):
        secret_key = secret_key.encode()

    # Get SHA256(public_key_bytes + secret_key)
    digest = hashes.Hash(hashes.SHA256())
    digest.update(public_key_bytes)
    digest.update(secret_key)
    key = digest.finalize()

    # Get the iv from asset_id
    digest = hashes.Hash(hashes.SHA1())
    digest.update(str(asset_id).encode())
    iv = digest.finalize()[:16]  # pylint: disable=invalid-name

    # Decrypt
    algorithm = algorithms.AES(key)
    cipher = Cipher(algorithm, mode=modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    # Decode base64
    plaintext = decryptor.update(base64.b64decode(ciphertext))

    # Unpad the plaintext
    unpadder = PKCS7(128).unpadder()
    unpadded_data = unpadder.update(plaintext)
    unpadded_data += unpadder.finalize()

    # Return string result
    return unpadded_data.decode()