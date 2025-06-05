import base64
import itertools
import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.decrepit.ciphers.algorithms import ARC4
from cryptography.hazmat.primitives.ciphers import algorithms, Cipher, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


def b64decode(encoded):
    """Wrapper around `base64.b64decode` to add padding if necessary"""
    padding_len = 4 - (len(encoded) % 4)
    if padding_len < 4:
        encoded += "=" * padding_len
    return base64.b64decode(encoded)


def decrypt(secret, ciphertext, nosalt=False):
    """Given the first 16 bytes of splunk.secret, decrypt a Splunk password"""
    plaintext = None

    if ciphertext.startswith("$1$"):
        ciphertext = b64decode(ciphertext[3:])
        if len(secret) < 16:
            raise ValueError(f"secret too short, need 16 bytes, got {len(secret)}")
        key = secret[:16]

        algorithm = ARC4(key)
        cipher = Cipher(algorithm, mode=None, backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext)

        chars = []
        if nosalt is False:
            for char1, char2 in zip(plaintext[:-1], itertools.cycle("DEFAULTSA")):
                if char1 == ord(char2):
                    chars.append(char1)
                else:
                    chars.append(char1 ^ ord(char2))
        else:
            chars = plaintext[:-1]

        plaintext = "".join([chr(c) for c in chars])
    elif ciphertext.startswith("$7$"):
        # pad secret to 254 bytes with nulls
        if isinstance(secret, str):
            secret = secret.encode()
        secret = secret.ljust(254, b"\0")

        ciphertext = b64decode(ciphertext[3:])

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"disk-encryption",
            iterations=1,
            backend=default_backend(),
        )
        key = kdf.derive(secret[:254])

        iv = ciphertext[:16]  # pylint: disable=invalid-name
        tag = ciphertext[-16:]
        ciphertext = ciphertext[16:-16]

        algorithm = algorithms.AES(key)
        cipher = Cipher(algorithm, mode=modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext).decode()

    return plaintext


def encrypt(secret, plaintext, nosalt=False):
    """Given the first 16 bytes of splunk.secret, encrypt a Splunk password"""
    if len(secret) < 16:
        raise ValueError(f"secret too short, need 16 bytes, got {len(secret)}")

    key = secret[:16]

    chars = []
    if nosalt is False:
        for char1, char2 in zip(plaintext, itertools.cycle("DEFAULTSA")):
            if ord(char1) == ord(char2):
                chars.append(ord(char1))
            else:
                chars.append(ord(char1) ^ ord(char2))
    else:
        chars = [ord(x) for x in plaintext]

    chars.append(0)

    plaintext = b"".join([bytes([c]) for c in chars])

    algorithm = ARC4(key)
    cipher = Cipher(algorithm, mode=None, backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext)
    ciphertext = base64.b64encode(ciphertext).decode()

    return f"$1${ciphertext}"


def encrypt_new(secret, plaintext, iv=None):  # pylint: disable=invalid-name
    """Use the new AES 256 GCM encryption in Splunk 7.2"""

    if isinstance(secret, str):
        # pad secret to 254 bytes with nulls
        secret = secret.encode()
    secret = secret.ljust(254, b"\0")

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"disk-encryption",
        iterations=1,
        backend=default_backend(),
    )
    key = kdf.derive(secret[:254])

    if iv is None:
        iv = os.urandom(16)

    algorithm = algorithms.AES(key)
    cipher = Cipher(algorithm, mode=modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
    payload = base64.b64encode(b"%s%s%s" % (iv, ciphertext, encryptor.tag)).decode()

    return f"$7${payload}"
