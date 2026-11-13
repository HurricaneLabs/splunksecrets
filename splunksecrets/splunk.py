import base64
import itertools
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.decrepit.ciphers.algorithms import ARC4
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def b64decode(encoded):
    """Wrapper around `base64.b64decode` to add padding if necessary"""
    padding_len = 4 - (len(encoded) % 4)
    if padding_len < 4:
        encoded += "=" * padding_len
    return base64.b64decode(encoded)


def decrypt_gcm(key: bytes, payload: bytes) -> str:
    """Decrypt an AES-256-GCM `iv + ciphertext + tag` payload, checking the tag.

    Raises:
        ValueError: The payload is too short, or the tag doesn't match, which
            means the wrong splunk.secret or a corrupted value.
    """
    if len(payload) < 32:
        raise ValueError("malformed ciphertext: too short to hold an iv and a tag")

    iv = payload[:16]
    tag = payload[-16:]
    ciphertext = payload[16:-16]

    algorithm = algorithms.AES(key)
    cipher = Cipher(algorithm, mode=modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    try:
        # finalize() checks the tag; decode only after it passes, or a wrong
        # secret surfaces as a UnicodeDecodeError instead
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    except InvalidTag:
        raise ValueError(
            "decryption failed: wrong splunk.secret or corrupted value"
        ) from None
    return plaintext.decode()


def decrypt(secret, ciphertext, nosalt=False):
    """Given the first 16 bytes of splunk.secret, decrypt a Splunk password"""
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

        plaintext = decrypt_gcm(key, ciphertext)
    elif ciphertext.startswith("$8$"):
        # pad secret to 254 bytes with nulls
        if isinstance(secret, str):
            secret = secret.encode()
        secret = secret.ljust(254, b"\0")

        parts = ciphertext.split("$")
        if len(parts) != 4:
            raise ValueError("malformed $8$ value: expected $8$<salt>$<payload>")
        _, _, b64salt, b64ciphertext = parts

        kdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b64decode(b64salt),
            info=b"disk-encryption-hkdf",
            backend=default_backend(),
        )
        key = kdf.derive(secret[:254])

        plaintext = decrypt_gcm(key, b64decode(b64ciphertext))
    else:
        raise ValueError(
            "unknown ciphertext format: expected a value starting with $1$, $7$ or $8$"
        )

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


def encrypt_new(secret, plaintext, iv=None):
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
    elif len(iv) != 16:
        raise ValueError(f"iv must be 16 bytes, got {len(iv)}")

    algorithm = algorithms.AES(key)
    cipher = Cipher(algorithm, mode=modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
    payload = base64.b64encode(b"%s%s%s" % (iv, ciphertext, encryptor.tag)).decode()

    return f"$7${payload}"


def encrypt_v8(secret, plaintext, salt=None, iv=None):
    """Use the new(er) FIPS-friendly AES 256 GCM encryption in Splunk 10.6

    `salt` and `iv` are raw 16-byte values; random ones are used when omitted.
    """

    if isinstance(secret, str):
        # pad secret to 254 bytes with nulls
        secret = secret.encode()
    secret = secret.ljust(254, b"\0")

    if salt is None:
        salt = os.urandom(16)
    elif len(salt) != 16:
        raise ValueError(f"salt must be 16 bytes, got {len(salt)}")

    kdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"disk-encryption-hkdf",
        backend=default_backend(),
    )
    key = kdf.derive(secret[:254])
    salt = base64.b64encode(salt).decode()

    if iv is None:
        iv = os.urandom(16)
    elif len(iv) != 16:
        raise ValueError(f"iv must be 16 bytes, got {len(iv)}")

    algorithm = algorithms.AES(key)
    cipher = Cipher(algorithm, mode=modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
    payload = base64.b64encode(b"%s%s%s" % (iv, ciphertext, encryptor.tag)).decode()

    return f"$8${salt}${payload}"
