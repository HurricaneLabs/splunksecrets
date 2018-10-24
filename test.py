import argparse
import base64
import getpass
import itertools
import sys

import six
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import algorithms, Cipher, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

backend = default_backend()

# key = "XjbVu1cHbINmbYJR9u5DWYGZ3Mii2O/ve//GdeONhSfwLRIGhIs9PP0Wq86JW/sZOKQ8LeIQBQePGVqFWBqCuPH.QZvMEFzyEmZfUkRsVB7zf4Z3ce8p5fYxAmhTh553b16TQ2G5yCO25QNl1IzRL9oNdr2j7MXiGKhNQKwRpI/95rLY0XvwYzsqHtMtC0Idf0fU7DSwcyQj.g9vBipCol4O3b1OhZDBTL/SoGaawIr7xj44tFYhoPu/rzHCr5"[:16]
# with open("/Users/steve/splunk/etc/auth/splunk.secret", "rb") as f:
#     secret = f.read().strip()
secret = b"YvGpxun5BS7H8HQG0iNDhXCnARLSI.hvhyaX2LHSiS0qoyse8JI.jKHhY0eJUdnC3J23NvTD4/DXMQHFmyb7PIqN06x3MYi8m6yFqqp3kVx.Qvd7.ByHZgSJXQh9eKkCbzZROB.50Alj5kTw7H97DwfO/QEcj3Mj6kdbbkEFJEoOJ2jhB5Ro0bUJtAZpHlEsQ.Y9ExvK7wPaLXHWVTiHDUOJMhEFwNgMRxVx7xpKS8QES/78QxgyZl4x6XalCy"

kdf = kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=b"disk-encryption",
    iterations=1,
    backend=default_backend()
)
key = kdf.derive(secret)
# print(len(key))
# sys.exit()

# def decrypt(key, ciphertext, iv, salt="DEFAULTSA"):
#     """Given the first 16 bytes of splunk.secret, decrypt a Splunk password"""
#     if ciphertext.startswith("$1$"):
#         ciphertext = base64.b64decode(ciphertext[3:])
#
#     algorithm = algorithms.AES(key)
#     cipher = Cipher(algorithm, mode=modes.CTR(iv), backend=default_backend())
#     decryptor = cipher.decryptor()
#     plaintext = decryptor.update(ciphertext)
#     return plaintext
#
#     chars = []
#     for char1, char2 in zip(plaintext[:-1], itertools.cycle(salt)):
#         chars.append(six.byte2int([char1]) ^ ord(char2))
#
#     return "".join([six.unichr(c) for c in chars])

def decrypt(key, iv, tag, ciphertext):
    """Given the first 16 bytes of splunk.secret, decrypt a Splunk password"""
    if ciphertext.startswith(b"$1$"):
        ciphertext = base64.b64decode(ciphertext[3:])

    algorithm = algorithms.AES(key)
    cipher = Cipher(algorithm, mode=modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext)
    return plaintext

    chars = []
    for char1, char2 in zip(plaintext[:-1], itertools.cycle("DEFAULTSA")):
        chars.append(six.byte2int([char1]) ^ ord(char2))

    return "".join([six.unichr(c) for c in chars])

ct1 = base64.b64decode(b"9+jpGm3BNDZbmnsde8MVBQfFvU1v1ku2P0BEerb9mjh2+9Y=")
# for i, x in enumerate([hex(ord(x)) for x in ct1]):
#     print("%s: %s" % (i,x))

iv = ct1[:16]
tag = ct1[-16:]
ct = ct1[16:-16]

print(iv)
print(tag)
print(ct)

# print(len(tag))
# print(len(iv))
# print(len(ct))

pt1 = decrypt(key, iv, tag, ct)
print(pt1)

# print("R\tpt\tR\ts\tu1")
# for c1, c2, u1 in zip(pt1, "foo", itertools.cycle(ct1)):
#     s = six.byte2int([c1]) ^ ord(c2)
#     print("%s\t%s\t%s\t%s\t%s" % (c2, hex(ord(c1)), hex(ord(c2)), hex(s), hex(ord(u1))))

# cts = map(base64.b64decode, [
#     b"OCz9ZqhhqxO1I0zbONgFTAk8HpoCB+qrI2D3oizPgEgD",            # f
#     b"zXH5w6BfJrZC8PqS2f/iaslahhAFyEHsblT4TzYkOIlp5HA=",        # foo
#     b"PxGknoVb0expVb48Fd045r9RP/WlMy5CivvWiGxdc5Pneeyp",        # foo1
#     b"G4HrZve6989SH2h9ScqzOufHKYMPh82tZ6JEE/370LXPthL1qg==",    # foo11
#     b"X4jdwDpUIxwiUvaFVL4O8Vzylp4zGbC1FstmX4F/H2mtdx8/Lx4=",    # foo111
# ])
#
# for ct in cts:
#     # for i, char in enumerate(ct):
#     #     print("%s: %s" % (i, ord(char)))
#
#     salt, iv, ct = ct[:16], ct[16:32], ct[32:]
#
#     key = secret[:24]
#     pt = decrypt(key, ct, iv, salt)
#     print(hex(ord(pt[0])))
