"""Command line tool for encrypting/decrypting Splunk passwords"""

import argparse
import base64
import getpass
import itertools

import six
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import algorithms, Cipher


def decrypt(key, ciphertext):
    """Given the first 16 bytes of splunk.secret, decrypt a Splunk password"""
    if ciphertext.startswith("$1$"):
        ciphertext = base64.b64decode(ciphertext[3:])

    algorithm = algorithms.ARC4(key)
    cipher = Cipher(algorithm, mode=None, backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext)

    chars = []
    for char1, char2 in zip(plaintext[:-1], itertools.cycle("DEFAULTSA")):
        chars.append(six.byte2int([char1]) ^ ord(char2))

    return "".join([six.unichr(c) for c in chars])


def encrypt(key, plaintext):
    """Given the first 16 bytes of splunk.secret, encrypt a Splunk password"""
    chars = []
    for char1, char2 in zip(plaintext, itertools.cycle("DEFAULTSA")):
        chars.append(ord(char1) ^ ord(char2))
    chars.append(0)

    plaintext = b"".join([six.int2byte(c) for c in chars])

    algorithm = algorithms.ARC4(key)
    cipher = Cipher(algorithm, mode=None, backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext)

    return "$1$%s" % base64.b64encode(ciphertext).decode()


def main():  # pragma: no cover
    """Command line interface"""
    cliargs = argparse.ArgumentParser()
    cliargs.add_argument("--splunk-secret", required=True)
    cliargs.add_argument("-D", "--decrypt", action="store_const", dest="mode", const="decrypt")
    args = cliargs.parse_args()

    with open(args.splunk_secret, "rb") as splunk_secret_file:
        key = splunk_secret_file.read()[:16]

    if args.mode == "decrypt":
        try:
            ciphertext = six.moves.input("Encrypted password: ")
        except KeyboardInterrupt:
            pass
        else:
            print(decrypt(key, ciphertext))
    else:
        try:
            plaintext = getpass.getpass("Plaintext password: ")
        except KeyboardInterrupt:
            pass
        else:
            print(encrypt(key, plaintext))
