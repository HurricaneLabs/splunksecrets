"""Command line tool for encrypting/decrypting Splunk passwords"""
from __future__ import print_function

import base64
import itertools
import os
import re
import struct

import click
import pcrypt
import six
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import algorithms, Cipher, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.padding import PKCS7


def b64decode(encoded):
    """Wrapper around `base64.b64decode` to add padding if necessary"""
    padding_len = 4 - (len(encoded) % 4)
    if padding_len < 4:
        encoded += "=" * padding_len
    return base64.b64decode(encoded)


def to_bytes(num, size, byte_order):
    """Function to convert a number to bytes"""
    fmt = ">" if byte_order.lower() == "big" else "<"
    fmt += "B" * int(size)
    num = bin(num)[2:].zfill(size * 8)
    args = [int(num[i:i+8], 2) for i in range(0, len(num), 8)]

    return struct.pack(fmt, *args)  # pylint: disable=no-member


def decrypt(secret, ciphertext, nosalt=False):
    """Given the first 16 bytes of splunk.secret, decrypt a Splunk password"""
    plaintext = None

    if ciphertext.startswith("$1$"):
        ciphertext = b64decode(ciphertext[3:])
        if len(secret) < 16:
            raise ValueError(f"secret too short, need 16 bytes, got {len(secret)}")
        key = secret[:16]

        algorithm = algorithms.ARC4(key)
        cipher = Cipher(algorithm, mode=None, backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext)

        chars = []
        if nosalt is False:
            for char1, char2 in zip(plaintext[:-1], itertools.cycle("DEFAULTSA")):
                if six.byte2int([char1]) == ord(char2):
                    chars.append(six.byte2int([char1]))
                else:
                    chars.append(six.byte2int([char1]) ^ ord(char2))
        else:
            chars = [six.byte2int([char]) for char in plaintext[:-1]]

        plaintext = "".join([six.unichr(c) for c in chars])
    elif ciphertext.startswith("$7$"):
        # pad secret to 254 bytes with nulls
        secret = six.ensure_binary(secret).ljust(254, b"\0")

        ciphertext = b64decode(ciphertext[3:])

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"disk-encryption",
            iterations=1,
            backend=default_backend()
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

    plaintext = b"".join([six.int2byte(c) for c in chars])

    algorithm = algorithms.ARC4(key)
    cipher = Cipher(algorithm, mode=None, backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext)
    ciphertext = base64.b64encode(ciphertext).decode()

    return f"$1${ciphertext}"


def encrypt_new(secret, plaintext, iv=None):  # pylint: disable=invalid-name
    """Use the new AES 256 GCM encryption in Splunk 7.2"""
    # pad secret to 254 bytes with nulls
    secret = six.ensure_binary(secret).ljust(254, b"\0")

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"disk-encryption",
        iterations=1,
        backend=default_backend()
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
    secret_key = six.ensure_binary(secret_key)

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
    secret_key = six.ensure_binary(secret_key)

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


def get_key_and_iv(password, salt, algorithm=hashes.MD5):
    """
    Python implementation of EVP_BytesToKey

    Based on https://gist.github.com/tly1980/b6c2cc10bb35cb4446fb6ccf5ee5efbc
    """
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


def decrypt_dbconnect(secret_key, ciphertext):
    """Implement `openssl aes-256-cbc` encryption as used in dbconnect"""

    # Get salt and actual ciphertext from input
    ciphertext = base64.b64decode(ciphertext)
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


def encrypt_dbconnect(secret_key, plaintext, salt=None):
    """Implement `openssl aes-256-cbc` decryption as used in dbconnect"""

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


def __ensure_binary(ctx, param, value):  # pragma: no cover
    # pylint: disable=unused-argument
    if value is None and not param.required:
        return None
    return six.ensure_binary(value)


def __ensure_int(ctx, param, value):  # pragma: no cover
    # pylint: disable=unused-argument
    if value is None and not param.required:
        return None
    try:
        return int(value)
    except ValueError:
        raise click.BadParameter(f"{param.name} should be int")  # pylint: disable=raise-missing-from


def __ensure_text(ctx, param, value):  # pragma: no cover
    # pylint: disable=unused-argument
    if value is None and not param.required:
        return None
    return six.ensure_text(value)


def __load_phantom_private_key(ctx, param, value):  # pragma: no cover
    # pylint: disable=unused-argument
    if ctx.get_parameter_source(param.name).name != "ENVIRONMENT":
        with open(value, "rb") as f:  # pylint: disable=invalid-name
            value = f.read().strip()

    # Validate the key loads
    serialization.load_pem_private_key(value, password=None)

    return value


def __load_phantom_secret_key(ctx, param, value):  # pragma: no cover
    # pylint: disable=unused-argument
    if ctx.get_parameter_source(param.name).name == "ENVIRONMENT":
        return value

    with open(value, "rb") as f:  # pylint: disable=invalid-name
        value = f.read().strip()
    m = re.search(  # pylint: disable=invalid-name
        six.b(r"^SECRET_KEY = '(?P<secret_key>.+)'$"),
        value,
        flags=re.MULTILINE
    )
    if not m:
        raise click.BadParameter("Malformed secret key file")
    return m.groupdict()["secret_key"]


def __load_splunk_secret(ctx, param, value):  # pragma: no cover
    # pylint: disable=unused-argument
    if ctx.get_parameter_source(param.name).name != "ENVIRONMENT":
        with open(value, "rb") as f:  # pylint: disable=invalid-name
            value = f.read().strip()

    return value.strip()


@click.group()
def main():  # pragma: no cover
    # pylint: disable=missing-function-docstring
    pass


@main.command("dbconnect-encrypt")
@click.option("-S", "--secret", required=True, envvar="DBCONNECT_SECRET",
              callback=__load_splunk_secret)
@click.option("--password", envvar="PASSWORD", prompt=True, hide_input=True,
              callback=__ensure_text)
def dbconnect_encrypt(secret, password):  # pragma: no cover
    """Encrypt password used for dbconnect identity"""
    click.echo(encrypt_dbconnect(secret, password))


@main.command("dbconnect-decrypt")
@click.option("-S", "--secret", required=True, envvar="DBCONNECT_SECRET",
              callback=__load_splunk_secret)
@click.option("--ciphertext", envvar="PASSWORD", prompt=True,
              callback=__ensure_text)
def dbconnect_decrypt(secret, ciphertext):  # pragma: no cover
    """Decrypt password used for dbconnect identity"""
    click.echo(decrypt_dbconnect(secret, ciphertext))


@main.command("phantom-encrypt")
@click.option("-P", "--private-key", required=True,
              envvar="PHANTOM_PRIVATE_KEY", callback=__load_phantom_private_key)
@click.option("-S", "--secret-key", required=True, envvar="PHANTOM_SECRET_KEY",
              callback=__load_phantom_secret_key)
@click.option("--password", envvar="PASSWORD", prompt=True, hide_input=True,
              callback=__ensure_text)
@click.option("-A", "--asset-id", envvar="PHANTOM_ASSET_ID", prompt=True,
              callback=__ensure_int)
def phantom_encrypt(private_key, secret_key, password, asset_id):  # pragma: no cover
    """Encrypt password used for Phantom asset"""
    click.echo(encrypt_phantom(private_key, secret_key, password, asset_id))


@main.command("phantom-decrypt")
@click.option("-P", "--private-key", required=True,
              envvar="PHANTOM_PRIVATE_KEY", callback=__load_phantom_private_key)
@click.option("-S", "--secret-key", required=True, envvar="PHANTOM_SECRET_KEY",
              callback=__load_phantom_secret_key)
@click.option("--ciphertext", envvar="PASSWORD", prompt=True,
              callback=__ensure_text)
@click.option("-A", "--asset-id", envvar="PHANTOM_ASSET_ID", prompt=True,
              callback=__ensure_int)
def phantom_decrypt(private_key, secret_key, ciphertext, asset_id):  # pragma: no cover
    """Decrypt password used for Phantom asset"""
    click.echo(decrypt_phantom(private_key, secret_key, ciphertext, asset_id))


@main.command("splunk-encrypt")
@click.option("-S", "--splunk-secret", required=True, envvar="SPLUNK_SECRET",
              callback=__load_splunk_secret)
@click.option("-I", "--iv", envvar="SPLUNK_IV", callback=__ensure_binary)
@click.option("--password", envvar="PASSWORD", prompt=True, hide_input=True,
              callback=__ensure_text)
def splunk_encrypt(splunk_secret, password, iv=None):  # pragma: no cover
    # pylint: disable=invalid-name
    """Encrypt password using Splunk 7.2 algorithm"""
    click.echo(encrypt_new(splunk_secret, password, iv))


@main.command("splunk-decrypt")
@click.option("-S", "--splunk-secret", required=True, envvar="SPLUNK_SECRET",
              callback=__load_splunk_secret)
@click.option("--ciphertext", envvar="PASSWORD", prompt=True,
              callback=__ensure_text)
def splunk_decrypt(splunk_secret, ciphertext):  # pragma: no cover
    """Decrypt password using Splunk 7.2 algorithm"""
    click.echo(decrypt(splunk_secret, ciphertext))


@main.command("splunk-legacy-encrypt")
@click.option("-S", "--splunk-secret", required=True, envvar="SPLUNK_SECRET",
              callback=__load_splunk_secret)
@click.option("--password", envvar="PASSWORD", prompt=True, hide_input=True,
              callback=__ensure_text)
@click.option("--no-salt/--salt", default=False)
def splunk_legacy_encrypt(splunk_secret, password, no_salt):  # pragma: no cover
    """Encrypt password using legacy Splunk algorithm (pre-7.2)"""
    click.echo(encrypt(splunk_secret, password, no_salt))


@main.command("splunk-legacy-decrypt")
@click.option("-S", "--splunk-secret", required=True, envvar="SPLUNK_SECRET",
              callback=__load_splunk_secret)
@click.option("--ciphertext", envvar="PASSWORD", prompt=True,
              callback=__ensure_text)
@click.option("--no-salt/--salt/=", default=False)
def splunk_legacy_decrypt(splunk_secret, ciphertext, no_salt):  # pragma: no cover
    """Decrypt password using legacy Splunk algorithm (pre-7.2)"""
    click.echo(decrypt(splunk_secret, ciphertext, no_salt))


@main.command("splunk-hash-passwd")
@click.option("--password", envvar="PASSWORD", prompt=True, hide_input=True,
              callback=__ensure_text)
def splunk_hash_passwd(password):  # pragma: no cover
    """Generate password hash for use in $SPLUNK_HOME/etc/passwd"""
    click.echo(pcrypt.crypt(password))
