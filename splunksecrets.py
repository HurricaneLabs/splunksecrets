"""Command line tool for encrypting/decrypting Splunk passwords"""
from __future__ import print_function

import argparse
import base64
import getpass
import hashlib
import itertools
import os

import pcrypt
import pyaes
import six
from pprp.pbkdf2 import _pbkdf2 as pbkdf2
# from cryptography.hazmat.backends import default_backend
# from cryptography.hazmat.primitives import hashes
# from cryptography.hazmat.primitives.ciphers import algorithms, Cipher, modes
# from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def arcfour(key, plaintext):
    """RC4 algorithm, based on wikipedia pseudo-code"""
    S = list(range(256))  # pylint: disable=invalid-name
    keylength = len(key)

    j = 0  # pylint: disable=invalid-name
    for i in range(256):  # pylint: disable=invalid-name
        j = (j + S[i] + six.byte2int([key[i % keylength]])) % 256
        S[i], S[j] = S[j], S[i]

    output = []
    i = 0  # pylint: disable=invalid-name
    j = 0  # pylint: disable=invalid-name
    for char1 in plaintext:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        K = (S[i] + S[j]) % 256  # pylint: disable=invalid-name

        char1 = six.byte2int([char1])
        output.append(six.int2byte(char1 ^ S[K]))

    return b"".join(output)


def bytes_to_long(byteslist):
    """Convert a byte string to long"""
    values = []
    for (shift, byt) in enumerate(reversed(byteslist)):
        values.append(six.byte2int([byt]) << (8 * shift))
    return sum(values, 0)


def long_to_bytes(number, length=0):
    """Convert a long to a byte string, padded with \x00 to `length`"""
    byteslist = bytes()
    while number:
        value, number = number & 0xff, number >> 8
        byteslist = six.int2byte(value) + byteslist

    if length and length > len(byteslist):
        pad = length - len(byteslist)
        byteslist = six.b("\x00" * pad) + byteslist
    elif length and length < len(byteslist):
        byteslist = byteslist[:length]
    return byteslist


class Counter:
    """Custom counter implementation supporting prefixes"""
    def __init__(self, initial_value=1, prefix=None, max_value=0xffffffff):
        self._counter = initial_value
        self._max_value = max_value
        self._prefix = prefix

    @property
    def value(self):
        """Bytes representation of the counter, with prefix"""
        value = long_to_bytes(self._counter, 4)
        if self._prefix:
            value = self._prefix + value

        return [six.byte2int([byt]) for byt in value]

    def increment(self):
        """Increment the counter, overflow at `max_value`"""
        if self._counter == self._max_value:
            self._counter = 0
        else:
            self._counter += 1


# Galois/Counter Mode with AES-128 and 96-bit IV
class AesGcm:
    """
        Copyright (C) 2013 Bo Zhu http://about.bozhu.me
        Permission is hereby granted, free of charge, to any person obtaining a
        copy of this software and associated documentation files (the "Software"),
        to deal in the Software without restriction, including without limitation
        the rights to use, copy, modify, merge, publish, distribute, sublicense,
        and/or sell copies of the Software, and to permit persons to whom the
        Software is furnished to do so, subject to the following conditions:
        The above copyright notice and this permission notice shall be included in
        all copies or substantial portions of the Software.
        THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
        IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
        FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
        THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
        LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
        FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
        DEALINGS IN THE SOFTWARE.
    """

    @staticmethod
    def gf_2_128_mul(x, y):  # pylint: disable=invalid-name
        """
        GF(2^128) defined by 1 + a + a^2 + a^7 + a^128
        Please note the MSB is x0 and LSB is x127
        """
        res = 0
        for i in range(127, -1, -1):
            res ^= x * ((y >> i) & 1)  # branchless
            x = (x >> 1) ^ ((x & 1) * 0xE1000000000000000000000000000000)
        return res

    def __init__(self, master_key):
        if isinstance(master_key, six.binary_type):
            master_key = bytes_to_long(master_key)

        self.change_key(master_key)

    def change_key(self, master_key):
        """Given a new master key, prepare a new auth key"""
        self.__master_key = long_to_bytes(master_key, 32)
        self.__aes_ecb = pyaes.AESModeOfOperationECB(self.__master_key)
        self.__auth_key = bytes_to_long(self.__aes_ecb.encrypt(b"\x00" * 16))

        # precompute the table for multiplication in finite field
        table = []  # for 8-bit
        for i in range(16):
            row = []
            for j in range(256):
                row.append(self.gf_2_128_mul(self.__auth_key, j << (8 * i)))
            table.append(tuple(row))
        self.__pre_table = tuple(table)

    def __times_auth_key(self, val):
        res = 0
        for i in range(16):
            res ^= self.__pre_table[i][val & 0xFF]
            val >>= 8
        return res

    def __ghash(self, txt):
        len_txt = len(txt)

        # padding
        data = bytes()
        if len_txt % 16 == 0:
            data += txt
        else:
            data += txt + six.b("\x00" * (16 - len_txt % 16))

        tag = 0
        for i in range(len(data) // 16):
            tag ^= bytes_to_long(data[i * 16: (i + 1) * 16])
            tag = self.__times_auth_key(tag)
            # print "X\t", hex(tag)
        tag ^= 8 * len_txt
        tag = self.__times_auth_key(tag)

        return tag

    def encrypt(self, init_value, plaintext):
        """Encrypt data"""
        if isinstance(init_value, six.binary_type):
            init_value = bytes_to_long(init_value)

        if isinstance(plaintext, six.text_type):
            plaintext = plaintext.encode()

        iv_bytes = long_to_bytes(init_value)
        initial_counter_bytes = long_to_bytes(self.__ghash(iv_bytes), 16)

        counter_prefix = initial_counter_bytes[:12]
        initial_counter_value = bytes_to_long(initial_counter_bytes[12:])

        len_plaintext = len(plaintext)

        counter = Counter(initial_value=initial_counter_value + 1, prefix=counter_prefix)
        aes_ctr = pyaes.AESModeOfOperationCTR(self.__master_key, counter)

        if len_plaintext % 16 != 0:
            padded_plaintext = plaintext + \
                b"\x00" * (16 - len_plaintext % 16)
        else:
            padded_plaintext = plaintext
        ciphertext = aes_ctr.encrypt(padded_plaintext)[:len_plaintext]

        auth_tag = self.__ghash(ciphertext)
        auth_tag ^= bytes_to_long(self.__aes_ecb.encrypt(initial_counter_bytes))

        return ciphertext, auth_tag

    def decrypt(self, init_value, ciphertext, auth_tag):
        """Decrypt data"""
        if isinstance(init_value, six.binary_type):
            init_value = bytes_to_long(init_value)

        iv_bytes = long_to_bytes(init_value)
        if len(iv_bytes) == 12:
            initial_counter_bytes = iv_bytes + six.b("\x00\x00\x00\x01")
        else:
            initial_counter_bytes = long_to_bytes(self.__ghash(iv_bytes), 16)

        counter_prefix = initial_counter_bytes[:12]
        initial_counter_value = bytes_to_long(initial_counter_bytes[12:])

        ghash = self.__ghash(ciphertext)
        ghash = ghash ^ bytes_to_long(
            self.__aes_ecb.encrypt(
                counter_prefix + long_to_bytes(initial_counter_value, 4)
            )
        )
        if auth_tag != long_to_bytes(ghash):
            return False, None

        len_ciphertext = len(ciphertext)
        counter = Counter(initial_value=initial_counter_value + 1, prefix=counter_prefix)
        aes_ctr = pyaes.AESModeOfOperationCTR(self.__master_key, counter)

        if len_ciphertext % 16 != 0:
            padded_ciphertext = ciphertext + \
                b"\x00" * (16 - len_ciphertext % 16)
        else:  # pragma: no cover
            padded_ciphertext = ciphertext
        plaintext = aes_ctr.decrypt(padded_ciphertext)[:len_ciphertext]

        plaintext = plaintext.decode()

        return True, plaintext


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
            raise ValueError("secret too short, need 16 bytes, got %d" % len(secret))
        key = secret[:16]

        # algorithm = algorithms.ARC4(key)
        # cipher = Cipher(algorithm, mode=None, backend=default_backend())
        # decryptor = cipher.decryptor()
        # plaintext = decryptor.update(ciphertext)
        plaintext = arcfour(key, ciphertext)

        chars = []
        if nosalt is False:
            for char1, char2 in six.moves.zip(plaintext[:-1], itertools.cycle("DEFAULTSA")):
                if six.byte2int([char1]) == ord(char2):
                    chars.append(six.byte2int([char1]))
                else:
                    chars.append(six.byte2int([char1]) ^ ord(char2))
        else:
            chars = [six.byte2int([char]) for char in plaintext[:-1]]

        plaintext = "".join([six.unichr(c) for c in chars])
    elif ciphertext.startswith("$7$"):
        if len(secret) < 254:
            raise ValueError("secret too short, need 254 bytes, got %d" % len(secret))
        ciphertext = b64decode(ciphertext[3:])

        # kdf = PBKDF2HMAC(
        #     algorithm=hashes.SHA256(),
        #     length=32,
        #     salt=b"disk-encryption",
        #     iterations=1,
        #     backend=default_backend()
        # )
        # key = kdf.derive(secret[:254])

        iv = ciphertext[:16]  # pylint: disable=invalid-name
        tag = ciphertext[-16:]
        ciphertext = ciphertext[16:-16]

        # algorithm = algorithms.AES(key)
        # cipher = Cipher(algorithm, mode=modes.GCM(iv, tag), backend=default_backend())
        # decryptor = cipher.decryptor()
        # plaintext = decryptor.update(ciphertext).decode()

        key = pbkdf2(
            digestmod=hashlib.sha256,
            password=secret[:254],
            salt=b"disk-encryption",
            count=1,
            dk_length=32
        )

        success, plaintext = AesGcm(key).decrypt(iv, ciphertext, tag)
        if not success:
            raise ValueError("failed to decrypt")

    return plaintext


def encrypt(secret, plaintext, nosalt=False):
    """Given the first 16 bytes of splunk.secret, encrypt a Splunk password"""
    if len(secret) < 16:
        raise ValueError("secret too short, need 16 bytes, got %d" % len(secret))

    key = secret[:16]

    chars = []
    if nosalt is False:
        for char1, char2 in six.moves.zip(plaintext, itertools.cycle("DEFAULTSA")):
            if ord(char1) == ord(char2):
                chars.append(ord(char1))
            else:
                chars.append(ord(char1) ^ ord(char2))
    else:
        chars = [ord(x) for x in plaintext]

    chars.append(0)

    plaintext = b"".join([six.int2byte(c) for c in chars])

    # algorithm = algorithms.ARC4(key)
    # cipher = Cipher(algorithm, mode=None, backend=default_backend())
    # encryptor = cipher.encryptor()
    # ciphertext = encryptor.update(plaintext)
    ciphertext = arcfour(key, plaintext)

    return "$1$%s" % base64.b64encode(ciphertext).decode()


def encrypt_new(secret, plaintext, iv=None):  # pylint: disable=invalid-name
    """Use the new AES 256 GCM encryption in Splunk 7.2"""
    if len(secret) < 254:
        raise ValueError("secret too short, need 254 bytes, got %d" % len(secret))

    # kdf = PBKDF2HMAC(
    #     algorithm=hashes.SHA256(),
    #     length=32,
    #     salt=b"disk-encryption",
    #     iterations=1,
    #     backend=default_backend()
    # )
    # key = kdf.derive(secret[:254])

    if iv is None:
        iv = os.urandom(16)

    # algorithm = algorithms.AES(key)
    # cipher = Cipher(algorithm, mode=modes.GCM(iv), backend=default_backend())
    # encryptor = cipher.encryptor()
    # ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()

    key = pbkdf2(
        digestmod=hashlib.sha256,
        password=secret[:254],
        salt=b"disk-encryption",
        count=1,
        dk_length=32
    )

    ciphertext, tag = AesGcm(key).encrypt(iv, plaintext)
    tag = long_to_bytes(tag)

    return "$7$%s" % base64.b64encode(b"%s%s%s" % (iv, ciphertext, tag)).decode()


def main():  # pragma: no cover
    """Command line interface"""
    cliargs = argparse.ArgumentParser()

    cliargs.add_argument("--splunk-secret", required=False, type=six.ensure_binary,
                         default=os.environ.get("SPLUNK_SECRET"))
    cliargs.add_argument("--splunk-secret-text", required=False, type=six.ensure_binary,
                         default=os.environ.get("SPLUNK_SECRET"))
    cliargs.add_argument("-D", "--decrypt", action="store_const", dest="mode", const="decrypt")
    cliargs.add_argument("-H", "--hash-passwd", action="store_const", dest="mode", const="hash")
    cliargs.add_argument("--new", action="store_const", dest="mode", const="encrypt_new")
    cliargs.add_argument("--nosalt", action="store_true", dest="nosalt")
    cliargs.add_argument("--password", default=os.environ.get("PASSWORD"))
    args = cliargs.parse_args()

    if args.splunk_secret:
        with open(args.splunk_secret, "rb") as splunk_secret_file:
            key = splunk_secret_file.read().strip()
    elif args.splunk_secret_text:
        key = args.splunk_secret_text.strip()
    elif args.mode != "hash":
        raise argparse.ArgumentTypeError("--splunk-secret or --splunk-secret-text must be defined")

    try:
        if args.mode == "decrypt":
            ciphertext = args.password or six.moves.input("Encrypted password: ")
            if ciphertext.startswith("$6$"):
                output = "Cannot decrypt Splunk user passwords - passwords are hashed not encrypted"
            else:
                output = decrypt(key, ciphertext, args.nosalt)
        elif args.mode == "hash":
            ciphertext = args.password or getpass.getpass("Password: ")
            output = pcrypt.crypt(ciphertext)
        else:
            plaintext = args.password or getpass.getpass("Plaintext password: ")
            if args.mode == "encrypt_new":
                output = encrypt_new(key, plaintext)
            else:
                output = encrypt(key, plaintext, args.nosalt)
    except KeyboardInterrupt:
        pass
    else:
        print(output)
