import base64
import os
import random
import unittest

import six
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key

import splunksecrets


splunk_secret = six.b(
                    "JX7cQAnH6Nznmild8MvfN8/BLQnGr8C3UYg3mqvc3ArFkaxj4gUt1RUCaRBD/r0CNn8xOA2oKX8"
                    "/0uyyChyGRiFKhp6h2FA+ydNIRnN46N8rZov8QGkchmebZa5GAM5U50GbCCgzJFObPyWi5yT8Cr"
                    "SCYmv9cpRtpKyiX+wkhJwltoJzAxWbBERiLp+oXZnN3lsRn6YkljmYBqN9tZLTVVpsLvqvkezPg"
                    "pv727Fd//5dRoWsWBv2zRp0mwDv3t\n"
                )

phantom_private_key = six.b("""
-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----
""".strip())
phantom_secret = six.b("bhxiegi%@^76toslu+7olp2fx)taw%vcqoxlhlr27^ri3i41vt")

dbconnect_secret = six.b("WeUSgc35gxALVesK01Z91MASQNl4E1NvYfmc5zC7KXI=")


class TestSplunkSecrets(unittest.TestCase):
    def test_to_bytes(self):
        self.assertEqual(
            splunksecrets.to_bytes(1234, 16, "big"),
            six.b(
                "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\xd2"
            )
        )

    def test_encrypt(self):
        ciphertext = splunksecrets.encrypt(splunk_secret, "temp1234")
        self.assertEqual(ciphertext, "$1$n6g0W7F51ZAK")

    def test_encrypt_nosalt(self):
        ciphertext = splunksecrets.encrypt(splunk_secret, "temp1234", nosalt=True)
        self.assertEqual(ciphertext, "$1$2+1yGuQ1gcMK")

    def test_encrypt_raises_value_error_short_secret(self):
        with self.assertRaises(ValueError):
            splunk_secret = base64.b64encode(os.urandom(255))[:15]
            splunksecrets.encrypt(splunk_secret, "temp1234")

    def test_encrypt_new(self):
        ciphertext = splunksecrets.encrypt_new(
            splunk_secret,
            "temp1234",
            iv=six.b("i5dKMGaSIRNpJty4")
        )
        self.assertEqual(ciphertext, "$7$aTVkS01HYVNJUk5wSnR5NKR+EdOfT4t84WSiXvPFHGHsfHtbgPIL3g==")

    def test_encrypt_new_pads_short_secret(self):
        ciphertext = splunksecrets.encrypt_new(
            splunk_secret[:30],
            "short123",
            iv=six.b("4KK0Ra8LWBKxUFQ8")
        )
        self.assertEqual(ciphertext, "$7$NEtLMFJhOExXQkt4VUZROK9vm0tDLbJn2jxESMRbs7MTdiHuTtBz8g==")

    def test_encrypt_character_matches_salt1(self):
        ciphertext = splunksecrets.encrypt(splunk_secret, "A" * 8)
        self.assertEqual(ciphertext, "$1$qowYK8EKp+UK")

    def test_encrypt_character_matches_salt2(self):
        ciphertext = splunksecrets.encrypt(splunk_secret, "DEFAULTSA" * 8)
        self.assertEqual(ciphertext, "$1$681ZK4BL5qRLsmMRT6EotpYVgOge69IZZhhxq0P+2ZBCaRTkci1IwiwRG9Ty2bHaSoG1p9QSXWIYA7mrYsyFqfWYqlvg+oQ+sg==")  # noqa: E501

    def test_encrypt_phantom(self):
        ciphertext = splunksecrets.encrypt_phantom(phantom_private_key, phantom_secret, "temp1234", 1234)
        self.assertEqual(ciphertext, "9Uzb3CO0PFFRUk0upbNvrA==")

    def test_decrypt(self):
        plaintext = splunksecrets.decrypt(splunk_secret, "$1$n6g0W7F51ZAK")
        self.assertEqual(plaintext, "temp1234")

    def test_decrypt_raises_value_error_short_secret1(self):
        with self.assertRaises(ValueError):
            splunk_secret = base64.b64encode(os.urandom(255))[:15]
            splunksecrets.decrypt(splunk_secret, "$1$n6g0W7F51ZAK")

    def test_decrypt_pads_short_secret2(self):
        plaintext = splunksecrets.decrypt(
            splunk_secret[:30],
            "$7$NEtLMFJhOExXQkt4VUZROK9vm0tDLbJn2jxESMRbs7MTdiHuTtBz8g=="
        )
        self.assertEqual(plaintext, "short123")

    def test_decrypt_nosalt(self):
        plaintext = splunksecrets.decrypt(splunk_secret, "$1$2+1yGuQ1gcMK", nosalt=True)
        self.assertEqual(plaintext, "temp1234")

    def test_decrypt_new(self):
        plaintext = splunksecrets.decrypt(
            splunk_secret,
            "$7$aTVkS01HYVNJUk5wSnR5NKR+EdOfT4t84WSiXvPFHGHsfHtbgPIL3g=="
        )
        self.assertEqual(plaintext, "temp1234")

    def test_decrypt_character_matches_salt1(self):
        plaintext = splunksecrets.decrypt(
            splunk_secret,
            "$1$qowYK8EKp+UK"
        )
        self.assertEqual(plaintext, "A" * 8)

    def test_decrypt_character_matches_salt2(self):
        plaintext = splunksecrets.decrypt(
            splunk_secret,
            "$1$681ZK4BL5qRLsmMRT6EotpYVgOge69IZZhhxq0P+2ZBCaRTkci1IwiwRG9Ty2bHaSoG1p9QSXWIYA7mrYsyFqfWYqlvg+oQ+sg=="  # noqa: E501
        )
        self.assertEqual(plaintext, "DEFAULTSA" * 8)

    def test_decrypt_unpadded_base64(self):
        plaintext = splunksecrets.decrypt(
            splunk_secret,
            "$1$iqw4ag"
        )
        self.assertEqual(plaintext, "aaa")

    def test_decrypt_phantom(self):
        plaintext = splunksecrets.decrypt_phantom(phantom_private_key, phantom_secret, "9Uzb3CO0PFFRUk0upbNvrA==", 1234)
        self.assertEqual(plaintext, "temp1234")

    def test_end_to_end(self):
        splunk_secret = base64.b64encode(os.urandom(255))[:254]
        plaintext1 = base64.b64encode(os.urandom(255))[:24].decode()
        ciphertext = splunksecrets.encrypt(splunk_secret, plaintext1)
        plaintext2 = splunksecrets.decrypt(splunk_secret, ciphertext)
        self.assertEqual(plaintext2, plaintext1)

    def test_end_to_end_nosalt(self):
        splunk_secret = base64.b64encode(os.urandom(255))[:254]
        plaintext1 = base64.b64encode(os.urandom(255))[:24].decode()
        ciphertext = splunksecrets.encrypt(splunk_secret, plaintext1, nosalt=True)
        plaintext2 = splunksecrets.decrypt(splunk_secret, ciphertext, nosalt=True)
        self.assertEqual(plaintext2, plaintext1)

    def test_end_to_end_new(self):
        splunk_secret = base64.b64encode(os.urandom(255))[:254]
        plaintext1 = base64.b64encode(os.urandom(255))[:24].decode()
        ciphertext = splunksecrets.encrypt_new(splunk_secret, plaintext1)
        plaintext2 = splunksecrets.decrypt(splunk_secret, ciphertext)
        self.assertEqual(plaintext2, plaintext1)

    def test_end_to_end_character_matches_salt(self):
        splunk_secret = base64.b64encode(os.urandom(255))[:254]
        plaintext1 = "".join([random.choice("DEFAULTSA") for _ in range(24)])
        ciphertext = splunksecrets.encrypt(splunk_secret, plaintext1)
        plaintext2 = splunksecrets.decrypt(splunk_secret, ciphertext)
        self.assertEqual(plaintext2, plaintext1)

    def test_encrypt_new_and_decrypt_use_only_first_254(self):
        splunk_secret1 = base64.b64encode(os.urandom(512))[:300]
        splunk_secret2 = splunk_secret1[:254]
        plaintext1 = base64.b64encode(os.urandom(255))[:24].decode()
        ciphertext = splunksecrets.encrypt_new(splunk_secret1, plaintext1)
        plaintext2 = splunksecrets.decrypt(splunk_secret2, ciphertext)
        self.assertEqual(plaintext2, plaintext1)

    def test_end_to_end_phantom(self):
        __phantom_private_key = generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        __phantom_private_key = __phantom_private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()
        )
        chars = "abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*(-_=+)"

        __phantom_secret = "".join(random.choice(chars) for _ in range(50))

        asset_id = random.randint(0, 999999)

        plaintext1 = base64.b64encode(os.urandom(255))[:24].decode()
        ciphertext = splunksecrets.encrypt_phantom(
            __phantom_private_key,
            __phantom_secret,
            plaintext1,
            asset_id
        )
        plaintext2 = splunksecrets.decrypt_phantom(
            __phantom_private_key,
            __phantom_secret,
            ciphertext,
            asset_id
        )
        self.assertEqual(plaintext2, plaintext1)

    def test_get_key_and_iv_1(self):
        key, iv = splunksecrets.get_key_and_iv(dbconnect_secret, six.b(" ") * 8)
        self.assertEqual(
            key,
            six.b("\xd5\x7f\x00\xab\xb2\xaa\xbf\x9a\xab\x00\x9bH\x08\x14+\xd0"
                  "\xf4d\xeb\xfa\xfc8\xa1J\x92v\xed\xed\x90X\xb4\x9c")
        )
        self.assertEqual(
            iv,
            six.b("\x1d\xd4\x97A\x06t\xc0\x9bv\xe78o\x84CwF")
        )

    def test_get_key_and_iv_2(self):
        key, iv = splunksecrets.get_key_and_iv(dbconnect_secret, six.b("0") * 8)
        self.assertEqual(
            key,
            six.b("Br\xc9\x08\xecL\x1b\t\x95\x12\xbc\x8c\xa4\xd8\xaf\x9f\x97w"
                  "\x8dy\x8bS\xd2riJ\x07Ls\x04\x98\x9a")
        )
        self.assertEqual(
            iv,
            six.b('\xe9{w^\x8e{s\x81\xe3*\x02\x04\xf8j"\xcb')
        )

    def test_encrypt_dbconnect(self):
        ciphertext = splunksecrets.encrypt_dbconnect(
            dbconnect_secret,
            "temp1234",
            salt=six.b("saup)j99")
        )
        self.assertEqual(ciphertext, "U2FsdGVkX19zYXVwKWo5ORLxPm8l7hVgaxH/DGPlq3c=")

    def test_decrypt_dbconnect(self):
        plaintext = splunksecrets.decrypt_dbconnect(
            dbconnect_secret,
            b"U2FsdGVkX19zYXVwKWo5ORLxPm8l7hVgaxH/DGPlq3c="
        )
        self.assertEqual(plaintext, "temp1234")

    def test_end_to_end_dbconnect(self):
        __dbconnect_secret = base64.b64encode(os.urandom(32))

        plaintext1 = base64.b64encode(os.urandom(255))[:24].decode()
        ciphertext = splunksecrets.encrypt_dbconnect(
            __dbconnect_secret,
            plaintext1
        )
        plaintext2 = splunksecrets.decrypt_dbconnect(
            __dbconnect_secret,
            ciphertext
        )
        self.assertEqual(plaintext2, plaintext1)
