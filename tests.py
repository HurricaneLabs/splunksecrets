import base64
import os
import random
import unittest

import six

import splunksecrets


splunk_secret = six.b(
                    "JX7cQAnH6Nznmild8MvfN8/BLQnGr8C3UYg3mqvc3ArFkaxj4gUt1RUCaRBD/r0CNn8xOA2oKX8"
                    "/0uyyChyGRiFKhp6h2FA+ydNIRnN46N8rZov8QGkchmebZa5GAM5U50GbCCgzJFObPyWi5yT8Cr"
                    "SCYmv9cpRtpKyiX+wkhJwltoJzAxWbBERiLp+oXZnN3lsRn6YkljmYBqN9tZLTVVpsLvqvkezPg"
                    "pv727Fd//5dRoWsWBv2zRp0mwDv3tj"
                )


class TestSplunkSecrets(unittest.TestCase):
    def test_encrypt(self):
        ciphertext = splunksecrets.encrypt(splunk_secret, "temp1234")
        self.assertEqual(ciphertext, "$1$n6g0W7F51ZAK")

    def test_encrypt_nosalt(self):
        ciphertext = splunksecrets.encrypt(splunk_secret, "temp1234", nosalt=True)
        self.assertEqual(ciphertext, "$1$2+1yGuQ1gcMK")

    def test_encrypt_new(self):
        ciphertext = splunksecrets.encrypt_new(
            splunk_secret,
            "temp1234",
            iv=six.b("i5dKMGaSIRNpJty4")
        )
        self.assertEqual(ciphertext, "$7$aTVkS01HYVNJUk5wSnR5NIu4GXLhj2Qd49n2B6Y8qmA/u1CdL9JYxQ==")

    def test_encrypt_character_matches_salt1(self):
        ciphertext = splunksecrets.encrypt(splunk_secret, "A" * 8)
        self.assertEqual(ciphertext, "$1$qowYK8EKp+UK")

    def test_encrypt_character_matches_salt2(self):
        ciphertext = splunksecrets.encrypt(splunk_secret, "DEFAULTSA" * 8)
        self.assertEqual(ciphertext, "$1$681ZK4BL5qRLsmMRT6EotpYVgOge69IZZhhxq0P+2ZBCaRTkci1IwiwRG9Ty2bHaSoG1p9QSXWIYA7mrYsyFqfWYqlvg+oQ+sg==")  # noqa: E501

    def test_decrypt(self):
        plaintext = splunksecrets.decrypt(splunk_secret, "$1$n6g0W7F51ZAK")
        self.assertEqual(plaintext, "temp1234")

    def test_decrypt_nosalt(self):
        plaintext = splunksecrets.decrypt(splunk_secret, "$1$2+1yGuQ1gcMK", nosalt=True)
        self.assertEqual(plaintext, "temp1234")

    def test_decrypt_new(self):
        plaintext = splunksecrets.decrypt(
            splunk_secret,
            "$7$aTVkS01HYVNJUk5wSnR5NIu4GXLhj2Qd49n2B6Y8qmA/u1CdL9JYxQ=="
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

    def test_end_to_end(self):
        splunk_secret = base64.b64encode(os.urandom(255))[:255]
        plaintext1 = base64.b64encode(os.urandom(255))[:24].decode()
        ciphertext = splunksecrets.encrypt(splunk_secret, plaintext1)
        plaintext2 = splunksecrets.decrypt(splunk_secret, ciphertext)
        self.assertEqual(plaintext2, plaintext1)

    def test_end_to_end_nosalt(self):
        splunk_secret = base64.b64encode(os.urandom(255))[:255]
        plaintext1 = base64.b64encode(os.urandom(255))[:24].decode()
        ciphertext = splunksecrets.encrypt(splunk_secret, plaintext1, nosalt=True)
        plaintext2 = splunksecrets.decrypt(splunk_secret, ciphertext, nosalt=True)
        self.assertEqual(plaintext2, plaintext1)

    def test_end_to_end_new(self):
        splunk_secret = base64.b64encode(os.urandom(255))[:255]
        plaintext1 = base64.b64encode(os.urandom(255))[:24].decode()
        ciphertext = splunksecrets.encrypt_new(splunk_secret, plaintext1)
        plaintext2 = splunksecrets.decrypt(splunk_secret, ciphertext)
        self.assertEqual(plaintext2, plaintext1)

    def test_end_to_end_character_matches_salt(self):
        splunk_secret = base64.b64encode(os.urandom(255))[:255]
        plaintext1 = "".join([random.choice("DEFAULTSA") for _ in range(24)])
        ciphertext = splunksecrets.encrypt(splunk_secret, plaintext1)
        plaintext2 = splunksecrets.decrypt(splunk_secret, ciphertext)
        self.assertEqual(plaintext2, plaintext1)
