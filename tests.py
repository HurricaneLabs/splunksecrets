import base64
import os
import random
import unittest

import six

import splunksecrets
from splunksecrets import bytes_to_long, long_to_bytes


splunk_secret = six.b(
                    "JX7cQAnH6Nznmild8MvfN8/BLQnGr8C3UYg3mqvc3ArFkaxj4gUt1RUCaRBD/r0CNn8xOA2oKX8"
                    "/0uyyChyGRiFKhp6h2FA+ydNIRnN46N8rZov8QGkchmebZa5GAM5U50GbCCgzJFObPyWi5yT8Cr"
                    "SCYmv9cpRtpKyiX+wkhJwltoJzAxWbBERiLp+oXZnN3lsRn6YkljmYBqN9tZLTVVpsLvqvkezPg"
                    "pv727Fd//5dRoWsWBv2zRp0mwDv3t\n"
                )


class TestSplunkSecrets(unittest.TestCase):
    def test_long_to_bytes(self):
        self.assertEqual(long_to_bytes(0xdeadbeef), six.b("\xde\xad\xbe\xef"))

    def test_long_to_bytes_pad(self):
        self.assertEqual(long_to_bytes(0xdeadbeef, 5), six.b("\x00\xde\xad\xbe\xef"))

    def test_long_to_bytes_truncate(self):
        self.assertEqual(long_to_bytes(0xdeadbeef, 2), six.b("\xde\xad"))

    def test_bytes_to_long(self):
        self.assertEqual(bytes_to_long(six.b("\xde\xad\xbe\xef")), 0xdeadbeef)

    def test_counter_value(self):
        counter = splunksecrets.Counter()
        self.assertEqual(counter.value, [0, 0, 0, 1])

    def test_counter_initial_value(self):
        counter = splunksecrets.Counter(initial_value=2)
        self.assertEqual(counter.value, [0, 0, 0, 2])

    def test_counter_initial_increment(self):
        counter = splunksecrets.Counter()
        counter.increment()
        self.assertEqual(counter.value, [0, 0, 0, 2])

    def test_counter_value_includes_prefix(self):
        counter = splunksecrets.Counter(prefix=six.b("\x00\x00\x00\x00"))
        self.assertEqual(counter.value, [0, 0, 0, 0, 0, 0, 0, 1])

    def test_counter_overflow(self):
        counter = splunksecrets.Counter(initial_value=0xffffffff)
        counter.increment()
        self.assertEqual(counter.value, [0, 0, 0, 0])

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

    def test_encrypt_new_no_padding(self):
        ciphertext = splunksecrets.encrypt_new(
            splunk_secret,
            "temp12344321pmet",
            iv=six.b("i5dKMGaSIRNpJty4")
        )
        self.assertEqual(ciphertext, "$7$aTVkS01HYVNJUk5wSnR5NKR+EdOfT4t8cdTNkhq354S1l9IDjbxt3CJ4TPF4oSZ9")

    def test_encrypt_new_raises_value_error_short_secret(self):
        with self.assertRaises(ValueError):
            splunk_secret = base64.b64encode(os.urandom(255))[:253]
            splunksecrets.encrypt_new(splunk_secret, "temp1234")

    def test_encrypt_character_matches_salt1(self):
        ciphertext = splunksecrets.encrypt(splunk_secret, "A" * 8)
        self.assertEqual(ciphertext, "$1$qowYK8EKp+UK")

    def test_encrypt_character_matches_salt2(self):
        ciphertext = splunksecrets.encrypt(splunk_secret, "DEFAULTSA" * 8)
        self.assertEqual(ciphertext, "$1$681ZK4BL5qRLsmMRT6EotpYVgOge69IZZhhxq0P+2ZBCaRTkci1IwiwRG9Ty2bHaSoG1p9QSXWIYA7mrYsyFqfWYqlvg+oQ+sg==")  # noqa: E501

    def test_decrypt(self):
        plaintext = splunksecrets.decrypt(splunk_secret, "$1$n6g0W7F51ZAK")
        self.assertEqual(plaintext, "temp1234")

    def test_decrypt_raises_value_error_short_secret1(self):
        with self.assertRaises(ValueError):
            splunk_secret = base64.b64encode(os.urandom(255))[:15]
            splunksecrets.decrypt(splunk_secret, "$1$n6g0W7F51ZAK")

    def test_decrypt_raises_value_error_short_secret2(self):
        with self.assertRaises(ValueError):
            splunk_secret = base64.b64encode(os.urandom(255))[:253]
            splunksecrets.decrypt(
                splunk_secret,
                "$7$aTVkS01HYVNJUk5wSnR5NKR+EdOfT4t84WSiXvPFHGHsfHtbgPIL3g=="
            )

    def test_decrypt_nosalt(self):
        plaintext = splunksecrets.decrypt(splunk_secret, "$1$2+1yGuQ1gcMK", nosalt=True)
        self.assertEqual(plaintext, "temp1234")

    def test_decrypt_new(self):
        plaintext = splunksecrets.decrypt(
            splunk_secret,
            "$7$aTVkS01HYVNJUk5wSnR5NKR+EdOfT4t84WSiXvPFHGHsfHtbgPIL3g=="
        )
        self.assertEqual(plaintext, "temp1234")

    def test_decrypt_new_fails(self):
        with self.assertRaises(ValueError):
            splunksecrets.decrypt(
                splunk_secret,
                "$7$bTVkS01HYVNJUk5wSnR5NKR+EdOfT4t84WSiXvPFHGHsfHtbgPIL3g=="
            )

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

    def test_encrypt_with_text_type_secret(self):
        ciphertext = splunksecrets.encrypt(splunk_secret.decode(), "temp1234")
        self.assertEqual(ciphertext, "$1$n6g0W7F51ZAK")

    def test_encrypt_new_with_text_type_secret(self):
        ciphertext = splunksecrets.encrypt_new(
            splunk_secret.decode(),
            "temp1234",
            iv=six.b("i5dKMGaSIRNpJty4")
        )
        self.assertEqual(ciphertext, "$7$aTVkS01HYVNJUk5wSnR5NKR+EdOfT4t84WSiXvPFHGHsfHtbgPIL3g==")

    def test_decrypt_with_binary_type_secret(self):
        plaintext = splunksecrets.decrypt(splunk_secret.decode(), "$1$n6g0W7F51ZAK")
        self.assertEqual(plaintext, "temp1234")

    def test_encrypt_with_binary_type_input(self):
        ciphertext = splunksecrets.encrypt(splunk_secret, six.b("temp1234"))
        self.assertEqual(ciphertext, "$1$n6g0W7F51ZAK")

    def test_encrypt_new_with_binary_type_input(self):
        ciphertext = splunksecrets.encrypt_new(
            splunk_secret,
            six.b("temp1234"),
            iv=six.b("i5dKMGaSIRNpJty4")
        )
        self.assertEqual(ciphertext, "$7$aTVkS01HYVNJUk5wSnR5NKR+EdOfT4t84WSiXvPFHGHsfHtbgPIL3g==")

    def test_decrypt_with_text_type_input(self):
        plaintext = splunksecrets.decrypt(splunk_secret, six.b("$1$n6g0W7F51ZAK"))
        self.assertEqual(plaintext, "temp1234")
