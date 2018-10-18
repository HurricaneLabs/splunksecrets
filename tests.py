import base64
import os
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
        ciphertext = splunksecrets.encrypt(splunk_secret[:16], "temp1234")
        self.assertEqual(ciphertext, "$1$n6g0W7F51ZAK")

    def test_decrypt(self):
        plaintext = splunksecrets.decrypt(splunk_secret[:16], "$1$n6g0W7F51ZAK")
        self.assertEqual(plaintext, "temp1234")

    def test_end_to_end(self):
        splunk_secret = base64.b64encode(os.urandom(255))[:255]
        plaintext1 = base64.b64encode(os.urandom(255))[:24].decode()
        ciphertext = splunksecrets.encrypt(splunk_secret[:16], plaintext1)
        plaintext2 = splunksecrets.decrypt(splunk_secret[:16], ciphertext)
        self.assertEqual(plaintext2, plaintext1)
