from unittest import TestCase

from buidl.pbkdf2 import PBKDF2


class PBKDF2Test(TestCase):
    def test_rfc6070_vector1(self):
        """password='password', salt='salt', iterations=1, dkLen=20"""
        result = PBKDF2("password", "salt", iterations=1).read(20)
        self.assertEqual(result.hex(), "0c60c80f961f0e71f3a9b524af6012062fe037a6")

    def test_rfc6070_vector2(self):
        """password='password', salt='salt', iterations=2, dkLen=20"""
        result = PBKDF2("password", "salt", iterations=2).read(20)
        self.assertEqual(result.hex(), "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957")

    def test_rfc6070_vector3(self):
        """password='password', salt='salt', iterations=4096, dkLen=20"""
        result = PBKDF2("password", "salt", iterations=4096).read(20)
        self.assertEqual(result.hex(), "4b007901b765489abead49d926f721d065a429c1")

    def test_bytes_input(self):
        """Passphrase and salt can be bytes."""
        result = PBKDF2(b"password", b"salt", iterations=1).read(20)
        self.assertEqual(result.hex(), "0c60c80f961f0e71f3a9b524af6012062fe037a6")

    def test_read_different_lengths(self):
        p = PBKDF2("password", "salt", iterations=1)
        key32 = p.read(32)
        self.assertEqual(len(key32), 32)

    def test_hexread(self):
        p = PBKDF2("password", "salt", iterations=1)
        hex_result = p.hexread(20)
        self.assertEqual(hex_result, "0c60c80f961f0e71f3a9b524af6012062fe037a6")

    def test_close(self):
        p = PBKDF2("password", "salt", iterations=1)
        p.close()
        self.assertTrue(p.closed)
        with self.assertRaises(ValueError):
            p.read(20)

    def test_invalid_passphrase_type(self):
        with self.assertRaises(TypeError):
            PBKDF2(12345, "salt")

    def test_invalid_salt_type(self):
        with self.assertRaises(TypeError):
            PBKDF2("password", 12345)

    def test_invalid_iterations_type(self):
        with self.assertRaises(TypeError):
            PBKDF2("password", "salt", iterations="many")

    def test_zero_iterations(self):
        with self.assertRaises(ValueError):
            PBKDF2("password", "salt", iterations=0)
