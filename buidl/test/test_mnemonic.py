from unittest import TestCase

from buidl.mnemonic import secure_mnemonic
from buidl.hd import HDPrivateKey


class MnemonicTest(TestCase):
    def test_secure_mnemonic_bits(self):
        tests = (
            # num_bits, num_words
            (128, 12),
            (160, 15),
            (192, 18),
            (224, 21),
            (256, 24),
        )

        for num_bits, num_words in tests:
            mnemonic = secure_mnemonic(num_bits=num_bits)
            self.assertEqual(num_words, len(mnemonic.split(" ")))
            # This is inherently non-deterministic, so we can't check the specific output
            HDPrivateKey.from_mnemonic(mnemonic, network="testnet")

        for invalid_num_bits in (-1, 1, 127, 129, 257, "notanint"):
            with self.assertRaises(ValueError):
                secure_mnemonic(num_bits=invalid_num_bits)

    def test_secure_mnemonic_extra_entropy(self):
        tests = (
            # num_bits, num_words, extra_entropy
            (128, 12, 0),
            (160, 15, 1),
            (192, 18, 2 ** 128),
            (224, 21, 2 ** 256),
            (256, 24, 2 ** 512),
        )

        for num_bits, num_words, extra_entropy in tests:
            mnemonic = secure_mnemonic(num_bits=num_bits, extra_entropy=extra_entropy)
            self.assertEqual(num_words, len(mnemonic.split(" ")))
            # This is inherently non-deterministic, so we can't check the specific output
            HDPrivateKey.from_mnemonic(mnemonic, network="testnet")

        with self.assertRaises(TypeError):
            secure_mnemonic(extra_entropy="not an int")
        with self.assertRaises(ValueError):
            secure_mnemonic(extra_entropy=-1)
