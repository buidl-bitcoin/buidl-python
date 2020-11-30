from unittest import TestCase

from buidl.mnemonic import secure_mnemonic
from buidl.hd import HDPrivateKey


class MnemonicTest(TestCase):
    def test_secure_mnemonic(self):
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
            HDPrivateKey.from_mnemonic(mnemonic, testnet=True)

        for invalid_num_bits in (1, 127, 129, 257):
            with self.assertRaises(AssertionError):
                secure_mnemonic(num_bits=invalid_num_bits)
