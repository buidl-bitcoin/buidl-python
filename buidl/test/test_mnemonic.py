from unittest import TestCase

from buidl.mnemonic import secure_mnemonic
from buidl.hd import HDPrivateKey


class MnemonicTest(TestCase):
    def test_secure_mnemonic(self):
        for num_bits in (128, 160, 192, 224, 256):
            mnemonic = secure_mnemonic(num_bits=num_bits)
            HDPrivateKey.from_mnemonic(mnemonic, testnet=True)
