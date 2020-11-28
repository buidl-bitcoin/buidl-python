from unittest import TestCase

from buidl.mnemonic import secure_mnemonic


class HDTest(TestCase):
    def test_invalid_entropy(self):
        with self.assertRaises(AssertionError):
            secure_mnemonic(extra_entropy="not_an_integer")

    def test_valid_entropy(self):
        # As the scall to the CSPRNG is not deterministic (by design) we cannot properly test that this is working
        for extra_entropy in (0, 1, 2 ** 128, 2 ** 256, 2 ** 512):
            res = secure_mnemonic(extra_entropy=2 ** 512)
            print("res", res)
            # FIXME: why 12 words?
            self.assertEqual(len(res.split(" ")), 12)
