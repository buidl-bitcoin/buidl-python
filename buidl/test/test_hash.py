from unittest import TestCase

from buidl.hash import hash_keyaggcoef,hash_bip322message


class HashTest(TestCase):
    def test_keyaggcoef(self):
        want = "55a02026378a033a97431c5ac6a72eeec43069940a330431216895c11eff3cc7"
        self.assertEqual(hash_keyaggcoef(b"").hex(), want)

    def test_bip322message(self):
        want = "c90c269c4f8fcbe6880f72a721ddfbf1914268a794cbb21cfafee13770ae19f1"
        self.assertEqual(hash_bip322message(b"").hex(), want)
