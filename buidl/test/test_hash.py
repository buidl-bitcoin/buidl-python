from unittest import TestCase

from buidl.hash import hash_keyaggcoef


class HashTest(TestCase):
    def test_keyaggcoef(self):
        want = "55a02026378a033a97431c5ac6a72eeec43069940a330431216895c11eff3cc7"
        self.assertEqual(hash_keyaggcoef(b"").hex(), want)
