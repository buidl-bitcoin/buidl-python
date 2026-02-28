from unittest import TestCase

from buidl.hash import (
    hash_aux,
    hash_challenge,
    hash_keyaggcoef,
    hash_keyagglist,
    hash_musignonce,
    hash_nonce,
    hash_tapbranch,
    hash_tapleaf,
    hash_tapsighash,
    hash_taptweak,
)


class HashTest(TestCase):
    def test_hash_keyaggcoef(self):
        want = "55a02026378a033a97431c5ac6a72eeec43069940a330431216895c11eff3cc7"
        self.assertEqual(hash_keyaggcoef(b"").hex(), want)
        want2 = "611b0f73920e178c3ff2465c26050d88ec53e37e94f532e9389e22e8b22527f5"
        self.assertEqual(hash_keyaggcoef(b"hello").hex(), want2)

    def test_hash_aux(self):
        self.assertEqual(
            hash_aux(b"").hex(),
            "07fab5f97e680abb8389d1fa164281e124439468f5bd699fcbd1ae86e6405d69",
        )
        self.assertEqual(
            hash_aux(b"hello").hex(),
            "28c62e0c486da0ba439f836f30bc05cba5c9e39ff2722c362722c8fc7aecdd64",
        )

    def test_hash_challenge(self):
        self.assertEqual(
            hash_challenge(b"").hex(),
            "c216d352f5818b7b4beacd4ae0a26fe888080823d2a598856661bcd54f1b3713",
        )
        self.assertEqual(
            hash_challenge(b"hello").hex(),
            "a97ff4dc59e2e158c00a7d9cf1e7d60fb090ecf5f728b6d17be7cbbb0fc572dd",
        )

    def test_hash_nonce(self):
        self.assertEqual(
            hash_nonce(b"").hex(),
            "5301f1001a8be6253a3583927793565cef360de8bac2bdcbf37b195e699435a8",
        )
        self.assertEqual(
            hash_nonce(b"hello").hex(),
            "11a805465ee0853d8c12cbaa6d431a0ff9e5adfa0c92d9a9a027a3f54b9e8eab",
        )

    def test_hash_tapbranch(self):
        self.assertEqual(
            hash_tapbranch(b"").hex(),
            "53c373ec4d6f3c53c1f5fb2ff506dcefe1a0ed74874f93fa93c8214cbe9ffddf",
        )
        self.assertEqual(
            hash_tapbranch(b"hello").hex(),
            "85078decf0533d9abbcaa0589e410b358752403b1c45cf1952f3923e06dbc88f",
        )

    def test_hash_tapleaf(self):
        self.assertEqual(
            hash_tapleaf(b"").hex(),
            "5212c288a377d1f8164962a5a13429f9ba6a7b84e59776a52c6637df2106facb",
        )
        self.assertEqual(
            hash_tapleaf(b"hello").hex(),
            "cc0d501f9c9c9610e44edb939ad98d59a1a98739d0e26dbe932660ae33a8196e",
        )

    def test_hash_tapsighash(self):
        self.assertEqual(
            hash_tapsighash(b"").hex(),
            "dabc11914abcd8072900042a2681e52f8dba99ce82e224f97b5fdb7cd4b9c803",
        )
        self.assertEqual(
            hash_tapsighash(b"hello").hex(),
            "ac12b2c18138a6ea5b05c3d05f88c7cb305fb94fe448aebdbba7b1dee05dd0eb",
        )

    def test_hash_taptweak(self):
        self.assertEqual(
            hash_taptweak(b"").hex(),
            "8aa4229474ab0100b2d6f0687f031d1fc9d8eef92a042ad97d279bff456b15e4",
        )
        self.assertEqual(
            hash_taptweak(b"hello").hex(),
            "38c140830ab88bf8dac2e03f0d765b6677949e5a9aab799378f49dde69c71926",
        )

    def test_hash_keyagglist(self):
        self.assertEqual(
            hash_keyagglist(b"").hex(),
            "634f77a422b6a39257a76f2c13ae017702bacd4c49b33dad1139cdd56060d360",
        )
        self.assertEqual(
            hash_keyagglist(b"hello").hex(),
            "c5bd0bd5c14f3d375ee03b476b8afa7209650974e564992c0ffd2b9572c6f762",
        )

    def test_hash_musignonce(self):
        self.assertEqual(
            hash_musignonce(b"").hex(),
            "74fc59e69748b3ab4f2d378fa0b0beaa8c2a34dd65a04d7bf0b406b2f8489329",
        )
        self.assertEqual(
            hash_musignonce(b"hello").hex(),
            "d5d765e8129eb1959a584408112484ed19f55d095545da60dfa0f19a342a1362",
        )

    def test_all_return_32_bytes(self):
        """All tagged hash functions should return 32 bytes (SHA256 output)."""
        fns = [
            hash_aux,
            hash_challenge,
            hash_keyaggcoef,
            hash_keyagglist,
            hash_musignonce,
            hash_nonce,
            hash_tapbranch,
            hash_tapleaf,
            hash_tapsighash,
            hash_taptweak,
        ]
        for fn in fns:
            result = fn(b"test")
            self.assertEqual(len(result), 32, f"{fn.__name__} should return 32 bytes")
