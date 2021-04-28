from unittest import TestCase

from buidl.blinding import blind_xpub, combine_bip32_paths, secure_secret_path
from buidl.hd import HDPrivateKey, is_valid_bip32_path


class BlindingTest(TestCase):
    def test_generate_secure_secret_path(self):
        for depth in range(1, 8):
            res = secure_secret_path(depth=depth)
            self.assertTrue(is_valid_bip32_path(res))
            self.assertEqual(depth, res.count("/"))

    def test_generate_secure_secret_path_fail(self):
        with self.assertRaises(ValueError):
            secure_secret_path(depth="foo")
            secure_secret_path(depth=-1)
            secure_secret_path(depth=0)
            secure_secret_path(depth=257)

    def test_combine_paths(self):
        self.assertEqual(combine_bip32_paths("m/1", "m/2/3"), "m/1/2/3")
        self.assertEqual(combine_bip32_paths("m/1h", "m/2/3"), "m/1h/2/3")
        self.assertEqual(
            combine_bip32_paths("m/48h/1h/0h/2h", "m/1/2/3/4/5"),
            "m/48h/1h/0h/2h/1/2/3/4/5",
        )
        self.assertEqual(combine_bip32_paths("m", "m/1"), "m/1")
        self.assertEqual(combine_bip32_paths("m/1", "m"), "m/1")
        self.assertEqual(combine_bip32_paths("m", "m"), "m")

    def test_combine_paths_error(self):
        with self.assertRaises(ValueError):
            combine_bip32_paths("m/foo", "m/1/2/3")
            combine_bip32_paths("m/1/2/3", "m/foo")

    def test_blind_m48_vpub(self):
        # All test vectors below compared manually to https://iancoleman.io/bip39/ and then converted with https://jlopp.github.io/xpub-converter/
        starting_path = "m/48h/1h/0h/2h"
        # Vpub version bytes
        starting_vpub = (
            HDPrivateKey.from_mnemonic("oil " * 12)
            .traverse(starting_path)
            .xpub(bytes.fromhex("02575483"))
        )
        self.assertEqual(
            starting_vpub,
            "Vpub5mvQbnmqKfpPjWfAZEw5Xjdr6UjnjyZEirzrhNMSuKjL8Qfd3nqLBkrBrVXNeMgKCjPXbyLnSCn6qcD8fHQCkNnNLnkpQtY3sh4MHmywvbe",
        )
        secret_path = "m/920870093/318569592/821713943/1914815254/1398142787/9"  # randomly generated
        have = blind_xpub(
            starting_xpub=starting_vpub,
            starting_path=starting_path,
            secret_path=secret_path,
        )
        want = {
            "blinded_full_path": "m/48h/1h/0h/2h/920870093/318569592/821713943/1914815254/1398142787/9",
            "blinded_child_xpub": "Vpub5xWzaq6Ya7K9Y2UeFyL8SfHhydnp5FZDskm9mkAfUppkXVJDKrnLxU2Ezd55k8RSzSf4YETJj982NJQGCSzKJxUa6oQmbe1HWTRavCRzzxj",
        }
        self.assertEqual(have, want)

    def test_blind_m48_xpub(self):
        # All test vectors below compared manually to https://iancoleman.io/bip39/ and then converted with https://jlopp.github.io/xpub-converter/
        starting_path = "m/48h/0h/0h/2h"
        starting_xpub = (
            HDPrivateKey.from_mnemonic("oil " * 12).traverse(starting_path).xpub()
        )

        self.assertEqual(
            starting_xpub,
            "xpub6F8WgTkiV8iDPFG1Kv4sNrcBNMMgKK4cjfxjdZWvR3kChfbt3L2dJF7xmCHBMGMmxjyzwgjdFkh9UN3623YpsmqN1KwZGR45Y3ANLQQX87u",
        )
        secret_path = "m/920870093/318569592/821713943/1914815254/1398142787/9"  # randomly generated
        have = blind_xpub(
            starting_xpub=starting_xpub,
            starting_path=starting_path,
            secret_path=secret_path,
        )
        want = {
            "blinded_full_path": "m/48h/0h/0h/2h/920870093/318569592/821713943/1914815254/1398142787/9",
            "blinded_child_xpub": "xpub6RKvkus7fgUnP2trNVo2N1jaQeGPBHCV9m63Jaje8EW2Ry5KjYySb1tbPSi3E7Vh6ZzxRn15hUmBg5KmSaQvKjZmTvXKQnRPXcoJS9PXkiS",
        }
        self.assertEqual(have, want)

    def test_blind_root_xpub(self):
        # All test vectors below compared manually to https://iancoleman.io/bip39/

        starting_path = "m"
        # The .traverse() here does nothing and is optional, just here for consistency/clarity:
        root_xpub = (
            HDPrivateKey.from_mnemonic("bacon " * 24).traverse(starting_path).xpub()
        )

        self.assertEqual(
            root_xpub,
            "xpub661MyMwAqRbcGMzZtBZrKWaDMAQKjd5bMSnHr8qBfCz5zMwZEuajnc8cxjsEUECAZDeDC7s4zbT3Z9KrrM9wJ3MaT6sH9eRYxLY1BNf45BF",
        )
        secret_path = "m/1/2/3/4/5/6/7/8/9"
        have = blind_xpub(
            starting_xpub=root_xpub, starting_path="m", secret_path=secret_path
        )
        want = {
            "blinded_full_path": secret_path,  # the same since we started with the root path
            "blinded_child_xpub": "xpub6QbmAk7amacgfQVY3aTAiqhM1okb4Gi3EFzBJQMEja1uU4gZvG9vwiExr2C1ryZqnyczTvvaNhw63UALmXGkFo7FHhajX8SNimgK3zu3tp5",
        }
        self.assertEqual(have, want)

        starting_path = "m/48h/0h/0h/2h"
        child_xpub = (
            HDPrivateKey.from_mnemonic("bacon " * 24).traverse(starting_path).xpub()
        )
        self.assertEqual(
            child_xpub,
            "xpub6EeqK2JLwngrHJEQ4X4iqrySZV9qU3TgwMgf6NStLZa37AfNiHTtTE9ji1F9YQDLArJMLy8sw3Q2samVj5VQQjaaUHr5z2Hz57NWHJCfh31",
        )
        secret_path = "m/920870093/318569592/821713943/1914815254/1398142787/9"  # randomly generated
        have = blind_xpub(
            starting_xpub=child_xpub,
            starting_path=starting_path,
            secret_path=secret_path,
        )
        want = {
            "blinded_full_path": "m/48h/0h/0h/2h/920870093/318569592/821713943/1914815254/1398142787/9",
            "blinded_child_xpub": "xpub6SDyub38LYeUd211VxRZCiVnU4fSr4ZwPssFGMxyyXjZ6EvrA4ZkZhp4f9My2qzqSJFHxkAv8ctaGipx7UM6sCzmso7wxiohHBhcBs7ipWz",
        }
        self.assertEqual(have, want)

    def test_bad_depth(self):
        starting_path = "m/48h/0h/0h/2h"
        starting_xpub = (
            HDPrivateKey.from_mnemonic("bacon " * 24).traverse(starting_path).xpub()
        )
        with self.assertRaises(ValueError):
            blind_xpub(
                starting_xpub=starting_xpub, starting_path="m/1", secret_path="m/999"
            )
