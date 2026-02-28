from unittest import TestCase

from buidl.mnemonic import (
    BIP39,
    InvalidBIP39Length,
    InvalidChecksumWordsError,
    bytes_to_mnemonic,
    mnemonic_to_bytes,
    secure_mnemonic,
)
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
            (192, 18, 2**128),
            (224, 21, 2**256),
            (256, 24, 2**512),
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


class BytesToMnemonicTest(TestCase):
    def test_128bit_zeros(self):
        entropy = bytes(16)
        mnemonic = bytes_to_mnemonic(entropy, 128)
        expected = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        self.assertEqual(mnemonic, expected)

    def test_128bit_ones(self):
        entropy = b"\xff" * 16
        mnemonic = bytes_to_mnemonic(entropy, 128)
        expected = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong"
        self.assertEqual(mnemonic, expected)

    def test_256bit_zeros(self):
        entropy = bytes(32)
        mnemonic = bytes_to_mnemonic(entropy, 256)
        expected = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"
        self.assertEqual(mnemonic, expected)

    def test_invalid_num_bits(self):
        with self.assertRaises(InvalidBIP39Length):
            bytes_to_mnemonic(bytes(16), 100)

    def test_roundtrip_all_sizes(self):
        """Test that bytes_to_mnemonic -> mnemonic_to_bytes is identity."""
        for num_bits in (128, 160, 192, 224, 256):
            num_bytes = num_bits // 8
            entropy = bytes(range(num_bytes))
            mnemonic = bytes_to_mnemonic(entropy, num_bits)
            recovered = mnemonic_to_bytes(mnemonic)
            self.assertEqual(recovered, entropy)


class MnemonicToBytesTest(TestCase):
    def test_known_vector(self):
        mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        result = mnemonic_to_bytes(mnemonic)
        self.assertEqual(result, bytes(16))

    def test_invalid_word_count(self):
        with self.assertRaises(InvalidBIP39Length):
            mnemonic_to_bytes("abandon abandon abandon")

    def test_invalid_checksum(self):
        # Replace last word to create bad checksum
        bad_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon"
        with self.assertRaises(InvalidChecksumWordsError):
            mnemonic_to_bytes(bad_mnemonic)

    def test_unknown_word(self):
        bad_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon notaword"
        with self.assertRaises(KeyError):
            mnemonic_to_bytes(bad_mnemonic)


class WordListTest(TestCase):
    def test_index_by_word(self):
        self.assertEqual(BIP39["abandon"], 0)
        self.assertEqual(BIP39["zoo"], 2047)

    def test_index_by_int(self):
        self.assertEqual(BIP39[0], "abandon")
        self.assertEqual(BIP39[2047], "zoo")

    def test_abbreviated_lookup(self):
        """Words longer than 4 chars can be looked up by first 4 chars."""
        self.assertEqual(BIP39["aban"], BIP39["abandon"])
        self.assertEqual(BIP39["abst"], BIP39["abstract"])

    def test_contains(self):
        self.assertIn("abandon", BIP39)
        self.assertNotIn("notaword", BIP39)

    def test_iter(self):
        words = list(BIP39)
        self.assertEqual(len(words), 2048)
        self.assertEqual(words[0], "abandon")
        self.assertEqual(words[-1], "zoo")

    def test_invalid_key_type(self):
        with self.assertRaises(KeyError):
            BIP39[3.14]

    def test_normalize(self):
        self.assertEqual(BIP39.normalize("ABANDON"), "abandon")
        self.assertEqual(BIP39.normalize("Zoo"), "zoo")
