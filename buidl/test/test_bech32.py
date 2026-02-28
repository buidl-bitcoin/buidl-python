from unittest import TestCase

from buidl.bech32 import (
    BECH32_ALPHABET,
    bc32decode,
    bc32encode,
    bech32_create_checksum,
    bech32_verify_checksum,
    bech32m_create_checksum,
    bech32m_verify_checksum,
    cbor_decode,
    cbor_encode,
    convertbits,
    decode_bech32,
    encode_bech32_checksum,
    group_32,
    uses_only_bech32_chars,
)


class Bech32Test(TestCase):
    def test_bech32(self):
        tests = [
            {
                "hex_script": "00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262",
                "mainnet": "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3",
                "testnet": "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7",
                "signet": "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7",
                "regtest": "bcrt1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qzf4jry",
            },
            {
                "hex_script": "00200000000000000000000000000000000000000000000000000000000000000000",
                "mainnet": "bc1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqthqst8",
                "testnet": "tb1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqulkl3g",
                "signet": "tb1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqulkl3g",
                "regtest": "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq3xueyj",
            },
            {
                "hex_script": "00140000000000000000000000000000000000000000",
                "mainnet": "bc1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq9e75rs",
                "testnet": "tb1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq0l98cr",
                "signet": "tb1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq0l98cr",
                "regtest": "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202",
            },
            {
                "hex_script": "0020000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433",
                "mainnet": "bc1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvses5wp4dt",
                "testnet": "tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy",
                "signet": "tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy",
                "regtest": "bcrt1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvseswlauz7",
            },
            {
                "hex_script": "5128751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6",
                "mainnet": "bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y",
                "testnet": "tb1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kxwkgjv",
                "signet": "tb1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kxwkgjv",
                "regtest": "bcrt1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7k0ylj56",
            },
            {
                "hex_script": "5120000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433",
                "mainnet": "bc1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvses7epu4h",
                "testnet": "tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c",
                "signet": "tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c",
                "regtest": "bcrt1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesyga46z",
            },
            {
                "hex_script": "512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
                "mainnet": "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0",
                "testnet": "tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq47zagq",
                "signet": "tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq47zagq",
                "regtest": "bcrt1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqc8gma6",
            },
        ]
        for test in tests:
            # Special-case signet here because it will decode as a testnet-inferred
            # address.
            raw = bytes.fromhex(test["hex_script"])
            want = test["signet"]
            version = BECH32_ALPHABET.index(want[3:4])
            result = encode_bech32_checksum(raw, network="signet")
            self.assertEqual(result, want)
            got_network, got_version, got_raw = decode_bech32(result)
            self.assertEqual(got_network, "testnet")
            self.assertEqual(got_version, version)
            self.assertEqual(got_raw, raw[2:])

            for network in ("mainnet", "testnet", "regtest"):
                ver_index = 3
                if network == "regtest":
                    # Account for the two extra letters ("rt") in the regtest prefix.
                    ver_index += 2

                want = test[network]
                version = BECH32_ALPHABET.index(want[ver_index])
                result = encode_bech32_checksum(raw, network=network)
                self.assertEqual(result, want)
                got_network, got_version, got_raw = decode_bech32(result)
                self.assertEqual(got_network, network)
                self.assertEqual(got_version, version)
                self.assertEqual(got_raw, raw[2:])


class Bc32Test(TestCase):
    def test_bc32_roundtrip(self):
        data = b"hello world"
        encoded = bc32encode(data)
        self.assertEqual(encoded, "dpjkcmr0ypmk7unvvsrvvse8")
        decoded = bc32decode(encoded)
        self.assertEqual(decoded, data)

    def test_bc32_empty(self):
        encoded = bc32encode(b"")
        decoded = bc32decode(encoded)
        self.assertEqual(decoded, b"")

    def test_bc32_roundtrip_binary(self):
        data = bytes(range(256))
        encoded = bc32encode(data)
        decoded = bc32decode(encoded)
        self.assertEqual(decoded, data)

    def test_bc32_invalid_mixed_case(self):
        # bc32 strings should be single case
        result = bc32decode("DpJkCmR0")
        self.assertIsNone(result)

    def test_bc32_invalid_chars(self):
        result = bc32decode("INVALIDCHARS!!!")
        self.assertIsNone(result)

    def test_bc32_bad_checksum(self):
        encoded = bc32encode(b"test")
        # corrupt last character
        corrupted = encoded[:-1] + ("q" if encoded[-1] != "q" else "p")
        result = bc32decode(corrupted)
        self.assertIsNone(result)


class CborTest(TestCase):
    def test_cbor_short(self):
        """Length <= 23 uses single-byte prefix."""
        data = b"\x01\x02\x03"
        encoded = cbor_encode(data)
        self.assertEqual(encoded, bytes.fromhex("43010203"))
        self.assertEqual(cbor_decode(encoded), data)

    def test_cbor_medium(self):
        """Length 24-255 uses 0x58 prefix."""
        data = bytes(range(30))
        encoded = cbor_encode(data)
        self.assertEqual(encoded[0], 0x58)
        self.assertEqual(encoded[1], 30)
        self.assertEqual(cbor_decode(encoded), data)

    def test_cbor_large(self):
        """Length 256-65535 uses 0x59 prefix."""
        data = bytes([0xAB]) * 300
        encoded = cbor_encode(data)
        self.assertEqual(encoded[0], 0x59)
        self.assertEqual(int.from_bytes(encoded[1:3], "big"), 300)
        self.assertEqual(cbor_decode(encoded), data)

    def test_cbor_roundtrip_empty(self):
        data = b""
        self.assertEqual(cbor_decode(cbor_encode(data)), data)

    def test_cbor_roundtrip_boundary_23(self):
        data = bytes(range(23))
        self.assertEqual(cbor_decode(cbor_encode(data)), data)

    def test_cbor_roundtrip_boundary_24(self):
        data = bytes(range(24))
        encoded = cbor_encode(data)
        self.assertEqual(encoded[0], 0x58)
        self.assertEqual(cbor_decode(encoded), data)


class ConvertbitsTest(TestCase):
    def test_8_to_5(self):
        result = convertbits([0, 1, 2, 3], 8, 5)
        self.assertEqual(result, [0, 0, 0, 16, 4, 0, 24])

    def test_roundtrip(self):
        original = list(range(20))
        five_bit = convertbits(original, 8, 5)
        back = convertbits(five_bit, 5, 8, False)
        self.assertEqual(back, original)

    def test_invalid_value(self):
        result = convertbits([-1], 8, 5)
        self.assertIsNone(result)

    def test_value_too_large(self):
        result = convertbits([256], 8, 5)
        self.assertIsNone(result)


class Group32Test(TestCase):
    def test_basic(self):
        result = group_32(b"\x00\x01\x02")
        self.assertEqual(result, [0, 0, 0, 16, 4])


class UsesOnlyBech32CharsTest(TestCase):
    def test_valid(self):
        self.assertTrue(uses_only_bech32_chars("qpzry9x8gf2tvdw0s3jn54khce6mua7l"))

    def test_valid_uppercase(self):
        self.assertTrue(uses_only_bech32_chars("QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L"))

    def test_invalid(self):
        self.assertFalse(uses_only_bech32_chars("boi"))

    def test_empty(self):
        self.assertTrue(uses_only_bech32_chars(""))


class Bech32ChecksumTest(TestCase):
    def test_bech32_checksum_roundtrip(self):
        hrp = "bc"
        data = [0, 14, 20, 15, 7, 13, 26, 0]
        checksum = bech32_create_checksum(hrp, data)
        self.assertTrue(bech32_verify_checksum(hrp, data + checksum))

    def test_bech32m_checksum_roundtrip(self):
        hrp = "bc"
        data = [1, 14, 20, 15, 7, 13, 26, 0]
        checksum = bech32m_create_checksum(hrp, data)
        self.assertTrue(bech32m_verify_checksum(hrp, data + checksum))

    def test_decode_invalid_network(self):
        with self.assertRaises(ValueError):
            decode_bech32("xx1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq0l98cr")

    def test_encode_invalid_network(self):
        raw = bytes.fromhex("00140000000000000000000000000000000000000000")
        with self.assertRaises(ValueError):
            encode_bech32_checksum(raw, network="invalid")
