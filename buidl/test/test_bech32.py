from unittest import TestCase

from buidl.bech32 import (
    encode_bech32_checksum,
    decode_bech32,
    BECH32_ALPHABET,
)


class Bech32Test(TestCase):
    def test_bech32(self):
        tests = [
            {
                "hex_script": "00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262",
                "mainnet": "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3",
                "testnet": "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7",
                "signet": "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7",
            },
            {
                "hex_script": "00200000000000000000000000000000000000000000000000000000000000000000",
                "mainnet": "bc1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqthqst8",
                "testnet": "tb1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqulkl3g",
                "signet": "tb1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqulkl3g",
            },
            {
                "hex_script": "00140000000000000000000000000000000000000000",
                "mainnet": "bc1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq9e75rs",
                "testnet": "tb1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq0l98cr",
                "signet": "tb1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq0l98cr",
            },
            {
                "hex_script": "0020000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433",
                "mainnet": "bc1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvses5wp4dt",
                "testnet": "tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy",
                "signet": "tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy",
            },
        ]
        for test in tests:
            raw = bytes.fromhex(test["hex_script"])
            want = test["signet"]
            version = BECH32_ALPHABET.index(want[3:4])
            result = encode_bech32_checksum(raw, network="signet")
            self.assertEqual(result, want)
            got_network, got_version, got_raw = decode_bech32(result)
            self.assertEqual(got_network, "testnet")
            self.assertEqual(got_version, version)
            self.assertEqual(got_raw, raw[2:])
            for network in ("mainnet", "testnet"):
                want = test[network]
                version = BECH32_ALPHABET.index(want[3:4])
                result = encode_bech32_checksum(raw, network=network)
                self.assertEqual(result, want)
                got_network, got_version, got_raw = decode_bech32(result)
                self.assertEqual(got_network, network)
                self.assertEqual(got_version, version)
                self.assertEqual(got_raw, raw[2:])
