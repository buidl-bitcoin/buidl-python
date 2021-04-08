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
                "address": "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7",
            },
            {
                "hex_script": "00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262",
                "address": "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7",
            },
            {
                "hex_script": "00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262",
                "address": "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7",
            },
            {
                "hex_script": "00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262",
                "address": "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7",
            },
        ]
        for test in tests:
            raw = bytes.fromhex(test["hex_script"])
            want = test["address"]
            testnet = want[:2] == "tb"
            version = BECH32_ALPHABET.index(want[3:4])
            result = encode_bech32_checksum(raw, testnet=testnet)
            self.assertEqual(result, want)
            got_testnet, got_version, got_raw = decode_bech32(result)
            self.assertEqual(got_testnet, testnet)
            self.assertEqual(got_version, version)
            self.assertEqual(got_raw, raw[2:])
