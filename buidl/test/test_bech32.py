from unittest import TestCase

from binascii import a2b_base64

from buidl.bech32 import (
    bcur_encode, bcur_decode,
    encode_bech32_checksum,
    encode_psbt_to_bcur,
    decode_qr_to_psbt,
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


class BCURTest(TestCase):

    def test_bcur(self):

        # Test case from specter-desktop: https://github.com/cryptoadvance/specter-desktop/blob/0a483316d0d2e83cb5a532a0cbbcd82a885587db/src/cryptoadvance/specter/util/bcur.py
        psbt_b64 = "cHNidP8BAHEBAAAAAfPQ5Rpeu5nH0TImK4Sbu9lxIOGEynRadywPxaPyhnTwAAAAAAD/////AkoRAAAAAAAAFgAUFCYoQzGSRmYVAuZNuXF0OrPg9jWIEwAAAAAAABYAFOZMlwM1sZGLivwOcOh77amAlvD5AAAAAAABAR+tKAAAAAAAABYAFM4u9V5WG+Fe9l3MefmYEX4ULWAWIgYDA+jO+oOuN37ABK67BA/+SuuR/57c7OkyfyR7hR34FDsYccBxUlQAAIAAAACAAAAAgAAAAAAFAAAAACICApJMZBvzWiavLN7nievKQoylwPoffLkXZUIgGHF4HgwaGHHAcVJUAACAAAAAgAAAAIABAAAACwAAAAAA"
        raw = a2b_base64(psbt_b64)
        enc, enc_hash = bcur_encode(raw)
        dec = bcur_decode(enc, enc_hash)
        assert dec == raw
        testres = [
            "tyq3wurnvf607qgqwyqsqqqqq8eapeg6t6aen373xgnzhpymh0vhzg8psn98gknh9s8utgljse60qqqqqqqqpllllllsyjs3qqqqqqqqqqtqq9q5yc5yxvvjgenp2qhxfkuhzap6k0s0vdvgzvqqqqqqqqqpvqq5uexfwqe4kxgchzhupecws7ld4xqfdu8eqqqqqqqq",
            "qyq3ltfgqqqqqqqqqqtqq9xw9m64u4smu900vhwv08uesyt7zskkq93zqcps86xwl2p6udm7cqz2awcyplly46u3l70dem8fxfljg7u9rhupgwccw8q8z5j5qqqgqqqqqzqqqqqqsqqqqqqqq5qqqqqqygpq9yjvvsdlxk3x4ukdaeufa09y9r99crap7l9ezaj5ygqc",
            "w9upurq6rpcuqu2j2sqqpqqqqqqgqqqqqzqqzqqqqq9sqqqqqqqqmkdau4",
        ]
        testhash = "hlwjxjx550k4nnfdl5py2tn3vnh6g60slnw5dmld6ktrkkz200as49spg5"
        assert enc_hash == testhash
        assert enc == "".join(testres)

        encoded = encode_psbt_to_bcur(psbt_b64=psbt_b64)
        prefix, encoded_hash, encoded_payload = encoded.split("/")
        self.assertEqual(prefix, "ur:bytes")
        self.assertEqual(enc_hash, encoded_hash)
        self.assertEqual(encoded_payload, enc)

        self.assertEqual(psbt_b64, decode_qr_to_psbt(bcur_string=encoded))
