from unittest import TestCase

from buidl.ecc import G, S256Point, PrivateKey, Signature
from buidl.bech32 import decode_bech32

from random import randint


class S256Test(TestCase):
    #    def test_order(self):
    #        point = N * G
    #        self.assertIsNone(point.x)

    def test_pubpoint(self):
        # write a test that tests the public point for the following
        points = (
            # secret, x, y
            (
                7,
                "045CBDF0646E5DB4EAA398F365F2EA7A0E3D419B7E0330E39CE92BDDEDCAC4F9BC6AEBCA40BA255960A3178D6D861A54DBA813D0B813FDE7B5A5082628087264DA",
            ),
            (
                1485,
                "04C982196A7466FBBBB0E27A940B6AF926C1A74D5AD07128C82824A11B5398AFDA7A91F9EAE64438AFB9CE6448A1C133DB2D8FB9254E4546B6F001637D50901F55",
            ),
            (
                2 ** 128,
                "048F68B9D2F63B5F339239C1AD981F162EE88C5678723EA3351B7B444C9EC4C0DA662A9F2DBA063986DE1D90C2B6BE215DBBEA2CFE95510BFDF23CBF79501FFF82",
            ),
            (
                2 ** 240 + 2 ** 31,
                "049577FF57C8234558F293DF502CA4F09CBC65A6572C842B39B366F2171794511610B49C67FA9365AD7B90DAB070BE339A1DAF9052373EC30FFAE4F72D5E66D053",
            ),
        )

        # iterate over points
        for secret, sec in points:
            # initialize the secp256k1 point (S256Point)
            point = S256Point.parse(bytes.fromhex(sec))
            # check that the secret*G is the same as the point
            self.assertEqual(secret * G, point)

    def test_sec(self):
        coefficient = 999 ** 3
        uncompressed = "049d5ca49670cbe4c3bfa84c96a8c87df086c6ea6a24ba6b809c9de234496808d56fa15cc7f3d38cda98dee2419f415b7513dde1301f8643cd9245aea7f3f911f9"
        compressed = (
            "039d5ca49670cbe4c3bfa84c96a8c87df086c6ea6a24ba6b809c9de234496808d5"
        )
        point = coefficient * G
        self.assertEqual(point.sec(compressed=False), bytes.fromhex(uncompressed))
        self.assertEqual(point.sec(compressed=True), bytes.fromhex(compressed))
        coefficient = 123
        uncompressed = "04a598a8030da6d86c6bc7f2f5144ea549d28211ea58faa70ebf4c1e665c1fe9b5204b5d6f84822c307e4b4a7140737aec23fc63b65b35f86a10026dbd2d864e6b"
        compressed = (
            "03a598a8030da6d86c6bc7f2f5144ea549d28211ea58faa70ebf4c1e665c1fe9b5"
        )
        point = coefficient * G
        self.assertEqual(point.sec(compressed=False), bytes.fromhex(uncompressed))
        self.assertEqual(point.sec(compressed=True), bytes.fromhex(compressed))
        coefficient = 42424242
        uncompressed = "04aee2e7d843f7430097859e2bc603abcc3274ff8169c1a469fee0f20614066f8e21ec53f40efac47ac1c5211b2123527e0e9b57ede790c4da1e72c91fb7da54a3"
        compressed = (
            "03aee2e7d843f7430097859e2bc603abcc3274ff8169c1a469fee0f20614066f8e"
        )
        point = coefficient * G
        self.assertEqual(point.sec(compressed=False), bytes.fromhex(uncompressed))
        self.assertEqual(point.sec(compressed=True), bytes.fromhex(compressed))

    def test_address(self):
        tests = (
            (
                888 ** 3,
                "148dY81A9BmdpMhvYEVznrM45kWN32vSCN",
                "mnabU9NCcRE5zcNZ2C16CnvKPELrFvisn3",
            ),
            (
                321,
                "1FNgueDbMYjNQ8HT77sHKxTwdrHMdTGwyN",
                "mfx3y63A7TfTtXKkv7Y6QzsPFY6QCBCXiP",
            ),
            (
                4242424242,
                "1HUYfVCXEmp76uh17bE2gA72Vuqv4wrM1a",
                "mgY3bVusRUL6ZB2Ss999CSrGVbdRwVpM8s",
            ),
        )
        for secret, mainnet_legacy, testnet_legacy in tests:
            point = secret * G
            self.assertEqual(point.address(network="mainnet"), mainnet_legacy)
            self.assertEqual(
                point.address(compressed=False, network="testnet"), testnet_legacy
            )
            self.assertEqual(
                point.address(compressed=False, network="signet"), testnet_legacy
            )

    def test_bech32_address(self):
        tests = (
            (
                888 ** 3,
                "bc1qyfvunnpszmjwcqgfk9dsne6j4edq3fglx9y5x7",
                "tb1qyfvunnpszmjwcqgfk9dsne6j4edq3fglvrl8ad",
            ),
            (
                321,
                "bc1qnk4u7vkat6ck9t4unlgvvle8dhsqp40mrssamm",
                "tb1qnk4u7vkat6ck9t4unlgvvle8dhsqp40mfktwqg",
            ),
            (
                4242424242,
                "bc1qkjm6e3c79zy7clsfx86q4pvy46ccc5u9xa6f6e",
                "tb1qkjm6e3c79zy7clsfx86q4pvy46ccc5u9vmp6p2",
            ),
        )
        for secret, mainnet_bech32, testnet_bech32 in tests:
            point = secret * G
            self.assertEqual(point.bech32_address(network="mainnet"), mainnet_bech32)
            self.assertEqual(decode_bech32(mainnet_bech32)[2], point.hash160())
            self.assertEqual(point.bech32_address(network="testnet"), testnet_bech32)
            self.assertEqual(point.bech32_address(network="signet"), testnet_bech32)

    def test_p2sh_p2wpkh_address(self):
        tests = (
            (
                888 ** 3,
                "32cE3VHX5k1Z4gDCJBXMSLgd1akUzvqNvH",
                "2MtAS7EDYhCWuGTqjyK9E4HftDvxek7ELQn",
            ),
            (
                321,
                "3KPpFmmGNoKi5ikrH4QsMNmNnQtzkdw4Kx",
                "2NAx2KWhHzFq4HWPPxC2jyKkdzm7AVsEge4",
            ),
            (
                4242424242,
                "3M7oCrExZ6ZYjyn2oxXxYnE14m813espco",
                "2NCg1GbAzAZ4twmQaV69qAjDGH7LApz5kA4",
            ),
        )
        for secret, mainnet_p2sh, testnet_p2sh in tests:
            point = secret * G
            self.assertEqual(point.p2sh_p2wpkh_address(network="mainnet"), mainnet_p2sh)
            self.assertEqual(point.p2sh_p2wpkh_address(network="testnet"), testnet_p2sh)
            self.assertEqual(point.p2sh_p2wpkh_address(network="signet"), testnet_p2sh)

    def test_verify(self):
        tests = (
            (
                0xEC208BAA0FC1C19F708A9CA96FDEFF3AC3F230BB4A7BA4AEDE4942AD003C0F60,
                "3045022100ac8d1c87e51d0d441be8b3dd5b05c8795b48875dffe00b7ffcfac23010d3a3950220068342ceff8935ededd102dd876ffd6ba72d6a427a3edb13d26eb0781cb423c4",
                "04887387e452b8eacc4acfde10d9aaf7f6d9a0f975aabb10d006e4da568744d06c61de6d95231cd89026e286df3b6ae4a894a3378e393e93a0f45b666329a0ae34",
            ),
            (
                0x7C076FF316692A3D7EB3C3BB0F8B1488CF72E1AFCD929E29307032997A838A3D,
                "3044022000eff69ef2b1bd93a66ed5219add4fb51e11a840f404876325a1e8ffe0529a2c022038df8011e682d839e75159debf909408cb3f12ae472b1d88cf6280cf01c6568b",
                "04887387e452b8eacc4acfde10d9aaf7f6d9a0f975aabb10d006e4da568744d06c61de6d95231cd89026e286df3b6ae4a894a3378e393e93a0f45b666329a0ae34",
            ),
            (
                0x2270CB0316E68389A3A23DE16023A03B8FC271A21B467B1DC97E0FC0E2CE97F7,
                "3045022100ea6d640d5275d091607e1f4ad5cdb214e45f8d17cca1095074894dde347605ba022029062e1ff0d9eee52da1f3621caf92436877d7076720e2b3d9f226bf853e2b75",
                "04f47dc2ac0ecaadda5ee2b3ab9bc4e02c3eafb2abcc426643686ad95f6d4e8c44e33fa47d96fc2dace0ef2f583965cf6a0f8faa7a070c0f8ee986d192e2d21835",
            ),
        )
        for z, der_hex, sec in tests:
            point = S256Point.parse(bytes.fromhex(sec))
            der = bytes.fromhex(der_hex)
            self.assertTrue(point.verify(z, Signature.parse(der)))

    def test_parse(self):
        csec = bytes.fromhex(
            "0349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278a"
        )
        point = S256Point.parse(csec)
        usec = bytes.fromhex(
            "0449fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278aa56c896489c71dfc65701ce25050f542f336893fb8cd15f4e8e5c124dbf58e47"
        )
        self.assertEqual(point.sec(False), usec)


class SignatureTest(TestCase):
    def test_der(self):
        tests = (
            "3045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed",
        )
        for der_hex in tests:
            der = bytes.fromhex(der_hex)
            sig = Signature.parse(der)
            self.assertTrue("Signature" in sig.__repr__())
            computed = sig.der()
            self.assertEqual(der, computed)


class PrivateKeyTest(TestCase):
    def test_sign(self):
        pk = PrivateKey(randint(0, 2 ** 256))
        z = randint(0, 2 ** 256)
        sig = pk.sign(z)
        self.assertTrue(pk.point.verify(z, sig))

    def test_sign_message(self):
        pk = PrivateKey(randint(0, 2 ** 256))
        message = b"This is a test message"
        sig = pk.sign_message(message)
        self.assertTrue(pk.point.verify_message(message, sig))
