from unittest import TestCase

from buidl.message import MessageSignatureFormat, verify_message, sign_message
from buidl.ecc import PrivateKey

class VerifyMessageTest(TestCase):

    def test_verify_valid_BIP322(self):

        # address , message, signature
        valid_sig_tests = [
            (
                "bc1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l",
                "",
                "AkcwRAIgM2gBAQqvZX15ZiysmKmQpDrG83avLIT492QBzLnQIxYCIBaTpOaD20qRlEylyxFSeEA2ba9YOixpX8z46TSDtS40ASECx/EgAxlkQpQ9hYjgGu6EBCPMVPwVIVJqO4XCsMvViHI="
            ),
            (
                "bc1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l",
                "Hello World",
                "AkcwRAIgZRfIY3p7/DoVTty6YZbWS71bc5Vct9p9Fia83eRmw2QCICK/ENGfwLtptFluMGs2KsqoNSk89pO7F29zJLUx9a/sASECx/EgAxlkQpQ9hYjgGu6EBCPMVPwVIVJqO4XCsMvViHI="
            ),
            (
                "bc1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l",
                "Hello World",
                "AkgwRQIhAOzyynlqt93lOKJr+wmmxIens//zPzl9tqIOua93wO6MAiBi5n5EyAcPScOjf1lAqIUIQtr3zKNeavYabHyR8eGhowEhAsfxIAMZZEKUPYWI4BruhAQjzFT8FSFSajuFwrDL1Yhy"
            ),
        ]

        for address, message, signature in valid_sig_tests:
            res = verify_message(address,signature,message)
            self.assertTrue(res)

    def test_verify_invalid_BIP322(self):

        invalid_sig_tests = [
            # Old sig from BIP322
            (
                "bc1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l",
                "Hello World",
                "AkcwRAIgG3PASL/vRTgAqogWT6S8rUOQXNnfRzX6JncmbFlHc1ACIGQdsW+rnVmsQzyAYRQisHKFMigDmKiL7LUw4x17Fw5tASECx/EgAxlkQpQ9hYjgGu6EBCPMVPwVIVJqO4XCsMvViHI="
            ),
            # Signatures swapped for "" and "Hello World"
            (
                "bc1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l",
                "",
                "AkcwRAIgZRfIY3p7/DoVTty6YZbWS71bc5Vct9p9Fia83eRmw2QCICK/ENGfwLtptFluMGs2KsqoNSk89pO7F29zJLUx9a/sASECx/EgAxlkQpQ9hYjgGu6EBCPMVPwVIVJqO4XCsMvViHI="
            ),
            (
                "bc1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l",
                "Hello World",
                "AkcwRAIgM2gBAQqvZX15ZiysmKmQpDrG83avLIT492QBzLnQIxYCIBaTpOaD20qRlEylyxFSeEA2ba9YOixpX8z46TSDtS40ASECx/EgAxlkQpQ9hYjgGu6EBCPMVPwVIVJqO4XCsMvViHI="
            )
        ]
        
        for address, message, signature in invalid_sig_tests:
            res = verify_message(address,signature,message)
            self.assertFalse(res)


    def test_bad_sig_encoding(self):

        address = "1KqbBpLy5FARmTPD4VZnDDpYjkUvkr82Pm",
        signature = "invalid signature, not in base64 encoding",
        message =        "message should be irrelevant"


        with self.assertRaises(ValueError):
            verify_message(address,signature,message)

    def test_bad_address(self):

        address = "not an address"
        signature = "AkcwRAIgZRfIY3p7/DoVTty6YZbWS71bc5Vct9p9Fia83eRmw2QCICK/ENGfwLtptFluMGs2KsqoNSk89pO7F29zJLUx9a/sASECx/EgAxlkQpQ9hYjgGu6EBCPMVPwVIVJqO4XCsMvViHI="
        message =        "message should be irrelevant" 

        with self.assertRaises(ValueError):
            verify_message(address,signature,message)

class SignMessageTest(TestCase):

    # TODO: Add LEGACY sig tests


    def test_simple_sig(self):

        private_key_wif = "L3VFeEujGtevx9w18HD1fhRbCH67Az2dpCymeRE1SoPK6XQtaN2k"
        private_key = PrivateKey.parse(private_key_wif)
        p2wpkh_address = private_key.point.p2wpkh_address(network="mainnet")

        # message, signature
        tests = [
            # Note: these two are from the BIP322 test vector
            # This implementation is able to VERIFY this signature, but produces a different one. See below.
            # Does this indicate a mismatch in deterministic_k implementation?
            # (
            #     "",
            #     "AkcwRAIgM2gBAQqvZX15ZiysmKmQpDrG83avLIT492QBzLnQIxYCIBaTpOaD20qRlEylyxFSeEA2ba9YOixpX8z46TSDtS40ASECx/EgAxlkQpQ9hYjgGu6EBCPMVPwVIVJqO4XCsMvViHI="
            # ),
            # (
            #     "Hello World",
            #     "AkcwRAIgZRfIY3p7/DoVTty6YZbWS71bc5Vct9p9Fia83eRmw2QCICK/ENGfwLtptFluMGs2KsqoNSk89pO7F29zJLUx9a/sASECx/EgAxlkQpQ9hYjgGu6EBCPMVPwVIVJqO4XCsMvViHI="
            # ),
            # The below signatures are also verifiable under the BIP322 PR to Bitcoin core
            (
                "",
                "AkgwRQIhAPkJ1Q4oYS0htvyuSFHLxRQpFAY56b70UvE7Dxazen0ZAiAtZfFz1S6T6I23MWI2lK/pcNTWncuyL8UL+oMdydVgzAEhAsfxIAMZZEKUPYWI4BruhAQjzFT8FSFSajuFwrDL1Yhy"
            ),
            (
                "Hello World",
                "AkgwRQIhAOzyynlqt93lOKJr+wmmxIens//zPzl9tqIOua93wO6MAiBi5n5EyAcPScOjf1lAqIUIQtr3zKNeavYabHyR8eGhowEhAsfxIAMZZEKUPYWI4BruhAQjzFT8FSFSajuFwrDL1Yhy"
            ),
        ]

        for message, signature in tests:
            res = sign_message(MessageSignatureFormat.SIMPLE, private_key, p2wpkh_address, message)
            self.assertEqual(res, signature)
