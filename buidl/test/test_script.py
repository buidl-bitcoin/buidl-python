from unittest import TestCase

from io import BytesIO

from buidl.helper import decode_base58
from buidl.hd import HDPrivateKey
from buidl.script import (
    address_to_script_pubkey,
    P2PKHScriptPubKey,
    P2SHScriptPubKey,
    P2WPKHScriptPubKey,
    P2WSHScriptPubKey,
    RedeemScript,
    Script,
    WitnessScript,
)


class ScriptTest(TestCase):
    def test_parse(self):
        script_pubkey = BytesIO(
            bytes.fromhex(
                "6a47304402207899531a52d59a6de200179928ca900254a36b8dff8bb75f5f5d71b1cdc26125022008b422690b8461cb52c3cc30330b23d574351872b7c361e9aae3649071c1a7160121035d5c93d9ac96881f19ba1f686f15f009ded7c62efe85a872e6a19b43c15a2937"
            )
        )
        script = Script.parse(script_pubkey)
        want = bytes.fromhex(
            "304402207899531a52d59a6de200179928ca900254a36b8dff8bb75f5f5d71b1cdc26125022008b422690b8461cb52c3cc30330b23d574351872b7c361e9aae3649071c1a71601"
        )
        self.assertEqual(script.commands[0].hex(), want.hex())
        want = bytes.fromhex(
            "035d5c93d9ac96881f19ba1f686f15f009ded7c62efe85a872e6a19b43c15a2937"
        )
        self.assertEqual(script.commands[1], want)

    def test_serialize(self):
        want = "6a47304402207899531a52d59a6de200179928ca900254a36b8dff8bb75f5f5d71b1cdc26125022008b422690b8461cb52c3cc30330b23d574351872b7c361e9aae3649071c1a7160121035d5c93d9ac96881f19ba1f686f15f009ded7c62efe85a872e6a19b43c15a2937"
        script_pubkey = BytesIO(bytes.fromhex(want))
        script = Script.parse(script_pubkey)
        self.assertEqual(script.serialize().hex(), want)


class P2PKHScriptPubKeyTest(TestCase):
    def test_address(self):
        address_1 = "1BenRpVUFK65JFWcQSuHnJKzc4M8ZP8Eqa"
        h160 = decode_base58(address_1)
        p2pkh_script_pubkey = P2PKHScriptPubKey(h160)
        self.assertEqual(p2pkh_script_pubkey.address(), address_1)
        address_2 = "mrAjisaT4LXL5MzE81sfcDYKU3wqWSvf9q"
        self.assertEqual(p2pkh_script_pubkey.address(network="testnet"), address_2)
        self.assertEqual(p2pkh_script_pubkey.address(network="signet"), address_2)


class P2SHScriptPubKeyTest(TestCase):
    def test_address(self):
        address_1 = "3CLoMMyuoDQTPRD3XYZtCvgvkadrAdvdXh"
        h160 = decode_base58(address_1)
        p2sh_script_pubkey = P2SHScriptPubKey(h160)
        self.assertEqual(p2sh_script_pubkey.address(), address_1)
        address_2 = "2N3u1R6uwQfuobCqbCgBkpsgBxvr1tZpe7B"
        self.assertEqual(p2sh_script_pubkey.address(network="testnet"), address_2)
        self.assertEqual(p2sh_script_pubkey.address(network="signet"), address_2)


class RedeemScriptTest(TestCase):
    def test_redeem_script(self):
        hex_redeem_script = "4752210223136797cb0d7596cb5bd476102fe3aface2a06338e1afabffacf8c3cab4883c210385c865e61e275ba6fda4a3167180fc5a6b607150ff18797ee44737cd0d34507b52ae"
        stream = BytesIO(bytes.fromhex(hex_redeem_script))
        redeem_script = RedeemScript.parse(stream)
        want = "36b865d5b9664193ea1db43d159edf9edf943802"
        self.assertEqual(redeem_script.hash160().hex(), want)
        want = "17a91436b865d5b9664193ea1db43d159edf9edf94380287"
        self.assertEqual(redeem_script.script_pubkey().serialize().hex(), want)
        want = "2MxEZNps15dAnGX5XaVwZWgoDvjvsDE5XSx"
        self.assertEqual(redeem_script.address(network="testnet"), want)
        self.assertEqual(redeem_script.address(network="signet"), want)

    def test_create_p2sh_multisig(self):
        BASE_PATH = "m/45h/0"

        # Insecure testing BIP39 mnemonics
        hdpriv_root_1 = HDPrivateKey.from_mnemonic("action " * 12, network="testnet")
        hdpriv_root_2 = HDPrivateKey.from_mnemonic("agent " * 12, network="testnet")

        child_xpriv_1 = hdpriv_root_1.traverse(BASE_PATH)
        child_xpriv_2 = hdpriv_root_2.traverse(BASE_PATH)

        # xpubs from electrum:
        self.assertEqual(
            child_xpriv_1.xpub(),
            "tpubDBnspiLZfrq1V7j1iuMxGiPsuHyy6e4QBnADwRrbH89AcnsUEMfWiAYXmSbMuNFsrMdnbQRDGGSM1AFGL6zUWNVSmwRavoJzdQBbZKLgLgd",
        )
        self.assertEqual(
            child_xpriv_2.xpub(),
            "tpubDAKJicb9Tkw34PFLEBUcbnH99twN3augmg7oYHHx9Aa9iodXmA4wtGEJr8h2XjJYqn2j1v5qHLjpWEe8aPihmC6jmsgomsuc9Zeh4ZushNk",
        )

        # addresses from electrum
        expected_receive_addrs = [
            "2ND4qfpdHyeXJboAUkKZqJsyiKyXvHRKhbi",
            "2N1T1HAC9TnNvhEDG4oDEuKNnmdsXs2HNwq",
            "2N7fdTu5JkQihTpo2mZ3QYudrfU2xMdgh3M",
        ]
        expected_change_addrs = [
            "2MzQhXqN93igSKGW9CMvkpZ9TYowWgiNEF8",
            "2Msk2ckm2Ee4kJnzQuyQtpYDpMZrXf5XtKD",
            "2N5wXpJBKtAKSCiAZLwdh2sPwt5k2HBGtGC",
        ]

        # validate receive addrs match electrum
        for cnt, expected_receive_addr in enumerate(expected_receive_addrs):
            redeem_script = RedeemScript.create_p2sh_multisig(
                quorum_m=1,
                pubkey_hexes=[
                    child_xpriv_1.traverse(f"m/0/{cnt}").pub.sec().hex(),
                    child_xpriv_2.traverse(f"m/0/{cnt}").pub.sec().hex(),
                ],
                # Electrum sorts child pubkeys lexicographically:
                sort_keys=True,
            )
            derived_addr = redeem_script.address(network="testnet")
            self.assertEqual(derived_addr, expected_receive_addr)

        # validate change addrs match electrum
        for cnt, expected_change_addr in enumerate(expected_change_addrs):
            redeem_script = RedeemScript.create_p2sh_multisig(
                quorum_m=1,
                pubkey_hexes=[
                    child_xpriv_1.traverse(f"m/1/{cnt}").pub.sec().hex(),
                    child_xpriv_2.traverse(f"m/1/{cnt}").pub.sec().hex(),
                ],
                # Electrum sorts lexicographically:
                sort_keys=True,
            )
            derived_addr = redeem_script.address(network="testnet")
            self.assertEqual(derived_addr, expected_change_addr)

        # For recovery only
        misordered_pubkeys_addr = "2NFzScjC9jaMbo5ST4M1WVeeWgSaVT7xS1W"
        pubkey_hexes = [
            child_xpriv_1.traverse("m/0/0").pub.sec().hex(),
            child_xpriv_2.traverse("m/0/0").pub.sec().hex(),
        ]
        misordered_redeem_script = RedeemScript.create_p2sh_multisig(
            quorum_m=1,
            # Note that the order here is intentional explicit and we're NOT sorting lexicographically (reverse=True)
            pubkey_hexes=sorted(pubkey_hexes, reverse=True),
            sort_keys=False,
            expected_addr=misordered_pubkeys_addr,
            expected_addr_network="testnet",
        )
        self.assertEqual(
            misordered_redeem_script.address("testnet"), misordered_pubkeys_addr
        )

        with self.assertRaises(ValueError):
            fake_addr = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"
            RedeemScript.create_p2sh_multisig(
                quorum_m=1,
                pubkey_hexes=pubkey_hexes,
                sort_keys=False,
                expected_addr=fake_addr,
                expected_addr_network="testnet",
            )


class WitnessScriptTest(TestCase):
    def test_address(self):
        witness_script_hex = "52210375e00eb72e29da82b89367947f29ef34afb75e8654f6ea368e0acdfd92976b7c2103a1b26313f430c4b15bb1fdce663207659d8cac749a0e53d70eff01874496feff2103c96d495bfdd5ba4145e3e046fee45e84a8a48ad05bd8dbb395c011a32cf9f88053ae"
        witness_script = WitnessScript.convert(bytes.fromhex(witness_script_hex))
        want = "bc1qwqdg6squsna38e46795at95yu9atm8azzmyvckulcc7kytlcckxswvvzej"
        self.assertEqual(witness_script.address(), want)

    def test_p2sh_address(self):
        witness_script_hex = "5221026ccfb8061f235cc110697c0bfb3afb99d82c886672f6b9b5393b25a434c0cbf32103befa190c0c22e2f53720b1be9476dcf11917da4665c44c9c71c3a2d28a933c352102be46dc245f58085743b1cc37c82f0d63a960efa43b5336534275fc469b49f4ac53ae"
        witness_script = WitnessScript.convert(bytes.fromhex(witness_script_hex))
        want = "2MvVx9ccWqyYVNa5Xz9pfCEVk99zVBZh9ms"
        self.assertEqual(witness_script.p2sh_address(network="testnet"), want)
        self.assertEqual(witness_script.p2sh_address(network="signet"), want)

    def test_p2wsh_with_quorum(self):

        p2wsh_script_hex = "ad51210236a6cf4254c8290a168ecab4aee771018d357ea87154a5b5fea9ed9baee2585e210355ec1001c2c4f1dce2de940beacbdcb7d7746140281a9283000aa46d251d46312103833d6e7c4121180fb79180b78a0573ad57c299825f18f49f6942cb38b6bf023a2103a9e341c32d8870706115443cf163bfc3d2da0ca8515a29bcc1a500c65cfb23bb2103b2ac11803043c0db884dcddfdcff02599324d5e747b26e4235f57b8019fae04155ae"
        witness_script = WitnessScript.parse(BytesIO(bytes.fromhex((p2wsh_script_hex))))

        want = "OP_1 0236a6cf4254c8290a168ecab4aee771018d357ea87154a5b5fea9ed9baee2585e 0355ec1001c2c4f1dce2de940beacbdcb7d7746140281a9283000aa46d251d4631 03833d6e7c4121180fb79180b78a0573ad57c299825f18f49f6942cb38b6bf023a 03a9e341c32d8870706115443cf163bfc3d2da0ca8515a29bcc1a500c65cfb23bb 03b2ac11803043c0db884dcddfdcff02599324d5e747b26e4235f57b8019fae041 OP_5 OP_CHECKMULTISIG "
        self.assertEqual(str(witness_script), want)
        self.assertTrue(witness_script.is_p2wsh_multisig())
        self.assertEqual(witness_script.get_quorum(), (1, 5))  # 1-of-5


class AddressToScriptPubKey(TestCase):
    def test_addr_to_script_pubkey(self):
        tests = (
            # scriptpubkey_type, addr, network
            (
                P2WPKHScriptPubKey,
                "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",
                "testnet",
            ),
            (
                P2WPKHScriptPubKey,
                "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
                "mainnet",
            ),
            (
                P2WSHScriptPubKey,
                "tb1qlrjv2ek09g9aplga83j9mfvelnt6qymen9gd49kpezdz2g5pgwnsfmrucp",
                "testnet",
            ),
            (
                P2WSHScriptPubKey,
                "bc1qwqdg6squsna38e46795at95yu9atm8azzmyvckulcc7kytlcckxswvvzej",
                "mainnet",
            ),
            (P2SHScriptPubKey, "2MvVx9ccWqyYVNa5Xz9pfCEVk99zVBZh9ms", "testnet"),
            (P2PKHScriptPubKey, "1BenRpVUFK65JFWcQSuHnJKzc4M8ZP8Eqa", "mainnet"),
        )
        for scriptpubkey_type, addr, network in tests:
            res = address_to_script_pubkey(addr)
            self.assertEqual(scriptpubkey_type, type(res))
            self.assertEqual(res.address(network=network), addr)
