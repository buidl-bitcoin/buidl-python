from unittest import TestCase

from buidl.hd import HDPrivateKey
from buidl.psbt_helper import create_ps2sh_multisig_psbt
from buidl.script import RedeemScript


class P2SHTest(TestCase):
    def test_receive_1of2(self):
        # This is not strictly neccesary, just proving/showing how I received these testnet coins
        # In the next test, I'll show to spend them
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
            pubkey_hex_list = [
                child_xpriv_1.traverse(f"m/0/{cnt}").pub.sec().hex(),
                child_xpriv_2.traverse(f"m/0/{cnt}").pub.sec().hex(),
            ]
            redeem_script = RedeemScript.create_p2sh_multisig(
                quorum_m=1,
                # Electrum sorts lexographically:
                pubkey_hex_list=sorted(pubkey_hex_list),
            )
            derived_addr = redeem_script.address(network="testnet")
            self.assertEqual(derived_addr, expected_receive_addr)

        # validate change addrs match electrum
        for cnt, expected_change_addr in enumerate(expected_change_addrs):
            pubkey_hex_list = [
                child_xpriv_1.traverse(f"m/1/{cnt}").pub.sec().hex(),
                child_xpriv_2.traverse(f"m/1/{cnt}").pub.sec().hex(),
            ]
            redeem_script = RedeemScript.create_p2sh_multisig(
                quorum_m=1,
                # Electrum sorts lexographically:
                pubkey_hex_list=sorted(pubkey_hex_list),
            )
            derived_addr = redeem_script.address(network="testnet")
            self.assertEqual(derived_addr, expected_change_addr)

        # Validate the 0th receive address for m/45'/0
        expected_spending_addr = "2ND4qfpdHyeXJboAUkKZqJsyiKyXvHRKhbi"
        child_path_to_use = "m/0/0"
        pubkey_hex_list = [
            child_xpriv.traverse(child_path_to_use).pub.sec().hex()
            for child_xpriv in (child_xpriv_1, child_xpriv_2)
        ]
        pubkey_hex_list.sort()

        redeem_script_to_use = RedeemScript.create_p2sh_multisig(
            quorum_m=1, pubkey_hex_list=pubkey_hex_list
        )
        self.assertEqual(
            expected_spending_addr, redeem_script_to_use.address(network="testnet")
        )

        # Faucet TX I sent myself to this address:
        # https://blockstream.info/testnet/tx/4412d2a7664d01bb784a0a359e9aacf160ee436067c6a42dca355da4817ca7da

    def test_spend_1of2_p2sh(self):

        # This test will produce a validly signed TX for the 1-of-2 p2sh using either key

        # Note: d8172be9981a4f57e6e4ebe0f4785f5f2035aee40ffbb2d6f1200810a879d490 is the one that was broadcast to the testnet blockchain:
        # https://blockstream.info/testnet/tx/d8172be9981a4f57e6e4ebe0f4785f5f2035aee40ffbb2d6f1200810a879d490

        psbt_instructions = {
            "quorum_m": 1,
            "xpub_dict_list": [
                {
                    # action x12
                    "xpub_hex": "tpubDBnspiLZfrq1V7j1iuMxGiPsuHyy6e4QBnADwRrbH89AcnsUEMfWiAYXmSbMuNFsrMdnbQRDGGSM1AFGL6zUWNVSmwRavoJzdQBbZKLgLgd",
                    "fingerprint_hex": "e0c595c5",
                    "base_path": "m/45h/0",
                },
                {
                    # agent x12
                    "xpub_hex": "tpubDAKJicb9Tkw34PFLEBUcbnH99twN3augmg7oYHHx9Aa9iodXmA4wtGEJr8h2XjJYqn2j1v5qHLjpWEe8aPihmC6jmsgomsuc9Zeh4ZushNk",
                    "fingerprint_hex": "838f3ff9",
                    "base_path": "m/45h/0",
                },
            ],
            "inputs_dict_list": [
                {
                    "path_dict": {
                        # xfp: child_path
                        "e0c595c5": "m/0/0",
                        "838f3ff9": "m/0/0",
                    },
                    "prev_tx_dict": {
                        "hex": "02000000000101380bff9db676d159ad34849079c77e0d5c1df9c841b6a6640cba9bfc15077eea0100000000feffffff02008312000000000017a914d96bb9c5888f473dbd077d77009fb49ba2fda24287611c92a00100000017a9148722f07fbcf0fc506ea4ba9daa811d11396bbcfd870247304402202fe3c2f18e1486407bf0baabd2b3376102f0844a754d8e2fb8de71b39b3f76c702200c1fe8f7f9ef5165929ed51bf754edd7dd3e591921979cf5b891c841a1fd19d80121037c8fe1fa1ae4dfff522c532917c73c4884469e3b6a284e9a039ec612dca78eefd29c1e00",
                        "hash_hex": "4412d2a7664d01bb784a0a359e9aacf160ee436067c6a42dca355da4817ca7da",
                        "output_idx": 0,
                        "output_sats": 1213184,
                    },
                },
            ],
            "outputs_dict_list": [
                {
                    "sats": 999500,
                    "address": "mkHS9ne12qx9pS9VojpwU5xtRd4T7X7ZUt",  # TODO: logic to go from script to addr
                },
            ],
            "fee_sats": 213684,
            "network": "testnet",
        }

        expected_unsigned_psbt_hex = "70736274ff01005801000000000101daa77c81a45d35ca2da4c6676043ee60f1ac9a9e350a4a78bb014d66a7d212440000000000ffffffff014c400f00000000001976a914344a0f48ca150ec2b903817660b9b68b13a6702688ac0000000000000100e002000000000101380bff9db676d159ad34849079c77e0d5c1df9c841b6a6640cba9bfc15077eea0100000000feffffff02008312000000000017a914d96bb9c5888f473dbd077d77009fb49ba2fda24287611c92a00100000017a9148722f07fbcf0fc506ea4ba9daa811d11396bbcfd870247304402202fe3c2f18e1486407bf0baabd2b3376102f0844a754d8e2fb8de71b39b3f76c702200c1fe8f7f9ef5165929ed51bf754edd7dd3e591921979cf5b891c841a1fd19d80121037c8fe1fa1ae4dfff522c532917c73c4884469e3b6a284e9a039ec612dca78eefd29c1e00010447512102139f7167f17da94d24df6fe2868cdb5edabd0cff83ab487c942ea2f07570d9f021023cb71c699990768c018df17a366c4eb74bde169f29e884261c10c973ec26ad3a52ae220602139f7167f17da94d24df6fe2868cdb5edabd0cff83ab487c942ea2f07570d9f014838f3ff92d0000800000000000000000000000002206023cb71c699990768c018df17a366c4eb74bde169f29e884261c10c973ec26ad3a14e0c595c52d0000800000000000000000000000000000"

        tests = (
            # seed_word (repeated 12x), signed_tx_hash_hex
            (
                "action ",
                "d8172be9981a4f57e6e4ebe0f4785f5f2035aee40ffbb2d6f1200810a879d490",
            ),  # this is the one we broadcasted
            (
                "agent ",
                "c38dcee54f40193d668c8911eeba7ec20f570fdbdb31fbe4351f66d7005c7bfb",
            ),
        )

        # Now we prove we can sign this with either key
        for seed_word, signed_tx_hash_hex in tests:
            psbt_obj = create_ps2sh_multisig_psbt(**psbt_instructions)
            self.assertEqual(psbt_obj.serialize().hex(), expected_unsigned_psbt_hex)

            hdpriv = HDPrivateKey.from_mnemonic(seed_word * 12, network="testnet")
            private_keys = [hdpriv.traverse("m/45h/0/0/0").private_key]

            assert psbt_obj.sign_with_private_keys(private_keys=private_keys) is True

            psbt_obj.finalize()

            assert psbt_obj.final_tx().hash().hex() == signed_tx_hash_hex
