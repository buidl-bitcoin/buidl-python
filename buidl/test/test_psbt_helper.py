from unittest import TestCase

from buidl.hd import HDPrivateKey
from buidl.psbt_helper import create_ps2sh_multisig_psbt
from buidl.script import RedeemScript


class P2SHTest(TestCase):
    def test_receive_1of2(self):
        # This test is not strictly neccesary, it just proves/shows how I generated the testnet address that received these coins
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
            redeem_script = RedeemScript.create_p2sh_multisig(
                quorum_m=1,
                pubkey_hex_list=[
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
                pubkey_hex_list=[
                    child_xpriv_1.traverse(f"m/1/{cnt}").pub.sec().hex(),
                    child_xpriv_2.traverse(f"m/1/{cnt}").pub.sec().hex(),
                ],
                # Electrum sorts lexicographically:
                sort_keys=True,
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

    def test_sweep_1of2_p2sh(self):

        # This test will produce a validly signed TX for the 1-of-2 p2sh using either key, which will result in a different TX ID
        # d8172be9981a4f57e6e4ebe0f4785f5f2035aee40ffbb2d6f1200810a879d490 is the one that was broadcast to the testnet blockchain:
        # https://blockstream.info/testnet/tx/d8172be9981a4f57e6e4ebe0f4785f5f2035aee40ffbb2d6f1200810a879d490

        kwargs = {
            "quorum_m": 1,
            "xpubs_dict": {
                "e0c595c5": {
                    # action x12
                    "xpub_hex": "tpubDBnspiLZfrq1V7j1iuMxGiPsuHyy6e4QBnADwRrbH89AcnsUEMfWiAYXmSbMuNFsrMdnbQRDGGSM1AFGL6zUWNVSmwRavoJzdQBbZKLgLgd",
                    "base_path": "m/45h/0",
                },
                "838f3ff9": {
                    # agent x12
                    "xpub_hex": "tpubDAKJicb9Tkw34PFLEBUcbnH99twN3augmg7oYHHx9Aa9iodXmA4wtGEJr8h2XjJYqn2j1v5qHLjpWEe8aPihmC6jmsgomsuc9Zeh4ZushNk",
                    "base_path": "m/45h/0",
                },
            },
            "input_dicts": [
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
            "output_dicts": [
                {
                    "sats": 999500,
                    "address": "mkHS9ne12qx9pS9VojpwU5xtRd4T7X7ZUt",
                },
            ],
            "fee_sats": 213684,
        }

        expected_unsigned_psbt_hex = "70736274ff01005801000000000101daa77c81a45d35ca2da4c6676043ee60f1ac9a9e350a4a78bb014d66a7d212440000000000ffffffff014c400f00000000001976a914344a0f48ca150ec2b903817660b9b68b13a6702688ac0000000000000100e002000000000101380bff9db676d159ad34849079c77e0d5c1df9c841b6a6640cba9bfc15077eea0100000000feffffff02008312000000000017a914d96bb9c5888f473dbd077d77009fb49ba2fda24287611c92a00100000017a9148722f07fbcf0fc506ea4ba9daa811d11396bbcfd870247304402202fe3c2f18e1486407bf0baabd2b3376102f0844a754d8e2fb8de71b39b3f76c702200c1fe8f7f9ef5165929ed51bf754edd7dd3e591921979cf5b891c841a1fd19d80121037c8fe1fa1ae4dfff522c532917c73c4884469e3b6a284e9a039ec612dca78eefd29c1e00010447512102139f7167f17da94d24df6fe2868cdb5edabd0cff83ab487c942ea2f07570d9f021023cb71c699990768c018df17a366c4eb74bde169f29e884261c10c973ec26ad3a52ae220602139f7167f17da94d24df6fe2868cdb5edabd0cff83ab487c942ea2f07570d9f014838f3ff92d0000800000000000000000000000002206023cb71c699990768c018df17a366c4eb74bde169f29e884261c10c973ec26ad3a14e0c595c52d0000800000000000000000000000000000"

        tests = (
            # (seed_word repeated x12, signed_tx_hash_hex),
            (
                # this is the one we broadcasted
                "action ",
                "d8172be9981a4f57e6e4ebe0f4785f5f2035aee40ffbb2d6f1200810a879d490",
            ),
            (
                "agent ",
                "c38dcee54f40193d668c8911eeba7ec20f570fdbdb31fbe4351f66d7005c7bfb",
            ),
        )

        # Now we prove we can sign this with either key
        for seed_word, signed_tx_hash_hex in tests:
            psbt_obj = create_ps2sh_multisig_psbt(**kwargs)
            self.assertEqual(psbt_obj.serialize().hex(), expected_unsigned_psbt_hex)

            hdpriv = HDPrivateKey.from_mnemonic(seed_word * 12, network="testnet")

            full_path_to_use = None
            for cnt, psbt_in in enumerate(psbt_obj.psbt_ins):

                self.assertEqual(psbt_in.redeem_script.get_quorum(), (1, 2))

                # For this TX there is only one psbt_in (1 input)
                for child_pubkey in psbt_in.redeem_script.signing_pubkeys():
                    named_pubkey = psbt_in.named_pubs[child_pubkey]
                    if (
                        named_pubkey.root_fingerprint.hex()
                        == hdpriv.fingerprint().hex()
                    ):
                        full_path_to_use = named_pubkey.root_path

                # In this example, the path is the same regardless of which key we sign with:
                self.assertEqual(full_path_to_use, "m/45'/0/0/0")

            private_keys = [hdpriv.traverse(full_path_to_use).private_key]

            self.assertTrue(psbt_obj.sign_with_private_keys(private_keys=private_keys))

            psbt_obj.finalize()

            self.assertEqual(psbt_obj.final_tx().hash().hex(), signed_tx_hash_hex)

    def test_spend_1of2_with_change(self):

        kwargs = {
            # this part is unchanged from the previous
            "quorum_m": 1,
            "xpubs_dict": {
                "e0c595c5": {
                    # action x12
                    "xpub_hex": "tpubDBnspiLZfrq1V7j1iuMxGiPsuHyy6e4QBnADwRrbH89AcnsUEMfWiAYXmSbMuNFsrMdnbQRDGGSM1AFGL6zUWNVSmwRavoJzdQBbZKLgLgd",
                    "base_path": "m/45h/0",
                },
                "838f3ff9": {
                    # agent x12
                    "xpub_hex": "tpubDAKJicb9Tkw34PFLEBUcbnH99twN3augmg7oYHHx9Aa9iodXmA4wtGEJr8h2XjJYqn2j1v5qHLjpWEe8aPihmC6jmsgomsuc9Zeh4ZushNk",
                    "base_path": "m/45h/0",
                },
            },
            # this part is changed:
            "input_dicts": [
                {
                    "path_dict": {
                        # xfp: child_path
                        "e0c595c5": "m/0/1",
                        "838f3ff9": "m/0/1",
                    },
                    "prev_tx_dict": {
                        "hex": "020000000001012c40a6810f7a670913d171e1f5b203ca01ed45ed3bf68b649850491eecb560080100000000feffffff02a7e50941010000001600147b3af2253632c3000f9cdd531747107fe249c7d1102700000000000017a91459fb638aaa55a7119a09faf5e8b2ce8a879cce338702473044022004666d885310990e1b0a61e93b1490acb172d43200d6fcfa22e89905b7f3094d02204a705e4a4fc8cab97f7d146f481e70718ee4567486796536d14c7808be3fd866012102cc3b01d2192b5275d3fda7f82eaf593dfb8ca9333f7296f93da401f8d1821335619f1e00",
                        "hash_hex": "3bbc91c1de188528d254ed145b1aabbb68b9050f7c660b345fc9feba73ff94a2",
                        "output_idx": 1,
                        "output_sats": 10000,
                    },
                },
            ],
            "output_dicts": [
                {
                    # this should be change:
                    "sats": 1000,
                    "address": "2MzQhXqN93igSKGW9CMvkpZ9TYowWgiNEF8",
                    "path_dict": {
                        # xfp: child_path (m/1/* is receiving addr branch)
                        "e0c595c5": "m/1/0",
                        "838f3ff9": "m/1/0",
                    },
                },
                {
                    # testnet faucet:
                    "sats": 5000,
                    "address": "tb1ql7w62elx9ucw4pj5lgw4l028hmuw80sndtntxt",
                },
            ],
            "fee_sats": 4000,
        }

        expected_unsigned_psbt_hex = "70736274ff01007501000000000101a294ff73bafec95f340b667c0f05b968bbab1a5b14ed54d2288518dec191bc3b0100000000ffffffff02e80300000000000017a9144e939ddfe567971692d19559f1f92d4fae5aa056878813000000000000160014ff9da567e62f30ea8654fa1d5fbd47bef8e3be130000000000000100df020000000001012c40a6810f7a670913d171e1f5b203ca01ed45ed3bf68b649850491eecb560080100000000feffffff02a7e50941010000001600147b3af2253632c3000f9cdd531747107fe249c7d1102700000000000017a91459fb638aaa55a7119a09faf5e8b2ce8a879cce338702473044022004666d885310990e1b0a61e93b1490acb172d43200d6fcfa22e89905b7f3094d02204a705e4a4fc8cab97f7d146f481e70718ee4567486796536d14c7808be3fd866012102cc3b01d2192b5275d3fda7f82eaf593dfb8ca9333f7296f93da401f8d1821335619f1e0001044751210226e53c7ab615da468364ca9f59879f51bd94278c26a39cac59a235a7cf8145932102d221e17bb80cf130bb0931434afac5e55f377ed9b2b003519a529ce02862444752ae22060226e53c7ab615da468364ca9f59879f51bd94278c26a39cac59a235a7cf81459314838f3ff92d000080000000000000000001000000220602d221e17bb80cf130bb0931434afac5e55f377ed9b2b003519a529ce02862444714e0c595c52d000080000000000000000001000000000000"

        # With p2sh, txid changes depending on which key signs
        tests = (
            # (seed_word repeated x12, signed_tx_hash_hex),
            (
                # this one we did not broadcast
                "action ",
                "0eefb9c614abff0fe859c2dd524a5cfc9582389c9ec938c02f2afb36c64a8e69",
            ),
            (
                # this is the one we did broadcast
                # https://blockstream.info/testnet/tx/5b7f81bbef354a48097d429cc6e5b7aad1a1b6940faa4aba284a8913fff643dc
                "agent ",
                "5b7f81bbef354a48097d429cc6e5b7aad1a1b6940faa4aba284a8913fff643dc",
            ),
        )

        # Now we prove we can sign this with either key
        for seed_word, signed_tx_hash_hex in tests:
            psbt_obj = create_ps2sh_multisig_psbt(**kwargs)
            self.assertEqual(psbt_obj.serialize().hex(), expected_unsigned_psbt_hex)

            hdpriv = HDPrivateKey.from_mnemonic(seed_word * 12, network="testnet")

            full_path_to_use = None
            for cnt, psbt_in in enumerate(psbt_obj.psbt_ins):

                self.assertEqual(psbt_in.redeem_script.get_quorum(), (1, 2))

                # For this TX there is only one psbt_in (1 input)
                for child_pubkey in psbt_in.redeem_script.signing_pubkeys():
                    named_pubkey = psbt_in.named_pubs[child_pubkey]
                    if (
                        named_pubkey.root_fingerprint.hex()
                        == hdpriv.fingerprint().hex()
                    ):
                        full_path_to_use = named_pubkey.root_path

                # In this example, the path is the same regardless of which key we sign with:
                self.assertEqual(full_path_to_use, "m/45'/0/0/1")

            private_keys = [hdpriv.traverse(full_path_to_use).private_key]

            self.assertTrue(psbt_obj.sign_with_private_keys(private_keys=private_keys))

            psbt_obj.finalize()

            self.assertEqual(psbt_obj.final_tx().hash().hex(), signed_tx_hash_hex)

        # Demonstrate that we will throw an error if the change address doesn't validate:

        # Confirm that swapping out the change address throws an error
        modified_kwargs = kwargs.copy()
        # nonsense address corresponding to secret exponent = 1
        fake_addr = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"
        modified_kwargs["output_dicts"][0]["address"] = fake_addr
        with self.assertRaises(ValueError):
            create_ps2sh_multisig_psbt(**modified_kwargs)

        # Confirm that changing the change paths (so that they no longer match the change address) throws an error
        modified_kwargs = kwargs.copy()
        # Change the path used to validate the change address
        # We don't bother altering 838f3ff9's path as well because changing anything will already throw this error
        modified_kwargs["output_dicts"][0]["path_dict"]["e0c595c5"] = "m/999"
        with self.assertRaises(ValueError):
            create_ps2sh_multisig_psbt(**modified_kwargs)
