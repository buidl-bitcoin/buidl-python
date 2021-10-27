from unittest import TestCase
from copy import deepcopy

from buidl.hd import HDPrivateKey, HDPublicKey
from buidl.psbt_helper import create_p2sh_multisig_psbt
from buidl.script import RedeemScript


class P2SHTest(TestCase):
    def test_receive_1of2(self):
        # This test is not strictly neccesary, it just proves/shows how I generated the testnet address that received these coins
        # In the next test, I'll show to spend them

        # For full details, see test_create_p2sh_multisig in test_script.py

        # Insecure testing BIP39 mnemonics
        root_path = "m/45'/0/0/0"
        hdprivs = [
            HDPrivateKey.from_mnemonic(seed_word * 12, network="testnet")
            for seed_word in ("action ", "agent ")
        ]

        # Validate the 0th receive address for m/45'/0
        expected_spending_addr = "2ND4qfpdHyeXJboAUkKZqJsyiKyXvHRKhbi"
        pubkey_hexes = [
            hdpriv.traverse(root_path).pub.sec().hex() for hdpriv in hdprivs
        ]

        redeem_script_to_use = RedeemScript.create_p2sh_multisig(
            quorum_m=1,
            pubkey_hexes=pubkey_hexes,
            sort_keys=True,
        )
        self.assertEqual(
            expected_spending_addr, redeem_script_to_use.address(network="testnet")
        )

        # Faucet TX sent to this address:
        # https://blockstream.info/testnet/tx/4412d2a7664d01bb784a0a359e9aacf160ee436067c6a42dca355da4817ca7da

    def test_sweep_1of2_p2sh(self):

        # This test will produce a validly signed TX for the 1-of-2 p2sh using either key, which will result in a different TX ID
        # d8172be9981a4f57e6e4ebe0f4785f5f2035aee40ffbb2d6f1200810a879d490 is the one that was broadcast to the testnet blockchain:
        # https://blockstream.info/testnet/tx/d8172be9981a4f57e6e4ebe0f4785f5f2035aee40ffbb2d6f1200810a879d490

        kwargs = {
            "public_key_records": [
                # action x12
                [
                    "e0c595c5",
                    "tpubDBnspiLZfrq1V7j1iuMxGiPsuHyy6e4QBnADwRrbH89AcnsUEMfWiAYXmSbMuNFsrMdnbQRDGGSM1AFGL6zUWNVSmwRavoJzdQBbZKLgLgd",
                    "m/45'/0",
                ],
                # agent x12
                [
                    "838f3ff9",
                    "tpubDAKJicb9Tkw34PFLEBUcbnH99twN3augmg7oYHHx9Aa9iodXmA4wtGEJr8h2XjJYqn2j1v5qHLjpWEe8aPihmC6jmsgomsuc9Zeh4ZushNk",
                    "m/45'/0",
                ],
            ],
            "input_dicts": [
                {
                    "quorum_m": 1,
                    "path_dict": {
                        # xfp: root_path
                        "e0c595c5": "m/45'/0/0/0",
                        "838f3ff9": "m/45'/0/0/0",
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

        expected_unsigned_psbt_b64 = "cHNidP8BAFUBAAAAAdqnfIGkXTXKLaTGZ2BD7mDxrJqeNQpKeLsBTWan0hJEAAAAAAD/////AUxADwAAAAAAGXapFDRKD0jKFQ7CuQOBdmC5tosTpnAmiKwAAAAATwEENYfPAheO+c4AAAAALjD5unTcevzcKaWlkg/+xoU+FD5bJ+iltDa2WE1bTngCfSOd3kkScA1e4OGM3MJ/Oqg+nxEHlwuV7YBCuoT745YMg48/+S0AAIAAAAAATwEENYfPAuBIVlUAAAAAHnpWPWgBnfWu2tzv9Ujws27ps0hOBHMQbZlpQ6c5m4MDN4/ffnc3ejfVlqkEgG7tlPX4aTS92pfU5LAvGDQQKHoM4MWVxS0AAIAAAAAAAAEA4AIAAAAAAQE4C/+dtnbRWa00hJB5x34NXB35yEG2pmQMupv8FQd+6gEAAAAA/v///wIAgxIAAAAAABepFNlrucWIj0c9vQd9dwCftJui/aJCh2EckqABAAAAF6kUhyLwf7zw/FBupLqdqoEdETlrvP2HAkcwRAIgL+PC8Y4UhkB78Lqr0rM3YQLwhEp1TY4vuN5xs5s/dscCIAwf6Pf571Flkp7VG/dU7dfdPlkZIZec9biRyEGh/RnYASEDfI/h+hrk3/9SLFMpF8c8SIRGnjtqKE6aA57GEtynju/SnB4AAQRHUSECE59xZ/F9qU0k32/ihozbXtq9DP+Dq0h8lC6i8HVw2fAhAjy3HGmZkHaMAY3xejZsTrdL3hafKeiEJhwQyXPsJq06Uq4iBgITn3Fn8X2pTSTfb+KGjNte2r0M/4OrSHyULqLwdXDZ8BSDjz/5LQAAgAAAAAAAAAAAAAAAACIGAjy3HGmZkHaMAY3xejZsTrdL3hafKeiEJhwQyXPsJq06FODFlcUtAACAAAAAAAAAAAAAAAAAAAA="
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
            psbt_obj = create_p2sh_multisig_psbt(**kwargs)
            self.assertEqual(len(psbt_obj.hd_pubs), 2)
            self.assertEqual(psbt_obj.serialize_base64(), expected_unsigned_psbt_b64)

            hdpriv = HDPrivateKey.from_mnemonic(seed_word * 12, network="testnet")

            root_path_to_use = None
            for cnt, psbt_in in enumerate(psbt_obj.psbt_ins):

                self.assertEqual(psbt_in.redeem_script.get_quorum(), (1, 2))

                # For this TX there is only one psbt_in (1 input)
                for child_pubkey in psbt_in.redeem_script.signing_pubkeys():
                    named_pubkey = psbt_in.named_pubs[child_pubkey]
                    if (
                        named_pubkey.root_fingerprint.hex()
                        == hdpriv.fingerprint().hex()
                    ):
                        root_path_to_use = named_pubkey.root_path

                # In this example, the path is the same regardless of which key we sign with:
                self.assertEqual(root_path_to_use, "m/45'/0/0/0")

            private_keys = [hdpriv.traverse(root_path_to_use).private_key]

            self.assertTrue(psbt_obj.sign_with_private_keys(private_keys=private_keys))

            psbt_obj.finalize()

            self.assertEqual(psbt_obj.final_tx().hash().hex(), signed_tx_hash_hex)

    def test_spend_1of2_with_change(self):

        kwargs = {
            # this part is unchanged from the previous
            "public_key_records": [
                # action x12
                [
                    "e0c595c5",
                    "tpubDBnspiLZfrq1V7j1iuMxGiPsuHyy6e4QBnADwRrbH89AcnsUEMfWiAYXmSbMuNFsrMdnbQRDGGSM1AFGL6zUWNVSmwRavoJzdQBbZKLgLgd",
                    "m/45'/0",
                ],
                # agent x12
                [
                    "838f3ff9",
                    "tpubDAKJicb9Tkw34PFLEBUcbnH99twN3augmg7oYHHx9Aa9iodXmA4wtGEJr8h2XjJYqn2j1v5qHLjpWEe8aPihmC6jmsgomsuc9Zeh4ZushNk",
                    "m/45'/0",
                ],
            ],
            # this part is changed:
            "input_dicts": [
                {
                    "quorum_m": 1,
                    "path_dict": {
                        # xfp: root_path
                        "e0c595c5": "m/45'/0/0/1",
                        "838f3ff9": "m/45'/0/0/1",
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
                    "quorum_m": 1,
                    "path_dict": {
                        # xfp: root_path (m/.../1/*/{idx} is change addr branch)
                        "e0c595c5": "m/45'/0/1/0",
                        "838f3ff9": "m/45'/0/1/0",
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

        expected_unsigned_psbt_b64 = "cHNidP8BAHIBAAAAAaKU/3O6/slfNAtmfA8FuWi7qxpbFO1U0iiFGN7Bkbw7AQAAAAD/////AugDAAAAAAAAF6kUTpOd3+VnlxaS0ZVZ8fktT65aoFaHiBMAAAAAAAAWABT/naVn5i8w6oZU+h1fvUe++OO+EwAAAABPAQQ1h88CF475zgAAAAAuMPm6dNx6/NwppaWSD/7GhT4UPlsn6KW0NrZYTVtOeAJ9I53eSRJwDV7g4Yzcwn86qD6fEQeXC5XtgEK6hPvjlgyDjz/5LQAAgAAAAABPAQQ1h88C4EhWVQAAAAAeelY9aAGd9a7a3O/1SPCzbumzSE4EcxBtmWlDpzmbgwM3j99+dzd6N9WWqQSAbu2U9fhpNL3al9TksC8YNBAoegzgxZXFLQAAgAAAAAAAAQDfAgAAAAABASxApoEPemcJE9Fx4fWyA8oB7UXtO/aLZJhQSR7stWAIAQAAAAD+////AqflCUEBAAAAFgAUezryJTYywwAPnN1TF0cQf+JJx9EQJwAAAAAAABepFFn7Y4qqVacRmgn69eiyzoqHnM4zhwJHMEQCIARmbYhTEJkOGwph6TsUkKyxctQyANb8+iLomQW38wlNAiBKcF5KT8jKuX99FG9IHnBxjuRWdIZ5ZTbRTHgIvj/YZgEhAsw7AdIZK1J10/2n+C6vWT37jKkzP3KW+T2kAfjRghM1YZ8eAAEER1EhAiblPHq2FdpGg2TKn1mHn1G9lCeMJqOcrFmiNafPgUWTIQLSIeF7uAzxMLsJMUNK+sXlXzd+2bKwA1GaUpzgKGJER1KuIgYCJuU8erYV2kaDZMqfWYefUb2UJ4wmo5ysWaI1p8+BRZMUg48/+S0AAIAAAAAAAAAAAAEAAAAiBgLSIeF7uAzxMLsJMUNK+sXlXzd+2bKwA1GaUpzgKGJERxTgxZXFLQAAgAAAAAAAAAAAAQAAAAABAEdRIQJ3tPielqw9CAqDy+Tn23vo4cUxiYYGk/KWtw5ryOPJ3yEC1WIbkoA7VEDNWw0VmAntyxp6EY5IfZ7sbF1PNJklWFFSriICAne0+J6WrD0ICoPL5Ofbe+jhxTGJhgaT8pa3DmvI48nfFODFlcUtAACAAAAAAAEAAAAAAAAAIgIC1WIbkoA7VEDNWw0VmAntyxp6EY5IfZ7sbF1PNJklWFEUg48/+S0AAIAAAAAAAQAAAAAAAAAAAA=="

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
            psbt_obj = create_p2sh_multisig_psbt(**kwargs)
            self.assertEqual(len(psbt_obj.hd_pubs), 2)
            self.assertEqual(psbt_obj.serialize_base64(), expected_unsigned_psbt_b64)

            hdpriv = HDPrivateKey.from_mnemonic(seed_word * 12, network="testnet")

            root_path_to_use = None
            for cnt, psbt_in in enumerate(psbt_obj.psbt_ins):

                self.assertEqual(psbt_in.redeem_script.get_quorum(), (1, 2))

                # For this TX there is only one psbt_in (1 input)
                for child_pubkey in psbt_in.redeem_script.signing_pubkeys():
                    named_pubkey = psbt_in.named_pubs[child_pubkey]
                    if (
                        named_pubkey.root_fingerprint.hex()
                        == hdpriv.fingerprint().hex()
                    ):
                        root_path_to_use = named_pubkey.root_path

                # In this example, the path is the same regardless of which key we sign with:
                self.assertEqual(root_path_to_use, "m/45'/0/0/1")

            private_keys = [hdpriv.traverse(root_path_to_use).private_key]

            self.assertTrue(psbt_obj.sign_with_private_keys(private_keys=private_keys))

            psbt_obj.finalize()

            self.assertEqual(psbt_obj.final_tx().hash().hex(), signed_tx_hash_hex)

        # Replace xfps
        psbt_obj = create_p2sh_multisig_psbt(**kwargs)
        with self.assertRaises(ValueError) as cm:
            # deadbeef  not in psbt
            psbt_obj.replace_root_xfps({"deadbeef": "00000000"})
        self.assertEqual(str(cm.exception), "xfp_hex deadbeef not found in psbt")

        psbt_obj.replace_root_xfps({"e0c595c5": "00000000"})
        self.assertNotEqual(psbt_obj.serialize_base64(), expected_unsigned_psbt_b64)

        # Confirm that swapping out the change address throws an error
        # nonsense address corresponding to secret exponent = 1
        modified_kwargs = deepcopy(kwargs)
        fake_addr = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"
        modified_kwargs["output_dicts"][0]["address"] = fake_addr
        with self.assertRaises(ValueError) as cm:
            create_p2sh_multisig_psbt(**modified_kwargs)
        self.assertEqual(
            "Invalid redeem script for output #0. Expecting 2MzQhXqN93igSKGW9CMvkpZ9TYowWgiNEF8 but got tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",
            str(cm.exception),
        )

        # Confirm that changing the change paths (so that they no longer match the change address) throws an error
        # Change the path used to validate the change address
        # We don't bother altering 838f3ff9's path as well because changing anything will already throw this error
        modified_kwargs = deepcopy(kwargs)
        modified_kwargs["output_dicts"][0]["path_dict"]["e0c595c5"] = "m/999"
        with self.assertRaises(ValueError) as cm:
            create_p2sh_multisig_psbt(**modified_kwargs)
        self.assertEqual(
            "xfp_hex e0c595c5 with m/999 for in/output #0 not supplied in xpub_dict",
            str(cm.exception),
        )

    def test_full_wallet_functionality(self):
        """
        Create a wallet, fund it, and spend it (validating on all devices first).
        Do this both with and without change.
        """

        child_path = "m/0/0"
        base_path = "m/45'/0"
        xpubs = [
            # Verified against electrum 2021-10
            "tpubDAp5uHrhyCRnoQdMmF9xFU78bev55TKux39Viwn8VCnWywjTCBB3TFSA1i5i4scj8ZkD8RR37EZMPyqBwk4wD4VNpxyowgk2rQ7i8AdVauN",
            "tpubDBxHJMmnouRSes7kweA5wUp2Jm5F1xEPCG3fjYRnBSiQM7hjsp9gp8Wsag16A8yrpMgJkPX8iddXmwuxKaUnAWfdcGcuXbiATYeGXCKkEXK",
            "tpubDANTttKyukGYwXvhTmdCa6p1nHmsbFef2yRXb9b2JTvLGoekYk6ZG9oHXGHYJjTn5g3DijvQrZ4rH6EosYqpVngKiUx2jvWdPmq6ZSDr3ZE",
        ]

        xfps = ["9a6a2580", "8c7e2500", "0586b1ce"]

        pubkey_records = []
        for cnt, seed_word in enumerate(("bacon", "flag", "gas")):
            seed_phrase = f"{seed_word} " * 24
            hd_obj = HDPrivateKey.from_mnemonic(seed_phrase, network="testnet")

            # takes the form xfp, child_xpub, base_path
            pubkey_record = [
                hd_obj.fingerprint().hex(),
                hd_obj.traverse(base_path).xpub(),
                base_path,
            ]
            pubkey_records.append(pubkey_record)

            self.assertEqual(pubkey_record, [xfps[cnt], xpubs[cnt], base_path])

        pubkey_hexes = [
            HDPublicKey.parse(tpub).traverse(child_path).sec().hex() for tpub in xpubs
        ]

        rs_obj = RedeemScript.create_p2sh_multisig(
            quorum_m=2, pubkey_hexes=pubkey_hexes, sort_keys=True
        )

        deposit_address = rs_obj.address(network="testnet")
        # We funded this testnet address in 2021-10:
        self.assertEqual(deposit_address, "2MzLzwPgo6ZTyPzkguNWKfFHgCXdZSJu9tL")

        input_dicts = [
            {
                "quorum_m": 2,
                "path_dict": {
                    # xfp: root_path
                    "9a6a2580": "m/45'/0/0/0",
                    "8c7e2500": "m/45'/0/0/0",
                    "0586b1ce": "m/45'/0/0/0",
                },
                "prev_tx_dict": {
                    # This was the funding transaction send to 2MzLzwPgo6ZTyPzkguNWKfFHgCXdZSJu9tL
                    "hex": "02000000000101045448b2faafc53a7586bd6a746a598d9a1cfc3dd548d8f8afd12c11c53c16740000000000feffffff02809a4b000000000017a914372becc78d20f8acb94059fa8d1e3219b67c1d9387a08601000000000017a9144de07b9788bc64143292f9610443a7f81cc5fc308702473044022059f2036e5b6da03e592863664082f957472dbb89330895d23ac66f94e3819f63022050d31d401cd86fe797c31ba7fb2a2cf9e12356bba8388897f4f522bc4999224f0121029c71554e111bb41463ad288b4808effef8136755da80d42aa2bcea12ed8a99bbba0e2000",
                    "hash_hex": "838504ad934d97915d9ab58b0ece6900ed123abf3a51936563ba9d67b0e41fa4",
                    "output_idx": 1,
                    "output_sats": 100_000,
                },
            }
        ]

        base_description_want = {
            "locktime": 0,
            "version": 1,
            "network": "testnet",
            "spend_addr": "2MxvTasFXms6w1R6omwqtKKTYDyjrbhCTYd",
            "is_batch_tx": False,
            "inputs_desc": [
                {
                    "quorum": "2-of-3",
                    "bip32_derivs": [
                        {
                            "pubkey": "02861f9fd125b4183cd3d5645ff7c7697573e7cf6da174aa993a25d498191f4ff4",
                            "master_fingerprint": "0586b1ce",
                            "path": "m/45'/0/0/0",
                            "xpub": "tpubDANTttKyukGYwXvhTmdCa6p1nHmsbFef2yRXb9b2JTvLGoekYk6ZG9oHXGHYJjTn5g3DijvQrZ4rH6EosYqpVngKiUx2jvWdPmq6ZSDr3ZE",
                        },
                        {
                            "pubkey": "03c46aea215fd0017576534cfad56aa06d14043947add8ffe4cb7b4ba1d9b023b3",
                            "master_fingerprint": "8c7e2500",
                            "path": "m/45'/0/0/0",
                            "xpub": "tpubDBxHJMmnouRSes7kweA5wUp2Jm5F1xEPCG3fjYRnBSiQM7hjsp9gp8Wsag16A8yrpMgJkPX8iddXmwuxKaUnAWfdcGcuXbiATYeGXCKkEXK",
                        },
                        {
                            "pubkey": "03f25b39eec4d2824883b2e4cb010adb7685f13540805767c763808a599fd8df36",
                            "master_fingerprint": "9a6a2580",
                            "path": "m/45'/0/0/0",
                            "xpub": "tpubDAp5uHrhyCRnoQdMmF9xFU78bev55TKux39Viwn8VCnWywjTCBB3TFSA1i5i4scj8ZkD8RR37EZMPyqBwk4wD4VNpxyowgk2rQ7i8AdVauN",
                        },
                    ],
                    "prev_txhash": "838504ad934d97915d9ab58b0ece6900ed123abf3a51936563ba9d67b0e41fa4",
                    "prev_idx": 1,
                    "n_sequence": 4294967295,
                    "sats": 100000,
                    "addr": "2MzLzwPgo6ZTyPzkguNWKfFHgCXdZSJu9tL",
                    "witness_script": None,
                    "redeem_script": "OP_2 02861f9fd125b4183cd3d5645ff7c7697573e7cf6da174aa993a25d498191f4ff4 03c46aea215fd0017576534cfad56aa06d14043947add8ffe4cb7b4ba1d9b023b3 03f25b39eec4d2824883b2e4cb010adb7685f13540805767c763808a599fd8df36 OP_3 OP_CHECKMULTISIG ",
                }
            ],
            "root_paths": {
                "0586b1ce": {"m/45'/0/0/0"},
                "8c7e2500": {"m/45'/0/0/0"},
                "9a6a2580": {"m/45'/0/0/0"},
            },
        }

        # We broadcast this to the testnet blockchain (confirmed in block 000000000000000ce65761d5949a930daa84381a5fb86c930947ea88742c957d)
        # Takes the form: (tx_output_dicts, psbt_outputs_desc, psbt_desc_want, expected_tx_hash)
        sweep_test_output = (
            # tx_output_dicts
            [
                # Sweep to faucet
                {
                    "sats": 60_000,
                    "address": "2MxvTasFXms6w1R6omwqtKKTYDyjrbhCTYd",
                },
            ],
            # psbt_outputs_desc
            [
                {
                    "sats": 60_000,
                    "addr": "2MxvTasFXms6w1R6omwqtKKTYDyjrbhCTYd",
                    "addr_type": "P2SH",
                    "is_change": False,
                }
            ],
            # psbt_desc_want
            {
                "txid": "1b768c9e7bc19898fbe92d28a5b3ed482ea9719cd34a77b8b9bcb050a99466c7",
                "tx_fee_sats": 40_000,
                "total_input_sats": 100_000,
                "total_output_sats": 60_000,
                "spend_sats": 60_000,
                "change_addr": "",
                "change_sats": 0,
                "tx_summary_text": "PSBT sends 60,000 sats to 2MxvTasFXms6w1R6omwqtKKTYDyjrbhCTYd with a fee of 40,000 sats (40.0% of spend)",
            },
            # expected_tx_hash
            "229fd99a2abab6c2b193bde547920424d2903978c4129472b06c9d2ffaced025",
        )

        # We sign but don't broadcast this
        # Takes the form: (tx_output_dicts, psbt_outputs_desc, psbt_desc_want, expected_tx_hash)
        change_test_outputs = (
            # tx_output_dicts
            [
                # Spend to faucet
                {
                    "sats": 50_000,
                    "address": "2MxvTasFXms6w1R6omwqtKKTYDyjrbhCTYd",
                },
                # Change back to self
                {
                    "sats": 30_000,
                    "address": "2MzJEYwRjTcpdpMa9J2sb9QQAWNB34umhbV",
                    "quorum_m": 2,
                    "path_dict": {
                        # xfp: root_path (m/.../1/*/{idx} is change addr branch)
                        "0586b1ce": "m/45'/0/1/0",
                        "8c7e2500": "m/45'/0/1/0",
                        "9a6a2580": "m/45'/0/1/0",
                    },
                },
            ],
            # psbt_outputs_desc
            [
                {
                    "sats": 50_000,
                    "addr": "2MxvTasFXms6w1R6omwqtKKTYDyjrbhCTYd",
                    "addr_type": "P2SH",
                    "is_change": False,
                },
                {
                    "sats": 30_000,
                    "addr": "2MzJEYwRjTcpdpMa9J2sb9QQAWNB34umhbV",
                    "addr_type": "P2SH",
                    "is_change": True,
                    "witness_script": None,
                    "redeem_script": "OP_2 02a1921eba209b568f6fa904c4b1e1b87790d2b73d48607aad4db91f977879a16b 02bae8e95f63062500fa18a5142e7103d1783cae028c56293735f7bddbf3ba7b15 032953df01093cab0c2d73067c90509039fe3599a2f80e9b90a6c2229eba432208 OP_3 OP_CHECKMULTISIG ",
                },
            ],
            # psbt_desc_want
            {
                "txid": "076baed6061d88f2342b57e8c9b1b96cf155cec0dce93e6f7d80b2c540876166",
                "tx_fee_sats": 20_000,
                "total_input_sats": 100_000,
                "total_output_sats": 80_000,
                "spend_sats": 50_000,
                "change_addr": "2MzJEYwRjTcpdpMa9J2sb9QQAWNB34umhbV",
                "change_sats": 30_000,
                "tx_summary_text": "PSBT sends 50,000 sats to 2MxvTasFXms6w1R6omwqtKKTYDyjrbhCTYd with a fee of 20,000 sats (20.0% of spend)",
            },
            # expected_tx_hash
            "668a7d61aa09c01db90a477e6aabdc433712b161cf419d23e94f0c1fc3a89097",
        )

        test_outputs = (change_test_outputs, sweep_test_output)

        for (
            tx_output_dicts,
            psbt_outputs_desc,
            psbt_desc_want,
            expected_tx_hash,
        ) in test_outputs:

            # Return all the funds to the faucet address
            psbt_obj = create_p2sh_multisig_psbt(
                public_key_records=pubkey_records,
                input_dicts=input_dicts,
                output_dicts=tx_output_dicts,
                fee_sats=psbt_desc_want["tx_fee_sats"],
            )

            self.assertTrue(psbt_obj.validate())

            description_want = {
                **base_description_want,
                **psbt_desc_want,
                **{"outputs_desc": psbt_outputs_desc},
            }

            self.assertEqual(psbt_obj.describe_basic_multisig(), description_want)

            # choosing to sign with these two seeds, could have signed with any 2-of-3
            private_child_keys = []
            for seed_word in ("bacon", "gas"):
                seed_phrase = f"{seed_word} " * 24
                hd_obj = HDPrivateKey.from_mnemonic(seed_phrase, network="testnet")
                private_child_key = hd_obj.traverse(f"{base_path}/0/0").private_key
                private_child_keys.append(private_child_key)

            self.assertTrue(psbt_obj.sign_with_private_keys(private_child_keys))

            psbt_obj.finalize()

            self.assertTrue(psbt_obj.validate())

            final_tx = psbt_obj.final_tx()

            # We would broadcast this to the network:
            # final_tx.serialize().hex()

            self.assertEqual(final_tx.hash().hex(), expected_tx_hash)
