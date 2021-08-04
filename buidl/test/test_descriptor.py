from unittest import TestCase

from buidl.descriptor import (
    calc_core_checksum,
    is_valid_xfp_hex,
    P2WSHSortedMulti,
    parse_full_key_record,
    parse_partial_key_record,
)
from buidl.hd import HDPrivateKey


class P2WSHMultiTest(TestCase):
    def test_p2wsh_1of4(self):
        valid_output_record = """wsh(sortedmulti(1,[c7d0648a/48h/1h/0h/2h]tpubDEpefcgzY6ZyEV2uF4xcW2z8bZ3DNeWx9h2BcwcX973BHrmkQxJhpAXoSWZeHkmkiTtnUjfERsTDTVCcifW6po3PFR1JRjUUTJHvPpDqJhr/0/*,[12980eed/48h/1h/0h/2h]tpubDEkXGoQhYLFnYyzUGadtceUKbzVfXVorJEdo7c6VKJLHrULhpSVLC7fo89DDhjHmPvvNyrun2LTWH6FYmHh5VaQYPLEqLviVQKh45ufz8Ae/0/*,[3a52b5cd/48h/1h/0h/2h]tpubDFdbVee2Zna6eL9TkYBZDJVJ3RxGYWgChksXBRgw6y6PU1jWPTXUqag3CBMd6VDwok1hn5HZGvg6ujsTLXykrS3DwbxqCzEvWoT49gRJy7s/0/*,[f7d04090/48h/1h/0h/2h]tpubDF7FTuPECTePubPXNK73TYCzV3nRWaJnRwTXD28kh6Fz4LcaRzWwNtX153J7WeJFcQB2T6k9THd424Kmjs8Ps1FC1Xb81TXTxxbGZrLqQNp/0/*))#tatkmj5q"""

        p2wsh_sortedmulti_obj = P2WSHSortedMulti.parse(valid_output_record)

        # Should recreate itself
        self.assertEqual(str(p2wsh_sortedmulti_obj), valid_output_record)

        self.assertEqual(p2wsh_sortedmulti_obj.network, "testnet")
        self.assertEqual(p2wsh_sortedmulti_obj.quorum_m, 1)

        self.assertEqual(p2wsh_sortedmulti_obj.checksum, "tatkmj5q")

        expected_change_addrs = [
            "tb1qf454te8pvz4txevejg8s8tx5kkyfxgtkpg6tu5xphnyf6l2gcjss5zw0jx",
            "tb1q0lh5an3hep9s57c5xkpyv0yldy825kzzwt888u0qfnu3nqkndrqqjuajuj",
            "tb1qcklg00ymx85x7f5vzll3zypd2epywdxmhx05k7395e470pth8g8qvh62kw",
        ]
        expected_receive_addrs = [
            "tb1qlrjv2ek09g9aplga83j9mfvelnt6qymen9gd49kpezdz2g5pgwnsfmrucp",
            "tb1qn2xhgxqxqcs8cl36f7efgg7jvreus4x6959hnc6mfmygnz435dksa39ygr",
            "tb1q2lzh628dmylpf9gr869lgyq9fcc9xqat7unpumnmmn5nph6447cs40k7mw",
        ]

        for cnt, change_addr in enumerate(expected_change_addrs):
            self.assertEqual(
                change_addr,
                p2wsh_sortedmulti_obj.get_address(is_change=True, offset=cnt),
            )

        for cnt, receive_addr in enumerate(expected_receive_addrs):
            self.assertEqual(
                receive_addr,
                p2wsh_sortedmulti_obj.get_address(is_change=False, offset=cnt),
            )

        expected_key_records = [
            {
                "xfp": "c7d0648a",
                "path": "m/48h/1h/0h/2h",
                "xpub_parent": "tpubDEpefcgzY6ZyEV2uF4xcW2z8bZ3DNeWx9h2BcwcX973BHrmkQxJhpAXoSWZeHkmkiTtnUjfERsTDTVCcifW6po3PFR1JRjUUTJHvPpDqJhr",
                "account_index": 0,
            },
            {
                "xfp": "12980eed",
                "path": "m/48h/1h/0h/2h",
                "xpub_parent": "tpubDEkXGoQhYLFnYyzUGadtceUKbzVfXVorJEdo7c6VKJLHrULhpSVLC7fo89DDhjHmPvvNyrun2LTWH6FYmHh5VaQYPLEqLviVQKh45ufz8Ae",
                "account_index": 0,
            },
            {
                "xfp": "3a52b5cd",
                "path": "m/48h/1h/0h/2h",
                "xpub_parent": "tpubDFdbVee2Zna6eL9TkYBZDJVJ3RxGYWgChksXBRgw6y6PU1jWPTXUqag3CBMd6VDwok1hn5HZGvg6ujsTLXykrS3DwbxqCzEvWoT49gRJy7s",
                "account_index": 0,
            },
            {
                "xfp": "f7d04090",
                "path": "m/48h/1h/0h/2h",
                "xpub_parent": "tpubDF7FTuPECTePubPXNK73TYCzV3nRWaJnRwTXD28kh6Fz4LcaRzWwNtX153J7WeJFcQB2T6k9THd424Kmjs8Ps1FC1Xb81TXTxxbGZrLqQNp",
                "account_index": 0,
            },
        ]
        self.assertEqual(p2wsh_sortedmulti_obj.key_records, expected_key_records)

        # Parse again, but without the checksum (should regenerate it)
        valid_output_record_sans_checksum = valid_output_record.split("#")[0]
        p2wsh_sortedmulti_obj_regenerated = P2WSHSortedMulti.parse(
            valid_output_record_sans_checksum
        )
        self.assertEqual(
            p2wsh_sortedmulti_obj_regenerated.checksum, p2wsh_sortedmulti_obj.checksum
        )
        # Redundant
        self.assertEqual(
            str(p2wsh_sortedmulti_obj_regenerated), str(p2wsh_sortedmulti_obj)
        )

        # Parse again, but with an invalid checksum, which should throw an error
        invalid_checksums = ["", "a", "a" * 9, "X"]
        for invalid_checksum in invalid_checksums:
            with self.assertRaises(ValueError):
                P2WSHSortedMulti.parse(
                    valid_output_record_sans_checksum + "#" + invalid_checksum
                )

        # Parse again, but with the wrong (but valid) checksum, which should throw an error
        with self.assertRaises(ValueError):
            P2WSHSortedMulti.parse(valid_output_record_sans_checksum + "#" + "a" * 8)

        # manually checked on 2021-06-08 that when imported to Caravan it generates the same addresses as buidl
        want = """{"name": "p2wsh", "addressType": "P2WSH", "network": "testnet", "client": {"type": "public"}, "quorum": {"requiredSigners": 1, "totalSigners": 4}, "extendedPublicKeys": [{"bip32Path": "m/48'/1'/0'/2'", "xpub": "tpubDEpefcgzY6ZyEV2uF4xcW2z8bZ3DNeWx9h2BcwcX973BHrmkQxJhpAXoSWZeHkmkiTtnUjfERsTDTVCcifW6po3PFR1JRjUUTJHvPpDqJhr", "xfp": "c7d0648a", "name": "Seed A"}, {"bip32Path": "m/48'/1'/0'/2'", "xpub": "tpubDEkXGoQhYLFnYyzUGadtceUKbzVfXVorJEdo7c6VKJLHrULhpSVLC7fo89DDhjHmPvvNyrun2LTWH6FYmHh5VaQYPLEqLviVQKh45ufz8Ae", "xfp": "12980eed", "name": "Seed B"}, {"bip32Path": "m/48'/1'/0'/2'", "xpub": "tpubDFdbVee2Zna6eL9TkYBZDJVJ3RxGYWgChksXBRgw6y6PU1jWPTXUqag3CBMd6VDwok1hn5HZGvg6ujsTLXykrS3DwbxqCzEvWoT49gRJy7s", "xfp": "3a52b5cd", "name": "Seed C"}, {"bip32Path": "m/48'/1'/0'/2'", "xpub": "tpubDF7FTuPECTePubPXNK73TYCzV3nRWaJnRwTXD28kh6Fz4LcaRzWwNtX153J7WeJFcQB2T6k9THd424Kmjs8Ps1FC1Xb81TXTxxbGZrLqQNp", "xfp": "f7d04090", "name": "Seed D"}], "startingAddressIndex": 0}"""
        self.assertEqual(p2wsh_sortedmulti_obj.caravan_export(), want)

    def test_p2wsh_2of3(self):
        valid_output_record = "wsh(sortedmulti(2,[c7d0648a/48h/1h/0h/2h]tpubDEpefcgzY6ZyEV2uF4xcW2z8bZ3DNeWx9h2BcwcX973BHrmkQxJhpAXoSWZeHkmkiTtnUjfERsTDTVCcifW6po3PFR1JRjUUTJHvPpDqJhr/0/*,[12980eed/48h/1h/0h/2h]tpubDEkXGoQhYLFnYyzUGadtceUKbzVfXVorJEdo7c6VKJLHrULhpSVLC7fo89DDhjHmPvvNyrun2LTWH6FYmHh5VaQYPLEqLviVQKh45ufz8Ae/0/*,[f7d04090/48h/1h/0h/2h]tpubDF7FTuPECTePubPXNK73TYCzV3nRWaJnRwTXD28kh6Fz4LcaRzWwNtX153J7WeJFcQB2T6k9THd424Kmjs8Ps1FC1Xb81TXTxxbGZrLqQNp/0/*))#0stzl64e"
        p2wsh_sortedmulti_obj = P2WSHSortedMulti.parse(valid_output_record)
        # Should recreate itself
        self.assertEqual(str(p2wsh_sortedmulti_obj), valid_output_record)

        self.assertEqual(p2wsh_sortedmulti_obj.network, "testnet")
        self.assertEqual(p2wsh_sortedmulti_obj.checksum, "0stzl64e")
        self.assertEqual(
            p2wsh_sortedmulti_obj.get_address(),
            "tb1q0cy5x39ezyvc4pfydrqedng0h9arh2hcw8lpfa6e9ama7ky7cffsmzmgx8",
        )

        expected_key_records = [
            {
                "xfp": "c7d0648a",
                "path": "m/48h/1h/0h/2h",
                "xpub_parent": "tpubDEpefcgzY6ZyEV2uF4xcW2z8bZ3DNeWx9h2BcwcX973BHrmkQxJhpAXoSWZeHkmkiTtnUjfERsTDTVCcifW6po3PFR1JRjUUTJHvPpDqJhr",
                "account_index": 0,
            },
            {
                "xfp": "12980eed",
                "path": "m/48h/1h/0h/2h",
                "xpub_parent": "tpubDEkXGoQhYLFnYyzUGadtceUKbzVfXVorJEdo7c6VKJLHrULhpSVLC7fo89DDhjHmPvvNyrun2LTWH6FYmHh5VaQYPLEqLviVQKh45ufz8Ae",
                "account_index": 0,
            },
            {
                "xfp": "f7d04090",
                "path": "m/48h/1h/0h/2h",
                "xpub_parent": "tpubDF7FTuPECTePubPXNK73TYCzV3nRWaJnRwTXD28kh6Fz4LcaRzWwNtX153J7WeJFcQB2T6k9THd424Kmjs8Ps1FC1Xb81TXTxxbGZrLqQNp",
                "account_index": 0,
            },
        ]
        self.assertEqual(p2wsh_sortedmulti_obj.key_records, expected_key_records)

        # manually checked on 2021-06-08 that when imported to Caravan it generates the same addresses as buidl
        want = """{"name": "p2wsh", "addressType": "P2WSH", "network": "testnet", "client": {"type": "public"}, "quorum": {"requiredSigners": 2, "totalSigners": 3}, "extendedPublicKeys": [{"bip32Path": "m/48'/1'/0'/2'", "xpub": "tpubDEpefcgzY6ZyEV2uF4xcW2z8bZ3DNeWx9h2BcwcX973BHrmkQxJhpAXoSWZeHkmkiTtnUjfERsTDTVCcifW6po3PFR1JRjUUTJHvPpDqJhr", "xfp": "c7d0648a", "name": "Seed A"}, {"bip32Path": "m/48'/1'/0'/2'", "xpub": "tpubDEkXGoQhYLFnYyzUGadtceUKbzVfXVorJEdo7c6VKJLHrULhpSVLC7fo89DDhjHmPvvNyrun2LTWH6FYmHh5VaQYPLEqLviVQKh45ufz8Ae", "xfp": "12980eed", "name": "Seed B"}, {"bip32Path": "m/48'/1'/0'/2'", "xpub": "tpubDF7FTuPECTePubPXNK73TYCzV3nRWaJnRwTXD28kh6Fz4LcaRzWwNtX153J7WeJFcQB2T6k9THd424Kmjs8Ps1FC1Xb81TXTxxbGZrLqQNp", "xfp": "f7d04090", "name": "Seed C"}], "startingAddressIndex": 0}"""
        self.assertEqual(p2wsh_sortedmulti_obj.caravan_export(), want)

    def test_p2wsh_1of2_sorted_and_unsorted(self):
        TESTNET_DEFAULT_PATH = "m/48h/1h/0h/2h"
        # https://github.com/satoshilabs/slips/blob/master/slip-0132.md
        TESTNET_VERSION_BYTE = bytes.fromhex("043587cf")

        key_records = []
        for mnenmonic in ("invest ", "sell "):
            hd_priv_obj = HDPrivateKey.from_mnemonic(mnenmonic * 12)
            xfp_hex = hd_priv_obj.fingerprint().hex()
            xpub = hd_priv_obj.traverse(path=TESTNET_DEFAULT_PATH).xpub(
                TESTNET_VERSION_BYTE
            )
            key_records.append(
                {
                    "xfp": xfp_hex,
                    "path": TESTNET_DEFAULT_PATH,
                    "xpub_parent": xpub,
                    "account_index": 0,
                }
            )

        p2wsh_sorted_obj = P2WSHSortedMulti(quorum_m=1, key_records=key_records)
        expected = "wsh(sortedmulti(1,[aa917e75/48h/1h/0h/2h]tpubDEZRP2dRKoGRJnR9zn6EoLouYKbYyjFsxywgG7wMQwCDVkwNvoLhcX1rTQipYajmTAF82kJoKDiNCgD4wUPahACE7n1trMSm7QS8B3S1fdy/0/*,[2553c4b8/48h/1h/0h/2h]tpubDEiNuxUt4pKjKk7khdv9jfcS92R1WQD6Z3dwjyMFrYj2iMrYbk3xB5kjg6kL4P8SoWsQHpd378RCTrM7fsw4chnJKhE2kfbfc4BCPkVh6g9/0/*))#t0v98kwu"
        self.assertEqual(expected, str(p2wsh_sorted_obj))
        self.assertEqual(
            p2wsh_sorted_obj.get_address(1),
            "tb1q6y5dh62l40q9de8k53sjekqz2zcn9dfs55g5v8pjmd7ehg08gk0sms9q4l",
        )

        # Test unsorted

        # These sometimes produce the same address (should be 50% on average)
        addr_matches = [False, True, True, True, True, False, True, False, True, False]
        for cnt, addr_match in enumerate(addr_matches):
            sorted_addr = p2wsh_sorted_obj.get_address(cnt, sort_keys=True)
            unsorted_addr = p2wsh_sorted_obj.get_address(cnt, sort_keys=False)
            if addr_match:
                self.assertEqual(sorted_addr, unsorted_addr)
            else:
                self.assertNotEqual(sorted_addr, unsorted_addr)

        # manually checked on 2021-06-08 that when imported to Caravan it generates the same addresses as buidl
        want = """{"name": "foo", "addressType": "P2WSH", "network": "testnet", "client": {"type": "public"}, "quorum": {"requiredSigners": 1, "totalSigners": 2}, "extendedPublicKeys": [{"bip32Path": "m/48'/1'/0'/2'", "xpub": "tpubDEZRP2dRKoGRJnR9zn6EoLouYKbYyjFsxywgG7wMQwCDVkwNvoLhcX1rTQipYajmTAF82kJoKDiNCgD4wUPahACE7n1trMSm7QS8B3S1fdy", "xfp": "aa917e75", "name": "alice"}, {"bip32Path": "m/48'/1'/0'/2'", "xpub": "tpubDEiNuxUt4pKjKk7khdv9jfcS92R1WQD6Z3dwjyMFrYj2iMrYbk3xB5kjg6kL4P8SoWsQHpd378RCTrM7fsw4chnJKhE2kfbfc4BCPkVh6g9", "xfp": "2553c4b8", "name": "bob"}], "startingAddressIndex": 0}"""
        self.assertEqual(
            p2wsh_sorted_obj.caravan_export(
                wallet_name="foo", key_record_names=["alice", "bob"]
            ),
            want,
        )

    def test_mixed_slip132_p2wsh_sortedmulti(self):
        # this should coalesce the values into non-slip132 (p2wsh sortedmulti already conveys the script type unambiguously)
        quorum_m = 1
        key_records = [
            {
                # investx12:
                "xfp": "aa917e75",
                "path": "m/48h/1h/0h/2h",
                "xpub_parent": "tpubDEZRP2dRKoGRJnR9zn6EoLouYKbYyjFsxywgG7wMQwCDVkwNvoLhcX1rTQipYajmTAF82kJoKDiNCgD4wUPahACE7n1trMSm7QS8B3S1fdy",
                "account_index": 0,
            },
            {
                # sellx12:
                "xfp": "2553c4b8",
                "path": "m/48h/1h/0h/2h/2046266013/1945465733/1801020214/1402692941",
                "xpub_parent": "Vpub5uMrp2GYpnHN8BkjvXpP71TuZ8BDqu61PPcwEKSzE9Mcuow727mUJNsDsKdzAiupHXea5F7ZxD9SaSQvbr1hvpNjrijJQ2J46VQjc5yEcm8",
                "account_index": 0,
            },
        ]
        p2wsh_sortedmulti_obj = P2WSHSortedMulti(
            quorum_m, key_records, sort_key_records=False
        )
        # notice that both values are tpub, despite ingesting Vpub
        want = "wsh(sortedmulti(1,[aa917e75/48h/1h/0h/2h]tpubDEZRP2dRKoGRJnR9zn6EoLouYKbYyjFsxywgG7wMQwCDVkwNvoLhcX1rTQipYajmTAF82kJoKDiNCgD4wUPahACE7n1trMSm7QS8B3S1fdy/0/*,[2553c4b8/48h/1h/0h/2h/2046266013/1945465733/1801020214/1402692941]tpubDNVvpMhdGTmQg1AT6muju2eUWPXWWAtUSyc1EQ2MxJ2s97fMqFZQbpzQM4gU8bwzfFM7KBpSXRJ5v2Wu8sY2GF5ZpXm3qy8GLArZZNM1Wru/0/*))#0lfdttke"
        self.assertEqual(str(p2wsh_sortedmulti_obj), want)

    def test_invalid_p2wsh_sortedmulti(self):
        # Notice the mix of xpub and tpub
        output_record = """wsh(sortedmulti(1,[c7d0648a/48h/1h/0h/2h]tpubDEpefcgzY6ZyEV2uF4xcW2z8bZ3DNeWx9h2BcwcX973BHrmkQxJhpAXoSWZeHkmkiTtnUjfERsTDTVCcifW6po3PFR1JRjUUTJHvPpDqJhr/0/*,[12980eed/48h/1h/0h/2h]xpub6ENtkZb1q4JLHBocpPeoQj8xGsQ1Y7Jnkc3Vm43LyPaQ7BfzkDeF3fzxt78SBELXc2PUNHPuVEdTaukwNRqqc8xFKjVXfQ4FpN6eKqe6y9E/0/*))#tatkmj5q"""

        with self.assertRaises(ValueError) as fail:
            print("fail")
            P2WSHSortedMulti.parse(output_record)

        self.assertIn(
            "Network mismatch: network is set to testnet but ", str(fail.exception)
        )


class ParseTest(TestCase):
    def test_valid_key_record_regular(self):
        key_record = "[c7d0648a/48h/1h/0h/2h]tpubDEpefcgzY6ZyEV2uF4xcW2z8bZ3DNeWx9h2BcwcX973BHrmkQxJhpAXoSWZeHkmkiTtnUjfERsTDTVCcifW6po3PFR1JRjUUTJHvPpDqJhr/0/*"
        results = parse_full_key_record(key_record)
        want = {
            "xfp": "c7d0648a",
            "path": "m/48h/1h/0h/2h",
            "xpub_parent": "tpubDEpefcgzY6ZyEV2uF4xcW2z8bZ3DNeWx9h2BcwcX973BHrmkQxJhpAXoSWZeHkmkiTtnUjfERsTDTVCcifW6po3PFR1JRjUUTJHvPpDqJhr",
            "xpub_child": "tpubDHXhgZEb9KfoFAuPQ5X6nayFrgifHEb3EUAbbs3EvwboxjttP4ekmPPz4NPRDE7p3q87DQH2TbNyxUmYGf2GNiSTfXj4Q5CfVgrpZuDEsak",
            "account_index": 0,
            "network": "testnet",
        }
        self.assertEqual(results, want)

    def test_valid_key_record_slip132(self):
        # oil * 12
        key_record = "[2a77e0a6/48h/1h/0h/2h]Vpub5mvQbnmqKfpPjWfAZEw5Xjdr6UjnjyZEirzrhNMSuKjL8Qfd3nqLBkrBrVXNeMgKCjPXbyLnSCn6qcD8fHQCkNnNLnkpQtY3sh4MHmywvbe"
        results = parse_partial_key_record(key_record)
        want = {
            "xfp": "2a77e0a6",
            "path": "m/48h/1h/0h/2h",
            "xpub": "Vpub5mvQbnmqKfpPjWfAZEw5Xjdr6UjnjyZEirzrhNMSuKjL8Qfd3nqLBkrBrVXNeMgKCjPXbyLnSCn6qcD8fHQCkNnNLnkpQtY3sh4MHmywvbe",
            "network": "testnet",
        }
        self.assertEqual(results, want)


class CoreChecksumTest(TestCase):
    def test_sd_descriptor_checksum_a(self):
        # https://github.com/cryptoadvance/specter-desktop/blob/c1ce0e982a0552883cc339ecf5ee6860574e79b7/tests/test_util_descriptor.py
        descriptor_ex_checksum = "sh(multi(2,[00000000/111'/222]xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL,xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y/0))"
        self.assertEqual(calc_core_checksum(descriptor_ex_checksum), "tjg09x5t")

    def test_sd_descriptor_checksum_b(self):
        # https://github.com/cryptoadvance/specter-desktop/blob/c1ce0e982a0552883cc339ecf5ee6860574e79b7/tests/test_util_descriptor.py
        descriptor_ex_checksum = "sh(wsh(sortedmulti(2,xpub6DkFAXWQ2dHxnMKoSBogHrw1rgNJKR4umdbnNVNTYeCGcduxWnNUHgGptqEQWPKRmeW4Zn4FHSbLMBKEWYaMDYu47Ytg6DdFnPNt8hwn5mE/1,xpub6DiXipxEgSYqTw3xX2apub7vzsC5gBzmikxriTRnfKRKQjUSpiGQ9XzyFktkVLTGVGF5emH8up1qtsyw726rvnmzHRU8cHH8gDxeLMXSkYE/1,xpub6FHZCoNb3tg3mxjcXsQx1xLpNmod6woECf2fB4nQbe9NXbvha2ucpDpnGbTFF68KUMUr1hNQ9E5jVEvpT2kUkVmFVDrJawcbgXzDpJc2hkF/2)))"
        self.assertEqual(calc_core_checksum(descriptor_ex_checksum), "mgjhd0rk")

    def test_sd_descriptor_checksum_c(self):
        # https://github.com/cryptoadvance/specter-desktop/blob/c1ce0e982a0552883cc339ecf5ee6860574e79b7/tests/test_util_descriptor.py
        descriptor_ex_checksum = "sh(wsh(sortedmulti(2,029dfee2aaa23e2220476c34eda9a76591c1257f8dfce54e42ff014f922ede0838,03151d5b21c6491915e7a103bff913b4d85246c8209a342bb7104850e4cb394686,03646d8e624fedb63739e7963d0c7ad368a7f7935557b2b28c4c954882b19fe6e1)))"
        self.assertEqual(calc_core_checksum(descriptor_ex_checksum), "rzmdthwy")


class SeedFingerprintTest(TestCase):
    def test_valid_xfps(self):
        self.assertTrue(is_valid_xfp_hex("a" * 8))
        self.assertTrue(is_valid_xfp_hex("abcdef01"))
        self.assertTrue(is_valid_xfp_hex("01234567"))
        self.assertTrue(is_valid_xfp_hex("deadbeef"))

    def test_invalid_xfps(self):
        invalid_xfps = [
            "a" * 7,
            "a" * 9,
            "hello123",
        ]
        for invalid in invalid_xfps:
            self.assertFalse(is_valid_xfp_hex(invalid))
