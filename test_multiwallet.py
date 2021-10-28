import unittest
import pexpect

from os import getenv


@unittest.skipIf(
    getenv("SKIP_SLOW_TESTS"),
    reason="This test takes a while",
)
class MultiwalletTest(unittest.TestCase):
    def expect(self, text):
        """
        Expect a string of bytes one at a time (not waiting on a newline)
        """
        buffer = ""
        while True:

            try:
                # This will error out at the end of the buffer
                latest_char = self.child.read(1)
            except Exception as e:
                raise Exception(
                    f"Failed to find text `{text}` in buffer `{buffer}`.\nError: `{e}`"
                )

            try:
                latest_char = latest_char.decode()
                if latest_char not in ("\n", "\r"):
                    buffer += latest_char
            except UnicodeDecodeError:
                # Handle non-unicode char edge-case (bitcoin symbol)
                buffer += str(latest_char)

            if text in buffer:
                return True

        # this line should never be reached, the script would timeout first
        assert f"`{text}` not in buffer: {buffer}"

    def setUp(self):
        self.child = pexpect.spawn("python3 multiwallet.py", timeout=2)
        self.expect("Welcome to multiwallet, the stateless multisig bitcoin wallet")

    def test_version_info(self):
        self.child.sendline("version_info")
        self.expect("buidl Version: ")
        self.expect("Multiwallet Mode: ")
        self.expect("Python Version: ")
        self.expect("Platform: ")
        self.expect("libsecp256k1 Configured: ")

    def test_seedpicker_basic(self):
        seedpicker_tests = [
            # is_mainnet, expected_key_record
            [
                "Y",
                "[9a6a2580/48h/0h/0h/2h]Zpub75DT3bNcp7LBQTn1fu6x67WFdDUzZe8H5rNmaRWCUMACqYrjz1BHnUKwZ87o6ek5DbbwiWL7jaVdmKcPThUP9h4T3SMLZFPxWHmfeGprSBc",
            ],
            [
                "N",
                "[9a6a2580/48h/1h/0h/2h]Vpub5nRfzmugs9H6jk6xnZbL76nd44JC6kHq6Sh8Hhd9ueUZG64ZTRoCwQNMHyPEFU9W5zhcZRvKUF4aiopXS683bUtsc2isQT8zX3873ExgPci",
            ],
        ]
        for is_mainnet, expected_key_record in seedpicker_tests:
            self.child.sendline("generate_seed")
            self.expect("Enter the first 23 words of your BIP39 seed phrase")

            self.child.sendline("bacon " * 23)
            self.expect("Use Mainnet?")

            self.child.sendline(is_mainnet)
            self.expect("Last word: bacon")
            self.expect(expected_key_record)

    def test_create_output_descriptors_blinded(self):
        # Blinded example from https://github.com/mflaxman/blind-xpub/blob/90af581695ef4ab1b7c40324c4cd7f2ce70e3403/README.md#create-output-descriptors

        self.child.sendline("create_output_descriptors")

        # UGLY HACK - Github CI uses a  narrow terminal and only displays part of this line:
        full_text = "How many signatures will be required to spend from this wallet?"
        self.expect(full_text[25:])

        self.child.sendline("1")

        # UGLY HACK - Github CI uses a  narrow terminal and only displays part of this line:
        self.expect(
            "How many total keys will be able to sign transaction from this wallet?"[
                33:
            ]
        )
        self.child.sendline("2")

        self.expect("Enter xpub key record ")
        self.child.sendline(
            "[aa917e75/48h/1h/0h/2h]tpubDEZRP2dRKoGRJnR9zn6EoLouYKbYyjFsxywgG7wMQwCDVkwNvoLhcX1rTQipYajmTAF82kJoKDiNCgD4wUPahACE7n1trMSm7QS8B3S1fdy"
        )

        self.expect("Enter xpub key record ")
        self.child.sendline(
            "[2553c4b8/48h/1h/0h/2h/2046266013/1945465733/1801020214/1402692941]tpubDNVvpMhdGTmQg1AT6muju2eUWPXWWAtUSyc1EQ2MxJ2s97fMqFZQbpzQM4gU8bwzfFM7KBpSXRJ5v2Wu8sY2GF5ZpXm3qy8GLArZZNM1Wru"
        )

        want = "wsh(sortedmulti(1,[aa917e75/48h/1h/0h/2h]tpubDEZRP2dRKoGRJnR9zn6EoLouYKbYyjFsxywgG7wMQwCDVkwNvoLhcX1rTQipYajmTAF82kJoKDiNCgD4wUPahACE7n1trMSm7QS8B3S1fdy/0/*,[2553c4b8/48h/1h/0h/2h/2046266013/1945465733/1801020214/1402692941]tpubDNVvpMhdGTmQg1AT6muju2eUWPXWWAtUSyc1EQ2MxJ2s97fMqFZQbpzQM4gU8bwzfFM7KBpSXRJ5v2Wu8sY2GF5ZpXm3qy8GLArZZNM1Wru/0/*))#0lfdttke"
        self.expect(want)

    def test_create_output_descriptors(self):
        # Validated 2021-06 against bitcoin core

        self.child.sendline("create_output_descriptors")

        # UGLY HACK - Github CI uses a  narrow terminal and only displays part of this line:
        full_text = "How many signatures will be required to spend from this wallet?"
        self.expect(full_text[25:])
        self.child.sendline("1")

        # UGLY HACK - Github CI uses a  narrow terminal and only displays part of this line:
        self.expect(
            "How many total keys will be able to sign transaction from this wallet?"[
                33:
            ]
        )
        self.child.sendline("2")

        self.expect("Enter xpub key record ")
        self.child.sendline(
            "[aa917e75/48h/1h/0h/2h]tpubDEZRP2dRKoGRJnR9zn6EoLouYKbYyjFsxywgG7wMQwCDVkwNvoLhcX1rTQipYajmTAF82kJoKDiNCgD4wUPahACE7n1trMSm7QS8B3S1fdy"
        )

        self.expect("Enter xpub key record ")
        self.child.sendline(
            "[2553c4b8/48h/1h/0h/2h]tpubDEiNuxUt4pKjKk7khdv9jfcS92R1WQD6Z3dwjyMFrYj2iMrYbk3xB5kjg6kL4P8SoWsQHpd378RCTrM7fsw4chnJKhE2kfbfc4BCPkVh6g9"
        )
        want = "wsh(sortedmulti(1,[aa917e75/48h/1h/0h/2h]tpubDEZRP2dRKoGRJnR9zn6EoLouYKbYyjFsxywgG7wMQwCDVkwNvoLhcX1rTQipYajmTAF82kJoKDiNCgD4wUPahACE7n1trMSm7QS8B3S1fdy/0/*,[2553c4b8/48h/1h/0h/2h]tpubDEiNuxUt4pKjKk7khdv9jfcS92R1WQD6Z3dwjyMFrYj2iMrYbk3xB5kjg6kL4P8SoWsQHpd378RCTrM7fsw4chnJKhE2kfbfc4BCPkVh6g9/0/*))#t0v98kwu"
        self.expect(want)

    def test_receive_addr(self):
        account_map = "wsh(sortedmulti(1,[aa917e75/48h/1h/0h/2h]tpubDEZRP2dRKoGRJnR9zn6EoLouYKbYyjFsxywgG7wMQwCDVkwNvoLhcX1rTQipYajmTAF82kJoKDiNCgD4wUPahACE7n1trMSm7QS8B3S1fdy/0/*,[2553c4b8/48h/1h/0h/2h]tpubDEiNuxUt4pKjKk7khdv9jfcS92R1WQD6Z3dwjyMFrYj2iMrYbk3xB5kjg6kL4P8SoWsQHpd378RCTrM7fsw4chnJKhE2kfbfc4BCPkVh6g9/0/*))#t0v98kwu"
        receive_addr = "tb1qtsvps7q8j5mn2qqfrujlrnwraelkptps5k595hn5d4tfq7mv644sfkkxps"

        self.child.sendline("validate_address")
        self.expect("Paste in your p2wsh output descriptors (account map)")

        self.child.sendline(account_map)
        self.expect("Limit of addresses to display")

        self.child.sendline("1")
        self.expect("Offset of addresses to display")

        self.child.sendline("0")
        self.expect("1-of-2 Multisig Receive Addresses")
        self.expect(receive_addr)

    def test_change_addr(self):
        account_map = "wsh(sortedmulti(1,[aa917e75/48h/1h/0h/2h]tpubDEZRP2dRKoGRJnR9zn6EoLouYKbYyjFsxywgG7wMQwCDVkwNvoLhcX1rTQipYajmTAF82kJoKDiNCgD4wUPahACE7n1trMSm7QS8B3S1fdy/0/*,[2553c4b8/48h/1h/0h/2h]tpubDEiNuxUt4pKjKk7khdv9jfcS92R1WQD6Z3dwjyMFrYj2iMrYbk3xB5kjg6kL4P8SoWsQHpd378RCTrM7fsw4chnJKhE2kfbfc4BCPkVh6g9/0/*))#t0v98kwu"
        change_addr = "tb1qjcsz3nmscxdecksnrn5k9dxrj0g3f7xkuclk53aqu33lg06r0cks5l8ew8"

        self.child.sendline("toggle_advanced_mode")
        self.expect("ADVANCED mode set")

        self.child.sendline("validate_address")
        self.expect("Paste in your p2wsh output descriptors (account map)")

        self.child.sendline(account_map)
        self.expect("Limit of addresses to display")

        self.child.sendline("1")
        self.expect("Offset of addresses to display")

        self.child.sendline("0")
        # UGLY HACK - Github CI uses a  narrow terminal and only displays part of this line:
        self.expect(
            "Display receive addresses? `N` to display change addresses instead. [Y/n]:"[
                31:
            ]
        )

        self.child.sendline("N")
        self.expect("1-of-2 Multisig Change Addresses")
        self.expect(change_addr)

    def test_sign_tx_from_psbt_without_xpubs(self):
        """many coordinators strip out xpubs to save space, as stateful Signers already have output descriptors to record state"""

        unsigned_psbt_b64 = "cHNidP8BAFICAAAAASqJ31Trzpdt/MCBc1rpqmJyTcrhHNgqYqmsoDzHoklrAQAAAAD+////AYcmAAAAAAAAFgAUVH5mMP/WhqzXEzUORHbh1WJ7TS4AAAAAAAEBKxAnAAAAAAAAIgAgW8ODIeZA3ep/uESxtEZmQlxl4Q0QWWbe4I7x3aHuEvABBYtRIQI0eOoa6SLJeaxzFWRXvzgWElJmJgyZMSfbSZ7plUxF9iECYYmlbj1NXorYlB1Ed7jOwa4nt+xwhePNaxnQW53o6lQhApaCK4Vcv04C6td57v3zGuHGrrVjXQEMKwKbbS8GHrkKIQLEV1INwWxsAYHEj/ElyUDHWQOxdbsfQzP2LT4IRZmWY1SuIgYCNHjqGukiyXmscxVkV784FhJSZiYMmTEn20me6ZVMRfYc99BAkDAAAIABAACAAAAAgAIAAIAAAAAABgAAACIGAmGJpW49TV6K2JQdRHe4zsGuJ7fscIXjzWsZ0Fud6OpUHDpStc0wAACAAQAAgAAAAIACAACAAAAAAAYAAAAiBgKWgiuFXL9OAurXee798xrhxq61Y10BDCsCm20vBh65ChwSmA7tMAAAgAEAAIAAAACAAgAAgAAAAAAGAAAAIgYCxFdSDcFsbAGBxI/xJclAx1kDsXW7H0Mz9i0+CEWZlmMcx9BkijAAAIABAACAAAAAgAIAAIAAAAAABgAAAAAA"

        self.child.sendline("sign_transaction")
        self.expect("Paste partially signed bitcoin transaction (PSBT) in base64 form")

        self.child.sendline(unsigned_psbt_b64)
        self.expect(
            "Transaction appears to be a testnet transaction. Display as testnet?"[-19:]
        )

        self.child.sendline("Y")
        self.expect("Paste in your p2wsh output descriptors (account map)")

        account_map = "wsh(sortedmulti(1,[c7d0648a/48h/1h/0h/2h]tpubDEpefcgzY6ZyEV2uF4xcW2z8bZ3DNeWx9h2BcwcX973BHrmkQxJhpAXoSWZeHkmkiTtnUjfERsTDTVCcifW6po3PFR1JRjUUTJHvPpDqJhr/0/*,[12980eed/48h/1h/0h/2h]tpubDEkXGoQhYLFnYyzUGadtceUKbzVfXVorJEdo7c6VKJLHrULhpSVLC7fo89DDhjHmPvvNyrun2LTWH6FYmHh5VaQYPLEqLviVQKh45ufz8Ae/0/*,[3a52b5cd/48h/1h/0h/2h]tpubDFdbVee2Zna6eL9TkYBZDJVJ3RxGYWgChksXBRgw6y6PU1jWPTXUqag3CBMd6VDwok1hn5HZGvg6ujsTLXykrS3DwbxqCzEvWoT49gRJy7s/0/*,[f7d04090/48h/1h/0h/2h]tpubDF7FTuPECTePubPXNK73TYCzV3nRWaJnRwTXD28kh6Fz4LcaRzWwNtX153J7WeJFcQB2T6k9THd424Kmjs8Ps1FC1Xb81TXTxxbGZrLqQNp/0/*))#tatkmj5q"
        self.child.sendline(account_map)
        self.expect(
            "PSBT sends 9,863 sats to tb1q23lxvv8l66r2e4cnx58ygahp6438knfwp8lapc with a fee of 137 sats (1.37% of spend)"
        )
        self.expect("In Depth Transaction View?")

        self.child.sendline("Y")
        self.expect("DETAILED VIEW")
        self.expect(
            "TXID: edbebb3fed50abcaecfffb993427becde623beac070fbcd822c36e2751cf0106"
        )
        self.expect("Sign this transaction?")

        self.child.sendline("Y")
        self.expect("Enter your full BIP39 seed phrase")

        self.child.sendline("zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo abstract")
        self.expect("Use a passphrase (advanced users only)?")

        self.child.sendline("N")
        self.expect("Signed PSBT to broadcast")

        signed_psbt_b64 = "cHNidP8BAFICAAAAASqJ31Trzpdt/MCBc1rpqmJyTcrhHNgqYqmsoDzHoklrAQAAAAD+////AYcmAAAAAAAAFgAUVH5mMP/WhqzXEzUORHbh1WJ7TS4AAAAAAAEBKxAnAAAAAAAAIgAgW8ODIeZA3ep/uESxtEZmQlxl4Q0QWWbe4I7x3aHuEvAiAgI0eOoa6SLJeaxzFWRXvzgWElJmJgyZMSfbSZ7plUxF9kgwRQIhAKTtWurRx19SWBS0G50IkvEDqbdZG2Q0KuTPB3BRWUCoAiBBWAtAQdmL+uV7aMwcJIacsFtYzrGagkhf6ZfEySXPXgEBBYtRIQI0eOoa6SLJeaxzFWRXvzgWElJmJgyZMSfbSZ7plUxF9iECYYmlbj1NXorYlB1Ed7jOwa4nt+xwhePNaxnQW53o6lQhApaCK4Vcv04C6td57v3zGuHGrrVjXQEMKwKbbS8GHrkKIQLEV1INwWxsAYHEj/ElyUDHWQOxdbsfQzP2LT4IRZmWY1SuIgYCNHjqGukiyXmscxVkV784FhJSZiYMmTEn20me6ZVMRfYc99BAkDAAAIABAACAAAAAgAIAAIAAAAAABgAAACIGAmGJpW49TV6K2JQdRHe4zsGuJ7fscIXjzWsZ0Fud6OpUHDpStc0wAACAAQAAgAAAAIACAACAAAAAAAYAAAAiBgKWgiuFXL9OAurXee798xrhxq61Y10BDCsCm20vBh65ChwSmA7tMAAAgAEAAIAAAACAAgAAgAAAAAAGAAAAIgYCxFdSDcFsbAGBxI/xJclAx1kDsXW7H0Mz9i0+CEWZlmMcx9BkijAAAIABAACAAAAAgAIAAIAAAAAABgAAAAAA"
        self.expect(signed_psbt_b64)

    def test_sign_tx_from_psbt_with_xpubs(self):
        unsigned_psbt_with_xpubs_b64 = "cHNidP8BAF4CAAAAAVnAAJBVdhn3JXR/+xnIV3909mMlK54ux56qruCYyDMxAAAAAAD9////AZ+EAQAAAAAAIgAghWi2ObHovaOzrJHz7w8+smg2+1eAamJxXoWGMhzN27FSfh8ATwEENYfPBIH57suAAAACWsKNF5QmpSZFlYXQ5PRaHaP9uAZOqPmLkbP9AiymDtwCd5mfakF7WtxnH7YzkJdpAnPKZ+WR+xHmGe5YW8C6z1EU4MWVxTAAAIABAACAAAAAgAIAAIBPAQQ1h88EkYCp9oAAAAIGrAFY5Fzsoqb8E8E/f9Lk6rTVkGn6Pkg6D9I4TN958gIhFhsdVpYmJBmJ+mkCBjuw/7eYCaArAD+9TT0JUQtzihSDjz/5MAAAgAEAAIAAAACAAgAAgAABAH0CAAAAAZt5QczPUEc5WphZD5A3659qq7bSTYLpCSu4cRZlWJezAAAAAAD+////AqCGAQAAAAAAIgAgiPOsvg8crqxeGccQKjuw5+A19GFMOaj83WdxsnakR8AKZ+QAAAAAABYAFA+VUziCYIHZLvUbTbABHskgY2f9wHofAAEBK6CGAQAAAAAAIgAgiPOsvg8crqxeGccQKjuw5+A19GFMOaj83WdxsnakR8ABAwQBAAAAAQVHUSEDOCPR/ei1x+po6gsWOhb7u/HPplV598QZG2DlCOVatoUhA7jNisc8iZsolWXC08/epb5ZM24r2zCPIqBt7KT1BYDSUq4iBgM4I9H96LXH6mjqCxY6Fvu78c+mVXn3xBkbYOUI5Vq2hRzgxZXFMAAAgAEAAIAAAACAAgAAgAAAAAAAAAAAIgYDuM2KxzyJmyiVZcLTz96lvlkzbivbMI8ioG3spPUFgNIcg48/+TAAAIABAACAAAAAgAIAAIAAAAAAAAAAAAAA"
        seed_phrase = "action " * 12

        self.child.sendline("sign_transaction")
        self.expect("Paste partially signed bitcoin transaction (PSBT) in base64 form")

        self.child.sendline(unsigned_psbt_with_xpubs_b64)
        self.expect(
            "Transaction appears to be a testnet transaction. Display as testnet?"[-19:]
        )

        self.child.sendline("Y")

        if not getenv("SKIP_UNRELIABLE_TESTS"):
            # HACK!
            # This test should always work locally, but something about how github does CLI app buffering prevents the text from rendering sometimes
            # It is safe enough to skip this test as the detailed view below contains sufficient info for a smoke test
            self.expect(
                "PSBT sends 99,487 sats to tb1qs45tvwd3az768vavj8e77re7kf5rd76hsp4xyu27skrry8xdmwcslqn7ar with a fee of 513 sats (0.51% of spend)"
            )
        self.expect("In Depth Transaction View?")

        self.child.sendline("Y")
        self.expect("DETAILED VIEW")
        self.expect(
            "TXID: 8b8f537cff81ca69fbccb08f0f5e1f4190f417a06c8242ccfb2880fac45f9f39"
        )
        self.expect("1 Input")
        self.expect(
            "addr: tb1q3re6e0s0rjh2chsecugz5wasulsrtarpfsu63lxavacmya4yglqq0gwqnl"
        )
        self.expect("1 Output")
        self.expect(
            "addr: tb1qs45tvwd3az768vavj8e77re7kf5rd76hsp4xyu27skrry8xdmwcslqn7ar"
        )
        self.expect("Sign this transaction?")

        self.child.sendline("Y")
        self.expect("Enter your full BIP39 seed phrase")

        self.child.sendline(seed_phrase)
        self.expect("Use a passphrase (advanced users only)?")

        self.child.sendline("N")
        self.expect("Signed PSBT to broadcast")

        signed_psbt_b64 = "cHNidP8BAF4CAAAAAVnAAJBVdhn3JXR/+xnIV3909mMlK54ux56qruCYyDMxAAAAAAD9////AZ+EAQAAAAAAIgAghWi2ObHovaOzrJHz7w8+smg2+1eAamJxXoWGMhzN27FSfh8ATwEENYfPBIH57suAAAACWsKNF5QmpSZFlYXQ5PRaHaP9uAZOqPmLkbP9AiymDtwCd5mfakF7WtxnH7YzkJdpAnPKZ+WR+xHmGe5YW8C6z1EU4MWVxTAAAIABAACAAAAAgAIAAIBPAQQ1h88EkYCp9oAAAAIGrAFY5Fzsoqb8E8E/f9Lk6rTVkGn6Pkg6D9I4TN958gIhFhsdVpYmJBmJ+mkCBjuw/7eYCaArAD+9TT0JUQtzihSDjz/5MAAAgAEAAIAAAACAAgAAgAABAH0CAAAAAZt5QczPUEc5WphZD5A3659qq7bSTYLpCSu4cRZlWJezAAAAAAD+////AqCGAQAAAAAAIgAgiPOsvg8crqxeGccQKjuw5+A19GFMOaj83WdxsnakR8AKZ+QAAAAAABYAFA+VUziCYIHZLvUbTbABHskgY2f9wHofACICAzgj0f3otcfqaOoLFjoW+7vxz6ZVeffEGRtg5QjlWraFRjBDAiBYKJHJz/ohPKrqPpcgret62o1sTX53zReWz89D+2qD1gIfAbESsACm2Y9Z1VfwnEu/2cwIfphH3nDuIF1AlF8hHgEBAwQBAAAAAQVHUSEDOCPR/ei1x+po6gsWOhb7u/HPplV598QZG2DlCOVatoUhA7jNisc8iZsolWXC08/epb5ZM24r2zCPIqBt7KT1BYDSUq4iBgM4I9H96LXH6mjqCxY6Fvu78c+mVXn3xBkbYOUI5Vq2hRzgxZXFMAAAgAEAAIAAAACAAgAAgAAAAAAAAAAAIgYDuM2KxzyJmyiVZcLTz96lvlkzbivbMI8ioG3spPUFgNIcg48/+TAAAIABAACAAAAAgAIAAIAAAAAAAAAAAAAA"
        self.expect(signed_psbt_b64)

    def test_caravan_output_descriptors(self):
        descriptors = "wsh(sortedmulti(1,[aa917e75/48h/1h/0h/2h]tpubDEZRP2dRKoGRJnR9zn6EoLouYKbYyjFsxywgG7wMQwCDVkwNvoLhcX1rTQipYajmTAF82kJoKDiNCgD4wUPahACE7n1trMSm7QS8B3S1fdy/0/*,[2553c4b8/48h/1h/0h/2h]tpubDEiNuxUt4pKjKk7khdv9jfcS92R1WQD6Z3dwjyMFrYj2iMrYbk3xB5kjg6kL4P8SoWsQHpd378RCTrM7fsw4chnJKhE2kfbfc4BCPkVh6g9/0/*))#t0v98kwu"
        self.child.sendline("convert_descriptors_to_caravan")
        self.expect("Paste in your p2wsh output descriptors (account map)")

        self.child.sendline(descriptors)
        self.expect("Enter wallet name [p2wsh wallet]: ")

        self.child.sendline("")
        self.expect("Give human name to each key record? [y/N]:")

        self.child.sendline("N")
        # This is a weak check that we didn't crash, we're not validating the response as it's too wide for GitHub CI terminal to be meaningful
        self.expect("Output descriptor as Caravan import (save this to a file):")

    def test_fail(self):
        # This has to take some seconds to fail
        mw = pexpect.spawn("python3 multiwallet.py", timeout=1)
        with self.assertRaises(pexpect.exceptions.TIMEOUT):
            mw.expect("this text should not match")
