import unittest

import pexpect


class MultiwalletTest(unittest.TestCase):
    def setUp(self):
        self.child = pexpect.spawn(
            "python3 multiwallet.py", timeout=10, encoding="utf-8"
        )
        self.child.expect(
            "Welcome to multiwallet, the stateless multisig bitcoin wallet"
        )

    def test_debug(self):
        self.child.sendline("debug")
        self.child.expect("buidl Version: ")
        self.child.expect("Multiwallet Mode: ")
        self.child.expect("Python Version: ")
        self.child.expect("Platform: ")
        self.child.expect("libsecp256k1 Configured: ")

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
            self.child.expect("Enter the first 23 words of your BIP39 seed phrase")
            self.child.sendline("bacon " * 23)
            # HACK
            # self.child.expect() doesn't work as expected because the prompts take place in the middle of a line
            self.child.readline()
            res = str(self.child.read(35))
            self.assertIn("Use Mainnet?", res)
            self.child.sendline(is_mainnet)
            self.child.expect("Last word: bacon")
            for _ in range(5):
                self.child.readline()
            res = str(self.child.readline())
            self.assertIn(expected_key_record, res)

    def test_receive_addr(self):
        account_map = "wsh(sortedmulti(1,[aa917e75/48h/1h/0h/2h]tpubDEZRP2dRKoGRJnR9zn6EoLouYKbYyjFsxywgG7wMQwCDVkwNvoLhcX1rTQipYajmTAF82kJoKDiNCgD4wUPahACE7n1trMSm7QS8B3S1fdy/0/*,[2553c4b8/48h/1h/0h/2h]tpubDEiNuxUt4pKjKk7khdv9jfcS92R1WQD6Z3dwjyMFrYj2iMrYbk3xB5kjg6kL4P8SoWsQHpd378RCTrM7fsw4chnJKhE2kfbfc4BCPkVh6g9/0/*))#t0v98kwu"
        receive_addr = "tb1qtsvps7q8j5mn2qqfrujlrnwraelkptps5k595hn5d4tfq7mv644sfkkxps"

        self.child.sendline("receive")
        for _ in range(6):
            self.child.readline()
        res = str(self.child.read(70))
        self.assertIn("Paste in your account map (AKA output record)", res)
        self.child.sendline(account_map)
        self.child.readline()
        res = str(self.child.read(60))
        self.assertIn("Limit of addresses to display", res)
        self.child.sendline("1")
        res = str(self.child.read(60))
        self.assertIn("Offset of addresses to display", res)
        if False:
            # FIXME: verify this
            self.child.sendline("N")
        self.child.sendline("0")
        self.child.expect("1-of-2 Multisig Receive Addresses")
        self.child.expect(receive_addr)

    def test_change_addr(self):
        account_map = "wsh(sortedmulti(1,[aa917e75/48h/1h/0h/2h]tpubDEZRP2dRKoGRJnR9zn6EoLouYKbYyjFsxywgG7wMQwCDVkwNvoLhcX1rTQipYajmTAF82kJoKDiNCgD4wUPahACE7n1trMSm7QS8B3S1fdy/0/*,[2553c4b8/48h/1h/0h/2h]tpubDEiNuxUt4pKjKk7khdv9jfcS92R1WQD6Z3dwjyMFrYj2iMrYbk3xB5kjg6kL4P8SoWsQHpd378RCTrM7fsw4chnJKhE2kfbfc4BCPkVh6g9/0/*))#t0v98kwu"
        change_addr = "tb1qjcsz3nmscxdecksnrn5k9dxrj0g3f7xkuclk53aqu33lg06r0cks5l8ew8"

        self.child.sendline("advanced_mode")
        self.child.expect("ADVANCED mode set")
        self.child.sendline("receive")
        res = str(self.child.read(115))
        self.assertIn("Paste in your account map (AKA output record)", res)
        self.child.sendline(account_map)
        self.child.readline()
        res = str(self.child.read(60))
        self.assertIn("Limit of addresses to display", res)
        self.child.sendline("1")
        res = str(self.child.read(60))
        self.assertIn("Offset of addresses to display", res)
        self.child.sendline("0")
        # FIXME: verify this
        self.child.sendline("N")
        self.child.expect("1-of-2 Multisig Change Addresses")
        self.child.expect(change_addr)

    def test_sign_tx(self):
        account_map = "wsh(sortedmulti(1,[c7d0648a/48h/1h/0h/2h]tpubDEpefcgzY6ZyEV2uF4xcW2z8bZ3DNeWx9h2BcwcX973BHrmkQxJhpAXoSWZeHkmkiTtnUjfERsTDTVCcifW6po3PFR1JRjUUTJHvPpDqJhr/0/*,[12980eed/48h/1h/0h/2h]tpubDEkXGoQhYLFnYyzUGadtceUKbzVfXVorJEdo7c6VKJLHrULhpSVLC7fo89DDhjHmPvvNyrun2LTWH6FYmHh5VaQYPLEqLviVQKh45ufz8Ae/0/*,[3a52b5cd/48h/1h/0h/2h]tpubDFdbVee2Zna6eL9TkYBZDJVJ3RxGYWgChksXBRgw6y6PU1jWPTXUqag3CBMd6VDwok1hn5HZGvg6ujsTLXykrS3DwbxqCzEvWoT49gRJy7s/0/*,[f7d04090/48h/1h/0h/2h]tpubDF7FTuPECTePubPXNK73TYCzV3nRWaJnRwTXD28kh6Fz4LcaRzWwNtX153J7WeJFcQB2T6k9THd424Kmjs8Ps1FC1Xb81TXTxxbGZrLqQNp/0/*))#tatkmj5q"
        unsigned_psbt_b64 = "cHNidP8BAFICAAAAASqJ31Trzpdt/MCBc1rpqmJyTcrhHNgqYqmsoDzHoklrAQAAAAD+////AYcmAAAAAAAAFgAUVH5mMP/WhqzXEzUORHbh1WJ7TS4AAAAAAAEBKxAnAAAAAAAAIgAgW8ODIeZA3ep/uESxtEZmQlxl4Q0QWWbe4I7x3aHuEvABBYtRIQI0eOoa6SLJeaxzFWRXvzgWElJmJgyZMSfbSZ7plUxF9iECYYmlbj1NXorYlB1Ed7jOwa4nt+xwhePNaxnQW53o6lQhApaCK4Vcv04C6td57v3zGuHGrrVjXQEMKwKbbS8GHrkKIQLEV1INwWxsAYHEj/ElyUDHWQOxdbsfQzP2LT4IRZmWY1SuIgYCNHjqGukiyXmscxVkV784FhJSZiYMmTEn20me6ZVMRfYc99BAkDAAAIABAACAAAAAgAIAAIAAAAAABgAAACIGAmGJpW49TV6K2JQdRHe4zsGuJ7fscIXjzWsZ0Fud6OpUHDpStc0wAACAAQAAgAAAAIACAACAAAAAAAYAAAAiBgKWgiuFXL9OAurXee798xrhxq61Y10BDCsCm20vBh65ChwSmA7tMAAAgAEAAIAAAACAAgAAgAAAAAAGAAAAIgYCxFdSDcFsbAGBxI/xJclAx1kDsXW7H0Mz9i0+CEWZlmMcx9BkijAAAIABAACAAAAAgAIAAIAAAAAABgAAAAAA"
        seed_phrase = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo abstract"
        signed_psbt_b64 = "cHNidP8BAFICAAAAASqJ31Trzpdt/MCBc1rpqmJyTcrhHNgqYqmsoDzHoklrAQAAAAD+////AYcmAAAAAAAAFgAUVH5mMP/WhqzXEzUORHbh1WJ7TS4AAAAAAAEBKxAnAAAAAAAAIgAgW8ODIeZA3ep/uESxtEZmQlxl4Q0QWWbe4I7x3aHuEvAiAgI0eOoa6SLJeaxzFWRXvzgWElJmJgyZMSfbSZ7plUxF9kgwRQIhAKTtWurRx19SWBS0G50IkvEDqbdZG2Q0KuTPB3BRWUCoAiBBWAtAQdmL+uV7aMwcJIacsFtYzrGagkhf6ZfEySXPXgEBBYtRIQI0eOoa6SLJeaxzFWRXvzgWElJmJgyZMSfbSZ7plUxF9iECYYmlbj1NXorYlB1Ed7jOwa4nt+xwhePNaxnQW53o6lQhApaCK4Vcv04C6td57v3zGuHGrrVjXQEMKwKbbS8GHrkKIQLEV1INwWxsAYHEj/ElyUDHWQOxdbsfQzP2LT4IRZmWY1SuIgYCNHjqGukiyXmscxVkV784FhJSZiYMmTEn20me6ZVMRfYc99BAkDAAAIABAACAAAAAgAIAAIAAAAAABgAAACIGAmGJpW49TV6K2JQdRHe4zsGuJ7fscIXjzWsZ0Fud6OpUHDpStc0wAACAAQAAgAAAAIACAACAAAAAAAYAAAAiBgKWgiuFXL9OAurXee798xrhxq61Y10BDCsCm20vBh65ChwSmA7tMAAAgAEAAIAAAACAAgAAgAAAAAAGAAAAIgYCxFdSDcFsbAGBxI/xJclAx1kDsXW7H0Mz9i0+CEWZlmMcx9BkijAAAIABAACAAAAAgAIAAIAAAAAABgAAAAAA"

        self.child.sendline("send")
        res = str(self.child.read(220))
        self.assertIn("Paste in your account map (AKA output record)", res)
        self.child.sendline(account_map)
        self.child.readline()
        res = str(self.child.read(90))
        self.assertIn(
            "Paste partially signed bitcoin transaction (PSBT) in base64 form", res
        )
        self.child.sendline(unsigned_psbt_b64)
        self.child.readline()
        res = str(self.child.read(100))
        self.assertIn(
            "Transaction appears to be a testnet transaction. Display as testnet?", res
        )
        self.child.sendline("Y")
        self.child.readline()
        res = str(self.child.readline())
        self.assertIn(
            "PSBT sends 9,863 sats to tb1q23lxvv8l66r2e4cnx58ygahp6438knfwp8lapc with a fee of 137 sats (1.37% of spend)",
            res,
        )
        res = str(self.child.read(40))
        self.assertIn("In Depth Transaction View?", res)
        self.child.sendline("Y")
        self.child.expect("DETAILED VIEW")
        self.child.expect(
            "TXID: edbebb3fed50abcaecfffb993427becde623beac070fbcd822c36e2751cf0106"
        )
        for _ in range(19):
            self.child.readline()
        res = str(self.child.read(45))
        self.assertIn("Sign this transaction? [Y/n]", res)
        self.child.sendline("Y")
        res = str(self.child.read(62))
        self.assertIn("Enter your full BIP39 seed phrase", res)
        self.child.sendline(seed_phrase)
        self.child.readline()
        res = str(self.child.read(70))
        self.assertIn("Use a passphrase (advanced users only)? [y/N]", res)
        self.child.sendline("N")
        self.child.expect("Signed PSBT to broadcast")
        res = str(self.child.read(890))
        self.assertIn(signed_psbt_b64, res)

    def test_fail(self):
        # This has to take some seconds to fail
        # TODO: find a way to make this optional (default to no because slow)
        mw = pexpect.spawn("python3 multiwallet.py", timeout=2)
        with self.assertRaises(pexpect.exceptions.TIMEOUT):
            mw.expect("this text should not match")
