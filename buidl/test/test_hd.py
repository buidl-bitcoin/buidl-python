from unittest import TestCase

from buidl.hd import (
    calc_num_valid_seedpicker_checksums,
    calc_valid_seedpicker_checksums,
    get_unhardened_child_path,
    HDPublicKey,
    HDPrivateKey,
    is_valid_bip32_path,
    ltrim_path,
)
from buidl.helper import encode_base58_checksum
from buidl.mnemonic import BIP39, InvalidBIP39Length, InvalidChecksumWordsError


class HDTest(TestCase):
    def test_from_seed(self):
        seed = b"jimmy@programmingblockchain.com Jimmy Song"
        tests = {
            "testnet": "tb1q7kn55vf3mmd40gyj46r245lw87dc6us5n50lrg",
            "signet": "tb1q7kn55vf3mmd40gyj46r245lw87dc6us5n50lrg",
            "mainnet": "bc1q7kn55vf3mmd40gyj46r245lw87dc6us5ej5vcm",
        }
        for network, want in tests.items():
            priv = HDPrivateKey.from_seed(seed, network=network)
            addr = priv.bech32_address()
            self.assertEqual(addr, want)

    def test_child(self):
        seed = b"jimmy@programmingblockchain.com Jimmy Song"
        tests = (
            (
                "testnet",
                "tb1qu6mnnk54hxfhy4aj58v0w6e7q8hghtv8wcdl7g",
                "tb1qscu8evdlqsucj7p84xwnrf63h4jsdr5yqga8zq",
            ),
            (
                "signet",
                "tb1qu6mnnk54hxfhy4aj58v0w6e7q8hghtv8wcdl7g",
                "tb1qscu8evdlqsucj7p84xwnrf63h4jsdr5yqga8zq",
            ),
            (
                "mainnet",
                "bc1qu6mnnk54hxfhy4aj58v0w6e7q8hghtv8y7kv9m",
                "bc1qscu8evdlqsucj7p84xwnrf63h4jsdr5y2wx5en",
            ),
        )
        for network, want1, want2 in tests:
            priv = HDPrivateKey.from_seed(seed, network=network)
            pub = priv.pub
            addr = priv.child(0).bech32_address()
            self.assertEqual(addr, want1)
            addr = pub.child(0).bech32_address()
            self.assertEqual(addr, want1)
            addr = priv.child(0x80000002).bech32_address()
            self.assertEqual(addr, want2)
            with self.assertRaises(ValueError):
                pub.child(0x80000002)

    def test_traverse(self):
        seed = b"jimmy@programmingblockchain.com Jimmy Song"
        tests = (
            ("testnet", "tb1q423gz8cenqt6vfw987vlyxql0rh2jgh4sy0tue"),
            ("signet", "tb1q423gz8cenqt6vfw987vlyxql0rh2jgh4sy0tue"),
            ("mainnet", "bc1q423gz8cenqt6vfw987vlyxql0rh2jgh46z5c82"),
        )
        for network, want in tests:
            priv = HDPrivateKey.from_seed(seed, network=network)
            pub = priv.pub
            path = "m/1/2/3/4"
            self.assertEqual(
                priv.traverse(path).bech32_address(),
                pub.traverse(path).bech32_address(),
            )
            path = "m/0/1'/2/3'"
            self.assertEqual(
                priv.traverse(path).bech32_address(),
                want,
            )

    def test_prv_pub(self):
        tests = [
            {
                "seed": bytes.fromhex("000102030405060708090a0b0c0d0e0f"),
                "paths": [
                    [
                        "m",
                        "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
                        "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi",
                    ],
                    [
                        "m/0'",
                        "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw",
                        "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7",
                    ],
                    [
                        "m/0'/1",
                        "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ",
                        "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs",
                    ],
                    [
                        "m/0'/1/2'",
                        "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5",
                        "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM",
                    ],
                    [
                        "m/0'/1/2'/2",
                        "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV",
                        "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334",
                    ],
                    [
                        "m/0'/1/2'/2/1000000000",
                        "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy",
                        "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76",
                    ],
                ],
            },
            {
                "seed": bytes.fromhex(
                    "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"
                ),
                "paths": [
                    [
                        "m",
                        "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB",
                        "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U",
                    ],
                    [
                        "m/0",
                        "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH",
                        "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt",
                    ],
                    [
                        "m/0/2147483647'",
                        "xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a",
                        "xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9",
                    ],
                    [
                        "m/0/2147483647'/1",
                        "xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon",
                        "xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef",
                    ],
                    [
                        "m/0/2147483647'/1/2147483646'",
                        "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL",
                        "xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc",
                    ],
                    [
                        "m/0/2147483647'/1/2147483646'/2",
                        "xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt",
                        "xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j",
                    ],
                ],
            },
            {
                "seed": bytes.fromhex(
                    "4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be"
                ),
                "paths": [
                    [
                        "m",
                        "xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13",
                        "xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6",
                    ],
                    [
                        "m/0'",
                        "xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y",
                        "xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L",
                    ],
                ],
            },
        ]
        for test in tests:
            seed = test["seed"]
            for path, xpub, xprv in test["paths"]:
                # test from seed
                private_key = HDPrivateKey.from_seed(seed).traverse(path)
                public_key = HDPublicKey.parse(xpub)
                self.assertEqual(private_key.xprv(), xprv)
                self.assertEqual(private_key.xpub(), public_key.xpub())
                self.assertEqual(private_key.address(), public_key.address())

    def test_parse(self):
        xpub = "xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13"
        hd_pub = HDPublicKey.parse(xpub)
        self.assertEqual(hd_pub.xpub(), xpub)
        xprv = "xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6"
        hd_priv = HDPrivateKey.parse(xprv)
        self.assertEqual(hd_priv.xprv(), xprv)

    def test_get_address(self):
        seedphrase = b"jimmy@programmingblockchain.com Jimmy Song"
        mainnet_priv = HDPrivateKey.from_seed(seedphrase)
        testnet_priv = HDPrivateKey.from_seed(seedphrase, network="testnet")
        signet_priv = HDPrivateKey.from_seed(seedphrase, network="signet")
        tests = [
            [
                mainnet_priv.get_p2pkh_receiving_address,
                0,
                1,
                "13pS51XfGTVhxbtrGKVSvwf36r96tLUu1K",
            ],
            [
                testnet_priv.get_p2pkh_change_address,
                1,
                0,
                "n4EiCRsEEPaJ73HWA6zYEaHwo45BrP5MHb",
            ],
            [
                signet_priv.get_p2pkh_change_address,
                1,
                0,
                "n4EiCRsEEPaJ73HWA6zYEaHwo45BrP5MHb",
            ],
            [
                testnet_priv.get_p2sh_p2wpkh_receiving_address,
                0,
                2,
                "2NGKoo11UopXBWLC7qqj9BjgH9F3gvLdapz",
            ],
            [
                signet_priv.get_p2sh_p2wpkh_receiving_address,
                0,
                2,
                "2NGKoo11UopXBWLC7qqj9BjgH9F3gvLdapz",
            ],
            [
                mainnet_priv.get_p2sh_p2wpkh_change_address,
                0,
                0,
                "38hYFPLMTykhURpCQTxkdDcpQKyieiYiU7",
            ],
            [
                mainnet_priv.get_p2wpkh_receiving_address,
                2,
                0,
                "bc1qzeln78k9sghatd3uwnks8jek46qe23dw99zu9j",
            ],
            [
                testnet_priv.get_p2wpkh_change_address,
                1,
                1,
                "tb1qecjwdw5uwwdfezzntec7m4kc8zkyjcamlz7dv9",
            ],
            [
                signet_priv.get_p2wpkh_change_address,
                1,
                1,
                "tb1qecjwdw5uwwdfezzntec7m4kc8zkyjcamlz7dv9",
            ],
        ]
        for function, account, address, want in tests:
            got = function(account, address)
            self.assertEqual(got, want)

    def test_from_mnemonic(self):
        tests = [
            [
                "00000000000000000000000000000000",
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
                "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
                "xprv9s21ZrQH143K3h3fDYiay8mocZ3afhfULfb5GX8kCBdno77K4HiA15Tg23wpbeF1pLfs1c5SPmYHrEpTuuRhxMwvKDwqdKiGJS9XFKzUsAF",
            ],
            [
                "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
                "legal winner thank year wave sausage worth useful legal winner thank yellow",
                "2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6fa457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607",
                "xprv9s21ZrQH143K2gA81bYFHqU68xz1cX2APaSq5tt6MFSLeXnCKV1RVUJt9FWNTbrrryem4ZckN8k4Ls1H6nwdvDTvnV7zEXs2HgPezuVccsq",
            ],
            [
                "80808080808080808080808080808080",
                "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
                "d71de856f81a8acc65e6fc851a38d4d7ec216fd0796d0a6827a3ad6ed5511a30fa280f12eb2e47ed2ac03b5c462a0358d18d69fe4f985ec81778c1b370b652a8",
                "xprv9s21ZrQH143K2shfP28KM3nr5Ap1SXjz8gc2rAqqMEynmjt6o1qboCDpxckqXavCwdnYds6yBHZGKHv7ef2eTXy461PXUjBFQg6PrwY4Gzq",
            ],
            [
                "ffffffffffffffffffffffffffffffff",
                "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
                "ac27495480225222079d7be181583751e86f571027b0497b5b5d11218e0a8a13332572917f0f8e5a589620c6f15b11c61dee327651a14c34e18231052e48c069",
                "xprv9s21ZrQH143K2V4oox4M8Zmhi2Fjx5XK4Lf7GKRvPSgydU3mjZuKGCTg7UPiBUD7ydVPvSLtg9hjp7MQTYsW67rZHAXeccqYqrsx8LcXnyd",
            ],
            [
                "000000000000000000000000000000000000000000000000",
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent",
                "035895f2f481b1b0f01fcf8c289c794660b289981a78f8106447707fdd9666ca06da5a9a565181599b79f53b844d8a71dd9f439c52a3d7b3e8a79c906ac845fa",
                "xprv9s21ZrQH143K3mEDrypcZ2usWqFgzKB6jBBx9B6GfC7fu26X6hPRzVjzkqkPvDqp6g5eypdk6cyhGnBngbjeHTe4LsuLG1cCmKJka5SMkmU",
            ],
            [
                "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
                "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal will",
                "f2b94508732bcbacbcc020faefecfc89feafa6649a5491b8c952cede496c214a0c7b3c392d168748f2d4a612bada0753b52a1c7ac53c1e93abd5c6320b9e95dd",
                "xprv9s21ZrQH143K3Lv9MZLj16np5GzLe7tDKQfVusBni7toqJGcnKRtHSxUwbKUyUWiwpK55g1DUSsw76TF1T93VT4gz4wt5RM23pkaQLnvBh7",
            ],
            [
                "808080808080808080808080808080808080808080808080",
                "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter always",
                "107d7c02a5aa6f38c58083ff74f04c607c2d2c0ecc55501dadd72d025b751bc27fe913ffb796f841c49b1d33b610cf0e91d3aa239027f5e99fe4ce9e5088cd65",
                "xprv9s21ZrQH143K3VPCbxbUtpkh9pRG371UCLDz3BjceqP1jz7XZsQ5EnNkYAEkfeZp62cDNj13ZTEVG1TEro9sZ9grfRmcYWLBhCocViKEJae",
            ],
            [
                "ffffffffffffffffffffffffffffffffffffffffffffffff",
                "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo when",
                "0cd6e5d827bb62eb8fc1e262254223817fd068a74b5b449cc2f667c3f1f985a76379b43348d952e2265b4cd129090758b3e3c2c49103b5051aac2eaeb890a528",
                "xprv9s21ZrQH143K36Ao5jHRVhFGDbLP6FCx8BEEmpru77ef3bmA928BxsqvVM27WnvvyfWywiFN8K6yToqMaGYfzS6Db1EHAXT5TuyCLBXUfdm",
            ],
            [
                "0000000000000000000000000000000000000000000000000000000000000000",
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
                "bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd3097170af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8",
                "xprv9s21ZrQH143K32qBagUJAMU2LsHg3ka7jqMcV98Y7gVeVyNStwYS3U7yVVoDZ4btbRNf4h6ibWpY22iRmXq35qgLs79f312g2kj5539ebPM",
            ],
            [
                "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
                "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title",
                "bc09fca1804f7e69da93c2f2028eb238c227f2e9dda30cd63699232578480a4021b146ad717fbb7e451ce9eb835f43620bf5c514db0f8add49f5d121449d3e87",
                "xprv9s21ZrQH143K3Y1sd2XVu9wtqxJRvybCfAetjUrMMco6r3v9qZTBeXiBZkS8JxWbcGJZyio8TrZtm6pkbzG8SYt1sxwNLh3Wx7to5pgiVFU",
            ],
            [
                "8080808080808080808080808080808080808080808080808080808080808080",
                "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless",
                "c0c519bd0e91a2ed54357d9d1ebef6f5af218a153624cf4f2da911a0ed8f7a09e2ef61af0aca007096df430022f7a2b6fb91661a9589097069720d015e4e982f",
                "xprv9s21ZrQH143K3CSnQNYC3MqAAqHwxeTLhDbhF43A4ss4ciWNmCY9zQGvAKUSqVUf2vPHBTSE1rB2pg4avopqSiLVzXEU8KziNnVPauTqLRo",
            ],
            [
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
                "dd48c104698c30cfe2b6142103248622fb7bb0ff692eebb00089b32d22484e1613912f0a5b694407be899ffd31ed3992c456cdf60f5d4564b8ba3f05a69890ad",
                "xprv9s21ZrQH143K2WFF16X85T2QCpndrGwx6GueB72Zf3AHwHJaknRXNF37ZmDrtHrrLSHvbuRejXcnYxoZKvRquTPyp2JiNG3XcjQyzSEgqCB",
            ],
            [
                "9e885d952ad362caeb4efe34a8e91bd2",
                "ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic",
                "274ddc525802f7c828d8ef7ddbcdc5304e87ac3535913611fbbfa986d0c9e5476c91689f9c8a54fd55bd38606aa6a8595ad213d4c9c9f9aca3fb217069a41028",
                "xprv9s21ZrQH143K2oZ9stBYpoaZ2ktHj7jLz7iMqpgg1En8kKFTXJHsjxry1JbKH19YrDTicVwKPehFKTbmaxgVEc5TpHdS1aYhB2s9aFJBeJH",
            ],
            [
                "6610b25967cdcca9d59875f5cb50b0ea75433311869e930b",
                "gravity machine north sort system female filter attitude volume fold club stay feature office ecology stable narrow fog",
                "628c3827a8823298ee685db84f55caa34b5cc195a778e52d45f59bcf75aba68e4d7590e101dc414bc1bbd5737666fbbef35d1f1903953b66624f910feef245ac",
                "xprv9s21ZrQH143K3uT8eQowUjsxrmsA9YUuQQK1RLqFufzybxD6DH6gPY7NjJ5G3EPHjsWDrs9iivSbmvjc9DQJbJGatfa9pv4MZ3wjr8qWPAK",
            ],
            [
                "68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c",
                "hamster diagram private dutch cause delay private meat slide toddler razor book happy fancy gospel tennis maple dilemma loan word shrug inflict delay length",
                "64c87cde7e12ecf6704ab95bb1408bef047c22db4cc7491c4271d170a1b213d20b385bc1588d9c7b38f1b39d415665b8a9030c9ec653d75e65f847d8fc1fc440",
                "xprv9s21ZrQH143K2XTAhys3pMNcGn261Fi5Ta2Pw8PwaVPhg3D8DWkzWQwjTJfskj8ofb81i9NP2cUNKxwjueJHHMQAnxtivTA75uUFqPFeWzk",
            ],
            [
                "c0ba5a8e914111210f2bd131f3d5e08d",
                "scheme spot photo card baby mountain device kick cradle pact join borrow",
                "ea725895aaae8d4c1cf682c1bfd2d358d52ed9f0f0591131b559e2724bb234fca05aa9c02c57407e04ee9dc3b454aa63fbff483a8b11de949624b9f1831a9612",
                "xprv9s21ZrQH143K3FperxDp8vFsFycKCRcJGAFmcV7umQmcnMZaLtZRt13QJDsoS5F6oYT6BB4sS6zmTmyQAEkJKxJ7yByDNtRe5asP2jFGhT6",
            ],
            [
                "6d9be1ee6ebd27a258115aad99b7317b9c8d28b6d76431c3",
                "horn tenant knee talent sponsor spell gate clip pulse soap slush warm silver nephew swap uncle crack brave",
                "fd579828af3da1d32544ce4db5c73d53fc8acc4ddb1e3b251a31179cdb71e853c56d2fcb11aed39898ce6c34b10b5382772db8796e52837b54468aeb312cfc3d",
                "xprv9s21ZrQH143K3R1SfVZZLtVbXEB9ryVxmVtVMsMwmEyEvgXN6Q84LKkLRmf4ST6QrLeBm3jQsb9gx1uo23TS7vo3vAkZGZz71uuLCcywUkt",
            ],
            [
                "9f6a2878b2520799a44ef18bc7df394e7061a224d2c33cd015b157d746869863",
                "panda eyebrow bullet gorilla call smoke muffin taste mesh discover soft ostrich alcohol speed nation flash devote level hobby quick inner drive ghost inside",
                "72be8e052fc4919d2adf28d5306b5474b0069df35b02303de8c1729c9538dbb6fc2d731d5f832193cd9fb6aeecbc469594a70e3dd50811b5067f3b88b28c3e8d",
                "xprv9s21ZrQH143K2WNnKmssvZYM96VAr47iHUQUTUyUXH3sAGNjhJANddnhw3i3y3pBbRAVk5M5qUGFr4rHbEWwXgX4qrvrceifCYQJbbFDems",
            ],
            [
                "23db8160a31d3e0dca3688ed941adbf3",
                "cat swing flag economy stadium alone churn speed unique patch report train",
                "deb5f45449e615feff5640f2e49f933ff51895de3b4381832b3139941c57b59205a42480c52175b6efcffaa58a2503887c1e8b363a707256bdd2b587b46541f5",
                "xprv9s21ZrQH143K4G28omGMogEoYgDQuigBo8AFHAGDaJdqQ99QKMQ5J6fYTMfANTJy6xBmhvsNZ1CJzRZ64PWbnTFUn6CDV2FxoMDLXdk95DQ",
            ],
            [
                "8197a4a47f0425faeaa69deebc05ca29c0a5b5cc76ceacc0",
                "light rule cinnamon wrap drastic word pride squirrel upgrade then income fatal apart sustain crack supply proud access",
                "4cbdff1ca2db800fd61cae72a57475fdc6bab03e441fd63f96dabd1f183ef5b782925f00105f318309a7e9c3ea6967c7801e46c8a58082674c860a37b93eda02",
                "xprv9s21ZrQH143K3wtsvY8L2aZyxkiWULZH4vyQE5XkHTXkmx8gHo6RUEfH3Jyr6NwkJhvano7Xb2o6UqFKWHVo5scE31SGDCAUsgVhiUuUDyh",
            ],
            [
                "066dca1a2bb7e8a1db2832148ce9933eea0f3ac9548d793112d9a95c9407efad",
                "all hour make first leader extend hole alien behind guard gospel lava path output census museum junior mass reopen famous sing advance salt reform",
                "26e975ec644423f4a4c4f4215ef09b4bd7ef924e85d1d17c4cf3f136c2863cf6df0a475045652c57eb5fb41513ca2a2d67722b77e954b4b3fc11f7590449191d",
                "xprv9s21ZrQH143K3rEfqSM4QZRVmiMuSWY9wugscmaCjYja3SbUD3KPEB1a7QXJoajyR2T1SiXU7rFVRXMV9XdYVSZe7JoUXdP4SRHTxsT1nzm",
            ],
            [
                "f30f8c1da665478f49b001d94c5fc452",
                "vessel ladder alter error federal sibling chat ability sun glass valve picture",
                "2aaa9242daafcee6aa9d7269f17d4efe271e1b9a529178d7dc139cd18747090bf9d60295d0ce74309a78852a9caadf0af48aae1c6253839624076224374bc63f",
                "xprv9s21ZrQH143K2QWV9Wn8Vvs6jbqfF1YbTCdURQW9dLFKDovpKaKrqS3SEWsXCu6ZNky9PSAENg6c9AQYHcg4PjopRGGKmdD313ZHszymnps",
            ],
            [
                "c10ec20dc3cd9f652c7fac2f1230f7a3c828389a14392f05",
                "scissors invite lock maple supreme raw rapid void congress muscle digital elegant little brisk hair mango congress clump",
                "7b4a10be9d98e6cba265566db7f136718e1398c71cb581e1b2f464cac1ceedf4f3e274dc270003c670ad8d02c4558b2f8e39edea2775c9e232c7cb798b069e88",
                "xprv9s21ZrQH143K4aERa2bq7559eMCCEs2QmmqVjUuzfy5eAeDX4mqZffkYwpzGQRE2YEEeLVRoH4CSHxianrFaVnMN2RYaPUZJhJx8S5j6puX",
            ],
            [
                "f585c11aec520db57dd353c69554b21a89b20fb0650966fa0a9d6f74fd989d8f",
                "void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold",
                "01f5bced59dec48e362f2c45b5de68b9fd6c92c6634f44d6d40aab69056506f0e35524a518034ddc1192e1dacd32c1ed3eaa3c3b131c88ed8e7e54c49a5d0998",
                "xprv9s21ZrQH143K39rnQJknpH1WEPFJrzmAqqasiDcVrNuk926oizzJDDQkdiTvNPr2FYDYzWgiMiC63YmfPAa2oPyNB23r2g7d1yiK6WpqaQS",
            ],
        ]
        for entropy, mnemonic, seed, xprv in tests:
            private_key = HDPrivateKey.from_mnemonic(mnemonic, b"TREZOR")
            self.assertEqual(private_key.xprv(), xprv)

    def test_from_shares(self):
        shares = [
            "eraser senior decision roster beard treat identify grumpy salt index fake aviation theater cubic bike cause research dragon emphasis counter",
            "eraser senior ceramic snake clay various huge numb argue hesitate auction category timber browser greatest hanger petition script leaf pickup",
            "eraser senior ceramic shaft dynamic become junior wrist silver peasant force math alto coal amazing segment yelp velvet image paces",
            "eraser senior ceramic round column hawk trust auction smug shame alive greatest sheriff living perfect corner chest sled fumes adequate",
            "eraser senior decision smug corner ruin rescue cubic angel tackle skin skunk program roster trash rumor slush angel flea amazing",
        ]
        hd_priv = HDPrivateKey.from_shares(shares, passphrase=b"TREZOR")
        expected = HDPrivateKey.from_mnemonic(
            "label original trim census flock area area virus purchase hobby globe cart"
        )
        self.assertEqual(hd_priv.xprv(), expected.xprv())
        shares = [
            "wildlife deal ceramic round aluminum pitch goat racism employer miracle percent math decision episode dramatic editor lily prospect program scene rebuild display sympathy have single mustang junction relate often chemical society wits estate",
            "wildlife deal decision scared acne fatal snake paces obtain election dryer dominant romp tactics railroad marvel trust helpful flip peanut theory theater photo luck install entrance taxi step oven network dictate intimate listen",
            "wildlife deal ceramic scatter argue equip vampire together ruin reject literary rival distance aquatic agency teammate rebound false argue miracle stay again blessing peaceful unknown cover beard acid island language debris industry idle",
            "wildlife deal ceramic snake agree voter main lecture axis kitchen physics arcade velvet spine idea scroll promise platform firm sharp patrol divorce ancestor fantasy forbid goat ajar believe swimming cowboy symbolic plastic spelling",
            "wildlife deal decision shadow analysis adjust bulb skunk muscle mandate obesity total guitar coal gravity carve slim jacket ruin rebuild ancestor numerous hour mortgage require herd maiden public ceiling pecan pickup shadow club",
        ]
        hd_priv = HDPrivateKey.from_shares(shares, passphrase=b"TREZOR")
        expected = HDPrivateKey.from_mnemonic(
            "fatal click tennis boring short ask clever bus valve island join edit blue end obtain rate travel fragile ahead mimic maid receive employ learn"
        )
        self.assertEqual(hd_priv.xprv(), expected.xprv())

    def test_bip49(self):
        mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        password = b""
        path = "m"
        hd_private_key = HDPrivateKey.from_mnemonic(
            mnemonic, password, path=path, network="testnet"
        )
        want = "tprv8ZgxMBicQKsPe5YMU9gHen4Ez3ApihUfykaqUorj9t6FDqy3nP6eoXiAo2ssvpAjoLroQxHqr3R5nE3a5dU3DHTjTgJDd7zrbniJr6nrCzd"
        self.assertEqual(hd_private_key.xprv(), want)
        hd_private_key = HDPrivateKey.from_mnemonic(
            mnemonic, password, path=path, network="signet"
        )
        want = "tprv8ZgxMBicQKsPe5YMU9gHen4Ez3ApihUfykaqUorj9t6FDqy3nP6eoXiAo2ssvpAjoLroQxHqr3R5nE3a5dU3DHTjTgJDd7zrbniJr6nrCzd"
        self.assertEqual(hd_private_key.xprv(), want)
        account0 = (
            hd_private_key.child((1 << 31) + 49).child((1 << 31) + 1).child(1 << 31)
        )
        want = "tprv8gRrNu65W2Msef2BdBSUgFdRTGzC8EwVXnV7UGS3faeXtuMVtGfEdidVeGbThs4ELEoayCAzZQ4uUji9DUiAs7erdVskqju7hrBcDvDsdbY"
        self.assertEqual(account0.xprv(), want)
        account0_pub = account0.pub
        account0_first_key = account0.child(0).child(0)
        pub_first_key = account0_pub.traverse("m/0/0")
        want = "cULrpoZGXiuC19Uhvykx7NugygA3k86b3hmdCeyvHYQZSxojGyXJ"
        self.assertEqual(account0_first_key.wif(), want)
        want = 0xC9BDB49CFBAEDCA21C4B1F3A7803C34636B1D7DC55A717132443FC3F4C5867E8
        self.assertEqual(account0_first_key.private_key.secret, want)
        want = bytes.fromhex(
            "03a1af804ac108a8a51782198c2d034b28bf90c8803f5a53f76276fa69a4eae77f"
        )
        self.assertEqual(account0_first_key.private_key.point.sec(), want)
        self.assertEqual(pub_first_key.address(), account0_first_key.address())

    def test_bech32_address(self):
        mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        password = b""
        path = "m/84'/0'/0'"
        account = HDPrivateKey.from_mnemonic(
            mnemonic, password, path=path, network="mainnet"
        )
        want = "zprvAdG4iTXWBoARxkkzNpNh8r6Qag3irQB8PzEMkAFeTRXxHpbF9z4QgEvBRmfvqWvGp42t42nvgGpNgYSJA9iefm1yYNZKEm7z6qUWCroSQnE"
        self.assertEqual(account.xprv(version=bytes.fromhex("04b2430c")), want)
        want = "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs"
        self.assertEqual(account.xpub(version=bytes.fromhex("04b24746")), want)
        first_key = account.child(0).child(0)
        want = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
        self.assertEqual(first_key.bech32_address(), want)

    def test_zprv(self):
        mnemonic, priv = HDPrivateKey.generate(extra_entropy=1 << 128)
        for word in mnemonic.split():
            self.assertTrue(word in BIP39)
        zprv = priv.xprv(version=bytes.fromhex("04b2430c"))
        self.assertTrue(zprv.startswith("zprv"))
        zpub = priv.pub.xpub(version=bytes.fromhex("04b24746"))
        self.assertTrue(zpub.startswith("zpub"))
        derived = HDPrivateKey.parse(zprv)
        self.assertEqual(zprv, derived.xprv(bytes.fromhex("04b2430c")))
        mnemonic, priv = HDPrivateKey.generate(network="testnet")
        zprv = priv.xprv(bytes.fromhex("045f18bc"))
        self.assertTrue(zprv.startswith("vprv"))
        zpub = priv.pub.xpub(bytes.fromhex("045f1cf6"))
        self.assertTrue(zpub.startswith("vpub"))
        xpub = priv.pub.xpub(bytes.fromhex("043587cf"))
        self.assertTrue(xpub.startswith("tpub"))
        derived = HDPrivateKey.parse(zprv)
        self.assertEqual(zprv, derived.xprv(bytes.fromhex("045f18bc")))
        derived_pub = HDPublicKey.parse(zpub)
        self.assertEqual(zpub, derived_pub.xpub(bytes.fromhex("045f1cf6")))
        mnemonic, priv = HDPrivateKey.generate(network="signet")
        zprv = priv.xprv(bytes.fromhex("045f18bc"))
        self.assertTrue(zprv.startswith("vprv"))
        zpub = priv.pub.xpub(bytes.fromhex("045f1cf6"))
        self.assertTrue(zpub.startswith("vpub"))
        xpub = priv.pub.xpub(bytes.fromhex("043587cf"))
        self.assertTrue(xpub.startswith("tpub"))
        derived = HDPrivateKey.parse(zprv)
        self.assertEqual(zprv, derived.xprv(bytes.fromhex("045f18bc")))
        derived_pub = HDPublicKey.parse(zpub)
        self.assertEqual(zpub, derived_pub.xpub(bytes.fromhex("045f1cf6")))
        with self.assertRaises(ValueError):
            bad_zprv = encode_base58_checksum(b"\x00" * 78)
            HDPrivateKey.parse(bad_zprv)
        with self.assertRaises(ValueError):
            bad_zpub = encode_base58_checksum(b"\x00" * 78)
            HDPublicKey.parse(bad_zpub)
        with self.assertRaises(ValueError):
            derived_pub.child(1 << 31)

    def test_vpub(self):
        # From https://seedpicker.net/calculator/last-word.html?network=testnet
        mnemonic = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo buddy"
        path = "m/48'/1'/0'/2'"

        self.assertEqual(
            "669dce62", HDPrivateKey.from_mnemonic(mnemonic).fingerprint().hex()
        )
        vpub = (
            HDPrivateKey.from_mnemonic(mnemonic)
            .traverse(path)
            .xpub(bytes.fromhex("02575483"))
        )
        want = "Vpub5mru9pEB9wFgRsCsYi4hcTvaqZ5p2xs2upUsN5Fig6nUrug2xkfPmbt2PfUS5QhDgCLctdkuQLmVnpN1j8a6RS9Mk53mbxi3Mx4HB6vCTWc"
        self.assertEqual(vpub, want)

        # Be sure that we can parse a vpub:
        hdpubkey_obj = HDPublicKey.parse(want)
        self.assertEqual(hdpubkey_obj.depth, 4)

    def test_from_mnemonic_errors(self):
        with self.assertRaises(InvalidBIP39Length):
            # only 1 word!
            HDPrivateKey.from_mnemonic("hello")

        with self.assertRaises(InvalidChecksumWordsError):
            # 12 words (11 would work)
            mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon"
            HDPrivateKey.from_mnemonic(mnemonic)

    def test_seedpicker(self):
        first_words = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo"
        want = ["buddy", "cash", "gap", "leaf", "move", "party", "sudden", "vote"]
        # calc_valid_seedpicker_checksums is a generator
        for cnt, checksum in enumerate(
            calc_valid_seedpicker_checksums(first_words=first_words)
        ):
            self.assertEqual(checksum, want[cnt])

        self.assertEqual(
            calc_num_valid_seedpicker_checksums(len(first_words.split())), len(want)
        )

        zoo_tests = [
            # length, default_checksum
            ["zoo " * 11, "abstract"],
            ["zoo " * 14, "account"],
            ["zoo " * 17, "advice"],
            ["zoo " * 20, "arrow"],
            ["zoo " * 23, "buddy"],
        ]
        for first_words, default_checksum_want in zoo_tests:
            generator = calc_valid_seedpicker_checksums(first_words=first_words.strip())
            self.assertEqual(default_checksum_want, next(generator))

        for length in (2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 13, 15, 16, 18, 19, 21, 22, 24):
            with self.assertRaises(InvalidBIP39Length):
                # Next is just a way to call the generator
                next(calc_valid_seedpicker_checksums(first_words="able " * length))

    def test_xpub_version(self):
        mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        hd_obj = HDPrivateKey.from_mnemonic(mnemonic, network="testnet")
        tprv = "tprv8ZgxMBicQKsPe5YMU9gHen4Ez3ApihUfykaqUorj9t6FDqy3nP6eoXiAo2ssvpAjoLroQxHqr3R5nE3a5dU3DHTjTgJDd7zrbniJr6nrCzd"
        tpub = "tpubD6NzVbkrYhZ4XYa9MoLt4BiMZ4gkt2faZ4BcmKu2a9te4LDpQmvEz2L2yDERivHxFPnxXXhqDRkUNnQCpZggCyEZLBktV7VaSmwayqMJy1s"
        self.assertEqual(hd_obj.xprv(), tprv)
        self.assertEqual(hd_obj.xpub(), tpub)
        hd_obj = HDPrivateKey.from_mnemonic(mnemonic, network="signet")
        self.assertEqual(hd_obj.xprv(), tprv)
        self.assertEqual(hd_obj.xpub(), tpub)
        # parse this same HDPrivateKey from the tprv (assume we no longer have the mnemonic)
        recreated_obj = HDPrivateKey.parse(tprv)
        self.assertEqual(recreated_obj.xpub(), tpub)
        # Confirm the version bytes have passed through correctly to the HDPublicKey object:
        self.assertEqual(recreated_obj.pub.xpub(), tpub)

        hd_obj = HDPrivateKey.from_mnemonic(mnemonic, network="mainnet")
        xprv = "xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu"
        xpub = "xpub661MyMwAqRbcFkPHucMnrGNzDwb6teAX1RbKQmqtEF8kK3Z7LZ59qafCjB9eCRLiTVG3uxBxgKvRgbubRhqSKXnGGb1aoaqLrpMBDrVxga8"
        self.assertEqual(hd_obj.xprv(), xprv)
        self.assertEqual(hd_obj.xpub(), xpub)

        # parse this same HDPrivateKey from the xprv (assume we no longer have the mnemonic)
        recreated_obj = HDPrivateKey.parse(xprv)
        self.assertEqual(recreated_obj.xpub(), xpub)
        # Confirm the version bytes have passed through correctly to the HDPublicKey object:
        self.assertEqual(recreated_obj.pub.xpub(), xpub)

    def test_key_record(self):
        # Matched against seedpicker.net on 2021-06-04
        seed_phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"

        # mainnet
        hdpriv_obj = HDPrivateKey.from_mnemonic(seed_phrase)
        want = "[5436d724/48h/0h/0h/2h]Zpub74fkz9VnCkwXHqheLbKfBEPKPfnFg3S1Ecn7Jx4HgBWwD1FS5VLMtFYNqLmFBVifGuXKz2nirv647gFYCinhBSdBqrrh5vq8ok8m2eaRAt7"
        self.assertEqual(
            hdpriv_obj.generate_p2wsh_key_record(use_slip132_version_byte=True), want
        )
        want = "[5436d724/48h/0h/0h/2h]xpub6E79FaRWLSJCAgA2jDHRvyrWKwT6aSmR685zptzyYPvmUd44omcxZ1NAzDtbdFBvEADjcVbV4NzTDwQeU6oiSV9KGiMSWhjANZjbfUHkm3Y"
        self.assertEqual(hdpriv_obj.generate_p2wsh_key_record(), want)
        # testnet
        hdpriv_obj = HDPrivateKey.from_mnemonic(seed_phrase, network="testnet")
        want = "[5436d724/48h/1h/0h/2h]Vpub5ncJ4gVToMcTWjG4shBZHeeCUXhX5r86W9cwggqw1m6aojbrHxr9yJFsoXaiXrBfAzV3TaVyxCB6EYUW21SVayfcAhiVc9XRJS1WL4Gh9td"
        self.assertEqual(
            hdpriv_obj.generate_p2wsh_key_record(use_slip132_version_byte=True), want
        )
        want = "[5436d724/48h/1h/0h/2h]tpubDFkN51vYF36W4Yfn3wGv5fpmRo3ok7vZZjc1gmRJjumq33L776e6GkP4HGdCVjDqYiBahXCrXQKja8aUZ2xovQNS8WkF46MdY7TLHJLYD7H"
        self.assertEqual(hdpriv_obj.generate_p2wsh_key_record(), want)
        # signet
        hdpriv_obj = HDPrivateKey.from_mnemonic(seed_phrase, network="signet")
        want = "[5436d724/48h/1h/0h/2h]Vpub5ncJ4gVToMcTWjG4shBZHeeCUXhX5r86W9cwggqw1m6aojbrHxr9yJFsoXaiXrBfAzV3TaVyxCB6EYUW21SVayfcAhiVc9XRJS1WL4Gh9td"
        self.assertEqual(
            hdpriv_obj.generate_p2wsh_key_record(use_slip132_version_byte=True), want
        )
        want = "[5436d724/48h/1h/0h/2h]tpubDFkN51vYF36W4Yfn3wGv5fpmRo3ok7vZZjc1gmRJjumq33L776e6GkP4HGdCVjDqYiBahXCrXQKja8aUZ2xovQNS8WkF46MdY7TLHJLYD7H"
        self.assertEqual(hdpriv_obj.generate_p2wsh_key_record(), want)


class BIP32PathsTest(TestCase):
    def test_valid_paths(self):
        self.assertTrue(is_valid_bip32_path("m"))
        self.assertTrue(is_valid_bip32_path("m/0"))
        self.assertTrue(is_valid_bip32_path("m/45"))
        self.assertTrue(is_valid_bip32_path("m/45h"))
        self.assertTrue(is_valid_bip32_path("m/45'"))
        self.assertTrue(is_valid_bip32_path("m/1/2/3/4/5"))
        self.assertTrue(is_valid_bip32_path("m/1/2h/3/4h/5"))
        self.assertTrue(is_valid_bip32_path("m/48'/1'/0'/1'"))
        self.assertTrue(is_valid_bip32_path("m/48h/1h/0h/2h"))

    def test_invalid_paths(self):
        # just "m" (without trailing slash) is valid:
        self.assertFalse(is_valid_bip32_path("m/"))
        self.assertFalse(is_valid_bip32_path("m/1/"))
        self.assertFalse(is_valid_bip32_path("m/1'/"))
        self.assertFalse(is_valid_bip32_path("m/-1"))
        self.assertFalse(is_valid_bip32_path("m/1/a"))
        self.assertFalse(is_valid_bip32_path("m/foo"))
        self.assertFalse(is_valid_bip32_path(f"m/{2**32}"))

    def test_ltrim_path(self):
        self.assertEqual(ltrim_path("m", 0), "m/")
        self.assertEqual(ltrim_path("m/1", 0), "m/1")
        self.assertEqual(ltrim_path("m/1", 1), "m/")
        self.assertEqual(ltrim_path("m/1/2/3", 1), "m/2/3")
        self.assertEqual(ltrim_path("m/1/2/3h", 2), "m/3h")
        with self.assertRaises(ValueError):
            ltrim_path("m/1", 2)

        with self.assertRaises(ValueError):
            ltrim_path("m/", 1)

    def test_child_path_calc(self):
        self.assertEqual(get_unhardened_child_path("m/45h/0", "m/45h/0/0/1"), "m/0/1")
        self.assertEqual(get_unhardened_child_path("m/45h/0", "m/45h/0/0/1"), "m/0/1")
        self.assertEqual(get_unhardened_child_path("m/45h/0", "m/45h/0"), "m")

        # Hardened derivation after base (m/0h/1)
        self.assertIsNone(get_unhardened_child_path("m/45h/0", "m/45h/0/0'/1"))

        # Doesn't share a base
        self.assertIsNone(get_unhardened_child_path("m/0/1", "m/45h/0/0"))
