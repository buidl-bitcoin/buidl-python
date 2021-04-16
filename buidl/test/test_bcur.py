from unittest import TestCase

from buidl.bcur import (
    bcur_encode,
    bcur_decode,
    BCURSingle,
    BCURMulti,
    _parse_bcur_helper,
    BCURStringFormatError,
)

from binascii import a2b_base64
from base64 import b64encode


class SpecterDesktopTest(TestCase):
    def test_specter_desktop(self):
        """
        Test case from specter-desktop:
        https://github.com/cryptoadvance/specter-desktop/blob/0a483316d0d2e83cb5a532a0cbbcd82a885587db/src/cryptoadvance/specter/util/bcur.py
        """

        psbt_b64 = "cHNidP8BAHEBAAAAAfPQ5Rpeu5nH0TImK4Sbu9lxIOGEynRadywPxaPyhnTwAAAAAAD/////AkoRAAAAAAAAFgAUFCYoQzGSRmYVAuZNuXF0OrPg9jWIEwAAAAAAABYAFOZMlwM1sZGLivwOcOh77amAlvD5AAAAAAABAR+tKAAAAAAAABYAFM4u9V5WG+Fe9l3MefmYEX4ULWAWIgYDA+jO+oOuN37ABK67BA/+SuuR/57c7OkyfyR7hR34FDsYccBxUlQAAIAAAACAAAAAgAAAAAAFAAAAACICApJMZBvzWiavLN7nievKQoylwPoffLkXZUIgGHF4HgwaGHHAcVJUAACAAAAAgAAAAIABAAAACwAAAAAA"
        raw = a2b_base64(psbt_b64)
        enc, enc_hash = bcur_encode(raw)
        dec = bcur_decode(enc, enc_hash)
        self.assertEqual(dec, raw)
        testres = [
            "tyq3wurnvf607qgqwyqsqqqqq8eapeg6t6aen373xgnzhpymh0vhzg8psn98gknh9s8utgljse60qqqqqqqqpllllllsyjs3qqqqqqqqqqtqq9q5yc5yxvvjgenp2qhxfkuhzap6k0s0vdvgzvqqqqqqqqqpvqq5uexfwqe4kxgchzhupecws7ld4xqfdu8eqqqqqqqq",
            "qyq3ltfgqqqqqqqqqqtqq9xw9m64u4smu900vhwv08uesyt7zskkq93zqcps86xwl2p6udm7cqz2awcyplly46u3l70dem8fxfljg7u9rhupgwccw8q8z5j5qqqgqqqqqzqqqqqqsqqqqqqqq5qqqqqqygpq9yjvvsdlxk3x4ukdaeufa09y9r99crap7l9ezaj5ygqc",
            "w9upurq6rpcuqu2j2sqqpqqqqqqgqqqqqzqqzqqqqq9sqqqqqqqqmkdau4",
        ]
        testhash = "hlwjxjx550k4nnfdl5py2tn3vnh6g60slnw5dmld6ktrkkz200as49spg5"
        self.assertEqual(enc_hash, testhash)
        self.assertEqual(enc, "".join(testres))

        # Test by instantiating a BCURSingle object
        bcur_single_obj = BCURSingle(text_b64=psbt_b64)
        self.assertEqual(bcur_single_obj.enc_hash, enc_hash)
        self.assertEqual(bcur_single_obj.encoded, enc)
        self.assertEqual(bcur_single_obj.text_b64, psbt_b64)
        self.assertEqual(
            bcur_single_obj.encode(use_checksum=True), f"ur:bytes/{enc_hash}/{enc}"
        )
        self.assertEqual(bcur_single_obj.encode(use_checksum=False), f"ur:bytes/{enc}")

        # Re-instantiate this object from the encoded version
        bcur_single_obj_2 = BCURSingle.parse(to_parse=f"ur:bytes/{enc}")
        self.assertEqual(bcur_single_obj.encode(), bcur_single_obj_2.encode())

        # Make it into a multi:
        expected_multi = []
        for cnt, res in enumerate(testres):
            expected_multi.append(f"ur:bytes/{cnt+1}of{len(testres)}/{testhash}/{res}")
        bcur_multi_obj = BCURMulti.parse(to_parse=expected_multi)
        self.assertEqual(bcur_multi_obj.text_b64, psbt_b64)


class BCURMultiTest(TestCase):
    def test_single_frame_qrgif(self):
        chunks = BCURMulti(text_b64=b64encode(b"foo")).encode(animate=False)
        self.assertEqual(len(chunks), 1)
        self.assertEqual(
            chunks[0],
            "ur:bytes/1of1/j7snj9l0tttmp4c0d9d9mdz0frkac8s6fz4cn8erca3nxz0cnjuq7fv7lv/gdnx7mc0p7099",
        )

    def test_bcur_multi_encoding_decoding(self):
        psbt_b64 = "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"

        chunks_calculated = BCURMulti(text_b64=psbt_b64).encode(
            max_size_per_chunk=300, animate=True
        )
        checksum_expected = "qud9jpcv0af7refxxwu7dvhqshmct65hdzjkpu9q85hw7vkmvshqs2snsx"
        chunks_expected = [
            "tyrukurnvf607qgqe5pqqqqqqsdasdzvck45x4ktrm5jg8nqvuxazw4zhrupuz5y63c9x32c8z7l7qqqqqqqpl0llll6uhht2jztjuekypk9gdsu307alw37afyjd2dzmzhue0g30634fyqqqqqqqq8allll7xd6tl5y20ta4k3wd9382m0kmfw4y5fp35c74rgjszstk72vqp08qqqqqqqqlhlllluhse9w6m4zy0h0t3c6slp6m6qxld8283t0fj2h3qrycf20g2dpfyqsqqqqqr7lllllq8y3",
            "2qqqqqqqqqqkqq2dvue6qn8ep555djamy6vxr9kfk8sx3vssqqqqqqqqzqfts5yqqqqqqqqqqgsqyrzmapaunvc7smex3stl7ygs94tyy3e5mwue7jm6yknxheu9wuaquqg93dgjzq3at9hf286k8gsv23t7a8wuezqcxmnrylf2qjgrgkrjz9e684sktsss9jfyeuqcr7zwmf8h3xcdvg2c92vz64dxkzr49tswx9vhx2y5myqayypd7pseq3autesaqjnd9axjhdjajygth8es7ulpcpnwa8x9",
            "u3ctfqppq0f5svtqyhxl6jz8atxdk3lxrk4elgx9jduwgzdl4m5zqmj99eytg49wygrqy02ed6237436yrz52lhfmhxgsxpkuce862syjq69sus3ww3av9jurnmaqsysxqqqpqqpqqqgqqqqqzqqyqqqsqqsqqqqqgqqqqpzqcpvjfx0qxqlsnk6faufkrtzzkp2nqk4tf4ssaf2ur33t9ej39xeq8gu8ffttnfsqqqgqqgqqzqqqqqqsqpqqqyqqyqqqqqzqqqqqgsxqt0svxgy00z7v8gy5mf0",
            "f54mvhv3zzae7v8h8cwqvmhfe30ywz6gq8qjnq8w6vqqqzqqzqqqsqqqqqyqqgqqpqqpqqqqqqsqqqqzypsr6dyrzcp9eh75s3l2end50esa4w06p3vn0rjqn0awaqsxu3fwfz6pe37svj9rqqqqsqqsqqyqqqqqpqqzqqqgqqgqqqqqyqqqqqqqzqftxvpsqqqqqqqqqgsqypxkj40yu9s24vm9nxfq7qav6j6c3yepwc9rf0jscx7v38tafrz2zqg93dgjzq3k5m85y4xg9y9pdrk2kjhwwugp",
            "356ha2r32jjmtl4fakd6acjctcssx40vzqqu9383mn3da9qtat9aed7hw3s5q2q6j2psqz4yd5j36333yypcx0tw03qjzxq0k7gcpdu2q4e6647znxp97x85na559jeck6lsyw3pqw57xswr9ky8qurpz4zreutrhlpa9ksv4pg452ducxjsp3julv3mk49wygrqyd4xeap9fjpfpgtgaj454mnhzqvdx4l2su255k6la20dnwhwykz7rnraqey2xqqqpqqpqqqgqqqqqzqqyqqqsqqsqqqqqqqq",
            "qqpzqcp4tmqsq8pvfuwuut0fgzl2e0wt04m5v9qzsx5jsvqq4frdy5w5vvgu8ffttnfsqqqgqqgqqzqqqqqqsqpqqqyqqyqqqqqqqqqqqgsxqwpn6mnugys3srahjxqt0zs9wwk40s5esf033ayld9pvkw9khupr58qjnq8w6vqqqzqqzqqqsqqqqqyqqgqqpqqpqqqqqqqqqqqzypsr4835rsed3pc8qcg4gs70zcalc0fd5r9g29dzn0xp55qvvh8mywa3ea7sgzgrqqqqsqqsqqyqqqqqpqqz",
            "qqqgqqgqqqqqqqqqqqqqzqft6qrsqqqqqqqqqgsqyzqy6gtmryq99fyjde5t85de57w4umkv3j8uc0m3q02pptqaffpxjqg93dgjzq4n6tcd2vnpsc97224c3hvrqenhttjklaclcflytu95mu3qqg7kzgss9hfmns4pg59ud6pnwumygpfpzlex6lxvga2rtq6xh3wyzpkat698yypsfq9w7rfvl7qefnmynmqc2p7vwnqgpvalusrjk27k50a579sxy6ppqwwfasmz9l0lvsx5xa0kunyla7uk",
            "cczppesja3qz3vgvr260uw8sx49wygrq9v7j7r2nycvxp0jj4wydmqcxva66u4hlw87z0ezlpdxlygqz84sjrnraqey2xqqqpqqpqqqgqqqqqzqqyqqqsqqqqqqqq5qqqqpzqcpd6wuu9g29p0rwsvmhxezq2ggh7fkhenz82s6cx34ut3qsdh273fcu7lgypypsqqqgqqgqqzqqqqqqsqpqqqyqqqqqqqq9qqqqqgsxqvzgpths6t8lsx2v7ey7cxzs0nr5czqt80lyqu4jh44rld83vp3xs8p6",
            "226u6vqqqzqqzqqqsqqqqqyqqgqqpqqqqqqqqpgqqqqzypsrnj0vxc30mlmyp4phtahye8l0h9kxqsgwvyhvgq5tzrq6knlr3up3cy5cpmknqqqqsqqsqqyqqqqqpqqzqqqgqqqqqqqq2qqqqqqqzqftaqpsqqqqqqqqqgsqyp7l65xe5xlkjqtedv8qxykzhjdg00kayjzxc0rnm2kp3kxcmkz6xqg93dgjzq3ke5mu4gfxzhp8vnzchxhptpjztzwm3fjwvd85m9v864plvglwr5ss93q68nq6",
            "5f33gsgqxgw760vljprc5shklwhkklr7xulh4lqnpchdyype2cej0zs0wuzkmmjyzzhdj6pehskmdfyvtn643usf32d7v4hquzppqwvhggjan6vcftzxwjwswuctvwwfeg5kehk48qujp88amtsy3004j49wygrqydkdxl92zfs4cfmyck9e4c2cvsjcnku2vnnrfaxetp74g0mz8msarnmaqsysxqqqpqqpqqqgqqqqqzqqyqqqsqqqqqqqqvqqqqpzqcpvgx3ucx4zvv2yzqpjrhknm8usg79y",
            "9ahm4a4hcl3h8aa0cycw9mguz2vqamfsqqqgqqgqqzqqqqqqsqpqqqyqqqqqqqqrqqqqqgsxqw2kxvnc5rmhq4k7u3qs4mvkswdu9km2frzu74v0yzv2n0n9dc8qs8x86pjg5vqqqzqqzqqqsqqqqqyqqgqqpqqqqqqqqqcqqqqzypsrn96zyhv7nxz2c3n5n5rhxzmrnjw299kda4fc8ysfelw6upytmav3cwjjkhxnqqqqsqqsqqyqqqqqpqqzqqqgqqqqqqqqxqqqqqqqqw35949",
        ]
        for cnt, chunk in enumerate(chunks_calculated):
            self.assertEqual(
                f"ur:bytes/{cnt+1}of{len(chunks_calculated)}/{checksum_expected}/{chunks_expected[cnt]}",
                chunk,
            )

        bcur_multi_obj = BCURMulti.parse(to_parse=chunks_calculated)
        self.assertEqual(bcur_multi_obj.text_b64, psbt_b64)
        self.assertEqual(bcur_multi_obj.encoded, "".join(chunks_expected))
        self.assertEqual(bcur_multi_obj.enc_hash, checksum_expected)


class ParseTest(TestCase):
    def setUp(self):
        self.GOOD_CHECKSUM = (
            "qud9jpcv0af7refxxwu7dvhqshmct65hdzjkpu9q85hw7vkmvshqs2snsx"
        )
        self.GOOD_ENCODED = "tyrukurnvf607qgqe5pqqqqqqsdasdzvck45x4ktrm5jg8nqvuxazw4zhrupuz5y63c9x32c8z7l7qqqqqqqpl0llll6uhht2jztjuekypk9gdsu307alw37afyjd2dzmzhue0g30634fyqqqqqqqq8allll7xd6tl5y20ta4k3wd9382m0kmfw4y5fp35c74rgjszstk72vqp08qqqqqqqqlhlllluhse9w6m4zy0h0t3c6slp6m6qxld8283t0fj2h3qrycf20g2dpfyqsqqqqqr7lllllq8y3"

    def test_valid_bcur_parse_single_yeschecksum(self):
        bcur_string = f"ur:bytes/{self.GOOD_CHECKSUM}/{self.GOOD_ENCODED}"
        payload_parsed, checksum_parsed, x, y = _parse_bcur_helper(bcur_string)
        self.assertEqual(x, 1)
        self.assertEqual(y, 1)
        self.assertEqual(checksum_parsed, self.GOOD_CHECKSUM)
        self.assertEqual(payload_parsed, self.GOOD_ENCODED)

    def test_valid_bcur_parse_single_nochecksum(self):
        bcur_string = f"ur:bytes/{self.GOOD_ENCODED}"
        payload_parsed, checksum_parsed, x, y = _parse_bcur_helper(bcur_string)
        self.assertEqual(x, 1)
        self.assertEqual(y, 1)
        self.assertEqual(checksum_parsed, None)
        self.assertEqual(payload_parsed, self.GOOD_ENCODED)

    def test_valid_bcur_parse_multi(self):
        bcur_string = f"ur:bytes/2of8/{self.GOOD_CHECKSUM}/{self.GOOD_ENCODED}"
        payload_parsed, checksum_parsed, x, y = _parse_bcur_helper(bcur_string)
        self.assertEqual(x, 2)
        self.assertEqual(y, 8)
        self.assertEqual(checksum_parsed, self.GOOD_CHECKSUM)
        self.assertEqual(payload_parsed, self.GOOD_ENCODED)

    def test_invalid_bcur_parse(self):
        with self.assertRaises(BCURStringFormatError):
            _parse_bcur_helper("fail")

        with self.assertRaises(BCURStringFormatError):
            _parse_bcur_helper("ur:bytes/1/2/3")

        with self.assertRaises(BCURStringFormatError):
            _parse_bcur_helper("ur:bytes/foo")

        with self.assertRaises(BCURStringFormatError):
            _parse_bcur_helper("ur:bytes/gd56dxsyew2w5/foo")


class BCURSingleTest(TestCase):
    def test_simple_bcur(self):
        """ 1of1 with and without checksum """

        # Basic test
        bcur_single_obj = BCURSingle(text_b64="aaaa")
        self.assertEqual(
            bcur_single_obj.enc_hash,
            "ysypyck5etagxt08hzn6vcnwam3lgupp0uhcs7n8pg0wmen32p3qate5eg",
        )
        self.assertEqual(bcur_single_obj.encoded, "gd56dxsyew2w5")

        # Render with and without checksum
        bcur_single_checksum = "ur:bytes/ysypyck5etagxt08hzn6vcnwam3lgupp0uhcs7n8pg0wmen32p3qate5eg/gd56dxsyew2w5"
        bcur_single_nochecksum = "ur:bytes/gd56dxsyew2w5"
        self.assertEqual(
            bcur_single_obj.encode(use_checksum=True), bcur_single_checksum
        )
        self.assertEqual(
            bcur_single_obj.encode(use_checksum=False), bcur_single_nochecksum
        )

        # Reconstruct from bcur string with checksum
        bcur_single_reconstructed_v1 = BCURSingle.parse(to_parse=bcur_single_checksum)
        self.assertEqual(
            bcur_single_reconstructed_v1.encode(use_checksum=True), bcur_single_checksum
        )
        self.assertEqual(
            bcur_single_reconstructed_v1.encode(use_checksum=False),
            bcur_single_nochecksum,
        )

        # Reconstruct from bcur string without checksum
        bcur_single_reconstructed_v2 = BCURSingle.parse(to_parse=bcur_single_nochecksum)
        self.assertEqual(
            bcur_single_reconstructed_v2.encode(use_checksum=True), bcur_single_checksum
        )
        self.assertEqual(
            bcur_single_reconstructed_v2.encode(use_checksum=False),
            bcur_single_nochecksum,
        )


class BCURDecodeTest(TestCase):
    def test_bcur_encode_decode(self):
        # See that encode/decode works
        b64_text = b64encode(b"foo")
        raw = a2b_base64(b64_text)
        enc, enc_hash = bcur_encode(raw)
        dec = bcur_decode(enc, checksum=enc_hash)
        self.assertEqual(dec, raw)

        # Confirm bad hash raises an error
        with self.assertRaises(ValueError):
            bcur_decode(enc, checksum=enc_hash + "fail")
