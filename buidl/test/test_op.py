from io import BytesIO

from buidl.op import (
    decode_num,
    encode_num,
    encode_minimal_num,
    number_to_op_code,
    number_to_op_code_byte,
    op_code_to_number,
    op_0,
    op_1,
    op_1negate,
    op_add,
    op_sub,
    op_1add,
    op_1sub,
    op_negate,
    op_abs,
    op_not,
    op_0notequal,
    op_booland,
    op_boolor,
    op_numequal,
    op_numequalverify,
    op_numnotequal,
    op_lessthan,
    op_greaterthan,
    op_lessthanorequal,
    op_greaterthanorequal,
    op_min,
    op_max,
    op_within,
    op_equal,
    op_equalverify,
    op_dup,
    op_2dup,
    op_3dup,
    op_drop,
    op_2drop,
    op_swap,
    op_rot,
    op_over,
    op_2over,
    op_2rot,
    op_2swap,
    op_nip,
    op_tuck,
    op_pick,
    op_roll,
    op_ifdup,
    op_depth,
    op_size,
    op_toaltstack,
    op_fromaltstack,
    op_verify,
    op_return,
    op_nop,
    op_if,
    op_notif,
    op_ripemd160,
    op_sha1,
    op_sha256,
    op_hash160,
    op_hash256,
    op_checklocktimeverify,
    op_checkmultisig,
    op_checksequenceverify,
    op_checksig,
)
from buidl.script import Script
from buidl.timelock import Locktime, Sequence
from buidl.tx import Tx, TxIn, TxOut

from buidl.test import OfflineTestCase


class EncodeDecodeNumTest(OfflineTestCase):
    def test_zero(self):
        self.assertEqual(encode_num(0), b"")
        self.assertEqual(decode_num(b""), 0)

    def test_positive_small(self):
        self.assertEqual(decode_num(encode_num(1)), 1)
        self.assertEqual(decode_num(encode_num(127)), 127)

    def test_positive_boundary(self):
        # 128 requires extra byte because top bit is sign bit
        encoded = encode_num(128)
        self.assertEqual(encoded, b"\x80\x00")
        self.assertEqual(decode_num(encoded), 128)

    def test_positive_large(self):
        self.assertEqual(decode_num(encode_num(255)), 255)
        self.assertEqual(decode_num(encode_num(256)), 256)
        self.assertEqual(decode_num(encode_num(1000)), 1000)
        self.assertEqual(decode_num(encode_num(65535)), 65535)

    def test_negative_small(self):
        self.assertEqual(decode_num(encode_num(-1)), -1)
        self.assertEqual(decode_num(encode_num(-127)), -127)

    def test_negative_boundary(self):
        encoded = encode_num(-128)
        self.assertEqual(encoded, b"\x80\x80")
        self.assertEqual(decode_num(encoded), -128)

    def test_negative_large(self):
        self.assertEqual(decode_num(encode_num(-255)), -255)
        self.assertEqual(decode_num(encode_num(-1000)), -1000)

    def test_roundtrip(self):
        for n in range(-1000, 1001):
            self.assertEqual(decode_num(encode_num(n)), n)


class NumberToOpCodeTest(OfflineTestCase):
    def test_number_to_op_code(self):
        self.assertEqual(number_to_op_code(0), 0)
        self.assertEqual(number_to_op_code(1), 81)
        self.assertEqual(number_to_op_code(16), 96)
        self.assertEqual(number_to_op_code(-1), 79)

    def test_number_to_op_code_invalid(self):
        with self.assertRaises(ValueError):
            number_to_op_code(-2)
        with self.assertRaises(ValueError):
            number_to_op_code(17)

    def test_number_to_op_code_byte(self):
        self.assertEqual(number_to_op_code_byte(0), b"\x00")
        self.assertEqual(number_to_op_code_byte(1), b"\x51")
        self.assertEqual(number_to_op_code_byte(16), b"\x60")
        self.assertEqual(number_to_op_code_byte(-1), b"\x4f")

    def test_op_code_to_number(self):
        self.assertEqual(op_code_to_number(0), 0)
        self.assertEqual(op_code_to_number(81), 1)
        self.assertEqual(op_code_to_number(96), 16)
        self.assertEqual(op_code_to_number(79), -1)

    def test_op_code_to_number_invalid(self):
        with self.assertRaises(ValueError):
            op_code_to_number(1)
        with self.assertRaises(ValueError):
            op_code_to_number(78)

    def test_encode_minimal_num(self):
        # -1 to 16 should return op codes
        for n in range(-1, 17):
            self.assertEqual(encode_minimal_num(n), number_to_op_code(n))
        # outside range should return encode_num
        self.assertEqual(encode_minimal_num(17), encode_num(17))
        self.assertEqual(encode_minimal_num(-2), encode_num(-2))


class StackOpTest(OfflineTestCase):
    def test_op_dup(self):
        stack = [b"\x01"]
        self.assertTrue(op_dup(stack))
        self.assertEqual(stack, [b"\x01", b"\x01"])

    def test_op_dup_empty(self):
        self.assertFalse(op_dup([]))

    def test_op_2dup(self):
        stack = [b"\x01", b"\x02"]
        self.assertTrue(op_2dup(stack))
        self.assertEqual(stack, [b"\x01", b"\x02", b"\x01", b"\x02"])

    def test_op_3dup(self):
        stack = [b"\x01", b"\x02", b"\x03"]
        self.assertTrue(op_3dup(stack))
        self.assertEqual(len(stack), 6)

    def test_op_drop(self):
        stack = [b"\x01", b"\x02"]
        self.assertTrue(op_drop(stack))
        self.assertEqual(stack, [b"\x01"])

    def test_op_2drop(self):
        stack = [b"\x01", b"\x02", b"\x03"]
        self.assertTrue(op_2drop(stack))
        self.assertEqual(stack, [b"\x01"])

    def test_op_swap(self):
        stack = [b"\x01", b"\x02"]
        self.assertTrue(op_swap(stack))
        self.assertEqual(stack, [b"\x02", b"\x01"])

    def test_op_rot(self):
        stack = [b"\x01", b"\x02", b"\x03"]
        self.assertTrue(op_rot(stack))
        self.assertEqual(stack, [b"\x02", b"\x03", b"\x01"])

    def test_op_over(self):
        stack = [b"\x01", b"\x02"]
        self.assertTrue(op_over(stack))
        self.assertEqual(stack, [b"\x01", b"\x02", b"\x01"])

    def test_op_2over(self):
        stack = [b"\x01", b"\x02", b"\x03", b"\x04"]
        self.assertTrue(op_2over(stack))
        self.assertEqual(stack, [b"\x01", b"\x02", b"\x03", b"\x04", b"\x01", b"\x02"])

    def test_op_2rot(self):
        stack = [b"\x01", b"\x02", b"\x03", b"\x04", b"\x05", b"\x06"]
        self.assertTrue(op_2rot(stack))
        self.assertEqual(len(stack), 8)
        self.assertEqual(stack[-2:], [b"\x01", b"\x02"])

    def test_op_2swap(self):
        stack = [b"\x01", b"\x02", b"\x03", b"\x04"]
        self.assertTrue(op_2swap(stack))
        self.assertEqual(stack, [b"\x03", b"\x04", b"\x01", b"\x02"])

    def test_op_nip(self):
        stack = [b"\x01", b"\x02"]
        self.assertTrue(op_nip(stack))
        self.assertEqual(stack, [b"\x02"])

    def test_op_tuck(self):
        stack = [b"\x01", b"\x02"]
        self.assertTrue(op_tuck(stack))
        self.assertEqual(stack, [b"\x02", b"\x01", b"\x02"])

    def test_op_pick(self):
        stack = [b"\x01", b"\x02", b"\x03", encode_num(2)]
        self.assertTrue(op_pick(stack))
        self.assertEqual(stack[-1], b"\x01")

    def test_op_roll(self):
        stack = [b"\x01", b"\x02", b"\x03", encode_num(2)]
        self.assertTrue(op_roll(stack))
        self.assertEqual(stack, [b"\x02", b"\x03", b"\x01"])

    def test_op_ifdup_nonzero(self):
        stack = [encode_num(1)]
        self.assertTrue(op_ifdup(stack))
        self.assertEqual(len(stack), 2)

    def test_op_ifdup_zero(self):
        stack = [encode_num(0)]
        self.assertTrue(op_ifdup(stack))
        self.assertEqual(len(stack), 1)

    def test_op_depth(self):
        stack = [b"\x01", b"\x02", b"\x03"]
        self.assertTrue(op_depth(stack))
        self.assertEqual(decode_num(stack[-1]), 3)

    def test_op_size(self):
        stack = [b"\x01\x02\x03"]
        self.assertTrue(op_size(stack))
        self.assertEqual(decode_num(stack[-1]), 3)

    def test_op_toaltstack_fromaltstack(self):
        stack = [b"\x01", b"\x02"]
        altstack = []
        self.assertTrue(op_toaltstack(stack, altstack))
        self.assertEqual(stack, [b"\x01"])
        self.assertEqual(altstack, [b"\x02"])
        self.assertTrue(op_fromaltstack(stack, altstack))
        self.assertEqual(stack, [b"\x01", b"\x02"])
        self.assertEqual(altstack, [])

    def test_op_fromaltstack_empty(self):
        self.assertFalse(op_fromaltstack([], []))


class ArithmeticOpTest(OfflineTestCase):
    def test_op_add(self):
        stack = [encode_num(2), encode_num(3)]
        self.assertTrue(op_add(stack))
        self.assertEqual(decode_num(stack[0]), 5)

    def test_op_add_negative(self):
        stack = [encode_num(-5), encode_num(3)]
        self.assertTrue(op_add(stack))
        self.assertEqual(decode_num(stack[0]), -2)

    def test_op_sub(self):
        stack = [encode_num(5), encode_num(3)]
        self.assertTrue(op_sub(stack))
        self.assertEqual(decode_num(stack[0]), 2)

    def test_op_1add(self):
        stack = [encode_num(5)]
        self.assertTrue(op_1add(stack))
        self.assertEqual(decode_num(stack[0]), 6)

    def test_op_1sub(self):
        stack = [encode_num(5)]
        self.assertTrue(op_1sub(stack))
        self.assertEqual(decode_num(stack[0]), 4)

    def test_op_negate(self):
        stack = [encode_num(5)]
        self.assertTrue(op_negate(stack))
        self.assertEqual(decode_num(stack[0]), -5)
        stack = [encode_num(-3)]
        self.assertTrue(op_negate(stack))
        self.assertEqual(decode_num(stack[0]), 3)

    def test_op_abs(self):
        stack = [encode_num(-5)]
        self.assertTrue(op_abs(stack))
        self.assertEqual(decode_num(stack[0]), 5)
        stack = [encode_num(5)]
        self.assertTrue(op_abs(stack))
        self.assertEqual(decode_num(stack[0]), 5)

    def test_op_not(self):
        stack = [encode_num(0)]
        self.assertTrue(op_not(stack))
        self.assertEqual(decode_num(stack[0]), 1)
        stack = [encode_num(5)]
        self.assertTrue(op_not(stack))
        self.assertEqual(decode_num(stack[0]), 0)

    def test_op_0notequal(self):
        stack = [encode_num(0)]
        self.assertTrue(op_0notequal(stack))
        self.assertEqual(decode_num(stack[0]), 0)
        stack = [encode_num(5)]
        self.assertTrue(op_0notequal(stack))
        self.assertEqual(decode_num(stack[0]), 1)

    def test_op_booland(self):
        stack = [encode_num(1), encode_num(1)]
        self.assertTrue(op_booland(stack))
        self.assertEqual(decode_num(stack[0]), 1)
        stack = [encode_num(1), encode_num(0)]
        self.assertTrue(op_booland(stack))
        self.assertEqual(decode_num(stack[0]), 0)

    def test_op_boolor(self):
        stack = [encode_num(0), encode_num(0)]
        self.assertTrue(op_boolor(stack))
        self.assertEqual(decode_num(stack[0]), 0)
        stack = [encode_num(1), encode_num(0)]
        self.assertTrue(op_boolor(stack))
        self.assertEqual(decode_num(stack[0]), 1)

    def test_op_numequal(self):
        stack = [encode_num(5), encode_num(5)]
        self.assertTrue(op_numequal(stack))
        self.assertEqual(decode_num(stack[0]), 1)
        stack = [encode_num(5), encode_num(4)]
        self.assertTrue(op_numequal(stack))
        self.assertEqual(decode_num(stack[0]), 0)

    def test_op_numnotequal(self):
        stack = [encode_num(5), encode_num(4)]
        self.assertTrue(op_numnotequal(stack))
        self.assertEqual(decode_num(stack[0]), 1)
        stack = [encode_num(5), encode_num(5)]
        self.assertTrue(op_numnotequal(stack))
        self.assertEqual(decode_num(stack[0]), 0)

    def test_op_lessthan(self):
        stack = [encode_num(3), encode_num(5)]
        self.assertTrue(op_lessthan(stack))
        self.assertEqual(decode_num(stack[0]), 1)
        stack = [encode_num(5), encode_num(3)]
        self.assertTrue(op_lessthan(stack))
        self.assertEqual(decode_num(stack[0]), 0)

    def test_op_greaterthan(self):
        stack = [encode_num(5), encode_num(3)]
        self.assertTrue(op_greaterthan(stack))
        self.assertEqual(decode_num(stack[0]), 1)
        stack = [encode_num(3), encode_num(5)]
        self.assertTrue(op_greaterthan(stack))
        self.assertEqual(decode_num(stack[0]), 0)

    def test_op_lessthanorequal(self):
        stack = [encode_num(5), encode_num(5)]
        self.assertTrue(op_lessthanorequal(stack))
        self.assertEqual(decode_num(stack[0]), 1)

    def test_op_greaterthanorequal(self):
        stack = [encode_num(5), encode_num(5)]
        self.assertTrue(op_greaterthanorequal(stack))
        self.assertEqual(decode_num(stack[0]), 1)

    def test_op_min(self):
        stack = [encode_num(3), encode_num(5)]
        self.assertTrue(op_min(stack))
        self.assertEqual(decode_num(stack[0]), 3)

    def test_op_max(self):
        stack = [encode_num(3), encode_num(5)]
        self.assertTrue(op_max(stack))
        self.assertEqual(decode_num(stack[0]), 5)

    def test_op_within(self):
        # 3 is within [2, 5)
        stack = [encode_num(3), encode_num(2), encode_num(5)]
        self.assertTrue(op_within(stack))
        self.assertEqual(decode_num(stack[0]), 1)
        # 5 is NOT within [2, 5) (exclusive upper bound)
        stack = [encode_num(5), encode_num(2), encode_num(5)]
        self.assertTrue(op_within(stack))
        self.assertEqual(decode_num(stack[0]), 0)

    def test_insufficient_stack(self):
        self.assertFalse(op_add([encode_num(1)]))
        self.assertFalse(op_sub([]))
        self.assertFalse(op_1add([]))
        self.assertFalse(op_negate([]))
        self.assertFalse(op_lessthan([encode_num(1)]))


class EqualOpTest(OfflineTestCase):
    def test_op_equal_true(self):
        stack = [b"\x01\x02", b"\x01\x02"]
        self.assertTrue(op_equal(stack))
        self.assertEqual(decode_num(stack[0]), 1)

    def test_op_equal_false(self):
        stack = [b"\x01", b"\x02"]
        self.assertTrue(op_equal(stack))
        self.assertEqual(decode_num(stack[0]), 0)

    def test_op_equalverify_true(self):
        stack = [b"\x01", b"\x01"]
        self.assertTrue(op_equalverify(stack))
        self.assertEqual(len(stack), 0)

    def test_op_equalverify_false(self):
        stack = [b"\x01", b"\x02"]
        self.assertFalse(op_equalverify(stack))


class CryptoOpTest(OfflineTestCase):
    def test_op_hash160(self):
        stack = [b"hello world"]
        self.assertTrue(op_hash160(stack))
        self.assertEqual(stack[0].hex(), "d7d5ee7824ff93f94c3055af9382c86c68b5ca92")

    def test_op_sha256(self):
        stack = [b""]
        self.assertTrue(op_sha256(stack))
        self.assertEqual(
            stack[0].hex(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        )

    def test_op_sha1(self):
        stack = [b""]
        self.assertTrue(op_sha1(stack))
        self.assertEqual(stack[0].hex(), "da39a3ee5e6b4b0d3255bfef95601890afd80709")

    def test_op_ripemd160(self):
        stack = [b""]
        self.assertTrue(op_ripemd160(stack))
        self.assertEqual(stack[0].hex(), "9c1185a5c5e9fc54612808977ee8f548b2258d31")

    def test_op_hash256(self):
        stack = [b""]
        self.assertTrue(op_hash256(stack))
        # hash256 = sha256(sha256(x))
        self.assertEqual(len(stack[0]), 32)

    def test_crypto_ops_empty_stack(self):
        self.assertFalse(op_sha256([]))
        self.assertFalse(op_sha1([]))
        self.assertFalse(op_ripemd160([]))
        self.assertFalse(op_hash160([]))
        self.assertFalse(op_hash256([]))


class FlowControlTest(OfflineTestCase):
    def test_op_verify_true(self):
        stack = [encode_num(1)]
        self.assertTrue(op_verify(stack))

    def test_op_verify_false(self):
        stack = [encode_num(0)]
        self.assertFalse(op_verify(stack))

    def test_op_verify_empty(self):
        self.assertFalse(op_verify([]))

    def test_op_return(self):
        self.assertFalse(op_return([]))

    def test_op_nop(self):
        self.assertTrue(op_nop([]))

    def test_op_numequalverify_true(self):
        stack = [encode_num(5), encode_num(5)]
        self.assertTrue(op_numequalverify(stack))

    def test_op_numequalverify_false(self):
        stack = [encode_num(5), encode_num(4)]
        self.assertFalse(op_numequalverify(stack))


class PushNumberTest(OfflineTestCase):
    def test_op_0(self):
        stack = []
        self.assertTrue(op_0(stack))
        self.assertEqual(decode_num(stack[0]), 0)

    def test_op_1(self):
        stack = []
        self.assertTrue(op_1(stack))
        self.assertEqual(decode_num(stack[0]), 1)

    def test_op_1negate(self):
        stack = []
        self.assertTrue(op_1negate(stack))
        self.assertEqual(decode_num(stack[0]), -1)


class OpTest(OfflineTestCase):
    def test_op_checksig(self):
        tests = (
            (
                "010000000148dcc16482f5c835828020498ec1c35f48a578585721b5a77445a4ce93334d18000000006a4730440220636b9f822ea2f85e6375ecd066a49cc74c20ec4f7cf0485bebe6cc68da92d8ce022068ae17620b12d99353287d6224740b585ff89024370a3212b583fb454dce7c160121021f955d36390a38361530fb3724a835f4f504049492224a028fb0ab8c063511a7ffffffff0220960705000000001976a914d23541bd04c58a1265e78be912e63b2557fb439088aca0860100000000001976a91456d95dc3f2414a210efb7188d287bff487df96c688ac00000000",
                "30440220636b9f822ea2f85e6375ecd066a49cc74c20ec4f7cf0485bebe6cc68da92d8ce022068ae17620b12d99353287d6224740b585ff89024370a3212b583fb454dce7c1601",
                "021f955d36390a38361530fb3724a835f4f504049492224a028fb0ab8c063511a7",
                "testnet",
            ),
            (
                "01000000000101e92e1c1d29218348f8ec9463a9fc94670f675a7f82ae100f3e8a5cbd63b4192e0100000017160014d52ad7ca9b3d096a38e752c2018e6fbc40cdf26fffffffff014c400f00000000001976a9146e13971913b9aa89659a9f53d327baa8826f2d7588ac0247304402205e3ae5ac9a0e0a16ae04b0678c5732973ce31051ba9f42193e69843e600d84f2022060a91cbd48899b1bf5d1ffb7532f69ab74bc1701a253a415196b38feb599163b012103935581e52c354cd2f484fe8ed83af7a3097005b2f9c60bff71d35bd795f54b6700000000",
                "304402205e3ae5ac9a0e0a16ae04b0678c5732973ce31051ba9f42193e69843e600d84f2022060a91cbd48899b1bf5d1ffb7532f69ab74bc1701a253a415196b38feb599163b01",
                "03935581e52c354cd2f484fe8ed83af7a3097005b2f9c60bff71d35bd795f54b67",
                "testnet",
            ),
            (
                "0200000000010140d43a99926d43eb0e619bf0b3d83b4a31f60c176beecfb9d35bf45e54d0f7420100000017160014a4b4ca48de0b3fffc15404a1acdc8dbaae226955ffffffff0100e1f5050000000017a9144a1154d50b03292b3024370901711946cb7cccc387024830450221008604ef8f6d8afa892dee0f31259b6ce02dd70c545cfcfed8148179971876c54a022076d771d6e91bed212783c9b06e0de600fab2d518fad6f15a2b191d7fbd262a3e0121039d25ab79f41f75ceaf882411fd41fa670a4c672c23ffaf0e361a969cde0692e800000000",
                "30450221008604ef8f6d8afa892dee0f31259b6ce02dd70c545cfcfed8148179971876c54a022076d771d6e91bed212783c9b06e0de600fab2d518fad6f15a2b191d7fbd262a3e01",
                "039d25ab79f41f75ceaf882411fd41fa670a4c672c23ffaf0e361a969cde0692e8",
                "mainnet",
            ),
        )
        for raw_tx, sig_hex, sec_hex, network in tests:
            tx_obj = Tx.parse(BytesIO(bytes.fromhex(raw_tx)), network=network)
            sec = bytes.fromhex(sec_hex)
            sig = bytes.fromhex(sig_hex)
            stack = [sig, sec]
            self.assertTrue(op_checksig(stack, tx_obj, 0))
            self.assertEqual(decode_num(stack[0]), 1)

    def test_op_checkmultisig(self):
        raw_tx = "0100000001868278ed6ddfb6c1ed3ad5f8181eb0c7a385aa0836f01d5e4789e6bd304d87221a000000db00483045022100dc92655fe37036f47756db8102e0d7d5e28b3beb83a8fef4f5dc0559bddfb94e02205a36d4e4e6c7fcd16658c50783e00c341609977aed3ad00937bf4ee942a8993701483045022100da6bee3c93766232079a01639d07fa869598749729ae323eab8eef53577d611b02207bef15429dcadce2121ea07f233115c6f09034c0be68db99980b9a6c5e75402201475221022626e955ea6ea6d98850c994f9107b036b1334f18ca8830bfff1295d21cfdb702103b287eaf122eea69030a0e9feed096bed8045c8b98bec453e1ffac7fbdbd4bb7152aeffffffff04d3b11400000000001976a914904a49878c0adfc3aa05de7afad2cc15f483a56a88ac7f400900000000001976a914418327e3f3dda4cf5b9089325a4b95abdfa0334088ac722c0c00000000001976a914ba35042cfe9fc66fd35ac2224eebdafd1028ad2788acdc4ace020000000017a91474d691da1574e6b3c192ecfb52cc8984ee7b6c568700000000"
        tx_obj = Tx.parse(BytesIO(bytes.fromhex(raw_tx)))
        sig1 = bytes.fromhex(
            "3045022100dc92655fe37036f47756db8102e0d7d5e28b3beb83a8fef4f5dc0559bddfb94e02205a36d4e4e6c7fcd16658c50783e00c341609977aed3ad00937bf4ee942a8993701"
        )
        sig2 = bytes.fromhex(
            "3045022100da6bee3c93766232079a01639d07fa869598749729ae323eab8eef53577d611b02207bef15429dcadce2121ea07f233115c6f09034c0be68db99980b9a6c5e75402201"
        )
        sec1 = bytes.fromhex(
            "022626e955ea6ea6d98850c994f9107b036b1334f18ca8830bfff1295d21cfdb70"
        )
        sec2 = bytes.fromhex(
            "03b287eaf122eea69030a0e9feed096bed8045c8b98bec453e1ffac7fbdbd4bb71"
        )
        stack = [b"", sig1, sig2, b"\x02", sec1, sec2, b"\x02"]
        self.assertTrue(op_checkmultisig(stack, tx_obj, 0))
        self.assertEqual(decode_num(stack[0]), 1)

    def test_op_cltv(self):
        locktime_0 = Locktime(1234)
        locktime_1 = Locktime(2345)
        sequence = Sequence()
        tx_in = TxIn(b"\x00" * 32, 0, sequence=sequence)
        tx_out = TxOut(1, Script())
        tx_obj = Tx(1, [tx_in], [tx_out], locktime_1)
        stack = []
        self.assertFalse(op_checklocktimeverify(stack, tx_obj, 0))
        tx_in.sequence = Sequence(0xFFFFFFFE)
        self.assertFalse(op_checklocktimeverify(stack, tx_obj, 0))
        stack = [encode_num(-5)]
        self.assertFalse(op_checklocktimeverify(stack, tx_obj, 0))
        stack = [encode_num(locktime_0)]
        self.assertTrue(op_checklocktimeverify(stack, tx_obj, 0))
        tx_obj.locktime = Locktime(1582820194)
        self.assertFalse(op_checklocktimeverify(stack, tx_obj, 0))
        tx_obj.locktime = Locktime(500)
        self.assertFalse(op_checklocktimeverify(stack, tx_obj, 0))

    def test_op_csv(self):
        sequence_0 = Sequence()
        sequence_1 = Sequence(2345)
        tx_in = TxIn(b"\x00" * 32, 0, sequence=sequence_0)
        tx_out = TxOut(1, Script())
        tx_obj = Tx(1, [tx_in], [tx_out])
        stack = []
        self.assertFalse(op_checksequenceverify(stack, tx_obj, 0))
        tx_in.sequence = sequence_1
        self.assertFalse(op_checksequenceverify(stack, tx_obj, 0))
        stack = [encode_num(-5)]
        self.assertFalse(op_checksequenceverify(stack, tx_obj, 0))
        tx_obj.version = 2
        self.assertFalse(op_checksequenceverify(stack, tx_obj, 0))
        stack = [encode_num(1234 | (1 << 22))]
        self.assertFalse(op_checksequenceverify(stack, tx_obj, 0))
        stack = [encode_num(9999)]
        self.assertFalse(op_checksequenceverify(stack, tx_obj, 0))
        stack = [encode_num(1234)]
        self.assertTrue(op_checksequenceverify(stack, tx_obj, 0))
