"""Tests to increase coverage for op.py, siphash.py, merkleblock.py, witness.py."""

from unittest import TestCase
from buidl.merkleblock import MerkleBlock, MerkleTree
from buidl.op import (
    decode_num,
    encode_minimal_num,
    encode_num,
    number_to_op_code,
    number_to_op_code_byte,
    op_0notequal,
    op_1add,
    op_1negate,
    op_1sub,
    op_2,
    op_2drop,
    op_2dup,
    op_2over,
    op_2rot,
    op_2swap,
    op_3,
    op_3dup,
    op_4,
    op_5,
    op_6,
    op_7,
    op_8,
    op_9,
    op_10,
    op_11,
    op_12,
    op_13,
    op_14,
    op_15,
    op_16,
    op_abs,
    op_add,
    op_booland,
    op_boolor,
    op_checkmultisigverify,
    op_checksequenceverify,
    op_code_to_number,
    op_depth,
    op_drop,
    op_fromaltstack,
    op_greaterthan,
    op_greaterthanorequal,
    op_hash256,
    op_ifdup,
    op_lessthan,
    op_lessthanorequal,
    op_max,
    op_min,
    op_negate,
    op_nip,
    op_not,
    op_notif,
    op_numequal,
    op_numequalverify,
    op_numnotequal,
    op_over,
    op_pick,
    op_return,
    op_ripemd160,
    op_roll,
    op_rot,
    op_sha1,
    op_sha256,
    op_size,
    op_sub,
    op_success,
    op_swap,
    op_toaltstack,
    op_tuck,
    op_verify,
    op_within,
)
from buidl.siphash import SipHash_2_4
from buidl.witness import Witness


class NumberToOpCodeByteTest(TestCase):
    def test_positive(self):
        self.assertEqual(number_to_op_code_byte(1), bytes([0x51]))
        self.assertEqual(number_to_op_code_byte(16), bytes([0x60]))

    def test_zero(self):
        self.assertEqual(number_to_op_code_byte(0), b"\x00")

    def test_negative_one(self):
        self.assertEqual(number_to_op_code_byte(-1), b"\x4f")

    def test_out_of_range(self):
        with self.assertRaises(ValueError):
            number_to_op_code_byte(17)
        with self.assertRaises(ValueError):
            number_to_op_code_byte(-2)


class NumberToOpCodeTest(TestCase):
    def test_zero(self):
        self.assertEqual(number_to_op_code(0), 0)

    def test_positive(self):
        self.assertEqual(number_to_op_code(1), 81)

    def test_out_of_range(self):
        with self.assertRaises(ValueError):
            number_to_op_code(17)


class OpCodeToNumberTest(TestCase):
    def test_zero(self):
        self.assertEqual(op_code_to_number(0), 0)

    def test_valid(self):
        self.assertEqual(op_code_to_number(81), 1)
        self.assertEqual(op_code_to_number(96), 16)

    def test_invalid(self):
        with self.assertRaises(ValueError):
            op_code_to_number(50)


class EncodeMinimalNumTest(TestCase):
    def test_small(self):
        self.assertEqual(encode_minimal_num(0), 0)
        self.assertEqual(encode_minimal_num(16), 96)
        self.assertEqual(encode_minimal_num(-1), 79)

    def test_large(self):
        result = encode_minimal_num(17)
        self.assertEqual(decode_num(result), 17)


class EncodeNumTest(TestCase):
    def test_negative(self):
        result = encode_num(-1)
        self.assertEqual(decode_num(result), -1)

    def test_negative_top_bit_set(self):
        result = encode_num(-255)
        self.assertEqual(decode_num(result), -255)

    def test_positive_top_bit_set(self):
        result = encode_num(128)
        self.assertEqual(result, b"\x80\x00")
        self.assertEqual(decode_num(result), 128)


class OpPushNumberTest(TestCase):
    """Test all op_N functions that push numbers onto the stack."""

    def test_op_1negate(self):
        stack = []
        self.assertTrue(op_1negate(stack))
        self.assertEqual(decode_num(stack[0]), -1)

    def test_op_2_through_16(self):
        ops = [
            op_2,
            op_3,
            op_4,
            op_5,
            op_6,
            op_7,
            op_8,
            op_9,
            op_10,
            op_11,
            op_12,
            op_13,
            op_14,
            op_15,
            op_16,
        ]
        for i, op in enumerate(ops, 2):
            stack = []
            self.assertTrue(op(stack))
            self.assertEqual(decode_num(stack[0]), i)


class OpVerifyTest(TestCase):
    def test_empty_stack(self):
        self.assertFalse(op_verify([]))

    def test_zero(self):
        self.assertFalse(op_verify([encode_num(0)]))

    def test_nonzero(self):
        self.assertTrue(op_verify([encode_num(1)]))


class OpReturnTest(TestCase):
    def test_returns_false(self):
        self.assertFalse(op_return([]))


class OpAltstackTest(TestCase):
    def test_toaltstack_empty(self):
        self.assertFalse(op_toaltstack([], []))

    def test_toaltstack(self):
        stack = [b"\x01"]
        altstack = []
        self.assertTrue(op_toaltstack(stack, altstack))
        self.assertEqual(altstack, [b"\x01"])
        self.assertEqual(stack, [])

    def test_fromaltstack_empty(self):
        self.assertFalse(op_fromaltstack([], []))

    def test_fromaltstack(self):
        stack = []
        altstack = [b"\x02"]
        self.assertTrue(op_fromaltstack(stack, altstack))
        self.assertEqual(stack, [b"\x02"])


class OpStackManipTest(TestCase):
    def test_2drop(self):
        stack = [b"\x01", b"\x02"]
        self.assertTrue(op_2drop(stack))
        self.assertEqual(stack, [])

    def test_2drop_empty(self):
        self.assertFalse(op_2drop([b"\x01"]))

    def test_2dup(self):
        stack = [b"\x01", b"\x02"]
        self.assertTrue(op_2dup(stack))
        self.assertEqual(len(stack), 4)

    def test_2dup_empty(self):
        self.assertFalse(op_2dup([b"\x01"]))

    def test_3dup(self):
        stack = [b"\x01", b"\x02", b"\x03"]
        self.assertTrue(op_3dup(stack))
        self.assertEqual(len(stack), 6)

    def test_3dup_empty(self):
        self.assertFalse(op_3dup([b"\x01"]))

    def test_2over(self):
        stack = [b"\x01", b"\x02", b"\x03", b"\x04"]
        self.assertTrue(op_2over(stack))
        self.assertEqual(stack[-2:], [b"\x01", b"\x02"])

    def test_2over_empty(self):
        self.assertFalse(op_2over([b"\x01"]))

    def test_2rot(self):
        stack = [b"\x01", b"\x02", b"\x03", b"\x04", b"\x05", b"\x06"]
        self.assertTrue(op_2rot(stack))
        self.assertEqual(stack[-2:], [b"\x01", b"\x02"])

    def test_2rot_empty(self):
        self.assertFalse(op_2rot([b"\x01"]))

    def test_2swap(self):
        stack = [b"\x01", b"\x02", b"\x03", b"\x04"]
        self.assertTrue(op_2swap(stack))
        self.assertEqual(stack, [b"\x03", b"\x04", b"\x01", b"\x02"])

    def test_2swap_empty(self):
        self.assertFalse(op_2swap([b"\x01"]))

    def test_ifdup_nonzero(self):
        stack = [encode_num(5)]
        self.assertTrue(op_ifdup(stack))
        self.assertEqual(len(stack), 2)

    def test_ifdup_zero(self):
        stack = [encode_num(0)]
        self.assertTrue(op_ifdup(stack))
        self.assertEqual(len(stack), 1)

    def test_ifdup_empty(self):
        self.assertFalse(op_ifdup([]))

    def test_depth(self):
        stack = [b"\x01", b"\x02"]
        self.assertTrue(op_depth(stack))
        self.assertEqual(decode_num(stack[-1]), 2)

    def test_drop_empty(self):
        self.assertFalse(op_drop([]))

    def test_nip(self):
        stack = [b"\x01", b"\x02"]
        self.assertTrue(op_nip(stack))
        self.assertEqual(stack, [b"\x02"])

    def test_nip_empty(self):
        self.assertFalse(op_nip([b"\x01"]))

    def test_over(self):
        stack = [b"\x01", b"\x02"]
        self.assertTrue(op_over(stack))
        self.assertEqual(stack[-1], b"\x01")

    def test_over_empty(self):
        self.assertFalse(op_over([b"\x01"]))

    def test_pick(self):
        stack = [b"\x01", b"\x02", encode_num(1)]
        self.assertTrue(op_pick(stack))
        self.assertEqual(stack[-1], b"\x01")

    def test_pick_empty(self):
        self.assertFalse(op_pick([]))

    def test_pick_too_deep(self):
        stack = [b"\x01", encode_num(5)]
        self.assertFalse(op_pick(stack))

    def test_roll(self):
        stack = [b"\x01", b"\x02", b"\x03", encode_num(2)]
        self.assertTrue(op_roll(stack))
        self.assertEqual(stack[-1], b"\x01")
        self.assertEqual(len(stack), 3)

    def test_roll_zero(self):
        stack = [b"\x01", encode_num(0)]
        self.assertTrue(op_roll(stack))
        self.assertEqual(stack, [b"\x01"])

    def test_roll_empty(self):
        self.assertFalse(op_roll([]))

    def test_roll_too_deep(self):
        stack = [b"\x01", encode_num(5)]
        self.assertFalse(op_roll(stack))

    def test_rot(self):
        stack = [b"\x01", b"\x02", b"\x03"]
        self.assertTrue(op_rot(stack))
        self.assertEqual(stack, [b"\x02", b"\x03", b"\x01"])

    def test_rot_empty(self):
        self.assertFalse(op_rot([b"\x01"]))

    def test_swap(self):
        stack = [b"\x01", b"\x02"]
        self.assertTrue(op_swap(stack))
        self.assertEqual(stack, [b"\x02", b"\x01"])

    def test_swap_empty(self):
        self.assertFalse(op_swap([b"\x01"]))

    def test_tuck(self):
        stack = [b"\x01", b"\x02"]
        self.assertTrue(op_tuck(stack))
        self.assertEqual(stack[0], b"\x02")

    def test_tuck_empty(self):
        self.assertFalse(op_tuck([b"\x01"]))

    def test_size(self):
        stack = [b"\x01\x02\x03"]
        self.assertTrue(op_size(stack))
        self.assertEqual(decode_num(stack[-1]), 3)

    def test_size_empty(self):
        self.assertFalse(op_size([]))


class OpArithmeticTest(TestCase):
    def test_1add(self):
        stack = [encode_num(5)]
        self.assertTrue(op_1add(stack))
        self.assertEqual(decode_num(stack[0]), 6)

    def test_1add_empty(self):
        self.assertFalse(op_1add([]))

    def test_1sub(self):
        stack = [encode_num(5)]
        self.assertTrue(op_1sub(stack))
        self.assertEqual(decode_num(stack[0]), 4)

    def test_1sub_empty(self):
        self.assertFalse(op_1sub([]))

    def test_negate(self):
        stack = [encode_num(5)]
        self.assertTrue(op_negate(stack))
        self.assertEqual(decode_num(stack[0]), -5)

    def test_negate_empty(self):
        self.assertFalse(op_negate([]))

    def test_abs_negative(self):
        stack = [encode_num(-5)]
        self.assertTrue(op_abs(stack))
        self.assertEqual(decode_num(stack[0]), 5)

    def test_abs_positive(self):
        stack = [encode_num(5)]
        self.assertTrue(op_abs(stack))
        self.assertEqual(decode_num(stack[0]), 5)

    def test_abs_empty(self):
        self.assertFalse(op_abs([]))

    def test_not_zero(self):
        stack = [encode_num(0)]
        self.assertTrue(op_not(stack))
        self.assertEqual(decode_num(stack[0]), 1)

    def test_not_nonzero(self):
        stack = [encode_num(5)]
        self.assertTrue(op_not(stack))
        self.assertEqual(decode_num(stack[0]), 0)

    def test_not_empty(self):
        self.assertFalse(op_not([]))

    def test_0notequal_zero(self):
        stack = [encode_num(0)]
        self.assertTrue(op_0notequal(stack))
        self.assertEqual(decode_num(stack[0]), 0)

    def test_0notequal_nonzero(self):
        stack = [encode_num(5)]
        self.assertTrue(op_0notequal(stack))
        self.assertEqual(decode_num(stack[0]), 1)

    def test_0notequal_empty(self):
        self.assertFalse(op_0notequal([]))

    def test_add(self):
        stack = [encode_num(2), encode_num(3)]
        self.assertTrue(op_add(stack))
        self.assertEqual(decode_num(stack[0]), 5)

    def test_add_empty(self):
        self.assertFalse(op_add([encode_num(1)]))

    def test_sub(self):
        stack = [encode_num(5), encode_num(3)]
        self.assertTrue(op_sub(stack))
        self.assertEqual(decode_num(stack[0]), 2)

    def test_sub_empty(self):
        self.assertFalse(op_sub([encode_num(1)]))

    def test_booland_true(self):
        stack = [encode_num(1), encode_num(1)]
        self.assertTrue(op_booland(stack))
        self.assertEqual(decode_num(stack[0]), 1)

    def test_booland_false(self):
        stack = [encode_num(0), encode_num(1)]
        self.assertTrue(op_booland(stack))
        self.assertEqual(decode_num(stack[0]), 0)

    def test_booland_empty(self):
        self.assertFalse(op_booland([encode_num(1)]))

    def test_boolor_true(self):
        stack = [encode_num(0), encode_num(1)]
        self.assertTrue(op_boolor(stack))
        self.assertEqual(decode_num(stack[0]), 1)

    def test_boolor_false(self):
        stack = [encode_num(0), encode_num(0)]
        self.assertTrue(op_boolor(stack))
        self.assertEqual(decode_num(stack[0]), 0)

    def test_boolor_empty(self):
        self.assertFalse(op_boolor([encode_num(1)]))


class OpComparisonTest(TestCase):
    def test_numequal_true(self):
        stack = [encode_num(5), encode_num(5)]
        self.assertTrue(op_numequal(stack))
        self.assertEqual(decode_num(stack[0]), 1)

    def test_numequal_false(self):
        stack = [encode_num(5), encode_num(6)]
        self.assertTrue(op_numequal(stack))
        self.assertEqual(decode_num(stack[0]), 0)

    def test_numequal_empty(self):
        self.assertFalse(op_numequal([encode_num(1)]))

    def test_numequalverify(self):
        stack = [encode_num(5), encode_num(5)]
        self.assertTrue(op_numequalverify(stack))

    def test_numnotequal_true(self):
        stack = [encode_num(5), encode_num(6)]
        self.assertTrue(op_numnotequal(stack))
        self.assertEqual(decode_num(stack[0]), 1)

    def test_numnotequal_false(self):
        stack = [encode_num(5), encode_num(5)]
        self.assertTrue(op_numnotequal(stack))
        self.assertEqual(decode_num(stack[0]), 0)

    def test_numnotequal_empty(self):
        self.assertFalse(op_numnotequal([encode_num(1)]))

    def test_lessthan_true(self):
        stack = [encode_num(3), encode_num(5)]
        self.assertTrue(op_lessthan(stack))
        self.assertEqual(decode_num(stack[0]), 1)

    def test_lessthan_false(self):
        stack = [encode_num(5), encode_num(3)]
        self.assertTrue(op_lessthan(stack))
        self.assertEqual(decode_num(stack[0]), 0)

    def test_lessthan_empty(self):
        self.assertFalse(op_lessthan([encode_num(1)]))

    def test_greaterthan_true(self):
        stack = [encode_num(5), encode_num(3)]
        self.assertTrue(op_greaterthan(stack))
        self.assertEqual(decode_num(stack[0]), 1)

    def test_greaterthan_false(self):
        stack = [encode_num(3), encode_num(5)]
        self.assertTrue(op_greaterthan(stack))
        self.assertEqual(decode_num(stack[0]), 0)

    def test_greaterthan_empty(self):
        self.assertFalse(op_greaterthan([encode_num(1)]))

    def test_lessthanorequal_true(self):
        stack = [encode_num(5), encode_num(5)]
        self.assertTrue(op_lessthanorequal(stack))
        self.assertEqual(decode_num(stack[0]), 1)

    def test_lessthanorequal_false(self):
        stack = [encode_num(5), encode_num(3)]
        self.assertTrue(op_lessthanorequal(stack))
        self.assertEqual(decode_num(stack[0]), 0)

    def test_lessthanorequal_empty(self):
        self.assertFalse(op_lessthanorequal([encode_num(1)]))

    def test_greaterthanorequal_true(self):
        stack = [encode_num(5), encode_num(5)]
        self.assertTrue(op_greaterthanorequal(stack))
        self.assertEqual(decode_num(stack[0]), 1)

    def test_greaterthanorequal_false(self):
        stack = [encode_num(3), encode_num(5)]
        self.assertTrue(op_greaterthanorequal(stack))
        self.assertEqual(decode_num(stack[0]), 0)

    def test_greaterthanorequal_empty(self):
        self.assertFalse(op_greaterthanorequal([encode_num(1)]))

    def test_min(self):
        stack = [encode_num(3), encode_num(5)]
        self.assertTrue(op_min(stack))
        self.assertEqual(decode_num(stack[0]), 3)

    def test_min_empty(self):
        self.assertFalse(op_min([encode_num(1)]))

    def test_max(self):
        stack = [encode_num(3), encode_num(5)]
        self.assertTrue(op_max(stack))
        self.assertEqual(decode_num(stack[0]), 5)

    def test_max_empty(self):
        self.assertFalse(op_max([encode_num(1)]))

    def test_within_true(self):
        stack = [encode_num(5), encode_num(3), encode_num(10)]
        self.assertTrue(op_within(stack))
        self.assertEqual(decode_num(stack[0]), 1)

    def test_within_false(self):
        stack = [encode_num(15), encode_num(3), encode_num(10)]
        self.assertTrue(op_within(stack))
        self.assertEqual(decode_num(stack[0]), 0)

    def test_within_empty(self):
        self.assertFalse(op_within([encode_num(1)]))


class OpCryptoTest(TestCase):
    def test_ripemd160(self):
        stack = [b"hello"]
        self.assertTrue(op_ripemd160(stack))
        self.assertEqual(len(stack[0]), 20)

    def test_sha1(self):
        stack = [b"hello"]
        self.assertTrue(op_sha1(stack))
        self.assertEqual(len(stack[0]), 20)

    def test_sha256(self):
        stack = [b"hello"]
        self.assertTrue(op_sha256(stack))
        self.assertEqual(len(stack[0]), 32)

    def test_hash256(self):
        stack = [b"hello"]
        self.assertTrue(op_hash256(stack))
        self.assertEqual(len(stack[0]), 32)

    def test_hash256_empty(self):
        self.assertFalse(op_hash256([]))


class OpNotifTest(TestCase):
    def test_notif_true(self):
        """Test OP_NOTIF with true condition (should execute false branch)."""
        stack = [encode_num(1)]
        # OP_NOTIF ... OP_ELSE ... OP_ENDIF = items: [103 (else), ..., 104 (endif)]
        items = [encode_num(5), 103, encode_num(10), 104]
        self.assertTrue(op_notif(stack, items))
        # True on stack means execute false_items (the else branch)
        self.assertEqual(decode_num(items[0]), 10)

    def test_notif_false(self):
        """Test OP_NOTIF with false condition (should execute true branch)."""
        stack = [encode_num(0)]
        items = [encode_num(5), 103, encode_num(10), 104]
        self.assertTrue(op_notif(stack, items))
        self.assertEqual(decode_num(items[0]), 5)

    def test_notif_no_endif(self):
        """Test OP_NOTIF without OP_ENDIF."""
        stack = [encode_num(1)]
        items = [encode_num(5)]
        self.assertFalse(op_notif(stack, items))

    def test_notif_empty(self):
        self.assertFalse(op_notif([], []))

    def test_notif_nested(self):
        """Test OP_NOTIF with nested IF."""
        stack = [encode_num(0)]
        # items: [nested_if(99), ..., nested_endif(104), else(103), ..., endif(104)]
        items = [99, encode_num(1), 104, 103, encode_num(2), 104]
        self.assertTrue(op_notif(stack, items))
        # False on stack => execute true_items which contains the nested if
        self.assertEqual(items[0], 99)


class OpCheckmultisigverifyTest(TestCase):
    def test_empty_stack(self):
        self.assertFalse(op_checkmultisigverify([], None, 0))


class OpChecksequenceverifyTest(TestCase):
    def test_version_too_low(self):
        """Covers line 876: tx_obj.version < 2"""

        class MockTxIn:
            def __init__(self):
                from buidl.timelock import Sequence

                self.sequence = Sequence(1)

        class MockTx:
            def __init__(self):
                self.tx_ins = [MockTxIn()]
                self.version = 1

        stack = [encode_num(1)]
        self.assertFalse(op_checksequenceverify(stack, MockTx(), 0))


class OpSuccessTest(TestCase):
    def test_success(self):
        self.assertTrue(op_success([]))


# --- siphash.py tests ---


class SipHashTest(TestCase):
    def test_digest(self):
        key = b"0123456789ABCDEF"
        h = SipHash_2_4(key, b"a")
        d = h.digest()
        self.assertEqual(len(d), 8)
        self.assertIsInstance(d, bytes)

    def test_hexdigest(self):
        key = b"0123456789ABCDEF"
        h = SipHash_2_4(key, b"a")
        hd = h.hexdigest()
        self.assertEqual(len(hd), 16)

    def test_copy(self):
        key = b"FEDCBA9876543210"
        a = SipHash_2_4(key, b"hello")
        b = a.copy()
        self.assertEqual(a.hash(), b.hash())
        a.update(b"more")
        self.assertNotEqual(a.hash(), b.hash())


# --- merkleblock.py tests ---


class MerkleTreeReprTest(TestCase):
    def test_repr(self):
        tree = MerkleTree(4)
        result = repr(tree)
        self.assertIn("None", result)

    def test_repr_with_hashes(self):
        tree = MerkleTree(2)
        tree.nodes[1][0] = bytes(32)
        tree.nodes[1][1] = bytes(32)
        result = repr(tree)
        self.assertIn("0000", result)


class MerkleBlockTest(TestCase):
    def test_repr(self):
        """MerkleBlock.__repr__ has a bug (no return), just exercise the code."""
        from buidl.block import Block

        header = Block.parse_header(
            hex="0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c"
        )
        mb = MerkleBlock(header, 1, [bytes(32)], b"\x01")
        # __repr__ doesn't return a value (bug in source), call it directly
        result = mb.__repr__()
        self.assertIsNone(result)

    def test_hash_and_id(self):
        from buidl.block import Block

        header = Block.parse_header(
            hex="0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c"
        )
        mb = MerkleBlock(header, 1, [bytes(32)], b"\x01")
        self.assertEqual(len(mb.hash()), 32)
        self.assertEqual(len(mb.id()), 64)

    def test_proved_txs_before_is_valid(self):
        """Covers line 205: proved_txs when merkle_tree is None."""
        from buidl.block import Block

        header = Block.parse_header(
            hex="0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c"
        )
        mb = MerkleBlock(header, 1, [bytes(32)], b"\x01")
        self.assertEqual(mb.proved_txs(), [])

    def test_populate_tree_hashes_not_consumed(self):
        """Covers line 138: hashes not all consumed."""
        tree = MerkleTree(2)
        flag_bits = [0, 1, 1]
        hashes = [bytes(32), bytes(32), bytes(32)]
        with self.assertRaises(RuntimeError):
            tree.populate_tree(flag_bits, hashes)

    def test_populate_tree_flags_not_consumed(self):
        """Covers line 141: flag bits not all consumed."""
        tree = MerkleTree(2)
        flag_bits = [0, 1, 1, 1]
        hashes = [bytes(32), bytes(32)]
        with self.assertRaises(RuntimeError):
            tree.populate_tree(flag_bits, hashes)


# --- witness.py tests ---


class WitnessReprTest(TestCase):
    def test_repr_null(self):
        w = Witness([b"", b"\x01\x02"])
        result = repr(w)
        self.assertIn("<null>", result)
        self.assertIn("0102", result)

    def test_repr_hex(self):
        w = Witness([b"\xab\xcd"])
        result = repr(w)
        self.assertIn("abcd", result)


class WitnessAnnexTest(TestCase):
    def test_has_annex(self):
        w = Witness([b"\x01", b"\x02", b"\x50extra"])
        self.assertTrue(w.has_annex())

    def test_no_annex(self):
        w = Witness([b"\x01", b"\x02"])
        self.assertFalse(w.has_annex())

    def test_control_block_with_annex(self):
        """Covers line 46: control_block with annex present."""
        from buidl.ecc import PrivateKey

        # Use a real public key for the internal key
        internal_key = PrivateKey(secret=1).point.xonly()
        cb_bytes = b"\xc0" + internal_key
        annex = b"\x50annex"
        # items: [sig, script, control_block, annex]
        w = Witness([b"\x01", b"\x02", cb_bytes, annex])
        self.assertTrue(w.has_annex())
        cb = w.control_block()
        self.assertIsNotNone(cb)

    def test_tap_script_with_annex(self):
        """Covers line 52: tap_script with annex present."""
        from buidl.ecc import PrivateKey

        raw_script = b"\x51"  # OP_TRUE
        internal_key = PrivateKey(secret=1).point.xonly()
        cb_bytes = b"\xc0" + internal_key
        annex = b"\x50annex"
        # items: [sig, script, control_block, annex]
        w = Witness([b"\x01", raw_script, cb_bytes, annex])
        tap_script = w.tap_script()
        self.assertIsNotNone(tap_script)
