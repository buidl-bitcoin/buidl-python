"""Tests to increase coverage for tx, bech32, pecc, hd, taproot, compactfilter, shamir."""

from io import BytesIO
from unittest import TestCase

from buidl.ecc import PrivateKey, S256Point
from buidl.hd import HDPrivateKey, HDPublicKey


# --- bech32.py tests ---


class ConvertBitsTest(TestCase):
    def test_out_of_range(self):
        from buidl.bech32 import convertbits

        result = convertbits([256], 8, 5)
        self.assertIsNone(result)

    def test_no_pad_leftover(self):
        from buidl.bech32 import convertbits

        # 3 bits left over when converting 8->5, pad=False should fail
        result = convertbits([0xFF], 8, 5, pad=False)
        self.assertIsNone(result)


class Bc32DecodeTest(TestCase):
    def test_mixed_case(self):
        from buidl.bech32 import bc32decode

        result = bc32decode("AbCdEf")
        self.assertIsNone(result)

    def test_invalid_chars(self):
        from buidl.bech32 import bc32decode

        # 'b' is not in bech32 alphabet
        result = bc32decode("bbbbbb")
        self.assertIsNone(result)


class CborLargeTest(TestCase):
    def test_encode_decode_medium(self):
        """Test cbor encode/decode with 24-255 byte data."""
        from buidl.bech32 import cbor_encode, cbor_decode

        data = b"\xab" * 100
        encoded = cbor_encode(data)
        self.assertEqual(encoded[0], 0x58)
        decoded = cbor_decode(encoded)
        self.assertEqual(decoded, data)

    def test_encode_decode_large(self):
        """Test cbor encode/decode with 256-65535 byte data."""
        from buidl.bech32 import cbor_encode, cbor_decode

        data = b"\xcd" * 300
        encoded = cbor_encode(data)
        self.assertEqual(encoded[0], 0x59)
        decoded = cbor_decode(encoded)
        self.assertEqual(decoded, data)


class EncodeBech32ChecksumTest(TestCase):
    def test_unknown_network(self):
        from buidl.bech32 import encode_bech32_checksum

        with self.assertRaises(ValueError):
            encode_bech32_checksum(b"\x00" + bytes(20), network="fakenet")


class DecodeBech32Test(TestCase):
    def test_regtest(self):
        from buidl.bech32 import decode_bech32

        # Use a known valid regtest address
        # Generate one: bcrt1q + 20-byte witness program
        pk = PrivateKey(secret=1)
        addr = pk.point.p2wpkh_address(network="regtest")
        self.assertTrue(addr.startswith("bcrt1"))
        result = decode_bech32(addr)
        self.assertEqual(result[0], "regtest")

    def test_bad_checksum(self):
        from buidl.bech32 import decode_bech32

        pk = PrivateKey(secret=1)
        addr = pk.point.p2wpkh_address()
        # Corrupt the last character
        bad = addr[:-1] + ("q" if addr[-1] != "q" else "p")
        with self.assertRaises(ValueError):
            decode_bech32(bad)


# --- pecc.py tests ---


class S256PointTest(TestCase):
    def test_repr(self):
        p = PrivateKey(secret=1).point
        result = repr(p)
        self.assertIsInstance(result, str)

    def test_sec_uncompressed(self):
        p = PrivateKey(secret=1).point
        sec = p.sec(compressed=False)
        self.assertEqual(len(sec), 65)
        self.assertEqual(sec[0], 4)

    def test_hash160_uncompressed(self):
        p = PrivateKey(secret=1).point
        h = p.hash160(compressed=False)
        self.assertEqual(len(h), 20)

    def test_parse_xonly(self):
        p = PrivateKey(secret=1).point
        xonly = p.xonly()
        parsed = S256Point.parse_xonly(xonly)
        self.assertEqual(parsed.xonly(), xonly)

    def test_parse_sec_uncompressed(self):
        p = PrivateKey(secret=1).point
        sec = p.sec(compressed=False)
        parsed = S256Point.parse(sec)
        self.assertEqual(parsed.sec(), p.sec())


class PrivateKeyTest(TestCase):
    def test_secret_too_big(self):
        N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        with self.assertRaises(RuntimeError):
            PrivateKey(secret=N)

    def test_secret_too_small(self):
        with self.assertRaises(RuntimeError):
            PrivateKey(secret=0)

    def test_hex(self):
        pk = PrivateKey(secret=1)
        self.assertEqual(len(pk.hex()), 64)

    def test_wif_testnet(self):
        pk = PrivateKey(secret=1, network="testnet")
        wif = pk.wif()
        self.assertIsNotNone(wif)

    def test_wif_uncompressed(self):
        pk = PrivateKey(secret=1, compressed=False)
        wif = pk.wif(compressed=False)
        self.assertIsNotNone(wif)

    def test_parse_testnet(self):
        pk = PrivateKey(secret=42, network="testnet")
        wif = pk.wif()
        parsed = PrivateKey.parse(wif)
        self.assertEqual(parsed.secret, 42)

    def test_parse_bad_wif(self):
        with self.assertRaises(ValueError):
            PrivateKey.parse("NotAValidWIF")


# --- hd.py tests ---


class HDPrivateKeyPassthroughTest(TestCase):
    def setUp(self):
        self.hd = HDPrivateKey.from_mnemonic(
            "abandon " * 11 + "about", network="mainnet"
        )

    def test_sec(self):
        child = self.hd.traverse("m/0")
        self.assertEqual(len(child.sec()), 33)

    def test_hash160(self):
        child = self.hd.traverse("m/0")
        self.assertEqual(len(child.hash160()), 20)

    def test_p2pkh_script(self):
        child = self.hd.traverse("m/0")
        self.assertIsNotNone(child.p2pkh_script())

    def test_p2wpkh_script(self):
        child = self.hd.traverse("m/0")
        self.assertIsNotNone(child.p2wpkh_script())

    def test_address(self):
        child = self.hd.traverse("m/0")
        addr = child.address()
        self.assertIsInstance(addr, str)

    def test_p2wpkh_address(self):
        child = self.hd.traverse("m/0")
        addr = child.p2wpkh_address()
        self.assertTrue(addr.startswith("bc1q"))

    def test_p2sh_p2wpkh_address(self):
        child = self.hd.traverse("m/0")
        addr = child.p2sh_p2wpkh_address()
        self.assertTrue(addr.startswith("3"))

    def test_repr(self):
        child = self.hd.traverse("m/0")
        result = repr(child)
        self.assertIsInstance(result, str)


class HDPrivateKeyTraverseTest(TestCase):
    def test_bad_path(self):
        hd = HDPrivateKey.from_mnemonic("abandon " * 11 + "about")
        with self.assertRaises(ValueError):
            hd.traverse("x/0/1")


class HDPrivateKeyParseTest(TestCase):
    def test_bad_length(self):
        from buidl.helper import encode_base58_checksum

        # Valid base58check but wrong length for xprv (needs 78 bytes)
        bad_xprv = encode_base58_checksum(b"\x04\x88\xad\xe4" + b"\x00" * 10)
        with self.assertRaises(ValueError):
            HDPrivateKey.parse(bad_xprv)


class HDPrivateKeyGetAddressTest(TestCase):
    def test_unknown_purpose(self):
        hd = HDPrivateKey.from_mnemonic("abandon " * 11 + "about")
        with self.assertRaises(ValueError):
            hd._get_address(purpose="99'")


class HDPrivateKeyP2trChangeTest(TestCase):
    def test_get_p2tr_change_privkey(self):
        hd = HDPrivateKey.from_mnemonic("abandon " * 11 + "about")
        pk = hd.get_p2tr_change_privkey()
        self.assertIsNotNone(pk)


class HDPublicKeyPassthroughTest(TestCase):
    def setUp(self):
        hd_priv = HDPrivateKey.from_mnemonic("abandon " * 11 + "about")
        self.hd = hd_priv.traverse("m/0").pub

    def test_p2pkh_script(self):
        self.assertIsNotNone(self.hd.p2pkh_script())

    def test_p2wpkh_script(self):
        self.assertIsNotNone(self.hd.p2wpkh_script())

    def test_p2sh_p2wpkh_address(self):
        addr = self.hd.p2sh_p2wpkh_address()
        self.assertTrue(addr.startswith("3"))

    def test_p2tr_address(self):
        addr = self.hd.p2tr_address()
        self.assertTrue(addr.startswith("bc1p"))


class HDPublicKeyTraverseTest(TestCase):
    def test_bad_path(self):
        hd_priv = HDPrivateKey.from_mnemonic("abandon " * 11 + "about")
        hd_pub = hd_priv.pub
        with self.assertRaises(ValueError):
            hd_pub.traverse("x/0")

    def test_hardened(self):
        hd_priv = HDPrivateKey.from_mnemonic("abandon " * 11 + "about")
        hd_pub = hd_priv.pub
        with self.assertRaises(ValueError):
            hd_pub.traverse("m/0'")


class HDPublicKeyParseTest(TestCase):
    def test_bad_length(self):
        from buidl.helper import encode_base58_checksum

        # Valid base58check but wrong length for xpub (needs 78 bytes)
        bad_xpub = encode_base58_checksum(b"\x04\x88\xb2\x1e" + b"\x00" * 10)
        with self.assertRaises(ValueError):
            HDPublicKey.parse(bad_xpub)


class HDPrivateKeyP2wshKeyRecordTest(TestCase):
    def test_valid(self):
        hd = HDPrivateKey.from_mnemonic("abandon " * 11 + "about")
        record = hd.generate_p2wsh_key_record()
        self.assertIn("[", record)
        self.assertIn("]", record)

    def test_non_root_depth(self):
        hd = HDPrivateKey.from_mnemonic("abandon " * 11 + "about")
        child = hd.traverse("m/0")
        with self.assertRaises(ValueError):
            child.generate_p2wsh_key_record()


class GetUnhardenedChildPathTest(TestCase):
    def test_matching(self):
        from buidl.hd import get_unhardened_child_path

        result = get_unhardened_child_path("m/48'/0'/0'/2'", "m/48'/0'/0'/2'/0/5")
        self.assertEqual(result, "m/0/5")

    def test_not_matching(self):
        from buidl.hd import get_unhardened_child_path

        result = get_unhardened_child_path("m/48'/0'/0'/2'", "m/49'/0'/0'/2'/0/5")
        self.assertIsNone(result)


class IsValidBip32PathTest(TestCase):
    def test_invalid_paths(self):
        from buidl.hd import is_valid_bip32_path

        self.assertFalse(is_valid_bip32_path("x/0"))
        self.assertFalse(is_valid_bip32_path("m/" + "/".join(["0"] * 257)))
        self.assertFalse(is_valid_bip32_path("m/abc"))
        self.assertFalse(is_valid_bip32_path("m/-1"))


# --- taproot.py tests ---


class TapLeafTest(TestCase):
    def test_repr(self):
        from buidl.taproot import TapLeaf
        from buidl.script import Script

        leaf = TapLeaf(Script([0x51]))
        result = repr(leaf)
        self.assertIsInstance(result, str)

    def test_eq(self):
        from buidl.taproot import TapLeaf
        from buidl.script import Script

        leaf1 = TapLeaf(Script([0x51]))
        leaf2 = TapLeaf(Script([0x51]))
        self.assertEqual(leaf1, leaf2)

    def test_control_block_wrong_leaf(self):
        from buidl.taproot import TapLeaf
        from buidl.script import Script

        leaf1 = TapLeaf(Script([0x51]))
        leaf2 = TapLeaf(Script([0x52]))
        p = PrivateKey(secret=1).point
        result = leaf1.control_block(p, tap_leaf=leaf2)
        self.assertIsNone(result)


class TapBranchTest(TestCase):
    def test_bad_init(self):
        from buidl.taproot import TapBranch

        with self.assertRaises(ValueError):
            TapBranch("not_a_leaf", "not_a_leaf")

    def test_path_hashes_not_found(self):
        from buidl.taproot import TapBranch, TapLeaf
        from buidl.script import Script

        leaf1 = TapLeaf(Script([0x51]))
        leaf2 = TapLeaf(Script([0x52]))
        leaf3 = TapLeaf(Script([0x53]))
        branch = TapBranch(leaf1, leaf2)
        result = branch.path_hashes(leaf3)
        self.assertIsNone(result)

    def test_control_block_not_found(self):
        from buidl.taproot import TapBranch, TapLeaf
        from buidl.script import Script

        leaf1 = TapLeaf(Script([0x51]))
        leaf2 = TapLeaf(Script([0x52]))
        leaf3 = TapLeaf(Script([0x53]))
        branch = TapBranch(leaf1, leaf2)
        p = PrivateKey(secret=1).point
        result = branch.control_block(p, leaf3)
        self.assertIsNone(result)


class ControlBlockTest(TestCase):
    def test_repr(self):
        from buidl.taproot import ControlBlock

        p = PrivateKey(secret=1).point
        cb_bytes = b"\xc0" + p.xonly()
        cb = ControlBlock.parse(cb_bytes)
        result = repr(cb)
        self.assertIsInstance(result, str)

    def test_parse_bad_length(self):
        from buidl.taproot import ControlBlock

        with self.assertRaises(ValueError):
            ControlBlock.parse(b"\xc0" + bytes(10))

    def test_parse_too_long(self):
        from buidl.taproot import ControlBlock

        # 33 + 129*32 = too many path hashes
        with self.assertRaises(ValueError):
            ControlBlock.parse(b"\xc0" + bytes(33 + 129 * 32))


class P2PKTapScriptTest(TestCase):
    def test_bad_point_type(self):
        from buidl.taproot import P2PKTapScript

        with self.assertRaises(TypeError):
            P2PKTapScript("not_a_point")


class MultiSigTapScriptTest(TestCase):
    def test_both_locktime_and_sequence(self):
        from buidl.taproot import MultiSigTapScript

        p = PrivateKey(secret=1).point
        with self.assertRaises(ValueError):
            MultiSigTapScript([p], k=1, locktime=100, sequence=100)

    def test_no_points(self):
        from buidl.taproot import MultiSigTapScript

        with self.assertRaises(ValueError):
            MultiSigTapScript([], k=1)


class MuSigTapScriptTest(TestCase):
    def test_both_locktime_and_sequence(self):
        from buidl.taproot import MuSigTapScript

        p = PrivateKey(secret=1).point
        with self.assertRaises(ValueError):
            MuSigTapScript([p], locktime=100, sequence=100)

    def test_no_points(self):
        from buidl.taproot import MuSigTapScript

        with self.assertRaises(ValueError):
            MuSigTapScript([])


# --- compactfilter.py tests ---


class CompactFilterTest(TestCase):
    def test_serialize_hash_eq(self):
        from buidl.compactfilter import CompactFilter

        cf = CompactFilter(key=bytes(16), hashes=[1, 2, 3])
        serialized = cf.serialize()
        self.assertIsNotNone(serialized)
        h = cf.hash()
        self.assertEqual(len(h), 32)

    def test_eq(self):
        from buidl.compactfilter import CompactFilter

        cf1 = CompactFilter(key=bytes(16), hashes=[1, 2])
        cf2 = CompactFilter(key=bytes(16), hashes=[1, 2])
        self.assertEqual(cf1, cf2)


class CFilterMessageTest(TestCase):
    def test_eq_and_hash(self):
        from buidl.compactfilter import CFilterMessage

        msg1 = CFilterMessage(filter_type=0, block_hash=bytes(32), filter_bytes=b"\x00")
        msg2 = CFilterMessage(filter_type=0, block_hash=bytes(32), filter_bytes=b"\x00")
        self.assertEqual(msg1, msg2)
        h = msg1.hash()
        self.assertEqual(len(h), 32)


class CFHeadersMessageTest(TestCase):
    def test_repr(self):
        from buidl.compactfilter import CFHeadersMessage

        msg = CFHeadersMessage(
            filter_type=0,
            stop_hash=bytes(32),
            previous_filter_header=bytes(32),
            filter_hashes=[bytes(32)],
        )
        result = repr(msg)
        self.assertIsInstance(result, str)


class CFCheckPointMessageTest(TestCase):
    def test_repr(self):
        from buidl.compactfilter import CFCheckPointMessage

        msg = CFCheckPointMessage(
            filter_type=0,
            stop_hash=bytes(32),
            filter_headers=[bytes(32)],
        )
        result = repr(msg)
        self.assertIsInstance(result, str)


# --- shamir.py tests ---


class ShareInitTest(TestCase):
    def test_group_index_out_of_range(self):
        from buidl.shamir import Share

        with self.assertRaises(ValueError):
            Share(
                share_bit_length=128,
                id=0,
                exponent=0,
                group_index=16,
                group_threshold=1,
                group_count=1,
                member_index=0,
                member_threshold=1,
                value=bytes(16),
            )

    def test_group_threshold_out_of_range(self):
        from buidl.shamir import Share

        with self.assertRaises(ValueError):
            Share(
                share_bit_length=128,
                id=0,
                exponent=0,
                group_index=0,
                group_threshold=5,
                group_count=1,
                member_index=0,
                member_threshold=1,
                value=bytes(16),
            )

    def test_group_count_out_of_range(self):
        from buidl.shamir import Share

        with self.assertRaises(ValueError):
            Share(
                share_bit_length=128,
                id=0,
                exponent=0,
                group_index=0,
                group_threshold=1,
                group_count=17,
                member_index=0,
                member_threshold=1,
                value=bytes(16),
            )

    def test_member_index_out_of_range(self):
        from buidl.shamir import Share

        with self.assertRaises(ValueError):
            Share(
                share_bit_length=128,
                id=0,
                exponent=0,
                group_index=0,
                group_threshold=1,
                group_count=1,
                member_index=16,
                member_threshold=1,
                value=bytes(16),
            )


class ShareSetSplitSecretTest(TestCase):
    def test_n_too_small(self):
        from buidl.shamir import ShareSet

        with self.assertRaises(ValueError):
            ShareSet.split_secret(bytes(16), k=1, n=0)

    def test_n_too_big(self):
        from buidl.shamir import ShareSet

        with self.assertRaises(ValueError):
            ShareSet.split_secret(bytes(16), k=1, n=17)

    def test_k_too_small(self):
        from buidl.shamir import ShareSet

        with self.assertRaises(ValueError):
            ShareSet.split_secret(bytes(16), k=0, n=1)

    def test_k_too_big(self):
        from buidl.shamir import ShareSet

        with self.assertRaises(ValueError):
            ShareSet.split_secret(bytes(16), k=3, n=2)

    def test_bad_secret_length(self):
        from buidl.shamir import ShareSet

        with self.assertRaises(ValueError):
            ShareSet.split_secret(bytes(10), k=1, n=1)

    def test_k_equals_1(self):
        from buidl.shamir import ShareSet

        shares = ShareSet.split_secret(bytes(16), k=1, n=1)
        self.assertEqual(len(shares), 1)


class ShareSetCryptOddTest(TestCase):
    def test_odd_payload(self):
        from buidl.shamir import ShareSet

        with self.assertRaises(ValueError):
            ShareSet._crypt(b"\x00" * 3, id=0, exponent=0, passphrase=b"", indices=[])


# --- tx.py tests ---


class TxParseSegwitBadMarkerTest(TestCase):
    def test_bad_marker(self):
        from buidl.tx import Tx

        # Version (4 bytes) + marker (not 0x0001) + rest
        raw = b"\x01\x00\x00\x00" + b"\x00\x02" + b"\x00" * 10
        with self.assertRaises(RuntimeError):
            Tx.parse_segwit(BytesIO(raw))


class TxCoinbaseHeightTest(TestCase):
    def test_not_coinbase(self):
        from buidl.tx import Tx, TxIn, TxOut

        tx = Tx(1, [TxIn(bytes(32), 0)], [TxOut(50000, b"\x00")], 0)
        self.assertIsNone(tx.coinbase_height())


class TxOutToAddressErrorTest(TestCase):
    def test_unknown_address(self):
        from buidl.tx import TxOut

        with self.assertRaises(ValueError):
            TxOut.to_address("xyz_unknown", 1000)

    def test_bad_bech32_v0_length(self):
        """bech32 v0 address that is not 42 or 62 chars."""
        from buidl.tx import TxOut

        # A valid bech32 address but with wrong witness program length
        # This would be caught by the address_to_script_pubkey checks
        with self.assertRaises((ValueError, RuntimeError)):
            TxOut.to_address("bc1q" + "q" * 10, 1000)
