"""Additional PSBT tests to increase code coverage from 87% to 97%+."""

from io import BytesIO
from unittest import TestCase

from buidl.ecc import PrivateKey
from buidl.hd import HDPrivateKey
from buidl.helper import (
    encode_varstr,
    int_to_little_endian,
    read_varstr,
    SIGHASH_ALL,
    serialize_key_value,
)
from buidl.psbt import (
    NamedHDPublicKey,
    NamedPublicKey,
    PSBT,
    PSBT_DELIMITER,
    PSBT_GLOBAL_UNSIGNED_TX,
    PSBT_IN_NON_WITNESS_UTXO,
    PSBT_IN_WITNESS_UTXO,
    PSBT_IN_SIGHASH_TYPE,
    PSBTIn,
    PSBTOut,
    path_to_child,
    serialize_binary_path,
)
from buidl.script import RedeemScript, Script, WitnessScript
from buidl.tx import Tx, TxIn, TxOut
from buidl.witness import Witness

from buidl.test import OfflineTestCase


class PathToChildTest(TestCase):
    def test_non_hardened(self):
        """Covers line 69: non-hardened path component"""
        self.assertEqual(path_to_child("0"), 0)
        self.assertEqual(path_to_child("5"), 5)
        self.assertEqual(path_to_child("44"), 44)

    def test_hardened(self):
        self.assertEqual(path_to_child("0'"), 0x80000000)
        self.assertEqual(path_to_child("44'"), 0x80000000 + 44)


class NamedPublicKeyTest(TestCase):
    def _make_named_pubkey(self):
        """Helper to create a NamedPublicKey with path data."""
        priv = PrivateKey(secret=12345)
        point = priv.point
        point.__class__ = NamedPublicKey
        raw_path = bytes.fromhex("deadbeef") + serialize_binary_path("m/44'/1'/0'/0/0")
        point.add_raw_path_data(raw_path)
        return point

    def test_repr(self):
        """Covers line 83: NamedPublicKey.__repr__"""
        named = self._make_named_pubkey()
        result = repr(named)
        self.assertIn("Point:", result)
        self.assertIn("Path:", result)
        self.assertIn("deadbeef", result)

    def test_replace_xfp(self):
        """Covers lines 97-101: NamedPublicKey.replace_xfp"""
        named = self._make_named_pubkey()
        old_path = named.root_path
        named.replace_xfp("aabbccdd")
        self.assertEqual(named.root_fingerprint, bytes.fromhex("aabbccdd"))
        self.assertEqual(named.root_path, old_path)

    def test_add_raw_path_data_with_network(self):
        """Covers line 95: explicit network parameter"""
        priv = PrivateKey(secret=12345)
        point = priv.point
        point.__class__ = NamedPublicKey
        raw_path = bytes.fromhex("deadbeef") + serialize_binary_path("m/44'/1'/0'/0/0")
        point.add_raw_path_data(raw_path, network="testnet")
        self.assertEqual(point.network, "testnet")


class NamedHDPublicKeyTest(TestCase):
    def _make_named_hd(self):
        """Helper to parse a NamedHDPublicKey from hex."""
        hex_named_hd = "4f01043587cf034d513c1580000000fb406c9fec09b6957a3449d2102318717b0c0d230b657d0ebc6698abd52145eb02eaf3397fea02c5dac747888a9e535eaf3c7e7cb9d5f2da77ddbdd943592a14af10fbfef36f2c0000800100008000000080"
        stream = BytesIO(bytes.fromhex(hex_named_hd))
        return NamedHDPublicKey.parse(read_varstr(stream), stream)

    def test_depth_mismatch(self):
        """Covers line 126: raw path depth mismatch"""
        named_hd = self._make_named_hd()
        # Give it a raw_path that doesn't match its depth
        bad_raw_path = bytes.fromhex("deadbeef") + serialize_binary_path("m/44'")
        with self.assertRaises(ValueError) as cm:
            named_hd.add_raw_path_data(bad_raw_path)
        self.assertIn("depth", str(cm.exception))

    def test_verify_descendent(self):
        """Covers lines 228-237: verify_descendent method"""
        named_hd = self._make_named_hd()
        # Create a child and verify descendent
        child = named_hd.child(0).child(0)
        self.assertTrue(named_hd.verify_descendent(child.point))

    def test_verify_descendent_not_ancestor(self):
        """Covers line 230: path is not a descendent"""
        named_hd = self._make_named_hd()
        # Create a NamedPublicKey that is NOT a descendent
        priv = PrivateKey(secret=99999)
        point = priv.point
        point.__class__ = NamedPublicKey
        point.add_raw_path_data(
            bytes.fromhex("aabbccdd") + serialize_binary_path("m/99'/0'/0'/0/0")
        )
        with self.assertRaises(ValueError) as cm:
            named_hd.verify_descendent(point)
        self.assertIn("not a descendent", str(cm.exception))

    def test_from_hd_pub(self):
        """Covers lines 201-209: from_hd_pub classmethod"""
        hd_priv = HDPrivateKey.from_mnemonic(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            network="testnet",
        )
        child = hd_priv.traverse("m/44'/1'/0'").pub
        named = NamedHDPublicKey.from_hd_pub(
            child_hd_pub=child,
            xfp_hex=hd_priv.fingerprint().hex(),
            path="m/44'/1'/0'",
        )
        self.assertEqual(named.root_fingerprint, hd_priv.fingerprint())

    def test_from_hd_priv(self):
        """Covers lines 211-218: from_hd_priv classmethod"""
        hd_priv = HDPrivateKey.from_mnemonic(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            network="testnet",
        )
        named = NamedHDPublicKey.from_hd_priv(hd_priv, "m/44'/1'/0'")
        self.assertEqual(named.root_fingerprint, hd_priv.fingerprint())
        self.assertIn("m/44'/1'/0'", named.root_path)


class PSBTCreateTest(OfflineTestCase):
    def test_create_with_scriptsig(self):
        """Covers lines 365-367: PSBT.create strips ScriptSig from tx inputs"""
        # Parse, sign, and finalize to get a tx with script_sig set
        hex_psbt = "70736274ff0100770100000001192f88eeabc44ac213604adbb5b699678815d24b718b5940f5b1b1853f0887480100000000ffffffff0220a10700000000001976a91426d5d464d148454c76f7095fdf03afc8bc8d82c388ac2c9f0700000000001976a9144df14c8c8873451290c53e95ebd1ee8fe488f0ed88ac00000000000100fda40102000000000102816f71fa2b62d7235ae316d54cb174053c793d16644064405a8326094518aaa901000000171600148900fe9d1950305978d57ebbc25f722bbf131b53feffffff6e3e62f2e005db1bb2a1f12e5ca2bfbb4f82f2ca023c23b0a10a035cabb38fb60000000017160014ae01dce99edb5398cee5e4dc536173d35a9495a9feffffff0278de16000000000017a914a2be7a5646958a5b53f1c3de5a896f6c0ff5419f8740420f00000000001976a9149a9bfaf8ef6c4b061a30e8e162da3458cfa122c688ac02473044022017506b1a15e0540efe5453fcc9c61dcc4457dd00d22cba5e5b937c56944f96ff02207a1c071a8e890cf69c4adef5154d6556e5b356fc09d74a7c811484de289c2d41012102de6c105c8ed6c54d9f7a166fbe3012fecbf4bb3cecda49a8aad1d0c07784110c0247304402207035217de1a2c587b1aaeb5605b043189d551451697acb74ffc99e5a288f4fde022013b7f33a916f9e05846d333b6ea314f56251e74f243682e0ec45ce9e16c6344d01210205174b405fba1b53a44faf08679d63c871cece6c3b2c343bd2d7c559aa32dfb1a2271800220602c1b6ac6e6a625fee295dc2d580f80aae08b7e76eca54ae88a854e956095af77c18fbfef36f2c00008001000080000000800000000000000000000000"
        psbt_obj = PSBT.parse(BytesIO(bytes.fromhex(hex_psbt)))
        hd_priv = HDPrivateKey.parse(
            "tprv8ZgxMBicQKsPeL2qb9uLkgTKhLHSUUHsxmr2fcGFRBVh6EiBrxHZNTagx3kDXN4yjHsYV5rUYZhpsLCrZYBXzWLWHA4xL3FcCF6CZz1LDGM"
        )
        psbt_obj.sign(hd_priv)
        psbt_obj.finalize()
        # The PSBTIn now has script_sig set
        self.assertIsNotNone(psbt_obj.psbt_ins[0].script_sig)
        # Make a tx with the script_sig baked in
        tx_obj = Tx(
            psbt_obj.tx_obj.version,
            psbt_obj.tx_obj.tx_ins,
            psbt_obj.tx_obj.tx_outs,
            psbt_obj.tx_obj.locktime,
        )
        tx_obj.tx_ins[0].script_sig = psbt_obj.psbt_ins[0].script_sig
        # Create PSBT from a tx that has script_sig populated
        psbt2 = PSBT.create(tx_obj, validate=False)
        # script_sig should have been captured in psbt_in
        self.assertIsNotNone(psbt2.psbt_ins[0].script_sig)

    def test_create_with_witness(self):
        """Covers lines 371-373: PSBT.create strips Witness from tx inputs"""
        # Use the finalized p2wpkh PSBT
        hex_psbt = "70736274ff01005201000000015c89191dc2abf62339e0f114cb4c3bf8fb399d522d112c9afa2dc7a43759f9060000000000ffffffff01583e0f000000000016001427459b7e4317d1c9e1d0f8320d557c6bb08731ef000000000001011f40420f0000000000160014f0cd79383f13584bdeca184cecd16135b8a79fc201070001086b024730440220575870ef714252a26bc4e61a6ee31db0f3896606a4792d11a42ef7d30c9f1b33022007cd28fb8618b704cbcf1cc6292d9be901bf3c99d967b0cace7307532619811e01210247aed77c3def4b8ce74a8db08d7f5fd315f8d96b6cd801729a910c3045d750f2002202026421c7673552fdad57193e102df96134be00649195b213fec9d07c6d918f418d18797dcdac2c0000800100008000000080010000000000000000"
        psbt_obj = PSBT.parse(BytesIO(bytes.fromhex(hex_psbt)))
        # The PSBTIn has a witness set
        self.assertIsNotNone(psbt_obj.psbt_ins[0].witness)
        # Build a tx with witness
        tx_obj = Tx(
            psbt_obj.tx_obj.version,
            psbt_obj.tx_obj.tx_ins,
            psbt_obj.tx_obj.tx_outs,
            psbt_obj.tx_obj.locktime,
            segwit=True,
        )
        tx_obj.tx_ins[0].witness = psbt_obj.psbt_ins[0].witness
        # Create PSBT from a tx with witness populated
        psbt2 = PSBT.create(tx_obj, validate=False)
        self.assertIsNotNone(psbt2.psbt_ins[0].witness)

    def test_create_with_hd_pubs(self):
        """Covers lines 401, 408-409: PSBT.create with tx_lookup and hd_pubs"""
        tx_in = TxIn(bytes(32), 0)
        tx_out = TxOut(50000, Script([0, bytes(20)]))
        tx_obj = Tx(2, [tx_in], [tx_out], 0)

        hd_priv = HDPrivateKey.from_mnemonic(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            network="testnet",
        )
        named = NamedHDPublicKey.from_hd_priv(hd_priv, "m/44'/1'/0'")
        hd_pubs = {named.raw_serialize(): named}

        psbt = PSBT.create(tx_obj, validate=False, hd_pubs=hd_pubs)
        self.assertEqual(len(psbt.hd_pubs), 1)


class PSBTCombineTest(OfflineTestCase):
    def test_combine_different_tx(self):
        """Covers lines 495-498: combine with different transactions raises ValueError"""
        tx_in_1 = TxIn(bytes.fromhex("aa" * 32), 0)
        tx_in_2 = TxIn(bytes.fromhex("bb" * 32), 0)
        tx_out = TxOut(50000, Script([0, bytes(20)]))

        psbt_1 = PSBT.create(Tx(2, [tx_in_1], [tx_out], 0), validate=False)
        psbt_2 = PSBT.create(Tx(2, [tx_in_2], [tx_out], 0), validate=False)

        with self.assertRaises(ValueError) as cm:
            psbt_1.combine(psbt_2)
        self.assertIn("different transactions", str(cm.exception))


class PSBTParseEdgeCasesTest(OfflineTestCase):
    def test_parse_bad_magic(self):
        """Covers line 551: bad magic"""
        with self.assertRaises(SyntaxError):
            PSBT.parse(BytesIO(b"\x00\x00\x00\x00\xff"))

    def test_parse_bad_separator(self):
        """Covers line 554: bad separator"""
        with self.assertRaises(SyntaxError):
            PSBT.parse(BytesIO(b"\x70\x73\x62\x74\x00"))

    def test_parse_duplicate_tx_key(self):
        """Covers line 566: duplicate unsigned tx key"""
        # Build a minimal PSBT with duplicate global unsigned tx
        tx_in = TxIn(bytes(32), 0)
        tx_out = TxOut(50000, Script([0, bytes(20)]))
        tx_obj = Tx(2, [tx_in], [tx_out], 0)
        tx_bytes = tx_obj.serialize()

        # Build the PSBT manually with duplicate PSBT_GLOBAL_UNSIGNED_TX
        result = b"\x70\x73\x62\x74\xff"  # magic + separator
        result += serialize_key_value(PSBT_GLOBAL_UNSIGNED_TX, tx_bytes)
        result += serialize_key_value(PSBT_GLOBAL_UNSIGNED_TX, tx_bytes)
        result += PSBT_DELIMITER

        with self.assertRaises(KeyError):
            PSBT.parse(BytesIO(result))

    def test_parse_extra_map_duplicate(self):
        """Covers lines 579-580: duplicate key in extra_map"""
        tx_in = TxIn(bytes(32), 0)
        tx_out = TxOut(50000, Script([0, bytes(20)]))
        tx_obj = Tx(2, [tx_in], [tx_out], 0)
        tx_bytes = tx_obj.serialize()

        unknown_key = b"\xfc\x01"  # unknown type
        unknown_val = b"\x01\x02\x03"

        result = b"\x70\x73\x62\x74\xff"
        result += serialize_key_value(PSBT_GLOBAL_UNSIGNED_TX, tx_bytes)
        result += serialize_key_value(unknown_key, unknown_val)
        result += serialize_key_value(unknown_key, unknown_val)
        result += PSBT_DELIMITER

        with self.assertRaises(KeyError):
            PSBT.parse(BytesIO(result))

    def test_parse_no_tx(self):
        """Covers line 584: no transaction in PSBT"""
        unknown_key = b"\xfc\x01"
        unknown_val = b"\x01\x02\x03"

        result = b"\x70\x73\x62\x74\xff"
        result += serialize_key_value(unknown_key, unknown_val)
        result += PSBT_DELIMITER

        with self.assertRaises(SyntaxError) as cm:
            PSBT.parse(BytesIO(result))
        self.assertIn("transaction is required", str(cm.exception))

    def test_parse_xpub_wrong_key_length(self):
        """Covers line 571: wrong key length for xpub"""
        tx_in = TxIn(bytes(32), 0)
        tx_out = TxOut(50000, Script([0, bytes(20)]))
        tx_obj = Tx(2, [tx_in], [tx_out], 0)
        tx_bytes = tx_obj.serialize()

        # PSBT_GLOBAL_XPUB key should be 79 bytes, give it something wrong
        bad_xpub_key = b"\x01" + b"\x00" * 10  # only 11 bytes, not 79

        result = b"\x70\x73\x62\x74\xff"
        result += serialize_key_value(PSBT_GLOBAL_UNSIGNED_TX, tx_bytes)
        result += serialize_key_value(bad_xpub_key, b"\x00" * 10)
        result += PSBT_DELIMITER

        with self.assertRaises(KeyError) as cm:
            PSBT.parse(BytesIO(result))
        self.assertIn("Wrong length", str(cm.exception))


class PSBTRemoveXpubsTest(OfflineTestCase):
    def test_remove_global_xpubs(self):
        """Covers lines 633-634: remove_global_xpubs"""
        hex_psbt = "70736274ff01005e01000000015c89191dc2abf62339e0f114cb4c3bf8fb399d522d112c9afa2dc7a43759f9060200000000ffffffff01583e0f0000000000220020878ce58b26789632a24ec6b62542e5d4e844dee56a7ddce7db41618049c3928c000000004f01043587cf034d513c1580000000fb406c9fec09b6957a3449d2102318717b0c0d230b657d0ebc6698abd52145eb02eaf3397fea02c5dac747888a9e535eaf3c7e7cb9d5f2da77ddbdd943592a14af10fbfef36f2c0000800100008000000080000000"
        psbt_obj = PSBT.parse(BytesIO(bytes.fromhex(hex_psbt)))
        self.assertTrue(len(psbt_obj.hd_pubs) > 0)
        b64 = psbt_obj.remove_global_xpubs()
        self.assertEqual(psbt_obj.hd_pubs, {})
        # Re-parse to confirm it's valid
        psbt2 = PSBT.parse_base64(b64)
        self.assertEqual(len(psbt2.hd_pubs), 0)


class PSBTReplaceXfpsTest(OfflineTestCase):
    def test_replace_root_xfps(self):
        """Covers lines 647-665: replace_root_xfps"""
        # Use the signed p2wsh PSBT that has named_pubs in inputs and outputs
        hex_psbt = "70736274ff01005e01000000015c89191dc2abf62339e0f114cb4c3bf8fb399d522d112c9afa2dc7a43759f9060200000000ffffffff01583e0f0000000000220020878ce58b26789632a24ec6b62542e5d4e844dee56a7ddce7db41618049c3928c000000004f01043587cf034d513c1580000000fb406c9fec09b6957a3449d2102318717b0c0d230b657d0ebc6698abd52145eb02eaf3397fea02c5dac747888a9e535eaf3c7e7cb9d5f2da77ddbdd943592a14af10fbfef36f2c00008001000080000000800001012b40420f0000000000220020c1b4fff485af1ac26714340af2e13d2e89ad70389332a0756d91a123c7fe7f5d010547522102c1b6ac6e6a625fee295dc2d580f80aae08b7e76eca54ae88a854e956095af77c210247aed77c3def4b8ce74a8db08d7f5fd315f8d96b6cd801729a910c3045d750f252ae22060247aed77c3def4b8ce74a8db08d7f5fd315f8d96b6cd801729a910c3045d750f218797dcdac2c00008001000080000000800000000000000000220602c1b6ac6e6a625fee295dc2d580f80aae08b7e76eca54ae88a854e956095af77c18fbfef36f2c0000800100008000000080000000000000000000010147522102db8b701c3210e1bf6f2a8a9a657acad18be1e8bff3f7435d48f973de8408f29021026421c7673552fdad57193e102df96134be00649195b213fec9d07c6d918f418d52ae2202026421c7673552fdad57193e102df96134be00649195b213fec9d07c6d918f418d18797dcdac2c00008001000080000000800100000000000000220202db8b701c3210e1bf6f2a8a9a657acad18be1e8bff3f7435d48f973de8408f29018fbfef36f2c0000800100008000000080010000000000000000"
        psbt_obj = PSBT.parse(BytesIO(bytes.fromhex(hex_psbt)))

        # Replace xfps that are known to be in the PSBT
        psbt_obj.replace_root_xfps(
            {
                "797dcdac": "11111111",
                "fbfef36f": "22222222",
            }
        )

        # Verify the replacement happened
        for psbt_in in psbt_obj.psbt_ins:
            for named_pub in psbt_in.named_pubs.values():
                self.assertIn(
                    named_pub.root_fingerprint.hex(),
                    ["11111111", "22222222"],
                )

    def test_replace_root_xfps_not_found(self):
        """Covers line 665: xfp not found raises ValueError"""
        hex_psbt = "70736274ff01005e01000000015c89191dc2abf62339e0f114cb4c3bf8fb399d522d112c9afa2dc7a43759f9060200000000ffffffff01583e0f0000000000220020878ce58b26789632a24ec6b62542e5d4e844dee56a7ddce7db41618049c3928c000000004f01043587cf034d513c1580000000fb406c9fec09b6957a3449d2102318717b0c0d230b657d0ebc6698abd52145eb02eaf3397fea02c5dac747888a9e535eaf3c7e7cb9d5f2da77ddbdd943592a14af10fbfef36f2c00008001000080000000800001012b40420f0000000000220020c1b4fff485af1ac26714340af2e13d2e89ad70389332a0756d91a123c7fe7f5d010547522102c1b6ac6e6a625fee295dc2d580f80aae08b7e76eca54ae88a854e956095af77c210247aed77c3def4b8ce74a8db08d7f5fd315f8d96b6cd801729a910c3045d750f252ae22060247aed77c3def4b8ce74a8db08d7f5fd315f8d96b6cd801729a910c3045d750f218797dcdac2c00008001000080000000800000000000000000220602c1b6ac6e6a625fee295dc2d580f80aae08b7e76eca54ae88a854e956095af77c18fbfef36f2c0000800100008000000080000000000000000000010147522102db8b701c3210e1bf6f2a8a9a657acad18be1e8bff3f7435d48f973de8408f29021026421c7673552fdad57193e102df96134be00649195b213fec9d07c6d918f418d52ae2202026421c7673552fdad57193e102df96134be00649195b213fec9d07c6d918f418d18797dcdac2c00008001000080000000800100000000000000220202db8b701c3210e1bf6f2a8a9a657acad18be1e8bff3f7435d48f973de8408f29018fbfef36f2c0000800100008000000080010000000000000000"
        psbt_obj = PSBT.parse(BytesIO(bytes.fromhex(hex_psbt)))

        with self.assertRaises(ValueError) as cm:
            psbt_obj.replace_root_xfps({"deadbeef": "11111111"})
        self.assertIn("not found", str(cm.exception))


class PSBTInValidateTest(TestCase):
    def test_prev_tx_hash_mismatch(self):
        """Covers lines 1135-1138: prev_tx hash doesn't match"""
        # Create a tx_in that references one prev_tx hash
        tx_in = TxIn(bytes.fromhex("aa" * 32), 0)
        # Create a different tx as prev_tx (its hash won't match)
        prev_tx = Tx(
            2,
            [TxIn(bytes(32), 0)],
            [TxOut(50000, Script([0, bytes(20)]))],
            0,
        )
        with self.assertRaises(ValueError) as cm:
            PSBTIn(tx_in, prev_tx=prev_tx)
        self.assertIn("does not match", str(cm.exception))

    def test_prev_tx_index_out_of_range(self):
        """Covers lines 1139-1140: prev_index out of range"""
        prev_tx = Tx(
            2,
            [TxIn(bytes(32), 0)],
            [TxOut(50000, Script([0, bytes(20)]))],
            0,
        )
        # Use prev_index=5 but prev_tx only has 1 output
        # The IndexError happens in script_pubkey() before validate can check,
        # so we test the validate path by patching
        tx_in = TxIn(prev_tx.hash(), 0)
        psbt_in = PSBTIn(tx_in, prev_tx=prev_tx)
        # Now manually set a bad index and call validate
        psbt_in.tx_in = TxIn(prev_tx.hash(), 5)
        with self.assertRaises((ValueError, IndexError)):
            psbt_in.validate()

    def test_witness_utxo_for_non_witness(self):
        """Covers lines 1143-1148: witness UTXO provided for non-witness input"""
        # p2pkh output is not a witness type
        p2pkh_script = Script([0x76, 0xA9, bytes(20), 0x88, 0xAC])
        prev_out = TxOut(50000, p2pkh_script)
        tx_in = TxIn(bytes(32), 0)
        tx_in._script_pubkey = p2pkh_script
        with self.assertRaises(ValueError) as cm:
            PSBTIn(tx_in, prev_out=prev_out)
        self.assertIn("non-witness", str(cm.exception))

    def test_too_many_pubkeys_p2wpkh(self):
        """Covers lines 1178-1179: too many pubkeys in p2wpkh"""
        priv1 = PrivateKey(secret=1)
        priv2 = PrivateKey(secret=2)
        h160 = priv1.point.hash160()
        script_pubkey = Script([0, h160])
        prev_out = TxOut(50000, script_pubkey)

        tx_in = TxIn(bytes(32), 0)
        tx_in._script_pubkey = script_pubkey

        # Create two named pubs
        np1 = priv1.point
        np1.__class__ = NamedPublicKey
        np1.add_raw_path_data(bytes(4) + serialize_binary_path("m/44'/0'/0'/0/0"))
        np2 = priv2.point
        np2.__class__ = NamedPublicKey
        np2.add_raw_path_data(bytes(4) + serialize_binary_path("m/44'/0'/0'/0/1"))

        named_pubs = {np1.sec(): np1, np2.sec(): np2}
        with self.assertRaises(ValueError) as cm:
            PSBTIn(tx_in, prev_out=prev_out, named_pubs=named_pubs)
        self.assertIn("too many pubkeys", str(cm.exception))

    def test_p2wpkh_hash160_mismatch(self):
        """Covers lines 1182-1187: pubkey hash160 doesn't match script"""
        priv1 = PrivateKey(secret=1)
        priv2 = PrivateKey(secret=2)
        # Script uses priv1's hash160
        h160 = priv1.point.hash160()
        script_pubkey = Script([0, h160])
        prev_out = TxOut(50000, script_pubkey)

        tx_in = TxIn(bytes(32), 0)
        tx_in._script_pubkey = script_pubkey

        # But named pub is priv2's point (different hash160)
        np = priv2.point
        np.__class__ = NamedPublicKey
        np.add_raw_path_data(bytes(4) + serialize_binary_path("m/44'/0'/0'/0/0"))

        named_pubs = {np.sec(): np}
        with self.assertRaises(ValueError) as cm:
            PSBTIn(tx_in, prev_out=prev_out, named_pubs=named_pubs)
        self.assertIn("does not match the hash160", str(cm.exception))

    def test_redeem_script_for_non_p2sh(self):
        """Covers lines 1191-1192: RedeemScript defined for non-p2sh"""
        prev_tx = Tx(
            2,
            [TxIn(bytes(32), 0)],
            [TxOut(50000, Script([0x76, 0xA9, bytes(20), 0x88, 0xAC]))],
            0,
        )
        tx_in = TxIn(prev_tx.hash(), 0)
        redeem_script = RedeemScript([0, bytes(20)])

        with self.assertRaises(ValueError) as cm:
            PSBTIn(tx_in, prev_tx=prev_tx, redeem_script=redeem_script)
        self.assertIn("non-p2sh", str(cm.exception))

    def test_non_witness_utxo_for_witness_redeem(self):
        """Covers lines 1194-1195: Non-witness UTXO with witness redeem_script"""
        # Create a p2sh output
        inner_script = RedeemScript([0, bytes(20)])  # p2wpkh inside
        p2sh_script = Script([0xA9, inner_script.hash160(), 0x87])
        prev_tx = Tx(
            2,
            [TxIn(bytes(32), 0)],
            [TxOut(50000, p2sh_script)],
            0,
        )
        tx_in = TxIn(prev_tx.hash(), 0)

        with self.assertRaises(ValueError) as cm:
            PSBTIn(tx_in, prev_tx=prev_tx, redeem_script=inner_script)
        self.assertIn("Non-witness UTXO provided for witness input", str(cm.exception))

    def test_too_many_pubkeys_p2pkh(self):
        """Covers lines 1208-1209: too many pubkeys in p2pkh"""
        priv1 = PrivateKey(secret=1)
        priv2 = PrivateKey(secret=2)
        p2pkh_script = Script([0x76, 0xA9, priv1.point.hash160(), 0x88, 0xAC])
        prev_tx = Tx(
            2,
            [TxIn(bytes(32), 0)],
            [TxOut(50000, p2pkh_script)],
            0,
        )
        tx_in = TxIn(prev_tx.hash(), 0)

        np1 = priv1.point
        np1.__class__ = NamedPublicKey
        np1.add_raw_path_data(bytes(4) + serialize_binary_path("m/44'/0'/0'/0/0"))
        np2 = priv2.point
        np2.__class__ = NamedPublicKey
        np2.add_raw_path_data(bytes(4) + serialize_binary_path("m/44'/0'/0'/0/1"))

        named_pubs = {np1.sec(): np1, np2.sec(): np2}
        with self.assertRaises(ValueError) as cm:
            PSBTIn(tx_in, prev_tx=prev_tx, named_pubs=named_pubs)
        self.assertIn("too many pubkeys", str(cm.exception))

    def test_p2pkh_hash160_mismatch(self):
        """Covers lines 1212-1216: p2pkh pubkey doesn't match hash160"""
        priv1 = PrivateKey(secret=1)
        priv2 = PrivateKey(secret=2)
        p2pkh_script = Script([0x76, 0xA9, priv1.point.hash160(), 0x88, 0xAC])
        prev_tx = Tx(
            2,
            [TxIn(bytes(32), 0)],
            [TxOut(50000, p2pkh_script)],
            0,
        )
        tx_in = TxIn(prev_tx.hash(), 0)

        # Named pub is priv2 but script expects priv1
        np = priv2.point
        np.__class__ = NamedPublicKey
        np.add_raw_path_data(bytes(4) + serialize_binary_path("m/44'/0'/0'/0/0"))

        named_pubs = {np.sec(): np}
        with self.assertRaises(ValueError) as cm:
            PSBTIn(tx_in, prev_tx=prev_tx, named_pubs=named_pubs)
        self.assertIn("does not match the hash160", str(cm.exception))


class PSBTInParseTest(TestCase):
    def test_parse_duplicate_non_witness_utxo(self):
        """Covers line 1251: duplicate non-witness UTXO key"""
        prev_tx = Tx(
            2,
            [TxIn(bytes(32), 0)],
            [TxOut(50000, Script([0x76, 0xA9, bytes(20), 0x88, 0xAC]))],
            0,
        )
        tx_in = TxIn(prev_tx.hash(), 0)
        tx_bytes = prev_tx.serialize()

        # Build PSBTIn data with duplicate PSBT_IN_NON_WITNESS_UTXO
        data = b""
        data += serialize_key_value(PSBT_IN_NON_WITNESS_UTXO, tx_bytes)
        data += serialize_key_value(PSBT_IN_NON_WITNESS_UTXO, tx_bytes)
        data += PSBT_DELIMITER

        with self.assertRaises(KeyError):
            PSBTIn.parse(BytesIO(data), tx_in)

    def test_parse_duplicate_witness_utxo(self):
        """Covers line 1263: duplicate witness UTXO key"""
        tx_out = TxOut(50000, Script([0, bytes(20)]))
        tx_in = TxIn(bytes(32), 0)
        tx_out_bytes = tx_out.serialize()

        data = b""
        data += serialize_key_value(PSBT_IN_WITNESS_UTXO, tx_out_bytes)
        data += serialize_key_value(PSBT_IN_WITNESS_UTXO, tx_out_bytes)
        data += PSBT_DELIMITER

        with self.assertRaises(KeyError):
            PSBTIn.parse(BytesIO(data), tx_in)

    def test_parse_witness_utxo_length_mismatch(self):
        """Covers line 1266: tx out length mismatch"""
        tx_out = TxOut(50000, Script([0, bytes(20)]))
        tx_in = TxIn(bytes(32), 0)
        tx_out_bytes = tx_out.serialize()

        # Manually construct with wrong length prefix
        key_data = encode_varstr(PSBT_IN_WITNESS_UTXO)
        # Claim the value is longer than it actually is
        from buidl.helper import encode_varint

        bad_data = (
            key_data + encode_varint(len(tx_out_bytes) + 5) + tx_out_bytes + b"\x00" * 5
        )
        bad_data += PSBT_DELIMITER

        with self.assertRaises(ValueError) as cm:
            PSBTIn.parse(BytesIO(bad_data), tx_in)
        self.assertIn("length does not match", str(cm.exception))

    def test_parse_duplicate_sighash(self):
        """Covers line 1277: duplicate sighash type"""
        tx_in = TxIn(bytes(32), 0)
        sighash_val = int_to_little_endian(SIGHASH_ALL, 4)

        data = b""
        data += serialize_key_value(PSBT_IN_SIGHASH_TYPE, sighash_val)
        data += serialize_key_value(PSBT_IN_SIGHASH_TYPE, sighash_val)
        data += PSBT_DELIMITER

        with self.assertRaises(KeyError):
            PSBTIn.parse(BytesIO(data), tx_in)

    def test_parse_duplicate_redeem_script(self):
        """Covers line 1283: duplicate redeem_script"""
        tx_in = TxIn(bytes(32), 0)
        rs = RedeemScript([0, bytes(20)])
        rs_bytes = rs.raw_serialize()

        data = b""
        data += serialize_key_value(b"\x04", rs_bytes)  # PSBT_IN_REDEEM_SCRIPT
        data += serialize_key_value(b"\x04", rs_bytes)
        data += PSBT_DELIMITER

        with self.assertRaises(KeyError):
            PSBTIn.parse(BytesIO(data), tx_in)

    def test_parse_duplicate_witness_script(self):
        """Covers line 1289: duplicate witness_script"""
        tx_in = TxIn(bytes(32), 0)
        priv1 = PrivateKey(secret=1)
        priv2 = PrivateKey(secret=2)
        ws = WitnessScript([0x52, priv1.point.sec(), priv2.point.sec(), 0x52, 0xAE])
        ws_bytes = ws.raw_serialize()

        data = b""
        data += serialize_key_value(b"\x05", ws_bytes)  # PSBT_IN_WITNESS_SCRIPT
        data += serialize_key_value(b"\x05", ws_bytes)
        data += PSBT_DELIMITER

        with self.assertRaises(KeyError):
            PSBTIn.parse(BytesIO(data), tx_in)

    def test_parse_duplicate_final_scriptsig(self):
        """Covers line 1300: duplicate final scriptsig"""
        tx_in = TxIn(bytes(32), 0)
        ss = Script([b"\x00"])
        ss_bytes = ss.raw_serialize()

        data = b""
        data += serialize_key_value(b"\x07", ss_bytes)  # PSBT_IN_FINAL_SCRIPTSIG
        data += serialize_key_value(b"\x07", ss_bytes)
        data += PSBT_DELIMITER

        with self.assertRaises(KeyError):
            PSBTIn.parse(BytesIO(data), tx_in)

    def test_parse_duplicate_final_witness(self):
        """Covers line 1306: duplicate final scriptwitness"""
        tx_in = TxIn(bytes(32), 0)
        w = Witness([b"\x00"])
        w_bytes = w.serialize()

        data = b""
        data += serialize_key_value(b"\x08", w_bytes)  # PSBT_IN_FINAL_SCRIPTWITNESS
        data += serialize_key_value(b"\x08", w_bytes)
        data += PSBT_DELIMITER

        with self.assertRaises(KeyError):
            PSBTIn.parse(BytesIO(data), tx_in)

    def test_parse_duplicate_extra_key(self):
        """Covers line 1311: duplicate extra key"""
        tx_in = TxIn(bytes(32), 0)
        extra_key = b"\xfc\x01"
        extra_val = b"\x01\x02"

        data = b""
        data += serialize_key_value(extra_key, extra_val)
        data += serialize_key_value(extra_key, extra_val)
        data += PSBT_DELIMITER

        with self.assertRaises(KeyError):
            PSBTIn.parse(BytesIO(data), tx_in)


class PSBTInCombineTest(TestCase):
    def test_combine_fields(self):
        """Covers lines 1493-1521: PSBTIn.combine with various fields"""
        tx_in = TxIn(bytes(32), 0)
        psbt_in_1 = PSBTIn(tx_in)

        # Create second PSBTIn with more data
        prev_tx = Tx(
            2,
            [TxIn(bytes(32), 0)],
            [TxOut(50000, Script([0x76, 0xA9, bytes(20), 0x88, 0xAC]))],
            0,
        )
        tx_in_2 = TxIn(prev_tx.hash(), 0)
        TxOut(50000, Script([0, bytes(20)]))

        psbt_in_2 = PSBTIn(
            tx_in_2,
            prev_tx=prev_tx,
            hash_type=SIGHASH_ALL,
        )

        # Combine: fields from psbt_in_2 should transfer to psbt_in_1
        psbt_in_1.combine(psbt_in_2)
        self.assertIsNotNone(psbt_in_1.prev_tx)
        self.assertEqual(psbt_in_1.hash_type, SIGHASH_ALL)

    def test_combine_prev_out_and_scripts(self):
        """Covers lines 1499-1500, 1507-1511, 1515-1519: combine prev_out, scripts, witness"""
        tx_in = TxIn(bytes(32), 0)
        psbt_in_1 = PSBTIn(tx_in)

        p2wpkh_script = Script([0, bytes(20)])
        prev_out = TxOut(50000, p2wpkh_script)

        tx_in_2 = TxIn(bytes(32), 0)
        tx_in_2._script_pubkey = p2wpkh_script
        psbt_in_2 = PSBTIn(tx_in_2, prev_out=prev_out)
        # Manually set fields after construction to avoid validate() issues
        psbt_in_2.script_sig = Script([b"\x00"])
        psbt_in_2.witness = Witness([b"\x00"])

        psbt_in_1.combine(psbt_in_2)
        self.assertIsNotNone(psbt_in_1.prev_out)
        self.assertIsNotNone(psbt_in_1.script_sig)
        self.assertIsNotNone(psbt_in_1.witness)


class PSBTInFinalizeTest(TestCase):
    def test_finalize_p2wpkh_no_redeem(self):
        """Covers lines 1534-1552: finalize p2wpkh without redeem_script"""
        priv = PrivateKey(secret=12345)
        h160 = priv.point.hash160()
        script_pubkey = Script([0, h160])
        prev_out = TxOut(50000, script_pubkey)

        tx_in = TxIn(bytes(32), 0)
        tx_in._script_pubkey = script_pubkey

        # Add a signature
        fake_sig = priv.sign(int.from_bytes(bytes(32), "big")).der() + bytes(
            [SIGHASH_ALL]
        )
        sigs = {priv.point.sec(): fake_sig}

        psbt_in = PSBTIn(tx_in, prev_out=prev_out, sigs=sigs)
        psbt_in.finalize()

        self.assertIsNotNone(psbt_in.witness)
        self.assertEqual(len(psbt_in.witness), 2)
        # Script should be empty (no redeem_script)
        self.assertEqual(psbt_in.script_sig.commands, [])

    def test_finalize_p2wpkh_wrong_sig_count(self):
        """Covers lines 1538-1541: p2wpkh with != 1 signature"""
        priv = PrivateKey(secret=12345)
        h160 = priv.point.hash160()
        script_pubkey = Script([0, h160])
        prev_out = TxOut(50000, script_pubkey)

        tx_in = TxIn(bytes(32), 0)
        tx_in._script_pubkey = script_pubkey

        # No signatures
        psbt_in = PSBTIn(tx_in, prev_out=prev_out)
        with self.assertRaises(RuntimeError) as cm:
            psbt_in.finalize()
        self.assertIn("exactly 1 signature", str(cm.exception))

    def test_finalize_p2wsh_no_witness_script(self):
        """Covers lines 1558-1561: p2wsh without WitnessScript"""
        script_pubkey = Script([0, bytes(32)])  # p2wsh
        prev_out = TxOut(50000, script_pubkey)

        tx_in = TxIn(bytes(32), 0)
        tx_in._script_pubkey = script_pubkey

        psbt_in = PSBTIn(tx_in, prev_out=prev_out)
        with self.assertRaises(RuntimeError) as cm:
            psbt_in.finalize()
        self.assertIn("WitnessScript", str(cm.exception))

    def test_finalize_p2wsh_not_enough_sigs(self):
        """Covers lines 1565-1568: p2wsh with insufficient signatures"""
        priv1 = PrivateKey(secret=1)
        priv2 = PrivateKey(secret=2)
        ws = WitnessScript([0x52, priv1.point.sec(), priv2.point.sec(), 0x52, 0xAE])

        script_pubkey = Script([0, ws.sha256()])
        prev_out = TxOut(50000, script_pubkey)

        tx_in = TxIn(bytes(32), 0)
        tx_in._script_pubkey = script_pubkey

        # Only provide 1 sig for 2-of-2
        fake_sig = priv1.sign(int.from_bytes(bytes(32), "big")).der() + bytes(
            [SIGHASH_ALL]
        )
        sigs = {priv1.point.sec(): fake_sig}

        psbt_in = PSBTIn(
            tx_in,
            prev_out=prev_out,
            witness_script=ws,
            sigs=sigs,
        )
        with self.assertRaises(RuntimeError) as cm:
            psbt_in.finalize()
        self.assertIn("sigs were provided", str(cm.exception))

    def test_finalize_p2sh_not_enough_sigs(self):
        """Covers lines 1595-1621: finalize p2sh multisig with not enough sigs"""
        priv1 = PrivateKey(secret=1)
        priv2 = PrivateKey(secret=2)
        rs = RedeemScript([0x52, priv1.point.sec(), priv2.point.sec(), 0x52, 0xAE])

        p2sh_script = Script([0xA9, rs.hash160(), 0x87])
        prev_tx = Tx(
            2,
            [TxIn(bytes(32), 0)],
            [TxOut(50000, p2sh_script)],
            0,
        )
        tx_in = TxIn(prev_tx.hash(), 0)

        # Only 1 sig for 2-of-2
        fake_sig = priv1.sign(int.from_bytes(bytes(32), "big")).der() + bytes(
            [SIGHASH_ALL]
        )
        sigs = {priv1.point.sec(): fake_sig}

        psbt_in = PSBTIn(
            tx_in,
            prev_tx=prev_tx,
            redeem_script=rs,
            sigs=sigs,
        )
        with self.assertRaises(RuntimeError) as cm:
            psbt_in.finalize()
        self.assertIn("sigs were provided", str(cm.exception))

    def test_finalize_p2pkh(self):
        """Covers lines 1626-1635: finalize p2pkh"""
        priv = PrivateKey(secret=12345)
        p2pkh_script = Script([0x76, 0xA9, priv.point.hash160(), 0x88, 0xAC])
        prev_tx = Tx(
            2,
            [TxIn(bytes(32), 0)],
            [TxOut(50000, p2pkh_script)],
            0,
        )
        tx_in = TxIn(prev_tx.hash(), 0)

        fake_sig = priv.sign(int.from_bytes(bytes(32), "big")).der() + bytes(
            [SIGHASH_ALL]
        )
        sigs = {priv.point.sec(): fake_sig}

        psbt_in = PSBTIn(tx_in, prev_tx=prev_tx, sigs=sigs)
        psbt_in.finalize()

        self.assertIsNotNone(psbt_in.script_sig)
        self.assertEqual(len(psbt_in.script_sig.commands), 2)
        # sigs/named_pubs should be cleared after finalize
        self.assertEqual(psbt_in.sigs, {})
        self.assertEqual(psbt_in.named_pubs, {})

    def test_finalize_p2pkh_wrong_sig_count(self):
        """Covers lines 1628-1629: p2pkh with != 1 signature"""
        priv = PrivateKey(secret=12345)
        p2pkh_script = Script([0x76, 0xA9, priv.point.hash160(), 0x88, 0xAC])
        prev_tx = Tx(
            2,
            [TxIn(bytes(32), 0)],
            [TxOut(50000, p2pkh_script)],
            0,
        )
        tx_in = TxIn(prev_tx.hash(), 0)

        psbt_in = PSBTIn(tx_in, prev_tx=prev_tx)
        with self.assertRaises(RuntimeError) as cm:
            psbt_in.finalize()
        self.assertIn("exactly 1 signature", str(cm.exception))

    def test_finalize_unknown_script_type(self):
        """Covers line 1637: unknown script type raises ValueError"""
        # OP_RETURN output - not a standard spendable type
        script_pubkey = Script([0x6A, bytes(20)])  # OP_RETURN
        prev_tx = Tx(
            2,
            [TxIn(bytes(32), 0)],
            [TxOut(0, script_pubkey)],
            0,
        )
        tx_in = TxIn(prev_tx.hash(), 0)

        psbt_in = PSBTIn(tx_in, prev_tx=prev_tx)
        with self.assertRaises(ValueError) as cm:
            psbt_in.finalize()
        self.assertIn("Cannot finalize", str(cm.exception))


class PSBTOutValidateTest(TestCase):
    def test_p2pkh_with_redeem_script(self):
        """Covers lines 1666-1667: RedeemScript in p2pkh output"""
        p2pkh_script = Script([0x76, 0xA9, bytes(20), 0x88, 0xAC])
        tx_out = TxOut(50000, p2pkh_script)
        rs = RedeemScript([0, bytes(20)])

        with self.assertRaises(KeyError) as cm:
            PSBTOut(tx_out, redeem_script=rs)
        self.assertIn("RedeemScript included in p2pkh", str(cm.exception))

    def test_p2pkh_with_witness_script(self):
        """Covers lines 1668-1669: WitnessScript in p2pkh output"""
        p2pkh_script = Script([0x76, 0xA9, bytes(20), 0x88, 0xAC])
        tx_out = TxOut(50000, p2pkh_script)
        priv = PrivateKey(secret=1)
        ws = WitnessScript([0x52, priv.point.sec(), 0x51, 0xAE])

        with self.assertRaises(KeyError) as cm:
            PSBTOut(tx_out, witness_script=ws)
        self.assertIn("WitnessScript included in p2pkh", str(cm.exception))

    def test_p2pkh_too_many_pubkeys(self):
        """Covers lines 1670-1671: too many pubkeys in p2pkh output"""
        priv1 = PrivateKey(secret=1)
        priv2 = PrivateKey(secret=2)
        p2pkh_script = Script([0x76, 0xA9, priv1.point.hash160(), 0x88, 0xAC])
        tx_out = TxOut(50000, p2pkh_script)

        np1 = priv1.point
        np1.__class__ = NamedPublicKey
        np1.add_raw_path_data(bytes(4) + serialize_binary_path("m/44'/0'/0'/0/0"))
        np2 = priv2.point
        np2.__class__ = NamedPublicKey
        np2.add_raw_path_data(bytes(4) + serialize_binary_path("m/44'/0'/0'/0/1"))

        with self.assertRaises(ValueError) as cm:
            PSBTOut(tx_out, named_pubs={np1.sec(): np1, np2.sec(): np2})
        self.assertIn("too many pubkeys", str(cm.exception))

    def test_p2pkh_hash160_mismatch(self):
        """Covers lines 1674-1679: pubkey hash mismatch in p2pkh output"""
        priv1 = PrivateKey(secret=1)
        priv2 = PrivateKey(secret=2)
        p2pkh_script = Script([0x76, 0xA9, priv1.point.hash160(), 0x88, 0xAC])
        tx_out = TxOut(50000, p2pkh_script)

        np = priv2.point
        np.__class__ = NamedPublicKey
        np.add_raw_path_data(bytes(4) + serialize_binary_path("m/44'/0'/0'/0/0"))

        with self.assertRaises(ValueError) as cm:
            PSBTOut(tx_out, named_pubs={np.sec(): np})
        self.assertIn("does not match the hash160", str(cm.exception))

    def test_p2wpkh_with_redeem_script(self):
        """Covers lines 1681-1682: RedeemScript in p2wpkh output"""
        p2wpkh_script = Script([0, bytes(20)])
        tx_out = TxOut(50000, p2wpkh_script)
        rs = RedeemScript([0, bytes(20)])

        with self.assertRaises(KeyError) as cm:
            PSBTOut(tx_out, redeem_script=rs)
        self.assertIn("RedeemScript included in p2wpkh", str(cm.exception))

    def test_p2wpkh_with_witness_script(self):
        """Covers lines 1683-1684: WitnessScript in p2wpkh output"""
        p2wpkh_script = Script([0, bytes(20)])
        tx_out = TxOut(50000, p2wpkh_script)
        priv = PrivateKey(secret=1)
        ws = WitnessScript([0x52, priv.point.sec(), 0x51, 0xAE])

        with self.assertRaises(KeyError) as cm:
            PSBTOut(tx_out, witness_script=ws)
        self.assertIn("WitnessScript included in p2wpkh", str(cm.exception))

    def test_p2wpkh_too_many_pubkeys(self):
        """Covers lines 1685-1686: too many pubkeys in p2wpkh output"""
        priv1 = PrivateKey(secret=1)
        priv2 = PrivateKey(secret=2)
        h160 = priv1.point.hash160()
        p2wpkh_script = Script([0, h160])
        tx_out = TxOut(50000, p2wpkh_script)

        np1 = priv1.point
        np1.__class__ = NamedPublicKey
        np1.add_raw_path_data(bytes(4) + serialize_binary_path("m/44'/0'/0'/0/0"))
        np2 = priv2.point
        np2.__class__ = NamedPublicKey
        np2.add_raw_path_data(bytes(4) + serialize_binary_path("m/44'/0'/0'/0/1"))

        with self.assertRaises(ValueError) as cm:
            PSBTOut(tx_out, named_pubs={np1.sec(): np1, np2.sec(): np2})
        self.assertIn("too many pubkeys", str(cm.exception))

    def test_p2wpkh_hash160_mismatch(self):
        """Covers lines 1689-1694: pubkey hash mismatch in p2wpkh output"""
        priv1 = PrivateKey(secret=1)
        priv2 = PrivateKey(secret=2)
        h160 = priv1.point.hash160()
        p2wpkh_script = Script([0, h160])
        tx_out = TxOut(50000, p2wpkh_script)

        np = priv2.point
        np.__class__ = NamedPublicKey
        np.add_raw_path_data(bytes(4) + serialize_binary_path("m/44'/0'/0'/0/0"))

        with self.assertRaises(ValueError) as cm:
            PSBTOut(tx_out, named_pubs={np.sec(): np})
        self.assertIn("does not match the hash160", str(cm.exception))


class PSBTOutParseTest(TestCase):
    def test_parse_duplicate_redeem_script(self):
        """Covers line 1746: duplicate redeem_script in output"""
        tx_out = TxOut(50000, Script([0xA9, bytes(20), 0x87]))
        rs = RedeemScript([0, bytes(20)])
        rs_bytes = rs.raw_serialize()

        data = b""
        data += serialize_key_value(b"\x00", rs_bytes)  # PSBT_OUT_REDEEM_SCRIPT
        data += serialize_key_value(b"\x00", rs_bytes)
        data += PSBT_DELIMITER

        with self.assertRaises(KeyError):
            PSBTOut.parse(BytesIO(data), tx_out)

    def test_parse_duplicate_witness_script(self):
        """Covers line 1752: duplicate witness_script in output"""
        priv = PrivateKey(secret=1)
        ws = WitnessScript([0x51, priv.point.sec(), 0x51, 0xAE])
        tx_out = TxOut(50000, Script([0, ws.sha256()]))
        ws_bytes = ws.raw_serialize()

        data = b""
        data += serialize_key_value(b"\x01", ws_bytes)  # PSBT_OUT_WITNESS_SCRIPT
        data += serialize_key_value(b"\x01", ws_bytes)
        data += PSBT_DELIMITER

        with self.assertRaises(KeyError):
            PSBTOut.parse(BytesIO(data), tx_out)

    def test_parse_duplicate_extra_key(self):
        """Covers line 1761: duplicate extra key in output"""
        tx_out = TxOut(50000, Script([0, bytes(20)]))
        extra_key = b"\xfc\x01"
        extra_val = b"\x01\x02"

        data = b""
        data += serialize_key_value(extra_key, extra_val)
        data += serialize_key_value(extra_key, extra_val)
        data += PSBT_DELIMITER

        with self.assertRaises(KeyError):
            PSBTOut.parse(BytesIO(data), tx_out)


class PSBTOutUpdateTest(OfflineTestCase):
    def _make_hd_and_lookup(self):
        """Helper: returns NamedHDPublicKey and derived lookup dicts."""
        hex_named_hd = "4f01043587cf0398242fbc80000000959cb81379545d7a34287f41485a3c08fc6ecf66cb89caff8a4f618b484d6e7d0362f19f492715b6041723d97403f166da0e3246eb614d80635c036a8d2f75339310797dcdac2c0000800100008000000080"
        stream = BytesIO(bytes.fromhex(hex_named_hd))
        named_hd = NamedHDPublicKey.parse(read_varstr(stream), stream)
        return named_hd

    def test_update_p2sh_no_redeem(self):
        """Covers lines 1793-1796: p2sh output with no matching redeem_script returns early"""
        p2sh_script = Script([0xA9, bytes(20), 0x87])
        tx_out = TxOut(50000, p2sh_script)
        psbt_out = PSBTOut(tx_out)
        psbt_out.update({}, {}, {})
        self.assertIsNone(psbt_out.redeem_script)

    def test_update_p2sh_p2wpkh(self):
        """Covers lines 1798-1809: p2sh-p2wpkh output update with redeem_script"""
        named_hd = self._make_hd_and_lookup()
        pubkey_lookup = named_hd.bip44_lookup()
        redeem_lookup = named_hd.redeem_script_lookup()

        # Find a child's hash160 to build a proper p2sh-p2wpkh output
        child = named_hd.child(0).child(0)
        redeem_script = RedeemScript([0, child.hash160()])
        p2sh_script = Script([0xA9, redeem_script.hash160(), 0x87])
        tx_out = TxOut(50000, p2sh_script)
        psbt_out = PSBTOut(tx_out)

        psbt_out.update(pubkey_lookup, redeem_lookup, {})
        self.assertIsNotNone(psbt_out.redeem_script)

    def test_update_p2pkh(self):
        """Covers lines 1841-1849: p2pkh output update"""
        named_hd = self._make_hd_and_lookup()
        pubkey_lookup = named_hd.bip44_lookup()

        # Get a child's hash160 for p2pkh
        child = named_hd.child(0).child(0)
        h160 = child.hash160()
        p2pkh_script = Script([0x76, 0xA9, h160, 0x88, 0xAC])
        tx_out = TxOut(50000, p2pkh_script)
        psbt_out = PSBTOut(tx_out)

        psbt_out.update(pubkey_lookup, {}, {})
        self.assertEqual(len(psbt_out.named_pubs), 1)

    def test_update_p2wsh(self):
        """Covers lines 1811-1829: p2wsh output update"""
        hex_named_hd_1 = "4f01043587cf034d513c1580000000fb406c9fec09b6957a3449d2102318717b0c0d230b657d0ebc6698abd52145eb02eaf3397fea02c5dac747888a9e535eaf3c7e7cb9d5f2da77ddbdd943592a14af10fbfef36f2c0000800100008000000080"
        hex_named_hd_2 = "4f01043587cf0398242fbc80000000959cb81379545d7a34287f41485a3c08fc6ecf66cb89caff8a4f618b484d6e7d0362f19f492715b6041723d97403f166da0e3246eb614d80635c036a8d2f75339310797dcdac2c0000800100008000000080"
        stream_1 = BytesIO(bytes.fromhex(hex_named_hd_1))
        stream_2 = BytesIO(bytes.fromhex(hex_named_hd_2))
        hd_1 = NamedHDPublicKey.parse(read_varstr(stream_1), stream_1)
        hd_2 = NamedHDPublicKey.parse(read_varstr(stream_2), stream_2)
        pubkey_lookup = {**hd_1.bip44_lookup(), **hd_2.bip44_lookup()}

        # Build a witness script from child keys
        child_1 = hd_1.child(0).child(0)
        child_2 = hd_2.child(0).child(0)
        ws = WitnessScript([0x52, child_1.sec(), child_2.sec(), 0x52, 0xAE])

        p2wsh_script = Script([0, ws.sha256()])
        tx_out = TxOut(50000, p2wsh_script)
        psbt_out = PSBTOut(tx_out)

        witness_lookup = {ws.sha256(): ws}
        psbt_out.update(pubkey_lookup, {}, witness_lookup)
        self.assertIsNotNone(psbt_out.witness_script)
        self.assertTrue(len(psbt_out.named_pubs) >= 1)

    def test_update_p2sh_p2wsh(self):
        """Covers lines 1811-1816: p2sh-p2wsh output update"""
        hex_named_hd_1 = "4f01043587cf034d513c1580000000fb406c9fec09b6957a3449d2102318717b0c0d230b657d0ebc6698abd52145eb02eaf3397fea02c5dac747888a9e535eaf3c7e7cb9d5f2da77ddbdd943592a14af10fbfef36f2c0000800100008000000080"
        hex_named_hd_2 = "4f01043587cf0398242fbc80000000959cb81379545d7a34287f41485a3c08fc6ecf66cb89caff8a4f618b484d6e7d0362f19f492715b6041723d97403f166da0e3246eb614d80635c036a8d2f75339310797dcdac2c0000800100008000000080"
        stream_1 = BytesIO(bytes.fromhex(hex_named_hd_1))
        stream_2 = BytesIO(bytes.fromhex(hex_named_hd_2))
        hd_1 = NamedHDPublicKey.parse(read_varstr(stream_1), stream_1)
        hd_2 = NamedHDPublicKey.parse(read_varstr(stream_2), stream_2)
        pubkey_lookup = {**hd_1.bip44_lookup(), **hd_2.bip44_lookup()}

        child_1 = hd_1.child(0).child(0)
        child_2 = hd_2.child(0).child(0)
        ws = WitnessScript([0x52, child_1.sec(), child_2.sec(), 0x52, 0xAE])
        inner = RedeemScript([0, ws.sha256()])
        p2sh_script = Script([0xA9, inner.hash160(), 0x87])
        tx_out = TxOut(50000, p2sh_script)
        psbt_out = PSBTOut(tx_out)

        redeem_lookup = {inner.hash160(): inner}
        witness_lookup = {ws.sha256(): ws}
        psbt_out.update(pubkey_lookup, redeem_lookup, witness_lookup)
        self.assertIsNotNone(psbt_out.witness_script)
        self.assertTrue(len(psbt_out.named_pubs) >= 1)

    def test_update_p2sh_bare_multisig(self):
        """Covers lines 1831-1839: p2sh bare (non-witness) output update"""
        hex_named_hd_1 = "4f01043587cf034d513c1580000000fb406c9fec09b6957a3449d2102318717b0c0d230b657d0ebc6698abd52145eb02eaf3397fea02c5dac747888a9e535eaf3c7e7cb9d5f2da77ddbdd943592a14af10fbfef36f2c0000800100008000000080"
        hex_named_hd_2 = "4f01043587cf0398242fbc80000000959cb81379545d7a34287f41485a3c08fc6ecf66cb89caff8a4f618b484d6e7d0362f19f492715b6041723d97403f166da0e3246eb614d80635c036a8d2f75339310797dcdac2c0000800100008000000080"
        stream_1 = BytesIO(bytes.fromhex(hex_named_hd_1))
        stream_2 = BytesIO(bytes.fromhex(hex_named_hd_2))
        hd_1 = NamedHDPublicKey.parse(read_varstr(stream_1), stream_1)
        hd_2 = NamedHDPublicKey.parse(read_varstr(stream_2), stream_2)
        pubkey_lookup = {**hd_1.bip44_lookup(), **hd_2.bip44_lookup()}

        child_1 = hd_1.child(0).child(0)
        child_2 = hd_2.child(0).child(0)
        rs = RedeemScript([0x52, child_1.sec(), child_2.sec(), 0x52, 0xAE])
        p2sh_script = Script([0xA9, rs.hash160(), 0x87])
        tx_out = TxOut(50000, p2sh_script)
        psbt_out = PSBTOut(tx_out)

        redeem_lookup = {rs.hash160(): rs}
        psbt_out.update(pubkey_lookup, redeem_lookup, {})
        self.assertTrue(len(psbt_out.named_pubs) >= 1)


class PSBTOutCombineTest(TestCase):
    def test_combine_fields(self):
        """Covers lines 1851-1862: PSBTOut.combine with various fields"""
        tx_out = TxOut(50000, Script([0, bytes(20)]))
        psbt_out_1 = PSBTOut(tx_out)

        priv = PrivateKey(secret=1)
        rs = RedeemScript([0, bytes(20)])
        ws = WitnessScript([0x51, priv.point.sec(), 0x51, 0xAE])

        # Second output with redeem/witness scripts
        tx_out_2 = TxOut(50000, Script([0, bytes(20)]))
        psbt_out_2 = PSBTOut(tx_out_2)
        psbt_out_2.redeem_script = rs
        psbt_out_2.witness_script = ws

        psbt_out_1.combine(psbt_out_2)
        self.assertIsNotNone(psbt_out_1.redeem_script)
        self.assertIsNotNone(psbt_out_1.witness_script)


class PSBTInUpdateTest(OfflineTestCase):
    def test_update_no_prev(self):
        """Covers lines 1411-1412: update with no prev_tx or prev_out returns early"""
        tx_in = TxIn(bytes.fromhex("ff" * 32), 0)
        psbt_in = PSBTIn(tx_in)
        psbt_in.update({}, {}, {}, {})
        self.assertIsNone(psbt_in.prev_tx)

    def test_update_p2sh_no_redeem(self):
        """Covers lines 1426-1427: p2sh input without matching redeem_script returns early"""
        p2sh_script = Script([0xA9, bytes(20), 0x87])
        prev_tx = Tx(
            2,
            [TxIn(bytes(32), 0)],
            [TxOut(50000, p2sh_script)],
            0,
        )
        tx_in = TxIn(prev_tx.hash(), 0)
        tx_lookup = {prev_tx.hash(): prev_tx}
        psbt_in = PSBTIn(tx_in)
        psbt_in.update(tx_lookup, {}, {}, {})
        self.assertIsNone(psbt_in.redeem_script)

    def test_update_unknown_script_type(self):
        """Covers lines 1488-1491: unsupported script type raises ValueError"""
        op_return_script = Script([0x6A, bytes(20)])
        prev_tx = Tx(
            2,
            [TxIn(bytes(32), 0)],
            [TxOut(0, op_return_script)],
            0,
        )
        tx_in = TxIn(prev_tx.hash(), 0)
        tx_lookup = {prev_tx.hash(): prev_tx}
        psbt_in = PSBTIn(tx_in)
        with self.assertRaises(ValueError) as cm:
            psbt_in.update(tx_lookup, {}, {}, {})
        self.assertIn("cannot update", str(cm.exception))


class PSBTValidateOutputMismatchTest(TestCase):
    def test_output_count_mismatch(self):
        """Covers lines 317-320: PSBT.validate with output count mismatch"""
        tx_in = TxIn(bytes(32), 0)
        tx_out = TxOut(50000, Script([0, bytes(20)]))
        tx_obj = Tx(2, [tx_in], [tx_out], 0)

        # Create with mismatched psbt_outs count
        psbt_in = PSBTIn(tx_in)
        psbt_out_1 = PSBTOut(tx_out)
        psbt_out_2 = PSBTOut(TxOut(25000, Script([0, bytes(20)])))

        with self.assertRaises(ValueError) as cm:
            PSBT(tx_obj, [psbt_in], [psbt_out_1, psbt_out_2])
        self.assertIn("psbt_outs", str(cm.exception))


class PSBTInWitnessScriptValidateTest(TestCase):
    def test_witness_script_sha256_mismatch(self):
        """Covers lines 1165-1168: WitnessScript sha256 mismatch"""
        priv1 = PrivateKey(secret=1)
        priv2 = PrivateKey(secret=2)

        # Create a proper witness script
        ws = WitnessScript([0x52, priv1.point.sec(), priv2.point.sec(), 0x52, 0xAE])

        # But use a DIFFERENT sha256 in the script_pubkey
        wrong_hash = bytes(32)  # all zeros
        script_pubkey = Script([0, wrong_hash])
        prev_out = TxOut(50000, script_pubkey)

        tx_in = TxIn(bytes(32), 0)
        tx_in._script_pubkey = script_pubkey

        with self.assertRaises(ValueError) as cm:
            PSBTIn(tx_in, prev_out=prev_out, witness_script=ws)
        self.assertIn("sha256", str(cm.exception))

    def test_pubkey_not_in_witness_script(self):
        """Covers lines 1173-1174: pubkey not found in WitnessScript"""
        priv1 = PrivateKey(secret=1)
        priv2 = PrivateKey(secret=2)
        priv3 = PrivateKey(secret=3)

        ws = WitnessScript([0x52, priv1.point.sec(), priv2.point.sec(), 0x52, 0xAE])
        script_pubkey = Script([0, ws.sha256()])
        prev_out = TxOut(50000, script_pubkey)

        tx_in = TxIn(bytes(32), 0)
        tx_in._script_pubkey = script_pubkey

        # Add named pub for priv3 which is NOT in the witness script
        np = priv3.point
        np.__class__ = NamedPublicKey
        np.add_raw_path_data(bytes(4) + serialize_binary_path("m/44'/0'/0'/0/0"))

        with self.assertRaises(ValueError) as cm:
            PSBTIn(
                tx_in, prev_out=prev_out, witness_script=ws, named_pubs={np.sec(): np}
            )
        self.assertIn("not in WitnessScript", str(cm.exception))


class PSBTInFinalizeP2shNoRedeemTest(TestCase):
    def test_finalize_p2sh_no_redeem_script(self):
        """Covers line 1532: finalize p2sh without RedeemScript"""
        p2sh_script = Script([0xA9, bytes(20), 0x87])
        prev_tx = Tx(
            2,
            [TxIn(bytes(32), 0)],
            [TxOut(50000, p2sh_script)],
            0,
        )
        tx_in = TxIn(prev_tx.hash(), 0)
        psbt_in = PSBTIn(tx_in, prev_tx=prev_tx)
        with self.assertRaises(RuntimeError) as cm:
            psbt_in.finalize()
        self.assertIn("Cannot finalize p2sh without a RedeemScript", str(cm.exception))

    def test_finalize_p2wsh_sigs_dont_match_commands(self):
        """Covers line 1584: sigs exist but don't match witness_script commands"""
        priv1 = PrivateKey(secret=1)
        priv2 = PrivateKey(secret=2)
        priv3 = PrivateKey(secret=3)
        ws = WitnessScript([0x52, priv1.point.sec(), priv2.point.sec(), 0x52, 0xAE])

        script_pubkey = Script([0, ws.sha256()])
        prev_out = TxOut(50000, script_pubkey)
        tx_in = TxIn(bytes(32), 0)
        tx_in._script_pubkey = script_pubkey

        # Provide 2 sigs but for keys NOT in the witness script
        # The check at line 1565 passes (len(sigs) >= num_sigs=2),
        # but the loop won't find them in witness_script.commands
        fake_sig = priv3.sign(int.from_bytes(bytes(32), "big")).der() + bytes(
            [SIGHASH_ALL]
        )
        priv4 = PrivateKey(secret=4)
        fake_sig2 = priv4.sign(int.from_bytes(bytes(32), "big")).der() + bytes(
            [SIGHASH_ALL]
        )
        sigs = {priv3.point.sec(): fake_sig, priv4.point.sec(): fake_sig2}

        psbt_in = PSBTIn(tx_in, prev_out=prev_out, witness_script=ws, sigs=sigs)
        with self.assertRaises(RuntimeError) as cm:
            psbt_in.finalize()
        self.assertIn("Not enough signatures", str(cm.exception))

    def test_finalize_p2sh_sigs_dont_match_commands(self):
        """Covers line 1621: p2sh finalize sigs don't match commands"""
        priv1 = PrivateKey(secret=1)
        priv2 = PrivateKey(secret=2)
        priv3 = PrivateKey(secret=3)
        rs = RedeemScript([0x52, priv1.point.sec(), priv2.point.sec(), 0x52, 0xAE])

        p2sh_script = Script([0xA9, rs.hash160(), 0x87])
        prev_tx = Tx(
            2,
            [TxIn(bytes(32), 0)],
            [TxOut(50000, p2sh_script)],
            0,
        )
        tx_in = TxIn(prev_tx.hash(), 0)

        # 2 sigs for keys NOT in the redeem script
        fake_sig = priv3.sign(int.from_bytes(bytes(32), "big")).der() + bytes(
            [SIGHASH_ALL]
        )
        priv4 = PrivateKey(secret=4)
        fake_sig2 = priv4.sign(int.from_bytes(bytes(32), "big")).der() + bytes(
            [SIGHASH_ALL]
        )
        sigs = {priv3.point.sec(): fake_sig, priv4.point.sec(): fake_sig2}

        psbt_in = PSBTIn(tx_in, prev_tx=prev_tx, redeem_script=rs, sigs=sigs)
        with self.assertRaises(RuntimeError) as cm:
            psbt_in.finalize()
        self.assertIn("Not enough signatures", str(cm.exception))


class PSBTOutValidateP2shP2wshTest(TestCase):
    def test_p2sh_p2wsh_output_valid(self):
        """Covers lines 1696-1702: valid p2sh-p2wsh output with redeem_script"""
        priv1 = PrivateKey(secret=1)
        priv2 = PrivateKey(secret=2)
        ws = WitnessScript([0x52, priv1.point.sec(), priv2.point.sec(), 0x52, 0xAE])
        inner = RedeemScript([0, ws.sha256()])
        p2sh_script = Script([0xA9, inner.hash160(), 0x87])
        tx_out = TxOut(50000, p2sh_script)

        # Should not raise
        psbt_out = PSBTOut(tx_out, redeem_script=inner, witness_script=ws)
        self.assertIsNotNone(psbt_out.witness_script)
        self.assertIsNotNone(psbt_out.redeem_script)


class PSBTInParseDuplicatePartialSigTest(TestCase):
    def test_duplicate_partial_sig(self):
        """Covers line 1271: duplicate partial sig key"""
        from buidl.psbt import PSBT_IN_PARTIAL_SIG

        tx_in = TxIn(bytes(32), 0)
        priv = PrivateKey(secret=1)
        sec = priv.point.sec()
        fake_sig = b"\x30\x06\x02\x01\x01\x02\x01\x01\x01"  # minimal DER + sighash

        sig_key = PSBT_IN_PARTIAL_SIG + sec
        data = b""
        data += serialize_key_value(sig_key, fake_sig)
        data += serialize_key_value(sig_key, fake_sig)
        data += PSBT_DELIMITER

        with self.assertRaises(KeyError):
            PSBTIn.parse(BytesIO(data), tx_in)

    def test_wrong_key_length_bip32_derivation(self):
        """Covers line 1293 (key length != 34 for BIP32_DERIVATION, though this is 1271 in missing)"""
        from buidl.psbt import PSBT_IN_BIP32_DERIVATION

        tx_in = TxIn(bytes(32), 0)
        bad_key = (
            PSBT_IN_BIP32_DERIVATION + b"\x00" * 10
        )  # should be 33 bytes after type

        data = b""
        data += serialize_key_value(bad_key, b"\x00" * 20)
        data += PSBT_DELIMITER

        with self.assertRaises(KeyError) as cm:
            PSBTIn.parse(BytesIO(data), tx_in)
        self.assertIn("Wrong length", str(cm.exception))


class PSBTInCombineMoreTest(TestCase):
    def test_combine_redeem_and_witness_scripts(self):
        """Covers lines 1507-1511: combine redeem_script and witness_script"""
        tx_in = TxIn(bytes(32), 0)
        psbt_in_1 = PSBTIn(tx_in)

        priv1 = PrivateKey(secret=1)
        priv2 = PrivateKey(secret=2)
        ws = WitnessScript([0x52, priv1.point.sec(), priv2.point.sec(), 0x52, 0xAE])
        rs = RedeemScript([0, ws.sha256()])

        tx_in_2 = TxIn(bytes(32), 0)
        psbt_in_2 = PSBTIn(tx_in_2)
        psbt_in_2.redeem_script = rs
        psbt_in_2.witness_script = ws

        psbt_in_1.combine(psbt_in_2)
        self.assertIsNotNone(psbt_in_1.redeem_script)
        self.assertIsNotNone(psbt_in_1.witness_script)


class PSBTOutValidateWitnessScriptTest(TestCase):
    def test_p2wsh_output_with_witness_script(self):
        """Covers lines 1695-1710: PSBTOut.validate with witness_script on p2wsh output"""
        priv1 = PrivateKey(secret=1)
        priv2 = PrivateKey(secret=2)
        ws = WitnessScript([0x52, priv1.point.sec(), priv2.point.sec(), 0x52, 0xAE])
        p2wsh_script = Script([0, ws.sha256()])
        tx_out = TxOut(50000, p2wsh_script)

        # Valid case - should not raise
        psbt_out = PSBTOut(tx_out, witness_script=ws)
        self.assertIsNotNone(psbt_out.witness_script)

    def test_p2wsh_output_witness_script_sha256_mismatch(self):
        """Covers lines 1705-1710: WitnessScript sha256 mismatch in output"""
        priv1 = PrivateKey(secret=1)
        priv2 = PrivateKey(secret=2)
        ws = WitnessScript([0x52, priv1.point.sec(), priv2.point.sec(), 0x52, 0xAE])
        # Use wrong sha256
        p2wsh_script = Script([0, bytes(32)])
        tx_out = TxOut(50000, p2wsh_script)

        with self.assertRaises(ValueError) as cm:
            PSBTOut(tx_out, witness_script=ws)
        self.assertIn("sha256", str(cm.exception))

    def test_p2wsh_output_pubkey_not_in_witness_script(self):
        """Covers lines 1714-1716: pubkey not in WitnessScript for output"""
        priv1 = PrivateKey(secret=1)
        priv2 = PrivateKey(secret=2)
        priv3 = PrivateKey(secret=3)
        ws = WitnessScript([0x52, priv1.point.sec(), priv2.point.sec(), 0x52, 0xAE])
        p2wsh_script = Script([0, ws.sha256()])
        tx_out = TxOut(50000, p2wsh_script)

        # named pub for priv3 not in witness script
        np = priv3.point
        np.__class__ = NamedPublicKey
        np.add_raw_path_data(bytes(4) + serialize_binary_path("m/44'/0'/0'/0/0"))

        with self.assertRaises(ValueError) as cm:
            PSBTOut(tx_out, witness_script=ws, named_pubs={np.sec(): np})
        self.assertIn("not in WitnessScript", str(cm.exception))

    def test_p2sh_p2wsh_output_redeem_hash_mismatch(self):
        """Covers lines 1696-1701: p2sh-p2wsh output redeem_script hash160 mismatch"""
        priv1 = PrivateKey(secret=1)
        priv2 = PrivateKey(secret=2)
        ws = WitnessScript([0x52, priv1.point.sec(), priv2.point.sec(), 0x52, 0xAE])
        inner = RedeemScript([0, ws.sha256()])
        # Use a DIFFERENT hash160 in the p2sh script
        p2sh_script = Script([0xA9, bytes(20), 0x87])
        tx_out = TxOut(50000, p2sh_script)

        with self.assertRaises(ValueError) as cm:
            PSBTOut(tx_out, redeem_script=inner, witness_script=ws)
        self.assertIn("hash160", str(cm.exception))

    def test_p2sh_output_pubkey_not_in_redeem_script(self):
        """Covers lines 1717-1723: pubkey not in RedeemScript for output"""
        priv1 = PrivateKey(secret=1)
        priv2 = PrivateKey(secret=2)
        priv3 = PrivateKey(secret=3)
        rs = RedeemScript([0x52, priv1.point.sec(), priv2.point.sec(), 0x52, 0xAE])
        p2sh_script = Script([0xA9, rs.hash160(), 0x87])
        tx_out = TxOut(50000, p2sh_script)

        np = priv3.point
        np.__class__ = NamedPublicKey
        np.add_raw_path_data(bytes(4) + serialize_binary_path("m/44'/0'/0'/0/0"))

        with self.assertRaises(ValueError) as cm:
            PSBTOut(tx_out, redeem_script=rs, named_pubs={np.sec(): np})
        self.assertIn("not in RedeemScript", str(cm.exception))


class PSBTInValidateRedeemScriptTest(TestCase):
    def test_pubkey_not_in_redeem_script(self):
        """Covers lines 1201-1206: pubkey not found in RedeemScript for non-witness p2sh input"""
        priv1 = PrivateKey(secret=1)
        priv2 = PrivateKey(secret=2)
        priv3 = PrivateKey(secret=3)

        # Non-witness p2sh multisig
        rs = RedeemScript([0x52, priv1.point.sec(), priv2.point.sec(), 0x52, 0xAE])
        p2sh_script = Script([0xA9, rs.hash160(), 0x87])
        prev_tx = Tx(
            2,
            [TxIn(bytes(32), 0)],
            [TxOut(50000, p2sh_script)],
            0,
        )
        tx_in = TxIn(prev_tx.hash(), 0)

        # Named pub for priv3 which is NOT in the redeem script
        np = priv3.point
        np.__class__ = NamedPublicKey
        np.add_raw_path_data(bytes(4) + serialize_binary_path("m/44'/0'/0'/0/0"))

        with self.assertRaises(ValueError) as cm:
            PSBTIn(tx_in, prev_tx=prev_tx, redeem_script=rs, named_pubs={np.sec(): np})
        self.assertIn("not in RedeemScript", str(cm.exception))

    def test_witness_script_provided_for_non_p2wsh(self):
        """Covers lines 1150-1154: WitnessScript provided for non-p2wsh ScriptPubKey"""
        priv1 = PrivateKey(secret=1)
        priv2 = PrivateKey(secret=2)
        ws = WitnessScript([0x52, priv1.point.sec(), priv2.point.sec(), 0x52, 0xAE])

        # p2wpkh output (not p2wsh) with witness_script is invalid
        h160 = priv1.point.hash160()
        script_pubkey = Script([0, h160])
        prev_out = TxOut(50000, script_pubkey)

        tx_in = TxIn(bytes(32), 0)
        tx_in._script_pubkey = script_pubkey

        with self.assertRaises(ValueError) as cm:
            PSBTIn(tx_in, prev_out=prev_out, witness_script=ws)
        self.assertIn("non-p2wsh", str(cm.exception))
