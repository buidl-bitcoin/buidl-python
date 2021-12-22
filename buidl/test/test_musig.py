from itertools import combinations
from random import randint
from unittest import TestCase

from buidl.ecc import N, G, S256Point
from buidl.hd import HDPrivateKey
from buidl.helper import SIGHASH_DEFAULT
from buidl.taproot import MultiSigTapScript, MuSigTapScript, TapRootMultiSig
from buidl.timelock import Locktime, Sequence
from buidl.tx import Tx, TxIn, TxOut
from buidl.witness import Witness


class MuSigTest(TestCase):
    def test_single_leaf_multisig(self):
        hd_priv_key = HDPrivateKey.from_mnemonic(
            "oil oil oil oil oil oil oil oil oil oil oil oil", network="signet"
        )
        # create a 3-of-5 single-leaf multisig
        private_keys = [
            hd_priv_key.get_p2tr_receiving_privkey(address_num=i) for i in range(5)
        ]
        points = [priv.point for priv in private_keys]
        tr_multisig = TapRootMultiSig(points, 3)
        tap_root_input = tr_multisig.single_leaf_tap_root()
        tap_root_output = tr_multisig.multi_leaf_tap_root()
        leaf = tap_root_input.tap_node
        self.assertEqual(
            tap_root_input.address(network="signet"),
            "tb1p9gpzhc5fhlwlf49ze00fgjszxh5pl2p7az76758xwarweq08gcas8qa0r7",
        )
        prev_tx = bytes.fromhex(
            "9baaec56eeef80bfa9c0f9c039fb71f134973179a3e2c3e8d037a4cc29cf6354"
        )
        tx_ins = []
        for prev_index in range(10):
            tx_in = TxIn(prev_tx, prev_index)
            tx_in._value = 999130
            tx_in._script_pubkey = tap_root_input.script_pubkey()
            tx_ins.append(tx_in)
        tx_out = TxOut(tx_in.value() - 200, tap_root_output.script_pubkey())
        tx_obj = Tx(1, tx_ins, [tx_out] * 10, 0, network="signet", segwit=True)
        for input_index, pubkeys in enumerate(combinations(points, 3)):
            tx_in = tx_ins[input_index]
            tx_in.witness.items = []
            tx_obj.initialize_p2tr_multisig(
                input_index,
                tap_root_input.control_block(leaf),
                tap_root_input.tap_node.tap_script,
            )
            sigs = []
            for priv in private_keys:
                if priv.point in pubkeys:
                    sig = tx_obj.get_sig_taproot(input_index, priv, ext_flag=1)
                else:
                    sig = b""
                sigs.append(sig)
            tx_obj.finalize_p2tr_multisig(input_index, sigs)
            self.assertTrue(tx_obj.verify_input(input_index))
        self.assertTrue(tx_obj.verify())

    def test_single_leaf_multisig_locktime(self):
        hd_priv_key = HDPrivateKey.from_mnemonic(
            "oil oil oil oil oil oil oil oil oil oil oil oil", network="signet"
        )
        # create a 3-of-5 single-leaf multisig
        private_keys = [
            hd_priv_key.get_p2tr_receiving_privkey(address_num=i) for i in range(5)
        ]
        points = [priv.point for priv in private_keys]
        tr_multisig = TapRootMultiSig(points, 3)
        current_locktime = Locktime(1638000000)
        tap_root_input = tr_multisig.single_leaf_tap_root(locktime=current_locktime)
        tap_root_output = tr_multisig.single_leaf_tap_root(
            sequence=Sequence.from_relative_time(3000)
        )
        leaf = tap_root_input.tap_node
        self.assertEqual(
            tap_root_input.address(network="signet"),
            "tb1pn5qyrghydw6xw3ltww8xxwcrlvs8dgv8h66y6n7cd7h0gqayuq4szv3rcz",
        )
        prev_tx = bytes.fromhex(
            "e3d892dbfee9f84c5aa372780f6932ea67e829b4dbf9fc15e1acfb97467a6ebb"
        )
        tx_in = TxIn(prev_tx, 0, sequence=0xFFFFFFFE)
        tx_in._value = 10000000
        tx_in._script_pubkey = tap_root_input.script_pubkey()
        tx_out = TxOut(
            tx_in.value(network="signet") - 200, tap_root_output.script_pubkey()
        )
        tx_obj = Tx(
            1, [tx_in], [tx_out], current_locktime, network="signet", segwit=True
        )
        tx_in.witness.items = []
        tx_obj.initialize_p2tr_multisig(
            0,
            tap_root_input.control_block(leaf),
            tap_root_input.tap_node.tap_script,
        )
        sigs = [
            tx_obj.get_sig_taproot(0, priv, ext_flag=1) for priv in private_keys[:3]
        ]
        tx_obj.finalize_p2tr_multisig(0, sigs)
        self.assertTrue(tx_obj.verify())

        tx_obj.locktime = Locktime(current_locktime - 1)
        tx_in.witness.items = []
        tx_obj.initialize_p2tr_multisig(
            0,
            tap_root_input.control_block(leaf),
            tap_root_input.tap_node.tap_script,
        )
        sigs = [
            tx_obj.get_sig_taproot(0, priv, ext_flag=1) for priv in private_keys[:3]
        ]
        tx_obj.finalize_p2tr_multisig(0, sigs)
        self.assertFalse(tx_obj.verify())

    def test_single_leaf_multisig_sequence(self):
        hd_priv_key = HDPrivateKey.from_mnemonic(
            "oil oil oil oil oil oil oil oil oil oil oil oil", network="signet"
        )
        # create a 3-of-5 single-leaf multisig
        private_keys = [
            hd_priv_key.get_p2tr_receiving_privkey(address_num=i) for i in range(5)
        ]
        points = [priv.point for priv in private_keys]
        tr_multisig = TapRootMultiSig(points, 3)
        current_sequence = Sequence.from_relative_time(3000)
        tap_root_input = tr_multisig.single_leaf_tap_root(sequence=current_sequence)
        tap_root_output = tr_multisig.multi_leaf_tap_root(locktime=Locktime(66000))
        leaf = tap_root_input.tap_node
        self.assertEqual(
            tap_root_input.address(network="signet"),
            "tb1psyu6fl6at80x42g50gzzffmz6sh5e7tz3xxxc8zpqc9euaq2u9tslamkpt",
        )
        prev_tx = bytes.fromhex(
            "bfde811ac4344f11a2aa5d8d68eade43d93664be1b7e3e252e747387119d675c"
        )
        tx_in = TxIn(prev_tx, 0, sequence=current_sequence)
        tx_in._value = 9999800
        tx_in._script_pubkey = tap_root_input.script_pubkey()
        tx_out = TxOut(tx_in.value() - 200, tap_root_output.script_pubkey())
        tx_obj = Tx(2, [tx_in], [tx_out], 0, network="signet", segwit=True)
        tx_in.witness.items = []
        tx_obj.initialize_p2tr_multisig(
            0,
            tap_root_input.control_block(leaf),
            tap_root_input.tap_node.tap_script,
        )
        sigs = [
            tx_obj.get_sig_taproot(0, priv, ext_flag=1) for priv in private_keys[:3]
        ]
        tx_obj.finalize_p2tr_multisig(0, sigs)
        self.assertTrue(tx_obj.verify())
        tx_in.sequence = Sequence(current_sequence - 1)
        tx_in.witness.items = []
        tx_obj.initialize_p2tr_multisig(
            0,
            tap_root_input.control_block(leaf),
            tap_root_input.tap_node.tap_script,
        )
        sigs = [
            tx_obj.get_sig_taproot(0, priv, ext_flag=1) for priv in private_keys[:3]
        ]
        tx_obj.finalize_p2tr_multisig(0, sigs)
        self.assertFalse(tx_obj.verify())

    def test_multi_leaf_multisig(self):
        hd_priv_key = HDPrivateKey.from_mnemonic(
            "oil oil oil oil oil oil oil oil oil oil oil oil", network="signet"
        )
        # create a 3-of-5 multi-leaf multisig
        private_keys = [
            hd_priv_key.get_p2tr_receiving_privkey(address_num=i) for i in range(5)
        ]
        points = [priv.point for priv in private_keys]
        multisig = TapRootMultiSig(points, 3)
        tap_root_input = multisig.multi_leaf_tap_root()
        tap_root_output = multisig.musig_tap_root()
        self.assertEqual(
            tap_root_input.address(network="signet"),
            "tb1p7e95u84xfjeuyndvpzauavkw59m2r9ekw28xxax3cftgzx3kza8q7ruv3u",
        )
        prev_tx = bytes.fromhex(
            "ee78952b6baa1cb2b04f174a0f3e7f536828062e2ce41341e2d2c079e2b83e74"
        )
        tx_ins = []
        for prev_index in range(10):
            tx_in = TxIn(prev_tx, prev_index)
            tx_in._value = 998930
            tx_in._script_pubkey = tap_root_input.script_pubkey()
            tx_ins.append(tx_in)
        tx_out = TxOut(tx_in.value() - 200, tap_root_output.script_pubkey())
        tx_obj = Tx(1, tx_ins, [tx_out] * 10, 0, network="signet", segwit=True)
        for input_index, pubkeys in enumerate(combinations(points, 3)):
            tx_in = tx_ins[input_index]
            tx_in.witness.items = []
            leaf = MultiSigTapScript(pubkeys, 3).tap_leaf()
            self.assertTrue(tap_root_input.control_block(leaf))
            tx_obj.initialize_p2tr_multisig(
                input_index, tap_root_input.control_block(leaf), leaf.tap_script
            )
            sigs = []
            for priv in private_keys:
                if priv.point in pubkeys:
                    sig = tx_obj.get_sig_taproot(input_index, priv, ext_flag=1)
                    sigs.append(sig)
            tx_obj.finalize_p2tr_multisig(input_index, sigs)
            self.assertTrue(tx_obj.verify_input(input_index))
        self.assertTrue(tx_obj.verify())

    def test_multi_leaf_multisig_locktime(self):
        hd_priv_key = HDPrivateKey.from_mnemonic(
            "oil oil oil oil oil oil oil oil oil oil oil oil", network="signet"
        )
        # create a 3-of-5 multi-leaf multisig
        private_keys = [
            hd_priv_key.get_p2tr_receiving_privkey(address_num=i) for i in range(5)
        ]
        points = [priv.point for priv in private_keys]
        tr_multisig = TapRootMultiSig(points, 3)
        current_locktime = Locktime(66000)
        tap_root_input = tr_multisig.multi_leaf_tap_root(locktime=current_locktime)
        tap_root_output = tr_multisig.multi_leaf_tap_root(
            sequence=Sequence.from_relative_blocks(50)
        )
        leaf = MultiSigTapScript(points[:3], 3, locktime=current_locktime).tap_leaf()
        self.assertTrue(tap_root_input.control_block(leaf))
        self.assertEqual(
            tap_root_input.address(network="signet"),
            "tb1pvl3r0t48sxypr6v938rlkykrzpp36zkee2krqh94lk7lr9utqf8sas0r0g",
        )
        prev_tx = bytes.fromhex(
            "cee7412e4aba98dd9e33a88221fc4752a644aeb3f5f444b3af0bd359b7a4edd9"
        )
        tx_in = TxIn(prev_tx, 0, sequence=0xFFFFFFFE)
        tx_in._value = 9999600
        tx_in._script_pubkey = tap_root_input.script_pubkey()
        tx_out = TxOut(tx_in.value() - 204, tap_root_output.script_pubkey())
        tx_obj = Tx(
            1, [tx_in], [tx_out], current_locktime, network="signet", segwit=True
        )
        tx_in.witness.items = []
        tx_obj.initialize_p2tr_multisig(
            0,
            tap_root_input.control_block(leaf),
            leaf.tap_script,
        )
        sigs = [
            tx_obj.get_sig_taproot(0, priv, ext_flag=1) for priv in private_keys[:3]
        ]
        tx_obj.finalize_p2tr_multisig(0, sigs)
        self.assertTrue(tx_obj.verify())
        tx_obj.locktime = Locktime(current_locktime - 1)
        tx_in.witness.items = []
        tx_obj.initialize_p2tr_multisig(
            0,
            tap_root_input.control_block(leaf),
            leaf.tap_script,
        )
        sigs = [
            tx_obj.get_sig_taproot(0, priv, ext_flag=1) for priv in private_keys[:3]
        ]
        tx_obj.finalize_p2tr_multisig(0, sigs)
        self.assertFalse(tx_obj.verify())

    def test_multi_leaf_multisig_sequence(self):
        hd_priv_key = HDPrivateKey.from_mnemonic(
            "oil oil oil oil oil oil oil oil oil oil oil oil", network="signet"
        )
        # create a 3-of-5 multi-leaf multisig
        private_keys = [
            hd_priv_key.get_p2tr_receiving_privkey(address_num=i) for i in range(5)
        ]
        points = [priv.point for priv in private_keys]
        tr_multisig = TapRootMultiSig(points, 3)
        current_sequence = Sequence.from_relative_blocks(50)
        tap_root_input = tr_multisig.multi_leaf_tap_root(sequence=current_sequence)
        tap_root_output = tr_multisig.musig_tap_root(locktime=Locktime(1638000000))
        leaf = MultiSigTapScript(points[:3], 3, sequence=current_sequence).tap_leaf()
        self.assertEqual(
            tap_root_input.address(network="signet"),
            "tb1px58s95zf3z7nmjl6d7p46lczgp52mz8z3lg3a4ck7grf0je0pl6q5gqdqu",
        )
        prev_tx = bytes.fromhex(
            "cf31d8a1f12c80407a2e6221f696a9f5300fe9c72fbdd3b6dd1b0a779b9da28f"
        )
        fee = 204
        tx_in = TxIn(prev_tx, 0, sequence=current_sequence)
        tx_in._value = 9999396
        tx_in._script_pubkey = tap_root_input.script_pubkey()
        tx_out = TxOut(tx_in.value() - fee, tap_root_output.script_pubkey())
        tx_obj = Tx(2, [tx_in], [tx_out], 0, network="signet", segwit=True)
        tx_in.witness.items = []
        tx_obj.initialize_p2tr_multisig(
            0,
            tap_root_input.control_block(leaf),
            leaf.tap_script,
        )
        sigs = [
            tx_obj.get_sig_taproot(0, priv, ext_flag=1) for priv in private_keys[:3]
        ]
        tx_obj.finalize_p2tr_multisig(0, sigs)
        self.assertEqual(fee, tx_obj.vbytes())
        self.assertTrue(tx_obj.verify())
        tx_in.sequence = Sequence(current_sequence - 1)
        tx_in.witness.items = []
        tx_obj.initialize_p2tr_multisig(
            0,
            tap_root_input.control_block(leaf),
            leaf.tap_script,
        )
        sigs = [
            tx_obj.get_sig_taproot(0, priv, ext_flag=1) for priv in private_keys[:3]
        ]
        tx_obj.finalize_p2tr_multisig(0, sigs)
        self.assertFalse(tx_obj.verify())

    def test_musig(self):
        hd_priv_key = HDPrivateKey.from_mnemonic(
            "oil oil oil oil oil oil oil oil oil oil oil oil", network="signet"
        )
        # create a 3-of-5 multi-leaf musig
        private_keys = []
        for i in range(5):
            private_keys.append(hd_priv_key.get_p2tr_receiving_privkey(address_num=i))
        points = [priv.point for priv in private_keys]
        tr_multisig = TapRootMultiSig(points, 3)
        musig = MuSigTapScript(points)
        tap_root = tr_multisig.musig_tap_root()
        self.assertEqual(tr_multisig.default_internal_pubkey, musig.point)
        prev_tx = bytes.fromhex(
            "aab3619891f8de651dcbd18ed897017ade7bf8eda89202ba56a7b0403c54c511"
        )
        self.assertEqual(
            tap_root.address(network="signet"),
            "tb1pt8sygq8v5zjzrt03lwatrwm4vzvy3fktuhpv6hyhd63euw774vxq9u0vhn",
        )
        tx_ins = []
        for prev_index in range(10):
            tx_in = TxIn(prev_tx, prev_index)
            tx_in._value = 998730
            tx_in._script_pubkey = tap_root.script_pubkey()
            tx_ins.append(tx_in)
        tx_out = TxOut((tx_in.value() - 150), tap_root.script_pubkey())
        tx_obj = Tx(1, tx_ins, [tx_out] * 10, 0, network="signet", segwit=True)
        for input_index, pubkeys in enumerate(combinations(points, 3)):
            tx_in = tx_obj.tx_ins[input_index]
            musig = MuSigTapScript(pubkeys)
            leaf = musig.tap_leaf()
            cb = tap_root.control_block(leaf)
            self.assertTrue(cb)
            tx_in.witness.items = [leaf.tap_script.raw_serialize(), cb.serialize()]
            sig_hash = tx_obj.sig_hash(input_index, SIGHASH_DEFAULT)
            ks = [randint(1, N) for _ in pubkeys]
            r = S256Point.combine([k_i * G for k_i in ks])
            s_sum = 0
            for priv in private_keys:
                if priv.point in pubkeys:
                    k_i = ks.pop()
                    s_sum += musig.sign(priv, k_i, r, sig_hash)
            schnorr = musig.get_signature(s_sum, r, sig_hash)
            self.assertTrue(musig.point.verify_schnorr(sig_hash, schnorr))
            tx_in.witness.items.insert(0, schnorr.serialize())
            self.assertTrue(tx_obj.verify_input(input_index))
        self.assertTrue(tx_obj.verify())

    def test_musig_locktime(self):
        hd_priv_key = HDPrivateKey.from_mnemonic(
            "oil oil oil oil oil oil oil oil oil oil oil oil", network="signet"
        )
        # create a 3-of-5 musig
        private_keys = [
            hd_priv_key.get_p2tr_receiving_privkey(address_num=i) for i in range(5)
        ]
        points = [priv.point for priv in private_keys]
        tr_multisig = TapRootMultiSig(points, 3)
        current_locktime = Locktime(1638000000)
        tap_root_input = tr_multisig.musig_tap_root(locktime=current_locktime)
        tap_root_output = tr_multisig.musig_tap_root(
            sequence=Sequence.from_relative_time(3000)
        )
        musig = MuSigTapScript(points[:3], locktime=current_locktime)
        leaf = musig.tap_leaf()
        self.assertTrue(tap_root_input.control_block(leaf))
        self.assertEqual(
            tap_root_input.address(network="signet"),
            "tb1pzkmhkr4ajyv9c293yc2n5z04uv5u62y2q8azg606r4qacxlx0y2sdrnrf0",
        )
        prev_tx = bytes.fromhex(
            "0bfb09b014f83769f3a87321b29d6eef97caa7a080c236ea48fc370ded514ee8"
        )
        fee = 154
        tx_in = TxIn(prev_tx, 0, sequence=0xFFFFFFFE)
        tx_in._value = 9999192
        tx_in._script_pubkey = tap_root_input.script_pubkey()
        tx_out = TxOut(tx_in.value() - fee, tap_root_output.script_pubkey())
        tx_obj = Tx(
            1, [tx_in], [tx_out], current_locktime, network="signet", segwit=True
        )
        cb = tap_root_input.control_block(leaf)
        tx_in.witness.items = [leaf.tap_script.raw_serialize(), cb.serialize()]
        sig_hash = tx_obj.sig_hash(0, SIGHASH_DEFAULT)
        ks = [randint(1, N) for _ in points[:3]]
        r = S256Point.combine([k_i * G for k_i in ks])
        s_sum = 0
        for priv in private_keys[:3]:
            k_i = ks.pop()
            s_sum += musig.sign(priv, k_i, r, sig_hash)
        schnorr = musig.get_signature(s_sum, r, sig_hash)
        self.assertTrue(musig.point.verify_schnorr(sig_hash, schnorr))
        tx_in.witness.items.insert(0, schnorr.serialize())
        self.assertEqual(fee, tx_obj.vbytes())
        self.assertTrue(tx_obj.verify())
        tx_obj.locktime = Locktime(current_locktime - 1)
        tx_in.witness.items.pop(0)
        sig_hash = tx_obj.sig_hash(0, SIGHASH_DEFAULT)
        ks = [randint(1, N) for _ in points[:3]]
        r = S256Point.combine([k_i * G for k_i in ks])
        s_sum = 0
        for priv in private_keys[:3]:
            k_i = ks.pop()
            s_sum += musig.sign(priv, k_i, r, sig_hash)
        schnorr = musig.get_signature(s_sum, r, sig_hash)
        self.assertTrue(musig.point.verify_schnorr(sig_hash, schnorr))
        tx_in.witness.items.insert(0, schnorr.serialize())
        self.assertFalse(tx_obj.verify())

    def test_musig_sequence(self):
        hd_priv_key = HDPrivateKey.from_mnemonic(
            "oil oil oil oil oil oil oil oil oil oil oil oil", network="signet"
        )
        # create a 3-of-5 multi-leaf multisig
        private_keys = [
            hd_priv_key.get_p2tr_receiving_privkey(address_num=i) for i in range(5)
        ]
        points = [priv.point for priv in private_keys]
        tr_multisig = TapRootMultiSig(points, 3)
        current_sequence = Sequence.from_relative_time(3000)
        tap_root_input = tr_multisig.musig_tap_root(sequence=current_sequence)
        tap_root_output = tr_multisig.degrading_multisig_tap_root(
            sequence_time_interval=512 * 18
        )
        musig = MuSigTapScript(points[:3], sequence=current_sequence)
        leaf = musig.tap_leaf()
        self.assertEqual(
            tap_root_input.address(network="signet"),
            "tb1p2yk9q796yu9peqgxcmwed97p9r3qqxjcl9l5ekqh8lra5zjscujsameghf",
        )
        prev_tx = bytes.fromhex(
            "feaf90c8a4d9d301deebd4f1ac1a55e711f7543bf58cc0b52127281418c31090"
        )
        fee = 154
        tx_in = TxIn(prev_tx, 0, sequence=current_sequence)
        tx_in._value = 9999038
        tx_in._script_pubkey = tap_root_input.script_pubkey()
        tx_out = TxOut(tx_in.value() - fee, tap_root_output.script_pubkey())
        tx_obj = Tx(2, [tx_in], [tx_out], 0, network="signet", segwit=True)
        cb = tap_root_input.control_block(leaf)
        tx_in.witness.items = [leaf.tap_script.raw_serialize(), cb.serialize()]
        sig_hash = tx_obj.sig_hash(0, SIGHASH_DEFAULT)
        ks = [randint(1, N) for _ in points[:3]]
        r = S256Point.combine([k_i * G for k_i in ks])
        s_sum = 0
        for priv in private_keys[:3]:
            k_i = ks.pop()
            s_sum += musig.sign(priv, k_i, r, sig_hash)
        schnorr = musig.get_signature(s_sum, r, sig_hash)
        self.assertTrue(musig.point.verify_schnorr(sig_hash, schnorr))
        tx_in.witness.items.insert(0, schnorr.serialize())
        self.assertEqual(fee, tx_obj.vbytes())
        self.assertTrue(tx_obj.verify())
        tx_in.sequence = Sequence(current_sequence - 1)
        tx_in.witness.items.pop(0)
        sig_hash = tx_obj.sig_hash(0, SIGHASH_DEFAULT)
        ks = [randint(1, N) for _ in points[:3]]
        r = S256Point.combine([k_i * G for k_i in ks])
        s_sum = 0
        for priv in private_keys[:3]:
            k_i = ks.pop()
            s_sum += musig.sign(priv, k_i, r, sig_hash)
        schnorr = musig.get_signature(s_sum, r, sig_hash)
        self.assertTrue(musig.point.verify_schnorr(sig_hash, schnorr))
        tx_in.witness.items.insert(0, schnorr.serialize())
        self.assertFalse(tx_obj.verify())

    def test_internal_pubkey_musig(self):
        hd_priv_key = HDPrivateKey.from_mnemonic(
            "oil oil oil oil oil oil oil oil oil oil oil oil", network="signet"
        )
        # create a 3-of-5 multi-leaf musig
        private_keys = []
        for i in range(5):
            private_keys.append(hd_priv_key.get_p2tr_receiving_privkey(address_num=i))
        points = [priv.point for priv in private_keys]
        tr_multisig = TapRootMultiSig(points, 3)
        musig = MuSigTapScript(points)
        tap_root_input = tr_multisig.musig_tap_root()
        tap_root_output = tr_multisig.musig_and_single_leaf_tap_root()
        self.assertEqual(tr_multisig.default_internal_pubkey, musig.point)
        prev_tx = bytes.fromhex(
            "d5b2a411f70a68fad8adb5362149aca04c213f0e195b7b2b4a7f4f905fbcce11"
        )
        tx_ins = []
        for prev_index in range(10):
            tx_in = TxIn(prev_tx, prev_index)
            tx_in._value = 998580
            tx_in._script_pubkey = tap_root_input.script_pubkey()
            tx_ins.append(tx_in)
        tx_out = TxOut((tx_in.value() - 102), tap_root_output.script_pubkey())
        tx_obj = Tx(1, tx_ins, [tx_out] * 10, 0, network="signet", segwit=True)
        for input_index, tx_in in enumerate(tx_ins):
            ks = [randint(1, N) for _ in points]
            r = S256Point.combine([k_i * G for k_i in ks])
            s_sum = 0
            sig_hash = tx_obj.sig_hash(input_index, SIGHASH_DEFAULT)
            for priv in private_keys:
                k_i = ks.pop()
                s_sum += musig.sign(priv, k_i, r, sig_hash, tweak=tap_root_input.tweak)
            schnorr = musig.get_signature(s_sum, r, sig_hash, tap_root_input.tweak)
            tx_in.witness = Witness([schnorr.serialize()])
            self.assertTrue(tx_obj.verify_input(input_index))
        self.assertTrue(tx_obj.verify())

    def test_musig_and_single_leaf_multisig(self):
        hd_priv_key = HDPrivateKey.from_mnemonic(
            "oil oil oil oil oil oil oil oil oil oil oil oil", network="signet"
        )
        # create a 3-of-5 single-leaf multisig
        private_keys = [
            hd_priv_key.get_p2tr_receiving_privkey(address_num=i) for i in range(5)
        ]
        points = [priv.point for priv in private_keys]
        tr_multisig = TapRootMultiSig(points, 3)
        tap_root_input = tr_multisig.musig_and_single_leaf_tap_root()
        tap_root_output = tr_multisig.everything_tap_root()
        leaf = tap_root_input.tap_node
        prev_tx = bytes.fromhex(
            "e6d03b31353c5bfcd2033db247d95909ed583e0d69d3bcbca9ddf31e98c861e4"
        )
        self.assertEqual(
            tap_root_input.address(network="signet"),
            "tb1pjzgcghtd0a0qxqwwl4c98assrvzsz647pkvvkty8r5pvz9ltndnq0adf09",
        )
        tx_ins = []
        for prev_index in range(10):
            tx_in = TxIn(prev_tx, prev_index)
            tx_in._value = 998478
            tx_in._script_pubkey = tap_root_input.script_pubkey()
            tx_ins.append(tx_in)
        tx_out = TxOut(tx_in.value() - 200, tap_root_output.script_pubkey())
        tx_obj = Tx(1, tx_ins, [tx_out] * 10, 0, network="signet", segwit=True)
        for input_index, pubkeys in enumerate(combinations(points, 3)):
            tx_in = tx_obj.tx_ins[input_index]
            if input_index & 1:
                tx_in.witness.items = []
                leaf = tr_multisig.single_leaf()
                tx_obj.initialize_p2tr_multisig(
                    input_index,
                    tap_root_input.control_block(leaf),
                    leaf.tap_script,
                )
                sigs = []
                for priv in private_keys:
                    if priv.point in pubkeys:
                        sig = tx_obj.get_sig_taproot(input_index, priv, ext_flag=1)
                    else:
                        sig = b""
                    sigs.append(sig)
                tx_obj.finalize_p2tr_multisig(input_index, sigs)
            else:
                musig = MuSigTapScript(pubkeys)
                leaf = musig.tap_leaf()
                cb = tap_root_input.control_block(leaf)
                self.assertTrue(cb)
                tx_in.witness.items = [leaf.tap_script.raw_serialize(), cb.serialize()]
                sig_hash = tx_obj.sig_hash(input_index, SIGHASH_DEFAULT)
                ks = [randint(1, N) for _ in pubkeys]
                r = S256Point.combine([k_i * G for k_i in ks])
                s_sum = 0
                for priv in private_keys:
                    if priv.point in pubkeys:
                        k_i = ks.pop()
                        s_sum += musig.sign(priv, k_i, r, sig_hash)
                schnorr = musig.get_signature(s_sum, r, sig_hash)
                self.assertTrue(musig.point.verify_schnorr(sig_hash, schnorr))
                tx_in.witness.items.insert(0, schnorr.serialize())
            self.assertTrue(tx_obj.verify_input(input_index))
        self.assertTrue(tx_obj.verify())

    def test_everything_multisig(self):
        hd_priv_key = HDPrivateKey.from_mnemonic(
            "oil oil oil oil oil oil oil oil oil oil oil oil", network="signet"
        )
        # create a 3-of-5 single-leaf multisig
        private_keys = [
            hd_priv_key.get_p2tr_receiving_privkey(address_num=i) for i in range(5)
        ]
        points = [priv.point for priv in private_keys]
        tr_multisig = TapRootMultiSig(points, 3)
        tap_root_input = tr_multisig.everything_tap_root()
        tap_root_output = tr_multisig.everything_tap_root()
        leaf = tap_root_input.tap_node
        prev_tx = bytes.fromhex(
            "d99d760498dfac4fdfce89bd81264614f1eec84ca9246c69e2a90e2be36ae5fa"
        )
        self.assertEqual(
            tap_root_input.address(network="signet"),
            "tb1pyn9z7vueyftuglrsfwgsgajmwnp08x3hjfefnkclx7220fq7mxgq2hy8xp",
        )
        tx_ins = []
        for prev_index in range(30):
            tx_in = TxIn(prev_tx, prev_index)
            tx_in._value = 332667
            tx_in._script_pubkey = tap_root_input.script_pubkey()
            tx_ins.append(tx_in)
        tx_out = TxOut((tx_in.value() - 200), tap_root_output.script_pubkey())
        tx_obj = Tx(1, tx_ins, [tx_out] * 30, 0, network="signet", segwit=True)
        for input_index, pubkeys in enumerate(combinations(points, 3)):
            tx_in = tx_obj.tx_ins[input_index]
            tx_in.witness.items = []
            leaf = tr_multisig.single_leaf()
            tx_obj.initialize_p2tr_multisig(
                input_index,
                tap_root_input.control_block(leaf),
                leaf.tap_script,
            )
            sigs = []
            for priv in private_keys:
                if priv.point in pubkeys:
                    sig = tx_obj.get_sig_taproot(input_index, priv, ext_flag=1)
                else:
                    sig = b""
                sigs.append(sig)
            tx_obj.finalize_p2tr_multisig(input_index, sigs)
            self.assertTrue(tx_obj.verify_input(input_index))
        for i, pubkeys in enumerate(combinations(points, 3)):
            input_index = i + 10
            tx_in = tx_obj.tx_ins[input_index]
            tx_in.witness.items = []
            leaf = MultiSigTapScript(pubkeys, 3).tap_leaf()
            self.assertTrue(tap_root_input.control_block(leaf))
            tx_obj.initialize_p2tr_multisig(
                input_index, tap_root_input.control_block(leaf), leaf.tap_script
            )
            sigs = []
            for priv in private_keys:
                if priv.point in pubkeys:
                    sig = tx_obj.get_sig_taproot(input_index, priv, ext_flag=1)
                    sigs.append(sig)
            tx_obj.finalize_p2tr_multisig(input_index, sigs)
            self.assertTrue(tx_obj.verify_input(input_index))
        for i, pubkeys in enumerate(combinations(points, 3)):
            input_index = i + 20
            tx_in = tx_obj.tx_ins[input_index]
            musig = MuSigTapScript(pubkeys)
            leaf = musig.tap_leaf()
            cb = tap_root_input.control_block(leaf)
            self.assertTrue(cb)
            tx_in.witness.items = [leaf.tap_script.raw_serialize(), cb.serialize()]
            sig_hash = tx_obj.sig_hash(input_index, SIGHASH_DEFAULT)
            ks = [randint(1, N) for _ in pubkeys]
            r = S256Point.combine([k_i * G for k_i in ks])
            s_sum = 0
            for priv in private_keys:
                if priv.point in pubkeys:
                    k_i = ks.pop()
                    s_sum += musig.sign(priv, k_i, r, sig_hash)
            schnorr = musig.get_signature(s_sum, r, sig_hash)
            self.assertTrue(musig.point.verify_schnorr(sig_hash, schnorr))
            tx_in.witness.items.insert(0, schnorr.serialize())
            self.assertTrue(tx_obj.verify_input(input_index))
        self.assertTrue(tx_obj.verify())

    def test_degrading_multisig(self):
        hd_priv_key = HDPrivateKey.from_mnemonic(
            "oil oil oil oil oil oil oil oil oil oil oil oil", network="signet"
        )
        # create a 3-of-5 multi-leaf multisig
        private_keys = [
            hd_priv_key.get_p2tr_receiving_privkey(address_num=i) for i in range(5)
        ]
        points = [priv.point for priv in private_keys]
        tr_multisig = TapRootMultiSig(points, 3)
        tap_root_input = tr_multisig.degrading_multisig_tap_root(
            sequence_time_interval=18 * 512
        )
        tap_root_output = tr_multisig.degrading_multisig_tap_root(
            sequence_block_interval=18
        )
        self.assertEqual(
            tap_root_input.address(network="signet"),
            "tb1pcjc4l8lrxzsquyftdrtez92vfnayla5nc5gz3z0vweaud9wd8fpss8z74v",
        )
        leaf = MultiSigTapScript(points[:3], 3).tap_leaf()
        prev_tx = bytes.fromhex(
            "f72536b7530e28bd6ca407aa9672d00c0a48633c4bea879d3a08be0f6bc8958e"
        )
        fee = 211
        tx_in = TxIn(prev_tx, 0)
        tx_in._value = 9998121
        tx_in._script_pubkey = tap_root_input.script_pubkey()
        tx_out = TxOut(
            tx_in.value(network="signet") - fee, tap_root_output.script_pubkey()
        )
        tx_obj = Tx(2, [tx_in], [tx_out], 0, network="signet", segwit=True)
        tx_in.witness.items = []
        tx_obj.initialize_p2tr_multisig(
            0,
            tap_root_input.control_block(leaf),
            leaf.tap_script,
        )
        sigs = [
            tx_obj.get_sig_taproot(0, priv, ext_flag=1) for priv in private_keys[:3]
        ]
        tx_obj.finalize_p2tr_multisig(0, sigs)
        self.assertEqual(fee, tx_obj.vbytes())
        self.assertTrue(tx_obj.verify())
        tx_in.sequence = Sequence.from_relative_time(18 * 512)
        fee = 195
        tx_out.amount = tx_in.value(network="signet") - fee
        tx_obj = Tx(2, [tx_in], [tx_out], 0, network="signet", segwit=True)
        leaf = MultiSigTapScript(points[:2], 2, sequence=tx_in.sequence).tap_leaf()
        tx_in.witness.items = []
        tx_obj.initialize_p2tr_multisig(
            0,
            tap_root_input.control_block(leaf),
            leaf.tap_script,
        )
        sigs = [
            tx_obj.get_sig_taproot(0, priv, ext_flag=1) for priv in private_keys[:2]
        ]
        self.assertTrue(tx_obj.finalize_p2tr_multisig(0, sigs))
        self.assertEqual(fee, tx_obj.vbytes())
        self.assertTrue(tx_obj.verify())
        tx_in.sequence = Sequence(tx_in.sequence - 1)
        tx_in.witness.items = []
        tx_obj.initialize_p2tr_multisig(
            0,
            tap_root_input.control_block(leaf),
            leaf.tap_script,
        )
        sigs = [
            tx_obj.get_sig_taproot(0, priv, ext_flag=1) for priv in private_keys[:2]
        ]
        tx_obj.finalize_p2tr_multisig(0, sigs)
        self.assertFalse(tx_obj.verify())
        tx_in.sequence = Sequence.from_relative_time(18 * 512 * 2)
        fee = 170
        tx_out.amount = tx_in.value(network="signet") - fee
        tx_obj = Tx(2, [tx_in], [tx_out], 0, network="signet", segwit=True)
        leaf = MultiSigTapScript(points[:1], 1, sequence=tx_in.sequence).tap_leaf()
        tx_in.witness.items = []
        tx_obj.initialize_p2tr_multisig(
            0,
            tap_root_input.control_block(leaf),
            leaf.tap_script,
        )
        sigs = [
            tx_obj.get_sig_taproot(0, priv, ext_flag=1) for priv in private_keys[:1]
        ]
        tx_obj.finalize_p2tr_multisig(0, sigs)
        self.assertEqual(fee, tx_obj.vbytes())
        self.assertTrue(tx_obj.verify())
        tx_in.sequence = Sequence(tx_in.sequence - 1)
        tx_in.witness.items = []
        tx_obj = Tx(2, [tx_in], [tx_out], 0, network="signet", segwit=True)
        tx_obj.initialize_p2tr_multisig(
            0,
            tap_root_input.control_block(leaf),
            leaf.tap_script,
        )
        sigs = [
            tx_obj.get_sig_taproot(0, priv, ext_flag=1) for priv in private_keys[:1]
        ]
        tx_obj.finalize_p2tr_multisig(0, sigs)
        self.assertFalse(tx_obj.verify())

    def test_degrading_multisig_2(self):
        hd_priv_key = HDPrivateKey.from_mnemonic(
            "oil oil oil oil oil oil oil oil oil oil oil oil", network="signet"
        )
        # create a 3-of-5 multi-leaf multisig
        private_keys = [
            hd_priv_key.get_p2tr_receiving_privkey(address_num=i) for i in range(5)
        ]
        points = [priv.point for priv in private_keys]
        tr_multisig = TapRootMultiSig(points, 3)
        tap_root_input = tr_multisig.degrading_multisig_tap_root(
            sequence_block_interval=18
        )
        tap_root_output = tr_multisig.degrading_multisig_tap_root(
            sequence_time_interval=18 * 512
        )
        self.assertEqual(
            tap_root_input.address(network="signet"),
            "tb1peffn9zd7lstjw8ets6acufenjkz48fsrgz3jadwnx48p40rttyzs4djsxw",
        )
        leaf = MultiSigTapScript(points[-3:], 3).tap_leaf()
        prev_tx = bytes.fromhex(
            "5e596ecf4ccc225e90ca44f3d66ebb1418648b8fb6d5c1ceb3d9be042528aad5"
        )
        fee = 211
        tx_in = TxIn(prev_tx, 0)
        tx_in._value = 9998291
        tx_in._script_pubkey = tap_root_input.script_pubkey()
        tx_out = TxOut(tx_in.value() - fee, tap_root_output.script_pubkey())
        tx_obj = Tx(2, [tx_in], [tx_out], 0, network="signet", segwit=True)
        tx_in.witness.items = []
        tx_obj.initialize_p2tr_multisig(
            0,
            tap_root_input.control_block(leaf),
            leaf.tap_script,
        )
        sigs = [
            tx_obj.get_sig_taproot(0, priv, ext_flag=1) for priv in private_keys[-3:]
        ]
        tx_obj.finalize_p2tr_multisig(0, sigs)
        self.assertEqual(fee, tx_obj.vbytes())
        self.assertTrue(tx_obj.verify())
        tx_in.sequence = Sequence.from_relative_blocks(18)
        fee = 195
        tx_out.amount = tx_in.value() - fee
        leaf = MultiSigTapScript(points[-2:], 2, sequence=tx_in.sequence).tap_leaf()
        tx_in.witness.items = []
        tx_obj = Tx(2, [tx_in], [tx_out], 0, network="signet", segwit=True)
        tx_obj.initialize_p2tr_multisig(
            0,
            tap_root_input.control_block(leaf),
            leaf.tap_script,
        )
        sigs = [
            tx_obj.get_sig_taproot(0, priv, ext_flag=1) for priv in private_keys[-2:]
        ]
        tx_obj.finalize_p2tr_multisig(0, sigs)
        self.assertEqual(fee, tx_obj.vbytes())
        self.assertTrue(tx_obj.verify())
        tx_in.sequence = Sequence(tx_in.sequence - 1)
        tx_in.witness.items = []
        tx_obj = Tx(2, [tx_in], [tx_out], 0, network="signet", segwit=True)
        tx_obj.initialize_p2tr_multisig(
            0,
            tap_root_input.control_block(leaf),
            leaf.tap_script,
        )
        sigs = [
            tx_obj.get_sig_taproot(0, priv, ext_flag=1) for priv in private_keys[-2:]
        ]
        tx_obj.finalize_p2tr_multisig(0, sigs)
        self.assertFalse(tx_obj.verify())
        tx_in.sequence = Sequence.from_relative_blocks(18 * 2)
        fee = 170
        tx_out.amount = tx_in.value() - fee
        leaf = MultiSigTapScript(points[-1:], 1, sequence=tx_in.sequence).tap_leaf()
        tx_in.witness.items = []
        tx_obj = Tx(2, [tx_in], [tx_out], 0, network="signet", segwit=True)
        tx_obj.initialize_p2tr_multisig(
            0,
            tap_root_input.control_block(leaf),
            leaf.tap_script,
        )
        sigs = [
            tx_obj.get_sig_taproot(0, priv, ext_flag=1) for priv in private_keys[-1:]
        ]
        tx_obj.finalize_p2tr_multisig(0, sigs)
        self.assertEqual(fee, tx_obj.vbytes())
        self.assertTrue(tx_obj.verify())
        tx_in.sequence = Sequence(tx_in.sequence - 1)
        tx_in.witness.items = []
        tx_obj = Tx(2, [tx_in], [tx_out], 0, network="signet", segwit=True)
        tx_obj.initialize_p2tr_multisig(
            0,
            tap_root_input.control_block(leaf),
            leaf.tap_script,
        )
        sigs = [
            tx_obj.get_sig_taproot(0, priv, ext_flag=1) for priv in private_keys[-1:]
        ]
        tx_obj.finalize_p2tr_multisig(0, sigs)
        self.assertFalse(tx_obj.verify())
