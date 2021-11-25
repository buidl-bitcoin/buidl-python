from itertools import combinations
from random import randint
from unittest import TestCase

from buidl.ecc import N, G, S256Point
from buidl.hd import HDPrivateKey
from buidl.helper import SIGHASH_DEFAULT
from buidl.taproot import MultiSigTapScript, MuSigTapScript, TapRootMultiSig
from buidl.tx import Tx, TxIn, TxOut
from buidl.witness import Witness


class MuSigTest(TestCase):
    def test_single_leaf_multisig(self):
        hd_priv_key = HDPrivateKey.from_mnemonic(
            "oil oil oil oil oil oil oil oil oil oil oil oil", network="signet"
        )
        # create a 3-of-5 single-leaf multisig
        private_keys = [
            hd_priv_key.get_p2tr_receiving_privkey(address=i) for i in range(5)
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

    def test_multi_leaf_multisig(self):
        hd_priv_key = HDPrivateKey.from_mnemonic(
            "oil oil oil oil oil oil oil oil oil oil oil oil", network="signet"
        )
        # create a 3-of-5 multi-leaf multisig
        private_keys = [
            hd_priv_key.get_p2tr_receiving_privkey(address=i) for i in range(5)
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

    def test_musig(self):
        hd_priv_key = HDPrivateKey.from_mnemonic(
            "oil oil oil oil oil oil oil oil oil oil oil oil", network="signet"
        )
        # create a 3-of-5 multi-leaf musig
        private_keys = []
        for i in range(5):
            private_keys.append(hd_priv_key.get_p2tr_receiving_privkey(address=i))
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

    def test_internal_pubkey_musig(self):
        hd_priv_key = HDPrivateKey.from_mnemonic(
            "oil oil oil oil oil oil oil oil oil oil oil oil", network="signet"
        )
        # create a 3-of-5 multi-leaf musig
        private_keys = []
        for i in range(5):
            private_keys.append(hd_priv_key.get_p2tr_receiving_privkey(address=i))
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
            hd_priv_key.get_p2tr_receiving_privkey(address=i) for i in range(5)
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
            hd_priv_key.get_p2tr_receiving_privkey(address=i) for i in range(5)
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
