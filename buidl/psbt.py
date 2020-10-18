from io import BytesIO
from unittest import TestCase

from ecc import PrivateKey, S256Point, Signature
from hd import HDPrivateKey, HDPublicKey
from helper import (
    base64_decode,
    base64_encode,
    child_to_path,
    encode_varstr,
    int_to_little_endian,
    little_endian_to_int,
    op_code_to_number,
    parse_binary_path,
    read_varint,
    read_varstr,
    serialize_binary_path,
    serialize_key_value,
    SIGHASH_ALL,
)
from script import (
    RedeemScript,
    Script,
    WitnessScript,
)
from tx import Tx, TxIn, TxOut
from witness import Witness


PSBT_MAGIC = b'\x70\x73\x62\x74'
PSBT_SEPARATOR = b'\xff'
PSBT_DELIMITER = b'\x00'
# PSBT global
PSBT_GLOBAL_UNSIGNED_TX = b'\x00'
PSBT_GLOBAL_XPUB = b'\x01'
# PSBT in
PSBT_IN_NON_WITNESS_UTXO = b'\x00'
PSBT_IN_WITNESS_UTXO = b'\x01'
PSBT_IN_PARTIAL_SIG = b'\x02'
PSBT_IN_SIGHASH_TYPE = b'\x03'
PSBT_IN_REDEEM_SCRIPT = b'\x04'
PSBT_IN_WITNESS_SCRIPT = b'\x05'
PSBT_IN_BIP32_DERIVATION = b'\x06'
PSBT_IN_FINAL_SCRIPTSIG = b'\x07'
PSBT_IN_FINAL_SCRIPTWITNESS = b'\x08'
PSBT_IN_POR_COMMITMENT = b'\x09'
# PSBT out
PSBT_OUT_REDEEM_SCRIPT = b'\x00'
PSBT_OUT_WITNESS_SCRIPT = b'\x01'
PSBT_OUT_BIP32_DERIVATION = b'\x02'


class NamedPublicKey(S256Point):

    def __repr__(self):
        return 'Point:\n{}\nPath:\n{}:{}\n'.format(self.sec().hex(), self.root_fingerprint.hex(), self.root_path)

    def add_raw_path_data(self, raw_path):
        self.root_fingerprint = raw_path[:4]
        self.root_path = parse_binary_path(raw_path[4:])
        self.raw_path = raw_path

    @classmethod
    def parse(cls, key, s):
        point = super().parse(key[1:])
        point.__class__ = cls
        point.add_raw_path_data(read_varstr(s))
        return point

    def serialize(self, prefix):
        return serialize_key_value(prefix + self.sec(), self.raw_path)


class NamedHDPublicKey(HDPublicKey):

    def __repr__(self):
        return 'HD:\n{}\nPath:\n{}:{}\n'.format(super().__repr__(), self.root_fingerprint.hex(), self.root_path)

    def add_raw_path_data(self, raw_path):
        self.root_fingerprint = raw_path[:4]
        bin_path = raw_path[4:]
        self.root_path = parse_binary_path(bin_path)
        if self.depth != len(bin_path) // 4:
            raise ValueError('raw path calculated depth and depth are different')
        self.raw_path = raw_path
        self.sync_point()

    def sync_point(self):
        self.point.__class__ = NamedPublicKey
        self.point.root_fingerprint = self.root_fingerprint
        self.point.root_path = self.root_path
        self.point.raw_path = self.raw_path

    def child(self, index):
        child = super().child(index)
        child.__class__ = self.__class__
        child.root_fingerprint = self.root_fingerprint
        child.root_path = self.root_path + child_to_path(index)
        child.raw_path = self.raw_path + int_to_little_endian(index, 4)
        child.sync_point()
        return child

    def pubkey_lookup(self, max_child=9):
        lookup = {}
        for child_index in range(max_child+1):
            child = self.child(child_index)
            lookup[child.sec()] = child
            lookup[child.hash160()] = child
        return lookup

    def redeem_script_lookup(self, max_external=9, max_internal=9):
        '''Returns a dictionary of RedeemScripts associated with p2sh-p2wpkh for the BIP44 child ScriptPubKeys'''
        # create a lookup to send back
        lookup = {}
        # create the external child (0)
        external = self.child(0)
        # loop through to the maximum external child + 1
        for child_index in range(max_external+1):
            # grab the child at the index
            child = external.child(child_index)
            # create the p2sh-p2wpkh RedeemScript of [0, hash160]
            redeem_script = RedeemScript([0, child.hash160()])
            # hash160 of the RedeemScript is the key, RedeemScript is the value
            lookup[redeem_script.hash160()] = redeem_script
        # create the internal child (1)
        internal = self.child(1)
        # loop through to the maximum internal child + 1
        for child_index in range(max_internal+1):
            # grab the child at the index
            child = internal.child(child_index)
            # create the p2sh-p2wpkh RedeemScript of [0, hash160]
            redeem_script = RedeemScript([0, child.hash160()])
            # hash160 of the RedeemScript is the key, RedeemScript is the value
            lookup[redeem_script.hash160()] = redeem_script
        # return the lookup
        return lookup

    def bip44_lookup(self, max_external=9, max_internal=9):
        external = self.child(0)
        internal = self.child(1)
        return {**external.pubkey_lookup(max_external), **internal.pubkey_lookup(max_internal)}

    @classmethod
    def parse(cls, key, s):
        hd_key = cls.raw_parse(BytesIO(key[1:]))
        hd_key.__class__ = cls
        hd_key.add_raw_path_data(read_varstr(s))
        return hd_key

    @classmethod
    def from_hd_priv(cls, hd_priv, path):
        hd_key = hd_priv.traverse(path).pub
        hd_key.__class__ = cls
        hd_key.add_raw_path_data(hd_priv.fingerprint() + serialize_binary_path(path))
        return hd_key

    def serialize(self):
        return serialize_key_value(PSBT_GLOBAL_XPUB + self.raw_serialize(), self.raw_path)

    def is_ancestor(self, named_pubkey):
        return named_pubkey.raw_path.startswith(self.raw_path)

    def verify_descendent(self, named_pubkey):
        if not self.is_ancestor(named_pubkey):
            raise ValueError('path is not a descendent of this key')
        remainder = named_pubkey.raw_path[len(self.raw_path):]
        current = self
        while len(remainder):
            child_index = little_endian_to_int(remainder[:4])
            current = current.child(child_index)
            remainder = remainder[4:]
        return current.point == named_pubkey


class NamedHDPublicKeyTest(TestCase):

    def test_redeem_script_lookup(self):
        hex_named_hd = '4f01043587cf034d513c1580000000fb406c9fec09b6957a3449d2102318717b0c0d230b657d0ebc6698abd52145eb02eaf3397fea02c5dac747888a9e535eaf3c7e7cb9d5f2da77ddbdd943592a14af10fbfef36f2c0000800100008000000080'
        stream = BytesIO(bytes.fromhex(hex_named_hd))
        named_hd = NamedHDPublicKey.parse(read_varstr(stream), stream)
        redeem_script_lookup = named_hd.redeem_script_lookup(max_external=1, max_internal=1)
        want = {
            bytes.fromhex('e2e642a0ab2cd9a77ae21e7f66610bc7e6647788'):
            RedeemScript([0, bytes.fromhex('9a9bfaf8ef6c4b061a30e8e162da3458cfa122c6')]),
            bytes.fromhex('df71c379eef82782c8f88b5228a9caf3f1ca3ecb'):
            RedeemScript([0, bytes.fromhex('b0c0277be1a8ee3e709e279d47eda9ed1058e5fc')]),
            bytes.fromhex('fad70562a3a2f5fdaeacfac35da9411b8d42934f'):
            RedeemScript([0, bytes.fromhex('c9bb368409c824f0a900f2f9b935d6de8c8b3ef7')]),
            bytes.fromhex('7d3dc1a56742708417819e201a4c572887e9555c'):
            RedeemScript([0, bytes.fromhex('1d36b1aa0b873fc919d3823e8bd162eba62ecf5d')]),
        }
        self.assertEqual(redeem_script_lookup, want)


class PSBT:

    def __init__(self, tx_obj, psbt_ins, psbt_outs, hd_pubs=None, extra_map=None):
        self.tx_obj = tx_obj
        self.psbt_ins = psbt_ins
        self.psbt_outs = psbt_outs
        self.hd_pubs = hd_pubs or {}
        self.extra_map = extra_map or {}
        self.validate()

    def validate(self):
        '''Checks the PSBT for consistency'''
        if len(self.tx_obj.tx_ins) != len(self.psbt_ins):
            raise ValueError('Number of psbt_ins in the transaction should match the psbt_ins array')
        for i, psbt_in in enumerate(self.psbt_ins):
            # validate the input
            psbt_in.validate()
            tx_in = self.tx_obj.tx_ins[i]
            if tx_in.script_sig.commands:
                raise ValueError('ScriptSig for the tx should not be defined')
            # validate the ScriptSig
            if psbt_in.script_sig:
                tx_in.script_sig = psbt_in.script_sig
                tx_in.witness = psbt_in.witness
                if not self.tx_obj.verify_input(i):
                    raise ValueError('ScriptSig/Witness at input {} provided, but not valid'.format(i))
                tx_in.script_sig = Script()
                tx_in.witness = Witness()
            # validate the signatures
            if psbt_in.sigs:
                for sec, sig in psbt_in.sigs.items():
                    point = S256Point.parse(sec)
                    signature = Signature.parse(sig[:-1])
                    if psbt_in.prev_tx:
                        # legacy
                        if not self.tx_obj.check_sig_legacy(i, point, signature, psbt_in.redeem_script):
                            raise ValueError('legacy signature provided does not validate {}'.format(self))
                    elif psbt_in.prev_out:
                        # segwit
                        if not self.tx_obj.check_sig_segwit(i, point, signature, psbt_in.redeem_script, psbt_in.witness_script):
                            raise ValueError('segwit signature provided does not validate')
            # validate the NamedPublicKeys
            if psbt_in.named_pubs:
                for named_pub in psbt_in.named_pubs.values():
                    for hd_pub in self.hd_pubs.values():
                        if hd_pub.is_ancestor(named_pub):
                            if not hd_pub.verify_descendent(named_pub):
                                raise ValueError('public key {} does not derive from xpub {}'.format(named_pub, hd_pub))
                            break
        if len(self.tx_obj.tx_outs) != len(self.psbt_outs):
            raise ValueError('Number of psbt_outs in the transaction should match the psbt_outs array')
        for psbt_out in self.psbt_outs:
            # validate output
            psbt_out.validate()
            # validate the NamedPublicKeys
            if psbt_out.named_pubs:
                for named_pub in psbt_out.named_pubs.values():
                    for hd_pub in self.hd_pubs.values():
                        if hd_pub.is_ancestor(named_pub):
                            if not hd_pub.verify_descendent(named_pub):
                                raise ValueError('public key {} does not derive from xpub {}'.format(named_pub, hd_pub))
                            break
        return True

    def __repr__(self):
        return 'Tx:\n{}\nPSBT XPUBS:\n{}\nPsbt_Ins:\n{}\nPsbt_Outs:\n{}\nExtra:{}\n'.format(self.tx_obj, self.hd_pubs, self.psbt_ins, self.psbt_outs, self.extra_map)

    @classmethod
    def create(cls, tx_obj):
        '''Create a PSBT from a transaction'''
        # create an array of PSBTIns
        psbt_ins = []
        # iterate through the inputs of the transaction
        for tx_in in tx_obj.tx_ins:
            # Empty ScriptSig and Witness fields
            # if ScriptSig exists, save it then empty it
            if tx_in.script_sig.commands:
                script_sig = tx_in.script_sig
                tx_in.script_sig = Script()
            else:
                script_sig = None
            # if Witness exists, save it then empty it
            if tx_in.witness:
                witness = tx_in.witness
                tx_in.witness = Witness()
            else:
                witness = None
            # Create a PSBTIn with the TxIn, ScriptSig and Witness
            psbt_in = PSBTIn(tx_in, script_sig=script_sig, witness=witness)
            # add PSBTIn to array
            psbt_ins.append(psbt_in)
        # create an array of PSBTOuts
        psbt_outs = []
        # iterate through the outputs of the transaction
        for tx_out in tx_obj.tx_outs:
            # create the PSBTOut with the TxOut
            psbt_out = PSBTOut(tx_out)
            # add PSBTOut to arary
            psbt_outs.append(psbt_out)
        # return an instance with the Tx, PSBTIn array and PSBTOut array
        return cls(tx_obj, psbt_ins, psbt_outs)

    def update(self, tx_lookup, pubkey_lookup, redeem_lookup=None, witness_lookup=None):
        if redeem_lookup is None:
            redeem_lookup = {}
        if witness_lookup is None:
            witness_lookup = {}
        # update each PSBTIn
        for psbt_in in self.psbt_ins:
            psbt_in.update(tx_lookup, pubkey_lookup, redeem_lookup, witness_lookup)
        # update each PSBTOut
        for psbt_out in self.psbt_outs:
            psbt_out.update(pubkey_lookup, redeem_lookup, witness_lookup)

    def sign(self, hd_priv):
        '''Signs appropriate inputs with the hd private key provided'''
        # set the signed boolean to False until we sign something
        signed = False
        # grab the fingerprint of the private key
        fingerprint = hd_priv.fingerprint()
        # iterate through each PSBTIn
        for i, psbt_in in enumerate(self.psbt_ins):
            # iterate through the public keys associated with the PSBTIn
            for named_pub in psbt_in.named_pubs.values():
                # if the fingerprints match
                if named_pub.root_fingerprint == fingerprint:
                    # get the private key at the root_path of the NamedPublicKey
                    private_key = hd_priv.traverse(named_pub.root_path).private_key
                    # check if prev_tx is defined (legacy)
                    if psbt_in.prev_tx:
                        # get the signature using get_sig_legacy
                        sig = self.tx_obj.get_sig_legacy(i, private_key, psbt_in.redeem_script)
                        # update the sigs dict of the PSBTIn object
                        #  key is the sec and the value is the sig
                        psbt_in.sigs[private_key.point.sec()] = sig
                    # Exercise 4: check if prev_out is defined (segwit)
                    elif psbt_in.prev_out:
                        # get the signature using get_sig_segwit
                        sig = self.tx_obj.get_sig_segwit(i, private_key, psbt_in.redeem_script, psbt_in.witness_script)
                        # update the sigs dict of the PSBTIn object
                        #  key is the sec and the value is the sig
                        psbt_in.sigs[private_key.point.sec()] = sig
                    else:
                        raise ValueError('pubkey included without the previous output')
                    # set signed to True
                    signed = True
        # return whether we signed something
        return signed

    def sign_with_private_keys(self, private_keys):
        '''Signs appropriate inputs with the hd private key provided'''
        # set the signed boolean to False until we sign something
        signed = False
        # iterate through each private key
        for private_key in private_keys:
            # grab the point associated with the point
            point = private_key.point
            # iterate through each PSBTIn
            for i, psbt_in in enumerate(self.psbt_ins):
                # if the sec is in the named_pubs dictionary
                if psbt_in.named_pubs.get(point.sec()):
                    if psbt_in.prev_tx:
                        # get the signature using get_sig_legacy
                        sig = self.tx_obj.get_sig_legacy(i, private_key, psbt_in.redeem_script)
                        # update the sigs dict of the PSBTIn object
                        #  key is the sec and the value is the sig
                        psbt_in.sigs[private_key.point.sec()] = sig
                    # Exercise 4: check if prev_out is defined (segwit)
                    elif psbt_in.prev_out:
                        # get the signature using get_sig_segwit
                        sig = self.tx_obj.get_sig_segwit(i, private_key, psbt_in.redeem_script, psbt_in.witness_script)
                        # update the sigs dict of the PSBTIn object
                        #  key is the sec and the value is the sig
                        psbt_in.sigs[private_key.point.sec()] = sig
                    else:
                        raise ValueError('pubkey included without the previous output')
                    # set signed to True
                    signed = True
        # return whether we signed something
        return signed

    def combine(self, other):
        '''combines information from another PSBT to this one'''
        # the tx_obj properties should be the same or raise a ValueError
        if self.tx_obj.hash() != other.tx_obj.hash():
            raise ValueError('cannot combine PSBTs that refer to different transactions')
        # combine the hd_pubs
        self.hd_pubs = {**other.hd_pubs, **self.hd_pubs}
        # combine extra_map
        self.extra_map = {**other.extra_map, **self.extra_map}
        # combine psbt_ins
        for psbt_in_1, psbt_in_2 in zip(self.psbt_ins, other.psbt_ins):
            psbt_in_1.combine(psbt_in_2)
        # combine psbt_outs
        for psbt_out_1, psbt_out_2 in zip(self.psbt_outs, other.psbt_outs):
            psbt_out_1.combine(psbt_out_2)

    def finalize(self):
        '''Finalize the transaction by filling in the ScriptSig and Witness fields for each input'''
        # iterate through the inputs
        for psbt_in in self.psbt_ins:
            # finalize each input
            psbt_in.finalize()

    def final_tx(self):
        '''Returns the broadcast-able transaction'''
        # clone the transaction from self.tx_obj
        tx_obj = self.tx_obj.clone()
        # determine if the transaction is segwit by looking for a witness field
        #  in any PSBTIn. if so, set tx_obj.segwit = True
        if any([psbt_in.witness for psbt_in in self.psbt_ins]):
            tx_obj.segwit = True
        # iterate through the transaction and PSBT inputs together
        #  using zip(tx_obj.tx_ins, self.psbt_ins)
        for tx_in, psbt_in in zip(tx_obj.tx_ins, self.psbt_ins):
            # set the ScriptSig of the transaction input
            tx_in.script_sig = psbt_in.script_sig
            # Exercise 7: if the tx is segwit, set the witness as well
            if tx_obj.segwit:
                # witness should be the PSBTIn witness or an empty Witness()
                tx_in.witness = psbt_in.witness or Witness()
        # check to see that the transaction verifies
        if not tx_obj.verify():
            raise RuntimeError('transaction invalid')
        # return the now filled in transaction
        return tx_obj

    @classmethod
    def parse_base64(cls, b64):
        stream = BytesIO(base64_decode(b64))
        return cls.parse(stream)

    @classmethod
    def parse(cls, s):
        '''Returns an instance of PSBT from a stream'''
        # prefix
        magic = s.read(4)
        if magic != PSBT_MAGIC:
            raise SyntaxError('Incorrect magic')
        separator = s.read(1)
        if separator != PSBT_SEPARATOR:
            raise SyntaxError('No separator')
        # global data
        tx_obj = None
        hd_pubs = {}
        extra_map = {}
        key = read_varstr(s)
        while key != b'':
            psbt_type = key[0:1]
            if psbt_type == PSBT_GLOBAL_UNSIGNED_TX:
                if len(key) != 1:
                    raise KeyError('Wrong length for the key')
                if tx_obj:
                    raise KeyError('Duplicate Key in parsing: {}'.format(key.hex()))
                _ = read_varint(s)
                tx_obj = Tx.parse_legacy(s)
            elif psbt_type == PSBT_GLOBAL_XPUB:
                if len(key) != 79:
                    raise KeyError('Wrong length for the key')
                hd_pub = NamedHDPublicKey.parse(key, s)
                hd_pubs[hd_pub.raw_serialize()] = hd_pub
            else:
                if extra_map.get(key):
                    raise KeyError('Duplicate Key in parsing: {}'.format(key.hex()))
                extra_map[key] = read_varstr(s)
            key = read_varstr(s)
        if not tx_obj:
            raise SyntaxError('transaction is required')
        # per input data
        psbt_ins = []
        for tx_in in tx_obj.tx_ins:
            psbt_ins.append(PSBTIn.parse(s, tx_in))
        # per output data
        psbt_outs = []
        for tx_out in tx_obj.tx_outs:
            psbt_outs.append(PSBTOut.parse(s, tx_out))
        return cls(tx_obj, psbt_ins, psbt_outs, hd_pubs, extra_map)

    def serialize_base64(self):
        return base64_encode(self.serialize())

    def serialize(self):
        # always start with the magic and separator
        result = PSBT_MAGIC + PSBT_SEPARATOR
        # tx
        result += serialize_key_value(PSBT_GLOBAL_UNSIGNED_TX, self.tx_obj.serialize())
        # xpubs
        for xpub in sorted(self.hd_pubs.keys()):
            hd_pub = self.hd_pubs[xpub]
            result += hd_pub.serialize()
        for key in sorted(self.extra_map.keys()):
            result += serialize_key_value(key, self.extra_map[key])
        # delimiter
        result += PSBT_DELIMITER
        # per input data
        for psbt_in in self.psbt_ins:
            result += psbt_in.serialize()
        # per output data
        for psbt_out in self.psbt_outs:
            result += psbt_out.serialize()
        return result


class PSBTIn:

    def __init__(self, tx_in, prev_tx=None, prev_out=None,
                 sigs=None, hash_type=None, redeem_script=None,
                 witness_script=None, named_pubs=None,
                 script_sig=None, witness=None, extra_map=None):
        self.tx_in = tx_in
        self.prev_tx = prev_tx
        self.prev_out = prev_out
        if self.prev_tx and self.prev_out:
            raise ValueError('only one of prev_tx and prev_out should be defined: {} {}'.format(prev_tx, prev_out))
        self.sigs = sigs or {}
        self.hash_type = hash_type
        self.redeem_script = redeem_script
        self.witness_script = witness_script
        self.named_pubs = named_pubs or {}
        self.script_sig = script_sig
        self.witness = witness
        self.extra_map = extra_map or {}
        self.validate()

    def validate(self):
        '''Checks the PSBTIn for consistency'''
        script_pubkey = self.script_pubkey()
        if self.prev_tx:
            if self.tx_in.prev_tx != self.prev_tx.hash():
                raise ValueError('previous transaction specified, but does not match the input tx')
            if self.tx_in.prev_index >= len(self.prev_tx.tx_outs):
                raise ValueError('input refers to an output index that does not exist')
            if self.redeem_script:
                if not script_pubkey.is_p2sh():
                    raise ValueError('RedeemScript defined for non-p2sh ScriptPubKey')
                # non-witness p2sh
                if self.redeem_script.is_p2wsh() or self.redeem_script.is_p2wpkh():
                    raise ValueError('Non-witness UTXO provided for witness input')
                h160 = script_pubkey.commands[1]
                if self.redeem_script.hash160() != h160:
                    raise ValueError('RedeemScript hash160 and ScriptPubKey hash160 do not match')
                for sec in self.named_pubs.keys():
                    try:
                        # this will raise a ValueError if it's not in there
                        self.redeem_script.commands.index(sec)
                    except ValueError:
                        raise ValueError('pubkey is not in RedeemScript {}'.format(self))
            elif script_pubkey.is_p2pkh():
                if len(self.named_pubs) > 1:
                    raise ValueError('too many pubkeys in p2pkh')
                elif len(self.named_pubs) == 1:
                    named_pub = list(self.named_pubs.values())[0]
                    if script_pubkey.commands[2] != named_pub.hash160():
                        raise ValueError('pubkey {} does not match the hash160'.format(named_pub.sec().hex()))
        elif self.prev_out:
            if not script_pubkey.is_p2sh() and not script_pubkey.is_p2wsh() and not script_pubkey.is_p2wpkh():
                raise ValueError('Witness UTXO provided for non-witness input')
            if self.witness_script:  # p2wsh or p2sh-p2wsh
                if not script_pubkey.is_p2wsh() and not (self.redeem_script and self.redeem_script.is_p2wsh()):
                    raise ValueError('WitnessScript provided for non-p2wsh ScriptPubKey')
                if self.redeem_script:
                    h160 = script_pubkey.commands[1]
                    if self.redeem_script.hash160() != h160:
                        raise ValueError('RedeemScript hash160 and ScriptPubKey hash160 do not match')
                    s256 = self.redeem_script.commands[1]
                else:
                    s256 = self.prev_out.script_pubkey.commands[1]
                if self.witness_script.sha256() != s256:
                    raise ValueError('WitnessScript sha256 and output sha256 do not match')
                for sec in self.named_pubs.keys():
                    try:
                        # this will raise a ValueError if it's not in there
                        self.witness_script.commands.index(sec)
                    except ValueError:
                        raise ValueError('pubkey is not in WitnessScript: {}'.format(self))
            elif script_pubkey.is_p2wpkh() or (self.redeem_script and self.redeem_script.is_p2wpkh()):
                if len(self.named_pubs) > 1:
                    raise ValueError('too many pubkeys in p2wpkh or p2sh-p2wpkh')
                elif len(self.named_pubs) == 1:
                    named_pub = list(self.named_pubs.values())[0]
                    if script_pubkey.commands[1] != named_pub.hash160():
                        raise ValueError('pubkey {} does not match the hash160'.format(named_pub.sec().hex()))

    def __repr__(self):
        return 'TxIn:\n{}\nPrev Tx:\n{}\nPrev Output\n{}\nSigs:\n{}\nRedeemScript:\n{}\nWitnessScript:\n{}\nPSBT Pubs:\n{}\nScriptSig:\n{}\nWitness:\n{}\n'.format(self.tx_in, self.prev_tx, self.prev_out, self.sigs, self.redeem_script, self.witness_script, self.named_pubs, self.script_sig, self.witness)

    @classmethod
    def parse(cls, s, tx_in):
        prev_tx = None
        prev_out = None
        sigs = {}
        hash_type = None
        redeem_script = None
        witness_script = None
        named_pubs = {}
        script_sig = None
        witness = None
        extra_map = {}
        key = read_varstr(s)
        while key != b'':
            psbt_type = key[0:1]
            if psbt_type == PSBT_IN_NON_WITNESS_UTXO:
                if len(key) != 1:
                    raise KeyError('Wrong length for the key')
                if prev_tx:
                    raise KeyError('Duplicate Key in parsing: {}'.format(key.hex()))
                tx_len = read_varint(s)
                prev_tx = Tx.parse(s)
                if len(prev_tx.serialize()) != tx_len:
                    raise IOError('tx length does not match')
                tx_in._value = prev_tx.tx_outs[tx_in.prev_index].amount
                tx_in._script_pubkey = prev_tx.tx_outs[tx_in.prev_index].script_pubkey
            elif psbt_type == PSBT_IN_WITNESS_UTXO:
                tx_out_len = read_varint(s)
                if len(key) != 1:
                    raise KeyError('Wrong length for the key')
                if prev_out:
                    raise KeyError('Duplicate Key in parsing: {}'.format(key.hex()))
                prev_out = TxOut.parse(s)
                if len(prev_out.serialize()) != tx_out_len:
                    raise ValueError('tx out length does not match')
                tx_in._value = prev_out.amount
                tx_in._script_pubkey = prev_out.script_pubkey
            elif psbt_type == PSBT_IN_PARTIAL_SIG:
                if sigs.get(key[1:]):
                    raise KeyError('Duplicate Key in parsing: {}'.format(key.hex()))
                sigs[key[1:]] = read_varstr(s)
            elif psbt_type == PSBT_IN_SIGHASH_TYPE:
                if len(key) != 1:
                    raise KeyError('Wrong length for the key')
                if hash_type:
                    raise KeyError('Duplicate Key in parsing: {}'.format(key.hex()))
                hash_type = little_endian_to_int(read_varstr(s))
            elif psbt_type == PSBT_IN_REDEEM_SCRIPT:
                if len(key) != 1:
                    raise KeyError('Wrong length for the key')
                if redeem_script:
                    raise KeyError('Duplicate Key in parsing: {}'.format(key.hex()))
                redeem_script = RedeemScript.parse(s)
            elif psbt_type == PSBT_IN_WITNESS_SCRIPT:
                if len(key) != 1:
                    raise KeyError('Wrong length for the key')
                if witness_script:
                    raise KeyError('Duplicate Key in parsing: {}'.format(key.hex()))
                witness_script = WitnessScript.parse(s)
            elif psbt_type == PSBT_IN_BIP32_DERIVATION:
                if len(key) != 34:
                    raise KeyError('Wrong length for the key')
                named_pub = NamedPublicKey.parse(key, s)
                named_pubs[named_pub.sec()] = named_pub
            elif psbt_type == PSBT_IN_FINAL_SCRIPTSIG:
                if len(key) != 1:
                    raise KeyError('Wrong length for the key')
                if script_sig:
                    raise KeyError('Duplicate Key in parsing: {}'.format(key.hex()))
                script_sig = Script.parse(s)
            elif psbt_type == PSBT_IN_FINAL_SCRIPTWITNESS:
                if len(key) != 1:
                    raise KeyError('Wrong length for the key')
                if witness:
                    raise KeyError('Duplicate Key in parsing: {}'.format(key.hex()))
                _ = read_varint(s)
                witness = Witness.parse(s)
            else:
                if extra_map.get(key):
                    raise KeyError('Duplicate Key in parsing: {}'.format(key.hex()))
                extra_map[key] = read_varstr(s)
            key = read_varstr(s)
        return cls(tx_in, prev_tx, prev_out, sigs, hash_type, redeem_script,
                   witness_script, named_pubs, script_sig, witness, extra_map)

    def serialize(self):
        result = b''
        if self.prev_tx:
            result += serialize_key_value(PSBT_IN_NON_WITNESS_UTXO, self.prev_tx.serialize())
        elif self.prev_out:
            result += serialize_key_value(PSBT_IN_WITNESS_UTXO, self.prev_out.serialize())
        # we need to put the keys in the witness script or redeem script order
        keys = []
        if self.witness_script:
            for command in self.witness_script.commands:
                if self.sigs.get(command):
                    keys.append(command)
        elif self.redeem_script and not self.redeem_script.is_p2wpkh():
            for command in self.redeem_script.commands:
                if self.sigs.get(command):
                    keys.append(command)
        else:
            keys = sorted(self.sigs.keys())
        for key in keys:
            result += serialize_key_value(PSBT_IN_PARTIAL_SIG + key, self.sigs[key])
        if self.hash_type:
            result += serialize_key_value(PSBT_IN_SIGHASH_TYPE, int_to_little_endian(self.hash_type, 4))
        if self.redeem_script:
            result += serialize_key_value(PSBT_IN_REDEEM_SCRIPT, self.redeem_script.raw_serialize())
        if self.witness_script:
            result += serialize_key_value(PSBT_IN_WITNESS_SCRIPT, self.witness_script.raw_serialize())
        for sec in sorted(self.named_pubs.keys()):
            named_pub = self.named_pubs[sec]
            result += named_pub.serialize(PSBT_IN_BIP32_DERIVATION)
        if self.script_sig:
            result += serialize_key_value(PSBT_IN_FINAL_SCRIPTSIG, self.script_sig.raw_serialize())
        if self.witness:
            result += serialize_key_value(PSBT_IN_FINAL_SCRIPTWITNESS, self.witness.serialize())
        # extra
        for key in sorted(self.extra_map.keys()):
            result += encode_varstr(key) + encode_varstr(self.extra_map[key])
        # delimiter
        result += PSBT_DELIMITER
        return result

    def script_pubkey(self):
        if self.prev_tx:
            return self.prev_tx.tx_outs[self.tx_in.prev_index].script_pubkey
        elif self.prev_out:
            return self.prev_out.script_pubkey
        else:
            return None

    def update(self, tx_lookup, pubkey_lookup, redeem_lookup, witness_lookup):
        '''Updates the input with NamedPublicKeys, RedeemScript or WitnessScript that
        correspond'''
        # the input might already have a previous transaction
        prev_tx = self.prev_tx or tx_lookup.get(self.tx_in.prev_tx)
        # grab the output at the previous index, or alternatively get the self.prev_out
        if prev_tx:
            prev_out = prev_tx.tx_outs[self.tx_in.prev_index]
        else:
            prev_out = self.prev_out
        # if we don't know the previous output we can't update anything
        if not prev_tx and not prev_out:
            return
        # get the ScriptPubKey that we're unlocking
        script_pubkey = prev_out.script_pubkey
        # Set the _value and _script_pubkey properties of the TxIn object
        #  so that no full node is needed to look those up
        self.tx_in._value = prev_out.amount
        self.tx_in._script_pubkey = script_pubkey
        # grab the RedeemScript
        if script_pubkey.is_p2sh():
            # see if we have a RedeemScript already defined or in the lookup
            self.redeem_script = self.redeem_script or redeem_lookup.get(script_pubkey.commands[1])
            # if there's no RedeemScript, we can't do any more updating, so return
            if not self.redeem_script:
                return
        # Exercise 2: if we have p2wpkh or p2sh-p2wpkh see if we have the appropriate NamedPublicKey
        if script_pubkey.is_p2wpkh() or \
           (self.redeem_script and self.redeem_script.is_p2wpkh()):
            # set the prev_out property as this is Segwit
            self.prev_out = prev_out
            # for p2wpkh, the hash160 is the second command of the ScriptPubKey
            # for p2sh-p2wpkh, the hash160 is the second command of the RedeemScript
            if script_pubkey.is_p2wpkh():
                h160 = script_pubkey.commands[1]
            else:
                h160 = self.redeem_script.commands[1]
            # see if we have the public key that corresponds to the hash160
            named_pub = pubkey_lookup.get(h160)
            # if so add it to the named_pubs dictionary
            if named_pub:
                self.named_pubs[named_pub.sec()] = named_pub.point
        # Exercise 12: if we have p2wsh or p2sh-p2wsh see if we have one or more NamedPublicKeys
        elif script_pubkey.is_p2wsh() or (self.redeem_script and self.redeem_script.is_p2wsh()):
            # set the prev_out property as this is Segwit
            self.prev_out = prev_out
            # for p2wsh, the sha256 is the second command of the ScriptPubKey
            # for p2sh-p2wsh, the sha256 is the second command of the RedeemScript
            if script_pubkey.is_p2wsh():
                s256 = script_pubkey.commands[1]
            else:
                s256 = self.redeem_script.commands[1]
            # see if we have the WitnessScript that corresponds to the sha256
            self.witness_script = self.witness_script or witness_lookup.get(s256)
            if self.witness_script:
                # go through the commands of the WitnessScript for NamedPublicKeys
                for command in self.witness_script.commands:
                    named_pub = pubkey_lookup.get(command)
                    if named_pub:
                        self.named_pubs[named_pub.sec()] = named_pub.point
        # we've eliminated p2sh wrapped segwit, handle p2sh here
        elif script_pubkey.is_p2sh():
            # set the prev_tx property as it's not segwit
            self.prev_tx = prev_tx
            # go through the commands of the RedeemScript for NamedPublicKeys
            for command in self.redeem_script.commands:
                # if we find a NamedPublicKey, add to the named_pubs dictionary
                #  key is compressed sec, value is the point object
                named_pub = pubkey_lookup.get(command)
                if named_pub:
                    self.named_pubs[named_pub.sec()] = named_pub.point
        # if we have p2pkh, see if we have the appropriate NamedPublicKey
        elif script_pubkey.is_p2pkh():
            # set the prev_tx property as it's not segwit
            self.prev_tx = prev_tx
            # look for the NamedPublicKey that corresponds to the hash160
            #  which is the 3rd command of the ScriptPubKey
            named_pub = pubkey_lookup.get(script_pubkey.commands[2])
            if named_pub:
                # if it exists, add to the named_pubs dict
                #  key is the sec and the value is the point
                self.named_pubs[named_pub.sec()] = named_pub.point
        # else we throw a ValueError
        else:
            raise ValueError('cannot update a transaction because it is not p2pkh, p2sh, p2wpkh or p2wsh'.format(script_pubkey))

    def combine(self, other):
        '''Combines two PSBTIn objects into self'''
        # if prev_tx is defined in the other, but not in self, add
        if self.prev_tx is None and other.prev_tx:
            self.prev_tx = other.prev_tx
        # if prev_tx is defined in the other, but not in self, add
        if self.prev_out is None and other.prev_out:
            self.prev_out = other.prev_out
        # combine the sigs
        self.sigs = {**self.sigs, **other.sigs}
        # if hash_type is defined in the other, but not in self, add
        if self.hash_type is None and other.hash_type:
            self.hash_type = other.hash_type
        # if redeem_script is defined in the other, but not in self, add
        if self.redeem_script is None and other.redeem_script:
            self.redeem_script = other.redeem_script
        # if witness_script is defined in the other, but not in self, add
        if self.witness_script is None and other.witness_script:
            self.witness_script = other.witness_script
        # combine the pubs
        self.named_pubs = {**other.named_pubs, **self.named_pubs}
        # if script_sig is defined in the other, but not in self, add
        if self.script_sig is None and other.script_sig:
            self.script_sig = other.script_sig
        # if witness is defined in the other, but not in self, add
        if self.witness is None and other.witness:
            self.witness = other.witness
        # combine extra_map
        self.extra_map = {**other.extra_map, **self.extra_map}

    def finalize(self):
        '''Removes all sigs/named pubs/RedeemScripts/WitnessScripts and
        sets the script_sig and witness fields'''
        # get the ScriptPubKey for this input
        script_pubkey = self.script_pubkey()
        # if the ScriptPubKey is p2sh
        if script_pubkey.is_p2sh():
            # make sure there's a RedeemScript
            if not self.redeem_script:
                raise RuntimeError('Cannot finalize p2sh without a RedeemScript')
        # Exercise 6: if p2wpkh or p2sh-p2wpkh
        if script_pubkey.is_p2wpkh() or (self.redeem_script and self.redeem_script.is_p2wpkh()):
            # check to see that we have exactly 1 signature
            if len(self.sigs) != 1:
                raise RuntimeError('p2wpkh or p2sh-p2wpkh should have exactly 1 signature')
            # the key of the sigs dict is the compressed SEC pubkey
            sec = list(self.sigs.keys())[0]
            # the value of the sigs dict is the signature
            sig = list(self.sigs.values())[0]
            # set the ScriptSig to the RedeemScript if there is one
            if self.redeem_script:
                self.script_sig = Script([self.redeem_script.raw_serialize()])
            else:
                self.script_sig = Script()
            # set the Witness to sig and sec
            self.witness = Witness([sig, sec])
        # Exercise 15: if p2wsh or p2sh-p2wsh
        elif script_pubkey.is_p2wsh() or (self.redeem_script and self.redeem_script.is_p2wsh()):
            # make sure there's a WitnessScript
            if not self.witness_script:
                raise RuntimeError('Cannot finalize p2wsh or p2sh-p2wsh without a WitnessScript')
            # convert the first command to a number (required # of sigs)
            num_sigs = op_code_to_number(self.witness_script.commands[0])
            # make sure we have at least the number of sigs required
            if len(self.sigs) < num_sigs:
                raise RuntimeError('Cannot finalize p2wsh or p2sh-p2wsh because {} sigs were provided where {} were needed'.format(len(self.sigs), num_sigs))
            # create a list of items for the Witness. Start with b'\x00' for the
            #  OP_CHECKMULTISIG off-by-one error
            witness_items = [b'\x00']
            # for each command in the WitnessScript
            for command in self.witness_script.commands:
                # grab the sig for the pubkey
                sig = self.sigs.get(command)
                # if the sig exists, then add to the Witness item list
                if sig is not None:
                    witness_items.append(sig)
                # when we have enough signatures, break
                if len(witness_items) - 1 >= num_sigs:
                    break
            # make sure we have enough sigs to pass validation
            if len(witness_items) - 1 < num_sigs:
                raise RuntimeError('Not enough signatures provided for p2sh-p2wsh')
            # add the raw WitnessScript as the last item for p2wsh execution
            witness_items.append(self.witness_script.raw_serialize())
            # create the witness
            self.witness = Witness(witness_items)
            # set the ScriptSig to the RedeemScript if there is one
            if self.redeem_script:
                self.script_sig = Script([self.redeem_script.raw_serialize()])
            else:
                self.script_sig = Script()
        # we've eliminated p2sh wrapped segwit, handle p2sh here
        elif script_pubkey.is_p2sh():
            # convert the first command to a number (required # of sigs)
            num_sigs = op_code_to_number(self.redeem_script.commands[0])
            # make sure we have at least the number of sigs required
            if len(self.sigs) < num_sigs:
                raise RuntimeError('Cannot finalize p2sh because {} sigs were provided where {} were needed'.format(len(self.sigs), num_sigs))
            # create a list of commands for the ScriptSig. Start with 0 for the
            #  OP_CHECKMULTISIG off-by-one error
            script_sig_commands = [0]
            # for each command in the RedeemScript
            for command in self.redeem_script.commands:
                # skip if the command is an integer
                if type(command) == int:
                    continue
                # grab the sig for the pubkey
                sig = self.sigs.get(command)
                # if the sig exists, then add to the ScriptSig command list
                if sig is not None:
                    script_sig_commands.append(sig)
                # when we have enough signatures, break
                if len(script_sig_commands) - 1 >= num_sigs:
                    break
            # make sure we have enough sigs to pass validation
            if len(script_sig_commands) < num_sigs:
                raise RuntimeError('Not enough signatures provided for p2wsh')
            # add the raw redeem script as the last command for p2sh execution
            script_sig_commands.append(self.redeem_script.raw_serialize())
            # change the ScriptSig to be a Script with the commands we've gathered
            self.script_sig = Script(script_sig_commands)
        elif script_pubkey.is_p2pkh():
            # check to see that we have exactly 1 signature
            if len(self.sigs) != 1:
                raise RuntimeError('P2pkh requires exactly 1 signature')
            # the key of the sigs dict is the compressed SEC pubkey
            sec = list(self.sigs.keys())[0]
            # the value of the sigs dict is the signature
            sig = list(self.sigs.values())[0]
            # set the ScriptSig, which is Script([sig, sec])
            self.script_sig = Script([sig, sec])
        else:
            raise ValueError('Cannot finalize this ScriptPubKey: {}'.format(script_pubkey))
        # reset sigs, hash_type, redeem_script, witness_script and named_pubs to be empty
        self.sigs = {}
        self.hash_type = None
        self.redeem_script = None
        self.witness_script = None
        self.named_pubs = {}


class PSBTOut:

    def __init__(self, tx_out, redeem_script=None,
                 witness_script=None, named_pubs=None, extra_map=None):
        self.tx_out = tx_out
        self.redeem_script = redeem_script
        self.witness_script = witness_script
        self.named_pubs = named_pubs or {}
        self.extra_map = extra_map or {}
        self.validate()

    def validate(self):
        '''Checks the PSBTOut for consistency'''
        script_pubkey = self.tx_out.script_pubkey
        if script_pubkey.is_p2pkh():
            if self.redeem_script:
                raise KeyError('RedeemScript included in p2pkh output')
            if self.witness_script:
                raise KeyError('WitnessScript included in p2pkh output')
            if len(self.named_pubs) > 1:
                raise ValueError('too many pubkeys in p2pkh')
            elif len(self.named_pubs) == 1:
                named_pub = list(self.named_pubs.values())[0]
                if script_pubkey.commands[2] != named_pub.hash160():
                    raise ValueError('pubkey {} does not match the hash160'.format(named_pub.sec().hex()))
        elif script_pubkey.is_p2wpkh():
            if self.redeem_script:
                raise KeyError('RedeemScript included in p2wpkh output')
            if self.witness_script:
                raise KeyError('WitnessScript included in p2wpkh output')
            if len(self.named_pubs) > 1:
                raise ValueError('too many pubkeys in p2wpkh')
            elif len(self.named_pubs) == 1:
                named_pub = list(self.named_pubs.values())[0]
                if script_pubkey.commands[1] != named_pub.hash160():
                    raise ValueError('pubkey {} does not match the hash160'.format(named_pub.sec().hex()))
        elif self.witness_script:
            if self.redeem_script:
                h160 = script_pubkey.commands[1]
                if self.redeem_script.hash160() != h160:
                    raise ValueError('RedeemScript hash160 and ScriptPubKey hash160 do not match')
                s256 = self.redeem_script.commands[1]
            else:
                s256 = script_pubkey.commands[1]
            if self.witness_script.sha256() != s256:
                raise ValueError('WitnessScript sha256 and output sha256 do not match {} {}'.format(self, self.witness_script.sha256().hex()))
            for sec in self.named_pubs.keys():
                try:
                    # this will raise a ValueError if it's not in there
                    self.witness_script.commands.index(sec)
                except ValueError:
                    raise ValueError('pubkey is not in WitnessScript {}'.format(self))
        elif self.redeem_script:
            for sec in self.named_pubs.keys():
                try:
                    # this will raise a ValueError if it's not in there
                    self.redeem_script.commands.index(sec)
                except ValueError:
                    raise ValueError('pubkey is not in RedeemScript {}'.format(self))

    def __repr__(self):
        return 'TxOut:\n{}\nRedeemScript:\n{}\nWitnessScript\n{}\nPSBT Pubs:\n{}\n'.format(self.tx_out, self.redeem_script, self.witness_script, self.named_pubs)

    @classmethod
    def parse(cls, s, tx_out):
        redeem_script = None
        witness_script = None
        named_pubs = {}
        extra_map = {}
        key = read_varstr(s)
        while key != b'':
            psbt_type = key[0:1]
            if psbt_type == PSBT_OUT_REDEEM_SCRIPT:
                if len(key) != 1:
                    raise KeyError('Wrong length for the key')
                if redeem_script:
                    raise KeyError('Duplicate Key in parsing: {}'.format(key.hex()))
                redeem_script = RedeemScript.parse(s)
            elif psbt_type == PSBT_OUT_WITNESS_SCRIPT:
                if len(key) != 1:
                    raise KeyError('Wrong length for the key')
                if witness_script:
                    raise KeyError('Duplicate Key in parsing: {}'.format(key.hex()))
                witness_script = WitnessScript.parse(s)
            elif psbt_type == PSBT_OUT_BIP32_DERIVATION:
                if len(key) != 34:
                    raise KeyError('Wrong length for the key')
                named_pub = NamedPublicKey.parse(key, s)
                named_pubs[named_pub.sec()] = named_pub
            else:
                if extra_map.get(key):
                    raise KeyError('Duplicate Key in parsing: {}'.format(key.hex()))
                extra_map[key] = read_varstr(s)
            key = read_varstr(s)
        return cls(tx_out, redeem_script, witness_script, named_pubs, extra_map)

    def serialize(self):
        result = b''
        if self.redeem_script:
            result += serialize_key_value(PSBT_OUT_REDEEM_SCRIPT, self.redeem_script.raw_serialize())
        if self.witness_script:
            result += serialize_key_value(PSBT_OUT_WITNESS_SCRIPT, self.witness_script.raw_serialize())
        for key in sorted(self.named_pubs.keys()):
            named_pub = self.named_pubs[key]
            result += named_pub.serialize(PSBT_OUT_BIP32_DERIVATION)
        # extra
        for key in sorted(self.extra_map.keys()):
            result += encode_varstr(key) + encode_varstr(self.extra_map[key])
        # delimiter
        result += PSBT_DELIMITER
        return result

    def update(self, pubkey_lookup, redeem_lookup, witness_lookup):
        '''Updates the output with NamedPublicKeys, RedeemScript or WitnessScript that
        correspond'''
        # get the ScriptPubKey
        script_pubkey = self.tx_out.script_pubkey
        # if the ScriptPubKey is p2sh, check for a RedeemScript
        if script_pubkey.is_p2sh():
            self.redeem_script = redeem_lookup.get(script_pubkey.commands[1])
            # if no RedeemScript exists, we can't update, so return
            if not self.redeem_script:
                return
        # Exercise 2: if p2wpkh or p2sh-p2wpkh
        if script_pubkey.is_p2wpkh() or (self.redeem_script and self.redeem_script.is_p2wpkh()):
            # get the hash160 (second command of RedeemScript or ScriptPubKey)
            if self.redeem_script:
                h160 = self.redeem_script.commands[1]
            else:
                h160 = script_pubkey.commands[1]
            # look for the NamedPublicKey and add if there
            named_pub = pubkey_lookup.get(h160)
            if named_pub:
                self.named_pubs[named_pub.sec()] = named_pub.point
        # Exercise 12: if p2wsh/p2sh-p2wsh
        elif script_pubkey.is_p2wsh() or (self.redeem_script and self.redeem_script.is_p2wsh()):
            # get the sha256 (second command of RedeemScript or ScriptPubKey)
            if self.redeem_script:
                s256 = self.redeem_script.commands[1]
            else:
                s256 = script_pubkey.commands[1]
            # look for the WitnessScript using the sha256
            witness_script = witness_lookup.get(s256)
            if witness_script:
                # update the WitnessScript
                self.witness_script = witness_script
                # look through the WitnessScript for any NamedPublicKeys
                for command in witness_script.commands:
                    named_pub = pubkey_lookup.get(command)
                    # if found, add the NamedPublicKey
                    if named_pub:
                        self.named_pubs[named_pub.sec()] = named_pub.point
        # we've eliminated p2sh wrapped segwit, handle p2sh here
        elif script_pubkey.is_p2sh():
            # Look through the commands in the RedeemScript for any NamedPublicKeys
            for command in self.redeem_script.commands:
                named_pub = pubkey_lookup.get(command)
                # if a NamedPublicKey exists
                if named_pub:
                    # add to the named_pubs dictionary
                    #  key is sec and the point is the value
                    self.named_pubs[named_pub.sec()] = named_pub.point
        # Exercise 3: if the ScriptPubKey is p2pkh,
        elif script_pubkey.is_p2pkh():
            # Look at the third command of the ScriptPubKey for the hash160
            # Use that to look up the NamedPublicKey
            named_pub = pubkey_lookup.get(script_pubkey.commands[2])
            # if a NamedPublicKey exists
            if named_pub:
                # add to the named_pubs dictionary
                #  key is sec and the point is the value
                self.named_pubs[named_pub.sec()] = named_pub.point

    def combine(self, other):
        '''Combines two PSBTOuts to self'''
        # if redeem_script is defined in the other, but not in self, add
        if self.redeem_script is None and other.redeem_script:
            self.redeem_script = other.redeem_script
        # if witness_script is defined in the other, but not in self, add
        if self.witness_script is None and other.witness_script:
            self.witness_script = other.witness_script
        # combine the pubs
        self.named_pubs = {**other.named_pubs, **self.named_pubs}
        # combine extra_map
        self.extra_map = {**other.extra_map, **self.extra_map}


class PSBTTest(TestCase):

    def test_create(self):
        tx_in_0 = TxIn(bytes.fromhex('75ddabb27b8845f5247975c8a5ba7c6f336c4570708ebe230caf6db5217ae858'), 0)
        tx_in_1 = TxIn(bytes.fromhex('1dea7cd05979072a3578cab271c02244ea8a090bbb46aa680a65ecd027048d83'), 1)
        tx_out_0 = TxOut(149990000, Script([0, bytes.fromhex('d85c2b71d0060b09c9886aeb815e50991dda124d')]))
        tx_out_1 = TxOut(100000000, Script([0, bytes.fromhex('00aea9a2e5f0f876a588df5546e8742d1d87008f')]))
        tx_obj = Tx(2, [tx_in_0, tx_in_1], [tx_out_0, tx_out_1], 0)
        psbt = PSBT.create(tx_obj)
        want = 'cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAAAAAA='
        self.assertEqual(psbt.serialize_base64(), want)

    def test_update_p2pkh(self):
        psbt_obj = PSBT.parse(BytesIO(bytes.fromhex('70736274ff0100770100000001192f88eeabc44ac213604adbb5b699678815d24b718b5940f5b1b1853f0887480100000000ffffffff0220a10700000000001976a91426d5d464d148454c76f7095fdf03afc8bc8d82c388ac2c9f0700000000001976a9144df14c8c8873451290c53e95ebd1ee8fe488f0ed88ac0000000000000000')))
        hex_named_hd = '4f01043587cf034d513c1580000000fb406c9fec09b6957a3449d2102318717b0c0d230b657d0ebc6698abd52145eb02eaf3397fea02c5dac747888a9e535eaf3c7e7cb9d5f2da77ddbdd943592a14af10fbfef36f2c0000800100008000000080'
        stream = BytesIO(bytes.fromhex(hex_named_hd))
        named_hd = NamedHDPublicKey.parse(read_varstr(stream), stream)
        psbt_obj.tx_obj.testnet = True
        tx_lookup = psbt_obj.tx_obj.get_input_tx_lookup()
        pubkey_lookup = named_hd.bip44_lookup()
        psbt_obj.update(tx_lookup, pubkey_lookup)
        want = '70736274ff0100770100000001192f88eeabc44ac213604adbb5b699678815d24b718b5940f5b1b1853f0887480100000000ffffffff0220a10700000000001976a91426d5d464d148454c76f7095fdf03afc8bc8d82c388ac2c9f0700000000001976a9144df14c8c8873451290c53e95ebd1ee8fe488f0ed88ac00000000000100fda40102000000000102816f71fa2b62d7235ae316d54cb174053c793d16644064405a8326094518aaa901000000171600148900fe9d1950305978d57ebbc25f722bbf131b53feffffff6e3e62f2e005db1bb2a1f12e5ca2bfbb4f82f2ca023c23b0a10a035cabb38fb60000000017160014ae01dce99edb5398cee5e4dc536173d35a9495a9feffffff0278de16000000000017a914a2be7a5646958a5b53f1c3de5a896f6c0ff5419f8740420f00000000001976a9149a9bfaf8ef6c4b061a30e8e162da3458cfa122c688ac02473044022017506b1a15e0540efe5453fcc9c61dcc4457dd00d22cba5e5b937c56944f96ff02207a1c071a8e890cf69c4adef5154d6556e5b356fc09d74a7c811484de289c2d41012102de6c105c8ed6c54d9f7a166fbe3012fecbf4bb3cecda49a8aad1d0c07784110c0247304402207035217de1a2c587b1aaeb5605b043189d551451697acb74ffc99e5a288f4fde022013b7f33a916f9e05846d333b6ea314f56251e74f243682e0ec45ce9e16c6344d01210205174b405fba1b53a44faf08679d63c871cece6c3b2c343bd2d7c559aa32dfb1a2271800220602c1b6ac6e6a625fee295dc2d580f80aae08b7e76eca54ae88a854e956095af77c18fbfef36f2c00008001000080000000800000000000000000000000'
        self.assertEqual(psbt_obj.serialize().hex(), want)

    def test_sign_p2pkh(self):
        hex_psbt = '70736274ff0100770100000001192f88eeabc44ac213604adbb5b699678815d24b718b5940f5b1b1853f0887480100000000ffffffff0220a10700000000001976a91426d5d464d148454c76f7095fdf03afc8bc8d82c388ac2c9f0700000000001976a9144df14c8c8873451290c53e95ebd1ee8fe488f0ed88ac00000000000100fda40102000000000102816f71fa2b62d7235ae316d54cb174053c793d16644064405a8326094518aaa901000000171600148900fe9d1950305978d57ebbc25f722bbf131b53feffffff6e3e62f2e005db1bb2a1f12e5ca2bfbb4f82f2ca023c23b0a10a035cabb38fb60000000017160014ae01dce99edb5398cee5e4dc536173d35a9495a9feffffff0278de16000000000017a914a2be7a5646958a5b53f1c3de5a896f6c0ff5419f8740420f00000000001976a9149a9bfaf8ef6c4b061a30e8e162da3458cfa122c688ac02473044022017506b1a15e0540efe5453fcc9c61dcc4457dd00d22cba5e5b937c56944f96ff02207a1c071a8e890cf69c4adef5154d6556e5b356fc09d74a7c811484de289c2d41012102de6c105c8ed6c54d9f7a166fbe3012fecbf4bb3cecda49a8aad1d0c07784110c0247304402207035217de1a2c587b1aaeb5605b043189d551451697acb74ffc99e5a288f4fde022013b7f33a916f9e05846d333b6ea314f56251e74f243682e0ec45ce9e16c6344d01210205174b405fba1b53a44faf08679d63c871cece6c3b2c343bd2d7c559aa32dfb1a2271800220602c1b6ac6e6a625fee295dc2d580f80aae08b7e76eca54ae88a854e956095af77c18fbfef36f2c00008001000080000000800000000000000000000000'
        psbt_obj = PSBT.parse(BytesIO(bytes.fromhex(hex_psbt)))
        hd_priv = HDPrivateKey.parse('tprv8ZgxMBicQKsPeL2qb9uLkgTKhLHSUUHsxmr2fcGFRBVh6EiBrxHZNTagx3kDXN4yjHsYV5rUYZhpsLCrZYBXzWLWHA4xL3FcCF6CZz1LDGM')
        self.assertTrue(psbt_obj.sign(hd_priv))
        want = '70736274ff0100770100000001192f88eeabc44ac213604adbb5b699678815d24b718b5940f5b1b1853f0887480100000000ffffffff0220a10700000000001976a91426d5d464d148454c76f7095fdf03afc8bc8d82c388ac2c9f0700000000001976a9144df14c8c8873451290c53e95ebd1ee8fe488f0ed88ac00000000000100fda40102000000000102816f71fa2b62d7235ae316d54cb174053c793d16644064405a8326094518aaa901000000171600148900fe9d1950305978d57ebbc25f722bbf131b53feffffff6e3e62f2e005db1bb2a1f12e5ca2bfbb4f82f2ca023c23b0a10a035cabb38fb60000000017160014ae01dce99edb5398cee5e4dc536173d35a9495a9feffffff0278de16000000000017a914a2be7a5646958a5b53f1c3de5a896f6c0ff5419f8740420f00000000001976a9149a9bfaf8ef6c4b061a30e8e162da3458cfa122c688ac02473044022017506b1a15e0540efe5453fcc9c61dcc4457dd00d22cba5e5b937c56944f96ff02207a1c071a8e890cf69c4adef5154d6556e5b356fc09d74a7c811484de289c2d41012102de6c105c8ed6c54d9f7a166fbe3012fecbf4bb3cecda49a8aad1d0c07784110c0247304402207035217de1a2c587b1aaeb5605b043189d551451697acb74ffc99e5a288f4fde022013b7f33a916f9e05846d333b6ea314f56251e74f243682e0ec45ce9e16c6344d01210205174b405fba1b53a44faf08679d63c871cece6c3b2c343bd2d7c559aa32dfb1a2271800220202c1b6ac6e6a625fee295dc2d580f80aae08b7e76eca54ae88a854e956095af77c483045022100b98bb5a69a081543e7e6de6b62b3243c8870211c679a8cf568916631494e99d50220631e1f70231286f059f5cdef8d746f7b8986cfec47346bdfea163528250d7d2401220602c1b6ac6e6a625fee295dc2d580f80aae08b7e76eca54ae88a854e956095af77c18fbfef36f2c00008001000080000000800000000000000000000000'
        self.assertEqual(psbt_obj.serialize().hex(), want)

    def test_finalize_p2pkh(self):
        hex_psbt = '70736274ff0100770100000001192f88eeabc44ac213604adbb5b699678815d24b718b5940f5b1b1853f0887480100000000ffffffff0220a10700000000001976a91426d5d464d148454c76f7095fdf03afc8bc8d82c388ac2c9f0700000000001976a9144df14c8c8873451290c53e95ebd1ee8fe488f0ed88ac00000000000100fda40102000000000102816f71fa2b62d7235ae316d54cb174053c793d16644064405a8326094518aaa901000000171600148900fe9d1950305978d57ebbc25f722bbf131b53feffffff6e3e62f2e005db1bb2a1f12e5ca2bfbb4f82f2ca023c23b0a10a035cabb38fb60000000017160014ae01dce99edb5398cee5e4dc536173d35a9495a9feffffff0278de16000000000017a914a2be7a5646958a5b53f1c3de5a896f6c0ff5419f8740420f00000000001976a9149a9bfaf8ef6c4b061a30e8e162da3458cfa122c688ac02473044022017506b1a15e0540efe5453fcc9c61dcc4457dd00d22cba5e5b937c56944f96ff02207a1c071a8e890cf69c4adef5154d6556e5b356fc09d74a7c811484de289c2d41012102de6c105c8ed6c54d9f7a166fbe3012fecbf4bb3cecda49a8aad1d0c07784110c0247304402207035217de1a2c587b1aaeb5605b043189d551451697acb74ffc99e5a288f4fde022013b7f33a916f9e05846d333b6ea314f56251e74f243682e0ec45ce9e16c6344d01210205174b405fba1b53a44faf08679d63c871cece6c3b2c343bd2d7c559aa32dfb1a2271800220202c1b6ac6e6a625fee295dc2d580f80aae08b7e76eca54ae88a854e956095af77c483045022100b98bb5a69a081543e7e6de6b62b3243c8870211c679a8cf568916631494e99d50220631e1f70231286f059f5cdef8d746f7b8986cfec47346bdfea163528250d7d2401220602c1b6ac6e6a625fee295dc2d580f80aae08b7e76eca54ae88a854e956095af77c18fbfef36f2c00008001000080000000800000000000000000000000'
        psbt_obj = PSBT.parse(BytesIO(bytes.fromhex(hex_psbt)))
        psbt_obj.finalize()
        want = '70736274ff0100770100000001192f88eeabc44ac213604adbb5b699678815d24b718b5940f5b1b1853f0887480100000000ffffffff0220a10700000000001976a91426d5d464d148454c76f7095fdf03afc8bc8d82c388ac2c9f0700000000001976a9144df14c8c8873451290c53e95ebd1ee8fe488f0ed88ac00000000000100fda40102000000000102816f71fa2b62d7235ae316d54cb174053c793d16644064405a8326094518aaa901000000171600148900fe9d1950305978d57ebbc25f722bbf131b53feffffff6e3e62f2e005db1bb2a1f12e5ca2bfbb4f82f2ca023c23b0a10a035cabb38fb60000000017160014ae01dce99edb5398cee5e4dc536173d35a9495a9feffffff0278de16000000000017a914a2be7a5646958a5b53f1c3de5a896f6c0ff5419f8740420f00000000001976a9149a9bfaf8ef6c4b061a30e8e162da3458cfa122c688ac02473044022017506b1a15e0540efe5453fcc9c61dcc4457dd00d22cba5e5b937c56944f96ff02207a1c071a8e890cf69c4adef5154d6556e5b356fc09d74a7c811484de289c2d41012102de6c105c8ed6c54d9f7a166fbe3012fecbf4bb3cecda49a8aad1d0c07784110c0247304402207035217de1a2c587b1aaeb5605b043189d551451697acb74ffc99e5a288f4fde022013b7f33a916f9e05846d333b6ea314f56251e74f243682e0ec45ce9e16c6344d01210205174b405fba1b53a44faf08679d63c871cece6c3b2c343bd2d7c559aa32dfb1a227180001076b483045022100b98bb5a69a081543e7e6de6b62b3243c8870211c679a8cf568916631494e99d50220631e1f70231286f059f5cdef8d746f7b8986cfec47346bdfea163528250d7d24012102c1b6ac6e6a625fee295dc2d580f80aae08b7e76eca54ae88a854e956095af77c000000'
        self.assertEqual(psbt_obj.serialize().hex(), want)

    def test_final_tx(self):
        hex_psbt = '70736274ff0100770100000001192f88eeabc44ac213604adbb5b699678815d24b718b5940f5b1b1853f0887480100000000ffffffff0220a10700000000001976a91426d5d464d148454c76f7095fdf03afc8bc8d82c388ac2c9f0700000000001976a9144df14c8c8873451290c53e95ebd1ee8fe488f0ed88ac00000000000100fda40102000000000102816f71fa2b62d7235ae316d54cb174053c793d16644064405a8326094518aaa901000000171600148900fe9d1950305978d57ebbc25f722bbf131b53feffffff6e3e62f2e005db1bb2a1f12e5ca2bfbb4f82f2ca023c23b0a10a035cabb38fb60000000017160014ae01dce99edb5398cee5e4dc536173d35a9495a9feffffff0278de16000000000017a914a2be7a5646958a5b53f1c3de5a896f6c0ff5419f8740420f00000000001976a9149a9bfaf8ef6c4b061a30e8e162da3458cfa122c688ac02473044022017506b1a15e0540efe5453fcc9c61dcc4457dd00d22cba5e5b937c56944f96ff02207a1c071a8e890cf69c4adef5154d6556e5b356fc09d74a7c811484de289c2d41012102de6c105c8ed6c54d9f7a166fbe3012fecbf4bb3cecda49a8aad1d0c07784110c0247304402207035217de1a2c587b1aaeb5605b043189d551451697acb74ffc99e5a288f4fde022013b7f33a916f9e05846d333b6ea314f56251e74f243682e0ec45ce9e16c6344d01210205174b405fba1b53a44faf08679d63c871cece6c3b2c343bd2d7c559aa32dfb1a227180001076b483045022100b98bb5a69a081543e7e6de6b62b3243c8870211c679a8cf568916631494e99d50220631e1f70231286f059f5cdef8d746f7b8986cfec47346bdfea163528250d7d24012102c1b6ac6e6a625fee295dc2d580f80aae08b7e76eca54ae88a854e956095af77c000000'
        psbt_obj = PSBT.parse(BytesIO(bytes.fromhex(hex_psbt)))
        psbt_obj.tx_obj.testnet = True
        tx_obj = psbt_obj.final_tx()
        want = '0100000001192f88eeabc44ac213604adbb5b699678815d24b718b5940f5b1b1853f088748010000006b483045022100b98bb5a69a081543e7e6de6b62b3243c8870211c679a8cf568916631494e99d50220631e1f70231286f059f5cdef8d746f7b8986cfec47346bdfea163528250d7d24012102c1b6ac6e6a625fee295dc2d580f80aae08b7e76eca54ae88a854e956095af77cffffffff0220a10700000000001976a91426d5d464d148454c76f7095fdf03afc8bc8d82c388ac2c9f0700000000001976a9144df14c8c8873451290c53e95ebd1ee8fe488f0ed88ac00000000'
        self.assertEqual(tx_obj.serialize().hex(), want)

    def test_update_p2sh(self):
        hex_psbt = '70736274ff01007501000000015c59ecb919792ecc26e031e9f4a6d4d74afce7b17dfe039002ef82b1f30bb63e0000000000ffffffff0220a10700000000001976a91426d5d464d148454c76f7095fdf03afc8bc8d82c388ac2c9f07000000000017a91481a19f39772bd741501e851e97ddd6a7f1ec194b870000000000000000'
        hex_redeem_scripts = ['47522102c1b6ac6e6a625fee295dc2d580f80aae08b7e76eca54ae88a854e956095af77c210247aed77c3def4b8ce74a8db08d7f5fd315f8d96b6cd801729a910c3045d750f252ae', '47522102db8b701c3210e1bf6f2a8a9a657acad18be1e8bff3f7435d48f973de8408f29021026421c7673552fdad57193e102df96134be00649195b213fec9d07c6d918f418d52ae']
        psbt_obj = PSBT.parse(BytesIO(bytes.fromhex(hex_psbt)))
        psbt_obj.tx_obj.testnet = True
        tx_lookup = psbt_obj.tx_obj.get_input_tx_lookup()
        key_1 = bytes.fromhex('02043587cf034d513c1580000000fb406c9fec09b6957a3449d2102318717b0c0d230b657d0ebc6698abd52145eb02eaf3397fea02c5dac747888a9e535eaf3c7e7cb9d5f2da77ddbdd943592a14af')
        key_2 = bytes.fromhex('02043587cf0398242fbc80000000959cb81379545d7a34287f41485a3c08fc6ecf66cb89caff8a4f618b484d6e7d0362f19f492715b6041723d97403f166da0e3246eb614d80635c036a8d2f753393')
        stream_1 = BytesIO(encode_varstr(bytes.fromhex('fbfef36f') + serialize_binary_path("m/44'/1'/0'")))
        stream_2 = BytesIO(encode_varstr(bytes.fromhex('797dcdac') + serialize_binary_path("m/44'/1'/0'")))
        hd_1 = NamedHDPublicKey.parse(key_1, stream_1)
        hd_2 = NamedHDPublicKey.parse(key_2, stream_2)
        pubkey_lookup = {**hd_1.bip44_lookup(), **hd_2.bip44_lookup()}
        redeem_lookup = {}
        for hex_redeem_script in hex_redeem_scripts:
            redeem_script = RedeemScript.parse(BytesIO(bytes.fromhex(hex_redeem_script)))
            redeem_lookup[redeem_script.hash160()] = redeem_script
        psbt_obj.update(tx_lookup, pubkey_lookup, redeem_lookup)
        want = '70736274ff01007501000000015c59ecb919792ecc26e031e9f4a6d4d74afce7b17dfe039002ef82b1f30bb63e0000000000ffffffff0220a10700000000001976a91426d5d464d148454c76f7095fdf03afc8bc8d82c388ac2c9f07000000000017a91481a19f39772bd741501e851e97ddd6a7f1ec194b8700000000000100fda201020000000001024b9f6ab9def1aabadd74f37c61361d4c555c08b3518b0f393e0df037a538058b010000001716001446fe25a61b6afad8e8619854ec65eaa5a3d707c2feffffff03df61643d0f37ca92b9e67d94d7acffb58bf167b3a73692ff2ca1933b51123f0100000017160014a77769eca770c1cafbcfa7bb06e44a7fc3748ef5feffffff0240420f000000000017a914c5bea2bad6a3171dff5fad0b99d2e60fca1d8bee87966f1b000000000017a914f10824ee9939fa638b9cc75e516408dc1d9fe248870247304402205c5f2ed7d4ce4da4913ee08b1413a7f0dadd8c59c6fe9c94fe299c8a7456076102203abb3b6f895938bf489a2473591877c7aa2cc7fddb1ca2e9632294b06d80f3a90121025ab592b2533bc8a4e4b3b52794b5f2318850c004b3dc24099271fb7db080ef820247304402204f57bbd3cc35c15bc7de0a8890c656d5608ab41c731c64413c45730fb0b05a5c0220162c676a55b2ff349cbea7d1908f034443419e30caf20a47beb5f209116cb0c3012102fed02d7c44b8bb82f23948e26e005572ff08fec43d6094daf67d2bc691f4d64d9f271800010447522102c1b6ac6e6a625fee295dc2d580f80aae08b7e76eca54ae88a854e956095af77c210247aed77c3def4b8ce74a8db08d7f5fd315f8d96b6cd801729a910c3045d750f252ae22060247aed77c3def4b8ce74a8db08d7f5fd315f8d96b6cd801729a910c3045d750f218797dcdac2c00008001000080000000800000000000000000220602c1b6ac6e6a625fee295dc2d580f80aae08b7e76eca54ae88a854e956095af77c18fbfef36f2c000080010000800000008000000000000000000000010047522102db8b701c3210e1bf6f2a8a9a657acad18be1e8bff3f7435d48f973de8408f29021026421c7673552fdad57193e102df96134be00649195b213fec9d07c6d918f418d52ae2202026421c7673552fdad57193e102df96134be00649195b213fec9d07c6d918f418d18797dcdac2c00008001000080000000800100000000000000220202db8b701c3210e1bf6f2a8a9a657acad18be1e8bff3f7435d48f973de8408f29018fbfef36f2c0000800100008000000080010000000000000000'
        self.assertEqual(psbt_obj.serialize().hex(), want)

    def test_finalize_p2sh(self):
        hex_psbt = '70736274ff0100530100000001e8be6d62ba1983b5d1c65406f87f7d73c2d7200d4075cf52589c53579870542b0000000000ffffffff01583e0f000000000017a91481a19f39772bd741501e851e97ddd6a7f1ec194b87000000004f01043587cf034d513c1580000000fb406c9fec09b6957a3449d2102318717b0c0d230b657d0ebc6698abd52145eb02eaf3397fea02c5dac747888a9e535eaf3c7e7cb9d5f2da77ddbdd943592a14af10fbfef36f2c0000800100008000000080000100fd01010100000000010187a22bb77a836c0a3bbb62e1e04950cffdf6a45489a8d7801b24b18c124d84850100000000ffffffff0340420f000000000017a914c5bea2bad6a3171dff5fad0b99d2e60fca1d8bee8740420f00000000001976a914f0cd79383f13584bdeca184cecd16135b8a79fc288ac10c69b01000000001600146e13971913b9aa89659a9f53d327baa8826f2d750247304402204edcdf923bdddad9b77b17ae0c65817f032b7cb6efd95c0c4101fa48aba17e4e02202158c3a077a0ee0a7bc7e2763a9356470ae3aa4866ae4e62a6f8faa2729b02da0121031dbe3aff7b9ad64e2612b8b15e9f5e4a3130663a526df91abfb7b1bd16de5d6e00000000220202c1b6ac6e6a625fee295dc2d580f80aae08b7e76eca54ae88a854e956095af77c47304402207360ee58276e8135ae1efdf1bbd7b3d87d1c7f072f3141cfe8afa78f3e36cdf7022059462d2e4598e3b441fa2503eb73b6d6b644838d3c9af547f09760b0655ce9380122020247aed77c3def4b8ce74a8db08d7f5fd315f8d96b6cd801729a910c3045d750f2473044022038c818f86a2cb1e092c55f2e30c74904c4ebbf80805ba7235369b626444ff7a402202594d8fa4f855be4dbecc148804056c2938218e7fe1a7b805a0d18f2d47a31e801010447522102c1b6ac6e6a625fee295dc2d580f80aae08b7e76eca54ae88a854e956095af77c210247aed77c3def4b8ce74a8db08d7f5fd315f8d96b6cd801729a910c3045d750f252ae22060247aed77c3def4b8ce74a8db08d7f5fd315f8d96b6cd801729a910c3045d750f218797dcdac2c00008001000080000000800000000000000000220602c1b6ac6e6a625fee295dc2d580f80aae08b7e76eca54ae88a854e956095af77c18fbfef36f2c0000800100008000000080000000000000000000010047522102db8b701c3210e1bf6f2a8a9a657acad18be1e8bff3f7435d48f973de8408f29021026421c7673552fdad57193e102df96134be00649195b213fec9d07c6d918f418d52ae2202026421c7673552fdad57193e102df96134be00649195b213fec9d07c6d918f418d18797dcdac2c00008001000080000000800100000000000000220202db8b701c3210e1bf6f2a8a9a657acad18be1e8bff3f7435d48f973de8408f29018fbfef36f2c0000800100008000000080010000000000000000'
        psbt_obj = PSBT.parse(BytesIO(bytes.fromhex(hex_psbt)))
        psbt_obj.finalize()
        want = '70736274ff0100530100000001e8be6d62ba1983b5d1c65406f87f7d73c2d7200d4075cf52589c53579870542b0000000000ffffffff01583e0f000000000017a91481a19f39772bd741501e851e97ddd6a7f1ec194b87000000004f01043587cf034d513c1580000000fb406c9fec09b6957a3449d2102318717b0c0d230b657d0ebc6698abd52145eb02eaf3397fea02c5dac747888a9e535eaf3c7e7cb9d5f2da77ddbdd943592a14af10fbfef36f2c0000800100008000000080000100fd01010100000000010187a22bb77a836c0a3bbb62e1e04950cffdf6a45489a8d7801b24b18c124d84850100000000ffffffff0340420f000000000017a914c5bea2bad6a3171dff5fad0b99d2e60fca1d8bee8740420f00000000001976a914f0cd79383f13584bdeca184cecd16135b8a79fc288ac10c69b01000000001600146e13971913b9aa89659a9f53d327baa8826f2d750247304402204edcdf923bdddad9b77b17ae0c65817f032b7cb6efd95c0c4101fa48aba17e4e02202158c3a077a0ee0a7bc7e2763a9356470ae3aa4866ae4e62a6f8faa2729b02da0121031dbe3aff7b9ad64e2612b8b15e9f5e4a3130663a526df91abfb7b1bd16de5d6e000000000107d90047304402207360ee58276e8135ae1efdf1bbd7b3d87d1c7f072f3141cfe8afa78f3e36cdf7022059462d2e4598e3b441fa2503eb73b6d6b644838d3c9af547f09760b0655ce93801473044022038c818f86a2cb1e092c55f2e30c74904c4ebbf80805ba7235369b626444ff7a402202594d8fa4f855be4dbecc148804056c2938218e7fe1a7b805a0d18f2d47a31e80147522102c1b6ac6e6a625fee295dc2d580f80aae08b7e76eca54ae88a854e956095af77c210247aed77c3def4b8ce74a8db08d7f5fd315f8d96b6cd801729a910c3045d750f252ae00010047522102db8b701c3210e1bf6f2a8a9a657acad18be1e8bff3f7435d48f973de8408f29021026421c7673552fdad57193e102df96134be00649195b213fec9d07c6d918f418d52ae2202026421c7673552fdad57193e102df96134be00649195b213fec9d07c6d918f418d18797dcdac2c00008001000080000000800100000000000000220202db8b701c3210e1bf6f2a8a9a657acad18be1e8bff3f7435d48f973de8408f29018fbfef36f2c0000800100008000000080010000000000000000'
        self.assertEqual(psbt_obj.serialize().hex(), want)

    def test_update_p2wpkh(self):
        hex_psbt = '70736274ff01005201000000015c89191dc2abf62339e0f114cb4c3bf8fb399d522d112c9afa2dc7a43759f9060000000000ffffffff01583e0f000000000016001427459b7e4317d1c9e1d0f8320d557c6bb08731ef00000000000000'
        psbt_obj = PSBT.parse(BytesIO(bytes.fromhex(hex_psbt)))
        psbt_obj.tx_obj.testnet = True
        tx_lookup = psbt_obj.tx_obj.get_input_tx_lookup()
        key = bytes.fromhex('02043587cf0398242fbc80000000959cb81379545d7a34287f41485a3c08fc6ecf66cb89caff8a4f618b484d6e7d0362f19f492715b6041723d97403f166da0e3246eb614d80635c036a8d2f753393')
        stream = BytesIO(encode_varstr(bytes.fromhex('797dcdac') + serialize_binary_path("m/44'/1'/0'")))
        hd = NamedHDPublicKey.parse(key, stream)
        psbt_obj.update(tx_lookup, hd.bip44_lookup())
        want = '70736274ff01005201000000015c89191dc2abf62339e0f114cb4c3bf8fb399d522d112c9afa2dc7a43759f9060000000000ffffffff01583e0f000000000016001427459b7e4317d1c9e1d0f8320d557c6bb08731ef000000000001011f40420f0000000000160014f0cd79383f13584bdeca184cecd16135b8a79fc222060247aed77c3def4b8ce74a8db08d7f5fd315f8d96b6cd801729a910c3045d750f218797dcdac2c00008001000080000000800000000000000000002202026421c7673552fdad57193e102df96134be00649195b213fec9d07c6d918f418d18797dcdac2c0000800100008000000080010000000000000000'
        self.assertEqual(psbt_obj.serialize().hex(), want)

    def test_sign_p2wpkh(self):
        hex_psbt = '70736274ff01005201000000015c89191dc2abf62339e0f114cb4c3bf8fb399d522d112c9afa2dc7a43759f9060000000000ffffffff01583e0f000000000016001427459b7e4317d1c9e1d0f8320d557c6bb08731ef000000000001011f40420f0000000000160014f0cd79383f13584bdeca184cecd16135b8a79fc222060247aed77c3def4b8ce74a8db08d7f5fd315f8d96b6cd801729a910c3045d750f218797dcdac2c00008001000080000000800000000000000000002202026421c7673552fdad57193e102df96134be00649195b213fec9d07c6d918f418d18797dcdac2c0000800100008000000080010000000000000000'
        psbt_obj = PSBT.parse(BytesIO(bytes.fromhex(hex_psbt)))
        hd_priv = HDPrivateKey.parse('tprv8ZgxMBicQKsPeZ6mVBLfLQ7HTpmX8QWKrxbqAtk5BAiwEa9t5WjLryMZUo8qD6mNwGjx98NyDLqbqGcBKor6khRgnQG4XTbUPpxu8YdFKCF')
        self.assertTrue(psbt_obj.sign(hd_priv))
        want = '70736274ff01005201000000015c89191dc2abf62339e0f114cb4c3bf8fb399d522d112c9afa2dc7a43759f9060000000000ffffffff01583e0f000000000016001427459b7e4317d1c9e1d0f8320d557c6bb08731ef000000000001011f40420f0000000000160014f0cd79383f13584bdeca184cecd16135b8a79fc222020247aed77c3def4b8ce74a8db08d7f5fd315f8d96b6cd801729a910c3045d750f24730440220575870ef714252a26bc4e61a6ee31db0f3896606a4792d11a42ef7d30c9f1b33022007cd28fb8618b704cbcf1cc6292d9be901bf3c99d967b0cace7307532619811e0122060247aed77c3def4b8ce74a8db08d7f5fd315f8d96b6cd801729a910c3045d750f218797dcdac2c00008001000080000000800000000000000000002202026421c7673552fdad57193e102df96134be00649195b213fec9d07c6d918f418d18797dcdac2c0000800100008000000080010000000000000000'
        self.assertEqual(psbt_obj.serialize().hex(), want)

    def test_finalize_p2wpkh(self):
        hex_psbt = '70736274ff01005201000000015c89191dc2abf62339e0f114cb4c3bf8fb399d522d112c9afa2dc7a43759f9060000000000ffffffff01583e0f000000000016001427459b7e4317d1c9e1d0f8320d557c6bb08731ef000000000001011f40420f0000000000160014f0cd79383f13584bdeca184cecd16135b8a79fc222020247aed77c3def4b8ce74a8db08d7f5fd315f8d96b6cd801729a910c3045d750f24730440220575870ef714252a26bc4e61a6ee31db0f3896606a4792d11a42ef7d30c9f1b33022007cd28fb8618b704cbcf1cc6292d9be901bf3c99d967b0cace7307532619811e0122060247aed77c3def4b8ce74a8db08d7f5fd315f8d96b6cd801729a910c3045d750f218797dcdac2c00008001000080000000800000000000000000002202026421c7673552fdad57193e102df96134be00649195b213fec9d07c6d918f418d18797dcdac2c0000800100008000000080010000000000000000'
        psbt_obj = PSBT.parse(BytesIO(bytes.fromhex(hex_psbt)))
        psbt_obj.finalize()
        want = '70736274ff01005201000000015c89191dc2abf62339e0f114cb4c3bf8fb399d522d112c9afa2dc7a43759f9060000000000ffffffff01583e0f000000000016001427459b7e4317d1c9e1d0f8320d557c6bb08731ef000000000001011f40420f0000000000160014f0cd79383f13584bdeca184cecd16135b8a79fc201070001086b024730440220575870ef714252a26bc4e61a6ee31db0f3896606a4792d11a42ef7d30c9f1b33022007cd28fb8618b704cbcf1cc6292d9be901bf3c99d967b0cace7307532619811e01210247aed77c3def4b8ce74a8db08d7f5fd315f8d96b6cd801729a910c3045d750f2002202026421c7673552fdad57193e102df96134be00649195b213fec9d07c6d918f418d18797dcdac2c0000800100008000000080010000000000000000'
        self.assertEqual(psbt_obj.serialize().hex(), want)

    def test_final_tx_p2wpkh(self):
        hex_psbt = '70736274ff01005201000000015c89191dc2abf62339e0f114cb4c3bf8fb399d522d112c9afa2dc7a43759f9060000000000ffffffff01583e0f000000000016001427459b7e4317d1c9e1d0f8320d557c6bb08731ef000000000001011f40420f0000000000160014f0cd79383f13584bdeca184cecd16135b8a79fc201070001086b024730440220575870ef714252a26bc4e61a6ee31db0f3896606a4792d11a42ef7d30c9f1b33022007cd28fb8618b704cbcf1cc6292d9be901bf3c99d967b0cace7307532619811e01210247aed77c3def4b8ce74a8db08d7f5fd315f8d96b6cd801729a910c3045d750f2002202026421c7673552fdad57193e102df96134be00649195b213fec9d07c6d918f418d18797dcdac2c0000800100008000000080010000000000000000'
        psbt_obj = PSBT.parse(BytesIO(bytes.fromhex(hex_psbt)))
        psbt_obj.tx_obj.testnet = True
        tx_obj = psbt_obj.final_tx()
        want = '010000000001015c89191dc2abf62339e0f114cb4c3bf8fb399d522d112c9afa2dc7a43759f9060000000000ffffffff01583e0f000000000016001427459b7e4317d1c9e1d0f8320d557c6bb08731ef024730440220575870ef714252a26bc4e61a6ee31db0f3896606a4792d11a42ef7d30c9f1b33022007cd28fb8618b704cbcf1cc6292d9be901bf3c99d967b0cace7307532619811e01210247aed77c3def4b8ce74a8db08d7f5fd315f8d96b6cd801729a910c3045d750f200000000'
        self.assertEqual(tx_obj.serialize().hex(), want)

    def test_p2sh_p2wpkh(self):
        hex_tx = '01000000015c89191dc2abf62339e0f114cb4c3bf8fb399d522d112c9afa2dc7a43759f9060100000000ffffffff01583e0f00000000001600146e13971913b9aa89659a9f53d327baa8826f2d7500000000'
        tx_obj = Tx.parse(BytesIO(bytes.fromhex(hex_tx)))
        psbt_obj = PSBT.create(tx_obj)
        want = '70736274ff01005201000000015c89191dc2abf62339e0f114cb4c3bf8fb399d522d112c9afa2dc7a43759f9060100000000ffffffff01583e0f00000000001600146e13971913b9aa89659a9f53d327baa8826f2d7500000000000000'
        self.assertEqual(psbt_obj.serialize().hex(), want)
        psbt_obj.tx_obj.testnet = True
        hex_named_hd = '4f01043587cf0398242fbc80000000959cb81379545d7a34287f41485a3c08fc6ecf66cb89caff8a4f618b484d6e7d0362f19f492715b6041723d97403f166da0e3246eb614d80635c036a8d2f75339310797dcdac2c0000800100008000000080'
        stream = BytesIO(bytes.fromhex(hex_named_hd))
        named_hd = NamedHDPublicKey.parse(read_varstr(stream), stream)
        tx_lookup = psbt_obj.tx_obj.get_input_tx_lookup()
        pubkey_lookup = named_hd.bip44_lookup()
        redeem_lookup = named_hd.redeem_script_lookup()
        psbt_obj.update(tx_lookup, pubkey_lookup, redeem_lookup)
        want = '70736274ff01005201000000015c89191dc2abf62339e0f114cb4c3bf8fb399d522d112c9afa2dc7a43759f9060100000000ffffffff01583e0f00000000001600146e13971913b9aa89659a9f53d327baa8826f2d75000000000001012040420f000000000017a914990dd86ae46c3d568535e5e482ac35151836d3cd870104160014f0cd79383f13584bdeca184cecd16135b8a79fc222060247aed77c3def4b8ce74a8db08d7f5fd315f8d96b6cd801729a910c3045d750f218797dcdac2c000080010000800000008000000000000000000000'
        self.assertEqual(psbt_obj.serialize().hex(), want)
        hd_priv = HDPrivateKey.parse('tprv8ZgxMBicQKsPeZ6mVBLfLQ7HTpmX8QWKrxbqAtk5BAiwEa9t5WjLryMZUo8qD6mNwGjx98NyDLqbqGcBKor6khRgnQG4XTbUPpxu8YdFKCF')
        self.assertTrue(psbt_obj.sign(hd_priv))
        want = '70736274ff01005201000000015c89191dc2abf62339e0f114cb4c3bf8fb399d522d112c9afa2dc7a43759f9060100000000ffffffff01583e0f00000000001600146e13971913b9aa89659a9f53d327baa8826f2d75000000000001012040420f000000000017a914990dd86ae46c3d568535e5e482ac35151836d3cd8722020247aed77c3def4b8ce74a8db08d7f5fd315f8d96b6cd801729a910c3045d750f2483045022100f332008498ada0d5c83717c638b6d9f2bc6b79e657ab1db0bd45538e1390905202203060d6ffa36bb49b3469ea806a03644958926d56dda96701e7eaa3ca5320c49f010104160014f0cd79383f13584bdeca184cecd16135b8a79fc222060247aed77c3def4b8ce74a8db08d7f5fd315f8d96b6cd801729a910c3045d750f218797dcdac2c000080010000800000008000000000000000000000'
        self.assertEqual(psbt_obj.serialize().hex(), want)
        psbt_obj.finalize()
        want = '70736274ff01005201000000015c89191dc2abf62339e0f114cb4c3bf8fb399d522d112c9afa2dc7a43759f9060100000000ffffffff01583e0f00000000001600146e13971913b9aa89659a9f53d327baa8826f2d75000000000001012040420f000000000017a914990dd86ae46c3d568535e5e482ac35151836d3cd87010717160014f0cd79383f13584bdeca184cecd16135b8a79fc201086c02483045022100f332008498ada0d5c83717c638b6d9f2bc6b79e657ab1db0bd45538e1390905202203060d6ffa36bb49b3469ea806a03644958926d56dda96701e7eaa3ca5320c49f01210247aed77c3def4b8ce74a8db08d7f5fd315f8d96b6cd801729a910c3045d750f20000'
        self.assertEqual(psbt_obj.serialize().hex(), want)
        tx_obj = psbt_obj.final_tx()
        want = '010000000001015c89191dc2abf62339e0f114cb4c3bf8fb399d522d112c9afa2dc7a43759f9060100000017160014f0cd79383f13584bdeca184cecd16135b8a79fc2ffffffff01583e0f00000000001600146e13971913b9aa89659a9f53d327baa8826f2d7502483045022100f332008498ada0d5c83717c638b6d9f2bc6b79e657ab1db0bd45538e1390905202203060d6ffa36bb49b3469ea806a03644958926d56dda96701e7eaa3ca5320c49f01210247aed77c3def4b8ce74a8db08d7f5fd315f8d96b6cd801729a910c3045d750f200000000'
        self.assertEqual(tx_obj.serialize().hex(), want)

    def test_update_p2wsh(self):
        hex_psbt = '70736274ff01005e01000000015c89191dc2abf62339e0f114cb4c3bf8fb399d522d112c9afa2dc7a43759f9060200000000ffffffff01583e0f0000000000220020878ce58b26789632a24ec6b62542e5d4e844dee56a7ddce7db41618049c3928c000000004f01043587cf034d513c1580000000fb406c9fec09b6957a3449d2102318717b0c0d230b657d0ebc6698abd52145eb02eaf3397fea02c5dac747888a9e535eaf3c7e7cb9d5f2da77ddbdd943592a14af10fbfef36f2c0000800100008000000080000000'
        hex_witness_scripts = ['47522102c1b6ac6e6a625fee295dc2d580f80aae08b7e76eca54ae88a854e956095af77c210247aed77c3def4b8ce74a8db08d7f5fd315f8d96b6cd801729a910c3045d750f252ae', '47522102db8b701c3210e1bf6f2a8a9a657acad18be1e8bff3f7435d48f973de8408f29021026421c7673552fdad57193e102df96134be00649195b213fec9d07c6d918f418d52ae']
        psbt_obj = PSBT.parse(BytesIO(bytes.fromhex(hex_psbt)))
        psbt_obj.tx_obj.testnet = True
        tx_lookup = psbt_obj.tx_obj.get_input_tx_lookup()
        key_1 = bytes.fromhex('02043587cf034d513c1580000000fb406c9fec09b6957a3449d2102318717b0c0d230b657d0ebc6698abd52145eb02eaf3397fea02c5dac747888a9e535eaf3c7e7cb9d5f2da77ddbdd943592a14af')
        key_2 = bytes.fromhex('02043587cf0398242fbc80000000959cb81379545d7a34287f41485a3c08fc6ecf66cb89caff8a4f618b484d6e7d0362f19f492715b6041723d97403f166da0e3246eb614d80635c036a8d2f753393')
        bin_path = serialize_binary_path("m/44'/1'/0'")
        stream_1 = BytesIO(encode_varstr(bytes.fromhex('fbfef36f') + bin_path))
        stream_2 = BytesIO(encode_varstr(bytes.fromhex('797dcdac') + bin_path))
        hd_1 = NamedHDPublicKey.parse(key_1, stream_1)
        hd_2 = NamedHDPublicKey.parse(key_2, stream_2)
        pubkey_lookup = {**hd_1.bip44_lookup(), **hd_2.bip44_lookup()}
        witness_lookup = {}
        for hex_witness_script in hex_witness_scripts:
            witness_script = WitnessScript.parse(BytesIO(bytes.fromhex(hex_witness_script)))
            witness_lookup[witness_script.sha256()] = witness_script
        psbt_obj.update(tx_lookup, pubkey_lookup, witness_lookup=witness_lookup)
        want = '70736274ff01005e01000000015c89191dc2abf62339e0f114cb4c3bf8fb399d522d112c9afa2dc7a43759f9060200000000ffffffff01583e0f0000000000220020878ce58b26789632a24ec6b62542e5d4e844dee56a7ddce7db41618049c3928c000000004f01043587cf034d513c1580000000fb406c9fec09b6957a3449d2102318717b0c0d230b657d0ebc6698abd52145eb02eaf3397fea02c5dac747888a9e535eaf3c7e7cb9d5f2da77ddbdd943592a14af10fbfef36f2c00008001000080000000800001012b40420f0000000000220020c1b4fff485af1ac26714340af2e13d2e89ad70389332a0756d91a123c7fe7f5d010547522102c1b6ac6e6a625fee295dc2d580f80aae08b7e76eca54ae88a854e956095af77c210247aed77c3def4b8ce74a8db08d7f5fd315f8d96b6cd801729a910c3045d750f252ae22060247aed77c3def4b8ce74a8db08d7f5fd315f8d96b6cd801729a910c3045d750f218797dcdac2c00008001000080000000800000000000000000220602c1b6ac6e6a625fee295dc2d580f80aae08b7e76eca54ae88a854e956095af77c18fbfef36f2c0000800100008000000080000000000000000000010147522102db8b701c3210e1bf6f2a8a9a657acad18be1e8bff3f7435d48f973de8408f29021026421c7673552fdad57193e102df96134be00649195b213fec9d07c6d918f418d52ae2202026421c7673552fdad57193e102df96134be00649195b213fec9d07c6d918f418d18797dcdac2c00008001000080000000800100000000000000220202db8b701c3210e1bf6f2a8a9a657acad18be1e8bff3f7435d48f973de8408f29018fbfef36f2c0000800100008000000080010000000000000000'
        self.assertEqual(psbt_obj.serialize().hex(), want)

    def test_finalize_p2wsh(self):
        hex_psbt = '70736274ff01005e01000000015c89191dc2abf62339e0f114cb4c3bf8fb399d522d112c9afa2dc7a43759f9060200000000ffffffff01583e0f0000000000220020878ce58b26789632a24ec6b62542e5d4e844dee56a7ddce7db41618049c3928c000000004f01043587cf034d513c1580000000fb406c9fec09b6957a3449d2102318717b0c0d230b657d0ebc6698abd52145eb02eaf3397fea02c5dac747888a9e535eaf3c7e7cb9d5f2da77ddbdd943592a14af10fbfef36f2c00008001000080000000800001012b40420f0000000000220020c1b4fff485af1ac26714340af2e13d2e89ad70389332a0756d91a123c7fe7f5d220202c1b6ac6e6a625fee295dc2d580f80aae08b7e76eca54ae88a854e956095af77c47304402203f26a975aae04a7ae12c964cdcea318c850351a3072aebbab7902e89957008ea022019f895271f70d1515f9da776d6ac17c21bcbca769d87c1beb4ebbf4c7a56fbc20122020247aed77c3def4b8ce74a8db08d7f5fd315f8d96b6cd801729a910c3045d750f247304402204fd654c27002d4c9e53bb001229e3d7587e5be245a81b6f7ead3bf136643af40022060ebf1193a6b3e82615a564f0043e5ae88e661bfdb7fd254c9a30bae8160583901010547522102c1b6ac6e6a625fee295dc2d580f80aae08b7e76eca54ae88a854e956095af77c210247aed77c3def4b8ce74a8db08d7f5fd315f8d96b6cd801729a910c3045d750f252ae22060247aed77c3def4b8ce74a8db08d7f5fd315f8d96b6cd801729a910c3045d750f218797dcdac2c00008001000080000000800000000000000000220602c1b6ac6e6a625fee295dc2d580f80aae08b7e76eca54ae88a854e956095af77c18fbfef36f2c0000800100008000000080000000000000000000010147522102db8b701c3210e1bf6f2a8a9a657acad18be1e8bff3f7435d48f973de8408f29021026421c7673552fdad57193e102df96134be00649195b213fec9d07c6d918f418d52ae2202026421c7673552fdad57193e102df96134be00649195b213fec9d07c6d918f418d18797dcdac2c00008001000080000000800100000000000000220202db8b701c3210e1bf6f2a8a9a657acad18be1e8bff3f7435d48f973de8408f29018fbfef36f2c0000800100008000000080010000000000000000'
        psbt_obj = PSBT.parse(BytesIO(bytes.fromhex(hex_psbt)))
        psbt_obj.finalize()
        want = '70736274ff01005e01000000015c89191dc2abf62339e0f114cb4c3bf8fb399d522d112c9afa2dc7a43759f9060200000000ffffffff01583e0f0000000000220020878ce58b26789632a24ec6b62542e5d4e844dee56a7ddce7db41618049c3928c000000004f01043587cf034d513c1580000000fb406c9fec09b6957a3449d2102318717b0c0d230b657d0ebc6698abd52145eb02eaf3397fea02c5dac747888a9e535eaf3c7e7cb9d5f2da77ddbdd943592a14af10fbfef36f2c00008001000080000000800001012b40420f0000000000220020c1b4fff485af1ac26714340af2e13d2e89ad70389332a0756d91a123c7fe7f5d0107000108da040047304402203f26a975aae04a7ae12c964cdcea318c850351a3072aebbab7902e89957008ea022019f895271f70d1515f9da776d6ac17c21bcbca769d87c1beb4ebbf4c7a56fbc20147304402204fd654c27002d4c9e53bb001229e3d7587e5be245a81b6f7ead3bf136643af40022060ebf1193a6b3e82615a564f0043e5ae88e661bfdb7fd254c9a30bae816058390147522102c1b6ac6e6a625fee295dc2d580f80aae08b7e76eca54ae88a854e956095af77c210247aed77c3def4b8ce74a8db08d7f5fd315f8d96b6cd801729a910c3045d750f252ae00010147522102db8b701c3210e1bf6f2a8a9a657acad18be1e8bff3f7435d48f973de8408f29021026421c7673552fdad57193e102df96134be00649195b213fec9d07c6d918f418d52ae2202026421c7673552fdad57193e102df96134be00649195b213fec9d07c6d918f418d18797dcdac2c00008001000080000000800100000000000000220202db8b701c3210e1bf6f2a8a9a657acad18be1e8bff3f7435d48f973de8408f29018fbfef36f2c0000800100008000000080010000000000000000'
        self.assertEqual(psbt_obj.serialize().hex(), want)

    def test_p2sh_p2wsh(self):
        hex_tx = '01000000015c89191dc2abf62339e0f114cb4c3bf8fb399d522d112c9afa2dc7a43759f9060300000000ffffffff01583e0f00000000001600146e13971913b9aa89659a9f53d327baa8826f2d7500000000'
        tx_obj = Tx.parse(BytesIO(bytes.fromhex(hex_tx)))
        psbt_obj = PSBT.create(tx_obj)
        want = '70736274ff01005201000000015c89191dc2abf62339e0f114cb4c3bf8fb399d522d112c9afa2dc7a43759f9060300000000ffffffff01583e0f00000000001600146e13971913b9aa89659a9f53d327baa8826f2d7500000000000000'
        self.assertEqual(psbt_obj.serialize().hex(), want)
        psbt_obj.tx_obj.testnet = True
        hex_witness_scripts = ['69532102c1b6ac6e6a625fee295dc2d580f80aae08b7e76eca54ae88a854e956095af77c21031b31547c895b5e301206740ea9890a0d6d127baeebb7fffb07356527323c915b210247aed77c3def4b8ce74a8db08d7f5fd315f8d96b6cd801729a910c3045d750f253ae']
        hex_named_hd = '4f01043587cf0398242fbc80000000959cb81379545d7a34287f41485a3c08fc6ecf66cb89caff8a4f618b484d6e7d0362f19f492715b6041723d97403f166da0e3246eb614d80635c036a8d2f75339310797dcdac2c0000800100008000000080'
        stream = BytesIO(bytes.fromhex(hex_named_hd))
        named_hd = NamedHDPublicKey.parse(read_varstr(stream), stream)
        tx_lookup = psbt_obj.tx_obj.get_input_tx_lookup()
        pubkey_lookup = named_hd.bip44_lookup()
        redeem_lookup = {}
        witness_lookup = {}
        for hex_witness_script in hex_witness_scripts:
            witness_script = WitnessScript.parse(BytesIO(bytes.fromhex(hex_witness_script)))
            witness_lookup[witness_script.sha256()] = witness_script
            redeem_script = RedeemScript([0, witness_script.sha256()])
            redeem_lookup[redeem_script.hash160()] = redeem_script
        psbt_obj.update(tx_lookup, pubkey_lookup, redeem_lookup, witness_lookup)
        want = '70736274ff01005201000000015c89191dc2abf62339e0f114cb4c3bf8fb399d522d112c9afa2dc7a43759f9060300000000ffffffff01583e0f00000000001600146e13971913b9aa89659a9f53d327baa8826f2d75000000000001012040420f000000000017a91423358e259fbcf478331138ceb9619d9a8c8350738701042200207fcc2ca7381db4bdfd02e1f2b5eb3d72435b8e09bdbd8bfe3d748bf19d78ef38010569532102c1b6ac6e6a625fee295dc2d580f80aae08b7e76eca54ae88a854e956095af77c21031b31547c895b5e301206740ea9890a0d6d127baeebb7fffb07356527323c915b210247aed77c3def4b8ce74a8db08d7f5fd315f8d96b6cd801729a910c3045d750f253ae22060247aed77c3def4b8ce74a8db08d7f5fd315f8d96b6cd801729a910c3045d750f218797dcdac2c000080010000800000008000000000000000000000'
        self.assertEqual(psbt_obj.serialize().hex(), want)
        hd_priv = HDPrivateKey.parse('tprv8ZgxMBicQKsPeZ6mVBLfLQ7HTpmX8QWKrxbqAtk5BAiwEa9t5WjLryMZUo8qD6mNwGjx98NyDLqbqGcBKor6khRgnQG4XTbUPpxu8YdFKCF')
        self.assertTrue(psbt_obj.sign(hd_priv))
        want = '70736274ff01005201000000015c89191dc2abf62339e0f114cb4c3bf8fb399d522d112c9afa2dc7a43759f9060300000000ffffffff01583e0f00000000001600146e13971913b9aa89659a9f53d327baa8826f2d75000000000001012040420f000000000017a91423358e259fbcf478331138ceb9619d9a8c8350738722020247aed77c3def4b8ce74a8db08d7f5fd315f8d96b6cd801729a910c3045d750f24830450221009b79ecffc98bf334ed4e2a1dddb6e18ce1aa54cb3c19d2d4b41b9ee3f87ae1b3022013f67f2e7caeb8a13463a954e054b04ddd7fbef94b77c4cd1fe32658ed5909590101042200207fcc2ca7381db4bdfd02e1f2b5eb3d72435b8e09bdbd8bfe3d748bf19d78ef38010569532102c1b6ac6e6a625fee295dc2d580f80aae08b7e76eca54ae88a854e956095af77c21031b31547c895b5e301206740ea9890a0d6d127baeebb7fffb07356527323c915b210247aed77c3def4b8ce74a8db08d7f5fd315f8d96b6cd801729a910c3045d750f253ae22060247aed77c3def4b8ce74a8db08d7f5fd315f8d96b6cd801729a910c3045d750f218797dcdac2c000080010000800000008000000000000000000000'
        self.assertEqual(psbt_obj.serialize().hex(), want)
        hex_named_hd = '4f01043587cf034d513c1580000000fb406c9fec09b6957a3449d2102318717b0c0d230b657d0ebc6698abd52145eb02eaf3397fea02c5dac747888a9e535eaf3c7e7cb9d5f2da77ddbdd943592a14af10fbfef36f2c0000800100008000000080'
        stream = BytesIO(bytes.fromhex(hex_named_hd))
        named_hd = NamedHDPublicKey.parse(read_varstr(stream), stream)
        psbt_obj.update({}, named_hd.bip44_lookup())
        want = '70736274ff01005201000000015c89191dc2abf62339e0f114cb4c3bf8fb399d522d112c9afa2dc7a43759f9060300000000ffffffff01583e0f00000000001600146e13971913b9aa89659a9f53d327baa8826f2d75000000000001012040420f000000000017a91423358e259fbcf478331138ceb9619d9a8c8350738722020247aed77c3def4b8ce74a8db08d7f5fd315f8d96b6cd801729a910c3045d750f24830450221009b79ecffc98bf334ed4e2a1dddb6e18ce1aa54cb3c19d2d4b41b9ee3f87ae1b3022013f67f2e7caeb8a13463a954e054b04ddd7fbef94b77c4cd1fe32658ed5909590101042200207fcc2ca7381db4bdfd02e1f2b5eb3d72435b8e09bdbd8bfe3d748bf19d78ef38010569532102c1b6ac6e6a625fee295dc2d580f80aae08b7e76eca54ae88a854e956095af77c21031b31547c895b5e301206740ea9890a0d6d127baeebb7fffb07356527323c915b210247aed77c3def4b8ce74a8db08d7f5fd315f8d96b6cd801729a910c3045d750f253ae22060247aed77c3def4b8ce74a8db08d7f5fd315f8d96b6cd801729a910c3045d750f218797dcdac2c00008001000080000000800000000000000000220602c1b6ac6e6a625fee295dc2d580f80aae08b7e76eca54ae88a854e956095af77c18fbfef36f2c000080010000800000008000000000000000002206031b31547c895b5e301206740ea9890a0d6d127baeebb7fffb07356527323c915b18fbfef36f2c000080010000800000008000000000010000000000'
        self.assertEqual(psbt_obj.serialize().hex(), want)
        private_keys = [
            PrivateKey.parse('cP88EsR4DgJNeswxecL4sE4Eornf3q1ZoRxoCnk8y9eEkQyxu3D7'),
            PrivateKey.parse('cP9BYGBfMbhsN5Lvyza3otuC14oKjqHbgbRXhm7QCF47EgYWQb6S'),
        ]
        self.assertTrue(psbt_obj.sign_with_private_keys(private_keys))
        want = '70736274ff01005201000000015c89191dc2abf62339e0f114cb4c3bf8fb399d522d112c9afa2dc7a43759f9060300000000ffffffff01583e0f00000000001600146e13971913b9aa89659a9f53d327baa8826f2d75000000000001012040420f000000000017a91423358e259fbcf478331138ceb9619d9a8c83507387220202c1b6ac6e6a625fee295dc2d580f80aae08b7e76eca54ae88a854e956095af77c47304402206c79809b2534d3c3ebb9f57958c3e1e24c523c33a47bea9d64e3201622dd194d02206042cc6138b85b865493d5d8cce419d5536112060c9fa73d36244bf2df555600012202031b31547c895b5e301206740ea9890a0d6d127baeebb7fffb07356527323c915b473044022077adf39dc6639cfa63bee2a05c07facf682009f87af6382c84b00f18b15ae4d602207588712aaf8c9f381273fe7985af86955ac3a090c4a87a37995eb6a7cb8023c90122020247aed77c3def4b8ce74a8db08d7f5fd315f8d96b6cd801729a910c3045d750f24830450221009b79ecffc98bf334ed4e2a1dddb6e18ce1aa54cb3c19d2d4b41b9ee3f87ae1b3022013f67f2e7caeb8a13463a954e054b04ddd7fbef94b77c4cd1fe32658ed5909590101042200207fcc2ca7381db4bdfd02e1f2b5eb3d72435b8e09bdbd8bfe3d748bf19d78ef38010569532102c1b6ac6e6a625fee295dc2d580f80aae08b7e76eca54ae88a854e956095af77c21031b31547c895b5e301206740ea9890a0d6d127baeebb7fffb07356527323c915b210247aed77c3def4b8ce74a8db08d7f5fd315f8d96b6cd801729a910c3045d750f253ae22060247aed77c3def4b8ce74a8db08d7f5fd315f8d96b6cd801729a910c3045d750f218797dcdac2c00008001000080000000800000000000000000220602c1b6ac6e6a625fee295dc2d580f80aae08b7e76eca54ae88a854e956095af77c18fbfef36f2c000080010000800000008000000000000000002206031b31547c895b5e301206740ea9890a0d6d127baeebb7fffb07356527323c915b18fbfef36f2c000080010000800000008000000000010000000000'
        self.assertEqual(psbt_obj.serialize().hex(), want)
        psbt_obj.finalize()
        want = '70736274ff01005201000000015c89191dc2abf62339e0f114cb4c3bf8fb399d522d112c9afa2dc7a43759f9060300000000ffffffff01583e0f00000000001600146e13971913b9aa89659a9f53d327baa8826f2d75000000000001012040420f000000000017a91423358e259fbcf478331138ceb9619d9a8c835073870107232200207fcc2ca7381db4bdfd02e1f2b5eb3d72435b8e09bdbd8bfe3d748bf19d78ef380108fd4501050047304402206c79809b2534d3c3ebb9f57958c3e1e24c523c33a47bea9d64e3201622dd194d02206042cc6138b85b865493d5d8cce419d5536112060c9fa73d36244bf2df55560001473044022077adf39dc6639cfa63bee2a05c07facf682009f87af6382c84b00f18b15ae4d602207588712aaf8c9f381273fe7985af86955ac3a090c4a87a37995eb6a7cb8023c9014830450221009b79ecffc98bf334ed4e2a1dddb6e18ce1aa54cb3c19d2d4b41b9ee3f87ae1b3022013f67f2e7caeb8a13463a954e054b04ddd7fbef94b77c4cd1fe32658ed5909590169532102c1b6ac6e6a625fee295dc2d580f80aae08b7e76eca54ae88a854e956095af77c21031b31547c895b5e301206740ea9890a0d6d127baeebb7fffb07356527323c915b210247aed77c3def4b8ce74a8db08d7f5fd315f8d96b6cd801729a910c3045d750f253ae0000'
        self.assertEqual(psbt_obj.serialize().hex(), want)
        tx_obj = psbt_obj.final_tx()
        want = '010000000001015c89191dc2abf62339e0f114cb4c3bf8fb399d522d112c9afa2dc7a43759f90603000000232200207fcc2ca7381db4bdfd02e1f2b5eb3d72435b8e09bdbd8bfe3d748bf19d78ef38ffffffff01583e0f00000000001600146e13971913b9aa89659a9f53d327baa8826f2d75050047304402206c79809b2534d3c3ebb9f57958c3e1e24c523c33a47bea9d64e3201622dd194d02206042cc6138b85b865493d5d8cce419d5536112060c9fa73d36244bf2df55560001473044022077adf39dc6639cfa63bee2a05c07facf682009f87af6382c84b00f18b15ae4d602207588712aaf8c9f381273fe7985af86955ac3a090c4a87a37995eb6a7cb8023c9014830450221009b79ecffc98bf334ed4e2a1dddb6e18ce1aa54cb3c19d2d4b41b9ee3f87ae1b3022013f67f2e7caeb8a13463a954e054b04ddd7fbef94b77c4cd1fe32658ed5909590169532102c1b6ac6e6a625fee295dc2d580f80aae08b7e76eca54ae88a854e956095af77c21031b31547c895b5e301206740ea9890a0d6d127baeebb7fffb07356527323c915b210247aed77c3def4b8ce74a8db08d7f5fd315f8d96b6cd801729a910c3045d750f253ae00000000'
        self.assertEqual(tx_obj.serialize().hex(), want)

    def test_errors(self):
        tests = [
            ['AgAAAAEmgXE3Ht/yhek3re6ks3t4AAwFZsuzrWRkFxPKQhcb9gAAAABqRzBEAiBwsiRRI+a/R01gxbUMBD1MaRpdJDXwmjSnZiqdwlF5CgIgATKcqdrPKAvfMHQOwDkEIkIsgctFg5RXrrdvwS7dlbMBIQJlfRGNM1e44PTCzUbbezn22cONmnCry5st5dyNv+TOMf7///8C09/1BQAAAAAZdqkU0MWZA8W6woaHYOkP1SGkZlqnZSCIrADh9QUAAAAAF6kUNUXm4zuDLEcFDyTT7rk8nAOUi8eHsy4TAA==', SyntaxError],
            ['cHNidP8BAHUCAAAAASaBcTce3/KF6Tet7qSze3gADAVmy7OtZGQXE8pCFxv2AAAAAAD+////AtPf9QUAAAAAGXapFNDFmQPFusKGh2DpD9UhpGZap2UgiKwA4fUFAAAAABepFDVF5uM7gyxHBQ8k0+65PJwDlIvHh7MuEwAAAQD9pQEBAAAAAAECiaPHHqtNIOA3G7ukzGmPopXJRjr6Ljl/hTPMti+VZ+UBAAAAFxYAFL4Y0VKpsBIDna89p95PUzSe7LmF/////4b4qkOnHf8USIk6UwpyN+9rRgi7st0tAXHmOuxqSJC0AQAAABcWABT+Pp7xp0XpdNkCxDVZQ6vLNL1TU/////8CAMLrCwAAAAAZdqkUhc/xCX/Z4Ai7NK9wnGIZeziXikiIrHL++E4sAAAAF6kUM5cluiHv1irHU6m80GfWx6ajnQWHAkcwRAIgJxK+IuAnDzlPVoMR3HyppolwuAJf3TskAinwf4pfOiQCIAGLONfc0xTnNMkna9b7QPZzMlvEuqFEyADS8vAtsnZcASED0uFWdJQbrUqZY3LLh+GFbTZSYG2YVi/jnF6efkE/IQUCSDBFAiEA0SuFLYXc2WHS9fSrZgZU327tzHlMDDPOXMMJ/7X85Y0CIGczio4OFyXBl/saiK9Z9R5E5CVbIBZ8hoQDHAXR8lkqASECI7cr7vCWXRC+B3jv7NYfysb3mk6haTkzgHNEZPhPKrMAAAAAAA==', IOError],
            ['cHNidP8BAP0KAQIAAAACqwlJoIxa98SbghL0F+LxWrP1wz3PFTghqBOfh3pbe+QAAAAAakcwRAIgR1lmF5fAGwNrJZKJSGhiGDR9iYZLcZ4ff89X0eURZYcCIFMJ6r9Wqk2Ikf/REf3xM286KdqGbX+EhtdVRs7tr5MZASEDXNxh/HupccC1AaZGoqg7ECy0OIEhfKaC3Ibi1z+ogpL+////qwlJoIxa98SbghL0F+LxWrP1wz3PFTghqBOfh3pbe+QBAAAAAP7///8CYDvqCwAAAAAZdqkUdopAu9dAy+gdmI5x3ipNXHE5ax2IrI4kAAAAAAAAGXapFG9GILVT+glechue4O/p+gOcykWXiKwAAAAAAAABASAA4fUFAAAAABepFDVF5uM7gyxHBQ8k0+65PJwDlIvHhwEEFgAUhdE1N/LiZUBaNNuvqePdoB+4IwgAAAA=', ValueError],
            ['cHNidP8AAQD9pQEBAAAAAAECiaPHHqtNIOA3G7ukzGmPopXJRjr6Ljl/hTPMti+VZ+UBAAAAFxYAFL4Y0VKpsBIDna89p95PUzSe7LmF/////4b4qkOnHf8USIk6UwpyN+9rRgi7st0tAXHmOuxqSJC0AQAAABcWABT+Pp7xp0XpdNkCxDVZQ6vLNL1TU/////8CAMLrCwAAAAAZdqkUhc/xCX/Z4Ai7NK9wnGIZeziXikiIrHL++E4sAAAAF6kUM5cluiHv1irHU6m80GfWx6ajnQWHAkcwRAIgJxK+IuAnDzlPVoMR3HyppolwuAJf3TskAinwf4pfOiQCIAGLONfc0xTnNMkna9b7QPZzMlvEuqFEyADS8vAtsnZcASED0uFWdJQbrUqZY3LLh+GFbTZSYG2YVi/jnF6efkE/IQUCSDBFAiEA0SuFLYXc2WHS9fSrZgZU327tzHlMDDPOXMMJ/7X85Y0CIGczio4OFyXBl/saiK9Z9R5E5CVbIBZ8hoQDHAXR8lkqASECI7cr7vCWXRC+B3jv7NYfysb3mk6haTkzgHNEZPhPKrMAAAAAAA==', SyntaxError],
            ['cHNidP8BAHUCAAAAASaBcTce3/KF6Tet7qSze3gADAVmy7OtZGQXE8pCFxv2AAAAAAD+////AtPf9QUAAAAAGXapFNDFmQPFusKGh2DpD9UhpGZap2UgiKwA4fUFAAAAABepFDVF5uM7gyxHBQ8k0+65PJwDlIvHh7MuEwAAAQD9pQEBAAAAAAECiaPHHqtNIOA3G7ukzGmPopXJRjr6Ljl/hTPMti+VZ+UBAAAAFxYAFL4Y0VKpsBIDna89p95PUzSe7LmF/////4b4qkOnHf8USIk6UwpyN+9rRgi7st0tAXHmOuxqSJC0AQAAABcWABT+Pp7xp0XpdNkCxDVZQ6vLNL1TU/////8CAMLrCwAAAAAZdqkUhc/xCX/Z4Ai7NK9wnGIZeziXikiIrHL++E4sAAAAF6kUM5cluiHv1irHU6m80GfWx6ajnQWHAkcwRAIgJxK+IuAnDzlPVoMR3HyppolwuAJf3TskAinwf4pfOiQCIAGLONfc0xTnNMkna9b7QPZzMlvEuqFEyADS8vAtsnZcASED0uFWdJQbrUqZY3LLh+GFbTZSYG2YVi/jnF6efkE/IQUCSDBFAiEA0SuFLYXc2WHS9fSrZgZU327tzHlMDDPOXMMJ/7X85Y0CIGczio4OFyXBl/saiK9Z9R5E5CVbIBZ8hoQDHAXR8lkqASECI7cr7vCWXRC+B3jv7NYfysb3mk6haTkzgHNEZPhPKrMAAAAAAQA/AgAAAAH//////////////////////////////////////////wAAAAAA/////wEAAAAAAAAAAANqAQAAAAAAAAAA', KeyError],
            ['cHNidP8CAAFVAgAAAAEnmiMjpd+1H8RfIg+liw/BPh4zQnkqhdfjbNYzO1y8OQAAAAAA/////wGgWuoLAAAAABl2qRT/6cAGEJfMO2NvLLBGD6T8Qn0rRYisAAAAAAABASCVXuoLAAAAABepFGNFIA9o0YnhrcDfHE0W6o8UwNvrhyICA7E0HMunaDtq9PEjjNbpfnFn1Wn6xH8eSNR1QYRDVb1GRjBDAiAEJLWO/6qmlOFVnqXJO7/UqJBkIkBVzfBwtncUaUQtBwIfXI6w/qZRbWC4rLM61k7eYOh4W/s6qUuZvfhhUduamgEBBCIAIHcf0YrUWWZt1J89Vk49vEL0yEd042CtoWgWqO1IjVaBAQVHUiEDsTQcy6doO2r08SOM1ul+cWfVafrEfx5I1HVBhENVvUYhA95V0eHayAXj+KWMH7+blMAvPbqv4Sf+/KSZXyb4IIO9Uq4iBgOxNBzLp2g7avTxI4zW6X5xZ9Vp+sR/HkjUdUGEQ1W9RhC0prpnAAAAgAAAAIAEAACAIgYD3lXR4drIBeP4pYwfv5uUwC89uq/hJ/78pJlfJvggg70QtKa6ZwAAAIAAAACABQAAgAAA', KeyError],
            ['cHNidP8BAFUCAAAAASeaIyOl37UfxF8iD6WLD8E+HjNCeSqF1+Ns1jM7XLw5AAAAAAD/////AaBa6gsAAAAAGXapFP/pwAYQl8w7Y28ssEYPpPxCfStFiKwAAAAAAAIBACCVXuoLAAAAABepFGNFIA9o0YnhrcDfHE0W6o8UwNvrhyICA7E0HMunaDtq9PEjjNbpfnFn1Wn6xH8eSNR1QYRDVb1GRjBDAiAEJLWO/6qmlOFVnqXJO7/UqJBkIkBVzfBwtncUaUQtBwIfXI6w/qZRbWC4rLM61k7eYOh4W/s6qUuZvfhhUduamgEBBCIAIHcf0YrUWWZt1J89Vk49vEL0yEd042CtoWgWqO1IjVaBAQVHUiEDsTQcy6doO2r08SOM1ul+cWfVafrEfx5I1HVBhENVvUYhA95V0eHayAXj+KWMH7+blMAvPbqv4Sf+/KSZXyb4IIO9Uq4iBgOxNBzLp2g7avTxI4zW6X5xZ9Vp+sR/HkjUdUGEQ1W9RhC0prpnAAAAgAAAAIAEAACAIgYD3lXR4drIBeP4pYwfv5uUwC89uq/hJ/78pJlfJvggg70QtKa6ZwAAAIAAAACABQAAgAAA', KeyError],
            ['cHNidP8BAFUCAAAAASeaIyOl37UfxF8iD6WLD8E+HjNCeSqF1+Ns1jM7XLw5AAAAAAD/////AaBa6gsAAAAAGXapFP/pwAYQl8w7Y28ssEYPpPxCfStFiKwAAAAAAAEBIJVe6gsAAAAAF6kUY0UgD2jRieGtwN8cTRbqjxTA2+uHIQIDsTQcy6doO2r08SOM1ul+cWfVafrEfx5I1HVBhENVvUYwQwIgBCS1jv+qppThVZ6lyTu/1KiQZCJAVc3wcLZ3FGlELQcCH1yOsP6mUW1guKyzOtZO3mDoeFv7OqlLmb34YVHbmpoBAQQiACB3H9GK1FlmbdSfPVZOPbxC9MhHdONgraFoFqjtSI1WgQEFR1IhA7E0HMunaDtq9PEjjNbpfnFn1Wn6xH8eSNR1QYRDVb1GIQPeVdHh2sgF4/iljB+/m5TALz26r+En/vykmV8m+CCDvVKuIgYDsTQcy6doO2r08SOM1ul+cWfVafrEfx5I1HVBhENVvUYQtKa6ZwAAAIAAAACABAAAgCIGA95V0eHayAXj+KWMH7+blMAvPbqv4Sf+/KSZXyb4IIO9ELSmumcAAACAAAAAgAUAAIAAAA==', ValueError],
            ['cHNidP8BAFUCAAAAASeaIyOl37UfxF8iD6WLD8E+HjNCeSqF1+Ns1jM7XLw5AAAAAAD/////AaBa6gsAAAAAGXapFP/pwAYQl8w7Y28ssEYPpPxCfStFiKwAAAAAAAEBIJVe6gsAAAAAF6kUY0UgD2jRieGtwN8cTRbqjxTA2+uHIgIDsTQcy6doO2r08SOM1ul+cWfVafrEfx5I1HVBhENVvUZGMEMCIAQktY7/qqaU4VWepck7v9SokGQiQFXN8HC2dxRpRC0HAh9cjrD+plFtYLisszrWTt5g6Hhb+zqpS5m9+GFR25qaAQIEACIAIHcf0YrUWWZt1J89Vk49vEL0yEd042CtoWgWqO1IjVaBAQVHUiEDsTQcy6doO2r08SOM1ul+cWfVafrEfx5I1HVBhENVvUYhA95V0eHayAXj+KWMH7+blMAvPbqv4Sf+/KSZXyb4IIO9Uq4iBgOxNBzLp2g7avTxI4zW6X5xZ9Vp+sR/HkjUdUGEQ1W9RhC0prpnAAAAgAAAAIAEAACAIgYD3lXR4drIBeP4pYwfv5uUwC89uq/hJ/78pJlfJvggg70QtKa6ZwAAAIAAAACABQAAgAAA', KeyError],
            ['cHNidP8BAFUCAAAAASeaIyOl37UfxF8iD6WLD8E+HjNCeSqF1+Ns1jM7XLw5AAAAAAD/////AaBa6gsAAAAAGXapFP/pwAYQl8w7Y28ssEYPpPxCfStFiKwAAAAAAAEBIJVe6gsAAAAAF6kUY0UgD2jRieGtwN8cTRbqjxTA2+uHIgIDsTQcy6doO2r08SOM1ul+cWfVafrEfx5I1HVBhENVvUZGMEMCIAQktY7/qqaU4VWepck7v9SokGQiQFXN8HC2dxRpRC0HAh9cjrD+plFtYLisszrWTt5g6Hhb+zqpS5m9+GFR25qaAQEEIgAgdx/RitRZZm3Unz1WTj28QvTIR3TjYK2haBao7UiNVoECBQBHUiEDsTQcy6doO2r08SOM1ul+cWfVafrEfx5I1HVBhENVvUYhA95V0eHayAXj+KWMH7+blMAvPbqv4Sf+/KSZXyb4IIO9Uq4iBgOxNBzLp2g7avTxI4zW6X5xZ9Vp+sR/HkjUdUGEQ1W9RhC0prpnAAAAgAAAAIAEAACAIgYD3lXR4drIBeP4pYwfv5uUwC89uq/hJ/78pJlfJvggg70QtKa6ZwAAAIAAAACABQAAgAAA', KeyError],
            ['cHNidP8BAFUCAAAAASeaIyOl37UfxF8iD6WLD8E+HjNCeSqF1+Ns1jM7XLw5AAAAAAD/////AaBa6gsAAAAAGXapFP/pwAYQl8w7Y28ssEYPpPxCfStFiKwAAAAAAAEBIJVe6gsAAAAAF6kUY0UgD2jRieGtwN8cTRbqjxTA2+uHIgIDsTQcy6doO2r08SOM1ul+cWfVafrEfx5I1HVBhENVvUZGMEMCIAQktY7/qqaU4VWepck7v9SokGQiQFXN8HC2dxRpRC0HAh9cjrD+plFtYLisszrWTt5g6Hhb+zqpS5m9+GFR25qaAQEEIgAgdx/RitRZZm3Unz1WTj28QvTIR3TjYK2haBao7UiNVoEBBUdSIQOxNBzLp2g7avTxI4zW6X5xZ9Vp+sR/HkjUdUGEQ1W9RiED3lXR4drIBeP4pYwfv5uUwC89uq/hJ/78pJlfJvggg71SriEGA7E0HMunaDtq9PEjjNbpfnFn1Wn6xH8eSNR1QYRDVb0QtKa6ZwAAAIAAAACABAAAgCIGA95V0eHayAXj+KWMH7+blMAvPbqv4Sf+/KSZXyb4IIO9ELSmumcAAACAAAAAgAUAAIAAAA==', KeyError],
            ['cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAIAALsCAAAAAarXOTEBi9JfhK5AC2iEi+CdtwbqwqwYKYur7nGrZW+LAAAAAEhHMEQCIFj2/HxqM+GzFUjUgcgmwBW9MBNarULNZ3kNq2bSrSQ7AiBKHO0mBMZzW2OT5bQWkd14sA8MWUL7n3UYVvqpOBV9ugH+////AoDw+gIAAAAAF6kUD7lGNCFpa4LIM68kHHjBfdveSTSH0PIKJwEAAAAXqRQpynT4oI+BmZQoGFyXtdhS5AY/YYdlAAAAAQfaAEcwRAIgdAGK1BgAl7hzMjwAFXILNoTMgSOJEEjn282bVa1nnJkCIHPTabdA4+tT3O+jOCPIBwUUylWn3ZVE8VfBZ5EyYRGMAUgwRQIhAPYQOLMI3B2oZaNIUnRvAVdyk0IIxtJEVDk82ZvfIhd3AiAFbmdaZ1ptCgK4WxTl4pB02KJam1dgvqKBb2YZEKAG6gFHUiEClYO/Oa4KYJdHrRma3dY0+mEIVZ1sXNObTCGD8auW4H8hAtq2H/SaFNtqfQKwzR+7ePxLGDErW05U2uTbovv+9TbXUq4AAQEgAMLrCwAAAAAXqRS39fr0Dj1ApaRZsds1NfK3L6kh6IcBByMiACCMI1MXN0O1ld+0oHtyuo5C43l9p06H/n2ddJfjsgKJAwEI2gQARzBEAiBi63pVYQenxz9FrEq1od3fb3B1+xJ1lpp/OD7/94S8sgIgDAXbt0cNvy8IVX3TVscyXB7TCRPpls04QJRdsSIo2l8BRzBEAiBl9FulmYtZon/+GnvtAWrx8fkNVLOqj3RQql9WolEDvQIgf3JHA60e25ZoCyhLVtT/y4j3+3Weq74IqjDym4UTg9IBR1IhAwidwQx6xttU+RMpr2FzM9s4jOrQwjH3IzedG5kDCwLcIQI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8Oc1KuACICA6mkw39ZltOqJdusa1cK8GUDlEkpQkYLNUdT7Z7spYdxENkMak8AAACAAAAAgAQAAIAAIgICf2OZdX0u/1WhNq0CxoSxg4tlVuXxtrNCgqlLa1AFEJYQ2QxqTwAAAIAAAACABQAAgAA=', KeyError],
            ['cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAACBwDaAEcwRAIgdAGK1BgAl7hzMjwAFXILNoTMgSOJEEjn282bVa1nnJkCIHPTabdA4+tT3O+jOCPIBwUUylWn3ZVE8VfBZ5EyYRGMAUgwRQIhAPYQOLMI3B2oZaNIUnRvAVdyk0IIxtJEVDk82ZvfIhd3AiAFbmdaZ1ptCgK4WxTl4pB02KJam1dgvqKBb2YZEKAG6gFHUiEClYO/Oa4KYJdHrRma3dY0+mEIVZ1sXNObTCGD8auW4H8hAtq2H/SaFNtqfQKwzR+7ePxLGDErW05U2uTbovv+9TbXUq4AAQEgAMLrCwAAAAAXqRS39fr0Dj1ApaRZsds1NfK3L6kh6IcBByMiACCMI1MXN0O1ld+0oHtyuo5C43l9p06H/n2ddJfjsgKJAwEI2gQARzBEAiBi63pVYQenxz9FrEq1od3fb3B1+xJ1lpp/OD7/94S8sgIgDAXbt0cNvy8IVX3TVscyXB7TCRPpls04QJRdsSIo2l8BRzBEAiBl9FulmYtZon/+GnvtAWrx8fkNVLOqj3RQql9WolEDvQIgf3JHA60e25ZoCyhLVtT/y4j3+3Weq74IqjDym4UTg9IBR1IhAwidwQx6xttU+RMpr2FzM9s4jOrQwjH3IzedG5kDCwLcIQI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8Oc1KuACICA6mkw39ZltOqJdusa1cK8GUDlEkpQkYLNUdT7Z7spYdxENkMak8AAACAAAAAgAQAAIAAIgICf2OZdX0u/1WhNq0CxoSxg4tlVuXxtrNCgqlLa1AFEJYQ2QxqTwAAAIAAAACABQAAgAA=', KeyError],
            ['cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAABB9oARzBEAiB0AYrUGACXuHMyPAAVcgs2hMyBI4kQSOfbzZtVrWecmQIgc9Npt0Dj61Pc76M4I8gHBRTKVafdlUTxV8FnkTJhEYwBSDBFAiEA9hA4swjcHahlo0hSdG8BV3KTQgjG0kRUOTzZm98iF3cCIAVuZ1pnWm0KArhbFOXikHTYolqbV2C+ooFvZhkQoAbqAUdSIQKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfyEC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtdSrgABASAAwusLAAAAABepFLf1+vQOPUClpFmx2zU18rcvqSHohwEHIyIAIIwjUxc3Q7WV37Sge3K6jkLjeX2nTof+fZ10l+OyAokDAggA2gQARzBEAiBi63pVYQenxz9FrEq1od3fb3B1+xJ1lpp/OD7/94S8sgIgDAXbt0cNvy8IVX3TVscyXB7TCRPpls04QJRdsSIo2l8BRzBEAiBl9FulmYtZon/+GnvtAWrx8fkNVLOqj3RQql9WolEDvQIgf3JHA60e25ZoCyhLVtT/y4j3+3Weq74IqjDym4UTg9IBR1IhAwidwQx6xttU+RMpr2FzM9s4jOrQwjH3IzedG5kDCwLcIQI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8Oc1KuACICA6mkw39ZltOqJdusa1cK8GUDlEkpQkYLNUdT7Z7spYdxENkMak8AAACAAAAAgAQAAIAAIgICf2OZdX0u/1WhNq0CxoSxg4tlVuXxtrNCgqlLa1AFEJYQ2QxqTwAAAIAAAACABQAAgAA=', KeyError],
            ['cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAABB9oARzBEAiB0AYrUGACXuHMyPAAVcgs2hMyBI4kQSOfbzZtVrWecmQIgc9Npt0Dj61Pc76M4I8gHBRTKVafdlUTxV8FnkTJhEYwBSDBFAiEA9hA4swjcHahlo0hSdG8BV3KTQgjG0kRUOTzZm98iF3cCIAVuZ1pnWm0KArhbFOXikHTYolqbV2C+ooFvZhkQoAbqAUdSIQKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfyEC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtdSrgABASAAwusLAAAAABepFLf1+vQOPUClpFmx2zU18rcvqSHohwEHIyIAIIwjUxc3Q7WV37Sge3K6jkLjeX2nTof+fZ10l+OyAokDAQjaBABHMEQCIGLrelVhB6fHP0WsSrWh3d9vcHX7EnWWmn84Pv/3hLyyAiAMBdu3Rw2/LwhVfdNWxzJcHtMJE+mWzThAlF2xIijaXwFHMEQCIGX0W6WZi1mif/4ae+0BavHx+Q1Us6qPdFCqX1aiUQO9AiB/ckcDrR7blmgLKEtW1P/LiPf7dZ6rvgiqMPKbhROD0gFHUiEDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwhAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zUq4AIQIDqaTDf1mW06ol26xrVwrwZQOUSSlCRgs1R1PtnuylhxDZDGpPAAAAgAAAAIAEAACAACICAn9jmXV9Lv9VoTatAsaEsYOLZVbl8bazQoKpS2tQBRCWENkMak8AAACAAAAAgAUAAIAA', KeyError],
            ['cHNidP8BAHMCAAAAATAa6YblFqHsisW0vGVz0y+DtGXiOtdhZ9aLOOcwtNvbAAAAAAD/////AnR7AQAAAAAAF6kUA6oXrogrXQ1Usl1jEE5P/s57nqKHYEOZOwAAAAAXqRS5IbG6b3IuS/qDtlV6MTmYakLsg4cAAAAAAAEBHwDKmjsAAAAAFgAU0tlLZK4IWH7vyO6xh8YB6Tn5A3wCAwABAAAAAAEAFgAUYunpgv/zTdgjlhAxawkM0qO3R8sAAQAiACCHa62DLx0WgBXtQSMqnqZaGBXZ7xPA74dZ9ktbKyeKZQEBJVEhA7fOI6AcW0vwCmQlN836uzFbZoMyhnR471EwnSvVf4qHUa4A', KeyError],
            ['cHNidP8BAHMCAAAAATAa6YblFqHsisW0vGVz0y+DtGXiOtdhZ9aLOOcwtNvbAAAAAAD/////AnR7AQAAAAAAF6kUA6oXrogrXQ1Usl1jEE5P/s57nqKHYEOZOwAAAAAXqRS5IbG6b3IuS/qDtlV6MTmYakLsg4cAAAAAAAEBHwDKmjsAAAAAFgAU0tlLZK4IWH7vyO6xh8YB6Tn5A3wAAgAAFgAUYunpgv/zTdgjlhAxawkM0qO3R8sAAQAiACCHa62DLx0WgBXtQSMqnqZaGBXZ7xPA74dZ9ktbKyeKZQEBJVEhA7fOI6AcW0vwCmQlN836uzFbZoMyhnR471EwnSvVf4qHUa4A', KeyError],
            ['cHNidP8BAHMCAAAAATAa6YblFqHsisW0vGVz0y+DtGXiOtdhZ9aLOOcwtNvbAAAAAAD/////AnR7AQAAAAAAF6kUA6oXrogrXQ1Usl1jEE5P/s57nqKHYEOZOwAAAAAXqRS5IbG6b3IuS/qDtlV6MTmYakLsg4cAAAAAAAEBHwDKmjsAAAAAFgAU0tlLZK4IWH7vyO6xh8YB6Tn5A3wAAQAWABRi6emC//NN2COWEDFrCQzSo7dHywABACIAIIdrrYMvHRaAFe1BIyqeploYFdnvE8Dvh1n2S1srJ4plIQEAJVEhA7fOI6AcW0vwCmQlN836uzFbZoMyhnR471EwnSvVf4qHUa4A', KeyError],
            ['cHNidP8BAKACAAAAAqsJSaCMWvfEm4IS9Bfi8Vqz9cM9zxU4IagTn4d6W3vkAAAAAAD+////qwlJoIxa98SbghL0F+LxWrP1wz3PFTghqBOfh3pbe+QBAAAAAP7///8CYDvqCwAAAAAZdqkUdopAu9dAy+gdmI5x3ipNXHE5ax2IrI4kAAAAAAAAGXapFG9GILVT+glechue4O/p+gOcykWXiKwAAAAAAAEBItPf9QUAAAAAGXapFNSO0xELlAFMsRS9Mtb00GbcdCVriKwAAQEgAOH1BQAAAAAXqRQ1RebjO4MsRwUPJNPuuTycA5SLx4cBBBYAFIXRNTfy4mVAWjTbr6nj3aAfuCMIACICAurVlmh8qAYEPtw94RbN8p1eklfBls0FXPaYyNAr8k6ZELSmumcAAACAAAAAgAIAAIAAIgIDlPYr6d8ZlSxVh3aK63aYBhrSxKJciU9H2MFitNchPQUQtKa6ZwAAAIABAACAAgAAgAA=', ValueError],
            ['cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAAiAgLath/0mhTban0CsM0fu3j8SxgxK1tOVNrk26L7/vU210gwRQIhAPYQOLMI3B2oZaNIUnRvAVdyk0IIxtJEVDk82ZvfIhd3AiAFbmdaZ1ptCgK4WxTl4pB02KJam1dgvqKBb2YZEKAG6gEBAwQBAAAAAQRHUiEClYO/Oa4KYJdHrRma3dY0+mEIVZ1sXNObTCGD8auW4H8hAtq2H/SaFNtqfQKwzR+7ePxLGDErW05U2uTbovv+9TbXUq8iBgKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfxDZDGpPAAAAgAAAAIAAAACAIgYC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtcQ2QxqTwAAAIAAAACAAQAAgAABASAAwusLAAAAABepFLf1+vQOPUClpFmx2zU18rcvqSHohyICAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zRzBEAiBl9FulmYtZon/+GnvtAWrx8fkNVLOqj3RQql9WolEDvQIgf3JHA60e25ZoCyhLVtT/y4j3+3Weq74IqjDym4UTg9IBAQMEAQAAAAEEIgAgjCNTFzdDtZXftKB7crqOQuN5fadOh/59nXSX47ICiQMBBUdSIQMIncEMesbbVPkTKa9hczPbOIzq0MIx9yM3nRuZAwsC3CECOt2QTz1tz1nduQaw3uI1Kbf/ue1Q5ehhUZJoYCIfDnNSriIGAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zENkMak8AAACAAAAAgAMAAIAiBgMIncEMesbbVPkTKa9hczPbOIzq0MIx9yM3nRuZAwsC3BDZDGpPAAAAgAAAAIACAACAACICA6mkw39ZltOqJdusa1cK8GUDlEkpQkYLNUdT7Z7spYdxENkMak8AAACAAAAAgAQAAIAAIgICf2OZdX0u/1WhNq0CxoSxg4tlVuXxtrNCgqlLa1AFEJYQ2QxqTwAAAIAAAACABQAAgAA=', ValueError],
            ['cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAAiAgLath/0mhTban0CsM0fu3j8SxgxK1tOVNrk26L7/vU210gwRQIhAPYQOLMI3B2oZaNIUnRvAVdyk0IIxtJEVDk82ZvfIhd3AiAFbmdaZ1ptCgK4WxTl4pB02KJam1dgvqKBb2YZEKAG6gEBAwQBAAAAAQRHUiEClYO/Oa4KYJdHrRma3dY0+mEIVZ1sXNObTCGD8auW4H8hAtq2H/SaFNtqfQKwzR+7ePxLGDErW05U2uTbovv+9TbXUq4iBgKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfxDZDGpPAAAAgAAAAIAAAACAIgYC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtcQ2QxqTwAAAIAAAACAAQAAgAABASAAwusLAAAAABepFLf1+vQOPUClpFmx2zU18rcvqSHohyICAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zRzBEAiBl9FulmYtZon/+GnvtAWrx8fkNVLOqj3RQql9WolEDvQIgf3JHA60e25ZoCyhLVtT/y4j3+3Weq74IqjDym4UTg9IBAQMEAQAAAAEEIgAgjCNTFzdDtZXftKB7crqOQuN5fadOh/59nXSX47ICiQABBUdSIQMIncEMesbbVPkTKa9hczPbOIzq0MIx9yM3nRuZAwsC3CECOt2QTz1tz1nduQaw3uI1Kbf/ue1Q5ehhUZJoYCIfDnNSriIGAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zENkMak8AAACAAAAAgAMAAIAiBgMIncEMesbbVPkTKa9hczPbOIzq0MIx9yM3nRuZAwsC3BDZDGpPAAAAgAAAAIACAACAACICA6mkw39ZltOqJdusa1cK8GUDlEkpQkYLNUdT7Z7spYdxENkMak8AAACAAAAAgAQAAIAAIgICf2OZdX0u/1WhNq0CxoSxg4tlVuXxtrNCgqlLa1AFEJYQ2QxqTwAAAIAAAACABQAAgAA=', ValueError],
            ['cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAAiAgLath/0mhTban0CsM0fu3j8SxgxK1tOVNrk26L7/vU210gwRQIhAPYQOLMI3B2oZaNIUnRvAVdyk0IIxtJEVDk82ZvfIhd3AiAFbmdaZ1ptCgK4WxTl4pB02KJam1dgvqKBb2YZEKAG6gEBAwQBAAAAAQRHUiEClYO/Oa4KYJdHrRma3dY0+mEIVZ1sXNObTCGD8auW4H8hAtq2H/SaFNtqfQKwzR+7ePxLGDErW05U2uTbovv+9TbXUq4iBgKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfxDZDGpPAAAAgAAAAIAAAACAIgYC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtcQ2QxqTwAAAIAAAACAAQAAgAABASAAwusLAAAAABepFLf1+vQOPUClpFmx2zU18rcvqSHohyICAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zRzBEAiBl9FulmYtZon/+GnvtAWrx8fkNVLOqj3RQql9WolEDvQIgf3JHA60e25ZoCyhLVtT/y4j3+3Weq74IqjDym4UTg9IBAQMEAQAAAAEEIgAgjCNTFzdDtZXftKB7crqOQuN5fadOh/59nXSX47ICiQMBBUdSIQMIncEMesbbVPkTKa9hczPbOIzq0MIx9yM3nRuZAwsC3CECOt2QTz1tz1nduQaw3uI1Kbf/ue1Q5ehhUZJoYCIfDnNSrSIGAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zENkMak8AAACAAAAAgAMAAIAiBgMIncEMesbbVPkTKa9hczPbOIzq0MIx9yM3nRuZAwsC3BDZDGpPAAAAgAAAAIACAACAACICA6mkw39ZltOqJdusa1cK8GUDlEkpQkYLNUdT7Z7spYdxENkMak8AAACAAAAAgAQAAIAAIgICf2OZdX0u/1WhNq0CxoSxg4tlVuXxtrNCgqlLa1AFEJYQ2QxqTwAAAIAAAACABQAAgAA=', ValueError],
        ]
        for base64_psbt, error in tests:
            with self.assertRaises(error):
                print(PSBT.parse_base64(base64_psbt))

    def test_parse(self):
        tests = [
            'cHNidP8BAHUCAAAAASaBcTce3/KF6Tet7qSze3gADAVmy7OtZGQXE8pCFxv2AAAAAAD+////AtPf9QUAAAAAGXapFNDFmQPFusKGh2DpD9UhpGZap2UgiKwA4fUFAAAAABepFDVF5uM7gyxHBQ8k0+65PJwDlIvHh7MuEwAAAQD9pQEBAAAAAAECiaPHHqtNIOA3G7ukzGmPopXJRjr6Ljl/hTPMti+VZ+UBAAAAFxYAFL4Y0VKpsBIDna89p95PUzSe7LmF/////4b4qkOnHf8USIk6UwpyN+9rRgi7st0tAXHmOuxqSJC0AQAAABcWABT+Pp7xp0XpdNkCxDVZQ6vLNL1TU/////8CAMLrCwAAAAAZdqkUhc/xCX/Z4Ai7NK9wnGIZeziXikiIrHL++E4sAAAAF6kUM5cluiHv1irHU6m80GfWx6ajnQWHAkcwRAIgJxK+IuAnDzlPVoMR3HyppolwuAJf3TskAinwf4pfOiQCIAGLONfc0xTnNMkna9b7QPZzMlvEuqFEyADS8vAtsnZcASED0uFWdJQbrUqZY3LLh+GFbTZSYG2YVi/jnF6efkE/IQUCSDBFAiEA0SuFLYXc2WHS9fSrZgZU327tzHlMDDPOXMMJ/7X85Y0CIGczio4OFyXBl/saiK9Z9R5E5CVbIBZ8hoQDHAXR8lkqASECI7cr7vCWXRC+B3jv7NYfysb3mk6haTkzgHNEZPhPKrMAAAAAAAAA',
            #            'cHNidP8BAKACAAAAAqsJSaCMWvfEm4IS9Bfi8Vqz9cM9zxU4IagTn4d6W3vkAAAAAAD+////qwlJoIxa98SbghL0F+LxWrP1wz3PFTghqBOfh3pbe+QBAAAAAP7///8CYDvqCwAAAAAZdqkUdopAu9dAy+gdmI5x3ipNXHE5ax2IrI4kAAAAAAAAGXapFG9GILVT+glechue4O/p+gOcykWXiKwAAAAAAAEHakcwRAIgR1lmF5fAGwNrJZKJSGhiGDR9iYZLcZ4ff89X0eURZYcCIFMJ6r9Wqk2Ikf/REf3xM286KdqGbX+EhtdVRs7tr5MZASEDXNxh/HupccC1AaZGoqg7ECy0OIEhfKaC3Ibi1z+ogpIAAQEgAOH1BQAAAAAXqRQ1RebjO4MsRwUPJNPuuTycA5SLx4cBBBYAFIXRNTfy4mVAWjTbr6nj3aAfuCMIAAAA',
            'cHNidP8BAHUCAAAAASaBcTce3/KF6Tet7qSze3gADAVmy7OtZGQXE8pCFxv2AAAAAAD+////AtPf9QUAAAAAGXapFNDFmQPFusKGh2DpD9UhpGZap2UgiKwA4fUFAAAAABepFDVF5uM7gyxHBQ8k0+65PJwDlIvHh7MuEwAAAQD9pQEBAAAAAAECiaPHHqtNIOA3G7ukzGmPopXJRjr6Ljl/hTPMti+VZ+UBAAAAFxYAFL4Y0VKpsBIDna89p95PUzSe7LmF/////4b4qkOnHf8USIk6UwpyN+9rRgi7st0tAXHmOuxqSJC0AQAAABcWABT+Pp7xp0XpdNkCxDVZQ6vLNL1TU/////8CAMLrCwAAAAAZdqkUhc/xCX/Z4Ai7NK9wnGIZeziXikiIrHL++E4sAAAAF6kUM5cluiHv1irHU6m80GfWx6ajnQWHAkcwRAIgJxK+IuAnDzlPVoMR3HyppolwuAJf3TskAinwf4pfOiQCIAGLONfc0xTnNMkna9b7QPZzMlvEuqFEyADS8vAtsnZcASED0uFWdJQbrUqZY3LLh+GFbTZSYG2YVi/jnF6efkE/IQUCSDBFAiEA0SuFLYXc2WHS9fSrZgZU327tzHlMDDPOXMMJ/7X85Y0CIGczio4OFyXBl/saiK9Z9R5E5CVbIBZ8hoQDHAXR8lkqASECI7cr7vCWXRC+B3jv7NYfysb3mk6haTkzgHNEZPhPKrMAAAAAAQMEAQAAAAAAAA==',
            'cHNidP8BAKACAAAAAqsJSaCMWvfEm4IS9Bfi8Vqz9cM9zxU4IagTn4d6W3vkAAAAAAD+////qwlJoIxa98SbghL0F+LxWrP1wz3PFTghqBOfh3pbe+QBAAAAAP7///8CYDvqCwAAAAAZdqkUdopAu9dAy+gdmI5x3ipNXHE5ax2IrI4kAAAAAAAAGXapFG9GILVT+glechue4O/p+gOcykWXiKwAAAAAAAEA3wIAAAABJoFxNx7f8oXpN63upLN7eAAMBWbLs61kZBcTykIXG/YAAAAAakcwRAIgcLIkUSPmv0dNYMW1DAQ9TGkaXSQ18Jo0p2YqncJReQoCIAEynKnazygL3zB0DsA5BCJCLIHLRYOUV663b8Eu3ZWzASECZX0RjTNXuOD0ws1G23s59tnDjZpwq8ubLeXcjb/kzjH+////AtPf9QUAAAAAGXapFNDFmQPFusKGh2DpD9UhpGZap2UgiKwA4fUFAAAAABepFDVF5uM7gyxHBQ8k0+65PJwDlIvHh7MuEwAAAQEgAOH1BQAAAAAXqRQ1RebjO4MsRwUPJNPuuTycA5SLx4cBBBYAFIXRNTfy4mVAWjTbr6nj3aAfuCMIACICAurVlmh8qAYEPtw94RbN8p1eklfBls0FXPaYyNAr8k6ZELSmumcAAACAAAAAgAIAAIAAIgIDlPYr6d8ZlSxVh3aK63aYBhrSxKJciU9H2MFitNchPQUQtKa6ZwAAAIABAACAAgAAgAA=',
            'cHNidP8BAFUCAAAAASeaIyOl37UfxF8iD6WLD8E+HjNCeSqF1+Ns1jM7XLw5AAAAAAD/////AaBa6gsAAAAAGXapFP/pwAYQl8w7Y28ssEYPpPxCfStFiKwAAAAAAAEBIJVe6gsAAAAAF6kUY0UgD2jRieGtwN8cTRbqjxTA2+uHIgIDsTQcy6doO2r08SOM1ul+cWfVafrEfx5I1HVBhENVvUZGMEMCIAQktY7/qqaU4VWepck7v9SokGQiQFXN8HC2dxRpRC0HAh9cjrD+plFtYLisszrWTt5g6Hhb+zqpS5m9+GFR25qaAQEEIgAgdx/RitRZZm3Unz1WTj28QvTIR3TjYK2haBao7UiNVoEBBUdSIQOxNBzLp2g7avTxI4zW6X5xZ9Vp+sR/HkjUdUGEQ1W9RiED3lXR4drIBeP4pYwfv5uUwC89uq/hJ/78pJlfJvggg71SriIGA7E0HMunaDtq9PEjjNbpfnFn1Wn6xH8eSNR1QYRDVb1GELSmumcAAACAAAAAgAQAAIAiBgPeVdHh2sgF4/iljB+/m5TALz26r+En/vykmV8m+CCDvRC0prpnAAAAgAAAAIAFAACAAAA=',
            'cHNidP8BAD8CAAAAAf//////////////////////////////////////////AAAAAAD/////AQAAAAAAAAAAA2oBAAAAAAAACg8BAgMEBQYHCAkPAQIDBAUGBwgJCgsMDQ4PAAA=',
            'cHNidP8BAJ0BAAAAAnEOp2q0XFy2Q45gflnMA3YmmBgFrp4N/ZCJASq7C+U1AQAAAAD/////GQmU1qizyMgsy8+y+6QQaqBmObhyqNRHRlwNQliNbWcAAAAAAP////8CAOH1BQAAAAAZdqkUtrwsDuVlWoQ9ea/t0MzD991kNAmIrGBa9AUAAAAAFgAUEYjvjkzgRJ6qyPsUHL9aEXbmoIgAAAAATwEEiLIeA55TDKyAAAAAPbyKXJdp8DGxfnf+oVGGAyIaGP0Y8rmlTGyMGsdcvDUC8jBYSxVdHH8c1FEgplPEjWULQxtnxbLBPyfXFCA3wWkQJ1acUDEAAIAAAACAAAAAgAABAR8A4fUFAAAAABYAFDO5gvkbKPFgySC0q5XljOUN2jpKIgIDMJaA8zx9446mpHzU7NZvH1pJdHxv+4gI7QkDkkPjrVxHMEQCIC1wTO2DDFapCTRL10K2hS3M0QPpY7rpLTjnUlTSu0JFAiAthsQ3GV30bAztoITyopHD2i1kBw92v5uQsZXn7yj3cgEiBgMwloDzPH3jjqakfNTs1m8fWkl0fG/7iAjtCQOSQ+OtXBgnVpxQMQAAgAAAAIAAAACAAAAAAAEAAAAAAQEfAOH1BQAAAAAWABQ4j7lEMH63fvRRl9CwskXgefAR3iICAsd3Fh9z0LfHK57nveZQKT0T8JW8dlatH1Jdpf0uELEQRzBEAiBMsftfhpyULg4mEAV2ElQ5F5rojcqKncO6CPeVOYj6pgIgUh9JynkcJ9cOJzybFGFphZCTYeJb4nTqIA1+CIJ+UU0BIgYCx3cWH3PQt8crnue95lApPRPwlbx2Vq0fUl2l/S4QsRAYJ1acUDEAAIAAAACAAAAAgAAAAAAAAAAAAAAiAgLSDKUC7iiWhtIYFb1DqAY3sGmOH7zb5MrtRF9sGgqQ7xgnVpxQMQAAgAAAAIAAAACAAAAAAAQAAAAA',
        ]
        for i, base64_psbt in enumerate(tests):
            # parse does all the validation
            psbt = PSBT.parse_base64(base64_psbt)
            self.assertEqual(psbt.serialize_base64(), base64_psbt)

    def test_parse_2(self):
        hex_psbt = '70736274ff01009d0100000002710ea76ab45c5cb6438e607e59cc037626981805ae9e0dfd9089012abb0be5350100000000ffffffff190994d6a8b3c8c82ccbcfb2fba4106aa06639b872a8d447465c0d42588d6d670000000000ffffffff0200e1f505000000001976a914b6bc2c0ee5655a843d79afedd0ccc3f7dd64340988ac605af405000000001600141188ef8e4ce0449eaac8fb141cbf5a1176e6a088000000004f010488b21e039e530cac800000003dbc8a5c9769f031b17e77fea1518603221a18fd18f2b9a54c6c8c1ac75cbc3502f230584b155d1c7f1cd45120a653c48d650b431b67c5b2c13f27d7142037c1691027569c503100008000000080000000800001011f00e1f5050000000016001433b982f91b28f160c920b4ab95e58ce50dda3a4a220203309680f33c7de38ea6a47cd4ecd66f1f5a49747c6ffb8808ed09039243e3ad5c47304402202d704ced830c56a909344bd742b6852dccd103e963bae92d38e75254d2bb424502202d86c437195df46c0ceda084f2a291c3da2d64070f76bf9b90b195e7ef28f77201220603309680f33c7de38ea6a47cd4ecd66f1f5a49747c6ffb8808ed09039243e3ad5c1827569c5031000080000000800000008000000000010000000001011f00e1f50500000000160014388fb944307eb77ef45197d0b0b245e079f011de220202c777161f73d0b7c72b9ee7bde650293d13f095bc7656ad1f525da5fd2e10b11047304402204cb1fb5f869c942e0e26100576125439179ae88dca8a9dc3ba08f7953988faa60220521f49ca791c27d70e273c9b14616985909361e25be274ea200d7e08827e514d01220602c777161f73d0b7c72b9ee7bde650293d13f095bc7656ad1f525da5fd2e10b1101827569c5031000080000000800000008000000000000000000000220202d20ca502ee289686d21815bd43a80637b0698e1fbcdbe4caed445f6c1a0a90ef1827569c50310000800000008000000080000000000400000000'
        psbt = PSBT.parse(BytesIO(bytes.fromhex(hex_psbt)))
        self.assertEqual(psbt.serialize().hex(), hex_psbt)

    def test_update_1(self):
        psbt = PSBT.parse_base64('cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAAAAAA=')
        transaction_data = ['0200000001aad73931018bd25f84ae400b68848be09db706eac2ac18298babee71ab656f8b0000000048473044022058f6fc7c6a33e1b31548d481c826c015bd30135aad42cd67790dab66d2ad243b02204a1ced2604c6735b6393e5b41691dd78b00f0c5942fb9f751856faa938157dba01feffffff0280f0fa020000000017a9140fb9463421696b82c833af241c78c17ddbde493487d0f20a270100000017a91429ca74f8a08f81999428185c97b5d852e4063f618765000000', '0200000000010158e87a21b56daf0c23be8e7070456c336f7cbaa5c8757924f545887bb2abdd7501000000171600145f275f436b09a8cc9a2eb2a2f528485c68a56323feffffff02d8231f1b0100000017a914aed962d6654f9a2b36608eb9d64d2b260db4f1118700c2eb0b0000000017a914b7f5faf40e3d40a5a459b1db3535f2b72fa921e88702483045022100a22edcc6e5bc511af4cc4ae0de0fcd75c7e04d8c1c3a8aa9d820ed4b967384ec02200642963597b9b1bc22c75e9f3e117284a962188bf5e8a74c895089046a20ad770121035509a48eb623e10aace8bfd0212fdb8a8e5af3c94b0b133b95e114cab89e4f7965000000']
        redeem_script_data = [
            '475221029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f2102dab61ff49a14db6a7d02b0cd1fbb78fc4b18312b5b4e54dae4dba2fbfef536d752ae',
            '2200208c2353173743b595dfb4a07b72ba8e42e3797da74e87fe7d9d7497e3b2028903',
        ]
        witness_script_data = ['47522103089dc10c7ac6db54f91329af617333db388cead0c231f723379d1b99030b02dc21023add904f3d6dcf59ddb906b0dee23529b7ffb9ed50e5e86151926860221f0e7352ae']
        tx_lookup = {}
        for hex_tx in transaction_data:
            tx_obj = Tx.parse(BytesIO(bytes.fromhex(hex_tx)))
            tx_lookup[tx_obj.hash()] = tx_obj
        hd_priv = HDPrivateKey.parse('tprv8ZgxMBicQKsPd9TeAdPADNnSyH9SSUUbTVeFszDE23Ki6TBB5nCefAdHkK8Fm3qMQR6sHwA56zqRmKmxnHk37JkiFzvncDqoKmPWubu7hDF')
        pubkey_lookup = {}
        for i in range(6):
            path = "m/0'/0'/{}'".format(i)
            named_pubkey = NamedHDPublicKey.from_hd_priv(hd_priv, path)
            pubkey_lookup[named_pubkey.sec()] = named_pubkey
            pubkey_lookup[named_pubkey.hash160()] = named_pubkey
        redeem_lookup = {}
        for hex_redeem_script in redeem_script_data:
            redeem_script = RedeemScript.parse(BytesIO(bytes.fromhex(hex_redeem_script)))
            redeem_lookup[redeem_script.hash160()] = redeem_script
        witness_lookup = {}
        for hex_witness_script in witness_script_data:
            witness_script = WitnessScript.parse(BytesIO(bytes.fromhex(hex_witness_script)))
            witness_lookup[witness_script.sha256()] = witness_script
        psbt.update(tx_lookup, pubkey_lookup, redeem_lookup, witness_lookup)
        self.assertTrue(psbt.validate())
        want = 'cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAABBEdSIQKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfyEC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtdSriIGApWDvzmuCmCXR60Zmt3WNPphCFWdbFzTm0whg/GrluB/ENkMak8AAACAAAAAgAAAAIAiBgLath/0mhTban0CsM0fu3j8SxgxK1tOVNrk26L7/vU21xDZDGpPAAAAgAAAAIABAACAAAEBIADC6wsAAAAAF6kUt/X69A49QKWkWbHbNTXyty+pIeiHAQQiACCMI1MXN0O1ld+0oHtyuo5C43l9p06H/n2ddJfjsgKJAwEFR1IhAwidwQx6xttU+RMpr2FzM9s4jOrQwjH3IzedG5kDCwLcIQI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8Oc1KuIgYCOt2QTz1tz1nduQaw3uI1Kbf/ue1Q5ehhUZJoYCIfDnMQ2QxqTwAAAIAAAACAAwAAgCIGAwidwQx6xttU+RMpr2FzM9s4jOrQwjH3IzedG5kDCwLcENkMak8AAACAAAAAgAIAAIAAIgIDqaTDf1mW06ol26xrVwrwZQOUSSlCRgs1R1Ptnuylh3EQ2QxqTwAAAIAAAACABAAAgAAiAgJ/Y5l1fS7/VaE2rQLGhLGDi2VW5fG2s0KCqUtrUAUQlhDZDGpPAAAAgAAAAIAFAACAAA=='
        self.assertEqual(psbt.serialize_base64(), want)

    def test_update_2(self):
        psbt = PSBT.parse_base64('cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAABBEdSIQKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfyEC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtdSriIGApWDvzmuCmCXR60Zmt3WNPphCFWdbFzTm0whg/GrluB/ENkMak8AAACAAAAAgAAAAIAiBgLath/0mhTban0CsM0fu3j8SxgxK1tOVNrk26L7/vU21xDZDGpPAAAAgAAAAIABAACAAAEBIADC6wsAAAAAF6kUt/X69A49QKWkWbHbNTXyty+pIeiHAQQiACCMI1MXN0O1ld+0oHtyuo5C43l9p06H/n2ddJfjsgKJAwEFR1IhAwidwQx6xttU+RMpr2FzM9s4jOrQwjH3IzedG5kDCwLcIQI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8Oc1KuIgYCOt2QTz1tz1nduQaw3uI1Kbf/ue1Q5ehhUZJoYCIfDnMQ2QxqTwAAAIAAAACAAwAAgCIGAwidwQx6xttU+RMpr2FzM9s4jOrQwjH3IzedG5kDCwLcENkMak8AAACAAAAAgAIAAIAAIgIDqaTDf1mW06ol26xrVwrwZQOUSSlCRgs1R1Ptnuylh3EQ2QxqTwAAAIAAAACABAAAgAAiAgJ/Y5l1fS7/VaE2rQLGhLGDi2VW5fG2s0KCqUtrUAUQlhDZDGpPAAAAgAAAAIAFAACAAA==')
        psbt.psbt_ins[0].hash_type = SIGHASH_ALL
        psbt.psbt_ins[1].hash_type = SIGHASH_ALL
        self.assertTrue(psbt.validate())
        want = 'cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAABAwQBAAAAAQRHUiEClYO/Oa4KYJdHrRma3dY0+mEIVZ1sXNObTCGD8auW4H8hAtq2H/SaFNtqfQKwzR+7ePxLGDErW05U2uTbovv+9TbXUq4iBgKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfxDZDGpPAAAAgAAAAIAAAACAIgYC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtcQ2QxqTwAAAIAAAACAAQAAgAABASAAwusLAAAAABepFLf1+vQOPUClpFmx2zU18rcvqSHohwEDBAEAAAABBCIAIIwjUxc3Q7WV37Sge3K6jkLjeX2nTof+fZ10l+OyAokDAQVHUiEDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwhAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zUq4iBgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8OcxDZDGpPAAAAgAAAAIADAACAIgYDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwQ2QxqTwAAAIAAAACAAgAAgAAiAgOppMN/WZbTqiXbrGtXCvBlA5RJKUJGCzVHU+2e7KWHcRDZDGpPAAAAgAAAAIAEAACAACICAn9jmXV9Lv9VoTatAsaEsYOLZVbl8bazQoKpS2tQBRCWENkMak8AAACAAAAAgAUAAIAA'
        self.assertEqual(psbt.serialize_base64(), want)

    def test_sign_1(self):
        psbt = PSBT.parse_base64('cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAABAwQBAAAAAQRHUiEClYO/Oa4KYJdHrRma3dY0+mEIVZ1sXNObTCGD8auW4H8hAtq2H/SaFNtqfQKwzR+7ePxLGDErW05U2uTbovv+9TbXUq4iBgKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfxDZDGpPAAAAgAAAAIAAAACAIgYC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtcQ2QxqTwAAAIAAAACAAQAAgAABASAAwusLAAAAABepFLf1+vQOPUClpFmx2zU18rcvqSHohwEDBAEAAAABBCIAIIwjUxc3Q7WV37Sge3K6jkLjeX2nTof+fZ10l+OyAokDAQVHUiEDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwhAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zUq4iBgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8OcxDZDGpPAAAAgAAAAIADAACAIgYDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwQ2QxqTwAAAIAAAACAAgAAgAAiAgOppMN/WZbTqiXbrGtXCvBlA5RJKUJGCzVHU+2e7KWHcRDZDGpPAAAAgAAAAIAEAACAACICAn9jmXV9Lv9VoTatAsaEsYOLZVbl8bazQoKpS2tQBRCWENkMak8AAACAAAAAgAUAAIAA')
        hd_priv = HDPrivateKey.parse('tprv8ZgxMBicQKsPd9TeAdPADNnSyH9SSUUbTVeFszDE23Ki6TBB5nCefAdHkK8Fm3qMQR6sHwA56zqRmKmxnHk37JkiFzvncDqoKmPWubu7hDF')
        private_keys = [
            hd_priv.traverse("m/0'/0'/0'").private_key,
            hd_priv.traverse("m/0'/0'/2'").private_key,
        ]
        psbt.sign_with_private_keys(private_keys)
        self.assertTrue(psbt.validate())
        want = 'cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAAiAgKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgf0cwRAIgdAGK1BgAl7hzMjwAFXILNoTMgSOJEEjn282bVa1nnJkCIHPTabdA4+tT3O+jOCPIBwUUylWn3ZVE8VfBZ5EyYRGMAQEDBAEAAAABBEdSIQKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfyEC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtdSriIGApWDvzmuCmCXR60Zmt3WNPphCFWdbFzTm0whg/GrluB/ENkMak8AAACAAAAAgAAAAIAiBgLath/0mhTban0CsM0fu3j8SxgxK1tOVNrk26L7/vU21xDZDGpPAAAAgAAAAIABAACAAAEBIADC6wsAAAAAF6kUt/X69A49QKWkWbHbNTXyty+pIeiHIgIDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtxHMEQCIGLrelVhB6fHP0WsSrWh3d9vcHX7EnWWmn84Pv/3hLyyAiAMBdu3Rw2/LwhVfdNWxzJcHtMJE+mWzThAlF2xIijaXwEBAwQBAAAAAQQiACCMI1MXN0O1ld+0oHtyuo5C43l9p06H/n2ddJfjsgKJAwEFR1IhAwidwQx6xttU+RMpr2FzM9s4jOrQwjH3IzedG5kDCwLcIQI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8Oc1KuIgYCOt2QTz1tz1nduQaw3uI1Kbf/ue1Q5ehhUZJoYCIfDnMQ2QxqTwAAAIAAAACAAwAAgCIGAwidwQx6xttU+RMpr2FzM9s4jOrQwjH3IzedG5kDCwLcENkMak8AAACAAAAAgAIAAIAAIgIDqaTDf1mW06ol26xrVwrwZQOUSSlCRgs1R1Ptnuylh3EQ2QxqTwAAAIAAAACABAAAgAAiAgJ/Y5l1fS7/VaE2rQLGhLGDi2VW5fG2s0KCqUtrUAUQlhDZDGpPAAAAgAAAAIAFAACAAA=='
        self.assertEqual(psbt.serialize_base64(), want)

    def test_sign_2(self):
        psbt = PSBT.parse_base64('cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAABAwQBAAAAAQRHUiEClYO/Oa4KYJdHrRma3dY0+mEIVZ1sXNObTCGD8auW4H8hAtq2H/SaFNtqfQKwzR+7ePxLGDErW05U2uTbovv+9TbXUq4iBgKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfxDZDGpPAAAAgAAAAIAAAACAIgYC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtcQ2QxqTwAAAIAAAACAAQAAgAABASAAwusLAAAAABepFLf1+vQOPUClpFmx2zU18rcvqSHohwEDBAEAAAABBCIAIIwjUxc3Q7WV37Sge3K6jkLjeX2nTof+fZ10l+OyAokDAQVHUiEDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwhAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zUq4iBgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8OcxDZDGpPAAAAgAAAAIADAACAIgYDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwQ2QxqTwAAAIAAAACAAgAAgAAiAgOppMN/WZbTqiXbrGtXCvBlA5RJKUJGCzVHU+2e7KWHcRDZDGpPAAAAgAAAAIAEAACAACICAn9jmXV9Lv9VoTatAsaEsYOLZVbl8bazQoKpS2tQBRCWENkMak8AAACAAAAAgAUAAIAA')
        hd_priv = HDPrivateKey.parse('tprv8ZgxMBicQKsPd9TeAdPADNnSyH9SSUUbTVeFszDE23Ki6TBB5nCefAdHkK8Fm3qMQR6sHwA56zqRmKmxnHk37JkiFzvncDqoKmPWubu7hDF')
        private_keys = [
            hd_priv.traverse("m/0'/0'/1'").private_key,
            hd_priv.traverse("m/0'/0'/3'").private_key,
        ]
        psbt.sign_with_private_keys(private_keys)
        self.assertTrue(psbt.validate())
        want = 'cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAAiAgLath/0mhTban0CsM0fu3j8SxgxK1tOVNrk26L7/vU210gwRQIhAPYQOLMI3B2oZaNIUnRvAVdyk0IIxtJEVDk82ZvfIhd3AiAFbmdaZ1ptCgK4WxTl4pB02KJam1dgvqKBb2YZEKAG6gEBAwQBAAAAAQRHUiEClYO/Oa4KYJdHrRma3dY0+mEIVZ1sXNObTCGD8auW4H8hAtq2H/SaFNtqfQKwzR+7ePxLGDErW05U2uTbovv+9TbXUq4iBgKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfxDZDGpPAAAAgAAAAIAAAACAIgYC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtcQ2QxqTwAAAIAAAACAAQAAgAABASAAwusLAAAAABepFLf1+vQOPUClpFmx2zU18rcvqSHohyICAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zRzBEAiBl9FulmYtZon/+GnvtAWrx8fkNVLOqj3RQql9WolEDvQIgf3JHA60e25ZoCyhLVtT/y4j3+3Weq74IqjDym4UTg9IBAQMEAQAAAAEEIgAgjCNTFzdDtZXftKB7crqOQuN5fadOh/59nXSX47ICiQMBBUdSIQMIncEMesbbVPkTKa9hczPbOIzq0MIx9yM3nRuZAwsC3CECOt2QTz1tz1nduQaw3uI1Kbf/ue1Q5ehhUZJoYCIfDnNSriIGAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zENkMak8AAACAAAAAgAMAAIAiBgMIncEMesbbVPkTKa9hczPbOIzq0MIx9yM3nRuZAwsC3BDZDGpPAAAAgAAAAIACAACAACICA6mkw39ZltOqJdusa1cK8GUDlEkpQkYLNUdT7Z7spYdxENkMak8AAACAAAAAgAQAAIAAIgICf2OZdX0u/1WhNq0CxoSxg4tlVuXxtrNCgqlLa1AFEJYQ2QxqTwAAAIAAAACABQAAgAA='
        self.assertEqual(psbt.serialize_base64(), want)

    def test_combine(self):
        psbt_1 = PSBT.parse_base64('cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAAiAgKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgf0cwRAIgdAGK1BgAl7hzMjwAFXILNoTMgSOJEEjn282bVa1nnJkCIHPTabdA4+tT3O+jOCPIBwUUylWn3ZVE8VfBZ5EyYRGMAQEDBAEAAAABBEdSIQKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfyEC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtdSriIGApWDvzmuCmCXR60Zmt3WNPphCFWdbFzTm0whg/GrluB/ENkMak8AAACAAAAAgAAAAIAiBgLath/0mhTban0CsM0fu3j8SxgxK1tOVNrk26L7/vU21xDZDGpPAAAAgAAAAIABAACAAAEBIADC6wsAAAAAF6kUt/X69A49QKWkWbHbNTXyty+pIeiHIgIDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtxHMEQCIGLrelVhB6fHP0WsSrWh3d9vcHX7EnWWmn84Pv/3hLyyAiAMBdu3Rw2/LwhVfdNWxzJcHtMJE+mWzThAlF2xIijaXwEBAwQBAAAAAQQiACCMI1MXN0O1ld+0oHtyuo5C43l9p06H/n2ddJfjsgKJAwEFR1IhAwidwQx6xttU+RMpr2FzM9s4jOrQwjH3IzedG5kDCwLcIQI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8Oc1KuIgYCOt2QTz1tz1nduQaw3uI1Kbf/ue1Q5ehhUZJoYCIfDnMQ2QxqTwAAAIAAAACAAwAAgCIGAwidwQx6xttU+RMpr2FzM9s4jOrQwjH3IzedG5kDCwLcENkMak8AAACAAAAAgAIAAIAAIgIDqaTDf1mW06ol26xrVwrwZQOUSSlCRgs1R1Ptnuylh3EQ2QxqTwAAAIAAAACABAAAgAAiAgJ/Y5l1fS7/VaE2rQLGhLGDi2VW5fG2s0KCqUtrUAUQlhDZDGpPAAAAgAAAAIAFAACAAA==')
        psbt_2 = PSBT.parse_base64('cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAAiAgLath/0mhTban0CsM0fu3j8SxgxK1tOVNrk26L7/vU210gwRQIhAPYQOLMI3B2oZaNIUnRvAVdyk0IIxtJEVDk82ZvfIhd3AiAFbmdaZ1ptCgK4WxTl4pB02KJam1dgvqKBb2YZEKAG6gEBAwQBAAAAAQRHUiEClYO/Oa4KYJdHrRma3dY0+mEIVZ1sXNObTCGD8auW4H8hAtq2H/SaFNtqfQKwzR+7ePxLGDErW05U2uTbovv+9TbXUq4iBgKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfxDZDGpPAAAAgAAAAIAAAACAIgYC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtcQ2QxqTwAAAIAAAACAAQAAgAABASAAwusLAAAAABepFLf1+vQOPUClpFmx2zU18rcvqSHohyICAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zRzBEAiBl9FulmYtZon/+GnvtAWrx8fkNVLOqj3RQql9WolEDvQIgf3JHA60e25ZoCyhLVtT/y4j3+3Weq74IqjDym4UTg9IBAQMEAQAAAAEEIgAgjCNTFzdDtZXftKB7crqOQuN5fadOh/59nXSX47ICiQMBBUdSIQMIncEMesbbVPkTKa9hczPbOIzq0MIx9yM3nRuZAwsC3CECOt2QTz1tz1nduQaw3uI1Kbf/ue1Q5ehhUZJoYCIfDnNSriIGAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zENkMak8AAACAAAAAgAMAAIAiBgMIncEMesbbVPkTKa9hczPbOIzq0MIx9yM3nRuZAwsC3BDZDGpPAAAAgAAAAIACAACAACICA6mkw39ZltOqJdusa1cK8GUDlEkpQkYLNUdT7Z7spYdxENkMak8AAACAAAAAgAQAAIAAIgICf2OZdX0u/1WhNq0CxoSxg4tlVuXxtrNCgqlLa1AFEJYQ2QxqTwAAAIAAAACABQAAgAA=')
        psbt_1.combine(psbt_2)
        self.assertTrue(psbt_1.validate())
        want = 'cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAAiAgKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgf0cwRAIgdAGK1BgAl7hzMjwAFXILNoTMgSOJEEjn282bVa1nnJkCIHPTabdA4+tT3O+jOCPIBwUUylWn3ZVE8VfBZ5EyYRGMASICAtq2H/SaFNtqfQKwzR+7ePxLGDErW05U2uTbovv+9TbXSDBFAiEA9hA4swjcHahlo0hSdG8BV3KTQgjG0kRUOTzZm98iF3cCIAVuZ1pnWm0KArhbFOXikHTYolqbV2C+ooFvZhkQoAbqAQEDBAEAAAABBEdSIQKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfyEC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtdSriIGApWDvzmuCmCXR60Zmt3WNPphCFWdbFzTm0whg/GrluB/ENkMak8AAACAAAAAgAAAAIAiBgLath/0mhTban0CsM0fu3j8SxgxK1tOVNrk26L7/vU21xDZDGpPAAAAgAAAAIABAACAAAEBIADC6wsAAAAAF6kUt/X69A49QKWkWbHbNTXyty+pIeiHIgIDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtxHMEQCIGLrelVhB6fHP0WsSrWh3d9vcHX7EnWWmn84Pv/3hLyyAiAMBdu3Rw2/LwhVfdNWxzJcHtMJE+mWzThAlF2xIijaXwEiAgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8Oc0cwRAIgZfRbpZmLWaJ//hp77QFq8fH5DVSzqo90UKpfVqJRA70CIH9yRwOtHtuWaAsoS1bU/8uI9/t1nqu+CKow8puFE4PSAQEDBAEAAAABBCIAIIwjUxc3Q7WV37Sge3K6jkLjeX2nTof+fZ10l+OyAokDAQVHUiEDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwhAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zUq4iBgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8OcxDZDGpPAAAAgAAAAIADAACAIgYDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwQ2QxqTwAAAIAAAACAAgAAgAAiAgOppMN/WZbTqiXbrGtXCvBlA5RJKUJGCzVHU+2e7KWHcRDZDGpPAAAAgAAAAIAEAACAACICAn9jmXV9Lv9VoTatAsaEsYOLZVbl8bazQoKpS2tQBRCWENkMak8AAACAAAAAgAUAAIAA'
        self.assertEqual(psbt_1.serialize_base64(), want)

    def test_combine_extra(self):
        psbt_1 = PSBT.parse_base64('cHNidP8BAD8CAAAAAf//////////////////////////////////////////AAAAAAD/////AQAAAAAAAAAAA2oBAAAAAAAKDwECAwQFBgcICQ8BAgMEBQYHCAkKCwwNDg8ACg8BAgMEBQYHCAkPAQIDBAUGBwgJCgsMDQ4PAAoPAQIDBAUGBwgJDwECAwQFBgcICQoLDA0ODwA=')
        psbt_2 = PSBT.parse_base64('cHNidP8BAD8CAAAAAf//////////////////////////////////////////AAAAAAD/////AQAAAAAAAAAAA2oBAAAAAAAKDwECAwQFBgcIEA8BAgMEBQYHCAkKCwwNDg8ACg8BAgMEBQYHCBAPAQIDBAUGBwgJCgsMDQ4PAAoPAQIDBAUGBwgQDwECAwQFBgcICQoLDA0ODwA=')
        psbt_1.combine(psbt_2)
        self.assertTrue(psbt_1.validate())
        want = 'cHNidP8BAD8CAAAAAf//////////////////////////////////////////AAAAAAD/////AQAAAAAAAAAAA2oBAAAAAAAKDwECAwQFBgcICQ8BAgMEBQYHCAkKCwwNDg8KDwECAwQFBgcIEA8BAgMEBQYHCAkKCwwNDg8ACg8BAgMEBQYHCAkPAQIDBAUGBwgJCgsMDQ4PCg8BAgMEBQYHCBAPAQIDBAUGBwgJCgsMDQ4PAAoPAQIDBAUGBwgJDwECAwQFBgcICQoLDA0ODwoPAQIDBAUGBwgQDwECAwQFBgcICQoLDA0ODwA='
        self.assertEqual(psbt_1.serialize_base64(), want)

    def test_finalize(self):
        psbt = PSBT.parse_base64('cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAAiAgKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgf0cwRAIgdAGK1BgAl7hzMjwAFXILNoTMgSOJEEjn282bVa1nnJkCIHPTabdA4+tT3O+jOCPIBwUUylWn3ZVE8VfBZ5EyYRGMASICAtq2H/SaFNtqfQKwzR+7ePxLGDErW05U2uTbovv+9TbXSDBFAiEA9hA4swjcHahlo0hSdG8BV3KTQgjG0kRUOTzZm98iF3cCIAVuZ1pnWm0KArhbFOXikHTYolqbV2C+ooFvZhkQoAbqAQEDBAEAAAABBEdSIQKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfyEC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtdSriIGApWDvzmuCmCXR60Zmt3WNPphCFWdbFzTm0whg/GrluB/ENkMak8AAACAAAAAgAAAAIAiBgLath/0mhTban0CsM0fu3j8SxgxK1tOVNrk26L7/vU21xDZDGpPAAAAgAAAAIABAACAAAEBIADC6wsAAAAAF6kUt/X69A49QKWkWbHbNTXyty+pIeiHIgIDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtxHMEQCIGLrelVhB6fHP0WsSrWh3d9vcHX7EnWWmn84Pv/3hLyyAiAMBdu3Rw2/LwhVfdNWxzJcHtMJE+mWzThAlF2xIijaXwEiAgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8Oc0cwRAIgZfRbpZmLWaJ//hp77QFq8fH5DVSzqo90UKpfVqJRA70CIH9yRwOtHtuWaAsoS1bU/8uI9/t1nqu+CKow8puFE4PSAQEDBAEAAAABBCIAIIwjUxc3Q7WV37Sge3K6jkLjeX2nTof+fZ10l+OyAokDAQVHUiEDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwhAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zUq4iBgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8OcxDZDGpPAAAAgAAAAIADAACAIgYDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwQ2QxqTwAAAIAAAACAAgAAgAAiAgOppMN/WZbTqiXbrGtXCvBlA5RJKUJGCzVHU+2e7KWHcRDZDGpPAAAAgAAAAIAEAACAACICAn9jmXV9Lv9VoTatAsaEsYOLZVbl8bazQoKpS2tQBRCWENkMak8AAACAAAAAgAUAAIAA')
        psbt.finalize()
        self.assertTrue(psbt.validate())
        want = 'cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAABB9oARzBEAiB0AYrUGACXuHMyPAAVcgs2hMyBI4kQSOfbzZtVrWecmQIgc9Npt0Dj61Pc76M4I8gHBRTKVafdlUTxV8FnkTJhEYwBSDBFAiEA9hA4swjcHahlo0hSdG8BV3KTQgjG0kRUOTzZm98iF3cCIAVuZ1pnWm0KArhbFOXikHTYolqbV2C+ooFvZhkQoAbqAUdSIQKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfyEC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtdSrgABASAAwusLAAAAABepFLf1+vQOPUClpFmx2zU18rcvqSHohwEHIyIAIIwjUxc3Q7WV37Sge3K6jkLjeX2nTof+fZ10l+OyAokDAQjaBABHMEQCIGLrelVhB6fHP0WsSrWh3d9vcHX7EnWWmn84Pv/3hLyyAiAMBdu3Rw2/LwhVfdNWxzJcHtMJE+mWzThAlF2xIijaXwFHMEQCIGX0W6WZi1mif/4ae+0BavHx+Q1Us6qPdFCqX1aiUQO9AiB/ckcDrR7blmgLKEtW1P/LiPf7dZ6rvgiqMPKbhROD0gFHUiEDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwhAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zUq4AIgIDqaTDf1mW06ol26xrVwrwZQOUSSlCRgs1R1Ptnuylh3EQ2QxqTwAAAIAAAACABAAAgAAiAgJ/Y5l1fS7/VaE2rQLGhLGDi2VW5fG2s0KCqUtrUAUQlhDZDGpPAAAAgAAAAIAFAACAAA=='
        self.assertEqual(psbt.serialize_base64(), want)
        tx_obj = psbt.final_tx()
        want = '0200000000010258e87a21b56daf0c23be8e7070456c336f7cbaa5c8757924f545887bb2abdd7500000000da00473044022074018ad4180097b873323c0015720b3684cc8123891048e7dbcd9b55ad679c99022073d369b740e3eb53dcefa33823c8070514ca55a7dd9544f157c167913261118c01483045022100f61038b308dc1da865a34852746f015772934208c6d24454393cd99bdf2217770220056e675a675a6d0a02b85b14e5e29074d8a25a9b5760bea2816f661910a006ea01475221029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f2102dab61ff49a14db6a7d02b0cd1fbb78fc4b18312b5b4e54dae4dba2fbfef536d752aeffffffff838d0427d0ec650a68aa46bb0b098aea4422c071b2ca78352a077959d07cea1d01000000232200208c2353173743b595dfb4a07b72ba8e42e3797da74e87fe7d9d7497e3b2028903ffffffff0270aaf00800000000160014d85c2b71d0060b09c9886aeb815e50991dda124d00e1f5050000000016001400aea9a2e5f0f876a588df5546e8742d1d87008f000400473044022062eb7a556107a7c73f45ac4ab5a1dddf6f7075fb1275969a7f383efff784bcb202200c05dbb7470dbf2f08557dd356c7325c1ed30913e996cd3840945db12228da5f01473044022065f45ba5998b59a27ffe1a7bed016af1f1f90d54b3aa8f7450aa5f56a25103bd02207f724703ad1edb96680b284b56d4ffcb88f7fb759eabbe08aa30f29b851383d20147522103089dc10c7ac6db54f91329af617333db388cead0c231f723379d1b99030b02dc21023add904f3d6dcf59ddb906b0dee23529b7ffb9ed50e5e86151926860221f0e7352ae00000000'
        self.assertEqual(tx_obj.serialize().hex(), want)
