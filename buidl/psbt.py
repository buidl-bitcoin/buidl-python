from collections import defaultdict
from io import BytesIO

from buidl.ecc import S256Point, Signature
from buidl.hd import HDPublicKey, ltrim_path
from buidl.helper import (
    base64_decode,
    base64_encode,
    child_to_path,
    encode_varstr,
    int_to_little_endian,
    little_endian_to_int,
    parse_binary_path,
    path_network,
    read_varint,
    read_varstr,
    serialize_key_value,
)
from buidl.op import op_code_to_number
from buidl.script import (
    RedeemScript,
    Script,
    WitnessScript,
)
from buidl.tx import Tx, TxOut
from buidl.witness import Witness


PSBT_MAGIC = b"\x70\x73\x62\x74"
PSBT_SEPARATOR = b"\xff"
PSBT_DELIMITER = b"\x00"
# PSBT global
PSBT_GLOBAL_UNSIGNED_TX = b"\x00"
PSBT_GLOBAL_XPUB = b"\x01"
# PSBT in
PSBT_IN_NON_WITNESS_UTXO = b"\x00"
PSBT_IN_WITNESS_UTXO = b"\x01"
PSBT_IN_PARTIAL_SIG = b"\x02"
PSBT_IN_SIGHASH_TYPE = b"\x03"
PSBT_IN_REDEEM_SCRIPT = b"\x04"
PSBT_IN_WITNESS_SCRIPT = b"\x05"
PSBT_IN_BIP32_DERIVATION = b"\x06"
PSBT_IN_FINAL_SCRIPTSIG = b"\x07"
PSBT_IN_FINAL_SCRIPTWITNESS = b"\x08"
PSBT_IN_POR_COMMITMENT = b"\x09"
# PSBT out
PSBT_OUT_REDEEM_SCRIPT = b"\x00"
PSBT_OUT_WITNESS_SCRIPT = b"\x01"
PSBT_OUT_BIP32_DERIVATION = b"\x02"


class MixedNetwork(Exception):
    pass


class SuspiciousTransaction(Exception):
    """
    Advanced/atypical transactions will raise a SuspiciousTransaction Exception, as these cannot be trivially summarized.
    This exception does not mean there is a problem with the transaction, just that it is too complex for simple summary.
    """

    pass


def path_to_child(path_component):
    if path_component[-1:] == "'":
        child_number = 0x80000000 + int(path_component[:-1])
    else:
        child_number = int(path_component)
    return child_number


def serialize_binary_path(path):
    path = path.lower().replace("h", "'")
    bin_path = b""
    for component in path.split("/")[1:]:
        bin_path += int_to_little_endian(path_to_child(component), 4)
    return bin_path


class NamedPublicKey(S256Point):
    def __repr__(self):
        return "Point:\n{}\nPath:\n{}:{}\n".format(
            self.sec().hex(), self.root_fingerprint.hex(), self.root_path
        )

    def add_raw_path_data(self, raw_path, network=None):
        self.root_fingerprint = raw_path[:4]
        self.root_path = parse_binary_path(raw_path[4:])
        self.raw_path = raw_path
        if network is None:
            self.network = path_network(self.root_path)
        else:
            self.network = network

    def replace_xfp(self, new_xfp):
        self.add_raw_path_data(
            raw_path=bytes.fromhex(new_xfp) + serialize_binary_path(self.root_path),
            network=self.network,
        )

    @classmethod
    def parse(cls, key, s, network=None):
        point = super().parse(key[1:])
        point.__class__ = cls
        point.add_raw_path_data(read_varstr(s), network=network)
        return point

    def serialize(self, prefix):
        return serialize_key_value(prefix + self.sec(), self.raw_path)


class NamedHDPublicKey(HDPublicKey):
    def __repr__(self):
        return "HD:\n{}\nPath:\n{}:{}\n".format(
            super().__repr__(), self.root_fingerprint.hex(), self.root_path
        )

    def add_raw_path_data(self, raw_path, network=None):
        self.root_fingerprint = raw_path[:4]
        bin_path = raw_path[4:]
        self.root_path = parse_binary_path(bin_path)
        if self.depth != len(bin_path) // 4:
            raise ValueError("raw path calculated depth and depth are different")
        if network is None:
            self.network = path_network(self.root_path)
        else:
            self.network = network
        self.raw_path = raw_path
        self.sync_point()

    def sync_point(self):
        self.point.__class__ = NamedPublicKey
        self.point.root_fingerprint = self.root_fingerprint
        self.point.root_path = self.root_path
        self.point.raw_path = self.raw_path
        self.point.network = self.network

    def child(self, index):
        child = super().child(index)
        child.__class__ = self.__class__
        child.root_fingerprint = self.root_fingerprint
        child.root_path = self.root_path + child_to_path(index)
        child.network = path_network(child.root_path)
        child.raw_path = self.raw_path + int_to_little_endian(index, 4)
        child.sync_point()
        return child

    def pubkey_lookup(self, max_child=9):
        lookup = {}
        for child_index in range(max_child + 1):
            child = self.child(child_index)
            lookup[child.sec()] = child
            lookup[child.hash160()] = child
        return lookup

    def redeem_script_lookup(self, max_external=9, max_internal=9):
        """Returns a dictionary of RedeemScripts associated with p2sh-p2wpkh for the BIP44 child ScriptPubKeys"""
        # create a lookup to send back
        lookup = {}
        # create the external child (0)
        external = self.child(0)
        # loop through to the maximum external child + 1
        for child_index in range(max_external + 1):
            # grab the child at the index
            child = external.child(child_index)
            # create the p2sh-p2wpkh RedeemScript of [0, hash160]
            redeem_script = RedeemScript([0, child.hash160()])
            # hash160 of the RedeemScript is the key, RedeemScript is the value
            lookup[redeem_script.hash160()] = redeem_script
        # create the internal child (1)
        internal = self.child(1)
        # loop through to the maximum internal child + 1
        for child_index in range(max_internal + 1):
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
        return {
            **external.pubkey_lookup(max_external),
            **internal.pubkey_lookup(max_internal),
        }

    @classmethod
    def parse(cls, key, s, network=None):
        hd_key = cls.raw_parse(BytesIO(key[1:]))
        hd_key.__class__ = cls
        hd_key.add_raw_path_data(read_varstr(s), network=network)
        return hd_key

    @classmethod
    def from_hd_pub(cls, child_hd_pub, xfp_hex, path):
        hd_key = child_hd_pub
        hd_key.__class__ = cls
        hd_key.add_raw_path_data(
            raw_path=bytes.fromhex(xfp_hex) + serialize_binary_path(path),
            network=hd_key.network,
        )
        return hd_key

    @classmethod
    def from_hd_priv(cls, root_hd_priv, path):
        child_hd_pub = root_hd_priv.traverse(path).pub
        return cls.from_hd_pub(
            child_hd_pub=child_hd_pub,
            xfp_hex=root_hd_priv.fingerprint().hex(),
            path=path,
        )

    def serialize(self):
        return serialize_key_value(
            PSBT_GLOBAL_XPUB + self.raw_serialize(), self.raw_path
        )

    def is_ancestor(self, named_pubkey):
        return named_pubkey.raw_path.startswith(self.raw_path)

    def verify_descendent(self, named_pubkey):
        if not self.is_ancestor(named_pubkey):
            raise ValueError("path is not a descendent of this key")
        remainder = named_pubkey.raw_path[len(self.raw_path) :]
        current = self
        while len(remainder):
            child_index = little_endian_to_int(remainder[:4])
            current = current.child(child_index)
            remainder = remainder[4:]
        return current.point == named_pubkey


class PSBT:
    def __init__(
        self,
        tx_obj,
        psbt_ins,
        psbt_outs,
        hd_pubs=None,
        extra_map=None,
        network="mainnet",
    ):
        self.tx_obj = tx_obj
        self.psbt_ins = psbt_ins
        self.psbt_outs = psbt_outs
        self.hd_pubs = hd_pubs or {}
        self.extra_map = extra_map or {}
        self.network = network
        self.tx_obj.network = network
        self.validate()

    def validate(self):
        """Checks the PSBT for consistency"""
        if len(self.tx_obj.tx_ins) != len(self.psbt_ins):
            raise ValueError(
                "Number of psbt_ins in the transaction should match the psbt_ins array"
            )
        for i, psbt_in in enumerate(self.psbt_ins):
            # validate the input
            psbt_in.validate()
            tx_in = self.tx_obj.tx_ins[i]
            if tx_in.script_sig.commands:
                raise ValueError("ScriptSig for the tx should not be defined")
            # validate the ScriptSig
            if psbt_in.script_sig:
                tx_in.script_sig = psbt_in.script_sig
                tx_in.witness = psbt_in.witness
                if not self.tx_obj.verify_input(i):
                    raise ValueError(
                        "ScriptSig/Witness at input {} provided, but not valid".format(
                            i
                        )
                    )
                tx_in.script_sig = Script()
                tx_in.witness = Witness()
            # validate the signatures
            if psbt_in.sigs:
                for sec, sig in psbt_in.sigs.items():
                    point = S256Point.parse(sec)
                    signature = Signature.parse(sig[:-1])
                    if psbt_in.prev_out:
                        # segwit
                        if not self.tx_obj.check_sig_segwit(
                            i,
                            point,
                            signature,
                            psbt_in.redeem_script,
                            psbt_in.witness_script,
                        ):
                            raise ValueError(
                                "segwit signature provided does not validate"
                            )
                    elif psbt_in.prev_tx:
                        # legacy
                        if not self.tx_obj.check_sig_legacy(
                            i, point, signature, psbt_in.redeem_script
                        ):
                            raise ValueError(
                                "legacy signature provided does not validate {}".format(
                                    self
                                )
                            )
            # validate the NamedPublicKeys
            if psbt_in.named_pubs:
                for named_pub in psbt_in.named_pubs.values():
                    named_pub.network = self.network
                    for hd_pub in self.hd_pubs.values():
                        if hd_pub.is_ancestor(named_pub):
                            if not hd_pub.verify_descendent(named_pub):
                                raise ValueError(
                                    "public key {} does not derive from xpub {}".format(
                                        named_pub, hd_pub
                                    )
                                )
                            break
        if len(self.tx_obj.tx_outs) != len(self.psbt_outs):
            raise ValueError(
                "Number of psbt_outs in the transaction should match the psbt_outs array"
            )
        for psbt_out in self.psbt_outs:
            # validate output
            psbt_out.validate()
            # validate the NamedPublicKeys
            if psbt_out.named_pubs:
                for named_pub in psbt_out.named_pubs.values():
                    named_pub.network = self.network
                    for hd_pub in self.hd_pubs.values():
                        if hd_pub.is_ancestor(named_pub):
                            if not hd_pub.verify_descendent(named_pub):
                                raise ValueError(
                                    "public key {} does not derive from xpub {}".format(
                                        named_pub, hd_pub
                                    )
                                )
                            break
        return True

    def __repr__(self):
        return "Tx:\n{}\nPSBT XPUBS:\n{}\nPsbt_Ins:\n{}\nPsbt_Outs:\n{}\nExtra:{}\n".format(
            self.tx_obj, self.hd_pubs, self.psbt_ins, self.psbt_outs, self.extra_map
        )

    @classmethod
    def create(
        cls,
        tx_obj,
        validate=True,
        tx_lookup={},
        pubkey_lookup={},
        redeem_lookup={},
        witness_lookup={},
        hd_pubs={},
    ):
        """Create a PSBT from a transaction"""

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
        psbt_obj = cls(tx_obj, psbt_ins, psbt_outs)

        # append metadata
        if tx_lookup or pubkey_lookup:
            psbt_obj.update(
                tx_lookup=tx_lookup,
                pubkey_lookup=pubkey_lookup,
                redeem_lookup=redeem_lookup,
                witness_lookup=witness_lookup,
            )
        if hd_pubs:
            psbt_obj.hd_pubs = hd_pubs

        if validate:
            psbt_obj.validate()

        return psbt_obj

    def update(self, tx_lookup, pubkey_lookup, redeem_lookup={}, witness_lookup={}):
        # update each PSBTIn
        for psbt_in in self.psbt_ins:
            psbt_in.update(tx_lookup, pubkey_lookup, redeem_lookup, witness_lookup)
        # update each PSBTOut
        for psbt_out in self.psbt_outs:
            psbt_out.update(pubkey_lookup, redeem_lookup, witness_lookup)

    def sign(self, hd_priv):
        """Signs appropriate inputs with the hd private key provided"""
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
                    if psbt_in.use_segwit_signature():
                        sig = self.tx_obj.get_sig_segwit(
                            i,
                            private_key,
                            psbt_in.redeem_script,
                            psbt_in.witness_script,
                        )
                    else:
                        sig = self.tx_obj.get_sig_legacy(
                            i, private_key, psbt_in.redeem_script
                        )
                    # update the sigs dict of the PSBTIn object
                    psbt_in.sigs[private_key.point.sec()] = sig
                    signed = True
        return signed

    def sign_with_private_keys(self, private_keys):
        """Signs appropriate inputs with the private key provided"""
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
                    if psbt_in.use_segwit_signature():
                        sig = self.tx_obj.get_sig_segwit(
                            i,
                            private_key,
                            psbt_in.redeem_script,
                            psbt_in.witness_script,
                        )
                    else:
                        sig = self.tx_obj.get_sig_legacy(
                            i, private_key, psbt_in.redeem_script
                        )
                    # update the sigs dict of the PSBTIn object
                    psbt_in.sigs[private_key.point.sec()] = sig
                    signed = True
        # return whether we signed something
        return signed

    def combine(self, other):
        """combines information from another PSBT to this one"""
        # the tx_obj properties should be the same or raise a ValueError
        if self.tx_obj.hash() != other.tx_obj.hash():
            raise ValueError(
                "cannot combine PSBTs that refer to different transactions"
            )
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
        """Finalize the transaction by filling in the ScriptSig and Witness fields for each input"""
        # iterate through the inputs
        for psbt_in in self.psbt_ins:
            # finalize each input
            psbt_in.finalize()

    def final_tx(self):
        """Returns the broadcast-able transaction"""
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
            raise RuntimeError("transaction invalid")
        # return the now filled in transaction
        return tx_obj

    @classmethod
    def parse_base64(cls, b64, network=None):
        stream = BytesIO(base64_decode(b64))
        return cls.parse(stream, network=network)

    @classmethod
    def parse(cls, s, network=None):
        """Returns an instance of PSBT from a stream"""
        # prefix
        magic = s.read(4)
        if magic != PSBT_MAGIC:
            raise SyntaxError("Incorrect magic")
        separator = s.read(1)
        if separator != PSBT_SEPARATOR:
            raise SyntaxError("No separator")
        # global data
        tx_obj = None
        hd_pubs = {}
        extra_map = {}
        key = read_varstr(s)
        while key != b"":
            psbt_type = key[0:1]
            if psbt_type == PSBT_GLOBAL_UNSIGNED_TX:
                if len(key) != 1:
                    raise KeyError("Wrong length for the key")
                if tx_obj:
                    raise KeyError("Duplicate Key in parsing: {}".format(key.hex()))
                _ = read_varint(s)
                tx_obj = Tx.parse_legacy(s)
            elif psbt_type == PSBT_GLOBAL_XPUB:
                if len(key) != 79:
                    raise KeyError("Wrong length for the key")
                hd_pub = NamedHDPublicKey.parse(key, s, network=network)
                hd_pubs[hd_pub.raw_serialize()] = hd_pub
                if network is None:
                    network = hd_pub.network
                if hd_pub.network != network:
                    raise MixedNetwork("PSBT Mainnet/Testnet Mixing")
            else:
                if extra_map.get(key):
                    raise KeyError("Duplicate Key in parsing: {}".format(key.hex()))
                extra_map[key] = read_varstr(s)
            key = read_varstr(s)
        if not tx_obj:
            raise SyntaxError("transaction is required")
        # per input data
        psbt_ins = []
        for tx_in in tx_obj.tx_ins:
            psbt_in = PSBTIn.parse(s, tx_in, network=network)
            for named_pub in psbt_in.named_pubs.values():
                if network is None:
                    network = named_pub.network
                if named_pub.network != network:
                    raise MixedNetwork("PSBTIn Mainnet/Testnet Mixing")
            psbt_ins.append(psbt_in)
        # per output data
        psbt_outs = []
        for tx_out in tx_obj.tx_outs:
            psbt_out = PSBTOut.parse(s, tx_out, network=network)
            for named_pub in psbt_out.named_pubs.values():
                if network is None:
                    network = named_pub.network
                if named_pub.network != network:
                    raise MixedNetwork("PSBTOut Mainnet/Testnet Mixing")
            psbt_outs.append(psbt_out)
        return cls(tx_obj, psbt_ins, psbt_outs, hd_pubs, extra_map, network)

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

    def replace_root_xfps(self, xfp_map):
        """
        Can be used for extra privacy to blind an XFP not relevant to that signer.

        Supply an xfp_map of the following form:
        {
            # to_hide: to_replace
            "deadbeef": "00000000",
            "ab01ab01": "ffffffff",
        }
        """
        for xfp_to_hide, xfp_to_replace in xfp_map.items():
            was_replaced = False

            # replace from inputs
            for psbt_in in self.psbt_ins:
                for named_pub in psbt_in.named_pubs.values():
                    if named_pub.root_fingerprint.hex() == xfp_to_hide:
                        named_pub.replace_xfp(new_xfp=xfp_to_replace)
                        was_replaced = True

            # replace from outputs
            for psbt_out in self.psbt_outs:
                for named_pub in psbt_out.named_pubs.values():
                    if named_pub.root_fingerprint.hex() == xfp_to_hide:
                        named_pub.replace_xfp(new_xfp=xfp_to_replace)
                        was_replaced = True

            if not was_replaced:
                raise ValueError(f"xfp_hex {xfp_to_hide} not found in psbt")

    def _describe_basic_p2wsh_inputs(self, hdpubkey_map):

        # These will be used for all inputs and change outputs
        inputs_quorum_m, inputs_quorum_n = None, None

        # Gather TX info and validate
        inputs_desc = []
        total_input_sats = 0

        root_paths_for_signing = defaultdict(set)
        for cnt, psbt_in in enumerate(self.psbt_ins):
            psbt_in.validate()

            if type(psbt_in.witness_script) != WitnessScript:
                # TODO: add support for legacy TXs?
                raise SuspiciousTransaction(
                    f"Input #{cnt} does not contain a witness script. "
                    "This tool can only sign p2wsh transactions."
                )

            # Be sure all xpubs are properly accounted for
            if len(hdpubkey_map) != len(psbt_in.named_pubs):
                # TODO: doesn't handle case where the same xfp is >1 signers
                raise SuspiciousTransaction(
                    f"{len(hdpubkey_map)} xpubs supplied != {len(psbt_in.named_pubs)} named_pubs in PSBT input."
                )

            input_quorum_m, input_quorum_n = psbt_in.witness_script.get_quorum()
            if inputs_quorum_m is None:
                inputs_quorum_m = input_quorum_m
            else:
                if inputs_quorum_m != input_quorum_m:
                    raise SuspiciousTransaction(
                        f"Previous input(s) set a quorum threshold of {inputs_quorum_m}, but this transaction is {input_quorum_m}"
                    )

            if inputs_quorum_n is None:
                inputs_quorum_n = input_quorum_n
                if inputs_quorum_n != len(hdpubkey_map):
                    raise SuspiciousTransaction(
                        f"Transaction has {len(hdpubkey_map)} pubkeys but we are expecting {input_quorum_n}"
                    )
            else:
                if inputs_quorum_n != input_quorum_n:
                    raise SuspiciousTransaction(
                        f"Previous input(s) set a max quorum of threshold of {inputs_quorum_n}, but this transaction is {input_quorum_n}"
                    )

            bip32_derivs = []
            for named_pub in psbt_in.named_pubs.values():
                # Match to corresponding xpub to validate that this xpub is a participant in this input
                xfp = named_pub.root_fingerprint.hex()

                try:
                    hdpub = hdpubkey_map[xfp]
                except KeyError:
                    raise SuspiciousTransaction(
                        f"Root fingerprint {xfp} for input #{cnt} not in the hdpubkey_map you supplied"
                    )

                trimmed_path = ltrim_path(named_pub.root_path, depth=hdpub.depth)
                if hdpub.traverse(trimmed_path).sec() != named_pub.sec():
                    raise SuspiciousTransaction(
                        f"xpub {hdpub} with path {named_pub.root_path} does not appear to be part of input # {cnt}"
                    )

                root_paths_for_signing[xfp].add(named_pub.root_path)

                # this is very similar to what bitcoin-core's decodepsbt returns
                bip32_derivs.append(
                    {
                        "pubkey": named_pub.sec().hex(),
                        "master_fingerprint": xfp,
                        "path": named_pub.root_path,
                        "xpub": hdpub.xpub(),
                    }
                )

            # BIP67 sort order
            bip32_derivs = sorted(bip32_derivs, key=lambda k: k["pubkey"])

            input_sats = psbt_in.tx_in.value()
            total_input_sats += input_sats

            input_desc = {
                "quorum": f"{input_quorum_m}-of-{input_quorum_n}",
                "bip32_derivs": bip32_derivs,
                "prev_txhash": psbt_in.tx_in.prev_tx.hex(),
                "prev_idx": psbt_in.tx_in.prev_index,
                "n_sequence": psbt_in.tx_in.sequence,
                "sats": input_sats,
                "addr": psbt_in.witness_script.address(network=self.network),
                # if adding support for p2sh in the future, the address would be: psbt_in.witness_script.p2sh_address(network=self.network),
                "witness_script": str(psbt_in.witness_script),
            }
            inputs_desc.append(input_desc)

        if not root_paths_for_signing:
            raise SuspiciousTransaction(
                "No `root_paths_for_signing` with `hdpubkey_map` {hdpubkey_map} in PSBT:\n{self}"
            )

        return {
            "inputs_quorum_m": inputs_quorum_m,
            "inputs_quorum_n": inputs_quorum_n,
            "inputs_desc": inputs_desc,
            "root_paths_for_signing": root_paths_for_signing,
            "total_input_sats": total_input_sats,
        }

    def _describe_basic_p2wsh_outputs(
        self,
        expected_quorum_m,
        expected_quorum_n,
        hdpubkey_map={},
    ):

        # intialize variable we'll loop through to set
        outputs_desc = []
        spend_addr, spend_sats = "", 0
        change_addr, change_sats = "", 0
        total_sats = 0
        spends_cnt = 0
        for cnt, psbt_out in enumerate(self.psbt_outs):
            psbt_out.validate()

            output_desc = {
                "sats": psbt_out.tx_out.amount,
                "addr": psbt_out.tx_out.script_pubkey.address(network=self.network),
                "addr_type": psbt_out.tx_out.script_pubkey.__class__.__name__.rstrip(
                    "ScriptPubKey"
                ),
            }
            total_sats += output_desc["sats"]

            if psbt_out.named_pubs:
                # Confirm below that this is correct (throw error otherwise)
                output_desc["is_change"] = True

                # FIXME: Confirm this works with a fake change test case
                output_quorum_m, output_quorum_n = psbt_out.witness_script.get_quorum()
                if expected_quorum_m != output_quorum_m:
                    raise SuspiciousTransaction(
                        f"Previous output(s) set a max quorum of threshold of {expected_quorum_m}, but this transaction is {output_quorum_m}"
                    )
                if expected_quorum_n != output_quorum_n:
                    raise SuspiciousTransaction(
                        f"Previous input(s) set a max cosigners of {expected_quorum_n}, but this transaction is {output_quorum_n}"
                    )

                # Be sure all xpubs are properly acocunted for
                if output_quorum_n != len(psbt_out.named_pubs):
                    # TODO: doesn't handle case where the same xfp is >1 signers (surprisngly complex)
                    raise SuspiciousTransaction(
                        f"{len(hdpubkey_map)} xpubs supplied != {len(psbt_out.named_pubs)} named_pubs in PSBT change output."
                        "You may be able to get this wallet to cosign a sweep transaction (1-output) instead."
                    )

                bip32_derivs = []
                for named_pub in psbt_out.named_pubs.values():
                    # Match to corresponding xpub to validate that this xpub is a participant in this change output
                    xfp = named_pub.root_fingerprint.hex()

                    try:
                        hdpub = hdpubkey_map[xfp]
                    except KeyError:
                        raise SuspiciousTransaction(
                            f"Root fingerprint {xfp} for output #{cnt} not in the hdpubkey_map you supplied"
                            "Do a sweep transaction (1-output) if you want this wallet to cosign."
                        )

                    trimmed_path = ltrim_path(named_pub.root_path, depth=hdpub.depth)
                    if hdpub.traverse(trimmed_path).sec() != named_pub.sec():
                        raise SuspiciousTransaction(
                            f"xpub {hdpub} with path {named_pub.root_path} does not appear to be part of output # {cnt}"
                            "You may be able to get this wallet to cosign a sweep transaction (1-output) instead."
                        )

                    # this is very similar to what bitcoin-core's decodepsbt returns
                    bip32_derivs.append(
                        {
                            "pubkey": named_pub.sec().hex(),
                            "master_fingerprint": xfp,
                            "path": named_pub.root_path,
                            "xpub": hdpub.xpub(),
                        }
                    )

                # BIP67 sort order
                bip32_derivs = sorted(bip32_derivs, key=lambda k: k["pubkey"])

                # Confirm there aren't >1 change ouputs
                # (this is technically allowed but too sketchy to support)
                if change_sats or change_addr:
                    raise SuspiciousTransaction(
                        f"Cannot have >1 change output.\n{outputs_desc}"
                    )
                change_addr = output_desc["addr"]
                change_sats = output_desc["sats"]

                output_desc["witness_script"] = str(psbt_out.witness_script)

            else:
                output_desc["is_change"] = False
                spends_cnt += 1
                spend_sats += output_desc["sats"]

                if spends_cnt > 1:
                    # There is no concept of a single spend addr/amount for batch spends
                    # Caller must interpret the batch spend from the returned outputs_desc
                    spend_addr = ""
                else:
                    spend_addr = output_desc["addr"]

            outputs_desc.append(output_desc)

        return {
            "total_sats": total_sats,
            "outputs_desc": outputs_desc,
            "change_addr": change_addr,
            "change_sats": change_sats,
            "spend_addr": spend_addr,
            "spend_sats": spend_sats,
            "is_batch_tx": spends_cnt > 1,
        }

    def describe_basic_p2wsh_multisig_tx(self, hdpubkey_map={}):
        """
        Describe a typical p2wsh multisig transaction in a human-readable way for manual verification before signing.

        This tool supports transactions with the following constraints:
        * ALL inputs have the exact same multisig wallet (quorum + xpubs)
        * All outputs are either spend or proven to be change. For UX reasons, there can not be >1 change address.

        A SuspiciousTransaction Exception does not strictly mean there is a problem with the transaction, it is likely just too complex for simple summary.

        Due to the nature of how PSBT works, if your PSBT is slimmed down (doesn't contain xpubs AND prev TX hexes), you must supply a `hdpubkey_map` for ALL n xpubs:
          {
            'xfphex1': HDPublicKey1,
            'xfphex2': HDPublicKey2,
          }
        These HDPublicKey's will be traversed according to the paths given in the PSBT.

        TODOS:
          - add helper method that accepts an output descriptor, converts it into an hdpubkey_map, and then calls this method
          - add support for p2sh and other script types
        """

        self.validate()

        tx_fee_sats = self.tx_obj.fee()

        if not hdpubkey_map:
            if not self.hd_pubs:
                raise ValueError(
                    "Cannot describe multisig PSBT without `hd_pubs` nor `hdpubkey_map`"
                )
            # build hdpubkey_map from PSBT's hdpubs
            hdpubkey_map = {}
            for hdpubkey in self.hd_pubs.values():
                hdpubkey_map[hdpubkey.root_fingerprint.hex()] = HDPublicKey.parse(
                    hdpubkey.xpub()
                )

        inputs_described = self._describe_basic_p2wsh_inputs(hdpubkey_map=hdpubkey_map)
        total_input_sats = inputs_described["total_input_sats"]

        outputs_described = self._describe_basic_p2wsh_outputs(
            hdpubkey_map=hdpubkey_map,
            # Tool requires m-of-n be same for inputs as outputs
            expected_quorum_m=inputs_described["inputs_quorum_m"],
            expected_quorum_n=inputs_described["inputs_quorum_n"],
        )
        is_batch_tx = outputs_described["is_batch_tx"]
        total_output_sats = outputs_described["total_sats"]
        spend_sats = outputs_described["spend_sats"]
        spend_addr = outputs_described["spend_addr"]

        tx_fee_rounded = round(tx_fee_sats / total_input_sats * 100, 2)
        # comma separating satoshis for better display
        if is_batch_tx:
            spend_breakdown = "\n".join(
                [
                    f"{x['addr']}: {x['sats']:,} sats"
                    for x in outputs_described["outputs_desc"]
                    if not x["is_change"]
                ]
            )
            tx_summary_text = f"Batch PSBT sends {spend_sats:,} sats with a fee of {tx_fee_sats:,} sats ({tx_fee_rounded}% of spend). Batch spend breakdown:\n{spend_breakdown}"
        else:
            tx_summary_text = f"PSBT sends {spend_sats:,} sats to {spend_addr} with a fee of {tx_fee_sats:,} sats ({tx_fee_rounded}% of spend)"

        return {
            # TX level:
            "txid": self.tx_obj.id(),
            "tx_summary_text": tx_summary_text,
            "locktime": self.tx_obj.locktime,
            "version": self.tx_obj.version,
            "network": self.network,
            "tx_fee_sats": tx_fee_sats,
            "total_input_sats": total_input_sats,
            "total_output_sats": total_output_sats,
            "spend_sats": spend_sats,
            "change_addr": outputs_described["change_addr"],
            "change_sats": outputs_described["change_sats"],
            "spend_addr": spend_addr,
            "is_batch_tx": is_batch_tx,
            # Input/output level
            "inputs_desc": inputs_described["inputs_desc"],
            "outputs_desc": outputs_described["outputs_desc"],
            "root_paths": inputs_described["root_paths_for_signing"],
        }

    def describe_p2pkh_sweep(self, privkey_obj=None):
        """
        Describe a single key p2pkh sweep transaction in a human-readable way for manual verification before signing.
        This would typically be used to sweep an old paper wallet.

        This tool supports transactions with the following constraints:
        * ALL inputs must be p2pkh and have the same private key. This does not currently support p2wpkh (TODO!).
        * There can only be 1 output (sweep transaction). Single sig is dangerous, this should only be used to migrate away.

        Note that for p2pkh we cannot directly verify the transaction fee, as the input amounts are not explicitly part of what we are prompted to sign.
        This "bug" was fixed with segwit.
        """
        self.validate()

        tx_fee_sats = self.tx_obj.fee()

        if privkey_obj:
            h160s = {
                privkey_obj.point.hash160(compressed=True),
                privkey_obj.point.hash160(compressed=False),
            }
        else:
            h160s = {}

        # Gather TX info and validate
        inputs_desc = []
        for cnt, psbt_in in enumerate(self.psbt_ins):
            psbt_in.validate()

            if psbt_in.witness_script or psbt_in.witness:
                raise SuspiciousTransaction(f"Input #{cnt} has witness")

            if psbt_in.redeem_script:
                raise SuspiciousTransaction(f"Input #{cnt} has redeem_script")

            if psbt_in.tx_in.script_pubkey().is_p2pkh() is not True:
                raise SuspiciousTransaction(f"Input #{cnt} is not p2pkh")

            # Optional check that this is the pubkey whose privkey we intend to sign with
            if h160s and psbt_in.tx_in.script_pubkey().hash160() not in h160s:
                raise SuspiciousTransaction(
                    f"Input #{cnt} is encumbered by another public key. {psbt_in.tx_in.script_pubkey().hash160()} not in {h160s}"
                )

            psbt_prev_tx_out = psbt_in.prev_tx.tx_outs[psbt_in.tx_in.prev_index]
            input_desc = {
                "prev_txhash": psbt_in.tx_in.prev_tx.hex(),
                "prev_idx": psbt_in.tx_in.prev_index,
                "n_sequence": psbt_in.tx_in.sequence,
                "sats": psbt_prev_tx_out.amount,
                "addr": psbt_prev_tx_out.script_pubkey.address(network=self.network),
            }
            inputs_desc.append(input_desc)

        total_input_sats = sum([x["sats"] for x in inputs_desc])

        if len(self.tx_obj.tx_outs) != len(self.psbt_outs):
            raise SuspiciousTransaction("Invalid PSBT: output mismatch")

        if len(self.psbt_outs) != 1:
            raise SuspiciousTransaction(
                f"PSBT with {len(self.psbt_outs)} outputs is incompatible with this script: this script only supports sweep transactions (1 output)"
            )

        psbt_out = self.psbt_outs[0]  # this script only accepts 1 output
        psbt_out.validate()

        spend_addr = psbt_out.tx_out.script_pubkey.address(network=self.network)
        output_spend_sats = psbt_out.tx_out.amount
        output_addr_type = psbt_out.tx_out.script_pubkey.__class__.__name__.rstrip(
            "ScriptPubKey"
        )
        outputs_desc = [
            {
                "sats": output_spend_sats,
                "addr": spend_addr,
                "addr_type": output_addr_type,
            }
        ]

        # comma separating satoshis for better display
        tx_summary_text = f"PSBT sends {output_spend_sats:,} sats to {spend_addr} with an UNVERIFIED fee of {tx_fee_sats:,} sats ({round(tx_fee_sats / total_input_sats * 100, 2)}% of spend)"

        return {
            # TX level:
            "tx_summary_text": tx_summary_text,
            "tx_size_bytes": len(
                self.tx_obj.serialize()
            ),  # no need to worry about vBytes because this is p2pkh
            "is_rbf_able": self.tx_obj.is_rbf_able(),
            "locktime": self.tx_obj.locktime,
            "version": self.tx_obj.version,
            "network": self.network,
            "tx_fee_sats": tx_fee_sats,
            "total_input_sats": total_input_sats,
            "output_spend_sats": output_spend_sats,
            "spend_addr": spend_addr,
            # Input/output level
            "inputs_desc": inputs_desc,
            "outputs_desc": outputs_desc,
        }


class PSBTIn:
    def __init__(
        self,
        tx_in,
        prev_tx=None,
        prev_out=None,
        sigs=None,
        hash_type=None,
        redeem_script=None,
        witness_script=None,
        named_pubs=None,
        script_sig=None,
        witness=None,
        extra_map=None,
    ):
        self.tx_in = tx_in
        self.prev_tx = prev_tx
        self.prev_out = prev_out
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
        """Checks the PSBTIn for consistency"""
        script_pubkey = self.script_pubkey()
        if self.prev_tx:
            if self.tx_in.prev_tx != self.prev_tx.hash():
                raise ValueError(
                    "previous transaction specified, but does not match the input tx"
                )
            if self.tx_in.prev_index >= len(self.prev_tx.tx_outs):
                raise ValueError("input refers to an output index that does not exist")
        if self.prev_out:
            # witness input
            if not (
                script_pubkey.is_p2sh()
                or script_pubkey.is_p2wsh()
                or script_pubkey.is_p2wpkh()
            ):
                raise ValueError("Witness UTXO provided for non-witness input")
            if self.witness_script:  # p2wsh or p2sh-p2wsh
                if not script_pubkey.is_p2wsh() and not (
                    self.redeem_script and self.redeem_script.is_p2wsh()
                ):
                    raise ValueError(
                        "WitnessScript provided for non-p2wsh ScriptPubKey"
                    )
                if self.redeem_script:
                    h160 = script_pubkey.commands[1]
                    if self.redeem_script.hash160() != h160:
                        raise ValueError(
                            "RedeemScript hash160 and ScriptPubKey hash160 do not match"
                        )
                    s256 = self.redeem_script.commands[1]
                else:
                    s256 = self.prev_out.script_pubkey.commands[1]
                if self.witness_script.sha256() != s256:
                    raise ValueError(
                        "WitnessScript sha256 and output sha256 do not match"
                    )
                for sec in self.named_pubs.keys():
                    try:
                        # this will raise a ValueError if it's not in there
                        self.witness_script.commands.index(sec)
                    except ValueError:
                        raise ValueError(
                            "pubkey is not in WitnessScript: {}".format(self)
                        )
            elif script_pubkey.is_p2wpkh() or (
                self.redeem_script and self.redeem_script.is_p2wpkh()
            ):
                if len(self.named_pubs) > 1:
                    raise ValueError("too many pubkeys in p2wpkh or p2sh-p2wpkh")
                elif len(self.named_pubs) == 1:
                    named_pub = list(self.named_pubs.values())[0]
                    if script_pubkey.commands[1] != named_pub.hash160():
                        raise ValueError(
                            "pubkey {} does not match the hash160".format(
                                named_pub.sec().hex()
                            )
                        )
        else:
            # non-witness input
            if self.redeem_script:
                if not script_pubkey.is_p2sh():
                    raise ValueError("RedeemScript defined for non-p2sh ScriptPubKey")
                # non-witness p2sh
                if self.redeem_script.is_p2wsh() or self.redeem_script.is_p2wpkh():
                    raise ValueError("Non-witness UTXO provided for witness input")
                h160 = script_pubkey.commands[1]
                if self.redeem_script.hash160() != h160:
                    raise ValueError(
                        "RedeemScript hash160 and ScriptPubKey hash160 do not match"
                    )
                for sec in self.named_pubs.keys():
                    try:
                        # this will raise a ValueError if it's not in there
                        self.redeem_script.commands.index(sec)
                    except ValueError:
                        raise ValueError(
                            "pubkey is not in RedeemScript {}".format(self)
                        )
            elif script_pubkey and script_pubkey.is_p2pkh():
                if len(self.named_pubs) > 1:
                    raise ValueError("too many pubkeys in p2pkh")
                elif len(self.named_pubs) == 1:
                    named_pub = list(self.named_pubs.values())[0]
                    if script_pubkey.commands[2] != named_pub.hash160():
                        raise ValueError(
                            "pubkey {} does not match the hash160".format(
                                named_pub.sec().hex()
                            )
                        )

    def __repr__(self):
        return "TxIn:\n{}\nPrev Tx:\n{}\nPrev Output\n{}\nSigs:\n{}\nRedeemScript:\n{}\nWitnessScript:\n{}\nPSBT Pubs:\n{}\nScriptSig:\n{}\nWitness:\n{}\n".format(
            self.tx_in,
            self.prev_tx,
            self.prev_out,
            self.sigs,
            self.redeem_script,
            self.witness_script,
            self.named_pubs,
            self.script_sig,
            self.witness,
        )

    @classmethod
    def parse(cls, s, tx_in, network=None):
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
        while key != b"":
            psbt_type = key[0:1]
            if psbt_type == PSBT_IN_NON_WITNESS_UTXO:
                if len(key) != 1:
                    raise KeyError("Wrong length for the key")
                if prev_tx:
                    raise KeyError("Duplicate Key in parsing: {}".format(key.hex()))
                tx_len = read_varint(s)
                prev_tx = Tx.parse(s)
                if len(prev_tx.serialize()) != tx_len:
                    raise IOError("tx length does not match")
                tx_in._value = prev_tx.tx_outs[tx_in.prev_index].amount
                tx_in._script_pubkey = prev_tx.tx_outs[tx_in.prev_index].script_pubkey
            elif psbt_type == PSBT_IN_WITNESS_UTXO:
                tx_out_len = read_varint(s)
                if len(key) != 1:
                    raise KeyError("Wrong length for the key")
                if prev_out:
                    raise KeyError("Duplicate Key in parsing: {}".format(key.hex()))
                prev_out = TxOut.parse(s)
                if len(prev_out.serialize()) != tx_out_len:
                    raise ValueError("tx out length does not match")
                tx_in._value = prev_out.amount
                tx_in._script_pubkey = prev_out.script_pubkey
            elif psbt_type == PSBT_IN_PARTIAL_SIG:
                if sigs.get(key[1:]):
                    raise KeyError("Duplicate Key in parsing: {}".format(key.hex()))
                sigs[key[1:]] = read_varstr(s)
            elif psbt_type == PSBT_IN_SIGHASH_TYPE:
                if len(key) != 1:
                    raise KeyError("Wrong length for the key")
                if hash_type:
                    raise KeyError("Duplicate Key in parsing: {}".format(key.hex()))
                hash_type = little_endian_to_int(read_varstr(s))
            elif psbt_type == PSBT_IN_REDEEM_SCRIPT:
                if len(key) != 1:
                    raise KeyError("Wrong length for the key")
                if redeem_script:
                    raise KeyError("Duplicate Key in parsing: {}".format(key.hex()))
                redeem_script = RedeemScript.parse(s)
            elif psbt_type == PSBT_IN_WITNESS_SCRIPT:
                if len(key) != 1:
                    raise KeyError("Wrong length for the key")
                if witness_script:
                    raise KeyError("Duplicate Key in parsing: {}".format(key.hex()))
                witness_script = WitnessScript.parse(s)
            elif psbt_type == PSBT_IN_BIP32_DERIVATION:
                if len(key) != 34:
                    raise KeyError("Wrong length for the key")
                named_pub = NamedPublicKey.parse(key, s, network=network)
                named_pubs[named_pub.sec()] = named_pub
            elif psbt_type == PSBT_IN_FINAL_SCRIPTSIG:
                if len(key) != 1:
                    raise KeyError("Wrong length for the key")
                if script_sig:
                    raise KeyError("Duplicate Key in parsing: {}".format(key.hex()))
                script_sig = Script.parse(s)
            elif psbt_type == PSBT_IN_FINAL_SCRIPTWITNESS:
                if len(key) != 1:
                    raise KeyError("Wrong length for the key")
                if witness:
                    raise KeyError("Duplicate Key in parsing: {}".format(key.hex()))
                _ = read_varint(s)
                witness = Witness.parse(s)
            else:
                if extra_map.get(key):
                    raise KeyError("Duplicate Key in parsing: {}".format(key.hex()))
                extra_map[key] = read_varstr(s)
            key = read_varstr(s)
        return cls(
            tx_in,
            prev_tx,
            prev_out,
            sigs,
            hash_type,
            redeem_script,
            witness_script,
            named_pubs,
            script_sig,
            witness,
            extra_map,
        )

    def serialize(self):
        result = b""
        if self.prev_tx:
            result += serialize_key_value(
                PSBT_IN_NON_WITNESS_UTXO, self.prev_tx.serialize()
            )
        elif self.prev_out:
            result += serialize_key_value(
                PSBT_IN_WITNESS_UTXO, self.prev_out.serialize()
            )
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
            result += serialize_key_value(
                PSBT_IN_SIGHASH_TYPE, int_to_little_endian(self.hash_type, 4)
            )
        if self.redeem_script:
            result += serialize_key_value(
                PSBT_IN_REDEEM_SCRIPT, self.redeem_script.raw_serialize()
            )
        if self.witness_script:
            result += serialize_key_value(
                PSBT_IN_WITNESS_SCRIPT, self.witness_script.raw_serialize()
            )
        for sec in sorted(self.named_pubs.keys()):
            named_pub = self.named_pubs[sec]
            result += named_pub.serialize(PSBT_IN_BIP32_DERIVATION)
        if self.script_sig:
            result += serialize_key_value(
                PSBT_IN_FINAL_SCRIPTSIG, self.script_sig.raw_serialize()
            )
        if self.witness:
            result += serialize_key_value(
                PSBT_IN_FINAL_SCRIPTWITNESS, self.witness.serialize()
            )
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

    def use_segwit_signature(self):
        # https://github.com/buidl-bitcoin/buidl-python/issues/23
        if self.witness_script or self.witness:
            return True
        if self.redeem_script and self.redeem_script.is_witness_script():
            return True
        if self.script_pubkey() and self.script_pubkey().is_witness_script():
            return True
        return False

    def update(self, tx_lookup, pubkey_lookup, redeem_lookup, witness_lookup):
        """Updates the input with NamedPublicKeys, RedeemScript or WitnessScript that
        correspond"""
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
            self.redeem_script = self.redeem_script or redeem_lookup.get(
                script_pubkey.commands[1]
            )
            # if there's no RedeemScript, we can't do any more updating, so return
            if not self.redeem_script:
                return
        # Exercise 2: if we have p2wpkh or p2sh-p2wpkh see if we have the appropriate NamedPublicKey
        if script_pubkey.is_p2wpkh() or (
            self.redeem_script and self.redeem_script.is_p2wpkh()
        ):
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
        elif script_pubkey.is_p2wsh() or (
            self.redeem_script and self.redeem_script.is_p2wsh()
        ):
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
            raise ValueError(
                "cannot update a transaction because it is not p2pkh, p2sh, p2wpkh or p2wsh: {}".format(
                    script_pubkey
                )
            )

    def combine(self, other):
        """Combines two PSBTIn objects into self"""
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
        """Removes all sigs/named pubs/RedeemScripts/WitnessScripts and
        sets the script_sig and witness fields"""
        # get the ScriptPubKey for this input
        script_pubkey = self.script_pubkey()
        # if the ScriptPubKey is p2sh
        if script_pubkey.is_p2sh():
            # make sure there's a RedeemScript
            if not self.redeem_script:
                raise RuntimeError("Cannot finalize p2sh without a RedeemScript")
        # Exercise 6: if p2wpkh or p2sh-p2wpkh
        if script_pubkey.is_p2wpkh() or (
            self.redeem_script and self.redeem_script.is_p2wpkh()
        ):
            # check to see that we have exactly 1 signature
            if len(self.sigs) != 1:
                raise RuntimeError(
                    "p2wpkh or p2sh-p2wpkh should have exactly 1 signature"
                )
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
        elif script_pubkey.is_p2wsh() or (
            self.redeem_script and self.redeem_script.is_p2wsh()
        ):
            # make sure there's a WitnessScript
            if not self.witness_script:
                raise RuntimeError(
                    "Cannot finalize p2wsh or p2sh-p2wsh without a WitnessScript"
                )
            # convert the first command to a number (required # of sigs)
            num_sigs = op_code_to_number(self.witness_script.commands[0])
            # make sure we have at least the number of sigs required
            if len(self.sigs) < num_sigs:
                raise RuntimeError(
                    "Cannot finalize p2wsh or p2sh-p2wsh because {} sigs were provided where {} were needed".format(
                        len(self.sigs), num_sigs
                    )
                )
            # create a list of items for the Witness. Start with b'\x00' for the
            #  OP_CHECKMULTISIG off-by-one error
            witness_items = [b"\x00"]
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
                raise RuntimeError("Not enough signatures provided for p2sh-p2wsh")
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
                raise RuntimeError(
                    "Cannot finalize p2sh because {} sigs were provided where {} were needed".format(
                        len(self.sigs), num_sigs
                    )
                )
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
                raise RuntimeError("Not enough signatures provided for p2wsh")
            # add the raw redeem script as the last command for p2sh execution
            script_sig_commands.append(self.redeem_script.raw_serialize())
            # change the ScriptSig to be a Script with the commands we've gathered
            self.script_sig = Script(script_sig_commands)
        elif script_pubkey.is_p2pkh():
            # check to see that we have exactly 1 signature
            if len(self.sigs) != 1:
                raise RuntimeError("P2pkh requires exactly 1 signature")
            # the key of the sigs dict is the compressed SEC pubkey
            sec = list(self.sigs.keys())[0]
            # the value of the sigs dict is the signature
            sig = list(self.sigs.values())[0]
            # set the ScriptSig, which is Script([sig, sec])
            self.script_sig = Script([sig, sec])
        else:
            raise ValueError(
                "Cannot finalize this ScriptPubKey: {}".format(script_pubkey)
            )
        # reset sigs, hash_type, redeem_script, witness_script and named_pubs to be empty
        self.sigs = {}
        self.hash_type = None
        self.redeem_script = None
        self.witness_script = None
        self.named_pubs = {}


class PSBTOut:
    def __init__(
        self,
        tx_out,
        redeem_script=None,
        witness_script=None,
        named_pubs=None,
        extra_map=None,
    ):
        self.tx_out = tx_out
        self.redeem_script = redeem_script
        self.witness_script = witness_script
        self.named_pubs = named_pubs or {}
        self.extra_map = extra_map or {}
        self.validate()

    def validate(self):
        """Checks the PSBTOut for consistency"""
        script_pubkey = self.tx_out.script_pubkey
        if script_pubkey.is_p2pkh():
            if self.redeem_script:
                raise KeyError("RedeemScript included in p2pkh output")
            if self.witness_script:
                raise KeyError("WitnessScript included in p2pkh output")
            if len(self.named_pubs) > 1:
                raise ValueError("too many pubkeys in p2pkh")
            elif len(self.named_pubs) == 1:
                named_pub = list(self.named_pubs.values())[0]
                if script_pubkey.commands[2] != named_pub.hash160():
                    raise ValueError(
                        "pubkey {} does not match the hash160".format(
                            named_pub.sec().hex()
                        )
                    )
        elif script_pubkey.is_p2wpkh():
            if self.redeem_script:
                raise KeyError("RedeemScript included in p2wpkh output")
            if self.witness_script:
                raise KeyError("WitnessScript included in p2wpkh output")
            if len(self.named_pubs) > 1:
                raise ValueError("too many pubkeys in p2wpkh")
            elif len(self.named_pubs) == 1:
                named_pub = list(self.named_pubs.values())[0]
                if script_pubkey.commands[1] != named_pub.hash160():
                    raise ValueError(
                        "pubkey {} does not match the hash160".format(
                            named_pub.sec().hex()
                        )
                    )
        elif self.witness_script:
            if self.redeem_script:
                h160 = script_pubkey.commands[1]
                if self.redeem_script.hash160() != h160:
                    raise ValueError(
                        "RedeemScript hash160 and ScriptPubKey hash160 do not match"
                    )
                s256 = self.redeem_script.commands[1]
            else:
                s256 = script_pubkey.commands[1]
            if self.witness_script.sha256() != s256:
                raise ValueError(
                    "WitnessScript sha256 and output sha256 do not match {} {}".format(
                        self, self.witness_script.sha256().hex()
                    )
                )
            for sec in self.named_pubs.keys():
                try:
                    # this will raise a ValueError if it's not in there
                    self.witness_script.commands.index(sec)
                except ValueError:
                    raise ValueError("pubkey is not in WitnessScript {}".format(self))
        elif self.redeem_script:
            for sec in self.named_pubs.keys():
                try:
                    # this will raise a ValueError if it's not in there
                    self.redeem_script.commands.index(sec)
                except ValueError:
                    raise ValueError("pubkey is not in RedeemScript {}".format(self))

    def __repr__(self):
        return (
            "TxOut:\n{}\nRedeemScript:\n{}\nWitnessScript\n{}\nPSBT Pubs:\n{}\n".format(
                self.tx_out, self.redeem_script, self.witness_script, self.named_pubs
            )
        )

    @classmethod
    def parse(cls, s, tx_out, network=None):
        redeem_script = None
        witness_script = None
        named_pubs = {}
        extra_map = {}
        key = read_varstr(s)
        while key != b"":
            psbt_type = key[0:1]
            if psbt_type == PSBT_OUT_REDEEM_SCRIPT:
                if len(key) != 1:
                    raise KeyError("Wrong length for the key")
                if redeem_script:
                    raise KeyError("Duplicate Key in parsing: {}".format(key.hex()))
                redeem_script = RedeemScript.parse(s)
            elif psbt_type == PSBT_OUT_WITNESS_SCRIPT:
                if len(key) != 1:
                    raise KeyError("Wrong length for the key")
                if witness_script:
                    raise KeyError("Duplicate Key in parsing: {}".format(key.hex()))
                witness_script = WitnessScript.parse(s)
            elif psbt_type == PSBT_OUT_BIP32_DERIVATION:
                if len(key) != 34:
                    raise KeyError("Wrong length for the key")
                named_pub = NamedPublicKey.parse(key, s, network=network)
                named_pubs[named_pub.sec()] = named_pub
            else:
                if extra_map.get(key):
                    raise KeyError("Duplicate Key in parsing: {}".format(key.hex()))
                extra_map[key] = read_varstr(s)
            key = read_varstr(s)
        return cls(tx_out, redeem_script, witness_script, named_pubs, extra_map)

    def serialize(self):
        result = b""
        if self.redeem_script:
            result += serialize_key_value(
                PSBT_OUT_REDEEM_SCRIPT, self.redeem_script.raw_serialize()
            )
        if self.witness_script:
            result += serialize_key_value(
                PSBT_OUT_WITNESS_SCRIPT, self.witness_script.raw_serialize()
            )
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
        """Updates the output with NamedPublicKeys, RedeemScript or WitnessScript that
        correspond"""
        # get the ScriptPubKey
        script_pubkey = self.tx_out.script_pubkey
        # if the ScriptPubKey is p2sh, check for a RedeemScript
        if script_pubkey.is_p2sh():
            self.redeem_script = redeem_lookup.get(script_pubkey.commands[1])
            # if no RedeemScript exists, we can't update, so return
            if not self.redeem_script:
                return
        # Exercise 2: if p2wpkh or p2sh-p2wpkh
        if script_pubkey.is_p2wpkh() or (
            self.redeem_script and self.redeem_script.is_p2wpkh()
        ):
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
        elif script_pubkey.is_p2wsh() or (
            self.redeem_script and self.redeem_script.is_p2wsh()
        ):
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
        """Combines two PSBTOuts to self"""
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
