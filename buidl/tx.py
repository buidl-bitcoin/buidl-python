from io import BytesIO

from urllib.request import Request, urlopen

import json

from buidl.ecc import SchnorrSignature
from buidl.helper import (
    big_endian_to_int,
    decode_base58,
    encode_varint,
    encode_varstr,
    hash256,
    hash_tapsighash,
    int_to_byte,
    int_to_little_endian,
    little_endian_to_int,
    read_varint,
    sha256,
    SIGHASH_ALL,
    SIGHASH_DEFAULT,
    SIGHASH_NONE,
    SIGHASH_SINGLE,
    SIGHASH_ANYONECANPAY,
)
from buidl.script import (
    P2PKHScriptPubKey,
    RedeemScript,
    Script,
    ScriptPubKey,
    WitnessScript,
)
from buidl.taproot import MultiSigTapScript
from buidl.witness import Witness


URL = {
    "mainnet": "https://blockstream.info/api",
    "testnet": "https://blockstream.info/testnet/api",
    "signet": "https://mempool.space/signet/api",
}


class TxFetcher:
    cache = {}

    @classmethod
    def get_url(cls, network="mainnet"):
        return URL[network]

    @classmethod
    def fetch(cls, tx_id, network="mainnet", fresh=False):
        if fresh or (tx_id not in cls.cache):
            url = "{}/tx/{}/hex".format(cls.get_url(network), tx_id)
            req = Request(url, headers={"User-Agent": "Mozilla/5.0"})
            response = urlopen(req).read().decode("utf-8").strip()
            try:
                raw = bytes.fromhex(response)
            except ValueError:
                raise ValueError(f"unexpected response: {response}")
            tx = Tx.parse(BytesIO(raw), network=network)
            # make sure the tx we got matches to the hash we requested
            if tx.segwit:
                computed = tx.id()
            else:
                computed = hash256(raw)[::-1].hex()
            if computed != tx_id:
                raise RuntimeError(f"server lied: {computed} vs {tx_id}")
            cls.cache[tx_id] = tx
        cls.cache[tx_id].network = network
        return cls.cache[tx_id]

    @classmethod
    def load_cache(cls, filename):
        disk_cache = json.loads(open(filename, "r").read())
        for k, raw_hex in disk_cache.items():
            cls.cache[k] = Tx.parse_hex(raw_hex)

    @classmethod
    def dump_cache(cls, filename):
        with open(filename, "w") as f:
            to_dump = {k: tx.serialize().hex() for k, tx in cls.cache.items()}
            s = json.dumps(to_dump, sort_keys=True, indent=4)
            f.write(s)


class Tx:
    command = b"tx"

    def __init__(
        self, version, tx_ins, tx_outs, locktime, network="mainnet", segwit=False
    ):
        self.version = version
        self.tx_ins = tx_ins
        self.tx_outs = tx_outs
        self.locktime = locktime
        self.network = network
        self.segwit = segwit
        self._hash_prevouts = None
        self._hash_sequence = None
        self._hash_outputs = None
        self._sha_prevouts = None
        self._sha_amounts = None
        self._sha_script_pubkeys = None
        self._sha_sequence = None
        self._sha_outputs = None

    def __repr__(self):
        tx_ins = "\n".join([str(txi) for txi in self.tx_ins])
        tx_outs = "\n".join([str(txo) for txo in self.tx_outs])
        return f"""
tx: {self.hash().hex()}
version: {self.version}
locktime: {self.locktime}
tx_ins:\n{tx_ins}
tx_outs:\n{tx_outs}
"""

    def clone(self):
        tx_obj = self.__class__.parse(BytesIO(self.serialize()), network=self.network)
        for tx_in_1, tx_in_2 in zip(self.tx_ins, tx_obj.tx_ins):
            tx_in_2._value = tx_in_1._value
            tx_in_2._script_pubkey = tx_in_1._script_pubkey
        return tx_obj

    def id(self):
        """Human-readable hexadecimal of the transaction hash"""
        return self.hash().hex()

    def hash(self):
        """Binary hash of the legacy serialization"""
        return hash256(self.serialize_legacy())[::-1]

    @classmethod
    def parse_hex(cls, s, network="mainnet"):
        """Parses a transaction from a hex string"""
        raw_hex = bytes.fromhex(s)
        stream = BytesIO(raw_hex)
        return cls.parse(s=stream, network=network)

    @classmethod
    def parse(cls, s, network="mainnet"):
        """Parses a transaction from stream"""
        # we can determine whether something is segwit or legacy by looking
        # at byte 5
        s.read(4)
        if s.read(1) == b"\x00":
            parse_method = cls.parse_segwit
        else:
            parse_method = cls.parse_legacy
        # reset the seek to the beginning so everything can go through
        s.seek(-5, 1)
        return parse_method(s, network=network)

    @classmethod
    def parse_legacy(cls, s, network="mainnet"):
        """Takes a byte stream and parses a legacy transaction"""
        # s.read(n) will return n bytes
        # version has 4 bytes, little-endian, interpret as int
        version = little_endian_to_int(s.read(4))
        # num_inputs is a varint, use read_varint(s)
        num_inputs = read_varint(s)
        # each input needs parsing
        inputs = []
        for _ in range(num_inputs):
            inputs.append(TxIn.parse(s))
        # num_outputs is a varint, use read_varint(s)
        num_outputs = read_varint(s)
        # each output needs parsing
        outputs = []
        for _ in range(num_outputs):
            outputs.append(TxOut.parse(s))
        # locktime is 4 bytes, little-endian
        locktime = little_endian_to_int(s.read(4))
        # return an instance of the class (cls(...))
        return cls(version, inputs, outputs, locktime, network=network, segwit=False)

    @classmethod
    def parse_segwit(cls, s, network="mainnet"):
        """Takes a byte stream and parses a segwit transaction"""
        # s.read(n) will return n bytes
        # version has 4 bytes, little-endian, interpret as int
        version = little_endian_to_int(s.read(4))
        # next two bytes need to be 0x00 and 0x01, otherwise raise RuntimeError
        marker = s.read(2)
        if marker != b"\x00\x01":
            raise RuntimeError(f"Not a segwit transaction {marker}")
        # num_inputs is a varint, use read_varint(s)
        num_inputs = read_varint(s)
        # each input needs parsing, create inputs array
        inputs = []
        # parse each input and add to the inputs array
        for _ in range(num_inputs):
            inputs.append(TxIn.parse(s))
        # num_outputs is a varint, use read_varint(s)
        num_outputs = read_varint(s)
        # each output needs parsing, create outputs array
        outputs = []
        # parse each output and add to the outputs array
        for _ in range(num_outputs):
            outputs.append(TxOut.parse(s))
        # there is a witness for each input
        for tx_in in inputs:
            tx_in.witness = Witness.parse(s)
        # locktime is 4 bytes, little-endian
        locktime = little_endian_to_int(s.read(4))
        # return an instance of the class (cls(...))
        return cls(version, inputs, outputs, locktime, network=network, segwit=True)

    def serialize(self):
        if self.segwit:
            return self.serialize_segwit()
        else:
            return self.serialize_legacy()

    def serialize_legacy(self):
        """Returns the byte serialization of the transaction"""
        # serialize version (4 bytes, little endian)
        result = int_to_little_endian(self.version, 4)
        # encode_varint on the number of inputs
        result += encode_varint(len(self.tx_ins))
        # iterate inputs
        for tx_in in self.tx_ins:
            # serialize each input
            result += tx_in.serialize()
        # encode_varint on the number of outputs
        result += encode_varint(len(self.tx_outs))
        # iterate outputs
        for tx_out in self.tx_outs:
            # serialize each output
            result += tx_out.serialize()
        # serialize locktime (4 bytes, little endian)
        result += int_to_little_endian(self.locktime, 4)
        return result

    def serialize_segwit(self):
        """Returns the byte serialization of the transaction"""
        # serialize version (4 bytes, little endian)
        result = int_to_little_endian(self.version, 4)
        # segwit marker b'\x00\x01'
        result += b"\x00\x01"
        # encode_varint on the number of inputs
        result += encode_varint(len(self.tx_ins))
        # iterate inputs
        for tx_in in self.tx_ins:
            # serialize each input
            result += tx_in.serialize()
        # encode_varint on the number of inputs
        result += encode_varint(len(self.tx_outs))
        # iterate outputs
        for tx_out in self.tx_outs:
            # serialize each output
            result += tx_out.serialize()
        # add the witness data for each input
        for tx_in in self.tx_ins:
            # serialize the witness field
            result += tx_in.witness.serialize()
        # serialize locktime (4 bytes, little endian)
        result += int_to_little_endian(self.locktime, 4)
        return result

    def fee(self):
        """Returns the fee of this transaction in satoshi"""
        # initialize input sum and output sum
        input_sum, output_sum = 0, 0
        # iterate through inputs
        for tx_in in self.tx_ins:
            # for each input get the value and add to input sum
            input_sum += tx_in.value(self.network)
        # iterate through outputs
        for tx_out in self.tx_outs:
            # for each output get the amount and add to output sum
            output_sum += tx_out.amount
        # return input sum - output sum
        return input_sum - output_sum

    def sig_hash_legacy(self, input_index, redeem_script=None, hash_type=SIGHASH_ALL):
        """Returns the integer representation of the hash that needs to get
        signed for index input_index"""

        # consensus bugs related to invalid input indices
        DEFAULT = 1 << 248
        if input_index >= len(self.tx_ins):
            return DEFAULT
        elif hash_type & 3 == SIGHASH_SINGLE and input_index >= len(self.tx_outs):
            return DEFAULT
        # create the serialization per spec
        # start with version: int_to_little_endian in 4 bytes
        s = int_to_little_endian(self.version, 4)
        # next, how many inputs there are: encode_varint
        s += encode_varint(len(self.tx_ins))
        # loop through each input: for i, tx_in in enumerate(self.tx_ins)
        for i, tx_in in enumerate(self.tx_ins):
            sequence = tx_in.sequence
            # if the input index is the one we're signing
            if i == input_index:
                # if the RedeemScript was passed in, that's the ScriptSig
                if redeem_script:
                    script_sig = redeem_script
                # otherwise the previous tx's ScriptPubkey is the ScriptSig
                else:
                    script_sig = tx_in.script_pubkey(self.network)
            # Otherwise, the ScriptSig is empty
            else:
                script_sig = None
                if hash_type & 3 in (SIGHASH_NONE, SIGHASH_SINGLE):
                    sequence = 0
            # create a TxIn object with the prev_tx, prev_index and sequence
            # the same as the current tx_in and the script_sig from above
            new_tx_in = TxIn(
                prev_tx=tx_in.prev_tx,
                prev_index=tx_in.prev_index,
                script_sig=script_sig,
                sequence=sequence,
            )
            # add the serialization of the TxIn object
            if hash_type & SIGHASH_ANYONECANPAY:
                if i == input_index:
                    s += new_tx_in.serialize()
            else:
                s += new_tx_in.serialize()
        # add how many outputs there are using encode_varint
        s += encode_varint(len(self.tx_outs))
        # add the serialization of each output
        for i, tx_out in enumerate(self.tx_outs):
            if hash_type & 3 == SIGHASH_NONE:
                continue
            elif hash_type & 3 == SIGHASH_SINGLE:
                if i == input_index:
                    s += tx_out.serialize()
                    break
                else:
                    s += b"\xff\xff\xff\xff\xff\xff\xff\xff\x00"
            else:
                s += tx_out.serialize()
        # add the locktime using int_to_little_endian in 4 bytes
        s += int_to_little_endian(self.locktime, 4)
        # add SIGHASH_ALL using int_to_little_endian in 4 bytes
        s += int_to_little_endian(hash_type, 4)
        # hash256 the serialization
        h256 = hash256(s)
        # convert the result to an integer using big_endian_to_int(x)
        return big_endian_to_int(h256)

    def hash_prevouts(self):
        if self._hash_prevouts is None:
            all_prevouts = b""
            all_sequence = b""
            for tx_in in self.tx_ins:
                all_prevouts += tx_in.prev_tx[::-1] + int_to_little_endian(
                    tx_in.prev_index, 4
                )
                all_sequence += int_to_little_endian(tx_in.sequence, 4)
            self._hash_prevouts = hash256(all_prevouts)
            self._hash_sequence = hash256(all_sequence)
        return self._hash_prevouts

    def hash_sequence(self):
        if self._hash_sequence is None:
            self.hash_prevouts()  # this should calculate self._hash_prevouts
        return self._hash_sequence

    def hash_outputs(self):
        if self._hash_outputs is None:
            all_outputs = b""
            for tx_out in self.tx_outs:
                all_outputs += tx_out.serialize()
            self._hash_outputs = hash256(all_outputs)
        return self._hash_outputs

    def sig_hash_bip143(
        self,
        input_index,
        redeem_script=None,
        witness_script=None,
        hash_type=SIGHASH_ALL,
    ):
        """Returns the integer representation of the hash that needs to get
        signed for index input_index"""
        # grab the input being signed by looking up the input_index
        tx_in = self.tx_ins[input_index]
        # start with the version in 4 bytes, little endian
        s = int_to_little_endian(self.version, 4)
        # add the HashPrevouts and HashSequence
        if hash_type & SIGHASH_ANYONECANPAY != SIGHASH_ANYONECANPAY:
            s += self.hash_prevouts()
        if hash_type & SIGHASH_ANYONECANPAY != SIGHASH_ANYONECANPAY and (
            hash_type & 3
        ) not in (SIGHASH_SINGLE, SIGHASH_NONE):
            s += self.hash_sequence()
        # add the previous transaction hash in little endian
        s += tx_in.prev_tx[::-1]
        # add the previous transaction index in 4 bytes, little endian
        s += int_to_little_endian(tx_in.prev_index, 4)
        # for p2wpkh, we need to compute the ScriptCode
        # Exercise 1: account for p2wsh. Check first for the existence of a WitnessScript
        if witness_script:
            # for p2wsh and p2sh-p2wsh the ScriptCode is the WitnessScript
            script_code = witness_script
        elif redeem_script:
            # for p2sh-p2wpkh, get the hash160 which is the 2nd command of the RedeemScript
            h160 = redeem_script.commands[1]
            # the ScriptCode is the P2PKHScriptPubKey created using the hash160
            script_code = P2PKHScriptPubKey(h160)
        else:
            # get the script pubkey associated with the previous output (remember network)
            script_pubkey = tx_in.script_pubkey(self.network)
            # next get the hash160 in the script_pubkey. for p2wpkh, it's the second command
            h160 = script_pubkey.commands[1]
            # finally the ScriptCode is the P2PKHScriptPubKey created using the hash160
            script_code = P2PKHScriptPubKey(h160)
        # add the serialized ScriptCode
        s += script_code.serialize()
        # add the value of the input in 8 bytes, little endian
        s += int_to_little_endian(tx_in.value(network=self.network), 8)
        # add the sequence of the input in 4 bytes, little endian
        s += int_to_little_endian(tx_in.sequence, 4)
        # add the HashOutputs
        if (hash_type & 3) not in (SIGHASH_SINGLE, SIGHASH_NONE):
            s += self.hash_outputs()
        elif hash_type & SIGHASH_SINGLE == SIGHASH_SINGLE:
            s += self.tx_outs[input_index].serialize()
        # add the locktime in 4 bytes, little endian
        s += int_to_little_endian(self.locktime, 4)
        # add the sighash (SIGHASH_ALL) in 4 bytes, little endian
        s += int_to_little_endian(hash_type, 4)
        # hash256 the whole thing, interpret the as a big endian integer using int_to_big_endian
        return big_endian_to_int(hash256(s))

    def sha_prevouts(self):
        if self._sha_prevouts is None:
            all_prevouts = b""
            all_amounts = b""
            all_script_pubkeys = b""
            all_sequence = b""
            for tx_in in self.tx_ins:
                all_prevouts += tx_in.prev_tx[::-1] + int_to_little_endian(
                    tx_in.prev_index, 4
                )
                all_amounts += int_to_little_endian(tx_in.value(self.network), 8)
                all_script_pubkeys += tx_in.script_pubkey(self.network).serialize()
                all_sequence += int_to_little_endian(tx_in.sequence, 4)
            self._sha_prevouts = sha256(all_prevouts)
            self._sha_amounts = sha256(all_amounts)
            self._sha_script_pubkeys = sha256(all_script_pubkeys)
            self._sha_sequences = sha256(all_sequence)
        return self._sha_prevouts

    def sha_amounts(self):
        if self._sha_amounts is None:
            self.sha_prevouts()  # this should calculate self._sha_amounts
        return self._sha_amounts

    def sha_script_pubkeys(self):
        if self._sha_script_pubkeys is None:
            self.sha_prevouts()  # this should calculate self._sha_script_pubkeys
        return self._sha_script_pubkeys

    def sha_sequences(self):
        if self._sha_sequences is None:
            self.sha_prevouts()  # this should calculate self._sha_sequences
        return self._sha_sequences

    def sha_outputs(self):
        if self._sha_outputs is None:
            all_outputs = b""
            for tx_out in self.tx_outs:
                all_outputs += tx_out.serialize()
            self._sha_outputs = sha256(all_outputs)
        return self._sha_outputs

    def sig_hash_bip341(self, input_index, ext_flag=0, hash_type=SIGHASH_DEFAULT):
        """Returns the root message being signed for p2tr"""
        tx_in = self.tx_ins[input_index]
        s = b"\x00"
        s += int_to_byte(hash_type)
        s += int_to_little_endian(self.version, 4)
        s += int_to_little_endian(self.locktime, 4)
        if not hash_type & SIGHASH_ANYONECANPAY:
            s += self.sha_prevouts()
            s += self.sha_amounts()
            s += self.sha_script_pubkeys()
            s += self.sha_sequences()
        if (hash_type & 3) not in (SIGHASH_NONE, SIGHASH_SINGLE):
            s += self.sha_outputs()
        spend_type = ext_flag * 2
        if tx_in.witness.has_annex():
            spend_type += 1
        s += int_to_byte(spend_type)
        if hash_type & SIGHASH_ANYONECANPAY:
            s += tx_in.prev_tx[::-1] + int_to_little_endian(tx_in.prev_index, 4)
            s += int_to_little_endian(tx_in.value(), 8)
            s += tx_in.script_pubkey().serialize()
            s += int_to_little_endian(tx_in.sequence, 4)
        else:
            s += int_to_little_endian(input_index, 4)
        if hash_type & SIGHASH_SINGLE == SIGHASH_SINGLE:
            s += sha256(self.tx_outs[input_index].serialize())
        if tx_in.witness.has_annex():
            s += sha256(encode_varstr(tx_in.witness[-1]))
        if ext_flag == 1:
            tapleaf_hash = tx_in.witness.tap_leaf().hash()
            # extension defined in BIP0342
            s += tapleaf_hash + b"\x00\xff\xff\xff\xff"
        return hash_tapsighash(s)

    def sig_hash(self, input_index, hash_type):
        # get the relevant input
        tx_in = self.tx_ins[input_index]
        # get the script_pubkey of the input
        script_pubkey = tx_in.script_pubkey(network=self.network)
        # grab the RedeemScript if we have a p2sh
        if script_pubkey.is_p2sh():
            # the last command of the ScriptSig is the raw RedeemScript
            raw_redeem_script = tx_in.script_sig.commands[-1]
            # convert to RedeemScript
            redeem_script = RedeemScript.convert(raw_redeem_script)
        else:
            redeem_script = None
        # grab the WitnessScript if we have a p2wsh
        if script_pubkey.is_p2wsh() or (redeem_script and redeem_script.is_p2wsh()):
            # the last item of the Witness is the raw WitnessScript
            raw_witness_script = tx_in.witness.items[-1]
            # convert to WitnessScript
            witness_script = WitnessScript.convert(raw_witness_script)
        else:
            witness_script = None
        # check to see if the ScriptPubKey or the RedeemScript is p2wpkh or p2wsh
        if (
            script_pubkey.is_p2wpkh()
            or (redeem_script and redeem_script.is_p2wpkh())
            or script_pubkey.is_p2wsh()
            or (redeem_script and redeem_script.is_p2wsh())
        ):
            return self.sig_hash_bip143(
                input_index,
                redeem_script=redeem_script,
                witness_script=witness_script,
                hash_type=hash_type,
            )
        elif script_pubkey.is_p2tr():
            if len(tx_in.witness) > 1:
                ext_flag = 1
            else:
                ext_flag = 0
            return self.sig_hash_bip341(
                input_index, ext_flag=ext_flag, hash_type=hash_type
            )
        else:
            return self.sig_hash_legacy(input_index, redeem_script, hash_type=hash_type)

    def verify_input(self, input_index):
        """Returns whether the input has a valid signature"""
        # get the relevant input
        tx_in = self.tx_ins[input_index]
        # combine the scripts
        combined_script = tx_in.script_sig + tx_in.script_pubkey(self.network)
        # evaluate the combined script
        return combined_script.evaluate(self, input_index)

    def verify(self):
        """Verify this transaction"""
        if self.fee() < 0:
            return False
        for i in range(len(self.tx_ins)):
            if not self.verify_input(i):
                return False
        return True

    def sign_p2pkh(self, input_index, private_key):
        """Signs the input assuming that the previous output is a p2pkh using the private key"""
        # get the sig using get_sig_legacy
        sig = self.get_sig_legacy(input_index, private_key)
        # calculate the sec
        sec = private_key.point.sec(compressed=private_key.compressed)
        # finalize the input using finalize_p2pkh
        self.tx_ins[input_index].finalize_p2pkh(sig, sec)
        # return whether sig is valid using self.verify_input
        return self.verify_input(input_index)

    def sign_p2wpkh(self, input_index, private_key):
        """Signs the input assuming that the previous output is a p2pkh using the private key"""
        # get the sig using get_sig_segwit
        sig = self.get_sig_segwit(input_index, private_key)
        # calculate the sec
        sec = private_key.point.sec(compressed=private_key.compressed)
        # finalize the input using finalize_p2wpkh
        self.tx_ins[input_index].finalize_p2wpkh(sig, sec)
        # return whether sig is valid using self.verify_input
        return self.verify_input(input_index)

    def sign_p2sh_p2wpkh(self, input_index, private_key):
        """Signs the input assuming that the previous output is a p2pkh using the private key"""
        # use p2sh_p2wpkh_redeem_script to get the RedeemScript
        redeem_script = private_key.point.p2sh_p2wpkh_redeem_script()
        # get the sig using get_sig_segwit
        sig = self.get_sig_segwit(input_index, private_key, redeem_script=redeem_script)
        # calculate the sec
        sec = private_key.point.sec(compressed=private_key.compressed)
        # finalize the input using finalize_p2wpkh
        self.tx_ins[input_index].finalize_p2wpkh(sig, sec, redeem_script)
        # return whether sig is valid using self.verify_input
        return self.verify_input(input_index)

    def sign_p2tr_keypath(
        self, input_index, private_key, hash_type=SIGHASH_DEFAULT, aux=b"\x00" * 32
    ):
        sig = self.get_sig_taproot(
            input_index, private_key, hash_type=hash_type, aux=aux
        )
        self.tx_ins[input_index].finalize_p2tr_keypath(sig)
        return self.verify_input(input_index)

    def initialize_p2tr_multisig(self, input_index, control_block, tap_script):
        tx_in = self.tx_ins[input_index]
        if len(tx_in.witness.items) == 0:
            tx_in.witness = Witness(
                [tap_script.raw_serialize(), control_block.serialize()]
            )
            if type(tap_script) != MultiSigTapScript:
                raise RuntimeError("tap script must be MultiSigTapScript")
            tx_in.tap_script = tap_script

    def finalize_p2tr_multisig(self, input_index, sigs):
        tx_in = self.tx_ins[input_index]
        if len(tx_in.witness.items) < 2 or tx_in.tap_script is None:
            raise RuntimeError("initialize single leaf multisig first")
        for point in tx_in.tap_script.points:
            for sig in sigs:
                if len(sig) == 0:
                    continue
                elif len(sig) == 64:
                    hash_type = SIGHASH_DEFAULT
                    schnorr = SchnorrSignature.parse(sig)
                elif len(sig) == 65:
                    hash_type = sig[-1]
                    schnorr = SchnorrSignature.parse(sig[:-1])
                else:
                    raise RuntimeError("invalid signature length")
                msg = self.sig_hash(input_index, hash_type=hash_type)
                if point.verify_schnorr(msg, schnorr):
                    tx_in.witness.items.insert(0, sig)
                    break
            else:
                tx_in.witness.items.insert(0, b"")
        return self.verify_input(input_index)

    def sign_input(
        self, input_index, private_key, redeem_script=None, hash_type=SIGHASH_ALL
    ):
        """Signs the input by figuring out what type of ScriptPubKey the previous output was"""
        # get the input
        tx_in = self.tx_ins[input_index]
        # find the previous ScriptPubKey
        script_pubkey = tx_in.script_pubkey(network=self.network)
        # if the script_pubkey is p2pkh, send to sign_p2pkh
        if script_pubkey.is_p2pkh():
            return self.sign_p2pkh(input_index, private_key)
        # if the script_pubkey is p2wpkh, send to sign_p2wpkh
        elif script_pubkey.is_p2wpkh():
            return self.sign_p2wpkh(input_index, private_key)
        # if the script_pubkey is p2sh and RedeemScript p2wpkh, send to sign_p2sh_p2wpkh
        elif redeem_script and redeem_script.is_p2wpkh():
            return self.sign_p2sh_p2wpkh(input_index, private_key)
        elif script_pubkey.is_p2tr():
            return self.sign_p2tr_keypath(input_index, private_key, hash_type=hash_type)
        # else return a RuntimeError
        else:
            raise RuntimeError("Unknown ScriptPubKey")

    def get_sig_legacy(self, input_index, private_key, redeem_script=None):
        # get the sig hash (z)
        z = self.sig_hash_legacy(input_index, redeem_script=redeem_script)
        # get der signature of z from private key
        der = private_key.sign(z).der()
        # append the SIGHASH_ALL with int_to_byte(SIGHASH_ALL)
        return der + int_to_byte(SIGHASH_ALL)

    def get_sig_segwit(
        self, input_index, private_key, redeem_script=None, witness_script=None
    ):
        # get the sig_hash (z)
        z = self.sig_hash_bip143(input_index, redeem_script, witness_script)
        # get der signature of z from private key
        der = private_key.sign(z).der()
        # append the SIGHASH_ALL with int_to_byte(SIGHASH_ALL)
        return der + int_to_byte(SIGHASH_ALL)

    def get_sig_taproot(
        self,
        input_index,
        private_key,
        ext_flag=0,
        hash_type=SIGHASH_DEFAULT,
        aux=b"\x00" * 32,
    ):
        # get the sig_hash (z)
        msg = self.sig_hash_bip341(input_index, ext_flag=ext_flag, hash_type=hash_type)
        # get der signature of z from private key
        schnorr = private_key.sign_schnorr(msg, aux).serialize()
        # append the SIGHASH_ALL with int_to_byte(SIGHASH_ALL)
        if hash_type:
            return schnorr + int_to_byte(hash_type)
        else:
            return schnorr

    def check_sig_legacy(self, input_index, point, signature, redeem_script=None):
        # get the sig_hash (z)
        z = self.sig_hash_legacy(input_index, redeem_script)
        # return whether the signature verifies
        return point.verify(z, signature)

    def check_sig_segwit(
        self, input_index, point, signature, redeem_script=None, witness_script=None
    ):
        # get the sig_hash (z)
        z = self.sig_hash_bip143(input_index, redeem_script, witness_script)
        # return whether the signature verifies
        return point.verify(z, signature)

    def is_coinbase(self):
        """Returns whether this transaction is a coinbase transaction or not"""
        # check that there is exactly 1 input
        if len(self.tx_ins) != 1:
            return False
        # grab the first input
        first_input = self.tx_ins[0]
        # check that first input prev_tx is b'\x00' * 32 bytes
        if first_input.prev_tx != b"\x00" * 32:
            return False
        # check that first input prev_index is 0xffffffff
        if first_input.prev_index != 0xFFFFFFFF:
            return False
        return True

    def coinbase_height(self):
        """Returns the height of the block this coinbase transaction is in
        Returns None if this transaction is not a coinbase transaction
        """
        # if this is NOT a coinbase transaction, return None
        if not self.is_coinbase():
            return None
        # grab the first input
        script_sig = self.tx_ins[0].script_sig
        # get the next length bytes
        command = script_sig.commands[0]
        # convert the command from little endian to int
        return little_endian_to_int(command)

    def is_rbf_able(self):
        # https://github.com/bitcoin/bips/blob/master/bip-0125.mediawiki#Implementation_Details
        eligible = False
        for tx_in in self.tx_ins:
            if tx_in.sequence < 0xFFFFFFFF - 1:
                eligible = True
        return eligible

    def find_utxos(self, address):
        """Returns transaction outputs that matches the address"""
        h160 = decode_base58(address)
        # utxos are a list of tuples: (hash, index, amount)
        utxos = []
        for index, tx_out in enumerate(self.tx_outs):
            if tx_out.script_pubkey.hash160() == h160:
                utxos.append((self.hash(), index, tx_out.amount))
        return utxos

    def get_input_tx_lookup(self):
        """Returns the tx lookup dictionary of hashes to the Tx objects
        for all the input transactions."""
        tx_lookup = {}
        for tx_in in self.tx_ins:
            tx_obj = TxFetcher.fetch(tx_in.prev_tx.hex(), network=self.network)
            tx_lookup[tx_obj.hash()] = tx_obj
        return tx_lookup


class TxIn:
    def __init__(self, prev_tx, prev_index, script_sig=None, sequence=0xFFFFFFFF):
        self.prev_tx = prev_tx
        self.prev_index = prev_index
        if script_sig is None:
            self.script_sig = Script()
        else:
            self.script_sig = script_sig
        self.sequence = sequence
        self._value = None
        self._script_pubkey = None
        self.witness = Witness()
        self.tap_script = None

    def __repr__(self):
        return "{self.prev_tx.hex()}:{self.prev_index}"

    @classmethod
    def parse(cls, s):
        """Takes a byte stream and parses the tx_input at the start
        return a TxIn object
        """
        # s.read(n) will return n bytes
        # prev_tx is 32 bytes, little endian
        prev_tx = s.read(32)[::-1]
        # prev_index is 4 bytes, little endian, interpret as int
        prev_index = little_endian_to_int(s.read(4))
        # script_sig is a variable field (length followed by the data)
        # you can use Script.parse to get the actual script
        script_sig = Script.parse(s)
        # sequence is 4 bytes, little-endian, interpret as int
        sequence = little_endian_to_int(s.read(4))
        # return an instance of the class (cls(...))
        return cls(prev_tx, prev_index, script_sig, sequence)

    def serialize(self):
        """Returns the byte serialization of the transaction input"""
        # serialize prev_tx, little endian
        result = self.prev_tx[::-1]
        # serialize prev_index, 4 bytes, little endian
        result += int_to_little_endian(self.prev_index, 4)
        # serialize the script_sig
        result += self.script_sig.serialize()
        # serialize sequence, 4 bytes, little endian
        result += int_to_little_endian(self.sequence, 4)
        return result

    def fetch_tx(self, network="mainnet"):
        return TxFetcher.fetch(self.prev_tx.hex(), network=network)

    def value(self, network="mainnet"):
        """Get the outpoint value by looking up the tx hash
        Returns the amount in satoshi
        """
        if self._value is None:
            # use self.fetch_tx to get the transaction
            tx = self.fetch_tx(network=network)
            # get the output at self.prev_index
            self._value = tx.tx_outs[self.prev_index].amount
        return self._value

    def script_pubkey(self, network="mainnet"):
        """Get the scriptPubKey by looking up the tx hash
        Returns a Script object
        """
        if self._script_pubkey is None:
            # use self.fetch_tx to get the transaction
            tx = self.fetch_tx(network=network)
            # get the output at self.prev_index
            self._script_pubkey = tx.tx_outs[self.prev_index].script_pubkey
        return self._script_pubkey

    def finalize_p2pkh(self, sig, sec):
        """Puts together the ScriptSig for a p2pkh input so the input verifies."""
        # the ScriptSig for p2pkh is [sig, sec]
        self.script_sig = Script([sig, sec])

    def finalize_p2wpkh(self, sig, sec, redeem_script=None):
        """Puts together the ScriptSig and Witness for a p2wpkh input so the input verifies."""
        # if the RedeemScript is given, the ScriptSig is a single element Script of its raw serialization
        if redeem_script:
            self.script_sig = Script([redeem_script.raw_serialize()])
        # else the ScriptSig should be empty
        else:
            self.script_sig = Script()
        # the Witness for p2wpkh is [sig, sec]
        self.witness = Witness([sig, sec])

    def finalize_p2sh_multisig(self, signatures, redeem_script):
        """Puts together the signatures for a p2sh input so the input verifies."""
        # the ScriptSig for p2sh multisig is [0, each signature, then the RedeemScript (raw-serialization)]
        script_sig = Script([0, *signatures, redeem_script.raw_serialize()])
        # set the witness of the input to be these items
        self.script_sig = script_sig

    def finalize_p2wsh_multisig(self, signatures, witness_script):
        """Puts together the signatures for a p2wsh input so the input verifies."""
        # the format for multisig is [b'\x00', each signature, then the WitnessScript (raw-serialization)]
        items = [b"\x00", *signatures, witness_script.raw_serialize()]
        # set the witness of the input to be these items
        self.witness = Witness(items)

    def finalize_p2sh_p2wsh_multisig(self, signatures, witness_script):
        """Puts together the signatures for a p2sh-p2wsh input so the input verifies."""
        # the format for multisig is [b'\x00', each signature, then the WitnessScript (raw-serialization)]
        items = [b"\x00", *signatures, witness_script.raw_serialize()]
        # set the witness of the input to be these items
        self.witness = Witness(items)
        # the RedeemScript is the p2wsh ScriptPubKey of the WitnessScript
        redeem_script = witness_script.script_pubkey()
        # set the ScriptSig of the tx_in to be a new script, which is just the RedeemScript raw-serialized
        self.script_sig = Script([redeem_script.raw_serialize()])

    def finalize_p2tr_keypath(self, sig):
        self.witness = Witness([sig])


class TxOut:
    def __init__(self, amount, script_pubkey):
        self.amount = amount
        self.script_pubkey = script_pubkey

    def __repr__(self):
        return f"{self.amount}:{self.script_pubkey}"

    def serialize(self):
        """Returns the byte serialization of the transaction output"""
        # serialize amount, 8 bytes, little endian
        result = int_to_little_endian(self.amount, 8)
        # serialize the script_pubkey
        result += self.script_pubkey.serialize()
        return result

    @classmethod
    def parse(cls, s):
        """Takes a byte stream and parses the tx_output at the start
        return a TxOut object
        """
        # s.read(n) will return n bytes
        # amount is 8 bytes, little endian, interpret as int
        amount = little_endian_to_int(s.read(8))
        # script_pubkey is a variable field (length followed by the data)
        # you can use Script.parse to get the actual script
        script_pubkey = ScriptPubKey.parse(s)
        # return an instance of the class (cls(...))
        return cls(amount, script_pubkey)
