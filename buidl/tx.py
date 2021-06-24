from io import BytesIO

from urllib.request import Request, urlopen

import json

from buidl.helper import (
    big_endian_to_int,
    decode_base58,
    hash256,
    encode_varint,
    int_to_byte,
    int_to_little_endian,
    little_endian_to_int,
    read_varint,
    SIGHASH_ALL,
)
from buidl.script import (
    P2PKHScriptPubKey,
    RedeemScript,
    Script,
    ScriptPubKey,
    WitnessScript,
)
from buidl.witness import Witness


URL = {
    "mainnet": "https://blockstream.info/api",
    "testnet": "https://blockstream.info/testnet/api",
    "signet": "https://explorer.bc-2.jp/api",
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
                raise ValueError("unexpected response: {}".format(response))
            tx = Tx.parse(BytesIO(raw), network=network)
            # make sure the tx we got matches to the hash we requested
            if tx.segwit:
                computed = tx.id()
            else:
                computed = hash256(raw)[::-1].hex()
            if computed != tx_id:
                raise RuntimeError("server lied: {} vs {}".format(computed, tx_id))
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

    def __repr__(self):
        tx_ins = ""
        for tx_in in self.tx_ins:
            tx_ins += tx_in.__repr__() + "\n"
        tx_outs = ""
        for tx_out in self.tx_outs:
            tx_outs += tx_out.__repr__() + "\n"
        return "tx: {}\nversion: {}\ntx_ins:\n{}\ntx_outs:\n{}\nlocktime: {}\n".format(
            self.hash().hex(),
            self.version,
            tx_ins,
            tx_outs,
            self.locktime,
        )

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
            raise RuntimeError("Not a segwit transaction {}".format(marker))
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

    def sig_hash(self, input_index, redeem_script=None):
        """Returns the integer representation of the hash that needs to get
        signed for index input_index"""
        # create the serialization per spec
        # start with version: int_to_little_endian in 4 bytes
        s = int_to_little_endian(self.version, 4)
        # next, how many inputs there are: encode_varint
        s += encode_varint(len(self.tx_ins))
        # loop through each input: for i, tx_in in enumerate(self.tx_ins)
        for i, tx_in in enumerate(self.tx_ins):
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
            # create a TxIn object with the prev_tx, prev_index and sequence
            # the same as the current tx_in and the script_sig from above
            new_tx_in = TxIn(
                prev_tx=tx_in.prev_tx,
                prev_index=tx_in.prev_index,
                script_sig=script_sig,
                sequence=tx_in.sequence,
            )
            # add the serialization of the TxIn object
            s += new_tx_in.serialize()
        # add how many outputs there are using encode_varint
        s += encode_varint(len(self.tx_outs))
        # add the serialization of each output
        for tx_out in self.tx_outs:
            s += tx_out.serialize()
        # add the locktime using int_to_little_endian in 4 bytes
        s += int_to_little_endian(self.locktime, 4)
        # add SIGHASH_ALL using int_to_little_endian in 4 bytes
        s += int_to_little_endian(SIGHASH_ALL, 4)
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

    def sig_hash_bip143(self, input_index, redeem_script=None, witness_script=None):
        """Returns the integer representation of the hash that needs to get
        signed for index input_index"""
        # grab the input being signed by looking up the input_index
        tx_in = self.tx_ins[input_index]
        # start with the version in 4 bytes, little endian
        s = int_to_little_endian(self.version, 4)
        # add the HashPrevouts and HashSequence
        s += self.hash_prevouts() + self.hash_sequence()
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
        s += self.hash_outputs()
        # add the locktime in 4 bytes, little endian
        s += int_to_little_endian(self.locktime, 4)
        # add the sighash (SIGHASH_ALL) in 4 bytes, little endian
        s += int_to_little_endian(SIGHASH_ALL, 4)
        # hash256 the whole thing, interpret the as a big endian integer using int_to_big_endian
        return big_endian_to_int(hash256(s))

    def verify_input(self, input_index):
        """Returns whether the input has a valid signature"""
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
            # calculate the z using sig_hash_bip143
            z = self.sig_hash_bip143(input_index, redeem_script, witness_script)
        else:
            # calculate z using legacy
            z = self.sig_hash(input_index, redeem_script)
        # combine the scripts
        combined_script = tx_in.script_sig + tx_in.script_pubkey(self.network)
        # evaluate the combined script
        return combined_script.evaluate(z, tx_in.witness)

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

    def sign_input(self, input_index, private_key, redeem_script=None):
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
        # else return a RuntimeError
        else:
            raise RuntimeError("Unknown ScriptPubKey")

    def get_sig_legacy(self, input_index, private_key, redeem_script=None):
        # get the sig hash (z)
        z = self.sig_hash(input_index, redeem_script=redeem_script)
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

    def check_sig_legacy(self, input_index, point, signature, redeem_script=None):
        # get the sig_hash (z)
        z = self.sig_hash(input_index, redeem_script)
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
        # get the first byte of the scriptsig, which is the length
        length = script_sig.coinbase[0]
        # get the next length bytes
        command = script_sig.coinbase[1 : 1 + length]
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

    def __repr__(self):
        return "{}:{}".format(
            self.prev_tx.hex(),
            self.prev_index,
        )

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
        coinbase_mode = prev_tx == b"\x00" * 32 and prev_index == 0xFFFFFFFF
        script_sig = Script.parse(s, coinbase_mode)
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


class TxOut:
    def __init__(self, amount, script_pubkey):
        self.amount = amount
        self.script_pubkey = script_pubkey

    def __repr__(self):
        return "{}:{}".format(self.amount, self.script_pubkey)

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

    def serialize(self):
        """Returns the byte serialization of the transaction output"""
        # serialize amount, 8 bytes, little endian
        result = int_to_little_endian(self.amount, 8)
        # serialize the script_pubkey
        result += self.script_pubkey.serialize()
        return result
