from io import BytesIO
from unittest import TestCase

import json
import requests

from ecc import PrivateKey, Signature
from helper import (
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
from script import (
    P2PKHScriptPubKey,
    RedeemScript,
    Script,
    ScriptPubKey,
    WitnessScript,
)
from witness import Witness


class TxFetcher:
    cache = {}

    @classmethod
    def get_url(cls, testnet=False):
        if testnet:
            return 'http://testnet.programmingbitcoin.com'
        else:
            return 'http://mainnet.programmingbitcoin.com'

    @classmethod
    def fetch(cls, tx_id, testnet=False, fresh=False):
        if fresh or (tx_id not in cls.cache):
            url = '{}/tx/{}.hex'.format(cls.get_url(testnet), tx_id)
            response = requests.get(url)
            try:
                raw = bytes.fromhex(response.text.strip())
            except ValueError:
                raise ValueError('unexpected response: {}'.format(response.text))
            tx = Tx.parse(BytesIO(raw), testnet=testnet)
            # make sure the tx we got matches to the hash we requested
            if tx.segwit:
                computed = tx.id()
            else:
                computed = hash256(raw)[::-1].hex()
            if computed != tx_id:
                raise RuntimeError('server lied: {} vs {}'.format(computed, tx_id))
            cls.cache[tx_id] = tx
        cls.cache[tx_id].testnet = testnet
        return cls.cache[tx_id]

    @classmethod
    def load_cache(cls, filename):
        disk_cache = json.loads(open(filename, 'r').read())
        for k, raw_hex in disk_cache.items():
            cls.cache[k] = Tx.parse(BytesIO(bytes.fromhex(raw_hex)))

    @classmethod
    def dump_cache(cls, filename):
        with open(filename, 'w') as f:
            to_dump = {k: tx.serialize().hex() for k, tx in cls.cache.items()}
            s = json.dumps(to_dump, sort_keys=True, indent=4)
            f.write(s)


class Tx:
    command = b'tx'

    def __init__(self, version, tx_ins, tx_outs, locktime, testnet=False, segwit=False):
        self.version = version
        self.tx_ins = tx_ins
        self.tx_outs = tx_outs
        self.locktime = locktime
        self.testnet = testnet
        self.segwit = segwit
        self._hash_prevouts = None
        self._hash_sequence = None
        self._hash_outputs = None

    def __repr__(self):
        tx_ins = ''
        for tx_in in self.tx_ins:
            tx_ins += tx_in.__repr__() + '\n'
        tx_outs = ''
        for tx_out in self.tx_outs:
            tx_outs += tx_out.__repr__() + '\n'
        return 'tx: {}\nversion: {}\ntx_ins:\n{}\ntx_outs:\n{}\nlocktime: {}\n'.format(
            self.hash().hex(),
            self.version,
            tx_ins,
            tx_outs,
            self.locktime,
        )

    def clone(self):
        tx_obj = self.__class__.parse(BytesIO(self.serialize()), testnet=self.testnet)
        for tx_in_1, tx_in_2 in zip(self.tx_ins, tx_obj.tx_ins):
            tx_in_2._value = tx_in_1._value
            tx_in_2._script_pubkey = tx_in_1._script_pubkey
        return tx_obj

    def id(self):
        '''Human-readable hexadecimal of the transaction hash'''
        return self.hash().hex()

    def hash(self):
        '''Binary hash of the legacy serialization'''
        return hash256(self.serialize_legacy())[::-1]

    @classmethod
    def parse(cls, s, testnet=False):
        '''Parses a transaction from stream'''
        # we can determine whether something is segwit or legacy by looking
        # at byte 5
        s.read(4)
        if s.read(1) == b'\x00':
            parse_method = cls.parse_segwit
        else:
            parse_method = cls.parse_legacy
        # reset the seek to the beginning so everything can go through
        s.seek(-5, 1)
        return parse_method(s, testnet=testnet)

    @classmethod
    def parse_legacy(cls, s, testnet=False):
        '''Takes a byte stream and parses a legacy transaction'''
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
        return cls(version, inputs, outputs, locktime, testnet=testnet, segwit=False)

    @classmethod
    def parse_segwit(cls, s, testnet=False):
        '''Takes a byte stream and parses a segwit transaction'''
        # s.read(n) will return n bytes
        # version has 4 bytes, little-endian, interpret as int
        version = little_endian_to_int(s.read(4))
        # next two bytes need to be 0x00 and 0x01, otherwise raise RuntimeError
        marker = s.read(2)
        if marker != b'\x00\x01':
            raise RuntimeError('Not a segwit transaction {}'.format(marker))
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
        return cls(version, inputs, outputs, locktime, testnet=testnet, segwit=True)

    def serialize(self):
        if self.segwit:
            return self.serialize_segwit()
        else:
            return self.serialize_legacy()

    def serialize_legacy(self):
        '''Returns the byte serialization of the transaction'''
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
        '''Returns the byte serialization of the transaction'''
        # serialize version (4 bytes, little endian)
        result = int_to_little_endian(self.version, 4)
        # segwit marker b'\x00\x01'
        result += b'\x00\x01'
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
        '''Returns the fee of this transaction in satoshi'''
        # initialize input sum and output sum
        input_sum, output_sum = 0, 0
        # iterate through inputs
        for tx_in in self.tx_ins:
            # for each input get the value and add to input sum
            input_sum += tx_in.value(self.testnet)
        # iterate through outputs
        for tx_out in self.tx_outs:
            # for each output get the amount and add to output sum
            output_sum += tx_out.amount
        # return input sum - output sum
        return input_sum - output_sum

    def sig_hash(self, input_index, redeem_script=None):
        '''Returns the integer representation of the hash that needs to get
        signed for index input_index'''
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
                    script_sig = tx_in.script_pubkey(self.testnet)
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
            all_prevouts = b''
            all_sequence = b''
            for tx_in in self.tx_ins:
                all_prevouts += tx_in.prev_tx[::-1] + int_to_little_endian(tx_in.prev_index, 4)
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
            all_outputs = b''
            for tx_out in self.tx_outs:
                all_outputs += tx_out.serialize()
            self._hash_outputs = hash256(all_outputs)
        return self._hash_outputs

    def sig_hash_bip143(self, input_index, redeem_script=None, witness_script=None):
        '''Returns the integer representation of the hash that needs to get
        signed for index input_index'''
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
            # get the script pubkey associated with the previous output (remember testnet)
            script_pubkey = tx_in.script_pubkey(self.testnet)
            # next get the hash160 in the script_pubkey. for p2wpkh, it's the second command
            h160 = script_pubkey.commands[1]
            # finally the ScriptCode is the P2PKHScriptPubKey created using the hash160
            script_code = P2PKHScriptPubKey(h160)
        # add the serialized ScriptCode
        s += script_code.serialize()
        # add the value of the input in 8 bytes, little endian
        s += int_to_little_endian(tx_in.value(testnet=self.testnet), 8)
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
        '''Returns whether the input has a valid signature'''
        # get the relevant input
        tx_in = self.tx_ins[input_index]
        # get the script_pubkey of the input
        script_pubkey = tx_in.script_pubkey(testnet=self.testnet)
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
        if script_pubkey.is_p2wpkh() or (redeem_script and redeem_script.is_p2wpkh()) \
           or script_pubkey.is_p2wsh() or (redeem_script and redeem_script.is_p2wsh()):
            # calculate the z using sig_hash_bip143
            z = self.sig_hash_bip143(input_index, redeem_script, witness_script)
        else:
            # calculate z using legacy
            z = self.sig_hash(input_index, redeem_script)
        # combine the scripts
        combined_script = tx_in.script_sig + tx_in.script_pubkey(self.testnet)
        # evaluate the combined script
        return combined_script.evaluate(z, tx_in.witness)

    def verify(self):
        '''Verify this transaction'''
        if self.fee() < 0:
            return False
        for i in range(len(self.tx_ins)):
            if not self.verify_input(i):
                return False
        return True

    def sign_p2pkh(self, input_index, private_key):
        '''Signs the input assuming that the previous output is a p2pkh using the private key'''
        # get the sig using get_sig_legacy
        sig = self.get_sig_legacy(input_index, private_key)
        # calculate the sec
        sec = private_key.point.sec()
        # finalize the input using finalize_p2pkh
        self.tx_ins[input_index].finalize_p2pkh(sig, sec)
        # return whether sig is valid using self.verify_input
        return self.verify_input(input_index)

    def sign_p2wpkh(self, input_index, private_key):
        '''Signs the input assuming that the previous output is a p2pkh using the private key'''
        # get the sig using get_sig_segwit
        sig = self.get_sig_segwit(input_index, private_key)
        # calculate the sec
        sec = private_key.point.sec()
        # finalize the input using finalize_p2wpkh
        self.tx_ins[input_index].finalize_p2wpkh(sig, sec)
        # return whether sig is valid using self.verify_input
        return self.verify_input(input_index)

    def sign_p2sh_p2wpkh(self, input_index, private_key):
        '''Signs the input assuming that the previous output is a p2pkh using the private key'''
        # use p2sh_p2wpkh_redeem_script to get the RedeemScript
        redeem_script = private_key.point.p2sh_p2wpkh_redeem_script()
        # get the sig using get_sig_segwit
        sig = self.get_sig_segwit(input_index, private_key, redeem_script=redeem_script)
        # calculate the sec
        sec = private_key.point.sec()
        # finalize the input using finalize_p2wpkh
        self.tx_ins[input_index].finalize_p2wpkh(sig, sec, redeem_script)
        # return whether sig is valid using self.verify_input
        return self.verify_input(input_index)

    def sign_input(self, input_index, private_key, redeem_script=None):
        '''Signs the input by figuring out what type of ScriptPubKey the previous output was'''
        # get the input
        tx_in = self.tx_ins[input_index]
        # find the previous ScriptPubKey
        script_pubkey = tx_in.script_pubkey(testnet=self.testnet)
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
            raise RuntimeError('Unknown ScriptPubKey')

    def get_sig_legacy(self, input_index, private_key, redeem_script=None):
        # get the sig hash (z)
        z = self.sig_hash(input_index, redeem_script=redeem_script)
        # get der signature of z from private key
        der = private_key.sign(z).der()
        # append the SIGHASH_ALL with int_to_byte(SIGHASH_ALL)
        return der + int_to_byte(SIGHASH_ALL)

    def get_sig_segwit(self, input_index, private_key, redeem_script=None, witness_script=None):
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

    def check_sig_segwit(self, input_index, point, signature, redeem_script=None, witness_script=None):
        # get the sig_hash (z)
        z = self.sig_hash_bip143(input_index, redeem_script, witness_script)
        # return whether the signature verifies
        return point.verify(z, signature)

    def is_coinbase(self):
        '''Returns whether this transaction is a coinbase transaction or not'''
        # check that there is exactly 1 input
        if len(self.tx_ins) != 1:
            return False
        # grab the first input
        first_input = self.tx_ins[0]
        # check that first input prev_tx is b'\x00' * 32 bytes
        if first_input.prev_tx != b'\x00' * 32:
            return False
        # check that first input prev_index is 0xffffffff
        if first_input.prev_index != 0xffffffff:
            return False
        return True

    def coinbase_height(self):
        '''Returns the height of the block this coinbase transaction is in
        Returns None if this transaction is not a coinbase transaction
        '''
        # if this is NOT a coinbase transaction, return None
        if not self.is_coinbase():
            return None
        # grab the first input
        first_input = self.tx_ins[0]
        # grab the first command of the script_sig (.script_sig.commands[0])
        first_command = first_input.script_sig.commands[0]
        # convert the first command from little endian to int
        return little_endian_to_int(first_command)

    def find_utxos(self, address):
        '''Returns transaction outputs that matches the address'''
        h160 = decode_base58(address)
        # utxos are a list of tuples: (hash, index, amount)
        utxos = []
        for index, tx_out in enumerate(self.tx_outs):
            if tx_out.script_pubkey.hash160() == h160:
                utxos.append((self.hash(), index, tx_out.amount))
        return utxos

    def get_input_tx_lookup(self):
        '''Returns the tx lookup dictionary of hashes to the Tx objects
        for all the input transactions.'''
        tx_lookup = {}
        for tx_in in self.tx_ins:
            tx_obj = TxFetcher.fetch(tx_in.prev_tx.hex(), testnet=self.testnet)
            tx_lookup[tx_obj.hash()] = tx_obj
        return tx_lookup


class TxIn:
    def __init__(self, prev_tx, prev_index, script_sig=None, sequence=0xffffffff):
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
        return '{}:{}'.format(
            self.prev_tx.hex(),
            self.prev_index,
        )

    @classmethod
    def parse(cls, s):
        '''Takes a byte stream and parses the tx_input at the start
        return a TxIn object
        '''
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
        '''Returns the byte serialization of the transaction input'''
        # serialize prev_tx, little endian
        result = self.prev_tx[::-1]
        # serialize prev_index, 4 bytes, little endian
        result += int_to_little_endian(self.prev_index, 4)
        # serialize the script_sig
        result += self.script_sig.serialize()
        # serialize sequence, 4 bytes, little endian
        result += int_to_little_endian(self.sequence, 4)
        return result

    def fetch_tx(self, testnet=False):
        return TxFetcher.fetch(self.prev_tx.hex(), testnet=testnet)

    def value(self, testnet=False):
        '''Get the outpoint value by looking up the tx hash
        Returns the amount in satoshi
        '''
        if self._value is None:
            # use self.fetch_tx to get the transaction
            tx = self.fetch_tx(testnet=testnet)
            # get the output at self.prev_index
            self._value = tx.tx_outs[self.prev_index].amount
        return self._value

    def script_pubkey(self, testnet=False):
        '''Get the scriptPubKey by looking up the tx hash
        Returns a Script object
        '''
        if self._script_pubkey is None:
            # use self.fetch_tx to get the transaction
            tx = self.fetch_tx(testnet=testnet)
            # get the output at self.prev_index
            self._script_pubkey = tx.tx_outs[self.prev_index].script_pubkey
        return self._script_pubkey

    def finalize_p2pkh(self, sig, sec):
        '''Puts together the ScriptSig for a p2pkh input so the input verifies.'''
        # the ScriptSig for p2pkh is [sig, sec]
        self.script_sig = Script([sig, sec])

    def finalize_p2wpkh(self, sig, sec, redeem_script=None):
        '''Puts together the ScriptSig and Witness for a p2wpkh input so the input verifies.'''
        # if the RedeemScript is given, the ScriptSig is a single element Script of its raw serialization
        if redeem_script:
            self.script_sig = Script([redeem_script.raw_serialize()])
        # else the ScriptSig should be empty
        else:
            self.script_sig = Script()
        # the Witness for p2wpkh is [sig, sec]
        self.witness = Witness([sig, sec])

    def finalize_p2sh_multisig(self, signatures, redeem_script):
        '''Puts together the signatures for a p2sh input so the input verifies.'''
        # the ScriptSig for p2sh multisig is [0, each signature, then the RedeemScript (raw-serialization)]
        script_sig = Script([0, *signatures, redeem_script.raw_serialize()])
        # set the witness of the input to be these items
        self.script_sig = script_sig

    def finalize_p2wsh_multisig(self, signatures, witness_script):
        '''Puts together the signatures for a p2wsh input so the input verifies.'''
        # the format for multisig is [b'\x00', each signature, then the WitnessScript (raw-serialization)]
        items = [b'\x00', *signatures, witness_script.raw_serialize()]
        # set the witness of the input to be these items
        self.witness = Witness(items)

    def finalize_p2sh_p2wsh_multisig(self, signatures, witness_script):
        '''Puts together the signatures for a p2sh-p2wsh input so the input verifies.'''
        # the format for multisig is [b'\x00', each signature, then the WitnessScript (raw-serialization)]
        items = [b'\x00', *signatures, witness_script.raw_serialize()]
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
        return '{}:{}'.format(self.amount, self.script_pubkey)

    @classmethod
    def parse(cls, s):
        '''Takes a byte stream and parses the tx_output at the start
        return a TxOut object
        '''
        # s.read(n) will return n bytes
        # amount is 8 bytes, little endian, interpret as int
        amount = little_endian_to_int(s.read(8))
        # script_pubkey is a variable field (length followed by the data)
        # you can use Script.parse to get the actual script
        script_pubkey = ScriptPubKey.parse(s)
        # return an instance of the class (cls(...))
        return cls(amount, script_pubkey)

    def serialize(self):
        '''Returns the byte serialization of the transaction output'''
        # serialize amount, 8 bytes, little endian
        result = int_to_little_endian(self.amount, 8)
        # serialize the script_pubkey
        result += self.script_pubkey.serialize()
        return result


class TxTest(TestCase):
    cache_file = 'tx.cache'

    @classmethod
    def setUpClass(cls):
        # fill with cache so we don't have to be online to run these tests
        TxFetcher.load_cache(cls.cache_file)

    def test_parse_version(self):
        raw_tx = bytes.fromhex('0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600')
        stream = BytesIO(raw_tx)
        tx = Tx.parse(stream)
        self.assertEqual(tx.version, 1)

    def test_parse_inputs(self):
        raw_tx = bytes.fromhex('0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600')
        stream = BytesIO(raw_tx)
        tx = Tx.parse(stream)
        self.assertEqual(len(tx.tx_ins), 1)
        want = bytes.fromhex('d1c789a9c60383bf715f3f6ad9d14b91fe55f3deb369fe5d9280cb1a01793f81')
        self.assertEqual(tx.tx_ins[0].prev_tx, want)
        self.assertEqual(tx.tx_ins[0].prev_index, 0)
        want = bytes.fromhex('6b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278a')
        self.assertEqual(tx.tx_ins[0].script_sig.serialize(), want)
        self.assertEqual(tx.tx_ins[0].sequence, 0xfffffffe)

    def test_parse_outputs(self):
        raw_tx = bytes.fromhex('0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600')
        stream = BytesIO(raw_tx)
        tx = Tx.parse(stream)
        self.assertEqual(len(tx.tx_outs), 2)
        want = 32454049
        self.assertEqual(tx.tx_outs[0].amount, want)
        want = bytes.fromhex('1976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac')
        self.assertEqual(tx.tx_outs[0].script_pubkey.serialize(), want)
        want = 10011545
        self.assertEqual(tx.tx_outs[1].amount, want)
        want = bytes.fromhex('1976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac')
        self.assertEqual(tx.tx_outs[1].script_pubkey.serialize(), want)

    def test_parse_locktime(self):
        raw_tx = bytes.fromhex('0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600')
        stream = BytesIO(raw_tx)
        tx = Tx.parse(stream)
        self.assertEqual(tx.locktime, 410393)

    def test_parse_segwit(self):
        raw_tx = bytes.fromhex('01000000000101c70c4ede5731f1b47a89d133be9244927fa12e15778ec78a7e071273c0c58a870400000000ffffffff02809698000000000017a9144f34d55c56f827169921df008e8dfdc23678fc1787d464da1f00000000220020701a8d401c84fb13e6baf169d59684e17abd9fa216c8cc5b9fc63d622ff8c58d0400473044022050a5a50e78e6f9c65b5d94c78f8e4b339848456ff7c2231702b4a37439e2a3bd02201569cbf1c672bbb1608d6e9feea28705d8d6e54aa51d9fa396469be6ffc83c2d0147304402200b69a83cc3e3e1694037ef639049b0ece00f15718a03e9038aa42ac9d1bd0ea50220780c510821cd5205e5d178e6277005f4dd61a7fcccd4f8fae9e2d2adc355e728016952210375e00eb72e29da82b89367947f29ef34afb75e8654f6ea368e0acdfd92976b7c2103a1b26313f430c4b15bb1fdce663207659d8cac749a0e53d70eff01874496feff2103c96d495bfdd5ba4145e3e046fee45e84a8a48ad05bd8dbb395c011a32cf9f88053ae00000000')
        stream = BytesIO(raw_tx)
        tx = Tx.parse(stream)
        self.assertTrue(tx.segwit)
        self.assertEqual(tx.version, 1)
        self.assertEqual(tx.tx_ins[0].prev_index, 4)
        self.assertEqual(tx.tx_outs[0].amount, 10000000)
        self.assertEqual(tx.locktime, 0)

    def test_serialize(self):
        raw_tx = bytes.fromhex('0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600')
        stream = BytesIO(raw_tx)
        tx = Tx.parse(stream)
        self.assertEqual(tx.serialize(), raw_tx)

    def test_serialize_segwit(self):
        raw_tx = bytes.fromhex('01000000000101c70c4ede5731f1b47a89d133be9244927fa12e15778ec78a7e071273c0c58a870400000000ffffffff02809698000000000017a9144f34d55c56f827169921df008e8dfdc23678fc1787d464da1f00000000220020701a8d401c84fb13e6baf169d59684e17abd9fa216c8cc5b9fc63d622ff8c58d0400473044022050a5a50e78e6f9c65b5d94c78f8e4b339848456ff7c2231702b4a37439e2a3bd02201569cbf1c672bbb1608d6e9feea28705d8d6e54aa51d9fa396469be6ffc83c2d0147304402200b69a83cc3e3e1694037ef639049b0ece00f15718a03e9038aa42ac9d1bd0ea50220780c510821cd5205e5d178e6277005f4dd61a7fcccd4f8fae9e2d2adc355e728016952210375e00eb72e29da82b89367947f29ef34afb75e8654f6ea368e0acdfd92976b7c2103a1b26313f430c4b15bb1fdce663207659d8cac749a0e53d70eff01874496feff2103c96d495bfdd5ba4145e3e046fee45e84a8a48ad05bd8dbb395c011a32cf9f88053ae00000000')
        stream = BytesIO(raw_tx)
        tx = Tx.parse(stream)
        self.assertEqual(tx.serialize(), raw_tx)

    def test_input_value(self):
        tx_hash = 'd1c789a9c60383bf715f3f6ad9d14b91fe55f3deb369fe5d9280cb1a01793f81'
        index = 0
        want = 42505594
        tx_in = TxIn(bytes.fromhex(tx_hash), index)
        self.assertEqual(tx_in.value(), want)

    def test_input_pubkey(self):
        tx_hash = 'd1c789a9c60383bf715f3f6ad9d14b91fe55f3deb369fe5d9280cb1a01793f81'
        index = 0
        tx_in = TxIn(bytes.fromhex(tx_hash), index)
        want = bytes.fromhex('1976a914a802fc56c704ce87c42d7c92eb75e7896bdc41ae88ac')
        self.assertEqual(tx_in.script_pubkey().serialize(), want)

    def test_fee(self):
        raw_tx = bytes.fromhex('0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600')
        stream = BytesIO(raw_tx)
        tx = Tx.parse(stream)
        self.assertEqual(tx.fee(), 40000)
        raw_tx = bytes.fromhex('010000000456919960ac691763688d3d3bcea9ad6ecaf875df5339e148a1fc61c6ed7a069e010000006a47304402204585bcdef85e6b1c6af5c2669d4830ff86e42dd205c0e089bc2a821657e951c002201024a10366077f87d6bce1f7100ad8cfa8a064b39d4e8fe4ea13a7b71aa8180f012102f0da57e85eec2934a82a585ea337ce2f4998b50ae699dd79f5880e253dafafb7feffffffeb8f51f4038dc17e6313cf831d4f02281c2a468bde0fafd37f1bf882729e7fd3000000006a47304402207899531a52d59a6de200179928ca900254a36b8dff8bb75f5f5d71b1cdc26125022008b422690b8461cb52c3cc30330b23d574351872b7c361e9aae3649071c1a7160121035d5c93d9ac96881f19ba1f686f15f009ded7c62efe85a872e6a19b43c15a2937feffffff567bf40595119d1bb8a3037c356efd56170b64cbcc160fb028fa10704b45d775000000006a47304402204c7c7818424c7f7911da6cddc59655a70af1cb5eaf17c69dadbfc74ffa0b662f02207599e08bc8023693ad4e9527dc42c34210f7a7d1d1ddfc8492b654a11e7620a0012102158b46fbdff65d0172b7989aec8850aa0dae49abfb84c81ae6e5b251a58ace5cfeffffffd63a5e6c16e620f86f375925b21cabaf736c779f88fd04dcad51d26690f7f345010000006a47304402200633ea0d3314bea0d95b3cd8dadb2ef79ea8331ffe1e61f762c0f6daea0fabde022029f23b3e9c30f080446150b23852028751635dcee2be669c2a1686a4b5edf304012103ffd6f4a67e94aba353a00882e563ff2722eb4cff0ad6006e86ee20dfe7520d55feffffff0251430f00000000001976a914ab0c0b2e98b1ab6dbf67d4750b0a56244948a87988ac005a6202000000001976a9143c82d7df364eb6c75be8c80df2b3eda8db57397088ac46430600')
        stream = BytesIO(raw_tx)
        tx = Tx.parse(stream)
        self.assertEqual(tx.fee(), 140500)

    def test_sig_hash(self):
        raw_tx = bytes.fromhex('0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600')
        stream = BytesIO(raw_tx)
        tx = Tx.parse(stream)
        want = int('27e0c5994dec7824e56dec6b2fcb342eb7cdb0d0957c2fce9882f715e85d81a6', 16)
        self.assertEqual(tx.sig_hash(0), want)

    def test_sig_hash_bip143(self):
        raw_tx = bytes.fromhex('0100000000010115e180dc28a2327e687facc33f10f2a20da717e5548406f7ae8b4c811072f8560100000000ffffffff0100b4f505000000001976a9141d7cd6c75c2e86f4cbf98eaed221b30bd9a0b92888ac02483045022100df7b7e5cda14ddf91290e02ea10786e03eb11ee36ec02dd862fe9a326bbcb7fd02203f5b4496b667e6e281cc654a2da9e4f08660c620a1051337fa8965f727eb19190121038262a6c6cec93c2d3ecd6c6072efea86d02ff8e3328bbd0242b20af3425990ac00000000')
        stream = BytesIO(raw_tx)
        tx = Tx.parse(stream, testnet=True)
        want = int('12bb9e0988736b8d1c3a180acd828b8a7eddae923a6a4bf0b4c14c40cd7327d1', 16)
        self.assertEqual(tx.sig_hash(0), want)

    def test_verify_p2pkh(self):
        tx = TxFetcher.fetch('452c629d67e41baec3ac6f04fe744b4b9617f8f859c63b3002f8684e7a4fee03')
        self.assertTrue(tx.verify())
        tx = TxFetcher.fetch('5418099cc755cb9dd3ebc6cf1a7888ad53a1a3beb5a025bce89eb1bf7f1650a2', testnet=True)
        self.assertTrue(tx.verify())

    def test_verify_p2sh(self):
        tx = TxFetcher.fetch('46df1a9484d0a81d03ce0ee543ab6e1a23ed06175c104a178268fad381216c2b')
        self.assertTrue(tx.verify())

    def test_verify_p2wpkh(self):
        tx = TxFetcher.fetch('d869f854e1f8788bcff294cc83b280942a8c728de71eb709a2c29d10bfe21b7c', testnet=True)
        self.assertTrue(tx.verify())

    def test_verify_p2sh_p2wpkh(self):
        tx = TxFetcher.fetch('c586389e5e4b3acb9d6c8be1c19ae8ab2795397633176f5a6442a261bbdefc3a')
        self.assertTrue(tx.verify())

    def test_verify_p2wsh(self):
        tx = TxFetcher.fetch('78457666f82c28aa37b74b506745a7c7684dc7842a52a457b09f09446721e11c', testnet=True)
        self.assertTrue(tx.verify())

    def test_sign_p2pkh(self):
        private_key = PrivateKey(secret=8675309)
        tx_ins = []
        prev_tx = bytes.fromhex('0025bc3c0fa8b7eb55b9437fdbd016870d18e0df0ace7bc9864efc38414147c8')
        tx_ins.append(TxIn(prev_tx, 0))
        tx_outs = []
        h160 = decode_base58('mzx5YhAH9kNHtcN481u6WkjeHjYtVeKVh2')
        tx_outs.append(TxOut(amount=int(0.99 * 100000000), script_pubkey=P2PKHScriptPubKey(h160)))
        h160 = decode_base58('mnrVtF8DWjMu839VW3rBfgYaAfKk8983Xf')
        tx_outs.append(TxOut(amount=int(0.1 * 100000000), script_pubkey=P2PKHScriptPubKey(h160)))
        tx = Tx(1, tx_ins, tx_outs, 0, testnet=True)
        self.assertTrue(tx.sign_p2pkh(0, private_key))

    def test_sign_p2wpkh(self):
        private_key = PrivateKey(secret=8675309)
        prev_tx = bytes.fromhex('6bfa079532dd9fad6cfbf218edc294fdfa7dd0cb3956375bc864577fb36fad97')
        prev_index = 0
        fee = 500
        tx_in = TxIn(prev_tx, prev_index)
        amount = tx_in.value(testnet=True) - fee
        h160 = decode_base58('mqYz6JpuKukHzPg94y4XNDdPCEJrNkLQcv')
        tx_out = TxOut(amount=amount, script_pubkey=P2PKHScriptPubKey(h160))
        t = Tx(1, [tx_in], [tx_out], 0, testnet=True, segwit=True)
        self.assertTrue(t.sign_input(0, private_key))
        want = '0100000000010197ad6fb37f5764c85b375639cbd07dfafd94c2ed18f2fb6cad9fdd329507fa6b0000000000ffffffff014c400f00000000001976a9146e13971913b9aa89659a9f53d327baa8826f2d7588ac02483045022100feab5b8feefd5e774bdfdc1dc23525b40f1ffaa25a376f8453158614f00fa6cb02204456493d0bc606ebeb3fa008e056bbc96a67cb0c11abcc871bfc2bec60206bf0012103935581e52c354cd2f484fe8ed83af7a3097005b2f9c60bff71d35bd795f54b6700000000'
        self.assertEqual(t.serialize().hex(), want)

    def test_sign_p2sh_p2wpkh(self):
        private_key = PrivateKey(secret=8675309)
        redeem_script = private_key.point.p2sh_p2wpkh_redeem_script()
        prev_tx = bytes.fromhex('2e19b463bd5c8a3e0f10ae827f5a670f6794fca96394ecf8488321291d1c2ee9')
        prev_index = 1
        fee = 500
        tx_in = TxIn(prev_tx, prev_index)
        amount = tx_in.value(testnet=True) - fee
        h160 = decode_base58('mqYz6JpuKukHzPg94y4XNDdPCEJrNkLQcv')
        tx_out = TxOut(amount=amount, script_pubkey=P2PKHScriptPubKey(h160))
        t = Tx(1, [tx_in], [tx_out], 0, testnet=True, segwit=True)
        self.assertTrue(t.sign_input(0, private_key, redeem_script=redeem_script))
        want = '01000000000101e92e1c1d29218348f8ec9463a9fc94670f675a7f82ae100f3e8a5cbd63b4192e0100000017160014d52ad7ca9b3d096a38e752c2018e6fbc40cdf26fffffffff014c400f00000000001976a9146e13971913b9aa89659a9f53d327baa8826f2d7588ac0247304402205e3ae5ac9a0e0a16ae04b0678c5732973ce31051ba9f42193e69843e600d84f2022060a91cbd48899b1bf5d1ffb7532f69ab74bc1701a253a415196b38feb599163b012103935581e52c354cd2f484fe8ed83af7a3097005b2f9c60bff71d35bd795f54b6700000000'
        self.assertEqual(t.serialize().hex(), want)

    def test_sign_input(self):
        private_key = PrivateKey(secret=8675309)
        tx_ins = []
        prev_tx = bytes.fromhex('0025bc3c0fa8b7eb55b9437fdbd016870d18e0df0ace7bc9864efc38414147c8')
        tx_ins.append(TxIn(prev_tx, 0))
        tx_outs = []
        h160 = decode_base58('mzx5YhAH9kNHtcN481u6WkjeHjYtVeKVh2')
        tx_outs.append(TxOut(amount=int(0.99 * 100000000), script_pubkey=P2PKHScriptPubKey(h160)))
        h160 = decode_base58('mnrVtF8DWjMu839VW3rBfgYaAfKk8983Xf')
        tx_outs.append(TxOut(amount=int(0.1 * 100000000), script_pubkey=P2PKHScriptPubKey(h160)))
        tx = Tx(1, tx_ins, tx_outs, 0, testnet=True)
        self.assertTrue(tx.sign_input(0, private_key))

    def test_sign_p2sh_multisig(self):
        private_key1 = PrivateKey(secret=8675309)
        private_key2 = PrivateKey(secret=8675310)
        redeem_script = RedeemScript([0x52, private_key1.point.sec(), private_key2.point.sec(), 0x52, 0xae])
        prev_tx = bytes.fromhex('ded9b3c8b71032d42ea3b2fd5211d75b39a90637f967e637b64dfdb887dd11d7')
        prev_index = 1
        fee = 500
        tx_in = TxIn(prev_tx, prev_index)
        amount = tx_in.value(testnet=True) - fee
        h160 = decode_base58('mqYz6JpuKukHzPg94y4XNDdPCEJrNkLQcv')
        tx_out = TxOut(amount=amount, script_pubkey=P2PKHScriptPubKey(h160))
        t = Tx(1, [tx_in], [tx_out], 0, testnet=True, segwit=True)
        sig1 = t.get_sig_legacy(0, private_key1, redeem_script=redeem_script)
        sig2 = t.get_sig_legacy(0, private_key2, redeem_script=redeem_script)
        self.assertTrue(t.check_sig_legacy(0, private_key1.point, Signature.parse(sig1[:-1]), redeem_script=redeem_script))
        self.assertTrue(t.check_sig_legacy(0, private_key2.point, Signature.parse(sig2[:-1]), redeem_script=redeem_script))
        tx_in.finalize_p2sh_multisig([sig1, sig2], redeem_script)
        want = '01000000000101d711dd87b8fd4db637e667f93706a9395bd71152fdb2a32ed43210b7c8b3d9de01000000da00483045022100c457fa45f63636eb2552cef642116a8363469d60b99dcda19686d30ed2a539bb0220222c7617e3dd9aef37095df52047e9a6bf11254a88eab521aec1b8b4e7913b3401473044022003d3d6a1b232b42d9fb961b42ab6854077a1e195473d952d54e6dcf22ef6dede02206f62a44b65e1dbccbdd54a3fd6f87c05a8d8da39c70e06f5ee07d469e1155e020147522103935581e52c354cd2f484fe8ed83af7a3097005b2f9c60bff71d35bd795f54b672103674944c63d8dc3373a88cd1f8403b39b48be07bdb83d51dbbaa34be070c72e1452aeffffffff014c400f00000000001976a9146e13971913b9aa89659a9f53d327baa8826f2d7588ac0000000000'
        self.assertEqual(t.serialize().hex(), want)

    def test_sign_p2wsh_multisig(self):
        private_key1 = PrivateKey(secret=8675309)
        private_key2 = PrivateKey(secret=8675310)
        witness_script = WitnessScript([0x52, private_key1.point.sec(), private_key2.point.sec(), 0x52, 0xae])
        prev_tx = bytes.fromhex('61cd20e3ffdf9216cee9cd607e1a65d3096513c4df3a63d410c047379b54a94a')
        prev_index = 1
        fee = 500
        tx_in = TxIn(prev_tx, prev_index)
        amount = tx_in.value(testnet=True) - fee
        h160 = decode_base58('mqYz6JpuKukHzPg94y4XNDdPCEJrNkLQcv')
        tx_out = TxOut(amount=amount, script_pubkey=P2PKHScriptPubKey(h160))
        t = Tx(1, [tx_in], [tx_out], 0, testnet=True, segwit=True)
        sig1 = t.get_sig_segwit(0, private_key1, witness_script=witness_script)
        sig2 = t.get_sig_segwit(0, private_key2, witness_script=witness_script)
        self.assertTrue(t.check_sig_segwit(0, private_key1.point, Signature.parse(sig1[:-1]), witness_script=witness_script))
        self.assertTrue(t.check_sig_segwit(0, private_key2.point, Signature.parse(sig2[:-1]), witness_script=witness_script))
        tx_in.finalize_p2wsh_multisig([sig1, sig2], witness_script)
        want = '010000000001014aa9549b3747c010d4633adfc4136509d3651a7e60cde9ce1692dfffe320cd610100000000ffffffff014c400f00000000001976a9146e13971913b9aa89659a9f53d327baa8826f2d7588ac04004730440220325e9f389c4835dab74d644e8c8e295535d9b082d28aefc3fa127e23538051bd022050d68dcecda660d4c01a8443c2b30bd0b3e4b1a405b0f352dcb068210862f6810147304402201abceabfc94903644cf7be836876eaa418cb226e03554c17a71c65b232f4507302202105a8344abae9632d1bc8249a52cf651c4ea02ca5259e20b50d8169c949f5a20147522103935581e52c354cd2f484fe8ed83af7a3097005b2f9c60bff71d35bd795f54b672103674944c63d8dc3373a88cd1f8403b39b48be07bdb83d51dbbaa34be070c72e1452ae00000000'
        self.assertEqual(t.serialize().hex(), want)

    def test_sign_p2sh_p2wsh_multisig(self):
        private_key1 = PrivateKey(secret=8675309)
        private_key2 = PrivateKey(secret=8675310)
        witness_script = WitnessScript([0x52, private_key1.point.sec(), private_key2.point.sec(), 0x52, 0xae])
        prev_tx = bytes.fromhex('f92c8c8e40296c6a94539b6d22d8994a56dd8ff2d6018d07a8371fef1f66efee')
        prev_index = 0
        fee = 500
        tx_in = TxIn(prev_tx, prev_index)
        amount = tx_in.value(testnet=True) - fee
        h160 = decode_base58('mqYz6JpuKukHzPg94y4XNDdPCEJrNkLQcv')
        tx_out = TxOut(amount=amount, script_pubkey=P2PKHScriptPubKey(h160))
        t = Tx(1, [tx_in], [tx_out], 0, testnet=True, segwit=True)
        sig1 = t.get_sig_segwit(0, private_key1, witness_script=witness_script)
        sig2 = t.get_sig_segwit(0, private_key2, witness_script=witness_script)
        self.assertTrue(t.check_sig_segwit(0, private_key1.point, Signature.parse(sig1[:-1]), witness_script=witness_script))
        self.assertTrue(t.check_sig_segwit(0, private_key2.point, Signature.parse(sig2[:-1]), witness_script=witness_script))
        tx_in.finalize_p2sh_p2wsh_multisig([sig1, sig2], witness_script)
        want = '01000000000101eeef661fef1f37a8078d01d6f28fdd564a99d8226d9b53946a6c29408e8c2cf900000000232200206ddafd1089f07a2ba9868df71f622801fe11f5452c6ff1f8f51573133828b437ffffffff014c400f00000000001976a9146e13971913b9aa89659a9f53d327baa8826f2d7588ac0400483045022100d31433973b7f8014a4e17d46c4720c6c9bed1ee720dc1f0839dd847fa6972553022039278e98a3c18f4748a2727b99acd41eb1534dcf041a3abefd0c7546c868f55801473044022027be7d616b0930c1edf7ed39cc99edf5975e7b859d3224fe340d55c595c2798f02206c05662d39e5b05cc13f936360d62a482b122ad9791074bbdafec3ddc221b8c00147522103935581e52c354cd2f484fe8ed83af7a3097005b2f9c60bff71d35bd795f54b672103674944c63d8dc3373a88cd1f8403b39b48be07bdb83d51dbbaa34be070c72e1452ae00000000'
        self.assertEqual(t.serialize().hex(), want)

    def test_is_coinbase(self):
        raw_tx = bytes.fromhex('01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff5e03d71b07254d696e656420627920416e74506f6f6c20626a31312f4542312f4144362f43205914293101fabe6d6d678e2c8c34afc36896e7d9402824ed38e856676ee94bfdb0c6c4bcd8b2e5666a0400000000000000c7270000a5e00e00ffffffff01faf20b58000000001976a914338c84849423992471bffb1a54a8d9b1d69dc28a88ac00000000')
        stream = BytesIO(raw_tx)
        tx = Tx.parse(stream)
        self.assertTrue(tx.is_coinbase())

    def test_coinbase_height(self):
        raw_tx = bytes.fromhex('01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff5e03d71b07254d696e656420627920416e74506f6f6c20626a31312f4542312f4144362f43205914293101fabe6d6d678e2c8c34afc36896e7d9402824ed38e856676ee94bfdb0c6c4bcd8b2e5666a0400000000000000c7270000a5e00e00ffffffff01faf20b58000000001976a914338c84849423992471bffb1a54a8d9b1d69dc28a88ac00000000')
        stream = BytesIO(raw_tx)
        tx = Tx.parse(stream)
        self.assertEqual(tx.coinbase_height(), 465879)
        raw_tx = bytes.fromhex('0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600')
        stream = BytesIO(raw_tx)
        tx = Tx.parse(stream)
        self.assertIsNone(tx.coinbase_height())
