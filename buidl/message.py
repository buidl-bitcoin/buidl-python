from buidl.tx import Tx, TxIn, TxOut
from buidl.script import Script,P2WPKHScriptPubKey
from buidl.helper import big_endian_to_int, base64_decode, base64_encode, str_to_bytes

from buidl.script import address_to_script_pubkey
from buidl.hash import hash_bip322message
from buidl.witness import Witness

from buidl.ecc import PrivateKey

import io
from enum import Enum


class MessageSignatureFormat(Enum):
    LEGACY = 0
    SIMPLE = 1
    FULL = 2

# From BIP322
# The to_spend transaction is:
#
#    nVersion = 0
#    nLockTime = 0
#    vin[0].prevout.hash = 0000...000
#    vin[0].prevout.n = 0xFFFFFFFF
#    vin[0].nSequence = 0
#    vin[0].scriptSig = OP_0 PUSH32[ message_hash ]
#    vin[0].scriptWitness = []
#    vout[0].nValue = 0
#    vout[0].scriptPubKey = message_challenge
#
def create_to_spend_tx(address, message):
    # Not a valid Tx hash. Will never be spendable on any BTC network.
    prevout_hash = bytes.fromhex('0000000000000000000000000000000000000000000000000000000000000000')
    # prevout.n
    prevout_index = big_endian_to_int(bytes.fromhex('FFFFFFFF'))
    
    sequence = 0

    b_msg = str_to_bytes(message)
    message_hash = hash_bip322message(b_msg)

    # Note BIP322 to_spend scriptSig commands = [0, 32, message_hash]
    # PUSH32 is implied and added by the size of the message added to the stack
    commands = [0, message_hash]
    script_sig = Script(commands)
    # Create Tx Input
    tx_in = TxIn(prevout_hash,prevout_index,script_sig,sequence)
    
    # Value of tx output
    value = 0

    # Convert address to a ScriptPubKey
    script_pubkey = None
    try:
        script_pubkey = address_to_script_pubkey(address)
    except:
        raise ValueError("Invalid address")
        
    tx_out = TxOut(value,script_pubkey)
    
    # create transaction
    version=0
    tx_inputs = [tx_in]
    tx_outputs = [tx_out]
    locktime=0
    network="mainnet"

    # TODO: Should this always be True? What about for FULL BIP322 with p2pkh?
    segwit=True

    return Tx(version,tx_inputs,tx_outputs,locktime,network,segwit)

# From BIP322
# The to_sign Tx is:
#    nVersion = 0 or (FULL format only) as appropriate (e.g. 2, for time locks)
#    nLockTime = 0 or (FULL format only) as appropriate (for time locks)
#    vin[0].prevout.hash = to_spend.txid
#    vin[0].prevout.n = 0
#    vin[0].nSequence = 0 or (FULL format only) as appropriate (for time locks)
#    vin[0].scriptWitness = message_signature
#    vout[0].nValue = 0
#    vout[0].scriptPubKey = OP_RETURN
#
def create_to_sign_tx(to_spend_tx_hash, sig_bytes=None):

    if (sig_bytes and is_full_signature(sig_bytes)):
        
        sig_stream = io.BytesIO(sig_bytes)
        to_sign = Tx.parse(sig_stream)
        
        if (len(to_sign.tx_ins) > 1):
            # TODO: Implement Proof of Funds
            raise NotImplemented("Not yet implemented proof of funds yet")
        elif (len(to_sign.tx_ins) == 0):
            raise ValueError("No transaction input")
        elif (to_sign.tx_ins[0].prev_tx != to_spend_tx_hash):
            raise ValueError("The to_sign transaction input's prevtx id does not equal the calculated to_spend transaction id")
        elif (len(to_sign.tx_outs) != 1):
            raise ValueError("to_sign does not have a single TxOutput")
        elif (to_sign.tx_outs[0].amount != 0):
            raise ValueError("Value is Non 0", to_sign.tx_outs[0].amount)
        elif(to_sign.tx_outs[0].script_pubkey.commands != [106]):
            raise ValueError("ScriptPubKey incorrect", to_sign.tx_outs[0].script_pubkey)
        else:
            return to_sign
            
    else:
        # signature is either None or an encoded witness stack
        
        # Identifies the index of the output from the virtual to_spend tx to be "spent"
        prevout_index = 0
        sequence = 0
        # TxInput identifies the single output from the to_spend Tx
        tx_input = TxIn(to_spend_tx_hash,prevout_index,script_sig=None,sequence=sequence)
    
        value = 0
        # OP Code 106 for OP_RETURN
        commands = [106]
        scriptPubKey = Script(commands)

        tx_output = TxOut(value,scriptPubKey)
        locktime=0
        version=0
        tx_inputs = [tx_input]
        tx_outputs = [tx_output]
        network="mainnet"
        # is to_sign always a segwit?
        segwit=True
    
        # create unsigned to_sign transaction
        to_sign_tx = Tx(version,tx_inputs,tx_outputs,locktime,network,segwit)
        
        if sig_bytes:
            try:
                stream = io.BytesIO(sig_bytes)
                witness = Witness.parse(stream)
                # Set the witness on the to_sign tx input
                to_sign_tx.tx_ins[0].witness = witness
            except:
                # TODO: Fall back to legacy ...
                print("Signature is niether an encoded witness or full transaction. Fall back to legacy")
                return None
                
        return to_sign_tx

# Test if sig_bytes can be decoded to a transaction
# TODO: Is there a better way to test than this?
def is_full_signature(sig_bytes):
    try:
        sig_stream = io.BytesIO(sig_bytes)

        Tx.parse(sig_stream)
    # TODO: more specific exception handling
    except:
        return False
    return True
        

def sign_message(format: MessageSignatureFormat, private_key: PrivateKey, address: str, message: str):
    
    if (format != MessageSignatureFormat.LEGACY):
        return sign_message_bip322(format,private_key,address,message)

    script_pubkey = address_to_script_pubkey(address)
    
    if (not script_pubkey.is_p2pkh()):
        raise ValueError("Address must be p2pkh for LEGACY signatures")
        
    # TODO: This legacy signing needs to produce a compact encoding of signature AND public key
    # Needs implementing in the library I believe?
    raise NotImplementedError("Legacy signing not yet implemented. Require compact encoding of sig and pubkey")
    # b_msg = str_to_bytes(message)
    # signature = private_key.sign_message(b_msg)
    
    # return base64_encode(signature.der())    
    
def sign_message_bip322(format: MessageSignatureFormat, private_key: PrivateKey, address: str, message: str):
    
    assert(format != MessageSignatureFormat.LEGACY)
      
    to_spend = create_to_spend_tx(address, message)
    to_sign = create_to_sign_tx(to_spend.hash(), None)
    
    to_sign.tx_ins[0]._script_pubkey = to_spend.tx_outs[0].script_pubkey
    to_sign.tx_ins[0]._value = to_spend.tx_outs[0].amount
    
    sig_ok = to_sign.sign_input(0, private_key)
    
    # Force the format to FULL, to_sign tx signed using a p2pkh scriptPubKey
    if (len(to_sign.tx_ins[0].script_sig.commands) > 0 or len(to_sign.tx_ins[0].witness.items) == 0):
        format = MessageSignatureFormat.FULL

    if (not sig_ok):
        # TODO: this may be a multisig which successfully signed but needed additional signatures
        raise RuntimeError("Unable to sign message")
    
    if (format ==  MessageSignatureFormat.SIMPLE):
            return base64_encode(to_sign.serialize_witness())
    else:
        return base64_encode(to_sign.serialize())


def verify_message(address: str, signature: str, message: str):
    try:
        sig_bytes = base64_decode(signature)
    except:
        raise ValueError("Signature is not base64 encoded")
        
    to_spend = create_to_spend_tx(address, message)
    to_sign = create_to_sign_tx(to_spend.hash(), sig_bytes)
    
    if to_sign == None:
        # try LEGACY
        # Check address is a p2pkh
        # Recover Secp256 point from BIP322 signature?
        # Verify signature
        raise NotImplementedError("Unable to verify LEGACY signatures currently")
    
    to_sign.tx_ins[0]._script_pubkey = to_spend.tx_outs[0].script_pubkey
    to_sign.tx_ins[0]._value = to_spend.tx_outs[0].amount
    return to_sign.verify_input(0)
    