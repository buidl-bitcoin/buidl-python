from buidl.helper import (
    bits_to_target,
    hash256,
    int_to_little_endian,
    little_endian_to_int,
    merkle_root,
    read_varint,
)
from buidl.tx import Tx


GENESIS_BLOCK_HASH = {
    "mainnet": bytes.fromhex(
        "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
    ),
    "testnet": bytes.fromhex(
        "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943"
    ),
    "signet": bytes.fromhex(
        "00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6"
    ),
}


class Block:
    command = b"block"

    def __init__(
        self,
        version,
        prev_block,
        merkle_root,
        timestamp,
        bits,
        nonce,
        txs=None,
        tx_hashes=None,
    ):
        self.version = version
        self.prev_block = prev_block
        self.merkle_root = merkle_root
        self.timestamp = timestamp
        self.bits = bits
        self.nonce = nonce
        self.txs = txs
        self.tx_hashes = tx_hashes
        self.merkle_tree = None

    def __repr__(self):
        return f"""
Version: {self.version}
Previous: {self.prev_block.hex()}
Merkle Root: {self.merkle_root.hex()}
Timestamp: {self.timestamp}
Bits: {self.bits[::-1].hex()}
Nonce: {self.nonce.hex()}
Num txs: {"unknown" if self.txs is None else len(self.txs)}
"""

    @classmethod
    def parse_header(cls, s):
        """Takes a byte stream and parses block headers. Returns a Block object"""
        # s.read(n) will read n bytes from the stream
        # version - 4 bytes, little endian, interpret as int
        version = little_endian_to_int(s.read(4))
        # prev_block - 32 bytes, little endian (use [::-1] to reverse)
        prev_block = s.read(32)[::-1]
        # merkle_root - 32 bytes, little endian (use [::-1] to reverse)
        merkle_root = s.read(32)[::-1]
        # timestamp - 4 bytes, little endian, interpret as int
        timestamp = little_endian_to_int(s.read(4))
        # bits - 4 bytes
        bits = s.read(4)
        # nonce - 4 bytes
        nonce = s.read(4)
        # initialize class
        return cls(version, prev_block, merkle_root, timestamp, bits, nonce)

    @classmethod
    def parse(cls, s):
        """Takes a byte stream and parses a block. Returns a Block object"""
        b = cls.parse_header(s)
        num_txs = read_varint(s)
        b.txs = []
        b.tx_hashes = []
        for _ in range(num_txs):
            t = Tx.parse(s)
            b.txs.append(t)
            b.tx_hashes.append(t.hash())
        return b

    def serialize(self):
        """Returns the 80 byte block header"""
        # version - 4 bytes, little endian
        result = int_to_little_endian(self.version, 4)
        # prev_block - 32 bytes, little endian
        result += self.prev_block[::-1]
        # merkle_root - 32 bytes, little endian
        result += self.merkle_root[::-1]
        # timestamp - 4 bytes, little endian
        result += int_to_little_endian(self.timestamp, 4)
        # bits - 4 bytes
        result += self.bits
        # nonce - 4 bytes
        result += self.nonce
        return result

    def hash(self):
        """Returns the hash256 interpreted little endian of the block"""
        # serialize
        s = self.serialize()
        # hash256
        h256 = hash256(s)
        # reverse
        return h256[::-1]

    def id(self):
        """Human-readable hexadecimal of the block hash"""
        return self.hash().hex()

    def bip9(self):
        """Returns whether this block is signaling readiness for BIP9"""
        # BIP9 is signalled if the top 3 bits are 001
        # remember version is 32 bytes so right shift 29 (>> 29) and see if
        # that is 001
        return self.version >> 29 == 0b001

    def bip91(self):
        """Returns whether this block is signaling readiness for BIP91"""
        # BIP91 is signalled if the 5th bit from the right is 1
        # shift 4 bits to the right and see if the last bit is 1
        return self.version >> 4 & 1 == 1

    def bip141(self):
        """Returns whether this block is signaling readiness for BIP141"""
        # BIP91 is signalled if the 2nd bit from the right is 1
        # shift 1 bit to the right and see if the last bit is 1
        return self.version >> 1 & 1 == 1

    def target(self):
        """Returns the proof-of-work target based on the bits"""
        return bits_to_target(self.bits)

    def difficulty(self):
        """Returns the block difficulty based on the bits"""
        # note difficulty is (target of lowest difficulty) / (self's target)
        # lowest difficulty has bits that equal 0xffff001d
        lowest = 0xFFFF * 256 ** (0x1D - 3)
        return lowest / self.target()

    def check_pow(self):
        """Returns whether this block satisfies proof of work"""
        # get the hash256 of the serialization of this block
        h256 = hash256(self.serialize())
        # interpret this hash as a little-endian number
        proof = little_endian_to_int(h256)
        # return whether this integer is less than the target
        return proof < self.target()

    def validate_merkle_root(self):
        """Gets the merkle root of the tx_hashes and checks that it's
        the same as the merkle root of this block.
        """
        # reverse all the transaction hashes (self.tx_hashes)
        hashes = [h[::-1] for h in self.tx_hashes]
        # get the Merkle Root
        root = merkle_root(hashes)
        # reverse the Merkle Root
        # return whether self.merkle root is the same as
        # the reverse of the calculated merkle root
        return root[::-1] == self.merkle_root

    def get_outpoints(self):
        if not self.txs:
            return []
        for t in self.txs:
            for tx_out in t.tx_outs:
                if not tx_out.script_pubkey.has_op_return():
                    yield (tx_out.script_pubkey.raw_serialize())
