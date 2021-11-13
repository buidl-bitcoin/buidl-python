from buidl.ecc import S256Point
from buidl.helper import (
    big_endian_to_int,
    hash_tapbranch,
    hash_tapleaf,
    hash_taptweak,
    int_to_byte,
)
from buidl.script import P2TRScriptPubKey


class TapLeaf:
    def __init__(self, tapleaf_version, tap_script):
        self.tapleaf_version = tapleaf_version
        self.tap_script = tap_script

    def __eq__(self, other):
        return (
            type(self) == type(other)
            and self.tapleaf_version == other.tapleaf_version
            and self.tap_script == other.tap_script
        )

    def hash(self):
        return hash_tapleaf(
            int_to_byte(self.tapleaf_version) + self.tap_script.serialize()
        )

    def leaves(self):
        return [self]

    def path_hashes(self, leaf):
        return b""


class TapBranch:
    def __init__(self, left, right):
        for item in (left, right):
            if type(item) not in (TapBranch, TapLeaf):
                raise ValueError(
                    "TapBranch needs a TapBranch or TapLeaf as the left and right elements"
                )
        self.left = left
        self.right = right
        self._leaves = None

    def hash(self):
        left_hash = self.left.hash()
        right_hash = self.right.hash()
        if left_hash < right_hash:
            return hash_tapbranch(left_hash + right_hash)
        else:
            return hash_tapbranch(right_hash + left_hash)

    def leaves(self):
        if self._leaves is None:
            self._leaves = []
            self._leaves.extend(self.left.leaves())
            self._leaves.extend(self.right.leaves())
        return self._leaves

    def path_hashes(self, leaf):
        if leaf in self.left.leaves():
            return self.left.path_hashes(leaf) + self.right.hash()
        elif leaf in self.right.leaves():
            return self.right.path_hashes(leaf) + self.left.hash()
        else:
            return None


class TapRoot:
    def __init__(self, internal_pubkey, tap_node=None, merkle_root=None):
        self.internal_pubkey = S256Point.parse_bip340(internal_pubkey.bip340())
        self.tap_node = tap_node
        if merkle_root is not None:
            self.tweak = big_endian_to_int(
                hash_taptweak(internal_pubkey.bip340() + merkle_root)
            )
        elif tap_node is None:
            self.tweak = big_endian_to_int(hash_taptweak(internal_pubkey.bip340()))
        else:
            self.tweak = big_endian_to_int(
                hash_taptweak(internal_pubkey.bip340() + tap_node.hash())
            )
        self.tweak_point = self.internal_pubkey + self.tweak
        self.parity = self.tweak_point.parity

    def address(self, network="mainnet"):
        return self.script_pubkey().address(network=network)

    def bip340(self):
        return self.tweak_point.bip340()

    def script_pubkey(self):
        return P2TRScriptPubKey(self.tweak_point)

    def control_block(self, leaf):
        if self.tap_node is None:
            return None
        if leaf not in self.tap_node.leaves():
            return None
        raw = int_to_byte(leaf.tapleaf_version + self.tweak_point.parity)
        raw += self.internal_pubkey.bip340()
        raw += self.tap_node.path_hashes(leaf)
        return ControlBlock.parse(raw)


class ControlBlock:
    def __init__(self, tapleaf_version, parity, internal_pubkey, hashes):
        self.tapleaf_version = tapleaf_version
        self.parity = parity
        self.internal_pubkey = internal_pubkey
        self.hashes = hashes

    def __repr__(self):
        return f"{self.tapleaf_version}:{self.parity}:{self.internal_pubkey}"

    def __eq__(self, other):
        return self.serialize() == other.serialize()

    def merkle_root(self, leaf):
        current = leaf.hash()
        for h in self.hashes:
            if current < h:
                current = hash_tapbranch(current + h)
            else:
                current = hash_tapbranch(h + current)
        return current

    def tweak(self, leaf):
        return hash_taptweak(self.internal_pubkey.bip340() + self.merkle_root(leaf))

    def tweak_point(self, leaf):
        return self.internal_pubkey + big_endian_to_int(self.tweak(leaf))

    def serialize(self):
        s = int_to_byte(self.tapleaf_version + self.parity)
        s += self.internal_pubkey.bip340()
        for h in self.hashes:
            s += h
        return s

    @classmethod
    def parse(cls, b):
        b_len = len(b)
        if b_len % 32 != 1:
            raise ValueError("There should be 32*m+1 bytes where m is an integer")
        if b_len < 33 or b_len > 33 + 128 * 32:
            raise ValueError(f"length is outside the bounds {b_len}")
        tapleaf_version = b[0] & 0xFE
        parity = b[0] & 1
        internal_pubkey = S256Point.parse_bip340(b[1:33])
        m = (b_len - 33) // 32
        hashes = [b[33 + 32 * i : 65 + 32 * i] for i in range(m)]
        return cls(tapleaf_version, parity, internal_pubkey, hashes)
