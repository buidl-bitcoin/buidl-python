from itertools import combinations

from buidl.ecc import N, S256Point, SchnorrSignature
from buidl.helper import (
    big_endian_to_int,
    hash_challenge,
    hash_tapbranch,
    hash_tapleaf,
    hash_taptweak,
    int_to_big_endian,
    int_to_byte,
    sha256,
)
from buidl.op import (
    encode_minimal_num,
    number_to_op_code,
)
from buidl.script import ScriptPubKey, P2TRScriptPubKey
from buidl.timelock import Locktime, Sequence


def locktime_commands(locktime):
    assert type(locktime) == Locktime, f"{locktime} needs to be Locktime"
    # 0xB1 is OP_CLTV, 0x75 is OP_DROP
    return [encode_minimal_num(locktime), 0xB1, 0x75]


def sequence_commands(sequence):
    assert type(sequence) == Sequence, f"{sequence} needs to be Sequence"
    # 0xB2 is OP_CSV, 0x75 is OP_DROP
    return [encode_minimal_num(sequence), 0xB2, 0x75]


class TapLeaf:
    def __init__(self, tap_script, tapleaf_version=0xC0):
        self.tap_script = tap_script
        self.tapleaf_version = tapleaf_version

    def __repr__(self):
        return f"{self.tap_script}"

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

    @classmethod
    def combine(cls, nodes):
        if len(nodes) == 1:
            return nodes[0]
        half_way = len(nodes) // 2
        left = cls.combine(nodes[:half_way])
        right = cls.combine(nodes[half_way:])
        return cls(left, right)


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

    def leaves(self):
        if self.tap_node:
            return self.tap_node.leaves()
        else:
            return []

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


class TapScript(ScriptPubKey):
    def tap_leaf(self):
        return TapLeaf(self)


class P2PKTapScript(TapScript):
    def __init__(self, point):
        super().__init__()
        if type(point) == S256Point:
            raw_point = point.bip340()
        elif type(point) == bytes:
            raw_point = point
        else:
            raise TypeError("To initialize P2PKTapScript, a point is needed")
        self.commands = [raw_point, 0xAC]


class MultiSigTapScript(TapScript):
    def __init__(self, points, k, locktime=None, sequence=None):
        if locktime is not None and sequence is not None:
            raise ValueError(
                "Both locktime and sequence are defined. Only one of them should be."
            )
        super().__init__()
        if len(points) == 0:
            raise ValueError("To initialize MultiSigTapScript at least one point")
        bip340s = sorted([p.bip340() for p in points])
        self.points = [S256Point.parse_bip340(b) for b in bip340s]
        if locktime is not None:
            self.commands = locktime_commands(locktime)
        elif sequence is not None:
            self.commands = sequence_commands(sequence)
        else:
            self.commands = []
        self.commands += [bip340s[0], 0xAC]
        if len(points) > 1:
            for bip340 in bip340s[1:]:
                self.commands += [bip340, 0xBA]
            self.commands += [number_to_op_code(k), 0x87]


class MuSigTapScript(TapScript):
    def __init__(self, points, locktime=None, sequence=None):
        if locktime is not None and sequence is not None:
            raise ValueError(
                "Both locktime and sequence are defined. Only one of them should be."
            )
        super().__init__()
        if len(points) == 0:
            raise ValueError("Need at least one public key")
        bip340s = sorted([p.bip340() for p in points])
        self.points = [S256Point.parse_bip340(b) for b in bip340s]
        preimage = b""
        for b in bip340s:
            preimage += b
        self.commitment = sha256(preimage)
        self.hashes = [big_endian_to_int(sha256(self.commitment + b)) for b in bip340s]
        self.hash_lookup = {b: h for h, b in zip(self.hashes, bip340s)}
        points = [h * p for h, p in zip(self.hashes, self.points)]
        self.point = S256Point.combine(points)
        if locktime is not None:
            self.commands = locktime_commands(locktime)
        elif sequence is not None:
            self.commands = sequence_commands(sequence)
        else:
            self.commands = []
        self.commands += [self.point.bip340(), 0xAC]

    def get_tweak_point(self, tweak):
        if self.point.parity:
            return -1 * self.point + tweak
        else:
            return self.point + tweak

    def sign(self, private_key, k, r, sig_hash, tweak=0):
        tweak_point = self.get_tweak_point(tweak)
        msg = r.bip340() + tweak_point.bip340() + sig_hash
        challenge = big_endian_to_int(hash_challenge(msg)) % N
        h_i = self.hash_lookup[private_key.point.bip340()]
        c_i = h_i * challenge % N
        if r.parity == tweak_point.parity:
            k_real = k
        else:
            k_real = -k
        if self.point.parity == private_key.point.parity:
            secret = private_key.secret
        else:
            secret = -private_key.secret
        return (k_real + c_i * secret) % N

    def get_signature(self, s_sum, r, sig_hash, tweak=0):
        tweak_point = self.get_tweak_point(tweak)
        if tweak:
            msg = r.bip340() + tweak_point.bip340() + sig_hash
            challenge = big_endian_to_int(hash_challenge(msg)) % N
            if tweak_point.parity:
                s = (s_sum - challenge * tweak) % N
            else:
                s = (s_sum + challenge * tweak) % N
        else:
            s = s_sum % N
        s_raw = int_to_big_endian(s, 32)
        sig = r.bip340() + s_raw
        schnorrsig = SchnorrSignature.parse(sig)
        if not tweak_point.verify_schnorr(sig_hash, schnorrsig):
            raise ValueError("Invalid inputs for signature")
        return schnorrsig


class TapRootMultiSig:
    def __init__(self, points, k):
        self.n = len(points)
        if self.n < k or k < 1:
            raise ValueError(f"{k} is invalid for {self.n} keys")
        self.k = k
        self.points = points
        self.default_internal_pubkey = MuSigTapScript(self.points).point

    def single_leaf(self, locktime=None, sequence=None):
        tap_script = MultiSigTapScript(
            self.points, self.k, locktime=locktime, sequence=sequence
        )
        return tap_script.tap_leaf()

    def single_leaf_tap_root(self, internal_pubkey=None, locktime=None, sequence=None):
        if internal_pubkey is None:
            internal_pubkey = self.default_internal_pubkey
        return TapRoot(
            internal_pubkey, self.single_leaf(locktime=locktime, sequence=sequence)
        )

    def multi_leaf_tap_node(self, locktime=None, sequence=None):
        leaves = []
        for pubkeys in combinations(self.points, self.k):
            tap_script = MultiSigTapScript(pubkeys, self.k, locktime, sequence)
            leaves.append(tap_script.tap_leaf())
        return TapBranch.combine(leaves)

    def multi_leaf_tap_root(self, internal_pubkey=None, locktime=None, sequence=None):
        if internal_pubkey is None:
            internal_pubkey = self.default_internal_pubkey
        return TapRoot(
            internal_pubkey,
            self.multi_leaf_tap_node(locktime=locktime, sequence=sequence),
        )

    def musig_tap_node(self, locktime=None, sequence=None):
        leaves = []
        for pubkeys in combinations(self.points, self.k):
            tap_script = MuSigTapScript(pubkeys, locktime=locktime, sequence=sequence)
            leaves.append(tap_script.tap_leaf())
        return TapBranch.combine(leaves)

    def musig_tap_root(self, internal_pubkey=None, locktime=None, sequence=None):
        if internal_pubkey is None:
            internal_pubkey = self.default_internal_pubkey
        return TapRoot(
            internal_pubkey, self.musig_tap_node(locktime=locktime, sequence=sequence)
        )

    def musig_and_single_leaf_tap_root(
        self, internal_pubkey=None, locktime=None, sequence=None
    ):
        if internal_pubkey is None:
            internal_pubkey = self.default_internal_pubkey
        node = TapBranch(
            self.single_leaf(locktime=locktime, sequence=sequence),
            self.musig_tap_node(locktime=locktime, sequence=sequence),
        )
        return TapRoot(internal_pubkey, node)

    def everything_tap_root(self, internal_pubkey=None, locktime=None, sequence=None):
        if internal_pubkey is None:
            internal_pubkey = self.default_internal_pubkey
        node = TapBranch(
            self.single_leaf(locktime=locktime, sequence=sequence),
            TapBranch(
                self.multi_leaf_tap_node(locktime=locktime, sequence=sequence),
                self.musig_tap_node(locktime=locktime, sequence=sequence),
            ),
        )
        return TapRoot(internal_pubkey, node)

    def degrading_multisig_tap_node(
        self, sequence_block_interval=None, sequence_time_interval=None
    ):
        """Can unlock with multisig as k-of-n, or (k-1)-of-n after a
        sequence_block_interval/sequence_time_interval amount of time,
        (k-2)-of-n after 2*sequence_block_interval/sequence_time_interval
        amount of time, (k-3)-of-n after 3*sequence_block_interval/
        sequence_time_interval amount of time and so on."""
        leaves = []
        for num_keys_needed in range(self.k, 0, -1):
            if num_keys_needed == self.k:
                sequence = None
            elif sequence_block_interval:
                sequence = Sequence.from_relative_blocks(
                    sequence_block_interval * (self.k - num_keys_needed)
                )
            elif sequence_time_interval:
                sequence = Sequence.from_relative_time(
                    sequence_time_interval * (self.k - num_keys_needed)
                )
            for pubkeys in combinations(self.points, num_keys_needed):
                tap_script = MultiSigTapScript(
                    pubkeys, num_keys_needed, sequence=sequence
                )
                leaves.append(tap_script.tap_leaf())
        return TapBranch.combine(leaves)

    def degrading_multisig_tap_root(
        self,
        internal_pubkey=None,
        sequence_block_interval=None,
        sequence_time_interval=None,
    ):
        if internal_pubkey is None:
            internal_pubkey = self.default_internal_pubkey
        return TapRoot(
            internal_pubkey,
            self.degrading_multisig_tap_node(
                sequence_block_interval=sequence_block_interval,
                sequence_time_interval=sequence_time_interval,
            ),
        )
