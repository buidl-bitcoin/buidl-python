from itertools import combinations
from secrets import randbelow

from buidl.ecc import G, N, S256Point, SchnorrSignature
from buidl.hash import (
    hash_challenge,
    hash_keyaggcoef,
    hash_keyagglist,
    hash_musignonce,
    hash_tapbranch,
    hash_tapleaf,
    hash_taptweak,
)
from buidl.helper import (
    big_endian_to_int,
    int_to_big_endian,
    int_to_byte,
)
from buidl.op import (
    encode_minimal_num,
    number_to_op_code,
)
from buidl.script import Script, ScriptPubKey, P2TRScriptPubKey
from buidl.timelock import Locktime, Sequence


def locktime_commands(locktime):
    assert isinstance(locktime, Locktime), f"{locktime} needs to be Locktime"
    # 0xB1 is OP_CLTV, 0x75 is OP_DROP
    return [encode_minimal_num(locktime), 0xB1, 0x75]


def sequence_commands(sequence):
    assert isinstance(sequence, Sequence), f"{sequence} needs to be Sequence"
    # 0xB2 is OP_CSV, 0x75 is OP_DROP
    return [encode_minimal_num(sequence), 0xB2, 0x75]


class TapLeaf:
    def __init__(self, tap_script, tapleaf_version=0xC0):
        if not isinstance(tap_script, Script):
            raise ValueError("Script is required")
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
        return []

    def external_pubkey(self, internal_pubkey):
        return internal_pubkey.tweaked_key(self.hash())

    def control_block(self, internal_pubkey, tap_leaf=None):
        """Assumes that this TapLeaf is the Merkle Root and constructs the
        control block"""
        if tap_leaf is not None and tap_leaf != self:
            return None
        external_pubkey = self.external_pubkey(internal_pubkey)
        return ControlBlock(
            self.tapleaf_version,
            external_pubkey.parity,
            internal_pubkey,
            self.path_hashes(None),
        )


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
            return [*self.left.path_hashes(leaf), self.right.hash()]
        elif leaf in self.right.leaves():
            return [*self.right.path_hashes(leaf), self.left.hash()]
        else:
            return None

    def external_pubkey(self, internal_pubkey):
        return internal_pubkey.tweaked_key(self.hash())

    def control_block(self, internal_pubkey, leaf):
        """Assumes this TapBranch is the Merkle Root and returns the control
        block. Also requires the leaf to be one of the descendents"""
        if leaf not in self.leaves():
            return None
        external_pubkey = self.external_pubkey(internal_pubkey)
        return ControlBlock(
            leaf.tapleaf_version,
            external_pubkey.parity,
            internal_pubkey,
            self.path_hashes(leaf),
        )

    @classmethod
    def combine(cls, nodes):
        if len(nodes) == 1:
            return nodes[0]
        half_way = len(nodes) // 2
        left = cls.combine(nodes[:half_way])
        right = cls.combine(nodes[half_way:])
        return cls(left, right)


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

    def merkle_root(self, tap_script):
        # create a TapLeaf from the tap_script and the tapleaf version in the control block
        leaf = TapLeaf(tap_script, self.tapleaf_version)
        # initialize the hash with the leaf's hash
        current = leaf.hash()
        # go through the hashes in self.hashes
        for h in self.hashes:
            # set the current hash as the hash_tapbranch of the sorted hashes
            if current < h:
                current = hash_tapbranch(current + h)
            else:
                current = hash_tapbranch(h + current)
        # return the current hash
        return current

    def external_pubkey(self, tap_script):
        # get the Merkle Root using self.merkle_root
        merkle_root = self.merkle_root(tap_script)
        # return the external pubkey using the tweaked_key method of internal pubkey
        return self.internal_pubkey.tweaked_key(merkle_root)

    def serialize(self):
        s = int_to_byte(self.tapleaf_version + self.parity)
        s += self.internal_pubkey.xonly()
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
        internal_pubkey = S256Point.parse_xonly(b[1:33])
        m = (b_len - 33) // 32
        hashes = [b[33 + 32 * i : 65 + 32 * i] for i in range(m)]
        return cls(tapleaf_version, parity, internal_pubkey, hashes)


class TapScript(ScriptPubKey):
    def tap_leaf(self):
        return TapLeaf(self)


class P2PKTapScript(TapScript):
    def __init__(self, point):
        super().__init__()
        if isinstance(point, S256Point):
            raw_point = point.xonly()
        elif isinstance(point, bytes):
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
        xonlys = sorted([p.xonly() for p in points])
        self.points = [S256Point.parse_xonly(b) for b in xonlys]
        if locktime is not None:
            self.commands = locktime_commands(locktime)
        elif sequence is not None:
            self.commands = sequence_commands(sequence)
        else:
            self.commands = []
        self.commands += [xonlys[0], 0xAC]
        if len(points) > 1:
            for xonly in xonlys[1:]:
                self.commands += [xonly, 0xBA]
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
        xonlys = sorted([p.xonly() for p in points])
        self.points = [S256Point.parse_xonly(b) for b in xonlys]
        self.commitment = hash_keyagglist(b"".join(xonlys))
        self.coefs = [
            big_endian_to_int(hash_keyaggcoef(self.commitment + b)) for b in xonlys
        ]
        # the second unique public key has a coefficient of 1
        self.coefs[1] = 1
        self.coef_lookup = {b: c for c, b in zip(self.coefs, xonlys)}
        # aggregate point
        self.point = S256Point.combine([c * p for c, p in zip(self.coefs, self.points)])
        if locktime is not None:
            self.commands = locktime_commands(locktime)
        elif sequence is not None:
            self.commands = sequence_commands(sequence)
        else:
            self.commands = []
        self.commands += [self.point.xonly(), 0xAC]

    def generate_nonces(self):
        k_1, k_2 = randbelow(N), randbelow(N)
        r_1, r_2 = k_1 * G, k_2 * G
        return (k_1, k_2), (r_1, r_2)

    def nonce_sums(self, nonce_point_pairs):
        sum_1 = S256Point.combine([n[0] for n in nonce_point_pairs])
        sum_2 = S256Point.combine([n[1] for n in nonce_point_pairs])
        return sum_1, sum_2

    def compute_coefficient(self, nonce_sums, sig_hash):
        bytes_to_hash = (
            nonce_sums[0].sec() + nonce_sums[1].sec() + self.point.xonly() + sig_hash
        )
        return big_endian_to_int(hash_musignonce(bytes_to_hash))

    def compute_k(self, nonce_secrets, nonce_sums, sig_hash):
        h = self.compute_coefficient(nonce_sums, sig_hash)
        return (nonce_secrets[0] + h * nonce_secrets[1]) % N

    def compute_r(self, nonce_sums, sig_hash):
        h = self.compute_coefficient(nonce_sums, sig_hash)
        return S256Point.combine([nonce_sums[0], h * nonce_sums[1]])

    def sign(self, private_key, k, r, sig_hash, merkle_root=b""):
        if merkle_root:
            external_pubkey = self.point.tweaked_key(merkle_root)
        else:
            external_pubkey = self.point.even_point()
        msg = r.xonly() + external_pubkey.xonly() + sig_hash
        challenge = big_endian_to_int(hash_challenge(msg)) % N
        h_i = self.coef_lookup[private_key.point.xonly()]
        c_i = h_i * challenge % N
        if r.parity == external_pubkey.parity:
            k_real = k
        else:
            k_real = -k
        if self.point.parity == private_key.point.parity:
            secret = private_key.secret
        else:
            secret = -private_key.secret
        return (k_real + c_i * secret) % N

    def get_signature(self, s_sum, r, sig_hash, merkle_root=b""):
        if merkle_root:
            external_pubkey = self.point.tweaked_key(merkle_root)
            tweak = big_endian_to_int(self.point.tweak(merkle_root))
            msg = r.xonly() + external_pubkey.xonly() + sig_hash
            challenge = big_endian_to_int(hash_challenge(msg)) % N
            if external_pubkey.parity:
                s = (-s_sum - challenge * tweak) % N
            else:
                s = (s_sum + challenge * tweak) % N
        else:
            external_pubkey = self.point.even_point()
            s = s_sum % N
        serialized = r.xonly() + int_to_big_endian(s, 32)
        schnorrsig = SchnorrSignature.parse(serialized)
        if not external_pubkey.verify_schnorr(sig_hash, schnorrsig):
            raise ValueError("Invalid signature")
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

    def multi_leaf_tree(self, locktime=None, sequence=None):
        leaves = []
        for pubkeys in combinations(self.points, self.k):
            tap_script = MultiSigTapScript(pubkeys, self.k, locktime, sequence)
            leaves.append(tap_script.tap_leaf())
        return TapBranch.combine(leaves)

    def musig_tree(self, locktime=None, sequence=None):
        leaves = []
        for pubkeys in combinations(self.points, self.k):
            tap_script = MuSigTapScript(pubkeys, locktime=locktime, sequence=sequence)
            leaves.append(tap_script.tap_leaf())
        return TapBranch.combine(leaves)

    def musig_and_single_leaf_tree(
        self, internal_pubkey=None, locktime=None, sequence=None
    ):
        if internal_pubkey is None:
            internal_pubkey = self.default_internal_pubkey
        return TapBranch(
            self.single_leaf(locktime=locktime, sequence=sequence),
            self.musig_tree(locktime=locktime, sequence=sequence),
        )

    def everything_tree(self, internal_pubkey=None, locktime=None, sequence=None):
        if internal_pubkey is None:
            internal_pubkey = self.default_internal_pubkey
        return TapBranch(
            self.single_leaf(locktime=locktime, sequence=sequence),
            TapBranch(
                self.multi_leaf_tree(locktime=locktime, sequence=sequence),
                self.musig_tree(locktime=locktime, sequence=sequence),
            ),
        )

    def degrading_multisig_tree(
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
