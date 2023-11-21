from secrets import randbelow

from buidl.ecc import N, G, S256Point, SchnorrSignature
from buidl.helper import (
    big_endian_to_int,
    encode_varint,
    int_to_big_endian,
)
from buidl.hash import hash_challenge
from buidl.phash import tagged_hash


def hash_frost_keygen(m):
    """Hash used for cooperative key generation. This should be a tagged hash"""
    return tagged_hash(b"FROST/keygen", m)


def hash_frost_commitment(m):
    """Hash used for message commitment in signing. This should be a tagged hash"""
    return tagged_hash(b"FROST/commitment", m)


class FrostParticipant:
    """Represents a participant in a t-of-n FROST"""

    def __init__(self, t, n, index):
        # t-of-n FROST with this one being at index in [1, n]
        self.t = t
        self.n = n
        self.index = index
        self.keygen_coefficients = None
        self.coefficient_commitments = [[] for _ in range(self.n)]
        self.shares_from = [None for _ in range(self.n)]

    def key_generation_round_1(self, name):
        if self.keygen_coefficients is not None:
            raise ValueError("secrets have already been defined")
        # generate t random numbers for a Shamir polynomial
        self.keygen_coefficients = [randbelow(N) for _ in range(self.t)]
        my_commitments = [coef * G for coef in self.keygen_coefficients]
        self.coefficient_commitments[self.index] = my_commitments
        k = randbelow(N)  # TODO: change this to use the k generation from bip340
        r = k * G
        c = hash_frost_keygen(
            encode_varint(self.index) + name + my_commitments[0].xonly() + r.xonly()
        )
        # proof proves that we know the first coefficient
        proof = (k + self.keygen_coefficients[0] * big_endian_to_int(c)) % N
        return (my_commitments, r, proof)

    def poly_value(self, x):
        """return the polynomial value f(x) for the polynomial defined by the secrets"""
        result = 0
        for coef_index in range(self.t):
            result += self.keygen_coefficients[coef_index] * x**coef_index % N
        return result % N

    def verify_round_1(self, name, participant_index, commitments, r, proof):
        """check that the commitment at index 0, r and proof are valid"""
        if participant_index == self.index:
            return
        c = hash_frost_keygen(
            encode_varint(participant_index) + name + commitments[0].xonly() + r.xonly()
        )
        if r != -big_endian_to_int(c) * commitments[0] + proof:
            raise RuntimeError("commitment does not correspond to proof")
        self.coefficient_commitments[participant_index] = commitments

    def key_generation_round_2(self):
        """Deal out shares to each participant corresponding to their index + 1"""
        shares = []
        for participant_index in range(self.n):
            shares.append(self.poly_value(participant_index + 1))
        self.shares_from[self.index] = shares[self.index]
        shares[self.index] = None
        return shares

    def verify_round_2(self, participant_index, share):
        """Check that we have a valid point in the committed Shamir polynomial
        from this participant"""
        if participant_index == self.index:
            return
        commitments = self.coefficient_commitments[participant_index]
        x = self.index + 1
        target = share * G
        points = []
        for coef_index in range(self.t):
            coef = x**coef_index % N
            points.append(coef * commitments[coef_index])
        if S256Point.combine(points) != target:
            raise RuntimeError("share does not correspond to the commitment")
        self.shares_from[participant_index] = share

    def compute_keys(self):
        """Now compute the pubkeys for each participant and the secret share for
        our pubkey"""
        self.pubkeys = []
        for _ in range(self.n):
            points = []
            for participant_index in range(self.n):
                for coef_index in range(self.t):
                    coef = (self.index + 1) ** coef_index % N
                    points.append(
                        coef
                        * self.coefficient_commitments[participant_index][coef_index]
                    )
            self.pubkeys.append(S256Point.combine(points))
        # the constant term of the combined polynomial is the pubkey
        self.group_pubkey = S256Point.combine(
            [
                self.coefficient_commitments[participant_index][0]
                for participant_index in range(self.n)
            ]
        )
        # the secret shares that were dealt to us, we now combine for the secret
        self.secret = sum(self.shares_from) % N
        # sanity check against the public key we computed
        self.pubkey = self.pubkeys[self.index]
        if self.secret * G != self.pubkey:
            raise RuntimeError("something wrong with the secret")
        # if we have an odd group key, negate everything
        if self.group_pubkey.parity:
            # negate the pubkeys, the group pubkey and our secret
            self.pubkeys = [-1 * p for p in self.pubkeys]
            self.group_pubkey = -1 * self.group_pubkey
            self.secret = N - self.secret
            self.pubkey = self.pubkeys[self.index]
        return self.group_pubkey

    def generate_nonce_pairs(self, num=200):
        """We now deal to everyone the nonces we will be using for signing.
        Each signing requires a pair of nonces and we return the nonce commitments"""
        # create two nonces for use in the signing
        self.nonces = {}
        self.nonce_pubs = []
        for _ in range(num):
            # this should probably involve some deterministic process involving
            # the private key
            nonce_1, nonce_2 = randbelow(N), randbelow(N)
            nonce_pub_1 = nonce_1 * G
            nonce_pub_2 = nonce_2 * G
            self.nonces[nonce_pub_1] = (nonce_1, nonce_2)
            self.nonce_pubs.append((nonce_pub_1, nonce_pub_2))
        return self.nonce_pubs

    def register_nonce_pubs(self, nonce_pubs_list):
        """When we receive the nonce commitments, we store them"""
        self.nonces_available = []
        for nonce_pubs in nonce_pubs_list:
            nonce_lookup = {}
            for nonce_pub_1, nonce_pub_2 in nonce_pubs:
                nonce_lookup[(nonce_pub_1, nonce_pub_2)] = True
            self.nonces_available.append(nonce_lookup)

    def compute_group_r(self, msg, nonces_to_use):
        """The R that we use for signing can be computed based on the nonces
        we are using and the message that we're signing"""
        # add up the first nonces as normal
        ds = []
        for key in sorted(nonces_to_use.keys()):
            value = nonces_to_use[key]
            ds.append(value[0])
        result = [S256Point.combine(ds)]
        # the second nonces need to be multiplied by the commitment
        for key in sorted(nonces_to_use.keys()):
            value = nonces_to_use[key]
            commitment = (
                big_endian_to_int(
                    hash_frost_commitment(
                        msg + encode_varint(key) + value[0].xonly() + value[1].xonly()
                    )
                )
                % N
            )
            result.append(commitment * value[1])
        return S256Point.combine(result)

    def sign(self, msg, nonces_to_use):
        """Sign using our secret share given the nonces we are supposed to use"""
        group_r = self.compute_group_r(msg, nonces_to_use)
        # compute the lagrange coefficient based on the participants
        lagrange = 1
        for key in sorted(nonces_to_use.keys()):
            value = nonces_to_use[key]
            if not self.nonces_available[key][value]:
                raise ValueError("Using an unknown or already used nonce")
            if key == self.index:
                my_commitment = (
                    big_endian_to_int(
                        hash_frost_commitment(
                            msg
                            + encode_varint(key)
                            + value[0].xonly()
                            + value[1].xonly()
                        )
                    )
                    % N
                )
            else:
                lagrange *= (key + 1) * pow(key - self.index, -1, N) % N
        # the group challenge is the normal Schnorr Signature challenge from BIP340
        challenge = big_endian_to_int(
            hash_challenge(group_r.xonly() + self.group_pubkey.xonly() + msg)
        )
        # use the two nonces to compute the k we will use
        my_d, my_e = self.nonces[nonces_to_use[self.index][0]]
        my_k = my_d + my_e * my_commitment
        d_pub, e_pub = my_d * G, my_e * G
        my_r = S256Point.combine([d_pub, my_commitment * e_pub])
        # if the group r is odd, we negate everything
        if group_r.parity:
            group_r = -1 * group_r
            my_k = N - my_k
            my_r = -1 * my_r
        sig_share = (my_k + lagrange * self.secret * challenge) % N
        # sanity check the s we generated
        second = (challenge * lagrange % N) * self.pubkey
        if -1 * second + sig_share != my_r:
            raise RuntimeError("signature didn't do what we expected")
        # delete nonce used
        for key in sorted(nonces_to_use.keys()):
            value = nonces_to_use[key]
            del self.nonces_available[key][value]
        return sig_share

    def combine_shares(self, shares, msg, nonces_to_use):
        """Convenience method to return a Schnorr Signature once
        the participants have returned their shares"""
        r = self.compute_group_r(msg, nonces_to_use)
        s = sum(shares) % N
        return SchnorrSignature.parse(r.xonly() + int_to_big_endian(s, 32))
