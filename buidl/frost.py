from secrets import randbelow

from buidl.ecc import N, G, S256Point, PrivateKey, SchnorrSignature
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


class UpdatePrivatePolynomial:
    """Private Polynomial for updating keys. Same as PrivatePolynomial
    except it doesn't have a constant term."""

    def __init__(self, coefficients):
        self.coefficients = coefficients
        points = [s * G for s in self.coefficients]
        self.public = UpdatePublicPolynomial(points)

    def y_value(self, x):
        """return the y value y = f(x) where f is the private polynomial"""
        result = 0
        # compute y = a_1 * x + a_2 * x^2 + ... + a_(t-1) * x^(t-1)
        for coef_index, coef in enumerate(self.coefficients):
            result += coef * x ** (coef_index + 1) % N
        return result % N

    @classmethod
    def generate(cls, t):
        return cls([randbelow(N) for _ in range(t - 1)])


class UpdatePublicPolynomial:
    """Pulic Polynomial for updating keys. Same as PublicPolynomial
    except it doesn't have a constant term."""

    def __init__(self, points):
        self.points = points

    def __repr__(self):
        return "\n".join([p.__repr__() for p in self.points])

    def y_value(self, x):
        """return the y value y = f(x) where f is the public polynomial"""
        to_sum = []
        # compute y = A_1 * x + A_2 * x^2 + ... + A_(t-1) * x^(t-1)
        for coef_index, point in enumerate(self.points):
            to_sum.append((x ** (coef_index + 1) % N) * self.points[coef_index])
        return S256Point.combine(to_sum)


class PrivatePolynomial:
    """Polynomial with scalar coefficients. We can combine many of these
    to create a polynomial for Shamir's Secret Sharing."""

    def __init__(self, coefficients):
        self.coefficients = coefficients
        # the constant term is the "private key" for this polynomial
        self.private_key = PrivateKey(coefficients[0])
        # we compute the corresponding PublicPolynomial which have ECC points
        # as coefficients
        points = [s * G for s in self.coefficients]
        self.public = PublicPolynomial(points)

    def y_value(self, x):
        """return the y value y = f(x) where f is the private polynomial"""
        result = 0
        # compute y = a_0 + a_1 * x + a_2 * x^2 + ... + a_(t-1) * x^(t-1)
        for coef_index, coef in enumerate(self.coefficients):
            result += coef * x**coef_index % N
        return result % N

    def sign_keygen(self, msg):
        """Sign a message to prove that the private key to the public point
        is in our posession"""
        return self.private_key.sign_schnorr(msg)

    @classmethod
    def generate(cls, t):
        return cls([randbelow(N) for _ in range(t)])

    @classmethod
    def from_hd(cls, t, hd_priv):
        """Get coefficients from the hardened children of a HDPrivateKey"""
        return cls([hd_priv.child((1 << 31) + i).private_key.secret for i in range(t)])


class PublicPolynomial:
    """Polynomial with ECC Point coefficients. We can combine many of these
    to create a public key for the shared secret from Shamir."""

    def __init__(self, points):
        self.points = points
        # the constant term of the polynomial is the public key
        self.public_key = points[0]

    def __repr__(self):
        return "\n".join([p.__repr__() for p in self.points])

    def y_value(self, x):
        """return the y value y = f(x) where f is the public polynomial"""
        to_sum = []
        # compute y = A_0 + A_1 * x + A_2 * x^2 + ... + A_(t-1) * x^(t-1)
        for coef_index, point in enumerate(self.points):
            to_sum.append((x**coef_index % N) * self.points[coef_index])
        return S256Point.combine(to_sum)

    def verify_keygen(self, msg, sig):
        return self.public_key.verify_schnorr(msg, sig)


class FrostParticipant:
    """Represents a participant in a t-of-n FROST"""

    def __init__(
        self,
        t,
        participants,
        x,
        hd_priv=None,
        secret=None,
        pubkeys=None,
        group_pubkey=None,
    ):
        self.participants = participants[:]
        self.n = len(participants)
        if t > self.n:
            raise ValueError("t should be less than or equal to n")
        # t-of-n FROST
        self.t = t  # threshold of participants
        self.x = x  # this participant's x coordinate
        self.hd_priv = hd_priv  # HDPrivateKey object for generating
        self.secret = secret  # this participant's secret, or y coordinate
        self.pubkeys = pubkeys  # the pubkeys of other participants
        if secret:
            self.pubkey = self.secret * G
        self.group_pubkey = group_pubkey  # the combined group pubkey
        # nonces that other participants have registered with us
        self.nonces_available = {x: {} for x in participants}
        # these are used in distributed key generation and distributed key
        #  update.
        self.private_polynomial = None
        self.public_polynomials = None
        self.my_shares = None

    def key_generation_round_1(self, name):
        """We generate a polynomial which will be combined with other
        participants to generate the Shamir Secret Sharing polynomial"""
        if self.private_polynomial is not None:
            raise ValueError("secrets have already been defined")
        # generate a private Shamir polynomial
        if self.hd_priv:
            self.private_polynomial = PrivatePolynomial.from_hd(self.t, self.hd_priv)
        else:
            self.private_polynomial = PrivatePolynomial.generate(self.t)
        # the share that we generated for ourselves needs to be registered
        self.my_shares = {self.x: self.private_polynomial.y_value(self.x)}
        self.public_polynomials = {self.x: self.private_polynomial.public}
        # sign with the first coefficient as private key, our x and name context
        msg = hash_frost_keygen(encode_varint(self.x) + name)
        schnorr_sig = self.private_polynomial.sign_keygen(msg)
        return (self.private_polynomial.public, schnorr_sig)

    def verify_round_1(self, name, participant_x, public_polynomial, schnorr_sig):
        """store the public polynomial for the participant and check the
        signature provided for the constant term"""
        if participant_x == self.x:
            return
        # check the signature
        msg = hash_frost_keygen(encode_varint(participant_x) + name)
        if not public_polynomial.verify_keygen(msg, schnorr_sig):
            raise RuntimeError("signature for round 1 does not verify")
        # register the polynomial for combining
        self.public_polynomials[participant_x] = public_polynomial

    def key_generation_round_2(self, participant_x):
        """Deal out share to a fellow participant. This gives the y value
        for our polynomial. When combined with the y values of other polynomials
        the participant will have the y value for the combined group polynomial.
        A threshold of such y values can be used to reconstruct the secret"""
        return self.private_polynomial.y_value(participant_x)

    def verify_round_2(self, participant_x, share):
        """Receive the share from a fellow participant and check that this share
        corresponds to the point in the public polynomial they committed to."""
        if participant_x == self.x:
            return
        public_polynomial = self.public_polynomials[participant_x]
        # check our share against the commitments this participant has made
        pubkey = public_polynomial.y_value(self.x)
        # the result should correspond to the share we got
        if pubkey != share * G:
            raise RuntimeError("share does not correspond to the commitment")
        # share is valid, we store it for later processing
        self.my_shares[participant_x] = share

    def compute_keys(self):
        """Now compute the pubkeys for each participant and the y value to
        the group polynomial, which is our secret"""
        self.pubkeys = {}
        # we go through each participant to compute their pubkeys
        # this is done by adding up the y values at x for every public polynomial
        # whose sum is the group public polynomial
        for x in self.participants:
            points = [p.y_value(x) for p in self.public_polynomials.values()]
            self.pubkeys[x] = S256Point.combine(points)
        # the constant term of the combined polynomial is the group pubkey
        self.group_pubkey = S256Point.combine(
            [p.public_key for p in self.public_polynomials.values()]
        )
        # delete the public polynomials and our private polynomial
        self.public_polynomials = None
        self.private_polynomial = None
        # the secret shares that were dealt to us, we now combine for the secret
        self.secret = sum(self.my_shares.values()) % N
        # delete the shares
        self.my_shares = None
        # sanity check against the public key we computed
        self.pubkey = self.pubkeys[self.x]
        if self.secret * G != self.pubkey:
            raise RuntimeError("something wrong with the secret")
        # if we have an odd group key, negate everything to make the x-only
        # value good
        if self.group_pubkey.parity:
            # negate the pubkeys, the group pubkey and our secret
            self.pubkeys = {x: -1 * p for x, p in self.pubkeys.items()}
            self.group_pubkey = -1 * self.group_pubkey
            self.secret = N - self.secret
            self.pubkey = self.pubkeys[self.x]
        return self.group_pubkey

    def generate_nonce_pairs(self, num=200):
        """We now deal to everyone the nonces we will be using for signing. Each
        signing requires a pair of nonces and we return the nonce commitments"""
        self.nonces = {}
        self.nonce_pubs = []
        for _ in range(num):
            # this should probably involve some deterministic process involving
            # some commitments to the group of participants
            nonce_1, nonce_2 = randbelow(N), randbelow(N)
            nonce_pub_1 = nonce_1 * G
            nonce_pub_2 = nonce_2 * G
            self.nonces[nonce_pub_1] = (nonce_1, nonce_2)
            self.nonce_pubs.append((nonce_pub_1, nonce_pub_2))
        return self.nonce_pubs[:]

    def extract_nonce_pairs(self, hd_priv, num=200):
        """We generate the nonce pairs using an HDPrivateKey as an alternative
        to random generation"""
        # create two nonces for use in the signing
        self.nonces = {}
        self.nonce_pubs = []
        for i in range(num):
            # use a hardened derivation
            child = hd_priv.child((1 << 31) + i)
            nonce_1, nonce_2 = (
                child.child(0).private_key.secret,
                child.child(1).private_key.secret,
            )
            nonce_pub_1 = nonce_1 * G
            nonce_pub_2 = nonce_2 * G
            self.nonces[nonce_pub_1] = (nonce_1, nonce_2)
            self.nonce_pubs.append((nonce_pub_1, nonce_pub_2))
        return self.nonce_pubs

    def register_nonces(self, x, nonce_pubs):
        """When we receive the nonce commitments, we store them"""
        nonce_lookup = {}
        for nonce_pub_1, nonce_pub_2 in nonce_pubs:
            nonce_lookup[(nonce_pub_1, nonce_pub_2)] = True
        self.nonces_available[x] = nonce_lookup

    def compute_commitment(self, x, msg, d, e):
        """Commitment is what we use to make the k we use deterministic in a way
        that's not manipulable by the other players ahead of time"""
        h = hash_frost_commitment(msg + encode_varint(x) + d.xonly() + e.xonly())
        return big_endian_to_int(h) % N

    def compute_partial_r(self, x, msg, d, e):
        """Return the R_x, or the target for the participant at x"""
        commitment = self.compute_commitment(x, msg, d, e)
        return S256Point.combine([d, commitment * e])

    def compute_group_r(self, msg, nonces_to_use):
        """The R that we use for signing is the sum of all the R_x's
        from the participants"""
        result = []
        participants = sorted(nonces_to_use.keys())
        for x in participants:
            d, e = nonces_to_use[x]
            partial_r = self.compute_partial_r(x, msg, d, e)
            result.append(partial_r)
        return S256Point.combine(result)

    def lagrange_coefficient(self, x, participants):
        """This calculates the value of the lagrange interpolating polynomial
        at 0. Multiplied by the secret, this represents the participant's
        additive portion of the group secret."""
        result = 1
        # compute Σ(p_x/(p_x-x)) where p_x != x
        for p_x in participants:
            if p_x != x:
                result *= p_x * pow(p_x - x, N - 2, N) % N
        return result

    def lagrange_y_value(self, p_xs, new_participant_x):
        """This calculates the value of the lagrange interpolating polynomial
        at x for this participant's x. If collected from all participants, a
        new FrostParticipant can be added. But we can't just send the value
        directly as it will reveal our secret, so it'll subsequently be split"""
        result = 1
        for p_x in p_xs:
            if p_x != self.x:
                result *= (new_participant_x - p_x) * pow(self.x - p_x, N - 2, N) % N
        return result * self.secret % N

    def sign(self, msg, nonces_to_use, tweak=None):
        """Sign using our secret share given the nonces we are supposed to use"""
        group_r = self.compute_group_r(msg, nonces_to_use)
        # compute the lagrange coefficient based on the participants
        participants = sorted(nonces_to_use.keys())
        lagrange = self.lagrange_coefficient(self.x, participants)
        # use the two nonces to compute the k we will use
        d, e = nonces_to_use[self.x]
        my_commitment = self.compute_commitment(self.x, msg, d, e)
        my_d, my_e = self.nonces[nonces_to_use[self.x][0]]
        my_k = my_d + my_e * my_commitment
        my_r = self.compute_partial_r(self.x, msg, d, e)
        # adjust the group pubkey, our secret and pubkey by the amount of the tweak
        if tweak:
            t = big_endian_to_int(tweak)
            group_pubkey = self.group_pubkey + t
            # if the tweaked pubkey is odd, we negate the secret and pubkey
            if group_pubkey.parity:
                secret = N - (self.secret + t)
                pubkey = -1 * (self.pubkey + t)
            else:
                secret = self.secret + t
                pubkey = self.pubkey + t
        else:
            group_pubkey = self.group_pubkey
            secret = self.secret
            pubkey = self.pubkey
        # the group challenge is the normal Schnorr Signature challenge from BIP340
        challenge = big_endian_to_int(
            hash_challenge(group_r.xonly() + group_pubkey.xonly() + msg)
        )
        # if the group r is odd, we negate the k and r
        if group_r.parity:
            my_k = N - my_k
            my_r = -1 * my_r
        working_secret = lagrange * secret
        working_pubkey = lagrange * pubkey
        # this is the partial signature, which added with a threshold number of
        # participants creates the signature as would be produced by the group
        # secret, which no one knows, and which validate using the group pubkey
        sig_share = (my_k + working_secret * challenge) % N
        # sanity check the s we generated
        commitment = challenge * working_pubkey
        if -1 * commitment + sig_share != my_r:
            raise RuntimeError("signature didn't validate")
        # delete nonce used
        for participant_x in participants:
            nonce = nonces_to_use[participant_x]
            del self.nonces_available[participant_x][nonce]
        return sig_share

    def combine_sig_shares(self, sig_shares, msg, nonces_to_use, tweak=None):
        """Convenience method to return a Schnorr Signature once
        the participants have returned their sig_shares"""
        group_r = self.compute_group_r(msg, nonces_to_use)
        if tweak:
            t = big_endian_to_int(tweak)
            group_pubkey = self.group_pubkey + t
        else:
            group_pubkey = self.group_pubkey
        challenge = big_endian_to_int(
            hash_challenge(group_r.xonly() + group_pubkey.xonly() + msg)
        )
        # check that the sig_shares from each participant validates
        participants = sorted(sig_shares.keys())
        for participant_x in participants:
            lagrange = self.lagrange_coefficient(participant_x, participants)
            sig_share = sig_shares[participant_x]
            d, e = nonces_to_use[participant_x]
            if tweak:
                if group_pubkey.parity:
                    pubkey = -1 * (self.pubkeys[participant_x] + t)
                else:
                    pubkey = self.pubkeys[participant_x] + t
            else:
                pubkey = self.pubkeys[participant_x]
            working_pubkey = lagrange * pubkey
            partial_r = self.compute_partial_r(participant_x, msg, d, e)
            commitment = challenge * working_pubkey
            if group_r.parity:
                partial_r = -1 * partial_r
            if -1 * commitment + sig_share != partial_r:
                raise RuntimeError("share didn't validate")
        # combine now
        s = sum(sig_shares.values()) % N
        return SchnorrSignature.parse(group_r.xonly() + int_to_big_endian(s, 32))

    def enrolment_round_1(self, participant_xs, new_participant_x):
        """enrolment is the act of adding a new participant, which turns
        t-of-n to t-of-n+1."""
        # we calculate the value we need to send to the new participant
        y_value = self.lagrange_y_value(participant_xs, new_participant_x)
        # we split the y value into N shares first so the new participant
        # can't derive our secret
        self.share_of_shares = {x: randbelow(N) for x in participant_xs[:-1]}
        last_value = (y_value - sum(self.share_of_shares.values())) % N
        self.share_of_shares[participant_xs[-1]] = last_value
        self.enrolment_round_1_values = {}

    def enrolment_round_1_send(self, x):
        """We communicate the share to the appropriate participant"""
        return self.share_of_shares.get(x)

    def enrolment_round_1_receive(self, x, value):
        """We receive our share of the new participant's secret from x"""
        self.enrolment_round_1_values[x] = value

    def enrolment_round_2_send(self):
        """We now send our accumulated shares of the new participant's
        y-value"""
        return sum(self.enrolment_round_1_values.values()) % N

    def add_participant(self, x, pubkey, nonce_pubs):
        """Add a new participant (make into n+1)"""
        self.participants.append(x)
        self.n = len(self.participants)
        self.pubkeys[x] = pubkey
        self.register_nonces(x, nonce_pubs)

    def remove_participant(self, x):
        """Remove an existing participant (make into n-1)"""
        self.participants.remove(x)
        self.n = len(self.participants)
        del self.pubkeys[x]
        del self.nonces_available[x]

    def polynomial(self):
        return self.private_polynomial.public

    def key_update_round_1(self):
        """Once you've removed a participant, it's important to update the
        polynomial so that we invalidate the removed participant's share"""
        if self.private_polynomial is not None:
            raise ValueError("secrets have already been defined")
        # generate a private Shamir polynomial without a constant term
        self.private_polynomial = UpdatePrivatePolynomial.generate(self.t)
        # the share that we generated for ourselves needs to be registered
        self.my_shares = {self.x: self.private_polynomial.y_value(self.x)}
        self.public_polynomials = {self.x: self.polynomial()}

    def key_update_round_1_register(self, participant_x, public_polynomial):
        """store the update public polynomial for the participant at x"""
        if participant_x == self.x:
            return
        self.public_polynomials[participant_x] = public_polynomial

    def key_update_round_2(self, participant_x):
        """Deal out share to a fellow participant"""
        return self.private_polynomial.y_value(participant_x)

    def key_update_round_2_register(self, x, share):
        """Register our share from x so we can add them together later"""
        if x == self.x:
            return
        # check our share against the commitments this participant has made
        pubkey = self.public_polynomials[x].y_value(self.x)
        # the result should correspond to the share we got
        if pubkey != share * G:
            raise RuntimeError("share does not correspond to the commitment")
        # share is valid, we store it for later processing
        self.my_shares[x] = share

    def update_keys(self):
        """Now update the pubkeys for each participant and the secret share for
        our pubkey"""
        # we go through each participant to compute their pubkeys
        # this is done by adding up the y values at x for every public polynomial
        # whose sum is the group public polynomial
        if self.secret * G != self.pubkey:
            raise RuntimeError("something wrong with the secret")
        # update everyone's pubkeys by the amount of the update polynomials
        for x in self.participants:
            points = [p.y_value(x) for p in self.public_polynomials.values()]
            self.pubkeys[x] = S256Point.combine([self.pubkeys[x]] + points)
        # delete the public polynomials and our private polynomial as we don't need them
        self.public_polynomials = None
        self.private_polynomial = None
        # the secret shares that were dealt to us, we now combine to add to the secret
        self.secret = (self.secret + sum(self.my_shares.values())) % N
        # delete the shares as we now don't need them
        self.my_shares = None
        # sanity check against the public key we computed
        self.pubkey = self.pubkeys[self.x]
        if self.secret * G != self.pubkey:
            raise RuntimeError("something wrong with the secret")
