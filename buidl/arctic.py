#!/usr/bin/env python3
"""
Arctic: Lightweight and Stateless Threshold Schnorr Signatures

Implementation based on:
  "Arctic: Lightweight and Stateless Threshold Schnorr Signatures"
  by Chelsea Komlo and Ian Goldberg
  https://eprint.iacr.org/2024/466  (PKC 2025)

Uses the buidl-python library for secp256k1 elliptic curve operations.

Arctic is a two-round, deterministic threshold Schnorr signature scheme.
It does not require participants to maintain state between signing rounds.
Key building block: VPSS1 (Verifiable Pseudorandom Secret Sharing).

Security model:
  - Honest majority: n >= 2t-1 total participants, at most t-1 corrupted
  - Secure under discrete logarithm assumption in the random oracle model
  - Static adversary (corruption set chosen before protocol begins)
"""

import hashlib
import secrets
from itertools import combinations
from buidl.ecc import S256Point, N, G
from buidl.hash import tagged_hash
from buidl.helper import big_endian_to_int, int_to_big_endian


def mod_inv(a, p=N):
    return pow(a % p, p - 2, p)


def H1(phi, w):
    """PRF for VPSS1 nonce generation: H1(φ, w) → Z_q."""
    data = int_to_big_endian(phi, 32) + (w if isinstance(w, bytes) else w.encode())
    return big_endian_to_int(tagged_hash(b"Arctic/VPSS1", data)) % N


def H2(pk_bytes, m):
    """Session binding hash: H2(pk, m) → 32-byte deterministic session id."""
    return tagged_hash(b"Arctic/Session", pk_bytes + m)


def H3(R_bytes, pk_bytes, m):
    """Schnorr challenge hash: H3(R, pk, m) → Z_q."""
    return (
        big_endian_to_int(tagged_hash(b"Arctic/Challenge", R_bytes + pk_bytes + m)) % N
    )


# ─── Lagrange Interpolation Helpers ──────────────────────────────────────────


def lagrange_coeff_at_zero(j, coalition):
    """
    Compute Lagrange coefficient λ_j = L_j(0) for party j in the coalition.
    Used for secret recovery / signature combination.
    """
    num = 1
    den = 1
    for k in coalition:
        if k != j:
            num = (num * (-k)) % N
            den = (den * (j - k)) % N
    return (num * mod_inv(den)) % N


def lagrange_basis_poly_coeffs(j, coalition):
    """
    Compute coefficients [a_0, a_1, ..., a_{m-1}] of L_j(x) = Σ a_i·x^i,
    the Lagrange basis polynomial for party j in the given coalition.
    Used by VPSS1.Verify to check polynomial degree in the exponent.
    """
    poly = [1]
    den = 1
    for k in coalition:
        if k == j:
            continue
        den = (den * (j - k)) % N
        new_poly = [0] * (len(poly) + 1)
        for i, c in enumerate(poly):
            new_poly[i + 1] = (new_poly[i + 1] + c) % N
            new_poly[i] = (new_poly[i] + (-k) * c) % N
        poly = new_poly
    inv_den = mod_inv(den)
    return [(c * inv_den) % N for c in poly]


# ─── VPSS1: Verifiable Pseudorandom Secret Sharing ──────────────────────────
#
# VPSS1 uses replicated secret sharing (Cramer et al.) extended with a
# public verifiability mechanism. Each participant holds a subset of the
# replicated shares and can independently generate Shamir shares of
# pseudorandom values by evaluating a PRF on each replicated share.
#
# The verification check ensures all participants' commitments lie on a
# polynomial of degree ≤ t-1 in the exponent, guaranteeing protocol honesty.


class VPSS1:
    """Verifiable Pseudorandom Secret Sharing (VPSS1) from the Arctic paper."""

    @staticmethod
    def keygen(n, t, mu):
        """
        Replicated secret sharing key generation.

        The dealer generates C(n, t-1) random shares and distributes them
        so that each party j receives all shares whose associated subset
        does NOT contain j.  This gives each party C(n-1, t-1) share tuples.

        Args:
            n: Total number of participants
            t: Corruption threshold (tolerates up to t-1 corruptions)
            mu: Minimum participants required (must be >= 2t-1)

        Returns:
            Dict {party_id: [(frozenset, int), ...]} mapping each party
            to its list of (subset, share_value) tuples, or None on failure.
        """
        if mu < 2 * t - 1 or mu > n:
            return None

        participants = list(range(1, n + 1))
        subsets = [frozenset(s) for s in combinations(participants, t - 1)]

        # Random replicated shares (one per (t-1)-subset)
        shares = [(s, secrets.randbelow(N - 1) + 1) for s in subsets]

        # Party j gets (a_i, φ_i) for every subset a_i that does NOT contain j
        keys = {}
        for j in participants:
            keys[j] = [(s, phi) for s, phi in shares if j not in s]

        return keys

    @staticmethod
    def gen(k, sk_k, w):
        """
        Generate a pseudorandom Shamir share and its EC commitment.

        Each party evaluates the PRF H1 on each of its replicated shares
        with input w, weights the results by pre-defined Lagrange-like
        coefficients L'_{a_i}(k), and sums to get its Shamir share d_k.
        The commitment is D_k = d_k · G.

        The resulting d_k values (across all honest parties) lie on a
        polynomial of degree t-1, whose constant term is the aggregated
        pseudorandom value d = Σ_i H1(φ_i, w).

        Args:
            k: Participant identifier (1-indexed)
            sk_k: Secret key (list of (subset, share) tuples)
            w: Session input (bytes)

        Returns:
            (d_k, D_k): scalar share and commitment point
        """
        if isinstance(w, str):
            w = w.encode()

        d_k = 0
        for a_i, phi_i in sk_k:
            # L'_{a_i}(k) = ∏_{j ∈ a_i} (j - k) / j
            # This polynomial equals 1 at x=0 and 0 at x=j for j ∈ a_i
            L_prime = 1
            for j in a_i:
                L_prime = L_prime * ((j - k) * mod_inv(j) % N) % N
            d_k = (d_k + H1(phi_i, w) * L_prime) % N

        D_k = d_k * G
        return d_k, D_k

    @staticmethod
    def verify(t, mu, C, commitments):
        """
        Verify that all participants' commitments lie on a degree-(t-1) polynomial.

        Computes polynomial coefficients "in the exponent" via Lagrange
        interpolation of the commitment points.  If the underlying shares
        lie on a degree-(t-1) polynomial, then the coefficients for terms
        x^t through x^{|C|-1} must be the point at infinity (identity).

        Args:
            t: Corruption threshold
            mu: Minimum participants
            C: Coalition (sorted list of party ids)
            commitments: Dict {party_id: S256Point}

        Returns:
            True if all commitments are consistent with a degree-(t-1) poly.
        """
        m = len(C)
        if m < mu:
            return False

        # Precompute Lagrange basis polynomial coefficients for each party
        all_coeffs = {j: lagrange_basis_poly_coeffs(j, C) for j in C}

        # B_i = Σ_{j∈C} L_{j,i} · D_j  (EC multi-scalar multiplication)
        # Check B_i = identity for i = t, t+1, ..., m-1
        for i in range(t, m):
            terms = []
            for j in C:
                coeff = all_coeffs[j][i] if i < len(all_coeffs[j]) else 0
                if coeff == 0:
                    continue
                terms.append(coeff * commitments[j])
            if not terms:
                continue
            if len(terms) == 1:
                # Single non-zero term means B_i is not identity
                return False
            try:
                S256Point.combine(terms)
                # combine succeeded, so B_i is not identity
                return False
            except RuntimeError:
                # combine failed, meaning sum is identity — this is correct
                continue

        return True

    @staticmethod
    def agg(C, commitments):
        """
        Aggregate commitments via Lagrange interpolation at x=0.

        D = Σ_{j∈C} λ_j · D_j = B_0  (the constant-term commitment)

        This value is the same regardless of which qualifying coalition C
        is used, because all shares lie on the same degree-(t-1) polynomial.

        Args:
            C: Coalition (sorted list of party ids)
            commitments: Dict {party_id: S256Point}

        Returns:
            Aggregated commitment point D.
        """
        terms = []
        for j in C:
            lam = lagrange_coeff_at_zero(j, C)
            if lam == 0:
                continue
            terms.append(lam * commitments[j])
        if len(terms) == 1:
            return terms[0]
        return S256Point.combine(terms)


# ─── Arctic: Deterministic Threshold Schnorr Signatures ─────────────────────
#
# Arctic uses VPSS1 to generate nonces deterministically.  The protocol:
#
#   KeyGen: Shamir-share a master signing key (sk^(2)_i for each party),
#           and generate VPSS1 keys (sk^(1)_i) for nonce generation.
#
#   Sign Round 1: Each party computes a deterministic session id
#           y = H2(pk, m) and generates its nonce share + commitment
#           via VPSS1.Gen.
#
#   Sign Round 2: Each party verifies all other parties' commitments
#           via VPSS1.Verify, aggregates the group nonce R, computes
#           the Schnorr challenge c = H3(R, pk, m), and outputs its
#           signature share z_k = r_k + c · sk^(2)_k.
#
#   Combine: Lagrange-interpolate the z_k shares to get z, output (R, z).
#
#   Verify: Standard Schnorr: check z·G = R + c·pk.
#
# The signature (R, z) is identical regardless of which qualifying
# coalition performs the signing, because VPSS1 is deterministic and
# the aggregated nonce R is coalition-independent.


class Arctic:
    """
    Arctic threshold Schnorr signature protocol.

    Args:
        n: Total number of signers
        t: Corruption threshold (tolerates up to t-1 corruptions)
        mu: Minimum signers required per session (must be >= 2t-1)
    """

    def __init__(self, n, t, mu):
        if mu < 2 * t - 1:
            raise ValueError(f"mu={mu} must be >= 2t-1={2*t-1}")
        if mu > n:
            raise ValueError(f"mu={mu} must be <= n={n}")
        if t < 2:
            raise ValueError("t must be >= 2 for meaningful threshold security")
        self.n = n
        self.t = t
        self.mu = mu

    def keygen(self):
        """
        Generate group key and per-participant key material.

        Performs two independent secret-sharing operations:
          1. Shamir(sk, n, t) → signing shares sk^(2)_i
          2. VPSS1.KeyGen(n, t, mu) → nonce-generation keys sk^(1)_i

        Returns:
            (pk, participants):
              pk - group public key (S256Point)
              participants - dict {id: {'pk': S256Point, 'sk': {...}}}
        """
        # Master signing key
        sk = secrets.randbelow(N - 1) + 1
        pk = sk * G

        # Shamir secret sharing of the signing key
        coeffs = [sk] + [secrets.randbelow(N - 1) + 1 for _ in range(self.t - 1)]
        signing_shares = {}
        for i in range(1, self.n + 1):
            signing_shares[i] = sum(c * pow(i, j, N) for j, c in enumerate(coeffs)) % N

        # VPSS1 keys for deterministic nonce generation
        vpss_keys = VPSS1.keygen(self.n, self.t, self.mu)
        if vpss_keys is None:
            raise RuntimeError("VPSS1.keygen failed")

        participants = {}
        for i in range(1, self.n + 1):
            participants[i] = {
                "pk": signing_shares[i] * G,
                "sk": {
                    "vpss_key": vpss_keys[i],
                    "signing_share": signing_shares[i],
                    "group_pk": pk,
                },
            }

        return pk, participants

    def sign1(self, k, sk_k, m):
        """
        Signing Round 1.

        Each participant deterministically derives a session id y_k from
        (pk, m), then generates a nonce share and commitment via VPSS1.

        Args:
            k: Participant identifier (1-indexed)
            sk_k: Participant's secret key dict
            m: Message (bytes)

        Returns:
            (y_k, R_k): 32-byte session id and nonce commitment point
        """
        pk_bytes = sk_k["group_pk"].sec()
        y_k = H2(pk_bytes, m)
        r_k, R_k = VPSS1.gen(k, sk_k["vpss_key"], y_k)
        return y_k, R_k

    def sign2(self, k, sk_k, m, C, round1_outputs):
        """
        Signing Round 2.

        Each participant:
          1. Re-derives the session id and checks all parties agree
          2. Re-derives its own nonce (stateless!) and verifies consistency
          3. Verifies all commitments via VPSS1.Verify
          4. Computes the Schnorr challenge and its signature share

        Args:
            k: Participant identifier
            sk_k: Participant's secret key dict
            m: Message (bytes)
            C: Coalition of participating signers (list of ids)
            round1_outputs: Dict {id: (y_j, R_j)} from Round 1

        Returns:
            z_k: Scalar signature share, or None if any check fails
        """
        C = sorted(C)
        if len(C) < self.mu:
            return None

        pk = sk_k["group_pk"]
        pk_bytes = pk.sec()

        # Derive the canonical session id
        y_prime = H2(pk_bytes, m)

        # Consistency check: all parties must agree on the session id
        for j in C:
            y_j, _ = round1_outputs[j]
            if y_j != y_prime:
                return None

        # Re-derive own nonce (stateless re-computation)
        r_k, R_k_check = VPSS1.gen(k, sk_k["vpss_key"], y_prime)

        # Verify own commitment wasn't tampered with
        _, R_k = round1_outputs[k]
        if R_k_check != R_k:
            return None

        # Verify all participants followed the VPSS1 protocol
        commitments = {j: round1_outputs[j][1] for j in C}
        if not VPSS1.verify(self.t, self.mu, C, commitments):
            return None

        # Aggregate group nonce commitment
        R = VPSS1.agg(C, commitments)

        # Schnorr challenge
        c = H3(R.sec(), pk_bytes, m)

        # Signature share: z_k = r_k + c · sk^(2)_k
        z_k = (r_k + c * sk_k["signing_share"]) % N
        return z_k

    def combine(self, pk, m, C, round1_outputs, sig_shares):
        """
        Combine partial signatures into a complete Schnorr signature.

        Aggregates the group nonce R from commitments, then Lagrange-
        interpolates the signature shares to recover the full response z.

        Args:
            pk: Group public key
            m: Message (bytes)
            C: Coalition of signers
            round1_outputs: Dict {id: (y_j, R_j)}
            sig_shares: Dict {id: z_j}

        Returns:
            (R, z): Complete Schnorr signature
        """
        C = sorted(C)
        commitments = {j: round1_outputs[j][1] for j in C}
        R = VPSS1.agg(C, commitments)

        z = 0
        for j in C:
            lam = lagrange_coeff_at_zero(j, C)
            z = (z + sig_shares[j] * lam) % N

        return R, z

    @staticmethod
    def verify(pk, m, signature):
        """
        Standard Schnorr signature verification.

        Checks z·G == R + c·pk  where c = H3(R, pk, m).

        Args:
            pk: Group public key (S256Point)
            m: Message (bytes)
            signature: (R, z) tuple

        Returns:
            True if the signature is valid.
        """
        R, z = signature
        c = H3(R.sec(), pk.sec(), m)
        lhs = z * G
        rhs = S256Point.combine([R, c * pk])
        return lhs == rhs
