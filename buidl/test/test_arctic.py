from itertools import combinations
from math import comb
from unittest import TestCase

from buidl.ecc import N, G

from buidl.arctic import (
    Arctic,
    VPSS1,
    H1,
    H2,
    H3,
    mod_inv,
    lagrange_coeff_at_zero,
    lagrange_basis_poly_coeffs,
)
from buidl.hash import tagged_hash
from buidl.helper import big_endian_to_int, int_to_big_endian


def full_sign(protocol, pk, participants, m, coalition):
    """Run the complete Arctic signing protocol and return (signature, round1, sig_shares)."""
    round1 = {k: protocol.sign1(k, participants[k]["sk"], m) for k in coalition}
    sig_shares = {}
    for k in coalition:
        z_k = protocol.sign2(k, participants[k]["sk"], m, coalition, round1)
        sig_shares[k] = z_k
    sig = protocol.combine(pk, m, coalition, round1, sig_shares)
    return sig, round1, sig_shares


class H1Test(TestCase):
    def test_deterministic(self):
        self.assertEqual(H1(42, b"input"), H1(42, b"input"))

    def test_different_phi(self):
        self.assertNotEqual(H1(1, b"input"), H1(2, b"input"))

    def test_different_w(self):
        self.assertNotEqual(H1(42, b"a"), H1(42, b"b"))

    def test_output_range(self):
        result = H1(99, b"test")
        self.assertTrue(0 <= result < N)

    def test_string_input(self):
        result = H1(1, "hello")
        self.assertTrue(0 <= result < N)


class H2Test(TestCase):
    def test_deterministic(self):
        pk = (42 * G).sec()
        self.assertEqual(H2(pk, b"msg"), H2(pk, b"msg"))

    def test_different_pk(self):
        pk1 = (1 * G).sec()
        pk2 = (2 * G).sec()
        self.assertNotEqual(H2(pk1, b"msg"), H2(pk2, b"msg"))

    def test_different_msg(self):
        pk = (42 * G).sec()
        self.assertNotEqual(H2(pk, b"a"), H2(pk, b"b"))

    def test_output_length(self):
        pk = G.sec()
        self.assertEqual(len(H2(pk, b"msg")), 32)


class H3Test(TestCase):
    def test_deterministic(self):
        R = (10 * G).sec()
        pk = (20 * G).sec()
        self.assertEqual(H3(R, pk, b"msg"), H3(R, pk, b"msg"))

    def test_output_range(self):
        R = (10 * G).sec()
        pk = (20 * G).sec()
        self.assertTrue(0 <= H3(R, pk, b"msg") < N)

    def test_domain_separation_from_h2(self):
        pk = (42 * G).sec()
        h2_result = big_endian_to_int(H2(pk, b"msg")) % N
        h3_result = H3(pk, pk, b"msg")
        self.assertNotEqual(h2_result, h3_result)


class LagrangeCoeffAtZeroTest(TestCase):
    def test_sum_to_one(self):
        for coalition in [[1, 2], [1, 2, 3], [2, 5, 7], [1, 3, 5, 7]]:
            total = sum(lagrange_coeff_at_zero(j, coalition) for j in coalition) % N
            self.assertEqual(total, 1)

    def test_interpolation(self):
        secret = 10
        f = lambda x: (secret + 3 * x) % N
        points = {1: f(1), 2: f(2), 3: f(3)}
        for coalition in [[1, 2], [2, 3], [1, 3]]:
            recovered = (
                sum(points[j] * lagrange_coeff_at_zero(j, coalition) for j in coalition)
                % N
            )
            self.assertEqual(recovered, secret)

    def test_single_party_is_one(self):
        self.assertEqual(lagrange_coeff_at_zero(5, [5]), 1)


class LagrangeBasisPolyCoeffsTest(TestCase):
    def test_degree(self):
        coalition = [1, 3, 5]
        coeffs = lagrange_basis_poly_coeffs(1, coalition)
        self.assertEqual(len(coeffs), len(coalition))

    def test_eval_at_zero_matches(self):
        for coalition in [[1, 2, 3], [2, 4, 6], [1, 3, 5, 7]]:
            for j in coalition:
                coeffs = lagrange_basis_poly_coeffs(j, coalition)
                self.assertEqual(coeffs[0], lagrange_coeff_at_zero(j, coalition))

    def test_basis_property(self):
        coalition = [1, 3, 5]
        for j in coalition:
            coeffs = lagrange_basis_poly_coeffs(j, coalition)
            for k in coalition:
                val = sum(c * pow(k, i, N) for i, c in enumerate(coeffs)) % N
                expected = 1 if k == j else 0
                self.assertEqual(val, expected)


class VPSS1KeyGenTest(TestCase):
    def test_returns_none_for_bad_mu(self):
        self.assertIsNone(VPSS1.keygen(5, 3, 4))
        self.assertIsNone(VPSS1.keygen(5, 2, 6))

    def test_correct_number_of_keys(self):
        keys = VPSS1.keygen(5, 2, 3)
        self.assertEqual(len(keys), 5)
        self.assertEqual(set(keys.keys()), {1, 2, 3, 4, 5})

    def test_key_size(self):
        n, t, mu = 5, 2, 3
        keys = VPSS1.keygen(n, t, mu)
        expected = comb(n - 1, t - 1)
        for j in range(1, n + 1):
            self.assertEqual(len(keys[j]), expected)

    def test_party_not_in_own_subsets(self):
        keys = VPSS1.keygen(5, 3, 5)
        for j, entries in keys.items():
            for subset, _ in entries:
                self.assertNotIn(j, subset)

    def test_subset_size(self):
        n, t = 5, 3
        keys = VPSS1.keygen(n, t, 2 * t - 1)
        for entries in keys.values():
            for subset, _ in entries:
                self.assertEqual(len(subset), t - 1)


class VPSS1GenTest(TestCase):
    def test_commitment_matches_share(self):
        keys = VPSS1.keygen(5, 2, 3)
        d, D = VPSS1.gen(1, keys[1], b"test")
        self.assertEqual(D.sec(), (d * G).sec())

    def test_deterministic(self):
        keys = VPSS1.keygen(5, 2, 3)
        d1, D1 = VPSS1.gen(3, keys[3], b"input")
        d2, D2 = VPSS1.gen(3, keys[3], b"input")
        self.assertEqual(d1, d2)
        self.assertEqual(D1.sec(), D2.sec())

    def test_different_inputs_differ(self):
        keys = VPSS1.keygen(5, 2, 3)
        d1, _ = VPSS1.gen(1, keys[1], b"a")
        d2, _ = VPSS1.gen(1, keys[1], b"b")
        self.assertNotEqual(d1, d2)

    def test_string_input(self):
        keys = VPSS1.keygen(5, 2, 3)
        d, D = VPSS1.gen(1, keys[1], "hello")
        self.assertTrue(0 <= d < N)
        self.assertEqual(len(D.sec()), 33)


class VPSS1ShareConsistencyTest(TestCase):
    def setUp(self):
        n, t, mu = 5, 2, 3
        keys = VPSS1.keygen(n, t, mu)
        w = b"consistency_test"
        self.n = n
        self.t = t
        self.mu = mu
        self.shares = {}
        self.commitments = {}
        for k in range(1, n + 1):
            d, D = VPSS1.gen(k, keys[k], w)
            self.shares[k] = d
            self.commitments[k] = D

    def test_any_t_parties_recover_same_secret(self):
        recovered_values = set()
        for coalition in combinations(range(1, self.n + 1), self.t):
            coalition = list(coalition)
            d = (
                sum(
                    self.shares[j] * lagrange_coeff_at_zero(j, coalition)
                    for j in coalition
                )
                % N
            )
            recovered_values.add(d)
        self.assertEqual(len(recovered_values), 1)

    def test_any_coalition_aggregates_same_commitment(self):
        agg_points = set()
        for coalition in combinations(range(1, self.n + 1), self.mu):
            D = VPSS1.agg(list(coalition), self.commitments)
            agg_points.add(D.sec())
        self.assertEqual(len(agg_points), 1)

    def test_commitment_equals_secret_times_g(self):
        coalition = [1, 2]
        d = (
            sum(
                self.shares[j] * lagrange_coeff_at_zero(j, coalition) for j in coalition
            )
            % N
        )
        D = VPSS1.agg(coalition, self.commitments)
        self.assertEqual(D.sec(), (d * G).sec())


class VPSS1VerifyTest(TestCase):
    def _make_commitments(self, n, t, mu):
        keys = VPSS1.keygen(n, t, mu)
        commitments = {}
        for k in range(1, n + 1):
            _, D = VPSS1.gen(k, keys[k], b"v")
            commitments[k] = D
        return commitments

    def test_honest_full_coalition(self):
        n, t, mu = 5, 2, 3
        commitments = self._make_commitments(n, t, mu)
        self.assertTrue(VPSS1.verify(t, mu, list(range(1, n + 1)), commitments))

    def test_honest_minimum_coalition(self):
        n, t, mu = 5, 2, 3
        commitments = self._make_commitments(n, t, mu)
        self.assertTrue(VPSS1.verify(t, mu, [1, 3, 5], commitments))

    def test_rejects_too_small_coalition(self):
        n, t, mu = 5, 2, 3
        commitments = self._make_commitments(n, t, mu)
        self.assertFalse(VPSS1.verify(t, mu, [1, 2], commitments))

    def test_rejects_single_tampered_commitment(self):
        n, t, mu = 5, 2, 3
        commitments = self._make_commitments(n, t, mu)
        bad = dict(commitments)
        bad[3] = 77777 * G
        self.assertFalse(VPSS1.verify(t, mu, [1, 2, 3], bad))

    def test_rejects_random_points(self):
        import secrets

        commitments = {j: secrets.randbelow(N) * G for j in range(1, 6)}
        self.assertFalse(VPSS1.verify(2, 3, [1, 2, 3], commitments))

    def test_higher_threshold(self):
        n, t, mu = 7, 3, 5
        commitments = self._make_commitments(n, t, mu)
        self.assertTrue(VPSS1.verify(t, mu, [1, 2, 3, 4, 5], commitments))
        self.assertTrue(VPSS1.verify(t, mu, [3, 4, 5, 6, 7], commitments))


class ArcticInitTest(TestCase):
    def test_valid_params(self):
        a = Arctic(5, 2, 3)
        self.assertEqual(a.n, 5)
        self.assertEqual(a.t, 2)
        self.assertEqual(a.mu, 3)

    def test_mu_too_small(self):
        with self.assertRaises(ValueError):
            Arctic(5, 2, 2)

    def test_mu_too_large(self):
        with self.assertRaises(ValueError):
            Arctic(5, 2, 6)

    def test_t_too_small(self):
        with self.assertRaises(ValueError):
            Arctic(5, 1, 3)


class ArcticKeyGenTest(TestCase):
    def test_returns_pk_and_participants(self):
        protocol = Arctic(5, 2, 3)
        pk, participants = protocol.keygen()
        self.assertEqual(len(pk.sec()), 33)
        self.assertEqual(len(participants), 5)

    def test_participant_structure(self):
        protocol = Arctic(5, 2, 3)
        _, participants = protocol.keygen()
        for i in range(1, 6):
            self.assertIn("pk", participants[i])
            self.assertIn("sk", participants[i])
            sk = participants[i]["sk"]
            self.assertIn("vpss_key", sk)
            self.assertIn("signing_share", sk)
            self.assertIn("group_pk", sk)

    def test_signing_shares_are_shamir(self):
        protocol = Arctic(5, 2, 3)
        pk, participants = protocol.keygen()
        shares = {i: participants[i]["sk"]["signing_share"] for i in range(1, 6)}
        for c in [[1, 2], [3, 5], [1, 4]]:
            sk = sum(shares[j] * lagrange_coeff_at_zero(j, c) for j in c) % N
            self.assertEqual((sk * G).sec(), pk.sec())


class ArcticSign1Test(TestCase):
    def test_returns_session_and_commitment(self):
        protocol = Arctic(5, 2, 3)
        pk, parts = protocol.keygen()
        y, R = protocol.sign1(1, parts[1]["sk"], b"msg")
        self.assertEqual(len(y), 32)
        self.assertEqual(len(R.sec()), 33)

    def test_deterministic(self):
        protocol = Arctic(5, 2, 3)
        pk, parts = protocol.keygen()
        y1, R1 = protocol.sign1(1, parts[1]["sk"], b"msg")
        y2, R2 = protocol.sign1(1, parts[1]["sk"], b"msg")
        self.assertEqual(y1, y2)
        self.assertEqual(R1.sec(), R2.sec())

    def test_all_parties_same_session_id(self):
        protocol = Arctic(5, 2, 3)
        pk, parts = protocol.keygen()
        m = b"same session"
        ys = set()
        for k in range(1, 6):
            y, _ = protocol.sign1(k, parts[k]["sk"], m)
            ys.add(y)
        self.assertEqual(len(ys), 1)

    def test_different_messages_different_session(self):
        protocol = Arctic(5, 2, 3)
        pk, parts = protocol.keygen()
        y1, _ = protocol.sign1(1, parts[1]["sk"], b"a")
        y2, _ = protocol.sign1(1, parts[1]["sk"], b"b")
        self.assertNotEqual(y1, y2)


class ArcticSign2Test(TestCase):
    def setUp(self):
        self.protocol = Arctic(5, 2, 3)
        self.pk, self.parts = self.protocol.keygen()

    def test_produces_signature_share(self):
        m = b"msg"
        coalition = [1, 2, 3]
        r1 = {k: self.protocol.sign1(k, self.parts[k]["sk"], m) for k in coalition}
        z = self.protocol.sign2(1, self.parts[1]["sk"], m, coalition, r1)
        self.assertIsNotNone(z)
        self.assertTrue(0 < z < N)

    def test_rejects_insufficient_coalition(self):
        m = b"msg"
        coalition = [1, 2]
        r1 = {k: self.protocol.sign1(k, self.parts[k]["sk"], m) for k in coalition}
        self.assertIsNone(self.protocol.sign2(1, self.parts[1]["sk"], m, coalition, r1))

    def test_rejects_mismatched_session_id(self):
        coalition = [1, 2, 3]
        r1 = {k: self.protocol.sign1(k, self.parts[k]["sk"], b"msg") for k in coalition}
        bad_y, _ = self.protocol.sign1(2, self.parts[2]["sk"], b"different")
        r1[2] = (bad_y, r1[2][1])
        self.assertIsNone(
            self.protocol.sign2(1, self.parts[1]["sk"], b"msg", coalition, r1)
        )

    def test_rejects_tampered_commitment(self):
        m = b"msg"
        coalition = [1, 2, 3]
        r1 = {k: self.protocol.sign1(k, self.parts[k]["sk"], m) for k in coalition}
        r1[2] = (r1[2][0], 99999 * G)
        self.assertIsNone(self.protocol.sign2(2, self.parts[2]["sk"], m, coalition, r1))
        self.assertIsNone(self.protocol.sign2(1, self.parts[1]["sk"], m, coalition, r1))


class ArcticSignAndVerifyTest(TestCase):
    def test_basic_3_of_5(self):
        protocol = Arctic(5, 2, 3)
        pk, parts = protocol.keygen()
        sig, _, _ = full_sign(protocol, pk, parts, b"hello", [1, 3, 5])
        self.assertTrue(Arctic.verify(pk, b"hello", sig))

    def test_3_of_3(self):
        protocol = Arctic(3, 2, 3)
        pk, parts = protocol.keygen()
        sig, _, _ = full_sign(protocol, pk, parts, b"msg", [1, 2, 3])
        self.assertTrue(Arctic.verify(pk, b"msg", sig))

    def test_5_of_7(self):
        protocol = Arctic(7, 3, 5)
        pk, parts = protocol.keygen()
        sig, _, _ = full_sign(protocol, pk, parts, b"msg", [1, 2, 4, 5, 7])
        self.assertTrue(Arctic.verify(pk, b"msg", sig))

    def test_all_parties(self):
        protocol = Arctic(5, 2, 3)
        pk, parts = protocol.keygen()
        sig, _, _ = full_sign(protocol, pk, parts, b"msg", [1, 2, 3, 4, 5])
        self.assertTrue(Arctic.verify(pk, b"msg", sig))

    def test_empty_message(self):
        protocol = Arctic(5, 2, 3)
        pk, parts = protocol.keygen()
        sig, _, _ = full_sign(protocol, pk, parts, b"", [1, 2, 3])
        self.assertTrue(Arctic.verify(pk, b"", sig))

    def test_long_message(self):
        protocol = Arctic(5, 2, 3)
        pk, parts = protocol.keygen()
        m = b"x" * 10000
        sig, _, _ = full_sign(protocol, pk, parts, m, [1, 2, 3])
        self.assertTrue(Arctic.verify(pk, m, sig))


class ArcticVerifyRejectsTest(TestCase):
    def setUp(self):
        protocol = Arctic(5, 2, 3)
        self.pk, parts = protocol.keygen()
        self.m = b"the message"
        self.sig, _, _ = full_sign(protocol, self.pk, parts, self.m, [1, 3, 5])

    def test_wrong_message(self):
        self.assertFalse(Arctic.verify(self.pk, b"wrong", self.sig))

    def test_wrong_pk(self):
        fake_pk = 12345 * G
        self.assertFalse(Arctic.verify(fake_pk, self.m, self.sig))

    def test_wrong_z(self):
        R, z = self.sig
        self.assertFalse(Arctic.verify(self.pk, self.m, (R, (z + 1) % N)))

    def test_wrong_R(self):
        _, z = self.sig
        fake_R = 54321 * G
        self.assertFalse(Arctic.verify(self.pk, self.m, (fake_R, z)))


class ArcticDeterministicTest(TestCase):
    def test_two_coalitions_same_sig(self):
        protocol = Arctic(5, 2, 3)
        pk, parts = protocol.keygen()
        m = b"deterministic"
        sig1, _, _ = full_sign(protocol, pk, parts, m, [1, 3, 5])
        sig2, _, _ = full_sign(protocol, pk, parts, m, [2, 3, 4])
        self.assertEqual(sig1[0].sec(), sig2[0].sec())
        self.assertEqual(sig1[1], sig2[1])

    def test_all_possible_coalitions_same_sig(self):
        protocol = Arctic(5, 2, 3)
        pk, parts = protocol.keygen()
        m = b"all coalitions"
        signatures = []
        for coalition in combinations(range(1, 6), 3):
            sig, _, _ = full_sign(protocol, pk, parts, m, list(coalition))
            signatures.append(sig)
        R_set = {s[0].sec() for s in signatures}
        self.assertEqual(len(R_set), 1)
        z_set = {s[1] for s in signatures}
        self.assertEqual(len(z_set), 1)

    def test_deterministic_across_superset_coalitions(self):
        protocol = Arctic(5, 2, 3)
        pk, parts = protocol.keygen()
        m = b"supersets"
        sig3, _, _ = full_sign(protocol, pk, parts, m, [1, 2, 3])
        sig4, _, _ = full_sign(protocol, pk, parts, m, [1, 2, 3, 4])
        sig5, _, _ = full_sign(protocol, pk, parts, m, [1, 2, 3, 4, 5])
        self.assertEqual(sig3[1], sig4[1])
        self.assertEqual(sig4[1], sig5[1])
        self.assertEqual(sig3[0].sec(), sig4[0].sec())
        self.assertEqual(sig4[0].sec(), sig5[0].sec())

    def test_same_message_same_sig(self):
        protocol = Arctic(5, 2, 3)
        pk, parts = protocol.keygen()
        m = b"repeat"
        sig1, _, _ = full_sign(protocol, pk, parts, m, [1, 2, 3])
        sig2, _, _ = full_sign(protocol, pk, parts, m, [1, 2, 3])
        self.assertEqual(sig1[1], sig2[1])
        self.assertEqual(sig1[0].sec(), sig2[0].sec())

    def test_different_messages_different_sigs(self):
        protocol = Arctic(5, 2, 3)
        pk, parts = protocol.keygen()
        sig1, _, _ = full_sign(protocol, pk, parts, b"msg1", [1, 2, 3])
        sig2, _, _ = full_sign(protocol, pk, parts, b"msg2", [1, 2, 3])
        self.assertNotEqual(sig1[1], sig2[1])

    def test_5_of_7_deterministic(self):
        protocol = Arctic(7, 3, 5)
        pk, parts = protocol.keygen()
        m = b"7 party"
        sig1, _, _ = full_sign(protocol, pk, parts, m, [1, 2, 3, 4, 5])
        sig2, _, _ = full_sign(protocol, pk, parts, m, [3, 4, 5, 6, 7])
        self.assertEqual(sig1[0].sec(), sig2[0].sec())
        self.assertEqual(sig1[1], sig2[1])


class ArcticStatelessTest(TestCase):
    def test_round1_idempotent(self):
        protocol = Arctic(5, 2, 3)
        _, parts = protocol.keygen()
        sk = parts[1]["sk"]
        m = b"idempotent"
        results = [protocol.sign1(1, sk, m) for _ in range(5)]
        for y, R in results:
            self.assertEqual(y, results[0][0])
            self.assertEqual(R.sec(), results[0][1].sec())

    def test_sign2_re_derives_nonce(self):
        protocol = Arctic(5, 2, 3)
        pk, parts = protocol.keygen()
        m = b"stateless"
        coalition = [1, 2, 3]
        r1 = {k: protocol.sign1(k, parts[k]["sk"], m) for k in coalition}
        for k in coalition:
            z = protocol.sign2(k, parts[k]["sk"], m, coalition, r1)
            self.assertIsNotNone(z)


class ArcticSchnorrEquationTest(TestCase):
    def test_equation_holds(self):
        protocol = Arctic(5, 2, 3)
        pk, parts = protocol.keygen()
        m = b"schnorr check"
        sig, _, _ = full_sign(protocol, pk, parts, m, [1, 2, 3])
        R, z = sig
        c = H3(R.sec(), pk.sec(), m)
        lhs = z * G
        from buidl.ecc import S256Point

        rhs = S256Point.combine([R, c * pk])
        self.assertEqual(lhs.sec(), rhs.sec())

    def test_signature_components_nonzero(self):
        protocol = Arctic(5, 2, 3)
        pk, parts = protocol.keygen()
        sig, _, _ = full_sign(protocol, pk, parts, b"nz", [1, 2, 3])
        R, z = sig
        self.assertEqual(len(R.sec()), 33)
        self.assertNotEqual(z, 0)
