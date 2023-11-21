from itertools import combinations
from unittest import TestCase

from buidl.frost import FrostParticipant
from buidl.helper import sha256


class FrostTest(TestCase):
    def test_frost(self):
        # create a three participant frost
        tests = [
            (1, 2),
            (2, 3),
            (3, 5),
            (4, 7),
            (5, 9),
            (3, 3),
            (4, 8),
        ]
        for t, n in tests:
            participants = [FrostParticipant(t, n, i) for i in range(n)]
            round_1_data = []
            key_name = b"test"
            for p in participants:
                round_1_data.append(p.key_generation_round_1(key_name))
            for p in participants:
                for i in range(n):
                    p.verify_round_1(key_name, i, *round_1_data[i])
            for i, p in enumerate(participants):
                for j, share in enumerate(p.key_generation_round_2()):
                    participants[j].verify_round_2(i, share)
            for p in participants:
                group_pubkey = p.compute_keys()
            self.assertFalse(group_pubkey.parity)
            combos = combinations(participants, t)
            num_nonces = len([0 for _ in combos])
            nonce_pubs = []
            for p in participants:
                nonce_pubs.append(p.generate_nonce_pairs(num_nonces))
            for p in participants:
                p.register_nonce_pubs(nonce_pubs)
            msg = sha256(b"I am testing FROST")
            for ps in combinations(participants, t):
                nonces_to_use = {p.index: nonce_pubs[p.index].pop() for p in ps}
                shares = []
                for p in ps:
                    shares.append(p.sign(msg, nonces_to_use))
                schnorr_sig = ps[0].combine_shares(shares, msg, nonces_to_use)
                self.assertTrue(group_pubkey.verify_schnorr(msg, schnorr_sig))
