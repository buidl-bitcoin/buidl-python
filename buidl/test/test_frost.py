from itertools import combinations
from unittest import TestCase

from buidl.ecc import N
from buidl.frost import FrostParticipant
from buidl.hd import HDPrivateKey
from buidl.tx import Tx, TxIn, TxOut


class FrostTest(TestCase):
    def test_frost(self):
        # create a three participant frost
        tests = [
            #            (1, 2),
            (3, 3),
            (2, 3),
            (3, 5),
            (4, 8),
            (5, 9),
        ]
        for t, n in tests:
            p_xs = [x for x in range(1, n + 1)]
            participants = []
            for x in p_xs:
                hd_priv = HDPrivateKey.from_mnemonic(
                    "oil oil oil oil oil oil oil oil oil oil oil oil",
                    password=f"FROST test {t}-of-{n} at {x}".encode("ascii"),
                    network="signet",
                )
                participants.append(FrostParticipant(t, p_xs, x, hd_priv=hd_priv))
            round_1_data = {}
            key_name = b"test"
            for p in participants:
                round_1_data[p.x] = p.key_generation_round_1(key_name)
            for p in participants:
                for x in p_xs:
                    p.verify_round_1(key_name, x, *round_1_data[x])
            for p1 in participants:
                for p2 in participants:
                    share = p1.key_generation_round_2(p2.x)
                    p2.verify_round_2(p1.x, share)
            for p in participants:
                group_pubkey = p.compute_keys()
            self.assertFalse(group_pubkey.parity)
            combos = combinations(participants, t)
            num_nonces = len([0 for _ in combos])
            num_nonces += num_nonces * n // (n - t + 1)
            nonce_pubs_lookup = {}
            for p in participants:
                hd_priv = HDPrivateKey.from_mnemonic(
                    "oil oil oil oil oil oil oil oil oil oil oil oil",
                    password=f"FROST test {t}-of-{n} at {p.x} nonces".encode("ascii"),
                    network="signet",
                )
                nonce_pubs_lookup[p.x] = p.extract_nonce_pairs(hd_priv, num_nonces)
            for p in participants:
                for x, nonce_pubs in nonce_pubs_lookup.items():
                    p.register_nonces(x, nonce_pubs)
            tweak = group_pubkey.tweak()
            tweaked_pubkey = group_pubkey.tweaked_key()
            for ps in combinations(participants, t):
                prev_tx = bytes.fromhex(
                    "66ee1cd94dde93df1b765f6ba5eecb74a5e9d14f901ae85c3e87a0645fc96bad"
                )
                prev_index = 0
                tx_in = TxIn(prev_tx, prev_index)
                script_pubkey = group_pubkey.p2tr_script(tweak=tweak)
                tx_in._value = 10000
                tx_in._script_pubkey = script_pubkey
                amount = 9000
                tx_out = TxOut(amount, script_pubkey)
                tx_obj = Tx(1, [tx_in], [tx_out], 0, segwit=True, network="signet")
                msg = tx_obj.sig_hash_bip341(0)
                nonces_to_use = {p.x: nonce_pubs_lookup[p.x].pop() for p in ps}
                sig_shares = {}
                for p in ps:
                    sig_shares[p.x] = p.sign(msg, nonces_to_use, tweak)
                schnorr_sig = ps[0].combine_sig_shares(
                    sig_shares, msg, nonces_to_use, tweak
                )
                self.assertTrue(tweaked_pubkey.verify_schnorr(msg, schnorr_sig))
                tx_obj.tx_ins[0].finalize_p2tr_keypath(schnorr_sig.serialize())
                self.assertTrue(tx_obj.verify())
            new_x = n + 1
            secret = 0
            p_xs = [x for x in range(1, t + 1)]
            for p in participants[:t]:
                p.enrolment_round_1(p_xs, new_x)
            for p in participants[:t]:
                for p2 in participants[:t]:
                    val = p.enrolment_round_1_send(p2.x)
                    p2.enrolment_round_1_receive(p.x, val)
            for p in participants[:t]:
                secret = (secret + p.enrolment_round_2_send()) % N
            new_participant = FrostParticipant(
                t, p_xs + [new_x], new_x, secret=secret, group_pubkey=group_pubkey
            )
            hd_priv = HDPrivateKey.from_mnemonic(
                "oil oil oil oil oil oil oil oil oil oil oil oil",
                password=f"FROST test {t}-of-{n} at {n+1} nonces".encode("ascii"),
            )
            new_nonces = new_participant.extract_nonce_pairs(hd_priv, num_nonces)
            nonce_pubs_lookup[new_x] = new_nonces
            for p in participants:
                p.add_participant(new_x, new_participant.pubkey, new_nonces)
            pubkeys = participants[0].pubkeys.copy()
            new_participant.pubkeys = pubkeys.copy()
            for x, nonce_pubs in nonce_pubs_lookup.items():
                new_participant.register_nonces(x, nonce_pubs)
            participants.append(new_participant)
            for p in participants[1:]:
                p.remove_participant(1)
            participants = participants[1:]
            for p in participants:
                p.key_update_round_1()
            for p in participants:
                polynomial = p.polynomial()
                for p2 in participants:
                    p2.key_update_round_1_register(p.x, polynomial)
            for p in participants:
                for p2 in participants:
                    share = p.key_update_round_2(p2.x)
                    p2.key_update_round_2_register(p.x, share)
            for p in participants:
                p.update_keys()
            for ps in combinations(participants, t):
                print([p.x for p in ps])
                prev_tx = bytes.fromhex(
                    "66ee1cd94dde93df1b765f6ba5eecb74a5e9d14f901ae85c3e87a0645fc96bad"
                )
                prev_index = 0
                tx_in = TxIn(prev_tx, prev_index)
                script_pubkey = group_pubkey.p2tr_script(tweak=tweak)
                tx_in._value = 10000
                tx_in._script_pubkey = script_pubkey
                amount = 9000
                tx_out = TxOut(amount, script_pubkey)
                tx_obj = Tx(1, [tx_in], [tx_out], 0, segwit=True, network="signet")
                msg = tx_obj.sig_hash_bip341(0)
                nonces_to_use = {p.x: nonce_pubs_lookup[p.x].pop() for p in ps}
                sig_shares = {}
                for p in ps:
                    sig_shares[p.x] = p.sign(msg, nonces_to_use, tweak)
                schnorr_sig = ps[0].combine_sig_shares(
                    sig_shares, msg, nonces_to_use, tweak
                )
                self.assertTrue(tweaked_pubkey.verify_schnorr(msg, schnorr_sig))
                tx_obj.tx_ins[0].finalize_p2tr_keypath(schnorr_sig.serialize())
                self.assertTrue(tx_obj.verify())
