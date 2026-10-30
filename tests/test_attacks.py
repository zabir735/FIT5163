"""Part C: the attack scripts must keep showing what the report claims.

Small trial counts so the suite stays fast. Written with AI assistance (Claude); review before use.
"""

import random

from attacks._common import Eve, Wallet, World
from attacks.miner_privacy import one_trial
from attacks.q_bound_linkability import run_q
from attacks.related_key_tag import NaiveRecipient, PolyRecipient, RULES, one_trial as rk_trial


def test_miner_privacy_unmitigated_is_always_broken():
    rng = random.Random(1)
    world = World(8, rng)
    for _ in range(5):
        hit, certain, _, _ = one_trial(world, "legacy", 8, rng, 3)
        assert hit and certain


def test_miner_privacy_mitigation_removes_exact_match():
    rng = random.Random(2)
    world = World(8, rng)
    for kind in ("self_only", "full"):
        for _ in range(5):
            _, certain, valid, _ = one_trial(world, kind, 8, rng, 3)
            assert not certain
            assert valid in (None, True)


def test_careless_self_transfer_still_leaks():
    rng = random.Random(3)
    world = World(8, rng)
    hit, certain, valid, _ = one_trial(world, "careless", 8, rng, 3)
    assert hit and certain and valid


def test_related_key_naive_linked_polynomial_not():
    naive = {n: {"same": 0, "diff": 0} for n in RULES}
    poly = {n: {"same": 0, "diff": 0} for n in RULES}
    for _ in range(3):
        rk_trial(NaiveRecipient, naive)
        rk_trial(PolyRecipient, poly)
    rule = next(iter(RULES))
    assert naive[rule]["same"] == 3 and naive[rule]["diff"] == 0
    assert all(v["same"] == 0 and v["diff"] == 0 for v in poly.values())


def test_q_bound_attack_needs_exactly_q_plus_1_tags():
    hits, false_pos, refused = run_q(2, 2)
    assert hits[1] == 0 and hits[2] == 0 and hits[3] == 2
    assert false_pos == 0 and refused == 2


def test_chain_scenario_enforces_rules_and_careless_still_leaks():
    from attacks.chain_scenario import new_chain, run_trial
    from succinct.nizk import stub

    rng = random.Random(4)
    chain, ordinary, coinbases = new_chain(8, stub, rng)
    for careless in (False, True):
        r = run_trial(chain, ordinary, coinbases, 8, rng, careless)
        assert r["refused"] and r["rejected"]          # coinbase alone: wallet refuses, chain says ⊥
        assert r["pay_ring_coinbases"] == 0            # ordinary spends get no coinbase decoys
        assert r["certain"] == careless                # exact match only when careless
