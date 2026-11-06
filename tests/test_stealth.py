"""Tests for keyagreement.py and stealth.py. Run with:  pytest -q

The first block is Definition 4.1 (correctness) from the paper, one test per
bullet. After that come the things that must fail, then a few tests that
demonstrate why the design looks the way it does.
"""

import pytest

from succinct.group import ORDER, G, U, Point, random_scalar, inv
from succinct.pedersen import commit
from succinct.keyagreement import ka_msg, ka_key
from succinct.stealth import (
    AMOUNT_MASK, sakgen, sakgen_miner, otaccgen, view, receive,
    check_amount, check_tag,
)

Q = 3   # small q keeps the tests fast; the default (90) behaves the same


@pytest.fixture
def bob():
    return sakgen(Q)


@pytest.fixture
def carol():
    return sakgen(Q)


# --- key agreement --------------------------------------------------------

def test_key_agreement_matches():
    a, b = random_scalar(), random_scalar()
    assert ka_key(a, ka_msg(b), 1) == ka_key(b, ka_msg(a), 1)


def test_key_agreement_depends_on_index():
    a, b = random_scalar(), random_scalar()
    assert ka_key(a, ka_msg(b), 1) != ka_key(a, ka_msg(b), 2)


# --- Definition 4.1: correctness ------------------------------------------

def test_honest_payment_received_correctly(bob):
    # "Honestly generated payments should be received correctly."
    mpk, msk, _ = bob
    ck, acc, info = otaccgen(mpk, 1234, kappa=1)
    got = receive(msk, mpk, acc, info)
    assert got is not None
    ck2, a2, _, _ = got
    assert (ck2, a2) == (ck, 1234)


def test_received_payment_has_valid_amount_and_tag(bob):
    # "Correctly received payments should have well-defined amounts and tags."
    mpk, msk, _ = bob
    _, acc, info = otaccgen(mpk, 50, kappa=1)
    ck, a, sk, tag = receive(msk, mpk, acc, info)
    assert check_amount(acc, ck, a)
    assert check_tag(acc, sk, tag)


def test_honest_payment_viewed_correctly(bob):
    # "Honestly generated payment should be viewed correctly."
    mpk, _, vk = bob
    _, acc, info = otaccgen(mpk, 777, kappa=2)
    assert view(vk, acc, info) == 777


def test_miner_receives_coinbase():
    # Miner half of "honest miners receive all fees and the block reward".
    # Adding up reward + fees is Mine's job (step 3); here we check the account.
    mpk, msk, _ = sakgen_miner()
    reward_plus_fees = 600_000 + 37
    ck, acc, info = otaccgen(mpk, reward_plus_fees, kappa=0)
    assert ck == 1 and info is None
    got_ck, got_a, sk, tag = receive(msk, mpk, acc, info)
    assert (got_ck, got_a) == (1, reward_plus_fees)
    assert check_tag(acc, sk, tag)
    assert check_amount(acc, 1, reward_plus_fees)


def test_zero_and_max_amounts(bob):
    mpk, msk, vk = bob
    for a in (0, AMOUNT_MASK):
        _, acc, info = otaccgen(mpk, a, kappa=1)
        assert view(vk, acc, info) == a


# --- things that must fail ------------------------------------------------

def test_wrong_receiver_gets_nothing(bob, carol):
    mpk_b, _, _ = bob
    mpk_c, msk_c, vk_c = carol
    _, acc, info = otaccgen(mpk_b, 10, kappa=1)
    assert receive(msk_c, mpk_c, acc, info) is None
    assert view(vk_c, acc, info) is None


def test_wrong_info_fails(bob):
    mpk, msk, vk = bob
    _, acc, _ = otaccgen(mpk, 10, kappa=1)
    _, _, other_info = otaccgen(mpk, 10, kappa=1)
    assert view(vk, acc, other_info) is None


def test_wrong_kappa_fails(bob):
    mpk, _, vk = bob
    _, acc, info = otaccgen(mpk, 10, kappa=1)
    moved = type(acc)(pk=acc.pk, co=acc.co, ctxt=acc.ctxt, kappa=2)
    assert view(vk, moved, info) is None


def test_tampered_amount_detected(bob):
    # Ciphertext says one amount, commitment says another: reject. Otherwise a
    # sender could show you 100 while the coin only holds 1.
    mpk, msk, vk = bob
    _, acc, info = otaccgen(mpk, 100, kappa=1)
    bad = type(acc)(pk=acc.pk, co=acc.co, ctxt=acc.ctxt ^ 1, kappa=acc.kappa)
    assert view(vk, bad, info) is None
    assert receive(msk, mpk, bad, info) is None


def test_tampered_coin_detected(bob):
    mpk, _, vk = bob
    _, acc, info = otaccgen(mpk, 100, kappa=1)
    bad = type(acc)(pk=acc.pk, co=commit(100, random_scalar()), ctxt=acc.ctxt, kappa=1)
    assert view(vk, bad, info) is None


def test_check_functions_reject_wrong_openings(bob):
    mpk, msk, _ = bob
    _, acc, info = otaccgen(mpk, 5, kappa=1)
    ck, a, sk, tag = receive(msk, mpk, acc, info)
    assert not check_amount(acc, ck, a + 1)
    assert not check_amount(acc, ck + 1, a)
    assert not check_tag(acc, sk + 1, tag)
    assert not check_tag(acc, sk, (sk + 1) * U)
    assert not check_tag(acc, sk, sk * G)      # tag on the wrong base


def test_amount_out_of_range(bob):
    mpk, _, _ = bob
    with pytest.raises(ValueError):
        otaccgen(mpk, -1, kappa=1)
    with pytest.raises(ValueError):
        otaccgen(mpk, AMOUNT_MASK + 1, kappa=1)


def test_kappa_zero_only_for_miners(bob):
    mpk, _, _ = bob
    with pytest.raises(ValueError):
        otaccgen(mpk, 5, kappa=0)
    miner_mpk, _, _ = sakgen_miner()
    with pytest.raises(ValueError):
        otaccgen(miner_mpk, 5, kappa=1)


def test_miner_wrong_key_rejected():
    mpk1, _, _ = sakgen_miner()
    mpk2, msk2, _ = sakgen_miner()
    _, acc, info = otaccgen(mpk1, 600, kappa=0)
    assert receive(msk2, mpk2, acc, info) is None


# --- the q limit ----------------------------------------------------------

def test_receive_stops_after_q_accounts(bob):
    mpk, msk, vk = bob
    for _ in range(Q):
        _, acc, info = otaccgen(mpk, 1, kappa=1)
        assert receive(msk, mpk, acc, info) is not None
    _, acc, info = otaccgen(mpk, 1, kappa=1)
    assert receive(msk, mpk, acc, info) is None
    assert view(vk, acc, info) == 1      # still visible, just not spendable


def test_receiving_same_account_twice_uses_one_slot(bob):
    mpk, msk, _ = bob
    _, acc, info = otaccgen(mpk, 1, kappa=1)
    first = receive(msk, mpk, acc, info)
    second = receive(msk, mpk, acc, info)
    assert first == second
    assert len(msk.received) == 1


def test_why_the_q_limit_exists():
    # Suppose senders (who know each s_i) watch q+2 accounts of one receiver.
    # f has degree q, so its (q+1)-th divided difference is zero:
    #     sum_i f(s_i) / prod_{j != i} (s_i - s_j) = 0.
    # The same relation then holds for the tags U^{f(s_i)}. Anyone with the s_i
    # can check it and confirm "these tags all belong to the same person".
    # At q+1 or fewer points there's no such relation.
    _, msk, _ = sakgen(Q)
    s_vals = [random_scalar() for _ in range(Q + 2)]
    tags = [msk.f(s) * U for s in s_vals]

    def divided_difference(points, values):
        total = Point.identity()
        for i, si in enumerate(points):
            denom = 1
            for j, sj in enumerate(points):
                if j != i:
                    denom = denom * (si - sj) % ORDER
            total = total + inv(denom) * values[i]
        return total

    assert divided_difference(s_vals, tags).is_identity()      # linked

    random_tags = [random_scalar() * U for _ in s_vals]
    assert not divided_difference(s_vals, random_tags).is_identity()


# --- design properties ----------------------------------------------------

def test_one_time_keys_are_unlinkable_on_chain(bob):
    # Two payments to the same address look unrelated: different pk, coin, tag.
    mpk, msk, _ = bob
    _, acc1, info1 = otaccgen(mpk, 10, kappa=1)
    _, acc2, info2 = otaccgen(mpk, 10, kappa=1)
    assert acc1.pk != acc2.pk
    assert acc1.co != acc2.co
    tag1 = receive(msk, mpk, acc1, info1)[3]
    tag2 = receive(msk, mpk, acc2, info2)[3]
    assert tag1 != tag2


def test_shared_tdk_gives_one_info_per_tx(bob, carol):
    # Spend uses one tdk for all outputs (Section 6.2), so info is stored once.
    mpk_b, msk_b, _ = bob
    mpk_c, msk_c, _ = carol
    tdk = random_scalar()
    _, acc1, info1 = otaccgen(mpk_b, 70, kappa=1, tdk=tdk)
    _, acc2, info2 = otaccgen(mpk_c, 30, kappa=2, tdk=tdk)
    assert info1 == info2
    assert receive(msk_b, mpk_b, acc1, info1)[1] == 70
    assert receive(msk_c, mpk_c, acc2, info2)[1] == 30
    assert receive(msk_b, mpk_b, acc2, info2) is None


def test_view_key_cannot_spend(bob):
    # The view key holder sees amounts but has nothing to compute sk with.
    mpk, msk, vk = bob
    _, acc, info = otaccgen(mpk, 99, kappa=1)
    assert view(vk, acc, info) == 99
    assert not hasattr(vk, "thetas")
    sk = receive(msk, mpk, acc, info)[2]
    assert sk != vk.vdk


def test_miner_amount_is_public():
    # The root cause of both attacks in Section 3: anyone can read and check
    # a coinbase amount without any key.
    mpk, _, _ = sakgen_miner()
    _, acc, _ = otaccgen(mpk, 600_000, kappa=0)
    assert acc.ctxt == 600_000
    assert acc.co == commit(acc.ctxt, 1)


def test_miner_key_reuse_repeats_the_tag():
    # Two coinbases to one miner key -> same sk -> same tag. The second spend
    # would look like a double spend. Use sakgen_miner() fresh per block.
    mpk, msk, _ = sakgen_miner()
    _, acc1, i1 = otaccgen(mpk, 600, kappa=0)
    _, acc2, i2 = otaccgen(mpk, 700, kappa=0)
    assert receive(msk, mpk, acc1, i1)[3] == receive(msk, mpk, acc2, i2)[3]


def test_default_q_works():
    mpk, msk, vk = sakgen()          # q = 90
    assert len(mpk.lpk) == 91        # q + 1 coefficients
    _, acc, info = otaccgen(mpk, 42, kappa=1)
    assert view(vk, acc, info) == 42
    assert receive(msk, mpk, acc, info)[1] == 42
