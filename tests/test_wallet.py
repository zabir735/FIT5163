"""Tests for wallet.py: self-transfer and multi-self-transfer (paper §3.1).

The finding these tests document: combined with the S-1 rule (§3.2), a miner
can never spend coinbases on their own. Multi-self-transfer, as the paper
describes it ("spend multiple coinbase outputs ... to at least two non-mining
accounts"), only works if an ordinary coin is added as an extra input.
"""

import pytest

from succinct.chain import Chain
from succinct.ct import verify
from succinct.stealth import sakgen, sakgen_miner, otaccgen, receive, view
from succinct.wallet import self_transfer, multi_self_transfer

REWARD = 600


@pytest.fixture
def chain():
    c = Chain(reward=REWARD)
    for _ in range(30):                       # decoys
        mpk, _, _ = sakgen(1)
        _, acc, info = otaccgen(mpk, 1000, 1)
        c.add_output(acc, info)
    return c


def mine_coinbases(chain, k):
    """k coinbases, a fresh miner key per block (key reuse repeats the tag)."""
    out = []
    for _ in range(k):
        mpk, msk, _ = sakgen_miner()
        out.append((chain.mine_block(mpk), mpk, msk))
    return out


def ordinary_coin(chain, wallet, amount):
    mpk, msk, _ = wallet
    _, acc, info = otaccgen(mpk, amount, 1)
    return (chain.add_output(acc, info), mpk, msk)


# --- multi-self-transfer --------------------------------------------------

def test_coinbases_alone_are_refused(chain):
    # The finding: S = 3 coinbase inputs, the ring may hold at most S-1 = 2
    # miner accounts, so pure consolidation is impossible.
    selves = [sakgen(5)[0], sakgen(5)[0]]
    with pytest.raises(ValueError, match="S-1"):
        multi_self_transfer(chain, mine_coinbases(chain, 3), None, selves, fee=3)


def test_coinbases_plus_ordinary_coin_verifies(chain):
    savings = sakgen(5)
    self_a, self_b = sakgen(5), sakgen(5)
    coinbases = mine_coinbases(chain, 3)
    ordinary = ordinary_coin(chain, savings, 50)

    tx, sig, amounts = multi_self_transfer(
        chain, coinbases, ordinary, [self_a[0], self_b[0]], fee=3)

    assert verify(tx, sig, chain) is True
    assert len(tx.tags) == 4                         # one transaction, four inputs
    assert sum(amounts) == 3 * REWARD + 50 - 3       # everything except the fee
    assert all(a > 0 for a in amounts)               # both accounts get something

    refs = chain.submit(tx, sig)
    for (mpk, msk, _), ref, amt in zip([self_a, self_b], refs, amounts):
        assert receive(msk, mpk, *chain.get(ref))[1] == amt


def test_ring_respects_s_minus_one(chain):
    savings = sakgen(5)
    coinbases = mine_coinbases(chain, 3)
    tx, _, _ = multi_self_transfer(
        chain, coinbases, ordinary_coin(chain, savings, 50),
        [sakgen(5)[0], sakgen(5)[0]], fee=3)
    miners_in_ring = sum(chain.get(r)[0].is_miner for r in tx.ring_refs)
    assert miners_in_ring <= len(tx.tags) - 1


def test_needs_two_self_accounts(chain):
    with pytest.raises(ValueError, match="two"):
        multi_self_transfer(chain, mine_coinbases(chain, 2),
                            ordinary_coin(chain, sakgen(5), 50), [sakgen(5)[0]], fee=1)


def test_self_accounts_must_not_be_miner_keys(chain):
    with pytest.raises(ValueError, match="non-mining"):
        multi_self_transfer(chain, mine_coinbases(chain, 2),
                            ordinary_coin(chain, sakgen(5), 50),
                            [sakgen(5)[0], sakgen_miner()[0]], fee=1)


def test_outsider_learns_no_amount(chain):
    # Eve holds someone else's view key: she can't open any output, so she has
    # nothing to compare with the public coinbase amounts.
    coinbases = mine_coinbases(chain, 2)
    tx, sig, _ = multi_self_transfer(
        chain, coinbases, ordinary_coin(chain, sakgen(5), 50),
        [sakgen(5)[0], sakgen(5)[0]], fee=1)
    _, _, eve_vk = sakgen(5)
    assert all(view(eve_vk, acc, tx.info) is None for acc in tx.outputs)


# --- single self-transfer -------------------------------------------------

def test_self_transfer_verifies(chain):
    (cb,) = mine_coinbases(chain, 1)
    savings, bob, me = sakgen(5), sakgen(5), sakgen(5)
    tx, sig = self_transfer(chain, cb, ordinary_coin(chain, savings, 100),
                            bob[0], 500, me[0], fee=5)
    assert verify(tx, sig, chain) is True
    refs = chain.submit(tx, sig)
    assert view(bob[2], *chain.get(refs[0])) == 500
    # Bob's view-key holder sees 500 + fee 5 = 505, which matches no coinbase.
    assert 500 + 5 != REWARD


def test_self_transfer_refuses_zero_change(chain):
    (cb,) = mine_coinbases(chain, 1)
    savings, bob, me = sakgen(5), sakgen(5), sakgen(5)
    with pytest.raises(ValueError, match="non-zero"):
        self_transfer(chain, cb, ordinary_coin(chain, savings, 100),
                      bob[0], REWARD + 100 - 5, me[0], fee=5)
