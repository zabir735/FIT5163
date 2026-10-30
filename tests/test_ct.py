"""Tests for ct.py (Spend, Verify, Mine) and the Eq. 5 relation.

Every test that builds a chain runs twice through the `nizk` fixture: once
with the stub proof (checks the scheme's algebra and rules) and once with the
real Σ-protocol (checks the proof accepts and rejects the same things). The
relation tests at the bottom read the witness out of the stub's "proof", so
they run with the stub only.
"""

import dataclasses

import pytest

from succinct import ct
from succinct.chain import Chain
from succinct.ct import (
    SpendInput, SpendOutput, Transaction, Signature,
    make_outputs, pick_ring, MAX_OUTPUTS,
)
from succinct.group import ORDER, G, random_scalar
from succinct.pedersen import commit
from succinct.stealth import Account, sakgen, sakgen_miner, otaccgen, receive, view
from succinct.nizk import sigma_ring, stub
from succinct.nizk.relation import relation_holds

Q = 20

stub_only = pytest.mark.parametrize("nizk", [stub], ids=["stub"])


@pytest.fixture(params=[stub, sigma_ring], ids=["stub", "sigma"])
def nizk(request):
    return request.param


def verify(tx, sig, chain):
    """ct.verify with whichever proof system the chain was built with."""
    return ct.verify(tx, sig, chain, nizk=chain.nizk)


# --- helpers --------------------------------------------------------------

class Wallet:
    def __init__(self):
        self.mpk, self.msk, self.vk = sakgen(Q)
        self.coins = []                    # refs this wallet owns

    def take(self, chain, ref):
        acc, info = chain.get(ref)
        got = receive(self.msk, self.mpk, acc, info)
        assert got is not None
        return got


def fresh_chain(decoys=30, nizk=stub):
    chain = Chain(nizk=nizk)
    for _ in range(decoys):
        mpk, _, _ = sakgen(1)
        _, acc, info = otaccgen(mpk, 1000, 1)
        chain.add_output(acc, info)
    return chain


def fund(chain, wallet, amount):
    _, acc, info = otaccgen(wallet.mpk, amount, 1)
    ref = chain.add_output(acc, info)
    wallet.coins.append(ref)
    return ref


def make_spend(chain, owner, refs, payments, fee, ring_size=8, msks=None):
    """Spend `refs` (all owned by `owner` unless msks given) to `payments`."""
    ring, positions = pick_ring(chain, refs, ring_size)
    inputs = []
    for ref, pos, keys in zip(refs, positions, msks or [owner] * len(refs)):
        acc, info = chain.get(ref)
        ck, a, sk, tag = receive(keys.msk, keys.mpk, acc, info)
        inputs.append(SpendInput(pos, ck, a, sk, tag))
    outputs, info = make_outputs(payments)
    return ct.spend([(r, chain.get(r)[0]) for r in ring], inputs, outputs, info, fee,
                    nizk=chain.nizk)


@pytest.fixture
def chain(nizk):
    return fresh_chain(nizk=nizk)


@pytest.fixture
def alice():
    return Wallet()


@pytest.fixture
def bob():
    return Wallet()


@pytest.fixture
def honest(chain, alice, bob):
    ref = fund(chain, alice, 100)
    tx, sig = make_spend(chain, alice, [ref], [(bob.mpk, 60), (alice.mpk, 39)], fee=1)
    return tx, sig


# --- honest transactions verify (Def 4.1, second bullet) ------------------

def test_honest_spend_verifies(chain, honest):
    tx, sig = honest
    assert verify(tx, sig, chain) is True


@pytest.mark.parametrize("n_inputs", [1, 2, 3, 4])
@pytest.mark.parametrize("ring_size", [4, 16])
@pytest.mark.parametrize("n_outputs", [2, 4])
def test_shapes(chain, alice, n_inputs, ring_size, n_outputs):
    refs = [fund(chain, alice, 50) for _ in range(n_inputs)]
    total = 50 * n_inputs - 2
    recipients = [Wallet() for _ in range(n_outputs)]
    amounts = [total // n_outputs] * n_outputs
    amounts[-1] += total - sum(amounts)
    tx, sig = make_spend(chain, alice, refs,
                         list(zip([w.mpk for w in recipients], amounts)), fee=2,
                         ring_size=ring_size)
    assert verify(tx, sig, chain) is True
    new_refs = chain.submit(tx, sig)
    # and every recipient can actually receive what they were sent
    for w, ref, amt in zip(recipients, new_refs, amounts):
        assert w.take(chain, ref)[1] == amt


def test_zero_fee_and_zero_output(chain, alice, bob):
    ref = fund(chain, alice, 10)
    tx, sig = make_spend(chain, alice, [ref], [(bob.mpk, 10), (alice.mpk, 0)], fee=0)
    assert verify(tx, sig, chain) is True


def test_recipient_and_auditor_see_amount(chain, honest, bob):
    tx, sig = honest
    refs = chain.submit(tx, sig)
    acc, info = chain.get(refs[0])
    assert view(bob.vk, acc, info) == 60
    assert bob.take(chain, refs[0])[1] == 60


def test_spent_output_can_be_spent_onwards(chain, honest, alice, bob):
    tx, sig = honest
    refs = chain.submit(tx, sig)
    tx2, sig2 = make_spend(chain, bob, [refs[0]], [(alice.mpk, 50), (bob.mpk, 9)], fee=1)
    assert chain.submit(tx2, sig2)


# --- double spending ------------------------------------------------------

def test_replay_rejected(chain, honest):
    tx, sig = honest
    chain.submit(tx, sig)
    assert verify(tx, sig, chain) is None


def test_same_coin_new_transaction_rejected(chain, alice, bob):
    ref = fund(chain, alice, 100)
    tx1, sig1 = make_spend(chain, alice, [ref], [(bob.mpk, 99), (alice.mpk, 0)], fee=1)
    chain.submit(tx1, sig1)
    # Different ring, different recipients, same coin -> same tag.
    tx2, sig2 = make_spend(chain, alice, [ref], [(alice.mpk, 50), (alice.mpk, 49)], fee=1)
    assert tx2.tags == tx1.tags
    assert verify(tx2, sig2, chain) is None


def test_same_coin_twice_in_one_tx(chain, alice, bob, honest):
    tx, sig = honest
    doubled = dataclasses.replace(tx, tags=tx.tags + tx.tags)
    assert verify(doubled, sig, chain) is None


# --- structural rules (⊥) -------------------------------------------------

def test_one_output_rejected(chain, alice, bob, honest):
    ref = fund(chain, alice, 10)
    with pytest.raises(ValueError):
        make_spend(chain, alice, [ref], [(bob.mpk, 9)], fee=1)
    tx, sig = honest
    assert verify(dataclasses.replace(tx, outputs=tx.outputs[:1]), sig, chain) is None


def test_too_many_outputs_rejected(chain, honest):
    tx, sig = honest
    many = tx.outputs * (MAX_OUTPUTS // 2 + 1)
    assert verify(dataclasses.replace(tx, outputs=many), sig, chain) is None


def test_bad_ring_reference(chain, honest):
    tx, sig = honest
    bad = dataclasses.replace(tx, ring_refs=tx.ring_refs[:-1] + (10**9,))
    assert verify(bad, sig, chain) is None


def test_duplicate_ring_member(chain, honest):
    tx, sig = honest
    bad = dataclasses.replace(tx, ring_refs=tx.ring_refs[:-1] + (tx.ring_refs[0],))
    assert verify(bad, sig, chain) is None


def test_coinbase_style_output_rejected(chain, honest):
    tx, sig = honest
    mpk, _, _ = sakgen_miner()
    _, cb, _ = otaccgen(mpk, 5, 0)
    assert verify(dataclasses.replace(tx, outputs=(cb,) + tx.outputs[1:]), sig, chain) is None


# --- miner rules (§3.2) ---------------------------------------------------

def test_coinbase_alone_cannot_be_spent(chain):
    # With S = 1, the ring may hold S-1 = 0 miner accounts, so a coinbase can
    # never be the only input. The miner needs an ordinary coin alongside it.
    miner_mpk, miner_msk, _ = sakgen_miner()
    cb = chain.mine_block(miner_mpk)
    with pytest.raises(ValueError):
        pick_ring(chain, [cb], 8)


def test_coinbase_with_ordinary_input(chain, alice, bob):
    miner_keys = type("K", (), {})()
    miner_keys.mpk, miner_keys.msk, _ = sakgen_miner()
    cb = chain.mine_block(miner_keys.mpk)
    ordinary = fund(chain, alice, 100)            # alice plays the miner's normal wallet
    reward = chain.reward
    tx, sig = make_spend(
        chain, None, [cb, ordinary],
        [(bob.mpk, 500_000), (alice.mpk, reward + 100 - 500_000 - 10)], fee=10,
        msks=[miner_keys, alice],
    )
    assert verify(tx, sig, chain) is True


def test_too_many_coinbases_in_ring(chain, alice, honest):
    tx, sig = honest                              # S = 1, so no coinbase allowed
    cb = chain.mine_block(sakgen_miner()[0])
    bad = dataclasses.replace(tx, ring_refs=tx.ring_refs[:-1] + (cb,))
    assert verify(bad, sig, chain) is None


def test_spend_refuses_bad_miner_ring(chain, alice, bob):
    ref = fund(chain, alice, 100)
    cb = chain.mine_block(sakgen_miner()[0])
    acc, info = chain.get(ref)
    ck, a, sk, tag = alice.take(chain, ref)
    outputs, info = make_outputs([(bob.mpk, 99), (alice.mpk, 0)])
    ring = [(ref, acc), (cb, chain.get(cb)[0])]
    with pytest.raises(ValueError):
        ct.spend(ring, [SpendInput(0, ck, a, sk, tag)], outputs, info, 1, nizk=chain.nizk)


# --- tampering: every signed field matters --------------------------------

@pytest.mark.parametrize("field,change", [
    ("fee", lambda tx: tx.fee + 1),
    ("mu", lambda tx: b"different message"),
    ("info", lambda tx: random_scalar() * G),
    ("outputs", lambda tx: tuple(reversed(tx.outputs))),
    ("ring_refs", lambda tx: tx.ring_refs[1:] + tx.ring_refs[:1]),
    ("tags", lambda tx: (random_scalar() * G,)),
])
def test_tampered_tx_rejected(chain, honest, field, change):
    tx, sig = honest
    bad = dataclasses.replace(tx, **{field: change(tx)})
    assert verify(bad, sig, chain) is False


def test_tampered_output_coin(chain, honest):
    tx, sig = honest
    o = tx.outputs[0]
    swapped = dataclasses.replace(o, co=commit(1_000_000, random_scalar()))
    bad = dataclasses.replace(tx, outputs=(swapped,) + tx.outputs[1:])
    assert verify(bad, sig, chain) is False


@pytest.mark.parametrize("field", ["R", "T"])
def test_tampered_signature(chain, honest, field):
    tx, sig = honest
    bad = dataclasses.replace(sig, **{field: random_scalar() * G})
    assert verify(tx, bad, chain) is False


def test_signature_from_another_tx(chain, alice, bob, honest):
    tx, sig = honest
    ref = fund(chain, alice, 100)
    _, other_sig = make_spend(chain, alice, [ref], [(bob.mpk, 60), (alice.mpk, 39)], fee=1)
    assert verify(tx, other_sig, chain) is False


# --- balance: Verify catches a cheating spender on its own ----------------

def test_inflation_caught_by_verify(chain, alice, bob, monkeypatch):
    # Turn off Spend's own balance check, print 50 extra coins, and confirm the
    # verifier still refuses.
    monkeypatch.setattr(ct, "_check_balance", lambda *a: None)
    ref = fund(chain, alice, 100)
    tx, sig = make_spend(chain, alice, [ref], [(bob.mpk, 120), (alice.mpk, 29)], fee=1)
    assert verify(tx, sig, chain) is False


def test_negative_output_caught_by_range_check(chain, alice, bob):
    # 100 in -> 150 to bob and -51 to a throwaway output (fee 1). The sums
    # balance, so Spend's check passes. Only the range proof stops this.
    ref = fund(chain, alice, 100)
    ring, (pos,) = pick_ring(chain, [ref], 8)
    ck, a, sk, tag = alice.take(chain, ref)
    good, info = make_outputs([(bob.mpk, 150), (alice.mpk, 0)])
    neg_ck = random_scalar()
    neg = SpendOutput(ck=neg_ck, a=-51,
                      acc=Account(pk=random_scalar() * G, co=commit(-51, neg_ck), ctxt=0, kappa=2))
    tx, sig = ct.spend([(r, chain.get(r)[0]) for r in ring],
                       [SpendInput(pos, ck, a, sk, tag)], [good[0], neg], info, 1,
                       nizk=chain.nizk)
    assert verify(tx, sig, chain) is False


# --- the relation itself (what B's proof must match) ----------------------

def _stmt_wit(chain, tx, sig):
    ring_accs = [chain.get(r)[0] for r in tx.ring_refs]
    stmt = ct.build_statement(tx.ring_refs, ring_accs, tx.tags, tx.outputs,
                              tx.info, tx.fee, tx.mu, sig.R, sig.T)
    return stmt, sig.proof                         # stub proof = witness


@stub_only
def test_relation_accepts_honest(chain, honest):
    stmt, wit = _stmt_wit(chain, *honest)
    assert relation_holds(stmt, wit)


@stub_only
def test_relation_rejects_wrong_position(chain, honest):
    stmt, wit = _stmt_wit(chain, *honest)
    vec = list(wit.bvecs[0])
    k = vec.index(1)
    vec[k], vec[(k + 1) % len(vec)] = 0, 1
    assert not relation_holds(stmt, dataclasses.replace(wit, bvecs=(tuple(vec),)))


@stub_only
@pytest.mark.parametrize("bad_vec", [
    lambda n, k: tuple(2 if i == k else 0 for i in range(n)),        # not binary
    lambda n, k: tuple(1 if i in (k, (k + 1) % n) else 0 for i in range(n)),  # two ones
    lambda n, k: tuple(0 for _ in range(n)),                          # no ones
    lambda n, k: tuple(1 if i == k else 0 for i in range(n - 1)),     # wrong length
])
def test_relation_rejects_bad_b(chain, honest, bad_vec):
    stmt, wit = _stmt_wit(chain, *honest)
    k = wit.bvecs[0].index(1)
    assert not relation_holds(stmt, dataclasses.replace(wit, bvecs=(bad_vec(stmt.n, k),)))


@stub_only
def test_gamma_alone_binds_nothing(chain, honest):
    # Why mu has to be the whole tx prefix (see ct.py docstring). An honest
    # witness satisfies Eq. 5 for EVERY gamma, because the gamma-weighted part
    # is the balance equation, which is true on its own. So a field that is
    # only hashed into gamma (as tek is, if at all, in §6.2) could be swapped
    # without breaking the relation.
    stmt, wit = _stmt_wit(chain, *honest)
    other = dataclasses.replace(stmt, gamma=random_scalar())
    assert relation_holds(other, wit)
    # h is different: z was computed with it, so changing h breaks the relation.
    assert not relation_holds(dataclasses.replace(stmt, h=random_scalar()), wit)


@stub_only
def test_relation_rejects_wrong_T_opening(chain, honest):
    stmt, wit = _stmt_wit(chain, *honest)
    assert not relation_holds(stmt, dataclasses.replace(wit, t=wit.t + 1))


@stub_only
def test_relation_rejects_wrapped_amount(chain, honest):
    # Claiming an amount of ORDER + 60 opens the same commitment as 60, but
    # it isn't a valid 64-bit amount.
    stmt, wit = _stmt_wit(chain, *honest)
    amts = (wit.out_amounts[0] + ORDER,) + wit.out_amounts[1:]
    assert not relation_holds(stmt, dataclasses.replace(wit, out_amounts=amts))


# --- mining ---------------------------------------------------------------

def test_miner_gets_reward_plus_fees(chain, honest):
    tx, sig = honest
    chain.submit(tx, sig)
    mpk, msk, _ = sakgen_miner()
    ref = chain.mine_block(mpk)
    acc, info = chain.get(ref)
    assert receive(msk, mpk, acc, info)[1] == chain.reward + tx.fee
    assert chain.pending_fees == []


# --- what the transaction does NOT reveal ---------------------------------

def test_tx_has_no_position_or_amount_fields():
    fields = {f.name for f in dataclasses.fields(Transaction)}
    assert fields == {"ring_refs", "tags", "outputs", "info", "fee", "mu"}


def test_real_input_position_is_shuffled(chain, alice):
    ref = fund(chain, alice, 1)
    positions = {pick_ring(chain, [ref], 8)[1][0] for _ in range(40)}
    assert len(positions) > 3
