"""Security requirements from the plan's evaluation table that the other test
files don't cover directly:

  * non-slanderability: an adversary holding every view key can't put an
    honest user's tag on chain (which would make the honest coin look spent)
  * anonymity: the proof carries no usable signal about the real position,
    and its encoded size doesn't depend on it
  * soundness hygiene: flipping any single bit of an encoded transaction
    never yields an accepted transaction

The adversary-with-view-keys tests run with both proof systems; the others
need the real proof.
"""

import dataclasses
import random

import pytest

from succinct import ct, serialize
from succinct.ct import SpendInput, make_outputs, pick_ring
from succinct.group import ORDER, U, random_scalar
from succinct.nizk import sigma_ring, stub
from succinct.stealth import _open, receive, view
from succinct.tagging import tag_eval

from .test_ct import Wallet, fresh_chain, fund, make_spend
from .test_nizk import stmt_and_witness


@pytest.fixture(params=[stub, sigma_ring], ids=["stub", "sigma"])
def chain(request):
    return fresh_chain(nizk=request.param)


def verify(tx, sig, chain):
    return ct.verify(tx, sig, chain, nizk=chain.nizk)


def spend_with(chain, ref, ck, a, sk, tag, payments, fee=1, ring_size=8):
    """Spend one coin with whatever key material the caller claims to have.
    ct.spend never checks that sk and tag belong to the coin; Verify must."""
    ring, (pos,) = pick_ring(chain, [ref], ring_size)
    outputs, info = make_outputs(payments)
    return ct.spend([(r, chain.get(r)[0]) for r in ring],
                    [SpendInput(pos, ck, a, sk, tag)], outputs, info, fee,
                    nizk=chain.nizk)


# --- non-slanderability ------------------------------------------------------

def test_view_key_does_not_reveal_the_tag(chain):
    # Everything Mallory can derive from Alice's view key: amount, blinding,
    # the shared secret s and the one-time pk. None of it gives U^sk.
    alice = Wallet()
    ref = fund(chain, alice, 100)
    acc, info = chain.get(ref)
    a, ck, s = _open(alice.vk.vdk, alice.vk.lpk, acc, info)
    assert a == view(alice.vk, acc, info) == 100
    real_tag = alice.take(chain, ref)[3]
    guesses = [tag_eval(x) for x in (s, ck, a, alice.vk.vdk, (s + alice.vk.vdk) % ORDER)]
    assert real_tag not in guesses


def test_view_key_holder_cannot_spend_the_coin(chain):
    # Mallory knows Alice's amount and blinding (so the balance works out),
    # but has to guess sk. Verify rejects, and Alice's coin stays unspent.
    alice, mallory = Wallet(), Wallet()
    ref = fund(chain, alice, 100)
    acc, info = chain.get(ref)
    a, ck, _ = _open(alice.vk.vdk, alice.vk.lpk, acc, info)
    fake_sk = random_scalar()
    tx, sig = spend_with(chain, ref, ck, a, fake_sk, tag_eval(fake_sk),
                         [(mallory.mpk, 60), (mallory.mpk, 39)])
    assert verify(tx, sig, chain) is False
    with pytest.raises(ValueError):
        chain.submit(tx, sig)
    alice_tag = alice.take(chain, ref)[3]
    assert not chain.is_spent(alice_tag)


def test_copied_tag_cannot_frame_the_owner(chain):
    # Alice broadcasts a spend. Mallory front-runs it with her OWN coin but
    # Alice's tag, hoping the chain records it and then rejects Alice as a
    # double spend. The tag isn't U^sk for any key Mallory has, so Verify
    # rejects her transaction and Alice's still goes through.
    alice, bob, mallory = Wallet(), Wallet(), Wallet()
    alice_ref = fund(chain, alice, 100)
    mallory_ref = fund(chain, mallory, 100)
    alice_tx, alice_sig = make_spend(chain, alice, [alice_ref],
                                     [(bob.mpk, 60), (alice.mpk, 39)], fee=1)
    (stolen_tag,) = alice_tx.tags

    ck, a, sk, _ = mallory.take(chain, mallory_ref)
    tx, sig = spend_with(chain, mallory_ref, ck, a, sk, stolen_tag,
                         [(mallory.mpk, 60), (mallory.mpk, 39)])
    assert verify(tx, sig, chain) is False
    with pytest.raises(ValueError):
        chain.submit(tx, sig)
    assert not chain.is_spent(stolen_tag)
    assert verify(alice_tx, alice_sig, chain) is True
    chain.submit(alice_tx, alice_sig)


def test_tag_swapped_into_a_valid_transaction_is_rejected(chain):
    # Taking a valid transaction and replacing its tag with Alice's breaks
    # the challenges that bind the tags, so the result doesn't verify.
    alice, bob = Wallet(), Wallet()
    alice_ref = fund(chain, alice, 100)
    alice_tag = alice.take(chain, alice_ref)[3]
    mallory = Wallet()
    ref = fund(chain, mallory, 100)
    tx, sig = make_spend(chain, mallory, [ref], [(bob.mpk, 60), (mallory.mpk, 39)], fee=1)
    framed = dataclasses.replace(tx, tags=(alice_tag,))
    assert verify(framed, sig, chain) is False
    assert not chain.is_spent(alice_tag)


# --- anonymity -----------------------------------------------------------------

def test_proof_gives_no_position_signal():
    # With n = 4 a blind guess is right 25% of the time. Guess from the
    # proof's masked responses with the obvious heuristics (largest, smallest
    # f, which the real position's f = x + a might stand out in) and check
    # none does clearly better. Also check the encoded size never changes.
    n, trials = 4, 16
    hits = {"largest f": 0, "smallest f": 0}
    sizes = set()
    for _ in range(trials):
        stmt, wit = stmt_and_witness(1, n)
        proof = sigma_ring.prove(stmt, wit)
        real = wit.bvecs[0].index(1)
        row = proof.f[0]                     # f for positions 1..n-1
        hits["largest f"] += real == 1 + row.index(max(row))
        hits["smallest f"] += real == 1 + row.index(min(row))
        sizes.add(len(serialize.encode_proof(proof)))
    # 16 trials at p = 1/4: P(11 or more hits) is about 3e-4 per heuristic.
    # A weak check by design; it would catch a proof that leaks the position.
    for name, count in hits.items():
        assert count < 11, f"guessing by {name} found the real input {count}/{trials} times"
    assert len(sizes) == 1


# --- soundness hygiene: random bit flips ---------------------------------------

@pytest.fixture(scope="module")
def encoded_spend():
    chain = fresh_chain(decoys=6, nizk=sigma_ring)
    alice, bob = Wallet(), Wallet()
    ref = fund(chain, alice, 100)
    tx, sig = make_spend(chain, alice, [ref], [(bob.mpk, 60), (alice.mpk, 39)],
                         fee=1, ring_size=4)
    assert verify(tx, sig, chain) is True
    return chain, serialize.encode_transaction(tx, sig)


def flip_positions(size, seed=5163, chunk=16):
    """One random bit in every `chunk`-byte stretch, so every field of the
    encoding gets hit at least once."""
    rng = random.Random(seed)
    return [rng.randrange(8 * start, 8 * min(start + chunk, size))
            for start in range(0, size, chunk)]


def test_every_single_bit_flip_is_rejected(encoded_spend):
    chain, data = encoded_spend
    flips = flip_positions(len(data))
    accepted, reached_verify = [], 0
    for bit in flips:
        flipped = bytearray(data)
        flipped[bit // 8] ^= 1 << (bit % 8)
        try:
            tx, sig = serialize.decode_transaction(bytes(flipped))
        except ValueError:
            continue                         # not even well-formed: rejected
        reached_verify += 1
        if verify(tx, sig, chain) is True:
            accepted.append(bit)
    assert accepted == []
    # About half of all flips land on a valid point or scalar and get to
    # Verify; make sure the test isn't passing on decoding errors alone.
    assert reached_verify > len(flips) // 3
