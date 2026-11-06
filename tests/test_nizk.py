"""Tests for Part B: inner-product argument, range proof and the Eq. 5 Σ-protocol.

The Σ-protocol is checked against relation_holds (the oracle from Part A):
an honest witness must give a proof that verifies, and each way of breaking
the relation must give one that doesn't. Every field of a proof and of the
statement is also tampered with individually.

End-to-end runs through Spend/Verify/Chain are in test_ct.py, which runs its
suite once per proof system via the `nizk` fixture.
"""

import dataclasses

import pytest

from succinct import ct
from succinct.chain import Chain
from succinct.ct import SpendInput, make_outputs, pick_ring, spend
from succinct.group import ORDER, G, Point, generator_vector, hash_to_point, multiexp, random_scalar
from succinct.pedersen import commit
from succinct.stealth import otaccgen, receive, sakgen
from succinct.transcript import Transcript
from succinct.nizk import ipa, rangeproof, sigma_ring, stub
from succinct.nizk.relation import relation_holds
from succinct.nizk.util import inner


def rand_point():
    return random_scalar() * G


# --- inner-product argument ------------------------------------------------

def ipa_instance(n):
    g, h, u = generator_vector("test/g", n), generator_vector("test/h", n), hash_to_point("test/u")
    a = [random_scalar() for _ in range(n)]
    b = [random_scalar() for _ in range(n)]
    P = multiexp(a + b + [inner(a, b)], g + h + [u])
    return g, h, u, P, ipa.prove(g, h, u, a, b, Transcript("test"))


@pytest.mark.parametrize("n", [1, 2, 4, 16])
def test_ipa_honest(n):
    g, h, u, P, proof = ipa_instance(n)
    assert ipa.verify(g, h, u, P, proof, Transcript("test"))
    assert len(proof.L) == len(proof.R) == n.bit_length() - 1


def test_ipa_rejects_wrong_P():
    g, h, u, P, proof = ipa_instance(8)
    assert not ipa.verify(g, h, u, P + u, proof, Transcript("test"))


def test_ipa_rejects_other_transcript():
    g, h, u, P, proof = ipa_instance(8)
    assert not ipa.verify(g, h, u, P, proof, Transcript("other"))


@pytest.mark.parametrize("change", [
    lambda p: dataclasses.replace(p, a=(p.a + 1) % ORDER),
    lambda p: dataclasses.replace(p, b=(p.b + 1) % ORDER),
    lambda p: dataclasses.replace(p, L=(rand_point(),) + p.L[1:]),
    lambda p: dataclasses.replace(p, R=p.R[:-1] + (rand_point(),)),
    lambda p: dataclasses.replace(p, L=p.L[:-1]),
    lambda p: dataclasses.replace(p, L=p.R, R=p.L),
    lambda p: dataclasses.replace(p, a=ORDER),
    lambda p: dataclasses.replace(p, b=True),
    lambda p: dataclasses.replace(p, L=(None,) + p.L[1:]),
], ids=["a", "b", "L0", "R-last", "short", "swap-LR", "a=ORDER", "bool", "None"])
def test_ipa_tampered(change):
    g, h, u, P, proof = ipa_instance(8)
    assert not ipa.verify(g, h, u, P, change(proof), Transcript("test"))


def test_ipa_prove_rejects_bad_lengths():
    g = generator_vector("test/g", 3)
    with pytest.raises(ValueError):
        ipa.prove(g, g, G, [1, 2, 3], [1, 2, 3], Transcript("test"))


# --- range proof -------------------------------------------------------------

def range_instance(amounts, bits=8):
    cks = [random_scalar() for _ in amounts]
    cos = [commit(a, ck) for a, ck in zip(amounts, cks)]
    return cos, rangeproof.prove(amounts, cks, Transcript("test"), bits)


@pytest.mark.parametrize("amounts", [[0], [255], [3, 200], [1, 2, 3], [0, 0, 0, 0, 255]])
def test_range_honest(amounts):
    cos, proof = range_instance(amounts)
    assert rangeproof.verify(cos, proof, Transcript("test"), 8)


def test_range_honest_64_bit_edges():
    cos, proof = range_instance([0, 2**64 - 1], bits=64)
    assert rangeproof.verify(cos, proof, Transcript("test"))


@pytest.mark.parametrize("amounts", [[256, 1], [1, -1], [ORDER - 1, 0], [2**64, 0]],
                         ids=["2^bits", "negative", "ORDER-1", "2^64"])
def test_range_rejects_out_of_range(amounts):
    cos, proof = range_instance(amounts)
    assert not rangeproof.verify(cos, proof, Transcript("test"), 8)


def test_range_amount_wrapped_by_ORDER_is_the_same_coin():
    # ORDER + 5 commits to exactly the same point as 5, so this is a valid
    # proof for that commitment: the coin really holds 5.
    ck = random_scalar()
    assert commit(ORDER + 5, ck) == commit(5, ck)
    cos, proof = range_instance([ORDER + 5, 1])
    assert rangeproof.verify(cos, proof, Transcript("test"), 8)


@pytest.fixture(scope="module")
def range_case():
    return range_instance([7, 100, 42])


def test_range_rejects_wrong_commitments(range_case):
    cos, proof = range_case
    assert not rangeproof.verify([cos[1], cos[0], cos[2]], proof, Transcript("test"), 8)
    assert not rangeproof.verify(cos[:2], proof, Transcript("test"), 8)
    assert not rangeproof.verify([cos[0] + G] + cos[1:], proof, Transcript("test"), 8)


def test_range_rejects_wrong_bits_or_transcript(range_case):
    cos, proof = range_case
    assert not rangeproof.verify(cos, proof, Transcript("test"), 16)
    assert not rangeproof.verify(cos, proof, Transcript("other"), 8)


@pytest.mark.parametrize("field", ["A", "S", "T1", "T2"])
def test_range_tampered_point(range_case, field):
    cos, proof = range_case
    bad = dataclasses.replace(proof, **{field: rand_point()})
    assert not rangeproof.verify(cos, bad, Transcript("test"), 8)


@pytest.mark.parametrize("field", ["tau_x", "mu", "t_hat"])
def test_range_tampered_scalar(range_case, field):
    cos, proof = range_case
    bad = dataclasses.replace(proof, **{field: (getattr(proof, field) + 1) % ORDER})
    assert not rangeproof.verify(cos, bad, Transcript("test"), 8)


def test_range_tampered_ipa(range_case):
    cos, proof = range_case
    bad = dataclasses.replace(proof, ipa=dataclasses.replace(proof.ipa, a=(proof.ipa.a + 1) % ORDER))
    assert not rangeproof.verify(cos, bad, Transcript("test"), 8)


@pytest.mark.parametrize("bad", [None, "proof", 0], ids=["None", "str", "int"])
def test_range_rejects_garbage(range_case, bad):
    cos, _ = range_case
    assert not rangeproof.verify(cos, bad, Transcript("test"), 8)
    assert not rangeproof.verify([], range_case[1], Transcript("test"), 8)


# --- Σ-protocol for Eq. 5 ---------------------------------------------------

def stmt_and_witness(n_inputs=2, ring_size=4, amounts=(120, 29), fee=1):
    """A real spend built with the stub, whose 'proof' is the witness."""
    chain = Chain()
    for _ in range(max(ring_size, 2)):
        mpk, _, _ = sakgen(1)
        chain.add_output(*otaccgen(mpk, 1000, 1)[1:])
    mpk, msk, _ = sakgen(10)
    total = sum(amounts) + fee
    each = [total // n_inputs] * n_inputs
    each[-1] += total - sum(each)
    refs = [chain.add_output(*otaccgen(mpk, a, 1)[1:]) for a in each]

    ring, positions = pick_ring(chain, refs, ring_size)
    inputs = []
    for ref, pos in zip(refs, positions):
        ck, a, sk, tag = receive(msk, mpk, *chain.get(ref))
        inputs.append(SpendInput(pos, ck, a, sk, tag))
    outputs, info = make_outputs([(mpk, a) for a in amounts])
    ring_accs = [chain.get(r)[0] for r in ring]
    tx, sig = spend(list(zip(ring, ring_accs)), inputs, outputs, info, fee, nizk=stub)
    stmt = ct.build_statement(tx.ring_refs, ring_accs, tx.tags, tx.outputs,
                              tx.info, tx.fee, tx.mu, sig.R, sig.T)
    return stmt, sig.proof


@pytest.fixture(scope="module")
def sigma_case():
    stmt, wit = stmt_and_witness()
    return stmt, wit, sigma_ring.prove(stmt, wit)


@pytest.mark.parametrize("n_inputs,ring_size", [(1, 1), (1, 4), (2, 2), (2, 8), (3, 4)])
def test_sigma_honest(n_inputs, ring_size):
    stmt, wit = stmt_and_witness(n_inputs, ring_size)
    assert relation_holds(stmt, wit)
    proof = sigma_ring.prove(stmt, wit)
    assert sigma_ring.verify(stmt, proof) is True
    assert len(proof.f) == n_inputs and all(len(row) == ring_size - 1 for row in proof.f)


# Each way of breaking the relation. relation_holds must say no, and so must
# the proof built from that witness.
def _move_one(vec):
    k = vec.index(1)
    out = [0] * len(vec)
    out[(k + 1) % len(vec)] = 1
    return tuple(out)


BAD_WITNESSES = {
    "wrong position": lambda w: dataclasses.replace(w, bvecs=(_move_one(w.bvecs[0]),) + w.bvecs[1:]),
    "b = 2": lambda w: dataclasses.replace(
        w, bvecs=(tuple(2 * b for b in w.bvecs[0]),) + w.bvecs[1:]),
    "two ones": lambda w: dataclasses.replace(
        w, bvecs=(tuple(max(a, b) for a, b in zip(w.bvecs[0], _move_one(w.bvecs[0]))),)
        + w.bvecs[1:]),
    "no ones": lambda w: dataclasses.replace(
        w, bvecs=(tuple(0 for _ in w.bvecs[0]),) + w.bvecs[1:]),
    "same position twice": lambda w: dataclasses.replace(w, bvecs=(w.bvecs[0], w.bvecs[0])),
    "wrong z": lambda w: dataclasses.replace(w, z=(w.z + 1) % ORDER),
    "wrong ck'": lambda w: dataclasses.replace(w, ck_prime=(w.ck_prime + 1) % ORDER),
    "wrong T opening": lambda w: dataclasses.replace(w, t=(w.t + 1) % ORDER),
    "wrong output amount": lambda w: dataclasses.replace(
        w, out_amounts=(w.out_amounts[0] + 1,) + w.out_amounts[1:]),
    "negative output": lambda w: dataclasses.replace(
        w, out_amounts=(-1,) + w.out_amounts[1:]),
}


@pytest.mark.parametrize("name", BAD_WITNESSES)
def test_sigma_matches_oracle_on_bad_witness(sigma_case, name):
    stmt, wit, _ = sigma_case
    bad = BAD_WITNESSES[name](wit)
    assert not relation_holds(stmt, bad)
    assert sigma_ring.verify(stmt, sigma_ring.prove(stmt, bad)) is False


def test_sigma_oracle_disagreement_is_only_representation(sigma_case):
    # The one case where relation_holds says no but a proof verifies: an
    # amount written as ORDER + a. That's the same field element, so the coin
    # does hold a valid amount and a correct witness exists.
    stmt, wit, _ = sigma_case
    wrapped = dataclasses.replace(wit, out_amounts=(wit.out_amounts[0] + ORDER,) + wit.out_amounts[1:])
    assert not relation_holds(stmt, wrapped)
    assert sigma_ring.verify(stmt, sigma_ring.prove(stmt, wrapped))


@pytest.mark.parametrize("field", ["A", "C", "D", "E"])
def test_sigma_tampered_point(sigma_case, field):
    stmt, _, proof = sigma_case
    assert not sigma_ring.verify(stmt, dataclasses.replace(proof, **{field: rand_point()}))


@pytest.mark.parametrize("field", ["s_z", "s_ck", "s_t", "s_bits"])
def test_sigma_tampered_scalar(sigma_case, field):
    stmt, _, proof = sigma_case
    bad = dataclasses.replace(proof, **{field: (getattr(proof, field) + 1) % ORDER})
    assert not sigma_ring.verify(stmt, bad)


@pytest.mark.parametrize("j,i", [(0, 0), (1, 2), (1, 0)])
def test_sigma_tampered_f(sigma_case, j, i):
    stmt, _, proof = sigma_case
    rows = [list(r) for r in proof.f]
    rows[j][i] = (rows[j][i] + 1) % ORDER
    bad = dataclasses.replace(proof, f=tuple(tuple(r) for r in rows))
    assert not sigma_ring.verify(stmt, bad)


@pytest.mark.parametrize("change", [
    lambda p: dataclasses.replace(p, f=p.f[:1]),
    lambda p: dataclasses.replace(p, f=(p.f[0][:-1], p.f[1])),
    lambda p: dataclasses.replace(p, f=(p.f[0] + (1,), p.f[1])),
    lambda p: dataclasses.replace(p, f=tuple(reversed(p.f))),
    lambda p: dataclasses.replace(p, s_z=ORDER),
    lambda p: dataclasses.replace(p, s_z=-1),
    lambda p: dataclasses.replace(p, A=None),
    lambda p: dataclasses.replace(p, range_proof=None),
], ids=["missing row", "short row", "long row", "rows swapped", "s_z=ORDER", "s_z<0",
        "A=None", "no range proof"])
def test_sigma_malformed(sigma_case, change):
    stmt, _, proof = sigma_case
    assert sigma_ring.verify(stmt, change(proof)) is False


@pytest.mark.parametrize("bad", [None, "proof", 0], ids=["None", "str", "int"])
def test_sigma_rejects_garbage(sigma_case, bad):
    stmt, wit, _ = sigma_case
    assert sigma_ring.verify(stmt, bad) is False
    assert sigma_ring.verify(stmt, wit) is False          # a stub "proof" isn't one


def test_sigma_range_proof_from_another_spend(sigma_case):
    stmt, _, proof = sigma_case
    other_stmt, other_wit = stmt_and_witness()
    other = sigma_ring.prove(other_stmt, other_wit)
    assert not sigma_ring.verify(stmt, dataclasses.replace(proof, range_proof=other.range_proof))
    assert not sigma_ring.verify(stmt, other)


# The transcript absorbs every field of Statement, so changing any of them
# breaks the proof, including gamma, which an honest witness satisfies for
# every value (test_ct.test_gamma_alone_binds_nothing).
STATEMENT_CHANGES = {
    "ring_pks": lambda s: dataclasses.replace(s, ring_pks=s.ring_pks[1:] + s.ring_pks[:1]),
    "ring_cos": lambda s: dataclasses.replace(s, ring_cos=s.ring_cos[:-1] + (rand_point(),)),
    "tags": lambda s: dataclasses.replace(s, tags=tuple(reversed(s.tags))),
    "out_cos": lambda s: dataclasses.replace(s, out_cos=tuple(reversed(s.out_cos))),
    "fee": lambda s: dataclasses.replace(s, fee=s.fee + 1),
    "alphas": lambda s: dataclasses.replace(s, alphas=tuple(reversed(s.alphas))),
    "beta": lambda s: dataclasses.replace(s, beta=random_scalar()),
    "h": lambda s: dataclasses.replace(s, h=random_scalar()),
    "gamma": lambda s: dataclasses.replace(s, gamma=random_scalar()),
    "R": lambda s: dataclasses.replace(s, R=rand_point()),
    "T": lambda s: dataclasses.replace(s, T=rand_point()),
}


@pytest.mark.parametrize("field", STATEMENT_CHANGES)
def test_sigma_rejects_changed_statement(sigma_case, field):
    stmt, _, proof = sigma_case
    assert not sigma_ring.verify(STATEMENT_CHANGES[field](stmt), proof)


def test_sigma_proof_shape_independent_of_real_position():
    # Same statement shape, real input at a random position each time:
    # identical field layout, so size can't leak the index.
    shapes = set()
    for _ in range(4):
        stmt, wit = stmt_and_witness(1, 4)
        proof = sigma_ring.prove(stmt, wit)
        shapes.add((len(proof.f), tuple(len(r) for r in proof.f),
                    len(proof.range_proof.ipa.L)))
    assert len(shapes) == 1


def test_sigma_prove_rejects_wrong_shape(sigma_case):
    stmt, wit, _ = sigma_case
    with pytest.raises(ValueError):
        sigma_ring.prove(stmt, dataclasses.replace(wit, bvecs=wit.bvecs[:1]))
