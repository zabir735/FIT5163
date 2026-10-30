"""Property-based tests (hypothesis): the algebraic facts the scheme relies on,
checked over generated inputs instead of hand-picked ones.

Each example costs a few elliptic-curve operations in pure Python, so example
counts are kept small and deadlines are off.
"""

from hypothesis import HealthCheck, given, settings, strategies as st

from succinct import serialize
from succinct.group import G, ORDER, Point, multiexp
from succinct.nizk import rangeproof
from succinct.pedersen import commit
from succinct.stealth import AMOUNT_BITS, otaccgen, receive, sakgen, view
from succinct.tagging import tag_eval
from succinct.transcript import Transcript

scalars = st.integers(min_value=0, max_value=ORDER - 1)
nonzero_scalars = st.integers(min_value=1, max_value=ORDER - 1)
amounts = st.integers(min_value=0, max_value=2**AMOUNT_BITS - 1)

fast = settings(max_examples=25, deadline=None)
slow = settings(max_examples=8, deadline=None,
                suppress_health_check=[HealthCheck.too_slow])


# --- group and encoding --------------------------------------------------------

@fast
@given(nonzero_scalars, nonzero_scalars)
def test_scalar_multiplication_is_linear(x, y):
    assert (x * G) + (y * G) == ((x + y) % ORDER) * G
    assert x * (y * G) == ((x * y) % ORDER) * G


@fast
@given(scalars)
def test_point_encoding_round_trips(x):
    p = x * G
    data = p.to_bytes()
    assert len(data) == serialize.POINT_BYTES
    assert Point.from_bytes(data) == p


@fast
@given(st.lists(scalars, min_size=1, max_size=5))
def test_multiexp_matches_naive_sum(xs):
    points = [(i + 2) * G for i in range(len(xs))]
    naive = Point.identity()
    for x, p in zip(xs, points):
        naive = naive + x * p
    assert multiexp(xs, points) == naive


# --- Pedersen commitments and tags -----------------------------------------------

@fast
@given(amounts, amounts, scalars, scalars)
def test_commitments_add_up(a, b, r, s):
    # What makes the balance check work: Com(a; r) + Com(b; s) = Com(a + b; r + s)
    assert commit(a, r) + commit(b, s) == commit(a + b, (r + s) % ORDER)


@fast
@given(amounts, scalars, scalars)
def test_commitment_binds_the_blinding(a, r, s):
    if r != s:
        assert commit(a, r) != commit(a, s)


@fast
@given(nonzero_scalars, nonzero_scalars)
def test_distinct_keys_give_distinct_tags(x, y):
    # Linkability rests on this: one key, one tag; different keys, different tags.
    assert (tag_eval(x) == tag_eval(y)) == (x == y)


# --- stealth accounts --------------------------------------------------------------

@slow
@given(amounts, st.integers(min_value=1, max_value=2**16 - 1))
def test_any_amount_round_trips_through_view_and_receive(a, kappa):
    # A fresh q = 1 recipient per example: receive() enforces the q-use limit,
    # and a large q makes every receive evaluate a long polynomial.
    mpk, msk, vk = sakgen(q=1)
    ck, acc, info = otaccgen(mpk, a, kappa)
    assert view(vk, acc, info) == a
    got_ck, got_a, sk, tag = receive(msk, mpk, acc, info)
    assert (got_ck, got_a) == (ck, a)
    assert acc.pk == sk * G and tag == tag_eval(sk)
    assert acc.co == commit(a, ck)


# --- range proof ---------------------------------------------------------------------

BITS = 8


@slow
@given(st.lists(st.integers(min_value=0, max_value=2**BITS - 1), min_size=1, max_size=3),
       st.data())
def test_range_proof_accepts_every_in_range_amount(values, data):
    cks = data.draw(st.lists(nonzero_scalars, min_size=len(values), max_size=len(values)))
    cos = [commit(v, ck) for v, ck in zip(values, cks)]
    proof = rangeproof.prove(values, cks, Transcript("prop"), BITS)
    assert rangeproof.verify(cos, proof, Transcript("prop"), BITS)


@slow
@given(st.integers(min_value=2**BITS, max_value=ORDER - 1), nonzero_scalars)
def test_range_proof_rejects_every_out_of_range_amount(value, ck):
    # Includes "negative" amounts, which are ORDER - k as field elements.
    proof = rangeproof.prove([value, 0], [ck, 1], Transcript("prop"), BITS)
    assert not rangeproof.verify([commit(value, ck), commit(0, 1)], proof,
                                 Transcript("prop"), BITS)
