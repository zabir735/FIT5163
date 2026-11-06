"""Tests for group.py, transcript.py, pedersen.py and tagging.py. Run with:  pytest -q

Grouped by what later steps rely on. If one of these breaks, everything built
on top of it (keys, tags, balance proof) will break in confusing ways, so fix
these first.
"""

import pytest

from succinct.group import (
    FIELD_P, ORDER, G, U, V, W, G_KA, Point,
    multiexp, point_sum, random_scalar, inv, encode, hash_to_point, generator_vector,
)
from succinct.transcript import H, H_a, H_b, H_c, H_n, H_n_kappa, Transcript
from succinct.pedersen import commit, vector_commit
from succinct.tagging import tag_kgen, tag_eval


# --- group laws -----------------------------------------------------------

def test_base_point_has_prime_order():
    assert not G.is_identity()
    assert (ORDER * G).is_identity()
    assert not ((ORDER - 1) * G).is_identity()


def test_identity_behaves():
    O = Point.identity()
    assert G + O == G
    assert O + G == G
    assert G - G == O
    assert 0 * G == O
    assert 5 * O == O


def test_addition_commutes_and_associates():
    A, B, C = 3 * G, 7 * G, 11 * G
    assert A + B == B + A
    assert (A + B) + C == A + (B + C)


def test_doubling_matches_addition():
    assert G + G == 2 * G
    P = 12345 * G
    assert P + P == 2 * P


def test_scalar_mul_is_a_homomorphism():
    # (a+b)G = aG + bG and (ab)G = a(bG). Tags, one-time keys and the balance
    # check all depend on these two lines being true.
    a, b = random_scalar(), random_scalar()
    assert (a + b) * G == a * G + b * G
    assert (a * b % ORDER) * G == a * (b * G)


def test_scalars_wrap_mod_order():
    a = random_scalar()
    assert (a + ORDER) * G == a * G
    assert (-a) * G == -(a * G)


def test_inverse():
    a = random_scalar()
    assert a * inv(a) % ORDER == 1
    assert inv(a) * (a * G) == G


def test_multiexp_matches_naive():
    xs = [random_scalar() for _ in range(5)]
    ps = [random_scalar() * G for _ in range(5)]
    naive = Point.identity()
    for x, p in zip(xs, ps):
        naive = naive + x * p
    assert multiexp(xs, ps) == naive


def test_multiexp_skips_zero_scalars():
    assert multiexp([0, 0], [G, U]).is_identity()
    assert multiexp([0, 3], [G, U]) == 3 * U


# --- encoding -------------------------------------------------------------

def test_point_roundtrip():
    for k in (1, 2, random_scalar(), ORDER - 1):
        P = k * G
        assert Point.from_bytes(P.to_bytes()) == P


def test_identity_roundtrip():
    O = Point.identity()
    assert Point.from_bytes(O.to_bytes()).is_identity()


def test_rejects_off_curve_point():
    with pytest.raises(ValueError):
        Point(1, 1)


def test_rejects_bad_encodings():
    with pytest.raises(ValueError):
        Point.from_bytes(b"\x05" + bytes(32))       # bad prefix
    with pytest.raises(ValueError):
        Point.from_bytes(b"\x02" + bytes(31))       # wrong length
    with pytest.raises(ValueError):
        Point.from_bytes(b"\x02" + (FIELD_P).to_bytes(32, "big"))  # x too big


# --- generators -----------------------------------------------------------

def test_generators_valid_and_distinct():
    gens = [G, U, V, W, G_KA]
    for g in gens:
        assert not g.is_identity()
        assert (ORDER * g).is_identity()
    assert len(set(gens)) == len(gens)


def test_hash_to_point_is_deterministic():
    assert hash_to_point("U") == U
    assert hash_to_point("something") == hash_to_point("something")
    assert hash_to_point("a") != hash_to_point("b")


def test_generator_vector():
    gs = generator_vector("test", 8)
    assert len(gs) == 8
    assert len(set(gs)) == 8
    assert generator_vector("test", 8) == gs
    assert generator_vector("other", 8) != gs


# --- hashing --------------------------------------------------------------

def test_hash_in_range_and_deterministic():
    h1 = H("msg", G, 42)
    assert 0 <= h1 < ORDER
    assert H("msg", G, 42) == h1


def test_hash_domains_are_separate():
    # Same input, different oracle -> different output. If H_a and H_b
    # collided, alpha and beta in Spend would be related.
    vals = {f(G, 1) for f in (H, H_a, H_b, H_c, H_n)}
    assert len(vals) == 5


def test_encoding_is_unambiguous():
    assert H("ab", "c") != H("a", "bc")
    assert H([1, 2], 3) != H(1, [2, 3])
    assert H(b"x") != H("x")
    assert H(1) != H(G)


def test_encode_rejects_unreduced_ints():
    with pytest.raises(ValueError):
        encode(-1)
    with pytest.raises(ValueError):
        encode(2**256)


def test_h_n_kappa_depends_on_kappa():
    X = random_scalar() * G
    assert H_n_kappa(X, 1) != H_n_kappa(X, 2)


# --- Pedersen commitments -------------------------------------------------

def test_commit_is_homomorphic():
    # Com(a1;r1) + Com(a2;r2) = Com(a1+a2; r1+r2). The balance equation is
    # this property applied to all inputs and outputs at once.
    a1, a2 = 100, 250
    r1, r2 = random_scalar(), random_scalar()
    assert commit(a1, r1) + commit(a2, r2) == commit(a1 + a2, r1 + r2)


def test_balance_identity():
    # Mini version of Eq. 3: inputs - fee = outputs, so
    # V^-fee * prod(co_in) == prod(co_out) * W^ck'  with ck' = sum(ck_in) - sum(ck_out)
    a_in, ck_in = [70, 40], [random_scalar(), random_scalar()]
    fee = 3
    a_out = [100, 7]
    ck_out = [random_scalar(), random_scalar()]
    assert sum(a_in) - fee == sum(a_out)

    lhs = (-fee) * V + commit(a_in[0], ck_in[0]) + commit(a_in[1], ck_in[1])
    ck_prime = (sum(ck_in) - sum(ck_out)) % ORDER
    rhs = commit(a_out[0], ck_out[0]) + commit(a_out[1], ck_out[1]) + ck_prime * W
    assert lhs == rhs


def test_unbalanced_amounts_fail():
    ck_in, ck_out = random_scalar(), random_scalar()
    lhs = commit(10, ck_in)
    ck_prime = (ck_in - ck_out) % ORDER
    rhs = commit(11, ck_out) + ck_prime * W      # one extra coin out of nowhere
    assert lhs != rhs


def test_commit_hides_with_different_keys():
    assert commit(5, random_scalar()) != commit(5, random_scalar())


def test_commit_zero_is_just_blinding():
    ck = random_scalar()
    assert commit(0, ck) == ck * W


def test_miner_coin_key():
    # Miner accounts use ck = 1 (Section 6.2, Mine), so the coin is V^a W and
    # anyone can check the amount. This is the transparency the attacks use.
    a = 600
    assert commit(a, 1) == a * V + W


def test_negative_amount_wraps():
    # Why range proofs matter: -1 commits to the same thing as ORDER-1.
    ck = random_scalar()
    assert commit(-1, ck) == commit(ORDER - 1, ck)


def test_vector_commit():
    vals = [1, 2, 3]
    t = random_scalar()
    gs = generator_vector("vcom", 3)
    expected = 1 * gs[0] + 2 * gs[1] + 3 * gs[2] + t * W
    assert vector_commit(vals, t) == expected
    assert vector_commit(vals, t) != vector_commit([1, 2, 4], t)
    assert vector_commit(vals, t, label="other") != vector_commit(vals, t)


# --- preview of step 2 ----------------------------------------------------

def test_polynomial_in_the_exponent():
    # SAKGen publishes F_i = G^{theta_i}. A sender who only knows the F_i and
    # some s can compute pk = prod F_i^{s^i}, and the receiver's one-time
    # secret key is f(s). This identity is the whole reason that works.
    q = 4
    thetas = [random_scalar() for _ in range(q + 1)]
    F = [t * G for t in thetas]
    s = random_scalar()

    pk_sender_side = multiexp([pow(s, i, ORDER) for i in range(q + 1)], F)
    f_of_s = sum(t * pow(s, i, ORDER) for i, t in enumerate(thetas)) % ORDER
    assert pk_sender_side == f_of_s * G


def test_tag_and_pk_share_secret():
    # tag = U^sk, pk = G^sk. Same sk, different base -> unlinkable unless you
    # know sk (that's DDH), but double-spends give the same tag.
    sk = random_scalar()
    assert tag_kgen(sk) == sk * G
    assert tag_eval(sk) == sk * U
    assert tag_kgen(sk) != tag_eval(sk)


def test_tag_kgen_is_homomorphic():
    x1, x2 = random_scalar(), random_scalar()
    assert tag_kgen(x1) + tag_kgen(x2) == tag_kgen(x1 + x2)


def test_point_sum():
    ps = [random_scalar() * G for _ in range(4)]
    assert point_sum(ps) == ps[0] + ps[1] + ps[2] + ps[3]
    assert point_sum([]).is_identity()


# --- transcript -----------------------------------------------------------

def test_transcript_is_deterministic():
    def run():
        t = Transcript("test")
        t.append("A", G)
        a = t.challenge("x")
        t.append("B", U)
        return a, t.challenge("y")
    assert run() == run()


def test_transcript_binds_everything_before_it():
    t1, t2 = Transcript("test"), Transcript("test")
    t1.append("A", G)
    t2.append("A", U)
    assert t1.challenge("x") != t2.challenge("x")


def test_transcript_challenges_chain():
    # Second challenge depends on the first, even with nothing appended between.
    t = Transcript("test")
    assert t.challenge("x") != t.challenge("x")


def test_transcript_label_matters():
    t1, t2 = Transcript("proto-1"), Transcript("proto-2")
    assert t1.challenge("x") != t2.challenge("x")
