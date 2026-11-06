"""Cross-check the coincurve (libsecp256k1) backend against an independent
pure-Python implementation, plus the identity edge cases libsecp256k1 can't
represent on its own.

If these pass, group.py's thin wrapper computes the same group as the
textbook formulas, so everything built on Point is on solid ground.
"""

import pytest

from tests import reference_curve as ref
from succinct.group import ORDER, G, U, Point, multiexp, point_sum, random_scalar


def as_ref(point):
    """Point -> reference (x, y) via its encoding."""
    b = point.to_bytes()
    if b == bytes(33):
        return None
    x = int.from_bytes(b[1:], "big")
    y = pow(x * x * x + 7, (ref.P + 1) // 4, ref.P)
    if (y & 1) != (b[0] & 1):
        y = ref.P - y
    return (x, y)


# --- known values -----------------------------------------------------------

def test_known_multiples_of_g():
    # Published secp256k1 values for 2G and 3G.
    assert (2 * G).to_bytes().hex() == \
        "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
    assert (3 * G).to_bytes().hex() == \
        "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"


# --- agreement with the reference -------------------------------------------

@pytest.mark.parametrize("k", [1, 2, 3, 7, 2**64 + 1, ORDER - 1, ORDER - 2])
def test_scalar_mult_matches_reference(k):
    assert (k * G).to_bytes() == ref.compress(ref.mul(k, ref.G))


def test_random_scalar_mult_matches_reference():
    for _ in range(20):
        k = random_scalar()
        assert (k * G).to_bytes() == ref.compress(ref.mul(k, ref.G))


def test_mult_of_non_generator_matches_reference():
    for _ in range(10):
        k = random_scalar()
        assert (k * U).to_bytes() == ref.compress(ref.mul(k, as_ref(U)))


def test_addition_matches_reference():
    for _ in range(20):
        a, b = random_scalar() * G, random_scalar() * U
        assert (a + b).to_bytes() == ref.compress(ref.add(as_ref(a), as_ref(b)))


def test_doubling_matches_reference():
    a = random_scalar() * G
    assert (a + a).to_bytes() == ref.compress(ref.add(as_ref(a), as_ref(a)))


def test_negation_matches_reference():
    a = random_scalar() * G
    x, y = as_ref(a)
    assert (-a).to_bytes() == ref.compress((x, ref.P - y))


def test_multiexp_matches_reference():
    ks = [random_scalar() for _ in range(6)]
    ps = [random_scalar() * G for _ in range(6)]
    expected = None
    for k, p in zip(ks, ps):
        expected = ref.add(expected, ref.mul(k, as_ref(p)))
    assert multiexp(ks, ps).to_bytes() == ref.compress(expected)


# --- the identity: libsecp256k1 can't represent it, Point must ----------------

def test_p_minus_p_is_identity():
    a = random_scalar() * G
    assert (a - a).is_identity()
    assert (a + (-a)).is_identity()


def test_order_times_point_is_identity():
    assert (ORDER * G).is_identity()
    assert ((ORDER - 1) * G) == -G


def test_identity_is_neutral():
    a = random_scalar() * G
    O = Point.identity()
    assert a + O == a and O + a == a
    assert (O + O).is_identity()
    assert (-O).is_identity()
    assert (5 * O).is_identity()


def test_multiexp_cancelling_to_identity():
    # k*P + (ORDER-k)*P = 0: the library would raise; we return the identity.
    k = random_scalar()
    assert multiexp([k, ORDER - k], [G, G]).is_identity()


def test_multiexp_all_zero_scalars_and_empty():
    assert multiexp([0, 0, 0], [G, U, G]).is_identity()
    assert multiexp([], []).is_identity()


def test_point_sum_with_identities():
    a = random_scalar() * G
    O = Point.identity()
    assert point_sum([O, a, O]) == a
    assert point_sum([a, -a]).is_identity()
    assert point_sum([]).is_identity()
