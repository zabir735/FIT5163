"""Small scalar-vector helpers and input checks shared by the proof systems."""

from ..group import ORDER, Point, random_scalar


def inner(a, b):
    """<a, b> mod ORDER."""
    return sum(x * y for x, y in zip(a, b)) % ORDER


def powers(x, n):
    """[1, x, x^2, ..., x^(n-1)] mod ORDER."""
    out, acc = [], 1
    for _ in range(n):
        out.append(acc)
        acc = acc * x % ORDER
    return out


def random_vector(n):
    return [random_scalar() for _ in range(n)]


def is_power_of_two(n):
    return n > 0 and n & (n - 1) == 0


# Verifiers get proofs from untrusted parties. These checks run before any
# arithmetic so a malformed proof is rejected cleanly instead of raising
# somewhere deep in the group code. bool is a subclass of int, hence `type is`.

def is_scalar(v):
    return type(v) is int and 0 <= v < ORDER


def is_point(p):
    return isinstance(p, Point)


def all_scalars(vs):
    return isinstance(vs, (list, tuple)) and all(is_scalar(v) for v in vs)


def all_points(ps):
    return isinstance(ps, (list, tuple)) and all(is_point(p) for p in ps)
