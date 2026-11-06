"""
Independent pure-Python secp256k1, used ONLY by tests/test_backend.py to
cross-check the coincurve-backed Point in succinct/group.py.

Plain affine textbook formulas, deliberately simple rather than fast. Points
are (x, y) tuples; None is the point at infinity. Not used by the scheme.
"""

P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    (x1, y1), (x2, y2) = a, b
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if a == b:
        lam = 3 * x1 * x1 * pow(2 * y1, -1, P) % P
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, P) % P
    x3 = (lam * lam - x1 - x2) % P
    return (x3, (lam * (x1 - x3) - y1) % P)


def mul(k, a):
    k %= N
    acc = None
    while k:
        if k & 1:
            acc = add(acc, a)
        a = add(a, a)
        k >>= 1
    return acc


def compress(a):
    if a is None:
        return bytes(33)
    x, y = a
    return bytes([2 + (y & 1)]) + x.to_bytes(32, "big")
