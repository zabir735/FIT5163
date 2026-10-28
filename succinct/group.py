"""
The prime-order group G that the whole scheme runs in.

Notation: the paper writes the group multiplicatively (G^x, A·B). Elliptic
curve code is usually written additively, so throughout this project:

    paper          code
    G^x            x * G
    A · B          A + B
    A^-1           -A
    prod_i A_i     sum of points

The paper calls the group order p. Here it's ORDER, so it doesn't get mixed up
with FIELD_P, the prime the curve coordinates live in.

The curve is secp256k1. It has prime order (cofactor 1), which is all the
scheme needs for DL/DDH to make sense. The authors used bn256 G1, also prime
order. Ristretto was dropped: PyNaCl doesn't expose it, and it buys nothing
here that secp256k1 doesn't already give.

Point arithmetic is done by libsecp256k1 (Bitcoin Core's audited, constant-time
C library) through the `coincurve` package. We don't do curve arithmetic
ourselves. The rest of the project only ever touches the Point interface below,
so nothing above this file knows or cares which library is underneath.

One thing libsecp256k1 can't do: represent the identity (the point at
infinity). It refuses to return it, e.g. combine_keys([P, -P]) raises. The
scheme does produce the identity (zero entries in one-hot vectors, P - P in
tests), so Point stores it as None and handles it before calling the library.
"""

import hashlib
import secrets

from coincurve import PublicKey

FIELD_P = 2**256 - 2**32 - 977
ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
CURVE_B = 7

_GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
_GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

_IDENTITY_BYTES = bytes(33)


def _on_curve(x, y):
    return (y * y - x * x * x - CURVE_B) % FIELD_P == 0


def _sqrt(a):
    # FIELD_P = 3 mod 4, so a square root (if one exists) is a^((p+1)/4).
    # Only used by hash_to_point; all real arithmetic goes through libsecp256k1.
    a %= FIELD_P
    r = pow(a, (FIELD_P + 1) // 4, FIELD_P)
    return r if r * r % FIELD_P == a else None


def _combine(pks):
    """Sum of non-identity coincurve keys; None if the sum is the identity."""
    if not pks:
        return None
    if len(pks) == 1:
        return pks[0]
    try:
        return PublicKey.combine_keys(pks)
    except ValueError:
        # libsecp256k1 refuses to return the point at infinity.
        return None


class Point:
    """An element of the group. Immutable. Use Point.identity() for the
    neutral element."""

    __slots__ = ("_pk",)          # a coincurve PublicKey, or None = identity

    def __init__(self, x, y):
        if not (0 <= x < FIELD_P and 0 <= y < FIELD_P) or not _on_curve(x, y):
            raise ValueError("point is not on the curve")
        self._pk = PublicKey.from_point(x, y)

    @classmethod
    def identity(cls):
        return cls._wrap(None)

    @classmethod
    def _wrap(cls, pk):
        p = object.__new__(cls)
        p._pk = pk
        return p

    def is_identity(self):
        return self._pk is None

    def __add__(self, other):
        return Point._wrap(_combine([p._pk for p in (self, other) if p._pk is not None]))

    def __neg__(self):
        if self._pk is None:
            return self
        raw = self._pk.format(compressed=True)
        # -P has the same x and the other y; in compressed form that's just
        # the other prefix byte (02 <-> 03).
        return Point._wrap(PublicKey(bytes([raw[0] ^ 1]) + raw[1:]))

    def __sub__(self, other):
        return self + (-other)

    def __rmul__(self, k):
        if not isinstance(k, int):
            return NotImplemented
        k %= ORDER
        if k == 0 or self._pk is None:
            return Point.identity()
        return Point._wrap(self._pk.multiply(k.to_bytes(32, "big")))

    def __eq__(self, other):
        return isinstance(other, Point) and self.to_bytes() == other.to_bytes()

    def __hash__(self):
        return hash(self.to_bytes())

    def __repr__(self):
        if self._pk is None:
            return "Point(identity)"
        return f"Point({self.to_bytes().hex()[:16]}...)"

    # SEC1 compressed encoding: 0x02/0x03 prefix + 32-byte x.
    # The identity gets 33 zero bytes so every point has a fixed-size encoding.
    def to_bytes(self):
        if self._pk is None:
            return _IDENTITY_BYTES
        return self._pk.format(compressed=True)

    @classmethod
    def from_bytes(cls, data):
        if len(data) != 33:
            raise ValueError("expected 33 bytes")
        if data == _IDENTITY_BYTES:
            return cls.identity()
        if data[0] not in (2, 3):
            raise ValueError("bad prefix")
        try:
            pk = PublicKey(bytes(data))        # libsecp256k1 validates it
        except ValueError:
            raise ValueError("not a valid curve point") from None
        return cls._wrap(pk)


G = Point(_GX, _GY)


def multiexp(scalars, points):
    """sum_i scalars[i] * points[i]. The paper's prod_i A_i^{x_i}.

    Zero scalars are skipped, which matters a lot for one-hot vectors.
    """
    if len(scalars) != len(points):
        raise ValueError("length mismatch")
    terms = []
    for k, p in zip(scalars, points):
        k %= ORDER
        if k and p._pk is not None:
            terms.append(p._pk.multiply(k.to_bytes(32, "big")))
    return Point._wrap(_combine(terms))


def point_sum(points):
    return Point._wrap(_combine([p._pk for p in points if p._pk is not None]))


# --- scalars --------------------------------------------------------------

def random_scalar():
    """Uniform in [1, ORDER-1]."""
    return secrets.randbelow(ORDER - 1) + 1


def inv(x):
    return pow(x % ORDER, -1, ORDER)


# --- encoding for hashes --------------------------------------------------
# Every value fed to a hash gets a type byte and, where the size varies, a
# length prefix. Without that, ("ab", "c") and ("a", "bc") would hash to the
# same thing, which is exactly the sort of ambiguity Fiat-Shamir bugs come from.

def encode(item):
    if isinstance(item, Point):
        return b"P" + item.to_bytes()
    if isinstance(item, bool):
        raise TypeError("encode bools as ints explicitly")
    if isinstance(item, int):
        if not 0 <= item < 2**256:
            raise ValueError("ints must be reduced into [0, 2^256) before hashing")
        return b"I" + item.to_bytes(32, "big")
    if isinstance(item, bytes):
        return b"B" + len(item).to_bytes(8, "big") + item
    if isinstance(item, str):
        raw = item.encode()
        return b"S" + len(raw).to_bytes(8, "big") + raw
    if isinstance(item, (list, tuple)):
        return b"L" + len(item).to_bytes(8, "big") + b"".join(encode(i) for i in item)
    raise TypeError(f"don't know how to encode {type(item).__name__}")


def hash_to_scalar(domain, *items):
    # sha3_512 then reduce: the extra 256 bits make the mod-ORDER bias negligible.
    # hashlib's sha3 is NIST SHA-3, not the original Keccak the paper's Go code
    # uses. Same security, different output bytes.
    h = hashlib.sha3_512()
    h.update(encode(domain))
    h.update(encode(list(items)))
    return int.from_bytes(h.digest(), "big") % ORDER


def hash_to_point(label):
    """A generator whose discrete log nobody knows (try-and-increment).

    Pick x from a hash, keep it if x^3 + 7 is a square. Roughly half of all x
    work, so this loops about twice on average.
    """
    ctr = 0
    while True:
        digest = hashlib.sha3_256(
            encode("SuccinCT/generator") + encode(label) + ctr.to_bytes(4, "big")
        ).digest()
        x = int.from_bytes(digest, "big") % FIELD_P
        y = _sqrt(x * x * x + CURVE_B)
        if y is not None:
            if y & 1:
                y = FIELD_P - y      # pick the even root so the result is unique
            return Point(x, y)
        ctr += 1


# Independent generators. Nobody may know log_G(U), log_V(W) and so on,
# otherwise tags could be forged or commitments opened two ways.
U = hash_to_point("U")      # tags:            tag = U^sk
V = hash_to_point("V")      # Pedersen value:  co = V^a W^ck
W = hash_to_point("W")      # Pedersen blinding
G_KA = hash_to_point("G'")  # key agreement (the paper's G')

_vector_gen_cache = {}


def generator_vector(label, n):
    """n independent generators, e.g. for the vector commitment T or the
    proof system's bases. Cached because hashing to the curve isn't free."""
    key = (label, n)
    if key not in _vector_gen_cache:
        _vector_gen_cache[key] = [hash_to_point(f"{label}/{i}") for i in range(n)]
    return _vector_gen_cache[key]
