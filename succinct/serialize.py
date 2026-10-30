"""
Canonical byte encodings for measuring transaction and proof sizes.

Points are 33 bytes (SEC1 compressed, group.Point.to_bytes) and scalars 32
bytes, so measured sizes line up with the paper's Table 1 formulas. Every
variable-length list carries a 2-byte count, so the encoding is
self-describing and decode_transaction / decode_proof can rebuild the exact
objects (the tests round-trip real transactions to show nothing is left out).

Layout (big-endian integers, u16 = 2 bytes, u64 = 8 bytes):

    transaction = u16 n, n * u32 ring ref
                  u16 S, S * point tag
                  u16 k, k * account
                  point info, u64 fee, u16 len(mu), mu
                  point R, point T, ring proof
    account     = point pk, point co, u64 ctxt, u16 kappa
    ring proof  = point A, C, D, E
                  u16 S, u16 n-1, S*(n-1) * scalar f
                  scalar s_z, s_ck, s_t, s_bits
                  range proof
    range proof = point A, S, T1, T2, scalar tau_x, mu, t_hat, ipa
    ipa         = u16 rounds, rounds * point L, rounds * point R, scalar a, b

Only sigma_ring proofs are encoded. The stub "proof" is the witness itself and
has no meaningful size, so encode_proof rejects it.
"""

from __future__ import annotations

from .ct import Signature, Transaction
from .group import ORDER, Point
from .nizk.ipa import InnerProductProof
from .nizk.rangeproof import RangeProof
from .nizk.sigma_ring import RingProof
from .stealth import AMOUNT_BITS, Account

POINT_BYTES = 33
SCALAR_BYTES = 32
COUNT_BYTES = 2
REF_BYTES = 4
AMOUNT_BYTES = AMOUNT_BITS // 8

# Read by eval/bench_size.py before it measures anything.
COMPLETE_TRANSACTION_ENCODING = True
COMPLETE_PROOF_ENCODING = True
TRANSACTION_FORMAT = "succinct-v1 (33-byte points, 32-byte scalars, u16 counts)"


# --- writing ---------------------------------------------------------------

def _uint(value, size, what):
    if type(value) is not int or not 0 <= value < 1 << (8 * size):
        raise ValueError(f"{what} must be an int in [0, 2^{8 * size})")
    return value.to_bytes(size, "big")


def _count(items, what):
    return _uint(len(items), COUNT_BYTES, f"number of {what}")


def _point(p):
    if not isinstance(p, Point):
        raise TypeError(f"expected a Point, got {type(p).__name__}")
    return p.to_bytes()


def _scalar(x):
    if type(x) is not int or not 0 <= x < ORDER:
        raise ValueError("scalar must be an int in [0, ORDER)")
    return x.to_bytes(SCALAR_BYTES, "big")


def _account(acc):
    return (_point(acc.pk) + _point(acc.co)
            + _uint(acc.ctxt, AMOUNT_BYTES, "ctxt")
            + _uint(acc.kappa, COUNT_BYTES, "kappa"))


def _ipa(proof):
    if len(proof.L) != len(proof.R):
        raise ValueError("IPA proof has different numbers of L and R")
    return (_count(proof.L, "IPA rounds")
            + b"".join(map(_point, proof.L)) + b"".join(map(_point, proof.R))
            + _scalar(proof.a) + _scalar(proof.b))


def _range(proof):
    return (b"".join(map(_point, (proof.A, proof.S, proof.T1, proof.T2)))
            + b"".join(map(_scalar, (proof.tau_x, proof.mu, proof.t_hat)))
            + _ipa(proof.ipa))


def encode_proof(proof: RingProof) -> bytes:
    """The sigma_ring proof on its own, including the range proof and IPA."""
    if not isinstance(proof, RingProof):
        raise TypeError("only sigma_ring proofs have a byte encoding")
    width = len(proof.f[0]) if proof.f else 0
    if any(len(row) != width for row in proof.f):
        raise ValueError("rows of f have different lengths")
    return (b"".join(map(_point, (proof.A, proof.C, proof.D, proof.E)))
            + _count(proof.f, "rows of f") + _uint(width, COUNT_BYTES, "width of f")
            + b"".join(_scalar(x) for row in proof.f for x in row)
            + b"".join(map(_scalar, (proof.s_z, proof.s_ck, proof.s_t, proof.s_bits)))
            + _range(proof.range_proof))


def encode_transaction(tx: Transaction, sig: Signature) -> bytes:
    """Everything a verifier receives: the transaction, R, T and the full proof."""
    return (_count(tx.ring_refs, "ring refs")
            + b"".join(_uint(r, REF_BYTES, "ring ref") for r in tx.ring_refs)
            + _count(tx.tags, "tags") + b"".join(map(_point, tx.tags))
            + _count(tx.outputs, "outputs") + b"".join(map(_account, tx.outputs))
            + _point(tx.info) + _uint(tx.fee, AMOUNT_BYTES, "fee")
            + _count(tx.mu, "bytes of mu") + tx.mu
            + _point(sig.R) + _point(sig.T) + encode_proof(sig.proof))


def transaction_size(tx: Transaction, sig: Signature) -> int:
    return len(encode_transaction(tx, sig))


def proof_size(proof: RingProof) -> int:
    return len(encode_proof(proof))


# --- reading ---------------------------------------------------------------

class _Reader:
    def __init__(self, data):
        self.data, self.pos = bytes(data), 0

    def take(self, size):
        if self.pos + size > len(self.data):
            raise ValueError("encoding is truncated")
        chunk = self.data[self.pos:self.pos + size]
        self.pos += size
        return chunk

    def uint(self, size):
        return int.from_bytes(self.take(size), "big")

    def count(self):
        return self.uint(COUNT_BYTES)

    def point(self):
        return Point.from_bytes(self.take(POINT_BYTES))

    def points(self, n):
        return tuple(self.point() for _ in range(n))

    def scalar(self):
        x = self.uint(SCALAR_BYTES)
        if x >= ORDER:
            raise ValueError("scalar out of range")
        return x

    def scalars(self, n):
        return tuple(self.scalar() for _ in range(n))

    def done(self):
        if self.pos != len(self.data):
            raise ValueError("trailing bytes after the encoding")


def _read_account(r):
    return Account(pk=r.point(), co=r.point(), ctxt=r.uint(AMOUNT_BYTES), kappa=r.count())


def _read_ipa(r):
    rounds = r.count()
    L, R = r.points(rounds), r.points(rounds)
    return InnerProductProof(L=L, R=R, a=r.scalar(), b=r.scalar())


def _read_range(r):
    A, S, T1, T2 = r.points(4)
    tau_x, mu, t_hat = r.scalars(3)
    return RangeProof(A=A, S=S, T1=T1, T2=T2, tau_x=tau_x, mu=mu, t_hat=t_hat,
                      ipa=_read_ipa(r))


def _read_proof(r):
    A, C, D, E = r.points(4)
    rows, width = r.count(), r.count()
    f = tuple(r.scalars(width) for _ in range(rows))
    s_z, s_ck, s_t, s_bits = r.scalars(4)
    return RingProof(A=A, C=C, D=D, E=E, f=f, s_z=s_z, s_ck=s_ck, s_t=s_t,
                     s_bits=s_bits, range_proof=_read_range(r))


def decode_proof(data: bytes) -> RingProof:
    r = _Reader(data)
    proof = _read_proof(r)
    r.done()
    return proof


def decode_transaction(data: bytes) -> tuple[Transaction, Signature]:
    r = _Reader(data)
    ring_refs = tuple(r.uint(REF_BYTES) for _ in range(r.count()))
    tags = r.points(r.count())
    outputs = tuple(_read_account(r) for _ in range(r.count()))
    info, fee = r.point(), r.uint(AMOUNT_BYTES)
    mu = r.take(r.count())
    R, T = r.point(), r.point()
    proof = _read_proof(r)
    r.done()
    tx = Transaction(ring_refs=ring_refs, tags=tags, outputs=outputs, info=info,
                     fee=fee, mu=mu)
    return tx, Signature(R=R, T=T, proof=proof)


# --- expected sizes ----------------------------------------------------------

def expected_proof_size(n, S, outputs, bits=AMOUNT_BITS):
    """Closed form of len(encode_proof(...)) for ring size n, S inputs and
    `outputs` outputs (padded to a power of two inside the range proof)."""
    padded = 1
    while padded < outputs:
        padded *= 2
    rounds = (bits * padded).bit_length() - 1
    ring = 4 * POINT_BYTES + 2 * COUNT_BYTES + (S * (n - 1) + 4) * SCALAR_BYTES
    rng = 4 * POINT_BYTES + 3 * SCALAR_BYTES
    ipa = COUNT_BYTES + 2 * rounds * POINT_BYTES + 2 * SCALAR_BYTES
    return ring + rng + ipa


def expected_transaction_size(n, S, outputs, mu_len=0, bits=AMOUNT_BITS):
    """Closed form of len(encode_transaction(...))."""
    account = 2 * POINT_BYTES + AMOUNT_BYTES + COUNT_BYTES
    return (COUNT_BYTES + n * REF_BYTES
            + COUNT_BYTES + S * POINT_BYTES
            + COUNT_BYTES + outputs * account
            + POINT_BYTES + AMOUNT_BYTES + COUNT_BYTES + mu_len
            + 2 * POINT_BYTES
            + expected_proof_size(n, S, outputs, bits))
