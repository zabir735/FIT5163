"""
Bulletproofs inner-product argument (Bünz et al. 2018, Protocol 2 with the
Fiat-Shamir transform). Proof size 2*log2(n) points + 2 scalars.

Proves knowledge of vectors a, b such that

    P = <a, g> + <b, h> + <a, b> * u

Each round halves the vectors: the prover sends L, R, gets a challenge x and
folds

    g' = x^-1 * g_lo + x * g_hi        a' = x * a_lo + x^-1 * a_hi
    h' = x * h_lo + x^-1 * h_hi        b' = x^-1 * b_lo + x * b_hi
    P' = x^2 * L + P + x^-2 * R

until one element is left. The verifier skips the folding and checks one
multi-exponentiation: after all rounds, g_final = sum_i s_i * g_i where s_i is
a product of x_k or x_k^-1 picked by the bits of i (likewise h_final with
1/s_i).

The caller must already have bound P (or everything P is built from) into the
transcript; this module only appends L and R. rangeproof.py does that.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..group import ORDER, Point, inv, multiexp
from ..transcript import Transcript
from .util import all_points, inner, is_point, is_power_of_two, is_scalar


@dataclass(frozen=True)
class InnerProductProof:
    L: tuple                   # log2(n) Points
    R: tuple                   # log2(n) Points
    a: int
    b: int


def prove(g, h, u: Point, a, b, transcript: Transcript) -> InnerProductProof:
    n = len(a)
    if not (len(g) == len(h) == len(b) == n and is_power_of_two(n)):
        raise ValueError("g, h, a, b must all have the same power-of-two length")
    g, h = list(g), list(h)
    a, b = [x % ORDER for x in a], [x % ORDER for x in b]

    Ls, Rs = [], []
    while n > 1:
        n //= 2
        a_lo, a_hi, b_lo, b_hi = a[:n], a[n:], b[:n], b[n:]
        g_lo, g_hi, h_lo, h_hi = g[:n], g[n:], h[:n], h[n:]

        L = multiexp(a_lo + b_hi + [inner(a_lo, b_hi)], g_hi + h_lo + [u])
        R = multiexp(a_hi + b_lo + [inner(a_hi, b_lo)], g_lo + h_hi + [u])
        Ls.append(L)
        Rs.append(R)
        transcript.append("ipa/L", L)
        transcript.append("ipa/R", R)
        x = transcript.challenge("ipa/x")
        if x == 0:
            raise ValueError("zero challenge")   # probability 2^-256
        xi = inv(x)

        g = [multiexp([xi, x], [lo, hi]) for lo, hi in zip(g_lo, g_hi)]
        h = [multiexp([x, xi], [lo, hi]) for lo, hi in zip(h_lo, h_hi)]
        a = [(lo * x + hi * xi) % ORDER for lo, hi in zip(a_lo, a_hi)]
        b = [(lo * xi + hi * x) % ORDER for lo, hi in zip(b_lo, b_hi)]

    return InnerProductProof(L=tuple(Ls), R=tuple(Rs), a=a[0], b=b[0])


def verification_scalars(proof, n, transcript: Transcript):
    """Replay the transcript. Returns (challenges, s) or None if the proof is
    malformed. s[i] is the coefficient of g_i in the folded generator; the
    coefficient of h_i is 1/s[i] = s[n-1-i]."""
    if not isinstance(proof, InnerProductProof) or not is_power_of_two(n):
        return None
    rounds = n.bit_length() - 1
    if len(proof.L) != rounds or len(proof.R) != rounds:
        return None
    if not (all_points(proof.L) and all_points(proof.R)):
        return None
    if not (is_scalar(proof.a) and is_scalar(proof.b)):
        return None

    xs = []
    for L, R in zip(proof.L, proof.R):
        transcript.append("ipa/L", L)
        transcript.append("ipa/R", R)
        x = transcript.challenge("ipa/x")
        if x == 0:
            return None
        xs.append(x)

    # Round k splits on bit (rounds-1-k) of the index (round 0 = top bit).
    # Start from prod x_k^-1 and, walking from the last round to the first,
    # double the list, multiplying the new half by x_k^2.
    s = [inv(_prod(xs))]
    for x in reversed(xs):
        x2 = x * x % ORDER
        s = s + [v * x2 % ORDER for v in s]
    return xs, s


def lr_terms(proof, xs):
    """Scalars and points for sum_k x_k^2 * L_k + x_k^-2 * R_k."""
    scalars, points = [], []
    for x, L, R in zip(xs, proof.L, proof.R):
        x2 = x * x % ORDER
        scalars += [x2, inv(x2)]
        points += [L, R]
    return scalars, points


def verify(g, h, u: Point, P: Point, proof, transcript: Transcript) -> bool:
    n = len(g)
    if len(h) != n or not (all_points(g) and all_points(h) and is_point(u) and is_point(P)):
        return False
    replay = verification_scalars(proof, n, transcript)
    if replay is None:
        return False
    xs, s = replay

    # P + sum(x^2 L + x^-2 R) - <a*s, g> - <b/s, h> - a*b*u == identity
    lr_s, lr_p = lr_terms(proof, xs)
    scalars = ([1] + lr_s
               + [-proof.a * si for si in s]
               + [-proof.b * s[n - 1 - i] for i in range(n)]
               + [-proof.a * proof.b])
    points = [P] + lr_p + list(g) + list(h) + [u]
    return multiexp(scalars, points).is_identity()


def _prod(xs):
    acc = 1
    for x in xs:
        acc = acc * x % ORDER
    return acc
