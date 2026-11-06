"""
Aggregated Bulletproofs range proof (Bünz et al. 2018, §4.3), own
implementation. Proves every output coin

    co_k = Com(a_k; ck_k) = a_k*V + ck_k*W      has  0 <= a_k < 2^bits

which is condition 4 of nizk/relation.py. V and W are the Pedersen bases from
group.py, so the commitments proved are exactly stmt.out_cos.

Notation (paper -> here, additive): value base g -> V, blinding base h -> W,
vector bases g_vec, h_vec -> generator_vector("BP/g"), ("BP/h"), IPA base
u -> U_IPA. Outputs are indexed j = 0..m-1, so the paper's z^(1+j) for
j = 1..m becomes z^(2+j) here.

m is padded up to a power of two with commitments to zero (the identity), so
m * bits is a power of two as the inner-product argument needs. Both sides pad
the same way, so the padding costs proof size only through log2.

The prover never refuses: give it an out-of-range or negative amount and it
returns a proof that fails to verify. That's how the tests play a cheating
spender (test_negative_output_caught_by_range_check). Soundness lives in
verify alone.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..group import ORDER, V, W, Point, generator_vector, hash_to_point, inv, multiexp, random_scalar
from ..pedersen import commit
from ..stealth import AMOUNT_BITS
from ..transcript import Transcript
from . import ipa
from .ipa import InnerProductProof
from .util import all_points, inner, is_point, is_power_of_two, is_scalar, powers, random_vector

G_LABEL = "BP/g"
H_LABEL = "BP/h"
U_IPA = hash_to_point("BP/u")


@dataclass(frozen=True)
class RangeProof:
    A: Point                   # commitment to the bits a_L and a_R = a_L - 1
    S: Point                   # commitment to the blinding vectors s_L, s_R
    T1: Point                  # commitments to the coefficients of t(X)
    T2: Point
    tau_x: int                 # blinding of t_hat
    mu: int                    # blinding of A + x*S
    t_hat: int                 # t(x) = <l(x), r(x)>
    ipa: InnerProductProof


def _padded(m):
    p = 1
    while p < m:
        p *= 2
    return p


def _block_weights(z, m, bits):
    """d_i = z^(2+j) * 2^k for i = j*bits + k: the r(X) term that ties block j
    to output j."""
    two = powers(2, bits)
    zj = powers(z, m + 2)[2:]
    return [zj[j] * two[k] % ORDER for j in range(m) for k in range(bits)]


def _delta(y, z, m, bits):
    """delta(y, z) = (z - z^2) * <1, y^N> - sum_j z^(3+j) * <1, 2^bits>."""
    N = m * bits
    sum_y = sum(powers(y, N)) % ORDER
    sum_2 = (1 << bits) - 1
    sum_z = sum(powers(z, m + 3)[3:]) % ORDER
    return ((z - z * z) * sum_y - sum_z * sum_2) % ORDER


def prove(amounts, blindings, transcript: Transcript, bits=AMOUNT_BITS) -> RangeProof:
    """amounts[k], blindings[k] open the k-th output commitment."""
    m = len(amounts)
    if m < 1 or len(blindings) != m or not is_power_of_two(bits):
        raise ValueError("need one blinding per amount, and bits a power of two")
    mp = _padded(m)
    values = [a % ORDER for a in amounts] + [0] * (mp - m)
    gammas = [ck % ORDER for ck in blindings] + [0] * (mp - m)
    N = mp * bits
    g, h = generator_vector(G_LABEL, N), generator_vector(H_LABEL, N)

    transcript.append("bp/V", [commit(v, c) for v, c in zip(values, gammas)])

    # Bits of each value, low bit first. A value >= 2^bits is silently
    # truncated here; the resulting proof won't verify.
    aL = [(v >> k) & 1 for v in values for k in range(bits)]
    aR = [(x - 1) % ORDER for x in aL]
    alpha = random_scalar()
    A = multiexp(aL + aR + [alpha], g + h + [W])

    sL, sR = random_vector(N), random_vector(N)
    rho = random_scalar()
    S = multiexp(sL + sR + [rho], g + h + [W])

    transcript.append("bp/A", A)
    transcript.append("bp/S", S)
    y = transcript.challenge("bp/y")
    z = transcript.challenge("bp/z")
    if y == 0:
        raise ValueError("zero challenge")

    # l(X) = l0 + l1*X,  r(X) = r0 + r1*X,  t(X) = <l(X), r(X)> = t0 + t1*X + t2*X^2
    yN = powers(y, N)
    d = _block_weights(z, mp, bits)
    l0 = [(a - z) % ORDER for a in aL]
    l1 = sL
    r0 = [(yi * (ar + z) + di) % ORDER for yi, ar, di in zip(yN, aR, d)]
    r1 = [yi * s % ORDER for yi, s in zip(yN, sR)]
    t1 = (inner(l0, r1) + inner(l1, r0)) % ORDER
    t2 = inner(l1, r1)

    tau1, tau2 = random_scalar(), random_scalar()
    T1 = multiexp([t1, tau1], [V, W])
    T2 = multiexp([t2, tau2], [V, W])
    transcript.append("bp/T1", T1)
    transcript.append("bp/T2", T2)
    x = transcript.challenge("bp/x")

    l = [(a + b * x) % ORDER for a, b in zip(l0, l1)]
    r = [(a + b * x) % ORDER for a, b in zip(r0, r1)]
    t_hat = inner(l, r)
    zj = powers(z, mp + 2)[2:]
    tau_x = (tau2 * x * x + tau1 * x + inner(zj, gammas)) % ORDER
    mu = (alpha + rho * x) % ORDER

    transcript.append("bp/tau_x", tau_x)
    transcript.append("bp/mu", mu)
    transcript.append("bp/t_hat", t_hat)
    w = transcript.challenge("bp/w")

    # Prove <l, r> = t_hat over bases g and h'_i = y^-i * h_i.
    y_inv = powers(inv(y), N)
    h_prime = [yi * hi for yi, hi in zip(y_inv, h)]
    proof = ipa.prove(g, h_prime, w * U_IPA, l, r, transcript)

    return RangeProof(A=A, S=S, T1=T1, T2=T2, tau_x=tau_x, mu=mu, t_hat=t_hat, ipa=proof)


def verify(commitments, proof, transcript: Transcript, bits=AMOUNT_BITS) -> bool:
    m = len(commitments)
    if m < 1 or not all_points(commitments) or not is_power_of_two(bits):
        return False
    if not isinstance(proof, RangeProof):
        return False
    if not all(is_point(p) for p in (proof.A, proof.S, proof.T1, proof.T2)):
        return False
    if not all(is_scalar(v) for v in (proof.tau_x, proof.mu, proof.t_hat)):
        return False

    mp = _padded(m)
    Vs = list(commitments) + [Point.identity()] * (mp - m)
    N = mp * bits
    g, h = generator_vector(G_LABEL, N), generator_vector(H_LABEL, N)

    transcript.append("bp/V", Vs)
    transcript.append("bp/A", proof.A)
    transcript.append("bp/S", proof.S)
    y = transcript.challenge("bp/y")
    z = transcript.challenge("bp/z")
    transcript.append("bp/T1", proof.T1)
    transcript.append("bp/T2", proof.T2)
    x = transcript.challenge("bp/x")
    transcript.append("bp/tau_x", proof.tau_x)
    transcript.append("bp/mu", proof.mu)
    transcript.append("bp/t_hat", proof.t_hat)
    w = transcript.challenge("bp/w")
    if y == 0:
        return False

    # (1) t_hat is t(x), with t0 = sum_j z^(2+j) * a_j + delta(y, z):
    #     t_hat*V + tau_x*W == sum_j z^(2+j)*V_j + delta*V + x*T1 + x^2*T2
    zj = powers(z, mp + 2)[2:]
    delta = _delta(y, z, mp, bits)
    check_t = multiexp(
        [(proof.t_hat - delta) % ORDER, proof.tau_x] + [-c for c in zj] + [-x, -x * x],
        [V, W] + Vs + [proof.T1, proof.T2],
    )
    if not check_t.is_identity():
        return False

    # (2) the inner-product argument for
    #     P = A + x*S - z*<1, g> + <z*y^N + d, h'> - mu*W + t_hat*w*U_IPA
    # with h'_i = y^-i h_i, folded into one multi-exponentiation.
    replay = ipa.verification_scalars(proof.ipa, N, transcript)
    if replay is None:
        return False
    xs, s = replay
    a, b = proof.ipa.a, proof.ipa.b
    y_inv = powers(inv(y), N)
    d = _block_weights(z, mp, bits)

    g_coef = [(-z - a * si) % ORDER for si in s]
    h_coef = [(z + (di - b * s[N - 1 - i]) * y_inv[i]) % ORDER for i, di in enumerate(d)]
    lr_s, lr_p = ipa.lr_terms(proof.ipa, xs)
    scalars = ([1, x, -proof.mu, w * (proof.t_hat - a * b)]
               + lr_s + g_coef + h_coef)
    points = [proof.A, proof.S, W, U_IPA] + lr_p + list(g) + list(h)
    return multiexp(scalars, points).is_identity()
