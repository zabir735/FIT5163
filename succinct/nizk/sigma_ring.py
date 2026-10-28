"""
Linear-size Σ-protocol (Fiat-Shamir) for the Eq. 5 relation. The MVP NIZK,
replacing the paper's Bulletproofs++ (Appendix C.3: any NIZK for the
inner-product relation works).

It proves all four conditions of nizk/relation.py. Write g_0, g_1, g_(j,i)
for the vector-Pedersen generators of T (label "T": z, ck', then the bits),
P = stmt.target(), B_z = stmt.base_z(), B_ck = stmt.base_ck().

Prover                                       (a's, r's uniformly random)
    a_(j,i) for i >= 1, a_(j,0) = -sum_(i>=1) a_(j,i)
    A = r_z g_0 + r_ck g_1 + sum a_(j,i) g_(j,i) + r_A W       masks T
    C = sum a_(j,i)(1 - 2 b_(j,i)) g_(j,i) + r_C W             bit check, X^1 term
    D = sum -a_(j,i)^2 g_(j,i) + r_D W                         bit check, X^0 term
    E = r_z B_z + r_ck B_ck - sum a_(j,i) Y(j,i)               masks Eq. 5
                       x = challenge(statement, range proof, A, C, D, E)
    f_(j,i) = b_(j,i) x + a_(j,i)   for i >= 1
    s_z = z x + r_z,  s_ck = ck' x + r_ck,  s_t = t x + r_A,  s_bits = r_C x + r_D

Verifier, with f_(j,0) := x - sum_(i>=1) f_(j,i)
    (i)   x T + A == s_z g_0 + s_ck g_1 + sum f_(j,i) g_(j,i) + s_t W
    (ii)  x C + D == sum f_(j,i)(x - f_(j,i)) g_(j,i) + s_bits W
    (iii) x P + E == s_z B_z + s_ck B_ck - sum f_(j,i) Y(j,i)

Why it works (for the report / Q&A):
  * (i) opens T at the masked values, so the same z, ck', b sit behind T,
    (ii) and (iii). Two accepting transcripts with different x give back the
    witness (special soundness).
  * f(x - f) = x a(1 - 2b) - a^2 + x^2 (b - b^2). The x^2 term has no
    commitment to absorb it, so (ii) can only hold for random x when b = b^2,
    i.e. every b is 0 or 1 (Groth-Kohlweiss bit trick).
  * Deriving f_(j,0) instead of sending it forces sum_i b_(j,i) = 1, so each
    b(j) is one-hot. It also saves S scalars.
  * Every f_(j,i) with i >= 1 is uniformly random (masked by a_(j,i)) whatever
    the real index is, and A, C, D, E are fixed by the responses, so a
    simulator can produce the same distribution: honest-verifier zero
    knowledge. The real position doesn't change the proof's size or shape.
  * Condition 4 (range) comes from the Bulletproofs range proof, run first on
    the same transcript.

Proof size: 4 points + S(n-1) + 4 scalars + the range proof, so O(S*n)
against the paper's O(log(S*n)).

Two shortcuts keep the verifier cheap:
  * sum_(j,i) f_(j,i) Y(j,i) collapses to 2n terms:
        sum_i (h sum_j alpha_j f_(j,i)) pk_i + (gamma sum_j f_(j,i)) co_i
    so the n*S bases Y(j, i) are never built.
  * (i) and (ii) share the bases g_(j,i) and W, so they are checked as one
    equation (i) + rho*(ii) with a fresh random rho. A cheater would need to
    guess rho.

The transcript absorbs every field of Statement (see docs/PART_A_NOTES.md,
paper issue 1).
"""

from __future__ import annotations

from dataclasses import dataclass

from ..group import ORDER, W, Point, generator_vector, multiexp, random_scalar
from ..transcript import Transcript
from . import rangeproof
from .relation import T_LABEL, Statement, Witness
from .util import all_scalars, is_point, is_scalar, random_vector

NAME = "Σ-protocol for Eq. 5 (linear size) + Bulletproofs range proof"
TRANSCRIPT_LABEL = "SuccinCT/sigma-eq5"


@dataclass(frozen=True)
class RingProof:
    A: Point
    C: Point
    D: Point
    E: Point
    f: tuple                   # S tuples of n-1 scalars: f_(j,i) for i = 1..n-1
    s_z: int
    s_ck: int
    s_t: int
    s_bits: int
    range_proof: rangeproof.RangeProof


def _transcript(stmt: Statement) -> Transcript:
    t = Transcript(TRANSCRIPT_LABEL)
    t.append("ring_pks", list(stmt.ring_pks))
    t.append("ring_cos", list(stmt.ring_cos))
    t.append("tags", list(stmt.tags))
    t.append("out_cos", list(stmt.out_cos))
    t.append("fee", stmt.fee)
    t.append("alphas", list(stmt.alphas))
    t.append("beta", stmt.beta)
    t.append("h", stmt.h)
    t.append("gamma", stmt.gamma)
    t.append("R", stmt.R)
    t.append("T", stmt.T)
    return t


def _T_generators(stmt: Statement):
    """Same bases as relation.commit_T: [g_z, g_ck, g_(0,0), ..., g_(S-1,n-1)]."""
    return generator_vector(T_LABEL, 2 + stmt.S * stmt.n)


def _sum_Y(stmt: Statement, coeffs):
    """sum_(j,i) coeffs[j][i] * Y(j, i), using 2n scalar multiplications."""
    pk_coef, co_coef = [], []
    for i in range(stmt.n):
        col = [row[i] for row in coeffs]
        pk_coef.append(stmt.h * sum(a * c for a, c in zip(stmt.alphas, col)) % ORDER)
        co_coef.append(stmt.gamma * sum(col) % ORDER)
    return multiexp(pk_coef + co_coef, list(stmt.ring_pks) + list(stmt.ring_cos))


def prove(stmt: Statement, wit: Witness) -> RingProof:
    """Like rangeproof.prove, never refuses a bad witness (wrong position,
    non-binary b, unbalanced amounts...): it returns a proof that fails to
    verify. Only a witness of the wrong shape raises."""
    S, n = stmt.S, stmt.n
    if len(wit.bvecs) != S or any(len(vec) != n for vec in wit.bvecs):
        raise ValueError("witness bit vectors don't match the statement's S x n")
    if n < 1:
        raise ValueError("empty ring")

    t = _transcript(stmt)
    range_proof = rangeproof.prove(wit.out_amounts, wit.out_cks, t)

    b = [[v % ORDER for v in vec] for vec in wit.bvecs]
    a = []
    for _ in range(S):
        rest = random_vector(n - 1)
        a.append([-sum(rest) % ORDER] + rest)
    flat_a = [v for row in a for v in row]
    flat_b = [v for row in b for v in row]

    r_z, r_ck, r_A, r_C, r_D = (random_scalar() for _ in range(5))
    gens = _T_generators(stmt)
    bit_gens = gens[2:]

    A = multiexp([r_z, r_ck] + flat_a + [r_A], gens + [W])
    C = multiexp([ai * (1 - 2 * bi) % ORDER for ai, bi in zip(flat_a, flat_b)] + [r_C],
                 bit_gens + [W])
    D = multiexp([-ai * ai % ORDER for ai in flat_a] + [r_D], bit_gens + [W])
    E = multiexp([r_z, r_ck], [stmt.base_z(), stmt.base_ck()]) - _sum_Y(stmt, a)

    for label, point in (("A", A), ("C", C), ("D", D), ("E", E)):
        t.append(label, point)
    x = t.challenge("x")

    f = tuple(tuple((b[j][i] * x + a[j][i]) % ORDER for i in range(1, n)) for j in range(S))
    return RingProof(
        A=A, C=C, D=D, E=E, f=f,
        s_z=(wit.z * x + r_z) % ORDER,
        s_ck=(wit.ck_prime * x + r_ck) % ORDER,
        s_t=(wit.t * x + r_A) % ORDER,
        s_bits=(r_C * x + r_D) % ORDER,
        range_proof=range_proof,
    )


def _well_formed(stmt: Statement, proof) -> bool:
    if not isinstance(proof, RingProof):
        return False
    if not all(is_point(p) for p in (proof.A, proof.C, proof.D, proof.E)):
        return False
    if not all(is_scalar(v) for v in (proof.s_z, proof.s_ck, proof.s_t, proof.s_bits)):
        return False
    if not isinstance(proof.f, (list, tuple)) or len(proof.f) != stmt.S:
        return False
    return all(all_scalars(row) and len(row) == stmt.n - 1 for row in proof.f)


def verify(stmt: Statement, proof) -> bool:
    if stmt.S < 1 or stmt.n < 1 or not _well_formed(stmt, proof):
        return False

    t = _transcript(stmt)
    if not rangeproof.verify(stmt.out_cos, proof.range_proof, t):
        return False
    for label, point in (("A", proof.A), ("C", proof.C), ("D", proof.D), ("E", proof.E)):
        t.append(label, point)
    x = t.challenge("x")

    f = [[(x - sum(row)) % ORDER] + list(row) for row in proof.f]
    flat_f = [v for row in f for v in row]

    # (i) + rho * (ii), sharing the bases g_(j,i) and W.
    rho = random_scalar()
    gens = _T_generators(stmt)
    bit_coef = [(-fi - rho * fi * (x - fi)) % ORDER for fi in flat_f]
    check_open = multiexp(
        [x, 1, rho * x % ORDER, rho, -proof.s_z, -proof.s_ck]
        + bit_coef
        + [(-proof.s_t - rho * proof.s_bits) % ORDER],
        [stmt.T, proof.A, proof.C, proof.D, gens[0], gens[1]] + gens[2:] + [W],
    )
    if not check_open.is_identity():
        return False

    # (iii) x P + E - s_z B_z - s_ck B_ck + sum f Y == identity
    check_eq5 = (
        multiexp([x, 1, -proof.s_z, -proof.s_ck],
                 [stmt.target(), proof.E, stmt.base_z(), stmt.base_ck()])
        + _sum_Y(stmt, f)
    )
    return check_eq5.is_identity()
