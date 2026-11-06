"""
The relation the NIZK proves (paper Eq. 5, §6.2). This file is the contract
between Spend/Verify (Part A) and the proof system (Part B).

In additive notation, with the public bases

    Y[j][i] = (alpha_j * h) * pk_i + gamma * co_i          (ring member i, input j)

the witness (z, ck', b(1..S), t, output openings) must satisfy

    (1) z*(G + beta*U) + ck'*(gamma*W) - sum_{j,i} b(j)_i * Y[j][i]  ==  target
        target = R - (fee*gamma)*V + beta*h * sum_j alpha_j*tag_j - gamma * sum_k co_out_k
    (2) each b(j) is a 0/1 vector with exactly one 1
    (3) T = Com(z, ck', b(1), ..., b(S); t)            (vector Pedersen, label "T")
    (4) co_out_k = Com(a_k; ck_k) and 0 <= a_k < 2^64   (the range proof)

(1) is Eq. 5 with every witness term moved to the left. The left side is
linear in the witness over public bases, which is exactly the shape a
Σ-protocol or inner-product argument can prove. The paper writes (2) as
(b - 1/2)^2 = 1/4 and <b, 1> = 1, which is the same condition.

Why each challenge is there (worth knowing for Q&A):
  alpha_j  MuSig coefficients. Without them, someone could pick input keys that
           cancel each other out in the aggregate (rogue-key attack).
  beta     Folds the pk equation (base G) and the tag equation (base U) into one
           using base G + beta*U, so the same secret has to stand behind both.
           Without it you could attach a tag unrelated to your key.
  h        The ordinary Schnorr challenge.
  gamma    Folds the signature equation and the balance equation into one. The
           balance proof in Appendix H.3 rewinds gamma to split them apart.

relation_holds() checks all four directly. It's the stub proof's verifier and
also the oracle B's tests should compare against: a real proof must accept
exactly when this returns True.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..group import G, U, V, W, Point, multiexp, point_sum
from ..pedersen import commit, vector_commit
from ..stealth import AMOUNT_MASK

T_LABEL = "T"


@dataclass(frozen=True)
class Statement:
    ring_pks: tuple            # n points
    ring_cos: tuple            # n points
    tags: tuple                # S points
    out_cos: tuple             # number-of-outputs points
    fee: int
    alphas: tuple              # S scalars
    beta: int                  # challenge from H_b (NOT the amount bit length)
    h: int
    gamma: int
    R: Point
    T: Point

    @property
    def n(self):
        return len(self.ring_pks)

    @property
    def S(self):
        return len(self.tags)

    def base_z(self):
        return G + self.beta * U

    def base_ck(self):
        return self.gamma * W

    def Y(self, j, i):
        return multiexp([self.alphas[j] * self.h, self.gamma],
                        [self.ring_pks[i], self.ring_cos[i]])

    def target(self):
        tag_part = multiexp([a * self.h * self.beta for a in self.alphas], list(self.tags))
        return (self.R
                - (self.fee * self.gamma) * V
                + tag_part
                - self.gamma * point_sum(self.out_cos))


@dataclass(frozen=True)
class Witness:
    z: int
    ck_prime: int
    bvecs: tuple               # S tuples of n bits
    t: int                     # blinding for T
    out_amounts: tuple
    out_cks: tuple

    def t_values(self):
        flat = [b for vec in self.bvecs for b in vec]
        return [self.z, self.ck_prime] + flat


def commit_T(z, ck_prime, bvecs, t):
    flat = [b for vec in bvecs for b in vec]
    return vector_commit([z, ck_prime] + flat, t, label=T_LABEL)


def relation_holds(stmt, wit):
    # (2) one-hot vectors
    if len(wit.bvecs) != stmt.S:
        return False
    for vec in wit.bvecs:
        if len(vec) != stmt.n:
            return False
        if any(b not in (0, 1) for b in vec) or sum(vec) != 1:
            return False

    # (3) T opens to the same witness
    if commit_T(wit.z, wit.ck_prime, wit.bvecs, wit.t) != stmt.T:
        return False

    # (4) outputs open and are in range
    if not (len(wit.out_amounts) == len(wit.out_cks) == len(stmt.out_cos)):
        return False
    for a, ck, co in zip(wit.out_amounts, wit.out_cks, stmt.out_cos):
        if not (isinstance(a, int) and 0 <= a <= AMOUNT_MASK):
            return False
        if commit(a, ck) != co:
            return False

    # (1) Eq. 5. Only the positions where b = 1 contribute, so this only
    # builds S of the n*S bases.
    lhs = wit.z * stmt.base_z() + wit.ck_prime * stmt.base_ck()
    for j, vec in enumerate(wit.bvecs):
        lhs = lhs - stmt.Y(j, vec.index(1))
    return lhs == stmt.target()
