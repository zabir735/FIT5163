"""
The confidential transaction itself (§6.2): Spend, Verify, Mine.

How a spend works, in one paragraph. The spender hides S real inputs in a ring
of n accounts. It makes ONE Schnorr-style signature for all inputs together
(MuSig, with weights alpha_j), on the combined base G + beta*U so the same
secret keys stand behind both the public keys and the tags. It folds the coin
balance into the same equation with weight gamma. Then it proves, in zero
knowledge, that it knows which ring positions are real (the one-hot vectors
b(j)) and the other secret values. That last part is the NIZK; see
nizk/relation.py for exactly what it proves.

Rules Verify enforces, beyond the proof itself:
  * 2 <= number of outputs <= 16      (paper: 2 <= T <= 2^iota, iota = 4)
  * tags are distinct and not already on chain      (no double spend)
  * at most S-1 miner (coinbase) accounts in the ring  (§3.2, anonymity reduction)
  * every ring reference points at a real output, no duplicates
  * outputs are ordinary accounts (kappa >= 1), never coinbase-style

Deviation from the paper: the signed message mu is the whole transaction
prefix (ring refs, outputs, info, fee, user message), as Monero does, not just
an optional user message. Reason, found by test_tampered_tx_rejected[info]:
in §6.2 the tek (info) is hashed nowhere, and the outputs and fee only go into
gamma. gamma just folds two equations together, and an honest witness
satisfies the balance half for every gamma, so gamma alone doesn't stop
anyone swapping fields. Swapping tek would leave the proof valid while making
every output unrecoverable by its recipient. Putting the prefix into h binds it
through z = r + h * sum(alpha_j sk_j), which can't be redone without the keys.
"""

from __future__ import annotations

import random as _random
from dataclasses import dataclass

from .group import ORDER, G, U, Point, random_scalar
from .transcript import H, H_a, H_b, H_c
from .stealth import AMOUNT_MASK, Account, otaccgen
from .nizk.relation import Statement, Witness, commit_T
from .nizk import sigma_ring

MAX_OUTPUTS = 16          # 2^iota with iota = 4 (Monero since v8)


# --- data types -----------------------------------------------------------

@dataclass(frozen=True)
class SpendInput:
    """One real input, as returned by Receive plus its position in the ring."""
    ind: int                   # 0-based position in the ring
    ck: int
    a: int
    sk: int
    tag: Point


@dataclass(frozen=True)
class SpendOutput:
    ck: int
    a: int
    acc: Account


@dataclass(frozen=True)
class Transaction:
    """What goes on chain. Note what's missing: no input positions, no amounts
    except the fee, no secret keys."""
    ring_refs: tuple           # pointers to existing outputs
    tags: tuple                # one key image per real input
    outputs: tuple             # Accounts
    info: Point                # shared tek for all outputs
    fee: int
    mu: bytes = b""


@dataclass(frozen=True)
class Signature:
    R: Point
    T: Point
    proof: object


# --- the statement, built identically by Spend and Verify -----------------

def _ring_items(ring_accs):
    return [acc.hash_items() for acc in ring_accs]


def tx_prefix(ring_refs, outputs, info, fee, mu):
    """Everything the signature must cover (the paper's mu, see docstring)."""
    return (list(ring_refs), [o.hash_items() for o in outputs], info, fee, mu)


def ring_challenges(ring_accs, tags):
    """alpha_j = H_a(ring, tags, j) for j = 1..S, and beta = H_b(alphas)."""
    ring = _ring_items(ring_accs)
    alphas = tuple(H_a(ring, list(tags), j) for j in range(1, len(tags) + 1))
    return alphas, H_b(list(alphas))


def schnorr_challenge(ring_refs, outputs, info, fee, mu, R, beta):
    return H(tx_prefix(ring_refs, outputs, info, fee, mu), R, beta)


def build_statement(ring_refs, ring_accs, tags, outputs, info, fee, mu, R, T):
    alphas, beta = ring_challenges(ring_accs, tags)
    h = schnorr_challenge(ring_refs, outputs, info, fee, mu, R, beta)
    gamma = H_c(h, T, [o.hash_items() for o in outputs], fee)
    return Statement(
        ring_pks=tuple(a.pk for a in ring_accs),
        ring_cos=tuple(a.co for a in ring_accs),
        tags=tuple(tags),
        out_cos=tuple(o.co for o in outputs),
        fee=fee,
        alphas=alphas,
        beta=beta,
        h=h,
        gamma=gamma,
        R=R,
        T=T,
    )


# --- helpers for building a spend -----------------------------------------

def make_outputs(payments):
    """payments: [(mpk, amount), ...] -> (outputs, info).

    One ephemeral key for the whole transaction, output index kappa = 1, 2, ...
    """
    tdk = random_scalar()
    outputs, info = [], None
    for kappa, (mpk, amount) in enumerate(payments, start=1):
        ck, acc, info = otaccgen(mpk, amount, kappa, tdk=tdk)
        outputs.append(SpendOutput(ck=ck, a=amount, acc=acc))
    return outputs, info


def pick_ring(chain, real_refs, size, rng=None):
    """Choose decoys and shuffle. Returns (ring_refs, positions of real_refs).

    Respects the S-1 miner-account rule. Decoys are uniform over the chain;
    Monero samples by age with a gamma distribution (Appendix F), which a
    real wallet would need for the ring to be convincing.
    """
    rng = rng or _random.SystemRandom()
    S = len(real_refs)
    if size < S:
        raise ValueError("ring smaller than number of inputs")
    real = set(real_refs)
    miners = sum(chain.get(r)[0].is_miner for r in real_refs)
    if miners > S - 1:
        raise ValueError("at most S-1 inputs may be coinbase outputs; "
                         "add an ordinary input alongside (§3.2)")

    candidates = [r for r in range(len(chain)) if r not in real]
    rng.shuffle(candidates)
    decoys = []
    for r in candidates:
        if len(decoys) == size - S:
            break
        if chain.get(r)[0].is_miner:
            if miners >= S - 1:
                continue
            miners += 1
        decoys.append(r)
    if len(decoys) < size - S:
        raise ValueError("not enough outputs on chain for this ring size")

    ring = list(real_refs) + decoys
    rng.shuffle(ring)
    return tuple(ring), [ring.index(r) for r in real_refs]


# --- Spend ----------------------------------------------------------------

def _check_balance(inputs, outputs, fee):
    # Kept separate so tests can switch it off and confirm Verify still
    # catches a cheating spender on its own.
    if sum(i.a for i in inputs) - fee != sum(o.a for o in outputs):
        raise ValueError("inputs - fee != outputs")


def spend(ring, inputs, outputs, info, fee, mu=b"", nizk=sigma_ring):
    """ring: [(ref, Account)], inputs: [SpendInput], outputs: [SpendOutput].

    Returns (Transaction, Signature).
    """
    ring_refs = tuple(ref for ref, _ in ring)
    ring_accs = [acc for _, acc in ring]
    n, S = len(ring_accs), len(inputs)

    if S < 1:
        raise ValueError("need at least one input")
    if not 2 <= len(outputs) <= MAX_OUTPUTS:
        raise ValueError(f"need 2..{MAX_OUTPUTS} outputs")
    if not 0 <= fee <= AMOUNT_MASK:
        raise ValueError("fee out of range")
    if sum(acc.is_miner for acc in ring_accs) > S - 1:
        raise ValueError("too many miner accounts in ring (max S-1)")
    _check_balance(inputs, outputs, fee)
    tags = tuple(i.tag for i in inputs)
    if len(set(tags)) != S:
        raise ValueError("same input used twice")
    for i in inputs:
        if not 0 <= i.ind < n:
            raise ValueError("input position outside ring")

    out_accs = tuple(o.acc for o in outputs)

    # (1) ring multi-signature
    alphas, beta = ring_challenges(ring_accs, tags)
    r = random_scalar()
    R = r * (G + beta * U)
    h = schnorr_challenge(ring_refs, out_accs, info, fee, mu, R, beta)
    z = (r + h * sum(a * i.sk for a, i in zip(alphas, inputs))) % ORDER

    # (2) coin balance: the leftover blinding between inputs and outputs
    ck_prime = (sum(i.ck for i in inputs) - sum(o.ck for o in outputs)) % ORDER

    # (3) commit to the witness, then prove
    bvecs = tuple(tuple(1 if k == i.ind else 0 for k in range(n)) for i in inputs)
    t = random_scalar()
    T = commit_T(z, ck_prime, bvecs, t)

    stmt = build_statement(ring_refs, ring_accs, tags, out_accs, info, fee, mu, R, T)
    assert stmt.h == h                     # Spend and Verify must agree
    wit = Witness(
        z=z,
        ck_prime=ck_prime,
        bvecs=bvecs,
        t=t,
        out_amounts=tuple(o.a for o in outputs),
        out_cks=tuple(o.ck for o in outputs),
    )
    proof = nizk.prove(stmt, wit)

    tx = Transaction(ring_refs=ring_refs, tags=tags, outputs=out_accs,
                     info=info, fee=fee, mu=mu)
    return tx, Signature(R=R, T=T, proof=proof)


# --- Verify ---------------------------------------------------------------

def verify(tx, sig, chain, nizk=sigma_ring):
    """True (valid), False (bad proof) or None (the paper's ⊥: rule broken)."""
    S, n = len(tx.tags), len(tx.ring_refs)
    if S < 1 or n < S:
        return None
    if not 2 <= len(tx.outputs) <= MAX_OUTPUTS:
        return None
    if not 0 <= tx.fee <= AMOUNT_MASK:
        return None
    if any(o.is_miner for o in tx.outputs):
        return None
    if len(set(tx.ring_refs)) != n:
        return None
    if len(set(tx.tags)) != S:
        return None
    if any(chain.is_spent(t) for t in tx.tags):
        return None

    ring_accs = []
    for ref in tx.ring_refs:
        found = chain.get(ref)
        if found is None:
            return None
        ring_accs.append(found[0])
    if sum(acc.is_miner for acc in ring_accs) > S - 1:
        return None

    stmt = build_statement(tx.ring_refs, ring_accs, tx.tags, tx.outputs,
                           tx.info, tx.fee, tx.mu, sig.R, sig.T)
    return bool(nizk.verify(stmt, sig.proof))


# --- Mine -----------------------------------------------------------------

def mine(txs, miner_mpk, reward):
    """Coinbase account worth reward + all fees, coin key 1, amount public."""
    total = reward + sum(tx.fee for tx in txs)
    _, acc, _ = otaccgen(miner_mpk, total, kappa=0)
    return acc
