"""
Wallet-side spending policies for miners (paper §3.1).

These are NOT consensus rules. Outputs are unlinkable, so no node can tell
whether an output goes back to the miner; the network can't enforce either
policy. A wallet has to apply them itself.

self_transfer        Solution 1: spend a coinbase, send some of it to Bob and a
                     non-zero amount back to the miner's own non-mining account.
multi_self_transfer  The P2Pool version: spend several small coinbases in ONE
                     transaction to at least two of the miner's own non-mining
                     accounts, so each account's balance stays hidden and the
                     fee is paid once instead of per coinbase.

Both need an ordinary (non-coinbase) input as well. That isn't in the paper's
description of the mechanisms; it falls out of its own S-1 rule (§3.2): with
S inputs the ring may hold at most S-1 miner accounts, so S coinbases alone are
always refused. pick_ring() enforces this and raises before anything is signed.
"""

import secrets

from .ct import SpendInput, spend, make_outputs, pick_ring
from .stealth import receive

RING_SIZE = 8


def _open_inputs(chain, owned, positions):
    """owned: [(ref, mpk, msk)] -> SpendInputs at the given ring positions."""
    inputs = []
    for (ref, mpk, msk), pos in zip(owned, positions):
        acc, info = chain.get(ref)
        got = receive(msk, mpk, acc, info)
        if got is None:
            raise ValueError(f"output #{ref} does not belong to the given key")
        ck, a, sk, tag = got
        inputs.append(SpendInput(pos, ck, a, sk, tag))
    return inputs


def _total(chain, owned):
    """Sum of the amounts in the coins we're about to spend."""
    total = 0
    for ref, mpk, msk in owned:
        got = receive(msk, mpk, *chain.get(ref))
        if got is None:
            raise ValueError(f"output #{ref} does not belong to the given key")
        total += got[1]
    return total


def _build(chain, owned, payments, fee, ring_size):
    refs = [ref for ref, _, _ in owned]
    ring, positions = pick_ring(chain, refs, ring_size)     # enforces S-1
    inputs = _open_inputs(chain, owned, positions)
    outputs, info = make_outputs(payments)
    return spend([(r, chain.get(r)[0]) for r in ring], inputs, outputs, info, fee)


def _split(total, parts):
    """total into `parts` random amounts, each at least 1."""
    if total < parts:
        raise ValueError(f"need at least {parts} to give every account a non-zero amount")
    cuts = sorted(secrets.SystemRandom().sample(range(1, total), parts - 1))
    edges = [0] + cuts + [total]
    return [b - a for a, b in zip(edges, edges[1:])]


def self_transfer(chain, coinbase, ordinary, recipient_mpk, amount, self_mpk,
                  fee, ring_size=RING_SIZE):
    """Pay `amount` to the recipient and the rest (non-zero) back to self_mpk.

    coinbase, ordinary: (ref, mpk, msk) for the miner's coinbase and one
    ordinary coin. Returns (tx, sig).
    """
    owned = [coinbase, ordinary]
    change = _total(chain, owned) - fee - amount
    if change <= 0:
        raise ValueError("self-transfer needs a non-zero amount back to the miner")
    return _build(chain, owned, [(recipient_mpk, amount), (self_mpk, change)],
                  fee, ring_size)


def multi_self_transfer(chain, coinbases, ordinary, self_mpks, fee,
                        ring_size=RING_SIZE):
    """Consolidate several coinbases (plus one ordinary coin) into >= 2 of the
    miner's own non-mining accounts, with random non-zero amounts.

    coinbases: [(ref, mpk, msk)], ordinary: (ref, mpk, msk) or None.
    Passing ordinary=None is refused by the S-1 rule (see module docstring).
    Returns (tx, sig, amounts sent to each self account).
    """
    if len(self_mpks) < 2:
        raise ValueError("multi-self-transfer needs at least two non-mining accounts")
    if any(m.is_miner for m in self_mpks):
        raise ValueError("self accounts must be non-mining addresses")

    owned = list(coinbases) + ([ordinary] if ordinary else [])
    refs = [ref for ref, _, _ in owned]
    # Check the ring rule first so the caller gets a clear error, not a
    # failure halfway through opening inputs.
    pick_ring(chain, refs, ring_size)

    amounts = _split(_total(chain, owned) - fee, len(self_mpks))
    tx, sig = _build(chain, owned, list(zip(self_mpks, amounts)), fee, ring_size)
    return tx, sig, amounts
