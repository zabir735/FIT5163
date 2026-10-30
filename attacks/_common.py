"""Shared pieces for the attack simulations (Part C). Local toy chain only.

PROVENANCE: first draft AI-assisted (Claude). The group must read, run and adapt it
before submission, and disclose this in the README.

Who Eve is
----------
Eve is the paper's passive observer (section 3). She sees the public chain (every
coinbase amount is in the clear), each transaction's ring and fee, and she may hold
the view keys of some recipients, which lets her read those outputs' amounts.
She only uses arithmetic from section 3. No signature breaking, no ring statistics:

  * match:     a coinbase in the ring whose amount equals (outputs she can read) + fee
  * exclusion: with ONE input, a coinbase smaller than (outputs she can read) + fee
               cannot be the spender (section 3.2)

A stronger Eve (ring-membership statistics, timing) is outside the paper's model.
Say so under threats to validity in the report.
"""

from __future__ import annotations

from succinct.chain import Chain
from succinct.ct import Transaction, make_outputs
from succinct.stealth import otaccgen, receive, sakgen, sakgen_miner, view

REWARD = 600_000


class Wallet:
    """A user: master keys plus the view key they could hand to an auditor."""

    def __init__(self, miner: bool = False, q: int = 3):
        if miner:
            self.mpk, self.msk, self.vk = sakgen_miner()   # vk is None for a miner
        else:
            self.mpk, self.msk, self.vk = sakgen(q=q)

    def open(self, chain, ref):
        """(ck, amount, sk, tag) for an output this wallet owns, else None."""
        acc, info = chain.get(ref)
        return receive(self.msk, self.mpk, acc, info)


class World:
    """A toy chain with ordinary decoy coins and a pool of other miners' coinbases."""

    def __init__(self, ring_size: int, rng, extra_decoys: int = 20, miner_pool: int = 8):
        self.rng = rng
        self.chain = Chain()
        self.ordinary = []                       # refs of other people's ordinary coins
        for _ in range(ring_size + extra_decoys):
            mpk, _, _ = sakgen(1)
            _, acc, info = otaccgen(mpk, rng.randint(100, 10_000), 1)
            self.ordinary.append(self.chain.add_output(acc, info))
        self.miner_pool = [self.add_coinbase()[0] for _ in range(miner_pool)]

    def add_coinbase(self):
        """A coinbase = reward + that block's fees. Returns (ref, miner wallet, amount)."""
        wallet = Wallet(miner=True)
        amount = REWARD + self.rng.randint(0, 5_000)
        _, acc, info = otaccgen(wallet.mpk, amount, 0)
        return self.chain.add_output(acc, info), wallet, amount

    def add_coin(self, wallet: Wallet, amount: int):
        """An ordinary (hidden-amount) coin owned by wallet."""
        _, acc, info = otaccgen(wallet.mpk, amount, 1)
        return self.chain.add_output(acc, info)

    def legacy_ring(self, real_refs, size: int, miner_decoys: int):
        """A ring built with NO at-most-(S-1)-miners rule: some coinbase decoys, rest uniform."""
        pool = [r for r in self.miner_pool if r not in real_refs]
        decoys = self.rng.sample(pool, miner_decoys)
        decoys += self.rng.sample(self.ordinary, size - len(real_refs) - miner_decoys)
        ring = list(real_refs) + decoys
        self.rng.shuffle(ring)
        return tuple(ring)


def observable_tx(ring, tags, payments, fee: int) -> Transaction:
    """What Eve sees of a transaction: ring, tags, outputs, fee. NO signature.

    Used for the 'legacy' worlds, where the repo's Spend/Verify (correctly) refuse to
    produce the transaction. Eve never reads the signature, so nothing is lost.
    """
    outputs, info = make_outputs(payments)
    return Transaction(ring_refs=tuple(ring), tags=tuple(tags),
                       outputs=tuple(o.acc for o in outputs), info=info, fee=fee)


class Eve:
    def __init__(self, chain, view_keys):
        self.chain = chain
        self.view_keys = [vk for vk in view_keys if vk is not None]

    def is_miner(self, ref) -> bool:
        return self.chain.get(ref)[0].is_miner

    def amount(self, ref) -> int:
        return self.chain.get(ref)[0].ctxt        # public for coinbase accounts

    def known_outputs(self, tx):
        """(sum of output amounts Eve can read, number of outputs she cannot read)."""
        known, hidden = 0, 0
        for acc in tx.outputs:
            seen = [view(vk, acc, tx.info) for vk in self.view_keys]
            seen = [a for a in seen if a is not None]
            if seen:
                known += seen[0]
            else:
                hidden += 1
        return known, hidden

    def remaining(self, tx):
        """Ring members Eve cannot rule out (the effective anonymity set)."""
        known, _ = self.known_outputs(tx)
        need = known + tx.fee
        ring = list(tx.ring_refs)
        if len(tx.tags) == 1:                     # one input must cover outputs + fee
            ring = [r for r in ring if not self.is_miner(r) or self.amount(r) >= need]
        return ring

    def guess_spender(self, tx, rng):
        """(guessed ref, 'match' | 'guess')."""
        known, _ = self.known_outputs(tx)
        need = known + tx.fee
        matches = [r for r in tx.ring_refs
                   if self.is_miner(r) and self.amount(r) == need]
        if len(matches) == 1:
            return matches[0], "match"
        return rng.choice(self.remaining(tx)), "guess"


def get_nizk(name: str):
    """'stub' (witness in the clear, fast) or 'real' (sigma_ring, signer hidden)."""
    from succinct.nizk import sigma_ring, stub
    return sigma_ring if name == "real" else stub


def pct(num: int, den: int) -> str:
    return f"{100 * num / den:5.1f}%" if den else "  n/a"
