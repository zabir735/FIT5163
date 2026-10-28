"""
Minimal toy chain: an append-only list of outputs, the set of spent tags, and
the fees waiting for the next coinbase. submit() runs Verify and refuses
anything that isn't True, so every rule in ct.verify is enforced by the chain.

Left out on purpose (none of the paper's attacks or mitigations depend on
them; the README's Part C section says the same):
  * coinbase maturity: a coinbase can be spent in the next transaction
  * block structure: mine_block only pays reward + pending fees
  * decoy selection: pick_ring is uniform over all outputs, where Monero uses
    an age-based gamma distribution (paper Appendix F)
  * networking, forks and a mempool

ct.verify() only needs two things from a chain, so keep these working:

    chain.get(ref)      -> (Account, info) or None
    chain.is_spent(tag) -> bool

pick_ring() also uses len(chain).
"""

from . import ct
from .nizk import sigma_ring


class Chain:
    def __init__(self, nizk=sigma_ring, reward=600_000):
        self.outputs = []          # list of (Account, info)
        self.spent = set()         # tags already used
        self.pending_fees = []     # txs since the last block
        self.nizk = nizk
        self.reward = reward

    def __len__(self):
        return len(self.outputs)

    def get(self, ref):
        if isinstance(ref, int) and 0 <= ref < len(self.outputs):
            return self.outputs[ref]
        return None

    def is_spent(self, tag):
        return tag in self.spent

    def add_output(self, acc, info):
        """Genesis-style allocation. Real outputs come from submit/mine_block."""
        self.outputs.append((acc, info))
        return len(self.outputs) - 1

    def submit(self, tx, sig):
        """Verify and apply. Returns the refs of the new outputs, or raises."""
        result = ct.verify(tx, sig, self, nizk=self.nizk)
        if result is not True:
            raise ValueError("rejected: " + ("rule broken (⊥)" if result is None else "invalid proof"))
        self.spent.update(tx.tags)
        self.pending_fees.append(tx)
        return [self.add_output(acc, tx.info) for acc in tx.outputs]

    def mine_block(self, miner_mpk):
        """Pay reward + pending fees to the miner. Returns the coinbase ref."""
        acc = ct.mine(self.pending_fees, miner_mpk, self.reward)
        self.pending_fees = []
        return self.add_output(acc, None)
