"""Attack 2 (paper section 3.2): coinbase decoys with output + fee > coinbase shrink the anonymity set.

Shows the at-most-(S-1) miner-accounts ring rule makes Verify reject non-compliant rings.

Run from the repo root:  python -m attacks.anonymity_reduction --trials 30 --ring-sizes 8 16 32

PROVENANCE: first draft AI-assisted (Claude); the group must review, run and adapt it.
"""

from __future__ import annotations

import argparse
import random
from dataclasses import replace

from succinct.ct import SpendInput, make_outputs, pick_ring, spend, verify
from succinct.nizk import stub

from ._common import REWARD, Eve, Wallet, World, get_nizk, observable_tx, pct


def run_size(size, trials, rng, miner_decoys, nizk=stub):
    world = World(size, rng)
    legacy_eff, reduced, big_spend = [], 0, 0
    mit_eff, valid, rejected = [], 0, 0
    for _ in range(trials):
        a_real = int(10 ** rng.uniform(3, 6.5))          # about 1,000 .. 3.2M, can exceed a block reward
        big_spend += a_real > REWARD
        sender, carol = Wallet(), Wallet()
        real_ref = world.add_coin(sender, a_real)
        fee = rng.randint(10, 200)
        x = rng.randint(1, a_real - fee - 1)
        payments = [(carol.mpk, x), (sender.mpk, a_real - fee - x)]
        eve = Eve(world.chain, [carol.vk, sender.vk])     # strongest case: she can read both outputs
        ck, a, sk, tag = sender.open(world.chain, real_ref)

        # legacy: coinbase decoys allowed in the ring
        legacy_ring = world.legacy_ring([real_ref], size, miner_decoys)
        left = len(eve.remaining(observable_tx(legacy_ring, [tag], payments, fee)))
        legacy_eff.append(left)
        reduced += left < size

        # mitigated: real Spend and Verify, ring built under the S-1 rule
        ring, pos = pick_ring(world.chain, [real_ref], size, rng)
        outputs, info = make_outputs(payments)
        tx, sig = spend([(r, world.chain.get(r)[0]) for r in ring],
                        [SpendInput(pos[0], ck, a, sk, tag)], outputs, info, fee, nizk=nizk)
        valid += verify(tx, sig, world.chain, nizk=nizk) is True
        mit_eff.append(len(eve.remaining(tx)))
        # the same transaction with a coinbase-stuffed ring swapped in must be rejected (None = rule broken)
        rejected += verify(replace(tx, ring_refs=legacy_ring), sig, world.chain, nizk=nizk) is None

    mean = lambda v: sum(v) / len(v)
    print(f"ring size n = {size}   ({pct(big_spend, trials).strip()} of trials spend more than a block reward)")
    print(f"  legacy    : effective anonymity set {mean(legacy_eff):6.2f} of {size}"
          f"   | trials where Eve removed >= 1 decoy: {pct(reduced, trials).strip()}")
    print(f"  mitigated : effective anonymity set {mean(mit_eff):6.2f} of {size}"
          f"   | honest tx valid: {pct(valid, trials).strip()}"
          f"   | coinbase-stuffed ring rejected by Verify: {pct(rejected, trials).strip()}\n")


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--seed", type=int, default=5163)
    parser.add_argument("--trials", type=int, default=30)
    parser.add_argument("--ring-sizes", type=int, nargs="+", default=[8, 16, 32])
    parser.add_argument("--miner-decoys", type=int, default=3,
                        help="coinbase decoys placed in legacy rings")
    parser.add_argument("--proof", choices=["stub", "real"], default="stub",
                        help="real = sigma_ring proof (slow); stub = witness in the clear")
    args = parser.parse_args(argv)
    nizk = get_nizk(args.proof)
    rng = random.Random(args.seed)     # seeds our choices; the keys themselves are not seeded

    print(f"Attack 2: anonymity reduction | trials={args.trials} seed={args.seed} proof={args.proof}")
    print("Eve reads all outputs; a coinbase smaller than outputs + fee cannot be the sole spender.\n")
    for size in args.ring_sizes:
        run_size(size, args.trials, rng, args.miner_decoys, nizk)


if __name__ == "__main__":
    main()
