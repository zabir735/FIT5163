"""Attack 1 (paper section 3.1): miner spends coinbase to Bob while Eve holds Bob's view key.

Reports attack success rate over N trials, unmitigated vs. with the self-transfer mitigation.

Run from the repo root:  python -m attacks.miner_privacy --trials 30 --ring-sizes 8 16 32

PROVENANCE: first draft AI-assisted (Claude); the group must review, run and adapt it.
"""

from __future__ import annotations

import argparse
import random

from succinct.ct import SpendInput, make_outputs, pick_ring, spend, verify
from succinct.nizk import stub

from ._common import Eve, Wallet, World, get_nizk, observable_tx, pct

SCENARIOS = [
    ("legacy: no mitigation", "legacy"),
    ("self-transfer only", "self_only"),
    ("self-transfer + S-1 ring rule", "full"),
    ("careless self-transfer + S-1 rule", "careless"),
]


def run_legacy(world, size, rng, miner_decoys, self_transfer):
    """One input (the coinbase), no S-1 rule. Observable-only transaction."""
    cb_ref, cb_wallet, a_M = world.add_coinbase()
    miner_normal, bob = Wallet(), Wallet()
    fee = rng.randint(10, 200)
    spendable = a_M - fee
    x = rng.randint(spendable // 4, 3 * spendable // 4) if self_transfer else spendable
    y = spendable - x                                   # 0 when there is no self-transfer
    ring = world.legacy_ring([cb_ref], size, miner_decoys)
    _, _, _, tag = cb_wallet.open(world.chain, cb_ref)
    tx = observable_tx(ring, [tag], [(bob.mpk, x), (miner_normal.mpk, y)], fee)
    return tx, {cb_ref}, bob, None


def run_full(world, size, rng, careless, nizk=stub):
    """Real Spend and Verify: coinbase + an ordinary coin (S = 2), at most S-1 miners in ring."""
    cb_ref, cb_wallet, a_M = world.add_coinbase()
    miner_normal, bob = Wallet(), Wallet()
    a_o = rng.randint(1_000, 5_000)
    o_ref = world.add_coin(miner_normal, a_o)
    fee = rng.randint(10, 200)
    total = a_M + a_o
    # careless: send exactly (coinbase - fee) to Bob, and only the ordinary coin back to self.
    x = a_M - fee if careless else rng.randint(total // 4, 3 * total // 4)
    y = total - fee - x
    owners = [(cb_wallet, cb_ref), (miner_normal, o_ref)]
    ring, positions = pick_ring(world.chain, [r for _, r in owners], size, rng)
    inputs = []
    for (w, ref), pos in zip(owners, positions):
        ck, a, sk, tag = w.open(world.chain, ref)
        inputs.append(SpendInput(pos, ck, a, sk, tag))
    outputs, info = make_outputs([(bob.mpk, x), (miner_normal.mpk, y)])
    tx, sig = spend([(r, world.chain.get(r)[0]) for r in ring], inputs, outputs, info, fee, nizk=nizk)
    valid = verify(tx, sig, world.chain, nizk=nizk) is True
    return tx, {cb_ref, o_ref}, bob, valid


def one_trial(world, kind, size, rng, miner_decoys, nizk=stub):
    if kind in ("legacy", "self_only"):
        tx, real, bob, valid = run_legacy(world, size, rng, miner_decoys, kind == "self_only")
    else:
        tx, real, bob, valid = run_full(world, size, rng, kind == "careless", nizk)
    guess, how = Eve(world.chain, [bob.vk]).guess_spender(tx, rng)
    return guess in real, how == "match", valid, len(real)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--seed", type=int, default=5163)
    parser.add_argument("--trials", type=int, default=30)
    parser.add_argument("--ring-sizes", type=int, nargs="+", default=[8, 16, 32])
    parser.add_argument("--miner-decoys", type=int, default=3,
                        help="other miners' coinbases placed in legacy rings")
    parser.add_argument("--proof", choices=["stub", "real"], default="stub",
                        help="real = sigma_ring proof (slow); stub = witness in the clear")
    args = parser.parse_args(argv)
    nizk = get_nizk(args.proof)
    rng = random.Random(args.seed)     # seeds our choices; the keys themselves are not seeded

    print(f"Attack 1: miner privacy | trials={args.trials} seed={args.seed} proof={args.proof}")
    print("Eve holds Bob's view key; success = she names a real input of the transaction.\n")
    for size in args.ring_sizes:
        world = World(size, rng)
        print(f"ring size n = {size}")
        print(f"  {'scenario':<36}{'Eve success':>12}{'certain':>9}{'chance':>9}{'tx valid':>10}")
        for label, kind in SCENARIOS:
            wins = certain = valid_ok = valid_n = n_real = 0
            for _ in range(args.trials):
                hit, sure, valid, n_real = one_trial(world, kind, size, rng, args.miner_decoys, nizk)
                wins += hit
                certain += sure
                if valid is not None:
                    valid_n += 1
                    valid_ok += valid
            print(f"  {label:<36}{pct(wins, args.trials):>12}{pct(certain, args.trials):>9}"
                  f"{pct(n_real, size):>9}{pct(valid_ok, valid_n) if valid_n else '    -':>10}")
        print()
    print("certain = Eve found an exact coinbase match (output + fee = coinbase amount).")
    print("chance  = success of a blind guess (real inputs / ring size).")
    print("tx valid: legacy rows are observable-only (Spend refuses to build them).")


if __name__ == "__main__":
    main()
