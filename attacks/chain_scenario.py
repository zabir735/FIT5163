"""End-to-end miner-privacy scenario on the real Chain (mine, spend, submit, then attack).

Unlike miner_privacy.py, which builds its own toy world, everything here goes through
Chain.mine_block and Chain.submit, so Verify's rules are enforced by the chain itself.

Story per trial (the S-1 rule means a miner can never spend a coinbase alone, so the miner
first needs an ordinary coin):
  1. Alice pays the miner's ordinary wallet; the fee lands in the next coinbase.
  2. The miner mines a block (a public-amount coinbase, fresh miner key).
  3. Legacy attempt: the miner spends the coinbase alone, ring stuffed with other coinbases.
     The wallet refuses to build it, and a hand-made copy is rejected by the chain (⊥).
  4. Mitigated: coinbase + ordinary coin as two inputs, outputs to Bob and back to the miner.
     The chain accepts it. Eve (who holds Bob's view key) tries the section 3.1 match.
  5. Careless variant: the same, but the miner sends exactly coinbase - fee to Bob.
     The chain also accepts it, and Eve wins: the mitigation only works if the numbers differ.
  6. Attack 2 on chain: coinbases found in the rings of ordinary spends (should be 0).

Run from the repo root:  python3 -m attacks.chain_scenario --trials 20 --ring-sizes 8 16
Add --proof real for the sigma_ring proof (slow).

PROVENANCE: first draft AI-assisted (Claude); the author must review, run and adapt it.
"""

from __future__ import annotations

import argparse
import random

from succinct.chain import Chain
from succinct.ct import Signature, SpendInput, make_outputs, pick_ring, spend
from succinct.group import G
from succinct.stealth import otaccgen

from ._common import Eve, Wallet, get_nizk, observable_tx, pct


def send(chain, owners, payments, fee, size, rng):
    """Build a real transaction through pick_ring + spend and submit it to the chain."""
    refs = [ref for _, ref in owners]
    ring, positions = pick_ring(chain, refs, size, rng)
    inputs = []
    for (wallet, ref), pos in zip(owners, positions):
        ck, a, sk, tag = wallet.open(chain, ref)
        inputs.append(SpendInput(pos, ck, a, sk, tag))
    outputs, info = make_outputs(payments)
    tx, sig = spend([(r, chain.get(r)[0]) for r in ring], inputs, outputs, info, fee,
                    nizk=chain.nizk)
    return chain.submit(tx, sig), tx


def new_chain(size, nizk, rng):
    chain = Chain(nizk=nizk)
    ordinary = []
    for _ in range(size + 20):
        wallet = Wallet(q=1)
        ordinary.append(chain.add_output(*otaccgen(wallet.mpk, rng.randint(100, 10_000), 1)[1:]))
    coinbases = [chain.mine_block(Wallet(miner=True).mpk) for _ in range(4)]
    return chain, ordinary, coinbases


def run_trial(chain, ordinary, coinbases, size, rng, careless):
    alice, miner_ord, bob, miner_change = Wallet(), Wallet(), Wallet(), Wallet()
    a_ref = chain.add_output(*otaccgen(alice.mpk, 50_000, 1)[1:])
    fee1 = rng.randint(10, 200)
    (paid_ref, _), pay_tx = send(chain, [(alice, a_ref)],
                                 [(miner_ord.mpk, 20_000), (alice.mpk, 30_000 - fee1)],
                                 fee1, size, rng)

    miner = Wallet(miner=True)
    cb_ref = chain.mine_block(miner.mpk)
    cb_amount = chain.get(cb_ref)[0].ctxt
    fee2 = rng.randint(10, 200)
    total = cb_amount + 20_000

    # legacy: spend the coinbase alone
    refused = rejected = False
    try:
        pick_ring(chain, [cb_ref], size, rng)
    except ValueError:
        refused = True
    _, _, _, cb_tag = miner.open(chain, cb_ref)
    others = rng.sample([r for r in coinbases if r != cb_ref], 3)
    ring = [cb_ref] + others + rng.sample(ordinary, size - 4)
    rng.shuffle(ring)
    stuffed = observable_tx(ring, [cb_tag], [(bob.mpk, cb_amount - fee2), (miner_change.mpk, 0)], fee2)
    try:
        chain.submit(stuffed, Signature(R=G, T=G, proof=None))
    except ValueError as err:
        rejected = "rule broken" in str(err)

    # mitigated or careless, both through the chain
    x = cb_amount - fee2 if careless else rng.randint(total // 4, 3 * total // 4)
    y = total - fee2 - x
    (_, _), tx = send(chain, [(miner, cb_ref), (miner_ord, paid_ref)],
                      [(bob.mpk, x), (miner_change.mpk, y)], fee2, size, rng)
    guess, how = Eve(chain, [bob.vk]).guess_spender(tx, rng)
    coinbases.append(cb_ref)
    pay_ring_coinbases = sum(chain.get(r)[0].is_miner for r in pay_tx.ring_refs)
    return {"refused": refused, "rejected": rejected,
            "hit": guess in {cb_ref, paid_ref}, "certain": how == "match",
            "pay_ring_coinbases": pay_ring_coinbases}


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--seed", type=int, default=5163)
    parser.add_argument("--trials", type=int, default=20)
    parser.add_argument("--ring-sizes", type=int, nargs="+", default=[8, 16])
    parser.add_argument("--proof", choices=["stub", "real"], default="stub",
                        help="real = sigma_ring proof (slow); stub = witness in the clear")
    args = parser.parse_args(argv)
    nizk = get_nizk(args.proof)
    rng = random.Random(args.seed)

    print(f"End-to-end on the real Chain | trials={args.trials} seed={args.seed} proof={args.proof}")
    print("Every transaction goes through Chain.submit, so Verify's rules are enforced by the chain.\n")
    for size in args.ring_sizes:
        chain, ordinary, coinbases = new_chain(size, nizk, rng)
        rows = {mode: [run_trial(chain, ordinary, coinbases, size, rng, mode == "careless")
                       for _ in range(args.trials)] for mode in ("mitigated", "careless")}
        n = args.trials * 2
        both = rows["mitigated"] + rows["careless"]
        print(f"ring size n = {size}   (chain now holds {len(chain)} outputs)")
        print(f"  legacy attempt (coinbase spent alone): wallet refuses to build "
              f"{pct(sum(r['refused'] for r in both), n).strip()}, "
              f"hand-made copy rejected by chain (⊥) {pct(sum(r['rejected'] for r in both), n).strip()}")
        for mode, label in (("mitigated", "self-transfer + S-1 rule"), ("careless", "careless self-transfer")):
            r = rows[mode]
            print(f"  {label:<26} accepted by chain: 100%   Eve success "
                  f"{pct(sum(x['hit'] for x in r), args.trials).strip():>6}   "
                  f"certain {pct(sum(x['certain'] for x in r), args.trials).strip():>6}   "
                  f"chance {pct(2, size).strip()}")
        print(f"  attack 2 on chain: coinbases in rings of ordinary spends: "
              f"{sum(r['pay_ring_coinbases'] for r in both) / n:.2f} on average\n")


if __name__ == "__main__":
    main()
