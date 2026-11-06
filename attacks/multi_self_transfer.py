"""Multi-self-transfer (paper 3.1, the P2Pool mitigation) on the real Chain, using succinct.wallet.

Several small coinbases are consolidated in ONE transaction into at least two of the miner's own
non-mining accounts. Nothing is paid to an outsider in that transaction, so Eve's view key has no
output to read. Later, a payment to Bob is made from one of those accounts as an ordinary spend.

What this script checks, per ring size:
  1. wallet.multi_self_transfer (k coinbases + 1 ordinary coin -> 2 own accounts) is accepted by
     the chain, every account gets a non-zero amount, and Eve cannot match any coinbase.
  2. The later payment to Bob (an ordinary spend) has NO coinbase in its ring, so the section 3.1
     match has nothing to match against.
  3. wallet.self_transfer refuses a zero-change "careless" self-transfer before anything is signed.
     (chain_scenario.py shows the careless case slipping through when the wallet check is bypassed.)

Needs succinct/wallet.py (Part A). The wallet builds with the chain's own proof system, so
--proof stub (default, fast) or --proof real (sigma_ring) both work. Run from the repo root:
    python3 -m attacks.multi_self_transfer --trials 50 --ring-sizes 8 16

PROVENANCE: first draft AI-assisted (Claude); reviewed, run and tested by the group (tests/test_attacks.py).
"""

from __future__ import annotations

import argparse
import random
import sys

from succinct.stealth import otaccgen

from ._common import Eve, Wallet, get_nizk, pct
from .chain_scenario import new_chain, send


def run_trial(wallet, chain, size, rng, k):
    alice, miner_ord, bob = Wallet(), Wallet(), Wallet()
    a_ref = chain.add_output(*otaccgen(alice.mpk, 50_000, 1)[1:])
    fee1 = rng.randint(10, 200)
    (paid_ref, _), _ = send(chain, [(alice, a_ref)],
                            [(miner_ord.mpk, 20_000), (alice.mpk, 30_000 - fee1)],
                            fee1, size, rng)
    ordinary = (paid_ref, miner_ord.mpk, miner_ord.msk)

    miners = [Wallet(miner=True) for _ in range(k + 1)]
    cb_refs = [chain.mine_block(m.mpk) for m in miners]
    coinbases = [(r, m.mpk, m.msk) for r, m in zip(cb_refs, miners)]
    spare, used = coinbases[0], coinbases[1:]          # spare is only used for the refusal check

    # 3. careless self-transfer (zero change): the wallet must refuse
    total = chain.get(spare[0])[0].ctxt + 20_000
    fee2 = rng.randint(10, 200)
    try:
        wallet.self_transfer(chain, spare, ordinary, bob.mpk, total - fee2, Wallet().mpk, fee2, size)
        refused = False
    except ValueError:
        refused = True

    # 1. multi-self-transfer, through the chain
    selves = [Wallet(), Wallet()]
    tx, sig, amounts = wallet.multi_self_transfer(chain, used, ordinary, [s.mpk for s in selves],
                                                  fee2, ring_size=size)
    refs = chain.submit(tx, sig)
    real = {r for r, _, _ in used} | {paid_ref}
    guess, how = Eve(chain, []).guess_spender(tx, rng)

    # 2. later payment to Bob from one self account, an ordinary spend
    fee3 = rng.randint(10, 200)
    x = rng.randint(1, amounts[0] - fee3 - 1)
    (_, _), tx2 = send(chain, [(selves[0], refs[0])], [(bob.mpk, x), (Wallet().mpk, amounts[0] - fee3 - x)],
                       fee3, size, rng)
    guess2, _ = Eve(chain, [bob.vk]).guess_spender(tx2, rng)
    return {"refused": refused, "all_nonzero": min(amounts) >= 1,
            "hit": guess in real, "certain": how == "match",
            "cb_in_ring2": sum(chain.get(r)[0].is_miner for r in tx2.ring_refs),
            "hit2": guess2 == refs[0]}


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--seed", type=int, default=5163)
    parser.add_argument("--trials", type=int, default=20)
    parser.add_argument("--ring-sizes", type=int, nargs="+", default=[8, 16])
    parser.add_argument("--proof", choices=["stub", "real"], default="stub", help="proof system of the chain")
    parser.add_argument("--coinbases", type=int, default=3, help="coinbases consolidated per transaction")
    args = parser.parse_args(argv)
    try:
        from succinct import wallet
    except ImportError:
        sys.exit("This scenario needs succinct/wallet.py (Part A, coincurve branch), which this checkout lacks.")
    nizk = get_nizk(args.proof)
    rng = random.Random(args.seed)
    k = args.coinbases

    print(f"Multi-self-transfer on the real Chain | trials={args.trials} seed={args.seed} proof={args.proof}")
    print(f"{k} coinbases + 1 ordinary coin consolidated into 2 own accounts, then a payment to Bob.\n")
    for size in args.ring_sizes:
        chain, _, _ = new_chain(size, nizk, rng)
        rows = [run_trial(wallet, chain, size, rng, k) for _ in range(args.trials)]
        n = args.trials
        print(f"ring size n = {size}")
        print(f"  wallet.self_transfer with zero change refused: {pct(sum(r['refused'] for r in rows), n).strip()}")
        print(f"  multi-self-transfer accepted by chain: 100%   every account non-zero: "
              f"{pct(sum(r['all_nonzero'] for r in rows), n).strip()}")
        print(f"    Eve success {pct(sum(r['hit'] for r in rows), n).strip():>6}   "
              f"certain {pct(sum(r['certain'] for r in rows), n).strip():>6}   chance {pct(k + 1, size).strip()}")
        print(f"  later payment to Bob: coinbases in ring {sum(r['cb_in_ring2'] for r in rows) / n:.2f} on average   "
              f"Eve success {pct(sum(r['hit2'] for r in rows), n).strip():>6}   chance {pct(1, size).strip()}\n")


if __name__ == "__main__":
    main()
