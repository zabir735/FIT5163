"""
End-to-end demo of SuccinCT on the toy chain.

    python demo.py            # real proof (Σ-protocol + Bulletproofs range proof)
    python demo.py --stub     # placeholder proof: fast, but reveals the witness

Walks through: keygen -> mine -> spend coinbase with self-transfer -> verify
-> receive -> miner-privacy attack (fails against the self-transfer, succeeds
against a careless one) -> double spend rejected -> tampered tx rejected ->
inflation rejected. The attack uses Part C's Eve (attacks/_common.py); the
full experiments with success rates are in attacks/.
"""

import argparse
import dataclasses
import random
import time

from attacks._common import Eve
from succinct import ct
from succinct.chain import Chain
from succinct.ct import SpendInput, spend, make_outputs, pick_ring
from succinct.nizk import sigma_ring, stub
from succinct.stealth import sakgen, sakgen_miner, otaccgen, receive, view

RING_SIZE = 8


def step(title):
    print(f"\n== {title}")


def ok(msg):
    print(f"   [ok]   {msg}")


def no(msg):
    print(f"   [nope] {msg}")


class Wallet:
    def __init__(self, name, miner=False):
        self.name = name
        if miner:
            self.mpk, self.msk, self.vk = sakgen_miner()
        else:
            self.mpk, self.msk, self.vk = sakgen(q=20)

    def open(self, chain, ref):
        acc, info = chain.get(ref)
        return receive(self.msk, self.mpk, acc, info)


def verify(tx, sig, chain):
    """ct.verify with the proof system the chain was set up with."""
    return ct.verify(tx, sig, chain, nizk=chain.nizk)


def build(chain, owners_refs, payments, fee):
    """owners_refs: [(wallet, ref)] for the real inputs."""
    refs = [r for _, r in owners_refs]
    ring, positions = pick_ring(chain, refs, RING_SIZE)
    inputs = []
    for (w, ref), pos in zip(owners_refs, positions):
        ck, a, sk, tag = w.open(chain, ref)
        inputs.append(SpendInput(pos, ck, a, sk, tag))
    outputs, info = make_outputs(payments)
    tx, sig = spend([(r, chain.get(r)[0]) for r in ring], inputs, outputs, info, fee,
                    nizk=chain.nizk)
    return tx, sig, positions


def explain_attack(eve, tx):
    """Print Eve's section 3.1 arithmetic for one transaction."""
    known, hidden = eve.known_outputs(tx)
    need = known + tx.fee
    coinbases = [(r, eve.amount(r)) for r in tx.ring_refs if eve.is_miner(r)]
    print(f"   Eve reads {known:,} sent to bob ({hidden} output(s) she can't open), fee {tx.fee}:"
          f" looks for a coinbase worth {need:,}")
    print("   coinbases in the ring: "
          + (", ".join(f"#{r} = {a:,}" for r, a in coinbases) or "none"))


def main():
    parser = argparse.ArgumentParser(description="SuccinCT end-to-end demo")
    parser.add_argument("--stub", action="store_true",
                        help="use the placeholder proof (fast, NOT private)")
    nizk = stub if parser.parse_args().stub else sigma_ring
    chain = Chain(nizk=nizk)

    step("Setup")
    print(f"   proof system: {nizk.NAME}")
    for _ in range(40):                      # other people's coins, used as decoys
        mpk, _, _ = sakgen(1)
        _, acc, info = otaccgen(mpk, 1_000, 1)
        chain.add_output(acc, info)
    miner_wallet = Wallet("miner (normal wallet)")
    bob, carol = Wallet("bob"), Wallet("carol")
    _, acc, info = otaccgen(miner_wallet.mpk, 1_000, 1)
    savings = chain.add_output(acc, info)
    print(f"   chain has {len(chain)} outputs; the miner also owns an ordinary coin of 1,000")

    step("Mine a block")
    miner_key = Wallet("miner (coinbase key)", miner=True)   # fresh key per block
    cb = chain.mine_block(miner_key.mpk)
    cb_acc, _ = chain.get(cb)
    print(f"   coinbase output #{cb}, amount {cb_acc.ctxt:,} (public, coin key 1)")

    step("Spend the coinbase on its own")
    try:
        pick_ring(chain, [cb], RING_SIZE)
    except ValueError as e:
        no(f"refused: {e}")

    step("Spend coinbase + ordinary coin, with a self-transfer")
    total = cb_acc.ctxt + 1_000
    fee = 50
    to_bob = 500_000
    change = total - fee - to_bob
    t0 = time.perf_counter()
    tx, sig, positions = build(chain, [(miner_key, cb), (miner_wallet, savings)],
                               [(bob.mpk, to_bob), (miner_wallet.mpk, change)], fee)
    t1 = time.perf_counter()
    print(f"   ring: {list(tx.ring_refs)}   (real inputs at positions {positions}, not in the tx)")
    print(f"   outputs: {to_bob:,} to bob, {change:,} back to the miner's normal wallet, fee {fee}")
    result = verify(tx, sig, chain)
    t2 = time.perf_counter()
    (ok if result else no)(f"verify -> {result}   (spend {1000*(t1-t0):.0f} ms, verify {1000*(t2-t1):.0f} ms)")
    if nizk is sigma_ring:
        f = sig.proof.f
        print(f"   proof: {len(f)} x {len(f[0])} masked responses f, all uniformly random,"
              f" so they look the same whichever position is real")
    new_refs = chain.submit(tx, sig)

    step("Bob receives")
    got = bob.open(chain, new_refs[0])
    ok(f"bob finds output #{new_refs[0]} worth {got[1]:,}")
    acc, info = chain.get(new_refs[0])
    print(f"   anyone with bob's view key sees {view(bob.vk, acc, info):,} as well")
    print(f"   {to_bob:,} + fee {fee} = {to_bob + fee:,}, which matches no coinbase in the ring:")
    print(f"   the self-transfer output is hidden, so the coinbase can't be singled out")
    print(f"   carol tries the same output: {carol.open(chain, new_refs[0])}")

    step("Miner-privacy attack (paper section 3.1): Eve holds bob's view key")
    eve = Eve(chain, [bob.vk])
    explain_attack(eve, tx)
    guess, how = eve.guess_spender(tx, random.Random(5163))
    (no if how == "match" else ok)(
        f"protected: no coinbase matches, Eve can only guess among "
        f"{len(eve.remaining(tx))} of {len(tx.ring_refs)} ring members")

    step("Next block pays the fee to the miner")
    miner_key2 = Wallet("miner (coinbase key 2)", miner=True)
    cb2 = chain.mine_block(miner_key2.mpk)
    cb2_amount = chain.get(cb2)[0].ctxt
    print(f"   coinbase #{cb2}: {cb2_amount:,} = reward {chain.reward:,} + fee {fee}")

    step("Same attack, careless self-transfer: bob gets exactly coinbase - fee")
    _, acc, info = otaccgen(miner_wallet.mpk, 1_000, 1)
    savings2 = chain.add_output(acc, info)
    careless_tx, careless_sig, positions = build(
        chain, [(miner_key2, cb2), (miner_wallet, savings2)],
        [(bob.mpk, cb2_amount - fee), (miner_wallet.mpk, 1_000)], fee)
    chain.submit(careless_tx, careless_sig)
    print(f"   accepted by the chain: the rules and the proof can't tell a careless amount apart")
    explain_attack(eve, careless_tx)
    guess, how = eve.guess_spender(careless_tx, random.Random(5163))
    real = careless_tx.ring_refs[positions[0]]
    (no if how == "match" and guess == real else ok)(
        f"unprotected: Eve names output #{guess} as the spender with certainty"
        f" ({'correct' if guess == real else 'wrong'}): the miner's block is linked to bob")
    print(f"   the fix: the self-transfer must change the visible amount, as in the first spend")

    step("Double spend: submit the same transaction again")
    print(f"   verify -> {verify(tx, sig, chain)}  (None = rule broken: tag already on chain)")
    try:
        chain.submit(tx, sig)
    except ValueError as e:
        no(str(e))

    step("Tampering: bob builds a tx, someone edits the fee in transit")
    tx2, sig2, _ = build(chain, [(bob, new_refs[0])],
                         [(carol.mpk, 300_000), (bob.mpk, 199_990)], 10)
    edited = dataclasses.replace(tx2, fee=0)
    (no if verify(edited, sig2, chain) is False else ok)(
        f"edited fee: verify -> {verify(edited, sig2, chain)}")
    ok(f"original: verify -> {verify(tx2, sig2, chain)}")

    step("Inflation: bob tries to send more than he has")
    try:
        build(chain, [(bob, new_refs[0])], [(carol.mpk, 900_000), (bob.mpk, 0)], 10)
    except ValueError as e:
        no(f"Spend refuses: {e}")
    original = ct._check_balance
    ct._check_balance = lambda *a: None          # pretend bob patched his wallet
    try:
        tx3, sig3, _ = build(chain, [(bob, new_refs[0])],
                             [(carol.mpk, 900_000), (bob.mpk, 0)], 10)
        no(f"patched wallet signs it anyway, but verify -> {verify(tx3, sig3, chain)}")
    finally:
        ct._check_balance = original

    print("\nDone.")


if __name__ == "__main__":
    main()
