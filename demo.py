"""
End-to-end demo of SuccinCT on the toy chain.

    python demo.py            # real proof (Σ-protocol + Bulletproofs range proof)
    python demo.py --stub     # placeholder proof: fast, but reveals the witness
    python demo.py --present  # for the live talk: --step --color --ring together

Presentation options (all off by default, so plain output stays as it was):
    --step    wait for Enter before each step
    --color   green [ok], red [nope], yellow public coinbase amounts
    --ring    print each attacked ring the way Eve sees it
    --explain under each step, the paper algorithm and function that ran and the
              values it produced (challenges, tags, proof size, Verify's checks)

Walks through: keygen -> mine -> spend coinbase with self-transfer -> verify
-> receive -> miner-privacy attack (fails against the self-transfer, succeeds
against a careless one) -> double spend rejected -> tampered tx rejected ->
inflation rejected. The attack uses Part C's Eve (attacks/_common.py); the
full experiments with success rates are in attacks/.
"""

import argparse
import dataclasses
import os
import random
import time

from attacks._common import Eve
from succinct import ct, serialize
from succinct.chain import Chain
from succinct.keyagreement import ka_key
from succinct.pedersen import commit
from succinct.ct import SpendInput, spend, make_outputs, pick_ring
from succinct.nizk import sigma_ring, stub
from succinct.stealth import sakgen, sakgen_miner, otaccgen, receive, view

RING_SIZE = 8


class Style:
    """Presentation switches, set once from the command line."""
    pause = False
    color = False
    ring = False
    explain = False
    steps_shown = 0


ANSI = {"green": "32", "red": "31", "yellow": "33", "bold": "1", "dim": "2", "cyan": "36"}


def paint(text, *names):
    if not Style.color:
        return text
    codes = ";".join(ANSI[n] for n in names)
    return f"\033[{codes}m{text}\033[0m"


def step(title):
    if Style.pause and Style.steps_shown:
        try:
            input(paint("\n   -- press Enter for the next step --", "dim"))
        except EOFError:                      # no keyboard (piped or recorded run)
            pass
    Style.steps_shown += 1
    print(paint(f"\n== {title}", "bold", "cyan"))


def explain(*lines):
    """Extra detail under a step, only with --explain."""
    if Style.explain:
        for line in lines:
            print(paint(f"   · {line}", "dim"))


def short(x):
    """First 12 hex digits of a scalar or point, enough to show it's a real value."""
    raw = f"{x:064x}" if isinstance(x, int) else x.to_bytes().hex()
    return raw[:12] + "..."


def ok(msg):
    print(f"   {paint('[ok]  ', 'green', 'bold')} {msg}")


def no(msg):
    print(f"   {paint('[nope]', 'red', 'bold')} {msg}")


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


def show_ring(eve, tx, need):
    """The ring as Eve sees it: ordinary amounts hidden, coinbase amounts public."""
    print(f"   {'ring member':<13}{'type':<11}amount, as Eve sees it")
    for ref in tx.ring_refs:
        if eve.is_miner(ref):
            amount = eve.amount(ref)
            verdict = (paint(f"<- equals {need:,}: match!", "red", "bold") if amount == need
                       else paint(f"<- not {need:,}: no match", "green"))
            print(f"   #{ref:<12}{paint('COINBASE'.ljust(11), 'yellow', 'bold')}"
                  f"{paint(f'{amount:,} public'.ljust(18), 'yellow')}{verdict}")
        else:
            print(f"   #{ref:<12}{'ordinary':<11}{paint('hidden', 'dim')}")


def explain_attack(eve, tx):
    """Print Eve's section 3.1 arithmetic for one transaction."""
    known, hidden = eve.known_outputs(tx)
    need = known + tx.fee
    coinbases = [(r, eve.amount(r)) for r in tx.ring_refs if eve.is_miner(r)]
    print(f"   Eve reads {known:,} sent to bob ({hidden} output(s) she can't open), fee {tx.fee}:"
          f" looks for a coinbase worth {need:,}")
    if Style.ring:
        show_ring(eve, tx, need)
    else:
        print("   coinbases in the ring: "
              + (", ".join(f"#{r} = {paint(f'{a:,}', 'yellow')}" for r, a in coinbases)
                 or "none"))


def main():
    parser = argparse.ArgumentParser(description="SuccinCT end-to-end demo")
    parser.add_argument("--stub", action="store_true",
                        help="use the placeholder proof (fast, NOT private)")
    parser.add_argument("--step", action="store_true", help="wait for Enter before each step")
    parser.add_argument("--color", action="store_true", help="colour the output")
    parser.add_argument("--ring", action="store_true",
                        help="show each attacked ring the way Eve sees it")
    parser.add_argument("--present", action="store_true",
                        help="presentation mode: --step --color --ring")
    parser.add_argument("--explain", action="store_true",
                        help="show which algorithm ran at each step and the values it produced")
    args = parser.parse_args()
    Style.pause = args.step or args.present
    Style.color = args.color or args.present
    Style.ring = args.ring or args.present
    Style.explain = args.explain
    if Style.color and os.name == "nt":
        os.system("")                         # turns on ANSI colours in the Windows console
    nizk = stub if args.stub else sigma_ring
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
    explain(f"SAKGen (stealth.sakgen): bob gets a secret polynomial f of degree q = {bob.msk.q}",
            f"his address: {len(bob.mpk.lpk)} public points F_i = theta_i*G, plus a view key vdk*G'",
            "the 40 decoys are other people's coins, each made with OTAccGen (stealth.otaccgen)")

    step("Mine a block")
    miner_key = Wallet("miner (coinbase key)", miner=True)   # fresh key per block
    cb = chain.mine_block(miner_key.mpk)
    cb_acc, _ = chain.get(cb)
    print(f"   coinbase output #{cb}, amount {paint(f'{cb_acc.ctxt:,}', 'yellow')}"
          f" (public, coin key 1)")
    explain("Mine (ct.mine, via chain.mine_block): coinbase = block reward + pending fees",
            "kappa = 0, coin key 1, amount stored in the clear, so anyone can check it:",
            f"  co == amount*V + 1*W ?  {commit(cb_acc.ctxt, 1) == cb_acc.co}")

    step("Spend the coinbase on its own")
    try:
        pick_ring(chain, [cb], RING_SIZE)
    except ValueError as e:
        no(f"refused: {e}")
    explain("pick_ring: S = 1 input, so the ring may hold at most S-1 = 0 coinbases",
            "Verify (ct.verify) enforces the same rule: a hand-built ring would return None")

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
    if Style.explain:
        ring_accs = [chain.get(r)[0] for r in tx.ring_refs]
        stmt = ct.build_statement(tx.ring_refs, ring_accs, tx.tags, tx.outputs, tx.info,
                                  tx.fee, tx.mu, sig.R, sig.T)
        S = len(tx.tags)
        cbs = sum(a.is_miner for a in ring_accs)
        explain(f"OTAccGen x{len(tx.outputs)} (ct.make_outputs): one shared tek; each output gets",
                "  a one-time key pk = prod F_i^(s^i), a commitment co = a*V + ck*W, an encrypted amount",
                f"pick_ring: S = {S} real inputs hidden in one ring of n = {len(tx.ring_refs)};"
                f" coinbases in it: {cbs} <= S-1 = {S - 1}",
                "Spend (ct.spend):",
                f"  alpha_1 = {short(stmt.alphas[0])}  alpha_2 = {short(stmt.alphas[1])}"
                "  MuSig weight per input",
                f"  beta    = {short(stmt.beta)}  ties key and tag: R = r*(G + beta*U)",
                f"  h       = {short(stmt.h)}  Schnorr challenge over the whole transaction",
                "  z = r + h * sum(alpha_j * sk_j)  one response for both inputs",
                f"  gamma   = {short(stmt.gamma)}  folds the balance check into Eq. 5",
                f"  tags (key images, sk*U): {', '.join(short(t) for t in tx.tags)}")
        if nizk is sigma_ring:
            explain(f"  proof {serialize.proof_size(sig.proof):,} bytes;"
                    f" whole transaction {serialize.transaction_size(tx, sig):,} bytes")
    result = verify(tx, sig, chain)
    t2 = time.perf_counter()
    (ok if result else no)(f"verify -> {result}   (spend {1000*(t1-t0):.0f} ms, verify {1000*(t2-t1):.0f} ms)")
    if Style.explain:
        checks = [
            (f"{len(tx.outputs)} outputs, between 2 and 16", "yes"),
            ("tags not already on chain",
             "no" if any(chain.is_spent(t) for t in tx.tags) else "yes"),
            ("ring references exist, no duplicates", "yes"),
            (f"coinbases in ring {cbs} <= S-1 = {S - 1}", "yes"),
            ("proof: Eq. 5, one-hot b, T, ranges", str(result)),
        ]
        explain("Verify (ct.verify) checks, in order:",
                *(f"  {label + ' ':.<40} {value}" for label, value in checks))
    if nizk is sigma_ring:
        f = sig.proof.f
        print(f"   proof: {len(f)} x {len(f[0])} masked responses f, all uniformly random,"
              f" so they look the same whichever position is real")
    new_refs = chain.submit(tx, sig)
    explain("chain.submit: the two tags join the spent list; the two new outputs join the chain")

    step("Bob receives")
    got = bob.open(chain, new_refs[0])
    ok(f"bob finds output #{new_refs[0]} worth {got[1]:,}")
    acc, info = chain.get(new_refs[0])
    explain(f"Receive (stealth.receive): s = H_n(vdk * tek, kappa) = {short(ka_key(bob.msk.vdk, info, acc.kappa))}",
            "  recompute pk = prod F_i^(s^i): it matches this output, so it is bob's",
            "  decrypt the amount and check co = a*V + ck*W; then sk = f(s), tag = sk*U",
            f"  address used {len(bob.msk.received)} of q = {bob.msk.q} times")
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
    print(f"   coinbase #{cb2}: {paint(f'{cb2_amount:,}', 'yellow')}"
          f" = reward {chain.reward:,} + fee {fee}")
    explain("the fee is not an output: Mine adds the pending fees to the next coinbase")

    step("Same attack, careless self-transfer: bob gets exactly coinbase - fee")
    _, acc, info = otaccgen(miner_wallet.mpk, 1_000, 1)
    savings2 = chain.add_output(acc, info)
    careless_tx, careless_sig, positions = build(
        chain, [(miner_key2, cb2), (miner_wallet, savings2)],
        [(bob.mpk, cb2_amount - fee), (miner_wallet.mpk, 1_000)], fee)
    chain.submit(careless_tx, careless_sig)
    print(f"   accepted by the chain: the rules and the proof can't tell a careless amount apart")
    explain("Verify can't see which output is change, so self-transfer is the spender's job:",
            "the paper's privacy model assumes honest miners call Spend this way")
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
    explain("Verify: the same coins give the same tags, already on the spent list,",
            "so a rule is broken and it returns None (the paper's bottom) before checking the proof")

    step("Tampering: bob builds a tx, someone edits the fee in transit")
    tx2, sig2, _ = build(chain, [(bob, new_refs[0])],
                         [(carol.mpk, 300_000), (bob.mpk, 199_990)], 10)
    edited = dataclasses.replace(tx2, fee=0)
    (no if verify(edited, sig2, chain) is False else ok)(
        f"edited fee: verify -> {verify(edited, sig2, chain)}")
    ok(f"original: verify -> {verify(tx2, sig2, chain)}")
    explain("the fee is part of the signed transaction prefix, so editing it changes h,",
            "z no longer satisfies Eq. 5, and the proof fails (False, not None)")

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
    explain("balance is checked inside Eq. 5 (the gamma part) and the range proof,",
            "so Verify catches it even when the wallet's own check is switched off")

    print(paint("\nDone.", "bold"))


if __name__ == "__main__":
    main()
