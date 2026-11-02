// Command demo is the Go version of demo.py: the same 13 steps, the same
// small amounts and the same options.
//
//	go run ./cmd/demo            # real proof (Σ-protocol + Bulletproofs range proof)
//	go run ./cmd/demo -stub      # placeholder proof: fast, but reveals the witness
//	go run ./cmd/demo -present   # for a live talk: -step -color -ring together
//	go run ./cmd/demo -explain   # the algorithm and values behind each step
package main

import (
	"bufio"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"succinctgo/attacks"
	"succinctgo/curve"
	"succinctgo/nizk"
	"succinctgo/succinct"
)

const ringSize = 8

var (
	pause, color, ring, explainOn bool
	stepsShown                    int
	stdin                         = bufio.NewReader(os.Stdin)
)

var ansi = map[string]string{"green": "32", "red": "31", "yellow": "33", "bold": "1", "dim": "2", "cyan": "36"}

func paint(text string, names ...string) string {
	if !color {
		return text
	}
	var codes []string
	for _, n := range names {
		codes = append(codes, ansi[n])
	}
	return "\033[" + strings.Join(codes, ";") + "m" + text + "\033[0m"
}

func step(title string) {
	if pause && stepsShown > 0 {
		fmt.Print(paint("\n   -- press Enter for the next step --", "dim"))
		stdin.ReadString('\n')
	}
	stepsShown++
	fmt.Println(paint("\n== "+title, "bold", "cyan"))
}

func explain(lines ...string) {
	if explainOn {
		for _, l := range lines {
			fmt.Println(paint("   · "+l, "dim"))
		}
	}
}

func ok(msg string) { fmt.Printf("   %s %s\n", paint("[ok]  ", "green", "bold"), msg) }
func no(msg string) { fmt.Printf("   %s %s\n", paint("[nope]", "red", "bold"), msg) }

// dots pads a label with dots to 40 characters, like demo.py's checklist.
func dots(label, value string) string {
	label += " "
	if n := 40 - len([]rune(label)); n > 0 {
		label += strings.Repeat(".", n)
	}
	return "  " + label + " " + value
}

func short(b []byte) string        { return hex.EncodeToString(b)[:12] + "..." }
func shortS(s curve.Scalar) string { b := s.Bytes(); return short(b[:]) }

// comma prints 1234567 as 1,234,567.
func comma(v uint64) string {
	s := fmt.Sprint(v)
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}

type wallet struct {
	*attacks.Wallet
	name string
}

func newWallet(name string, miner bool) wallet {
	if miner {
		return wallet{attacks.NewMiner(), name}
	}
	return wallet{attacks.NewWallet(20), name}
}

func build(c *succinct.Chain, owners []wallet, refs []uint32, pays []succinct.Payment, fee uint64) (*succinct.Transaction, *succinct.Signature, []int, error) {
	owned := make([]succinct.Owned, len(owners))
	for k, w := range owners {
		owned[k] = w.Owned(refs[k])
	}
	return succinct.Build(c, owned, pays, fee, ringSize)
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func showRing(eve *attacks.Eve, tx *succinct.Transaction, need uint64, test string) {
	fmt.Printf("   %-13s%-11samount, as Eve sees it\n", "ring member", "type")
	for _, ref := range tx.RingRefs {
		if eve.IsMiner(ref) {
			amount := eve.Amount(ref)
			var verdict string
			if test == "cover" {
				if amount < need {
					verdict = paint(fmt.Sprintf("<- less than %s: ruled out", comma(need)), "red", "bold")
				} else {
					verdict = paint(fmt.Sprintf("<- could have paid %s", comma(need)), "green")
				}
			} else if amount == need {
				verdict = paint(fmt.Sprintf("<- equals %s: match!", comma(need)), "red", "bold")
			} else {
				verdict = paint(fmt.Sprintf("<- not %s: no match", comma(need)), "green")
			}
			fmt.Printf("   #%-12d%s%s%s\n", ref, paint(fmt.Sprintf("%-11s", "COINBASE"), "yellow", "bold"),
				paint(fmt.Sprintf("%-18s", comma(amount)+" public"), "yellow"), verdict)
		} else {
			fmt.Printf("   #%-12d%-11s%s\n", ref, "ordinary", paint("hidden", "dim"))
		}
	}
}

func explainAttack(eve *attacks.Eve, tx *succinct.Transaction) {
	known, hidden := eve.KnownOutputs(tx)
	need := known + tx.Fee
	fmt.Printf("   Eve reads %s sent to bob (%d output(s) she can't open), fee %d: looks for a coinbase worth %s\n",
		comma(known), hidden, tx.Fee, comma(need))
	if ring {
		showRing(eve, tx, need, "match")
		return
	}
	var parts []string
	for _, r := range tx.RingRefs {
		if eve.IsMiner(r) {
			parts = append(parts, fmt.Sprintf("#%d = %s", r, paint(comma(eve.Amount(r)), "yellow")))
		}
	}
	if len(parts) == 0 {
		parts = []string{"none"}
	}
	fmt.Println("   coinbases in the ring: " + strings.Join(parts, ", "))
}

func main() {
	stub := flag.Bool("stub", false, "use the placeholder proof (fast, NOT private)")
	flag.BoolVar(&pause, "step", false, "wait for Enter before each step")
	flag.BoolVar(&color, "color", false, "colour the output")
	flag.BoolVar(&ring, "ring", false, "show each attacked ring the way Eve sees it")
	present := flag.Bool("present", false, "presentation mode: -step -color -ring")
	flag.BoolVar(&explainOn, "explain", false, "show which algorithm ran at each step and the values it produced")
	flag.Parse()
	if *present {
		pause, color, ring = true, true, true
	}
	var sys nizk.System = nizk.Sigma{}
	if *stub {
		sys = nizk.Stub{}
	}
	chain := succinct.NewChain(sys, 600) // small round numbers, easy to read aloud
	rng := succinct.NewSeededRng(5163)

	step("Setup")
	fmt.Printf("   proof system: %s (Go)\n", sys.Name())
	for i := 0; i < 40; i++ { // other people's coins, used as decoys
		mpk, _, _ := succinct.SAKGen(1)
		_, acc, info := succinct.OTAccGen(mpk, 100, 1, nil)
		chain.AddOutput(acc, info)
	}
	minerWallet := newWallet("miner (normal wallet)", false)
	bob, carol := newWallet("bob", false), newWallet("carol", false)
	_, acc, info := succinct.OTAccGen(minerWallet.Mpk, 100, 1, nil)
	savings := chain.AddOutput(acc, info)
	fmt.Printf("   chain has %d outputs; the miner also owns an ordinary coin of 100\n", chain.Len())
	explain(fmt.Sprintf("SAKGen (succinct.SAKGen): bob gets a secret polynomial f of degree q = %d", bob.Msk.Q),
		fmt.Sprintf("his address: %d public points F_i = theta_i*G, plus a view key vdk*G'", len(bob.Mpk.Lpk)),
		"the 40 decoys are other people's coins, each made with OTAccGen (succinct.OTAccGen)")

	step("Mine a block")
	minerKey := newWallet("miner (coinbase key)", true) // fresh key per block
	cb := chain.MineBlock(minerKey.Mpk)
	cbAcc, _, _ := chain.Get(cb)
	fmt.Printf("   coinbase output #%d, amount %s (public, coin key 1)\n", cb, paint(comma(cbAcc.Ctxt), "yellow"))
	explain("Mine (succinct.Mine, via chain.MineBlock): coinbase = block reward + pending fees",
		"kappa = 0, coin key 1, amount stored in the clear, so anyone can check it:",
		fmt.Sprintf("  co == amount*V + 1*W ?  %v", curve.Commit(curve.S(cbAcc.Ctxt), curve.S(1)).Equal(cbAcc.Co)))

	step("Spend the coinbase on its own")
	if _, _, err := succinct.PickRing(chain, []uint32{cb}, ringSize, nil); err != nil {
		no("refused: " + err.Error())
	}
	explain("PickRing: S = 1 input, so the ring may hold at most S-1 = 0 coinbases",
		"Verify enforces the same rule: a hand-built ring would return None")

	step("Spend coinbase + ordinary coin, with a self-transfer")
	total := cbAcc.Ctxt + 100
	var fee, toBob uint64 = 5, 500
	change := total - fee - toBob
	t0 := time.Now()
	tx, sig, positions, err := build(chain, []wallet{minerKey, minerWallet}, []uint32{cb, savings},
		[]succinct.Payment{{To: bob.Mpk, Amount: toBob}, {To: minerWallet.Mpk, Amount: change}}, fee)
	if err != nil {
		panic(err)
	}
	t1 := time.Now()
	fmt.Printf("   ring: %v   (real inputs at positions %v, not in the tx)\n", tx.RingRefs, positions)
	fmt.Printf("   outputs: %s to bob, %s back to the miner's normal wallet, fee %d\n", comma(toBob), comma(change), fee)
	nS, cbs := len(tx.Tags), 0
	if explainOn {
		var accs []succinct.Account
		for _, r := range tx.RingRefs {
			a, _, _ := chain.Get(r)
			accs = append(accs, a)
			if a.IsMiner() {
				cbs++
			}
		}
		st := must(succinct.BuildStatement(tx.RingRefs, accs, tx.Tags, tx.Outputs, tx.Info, tx.Fee, tx.Mu, sig.R, sig.T))
		explain(fmt.Sprintf("OTAccGen x%d (succinct.MakeOutputs): one shared tek; each output gets", len(tx.Outputs)),
			"  a one-time key pk = prod F_i^(s^i), a commitment co = a*V + ck*W, an encrypted amount",
			fmt.Sprintf("PickRing: S = %d real inputs hidden in one ring of n = %d; coinbases in it: %d <= S-1 = %d", nS, len(tx.RingRefs), cbs, nS-1),
			"Spend (succinct.Spend):",
			fmt.Sprintf("  alpha_1 = %s  alpha_2 = %s  MuSig weight per input", shortS(st.Alphas[0]), shortS(st.Alphas[1])),
			fmt.Sprintf("  beta    = %s  ties key and tag: R = r*(G + beta*U)", shortS(st.Beta)),
			fmt.Sprintf("  h       = %s  Schnorr challenge over the whole transaction", shortS(st.H)),
			"  z = r + h * sum(alpha_j * sk_j)  one response for both inputs",
			fmt.Sprintf("  gamma   = %s  folds the balance check into Eq. 5", shortS(st.Gamma)),
			fmt.Sprintf("  tags (key images, sk*U): %s, %s", short(tx.Tags[0].Bytes()), short(tx.Tags[1].Bytes())))
		if _, real := sys.(nizk.Sigma); real {
			explain(fmt.Sprintf("  proof %s bytes; whole transaction %s bytes",
				comma(uint64(succinct.ProofSize(sig.Proof))), comma(uint64(succinct.TransactionSize(tx, sig)))))
		}
	}
	result := chain.Verify(tx, sig)
	t2 := time.Now()
	line := fmt.Sprintf("verify -> %v   (spend %d ms, verify %d ms)", result, t1.Sub(t0).Milliseconds(), t2.Sub(t1).Milliseconds())
	if result == succinct.Valid {
		ok(line)
	} else {
		no(line)
	}
	explain("Verify (succinct.Verify) checks, in order:",
		dots(fmt.Sprintf("%d outputs, between 2 and 16", len(tx.Outputs)), "yes"),
		dots("tags not already on chain", "yes"),
		dots("ring references exist, no duplicates", "yes"),
		dots(fmt.Sprintf("coinbases in ring %d <= S-1 = %d", cbs, nS-1), "yes"),
		dots("proof: Eq. 5, one-hot b, T, ranges", result.String()))
	if rp, real := sig.Proof.(*nizk.RingProof); real {
		fmt.Printf("   proof: %d x %d masked responses f, all uniformly random, so they look the same whichever position is real\n",
			len(rp.F), len(rp.F[0]))
	}
	newRefs := must(chain.Submit(tx, sig))
	explain("chain.Submit: the two tags join the spent list; the two new outputs join the chain")

	step("Bob receives")
	got := bob.Open(chain, newRefs[0])
	ok(fmt.Sprintf("bob finds output #%d worth %s", newRefs[0], comma(got.A)))
	acc, infoP, _ := chain.Get(newRefs[0])
	explain(fmt.Sprintf("Receive (succinct.Receive): s = H_n(vdk * tek, kappa) = %s", shortS(curve.KaKey(bob.Msk.Vdk, *infoP, acc.Kappa))),
		"  recompute pk = prod F_i^(s^i): it matches this output, so it is bob's",
		"  decrypt the amount and check co = a*V + ck*W; then sk = f(s), tag = sk*U",
		fmt.Sprintf("  address used %d of q = %d times", bob.Msk.Received(), bob.Msk.Q))
	seen, _ := succinct.View(bob.Vk, acc, infoP)
	fmt.Printf("   anyone with bob's view key sees %s as well\n", comma(seen))
	fmt.Printf("   %s + fee %d = %s, which matches no coinbase in the ring:\n", comma(toBob), fee, comma(toBob+fee))
	fmt.Println("   the self-transfer output is hidden, so the coinbase can't be singled out")
	_, carolOK := succinct.Receive(carol.Msk, carol.Mpk, acc, infoP)
	carolSays := "None"
	if carolOK {
		carolSays = "found it (should not happen)"
	}
	fmt.Printf("   carol tries the same output: %s\n", carolSays)

	step("Miner-privacy attack (paper section 3.1): Eve holds bob's view key")
	eve := attacks.NewEve(chain, bob.Vk)
	explainAttack(eve, tx)
	_, match := eve.GuessSpender(tx, rng)
	msg := fmt.Sprintf("protected: no coinbase matches, Eve can only guess among %d of %d ring members",
		len(eve.Remaining(tx)), len(tx.RingRefs))
	if match {
		no(msg)
	} else {
		ok(msg)
	}

	step("Next block pays the fee to the miner")
	minerKey2 := newWallet("miner (coinbase key 2)", true)
	cb2 := chain.MineBlock(minerKey2.Mpk)
	cb2Acc, _, _ := chain.Get(cb2)
	fmt.Printf("   coinbase #%d: %s = reward %s + fee %d\n", cb2, paint(comma(cb2Acc.Ctxt), "yellow"), comma(chain.Reward), fee)
	explain("the fee is not an output: Mine adds the pending fees to the next coinbase")

	step("Same attack, careless self-transfer: bob gets exactly coinbase - fee")
	_, acc, info = succinct.OTAccGen(minerWallet.Mpk, 100, 1, nil)
	savings2 := chain.AddOutput(acc, info)
	ctx, csig, cpos, err := build(chain, []wallet{minerKey2, minerWallet}, []uint32{cb2, savings2},
		[]succinct.Payment{{To: bob.Mpk, Amount: cb2Acc.Ctxt - fee}, {To: minerWallet.Mpk, Amount: 100}}, fee)
	if err != nil {
		panic(err)
	}
	must(chain.Submit(ctx, csig))
	fmt.Println("   accepted by the chain: the rules and the proof can't tell a careless amount apart")
	explain("Verify can't see which output is change, so self-transfer is the spender's job:",
		"the paper's privacy model assumes honest miners call Spend this way")
	explainAttack(eve, ctx)
	guess, match := eve.GuessSpender(ctx, rng)
	real := ctx.RingRefs[cpos[0]]
	verdict := "wrong"
	if guess == real {
		verdict = "correct"
	}
	msg = fmt.Sprintf("unprotected: Eve names output #%d as the spender with certainty (%s): the miner's block is linked to bob", guess, verdict)
	if match && guess == real {
		no(msg)
	} else {
		ok(msg)
	}
	fmt.Println("   the fix: the self-transfer must change the visible amount, as in the first spend")

	step("Wallet policy (succinct.SelfTransfer): refuses a zero-change self-transfer, consolidates safely")
	mk3, mk4 := newWallet("miner (coinbase key 3)", true), newWallet("miner (coinbase key 4)", true)
	cb3, cb4 := chain.MineBlock(mk3.Mpk), chain.MineBlock(mk4.Mpk)
	_, acc, info = succinct.OTAccGen(minerWallet.Mpk, 100, 1, nil)
	savings3 := chain.AddOutput(acc, info)
	own := minerWallet.Owned(savings3)
	cb3Acc, _, _ := chain.Get(cb3)
	if _, _, err := succinct.SelfTransfer(chain, mk3.Owned(cb3), own, bob.Mpk, cb3Acc.Ctxt+100-fee, minerWallet.Mpk, fee, ringSize); err != nil {
		no("wallet refused the zero-change self-transfer: " + err.Error())
	}
	accA, accB := newWallet("miner account A", false), newWallet("miner account B", false)
	txm, sigm, amounts, err := succinct.MultiSelfTransfer(chain, []succinct.Owned{mk3.Owned(cb3), mk4.Owned(cb4)}, &own,
		[]*succinct.MasterPublicKey{accA.Mpk, accB.Mpk}, fee, ringSize)
	if err != nil {
		panic(err)
	}
	must(chain.Submit(txm, sigm))
	ok(fmt.Sprintf("multi-self-transfer accepted: 2 coinbases + 1 ordinary coin -> 2 own accounts (%s and %s), nothing paid to an outsider",
		comma(amounts[0]), comma(amounts[1])))
	explain("these are wallet policies, not consensus rules: no node can tell an output goes back to",
		"the miner, so the wallet has to apply them itself (succinct/wallet.go)",
		"a coinbase-only multi-self-transfer is refused by the S-1 rule, so one ordinary coin is added")

	step("Anonymity-reduction attack (paper section 3.2): Eve holds carol's view key")
	alice := newWallet("alice", false)
	_, acc, info = succinct.OTAccGen(alice.Mpk, 700, 1, nil)
	aliceCoin := chain.AddOutput(acc, info)
	txa, siga, posa, err := build(chain, []wallet{alice}, []uint32{aliceCoin},
		[]succinct.Payment{{To: carol.Mpk, Amount: 650}, {To: alice.Mpk, Amount: 45}}, fee)
	if err != nil {
		panic(err)
	}
	eve2 := attacks.NewEve(chain, carol.Vk)
	known, _ := eve2.KnownOutputs(txa)
	need := known + txa.Fee
	fmt.Printf("   alice spends ONE coin: %s to carol (Eve can read it) + fee %d, so the real coin held at least %s\n",
		comma(known), txa.Fee, comma(need))
	legacy := txa.Copy() // the same transaction, one decoy swapped for the first coinbase
	slot := (posa[0] + 1) % len(legacy.RingRefs)
	legacy.RingRefs[slot] = cb
	fmt.Println("   without the S-1 rule, a coinbase could sit in her ring as a decoy:")
	if ring {
		showRing(eve2, legacy, need, "cover")
	} else {
		fmt.Printf("   coinbase in the ring: #%d = %s\n", cb, paint(comma(eve2.Amount(cb)), "yellow"))
	}
	no(fmt.Sprintf("unprotected: #%d holds only %s, less than %s, so Eve crosses it off: anonymity set %d of %d",
		cb, comma(eve2.Amount(cb)), comma(need), len(eve2.Remaining(legacy)), len(legacy.RingRefs)))
	ok(fmt.Sprintf("with the rule: alice's real ring holds no coinbase, so Eve rules out no one: %d of %d",
		len(eve2.Remaining(txa)), len(txa.RingRefs)))
	no(fmt.Sprintf("and that coinbase-stuffed ring is rejected: verify -> %v", chain.Verify(legacy, siga)))
	explain("one input must cover outputs + fee on its own, so a too-small public coinbase can't be it;",
		"with S = 1 the S-1 rule allows no coinbase at all, and Verify returns None if one is there")

	step("Double spend: submit the same transaction again")
	fmt.Printf("   verify -> %v  (None = rule broken: tag already on chain)\n", chain.Verify(tx, sig))
	if _, err := chain.Submit(tx, sig); err != nil {
		no(err.Error())
	}
	explain("Verify: the same coins give the same tags, already on the spent list,",
		"so a rule is broken and it returns None (the paper's bottom) before checking the proof")

	step("Tampering: bob builds a tx, someone edits it in transit")
	tx2, sig2, _, err := build(chain, []wallet{bob}, []uint32{newRefs[0]},
		[]succinct.Payment{{To: carol.Mpk, Amount: 300}, {To: bob.Mpk, Amount: 195}}, 5)
	if err != nil {
		panic(err)
	}
	edited := tx2.Copy()
	edited.Fee = 0
	no(fmt.Sprintf("edited fee: verify -> %v", chain.Verify(edited, sig2)))
	swapped := tx2.Copy()
	swapped.Info = curve.G.Mul(curve.RandomScalar())
	no(fmt.Sprintf("swapped tek: verify -> %v   (our fix: the paper's 6.2 leaves the tek unsigned)", chain.Verify(swapped, sig2)))
	ok(fmt.Sprintf("original: verify -> %v", chain.Verify(tx2, sig2)))
	explain("the fee and the tek are part of the signed transaction prefix, so editing either changes h,",
		"z no longer satisfies Eq. 5, and the proof fails (False, not None)",
		"without the fix, a swapped tek would still verify, but carol could never find her coin")

	step("Inflation: bob tries to send more than he has")
	inflate := []succinct.Payment{{To: carol.Mpk, Amount: 900}, {To: bob.Mpk, Amount: 0}}
	if _, _, _, err := build(chain, []wallet{bob}, []uint32{newRefs[0]}, inflate, 5); err != nil {
		no("Spend refuses: " + err.Error())
	}
	saved := succinct.CheckBalance
	succinct.CheckBalance = func([]succinct.SpendInput, []succinct.SpendOutput, uint64) error { return nil } // a patched wallet
	tx3, sig3, _, err := build(chain, []wallet{bob}, []uint32{newRefs[0]}, inflate, 5)
	succinct.CheckBalance = saved
	if err != nil {
		panic(errors.Join(errors.New("patched wallet failed"), err))
	}
	no(fmt.Sprintf("patched wallet signs it anyway, but verify -> %v", chain.Verify(tx3, sig3)))
	explain("balance is checked inside Eq. 5 (the gamma part) and the range proof,",
		"so Verify catches it even when the wallet's own check is switched off")

	fmt.Println(paint("\nDone.", "bold"))
}
