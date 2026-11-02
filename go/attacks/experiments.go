package attacks

import (
	"errors"
	"fmt"
	"io"
	"math"
	mrand "math/rand/v2"

	"succinctgo/curve"
	"succinctgo/nizk"
	"succinctgo/succinct"
)

// Config holds every experiment's options (unused ones are ignored).
type Config struct {
	Seed        uint64
	Trials      int
	RingSizes   []int
	Proof       string // "stub" or "real"
	MinerDecoys int    // coinbase decoys in legacy rings
	Qs          []int  // q values for the q-bound experiment
	Coinbases   int    // coinbases per multi-self-transfer
}

func newRng(seed uint64) *mrand.Rand { return succinct.NewSeededRng(seed) }

// spendWith runs PickRing + Spend with a seeded rng (the wallet helpers use the OS).
func spendWith(c *succinct.Chain, owners []*Wallet, refs []uint32, pays []succinct.Payment,
	fee uint64, size int, rng *mrand.Rand) (*succinct.Transaction, *succinct.Signature, []uint32, error) {
	ring, pos, err := succinct.PickRing(c, refs, size, rng)
	if err != nil {
		return nil, nil, nil, err
	}
	var inputs []succinct.SpendInput
	for k, w := range owners {
		o := w.Open(c, refs[k])
		inputs = append(inputs, succinct.SpendInput{Ind: pos[k], Ck: o.Ck, A: int64(o.A), Sk: o.Sk, Tag: o.Tag})
	}
	outs, info := succinct.MakeOutputs(pays)
	members := make([]succinct.RingMember, len(ring))
	for i, r := range ring {
		acc, _, _ := c.Get(r)
		members[i] = succinct.RingMember{Ref: r, Acc: acc}
	}
	tx, sig, err := succinct.Spend(members, inputs, outs, info, fee, nil, c.System)
	return tx, sig, ring, err
}

// --- 1. miner privacy (section 3.1) -----------------------------------------

// MinerPrivacy: a miner spends a coinbase to Bob while Eve holds Bob's view key.
func MinerPrivacy(out io.Writer, cfg Config) {
	sys := GetSystem(cfg.Proof)
	rng := newRng(cfg.Seed)
	fmt.Fprintf(out, "Attack 1: miner privacy | trials=%d seed=%d proof=%s (Go)\n", cfg.Trials, cfg.Seed, cfg.Proof)
	fmt.Fprintf(out, "Eve holds Bob's view key; success = she names a real input of the transaction.\n\n")
	scenarios := []struct{ label, kind string }{
		{"legacy: no mitigation", "legacy"},
		{"self-transfer only", "self_only"},
		{"self-transfer + S-1 ring rule", "full"},
		{"careless self-transfer + S-1 rule", "careless"},
	}
	for _, size := range cfg.RingSizes {
		w := NewWorld(size, rng, sys)
		fmt.Fprintf(out, "ring size n = %d\n", size)
		fmt.Fprintf(out, "  %-36s%12s%9s%9s%10s\n", "scenario", "Eve success", "certain", "chance", "tx valid")
		for _, sc := range scenarios {
			wins, certain, validOK, validN, nReal := 0, 0, 0, 0, 0
			for t := 0; t < cfg.Trials; t++ {
				var tx *succinct.Transaction
				real := map[uint32]bool{}
				bob := NewWallet(3)
				if sc.kind == "legacy" || sc.kind == "self_only" {
					cb, miner, aM := w.AddCoinbase()
					normal := NewWallet(3)
					fee := uint64(RandInt(rng, 10, 200))
					spendable := aM - fee
					x := spendable
					if sc.kind == "self_only" {
						x = uint64(RandInt(rng, int(spendable/4), int(3*spendable/4)))
					}
					ring := w.LegacyRing([]uint32{cb}, size, cfg.MinerDecoys)
					tag := miner.Open(w.Chain, cb).Tag
					tx = ObservableTx(ring, []curve.Point{tag},
						[]succinct.Payment{{To: bob.Mpk, Amount: x}, {To: normal.Mpk, Amount: spendable - x}}, fee)
					real[cb] = true
					nReal = 1
				} else {
					cb, miner, aM := w.AddCoinbase()
					normal := NewWallet(3)
					aO := uint64(RandInt(rng, 1_000, 5_000))
					oRef := w.AddCoin(normal, aO)
					fee := uint64(RandInt(rng, 10, 200))
					total := aM + aO
					x := aM - fee
					if sc.kind != "careless" {
						x = uint64(RandInt(rng, int(total/4), int(3*total/4)))
					}
					var sig *succinct.Signature
					var err error
					tx, sig, _, err = spendWith(w.Chain, []*Wallet{miner, normal}, []uint32{cb, oRef},
						[]succinct.Payment{{To: bob.Mpk, Amount: x}, {To: normal.Mpk, Amount: total - fee - x}}, fee, size, rng)
					if err != nil {
						panic(err)
					}
					validN++
					if w.Chain.Verify(tx, sig) == succinct.Valid {
						validOK++
					}
					real[cb], real[oRef] = true, true
					nReal = 2
				}
				guess, match := NewEve(w.Chain, bob.Vk).GuessSpender(tx, rng)
				if real[guess] {
					wins++
				}
				if match {
					certain++
				}
			}
			valid := "    -"
			if validN > 0 {
				valid = Pct(validOK, validN)
			}
			fmt.Fprintf(out, "  %-36s%12s%9s%9s%10s\n", sc.label, Pct(wins, cfg.Trials), Pct(certain, cfg.Trials),
				Pct(nReal, size), valid)
		}
		fmt.Fprintln(out)
	}
	fmt.Fprintln(out, "certain = Eve found an exact coinbase match (output + fee = coinbase amount).")
	fmt.Fprintln(out, "chance  = success of a blind guess (real inputs / ring size).")
	fmt.Fprintln(out, "tx valid: legacy rows are observable-only (Spend refuses to build them).")
}

// --- 2. anonymity reduction (section 3.2) -----------------------------------

// AnonymityReduction: coinbase decoys smaller than outputs + fee are crossed off.
func AnonymityReduction(out io.Writer, cfg Config) {
	sys := GetSystem(cfg.Proof)
	rng := newRng(cfg.Seed)
	fmt.Fprintf(out, "Attack 2: anonymity reduction | trials=%d seed=%d proof=%s (Go)\n", cfg.Trials, cfg.Seed, cfg.Proof)
	fmt.Fprintf(out, "Eve reads all outputs; a coinbase smaller than outputs + fee cannot be the sole spender.\n\n")
	for _, size := range cfg.RingSizes {
		w := NewWorld(size, rng, sys)
		var legacySum, mitSum float64
		reduced, big, valid, rejected := 0, 0, 0, 0
		for t := 0; t < cfg.Trials; t++ {
			aReal := uint64(math.Pow(10, 3+3.5*rng.Float64())) // about 1,000 .. 3.2M
			if aReal > Reward {
				big++
			}
			sender, carol := NewWallet(3), NewWallet(3)
			realRef := w.AddCoin(sender, aReal)
			fee := uint64(RandInt(rng, 10, 200))
			x := uint64(RandInt(rng, 1, int(aReal-fee-1)))
			pays := []succinct.Payment{{To: carol.Mpk, Amount: x}, {To: sender.Mpk, Amount: aReal - fee - x}}
			eve := NewEve(w.Chain, carol.Vk, sender.Vk)
			tag := sender.Open(w.Chain, realRef).Tag

			legacy := w.LegacyRing([]uint32{realRef}, size, cfg.MinerDecoys)
			left := len(eve.Remaining(ObservableTx(legacy, []curve.Point{tag}, pays, fee)))
			legacySum += float64(left)
			if left < size {
				reduced++
			}

			tx, sig, _, err := spendWith(w.Chain, []*Wallet{sender}, []uint32{realRef}, pays, fee, size, rng)
			if err != nil {
				panic(err)
			}
			if w.Chain.Verify(tx, sig) == succinct.Valid {
				valid++
			}
			mitSum += float64(len(eve.Remaining(tx)))
			stuffed := tx.Copy()
			stuffed.RingRefs = legacy
			if w.Chain.Verify(stuffed, sig) == succinct.Broken {
				rejected++
			}
		}
		n := float64(cfg.Trials)
		fmt.Fprintf(out, "ring size n = %d   (%s of trials spend more than a block reward)\n", size, Pct(big, cfg.Trials))
		fmt.Fprintf(out, "  legacy    : effective anonymity set %6.2f of %d   | trials where Eve removed >= 1 decoy: %s\n",
			legacySum/n, size, Pct(reduced, cfg.Trials))
		fmt.Fprintf(out, "  mitigated : effective anonymity set %6.2f of %d   | honest tx valid: %s   | coinbase-stuffed ring rejected by Verify: %s\n\n",
			mitSum/n, size, Pct(valid, cfg.Trials), Pct(rejected, cfg.Trials))
	}
}

// --- 3. related-key tags (section 5) -----------------------------------------

type recipient interface {
	receiveFrom() (s curve.Scalar, tag curve.Point)
}

type naiveRecipient struct{ lsk curve.Scalar }

func (n *naiveRecipient) receiveFrom() (curve.Scalar, curve.Point) {
	s := curve.RandomScalar()
	sk := curve.Add(curve.Hn("naive_onetime", s), n.lsk)
	return s, curve.TagEval(sk)
}

type polyRecipient struct{ w *Wallet }

func (p *polyRecipient) receiveFrom() (curve.Scalar, curve.Point) {
	tdk := curve.RandomScalar()
	_, acc, info := succinct.OTAccGen(p.w.Mpk, 1000, 1, &tdk)
	s := curve.KaKey(tdk, p.w.Mpk.Vek, 1) // Alice, the sender, can compute this
	got, ok := succinct.Receive(p.w.Msk, p.w.Mpk, acc, info)
	if !ok {
		panic("receive refused: raise q")
	}
	return s, got.Tag
}

// RelatedKey: Alice knows both shared secrets; can she link Bob's two tags?
func RelatedKey(out io.Writer, cfg Config) {
	rules := []struct {
		name string
		off  func(curve.Scalar) curve.Scalar
	}{
		{"Monero-style: delta = H(s1) - H(s2)", func(s curve.Scalar) curve.Scalar { return curve.Hn("naive_onetime", s) }},
		{"plain linear: delta = s1 - s2", func(s curve.Scalar) curve.Scalar { return s }},
	}
	link := func(tx curve.Point, sx curve.Scalar, ty curve.Point, sy curve.Scalar, off func(curve.Scalar) curve.Scalar) bool {
		return tx.Sub(ty).Equal(curve.U.Mul(curve.Sub(off(sx), off(sy))))
	}
	fmt.Fprintf(out, "Related-key tag attack | trials=%d (Go)\n", cfg.Trials)
	fmt.Fprintf(out, "Alice knows both shared secrets. 'links' = her check says the two tags share a recipient.\n\n")
	fmt.Fprintf(out, "  %-34s%-40s%11s%11s\n", "scheme", "alice check", "links same", "links diff")
	schemes := []struct {
		name string
		make func() recipient
	}{
		{"naive  sk = H(s) + lsk", func() recipient { return &naiveRecipient{curve.RandomScalar()} }},
		{"SuccinCT  sk = f(s), q = 3", func() recipient { return &polyRecipient{NewWallet(3)} }},
	}
	for _, sc := range schemes {
		same := make([]int, len(rules))
		diff := make([]int, len(rules))
		for t := 0; t < cfg.Trials; t++ {
			a, b := sc.make(), sc.make()
			s1, t1 := a.receiveFrom()
			s2, t2 := a.receiveFrom()
			s3, t3 := b.receiveFrom()
			for i, r := range rules {
				if link(t1, s1, t2, s2, r.off) {
					same[i]++
				}
				if link(t1, s1, t3, s3, r.off) {
					diff[i]++
				}
			}
		}
		for i, r := range rules {
			fmt.Fprintf(out, "  %-34s%-40s%10.0f%%%10.0f%%\n", sc.name, r.name,
				100*float64(same[i])/float64(cfg.Trials), 100*float64(diff[i])/float64(cfg.Trials))
		}
		fmt.Fprintln(out)
	}
	fmt.Fprintln(out, "links same = pair of tags from ONE recipient (Alice wants this to be 100%).")
	fmt.Fprintln(out, "links diff = pair from two DIFFERENT recipients (should be 0% or the test is useless).")
}

// --- 4. the q bound (section 5) ----------------------------------------------

// predict interpolates through (xs, f(xs)*U) in the exponent and evaluates at x.
func predict(xs []curve.Scalar, pts []curve.Point, x curve.Scalar) curve.Point {
	sc := make([]curve.Scalar, len(xs))
	for i := range xs {
		num, den := curve.S(1), curve.S(1)
		for j := range xs {
			if i != j {
				num = curve.Mul(num, curve.Sub(x, xs[j]))
				den = curve.Mul(den, curve.Sub(xs[i], xs[j]))
			}
		}
		sc[i] = curve.Mul(num, curve.Inv(den))
	}
	return curve.MultiExp(sc, pts)
}

// QBound: with q+1 tags the next one is predictable, with q it isn't.
func QBound(out io.Writer, cfg Config) {
	fmt.Fprintf(out, "q-bound linkability | trials=%d (Go; keys use OS randomness)\n", cfg.Trials)
	fmt.Fprintf(out, "Alice made every output, so she knows each s_i. 'predicted' = she computed the next tag.\n\n")
	for _, q := range cfg.Qs {
		hits := make([]int, q+2)
		falsePos, refused := 0, 0
		for t := 0; t < cfg.Trials; t++ {
			w := NewWallet(q)
			var xs []curve.Scalar
			var tags []curve.Point
			for k := 0; k < q+2; k++ { // q+1 observed uses + 1 target
				tdk := curve.RandomScalar()
				_, acc, info := succinct.OTAccGen(w.Mpk, 1000, 1, &tdk)
				s := curve.KaKey(tdk, w.Mpk.Vek, 1)
				_, ok := succinct.Receive(w.Msk, w.Mpk, acc, info)
				if k == q && !ok {
					refused++ // the honest wallet stops at use q+1
				}
				xs = append(xs, s)
				tags = append(tags, curve.TagEval(w.Msk.F(s)))
			}
			for m := 1; m <= q+1; m++ {
				if predict(xs[:m], tags[:m], xs[q+1]).Equal(tags[q+1]) {
					hits[m]++
				}
			}
			other := NewWallet(q)
			tdk := curve.RandomScalar()
			s2 := curve.KaKey(tdk, other.Mpk.Vek, 1)
			if predict(xs[:q+1], tags[:q+1], s2).Equal(curve.TagEval(other.Msk.F(s2))) {
				falsePos++
			}
		}
		fmt.Fprintf(out, "q = %d   (key supports %d uses; wallet refused use #%d in %.0f%% of trials)\n",
			q, q, q+1, 100*float64(refused)/float64(cfg.Trials))
		for m := 1; m <= q+1; m++ {
			note := ""
			if m == q+1 {
				note = "  <- first point where it works (q+1 tags)"
			}
			fmt.Fprintf(out, "   tags seen = %2d   next tag predicted: %4.0f%%%s\n", m, 100*float64(hits[m])/float64(cfg.Trials), note)
		}
		fmt.Fprintf(out, "   control: other recipient's tag predicted: %.0f%%\n\n", 100*float64(falsePos)/float64(cfg.Trials))
	}
}

// --- 5. end to end on the real chain -----------------------------------------

func newScenarioChain(size int, sys nizk.System, rng *mrand.Rand) (*succinct.Chain, []uint32, []uint32) {
	c := succinct.NewChain(sys, Reward)
	var ordinary, coinbases []uint32
	for i := 0; i < size+20; i++ {
		w := NewWallet(1)
		_, acc, info := succinct.OTAccGen(w.Mpk, uint64(RandInt(rng, 100, 10_000)), 1, nil)
		ordinary = append(ordinary, c.AddOutput(acc, info))
	}
	for i := 0; i < 4; i++ {
		coinbases = append(coinbases, c.MineBlock(NewMiner().Mpk))
	}
	return c, ordinary, coinbases
}

func send(c *succinct.Chain, owners []*Wallet, refs []uint32, pays []succinct.Payment, fee uint64,
	size int, rng *mrand.Rand) ([]uint32, *succinct.Transaction) {
	tx, sig, _, err := spendWith(c, owners, refs, pays, fee, size, rng)
	if err != nil {
		panic(err)
	}
	newRefs, err := c.Submit(tx, sig)
	if err != nil {
		panic(err)
	}
	return newRefs, tx
}

type scenarioRow struct {
	refused, rejected, hit, certain bool
	payRingCoinbases                int
}

func scenarioTrial(c *succinct.Chain, ordinary []uint32, coinbases *[]uint32, size int, rng *mrand.Rand, careless bool) scenarioRow {
	alice, minerOrd, bob, minerChange := NewWallet(3), NewWallet(3), NewWallet(3), NewWallet(3)
	_, acc, info := succinct.OTAccGen(alice.Mpk, 50_000, 1, nil)
	aRef := c.AddOutput(acc, info)
	fee1 := uint64(RandInt(rng, 10, 200))
	paid, payTx := send(c, []*Wallet{alice}, []uint32{aRef},
		[]succinct.Payment{{To: minerOrd.Mpk, Amount: 20_000}, {To: alice.Mpk, Amount: 30_000 - fee1}}, fee1, size, rng)

	miner := NewMiner()
	cb := c.MineBlock(miner.Mpk)
	cbAcc, _, _ := c.Get(cb)
	cbAmount := cbAcc.Ctxt
	fee2 := uint64(RandInt(rng, 10, 200))
	total := cbAmount + 20_000

	var row scenarioRow
	if _, _, err := succinct.PickRing(c, []uint32{cb}, size, rng); errors.Is(err, succinct.ErrTooManyCoinbases) {
		row.refused = true
	}
	cbTag := miner.Open(c, cb).Tag
	var others []uint32
	for _, r := range *coinbases {
		if r != cb {
			others = append(others, r)
		}
	}
	ring := append([]uint32{cb}, Sample(rng, others, 3)...)
	ring = append(ring, Sample(rng, ordinary, size-4)...)
	rng.Shuffle(len(ring), func(i, j int) { ring[i], ring[j] = ring[j], ring[i] })
	stuffed := ObservableTx(ring, []curve.Point{cbTag},
		[]succinct.Payment{{To: bob.Mpk, Amount: cbAmount - fee2}, {To: minerChange.Mpk, Amount: 0}}, fee2)
	if _, err := c.Submit(stuffed, &succinct.Signature{R: curve.G, T: curve.G}); errors.Is(err, succinct.ErrRuleBroken) {
		row.rejected = true
	}

	x := cbAmount - fee2
	if !careless {
		x = uint64(RandInt(rng, int(total/4), int(3*total/4)))
	}
	_, tx := send(c, []*Wallet{miner, minerOrd}, []uint32{cb, paid[0]},
		[]succinct.Payment{{To: bob.Mpk, Amount: x}, {To: minerChange.Mpk, Amount: total - fee2 - x}}, fee2, size, rng)
	guess, match := NewEve(c, bob.Vk).GuessSpender(tx, rng)
	*coinbases = append(*coinbases, cb)
	row.hit = guess == cb || guess == paid[0]
	row.certain = match
	for _, r := range payTx.RingRefs {
		if a, _, _ := c.Get(r); a.IsMiner() {
			row.payRingCoinbases++
		}
	}
	return row
}

// ChainScenario: both attacks end to end through Chain.Submit.
func ChainScenario(out io.Writer, cfg Config) {
	sys := GetSystem(cfg.Proof)
	rng := newRng(cfg.Seed)
	fmt.Fprintf(out, "End-to-end on the real Chain | trials=%d seed=%d proof=%s (Go)\n", cfg.Trials, cfg.Seed, cfg.Proof)
	fmt.Fprintf(out, "Every transaction goes through Chain.Submit, so Verify's rules are enforced by the chain.\n\n")
	for _, size := range cfg.RingSizes {
		c, ordinary, coinbases := newScenarioChain(size, sys, rng)
		rows := map[string][]scenarioRow{}
		for _, mode := range []string{"mitigated", "careless"} {
			for t := 0; t < cfg.Trials; t++ {
				rows[mode] = append(rows[mode], scenarioTrial(c, ordinary, &coinbases, size, rng, mode == "careless"))
			}
		}
		both := append(append([]scenarioRow{}, rows["mitigated"]...), rows["careless"]...)
		refused, rejected, cbs := 0, 0, 0
		for _, r := range both {
			if r.refused {
				refused++
			}
			if r.rejected {
				rejected++
			}
			cbs += r.payRingCoinbases
		}
		fmt.Fprintf(out, "ring size n = %d   (chain now holds %d outputs)\n", size, c.Len())
		fmt.Fprintf(out, "  legacy attempt (coinbase spent alone): wallet refuses to build %s, hand-made copy rejected by chain (⊥) %s\n",
			Pct(refused, len(both)), Pct(rejected, len(both)))
		for _, m := range []struct{ mode, label string }{{"mitigated", "self-transfer + S-1 rule"}, {"careless", "careless self-transfer"}} {
			hit, cert := 0, 0
			for _, r := range rows[m.mode] {
				if r.hit {
					hit++
				}
				if r.certain {
					cert++
				}
			}
			fmt.Fprintf(out, "  %-26s accepted by chain: 100%%   Eve success %6s   certain %6s   chance %s\n",
				m.label, Pct(hit, cfg.Trials), Pct(cert, cfg.Trials), Pct(2, size))
		}
		fmt.Fprintf(out, "  attack 2 on chain: coinbases in rings of ordinary spends: %.2f on average\n\n",
			float64(cbs)/float64(len(both)))
	}
}

// --- 6. multi-self-transfer (section 3.1, P2Pool) ---------------------------

// MultiSelfTransfer: several coinbases consolidated into two own accounts, then
// a payment to Bob from one of them.
func MultiSelfTransfer(out io.Writer, cfg Config) {
	sys := GetSystem(cfg.Proof)
	rng := newRng(cfg.Seed)
	k := cfg.Coinbases
	fmt.Fprintf(out, "Multi-self-transfer on the real Chain | trials=%d seed=%d proof=%s (Go)\n", cfg.Trials, cfg.Seed, cfg.Proof)
	fmt.Fprintf(out, "%d coinbases + 1 ordinary coin consolidated into 2 own accounts, then a payment to Bob.\n\n", k)
	for _, size := range cfg.RingSizes {
		c, _, _ := newScenarioChain(size, sys, rng)
		refused, nonzero, hit, cert, cbInRing2, hit2 := 0, 0, 0, 0, 0, 0
		for t := 0; t < cfg.Trials; t++ {
			alice, minerOrd, bob := NewWallet(3), NewWallet(3), NewWallet(3)
			_, acc, info := succinct.OTAccGen(alice.Mpk, 50_000, 1, nil)
			aRef := c.AddOutput(acc, info)
			fee1 := uint64(RandInt(rng, 10, 200))
			paid, _ := send(c, []*Wallet{alice}, []uint32{aRef},
				[]succinct.Payment{{To: minerOrd.Mpk, Amount: 20_000}, {To: alice.Mpk, Amount: 30_000 - fee1}}, fee1, size, rng)
			ordinary := minerOrd.Owned(paid[0])

			var cbs []succinct.Owned
			for i := 0; i < k+1; i++ {
				m := NewMiner()
				cbs = append(cbs, m.Owned(c.MineBlock(m.Mpk)))
			}
			spare, used := cbs[0], cbs[1:]

			spareAcc, _, _ := c.Get(spare.Ref)
			total := spareAcc.Ctxt + 20_000
			fee2 := uint64(RandInt(rng, 10, 200))
			if _, _, err := succinct.SelfTransfer(c, spare, ordinary, bob.Mpk, total-fee2, NewWallet(3).Mpk, fee2, size); err != nil {
				refused++
			}

			selves := []*Wallet{NewWallet(3), NewWallet(3)}
			tx, sig, amounts, err := succinct.MultiSelfTransfer(c, used, &ordinary,
				[]*succinct.MasterPublicKey{selves[0].Mpk, selves[1].Mpk}, fee2, size)
			if err != nil {
				panic(err)
			}
			refs, err := c.Submit(tx, sig)
			if err != nil {
				panic(err)
			}
			if amounts[0] >= 1 && amounts[1] >= 1 {
				nonzero++
			}
			real := map[uint32]bool{paid[0]: true}
			for _, u := range used {
				real[u.Ref] = true
			}
			guess, match := NewEve(c).GuessSpender(tx, rng)
			if real[guess] {
				hit++
			}
			if match {
				cert++
			}

			fee3 := uint64(RandInt(rng, 10, 200))
			x := uint64(RandInt(rng, 1, int(amounts[0]-fee3-1)))
			_, tx2 := send(c, []*Wallet{selves[0]}, []uint32{refs[0]},
				[]succinct.Payment{{To: bob.Mpk, Amount: x}, {To: NewWallet(3).Mpk, Amount: amounts[0] - fee3 - x}}, fee3, size, rng)
			for _, r := range tx2.RingRefs {
				if a, _, _ := c.Get(r); a.IsMiner() {
					cbInRing2++
				}
			}
			if g2, _ := NewEve(c, bob.Vk).GuessSpender(tx2, rng); g2 == refs[0] {
				hit2++
			}
		}
		n := cfg.Trials
		fmt.Fprintf(out, "ring size n = %d\n", size)
		fmt.Fprintf(out, "  wallet.self_transfer with zero change refused: %s\n", Pct(refused, n))
		fmt.Fprintf(out, "  multi-self-transfer accepted by chain: 100%%   every account non-zero: %s\n", Pct(nonzero, n))
		fmt.Fprintf(out, "    Eve success %6s   certain %6s   chance %s\n", Pct(hit, n), Pct(cert, n), Pct(k+1, size))
		fmt.Fprintf(out, "  later payment to Bob: coinbases in ring %.2f on average   Eve success %6s   chance %s\n\n",
			float64(cbInRing2)/float64(n), Pct(hit2, n), Pct(1, size))
	}
}
