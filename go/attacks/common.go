// Package attacks ports the six attack experiments in attacks/ (Part C). Eve is
// the paper's passive observer: she sees the public chain, every coinbase
// amount, each transaction's ring and fee, and the view keys of some
// recipients. She only uses the arithmetic of section 3.
//
// Python's random module and Go's math/rand produce different streams, so the
// same seed gives statistically similar, not identical, tables.
package attacks

import (
	"fmt"
	mrand "math/rand/v2"

	"succinctgo/curve"
	"succinctgo/nizk"
	"succinctgo/succinct"
)

// Reward is the block reward the experiments use, as in attacks/_common.py.
const Reward = 600_000

// Wallet is a user: keys plus the view key they could hand to an auditor.
type Wallet struct {
	Mpk *succinct.MasterPublicKey
	Msk *succinct.MasterSecretKey
	Vk  *succinct.ViewKey // nil for a miner
}

// NewWallet makes an ordinary wallet with a degree-q polynomial.
func NewWallet(q int) *Wallet {
	mpk, msk, vk := succinct.SAKGen(q)
	return &Wallet{mpk, msk, vk}
}

// NewMiner makes a miner wallet.
func NewMiner() *Wallet {
	mpk, msk := succinct.SAKGenMiner()
	return &Wallet{Mpk: mpk, Msk: msk}
}

// Open receives an output this wallet owns.
func (w *Wallet) Open(c *succinct.Chain, ref uint32) *succinct.Opened {
	acc, info, _ := c.Get(ref)
	got, ok := succinct.Receive(w.Msk, w.Mpk, acc, info)
	if !ok {
		panic(fmt.Sprintf("output #%d is not this wallet's", ref))
	}
	return got
}

// Owned is this wallet's handle on a coin, for the wallet helpers.
func (w *Wallet) Owned(ref uint32) succinct.Owned {
	return succinct.Owned{Ref: ref, Mpk: w.Mpk, Msk: w.Msk}
}

// RandInt is Python's randint(a, b), both ends included.
func RandInt(r *mrand.Rand, a, b int) int { return a + r.IntN(b-a+1) }

// Sample is Python's random.sample.
func Sample(r *mrand.Rand, pool []uint32, k int) []uint32 {
	cp := append([]uint32{}, pool...)
	r.Shuffle(len(cp), func(i, j int) { cp[i], cp[j] = cp[j], cp[i] })
	return cp[:k]
}

// World is a toy chain with ordinary decoys and a pool of other miners' coinbases.
type World struct {
	Rng       *mrand.Rand
	Chain     *succinct.Chain
	Ordinary  []uint32
	MinerPool []uint32
}

// NewWorld builds ringSize+extra decoys and a pool of coinbases.
func NewWorld(ringSize int, rng *mrand.Rand, sys nizk.System) *World {
	w := &World{Rng: rng, Chain: succinct.NewChain(sys, Reward)}
	for i := 0; i < ringSize+20; i++ {
		mpk, _, _ := succinct.SAKGen(1)
		_, acc, info := succinct.OTAccGen(mpk, uint64(RandInt(rng, 100, 10_000)), 1, nil)
		w.Ordinary = append(w.Ordinary, w.Chain.AddOutput(acc, info))
	}
	for i := 0; i < 8; i++ {
		ref, _, _ := w.AddCoinbase()
		w.MinerPool = append(w.MinerPool, ref)
	}
	return w
}

// AddCoinbase adds a coinbase = reward + that block's fees.
func (w *World) AddCoinbase() (uint32, *Wallet, uint64) {
	m := NewMiner()
	amount := uint64(Reward + RandInt(w.Rng, 0, 5_000))
	_, acc, _ := succinct.OTAccGen(m.Mpk, amount, 0, nil)
	return w.Chain.AddOutput(acc, nil), m, amount
}

// AddCoin adds an ordinary (hidden-amount) coin.
func (w *World) AddCoin(owner *Wallet, amount uint64) uint32 {
	_, acc, info := succinct.OTAccGen(owner.Mpk, amount, 1, nil)
	return w.Chain.AddOutput(acc, info)
}

// LegacyRing builds a ring with NO S-1 rule: some coinbase decoys, the rest uniform.
func (w *World) LegacyRing(real []uint32, size, minerDecoys int) []uint32 {
	isReal := map[uint32]bool{}
	for _, r := range real {
		isReal[r] = true
	}
	var pool []uint32
	for _, r := range w.MinerPool {
		if !isReal[r] {
			pool = append(pool, r)
		}
	}
	decoys := Sample(w.Rng, pool, minerDecoys)
	decoys = append(decoys, Sample(w.Rng, w.Ordinary, size-len(real)-minerDecoys)...)
	ring := append(append([]uint32{}, real...), decoys...)
	w.Rng.Shuffle(len(ring), func(i, j int) { ring[i], ring[j] = ring[j], ring[i] })
	return ring
}

// ObservableTx is what Eve sees: ring, tags, outputs and fee, no signature.
// Used where Spend correctly refuses to build the transaction.
func ObservableTx(ring []uint32, tags []curve.Point, payments []succinct.Payment, fee uint64) *succinct.Transaction {
	outs, info := succinct.MakeOutputs(payments)
	tx := &succinct.Transaction{RingRefs: ring, Tags: tags, Info: info, Fee: fee}
	for _, o := range outs {
		tx.Outputs = append(tx.Outputs, o.Acc)
	}
	return tx
}

// Eve is the observer with some view keys.
type Eve struct {
	Chain *succinct.Chain
	Keys  []*succinct.ViewKey
}

// NewEve drops nil keys (miners have none).
func NewEve(c *succinct.Chain, keys ...*succinct.ViewKey) *Eve {
	e := &Eve{Chain: c}
	for _, k := range keys {
		if k != nil {
			e.Keys = append(e.Keys, k)
		}
	}
	return e
}

// IsMiner and Amount read the public chain.
func (e *Eve) IsMiner(ref uint32) bool  { a, _, _ := e.Chain.Get(ref); return a.IsMiner() }
func (e *Eve) Amount(ref uint32) uint64 { a, _, _ := e.Chain.Get(ref); return a.Ctxt }

// KnownOutputs is the sum Eve can read and how many outputs she can't.
func (e *Eve) KnownOutputs(tx *succinct.Transaction) (known uint64, hidden int) {
	info := tx.Info
	for _, acc := range tx.Outputs {
		seen := false
		for _, k := range e.Keys {
			if a, ok := succinct.View(k, acc, &info); ok {
				known += a
				seen = true
				break
			}
		}
		if !seen {
			hidden++
		}
	}
	return known, hidden
}

// Remaining is the effective anonymity set: with one input, a coinbase smaller
// than outputs + fee can't be the spender.
func (e *Eve) Remaining(tx *succinct.Transaction) []uint32 {
	known, _ := e.KnownOutputs(tx)
	need := known + tx.Fee
	if len(tx.Tags) != 1 {
		return append([]uint32{}, tx.RingRefs...)
	}
	var out []uint32
	for _, r := range tx.RingRefs {
		if !e.IsMiner(r) || e.Amount(r) >= need {
			out = append(out, r)
		}
	}
	return out
}

// GuessSpender returns a ring member and whether it was an exact match.
func (e *Eve) GuessSpender(tx *succinct.Transaction, rng *mrand.Rand) (uint32, bool) {
	known, _ := e.KnownOutputs(tx)
	need := known + tx.Fee
	var matches []uint32
	for _, r := range tx.RingRefs {
		if e.IsMiner(r) && e.Amount(r) == need {
			matches = append(matches, r)
		}
	}
	if len(matches) == 1 {
		return matches[0], true
	}
	rem := e.Remaining(tx)
	return rem[rng.IntN(len(rem))], false
}

// GetSystem maps "stub" / "real" to a proof system.
func GetSystem(name string) nizk.System {
	if name == "real" {
		return nizk.Sigma{}
	}
	return nizk.Stub{}
}

// Pct formats num/den like the Python pct().
func Pct(num, den int) string {
	if den == 0 {
		return "n/a"
	}
	return fmt.Sprintf("%.1f%%", 100*float64(num)/float64(den))
}
