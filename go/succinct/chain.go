package succinct

import (
	"errors"

	"succinctgo/nizk"
)

// Chain is the toy ledger: an append-only list of outputs, the spent tags and
// the fees waiting for the next coinbase. Submit runs Verify and refuses
// anything that isn't Valid, so every rule is enforced by the chain. Same
// simplifications as chain.py: no maturity, no blocks beyond the coinbase,
// uniform decoys, no networking.
type Chain struct {
	outputs     []entry
	spent       map[string]bool
	pendingFees []uint64
	System      nizk.System
	Reward      uint64
}

type entry struct {
	acc  Account
	info *Point
}

// NewChain makes an empty chain with a proof system and a block reward.
func NewChain(sys nizk.System, reward uint64) *Chain {
	return &Chain{spent: map[string]bool{}, System: sys, Reward: reward}
}

// Len is the number of outputs.
func (c *Chain) Len() int { return len(c.outputs) }

// Get returns an output and its tek.
func (c *Chain) Get(ref uint32) (Account, *Point, bool) {
	if int(ref) >= len(c.outputs) {
		return Account{}, nil, false
	}
	e := c.outputs[ref]
	return e.acc, e.info, true
}

// IsSpent reports whether a tag is already on chain.
func (c *Chain) IsSpent(tag Point) bool { return c.spent[tag.Key()] }

// Spent is the number of spent tags.
func (c *Chain) Spent() int { return len(c.spent) }

// AddOutput is a genesis-style allocation.
func (c *Chain) AddOutput(acc Account, info *Point) uint32 {
	c.outputs = append(c.outputs, entry{acc, info})
	return uint32(len(c.outputs) - 1)
}

// Verify runs Verify with the chain's proof system.
func (c *Chain) Verify(tx *Transaction, sig *Signature) Result {
	return Verify(tx, sig, c, c.System)
}

// ErrRuleBroken and ErrBadProof are Submit's two refusals.
var (
	ErrRuleBroken = errors.New("rejected: rule broken (⊥)")
	ErrBadProof   = errors.New("rejected: invalid proof")
)

// Submit verifies and applies; it returns the refs of the new outputs.
func (c *Chain) Submit(tx *Transaction, sig *Signature) ([]uint32, error) {
	switch c.Verify(tx, sig) {
	case Broken:
		return nil, ErrRuleBroken
	case BadProof:
		return nil, ErrBadProof
	}
	for _, t := range tx.Tags {
		c.spent[t.Key()] = true
	}
	c.pendingFees = append(c.pendingFees, tx.Fee)
	info := tx.Info
	refs := make([]uint32, len(tx.Outputs))
	for k, acc := range tx.Outputs {
		refs[k] = c.AddOutput(acc, &info)
	}
	return refs, nil
}

// ClearPendingFees drops fees not yet paid out (the demo uses it).
func (c *Chain) ClearPendingFees() { c.pendingFees = nil }

// MineBlock pays reward + pending fees to the miner; returns the coinbase ref.
func (c *Chain) MineBlock(miner *MasterPublicKey) uint32 {
	acc := Mine(c.pendingFees, miner, c.Reward)
	c.pendingFees = nil
	return c.AddOutput(acc, nil)
}
