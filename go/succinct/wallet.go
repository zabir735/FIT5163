package succinct

import (
	"errors"
	"fmt"
	"sort"

	"succinctgo/curve"
)

// Wallet-side spending policies for miners (paper §3.1). Not consensus rules:
// outputs are unlinkable, so no node can tell an output goes back to the miner.
// Both need an ordinary (non-coinbase) input as well, because of the S-1 rule.

// WalletRingSize is the default ring size of the wallet helpers.
const WalletRingSize = 8

// Owned is a coin the wallet can open: its ref and keys.
type Owned struct {
	Ref uint32
	Mpk *MasterPublicKey
	Msk *MasterSecretKey
}

func openInputs(chain *Chain, owned []Owned, positions []int) ([]SpendInput, error) {
	var inputs []SpendInput
	for k, o := range owned {
		acc, info, _ := chain.Get(o.Ref)
		got, ok := Receive(o.Msk, o.Mpk, acc, info)
		if !ok {
			return nil, fmt.Errorf("output #%d does not belong to the given key", o.Ref)
		}
		inputs = append(inputs, SpendInput{Ind: positions[k], Ck: got.Ck, A: int64(got.A), Sk: got.Sk, Tag: got.Tag})
	}
	return inputs, nil
}

func total(chain *Chain, owned []Owned) (uint64, error) {
	var sum uint64
	for _, o := range owned {
		acc, info, _ := chain.Get(o.Ref)
		got, ok := Receive(o.Msk, o.Mpk, acc, info)
		if !ok {
			return 0, fmt.Errorf("output #%d does not belong to the given key", o.Ref)
		}
		sum += got.A
	}
	return sum, nil
}

// Build picks a ring, opens the inputs, makes the outputs and spends, with the
// chain's own proof system.
func Build(chain *Chain, owned []Owned, payments []Payment, fee uint64, ringSize int) (*Transaction, *Signature, []int, error) {
	refs := make([]uint32, len(owned))
	for k, o := range owned {
		refs[k] = o.Ref
	}
	ring, pos, err := PickRing(chain, refs, ringSize, nil)
	if err != nil {
		return nil, nil, nil, err
	}
	inputs, err := openInputs(chain, owned, pos)
	if err != nil {
		return nil, nil, nil, err
	}
	outputs, info := MakeOutputs(payments)
	members := make([]RingMember, len(ring))
	for i, r := range ring {
		acc, _, _ := chain.Get(r)
		members[i] = RingMember{r, acc}
	}
	tx, sig, err := Spend(members, inputs, outputs, info, fee, nil, chain.System)
	return tx, sig, pos, err
}

func split(totalAmt uint64, parts int) ([]uint64, error) {
	if totalAmt < uint64(parts) {
		return nil, fmt.Errorf("need at least %d to give every account a non-zero amount", parts)
	}
	cuts := map[uint64]bool{}
	for len(cuts) < parts-1 {
		c := 1 + curve.ToBig(curve.RandomScalar()).Uint64()%(totalAmt-1)
		cuts[c] = true
	}
	edges := []uint64{0}
	for c := range cuts {
		edges = append(edges, c)
	}
	sort.Slice(edges, func(i, j int) bool { return edges[i] < edges[j] })
	edges = append(edges, totalAmt)
	out := make([]uint64, parts)
	for i := range out {
		out[i] = edges[i+1] - edges[i]
	}
	return out, nil
}

// SelfTransfer pays amount to the recipient and the rest (non-zero) back to
// self. It only checks that some change comes back, exactly the paper's
// condition, so a "careless" amount that passes the ordinary coin straight
// through is still accepted.
func SelfTransfer(chain *Chain, coinbase, ordinary Owned, recipient *MasterPublicKey, amount uint64,
	self *MasterPublicKey, fee uint64, ringSize int) (*Transaction, *Signature, error) {
	owned := []Owned{coinbase, ordinary}
	tot, err := total(chain, owned)
	if err != nil {
		return nil, nil, err
	}
	if tot <= fee+amount {
		return nil, nil, errors.New("self-transfer needs a non-zero amount back to the miner")
	}
	tx, sig, _, err := Build(chain, owned, []Payment{{recipient, amount}, {self, tot - fee - amount}}, fee, ringSize)
	return tx, sig, err
}

// MultiSelfTransfer consolidates several coinbases plus one ordinary coin into
// at least two of the miner's own non-mining accounts, with random non-zero
// amounts. Without the ordinary coin the S-1 rule refuses it.
func MultiSelfTransfer(chain *Chain, coinbases []Owned, ordinary *Owned, selves []*MasterPublicKey,
	fee uint64, ringSize int) (*Transaction, *Signature, []uint64, error) {
	if len(selves) < 2 {
		return nil, nil, nil, errors.New("multi-self-transfer needs at least two non-mining accounts")
	}
	for _, m := range selves {
		if m.IsMiner {
			return nil, nil, nil, errors.New("self accounts must be non-mining addresses")
		}
	}
	owned := append([]Owned{}, coinbases...)
	if ordinary != nil {
		owned = append(owned, *ordinary)
	}
	refs := make([]uint32, len(owned))
	for k, o := range owned {
		refs[k] = o.Ref
	}
	if _, _, err := PickRing(chain, refs, ringSize, nil); err != nil {
		return nil, nil, nil, err
	}
	tot, err := total(chain, owned)
	if err != nil {
		return nil, nil, nil, err
	}
	if tot < fee {
		return nil, nil, nil, errors.New("fee larger than the coins")
	}
	amounts, err := split(tot-fee, len(selves))
	if err != nil {
		return nil, nil, nil, err
	}
	pays := make([]Payment, len(selves))
	for i, m := range selves {
		pays[i] = Payment{m, amounts[i]}
	}
	tx, sig, _, err := Build(chain, owned, pays, fee, ringSize)
	return tx, sig, amounts, err
}
