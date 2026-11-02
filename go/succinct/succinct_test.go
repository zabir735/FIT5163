package succinct

import (
	"bytes"
	"testing"

	"succinctgo/curve"
	"succinctgo/nizk"
)

// Every chain test runs with both proof systems, like tests/test_ct.py.
var systems = []nizk.System{nizk.Stub{}, nizk.Sigma{}}

type user struct {
	mpk *MasterPublicKey
	msk *MasterSecretKey
	vk  *ViewKey
}

func newUser(q int) user {
	mpk, msk, vk := SAKGen(q)
	return user{mpk, msk, vk}
}

func newMiner() user {
	mpk, msk := SAKGenMiner()
	return user{mpk: mpk, msk: msk}
}

// world: 30 decoys, plus a coin of 1,000 for alice.
func world(t *testing.T, sys nizk.System) (*Chain, user, uint32) {
	t.Helper()
	c := NewChain(sys, 600)
	for i := 0; i < 30; i++ {
		u := newUser(1)
		_, acc, info := OTAccGen(u.mpk, 1000, 1, nil)
		c.AddOutput(acc, info)
	}
	alice := newUser(5)
	_, acc, info := OTAccGen(alice.mpk, 1000, 1, nil)
	return c, alice, c.AddOutput(acc, info)
}

func pay(t *testing.T, c *Chain, from user, ref uint32, pays []Payment, fee uint64) (*Transaction, *Signature) {
	t.Helper()
	tx, sig, _, err := Build(c, []Owned{{ref, from.mpk, from.msk}}, pays, fee, 8)
	if err != nil {
		t.Fatal(err)
	}
	return tx, sig
}

func TestHonestSpendVerifiesAndIsReceived(t *testing.T) {
	for _, sys := range systems {
		c, alice, ref := world(t, sys)
		bob := newUser(5)
		tx, sig := pay(t, c, alice, ref, []Payment{{bob.mpk, 700}, {alice.mpk, 290}}, 10)
		if got := c.Verify(tx, sig); got != Valid {
			t.Fatalf("%s: verify = %v", sys.Name(), got)
		}
		refs, err := c.Submit(tx, sig)
		if err != nil {
			t.Fatal(err)
		}
		acc, info, _ := c.Get(refs[0])
		got, ok := Receive(bob.msk, bob.mpk, acc, info)
		if !ok || got.A != 700 {
			t.Fatalf("bob could not receive 700: %v %v", ok, got)
		}
		if a, ok := View(bob.vk, acc, info); !ok || a != 700 {
			t.Fatal("view key cannot read the amount")
		}
		carol := newUser(5)
		if _, ok := Receive(carol.msk, carol.mpk, acc, info); ok {
			t.Fatal("carol received bob's coin")
		}
		// double spend: the same tags again
		if c.Verify(tx, sig) != Broken {
			t.Fatal("replay was not rejected as a broken rule")
		}
	}
}

func TestTamperingFailsTheProof(t *testing.T) {
	c, alice, ref := world(t, nizk.Sigma{})
	bob := newUser(5)
	tx, sig := pay(t, c, alice, ref, []Payment{{bob.mpk, 700}, {alice.mpk, 290}}, 10)
	edits := map[string]func(*Transaction){
		"fee":  func(x *Transaction) { x.Fee = 0 },
		"tek":  func(x *Transaction) { x.Info = curve.G.Mul(curve.RandomScalar()) },
		"mu":   func(x *Transaction) { x.Mu = []byte("hello") },
		"ctxt": func(x *Transaction) { x.Outputs[0].Ctxt ^= 1 },
		"ring": func(x *Transaction) {
			for r := uint32(0); ; r++ {
				used := false
				for _, q := range x.RingRefs {
					used = used || q == r
				}
				if !used {
					x.RingRefs[0] = r
					return
				}
			}
		},
	}
	for name, edit := range edits {
		bad := tx.Copy()
		edit(bad)
		if got := c.Verify(bad, sig); got != BadProof {
			t.Errorf("edited %s: verify = %v, want False", name, got)
		}
	}
	if c.Verify(tx, sig) != Valid {
		t.Fatal("original stopped verifying")
	}
}

func TestInflationCaughtEvenWithWalletCheckOff(t *testing.T) {
	for _, sys := range systems {
		c, alice, ref := world(t, sys)
		bob := newUser(5)
		if _, _, _, err := Build(c, []Owned{{ref, alice.mpk, alice.msk}}, []Payment{{bob.mpk, 1500}, {alice.mpk, 0}}, 10, 8); err == nil {
			t.Fatal("wallet check let inflation through")
		}
		saved := CheckBalance
		CheckBalance = func([]SpendInput, []SpendOutput, uint64) error { return nil }
		tx, sig, _, err := Build(c, []Owned{{ref, alice.mpk, alice.msk}}, []Payment{{bob.mpk, 1500}, {alice.mpk, 0}}, 10, 8)
		CheckBalance = saved
		if err != nil {
			t.Fatal(err)
		}
		if got := c.Verify(tx, sig); got != BadProof {
			t.Fatalf("%s: inflation verify = %v, want False", sys.Name(), got)
		}
	}
}

func TestSMinusOneRule(t *testing.T) {
	c, _, _ := world(t, nizk.Stub{})
	miner := newMiner()
	cb := c.MineBlock(miner.mpk)
	if _, _, err := PickRing(c, []uint32{cb}, 8, nil); err != ErrTooManyCoinbases {
		t.Fatalf("coinbase alone: err = %v", err)
	}
	// coinbase + ordinary coin is fine, and the ring holds exactly one coinbase
	ord := newUser(3)
	_, acc, info := OTAccGen(ord.mpk, 100, 1, nil)
	oref := c.AddOutput(acc, info)
	bob := newUser(3)
	tx, sig, _, err := Build(c, []Owned{{cb, miner.mpk, miner.msk}, {oref, ord.mpk, ord.msk}},
		[]Payment{{bob.mpk, 500}, {ord.mpk, 195}}, 5, 8)
	if err != nil || c.Verify(tx, sig) != Valid {
		t.Fatalf("coinbase + ordinary: %v", err)
	}
	// a ring stuffed with a second coinbase is a broken rule
	c.MineBlock(newMiner().mpk)
	alice := newUser(3)
	_, acc, info = OTAccGen(alice.mpk, 900, 1, nil)
	aref := c.AddOutput(acc, info)
	tx2, sig2, pos, err := Build(c, []Owned{{aref, alice.mpk, alice.msk}}, []Payment{{bob.mpk, 800}, {alice.mpk, 95}}, 5, 8)
	if err != nil {
		t.Fatal(err)
	}
	bad := tx2.Copy()
	bad.RingRefs[(pos[0]+1)%8] = cb
	if c.Verify(bad, sig2) != Broken {
		t.Fatal("coinbase-stuffed one-input ring was not rejected as a broken rule")
	}
}

func TestQLimitAndMinerKeys(t *testing.T) {
	u := newUser(2)
	for i := 0; i < 3; i++ {
		_, acc, info := OTAccGen(u.mpk, 10, 1, nil)
		_, ok := Receive(u.msk, u.mpk, acc, info)
		if ok != (i < 2) {
			t.Fatalf("use %d: ok = %v", i+1, ok)
		}
	}
	m := newMiner()
	a1 := Mine(nil, m.mpk, 600)
	a2 := Mine([]uint64{5}, m.mpk, 600)
	o1, _ := Receive(m.msk, m.mpk, a1, nil)
	o2, _ := Receive(m.msk, m.mpk, a2, nil)
	if !o1.Tag.Equal(o2.Tag) || o2.A != 605 {
		t.Fatal("a reused miner key should repeat the tag; coinbase should be reward + fees")
	}
}

func TestWalletPolicies(t *testing.T) {
	c, _, _ := world(t, nizk.Stub{})
	miner, ord, bob := newMiner(), newUser(5), newUser(5)
	cb := c.MineBlock(miner.mpk)
	_, acc, info := OTAccGen(ord.mpk, 100, 1, nil)
	oref := c.AddOutput(acc, info)
	cbO, ordO := Owned{cb, miner.mpk, miner.msk}, Owned{oref, ord.mpk, ord.msk}
	if _, _, err := SelfTransfer(c, cbO, ordO, bob.mpk, 695, ord.mpk, 5, 8); err == nil {
		t.Fatal("zero-change self-transfer was accepted")
	}
	tx, sig, err := SelfTransfer(c, cbO, ordO, bob.mpk, 500, ord.mpk, 5, 8)
	if err != nil || c.Verify(tx, sig) != Valid {
		t.Fatalf("self-transfer: %v", err)
	}
	m2 := newMiner()
	cb2, cb3 := c.MineBlock(m2.mpk), c.MineBlock(newMiner().mpk)
	_ = cb3
	if _, _, _, err := MultiSelfTransfer(c, []Owned{cbO, {cb2, m2.mpk, m2.msk}}, nil,
		[]*MasterPublicKey{newUser(3).mpk, newUser(3).mpk}, 5, 8); err == nil {
		t.Fatal("coinbase-only multi-self-transfer passed the S-1 rule")
	}
	tx, sig, amounts, err := MultiSelfTransfer(c, []Owned{cbO, {cb2, m2.mpk, m2.msk}}, &ordO,
		[]*MasterPublicKey{newUser(3).mpk, newUser(3).mpk}, 5, 8)
	if err != nil || c.Verify(tx, sig) != Valid || amounts[0] == 0 || amounts[1] == 0 || amounts[0]+amounts[1] != 600+600+100-5 {
		t.Fatalf("multi-self-transfer: %v %v", err, amounts)
	}
}

func TestSerializeRoundTrip(t *testing.T) {
	c, alice, ref := world(t, nizk.Sigma{})
	bob := newUser(5)
	tx, sig := pay(t, c, alice, ref, []Payment{{bob.mpk, 700}, {alice.mpk, 290}}, 10)
	data, err := EncodeTransaction(tx, sig)
	if err != nil {
		t.Fatal(err)
	}
	tx2, sig2, err := DecodeTransaction(data)
	if err != nil {
		t.Fatal(err)
	}
	again, _ := EncodeTransaction(tx2, sig2)
	if !bytes.Equal(data, again) || c.Verify(tx2, sig2) != Valid {
		t.Fatal("round trip changed the transaction")
	}
	// same closed form as serialize.expected_transaction_size: n=8, S=1, 2 outputs
	proof := 4*33 + 2*2 + (1*7+4)*32 + 4*33 + 3*32 + 2 + 2*7*33 + 2*32
	want := 2 + 8*4 + 2 + 33 + 2 + 2*(2*33+8+2) + 33 + 8 + 2 + 2*33 + proof
	if len(data) != want {
		t.Fatalf("size %d, want %d", len(data), want)
	}
	if _, _, err := DecodeTransaction(data[:len(data)-1]); err == nil {
		t.Fatal("truncated bytes were accepted")
	}
}
