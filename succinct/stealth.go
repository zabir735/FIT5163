// Package succinct is the Go port of the SuccinCT scheme: stealth addresses
// (SAKGen, OTAccGen, View, Receive), Spend, Verify and Mine, the toy chain,
// the miner wallet helpers and the byte format. It follows the Python package
// of the same name file for file.
package succinct

import (
	"succinctgo/curve"
	"succinctgo/nizk"
)

type (
	Point  = curve.Point
	Scalar = curve.Scalar
)

// DefaultQ is the paper's suggestion so mpk fits in a 3 KB QR code.
const DefaultQ = 90

// MasterPublicKey is the address people pay: F_i = theta_i*G and the view
// encryption key. A miner's has one point and no view key.
type MasterPublicKey struct {
	Lpk     []Point
	Vek     Point
	IsMiner bool
}

// MasterSecretKey holds the polynomial f, the view key and the q limit.
type MasterSecretKey struct {
	Thetas   []Scalar
	Vdk      Scalar
	Q        int
	received map[string]bool // pks already received, for the q limit
}

// F evaluates the secret polynomial at x (Horner's rule).
func (k *MasterSecretKey) F(x Scalar) Scalar {
	var acc Scalar
	for i := len(k.Thetas) - 1; i >= 0; i-- {
		acc = curve.Add(curve.Mul(acc, x), k.Thetas[i])
	}
	return acc
}

// Received is how many of the q uses are gone.
func (k *MasterSecretKey) Received() int { return len(k.received) }

// ViewKey is what you hand an auditor: it can read amounts, never spend.
type ViewKey struct {
	Vdk Scalar
	Lpk []Point
}

// Account is one output on chain.
type Account struct {
	Pk    Point  // one-time public key f(s)*G
	Co    Point  // a*V + ck*W
	Ctxt  uint64 // encrypted amount (plain amount for a coinbase)
	Kappa int    // output index; 0 means coinbase
}

// IsMiner reports a coinbase account.
func (a Account) IsMiner() bool { return a.Kappa == 0 }

// HashItems is what the signature hashes for this account.
func (a Account) HashItems() curve.List {
	return curve.List{a.Pk, a.Co, a.Ctxt, a.Kappa}
}

// SAKGen makes an ordinary address with a degree-q polynomial.
func SAKGen(q int) (*MasterPublicKey, *MasterSecretKey, *ViewKey) {
	thetas := curve.RandomVector(q + 1)
	lpk := make([]Point, len(thetas))
	for i, t := range thetas {
		lpk[i] = curve.TagKGen(t)
	}
	vdk := curve.RandomScalar()
	mpk := &MasterPublicKey{Lpk: lpk, Vek: curve.KaMsg(vdk)}
	msk := &MasterSecretKey{Thetas: thetas, Vdk: vdk, Q: q, received: map[string]bool{}}
	return mpk, msk, &ViewKey{Vdk: vdk, Lpk: lpk}
}

// SAKGenMiner makes a miner address: q = 0, no view key. Use a fresh one per
// block; a reused one repeats the tag and the second coinbase is unspendable.
func SAKGenMiner() (*MasterPublicKey, *MasterSecretKey) {
	lsk := curve.RandomScalar()
	mpk := &MasterPublicKey{Lpk: []Point{curve.TagKGen(lsk)}, IsMiner: true}
	msk := &MasterSecretKey{Thetas: []Scalar{lsk}, Q: 0, received: map[string]bool{}}
	return mpk, msk
}

func derive(s Scalar) (pad uint64, ck Scalar) {
	h := curve.Hn("amount", s)
	b := h.Bytes()
	for i := 24; i < 32; i++ {
		pad = pad<<8 | uint64(b[i])
	}
	return pad, curve.Hn("commitment_mask", s)
}

func pkFromLpk(lpk []Point, s Scalar) Point {
	return curve.MultiExp(curve.Powers(s, len(lpk)), lpk)
}

// OTAccGen builds the receiver's coin. Pass the same tdk for every output of
// one transaction; kappa keeps their keys apart. Returns (ck, account, tek).
func OTAccGen(mpk *MasterPublicKey, a uint64, kappa int, tdk *Scalar) (Scalar, Account, *Point) {
	if kappa == 0 {
		if !mpk.IsMiner {
			panic("kappa = 0 is reserved for miner accounts")
		}
		return curve.S(1), Account{Pk: mpk.Lpk[0], Co: curve.Commit(curve.S(a), curve.S(1)), Ctxt: a, Kappa: 0}, nil
	}
	if mpk.IsMiner {
		panic("miner addresses only receive coinbase (kappa = 0)")
	}
	var d Scalar
	if tdk == nil {
		d = curve.RandomScalar()
	} else {
		d = *tdk
	}
	tek := curve.KaMsg(d)
	s := curve.KaKey(d, mpk.Vek, kappa)
	pad, ck := derive(s)
	acc := Account{Pk: pkFromLpk(mpk.Lpk, s), Co: curve.Commit(curve.S(a), ck), Ctxt: a ^ pad, Kappa: kappa}
	return ck, acc, &tek
}

func open(vdk Scalar, lpk []Point, acc Account, info *Point) (a uint64, ck, s Scalar, ok bool) {
	if acc.IsMiner() || info == nil {
		return 0, ck, s, false
	}
	s = curve.KaKey(vdk, *info, acc.Kappa)
	if !acc.Pk.Equal(pkFromLpk(lpk, s)) {
		return 0, ck, s, false // not ours
	}
	pad, ck := derive(s)
	a = acc.Ctxt ^ pad
	if !acc.Co.Equal(curve.Commit(curve.S(a), ck)) {
		return 0, ck, s, false // ours, but the sender lied about the amount
	}
	return a, ck, s, true
}

// View returns the amount, read-only.
func View(vk *ViewKey, acc Account, info *Point) (uint64, bool) {
	a, _, _, ok := open(vk.Vdk, vk.Lpk, acc, info)
	return a, ok
}

// Opened is what Receive returns: everything needed to spend the coin.
type Opened struct {
	Ck  Scalar
	A   uint64
	Sk  Scalar
	Tag Point
}

// Receive opens a coin if it's ours, and uses one of the key's q slots.
func Receive(msk *MasterSecretKey, mpk *MasterPublicKey, acc Account, info *Point) (*Opened, bool) {
	if mpk.IsMiner {
		if !acc.IsMiner() || !acc.Pk.Equal(mpk.Lpk[0]) {
			return nil, false
		}
		if !acc.Co.Equal(curve.Commit(curve.S(acc.Ctxt), curve.S(1))) {
			return nil, false
		}
		sk := msk.Thetas[0]
		return &Opened{Ck: curve.S(1), A: acc.Ctxt, Sk: sk, Tag: curve.TagEval(sk)}, true
	}
	a, ck, s, ok := open(msk.Vdk, mpk.Lpk, acc, info)
	if !ok {
		return nil, false
	}
	key := acc.Pk.Key()
	if !msk.received[key] {
		if len(msk.received) >= msk.Q {
			return nil, false // key exhausted
		}
		msk.received[key] = true
	}
	sk := msk.F(s)
	return &Opened{Ck: ck, A: a, Sk: sk, Tag: curve.TagEval(sk)}, true
}

// AmountBits re-exports the range for callers.
const AmountBits = nizk.AmountBits
