package nizk

import (
	"testing"

	"succinctgo/curve"
)

func TestBPPLayout(t *testing.T) {
	for _, c := range []struct{ n, S, m, L, r int }{
		{128, 1, 2, 256, 5},   // final 8 scalars
		{1024, 1, 2, 1152, 8}, // 1152 = 4.5*256 -> 1280? no: 1152 = 9*128, r=8 -> 5*256
		{8, 1, 2, 136, 5},
	} {
		size, L, r := bppLayout(c.n, c.S, c.m)
		if size != c.S*c.n+64*c.m || L%(1<<r) != 0 || L>>r > 8 || L < size {
			t.Errorf("layout(%d,%d,%d) = %d, %d, %d", c.n, c.S, c.m, size, L, r)
		}
	}
}

func TestBPPAcceptsHonest(t *testing.T) {
	for _, n := range []int{1, 2, 5, 8, 16} {
		st, w := honest(t, n, n-1)
		p, err := BPP{}.Prove(st, w)
		if err != nil || !(BPP{}).Verify(st, p) {
			t.Fatalf("n=%d: honest proof rejected (%v)", n, err)
		}
	}
}

func TestBPPRejectsBadWitnesses(t *testing.T) {
	bad := map[string]func(*Statement, *Witness){
		"wrong position": func(s *Statement, w *Witness) {
			w.Bvecs = [][]int64{{1, 0, 0, 0, 0}}
			w.T = curve.RandomScalar()
			s.T = CommitT(w.Z, w.CkPrime, w.Bvecs, w.T)
		},
		"bit is 2": func(s *Statement, w *Witness) {
			w.Bvecs = [][]int64{{0, 0, 0, 0, 2}}
			s.T = CommitT(w.Z, w.CkPrime, w.Bvecs, w.T)
		},
		"two ones": func(s *Statement, w *Witness) {
			w.Bvecs = [][]int64{{0, 0, 0, 1, 1}}
			s.T = CommitT(w.Z, w.CkPrime, w.Bvecs, w.T)
		},
		"no ones": func(s *Statement, w *Witness) {
			w.Bvecs = [][]int64{{0, 0, 0, 0, 0}}
			s.T = CommitT(w.Z, w.CkPrime, w.Bvecs, w.T)
		},
		"T opens to something else": func(s *Statement, w *Witness) { w.Z = curve.Add(w.Z, curve.S(1)) },
		"negative output": func(s *Statement, w *Witness) {
			w.OutAmounts = []int64{150, -51}
			s.OutCos = []Point{curve.Commit(curve.S(150), w.OutCks[0]), curve.Commit(curve.SInt(-51), w.OutCks[1])}
		},
		"fee changed":       func(s *Statement, w *Witness) { s.Fee = 0 },
		"output overstated": func(s *Statement, w *Witness) { w.OutAmounts[0]++ },
	}
	for name, edit := range bad {
		st, w := honest(t, 5, 4)
		edit(st, w)
		if RelationHolds(st, w) {
			t.Errorf("%s: the oracle accepts it", name)
		}
		p, err := BPP{}.Prove(st, w)
		if err == nil && (BPP{}).Verify(st, p) {
			t.Errorf("%s: the proof verifies", name)
		}
	}
}

// Change one part of an honest proof at a time; every change must be caught.
func TestBPPRejectsTampering(t *testing.T) {
	st, w := honest(t, 16, 3)
	pr, err := BPP{}.Prove(st, w)
	if err != nil {
		t.Fatal(err)
	}
	orig := pr.(*BPPProof)
	clone := func() *BPPProof {
		c := *orig
		c.Ek = append([]Point{}, orig.Ek...)
		c.Abar = append([]Scalar{}, orig.Abar...)
		c.Sk = append([]Scalar{}, orig.Sk...)
		c.Xs = append([]Point{}, orig.Xs...)
		c.Rs = append([]Point{}, orig.Rs...)
		c.X2s = append([]Point{}, orig.X2s...)
		c.R2s = append([]Point{}, orig.R2s...)
		c.N = append([]Scalar{}, orig.N...)
		return &c
	}
	one := curve.S(1)
	bump := func(p Point) Point { return p.Add(curve.G) }
	edits := map[string]func(*BPPProof){
		"B": func(p *BPPProof) { p.B = bump(p.B) }, "A": func(p *BPPProof) { p.A = bump(p.A) },
		"E0": func(p *BPPProof) { p.E0 = bump(p.E0) }, "C": func(p *BPPProof) { p.C = bump(p.C) },
		"D": func(p *BPPProof) { p.D = bump(p.D) }, "Ek": func(p *BPPProof) { p.Ek[1] = bump(p.Ek[1]) },
		"abar": func(p *BPPProof) { p.Abar[0] = curve.Add(p.Abar[0], one) },
		"sz":   func(p *BPPProof) { p.Sz = curve.Add(p.Sz, one) },
		"sck":  func(p *BPPProof) { p.Sck = curve.Add(p.Sck, one) },
		"sw":   func(p *BPPProof) { p.Sw = curve.Add(p.Sw, one) },
		"scd":  func(p *BPPProof) { p.Scd = curve.Add(p.Scd, one) },
		"sk":   func(p *BPPProof) { p.Sk[0] = curve.Add(p.Sk[0], one) },
		"X":    func(p *BPPProof) { p.Xs[2] = bump(p.Xs[2]) }, "R": func(p *BPPProof) { p.Rs[0] = bump(p.Rs[0]) },
		"X2": func(p *BPPProof) { p.X2s[1] = bump(p.X2s[1]) }, "R2": func(p *BPPProof) { p.R2s[2] = bump(p.R2s[2]) },
		"final n":      func(p *BPPProof) { p.N[0] = curve.Add(p.N[0], one) },
		"drop a round": func(p *BPPProof) { p.Xs = p.Xs[1:] },
	}
	if !(BPP{}).Verify(st, orig) {
		t.Fatal("honest proof rejected")
	}
	for name, edit := range edits {
		c := clone()
		edit(c)
		if (BPP{}).Verify(st, c) {
			t.Errorf("tampered %s still verifies", name)
		}
	}
	// and the proof is tied to its statement
	st2 := *st
	st2.Fee = st.Fee + 1
	if (BPP{}).Verify(&st2, orig) {
		t.Error("proof verifies for a different fee")
	}
	if (Sigma{}).Verify(st, orig) || (BPP{}).Verify(st, &RingProof{}) {
		t.Error("proof types got mixed up")
	}
}

// Two inputs share the ring; both one-hot vectors and the bits are checked.
func TestBPPTwoInputs(t *testing.T) {
	st, w := honestMulti(t, 8, []int{2, 6})
	p, err := BPP{}.Prove(st, w)
	if err != nil || !(BPP{}).Verify(st, p) {
		t.Fatalf("honest two-input proof rejected (%v)", err)
	}
	w.Bvecs[1] = []int64{0, 0, 0, 0, 0, 0, 0, 0} // second input points nowhere
	st.T = CommitT(w.Z, w.CkPrime, w.Bvecs, w.T)
	p, err = BPP{}.Prove(st, w)
	if err == nil && (BPP{}).Verify(st, p) {
		t.Fatal("empty second one-hot vector verified")
	}
}

// honestMulti is honest() with several inputs at the given ring positions.
func honestMulti(t *testing.T, n int, pos []int) (*Statement, *Witness) {
	t.Helper()
	ringPks := make([]Point, n)
	ringCos := make([]Point, n)
	for i := range ringPks {
		ringPks[i] = curve.G.Mul(curve.RandomScalar())
		ringCos[i] = curve.Commit(curve.S(100), curve.RandomScalar())
	}
	nS := len(pos)
	alphas := make([]Scalar, nS)
	tags := make([]Point, nS)
	var ckIn, hsk Scalar
	sks := make([]Scalar, nS)
	for j, i := range pos {
		sks[j] = curve.RandomScalar()
		ck := curve.RandomScalar()
		ckIn = curve.Add(ckIn, ck)
		ringPks[i] = curve.TagKGen(sks[j])
		ringCos[i] = curve.Commit(curve.S(100), ck)
		tags[j] = curve.TagEval(sks[j])
		alphas[j] = curve.Ha("test", j)
	}
	beta := curve.Hb(alphas)
	r := curve.RandomScalar()
	R := curve.G.Add(curve.U.Mul(beta)).Mul(r)
	h := curve.H("test", R)
	for j := range sks {
		hsk = curve.Add(hsk, curve.Mul(alphas[j], sks[j]))
	}
	z := curve.Add(r, curve.Mul(h, hsk))
	ck1, ck2 := curve.RandomScalar(), curve.RandomScalar()
	total := int64(100*nS - 1)
	outs := []Point{curve.Commit(curve.S(60), ck1), curve.Commit(curve.SInt(total-60), ck2)}
	ckPrime := curve.Sub(ckIn, curve.Add(ck1, ck2))
	bvecs := make([][]int64, nS)
	for j, i := range pos {
		bvecs[j] = make([]int64, n)
		bvecs[j][i] = 1
	}
	tb := curve.RandomScalar()
	T := CommitT(z, ckPrime, bvecs, tb)
	gamma := curve.Hc(h, T)
	st := &Statement{RingPks: ringPks, RingCos: ringCos, Tags: tags, OutCos: outs, Fee: 1,
		Alphas: alphas, Beta: beta, H: h, Gamma: gamma, R: R, T: T}
	w := &Witness{Z: z, CkPrime: ckPrime, Bvecs: bvecs, T: tb,
		OutAmounts: []int64{60, total - 60}, OutCks: []Scalar{ck1, ck2}}
	if !RelationHolds(st, w) {
		t.Fatal("honestMulti built a bad witness")
	}
	return st, w
}

// With the real input duplicated at positions 3 and 4, b = (0,0,0,2,-1) passes
// Eq. 5 (2Y - Y = Y), the one-hot sum (2 - 1 = 1) and T. Only the bit check
// (b - 1/2)^2 = 1/4 can catch it, so this tests that check on its own.
func TestBPPBitCheckAlone(t *testing.T) {
	st, w := honest(t, 5, 4)
	st.RingPks[3], st.RingCos[3] = st.RingPks[4], st.RingCos[4]
	w.Bvecs = [][]int64{{0, 0, 0, 2, -1}}
	st.T = CommitT(w.Z, w.CkPrime, w.Bvecs, w.T)
	if RelationHolds(st, w) {
		t.Fatal("oracle accepts non-bits")
	}
	// the linear parts really do hold, so nothing else can be what rejects it
	lhs := st.BaseZ().Mul(w.Z).Add(st.BaseCk().Mul(w.CkPrime)).Sub(st.Y(0, 3).Mul(curve.S(2))).Add(st.Y(0, 4))
	if !lhs.Equal(st.Target()) {
		t.Fatal("setup wrong: Eq. 5 should hold for the fake vector")
	}
	for i := 0; i < 5; i++ {
		p, err := BPP{}.Prove(st, w)
		if err == nil && (BPP{}).Verify(st, p) {
			t.Fatal("non-bit vector verified")
		}
	}
	// and the honest vector in the same ring still verifies
	w.Bvecs = [][]int64{{0, 0, 0, 0, 1}}
	st.T = CommitT(w.Z, w.CkPrime, w.Bvecs, w.T)
	p, _ := BPP{}.Prove(st, w)
	if !(BPP{}).Verify(st, p) {
		t.Fatal("honest proof rejected in duplicated ring")
	}
}
