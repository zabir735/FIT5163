package nizk

import (
	"testing"

	"succinctgo/curve"
)

// A small honest statement + witness for Eq. 5, built directly (no chain), so
// the proof can be checked against RelationHolds the way tests/test_nizk.py does.
func honest(t *testing.T, n, real int) (*Statement, *Witness) {
	t.Helper()
	sk := curve.RandomScalar()
	ringPks := make([]Point, n)
	ringCos := make([]Point, n)
	for i := range ringPks {
		ringPks[i] = curve.G.Mul(curve.RandomScalar())
		ringCos[i] = curve.Commit(curve.S(100), curve.RandomScalar())
	}
	ckIn := curve.RandomScalar()
	ringPks[real] = curve.TagKGen(sk)
	ringCos[real] = curve.Commit(curve.S(100), ckIn)
	tag := curve.TagEval(sk)
	ck1, ck2 := curve.RandomScalar(), curve.RandomScalar()
	outs := []Point{curve.Commit(curve.S(60), ck1), curve.Commit(curve.S(39), ck2)}

	alpha := curve.Ha("test", 1)
	beta := curve.Hb([]Scalar{alpha})
	r := curve.RandomScalar()
	R := curve.G.Add(curve.U.Mul(beta)).Mul(r)
	h := curve.H("test", R)
	z := curve.Add(r, curve.Mul(h, curve.Mul(alpha, sk)))
	ckPrime := curve.Sub(ckIn, curve.Add(ck1, ck2))
	bv := make([]int64, n)
	bv[real] = 1
	tb := curve.RandomScalar()
	T := CommitT(z, ckPrime, [][]int64{bv}, tb)
	gamma := curve.Hc(h, T)
	st := &Statement{RingPks: ringPks, RingCos: ringCos, Tags: []Point{tag}, OutCos: outs, Fee: 1,
		Alphas: []Scalar{alpha}, Beta: beta, H: h, Gamma: gamma, R: R, T: T}
	w := &Witness{Z: z, CkPrime: ckPrime, Bvecs: [][]int64{bv}, T: tb,
		OutAmounts: []int64{60, 39}, OutCks: []Scalar{ck1, ck2}}
	return st, w
}

func TestSigmaAcceptsHonestAndMatchesOracle(t *testing.T) {
	for _, n := range []int{1, 2, 5, 8} {
		st, w := honest(t, n, n-1)
		if !RelationHolds(st, w) {
			t.Fatalf("n=%d: honest witness fails the relation", n)
		}
		p, err := Sigma{}.Prove(st, w)
		if err != nil || !(Sigma{}).Verify(st, p) {
			t.Fatalf("n=%d: honest proof rejected (%v)", n, err)
		}
	}
}

func TestSigmaRejectsBadWitnesses(t *testing.T) {
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
		"T opens to something else": func(s *Statement, w *Witness) { w.Z = curve.Add(w.Z, curve.S(1)) },
		"negative output": func(s *Statement, w *Witness) {
			// -51 and 150 still balance, but -51 wraps around: the range proof must catch it
			w.OutAmounts = []int64{150, -51}
			s.OutCos = []Point{curve.Commit(curve.S(150), w.OutCks[0]), curve.Commit(curve.SInt(-51), w.OutCks[1])}
		},
		"fee changed": func(s *Statement, w *Witness) { s.Fee = 0 },
	}
	for name, edit := range bad {
		st, w := honest(t, 5, 4)
		edit(st, w)
		if RelationHolds(st, w) {
			t.Errorf("%s: the oracle accepts it", name)
		}
		p, err := Sigma{}.Prove(st, w)
		if err == nil && (Sigma{}).Verify(st, p) {
			t.Errorf("%s: the proof verifies", name)
		}
	}
}

func TestRangeProofEdges(t *testing.T) {
	for _, a := range []int64{0, 1, 1<<62 + 12345} {
		ck := curve.RandomScalar()
		co := curve.Commit(curve.SInt(a), ck)
		p, err := RangeProve([]int64{a}, []Scalar{ck}, curve.NewTranscript("rp"), AmountBits)
		if err != nil || !RangeVerify([]Point{co}, p, curve.NewTranscript("rp"), AmountBits) {
			t.Fatalf("amount %d: honest range proof rejected", a)
		}
		if RangeVerify([]Point{co}, p, curve.NewTranscript("other"), AmountBits) {
			t.Fatal("range proof verified under another transcript")
		}
	}
}
