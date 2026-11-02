// Package nizk holds the Eq. 5 relation and the proof systems for it: the
// Σ-protocol with a Bulletproofs range proof (the real one) and a stub.
// It mirrors succinct/nizk in the Python version, including every transcript
// label, so proofs made by either version verify in the other.
package nizk

import (
	"succinctgo/curve"
)

type (
	Point  = curve.Point
	Scalar = curve.Scalar
)

// AmountBits is the paper's beta (bit length of amounts); AmountMask = 2^64 - 1.
const (
	AmountBits = 64
	AmountMask = ^uint64(0)
)

// TLabel names the generators of the vector commitment T.
const TLabel = "T"

// Statement is everything public the proof is about (relation.Statement).
type Statement struct {
	RingPks []Point // n points
	RingCos []Point // n points
	Tags    []Point // S points
	OutCos  []Point // output coins
	Fee     uint64
	Alphas  []Scalar // S MuSig weights
	Beta    Scalar   // challenge from H_b (not the amount bit length)
	H       Scalar
	Gamma   Scalar
	R       Point
	T       Point
}

// N is the ring size, NS the number of real inputs.
func (s *Statement) N() int  { return len(s.RingPks) }
func (s *Statement) NS() int { return len(s.Tags) }

// BaseZ is G + beta*U, the base z sits on.
func (s *Statement) BaseZ() Point { return curve.G.Add(curve.U.Mul(s.Beta)) }

// BaseCk is gamma*W, the base ck' sits on.
func (s *Statement) BaseCk() Point { return curve.W.Mul(s.Gamma) }

// Y is (alpha_j*h)*pk_i + gamma*co_i.
func (s *Statement) Y(j, i int) Point {
	return curve.MultiExp([]Scalar{curve.Mul(s.Alphas[j], s.H), s.Gamma},
		[]Point{s.RingPks[i], s.RingCos[i]})
}

// Target is R - (fee*gamma)*V + beta*h*sum_j alpha_j*tag_j - gamma*sum_k co_out_k.
func (s *Statement) Target() Point {
	hb := curve.Mul(s.H, s.Beta)
	coefs := make([]Scalar, len(s.Alphas))
	for j := range s.Alphas {
		coefs[j] = curve.Mul(s.Alphas[j], hb)
	}
	tagPart := curve.MultiExp(coefs, s.Tags)
	feeGamma := curve.Mul(curve.S(s.Fee), s.Gamma)
	return s.R.
		Sub(curve.V.Mul(feeGamma)).
		Add(tagPart).
		Sub(curve.PointSum(s.OutCos).Mul(s.Gamma))
}

// Witness is everything secret the spender knows (relation.Witness). The bit
// vectors and output amounts are plain integers, so a cheating witness (a 2 in
// a bit vector, an amount past 2^64) can still be written down and tested.
type Witness struct {
	Z          Scalar
	CkPrime    Scalar
	Bvecs      [][]int64 // S vectors of n bits
	T          Scalar    // blinding of T
	OutAmounts []int64   // may be negative in tests; the range proof must catch it
	OutCks     []Scalar
}

func flatBits(bvecs [][]int64) []Scalar {
	var out []Scalar
	for _, vec := range bvecs {
		for _, b := range vec {
			out = append(out, curve.SInt(b))
		}
	}
	return out
}

// CommitT is the vector commitment to (z, ck', b(1), ..., b(S)) with blinding t.
func CommitT(z, ckPrime Scalar, bvecs [][]int64, t Scalar) Point {
	values := append([]Scalar{z, ckPrime}, flatBits(bvecs)...)
	return curve.VectorCommit(values, t, TLabel)
}

// RelationHolds checks all four conditions directly. It is the stub's verifier
// and the oracle the real proof is tested against.
func RelationHolds(s *Statement, w *Witness) bool {
	// (2) one-hot vectors
	if len(w.Bvecs) != s.NS() {
		return false
	}
	idx := make([]int, len(w.Bvecs))
	for j, vec := range w.Bvecs {
		if len(vec) != s.N() {
			return false
		}
		ones := 0
		for i, b := range vec {
			if b != 0 && b != 1 {
				return false
			}
			if b == 1 {
				ones++
				idx[j] = i
			}
		}
		if ones != 1 {
			return false
		}
	}
	// (3) T opens to the same witness
	if !CommitT(w.Z, w.CkPrime, w.Bvecs, w.T).Equal(s.T) {
		return false
	}
	// (4) outputs open and are in range
	if len(w.OutAmounts) != len(w.OutCks) || len(w.OutAmounts) != len(s.OutCos) {
		return false
	}
	for k, a := range w.OutAmounts {
		if a < 0 {
			return false
		}
		if !curve.Commit(curve.S(uint64(a)), w.OutCks[k]).Equal(s.OutCos[k]) {
			return false
		}
	}
	// (1) Eq. 5; only the positions where b = 1 contribute.
	lhs := s.BaseZ().Mul(w.Z).Add(s.BaseCk().Mul(w.CkPrime))
	for j := range w.Bvecs {
		lhs = lhs.Sub(s.Y(j, idx[j]))
	}
	return lhs.Equal(s.Target())
}

// Proof is whatever a proof system produces.
type Proof any

// System is the interface Spend and Verify use: prove and verify Eq. 5.
type System interface {
	Name() string
	Prove(s *Statement, w *Witness) (Proof, error)
	Verify(s *Statement, p Proof) bool
}

// Stub is the placeholder proof: the "proof" is the witness itself. NOT
// zero-knowledge; it exists for fast tests and attack runs.
type Stub struct{}

func (Stub) Name() string { return "stub (witness in the clear, NOT private)" }
func (Stub) Prove(s *Statement, w *Witness) (Proof, error) {
	return w, nil
}
func (Stub) Verify(s *Statement, p Proof) bool {
	w, ok := p.(*Witness)
	return ok && RelationHolds(s, w)
}
