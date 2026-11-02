package nizk

import (
	"errors"
	"math/big"

	"succinctgo/curve"
)

// Linear-size Σ-protocol (Fiat-Shamir) for the Eq. 5 relation, a line-by-line
// port of nizk/sigma_ring.py; see that file's docstring for why each check is
// there. Proof size: 4 points + S(n-1) + 4 scalars + the range proof.

const sigmaTranscriptLabel = "SuccinCT/sigma-eq5"

// RingProof is the Σ-protocol proof plus its range proof.
type RingProof struct {
	A, C, D, E         Point
	F                  [][]Scalar // S rows of n-1 scalars: f_(j,i) for i = 1..n-1
	Sz, Sck, St, Sbits Scalar
	Range              *RangeProof
}

// Sigma is the real proof system.
type Sigma struct{}

func (Sigma) Name() string {
	return "Σ-protocol for Eq. 5 (linear size) + Bulletproofs range proof"
}

func new2Pow(bits int) *big.Int {
	v := new(big.Int).Lsh(big.NewInt(1), uint(bits))
	return v.Sub(v, big.NewInt(1))
}

func sigmaTranscript(s *Statement) *curve.Transcript {
	t := curve.NewTranscript(sigmaTranscriptLabel)
	t.Append("ring_pks", s.RingPks)
	t.Append("ring_cos", s.RingCos)
	t.Append("tags", s.Tags)
	t.Append("out_cos", s.OutCos)
	t.Append("fee", s.Fee)
	t.Append("alphas", s.Alphas)
	t.Append("beta", s.Beta)
	t.Append("h", s.H)
	t.Append("gamma", s.Gamma)
	t.Append("R", s.R)
	t.Append("T", s.T)
	return t
}

func tGenerators(s *Statement) []Point {
	return curve.GeneratorVector(TLabel, 2+s.NS()*s.N())
}

// sumY is sum_(j,i) coeffs[j][i] * Y(j, i) using 2n scalar multiplications.
func sumY(s *Statement, coeffs [][]Scalar) Point {
	n := s.N()
	sc := make([]Scalar, 2*n)
	for i := 0; i < n; i++ {
		var pk, co Scalar
		for j := range coeffs {
			t := curve.Mul(s.Alphas[j], coeffs[j][i])
			pk.Add(&t)
			co.Add(&coeffs[j][i])
		}
		sc[i] = curve.Mul(s.H, pk)
		sc[n+i] = curve.Mul(s.Gamma, co)
	}
	return curve.MultiExp(sc, concatP(s.RingPks, s.RingCos))
}

// Prove never refuses a bad witness; it returns a proof that fails to verify.
// Only a witness of the wrong shape is an error.
func (Sigma) Prove(s *Statement, w *Witness) (Proof, error) {
	nS, n := s.NS(), s.N()
	if len(w.Bvecs) != nS {
		return nil, errors.New("witness bit vectors don't match the statement's S x n")
	}
	for _, v := range w.Bvecs {
		if len(v) != n {
			return nil, errors.New("witness bit vectors don't match the statement's S x n")
		}
	}
	if n < 1 {
		return nil, errors.New("empty ring")
	}

	t := sigmaTranscript(s)
	rp, err := RangeProve(w.OutAmounts, w.OutCks, t, AmountBits)
	if err != nil {
		return nil, err
	}

	b := make([][]Scalar, nS)
	a := make([][]Scalar, nS)
	var flatA, flatB []Scalar
	for j := 0; j < nS; j++ {
		b[j] = make([]Scalar, n)
		for i, v := range w.Bvecs[j] {
			b[j][i] = curve.SInt(v)
		}
		rest := curve.RandomVector(n - 1)
		a[j] = append([]Scalar{curve.Neg(curve.Sum(rest))}, rest...)
		flatA = append(flatA, a[j]...)
		flatB = append(flatB, b[j]...)
	}

	rz, rck, rA, rC, rD := curve.RandomScalar(), curve.RandomScalar(), curve.RandomScalar(), curve.RandomScalar(), curve.RandomScalar()
	gens := tGenerators(s)
	bitGens := gens[2:]

	A := curve.MultiExp(concatS([]Scalar{rz, rck}, flatA, []Scalar{rA}), concatP(gens, []Point{curve.W}))
	cCoef := make([]Scalar, len(flatA))
	dCoef := make([]Scalar, len(flatA))
	one, two := curve.S(1), curve.S(2)
	for i := range flatA {
		cCoef[i] = curve.Mul(flatA[i], curve.Sub(one, curve.Mul(two, flatB[i])))
		dCoef[i] = curve.Neg(curve.Mul(flatA[i], flatA[i]))
	}
	C := curve.MultiExp(append(cCoef, rC), concatP(bitGens, []Point{curve.W}))
	D := curve.MultiExp(append(dCoef, rD), concatP(bitGens, []Point{curve.W}))
	E := curve.MultiExp([]Scalar{rz, rck}, []Point{s.BaseZ(), s.BaseCk()}).Sub(sumY(s, a))

	t.Append("A", A)
	t.Append("C", C)
	t.Append("D", D)
	t.Append("E", E)
	x := t.Challenge("x")

	f := make([][]Scalar, nS)
	for j := 0; j < nS; j++ {
		f[j] = make([]Scalar, n-1)
		for i := 1; i < n; i++ {
			f[j][i-1] = curve.Add(curve.Mul(b[j][i], x), a[j][i])
		}
	}
	return &RingProof{
		A: A, C: C, D: D, E: E, F: f,
		Sz:    curve.Add(curve.Mul(w.Z, x), rz),
		Sck:   curve.Add(curve.Mul(w.CkPrime, x), rck),
		St:    curve.Add(curve.Mul(w.T, x), rA),
		Sbits: curve.Add(curve.Mul(rC, x), rD),
		Range: rp,
	}, nil
}

func wellFormed(s *Statement, p *RingProof) bool {
	if p == nil || p.Range == nil || len(p.F) != s.NS() {
		return false
	}
	for _, row := range p.F {
		if len(row) != s.N()-1 {
			return false
		}
	}
	return true
}

// Verify checks the range proof, then (i)+rho*(ii), then (iii).
func (Sigma) Verify(s *Statement, proof Proof) bool {
	p, ok := proof.(*RingProof)
	if !ok || s.NS() < 1 || s.N() < 1 || !wellFormed(s, p) {
		return false
	}
	t := sigmaTranscript(s)
	if !RangeVerify(s.OutCos, p.Range, t, AmountBits) {
		return false
	}
	t.Append("A", p.A)
	t.Append("C", p.C)
	t.Append("D", p.D)
	t.Append("E", p.E)
	x := t.Challenge("x")

	f := make([][]Scalar, len(p.F))
	var flatF []Scalar
	for j, row := range p.F {
		f[j] = append([]Scalar{curve.Sub(x, curve.Sum(row))}, row...)
		flatF = append(flatF, f[j]...)
	}

	// (i) + rho*(ii), sharing the bases g_(j,i) and W.
	rho := curve.RandomScalar()
	gens := tGenerators(s)
	bitCoef := make([]Scalar, len(flatF))
	for i, fi := range flatF {
		bitCoef[i] = curve.Neg(curve.Add(fi, curve.Mul(rho, curve.Mul(fi, curve.Sub(x, fi)))))
	}
	sc := concatS(
		[]Scalar{x, curve.S(1), curve.Mul(rho, x), rho, curve.Neg(p.Sz), curve.Neg(p.Sck)},
		bitCoef,
		[]Scalar{curve.Neg(curve.Add(p.St, curve.Mul(rho, p.Sbits)))},
	)
	pts := concatP([]Point{s.T, p.A, p.C, p.D, gens[0], gens[1]}, gens[2:], []Point{curve.W})
	if !curve.MultiExp(sc, pts).IsIdentity() {
		return false
	}

	// (iii) x*P + E - s_z*B_z - s_ck*B_ck + sum f*Y == identity
	check := curve.MultiExp([]Scalar{x, curve.S(1), curve.Neg(p.Sz), curve.Neg(p.Sck)},
		[]Point{s.Target(), p.E, s.BaseZ(), s.BaseCk()}).Add(sumY(s, f))
	return check.IsIdentity()
}
