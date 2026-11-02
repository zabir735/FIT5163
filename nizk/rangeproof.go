package nizk

import (
	"errors"

	"succinctgo/curve"
)

// Aggregated Bulletproofs range proof (Bünz et al. 2018, §4.3): every output
// coin co_k = a_k*V + ck_k*W has 0 <= a_k < 2^bits. Same labels and padding as
// nizk/rangeproof.py.

const (
	bpGLabel = "BP/g"
	bpHLabel = "BP/h"
)

// UIPA is the inner-product argument's extra base.
var UIPA = curve.HashToPoint("BP/u")

// RangeProof is the aggregated range proof.
type RangeProof struct {
	A, S, T1, T2   Point
	TauX, Mu, THat Scalar
	IPA            *InnerProductProof
}

func padded(m int) int {
	p := 1
	for p < m {
		p *= 2
	}
	return p
}

// blockWeights: d_i = z^(2+j) * 2^k for i = j*bits + k.
func blockWeights(z Scalar, m, bits int) []Scalar {
	two := curve.Powers(curve.S(2), bits)
	zj := curve.Powers(z, m+2)[2:]
	out := make([]Scalar, 0, m*bits)
	for j := 0; j < m; j++ {
		for k := 0; k < bits; k++ {
			out = append(out, curve.Mul(zj[j], two[k]))
		}
	}
	return out
}

// delta(y, z) = (z - z^2) * <1, y^N> - sum_j z^(3+j) * (2^bits - 1).
func delta(y, z Scalar, m, bits int) Scalar {
	n := m * bits
	sumY := curve.Sum(curve.Powers(y, n))
	sum2 := curve.FromBig(new2Pow(bits))
	sumZ := curve.Sum(curve.Powers(z, m+3)[3:])
	zz := curve.Mul(z, z)
	return curve.Sub(curve.Mul(curve.Sub(z, zz), sumY), curve.Mul(sumZ, sum2))
}

// RangeProve proves the amounts behind the commitments. Like the Python
// version it never refuses an out-of-range amount: the proof just won't verify.
func RangeProve(amounts []int64, blindings []Scalar, t *curve.Transcript, bits int) (*RangeProof, error) {
	m := len(amounts)
	if m < 1 || len(blindings) != m || !curve.IsPowerOfTwo(bits) {
		return nil, errors.New("need one blinding per amount, and bits a power of two")
	}
	mp := padded(m)
	values := make([]Scalar, mp)
	gammas := make([]Scalar, mp)
	for k := 0; k < m; k++ {
		values[k] = curve.SInt(amounts[k])
		gammas[k] = blindings[k]
	}
	n := mp * bits
	g, h := curve.GeneratorVector(bpGLabel, n), curve.GeneratorVector(bpHLabel, n)

	vs := make([]Point, mp)
	for k := range vs {
		vs[k] = curve.Commit(values[k], gammas[k])
	}
	t.Append("bp/V", vs)

	// Bits of each value, low bit first. A value >= 2^bits is silently
	// truncated; the resulting proof won't verify.
	aL := make([]Scalar, 0, n)
	for _, v := range values {
		vb := curve.ToBig(v)
		for k := 0; k < bits; k++ {
			aL = append(aL, curve.S(uint64(vb.Bit(k))))
		}
	}
	one := curve.S(1)
	aR := make([]Scalar, n)
	for i := range aL {
		aR[i] = curve.Sub(aL[i], one)
	}
	alpha := curve.RandomScalar()
	A := curve.MultiExp(concatS(aL, aR, []Scalar{alpha}), concatP(g, h, []Point{curve.W}))

	sL, sR := curve.RandomVector(n), curve.RandomVector(n)
	rho := curve.RandomScalar()
	S := curve.MultiExp(concatS(sL, sR, []Scalar{rho}), concatP(g, h, []Point{curve.W}))

	t.Append("bp/A", A)
	t.Append("bp/S", S)
	y := t.Challenge("bp/y")
	z := t.Challenge("bp/z")
	if y.IsZero() {
		return nil, errors.New("zero challenge")
	}

	yN := curve.Powers(y, n)
	d := blockWeights(z, mp, bits)
	l0, l1 := make([]Scalar, n), sL
	r0, r1 := make([]Scalar, n), make([]Scalar, n)
	for i := 0; i < n; i++ {
		l0[i] = curve.Sub(aL[i], z)
		r0[i] = curve.Add(curve.Mul(yN[i], curve.Add(aR[i], z)), d[i])
		r1[i] = curve.Mul(yN[i], sR[i])
	}
	t1 := curve.Add(curve.Inner(l0, r1), curve.Inner(l1, r0))
	t2 := curve.Inner(l1, r1)

	tau1, tau2 := curve.RandomScalar(), curve.RandomScalar()
	T1 := curve.MultiExp([]Scalar{t1, tau1}, []Point{curve.V, curve.W})
	T2 := curve.MultiExp([]Scalar{t2, tau2}, []Point{curve.V, curve.W})
	t.Append("bp/T1", T1)
	t.Append("bp/T2", T2)
	x := t.Challenge("bp/x")

	l, r := make([]Scalar, n), make([]Scalar, n)
	for i := 0; i < n; i++ {
		l[i] = curve.Add(l0[i], curve.Mul(l1[i], x))
		r[i] = curve.Add(r0[i], curve.Mul(r1[i], x))
	}
	tHat := curve.Inner(l, r)
	zj := curve.Powers(z, mp+2)[2:]
	tauX := curve.Add(curve.Add(curve.Mul(tau2, curve.Mul(x, x)), curve.Mul(tau1, x)), curve.Inner(zj, gammas))
	mu := curve.Add(alpha, curve.Mul(rho, x))

	t.Append("bp/tau_x", tauX)
	t.Append("bp/mu", mu)
	t.Append("bp/t_hat", tHat)
	w := t.Challenge("bp/w")

	yInv := curve.Powers(curve.Inv(y), n)
	hPrime := make([]Point, n)
	for i := range h {
		hPrime[i] = h[i].Mul(yInv[i])
	}
	ipa, err := IPAProve(g, hPrime, UIPA.Mul(w), l, r, t)
	if err != nil {
		return nil, err
	}
	return &RangeProof{A: A, S: S, T1: T1, T2: T2, TauX: tauX, Mu: mu, THat: tHat, IPA: ipa}, nil
}

// RangeVerify checks the proof against the output commitments.
func RangeVerify(commitments []Point, p *RangeProof, t *curve.Transcript, bits int) bool {
	m := len(commitments)
	if m < 1 || p == nil || p.IPA == nil || !curve.IsPowerOfTwo(bits) {
		return false
	}
	mp := padded(m)
	vs := append(append([]Point{}, commitments...), make([]Point, mp-m)...)
	n := mp * bits
	g, h := curve.GeneratorVector(bpGLabel, n), curve.GeneratorVector(bpHLabel, n)

	t.Append("bp/V", vs)
	t.Append("bp/A", p.A)
	t.Append("bp/S", p.S)
	y := t.Challenge("bp/y")
	z := t.Challenge("bp/z")
	t.Append("bp/T1", p.T1)
	t.Append("bp/T2", p.T2)
	x := t.Challenge("bp/x")
	t.Append("bp/tau_x", p.TauX)
	t.Append("bp/mu", p.Mu)
	t.Append("bp/t_hat", p.THat)
	w := t.Challenge("bp/w")
	if y.IsZero() {
		return false
	}

	// (1) t_hat*V + tau_x*W == sum_j z^(2+j)*V_j + delta*V + x*T1 + x^2*T2
	zj := curve.Powers(z, mp+2)[2:]
	dl := delta(y, z, mp, bits)
	sc := []Scalar{curve.Sub(p.THat, dl), p.TauX}
	for _, c := range zj {
		sc = append(sc, curve.Neg(c))
	}
	sc = append(sc, curve.Neg(x), curve.Neg(curve.Mul(x, x)))
	pts := concatP([]Point{curve.V, curve.W}, vs, []Point{p.T1, p.T2})
	if !curve.MultiExp(sc, pts).IsIdentity() {
		return false
	}

	// (2) the inner-product argument, folded into one multi-exponentiation.
	xs, s, ok := IPAVerificationScalars(p.IPA, n, t)
	if !ok {
		return false
	}
	a, b := p.IPA.A, p.IPA.B
	yInv := curve.Powers(curve.Inv(y), n)
	d := blockWeights(z, mp, bits)

	gCoef := make([]Scalar, n)
	hCoef := make([]Scalar, n)
	for i := 0; i < n; i++ {
		gCoef[i] = curve.Neg(curve.Add(z, curve.Mul(a, s[i])))
		hCoef[i] = curve.Add(z, curve.Mul(curve.Sub(d[i], curve.Mul(b, s[n-1-i])), yInv[i]))
	}
	lrS, lrP := IPALRTerms(p.IPA, xs)
	scalars := concatS([]Scalar{curve.S(1), x, curve.Neg(p.Mu), curve.Mul(w, curve.Sub(p.THat, curve.Mul(a, b)))},
		lrS, gCoef, hCoef)
	points := concatP([]Point{p.A, p.S, curve.W, UIPA}, lrP, g, h)
	return curve.MultiExp(scalars, points).IsIdentity()
}
