package nizk

import (
	"errors"

	"succinctgo/curve"
)

// InnerProductProof is the Bulletproofs inner-product argument (Bünz et al.
// 2018, Protocol 2 with Fiat-Shamir): 2*log2(n) points and 2 scalars.
type InnerProductProof struct {
	L, R []Point
	A, B Scalar
}

// IPAProve proves knowledge of a, b with P = <a, g> + <b, h> + <a, b>*u. The
// caller must already have bound P (or what it's built from) into t.
func IPAProve(g, h []Point, u Point, a, b []Scalar, t *curve.Transcript) (*InnerProductProof, error) {
	n := len(a)
	if len(g) != n || len(h) != n || len(b) != n || !curve.IsPowerOfTwo(n) {
		return nil, errors.New("g, h, a, b must all have the same power-of-two length")
	}
	g = append([]Point{}, g...)
	h = append([]Point{}, h...)
	a = append([]Scalar{}, a...)
	b = append([]Scalar{}, b...)

	proof := &InnerProductProof{}
	for n > 1 {
		n /= 2
		aLo, aHi, bLo, bHi := a[:n], a[n:], b[:n], b[n:]
		gLo, gHi, hLo, hHi := g[:n], g[n:], h[:n], h[n:]

		L := curve.MultiExp(concatS(aLo, bHi, []Scalar{curve.Inner(aLo, bHi)}), concatP(gHi, hLo, []Point{u}))
		R := curve.MultiExp(concatS(aHi, bLo, []Scalar{curve.Inner(aHi, bLo)}), concatP(gLo, hHi, []Point{u}))
		proof.L = append(proof.L, L)
		proof.R = append(proof.R, R)
		t.Append("ipa/L", L)
		t.Append("ipa/R", R)
		x := t.Challenge("ipa/x")
		if x.IsZero() {
			return nil, errors.New("zero challenge")
		}
		xi := curve.Inv(x)

		ng, nh := make([]Point, n), make([]Point, n)
		na, nb := make([]Scalar, n), make([]Scalar, n)
		for i := 0; i < n; i++ {
			ng[i] = curve.MultiExp([]Scalar{xi, x}, []Point{gLo[i], gHi[i]})
			nh[i] = curve.MultiExp([]Scalar{x, xi}, []Point{hLo[i], hHi[i]})
			na[i] = curve.Add(curve.Mul(aLo[i], x), curve.Mul(aHi[i], xi))
			nb[i] = curve.Add(curve.Mul(bLo[i], xi), curve.Mul(bHi[i], x))
		}
		g, h, a, b = ng, nh, na, nb
	}
	proof.A, proof.B = a[0], b[0]
	return proof, nil
}

// IPAVerificationScalars replays the transcript. s[i] is the coefficient of
// g_i in the folded generator; the coefficient of h_i is 1/s[i] = s[n-1-i].
func IPAVerificationScalars(p *InnerProductProof, n int, t *curve.Transcript) ([]Scalar, []Scalar, bool) {
	if p == nil || !curve.IsPowerOfTwo(n) {
		return nil, nil, false
	}
	rounds := 0
	for m := n; m > 1; m /= 2 {
		rounds++
	}
	if len(p.L) != rounds || len(p.R) != rounds {
		return nil, nil, false
	}
	xs := make([]Scalar, rounds)
	for k := range p.L {
		t.Append("ipa/L", p.L[k])
		t.Append("ipa/R", p.R[k])
		x := t.Challenge("ipa/x")
		if x.IsZero() {
			return nil, nil, false
		}
		xs[k] = x
	}
	prod := curve.S(1)
	for _, x := range xs {
		prod = curve.Mul(prod, x)
	}
	s := []Scalar{curve.Inv(prod)}
	for k := len(xs) - 1; k >= 0; k-- {
		x2 := curve.Mul(xs[k], xs[k])
		m := len(s)
		for i := 0; i < m; i++ {
			s = append(s, curve.Mul(s[i], x2))
		}
	}
	return xs, s, true
}

// IPALRTerms gives the scalars and points of sum_k x_k^2*L_k + x_k^-2*R_k.
func IPALRTerms(p *InnerProductProof, xs []Scalar) ([]Scalar, []Point) {
	var sc []Scalar
	var pts []Point
	for k, x := range xs {
		x2 := curve.Mul(x, x)
		sc = append(sc, x2, curve.Inv(x2))
		pts = append(pts, p.L[k], p.R[k])
	}
	return sc, pts
}

func concatS(parts ...[]Scalar) []Scalar {
	var out []Scalar
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func concatP(parts ...[]Point) []Point {
	var out []Point
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}
