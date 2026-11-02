package nizk

import (
	"errors"
	"math/bits"

	"succinctgo/curve"
)

// BPP is a log-size proof of the Eq. 5 relation built on the core of
// Bulletproofs++ (Eagen, Kanjalkar, Ruffing, Nick, EUROCRYPT 2024): the weighted
// norm linear argument (WNLA). The paper says it uses BP++ but does not give
// its encoding of Eq. 5, so THIS ENCODING IS OURS. It follows the hint the
// paper does give (§5, Step 3): a bit b satisfies (b - 1/2)^2 = 1/4, so "all of
// these are bits" is one weighted-norm equation.
//
// What is proved, for the same Statement and Witness as the Σ-protocol:
//
//	beta = (b(1), ..., b(S), bits of amount 1, ..., bits of amount m, 0 padding)
//
//	(1) T = z*Tg0 + ck'*Tg1 + <b, Tg_b> + t*W            (T opens to the witness)
//	(2) z*BaseZ + ck'*BaseCk - sum b(j,i)*Y(j,i) = Target (Eq. 5)
//	(3) co_k = (sum_i 2^i beta(k,i))*V + ck_k*W           (outputs open to 64-bit amounts)
//	(4) sum_i b(j,i) = 1 for every input j                (one-hot)
//	(5) every entry of beta is 0 or 1
//
// How, in three moves plus the folding:
//
//  1. Commit to the amount bits (B) and to random masks a for every bit and
//     for z, ck', the blindings (A, E0, E_k), and reveal abar_j = sum_i a(j,i).
//     Challenge rho; the bit weights are w_i = mu^(i+1), mu = rho^2.
//  2. Commit to the two scalars of the Groth-Kohlweiss bit check,
//     c = sum w_i a_i(1 - 2beta_i) and d = -sum w_i a_i^2 (C, D). Challenge x.
//  3. The masked witness is f = x*beta + a (never sent) and s_z, s_ck, ...
//     (sent). For true bits, f_i(x - f_i) = x*c_i + d_i, which rearranges to
//     |f - x/2|^2_w = (x^2/4) sum w_i - (x*c + d): a weighted norm of
//     n = f - x/2, exactly what WNLA proves. Challenge eps.
//  4. WNLA folds n against two base vectors at once: the independent
//     generators Gvec (carrying (1) and (5)) and Q, whose entries are the
//     public points of (2)-(4) mixed with powers of eps. Each round sends 4
//     points, so the proof is O(log(S*n + 64m)).
//
// Why it is sound, in short: the Gvec part binds f (independent generators);
// powers of eps make every equation in Q hold separately; three values of x
// give f = x*beta + a with sum w_i beta_i(beta_i - 1) = 0, and since w comes
// from rho, chosen after beta was committed, every beta_i is a bit.
// Why it hides: a is uniform, so f is uniform, and every message is either a
// hiding commitment or fixed by f and the challenges (honest-verifier ZK, then
// Fiat-Shamir).
//
// This is a construction written for this project, tested against the
// relation oracle and tampering, NOT reviewed by a cryptographer.
type BPP struct{}

const bppTranscriptLabel = "SuccinCT/bpp-eq5"

func (BPP) Name() string {
	return "Bulletproofs++ weighted norm argument for Eq. 5 + bits (log size, our encoding)"
}

// BPPProof is the proof. Rounds = len(Xs); the final vector N has at most 8
// entries.
type BPPProof struct {
	B, A, E0, C, D   Point
	Ek               []Point  // one per output
	Abar             []Scalar // one per input
	Sz, Sck, Sw, Scd Scalar
	Sk               []Scalar // one per output
	Xs, Rs, X2s, R2s []Point  // one per folding round
	N                []Scalar // what is left after folding
}

var (
	bppG      = curve.HashToPoint("BPP/G")      // value base of the norm
	bppH      = curve.HashToPoint("BPP/H")      // blinding of C and D
	bppOneHot = curve.HashToPoint("BPP/onehot") // base for the one-hot sums
)

// bppLayout: n ring members, S inputs, m outputs -> real length, padded length
// L and number of folding rounds r. L = k*2^r with k <= 8, so folding stops at
// k scalars instead of padding all the way to a power of two.
func bppLayout(n, S, m int) (size, L, r int) {
	size = S*n + AmountBits*m
	if size <= 8 {
		return size, size, 0
	}
	r = bits.Len(uint(size-1)) - 3
	step := 1 << r
	L = (size + step - 1) / step * step
	return size, L, r
}

func bppGens(s *Statement, L int) (tg []Point, gvec []Point) {
	sn := s.NS() * s.N()
	tg = curve.GeneratorVector(TLabel, 2+sn)
	ga := curve.GeneratorVector("BPP/amt", L-sn)
	gvec = make([]Point, 0, L)
	gvec = append(gvec, tg[2:]...)
	gvec = append(gvec, ga...)
	return tg, gvec
}

func bppTranscript(s *Statement, L int) *curve.Transcript {
	t := sigmaTranscript(s)
	t.Append("system", bppTranscriptLabel)
	t.Append("L", L)
	return t
}

// weights returns mu^1, ..., mu^L.
func weights(mu Scalar, L int) []Scalar {
	w := curve.Powers(mu, L+1)
	return w[1:]
}

func (BPP) Prove(s *Statement, w *Witness) (Proof, error) {
	nS, n, m := s.NS(), s.N(), len(s.OutCos)
	if len(w.Bvecs) != nS || len(w.OutAmounts) != m || len(w.OutCks) != m {
		return nil, errors.New("witness doesn't match the statement's shape")
	}
	for _, v := range w.Bvecs {
		if len(v) != n {
			return nil, errors.New("witness bit vectors don't match the statement's S x n")
		}
	}
	sn := nS * n
	_, L, rounds := bppLayout(n, nS, m)
	tg, gvec := bppGens(s, L)

	// beta: ring bits, then amount bits (of the amount as a 64-bit word: a
	// negative amount gives the wrong number here and the proof fails)
	beta := make([]Scalar, L)
	for j, v := range w.Bvecs {
		for i, b := range v {
			beta[j*n+i] = curve.SInt(b)
		}
	}
	for k, amt := range w.OutAmounts {
		u := uint64(amt)
		for i := 0; i < AmountBits; i++ {
			beta[sn+k*AmountBits+i] = curve.S((u >> i) & 1)
		}
	}

	// move 1
	a := curve.RandomVector(L)
	rz, rck, rA, ta := curve.RandomScalar(), curve.RandomScalar(), curve.RandomScalar(), curve.RandomScalar()
	rk := curve.RandomVector(m)
	p := &BPPProof{}
	p.B = curve.MultiExp(append(append([]Scalar{}, beta[sn:]...), ta), append(append([]Point{}, gvec[sn:]...), curve.W))
	p.A = curve.MultiExp(append(append([]Scalar{rz, rck}, a...), rA),
		append(append([]Point{tg[0], tg[1]}, gvec...), curve.W))
	pow2 := curve.Powers(curve.S(2), AmountBits)
	p.Ek = make([]Point, m)
	for k := 0; k < m; k++ {
		amask := curve.Inner(pow2, a[sn+k*AmountBits:sn+(k+1)*AmountBits])
		p.Ek[k] = curve.MultiExp([]Scalar{amask, rk[k]}, []Point{curve.V, curve.W})
	}
	amat := make([][]Scalar, nS)
	p.Abar = make([]Scalar, nS)
	for j := 0; j < nS; j++ {
		amat[j] = a[j*n : (j+1)*n]
		p.Abar[j] = curve.Sum(amat[j])
	}
	p.E0 = curve.MultiExp([]Scalar{rz, rck}, []Point{s.BaseZ(), s.BaseCk()}).Sub(sumY(s, amat))

	tr := bppTranscript(s, L)
	tr.Append("B", p.B)
	tr.Append("A", p.A)
	tr.Append("E0", p.E0)
	tr.Append("Ek", p.Ek)
	tr.Append("abar", p.Abar)
	rho := tr.Challenge("rho")
	if rho.IsZero() {
		return nil, errors.New("zero challenge")
	}
	mu := curve.Mul(rho, rho)
	wts := weights(mu, L)

	// move 2
	one, two := curve.S(1), curve.S(2)
	var c, d Scalar
	for i := 0; i < L; i++ {
		ci := curve.Mul(wts[i], curve.Mul(a[i], curve.Sub(one, curve.Mul(two, beta[i]))))
		di := curve.Mul(wts[i], curve.Mul(a[i], a[i]))
		c = curve.Add(c, ci)
		d = curve.Sub(d, di)
	}
	rC, rD := curve.RandomScalar(), curve.RandomScalar()
	p.C = curve.MultiExp([]Scalar{c, rC}, []Point{bppG, bppH})
	p.D = curve.MultiExp([]Scalar{d, rD}, []Point{bppG, bppH})
	tr.Append("C", p.C)
	tr.Append("D", p.D)
	x := tr.Challenge("x")

	// move 3
	p.Sz = curve.Add(curve.Mul(x, w.Z), rz)
	p.Sck = curve.Add(curve.Mul(x, w.CkPrime), rck)
	p.Sw = curve.Add(curve.Mul(x, curve.Add(w.T, ta)), rA)
	p.Scd = curve.Add(curve.Mul(x, rC), rD)
	p.Sk = make([]Scalar, m)
	for k := range p.Sk {
		p.Sk[k] = curve.Add(curve.Mul(x, w.OutCks[k]), rk[k])
	}
	bppAppendResponses(tr, p)
	eps := tr.Challenge("eps")

	halfX := curve.Mul(x, curve.Inv(two))
	nvec := make([]Scalar, L)
	for i := range nvec {
		nvec[i] = curve.Sub(curve.Add(curve.Mul(x, beta[i]), a[i]), halfX)
	}
	q := bppQ(s, L, eps)

	// the folding (WNLA with two base vectors)
	g := append([]Point{}, gvec...)
	rhoC, muC := rho, mu
	sigma := curve.S(1) // true generators = sigma * (g, q)
	for r := 0; r < rounds; r++ {
		h := len(nvec) / 2
		n0, n1 := make([]Scalar, h), make([]Scalar, h)
		g0, g1 := make([]Point, h), make([]Point, h)
		q0, q1 := make([]Point, h), make([]Point, h)
		for i := 0; i < h; i++ {
			n0[i], n1[i] = nvec[2*i], nvec[2*i+1]
			g0[i], g1[i] = g[2*i], g[2*i+1]
			q0[i], q1[i] = q[2*i], q[2*i+1]
		}
		muN := curve.Mul(muC, muC)
		rhoInv := curve.Inv(rhoC)
		wn := weights(muN, h)
		var vX, vR Scalar
		for i := 0; i < h; i++ {
			vX = curve.Add(vX, curve.Mul(wn[i], curve.Mul(n0[i], n1[i])))
			vR = curve.Add(vR, curve.Mul(wn[i], curve.Mul(n1[i], n1[i])))
		}
		vX = curve.Mul(curve.Mul(two, rhoInv), vX)
		cross := make([]Scalar, 0, 2*h)
		for i := 0; i < h; i++ {
			cross = append(cross, curve.Mul(rhoInv, n0[i]))
		}
		for i := 0; i < h; i++ {
			cross = append(cross, curve.Mul(rhoC, n1[i]))
		}
		// g and q are stored divided by sigma (see below), so scale the
		// coefficients back up
		sc := make([]Scalar, len(cross))
		sn1 := make([]Scalar, h)
		for i := range cross {
			sc[i] = curve.Mul(sigma, cross[i])
		}
		for i := range n1 {
			sn1[i] = curve.Mul(sigma, n1[i])
		}
		X := curve.MultiExp(append([]Scalar{vX}, sc...), append(append([]Point{bppG}, g1...), g0...))
		R := curve.MultiExp(append([]Scalar{vR}, sn1...), append([]Point{bppG}, g1...))
		X2 := curve.MultiExp(sc, append(append([]Point{}, q1...), q0...))
		R2 := curve.MultiExp(sn1, q1)
		p.Xs, p.Rs, p.X2s, p.R2s = append(p.Xs, X), append(p.Rs, R), append(p.X2s, X2), append(p.R2s, R2)
		gam := bppRoundChallenge(tr, X, R, X2, R2)
		if gam.IsZero() {
			return nil, errors.New("zero challenge")
		}
		// The protocol folds G' = rho*G0 + gam*G1. Writing that as
		// rho*(G0 + (gam/rho)*G1) and keeping the common factor rho in sigma
		// costs one multiplication per pair instead of two.
		delta := curve.Mul(gam, rhoInv)
		for i := 0; i < h; i++ {
			n0[i] = curve.Add(curve.Mul(rhoInv, n0[i]), curve.Mul(gam, n1[i]))
			g0[i] = g0[i].Add(g1[i].Mul(delta))
			q0[i] = q0[i].Add(q1[i].Mul(delta))
		}
		sigma = curve.Mul(sigma, rhoC)
		nvec, g, q = n0, g0, q0
		rhoC, muC = muC, muN
	}
	p.N = nvec
	return p, nil
}

func bppAppendResponses(tr *curve.Transcript, p *BPPProof) {
	tr.Append("sz", p.Sz)
	tr.Append("sck", p.Sck)
	tr.Append("sw", p.Sw)
	tr.Append("scd", p.Scd)
	tr.Append("sk", p.Sk)
}

func bppRoundChallenge(tr *curve.Transcript, X, R, X2, R2 Point) Scalar {
	tr.Append("X", X)
	tr.Append("R", R)
	tr.Append("X2", X2)
	tr.Append("R2", R2)
	return tr.Challenge("gamma")
}

// bppQ is the second base vector, built by the prover. The verifier never
// builds it: it only needs Q's final combination, which is a short sum over
// the ring's points (see Verify).
//
//	ring bit (j,i):    -Y(j,i) + eps^(1+m+j) * OneHot
//	amount bit (k,i):  eps^(1+k) * 2^i * V
//	padding:           identity
func bppQ(s *Statement, L int, eps Scalar) []Point {
	nS, n, m := s.NS(), s.N(), len(s.OutCos)
	sn := nS * n
	ep := curve.Powers(eps, 2+m+nS)
	q := make([]Point, L)
	gco := make([]Point, n)
	for i := 0; i < n; i++ {
		gco[i] = s.RingCos[i].Mul(s.Gamma)
	}
	for j := 0; j < nS; j++ {
		ah := curve.Mul(s.Alphas[j], s.H)
		oh := bppOneHot.Mul(ep[1+m+j])
		for i := 0; i < n; i++ {
			q[j*n+i] = oh.Sub(s.RingPks[i].Mul(ah).Add(gco[i]))
		}
	}
	for k := 0; k < m; k++ {
		base := curve.V.Mul(ep[1+k])
		for i := 0; i < AmountBits; i++ {
			q[sn+k*AmountBits+i] = base
			base = base.Add(base)
		}
	}
	for i := sn + m*AmountBits; i < L; i++ {
		q[i] = curve.Identity()
	}
	return q
}

func (BPP) Verify(s *Statement, proof Proof) bool {
	p, ok := proof.(*BPPProof)
	if !ok || p == nil {
		return false
	}
	nS, n, m := s.NS(), s.N(), len(s.OutCos)
	if nS == 0 || n == 0 || len(s.Alphas) != nS || len(s.RingCos) != n {
		return false
	}
	_, L, rounds := bppLayout(n, nS, m)
	if len(p.Ek) != m || len(p.Abar) != nS || len(p.Sk) != m ||
		len(p.Xs) != rounds || len(p.Rs) != rounds || len(p.X2s) != rounds || len(p.R2s) != rounds ||
		len(p.N) != L>>rounds {
		return false
	}
	sn := nS * n
	tg, gvec := bppGens(s, L)

	tr := bppTranscript(s, L)
	tr.Append("B", p.B)
	tr.Append("A", p.A)
	tr.Append("E0", p.E0)
	tr.Append("Ek", p.Ek)
	tr.Append("abar", p.Abar)
	rho := tr.Challenge("rho")
	tr.Append("C", p.C)
	tr.Append("D", p.D)
	x := tr.Challenge("x")
	bppAppendResponses(tr, p)
	eps := tr.Challenge("eps")
	gams := make([]Scalar, rounds)
	for r := 0; r < rounds; r++ {
		gams[r] = bppRoundChallenge(tr, p.Xs[r], p.Rs[r], p.X2s[r], p.R2s[r])
		if gams[r].IsZero() {
			return false
		}
	}
	if rho.IsZero() {
		return false
	}

	// rho_r = rho^(2^r); the folded coefficient of original index idx is the
	// product over rounds of rho_r (bit r of idx is 0) or gamma_r (bit is 1).
	rhos := make([]Scalar, rounds+2)
	rhos[0] = rho
	for r := 1; r < len(rhos); r++ {
		rhos[r] = curve.Mul(rhos[r-1], rhos[r-1])
	}
	mu := rhos[1]
	coef := make([]Scalar, L)
	coef[0] = curve.S(1)
	for r := 0; r < rounds; r++ {
		span := 1 << r
		for i := 0; i < span; i++ {
			coef[i+span] = curve.Mul(coef[i], gams[r])
			coef[i] = curve.Mul(coef[i], rhos[r])
		}
	}
	// coef so far covers the low "rounds" bits; the high bits pick the final slot
	two := curve.S(2)
	halfX := curve.Mul(x, curve.Inv(two))
	low := (1 << rounds) - 1
	u := make([]Scalar, L) // e_idx + x/2
	for idx := 0; idx < L; idx++ {
		u[idx] = curve.Add(curve.Mul(p.N[idx>>rounds], coef[idx&low]), halfX)
	}
	muFinal := rhos[rounds+1]
	var vFinal Scalar
	wf := weights(muFinal, len(p.N))
	for i, v := range p.N {
		vFinal = curve.Add(vFinal, curve.Mul(wf[i], curve.Mul(v, v)))
	}
	sumW := curve.Sum(weights(mu, L))
	one := curve.S(1)

	// Check 1 (the Gvec component):
	//  (x^2/4)sumW*G - xC - D + scd*H + x(T + B) + A - sz*Tg0 - sck*Tg1 - sw*W
	//  + sum_r gamma_r X_r + (gamma_r^2 - 1) R_r  ==  vFinal*G + sum u_idx Gvec_idx
	sc := []Scalar{
		curve.Sub(curve.Mul(curve.Mul(halfX, halfX), sumW), vFinal),
		curve.Neg(x), curve.Neg(one), p.Scd, x, x, one,
		curve.Neg(p.Sz), curve.Neg(p.Sck), curve.Neg(p.Sw),
	}
	pt := []Point{bppG, p.C, p.D, bppH, s.T, p.B, p.A, tg[0], tg[1], curve.W}
	for r := 0; r < rounds; r++ {
		sc = append(sc, gams[r], curve.Sub(curve.Mul(gams[r], gams[r]), one))
		pt = append(pt, p.Xs[r], p.Rs[r])
	}
	for idx := 0; idx < L; idx++ {
		sc = append(sc, curve.Neg(u[idx]))
	}
	pt = append(pt, gvec...)
	if !curve.MultiExp(sc, pt).IsIdentity() {
		return false
	}

	// Check 2 (the Q component), with Q expanded into the ring's own points:
	//  sum_idx u_idx Q_idx == x*Target + E0 - sz*BaseZ - sck*BaseCk
	//    + sum_k eps^(1+k) (x co_k + E_k - s_k W) + sum_j eps^(1+m+j) (x + abar_j) OneHot
	//    + sum_r gamma_r X2_r + (gamma_r^2 - 1) R2_r
	ep := curve.Powers(eps, 2+m+nS)
	pkC := make([]Scalar, n)
	coC := make([]Scalar, n)
	var oneHotC, vC, wC Scalar
	for j := 0; j < nS; j++ {
		ah := curve.Mul(s.Alphas[j], s.H)
		var rowSum Scalar
		for i := 0; i < n; i++ {
			uji := u[j*n+i]
			pkC[i] = curve.Sub(pkC[i], curve.Mul(ah, uji))
			coC[i] = curve.Sub(coC[i], curve.Mul(s.Gamma, uji))
			rowSum = curve.Add(rowSum, uji)
		}
		rhs := curve.Add(x, p.Abar[j])
		oneHotC = curve.Add(oneHotC, curve.Mul(ep[1+m+j], curve.Sub(rowSum, rhs)))
	}
	pow2 := curve.Powers(two, AmountBits)
	for k := 0; k < m; k++ {
		vC = curve.Add(vC, curve.Mul(ep[1+k], curve.Inner(pow2, u[sn+k*AmountBits:sn+(k+1)*AmountBits])))
		wC = curve.Add(wC, curve.Mul(ep[1+k], p.Sk[k]))
	}
	sc = append([]Scalar{}, pkC...)
	sc = append(sc, coC...)
	pt = append(append([]Point{}, s.RingPks...), s.RingCos...)
	sc = append(sc, oneHotC, vC, wC, curve.Neg(x), curve.Neg(one), p.Sz, p.Sck)
	pt = append(pt, bppOneHot, curve.V, curve.W, s.Target(), p.E0, s.BaseZ(), s.BaseCk())
	for k := 0; k < m; k++ {
		sc = append(sc, curve.Neg(curve.Mul(ep[1+k], x)), curve.Neg(ep[1+k]))
		pt = append(pt, s.OutCos[k], p.Ek[k])
	}
	for r := 0; r < rounds; r++ {
		sc = append(sc, curve.Neg(gams[r]), curve.Sub(one, curve.Mul(gams[r], gams[r])))
		pt = append(pt, p.X2s[r], p.R2s[r])
	}
	return curve.MultiExp(sc, pt).IsIdentity()
}
