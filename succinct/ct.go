package succinct

import (
	"crypto/rand"
	"errors"
	"math/big"
	mrand "math/rand/v2"

	"succinctgo/curve"
	"succinctgo/nizk"
)

// MaxOutputs is 2^iota with iota = 4, as in the paper and Monero.
const MaxOutputs = 16

// SpendInput is one real input, as returned by Receive plus its ring position.
type SpendInput struct {
	Ind int
	Ck  Scalar
	A   int64
	Sk  Scalar
	Tag Point
}

// SpendOutput is one output with its opening.
type SpendOutput struct {
	Ck  Scalar
	A   int64
	Acc Account
}

// Transaction is what goes on chain: no input positions, no amounts except
// the fee, no secret keys.
type Transaction struct {
	RingRefs []uint32
	Tags     []Point
	Outputs  []Account
	Info     Point // the shared tek
	Fee      uint64
	Mu       []byte
}

// Signature is R, T and the proof.
type Signature struct {
	R, T  Point
	Proof nizk.Proof
}

// Copy returns a shallow copy whose slices can be changed without touching tx
// (for tampering tests and the demo).
func (tx *Transaction) Copy() *Transaction {
	c := *tx
	c.RingRefs = append([]uint32{}, tx.RingRefs...)
	c.Tags = append([]Point{}, tx.Tags...)
	c.Outputs = append([]Account{}, tx.Outputs...)
	c.Mu = append([]byte{}, tx.Mu...)
	return &c
}

func accountItems(accs []Account) curve.List {
	out := make(curve.List, len(accs))
	for i, a := range accs {
		out[i] = a.HashItems()
	}
	return out
}

// txPrefix is everything the signature covers: our fix makes mu the whole
// prefix, so the tek is bound (the paper's §6.2 leaves it out).
func txPrefix(refs []uint32, outputs []Account, info Point, fee uint64, mu []byte) curve.List {
	return curve.List{refs, accountItems(outputs), info, fee, mu}
}

func ringChallenges(ringAccs []Account, tags []Point) ([]Scalar, Scalar) {
	ring := accountItems(ringAccs)
	alphas := make([]Scalar, len(tags))
	for j := range tags {
		alphas[j] = curve.Ha(ring, tags, j+1)
	}
	return alphas, curve.Hb(alphas)
}

func schnorrChallenge(refs []uint32, outputs []Account, info Point, fee uint64, mu []byte, R Point, beta Scalar) Scalar {
	return curve.H(txPrefix(refs, outputs, info, fee, mu), R, beta)
}

// BuildStatement builds the Eq. 5 statement, identically for Spend and Verify.
func BuildStatement(refs []uint32, ringAccs []Account, tags []Point, outputs []Account,
	info Point, fee uint64, mu []byte, R, T Point) (*nizk.Statement, error) {
	alphas, beta := ringChallenges(ringAccs, tags)
	h := schnorrChallenge(refs, outputs, info, fee, mu, R, beta)
	gamma := curve.Hc(h, T, accountItems(outputs), fee)
	st := &nizk.Statement{Fee: fee, Alphas: alphas, Beta: beta, H: h, Gamma: gamma, R: R, T: T, Tags: tags}
	for _, a := range ringAccs {
		st.RingPks = append(st.RingPks, a.Pk)
		st.RingCos = append(st.RingCos, a.Co)
	}
	for _, o := range outputs {
		st.OutCos = append(st.OutCos, o.Co)
	}
	return st, nil
}

// MakeOutputs runs OTAccGen for each payment with one shared tek.
func MakeOutputs(payments []Payment) ([]SpendOutput, Point) {
	tdk := curve.RandomScalar()
	var outs []SpendOutput
	var info Point
	for k, p := range payments {
		ck, acc, tek := OTAccGen(p.To, p.Amount, k+1, &tdk)
		outs = append(outs, SpendOutput{Ck: ck, A: int64(p.Amount), Acc: acc})
		info = *tek
	}
	return outs, info
}

// Payment is one (address, amount) pair.
type Payment struct {
	To     *MasterPublicKey
	Amount uint64
}

// Rng is the randomness pick_ring uses; nil means the OS.
type Rng interface {
	IntN(n int) int
	Shuffle(n int, swap func(i, j int))
}

type osRng struct{}

func (osRng) IntN(n int) int {
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		panic(err)
	}
	return int(v.Int64())
}
func (r osRng) Shuffle(n int, swap func(i, j int)) {
	for i := n - 1; i > 0; i-- {
		swap(i, r.IntN(i+1))
	}
}

// NewSeededRng is a reproducible Rng for the experiments.
func NewSeededRng(seed uint64) *mrand.Rand { return mrand.New(mrand.NewPCG(seed, seed^0x5163)) }

// ErrTooManyCoinbases is the S-1 rule.
var ErrTooManyCoinbases = errors.New("at most S-1 inputs may be coinbase outputs; add an ordinary input alongside (§3.2)")

// PickRing chooses decoys uniformly, enforces the S-1 rule and shuffles.
// Returns the ring refs and the positions of the real refs.
func PickRing(chain *Chain, real []uint32, size int, rng Rng) ([]uint32, []int, error) {
	if rng == nil {
		rng = osRng{}
	}
	nS := len(real)
	if size < nS {
		return nil, nil, errors.New("ring smaller than number of inputs")
	}
	isReal := map[uint32]bool{}
	miners := 0
	for _, r := range real {
		isReal[r] = true
		if acc, _, ok := chain.Get(r); ok && acc.IsMiner() {
			miners++
		}
	}
	if miners > nS-1 {
		return nil, nil, ErrTooManyCoinbases
	}
	var candidates []uint32
	for r := 0; r < chain.Len(); r++ {
		if !isReal[uint32(r)] {
			candidates = append(candidates, uint32(r))
		}
	}
	rng.Shuffle(len(candidates), func(i, j int) { candidates[i], candidates[j] = candidates[j], candidates[i] })
	var decoys []uint32
	for _, r := range candidates {
		if len(decoys) == size-nS {
			break
		}
		acc, _, _ := chain.Get(r)
		if acc.IsMiner() {
			if miners >= nS-1 {
				continue
			}
			miners++
		}
		decoys = append(decoys, r)
	}
	if len(decoys) < size-nS {
		return nil, nil, errors.New("not enough outputs on chain for this ring size")
	}
	ring := append(append([]uint32{}, real...), decoys...)
	rng.Shuffle(len(ring), func(i, j int) { ring[i], ring[j] = ring[j], ring[i] })
	pos := make([]int, nS)
	for k, r := range real {
		for i, x := range ring {
			if x == r {
				pos[k] = i
			}
		}
	}
	return ring, pos, nil
}

// CheckBalance is the wallet's own check (switchable for the inflation test).
var CheckBalance = func(inputs []SpendInput, outputs []SpendOutput, fee uint64) error {
	var in, out int64
	for _, i := range inputs {
		in += i.A
	}
	for _, o := range outputs {
		out += o.A
	}
	if in-int64(fee) != out {
		return errors.New("inputs - fee != outputs")
	}
	return nil
}

// RingMember is a ring reference with its account.
type RingMember struct {
	Ref uint32
	Acc Account
}

// Spend builds the transaction: one MuSig signature for all inputs on base
// G + beta*U, the balance folded in with gamma, and the proof.
func Spend(ring []RingMember, inputs []SpendInput, outputs []SpendOutput, info Point,
	fee uint64, mu []byte, sys nizk.System) (*Transaction, *Signature, error) {
	refs := make([]uint32, len(ring))
	accs := make([]Account, len(ring))
	for i, m := range ring {
		refs[i], accs[i] = m.Ref, m.Acc
	}
	n, nS := len(accs), len(inputs)
	if nS < 1 {
		return nil, nil, errors.New("need at least one input")
	}
	if len(outputs) < 2 || len(outputs) > MaxOutputs {
		return nil, nil, errors.New("need 2..16 outputs")
	}
	miners := 0
	for _, a := range accs {
		if a.IsMiner() {
			miners++
		}
	}
	if miners > nS-1 {
		return nil, nil, errors.New("too many miner accounts in ring (max S-1)")
	}
	if err := CheckBalance(inputs, outputs, fee); err != nil {
		return nil, nil, err
	}
	tags := make([]Point, nS)
	seen := map[string]bool{}
	for j, in := range inputs {
		if in.Ind < 0 || in.Ind >= n {
			return nil, nil, errors.New("input position outside ring")
		}
		tags[j] = in.Tag
		seen[in.Tag.Key()] = true
	}
	if len(seen) != nS {
		return nil, nil, errors.New("same input used twice")
	}
	outAccs := make([]Account, len(outputs))
	for k, o := range outputs {
		outAccs[k] = o.Acc
	}

	// (1) ring multi-signature
	alphas, beta := ringChallenges(accs, tags)
	r := curve.RandomScalar()
	R := curve.G.Add(curve.U.Mul(beta)).Mul(r)
	h := schnorrChallenge(refs, outAccs, info, fee, mu, R, beta)
	var ask Scalar
	for j, in := range inputs {
		t := curve.Mul(alphas[j], in.Sk)
		ask.Add(&t)
	}
	z := curve.Add(r, curve.Mul(h, ask))

	// (2) coin balance: the leftover blinding
	var ckIn, ckOut Scalar
	for _, in := range inputs {
		ckIn.Add(&in.Ck)
	}
	for _, o := range outputs {
		ckOut.Add(&o.Ck)
	}
	ckPrime := curve.Sub(ckIn, ckOut)

	// (3) commit to the witness, then prove
	bvecs := make([][]int64, nS)
	for j, in := range inputs {
		bvecs[j] = make([]int64, n)
		bvecs[j][in.Ind] = 1
	}
	t := curve.RandomScalar()
	T := nizk.CommitT(z, ckPrime, bvecs, t)

	st, err := BuildStatement(refs, accs, tags, outAccs, info, fee, mu, R, T)
	if err != nil {
		return nil, nil, err
	}
	if !st.H.Equals(&h) {
		panic("Spend and Verify disagree on h")
	}
	wit := &nizk.Witness{Z: z, CkPrime: ckPrime, Bvecs: bvecs, T: t}
	for _, o := range outputs {
		wit.OutAmounts = append(wit.OutAmounts, o.A)
		wit.OutCks = append(wit.OutCks, o.Ck)
	}
	proof, err := sys.Prove(st, wit)
	if err != nil {
		return nil, nil, err
	}
	tx := &Transaction{RingRefs: refs, Tags: tags, Outputs: outAccs, Info: info, Fee: fee, Mu: append([]byte{}, mu...)}
	return tx, &Signature{R: R, T: T, Proof: proof}, nil
}

// Result is Verify's answer: Valid (True), BadProof (False) or Broken (None,
// the paper's ⊥: a rule is broken).
type Result int

const (
	Broken Result = iota
	BadProof
	Valid
)

func (r Result) String() string {
	switch r {
	case Valid:
		return "True"
	case BadProof:
		return "False"
	}
	return "None"
}

// Verify checks the rules first (returning Broken), then the proof.
func Verify(tx *Transaction, sig *Signature, chain *Chain, sys nizk.System) Result {
	nS, n := len(tx.Tags), len(tx.RingRefs)
	if nS < 1 || n < nS {
		return Broken
	}
	if len(tx.Outputs) < 2 || len(tx.Outputs) > MaxOutputs {
		return Broken
	}
	for _, o := range tx.Outputs {
		if o.IsMiner() {
			return Broken
		}
	}
	refs := map[uint32]bool{}
	for _, r := range tx.RingRefs {
		refs[r] = true
	}
	if len(refs) != n {
		return Broken
	}
	tags := map[string]bool{}
	for _, t := range tx.Tags {
		tags[t.Key()] = true
		if chain.IsSpent(t) {
			return Broken
		}
	}
	if len(tags) != nS {
		return Broken
	}
	accs := make([]Account, n)
	miners := 0
	for i, r := range tx.RingRefs {
		acc, _, ok := chain.Get(r)
		if !ok {
			return Broken
		}
		accs[i] = acc
		if acc.IsMiner() {
			miners++
		}
	}
	if miners > nS-1 {
		return Broken
	}
	st, err := BuildStatement(tx.RingRefs, accs, tx.Tags, tx.Outputs, tx.Info, tx.Fee, tx.Mu, sig.R, sig.T)
	if err != nil || !sys.Verify(st, sig.Proof) {
		return BadProof
	}
	return Valid
}

// Mine makes the coinbase: reward + all fees, coin key 1, amount public.
func Mine(fees []uint64, miner *MasterPublicKey, reward uint64) Account {
	total := reward
	for _, f := range fees {
		total += f
	}
	_, acc, _ := OTAccGen(miner, total, 0, nil)
	return acc
}
