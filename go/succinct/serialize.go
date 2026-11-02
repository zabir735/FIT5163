package succinct

import (
	"encoding/binary"
	"errors"

	"succinctgo/curve"
	"succinctgo/nizk"
)

// Byte format, identical to serialize.py ("succinct-v1"): 33-byte points,
// 32-byte scalars, u16 counts, u32 ring refs, u64 amounts. Only Σ-protocol
// proofs have an encoding.

const (
	scalarBytes = 32
	refBytes    = 4
	amountBytes = 8
)

type writer struct{ b []byte }

func (w *writer) u16(v int) {
	if v < 0 || v >= 1<<16 {
		panic("count does not fit in u16")
	}
	w.b = binary.BigEndian.AppendUint16(w.b, uint16(v))
}
func (w *writer) u32(v uint32)    { w.b = binary.BigEndian.AppendUint32(w.b, v) }
func (w *writer) u64(v uint64)    { w.b = binary.BigEndian.AppendUint64(w.b, v) }
func (w *writer) point(p Point)   { w.b = append(w.b, p.Bytes()...) }
func (w *writer) scalar(s Scalar) { b := s.Bytes(); w.b = append(w.b, b[:]...) }

func (w *writer) account(a Account) {
	w.point(a.Pk)
	w.point(a.Co)
	w.u64(a.Ctxt)
	w.u16(a.Kappa)
}

func (w *writer) ipa(p *nizk.InnerProductProof) {
	w.u16(len(p.L))
	for _, x := range p.L {
		w.point(x)
	}
	for _, x := range p.R {
		w.point(x)
	}
	w.scalar(p.A)
	w.scalar(p.B)
}

func (w *writer) proof(p *nizk.RingProof) {
	for _, x := range []Point{p.A, p.C, p.D, p.E} {
		w.point(x)
	}
	width := 0
	if len(p.F) > 0 {
		width = len(p.F[0])
	}
	w.u16(len(p.F))
	w.u16(width)
	for _, row := range p.F {
		for _, x := range row {
			w.scalar(x)
		}
	}
	for _, x := range []Scalar{p.Sz, p.Sck, p.St, p.Sbits} {
		w.scalar(x)
	}
	r := p.Range
	for _, x := range []Point{r.A, r.S, r.T1, r.T2} {
		w.point(x)
	}
	for _, x := range []Scalar{r.TauX, r.Mu, r.THat} {
		w.scalar(x)
	}
	w.ipa(r.IPA)
}

// EncodeProof encodes a Σ-protocol proof on its own.
func EncodeProof(p nizk.Proof) ([]byte, error) {
	rp, ok := p.(*nizk.RingProof)
	if !ok {
		return nil, errors.New("only sigma_ring proofs have a byte encoding")
	}
	var w writer
	w.proof(rp)
	return w.b, nil
}

// EncodeTransaction is everything a verifier receives.
func EncodeTransaction(tx *Transaction, sig *Signature) ([]byte, error) {
	rp, ok := sig.Proof.(*nizk.RingProof)
	if !ok {
		return nil, errors.New("only sigma_ring proofs have a byte encoding")
	}
	var w writer
	w.u16(len(tx.RingRefs))
	for _, r := range tx.RingRefs {
		w.u32(r)
	}
	w.u16(len(tx.Tags))
	for _, t := range tx.Tags {
		w.point(t)
	}
	w.u16(len(tx.Outputs))
	for _, a := range tx.Outputs {
		w.account(a)
	}
	w.point(tx.Info)
	w.u64(tx.Fee)
	w.u16(len(tx.Mu))
	w.b = append(w.b, tx.Mu...)
	w.point(sig.R)
	w.point(sig.T)
	w.proof(rp)
	return w.b, nil
}

type reader struct {
	b   []byte
	pos int
	err error
}

func (r *reader) take(n int) []byte {
	if r.err != nil {
		return make([]byte, n)
	}
	if r.pos+n > len(r.b) {
		r.err = errors.New("encoding is truncated")
		return make([]byte, n)
	}
	out := r.b[r.pos : r.pos+n]
	r.pos += n
	return out
}
func (r *reader) u16() int    { return int(binary.BigEndian.Uint16(r.take(2))) }
func (r *reader) u32() uint32 { return binary.BigEndian.Uint32(r.take(refBytes)) }
func (r *reader) u64() uint64 { return binary.BigEndian.Uint64(r.take(amountBytes)) }
func (r *reader) point() Point {
	p, err := curve.PointFromBytes(r.take(curve.PointBytes))
	if err != nil && r.err == nil {
		r.err = err
	}
	return p
}
func (r *reader) points(n int) []Point {
	out := make([]Point, n)
	for i := range out {
		out[i] = r.point()
	}
	return out
}
func (r *reader) scalar() Scalar {
	s, ok := curve.ScalarFromBytes(r.take(scalarBytes))
	if !ok && r.err == nil {
		r.err = errors.New("scalar out of range")
	}
	return s
}

func (r *reader) proof() *nizk.RingProof {
	p := &nizk.RingProof{}
	pts := r.points(4)
	p.A, p.C, p.D, p.E = pts[0], pts[1], pts[2], pts[3]
	rows, width := r.u16(), r.u16()
	for j := 0; j < rows && r.err == nil; j++ {
		row := make([]Scalar, width)
		for i := range row {
			row[i] = r.scalar()
		}
		p.F = append(p.F, row)
	}
	p.Sz, p.Sck, p.St, p.Sbits = r.scalar(), r.scalar(), r.scalar(), r.scalar()
	rg := &nizk.RangeProof{}
	pts = r.points(4)
	rg.A, rg.S, rg.T1, rg.T2 = pts[0], pts[1], pts[2], pts[3]
	rg.TauX, rg.Mu, rg.THat = r.scalar(), r.scalar(), r.scalar()
	rounds := r.u16()
	ipa := &nizk.InnerProductProof{L: r.points(rounds), R: r.points(rounds)}
	ipa.A, ipa.B = r.scalar(), r.scalar()
	rg.IPA = ipa
	p.Range = rg
	return p
}

// DecodeTransaction reads what EncodeTransaction wrote (or Python's
// serialize.encode_transaction).
func DecodeTransaction(data []byte) (*Transaction, *Signature, error) {
	r := &reader{b: data}
	tx := &Transaction{}
	n := r.u16()
	for i := 0; i < n && r.err == nil; i++ {
		tx.RingRefs = append(tx.RingRefs, r.u32())
	}
	tx.Tags = r.points(r.u16())
	k := r.u16()
	for i := 0; i < k && r.err == nil; i++ {
		tx.Outputs = append(tx.Outputs, Account{Pk: r.point(), Co: r.point(), Ctxt: r.u64(), Kappa: r.u16()})
	}
	tx.Info = r.point()
	tx.Fee = r.u64()
	tx.Mu = append([]byte{}, r.take(r.u16())...)
	sig := &Signature{R: r.point(), T: r.point()}
	sig.Proof = r.proof()
	if r.err == nil && r.pos != len(r.b) {
		r.err = errors.New("trailing bytes after the encoding")
	}
	if r.err != nil {
		return nil, nil, r.err
	}
	return tx, sig, nil
}

// ProofSize and TransactionSize are the measured sizes.
func ProofSize(p nizk.Proof) int {
	b, err := EncodeProof(p)
	if err != nil {
		return 0
	}
	return len(b)
}

func TransactionSize(tx *Transaction, sig *Signature) int {
	b, err := EncodeTransaction(tx, sig)
	if err != nil {
		return 0
	}
	return len(b)
}
