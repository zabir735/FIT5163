package curve

import (
	"crypto/sha3"
	"encoding/binary"
	"fmt"
	"math/big"
	"sync"
)

// --- encoding for hashes ---------------------------------------------------
// The same type-tagged, length-prefixed encoding as group.encode in Python, so
// both versions derive the same challenges from the same transaction.
//
//	Point       "P" + 33 bytes
//	scalar/int  "I" + 32 bytes big-endian (Scalar, uint64, int, *big.Int >= 0)
//	[]byte      "B" + 8-byte length + bytes
//	string      "S" + 8-byte length + UTF-8
//	list        "L" + 8-byte count + encoded items

// List is a heterogeneous list, the Python list/tuple.
type List []any

func appendLen(buf []byte, n int) []byte {
	return binary.BigEndian.AppendUint64(buf, uint64(n))
}

func appendInt32(buf []byte, b [32]byte) []byte {
	buf = append(buf, 'I')
	return append(buf, b[:]...)
}

// Encode appends the encoding of item to buf.
func Encode(buf []byte, item any) []byte {
	switch v := item.(type) {
	case Point:
		buf = append(buf, 'P')
		return append(buf, v.Bytes()...)
	case Scalar:
		return appendInt32(buf, v.Bytes())
	case *Scalar:
		return appendInt32(buf, v.Bytes())
	case uint64:
		var b [32]byte
		binary.BigEndian.PutUint64(b[24:], v)
		return appendInt32(buf, b)
	case int:
		if v < 0 {
			panic("ints must be reduced into [0, 2^256) before hashing")
		}
		return Encode(buf, uint64(v))
	case uint32:
		return Encode(buf, uint64(v))
	case uint16:
		return Encode(buf, uint64(v))
	case *big.Int:
		if v.Sign() < 0 || v.BitLen() > 256 {
			panic("ints must be reduced into [0, 2^256) before hashing")
		}
		var b [32]byte
		v.FillBytes(b[:])
		return appendInt32(buf, b)
	case []byte:
		buf = append(buf, 'B')
		buf = appendLen(buf, len(v))
		return append(buf, v...)
	case string:
		buf = append(buf, 'S')
		buf = appendLen(buf, len(v))
		return append(buf, v...)
	case List:
		buf = append(buf, 'L')
		buf = appendLen(buf, len(v))
		for _, it := range v {
			buf = Encode(buf, it)
		}
		return buf
	case []any:
		return Encode(buf, List(v))
	case []Point:
		buf = append(buf, 'L')
		buf = appendLen(buf, len(v))
		for _, p := range v {
			buf = Encode(buf, p)
		}
		return buf
	case []Scalar:
		buf = append(buf, 'L')
		buf = appendLen(buf, len(v))
		for _, s := range v {
			buf = Encode(buf, s)
		}
		return buf
	case []uint64:
		buf = append(buf, 'L')
		buf = appendLen(buf, len(v))
		for _, x := range v {
			buf = Encode(buf, x)
		}
		return buf
	case []uint32:
		buf = append(buf, 'L')
		buf = appendLen(buf, len(v))
		for _, x := range v {
			buf = Encode(buf, uint64(x))
		}
		return buf
	}
	panic(fmt.Sprintf("don't know how to encode %T", item))
}

// HashToScalar is SHA3-512 over encode(domain) + encode(items), reduced mod
// Order: the extra 256 bits make the bias negligible.
func HashToScalar(domain string, items ...any) Scalar {
	h := sha3.New512()
	h.Write(Encode(nil, domain))
	h.Write(Encode(nil, List(items)))
	return FromBig(new(big.Int).SetBytes(h.Sum(nil)))
}

// HashToPoint is try-and-increment: hash a label to x, keep it if x^3 + 7 is
// a square, take the even y. Nobody knows the discrete log of the result.
func HashToPoint(label string) Point {
	prefix := Encode(Encode(nil, "SuccinCT/generator"), label)
	for ctr := uint32(0); ; ctr++ {
		var c [4]byte
		binary.BigEndian.PutUint32(c[:], ctr)
		digest := sha3.Sum256(append(append([]byte{}, prefix...), c[:]...))
		x := new(big.Int).SetBytes(digest[:])
		x.Mod(x, FieldP)
		if p, ok := pointFromX(x); ok {
			return p
		}
	}
}

// Independent generators, same labels as group.py.
var (
	U   = HashToPoint("U")  // tags:            tag = sk*U
	V   = HashToPoint("V")  // Pedersen value:  co = a*V + ck*W
	W   = HashToPoint("W")  // Pedersen blinding
	GKA = HashToPoint("G'") // key agreement (the paper's G')
)

var (
	genMu    sync.Mutex
	genCache = map[string][]Point{}
)

// GeneratorVector returns n independent generators "label/0", "label/1", ...
// Cached, and grown on demand, because hashing to the curve isn't free.
func GeneratorVector(label string, n int) []Point {
	genMu.Lock()
	defer genMu.Unlock()
	have := genCache[label]
	for i := len(have); i < n; i++ {
		have = append(have, HashToPoint(fmt.Sprintf("%s/%d", label, i)))
	}
	genCache[label] = have
	return have[:n:n]
}

// --- the paper's named hash functions (transcript.py) ----------------------

func H(items ...any) Scalar  { return HashToScalar("SuccinCT/H", items...) }
func Ha(items ...any) Scalar { return HashToScalar("SuccinCT/H_a", items...) }
func Hb(items ...any) Scalar { return HashToScalar("SuccinCT/H_b", items...) }
func Hc(items ...any) Scalar { return HashToScalar("SuccinCT/H_c", items...) }
func Hn(items ...any) Scalar { return HashToScalar("SuccinCT/H_n", items...) }

// HnKappa is the paper's H_n^kappa(X) = H_n(X || kappa).
func HnKappa(x Point, kappa int) Scalar { return Hn(x, kappa) }

// Transcript is the running Fiat-Shamir transcript for the NIZK. Prover and
// verifier must append the same things in the same order.
type Transcript struct {
	data []byte
}

// NewTranscript starts a transcript with a label.
func NewTranscript(label string) *Transcript {
	return &Transcript{data: Encode(nil, label)}
}

// Append adds a labelled item.
func (t *Transcript) Append(label string, item any) {
	t.data = Encode(t.data, label)
	t.data = Encode(t.data, item)
}

// Challenge hashes everything so far and feeds the result back in.
func (t *Transcript) Challenge(label string) Scalar {
	x := HashToScalar("SuccinCT/transcript", t.data, label)
	t.Append(label, x)
	return x
}

// --- Pedersen commitments, tags, key agreement -----------------------------

// Commit is Com(a; ck) = a*V + ck*W.
func Commit(a, ck Scalar) Point {
	return MultiExp([]Scalar{a, ck}, []Point{V, W})
}

// VectorCommit is t*W + sum v_i*g_i with g_i = GeneratorVector(label, n).
func VectorCommit(values []Scalar, blind Scalar, label string) Point {
	gens := GeneratorVector(label, len(values))
	sc := append(append([]Scalar{}, values...), blind)
	pts := append(append([]Point{}, gens...), W)
	return MultiExp(sc, pts)
}

// TagKGen is x*G (one-time public key); TagEval is x*U (the tag).
func TagKGen(x Scalar) Point { return G.Mul(x) }
func TagEval(x Scalar) Point { return U.Mul(x) }

// KaMsg is x*G'; KaKey is H_n^kappa(x * theirMsg). Both sides of the hashed
// Diffie-Hellman get the same value because tdk*(vdk*G') = vdk*(tdk*G').
func KaMsg(x Scalar) Point                             { return GKA.Mul(x) }
func KaKey(x Scalar, theirMsg Point, kappa int) Scalar { return HnKappa(theirMsg.Mul(x), kappa) }
