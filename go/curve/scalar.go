package curve

import (
	"crypto/rand"
	"math/big"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// Scalar is an integer mod the group order (the Python ORDER). The library's
// ModNScalar does the arithmetic in fixed-size words, so it's fast and always
// reduced.
type Scalar = secp256k1.ModNScalar

// Order is the group order.
var Order, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)

// S makes a scalar from a small non-negative number.
func S(v uint64) Scalar {
	var b [32]byte
	for i := 0; i < 8; i++ {
		b[31-i] = byte(v >> (8 * i))
	}
	var s Scalar
	s.SetBytes(&b)
	return s
}

// SInt makes a scalar from a possibly negative number (reduced mod Order).
func SInt(v int64) Scalar {
	if v >= 0 {
		return S(uint64(v))
	}
	return Neg(S(uint64(-v)))
}

// FromBig reduces a big integer mod Order.
func FromBig(x *big.Int) Scalar {
	r := new(big.Int).Mod(x, Order)
	var b [32]byte
	r.FillBytes(b[:])
	var s Scalar
	s.SetBytes(&b)
	return s
}

// ToBig converts a scalar to a big integer in [0, Order).
func ToBig(s Scalar) *big.Int {
	b := s.Bytes()
	return new(big.Int).SetBytes(b[:])
}

// ScalarFromBytes reads 32 big-endian bytes and refuses values >= Order.
func ScalarFromBytes(b []byte) (Scalar, bool) {
	var s Scalar
	if len(b) != 32 {
		return s, false
	}
	overflow := s.SetByteSlice(b)
	return s, !overflow
}

// Add, Sub, Mul, Neg and Inv are mod Order and leave their arguments alone.
func Add(a, b Scalar) Scalar { var r Scalar; r.Add2(&a, &b); return r }
func Sub(a, b Scalar) Scalar { n := Neg(b); return Add(a, n) }
func Mul(a, b Scalar) Scalar { var r Scalar; r.Mul2(&a, &b); return r }
func Neg(a Scalar) Scalar    { var r Scalar; r.NegateVal(&a); return r }
func Inv(a Scalar) Scalar    { var r Scalar; r.InverseValNonConst(&a); return r }

// Sum adds a list of scalars.
func Sum(xs []Scalar) Scalar {
	var acc Scalar
	for i := range xs {
		acc.Add(&xs[i])
	}
	return acc
}

// RandomScalar is uniform in [1, Order-1], like group.random_scalar.
func RandomScalar() Scalar {
	limit := new(big.Int).Sub(Order, big.NewInt(1))
	for {
		x, err := rand.Int(rand.Reader, limit)
		if err != nil {
			panic(err)
		}
		x.Add(x, big.NewInt(1))
		return FromBig(x)
	}
}

// RandomVector returns n random scalars.
func RandomVector(n int) []Scalar {
	out := make([]Scalar, n)
	for i := range out {
		out[i] = RandomScalar()
	}
	return out
}

// Inner returns <a, b> mod Order.
func Inner(a, b []Scalar) Scalar {
	var acc Scalar
	for i := range a {
		t := Mul(a[i], b[i])
		acc.Add(&t)
	}
	return acc
}

// Powers returns [1, x, x^2, ..., x^(n-1)].
func Powers(x Scalar, n int) []Scalar {
	out := make([]Scalar, n)
	acc := S(1)
	for i := 0; i < n; i++ {
		out[i] = acc
		acc = Mul(acc, x)
	}
	return out
}

// IsPowerOfTwo is the same check as nizk/util.is_power_of_two.
func IsPowerOfTwo(n int) bool { return n > 0 && n&(n-1) == 0 }
