//go:build !bn256

package curve

import (
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
