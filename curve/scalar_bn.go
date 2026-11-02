//go:build bn256

package curve

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// Scalar is an integer mod the BN254 group order r. It wraps gnark-crypto's
// fr.Element (Montgomery form, fixed-size words) and copies the few methods of
// secp256k1.ModNScalar the rest of the code uses, so nothing outside this
// package needs to know which curve it runs on.
type Scalar struct{ e fr.Element }

// Order is the BN254 group order r.
var Order = fr.Modulus()

func (s *Scalar) Add(o *Scalar) *Scalar { s.e.Add(&s.e, &o.e); return s }
func (s *Scalar) IsZero() bool          { return s.e.IsZero() }
func (s *Scalar) Equals(o *Scalar) bool { return s.e.Equal(&o.e) }
func (s *Scalar) SetInt(v uint32) *Scalar {
	s.e.SetUint64(uint64(v))
	return s
}

// Bytes is the 32-byte big-endian value, as for ModNScalar.
func (s *Scalar) Bytes() [32]byte { return s.e.Bytes() }

func S(v uint64) Scalar {
	var s Scalar
	s.e.SetUint64(v)
	return s
}

func FromBig(x *big.Int) Scalar {
	var s Scalar
	s.e.SetBigInt(x) // reduces mod r, negatives included
	return s
}

func ToBig(s Scalar) *big.Int { return s.e.BigInt(new(big.Int)) }

// ScalarFromBytes reads 32 big-endian bytes and refuses values >= Order.
func ScalarFromBytes(b []byte) (Scalar, bool) {
	var s Scalar
	if len(b) != 32 {
		return s, false
	}
	if new(big.Int).SetBytes(b).Cmp(Order) >= 0 {
		return s, false
	}
	s.e.SetBytes(b)
	return s, true
}

func Add(a, b Scalar) Scalar { var r Scalar; r.e.Add(&a.e, &b.e); return r }
func Sub(a, b Scalar) Scalar { var r Scalar; r.e.Sub(&a.e, &b.e); return r }
func Mul(a, b Scalar) Scalar { var r Scalar; r.e.Mul(&a.e, &b.e); return r }
func Neg(a Scalar) Scalar    { var r Scalar; r.e.Neg(&a.e); return r }
func Inv(a Scalar) Scalar    { var r Scalar; r.e.Inverse(&a.e); return r }
