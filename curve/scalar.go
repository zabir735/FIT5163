package curve

import (
	"crypto/rand"
	"math/big"
)

// SInt makes a scalar from a possibly negative number (reduced mod Order).
func SInt(v int64) Scalar {
	if v >= 0 {
		return S(uint64(v))
	}
	return Neg(S(uint64(-v)))
}

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

// FromBigBytes writes a non-negative integer as 32 big-endian bytes (for tests
// that need an out-of-range encoding).
func FromBigBytes(x *big.Int) []byte {
	b := make([]byte, 32)
	x.FillBytes(b)
	return b
}
