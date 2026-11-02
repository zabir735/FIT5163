//go:build !bn256

package curve

import (
	"math/bits"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// pippenger computes sum k_i*P_i with the bucket method: split every scalar
// into c-bit windows; for each window, drop each point into the bucket of its
// digit, then add the buckets up with a running sum. Cost is about
// (256/c)*(n + 2^c) point additions instead of n full multiplications, which is
// what makes large proofs cheap to check. Only the library's add and double
// are used.
func pippenger(scalars []Scalar, points []Point) Point {
	n := len(scalars)
	c := bits.Len(uint(n)) - 2 // about log2(n) - 1
	if c < 2 {
		c = 2
	}
	if c > 12 {
		c = 12
	}
	digits := make([][32]byte, n)
	for i := range scalars {
		digits[i] = scalars[i].Bytes()
	}
	digit := func(i, w int) int {
		// bits [w*c, w*c+c) of scalar i, little-endian bit order
		v, start := 0, w*c
		for b := 0; b < c; b++ {
			bit := start + b
			if bit >= 256 {
				break
			}
			if digits[i][31-bit/8]>>(bit%8)&1 == 1 {
				v |= 1 << b
			}
		}
		return v
	}
	windows := (256 + c - 1) / c
	buckets := make([]secp256k1.JacobianPoint, 1<<c)
	var acc secp256k1.JacobianPoint
	for w := windows - 1; w >= 0; w-- {
		for k := 0; k < c; k++ {
			secp256k1.DoubleNonConst(&acc, &acc)
		}
		for b := range buckets {
			buckets[b] = secp256k1.JacobianPoint{}
		}
		for i := 0; i < n; i++ {
			if points[i].IsIdentity() {
				continue
			}
			if d := digit(i, w); d != 0 {
				secp256k1.AddNonConst(&buckets[d], &points[i].j, &buckets[d])
			}
		}
		var running, total secp256k1.JacobianPoint
		for b := len(buckets) - 1; b >= 1; b-- {
			secp256k1.AddNonConst(&running, &buckets[b], &running)
			secp256k1.AddNonConst(&total, &running, &total)
		}
		secp256k1.AddNonConst(&acc, &total, &acc)
	}
	return fromJacobian(&acc)
}
