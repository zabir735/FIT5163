// Package curve is the Go twin of succinct/group.py, transcript.py, pedersen.py,
// tagging.py and keyagreement.py: the prime-order group, the hashes and the
// small building blocks everything else is made from.
//
// Notation is additive, as in the Python code: the paper's G^x is x*G here, and
// A·B is A + B.
//
// The curve is secp256k1. Point arithmetic comes from github.com/decred/dcrd's
// secp256k1 package (pure Go, used by Decred and btcd); we never do curve
// arithmetic ourselves. Like libsecp256k1 in the Python version, the library's
// public-key type can't hold the identity, so Point keeps it as a flag-free
// "all zero" Jacobian point and every operation checks for it first.
//
// Every encoding (points, hashes, generators) matches the Python version byte
// for byte, so a transaction made by one can be verified by the other.
package curve

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// PointBytes is the size of an encoded point: SEC1 compressed, or 33 zero bytes
// for the identity.
const PointBytes = 33

// Point is an element of the group. It is always stored either as the identity
// (all zero) or in affine form (Z = 1), so encoding and comparing are cheap.
// Points are values; operations return new ones.
type Point struct {
	j secp256k1.JacobianPoint
}

// Identity returns the neutral element.
func Identity() Point { return Point{} }

// IsIdentity reports whether p is the point at infinity.
func (p Point) IsIdentity() bool {
	return (p.j.X.IsZero() && p.j.Y.IsZero()) || p.j.Z.IsZero()
}

func fromJacobian(j *secp256k1.JacobianPoint) Point {
	var out Point
	if (j.X.IsZero() && j.Y.IsZero()) || j.Z.IsZero() {
		return out
	}
	out.j.Set(j)
	out.j.ToAffine()
	return out
}

// Add returns p + q.
func (p Point) Add(q Point) Point {
	if p.IsIdentity() {
		return q
	}
	if q.IsIdentity() {
		return p
	}
	var r secp256k1.JacobianPoint
	secp256k1.AddNonConst(&p.j, &q.j, &r)
	return fromJacobian(&r)
}

// Neg returns -p: same x, the other y.
func (p Point) Neg() Point {
	if p.IsIdentity() {
		return p
	}
	out := p
	out.j.Y.Negate(1).Normalize()
	return out
}

// Sub returns p - q.
func (p Point) Sub(q Point) Point { return p.Add(q.Neg()) }

// Mul returns k*p.
func (p Point) Mul(k Scalar) Point {
	if k.IsZero() || p.IsIdentity() {
		return Identity()
	}
	var r secp256k1.JacobianPoint
	secp256k1.ScalarMultNonConst(&k, &p.j, &r)
	return fromJacobian(&r)
}

// Equal compares two points.
func (p Point) Equal(q Point) bool {
	if p.IsIdentity() || q.IsIdentity() {
		return p.IsIdentity() && q.IsIdentity()
	}
	return p.j.X.Equals(&q.j.X) && p.j.Y.Equals(&q.j.Y)
}

// Bytes is the SEC1 compressed encoding (0x02/0x03 + 32-byte x), or 33 zero
// bytes for the identity, exactly like group.Point.to_bytes in Python.
func (p Point) Bytes() []byte {
	out := make([]byte, PointBytes)
	if p.IsIdentity() {
		return out
	}
	out[0] = 2
	if p.j.Y.IsOdd() {
		out[0] = 3
	}
	p.j.X.PutBytesUnchecked(out[1:])
	return out
}

// Key is the point's encoding as a string, for use as a map key.
func (p Point) Key() string { return string(p.Bytes()) }

// String shows the first bytes, like the Python repr.
func (p Point) String() string {
	if p.IsIdentity() {
		return "Point(identity)"
	}
	return fmt.Sprintf("Point(%x...)", p.Bytes()[:8])
}

// PointFromBytes decodes 33 bytes; the library checks the point is on the curve.
func PointFromBytes(data []byte) (Point, error) {
	if len(data) != PointBytes {
		return Point{}, errors.New("expected 33 bytes")
	}
	zero := true
	for _, b := range data {
		if b != 0 {
			zero = false
			break
		}
	}
	if zero {
		return Identity(), nil
	}
	if data[0] != 2 && data[0] != 3 {
		return Point{}, errors.New("bad prefix")
	}
	pk, err := secp256k1.ParsePubKey(data)
	if err != nil {
		return Point{}, errors.New("not a valid curve point")
	}
	var j secp256k1.JacobianPoint
	pk.AsJacobian(&j)
	return fromJacobian(&j), nil
}

// UsePippenger switches MultiExp from one multiplication per term (the same
// algorithm as the Python version, the default) to Pippenger's bucket method
// for large sums. The benchmark runs both, to separate the language from the
// algorithm.
var UsePippenger = false

// MultiExp returns sum_i scalars[i]*points[i] (the paper's prod A_i^x_i).
// Zero scalars and identity points are skipped, which matters for one-hot
// vectors.
func MultiExp(scalars []Scalar, points []Point) Point {
	if len(scalars) != len(points) {
		panic("MultiExp: length mismatch")
	}
	if UsePippenger && len(scalars) >= 32 {
		return pippenger(scalars, points)
	}
	var acc, term secp256k1.JacobianPoint
	for i := range scalars {
		if scalars[i].IsZero() || points[i].IsIdentity() {
			continue
		}
		secp256k1.ScalarMultNonConst(&scalars[i], &points[i].j, &term)
		secp256k1.AddNonConst(&acc, &term, &acc)
	}
	return fromJacobian(&acc)
}

// PointSum adds a list of points.
func PointSum(points []Point) Point {
	var acc secp256k1.JacobianPoint
	for i := range points {
		if points[i].IsIdentity() {
			continue
		}
		secp256k1.AddNonConst(&acc, &points[i].j, &acc)
	}
	return fromJacobian(&acc)
}

// --- the curve's own constants ---------------------------------------------

// FieldP is the prime the coordinates live in.
var FieldP, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)

// G is the standard secp256k1 base point.
var G = func() Point {
	var one secp256k1.ModNScalar
	one.SetInt(1)
	var j secp256k1.JacobianPoint
	secp256k1.ScalarBaseMultNonConst(&one, &j)
	return fromJacobian(&j)
}()

// pointFromX returns the point with this x and an even y, or false if x^3 + 7
// isn't a square. Used by HashToPoint.
func pointFromX(x *big.Int) (Point, bool) {
	var fx, fy secp256k1.FieldVal
	var buf [32]byte
	x.FillBytes(buf[:])
	fx.SetBytes(&buf)
	if !secp256k1.DecompressY(&fx, false, &fy) {
		return Point{}, false
	}
	var one secp256k1.FieldVal
	one.SetInt(1)
	j := secp256k1.MakeJacobianPoint(&fx, &fy, &one)
	return fromJacobian(&j), true
}
