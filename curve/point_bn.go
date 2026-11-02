//go:build bn256

// Package curve, BN254 build. Built with -tags bn256, every point lives in G1
// of BN254 (the "bn256" / alt_bn128 curve the SuccinCT paper benchmarks on),
// using github.com/consensys/gnark-crypto. Hashes, labels and the protocol are
// unchanged; only the group differs, so encodings are not compatible with the
// Python version (which is secp256k1 only).
package curve

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// PointBytes is gnark's compressed G1 encoding: 32 bytes, flags in the top bits.
const PointBytes = 32

// CurveName is printed by the benchmarks.
const CurveName = "BN254 (gnark-crypto)"

// Point is a G1 element kept in affine form; (0, 0) is the identity, as in gnark.
type Point struct{ a bn254.G1Affine }

func Identity() Point            { return Point{} }
func (p Point) IsIdentity() bool { return p.a.IsInfinity() }

func fromJac(j *bn254.G1Jac) Point {
	var out Point
	out.a.FromJacobian(j)
	return out
}

func (p Point) Add(q Point) Point {
	var j bn254.G1Jac
	j.FromAffine(&p.a)
	j.AddMixed(&q.a)
	return fromJac(&j)
}

func (p Point) Neg() Point {
	var out Point
	out.a.Neg(&p.a)
	return out
}

func (p Point) Sub(q Point) Point { return p.Add(q.Neg()) }

func (p Point) Mul(k Scalar) Point {
	if k.IsZero() || p.IsIdentity() {
		return Identity()
	}
	var out Point
	out.a.ScalarMultiplication(&p.a, k.e.BigInt(new(big.Int)))
	return out
}

func (p Point) Equal(q Point) bool { return p.a.Equal(&q.a) }

func (p Point) Bytes() []byte {
	b := p.a.Bytes()
	return b[:]
}

func (p Point) Key() string { return string(p.Bytes()) }

func (p Point) String() string {
	if p.IsIdentity() {
		return "Point(identity)"
	}
	return fmt.Sprintf("Point(%x...)", p.Bytes()[:8])
}

// PointFromBytes decodes 32 bytes; gnark checks the point is on the curve
// (G1 has cofactor 1, so that is also the subgroup check).
func PointFromBytes(data []byte) (Point, error) {
	if len(data) != PointBytes {
		return Point{}, errors.New("expected 32 bytes")
	}
	var out Point
	if _, err := out.a.SetBytes(data); err != nil {
		return Point{}, errors.New("not a valid curve point")
	}
	return out, nil
}

// UsePippenger switches MultiExp from one multiplication per term to
// gnark-crypto's multi-scalar multiplication (a tuned Pippenger), single core.
var UsePippenger = false

func MultiExp(scalars []Scalar, points []Point) Point {
	if len(scalars) != len(points) {
		panic("MultiExp: length mismatch")
	}
	if UsePippenger && len(scalars) >= 32 {
		pts := make([]bn254.G1Affine, len(points))
		sc := make([]fr.Element, len(scalars))
		for i := range points {
			pts[i] = points[i].a
			sc[i] = scalars[i].e
		}
		var out Point
		if _, err := out.a.MultiExp(pts, sc, ecc.MultiExpConfig{NbTasks: 1}); err != nil {
			panic(err)
		}
		return out
	}
	var acc, term bn254.G1Jac
	for i := range scalars {
		if scalars[i].IsZero() || points[i].IsIdentity() {
			continue
		}
		term.FromAffine(&points[i].a)
		term.ScalarMultiplication(&term, scalars[i].e.BigInt(new(big.Int)))
		acc.AddAssign(&term)
	}
	return fromJac(&acc)
}

func PointSum(points []Point) Point {
	var acc bn254.G1Jac
	for i := range points {
		acc.AddMixed(&points[i].a)
	}
	return fromJac(&acc)
}

// FieldP is the base-field prime.
var FieldP = fp.Modulus()

// G is gnark's standard G1 generator (1, 2).
var G = func() Point {
	_, _, g, _ := bn254.Generators()
	return Point{g}
}()

// pointFromX: y^2 = x^3 + 3; keep the even y, like the secp256k1 build.
func pointFromX(x *big.Int) (Point, bool) {
	var fx, rhs, y fp.Element
	fx.SetBigInt(x)
	rhs.Square(&fx).Mul(&rhs, &fx)
	var three fp.Element
	three.SetUint64(3)
	rhs.Add(&rhs, &three)
	if y.Sqrt(&rhs) == nil {
		return Point{}, false
	}
	if y.BigInt(new(big.Int)).Bit(0) == 1 {
		y.Neg(&y)
	}
	return Point{bn254.G1Affine{X: fx, Y: y}}, true
}
