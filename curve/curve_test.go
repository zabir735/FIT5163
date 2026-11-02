//go:build !bn256

package curve

import "testing"

func TestPippengerMatchesNaive(t *testing.T) {
	for _, n := range []int{32, 33, 100, 515} {
		pts := GeneratorVector("pip", n)
		sc := RandomVector(n)
		sc[3] = S(0)
		sc[5] = Neg(S(1))
		pts2 := append([]Point{}, pts...)
		pts2[7] = Identity()
		UsePippenger = false
		want := MultiExp(sc, pts2)
		UsePippenger = true
		got := MultiExp(sc, pts2)
		UsePippenger = false
		if !got.Equal(want) {
			t.Fatalf("n=%d: Pippenger differs from term-by-term", n)
		}
	}
}

func TestIdentityAndNegation(t *testing.T) {
	if !G.Sub(G).IsIdentity() || !G.Add(Identity()).Equal(G) || !G.Mul(Order1()).IsIdentity() {
		t.Fatal("identity rules broken")
	}
	p, err := PointFromBytes(make([]byte, 33))
	if err != nil || !p.IsIdentity() {
		t.Fatal("33 zero bytes should decode to the identity")
	}
	bad := append([]byte{2}, make([]byte, 32)...)
	bad[32] = 5
	if _, err := PointFromBytes(bad); err == nil {
		t.Fatal("an x with no point should be refused")
	}
}

// Order1 is Order as a scalar plus... Order mod Order is zero, so k*G for k = 0.
func Order1() Scalar { return FromBig(Order) }
