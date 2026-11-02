package curve

import "testing"

// Runs on both curves (go test ./... and go test -tags bn256 ./...).

func TestGroupBasics(t *testing.T) {
	a, b := RandomScalar(), RandomScalar()
	if !G.Mul(a).Add(G.Mul(b)).Equal(G.Mul(Add(a, b))) {
		t.Fatal("aG + bG != (a+b)G")
	}
	if !G.Mul(a).Sub(G.Mul(a)).IsIdentity() || !G.Add(Identity()).Equal(G) {
		t.Fatal("identity rules broken")
	}
	if !G.Mul(FromBig(Order)).IsIdentity() {
		t.Fatal("Order*G is not the identity")
	}
	one := S(1)
	if x := Mul(a, Inv(a)); !x.Equals(&one) {
		t.Fatal("a * a^-1 != 1")
	}
	for _, p := range []Point{G, U, G.Mul(a), Identity()} {
		q, err := PointFromBytes(p.Bytes())
		if err != nil || !q.Equal(p) || len(p.Bytes()) != PointBytes {
			t.Fatalf("encoding round trip failed for %v", p)
		}
	}
	sb := a.Bytes()
	if back, ok := ScalarFromBytes(sb[:]); !ok || !back.Equals(&a) {
		t.Fatal("scalar round trip failed")
	}
	if _, ok := ScalarFromBytes(FromBigBytes(Order)); ok {
		t.Fatal("scalar >= Order accepted")
	}
}

func TestMultiExpModesAgree(t *testing.T) {
	for _, n := range []int{1, 31, 32, 100} {
		sc := RandomVector(n)
		pts := GeneratorVector("test/msm", n)
		sc[0] = S(0) // zero scalars are skipped
		UsePippenger = false
		want := MultiExp(sc, pts)
		UsePippenger = true
		got := MultiExp(sc, pts)
		UsePippenger = false
		if !got.Equal(want) {
			t.Fatalf("n=%d: multiexp modes disagree", n)
		}
	}
}
