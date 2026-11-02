package curve

import "testing"

func BenchmarkMul(b *testing.B) {
	k := RandomScalar()
	p := U
	for i := 0; i < b.N; i++ {
		p.Mul(k)
	}
}

func BenchmarkMultiExp64(b *testing.B) {
	pts := GeneratorVector("bench", 64)
	sc := RandomVector(64)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		MultiExp(sc, pts)
	}
}
