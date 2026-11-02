//go:build !bn256

package succinct

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"succinctgo/curve"
	"succinctgo/nizk"
)

// Encodings and hashes must match the Python version byte for byte.
func TestVectorsMatchPython(t *testing.T) {
	cases := map[string]string{
		"G":   hex.EncodeToString(curve.G.Bytes()),
		"U":   hex.EncodeToString(curve.U.Bytes()),
		"GKA": hex.EncodeToString(curve.GKA.Bytes()),
		"T/5": hex.EncodeToString(curve.GeneratorVector("T", 6)[5].Bytes()),
		"com": hex.EncodeToString(curve.Commit(curve.S(500), curve.S(7)).Bytes()),
		"neg": hex.EncodeToString(curve.Commit(curve.SInt(-51), curve.S(7)).Bytes()),
	}
	h := curve.H("abc", 5, curve.List{curve.U, []byte{1, 2}}, curve.S(7))
	hb := h.Bytes()
	cases["H"] = hex.EncodeToString(hb[:])
	tr := curve.NewTranscript("lbl")
	tr.Append("a", []curve.Point{curve.G, curve.U})
	tr.Append("fee", 5)
	x := tr.Challenge("x")
	xb := x.Bytes()
	cases["transcript"] = hex.EncodeToString(xb[:])
	// printed by the Python version (succinct.group / transcript / pedersen)
	want := map[string]string{
		"G":          "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
		"U":          "02a86e29358fde3d36c620cc78ba1a81a7be6deef3f507dd07e703bfcf83f58968",
		"GKA":        "0290a3ffe3cb2e94114be434b379222fdc80719a6faa2db79c7bcfb40a5f42f703",
		"T/5":        "02d245ba08914ac7eb547d6d06540a835f26de105e34c468933c18c7a1820d7b89",
		"H":          "2c7056350364ab4248d67cc52cfd209f65a7cb9f9face0e4916e0cf6754b993e",
		"com":        "03fad766edebddad7484e0696af47095fe2de00a27d2ca58b426eaf3548fa8c467",
		"neg":        "03ce428c3c064fed05bd003cb82b41a5f0482ca039bf942a162c94c790dc9e71fc",
		"transcript": "0075e79d6c4de9fab42fc96419a92c952fd744b5a1da5411b525b88db02dd430",
	}
	for k, v := range want {
		if cases[k] != v {
			t.Errorf("%s = %s, Python gives %s", k, cases[k], v)
		}
	}
}

// A transaction made by the Python version verifies here (go/crosscheck.py make).
func TestPythonTransactionVerifies(t *testing.T) {
	raw, err := os.ReadFile("testdata/python_tx.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Outputs []struct {
			Pk, Co, Info string
			Ctxt         uint64
			Kappa        int
		}
		Tx string
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	pt := func(h string) curve.Point {
		b, _ := hex.DecodeString(h)
		p, err := curve.PointFromBytes(b)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	c := NewChain(nizk.Sigma{}, 600)
	for _, o := range f.Outputs {
		var info *curve.Point
		if o.Info != "" {
			p := pt(o.Info)
			info = &p
		}
		c.AddOutput(Account{Pk: pt(o.Pk), Co: pt(o.Co), Ctxt: o.Ctxt, Kappa: o.Kappa}, info)
	}
	data, _ := hex.DecodeString(f.Tx)
	tx, sig, err := DecodeTransaction(data)
	if err != nil {
		t.Fatal(err)
	}
	if got := c.Verify(tx, sig); got != Valid {
		t.Fatalf("Python's transaction: verify = %v", got)
	}
	bad := tx.Copy()
	bad.Info = curve.G
	if c.Verify(bad, sig) != BadProof {
		t.Fatal("swapped tek should fail the proof")
	}
}
