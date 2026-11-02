// Command crosscheck shows the Go and Python versions are the same scheme: a
// transaction made by one verifies in the other.
//
//	go run ./cmd/crosscheck make  fixture.json   # Go makes a chain and a transaction
//	go run ./cmd/crosscheck check fixture.json   # Go verifies a fixture (e.g. from Python)
//
// go/crosscheck.py is the Python side with the same two commands. The fixture
// holds every chain output (so ring refs resolve the same way), the encoded
// transaction, and the tamper results each side should agree on.
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"succinctgo/curve"
	"succinctgo/nizk"
	"succinctgo/succinct"
)

type output struct {
	Pk    string `json:"pk"`
	Co    string `json:"co"`
	Ctxt  uint64 `json:"ctxt"`
	Kappa int    `json:"kappa"`
	Info  string `json:"info,omitempty"`
}

type fixture struct {
	Maker   string   `json:"maker"`
	Outputs []output `json:"outputs"`
	Tx      string   `json:"tx"`
}

func mustPoint(h string) curve.Point {
	b, err := hex.DecodeString(h)
	if err != nil {
		panic(err)
	}
	p, err := curve.PointFromBytes(b)
	if err != nil {
		panic(err)
	}
	return p
}

func chainFrom(f *fixture) *succinct.Chain {
	c := succinct.NewChain(nizk.Sigma{}, 600)
	for _, o := range f.Outputs {
		acc := succinct.Account{Pk: mustPoint(o.Pk), Co: mustPoint(o.Co), Ctxt: o.Ctxt, Kappa: o.Kappa}
		var info *curve.Point
		if o.Info != "" {
			p := mustPoint(o.Info)
			info = &p
		}
		c.AddOutput(acc, info)
	}
	return c
}

func check(path string) {
	raw, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	var f fixture
	if err := json.Unmarshal(raw, &f); err != nil {
		panic(err)
	}
	c := chainFrom(&f)
	data, _ := hex.DecodeString(f.Tx)
	tx, sig, err := succinct.DecodeTransaction(data)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Go verifying a transaction made by %s (ring %d, %d bytes)\n", f.Maker, len(tx.RingRefs), len(data))
	fmt.Printf("  original:     %v\n", c.Verify(tx, sig))
	fee := tx.Copy()
	fee.Fee = 0
	fmt.Printf("  fee edited:   %v\n", c.Verify(fee, sig))
	tek := tx.Copy()
	tek.Info = curve.G.Mul(curve.RandomScalar())
	fmt.Printf("  tek swapped:  %v\n", c.Verify(tek, sig))
	if _, err := c.Submit(tx, sig); err != nil {
		panic(err)
	}
	fmt.Printf("  resubmitted:  %v\n", c.Verify(tx, sig))
}

func make_(path string) {
	c := succinct.NewChain(nizk.Sigma{}, 600)
	for i := 0; i < 20; i++ {
		mpk, _, _ := succinct.SAKGen(1)
		_, acc, info := succinct.OTAccGen(mpk, 1000, 1, nil)
		c.AddOutput(acc, info)
	}
	mpk, msk, _ := succinct.SAKGen(5)
	_, acc, info := succinct.OTAccGen(mpk, 1000, 1, nil)
	ref := c.AddOutput(acc, info)
	bob, _, _ := succinct.SAKGen(5)
	tx, sig, _, err := succinct.Build(c, []succinct.Owned{{Ref: ref, Mpk: mpk, Msk: msk}},
		[]succinct.Payment{{To: bob, Amount: 700}, {To: mpk, Amount: 290}}, 10, 16)
	if err != nil {
		panic(err)
	}
	data, err := succinct.EncodeTransaction(tx, sig)
	if err != nil {
		panic(err)
	}
	f := fixture{Maker: "Go", Tx: hex.EncodeToString(data)}
	for r := 0; r < c.Len(); r++ {
		a, info, _ := c.Get(uint32(r))
		o := output{Pk: hex.EncodeToString(a.Pk.Bytes()), Co: hex.EncodeToString(a.Co.Bytes()), Ctxt: a.Ctxt, Kappa: a.Kappa}
		if info != nil {
			o.Info = hex.EncodeToString(info.Bytes())
		}
		f.Outputs = append(f.Outputs, o)
	}
	out, _ := json.MarshalIndent(f, "", " ")
	if err := os.WriteFile(path, out, 0o644); err != nil {
		panic(err)
	}
	fmt.Printf("Go wrote %s: ring 16, %d bytes, verifies here: %v\n", path, len(data), c.Verify(tx, sig))
}

func main() {
	if len(os.Args) != 3 || (os.Args[1] != "make" && os.Args[1] != "check") {
		fmt.Fprintln(os.Stderr, "usage: crosscheck make|check fixture.json")
		os.Exit(2)
	}
	if os.Args[1] == "make" {
		make_(os.Args[2])
	} else {
		check(os.Args[2])
	}
}
