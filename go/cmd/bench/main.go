// Command bench measures Spend and Verify time and transaction size, with the
// same transaction shape as eval/bench_time.py and eval/bench_size.py: two
// ordinary inputs of 60 and 40 pay 60 and 39 with a fee of 1, rings 128-1024.
// Keys, chain, ring and inputs are built before timing; each repetition makes a
// fresh proof and only pairs whose Verify returns Valid count.
//
//	go run ./cmd/bench                          # 100 runs per ring size
//	go run ./cmd/bench -reps 10 -rings 128,256  # quicker
//	go run ./cmd/bench -csv results/bench_go.csv
package main

import (
	"encoding/csv"
	"flag"
	"fmt"
	"math"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"succinctgo/attacks"
	"succinctgo/curve"
	"succinctgo/nizk"
	"succinctgo/succinct"
)

type setup struct {
	members []succinct.RingMember
	inputs  []succinct.SpendInput
	outputs []succinct.SpendOutput
	info    curve.Point
	chain   *succinct.Chain
}

func prepare(n int) setup {
	c := succinct.NewChain(nizk.Sigma{}, 600)
	for i := 0; i < n; i++ {
		mpk, _, _ := succinct.SAKGen(1)
		_, acc, info := succinct.OTAccGen(mpk, 1000, 1, nil)
		c.AddOutput(acc, info)
	}
	mpk, msk, _ := succinct.SAKGen(4)
	var refs []uint32
	for _, a := range []uint64{60, 40} {
		_, acc, info := succinct.OTAccGen(mpk, a, 1, nil)
		refs = append(refs, c.AddOutput(acc, info))
	}
	ring, pos, err := succinct.PickRing(c, refs, n, succinct.NewSeededRng(5163))
	if err != nil {
		panic(err)
	}
	var s setup
	s.chain = c
	for k, r := range refs {
		acc, info, _ := c.Get(r)
		o, ok := succinct.Receive(msk, mpk, acc, info)
		if !ok {
			panic("receive failed")
		}
		s.inputs = append(s.inputs, succinct.SpendInput{Ind: pos[k], Ck: o.Ck, A: int64(o.A), Sk: o.Sk, Tag: o.Tag})
	}
	bob, _, _ := succinct.SAKGen(1)
	s.outputs, s.info = succinct.MakeOutputs([]succinct.Payment{{To: bob, Amount: 60}, {To: mpk, Amount: 39}})
	for _, r := range ring {
		acc, _, _ := c.Get(r)
		s.members = append(s.members, succinct.RingMember{Ref: r, Acc: acc})
	}
	return s
}

func stats(xs []float64) (mean, std, lo, hi float64) {
	lo, hi = math.Inf(1), math.Inf(-1)
	for _, x := range xs {
		mean += x
		lo, hi = math.Min(lo, x), math.Max(hi, x)
	}
	mean /= float64(len(xs))
	for _, x := range xs {
		std += (x - mean) * (x - mean)
	}
	if len(xs) > 1 {
		std = math.Sqrt(std / float64(len(xs)-1))
	}
	return
}

func main() {
	reps := flag.Int("reps", 100, "spend/verify pairs per ring size")
	rings := flag.String("rings", "128,256,512,1024", "comma-separated ring sizes")
	out := flag.String("csv", "", "write results to this CSV file")
	pip := flag.Bool("pippenger", false, "use Pippenger multi-exponentiation instead of one multiplication per term")
	proofName := flag.String("proof", "sigma", "sigma (Σ-protocol + Bulletproofs range proof) or bpp (Bulletproofs++)")
	flag.Parse()
	sys := attacks.GetSystem(*proofName)
	if _, isStub := sys.(nizk.Stub); isStub {
		panic("-proof must be sigma or bpp")
	}
	curve.UsePippenger = *pip
	mode := "term-by-term multiexp (same algorithm as Python)"
	if *pip {
		mode = "Pippenger multiexp"
	}

	var sizes []int
	for _, p := range strings.Split(*rings, ",") {
		v, err := strconv.Atoi(strings.TrimSpace(p))
		if err != nil {
			panic(err)
		}
		sizes = append(sizes, v)
	}
	header := []string{"ring_size", "repetitions", "spend_mean_ms", "spend_std_ms", "spend_min_ms", "spend_max_ms",
		"verify_mean_ms", "verify_std_ms", "verify_min_ms", "verify_max_ms", "tx_bytes", "proof_bytes",
		"go_version", "os", "arch", "cpus", "threads", "multiexp", "curve", "proof"}
	var rows [][]string
	fmt.Printf("Go %s, %s/%s, single goroutine, %s, %d reps per ring size\n", runtime.Version(), runtime.GOOS, runtime.GOARCH, mode, *reps)
	fmt.Printf("curve: %s; proof: %s; 2 inputs, 2 outputs\n", curve.CurveName, sys.Name())
	fmt.Printf("%6s %12s %12s %10s %10s\n", "ring", "spend ms", "verify ms", "tx bytes", "proof B")
	for _, n := range sizes {
		s := prepare(n)
		// warm-up: builds and caches the generators, so the first timed run isn't penalised
		tx, sig, err := succinct.Spend(s.members, s.inputs, s.outputs, s.info, 1, nil, sys)
		if err != nil || succinct.Verify(tx, sig, s.chain, sys) != succinct.Valid {
			panic(fmt.Sprintf("warm-up failed: %v", err))
		}
		var sp, vf []float64
		size, proof := succinct.TransactionSize(tx, sig), succinct.ProofSize(sig.Proof)
		for r := 0; r < *reps; r++ {
			t0 := time.Now()
			tx, sig, err := succinct.Spend(s.members, s.inputs, s.outputs, s.info, 1, nil, sys)
			t1 := time.Now()
			if err != nil {
				continue
			}
			ok := succinct.Verify(tx, sig, s.chain, sys) == succinct.Valid
			t2 := time.Now()
			if ok {
				sp = append(sp, float64(t1.Sub(t0).Nanoseconds())/1e6)
				vf = append(vf, float64(t2.Sub(t1).Nanoseconds())/1e6)
			}
		}
		sm, ss, sl, sh := stats(sp)
		vm, vs, vl, vh := stats(vf)
		fmt.Printf("%6d %7.1f ± %-4.1f %7.1f ± %-4.1f %10d %10d\n", n, sm, ss, vm, vs, size, proof)
		f := func(x float64) string { return strconv.FormatFloat(x, 'f', 3, 64) }
		rows = append(rows, []string{strconv.Itoa(n), strconv.Itoa(len(sp)), f(sm), f(ss), f(sl), f(sh),
			f(vm), f(vs), f(vl), f(vh), strconv.Itoa(size), strconv.Itoa(proof),
			runtime.Version(), runtime.GOOS, runtime.GOARCH, strconv.Itoa(runtime.NumCPU()), "1", map[bool]string{false: "term-by-term", true: "pippenger"}[*pip],
			curve.CurveName, *proofName})
	}
	if *out != "" {
		fh, err := os.Create(*out)
		if err != nil {
			panic(err)
		}
		w := csv.NewWriter(fh)
		w.Write(header)
		w.WriteAll(rows)
		fh.Close()
		fmt.Println("wrote", *out)
	}
}
