// Command attacks runs the six attack experiments, like python -m attacks.<name>.
//
//	go run ./cmd/attacks miner_privacy --trials 200 --ring-sizes 8,16,32
//	go run ./cmd/attacks all                      # every experiment with run_all's settings
package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	"succinctgo/attacks"
)

func ints(s string) []int {
	var out []int
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p == "" {
			continue
		}
		v, err := strconv.Atoi(p)
		if err != nil {
			fmt.Fprintf(os.Stderr, "bad number %q\n", p)
			os.Exit(2)
		}
		out = append(out, v)
	}
	return out
}

var experiments = map[string]func(cfg attacks.Config){
	"miner_privacy":       func(c attacks.Config) { attacks.MinerPrivacy(os.Stdout, c) },
	"anonymity_reduction": func(c attacks.Config) { attacks.AnonymityReduction(os.Stdout, c) },
	"related_key_tag":     func(c attacks.Config) { attacks.RelatedKey(os.Stdout, c) },
	"q_bound_linkability": func(c attacks.Config) { attacks.QBound(os.Stdout, c) },
	"chain_scenario":      func(c attacks.Config) { attacks.ChainScenario(os.Stdout, c) },
	"multi_self_transfer": func(c attacks.Config) { attacks.MultiSelfTransfer(os.Stdout, c) },
}

// The settings run_all uses for the Python version.
var runAll = []struct {
	name string
	cfg  attacks.Config
}{
	{"miner_privacy", attacks.Config{Trials: 200, RingSizes: []int{8, 16, 32}, MinerDecoys: 3}},
	{"anonymity_reduction", attacks.Config{Trials: 200, RingSizes: []int{8, 16, 32}, MinerDecoys: 3}},
	{"related_key_tag", attacks.Config{Trials: 20}},
	{"q_bound_linkability", attacks.Config{Trials: 10, Qs: []int{1, 2, 3, 5}}},
	{"chain_scenario", attacks.Config{Trials: 200, RingSizes: []int{8, 16, 32, 64}}},
	{"multi_self_transfer", attacks.Config{Trials: 200, RingSizes: []int{8, 16, 32, 64}, Coinbases: 3}},
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: attacks <name>|all [--trials N] [--ring-sizes 8,16] [--seed N] [--proof stub|real|bpp]")
		fmt.Fprintln(os.Stderr, "names: miner_privacy anonymity_reduction related_key_tag q_bound_linkability chain_scenario multi_self_transfer")
		os.Exit(2)
	}
	name := os.Args[1]
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	seed := fs.Uint64("seed", 5163, "seed for the experiment's own choices")
	trials := fs.Int("trials", 0, "trials per setting (default: the Python script's)")
	rings := fs.String("ring-sizes", "", "comma-separated ring sizes")
	proof := fs.String("proof", "stub", "stub (fast), real (Σ-protocol) or bpp (Bulletproofs++)")
	decoys := fs.Int("miner-decoys", 3, "coinbase decoys in legacy rings")
	qs := fs.String("q", "", "comma-separated q values (q-bound)")
	cbs := fs.Int("coinbases", 3, "coinbases per multi-self-transfer")
	fs.Parse(os.Args[2:])

	if name == "all" {
		for i, e := range runAll {
			if i > 0 {
				fmt.Println(strings.Repeat("=", 60))
			}
			cfg := e.cfg
			cfg.Seed, cfg.Proof = *seed, *proof
			experiments[e.name](cfg)
		}
		return
	}
	run, ok := experiments[name]
	if !ok {
		fmt.Fprintf(os.Stderr, "unknown experiment %q\n", name)
		os.Exit(2)
	}
	cfg := attacks.Config{Trials: 30, RingSizes: []int{8, 16, 32}, MinerDecoys: *decoys, Qs: []int{1, 2, 3, 5},
		Coinbases: *cbs, Seed: *seed, Proof: *proof}
	for _, e := range runAll {
		if e.name == name {
			cfg.Trials = e.cfg.Trials
		}
	}
	if *trials > 0 {
		cfg.Trials = *trials
	}
	if *rings != "" {
		cfg.RingSizes = ints(*rings)
	}
	if *qs != "" {
		cfg.Qs = ints(*qs)
	}
	run(cfg)
}
