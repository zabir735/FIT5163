package attacks

import (
	"bytes"
	"strings"
	"testing"
)

// Small versions of the experiments, checking the outcomes that must always
// hold, like tests/test_attacks.py.

func TestMinerPrivacyShape(t *testing.T) {
	var out bytes.Buffer
	MinerPrivacy(&out, Config{Seed: 1, Trials: 6, RingSizes: []int{8}, Proof: "stub", MinerDecoys: 3})
	s := out.String()
	for _, want := range []string{
		"legacy: no mitigation                     100.0%   100.0%",
		"careless self-transfer + S-1 rule         100.0%   100.0%",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in:\n%s", want, s)
		}
	}
	if !strings.Contains(s, "self-transfer + S-1 ring rule") || strings.Contains(s, "self-transfer + S-1 ring rule              100.0%   100.0%") {
		t.Errorf("the protected row should never be certain:\n%s", s)
	}
}

func TestQBoundIsExact(t *testing.T) {
	var out bytes.Buffer
	QBound(&out, Config{Trials: 2, Qs: []int{2}})
	s := out.String()
	if !strings.Contains(s, "tags seen =  2   next tag predicted:    0%") ||
		!strings.Contains(s, "tags seen =  3   next tag predicted:  100%") ||
		!strings.Contains(s, "wallet refused use #3 in 100%") {
		t.Fatalf("q-bound not exact:\n%s", s)
	}
}

func TestRelatedKey(t *testing.T) {
	var out bytes.Buffer
	RelatedKey(&out, Config{Trials: 3})
	s := strings.Join(strings.Fields(out.String()), " ")
	if !strings.Contains(s, "naive sk = H(s) + lsk Monero-style: delta = H(s1) - H(s2) 100% 0%") {
		t.Fatalf("naive keys should always link:\n%s", s)
	}
	if strings.Count(s, " 0% 0%") < 3 {
		t.Fatalf("polynomial keys should never link:\n%s", s)
	}
}

func TestChainScenarioRules(t *testing.T) {
	var out bytes.Buffer
	ChainScenario(&out, Config{Seed: 4, Trials: 3, RingSizes: []int{8}, Proof: "stub"})
	s := out.String()
	for _, want := range []string{
		"wallet refuses to build 100.0%, hand-made copy rejected by chain (⊥) 100.0%",
		"careless self-transfer     accepted by chain: 100%   Eve success 100.0%   certain 100.0%",
		"coinbases in rings of ordinary spends: 0.00",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in:\n%s", want, s)
		}
	}
}
