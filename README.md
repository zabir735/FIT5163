# SuccinCT in Go

This is the Go extension of the group's SuccinCT project. In the submission
it is its own zip (`FIT5163-A2-…-Code-Go.zip`) that unpacks into a folder
named `go`; unzip it inside the Python project's folder so the two sit side
by side as `go/`. In the git repository it is the `go-port` branch. Building,
testing, the demo and the benchmarks work from this folder on its own; only
the Python half of the cross-check needs the Python project around it. The main project, the Python implementation the group
submits and demos, is on the `part-a-coincurve-wallet` branch.

A second implementation of our Python code, written to answer one question
from the evaluation: **how much of the gap with the paper is the language, the
curve, and the proof system?** By default it is the same design as the
Python version: the same secp256k1 curve, the same Σ-protocol and
Bulletproofs range proof, the same toy chain, demo and attack experiments.
On top of that it adds the two things the paper uses and Python doesn't:

* **the BN254 curve** (the paper's "bn256"), via `-tags bn256`;
* **a Bulletproofs++ proof of Eq. 5** (`nizk/bpp.go`), log size, picked with
  `-proof bpp` / `-bpp`.

Every combination runs the same scheme code, so each change can be measured
on its own.

The Python version stays the main submission and the one we demo. This is
extra evidence for the report.

## It is the same scheme, byte for byte

Every hash, generator, transcript label and byte of the transaction format
matches the Python code, so **a transaction made by either version verifies in
the other**, and both reject the same tampered copies:

```
go run ./cmd/crosscheck make fx.json    # Go writes a transaction and tampered copies
go run ./cmd/crosscheck check fx.json   # Go checks a file the Python version wrote
```

The Python side of the check (`crosscheck.py`) needs the Python package, so
it runs only when this folder sits as `go/` inside the Python project, which is
how the group's submission is laid out. From the Python project's root:
`python go/crosscheck.py check fx.json` (or `make fx.json`).
Both directions print `original: True`, `fee edited: False`, `tek swapped:
False`, `resubmitted: None`. `succinct/compat_test.go` keeps this checked: it
compares test vectors with the Python output and verifies a transaction the
Python version made (`succinct/testdata/python_tx.json`). Transaction sizes
are identical too (9,993 bytes at ring 128, 70,921 at ring 1024).

## Layout

| Go | Python | What |
|---|---|---|
| `curve/` | `group.py`, `transcript.py`, `pedersen.py`, `tagging.py`, `keyagreement.py` | Points, scalars, hashes, generators, commitments, tags, key agreement |
| `nizk/` | `nizk/` | Eq. 5 relation, Σ-protocol, Bulletproofs range proof, inner-product argument, stub; `bpp.go` (Go only) the Bulletproofs++ proof |
| `succinct/` | `stealth.py`, `ct.py`, `chain.py`, `wallet.py`, `serialize.py` | SAKGen, OTAccGen, View, Receive, PickRing, Spend, Verify, Mine, the chain, wallet helpers, byte format |
| `attacks/` | `attacks/` | All six experiments and Eve |
| `cmd/demo` | `demo.py` | The same 13-step demo, same amounts and options |
| `cmd/bench` | `eval/bench_time.py`, `bench_size.py` | Spend/Verify timing and sizes, rings 128-1024 |
| `cmd/attacks` | `python -m attacks.<name>` | Runs one experiment or `all` |
| `cmd/crosscheck` | | The Go side of the Go/Python cross-check |
| `plot_go.py` | `eval/compare.py` | Charts of every version against the paper |

Curve arithmetic comes from `github.com/decred/dcrd/dcrec/secp256k1/v4` (pure
Go, used by Decred and btcd) or, with `-tags bn256`, from
`github.com/consensys/gnark-crypto` (BN254, used by gnark and many Ethereum
tools); like libsecp256k1 in Python, we never do curve arithmetic ourselves.
Hashing uses Go's standard `crypto/sha3`. `curve/point.go` and
`curve/scalar_secp.go` are the secp256k1 build, `curve/point_bn.go` and
`curve/scalar_bn.go` the BN254 one; nothing outside `curve/` knows which
curve it runs on.

## Setup

**Prerequisites**

* Go 1.24 or newer. Install from <https://go.dev/dl/>, then check with `go version`.
* Optional: Python 3.11–3.13 with matplotlib, only for `plot_go.py`. The
  Python half of the cross-check (`crosscheck.py`) also needs the Python
  project's packages (`pip install -r ../requirements.txt` from the
  submission layout).

**Dependencies.** `go.mod` pins them and `go.sum` holds their checksums:

* `github.com/decred/dcrd/dcrec/secp256k1/v4` v4.4.1, the default curve;
* `github.com/consensys/gnark-crypto` v0.14.0, the BN254 curve, used only with `-tags bn256`.

Go downloads them on the first build. To fetch them in advance, run:

```
go mod download
```

Two of gnark-crypto's own dependencies (`golang.org/x/sys`, `rsc.io/tmplfunc`)
are fetched from their official GitHub mirrors through `replace` lines,
because the network this was built on blocked golang.org and rsc.io. That
changes where they come from, not what they are, and it works on any network.

**Configuration.** Nothing to configure; all options are command-line flags:

* `-tags bn256` switches the curve from secp256k1 to BN254 at build time;
* `-proof sigma|bpp` (bench, attacks) or `-bpp` (demo) picks the proof;
* `-pippenger` turns on multi-exponentiation in the benchmark;
* `-reps` and `-rings` control the benchmark;
* `-stub`, `-explain` and `-present` control the demo, as in Python.

Seeds are fixed at 5163 where the Python version uses one; keys and proofs
use OS randomness (`crypto/rand`).

## Running it

From this folder:

```
go test ./...                         # unit, compatibility and attack tests (secp256k1)
go test -tags bn256 ./...             # the same tests on BN254
go run ./cmd/demo -present            # the demo, real proof, pauses between steps
go run ./cmd/demo -stub -explain      # quick, with the values behind each step
go run -tags bn256 ./cmd/demo -bpp    # the demo on BN254 with the Bulletproofs++ proof
go run ./cmd/attacks all              # all six experiments with run_all's settings
go run ./cmd/attacks miner_privacy -trials 200 -ring-sizes 8,16,32
go run ./cmd/bench                    # 100 runs per ring size, same algorithm as Python
go run ./cmd/bench -reps 10 -rings 128,1024   # a quick version
python plot_go.py                     # redraw the charts in results/plots/
```

Cross-check with Python, from the Python project's root (the folder above this one):

```
(cd go && go run ./cmd/crosscheck make fx.json) && python go/crosscheck.py check go/fx.json   # Go -> Python
python go/crosscheck.py make fx.json && (cd go && go run ./cmd/crosscheck check ../fx.json)    # Python -> Go
```

The cross-check only works in the default build (secp256k1, Σ-protocol),
because Python has neither BN254 nor the BP++ proof.

## Expected output

Times vary by machine; everything else should match.

| Command | Expected result |
|---|---|
| `go test ./...` | `ok` for `succinctgo/attacks`, `curve`, `nizk`, `succinct` (27 tests) |
| `go test -tags bn256 ./...` | the same four `ok` lines (23 tests; the Python-compatibility tests are secp256k1 only) |
| `go run ./cmd/demo` | first line `proof system: Σ-protocol for Eq. 5 (linear size) + Bulletproofs range proof (Go)`; the same 13 steps as `python demo.py`; ends with `Done.` |
| `go run -tags bn256 ./cmd/demo -bpp` | `proof system: Bulletproofs++ weighted norm argument …`, a line `proof: BP++, 5 folding rounds of 4 points + 5 final scalars`, the same outcomes; ends with `Done.` |
| `go run ./cmd/attacks all` | six sections (Attack 1, Attack 2, Related-key, q-bound, End-to-end, Multi-self-transfer) with the same conclusions as `results/attacks.txt` |
| `go run ./cmd/bench …` | a header naming the Go version, curve and proof, then one row per ring: spend ms, verify ms, tx bytes, proof bytes. Bytes are exact: 9,993 / 9,148 at ring 128 on secp256k1 with Σ. |
| cross-check, both directions | `original: True`, `fee edited: False`, `tek swapped: False`, `resubmitted: None` |
| `python plot_go.py` | `wrote results/plots/size_vs_paper.png` (and spend, verify) |

## Reproducing the results

Each file in `results/` comes from one command (100 runs per ring size,
rings 128–1024, two inputs and two outputs). Each writes a table to the
screen and a CSV with `-csv`:

| File | Command |
|---|---|
| `bench_go_term.*` | `go run ./cmd/bench -csv results/bench_go_term.csv` |
| `bench_go_pippenger.*` | `go run ./cmd/bench -pippenger -csv results/bench_go_pippenger.csv` |
| `bench_secp_bpp_msm.*` | `go run ./cmd/bench -pippenger -proof bpp -csv results/bench_secp_bpp_msm.csv` |
| `bench_bn254_sigma_msm.*` | `go run -tags bn256 ./cmd/bench -pippenger -proof sigma -csv results/bench_bn254_sigma_msm.csv` |
| `bench_bn254_bpp_msm.*` | `go run -tags bn256 ./cmd/bench -pippenger -proof bpp -csv results/bench_bn254_bpp_msm.csv` |
| `attacks.txt` | `go run ./cmd/attacks all > results/attacks.txt` |
| `plots/*.png` | `python plot_go.py` |

`results/baseline/` holds copies of the Python version's Linux results and
the paper's size model (from the Python project's `eval/`), so the charts
can be drawn from this folder alone.

## Environment of the recorded results

| Item | Value |
|---|---|
| Machine | Cloud VM, Intel Xeon @ 2.10 GHz, 2 vCPUs (each CSV records `cpus = 2`) |
| OS / architecture | Linux, amd64 |
| Go | 1.24.7 |
| Threads | one goroutine (single core), as in the paper's Table 3 |
| Libraries | dcrd secp256k1 v4.4.1, gnark-crypto v0.14.0 |

This is not the M3 Max that produced the Python project's final results, so
compare Go timings with each other and with the Python row measured on the
same VM, not with the M3 Max numbers.

## Results

All runs: one core, 100 spend/verify pairs per ring size, 2 inputs and 2
outputs, the same Linux VM described above (not the paper's Apple M1). Times are
means in ms; sizes are the full transaction / the proof alone, in bytes.
Raw output and CSVs are in `results/`; the Python version's results and the
paper's size model it is compared with are copied into `results/baseline/`.
`python plot_go.py` (needs matplotlib) draws the three comparison charts in `results/plots/`:
transaction size, Spend and Verify against ring size, every version plus the
paper.

**Ring 128**

| Version | Spend | Verify | Tx bytes | Proof bytes |
|---|---:|---:|---:|---:|
| Python, secp256k1, Σ-protocol | 115 | 39 | 9,993 | 9,148 |
| Go, secp256k1, Σ, one mult per term | 412 | 135 | 9,993 | 9,148 |
| Go, secp256k1, Σ, Pippenger | 260 | 55 | 9,993 | 9,148 |
| Go, secp256k1, **BP++**, Pippenger | 463 | 46 | 2,324 | 1,479 |
| Go, **BN254**, Σ, gnark MSM | 106 | 19 | 9,962 | 9,126 |
| Go, **BN254**, **BP++**, gnark MSM | 180 | 14 | 2,284 | 1,448 |
| Paper (Go, bn256, BP++, M1) | 2.0 | 1.2 | 1,648 | ~896 |

**Ring 1024**

| Version | Spend | Verify | Tx bytes | Proof bytes |
|---|---:|---:|---:|---:|
| Python, secp256k1, Σ-protocol | 488 | 231 | 70,921 | 66,492 |
| Go, secp256k1, Σ, one mult per term | 1,579 | 733 | 70,921 | 66,492 |
| Go, secp256k1, Σ, Pippenger | 610 | 228 | 70,921 | 66,492 |
| Go, secp256k1, **BP++**, Pippenger | 2,579 | 234 | 6,272 | 1,843 |
| Go, **BN254**, Σ, gnark MSM | 218 | 74 | 70,890 | 66,470 |
| Go, **BN254**, **BP++**, gnark MSM | 1,039 | 72 | 6,220 | 1,800 |
| Paper (Go, bn256, BP++, M1) | 3.6 | 2.6 | 5,424 | ~1,088 |

What this shows:

* **Bulletproofs++ fixes size, not speed.** The proof drops from 66 KB to
  1.8 KB at ring 1024 and grows by about 100 bytes per doubling of the ring,
  like the paper's. Transactions are now within 15–40% of the paper's;
  what's left is ring references (4 B each, as in the paper) and our slightly
  bigger proof. Verify gets a little faster. Spend gets slower: a
  straightforward BP++ prover folds its generator vectors point by point,
  which costs about one full multiplication per entry per vector.
* **The curve library matters more than the language.** Plain Go with the
  same algorithm is slower than Python, because dcrd's multiplication
  (~175 µs) is slower than libsecp256k1's (~39 µs) and profiling shows 95%
  of the time in it. gnark-crypto's BN254 (~61 µs, and a much faster
  multi-exponentiation) is the single biggest speed-up: 2.5–3× on everything.
* **We do not reach the paper's times.** The best version here is still
  ~50–300× slower than Table 3. A different CPU explains a factor of a few,
  not that. The paper's Spend barely grows with the ring (2.0 → 3.6 ms for
  8× more members). Even one multi-exponentiation over 1,024 points takes
  ~15 ms on this machine with gnark. So their prover must avoid work linear
  in the ring in a way their paper doesn't describe, or measure something
  narrower than our full Spend/Verify. We can't tell which from the paper.

## The Bulletproofs++ proof (`nizk/bpp.go`)

The paper says it proves Eq. 5 with Bulletproofs++ but never gives the
encoding, so **this encoding is ours**. It proves exactly what the
Σ-protocol proves (same `Statement`, same `Witness`, same oracle
`RelationHolds`), in one log-size proof instead of a linear one plus a
separate range proof:

1. Every secret bit goes in one vector: the S one-hot vectors (S·n bits) and
   the 64 bits of each output amount. The paper's hint (§5, Step 3) is that a
   bit satisfies (b − ½)² = ¼, so "all of these are bits" becomes one
   weighted-norm equation, the thing Bulletproofs++ proves.
2. The prover masks every bit (f = x·b + a). After a challenge, the masked
   vector shifted by x/2 has a weighted norm the verifier can predict from two
   committed scalars. That equation only holds for real bits (a
   Groth–Kohlweiss bit check written as a norm).
3. Eq. 5, the output openings and the one-hot sums are linear in the same
   vector. They ride along as a second base vector, folded with the same
   challenges as BP++'s weighted norm linear argument (WNLA). Each round sends
   4 points.

Proof size: 5 + m points and 4 + S + m scalars up front, 4 points per round,
≤ 8 scalars at the end. Rounds = ⌈log₂(S·n + 64m)⌉ − 3. At ring 1024 that is
about 1.8 KB, against 66 KB for our Σ-protocol and 1,088 B in the paper.

**Honest caveats.** This is a construction written for this project. It is
tested, but not reviewed by a cryptographer. The tests check it:

* against the relation oracle;
* against every bad witness the Σ-protocol tests use;
* against a ring with a duplicated member, where the cheating vector
  (0,0,0,2,−1) satisfies Eq. 5 and the one-hot sum, so only the bit check can
  catch it (`TestBPPBitCheckAlone`);
* against tampering with each part of the proof;
* against every chain test.

It uses BP++'s core (the WNLA and the norm trick for bits), not its
reciprocal range proof or full arithmetic-circuit protocol. The paper's own
proof is about 40% smaller (1,088 B vs ~1.8 KB at ring 1024), probably for
those reasons.

## Differences from the Python version

* **Randomness in the experiments.** Python's `random` and Go's `math/rand`
  give different streams, so the same seed gives statistically similar, not
  identical, attack tables (`results/attacks.txt`). The conclusions match
  (100% without the fixes, chance with them, 100% for the careless case).
  One run shows a nice edge case: at ring 32 the no-mitigation row is 99.5%,
  not 100%, because two coinbases in one ring happened to hold the same
  amount, so Eve had no unique match. That is our finding 5 (the attack is an
  inference, not a proof) happening by chance.
* **Amounts in the witness are `int64`,** so the Go version handles amounts up
  to 2^63 - 1 rather than 2^64 - 1. The range proof is still 64-bit.
* **Optional Pippenger multi-exponentiation** (`curve.UsePippenger`); off by
  default so the comparison with Python is like for like.

## Provenance

| Component | Source |
|---|---|
| Port of the scheme (`curve/`, `nizk/` Σ-protocol and range proof, `succinct/`, `attacks/`, `cmd/`) | own code, AI-assisted (Claude), run and checked by Zabir; a port of the group's Python code, kept byte-compatible with it by `succinct/compat_test.go` and the cross-check |
| BN254 backend (`curve/point_bn.go`, `curve/scalar_bn.go`) | own code, AI-assisted (Claude); curve arithmetic from gnark-crypto v0.14.0 |
| secp256k1 backend (`curve/point.go`, `curve/scalar_secp.go`, `curve/pippenger.go`) | own code, AI-assisted (Claude); curve arithmetic from dcrd secp256k1 v4.4.1 |
| Bulletproofs++ proof (`nizk/bpp.go`) | own design and code, AI-assisted (Claude). It follows the paper's §5 bit hint and the weighted norm linear argument of Eagen, Kanjalkar, Ruffing and Nick, "Bulletproofs++" (EUROCRYPT 2024). Tested, not reviewed by a cryptographer. |
| `crosscheck.py`, `plot_go.py` | own code, AI-assisted (Claude); `crosscheck.py` uses the group's Python package |
| `results/baseline/` | copies of the group's Python results (Part D) and the paper's size model; the paper's Table 3 timings are typed into `plot_go.py` |

No author code exists for SuccinCT; nothing here is copied from the paper's authors.
