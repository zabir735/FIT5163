# SuccinCT in Go

A second implementation of our Python code, written to answer one question
from the evaluation: **how much of the gap with the paper is the language, and
how much is our proof?** It is the same design, not the paper's: the same
secp256k1 curve, the same Σ-protocol and Bulletproofs range proof (no
Bulletproofs++), the same toy chain, demo and attack experiments.

The Python version stays the main submission and the one we demo. This is
extra evidence for the report.

## It is the same scheme, byte for byte

Every hash, generator, transcript label and byte of the transaction format
matches the Python code, so **a transaction made by either version verifies in
the other**, and both reject the same tampered copies:

```
go run ./cmd/crosscheck make fx.json && python crosscheck.py check fx.json   # Go -> Python
python crosscheck.py make fx.json && go run ./cmd/crosscheck check fx.json   # Python -> Go
```

Both directions print `original: True`, `fee edited: False`, `tek swapped:
False`, `resubmitted: None`. `succinct/compat_test.go` keeps this checked: it
compares test vectors with the Python output and verifies a transaction the
Python version made (`succinct/testdata/python_tx.json`). Transaction sizes
are identical too (9,993 bytes at ring 128, 70,921 at ring 1024).

## Layout

| Go | Python | What |
|---|---|---|
| `curve/` | `group.py`, `transcript.py`, `pedersen.py`, `tagging.py`, `keyagreement.py` | Points, scalars, hashes, generators, commitments, tags, key agreement |
| `nizk/` | `nizk/` | Eq. 5 relation, Σ-protocol, Bulletproofs range proof, inner-product argument, stub |
| `succinct/` | `stealth.py`, `ct.py`, `chain.py`, `wallet.py`, `serialize.py` | SAKGen, OTAccGen, View, Receive, PickRing, Spend, Verify, Mine, the chain, wallet helpers, byte format |
| `attacks/` | `attacks/` | All six experiments and Eve |
| `cmd/demo` | `demo.py` | The same 13-step demo, same amounts and options |
| `cmd/bench` | `eval/bench_time.py`, `bench_size.py` | Spend/Verify timing and sizes, rings 128-1024 |
| `cmd/attacks` | `python -m attacks.<name>` | Runs one experiment or `all` |
| `cmd/crosscheck`, `crosscheck.py` | | The Go/Python cross-check |

Curve arithmetic comes from `github.com/decred/dcrd/dcrec/secp256k1/v4` (pure
Go, used by Decred and btcd); like libsecp256k1 in Python, we never do curve
arithmetic ourselves. Hashing uses Go's standard `crypto/sha3`.

## Running it

Needs Go 1.24 or newer (`go version`). From this folder:

```
go test ./...                         # unit, compatibility and attack tests
go run ./cmd/demo -present            # the demo, real proof, pauses between steps
go run ./cmd/demo -stub -explain      # quick, with the values behind each step
go run ./cmd/attacks all              # all six experiments with run_all's settings
go run ./cmd/attacks miner_privacy -trials 200 -ring-sizes 8,16,32
go run ./cmd/bench                    # 100 runs per ring size, same algorithm as Python
go run ./cmd/bench -pippenger         # the same with Pippenger multi-exponentiation
```

The first `go` command downloads the secp256k1 module.

## Results

RESULTS_PLACEHOLDER

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

PROVENANCE: written with AI assistance (Claude) as a port of the group's
Python code; checked by the compatibility tests and the cross-check above.
