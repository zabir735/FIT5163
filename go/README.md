# SuccinCT in Go

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
| `nizk/` | `nizk/` | Eq. 5 relation, Σ-protocol, Bulletproofs range proof, inner-product argument, stub; `bpp.go` (Go only) the Bulletproofs++ proof |
| `succinct/` | `stealth.py`, `ct.py`, `chain.py`, `wallet.py`, `serialize.py` | SAKGen, OTAccGen, View, Receive, PickRing, Spend, Verify, Mine, the chain, wallet helpers, byte format |
| `attacks/` | `attacks/` | All six experiments and Eve |
| `cmd/demo` | `demo.py` | The same 13-step demo, same amounts and options |
| `cmd/bench` | `eval/bench_time.py`, `bench_size.py` | Spend/Verify timing and sizes, rings 128-1024 |
| `cmd/attacks` | `python -m attacks.<name>` | Runs one experiment or `all` |
| `cmd/crosscheck`, `crosscheck.py` | | The Go/Python cross-check |

Curve arithmetic comes from `github.com/decred/dcrd/dcrec/secp256k1/v4` (pure
Go, used by Decred and btcd) or, with `-tags bn256`, from
`github.com/consensys/gnark-crypto` (BN254, used by gnark and many Ethereum
tools); like libsecp256k1 in Python, we never do curve arithmetic ourselves.
Hashing uses Go's standard `crypto/sha3`. `curve/point.go` and
`curve/scalar_secp.go` are the secp256k1 build, `curve/point_bn.go` and
`curve/scalar_bn.go` the BN254 one; nothing outside `curve/` knows which
curve it runs on.

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
go run ./cmd/bench -pippenger -proof bpp            # Bulletproofs++ instead of the Σ-protocol
go run -tags bn256 ./cmd/bench -pippenger -proof bpp # ...on BN254, the paper's setting
go run ./cmd/demo -bpp                # the demo with the Bulletproofs++ proof
go test -tags bn256 ./...             # every test again on BN254
```

The first `go` command downloads the modules. `go.mod` fetches two of
gnark-crypto's dependencies from their GitHub mirrors (`replace` lines),
because the network this was built on blocks golang.org and rsc.io; that
changes where they come from, not what they are.

Cross-checking with Python only works in the default (secp256k1, Σ-protocol)
build: Python has neither BN254 nor the BP++ proof.

## Results

RESULTS_PLACEHOLDER

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

PROVENANCE: written with AI assistance (Claude) as a port of the group's
Python code; checked by the compatibility tests and the cross-check above.
