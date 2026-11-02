# SuccinCT in Python — FIT5163 Programming Assignment

Implementation of *SuccinCT: Succinct Confidential Transaction for Miner Privacy* (Chen et al.):
stealth one-time accounts with polynomial keys/tags, a ring multi-signature over Eq. 5, a toy
blockchain, and simulations of the paper's two miner attacks and their mitigations.

**Substitution:** the paper's Bulletproofs++ NIZK is replaced by a linear-size Σ-protocol for the
Eq. 5 relation plus an aggregated Bulletproofs (2018) range proof. Appendix C.3 of the paper states
the scheme works with any NIZK for the inner-product relation.

**Group:** secp256k1 (prime order). Point arithmetic is done by libsecp256k1 (Bitcoin Core's audited,
constant-time library) through `coincurve`; `succinct/group.py` wraps it and handles the identity point,
which libsecp256k1 can't represent. Ristretto255 was dropped because PyNaCl doesn't expose it. Code uses additive notation: the paper's `G^x · Y` is `x*G + Y`.
Scalars are plain `int`s mod `ORDER`.

## Layout

```
succinct/          core library
  group.py         secp256k1 Point (wraps libsecp256k1 via coincurve), multiexp, hash_to_scalar/point, generators U, V, W, G'
  transcript.py    the paper's H, H_a, H_b, H_c, H_n plus a Fiat–Shamir Transcript
  pedersen.py      Com(a; ck) = a*V + ck*W and vector Pedersen
  tagging.py       TagKGen / TagEval
  keyagreement.py  hashed Diffie–Hellman
  stealth.py       SAKGen, OTAccGen, View, Receive, miner keys (q = 0)
  nizk/
    relation.py    Eq. 5 Statement/Witness and relation_holds (contract between Spend and the proof)
    stub.py        placeholder proof (witness in the clear, NOT private)
    sigma_ring.py  Σ-protocol for Eq. 5, O(S*n) size, includes the range proof
    rangeproof.py  aggregated Bulletproofs range proof on the outputs
    ipa.py         Bulletproofs inner-product argument (used by rangeproof)
    util.py        scalar-vector helpers and input checks
  ct.py            Spend, Verify, Mine (paper §6.2)
  wallet.py        self-transfer and multi-self-transfer (§3.1 wallet policies, not consensus rules)
  chain.py         minimal toy blockchain: genesis outputs, submit (runs Verify), mine_block
  serialize.py     byte encodings and measured sizes
attacks/           miner-privacy, anonymity-reduction, related-key tag, q-bound experiments
eval/              timing/size benchmarks, Table 1 size model, comparison with the paper, plots/
tests/             unit, property-based and tamper tests
demo.py            scripted end-to-end scenario for the live demo
docs/              team notes (PART_A_NOTES.md: interfaces, decisions, paper issues found)
```

Any proof system plugs in through `prove(stmt, wit)` / `verify(stmt, proof)`, passed as
`nizk=` to `ct.spend`, `ct.verify` or `Chain(nizk=...)`. The default is the real proof,
`nizk.sigma_ring`. Pass `nizk=stub` explicitly for the fast placeholder, which checks the
scheme's algebra but reveals the witness, so never benchmark or demo privacy with it.
`tests/test_ct.py` runs its whole suite with both.

## Setup

Python 3.11-3.13 is required by `pyproject.toml`. `requirements.txt` pins
`coincurve==21.0.0` for libsecp256k1 curve operations, plus pytest,
Hypothesis, and Matplotlib. Pandas is not required. The historical Part D
plots used Matplotlib 3.10.0; the current requirements pin 3.11.2.

```bash
python -m venv .venv
. .venv/bin/activate        # Windows: .venv\Scripts\activate
python -m pip install -r requirements.txt
python -m pytest
python -m pytest tests/test_size_model.py tests/test_bench_time.py tests/test_bench_size.py tests/test_plot_results.py tests/test_run_all.py -q
python -m pytest tests/test_security.py tests/test_backend.py tests/test_wallet.py -q
```

The installation commands are instructions; recorded benchmark data came from
the environments described below. Matplotlib is needed only for plots, not
the CSV-only analytical model or benchmark CSV generation. Historical local
validation passed `bash -n run_all.sh` and 149 Part D tests. On the
current master all 529 group tests pass (Python 3.13.5, Windows 11, about
20 s), and `run_all.bat quick` completes every step.

The demo includes the coincurve-backed wallet's self-transfer and
multi-self-transfer policies. Run `python demo.py` for the real proof or
`python demo.py --stub` for a fast functional walkthrough; the stub exposes
the witness and does not demonstrate privacy. `python demo.py --present`
enables the interactive presentation controls.

## Evaluation and reproducibility (Part D)

The paper analytical model in `eval/size_model.py` applies Table 1 to the six
compared protocols. It exports Figure 1 at ring size 256 with two inputs and
two outputs, and Figure 7 on the documented ring-size grid. Its CSV values are
**paper estimates**, not serialized Python transaction bytes. The Figure 7
sampling grid is not specified exactly in the paper; the default uses 128,
256, 512, and 1024. ZGSX23's Table 1 output size is unknown, and its plotted
total uses the paper's Section 1.2 output conjecture.

`eval/bench_time.py` builds two-input, two-output transactions and times the
`ct.spend` and `ct.verify` API calls with `time.perf_counter_ns()`. Fixture
construction is outside the timed intervals. `eval/bench_size.py` verifies
transactions, then counts `len(encode_transaction(tx, sig))` and separately
`len(encode_proof(sig.proof))` using the project's `succinct-v1` serializer.
The proof bytes are **already included** in complete transaction bytes. Both
benchmarks pass `nizk=sigma_ring` explicitly. The `stub` backend exposes the
witness and is unsuitable for privacy-proof benchmarks.

From the repository root, run the Part D tests or regenerate figures from
the final M3 Max coincurve CSVs in a new output directory:

```bash
python -m pytest tests/test_size_model.py tests/test_bench_time.py tests/test_bench_size.py tests/test_plot_results.py tests/test_run_all.py -q
RUN_TAG="$(date -u +%Y%m%dT%H%M%SZ)-$$"
python -m eval.size_model --csv-only --output-dir "eval/plots/paper_model_${RUN_TAG}"
python -m eval.plot_results --input eval/results/final_coincurve_20261030T080946Z/bench_time_sigma_ring_n100.csv --size-input eval/results/final_coincurve_20261030T080946Z/bench_size_sigma_ring_n10.csv --output-dir "eval/plots/final_reproduction_${RUN_TAG}"
```

The benchmark `--smoke` option means one attempt at ring size 4; it cannot be
combined with explicit ring sizes or repetition counts. Each standalone
benchmark defaults to four ring sizes and 100 target repetitions, so specify
repetitions for a particular experiment. The seed selects ring positions;
keys and proofs still use operating-system randomness. The deterministic
analytical model accepts `--seed` for wrapper compatibility but ignores it.

The model command writes `figure1_paper_size_model.csv` and
`figure7_paper_size_model.csv`, plus matching `.png` files unless `--csv-only`
is set. The benchmarks each write one CSV row per ring size, including target,
attempted, successful, failed, and unattempted counts, backend, environment,
parameters, status, and timing or byte-size statistics. The plotter writes
timing and size summary CSVs, two timing PNGs, a measured transaction/proof
PNG, and a separate paper-model-versus-prototype PNG. See
[`docs/PART_D_EVALUATION.md`](docs/PART_D_EVALUATION.md) for methods and
[`docs/PART_D_REPORT_DRAFT.md`](docs/PART_D_REPORT_DRAFT.md) for an
AI-assisted group review draft. Both documents now center Felix's final
M3 Max coincurve evaluation and retain the older runs as separate records.

On macOS/Linux, `./run_all.sh [--seed N]` runs the full group tests, paper
model, and all six attack scenarios, **without** expensive timing or size
benchmarks. `./run_all.sh --quick` runs a small test selection and shorter
attack scenarios. Use `./run_all.sh --benchmarks --seed 5163` to opt into
four-ring benchmarks and plots: 10 transaction-size measurements and 100
timing measurements per ring. Combining `--quick --benchmarks` uses rings 8
and 16 with 10 repetitions of each benchmark. The
script selects `.venv/bin/python` when executable and enables UTF-8 output.
Each run uses new timestamped directories under `eval/results/` and
`eval/plots/`; attack tables are also saved as text files in the run's
`attacks/` directory. Formal benchmark runs also generate the side-by-side
paper comparison from that run's CSVs. Attack scenarios use their own default
proof settings; they are not the `sigma_ring` performance experiment.

On Windows, the separately maintained `run_all.bat` accepts `quick` and
`seed N` positional arguments and selects `.venv\Scripts\python.exe` when
available. It runs the same tests, paper model and six attack scenarios,
and always includes the benchmarks: rings 128-1024 with 100 timing and 10
size repetitions (quick: rings 8 and 16, 10 of each), then the benchmark
plots in `eval\plots\benchmarks` and, in full mode, the paper comparison.
It writes to fixed locations under `eval\results` and `eval\plots` (quick
mode: their `quick\` subfolders), not timestamped run directories, so a
full run overwrites `eval\results\bench_*_sigma_ring.csv`.

The primary final sources are
`eval/results/final_coincurve_20261030T080946Z/bench_time_sigma_ring_n100.csv`
(100 successful repetitions per ring) and
`eval/results/final_coincurve_20261030T080946Z/bench_size_sigma_ring_n10.csv`
(10 successful repetitions per ring). Their two summary CSVs and four figures
are under
`eval/plots/final_coincurve_20261030T080946Z/benchmark_results/`.
Felix's earlier pure-Python M3 Max sources are
`eval/results/bench_time_sigma_ring_n10.csv` and
`eval/results/bench_size_sigma_ring_n10.csv` (10 per ring each). Zabir's
Linux coincurve sources are `eval/results/bench_time_sigma_ring.csv`
(100 per ring) and `eval/results/bench_size_sigma_ring.csv` (3 per ring).
All use rings 128, 256, 512, and 1024, the `sigma_ring` proof backend,
and two inputs and two outputs. The size CSVs use `succinct-v1`
serialization. The original paper used Go and Bulletproofs++; its results
are separate analytical and experimental evidence. The final source CSVs
are currently ignored by Git and require deliberate staging.

## Attacks and mitigations (Part C)

Six experiments on a local toy chain. Each takes `--seed` (default 5163); keys use OS
randomness, so exact percentages vary a little between runs.

| Script | Paper | What it shows |
|--------|-------|---------------|
| `attacks/miner_privacy.py` | §3.1 | Eve holds the recipient's view key and matches `output + fee` to a coinbase amount in the ring. Compares no mitigation, self-transfer, self-transfer + at-most-(S-1)-miners ring rule, and a careless self-transfer. |
| `attacks/anonymity_reduction.py` | §3.2 | A coinbase decoy smaller than `output + fee` cannot be the sole spender, so it shrinks the anonymity set. With the S-1 rule the set stays full and `Verify` rejects coinbase-stuffed rings (returns `None`, the paper's ⊥). |
| `attacks/related_key_tag.py` | §5 | A sender who knows the shared secrets links tags of the naive `sk = H(s) + lsk` form. The polynomial tag `U^f(s)` resists the same checks. |
| `attacks/q_bound_linkability.py` | §5 | Interpolating `U^f(s)` through `q+1` tags predicts the next tag; with `q` or fewer it fails. This is why a long-term key has a use limit of `q`. |
| `attacks/chain_scenario.py` | §3.1, §3.2 | End to end on the real `Chain` (`mine_block`, `submit`): a coinbase spent alone is refused by the wallet and rejected by the chain (⊥); a coinbase plus an ordinary coin with a real self-transfer is accepted and Eve falls to chance; a careless self-transfer is also accepted and Eve still wins. Ordinary rings contain no coinbase decoys. |
| `attacks/multi_self_transfer.py` | §3.1 | Uses `succinct.wallet`: three coinbases plus one ordinary coin are consolidated into two own accounts (the P2Pool-style mitigation). The wallet refuses a zero-change self-transfer, every output is non-zero, and Eve stays near blind-guess rates both on the consolidation and on the later payment to Bob. |

```bash
python -m attacks.miner_privacy --trials 30 --ring-sizes 8 16 32
python -m attacks.miner_privacy --trials 30 --ring-sizes 128 256 512 1024
python -m attacks.anonymity_reduction --trials 30 --ring-sizes 8 16 32
python -m attacks.related_key_tag --trials 20
python -m attacks.q_bound_linkability --q 1 2 3 5 --trials 10
python -m attacks.chain_scenario --trials 200 --ring-sizes 8 16 32 64
python -m attacks.multi_self_transfer --trials 300 --ring-sizes 8 16 32
python -m attacks.miner_privacy --trials 5 --ring-sizes 8 --proof real   # sigma_ring instead of the stub
python -m attacks.chain_scenario --trials 2 --ring-sizes 8 --proof real   # same, with sigma_ring
python -m pytest tests/test_attacks.py                                   # fast checks of all of them
```

How to read the output
- **Eve success** is how often she names a real input. **chance** is a blind guess (real inputs / ring size). A mitigation works when success falls to about the chance column.
- **certain** counts exact `output + fee = coinbase` matches.
- Rows marked "legacy" in `miner_privacy.py` are observable-only transactions: `Spend` and `Verify` correctly refuse to build them, and Eve never uses the signature. `chain_scenario.py` shows the same refusal on the real chain.

Limits
- Eve is the paper's passive observer using only the §3 arithmetic. Ring-membership statistics and timing are out of scope.
- A failed linking test is not a security proof; the proof is the DDH argument in the paper.
- `chain.py` is minimal: no coinbase maturity, no block structure beyond `mine_block`, uniform decoy choice (Monero uses an age-based gamma distribution, Appendix F). The attacks do not depend on these.
- Small trial counts are noisy (20 trials can read 15% to 40% against a 25% baseline). Use 200 or more for any number you quote.
- Attacks 3 and 4 bypass `Receive`'s use counter on purpose to show what the limit protects against.

## Environment

These three measured data sets are separate experiments. All used
`sigma_ring`, seed 5163, two inputs, two outputs, and rings 128, 256, 512,
and 1024.

| Item | Felix final coincurve (primary) | Felix historical pure-Python curve | Zabir Linux coincurve (team run) |
|------|---------------------------------|------------------------------------|----------------------------------|
| Timing successes per ring | 100 | 10 | 100 |
| Size successes per ring | 10 | 10 | 3 |
| Device / CPU | MacBook Pro, Apple M3 Max; 14 cores (10 performance, 4 efficiency), separately confirmed | Same M3 Max environment, separately confirmed | Cloud container; Intel Xeon @ 2.80 GHz, 2 vCPUs, as reported by the team |
| Memory | 36 GB, separately confirmed | 36 GB, separately confirmed | Not recorded in the CSVs |
| Python | 3.13.5 | 3.13.5 | 3.13.17 |
| OS / architecture | Darwin 23.4.0, arm64 | Darwin 23.4.0, arm64 | Linux 6.18.44-fc-v180, x86_64; team reports Ubuntu 24.04.5 LTS |
| Proof / serialization | `sigma_ring` / `succinct-v1` | `sigma_ring` / `succinct-v1` | `sigma_ring` / `succinct-v1` |
| Plotting library | Final version not recorded in the CSVs | Matplotlib 3.10.0, separately confirmed | Matplotlib 3.11.2, reported by the team |

The final CSVs record CPU as `arm`, not the exact model. Their metadata
do not include memory or Matplotlib. `requirements.txt` now pins
Matplotlib 3.11.2; this does not establish the version used for the final
plots. Cross-machine and cross-session timing differences are not a
controlled coincurve speedup measurement.

## Results

Felix's final M3 Max coincurve results are the primary evaluation. The final
source CSVs have four complete rows each: 100 timing and 10 size successes
per ring, with zero failed or unattempted attempts. Spend and Verify are
mean ± sample standard deviation in milliseconds; size is measured encoded
bytes. The proof is contained in the complete transaction.

| Ring | Spend (ms), n=100 | Verify (ms), n=100 | Complete tx (B), n=10 | Contained proof (B), n=10 |
|-----:|------------------:|-------------------:|----------------------:|--------------------------:|
| 128 | 48.76 ± 11.80 | 16.33 ± 0.18 | 9,993 | 9,148 |
| 256 | 70.09 ± 11.82 | 27.30 ± 0.38 | 18,697 | 17,340 |
| 512 | 114.26 ± 25.14 | 49.54 ± 1.09 | 36,105 | 33,724 |
| 1024 | 203.14 ± 47.99 | 94.70 ± 3.47 | 70,921 | 66,492 |

Mean Spend rises about 4.17 times, Verify about 5.80 times, and complete
transaction bytes about 7.10 times from ring 128 to 1024. Large Spend
maxima increase the recorded means and sample standard deviations; the
aggregate CSV cannot show whether they occurred on first repetitions.
The paper's Table 1/Figures 1 and 7 are analytical byte estimates, and its
Table 3 measures a Go/Bulletproofs++ implementation. Our Python
sigma_ring/coincurve timing and `succinct-v1` bytes do not measure an
equivalent implementation. Do not pool these results with Felix's earlier
pure-Python run or Zabir's Linux coincurve run. The team's separate Linux
comparison remains in `eval/results/comparison.md`; its numbers are not the
final M3 Max results. Final figures and summary CSVs are under
`eval/plots/final_coincurve_20261030T080946Z/benchmark_results/`.
The recorded attack tables remain under `eval/results/<attack>.txt`.

**Attacks** (200 trials unless noted; "chance" = real inputs / ring size):

| Experiment | Without the fix | With the fix |
|---|---|---|
| Miner privacy (§3.1), ring 16 | Eve names the miner 100% (exact match) | 11.0%, chance 12.5% (self-transfer + S-1) |
| Same, careless self-transfer | 100%: accepted by the chain, still linked | - |
| Anonymity reduction (§3.2), ring 16 | anonymity set 15.23 of 16 | 16.00 of 16; coinbase-stuffed rings rejected 100% |
| Related-key tags (§5), 20 trials | naive Monero-style keys linked 100% | polynomial tags linked 0% |
| q-bound (§5), 10 trials | next tag predicted once q+1 tags are seen | wallet refuses use q+1 in 100% of trials |
| End to end on the chain, ring 16 | coinbase spent alone: refused 100% | Eve 11.5%, chance 12.5% |
| Multi-self-transfer (§3.1), ring 16 | zero-change self-transfer: wallet refuses 100% | consolidation: Eve 28.5%, chance 25.0%; later payment to Bob: 5.0%, chance 6.2% |

Attack runs use the stub proof by default: Eve reads the public transaction;
these attack tables are not proof-system performance or security measurements.
Use `--proof real` where supported to exercise the Σ-protocol.

## Provenance

| Component | Source |
|-----------|--------|
| Crypto core, Spend/Verify/Mine, wallet helpers, demo (Part A) | own code, AI-assisted (Claude) |
| Curve arithmetic | libsecp256k1 via `coincurve` 21.0.0 (MIT); cross-checked against an independent textbook implementation in `tests/reference_curve.py` |
| NIZK: Σ-protocol, range proof, IPA (Part B) | own code, AI-assisted; follows Bünz et al. 2018 (Bulletproofs) and Groth–Kohlweiss 2015 (bit-commitment trick) |
| Attack simulations, end-to-end chain scenario, multi-self-transfer scenario, shared toy world, attack tests (Part C) | own design; first drafts of the scripts AI-assisted (Claude), reviewed, run and tested by the author; follows the paper's §3 and §5 |
| Transaction and proof serialization | Ryan (`47e3f7b`), with `succinct-v1` encoding used by the size benchmarks |
| Security-gap tests | Ryan (`b26a86b`); their presence does not establish cryptographic security |
| Analytical model, timing and size benchmarks, historical and final M3 Max results, plots, and Part D documentation | Felix (Part D); AI-assisted code and documentation drafts, reviewed against recorded CSVs by Felix. Paper formulas are attributed to SuccinCT. The group must review and rewrite the AI-assisted report draft before submission. |

All experiments run on the local toy chain only.
