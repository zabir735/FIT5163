# Part D Evaluation and Reproducibility

## Final experiment and measurement method

The final Part D evaluation uses the coincurve 21.0.0 elliptic-curve backend
and the explicit `sigma_ring` proof backend. `eval/bench_time.py` prepares a
valid two-input, two-output fixture outside the timed intervals, then times
the `ct.spend` and `ct.verify` API calls with `time.perf_counter_ns()`. Only
verified pairs enter the timing statistics; the CSV reports sample standard
deviations. `eval/bench_size.py` verifies each transaction before measuring
`len(encode_transaction(tx, sig))` and `len(encode_proof(sig.proof))`. These
are `succinct-v1` encoded lengths, not Python object sizes. The proof is
already contained in the complete transaction and must not be added to it.

| Parameter | Final recorded value |
|-----------|----------------------|
| Ring sizes | 128, 256, 512, 1024 |
| Timing | 100 target, attempted, and successful repetitions per ring; zero failures and zero unattempted |
| Encoded sizes | 10 target, attempted, successful transaction and proof measurements per ring; zero failures and zero unattempted |
| Fixture | Two inputs of 60 and 40; two outputs of 60 and 39; fee 1 |
| Backend / encoding | `sigma_ring` / `succinct-v1 (33-byte points, 32-byte scalars, u16 counts)` |
| Seed / timing threads | 5163 for ring selection / 1 thread |
| Timing scope | `ct.spend` and `ct.verify` API calls only; fixture setup excluded |
| CSV environment | Python 3.13.5; Darwin 23.4.0; arm64; CPU field `arm` |
| Separately confirmed hardware | MacBook Pro, Apple M3 Max, 14 CPU cores (10 performance, 4 efficiency), 36 GB memory |

The final CSVs do not record the exact CPU model, memory, Matplotlib version,
or individual timing observations. The hardware details above were confirmed
separately by the experimenter. `requirements.txt` pins coincurve 21.0.0 and
Matplotlib 3.11.2; the Matplotlib version used to generate the final PNGs was
not recorded in the final CSVs. The seed does not fix operating-system
cryptographic randomness.

## Verified final results

Source CSVs:

- `eval/results/final_coincurve_20261030T080946Z/bench_time_sigma_ring_n100.csv`
- `eval/results/final_coincurve_20261030T080946Z/bench_size_sigma_ring_n10.csv`

The four timing source rows have `status=complete`, 100/100 successful
attempts, and zero setup, Spend, Verify, or rejected-verification failures.
The corresponding summary CSV reproduces every recorded mean and sample
standard deviation. Individual timing samples were not retained, so these
statistics cannot be independently recalculated from the source CSV. Values
below are mean ± sample standard deviation in
milliseconds, rounded to two decimals for display; the CSVs retain the full
precision.

| Ring size | Spend (ms), n=100 | Verify (ms), n=100 | Spend maximum (ms) |
|----------:|------------------:|-------------------:|-------------------:|
| 128 | 48.76 ± 11.80 | 16.33 ± 0.18 | 165.55 |
| 256 | 70.09 ± 11.82 | 27.30 ± 0.38 | 186.96 |
| 512 | 114.26 ± 25.14 | 49.54 ± 1.09 | 362.54 |
| 1024 | 203.14 ± 47.99 | 94.70 ± 3.47 | 675.01 |

The four size source rows have `measurement_status=complete` and
`proof_size_status=complete`, 10/10 successful transaction and proof
measurements, and zero failed or unattempted attempts. Every one of the ten
observations at a given ring size has the same byte count; the size summary
CSV matches the source means, counts, backend, and serialization format.

| Ring size | Complete transaction (bytes), n=10 | Contained proof (bytes), n=10 |
|----------:|-----------------------------------:|------------------------------:|
| 128 | 9,993 | 9,148 |
| 256 | 18,697 | 17,340 |
| 512 | 36,105 | 33,724 |
| 1024 | 70,921 | 66,492 |

Spend and Verify means rise across the four ring sizes: from ring 128 to
1024, Spend rises about 4.17 times and Verify about 5.80 times. Complete
transaction bytes rise about 7.10 times. These four points describe the
sampled prototype, not an asymptotic proof. The high Spend maxima, especially
675.01 ms at ring 1024, contribute to the reported means and sample standard
deviations. The timing CSV contains aggregates only, so it cannot establish
whether those maxima occurred on the first repetition or quantify a warm-up
effect. No samples were removed or adjusted.

## Figure and data inventory

The final figure directory is
`eval/plots/final_coincurve_20261030T080946Z/benchmark_results/`:

| File | Report caption / content |
|------|--------------------------|
| `python_sigma_ring_timing_summary.csv` | Final n=100 timing summary; matches the source means and sample standard deviations |
| `python_sigma_ring_size_summary.csv` | Final n=10 encoded-size summary; matches source byte means and metadata |
| `python_sigma_ring_mean_times.png` | Mean Spend and Verify API time (ms) by ring size; Python/sigma_ring/coincurve, n=100 per ring |
| `python_sigma_ring_mean_sample_std.png` | Mean ± sample standard deviation of Spend and Verify API time (ms); same final run |
| `python_sigma_ring_transaction_and_proof_bytes.png` | Complete transaction and contained proof bytes; `succinct-v1`, n=10 per ring |
| `paper_succinctct_model_vs_python_sigma_ring_bytes.png` | Paper analytical SuccinCT estimate versus measured Python/sigma_ring encoded bytes; distinct proof systems and encodings |

`eval/size_model.py` separately applies the paper's Table 1 analytical
formulas to six protocols. Its Figure 1 configuration is ring size 256 with
two inputs and two outputs; its Figure 7 output uses a documented ring-size
grid, since the exact plotted sampling grid is not specified in the paper.
The Table 1 ZGSX23 output size is absent; the model labels its Section 1.2
output conjecture as an assumption. Paper model bytes are not measurements of
this repository's transactions.

## Distinct historical sources

Do not combine these experiments into one statistical sample:

| Source | Platform and implementation | Timing | Encoded size |
|--------|-----------------------------|--------|--------------|
| Felix's earlier run | M3 Max, Python 3.13.5, pure-Python curve, `sigma_ring` | `eval/results/bench_time_sigma_ring_n10.csv`, n=10 per ring | `eval/results/bench_size_sigma_ring_n10.csv`, n=10 per ring |
| Zabir's team run | Linux x86_64, Python 3.13.17, coincurve, `sigma_ring`; team-reported cloud Intel Xeon environment | `eval/results/bench_time_sigma_ring.csv`, n=100 per ring | `eval/results/bench_size_sigma_ring.csv`, n=3 per ring |
| Felix's final run | M3 Max, Python 3.13.5, coincurve, `sigma_ring` | Final timestamped timing CSV above, n=100 per ring | Final timestamped size CSV above, n=10 per ring |
| Original paper | Go/Bulletproofs++ analytical and experimental results | Paper Table 3, separate environment | Paper Table 1 and Figures 1/7 analytical estimates |

Cross-machine and cross-session timing differences are not a controlled
coincurve speedup experiment. The paper uses Go and Bulletproofs++; this
prototype uses Python, a sigma-ring relation proof with a range proof, and
coincurve point arithmetic. Paper byte estimates use different proof and
encoding assumptions. These measurements do not establish cryptographic
soundness, privacy, blockchain throughput, or equivalent performance to the
paper implementation.

## Reproduction and validation

From the repository root, use an environment satisfying `requirements.txt`.
Select fresh output paths to preserve the recorded experiment. These
commands are instructions and were not run while updating this document.

```bash
python -m pip install -r requirements.txt
python -m pytest tests/test_size_model.py tests/test_bench_time.py tests/test_bench_size.py tests/test_plot_results.py tests/test_run_all.py -q
RUN_TAG="$(date -u +%Y%m%dT%H%M%SZ)-$$"
python -m eval.size_model --seed 5163 --output-dir "eval/plots/paper_model_${RUN_TAG}"
python -m eval.bench_time --seed 5163 --ring-sizes 128 256 512 1024 --repetitions 100 --output "eval/results/bench_time_final_reproduction_${RUN_TAG}.csv"
python -m eval.bench_size --seed 5163 --ring-sizes 128 256 512 1024 --repetitions 10 --output "eval/results/bench_size_final_reproduction_${RUN_TAG}.csv"
python -m eval.plot_results --input eval/results/final_coincurve_20261030T080946Z/bench_time_sigma_ring_n100.csv --size-input eval/results/final_coincurve_20261030T080946Z/bench_size_sigma_ring_n10.csv --output-dir "eval/plots/final_reproduction_${RUN_TAG}"
```

The timing and size benchmarks can be slow; `./run_all.sh` excludes them by
default and `--benchmarks` opts in to 100 timing and 10 size repetitions per
ring with timestamped outputs. The user reported 511 passing group tests
after the coincurve integration. This documentation update did not rerun
tests, scripts, plots, or benchmarks. `eval/results/` is ignored by Git, so
the two final source CSVs require explicit inclusion when staging; the final
summary CSVs and PNGs should be included without the temporary validation
directories.
