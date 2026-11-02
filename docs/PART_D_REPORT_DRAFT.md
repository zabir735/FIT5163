# Part D: Evaluation and Results (Group Integration Draft)

**AI-assisted working draft for group review.** The FIT5163 Programming
Specification prohibits submitting AI-generated report sections or critical
analysis as the students' own work. The group must verify the evidence,
rewrite and integrate the analysis in its own words, disclose AI assistance,
and fit the assessed material within its 2–5 page IEEE-style report. This
file is not the final report.

## Method and environment

Felix's final evaluation used Python 3.13.5, coincurve 21.0.0 point
arithmetic, the `sigma_ring` proof backend, and `succinct-v1` serialization
on a MacBook Pro with an Apple M3 Max (14 CPU cores: 10 performance and
4 efficiency) and 36 GB RAM. The source CSVs record Darwin 23.4.0, arm64,
and CPU field `arm`; the exact hardware model and memory were confirmed
separately. The Matplotlib version used for the final plots was not recorded.
Ring sizes were 128, 256, 512, and 1024. Each transaction used two inputs
(60, 40), two outputs (60, 39), fee 1, and seed 5163 for ring selection;
cryptographic randomness remained OS supplied.

The timing benchmark excluded fixture construction and measured the
`ct.spend` and `ct.verify` API calls using `time.perf_counter_ns()` on one
thread. All four rings completed 100 verified pairs, with zero failures or
unattempted repetitions. The size benchmark verified each transaction and
counted the encoded transaction and contained proof bytes; all four rings
completed ten successful encodings with zero failures. The proof is included
in the complete transaction size.

## Final results

**API time (mean ± sample standard deviation, milliseconds; n=100 per ring).**

| Ring size | Spend | Verify |
|----------:|------:|-------:|
| 128 | 48.76 ± 11.80 | 16.33 ± 0.18 |
| 256 | 70.09 ± 11.82 | 27.30 ± 0.38 |
| 512 | 114.26 ± 25.14 | 49.54 ± 1.09 |
| 1024 | 203.14 ± 47.99 | 94.70 ± 3.47 |

**`succinct-v1` encoded size (bytes; n=10 per ring).**

| Ring size | Complete transaction | Contained proof |
|----------:|---------------------:|----------------:|
| 128 | 9,993 | 9,148 |
| 256 | 18,697 | 17,340 |
| 512 | 36,105 | 33,724 |
| 1024 | 70,921 | 66,492 |

From ring 128 to 1024, mean Spend and Verify time increased about 4.17 and
5.80 times, respectively; encoded transaction size increased about 7.10
times. The Spend maxima (165.55, 186.96, 362.54, and 675.01 ms) are much
higher than the corresponding minima and contribute to the means and
standard deviations. Only aggregate timing data were saved, so their
position in the run, including whether they were first repetitions, cannot
be confirmed. Four ring sizes do not establish an asymptotic result.

Suggested figure captions:

- **Mean time:** Mean Spend and Verify API time for the Python
  sigma_ring/coincurve prototype (n=100 verified pairs per ring; ms).
- **Time dispersion:** Mean ± sample standard deviation of the same
  measured API times (n=100 per ring).
- **Encoded size:** Complete transaction and contained proof sizes for
  `succinct-v1` (n=10 verified encodings per ring; bytes).
- **Paper-model comparison:** Analytical SuccinCT bytes from the original
  paper versus measured Python sigma_ring transaction bytes at comparable
  ring and input/output counts; different proof systems and encodings.

The source CSVs are
`eval/results/final_coincurve_20261030T080946Z/bench_time_sigma_ring_n100.csv`
and
`eval/results/final_coincurve_20261030T080946Z/bench_size_sigma_ring_n10.csv`.
The two summary CSVs and four figures are under
`eval/plots/final_coincurve_20261030T080946Z/benchmark_results/`.
Detailed reproduction commands are in `docs/PART_D_EVALUATION.md`.

## Interpretation, provenance, and limitations

The paper's Table 1 and Figures 1/7 are analytical size estimates; Table 3
reports a Go/Bulletproofs++ implementation. Our prototype uses
Python/sigma_ring/coincurve, 33-byte compressed points, and `succinct-v1`
framing. Neither the timing nor byte totals demonstrate equivalent
implementations. The earlier pure-Python M3 Max run (n=10 timing, n=10 size)
and Zabir's Linux coincurve run (n=100 timing, n=3 size) are separate
historical records. They are not pooled with Felix's final run, and
cross-machine or cross-session differences are not a controlled speedup
measurement. The results do not establish cryptographic security, network
performance, or full-chain throughput.

Felix contributed the Part D analytical model, benchmarks, plots, data
review, and documentation, with AI assistance in code and drafts and human
review of the recorded evidence. Serialization and security-test work should
retain the contributor attribution established by the repository history;
this evaluation does not assign either contribution to Felix. The user
reported 511 passing group tests after integration. No tests or benchmarks
were run while updating this draft.
