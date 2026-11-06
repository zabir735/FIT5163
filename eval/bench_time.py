"""Measure actual sigma_ring Spend and Verify calls (cf. SuccinCT Table 3).

Two ordinary inputs of 60 and 40 units pay two outputs of 60 and 39 units
with a fee of 1. Keys, chain, ring, inputs, and outputs are built before timing.
Each repetition uses the prepared data but creates a fresh proof. The chain
is not submitted to, so repeated verification does not mark tags as spent.

Spend includes its required signature, statement, randomness, and proof work.
Verify includes its required chain lookups and statement reconstruction.
Only pairs whose verification returns exactly True enter the statistics.
Standard deviation is the sample standard deviation (n-1); it is blank for
fewer than two successful pairs. These are Python implementation measurements,
not the original paper's Go timings. The seed selects ring positions only;
cryptographic keys and proofs use operating-system randomness.
Progress messages are printed outside the measured API intervals.
"""

from __future__ import annotations

import argparse
import csv
import platform
import random
import statistics
import time
from dataclasses import asdict, dataclass
from pathlib import Path

from succinct import ct
from succinct.chain import Chain
from succinct.nizk import sigma_ring
from succinct.stealth import otaccgen, receive, sakgen


DEFAULT_RING_SIZES = (128, 256, 512, 1024)
DEFAULT_REPETITIONS = 100
BACKEND_NAME = "sigma_ring"
INPUT_AMOUNTS = (60, 40)
OUTPUT_AMOUNTS = (60, 39)
FEE = 1


@dataclass(frozen=True)
class PreparedSpend:
    """Valid data prepared outside the measured Spend/Verify intervals."""

    chain: Chain
    ring: list
    inputs: list
    outputs: list
    info: object
    fee: int


@dataclass(frozen=True)
class TimingStats:
    """Milliseconds calculated from verified pairs only."""

    mean_ms: float | None
    std_ms: float | None
    min_ms: float | None
    max_ms: float | None


@dataclass(frozen=True)
class BenchmarkResult:
    """A configured ring size and its actual completed measurement counts."""

    ring_size: int
    target_repetitions: int
    attempted_repetitions: int
    successful_repetitions: int
    failed_repetitions: int
    unattempted_repetitions: int
    setup_failures: int
    spend_failures: int
    verify_failures: int
    rejected_verifications: int
    proof_backend: str
    python_version: str
    operating_system: str
    os_release: str
    cpu: str
    machine: str
    seed: int
    threads: int
    input_count: int
    output_count: int
    input_amounts: str
    output_amounts: str
    fee: int
    spend_mean_ms: float | None
    spend_std_ms: float | None
    spend_min_ms: float | None
    spend_max_ms: float | None
    verify_mean_ms: float | None
    verify_std_ms: float | None
    verify_min_ms: float | None
    verify_max_ms: float | None
    status: str
    timing_scope: str


def prepare_spend(ring_size: int, seed: int) -> PreparedSpend:
    """Build a valid two-input, two-output fixture using existing interfaces."""
    if ring_size < 2:
        raise ValueError("Ring size must be at least 2 for two real inputs.")
    chain = Chain(nizk=sigma_ring)
    owner_mpk, owner_msk, _ = sakgen(q=2)
    recipient_mpk, _, _ = sakgen(q=1)
    real_refs = []
    for amount in INPUT_AMOUNTS:
        _, acc, info = otaccgen(owner_mpk, amount, 1)
        real_refs.append(chain.add_output(acc, info))
    if ring_size > len(real_refs):
        # Decoys are not opened; fresh one-time outputs can share this public key.
        decoy_mpk, _, _ = sakgen(q=1)
        for _ in range(ring_size - len(real_refs)):
            _, acc, info = otaccgen(decoy_mpk, 100, 1)
            chain.add_output(acc, info)

    ring_refs, positions = ct.pick_ring(chain, real_refs, ring_size,
                                        rng=random.Random(seed))
    inputs = []
    for ref, position in zip(real_refs, positions):
        received = receive(owner_msk, owner_mpk, *chain.get(ref))
        if received is None:
            raise ValueError("Prepared input could not be received.")
        ck, amount, secret_key, tag = received
        inputs.append(ct.SpendInput(position, ck, amount, secret_key, tag))
    outputs, info = ct.make_outputs([
        (recipient_mpk, OUTPUT_AMOUNTS[0]),
        (owner_mpk, OUTPUT_AMOUNTS[1]),
    ])
    ring = [(ref, chain.get(ref)[0]) for ref in ring_refs]
    return PreparedSpend(chain, ring, inputs, outputs, info, FEE)


def summarize_ns(durations_ns: list[int]) -> TimingStats:
    """Convert completed nanosecond durations to millisecond statistics."""
    if not durations_ns:
        return TimingStats(None, None, None, None)
    values = [duration / 1_000_000 for duration in durations_ns]
    return TimingStats(
        mean_ms=statistics.mean(values),
        std_ms=statistics.stdev(values) if len(values) >= 2 else None,
        min_ms=min(values),
        max_ms=max(values),
    )


def system_metadata() -> dict[str, str]:
    """Record available environment details without guessing the CPU model."""
    return {
        "python_version": platform.python_version(),
        "operating_system": platform.system(),
        "os_release": platform.release(),
        "cpu": platform.processor() or platform.uname().processor or "unknown",
        "machine": platform.machine() or "unknown",
    }


def _duration_ms(duration_ns: int | None) -> str:
    """Show an unavailable duration explicitly after an incomplete call."""
    return "N/A" if duration_ns is None else f"{duration_ns / 1_000_000:.3f}"


def _progress(ring_size: int, repetition: int, total: int,
              spend_ns: int | None, verify_ns: int | None,
              status: str, quiet: bool) -> None:
    """Print one completed attempt after both timing boundaries have closed."""
    if not quiet:
        print(f"Ring {ring_size} repetition {repetition}/{total}: "
              f"Spend={_duration_ms(spend_ns)} ms, "
              f"Verify={_duration_ms(verify_ns)} ms, status={status}", flush=True)


def _failure(stage: str, ring_size: int, repetition: int | None,
             error: Exception | str) -> None:
    """Keep failure output concise, including when detailed progress is quiet."""
    detail = str(error).splitlines()[0][:120] if str(error) else "no details"
    prefix = f"Ring {ring_size}" if repetition is None else f"Ring {ring_size} repetition {repetition}"
    print(f"{prefix}: {stage} failed: {detail}", flush=True)


def benchmark_ring(ring_size: int, repetitions: int, seed: int,
                   *, backend=sigma_ring, quiet: bool = False) -> BenchmarkResult:
    """Time each public API call and retain only verified Spend/Verify pairs."""
    if backend is not sigma_ring:
        raise ValueError("Only the sigma_ring proof backend is permitted.")
    if not isinstance(ring_size, int) or isinstance(ring_size, bool) or ring_size < 2:
        raise ValueError("Ring size must be an integer of at least 2.")
    if not isinstance(repetitions, int) or isinstance(repetitions, bool) or repetitions < 1:
        raise ValueError("Repetitions must be a positive integer.")

    print(f"Ring {ring_size}: starting {repetitions} repetitions.", flush=True)
    attempted = setup_failures = spend_failures = verify_failures = rejected = 0
    spend_ns: list[int] = []
    verify_ns: list[int] = []
    try:
        prepared = prepare_spend(ring_size, seed)
    except Exception as error:
        setup_failures = 1
        _failure("Setup", ring_size, None, error)
    else:
        for _ in range(repetitions):
            repetition = attempted + 1
            if not quiet:
                print(f"Ring {ring_size} repetition {repetition}/{repetitions}: starting.",
                      flush=True)
            attempted += 1
            try:
                start = time.perf_counter_ns()
                tx, sig = ct.spend(prepared.ring, prepared.inputs, prepared.outputs,
                                   prepared.info, prepared.fee, nizk=backend)
                spend_elapsed = time.perf_counter_ns() - start
            except Exception as error:
                spend_failures += 1
                _progress(ring_size, repetition, repetitions, None, None,
                          "failed (Spend)", quiet)
                _failure("Spend", ring_size, repetition, error)
                continue
            try:
                start = time.perf_counter_ns()
                accepted = ct.verify(tx, sig, prepared.chain, nizk=backend)
                verify_elapsed = time.perf_counter_ns() - start
            except Exception as error:
                verify_failures += 1
                _progress(ring_size, repetition, repetitions, spend_elapsed, None,
                          "failed (Verify)", quiet)
                _failure("Verify", ring_size, repetition, error)
                continue
            if accepted is not True:
                rejected += 1
                _progress(ring_size, repetition, repetitions, spend_elapsed, verify_elapsed,
                          "failed (Verify rejected)", quiet)
                _failure("Verify", ring_size, repetition,
                         f"verification returned {accepted!r}")
                continue
            spend_ns.append(spend_elapsed)
            verify_ns.append(verify_elapsed)
            _progress(ring_size, repetition, repetitions, spend_elapsed, verify_elapsed,
                      "success", quiet)

    successful = len(spend_ns)
    failed = attempted - successful
    spend_stats, verify_stats = summarize_ns(spend_ns), summarize_ns(verify_ns)
    status = "setup_failed" if setup_failures else (
        "complete" if successful == repetitions else "partial"
    )
    return BenchmarkResult(
        ring_size=ring_size,
        target_repetitions=repetitions,
        attempted_repetitions=attempted,
        successful_repetitions=successful,
        failed_repetitions=failed,
        unattempted_repetitions=repetitions - attempted,
        setup_failures=setup_failures,
        spend_failures=spend_failures,
        verify_failures=verify_failures,
        rejected_verifications=rejected,
        proof_backend=BACKEND_NAME,
        **system_metadata(),
        seed=seed,
        threads=1,
        input_count=len(INPUT_AMOUNTS),
        output_count=len(OUTPUT_AMOUNTS),
        input_amounts=";".join(map(str, INPUT_AMOUNTS)),
        output_amounts=";".join(map(str, OUTPUT_AMOUNTS)),
        fee=FEE,
        spend_mean_ms=spend_stats.mean_ms,
        spend_std_ms=spend_stats.std_ms,
        spend_min_ms=spend_stats.min_ms,
        spend_max_ms=spend_stats.max_ms,
        verify_mean_ms=verify_stats.mean_ms,
        verify_std_ms=verify_stats.std_ms,
        verify_min_ms=verify_stats.min_ms,
        verify_max_ms=verify_stats.max_ms,
        status=status,
        timing_scope="ct.spend and ct.verify API calls only; verified pairs only",
    )


def write_csv(path: Path, rows: list[BenchmarkResult]) -> None:
    """Export one row per configured ring size; missing statistics stay blank."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(BenchmarkResult.__dataclass_fields__))
        writer.writeheader()
        writer.writerows(asdict(row) for row in rows)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--seed", type=int, default=5163,
                        help="Seed for ring selection only; cryptographic randomness remains unseeded.")
    parser.add_argument("--ring-sizes", type=int, nargs="+", default=None,
                        help="Ring sizes to measure (default: 128 256 512 1024).")
    parser.add_argument("--repetitions", type=int, default=None,
                        help="Target Spend/Verify pairs per ring size (default: 100).")
    parser.add_argument("--smoke", action="store_true",
                        help="Measure one pair at ring size 4; cannot be combined with size/repetition options.")
    parser.add_argument("--quiet", action="store_true",
                        help="Hide per-repetition progress; retain failures and ring summaries.")
    parser.add_argument("--output", type=Path,
                        default=Path("eval/plots/bench_time_sigma_ring.csv"),
                        help="CSV output path (default: eval/plots/bench_time_sigma_ring.csv).")
    args = parser.parse_args(argv)
    if args.smoke and (args.ring_sizes is not None or args.repetitions is not None):
        parser.error("--smoke cannot be combined with --ring-sizes or --repetitions.")
    ring_sizes = [4] if args.smoke else (args.ring_sizes or list(DEFAULT_RING_SIZES))
    repetitions = 1 if args.smoke else (
        DEFAULT_REPETITIONS if args.repetitions is None else args.repetitions
    )
    if any(size < 2 for size in ring_sizes):
        parser.error("Every ring size must be at least 2.")
    if repetitions < 1:
        parser.error("--repetitions must be a positive integer.")
    if len(set(ring_sizes)) != len(ring_sizes):
        parser.error("Ring sizes must be distinct.")

    print("Actual Python ct.spend/ct.verify timing with explicit sigma_ring proof.", flush=True)
    print("The seed controls ring selection only; cryptographic keys use OS randomness.",
          flush=True)
    rows = []
    for ring_size in ring_sizes:
        options = {"backend": sigma_ring}
        if args.quiet:
            options["quiet"] = True
        row = benchmark_ring(ring_size, repetitions, args.seed, **options)
        rows.append(row)
        print(f"Ring {ring_size} complete: target={row.target_repetitions}, "
              f"attempted={row.attempted_repetitions}, "
              f"successful={row.successful_repetitions}, failed={row.failed_repetitions}, "
              f"unattempted={row.unattempted_repetitions}; "
              f"Spend mean={row.spend_mean_ms} ms, Verify mean={row.verify_mean_ms} ms",
              flush=True)
    write_csv(args.output, rows)
    print(f"Wrote {args.output}.", flush=True)
    if any(row.status != "complete" for row in rows):
        raise SystemExit("Benchmark incomplete; inspect the CSV failure counts.")


if __name__ == "__main__":
    main()
