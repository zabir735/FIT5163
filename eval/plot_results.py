"""Plot existing Python sigma_ring timing and transaction-size measurements.

The input contains aggregate statistics, not individual timings. The error
bands use the sample standard deviations already recorded by bench_time.py.
These measurements are not timings of the original paper's Go implementation.
Size comparison uses the paper's analytical SuccinCT model only at matching
ring and input/output counts. Its Bulletproofs++ proof and 32-byte elements
differ from the measured sigma_ring proof and succinct-v1 encoding.
"""

from __future__ import annotations

import argparse
import csv
import math
from dataclasses import asdict, dataclass
from pathlib import Path

from . import size_model


DEFAULT_INPUT = Path("eval/results/bench_time_sigma_ring_n10.csv")
DEFAULT_SIZE_INPUT = Path("eval/results/bench_size_sigma_ring_n10.csv")
DEFAULT_OUTPUT_DIR = Path("eval/plots/benchmark_results")
SUMMARY_NAME = "python_sigma_ring_timing_summary.csv"
MEANS_NAME = "python_sigma_ring_mean_times.png"
MEAN_STD_NAME = "python_sigma_ring_mean_sample_std.png"
MEASUREMENT_LABEL = "Measured Python sigma_ring implementation; not original paper Go timings"
SIZE_SUMMARY_NAME = "python_sigma_ring_size_summary.csv"
SIZE_PLOT_NAME = "python_sigma_ring_transaction_and_proof_bytes.png"
SIZE_COMPARISON_NAME = "paper_succinctct_model_vs_python_sigma_ring_bytes.png"
SIZE_MEASUREMENT_LABEL = "Measured Python sigma_ring, succinct-v1 serialized bytes"
PAPER_SIZE_LABEL = "Paper SuccinCT analytical estimate (Bulletproofs++; 32-byte elements)"
EXPECTED_INPUT_AMOUNTS = "60;40"
EXPECTED_OUTPUT_AMOUNTS = "60;39"
EXPECTED_FEE = 1
SIZE_REQUIRED_COLUMNS = frozenset({
    "ring_size", "target_repetitions", "attempted_repetitions",
    "successful_repetitions", "failed_repetitions", "unattempted_repetitions",
    "setup_failures", "spend_failures", "verify_failures",
    "rejected_verifications", "serialization_failures",
    "proof_serialization_failures", "proof_backend", "serialization_format",
    "input_count", "output_count", "input_amounts", "output_amounts", "fee",
    "transaction_bytes_observations",
    "transaction_bytes_mean", "transaction_bytes_min", "transaction_bytes_max",
    "proof_bytes_observations", "proof_successful_repetitions",
    "proof_bytes_mean", "proof_bytes_min", "proof_bytes_max",
    "proof_size_status", "measurement_status", "blocker",
})

REQUIRED_COLUMNS = frozenset({
    "ring_size", "target_repetitions", "attempted_repetitions",
    "successful_repetitions", "failed_repetitions", "unattempted_repetitions",
    "setup_failures", "spend_failures", "verify_failures", "rejected_verifications",
    "input_count", "output_count", "input_amounts", "output_amounts", "fee",
    "proof_backend", "spend_mean_ms", "spend_std_ms", "verify_mean_ms",
    "verify_std_ms", "status",
})


@dataclass(frozen=True)
class TimingRow:
    """A complete benchmark row; standard deviations are sample statistics."""

    ring_size: int
    successful_repetitions: int
    spend_mean_ms: float
    spend_sample_std_ms: float
    verify_mean_ms: float
    verify_sample_std_ms: float
    proof_backend: str
    measurement_source: str


@dataclass(frozen=True)
class SizeRow:
    """Measured complete transaction and contained proof sizes, in bytes."""

    ring_size: int
    successful_repetitions: int
    input_count: int
    output_count: int
    transaction_bytes_mean: float
    proof_bytes_mean: float
    proof_backend: str
    serialization_format: str
    measurement_source: str


def _integer(record: dict[str, str], name: str, line: int) -> int:
    """Parse a nonnegative count without accepting fractional or blank values."""
    try:
        value = int(record[name])
    except (TypeError, ValueError) as error:
        raise ValueError(f"CSV line {line}: {name} must be an integer") from error
    if value < 0:
        raise ValueError(f"CSV line {line}: {name} must be nonnegative")
    return value


def _number(record: dict[str, str], name: str, line: int, *, positive: bool) -> float:
    """Reject blank, nonfinite, negative, and invalid timing statistics."""
    try:
        value = float(record[name])
    except (TypeError, ValueError) as error:
        raise ValueError(f"CSV line {line}: {name} must be numeric") from error
    if not math.isfinite(value) or (value <= 0 if positive else value < 0):
        condition = "positive and finite" if positive else "nonnegative and finite"
        raise ValueError(f"CSV line {line}: {name} must be {condition}")
    return value


def _validate_benchmark_inputs(record: dict[str, str], line: int) -> tuple[int, int]:
    """Require the two-input, two-output fixture used for the paper comparison."""
    input_count = _integer(record, "input_count", line)
    output_count = _integer(record, "output_count", line)
    fee = _integer(record, "fee", line)
    if (input_count, output_count) != (size_model.INPUT_COUNT, size_model.OUTPUT_COUNT):
        raise ValueError(f"CSV line {line}: comparison requires two inputs and two outputs")
    if (record["input_amounts"] != EXPECTED_INPUT_AMOUNTS
            or record["output_amounts"] != EXPECTED_OUTPUT_AMOUNTS
            or fee != EXPECTED_FEE):
        raise ValueError(f"CSV line {line}: benchmark amounts or fee do not match the fixture")
    return input_count, output_count


def load_timing_csv(path: Path) -> list[TimingRow]:
    """Read only complete, successful sigma_ring timing rows from a CSV file."""
    with path.open(encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames:
            raise ValueError("Timing CSV is empty or has no header")
        if len(reader.fieldnames) != len(set(reader.fieldnames)):
            raise ValueError("Timing CSV contains duplicate column names")
        missing = REQUIRED_COLUMNS.difference(reader.fieldnames)
        if missing:
            raise ValueError(f"Timing CSV is missing columns: {', '.join(sorted(missing))}")

        rows: list[TimingRow] = []
        seen_sizes: set[int] = set()
        for line, record in enumerate(reader, start=2):
            if None in record or any(value is None for value in record.values()):
                raise ValueError(f"CSV line {line}: malformed column count")
            ring_size = _integer(record, "ring_size", line)
            target = _integer(record, "target_repetitions", line)
            attempted = _integer(record, "attempted_repetitions", line)
            successful = _integer(record, "successful_repetitions", line)
            failed = _integer(record, "failed_repetitions", line)
            unattempted = _integer(record, "unattempted_repetitions", line)
            if ring_size < 2 or ring_size in seen_sizes:
                raise ValueError(f"CSV line {line}: ring size must be unique and at least 2")
            seen_sizes.add(ring_size)
            if record["proof_backend"] != "sigma_ring":
                raise ValueError(f"CSV line {line}: proof backend must be sigma_ring")
            if record["status"] != "complete":
                raise ValueError(f"CSV line {line}: benchmark status must be complete")
            if (successful < 2 or target != attempted or attempted != successful
                    or failed != 0 or unattempted != 0):
                raise ValueError(f"CSV line {line}: repetitions are incomplete or failed")
            if any(_integer(record, field, line) != 0 for field in
                   ("setup_failures", "spend_failures", "verify_failures",
                    "rejected_verifications")):
                raise ValueError(f"CSV line {line}: timing benchmark has failed work")
            _validate_benchmark_inputs(record, line)

            rows.append(TimingRow(
                ring_size=ring_size,
                successful_repetitions=successful,
                spend_mean_ms=_number(record, "spend_mean_ms", line, positive=True),
                spend_sample_std_ms=_number(record, "spend_std_ms", line, positive=False),
                verify_mean_ms=_number(record, "verify_mean_ms", line, positive=True),
                verify_sample_std_ms=_number(record, "verify_std_ms", line, positive=False),
                proof_backend="sigma_ring",
                measurement_source=MEASUREMENT_LABEL,
            ))
    if not rows:
        raise ValueError("Timing CSV contains no benchmark rows")
    return sorted(rows, key=lambda row: row.ring_size)


def _observations(record: dict[str, str], name: str, line: int,
                  expected_count: int) -> list[int]:
    """Validate raw encoded byte lengths rather than treating estimates as data."""
    parts = record[name].split(";")
    try:
        values = [int(part) for part in parts]
    except ValueError as error:
        raise ValueError(f"CSV line {line}: {name} must contain integer bytes") from error
    if len(values) != expected_count or any(value <= 0 for value in values):
        raise ValueError(f"CSV line {line}: {name} must contain {expected_count} positive sizes")
    return values


def load_size_csv(path: Path) -> list[SizeRow]:
    """Accept only ten verified, complete succinct-v1 size observations per ring."""
    with path.open(encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames:
            raise ValueError("Size CSV is empty or has no header")
        if len(reader.fieldnames) != len(set(reader.fieldnames)):
            raise ValueError("Size CSV contains duplicate column names")
        missing = SIZE_REQUIRED_COLUMNS.difference(reader.fieldnames)
        if missing:
            raise ValueError(f"Size CSV is missing columns: {', '.join(sorted(missing))}")
        rows: list[SizeRow] = []
        seen_sizes: set[int] = set()
        for line, record in enumerate(reader, start=2):
            if None in record or any(value is None for value in record.values()):
                raise ValueError(f"CSV line {line}: malformed column count")
            ring_size = _integer(record, "ring_size", line)
            if ring_size < 2 or ring_size in seen_sizes:
                raise ValueError(f"CSV line {line}: ring size must be unique and at least 2")
            seen_sizes.add(ring_size)
            target = _integer(record, "target_repetitions", line)
            attempted = _integer(record, "attempted_repetitions", line)
            successful = _integer(record, "successful_repetitions", line)
            proof_successful = _integer(record, "proof_successful_repetitions", line)
            if (target, attempted, successful, proof_successful) != (10, 10, 10, 10):
                raise ValueError(f"CSV line {line}: expected ten completed transaction and proof measurements")
            failure_fields = (
                "failed_repetitions", "unattempted_repetitions", "setup_failures",
                "spend_failures", "verify_failures", "rejected_verifications",
                "serialization_failures", "proof_serialization_failures",
            )
            if any(_integer(record, field, line) != 0 for field in failure_fields):
                raise ValueError(f"CSV line {line}: size benchmark has failed or unattempted work")
            if (record["measurement_status"] != "complete"
                    or record["proof_size_status"] != "complete" or record["blocker"].strip()):
                raise ValueError(f"CSV line {line}: size or proof measurement is incomplete")
            if record["proof_backend"] != "sigma_ring":
                raise ValueError(f"CSV line {line}: proof backend must be sigma_ring")
            format_name = record["serialization_format"].strip()
            if not format_name.startswith("succinct-v1"):
                raise ValueError(f"CSV line {line}: serialization format must be succinct-v1")
            input_count, output_count = _validate_benchmark_inputs(record, line)
            transaction_sizes = _observations(record, "transaction_bytes_observations", line, 10)
            proof_sizes = _observations(record, "proof_bytes_observations", line, 10)
            if any(proof > transaction for transaction, proof in zip(transaction_sizes, proof_sizes)):
                raise ValueError(f"CSV line {line}: proof cannot exceed its complete transaction")
            for prefix, values in (("transaction", transaction_sizes), ("proof", proof_sizes)):
                reported_mean = _number(record, f"{prefix}_bytes_mean", line, positive=True)
                reported_min = _integer(record, f"{prefix}_bytes_min", line)
                reported_max = _integer(record, f"{prefix}_bytes_max", line)
                if (not math.isclose(reported_mean, sum(values) / 10, rel_tol=1e-12)
                        or reported_min != min(values) or reported_max != max(values)):
                    raise ValueError(f"CSV line {line}: {prefix} summary disagrees with observations")
            rows.append(SizeRow(
                ring_size=ring_size,
                successful_repetitions=successful,
                input_count=input_count,
                output_count=output_count,
                transaction_bytes_mean=_number(record, "transaction_bytes_mean", line,
                                               positive=True),
                proof_bytes_mean=_number(record, "proof_bytes_mean", line, positive=True),
                proof_backend="sigma_ring",
                serialization_format=format_name,
                measurement_source=SIZE_MEASUREMENT_LABEL,
            ))
    if not rows:
        raise ValueError("Size CSV contains no benchmark rows")
    return sorted(rows, key=lambda row: row.ring_size)


def paper_size_totals(rows: list[SizeRow]) -> list[int]:
    """Use Task 01's SuccinCT analytical total at each measured ring size."""
    totals = []
    for row in rows:
        if (row.input_count, row.output_count) != (size_model.INPUT_COUNT,
                                                   size_model.OUTPUT_COUNT):
            raise ValueError("Paper comparison requires two inputs and two outputs")
        estimates = size_model.estimate_sizes(row.ring_size, "Size comparison",
                                              "Matched ring size and input/output counts")
        totals.append(next(item.total_bytes for item in estimates if item.protocol == "SuccinCT"))
    return totals


def write_summary(path: Path, rows: list[TimingRow]) -> None:
    """Export the validated statistics without changing the source CSV."""
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(TimingRow.__dataclass_fields__))
        writer.writeheader()
        writer.writerows(asdict(row) for row in rows)


def write_size_summary(path: Path, rows: list[SizeRow]) -> None:
    """Export measured sizes only; paper estimates stay in a separate plot."""
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(SizeRow.__dataclass_fields__))
        writer.writeheader()
        writer.writerows(asdict(row) for row in rows)


def _sample_count_label(rows: list[TimingRow] | list[SizeRow]) -> str:
    """Show completed observations for each ring, including mixed sample counts."""
    return "Successful repetitions by ring size: " + ", ".join(
        f"{row.ring_size}: n={row.successful_repetitions}" for row in rows
    )


def plot_timings(plt, output_dir: Path, rows: list[TimingRow]) -> None:
    """Save mean lines and mean ± recorded sample-standard-deviation bands."""
    ring_sizes = [row.ring_size for row in rows]
    series = (
        ("Spend", [row.spend_mean_ms for row in rows],
         [row.spend_sample_std_ms for row in rows], "tab:blue"),
        ("Verify", [row.verify_mean_ms for row in rows],
         [row.verify_sample_std_ms for row in rows], "tab:orange"),
    )
    for with_spread, filename in ((False, MEANS_NAME), (True, MEAN_STD_NAME)):
        fig, ax = plt.subplots(figsize=(9, 6))
        for label, means, standard_deviations, color in series:
            ax.plot(ring_sizes, means, marker="o", color=color, label=label)
            if with_spread:
                lower = [mean - spread for mean, spread in zip(means, standard_deviations)]
                upper = [mean + spread for mean, spread in zip(means, standard_deviations)]
                ax.fill_between(ring_sizes, lower, upper, color=color, alpha=0.18)
        ax.set_xticks(ring_sizes)
        ax.set_xlabel("Ring size (accounts)")
        ax.set_ylabel("Execution time (ms)")
        ax.set_title("Python sigma_ring Spend and Verify: " +
                     ("mean ± sample standard deviation" if with_spread else "mean time"))
        ax.grid(True, alpha=0.25)
        ax.legend()
        fig.text(0.02, 0.02,
                 MEASUREMENT_LABEL + "\n" + _sample_count_label(rows), fontsize=8)
        fig.tight_layout(rect=(0, 0.1, 1, 1))
        try:
            fig.savefig(output_dir / filename, dpi=200)
        finally:
            plt.close(fig)


def plot_sizes(plt, output_dir: Path, rows: list[SizeRow]) -> None:
    """Plot measured nested sizes and a separately labeled paper model comparison."""
    ring_sizes = [row.ring_size for row in rows]
    transaction_sizes = [row.transaction_bytes_mean for row in rows]
    proof_sizes = [row.proof_bytes_mean for row in rows]

    fig, ax = plt.subplots(figsize=(9, 6))
    ax.plot(ring_sizes, transaction_sizes, marker="o", label="Complete transaction (measured)")
    ax.plot(ring_sizes, proof_sizes, marker="s", label="Contained proof (measured)")
    ax.set_xticks(ring_sizes)
    ax.set_xlabel("Ring size (accounts)")
    ax.set_ylabel("Encoded size (bytes)")
    ax.set_title("Measured Python sigma_ring sizes (succinct-v1)")
    ax.grid(True, alpha=0.25)
    ax.legend()
    fig.text(0.02, 0.02, SIZE_MEASUREMENT_LABEL + "\n"
             "Proof bytes are already included in complete transaction bytes.\n"
             + _sample_count_label(rows),
             fontsize=8)
    fig.tight_layout(rect=(0, 0.13, 1, 1))
    try:
        fig.savefig(output_dir / SIZE_PLOT_NAME, dpi=200)
    finally:
        plt.close(fig)

    fig, ax = plt.subplots(figsize=(9, 6))
    ax.plot(ring_sizes, paper_size_totals(rows), marker="o", label=PAPER_SIZE_LABEL)
    ax.plot(ring_sizes, transaction_sizes, marker="s",
            label="Measured Python sigma_ring complete transaction (succinct-v1)")
    ax.set_xticks(ring_sizes)
    ax.set_xlabel("Ring size (accounts)")
    ax.set_yscale("log")
    ax.set_ylabel("Complete transaction size (bytes, log scale)")
    ax.set_title("Paper analytical SuccinCT vs measured Python sigma_ring")
    ax.grid(True, alpha=0.25)
    ax.legend()
    fig.text(0.02, 0.02,
             "Same ring sizes, two inputs, two outputs, 64-bit amounts and 4-byte references.\n"
             "Different proof systems and encodings: paper Bulletproofs++/32-byte elements; "
             "Python sigma_ring/33-byte points. Not equivalent implementations.\n"
             + _sample_count_label(rows), fontsize=8)
    fig.tight_layout(rect=(0, 0.16, 1, 1))
    try:
        fig.savefig(output_dir / SIZE_COMPARISON_NAME, dpi=200)
    finally:
        plt.close(fig)


def main(argv: list[str] | None = None) -> None:
    """Validate inputs before writing timing and optional actual-size outputs."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT,
                        help=f"Existing timing CSV (default: {DEFAULT_INPUT}).")
    parser.add_argument("--size-input", type=Path, default=None,
                        help=f"Verified size CSV (for example: {DEFAULT_SIZE_INPUT}).")
    parser.add_argument("--size-only", action="store_true",
                        help="Add only size outputs; preserve existing timing outputs.")
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR,
                        help=f"New output directory (default: {DEFAULT_OUTPUT_DIR}).")
    args = parser.parse_args(argv)
    if args.size_only and args.size_input is None:
        parser.error("--size-only requires --size-input")
    timing_rows = None
    size_rows = None
    try:
        if not args.size_only:
            timing_rows = load_timing_csv(args.input)
        if args.size_input is not None:
            size_rows = load_size_csv(args.size_input)
    except (OSError, UnicodeError, ValueError) as error:
        parser.error(f"Cannot use benchmark CSV: {error}")
    timing_outputs = [args.output_dir / name for name in
                      (SUMMARY_NAME, MEANS_NAME, MEAN_STD_NAME)]
    size_outputs = [args.output_dir / name for name in
                    (SIZE_SUMMARY_NAME, SIZE_PLOT_NAME, SIZE_COMPARISON_NAME)]
    output_paths = (timing_outputs if timing_rows is not None else []) + (
        size_outputs if size_rows is not None else [])
    inputs = [args.input] if timing_rows is not None else []
    if args.size_input is not None:
        inputs.append(args.size_input)
    if any(output.resolve() == source.resolve()
           for output in output_paths for source in inputs):
        parser.error("An output path matches a source CSV")
    existing = [path for path in output_paths if path.exists()]
    if existing:
        parser.error(f"Output already exists: {existing[0]}. Choose another directory.")
    try:
        import matplotlib
        matplotlib.use("Agg")  # Render files without an interactive display.
        import matplotlib.pyplot as plt
    except ImportError as error:
        parser.error(f"matplotlib is required to generate timing plots: {error}")

    args.output_dir.mkdir(parents=True, exist_ok=True)
    if timing_rows is not None:
        write_summary(timing_outputs[0], timing_rows)
        plot_timings(plt, args.output_dir, timing_rows)
        print(f"Timing source: {args.input} ({len(timing_rows)} complete sigma_ring configurations; "
              f"{_sample_count_label(timing_rows)}).")
        for path in timing_outputs:
            print(f"Wrote {path}.")
        print(MEASUREMENT_LABEL + ".")
    if size_rows is not None:
        write_size_summary(size_outputs[0], size_rows)
        plot_sizes(plt, args.output_dir, size_rows)
        print(f"Size source: {args.size_input} ({len(size_rows)} complete sigma_ring configurations; "
              f"{_sample_count_label(size_rows)}).")
        for path in size_outputs:
            print(f"Wrote {path}.")
        print("Proof bytes are contained within complete transaction bytes; they were not added.")
        print("Paper analytical Bulletproofs++ sizes and Python sigma_ring measurements "
              "use different proof systems and encodings.")
    else:
        print("Size-measurement plots skipped: no verified complete-transaction size input "
              "was supplied.")


if __name__ == "__main__":
    main()
