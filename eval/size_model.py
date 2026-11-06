"""Export paper analytical size estimates for SuccinCT Figures 1 and 7.

Source: SuccinCT: Succinct Confidential Transaction for Miner Privacy,
Table 1, Section 1.2, Section 7, and Appendices E and J.1. These formulas
describe the paper's protocols, NOT serialized Python transactions or the
repository's replacement sigma_ring proof. No cryptographic code is imported.

Figure 1 fixes R=256 and S=T=2. Both figures use 32-byte group/field elements,
64-bit amounts (Appendix E), and 4-byte input references (Appendix J.1).
Figure 7 fixes S=T=2 and varies R. Its exact sampling grid is not specified
in the paper. The default grid uses Section 7's explicitly listed ring sizes;
--ring-sizes supplies a different, explicitly selected visualization grid.

Table 1 leaves ZGSX23 output size unknown. For the figures, Section 1.2
explicitly conjectures the CLSAG/RingCT 3.0 output format. That conjecture is
reported separately from the specified Table 1 components, never as a fact
about an implemented ZGSX23 output format. No additional wire-format overhead
(for example fees, messages, or length prefixes) is invented.
"""

from __future__ import annotations

import argparse
import csv
from dataclasses import asdict, dataclass
from pathlib import Path


PROTOCOLS = ("CLSAG", "RingCT 3.0", "Omniring", "ZGSX23", "BulletCT", "SuccinCT")
GROUP_BYTES = 32
AMOUNT_BITS = 64
REFERENCE_BYTES = 4
INPUT_COUNT = 2
OUTPUT_COUNT = 2
FIGURE1_RING_SIZE = 256
DEFAULT_RING_SIZES = (128, 256, 512, 1024)
ESTIMATE_KIND = "paper analytical estimate; not measured Python transaction bytes"
ZGSX23_NOTE = (
    "Table 1 output unknown; Section 1.2 conjectures CLSAG/RingCT 3.0 output size"
)


@dataclass(frozen=True)
class SizeEstimate:
    """One Table 1 component breakdown, in bytes, with its assumptions."""

    figure: str
    protocol: str
    ring_size: int
    input_count: int
    output_count: int
    group_bytes: int
    amount_bits: int
    reference_bytes: int
    input_reference_bytes: int
    key_image_bytes: int
    proof_bytes: int
    # None preserves Table 1's '?' instead of silently substituting a value.
    table1_output_bytes: int | None
    # The figures may use the paper's explicitly stated output conjecture.
    output_bytes: int
    total_bytes: int
    output_status: str
    estimate_kind: str
    sampling_note: str
    source: str


def ceil_log2(value: int) -> int:
    """Return ceil(log2(value)) exactly, without floating-point rounding."""
    if value < 1:
        raise ValueError("The logarithm argument must be positive.")
    return (value - 1).bit_length()


def estimate_sizes(ring_size: int, figure: str, sampling_note: str) -> list[SizeEstimate]:
    """Apply all six Table 1 rows to a two-input, two-output transaction.

    R is the total number of ring accounts, S the real input count, T the
    output count, beta the amount bit length, g=|G| the group/field element
    size, and i=|I| the size of one reference to a previous output. A key
    image is the public tag used to detect spending an input twice.
    """
    if ring_size < INPUT_COUNT:
        raise ValueError("Ring size must be at least the number of real inputs (2).")
    r, s, t = ring_size, INPUT_COUNT, OUTPUT_COUNT
    beta, g, i = AMOUNT_BITS, GROUP_BYTES, REFERENCE_BYTES

    # Table 1 proof coefficients multiply |G|, treating group and field
    # elements as equally sized. Parentheses and ceiling placement follow
    # the printed table, including RingCT 3.0's R + 17 expression.
    proof_elements = {
        "CLSAG": (2 * r + 1) * s + 2 * ceil_log2(beta * t) + 9,
        "RingCT 3.0": 2 * s * ceil_log2(r + 17) + 2 * ceil_log2(beta * t) + 2,
        "Omniring": 2 * ceil_log2(3 + r + r * s + beta * t + 3 * s) + 9,
        "ZGSX23": 2 * ceil_log2(r + beta * t) + 9,
        "BulletCT": 2 * ceil_log2(r + s + beta * t) + 20,
        "SuccinCT": 2 * ceil_log2(r * (s + 1) + beta * t) + 10,
    }

    # Table 1: two group elements per output, one shared ephemeral key,
    # and beta/8 encrypted amount bytes per output. Omniring instead has
    # 8*T group elements and two beta-bit ciphertext contributions per output.
    common_output = (2 * t + 1) * g + t * (beta // 8)
    omniring_output = 8 * t * g + 2 * t * (beta // 8)
    estimates = []
    for protocol in PROTOCOLS:
        input_bytes = r * i                 # Table 1: R references for every protocol.
        image_bytes = (r if protocol == "ZGSX23" else s) * g
        proof_bytes = proof_elements[protocol] * g
        output_bytes = omniring_output if protocol == "Omniring" else common_output
        conjectured = protocol == "ZGSX23"
        estimates.append(SizeEstimate(
            figure=figure,
            protocol=protocol,
            ring_size=r,
            input_count=s,
            output_count=t,
            group_bytes=g,
            amount_bits=beta,
            reference_bytes=i,
            input_reference_bytes=input_bytes,
            key_image_bytes=image_bytes,
            proof_bytes=proof_bytes,
            table1_output_bytes=None if conjectured else output_bytes,
            output_bytes=output_bytes,
            total_bytes=input_bytes + image_bytes + proof_bytes + output_bytes,
            output_status=ZGSX23_NOTE if conjectured else "specified in Table 1",
            estimate_kind=ESTIMATE_KIND,
            sampling_note=sampling_note,
            source="SuccinCT Table 1; Section 1.2; Appendices E and J.1",
        ))
    return estimates


def write_csv(path: Path, rows: list[SizeEstimate]) -> None:
    """Write components, totals, parameters, and caveats without pandas."""
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(SizeEstimate.__dataclass_fields__))
        writer.writeheader()
        writer.writerows(asdict(row) for row in rows)


def plot_figures(plt, output_dir: Path, figure1: list[SizeEstimate],
                 figure7: list[SizeEstimate], sampling_note: str) -> None:
    """Plot the Figure 1 breakdown and Figure 7 log-log total comparison.

    Figure 1 uses a log y-axis to retain the full CLSAG bar without clipping.
    Figure 7 connects the exported samples; it does not claim to recover
    the paper's original sampling grid or any unexported measurements.
    """
    labels = [row.protocol + ("*" if row.protocol == "ZGSX23" else "") for row in figure1]
    fig, ax = plt.subplots(figsize=(10, 6))
    bottom = [0] * len(figure1)
    for field, label in (
        ("input_reference_bytes", "Input references"),
        ("key_image_bytes", "Key images"),
        ("proof_bytes", "Proof"),
        ("output_bytes", "Outputs"),
    ):
        values = [getattr(row, field) for row in figure1]
        ax.bar(labels, values, bottom=bottom, label=label)
        bottom = [base + value for base, value in zip(bottom, values)]
    for label, row in zip(labels, figure1):
        ax.annotate(f"{row.total_bytes:,}", (label, row.total_bytes),
                    xytext=(0, 5), textcoords="offset points", ha="center")
    ax.set_yscale("log")
    ax.set_ylim(1, max(row.total_bytes for row in figure1) * 3)
    ax.set_ylabel("Transaction size (bytes, log scale)")
    ax.set_title("Figure 1 model: paper analytical estimates\n"
                 "R=256; S=T=2; |G|=32 bytes; beta=64 bits; |I|=4 bytes")
    ax.legend()
    fig.text(0.02, 0.02, "* ZGSX23 outputs use the paper's Section 1.2 conjecture.\n"
             "Not measured Python transaction sizes.", fontsize=9)
    fig.tight_layout(rect=(0, 0.09, 1, 1))
    try:
        fig.savefig(output_dir / "figure1_paper_size_model.png", dpi=200)
    finally:
        plt.close(fig)

    fig, ax = plt.subplots(figsize=(10, 6))
    for protocol in PROTOCOLS:
        rows = [row for row in figure7 if row.protocol == protocol]
        ax.plot([row.ring_size for row in rows], [row.total_bytes for row in rows],
                marker="o", linestyle="--" if protocol == "CLSAG" else "-",
                label=protocol + ("*" if protocol == "ZGSX23" else ""))
    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.set_xlabel("Ring size R (total ring accounts, log scale)")
    ax.set_ylabel("Transaction size (bytes, log scale)")
    ax.set_title("Figure 7 model: paper analytical estimates\n"
                 "S=T=2; |G|=32 bytes; beta=64 bits; |I|=4 bytes")
    ax.grid(True, which="both", alpha=0.25)
    ax.legend()
    fig.text(0.02, 0.02, "* ZGSX23 outputs use the paper's Section 1.2 conjecture.\n"
             "Not measured Python transaction sizes.\n" + sampling_note, fontsize=8)
    fig.tight_layout(rect=(0, 0.12, 1, 1))
    try:
        fig.savefig(output_dir / "figure7_paper_size_model.png", dpi=200)
    finally:
        plt.close(fig)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--seed", type=int, default=5163,
                        help="Accepted for run_all.sh compatibility; has no effect on this deterministic model.")
    parser.add_argument("--csv-only", action="store_true",
                        help="Write CSV files without importing matplotlib or generating plots.")
    parser.add_argument("--output-dir", type=Path, default=Path("eval/plots"),
                        help="Output directory, relative to the working directory (default: eval/plots).")
    parser.add_argument("--ring-sizes", type=int, nargs="+", default=None,
                        help="Explicit Figure 7 sampling grid. Default: 128 256 512 1024 from Section 7; "
                             "the paper does not specify Figure 7's exact sampling grid.")
    args = parser.parse_args(argv)
    if args.ring_sizes is not None and any(size < INPUT_COUNT for size in args.ring_sizes):
        parser.error("Every ring size must be at least 2.")
    ring_sizes = sorted(set(args.ring_sizes or DEFAULT_RING_SIZES))
    sampling_note = (
        "User-selected grid; original Figure 7 sampling grid unspecified in the paper."
        if args.ring_sizes is not None else
        "Section 7 grid only; original Figure 7 sampling grid unspecified in the paper."
    )
    figure1 = estimate_sizes(FIGURE1_RING_SIZE, "Figure 1", "Fixed R=256 in Figure 1 caption.")
    figure7 = [row for size in ring_sizes
               for row in estimate_sizes(size, "Figure 7", sampling_note)]
    args.output_dir.mkdir(parents=True, exist_ok=True)
    for filename, rows in (("figure1_paper_size_model.csv", figure1),
                           ("figure7_paper_size_model.csv", figure7)):
        path = args.output_dir / filename
        write_csv(path, rows)
        print(f"Wrote {path} ({len(rows)} analytical estimate rows).")
    print(f"Results: {ESTIMATE_KIND}.")
    print(f"--seed={args.seed} has no effect: all formulas are deterministic.")
    print(f"Figure 7 ring sizes: {', '.join(map(str, ring_sizes))}. {sampling_note}")
    print(f"ZGSX23 caveat: {ZGSX23_NOTE}.")
    if args.csv_only:
        print("CSV-only mode: no plotting dependencies were imported.")
        return
    try:
        import matplotlib
        matplotlib.use("Agg")  # File output only; no interactive display is needed.
        import matplotlib.pyplot as plt
    except ImportError:
        print("Matplotlib is unavailable. CSV exports are complete; plots were skipped.")
        return
    plot_figures(plt, args.output_dir, figure1, figure7, sampling_note)
    print(f"Wrote {args.output_dir / 'figure1_paper_size_model.png'}.")
    print(f"Wrote {args.output_dir / 'figure7_paper_size_model.png'}.")


if __name__ == "__main__":
    main()
