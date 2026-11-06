"""Put our measured timings and sizes next to the paper's.

Reads the CSVs that run_all already writes and produces:

    eval/results/comparison.csv     one row per ring size, every number side by side
    eval/results/comparison.md      the same as a markdown table, for the report
    eval/plots/timing_vs_paper.png  Spend and Verify time against ring size
    eval/plots/size_vs_paper.png    transaction size against ring size

Paper numbers come from two places:
  * timing: Table 3 (Go, cloudflare/bn256, Bulletproofs++, Apple M1,
    single thread, mean +- std over 100 runs), copied below;
  * size: eval.size_model's Figure 7 CSV (the paper's Table 1 formulas,
    S = T = 2, 32-byte elements).

The comparison is about how cost grows with ring size, not absolute speed:
language, curve, proof system and hardware all differ (see the README).
An optional pure-Python timing CSV (the curve before the libsecp256k1 swap)
can be passed with --baseline-time to show that change separately.

    python -m eval.compare
    python -m eval.compare --baseline-time eval/results/bench_time_sigma_ring_n10.csv
"""

from __future__ import annotations

import argparse
import csv
from pathlib import Path

# Paper Table 3: ring size -> (spend mean, spend std, verify mean, verify std), ms.
PAPER_TABLE3_MS = {
    128: (2.00509, 0.323716, 1.24612, 0.221242),
    256: (2.18062, 0.097861, 1.39342, 0.123428),
    512: (2.64914, 0.128827, 1.80817, 0.206267),
    1024: (3.56213, 0.158974, 2.60732, 0.169522),
}

DEFAULT_TIME = Path("eval/results/bench_time_sigma_ring.csv")
DEFAULT_SIZE = Path("eval/results/bench_size_sigma_ring.csv")
DEFAULT_MODEL = Path("eval/plots/figure7_paper_size_model.csv")

# Categorical slots 1-3 of the reference palette (validated for CVD separation).
# Slot 3 sits below 3:1 contrast on white, so every line is also direct-labelled.
OURS, PAPER, BASELINE = "#2a78d6", "#eb6834", "#1baf7a"
INK, MUTED, GRID = "#0b0b0b", "#52514e", "#e4e3df"


def _rows(path):
    with open(path, newline="") as f:
        return list(csv.DictReader(f))


def _by_ring(rows, *fields):
    out = {}
    for r in rows:
        if r.get("status", r.get("measurement_status", "complete")) != "complete":
            continue
        out[int(r["ring_size"])] = tuple(float(r[f]) for f in fields)
    return out


def load(time_path, size_path, model_path, baseline_path=None):
    time = _by_ring(_rows(time_path), "spend_mean_ms", "spend_std_ms",
                    "verify_mean_ms", "verify_std_ms")
    size = _by_ring(_rows(size_path), "transaction_bytes_mean", "proof_bytes_mean")
    model = {}
    for r in _rows(model_path):
        if r["protocol"] in ("SuccinCT", "BulletCT"):
            model.setdefault(int(r["ring_size"]), {})[r["protocol"]] = int(r["total_bytes"])
    baseline = {}
    if baseline_path:
        baseline = _by_ring(_rows(baseline_path), "spend_mean_ms", "spend_std_ms",
                            "verify_mean_ms", "verify_std_ms")

    rings = sorted(set(time) & set(size) & set(model) & set(PAPER_TABLE3_MS))
    if not rings:
        raise SystemExit("no ring size appears in every input; run run_all first")
    table = []
    for n in rings:
        ps, pss, pv, pvs = PAPER_TABLE3_MS[n]
        os_, oss, ov, ovs = time[n]
        tx_bytes, proof_bytes = size[n]
        row = {
            "ring_size": n,
            "paper_spend_ms": ps, "paper_spend_std_ms": pss,
            "paper_verify_ms": pv, "paper_verify_std_ms": pvs,
            "ours_spend_ms": round(os_, 3), "ours_spend_std_ms": round(oss, 3),
            "ours_verify_ms": round(ov, 3), "ours_verify_std_ms": round(ovs, 3),
            "spend_ratio_ours_over_paper": round(os_ / ps, 1),
            "verify_ratio_ours_over_paper": round(ov / pv, 1),
            "ours_tx_bytes": int(tx_bytes), "ours_proof_bytes": int(proof_bytes),
            "paper_succinct_tx_bytes": model[n]["SuccinCT"],
            "paper_bulletct_tx_bytes": model[n]["BulletCT"],
            "size_ratio_ours_over_paper": round(tx_bytes / model[n]["SuccinCT"], 1),
        }
        if n in baseline:
            row["purepython_spend_ms"] = round(baseline[n][0], 1)
            row["purepython_verify_ms"] = round(baseline[n][2], 1)
        table.append(row)
    return table


def growth(table, key):
    """Cost at the largest ring divided by cost at the smallest."""
    return table[-1][key] / table[0][key]


def write_csv(table, path):
    fields = list(dict.fromkeys(k for row in table for k in row))
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(table)


def write_markdown(table, path):
    lines = [
        "| Ring | Paper spend (ms) | Ours spend (ms) | Paper verify (ms) | Ours verify (ms)"
        " | Paper tx (B) | Ours tx (B) |",
        "|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for r in table:
        lines.append(
            f"| {r['ring_size']} "
            f"| {r['paper_spend_ms']:.2f} ± {r['paper_spend_std_ms']:.2f} "
            f"| {r['ours_spend_ms']:.1f} ± {r['ours_spend_std_ms']:.1f} "
            f"| {r['paper_verify_ms']:.2f} ± {r['paper_verify_std_ms']:.2f} "
            f"| {r['ours_verify_ms']:.1f} ± {r['ours_verify_std_ms']:.1f} "
            f"| {r['paper_succinct_tx_bytes']:,} | {r['ours_tx_bytes']:,} |")
    lo, hi = table[0]["ring_size"], table[-1]["ring_size"]
    lines += [
        "",
        f"Growth from ring {lo} to {hi} (largest / smallest):",
        f"paper spend x{growth(table, 'paper_spend_ms'):.2f}, "
        f"ours x{growth(table, 'ours_spend_ms'):.2f}; "
        f"paper verify x{growth(table, 'paper_verify_ms'):.2f}, "
        f"ours x{growth(table, 'ours_verify_ms'):.2f}; "
        f"paper tx size x{growth(table, 'paper_succinct_tx_bytes'):.2f}, "
        f"ours x{growth(table, 'ours_tx_bytes'):.2f}.",
        "",
        "Paper: Table 3 timings (Go, bn256, Bulletproofs++, Apple M1, 1 thread, 100 runs) and",
        "Table 1 size formulas (S = T = 2). Ours: Python, secp256k1 via libsecp256k1,",
        "linear Sigma-protocol + Bulletproofs range proof, 2 inputs, 2 outputs, 1 thread.",
    ]
    Path(path).write_text("\n".join(lines) + "\n")


def _style(ax, title, ylabel):
    ax.set_title(title, loc="left", fontsize=12, color=INK, pad=10)
    ax.set_xscale("log", base=2)
    ax.set_yscale("log")
    ax.set_xlabel("Ring size", color=MUTED)
    ax.set_ylabel(ylabel, color=MUTED)
    ax.grid(True, which="major", color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    for side in ("left", "bottom"):
        ax.spines[side].set_color(MUTED)
    ax.tick_params(colors=MUTED)


def _line(ax, xs, ys, color, label, errs=None, nudge=0):
    ax.errorbar(xs, ys, yerr=errs, color=color, linewidth=2, marker="o",
                markersize=6, markeredgecolor="white", markeredgewidth=1.5,
                capsize=3, label=label)
    # Direct label at the right end so identity never rests on colour alone.
    # nudge (points) separates two labels whose lines end close together.
    ax.annotate(label, (xs[-1], ys[-1]), xytext=(8, nudge), textcoords="offset points",
                va="center", fontsize=9, color=INK)


def _legend(fig, ax, y):
    """One legend row under the title, clear of the data."""
    handles, labels = ax.get_legend_handles_labels()
    fig.legend(handles, labels, loc="upper left", bbox_to_anchor=(0.01, y),
               ncol=len(labels), frameon=False, fontsize=9)


def plot(table, out_dir):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib.ticker import FixedLocator, FuncFormatter

    xs = [r["ring_size"] for r in table]
    ticks = FixedLocator(xs)
    plain = FuncFormatter(lambda v, _: f"{v:g}")
    has_base = all("purepython_spend_ms" in r for r in table)

    fig, axes = plt.subplots(1, 2, figsize=(11, 4.6), sharey=True)
    for ax, op in zip(axes, ("spend", "verify")):
        _style(ax, f"{op.capitalize()} time", "Time (ms, log scale)" if op == "spend" else "")
        _line(ax, xs, [r[f"ours_{op}_ms"] for r in table], OURS, "Ours (libsecp256k1)",
              [r[f"ours_{op}_std_ms"] for r in table])
        if has_base:
            _line(ax, xs, [r[f"purepython_{op}_ms"] for r in table], BASELINE,
                  "Ours, pure-Python curve")
        _line(ax, xs, [r[f"paper_{op}_ms"] for r in table], PAPER, "Paper (Table 3)",
              [r[f"paper_{op}_std_ms"] for r in table])
        ax.xaxis.set_major_locator(ticks)
        ax.xaxis.set_major_formatter(plain)
        ax.xaxis.set_minor_locator(FixedLocator([]))
        ax.set_xlim(xs[0] / 1.3, xs[-1] * 4.5)
    axes[0].yaxis.set_major_formatter(plain)
    lo_n, hi_n = table[0]["ring_size"], table[-1]["ring_size"]
    fig.suptitle(f"Our spend time grows {growth(table, 'ours_spend_ms'):.1f}x from ring "
                 f"{lo_n} to {hi_n}; the paper's grows {growth(table, 'paper_spend_ms'):.1f}x",
                 x=0.01, ha="left", fontsize=13, color=INK)
    _legend(fig, axes[0], 0.93)
    note = ("Paper: Go, bn256, Bulletproofs++, Apple M1. Ours: Python, secp256k1, "
            "linear Σ-protocol, 2 inputs, 2 outputs, 1 thread. Error bars: ±1 std.")
    if has_base:
        note += "\nPure-Python curve: an earlier 10-run measurement on a different machine."
    fig.text(0.01, 0.01, note, fontsize=8, color=MUTED)
    fig.tight_layout(rect=(0, 0.08 if has_base else 0.05, 1, 0.88))
    fig.savefig(Path(out_dir) / "timing_vs_paper.png", dpi=200)
    plt.close(fig)

    fig, ax = plt.subplots(figsize=(8, 4.8))
    _style(ax, "", "Transaction size (bytes, log scale)")
    _line(ax, xs, [r["ours_tx_bytes"] for r in table], OURS, "Ours (measured)")
    _line(ax, xs, [r["paper_bulletct_tx_bytes"] for r in table], BASELINE,
          "BulletCT (paper model)", nudge=7)
    _line(ax, xs, [r["paper_succinct_tx_bytes"] for r in table], PAPER,
          "SuccinCT (paper model)", nudge=-7)
    ax.xaxis.set_major_locator(ticks)
    ax.xaxis.set_major_formatter(plain)
    ax.xaxis.set_minor_locator(FixedLocator([]))
    ax.yaxis.set_major_locator(FixedLocator([1000, 2000, 5000, 10000, 20000, 50000, 100000]))
    ax.yaxis.set_minor_locator(FixedLocator([]))
    ax.yaxis.set_major_formatter(FuncFormatter(lambda v, _: f"{v:,.0f}"))
    ax.set_ylim(1000, 120000)
    ax.set_xlim(xs[0] / 1.3, xs[-1] * 4)
    _legend(fig, ax, 0.91)
    lo, hi = table[0], table[-1]
    fig.suptitle(f"Our linear proof makes transactions {lo['size_ratio_ours_over_paper']:g}x "
                 f"to {hi['size_ratio_ours_over_paper']:g}x the paper's size",
                 x=0.01, ha="left", fontsize=13, color=INK)
    fig.text(0.01, 0.01, "Paper sizes: Table 1 formulas (S = T = 2, 32-byte elements). "
             "Ours: serialized transaction incl. R, T and the full proof.",
             fontsize=8, color=MUTED)
    fig.tight_layout(rect=(0, 0.04, 1, 0.86))
    fig.savefig(Path(out_dir) / "size_vs_paper.png", dpi=200)
    plt.close(fig)


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--time", type=Path, default=DEFAULT_TIME)
    p.add_argument("--size", type=Path, default=DEFAULT_SIZE)
    p.add_argument("--model", type=Path, default=DEFAULT_MODEL)
    p.add_argument("--baseline-time", type=Path, default=None,
                   help="optional earlier timing CSV (pure-Python curve)")
    p.add_argument("--results-dir", type=Path, default=Path("eval/results"))
    p.add_argument("--plots-dir", type=Path, default=Path("eval/plots"))
    p.add_argument("--no-plots", action="store_true")
    args = p.parse_args(argv)

    table = load(args.time, args.size, args.model, args.baseline_time)
    args.results_dir.mkdir(parents=True, exist_ok=True)
    write_csv(table, args.results_dir / "comparison.csv")
    write_markdown(table, args.results_dir / "comparison.md")
    if not args.no_plots:
        args.plots_dir.mkdir(parents=True, exist_ok=True)
        plot(table, args.plots_dir)
    print((args.results_dir / "comparison.md").read_text())


if __name__ == "__main__":
    main()
