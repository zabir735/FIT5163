"""Plot every version of SuccinCT against the paper: transaction size, Spend
time and Verify time against ring size.

Reads the Go CSVs in go/results/, the Python CSVs in eval/results/ and the
paper's numbers (Table 3 for time, the Table 1 size model for bytes), and
writes three PNGs to go/results/plots/. Run from the repository root:

    python go/plot_go.py

Every line has its own marker as well as its colour, and the legend names
them, so no line is told apart by colour alone. Where lines overlap (the
Σ-protocol sizes are identical in every version) the legend still lists them.
The time axes are logarithmic because the versions differ by up to 1000x; the size axis is linear so the drop from BP++ is shown at true scale; the numbers themselves are in go/README.md.
"""

from __future__ import annotations

import csv
import sys
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.ticker import FuncFormatter, LogLocator, NullFormatter  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
GO = ROOT / "go" / "results"
OUT = GO / "plots"
sys.path.insert(0, str(ROOT))
from eval.compare import PAPER_TABLE3_MS  # noqa: E402

RINGS = [128, 256, 512, 1024]
INK, MUTED, GRID = "#1f1f1e", "#6b6a63", "#e4e3dd"

# (label, colour, marker). Fixed order: the same version always gets the same
# colour in every chart.
STYLE = {
    "python": ("Python · secp256k1 · Σ", "#2a78d6", "o"),
    "secp_sigma": ("Go · secp256k1 · Σ", "#eb6834", "s"),
    "secp_bpp": ("Go · secp256k1 · BP++", "#1baf7a", "^"),
    "bn_sigma": ("Go · BN254 · Σ", "#eda100", "D"),
    "bn_bpp": ("Go · BN254 · BP++", "#e87ba4", "v"),
    "paper": ("Paper · bn256 · BP++", "#008300", "P"),
}


def read(path: Path) -> dict[int, dict[str, str]]:
    with path.open(newline="") as fh:
        return {int(r["ring_size"]): r for r in csv.DictReader(fh)}


def paper_bytes() -> dict[int, float]:
    """Total bytes of the paper's model (S = T = 2), from eval.size_model's CSV."""
    path = ROOT / "eval" / "plots" / "figure7_paper_size_model.csv"
    out: dict[int, float] = {}
    if not path.exists():
        return out
    with path.open(newline="") as fh:
        for r in csv.DictReader(fh):
            keys = {k.lower(): k for k in r}
            ring = r.get(keys.get("ring_size", ""), "")
            total = next((r[keys[k]] for k in keys if "total" in k and "byte" in k), None)
            proto = next((r[keys[k]] for k in keys if k in ("protocol", "scheme")), "SuccinCT")
            if ring and total and "succinct" in proto.lower():
                out[int(ring)] = float(total)
    return out


def load() -> dict[str, dict[str, dict[int, float]]]:
    py_t = read(ROOT / "eval" / "results" / "bench_time_sigma_ring.csv")
    py_s = read(ROOT / "eval" / "results" / "bench_size_sigma_ring.csv")
    data = {
        "python": {
            "spend": {n: float(py_t[n]["spend_mean_ms"]) for n in py_t},
            "verify": {n: float(py_t[n]["verify_mean_ms"]) for n in py_t},
            "bytes": {n: float(py_s[n]["transaction_bytes_mean"]) for n in py_s},
        }
    }
    for key, name in [
        ("secp_sigma", "bench_go_pippenger"),
        ("secp_bpp", "bench_secp_bpp_msm"),
        ("bn_sigma", "bench_bn254_sigma_msm"),
        ("bn_bpp", "bench_bn254_bpp_msm"),
    ]:
        rows = read(GO / f"{name}.csv")
        data[key] = {
            "spend": {n: float(rows[n]["spend_mean_ms"]) for n in rows},
            "verify": {n: float(rows[n]["verify_mean_ms"]) for n in rows},
            "bytes": {n: float(rows[n]["tx_bytes"]) for n in rows},
        }
    data["paper"] = {
        "spend": {n: v[0] for n, v in PAPER_TABLE3_MS.items()},
        "verify": {n: v[2] for n, v in PAPER_TABLE3_MS.items()},
        "bytes": paper_bytes(),
    }
    return data


def human(v: float, _pos=None) -> str:
    if v >= 1000:
        return f"{v / 1000:g}k"
    return f"{v:g}"


def chart(data, metric: str, title: str, ylabel: str, fname: str) -> Path:
    fig, ax = plt.subplots(figsize=(8.6, 5.2), dpi=160)
    fig.patch.set_facecolor("white")
    for key, (label, colour, marker) in STYLE.items():
        series = data[key][metric]
        xs = [n for n in RINGS if n in series]
        if not xs:
            continue
        ys = [series[n] for n in xs]
        ax.plot(xs, ys, color=colour, lw=2, marker=marker, ms=7,
                markeredgecolor="white", markeredgewidth=1.5, label=label, zorder=3)

    linear = metric == "bytes"  # size: a linear axis shows the 11x drop as it is
    ax.set_xscale("log", base=2)
    ax.set_xticks(RINGS)
    ax.set_xticklabels([str(n) for n in RINGS])
    ax.set_xlim(110, 1100)
    if linear:
        ax.set_ylim(0, 76000)
        ax.yaxis.set_major_formatter(FuncFormatter(human))
        ax.annotate("Σ-protocol: Python and both Go curves\n(within 31 bytes, lines overlap)",
                    xy=(512, data["bn_sigma"]["bytes"][512]), xytext=(150, 48000),
                    fontsize=8.5, color=MUTED, arrowprops=dict(arrowstyle="-", color=MUTED, lw=0.8))
        bpp, sig = data["bn_bpp"]["bytes"][1024], data["bn_sigma"]["bytes"][1024]
        ax.annotate(f"BP++: {sig / bpp:.0f}x smaller at ring 1024\n(close to the paper)",
                    xy=(1024, bpp), xytext=(400, 16000),
                    fontsize=8.5, color=MUTED, arrowprops=dict(arrowstyle="-", color=MUTED, lw=0.8))
    else:
        ax.set_yscale("log")
        ax.yaxis.set_major_locator(LogLocator(base=10, subs=(1, 2, 5)))
        ax.yaxis.set_major_formatter(FuncFormatter(human))
        ax.yaxis.set_minor_formatter(NullFormatter())
    ax.set_xlabel("Ring size (members)", color=MUTED)
    ax.set_ylabel(ylabel, color=MUTED)
    ax.set_title(title, loc="left", color=INK, fontsize=12, pad=12)
    ax.grid(True, which="major", color=GRID, lw=0.8, zorder=0)
    ax.grid(False, which="minor")
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    for side in ("left", "bottom"):
        ax.spines[side].set_color(GRID)
    ax.tick_params(colors=MUTED, labelsize=9)
    ax.legend(loc="upper center", bbox_to_anchor=(0.5, -0.13), ncol=3, frameon=False,
              fontsize=8.5, labelcolor=INK)
    scale = "Linear y axis" if linear else "Log y axis"
    fig.text(0.01, 0.005, f"{scale}, ring size doubles per step. Ours: one core, 100 runs, Linux container. "
             "Paper: Table 3 (Apple M1) / Table 1 size model.", fontsize=7.5, color=MUTED)
    fig.subplots_adjust(left=0.09, right=0.97, top=0.9, bottom=0.25)
    OUT.mkdir(parents=True, exist_ok=True)
    path = OUT / fname
    fig.savefig(path)
    plt.close(fig)
    return path


def main() -> None:
    data = load()
    for args in [
        ("bytes", "Transaction size: BP++ closes most of the gap", "Bytes (2 inputs, 2 outputs)", "size_vs_paper.png"),
        ("spend", "Spend time: no version gets near the paper", "Milliseconds (mean)", "spend_vs_paper.png"),
        ("verify", "Verify time: the curve library matters most", "Milliseconds (mean)", "verify_vs_paper.png"),
    ]:
        print("wrote", chart(data, *args).relative_to(ROOT))


if __name__ == "__main__":
    main()
