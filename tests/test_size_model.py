"""Paper-anchored checks for the deterministic Table 1 size model.

Figure 1 totals come from the labels in the SuccinCT paper, not from
recalculating the implementation's formulas inside these tests.
"""

from __future__ import annotations

import builtins
import csv
from pathlib import Path

import pytest

from eval import size_model


# Figure 1, R=256, S=T=2, |G|=32 bytes, beta=64 bits, |I|=4 bytes.
# The ZGSX23 total includes the paper's explicitly conjectured output size.
PAPER_FIGURE1_TOTALS = {
    "CLSAG": 34832,
    "RingCT 3.0": 2928,
    "Omniring": 2560,
    "ZGSX23": 10256,
    "BulletCT": 2480,
    "SuccinCT": 2224,
}


def read_csv(path: Path) -> tuple[list[str], list[dict[str, str]]]:
    """Read a generated CSV with the standard library."""
    with path.open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        return list(reader.fieldnames or []), list(reader)


@pytest.mark.parametrize("protocol,expected", PAPER_FIGURE1_TOTALS.items())
def test_figure1_matches_paper_labels(protocol: str, expected: int) -> None:
    rows = size_model.estimate_sizes(256, "Figure 1", "Paper caption")
    by_protocol = {row.protocol: row for row in rows}

    assert len(rows) == 6
    assert by_protocol[protocol].total_bytes == expected
    assert by_protocol[protocol].ring_size == 256
    assert (by_protocol[protocol].input_count, by_protocol[protocol].output_count) == (2, 2)
    assert (by_protocol[protocol].group_bytes, by_protocol[protocol].amount_bits) == (32, 64)
    assert by_protocol[protocol].reference_bytes == 4


def test_figure1_components_match_paper_breakdown() -> None:
    rows = size_model.estimate_sizes(256, "Figure 1", "Paper caption")
    by_protocol = {row.protocol: row for row in rows}

    # These are byte counts at the paper's fixed Figure 1 parameters.
    # They independently check the Table 1 categories and units.
    assert {row.input_reference_bytes for row in rows} == {1024}
    assert {row.key_image_bytes for row in rows if row.protocol != "ZGSX23"} == {64}
    assert by_protocol["ZGSX23"].key_image_bytes == 8192
    assert {row.output_bytes for row in rows if row.protocol != "Omniring"} == {176}
    assert by_protocol["Omniring"].output_bytes == 544
    assert {name: row.proof_bytes for name, row in by_protocol.items()} == {
        "CLSAG": 33568,
        "RingCT 3.0": 1664,
        "Omniring": 928,
        "ZGSX23": 864,
        "BulletCT": 1216,
        "SuccinCT": 960,
    }


@pytest.mark.parametrize("ring_size", [2, 128, 256, 1024])
def test_total_is_sum_of_four_components(ring_size: int) -> None:
    for row in size_model.estimate_sizes(ring_size, "Figure 7", "Selected grid"):
        assert row.total_bytes == sum((
            row.input_reference_bytes,
            row.key_image_bytes,
            row.proof_bytes,
            row.output_bytes,
        ))
        assert all(value >= 0 for value in (
            row.input_reference_bytes,
            row.key_image_bytes,
            row.proof_bytes,
            row.output_bytes,
        ))


def test_figure7_custom_grid_has_six_rows_per_ring_size(tmp_path: Path) -> None:
    output_dir = tmp_path / "figure7"
    size_model.main([
        "--csv-only", "--output-dir", str(output_dir),
        "--ring-sizes", "1024", "128", "256",
    ])
    _, rows = read_csv(output_dir / "figure7_paper_size_model.csv")

    assert len(rows) == 18
    assert {int(row["ring_size"]) for row in rows} == {128, 256, 1024}
    assert all(sum(row["protocol"] == name for row in rows) == 3
               for name in PAPER_FIGURE1_TOTALS)
    assert all(row["input_count"] == "2" and row["output_count"] == "2" for row in rows)
    assert all(row["figure"] == "Figure 7" for row in rows)
    assert all("User-selected grid" in row["sampling_note"] for row in rows)
    # Independent hand calculations for the SuccinCT Figure 7 curve.
    assert {int(row["ring_size"]): int(row["total_bytes"])
            for row in rows if row["protocol"] == "SuccinCT"} == {
                128: 1648,
                256: 2224,
                1024: 5424,
            }


def test_csv_headers_and_figure1_data(tmp_path: Path) -> None:
    output_dir = tmp_path / "exports"
    size_model.main(["--csv-only", "--output-dir", str(output_dir)])
    headers, rows = read_csv(output_dir / "figure1_paper_size_model.csv")
    expected_headers = {
        "figure", "protocol", "ring_size", "input_count", "output_count",
        "group_bytes", "amount_bits", "reference_bytes", "input_reference_bytes",
        "key_image_bytes", "proof_bytes", "table1_output_bytes", "output_bytes",
        "total_bytes", "output_status", "estimate_kind", "sampling_note", "source",
    }

    assert set(headers) == expected_headers
    assert len(rows) == 6
    assert {row["protocol"]: int(row["total_bytes"]) for row in rows} == PAPER_FIGURE1_TOTALS
    assert all(row["figure"] == "Figure 1" and row["ring_size"] == "256" for row in rows)
    assert all("paper analytical estimate" in row["estimate_kind"] for row in rows)
    assert all("not measured Python transaction bytes" in row["estimate_kind"] for row in rows)
    assert all("Table 1" in row["source"] for row in rows)

    figure7_headers, figure7_rows = read_csv(output_dir / "figure7_paper_size_model.csv")
    assert figure7_headers == headers
    assert len(figure7_rows) == 24
    assert {int(row["ring_size"]) for row in figure7_rows} == {128, 256, 512, 1024}


def test_changing_seed_does_not_change_model_csv(tmp_path: Path) -> None:
    first = tmp_path / "seed_1"
    second = tmp_path / "seed_2"
    size_model.main(["--csv-only", "--seed", "1", "--output-dir", str(first)])
    size_model.main(["--csv-only", "--seed", "999", "--output-dir", str(second)])

    for filename in ("figure1_paper_size_model.csv", "figure7_paper_size_model.csv"):
        assert (first / filename).read_bytes() == (second / filename).read_bytes()


def test_csv_only_does_not_import_matplotlib(tmp_path: Path, monkeypatch) -> None:
    original_import = builtins.__import__
    attempted_imports: list[str] = []

    def reject_matplotlib(name, *args, **kwargs):
        if name == "matplotlib" or name.startswith("matplotlib."):
            attempted_imports.append(name)
            raise AssertionError("CSV-only mode attempted to import matplotlib")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", reject_matplotlib)
    output_dir = tmp_path / "csv_only"
    size_model.main(["--csv-only", "--output-dir", str(output_dir)])

    assert attempted_imports == []
    assert (output_dir / "figure1_paper_size_model.csv").is_file()
    assert (output_dir / "figure7_paper_size_model.csv").is_file()
    assert list(output_dir.glob("*.png")) == []


@pytest.mark.parametrize("value,expected", [(1, 0), (2, 1), (3, 2), (256, 8), (257, 9)])
def test_ceil_log2_integer_boundaries(value: int, expected: int) -> None:
    assert size_model.ceil_log2(value) == expected


@pytest.mark.parametrize("value", [0, -1])
def test_ceil_log2_rejects_nonpositive_parameter(value: int) -> None:
    with pytest.raises(ValueError, match="positive"):
        size_model.ceil_log2(value)


@pytest.mark.parametrize("ring_size", [0, 1, -8])
def test_estimate_sizes_rejects_invalid_ring_size(ring_size: int) -> None:
    with pytest.raises(ValueError, match="at least"):
        size_model.estimate_sizes(ring_size, "Figure 7", "Invalid grid")


@pytest.mark.parametrize("invalid_args", [
    ["--ring-sizes", "1"],
    ["--ring-sizes", "0", "256"],
    ["--ring-sizes", "not-an-integer"],
    ["--seed", "not-an-integer"],
])
def test_cli_rejects_invalid_parameters_without_writing_files(
    tmp_path: Path, invalid_args: list[str],
) -> None:
    output_dir = tmp_path / "invalid"
    with pytest.raises(SystemExit) as error:
        size_model.main(["--csv-only", "--output-dir", str(output_dir), *invalid_args])

    assert error.value.code == 2
    assert not output_dir.exists()


def test_zgsx23_output_is_explicitly_a_conjecture(tmp_path: Path) -> None:
    row = next(row for row in size_model.estimate_sizes(256, "Figure 1", "Paper caption")
               if row.protocol == "ZGSX23")
    assert row.table1_output_bytes is None
    assert row.output_bytes == 176
    assert "Table 1 output unknown" in row.output_status
    assert "conjectures" in row.output_status

    output_dir = tmp_path / "zgsx23"
    size_model.main(["--csv-only", "--output-dir", str(output_dir)])
    _, rows = read_csv(output_dir / "figure1_paper_size_model.csv")
    csv_row = next(item for item in rows if item["protocol"] == "ZGSX23")
    assert csv_row["table1_output_bytes"] == ""
    assert csv_row["output_bytes"] == "176"
    assert "conjectures" in csv_row["output_status"]
    assert all(item["table1_output_bytes"] == item["output_bytes"]
               for item in rows if item["protocol"] != "ZGSX23")
