"""Tests for plotting existing timing aggregates; no cryptographic work runs."""

from __future__ import annotations

import csv
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from eval import plot_results


FIELDS = [
    "ring_size", "target_repetitions", "attempted_repetitions",
    "successful_repetitions", "failed_repetitions", "unattempted_repetitions",
    "setup_failures", "spend_failures", "verify_failures", "rejected_verifications",
    "input_count", "output_count", "input_amounts", "output_amounts", "fee",
    "proof_backend", "spend_mean_ms", "spend_std_ms", "verify_mean_ms",
    "verify_std_ms", "status",
]
SIZE_FIELDS = sorted(plot_results.SIZE_REQUIRED_COLUMNS)


def sample_row(ring_size: int = 128, repetitions: int = 10) -> dict[str, str]:
    """Use fabricated aggregate values only to test CSV handling."""
    return {
        "ring_size": str(ring_size), "target_repetitions": str(repetitions),
        "attempted_repetitions": str(repetitions),
        "successful_repetitions": str(repetitions),
        "failed_repetitions": "0", "unattempted_repetitions": "0",
        "setup_failures": "0", "spend_failures": "0", "verify_failures": "0",
        "rejected_verifications": "0", "input_count": "2", "output_count": "2",
        "input_amounts": "60;40", "output_amounts": "60;39", "fee": "1",
        "proof_backend": "sigma_ring", "spend_mean_ms": "12.25",
        "spend_std_ms": "1.5", "verify_mean_ms": "4.75",
        "verify_std_ms": "0.25", "status": "complete",
    }


def make_csv(path: Path, rows: list[dict[str, str]],
             fields: list[str] | None = None) -> None:
    columns = FIELDS if fields is None else fields
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def sample_size_row(ring_size: int = 256) -> dict[str, str]:
    """Synthetic encoded lengths test parsing, not real transaction sizes."""
    row = {name: "0" for name in SIZE_FIELDS}
    row.update({
        "ring_size": str(ring_size), "target_repetitions": "10",
        "attempted_repetitions": "10", "successful_repetitions": "10",
        "proof_successful_repetitions": "10", "proof_backend": "sigma_ring",
        "serialization_format": "succinct-v1 (mock test encoding)",
        "input_count": "2", "output_count": "2",
        "input_amounts": "60;40", "output_amounts": "60;39", "fee": "1",
        "transaction_bytes_observations": ";".join(["100"] * 10),
        "transaction_bytes_mean": "100", "transaction_bytes_min": "100",
        "transaction_bytes_max": "100",
        "proof_bytes_observations": ";".join(["80"] * 10),
        "proof_bytes_mean": "80", "proof_bytes_min": "80",
        "proof_bytes_max": "80", "proof_size_status": "complete",
        "measurement_status": "complete", "blocker": "",
    })
    return row


def make_size_csv(path: Path, rows: list[dict[str, str]],
                  fields: list[str] | None = None) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=SIZE_FIELDS if fields is None else fields,
                                extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def test_loader_preserves_measured_aggregates_and_sorts_ring_sizes(tmp_path: Path) -> None:
    source = tmp_path / "input.csv"
    make_csv(source, [sample_row(256), sample_row(128)])

    rows = plot_results.load_timing_csv(source)

    assert [row.ring_size for row in rows] == [128, 256]
    assert [row.successful_repetitions for row in rows] == [10, 10]
    assert rows[0].spend_mean_ms == 12.25
    assert rows[0].spend_sample_std_ms == 1.5
    assert rows[0].verify_mean_ms == 4.75
    assert rows[0].verify_sample_std_ms == 0.25
    assert rows[0].proof_backend == "sigma_ring"
    assert "Python sigma_ring" in rows[0].measurement_source
    assert "not original paper Go timings" in rows[0].measurement_source


def test_loader_accepts_complete_100_run_timing_and_keeps_10_run_history(
    tmp_path: Path,
) -> None:
    source = tmp_path / "timing.csv"
    make_csv(source, [sample_row(256, 100), sample_row(128, 10)])

    rows = plot_results.load_timing_csv(source)

    assert [(row.ring_size, row.successful_repetitions) for row in rows] == [
        (128, 10), (256, 100),
    ]
    assert rows[1].spend_mean_ms == 12.25
    assert rows[1].spend_sample_std_ms == 1.5
    assert rows[1].verify_mean_ms == 4.75
    assert rows[1].verify_sample_std_ms == 0.25


def test_loader_rejects_missing_required_column(tmp_path: Path) -> None:
    source = tmp_path / "missing.csv"
    make_csv(source, [sample_row()], [name for name in FIELDS if name != "verify_std_ms"])
    with pytest.raises(ValueError, match="verify_std_ms"):
        plot_results.load_timing_csv(source)


def test_timing_loader_requires_fixture_metadata_columns(tmp_path: Path) -> None:
    source = tmp_path / "missing_fixture.csv"
    make_csv(source, [sample_row()], [name for name in FIELDS if name != "input_amounts"])
    with pytest.raises(ValueError, match="input_amounts"):
        plot_results.load_timing_csv(source)


@pytest.mark.parametrize("field,value", [
    ("ring_size", "one hundred"),
    ("ring_size", "1"),
    ("successful_repetitions", "ten"),
    ("successful_repetitions", ""),
    ("spend_mean_ms", ""),
    ("spend_mean_ms", "nan"),
    ("spend_mean_ms", "inf"),
    ("spend_mean_ms", "-1"),
    ("spend_std_ms", "-0.1"),
    ("verify_std_ms", "not a number"),
    ("proof_backend", "stub"),
    ("proof_backend", "bulletproofs++"),
    ("status", "partial"),
    ("target_repetitions", "100"),
    ("attempted_repetitions", "9"),
    ("successful_repetitions", "9"),
    ("failed_repetitions", "1"),
    ("unattempted_repetitions", "1"),
    ("setup_failures", "1"),
    ("spend_failures", "1"),
    ("verify_failures", "1"),
    ("rejected_verifications", "1"),
    ("input_count", "1"),
    ("output_count", "3"),
    ("input_amounts", "40;60"),
    ("output_amounts", "60;40"),
    ("fee", "2"),
])
def test_loader_rejects_bad_or_incomplete_rows(
    tmp_path: Path, field: str, value: str,
) -> None:
    source = tmp_path / "bad.csv"
    row = sample_row()
    row[field] = value
    make_csv(source, [row])
    with pytest.raises(ValueError):
        plot_results.load_timing_csv(source)


def test_loader_rejects_incomplete_100_run_timing(tmp_path: Path) -> None:
    source = tmp_path / "incomplete_100.csv"
    row = sample_row(repetitions=100)
    row["successful_repetitions"] = "99"
    row["failed_repetitions"] = "1"
    make_csv(source, [row])

    with pytest.raises(ValueError, match="incomplete or failed"):
        plot_results.load_timing_csv(source)


def test_loader_rejects_duplicate_sizes_empty_file_and_bad_width(tmp_path: Path) -> None:
    duplicate = tmp_path / "duplicate.csv"
    make_csv(duplicate, [sample_row(128), sample_row(128)])
    with pytest.raises(ValueError, match="unique"):
        plot_results.load_timing_csv(duplicate)

    empty = tmp_path / "empty.csv"
    make_csv(empty, [])
    with pytest.raises(ValueError, match="no benchmark rows"):
        plot_results.load_timing_csv(empty)

    malformed = tmp_path / "malformed.csv"
    malformed.write_text(",".join(FIELDS) + "\n" + ",".join(sample_row().values()) + ",extra\n",
                         encoding="utf-8")
    with pytest.raises(ValueError, match="malformed column count"):
        plot_results.load_timing_csv(malformed)


def test_summary_csv_preserves_values_and_backend(tmp_path: Path) -> None:
    source = tmp_path / "input.csv"
    summary = tmp_path / "summary.csv"
    make_csv(source, [sample_row()])
    original = source.read_bytes()

    plot_results.write_summary(summary, plot_results.load_timing_csv(source))

    with summary.open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        rows = list(reader)
        assert set(reader.fieldnames or []) == set(plot_results.TimingRow.__dataclass_fields__)
    assert len(rows) == 1
    assert rows[0]["ring_size"] == "128"
    assert rows[0]["successful_repetitions"] == "10"
    assert rows[0]["spend_mean_ms"] == "12.25"
    assert rows[0]["spend_sample_std_ms"] == "1.5"
    assert rows[0]["verify_mean_ms"] == "4.75"
    assert rows[0]["verify_sample_std_ms"] == "0.25"
    assert rows[0]["proof_backend"] == "sigma_ring"
    assert "not original paper Go timings" in rows[0]["measurement_source"]
    assert source.read_bytes() == original


def test_100_run_timing_summary_and_plot_caption_use_actual_counts(tmp_path: Path) -> None:
    source = tmp_path / "timing_100.csv"
    summary = tmp_path / "timing_summary.csv"
    make_csv(source, [sample_row(128, 100), sample_row(256, 100)])
    original = source.read_bytes()
    rows = plot_results.load_timing_csv(source)
    plot_results.write_summary(summary, rows)

    with summary.open(encoding="utf-8", newline="") as handle:
        records = list(csv.DictReader(handle))
    assert [record["successful_repetitions"] for record in records] == ["100", "100"]
    assert records[0]["spend_sample_std_ms"] == "1.5"
    assert records[0]["verify_sample_std_ms"] == "0.25"
    assert all(record["proof_backend"] == "sigma_ring" for record in records)

    figures = [MagicMock(), MagicMock()]
    plotting = MagicMock()
    plotting.subplots.side_effect = [(figures[0], MagicMock()),
                                     (figures[1], MagicMock())]
    plot_results.plot_timings(plotting, tmp_path, rows)

    for figure in figures:
        caption = figure.text.call_args.args[2]
        assert "128: n=100" in caption
        assert "256: n=100" in caption
        assert "not original paper Go timings" in caption
    assert source.read_bytes() == original


def test_plot_uses_recorded_means_and_sample_standard_deviations(tmp_path: Path) -> None:
    source = tmp_path / "input.csv"
    make_csv(source, [sample_row(128), sample_row(256)])
    rows = plot_results.load_timing_csv(source)
    axes = [MagicMock(), MagicMock()]
    figures = [MagicMock(), MagicMock()]
    plotting = MagicMock()
    plotting.subplots.side_effect = list(zip(figures, axes))

    plot_results.plot_timings(plotting, tmp_path, rows)

    assert axes[0].plot.call_count == 2
    assert axes[0].fill_between.call_count == 0
    assert axes[1].plot.call_count == 2
    assert axes[1].fill_between.call_count == 2
    assert axes[1].plot.call_args_list[0].args[:2] == ([128, 256], [12.25, 12.25])
    assert axes[1].plot.call_args_list[1].args[:2] == ([128, 256], [4.75, 4.75])
    assert axes[1].fill_between.call_args_list[0].args[:3] == (
        [128, 256], [10.75, 10.75], [13.75, 13.75],
    )
    assert axes[1].fill_between.call_args_list[1].args[:3] == (
        [128, 256], [4.5, 4.5], [5.0, 5.0],
    )
    assert "sample standard deviation" in axes[1].set_title.call_args.args[0]
    assert "not original paper Go timings" in figures[1].text.call_args.args[2]
    assert "n=10" in figures[1].text.call_args.args[2]


def test_cli_generates_two_plots_and_skips_unavailable_size_data(
    tmp_path: Path, capsys,
) -> None:
    pytest.importorskip("matplotlib")
    source = tmp_path / "input.csv"
    output_dir = tmp_path / "new_plots"
    make_csv(source, [sample_row(128), sample_row(256)])
    original = source.read_bytes()

    plot_results.main(["--input", str(source), "--output-dir", str(output_dir)])

    assert (output_dir / plot_results.SUMMARY_NAME).is_file()
    assert (output_dir / plot_results.MEANS_NAME).read_bytes().startswith(b"\x89PNG\r\n\x1a\n")
    assert (output_dir / plot_results.MEAN_STD_NAME).read_bytes().startswith(
        b"\x89PNG\r\n\x1a\n")
    assert sorted(path.name for path in output_dir.iterdir()) == sorted([
        plot_results.SUMMARY_NAME, plot_results.MEANS_NAME,
        plot_results.MEAN_STD_NAME,
    ])
    terminal = capsys.readouterr().out
    assert "Size-measurement plots skipped" in terminal
    assert "not original paper Go timings" in terminal
    assert source.read_bytes() == original


def test_cli_refuses_to_overwrite_source_or_existing_outputs(tmp_path: Path) -> None:
    source = tmp_path / plot_results.SUMMARY_NAME
    make_csv(source, [sample_row()])
    original = source.read_bytes()
    with pytest.raises(SystemExit) as error:
        plot_results.main(["--input", str(source), "--output-dir", str(tmp_path)])
    assert error.value.code == 2
    assert source.read_bytes() == original

    separate = tmp_path / "separate"
    separate.mkdir()
    (separate / plot_results.MEANS_NAME).write_bytes(b"keep")
    with pytest.raises(SystemExit) as error:
        plot_results.main(["--input", str(source), "--output-dir", str(separate)])
    assert error.value.code == 2
    assert (separate / plot_results.MEANS_NAME).read_bytes() == b"keep"


def test_size_loader_preserves_bytes_counts_and_format(tmp_path: Path) -> None:
    source = tmp_path / "size.csv"
    make_size_csv(source, [sample_size_row(512), sample_size_row(256)])

    rows = plot_results.load_size_csv(source)

    assert [row.ring_size for row in rows] == [256, 512]
    assert [row.successful_repetitions for row in rows] == [10, 10]
    assert rows[0].transaction_bytes_mean == 100
    assert rows[0].proof_bytes_mean == 80
    assert rows[0].proof_backend == "sigma_ring"
    assert rows[0].serialization_format.startswith("succinct-v1")
    assert "Measured Python sigma_ring" in rows[0].measurement_source


def test_size_loader_rejects_missing_column(tmp_path: Path) -> None:
    source = tmp_path / "missing.csv"
    make_size_csv(source, [sample_size_row()],
                  [field for field in SIZE_FIELDS if field != "proof_bytes_mean"])
    with pytest.raises(ValueError, match="proof_bytes_mean"):
        plot_results.load_size_csv(source)


def test_size_loader_rejects_three_successful_measurements(tmp_path: Path) -> None:
    source = tmp_path / "size_3.csv"
    row = sample_size_row()
    for name in ("target_repetitions", "attempted_repetitions",
                 "successful_repetitions", "proof_successful_repetitions"):
        row[name] = "3"
    row["transaction_bytes_observations"] = "100;100;100"
    row["proof_bytes_observations"] = "80;80;80"
    make_size_csv(source, [row])

    with pytest.raises(ValueError, match="expected ten completed"):
        plot_results.load_size_csv(source)


@pytest.mark.parametrize("field,value", [
    ("target_repetitions", "100"),
    ("attempted_repetitions", "9"),
    ("successful_repetitions", "9"),
    ("proof_successful_repetitions", "9"),
    ("failed_repetitions", "1"),
    ("proof_serialization_failures", "1"),
    ("measurement_status", "partial"),
    ("proof_size_status", "partial"),
    ("blocker", "serializer incomplete"),
    ("proof_backend", "stub"),
    ("serialization_format", "unknown"),
    ("input_count", "1"),
    ("output_count", "3"),
    ("input_amounts", "40;60"),
    ("output_amounts", "60;40"),
    ("fee", "2"),
    ("transaction_bytes_observations", "100;100"),
    ("proof_bytes_observations", ";".join(["101"] * 10)),
    ("transaction_bytes_mean", "101"),
    ("proof_bytes_max", "81"),
])
def test_size_loader_rejects_incomplete_or_inconsistent_rows(
    tmp_path: Path, field: str, value: str,
) -> None:
    source = tmp_path / "bad_size.csv"
    row = sample_size_row()
    row[field] = value
    make_size_csv(source, [row])
    with pytest.raises(ValueError):
        plot_results.load_size_csv(source)


def test_size_summary_uses_only_measured_bytes_and_preserves_source(tmp_path: Path) -> None:
    source = tmp_path / "size.csv"
    summary = tmp_path / "summary.csv"
    make_size_csv(source, [sample_size_row()])
    original = source.read_bytes()

    plot_results.write_size_summary(summary, plot_results.load_size_csv(source))

    with summary.open(encoding="utf-8", newline="") as handle:
        records = list(csv.DictReader(handle))
    assert len(records) == 1
    assert records[0]["successful_repetitions"] == "10"
    assert records[0]["transaction_bytes_mean"] == "100.0"
    assert records[0]["proof_bytes_mean"] == "80.0"
    assert records[0]["proof_backend"] == "sigma_ring"
    assert records[0]["serialization_format"].startswith("succinct-v1")
    assert "paper" not in records[0]["measurement_source"].lower()
    assert source.read_bytes() == original


def test_size_plot_separates_contained_proof_and_paper_model(tmp_path: Path) -> None:
    source = tmp_path / "size.csv"
    make_size_csv(source, [sample_size_row(256)])
    rows = plot_results.load_size_csv(source)
    assert plot_results.paper_size_totals(rows) == [2224]
    axes = [MagicMock(), MagicMock()]
    figures = [MagicMock(), MagicMock()]
    plotting = MagicMock()
    plotting.subplots.side_effect = list(zip(figures, axes))

    plot_results.plot_sizes(plotting, tmp_path, rows)

    assert axes[0].plot.call_args_list[0].args[:2] == ([256], [100])
    assert axes[0].plot.call_args_list[1].args[:2] == ([256], [80])
    assert axes[1].plot.call_args_list[0].args[:2] == ([256], [2224])
    assert axes[1].plot.call_args_list[1].args[:2] == ([256], [100])
    assert "Bulletproofs++" in axes[1].plot.call_args_list[0].kwargs["label"]
    assert "sigma_ring" in axes[1].plot.call_args_list[1].kwargs["label"]
    assert "already included" in figures[0].text.call_args.args[2]
    assert "256: n=10" in figures[0].text.call_args.args[2]
    assert "Not equivalent implementations" in figures[1].text.call_args.args[2]
    assert "256: n=10" in figures[1].text.call_args.args[2]


def test_size_only_cli_preserves_existing_timing_outputs_and_both_sources(
    tmp_path: Path, capsys,
) -> None:
    pytest.importorskip("matplotlib")
    size_source = tmp_path / "size.csv"
    timing_source = tmp_path / "time.csv"
    make_size_csv(size_source, [sample_size_row(256)])
    make_csv(timing_source, [sample_row(256)])
    size_original, timing_original = size_source.read_bytes(), timing_source.read_bytes()
    output_dir = tmp_path / "outputs"
    output_dir.mkdir()
    old_timing = output_dir / plot_results.MEANS_NAME
    old_timing.write_bytes(b"keep old timing result")

    plot_results.main(["--size-only", "--size-input", str(size_source),
                       "--input", str(timing_source), "--output-dir", str(output_dir)])

    assert old_timing.read_bytes() == b"keep old timing result"
    assert (output_dir / plot_results.SIZE_SUMMARY_NAME).is_file()
    assert (output_dir / plot_results.SIZE_PLOT_NAME).read_bytes().startswith(b"\x89PNG")
    assert (output_dir / plot_results.SIZE_COMPARISON_NAME).read_bytes().startswith(b"\x89PNG")
    assert size_source.read_bytes() == size_original
    assert timing_source.read_bytes() == timing_original
    terminal = capsys.readouterr().out
    assert "Proof bytes are contained" in terminal
    assert "Bulletproofs++" in terminal and "sigma_ring" in terminal


def test_combined_cli_writes_timing_and_size_outputs_to_new_directory(tmp_path: Path) -> None:
    pytest.importorskip("matplotlib")
    timing_source = tmp_path / "time.csv"
    size_source = tmp_path / "size.csv"
    output_dir = tmp_path / "combined"
    make_csv(timing_source, [sample_row(256)])
    make_size_csv(size_source, [sample_size_row(256)])
    original_timing = timing_source.read_bytes()
    original_size = size_source.read_bytes()

    plot_results.main(["--input", str(timing_source), "--size-input", str(size_source),
                       "--output-dir", str(output_dir)])

    assert sorted(path.name for path in output_dir.iterdir()) == sorted([
        plot_results.SUMMARY_NAME, plot_results.MEANS_NAME, plot_results.MEAN_STD_NAME,
        plot_results.SIZE_SUMMARY_NAME, plot_results.SIZE_PLOT_NAME,
        plot_results.SIZE_COMPARISON_NAME,
    ])
    assert timing_source.read_bytes() == original_timing
    assert size_source.read_bytes() == original_size


def test_combined_cli_accepts_100_timing_and_10_size_runs(
    tmp_path: Path, capsys,
) -> None:
    pytest.importorskip("matplotlib")
    timing_source = tmp_path / "timing_100.csv"
    size_source = tmp_path / "size_10.csv"
    output_dir = tmp_path / "final_plots"
    make_csv(timing_source, [sample_row(128, 100), sample_row(256, 100)])
    make_size_csv(size_source, [sample_size_row(128), sample_size_row(256)])
    originals = (timing_source.read_bytes(), size_source.read_bytes())

    plot_results.main(["--input", str(timing_source), "--size-input", str(size_source),
                       "--output-dir", str(output_dir)])

    with (output_dir / plot_results.SUMMARY_NAME).open(encoding="utf-8", newline="") as handle:
        timing_records = list(csv.DictReader(handle))
    with (output_dir / plot_results.SIZE_SUMMARY_NAME).open(encoding="utf-8", newline="") as handle:
        size_records = list(csv.DictReader(handle))
    assert [row["successful_repetitions"] for row in timing_records] == ["100", "100"]
    assert [row["successful_repetitions"] for row in size_records] == ["10", "10"]
    assert (output_dir / plot_results.MEANS_NAME).read_bytes().startswith(b"\x89PNG")
    assert (output_dir / plot_results.SIZE_COMPARISON_NAME).read_bytes().startswith(b"\x89PNG")
    terminal = capsys.readouterr().out
    assert "128: n=100" in terminal and "256: n=100" in terminal
    assert "128: n=10" in terminal and "256: n=10" in terminal
    assert (timing_source.read_bytes(), size_source.read_bytes()) == originals


def test_size_only_requires_input_and_refuses_existing_size_output(tmp_path: Path) -> None:
    with pytest.raises(SystemExit) as error:
        plot_results.main(["--size-only", "--output-dir", str(tmp_path)])
    assert error.value.code == 2

    source = tmp_path / "size.csv"
    make_size_csv(source, [sample_size_row()])
    existing = tmp_path / plot_results.SIZE_PLOT_NAME
    existing.write_bytes(b"keep")
    with pytest.raises(SystemExit) as error:
        plot_results.main(["--size-only", "--size-input", str(source),
                           "--output-dir", str(tmp_path)])
    assert error.value.code == 2
    assert existing.read_bytes() == b"keep"
