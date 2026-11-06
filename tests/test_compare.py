"""eval.compare: lines our CSVs up against the paper's numbers correctly."""

import csv

import pytest

from eval import compare


def _write(path, rows):
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    return path


@pytest.fixture
def inputs(tmp_path):
    rings = (128, 256, 512, 1024)
    time = _write(tmp_path / "time.csv", [
        {"ring_size": n, "status": "complete", "spend_mean_ms": 100 * i,
         "spend_std_ms": 1, "verify_mean_ms": 50 * i, "verify_std_ms": 1}
        for i, n in enumerate(rings, start=1)])
    size = _write(tmp_path / "size.csv", [
        {"ring_size": n, "measurement_status": "complete",
         "transaction_bytes_mean": 10 * n, "proof_bytes_mean": 9 * n}
        for n in rings])
    model = _write(tmp_path / "model.csv", [
        {"protocol": p, "ring_size": n, "total_bytes": base + n}
        for n in rings for p, base in (("SuccinCT", 1000), ("BulletCT", 2000), ("CLSAG", 0))])
    return time, size, model


def test_rows_join_on_ring_size(inputs):
    table = compare.load(*inputs)
    assert [r["ring_size"] for r in table] == [128, 256, 512, 1024]
    first = table[0]
    assert first["ours_spend_ms"] == 100
    assert first["paper_spend_ms"] == compare.PAPER_TABLE3_MS[128][0]
    assert first["paper_succinct_tx_bytes"] == 1128
    assert first["paper_bulletct_tx_bytes"] == 2128
    assert first["ours_tx_bytes"] == 1280
    assert first["spend_ratio_ours_over_paper"] == round(100 / compare.PAPER_TABLE3_MS[128][0], 1)


def test_incomplete_rows_are_skipped(inputs, tmp_path):
    time, size, model = inputs
    rows = list(csv.DictReader(open(time)))
    rows[0]["status"] = "partial"
    _write(time, rows)
    assert [r["ring_size"] for r in compare.load(time, size, model)] == [256, 512, 1024]


def test_no_overlap_is_an_error(tmp_path, inputs):
    _, size, model = inputs
    quick = _write(tmp_path / "quick.csv", [
        {"ring_size": 8, "status": "complete", "spend_mean_ms": 1,
         "spend_std_ms": 0, "verify_mean_ms": 1, "verify_std_ms": 0}])
    with pytest.raises(SystemExit):
        compare.load(quick, size, model)


def test_baseline_is_optional(inputs, tmp_path):
    time, size, model = inputs
    assert "purepython_spend_ms" not in compare.load(time, size, model)[0]
    with_base = compare.load(time, size, model, baseline_path=time)
    assert with_base[0]["purepython_spend_ms"] == 100


def test_outputs_written(inputs, tmp_path):
    table = compare.load(*inputs)
    compare.write_csv(table, tmp_path / "c.csv")
    compare.write_markdown(table, tmp_path / "c.md")
    md = (tmp_path / "c.md").read_text()
    assert "| 1024 |" in md and "Growth from ring 128 to 1024" in md
    assert len(list(csv.DictReader(open(tmp_path / "c.csv")))) == 4
