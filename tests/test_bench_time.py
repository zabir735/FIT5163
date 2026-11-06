"""Mock-based checks for the timing harness; no cryptography is executed."""

from __future__ import annotations

import csv
import itertools
from pathlib import Path
from types import SimpleNamespace

import pytest

from eval import bench_time
from succinct.nizk import stub


def prepared_fixture() -> bench_time.PreparedSpend:
    """Return identity-only stand-ins for the already prepared API inputs."""
    return bench_time.PreparedSpend(
        chain=object(), ring=[object()], inputs=[object()],
        outputs=[object()], info=object(), fee=1,
    )


def read_csv(path: Path) -> tuple[list[str], list[dict[str, str]]]:
    with path.open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        return list(reader.fieldnames or []), list(reader)


@pytest.mark.parametrize("args", [
    ["--ring-sizes", "0"],
    ["--ring-sizes", "1"],
    ["--ring-sizes", "8", "8"],
    ["--ring-sizes", "not-an-integer"],
    ["--repetitions", "0"],
    ["--repetitions", "-1"],
    ["--repetitions", "not-an-integer"],
    ["--seed", "not-an-integer"],
    ["--smoke", "--ring-sizes", "8"],
    ["--smoke", "--repetitions", "1"],
])
def test_cli_rejects_invalid_parameters_without_writing_csv(
    tmp_path: Path, args: list[str],
) -> None:
    output = tmp_path / "invalid.csv"
    with pytest.raises(SystemExit) as error:
        bench_time.main(["--output", str(output), *args])
    assert error.value.code == 2
    assert not output.exists()


def test_default_cli_requests_paper_ring_sizes_and_100_pairs(tmp_path: Path, monkeypatch) -> None:
    calls = []
    written = []

    def fake_benchmark(ring_size, repetitions, seed, *, backend):
        assert backend is bench_time.sigma_ring
        calls.append((ring_size, repetitions, seed))
        return SimpleNamespace(
            ring_size=ring_size, target_repetitions=repetitions,
            attempted_repetitions=repetitions, successful_repetitions=repetitions,
            failed_repetitions=0, unattempted_repetitions=0,
            spend_mean_ms=1.0, verify_mean_ms=2.0, status="complete",
        )

    monkeypatch.setattr(bench_time, "benchmark_ring", fake_benchmark)
    monkeypatch.setattr(bench_time, "write_csv", lambda path, rows: written.append((path, rows)))
    output = tmp_path / "default.csv"
    bench_time.main(["--output", str(output)])

    assert calls == [(128, 100, 5163), (256, 100, 5163),
                     (512, 100, 5163), (1024, 100, 5163)]
    assert len(written) == 1
    assert written[0][0] == output
    assert len(written[0][1]) == 4


@pytest.mark.parametrize("ring_size,repetitions", [(1, 1), (0, 1), (4, 0), (4, -1),
                                                     (2.5, 1), (4, True)])
def test_api_rejects_invalid_sizes_and_counts(ring_size, repetitions) -> None:
    with pytest.raises(ValueError):
        bench_time.benchmark_ring(ring_size, repetitions, seed=1)


def test_statistics_use_actual_nanoseconds_and_sample_std() -> None:
    stats = bench_time.summarize_ns([1_000_000, 3_000_000, 5_000_000])
    assert stats.mean_ms == pytest.approx(3)
    assert stats.std_ms == pytest.approx(2)
    assert stats.min_ms == pytest.approx(1)
    assert stats.max_ms == pytest.approx(5)

    one = bench_time.summarize_ns([7_000_000])
    assert (one.mean_ms, one.min_ms, one.max_ms) == (7, 7, 7)
    assert one.std_ms is None
    empty = bench_time.summarize_ns([])
    assert (empty.mean_ms, empty.std_ms, empty.min_ms, empty.max_ms) == (
        None, None, None, None,
    )


def test_explicit_backend_rejects_stub_before_setup(monkeypatch) -> None:
    def forbidden_setup(*args, **kwargs):
        raise AssertionError("Fixture setup must not run for a forbidden backend")

    monkeypatch.setattr(bench_time, "prepare_spend", forbidden_setup)
    with pytest.raises(ValueError, match="sigma_ring"):
        bench_time.benchmark_ring(4, 1, 5163, backend=stub)


def test_mock_call_flow_times_only_spend_and_verify(monkeypatch) -> None:
    events: list[str] = []
    fixture = prepared_fixture()
    tx, sig = object(), object()

    def fake_prepare(ring_size, seed):
        assert (ring_size, seed) == (4, 12)
        events.append("prepare")
        return fixture

    def fake_clock():
        events.append("clock")
        return {1: 0, 2: 1_000_000, 3: 2_000_000, 4: 5_000_000}[
            events.count("clock")
        ]

    def fake_spend(ring, inputs, outputs, info, fee, *, nizk):
        assert (ring, inputs, outputs, info, fee) == (
            fixture.ring, fixture.inputs, fixture.outputs, fixture.info, fixture.fee,
        )
        assert nizk is bench_time.sigma_ring
        events.append("spend")
        return tx, sig

    def fake_verify(actual_tx, actual_sig, chain, *, nizk):
        assert (actual_tx, actual_sig, chain) == (tx, sig, fixture.chain)
        assert nizk is bench_time.sigma_ring
        events.append("verify")
        return True

    monkeypatch.setattr(bench_time, "prepare_spend", fake_prepare)
    monkeypatch.setattr(bench_time.time, "perf_counter_ns", fake_clock)
    monkeypatch.setattr(bench_time.ct, "spend", fake_spend)
    monkeypatch.setattr(bench_time.ct, "verify", fake_verify)

    row = bench_time.benchmark_ring(4, 1, 12, backend=bench_time.sigma_ring)

    assert events == ["prepare", "clock", "spend", "clock", "clock", "verify", "clock"]
    assert row.proof_backend == "sigma_ring"
    assert (row.target_repetitions, row.attempted_repetitions,
            row.successful_repetitions, row.failed_repetitions,
            row.unattempted_repetitions) == (1, 1, 1, 0, 0)
    assert row.spend_mean_ms == pytest.approx(1)
    assert row.verify_mean_ms == pytest.approx(3)
    assert row.spend_std_ms is None and row.verify_std_ms is None
    assert row.status == "complete"


def test_failures_are_counted_and_excluded_from_both_statistics(monkeypatch) -> None:
    monkeypatch.setattr(bench_time, "prepare_spend", lambda *args: prepared_fixture())
    ticks = itertools.count(step=1_000_000)
    monkeypatch.setattr(bench_time.time, "perf_counter_ns", lambda: next(ticks))
    spend_calls = verify_calls = 0

    def fake_spend(*args, nizk):
        nonlocal spend_calls
        assert nizk is bench_time.sigma_ring
        spend_calls += 1
        if spend_calls == 2:
            raise RuntimeError("mock Spend failure")
        return object(), object()

    def fake_verify(*args, nizk):
        nonlocal verify_calls
        assert nizk is bench_time.sigma_ring
        verify_calls += 1
        if verify_calls == 2:
            return False
        if verify_calls == 3:
            raise RuntimeError("mock Verify failure")
        return True

    monkeypatch.setattr(bench_time.ct, "spend", fake_spend)
    monkeypatch.setattr(bench_time.ct, "verify", fake_verify)
    row = bench_time.benchmark_ring(4, 5, 5163)

    assert (spend_calls, verify_calls) == (5, 4)
    assert (row.target_repetitions, row.attempted_repetitions,
            row.successful_repetitions, row.failed_repetitions,
            row.unattempted_repetitions) == (5, 5, 2, 3, 0)
    assert (row.setup_failures, row.spend_failures, row.verify_failures,
            row.rejected_verifications) == (0, 1, 1, 1)
    assert row.spend_mean_ms == pytest.approx(1)
    assert row.verify_mean_ms == pytest.approx(1)
    assert row.spend_std_ms == pytest.approx(0)
    assert row.verify_std_ms == pytest.approx(0)
    assert row.status == "partial"


def test_setup_failure_does_not_claim_attempted_measurements(monkeypatch) -> None:
    def fail_setup(*args):
        raise RuntimeError("mock setup failure")

    monkeypatch.setattr(bench_time, "prepare_spend", fail_setup)
    row = bench_time.benchmark_ring(8, 3, 5163)

    assert (row.target_repetitions, row.attempted_repetitions,
            row.successful_repetitions, row.failed_repetitions,
            row.unattempted_repetitions) == (3, 0, 0, 0, 3)
    assert row.setup_failures == 1
    assert row.spend_mean_ms is None and row.verify_mean_ms is None
    assert row.status == "setup_failed"


def test_smoke_cli_exports_csv_schema_with_mocked_calls(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(bench_time, "prepare_spend", lambda *args: prepared_fixture())
    ticks = itertools.count(step=2_000_000)
    monkeypatch.setattr(bench_time.time, "perf_counter_ns", lambda: next(ticks))

    def fake_spend(*args, nizk):
        assert nizk is bench_time.sigma_ring
        return object(), object()

    def fake_verify(*args, nizk):
        assert nizk is bench_time.sigma_ring
        return True

    monkeypatch.setattr(bench_time.ct, "spend", fake_spend)
    monkeypatch.setattr(bench_time.ct, "verify", fake_verify)
    output = tmp_path / "mock_bench_time.csv"
    bench_time.main(["--smoke", "--seed", "7", "--output", str(output)])
    headers, rows = read_csv(output)

    assert len(rows) == 1
    row = rows[0]
    assert {"ring_size", "target_repetitions", "attempted_repetitions",
            "successful_repetitions", "failed_repetitions", "unattempted_repetitions",
            "proof_backend", "python_version", "operating_system", "os_release",
            "cpu", "machine", "seed", "threads", "input_count", "output_count",
            "input_amounts", "output_amounts", "fee", "spend_mean_ms",
            "spend_std_ms", "spend_min_ms", "spend_max_ms", "verify_mean_ms",
            "verify_std_ms", "verify_min_ms", "verify_max_ms", "status",
            "timing_scope"}.issubset(headers)
    assert row["ring_size"] == "4"
    assert row["target_repetitions"] == "1"
    assert row["attempted_repetitions"] == "1"
    assert row["successful_repetitions"] == "1"
    assert row["failed_repetitions"] == "0"
    assert row["proof_backend"] == "sigma_ring"
    assert row["seed"] == "7"
    assert row["spend_mean_ms"] == "2.0"
    assert row["verify_mean_ms"] == "2.0"
    assert row["spend_std_ms"] == "" and row["verify_std_ms"] == ""
    assert row["status"] == "complete"
    assert row["python_version"] and row["operating_system"]


def test_incomplete_cli_keeps_csv_and_reports_failure(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(bench_time, "prepare_spend", lambda *args: prepared_fixture())
    monkeypatch.setattr(bench_time.ct, "spend", lambda *args, **kwargs: (object(), object()))
    monkeypatch.setattr(bench_time.ct, "verify", lambda *args, **kwargs: False)
    ticks = itertools.count(step=1_000_000)
    monkeypatch.setattr(bench_time.time, "perf_counter_ns", lambda: next(ticks))
    output = tmp_path / "failed.csv"

    with pytest.raises(SystemExit, match="Benchmark incomplete"):
        bench_time.main(["--smoke", "--output", str(output)])
    _, rows = read_csv(output)
    assert rows[0]["target_repetitions"] == "1"
    assert rows[0]["successful_repetitions"] == "0"
    assert rows[0]["failed_repetitions"] == "1"
    assert rows[0]["rejected_verifications"] == "1"
    assert rows[0]["spend_mean_ms"] == ""
    assert rows[0]["verify_mean_ms"] == ""


def test_progress_surrounds_calls_and_every_message_is_flushed(monkeypatch) -> None:
    events = []
    fixture = prepared_fixture()
    ticks = iter((0, 1_000_000, 2_000_000, 5_000_000))

    def fake_print(*args, **kwargs):
        events.append(("print", " ".join(map(str, args)), kwargs.get("flush")))

    def fake_spend(*args, nizk):
        assert nizk is bench_time.sigma_ring
        events.append(("spend",))
        return object(), object()

    def fake_verify(*args, nizk):
        assert nizk is bench_time.sigma_ring
        events.append(("verify",))
        return True

    monkeypatch.setattr(bench_time, "prepare_spend", lambda *args: fixture)
    monkeypatch.setattr(bench_time.time, "perf_counter_ns", lambda: next(ticks))
    monkeypatch.setattr(bench_time.ct, "spend", fake_spend)
    monkeypatch.setattr(bench_time.ct, "verify", fake_verify)
    with monkeypatch.context() as printing:
        printing.setattr("builtins.print", fake_print)
        row = bench_time.benchmark_ring(4, 1, 5163)

    assert row.successful_repetitions == 1
    assert [event[0] for event in events] == ["print", "print", "spend", "verify", "print"]
    messages = [event for event in events if event[0] == "print"]
    assert all(event[2] is True for event in messages)
    assert "Ring 4: starting 1 repetitions" in messages[0][1]
    assert "Ring 4 repetition 1/1: starting" in messages[1][1]
    assert "Spend=1.000 ms" in messages[2][1]
    assert "Verify=3.000 ms" in messages[2][1]
    assert "status=success" in messages[2][1]


def test_quiet_hides_repetition_progress_but_keeps_summary(
    tmp_path: Path, monkeypatch, capsys,
) -> None:
    monkeypatch.setattr(bench_time, "prepare_spend", lambda *args: prepared_fixture())
    monkeypatch.setattr(bench_time.ct, "spend", lambda *args, **kwargs: (object(), object()))
    monkeypatch.setattr(bench_time.ct, "verify", lambda *args, **kwargs: True)
    ticks = itertools.count(step=1_000_000)
    monkeypatch.setattr(bench_time.time, "perf_counter_ns", lambda: next(ticks))
    output = tmp_path / "quiet.csv"

    bench_time.main(["--smoke", "--quiet", "--output", str(output)])
    terminal = capsys.readouterr().out
    _, rows = read_csv(output)

    assert "Ring 4: starting 1 repetitions." in terminal
    assert "Ring 4 complete: target=1, attempted=1, successful=1, failed=0, unattempted=0" in terminal
    assert "repetition 1/1" not in terminal
    assert rows[0]["successful_repetitions"] == "1"


@pytest.mark.parametrize("stage,expected", [
    ("setup", "Setup failed: mock setup error"),
    ("spend", "Spend failed: mock spend error"),
    ("verify", "Verify failed: mock verify error"),
    ("rejected", "Verify failed: verification returned False"),
])
def test_failure_stage_is_reported_even_when_quiet(stage, expected, monkeypatch, capsys) -> None:
    if stage == "setup":
        def fail_setup(*args):
            raise RuntimeError("mock setup error")

        monkeypatch.setattr(bench_time, "prepare_spend", fail_setup)
    else:
        monkeypatch.setattr(bench_time, "prepare_spend", lambda *args: prepared_fixture())

    def fake_spend(*args, **kwargs):
        if stage == "spend":
            raise RuntimeError("mock spend error")
        return object(), object()

    def fake_verify(*args, **kwargs):
        if stage == "verify":
            raise RuntimeError("mock verify error")
        return False

    monkeypatch.setattr(bench_time.ct, "spend", fake_spend)
    monkeypatch.setattr(bench_time.ct, "verify", fake_verify)
    ticks = itertools.count(step=1_000_000)
    monkeypatch.setattr(bench_time.time, "perf_counter_ns", lambda: next(ticks))
    row = bench_time.benchmark_ring(4, 1, 5163, quiet=True)
    terminal = capsys.readouterr().out

    assert expected in terminal
    assert "repetition 1/1" not in terminal
    assert row.successful_repetitions == 0
    assert row.setup_failures == (stage == "setup")
    assert row.spend_failures == (stage == "spend")
    assert row.verify_failures == (stage == "verify")
    assert row.rejected_verifications == (stage == "rejected")


def test_failed_repetition_shows_available_duration_and_status(monkeypatch, capsys) -> None:
    monkeypatch.setattr(bench_time, "prepare_spend", lambda *args: prepared_fixture())
    monkeypatch.setattr(bench_time.ct, "spend", lambda *args, **kwargs: (object(), object()))
    monkeypatch.setattr(bench_time.ct, "verify", lambda *args, **kwargs: False)
    ticks = itertools.count(step=1_000_000)
    monkeypatch.setattr(bench_time.time, "perf_counter_ns", lambda: next(ticks))

    row = bench_time.benchmark_ring(4, 1, 5163)
    terminal = capsys.readouterr().out

    assert "Ring 4 repetition 1/1: starting." in terminal
    assert "Spend=1.000 ms, Verify=1.000 ms, status=failed (Verify rejected)" in terminal
    assert "Verify failed: verification returned False" in terminal
    assert row.failed_repetitions == 1


@pytest.mark.parametrize("stage,expected", [
    ("spend", "Spend=N/A ms, Verify=N/A ms, status=failed (Spend)"),
    ("verify", "Spend=1.000 ms, Verify=N/A ms, status=failed (Verify)"),
])
def test_exception_progress_marks_incomplete_durations(stage, expected, monkeypatch, capsys) -> None:
    monkeypatch.setattr(bench_time, "prepare_spend", lambda *args: prepared_fixture())

    def fake_spend(*args, **kwargs):
        if stage == "spend":
            raise RuntimeError("mock spend error")
        return object(), object()

    def fake_verify(*args, **kwargs):
        raise RuntimeError("mock verify error")

    monkeypatch.setattr(bench_time.ct, "spend", fake_spend)
    monkeypatch.setattr(bench_time.ct, "verify", fake_verify)
    ticks = itertools.count(step=1_000_000)
    monkeypatch.setattr(bench_time.time, "perf_counter_ns", lambda: next(ticks))

    row = bench_time.benchmark_ring(4, 1, 5163)
    terminal = capsys.readouterr().out

    assert expected in terminal
    assert row.failed_repetitions == 1
    assert row.spend_mean_ms is None and row.verify_mean_ms is None
