"""Mock-based checks for the size harness; fake bytes are not measurements."""

from __future__ import annotations

import csv
from pathlib import Path
from types import SimpleNamespace

import pytest

from eval import bench_size, bench_time
from succinct.nizk import stub


def fake_prepared() -> bench_time.PreparedSpend:
    """Provide placeholders for the already prepared transaction inputs."""
    return bench_time.PreparedSpend(
        chain=object(), ring=[object()], inputs=[object()],
        outputs=[object()], info=object(), fee=1,
    )


def ready_serializer(monkeypatch, *, proof: bool = False) -> None:
    """Mock the required declarations, not an actual canonical encoding."""
    monkeypatch.setattr(bench_size.serialize, "COMPLETE_TRANSACTION_ENCODING", True,
                        raising=False)
    monkeypatch.setattr(bench_size.serialize, "TRANSACTION_FORMAT", "mock-complete-v1",
                        raising=False)
    monkeypatch.setattr(bench_size.serialize, "COMPLETE_PROOF_ENCODING", proof,
                        raising=False)


def read_csv(path: Path) -> tuple[list[str], list[dict[str, str]]]:
    with path.open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        return list(reader.fieldnames or []), list(reader)


@pytest.mark.parametrize("invalid", [
    ["--ring-sizes", "0"],
    ["--ring-sizes", "1"],
    ["--ring-sizes", "4", "4"],
    ["--ring-sizes", "not-an-integer"],
    ["--repetitions", "0"],
    ["--repetitions", "-1"],
    ["--repetitions", "not-an-integer"],
    ["--seed", "not-an-integer"],
    ["--smoke", "--ring-sizes", "4"],
    ["--smoke", "--repetitions", "1"],
])
def test_cli_rejects_invalid_options_without_creating_csv(
    tmp_path: Path, invalid: list[str],
) -> None:
    output = tmp_path / "invalid.csv"
    with pytest.raises(SystemExit) as error:
        bench_size.main(["--output", str(output), *invalid])
    assert error.value.code == 2
    assert not output.exists()


def test_cli_refuses_to_overwrite_existing_results(tmp_path: Path) -> None:
    output = tmp_path / "existing.csv"
    output.write_text("keep this result\n", encoding="utf-8")
    with pytest.raises(SystemExit) as error:
        bench_size.main(["--smoke", "--output", str(output)])
    assert error.value.code == 2
    assert output.read_text(encoding="utf-8") == "keep this result\n"


@pytest.mark.parametrize("ring_size,repetitions", [(0, 1), (1, 1), (2.5, 1),
                                                     (4, 0), (4, -1), (4, True)])
def test_api_rejects_invalid_sizes_and_counts(ring_size, repetitions) -> None:
    with pytest.raises(ValueError):
        bench_size.benchmark_ring(ring_size, repetitions, 5163)


def test_stub_backend_is_rejected_before_any_setup(monkeypatch) -> None:
    monkeypatch.setattr(bench_size.bench_time, "prepare_spend",
                        lambda *args: pytest.fail("setup must not run"))
    with pytest.raises(ValueError, match="sigma_ring"):
        bench_size.benchmark_ring(4, 1, 5163, backend=stub)


def test_missing_serializer_blocks_before_cryptographic_work(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.delattr(bench_size.serialize, "COMPLETE_TRANSACTION_ENCODING", raising=False)
    monkeypatch.setattr(bench_size.bench_time, "prepare_spend",
                        lambda *args: pytest.fail("setup must not run"))
    output = tmp_path / "blocked.csv"

    with pytest.raises(SystemExit, match="incomplete or blocked"):
        bench_size.main(["--smoke", "--output", str(output)])

    headers, rows = read_csv(output)
    assert len(rows) == 1
    row = rows[0]
    assert {"ring_size", "target_repetitions", "attempted_repetitions",
            "successful_repetitions", "failed_repetitions", "unattempted_repetitions",
            "proof_backend", "python_version", "operating_system", "cpu",
            "serialization_format", "transaction_bytes_observations",
            "transaction_bytes_mean", "proof_bytes_observations", "proof_bytes_mean",
            "theoretical_model_bytes", "measurement_status", "blocker"}.issubset(headers)
    assert row["ring_size"] == "4"
    assert row["target_repetitions"] == "1"
    assert row["attempted_repetitions"] == "0"
    assert row["successful_repetitions"] == "0"
    assert row["failed_repetitions"] == "0"
    assert row["unattempted_repetitions"] == "1"
    assert row["measurement_status"] == "blocked_serializer"
    assert "COMPLETE_TRANSACTION_ENCODING" in row["blocker"]
    assert row["transaction_bytes_observations"] == ""
    assert row["transaction_bytes_mean"] == ""
    assert row["proof_bytes_mean"] == ""
    assert row["theoretical_model_bytes"] == ""


def test_incomplete_format_declaration_is_blocked(monkeypatch) -> None:
    monkeypatch.setattr(bench_size.serialize, "COMPLETE_TRANSACTION_ENCODING", True,
                        raising=False)
    monkeypatch.delattr(bench_size.serialize, "TRANSACTION_FORMAT", raising=False)
    monkeypatch.setattr(bench_size.bench_time, "prepare_spend",
                        lambda *args: pytest.fail("setup must not run"))
    row = bench_size.benchmark_ring(4, 2, 5163)
    assert row.measurement_status == "blocked_serializer"
    assert "TRANSACTION_FORMAT" in row.blocker
    assert row.attempted_repetitions == 0 and row.unattempted_repetitions == 2


def test_declared_encoder_that_is_still_a_stub_is_not_measured(monkeypatch, capsys) -> None:
    ready_serializer(monkeypatch)
    def still_a_stub(*args):
        raise NotImplementedError

    monkeypatch.setattr(bench_size.serialize, "encode_transaction", still_a_stub)
    monkeypatch.setattr(bench_size.bench_time, "prepare_spend", lambda *args: fake_prepared())
    monkeypatch.setattr(bench_size.ct, "spend",
                        lambda *args, **kwargs: (object(), SimpleNamespace(proof=object())))
    monkeypatch.setattr(bench_size.ct, "verify", lambda *args, **kwargs: True)

    row = bench_size.benchmark_ring(4, 3, 5163)
    terminal = capsys.readouterr().out

    assert row.measurement_status == "blocked_serializer"
    assert row.attempted_repetitions == 1
    assert row.failed_repetitions == 1
    assert row.unattempted_repetitions == 2
    assert row.serialization_failures == 1
    assert row.transaction_bytes_observations == ""
    assert row.transaction_bytes_mean is None
    assert "repetition 1/3: transaction=N/A bytes, proof=N/A bytes, " \
           "status=failed (Serialization)" in terminal


def test_setup_failure_records_unattempted_repetitions(monkeypatch) -> None:
    ready_serializer(monkeypatch)

    def fail_setup(*args):
        raise RuntimeError("mock setup failure")

    monkeypatch.setattr(bench_size.bench_time, "prepare_spend", fail_setup)
    row = bench_size.benchmark_ring(4, 3, 5163)

    assert row.measurement_status == "setup_failed"
    assert row.setup_failures == 1
    assert row.attempted_repetitions == 0
    assert row.failed_repetitions == 0
    assert row.unattempted_repetitions == 3
    assert row.transaction_bytes_mean is None


def test_valid_mock_flow_counts_encoded_lengths_not_object_memory(monkeypatch, capsys) -> None:
    ready_serializer(monkeypatch, proof=True)
    fixture = fake_prepared()
    monkeypatch.setattr(bench_size.bench_time, "prepare_spend", lambda *args: fixture)
    calls = []
    signature = SimpleNamespace(proof=object())

    def fake_spend(ring, inputs, outputs, info, fee, *, nizk):
        assert (ring, inputs, outputs, info, fee) == (
            fixture.ring, fixture.inputs, fixture.outputs, fixture.info, fixture.fee,
        )
        assert nizk is bench_size.sigma_ring
        calls.append("spend")
        return object(), signature

    def fake_verify(tx, sig, chain, *, nizk):
        assert sig is signature and chain is fixture.chain
        assert nizk is bench_size.sigma_ring
        calls.append("verify")
        return True

    transaction_bytes = iter((b"x" * 37, b"x" * 41))
    proof_bytes = iter((b"p" * 11, b"p" * 12))

    def fake_encode_transaction(tx, sig):
        assert sig is signature
        calls.append("encode_transaction")
        return next(transaction_bytes)

    def fake_encode_proof(proof):
        assert proof is signature.proof
        calls.append("encode_proof")
        return next(proof_bytes)

    monkeypatch.setattr(bench_size.ct, "spend", fake_spend)
    monkeypatch.setattr(bench_size.ct, "verify", fake_verify)
    monkeypatch.setattr(bench_size.serialize, "encode_transaction", fake_encode_transaction)
    monkeypatch.setattr(bench_size.serialize, "encode_proof", fake_encode_proof,
                        raising=False)

    row = bench_size.benchmark_ring(4, 2, 7, backend=bench_size.sigma_ring)
    terminal = capsys.readouterr().out

    assert calls == ["spend", "verify", "encode_transaction", "encode_proof"] * 2
    assert (row.target_repetitions, row.attempted_repetitions,
            row.successful_repetitions, row.failed_repetitions) == (2, 2, 2, 0)
    assert row.transaction_bytes_observations == "37;41"
    assert (row.transaction_bytes_mean, row.transaction_bytes_min,
            row.transaction_bytes_max) == (39, 37, 41)
    assert row.proof_bytes_observations == "11;12"
    assert (row.proof_bytes_mean, row.proof_bytes_min, row.proof_bytes_max) == (
        11.5, 11, 12,
    )
    assert row.proof_successful_repetitions == 2
    assert row.proof_size_status == "complete"
    assert row.theoretical_model_bytes is None
    assert row.serialization_format == "mock-complete-v1"
    assert row.measurement_status == "complete"
    assert "Ring 4 repetition 1/2: transaction=37 bytes, proof=11 bytes" in terminal
    assert "Ring 4 repetition 2/2: transaction=41 bytes, proof=12 bytes" in terminal


def test_verification_failure_does_not_accept_encoded_bytes(monkeypatch, capsys) -> None:
    ready_serializer(monkeypatch)
    monkeypatch.setattr(bench_size.bench_time, "prepare_spend", lambda *args: fake_prepared())
    monkeypatch.setattr(bench_size.ct, "spend",
                        lambda *args, **kwargs: (object(), SimpleNamespace(proof=object())))
    accepted = iter((False, True))
    monkeypatch.setattr(bench_size.ct, "verify", lambda *args, **kwargs: next(accepted))
    encoded_calls = []

    def fake_encode(tx, sig):
        encoded_calls.append(1)
        return b"z" * 29

    monkeypatch.setattr(bench_size.serialize, "encode_transaction", fake_encode)
    row = bench_size.benchmark_ring(4, 2, 5163)
    terminal = capsys.readouterr().out

    assert len(encoded_calls) == 1
    assert (row.attempted_repetitions, row.successful_repetitions,
            row.failed_repetitions, row.rejected_verifications) == (2, 1, 1, 1)
    assert row.transaction_bytes_observations == "29"
    assert row.proof_bytes_observations == ""
    assert row.proof_size_status == "unavailable"
    assert row.measurement_status == "partial"
    assert "repetition 1/2: transaction=N/A bytes, proof=N/A bytes, " \
           "status=failed (Verify)" in terminal


@pytest.mark.parametrize("stage", ["Spend", "Verify"])
def test_call_exception_records_failure_stage_and_preserves_attempt_count(
    monkeypatch, capsys, stage: str,
) -> None:
    ready_serializer(monkeypatch)
    monkeypatch.setattr(bench_size.bench_time, "prepare_spend", lambda *args: fake_prepared())

    def fail_call(*args, **kwargs):
        raise RuntimeError("mock call error")

    def successful_spend(*args, **kwargs):
        return object(), SimpleNamespace(proof=object())

    monkeypatch.setattr(
        bench_size.ct, "spend",
        fail_call if stage == "Spend" else successful_spend,
    )
    monkeypatch.setattr(bench_size.ct, "verify",
                        fail_call if stage == "Verify" else lambda *args, **kwargs: True)
    monkeypatch.setattr(bench_size.serialize, "encode_transaction",
                        lambda *args: pytest.fail("failed call must not be encoded"))

    row = bench_size.benchmark_ring(4, 1, 5163)
    terminal = capsys.readouterr().out

    assert row.attempted_repetitions == 1
    assert row.failed_repetitions == 1
    assert row.unattempted_repetitions == 0
    assert getattr(row, f"{stage.lower()}_failures") == 1
    assert f"{stage} failed: mock call error" in terminal
    assert f"status=failed ({stage})" in terminal


@pytest.mark.parametrize("bad_value", [b"", "bytes-like text", 123])
def test_incomplete_encoder_output_is_not_counted(monkeypatch, bad_value) -> None:
    ready_serializer(monkeypatch)
    monkeypatch.setattr(bench_size.bench_time, "prepare_spend", lambda *args: fake_prepared())
    monkeypatch.setattr(bench_size.ct, "spend",
                        lambda *args, **kwargs: (object(), SimpleNamespace(proof=object())))
    monkeypatch.setattr(bench_size.ct, "verify", lambda *args, **kwargs: True)
    monkeypatch.setattr(bench_size.serialize, "encode_transaction",
                        lambda *args: bad_value)
    row = bench_size.benchmark_ring(4, 1, 5163)
    assert row.serialization_failures == 1
    assert row.successful_repetitions == 0
    assert row.transaction_bytes_mean is None


def test_proof_encoding_is_optional_and_must_fit_in_transaction(monkeypatch) -> None:
    ready_serializer(monkeypatch, proof=True)
    monkeypatch.setattr(bench_size.bench_time, "prepare_spend", lambda *args: fake_prepared())
    monkeypatch.setattr(bench_size.ct, "spend",
                        lambda *args, **kwargs: (object(), SimpleNamespace(proof=object())))
    monkeypatch.setattr(bench_size.ct, "verify", lambda *args, **kwargs: True)
    monkeypatch.setattr(bench_size.serialize, "encode_transaction", lambda *args: b"t" * 20)
    monkeypatch.setattr(bench_size.serialize, "encode_proof", lambda *args: b"p" * 21,
                        raising=False)

    row = bench_size.benchmark_ring(4, 1, 5163)

    assert row.successful_repetitions == 1
    assert row.transaction_bytes_mean == 20
    assert row.proof_successful_repetitions == 0
    assert row.proof_serialization_failures == 1
    assert row.proof_bytes_mean is None
    assert row.proof_size_status == "partial"


def test_smoke_configuration_exports_mock_csv_and_flushes(tmp_path: Path, monkeypatch) -> None:
    ready_serializer(monkeypatch)
    monkeypatch.setattr(bench_size.bench_time, "prepare_spend", lambda *args: fake_prepared())
    monkeypatch.setattr(bench_size.ct, "spend",
                        lambda *args, **kwargs: (object(), SimpleNamespace(proof=object())))
    monkeypatch.setattr(bench_size.ct, "verify", lambda *args, **kwargs: True)
    monkeypatch.setattr(bench_size.serialize, "encode_transaction", lambda *args: b"q" * 25)
    messages = []

    def fake_print(*args, **kwargs):
        messages.append((" ".join(map(str, args)), kwargs.get("flush")))

    output = tmp_path / "mock_smoke.csv"
    with monkeypatch.context() as printing:
        printing.setattr("builtins.print", fake_print)
        bench_size.main(["--smoke", "--seed", "7", "--output", str(output)])
    _, rows = read_csv(output)

    assert len(rows) == 1
    row = rows[0]
    assert (row["ring_size"], row["target_repetitions"], row["seed"]) == (
        "4", "1", "7",
    )
    assert row["transaction_bytes_observations"] == "25"
    assert row["proof_backend"] == "sigma_ring"
    assert row["measurement_status"] == "complete"
    assert row["python_version"] and row["operating_system"]
    assert all(flush is True for _, flush in messages)
    assert any("repetition 1/1: starting" in message for message, _ in messages)
    assert any("transaction=25 bytes" in message for message, _ in messages)
    assert any("successful=1, failed=0" in message for message, _ in messages)
