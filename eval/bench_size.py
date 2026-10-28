"""Measure complete serialized Python transactions when the serializer is ready.

The current succinct.serialize.encode_transaction raises NotImplementedError.
No transaction size is reported until the serializer declares
COMPLETE_TRANSACTION_ENCODING = True and a nonempty TRANSACTION_FORMAT, and
encode_transaction(tx, sig) returns nonempty bytes. That declaration must mean
the encoding includes the transaction, signature R/T, and the complete nested
sigma_ring, range, and inner-product proofs. A separate proof byte count is
reported only if COMPLETE_PROOF_ENCODING and encode_proof(proof) are provided.

This benchmark does not calculate Table 1 estimates. Empty theoretical model
fields keep paper estimates separate from actual encoded byte lengths.
"""

from __future__ import annotations

import argparse
import csv
import statistics
from dataclasses import asdict, dataclass
from pathlib import Path

from succinct import ct, serialize
from succinct.nizk import sigma_ring

from . import bench_time


DEFAULT_RING_SIZES = (128, 256, 512, 1024)
DEFAULT_REPETITIONS = 100
DEFAULT_OUTPUT = Path("eval/results/bench_size_sigma_ring.csv")


@dataclass(frozen=True)
class SizeResult:
    """One ring-size row with observed bytes or an explicit blocked status."""

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
    serialization_failures: int
    proof_serialization_failures: int
    proof_backend: str
    python_version: str
    operating_system: str
    os_release: str
    cpu: str
    machine: str
    seed: int
    input_count: int
    output_count: int
    input_amounts: str
    output_amounts: str
    fee: int
    serialization_format: str
    transaction_bytes_observations: str
    transaction_bytes_mean: float | None
    transaction_bytes_min: int | None
    transaction_bytes_max: int | None
    proof_bytes_observations: str
    proof_successful_repetitions: int
    proof_bytes_mean: float | None
    proof_bytes_min: int | None
    proof_bytes_max: int | None
    proof_size_status: str
    theoretical_model_bytes: int | None
    theoretical_model_status: str
    measurement_status: str
    blocker: str


def serializer_contract() -> tuple[bool, str, str]:
    """Require an explicit complete-transaction claim before doing expensive work."""
    if getattr(serialize, "COMPLETE_TRANSACTION_ENCODING", False) is not True:
        return False, "unavailable", (
            "succinct.serialize.COMPLETE_TRANSACTION_ENCODING is missing or false"
        )
    format_name = getattr(serialize, "TRANSACTION_FORMAT", None)
    if not isinstance(format_name, str) or not format_name.strip():
        return False, "unavailable", "succinct.serialize.TRANSACTION_FORMAT is missing"
    if not callable(getattr(serialize, "encode_transaction", None)):
        return False, "unavailable", "succinct.serialize.encode_transaction is missing"
    return True, format_name, ""


def proof_contract() -> bool:
    """Check whether independent complete-proof encoding is available."""
    return (getattr(serialize, "COMPLETE_PROOF_ENCODING", False) is True
            and callable(getattr(serialize, "encode_proof", None)))


def _sizes(values: list[int]) -> tuple[str, float | None, int | None, int | None]:
    """Keep each raw byte length and summarize only actual observations."""
    if not values:
        return "", None, None, None
    return ";".join(map(str, values)), statistics.mean(values), min(values), max(values)


def _failure(ring_size: int, repetition: int | None, stage: str, error: object) -> None:
    """Report a concise failure without exposing transaction or proof objects."""
    message = str(error).splitlines()[0][:120] if str(error) else "no details"
    location = f"Ring {ring_size}" if repetition is None else f"Ring {ring_size} repetition {repetition}"
    print(f"{location}: {stage} failed: {message}", flush=True)


def _failed_attempt(ring_size: int, repetition: int, total: int,
                    stage: str) -> None:
    """Close a failed repetition with an explicit progress status."""
    print(f"Ring {ring_size} repetition {repetition}/{total}: "
          f"transaction=N/A bytes, proof=N/A bytes, status=failed ({stage}).",
          flush=True)


def benchmark_ring(ring_size: int, repetitions: int, seed: int,
                   *, backend=sigma_ring) -> SizeResult:
    """Verify real sigma_ring spends, then count bytes from a declared-complete encoder.

    A successful repetition is verified and has a complete encoded transaction.
    Proof-size encoding is optional and tracked independently. Mock encoders in
    tests check this flow but do not constitute real transaction measurements.
    """
    if backend is not sigma_ring:
        raise ValueError("Only the sigma_ring proof backend is permitted.")
    if not isinstance(ring_size, int) or isinstance(ring_size, bool) or ring_size < 2:
        raise ValueError("Ring size must be an integer of at least 2.")
    if not isinstance(repetitions, int) or isinstance(repetitions, bool) or repetitions < 1:
        raise ValueError("Repetitions must be a positive integer.")

    print(f"Ring {ring_size}: starting size benchmark, target={repetitions}.", flush=True)
    ready, format_name, blocker = serializer_contract()
    proof_ready = proof_contract() if ready else False
    attempted = setup_failures = spend_failures = verify_failures = rejected = 0
    serialization_failures = proof_failures = 0
    transaction_sizes: list[int] = []
    proof_sizes: list[int] = []
    halted = False
    if not ready:
        _failure(ring_size, None, "Serialization", blocker)
    else:
        if not proof_ready:
            print(f"Ring {ring_size}: independent proof byte size unavailable; "
                  "transaction size may still be measured.", flush=True)
        try:
            prepared = bench_time.prepare_spend(ring_size, seed)
        except Exception as error:
            setup_failures = 1
            _failure(ring_size, None, "Setup", error)
        else:
            for repetition in range(1, repetitions + 1):
                print(f"Ring {ring_size} repetition {repetition}/{repetitions}: starting.", flush=True)
                attempted += 1
                try:
                    tx, sig = ct.spend(prepared.ring, prepared.inputs, prepared.outputs,
                                       prepared.info, prepared.fee, nizk=backend)
                except Exception as error:
                    spend_failures += 1
                    _failure(ring_size, repetition, "Spend", error)
                    _failed_attempt(ring_size, repetition, repetitions, "Spend")
                    continue
                try:
                    accepted = ct.verify(tx, sig, prepared.chain, nizk=backend)
                except Exception as error:
                    verify_failures += 1
                    _failure(ring_size, repetition, "Verify", error)
                    _failed_attempt(ring_size, repetition, repetitions, "Verify")
                    continue
                if accepted is not True:
                    rejected += 1
                    _failure(ring_size, repetition, "Verify", f"returned {accepted!r}")
                    _failed_attempt(ring_size, repetition, repetitions, "Verify")
                    continue
                try:
                    encoded = serialize.encode_transaction(tx, sig)
                    if not isinstance(encoded, bytes) or not encoded:
                        raise ValueError("complete transaction encoder must return nonempty bytes")
                except NotImplementedError:
                    serialization_failures += 1
                    blocker = "succinct.serialize.encode_transaction is not implemented"
                    _failure(ring_size, repetition, "Serialization", blocker)
                    _failed_attempt(ring_size, repetition, repetitions, "Serialization")
                    halted = True
                    break
                except Exception as error:
                    serialization_failures += 1
                    _failure(ring_size, repetition, "Serialization", error)
                    _failed_attempt(ring_size, repetition, repetitions, "Serialization")
                    continue
                transaction_size = len(encoded)
                transaction_sizes.append(transaction_size)
                proof_size = None
                if proof_ready:
                    try:
                        encoded_proof = serialize.encode_proof(sig.proof)
                        if not isinstance(encoded_proof, bytes) or not encoded_proof:
                            raise ValueError("complete proof encoder must return nonempty bytes")
                        if len(encoded_proof) > transaction_size:
                            raise ValueError("proof encoding exceeds transaction encoding")
                    except Exception as error:
                        proof_failures += 1
                        _failure(ring_size, repetition, "Proof serialization", error)
                    else:
                        proof_size = len(encoded_proof)
                        proof_sizes.append(proof_size)
                proof_display = "N/A" if proof_size is None else str(proof_size)
                print(f"Ring {ring_size} repetition {repetition}/{repetitions}: "
                      f"transaction={transaction_size} bytes, proof={proof_display} bytes, "
                      "status=success.", flush=True)

    successful = len(transaction_sizes)
    transaction_text, transaction_mean, transaction_min, transaction_max = _sizes(transaction_sizes)
    proof_text, proof_mean, proof_min, proof_max = _sizes(proof_sizes)
    if not ready or halted:
        status = "blocked_serializer"
    elif setup_failures:
        status = "setup_failed"
    else:
        status = "complete" if successful == repetitions else "partial"
    proof_status = "unavailable" if not proof_ready else (
        "not_measured" if not successful else (
            "complete" if len(proof_sizes) == successful else "partial"
        )
    )
    result = SizeResult(
        ring_size=ring_size,
        target_repetitions=repetitions,
        attempted_repetitions=attempted,
        successful_repetitions=successful,
        failed_repetitions=attempted - successful,
        unattempted_repetitions=repetitions - attempted,
        setup_failures=setup_failures,
        spend_failures=spend_failures,
        verify_failures=verify_failures,
        rejected_verifications=rejected,
        serialization_failures=serialization_failures,
        proof_serialization_failures=proof_failures,
        proof_backend="sigma_ring",
        **bench_time.system_metadata(),
        seed=seed,
        input_count=len(bench_time.INPUT_AMOUNTS),
        output_count=len(bench_time.OUTPUT_AMOUNTS),
        input_amounts=";".join(map(str, bench_time.INPUT_AMOUNTS)),
        output_amounts=";".join(map(str, bench_time.OUTPUT_AMOUNTS)),
        fee=bench_time.FEE,
        serialization_format=format_name,
        transaction_bytes_observations=transaction_text,
        transaction_bytes_mean=transaction_mean,
        transaction_bytes_min=transaction_min,
        transaction_bytes_max=transaction_max,
        proof_bytes_observations=proof_text,
        proof_successful_repetitions=len(proof_sizes),
        proof_bytes_mean=proof_mean,
        proof_bytes_min=proof_min,
        proof_bytes_max=proof_max,
        proof_size_status=proof_status,
        theoretical_model_bytes=None,
        theoretical_model_status="not computed; see eval.size_model for paper estimates",
        measurement_status=status,
        blocker=blocker,
    )
    print(f"Ring {ring_size} complete: target={repetitions}, attempted={attempted}, "
          f"successful={successful}, failed={result.failed_repetitions}, "
          f"unattempted={result.unattempted_repetitions}, status={status}.", flush=True)
    return result


def write_csv(path: Path, rows: list[SizeResult]) -> None:
    """Write actual observations or explicit blocked rows, never model values."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(SizeResult.__dataclass_fields__))
        writer.writeheader()
        writer.writerows(asdict(row) for row in rows)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--seed", type=int, default=5163)
    parser.add_argument("--ring-sizes", type=int, nargs="+", default=None,
                        help="Ring sizes (default: 128 256 512 1024).")
    parser.add_argument("--repetitions", type=int, default=None,
                        help="Target attempts per ring size (default: 100).")
    parser.add_argument("--smoke", action="store_true",
                        help="One attempt at ring size 4; cannot combine with sizes/repetitions.")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT,
                        help=f"New CSV output path (default: {DEFAULT_OUTPUT}).")
    args = parser.parse_args(argv)
    if args.smoke and (args.ring_sizes is not None or args.repetitions is not None):
        parser.error("--smoke cannot be combined with --ring-sizes or --repetitions.")
    sizes = [4] if args.smoke else (args.ring_sizes or list(DEFAULT_RING_SIZES))
    repetitions = 1 if args.smoke else (
        DEFAULT_REPETITIONS if args.repetitions is None else args.repetitions
    )
    if any(size < 2 for size in sizes):
        parser.error("Every ring size must be at least 2.")
    if repetitions < 1:
        parser.error("--repetitions must be a positive integer.")
    if len(set(sizes)) != len(sizes):
        parser.error("Ring sizes must be distinct.")
    if args.output.exists():
        parser.error(f"Output already exists: {args.output}. Choose a new path.")

    print("Actual size benchmark: explicit sigma_ring; no theoretical bytes are measured here.",
          flush=True)
    rows = [benchmark_ring(size, repetitions, args.seed, backend=sigma_ring) for size in sizes]
    write_csv(args.output, rows)
    print(f"Wrote {args.output}.", flush=True)
    if any(row.measurement_status != "complete" for row in rows):
        raise SystemExit("Size benchmark incomplete or blocked; inspect CSV status and blocker fields.")


if __name__ == "__main__":
    main()
