"""Byte encoding: real sigma_ring transactions round-trip exactly, so the
measured sizes cover every field, and the sizes match the closed form."""

import dataclasses

import pytest

from eval import bench_time
from succinct import ct, serialize
from succinct.group import G, ORDER, Point
from succinct.nizk import sigma_ring, stub
from succinct.nizk.rangeproof import RangeProof
from succinct.nizk.sigma_ring import RingProof

RING_SIZE = 8


@pytest.fixture(scope="module")
def spent():
    prepared = bench_time.prepare_spend(RING_SIZE, 5163)
    tx, sig = ct.spend(prepared.ring, prepared.inputs, prepared.outputs,
                       prepared.info, prepared.fee, nizk=sigma_ring)
    assert ct.verify(tx, sig, prepared.chain, nizk=sigma_ring) is True
    return prepared, tx, sig


def test_transaction_round_trips(spent):
    prepared, tx, sig = spent
    data = serialize.encode_transaction(tx, sig)
    tx2, sig2 = serialize.decode_transaction(data)
    assert (tx2, sig2) == (tx, sig)
    assert ct.verify(tx2, sig2, prepared.chain, nizk=sigma_ring) is True


def test_proof_round_trips(spent):
    _, _, sig = spent
    assert serialize.decode_proof(serialize.encode_proof(sig.proof)) == sig.proof


def test_mu_is_encoded(spent):
    _, tx, sig = spent
    with_mu = dataclasses.replace(tx, mu=b"memo")
    data = serialize.encode_transaction(with_mu, sig)
    assert serialize.decode_transaction(data)[0].mu == b"memo"
    assert len(data) == serialize.transaction_size(tx, sig) + 4


def test_sizes_match_closed_form(spent):
    _, tx, sig = spent
    S, k = len(tx.tags), len(tx.outputs)
    assert serialize.proof_size(sig.proof) == serialize.expected_proof_size(RING_SIZE, S, k)
    assert serialize.transaction_size(tx, sig) == \
        serialize.expected_transaction_size(RING_SIZE, S, k)


def test_proof_is_part_of_the_transaction(spent):
    _, tx, sig = spent
    assert serialize.encode_transaction(tx, sig).endswith(serialize.encode_proof(sig.proof))


def test_closed_form_counts_elements():
    # n = 128, S = 2, 2 outputs: ring proof 4 points + (2*127 + 4) scalars,
    # range proof 4 points + 3 scalars, IPA over 128 bits = 7 rounds.
    P, F, C = serialize.POINT_BYTES, serialize.SCALAR_BYTES, serialize.COUNT_BYTES
    expected = (4 * P + 2 * C + 258 * F) + (4 * P + 3 * F) + (C + 14 * P + 2 * F)
    assert serialize.expected_proof_size(128, 2, 2) == expected
    # three outputs pad to four inside the range proof: 256 bits, 8 rounds
    assert serialize.expected_proof_size(128, 2, 3) == expected + 2 * P


def test_bench_size_contract_is_declared():
    assert serialize.COMPLETE_TRANSACTION_ENCODING is True
    assert serialize.COMPLETE_PROOF_ENCODING is True
    assert serialize.TRANSACTION_FORMAT.strip()


def test_stub_proof_is_rejected(spent):
    _, tx, sig = spent
    with pytest.raises(TypeError):
        serialize.encode_proof(object())
    with pytest.raises(TypeError):
        serialize.encode_transaction(tx, dataclasses.replace(sig, proof=stub.prove(None, None)))


@pytest.mark.parametrize("change", [
    lambda tx, sig: (dataclasses.replace(tx, fee=-1), sig),
    lambda tx, sig: (dataclasses.replace(tx, fee=1 << 64), sig),
    lambda tx, sig: (dataclasses.replace(tx, ring_refs=(-1,) + tx.ring_refs[1:]), sig),
    lambda tx, sig: (dataclasses.replace(tx, tags=(5,) + tx.tags[1:]), sig),
    lambda tx, sig: (tx, dataclasses.replace(sig, R=None)),
    lambda tx, sig: (tx, dataclasses.replace(sig, proof=dataclasses.replace(sig.proof, s_z=ORDER))),
    lambda tx, sig: (tx, dataclasses.replace(
        sig, proof=dataclasses.replace(sig.proof, f=sig.proof.f[:1] + (sig.proof.f[1][1:],)))),
])
def test_invalid_fields_are_refused(spent, change):
    _, tx, sig = spent
    with pytest.raises((TypeError, ValueError)):
        serialize.encode_transaction(*change(tx, sig))


def test_truncated_or_padded_bytes_are_refused(spent):
    _, tx, sig = spent
    data = serialize.encode_transaction(tx, sig)
    with pytest.raises(ValueError):
        serialize.decode_transaction(data[:-1])
    with pytest.raises(ValueError):
        serialize.decode_transaction(data + b"\x00")


def test_identity_point_has_fixed_size():
    assert len(Point.identity().to_bytes()) == serialize.POINT_BYTES == len(G.to_bytes())
