"""Smoke test: every module imports, including the not-yet-implemented ones."""

import importlib

import pytest

MODULES = [
    "succinct.group",
    "succinct.transcript",
    "succinct.pedersen",
    "succinct.tagging",
    "succinct.keyagreement",
    "succinct.stealth",
    "succinct.nizk.relation",
    "succinct.nizk.stub",
    "succinct.nizk.sigma_ring",
    "succinct.nizk.rangeproof",
    "succinct.nizk.ipa",
    "succinct.nizk.util",
    "succinct.ct",
    "succinct.chain",
    "succinct.serialize",
    "attacks.miner_privacy",
    "attacks.anonymity_reduction",
    "attacks.related_key_tag",
    "attacks.q_bound_linkability",
    "eval.bench_time",
    "eval.bench_size",
    "eval.size_model",
    "demo",
]


@pytest.mark.parametrize("name", MODULES)
def test_imports(name):
    importlib.import_module(name)


@pytest.mark.parametrize("name", ["succinct.nizk.stub", "succinct.nizk.sigma_ring"])
def test_proof_systems_share_the_interface(name):
    nizk = importlib.import_module(name)
    assert callable(nizk.prove) and callable(nizk.verify) and nizk.NAME
