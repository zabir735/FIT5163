"""Python side of the Go/Python cross-check (see go/cmd/crosscheck).

Run from the repository root:

    python go/crosscheck.py make  fixture.json    # Python makes a chain and a transaction
    python go/crosscheck.py check fixture.json    # Python verifies a fixture (e.g. from Go)

A transaction made by either version must verify in the other, and both must
reject the same tampered copies. That only works if the two agree on every
hash, generator, transcript label and byte of the encoding.
"""

import dataclasses
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from succinct import ct, serialize                          # noqa: E402
from succinct.chain import Chain                            # noqa: E402
from succinct.group import G, Point, random_scalar          # noqa: E402
from succinct.nizk import sigma_ring                        # noqa: E402
from succinct.stealth import Account, otaccgen, sakgen      # noqa: E402
from succinct.wallet import _build                          # noqa: E402


def make(path):
    chain = Chain(nizk=sigma_ring, reward=600)
    for _ in range(20):
        mpk, _, _ = sakgen(1)
        _, acc, info = otaccgen(mpk, 1000, 1)
        chain.add_output(acc, info)
    mpk, msk, _ = sakgen(5)
    _, acc, info = otaccgen(mpk, 1000, 1)
    ref = chain.add_output(acc, info)
    bob, _, _ = sakgen(5)
    tx, sig = _build(chain, [(ref, mpk, msk)], [(bob, 700), (mpk, 290)], 10, 16)
    data = serialize.encode_transaction(tx, sig)
    outputs = []
    for acc, info in chain.outputs:
        o = {"pk": acc.pk.to_bytes().hex(), "co": acc.co.to_bytes().hex(),
             "ctxt": acc.ctxt, "kappa": acc.kappa}
        if info is not None:
            o["info"] = info.to_bytes().hex()
        outputs.append(o)
    with open(path, "w") as f:
        json.dump({"maker": "Python", "outputs": outputs, "tx": data.hex()}, f, indent=1)
    print(f"Python wrote {path}: ring 16, {len(data)} bytes, verifies here: "
          f"{ct.verify(tx, sig, chain, nizk=sigma_ring)}")


def check(path):
    with open(path) as f:
        fx = json.load(f)
    chain = Chain(nizk=sigma_ring, reward=600)
    for o in fx["outputs"]:
        acc = Account(pk=Point.from_bytes(bytes.fromhex(o["pk"])),
                      co=Point.from_bytes(bytes.fromhex(o["co"])),
                      ctxt=o["ctxt"], kappa=o["kappa"])
        info = Point.from_bytes(bytes.fromhex(o["info"])) if "info" in o else None
        chain.add_output(acc, info)
    data = bytes.fromhex(fx["tx"])
    tx, sig = serialize.decode_transaction(data)
    v = lambda t: ct.verify(t, sig, chain, nizk=sigma_ring)
    print(f"Python verifying a transaction made by {fx['maker']} (ring {len(tx.ring_refs)}, {len(data)} bytes)")
    print(f"  original:     {v(tx)}")
    print(f"  fee edited:   {v(dataclasses.replace(tx, fee=0))}")
    print(f"  tek swapped:  {v(dataclasses.replace(tx, info=random_scalar() * G))}")
    chain.submit(tx, sig)
    print(f"  resubmitted:  {v(tx)}")


if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] not in ("make", "check"):
        sys.exit("usage: crosscheck.py make|check fixture.json")
    (make if sys.argv[1] == "make" else check)(sys.argv[2])
