"""
Placeholder proof: the "proof" is the witness itself.

This is NOT zero-knowledge. It reveals the real input positions, every amount
and every key offset. It was the stand-in while the real proof
(nizk/sigma_ring.py, now the default) was being written. It's still useful
where speed matters more than privacy (fast test runs, attack simulations
that only look at the public transaction) and for debugging, because you can
print exactly what failed. Pass nizk=stub explicitly to use it.

Any proof system plugs in by providing the same two functions:

    prove(stmt: Statement, wit: Witness) -> proof
    verify(stmt: Statement, proof) -> bool
"""

from .relation import relation_holds

NAME = "stub (witness in the clear, NOT private)"


def prove(stmt, wit):
    return wit


def verify(stmt, proof):
    return relation_holds(stmt, proof)
