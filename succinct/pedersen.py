"""Pedersen commitments (Appendix C.1)."""

from .group import V, W, multiexp, generator_vector


def commit(a, ck):
    """Com(a; ck) = V^a W^ck.

    Amounts are reduced mod ORDER, so a negative amount commits to the same
    thing as ORDER - |a|. That's why outputs need range proofs.
    """
    return multiexp([a, ck], [V, W])


def vector_commit(values, blind, label="vcom"):
    """Com(v_1..v_n; t) = W^t * prod g_i^{v_i}, with g_i = generator_vector(label, n)."""
    gens = generator_vector(label, len(values))
    return multiexp(list(values) + [blind], list(gens) + [W])
