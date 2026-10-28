"""
Hashed Diffie-Hellman key agreement (§6.1.2).

The receiver's static key is vdk (message vek = G'^vdk, published in mpk).
The sender picks an ephemeral tdk (message tek = G'^tdk, stored in the tx).
Both sides then get the same s = H_n(shared point, kappa).

KAmsg1/KAmsg2 and KAkey1/KAkey2 in the paper are the same functions here; the
two names only say which side is static and which is ephemeral.
"""

from .group import G_KA
from .transcript import H_n_kappa


def ka_msg(secret):
    return secret * G_KA


def ka_key(secret, their_msg, kappa):
    """H_n^kappa(their_msg^secret). Matches on both sides because
    tdk * (vdk * G') == vdk * (tdk * G')."""
    return H_n_kappa(secret * their_msg, kappa)
