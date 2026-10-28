"""
Fiat-Shamir hashing.

Two things live here:

1. The paper's named hash functions (H, H_a, H_b, H_c, H_n). Each has its own
   domain tag, so they behave like independent random oracles. Spend and
   Verify use these directly, exactly as §6.2 writes them.

2. A Transcript class for the NIZK. A Σ-protocol made non-interactive needs
   every challenge to depend on the full statement and every message sent so
   far. The easy way to get that right is to append everything to one running
   transcript and derive challenges from it, instead of hand-picking what goes
   into each hash (which is how "weak Fiat-Shamir" bugs happen).
"""

from .group import hash_to_scalar, encode


def H(*items):    return hash_to_scalar("SuccinCT/H", *items)     # Schnorr challenge h
def H_a(*items):  return hash_to_scalar("SuccinCT/H_a", *items)   # MuSig coefficients alpha_j
def H_b(*items):  return hash_to_scalar("SuccinCT/H_b", *items)   # beta: folds the G and U equations
def H_c(*items):  return hash_to_scalar("SuccinCT/H_c", *items)   # gamma: folds signature and balance
def H_n(*items):  return hash_to_scalar("SuccinCT/H_n", *items)   # key derivation / amount masking


def H_n_kappa(X, kappa):
    """The paper's H_n^kappa(X) := H_n(X || kappa), used by the key agreement."""
    return H_n(X, kappa)


class Transcript:
    """Running Fiat-Shamir transcript.

        t = Transcript("SuccinCT/sigma-eq5")
        t.append("statement", stmt_items)
        t.append("A", commitment_point)
        x = t.challenge("x")

    Prover and verifier must append the same things in the same order, or the
    challenges won't match and an honest proof will fail to verify.
    """

    def __init__(self, label):
        self._data = [encode(label)]

    def append(self, label, item):
        self._data.append(encode(label) + encode(item))

    def challenge(self, label):
        x = hash_to_scalar("SuccinCT/transcript", b"".join(self._data), label)
        # Feed the challenge back in so the next one depends on it too.
        self.append(label, x)
        return x
