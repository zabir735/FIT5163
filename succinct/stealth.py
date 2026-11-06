"""
Stealth addresses and one-time accounts (§6.2: SAKGen, OTAccGen, View,
Receive, plus CheckAmount / CheckTag from Appendix H.3).

The big idea, compared to Monero:

  Monero:    one-time sk = H(shared secret) + spend_key           (linear in the key)
  SuccinCT:  one-time sk = f(s), f a secret degree-q polynomial    (non-linear in s)

The tag is U^sk in both. With Monero's linear form, a sender who knows the
offset H(shared secret) could link two of your tags (the related-key problem in
§5). Evaluating a random polynomial at q or fewer points gives values that look
independent, so that link disappears, as long as the key is used at most q
times. tests/test_stealth.py shows what goes wrong past that.

The miner account is the degenerate case q = 0: f is the constant lsk, there's
no view key, and the amount is published in the clear with coin key 1.

Two interface changes from the paper:
  * View takes (vdk, lpk). It has to recompute pk = prod F_i^{s^i}, and a bare
    vdk can't do that. lpk is public, so nothing leaks.
  * Receive also takes mpk, so it doesn't rebuild the public points each time.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .group import ORDER, Point, multiexp, random_scalar
from .transcript import H_n
from .pedersen import commit
from .tagging import tag_kgen, tag_eval
from .keyagreement import ka_msg, ka_key

AMOUNT_BITS = 64                      # the paper's beta (bit length of amounts)
AMOUNT_MASK = (1 << AMOUNT_BITS) - 1
DEFAULT_Q = 90                        # paper's suggestion so mpk fits in a 3KB QR code


# --- data types -----------------------------------------------------------

@dataclass(frozen=True)
class MasterPublicKey:
    lpk: tuple                 # (F_0, ..., F_q) with F_i = G^theta_i
    vek: Point | None          # view encryption key; None for a miner

    @property
    def is_miner(self):
        return self.vek is None


@dataclass
class MasterSecretKey:
    thetas: tuple              # coefficients of f; for a miner just (lsk,)
    vdk: int | None
    q: int
    received: set = field(default_factory=set)   # pks already received, for the q limit

    def f(self, x):
        # Horner's rule, mod ORDER.
        acc = 0
        for t in reversed(self.thetas):
            acc = (acc * x + t) % ORDER
        return acc


@dataclass(frozen=True)
class ViewKey:
    """What you hand to an auditor or light-wallet server."""
    vdk: int
    lpk: tuple


@dataclass(frozen=True)
class Account:
    pk: Point                  # one-time public key, G^sk
    co: Point                  # coin, Com(a; ck) = V^a W^ck
    ctxt: int                  # encrypted amount (plain amount for a miner)
    kappa: int                 # output index; 0 means miner/coinbase account

    @property
    def is_miner(self):
        return self.kappa == 0

    def hash_items(self):
        return (self.pk, self.co, self.ctxt, self.kappa)


# --- SAKGen ---------------------------------------------------------------

def sakgen(q=DEFAULT_Q):
    """Returns (mpk, msk, view_key)."""
    thetas = tuple(random_scalar() for _ in range(q + 1))
    lpk = tuple(tag_kgen(t) for t in thetas)
    vdk = random_scalar()
    mpk = MasterPublicKey(lpk=lpk, vek=ka_msg(vdk))
    msk = MasterSecretKey(thetas=thetas, vdk=vdk, q=q)
    return mpk, msk, ViewKey(vdk=vdk, lpk=lpk)


def sakgen_miner():
    """Miner address: q = 0, no view key. Use a fresh one per block. A miner key
    has a single fixed sk, so two coinbases to it share a tag and the second
    one can never be spent."""
    lsk = random_scalar()
    mpk = MasterPublicKey(lpk=(tag_kgen(lsk),), vek=None)
    msk = MasterSecretKey(thetas=(lsk,), vdk=None, q=0)
    return mpk, msk, None


# --- OTAccGen -------------------------------------------------------------

def _derive(s):
    """Everything both sides derive from the shared secret s."""
    amount_pad = H_n("amount", s) & AMOUNT_MASK      # XOR with the first beta/8 bytes
    ck = H_n("commitment_mask", s)
    return amount_pad, ck


def _pk_from_lpk(lpk, s):
    # G^{f(s)} = prod F_i^{s^i}: the sender evaluates f "in the exponent"
    # without knowing any theta_i.
    powers = [pow(s, i, ORDER) for i in range(len(lpk))]
    return multiexp(powers, list(lpk))


def otaccgen(mpk, a, kappa, tdk=None):
    """Returns (ck, acc, info).

    Pass the same tdk for every output of one transaction. All outputs then
    share one tek (info), and kappa keeps their keys apart.
    """
    if not 0 <= a <= AMOUNT_MASK:
        raise ValueError(f"amount must fit in {AMOUNT_BITS} bits")

    if kappa == 0:
        if not mpk.is_miner:
            raise ValueError("kappa = 0 is reserved for miner accounts")
        acc = Account(pk=mpk.lpk[0], co=commit(a, 1), ctxt=a, kappa=0)
        return 1, acc, None

    if mpk.is_miner:
        raise ValueError("miner addresses only receive coinbase (kappa = 0)")
    if tdk is None:
        tdk = random_scalar()

    tek = ka_msg(tdk)
    s = ka_key(tdk, mpk.vek, kappa)
    pad, ck = _derive(s)
    acc = Account(
        pk=_pk_from_lpk(mpk.lpk, s),
        co=commit(a, ck),
        ctxt=a ^ pad,
        kappa=kappa,
    )
    return ck, acc, tek


# --- View -----------------------------------------------------------------

def _open(vdk, lpk, acc, info):
    """Shared by View and Receive. Returns (a, ck, s) or None."""
    if acc.is_miner or info is None:
        return None
    s = ka_key(vdk, info, acc.kappa)
    if acc.pk != _pk_from_lpk(lpk, s):
        return None                      # not ours
    pad, ck = _derive(s)
    a = acc.ctxt ^ pad
    if acc.co != commit(a, ck):
        return None                      # ours, but the sender lied about the amount
    return a, ck, s


def view(view_key, acc, info):
    """Amount in acc, or None. Read-only: there's no way to get sk from this."""
    opened = _open(view_key.vdk, view_key.lpk, acc, info)
    return None if opened is None else opened[0]


# --- Receive --------------------------------------------------------------

def receive(msk, mpk, acc, info):
    """Returns (ck, a, sk, tag) or None. Consumes one of the key's q uses."""
    if mpk.is_miner:
        if not acc.is_miner or acc.pk != mpk.lpk[0]:
            return None
        if acc.co != commit(acc.ctxt, 1):
            return None
        sk = msk.thetas[0]
        return 1, acc.ctxt, sk, tag_eval(sk)

    opened = _open(msk.vdk, mpk.lpk, acc, info)
    if opened is None:
        return None
    a, ck, s = opened

    if acc.pk not in msk.received:
        if len(msk.received) >= msk.q:
            return None                  # key exhausted, see module docstring
        msk.received.add(acc.pk)

    sk = msk.f(s)
    return ck, a, sk, tag_eval(sk)


# --- checks used by the security definitions ------------------------------

def check_amount(acc, ck, a):
    return acc.co == commit(a, ck)


def check_tag(acc, sk, tag):
    return acc.pk == tag_kgen(sk) and tag == tag_eval(sk)
