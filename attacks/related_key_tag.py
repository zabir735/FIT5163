"""Related-key tag attack: naive tag U^sk with additive one-time keys lets the sender link tags.
Contrasts with the polynomial tag U^f(s), where the attack fails.

Setting (paper section 5). Alice pays Bob twice. Alice chose the ephemeral keys, so she
knows both shared secrets s1, s2. Later Bob spends both coins, which puts two tags on chain.
Alice wants to know if the two tags belong to the same recipient.

  naive / Monero-style:  sk = H(s) + lsk          tag = U^sk
      tag1 - tag2 = (H(s1) - H(s2)) * U           Alice knows s1, s2, so she can check this.
  SuccinCT:              sk = f(s), f a secret degree-q polynomial
      Alice does not know f, so the same check has nothing to compare against
      (as long as the key is used at most q times; see attacks.q_bound_linkability).

Run from the repo root:  python3 -m attacks.related_key_tag --trials 20

Limits: a failed test is not a proof. It shows the two natural linear checks stop working.
The proof is the DDH argument in the paper. Keys use OS randomness, so --seed only exists
for CLI consistency with the other attack scripts.

PROVENANCE: first draft AI-assisted (Claude); the group must review, run and adapt it.
"""

from __future__ import annotations

import argparse

from succinct.group import ORDER, U, random_scalar
from succinct.keyagreement import ka_key
from succinct.stealth import otaccgen, receive, sakgen
from succinct.tagging import tag_eval
from succinct.transcript import H_n

RULES = {
    "Monero-style: delta = H(s1) - H(s2)": lambda s: H_n("naive_onetime", s),
    "plain linear: delta = s1 - s2": lambda s: s,
}


def link_test(tag_x, s_x, tag_y, s_y, offset) -> bool:
    """Alice's check: does tag_x - tag_y equal (offset(s_x) - offset(s_y)) * U ?"""
    delta = (offset(s_x) - offset(s_y)) % ORDER
    return tag_x - tag_y == delta * U


class NaiveRecipient:
    """One-time key sk = H(s) + lsk, the additive form SuccinCT replaces."""

    def __init__(self):
        self.lsk = random_scalar()

    def receive_from(self, s):
        sk = (H_n("naive_onetime", s) + self.lsk) % ORDER
        return s, tag_eval(sk)


class PolyRecipient:
    """The real SuccinCT account: sk = f(s), with the repo's own OTAccGen and Receive."""

    def __init__(self, q=3):
        self.mpk, self.msk, _ = sakgen(q=q)

    def receive_from(self, _s=None):
        tdk = random_scalar()
        _, acc, info = otaccgen(self.mpk, 1000, 1, tdk=tdk)
        s = ka_key(tdk, self.mpk.vek, 1)              # Alice (the sender) can compute this
        got = receive(self.msk, self.mpk, acc, info)  # Bob's side, real code path
        assert got is not None, "receive refused: raise q"
        return s, got[3]


def one_trial(make_recipient, tally):
    a, b = make_recipient(), make_recipient()
    s1, t1 = a.receive_from(random_scalar())
    s2, t2 = a.receive_from(random_scalar())
    s3, t3 = b.receive_from(random_scalar())
    for name, off in RULES.items():
        tally[name]["same"] += link_test(t1, s1, t2, s2, off)       # should link
        tally[name]["diff"] += link_test(t1, s1, t3, s3, off)       # should not
    return tally


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--seed", type=int, default=5163)
    parser.add_argument("--trials", type=int, default=20)
    args = parser.parse_args(argv)

    print(f"Related-key tag attack | trials={args.trials}")
    print("Alice knows both shared secrets. 'links' = her check says the two tags share a recipient.\n")
    print(f"  {'scheme':<34}{'alice check':<40}{'links same':>11}{'links diff':>11}")
    for scheme, make in (("naive  sk = H(s) + lsk", NaiveRecipient),
                         ("SuccinCT  sk = f(s), q = 3", PolyRecipient)):
        tally = {name: {"same": 0, "diff": 0} for name in RULES}
        for _ in range(args.trials):
            one_trial(make, tally)
        for name, t in tally.items():
            print(f"  {scheme:<34}{name:<40}"
                  f"{100 * t['same'] / args.trials:>10.0f}%{100 * t['diff'] / args.trials:>10.0f}%")
        print()
    print("links same = pair of tags from ONE recipient (Alice wants this to be 100%).")
    print("links diff = pair from two DIFFERENT recipients (should be 0% or the test is useless).")


if __name__ == "__main__":
    main()
