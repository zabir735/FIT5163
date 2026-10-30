"""q-bound: reuse one long-term key q+1 times and Lagrange-interpolate U^theta_i in the exponent.
Predicting future tags demonstrates the usage limit is real.

One-time key sk_i = f(s_i) with f of degree q, so tag_i = U^f(s_i). A sender who made outputs
to the same recipient knows the points s_i. Once q+1 tags are public, f is pinned down in the
exponent. For any new point s*, the tag is
    U^f(s*) = sum_i L_i(s*) * tag_i        (L_i = Lagrange basis over s_0..s_q)
so the sender can PREDICT the tag of a future output and spot it on chain. With only q tags
the same formula gives the wrong point. That is why a long-term key has a use limit of q.

Run from the repo root:  python3 -m attacks.q_bound_linkability --q 1 2 3 5 --trials 10

The honest wallet refuses use number q+1 (Receive returns None). To show what the limit
protects against, this script computes the tags of the forbidden uses directly with msk.f.

PROVENANCE: first draft AI-assisted (Claude); the group must review, run and adapt it.
"""

from __future__ import annotations

import argparse

from succinct.group import ORDER, inv, multiexp, random_scalar
from succinct.keyagreement import ka_key
from succinct.stealth import otaccgen, receive, sakgen
from succinct.tagging import tag_eval


def predict(xs, points, x):
    """Interpolate through (xs, U^f(xs)) in the exponent and evaluate at x."""
    scalars = []
    for i, xi in enumerate(xs):
        num = den = 1
        for j, xj in enumerate(xs):
            if i != j:
                num = num * (x - xj) % ORDER
                den = den * (xi - xj) % ORDER
        scalars.append(num * inv(den) % ORDER)
    return multiexp(scalars, list(points))


def make_outputs(mpk, count):
    """Sender side: count outputs to one account. Returns [(acc, info, s)], s known to the sender."""
    outs = []
    for _ in range(count):
        tdk = random_scalar()
        _, acc, info = otaccgen(mpk, 1000, 1, tdk=tdk)
        outs.append((acc, info, ka_key(tdk, mpk.vek, 1)))
    return outs


def run_q(q, trials):
    hits = {m: 0 for m in range(1, q + 2)}
    false_pos = 0
    refused = 0
    for _ in range(trials):
        mpk, msk, _ = sakgen(q=q)
        outs = make_outputs(mpk, q + 2)               # q+1 observed uses + 1 target use
        results = [receive(msk, mpk, acc, info) for acc, info, _ in outs]
        refused += results[q] is None                  # the honest wallet stops at use q+1
        tags = [tag_eval(msk.f(s)) for _, _, s in outs]
        xs = [s for _, _, s in outs]
        target_x, target_tag = xs[q + 1], tags[q + 1]
        for m in hits:                                 # Alice has seen m tags
            hits[m] += predict(xs[:m], tags[:m], target_x) == target_tag
        # control: a different recipient's tag must not be predicted
        mpk2, msk2, _ = sakgen(q=q)
        (_, _, s2), = make_outputs(mpk2, 1)
        false_pos += predict(xs[:q + 1], tags[:q + 1], s2) == tag_eval(msk2.f(s2))
    return hits, false_pos, refused


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--seed", type=int, default=5163)
    parser.add_argument("--q", type=int, nargs="+", default=[1, 2, 3, 5])
    parser.add_argument("--trials", type=int, default=10)
    args = parser.parse_args(argv)

    print(f"q-bound linkability | trials={args.trials} (keys use OS randomness; --seed unused)")
    print("Alice made every output, so she knows each s_i. 'predicted' = she computed the next tag.\n")
    for q in args.q:
        hits, false_pos, refused = run_q(q, args.trials)
        print(f"q = {q}   (key supports {q} uses; wallet refused use #{q + 1} in "
              f"{100 * refused / args.trials:.0f}% of trials)")
        for m, h in hits.items():
            note = "  <- first point where it works (q+1 tags)" if m == q + 1 else ""
            print(f"   tags seen = {m:>2}   next tag predicted: {100 * h / args.trials:>4.0f}%{note}")
        print(f"   control: other recipient's tag predicted: {100 * false_pos / args.trials:.0f}%\n")


if __name__ == "__main__":
    main()
