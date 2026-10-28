# SuccinCT in Python — FIT5163 Programming Assignment

Implementation of *SuccinCT: Succinct Confidential Transaction for Miner Privacy* (Chen et al.):
stealth one-time accounts with polynomial keys/tags, a ring multi-signature over Eq. 5, a toy
blockchain, and simulations of the paper's two miner attacks and their mitigations.

**Substitution:** the paper's Bulletproofs++ NIZK is replaced by a linear-size Σ-protocol for the
Eq. 5 relation plus an aggregated Bulletproofs (2018) range proof. Appendix C.3 of the paper states
the scheme works with any NIZK for the inner-product relation.

**Group:** secp256k1 (prime order). Point arithmetic is done by libsecp256k1 (Bitcoin Core's audited,
constant-time library) through `coincurve`; `succinct/group.py` wraps it and handles the identity point,
which libsecp256k1 can't represent. Ristretto255 was dropped because PyNaCl doesn't expose it. Code uses additive notation: the paper's `G^x · Y` is `x*G + Y`.
Scalars are plain `int`s mod `ORDER`.

## Layout

```
succinct/          core library
  group.py         secp256k1 Point (wraps libsecp256k1 via coincurve), multiexp, hash_to_scalar/point, generators U, V, W, G'
  transcript.py    the paper's H, H_a, H_b, H_c, H_n plus a Fiat–Shamir Transcript
  pedersen.py      Com(a; ck) = a*V + ck*W and vector Pedersen
  tagging.py       TagKGen / TagEval
  keyagreement.py  hashed Diffie–Hellman
  stealth.py       SAKGen, OTAccGen, View, Receive, miner keys (q = 0)
  nizk/
    relation.py    Eq. 5 Statement/Witness and relation_holds (contract between Spend and the proof)
    stub.py        placeholder proof (witness in the clear, NOT private)
    sigma_ring.py  Σ-protocol for Eq. 5, O(S*n) size, includes the range proof
    rangeproof.py  aggregated Bulletproofs range proof on the outputs
    ipa.py         Bulletproofs inner-product argument (used by rangeproof)
    util.py        scalar-vector helpers and input checks
  ct.py            Spend, Verify, Mine (paper §6.2)
  wallet.py        self-transfer and multi-self-transfer (§3.1 wallet policies, not consensus rules)
  chain.py         minimal toy blockchain: genesis outputs, submit (runs Verify), mine_block
  serialize.py     byte encodings and measured sizes
attacks/           miner-privacy, anonymity-reduction, related-key tag, q-bound experiments
eval/              timing/size benchmarks, Table 1 size model, plots/
tests/             unit, property-based and tamper tests
demo.py            scripted end-to-end scenario for the live demo
docs/              team notes (PART_A_NOTES.md: interfaces, decisions, paper issues found)
```

Any proof system plugs in through `prove(stmt, wit)` / `verify(stmt, proof)`, passed as
`nizk=` to `ct.spend`, `ct.verify` or `Chain(nizk=...)`. The default is the real proof,
`nizk.sigma_ring`. Pass `nizk=stub` explicitly for the fast placeholder, which checks the
scheme's algebra but reveals the witness, so never benchmark or demo privacy with it.
`tests/test_ct.py` runs its whole suite with both.

## Setup

Needs Python 3.11-3.13: `coincurve` 21.0.0 ships prebuilt wheels only up to 3.13, so `pip install` fails on 3.14.

```bash
python -m venv .venv
. .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python -m pytest
```

To regenerate every table and plot (fixed seed 5163 by default):

```bat
run_all.bat              :: full run as in the plan: rings 128-1024, 100 timing runs each (over an hour)
run_all.bat quick        :: smoke run, a few minutes; writes to eval\results\quick and eval\plots\quick
run_all.bat seed 42      :: another seed, works with quick too
```

On macOS/Linux use `./run_all.sh` with the same arguments. Both use `.venv` when it exists.
Outputs: `eval/results/` holds the timing and size CSVs and each attack's table as `<attack>.txt`;
`eval/plots/` holds the size-model figures (PNG and CSV). The script stops at the first failing step.

## Attacks and mitigations (Part C)

Five experiments on a local toy chain. Each takes `--seed` (default 5163); keys use OS
randomness, so exact percentages vary a little between runs.

| Script | Paper | What it shows |
|--------|-------|---------------|
| `attacks/miner_privacy.py` | §3.1 | Eve holds the recipient's view key and matches `output + fee` to a coinbase amount in the ring. Compares no mitigation, self-transfer, self-transfer + at-most-(S-1)-miners ring rule, and a careless self-transfer. |
| `attacks/anonymity_reduction.py` | §3.2 | A coinbase decoy smaller than `output + fee` cannot be the sole spender, so it shrinks the anonymity set. With the S-1 rule the set stays full and `Verify` rejects coinbase-stuffed rings (returns `None`, the paper's ⊥). |
| `attacks/related_key_tag.py` | §5 | A sender who knows the shared secrets links tags of the naive `sk = H(s) + lsk` form. The polynomial tag `U^f(s)` resists the same checks. |
| `attacks/q_bound_linkability.py` | §5 | Interpolating `U^f(s)` through `q+1` tags predicts the next tag; with `q` or fewer it fails. This is why a long-term key has a use limit of `q`. |
| `attacks/chain_scenario.py` | §3.1, §3.2 | End to end on the real `Chain` (`mine_block`, `submit`): a coinbase spent alone is refused by the wallet and rejected by the chain (⊥); a coinbase plus an ordinary coin with a real self-transfer is accepted and Eve falls to chance; a careless self-transfer is also accepted and Eve still wins. Ordinary rings contain no coinbase decoys. |

```bash
python -m attacks.miner_privacy --trials 30 --ring-sizes 8 16 32
python -m attacks.miner_privacy --trials 30 --ring-sizes 128 256 512 1024
python -m attacks.anonymity_reduction --trials 30 --ring-sizes 8 16 32
python -m attacks.related_key_tag --trials 20
python -m attacks.q_bound_linkability --q 1 2 3 5 --trials 10
python -m attacks.chain_scenario --trials 200 --ring-sizes 8 16 32 64
python -m attacks.miner_privacy --trials 5 --ring-sizes 8 --proof real   # sigma_ring instead of the stub
python -m attacks.chain_scenario --trials 2 --ring-sizes 8 --proof real   # same, with sigma_ring
python -m pytest tests/test_attacks.py                                   # fast checks of all of them
```

How to read the output
- **Eve success** is how often she names a real input. **chance** is a blind guess (real inputs / ring size). A mitigation works when success falls to about the chance column.
- **certain** counts exact `output + fee = coinbase` matches.
- Rows marked "legacy" in `miner_privacy.py` are observable-only transactions: `Spend` and `Verify` correctly refuse to build them, and Eve never uses the signature. `chain_scenario.py` shows the same refusal on the real chain.

Limits
- Eve is the paper's passive observer using only the §3 arithmetic. Ring-membership statistics and timing are out of scope.
- A failed linking test is not a security proof; the proof is the DDH argument in the paper.
- `chain.py` is minimal: no coinbase maturity, no block structure beyond `mine_block`, uniform decoy choice (Monero uses an age-based gamma distribution, Appendix F). The attacks do not depend on these.
- Small trial counts are noisy (20 trials can read 15% to 40% against a 25% baseline). Use 200 or more for any number you quote.
- Attacks 3 and 4 bypass `Receive`'s use counter on purpose to show what the limit protects against.

## Environment

| Item   | Value |
|--------|-------|
| Python | TODO  |
| OS     | TODO  |
| CPU    | TODO  |

## Provenance

| Component | Source |
|-----------|--------|
| Crypto core, Spend/Verify/Mine, wallet helpers, demo (Part A) | own code, AI-assisted (Claude) |
| Curve arithmetic | libsecp256k1 via `coincurve` 21.0.0 (MIT); cross-checked against an independent textbook implementation in `tests/reference_curve.py` |
| NIZK: Σ-protocol, range proof, IPA (Part B) | own code, AI-assisted; follows Bünz et al. 2018 (Bulletproofs) and Groth–Kohlweiss 2015 (bit-commitment trick) |
| Attack simulations, end-to-end chain scenario, shared toy world, attack tests (Part C) | own design; first drafts of the scripts AI-assisted (Claude), reviewed, run and tested by the author; follows the paper's §3 and §5 |

All experiments run on the local toy chain only.
