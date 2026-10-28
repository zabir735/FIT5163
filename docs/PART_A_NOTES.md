# Part A (crypto core): notes for the team

## Run

    pip install -r requirements.txt
    pytest -q          # ~140 tests, a few seconds
    python demo.py

Python 3.11-3.13 (coincurve 21 has no 3.14 build yet). Dependencies: pytest, coincurve 21.0.0 (libsecp256k1).

## Layout (what's done)

| File | Paper | Notes |
|---|---|---|
| `succinct/group.py` | group G | secp256k1 via coincurve (libsecp256k1), prime order. Additive notation: paper `G^x · Y` = code `x*G + Y` |
| `succinct/transcript.py` | H, H_a, H_b, H_c, H_n | Domain-separated hashes + `Transcript` class for the NIZK |
| `succinct/pedersen.py` | App. C.1 | `commit(a, ck) = a*V + ck*W`, `vector_commit` |
| `succinct/tagging.py` | §6.1.1 | `tag_kgen(x) = x*G`, `tag_eval(x) = x*U` |
| `succinct/keyagreement.py` | §6.1.2 | hashed DH |
| `succinct/stealth.py` | SAKGen, OTAccGen, View, Receive | polynomial keys, q limit, miner keys |
| `succinct/nizk/relation.py` | Eq. 5 | **contract with Part B**: `Statement`, `Witness`, `relation_holds` |
| `succinct/nizk/stub.py` | — | placeholder proof (witness in the clear, NOT private) |
| `succinct/ct.py` | Spend, Verify, Mine | consensus rules, ring picking |
| `succinct/wallet.py` | §3.1 Solution 1 | `self_transfer`, `multi_self_transfer` (wallet policies, not consensus rules) |
| `succinct/chain.py` | — | **placeholder for Part C** |
| `demo.py` | — | live demo script |

## For Part B (NIZK)

Write `succinct/nizk/sigma_ring.py` with

    prove(stmt: Statement, wit: Witness) -> proof
    verify(stmt: Statement, proof) -> bool

and pass it as `nizk=` to `ct.spend`, `ct.verify` or `Chain(nizk=...)`.
`relation.py` documents exactly what to prove; `Statement` already gives you
`base_z()`, `base_ck()`, `Y(j, i)` and `target()`.
Test oracle: your `verify` must return True exactly when `relation_holds` does.
Range proofs on outputs are part of the relation (condition 4).

**Your transcript must absorb the whole statement** (every field of
`Statement`), not just the commitments. See "gamma" below for why.

## For Part C (chain + attacks)

`ct.verify` needs only `chain.get(ref) -> (Account, info) | None`,
`chain.is_spent(tag) -> bool`, and `len(chain)` for `pick_ring`. Extend
`chain.py` freely (maturity, blocks, gamma decoy sampling) but keep those.

## Decisions to put in the spec

- Curve secp256k1 via coincurve (Bitcoin's audited libsecp256k1). Ristretto dropped (PyNaCl has no bindings;
  the paper used bn256, not ristretto). ~0.05 ms per scalar mult. libsecp256k1 can't represent the identity; Point stores it as None (tests/test_backend.py).
- Hashes: SHA3-512 reduced mod order, type- and length-prefixed encoding.
- beta = 64-bit amounts; max 16 outputs; default q = 90.
- View takes (vdk, lpk); Receive also takes mpk.
- Miner keys must be fresh per block.

## Paper issues found while implementing (for the report)

1. **tek is unbound in §6.2.** h = H(mu, R, beta) and gamma = H_c(h, T, outputs, fee)
   never hash the tek. gamma only folds the balance equation in, and an honest
   witness satisfies that for every gamma (`test_gamma_alone_binds_nothing`),
   so a relayer could swap tek and the tx would still verify, making all
   outputs unrecoverable. Fix: mu = full tx prefix, as Monero does
   (`ct.tx_prefix`). Found by `test_tampered_tx_rejected[info]`.
2. **A coinbase can never be spent on its own.** The S-1 rule with S = 1 allows
   zero miner accounts in the ring, so a miner needs an ordinary coin as a
   second input. A brand-new solo miner with no other coins is stuck.
3. **Miner key reuse** repeats the tag (`test_miner_key_reuse_repeats_the_tag`).
4. **beta** means both amount bit length and H_b's output.
5. **§5 vs §6.2**: §5 has a separate R_U and two gammas; §6.2 folds into
   R = (G·U^beta)^r with one gamma; the balance proof still mentions R_U.
6. **View needs lpk**, not just vdk, to recompute pk.
7. **Multi-self-transfer needs an ordinary input.** §3.1 describes it as spending
   several coinbases to at least two non-mining accounts, but the paper's own
   S-1 rule (§3.2) refuses S coinbases on their own. A P2Pool miner must add an
   ordinary coin as well (`test_coinbases_alone_are_refused`). Same root cause
   as finding 2.
8. **The S-1 rule keeps coinbases out of every single-input ring.** With S = 1 the
   ring may hold no miner account at all, so coinbases can never be decoys in
   one-input spends (most transactions: the paper cites 70-90% one-input in
   Bitcoin, Appendix D). `attacks/chain_scenario.py` shows 0.00 coinbases per
   ordinary ring. Coinbases then only ever appear in multi-input rings, which
   shrinks the decoy pool for them. Not an attack in itself, but a cost of the
   mitigation the paper doesn't discuss.
