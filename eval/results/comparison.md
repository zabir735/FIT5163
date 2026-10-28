| Ring | Paper spend (ms) | Ours spend (ms) | Paper verify (ms) | Ours verify (ms) | Paper tx (B) | Ours tx (B) |
|---:|---:|---:|---:|---:|---:|---:|
| 128 | 2.01 ± 0.32 | 115.0 ± 24.0 | 1.25 ± 0.22 | 39.0 ± 7.6 | 1,648 | 9,993 |
| 256 | 2.18 ± 0.10 | 181.7 ± 44.2 | 1.39 ± 0.12 | 69.7 ± 16.5 | 2,224 | 18,697 |
| 512 | 2.65 ± 0.13 | 271.3 ± 58.8 | 1.81 ± 0.21 | 122.8 ± 28.6 | 3,312 | 36,105 |
| 1024 | 3.56 ± 0.16 | 488.3 ± 98.7 | 2.61 ± 0.17 | 230.6 ± 49.4 | 5,424 | 70,921 |

Growth from ring 128 to 1024 (largest / smallest):
paper spend x1.78, ours x4.25; paper verify x2.09, ours x5.91; paper tx size x3.29, ours x7.10.

Paper: Table 3 timings (Go, bn256, Bulletproofs++, Apple M1, 1 thread, 100 runs) and
Table 1 size formulas (S = T = 2). Ours: Python, secp256k1 via libsecp256k1,
linear Sigma-protocol + Bulletproofs range proof, 2 inputs, 2 outputs, 1 thread.
