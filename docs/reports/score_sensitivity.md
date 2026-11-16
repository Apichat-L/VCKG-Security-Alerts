# Sensitivity of the EVS to β and γ

> **8-host lab.** Generated on the original 8-host lab, before it grew to 17 hosts and a MGMT zone on 2026-11-16 (`lab_env/README.md`). The numbers below are unchanged; rerun the generating command to update them.

Generated 2026-11-15 by `python -m score_kg sensitivity`. Reference: β = 0.5, γ = 0.5. 287 asset × CVE pairs, no alert (E = X).

Kendall τ-b against the reference: min 0.906, max 1.000.

| β | γ | Kendall τ | Same top-10 | Pairs whose level changes |
|---:|---:|---:|---:|---:|
| 0 | 0.25 | 0.970 | 9/10 | 49 |
| 0 | 0.5 | 0.970 | 9/10 | 49 |
| 0 | 0.75 | 0.970 | 9/10 | 49 |
| 0.25 | 0.25 | 0.984 | 10/10 | 24 |
| 0.25 | 0.5 | 0.990 | 10/10 | 21 |
| 0.25 | 0.75 | 0.998 | 10/10 | 16 |
| 0.5 | 0.25 | 0.987 | 10/10 | 21 |
| 0.5 | 0.5 | 1.000 | 10/10 | 0 |
| 0.5 | 0.75 | 0.980 | 9/10 | 3 |
| 0.75 | 0.25 | 0.993 | 10/10 | 21 |
| 0.75 | 0.5 | 0.991 | 10/10 | 3 |
| 0.75 | 0.75 | 0.952 | 6/10 | 33 |
| 1 | 0.25 | 0.997 | 10/10 | 17 |
| 1 | 0.5 | 0.974 | 10/10 | 23 |
| 1 | 0.75 | 0.906 | 5/10 | 50 |
