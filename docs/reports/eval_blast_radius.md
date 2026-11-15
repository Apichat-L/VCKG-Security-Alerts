# Evaluation, Part B: blast-radius variants against the lab

Generated 2026-11-15 by `python -m eval_kg blast-ablation`. Protocol: `docs/evaluation.md`.

Ground truth, measured in the running lab (not read from `lab/*.csv`):

- **network**: TCP reachability from each host (compromise mode, network view), measured 2026-11-15T00:46:14+00:00.
- **usable**: hosts usable with what is stored on each host (compromise mode), measured 2026-11-15T00:46:17+00:00.
- **dependents**: hosts whose service fails when a host is stopped (disruption mode), measured 2026-11-15T00:50:31+00:00.

Variants: B0 none · B1 unrestricted k-hop over any edge type · B2 zone-level · B3 ours undirected · B4 ours (Algorithm 1, k=1) · B5 ours k=2/3.

## network (compromise mode), per asset

| Variant | Precision | Recall | F1 | Mean set size |
|---|---:|---:|---:|---:|
| B0 | 1.000 | 0.000 | 0.000 | 0.00 |
| B1 (k=1) | 0.708 | 0.292 | 0.371 | 1.25 |
| B1 (k=2) | 0.357 | 1.000 | 0.512 | 7.00 |
| B2 | 1.000 | 1.000 | 1.000 | 2.50 |
| B3 | 0.708 | 0.292 | 0.371 | 1.25 |
| B4 | 1.000 | 0.208 | 0.312 | 0.62 |
| B5 (k=2) | 0.938 | 0.292 | 0.375 | 1.00 |
| B5 (k=3) | 0.896 | 0.292 | 0.358 | 1.12 |

Observed sets: API → Files-SMB, Jenkins, PostgreSQL; Admin-PC → Dep-PC, Files-SMB, PostgreSQL; Dep-PC → Admin-PC, Files-SMB, PostgreSQL; Files-SMB → PostgreSQL; Jenkins → API, Files-SMB, PostgreSQL; Nginx → API, Jenkins, Web; PostgreSQL → Files-SMB; Web → API, Jenkins, Nginx

## usable (compromise mode), per asset

| Variant | Precision | Recall | F1 | Mean set size |
|---|---:|---:|---:|---:|
| B0 | 1.000 | 0.375 | 0.375 | 0.00 |
| B1 (k=1) | 0.604 | 1.000 | 0.646 | 1.25 |
| B1 (k=2) | 0.089 | 1.000 | 0.156 | 7.00 |
| B2 | 0.208 | 1.000 | 0.312 | 2.50 |
| B3 | 0.604 | 1.000 | 0.646 | 1.25 |
| B4 | 1.000 | 1.000 | 1.000 | 0.62 |
| B5 (k=2) | 0.812 | 1.000 | 0.875 | 1.00 |
| B5 (k=3) | 0.792 | 1.000 | 0.854 | 1.12 |

Observed sets: API → PostgreSQL; Admin-PC → Files-SMB; Dep-PC → ∅; Files-SMB → ∅; Jenkins → API; Nginx → Web; PostgreSQL → ∅; Web → API

## dependents (disruption mode), per asset

| Variant | Precision | Recall | F1 | Mean set size |
|---|---:|---:|---:|---:|
| B0 | 1.000 | 0.500 | 0.500 | 0.00 |
| B1 (k=1) | 0.521 | 0.938 | 0.517 | 1.25 |
| B1 (k=2) | 0.107 | 1.000 | 0.174 | 7.00 |
| B2 | 0.258 | 0.938 | 0.302 | 2.50 |
| B3 | 0.521 | 0.938 | 0.517 | 1.25 |
| B4 | 1.000 | 0.938 | 0.958 | 0.62 |
| B5 (k=2) | 0.917 | 1.000 | 0.950 | 1.00 |
| B5 (k=3) | 0.896 | 1.000 | 0.933 | 1.12 |

Observed sets: API → Jenkins, Web; Admin-PC → ∅; Dep-PC → ∅; Files-SMB → Admin-PC; Jenkins → ∅; Nginx → ∅; PostgreSQL → API, Web; Web → Nginx

## Per (asset, CVE) pair

287 vulnerability instances on the lab assets; each CVE's impact mode picks the direction and the ground truth (compromise → usable, disruption → dependents).

| Variant | Precision | Recall | F1 |
|---|---:|---:|---:|
| B0 | 1.000 | 0.328 | 0.328 |
| B1 (k=1) | 0.677 | 0.997 | 0.718 |
| B1 (k=2) | 0.098 | 1.000 | 0.170 |
| B2 | 0.260 | 0.997 | 0.362 |
| B3 | 0.677 | 0.997 | 0.718 |
| B4 | 1.000 | 0.997 | 0.998 |
| B5 (k=2) | 0.775 | 1.000 | 0.850 |
| B5 (k=3) | 0.764 | 1.000 | 0.840 |

## Cost

| Variant | Mean runtime per query (ms) | Mean affected hosts | Mean non-asset nodes returned |
|---|---:|---:|---:|
| B0 | 0.00 | 0.00 | 0.0 |
| B1 (k=1) | 11.63 | 1.25 | 700.8 |
| B1 (k=2) | 29.44 | 7.00 | 1909.5 |
| B2 | 0.00 | 2.50 | 0.0 |
| B3 | 0.00 | 1.25 | 0.0 |
| B4 | 0.00 | 0.62 | 0.0 |
| B5 (k=2) | 0.00 | 1.00 | 0.0 |
| B5 (k=3) | 0.00 | 1.12 | 0.0 |

## Downstream: L4 ranking with each variant's P(u)

Labels: `evaluation/pentest_results.csv`

| Variant | NDCG@10 (asset × CVE) |
|---|---:|
| B0 | 1.000 |
| B1 (k=1) | 1.000 |
| B1 (k=2) | 1.000 |
| B2 | 1.000 |
| B3 | 1.000 |
| B4 | 1.000 |
| B5 (k=2) | 1.000 |
| B5 (k=3) | 1.000 |
