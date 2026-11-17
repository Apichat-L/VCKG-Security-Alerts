# Evaluation, Part A4: ranking by the consequence measured in the lab

Generated 2026-11-17 by `python -m eval_kg consequence`. β = 0.5, γ = 0.5. EPSS v2026.06.15. Protocol: `evaluation/README.md` (A4).

**Question.** The EVS claims to prioritise a vulnerability by what its exploitation would *do in this network*, which a CVSS base score cannot see. A4 checks that claim against what the lab *measured*: for each asset × CVE pair, the number of other hosts actually affected in the CVE's impact mode.

**Label (grade 0–3, capped).** Compromise-mode CVE (C or I impact): hosts usable with what is stored on the asset (`measure-usable`, 2026-11-16T18:27:39+00:00). Disruption-mode CVE (availability only): hosts whose service fails when the asset stops (`measure-deps`, 2026-11-16T18:38:31+00:00). Both are measured in the running lab and read none of the score's inputs (CR/IR/AR, CVSS, KEV, EPSS).

**Items.** 615 asset × CVE pairs (the whole graph inventory, no sampling), 388 with grade ≥ 1 (prevalence 0.63, the AP of a random ranking). Grades: 0: 227, 1: 291, 2: 95, 3: 2.

**Threat to validity.** The blast radius inside L4 is built from `CONNECTS_TO` edges written from the lab design, and Part B shows it matches the same measurements. A4 therefore tests that the EVS carries measured consequence through to the *ranking* (CVSS cannot, whatever its quality); it is not an exploit-prediction test (A1/A3) and not a claim that the edges were discovered independently.

## 1. Ranking quality per score

Expected values over random orders within tied scores. τ-b and concordance are against the grade over all item pairs (concordance: share of differently-graded pairs ordered correctly, a tie counts ½; 0.5 = chance).

| Score | NDCG@10 | NDCG@50 | NDCG (full) | P@50 | AP | Kendall τ-b | Pair concordance |
|---|---:|---:|---:|---:|---:|---:|---:|
| L0 | 0.078 | 0.190 | 0.726 | 0.693 | 0.637 | -0.043 | 0.474 |
| L1 | 0.044 | 0.201 | 0.732 | 0.772 | 0.711 | 0.067 | 0.542 |
| L2 | 0.042 | 0.191 | 0.730 | 0.764 | 0.714 | 0.076 | 0.547 |
| L3 | 0.166 | 0.219 | 0.743 | 0.766 | 0.719 | 0.078 | 0.549 |
| L4 | 0.325 | 0.454 | 0.809 | 1.000 | 0.882 | 0.317 | 0.700 |
| EPSS | 0.310 | 0.339 | 0.770 | 0.800 | 0.686 | 0.026 | 0.517 |
| KEV | 0.301 | 0.310 | 0.770 | 0.660 | 0.646 | 0.052 | 0.505 |
| SSVC | 0.305 | 0.329 | 0.776 | 0.877 | 0.780 | 0.156 | 0.578 |
| WazuhVD | 0.078 | 0.190 | 0.726 | 0.693 | 0.637 | -0.043 | 0.474 |
| Random | 0.122 | 0.257 | 0.749 | 0.660 | 0.624 | -0.024 | 0.485 |

Gain in NDCG@50 with a 95% paired-bootstrap CI (resampled within each grade; * = CI excludes 0):

| Comparison | Δ NDCG@50 [95% CI] |
|---|---|
| L1 − L0 | +0.011 [-0.024, +0.042] |
| L2 − L1 | -0.009 [-0.032, +0.003] |
| L3 − L2 | +0.028 [+0.004, +0.075] * |
| L4 − L3 | +0.235 [+0.143, +0.293] * |
| L4 − L0 | +0.264 [+0.165, +0.328] * |
| L4 − EPSS | +0.115 [+0.027, +0.196] * |
| L4 − KEV | +0.144 [+0.039, +0.200] * |
| L4 − SSVC | +0.126 [+0.017, +0.185] * |
| L4 − WazuhVD | +0.264 [+0.165, +0.328] * |
| L4 − Random | +0.198 [+0.059, +0.283] * |

## 2. The same CVE on different hosts

38 CVEs are present on two or more hosts whose measured consequence differs. CVSS gives every copy the same score, so it can only tie them (concordance 0.5). Concordance pooled over the host pairs, 95% CI from a bootstrap over CVEs.

| Score | Host pairs | Ordered like the lab | Tied | Reversed | Concordance [95% CI] |
|---|---:|---:|---:|---:|---|
| L0 | 169 | 0 | 169 | 0 | 0.500 [0.500, 0.500] |
| L1 | 169 | 142 | 27 | 0 | 0.920 [0.910, 0.934] |
| L2 | 169 | 142 | 27 | 0 | 0.920 [0.910, 0.934] |
| L3 | 169 | 142 | 27 | 0 | 0.920 [0.910, 0.934] |
| L4 | 169 | 169 | 0 | 0 | 1.000 [1.000, 1.000] |
| EPSS | 169 | 0 | 169 | 0 | 0.500 [0.500, 0.500] |
| KEV | 169 | 0 | 169 | 0 | 0.500 [0.500, 0.500] |
| SSVC | 169 | 46 | 123 | 0 | 0.636 [0.574, 0.698] |
| WazuhVD | 169 | 0 | 169 | 0 | 0.500 [0.500, 0.500] |
| Random | 169 | 79 | 0 | 90 | 0.467 [0.380, 0.549] |

Examples (same CVE, same CVSS base, different host):

| CVE | Host | Mode | Measured affected hosts | L0 | L1 | L3 | EVS (L4) |
|---|---|---|---|---:|---:|---:|---:|
| CVE-2016-20012 | Jump | compromise | HR-App, Jenkins | 5.3 | 6.1 | 4.6 | 6.4 |
| CVE-2016-20012 | Admin-PC | compromise | Files-SMB | 5.3 | 6.1 | 4.6 | 5.8 |
| CVE-2016-20012 | Dev-PC | compromise | ∅ | 5.3 | 5.3 | 4.0 | 4.0 |
| CVE-2016-20012 | Dep-PC | compromise | ∅ | 5.3 | 4.6 | 3.3 | 3.3 |
| CVE-2020-14145 | Jump | compromise | HR-App, Jenkins | 5.9 | 7.7 | 6.5 | 9.0 |
| CVE-2020-14145 | Admin-PC | compromise | Files-SMB | 5.9 | 7.7 | 6.5 | 8.2 |
| CVE-2020-14145 | Dev-PC | compromise | ∅ | 5.9 | 5.9 | 4.9 | 4.9 |
| CVE-2020-14145 | Dep-PC | compromise | ∅ | 5.9 | 4.1 | 3.2 | 3.2 |
| CVE-2024-6387 | Jump | compromise | HR-App, Jenkins | 8.1 | 8.1 | 7.1 | 9.8 |
| CVE-2024-6387 | Admin-PC | compromise | Files-SMB | 8.1 | 8.1 | 7.1 | 8.9 |
| CVE-2024-6387 | Dev-PC | compromise | ∅ | 8.1 | 7.8 | 6.8 | 6.8 |
| CVE-2024-6387 | Dep-PC | compromise | ∅ | 8.1 | 6.3 | 5.4 | 5.4 |
| CVE-2025-26465 | Jump | compromise | HR-App, Jenkins | 6.8 | 7.5 | 6.7 | 9.3 |
| CVE-2025-26465 | Admin-PC | compromise | Files-SMB | 6.8 | 7.5 | 6.7 | 8.4 |
| CVE-2025-26465 | Dev-PC | compromise | ∅ | 6.8 | 6.8 | 6.1 | 6.1 |
| CVE-2025-26465 | Dep-PC | compromise | ∅ | 6.8 | 4.8 | 4.1 | 4.1 |

## 3. Ties in the CVSS base score that the EVS breaks

- Pairs of items with the **same CVSS base score**: 14916. The EVS separates 12262 of them (82%).
- Of the tied pairs whose measured consequence differs (7501): EVS orders **6714** like the lab, 764 the other way, 23 still tied.

## 4. Per asset

| Asset | CR/IR/AR | Internet path | Measured: usable / dependents | CVEs | mean L0 | mean EVS | mean grade |
|---|---|---|---|---:|---:|---:|---:|
| API | H/H/M | yes | 1 / 2 | 7 | 8.57 | 9.59 | 1.14 |
| DNS | L/H/H | yes | 0 / 1 | 47 | 7.20 | 9.19 | 0.77 |
| Web | M/M/H | yes | 1 / 1 | 69 | 7.42 | 8.78 | 1.00 |
| HR-App | H/H/L | yes | 1 / 1 | 59 | 7.80 | 8.66 | 1.00 |
| Gitea | H/H/M | yes | 1 / 1 | 45 | 6.87 | 8.03 | 1.00 |
| Redis | M/M/M | yes | 0 / 1 | 18 | 8.06 | 7.93 | 0.28 |
| Jenkins | M/H/M | yes | 2 / 1 | 58 | 5.98 | 7.62 | 1.98 |
| Jump | H/H/M | no | 2 / 0 | 40 | 5.90 | 7.52 | 1.85 |
| Nginx | M/M/H | yes | 1 / 0 | 22 | 6.31 | 7.48 | 0.77 |
| Admin-PC | H/H/L | no | 1 / 0 | 40 | 6.10 | 7.04 | 0.95 |
| HR-DB | H/H/M | yes | 0 / 2 | 22 | 7.41 | 7.02 | 0.00 |
| PostgreSQL | H/H/M | yes | 0 / 3 | 46 | 7.03 | 6.87 | 0.13 |
| Files-SMB | H/M/M | yes | 0 / 1 | 5 | 6.40 | 6.72 | 0.60 |
| Mail | H/M/M | yes | 0 / 0 | 38 | 5.72 | 6.11 | 0.00 |
| Monitoring | M/M/L | no | 1 / 0 | 19 | 6.79 | 5.75 | 0.63 |
| Dev-PC | M/M/L | no | 0 / 0 | 40 | 6.10 | 4.88 | 0.00 |
| Dep-PC | L/L/L | no | 0 / 0 | 40 | 6.10 | 3.76 | 0.00 |
