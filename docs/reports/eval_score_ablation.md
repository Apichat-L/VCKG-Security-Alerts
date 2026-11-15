# Evaluation, Part A: score ablation (L0 → L4) against pentest ground truth

Generated 2026-11-15 by `python -m eval_kg score-ablation`. Protocol: `docs/evaluation.md`. β = 0.5, γ = 0.5. EPSS v2026.06.15. Ties are broken by item id.

Ladder: L0 CVSS base · L1 + CR/IR/AR · L2 + MAV (Internet reachability) · L3 + E (alert/KEV/SSVC) · L4 + P(u) = EVS. Baselines (not our score): EPSS percentile, KEV, CISA SSVC, Wazuh rule.level.

## A1. Vulnerabilities on assets (asset × CVE, no alert)

6 labelled pairs from `pentest_results.csv` (1 exploited); `not_tried` pairs are left out. Relevance = exploited (1/0). Bootstrap resamples pairs.

| Score | NDCG@5 | NDCG@10 | P@5 | P@10 | MRR | Rank of first true item |
|---|---:|---:|---:|---:|---:|---:|
| L0 | 1.000 | 1.000 | 0.200 | 0.100 | 1.000 | 1.0 |
| L1 | 1.000 | 1.000 | 0.200 | 0.100 | 1.000 | 1.0 |
| L2 | 1.000 | 1.000 | 0.200 | 0.100 | 1.000 | 1.0 |
| L3 | 1.000 | 1.000 | 0.200 | 0.100 | 1.000 | 1.0 |
| L4 | 1.000 | 1.000 | 0.200 | 0.100 | 1.000 | 1.0 |
| EPSS | 1.000 | 1.000 | 0.200 | 0.100 | 1.000 | 1.0 |
| KEV | 1.000 | 1.000 | 0.200 | 0.100 | 1.000 | 1.0 |
| SSVC | 1.000 | 1.000 | 0.200 | 0.100 | 1.000 | 1.0 |

Gain in NDCG@10 with a 95% paired-bootstrap CI (* = CI excludes 0):

| Comparison | Δ NDCG@10 [95% CI] |
|---|---|
| L1 − L0 | +0.000 [+0.000, +0.000] |
| L2 − L1 | +0.000 [+0.000, +0.000] |
| L3 − L2 | +0.000 [+0.000, +0.000] |
| L4 − L3 | +0.000 [+0.000, +0.000] |
| L4 − EPSS | +0.000 [+0.000, +0.000] |
| L4 − KEV | +0.000 [+0.000, +0.000] |
| L4 − SSVC | +0.000 [+0.000, +0.000] |

## A2. Alerted vulnerability instances, per pentest scenario

5 scenarios, 6 instances in their time windows. Grades 3/2/1/0 from the pentest record. Metrics averaged over scenarios; bootstrap over scenarios.

| Score | NDCG@5 | NDCG@10 | P@5 | P@10 | MRR | Rank of first true item |
|---|---:|---:|---:|---:|---:|---:|
| L0 | 1.000 | 1.000 | 0.040 | 0.020 | 0.200 | 1.0 |
| L1 | 1.000 | 1.000 | 0.040 | 0.020 | 0.200 | 1.0 |
| L2 | 1.000 | 1.000 | 0.040 | 0.020 | 0.200 | 1.0 |
| L3 | 1.000 | 1.000 | 0.040 | 0.020 | 0.200 | 1.0 |
| L4 | 1.000 | 1.000 | 0.040 | 0.020 | 0.200 | 1.0 |
| EPSS | 1.000 | 1.000 | 0.040 | 0.020 | 0.200 | 1.0 |
| KEV | 1.000 | 1.000 | 0.040 | 0.020 | 0.200 | 1.0 |
| SSVC | 1.000 | 1.000 | 0.040 | 0.020 | 0.200 | 1.0 |
| Wazuh | 0.855 | 0.855 | 0.040 | 0.020 | 0.100 | 2.0 |

Gain in NDCG@10 with a 95% paired-bootstrap CI (* = CI excludes 0):

| Comparison | Δ NDCG@10 [95% CI] |
|---|---|
| L1 − L0 | +0.000 [+0.000, +0.000] |
| L2 − L1 | +0.000 [+0.000, +0.000] |
| L3 − L2 | +0.000 [+0.000, +0.000] |
| L4 − L3 | +0.000 [+0.000, +0.000] |
| L4 − EPSS | +0.000 [+0.000, +0.000] |
| L4 − KEV | +0.000 [+0.000, +0.000] |
| L4 − SSVC | +0.000 [+0.000, +0.000] |
| L4 − Wazuh | +0.145 [+0.000, +0.290] |
