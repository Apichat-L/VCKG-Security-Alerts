# Evaluation, Part A: score ablation (L0 → L4) against pentest ground truth

Generated 2026-11-17 by `python -m eval_kg score-ablation`. Protocol: `docs/evaluation.md`. β = 0.5, γ = 0.5. EPSS v2026.06.15. Tied scores: every metric is the expected value over random orders within the tie (not the id order); EVS scores tied at the cap of 10 are ordered by the uncapped Env·(1+βP) (docs/scoring.md).

Ladder: L0 CVSS base · L1 + CR/IR/AR · L2 + MAV (Internet reachability) · L3 + E (alert/KEV/SSVC) · L4 + P(a,c) over the blast radius = EVS. Baselines (not our score): EPSS percentile, KEV, CISA SSVC, Wazuh rule.level, WazuhVD (the CVSS base Wazuh's vulnerability detector shows for the pair), Random (chance level).

## A1. Vulnerabilities on assets (asset × CVE, no alert)

9 labelled pairs from `pentest_results.csv` (1 exploited); `not_tried` pairs are left out. Relevance = exploited (1/0). Bootstrap resamples pairs. Origin: 0 drawn by the sampler (`pentest_candidates.csv`), 9 hand-picked. WazuhVD: 2 pairs reported by Wazuh, 7 not (CVSS base used).

| Score | NDCG@5 | NDCG@10 | P@5 | P@10 | MRR | AP | Rank of first true item |
|---|---:|---:|---:|---:|---:|---:|---:|
| L0 | 0.710 | 0.710 | 0.200 | 0.100 | 0.606 | 0.606 | 2.0 |
| L1 | 0.710 | 0.710 | 0.200 | 0.100 | 0.603 | 0.603 | 2.0 |
| L2 | 0.710 | 0.710 | 0.200 | 0.100 | 0.596 | 0.596 | 2.0 |
| L3 | 1.000 | 1.000 | 0.200 | 0.100 | 1.000 | 1.000 | 1.0 |
| L4 | 1.000 | 1.000 | 0.200 | 0.100 | 1.000 | 1.000 | 1.0 |
| EPSS | 1.000 | 1.000 | 0.200 | 0.100 | 1.000 | 1.000 | 1.0 |
| KEV | 1.000 | 1.000 | 0.200 | 0.100 | 1.000 | 1.000 | 1.0 |
| SSVC | 1.000 | 1.000 | 0.200 | 0.100 | 1.000 | 1.000 | 1.0 |
| WazuhVD | 0.710 | 0.710 | 0.200 | 0.100 | 0.606 | 0.606 | 2.0 |
| Random | 0.431 | 0.431 | 0.200 | 0.100 | 0.250 | 0.250 | 4.0 |

Gain in NDCG@10 with a 95% paired-bootstrap CI, resampling positives and negatives separately (* = CI excludes 0):

| Comparison | Δ NDCG@10 [95% CI] |
|---|---|
| L1 − L0 | +0.000 [+0.000, +0.000] |
| L2 − L1 | +0.000 [+0.000, +0.000] |
| L3 − L2 | +0.290 [+0.000, +0.410] |
| L4 − L3 | +0.000 [+0.000, +0.000] |
| L4 − EPSS | +0.000 [+0.000, +0.000] |
| L4 − KEV | +0.000 [+0.000, +0.000] |
| L4 − SSVC | +0.000 [+0.000, +0.000] |
| L4 − WazuhVD | +0.290 [+0.000, +0.410] |
| L4 − Random | +0.569 [+0.000, +0.667] |

## A1s. Sampled pairs only

0 sampled pairs labelled yes/no, 0 exploited: nothing to rank yet.

## A2. Alerted instances

No pentest scenario with alert instances in its window yet.
