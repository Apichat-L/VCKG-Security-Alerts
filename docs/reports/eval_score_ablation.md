# Evaluation, Part A: score ablation (L0 → L4) against pentest ground truth

Generated 2026-11-17 by `python -m eval_kg score-ablation`. Protocol: `docs/evaluation.md`. β = 0.5, γ = 0.5. EPSS v2026.06.15. Tied scores: every metric is the expected value over random orders within the tie (not the id order); EVS scores tied at the cap of 10 are ordered by the uncapped Env·(1+βP) (docs/scoring.md).

Ladder: L0 CVSS base · L1 + CR/IR/AR · L2 + MAV (Internet reachability) · L3 + E (alert/KEV/SSVC) · L4 + P(a,c) over the blast radius = EVS. Baselines (not our score): EPSS percentile, KEV, CISA SSVC, Wazuh rule.level, WazuhVD (the CVSS base Wazuh's vulnerability detector shows for the pair), Random (chance level).

## A1. Vulnerabilities on assets (asset × CVE, no alert)

34 labelled pairs from `pentest_results.csv` (25 exploited); `not_tried` pairs are left out. Relevance = exploited (1/0). Bootstrap resamples pairs. Origin: 0 drawn by the sampler (`pentest_candidates.csv`), 34 hand-picked. WazuhVD: 4 pairs reported by Wazuh, 30 not (CVSS base used). Not scorable (no CVSS v3.1 vector, or not in the inventory): HR-App/CVE-2017-12617, Jump/CVE-2023-48795.

| Score | NDCG@5 | NDCG@10 | P@5 | P@10 | MRR | AP | Rank of first true item |
|---|---:|---:|---:|---:|---:|---:|---:|
| L0 | 0.780 | 0.773 | 0.733 | 0.750 | 1.000 | 0.748 | 1.0 |
| L1 | 0.780 | 0.711 | 0.733 | 0.660 | 1.000 | 0.736 | 1.0 |
| L2 | 0.780 | 0.711 | 0.733 | 0.660 | 1.000 | 0.740 | 1.0 |
| L3 | 0.913 | 0.757 | 0.867 | 0.675 | 1.000 | 0.763 | 1.0 |
| L4 | 0.723 | 0.609 | 0.600 | 0.500 | 1.000 | 0.720 | 1.0 |
| EPSS | 0.684 | 0.596 | 0.600 | 0.500 | 1.000 | 0.724 | 1.0 |
| KEV | 0.874 | 0.820 | 0.831 | 0.775 | 1.000 | 0.796 | 1.0 |
| SSVC | 0.777 | 0.679 | 0.700 | 0.600 | 1.000 | 0.731 | 1.0 |
| WazuhVD | 0.780 | 0.773 | 0.733 | 0.750 | 1.000 | 0.748 | 1.0 |
| Random | 0.447 | 0.641 | 0.600 | 0.800 | 0.333 | 0.753 | 3.0 |

Gain in NDCG@10 with a 95% paired-bootstrap CI, resampling positives and negatives separately (* = CI excludes 0):

| Comparison | Δ NDCG@10 [95% CI] |
|---|---|
| L1 − L0 | -0.062 [-0.195, +0.039] |
| L2 − L1 | +0.000 [-0.064, +0.000] |
| L3 − L2 | +0.046 [+0.000, +0.130] |
| L4 − L3 | -0.148 [-0.350, +0.000] |
| L4 − EPSS | +0.013 [-0.274, +0.227] |
| L4 − KEV | -0.211 [-0.441, -0.017] * |
| L4 − SSVC | -0.071 [-0.293, +0.123] |
| L4 − WazuhVD | -0.165 [-0.405, +0.079] |
| L4 − Random | -0.033 [-0.475, +0.291] |

## A1s. Sampled pairs only

0 sampled pairs labelled yes/no, 0 exploited: nothing to rank yet.

## A2. Alerted vulnerability instances, per pentest scenario

5 scenarios, 7 instances in their time windows. Grades 3/2/1/0 from the pentest record. Metrics averaged over scenarios; bootstrap over scenarios.

| Score | NDCG@5 | NDCG@10 | P@5 | P@10 | MRR | AP | Rank of first true item |
|---|---:|---:|---:|---:|---:|---:|---:|
| L0 | 0.877 | 0.877 | 0.080 | 0.040 | 0.400 | 1.000 | 1.0 |
| L1 | 0.877 | 0.877 | 0.080 | 0.040 | 0.400 | 1.000 | 1.0 |
| L2 | 0.877 | 0.877 | 0.080 | 0.040 | 0.400 | 1.000 | 1.0 |
| L3 | 0.877 | 0.877 | 0.080 | 0.040 | 0.400 | 1.000 | 1.0 |
| L4 | 0.877 | 0.877 | 0.080 | 0.040 | 0.400 | 1.000 | 1.0 |
| EPSS | 0.877 | 0.877 | 0.080 | 0.040 | 0.400 | 1.000 | 1.0 |
| KEV | 0.877 | 0.877 | 0.080 | 0.040 | 0.349 | 0.873 | 1.5 |
| SSVC | 0.877 | 0.877 | 0.080 | 0.040 | 0.349 | 0.873 | 1.5 |
| Wazuh | 0.877 | 0.877 | 0.080 | 0.040 | 0.349 | 0.873 | 1.5 |
| WazuhVD | 0.877 | 0.877 | 0.080 | 0.040 | 0.400 | 1.000 | 1.0 |
| Random | 0.877 | 0.877 | 0.080 | 0.040 | 0.300 | 0.750 | 2.0 |

Gain in NDCG@10 with a 95% paired-bootstrap CI, resampling positives and negatives separately (* = CI excludes 0):

| Comparison | Δ NDCG@10 [95% CI] |
|---|---|
| L1 − L0 | +0.000 [+0.000, +0.000] |
| L2 − L1 | +0.000 [+0.000, +0.000] |
| L3 − L2 | +0.000 [+0.000, +0.000] |
| L4 − L3 | +0.000 [+0.000, +0.000] |
| L4 − EPSS | +0.000 [+0.000, +0.000] |
| L4 − KEV | +0.000 [-0.185, +0.185] |
| L4 − SSVC | +0.000 [-0.185, +0.185] |
| L4 − Wazuh | +0.000 [-0.185, +0.185] |
| L4 − WazuhVD | +0.000 [+0.000, +0.000] |
| L4 − Random | +0.000 [-0.369, +0.369] |
