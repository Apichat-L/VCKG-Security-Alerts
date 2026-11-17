# Evaluation, Part A3: forward-in-time KEV test on the Wazuh inventory

> **Underpowered.** Only 0 distinct CVE(s) on the lab's inventory were added to KEV after T0 = 2026-05-01 (fewer than 5). The table shows that the test runs; its numbers are not evidence for or against any score. Positives that sit on several hosts count once per host.

Generated 2026-11-17 by `python -m eval_kg kev-forward --t0 2026-05-01`. Method: `eval_kg/kev_forward.py`. Inventory: Wazuh vulnerability detection snapshot 2026-11-16T23:18:53Z ∪ the graph's links. β = 0.5, γ = 0.5. EPSS v2025.03.14 scored 2026-05-01T12:55:00Z. Ties broken by item id.

**Items:** 1268 (asset, CVE) pairs on 17 assets; **positives:** 0 pairs, 0 distinct CVEs added to KEV after T0 (none).

Excluded from the frame: no CVSS v3.1 vector 92, in KEV at T0 4, published after T0 355, no publication date 0.

E uses KEV as of T0 only and drops SSVC exploitation (no assessment date), so **L3 = L2** in this test. Pairs that are not a network service of the host keep their base AV in L2.

| Score | NDCG@10 | NDCG@100 | P@10 | P@100 | MRR | Rank of first positive | Mean rank of positives |
|---|---:|---:|---:|---:|---:|---:|---:|
| L0 | - | - | 0.000 | 0.000 | 0.000 | - | - |
| L1 | - | - | 0.000 | 0.000 | 0.000 | - | - |
| L2 | - | - | 0.000 | 0.000 | 0.000 | - | - |
| L3 | - | - | 0.000 | 0.000 | 0.000 | - | - |
| L4 | - | - | 0.000 | 0.000 | 0.000 | - | - |
| EPSS@T0 | - | - | 0.000 | 0.000 | 0.000 | - | - |
| SSVC@T0 | - | - | 0.000 | 0.000 | 0.000 | - | - |
| WazuhVD | - | - | 0.000 | 0.000 | 0.000 | - | - |

Gain in NDCG@100 with a 95% paired-bootstrap CI over items (* = CI excludes 0):

| Comparison | Δ NDCG@100 [95% CI] |
|---|---|
| L1 − L0 | - |
| L2 − L1 | - |
| L3 − L2 | - |
| L4 − L3 | - |
| L4 − EPSS@T0 | - |
| L4 − SSVC@T0 | - |
| L4 − WazuhVD | - |

Positives and where each score ranks them:

| Asset | CVE | KEV added | CVSS | L0 | L1 | L2 | L3 | L4 | EPSS@T0 | SSVC@T0 | WazuhVD |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
