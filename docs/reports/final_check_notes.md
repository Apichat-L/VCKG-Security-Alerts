## Summary

The whole system was rebuilt from scratch on 2026-11-15: Neo4j wiped to 0 nodes / 0 relationships, the CTI graph reloaded
from the cached sources, the asset graph reloaded and relinked, alerts re-fetched (last 7 days) and re-contextualised,
the EVS recomputed, lab ground truth re-measured, and the stage-5 reports regenerated. Backups of the previous run
(alerts, ground truth, reports, pre-wipe counts) are in `data/backup-2026-11-15/`.

| Check | Result |
|---|---|
| Wipe | 0 nodes, 0 relationships |
| CTI rebuild | exit 0; Vulnerability 406,379 → 406,586 (+207, upstream feeds updated), CPE 378,622 → 378,651 |
| CTI validation | CAPEC→ATT&CK recall 99.63 %, CAUSES_WEAKNESS F1 100 %, EXPLOITED_BY (most-specific CWEs) F1 94.91 % (94.90 % before) |
| Asset graph | 8 assets, 5 zones, 9 services, 7 software; 257 HAS_VULNERABILITY (unchanged); all 7 integrity checks ok; CPE linking 7/7 |
| Unit tests | 75 passed |
| Lab ground truth | re-measured (network, usable, dependents); **identical to the previous measurement** on all three, and every host came back up |
| Alerts | 5,664 raw (7 days) → 183 with graph context (24 raw before) |
| Scored pairs | 287 asset × CVE (288 before): Admin-PC and Dep-PC 41 → 40 (OpenSSH, 40 of 41 OSV CVEs now in the graph), Web 68 → 69. Consistent with refreshed upstream feeds; the individual CVEs were not traced |

## What the results do and do not show

- **Part B is the strongest result and it reproduces.** Against the measured usable-reach truth, B4 (ours, Algorithm 1) has
  precision 1.000, recall 1.000, F1 1.000; B2 (zone-level) 0.312; B1 k=1 0.646; B5 k=2 0.875. Against dependents (disruption),
  B4 F1 is 0.958. **Not in B4's favour:** against raw TCP network reachability, B2 (zone-level) wins (F1 1.000 vs B4 0.312,
  B4 recall 0.208), because B4 follows only the paths the policy and graph model as usable, not every open port.
- **A1 cannot discriminate.** 6 labelled pairs, 1 exploited (Jenkins CVE-2024-23897). Every score, ladder and baseline, ranks it first
  (NDCG@10 1.000 everywhere).
- **A2 is dominated by one artifact and should not be read as five scenarios.** The single alert instance
  `Web | CVE-2024-38476 | rule 31164` is counted in S04, S05, S06 and S07 because those scenarios ran within ~10 s of each other and
  the ±120 s match slack makes their windows overlap (it is graded 0, 0, 0, 1). That is one observation counted four times. It
  depresses MRR (0.200) and P@5 (0.040) identically for every score, so it does not separate any of them. The matching was
  deliberately **not changed** during this run.
- **EVS vs CVSS in A2: no difference.** L0 to L4 are identical because every alerting CVE is CVSS 9.8 (EVS ceiling 10), so ranking within
  a scenario is decided by the id tiebreak, not by the score.
- **EVS vs Wazuh rule.level:** +0.145 NDCG@10, 95 % CI [0.000, 0.290], so the interval touches 0 and this is not significant on its
  own. It is half the earlier S08-only figure (+0.290) because the duplicated S07 instance adds a scenario where every score
  ties. The earlier, cleaner statement still holds in S08: Wazuh ranks the harmless SQLi probe (level 6) above the real Jenkins
  file read (level 3), and every vulnerability-aware score avoids that inversion.
- **Sensitivity is mechanism analysis, not validation.** Over all 287 pairs the EVS keeps the broad CVSS order but reorders within
  it (Kendall tau-b 0.694). There is no outcome label behind it.
- **β / γ:** across the 15 settings the EVS ranking stays within Kendall tau-b ≥ 0.906 of the default. This is stability of the score's
  own ranking, not tuning against ground truth, which the ceiling-saturated labels cannot support.

## Follow-ups this run points to (not done here)

1. Attribute each alert instance to one scenario (for example by requiring the asset and time to match a step, or by
   non-overlapping windows) so S04-S07 stop sharing a single alert.
2. Add exploited CVEs below the 9.8 ceiling on high-value hosts; that is what A1/A2 need before the EVS can be separated from CVSS.
