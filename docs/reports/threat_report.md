# Threat report: Environmental Vulnerability Score (EVS)

Generated 2026-11-16 by `python -m score_kg report`. Method: `docs/scoring.md` (paper §III.A.2–3).

| Parameter / input | Value |
|---|---|
| β (propagation uplift bound), γ (distance discount), k (blast-radius depth) | 0.5, 0.5, 1 |
| Zones reachable from the Internet (Internet) | APP, DATA, DMZ |
| CTI graph | CVEs published 2024 and later |
| Distro security data (OSV) | downloaded ? |
| EPSS (baseline only, not in the EVS) | model -, - |

`EVS(c,u) = min(10, Env(c,u) · (1 + β·P(u)))`. Env is the CVSS v3.1 Environmental score with CR/IR/AR of the asset, MAV from Internet reachability of its zone, and E = H for the alerted CVE or from KEV/SSVC exploitation otherwise. P(u) is the discounted criticality of the assets reachable from u.

## 1. Alerted vulnerabilities, by EVS

One row per vulnerability instance (a, c): an alert that reports CVE c on asset a.

| # | EVS (level) | CVSS base (band) | Env | P(u) | CVE | Asset (zone) | On asset per graph | Blast radius (k=1) | Event | Count |
|---:|---|---|---:|---:|---|---|---|---|---|---:|
| | no alert reports a CVE yet | | | | | | | | | |

## 2. Details

## 3. Alerts that report no CVE (not scored by the method)

The EVS is defined for a vulnerability instance (a, c). These alerts name no CVE; they are listed with their context.

| Wazuh level | Event | Asset | Source | Techniques | Count | Last seen |
|---:|---|---|---|---|---:|---|
| 8 | New user added to the system. (rule 5902) | Admin-PC | unknown | T1136 | 1 | 2026-11-16T14:53:14 |
| 8 | New user added to the system. (rule 5902) | Dep-PC | unknown | T1136 | 1 | 2026-11-16T14:53:16 |
| 8 | New user added to the system. (rule 5902) | Dev-PC | unknown | T1136 | 1 | 2026-11-16T14:53:20 |
| 8 | New user added to the system. (rule 5902) | Jump | unknown | T1136 | 1 | 2026-11-16T14:53:15 |
| 8 | New user added to the system. (rule 5902) | Mail | unknown | T1136 | 1 | 2026-11-16T14:53:17 |
| 7 | Integrity checksum changed. (rule 550) | Dep-PC | unknown | T1565.001 | 12 | 2026-11-16T10:14:29 |
| 3 | Wazuh agent stopped. (rule 506) | Admin-PC | unknown | T1685 | 1 | 2026-11-16T14:53:48 |
| 3 | Wazuh agent stopped. (rule 506) | Dep-PC | unknown | T1685 | 1 | 2026-11-16T14:53:54 |
| 3 | Wazuh agent stopped. (rule 506) | Dev-PC | unknown | T1685 | 1 | 2026-11-16T14:53:55 |
| 3 | Wazuh agent stopped. (rule 506) | Files-SMB | unknown | T1685 | 1 | 2026-11-16T14:53:12 |
| 3 | PAM: Login session opened. (rule 5501) | Gitea | unknown | T1078 | 9 | 2026-11-16T16:13:27 |
| 3 | Wazuh agent stopped. (rule 506) | Jenkins | unknown | T1685 | 1 | 2026-11-16T14:53:14 |
| 3 | Wazuh agent stopped. (rule 506) | Jump | unknown | T1685 | 1 | 2026-11-16T14:53:49 |
| 3 | Wazuh agent stopped. (rule 506) | Mail | unknown | T1685 | 1 | 2026-11-16T14:53:49 |
| 3 | Wazuh agent stopped. (rule 506) | Nginx | unknown | T1685 | 1 | 2026-11-16T14:53:44 |
| 3 | Wazuh agent stopped. (rule 506) | PostgreSQL | unknown | T1685 | 1 | 2026-11-16T14:53:48 |
| 3 | Wazuh agent stopped. (rule 506) | Web | unknown | T1685 | 1 | 2026-11-16T14:53:41 |

## 4. Assets (vulnerabilities present, no alert: E = X)

| Asset | Zone | CR/IR/AR | Internet path | P(u) | CVEs | Highest CVSS base | Highest EVS |
|---|---|---|---|---:|---:|---:|---:|
| API | APP | H/H/M | yes | 0.031 | 7 | 9.8 | 10.0 |
| HR-App | APP | H/H/L | yes | 0.031 | 59 | 9.8 | 10.0 |
| Jenkins | APP | M/H/M | yes | 0.086 | 58 | 9.8 | 10.0 |
| Redis | DATA | M/M/M | yes | 0.000 | 18 | 10.0 | 10.0 |
| Gitea | APP | H/H/M | yes | 0.016 | 45 | 9.8 | 9.9 |
| DNS | DMZ | L/H/H | yes | 0.000 | 47 | 8.6 | 9.4 |
| Web | DMZ | M/M/H | yes | 0.047 | 69 | 9.8 | 9.4 |
| HR-DB | DATA | H/H/M | yes | 0.000 | 22 | 9.9 | 9.1 |
| Nginx | DMZ | M/M/H | yes | 0.055 | 22 | 8.2 | 9.1 |
| Mail | DMZ | H/M/M | yes | 0.031 | 38 | 9.1 | 8.8 |
| Jump | MGMT | H/H/M | no | 0.121 | 40 | 9.4 | 8.6 |
| Admin-PC | Office | H/H/L | no | 0.031 | 40 | 9.8 | 8.3 |
| Files-SMB | DATA | H/M/M | yes | 0.000 | 5 | 8.8 | 8.1 |
| PostgreSQL | DATA | H/H/M | yes | 0.000 | 46 | 8.8 | 8.1 |
| Monitoring | MGMT | M/M/L | no | 0.031 | 19 | 9.1 | 7.8 |
| Dev-PC | Office | M/M/L | no | 0.000 | 40 | 9.8 | 7.7 |
| Dep-PC | Office | L/L/L | no | 0.000 | 40 | 9.8 | 6.3 |

### Top 20 by EVS

| Asset | CVE | Source | CVSS base (band) | Env | EVS (level) | Change |
|---|---|---|---|---:|---|---|
| Redis | CVE-2022-0543 | nvd | 10.0 (Critical) | 10.0 | 10.0 (Critical) | = |
| API | CVE-2026-111497 | nvd | 9.8 (Critical) | 9.8 | 10.0 (Critical) | = |
| HR-App | CVE-2025-24813 | nvd | 9.8 (Critical) | 9.8 | 10.0 (Critical) | = |
| Jenkins | CVE-2024-23897 | nvd | 9.8 (Critical) | 9.8 | 10.0 (Critical) | = |
| Gitea | CVE-2026-60004 | nvd | 9.8 (Critical) | 9.8 | 9.9 (Critical) | = |
| Redis | CVE-2022-3734 | nvd | 9.8 (Critical) | 9.8 | 9.8 (Critical) | = |
| API | CVE-2024-3566 | nvd | 9.8 (Critical) | 9.3 | 9.5 (Critical) | = |
| HR-App | CVE-2024-50379 | nvd | 9.8 (Critical) | 9.3 | 9.5 (Critical) | = |
| Redis | CVE-2025-49844 | nvd | 9.9 (Critical) | 9.4 | 9.4 (Critical) | = |
| Web | CVE-2024-38475 | nvd | 9.1 (Critical) | 9.1 | 9.4 (Critical) | = |
| DNS | CVE-2025-40778 | osv:Debian:12 | 8.6 (High) | 9.4 | 9.4 (Critical) | ↑ |
| Web | CVE-2024-38474 | nvd | 9.8 (Critical) | 9.0 | 9.3 (Critical) | = |
| Web | CVE-2024-38476 | nvd | 9.8 (Critical) | 9.0 | 9.3 (Critical) | = |
| Web | CVE-2026-28780 | nvd | 9.8 (Critical) | 9.0 | 9.3 (Critical) | = |
| Web | CVE-2026-29167 | nvd | 9.8 (Critical) | 9.0 | 9.3 (Critical) | = |
| Web | CVE-2026-44631 | nvd | 9.8 (Critical) | 9.0 | 9.3 (Critical) | = |
| Web | CVE-2026-56154 | nvd | 9.8 (Critical) | 9.0 | 9.3 (Critical) | = |
| Web | CVE-2026-57941 | nvd | 9.8 (Critical) | 9.0 | 9.3 (Critical) | = |
| Web | CVE-2026-59797 | nvd | 9.8 (Critical) | 9.0 | 9.3 (Critical) | = |
| Web | CVE-2026-42535 | nvd | 9.1 (Critical) | 9.0 | 9.3 (Critical) | = |

## 5. CVSS base band → EVS level (asset × CVE, no alert)

| CVSS \ EVS | Low | Medium | High | Critical |
|---|---:|---:|---:|---:|
| Low | 39 | 16 |  |  |
| Medium | 24 | 177 | 27 |  |
| High |  | 60 | 203 | 6 |
| Critical |  | 3 | 10 | 50 |

Data: `data/scores/asset_cve_scores.csv`, `data/scores/alert_scores.csv`, structured JSON per instance in `data/reports/assessments/`.
