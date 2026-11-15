# Threat report: Environmental Vulnerability Score (EVS)

Generated 2026-11-15 by `python -m score_kg report`. Method: `docs/scoring.md` (paper §III.A.2–3).

| Parameter / input | Value |
|---|---|
| β (propagation uplift bound), γ (distance discount), k (blast-radius depth) | 0.5, 0.5, 1 |
| Zones reachable from the Internet (Internet) | APP, DATA, DMZ |
| CTI graph | CVEs published 2024 and later |
| Distro security data (OSV) | downloaded ? |
| EPSS (baseline only, not in the EVS) | model v2026.06.15, 2026-11-14 |

`EVS(c,u) = min(10, Env(c,u) · (1 + β·P(u)))`. Env is the CVSS v3.1 Environmental score with CR/IR/AR of the asset, MAV from Internet reachability of its zone, and E = H for the alerted CVE or from KEV/SSVC exploitation otherwise. P(u) is the discounted criticality of the assets reachable from u.

## 1. Alerted vulnerabilities, by EVS

One row per vulnerability instance (a, c): an alert that reports CVE c on asset a.

| # | EVS (level) | CVSS base (band) | Env | P(u) | CVE | Asset (zone) | On asset per graph | Blast radius (k=1) | Event | Count |
|---:|---|---|---:|---:|---|---|---|---|---|---:|
| 1 | **10.0** (Critical) | 9.8 (Critical) | 9.8 | 0.107 | CVE-2024-23897 | Jenkins (APP) | yes | Jenkins, API | Suricata: Alert - LAB TEST Jenkins CLI endpoint request (CVE-2024-23897 surface) (rule 86601) | 22 |

## 2. Details

### 1. CVE-2024-23897 on Jenkins: EVS 10.0 (Critical)

- **Event:** Suricata: Alert - LAB TEST Jenkins CLI endpoint request (CVE-2024-23897 surface) (rule 86601, Wazuh level 3), 22× from 2026-11-14T18:23:47 to 2026-11-14T18:40:22. Source: asset Web 10.10.10.12; destination 10.10.20.22:8080.
- **Asset:** Jenkins (ci/cd, 10.10.20.22, zone APP), CR/IR/AR M/H/M — Builds and deploys the applications: a tampered pipeline compromises every release (IR H); holds deployment secrets (CR M); not customer-facing (AR M).
- **Vulnerability:** CVE-2024-23897, CVSS v3.1 base 9.8 (Critical). Present on the asset according to the graph.
- **Environmental metrics (Table I):** E = H (alert reports this CVE on this asset (also in KEV)); MAV = N (base AV N; zone APP is reachable from the Internet); CR/IR/AR = M/H/M. Vector `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:H/CR:M/IR:H/AR:M/MAV:N` → **Env 9.8**.
- **Propagation:** P(Jenkins) = 0.1071 → EVS = min(10, 9.8 × (1 + 0.5 × 0.1071)) = **10.0**.
- **Blast radius BR_1** (impact mode *compromise*: assets it can reach):

| Asset | Hops | Zone | Role | CR/IR/AR | crit |
|---|---:|---|---|---|---:|
| Jenkins | 0 | APP | ci/cd | M/H/M | 1 |
| API | 1 | APP | api server | H/H/M | 1 |

- **Mitigations (CWE):** Ensure that error messages only contain minimal details that are useful to the i (CWE-22); Firewall (CWE-22); Environment Hardening (CWE-22); Input Validation (CWE-22); Environment Hardening (CWE-22).
- Baselines (not in the EVS): EPSS 0.99999, KEV yes, CISA SSVC Act.

## 3. Alerts that report no CVE (not scored by the method)

The EVS is defined for a vulnerability instance (a, c). These alerts name no CVE; they are listed with their context.

| Wazuh level | Event | Asset | Source | Techniques | Count | Last seen |
|---:|---|---|---|---|---:|---|
| 8 | New user added to the system. (rule 5902) | Dep-PC | unknown | T1136 | 2 | 2026-11-13T14:38:21 |
| 7 | SQL injection attempt. (rule 31103) | API | Web | T1190 | 3 | 2026-11-14T18:40:29 |
| 6 | SQL injection attempt. (rule 31164) | API | Web | T1055, T1190 | 3 | 2026-11-14T18:40:29 |
| 6 | A web attack returned code 200 (success). (rule 31106) | Nginx | Web | T1190 | 3 | 2026-11-14T18:40:36 |
| 6 | A web attack returned code 200 (success). (rule 31106) | Web | Nginx | T1190 | 5 | 2026-11-14T18:40:42 |
| 6 | SQL injection attempt. (rule 31164) | Web | Web | T1055, T1190 | 3 | 2026-11-14T18:40:41 |
| 5 | PAM: User login failed. (rule 5503) | Admin-PC | Dep-PC | T1110.001 | 4 | 2026-11-13T14:38:25 |
| 5 | sshd: authentication failed. (rule 5760) | Admin-PC | Dep-PC | T1021.004, T1110.001 | 4 | 2026-11-13T14:38:27 |
| 5 | PAM: User login failed. (rule 5503) | Dep-PC | Admin-PC | T1110.001 | 1 | 2026-11-13T14:36:42 |
| 5 | sshd: authentication failed. (rule 5760) | Dep-PC | Admin-PC | T1021.004, T1110.001 | 1 | 2026-11-13T14:36:44 |
| 5 | Samba: authentication failed for user alice (NT_STATUS_WRONG_PASSWORD). (rule 100110) | Files-SMB | Dep-PC | T1110 | 2 | 2026-11-13T14:38:29 |
| 3 | Wazuh agent stopped. (rule 506) | API | unknown | T1685 | 3 | 2026-11-14T17:11:10 |
| 3 | Wazuh agent stopped. (rule 506) | Admin-PC | unknown | T1685 | 3 | 2026-11-14T17:08:05 |
| 3 | PAM: Login session opened. (rule 5501) | Admin-PC | unknown | T1078 | 2 | 2026-11-13T14:38:29 |
| 3 | sshd: authentication success. (rule 5715) | Admin-PC | Dep-PC | T1021, T1078 | 2 | 2026-11-13T14:38:29 |
| 3 | Wazuh agent stopped. (rule 506) | Dep-PC | unknown | T1685 | 3 | 2026-11-14T17:08:02 |
| 3 | PAM: Login session opened. (rule 5501) | Dep-PC | unknown | T1078 | 1 | 2026-11-13T14:36:46 |
| 3 | sshd: authentication success. (rule 5715) | Dep-PC | Admin-PC | T1021, T1078 | 1 | 2026-11-13T14:36:46 |
| 3 | Group (or user) deleted from the system. (rule 5903) | Dep-PC | unknown | T1531 | 2 | 2026-11-13T14:38:21 |
| 3 | Samba: user alice authenticated. (rule 100111) | Files-SMB | Admin-PC | T1021.002, T1078 | 34 | 2026-11-13T19:58:55 |
| 3 | Wazuh agent stopped. (rule 506) | Files-SMB | unknown | T1685 | 3 | 2026-11-14T17:08:02 |
| 3 | Wazuh agent stopped. (rule 506) | Jenkins | unknown | T1685 | 3 | 2026-11-14T17:08:12 |
| 3 | Wazuh agent stopped. (rule 506) | Nginx | unknown | T1685 | 3 | 2026-11-14T17:08:02 |
| 3 | PostgreSQL: Database authentication success. (rule 50511) | PostgreSQL | API | T1078 | 62 | 2026-11-13T19:58:45 |
| 3 | Wazuh agent stopped. (rule 506) | PostgreSQL | unknown | T1685 | 3 | 2026-11-14T17:08:04 |
| 3 | Wazuh agent stopped. (rule 506) | Web | unknown | T1685 | 3 | 2026-11-14T17:08:14 |

## 4. Assets (vulnerabilities present, no alert: E = X)

| Asset | Zone | CR/IR/AR | Internet path | P(u) | CVEs | Highest CVSS base | Highest EVS |
|---|---|---|---|---:|---:|---:|---:|
| API | APP | H/H/M | yes | 0.071 | 7 | 9.8 | 10.0 |
| Jenkins | APP | M/H/M | yes | 0.107 | 58 | 9.8 | 10.0 |
| Web | DMZ | M/M/H | yes | 0.107 | 69 | 9.8 | 9.6 |
| Nginx | DMZ | M/M/H | yes | 0.125 | 22 | 8.2 | 9.4 |
| Admin-PC | Office | H/H/L | no | 0.071 | 40 | 9.8 | 8.4 |
| Files-SMB | DATA | H/M/M | yes | 0.000 | 5 | 8.8 | 8.1 |
| PostgreSQL | DATA | H/H/M | yes | 0.000 | 46 | 8.8 | 8.1 |
| Dep-PC | Office | L/L/L | no | 0.000 | 40 | 9.8 | 6.3 |

### Top 20 by EVS

| Asset | CVE | Source | CVSS base (band) | Env | EVS (level) | Change |
|---|---|---|---|---:|---|---|
| API | CVE-2026-111497 | nvd | 9.8 (Critical) | 9.8 | 10.0 (Critical) | = |
| Jenkins | CVE-2024-23897 | nvd | 9.8 (Critical) | 9.8 | 10.0 (Critical) | = |
| API | CVE-2024-3566 | nvd | 9.8 (Critical) | 9.3 | 9.7 (Critical) | = |
| Web | CVE-2024-38475 | nvd | 9.1 (Critical) | 9.1 | 9.6 (Critical) | = |
| Web | CVE-2024-38474 | nvd | 9.8 (Critical) | 9.0 | 9.5 (Critical) | = |
| Web | CVE-2024-38476 | nvd | 9.8 (Critical) | 9.0 | 9.5 (Critical) | = |
| Web | CVE-2026-28780 | nvd | 9.8 (Critical) | 9.0 | 9.5 (Critical) | = |
| Web | CVE-2026-29167 | nvd | 9.8 (Critical) | 9.0 | 9.5 (Critical) | = |
| Web | CVE-2026-44631 | nvd | 9.8 (Critical) | 9.0 | 9.5 (Critical) | = |
| Web | CVE-2026-56154 | nvd | 9.8 (Critical) | 9.0 | 9.5 (Critical) | = |
| Web | CVE-2026-57941 | nvd | 9.8 (Critical) | 9.0 | 9.5 (Critical) | = |
| Web | CVE-2026-59797 | nvd | 9.8 (Critical) | 9.0 | 9.5 (Critical) | = |
| Web | CVE-2026-42535 | nvd | 9.1 (Critical) | 9.0 | 9.5 (Critical) | = |
| API | CVE-2024-21896 | nvd | 9.8 (Critical) | 9.0 | 9.4 (Critical) | = |
| Nginx | CVE-2026-27654 | nvd | 8.2 (High) | 8.8 | 9.4 (Critical) | ↑ |
| Web | CVE-2026-49975 | nvd | 7.5 (High) | 8.8 | 9.3 (Critical) | ↑ |
| Web | CVE-2025-23048 | nvd | 9.1 (Critical) | 8.6 | 9.1 (Critical) | = |
| Nginx | CVE-2024-24989 | nvd | 7.5 (High) | 8.5 | 9.1 (Critical) | ↑ |
| Nginx | CVE-2024-24990 | nvd | 7.5 (High) | 8.5 | 9.1 (Critical) | ↑ |
| Nginx | CVE-2026-27651 | nvd | 7.5 (High) | 8.5 | 9.1 (Critical) | ↑ |

## 5. CVSS base band → EVS level (asset × CVE, no alert)

| CVSS \ EVS | Low | Medium | High | Critical |
|---|---:|---:|---:|---:|
| Low | 21 | 7 |  |  |
| Medium | 14 | 90 | 8 |  |
| High |  | 19 | 89 | 18 |
| Critical |  | 3 | 3 | 15 |

Data: `data/scores/asset_cve_scores.csv`, `data/scores/alert_scores.csv`, structured JSON per instance in `data/reports/assessments/`.
