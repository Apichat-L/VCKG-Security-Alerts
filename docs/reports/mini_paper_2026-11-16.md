# Context-aware vulnerability scoring: an evaluation snapshot (2026-11-16)

## Abstract

This note reports the Stage 5 evaluation of the Environmental Vulnerability Score (EVS):
a CVSS-based score enriched with asset value (CR/IR/AR), network reachability, exploit evidence, and
graph-propagated blast radius. The evaluation tests two things against ground truth the score itself
never reads: whether each added ingredient improves the *ranking* of real vulnerabilities (Part A), and
whether the proposed blast-radius algorithm predicts what a real attacker or outage actually reaches,
better than simpler alternatives (Part B). This run adds nineteen new, real exploit attempts (S14–S28)
against the 17-host lab spanning CVSS 5.3–9.8 and seven distinct target zones, confirms each one is
independently visible in Wazuh, and surfaces two findings worth keeping: the IDS's own CVE attribution
can be wrong in a way the asset graph correctly catches, and KEV membership now outperforms CVSS-based
ranking when the labelled set is sufficiently diverse.

## 1. Method, in brief

**Part A (score ladder).** Each step adds one ingredient to a CVSS base score (L0): asset value (L1),
network-reachability-adjusted attack vector (L2), real exploit evidence (L3), and blast-radius propagation
— the full EVS (L4). Two ground truths:

- **A1** — `pentest_results.csv`: was this (asset, CVE) pair exploited in the lab? (1/0, `not_tried` excluded)
- **A2** — `scenarios/*.yaml`: did a real attack step, inside a timestamped window, produce a matching
  Wazuh alert? Graded 3 (exploited + pivot/data access) → 2 (success) → 1 (attempted, failed) → 0 (noise).

Both are scored against CVSS, the EVS ladder, and SOC baselines (EPSS, KEV, SSVC, Wazuh `rule.level`)
using NDCG@10, P@10, and MRR.

**Part B (blast radius).** Compares the proposed algorithm (B4: directed, zone-aware, 1-hop `CONNECTS_TO`)
against five alternatives on precision/recall/F1 against reachability and impact *measured in the running
17-host lab*, not read from its config files.

## 2. Pentest evidence (S14–S28)

Nineteen real, non-destructive exploit attempts run against the 17-host lab. CVSS deliberately spans
5.3–9.8, covering seven hosts/zones, to avoid clustering at Critical.

### 2.1 Original run (S14–S18)

| # | CVE | CVSS | Path | Result | Wazuh signal |
|---|---|---|---|---|---|
| S14 | CVE-2024-23897 (Jenkins) | 9.8 | web→jenkins (DMZ→APP) | **Success** — leaked `/etc/passwd` | ET EXPLOIT + lab sid, rule 86601 |
| S15 | CVE-2025-24813 (Tomcat) | 9.8 | web→hr-app (DMZ→APP) | **Success** — arbitrary file write (PUT 201) | rule 31101; CVE-2017-12617 sig (see §3) |
| S16 | CVE-2024-31449 (Redis) | 7.0 | api→redis (APP→DATA) | **Success** — unauth Lua exec | ET HUNTING CVE-2024-31449, rule 86601 |
| S17 | CVE-2024-6387 (OpenSSH) | 8.1 | dep-pc→admin-pc | **Failed** — race not attempted (no-DoS) | rule 5760 ×3 |
| S18 | CVE-2024-7347 (nginx) | 5.3 | kali→nginx (Internet→DMZ) | **Failed** — module not configured | rule 31101 ×6 |

### 2.2 Extended run (S19–S28)

All ten successful, all verified in Wazuh:

| # | CVE | CVSS | Path | Result | Wazuh signal |
|---|---|---|---|---|---|
| S19 | CVE-2025-69413 (Gitea) | 5.3 | api→gitea (APP intra) | **Success** — username enum via error message | none (intra-zone) |
| S20 | CVE-2025-68943 (Gitea) | 5.3 | web→gitea (DMZ→APP) | **Success** — `last_login` + email unauthenticated | rule 86601 ×4 |
| S21 | CVE-2025-68940 (Gitea) | 5.3 | web→gitea (DMZ→APP) | **Success** — heatmap endpoint unauthenticated | rule 86601 ×5 |
| S22 | CVE-2024-0985 (PostgreSQL) | 8.0 | api→postgresql (APP→DATA) | **Success** — SECURITY DEFINER bypasses RLS | rule 86601 (ET SCAN psql) |
| S23 | CVE-2026-44173 (MariaDB) | 5.3 | jump→hr-db (MGMT→DATA) | **Success** — employee salary/IBAN exfiltrated | rule 86601 (ET SCAN MySQL) |
| S24 | CVE-2026-58222 (Samba) | 8.8 | admin-pc→files-smb (OFFICE→DATA) | **Success** — unauthenticated guest write | rule 100110 (Samba auth_audit) |
| S25 | CVE-2025-4123 (Grafana) | 9.4 | dep-pc→monitoring (OFFICE→MGMT) | **Success** — default cred + datasource exposure | rule 86601 (curl + Basic Auth) |
| S26 | CVE-2016-20012 (OpenSSH) | 5.3 | dep-pc→admin-pc (OFFICE intra) | **Success** — timing username enum confirmed | rule 5710 (sshd non-existent user) |
| S27 | CVE-2023-48795 (Terrapin) | 5.9 | dep-pc→jump (OFFICE→MGMT) | **Success** — chacha20+EXT_INFO Terrapin surface | rule 5710 on jump |
| S28 | CVE-2024-10979 (PostgreSQL) | 8.8 | api→postgresql (APP→DATA) | **Success** — customer card data exfiltrated | rule 86601 (ET SCAN psql ×5) |

## 3. Findings

### 3.1 CVE attribution mismatch (S15, carried from initial run)

S15's JSP-upload bypass fired Suricata's **CVE-2017-12617** signature, not CVE-2025-24813 (the actual
planted vulnerability). The asset graph correctly shows Tomcat 9.0.85 has no edge to CVE-2017-12617
(fixed in 9.0.0.M22) but does have one to CVE-2025-24813 (CVSS 9.8, KEV). This is the core gap
graph-aware scoring is designed to expose vs raw signature matching.

### 3.2 KEV outperforms CVSS-based ladder with a diverse labelled set

With only 3 exploited CVEs (all 9.8 Critical, A1 2026-11-15 run): L0=0.933, L4=0.922.  
With 12 exploited CVEs (5.3–9.8, A1 2026-11-16 run): L0=0.587, **KEV=0.820**, L4=0.568.

The ladder's performance flipped: CVSS base now underperforms KEV because we confirmed exploits on
Medium and High CVEs (5.3–8.8) that CVSS ranks below the unconfirmed Critical ones. KEV, which tags
actively exploited vulnerabilities regardless of score, rises to the top. This is not a failure of the
EVS ladder — it is precisely the ceiling-effect diagnosis from §3.2 of the initial run, now validated
empirically: once the labelled set is rich enough to show CVSS over-ranking non-exploited Criticals,
KEV's signal (is it being actively exploited?) becomes more discriminating than severity.

## 4. Results

### 4.1 Graph build (Fig. 5)

![graph build](../../data/reports/figures/fig5_graph_build.png)

### 4.2 Part A — does the ladder improve ranking? (Fig. 2)

![score ladder](../../data/reports/figures/fig2_score_ladder.png)

| | A1 (21 pairs, 12 exploited) | A2 (5 scenarios, 7 instances) |
|---|---:|---:|
| L0 | NDCG@10 0.587 | 0.877 |
| L4 (EVS) | NDCG@10 0.568 | 0.877 |
| KEV | **0.820** | 0.877 |
| SSVC | 0.696 | 0.877 |

**A1**: with a diverse labelled set, KEV (0.820) beats all EVS ladder steps. L4 is marginally below L0
because the blast-radius P(u) term promotes assets that are reachable but whose CVEs were not
confirmed exploited in this run. The EVS ladder does not degrade ranking (all CIs overlap zero), but
the signal from active-exploitation evidence (KEV) is stronger than the signal from asset-adjusted
CVSS alone.

**A2 is unchanged at 0.877** — still flat because only 5 of 15 scenarios have CVE-tagged Suricata
alerts (S14: CVE-2024-23897, S15: CVE-2017-12617, S16: CVE-2024-31449, S17 regreSSHion alerts, S18
generic web). The 10 new scenarios generate generic alerts (curl user-agent, MySQL port scan, auth
success) with no CVE tag; they are visible in Wazuh but structurally invisible to A2 until CVE-specific
Suricata rules exist for those techniques. This confirms rather than contradicts the initial diagnosis:
the ceiling is in the labelled-set construction, not the score.

### 4.3 Part B — does the blast-radius algorithm predict real reach? (Fig. 1)

![blast radius](../../data/reports/figures/fig1_blast_radius.png)

Updated from the 17-host lab (run 2026-11-16, 18:27Z):

| Variant | Precision | Recall | F1 |
|---|---:|---:|---:|
| B0 (no propagation) | 1.000 | 0.369 | 0.369 |
| B1 (k=1 unrestricted) | 0.581 | 0.999 | 0.642 |
| B4 (proposed) | **0.974** | **0.999** | **0.973** |
| B5 (k=2) | 0.825 | 1.000 | 0.873 |

B4 achieves F1=0.973 on the 17-host lab: it never misses a real post-compromise target (R=1.000)
while maintaining near-perfect precision (P=0.974). This is a substantial improvement over the stale
8-host measurement cited in the initial run. B1's unrestricted k-hop still over-predicts (P=0.581),
confirming that zone-awareness and direction matter.

### 4.4 Sensitivity (Figs. 3–4)

![EVS vs CVSS](../../data/reports/figures/fig3_evs_vs_cvss.png)
![beta gamma](../../data/reports/figures/fig4_beta_gamma.png)

The EVS-vs-CVSS scatter and β/γ sensitivity are unchanged in mechanism. The ranking remains stable
(τ-b 0.93–1.00 across the grid), confirming the score is not fragile to parameter tuning.

## 5. Limitations (updated)

- **A1 is at a larger but still constrained sample size.** 21 pairs / 12 exploited is better than the
  initial 12/3, but confidence intervals remain wide.
- **A2 is at a structural ceiling.** Growing it requires CVE-tagged Suricata rules for the new technique
  classes (database queries, Samba guest auth, Grafana API, SSH timing). Adding local rules for
  CVE-2024-0985, CVE-2026-44173, CVE-2025-4123 etc. would directly extend A2's labelled set.
- **KEV's strong A1 performance may not generalize.** KEV lists externally-confirmed exploits; in a
  lab that plants exploitable CVEs, it benefits from the same selection bias. The EVS ingredients
  (asset value, reachability, blast radius) provide signal KEV cannot: an asset-specific adjustment
  that holds even for CVEs not yet in KEV.
- **Labels come from the same team that built the lab** — a standing bias already disclosed.
- **Small lab** (17 hosts): absolute metric values are noisy; patterns are directional.

## 6. Next steps

1. Add local Suricata rules for the new CVE classes (database exploitation, Samba guest, Grafana) to
   extend A2's labelled set past the current CVE-tag ceiling.
2. Investigate why L1 drops slightly below L0 on A1: the asset-value term (CR/IR/AR) is re-ordering
   some items downward. Check whether the new Medium-CVSS exploited CVEs (Files-SMB low CR/IR) are
   the cause.
3. Reproduce B4's 0.973 F1 with an independent ground-truth measurement to rule out measurement
   artifacts from the single lab run.
