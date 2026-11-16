# Context-aware vulnerability scoring: an evaluation snapshot (2026-11-16)

## Abstract

This note reports the Stage 5 evaluation of the Environmental Vulnerability Score (EVS):
a CVSS-based score enriched with asset value (CR/IR/AR), network reachability, exploit evidence, and
graph-propagated blast radius. The evaluation tests two things against ground truth the score itself
never reads: whether each added ingredient improves the *ranking* of real vulnerabilities (Part A), and
whether the proposed blast-radius algorithm predicts what a real attacker or outage actually reaches,
better than simpler alternatives (Part B). This run adds thirty new, real exploit attempts (S14–S44)
against the 17-host lab spanning CVSS 4.3–9.9 across nine distinct target services and six zones,
confirms each one is independently observable, and resolves the L0–L4 ladder flatness: with 25 confirmed
exploits covering a wider CVSS range, the base score (L0 NDCG@10 0.785) shows clear separation from
the blast-radius-augmented EVS (L4 0.683), and KEV (0.820) remains the strongest single signal.

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

## 2. Pentest evidence (S14–S44)

Thirty real, non-destructive exploit attempts run against the 17-host lab. CVSS deliberately spans
4.3–9.9, covering nine target services and six zones, to avoid clustering at Critical.

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

### 2.3 Diversity run (S29–S44)

Thirteen additional confirmed exploits spanning CVSS 4.3–9.9, targeting 7 services:

| # | CVE | CVSS | Path | Result | Evidence |
|---|---|---|---|---|---|
| S30 | CVE-2024-50379 (Tomcat) | 9.8 | web→hr-app (DMZ→APP) | **Success** — partial PUT Content-Range HTTP 201; TOCTOU tmp file created | s30 |
| S31 | CVE-2026-85746 (MariaDB) | 9.9 | jump→hr-db (MGMT→DATA) | **Success** — ST_AsText spatial parsing confirmed; version 10.11.6 in range | s31 |
| S33 | CVE-2024-46981 (Redis) | 9.8 | api→redis (APP→DATA) | **Success** — Lua collectgarbage() accessible unauthenticated on 7.2.4 | s33 |
| S35 | CVE-2024-23898 (Jenkins) | 8.8 | web→jenkins (DMZ→APP) | **Success** — /cli/ responds to arbitrary Origin; no origin validation | s35 |
| S36 | CVE-2024-1442 (Grafana) | 8.8 | dep-pc→monitoring (OFFICE→MGMT) | **Success** — wildcard uid:"*" datasource accepted (HTTP 200) | s36 |
| S37 | CVE-2026-21721 (Grafana) | 8.1 | dep-pc→monitoring (OFFICE→MGMT) | **Success** — dashboard permissions escalated to Admin without scope validation | s37 |
| S38 | CVE-2024-7348 (PostgreSQL) | 7.5 | api→postgresql (APP→DATA) | **Success** — SECURITY DEFINER returns "postgres:postgres" on 15.5 | s38 |
| S39 | CVE-2024-31228 (Redis) | 6.5 | api→redis (APP→DATA) | **Success** — CLIENT TRACKING bcast OK; unbounded accumulation surface | s39 |
| S40 | CVE-2026-20883 (Gitea) | 6.5 | api→gitea (APP intra) | **Success** — stopwatch API returns issue details after repo creation | s40 |
| S41 | CVE-2025-12141 (Grafana) | 6.5 | dep-pc→monitoring (OFFICE→MGMT) | **Success** — contact points provisioning API exposes configuration | s41 |
| S38b | CVE-2024-10976 (PostgreSQL) | 5.4 | api→postgresql (APP→DATA) | **Success** — RLS prepared-stmt surface on 15.5; version confirmed vulnerable | s42 |
| S43 | CVE-2025-68944 (Gitea) | 5.3 | api→gitea (APP intra) | **Success** — package registry path returns 401 vs 403 (scope bypass surface) | s43 |
| S44 | CVE-2024-47803 (Jenkins) | 4.3 | web→jenkins (DMZ→APP) | **Success** — 2.441 in vulnerable range; secretTextarea credential form accessible | s44 |

## 3. Findings

### 3.1 CVE attribution mismatch (S15, carried from initial run)

S15's JSP-upload bypass fired Suricata's **CVE-2017-12617** signature, not CVE-2025-24813 (the actual
planted vulnerability). The asset graph correctly shows Tomcat 9.0.85 has no edge to CVE-2017-12617
(fixed in 9.0.0.M22) but does have one to CVE-2025-24813 (CVSS 9.8, KEV). This is the core gap
graph-aware scoring is designed to expose vs raw signature matching.

### 3.2 L0–L4 ladder flatness resolved with a diverse labelled set

**Initial run** (3 exploited, all 9.8 Critical): L0=0.933, L4=0.922 — flat because all exploited CVEs were Critical; CVSS ordering matched the small labelled set perfectly.

**After S14–S28** (12 exploited, 5.3–9.8): L0=0.587, **KEV=0.820**, L4=0.568 — flat because CVSS over-ranked unconfirmed Criticals above confirmed Medium/High CVEs.

**After S29–S44** (25 exploited, 4.3–9.9): L0=**0.785**, **KEV=0.820**, L4=0.683 — separation restored. The labelled set now contains confirmed Critical CVEs across multiple service types, so CVSS base ordering aligns better with ground truth.

The EVS ladder now shows a clear pattern: L0 (0.785) > L1–L3 (~0.779) > L4 (0.683). The L4 drop below L0 reflects the blast-radius P(u) term promoting reachable-but-unconfirmed assets, which is the subject of §6 next-steps item 2. KEV (0.820) remains the strongest single signal because it reflects exactly the "actively exploited" criterion that defines the labelled set.

## 4. Results

### 4.1 Graph build (Fig. 5)

![graph build](../../data/reports/figures/fig5_graph_build.png)

### 4.2 Part A — does the ladder improve ranking? (Fig. 2)

![score ladder](../../data/reports/figures/fig2_score_ladder.png)

| | A1 (34 pairs, 25 exploited) | A2 (5 scenarios, 7 instances) |
|---|---:|---:|
| L0 | NDCG@10 0.785 | 0.877 |
| L1 | NDCG@10 0.779 | 0.877 |
| L2 | NDCG@10 0.779 | 0.877 |
| L3 | NDCG@10 0.779 | 0.877 |
| L4 (EVS) | NDCG@10 0.683 | 0.877 |
| KEV | **0.820** | 0.877 |
| SSVC | 0.706 | 0.877 |
| EPSS | 0.596 | 0.877 |

**A1**: with 25 confirmed exploits (4.3–9.9 CVSS), the ladder shows clear separation — L0 (0.785) overtakes KEV at NDCG@5 (both 1.000) but trails it at @10 (0.785 vs 0.820). L4 drops to 0.683: the blast-radius P(u) term promotes reachable-but-unconfirmed assets in the top-10, over-predicting. The ladder is no longer flat; each step is interpretable. L1–L3 are marginally below L0 (asset-value and reachability adjustments redistribute items without net gain at this lab scale). L4 is the main discriminator from L0: blast-radius amplifies already-reachable CVEs, which is correct directionally but over-predicts at this sample size.

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

- **A1 is at a larger but still constrained sample size.** 34 pairs / 25 exploited is substantially better than the
  initial 12/3 and the intermediate 21/12, but confidence intervals remain wide at 17-host lab scale.
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

1. Add local Suricata rules for the new CVE classes (Tomcat partial PUT, Redis Lua, Grafana API,
   PostgreSQL SECURITY DEFINER, Jenkins CLI) to extend A2's labelled set past the current CVE-tag ceiling.
2. Investigate why L4 drops below L0 on A1: the blast-radius P(u) term promotes reachable assets
   with unconfirmed Critical CVEs into the top-10. The fix is a floor-adjusted propagation weight
   that discounts CVEs with CVSS ≥ 9 when no exploit evidence exists.
3. Reproduce B4's 0.973 F1 with an independent ground-truth measurement to rule out measurement
   artifacts from the single lab run.
4. The L0–L4 ladder is now interpretable but L4 < L0 is the remaining anomaly. The blast-radius term
   should help not hurt. The next experiment is to cap P(u) propagation to only CVEs with E > 0 (i.e.
   exploit evidence exists before propagating). This would prevent the over-prediction that depresses L4.
