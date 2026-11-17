# Stage 5: evaluation protocol (ablation against lab ground truth)

The EVS is built from parts: CVSS base, asset requirements, Internet reachability, exploit maturity, and
propagation. The blast radius is built from design choices: edge type, zone policy, direction and depth. The
evaluation adds or swaps one part at a time. If it only showed that each part *changes* the ranking, it would be a
sensitivity analysis. To show that a part *helps*, every variant is scored against **ground truth that does not
come from the score or from the files the algorithm reads**. Code: `eval_kg/`. Commands: `python -m eval_kg --help`.

## Part A: score ladder

| Step | Adds | Question |
|---|---|---|
| L0 | CVSS v3.1 base | baseline |
| L1 | + CR/IR/AR (Environmental, E = X, MAV = base) | does asset value change the ranking? |
| L2 | + MAV from Internet reachability (Table I) | does network position? |
| L3 | + E from alert / KEV / SSVC (Eq. 14) | does exploitation evidence? |
| L4 | + P(a,c) over the blast radius BR_1(a,c), giving the EVS (Eqs. 16–17) | does the propagation (blast radius) term? |
| Baselines | EPSS percentile, KEV (0/1), CISA SSVC decision, Wazuh `rule.level`, **WazuhVD** (the CVSS base Wazuh's vulnerability detector shows for the pair), **Random** (chance level, seeded) | is the EVS better than what a SOC uses today? |

**What each rung asks** (changed 2026-11-17, docs/PLAN.md §9). The EVS is a *priority given consequence*, not
an exploit predictor, so the ladder has a rung for each kind of evidence and each states what it can and cannot
show:

| Rung | Ground truth | Can show | Cannot show |
|---|---|---|---|
| A0 | property tests on Eq. 16 (`tests/test_score_offline.py`: isolated host → 0, monotone in criticality and edges, firewall tightening never raises P, disruption = compromise on the reversed graph, BR_1 ⊆ BR_2) | the score behaves as specified | that it is useful |
| Sensitivity | none (mechanism) | how far and in which direction each step moves CVSS | that the movement is right |
| A1 | pentest: exploited yes/no | exploit-evidence steps (L3) | anything about L1/L2/L4 (1 positive; exploitability depends on configuration, which no EVS input models) |
| A2 | pentest scenarios, graded alert instances | alert triage | currently empty, see below |
| A3 | forward-in-time KEV | exploit prediction | underpowered (≤ 2 positives) |
| **A4** | **consequence measured in the lab** (usable / dependents sets, per the CVE's impact mode) | that the EVS orders vulnerabilities by what their exploitation does *in this network*, including the same CVE on different hosts | exploit prediction; independence from the lab design (the edges and the measurements share it) |

**Ground truth: the pentest record** (`evaluation/`, filled in by the team).

- **A1, asset × CVE:** `pentest_results.csv` says whether each examined vulnerability was exploited in the lab. Relevance is 1 or 0; `not_tried` rows are left out, because unknown is not the same as negative.
  **Which pairs get tried is sampled, not hand-picked** (from 2026-11-16, below). The report gives each row's
  origin (sampled / hand-picked) and repeats A1 on the sampled rows alone (A1s).
- **A3, forward-in-time KEV** (`python -m eval_kg kev-forward`): see *Wazuh vulnerability detection* below.
- **A4, measured consequence** (`python -m eval_kg consequence`): every graph asset × CVE pair (615), graded 0–3 by
  the number of other hosts the lab measured as affected in the CVE's impact mode: compromise → hosts usable with
  what is stored on the asset, disruption → hosts whose service fails when it stops. Neither measurement reads
  CR/IR/AR, CVSS, KEV or EPSS. Reported: NDCG@10/@50, AP, Kendall τ-b and pair concordance against the grade;
  paired bootstrap CIs (within-grade resampling) for each ladder step and L4 against each baseline; concordance on
  the **same CVE on different hosts** (CVSS can only tie these); and how many CVSS ties the EVS breaks, and in which
  direction.

**Metrics, all rungs.** Tied scores are scored at their expected value over random orders within the tie
(exact for NDCG and P@k, Monte Carlo for MRR/AP), never by item id. EVS values tied at the cap of 10 are ordered
by the uncapped Env·(1+βP) (docs/scoring.md). Paired bootstrap CIs resample positives and negatives (or each
grade) separately, so every resample is defined.

### Wazuh vulnerability detection: inventory, sampling frame, baseline (docs/PLAN.md §8)

Wazuh's vulnerability detector reports every (agent, package, CVE) on every host. The graph's links do not use
it (they come from OSV / NVD), so it is an independent, scanner-produced inventory. It is used in three ways, never
as a relevance label (a scanner says a CVE is *present*, not that it is *exploitable* or *important*):

1. **Snapshot.** `python -m eval_kg wazuh-pairs` writes the states index to `data/eval/wazuh_pairs.csv`, one row per
   (asset, CVE), dated. The **frame** = these pairs ∪ the graph's own links (so software Wazuh cannot inventory,
   e.g. Jenkins, Apache httpd, Node.js, still counts), joined to the CTI graph for the CVSS vector, KEV and SSVC.
2. **A1 sampling frame.** `python -m eval_kg sample --n 20` draws the next pentest targets from the frame's scorable
   pairs that have no label yet: a stratified random sample, strata = zone × CVSS band (≥ 9 / ≥ 7 / below) ×
   public exploit available (KEV, or SSVC exploitation `poc`/`active`; the graph stores no exploit-db references).
   Half the sample comes from exploit-available pairs (`EVAL_SAMPLE_EXPLOIT_SHARE`), because a uniform draw would
   be almost all library CVEs nobody can exercise in a container. Seed 7; every row records its inclusion
   probability. Output: `evaluation/pentest_candidates.csv`; the team protocol is in `evaluation/README.md`.
3. **WazuhVD baseline.** The score a Wazuh SOC actually sorts its vulnerability list by. Pairs Wazuh does not
   report (graph-only links) fall back to the CVE's CVSS base; the A1 note says how many did.

**A3, forward-in-time KEV test** (PLAN.md §6 tier A). Items = the frame. Cut-off T0 (`--t0`, default 2026-05-01):
CVEs already in KEV at T0, and CVEs published after T0, are excluded; label = added to KEV after T0. The ladder
uses only what was known at T0: E from KEV at T0 (never set after the exclusion) and no SSVC exploitation (the
graph has no assessment date, and `active` would leak the label), so L3 = L2 in this test. EPSS is the daily file
of T0. Packages that are not a network service of the host keep their base AV. The report flags itself as
underpowered below 5 distinct positive CVEs.
- **A2, alerted vulnerability instances:** each scenario (`scenarios/*.yaml`) lists its steps with time windows and outcomes. An alert instance (asset, CVE) inside a scenario's window gets the grade of the step it matches (same target, same CVE if the step names one, overlapping time ± 120 s):

  | Grade | Step outcome |
  |---:|---|
  | 3 | success with data access, or used as a pivot onward |
  | 2 | success on the target |
  | 1 | attempted, failed |
  | 0 | the alert matches no step (noise) |

  The grades come only from what the attacker achieved. CR/IR/AR are deliberately **not** used for grading, because they are an input of L1–L4, and using them would make the evaluation circular.

**Metrics.**

- NDCG@5 and NDCG@10, with gain 2^g − 1;
- P@5 and P@10 (relevant = grade ≥ 2, or exploited);
- MRR;
- rank of the first true attack-chain item (grade 3).

For A2 these are computed per scenario and then averaged. Each step's gain L(i) − L(i−1), and L4 against each
baseline, is reported as ΔNDCG@10 with a 95% paired-bootstrap confidence interval (1000 resamples, seed 7). The
resampling is over scenarios, or over items when there are fewer than five scenarios; the report says which. Ties
in a score are broken by item id.

## Part B: blast-radius algorithm

| Variant | What it does | What it shows |
|---|---|---|
| B0 | no blast radius (P = 0) | what is lost without one |
| B1 | unrestricted: every Asset within k hops (k = 1, 2) over any edge type of the unified graph | the "no rules" query (it also returns zones, services, alerts, CVEs) |
| B2 | zone-level: hosts in the same or an allowed zone (outbound for compromise, inbound for disruption), ignoring CONNECTS_TO | the coarse subnet approach |
| B3 | ours, undirected: no impact mode | does direction matter? |
| B4 | ours: CONNECTS_TO with the π(u, v) zone rule, direction by impact mode, k = 1 (Algorithm 1) | the proposed algorithm |
| B5 | ours at k = 2 and k = 3 | is the depth choice justified? |

**Ground truth: measured in the running lab** (`python -m eval_kg measure`). It is never read from `lab/*.csv`.

| Truth set | Mode | How it is measured |
|---|---|---|
| network | compromise | from every host, a TCP connect to every other host on the lab's service ports. This is what the firewall really lets through |
| usable | compromise | on every host, `lab_env/eval/harvest.sh` looks for stored targets and credentials, the way post-compromise enumeration does: environment, config files, home directories, Jenkins jobs. It then tries a harmless authenticated access with each (HTTP GET, `psql select 1`, `smbclient ls`). It is not told where to look for any particular host |
| dependents | disruption | stop one host (`docker compose stop`), run every other host's health check (`lab_env/eval/checks.csv`), then start it again. The hosts whose service fails are the real dependents |

The lab's dependencies are real: Nginx proxies Web, Web proxies `/api/` to the API, the API reads PostgreSQL,
Jenkins' `api-smoke` job calls the API, and Admin-PC maps the finance share with stored credentials. The network
set alone would favour B2, because this lab's firewall works per zone. The usable and dependents sets measure what
an intruder or an outage actually affects.

**Metrics.**

- Per asset, and per (asset, CVE) pair with the CVE's impact mode choosing the direction and the truth set: **pooled** (micro-averaged over (host, affected host) pairs) precision, recall and F1, which give B0 and empty sets no free credit; the earlier per-host mean is kept next to it. Hosts with an empty truth are counted, with each variant's false positives on them.
- **Independent check against the pentest:** for each scenario with a foothold inside the lab, the hosts the attacker actually reached (`outcome: success`), against the variant's compromise-mode blast radius of the foothold. These were achieved by hand and are read neither from `CONNECTS_TO` nor from `checks.csv`.
- Cost: runtime per query and set size. B1 also reports the non-asset nodes it returns.
- Downstream: each variant's set replaces BR_1 inside P(a,c), and the resulting EVS is ranked against the A4 labels (NDCG@50, AP, τ-b, same-CVE concordance).

## Threats to validity (to state in the paper)

- **A4 and Part B share the lab design.** `CONNECTS_TO` was written from the intended flows that the health checks
  exercise, and the usable set finds credentials the team placed. A4 shows that the EVS carries the measured
  consequence into the ranking, and that CVSS cannot; it does not show that the edges were discovered
  independently. The pentest-pivot check in Part B is the independent counterpart, and it shows the limit of a
  one-hop, flow-based blast radius: from the pentest footholds, B4 contains 2 of the 11 hosts the attacker reached;
  most were reached by guessing or reusing a password towards a host the foothold has no recorded flow to.
- **The EVS cap.** With the blast-radius P, 126 of 615 pairs reach the cap of 10 (38 have CVSS ≥ 9.8). The reported
  EVS keeps the cap; rankings order capped values by the uncapped product.

- **Small lab:** 17 hosts in 5 zones (8 in the runs reported below, before the lab was extended on 2026-11-16). The CIs will be wide, and they are reported rather than hidden.
- **Labels from the same team:** the pentest is run and recorded by the authors. Grading by outcome rather than by asset value limits, but does not remove, the bias.
- **Lab-specific ground truth:** the measured sets describe this lab. Another network would need its own measurement, which the scripts automate.
- **NVD has no feed before 2002:** `cti_kg` covers CVE ids from 1999 on via `cvelistV5`, but NVD's own CVSS/CPE/CWE enrichment (`download_nvd`, clamped to `NVD_FIRST_YEAR = 2002`) only starts at 2002, since NVD publishes no yearly feed before then. A 1999-2001 CVE can still be in the graph with whatever `cvelistV5` alone provides, just without NVD's CVSS vector unless a CNA supplied one.
- **Usable reach:** it finds what is stored on a host in common places. It is a lower bound on what a skilled intruder could use.
- **Wazuh pairs are a scanner's view, not exploitability.** They decide which pairs *can* be drawn for the pentest
  and give the WazuhVD baseline; they never grade a pair. Wazuh also has blind spots (software not installed as a
  package) and quirks (on Jump it files openssh CVEs under `openssh-client` and none under `openssh-server`), which
  is why the frame adds the graph's links.

## Preliminary run (2026-11-14)

> **8-host lab.** Every number in this section was measured on the original 8-host lab (DMZ, APP, DATA,
> Office). On 2026-11-16 the lab grew to 17 hosts with a new MGMT zone (`lab_env/README.md`). Part B ground
> truth (`python -m eval_kg measure`), the sensitivity analysis and the reports must be rerun before these
> numbers are quoted for the 17-host lab.

First end-to-end run of this pipeline against the current scenario set (`evaluation/scenarios/S01-S03.yaml`,
the real 2026-11-13 pentest). S04-S07 exist only as raw evidence
(`evaluation/pentest/evidence/steps_atomics.csv`) and have not been transcribed into scenario YAML yet — the
team will expand the scenario set and re-run this. These numbers (`data/reports/eval_score_ablation.md`,
`data/reports/eval_blast_radius.md`) show the pipeline runs end to end and what the report looks like; they
are **not final results**.

**Part A.** A1 has 4 labelled (asset, CVE) pairs (1 exploited); L0 through L4 all tie at NDCG@10 = 1.000
(also P@5 = 0.200, P@10 = 0.100, MRR = 1.000, rank of first true item = 1). This is the sample-size ceiling
effect this doc already flags above, not evidence the ladder steps make no difference: with one positive
among four pairs, it already ranks first under every step, so there is no room left to show a gain. The one
directional signal: L4 (EVS) beats the EPSS baseline by +0.500 NDCG@10, though its 95% CI `[+0.000, +0.569]`
touches zero. A2 currently has 0 of 3 scenarios with any alert instance in their window — a separate,
structural gap: `score_kg.run.vulnerability_instances()` only counts an alert as a vulnerability instance
when Wazuh populates `data.vulnerability.cve` on it, and no alert in this lab does yet, including the real
Jenkins CVE-2024-23897 exploit in S01 (Jenkins has no dedicated Wazuh decoder). A broader per-alert match
already exists (`alert_kg/context.py`'s `via_techniques`, stored as `vulnerabilities.related_to_alert`) but
wiring it into A2 was proposed and left for a separate decision — not done in this run.

**Part B.** B4 (the proposed algorithm) is best or tied-best on every ground truth that reflects real
attacker capability: usable reach (P/R/F1 = 1.000/1.000/1.000), dependents (1.000/0.938/0.958), and the
combined per-(asset, CVE) set across 288 instances (1.000/0.997/0.998). B2 (zone-level) only wins on raw
network reachability (1.000/1.000/1.000) — exactly what this doc predicted above before measuring, which is
itself evidence the measurement design is doing what it is supposed to. B1 (unrestricted k-hop) shows the
"no rules" failure mode concretely: 253-912 non-asset nodes returned per query, against 0 for every other
variant. The downstream L4-ranking-by-variant table is flat at NDCG@10 = 1.000 for every variant — that
inherits A1's ceiling effect above, it is not a Part B finding.

**What would change this:** more real scenarios (past 5, the bootstrap resamples over scenarios rather than
over items — a stronger guarantee) and closing the A2 CVE-matching gap would both widen A1/A2's labelled set
past the current ceiling. Neither is done in this run.

**Update 2026-11-15.** Merged Prant's two A1 rows (Web / CVE-2026-42356, Nginx / CVE-2026-27654, both `no`) and
transcribed our own S04–S07 (atomics run of 2026-11-13) into `evaluation/scenarios/`, so the scenario set is now
7 files and A1 has 6 labelled pairs. Result: nothing moves. A1 is still flat at NDCG@10 = 1.000 for L0–L4 (the one
exploited CVE, Jenkins CVE-2024-23897, is also the highest-scored pair under every step; the two new negatives rank
below it), L4 − EPSS is +0.500 with CI `[+0.000, +0.613]`, and A2 still reports no scenario with an alert instance
in its window, for the same `data.vulnerability.cve` reason as above, so the extra scenarios cannot count yet.
Caveat on the new rows: Prant's two `no` labels come from generic probes (a path-traversal request, a 404 on
Nginx) that do not exercise the vulnerable feature (Apache wrong-handler bug, nginx WebDAV module), and carry no
timestamped evidence; read them as weak negatives. Prant's separate blast-radius run (`nc` reachability, V0–V4)
agrees with Part B's network row (V4 precision 1.00 / recall 0.23 against our B4 1.000 / 0.208); their KEV/AUC
scripts are not used here because KEV feeds E and would make the comparison circular.

**A2 CVE matching (2026-11-15).** `score_kg.run.vulnerability_instances()` now takes `technique_matches`, which
`eval_kg` turns on: an alert that names no CVE falls back to the CVEs `alert_kg` linked to it through its ATT&CK
technique (`vulnerabilities.related_to_alert`), except Wazuh `ossec` administrative alerts (this drops the false
match of "agent stopped" to CVE-2025-59476). The scoring CLI keeps the old behaviour, because a technique match is
an inference and should not set E = H.

**S08, making the Jenkins exploit visible to A2 (2026-11-14 lab run).** A2 was structurally empty because the one
genuinely-exploitable CVE in the lab, Jenkins CVE-2024-23897, produced no alert: the original S01 runs that exploit
from `api` (APP) to `jenkins` (APP), an intra-zone hop the firewall never forwards, so Suricata (which lives in the
firewall namespace) is blind to it, and Jenkins has no Wazuh log decoder of its own. `evaluation/pentest/run_pentest_s08.sh`
runs the *same* real exploit from a `web` (DMZ) foothold instead. `DMZ→APP` is an allowed firewall path, so the CLI
file-read crosses the firewall, Suricata sees it, and two signatures fire carrying the CVE — the lab test sid 9000001
and, more importantly, the stock ET Open rule `sid 2050517 "ET EXPLOIT Jenkins Unauthenticated RCE Attempt Observed
(CVE-2024-23897)"`. This is a more realistic external-compromise path, not a contrivance: an attacker who owns the
public web server pivots to CI. The scenario also sends a SQLi probe at Web, which raises rule 31164 (technique T1055,
which chains through the CWE/CAPEC graph to Apache CVE-2024-38476 on that host), giving a second, probed-but-not-
exploited instance for contrast.

Result (`data/reports/eval_score_ablation.md`, A2): one scenario, two instances — Jenkins/CVE-2024-23897 (grade 3,
exploited) and Web/CVE-2024-38476 (grade 1, probed). The honest reading:

- **The only non-circular, non-artifact finding is that the EVS beats Wazuh's own `rule.level`** (ΔNDCG@10 +0.290,
  MRR 1.000 vs 0.500). Wazuh gives the noisy SQLi probe level 6 and the Suricata exploit alert level 3, so an analyst
  triaging by rule severity looks at the harmless probe before the real file-read; every score that is aware of the
  vulnerability's severity avoids that inversion.
- **The EVS does not out-rank plain CVSS here, and the report should not be read as if it does.** Both CVEs are
  CVSS 9.8 and both saturate the EVS ceiling of 10, so L0 through L4 are tied between the two instances; the 1.000 in
  those rows is the id tiebreak, not the score distinguishing them. Showing the EVS *add value over CVSS* in A2 needs
  alerting instances whose base severities differ and whose asset context reorders them — which this lab, with one
  reliably-alerting exploit at ceiling severity, does not yet provide. That evidence lives in A1 (needs more exploited
  CVEs of varied severity) and in Part B (blast radius), not in this A2 scenario.

S01–S07 stay in the scenario set but contribute nothing to A2: S01–S03's alerts predate the current graph, and
S04–S06 are brute-force/account techniques whose alerts carry no CVE. The A1 numbers (6 pairs, flat) are unchanged
by this work, and Part B is independent of the pentest entirely.

### Part A sensitivity: how the EVS reprioritises CVSS (2026-11-15)

Because A2 cannot show the EVS beating plain CVSS with the lab's current exploitable/alertable surface (both
alerting CVEs and the one repeatable exploit are CVSS 9.8, the ceiling), `python -m eval_kg sensitivity`
(`data/reports/eval_sensitivity.md`) reports the EVS's effect a different way: over the **whole** asset × CVE
inventory (288 pairs, 8 assets, no alert and no exploit outcome), it measures how far the EVS (L4) reorders a
pure CVSS-base (L0) ranking. This is a **sensitivity analysis of the scoring mechanism, not a ground-truth
validation** — it quantifies the reprioritisation and checks it tracks context, but it cannot show the
reprioritisation is *correct*, because there is no outcome label. The validated contextual claim remains Part B
(blast radius vs lab-measured impact); the labelled ranking tests remain A1/A2.

- **Magnitude.** Kendall's tau-b between the L0 and L4 orderings is **0.691** — the EVS keeps the broad CVSS
  order but reorders within it (5389 of 41328 pairs discordant; 4340 are "material" cross-asset flips where a
  CVSS gap ≥ 0.5 is reversed).
- **Direction.** Per-asset mean ΔEVS = L4 − L0 moves with context, though not as a clean value ranking: the
  isolated, worthless **Dep-PC** (L/L/L, not reachable) is suppressed hardest (−2.34), while the reachable DMZ
  web tier (**Nginx** +0.47, **Web** +0.27) is lifted; the internal high-confidentiality data hosts
  (PostgreSQL, API) sit near neutral, because asset value and the MAV reachability term pull in opposite
  directions there and high base scores have little headroom under the ceiling. The honest read is that the two
  unambiguous effects are reachability-lift on the DMZ tier and value-suppression on the throwaway host, not a
  monotonic "critical = higher" story.
- **Exemplars.** Dep-PC's two 9.8 CVEs fall to EVS 6.30 while Nginx's 7.5 CVEs rise to 9.10 — a moderate CVE on
  a reachable, high-availability host out-ranking a critical CVE on an isolated workstation, the reprioritisation
  a flat CVSS cannot make. Whether that reprioritisation is *right* is what Part B measures, not this report.

### Wazuh vulnerability detection on the 17-host lab (2026-11-16)

- **Inventory.** 3,047 (asset, CVE) pairs from Wazuh on all 17 hosts (42–306 per host; the IDS box's 280 are dropped,
  it is not an asset). With the graph's links the frame has 3,427 pairs: 249 both, 2,798 Wazuh only (mostly OS
  libraries on hosts whose service is modelled), 380 graph only; 3,337 have a CVSS v3.1 vector.
- **Link agreement rerun** (`python -m asset_kg wazuh-check`, `docs/reports/asset_cve_validation.md`): on software
  both sides see, precision 68.3% and recall 97.1% (235 CVEs in both), against 9.7% / 93.8% on the 8-host lab. It
  stays *agreement*: most graph-only links are distribution-listed CVEs Wazuh does not report, or upstream builds.
- **A1 sample drawn.** `evaluation/pentest_candidates.csv`, 20 pairs (seed 7) from 3,328 unlabelled pairs, 10 with a
  public exploit. Only 3 of the 20 are a network service of the host; the rest are local library CVEs (libpcre2,
  binutils, perl, gnutls…). Expect many `not_tried`, and record them honestly rather than swapping in easier pairs.
- **A3 is not usable on this lab.** The inventory holds 8 KEV CVEs, and all but one were added to KEV within weeks
  of publication. At any T0 from 2023 to 2026 there are at most 2 distinct positive CVEs (2024-07-01:
  CVE-2024-23897, CVE-2024-38475), and 0 at the default T0. `data/reports/eval_kev_forward.md` says so in its
  banner; the command stays for a larger inventory.
- **WazuhVD** joins the A1 table (2 of the 9 labelled pairs are Wazuh-reported); A1 is still flat at NDCG@10 = 1.000
  for every score, the ceiling effect described above, until sampled rows are labelled.

## Results with the blast-radius P (17-host lab, 2026-11-17)

Reports: `data/reports/eval_consequence.md` (A4), `eval_score_ablation.md` (A1/A2), `eval_blast_radius.md`
(Part B), `eval_sensitivity.md`; figures and summary in `final_check_report.md`. β = γ = 0.5, k = 1.

**A4, measured consequence (615 pairs, 388 with a consequence).** NDCG@50: L0 0.190, L1 0.201, L2 0.191, L3 0.219,
**L4 0.454**; EPSS 0.339, SSVC 0.329, KEV 0.310, Random 0.257, WazuhVD 0.198. Paired bootstrap, within-grade:

| Comparison | Δ NDCG@50 [95% CI] |
|---|---|
| L4 − L3 (the blast-radius term) | +0.235 [+0.143, +0.293] |
| L4 − L0 (EVS vs CVSS) | +0.264 [+0.165, +0.328] |
| L4 − EPSS / KEV / SSVC | +0.115 [+0.027, +0.194] / +0.144 [+0.039, +0.200] / +0.126 [+0.017, +0.185] |
| L1 − L0, L2 − L1, L3 − L2 | +0.011 [−0.024, +0.042], −0.009 [−0.032, +0.003], +0.028 [+0.004, +0.075] |

Same CVE on different hosts (38 CVEs, 169 host pairs with different measured consequence): CVSS, EPSS and KEV tie
all of them (0.5); **CR/IR/AR alone (L1) orders 92% like the lab, and the EVS 100%**; SSVC 0.64, WazuhVD 0.60.
Of 14,916 pairs tied on CVSS base, the EVS separates 82%; where their consequence differs (7,501), it orders 6,714
like the lab, 764 the other way.

**Part B (pooled over host pairs).** Per (asset, CVE): B4 F1 0.982 (B5 k=2 0.750, B3/B1 k=1 0.687, B2 0.204,
B0 none). Usable: B4 P/R 0.917/1.000; dependents: 1.000/0.857. Downstream (each variant inside P, A4 labels):
B4 NDCG@50 0.454 vs B0 0.219, B3 0.302, B2 0.272; B5 is slightly higher (0.474/0.482) because a deeper set adds
more critical hosts to P. Pentest pivots (independent): B4 recall 2/11, B2 11/11 at 7.6 predicted hosts per
foothold.

**A1** (9 hand-picked pairs, 1 exploited): with ties scored honestly, L0 0.710 → L3/L4 1.000 (the KEV-listed
Jenkins CVE separates once E is added); EPSS, KEV, SSVC also 1.000. Underpowered: one positive.

**A2** is empty: the alert store was rebuilt on 2026-11-15 15:23 UTC, after every scenario window
(S01–S13 run 2026-11-13 to 2026-11-15 13:05). The earlier alerts are in
`data/backup-2026-11-15/alerts/raw.jsonl`; re-ingesting them with `alert_kg` would restore A2.

**Sensitivity.** Kendall τ-b (CVSS vs EVS) 0.566 over 615 pairs. Per-step attribution: Dep-PC −2.34 on average,
of which CR/IR/AR −1.43, MAV −0.59, E −0.31, P 0; the P term lifts the hosts with critical neighbours (Jump +1.91,
Jenkins +1.84, Web +1.51, API +1.43). β/γ grid: τ-b against the default ≥ 0.781.

## Running

```powershell
cd lab_env; docker compose up -d; cd ..        # the lab must run for the measurements
python -m eval_kg measure                       # Part B ground truth -> data/eval/*.json
python -m eval_kg all                           # both reports -> data/reports/eval_*.md (+ CSV)
python -m eval_kg sensitivity                    # Part A sensitivity -> data/reports/eval_sensitivity.md (no ground truth)
python -m eval_kg wazuh-pairs                    # Wazuh vulnerability detection snapshot -> data/eval/wazuh_pairs.csv
python -m eval_kg sample --n 20                  # A1 pentest targets -> evaluation/pentest_candidates.csv
python -m eval_kg kev-forward --t0 2026-05-01    # A3 forward-in-time KEV test -> data/reports/eval_kev_forward.md
python -m eval_kg plot [--notes FILE] [--before STATS]   # figures + data/reports/final_check_report.md from the reports' JSON
python -m eval_kg all --labels evaluation/dry_run   # pipeline test with synthetic labels (never report these)
```
