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
| L4 | + P(u), giving the EVS (Eqs. 16–17) | does the propagation (blast radius) term? |
| Baselines | EPSS percentile, KEV (0/1), CISA SSVC decision, Wazuh `rule.level` | is the EVS better than what a SOC uses today? |

**Ground truth: the pentest record** (`evaluation/`, filled in by the team).

- **A1, asset × CVE:** `pentest_results.csv` says whether each examined vulnerability was exploited in the lab. Relevance is 1 or 0; `not_tried` rows are left out, because unknown is not the same as negative.
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

- Per asset, and per (asset, CVE) pair with the CVE's impact mode choosing the direction and the truth set: precision, recall and F1 of the predicted affected set. An empty prediction has precision 1, and an empty truth set has recall 1.
- Cost: runtime per query and set size. B1 also reports the non-asset nodes it returns.
- Downstream: L4 recomputed with each variant's reachable set feeding P(u), then NDCG@10 on the A1 labels.

## Threats to validity (to state in the paper)

- **Small lab:** 8 hosts. The CIs will be wide, and they are reported rather than hidden.
- **Labels from the same team:** the pentest is run and recorded by the authors. Grading by outcome rather than by asset value limits, but does not remove, the bias.
- **Lab-specific ground truth:** the measured sets describe this lab. Another network would need its own measurement, which the scripts automate.
- **NVD has no feed before 2002:** `cti_kg` covers CVE ids from 1999 on via `cvelistV5`, but NVD's own CVSS/CPE/CWE enrichment (`download_nvd`, clamped to `NVD_FIRST_YEAR = 2002`) only starts at 2002, since NVD publishes no yearly feed before then. A 1999-2001 CVE can still be in the graph with whatever `cvelistV5` alone provides, just without NVD's CVSS vector unless a CNA supplied one.
- **Usable reach:** it finds what is stored on a host in common places. It is a lower bound on what a skilled intruder could use.

## Preliminary run (2026-11-14)

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

## Running

```powershell
cd lab_env; docker compose up -d; cd ..        # the lab must run for the measurements
python -m eval_kg measure                       # Part B ground truth -> data/eval/*.json
python -m eval_kg all                           # both reports -> data/reports/eval_*.md (+ CSV)
python -m eval_kg sensitivity                    # Part A sensitivity -> data/reports/eval_sensitivity.md (no ground truth)
python -m eval_kg all --labels evaluation/dry_run   # pipeline test with synthetic labels (never report these)
```
