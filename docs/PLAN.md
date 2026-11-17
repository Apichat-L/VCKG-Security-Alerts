# Project plan: stages after the CTI knowledge graph

Status: **draft, for review. Nothing below is built yet.**
Last updated: 2026-10-17

This plan covers everything after the CTI knowledge graph (stage 2, step 1), which is finished and running in Neo4j for 2024+ CVEs. The stages follow `outline_n_ideas.md`. Each stage lists what it will build, the decisions you need to make (marked **Decide**), and how it will be checked.

## Changes proposed by the literature review (pending your approval)

The review is complete: `reports/Asset KG linking and alert rescoring.md`. Its last table checks each item below against the literature. I have **not** rewritten the sections yet. If you approve, these changes will be folded in:

1. **The full-corpus CTI run moves from housekeeping to a blocker (§0).** Deliberately vulnerable lab software, the AIT-ADS dataset (CVE-2020-24186) and the KEV-based evaluation all need CVEs from before 2024.
2. **The lab uses VMs and includes a Windows host (§1).** Windows applications and nmap-found services are the only asset→CVE links that can be validated without circularity. Windows also gives most of the Atomic Red Team coverage.
3. **Linux packages are not matched to NVD CPEs (§3).** dpkg/rpm packages get their vulnerabilities from Wazuh's states index or from distro OVAL data, because backports make NVD version ranges over-report. CPE matching is used only for Windows/macOS applications and nmap services, with a check that rejects partial name matches (as Dependency-Track does). Version ranges are checked in Python with `univers`.
4. **Asset→CVE validation is partitioned (§3).** Wazuh is compared only against links the graph computes on its own, plus a hand-checked sample. This is reported as agreement, not ground truth.
5. **The CTI graph change (new decision):** the CTI graph drops NVD's "running on platform" condition. It would store those platform CPEs on `VULNERABLE_TO` so they can be checked against the host's OS.
6. **Reachability is computed per host and service in Python (§2.2),** not per subnet. Firewall rules are evaluated in order, first match wins. Services listening only on loopback are filtered out, and the result is cross-checked with nmap. nmap is required, not optional.
7. **CR/IR/AR are mandatory on every host (§2.3).** They are derived as a FIPS 199 high-water mark from business functions. CVSS v3.1 and v4.0 handle an unset value differently, so a missing value would silently change the score.
8. **Alert mapping plans for low ATT&CK coverage (§4).** Only about 22.5% of Wazuh rules carry an ATT&CK ID (unofficial count). The rest get an offline `rule.id → technique` lookup, reviewed by hand. Tactic order is stored from the ATT&CK matrix, not inferred from TA IDs.
9. **Scoring is a transparent, standards-based score (§5):** CVSS v3.1 environmental, with attack vector taken from graph reachability, plus a bounded uplift for EPSS, blast radius and alert evidence. CVSS threat metrics can only lower a score. ML and GNN models only supply features.
10. **Evaluation has three tiers (§6).** (A) A forward-in-time KEV test that never uses KEV as both input and label. (B) Lab scenarios scored with NDCG@k and ablations. (C) Agreement with experts (weighted κ).

Two things to check live before any code: one real Wazuh alert and one states-index document, to confirm the `data.vulnerability.*` field paths.

---

## 0. Housekeeping (before any new work)

- [x] Fix the syntax error in `cti_kg/load/neo4j_loader.py:28` (done 2026-10-17; tests pass).
- [ ] Decide two things left open from the CTI graph:
  - **Decide:** should near-identical CWE mitigation texts be merged, e.g. "leading" vs "trailing" special elements? (Currently yes. Merges are listed in `data/processed/alignment_report.csv`.)
  - **Decide:** should CWE categories get links to their member CWEs? (Currently no, because they would mix OWASP/CERT groupings into the CWE hierarchy.)
- [ ] Run the full CVE corpus once (`python -m cti_kg all` without `--since-year`). This needs a long download from NVD.
- [ ] Commit the CTI graph code (nothing is committed yet).

## 1. Lab testbed (stage 1, asset data)

The asset graph needs a real environment to describe. The outline lists these nodes:

| Node | Role | Proposed setup |
|---|---|---|
| Wazuh server | security tool | Wazuh 4.x all-in-one (manager + indexer + dashboard), Docker or VM |
| Victim hosts (2–4) | valuable assets with priority tiers | e.g. 1 Linux web server (DB + app), 1 Windows workstation, 1 Linux file server, each with a Wazuh agent |
| Network | topology | 2 subnets (e.g. "DMZ" and "internal") joined by a router/firewall VM |
| Attacker | outside the victim network | Kali Linux + Atomic Red Team (Invoke-AtomicRedTeam on Windows, atomics via bash on Linux) |

- **Decide:** VMs (VirtualBox/Proxmox) or Docker containers? VMs are more realistic, especially for Windows and Atomic Red Team. Docker is lighter, but the Windows host would be lost.
- **Decide:** which OS/software to install. This should deliberately include a few known-vulnerable versions, so there are real CVE links and real alerts to check against.
- **Decide:** asset value / priority tiers for each host (see section 2.3).

Deliverable: `lab/` with setup notes or compose files, and an inventory sheet (`lab/assets.yaml`) for the details no tool can collect, such as owner, business value and role.

## 2. Asset knowledge graph (stage 2, step 2)

### 2.1 Data collection *(to confirm in research)*
- **Automatic:** Wazuh syscollector via the Wazuh API (`/syscollector/{agent}/os`, `/packages`, `/ports`, `/netaddr`, `/processes`, `/hardware`). The existing `old_design/wazuh_connector.py` can be extended for this.
- **Network scan (optional):** `nmap -sV` from a scanner host, for exposed services and reachability.
- **Manual:** `lab/assets.yaml` for asset value, role, data sensitivity, subnet, and firewall rules / allowed flows.

### 2.2 Proposed schema (new labels; the CTI labels stay unchanged)

```
(Host {name, agent_id, ip, role, criticality, cr, ir, ar})
  -[:RUNS_OS]->(OperatingSystem {name, version})          -[:MATCHES]-> (CPE)  and -[:IS_PLATFORM]-> (Platform)
  -[:HAS_INSTALLED]->(Software {name, vendor, version})   -[:MATCHES {method, score}]-> (CPE)
  -[:EXPOSES]->(Service {port, protocol, product})        -[:PROVIDED_BY]-> (Software)
  -[:IN_SUBNET]->(Subnet {cidr, zone})
(Subnet)-[:CAN_REACH {ports}]->(Subnet)                   # from firewall rules
(Host)-[:DEPENDS_ON]->(Host)                              # e.g. web app → DB, for criticality propagation
(Host)-[:HAS_VULNERABILITY {via, confidence}]->(Vulnerability)   # derived, see 2.4
```

- **Decide:** should this follow an existing ontology (e.g. D3FEND digital artifacts, UCO) or use a minimal custom schema like the one above? *(Research will compare these. My default is minimal custom with a mapping table, for speed.)*

### 2.3 Asset value
- Each host gets CIA requirements (`cr`, `ir`, `ar` = Low/Medium/High), the same scale as the CVSS environmental requirements, so the values plug directly into CVSS later.
- An overall `criticality` tier (1–4) is derived from those, with optional propagation along `DEPENDS_ON`.
- **Decide:** the scale and how the values are assigned (your own judgment, a business-impact table, or FIPS 199 style).

## 3. Linking the asset graph to the CTI graph (stage 2, step 3)

Nagaty's Phase 3 calls this "entity alignment and resolution."

1. **Software/OS → CPE.** Normalize the package vendor/name/version, then match against the NVD CPE dictionary. The order is: exact match, then alias table (`overrides/cpe_aliases.csv`), then fuzzy match (rapidfuzz, reusing `cti_kg/align/resolve.py`), possibly with a tool such as CIRCL cpe-guesser *(to confirm in research)*. Every match records its `method` and `score` and goes to a review report, the same pattern as `alignment_report.csv`.
2. **CPE → CVE (version check).** Follow `VULNERABLE_TO` edges and keep only CVEs whose version range contains the installed version. Create `(Host)-[:HAS_VULNERABILITY]->(Vulnerability)`.
3. **OS → Platform.** Link to the ATT&CK and CWE `Platform` nodes, so techniques can be filtered to the platforms a host actually runs.
4. **Known risk:** Linux distro backports (e.g. Ubuntu patching without changing the upstream version) create false positives against NVD version ranges.
   - **Decide:** accept this and document it, or add a distro security-tracker (OVAL) source *(research will cover this)*.

**Validation:** compare the derived `HAS_VULNERABILITY` edges with Wazuh's own vulnerability-detection results for the same agents, reporting precision and recall. This answers the outline's open question "Test and validate the links by test querying — don't know how." Also add a set of fixed sanity queries, e.g. "every host has an OS", "every critical host reaches ≥1 subnet".

## 4. Querying: alert → graph (stage 3)

1. **Ingest alerts.** Pull them from the Wazuh indexer (OpenSearch `wazuh-alerts-*`), not the manager API. Store the raw JSON plus a normalized record.
2. **Entity extraction.** First version is rule-based field mapping, since Wazuh alerts are already structured:
   - `agent.id` → Host
   - `rule.mitre.id` → Technique
   - `data.vulnerability.cve` → Vulnerability
   - `data.srcip` → external or internal source
   - `rule.level`, `rule.groups` → alert properties

   NER/LLM extraction (SecBERT etc.) only for free-text fields, and only if the rule-based version leaves gaps.
   - **Decide:** is rule-based enough for the thesis, or is ML extraction a required contribution?
3. **Graph queries (Cypher), a fixed library of query templates:**
   - Alert → Technique → (AttackPattern → Weakness → Vulnerability) ∩ the target Host's `HAS_VULNERABILITY` → "this alert matches an exploitable vulnerability on this host."
   - Host → reachable Hosts (via `IN_SUBNET`/`CAN_REACH`) that have vulnerabilities reachable by the same or following tactics → attack path and blast radius.
   - Technique → Mitigation / DetectionMethod, for the response view.
4. Output: an "alert context" JSON per alert containing the matched CVEs, affected assets, path(s) and mitigations.

## 5. Classification / re-scoring (stage 4)

Proposed design: a transparent score first, ML second. *(The formula is to be finalized after the research.)*

- **Baseline:** CVSS base score of the matched CVE(s) (or of the alert's rule level when there is no CVE).
- **Threat context:** KEV flag, EPSS probability (new data source, daily CSV from FIRST), and the SSVC fields already stored on `Vulnerability`.
- **Environmental context:** the host's CR/IR/AR applied through the CVSS v3.1/v4 environmental formula, plus exposure/reachability from the graph (internet-facing? number of downstream critical assets?).
- **Alert evidence:** does the alert's technique actually lead to a vulnerability present on that host?
- **Result:** a new score and priority class, stored next to the original CVSS so the two can be compared.
- **Optional:** an ML model (SecBERT text features + graph features, or a GNN as in Nagaty's Phase 4) trained on labelled lab alerts.
  - **Decide:** is an ML model expected by your professor, or is a rule-based, explainable score acceptable as the main contribution?

## 6. Validation (stage 5, "TBD, consult with prof")

Proposed evaluation, to discuss with your professor:

1. **Lab scenarios with ground truth.** Run Atomic Red Team tests (known ATT&CK IDs) and a few real exploits from Kali against the known-vulnerable hosts. Label each resulting alert with its true impact (e.g. critical host compromised vs. noise).
2. **Metrics:** rank the alerts by the new score vs. by CVSS / Wazuh rule level. Report NDCG@k, precision@k on true-high-impact alerts, and Spearman correlation with the analyst labels.
3. **Component checks:** asset-to-CVE link precision/recall (section 3), and alert-to-technique mapping accuracy.
4. **Baselines:** CVSS base, CVSS + environmental, EPSS, and SSVC decision tree.

## 7. Demo: `explain` (attack path, blast radius and EVS for one input) *(built 2026-11-16)*

**Goal.** Show the blast-radius algorithm and the EVS calculation live in the Neo4j Browser, for any input you
choose during the demo. Today they only run in bulk inside `score_kg alerts`.

**Why the calculation runs in Python, not in the Browser.** The Browser cannot call a Python function, and
custom APOC procedures are not installed (core APOC only). The EVS also needs the CVSS v3.1 Environmental
equation, which `score_kg` computes with the `cvss` library. Copying that equation into Cypher would give two
implementations that can disagree. So one command computes the result with the existing code and writes it
to the graph as a small, separate result subgraph. The Browser then draws it.

**Command** (new `explain` subcommand of `score_kg`):
```
python -m score_kg explain --cve CVE-2024-23897 [--asset Jenkins]
python -m score_kg explain --technique T1574.010 [--asset PostgreSQL]
python -m score_kg explain --tactic TA0006 [--asset Web]
python -m score_kg explain --clear          # remove all results
```
`--asset` is optional. If it is left out, the targets are every asset where the input finds a CVE.

**What it does**

| Input | Steps |
|---|---|
| CVE | 1. Targets: `--asset`, or every asset whose software `HAS_VULNERABILITY` the CVE. 2. Attack paths from the Internet to each target over `CAN_REACH` (same query as `alert_kg/context.py` `Q_PATHS`, ≤ 4 hops, 3 shortest). 3. EVS of (target, CVE) with `model.score`. 4. Blast radius BR_k with `model.blast_radius` (k = 1, impact mode from the CVE). |
| Technique | 1. Technique family: the technique, its parent and its sub-techniques (as in `alert_kg`). 2. CVEs: Technique ← CAPEC ← CWE (Base/Variant/Compound only, as in `alert_kg`) → CVE, limited to CVEs present on lab software. 3. Targets: only the hosts that have such a CVE (with `--asset`, only that host, if it has one). 4. Attack paths to each target. 5. EVS and blast radius of each linked CVE on its target. |
| Tactic | Expands to every technique that `IMPLEMENTS` it (with sub-techniques), then the same as Technique. In the lab a tactic reaches 2–21 CVEs. |

`E` follows the existing rule (`cvss31.exploit_maturity`). It is H when an Alert already `MENTIONS` that CVE and `TARGETS` that host. Otherwise it comes from KEV/SSVC.
A CVE without a CVSS v3.1 vector is listed as "not scored".

**Result subgraph** (new labels, used by nothing else; `--clear` and `cti_kg wipe` remove them):
```
(:Analysis {id, input, created})-[:INPUT]->(Vulnerability | Technique | Tactic)
(:Analysis)-[:TARGET]->(Asset)
(:Analysis)-[:HAS_SCORE]->(:Score {asset, cve, evs, level, cvss_base, env, env_vector, MAV, E, E_reason,
                                     P, P_terms, impact_mode, internet_path, beta, gamma, k})
(:Score)-[:FOR_ASSET]->(Asset)    (:Score)-[:FOR_CVE]->(Vulnerability)
(:Score)-[:BLAST_RADIUS {hops}]->(Asset)
```
`P_terms` lists every term of Eq. 15, e.g. `"Web: crit 0.5 × γ^1 = 0.25"`. The Browser can then show how P(u) adds up.
Each new run replaces the previous Analysis with the same input.

**Terminal output.** The same steps as text: the input, how it expanded, the targets, the paths, and for each score the vector → Env → P(u) sum → EVS → level. Use it as a backup if the Browser misbehaves.

**Browser queries** go into a new Step 5 of `docs/demo_queries.md`:
- the analysis graph: input → targets → Score nodes → CVEs, plus blast-radius edges;
- the attack paths to the targets (the `CAN_REACH` query, with the target as a parameter);
- the calculation table: one row per Score with every intermediate value;
- the P(u) breakdown (`UNWIND s.P_terms`).

**Files**
- new `score_kg/explain.py`: resolve the input, find the paths, score, print, and write the result subgraph. It reuses `graph.load`, `graph.cve_details`, `model.score`, `model.blast_radius` and `model.distances`, and the path query and `SPECIFIC_CWE` from `alert_kg/context.py`.
- `score_kg/__main__.py`: the `explain` subcommand.
- `tests/test_score_explain.py`: offline tests for the P(u) breakdown (the terms add up to `model.propagation`) and for building the result rows.
- `docs/scoring.md` (short section) and `docs/demo_queries.md` (Step 5).

**Check.** Run the command on CVE-2024-23897/Jenkins. Its EVS must equal the `alert_scores.csv` row (10.0) and its blast radius {Jenkins, API}. Then run T1574.010, TA0006, and a CVE with no `--asset`, and look at each in the Browser.
Finally, `--clear` must leave no `Analysis` or `Score` node.

**Decisions (approved 2026-11-16)**
1. Writing the results to Neo4j is accepted. `explain` is a separate command and is not part of `score_kg all`.
2. For technique and tactic input, only the CVEs the technique links to count, and paths go only to the hosts that have them.
3. No APOC Extended. Custom procedures can only wrap Cypher, so the EVS would need a second CVSS implementation.

## 8. Evaluation with Wazuh vulnerability detection pairs *(built 2026-11-16; results in docs/evaluation.md)*

### Context

The lab grew from 8 to 17 hosts (2026-11-16). Wazuh's vulnerability detector reports every (agent, package, CVE) it
finds. These pairs do **not** come from the graph: the graph's `HAS_VULNERABILITY` links come from OSV/NVD
(`asset_kg/link.py`). So they are an independent source. Today they are only used in `python -m asset_kg wazuh-check`
(link agreement, 8 hosts: P 9.7%, R 93.8%).

Problem they can fix: Part A's labelled set is tiny (A1 = 6 pentest pairs, 1 positive), so L0–L4 all tie at
NDCG@10 = 1.000 (a ceiling effect). Wazuh sees every package on every host, not only the one service per host in
`services.csv`, so its pairs give a much larger, realistic, scanner-produced inventory.

The user picked **pentest sampling frame** and asked what I recommend. Recommendation, in priority order:

1. **Pentest sampling frame** (chosen). Draw the next A1 targets from the Wazuh pairs with a recorded, stratified
   random sample. Today A1 rows are hand-picked, which is a selection bias a reviewer will raise.
2. **Wazuh VD severity as a baseline** (recommended, cheap). It is what a Wazuh SOC actually sorts by. It answers
   "is the EVS better than the tool's own ranking?" It is a one-function change.
3. **Forward-in-time KEV test on the Wazuh inventory** (recommended, the biggest gain). It is PLAN.md §6 tier A,
   still unbuilt. It gives hundreds of items and a label that does not come from the team.
4. Not recommended: treating Wazuh as link **ground truth**. Its misses are systematic (no-fix CVEs, upstream
   builds), so it would penalise correct links. Keep it as agreement and just rerun on 17 hosts.


### 1. Shared: export the Wazuh pairs — `eval_kg/wazuh_pairs.py` (new)

- Reuse `asset_kg/wazuh_check.py`: `wazuh_inventory()` (agent name→id, packages) and the paging loop in
  `wazuh_cves()`. Extend `_source` with `vulnerability.score.base`, `vulnerability.severity`,
  `vulnerability.detected_at` and `package.version`. Use `alert_kg.config.VULN_INDEX` and `alert_kg.fetch.search`.
- Map agent → `Asset.hostname` (`lab/assets.csv`). Join each CVE to the CTI graph for the CVSS v3.1 vector, EPSS,
  KEV and SSVC fields (the same item fields `eval_kg/run.py` already builds).
- Output: `data/eval/wazuh_pairs.csv`, a frozen snapshot with its date. Columns: asset, package, package_version,
  cve, wazuh_severity, wazuh_score, in_graph, graph_linked (whether the graph also links it), service_match
  (whether the package maps to a `services.csv` software via `lab/wazuh_packages.csv`).
- CLI: `python -m eval_kg wazuh-pairs` (needs the lab running). Everything later reads the CSV, not the live API,
  so the results can be reproduced.

### 2. Pentest sampling frame — `eval_kg/sample.py` (new)

- Frame = rows of `wazuh_pairs.csv` ∪ the graph's own links (so services Wazuh cannot see, such as Jenkins, Apache
  and Node, are not excluded). One row per (asset, CVE).
- Strata: zone × CVSS band (critical/high/medium-low) × **public exploit available** (KEV, or an exploit-db /
  Metasploit reference in the CVE's references; flag from the CTI graph). Oversample the exploit-available
  stratum, because a uniform sample of library CVEs would be almost all "not exploitable in a container". Record
  the inclusion probability per row so the report can say how the sample was drawn.
- Fixed seed (7, as elsewhere). Size via `--n` (default 20). Output `evaluation/pentest_candidates.csv` with the
  same columns as `pentest_results.csv`: `exploited` is pre-filled as `not_tried`, plus stratum, weight and
  a note on why the CVE was drawn.
- Team protocol (goes in `evaluation/README.md`): fixed time box per pair; `yes`/`no` require evidence; `no` must
  say whether the vulnerable feature was actually exercised (otherwise `not_tried`). This fixes the "weak
  negative" problem noted for Prant's rows. Already-labelled pairs are kept and marked `hand-picked`.
- `eval_kg/labels.py` reads the new rows unchanged. The A1 report adds a line on sample origin (hand-picked vs.
  sampled) and runs a sensitivity check that uses only the sampled rows.

### 3. Wazuh VD severity baseline — `eval_kg/ladder.py`

- Add `"WazuhVD"` to `BASELINES`. In `baselines()`, return Wazuh's `vulnerability.score.base` for the
  (asset, CVE) pair, looked up from `wazuh_pairs.csv`, falling back to the CVSS base when Wazuh did not report it
  (record how many fallbacks). It is reported as a ΔNDCG@10 row in `eval_score_ablation.md`, like the others.

### 4. Forward-in-time KEV test — `eval_kg/kev_forward.py` (new), `python -m eval_kg kev-forward`

- Items = every (asset, CVE) in `wazuh_pairs.csv` ∪ graph links, on all 17 hosts.
- Cut-off T0 (default 2026-05-01, option `--t0`). Score L0–L4 with **KEV as of T0** inside E (only KEV entries
  with `dateAdded` ≤ T0) and no alert evidence. Label = CVE added to KEV after T0. Exclude CVEs already in KEV at
  T0, and CVEs published after T0. EPSS baseline uses EPSS **at T0** (api.first.org `date=` parameter, cached
  under `data/raw/`). SSVC exploitation is set to `none` unless its timestamp is ≤ T0, otherwise it leaks the label.
- Reuse `eval_kg/metrics.py` (NDCG, P@k, MRR, paired bootstrap over items) and the report style of `run.py`.
  Output: `data/reports/eval_kev_forward.md`. State the number of positives up front. If it is < 5, the report
  says the test is underpowered instead of quoting CIs as evidence.
- MAV for pairs whose package is not a network service: keep the base AV (L2 = L1 for them). State this in the
  report.

### 5. Rerun the link agreement on 17 hosts

`python -m asset_kg wazuh-check`. No code change unless new packages need rows in `lab/wazuh_packages.csv`
(bind, postfix, dovecot and mariadb are already there; check Redis, Gitea and HR-App).

### Docs

`docs/evaluation.md`: add the KEV-forward test (Part A3), the WazuhVD baseline, and the sampling-frame procedure
for A1. Add "Wazuh pairs are a scanner's view, not exploitability" under threats to validity.

### Verification

- `python -m eval_kg wazuh-pairs` with the lab up: the row count per host is > 0 for every agent, and spot-check
  2 rows against the Wazuh dashboard.
- `python -m eval_kg sample --n 20` twice gives an identical file (seed). The strata counts printed match the CSV.
- `python -m eval_kg score-ablation` still runs. The new WazuhVD row appears.
- `python -m eval_kg kev-forward --t0 2026-05-01`: assert that no item is labelled positive with KEV in E, and that
  no CVE was published after T0.
- Unit tests in `tests/` for the stratified sampler (weights sum, determinism) and for the T0 filters, with tiny
  fixtures that need no Wazuh or Neo4j.

## 9. Evaluation rework: BR-based P and the consequence rung *(approved 2026-11-17)*

### Context
The evaluation can't currently tell EVS apart from CVSS. Reasons:
- **Labels:** A1 has 1 exploited pair, A3 has 0 positives, and A2 is empty on the 17-host run.
- **Tie artifact:** ties are broken by id (`eval_kg/metrics.py:36`), which hides the one real L0→L4 gain.
- **P(u) is nearly inert:** it uses R(u) normalised by |V_A|−1 (max +6%, 8/17 hosts get 0).
- **Paper inconsistency:** the tex says BR_1 "forms the input to the environmental scoring" (main_2.tex:228), but Eq. 16 uses R(u).

The user's confident result is the sensitivity analysis (Dep-PC: isolated, L/L/L → EVS drops). The professor wants the Part A ladder and Part B variants.

Decisions made:
1. Change Eq. 16 so P uses **BR_k(a,c)** with **noisy-OR**.
2. Add a **consequence-based Part A rung**, labelled with lab-measured impact.
3. **No expert panel**.
4. The LLM threat-report contribution is dropped.

Goal: a defensible result set in which every ladder rung has a non-saturated label, and EVS differs from CVSS in the direction the lab measurements support.

### Step 0: record the plan
Copy this plan into `docs/PLAN.md` as a new §9 (per the user's plan-first rule).

### Step 1: scoring change (new Eq. 16) — ~2.5 h
**New equation:**
P(a,c) = 1 − ∏_{v ∈ BR_k(a,c)\{a}} (1 − crit(v)·γ^{d_c(a,v)})
- Here k = 1 and the direction comes from m(c). P ∈ [0,1).
- EVS(c,a) = min(10, Env·(1+β·P(a,c))). Eq. 17 is unchanged.
- In the 17-host lab P takes the values 0, 0.25, 0.5, 0.625 or 0.75.

**Code changes:**
- `score_kg/model.py`: rewrite `propagation(edges, asset, crit_of, gamma, mode, k=1)` on top of `blast_radius()` (already there, L60-62). Update the module docstring.
- `score_kg/graph.py:63` `propagation(hostname, gamma, mode, k=1)`.
- Callers pass `model.impact_mode(vector)`:
  - `score_kg/run.py:40,101,304`: becomes a per-(asset, mode) cache.
  - `score_kg/explain.py:108,198`: the P terms now list BR members.
- Tests: update `tests/test_score_graph.py:34-35`, `tests/test_score_explain.py`, and `tests/test_eval_offline.py:62`. Add property tests:
  - an isolated host gives P = 0;
  - adding a critical neighbour never lowers P;
  - disruption mode equals compromise mode on the reversed graph.

**Paper and docs:**
- `docs/main_2.tex`: replace the §Propagation Term R(u) text and the equation with the BR form. Note that BR_k is defined in Algorithm 1, so line 228 is now true. Remove the LLM contribution bullet.
- `docs/scoring.md`: same edit, and fix the shifted equation numbers.

### Step 2: evaluation plumbing (eval_kg only) — ~1.5 h
- `eval_kg/metrics.py`:
  - **`ranked`:** a tie-aware variant that returns the **expected** metric over random orderings within tied groups (Monte Carlo, 200 shuffles, seed 7). It replaces the id tie-break, and the reports must state this.
  - **Add `average_precision`.**
  - **`paired_bootstrap`:** add a `strata` option that resamples positives and negatives separately, so no resample is ever skipped.
  - **`set_prf`:** keep it, and add `pooled_prf`, a micro-average over all (host, member) pairs.
- `eval_kg/ladder.py`:
  - add a **Random** baseline (seeded);
  - `levels()` takes p per item, not per asset.
- Callers of the old per-asset `propagation`:
  - `eval_kg/run.py:41,73`: compute p per (asset, impact_mode).
  - `eval_kg/kev_forward.py:87`: the same change.
  - `eval_kg/variants.py:70-85`: update `distances_for_p` and `propagation` to the noisy-OR form, so the "downstream" row uses each variant's set. This makes Part B's B0–B5 variants change EVS for real.

### Step 3: new rung A4, consequence ranking (the core evidence) — ~3 h
New function `consequence()` in `eval_kg/run.py` and CLI `python -m eval_kg consequence` (`__main__.py`).
- **Items:** every graph asset×CVE pair (≈615), built with `asset_cve_items` (run.py:36).
- **Label (independent of CR/IR/AR and CVSS):** the measured consequence of the pair, taken from `data/eval/observed_*.json` through `_load_observed()` (run.py:348):
  - compromise-mode CVE: |usable[a]| (the hosts that become usable from a);
  - disruption-mode CVE: |dependents[a]|;
  - grade = min(size, 3).
- **Report:**
  - **(a) Ladder table:** L0–L4 plus EPSS/KEV/SSVC/Wazuh/Random, scored with NDCG@10/@50, AP (grade ≥ 1), and Kendall τ-b against the grade, using tie-aware metrics. Show stratified paired-bootstrap CIs for L4−L0 and L4−best baseline.
  - **(b) Same CVE on different hosts:** for every CVE present on ≥ 2 hosts, the share of host pairs whose EVS order agrees with their measured-consequence order. CVSS ties these pairs by construction, so it scores 0.5. This is the headline result: "CVSS cannot separate them; EVS does, in the measured direction."
  - **(c) CVSS ties broken:** among pairs tied on CVSS base, the fraction EVS separates, and how many of those it separates in the right direction.
- **Threat to validity, stated in the report:** the label and Part B share the same measurements, and the edges reflect the intended flows. This rung shows that EVS agrees with measured lab impact; it does not show exploit prediction.

### Step 4: sensitivity on 17 hosts (the user's confident result, strengthened) — ~1 h
In `eval_kg/run.py:257` `sensitivity()`:
- rerun on the 17-host lab with the new P;
- add the per-factor attribution (ΔL1, ΔL2, ΔL3, ΔL4 per asset), so the Dep-PC drop is shown coming from CR/IR/AR, and the BR uplift on Jump/Jenkins/API from P;
- add a same-CVE exemplar table (e.g. CVE-2024-6387 on Admin-PC vs Dep-PC).

### Step 5: Part B fixes — ~1.5 h
In `eval_kg/run.py:362` `blast_ablation()`:
- report pooled micro P/R/F1, and report hosts with empty truth separately, so B0 gets no free credit;
- the "downstream" row now ranks with the A4 consequence labels, so the variants actually differ;
- add a short scenario-pivot check: compare the pivots in S01, S08/S10, S11 and S12 (each scenario's `pivot: true` steps, read via `labels.load_scenarios`) against BR_1 from each foothold, and report hit or miss per scenario.

### Step 6: rerun, plots, docs — ~2 h
- Run `python -m eval_kg measure` (only if the measured truth is stale), then `python -m eval_kg all`, then `python -m eval_kg plot`.
- Update the figure functions in `eval_kg/plots.py` for A4.
- `evaluation/README.md`: add a dated "Changes 2026-11-17" section covering the Eq. 16 change, tie-aware metrics, the stratified bootstrap, rung A4 and its label, pooled Part B metrics, and what each rung can and cannot claim.
- `docs/evaluation.md`: update the protocol.

### Out of scope (state as future work)
- the expert panel;
- a new pentest labelling round;
- the A2 17-host regression (only a 30-min timebox at the end if time remains);
- CALDERA emulation;
- the LLM report.

### Verification
- `pytest tests/`: all pass, including the new property tests.
- `python -m eval_kg all --labels evaluation/dry_run` runs the pipeline end to end.
- Real run: confirm L0's A1 NDCG is no longer the artifact 1.000.
- A4 sanity checks:
  - CVSS (L0) gets 0.5 on the same-CVE contrasts;
  - Random gets ≈ prevalence AP;
  - Dep-PC pairs get grade 0.
- Spot-check 3 EVS values by hand with `python -m score_kg explain`.
- Rebuild the tex (if a LaTeX toolchain is present) and check that Eq. 16 renders.


## Proposed order of work

| # | Step | Depends on |
|---|---|---|
| 0 | Housekeeping (fix, commit, decisions) | — |
| 1 | Lab testbed + `assets.yaml` | your decisions in section 1 |
| 2 | Asset graph collector + loader | 1 |
| 3 | Asset↔CTI linking + Wazuh-based validation | 2 |
| 4 | Alert ingestion + query templates | 3 |
| 5 | Scoring | 4 |
| 6 | Evaluation scenarios + report | 5 |

Each step will get its own detailed plan, which you approve before I write any code.

## Open questions for you (summary)
1. Lab: VMs or Docker? Which OSes and software? Is a Windows host needed?
2. Asset value: scale and who assigns it.
3. Asset schema: minimal custom, or adopt an ontology (D3FEND/UCO)?
4. Distro backport false positives: accept, or add OVAL data?
5. Alert entity extraction: rule-based only, or ML extraction as a contribution?
6. Scoring: transparent formula only, or is an ML/GNN model expected?
7. The two leftover CTI-graph decisions in section 0.
