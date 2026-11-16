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
