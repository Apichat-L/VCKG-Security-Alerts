# Stage 4: Environmental Vulnerability Score (EVS)

This document is the implementation of the paper's §III.A.2–3 ("Affected Assets Identification" and
"Environmental Vulnerability Score"). Equation numbers match the paper. Code: `score_kg/model.py` (the
equations), `score_kg/cvss31.py` (Table I), `score_kg/graph.py` (graph queries) and `score_kg/run.py`
(outputs). The parameters the paper leaves open are listed in §5.

## 1. Input: vulnerability instances (a, c)

A monitoring tool reports a vulnerability instance as a pair (a, c): a ∈ V_A is the affected asset and c
is the reported CVE.

| Source | How the pair is found (`alert_kg`) |
|---|---|
| Suricata (EVE JSON, forwarded by the Wazuh agent `ids`) | a = the asset whose IP is `data.dest_ip`. c = `data.alert.metadata.cve` (`CVE_2024_23897` → `CVE-2024-23897`) or a CVE id in `data.alert.signature`. |
| Wazuh rules on a host agent (e.g. vulnerability detector) | a = the agent's host. c = `data.vulnerability.cve`. |

Alerts with the same rule, asset and CVE form one instance and are counted together. Alerts that name no CVE
are not scored, because the method is defined for (a, c). The threat report lists them separately.

## 2. Affected assets: blast radius (Eqs. 5–9, Algorithm 1)

**Asset Reachability Graph G_R (Eqs. 5–6).** This is a projection of the VCKG onto assets. The edges are the
`CONNECTS_TO` edges (u, v) that the network policy permits, written π(u, v): either u and v are in the same
zone, or zone(u) `ALLOWED_TO_REACH` zone(v). Zones only constrain traversal; they are never a way to expand
it.

**Impact mode.** m(c) = *compromise* if the CVSS v3.1 Confidentiality or Integrity impact of c is not None,
and *disruption* otherwise. A compromised host is a pivot towards what it can reach (out-neighbours, Eq. 7).
A disrupted host affects the hosts that depend on it (in-neighbours, Eq. 8).

**Blast radius (Eq. 9).** BR_k(a, c) = {v : d_c(a, v) ≤ k}, using a breadth-first search on G_R in the
direction m(c). It always contains a itself, at distance 0. In this work k = 1.

In the lab, `CONNECTS_TO` (`lab/asset_edges.csv`) contains Nginx→Web, Web→API, Jenkins→API, API→PostgreSQL
and Admin-PC→Files-SMB. For example:

- BR₁(Jenkins, compromise) = {Jenkins, API}
- BR₁(API, disruption) = {API, Web, Jenkins}

## 3. Environmental score Env(c, u) (Eqs. 10–13, Table I)

The CVSS v3.1 Environmental equation is applied to the base vector of c, using metrics taken from the VCKG
instead of being assigned by hand. The `cvss` library computes it to the FIRST specification, including
Roundup.

| Metric | Derivation (Table I) |
|---|---|
| CR, IR, AR | the attributes of u's Asset node (`lab/assets.csv`, with a justification) |
| MAV | the base AV if a path of `ALLOWED_TO_REACH` edges, of any length, connects the Internet zone to zone(u). Otherwise AV:N is lowered to A; A, L and P stay as they are. In the lab, DMZ, APP and DATA are reachable (Internet→DMZ→APP→DATA); Office and MGMT are not (Office→MGMT and MGMT→DMZ/APP/DATA point away from the Internet) |
| E | first match wins: **H** if an alert reports c on u; **H** if c is in CISA KEV or CISA vulnrichment SSVC `exploitation = active`; **P** if `poc`; **U** if `none`; otherwise Not Defined. See §5 for how this differs from the paper's Table I |
| RL, RC | Not Defined |
| all other metrics | the base values of c |

## 4. Propagation and final score (Eqs. 14–17)

```
crit(v) = max(CR_v, IR_v, AR_v) − 0.5            weights H 1.5, M 1.0, L 0.5  →  H 1, M 0.5, L 0      (14)
P(u)    = 1/(|V_A| − 1) · Σ_{v ∈ R(u)\{u}} crit(v) · γ^d(u,v)                                         (15)
EVS     = min(10, Env(c, u) · (1 + β · P(u)))                                                         (16)
level   = Critical 9.0–10, High 7.0–8.9, Medium 4.0–6.9, Low 0.1–3.9                                  (17)
```

R(u) is every asset reachable from u in G_R, at any depth, and d(u, v) is the shortest hop distance. Each
graph signal enters exactly one term. Internet exposure changes only MAV, and lateral reachability changes
only P(u).

Lab example. P(Nginx) = (crit(Web)·γ + crit(API)·γ² + crit(PostgreSQL)·γ³) / 7 = (0.5 + 0.25 + 0.125) / 7 = 0.125.
With β = 0.5, Nginx's EVS is Env × 1.0625.

## 5. Choices the paper leaves to the implementation

| Choice | Value | Where |
|---|---|---|
| β (bound on the uplift) | 0.5. With P = 1, EVS = 1.5 × Env | `SCORE_BETA`, `--beta` |
| γ (distance discount) | 0.5 | `SCORE_GAMMA`, `--gamma` |
| k (blast-radius depth) | 1, as in the paper | `SCORE_BLAST_K`, `--k` |
| Rounding of the EVS | rounded up to one decimal, like every CVSS score (CVSS Roundup) | `model.roundup` |
| Internet zone | the Zone named `Internet` | `SCORE_INTERNET_ZONE` |
| E (exploit code maturity) | Deliberately broader than the paper's Table I, which has only "H if the alert maps to c on u, otherwise Not Defined". Threat intelligence sets E for every CVE: KEV or SSVC `active` → H, `poc` → P, `none` → U. An alert observed in this environment raises it to H. So the CVSS temporal metric reflects both global exploitation and local evidence, and vulnerabilities nobody exploits are demoted even when there is no alert | `score_kg/cvss31.py::exploit_maturity` |
| Vulnerabilities on an asset without an alert | scored with E from KEV/SSVC (above) | `python -m score_kg vulns` |
| Alerted CVE not linked to the asset's software | still scored, and flagged `present_on_asset_per_graph: false` (e.g. an attempt against software the host does not run) | assessment JSON |

`python -m score_kg sensitivity` reports how the ranking changes for β ∈ {0, 0.25, 0.5, 0.75, 1} and
γ ∈ {0.25, 0.5, 0.75}.

## 6. Outputs

| Output | Content |
|---|---|
| `data/reports/assessments/<asset>_<cve>_<rule>.json` | the structured object of §III.A.4 for each alerted instance: alert, affected asset (with CR/IR/AR and justification), CVE and base CVSS, Env, P(u), EVS, risk level, blast-radius assets with their CIA requirements, mitigations from the VCKG (CWE `MITIGATED_BY`, plus ATT&CK mitigations of the alert's technique). This is the input for the LLM threat report (not implemented yet) |
| `data/reports/threat_report.md` | alerted instances ranked by EVS with every intermediate value, the alerts that report no CVE, assets, and a CVSS band → EVS level matrix |
| `data/scores/alert_scores.csv`, `asset_cve_scores.csv` | every score and metric. The asset × CVE file also holds EPSS, KEV and CISA SSVC as **baselines** for stage 5; they are not part of the EVS |
| Neo4j | `Alert.evs`, `evs_level`, `evs_cve`, `blast_radius` |

## 7. Explaining one input (`explain`, for the demo)

`python -m score_kg explain --cve <id> | --technique <id> | --tactic <id> [--asset <host>]` runs the same
calculation for one input and prints every step. It is not part of `score_kg all`.

| Input | Targets and CVEs |
|---|---|
| CVE | the hosts whose software has it (or `--asset`, scored even when the CVE is not on its software, flagged `present_on_asset: false`) |
| Technique | Technique family ← CAPEC ← CWE (Base/Variant/Compound) → CVE on lab software, the link rule of `alert_kg`. Only hosts with such a CVE are targets |
| Tactic | all techniques that `IMPLEMENTS` it (with sub-techniques), then as Technique |

For each target: the 3 shortest attack paths from the Internet zone over `CAN_REACH` (≤ 4 hops). For each
(target, CVE): `model.score` (E = H when an alert already reports that CVE on that host), the terms of P(u) and BR_k.

The result goes to Neo4j as its own subgraph. Nothing else reads it. `explain --clear` removes it.
```
(:Analysis {id: '<input>@<asset|all>'})-[:INPUT]->(Vulnerability | Technique | Tactic)
(:Analysis)-[:TARGET {paths}]->(Asset)
(:Analysis)-[:HAS_SCORE]->(:Score)-[:FOR_ASSET]->(Asset)
                                  -[:FOR_CVE]->(Vulnerability)
                                  -[:BLAST_RADIUS {hops}]->(Asset)
                                  -[:VIA_TECHNIQUE]->(Technique)      the technique CAPEC maps to
```
`Score` holds every value of §3–4 (`env_vector`, `MAV`, `E`, `E_reason`, `env`, `P`, `P_terms`, `evs_formula`,
`evs`, `level`, `blast_radius`). The Browser queries are in [demo_queries.md](demo_queries.md), Step 5.
