# Demo script: Neo4j Browser walkthrough

Shows the graph being built in order: clean database → CTI → assets → CTI–asset links → alerts.
Open the Neo4j Browser at http://localhost:7474 and paste each query into the editor at the top
(Ctrl+Enter runs it). Each step has a shell command, then queries to show, then a line on what to say.

Tested on 2026-11-16 against the full graph (406,586 CVEs, 8 lab hosts, 2,023 alerts). Every query runs in under a second.

> **Before class.** `cti_kg load` of the full CVE corpus takes a long time. Run Step 0 and Step 1
> before the demo, or plan to talk while it loads. Steps 2–4 take only seconds.
>
> **Browser tip.** If a picture shows extra edges you did not ask for, turn off
> *Settings (gear icon, bottom left) → Connect result nodes*.

---

## Step 0: Clean database

```bash
python -m cti_kg wipe
```

```cypher
MATCH (n) RETURN count(n) AS nodes
```
```cypher
CALL db.schema.visualization()
```
Point out: 0 nodes and an empty schema.

---

## Step 1: CTI side

```bash
python -m cti_kg load      # uses data/processed/, so it does not download or parse again
```

### 1.1 CTI schema only
```cypher
CALL apoc.meta.subGraph({labels: ['Weakness','Vulnerability','AttackPattern','Technique','Tactic',
  'Group','Mitigation','DetectionMethod','Platform','CPE']})
```
Point out: the threat layer of Nagaty et al. CWE, CVE, CAPEC and ATT&CK are joined in one graph, plus CPE (product identifiers).

### 1.2 How much was loaded
```cypher
CALL apoc.meta.stats() YIELD labels, relTypesCount
RETURN labels, relTypesCount
```

### 1.3 Samples

**a) A full threat chain: product → CVE ← CWE → CAPEC → ATT&CK technique → tactic**
```cypher
MATCH p = (:CPE)-[:VULNERABLE_TO]->(:Vulnerability)<-[:EXPLOITED_BY]-(:Weakness)
          -[:CAUSES_WEAKNESS]->(:AttackPattern)-[:USES_TECHNIQUE]->(:Technique)-[:IMPLEMENTS]->(:Tactic)
RETURN p LIMIT 3
```

**b) One weakness (XSS, CWE-79) and its neighbourhood: mitigations, detection methods, platforms, child CWEs**
```cypher
MATCH (w:Weakness {cwe_id: 'CWE-79'})-[r:MITIGATED_BY|DETECTED_BY|AFFECTS|IS_PARENT]->(x)
RETURN w, r, x LIMIT 30
```

**c) A threat group, the techniques it uses, and their tactics**
```cypher
MATCH p = (g:Group)-[:USES_TECHNIQUE]->(:Technique)-[:IMPLEMENTS]->(:Tactic)
WITH g, collect(p)[..15] AS paths
RETURN paths LIMIT 1
```

**d) CVE properties as a table: CVSS and CISA KEV**
```cypher
MATCH (v:Vulnerability) WHERE v.kev_date_added IS NOT NULL
RETURN v.cve_id, v.cvss3_score, v.cvss3_severity, v.kev_date_added, left(v.description, 120) AS description
LIMIT 5
```

---

## Step 2: Asset side

```bash
python -m asset_kg load    # load only, no links yet
```

### 2.1 Asset schema only
```cypher
CALL apoc.meta.subGraph({labels: ['Zone','Asset','Service','Software']})
```
Point out: zones, hosts, the services they run and the software behind each service. Nothing connects to the CTI side yet.
(If `link` already ran, a `CAN_REACH` edge shows up here too.)

### 2.2 Samples (the lab is small, so this shows all of it)

**a) Zones → hosts → services → software**
```cypher
MATCH p = (:Zone)<-[:IN_ZONE]-(:Asset)-[:RUNS]->(:Service)-[:IMPLEMENTED_BY]->(:Software)
RETURN p
```

**b) Network topology: firewall rules (zone → zone) and application flows (host → host)**
```cypher
MATCH p = (:Zone)-[:ALLOWED_TO_REACH]->(:Zone) RETURN p
UNION
MATCH p = (:Asset)-[:CONNECTS_TO]->(:Asset) RETURN p
```

**c) Hosts as a table, with business criticality (CVSS security requirements CR/IR/AR)**
```cypher
MATCH (a:Asset)-[:IN_ZONE]->(z:Zone)
RETURN a.hostname, z.name AS zone, a.ip, a.os, a.cr, a.ir, a.ar
ORDER BY zone
```

---

## Step 3: Links between the CTI side and the asset side

```bash
python -m asset_kg link
```

### 3.1 Bridge schema
```cypher
CALL apoc.meta.subGraph({labels: ['Zone','Asset','Service','Software','CPE','Vulnerability','Platform'],
  rels: ['IN_ZONE','RUNS','IMPLEMENTED_BY','IDENTIFIED_AS','HAS_VULNERABILITY','VULNERABLE_TO','RUNS_ON','CAN_REACH']})
```
Point out the four new edge types. `IDENTIFIED_AS` and `HAS_VULNERABILITY` map software to CPEs and CVEs.
`RUNS_ON` maps a host's OS to an ATT&CK platform. `CAN_REACH` records which zones and hosts can reach which services.

### 3.2 Samples

**a) Software → CPE → CVE (the NVD version-range match)**
```cypher
MATCH p = (:Software)-[:IDENTIFIED_AS]->(:CPE)-[:VULNERABLE_TO]->(:Vulnerability)
RETURN p LIMIT 25
```

**b) The CVEs on one host**
```cypher
MATCH p = (:Asset {hostname: 'Jenkins'})-[:RUNS]->(:Service)-[:IMPLEMENTED_BY]->(:Software)
          -[:HAS_VULNERABILITY]->(:Vulnerability)
RETURN p LIMIT 25
```

**c) Vulnerable software per host, as a table**
```cypher
MATCH (a:Asset)-[:RUNS]->(:Service)-[:IMPLEMENTED_BY]->(sw:Software)-[h:HAS_VULNERABILITY]->(v)
RETURN a.hostname, sw.id AS software, count(v) AS cves, collect(DISTINCT h.via) AS matched_via
ORDER BY cves DESC
```
Point out `matched_via`. `nvd` means the CVE came from NVD version ranges. `osv:...` means it came from Debian/Ubuntu security data, which accounts for backported fixes.

**d) The full chain from a host to an ATT&CK technique**
```cypher
MATCH p = (:Asset)-[:RUNS]->(:Service)-[:IMPLEMENTED_BY]->(:Software)-[:HAS_VULNERABILITY]->(:Vulnerability)
          <-[:EXPLOITED_BY]-(:Weakness)-[:CAUSES_WEAKNESS]->(:AttackPattern)-[:USES_TECHNIQUE]->(:Technique)
RETURN p LIMIT 5
```

**e) OS bridge: the hosts a technique (Unix shell, T1059.004) can run on**
```cypher
MATCH p = (:Technique {attack_id: 'T1059.004'})-[:AFFECTS]->(:Platform)<-[:RUNS_ON]-(:Asset)
RETURN p
```

**f) Attack paths from the Internet to the database**
```cypher
MATCH p = (:Zone {name: 'Internet'})-[:CAN_REACH]->(:Service)<-[:RUNS]-(:Asset)
          (()-[:CAN_REACH]->(:Service)<-[:RUNS]-(:Asset)){0,3}
WHERE last(nodes(p)).hostname = 'PostgreSQL'
RETURN p LIMIT 25
```

---

## Step 4: Alerts

```bash
python -m alert_kg load    # loads the saved data/alerts/raw.jsonl, so the lab does not need to run
python -m score_kg alerts  # adds the EVS score and blast radius to alerts that report a CVE
```

### 4.1 Alert schema
```cypher
CALL apoc.meta.subGraph({labels: ['Alert','Asset','Zone','Technique','Vulnerability'],
  rels: ['TARGETS','INDICATES','MENTIONS','FROM']})
```

### 4.2 Samples

**a) Alerts and what they point to**
```cypher
MATCH p = (:Alert)-[:TARGETS|INDICATES|MENTIONS|FROM]->()
RETURN p LIMIT 50
```

**b) A CVE alert in context (Jenkins CVE-2024-23897)**
The alert names a CVE. The graph confirms that the targeted host runs software with that CVE, and shows the CWE behind it.
```cypher
MATCH (al:Alert)-[:MENTIONS]->(:Vulnerability {cve_id: 'CVE-2024-23897'})
WITH al LIMIT 1
MATCH p1 = (al)-[:TARGETS]->(:Asset)-[:RUNS]->(:Service)-[:IMPLEMENTED_BY]->(:Software)
           -[:HAS_VULNERABILITY]->(v:Vulnerability)<-[:MENTIONS]-(al)
OPTIONAL MATCH p2 = (al)-[:FROM]->()
OPTIONAL MATCH p3 = (v)<-[:EXPLOITED_BY]-(:Weakness)
RETURN p1, p2, p3
```

**c) A technique alert in context (T1190, Exploit Public-Facing Application)**
It shows the alert → technique → tactic, whether the technique applies to the target's OS, the mitigations, and where the alert came from.
```cypher
MATCH (al:Alert)-[:INDICATES]->(:Technique {attack_id: 'T1190'})
WITH al LIMIT 1
MATCH p1 = (al)-[:INDICATES]->(t:Technique)-[:IMPLEMENTS]->(:Tactic)
OPTIONAL MATCH p2 = (al)-[:TARGETS]->(:Asset)-[:RUNS_ON]->(:Platform)<-[:AFFECTS]-(t)
OPTIONAL MATCH p3 = (t)-[:MITIGATED_BY]->(:Mitigation)
OPTIONAL MATCH p4 = (al)-[:FROM]->()
RETURN p1, p2, p3, p4
```

**d) Prioritisation: alerts ranked by Environmental Vulnerability Score**
```cypher
MATCH (al:Alert) WHERE al.evs IS NOT NULL
RETURN al.description, al.evs_cve, al.evs, al.evs_level, al.blast_radius
ORDER BY al.evs DESC LIMIT 10
```

---

## Step 5: Blast radius and EVS for any input

One command computes the attack paths, blast radius and EVS for a CVE, an ATT&CK technique or a tactic.
It uses the same scoring code as `score_kg alerts`, prints every step, and saves the result in the graph as
`Analysis` and `Score` nodes so the Browser can draw it. `--asset` is optional. Without it, the targets are every
lab host the input links to.

```bash
python -m score_kg explain --cve CVE-2024-23897 --asset Jenkins
python -m score_kg explain --technique T1574.010
python -m score_kg explain --tactic TA0006
```
The run prints its id at the end, e.g. `Analysis {id: 'CVE-2024-23897@Jenkins'}` (`<input>@<asset>`, or
`@all` without `--asset`). Set it once in the Browser, and every query below uses it:
```
:param id => 'CVE-2024-23897@Jenkins'
```

What the inputs do:
- **CVE**: targets = the hosts whose software has it.
- **Technique**: Technique ← CAPEC ← CWE (specific CWEs only) → CVEs on lab software. Targets are only the hosts that have one of those CVEs. Each of those CVEs is scored on its host.
- **Tactic**: expands to all of its techniques, then works like a technique.

### 5.1 The result: input → targets → scores → CVEs, with blast radius
```cypher
MATCH (an:Analysis {id: $id})
OPTIONAL MATCH p1 = (an)-[:INPUT|TARGET]->()
OPTIONAL MATCH p2 = (an)-[:HAS_SCORE]->(:Score)-[:FOR_ASSET|FOR_CVE|BLAST_RADIUS|VIA_TECHNIQUE]->()
RETURN an, p1, p2
```
Point out: each `Score` node is one (asset, CVE) pair and its caption is the EVS. `BLAST_RADIUS` edges (with `hops`)
go to the affected assets. Click a Score node to see every intermediate value.

### 5.2 Attack paths from the Internet to the targets
```cypher
MATCH (an:Analysis {id: $id})-[:TARGET]->(a:Asset)
MATCH (i:Zone {name: 'Internet'})
MATCH p = SHORTEST 3 (i) ((x)-[:CAN_REACH]->(:Service)<-[:RUNS]-(y)){1,4} (a)
RETURN p
```
Hosts in the Office zone have no path: the firewall does not let the Internet reach them.

### 5.3 Why a technique leads to these CVEs (technique and tactic input only)
```cypher
MATCH (an:Analysis {id: $id})-[:HAS_SCORE]->(s:Score)-[:FOR_CVE]->(v:Vulnerability)
MATCH p = (v)<-[:EXPLOITED_BY]-(w:Weakness)-[:CAUSES_WEAKNESS]->(ap:AttackPattern)-[:USES_TECHNIQUE]->(t:Technique)
WHERE w.cwe_id IN s.cwes AND ap.capec_id IN s.capecs AND t.attack_id IN s.techniques
MATCH q = (s)-[:FOR_ASSET]->(:Asset)
RETURN p, q
```

### 5.4 The EVS calculation as a table
```cypher
MATCH (an:Analysis {id: $id})-[:HAS_SCORE]->(s:Score)
RETURN s.asset AS asset, s.cve AS cve, s.cvss_base AS base, s.impact_mode AS mode,
       s.MAV AS MAV, s.E AS E, s.E_reason AS E_reason, s.CR + '/' + s.IR + '/' + s.AR AS `CR/IR/AR`,
       s.env_vector AS env_vector, s.env AS env, s.P AS P, s.evs_formula AS evs_formula, s.level AS level,
       s.blast_radius AS blast_radius
ORDER BY s.evs DESC
```
Walk through one row from left to right: base CVSS, then MAV (Internet reachability of the zone), E (exploitation evidence) and
CR/IR/AR (the asset's value) make the Environmental vector. That gives Env, and then EVS = min(10, Env × (1 + β·P)).

### 5.5 How P(u) adds up (Eq. 15)
```cypher
MATCH (an:Analysis {id: $id})-[:HAS_SCORE]->(s:Score)
RETURN DISTINCT s.asset AS asset, s.P AS P, s.P_terms AS terms
```
Each term is one asset reachable from u: its criticality × γ^hops, divided by |V_A| − 1.

To remove every result: `python -m score_kg explain --clear`.

---

## Ending: the whole unified graph
```cypher
CALL db.schema.visualization()
```
