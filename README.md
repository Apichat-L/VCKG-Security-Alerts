# Context-aware vulnerability classification with knowledge graphs

This project re-classifies the impact of security alerts using the context of the environment they
fire in. A Wazuh alert is mapped onto one Neo4j graph that combines:

- a **CTI knowledge graph**: CVE (cvelistV5 + NVD), CWE, CAPEC and MITRE ATT&CK, built the way Nagaty et al. (ICCA 2025) describe;
- an **asset knowledge graph** of a test network: hosts, zones, firewall rules, services, software versions and asset value (CR/IR/AR);
- **bridges** between the two: software → CPE → CVE, host → ATT&CK platform, and who can reach which service.

From that graph each alert gets a context: the target host, the source, the techniques and their
mitigations, the related CVEs, the attack paths, and the blast radius. Stage 4 will turn this context
into a new score and compare it with CVSS. Background: [outline_n_ideas.md](docs/outline_n_ideas.md), plan: [PLAN.md](docs/PLAN.md).

## Status

| Stage | Package | Status |
|---|---|---|
| 1. Lab test network (Docker) | `lab_env/` | done: 17 hosts in 5 zones (DMZ, APP, DATA, Office, MGMT), firewall with Suricata IDS, Kali, Wazuh 4.9.2, service logs collected |
| 2.1 CTI knowledge graph | `cti_kg/` | done for CVEs published 2024 and later |
| 2.2 Asset knowledge graph | `asset_kg/`, `lab/*.csv` | done |
| 2.3 Bridges (CVE, platform, reachability) | `asset_kg/link.py` | done |
| 3. Alert → graph queries | `alert_kg/` | done |
| 4. Environmental Vulnerability Score + threat report | `score_kg/` | done as in the paper (§III.A.2–3): blast radius, Env, P(u), EVS, structured JSON; the LLM report is not done yet ([docs/scoring.md](docs/scoring.md)) |
| 5. Evaluation | — | not started |

## How the pieces fit

```
lab_env/ (Docker: hosts + Wazuh)             repository root (Docker: Neo4j)
┌───────────────────────────────┐            ┌──────────────────────────────────────────┐
│ Kali → Firewall → DMZ/APP/... │            │ Neo4j  (one database)                    │
│ Wazuh agents ──► Wazuh manager│            │   CTI graph      ◄── python -m cti_kg    │
│              indexer :9200 ───┼── alerts ─►│   asset graph    ◄── python -m asset_kg  │
└───────────────────────────────┘            │   Alert nodes    ◄── python -m alert_kg  │
        lab/*.csv  (same hosts, by hand) ───►│                                          │
                                             └──────────► data/alerts/context/*.json    │
```

There are two separate Docker Compose setups. They are started and stopped separately:

| Setup | Compose file | Containers | Ports on localhost |
|---|---|---|---|
| Knowledge graph | `docker-compose.yml` (root) | `cti-neo4j` | 7474 (browser), 7687 (bolt) |
| Lab | `lab_env/docker-compose.yml` (project `vckg-lab`) | 23: firewall, IDS, kali, 17 hosts, 3 Wazuh | 8443 (dashboard), 9200 (indexer), 55500 (Wazuh API) |

The Python packages run on the host, from the repository's `.venv`, and talk to both setups through these ports.

## Repository layout

| Path | What it is |
|---|---|
| `cti_kg/` | CTI graph: download → parse → load → validate |
| `asset_kg/` | asset graph from `lab/*.csv`, plus the bridges to the CTI graph |
| `alert_kg/` | Wazuh alerts → `Alert` nodes → alert context JSON |
| `lab/` | hand-written description of the lab: `assets.csv`, `services.csv`, `zones.csv`, `zone_edges.csv`, `asset_edges.csv`, `os_platforms.csv` |
| `lab_env/` | the Docker lab itself, with its own [README](lab_env/README.md) |
| `overrides/` | manual corrections: platform aliases, entity merges, extra/removed edges, Wazuh rule → technique |
| `tests/` | pytest suite (offline tests + tests that need Neo4j and the loaded graphs) |
| `data/` | generated, git-ignored: raw downloads, processed JSONL, reports, alerts |
| `neo4j_data/` | Neo4j's database files, git-ignored |
| `docs/` | [schema.md](docs/schema.md), [PLAN.md](docs/PLAN.md), method notes |

## Requirements

- Windows with Docker Desktop (WSL2). Give Docker at least **8 GB of memory**, since the lab and Wazuh use about 4–5 GB.
- Python 3.12.
- About 5 GB of disk for images, plus about 1 GB for the CTI downloads.

## First-time setup

Run once, from the repository root. The commands work in PowerShell and in bash.

```powershell
# 1. Python environment
python -m venv .venv
.venv\Scripts\activate                 # bash: source .venv/Scripts/activate
pip install -r requirements.txt

# 2. Settings for the knowledge graph (Neo4j password: at least 8 characters)
copy .env.example .env                 # bash: cp .env.example .env ; then edit NEO4J_PASSWORD

# 3. Settings and TLS certificates for the lab
cd lab_env
copy .env.example .env                 # bash: cp .env.example .env
docker compose -f wazuh/generate-indexer-certs.yml run --rm generator
cd ..
```

`NEO4J_PASSWORD` in `.env` is used both by Neo4j (at its **first** start) and by the Python packages.
If you change it later, the existing database in `neo4j_data/` keeps the old password. Delete
`neo4j_data/` and reload, or change the password in the Neo4j browser.

## Start and stop

### Start (every session)

```powershell
# Knowledge graph
docker compose up -d                          # from the repository root
# -> Neo4j browser: http://localhost:7474  (user neo4j, password from .env)

# Lab
wsl -d docker-desktop sysctl -w vm.max_map_count=262144   # once after every Docker Desktop restart
cd lab_env
docker compose up -d                          # first time, or after editing a Dockerfile: add --build
cd ..
# -> Wazuh dashboard: https://localhost:8443  (admin / SecretPassword)
```

The Wazuh agents connect 1–2 minutes after the manager starts.
Check that everything is up:

```powershell
docker compose ps                             # root: cti-neo4j "Up"
docker compose -f lab_env/docker-compose.yml ps   # lab: 13 containers "Up"
```

You only need the lab for alert work (`alert_kg`) and for checking the lab itself. The CTI and asset
graphs only need Neo4j.

### Stop

```powershell
docker compose -f lab_env/docker-compose.yml down   # lab: containers stop, data volumes stay
docker compose down                                 # Neo4j: data stays in neo4j_data/
```

| Command | Containers | Data |
|---|---|---|
| `docker compose stop` | stopped, kept | kept |
| `docker compose down` | removed | kept (volumes, `neo4j_data/`) |
| `docker compose -f lab_env/docker-compose.yml down -v` | removed | **lab data deleted**: Wazuh alerts and agent registrations, Jenkins home, PostgreSQL |

Neo4j's data lives in the `neo4j_data/` folder, not in a Docker volume, so `down -v` at the root
does not delete it. Delete that folder to start the graph from scratch.

### Restart or rebuild part of the lab

```powershell
cd lab_env
docker compose restart wazuh.manager                 # after editing wazuh/config/wazuh_cluster/*.xml or *.conf
docker compose up -d --build web                     # after editing hosts/web/* (same for other hosts)
docker compose logs -f firewall                      # follow one container's output
docker compose exec admin-pc bash                    # shell inside a host
```

## Build the graphs

Neo4j must be running. Run these from the repository root with the virtualenv active.

### 1. CTI graph (`cti_kg`)

```powershell
python -m cti_kg all --since-year 2024     # download -> parse -> load -> validate -> stats
```

Steps can also be run one at a time: `download [--force]`, `parse`, `load [--wipe]`, `validate`, `stats`.
Without `--since-year` (and with an empty `CTI_SINCE_YEAR`), it loads the whole CVE corpus (1999+).
That needs a much longer download.

| Step | Output |
|---|---|
| download | `data/raw/` + `data/raw/manifest.json` (source versions, ETags, git commit) |
| parse | `data/processed/{catalog,cve/<year>}/` JSONL, `build_report.json`, `alignment_report.csv` |
| load | Neo4j (idempotent MERGE; `--wipe` for a clean rebuild) |
| validate | `data/reports/validation.md` (reproduces Table 1 of the paper) |

To make manual adjustments, edit `overrides/*.csv` (platform aliases, entity merges, added or removed
edges), then re-run `parse` and `load --wipe`. Automatic merges are listed in
`data/processed/alignment_report.csv` for review.

### 2. Asset graph and bridges (`asset_kg`)

```powershell
python -m asset_kg all --wipe     # load lab/*.csv -> link -> validate -> stats
```

`--wipe` removes only the nodes `asset_kg` created; CTI nodes are never touched. `link` rebuilds three bridges:

| Bridge | Edge | From |
|---|---|---|
| CVEs on a host | `Software -IDENTIFIED_AS-> CPE`, `Software -HAS_VULNERABILITY-> Vulnerability` | upstream builds: NVD version ranges for `cpe_vendor`/`cpe_product`/`version` in `lab/services.csv`; distro packages (`distro_package`, `package_version`): the distribution's security data from OSV (see below) |
| ATT&CK techniques for a host | `Asset -RUNS_ON-> Platform` | `os` in `lab/assets.csv` + `lab/os_platforms.csv` |
| Reachability | `Asset/Zone -CAN_REACH-> Service` | zones + `lab/zone_edges.csv` (= the lab's firewall rules) |

**Distro packages and backports.** Debian and Ubuntu patch security holes without changing the
upstream version. For example, Samba `2:4.17.12+dfsg-0+deb12u4` is still "4.17.12", yet some 4.17.12 CVEs
are fixed in it. NVD's upstream ranges cannot see that.

For software installed from the OS repository, set `distro_package` (the source package) and
`package_version` (the full `dpkg` version) in `lab/services.csv`. Its CVEs then come from that
distribution's security tracker via OSV, matched with dpkg version rules (`asset_kg/osv.py`,
`asset_kg/dpkg.py`). The OS → OSV ecosystem mapping is in `lab/os_ecosystems.csv`.

Download the OSV data once (about 900 MB), and again whenever you want fresher data:

```powershell
python -m asset_kg osv-download        # -> data/raw/osv/{Debian,Ubuntu}-all.zip
```

The first `link` after a download indexes each ecosystem into `data/processed/osv/` (this takes about a minute).

If you change the lab, update `lab/*.csv` to match and run the command again. To find the CPE
vendor/product pair for a piece of software:

```powershell
python -m asset_kg.find_cpe nginx                          # vendor:product pairs
python -m asset_kg.find_cpe --versions f5 nginx_open_source   # versions stored for one pair
```

#### Validate the CVE links against Wazuh

The lab must be running.

```powershell
python -m asset_kg wazuh-check
```

This compares each host's `HAS_VULNERABILITY` links with the CVEs that Wazuh's own vulnerability
detection reports for the same package on the same agent (`wazuh-states-vulnerabilities-*`).
Results are reported as **agreement**, not accuracy, because Wazuh is not ground truth ([PLAN.md](docs/PLAN.md) §3).
What it does:

- It scores only software that Wazuh inventories as a `.deb` package. `lab/wazuh_packages.csv` maps each software to its package.
- Apache httpd, Node.js and Jenkins are installed from source, a tarball and a WAR file. Wazuh cannot see them, so they are listed as "not scored".
- Wazuh CVEs that are not in the CTI graph, because those CVE years were not loaded, are counted separately.

| Output | Content |
|---|---|
| `data/reports/asset_cve_validation.md` | precision / recall per host and software, disagreements grouped by reason |
| `data/reports/asset_cve_disagreements.csv` | every CVE on only one side, with CVSS and the reason (e.g. what NVD's range says) |

### 3. Alerts → graph (`alert_kg`)

The lab must be running.

```powershell
python -m alert_kg all --since 24h     # fetch -> load -> context
```

| Step | Output |
|---|---|
| fetch | `data/alerts/raw.jsonl` (`wazuh-alerts-*` with `rule.level >= --min-level`, default 3) |
| load | `Alert` nodes: `TARGETS` Asset, `INDICATES` Technique, `MENTIONS` Vulnerability, `FROM` Asset/Internet |
| context | `data/alerts/context/<alert_id>.json`: target, source, techniques (+ tactics, mitigations), related CVEs, attack paths, blast radius |

Useful options:

- `context --alert <id>`: one alert only.
- `context --all-alerts`: also alerts without a technique or CVE.
- `load --input <file.jsonl>`: load a saved file instead of `data/alerts/raw.jsonl`.

How the extraction works:

- It is rule-based field mapping (`alert_kg/extract.py`).
- ATT&CK ids that MITRE has revoked are remapped to their replacements. The Wazuh 4.9 ruleset still uses some old ids, e.g. T1562.001 → T1685.
- Wazuh rules without `rule.mitre` can be mapped by hand in `overrides/wazuh_rule_techniques.csv`.

### 4. Environmental Vulnerability Score and threat report (`score_kg`)

This implements the paper's §III.A.2–3. It needs Neo4j with the graphs linked, and alert contexts from `alert_kg`.

```powershell
python -m score_kg all             # EVS of asset x CVE and of alerted instances, JSON assessments, report, sensitivity
python -m score_kg epss-download   # optional: EPSS, shown as a baseline next to the EVS (not part of it)
```

For each vulnerability instance (a, c) reported by an alert (Suricata via the Wazuh agent `ids`, or a Wazuh rule
naming a CVE):

1. **Blast radius** BR₁(a, c): the assets one `CONNECTS_TO` hop away that the firewall policy allows. Use
   out-edges if c compromises confidentiality or integrity, in-edges if it only affects availability.
2. **Env(c, u):** the CVSS v3.1 Environmental score with metrics from the graph (Table I):
   - CR/IR/AR of the asset;
   - MAV = base AV if the Internet zone reaches the asset's zone through `ALLOWED_TO_REACH`, otherwise N → A;
   - E = H for the alerted CVE, otherwise from threat intelligence (KEV or SSVC active → H, poc → P, none → U).
3. **EVS** = `min(10, Env · (1 + β·P(u)))`. P(u) is the criticality of the assets reachable from u, discounted by γ per hop.
4. **Level**: Critical / High / Medium / Low.

Defaults: β = 0.5, γ = 0.5, k = 1 (`--beta`, `--gamma`, `--k`, or `SCORE_BETA` / `SCORE_GAMMA` / `SCORE_BLAST_K`).
Method and design choices: [docs/scoring.md](docs/scoring.md).

| Output | Content |
|---|---|
| `data/reports/assessments/*.json` | the structured assessment per alerted instance (alert, asset, CVE, base CVSS, EVS, level, affected assets, mitigations): the input for the LLM threat report |
| `data/reports/threat_report.md` | alerted instances ranked by EVS with every intermediate value, alerts with no CVE (not scored), assets, CVSS band → EVS level |
| `data/scores/asset_cve_scores.csv`, `alert_scores.csv` | every score and metric. EPSS, KEV and SSVC are baseline columns only |
| `data/reports/score_sensitivity.md` | ranking stability for other β and γ |

## Look at the graph

Neo4j browser at http://localhost:7474. Do **not** run `MATCH (n) RETURN n`: the graph has over
300 000 nodes, and the browser will hang. Start with these instead:

```cypher
CALL db.schema.visualization()                                   // every label and edge type

MATCH (n) RETURN labels(n)[0] AS label, count(*) AS n ORDER BY n DESC

// the whole asset graph and its bridges
MATCH (n)-[r]->(m) WHERE 'asset_kg' IN coalesce(r.sources, []) RETURN n, r, m

// attack paths from the Internet to the database
MATCH p = (:Zone {name: 'Internet'})-[:CAN_REACH]->(:Service)<-[:RUNS]-(:Asset)
          (()-[:CAN_REACH]->(:Service)<-[:RUNS]-(:Asset)){0,3}
WHERE last(nodes(p)).hostname = 'PostgreSQL' RETURN p LIMIT 25

// alerts and what they point to
MATCH (al:Alert)-[r]->(x) RETURN al, r, x LIMIT 100
```

More queries and every label and edge: [schema.md](docs/schema.md).

## Check the lab

- Firewall and reachability checks, logins, and what Wazuh collects: see [lab_env/README.md](lab_env/README.md).
- Generate test alerts with harmless events. A missing page gives Wazuh rule 31101, and one wrong password gives 5760 / 50512 / 100110. The commands are in that README.

## Tests

```powershell
python -m pytest tests
```

The offline tests (parsers, version ranges, alert extraction) always run. The other tests need Neo4j
with the CTI and asset graphs loaded, and they skip themselves when Neo4j is not reachable. Alert tests load fixtures
with ids starting `test-` and remove them afterwards.

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `UnicodeDecodeError: 'charmap' codec ... cp874` | Windows with a Thai locale reads files as cp874. Fixed in code (all file I/O uses UTF-8); if it appears in new code, add `encoding="utf-8"`. |
| `cti-neo4j` restarts in a loop; log says the password must be at least 8 characters | Set an `NEO4J_PASSWORD` of 8+ characters in `.env`, then `docker compose up -d`. |
| `Neo4j rejected the username/password` | `.env` and the database disagree, because the password was changed after the first start. See *First-time setup*. |
| `Weakness` count is 0 after `cti_kg` | An old CWE parser. CWE 5.0 changed the XML namespace; the current parser reads both. Re-run `python -m cti_kg all`. |
| `cp: cannot create regular file '/certificates/...': Permission denied` | The certificate generator ran a second time; the certificates already exist. This is harmless; see [lab_env/README.md](lab_env/README.md). |
| Wazuh dashboard does not come up; indexer exits | `vm.max_map_count` was reset by a Docker Desktop restart. Run the `wsl -d docker-desktop sysctl ...` line, then `docker compose up -d` in `lab_env`. |
| `The token '\|\|' is not a valid statement separator` | Windows PowerShell 5.1 has no `\|\|` / `&&`. Use `sh -c "... \|\| ..."` inside the container, or PowerShell 7. |
| No new alerts at all | Check the manager with `docker compose -f lab_env/docker-compose.yml exec wazuh.manager grep -E "CRITICAL\|ERROR" /var/ossec/logs/ossec.log`. A bad local rule stops all analysis. |
| Events in the first minute after restarting the manager are missing | The agents restart when the manager does. Wait about a minute before generating events. |
| `alert_kg fetch`: cannot reach the indexer | The lab is not running, or Wazuh is still starting. |

## Known limitations

- **CTI only has CVEs from 2024 on.** Older software in a lab will not link to CVEs until the full corpus is loaded (`python -m cti_kg all` without `--since-year`).
- **Distro packages (Samba, OpenSSH) are matched to NVD ranges.** Distributions backport fixes without changing the version number, so these may over-report CVEs ([PLAN.md](docs/PLAN.md) §3).
- **Reachability is per zone and covers all ports,** like the current firewall rules. Per-port rules would need `lab/zone_edges.csv` and `link` to be extended.
- **All lab hosts are Linux,** so every host gets the same ATT&CK techniques through its platform.
- **Few techniques lead to CVEs.** Only about 174 ATT&CK techniques can be reached from CWE/CAPEC, so many alerts link to CVEs only when the alert names the CVE.
- **Wazuh rules without `rule.mitre`** (e.g. 31101, 50512) have no technique until they are mapped in `overrides/wazuh_rule_techniques.csv`.
