"""Validate the Software -[HAS_VULNERABILITY]-> CVE links against Wazuh's vulnerability detection.

PLAN.md section 3: Wazuh is not ground truth, so the result is reported as *agreement*, and only on
the part both sides can see:

  comparable        software that Wazuh inventories as a .deb package on the same host
                    (lab/wazuh_packages.csv maps Software.name -> package name)
  not inventoried   software installed from source, a tarball or a WAR (Apache httpd, Node.js, Jenkins):
                    Wazuh cannot see it, so the graph's links there are reported but not scored

For comparable pairs (asset, software):
  G  = CVEs the graph links to the software
  W  = CVEs Wazuh reports for the package on that agent, restricted to CVEs present in the CTI graph
       (the graph only holds the CVE years that were loaded; Wazuh CVEs outside it are counted apart)
  agreement = |G & W|,  precision = |G & W| / |G|,  recall = |G & W| / |W|

Every disagreement gets a reason and is written to data/reports/asset_cve_disagreements.csv.

    python -m asset_kg wazuh-check        (needs Neo4j and the lab's Wazuh running)
"""
import csv
import re
from collections import defaultdict
from datetime import date

import requests
import urllib3

from alert_kg import config as wz
from alert_kg.fetch import search

from . import config
from .db import driver
from .loader import read_csv

REPORTS = config.ROOT / "data" / "reports"
REPORT_MD = REPORTS / "asset_cve_validation.md"
REPORT_CSV = REPORTS / "asset_cve_disagreements.csv"

Q_GRAPH = """
MATCH (a:Asset)-[:RUNS]->(:Service)-[:IMPLEMENTED_BY]->(sw:Software)
OPTIONAL MATCH (sw)-[h:HAS_VULNERABILITY]->(v:Vulnerability)
RETURN a.hostname AS asset, sw.id AS software_id, sw.name AS software, sw.version AS version,
       sw.cpe_vendor AS vendor, sw.cpe_product AS product,
       sw.distro_package AS distro_package, sw.package_version AS package_version,
       collect(DISTINCT v.cve_id) AS cves,
       collect(DISTINCT {cve: v.cve_id, via: h.via, fixed: h.fixed_version}) AS links
ORDER BY asset, software_id
"""
Q_PRESENT = "UNWIND $ids AS id MATCH (v:Vulnerability {cve_id: id}) RETURN collect(id) AS present"
Q_NVD_CPES = """
UNWIND $ids AS id
MATCH (:Vulnerability {cve_id: id})<-[e:VULNERABLE_TO]-(c:CPE)
RETURN id, c.vendor AS vendor, c.product AS product, c.version AS version, properties(e) AS edge
"""
Q_CVSS = "UNWIND $ids AS id MATCH (v:Vulnerability {cve_id: id}) RETURN id, v.cvss3_score AS cvss3"

def graph_only_reason(via: str | None, fixed: str | None, pkg_vendor: str | None) -> str:
    """Why the graph links a CVE that Wazuh does not report, from where the link came from.

    services.csv decides what a package is: rows with distro_package use the distribution's data
    (via 'osv:...'); rows without it are declared upstream builds and use NVD. The package's
    maintainer string is shown, not interpreted (e.g. apt.postgresql.org builds are maintained by
    "Debian PostgreSQL Maintainers" but are upstream releases).
    """
    if via and via.startswith("osv:"):
        fix = f"fixed in {fixed}" if fixed else "no fix released yet"
        return f"distribution data ({via[4:]}) lists the installed version as affected ({fix}); Wazuh does not report it"
    return (f"upstream build (no distro_package in services.csv; maintainer {pkg_vendor or 'unknown'}): "
            "NVD range covers the version, Wazuh does not report it")


# ---------------------------------------------------------------------------------------------- Wazuh
def _api(session: requests.Session, path: str) -> dict:
    r = session.get(f"{wz.WAZUH_API_URL}{path}", timeout=60)
    r.raise_for_status()
    return r.json()["data"]


def wazuh_inventory() -> tuple[dict, dict]:
    """agent name -> agent id, and agent id -> [{name, version}] (syscollector packages)."""
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    s = requests.Session()
    s.verify = False
    try:
        r = s.post(f"{wz.WAZUH_API_URL}/security/user/authenticate?raw=true",
                   auth=(wz.WAZUH_API_USER, wz.WAZUH_API_PASSWORD), timeout=30)
    except requests.ConnectionError:
        raise SystemExit(f"cannot reach the Wazuh API at {wz.WAZUH_API_URL} (is lab_env running?)")
    if r.status_code == 401:
        raise SystemExit("Wazuh API rejected the login (WAZUH_API_USER / WAZUH_API_PASSWORD)")
    r.raise_for_status()
    s.headers["Authorization"] = f"Bearer {r.text.strip()}"

    agents = {a["name"].lower(): a["id"] for a in _api(s, "/agents?select=id,name&limit=500")["affected_items"]}
    packages = {aid: _api(s, f"/syscollector/{aid}/packages?select=name,version,vendor,source&limit=100000")["affected_items"]
                for name, aid in agents.items() if aid != "000"}
    return agents, packages


def scan_vulnerabilities(fields: list[str], query: dict | None = None, page: int = 1000):
    """Yield every document (its _source) of Wazuh's vulnerability states index, paging with search_after."""
    body = {"size": page, "_source": fields, "query": query or {"match_all": {}}, "sort": [{"_doc": "asc"}]}
    while True:
        hits = search(body, index=wz.VULN_INDEX)["hits"]["hits"]
        for h in hits:
            yield h["_source"]
        if len(hits) < page:
            return
        body["search_after"] = hits[-1]["sort"]


def wazuh_cves(agent_ids: list[str]) -> dict:
    """(agent id, package name) -> {cve id: wazuh severity}, from the vulnerability states index."""
    out: dict = defaultdict(dict)
    for d in scan_vulnerabilities(["agent.id", "package.name", "vulnerability.id", "vulnerability.severity"],
                                  {"terms": {"agent.id": agent_ids}}):
        out[(d["agent"]["id"], d["package"]["name"])][d["vulnerability"]["id"]] = d["vulnerability"].get("severity")
    return out


# ---------------------------------------------------------------------------------------------- reasons
def _range(edge: dict, version) -> str:
    if version not in (None, "", "*"):
        return f"={version}"
    return " ".join(sorted(edge.get("version_ranges") or [])) or "all versions"


def wazuh_only_reasons(session, cves: list[str], vendor: str, product: str, version: str) -> dict[str, str]:
    """Why the graph missed a CVE Wazuh reports: what NVD's CPE data says about it."""
    rows = defaultdict(list)
    for r in session.run(Q_NVD_CPES, ids=cves):
        rows[r["id"]].append(r)
    out = {}
    for cve in cves:
        ours = [r for r in rows[cve] if r["vendor"] == vendor and r["product"] == product]
        others = sorted({f"{r['vendor']}:{r['product']}" for r in rows[cve]})
        if ours:
            ranges = "; ".join(sorted({_range(r["edge"], r["version"]) for r in ours}))
            out[cve] = f"NVD range for {vendor}:{product} ({ranges}) does not include {version}"
        elif others:
            out[cve] = f"NVD lists other products only: {', '.join(others[:4])}{' ...' if len(others) > 4 else ''}"
        else:
            out[cve] = "no CPE in the NVD record (not yet analysed by NVD)"
    return out


# ---------------------------------------------------------------------------------------------- main
def _pct(a: int, b: int) -> str:
    return f"{100 * a / b:.1f}%" if b else "n/a"


def run(wait: int = 60) -> dict:
    mapping = {r["software"]: re.compile(r["package"]) for r in read_csv("wazuh_packages.csv")}
    agents, packages = wazuh_inventory()
    wcves = wazuh_cves(list(packages))

    rows, disagreements = [], []
    with driver(wait) as drv, drv.session() as s:
        for g in s.run(Q_GRAPH).data():
            aid = agents.get(g["asset"].lower())
            pattern = mapping.get(g["software"])
            pkg = None
            if aid and pattern:
                pkg = next((p for p in packages.get(aid, []) if pattern.search(p["name"])), None)
            csv_version = g["package_version"]
            row = {**g, "agent_id": aid, "package": pkg["name"] if pkg else None,
                   "package_version": pkg["version"] if pkg else None, "csv_package_version": csv_version,
                   "version_warning": None}
            if pkg and csv_version and pkg["version"] != csv_version:
                row["version_warning"] = f"services.csv says {csv_version}, Wazuh sees {pkg['version']}"
            elif pkg and not csv_version and g["version"] not in pkg["version"]:
                row["version_warning"] = f"services.csv says {g['version']}, Wazuh sees {pkg['version']}"
            if not aid:
                row["status"] = "no Wazuh agent"
            elif not pkg:
                row["status"] = "not inventoried by Wazuh" if not pattern else "package not found on agent"
            else:
                row["status"] = "comparable"
                reported = wcves.get((aid, pkg["name"]), {})
                present = set(s.run(Q_PRESENT, ids=list(reported)).single()["present"])
                G, W = set(g["cves"]), present
                row.update(both=sorted(G & W), graph_only=sorted(G - W), wazuh_only=sorted(W - G),
                           wazuh_outside_graph=sorted(set(reported) - present))
                cvss = {r["id"]: r["cvss3"] for r in s.run(Q_CVSS, ids=sorted(G ^ W))}
                links = {l["cve"]: (l["via"], l["fixed"]) for l in g["links"] if l["cve"]}
                reasons = wazuh_only_reasons(s, row["wazuh_only"], g["vendor"], g["product"], g["version"])
                for cve in row["graph_only"]:
                    disagreements.append([g["asset"], g["software_id"], pkg["name"], pkg["version"], cve,
                                          "graph only", cvss.get(cve),
                                          graph_only_reason(*links.get(cve, (None, None)), pkg.get("vendor"))])
                for cve in row["wazuh_only"]:
                    disagreements.append([g["asset"], g["software_id"], pkg["name"], pkg["version"], cve,
                                          "wazuh only", cvss.get(cve), reasons[cve]])
            rows.append(row)

    comp = [r for r in rows if r["status"] == "comparable"]
    tot = {k: sum(len(r[k]) for r in comp) for k in ("both", "graph_only", "wazuh_only", "wazuh_outside_graph")}
    tot["graph"] = tot["both"] + tot["graph_only"]
    tot["wazuh"] = tot["both"] + tot["wazuh_only"]

    REPORTS.mkdir(parents=True, exist_ok=True)
    with open(REPORT_CSV, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["asset", "software", "package", "package_version", "cve", "side", "cvss3", "reason"])
        w.writerows(disagreements)
    REPORT_MD.write_text(_markdown(rows, tot, disagreements), encoding="utf-8")

    print("asset -> CVE links vs Wazuh vulnerability detection (agreement, not ground truth)")
    for r in rows:
        if r["status"] == "comparable":
            print(f"  {r['asset']:<11} {r['software_id']:<20} {r['package']} {r['package_version']}: "
                  f"graph {len(r['both']) + len(r['graph_only'])}, wazuh {len(r['both']) + len(r['wazuh_only'])}, "
                  f"both {len(r['both'])} (wazuh CVEs outside the CTI graph: {len(r['wazuh_outside_graph'])}) "
                  f"[graph CVEs from {_sources(r)}]")
            if r["version_warning"]:
                print(f"      VERSION MISMATCH: {r['version_warning']}")
        else:
            print(f"  {r['asset']:<11} {r['software_id']:<20} {r['status']} ({len(r['cves'])} graph CVEs, not scored)")
    print(f"  total: agreement {tot['both']}, precision {_pct(tot['both'], tot['graph'])}, "
          f"recall {_pct(tot['both'], tot['wazuh'])}  -> {REPORT_MD}")
    return {"rows": rows, "totals": tot}


def _sources(r: dict) -> str:
    vias = sorted({l["via"] for l in r.get("links", []) if l.get("via")})
    return ", ".join(v.upper() if v == "nvd" else "OSV " + v[4:] for v in vias) or "-"


def _markdown(rows: list[dict], tot: dict, disagreements: list[list]) -> str:
    comp = [r for r in rows if r["status"] == "comparable"]
    other = [r for r in rows if r["status"] != "comparable"]
    L = [f"# Asset → CVE links vs Wazuh vulnerability detection",
         "",
         f"Generated {date.today().isoformat()} by `python -m asset_kg wazuh-check`. Method: `asset_kg/wazuh_check.py`.",
         "",
         "Wazuh is a second opinion, not ground truth (PLAN.md §3), so the numbers below are **agreement**. "
         "Only software that Wazuh inventories as a package on the same host is scored. "
         "Wazuh CVEs that are not in the CTI graph (CVE years not loaded) are counted separately, not as misses.",
         "",
         "## Summary (comparable software)",
         "",
         "| Graph CVEs | Wazuh CVEs (in graph) | Both | Graph only | Wazuh only | Precision | Recall | Wazuh CVEs outside the graph |",
         "|---:|---:|---:|---:|---:|---:|---:|---:|",
         f"| {tot['graph']} | {tot['wazuh']} | {tot['both']} | {tot['graph_only']} | {tot['wazuh_only']} | "
         f"{_pct(tot['both'], tot['graph'])} | {_pct(tot['both'], tot['wazuh'])} | {tot['wazuh_outside_graph']} |",
         "",
         "## Per asset and software",
         "",
         "| Asset | Software (graph) | Graph CVEs from | Package (Wazuh) | Graph | Wazuh | Both | Precision | Recall | Outside graph |",
         "|---|---|---|---|---:|---:|---:|---:|---:|---:|"]
    for r in comp:
        g, w = len(r["both"]) + len(r["graph_only"]), len(r["both"]) + len(r["wazuh_only"])
        L.append(f"| {r['asset']} | {r['software_id']} | {_sources(r)} | {r['package']} {r['package_version']} | {g} | {w} | "
                 f"{len(r['both'])} | {_pct(len(r['both']), g)} | {_pct(len(r['both']), w)} | {len(r['wazuh_outside_graph'])} |")
    warnings = [r for r in comp if r["version_warning"]]
    L += ["", "## Version check (services.csv vs Wazuh inventory)", ""]
    L += [f"- **{r['asset']} {r['software_id']}**: {r['version_warning']}" for r in warnings] or          ["All comparable software has the version Wazuh sees on the host."]
    L += ["", "## Not scored", "", "| Asset | Software | Graph CVEs | Why |", "|---|---|---:|---|"]
    for r in other:
        L.append(f"| {r['asset']} | {r['software_id']} | {len(r['cves'])} | {r['status']} |")
    by_reason = defaultdict(int)
    for d in disagreements:
        key = re.sub(r"fixed in [^)]+\)", "fixed in a later revision)", d[7]) if d[5] == "graph only" else re.sub(r"\(.*\)", "(...)", d[7].split(":")[0] if "other products" in d[7] else d[7])
        by_reason[(d[5], key)] += 1
    L += ["", "## Disagreements by reason", "", "| Side | Reason | CVEs |", "|---|---|---:|"]
    for (side, reason), n in sorted(by_reason.items(), key=lambda x: -x[1]):
        L.append(f"| {side} | {reason} | {n} |")
    L += ["", f"Every disagreement, with its CVSS and reason: `{REPORT_CSV.relative_to(config.ROOT).as_posix()}`.", ""]
    return "\n".join(L)
