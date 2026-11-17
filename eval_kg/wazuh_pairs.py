"""Wazuh vulnerability detection as an evaluation source (docs/PLAN.md §8).

Wazuh's vulnerability detector reports (agent, package, CVE) for every package on every host. The graph's
HAS_VULNERABILITY links do not use it (they come from OSV / NVD, asset_kg/link.py), so the two are independent.

  export()   the live states index -> data/eval/wazuh_pairs.csv, one row per (asset, CVE), a dated snapshot.
             Everything downstream reads the snapshot, so results can be reproduced without the lab.
  frame()    the evaluation inventory: Wazuh pairs ∪ the graph's own links, joined to the CTI graph for the
             CVSS vector, KEV date, SSVC and publication date. Used by the pentest sampler (sample.py), the
             WazuhVD baseline and the forward-in-time KEV test (kev_forward.py).

    python -m eval_kg wazuh-pairs        (needs the lab's Wazuh indexer and Neo4j)
"""
import csv
import re
from collections import defaultdict
from datetime import datetime, timezone

from asset_kg.db import driver
from asset_kg.loader import read_csv

from . import config

COLUMNS = ["asset", "cve", "packages", "package_versions", "wazuh_severity", "wazuh_score", "detected_at",
           "service_software"]

Q_GRAPH_LINKS = """
MATCH (a:Asset)-[:RUNS]->(:Service)-[:IMPLEMENTED_BY]->(sw:Software)-[h:HAS_VULNERABILITY]->(v:Vulnerability)
RETURN DISTINCT a.hostname AS asset, v.cve_id AS cve, sw.id AS software, h.via AS via
"""
Q_CVES = """
UNWIND $ids AS id
MATCH (v:Vulnerability {cve_id: id})
RETURN v.cve_id AS cve, v.cvss3_vector AS cvss3_vector, v.cvss3_score AS cvss3_score, v.published AS published,
       v.kev_date_added AS kev_date_added, v.kev_date_added IS NOT NULL AS kev,
       v.ssvc_exploitation AS ssvc_exploitation, v.ssvc_automatable AS ssvc_automatable,
       v.ssvc_technical_impact AS ssvc_technical_impact
"""
SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}


# ---------------------------------------------------------------------------------------------- export
def service_patterns() -> dict[str, list[tuple[str, re.Pattern]]]:
    """asset -> [(software, package regex)] for the network services services.csv says the asset runs."""
    pkg = {r["software"]: re.compile(r["package"]) for r in read_csv("wazuh_packages.csv")}
    out: dict = defaultdict(list)
    for r in read_csv("services.csv"):
        if r["software"] in pkg and (r["software"], pkg[r["software"]]) not in out[r["asset"]]:
            out[r["asset"]].append((r["software"], pkg[r["software"]]))
    return out


def aggregate(docs, hostnames: dict[str, str], services: dict) -> tuple[list[dict], dict]:
    """Wazuh documents -> one row per (asset, CVE). A CVE reported for several packages on one host keeps the
    highest score. Agents that are not lab assets (e.g. the IDS box) are counted and dropped."""
    rows: dict = {}
    skipped: dict = defaultdict(int)
    for d in docs:
        agent = d["agent"]["name"].lower()
        asset = hostnames.get(agent)
        if not asset:
            skipped[agent] += 1
            continue
        v, p = d["vulnerability"], d["package"]
        cve = v["id"].upper()
        score = (v.get("score") or {}).get("base")
        r = rows.setdefault((asset, cve), {"asset": asset, "cve": cve, "packages": set(), "package_versions": set(),
                                           "wazuh_severity": None, "wazuh_score": None, "detected_at": None,
                                           "service_software": set()})
        r["packages"].add(p["name"])
        r["package_versions"].add(f"{p['name']}={p.get('version', '')}")
        if score is not None and (r["wazuh_score"] is None or score > r["wazuh_score"]):
            r["wazuh_score"] = score
        sev = (v.get("severity") or "").strip()
        if SEVERITY_ORDER.get(sev.lower(), 0) > SEVERITY_ORDER.get((r["wazuh_severity"] or "").lower(), 0):
            r["wazuh_severity"] = sev
        if v.get("detected_at") and (r["detected_at"] is None or v["detected_at"] < r["detected_at"]):
            r["detected_at"] = v["detected_at"]
        r["service_software"].update(sw for sw, pat in services.get(asset, []) if pat.search(p["name"]))
    out = []
    for key in sorted(rows):
        r = rows[key]
        out.append({**r, **{k: ";".join(sorted(r[k])) for k in ("packages", "package_versions", "service_software")}})
    return out, dict(skipped)


def export() -> list[dict]:
    from asset_kg.wazuh_check import scan_vulnerabilities

    hostnames = {r["hostname"].lower(): r["hostname"] for r in read_csv("assets.csv")}
    docs = scan_vulnerabilities(["agent.name", "package.name", "package.version", "vulnerability.id",
                                 "vulnerability.severity", "vulnerability.score.base", "vulnerability.detected_at"])
    rows, skipped = aggregate(docs, hostnames, service_patterns())
    config.WAZUH_PAIRS.parent.mkdir(parents=True, exist_ok=True)
    taken = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    with open(config.WAZUH_PAIRS, "w", newline="", encoding="utf-8") as fh:
        fh.write(f"# Wazuh vulnerability detection snapshot taken {taken} (python -m eval_kg wazuh-pairs)\n")
        w = csv.DictWriter(fh, fieldnames=COLUMNS)
        w.writeheader()
        w.writerows(rows)
    per_asset = defaultdict(int)
    for r in rows:
        per_asset[r["asset"]] += 1
    print(f"Wazuh pairs: {len(rows)} (asset, CVE) on {len(per_asset)} assets -> {config.WAZUH_PAIRS}")
    for h in sorted(hostnames.values()):
        print(f"  {h:<11} {per_asset.get(h, 0):>5}" + ("   NO DETECTIONS" if not per_asset.get(h) else ""))
    if skipped:
        print(f"  not lab assets (dropped): {', '.join(f'{a} ({n})' for a, n in sorted(skipped.items()))}")
    return rows


def load(path=None) -> dict:
    """(asset, CVE) -> snapshot row; {} when no snapshot exists (Wazuh-based parts are then skipped)."""
    path = path or config.WAZUH_PAIRS
    if not path.exists():
        return {}
    with open(path, newline="", encoding="utf-8") as fh:
        lines = (ln for ln in fh if ln.strip() and not ln.startswith("#"))
        out = {}
        for r in csv.DictReader(lines):
            r["wazuh_score"] = float(r["wazuh_score"]) if r["wazuh_score"] else None
            out[(r["asset"], r["cve"])] = r
    return out


def snapshot_date(path=None) -> str | None:
    path = path or config.WAZUH_PAIRS
    if not path.exists():
        return None
    first = path.open(encoding="utf-8").readline()
    m = re.search(r"taken (\S+)", first)
    return m.group(1) if m else None


# ---------------------------------------------------------------------------------------------- frame
def merge(wazuh: dict, graph_links: list[dict], cves: dict) -> list[dict]:
    """Wazuh pairs ∪ graph links -> one item per (asset, CVE), with the CVE's CTI fields.

    source: 'both', 'wazuh' (scanner only: any package on the host) or 'graph' (graph only: e.g. software
    Wazuh cannot inventory, or a CVE the distribution lists as affected and Wazuh does not report)."""
    links: dict = defaultdict(list)
    for l in graph_links:
        links[(l["asset"], l["cve"])].append(l)
    out = []
    for key in sorted(set(wazuh) | set(links)):
        asset, cve = key
        w = wazuh.get(key)
        g = links.get(key, [])
        c = cves.get(cve) or {}
        out.append({
            "asset": asset, "cve": cve, "id": f"{asset}|{cve}",
            "source": "both" if w and g else ("wazuh" if w else "graph"),
            "in_graph": bool(c),
            "software": ";".join(sorted({l["software"] for l in g})) or None,
            "via": ";".join(sorted({l["via"] or "" for l in g})) or None,
            "packages": w["packages"] if w else None,
            "wazuh_score": w["wazuh_score"] if w else None,
            "wazuh_severity": w["wazuh_severity"] if w else None,
            # a network service of the host: a graph link (always a services.csv service) or a Wazuh package
            # that wazuh_packages.csv maps to one of the host's services
            "service": bool(g) or bool(w and w.get("service_software")),
            **{k: c.get(k) for k in ("cvss3_vector", "cvss3_score", "published", "kev_date_added", "kev",
                                     "ssvc_exploitation", "ssvc_automatable", "ssvc_technical_impact")},
        })
        out[-1]["kev"] = bool(out[-1]["kev"])
    return out


def frame(wait: int = 60, wazuh: dict | None = None) -> list[dict]:
    wazuh = load() if wazuh is None else wazuh
    with driver(wait) as drv, drv.session() as s:
        links = s.run(Q_GRAPH_LINKS).data()
        ids = sorted({c for _, c in wazuh} | {l["cve"] for l in links})
        cves = {r["cve"]: r for r in s.run(Q_CVES, ids=ids).data()}
    return merge(wazuh, links, cves)


def exploit_available(item: dict) -> bool:
    """Public exploit known: in CISA KEV, or CISA vulnrichment SSVC exploitation 'poc' / 'active'.
    (The CTI graph does not store CVE references, so exploit-db / Metasploit links cannot be checked.)"""
    return bool(item.get("kev")) or (item.get("ssvc_exploitation") or "").strip().lower() in ("poc", "active")
