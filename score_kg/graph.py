"""Read what the EVS needs from the unified graph (VCKG): assets, zones and policy, CONNECTS_TO, CVEs."""
from dataclasses import dataclass, field

from asset_kg.db import driver

from . import config, model

Q_ASSETS = """
MATCH (a:Asset)-[:IN_ZONE]->(z:Zone)
RETURN a.hostname AS hostname, a.ip AS ip, a.role AS role, a.os AS os, z.name AS zone,
       a.cr AS cr, a.ir AS ir, a.ar AS ar, a.justification AS justification
ORDER BY hostname
"""
Q_ALLOWED = "MATCH (a:Zone)-[:ALLOWED_TO_REACH]->(b:Zone) RETURN a.name AS src, b.name AS dst"
# Zones an Internet attacker can reach through ALLOWED_TO_REACH, at any depth (Table I, MAV rule)
Q_INTERNET_ZONES = """
MATCH (i:Zone {name: $internet})
OPTIONAL MATCH (i)-[:ALLOWED_TO_REACH*1..]->(z:Zone)
RETURN collect(DISTINCT z.name) AS zones, count(i) AS found
"""
Q_CONNECTS = "MATCH (a:Asset)-[:CONNECTS_TO]->(b:Asset) RETURN a.hostname AS src, b.hostname AS dst"
Q_VULNS = """
MATCH (a:Asset)-[:RUNS]->(:Service)-[:IMPLEMENTED_BY]->(sw:Software)-[h:HAS_VULNERABILITY]->(v:Vulnerability)
WHERE v.cvss3_vector IS NOT NULL
RETURN DISTINCT a.hostname AS asset, sw.id AS software, h.via AS via, v.cve_id AS cve,
       v.cvss3_vector AS cvss3_vector, v.kev_date_added IS NOT NULL AS kev,
       v.ssvc_exploitation AS ssvc_exploitation, v.ssvc_automatable AS ssvc_automatable,
       v.ssvc_technical_impact AS ssvc_technical_impact
ORDER BY asset, cve
"""
Q_CVE = """
UNWIND $ids AS id
MATCH (v:Vulnerability {cve_id: id})
RETURN v.cve_id AS cve, v.cvss3_vector AS cvss3_vector, v.cvss3_score AS cvss3_score,
       left(v.description, 400) AS description, v.kev_date_added IS NOT NULL AS kev,
       v.ssvc_exploitation AS ssvc_exploitation, v.ssvc_automatable AS ssvc_automatable,
       v.ssvc_technical_impact AS ssvc_technical_impact
"""
# Mitigations of a CVE through its specific CWEs (Base / Variant / Compound, as in alert_kg)
Q_CVE_MITIGATIONS = """
UNWIND $ids AS id
MATCH (:Vulnerability {cve_id: id})<-[:EXPLOITED_BY]-(w:Weakness)-[:MITIGATED_BY]->(m:Mitigation)
WHERE w.abstraction IN ['Base', 'Variant', 'Compound']
RETURN id, w.cwe_id AS cwe, w.name AS weakness, m.mit_id AS mit_id, m.name AS name,
       left(m.description, 300) AS description
"""


@dataclass
class VCKG:
    assets: dict                              # hostname -> asset dict
    internet_zones: set
    edges: set                                # E_R
    crit: dict                                # hostname -> crit(v)
    vulns: list                               # asset x CVE rows
    connects: list = field(default_factory=list)
    allowed: set = field(default_factory=set)  # (zone, zone) ALLOWED_TO_REACH
    zone: dict = field(default_factory=dict)   # hostname -> zone

    def internet_path(self, hostname: str) -> bool:
        return self.assets[hostname]["zone"] in self.internet_zones

    def propagation(self, hostname: str, gamma: float, mode: str = "compromise", k: int = config.BLAST_K) -> float:
        """P(a, c) of Eq. 16 for a vulnerability with impact mode `mode` on `hostname`."""
        return model.propagation(self.edges, hostname, self.crit, gamma, mode, k)

    def propagation_for(self, hostname: str, vector: str, gamma: float, k: int = config.BLAST_K) -> float:
        return self.propagation(hostname, gamma, model.impact_mode(vector), k)


def load(wait: int = 60) -> VCKG:
    with driver(wait) as drv, drv.session() as s:
        assets = {r["hostname"]: r for r in s.run(Q_ASSETS).data()}
        allowed = {(r["src"], r["dst"]) for r in s.run(Q_ALLOWED)}
        row = s.run(Q_INTERNET_ZONES, internet=config.INTERNET_ZONE).single()
        if not row["found"]:
            raise SystemExit(f"no Zone named {config.INTERNET_ZONE!r} (SCORE_INTERNET_ZONE): MAV needs the Internet zone")
        connects = [(r["src"], r["dst"]) for r in s.run(Q_CONNECTS)]
        vulns = s.run(Q_VULNS).data()
    zone = {h: a["zone"] for h, a in assets.items()}
    edges = model.reachability_edges(connects, zone, allowed)
    crit = {h: model.crit(a["cr"], a["ir"], a["ar"]) for h, a in assets.items()}
    return VCKG(assets, set(row["zones"]), edges, crit, vulns, connects, allowed, zone)


def cve_details(ids: list[str], wait: int = 60) -> tuple[dict, dict]:
    """CVE properties and their CWE mitigations, for CVEs reported by alerts."""
    if not ids:
        return {}, {}
    with driver(wait) as drv, drv.session() as s:
        cves = {r["cve"]: r for r in s.run(Q_CVE, ids=ids).data()}
        mitigations: dict[str, list] = {}
        for r in s.run(Q_CVE_MITIGATIONS, ids=ids):
            mitigations.setdefault(r["id"], []).append(
                {"cwe": r["cwe"], "weakness": r["weakness"], "id": r["mit_id"], "name": r["name"],
                 "description": r["description"]})
    return cves, mitigations
