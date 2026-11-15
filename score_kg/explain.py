"""Explain one input for a demo: attack paths, blast radius and EVS (docs/PLAN.md section 7).

    python -m score_kg explain --cve CVE-2024-23897 [--asset Jenkins]
    python -m score_kg explain --technique T1574.010 [--asset PostgreSQL]
    python -m score_kg explain --tactic TA0006 [--asset Web]
    python -m score_kg explain --clear

CVE        targets = --asset, or every asset whose software has the CVE
Technique  the technique family (itself, parent, sub-techniques) -> CAPEC -> specific CWE -> CVEs on lab
           software, as alert_kg does; targets = only the hosts that have such a CVE
Tactic     every technique that IMPLEMENTS it (and their sub-techniques), then as Technique

For each target: shortest attack paths from the Internet zone over CAN_REACH. For each (target, CVE):
EVS with every intermediate value (model.score), the terms of P(u) (Eq. 15) and the blast radius BR_k.

The result is printed and written to Neo4j as a separate result subgraph for the Browser:
    (:Analysis)-[:INPUT]->(Vulnerability | Technique | Tactic)
    (:Analysis)-[:TARGET {paths}]->(Asset)
    (:Analysis)-[:HAS_SCORE]->(:Score)-[:FOR_ASSET]->(Asset), -[:FOR_CVE]->(Vulnerability),
                                      -[:BLAST_RADIUS {hops}]->(Asset), -[:VIA_TECHNIQUE]->(Technique)
Nothing else reads these labels. `--clear` removes them all; a new run replaces the Analysis with the same id.
"""
from asset_kg.db import driver
from alert_kg.context import PATH_HOPS, SPECIFIC_CWE

from . import config, graph, model

# label and key of the input node, per kind (constants, safe to put into the query text)
INPUT_NODE = {"cve": ("Vulnerability", "cve_id"), "technique": ("Technique", "attack_id"),
              "tactic": ("Tactic", "attack_id")}

Q_INPUT = "MATCH (n:%s {%s: $id}) RETURN n.name AS name"
Q_TACTIC_TECHNIQUES = """
MATCH (ta:Tactic {attack_id: $id})
MATCH (t:Technique) WHERE (t)-[:IMPLEMENTS]->(ta) OR (t)-[:SUBTECHNIQUE_OF]->()-[:IMPLEMENTS]->(ta)
RETURN t.attack_id AS id ORDER BY id
"""
Q_CVE_TARGETS = """
MATCH (a:Asset)-[:RUNS]->(:Service)-[:IMPLEMENTED_BY]->(sw:Software)-[:HAS_VULNERABILITY]->(:Vulnerability {cve_id: $cve})
RETURN a.hostname AS asset, collect(DISTINCT sw.id) AS software ORDER BY asset
"""
# Same link rule as alert_kg/context.py Q_VULNS: technique family, specific CWEs only.
Q_TECHNIQUE_CVES = """
MATCH (t:Technique) WHERE t.attack_id IN $techniques
MATCH (a:Asset)-[:RUNS]->(:Service)-[:IMPLEMENTED_BY]->(sw:Software)-[:HAS_VULNERABILITY]->(v:Vulnerability)
      <-[:EXPLOITED_BY]-(w:Weakness)-[:CAUSES_WEAKNESS]->(ap:AttackPattern)-[:USES_TECHNIQUE]->(u:Technique)
WHERE w.abstraction IN $specific
  AND (u = t OR (t)-[:SUBTECHNIQUE_OF]->(u) OR (u)-[:SUBTECHNIQUE_OF]->(t))
  AND ($asset IS NULL OR a.hostname = $asset)
RETURN a.hostname AS asset, v.cve_id AS cve, collect(DISTINCT sw.id) AS software,
       collect(DISTINCT u.attack_id) AS techniques, collect(DISTINCT w.cwe_id) AS cwes,
       collect(DISTINCT ap.capec_id) AS capecs
ORDER BY asset, cve
"""
Q_ALERTED = """
UNWIND $pairs AS p
MATCH (al:Alert)-[:MENTIONS]->(:Vulnerability {cve_id: p.cve})
WHERE EXISTS { (al)-[:TARGETS]->(:Asset {hostname: p.asset}) }
RETURN DISTINCT p.asset AS asset, p.cve AS cve
"""
Q_PATHS = """
MATCH (start:Zone {name: $internet}), (a:Asset {hostname: $asset})
MATCH p = SHORTEST 3 (start) ((x)-[:CAN_REACH]->(:Service)<-[:RUNS]-(y)){1,%d} (a)
RETURN [n IN nodes(p) | coalesce(n.hostname, n.id, n.name)] AS hops
""" % PATH_HOPS

Q_DELETE = """
MATCH (an:Analysis {id: $id})
OPTIONAL MATCH (an)-[:HAS_SCORE]->(s:Score)
DETACH DELETE an, s
"""
Q_CLEAR = "MATCH (n) WHERE n:Analysis OR n:Score DETACH DELETE n"
Q_WRITE_ANALYSIS = """
CREATE (an:Analysis) SET an = $props, an.created = datetime()
WITH an
OPTIONAL MATCH (n:%s {%s: $input})
FOREACH (_ IN CASE WHEN n IS NULL THEN [] ELSE [1] END | CREATE (an)-[:INPUT]->(n))
WITH an
UNWIND $targets AS t
MATCH (a:Asset {hostname: t.asset})
CREATE (an)-[:TARGET {paths: t.paths, path_count: size(t.paths)}]->(a)
"""
Q_WRITE_SCORES = """
MATCH (an:Analysis {id: $id})
UNWIND $scores AS r
MATCH (a:Asset {hostname: r.props.asset}), (v:Vulnerability {cve_id: r.props.cve})
CREATE (an)-[:HAS_SCORE]->(s:Score)
SET s = r.props
CREATE (s)-[:FOR_ASSET]->(a), (s)-[:FOR_CVE]->(v)
WITH s, r
CALL (s, r) {
  UNWIND r.blast AS b
  MATCH (x:Asset {hostname: b.asset})
  CREATE (s)-[:BLAST_RADIUS {hops: b.hops}]->(x)
}
CALL (s, r) {
  UNWIND r.techniques AS tid
  MATCH (t:Technique {attack_id: tid})
  CREATE (s)-[:VIA_TECHNIQUE]->(t)
}
"""


# ------------------------------------------------------------------------------------------- pure parts
def p_terms(edges: set, asset: str, crit_of: dict, gamma: float) -> list[dict]:
    """The terms of Eq. 15 for one asset: each reachable v with crit(v) * gamma^d / (|V_A| - 1).

    They add up to model.propagation(edges, asset, crit_of, gamma).
    """
    others = len(crit_of) - 1
    if others <= 0:
        return []
    dist = model.distances(edges, asset)
    return [{"asset": v, "hops": d, "crit": crit_of[v], "term": crit_of[v] * gamma ** d / others}
            for v, d in sorted(dist.items(), key=lambda x: (x[1], x[0])) if v != asset]


def term_text(t: dict, gamma: float, n_others: int) -> str:
    return (f"{t['asset']}: crit {t['crit']:g} × {gamma:g}^{t['hops']} / {n_others} = {t['term']:.4f}")


def score_props(row: dict, analysis_id: str, software: list, techniques: list, cwes: list, capecs: list,
                present: bool, terms: list[dict], blast: dict, beta: float, gamma: float, k: int,
                n_others: int) -> dict:
    """Properties of one Score node (Neo4j accepts only primitives and lists of them)."""
    return {
        "name": f"{row['cve']} @ {row['asset']}: EVS {row['evs']} ({row['level']})",
        "analysis": analysis_id, "asset": row["asset"], "cve": row["cve"],
        "software": software, "present_on_asset": present,
        "techniques": techniques, "cwes": cwes, "capecs": capecs,
        "cvss_base": row["cvss_base"], "base_band": row["base_band"], "impact_mode": row["impact_mode"],
        "AV": row["AV"], "MAV": row["MAV"], "internet_path": row["internet_path"],
        "E": row["E"], "E_reason": row["E_reason"], "CR": row["CR"], "IR": row["IR"], "AR": row["AR"],
        "env_vector": row["env_vector"], "env": row["env"],
        "P": row["P"], "P_terms": [term_text(t, gamma, n_others) for t in terms],
        "evs": row["evs"], "level": row["level"],
        "evs_formula": f"min(10, {row['env']} × (1 + {beta:g} × {row['P']:.4f})) = {row['evs']}",
        "blast_radius": [f"{h} ({d} hop{'s' if d != 1 else ''})" for h, d in sorted(blast.items(), key=lambda x: (x[1], x[0]))],
        "beta": beta, "gamma": gamma, "k": k,
    }


# ------------------------------------------------------------------------------------------- graph parts
def _resolve_asset(g: graph.VCKG, name: str | None) -> str | None:
    if name is None:
        return None
    by_lower = {h.lower(): h for h in g.assets}
    if name.lower() not in by_lower:
        raise SystemExit(f"no Asset {name!r}; assets: {', '.join(sorted(g.assets))}")
    return by_lower[name.lower()]


def _findings(s, kind: str, ident: str, asset: str | None) -> tuple[list[str], list[dict]]:
    """(techniques the input expanded to, [{asset, cve, software, techniques, cwes, capecs, present}])."""
    if kind == "cve":
        on = {r["asset"]: r["software"] for r in s.run(Q_CVE_TARGETS, cve=ident)}
        if asset:
            return [], [{"asset": asset, "cve": ident, "software": on.get(asset, []), "techniques": [],
                         "cwes": [], "capecs": [], "present": asset in on}]
        return [], [{"asset": h, "cve": ident, "software": sw, "techniques": [], "cwes": [], "capecs": [],
                     "present": True} for h, sw in on.items()]
    techniques = ([ident] if kind == "technique"
                  else [r["id"] for r in s.run(Q_TACTIC_TECHNIQUES, id=ident)])
    rows = s.run(Q_TECHNIQUE_CVES, techniques=techniques, specific=SPECIFIC_CWE, asset=asset).data()
    for r in rows:
        r["present"] = True
    return techniques, rows


def explain(kind: str, ident: str, asset_name: str | None = None, beta: float = config.BETA,
            gamma: float = config.GAMMA, k: int = config.BLAST_K, wait: int = 60) -> dict:
    ident = ident.strip().upper()
    g = graph.load(wait)
    asset = _resolve_asset(g, asset_name)
    label, key = INPUT_NODE[kind]
    analysis_id = f"{ident}@{asset or 'all'}"
    n_others = len(g.assets) - 1

    with driver(wait) as drv, drv.session() as s:
        head = s.run(Q_INPUT % (label, key), id=ident).single()
        if head is None:
            raise SystemExit(f"no {label} {ident!r} in the graph")
        techniques, found = _findings(s, kind, ident, asset)
        alerted = {(r["asset"], r["cve"]) for r in s.run(
            Q_ALERTED, pairs=[{"asset": f["asset"], "cve": f["cve"]} for f in found])}
        targets = sorted({f["asset"] for f in found})
        paths = {t: [" > ".join(r["hops"]) for r in s.run(Q_PATHS, internet=config.INTERNET_ZONE, asset=t)]
                 for t in targets}
    cves, _ = graph.cve_details(sorted({f["cve"] for f in found}), wait)

    scores, skipped = [], []
    for f in found:
        vuln = cves.get(f["cve"])
        if not vuln or not vuln.get("cvss3_vector"):
            skipped.append(f"{f['cve']} on {f['asset']}: " + ("not in the CTI graph" if not vuln else "no CVSS v3.1 vector"))
            continue
        h = f["asset"]
        p = g.propagation(h, gamma)
        row = model.score(g.assets[h], vuln, g.internet_path(h), p, beta, alerted=(h, f["cve"]) in alerted)
        blast = model.blast_radius(g.edges, h, row["impact_mode"], k)
        terms = p_terms(g.edges, h, g.crit, gamma)
        props = score_props(row, analysis_id, f["software"], f["techniques"], f["cwes"], f["capecs"],
                            f["present"], terms, blast, beta, gamma, k, n_others)
        scores.append({"props": props, "terms": terms, "techniques": f["techniques"],
                       "blast": [{"asset": a, "hops": d} for a, d in blast.items()]})
    scores.sort(key=lambda r: (-r["props"]["evs"], r["props"]["asset"], r["props"]["cve"]))

    result = {"id": analysis_id, "kind": kind, "input": ident, "input_name": head["name"], "asset": asset,
              "techniques": techniques, "targets": [{"asset": t, "paths": paths[t]} for t in targets],
              "scores": scores, "skipped": skipped, "beta": beta, "gamma": gamma, "k": k, "n_others": n_others,
              "zones": {h: a["zone"] for h, a in g.assets.items()}}
    write(result, wait)
    print_result(result)
    return result


def write(result: dict, wait: int = 60) -> None:
    label, key = INPUT_NODE[result["kind"]]
    props = {"id": result["id"], "name": f"{result['kind']} {result['input']}" + (f" → {result['asset']}" if result["asset"] else ""),
             "kind": result["kind"], "input": result["input"], "asset": result["asset"] or "all",
             "techniques": result["techniques"], "targets": [t["asset"] for t in result["targets"]],
             "skipped": result["skipped"], "beta": result["beta"], "gamma": result["gamma"], "k": result["k"]}
    with driver(wait) as drv, drv.session() as s:
        s.run(Q_DELETE, id=result["id"]).consume()
        s.run(Q_WRITE_ANALYSIS % (label, key), props=props, input=result["input"],
              targets=result["targets"]).consume()
        s.run(Q_WRITE_SCORES, id=result["id"],
              scores=[{"props": r["props"], "blast": r["blast"], "techniques": r["techniques"]}
                      for r in result["scores"]]).consume()


def clear(wait: int = 60) -> None:
    with driver(wait) as drv, drv.session() as s:
        n = s.run(Q_CLEAR).consume().counters.nodes_deleted
    print(f"removed {n} Analysis/Score nodes")


# ------------------------------------------------------------------------------------------- printing
def print_result(r: dict) -> None:
    L = [f"== {r['kind']} {r['input']}" + (f" ({r['input_name']})" if r["input_name"] else "")
         + (f", target {r['asset']}" if r["asset"] else ""), ""]
    if r["kind"] == "tactic":
        linked = sorted({t for s in r["scores"] for t in s["techniques"]})
        shown = ", ".join(linked[:12]) + (f", ... (+{len(linked) - 12})" if len(linked) > 12 else "")
        L.append(f"1. Tactic -> {len(r['techniques'])} techniques (with sub-techniques) -> CAPEC -> CWE -> CVE; "
                 f"CAPEC maps to {len(linked)} of their families: {shown or 'none'}")
    elif r["kind"] == "technique":
        L.append("1. Technique family (itself, parent, sub-techniques) -> CAPEC -> CWE (Base/Variant/Compound) -> CVE")
    else:
        L.append("1. CVE -> assets whose software has it")
    if not r["targets"]:
        L += ["", "No lab host is linked to this input" + (f" ({r['asset']})" if r["asset"] else "") + "."]
        print("\n".join(L))
        return
    L += ["", f"2. Targets and attack paths from {config.INTERNET_ZONE} (CAN_REACH, ≤ {PATH_HOPS} hops):"]
    for t in r["targets"]:
        L.append(f"   {t['asset']} ({r['zones'][t['asset']]})")
        L += [f"     {p}" for p in t["paths"]] or [f"     no path from {config.INTERNET_ZONE}"]
    L += ["", f"3. Scores (β {r['beta']:g}, γ {r['gamma']:g}, k {r['k']}):"]
    for s in r["scores"]:
        p = s["props"]
        L += ["", f"   {p['name']}" + ("" if p["present_on_asset"] else "   [CVE not on this asset's software]"),
              f"     software      {', '.join(p['software']) or '-'}"
              + (f"; via {', '.join(p['techniques'])} / {', '.join(p['capecs'])} / {', '.join(p['cwes'])}" if p["techniques"] else ""),
              f"     CVSS base     {p['cvss_base']} ({p['base_band']}), impact mode {p['impact_mode']}",
              f"     MAV           {p['MAV']} (base AV {p['AV']}; Internet path to zone: {'yes' if p['internet_path'] else 'no'})",
              f"     E             {p['E']} ({p['E_reason']})",
              f"     Env           {p['env_vector']} -> {p['env']}",
              f"     P(u)          {p['P']:.4f} = sum of:"]
        L += [f"                     {t}" for t in p["P_terms"]] or ["                     (nothing reachable)"]
        L += [f"     EVS           {p['evs_formula']} -> {p['level']}",
              f"     blast radius  {', '.join(p['blast_radius'])}"]
    for sk in r["skipped"]:
        L.append(f"   not scored: {sk}")
    L += ["", f"Written to Neo4j as Analysis {{id: '{r['id']}'}} ({len(r['scores'])} Score nodes)."]
    print("\n".join(L))
