"""Stage 4 commands (paper §III.A.2-4): EVS per asset x CVE and per alerted vulnerability instance (a, c),
the structured assessment JSON, the threat report and the beta/gamma sensitivity analysis."""
import csv
import json
import re
from collections import Counter, defaultdict
from datetime import date
from itertools import product

from asset_kg.db import driver

from . import config, cvss31, graph, model, ssvc
from .cvss31 import band

BAND_ORDER = ["None", "Low", "Medium", "High", "Critical"]


# ------------------------------------------------------------------------------------------- baselines
def _epss():
    """EPSS is a baseline only (not in the EVS); scoring works without the file."""
    try:
        from . import epss
        return epss.load()
    except SystemExit:
        return {}, {}


def baselines(vuln: dict, asset: dict, epss_scores: dict) -> dict:
    mission = ssvc.mission_prevalence(asset["cr"], asset["ir"], asset["ar"])
    e = epss_scores.get(vuln["cve"])
    return {"epss": e[0] if e else None, "epss_percentile": e[1] if e else None, "kev": bool(vuln.get("kev")),
            "ssvc": ssvc.outcome(vuln.get("ssvc_exploitation"), vuln.get("ssvc_automatable"),
                                 vuln.get("ssvc_technical_impact"), bool(vuln.get("kev")),
                                 vuln["cvss3_vector"], mission)}


# ------------------------------------------------------------------------------------------- asset x CVE
def score_vulns(g: graph.VCKG, beta: float, gamma: float, epss_scores: dict | None = None) -> list[dict]:
    """EVS of every vulnerability present on every asset, with no alert (E = Not Defined)."""
    p = {h: g.propagation(h, gamma) for h in g.assets}
    rows = []
    for v in g.vulns:
        asset = g.assets[v["asset"]]
        row = model.score(asset, v, g.internet_path(v["asset"]), p[v["asset"]], beta, alerted=False)
        row.update(software=v["software"], source=v["via"])
        if epss_scores is not None:
            row.update(baselines(v, asset, epss_scores))
        rows.append(row)
    return rows


# ------------------------------------------------------------------------------------------- alerts
def alert_contexts() -> list[dict]:
    return [json.loads(f.read_text(encoding="utf-8")) for f in sorted(config.ALERT_CONTEXTS.glob("*.json"))]


NON_ATTACK_GROUPS = {"ossec"}  # Wazuh agent lifecycle/administration alerts, never an attack on a service


def vulnerability_instances(contexts: list[dict], technique_matches: bool = False) -> tuple[dict, dict]:
    """Group alerts into vulnerability instances (a, c) = (target asset, reported CVE).

    Returns ({(asset, cve, rule): [contexts]}, {(asset, rule): [contexts]} for alerts reporting no CVE).
    With technique_matches, an alert that names no CVE falls back to the CVEs alert_kg linked to it through its
    ATT&CK technique and the CWE/CAPEC chain (vulnerabilities.related_to_alert), except administrative alerts.
    That is an inference, not a report by the sensor, so only the evaluation uses it.
    """
    instances, unscored = defaultdict(list), defaultdict(list)
    for ctx in contexts:
        if not ctx.get("target"):
            continue
        asset, al = ctx["target"]["hostname"], ctx["alert"]
        cves = al.get("cves") or []
        if not cves and technique_matches and not NON_ATTACK_GROUPS & set(al.get("groups") or []):
            cves = [r["cve"] for r in (ctx.get("vulnerabilities") or {}).get("related_to_alert", [])]
        if cves:
            for cve in cves:
                instances[(asset, cve, al["rule_id"])].append(ctx)
        else:
            unscored[(asset, al["rule_id"])].append(ctx)
    return instances, unscored


def _times(ctxs):
    ts = sorted(c["alert"].get("timestamp") or "" for c in ctxs)
    return ts[0], ts[-1]


def score_alerts(g: graph.VCKG, beta: float, gamma: float, k: int, epss_scores: dict, wait: int = 60):
    instances, unscored = vulnerability_instances(alert_contexts())
    cves, mitigations = graph.cve_details(sorted({c for _, c, _ in instances}), wait)
    on_asset = {(v["asset"], v["cve"]) for v in g.vulns}
    scored, skipped = [], []
    for (asset_name, cve, rule), ctxs in instances.items():
        vuln = cves.get(cve)
        if not vuln or not vuln.get("cvss3_vector"):
            skipped.append({"asset": asset_name, "cve": cve, "rule_id": rule, "count": len(ctxs),
                            "why": "CVE not in the CTI graph" if not vuln else "CVE has no CVSS v3.1 vector"})
            continue
        asset = g.assets[asset_name]
        p = g.propagation(asset_name, gamma)
        row = model.score(asset, vuln, g.internet_path(asset_name), p, beta, alerted=True)
        br = model.blast_radius(g.edges, asset_name, row["impact_mode"], k)
        ctx, (first, last) = ctxs[0], _times(ctxs)
        al = ctx["alert"]
        techniques = ctx.get("techniques", [])
        row.update({
            "id": re.sub(r"[^A-Za-z0-9_.-]", "_", f"{asset_name}_{cve}_{rule}"),
            "rule_id": rule, "description": al["description"], "rule_level": al["rule_level"], "count": len(ctxs),
            "first_seen": first, "last_seen": last, "alert_ids": [c["alert"]["alert_id"] for c in ctxs],
            "source": ctx.get("source") or {}, "dstip": al.get("dstip"), "dstport": al.get("dstport"),
            "vulnerable_on_asset": (asset_name, cve) in on_asset,
            "blast_radius": [{"asset": h, "hops": d, "zone": g.assets[h]["zone"], "role": g.assets[h]["role"],
                              "CR": g.assets[h]["cr"], "IR": g.assets[h]["ir"], "AR": g.assets[h]["ar"],
                              "crit": g.crit[h]} for h, d in sorted(br.items(), key=lambda x: (x[1], x[0]))],
            "cve_description": vuln.get("description"),
            "mitigations": mitigations.get(cve, [])[:8],
            "technique_mitigations": [{"technique": t["id"], "name": t["name"], "mitigations": t["mitigations"][:5]}
                                      for t in techniques],
            "baselines": baselines(vuln, asset, epss_scores),
        })
        scored.append(row)
    scored.sort(key=lambda r: (-r["evs"], -r["cvss_base"], r["asset"]))
    unscored_rows = []
    for (asset_name, rule), ctxs in unscored.items():
        al, (first, last) = ctxs[0]["alert"], _times(ctxs)
        unscored_rows.append({"asset": asset_name, "rule_id": rule, "description": al["description"],
                              "rule_level": al["rule_level"], "count": len(ctxs), "first_seen": first,
                              "last_seen": last, "source": (ctxs[0].get("source") or {}).get("name") or "unknown",
                              "techniques": ", ".join(t["id"] for t in ctxs[0].get("techniques", []))})
    unscored_rows.sort(key=lambda r: (-r["rule_level"], r["asset"], r["rule_id"]))
    return scored, unscored_rows, skipped


def assessment(row: dict, g: graph.VCKG, beta: float, gamma: float, k: int) -> dict:
    """The structured JSON object of §III.A.4 (input for the LLM threat report)."""
    a = g.assets[row["asset"]]
    return {
        "alert": {"rule_id": row["rule_id"], "description": row["description"], "wazuh_level": row["rule_level"],
                  "count": row["count"], "first_seen": row["first_seen"], "last_seen": row["last_seen"],
                  "source": row["source"], "destination": {"ip": row["dstip"], "port": row["dstport"]},
                  "alert_ids": row["alert_ids"]},
        "affected_asset": {"hostname": a["hostname"], "ip": a["ip"], "role": a["role"], "zone": a["zone"],
                           "os": a["os"], "CR": a["cr"], "IR": a["ir"], "AR": a["ar"],
                           "justification": a.get("justification")},
        "vulnerability": {"cve": row["cve"], "description": row["cve_description"],
                          "cvss_v31_base_score": row["cvss_base"], "base_severity": row["base_band"],
                          "present_on_asset_per_graph": row["vulnerable_on_asset"]},
        "assessment": {"impact_mode": row["impact_mode"], "E": row["E"], "MAV": row["MAV"],
                       "internet_path_to_zone": row["internet_path"], "environmental_vector": row["env_vector"],
                       "environmental_score": row["env"], "propagation_P": row["P"], "beta": beta, "gamma": gamma,
                       "evs": row["evs"], "risk_level": row["level"]},
        "affected_assets": {"k": k, "assets": row["blast_radius"]},
        "mitigations": {"cwe": row["mitigations"], "attack": row["technique_mitigations"]},
        "baselines_not_in_evs": row["baselines"],
    }


Q_SET_ALERT = """
UNWIND $rows AS r
MATCH (al:Alert {alert_id: r.alert_id})
SET al.evs = r.evs, al.evs_level = r.level, al.evs_cve = r.cve, al.blast_radius = r.blast_radius
REMOVE al.event_score, al.event_band, al.event_basis, al.host_risk, al.host_band, al.host_top_cve,
       al.ssvc, al.risk_score, al.risk_band, al.top_cve
"""


# ------------------------------------------------------------------------------------------- outputs
VULN_FIELDS = ["asset", "software", "source", "cve", "cvss_base", "base_band", "impact_mode", "AV", "MAV",
               "internet_path", "E", "E_reason", "CR", "IR", "AR", "env_vector", "env", "P", "evs", "level",
               "epss", "epss_percentile", "kev", "ssvc"]
ALERT_FIELDS = ["id", "asset", "cve", "rule_id", "description", "rule_level", "count", "first_seen", "last_seen",
                "vulnerable_on_asset", "cvss_base", "impact_mode", "MAV", "E", "E_reason", "env", "P", "evs", "level",
                "blast_radius_assets"]


def write_csv(path, rows, fields) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)


def run_vulns(beta=config.BETA, gamma=config.GAMMA, wait=60):
    g = graph.load(wait)
    meta, epss_scores = _epss()
    rows = score_vulns(g, beta, gamma, epss_scores)
    write_csv(config.ASSET_CVE_CSV, rows, VULN_FIELDS)
    shift = Counter((r["base_band"], r["level"]) for r in rows)
    up = sum(n for (b, a), n in shift.items() if BAND_ORDER.index(a) > BAND_ORDER.index(b))
    down = sum(n for (b, a), n in shift.items() if BAND_ORDER.index(a) < BAND_ORDER.index(b))
    print(f"EVS of {len(rows)} asset x CVE pairs (no alert, E = X): {up} above their CVSS band, {down} below, "
          f"{len(rows) - up - down} same -> {config.ASSET_CVE_CSV}")
    return g, meta, epss_scores, rows


def run_alerts(beta=config.BETA, gamma=config.GAMMA, k=config.BLAST_K, wait=60, data=None):
    g, meta, epss_scores, _ = data or run_vulns(beta, gamma, wait)
    scored, unscored, skipped = score_alerts(g, beta, gamma, k, epss_scores, wait)
    for r in scored:
        r["blast_radius_assets"] = " ".join(f"{b['asset']}({b['hops']})" for b in r["blast_radius"])
    write_csv(config.ALERT_CSV, scored, ALERT_FIELDS)
    config.ASSESSMENTS.mkdir(parents=True, exist_ok=True)
    for old in config.ASSESSMENTS.glob("*.json"):
        old.unlink()
    for r in scored:
        (config.ASSESSMENTS / f"{r['id']}.json").write_text(
            json.dumps(assessment(r, g, beta, gamma, k), indent=2, default=str), encoding="utf-8")
    rows = [{"alert_id": aid, "evs": r["evs"], "level": r["level"], "cve": r["cve"],
             "blast_radius": [b["asset"] for b in r["blast_radius"]]} for r in scored for aid in r["alert_ids"]]
    with driver(wait) as drv, drv.session() as s:
        s.run(Q_SET_ALERT, rows=rows).consume()
    print(f"{len(scored)} vulnerability instances (a, c) from alerts scored -> {config.ALERT_CSV}, "
          f"{config.ASSESSMENTS}; {sum(u['count'] for u in unscored)} alerts report no CVE (not scored)"
          + (f"; {len(skipped)} instances skipped (CVE unknown or without CVSS v3.1)" if skipped else ""))
    return scored, unscored, skipped


def _src(source: dict) -> str:
    if not source:
        return "unknown"
    return " ".join(str(x) for x in (source.get("kind"), source.get("name"), source.get("ip")) if x)


def write_report(g, meta, vuln_rows, scored, unscored, skipped, beta, gamma, k) -> None:
    osv_date = config.ROOT / "data" / "raw" / "osv" / "downloaded_at.txt"
    L = ["# Threat report: Environmental Vulnerability Score (EVS)", "",
         f"Generated {date.today().isoformat()} by `python -m score_kg report`. Method: `docs/scoring.md` "
         "(paper §III.A.2–3).", "",
         "| Parameter / input | Value |", "|---|---|",
         f"| β (propagation uplift bound), γ (distance discount), k (blast-radius depth) | {beta:g}, {gamma:g}, {k} |",
         f"| Zones reachable from the Internet ({config.INTERNET_ZONE}) | {', '.join(sorted(g.internet_zones)) or 'none'} |",
         "| CTI graph | CVEs published 2024 and later |",
         f"| Distro security data (OSV) | downloaded {osv_date.read_text().strip()[:10] if osv_date.exists() else '?'} |",
         f"| EPSS (baseline only, not in the EVS) | model {meta.get('model_version', '-')}, {meta.get('score_date', '-')[:10]} |",
         "",
         "`EVS(c,u) = min(10, Env(c,u) · (1 + β·P(u)))`. Env is the CVSS v3.1 Environmental score with CR/IR/AR of the "
         "asset, MAV from Internet reachability of its zone, and E = H for the alerted CVE or from KEV/SSVC exploitation otherwise. P(u) is the "
         "discounted criticality of the assets reachable from u.", ""]

    # ---- 1. alerted vulnerability instances
    L += ["## 1. Alerted vulnerabilities, by EVS", "",
          "One row per vulnerability instance (a, c): an alert that reports CVE c on asset a.", "",
          "| # | EVS (level) | CVSS base (band) | Env | P(u) | CVE | Asset (zone) | On asset per graph | Blast radius (k=%d) | Event | Count |" % k,
          "|---:|---|---|---:|---:|---|---|---|---|---|---:|"]
    for i, r in enumerate(scored, 1):
        L.append(f"| {i} | **{r['evs']}** ({r['level']}) | {r['cvss_base']} ({r['base_band']}) | {r['env']} | {r['P']:.3f} | "
                 f"{r['cve']} | {r['asset']} ({g.assets[r['asset']]['zone']}) | {'yes' if r['vulnerable_on_asset'] else 'no'} | "
                 f"{', '.join(b['asset'] for b in r['blast_radius'])} | {r['description']} (rule {r['rule_id']}) | {r['count']} |")
    if not scored:
        L.append("| | no alert reports a CVE yet | | | | | | | | | |")
    for s in skipped:
        L.append(f"\nNot scored: {s['cve']} on {s['asset']} (rule {s['rule_id']}, {s['count']}×): {s['why']}.")

    L += ["", "## 2. Details", ""]
    for i, r in enumerate(scored, 1):
        a = g.assets[r["asset"]]
        L += [f"### {i}. {r['cve']} on {r['asset']}: EVS {r['evs']} ({r['level']})", "",
              f"- **Event:** {r['description']} (rule {r['rule_id']}, Wazuh level {r['rule_level']}), {r['count']}× "
              f"from {r['first_seen'][:19]} to {r['last_seen'][:19]}. Source: {_src(r['source'])}; destination "
              f"{r['dstip'] or '-'}:{r['dstport'] or '-'}.",
              f"- **Asset:** {a['hostname']} ({a['role']}, {a['ip']}, zone {a['zone']}), CR/IR/AR {a['cr']}/{a['ir']}/{a['ar']}"
              + (f" — {a['justification']}" if a.get("justification") else "") + ".",
              f"- **Vulnerability:** {r['cve']}, CVSS v3.1 base {r['cvss_base']} ({r['base_band']}). "
              f"{'Present on the asset according to the graph.' if r['vulnerable_on_asset'] else 'Not linked to the asset’s software in the graph (the alert may be an attempt against software the host does not run).'}",
              f"- **Environmental metrics (Table I):** E = {r['E']} ({r['E_reason']}); "
              f"MAV = {r['MAV']} (base AV {r['AV']}; zone {a['zone']} {'is' if r['internet_path'] else 'is not'} reachable from the Internet); "
              f"CR/IR/AR = {r['CR']}/{r['IR']}/{r['AR']}. Vector `{r['env_vector']}` → **Env {r['env']}**.",
              f"- **Propagation:** P({r['asset']}) = {r['P']:.4f} → EVS = min(10, {r['env']} × (1 + {beta:g} × {r['P']:.4f})) = **{r['evs']}**.",
              f"- **Blast radius BR_{k}** (impact mode *{r['impact_mode']}*: "
              f"{'assets it can reach' if r['impact_mode'] == 'compromise' else 'assets that depend on it'}):", "",
              "| Asset | Hops | Zone | Role | CR/IR/AR | crit |", "|---|---:|---|---|---|---:|"]
        for b in r["blast_radius"]:
            L.append(f"| {b['asset']} | {b['hops']} | {b['zone']} | {b['role']} | {b['CR']}/{b['IR']}/{b['AR']} | {b['crit']:g} |")
        L.append("")
        if r["mitigations"]:
            L.append("- **Mitigations (CWE):** " + "; ".join(
                f"{m['name']} ({m['cwe']})" for m in r["mitigations"][:5]) + ".")
        for t in r["technique_mitigations"]:
            if t["mitigations"]:
                L.append(f"- **Mitigations ({t['technique']} {t['name']}):** " + ", ".join(m["name"] for m in t["mitigations"]) + ".")
        b = r["baselines"]
        L += [f"- Baselines (not in the EVS): EPSS {b['epss'] if b['epss'] is not None else '-'}, "
              f"KEV {'yes' if b['kev'] else 'no'}, CISA SSVC {b['ssvc']}.", ""]

    # ---- 3. unscored alerts
    L += ["## 3. Alerts that report no CVE (not scored by the method)", "",
          "The EVS is defined for a vulnerability instance (a, c). These alerts name no CVE; they are listed with their context.", "",
          "| Wazuh level | Event | Asset | Source | Techniques | Count | Last seen |", "|---:|---|---|---|---|---:|---|"]
    for u in unscored:
        L.append(f"| {u['rule_level']} | {u['description']} (rule {u['rule_id']}) | {u['asset']} | {u['source']} | "
                 f"{u['techniques'] or '-'} | {u['count']} | {u['last_seen'][:19]} |")

    # ---- 4. assets
    by_asset = defaultdict(list)
    for r in vuln_rows:
        by_asset[r["asset"]].append(r)
    L += ["", "## 4. Assets (vulnerabilities present, no alert: E = X)", "",
          "| Asset | Zone | CR/IR/AR | Internet path | P(u) | CVEs | Highest CVSS base | Highest EVS |",
          "|---|---|---|---|---:|---:|---:|---:|"]
    for h, a in sorted(g.assets.items(), key=lambda x: -max((r["evs"] for r in by_asset[x[0]]), default=0)):
        rows = by_asset[h]
        p = rows[0]["P"] if rows else g.propagation(h, gamma)
        L.append(f"| {h} | {a['zone']} | {a['cr']}/{a['ir']}/{a['ar']} | {'yes' if h and g.internet_path(h) else 'no'} | "
                 f"{p:.3f} | {len(rows)} | {max((r['cvss_base'] for r in rows), default='-')} | "
                 f"{max((r['evs'] for r in rows), default='-')} |")
    L += ["", "### Top 20 by EVS", "", "| Asset | CVE | Source | CVSS base (band) | Env | EVS (level) | Change |",
          "|---|---|---|---|---:|---|---|"]
    for r in sorted(vuln_rows, key=lambda r: (-r["evs"], -r["cvss_base"]))[:20]:
        ch = BAND_ORDER.index(r["level"]) - BAND_ORDER.index(r["base_band"])
        L.append(f"| {r['asset']} | {r['cve']} | {r['source']} | {r['cvss_base']} ({r['base_band']}) | {r['env']} | "
                 f"{r['evs']} ({r['level']}) | {'↑' * ch or '↓' * -ch or '='} |")

    shift = Counter((r["base_band"], r["level"]) for r in vuln_rows)
    present = [b for b in BAND_ORDER if any(b in key for key in shift)]
    L += ["", "## 5. CVSS base band → EVS level (asset × CVE, no alert)", "",
          "| CVSS \\ EVS | " + " | ".join(present) + " |", "|---|" + "---:|" * len(present)]
    for b in present:
        L.append(f"| {b} | " + " | ".join(str(shift.get((b, x), "")) for x in present) + " |")
    L += ["", "Data: `data/scores/asset_cve_scores.csv`, `data/scores/alert_scores.csv`, structured JSON per instance in "
              "`data/reports/assessments/`.", ""]
    config.REPORTS.mkdir(parents=True, exist_ok=True)
    config.THREAT_REPORT.write_text("\n".join(L), encoding="utf-8")
    print(f"threat report -> {config.THREAT_REPORT}")


def run_report(beta=config.BETA, gamma=config.GAMMA, k=config.BLAST_K, wait=60):
    data = run_vulns(beta, gamma, wait)
    scored, unscored, skipped = run_alerts(beta, gamma, k, wait, data)
    g, meta, _, rows = data
    write_report(g, meta, rows, scored, unscored, skipped, beta, gamma, k)


# ------------------------------------------------------------------------------------------- sensitivity
def kendall_tau(a: list[float], b: list[float]) -> float:
    """Kendall tau-b between two score lists over the same items (ties handled)."""
    conc = disc = ties_a = ties_b = 0
    n = len(a)
    for i in range(n):
        for j in range(i + 1, n):
            da, db = a[i] - a[j], b[i] - b[j]
            if da == 0 and db == 0:
                continue
            if da == 0:
                ties_a += 1
            elif db == 0:
                ties_b += 1
            elif (da > 0) == (db > 0):
                conc += 1
            else:
                disc += 1
    denom = ((conc + disc + ties_a) * (conc + disc + ties_b)) ** 0.5
    return (conc - disc) / denom if denom else 1.0


def run_sensitivity(wait=60):
    g = graph.load(wait)
    ref = score_vulns(g, config.BETA, config.GAMMA)
    ref_evs = [r["evs"] for r in ref]
    top = lambda rows: {(r["asset"], r["cve"]) for r in sorted(rows, key=lambda r: (-r["evs"], r["cve"]))[:10]}
    ref_top = top(ref)
    lines = []
    for beta, gamma in product([0, 0.25, 0.5, 0.75, 1.0], [0.25, 0.5, 0.75]):
        rows = score_vulns(g, beta, gamma)
        shifted = sum(r["level"] != q["level"] for r, q in zip(rows, ref))
        lines.append((beta, gamma, kendall_tau(ref_evs, [r["evs"] for r in rows]), len(top(rows) & ref_top), shifted))
    taus = [x[2] for x in lines]
    L = ["# Sensitivity of the EVS to β and γ", "",
         f"Generated {date.today().isoformat()} by `python -m score_kg sensitivity`. Reference: β = {config.BETA:g}, "
         f"γ = {config.GAMMA:g}. {len(ref)} asset × CVE pairs, no alert (E = X).", "",
         f"Kendall τ-b against the reference: min {min(taus):.3f}, max {max(taus):.3f}.", "",
         "| β | γ | Kendall τ | Same top-10 | Pairs whose level changes |", "|---:|---:|---:|---:|---:|"]
    for beta, gamma, tau, t10, shifted in lines:
        L.append(f"| {beta:g} | {gamma:g} | {tau:.3f} | {t10}/10 | {shifted} |")
    config.REPORTS.mkdir(parents=True, exist_ok=True)
    config.SENSITIVITY_REPORT.write_text("\n".join(L) + "\n", encoding="utf-8")
    config.SENSITIVITY_REPORT.with_suffix(".json").write_text(json.dumps({
        "generated": date.today().isoformat(), "ref_beta": config.BETA, "ref_gamma": config.GAMMA, "n_pairs": len(ref),
        "grid": [{"beta": b, "gamma": gm, "tau": t, "top10_overlap": t10, "level_changes": sh}
                 for b, gm, t, t10, sh in lines]}, indent=1), encoding="utf-8")
    print(f"sensitivity: {len(lines)} (beta, gamma) settings, Kendall tau min {min(taus):.3f} -> {config.SENSITIVITY_REPORT}")
