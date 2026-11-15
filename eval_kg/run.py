"""Stage 5 reports: score ladder (Part A) and blast-radius variants (Part B) against lab ground truth."""
import csv
import json
import time
from datetime import date
from pathlib import Path

from asset_kg.db import driver
from score_kg import config as score_config
from score_kg import graph as vckg_graph
from score_kg import model
from score_kg.run import _epss, _times, alert_contexts, vulnerability_instances

from . import config, labels, ladder, metrics, variants


def _f(x, nd=3):
    return "-" if x is None else f"{x:.{nd}f}"


def _ci(b: dict) -> str:
    if b["diff"] is None:
        return "-"
    if b["lo"] is None:
        return f"{b['diff']:+.3f}"
    flag = " *" if b["lo"] > 0 or b["hi"] < 0 else ""
    return f"{b['diff']:+.3f} [{b['lo']:+.3f}, {b['hi']:+.3f}]{flag}"


def _mean(xs):
    xs = [x for x in xs if x is not None]
    return sum(xs) / len(xs) if xs else None


# =========================================================================================== Part A
def asset_cve_items(g, epss, beta, gamma, p_of=None) -> list[dict]:
    """Every vulnerability present on an asset, no alert: E from KEV/SSVC (Eq. 14)."""
    p_of = p_of or {h: g.propagation(h, gamma) for h in g.assets}
    out = []
    for v in g.vulns:
        asset = g.assets[v["asset"]]
        item = {**v, "alerted": False, "id": f"{v['asset']}|{v['cve']}"}
        item.update(ladder.levels(item, asset, g.internet_path(v["asset"]), p_of[v["asset"]], beta))
        item.update(ladder.baselines(item, asset, epss))
        out.append(item)
    return out


def alert_items(g, epss, beta, gamma, wait=60) -> list[dict]:
    """Vulnerability instances (a, c) reported by alerts, E = H (Eq. 14), with their alert time span."""
    instances, _ = vulnerability_instances(alert_contexts(), technique_matches=True)
    cves, _ = vckg_graph.cve_details(sorted({c for _, c, _ in instances}), wait)
    out = []
    for (asset_name, cve, rule), ctxs in instances.items():
        vuln = cves.get(cve)
        if not vuln or not vuln.get("cvss3_vector") or asset_name not in g.assets:
            continue
        asset = g.assets[asset_name]
        first, last = _times(ctxs)
        item = {**vuln, "asset": asset_name, "cve": cve, "rule_id": rule, "alerted": True,
                "rule_level": ctxs[0]["alert"]["rule_level"], "first_seen": first, "last_seen": last,
                "id": f"{asset_name}|{cve}|{rule}"}
        item.update(ladder.levels(item, asset, g.internet_path(asset_name), g.propagation(asset_name, gamma), beta))
        item.update(ladder.baselines(item, asset, epss))
        out.append(item)
    return out


def ranking_metrics(items: list[dict], key: str, rel_threshold: int, chain_threshold: int) -> dict:
    rels = metrics.ranked(items, key)
    return {"NDCG@5": metrics.ndcg_at_k(rels, 5), "NDCG@10": metrics.ndcg_at_k(rels, 10),
            "P@5": metrics.precision_at_k(rels, 5, rel_threshold), "P@10": metrics.precision_at_k(rels, 10, rel_threshold),
            "first": metrics.first_hit(rels, chain_threshold), "MRR": metrics.reciprocal_rank(rels, rel_threshold)}


def _ndcg10(key):
    return lambda sample: metrics.ndcg_at_k(metrics.ranked(sample, key), 10)


def _mean_query_ndcg10(key):
    return lambda queries: _mean([metrics.ndcg_at_k(metrics.ranked(q, key), 10) for q in queries])


def score_ablation(labels_dir: Path, beta=score_config.BETA, gamma=score_config.GAMMA, wait=60) -> None:
    labels_dir = Path(labels_dir)
    g = vckg_graph.load(wait)
    epss_meta, epss = _epss()
    keys = ladder.LEVELS + ladder.BASELINES
    synthetic = labels_dir.resolve() == config.DRY_RUN.resolve()

    # ---- A1: asset x CVE ranking against exploited (pentest_results.csv)
    truth = labels.load_pentest_results(labels_dir / "pentest_results.csv")
    a_items = [dict(i, grade=truth[(i["asset"], i["cve"])]) for i in asset_cve_items(g, epss, beta, gamma)
               if (i["asset"], i["cve"]) in truth]
    # ---- A2: alert instances ranked inside each pentest scenario
    scenarios = labels.load_scenarios(labels_dir / "scenarios")
    synthetic = synthetic or any(s["synthetic"] for s in scenarios)
    all_alerts = alert_items(g, epss, beta, gamma, wait) if scenarios else []
    queries = []
    for s in scenarios:
        q = [dict(i, grade=labels.label_instance(i, s, config.MATCH_SLACK_SECONDS), scenario=s["id"])
             for i in all_alerts if labels.in_window(i, s, config.MATCH_SLACK_SECONDS)]
        if q:
            queries.append(q)

    L = ["# Evaluation, Part A: score ablation (L0 → L4) against pentest ground truth", ""]
    if synthetic:
        L += [f"> **SYNTHETIC DRY RUN.** The labels in `{labels_dir.as_posix()}` are made up to test the pipeline. "
              "These numbers are not results and must not be reported.", ""]
    L += [f"Generated {date.today().isoformat()} by `python -m eval_kg score-ablation`. Protocol: `docs/evaluation.md`. "
          f"β = {beta:g}, γ = {gamma:g}. EPSS {epss_meta.get('model_version', '-')}. Ties are broken by item id.", "",
          "Ladder: L0 CVSS base · L1 + CR/IR/AR · L2 + MAV (Internet reachability) · L3 + E (alert/KEV/SSVC) · "
          "L4 + P(u) = EVS. Baselines (not our score): EPSS percentile, KEV, CISA SSVC, Wazuh rule.level.", ""]

    def table(items_or_queries, per_query, rel_t, chain_t):
        rows = []
        for k in keys:
            if per_query:
                ms = [ranking_metrics(q, k, rel_t, chain_t) for q in items_or_queries if q[0].get(k) is not None]
                if not ms:
                    continue
                m = {x: _mean([r[x] for r in ms]) for x in ("NDCG@5", "NDCG@10", "P@5", "P@10", "MRR")}
                m["first"] = _mean([r["first"] for r in ms])
            else:
                if any(i.get(k) is None for i in items_or_queries):
                    continue
                m = ranking_metrics(items_or_queries, k, rel_t, chain_t)
            rows.append((k, m))
        return rows

    def gains(units, per_query):
        fn = _mean_query_ndcg10 if per_query else _ndcg10
        out = []
        for a, b in zip(ladder.LEVELS[1:], ladder.LEVELS[:-1]):
            out.append((f"{a} − {b}", metrics.paired_bootstrap(units, fn(a), fn(b), config.BOOTSTRAP, config.SEED)))
        for base in ladder.BASELINES:
            if per_query and any(q[0].get(base) is None for q in units):
                continue
            if not per_query and any(i.get(base) is None for i in units):
                continue
            out.append((f"L4 − {base}", metrics.paired_bootstrap(units, fn("L4"), fn(base), config.BOOTSTRAP, config.SEED)))
        return out

    payload = {"generated": date.today().isoformat(), "beta": beta, "gamma": gamma, "synthetic": synthetic, "sets": {}}

    def emit(title, rows, gain_rows, note, set_key=None):
        nonlocal L
        if set_key:
            payload["sets"][set_key] = {"title": title, "note": note,
                                        "scores": {k: m for k, m in rows},
                                        "gains": {name: b for name, b in gain_rows}}
        L += [f"## {title}", "", note, "",
              "| Score | NDCG@5 | NDCG@10 | P@5 | P@10 | MRR | Rank of first true item |",
              "|---|---:|---:|---:|---:|---:|---:|"]
        for k, m in rows:
            L.append(f"| {k} | {_f(m['NDCG@5'])} | {_f(m['NDCG@10'])} | {_f(m['P@5'])} | {_f(m['P@10'])} | "
                     f"{_f(m['MRR'])} | {_f(m['first'], 1) if m['first'] is not None else '-'} |")
        L += ["", "Gain in NDCG@10 with a 95% paired-bootstrap CI (* = CI excludes 0):", "",
              "| Comparison | Δ NDCG@10 [95% CI] |", "|---|---|"]
        L += [f"| {name} | {_ci(b)} |" for name, b in gain_rows]
        L.append("")

    if a_items:
        n_pos = sum(i["grade"] for i in a_items)
        emit("A1. Vulnerabilities on assets (asset × CVE, no alert)", table(a_items, False, 1, 1),
             gains(a_items, False),
             f"{len(a_items)} labelled pairs from `pentest_results.csv` ({n_pos} exploited); `not_tried` pairs are "
             "left out. Relevance = exploited (1/0). Bootstrap resamples pairs.", set_key="A1")
        payload["sets"]["A1"].update(n_items=len(a_items), n_positive=n_pos)
    else:
        L += ["## A1. Vulnerabilities on assets", "", "No labelled pairs yet (`pentest_results.csv` empty or missing).", ""]
    if queries:
        by_items = len(queries) < 5
        units = [i for q in queries for i in q] if by_items else queries
        emit("A2. Alerted vulnerability instances, per pentest scenario", table(queries, True, 2, 3),
             gains(units, not by_items),
             f"{len(queries)} scenarios, {sum(len(q) for q in queries)} instances in their time windows. Grades 3/2/1/0 "
             f"from the pentest record. Metrics averaged over scenarios; bootstrap over "
             f"{'instances (fewer than 5 scenarios)' if by_items else 'scenarios'}.", set_key="A2")
        payload["sets"]["A2"].update(n_scenarios=len(queries), n_instances=sum(len(q) for q in queries),
                                     scenarios=[{"id": q[0]["scenario"], "n": len(q),
                                                 "grades": sorted(i["grade"] for i in q)} for q in queries])
    else:
        L += ["## A2. Alerted instances", "", "No pentest scenario with alert instances in its window yet.", ""]

    config.REPORTS.mkdir(parents=True, exist_ok=True)
    config.SCORE_REPORT.write_text("\n".join(L), encoding="utf-8")
    config.SCORE_REPORT.with_suffix(".json").write_text(json.dumps(payload, indent=1), encoding="utf-8")
    with open(config.SCORE_REPORT.with_suffix(".csv"), "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["set", "item", "grade", *keys])
        for i in a_items:
            w.writerow(["asset_cve", i["id"], i["grade"], *[i.get(k) for k in keys]])
        for q in queries:
            for i in q:
                w.writerow([f"scenario:{i['scenario']}", i["id"], i["grade"], *[i.get(k) for k in keys]])
    print(f"score ablation: {len(a_items)} asset x CVE pairs, {len(queries)} scenarios -> {config.SCORE_REPORT}")


# =================================================================================== Part A, sensitivity
def _kendall_tau_b(xs: list[float], ys: list[float]) -> dict:
    """Concordant / discordant / tie counts and Kendall's tau-b between two score orderings of the same
    items. O(n^2), fine for a few hundred pairs; no SciPy so no new dependency."""
    n = len(xs)
    c = d = tx = ty = 0
    for i in range(n):
        for j in range(i + 1, n):
            a, b = xs[i] - xs[j], ys[i] - ys[j]
            if a == 0 and b == 0:
                continue
            if a == 0:
                tx += 1
            elif b == 0:
                ty += 1
            elif a * b > 0:
                c += 1
            else:
                d += 1
    denom = ((c + d + tx) * (c + d + ty)) ** 0.5
    tau = (c - d) / denom if denom else None
    return {"concordant": c, "discordant": d, "tied_L0_only": tx, "tied_EVS_only": ty, "tau_b": tau,
            "total_pairs": n * (n - 1) // 2}


def sensitivity(wait: int = 60, beta=score_config.BETA, gamma=score_config.GAMMA) -> None:
    """How the EVS (L4) reprioritises the CVSS base (L0) ranking across the whole asset x CVE inventory.

    This is a sensitivity analysis of the scoring mechanism, not a ground-truth validation: there is no
    outcome label here. It quantifies how much the context terms (CR/IR/AR, MAV, blast radius) reorder a
    pure-CVSS ranking, and checks the reordering tracks asset value and reachability (the design intent).
    The validated contextual claim is Part B (blast radius vs lab-measured impact)."""
    g = vckg_graph.load(wait)
    _, epss = _epss()
    items = []
    for it in asset_cve_items(g, epss, beta, gamma):
        a = g.assets[it["asset"]]
        tier = max(a["cr"], a["ir"], a["ar"], key=lambda x: {"L": 0, "M": 1, "H": 2}[x])
        items.append({"asset": it["asset"], "cve": it["cve"], "L0": it["L0"], "L4": it["L4"],
                      "delta": it["L4"] - it["L0"], "cr": a["cr"], "ir": a["ir"], "ar": a["ar"],
                      "tier": tier, "internet": g.internet_path(it["asset"])})

    tb = _kendall_tau_b([i["L0"] for i in items], [i["L4"] for i in items])
    # "material" cross-asset reorderings: a clear base-CVSS gap (>=0.5) that the EVS flips
    material = sum(1 for i in range(len(items)) for j in range(i + 1, len(items))
                   if items[i]["asset"] != items[j]["asset"]
                   and abs(items[i]["L0"] - items[j]["L0"]) >= 0.5
                   and (items[i]["L0"] - items[j]["L0"]) * (items[i]["L4"] - items[j]["L4"]) < 0)

    def summ(xs):
        xs = sorted(xs)
        if not xs:
            return None, None, 0
        mean = sum(xs) / len(xs)
        mid = xs[len(xs) // 2] if len(xs) % 2 else (xs[len(xs) // 2 - 1] + xs[len(xs) // 2]) / 2
        return mean, mid, len(xs)

    per_asset = []
    for h in g.assets:
        a = g.assets[h]
        mean, mid, n = summ([i["delta"] for i in items if i["asset"] == h])
        if n:
            per_asset.append((h, a["cr"], a["ir"], a["ar"], g.internet_path(h), mean, mid, n))
    per_asset.sort(key=lambda r: r[5])  # most-suppressed first

    L = ["# Evaluation, Part A (sensitivity): how the EVS reprioritises CVSS", "",
         f"Generated {date.today().isoformat()} by `python -m eval_kg sensitivity`. β = {beta:g}, γ = {gamma:g}.", "",
         "> **This is a sensitivity analysis of the scoring mechanism, not a ground-truth validation.** It measures "
         "how far the EVS (L4) reorders a pure CVSS-base (L0) ranking across the whole asset × CVE inventory, with "
         "no alert and no exploit outcome, and checks the reordering follows asset value and reachability — i.e. the "
         "context terms do what the design claims. It does **not** show the reordering is *correct*: there is no "
         "outcome label here. The validated contextual claim is Part B (blast radius vs lab-measured impact); the "
         "ground-truth ranking tests are Parts A1/A2. Reason this matters: the lab's only alertable CVEs and its "
         "only repeatable exploit are all CVSS 9.8 (ceiling), so an A2 EVS-beats-CVSS result is not reachable here.", "",
         f"**Inventory:** {len(items)} asset × CVE pairs across {len({i['asset'] for i in items})} assets.", "",
         "## Reordering magnitude (L0 CVSS base vs L4 EVS)", "",
         f"- Kendall's tau-b: **{_f(tb['tau_b'])}** (1 = identical order, 0 = unrelated). The EVS keeps the broad "
         "CVSS order but reorders within it.",
         f"- Pairs: {tb['concordant']} concordant, **{tb['discordant']} discordant**, "
         f"{tb['tied_L0_only']} tied on CVSS only, {tb['tied_EVS_only']} tied on EVS only, of {tb['total_pairs']} total.",
         f"- Material cross-asset reorderings (a CVSS gap ≥ 0.5 that the EVS flips): **{material}**.", "",
         "## Direction check (mean / median of L4 − L0, per asset)", "",
         "If the reordering tracks context, the EVS should lift CVEs on valuable, reachable hosts and lower them on "
         "throwaway, contained ones. Assets below are ordered most-suppressed first.", "",
         "| asset | CR/IR/AR | internet-reachable | mean ΔEVS | median ΔEVS | n CVEs |",
         "|---|:--:|:--:|--:|--:|--:|"]
    for h, cr, ir, ar, net, mean, mid, n in per_asset:
        L.append(f"| {h} | {cr}/{ir}/{ar} | {'yes' if net else 'no'} | {mean:+.2f} | {mid:+.2f} | {n} |")

    lifted = sorted(items, key=lambda i: -i["delta"])[:6]
    dropped = sorted(items, key=lambda i: i["delta"])[:6]
    L += ["", "## Exemplars", "",
          "Largest lifts (EVS raises a CVE because its host is valuable / reachable / high-blast):", "",
          "| asset | CVE | CR/IR/AR | CVSS base (L0) | EVS (L4) | Δ |", "|---|---|:--:|--:|--:|--:|"]
    for i in lifted:
        L.append(f"| {i['asset']} | {i['cve']} | {i['cr']}/{i['ir']}/{i['ar']} | {i['L0']:.1f} | {i['L4']:.2f} | {i['delta']:+.2f} |")
    L += ["", "Largest drops (EVS lowers a CVE because its host is low-value / contained):", "",
          "| asset | CVE | CR/IR/AR | CVSS base (L0) | EVS (L4) | Δ |", "|---|---|:--:|--:|--:|--:|"]
    for i in dropped:
        L.append(f"| {i['asset']} | {i['cve']} | {i['cr']}/{i['ir']}/{i['ar']} | {i['L0']:.1f} | {i['L4']:.2f} | {i['delta']:+.2f} |")
    L += ["", "Reading these together: a moderate CVE on a critical, reachable host can out-rank a high CVE on a "
          "throwaway host — the reprioritisation a pure CVSS score cannot make. Whether that reprioritisation is "
          "*right* is what Part B measures, not this report.", ""]

    config.SENSITIVITY_REPORT.parent.mkdir(parents=True, exist_ok=True)
    config.SENSITIVITY_REPORT.write_text("\n".join(L), encoding="utf-8")
    config.SENSITIVITY_REPORT.with_suffix(".json").write_text(json.dumps({
        "generated": date.today().isoformat(), "beta": beta, "gamma": gamma, "kendall": tb, "material_reorderings": material,
        "pairs": [{k: i[k] for k in ("asset", "cve", "L0", "L4", "delta", "cr", "ir", "ar", "internet")} for i in items],
        "per_asset": [{"asset": h, "cr": cr, "ir": ir, "ar": ar, "internet": bool(net), "mean": mean, "median": mid, "n": n}
                      for h, cr, ir, ar, net, mean, mid, n in per_asset]}, indent=1), encoding="utf-8")
    print(f"sensitivity: {len(items)} pairs, tau-b {_f(tb['tau_b'])}, {material} material reorderings "
          f"-> {config.SENSITIVITY_REPORT}")


# =========================================================================================== Part B
def _load_observed() -> dict:
    out = {}
    for name, path, key in (("network", config.OBSERVED_NETWORK, "reachable"),
                            ("usable", config.OBSERVED_USABLE, "usable"),
                            ("dependents", config.OBSERVED_DEPENDENTS, "dependents")):
        if path.exists():
            data = json.loads(path.read_text(encoding="utf-8"))
            out[name] = {"sets": {a: set(h[key]) for a, h in data["hosts"].items()}, "measured_at": data["measured_at"]}
    return out


TRUTH_MODE = {"network": "compromise", "usable": "compromise", "dependents": "disruption"}


def blast_ablation(labels_dir: Path | None = None, beta=score_config.BETA, gamma=score_config.GAMMA, wait=60) -> None:
    g = vckg_graph.load(wait)
    observed = _load_observed()
    if not observed:
        raise SystemExit("no measured ground truth: run python -m eval_kg measure-reach / measure-usable / measure-deps")
    hosts = sorted(g.assets)
    pred, cost = {}, {}
    with driver(wait) as drv, drv.session() as s:
        for v in variants.VARIANTS:
            for mode in ("compromise", "disruption"):
                for h in hosts:
                    t0 = time.perf_counter()
                    sets, extra = variants.predict(g, h, mode, v, s)
                    cost.setdefault(v, []).append(((time.perf_counter() - t0) * 1000, len(sets), extra))
                    pred[(v, mode, h)] = set(sets)
        dist_p = {v: {h: variants.distances_for_p(g, h, v, s) for h in hosts} for v in variants.VARIANTS}

    L = ["# Evaluation, Part B: blast-radius variants against the lab", "",
         f"Generated {date.today().isoformat()} by `python -m eval_kg blast-ablation`. Protocol: `docs/evaluation.md`.", "",
         "Ground truth, measured in the running lab (not read from `lab/*.csv`):", ""]
    descr = {"network": "TCP reachability from each host (compromise mode, network view)",
             "usable": "hosts usable with what is stored on each host (compromise mode)",
             "dependents": "hosts whose service fails when a host is stopped (disruption mode)"}
    for name, o in observed.items():
        L.append(f"- **{name}**: {descr[name]}, measured {o['measured_at']}.")
    L += ["", "Variants: B0 none · B1 unrestricted k-hop over any edge type · B2 zone-level · B3 ours undirected · "
              "B4 ours (Algorithm 1, k=1) · B5 ours k=2/3.", ""]

    bp = {"generated": date.today().isoformat(), "variants": variants.VARIANTS, "per_asset": {}, "per_pair": {},
          "cost": {}, "downstream_ndcg10": {}, "measured_at": {n: o["measured_at"] for n, o in observed.items()}}

    # ---- per asset (each asset is one alerted host)
    for name, o in observed.items():
        mode = TRUTH_MODE[name]
        bp["per_asset"][name] = {"mode": mode, "variants": {}}
        L += [f"## {name} ({mode} mode), per asset", "", "| Variant | Precision | Recall | F1 | Mean set size |",
              "|---|---:|---:|---:|---:|"]
        for v in variants.VARIANTS:
            prf = [metrics.set_prf(pred[(v, mode, h)], o["sets"].get(h, set())) for h in hosts]
            bp["per_asset"][name]["variants"][v] = {
                "precision": _mean([p for p, _, _ in prf]), "recall": _mean([r for _, r, _ in prf]),
                "f1": _mean([f for _, _, f in prf]), "mean_size": _mean([len(pred[(v, mode, h)]) for h in hosts])}
            L.append(f"| {v} | {_f(_mean([p for p, _, _ in prf]))} | {_f(_mean([r for _, r, _ in prf]))} | "
                     f"{_f(_mean([f for _, _, f in prf]))} | {_f(_mean([len(pred[(v, mode, h)]) for h in hosts]), 2)} |")
        L += ["", "Observed sets: " + "; ".join(f"{h} → {', '.join(sorted(o['sets'].get(h, set()))) or '∅'}" for h in hosts), ""]

    # ---- per (asset, CVE): the impact mode of each CVE picks the direction and the truth
    primary = {"compromise": "usable" if "usable" in observed else "network", "disruption": "dependents"}
    pairs = [(v["asset"], model.impact_mode(v["cvss3_vector"])) for v in g.vulns]
    pairs = [(h, m) for h, m in pairs if primary[m] in observed]
    if pairs:
        L += ["## Per (asset, CVE) pair", "",
              f"{len(pairs)} vulnerability instances on the lab assets; each CVE's impact mode picks the direction and "
              f"the ground truth (compromise → {primary['compromise']}, disruption → dependents).", "",
              "| Variant | Precision | Recall | F1 |", "|---|---:|---:|---:|"]
        for v in variants.VARIANTS:
            prf = [metrics.set_prf(pred[(v, m, h)], observed[primary[m]]["sets"].get(h, set())) for h, m in pairs]
            bp["per_pair"][v] = {"precision": _mean([p for p, _, _ in prf]), "recall": _mean([r for _, r, _ in prf]),
                                 "f1": _mean([f for _, _, f in prf]), "n_pairs": len(pairs)}
            L.append(f"| {v} | {_f(_mean([p for p, _, _ in prf]))} | {_f(_mean([r for _, r, _ in prf]))} | "
                     f"{_f(_mean([f for _, _, f in prf]))} |")
        L.append("")

    # ---- cost
    L += ["## Cost", "", "| Variant | Mean runtime per query (ms) | Mean affected hosts | Mean non-asset nodes returned |",
          "|---|---:|---:|---:|"]
    for v in variants.VARIANTS:
        c = cost[v]
        bp["cost"][v] = {"ms": _mean([x[0] for x in c]), "hosts": _mean([x[1] for x in c]),
                         "non_asset_nodes": _mean([x[2] for x in c])}
        L.append(f"| {v} | {_f(_mean([x[0] for x in c]), 2)} | {_f(_mean([x[1] for x in c]), 2)} | "
                 f"{_f(_mean([x[2] for x in c]), 1)} |")
    L.append("")

    # ---- downstream: L4 with each variant's P against Part A labels
    labels_dir = Path(labels_dir or config.ROOT / "evaluation")
    truth = labels.load_pentest_results(labels_dir / "pentest_results.csv")
    L += ["## Downstream: L4 ranking with each variant's P(u)", ""]
    if truth:
        _, epss = _epss()
        L += [f"Labels: `{labels_dir.name}/pentest_results.csv`" +
              (" — **SYNTHETIC DRY RUN, not a result**" if labels_dir.resolve() == config.DRY_RUN.resolve() else ""), "",
              "| Variant | NDCG@10 (asset × CVE) |", "|---|---:|"]
        for v in variants.VARIANTS:
            p_of = {h: variants.propagation(dist_p[v][h], g.crit, gamma) for h in hosts}
            items = [dict(i, grade=truth[(i["asset"], i["cve"])])
                     for i in asset_cve_items(g, epss, beta, gamma, p_of) if (i["asset"], i["cve"]) in truth]
            bp["downstream_ndcg10"][v] = metrics.ndcg_at_k(metrics.ranked(items, 'L4'), 10)
            L.append(f"| {v} | {_f(bp['downstream_ndcg10'][v])} |")
    else:
        L.append("Pending: needs `evaluation/pentest_results.csv` from the pentest.")
    config.REPORTS.mkdir(parents=True, exist_ok=True)
    config.BLAST_REPORT.write_text("\n".join(L) + "\n", encoding="utf-8")
    config.BLAST_REPORT.with_suffix(".json").write_text(json.dumps(bp, indent=1), encoding="utf-8")
    print(f"blast-radius ablation -> {config.BLAST_REPORT}")
