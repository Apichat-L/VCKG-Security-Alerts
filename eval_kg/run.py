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

from . import config, labels, ladder, metrics, sample, variants, wazuh_pairs


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
def asset_cve_items(g, epss, beta, gamma, p_of=None, vulns=None) -> list[dict]:
    """Every vulnerability present on an asset, no alert: E from KEV/SSVC (Eq. 14).

    vulns: the inventory to score; default the graph's own links (g.vulns). Part A1 passes the Wazuh frame
    (wazuh_pairs.frame(), graph links ∪ Wazuh pairs) so sampled Wazuh-only pairs can be scored too."""
    p_of = p_of or {(h, m): g.propagation(h, gamma, m) for h in g.assets for m in ("compromise", "disruption")}
    wazuh = wazuh_pairs.load()
    out = []
    for v in (g.vulns if vulns is None else vulns):
        if not v.get("cvss3_vector") or v["asset"] not in g.assets:
            continue
        if "wazuh_score" not in v:
            v = {**v, "wazuh_score": (wazuh.get((v["asset"], v["cve"])) or {}).get("wazuh_score")}
        asset = g.assets[v["asset"]]
        item = {**v, "alerted": False, "id": f"{v['asset']}|{v['cve']}"}
        p = p_of[(v["asset"], model.impact_mode(v["cvss3_vector"]))]
        item.update(ladder.levels(item, asset, g.internet_path(v["asset"]), p, beta))
        item.update(ladder.baselines(item, asset, epss))
        out.append(item)
    return out


def alert_items(g, epss, beta, gamma, wait=60) -> list[dict]:
    """Vulnerability instances (a, c) reported by alerts, E = H (Eq. 14), with their alert time span."""
    instances, _ = vulnerability_instances(alert_contexts(), technique_matches=True)
    cves, _ = vckg_graph.cve_details(sorted({c for _, c, _ in instances}), wait)
    wazuh = wazuh_pairs.load()
    out = []
    for (asset_name, cve, rule), ctxs in instances.items():
        vuln = cves.get(cve)
        if not vuln or not vuln.get("cvss3_vector") or asset_name not in g.assets:
            continue
        asset = g.assets[asset_name]
        first, last = _times(ctxs)
        item = {**vuln, "asset": asset_name, "cve": cve, "rule_id": rule, "alerted": True,
                "rule_level": ctxs[0]["alert"]["rule_level"], "first_seen": first, "last_seen": last,
                "id": f"{asset_name}|{cve}|{rule}",
                "wazuh_score": (wazuh.get((asset_name, cve)) or {}).get("wazuh_score")}
        item.update(ladder.levels(item, asset, g.internet_path(asset_name),
                                  g.propagation_for(asset_name, vuln["cvss3_vector"], gamma), beta))
        item.update(ladder.baselines(item, asset, epss))
        out.append(item)
    return out


def ranking_metrics(items: list[dict], key: str, rel_threshold: int, chain_threshold: int) -> dict:
    """Every metric is the expected value over random orders within tied scores (metrics.py docstring)."""
    g = metrics.tie_groups(items, key)
    E = lambda fn: metrics.expected(g, fn, 200, config.SEED)
    return {"NDCG@5": metrics.expected_ndcg_at_k(g, 5), "NDCG@10": metrics.expected_ndcg_at_k(g, 10),
            "P@5": metrics.expected_precision_at_k(g, 5, rel_threshold),
            "P@10": metrics.expected_precision_at_k(g, 10, rel_threshold),
            "first": E(lambda r: metrics.first_hit(r, chain_threshold)),
            "MRR": E(lambda r: metrics.reciprocal_rank(r, rel_threshold)),
            "AP": E(lambda r: metrics.average_precision(r, rel_threshold))}


def _ndcg10(key):
    return lambda sample: metrics.expected_ndcg_at_k(metrics.tie_groups(sample, key), 10)


def _mean_query_ndcg10(key):
    return lambda queries: _mean([metrics.expected_ndcg_at_k(metrics.tie_groups(q, key), 10) for q in queries])


def _positive(unit) -> bool:
    return bool(unit["grade"]) if isinstance(unit, dict) else any(i["grade"] for i in unit)


def score_ablation(labels_dir: Path, beta=score_config.BETA, gamma=score_config.GAMMA, wait=60) -> None:
    labels_dir = Path(labels_dir)
    g = vckg_graph.load(wait)
    epss_meta, epss = _epss()
    keys = ladder.LEVELS + ladder.BASELINES
    synthetic = labels_dir.resolve() == config.DRY_RUN.resolve()

    # ---- A1: asset x CVE ranking against exploited (pentest_results.csv)
    truth = labels.load_pentest_results(labels_dir / "pentest_results.csv")
    frame = wazuh_pairs.frame(wait) if not synthetic and config.WAZUH_PAIRS.exists() else None
    a_items = [dict(i, grade=truth[(i["asset"], i["cve"])]) for i in asset_cve_items(g, epss, beta, gamma, vulns=frame)
               if (i["asset"], i["cve"]) in truth]
    drawn = sample.sampled_pairs()
    for i in a_items:
        i["origin"] = "sampled" if (i["asset"], i["cve"]) in drawn else "hand-picked"
    missing = sorted(set(truth) - {(i["asset"], i["cve"]) for i in a_items})
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
          f"β = {beta:g}, γ = {gamma:g}. EPSS {epss_meta.get('model_version', '-')}. Tied scores: every metric is the expected value over random orders within the tie (not the id order); "
          "EVS scores tied at the cap of 10 are ordered by the uncapped Env·(1+βP) (docs/scoring.md).", "",
          "Ladder: L0 CVSS base · L1 + CR/IR/AR · L2 + MAV (Internet reachability) · L3 + E (alert/KEV/SSVC) · "
          "L4 + P(a,c) over the blast radius = EVS. Baselines (not our score): EPSS percentile, KEV, CISA SSVC, Wazuh rule.level, "
          "WazuhVD (the CVSS base Wazuh's vulnerability detector shows for the pair), Random (chance level).", ""]

    def table(items_or_queries, per_query, rel_t, chain_t):
        rows = []
        for k in keys:
            if per_query:
                ms = [ranking_metrics(q, k, rel_t, chain_t) for q in items_or_queries if q[0].get(k) is not None]
                if not ms:
                    continue
                m = {x: _mean([r[x] for r in ms]) for x in ("NDCG@5", "NDCG@10", "P@5", "P@10", "MRR", "AP")}
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
            out.append((f"{a} − {b}", metrics.paired_bootstrap(units, fn(a), fn(b), config.BOOTSTRAP, config.SEED, _positive)))
        for base in ladder.BASELINES:
            if per_query and any(q[0].get(base) is None for q in units):
                continue
            if not per_query and any(i.get(base) is None for i in units):
                continue
            out.append((f"L4 − {base}", metrics.paired_bootstrap(units, fn("L4"), fn(base), config.BOOTSTRAP, config.SEED, _positive)))
        return out

    payload = {"generated": date.today().isoformat(), "beta": beta, "gamma": gamma, "synthetic": synthetic, "sets": {}}

    def emit(title, rows, gain_rows, note, set_key=None):
        nonlocal L
        if set_key:
            payload["sets"][set_key] = {"title": title, "note": note,
                                        "scores": {k: m for k, m in rows},
                                        "gains": {name: b for name, b in gain_rows}}
        L += [f"## {title}", "", note, "",
              "| Score | NDCG@5 | NDCG@10 | P@5 | P@10 | MRR | AP | Rank of first true item |",
              "|---|---:|---:|---:|---:|---:|---:|---:|"]
        for k, m in rows:
            L.append(f"| {k} | {_f(m['NDCG@5'])} | {_f(m['NDCG@10'])} | {_f(m['P@5'])} | {_f(m['P@10'])} | "
                     f"{_f(m['MRR'])} | {_f(m.get('AP'))} | {_f(m['first'], 1) if m['first'] is not None else '-'} |")
        L += ["", "Gain in NDCG@10 with a 95% paired-bootstrap CI, resampling positives and negatives separately "
                  "(* = CI excludes 0):", "",
              "| Comparison | Δ NDCG@10 [95% CI] |", "|---|---|"]
        L += [f"| {name} | {_ci(b)} |" for name, b in gain_rows]
        L.append("")

    if a_items:
        n_pos = sum(i["grade"] for i in a_items)
        n_sampled = sum(i["origin"] == "sampled" for i in a_items)
        n_fallback = sum(i["wazuh_vd_fallback"] for i in a_items)
        emit("A1. Vulnerabilities on assets (asset × CVE, no alert)", table(a_items, False, 1, 1),
             gains(a_items, False),
             f"{len(a_items)} labelled pairs from `pentest_results.csv` ({n_pos} exploited); `not_tried` pairs are "
             f"left out. Relevance = exploited (1/0). Bootstrap resamples pairs. Origin: {n_sampled} drawn by the "
             f"sampler (`pentest_candidates.csv`), {len(a_items) - n_sampled} hand-picked. WazuhVD: "
             f"{len(a_items) - n_fallback} pairs reported by Wazuh, {n_fallback} not (CVSS base used)."
             + (f" Not scorable (no CVSS v3.1 vector, or not in the inventory): {', '.join(f'{a}/{c}' for a, c in missing)}."
                if missing else ""), set_key="A1")
        payload["sets"]["A1"].update(n_items=len(a_items), n_positive=n_pos, n_sampled=n_sampled,
                                     n_wazuh_vd_fallback=n_fallback)
        sampled = [i for i in a_items if i["origin"] == "sampled"]
        if sampled and any(i["grade"] for i in sampled):
            emit("A1s. Sampled pairs only (sensitivity check)", table(sampled, False, 1, 1), gains(sampled, False),
                 f"{len(sampled)} pairs drawn by the sampler ({sum(i['grade'] for i in sampled)} exploited); "
                 "the hand-picked rows are left out.", set_key="A1s")
        else:
            L += ["## A1s. Sampled pairs only", "",
                  f"{len(sampled)} sampled pairs labelled yes/no, {sum(i['grade'] for i in sampled)} exploited: "
                  "nothing to rank yet.", ""]
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
            a, b = (xs[i] > xs[j]) - (xs[i] < xs[j]), (ys[i] > ys[j]) - (ys[i] < ys[j])
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
        items.append({"asset": it["asset"], "cve": it["cve"], "L0": it["L0"], "L1": it["L1"], "L2": it["L2"],
                      "L3": it["L3"], "L4": it["L4"],
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
        mine = [i for i in items if i["asset"] == h]
        mean, mid, n = summ([i["delta"] for i in mine])
        if n:
            steps = tuple(_mean([i[b] - i[a] for i in mine]) for a, b in zip(ladder.LEVELS[:-1], ladder.LEVELS[1:]))
            per_asset.append((h, a["cr"], a["ir"], a["ar"], g.internet_path(h), mean, mid, n, steps))
    per_asset.sort(key=lambda r: r[5])  # most-suppressed first

    L = ["# Evaluation, Part A (sensitivity): how the EVS reprioritises CVSS", "",
         f"Generated {date.today().isoformat()} by `python -m eval_kg sensitivity`. β = {beta:g}, γ = {gamma:g}.", "",
         "> **This is a sensitivity analysis of the scoring mechanism, not a ground-truth validation.** It measures "
         "how far the EVS (L4) reorders a pure CVSS-base (L0) ranking across the whole asset × CVE inventory, with "
         "no alert and no exploit outcome, and checks the reordering follows asset value and reachability — i.e. the "
         "context terms do what the design claims. It does **not** show the reordering is *correct*: there is no "
         "outcome label here. The validated contextual claim is Part B (blast radius vs lab-measured impact); the "
         "ground-truth ranking test of this direction is Part A4 (`eval_consequence.md`), which compares the same "
         "orderings with the consequence measured in the lab.", "",
         f"**Inventory:** {len(items)} asset × CVE pairs across {len({i['asset'] for i in items})} assets.", "",
         "## Reordering magnitude (L0 CVSS base vs L4 EVS)", "",
         f"- Kendall's tau-b: **{_f(tb['tau_b'])}** (1 = identical order, 0 = unrelated). The EVS keeps the broad "
         "CVSS order but reorders within it.",
         f"- Pairs: {tb['concordant']} concordant, **{tb['discordant']} discordant**, "
         f"{tb['tied_L0_only']} tied on CVSS only, {tb['tied_EVS_only']} tied on EVS only, of {tb['total_pairs']} total.",
         f"- Material cross-asset reorderings (a CVSS gap ≥ 0.5 that the EVS flips): **{material}**.", "",
         "## Direction check (mean / median of L4 − L0, per asset)", "",
         "If the reordering tracks context, the EVS should lift CVEs on valuable, reachable hosts and lower them on "
         "throwaway, contained ones. Assets below are ordered most-suppressed first. The step columns attribute "
         "the mean change to each ladder step: +CR/IR/AR (L1−L0), +MAV (L2−L1), +E (L3−L2), +blast-radius "
         "propagation P(a,c) (L4−L3); they add up to the mean ΔEVS.", "",
         "| asset | CR/IR/AR | internet-reachable | mean ΔEVS | median ΔEVS | +CR/IR/AR | +MAV | +E | +P(a,c) | n CVEs |",
         "|---|:--:|:--:|--:|--:|--:|--:|--:|--:|--:|"]
    for h, cr, ir, ar, net, mean, mid, n, st in per_asset:
        L.append(f"| {h} | {cr}/{ir}/{ar} | {'yes' if net else 'no'} | {mean:+.2f} | {mid:+.2f} | "
                 + " | ".join(f"{x:+.2f}" for x in st) + f" | {n} |")

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
          "*right* is what Part A4 (measured consequence) and Part B (blast radius vs the lab) measure.", ""]

    config.SENSITIVITY_REPORT.parent.mkdir(parents=True, exist_ok=True)
    config.SENSITIVITY_REPORT.write_text("\n".join(L), encoding="utf-8")
    config.SENSITIVITY_REPORT.with_suffix(".json").write_text(json.dumps({
        "generated": date.today().isoformat(), "beta": beta, "gamma": gamma, "kendall": tb, "material_reorderings": material,
        "pairs": [{k: i[k] for k in ("asset", "cve", "L0", "L4", "delta", "cr", "ir", "ar", "internet")} for i in items],
        "per_asset": [{"asset": h, "cr": cr, "ir": ir, "ar": ar, "internet": bool(net), "mean": mean, "median": mid, "n": n,
                       "steps": dict(zip(["L1-L0", "L2-L1", "L3-L2", "L4-L3"], st))}
                      for h, cr, ir, ar, net, mean, mid, n, st in per_asset]}, indent=1), encoding="utf-8")
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
        dist_p = {v: {(h, m): variants.distances_for_p(g, h, v, m, s) for h in hosts
                      for m in ("compromise", "disruption")} for v in variants.VARIANTS}

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
        empty = [h for h in hosts if not (o["sets"].get(h, set()) - {h})]
        L += [f"## {name} ({mode} mode), per asset", "",
              f"Pooled = micro-average over every (host, affected host) pair: hosts with an empty prediction or an empty "
              f"truth add nothing, so B0 gets no free credit. Mean = the earlier per-host average (an empty truth "
              f"counts as recall 1, an empty prediction as precision 1). {len(empty)} of {len(hosts)} hosts have an "
              f"empty truth here; 'FP on empty' counts the hosts a variant predicts for them.", "",
              "| Variant | Pooled P | Pooled R | Pooled F1 | Mean P | Mean R | Mean F1 | FP on empty | Mean set size |",
              "|---|---:|---:|---:|---:|---:|---:|---:|---:|"]
        for v in variants.VARIANTS:
            sets = [(set(pred[(v, mode, h)]), o["sets"].get(h, set()) - {h}) for h in hosts]
            prf = [metrics.set_prf(p, t) for p, t in sets]
            pp, pr, pf = metrics.pooled_prf(sets)
            fp_empty = sum(len(pred[(v, mode, h)]) for h in empty)
            bp["per_asset"][name]["variants"][v] = {
                "precision": _mean([p for p, _, _ in prf]), "recall": _mean([r for _, r, _ in prf]),
                "f1": _mean([f for _, _, f in prf]), "mean_size": _mean([len(pred[(v, mode, h)]) for h in hosts]),
                "pooled_precision": pp, "pooled_recall": pr, "pooled_f1": pf, "fp_on_empty": fp_empty}
            L.append(f"| {v} | {_f(pp)} | {_f(pr)} | {_f(pf)} | {_f(_mean([p for p, _, _ in prf]))} | "
                     f"{_f(_mean([r for _, r, _ in prf]))} | {_f(_mean([f for _, _, f in prf]))} | {fp_empty} | "
                     f"{_f(_mean([len(pred[(v, mode, h)]) for h in hosts]), 2)} |")
        L += ["", "Observed sets: " + "; ".join(f"{h} → {', '.join(sorted(o['sets'].get(h, set()))) or '∅'}" for h in hosts), ""]

    # ---- per (asset, CVE): the impact mode of each CVE picks the direction and the truth
    primary = {"compromise": "usable" if "usable" in observed else "network", "disruption": "dependents"}
    pairs = [(v["asset"], model.impact_mode(v["cvss3_vector"])) for v in g.vulns]
    pairs = [(h, m) for h, m in pairs if primary[m] in observed]
    if pairs:
        L += ["## Per (asset, CVE) pair", "",
              f"{len(pairs)} vulnerability instances on the lab assets; each CVE's impact mode picks the direction and "
              f"the ground truth (compromise → {primary['compromise']}, disruption → dependents).", "",
              "| Variant | Pooled P | Pooled R | Pooled F1 | Mean P | Mean R | Mean F1 |", "|---|---:|---:|---:|---:|---:|---:|"]
        for v in variants.VARIANTS:
            sets = [(set(pred[(v, m, h)]), observed[primary[m]]["sets"].get(h, set()) - {h}) for h, m in pairs]
            prf = [metrics.set_prf(p, t) for p, t in sets]
            pp, pr, pf = metrics.pooled_prf(sets)
            bp["per_pair"][v] = {"precision": _mean([p for p, _, _ in prf]), "recall": _mean([r for _, r, _ in prf]),
                                 "f1": _mean([f for _, _, f in prf]), "n_pairs": len(pairs),
                                 "pooled_precision": pp, "pooled_recall": pr, "pooled_f1": pf}
            L.append(f"| {v} | {_f(pp)} | {_f(pr)} | {_f(pf)} | {_f(_mean([p for p, _, _ in prf]))} | "
                     f"{_f(_mean([r for _, r, _ in prf]))} | {_f(_mean([f for _, _, f in prf]))} |")
        L.append("")

    # ---- independent check: hosts the pentest actually reached from each foothold
    scen = [s for s in labels.load_scenarios(config.SCENARIOS) if not s["synthetic"]]
    by_service = {svc: h for h, svc in config.SERVICES.items()}
    pivot_rows = []
    for s in scen:
        foot = by_service.get(s.get("attacker") or "")
        if not foot:
            continue                                       # external attacker (kali): no foothold asset
        reached = {st["target"] for st in s["steps"]
                   if str(st.get("outcome", "")).lower() == "success" and st.get("target") in g.assets} - {foot}
        if reached:
            pivot_rows.append((s["id"], foot, reached))
    bp["pentest_pivots"] = {}
    if pivot_rows:
        L += ["## Independent check: hosts the pentest reached from its foothold", "",
              "The pentest scenarios record an attacker foothold (`attacker:`) and the hosts it then compromised "
              "(`outcome: success`). Those were achieved by hand, not read from `CONNECTS_TO` or `checks.csv`. "
              "Recall = share of the reached hosts inside the variant's compromise-mode blast radius of the foothold.", "",
              "| Scenario | Foothold | Reached in the pentest | " + " | ".join(variants.VARIANTS) + " |",
              "|---|---|---|" + "---:|" * len(variants.VARIANTS)]
        tot = {v: [0, 0, 0] for v in variants.VARIANTS}            # hit, reached, predicted
        for sid, foot, reached in pivot_rows:
            cells = []
            for v in variants.VARIANTS:
                p = set(pred[(v, "compromise", foot)])
                hit = len(p & reached)
                tot[v][0] += hit; tot[v][1] += len(reached); tot[v][2] += len(p)
                cells.append(f"{hit}/{len(reached)}")
            L.append(f"| {sid} | {foot} | {', '.join(sorted(reached))} | " + " | ".join(cells) + " |")
        L.append("| **Pooled recall** | | | " + " | ".join(_f(tot[v][0] / tot[v][1]) for v in variants.VARIANTS) + " |")
        L.append("| Hosts predicted per foothold | | | " + " | ".join(_f(tot[v][2] / len(pivot_rows), 1) for v in variants.VARIANTS) + " |")
        L += ["", "A miss means the attacker got somewhere the variant did not predict (e.g. guessing a password "
                  "for a host the foothold has no recorded flow to); a large predicted set buys recall with precision.", ""]
        bp["pentest_pivots"] = {"rows": [{"scenario": a, "foothold": b, "reached": sorted(c)} for a, b, c in pivot_rows],
                                "recall": {v: tot[v][0] / tot[v][1] for v in variants.VARIANTS},
                                "mean_predicted": {v: tot[v][2] / len(pivot_rows) for v in variants.VARIANTS}}

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

    # ---- downstream: the EVS with each variant's blast radius in P(a,c), ranked against the A4 labels
    L += ["## Downstream: the EVS with each variant's blast radius in P(a,c)", ""]
    if all(t in observed for t in TRUTH_FOR_MODE.values()):
        _, epss = _epss()
        L += ["Each variant's set replaces BR_1 inside P(a,c) (Eq. 16); the resulting EVS ranks the asset × CVE "
              "inventory against the consequence measured in the lab (Part A4 labels, `eval_consequence.md`). "
              "Tie-aware metrics.", "",
              "| Variant | NDCG@50 | AP | Kendall τ-b | Pair concordance | Same-CVE concordance |", "|---|---:|---:|---:|---:|---:|"]
        base = consequence_items(g, epss, observed, beta, gamma)
        for v in variants.VARIANTS:
            p_of = {hm: variants.propagation(d, g.crit, gamma) for hm, d in dist_p[v].items()}
            l4 = {i["id"]: (i["L4"], i["L4_raw"]) for i in asset_cve_items(g, epss, beta, gamma, p_of)}
            items = [dict(i, L4=l4[i["id"]][0], L4_raw=l4[i["id"]][1]) for i in base]
            gr = metrics.tie_groups(items, "L4")
            by_cve = {}
            for i in items:
                by_cve.setdefault(i["cve"], []).append(i)
            per = [_pair_concordance(x, "L4") for x in by_cve.values() if len({i["grade"] for i in x}) >= 2]
            r_, t_, w_ = (sum(p[k] for p in per) for k in (1, 2, 3))
            row = {"NDCG@50": metrics.expected_ndcg_at_k(gr, 50),
                   "AP": metrics.expected(gr, lambda r: metrics.average_precision(r, 1), 100, config.SEED),
                   "tau_b": _kendall_tau_b([metrics.rank_key(i, "L4") for i in items], [i["grade"] for i in items])["tau_b"],
                   "concordance": _pair_concordance(items, "L4")[0],
                   "same_cve": (r_ + 0.5 * t_) / (r_ + t_ + w_) if r_ + t_ + w_ else None}
            bp["downstream_ndcg10"][v] = row
            L.append(f"| {v} | {_f(row['NDCG@50'])} | {_f(row['AP'])} | {_f(row['tau_b'])} | {_f(row['concordance'])} | "
                     f"{_f(row['same_cve'])} |")
        L.append("")
    else:
        L.append("Pending: needs the measured usable and dependents sets.")
    config.REPORTS.mkdir(parents=True, exist_ok=True)
    config.BLAST_REPORT.write_text("\n".join(L) + "\n", encoding="utf-8")
    config.BLAST_REPORT.with_suffix(".json").write_text(json.dumps(bp, indent=1), encoding="utf-8")
    print(f"blast-radius ablation -> {config.BLAST_REPORT}")


# ====================================================================== Part A4, measured consequence
TRUTH_FOR_MODE = {"compromise": "usable", "disruption": "dependents"}


def consequence_items(g, epss, observed, beta, gamma) -> list[dict]:
    """Every graph asset x CVE pair, labelled with the consequence measured in the running lab.

    grade = number of other hosts the lab measured as affected in the CVE's impact mode, capped at 3:
    compromise -> hosts usable with what is stored on the asset (measure-usable),
    disruption -> hosts whose service fails when the asset stops (measure-deps).
    Neither measurement reads CR/IR/AR, CVSS, KEV or EPSS."""
    out = []
    for i in asset_cve_items(g, epss, beta, gamma):
        mode = model.impact_mode(i["cvss3_vector"])
        truth = observed[TRUTH_FOR_MODE[mode]]["sets"].get(i["asset"], set()) - {i["asset"]}
        out.append(dict(i, mode=mode, affected=sorted(truth), grade=min(len(truth), 3)))
    return out


def _pair_concordance(items: list[dict], key: str) -> tuple[float, int, int, int]:
    """Over item pairs with different grades: share ordered like the grade (a tie counts 1/2), and the counts
    (right, tied, wrong)."""
    right = tied = wrong = 0
    for x in range(len(items)):
        for y in range(x + 1, len(items)):
            a, b = items[x], items[y]
            dg = a["grade"] - b["grade"]
            if dg == 0:
                continue
            ka, kb = metrics.rank_key(a, key), metrics.rank_key(b, key)
            ds = (ka > kb) - (ka < kb)
            if ds == 0:
                tied += 1
            elif (ds > 0) == (dg > 0):
                right += 1
            else:
                wrong += 1
    n = right + tied + wrong
    return ((right + 0.5 * tied) / n if n else None), right, tied, wrong


def consequence(beta=score_config.BETA, gamma=score_config.GAMMA, wait=60) -> None:
    """Part A4: does each ladder step order the inventory by the consequence measured in the lab?"""
    import random
    g = vckg_graph.load(wait)
    observed = _load_observed()
    if not all(t in observed for t in TRUTH_FOR_MODE.values()):
        raise SystemExit("needs measured usable and dependents sets: python -m eval_kg measure-usable / measure-deps")
    epss_meta, epss = _epss()
    items = consequence_items(g, epss, observed, beta, gamma)
    keys = ladder.LEVELS + [b for b in ladder.BASELINES if all(i.get(b) is not None for i in items)]
    n_pos = sum(1 for i in items if i["grade"])
    rate = n_pos / len(items)

    # ---- 1. ranking quality per score
    rows = {}
    for k in keys:
        gr = metrics.tie_groups(items, k)
        tau = _kendall_tau_b([metrics.rank_key(i, k) for i in items], [i["grade"] for i in items])["tau_b"]
        rows[k] = {"NDCG@10": metrics.expected_ndcg_at_k(gr, 10), "NDCG@50": metrics.expected_ndcg_at_k(gr, 50),
                   "NDCG": metrics.expected_ndcg_at_k(gr, len(items)),
                   "P@50": metrics.expected_precision_at_k(gr, 50, 1),
                   "AP": metrics.expected(gr, lambda r: metrics.average_precision(r, 1), 100, config.SEED),
                   "tau_b": tau, "concordance": _pair_concordance(items, k)[0]}

    strata = lambda i: i["grade"]
    nd = lambda k: (lambda s: metrics.expected_ndcg_at_k(metrics.tie_groups(s, k), 50))
    comps = [(f"{a} − {b}", a, b) for a, b in zip(ladder.LEVELS[1:], ladder.LEVELS[:-1])]
    comps += [("L4 − L0", "L4", "L0")] + [(f"L4 − {b}", "L4", b) for b in keys if b not in ladder.LEVELS]
    gains = [(name, metrics.paired_bootstrap(items, nd(a), nd(b), config.BOOTSTRAP, config.SEED, strata))
             for name, a, b in comps]

    # ---- 2. the same CVE on different hosts: CVSS ties these by construction
    by_cve = {}
    for i in items:
        by_cve.setdefault(i["cve"], []).append(i)
    multi = {c: v for c, v in by_cve.items() if len({i["asset"] for i in v}) >= 2 and len({i["grade"] for i in v}) >= 2}
    same = {}
    for k in keys:
        per = [_pair_concordance(v, k) for v in multi.values()]
        right, tied, wrong = (sum(p[i] for p in per) for i in (1, 2, 3))
        n = right + tied + wrong
        # cluster bootstrap over CVEs for the pooled concordance
        rng, cves, boots = random.Random(config.SEED), list(multi), []
        for _ in range(config.BOOTSTRAP if n else 0):
            pick = [per[cves.index(cves[rng.randrange(len(cves))])] for _ in cves]
            r_, t_, w_ = (sum(p[i] for p in pick) for i in (1, 2, 3))
            if r_ + t_ + w_:
                boots.append((r_ + 0.5 * t_) / (r_ + t_ + w_))
        boots.sort()
        same[k] = {"pairs": n, "right": right, "tied": tied, "wrong": wrong,
                   "concordance": (right + 0.5 * tied) / n if n else None,
                   "lo": boots[int(0.025 * (len(boots) - 1))] if boots else None,
                   "hi": boots[int(0.975 * (len(boots) - 1))] if boots else None}

    # ---- 3. ties in CVSS that the EVS breaks
    tie_pairs = right = wrong = still = separated = 0
    groups = {}
    for i in items:
        groups.setdefault(i["L0"], []).append(i)
    for v in groups.values():
        for x in range(len(v)):
            for y in range(x + 1, len(v)):
                a, b = v[x], v[y]
                tie_pairs += 1
                ka, kb = metrics.rank_key(a, "L4"), metrics.rank_key(b, "L4")
                ds = (ka > kb) - (ka < kb)
                separated += ds != 0
                dg = a["grade"] - b["grade"]
                if dg == 0:
                    continue
                if ds == 0:
                    still += 1
                elif (ds > 0) == (dg > 0):
                    right += 1
                else:
                    wrong += 1

    # ---- report
    L = ["# Evaluation, Part A4: ranking by the consequence measured in the lab", "",
         f"Generated {date.today().isoformat()} by `python -m eval_kg consequence`. β = {beta:g}, γ = {gamma:g}. "
         f"EPSS {epss_meta.get('model_version', '-')}. Protocol: `evaluation/README.md` (A4).", "",
         "**Question.** The EVS claims to prioritise a vulnerability by what its exploitation would *do in this "
         "network*, which a CVSS base score cannot see. A4 checks that claim against what the lab *measured*: for "
         "each asset × CVE pair, the number of other hosts actually affected in the CVE's impact mode.", "",
         "**Label (grade 0–3, capped).** Compromise-mode CVE (C or I impact): hosts usable with what is stored on the "
         f"asset (`measure-usable`, {observed['usable']['measured_at']}). Disruption-mode CVE (availability only): "
         f"hosts whose service fails when the asset stops (`measure-deps`, {observed['dependents']['measured_at']}). "
         "Both are measured in the running lab and read none of the score's inputs (CR/IR/AR, CVSS, KEV, EPSS).", "",
         f"**Items.** {len(items)} asset × CVE pairs (the whole graph inventory, no sampling), {n_pos} with grade ≥ 1 "
         f"(prevalence {rate:.2f}, the AP of a random ranking). Grades: "
         + ", ".join(f"{gr}: {sum(1 for i in items if i['grade'] == gr)}" for gr in range(4)) + ".", "",
         "**Threat to validity.** The blast radius inside L4 is built from `CONNECTS_TO` edges written from the lab "
         "design, and Part B shows it matches the same measurements. A4 therefore tests that the EVS carries measured "
         "consequence through to the *ranking* (CVSS cannot, whatever its quality); it is not an exploit-prediction "
         "test (A1/A3) and not a claim that the edges were discovered independently.", "",
         "## 1. Ranking quality per score", "",
         "Expected values over random orders within tied scores. τ-b and concordance are against the grade over "
         "all item pairs (concordance: share of differently-graded pairs ordered correctly, a tie counts ½; "
         "0.5 = chance).", "",
         "| Score | NDCG@10 | NDCG@50 | NDCG (full) | P@50 | AP | Kendall τ-b | Pair concordance |",
         "|---|---:|---:|---:|---:|---:|---:|---:|"]
    for k in keys:
        m = rows[k]
        L.append(f"| {k} | {_f(m['NDCG@10'])} | {_f(m['NDCG@50'])} | {_f(m['NDCG'])} | {_f(m['P@50'])} | "
                 f"{_f(m['AP'])} | {_f(m['tau_b'])} | {_f(m['concordance'])} |")
    L += ["", "Gain in NDCG@50 with a 95% paired-bootstrap CI (resampled within each grade; * = CI excludes 0):", "",
          "| Comparison | Δ NDCG@50 [95% CI] |", "|---|---|"]
    L += [f"| {name} | {_ci(b)} |" for name, b in gains]
    L += ["", "## 2. The same CVE on different hosts", "",
          f"{len(multi)} CVEs are present on two or more hosts whose measured consequence differs. CVSS gives every "
          "copy the same score, so it can only tie them (concordance 0.5). Concordance pooled over the host pairs, "
          "95% CI from a bootstrap over CVEs.", "",
          "| Score | Host pairs | Ordered like the lab | Tied | Reversed | Concordance [95% CI] |",
          "|---|---:|---:|---:|---:|---|"]
    for k in keys:
        s = same[k]
        L.append(f"| {k} | {s['pairs']} | {s['right']} | {s['tied']} | {s['wrong']} | "
                 f"{_f(s['concordance'])} [{_f(s['lo'])}, {_f(s['hi'])}] |")
    ex = sorted(multi.items(), key=lambda kv: (-len(kv[1]), kv[0]))[:4]
    if ex:
        L += ["", "Examples (same CVE, same CVSS base, different host):", "",
              "| CVE | Host | Mode | Measured affected hosts | L0 | L1 | L3 | EVS (L4) |", "|---|---|---|---|---:|---:|---:|---:|"]
        for c, v in ex:
            for i in sorted(v, key=lambda i: (-i["grade"], -i["L4"], i["asset"])):
                L.append(f"| {c} | {i['asset']} | {i['mode']} | {', '.join(i['affected']) or '∅'} | {i['L0']} | "
                         f"{i['L1']} | {i['L3']} | {i['L4']} |")
    L += ["", "## 3. Ties in the CVSS base score that the EVS breaks", "",
          f"- Pairs of items with the **same CVSS base score**: {tie_pairs}. The EVS separates {separated} of them "
          f"({separated / tie_pairs:.0%})." if tie_pairs else "- No CVSS ties.",
          f"- Of the tied pairs whose measured consequence differs ({right + wrong + still}): EVS orders "
          f"**{right}** like the lab, {wrong} the other way, {still} still tied.", "",
          "## 4. Per asset", "", "| Asset | CR/IR/AR | Internet path | Measured: usable / dependents | CVEs | "
          "mean L0 | mean EVS | mean grade |", "|---|---|---|---|---:|---:|---:|---:|"]
    by_asset = {}
    for i in items:
        by_asset.setdefault(i["asset"], []).append(i)
    for h, v in sorted(by_asset.items(), key=lambda kv: -_mean([i["L4"] for i in kv[1]])):
        a = g.assets[h]
        L.append(f"| {h} | {a['cr']}/{a['ir']}/{a['ar']} | {'yes' if g.internet_path(h) else 'no'} | "
                 f"{len(observed['usable']['sets'].get(h, set()) - {h})} / {len(observed['dependents']['sets'].get(h, set()) - {h})} | "
                 f"{len(v)} | {_mean([i['L0'] for i in v]):.2f} | {_mean([i['L4'] for i in v]):.2f} | "
                 f"{_mean([i['grade'] for i in v]):.2f} |")
    config.REPORTS.mkdir(parents=True, exist_ok=True)
    config.CONSEQUENCE_REPORT.write_text("\n".join(L) + "\n", encoding="utf-8")
    config.CONSEQUENCE_REPORT.with_suffix(".json").write_text(json.dumps({
        "generated": date.today().isoformat(), "beta": beta, "gamma": gamma, "n_items": len(items),
        "n_positive": n_pos, "prevalence": rate, "scores": rows, "gains": {n: b for n, b in gains},
        "same_cve": {"n_cves": len(multi), "scores": same},
        "cvss_ties": {"pairs": tie_pairs, "separated": separated, "right": right, "wrong": wrong, "still_tied": still},
    }, indent=1), encoding="utf-8")
    print(f"consequence: {len(items)} pairs, {n_pos} with measured consequence, {len(multi)} multi-host CVEs "
          f"-> {config.CONSEQUENCE_REPORT}")
