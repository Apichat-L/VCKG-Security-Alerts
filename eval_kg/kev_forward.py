"""Part A3: forward-in-time KEV test on the Wazuh inventory (docs/PLAN.md §6 tier A and §8).

Label that does not come from the team: was the CVE added to CISA KEV *after* a cut-off T0? The ladder is
computed with only what was known at T0, so KEV is never both an input and the label:

  items     the evaluation frame (wazuh_pairs.frame(): Wazuh pairs ∪ graph links), scorable CVEs only
  excluded  CVEs already in KEV at T0 (known, nothing to predict) and CVEs published after T0 (not knowable)
  label     1 if kev_date_added > T0, else 0
  E (L3)    KEV as of T0 only, which after the exclusion is never set; SSVC exploitation is dropped, because the
            graph does not store when vulnrichment assessed it and 'active' would leak the label. So L3 = L2 here.
  MAV (L2)  Internet reachability for pairs on a network service of the host; other packages (libraries, tools)
            keep their base AV, since the host's reachability says nothing about how they are reached.
  EPSS      the daily EPSS file *of T0* (downloaded once to data/raw/epss/), not today's.

    python -m eval_kg kev-forward [--t0 2026-05-01]     -> data/reports/eval_kev_forward.md
"""
import gzip
import json
from datetime import date

import requests

from score_kg import config as score_config
from score_kg import epss as epss_mod
from score_kg import graph as vckg_graph
from score_kg import model, ssvc

from . import config, ladder, metrics, wazuh_pairs

MIN_POSITIVE_CVES = 5
KEYS = ["L0", "L1", "L2", "L3", "L4", "EPSS@T0", "SSVC@T0", "WazuhVD"]


def split(items: list[dict], t0: str) -> tuple[list[dict], dict]:
    """Items kept for the test, each with 'grade' (added to KEV after T0); and the exclusion counts."""
    kept, why = [], {"no CVSS v3.1 vector": 0, "in KEV at T0": 0, "published after T0": 0, "no publication date": 0}
    for i in items:
        kev = i.get("kev_date_added") or ""
        pub = (i.get("published") or "")[:10]
        if not i.get("cvss3_vector"):
            why["no CVSS v3.1 vector"] += 1
        elif kev and kev[:10] <= t0:
            why["in KEV at T0"] += 1
        elif not pub:
            why["no publication date"] += 1
        elif pub > t0:
            why["published after T0"] += 1
        else:
            kept.append({**i, "grade": 1 if kev else 0})
    return kept, why


def epss_at(t0: str) -> tuple[dict, dict]:
    path = config.EPSS_HISTORY / f"epss_scores-{t0}.csv.gz"
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        r = requests.get(config.EPSS_HISTORY_URL.format(date=t0), timeout=120)
        if r.status_code == 404:
            raise SystemExit(f"no EPSS file for {t0} at {config.EPSS_HISTORY_URL.format(date=t0)}")
        r.raise_for_status()
        path.write_bytes(r.content)
    with gzip.open(path, "rt", encoding="utf-8") as fh:
        return epss_mod.parse(fh)


def score(item: dict, g, epss: dict, beta: float, gamma_p: dict) -> dict:
    asset = g.assets[item["asset"]]
    as_of_t0 = {**item, "kev": False, "ssvc_exploitation": None, "alerted": False}
    reach = g.internet_path(item["asset"]) if item.get("service") else True      # True keeps the base AV
    out = ladder.levels(as_of_t0, asset, reach, gamma_p[(item["asset"], model.impact_mode(item["cvss3_vector"]))], beta)
    mission = ssvc.mission_prevalence(asset["cr"], asset["ir"], asset["ar"])
    decision = ssvc.outcome(None, item.get("ssvc_automatable"), item.get("ssvc_technical_impact"), False,
                            item["cvss3_vector"], mission)
    e = epss.get(item["cve"])
    out.update({"EPSS@T0": e[1] if e else 0.0, "SSVC@T0": float(ladder.SSVC_ORDER[decision]),
                "WazuhVD": item["wazuh_score"] if item.get("wazuh_score") is not None else out["L0"]})
    return out


def run(t0: str = config.KEV_T0, beta=score_config.BETA, gamma=score_config.GAMMA, wait: int = 60) -> dict:
    if not config.WAZUH_PAIRS.exists():
        raise SystemExit(f"{config.WAZUH_PAIRS} not found: run `python -m eval_kg wazuh-pairs` first")
    g = vckg_graph.load(wait)
    frame = [i for i in wazuh_pairs.frame(wait) if i["asset"] in g.assets]
    items, excluded = split(frame, t0)
    epss_meta, epss = epss_at(t0)
    p = {(h, m): g.propagation(h, gamma, m) for h in g.assets for m in ("compromise", "disruption")}
    for i in items:
        i.update(score(i, g, epss, beta, p))

    pos = [i for i in items if i["grade"]]
    pos_cves = sorted({i["cve"] for i in pos})
    under = len(pos_cves) < MIN_POSITIVE_CVES
    rows = {}
    for k in KEYS:
        gr = metrics.tie_groups(items, k)                     # tie-aware (expected over tie orders)
        E = lambda fn: metrics.expected(gr, fn, 50, config.SEED)
        rows[k] = {"NDCG@10": metrics.expected_ndcg_at_k(gr, 10), "NDCG@100": metrics.expected_ndcg_at_k(gr, 100),
                   "P@10": metrics.expected_precision_at_k(gr, 10, 1), "P@100": metrics.expected_precision_at_k(gr, 100, 1),
                   "MRR": E(lambda r: metrics.reciprocal_rank(r, 1)), "first": E(lambda r: metrics.first_hit(r, 1)),
                   "mean_rank": E(lambda r: sum(i for i, x in enumerate(r, 1) if x) / len(pos)) if pos else None}

    def ndcg100(key):
        return lambda sample: metrics.expected_ndcg_at_k(metrics.tie_groups(sample, key), 100)

    gains = [(f"{a} − {b}", metrics.paired_bootstrap(items, ndcg100(a), ndcg100(b), config.BOOTSTRAP, config.SEED, lambda i: bool(i["grade"])))
             for a, b in zip(ladder.LEVELS[1:], ladder.LEVELS[:-1])]
    gains += [(f"L4 − {b}", metrics.paired_bootstrap(items, ndcg100("L4"), ndcg100(b), config.BOOTSTRAP, config.SEED, lambda i: bool(i["grade"])))
              for b in ("EPSS@T0", "SSVC@T0", "WazuhVD")]

    from .run import _ci, _f
    L = ["# Evaluation, Part A3: forward-in-time KEV test on the Wazuh inventory", ""]
    if under:
        L += [f"> **Underpowered.** Only {len(pos_cves)} distinct CVE(s) on the lab's inventory were added to KEV after "
              f"T0 = {t0} (fewer than {MIN_POSITIVE_CVES}). The table shows that the test runs; its numbers are not "
              "evidence for or against any score. Positives that sit on several hosts count once per host.", ""]
    L += [f"Generated {date.today().isoformat()} by `python -m eval_kg kev-forward --t0 {t0}`. Method: "
          "`eval_kg/kev_forward.py`. Inventory: Wazuh vulnerability detection snapshot "
          f"{wazuh_pairs.snapshot_date()} ∪ the graph's links. β = {beta:g}, γ = {gamma:g}. "
          f"EPSS {epss_meta.get('model_version', '-')} scored {epss_meta.get('score_date', t0)}. Ties broken by item id.", "",
          f"**Items:** {len(items)} (asset, CVE) pairs on {len({i['asset'] for i in items})} assets; "
          f"**positives:** {len(pos)} pairs, {len(pos_cves)} distinct CVEs added to KEV after T0 "
          f"({', '.join(f'{c} ({next(i for i in pos if i['cve'] == c)['kev_date_added']}, '
                        f'{sum(i['cve'] == c for i in pos)} hosts)' for c in pos_cves) or 'none'}).", "",
          "Excluded from the frame: " + ", ".join(f"{k} {v}" for k, v in excluded.items()) + ".", "",
          "E uses KEV as of T0 only and drops SSVC exploitation (no assessment date), so **L3 = L2** in this test. "
          "Pairs that are not a network service of the host keep their base AV in L2.", "",
          "| Score | NDCG@10 | NDCG@100 | P@10 | P@100 | MRR | Rank of first positive | Mean rank of positives |",
          "|---|---:|---:|---:|---:|---:|---:|---:|"]
    for k, m in rows.items():
        L.append(f"| {k} | {_f(m['NDCG@10'])} | {_f(m['NDCG@100'])} | {_f(m['P@10'])} | {_f(m['P@100'])} | "
                 f"{_f(m['MRR'])} | {m['first'] or '-'} | {_f(m['mean_rank'], 1)} |")
    L += ["", "Gain in NDCG@100 with a 95% paired-bootstrap CI over items (* = CI excludes 0):", "",
          "| Comparison | Δ NDCG@100 [95% CI] |", "|---|---|"]
    L += [f"| {name} | {_ci(b)} |" for name, b in gains]
    L += ["", "Positives and where each score ranks them:", "",
          "| Asset | CVE | KEV added | CVSS | " + " | ".join(KEYS) + " |", "|---|---|---|---:|" + "---:|" * len(KEYS)]
    ranks = {k: {i["id"]: r for r, i in enumerate(sorted(items, key=lambda i: (-i[k], i["id"])), 1)} for k in KEYS}
    for i in sorted(pos, key=lambda i: i["id"]):
        L.append(f"| {i['asset']} | {i['cve']} | {i['kev_date_added']} | {i['L0']:.1f} | "
                 + " | ".join(str(ranks[k][i["id"]]) for k in KEYS) + " |")
    L.append("")

    config.REPORTS.mkdir(parents=True, exist_ok=True)
    config.KEV_FORWARD_REPORT.write_text("\n".join(L), encoding="utf-8")
    payload = {"generated": date.today().isoformat(), "t0": t0, "n_items": len(items), "n_positive": len(pos),
               "positive_cves": pos_cves, "underpowered": under, "excluded": excluded, "scores": rows,
               "gains": {n: b for n, b in gains}}
    config.KEV_FORWARD_REPORT.with_suffix(".json").write_text(json.dumps(payload, indent=1), encoding="utf-8")
    print(f"kev-forward: T0 {t0}, {len(items)} items, {len(pos)} positive pairs ({len(pos_cves)} CVEs)"
          f"{' UNDERPOWERED' if under else ''} -> {config.KEV_FORWARD_REPORT}")
    return payload
