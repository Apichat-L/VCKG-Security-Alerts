"""Pentest sampling frame for Part A1 (docs/PLAN.md §8, docs/evaluation.md).

A1 rows used to be chosen by hand, which is a selection bias. The next targets are drawn instead from the
evaluation frame (wazuh_pairs.frame(): Wazuh pairs ∪ graph links, scorable CVEs only) by a stratified random
sample with a fixed seed:

  strata   zone × CVSS band (critical ≥ 9 / high ≥ 7 / medium-low) × public exploit available (KEV or SSVC poc/active)
  share    EVAL_SAMPLE_EXPLOIT_SHARE of the sample (default half) comes from exploit-available pairs, because a
           uniform draw from thousands of library CVEs would be almost all "cannot be exercised in the lab"
  weight   each drawn row records its inclusion probability n_h / N_h, so the report can say how it was drawn

Pairs already in pentest_results.csv are left out of the draw (they stay labelled, as hand-picked).

    python -m eval_kg sample [--n 20]      -> evaluation/pentest_candidates.csv
"""
import csv
import random
from collections import defaultdict

from asset_kg.loader import read_csv

from . import config, labels, wazuh_pairs

COLUMNS = ["asset", "cve", "exploited", "notes", "stratum", "inclusion_prob", "source", "service", "software",
           "packages", "cvss3_score", "exploit_available", "kev", "ssvc_exploitation"]


def band(score) -> str:
    s = float(score or 0)
    return "critical" if s >= 9 else "high" if s >= 7 else "medium-low"


def stratum(item: dict, zone: dict) -> tuple:
    return (zone[item["asset"]], band(item["cvss3_score"]), "exploit" if wazuh_pairs.exploit_available(item) else "no-exploit")


def allocate(sizes: dict, n: int) -> dict:
    """Proportional allocation of n over strata (largest remainder), never more than a stratum holds."""
    total = sum(sizes.values())
    n = min(n, total)
    if not n:
        return {k: 0 for k in sizes}
    exact = {k: n * v / total for k, v in sizes.items()}
    alloc = {k: int(x) for k, x in exact.items()}
    for k in sorted(sizes, key=lambda k: (-(exact[k] - alloc[k]), k)):
        if sum(alloc.values()) >= n:
            break
        if alloc[k] < sizes[k]:
            alloc[k] += 1
    return alloc


def draw(items: list[dict], zone: dict, n: int, exploit_share: float, seed: int) -> list[dict]:
    """Stratified sample; returns the drawn items with 'stratum' and 'inclusion_prob' added."""
    strata: dict = defaultdict(list)
    for i in items:
        strata[stratum(i, zone)].append(i)
    for k in strata:
        strata[k].sort(key=lambda i: i["id"])
    sizes = {k: len(v) for k, v in strata.items()}
    pool = {g: {k: s for k, s in sizes.items() if k[2] == g} for g in ("exploit", "no-exploit")}
    n_e = min(round(n * exploit_share), sum(pool["exploit"].values()))
    n_o = min(n - n_e, sum(pool["no-exploit"].values()))
    n_e = min(n - n_o, sum(pool["exploit"].values()))          # top up from the other group if one runs short
    alloc = {**allocate(pool["exploit"], n_e), **allocate(pool["no-exploit"], n_o)}
    rng = random.Random(seed)
    out = []
    for k in sorted(strata):
        if not alloc.get(k):
            continue
        for i in rng.sample(strata[k], alloc[k]):
            out.append({**i, "stratum": "/".join(k), "inclusion_prob": alloc[k] / sizes[k]})
    return sorted(out, key=lambda i: i["id"])


def run(n: int = config.SAMPLE_SIZE, seed: int = config.SEED, exploit_share: float = config.SAMPLE_EXPLOIT_SHARE,
        wait: int = 60) -> list[dict]:
    wazuh = wazuh_pairs.load()
    if not wazuh:
        raise SystemExit(f"{config.WAZUH_PAIRS} not found: run `python -m eval_kg wazuh-pairs` first")
    zone = {r["hostname"]: r["zone"] for r in read_csv("assets.csv")}
    labelled = labels.load_pentest_results(config.PENTEST_RESULTS)
    items = [i for i in wazuh_pairs.frame(wait, wazuh) if i["cvss3_vector"] and (i["asset"], i["cve"]) not in labelled]
    picked = draw(items, zone, n, exploit_share, seed)

    with open(config.PENTEST_CANDIDATES, "w", newline="", encoding="utf-8") as fh:
        fh.write(f"# Pentest candidates for Part A1, drawn by `python -m eval_kg sample --n {n}` (seed {seed}, "
                 f"exploit share {exploit_share:g}) from {len(items)} unlabelled scorable (asset, CVE) pairs.\n"
                 f"# Frame: Wazuh vulnerability detection snapshot {wazuh_pairs.snapshot_date()} ∪ the graph's links. "
                 "Protocol: evaluation/README.md, 'Sampled targets'.\n"
                 "# Copy a row into pentest_results.csv once tried (exploited yes/no with evidence), or leave it "
                 "here as not_tried. Do not replace a drawn row by a hand-picked one.\n")
        w = csv.DictWriter(fh, fieldnames=COLUMNS, extrasaction="ignore")
        w.writeheader()
        for i in picked:
            w.writerow({**i, "exploited": "not_tried", "notes": "", "inclusion_prob": f"{i['inclusion_prob']:.4f}",
                        "exploit_available": wazuh_pairs.exploit_available(i)})

    print(f"sample: {len(picked)} of {len(items)} unlabelled scorable pairs ({len(labelled)} already labelled, "
          f"left out) -> {config.PENTEST_CANDIDATES}")
    counts: dict = defaultdict(int)
    for i in picked:
        counts[i["stratum"]] += 1
    for k in sorted(counts):
        print(f"  {k:<40} {counts[k]}")
    print(f"  network-service pairs: {sum(i['service'] for i in picked)} of {len(picked)}")
    return picked


def sampled_pairs() -> set:
    """(asset, CVE) pairs that came from the sampler, to tell sampled from hand-picked A1 rows."""
    if not config.PENTEST_CANDIDATES.exists():
        return set()
    with open(config.PENTEST_CANDIDATES, newline="", encoding="utf-8") as fh:
        rows = (ln for ln in fh if ln.strip() and not ln.startswith("#"))
        return {(r["asset"], r["cve"]) for r in csv.DictReader(rows)}
