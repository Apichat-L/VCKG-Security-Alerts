"""Evaluation metrics: graded ranking metrics, set overlap, and a paired bootstrap for differences.

Relevance grades (docs/evaluation.md): 3 successful step with data access or a pivot, 2 successful step,
1 attempted / failed step, 0 noise. "Relevant" for P@k is grade >= 2; the "first true attack-chain item"
is the first item with grade 3.

Ties (changed 2026-11-17, docs/PLAN.md §9). A score that gives several items the same value says nothing about
their order. `ranked` breaks ties by id only for display; every reported metric is the **expected value over
random orderings within tied groups**: exact for NDCG@k and P@k (each tied position gets the group's mean gain),
Monte Carlo (seeded) for MRR, AP and the first hit. Before, ties were broken by id, which credited a score with
whatever order the item names happened to give (e.g. "Jenkins|..." sorting before "Web|...").
"""
import math
import random


def dcg(rels: list[int]) -> float:
    return sum((2 ** r - 1) / math.log2(i + 2) for i, r in enumerate(rels))


def ndcg_at_k(ranked_rels: list[int], k: int) -> float | None:
    """NDCG@k with exponential gain; None when the list has no relevant item (undefined)."""
    ideal = dcg(sorted(ranked_rels, reverse=True)[:k])
    return None if ideal == 0 else dcg(ranked_rels[:k]) / ideal


def precision_at_k(ranked_rels: list[int], k: int, threshold: int = 2) -> float:
    top = ranked_rels[:k]
    return sum(r >= threshold for r in top) / k if top else 0.0


def first_hit(ranked_rels: list[int], threshold: int = 3) -> int | None:
    """1-based rank of the first item with grade >= threshold, None if there is none."""
    return next((i + 1 for i, r in enumerate(ranked_rels) if r >= threshold), None)


def reciprocal_rank(ranked_rels: list[int], threshold: int = 2) -> float:
    rank = first_hit(ranked_rels, threshold)
    return 1.0 / rank if rank else 0.0


def rank_key(item: dict, score_key: str) -> tuple:
    """What a score orders by: its value, then `<key>_raw` if present (the EVS before its cap of 10, so scores
    tied at 10 are ordered by the uncapped product; docs/scoring.md). A missing score ranks last."""
    v = item[score_key]
    return (v if v is not None else -1, item.get(f"{score_key}_raw") or 0)


def tie_groups(items: list[dict], score_key: str, rel_key: str = "grade") -> list[list[int]]:
    """Relevance grades grouped by equal score, highest score first (a missing score ranks last)."""
    order = sorted(items, key=lambda x: rank_key(x, score_key), reverse=True)
    groups, last = [], object()
    for x in order:
        s = rank_key(x, score_key)
        if not groups or s != last:
            groups.append([])
            last = s
        groups[-1].append(x[rel_key])
    return groups


def expected_ndcg_at_k(groups: list[list[int]], k: int) -> float | None:
    """E[NDCG@k] over random orders within tied groups (exact: each tied position gets the mean gain)."""
    rels = [r for g in groups for r in g]
    ideal = dcg(sorted(rels, reverse=True)[:k])
    if ideal == 0:
        return None
    got, pos = 0.0, 0
    for g in groups:
        mean_gain = sum(2 ** r - 1 for r in g) / len(g)
        for i in range(pos, min(pos + len(g), k)):
            got += mean_gain / math.log2(i + 2)
        pos += len(g)
        if pos >= k:
            break
    return got / ideal


def expected_precision_at_k(groups: list[list[int]], k: int, threshold: int = 2) -> float:
    hit, pos = 0.0, 0
    for g in groups:
        take = min(len(g), k - pos)
        if take <= 0:
            break
        hit += take * sum(r >= threshold for r in g) / len(g)
        pos += len(g)
    return hit / k if k else 0.0


def average_precision(ranked_rels: list[int], threshold: int = 1) -> float | None:
    """AP: mean precision at the rank of each relevant item; None when nothing is relevant."""
    hits, total = 0, 0.0
    for i, r in enumerate(ranked_rels, 1):
        if r >= threshold:
            hits += 1
            total += hits / i
    return total / hits if hits else None


def tie_shuffles(groups: list[list[int]], n: int = 200, seed: int = 7):
    """Yield n rankings with each tied group in random order (one ranking if there are no ties)."""
    if all(len(g) == 1 for g in groups):
        yield [g[0] for g in groups]
        return
    rng = random.Random(seed)
    for _ in range(n):
        out = []
        for g in groups:
            g = list(g)
            rng.shuffle(g)
            out += g
        yield out


def expected(groups: list[list[int]], fn, n: int = 200, seed: int = 7) -> float | None:
    """Monte Carlo E[fn(ranking)] over tie orders; None values (undefined) are skipped."""
    vals = [v for v in (fn(r) for r in tie_shuffles(groups, n, seed)) if v is not None]
    return sum(vals) / len(vals) if vals else None


def ranked(items: list[dict], score_key: str, rel_key: str = "grade") -> list[int]:
    """Relevance grades in the order of the score (highest first; ties broken by item id). Display only: the
    reported metrics use tie_groups / expected_* instead."""
    order = sorted(items, key=lambda x: (-(x[score_key] if x[score_key] is not None else -1), x["id"]))
    return [x[rel_key] for x in order]


def set_prf(predicted: set, observed: set) -> tuple[float, float, float]:
    """Precision, recall, F1. An empty prediction has precision 1 (it claims nothing false); an empty
    observed set has recall 1 (there is nothing to find)."""
    tp = len(predicted & observed)
    p = tp / len(predicted) if predicted else 1.0
    r = tp / len(observed) if observed else 1.0
    return p, r, (2 * p * r / (p + r) if p + r else 0.0)


def pooled_prf(pairs: list[tuple[set, set]]) -> tuple[float | None, float | None, float | None]:
    """Micro-averaged precision / recall / F1 over (predicted, observed) set pairs: counts are pooled, so a host
    with an empty prediction or an empty truth adds nothing (no free credit, unlike the per-host mean)."""
    tp = sum(len(p & o) for p, o in pairs)
    np_, no = sum(len(p) for p, _ in pairs), sum(len(o) for _, o in pairs)
    p = tp / np_ if np_ else None
    r = tp / no if no else None
    f = 2 * p * r / (p + r) if p and r else (0.0 if p is not None and r is not None else None)
    return p, r, f


def paired_bootstrap(units: list, metric_a, metric_b, n: int = 1000, seed: int = 7, strata=None) -> dict:
    """Mean difference metric_a - metric_b over the units, with a 95% percentile CI.

    metric_x(sample) receives a resampled list of units (with replacement) and returns a number or None;
    resamples where either is None are skipped. Both metrics see the same resample (paired).
    strata(unit) -> key: resample within each stratum (e.g. positives and negatives separately), so every
    resample keeps the observed number of positives and none is skipped for having no positive.
    """
    rng = random.Random(seed)
    observed_a, observed_b = metric_a(units), metric_b(units)
    if observed_a is None or observed_b is None or not units:
        return {"diff": None, "lo": None, "hi": None, "n": 0}
    groups: dict = {}
    for u in units:
        groups.setdefault(strata(u) if strata else 0, []).append(u)
    groups = list(groups.values())
    diffs = []
    for _ in range(n):
        sample = [g[rng.randrange(len(g))] for g in groups for _ in g]
        a, b = metric_a(sample), metric_b(sample)
        if a is not None and b is not None:
            diffs.append(a - b)
    diffs.sort()
    if not diffs:
        return {"diff": observed_a - observed_b, "lo": None, "hi": None, "n": 0}
    lo, hi = diffs[int(0.025 * (len(diffs) - 1))], diffs[int(0.975 * (len(diffs) - 1))]
    return {"diff": observed_a - observed_b, "lo": lo, "hi": hi, "n": len(diffs)}
