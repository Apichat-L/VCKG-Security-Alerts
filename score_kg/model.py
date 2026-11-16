"""Environmental Vulnerability Score (paper §III.A.2-3, Eqs. 5-17, Algorithm 1). Pure functions.

    G_R      Asset Reachability Graph: CONNECTS_TO edges (u, v) whose zones allow the flow (Eqs. 5-6)
    m(c)     impact mode: compromise if the CVSS C or I impact is not None, otherwise disruption
    BR_k     blast radius: BFS over G_R to depth k, out-edges for compromise, in-edges for disruption (Eqs. 7-9)
    Env      CVSS v3.1 Environmental score with graph-derived metrics (Eqs. 10-13, Table I; cvss31.py)
    crit(v)  max(CR, IR, AR) - 0.5 with weights H 1.5, M 1.0, L 0.5  ->  H 1, M 0.5, L 0 (Eq. 15)
    P(a,c)   1 - prod over v in BR_k(a,c) minus a of (1 - crit(v) * gamma^d_c(a,v))  (Eq. 16, noisy-OR over the
             blast radius: the chance that at least one critical asset in the affected zone is hit)
    EVS      min(10, Env * (1 + beta * P(a,c)))  (Eq. 17), level by the CVSS qualitative scale (Eq. 18)
"""
import math
from collections import deque

from . import cvss31

WEIGHT = {"H": 1.5, "M": 1.0, "L": 0.5}           # CVSS v3.1 security-requirement weights


def crit(cr: str, ir: str, ar: str) -> float:
    """Eq. 15: the asset's highest security requirement, normalised to [0, 1]."""
    return max(WEIGHT[cr], WEIGHT[ir], WEIGHT[ar]) - 0.5


def impact_mode(base_vector: str) -> str:
    """compromise if the vulnerability affects confidentiality or integrity, else disruption."""
    m = cvss31.metrics(base_vector)
    return "compromise" if m.get("C", "N") != "N" or m.get("I", "N") != "N" else "disruption"


def reachability_edges(connects: list[tuple[str, str]], zone: dict[str, str],
                       allowed: set[tuple[str, str]]) -> set[tuple[str, str]]:
    """E_R (Eqs. 5-6): CONNECTS_TO edges permitted by the network policy (same zone or zones allowed)."""
    return {(u, v) for u, v in connects
            if u != v and (zone[u] == zone[v] or (zone[u], zone[v]) in allowed)}


def _neighbours(edges: set[tuple[str, str]], reverse: bool = False) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for u, v in edges:
        a, b = (v, u) if reverse else (u, v)
        out.setdefault(a, set()).add(b)
    return out


def distances(edges: set[tuple[str, str]], start: str, reverse: bool = False, k: int | None = None) -> dict[str, int]:
    """Shortest hop distance from `start` over the edges (in-edges if reverse), optionally bounded at k."""
    nbr = _neighbours(edges, reverse)
    dist, frontier = {start: 0}, deque([start])
    while frontier:
        u = frontier.popleft()
        if k is not None and dist[u] >= k:
            continue
        for v in nbr.get(u, ()):
            if v not in dist:
                dist[v] = dist[u] + 1
                frontier.append(v)
    return dist


def blast_radius(edges: set[tuple[str, str]], asset: str, mode: str, k: int = 1) -> dict[str, int]:
    """Algorithm 1: BR_k(a, c) as {asset: hops}; the asset itself is included at 0."""
    return distances(edges, asset, reverse=(mode == "disruption"), k=k)


def propagation_terms(edges: set[tuple[str, str]], asset: str, crit_of: dict[str, float], gamma: float,
                      mode: str = "compromise", k: int = 1) -> list[dict]:
    """The factors of Eq. 16: each v in BR_k(a, c) other than a, with its discounted criticality crit(v) * gamma^d."""
    br = blast_radius(edges, asset, mode, k)
    return [{"asset": v, "hops": d, "crit": crit_of[v], "term": crit_of[v] * gamma ** d}
            for v, d in sorted(br.items(), key=lambda x: (x[1], x[0])) if v != asset]


def propagation(edges: set[tuple[str, str]], asset: str, crit_of: dict[str, float], gamma: float,
                mode: str = "compromise", k: int = 1) -> float:
    """Eq. 16: noisy-OR of the discounted criticality of the assets in the blast radius BR_k(a, c).

    P = 1 - prod(1 - crit(v) * gamma^d). In [0, 1): 0 when nothing critical is affected, rising with each further
    critical asset with diminishing returns; independent of the network size and direction-aware through m(c)."""
    q = 1.0
    for t in propagation_terms(edges, asset, crit_of, gamma, mode, k):
        q *= 1 - t["term"]
    return 1 - q


def roundup(x: float) -> float:
    """Smallest one-decimal number >= x (CVSS v3.1 Roundup, integer form to avoid float error)."""
    i = round(x * 100000)
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0


def evs_uncapped(env: float, p: float, beta: float) -> float:
    """Env * (1 + beta * P) before the cap of Eq. 17. Used only to order scores tied at 10 (the reported EVS stays
    capped): within the Critical band, the instance with the larger uncapped product ranks first."""
    return env * (1 + beta * p)


def evs(env: float, p: float, beta: float) -> float:
    """Eq. 17 (rounded up to one decimal, like every CVSS score)."""
    return min(10.0, roundup(env * (1 + beta * p)))


def score(asset: dict, vuln: dict, internet_path: bool, p: float, beta: float, alerted: bool = False) -> dict:
    """EVS(c, u) with every intermediate value, so a report can show how it was reached.

    asset: hostname, cr, ir, ar     vuln: cve, cvss3_vector
    """
    mav = cvss31.modified_av(vuln["cvss3_vector"], internet_path)
    e, e_reason = cvss31.exploit_maturity(alerted, bool(vuln.get("kev")), vuln.get("ssvc_exploitation"))
    env = cvss31.environmental(vuln["cvss3_vector"], e, asset["cr"], asset["ir"], asset["ar"], mav)
    value = evs(env["environmental"], p, beta)
    return {
        "asset": asset["hostname"], "cve": vuln["cve"],
        "cvss_base": env["base"], "base_band": cvss31.band(env["base"]),
        "AV": cvss31.metrics(vuln["cvss3_vector"]).get("AV"), "MAV": mav, "E": e, "E_reason": e_reason,
        "CR": asset["cr"], "IR": asset["ir"], "AR": asset["ar"], "internet_path": internet_path,
        "env_vector": env["vector"], "env": env["environmental"], "P": round(p, 4),
        "evs": value, "evs_raw": round(evs_uncapped(env["environmental"], p, beta), 4),
        "level": cvss31.band(value), "impact_mode": impact_mode(vuln["cvss3_vector"]),
    }
