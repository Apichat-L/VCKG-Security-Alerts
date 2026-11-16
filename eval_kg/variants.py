"""Part B: blast-radius variants. Each returns {affected asset: hops} for an alerted asset a (a itself excluded).

    B0  no blast radius
    B1  unrestricted: every Asset within k hops of a over any edge type of the unified graph (Neo4j)
    B2  zone-level: every host in a's zone or in a zone the policy connects (outbound for compromise,
        inbound for disruption), ignoring CONNECTS_TO
    B3  ours, undirected: CONNECTS_TO edges allowed by the zone policy, in either direction (no impact mode)
    B4  ours (paper Algorithm 1): E_R in the direction of the impact mode, k = 1
    B5  ours at k = 2 and k = 3
`distances_for_p` gives the set each variant would feed into P(a, c) (Eq. 16, noisy-OR over the blast radius):
the variant's own predicted set, so the "downstream" comparison really changes the EVS.
"""
from score_kg import model

VARIANTS = ["B0", "B1 (k=1)", "B1 (k=2)", "B2", "B3", "B4", "B5 (k=2)", "B5 (k=3)"]

Q_UNRESTRICTED = """
MATCH p = (a:Asset {hostname: $host})-[*1..%d]-(n)
WITH n, min(length(p)) AS d
RETURN labels(n)[0] AS label, n.hostname AS hostname, d
"""


def unrestricted(session, host: str, k: int) -> tuple[dict, int]:
    """B1: (assets with hops, number of non-asset nodes the same query returns)."""
    assets, other = {}, 0
    for r in session.run(Q_UNRESTRICTED % k, host=host):
        if r["label"] == "Asset" and r["hostname"] != host:
            assets[r["hostname"]] = r["d"]
        elif r["label"] != "Asset":
            other += 1
    return assets, other


def zone_level(g, host: str, mode: str) -> dict:
    z = g.zone[host]
    if mode == "compromise":
        zones = {z} | {b for a, b in g.allowed if a == z}
    else:
        zones = {z} | {a for a, b in g.allowed if b == z}
    return {h: 1 for h, zh in g.zone.items() if zh in zones and h != host}


def ours(g, host: str, mode: str, k: int | None) -> dict:
    return {h: d for h, d in model.blast_radius(g.edges, host, mode, k).items() if h != host}


def undirected(g, host: str, k: int | None) -> dict:
    both = g.edges | {(v, u) for u, v in g.edges}
    return {h: d for h, d in model.distances(both, host, k=k).items() if h != host}


def predict(g, host: str, mode: str, variant: str, session=None) -> tuple[dict, int]:
    """(affected assets with hops, extra non-asset nodes returned) for one variant."""
    if variant == "B0":
        return {}, 0
    if variant.startswith("B1"):
        return unrestricted(session, host, int(variant[-2]))
    if variant == "B2":
        return zone_level(g, host, mode), 0
    if variant == "B3":
        return undirected(g, host, 1), 0
    if variant == "B4":
        return ours(g, host, mode, 1), 0
    if variant.startswith("B5"):
        return ours(g, host, mode, int(variant[-2])), 0
    raise ValueError(variant)


def distances_for_p(g, host: str, variant: str, mode: str = "compromise", session=None) -> dict:
    """The blast radius (assets with hop distance) each variant would feed into P(a, c) for impact mode `mode`."""
    return predict(g, host, mode, variant, session)[0]


def propagation(dist: dict, crit: dict, gamma: float) -> float:
    """Eq. 16 on a given set: 1 - prod(1 - crit(v) * gamma^d)."""
    q = 1.0
    for v, d in dist.items():
        q *= 1 - crit[v] * gamma ** d
    return 1 - q
