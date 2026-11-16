"""CVSS v3.1 pieces of the EVS (paper Eqs. 10-13 and Table I).

The Environmental equation itself is computed by the `cvss` library (RedHat), which implements the
FIRST v3.1 specification including Roundup. This module only builds the environmental vector from the
graph-derived metrics of Table I:

    CR, IR, AR   attributes of the Asset node of u
    MAV          base AV if an ALLOWED_TO_REACH path connects the Internet zone to the zone of u;
                 otherwise AV:N is lowered to A (A, L, P are unchanged)
    E            exploit code maturity, first match wins (deliberately not the paper's alert-only rule,
                 see docs/scoring.md §5): an alert reports c on u -> H; c in CISA KEV or SSVC
                 exploitation 'active' -> H; 'poc' -> P; 'none' -> U; no data -> X
    RL, RC       Not Defined
"""
from cvss import CVSS3

BANDS = [(9.0, "Critical"), (7.0, "High"), (4.0, "Medium"), (0.1, "Low"), (0.0, "None")]


def band(score: float) -> str:
    """CVSS v3.1 qualitative rating (paper Eq. 18; 0 is None)."""
    for low, name in BANDS:
        if score >= low:
            return name
    return "None"


def metrics(vector: str) -> dict:
    return dict(part.split(":", 1) for part in vector.split("/")[1:])


def modified_av(base_vector: str, internet_path: bool) -> str:
    """Table I: MAV = base AV if the Internet zone reaches the asset's zone, else AV:N lowered to A."""
    base_av = metrics(base_vector).get("AV", "N")
    return "A" if base_av == "N" and not internet_path else base_av


def exploit_maturity(alerted: bool, kev: bool = False, ssvc_exploitation: str | None = None) -> tuple[str, str]:
    """E and the reason for it.

    Local evidence first (an alert in this environment reports the CVE on this asset), then global threat
    intelligence: exploited in the wild (CISA KEV, or vulnrichment SSVC exploitation 'active') -> High,
    public proof of concept -> P, no known exploitation -> Unproven, nothing known -> Not Defined.
    """
    expl = (ssvc_exploitation or "").strip().lower()
    if alerted:
        return "H", "alert reports this CVE on this asset" + (" (also in KEV)" if kev else "")
    if kev:
        return "H", "in CISA KEV (exploited in the wild)"
    if expl == "active":
        return "H", "SSVC exploitation: active"
    if expl == "poc":
        return "P", "SSVC exploitation: public PoC"
    if expl == "none":
        return "U", "SSVC exploitation: none known"
    return "X", "no exploitation data"


def environmental(base_vector: str, e: str, cr: str, ir: str, ar: str, mav: str) -> dict:
    """Env(c, u): base vector + E/CR/IR/AR/MAV (RL, RC and the other modified metrics not defined)."""
    vector = f"{base_vector}/E:{e}/CR:{cr}/IR:{ir}/AR:{ar}/MAV:{mav}"
    base, _temporal, env = (float(s) for s in CVSS3(vector).scores())
    return {"vector": vector, "base": base, "environmental": env}
