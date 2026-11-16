"""Part A: the score ladder L0-L4 (each step adds one part of the EVS) and the external baselines.

    L0  CVSS v3.1 base score
    L1  + CR/IR/AR of the asset                (Environmental, E = X, MAV = base AV)
    L2  + MAV from Internet reachability       (Table I)
    L3  + E from alert / KEV / SSVC            (Eq. 14)        = Env(c, u)
    L4  + propagation P(a,c) over BR_1(a,c)    (Eqs. 16-17)    = EVS
    Baselines, not part of the score: EPSS percentile, KEV (0/1), CISA SSVC decision, Wazuh rule.level, and
    WazuhVD = the CVSS base score Wazuh's vulnerability detector shows for the pair (vulnerability.score.base;
    the CVE's CVSS base when Wazuh does not report the pair, flagged as wazuh_vd_fallback).
"""
import hashlib

from score_kg import cvss31, model, ssvc

LEVELS = ["L0", "L1", "L2", "L3", "L4"]
BASELINES = ["EPSS", "KEV", "SSVC", "Wazuh", "WazuhVD", "Random"]
SSVC_ORDER = {"Track": 0, "Track*": 1, "Attend": 2, "Act": 3}


def levels(item: dict, asset: dict, internet_path: bool, p: float, beta: float) -> dict:
    """item: cve, cvss3_vector, kev, ssvc_exploitation, alerted."""
    vec = item["cvss3_vector"]
    base_av = cvss31.metrics(vec).get("AV", "N")
    mav = cvss31.modified_av(vec, internet_path)
    e, _ = cvss31.exploit_maturity(item.get("alerted", False), bool(item.get("kev")), item.get("ssvc_exploitation"))
    cr, ir, ar = asset["cr"], asset["ir"], asset["ar"]
    l1 = cvss31.environmental(vec, "X", cr, ir, ar, base_av)
    l2 = cvss31.environmental(vec, "X", cr, ir, ar, mav)
    l3 = cvss31.environmental(vec, e, cr, ir, ar, mav)
    return {"L0": l1["base"], "L1": l1["environmental"], "L2": l2["environmental"], "L3": l3["environmental"],
            "L4": model.evs(l3["environmental"], p, beta),
            "L4_raw": model.evs_uncapped(l3["environmental"], p, beta)}   # orders EVS ties at the cap of 10


def baselines(item: dict, asset: dict, epss: dict) -> dict:
    mission = ssvc.mission_prevalence(asset["cr"], asset["ir"], asset["ar"])
    decision = ssvc.outcome(item.get("ssvc_exploitation"), item.get("ssvc_automatable"),
                            item.get("ssvc_technical_impact"), bool(item.get("kev")), item["cvss3_vector"], mission)
    e = epss.get(item["cve"])
    wazuh_vd = item.get("wazuh_score")
    return {"EPSS": e[1] if e else 0.0, "KEV": 1.0 if item.get("kev") else 0.0,
            "SSVC": float(SSVC_ORDER[decision]), "Wazuh": item.get("rule_level"),
            "WazuhVD": wazuh_vd if wazuh_vd is not None else cvss_base(item["cvss3_vector"]),
            "Random": random_score(item),
            "wazuh_vd_fallback": wazuh_vd is None}


def random_score(item: dict) -> float:
    """A fixed pseudo-random score per (asset, CVE[, rule]): the chance-level baseline, reproducible across runs."""
    key = f"{item.get('asset')}|{item.get('cve')}|{item.get('rule_id', '')}"
    return int(hashlib.sha256(key.encode()).hexdigest()[:8], 16) / 0xFFFFFFFF


def cvss_base(vec: str) -> float:
    av = cvss31.metrics(vec).get("AV", "N")
    return cvss31.environmental(vec, "X", "M", "M", "M", av)["base"]
