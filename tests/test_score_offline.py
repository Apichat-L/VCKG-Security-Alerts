"""Offline tests for the Environmental Vulnerability Score (paper §III.A.2-3). No Neo4j, no network."""
from score_kg import cvss31, model, ssvc
from score_kg.epss import parse
from score_kg.run import kendall_tau, vulnerability_instances

FULL = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
AVAIL = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"


# --- Table I ---------------------------------------------------------------------------------------
def test_mav_keeps_base_av_with_an_internet_path_and_lowers_n_to_a_without():
    assert cvss31.modified_av(FULL, internet_path=True) == "N"
    assert cvss31.modified_av(FULL, internet_path=False) == "A"
    for av in "ALP":                                     # only AV:N is lowered
        vec = FULL.replace("AV:N", f"AV:{av}")
        assert cvss31.modified_av(vec, internet_path=False) == av


def test_exploit_maturity_alert_first_then_threat_intelligence():
    e = lambda *args: cvss31.exploit_maturity(*args)[0]
    assert e(True, False, "none") == "H"          # an alert in this environment wins
    assert e(False, True, "none") == "H"          # KEV
    assert e(False, False, "active") == "H"
    assert e(False, False, " PoC ") == "P"        # normalised
    assert e(False, False, "none") == "U"
    assert e(False, False, None) == "X"
    assert "KEV" in cvss31.exploit_maturity(True, True, None)[1]


def test_environmental_scores_match_the_specification():
    assert cvss31.environmental(FULL, "X", "M", "M", "M", "N")["environmental"] == 9.8
    assert cvss31.environmental(FULL, "H", "M", "M", "M", "N")["environmental"] == 9.8      # E:H = 1.0
    assert cvss31.environmental(FULL, "X", "L", "L", "L", "A")["environmental"] == 6.9      # hand-checked
    assert cvss31.environmental(FULL, "X", "H", "H", "H", "A")["environmental"] == 8.8


# --- Eqs. 14-17 --------------------------------------------------------------------------------------
def test_crit():
    assert model.crit("H", "L", "L") == 1.0
    assert model.crit("M", "M", "L") == 0.5
    assert model.crit("L", "L", "L") == 0.0


# toy network: a -> b -> c, a -> d ; d is in a zone a may not reach
ZONE = {"a": "Z1", "b": "Z1", "c": "Z2", "d": "Z3"}
CONNECTS = [("a", "b"), ("b", "c"), ("a", "d")]
ALLOWED = {("Z1", "Z2")}


def test_reachability_edges_respect_the_zone_policy():
    assert model.reachability_edges(CONNECTS, ZONE, ALLOWED) == {("a", "b"), ("b", "c")}


def test_propagation_is_noisy_or_over_the_blast_radius():
    edges = model.reachability_edges(CONNECTS, ZONE, ALLOWED)
    crit = {"a": 1.0, "b": 0.5, "c": 1.0, "d": 1.0}
    # Eq. 16, k = 1: from a only b (0.5 * 0.5) is in BR_1; k = 2 adds c at 2 hops (1 * 0.25); d is never reachable
    assert model.propagation(edges, "a", crit, 0.5) == 0.25
    assert model.propagation(edges, "a", crit, 0.5, k=2) == 1 - (1 - 0.25) * (1 - 0.25)
    assert model.propagation(edges, "c", crit, 0.5) == 0.0                       # c reaches nothing
    assert model.propagation(edges, "c", crit, 0.5, "disruption") == 0.25        # b depends on c


# --- metamorphic properties of Eq. 16 (A0 rung of the evaluation) ----------------------------------------
def _edges(pairs):
    return set(pairs)


def test_p_is_zero_for_an_isolated_asset_and_bounded():
    crit = {"a": 1.0, "b": 1.0, "c": 1.0}
    assert model.propagation(set(), "a", crit, 0.5) == 0.0
    star = _edges([("a", "b"), ("a", "c")])
    assert 0.0 <= model.propagation(star, "a", crit, 0.9, k=3) < 1.0


def test_p_never_falls_when_a_critical_neighbour_is_added_or_a_neighbour_gets_more_critical():
    crit = {"a": 1.0, "b": 0.5, "c": 0.0}
    base = _edges([("a", "b")])
    p0 = model.propagation(base, "a", crit, 0.5)
    assert model.propagation(base | {("a", "c")}, "a", crit, 0.5) >= p0
    assert model.propagation(base, "a", {**crit, "b": 1.0}, 0.5) >= p0
    assert model.propagation(base, "a", {**crit, "b": 0.0}, 0.5) <= p0


def test_p_never_rises_when_an_edge_is_removed_or_the_firewall_tightens():
    zone = {"a": "Z1", "b": "Z2", "c": "Z2"}
    crit = {"a": 1.0, "b": 1.0, "c": 1.0}
    connects = [("a", "b"), ("a", "c")]
    open_ = model.reachability_edges(connects, zone, {("Z1", "Z2")})
    closed = model.reachability_edges(connects, zone, set())
    assert model.propagation(closed, "a", crit, 0.5) <= model.propagation(open_, "a", crit, 0.5)
    assert model.propagation(open_ - {("a", "c")}, "a", crit, 0.5) <= model.propagation(open_, "a", crit, 0.5)


def test_disruption_equals_compromise_on_the_reversed_graph_and_depth_nests():
    edges = _edges([("a", "b"), ("b", "c"), ("d", "b")])
    rev = {(v, u) for u, v in edges}
    crit = {"a": 1.0, "b": 0.5, "c": 1.0, "d": 0.5}
    for h in crit:
        assert model.propagation(edges, h, crit, 0.5, "disruption", 2) == model.propagation(rev, h, crit, 0.5, "compromise", 2)
        assert set(model.blast_radius(edges, h, "compromise", 1)) <= set(model.blast_radius(edges, h, "compromise", 2))
        assert model.propagation(edges, h, crit, 0.5, k=1) <= model.propagation(edges, h, crit, 0.5, k=2)


def test_evs_formula_cap_and_rounding():
    assert model.evs(7.0, 0.0, 0.5) == 7.0                    # no propagation: Env
    assert model.evs(7.0, 0.2, 0.5) == 7.7                    # 7.0 * 1.1
    assert model.evs(7.1, 0.123, 0.5) == 7.6                  # 7.1 * 1.0615 = 7.5367 -> rounded up
    assert model.evs(9.8, 1.0, 0.5) == 10.0                   # capped
    assert model.roundup(4.02) == 4.1 and model.roundup(4.0) == 4.0


def test_levels():
    assert [cvss31.band(s) for s in (0.0, 0.1, 3.9, 4.0, 6.9, 7.0, 8.9, 9.0, 10.0)] == \
        ["None", "Low", "Low", "Medium", "Medium", "High", "High", "Critical", "Critical"]


# --- blast radius (Eqs. 7-9, Algorithm 1) ---------------------------------------------------------------
def test_impact_mode():
    assert model.impact_mode(FULL) == "compromise"
    assert model.impact_mode(AVAIL) == "disruption"


def test_blast_radius_direction_and_depth():
    edges = model.reachability_edges(CONNECTS, ZONE, ALLOWED)
    assert model.blast_radius(edges, "b", "compromise", 1) == {"b": 0, "c": 1}     # what b can reach
    assert model.blast_radius(edges, "b", "disruption", 1) == {"b": 0, "a": 1}     # who depends on b
    assert model.blast_radius(edges, "a", "compromise", 2) == {"a": 0, "b": 1, "c": 2}
    assert model.blast_radius(edges, "a", "compromise", 0) == {"a": 0}


def test_score_keeps_every_intermediate_value():
    asset = {"hostname": "x", "cr": "H", "ir": "H", "ar": "M"}
    row = model.score(asset, {"cve": "CVE-2024-0001", "cvss3_vector": FULL}, internet_path=False, p=0.2,
                      beta=0.5, alerted=True)
    assert row["MAV"] == "A" and row["E"] == "H" and row["impact_mode"] == "compromise"
    assert row["evs"] == model.evs(row["env"], 0.2, 0.5)
    quiet = model.score(asset, {"cve": "CVE-2024-0002", "cvss3_vector": FULL, "kev": False,
                                "ssvc_exploitation": "none"}, internet_path=True, p=0.0, beta=0.5)
    assert quiet["E"] == "U" and quiet["env"] < quiet["cvss_base"]   # no alert, no exploitation: demoted


# --- alerts become vulnerability instances (a, c) ---------------------------------------------------------
def test_only_alerts_that_report_a_cve_are_instances():
    ctx = lambda aid, cves, rule="1": {"target": {"hostname": "Jenkins"},
                                       "alert": {"alert_id": aid, "rule_id": rule, "cves": cves}}
    instances, unscored = vulnerability_instances(
        [ctx("1", ["CVE-2024-23897"]), ctx("2", ["CVE-2024-23897"]), ctx("3", [], "5")])
    assert list(instances) == [("Jenkins", "CVE-2024-23897", "1")] and len(instances[("Jenkins", "CVE-2024-23897", "1")]) == 2
    assert list(unscored) == [("Jenkins", "5")]


# --- baselines kept next to the EVS -----------------------------------------------------------------------
def test_ssvc_baseline():
    assert ssvc.outcome("active", "yes", "total", False, FULL, "essential") == "Act"
    assert ssvc.outcome("none", "no", "partial", True, FULL, "essential") == "Attend"   # KEV -> active


def test_epss_csv_parsing():
    meta, scores = parse(["#model_version:v2026.06.15,score_date:2026-11-09T12:00:23Z\n",
                          "cve,epss,percentile\n", "CVE-2024-23897,0.99999,0.99995\n"])
    assert meta["model_version"] == "v2026.06.15" and scores["CVE-2024-23897"] == (0.99999, 0.99995)


def test_kendall_tau():
    assert kendall_tau([1, 2, 3], [1, 2, 3]) == 1.0
    assert kendall_tau([1, 2, 3], [3, 2, 1]) == -1.0
