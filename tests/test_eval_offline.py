"""Offline tests for the evaluation package (stage 5): metrics, blast-radius variants, ladder, labels."""
import math
from types import SimpleNamespace

from eval_kg import ladder, labels, metrics, variants
from score_kg import cvss31, model

FULL = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


# --- metrics -----------------------------------------------------------------------------------------
def test_ndcg_precision_mrr_by_hand():
    rels = [0, 3, 2, 0]
    ideal = (2 ** 3 - 1) / math.log2(2) + (2 ** 2 - 1) / math.log2(3)
    got = (2 ** 3 - 1) / math.log2(3) + (2 ** 2 - 1) / math.log2(4)
    assert metrics.ndcg_at_k(rels, 3) == got / ideal
    assert metrics.ndcg_at_k([0, 0], 2) is None                      # nothing relevant: undefined
    assert metrics.precision_at_k(rels, 2, threshold=2) == 0.5
    assert metrics.first_hit(rels, 3) == 2 and metrics.first_hit([1, 1], 3) is None
    assert metrics.reciprocal_rank(rels, 2) == 0.5


def test_ranked_breaks_ties_by_id():
    items = [{"id": "b", "s": 5, "grade": 1}, {"id": "a", "s": 5, "grade": 0}, {"id": "c", "s": 9, "grade": 2}]
    assert metrics.ranked(items, "s") == [2, 0, 1]


def test_set_prf_conventions():
    assert metrics.set_prf({"a", "b"}, {"b", "c"}) == (0.5, 0.5, 0.5)
    assert metrics.set_prf(set(), {"a"}) == (1.0, 0.0, 0.0)         # B0: no false claims, nothing found
    assert metrics.set_prf(set(), set()) == (1.0, 1.0, 1.0)


def test_paired_bootstrap_is_deterministic_and_contains_the_observed_gain():
    units = list(range(20))
    a = lambda s: sum(1 for u in s if u % 2 == 0) / len(s) + 0.3
    b = lambda s: sum(1 for u in s if u % 2 == 0) / len(s)
    r1 = metrics.paired_bootstrap(units, a, b, 200, seed=1)
    r2 = metrics.paired_bootstrap(units, a, b, 200, seed=1)
    assert r1 == r2 and abs(r1["diff"] - 0.3) < 1e-9 and r1["lo"] <= 0.3 <= r1["hi"]


# --- blast-radius variants on the toy network of test_score_offline (a -> b -> c, a -> d) --------------
ZONE = {"a": "Z1", "b": "Z1", "c": "Z2", "d": "Z3"}
EDGES = model.reachability_edges([("a", "b"), ("b", "c"), ("a", "d")], ZONE, {("Z1", "Z2")})
G = SimpleNamespace(edges=EDGES, zone=ZONE, allowed={("Z1", "Z2")})


def test_variants_relations():
    assert variants.predict(G, "a", "compromise", "B0") == ({}, 0)
    b4 = set(variants.predict(G, "b", "compromise", "B4")[0])
    b3 = set(variants.predict(G, "b", "compromise", "B3")[0])
    assert b4 == {"c"} and b3 == {"a", "c"} and b3 >= b4               # undirected adds the dependant a
    assert set(variants.predict(G, "a", "compromise", "B5 (k=2)")[0]) >= set(variants.predict(G, "a", "compromise", "B4")[0])
    assert set(variants.predict(G, "a", "compromise", "B2")[0]) == {"b", "c"}   # same zone + allowed zone, no edges
    assert set(variants.predict(G, "c", "disruption", "B2")[0]) == {"a", "b"}   # inbound zones for disruption


def test_variant_propagation_matches_model():
    crit = {"a": 1.0, "b": 0.5, "c": 1.0, "d": 1.0}
    for mode in ("compromise", "disruption"):
        for h in ZONE:
            dist = variants.distances_for_p(G, h, "B4", mode)
            assert variants.propagation(dist, crit, 0.5) == model.propagation(EDGES, h, crit, 0.5, mode)
    assert variants.propagation({}, crit, 0.5) == 0.0


# --- ladder ------------------------------------------------------------------------------------------------
def test_ladder_steps_add_one_part_each():
    asset = {"cr": "L", "ir": "L", "ar": "L"}
    item = {"cve": "CVE-2024-0001", "cvss3_vector": FULL, "kev": False, "ssvc_exploitation": "none", "alerted": False}
    lv = ladder.levels(item, asset, internet_path=False, p=0.4, beta=0.5)
    assert lv["L0"] == 9.8
    assert lv["L1"] == cvss31.environmental(FULL, "X", "L", "L", "L", "N")["environmental"]
    assert lv["L2"] == cvss31.environmental(FULL, "X", "L", "L", "L", "A")["environmental"]
    assert lv["L3"] == cvss31.environmental(FULL, "U", "L", "L", "L", "A")["environmental"]
    assert lv["L4"] == model.evs(lv["L3"], 0.4, 0.5)


def test_baselines():
    asset = {"cr": "H", "ir": "H", "ar": "H"}
    item = {"cve": "CVE-2024-0001", "cvss3_vector": FULL, "kev": True, "ssvc_exploitation": "active",
            "ssvc_automatable": "yes", "ssvc_technical_impact": "total", "rule_level": 7}
    b = ladder.baselines(item, asset, {"CVE-2024-0001": (0.9, 0.99)})
    rnd = b.pop("Random")
    assert b == {"EPSS": 0.99, "KEV": 1.0, "SSVC": 3.0, "Wazuh": 7, "WazuhVD": 9.8, "wazuh_vd_fallback": True}
    assert 0.0 <= rnd <= 1.0 and rnd == ladder.baselines(item, asset, {})["Random"]   # reproducible


# --- labels ---------------------------------------------------------------------------------------------------
def test_grades_and_matching(tmp_path):
    (tmp_path / "s.yaml").write_text(
        "id: S\nsteps:\n"
        "  - {start: 2026-11-20T09:00:00Z, end: 2026-11-20T09:05:00Z, target: Jenkins, cve: CVE-2024-23897,\n"
        "     outcome: success, achieved: code_exec, pivot: true}\n"
        "  - {start: 2026-11-20T09:10:00Z, end: 2026-11-20T09:12:00Z, target: API, outcome: failed}\n",
        encoding="utf-8")
    (scenario,) = labels.load_scenarios(tmp_path)
    hit = {"asset": "Jenkins", "cve": "CVE-2024-23897", "first_seen": "2026-11-20T09:06:00Z", "last_seen": "2026-11-20T09:06:30Z"}
    wrong_cve = dict(hit, cve="CVE-2024-0001")
    api = {"asset": "API", "cve": "CVE-2024-22019", "first_seen": "2026-11-20T09:11:00Z", "last_seen": "2026-11-20T09:11:00Z"}
    assert labels.label_instance(hit, scenario, slack=120) == 3        # pivot -> 3, within slack
    assert labels.label_instance(wrong_cve, scenario, slack=120) == 0
    assert labels.label_instance(api, scenario, slack=0) == 1          # step without CVE matches any CVE
    assert labels.in_window(api, scenario, 0)


def test_pentest_results_skip_not_tried(tmp_path):
    f = tmp_path / "r.csv"
    f.write_text("# c\nasset,cve,exploited\nJenkins,cve-2024-23897,yes\nWeb,CVE-1,no\nAPI,CVE-2,not_tried\n", encoding="utf-8")
    assert labels.load_pentest_results(f) == {("Jenkins", "CVE-2024-23897"): 1, ("Web", "CVE-1"): 0}


# --- tie-aware metrics and the A4 helpers (docs/PLAN.md §9) --------------------------------------------
def _items(scores_grades):
    return [{"id": f"i{n}", "s": s, "grade": g} for n, (s, g) in enumerate(scores_grades)]


def test_tie_aware_ndcg_does_not_reward_the_id_order():
    # the positive is tied with two negatives: id order would put it first (NDCG 1), random order averages
    items = [{"id": "a", "s": 9.8, "grade": 1}, {"id": "b", "s": 9.8, "grade": 0}, {"id": "c", "s": 9.8, "grade": 0}]
    g = metrics.tie_groups(items, "s")
    exact = (1 + 1 / math.log2(3) + 1 / math.log2(4)) / 3
    assert metrics.ndcg_at_k(metrics.ranked(items, "s"), 10) == 1.0
    assert abs(metrics.expected_ndcg_at_k(g, 10) - exact) < 1e-12
    mc = metrics.expected(g, lambda r: metrics.ndcg_at_k(r, 10), 4000, 1)
    assert abs(mc - exact) < 0.02
    assert metrics.expected_ndcg_at_k(metrics.tie_groups(_items([(2, 1), (1, 0)]), "s"), 10) == 1.0


def test_expected_precision_and_average_precision():
    g = metrics.tie_groups(_items([(5, 1), (5, 0), (1, 1)]), "s")
    assert metrics.expected_precision_at_k(g, 1, 1) == 0.5
    assert metrics.expected_precision_at_k(g, 3, 1) == 2 / 3
    assert metrics.average_precision([1, 0, 1], 1) == (1 + 2 / 3) / 2
    assert metrics.average_precision([0, 0], 1) is None


def test_evs_ties_at_the_cap_are_ordered_by_the_uncapped_product():
    items = [{"id": "a", "L4": 10.0, "L4_raw": 11.2, "grade": 0}, {"id": "b", "L4": 10.0, "L4_raw": 12.5, "grade": 1},
             {"id": "c", "L4": 9.1, "L4_raw": 9.05, "grade": 0}]
    assert metrics.tie_groups(items, "L4") == [[1], [0], [0]]
    lv = ladder.levels({"cve": "C", "cvss3_vector": FULL, "kev": True, "alerted": True},
                       {"cr": "H", "ir": "H", "ar": "H"}, True, 0.75, 0.5)
    assert lv["L4"] == 10.0 and lv["L4_raw"] > 10.0


def test_pooled_prf_gives_no_free_credit_for_empty_sets():
    assert metrics.pooled_prf([(set(), set()), (set(), {"x"})]) == (None, 0.0, None)
    assert metrics.pooled_prf([({"a"}, {"a"}), ({"b"}, set())]) == (0.5, 1.0, 2 * 0.5 / 1.5)


def test_stratified_bootstrap_keeps_every_resample():
    units = [{"grade": 1}] + [{"grade": 0}] * 9
    ok = lambda s: 1.0 if any(u["grade"] for u in s) else None
    plain = metrics.paired_bootstrap(units, ok, lambda s: 0.0, 300, 3)
    strat = metrics.paired_bootstrap(units, ok, lambda s: 0.0, 300, 3, lambda u: u["grade"])
    assert plain["n"] < 300 and strat["n"] == 300


def test_pair_concordance_counts_ties_as_half():
    from eval_kg.run import _pair_concordance
    items = [{"L0": 5, "L4": 7, "grade": 2}, {"L0": 5, "L4": 4, "grade": 0}, {"L0": 5, "L4": 4, "grade": 1}]
    assert _pair_concordance(items, "L0") == (0.5, 0, 3, 0)
    assert _pair_concordance(items, "L4") == ((2 + 0.5) / 3, 2, 1, 0)
