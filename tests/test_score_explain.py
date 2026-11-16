"""Offline tests for `python -m score_kg explain` (docs/PLAN.md section 7). No Neo4j."""
import pytest

from score_kg import explain, model

FULL = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

# toy network: a -> b -> c, a -> d ; d is in a zone a may not reach
ZONE = {"a": "Z1", "b": "Z1", "c": "Z2", "d": "Z3"}
EDGES = model.reachability_edges([("a", "b"), ("b", "c"), ("a", "d")], ZONE, {("Z1", "Z2")})
CRIT = {"a": 1.0, "b": 0.5, "c": 1.0, "d": 1.0}


@pytest.mark.parametrize("asset", ["a", "b", "c", "d"])
def test_p_terms_combine_to_the_propagation(asset):
    for mode in ("compromise", "disruption"):
        q = 1.0
        for t in explain.p_terms(EDGES, asset, CRIT, 0.5, mode, 2):
            q *= 1 - t["term"]
        assert 1 - q == pytest.approx(model.propagation(EDGES, asset, CRIT, 0.5, mode, 2))


def test_p_terms_list_blast_radius_by_distance_without_the_asset_itself():
    assert [(t["asset"], t["hops"]) for t in explain.p_terms(EDGES, "a", CRIT, 0.5)] == [("b", 1)]
    terms = explain.p_terms(EDGES, "a", CRIT, 0.5, k=2)
    assert [(t["asset"], t["hops"]) for t in terms] == [("b", 1), ("c", 2)]
    assert explain.term_text(terms[1], 0.5) == "c: crit 1 × 0.5^2 = 0.2500"
    assert explain.p_terms(EDGES, "c", CRIT, 0.5) == []                 # c reaches nothing


def test_score_props_carry_every_intermediate_value_as_neo4j_types():
    asset = {"hostname": "a", "cr": "M", "ir": "H", "ar": "M"}
    p = model.propagation(EDGES, "a", CRIT, 0.5)
    row = model.score(asset, {"cve": "CVE-1", "cvss3_vector": FULL}, True, p, 0.5, alerted=True)
    blast = model.blast_radius(EDGES, "a", row["impact_mode"], 1)
    props = explain.score_props(row, "CVE-1@a", ["sw 1.0"], [], [], [], True,
                                explain.p_terms(EDGES, "a", CRIT, 0.5), blast, 0.5, 0.5, 1, 3)
    assert props["name"] == f"CVE-1 @ a: EVS {row['evs']} ({row['level']})"
    assert props["blast_radius"] == ["a (0 hops)", "b (1 hop)"]
    assert props["evs_formula"].endswith(f"= {row['evs']}")
    assert len(props["P_terms"]) == 1
    for v in props.values():          # Neo4j properties: primitives or lists of primitives
        assert isinstance(v, (str, int, float, bool)) or (isinstance(v, list) and all(isinstance(x, (str, int, float)) for x in v))
