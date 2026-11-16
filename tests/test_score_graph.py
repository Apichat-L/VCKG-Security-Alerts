"""EVS on the loaded lab graph (paper §III.A.2-3). Needs Neo4j with the CTI + asset graph; skips otherwise."""
import pytest

from score_kg import model


@pytest.fixture(scope="module")
def vckg():
    from score_kg import graph
    try:
        g = graph.load(wait=5)
    except SystemExit:
        pytest.skip("Neo4j is not reachable or the asset graph is not loaded")
    if not g.vulns:
        pytest.skip("asset graph not linked (python -m asset_kg all)")
    return g


def test_internet_path_follows_allowed_to_reach_transitively(vckg):
    # Internet -> DMZ -> APP -> DATA; Office and MGMT are never reached from the Internet zones
    assert vckg.internet_zones == {"DMZ", "APP", "DATA"}


def test_office_hosts_get_adjacent_mav_on_network_cves(vckg):
    from score_kg.run import score_vulns
    rows = score_vulns(vckg, 0.5, 0.5)
    for r in rows:
        if r["AV"] == "N":
            assert r["MAV"] == ("A" if vckg.zone[r["asset"]] in ("Office", "MGMT") else "N"), r


def test_propagation_of_nginx(vckg):
    # Nginx -> Web (1 hop) -> API (2) -> PostgreSQL (3), all crit 1, seventeen assets
    assert vckg.propagation("Nginx", 0.5) == pytest.approx((0.5 + 0.25 + 0.125) / 16)
    assert vckg.propagation("Dep-PC", 0.5) == 0.0


def test_blast_radius_direction(vckg):
    assert set(model.blast_radius(vckg.edges, "Nginx", "compromise", 1)) == {"Nginx", "Web"}
    assert set(model.blast_radius(vckg.edges, "API", "disruption", 1)) == {"API", "Web", "Jenkins"}
    assert set(model.blast_radius(vckg.edges, "Jenkins", "compromise", 1)) == {"Jenkins", "API", "Gitea"}
    assert set(model.blast_radius(vckg.edges, "Redis", "disruption", 1)) == {"Redis", "Gitea"}
    assert set(model.blast_radius(vckg.edges, "HR-DB", "disruption", 2)) == {"HR-DB", "HR-App", "Jump"}


def test_exploit_maturity_from_threat_intelligence_without_alerts(vckg):
    from score_kg.run import score_vulns
    rows = {(r["asset"], r["cve"]): r for r in score_vulns(vckg, 0.5, 0.5)}
    assert rows[("Jenkins", "CVE-2024-23897")]["E"] == "H"        # KEV, no alert needed
    assert any(r["E"] == "U" for r in rows.values())               # SSVC exploitation none
