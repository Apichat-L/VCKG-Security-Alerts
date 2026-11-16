"""Checks on the loaded asset graph. Needs Neo4j running with the asset graph already loaded.

    python -m pytest tests/test_asset_kg.py -v
"""
import pytest

from asset_kg.checks import run
from asset_kg.db import driver
from asset_kg.schema import LEVELS


@pytest.fixture(scope="module")
def session():
    try:
        drv = driver(wait=5)
    except SystemExit:
        pytest.skip("Neo4j is not reachable")
    with drv.session() as s:
        yield s
    drv.close()


def test_assets_exist_and_have_valid_requirements(session):
    rows = session.run("MATCH (a:Asset) RETURN a.cr AS cr, a.ir AS ir, a.ar AS ar").data()
    assert rows, "no Asset nodes: run `python -m asset_kg load` first"
    for r in rows:
        assert {r["cr"], r["ir"], r["ar"]} <= LEVELS


def test_structural_checks_pass(session):     # `session` skips the test when Neo4j is down
    assert run(wait=5)


# The tests below assume the lab in lab/*.csv (= lab_env/) and its firewall rules.

def reachable(session, src: str) -> set[str]:
    return {r["svc"] for r in session.run(
        "MATCH (s)-[:CAN_REACH]->(svc:Service) WHERE s.hostname = $n OR s.name = $n RETURN svc.id AS svc", n=src)}


def test_every_asset_runs_on_linux(session):
    rows = session.run("MATCH (a:Asset) OPTIONAL MATCH (a)-[:RUNS_ON]->(p:Platform) "
                       "RETURN a.hostname AS host, collect(p.name) AS platforms").data()
    assert rows and all(r["platforms"] == ["Linux"] for r in rows), rows


def test_platform_link_reaches_attack_techniques(session):
    n = session.run("MATCH (:Asset {hostname: 'Jenkins'})-[:RUNS_ON]->(:Platform)<-[:AFFECTS]-(t:Technique) "
                    "RETURN count(DISTINCT t) AS n").single()["n"]
    assert n > 0


def test_internet_reaches_only_the_dmz(session):
    assert reachable(session, "Internet") == {"Nginx:80/tcp", "Nginx:443/tcp", "Web:80/tcp", "DNS:53/udp", "DNS:53/tcp",
                                              "Mail:25/tcp", "Mail:143/tcp"}
    exposed = {r["h"] for r in session.run("MATCH (a:Asset {internet_exposed: true}) RETURN a.hostname AS h")}
    assert exposed == {"Nginx", "Web", "DNS", "Mail"}


def test_firewall_rules_are_reflected(session):
    dep = reachable(session, "Dep-PC")
    assert "PostgreSQL:5432/tcp" in dep           # Office -> DATA allowed
    assert "Jenkins:8080/tcp" not in dep          # Office -> APP blocked
    assert "API:3000/tcp" in reachable(session, "Web")             # DMZ -> APP allowed
    assert "Admin-PC:22/tcp" not in reachable(session, "Files-SMB")   # DATA -> Office blocked


def test_mgmt_zone_rules_are_reflected(session):
    assert "Jump:22/tcp" in reachable(session, "Dev-PC")             # Office -> MGMT allowed
    jump = reachable(session, "Jump")
    assert {"HR-DB:3306/tcp", "Jenkins:8080/tcp", "Nginx:443/tcp"} <= jump   # MGMT -> DATA, APP, DMZ allowed
    assert "Admin-PC:22/tcp" not in jump                              # MGMT -> Office blocked
    assert not {"Jump:22/tcp", "Monitoring:3000/tcp"} & reachable(session, "Internet")
    assert "Jump:22/tcp" not in reachable(session, "Jenkins")         # APP -> MGMT blocked


def test_same_zone_hosts_reach_each_other(session):
    via = session.run("MATCH (:Asset {hostname: 'Admin-PC'})-[e:CAN_REACH]->(:Service {id: 'Dep-PC:22/tcp'}) "
                      "RETURN e.via AS via").single()
    assert via and via["via"] == "same-zone"
