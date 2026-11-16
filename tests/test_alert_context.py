"""Alert -> graph mapping and alert context. Needs Neo4j with the CTI graph and the lab asset graph.

Loads tests/fixtures/wazuh_alerts.jsonl as Alert nodes (ids start with "test-") and removes them after.
"""
from pathlib import Path

import pytest

from alert_kg.context import build_context
from alert_kg.extract import normalize, read_jsonl
from alert_kg.load import load_records, revoked_techniques
from asset_kg.db import driver

FIX = Path(__file__).parent / "fixtures" / "wazuh_alerts.jsonl"


@pytest.fixture(scope="module")
def session():
    try:
        drv = driver(wait=5)
    except SystemExit:
        pytest.skip("Neo4j is not reachable")
    with drv.session() as s:
        if not s.run("MATCH (a:Asset {hostname: 'Admin-PC'}) RETURN count(a) AS n").single()["n"]:
            pytest.skip("lab asset graph not loaded (python -m asset_kg all)")
        revoked = revoked_techniques()
        load_records(s, [normalize(h, revoked=revoked) for h in read_jsonl(FIX)])
        yield s
        s.run("MATCH (al:Alert) WHERE al.alert_id STARTS WITH 'test-' DETACH DELETE al").consume()
    drv.close()


def path_text(path):
    return " > ".join(h.get("node") or h.get("service") for h in path)


def test_internal_alert_source_target_and_path(session):
    ctx = build_context(session, "test-sshd-internal")
    assert ctx["target"]["hostname"] == "Admin-PC" and ctx["target"]["zone"] == "Office"
    assert ctx["source"] == {"kind": "asset", "name": "Dep-PC", "ip": "10.10.40.42"}
    assert ctx["attack_paths"][0] and path_text(ctx["attack_paths"][0]) == "Dep-PC > Admin-PC:22/tcp > Admin-PC"
    assert all(t["applies_to_target"] for t in ctx["techniques"])
    blast = {b["asset"]: b["hops"] for b in ctx["blast_radius"]}
    # Office reaches Office, DATA and MGMT directly; through the MGMT bastion it reaches DMZ and APP in a second hop
    assert {h for h, n in blast.items() if n == 1} == {"Dep-PC", "Dev-PC", "Files-SMB", "PostgreSQL", "HR-DB", "Redis",
                                                       "Jump", "Monitoring"}
    assert {h for h, n in blast.items() if n == 2} == {"Nginx", "Web", "DNS", "Mail", "API", "Jenkins", "HR-App", "Gitea"}


def test_external_alert_paths_start_at_the_internet(session):
    ctx = build_context(session, "test-web-external")
    assert ctx["source"]["kind"] == "external" and ctx["source"]["name"] == "Internet"
    assert ctx["target"]["internet_exposed"] is True
    assert "Internet > Web:80/tcp > Web" in [path_text(p) for p in ctx["attack_paths"]]
    blast = {b["asset"]: b["hops"] for b in ctx["blast_radius"]}
    assert blast["API"] == 1 and blast["PostgreSQL"] == 2


def test_cve_alert_flags_the_named_kev_vulnerability(session):
    ctx = build_context(session, "test-vuln-jenkins")
    related = ctx["vulnerabilities"]["related_to_alert"]
    assert related[0]["cve"] == "CVE-2024-23897" and related[0]["named_in_alert"] and related[0]["kev"]
    assert ctx["source"]["kind"] == "unknown"
    # no source: paths are computed from the Internet; Jenkins is only reachable through the DMZ
    assert ctx["attack_paths"] and all(path_text(p).startswith("Internet > ") for p in ctx["attack_paths"])
    assert all(len(p) == 5 for p in ctx["attack_paths"])      # Internet > svc > DMZ host > Jenkins:8080 > Jenkins


def test_revoked_wazuh_technique_reaches_the_graph(session):
    ctx = build_context(session, "test-agent-stopped")
    assert [t["id"] for t in ctx["techniques"]] == ["T1685"]
    assert ctx["alert"]["techniques_original"] == ["T1562.001"]


def test_sensor_alert_targets_the_destination_asset(session):
    ctx = build_context(session, "test-suricata-jenkins")
    assert ctx["target"]["hostname"] == "Jenkins"            # agent `ids` is not an asset: dest_ip decides
    assert ctx["source"]["name"] == "Web"
    assert ctx["vulnerabilities"]["related_to_alert"][0]["cve"] == "CVE-2024-23897"
