"""Offline tests for the Wazuh-based evaluation parts (docs/PLAN.md §8): pair export, frame, sampler, KEV split."""
import re

from eval_kg import kev_forward, ladder, sample, wazuh_pairs

FULL = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


def doc(agent, pkg, cve, score=None, sev=None, version="1.0", at="2026-11-16T00:00:00Z"):
    return {"agent": {"name": agent}, "package": {"name": pkg, "version": version},
            "vulnerability": {"id": cve, "score": {"base": score} if score is not None else {}, "severity": sev,
                              "detected_at": at}}


def test_aggregate_one_row_per_asset_cve_keeps_max_and_drops_non_assets():
    docs = [doc("jump", "openssh-server", "cve-1", 5.0, "Medium"),
            doc("jump", "openssh-client", "CVE-1", 8.1, "High", at="2026-11-15T00:00:00Z"),
            doc("jump", "libc6", "CVE-2", None, None),
            doc("ids", "suricata", "CVE-3", 9.8, "Critical")]
    rows, skipped = wazuh_pairs.aggregate(docs, {"jump": "Jump"}, {"Jump": [("openssh", re.compile("^openssh-server$"))]})
    by = {(r["asset"], r["cve"]): r for r in rows}
    assert set(by) == {("Jump", "CVE-1"), ("Jump", "CVE-2")} and skipped == {"ids": 1}
    r = by[("Jump", "CVE-1")]
    assert r["wazuh_score"] == 8.1 and r["wazuh_severity"] == "High" and r["detected_at"].startswith("2026-11-15")
    assert r["packages"] == "openssh-client;openssh-server" and r["service_software"] == "openssh"
    assert by[("Jump", "CVE-2")]["service_software"] == "" and by[("Jump", "CVE-2")]["wazuh_score"] is None


def test_merge_sources_and_service_flag():
    wazuh = {("A", "CVE-1"): {"packages": "x", "wazuh_score": 7.0, "wazuh_severity": "High", "service_software": ""},
             ("A", "CVE-2"): {"packages": "nginx", "wazuh_score": 5.0, "wazuh_severity": "Medium",
                              "service_software": "nginx"}}
    links = [{"asset": "A", "cve": "CVE-2", "software": "nginx", "via": "nvd"},
             {"asset": "B", "cve": "CVE-3", "software": "jenkins", "via": "nvd"}]
    cves = {"CVE-1": {"cvss3_vector": FULL, "kev": True}, "CVE-3": {"cvss3_vector": FULL, "kev": False}}
    items = {i["id"]: i for i in wazuh_pairs.merge(wazuh, links, cves)}
    assert items["A|CVE-1"]["source"] == "wazuh" and not items["A|CVE-1"]["service"] and items["A|CVE-1"]["kev"]
    assert items["A|CVE-2"]["source"] == "both" and items["A|CVE-2"]["service"] and not items["A|CVE-2"]["in_graph"]
    assert items["B|CVE-3"]["source"] == "graph" and items["B|CVE-3"]["wazuh_score"] is None


def test_exploit_available():
    assert wazuh_pairs.exploit_available({"kev": True})
    assert wazuh_pairs.exploit_available({"ssvc_exploitation": "PoC"})
    assert not wazuh_pairs.exploit_available({"ssvc_exploitation": "none"})


def test_allocate_is_proportional_capped_and_exact():
    a = sample.allocate({"x": 90, "y": 9, "z": 1}, 10)
    assert sum(a.values()) == 10 and a["x"] == 9 and a["y"] == 1 and a["z"] == 0
    assert sample.allocate({"x": 2, "y": 1}, 10) == {"x": 2, "y": 1}
    assert sample.allocate({"x": 3}, 0) == {"x": 0}


def _items():
    out = []
    for n in range(60):
        out.append({"id": f"H{n % 3}|CVE-{n}", "asset": f"H{n % 3}", "cve": f"CVE-{n}",
                    "cvss3_score": [9.8, 7.5, 4.0][n % 3 if n < 30 else (n + 1) % 3],
                    "kev": False, "ssvc_exploitation": "poc" if n % 5 == 0 else "none"})
    return out, {"H0": "DMZ", "H1": "APP", "H2": "DATA"}


def test_draw_is_deterministic_and_records_inclusion_probability():
    items, zone = _items()
    a = sample.draw(items, zone, 10, 0.5, seed=7)
    b = sample.draw(items, zone, 10, 0.5, seed=7)
    assert [i["id"] for i in a] == [i["id"] for i in b] and len(a) == 10
    assert len({i["id"] for i in a}) == 10
    n_exploit = sum(i["stratum"].endswith("/exploit") for i in a)
    assert n_exploit == 5                                   # half from the 12 exploit-available pairs
    for i in a:
        size = sum(1 for j in items if "/".join(sample.stratum(j, zone)) == i["stratum"])
        drawn = sum(1 for j in a if j["stratum"] == i["stratum"])
        assert i["inclusion_prob"] == drawn / size


def test_draw_tops_up_when_one_group_is_short():
    items, zone = _items()
    few = [i for i in items if i["ssvc_exploitation"] == "none"] + \
          [i for i in items if i["ssvc_exploitation"] == "poc"][:2]
    got = sample.draw(few, zone, 10, 0.5, seed=7)
    assert len(got) == 10 and sum(i["stratum"].endswith("/exploit") for i in got) == 2


def test_kev_split_never_uses_kev_known_at_t0_and_drops_later_cves():
    items = [{"cve": "OLD-KEV", "cvss3_vector": FULL, "published": "2024-01-01", "kev_date_added": "2025-01-01"},
             {"cve": "NEW-KEV", "cvss3_vector": FULL, "published": "2025-01-01", "kev_date_added": "2026-06-01"},
             {"cve": "LATE", "cvss3_vector": FULL, "published": "2026-06-01T00:00:00", "kev_date_added": None},
             {"cve": "PLAIN", "cvss3_vector": FULL, "published": "2025-02-01", "kev_date_added": None},
             {"cve": "NOVEC", "cvss3_vector": None, "published": "2025-02-01", "kev_date_added": None}]
    kept, why = kev_forward.split(items, "2026-05-01")
    assert {i["cve"]: i["grade"] for i in kept} == {"NEW-KEV": 1, "PLAIN": 0}
    assert why["in KEV at T0"] == 1 and why["published after T0"] == 1 and why["no CVSS v3.1 vector"] == 1


def test_kev_forward_score_ignores_kev_and_ssvc_and_keeps_base_av_off_service():
    from types import SimpleNamespace
    asset = {"cr": "H", "ir": "H", "ar": "H"}
    g = SimpleNamespace(assets={"A": asset}, internet_path=lambda h: False)
    item = {"asset": "A", "cve": "C", "cvss3_vector": FULL, "kev": True, "ssvc_exploitation": "active",
            "service": False, "wazuh_score": None}
    out = kev_forward.score(item, g, {}, 0.5, {("A", "compromise"): 0.0})
    assert out["L3"] == out["L2"]                         # E = X: no KEV / SSVC leak
    on_service = kev_forward.score({**item, "service": True}, g, {}, 0.5, {("A", "compromise"): 0.0})
    assert on_service["L2"] < out["L2"]                   # AV:N lowered to A only for the host's network service
    assert out["WazuhVD"] == out["L0"]


def test_wazuh_vd_baseline_falls_back_to_cvss_base():
    asset = {"cr": "M", "ir": "M", "ar": "M"}
    got = ladder.baselines({"cve": "C", "cvss3_vector": FULL, "wazuh_score": 7.5}, asset, {})
    assert got["WazuhVD"] == 7.5 and not got["wazuh_vd_fallback"]
    got = ladder.baselines({"cve": "C", "cvss3_vector": FULL}, asset, {})
    assert got["WazuhVD"] == 9.8 and got["wazuh_vd_fallback"]
