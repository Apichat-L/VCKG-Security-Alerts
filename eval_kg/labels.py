"""Part A ground truth: the pentest record, turned into relevance grades.

Scenario files (evaluation/scenarios/*.yaml, see evaluation/README.md) list the steps the team ran, each with
its time window, target asset, optional CVE and what it achieved. Grades come only from those outcomes, never
from CR/IR/AR or any other input of the score:
    3  success with data access, or used as a pivot onward
    2  success on the target (e.g. code execution)
    1  attempted but failed (or stopped)
    0  an alert that matches no step (noise)
evaluation/pentest_results.csv gives, per asset x CVE, whether the team exploited it (yes / no / not_tried).
"""
import csv
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml


def parse_time(value) -> datetime:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    return datetime.fromisoformat(str(value).replace("Z", "+00:00"))


def grade(step: dict) -> int:
    if str(step.get("outcome", "")).lower() != "success":
        return 1
    if step.get("pivot") or str(step.get("achieved", "")).lower() == "data_access":
        return 3
    return 2


def load_scenarios(folder: Path) -> list[dict]:
    scenarios = []
    for f in sorted(folder.glob("*.yaml")) + sorted(folder.glob("*.yml")):
        doc = yaml.safe_load(f.read_text(encoding="utf-8")) or {}
        if not doc.get("steps"):
            continue
        steps = []
        for s in doc["steps"]:
            steps.append({**s, "start": parse_time(s["start"]), "end": parse_time(s["end"]),
                          "cve": (s.get("cve") or "").upper() or None, "grade": grade(s)})
        scenarios.append({"id": doc.get("id", f.stem), "file": f.name, "synthetic": bool(doc.get("synthetic")),
                          "attacker": doc.get("attacker"), "description": doc.get("description", ""),
                          "start": parse_time(doc.get("start") or min(s["start"] for s in steps)),
                          "end": parse_time(doc.get("end") or max(s["end"] for s in steps)), "steps": steps})
    return scenarios


def label_instance(item: dict, scenario: dict, slack: int) -> int:
    """Grade of a vulnerability instance (asset, cve, first..last seen) within one scenario."""
    pad = timedelta(seconds=slack)
    first, last = parse_time(item["first_seen"]), parse_time(item["last_seen"])
    best = 0
    for s in scenario["steps"]:
        if s["target"] != item["asset"] or (s["cve"] and s["cve"] != item["cve"]):
            continue
        if first <= s["end"] + pad and last >= s["start"] - pad:
            best = max(best, s["grade"])
    return best


def in_window(item: dict, scenario: dict, slack: int) -> bool:
    pad = timedelta(seconds=slack)
    return parse_time(item["first_seen"]) <= scenario["end"] + pad and \
        parse_time(item["last_seen"]) >= scenario["start"] - pad


def load_pentest_results(path: Path) -> dict:
    """(asset, CVE) -> 1 exploited / 0 not exploited; `not_tried` rows are left out (unknown, not negative)."""
    if not path.exists():
        return {}
    out = {}
    with open(path, newline="", encoding="utf-8") as fh:
        rows = (ln for ln in fh if ln.strip() and not ln.lstrip().startswith("#"))
        for r in csv.DictReader(rows):
            val = (r.get("exploited") or "").strip().lower()
            if val in ("yes", "no"):
                out[(r["asset"].strip(), r["cve"].strip().upper())] = 1 if val == "yes" else 0
    return out
