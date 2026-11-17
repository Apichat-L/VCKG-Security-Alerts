"""Distribution security data from OSV (osv.dev) for distro packages (the backport problem, PLAN.md §3).

Debian and Ubuntu fix vulnerabilities by backporting patches without changing the upstream
version (samba 2:4.17.12+dfsg-0+deb12u4 is still "4.17.12"), so NVD's upstream version ranges
over-report for distro packages. For those, the graph takes CVEs from the distribution's own
data instead, as Trivy, Grype and Wazuh (>= 4.8) do.

Source: OSV's per-ecosystem dumps (the Debian Security Tracker and the Ubuntu CVE Tracker in one
format), downloaded to data/raw/osv/<Ecosystem>-all.zip:

    DEBIAN-CVE-2024-6387   affected: {package: {ecosystem: "Debian:12", name: "openssh"},
                                      ranges: [{type: ECOSYSTEM, events: [{introduced: "0"}, {fixed: "1:9.2p1-2+deb12u3"}]}]}

Package names are *source* packages (openssh, not openssh-server). A CVE affects an installed
version when it falls inside one of the ranges (dpkg comparison) or is listed in `versions`.

Reading an 800 MB zip is slow, so each ecosystem is indexed once into
data/processed/osv/<ecosystem>.json and rebuilt when the zip is newer.
"""
import json
import re
import zipfile
from pathlib import Path

import requests

from . import config
from .dpkg import compare

RAW = config.ROOT / "data" / "raw" / "osv"
INDEX = config.ROOT / "data" / "processed" / "osv"
URL = "https://osv-vulnerabilities.storage.googleapis.com/{family}/all.zip"
CVE = re.compile(r"CVE-\d{4}-\d{4,}")


def family(ecosystem: str) -> str:
    """'Ubuntu:22.04:LTS' -> 'Ubuntu' (the name of the OSV dump)."""
    return ecosystem.split(":", 1)[0]


def download(families=("Debian", "Ubuntu")) -> None:
    """Fetch (or resume) the OSV dumps. Ubuntu's is about 800 MB."""
    RAW.mkdir(parents=True, exist_ok=True)
    for fam in families:
        out = RAW / f"{fam}-all.zip"
        print(f"downloading {URL.format(family=fam)} -> {out}")
        with requests.get(URL.format(family=fam), stream=True, timeout=120) as r:
            r.raise_for_status()
            tmp = out.with_suffix(".part")
            with open(tmp, "wb") as fh:
                for chunk in r.iter_content(1 << 20):
                    fh.write(chunk)
            tmp.replace(out)
        print(f"  {out.stat().st_size:,} bytes")


def _cve_id(record: dict) -> str | None:
    for candidate in [record.get("id", "")] + record.get("aliases", []) + record.get("upstream", []):
        m = CVE.search(candidate)
        if m:
            return m.group(0)
    return None


def build_index(ecosystem: str) -> dict:
    """{source package: [[cve, ranges, versions], ...]} for one ecosystem, from the zip."""
    zpath = RAW / f"{family(ecosystem)}-all.zip"
    if not zpath.exists():
        raise SystemExit(f"{zpath} not found: run `python -m asset_kg osv-download`")
    index: dict[str, list] = {}
    with zipfile.ZipFile(zpath) as z:
        for name in z.namelist():
            if not name.endswith(".json"):
                continue
            rec = json.loads(z.read(name))
            cve = _cve_id(rec)
            if not cve:
                continue
            for a in rec.get("affected", []):
                pkg = a.get("package", {})
                if pkg.get("ecosystem") != ecosystem:
                    continue
                ranges = [r["events"] for r in a.get("ranges", []) if r.get("type") == "ECOSYSTEM"]
                index.setdefault(pkg["name"], []).append([cve, ranges, a.get("versions", [])])
    return index


def load_index(ecosystem: str) -> dict:
    zpath = RAW / f"{family(ecosystem)}-all.zip"
    cache = INDEX / f"{ecosystem.replace(':', '_')}.json"
    if cache.exists() and (not zpath.exists() or cache.stat().st_mtime >= zpath.stat().st_mtime):
        try:
            return json.loads(cache.read_text(encoding="utf-8"))
        except json.JSONDecodeError:   # empty/truncated by an interrupted earlier run: rebuild
            print(f"  {cache.relative_to(config.ROOT)} is corrupt, rebuilding")
    print(f"  indexing OSV {ecosystem} from {zpath.name} (once; cached in {cache.relative_to(config.ROOT)})")
    index = build_index(ecosystem)
    cache.parent.mkdir(parents=True, exist_ok=True)
    tmp = cache.with_suffix(".part")   # write then rename, so an interrupted run leaves no bad cache
    tmp.write_text(json.dumps(index), encoding="utf-8")
    tmp.replace(cache)
    return index


def in_range(version: str, events: list[dict]) -> bool:
    """OSV ECOSYSTEM range semantics: introduced <= v < fixed, or introduced <= v <= last_affected."""
    affected = False
    for e in events:            # OSV lists events in version order
        if "introduced" in e:
            if e["introduced"] == "0" or compare(version, e["introduced"]) >= 0:
                affected = True
        elif "fixed" in e:
            if compare(version, e["fixed"]) >= 0:
                affected = False
        elif "last_affected" in e:
            if compare(version, e["last_affected"]) > 0:
                affected = False
        elif "limit" in e:
            if compare(version, e["limit"]) >= 0:
                affected = False
    return affected


def affected_cves(index: dict, package: str, version: str) -> dict[str, str | None]:
    """CVE -> fixed version (None = no fix yet) for an installed source package version."""
    out = {}
    for cve, ranges, versions in index.get(package, []):
        if version in versions or any(in_range(version, events) for events in ranges):
            fixed = [e["fixed"] for events in ranges for e in events if "fixed" in e]
            out[cve] = fixed[-1] if fixed else None
    return out
