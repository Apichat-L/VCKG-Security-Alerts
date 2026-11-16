# Asset → CVE links vs Wazuh vulnerability detection

Generated 2026-11-16 by `python -m asset_kg wazuh-check`. Method: `asset_kg/wazuh_check.py`.

Wazuh is a second opinion, not ground truth (PLAN.md §3), so the numbers below are **agreement**. Only software that Wazuh inventories as a package on the same host is scored. Wazuh CVEs that are not in the CTI graph (CVE years not loaded) are counted separately, not as misses.

## Summary (comparable software)

| Graph CVEs | Wazuh CVEs (in graph) | Both | Graph only | Wazuh only | Precision | Recall | Wazuh CVEs outside the graph |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 344 | 242 | 235 | 109 | 7 | 68.3% | 97.1% | 1 |

## Per asset and software

| Asset | Software (graph) | Graph CVEs from | Package (Wazuh) | Graph | Wazuh | Both | Precision | Recall | Outside graph |
|---|---|---|---|---:|---:|---:|---:|---:|---:|
| Admin-PC | openssh 1:8.9p1-3 | OSV Ubuntu:22.04:LTS | openssh-server 1:8.9p1-3 | 40 | 36 | 36 | 90.0% | 100.0% | 0 |
| DNS | bind 1:9.18.19-1~deb12u1 | OSV Debian:12 | bind9 1:9.18.19-1~deb12u1 | 47 | 47 | 47 | 100.0% | 100.0% | 0 |
| Dep-PC | openssh 1:8.9p1-3 | OSV Ubuntu:22.04:LTS | openssh-server 1:8.9p1-3 | 40 | 36 | 36 | 90.0% | 100.0% | 0 |
| Dev-PC | openssh 1:8.9p1-3 | OSV Ubuntu:22.04:LTS | openssh-server 1:8.9p1-3 | 40 | 36 | 36 | 90.0% | 100.0% | 0 |
| Files-SMB | samba 2:4.17.12+dfsg-0+deb12u4 | OSV Debian:12 | samba 2:4.17.12+dfsg-0+deb12u4 | 5 | 0 | 0 | 0.0% | n/a | 0 |
| HR-DB | mariadb 10.11.6 | NVD | mariadb-server 1:10.11.6+maria~ubu2204 | 22 | 0 | 0 | 0.0% | n/a | 0 |
| Jump | openssh 1:9.2p1-2+deb12u2 | OSV Debian:12 | openssh-server 1:9.2p1-2+deb12u2 | 43 | 0 | 0 | 0.0% | n/a | 0 |
| Mail | dovecot 1:2.3.19.1+dfsg1-2.1 | OSV Debian:12 | dovecot-core 1:2.3.19.1+dfsg1-2.1 | 38 | 37 | 37 | 97.4% | 100.0% | 1 |
| Mail | postfix 3.7.10-0+deb12u1 | OSV Debian:12 | postfix 3.7.10-0+deb12u1 | 1 | 0 | 0 | 0.0% | n/a | 0 |
| Nginx | nginx 1.25.3 | NVD | nginx 1.25.3-1~bookworm | 22 | 0 | 0 | 0.0% | n/a | 0 |
| PostgreSQL | postgresql 15.5 | NVD | postgresql-15 15.5-1.pgdg120+1 | 46 | 50 | 43 | 93.5% | 86.0% | 0 |

## Version check (services.csv vs Wazuh inventory)

All comparable software has the version Wazuh sees on the host.

## Not scored

| Asset | Software | Graph CVEs | Why |
|---|---|---:|---|
| API | node.js 21.6.1 | 7 | not inventoried by Wazuh |
| Gitea | gitea 1.21.7 | 45 | not inventoried by Wazuh |
| HR-App | apache tomcat 9.0.85 | 59 | not inventoried by Wazuh |
| Jenkins | jenkins 2.441 | 58 | not inventoried by Wazuh |
| Monitoring | grafana 10.2.3 | 19 | not inventoried by Wazuh |
| Redis | redis 7.2.4 | 18 | not inventoried by Wazuh |
| Web | apache httpd 2.4.58 | 79 | not inventoried by Wazuh |

## Disagreements by reason

| Side | Reason | CVEs |
|---|---|---:|
| graph only | distribution data (Debian:12) lists the installed version as affected (no fix released yet); Wazuh does not report it | 39 |
| graph only | upstream build (no distro_package in services.csv; maintainer MariaDB Developers <maria-developers@lists.launchpad.net>): NVD range covers the version, Wazuh does not report it | 22 |
| graph only | upstream build (no distro_package in services.csv; maintainer NGINX Packaging <nginx-packaging@f5.com>): NVD range covers the version, Wazuh does not report it | 22 |
| graph only | distribution data (Debian:12) lists the installed version as affected (fixed in a later revision); Wazuh does not report it | 11 |
| graph only | distribution data (Ubuntu:22.04:LTS) lists the installed version as affected (no fix released yet); Wazuh does not report it | 9 |
| wazuh only | no CPE in the NVD record (...) | 7 |
| graph only | distribution data (Ubuntu:22.04:LTS) lists the installed version as affected (fixed in a later revision); Wazuh does not report it | 3 |
| graph only | upstream build (no distro_package in services.csv; maintainer Debian PostgreSQL Maintainers <team+postgresql@tracker.debian.org>): NVD range covers the version, Wazuh does not report it | 3 |

Every disagreement, with its CVSS and reason: `data/reports/asset_cve_disagreements.csv`.
