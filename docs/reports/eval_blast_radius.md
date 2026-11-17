# Evaluation, Part B: blast-radius variants against the lab

Generated 2026-11-17 by `python -m eval_kg blast-ablation`. Protocol: `docs/evaluation.md`.

Ground truth, measured in the running lab (not read from `lab/*.csv`):

- **network**: TCP reachability from each host (compromise mode, network view), measured 2026-11-17T00:08:05+00:00.
- **usable**: hosts usable with what is stored on each host (compromise mode), measured 2026-11-17T00:08:24+00:00.
- **dependents**: hosts whose service fails when a host is stopped (disruption mode), measured 2026-11-17T00:18:25+00:00.

Variants: B0 none · B1 unrestricted k-hop over any edge type · B2 zone-level · B3 ours undirected · B4 ours (Algorithm 1, k=1) · B5 ours k=2/3.

## network (compromise mode), per asset

Pooled = micro-average over every (host, affected host) pair: hosts with an empty prediction or an empty truth add nothing, so B0 gets no free credit. Mean = the earlier per-host average (an empty truth counts as recall 1, an empty prediction as precision 1). 0 of 17 hosts have an empty truth here; 'FP on empty' counts the hosts a variant predicts for them.

| Variant | Pooled P | Pooled R | Pooled F1 | Mean P | Mean R | Mean F1 | FP on empty | Mean set size |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| B0 | - | 0.000 | - | 1.000 | 0.000 | 0.000 | 0 | 0.00 |
| B1 (k=1) | 0.667 | 0.136 | 0.225 | 0.696 | 0.122 | 0.194 | 0 | 1.41 |
| B1 (k=2) | 0.434 | 1.000 | 0.605 | 0.434 | 1.000 | 0.584 | 0 | 16.00 |
| B2 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 0 | 6.94 |
| B3 | 0.667 | 0.136 | 0.225 | 0.696 | 0.122 | 0.194 | 0 | 1.41 |
| B4 | 1.000 | 0.102 | 0.185 | 1.000 | 0.088 | 0.152 | 0 | 0.71 |
| B5 (k=2) | 0.947 | 0.153 | 0.263 | 0.971 | 0.127 | 0.195 | 0 | 1.12 |
| B5 (k=3) | 0.909 | 0.169 | 0.286 | 0.951 | 0.136 | 0.201 | 0 | 1.29 |

Observed sets: API → Files-SMB, Gitea, HR-App, HR-DB, Jenkins, PostgreSQL, Redis; Admin-PC → Dep-PC, Dev-PC, Files-SMB, HR-DB, Jump, Monitoring, PostgreSQL, Redis; DNS → API, Gitea, HR-App, Jenkins, Mail, Nginx, Web; Dep-PC → Admin-PC, Dev-PC, Files-SMB, HR-DB, Jump, Monitoring, PostgreSQL, Redis; Dev-PC → Admin-PC, Dep-PC, Files-SMB, HR-DB, Jump, Monitoring, PostgreSQL, Redis; Files-SMB → HR-DB, PostgreSQL, Redis; Gitea → API, Files-SMB, HR-App, HR-DB, Jenkins, PostgreSQL, Redis; HR-App → API, Files-SMB, Gitea, HR-DB, Jenkins, PostgreSQL, Redis; HR-DB → Files-SMB, PostgreSQL, Redis; Jenkins → API, Files-SMB, Gitea, HR-App, HR-DB, PostgreSQL, Redis; Jump → API, DNS, Files-SMB, Gitea, HR-App, HR-DB, Jenkins, Mail, Monitoring, Nginx, PostgreSQL, Redis, Web; Mail → API, DNS, Gitea, HR-App, Jenkins, Nginx, Web; Monitoring → API, DNS, Files-SMB, Gitea, HR-App, HR-DB, Jenkins, Jump, Mail, Nginx, PostgreSQL, Redis, Web; Nginx → API, DNS, Gitea, HR-App, Jenkins, Mail, Web; PostgreSQL → Files-SMB, HR-DB, Redis; Redis → Files-SMB, HR-DB, PostgreSQL; Web → API, DNS, Gitea, HR-App, Jenkins, Mail, Nginx

## usable (compromise mode), per asset

Pooled = micro-average over every (host, affected host) pair: hosts with an empty prediction or an empty truth add nothing, so B0 gets no free credit. Mean = the earlier per-host average (an empty truth counts as recall 1, an empty prediction as precision 1). 8 of 17 hosts have an empty truth here; 'FP on empty' counts the hosts a variant predicts for them.

| Variant | Pooled P | Pooled R | Pooled F1 | Mean P | Mean R | Mean F1 | FP on empty | Mean set size |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| B0 | - | 0.000 | - | 1.000 | 0.471 | 0.471 | 0 | 0.00 |
| B1 (k=1) | 0.458 | 1.000 | 0.629 | 0.500 | 1.000 | 0.547 | 7 | 1.41 |
| B1 (k=2) | 0.040 | 1.000 | 0.078 | 0.040 | 1.000 | 0.075 | 128 | 16.00 |
| B2 | 0.093 | 1.000 | 0.171 | 0.080 | 1.000 | 0.137 | 42 | 6.94 |
| B3 | 0.458 | 1.000 | 0.629 | 0.500 | 1.000 | 0.547 | 7 | 1.41 |
| B4 | 0.917 | 1.000 | 0.957 | 0.941 | 1.000 | 0.941 | 1 | 0.71 |
| B5 (k=2) | 0.579 | 1.000 | 0.733 | 0.818 | 1.000 | 0.857 | 1 | 1.12 |
| B5 (k=3) | 0.500 | 1.000 | 0.667 | 0.801 | 1.000 | 0.840 | 1 | 1.29 |

Observed sets: API → PostgreSQL; Admin-PC → Files-SMB; DNS → ∅; Dep-PC → ∅; Dev-PC → ∅; Files-SMB → ∅; Gitea → Redis; HR-App → HR-DB; HR-DB → ∅; Jenkins → API, Gitea; Jump → HR-App, Jenkins; Mail → ∅; Monitoring → PostgreSQL; Nginx → Web; PostgreSQL → ∅; Redis → ∅; Web → API

## dependents (disruption mode), per asset

Pooled = micro-average over every (host, affected host) pair: hosts with an empty prediction or an empty truth add nothing, so B0 gets no free credit. Mean = the earlier per-host average (an empty truth counts as recall 1, an empty prediction as precision 1). 7 of 17 hosts have an empty truth here; 'FP on empty' counts the hosts a variant predicts for them.

| Variant | Pooled P | Pooled R | Pooled F1 | Mean P | Mean R | Mean F1 | FP on empty | Mean set size |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| B0 | - | 0.000 | - | 1.000 | 0.412 | 0.412 | 0 | 0.00 |
| B1 (k=1) | 0.500 | 0.857 | 0.632 | 0.559 | 0.951 | 0.575 | 6 | 1.41 |
| B1 (k=2) | 0.051 | 1.000 | 0.098 | 0.051 | 1.000 | 0.093 | 112 | 16.00 |
| B2 | 0.110 | 0.929 | 0.197 | 0.086 | 0.980 | 0.146 | 24 | 6.94 |
| B3 | 0.500 | 0.857 | 0.632 | 0.559 | 0.951 | 0.575 | 6 | 1.41 |
| B4 | 1.000 | 0.857 | 0.923 | 1.000 | 0.951 | 0.969 | 0 | 0.71 |
| B5 (k=2) | 0.737 | 1.000 | 0.848 | 0.897 | 1.000 | 0.933 | 0 | 1.12 |
| B5 (k=3) | 0.636 | 1.000 | 0.778 | 0.873 | 1.000 | 0.912 | 0 | 1.29 |

Observed sets: API → Jenkins, Web; Admin-PC → ∅; DNS → Mail; Dep-PC → ∅; Dev-PC → ∅; Files-SMB → Admin-PC; Gitea → Jenkins; HR-App → Jump; HR-DB → HR-App, Jump; Jenkins → Jump; Jump → ∅; Mail → ∅; Monitoring → ∅; Nginx → ∅; PostgreSQL → API, Monitoring, Web; Redis → Gitea; Web → Nginx

## Per (asset, CVE) pair

615 vulnerability instances on the lab assets; each CVE's impact mode picks the direction and the ground truth (compromise → usable, disruption → dependents).

| Variant | Pooled P | Pooled R | Pooled F1 | Mean P | Mean R | Mean F1 |
|---|---:|---:|---:|---:|---:|---:|
| B0 | - | 0.000 | - | 1.000 | 0.369 | 0.369 |
| B1 (k=1) | 0.525 | 0.996 | 0.687 | 0.581 | 0.999 | 0.642 |
| B1 (k=2) | 0.049 | 1.000 | 0.094 | 0.049 | 1.000 | 0.091 |
| B2 | 0.114 | 0.996 | 0.204 | 0.105 | 0.999 | 0.177 |
| B3 | 0.525 | 0.996 | 0.687 | 0.581 | 0.999 | 0.642 |
| B4 | 0.968 | 0.996 | 0.982 | 0.974 | 0.999 | 0.973 |
| B5 (k=2) | 0.600 | 1.000 | 0.750 | 0.825 | 1.000 | 0.873 |
| B5 (k=3) | 0.534 | 1.000 | 0.696 | 0.811 | 1.000 | 0.859 |

## Independent check: hosts the pentest reached from its foothold

The pentest scenarios record an attacker foothold (`attacker:`) and the hosts it then compromised (`outcome: success`). Those were achieved by hand, not read from `CONNECTS_TO` or `checks.csv`. Recall = share of the reached hosts inside the variant's compromise-mode blast radius of the foothold.

| Scenario | Foothold | Reached in the pentest | B0 | B1 (k=1) | B1 (k=2) | B2 | B3 | B4 | B5 (k=2) | B5 (k=3) |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| S01-web-to-data | API | Jenkins, PostgreSQL | 0/2 | 2/2 | 2/2 | 2/2 | 2/2 | 1/2 | 1/2 | 1/2 |
| S02-office-to-data | Admin-PC | Files-SMB, PostgreSQL | 0/2 | 1/2 | 2/2 | 2/2 | 1/2 | 1/2 | 1/2 | 1/2 |
| S05-ssh-brute-force-pivot | Dep-PC | Admin-PC | 0/1 | 0/1 | 1/1 | 1/1 | 0/1 | 0/1 | 0/1 | 0/1 |
| S06-smb-credential-stuffing | Dep-PC | Files-SMB | 0/1 | 0/1 | 1/1 | 1/1 | 0/1 | 0/1 | 0/1 | 0/1 |
| S08-dmz-web-to-jenkins | Web | Jenkins | 0/1 | 0/1 | 1/1 | 1/1 | 0/1 | 0/1 | 0/1 | 0/1 |
| S10-dmz-web-to-jenkins-1115 | Web | Jenkins | 0/1 | 0/1 | 1/1 | 1/1 | 0/1 | 0/1 | 0/1 | 0/1 |
| S11-office-ssh-smb-bruteforce | Dep-PC | Admin-PC, Files-SMB | 0/2 | 0/2 | 2/2 | 2/2 | 0/2 | 0/2 | 0/2 | 0/2 |
| S12-office-db-credential-theft | Dep-PC | PostgreSQL | 0/1 | 0/1 | 1/1 | 1/1 | 0/1 | 0/1 | 0/1 | 0/1 |
| S14-web-to-jenkins-1116 | Web | Jenkins | 0/1 | 0/1 | 1/1 | 1/1 | 0/1 | 0/1 | 0/1 | 0/1 |
| S15-web-to-tomcat-write | Web | HR-App | 0/1 | 0/1 | 1/1 | 1/1 | 0/1 | 0/1 | 0/1 | 0/1 |
| S16-api-to-redis | API | Redis | 0/1 | 0/1 | 1/1 | 1/1 | 0/1 | 0/1 | 0/1 | 0/1 |
| S19-api-to-gitea-userenum | API | Gitea | 0/1 | 0/1 | 1/1 | 1/1 | 0/1 | 0/1 | 0/1 | 0/1 |
| S20-web-to-gitea-lastlogin | Web | Gitea | 0/1 | 0/1 | 1/1 | 1/1 | 0/1 | 0/1 | 0/1 | 0/1 |
| S21-web-to-gitea-heatmap | Web | Gitea | 0/1 | 0/1 | 1/1 | 1/1 | 0/1 | 0/1 | 0/1 | 0/1 |
| S22-api-to-postgresql-rls | API | PostgreSQL | 0/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 |
| S23-jump-to-hrdb-mariadb | Jump | HR-DB | 0/1 | 0/1 | 1/1 | 1/1 | 0/1 | 0/1 | 1/1 | 1/1 |
| S24-adminpc-to-samba-guest | Admin-PC | Files-SMB | 0/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 |
| S25-deppc-to-grafana-creds | Dep-PC | Monitoring | 0/1 | 0/1 | 1/1 | 1/1 | 0/1 | 0/1 | 0/1 | 0/1 |
| S26-deppc-to-adminpc-sshenum | Dep-PC | Admin-PC | 0/1 | 0/1 | 1/1 | 1/1 | 0/1 | 0/1 | 0/1 | 0/1 |
| S27-deppc-to-jump-terrapin | Dep-PC | Jump | 0/1 | 0/1 | 1/1 | 1/1 | 0/1 | 0/1 | 0/1 | 0/1 |
| S28-api-to-postgresql-carddata | API | PostgreSQL | 0/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 |
| S30-web-to-hrapp-tomcat-partialput | Web | HR-App | 0/1 | 0/1 | 1/1 | 1/1 | 0/1 | 0/1 | 0/1 | 0/1 |
| S31-jump-to-hrdb-mariadb-spatial | Jump | HR-DB | 0/1 | 0/1 | 1/1 | 1/1 | 0/1 | 0/1 | 1/1 | 1/1 |
| S33-api-to-redis-lua-gc | API | Redis | 0/1 | 0/1 | 1/1 | 1/1 | 0/1 | 0/1 | 0/1 | 0/1 |
| S35-web-to-jenkins-websocket-cli | Web | Jenkins | 0/1 | 0/1 | 1/1 | 1/1 | 0/1 | 0/1 | 0/1 | 0/1 |
| S36-deppc-to-grafana-wildcard-uid | Dep-PC | Monitoring | 0/1 | 0/1 | 1/1 | 1/1 | 0/1 | 0/1 | 0/1 | 0/1 |
| S37-deppc-to-grafana-dashboard-perms | Dep-PC | Monitoring | 0/1 | 0/1 | 1/1 | 1/1 | 0/1 | 0/1 | 0/1 | 0/1 |
| S38-api-to-postgresql-secdef-toctou | API | PostgreSQL | 0/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 |
| S39-api-to-redis-client-tracking | API | Redis | 0/1 | 0/1 | 1/1 | 1/1 | 0/1 | 0/1 | 0/1 | 0/1 |
| S40-api-to-gitea-stopwatch | API | Gitea | 0/1 | 0/1 | 1/1 | 1/1 | 0/1 | 0/1 | 0/1 | 0/1 |
| S41-deppc-to-grafana-contact-points | Dep-PC | Monitoring | 0/1 | 0/1 | 1/1 | 1/1 | 0/1 | 0/1 | 0/1 | 0/1 |
| S42-api-to-postgresql-rls-prepared | API | PostgreSQL | 0/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 |
| S43-api-to-gitea-token-scope | API | Gitea | 0/1 | 0/1 | 1/1 | 1/1 | 0/1 | 0/1 | 0/1 | 0/1 |
| S44-web-to-jenkins-secrettextarea | Web | Jenkins | 0/1 | 0/1 | 1/1 | 1/1 | 0/1 | 0/1 | 0/1 | 0/1 |
| **Pooled recall** | | | 0.000 | 0.216 | 1.000 | 1.000 | 0.216 | 0.189 | 0.243 | 0.243 |
| Hosts predicted per foothold | | | 0.0 | 1.7 | 16.0 | 7.7 | 1.7 | 0.8 | 1.2 | 1.3 |

A miss means the attacker got somewhere the variant did not predict (e.g. guessing a password for a host the foothold has no recorded flow to); a large predicted set buys recall with precision.

## Cost

| Variant | Mean runtime per query (ms) | Mean affected hosts | Mean non-asset nodes returned |
|---|---:|---:|---:|
| B0 | 0.00 | 0.00 | 0.0 |
| B1 (k=1) | 49.06 | 1.41 | 368.4 |
| B1 (k=2) | 96.86 | 16.00 | 1218.8 |
| B2 | 0.01 | 6.94 | 0.0 |
| B3 | 0.02 | 1.41 | 0.0 |
| B4 | 0.01 | 0.71 | 0.0 |
| B5 (k=2) | 0.01 | 1.12 | 0.0 |
| B5 (k=3) | 0.01 | 1.29 | 0.0 |

## Downstream: the EVS with each variant's blast radius in P(a,c)

Each variant's set replaces BR_1 inside P(a,c) (Eq. 16); the resulting EVS ranks the asset × CVE inventory against the consequence measured in the lab (Part A4 labels, `eval_consequence.md`). Tie-aware metrics.

| Variant | NDCG@50 | AP | Kendall τ-b | Pair concordance | Same-CVE concordance |
|---|---:|---:|---:|---:|---:|
| B0 | 0.219 | 0.719 | 0.078 | 0.549 | 0.920 |
| B1 (k=1) | 0.302 | 0.789 | 0.181 | 0.615 | 1.000 |
| B1 (k=2) | 0.235 | 0.731 | 0.093 | 0.559 | 1.000 |
| B2 | 0.272 | 0.750 | 0.110 | 0.570 | 1.000 |
| B3 | 0.302 | 0.789 | 0.181 | 0.615 | 1.000 |
| B4 | 0.454 | 0.882 | 0.317 | 0.700 | 1.000 |
| B5 (k=2) | 0.474 | 0.889 | 0.343 | 0.717 | 1.000 |
| B5 (k=3) | 0.482 | 0.890 | 0.344 | 0.717 | 1.000 |

