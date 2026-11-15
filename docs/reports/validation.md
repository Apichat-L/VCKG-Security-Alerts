# CTI KG validation (cf. Nagaty et al. Table 1)

Graph: data/processed, CVE years 1999+. Generated 2026-11-15.

| Task | Ref | KG | Hits | Rec % | Prec % | F1 % |
|---|---:|---:|---:|---:|---:|---:|
| CAPEC->ATT&CK edges vs CAPEC STIX | 271 | 270 | 270 | 99.63 | 100.00 | 99.82 |
| CAUSES_WEAKNESS edges vs CAPEC STIX | 1211 | 1211 | 1211 | 100.00 | 100.00 | 100.00 |
| CWE nodes vs NVD-referenced CWEs (2020+) | 788 | 1415 | 785 | 99.62 | 55.48 | 71.27 |
| EXPLOITED_BY edges vs CVE2CAPEC (shared CVEs) | 1200841 | 386049 | 360659 | 30.03 | 93.42 | 45.45 |
| EXPLOITED_BY vs CVE2CAPEC, most-specific CWEs | 354247 | 386049 | 351313 | 99.17 | 91.00 | 94.91 |
| AFFECTS (OS) edges with NVD CPE evidence | 24 | 24 | 15 | – | 62.50 | – |

Notes: see cti_kg/validate/checks.py docstrings for each reference and deviations from the paper. CVE2CAPEC expands each CVE's CWE to its ancestors, which lowers recall.
