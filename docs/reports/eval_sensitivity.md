# Evaluation, Part A (sensitivity): how the EVS reprioritises CVSS

> **8-host lab.** Generated on the original 8-host lab, before it grew to 17 hosts and a MGMT zone on 2026-11-16 (`lab_env/README.md`). The numbers below are unchanged; rerun the generating command to update them.

Generated 2026-11-15 by `python -m eval_kg sensitivity`. β = 0.5, γ = 0.5.

> **This is a sensitivity analysis of the scoring mechanism, not a ground-truth validation.** It measures how far the EVS (L4) reorders a pure CVSS-base (L0) ranking across the whole asset × CVE inventory, with no alert and no exploit outcome, and checks the reordering follows asset value and reachability — i.e. the context terms do what the design claims. It does **not** show the reordering is *correct*: there is no outcome label here. The validated contextual claim is Part B (blast radius vs lab-measured impact); the ground-truth ranking tests are Parts A1/A2. Reason this matters: the lab's only alertable CVEs and its only repeatable exploit are all CVSS 9.8 (ceiling), so an A2 EVS-beats-CVSS result is not reachable here.

**Inventory:** 287 asset × CVE pairs across 8 assets.

## Reordering magnitude (L0 CVSS base vs L4 EVS)

- Kendall's tau-b: **0.694** (1 = identical order, 0 = unrelated). The EVS keeps the broad CVSS order but reorders within it.
- Pairs: 32263 concordant, **5293 discordant**, 2282 tied on CVSS only, 381 tied on EVS only, of 41041 total.
- Material cross-asset reorderings (a CVSS gap ≥ 0.5 that the EVS flips): **4238**.

## Direction check (mean / median of L4 − L0, per asset)

If the reordering tracks context, the EVS should lift CVEs on valuable, reachable hosts and lower them on throwaway, contained ones. Assets below are ordered most-suppressed first.

| asset | CR/IR/AR | internet-reachable | mean ΔEVS | median ΔEVS | n CVEs |
|---|:--:|:--:|--:|--:|--:|
| Dep-PC | L/L/L | no | -2.34 | -2.55 | 40 |
| Files-SMB | H/M/M | yes | -0.50 | -0.50 | 5 |
| PostgreSQL | H/H/M | yes | -0.23 | -0.65 | 46 |
| Admin-PC | H/H/L | no | -0.19 | -0.05 | 40 |
| API | H/H/M | yes | -0.10 | -0.30 | 7 |
| Jenkins | M/H/M | yes | +0.16 | +0.00 | 58 |
| Web | M/M/H | yes | +0.27 | -0.10 | 69 |
| Nginx | M/M/H | yes | +0.47 | +0.40 | 22 |

## Exemplars

Largest lifts (EVS raises a CVE because its host is valuable / reachable / high-blast):

| asset | CVE | CR/IR/AR | CVSS base (L0) | EVS (L4) | Δ |
|---|---|:--:|--:|--:|--:|
| Web | CVE-2026-49975 | M/M/H | 7.5 | 9.30 | +1.80 |
| PostgreSQL | CVE-2017-8806 | H/H/M | 5.5 | 7.30 | +1.80 |
| Nginx | CVE-2024-7347 | M/M/H | 4.7 | 6.40 | +1.70 |
| Nginx | CVE-2024-24989 | M/M/H | 7.5 | 9.10 | +1.60 |
| Nginx | CVE-2024-24990 | M/M/H | 7.5 | 9.10 | +1.60 |
| Nginx | CVE-2026-27651 | M/M/H | 7.5 | 9.10 | +1.60 |

Largest drops (EVS lowers a CVE because its host is low-value / contained):

| asset | CVE | CR/IR/AR | CVSS base (L0) | EVS (L4) | Δ |
|---|---|:--:|--:|--:|--:|
| Dep-PC | CVE-2026-60002 | L/L/L | 9.4 | 5.80 | -3.60 |
| Dep-PC | CVE-2023-28531 | L/L/L | 9.8 | 6.30 | -3.50 |
| Dep-PC | CVE-2023-38408 | L/L/L | 9.8 | 6.30 | -3.50 |
| Dep-PC | CVE-2026-106553 | L/L/L | 7.5 | 4.30 | -3.20 |
| Dep-PC | CVE-2026-106555 | L/L/L | 7.5 | 4.30 | -3.20 |
| Dep-PC | CVE-2026-3497 | L/L/L | 7.5 | 4.30 | -3.20 |

Reading these together: a moderate CVE on a critical, reachable host can out-rank a high CVE on a throwaway host — the reprioritisation a pure CVSS score cannot make. Whether that reprioritisation is *right* is what Part B measures, not this report.
