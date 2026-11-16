# Evaluation, Part A (sensitivity): how the EVS reprioritises CVSS

Generated 2026-11-17 by `python -m eval_kg sensitivity`. β = 0.5, γ = 0.5.

> **This is a sensitivity analysis of the scoring mechanism, not a ground-truth validation.** It measures how far the EVS (L4) reorders a pure CVSS-base (L0) ranking across the whole asset × CVE inventory, with no alert and no exploit outcome, and checks the reordering follows asset value and reachability — i.e. the context terms do what the design claims. It does **not** show the reordering is *correct*: there is no outcome label here. The validated contextual claim is Part B (blast radius vs lab-measured impact); the ground-truth ranking test of this direction is Part A4 (`eval_consequence.md`), which compares the same orderings with the consequence measured in the lab.

**Inventory:** 615 asset × CVE pairs across 17 assets.

## Reordering magnitude (L0 CVSS base vs L4 EVS)

- Kendall's tau-b: **0.566** (1 = identical order, 0 = unrelated). The EVS keeps the broad CVSS order but reorders within it.
- Pairs: 133177 concordant, **33474 discordant**, 11695 tied on CVSS only, 7238 tied on EVS only, of 188805 total.
- Material cross-asset reorderings (a CVSS gap ≥ 0.5 that the EVS flips): **27619**.

## Direction check (mean / median of L4 − L0, per asset)

If the reordering tracks context, the EVS should lift CVEs on valuable, reachable hosts and lower them on throwaway, contained ones. Assets below are ordered most-suppressed first. The step columns attribute the mean change to each ladder step: +CR/IR/AR (L1−L0), +MAV (L2−L1), +E (L3−L2), +blast-radius propagation P(a,c) (L4−L3); they add up to the mean ΔEVS.

| asset | CR/IR/AR | internet-reachable | mean ΔEVS | median ΔEVS | +CR/IR/AR | +MAV | +E | +P(a,c) | n CVEs |
|---|:--:|:--:|--:|--:|--:|--:|--:|--:|--:|
| Dep-PC | L/L/L | no | -2.34 | -2.55 | -1.43 | -0.59 | -0.31 | +0.00 | 40 |
| Dev-PC | M/M/L | no | -1.22 | -1.25 | -0.23 | -0.59 | -0.40 | +0.00 | 40 |
| Monitoring | M/M/L | no | -1.05 | -0.10 | -0.69 | -0.80 | -0.43 | +0.87 | 19 |
| HR-DB | H/H/M | yes | -0.39 | -0.60 | +0.25 | +0.00 | -0.64 | +0.00 | 22 |
| PostgreSQL | H/H/M | yes | -0.15 | -0.65 | +0.34 | +0.00 | -0.57 | +0.08 | 46 |
| Redis | M/M/M | yes | -0.13 | -0.55 | +0.01 | +0.00 | -0.54 | +0.41 | 18 |
| Files-SMB | H/M/M | yes | +0.32 | +0.90 | +0.00 | +0.00 | -0.50 | +0.82 | 5 |
| Mail | H/M/M | yes | +0.38 | -0.30 | +0.27 | +0.00 | -0.47 | +0.58 | 38 |
| HR-App | H/H/L | yes | +0.86 | +0.90 | +0.12 | +0.00 | -0.62 | +1.36 | 59 |
| Admin-PC | H/H/L | no | +0.93 | +1.05 | +0.61 | -0.59 | -0.47 | +1.38 | 40 |
| API | H/H/M | yes | +1.01 | +1.10 | +0.14 | +0.00 | -0.56 | +1.43 | 7 |
| Gitea | H/H/M | yes | +1.16 | +1.00 | +0.83 | +0.00 | -0.62 | +0.95 | 45 |
| Nginx | M/M/H | yes | +1.17 | +1.20 | +0.60 | +0.00 | -0.58 | +1.15 | 22 |
| Web | M/M/H | yes | +1.36 | +1.20 | +0.47 | +0.00 | -0.63 | +1.51 | 69 |
| Jump | H/H/M | no | +1.63 | +1.70 | +0.73 | -0.57 | -0.45 | +1.91 | 40 |
| Jenkins | M/H/M | yes | +1.64 | +1.55 | +0.28 | +0.00 | -0.48 | +1.84 | 58 |
| DNS | L/H/H | yes | +1.99 | +2.50 | +1.58 | +0.00 | -0.75 | +1.16 | 47 |

## Exemplars

Largest lifts (EVS raises a CVE because its host is valuable / reachable / high-blast):

| asset | CVE | CR/IR/AR | CVSS base (L0) | EVS (L4) | Δ |
|---|---|:--:|--:|--:|--:|
| Jump | CVE-2026-55655 | H/H/M | 6.1 | 9.70 | +3.60 |
| Jump | CVE-2020-14145 | H/H/M | 5.9 | 9.00 | +3.10 |
| DNS | CVE-2026-10822 | L/H/H | 6.5 | 9.50 | +3.00 |
| DNS | CVE-2026-19662 | L/H/H | 5.9 | 8.90 | +3.00 |
| HR-App | CVE-2025-55668 | H/H/L | 6.5 | 9.50 | +3.00 |
| Jump | CVE-2026-106552 | H/H/M | 6.5 | 9.50 | +3.00 |

Largest drops (EVS lowers a CVE because its host is low-value / contained):

| asset | CVE | CR/IR/AR | CVSS base (L0) | EVS (L4) | Δ |
|---|---|:--:|--:|--:|--:|
| Dep-PC | CVE-2026-60002 | L/L/L | 9.4 | 5.80 | -3.60 |
| Dep-PC | CVE-2023-28531 | L/L/L | 9.8 | 6.30 | -3.50 |
| Dep-PC | CVE-2023-38408 | L/L/L | 9.8 | 6.30 | -3.50 |
| Admin-PC | CVE-2026-3497 | H/H/L | 7.5 | 4.30 | -3.20 |
| Admin-PC | CVE-2026-60000 | H/H/L | 7.5 | 4.30 | -3.20 |
| Dep-PC | CVE-2026-106553 | L/L/L | 7.5 | 4.30 | -3.20 |

Reading these together: a moderate CVE on a critical, reachable host can out-rank a high CVE on a throwaway host — the reprioritisation a pure CVSS score cannot make. Whether that reprioritisation is *right* is what Part A4 (measured consequence) and Part B (blast radius vs the lab) measure.
