# Evaluation ground truth (pentest record)

This folder holds the labels for Part A of the evaluation (the score ladder L0 → L4, see `docs/evaluation.md`).
The labels come only from what the pentest team **did and achieved** in the lab. They never come from CR/IR/AR
or any other input of the score, because that would make the evaluation circular.

| File | What the team fills in |
|---|---|
| `scenarios/<id>.yaml` | one file per attack scenario: its time window and every step (start/end in UTC, target asset, CVE if any, outcome) |
| `pentest_results.csv` | for each asset × CVE the team examined: was it exploited (`yes` / `no` / `not_tried`) |
| `pentest_candidates.csv` | **generated** by `python -m eval_kg sample`: the (asset, CVE) pairs to try next, drawn at random from Wazuh's detections ∪ the graph's links (see below) |
| `dry_run/` | **synthetic** files to test the pipeline. Its numbers are never reported |

**Running a new pentest session to add to this?** See `pentest/CONTRIBUTING.md` for the step-by-step guide
(what counts for A1 vs A2, grading, exact file gotchas, how to verify it was picked up).

## Scenario file

Copy `scenarios/TEMPLATE.yaml.example` to `scenarios/<id>.yaml`. Record times in **UTC**, and record them while
the scenario runs (the lab clocks are the host's clock). Alerts are matched to a step when their target asset is
the step's `target`, their CVE is the step's `cve` (if the step names one), and their time falls in the step's
window, ± `EVAL_MATCH_SLACK` seconds (default 120).

Grades, computed from each step:

| Grade | Step |
|---:|---|
| 3 | `outcome: success` and (`achieved: data_access` or `pivot: true`) |
| 2 | `outcome: success` |
| 1 | `outcome: failed`: attempted but did not work |
| 0 | an alert in the scenario's window that matches no step (noise) |

## Sampled targets (A1)

Which pairs the team tries is drawn, not chosen, so A1 is not biased towards CVEs we already know work.
`python -m eval_kg sample --n 20` writes `pentest_candidates.csv` (stratified by zone, CVSS band and whether a
public exploit is known; seed 7, so rerunning it gives the same file). For each row:

1. **Time box:** at most 1 hour per pair. Look for a public exploit or PoC, check the vulnerable feature is
   reachable or usable on that host, and try it.
2. Copy the row's `asset,cve` into `pentest_results.csv` with:
   - `yes`: exploited. Name the evidence file (`pentest/evidence/...`) in `notes`.
   - `no`: the vulnerable code path **was exercised** and the attack failed. Say how in `notes`.
   - `not_tried`: the time box ran out, no exploit exists, or the feature could not be reached (e.g. a library
     CVE in a tool nothing on the host calls). Say which in `notes`. This is not a negative.
3. Do **not** replace a drawn row with an easier one. Rows that were not drawn (hand-picked) are still welcome
   in `pentest_results.csv`, and the report keeps them apart (A1 vs A1s).

Don't redraw the sample after the team has started on it. If more pairs are needed, draw a fresh sample with a
new `--seed` and a larger `--n`; already-labelled pairs are left out automatically.

## Running

```powershell
python -m eval_kg measure                                       # Part B ground truth from the running lab
python -m eval_kg all                                           # both reports, labels from this folder
python -m eval_kg all --labels evaluation/dry_run               # pipeline test with the synthetic labels
```

## Changes 2026-11-17 (docs/PLAN.md §9)

Why: the earlier evaluation could not tell the EVS from plain CVSS. A1 has one exploited pair, A3 has none, and
the propagation term moved the score by at most +6%. What changed, and where:

| Change | Files | Effect on the reports |
|---|---|---|
| **Eq. 16 now uses the blast radius.** P(a,c) = 1 − Π_{v ∈ BR_k(a,c)\{a}} (1 − crit(v)·γ^d), a noisy-OR over Algorithm 1's set, in the CVE's impact direction. It replaces the sum over every reachable asset divided by \|V_A\| − 1. Paper (`docs/main_2.tex`) and `docs/scoring.md` updated to match | `score_kg/model.py`, `graph.py`, `run.py`, `explain.py`; `eval_kg/variants.py`, `run.py`, `kev_forward.py` | every EVS changes; P now ranges 0–0.75 in this lab and differs per CVE on the same host |
| **EVS ties at the cap of 10** are ordered by the uncapped Env·(1+βP) when ranking. The reported EVS keeps the cap | `score_kg/model.py` (`evs_uncapped`), `eval_kg/ladder.py` (`L4_raw`), `eval_kg/metrics.py` (`rank_key`) | the 126 capped pairs are ordered, not tied |
| **Tie-aware metrics.** Tied scores get the expected value over random orders within the tie (exact for NDCG/P@k, Monte Carlo for MRR/AP), instead of the item-id order | `eval_kg/metrics.py`, `run.py`, `kev_forward.py` | A1's L0 drops from an artifactual 1.000 to 0.710 |
| **AP** added to every ranking table | `eval_kg/metrics.py`, `run.py` | — |
| **Stratified paired bootstrap**: positives and negatives (or each grade) are resampled separately. Before, resamples without a positive were silently skipped | `eval_kg/metrics.py`, `run.py`, `kev_forward.py` | every resample is used |
| **Random baseline** (seeded per item) | `eval_kg/ladder.py` | chance level in every table |
| **New rung A4: measured consequence.** `python -m eval_kg consequence` grades every asset × CVE pair by the hosts the lab measured as affected in the CVE's impact mode, then scores L0–L4 and the baselines. Includes the same-CVE-on-different-hosts test and the count of CVSS ties the EVS breaks | `eval_kg/run.py` (`consequence`), `config.py`, `__main__.py`, `plots.py` (fig5) | `data/reports/eval_consequence.md` |
| **Part B: pooled metrics.** Precision/recall/F1 are micro-averaged over (host, affected host) pairs, so empty predictions and empty truths give no free credit; hosts with an empty truth are counted | `eval_kg/metrics.py` (`pooled_prf`), `run.py`, `plots.py` | B0 no longer scores F1 0.47 |
| **Part B: pentest-pivot check.** For each scenario's foothold (`attacker:`), the hosts the pentest reached against each variant's blast radius. Truth independent of the edges | `eval_kg/run.py`, `labels.py` (keeps `attacker`) | new table in `eval_blast_radius.md` |
| **Part B downstream** now puts each variant's set inside P(a,c) and ranks against the A4 labels, instead of NDCG@10 on A1's single positive | `eval_kg/run.py` | variants now differ downstream |
| **Sensitivity** attributes each asset's mean change to the ladder steps (+CR/IR/AR, +MAV, +E, +P) | `eval_kg/run.py` (`sensitivity`) | `eval_sensitivity.md` |
| `all` also runs `consequence` and `sensitivity` | `eval_kg/__main__.py` | — |
| Property tests for Eq. 16 (rung A0) and tests for the new metrics | `tests/test_score_offline.py`, `tests/test_eval_offline.py` | 101 tests pass |

What each rung can claim is listed in `docs/evaluation.md` (Part A table). In short, A4 shows that the EVS orders
vulnerabilities by the consequence measured in this lab, and that CVSS cannot. It is not an exploit-prediction
result. The edges and the measured sets share the lab design; the pentest-pivot check is the independent
counterpart.

A2 is empty on the current data: the alert store was rebuilt after the scenario windows (see
`docs/evaluation.md`, *Results 2026-11-17*). Rerun everything with:

```bash
python -m score_kg sensitivity        # β/γ grid (score_sensitivity.json)
python -m eval_kg all                 # Part B, A1/A2, A4, sensitivity
python -m eval_kg plot                # figures + data/reports/final_check_report.md
```
