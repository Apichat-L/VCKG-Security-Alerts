"""CLI: python -m eval_kg {measure-reach,measure-usable,measure-deps,measure,blast-ablation,score-ablation,all}

  measure-reach    lab ground truth: TCP reachability between hosts      -> data/eval/observed_network_reach.json
  measure-usable   lab ground truth: hosts usable with stored credentials -> data/eval/observed_usable_reach.json
  measure-deps     lab ground truth: stop one host, see who fails          -> data/eval/observed_dependents.json
  measure          the three above
  blast-ablation   Part B: B0-B5 vs the measured sets               -> data/reports/eval_blast_radius.md
  score-ablation   Part A: L0-L4 + baselines vs pentest labels      -> data/reports/eval_score_ablation.md
  sensitivity      Part A: how the EVS reprioritises CVSS (inventory, no ground truth) -> data/reports/eval_sensitivity.md
  wazuh-pairs      snapshot of Wazuh vulnerability detection, one row per (asset, CVE) -> data/eval/wazuh_pairs.csv
  sample           draw pentest targets for A1 from Wazuh pairs ∪ graph links -> evaluation/pentest_candidates.csv
  consequence      Part A4: L0-L4 + baselines vs the consequence measured in the lab -> data/reports/eval_consequence.md
  kev-forward      Part A3: forward-in-time KEV test on the Wazuh inventory -> data/reports/eval_kev_forward.md
  plot             figures (data/reports/figures/) + data/reports/final_check_report.md from the reports' JSON
  all              blast-ablation + score-ablation + consequence + sensitivity (uses existing measurements)
Labels: --labels evaluation (the real pentest record, default) or --labels evaluation/dry_run (synthetic test).
"""
import argparse
from pathlib import Path

from . import config


def main() -> None:
    ap = argparse.ArgumentParser(prog="eval_kg", description="Ground truth and ablation evaluation (stage 5).")
    ap.add_argument("command", choices=["measure-reach", "measure-usable", "measure-deps", "measure",
                                        "blast-ablation", "score-ablation", "sensitivity", "plot", "all",
                                        "wazuh-pairs", "sample", "kev-forward", "consequence"])
    ap.add_argument("--notes", type=Path, help="plot: markdown (build, validation, caveats) placed at the top of the report")
    ap.add_argument("--before", type=Path, help="plot: saved `cti_kg stats` output from before the wipe, for the build figure")
    ap.add_argument("--labels", type=Path, default=config.ROOT / "evaluation",
                    help="folder with scenarios/ and pentest_results.csv (evaluation/dry_run for the synthetic test)")
    ap.add_argument("--n", type=int, default=config.SAMPLE_SIZE, help="sample: number of pairs to draw")
    ap.add_argument("--seed", type=int, default=config.SEED, help="sample: random seed")
    ap.add_argument("--t0", default=config.KEV_T0, help="kev-forward: cut-off date (YYYY-MM-DD)")
    ap.add_argument("--wait", type=int, default=60)
    args = ap.parse_args()

    from . import measure, run
    if args.command in ("measure-reach", "measure"):
        measure.measure_reach()
    if args.command in ("measure-usable", "measure"):
        measure.measure_usable()
    if args.command in ("measure-deps", "measure"):
        measure.measure_deps()
    if args.command in ("blast-ablation", "all"):
        run.blast_ablation(args.labels, wait=args.wait)
    if args.command in ("score-ablation", "all"):
        run.score_ablation(args.labels, wait=args.wait)
    if args.command in ("consequence", "all"):
        run.consequence(wait=args.wait)
    if args.command in ("sensitivity", "all"):
        run.sensitivity(wait=args.wait)
    if args.command == "wazuh-pairs":
        from . import wazuh_pairs
        wazuh_pairs.export()
    if args.command == "sample":
        from . import sample
        sample.run(args.n, args.seed, wait=args.wait)
    if args.command == "kev-forward":
        from . import kev_forward
        kev_forward.run(args.t0, wait=args.wait)
    if args.command == "plot":
        from . import plots
        plots.plot(args.notes, args.before)


if __name__ == "__main__":
    main()
