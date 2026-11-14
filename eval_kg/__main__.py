"""CLI: python -m eval_kg {measure-reach,measure-usable,measure-deps,measure,blast-ablation,score-ablation,all}

  measure-reach    lab ground truth: TCP reachability between hosts      -> data/eval/observed_network_reach.json
  measure-usable   lab ground truth: hosts usable with stored credentials -> data/eval/observed_usable_reach.json
  measure-deps     lab ground truth: stop one host, see who fails          -> data/eval/observed_dependents.json
  measure          the three above
  blast-ablation   Part B: B0-B5 vs the measured sets               -> data/reports/eval_blast_radius.md
  score-ablation   Part A: L0-L4 + baselines vs pentest labels      -> data/reports/eval_score_ablation.md
  sensitivity      Part A: how the EVS reprioritises CVSS (inventory, no ground truth) -> data/reports/eval_sensitivity.md
  all              blast-ablation + score-ablation (uses existing measurements)
Labels: --labels evaluation (the real pentest record, default) or --labels evaluation/dry_run (synthetic test).
"""
import argparse
from pathlib import Path

from . import config


def main() -> None:
    ap = argparse.ArgumentParser(prog="eval_kg", description="Ground truth and ablation evaluation (stage 5).")
    ap.add_argument("command", choices=["measure-reach", "measure-usable", "measure-deps", "measure",
                                        "blast-ablation", "score-ablation", "sensitivity", "all"])
    ap.add_argument("--labels", type=Path, default=config.ROOT / "evaluation",
                    help="folder with scenarios/ and pentest_results.csv (evaluation/dry_run for the synthetic test)")
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
    if args.command == "sensitivity":
        run.sensitivity(wait=args.wait)


if __name__ == "__main__":
    main()
