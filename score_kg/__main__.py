"""CLI: python -m score_kg {epss-download,vulns,alerts,report,sensitivity,all}

  vulns          EVS of every asset x CVE (no alert, E = X) -> data/scores/asset_cve_scores.csv
  alerts         EVS of every alerted vulnerability instance (a, c) -> data/scores/alert_scores.csv,
                 structured JSON per instance in data/reports/assessments/, Alert.evs* in Neo4j
  report         vulns + alerts + data/reports/threat_report.md
  sensitivity    EVS ranking under other beta / gamma -> data/reports/score_sensitivity.md
  all            report + sensitivity
  epss-download  fetch EPSS scores (a baseline shown next to the EVS, not part of it)
  explain        attack paths, blast radius and EVS for one --cve / --technique / --tactic [--asset],
                 printed and written to Neo4j as Analysis/Score nodes for the Browser (not part of `all`)
"""
import argparse

from . import config


def main() -> None:
    ap = argparse.ArgumentParser(prog="score_kg", description="Environmental Vulnerability Score (paper §III.A.2-4).")
    ap.add_argument("command", choices=["epss-download", "vulns", "alerts", "report", "sensitivity", "all", "explain"])
    ex = ap.add_argument_group("explain (one input, for a demo; not part of `all`)")
    which = ex.add_mutually_exclusive_group()
    which.add_argument("--cve", help="e.g. CVE-2024-23897")
    which.add_argument("--technique", help="ATT&CK technique, e.g. T1574.010")
    which.add_argument("--tactic", help="ATT&CK tactic, e.g. TA0006")
    which.add_argument("--clear", action="store_true", help="remove every Analysis/Score node")
    ex.add_argument("--asset", help="target hostname (default: every asset the input links to)")
    ap.add_argument("--beta", type=float, default=config.BETA, help="uplift bound in EVS = Env(1 + beta P)")
    ap.add_argument("--gamma", type=float, default=config.GAMMA, help="distance discount in P(u), 0 < gamma < 1")
    ap.add_argument("--k", type=int, default=config.BLAST_K, help="blast-radius depth")
    ap.add_argument("--wait", type=int, default=60, help="seconds to wait for Neo4j")
    args = ap.parse_args()
    if not 0 < args.gamma < 1:
        ap.error("--gamma must be between 0 and 1")
    if args.beta < 0 or args.k < 0:
        ap.error("--beta and --k must be >= 0")

    if args.command == "explain":
        from . import explain
        if args.clear:
            explain.clear(args.wait)
            return
        kind = next((k for k in ("cve", "technique", "tactic") if getattr(args, k)), None)
        if kind is None:
            ap.error("explain needs --cve, --technique, --tactic or --clear")
        explain.explain(kind, getattr(args, kind), args.asset, args.beta, args.gamma, args.k, args.wait)
        return

    from . import run
    if args.command == "epss-download":
        from .epss import download
        download()
    elif args.command == "vulns":
        run.run_vulns(args.beta, args.gamma, args.wait)
    elif args.command == "alerts":
        run.run_alerts(args.beta, args.gamma, args.k, args.wait)
    elif args.command in ("report", "all"):
        run.run_report(args.beta, args.gamma, args.k, args.wait)
    if args.command in ("sensitivity", "all"):
        run.run_sensitivity(args.wait)


if __name__ == "__main__":
    main()
