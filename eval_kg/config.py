"""Settings for stage 5 (evaluation). See docs/evaluation.md for the protocol."""
import os

from asset_kg.config import ROOT

LAB_COMPOSE = ROOT / "lab_env" / "docker-compose.yml"
CHECKS_CSV = ROOT / "lab_env" / "eval" / "checks.csv"
HARVEST_SH = ROOT / "lab_env" / "eval" / "harvest.sh"

# Lab hosts: asset hostname (as in lab/assets.csv) -> docker compose service. This only names the hosts; it says
# nothing about how they depend on each other, which is what the measurements observe.
SERVICES = {"Nginx": "nginx", "Web": "web", "API": "api", "Jenkins": "jenkins", "PostgreSQL": "postgresql",
            "Files-SMB": "files-smb", "Admin-PC": "admin-pc", "Dep-PC": "dep-pc",
            "DNS": "dns", "Mail": "mail", "HR-App": "hr-app", "Gitea": "gitea", "HR-DB": "hr-db", "Redis": "redis",
            "Dev-PC": "dev-pc", "Jump": "jump", "Monitoring": "monitoring"}
# network reachability probe: every TCP port any host serves (DNS also answers on 53/tcp)
PROBE_PORTS = [22, 25, 53, 80, 143, 443, 445, 3000, 3306, 5432, 6379, 8080]

OBSERVED = ROOT / "data" / "eval"                        # measured ground truth (git-ignored, regenerated)
OBSERVED_NETWORK = OBSERVED / "observed_network_reach.json"
OBSERVED_USABLE = OBSERVED / "observed_usable_reach.json"
OBSERVED_DEPENDENTS = OBSERVED / "observed_dependents.json"

SCENARIOS = ROOT / "evaluation" / "scenarios"            # pentest record (Part A ground truth), committed
PENTEST_RESULTS = ROOT / "evaluation" / "pentest_results.csv"
DRY_RUN = ROOT / "evaluation" / "dry_run"                # synthetic, pipeline test only

REPORTS = ROOT / "data" / "reports"
SCORE_REPORT = REPORTS / "eval_score_ablation.md"
BLAST_REPORT = REPORTS / "eval_blast_radius.md"
SENSITIVITY_REPORT = REPORTS / "eval_sensitivity.md"
KEV_FORWARD_REPORT = REPORTS / "eval_kev_forward.md"
CONSEQUENCE_REPORT = REPORTS / "eval_consequence.md"

# Wazuh vulnerability detection (docs/PLAN.md §8)
WAZUH_PAIRS = OBSERVED / "wazuh_pairs.csv"                 # snapshot of the states index, one row per (asset, CVE)
PENTEST_CANDIDATES = ROOT / "evaluation" / "pentest_candidates.csv"   # sampled A1 targets, committed
SAMPLE_SIZE = int(os.getenv("EVAL_SAMPLE_SIZE", "20"))
SAMPLE_EXPLOIT_SHARE = float(os.getenv("EVAL_SAMPLE_EXPLOIT_SHARE", "0.5"))  # share drawn from exploit-available pairs
KEV_T0 = os.getenv("EVAL_KEV_T0", "2026-05-01")             # forward-in-time KEV test cut-off
EPSS_HISTORY_URL = os.getenv("EPSS_HISTORY_URL", "https://epss.empiricalsecurity.com/epss_scores-{date}.csv.gz")
EPSS_HISTORY = ROOT / "data" / "raw" / "epss"

MATCH_SLACK_SECONDS = int(os.getenv("EVAL_MATCH_SLACK", "120"))   # alert <-> pentest step time tolerance
BOOTSTRAP = int(os.getenv("EVAL_BOOTSTRAP", "1000"))
SEED = int(os.getenv("EVAL_SEED", "7"))
