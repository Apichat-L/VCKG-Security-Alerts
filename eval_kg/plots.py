"""Figures and the complementary report for the final check.

Reads the JSON side-outputs the stage-4/5 reports write next to their markdown (eval_blast_radius.json,
eval_score_ablation.json, eval_consequence.json, eval_sensitivity.json, score_sensitivity.json) and the live graph counts, and writes
PNGs to data/reports/figures/ plus data/reports/final_check_report.md. It computes nothing new: every number
plotted is one the reports already print.

Palette: the validated categorical slots in order (blue, orange, aqua; only three series are ever drawn on one
chart, the all-pairs cap), the single-hue blue ramp for magnitude / ladder order, neutral grey for everything
that is not the subject. Text is always ink, never the series colour.
"""
import json
import re
from datetime import date
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.patches import Patch  # noqa: E402

from . import config  # noqa: E402

BLUE, ORANGE, AQUA, GREY = "#2a78d6", "#eb6834", "#1baf7a", "#a9a8a3"
LADDER = {"L0": "#9ec5f4", "L1": "#6da7ec", "L2": "#3987e5", "L3": "#1c5cab", "L4": "#104281"}   # blue 200..650
INK, MUTED, GRID, SURFACE = "#0b0b0b", "#52514e", "#e6e5e1", "#fcfcfb"
FIGS = config.REPORTS / "figures"


def _n(x):
    return 0.0 if x is None else float(x)


def _load(path: Path):
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None


def _style(ax, grid_axis="y"):
    ax.set_facecolor(SURFACE)
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    for s in ("left", "bottom"):
        ax.spines[s].set_color(GRID)
    ax.tick_params(colors=MUTED, labelsize=8, length=0)
    ax.grid(axis=grid_axis, color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)
    ax.xaxis.label.set_color(MUTED)
    ax.yaxis.label.set_color(MUTED)


def _fig(w, h):
    fig = plt.figure(figsize=(w, h), facecolor=SURFACE)
    return fig


def _save(fig, name):
    FIGS.mkdir(parents=True, exist_ok=True)
    path = FIGS / name
    fig.savefig(path, dpi=160, facecolor=SURFACE, bbox_inches="tight")
    plt.close(fig)
    return path


# ------------------------------------------------------------------------------------------------- figures
def fig_blast(bp):
    sets = bp["per_asset"]
    variants = bp["variants"]
    fig = _fig(5.2 * len(sets), 3.8)
    axes = fig.subplots(1, len(sets), sharey=True)
    axes = [axes] if len(sets) == 1 else list(axes)
    for ax, (name, d) in zip(axes, sets.items()):
        _style(ax)
        xs = range(len(variants))
        for off, (key, col, lab) in zip((-0.27, 0, 0.27), (("pooled_precision", BLUE, "precision"),
                                                          ("pooled_recall", ORANGE, "recall"), ("pooled_f1", AQUA, "F1"))):
            ax.bar([x + off for x in xs], [_n(d["variants"][v].get(key)) for v in variants], width=0.24, color=col,
                   edgecolor=SURFACE, linewidth=1.2, label=lab)
        ax.set_xticks(list(xs))
        ax.set_xticklabels([v.replace(" (", "\n(") for v in variants], fontsize=7)
        ax.set_ylim(0, 1.05)
        ax.set_title(f"{name} truth ({d['mode']} mode)", fontsize=9, color=INK, loc="left")
        b4 = variants.index("B4")
        ax.annotate(f"B4  P {_n(d['variants']['B4'].get('pooled_precision')):.2f} / R {_n(d['variants']['B4'].get('pooled_recall')):.2f}",
                    (b4, 1.0), xytext=(0, 4), textcoords="offset points", ha="center", fontsize=7.5, color=INK)
    axes[0].set_ylabel("pooled over (host, affected host) pairs")
    axes[0].legend(frameon=False, fontsize=8, ncol=3, loc="lower left", bbox_to_anchor=(0, 1.1))
    fig.suptitle("Part B: blast-radius variants against what the lab measured", x=0.01, ha="left", fontsize=11, color=INK, y=1.16)
    return _save(fig, "fig1_blast_radius.png")


def fig_ladder(sp):
    sets = [(k, sp["sets"][k]) for k in ("A1",) if k in sp["sets"]]
    if not sets:
        return None
    fig = _fig(5.4 * len(sets), 3.6)
    axes = fig.subplots(1, len(sets))
    axes = [axes] if len(sets) == 1 else list(axes)
    for ax, (key, d) in zip(axes, sets):
        _style(ax)
        names = [k for k, m in d["scores"].items() if m.get("NDCG@10") is not None]
        vals = [d["scores"][k]["NDCG@10"] for k in names]
        ax.bar(range(len(names)), vals, width=0.6, color=[LADDER.get(k, GREY) for k in names], edgecolor=SURFACE, linewidth=1.2)
        for i, v in enumerate(vals):
            ax.annotate(f"{v:.2f}", (i, v), xytext=(0, 3), textcoords="offset points", ha="center", fontsize=8, color=INK)
        ax.set_xticks(range(len(names)))
        ax.set_xticklabels(names, fontsize=8)
        ax.set_ylim(0, 1.12)
        ax.set_ylabel("NDCG@10")
        size = (f"{d.get('n_items')} pairs, {d.get('n_positive')} exploited" if key == "A1"
                else f"{d.get('n_scenarios')} scenarios, {d.get('n_instances')} instances")
        ax.set_title(f"{key} ({size})", fontsize=9, color=INK, loc="left")
    handles = [Patch(color=LADDER["L2"], label="our ladder L0-L4 (light to dark)"), Patch(color=GREY, label="baselines")]
    axes[0].legend(handles=handles, frameon=False, fontsize=8, loc="lower left", bbox_to_anchor=(0, 1.1), ncol=2)
    fig.suptitle("Part A: ranking quality of each ladder level and baseline", x=0.01, ha="left", fontsize=11, color=INK, y=1.16)
    return _save(fig, "fig2_score_ladder.png")


def fig_consequence(cq):
    """Part A4: each score against the consequence measured in the lab."""
    fig = _fig(11.4, 4.1)
    ax1, ax2 = fig.subplots(1, 2)
    names = list(cq["scores"])
    colors = [LADDER.get(k, GREY) for k in names]
    _style(ax1)
    vals = [_n(cq["scores"][k]["NDCG@50"]) for k in names]
    ax1.bar(range(len(names)), vals, width=0.6, color=colors, edgecolor=SURFACE, linewidth=1.2)
    for i, v in enumerate(vals):
        ax1.annotate(f"{v:.2f}", (i, v), xytext=(0, 3), textcoords="offset points", ha="center", fontsize=7.5, color=INK)
    ax1.set_xticks(range(len(names)))
    ax1.set_xticklabels(names, fontsize=8, rotation=35, ha="right")
    ax1.set_ylim(0, max(vals) * 1.25)
    ax1.set_ylabel("NDCG@50 (tie-aware)")
    ax1.set_title(f"{cq['n_items']} asset x CVE pairs, graded by measured consequence", fontsize=9, color=INK, loc="left")

    _style(ax2)
    same = cq["same_cve"]["scores"]
    vals = [_n(same[k]["concordance"]) for k in names]
    lo = [v - _n(same[k]["lo"]) for k, v in zip(names, vals)]
    hi = [_n(same[k]["hi"]) - v for k, v in zip(names, vals)]
    ax2.bar(range(len(names)), vals, width=0.6, color=colors, edgecolor=SURFACE, linewidth=1.2,
            yerr=[lo, hi], error_kw={"ecolor": MUTED, "elinewidth": 0.9, "capsize": 2})
    for i, v in enumerate(vals):
        ax2.annotate(f"{v:.2f}", (i, v), xytext=(0, 6), textcoords="offset points", ha="center", fontsize=7.5, color=INK)
    ax2.axhline(0.5, color=MUTED, linewidth=0.9, linestyle=(0, (4, 3)))
    ax2.set_xticks(range(len(names)))
    ax2.set_xticklabels(names, fontsize=8, rotation=35, ha="right")
    ax2.set_ylim(0, 1.12)
    ax2.set_ylabel("share ordered like the lab")
    ax2.set_title(f"Same CVE on different hosts ({cq['same_cve']['n_cves']} CVEs, "
                  f"{same['L0']['pairs']} host pairs; dashed = tie / chance)", fontsize=9, color=INK, loc="left")
    handles = [Patch(color=LADDER["L2"], label="our ladder L0-L4 (light to dark)"), Patch(color=GREY, label="baselines")]
    ax1.legend(handles=handles, frameon=False, fontsize=8, loc="lower left", bbox_to_anchor=(0, 1.1), ncol=2)
    fig.suptitle("Part A4: ranking by the consequence measured in the lab", x=0.01, ha="left", fontsize=11, color=INK, y=1.16)
    return _save(fig, "fig6_consequence.png")


def fig_sensitivity(se):
    fig = _fig(10.4, 4.0)
    ax1, ax2 = fig.subplots(1, 2, gridspec_kw={"width_ratios": [1.1, 1]})
    _style(ax1, "both")
    dmz = {"Nginx", "Web", "DNS", "Mail"}           # the internet-exposed zone (lab/assets.csv)
    groups = [("other assets", GREY, lambda a: a not in dmz and a != "Dep-PC", 0.55),
              ("DMZ, internet-exposed (Nginx, Web, DNS, Mail)", BLUE, lambda a: a in dmz, 0.8),
              ("Dep-PC (isolated, L/L/L)", ORANGE, lambda a: a == "Dep-PC", 0.9)]
    for lab, col, pred, alpha in groups:
        pts = [p for p in se["pairs"] if pred(p["asset"])]
        ax1.scatter([p["L0"] for p in pts], [p["L4"] for p in pts], s=16, color=col, alpha=alpha, linewidths=0.6,
                    edgecolors=SURFACE, label=f"{lab} (n={len(pts)})")
    ax1.plot([0, 10], [0, 10], color=MUTED, linewidth=0.9, linestyle=(0, (4, 3)))
    ax1.set_xlim(2, 10.2)
    ax1.set_ylim(2, 10.2)
    ax1.set_xlabel("CVSS base (L0)")
    ax1.set_ylabel("EVS (L4)")
    ax1.set_title(f"{len(se['pairs'])} asset x CVE pairs: EVS vs CVSS  (tau-b {se['kendall']['tau_b']:.2f})", fontsize=9, color=INK,
                  loc="left")
    ax1.legend(frameon=False, fontsize=7.5, loc="upper left")
    ax1.text(0.98, 0.04, "dashed line: EVS equals CVSS", transform=ax1.transAxes, ha="right", fontsize=7.5, color=MUTED)

    _style(ax2, "x")
    rows = sorted(se["per_asset"], key=lambda r: r["mean"])
    ax2.barh([r["asset"] for r in rows], [r["mean"] for r in rows], height=0.55,
             color=[BLUE if r["mean"] >= 0 else ORANGE for r in rows], edgecolor=SURFACE)
    for i, r in enumerate(rows):
        ax2.annotate(f"{r['mean']:+.2f}", (r["mean"], i), xytext=(4 if r["mean"] >= 0 else -4, 0), textcoords="offset points",
                     ha="left" if r["mean"] >= 0 else "right", va="center", fontsize=8, color=INK)
    ax2.axvline(0, color=MUTED, linewidth=0.9)
    ax2.set_xlabel("mean change, EVS minus CVSS base")
    ax2.set_xlim(min(r["mean"] for r in rows) - 0.7, max(r["mean"] for r in rows) + 0.7)
    ax2.set_title("Direction of the change, per asset", fontsize=9, color=INK, loc="left")
    fig.suptitle("Sensitivity analysis (mechanism only, not ground truth)", x=0.01, ha="left", fontsize=11, color=INK, y=1.03)
    fig.tight_layout()
    return _save(fig, "fig3_evs_vs_cvss.png")


def fig_grid(gs):
    betas = sorted({g["beta"] for g in gs["grid"]})
    gammas = sorted({g["gamma"] for g in gs["grid"]})
    cell = {(g["beta"], g["gamma"]): g for g in gs["grid"]}
    fig = _fig(5.2, 3.8)
    ax = fig.subplots()
    ax.set_facecolor(SURFACE)
    lo = min(g["tau"] for g in gs["grid"])
    import numpy as np
    z = np.array([[cell[(b, gm)]["tau"] for gm in gammas] for b in betas])
    im = ax.imshow(z, cmap="Blues", vmin=min(lo, 0.9) - 0.02, vmax=1.0, aspect="auto", origin="lower")
    for i, b in enumerate(betas):
        for j, gm in enumerate(gammas):
            c = cell[(b, gm)]
            dark = c["tau"] > (1.0 + min(lo, 0.9)) / 2
            ax.text(j, i, f"{c['tau']:.3f}\n{c['top10_overlap']}/10 top-10", ha="center", va="center", fontsize=7.5,
                    color="#ffffff" if dark else INK)
    ax.set_xticks(range(len(gammas)))
    ax.set_xticklabels([f"{x:g}" for x in gammas], fontsize=8, color=MUTED)
    ax.set_yticks(range(len(betas)))
    ax.set_yticklabels([f"{x:g}" for x in betas], fontsize=8, color=MUTED)
    ax.set_xlabel("gamma (distance discount)", color=MUTED)
    ax.set_ylabel("beta (uplift bound)", color=MUTED)
    for s in ax.spines.values():
        s.set_visible(False)
    ax.tick_params(length=0)
    ax.set_title(f"EVS ranking vs the default (beta {gs['ref_beta']:g}, gamma {gs['ref_gamma']:g}): Kendall tau-b", fontsize=9,
                 color=INK, loc="left")
    fig.colorbar(im, ax=ax, fraction=0.045, pad=0.03).ax.tick_params(labelsize=7, colors=MUTED)
    return _save(fig, "fig4_beta_gamma.png")


def parse_stats(text: str) -> dict:
    """Rows of cti_kg's stats tables ('| name | ours | paper |') -> {name: ours}."""
    out = {}
    for m in re.finditer(r"^\|\s*([^|]+?)\s*\|\s*(\d+)\s*\|", text, re.M):
        out[m.group(1)] = int(m.group(2))
    return out


def fig_build(after: tuple[dict, dict], before: dict | None):
    nodes, edges = after
    fig = _fig(11, 5.4)
    axes = fig.subplots(1, 2, gridspec_kw={"width_ratios": [1, 1.5]})
    for ax, data, title in ((axes[0], nodes, "Nodes by label"), (axes[1], edges, "Edges by type")):
        _style(ax, "x")
        keys = sorted(data, key=lambda k: data[k])
        ys = range(len(keys))
        if before:
            have = [(y, before[k]) for y, k in zip(ys, keys) if before.get(k, 0) > 0]      # no bar where nothing was recorded
            ax.barh([y + 0.19 for y, _ in have], [v for _, v in have], height=0.34, color=ORANGE, edgecolor=SURFACE,
                    label="before wipe")
        ax.barh([y - 0.19 if before else y for y in ys], [max(data[k], 0.8) for k in keys], height=0.34 if before else 0.6,
                color=BLUE, edgecolor=SURFACE, label="after rebuild")
        ax.set_xscale("log")
        ax.set_yticks(list(ys))
        ax.set_yticklabels(keys, fontsize=6.5)
        ax.set_title(title, fontsize=9, color=INK, loc="left")
        ax.set_xlabel("count (log scale)")
    axes[0].legend(frameon=False, fontsize=8, loc="lower right")
    fig.text(0.01, -0.01, "No 'before wipe' bar means the pre-wipe stats did not record that label or edge type (the saved "
             "`cti_kg stats` output lists only the CTI labels), not that it was zero.", fontsize=7.5, color=MUTED, ha="left")
    fig.suptitle("Graph build: wiped and rebuilt from the cached sources", x=0.01, ha="left", fontsize=11, color=INK, y=1.0)
    fig.tight_layout()
    return _save(fig, "fig5_graph_build.png")


# ------------------------------------------------------------------------------------------------- report
def _f(x, nd=3):
    return "-" if x is None else f"{x:.{nd}f}"


def _ci(b):
    if not b or b.get("diff") is None:
        return "-"
    if b.get("lo") is None:
        return f"{b['diff']:+.3f}"
    return f"{b['diff']:+.3f} [{b['lo']:+.3f}, {b['hi']:+.3f}]" + (" *" if b["lo"] > 0 or b["hi"] < 0 else "")


def _score_tables(sp):
    L = []
    for key in ("A1", "A2"):
        d = sp["sets"].get(key)
        if not d:
            L += [f"### {key}", "", "No labelled data in this run.", ""]
            continue
        L += [f"### {d['title']}", "", d["note"], "", "| Score | NDCG@5 | NDCG@10 | P@5 | P@10 | MRR | AP |",
              "|---|---:|---:|---:|---:|---:|---:|"]
        for k, m in d["scores"].items():
            L.append(f"| {k} | {_f(m['NDCG@5'])} | {_f(m['NDCG@10'])} | {_f(m['P@5'])} | {_f(m['P@10'])} | {_f(m['MRR'])} | "
                     f"{_f(m.get('AP'))} |")
        L += ["", "| Comparison | change in NDCG@10 [95% CI] (* = CI excludes 0) |", "|---|---|"]
        L += [f"| {n} | {_ci(b)} |" for n, b in d["gains"].items()]
        if key == "A2":
            L += ["", "Scenarios scored: " + "; ".join(f"{s['id']} (n={s['n']}, grades {s['grades']})" for s in d.get("scenarios", [])), ""]
        L.append("")
    return L


def build_report(notes: str, figs: dict, bp, sp, se, gs, cq=None) -> Path:
    L = [f"# Final check: full rebuild, validation and results ({date.today().isoformat()})", ""]
    if notes:
        L += [notes.strip(), ""]
    if "build" in figs:
        L += ["## Graph build", "", f"![graph build]({figs['build'].relative_to(config.REPORTS).as_posix()})", ""]
    if bp:
        L += ["## Part B: blast radius against the lab's measured ground truth", "",
              f"![blast radius]({figs['blast'].relative_to(config.REPORTS).as_posix()})", "",
              "Measured: " + "; ".join(f"{k} {v}" for k, v in bp["measured_at"].items()) + ".", ""]
        if bp["per_pair"]:
            L += ["Per (asset, CVE) pair, pooled over (host, affected host) pairs:", "",
                  "| Variant | Precision | Recall | F1 |", "|---|---:|---:|---:|"]
            L += [f"| {v} | {_f(m.get('pooled_precision'))} | {_f(m.get('pooled_recall'))} | {_f(m.get('pooled_f1'))} |"
                  for v, m in bp["per_pair"].items()]
            L.append("")
        pv = bp.get("pentest_pivots") or {}
        if pv.get("recall"):
            L += ["Hosts the pentest reached from its foothold (independent of the edges): pooled recall per variant, "
                  "and hosts predicted per foothold:", "", "| Variant | Recall | Predicted per foothold |", "|---|---:|---:|"]
            L += [f"| {v} | {_f(r)} | {_f(pv['mean_predicted'][v], 1)} |" for v, r in pv["recall"].items()] + [""]
        if bp["downstream_ndcg10"] and isinstance(next(iter(bp["downstream_ndcg10"].values())), dict):
            L += ["EVS with each variant's set inside P(a,c), ranked against the A4 consequence labels:", "",
                  "| Variant | NDCG@50 | AP | Kendall tau-b | Same-CVE concordance |", "|---|---:|---:|---:|---:|"]
            L += [f"| {v} | {_f(m['NDCG@50'])} | {_f(m['AP'])} | {_f(m['tau_b'])} | {_f(m['same_cve'])} |"
                  for v, m in bp["downstream_ndcg10"].items()] + [""]
    if cq:
        L += ["## Part A4: ranking by the consequence measured in the lab", "",
              f"![consequence]({figs['cons'].relative_to(config.REPORTS).as_posix()})" if "cons" in figs else "", "",
              f"{cq['n_items']} asset x CVE pairs, {cq['n_positive']} with a measured consequence (prevalence "
              f"{cq['prevalence']:.2f}). Full tables: `eval_consequence.md`.", "",
              "| Score | NDCG@50 | AP | Kendall tau-b | Same-CVE concordance |", "|---|---:|---:|---:|---:|"]
        L += [f"| {k} | {_f(m['NDCG@50'])} | {_f(m['AP'])} | {_f(m['tau_b'])} | "
              f"{_f(cq['same_cve']['scores'][k]['concordance'])} |" for k, m in cq["scores"].items()]
        L += ["", "| Comparison | change in NDCG@50 [95% CI] |", "|---|---|"]
        L += [f"| {n} | {_ci(b)} |" for n, b in cq["gains"].items()] + [""]
    if sp:
        L += ["## Part A: score ladder against pentest ground truth", "",
              f"![score ladder]({figs['ladder'].relative_to(config.REPORTS).as_posix()})" if "ladder" in figs else "", ""]
        L += _score_tables(sp)
    if se:
        k = se["kendall"]
        L += ["## Sensitivity: how the EVS reprioritises CVSS (mechanism only, not ground truth)", "",
              f"![EVS vs CVSS]({figs['sens'].relative_to(config.REPORTS).as_posix()})", "",
              f"Kendall tau-b {_f(k['tau_b'])}; {k['discordant']} of {k['total_pairs']} pairs reorder; "
              f"{se['material_reorderings']} cross-asset reorderings with a CVSS gap of at least 0.5.", "",
              "| Asset | CR/IR/AR | Internet-reachable | Mean change | Median change | CVEs |", "|---|:--:|:--:|--:|--:|--:|"]
        L += [f"| {r['asset']} | {r['cr']}/{r['ir']}/{r['ar']} | {'yes' if r['internet'] else 'no'} | {r['mean']:+.2f} | "
              f"{r['median']:+.2f} | {r['n']} |" for r in sorted(se["per_asset"], key=lambda r: r["mean"])] + [""]
    if gs:
        taus = [g["tau"] for g in gs["grid"]]
        L += ["## Parameter sensitivity (beta, gamma)", "", f"![beta gamma]({figs['grid'].relative_to(config.REPORTS).as_posix()})", "",
              f"Across the {len(taus)} settings, Kendall tau-b against the default ranges {min(taus):.3f} to {max(taus):.3f}. "
              "This is the stability of the score's own ranking; it is not tuning against ground truth.", ""]
    path = config.REPORTS / "final_check_report.md"
    path.write_text("\n".join(L) + "\n", encoding="utf-8")
    return path


def plot(notes_file: Path | None = None, before_file: Path | None = None) -> None:
    R = config.REPORTS
    bp = _load(R / "eval_blast_radius.json")
    sp = _load(R / "eval_score_ablation.json")
    se = _load(R / "eval_sensitivity.json")
    gs = _load(R / "score_sensitivity.json")
    cq = _load(R / "eval_consequence.json")
    figs = {}
    if cq:
        figs["cons"] = fig_consequence(cq)
    if bp:
        figs["blast"] = fig_blast(bp)
    if sp:
        p = fig_ladder(sp)
        if p:
            figs["ladder"] = p
    if se:
        figs["sens"] = fig_sensitivity(se)
    if gs:
        figs["grid"] = fig_grid(gs)
    try:
        from cti_kg.load.neo4j_loader import db_counts
        before = parse_stats(before_file.read_text(encoding="utf-8")) if before_file and before_file.exists() else None
        figs["build"] = fig_build(db_counts(), before)
    except Exception as e:                                  # the graph may be unreachable; the other figures stand alone
        print(f"graph-build figure skipped: {e}")
    notes = notes_file.read_text(encoding="utf-8") if notes_file and notes_file.exists() else ""
    path = build_report(notes, figs, bp, sp, se, gs, cq)
    print(f"{len(figs)} figures -> {FIGS}; report -> {path}")
