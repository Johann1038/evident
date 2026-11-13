"""Aggregate results into paper tables (JSON) and figures (PNG). Reads data/results only."""
from __future__ import annotations

import json
import statistics as st
import sys
from collections import Counter, defaultdict
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
RES = ROOT / "data" / "results"
FIG = ROOT / "paper" / "figures"
plt.rcParams.update({"font.family": "serif", "font.size": 8, "axes.spines.top": False, "axes.spines.right": False,
                     "figure.dpi": 300, "savefig.bbox": "tight", "axes.titlesize": 8})
LABEL = {"version_match": "Version match (SBOM scanner)", "coral_style": "CORAL-style coefficients",
         "cape_style": "CAPE-style weighted score", "logistic": "Logistic regression",
         "logistic_iso": "Logistic + isotonic", "evident": "EVIDENT staged model"}
STRAT = {"audit_fix": "Minimal fix (pip-audit style)", "latest": "Latest version", "upgrade_all": "Upgrade all",
         "vm_opt": "Optimiser, version-match weights (KEVGraph-like)", "coral_opt": "Optimiser, CORAL-style weights",
         "cape_opt": "Optimiser, CAPE-style weights", "evident": "EVIDENT (calibrated weights)"}


def load_realworld():
    out = []
    for d in sorted((RES / "realworld").glob("*/result.json")):
        out.append(json.loads(d.read_text("utf8")))
    return out


def fig_reliability(ev):
    fig, ax = plt.subplots(figsize=(3.2, 2.6))
    ax.plot([0, 1], [0, 1], ls=":", c="0.5", lw=0.8)
    mk = {"version_match": "s", "coral_style": "^", "cape_style": "v", "logistic_iso": "D", "evident": "o"}
    for m, pts in ev["reliability"].items():
        if not pts:
            continue
        x, y, n = zip(*pts)
        ax.plot(x, y, marker=mk.get(m, "o"), ms=3.5, lw=1.0 if m == "evident" else 0.7,
                c="k" if m == "evident" else None, label=LABEL[m])
    ax.set_xlabel("Predicted exposure probability")
    ax.set_ylabel("Observed exposure rate")
    ax.set_xlim(-0.02, 1.02)
    ax.set_ylim(-0.02, 1.02)
    ax.legend(fontsize=6, frameon=False, loc="upper left")
    fig.savefig(FIG / "reliability.png")
    plt.close(fig)


def fig_missingness(ev):
    rob = ev.get("missingness") or {}
    if not rob:
        return
    qs = sorted(rob, key=float)
    fig, ax = plt.subplots(figsize=(3.2, 2.4))
    mk = {"evident": "o", "logistic_iso": "D", "coral_style": "^", "cape_style": "v"}
    for m in ("evident", "logistic_iso", "coral_style", "cape_style"):
        ax.plot([100 * float(q) for q in qs], [rob[q][m]["ece"] for q in qs], marker=mk[m], ms=3.5,
                lw=1.1 if m == "evident" else 0.7, c="k" if m == "evident" else None, label=LABEL[m])
    ax.set_xlabel("Static/runtime evidence missing (%)")
    ax.set_ylabel("Expected calibration error")
    ax.legend(fontsize=6, frameon=False)
    fig.savefig(FIG / "missingness.png")
    plt.close(fig)


def fig_architecture():
    from matplotlib.patches import FancyArrowPatch, FancyBboxPatch
    fig, ax = plt.subplots(figsize=(6.2, 2.5))
    ax.set_xlim(0, 100)
    ax.set_ylim(0, 40)
    ax.axis("off")
    boxes = {
        "lock": (1, 27, 15, 9, "Lockfile +\nmanifest"),
        "res": (19, 27, 17, 9, "Target-env\nresolution\n(markers, scope)"),
        "intel": (19, 14, 17, 9, "OSV / CVSS /\nEPSS / KEV\n(dated snapshot)"),
        "match": (39, 27, 17, 9, "Findings\nL1 L2 L3"),
        "code": (39, 14, 17, 9, "Cross-package\nstatic analysis\nL3b L4"),
        "sym": (19, 1, 17, 9, "Fix-commit\nsymbol mining"),
        "rt": (39, 1, 17, 9, "Runtime traces\nL5 (optional)"),
        "model": (59, 20, 17, 11, "Staged exposure\nmodel\nP(Y|E) calibrated"),
        "opt": (79, 27, 20, 9, "CP-SAT remediation\n+ resolver loop (uv)"),
        "loop": (79, 14, 20, 9, "Re-resolve, SBOM,\nre-scan: realised\nrisk & drift"),
        "vex": (79, 1, 20, 9, "VEX / SBOM,\nEVPI: what to\ninvestigate"),
    }
    for k, (x, y, w, h, t) in boxes.items():
        ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.3,rounding_size=1.2",
                                    fc="0.93" if k in ("model", "opt") else "white", ec="0.2", lw=0.7))
        ax.text(x + w / 2, y + h / 2, t, ha="center", va="center", fontsize=6.2)

    def arr(a, b, ya=None, yb=None):
        xa, y0, wa, ha, _ = boxes[a]
        xb, y1, wb, hb, _ = boxes[b]
        p0 = (xa + wa, ya if ya is not None else y0 + ha / 2)
        p1 = (xb, yb if yb is not None else y1 + hb / 2)
        ax.add_patch(FancyArrowPatch(p0, p1, arrowstyle="-|>", mutation_scale=7, lw=0.6, color="0.25"))
    arr("lock", "res")
    arr("res", "match")
    arr("intel", "match", yb=29)
    arr("match", "model", yb=28)
    arr("code", "model", yb=25)
    arr("rt", "model", yb=22)
    arr("model", "opt")
    arr("model", "vex", yb=6)
    arr("sym", "code", yb=16)
    ax.add_patch(FancyArrowPatch((89, 27), (89, 23.2), arrowstyle="<|-|>", mutation_scale=7, lw=0.6, color="0.25"))
    fig.savefig(FIG / "architecture.png")
    plt.close(fig)


def fig_evidence_funnel(rw):
    cls = Counter()
    for r in rw:
        for f in json.loads((RES / "realworld" / r["id"] / "findings.json").read_text("utf8")):
            cls[f["exposure_class"]] += 1
    order = ["NOT_INSTALLED", "DEV_ONLY", "NOT_IMPORTED", "STATICALLY_UNREACHABLE", "INSTALLED_UNKNOWN",
             "IMPORTED_REACH_UNKNOWN", "POSSIBLY_REACHABLE", "STATICALLY_REACHABLE", "RUNTIME_OBSERVED"]
    names = [o for o in order if cls.get(o)]
    vals = [cls[o] for o in names]
    fig, ax = plt.subplots(figsize=(4.6, 2.3))
    ax.barh(range(len(names)), vals, color="0.35")
    ax.set_yticks(range(len(names)))
    ax.set_yticklabels([n.replace("_", " ").title() for n in names], fontsize=7)
    ax.invert_yaxis()
    tot = sum(vals)
    for i, v in enumerate(vals):
        ax.text(v, i, f" {v} ({100 * v / tot:.1f}%)", va="center", fontsize=6)
    ax.set_xlabel("Version-matched findings")
    ax.set_xlim(0, max(vals) * 1.25)
    fig.savefig(FIG / "exposure_classes.png")
    plt.close(fig)
    return dict(cls)


def fig_pareto(rw):
    fig, ax = plt.subplots(figsize=(3.2, 2.5))
    R_e, C_e, R_v, C_v = defaultdict(list), defaultdict(list), defaultdict(list), defaultdict(list)
    for r in rw:
        pe, pv = r.get("pareto_evident") or [], r.get("pareto_vm") or []
        if not pe or not pv:
            continue
        r0e = max(p["risk"] for p in pe) or 1
        r0v = max(p["risk"] for p in pv) or 1
        for p in pe:
            R_e[p["lambda"]].append(p["risk"] / r0e)
            C_e[p["lambda"]].append(p["changes"])
        for p in pv:
            R_v[p["lambda"]].append(p["risk"] / r0v)
            C_v[p["lambda"]].append(p["changes"])
    for R, C, lab, m in ((R_e, C_e, "EVIDENT weights", "o"), (R_v, C_v, "Version-match weights", "s")):
        lams = sorted(R)
        ax.plot([np.mean(C[l]) for l in lams], [np.mean(R[l]) for l in lams], marker=m, ms=3, lw=0.9, label=lab)
    ax.set_xlabel("Mean packages changed per project")
    ax.set_ylabel("Residual risk (fraction of max.)")
    ax.legend(fontsize=6, frameon=False)
    fig.savefig(FIG / "pareto.png")
    plt.close(fig)


def tables(ev, rw):
    T = {}
    T["bench"] = {k: ev[k] for k in ("n_rows", "n_packages", "n_advisories", "label_rate")}
    T["bench_methods"] = ev["methods"]
    T["bench_confusion"] = ev["analysis_confusion"]
    T["bench_patterns"] = ev["verdicts_by_pattern"]
    ok = [r for r in rw if r.get("status") == "ok"]
    T["realworld_n"] = {"snapshots": len(rw), "resolvable": len(ok),
                        "lock_kinds": dict(Counter(r["meta"]["lock_kind"] for r in rw)),
                        "unresolvable": [r["id"] for r in rw if r.get("status") != "ok"]}
    agg = defaultdict(list)
    for r in rw:
        s = r["summary"]
        agg["installed"].append(s["installed"])
        agg["direct"].append(s["direct"])
        agg["transitive"].append(s["transitive"])
        fs = json.loads((RES / "realworld" / r["id"] / "findings.json").read_text("utf8"))
        agg["findings"].append(len(fs))
        agg["vuln_pkgs"].append(len({f["package"] for f in fs}))
        agg["transitive_findings_share"].append(
            sum(1 for f in fs if not f["direct"]) / len(fs) if fs else 0)
        live = [f for f in fs if f.get("L3_state") == "CONFIRMED"]
        exp = sum(f["p_exposed"] or 0 for f in fs)
        agg["expected_exposed"].append(exp)
        agg["confirmed_reachable"].append(sum(1 for f in fs if f.get("L4_state") == "CONFIRMED"))
        agg["l4_unknown"].append(sum(1 for f in live if f.get("L4_state") == "UNKNOWN"))
        agg["l3b_refuted"].append(sum(1 for f in live if f.get("L3b_state") == "REFUTED"))
        agg["live"].append(len(live))
    T["realworld_scan"] = {k: {"sum": float(sum(v)), "median": float(st.median(v)) if v else 0,
                               "mean": float(st.mean(v)) if v else 0} for k, v in agg.items()}
    strat = defaultdict(lambda: defaultdict(list))
    for r in ok:
        orig = r["original"]
        for name, s in r["strategies"].items():
            strat[name]["ok"].append(1 if s.get("ok") else 0)
            if not s.get("ok"):
                continue
            for k in ("changed", "major_bumps", "residual_findings", "residual_risk_evident", "residual_risk_vm",
                      "residual_confirmed", "new_findings", "unplanned_changes", "plan_not_realised"):
                if k in s:
                    strat[name][k].append(s[k])
            strat[name]["risk_reduction_evident"].append(
                1 - s["residual_risk_evident"] / orig["residual_risk_evident"] if orig["residual_risk_evident"] else 1)
            strat[name]["risk_reduction_vm"].append(
                1 - s["residual_risk_vm"] / orig["residual_risk_vm"] if orig["residual_risk_vm"] else 1)
            strat[name]["confirmed_fixed"].append(
                1 - s["residual_confirmed"] / orig["residual_confirmed"] if orig["residual_confirmed"] else 1)
            if "seconds" in s:
                strat[name]["seconds"].append(s["seconds"])
            if "iterations" in s:
                strat[name]["iterations"].append(s["iterations"])
    T["remediation"] = {n: {k: {"mean": float(np.mean(v)), "median": float(np.median(v)), "n": len(v)}
                            for k, v in d.items() if v} for n, d in strat.items()}
    dec = [r["decision"] for r in ok if r.get("decision")]
    T["decision"] = {"projects": len(dec), "uncertain_total": sum(d["uncertain"] for d in dec),
                     "critical_total": sum(d["critical"] for d in dec),
                     "median_critical": float(np.median([d["critical"] for d in dec])) if dec else 0}
    drift = [r.get("baseline_drift", 0) for r in ok]
    T["baseline_drift"] = {"median": float(np.median(drift)) if drift else 0, "mean": float(np.mean(drift)) if drift else 0}
    return T


def main():
    FIG.mkdir(parents=True, exist_ok=True)
    ev = json.loads((RES / "bench_eval.json").read_text("utf8"))
    fig_reliability(ev)
    fig_missingness(ev)
    fig_architecture()
    rw = load_realworld()
    T = tables(ev, rw)
    if rw:
        T["exposure_classes"] = fig_evidence_funnel(rw)
        fig_pareto([r for r in rw if r.get("status") == "ok"])
    (RES / "paper_tables.json").write_text(json.dumps(T, indent=1), "utf8")
    print(json.dumps({k: T[k] for k in ("bench", "realworld_n", "decision", "baseline_drift") if k in T}, indent=1))


if __name__ == "__main__":
    sys.exit(main())
