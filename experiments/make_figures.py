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


def fig_calibration(ev):
    """Two panels: (a) 10-bin reliability with bootstrap 95% CIs (static setting); (b) ECE under missing evidence."""
    fig, (ax, bx) = plt.subplots(1, 2, figsize=(6.3, 2.5))
    ax.plot([0, 1], [0, 1], ls=":", c="0.5", lw=0.8)
    mk = {"coral_style": "^", "cape_style": "v", "logistic_iso": "D", "evident": "o"}
    for m, pts in ev["reliability"]["static"].items():
        if not pts:
            continue
        x, y, n, lo, hi = zip(*pts)
        yerr = [np.array(y) - np.array(lo), np.array(hi) - np.array(y)]
        ax.errorbar(x, y, yerr=yerr if m == "evident" else None, marker=mk[m], ms=3, lw=1.0 if m == "evident" else 0.6,
                    capsize=1.5, c="k" if m == "evident" else None, label=LABEL[m])
    ax.set_xlabel("Predicted exposure probability")
    ax.set_ylabel("Observed exposure rate")
    ax.set_xlim(-0.02, 1.02)
    ax.set_ylim(-0.05, 1.05)
    ax.set_title("(a) Reliability, 10 bins, 95% CI", loc="left")
    ax.legend(fontsize=5.5, frameon=False, loc="upper left")
    miss = ev["missingness"]
    cats = [("independent", "0.5", "random\n50%"), ("advisory", "0.5", "per advisory\n50%"),
            ("package", "0.5", "per package\n50%")]
    vals = {m: [miss[a][q][m]["ece"] for a, q, _ in cats] for m in ("evident", "logistic_iso", "coral_style", "cape_style")}
    labels = [c[2] for c in cats]
    if "realworld_profile" in miss:
        for m in vals:
            vals[m].append(miss["realworld_profile"][m]["ece"])
        labels.append("real-world\nprofile")
    xs = np.arange(len(labels))
    for i, m in enumerate(("evident", "logistic_iso", "coral_style", "cape_style")):
        bx.bar(xs + (i - 1.5) * 0.2, vals[m], width=0.2, label=LABEL[m],
               color=["0.1", "0.45", "0.7", "0.88"][i], edgecolor="0.2", lw=0.3)
    bx.set_xticks(xs)
    bx.set_xticklabels(labels, fontsize=6)
    bx.set_ylim(0, 1.45 * max(max(v) for v in vals.values()))
    bx.legend(fontsize=5, frameon=False, loc="upper left", ncol=2)
    bx.set_ylabel("Expected calibration error")
    bx.set_title("(b) Static evidence (L4) missing", loc="left")
    fig.tight_layout()
    fig.savefig(FIG / "calibration.png")
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


def _front_auc(pts, key, r0):
    """Area under the residual-fraction vs changes curve (lower = better), on a common change grid."""
    if not pts or r0 <= 0:
        return None
    pts = sorted(pts, key=lambda p: p["changes"])
    grid = np.arange(0, 31)
    xs = [p["changes"] for p in pts]
    ys = [p[key] / r0 for p in pts]
    # best residual achievable with at most g changes (step function)
    vals = [min([y for x, y in zip(xs, ys) if x <= g] or [1.0]) for g in grid]
    return float(np.mean(vals))


def fig_pareto(rw):
    """Fronts scored under a common yardstick (calibrated expected exposure), from pareto_common.json."""
    p = RES / "pareto_common.json"
    if not p.exists():
        return {}
    d = json.loads(p.read_text("utf8"))
    fig, ax = plt.subplots(figsize=(3.3, 2.5))
    stats = {}
    for name, lab, m in (("evident", "Calibrated (EVIDENT) weights", "o"), ("vm", "Version-match weights", "s")):
        by = defaultdict(list)
        for v in d.values():
            for q in v["fronts"][name]:
                by[q["lambda"]].append((q["changes"], q["exposure"] / max(v["r0_exposure"], 1e-9)))
        lams = sorted(by)
        ax.plot([np.mean([a for a, _ in by[l]]) for l in lams], [np.mean([b for _, b in by[l]]) for l in lams],
                marker=m, ms=3, lw=0.9, label=lab, c="k" if name == "evident" else None)
    ax.set_xlabel("Mean packages changed per project")
    ax.set_ylabel("Remaining expected exposure")
    ax.legend(fontsize=6, frameon=False)
    fig.savefig(FIG / "pareto.png")
    plt.close(fig)
    # per-project front comparison under the common yardstick
    diffs = []
    for sid, v in d.items():
        ae = _front_auc(v["fronts"]["evident"], "exposure", v["r0_exposure"])
        av = _front_auc(v["fronts"]["vm"], "exposure", v["r0_exposure"])
        if ae is not None and av is not None:
            diffs.append((sid, av - ae))
    if diffs:
        dv = np.array([x for _, x in diffs])
        stats = {"projects": len(dv), "mean_auc_gain": float(dv.mean()), "median_auc_gain": float(np.median(dv)),
                 "better": int((dv > 1e-3).sum()), "worse": int((dv < -1e-3).sum()),
                 "per_project": dict(diffs)}
    return stats


def tables(ev, rw):
    T = {}
    T["bench"] = {k: ev[k] for k in ("n_rows", "n_packages", "n_advisories", "label_rate")}
    T["bench_confusion"] = ev["analysis_confusion"]
    ok = [r for r in rw if r.get("status") == "ok"]
    T["realworld_n"] = {"snapshots": len(rw), "resolvable": len(ok),
                        "lock_kinds": dict(Counter(r["meta"]["lock_kind"] for r in rw)),
                        "unresolvable": [r["id"] for r in rw if r.get("status") != "ok"]}
    snaps = [p for p in (ROOT / "data" / "snapshots").iterdir() if (p / "meta.json").exists()]
    tos = [p.name for p in (RES / "realworld").iterdir()
           if (p / "error.txt").exists() and not (p / "result.json").exists()
           and (p / "error.txt").read_text("utf8", errors="replace").startswith("timeout after")]
    T["realworld_n"].update({"collected": len(snaps), "timeouts": len(tos), "timeout_ids": tos,
                             "not_run": len(snaps) - len(rw) - len(tos)})
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
                      "residual_confirmed", "new_findings", "unplanned_changes", "plan_not_realised",
                      "unplanned_major", "unplanned_added", "new_findings_from_unplanned", "objective_gap",
                      "planned_changes"):
                if k in s and s[k] is not None:
                    strat[name][k].append(s[k])
            c = s.get("compat") or {}
            if "api_compatible" in c:
                strat[name]["api_compatible"].append(1 if c["api_compatible"] else 0)
                strat[name]["api_broken_pkgs"].append(c["packages_with_missing"])
                strat[name]["api_used_changed"].append(c["used_changed"])
            orig_kev = orig.get("residual_kev")
            if orig.get("residual_findings"):
                strat[name]["findings_removed"].append(1 - s["residual_findings"] / orig["residual_findings"])
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
    rng = np.random.default_rng(11)
    rci = {}
    for n_ in ("evident", "vm_opt", "uv_fix", "upgrade_all"):
        for k in ("changed", "findings_removed"):
            v = np.array(strat[n_].get(k, []), float)
            if len(v) >= 3:
                bs = [rng.choice(v, len(v)).mean() for _ in range(2000)]
                rci[f"{n_}_{k}"] = f"[{np.percentile(bs, 2.5):.1f}, {np.percentile(bs, 97.5):.1f}]" if k == "changed" \
                    else f"[{100 * np.percentile(bs, 2.5):.0f}%, {100 * np.percentile(bs, 97.5):.0f}%]"
    T["remediation_ci"] = rci
    # per-project outcomes (supplement)
    T["per_project"] = {r["id"]: {n_: {k: s.get(k) for k in ("ok", "changed", "major_bumps", "residual_findings",
                                                               "unplanned_changes", "failure")}
                                  for n_, s in r["strategies"].items()} | {"original_findings": r["original"]["residual_findings"]}
                        for r in ok}
    # failure taxonomy over resolvable projects
    fail = defaultdict(Counter)
    for r in ok:
        for name, s in r["strategies"].items():
            fail[name][s.get("failure", "none" if s.get("ok") else "other")] += 1
    T["failures"] = {n: dict(c) for n, c in fail.items()}
    # paired tests EVIDENT vs alternatives (projects where both resolved)
    from scipy.stats import wilcoxon
    tests = {}
    for other in ("vm_opt", "uv_fix", "upgrade_all", "coral_opt"):
        for k in ("changed", "major_bumps", "risk_reduction_evident", "findings_removed"):
            a, b = [], []
            for r in ok:
                se, so = r["strategies"].get("evident", {}), r["strategies"].get(other, {})
                if not (se.get("ok") and so.get("ok")):
                    continue
                orig = r["original"]
                def val(s):
                    if k == "risk_reduction_evident":
                        return 1 - s["residual_risk_evident"] / orig["residual_risk_evident"] if orig["residual_risk_evident"] else 1
                    if k == "findings_removed":
                        return 1 - s["residual_findings"] / orig["residual_findings"] if orig["residual_findings"] else 1
                    return s[k]
                a.append(val(se))
                b.append(val(so))
            if len(a) >= 5 and any(x != y for x, y in zip(a, b)):
                st_, p = wilcoxon(a, b)
                tests[f"evident_vs_{other}_{k}"] = {"n": len(a), "evident": float(np.median(a)),
                                                     "other": float(np.median(b)), "p": float(p)}
    T["remediation_tests"] = tests
    # why no statically unreachable findings: reasons for non-REFUTED static verdicts among imported packages
    reasons = Counter()
    blockers = Counter()
    for r in rw:
        for f in json.loads((RES / "realworld" / r["id"] / "findings.json").read_text("utf8")):
            if f.get("L3_state") != "CONFIRMED" or f.get("L3b_state") != "CONFIRMED":
                continue
            ev4 = f["evidence"].get("L4", {})
            st4 = ev4.get("state")
            rs = (ev4.get("detail") or {}).get("reason", "")
            if st4 == "UNKNOWN":
                key = "no symbol data / no source" if (ev4.get("detail") or {}).get("missing") else "reflection blocks refutation"
                if "reflection" in rs:
                    where = rs.split("(")[-1].split(":")[0] if "(" in rs else "?"
                    blockers[where] += 1
            else:
                key = st4
            reasons[key] += 1
    T["l4_breakdown"] = {"states": dict(reasons), "reflection_where": dict(blockers)}
    app_refl = Counter()
    for r in rw:
        kinds = (r.get("stats") or {}).get("reflection_kinds", {})
        app_refl["projects"] += 1
        if kinds.get("__app__"):
            app_refl["app_has_blocking_reflection"] += 1
    T["app_reflection"] = dict(app_refl)
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
    fig_calibration(ev)
    fig_architecture()
    rw = load_realworld()
    T = tables(ev, rw)
    if rw:
        T["exposure_classes"] = fig_evidence_funnel(rw)
        T["pareto_common"] = fig_pareto([r for r in rw if r.get("status") == "ok"])
        # does the benefit of calibrated weights grow with how discriminative the evidence is?
        pc = T["pareto_common"].get("per_project", {})
        xs, ys = [], []
        for r in rw:
            if r["id"] not in pc:
                continue
            fs = json.loads((RES / "realworld" / r["id"] / "findings.json").read_text("utf8"))
            if not fs:
                continue
            disc = sum(1 for f in fs if f["exposure_class"] in ("NOT_INSTALLED", "DEV_ONLY", "NOT_IMPORTED",
                                                                   "STATICALLY_UNREACHABLE", "STATICALLY_REACHABLE"))
            xs.append(disc / len(fs))
            ys.append(pc[r["id"]])
        if len(xs) > 3:
            from scipy.stats import spearmanr
            rho, pval = spearmanr(xs, ys)
            hi = [y for x, y in zip(xs, ys) if x >= np.median(xs)]
            lo = [y for x, y in zip(xs, ys) if x < np.median(xs)]
            T["pareto_vs_discrimination"] = {"spearman_rho": float(rho), "p": float(pval), "n": len(xs),
                                             "gain_high_disc": float(np.mean(hi)) if hi else 0.0,
                                             "gain_low_disc": float(np.mean(lo)) if lo else 0.0}
    (RES / "paper_tables.json").write_text(json.dumps(T, indent=1), "utf8")
    print(json.dumps({k: T[k] for k in ("bench", "realworld_n", "decision", "baseline_drift") if k in T}, indent=1))


if __name__ == "__main__":
    sys.exit(main())
