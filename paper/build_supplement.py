"""Online supplement (docs/SUPPLEMENT.md) with the extended results referenced by the paper."""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RES = ROOT / "data" / "results"


def J(n, d=None):
    p = RES / n
    return json.loads(p.read_text("utf8")) if p.exists() else d


def f3(x):
    return "n/a" if x is None or x != x else f"{x:.3f}"


def table(head, rows):
    out = ["| " + " | ".join(head) + " |", "|" + "---|" * len(head)]
    out += ["| " + " | ".join(str(c) for c in r) + " |" for r in rows]
    return "\n".join(out)


def case_study():
    """Pick a real finding with a confirmed static path whose package the verified EVIDENT plan changes."""
    best = None
    for d in sorted((RES / "realworld").glob("*/result.json")):
        r = json.loads(d.read_text("utf8"))
        ev = (r.get("strategies") or {}).get("evident", {})
        if not ev.get("ok"):
            continue
        fs = json.loads((d.parent / "findings.json").read_text("utf8"))
        for f in fs:
            e4 = f["evidence"].get("L4", {})
            wit = (e4.get("detail") or {}).get("witness") or []
            if e4.get("state") == "CONFIRMED" and len(wit) >= 3 and f["package"] in ev.get("planned", {}):
                score = (f.get("cvss") or 0) + 0.1 * len(wit)
                if best is None or score > best[0]:
                    best = (score, r, f, ev)
    if not best:
        return "No case found."
    _, r, f, ev = best
    e4 = f["evidence"]["L4"]["detail"]
    st = {k: v["state"] for k, v in f["evidence"].items()}
    compat = ev.get("compat", {})
    lines = [f"**Project:** {r['meta']['repo']} @ {r['meta']['tag'][:12]} (lockfile {r['meta']['lock_file']}, "
             f"target Python {r['python']}).",
             f"**Finding:** {f['package']}=={f['version']}, {f['advisory']} (CVSS {f.get('cvss')}, EPSS {f3(f.get('epss'))}, "
             f"KEV {f.get('kev')}), dependency depth {f.get('depth')}, direct={f.get('direct')}.",
             f"**Evidence:** " + ", ".join(f"{k}={v}" for k, v in sorted(st.items())) + ".",
             f"**Mined symbols:** {', '.join(e4.get('symbols', [])[:5])} (granularity {e4.get('granularity')}).",
             "**Witness path (strong edges):** " + " → ".join(e4.get("witness", [])[:8]) + ".",
             f"**Exposure probability:** {f3(f.get('p_exposed'))} (class {f.get('exposure_class')}; VEX {f.get('vex')}).",
             f"**Verified plan:** {f['package']} {f['version']} → {ev['planned'][f['package']]}; plan changes "
             f"{len(ev['planned'])} packages, realised environment changes {ev.get('changed')} "
             f"({ev.get('unplanned_changes')} added by the resolver), {ev.get('iterations')} solver/resolver iteration(s).",
             f"**Residual after re-scan:** {ev.get('residual_findings')} findings (from {r['original']['residual_findings']}); "
             f"API check: {compat.get('checked')} used packages checked, {compat.get('packages_with_missing')} with missing "
             f"symbols."]
    return "\n\n".join(lines)


def main():
    ev, T, cg, sv = J("bench_eval.json"), J("paper_tables.json"), J("callgraph_summary.json", {}), J("symbol_validation.json", {})
    cgr = J("callgraph_comparison.json", [])
    md = ["# EVIDENT — Online Supplement", "",
          "All tables are generated from `data/results/` by `paper/build_supplement.py`.", ""]
    md += ["## S1 Benchmark sample flow and leakage audit", "",
           table(["Stage", "Count"], [[k.replace("_", " "), v] for k, v in ev["sample_flow"].items()]), "",
           table(["Leakage audit", "Value"], [[k.replace("_", " "), v] for k, v in ev["leakage_audit"].items()]), ""]
    for s in ("static", "runtime"):
        M = ev["methods"][s]
        rows = []
        for m in ("version_match", "coral_style", "cape_style", "naive_bayes", "logistic", "logistic_iso", "hgb_iso", "evident"):
            d = M[m]
            rows.append([m, f3(d["brier"]), d["ci"]["brier"], f3(d["ece"]), d["ci"]["ece"], f3(d["ace"]), f3(d["logloss"]),
                         f3(d["auc"]), d["ci"]["auc"], f3(d["slope"]), f3(d["intercept"]), f3(d["citl"]), f3(d.get("AP")),
                         f3(d.get("NDCG@5"))])
        md += [f"## S2 Exposure probabilities — {s} setting", "",
               table(["Method", "Brier", "95% CI", "ECE", "95% CI", "Adaptive ECE", "Log-loss", "AUC", "95% CI", "Slope",
                      "Intercept", "Calib.-in-the-large", "AP", "NDCG@5"], rows), "",
               table(["Paired difference (EVIDENT − other)", "ΔBrier [CI] p", "ΔECE [CI] p", "ΔAUC [CI] p"],
                     [[k] + [f"{v[x]['mean']:+.3f} {[round(c, 3) for c in v[x]['ci']]} p={v[x]['p']:.3f}"
                             for x in ("brier", "ece", "auc")] for k, v in M["paired"].items()]), ""]
    md += ["## S3 Brier decomposition (static)", "",
           table(["Method", "Reliability", "Resolution", "Uncertainty"],
                 [[m, f3(d["reliability"]), f3(d["resolution"]), f3(d["uncertainty"])]
                  for m, d in ev["brier_decomposition"]["static"].items()]), "",
           "## S4 Per-pattern results (static)", "",
           table(["Pattern", "Label rate", "EVIDENT mean p", "EVIDENT Brier", "Logistic+iso Brier", "CORAL-style Brier"],
                 [[p, f3(d["label_rate"]), f3(d["evident"]["mean_p"]), f3(d["evident"]["brier"]),
                   f3(d["logistic_iso"]["brier"]), f3(d["coral_style"]["brier"])] for p, d in ev["per_pattern"].items()]), "",
           "## S5 Factorial ablation (evidence levels kept)", "",
           table(["Levels", "Brier", "ECE", "AUC"], [[k, f3(v["brier"]), f3(v["ece"]), f3(v["auc"])]
                                                     for k, v in ev["factorial"].items()]), "",
           "## S6 Prevalence shift (static; raw vs prior-corrected)", "",
           table(["Prevalence"] + list(next(iter(ev["prevalence_shift"].values())).keys()),
                 [[pi] + [f"{f3(v['brier'])}/{f3(v['ece'])}" for v in d.values()] for pi, d in ev["prevalence_shift"].items()]),
           "", "Cells: Brier/ECE.", "",
           "## S7 Missing static evidence (ECE; Brier in parentheses)", ""]
    rows = []
    for mode in ("independent", "advisory", "package"):
        for q, d in ev["missingness"][mode].items():
            rows.append([mode, q] + [f"{f3(d[m]['ece'])} ({f3(d[m]['brier'])})"
                                     for m in ("evident", "logistic_iso", "coral_style", "cape_style")])
    rp = ev["missingness"].get("realworld_profile")
    if rp:
        rows.append(["real-world profile", f3(rp["overall_rate"])] + [f"{f3(rp[m]['ece'])} ({f3(rp[m]['brier'])})"
                                                                       for m in ("evident", "logistic_iso", "coral_style", "cape_style")])
    md += [table(["Mode", "Rate", "EVIDENT", "Logistic+iso", "CORAL-style", "CAPE-style"], rows), "",
           "## S8 Time split", "", table(["Method", "Brier", "ECE", "AUC"],
                                          [[m, f3(d["brier"]), f3(d["ece"]), f3(d["auc"])]
                                           for m, d in ev["time_split"].get("methods", {}).items()]), "",
           "## S9 Reachability comparison (per pattern)", ""]
    if cgr:
        pats = sorted({x["pattern"] for x in cgr})
        rows = []
        for p in pats:
            xs = [x for x in cgr if x["pattern"] == p]
            rows.append([p, sum(x["label"] for x in xs), len(xs),
                         sum(1 for x in xs if x["pycg_pred"] == x["label"]), sum(1 for x in xs if x["pycg_pred"] is None),
                         sum(1 for x in xs if x["jarvis_pred"] == x["label"]), sum(1 for x in xs if x["jarvis_pred"] is None),
                         sum(1 for x in xs if x["evident_strong"] == x["label"]),
                         sum(1 for x in xs if x["evident_weak"] == x["label"])])
        md += [table(["Pattern", "Exposed", "Apps", "PyCG correct", "PyCG failed", "Jarvis correct", "Jarvis failed",
                      "EVIDENT strong correct", "EVIDENT strong+weak correct"], rows), "",
               "```json\n" + json.dumps(cg, indent=1) + "\n```", ""]
    md += ["## S10 Vulnerable-symbol mining validation", "", "```json\n" + json.dumps(sv, indent=1) + "\n```", "",
           "Manual validation protocol: `data/results/symbol_annotation_sheet.csv` lists a seeded random sample of 40 "
           "function-level advisories with their fix commits and mined functions. Two annotators independently mark "
           "whether the vulnerable operation lies inside the mined functions (yes/partial/no) and list missed "
           "functions; disagreements are resolved by discussion and Cohen's kappa is reported.", "",
           "## S11 Remediation details", ""]
    REM = T["remediation"]
    keys = ["ok", "changed", "planned_changes", "unplanned_changes", "unplanned_major", "unplanned_added",
            "new_findings_from_unplanned", "major_bumps", "findings_removed", "risk_reduction_evident",
            "risk_reduction_vm", "confirmed_fixed", "new_findings", "api_compatible", "api_broken_pkgs", "objective_gap",
            "iterations", "seconds"]
    md += [table(["Strategy"] + keys, [[s] + [f3(REM[s].get(k, {}).get("mean")) for k in keys] for s in REM]), "",
           "Failure taxonomy (resolvable projects):", "",
           table(["Strategy", "Failures"], [[s, ", ".join(f"{k}: {v}" for k, v in sorted(c.items()))]
                                            for s, c in T.get("failures", {}).items()]), "",
           "Paired Wilcoxon tests (projects where both strategies resolved):", "",
           table(["Comparison", "n", "EVIDENT median", "Other median", "p"],
                 [[k, v["n"], f3(v["evident"]), f3(v["other"]), f3(v["p"])]
                  for k, v in T.get("remediation_tests", {}).items()]), "",
           "Static verdicts for findings in imported packages:", "",
           "```json\n" + json.dumps({k: T.get(k) for k in ("l4_breakdown", "app_reflection", "pareto_common",
                                                           "pareto_vs_discrimination", "decision", "baseline_drift")},
                                    indent=1) + "\n```", "",
           "## S12 End-to-end case study", "", case_study(), ""]
    pp = T.get("per_project", {})
    if pp:
        strats = ["audit_fix", "latest", "upgrade_all", "uv_fix", "vm_opt", "evident"]
        rows = []
        for pid, d in sorted(pp.items()):
            rows.append([pid.split("@")[0].replace("__", "/"), d.get("original_findings")] +
                        [("–" if not d.get(s, {}).get("ok") else f"{d[s].get('changed')}/{d[s].get('residual_findings')}")
                         for s in strats])
        md += ["## S11b Per-application remediation outcomes", "",
               "Cells: packages changed / residual findings; – = no resolvable plan.", "",
               table(["Application", "Findings"] + strats, rows), ""]
    fm = ev.get("final_model_static", {})
    md += ["## S13 Fitted parameters of the staged model (static setting)", "",
           table(["Parameter", "Value"],
                 [["P(D | dev-only) (heuristic)", fm.get("p_dev_deployed")], ["P(M) marginal", f3(fm.get("p_import_marg"))],
                  ["prior P(C)", f3(fm.get("prior_call"))]] +
                 [[f"P(M | L3b={k})", f3(v)] for k, v in (fm.get("p_import") or {}).items()] +
                 [[f"P(C | L4={k})", f3(v)] for k, v in (fm.get("p_call_l4") or {}).items()] +
                 [[f"P(C | {k})", f3(v)] for k, v in (fm.get("p_call") or {}).items()]), "",
           "P(I | L3) is fixed: 1 (C), 0 (R), 0.8 (U).", ""]
    ph = J("posthoc_realworld.json", {})
    if ph:
        md += ["## S14 Real-world post-hoc analyses", "",
               "Compatibility levels (plans):", "", table(["Strategy", "Plans", "L2 ok", "L2b ok", "No used package changed"],
                                                          [[s, c.get("plans"), c.get("level2_ok"), c.get("level2b_ok"),
                                                            c.get("no_used_package_changed")] for s, c in ph.get("compat", {}).items()]), "",
               "Development-only prior δ:", "", table(["δ", "Expected exposed", "of which dev-only", "Plan Jaccard vs default", "Mean changes"],
                                                     [[k, f3(v["expected_exposed"]), f3(v["expected_exposed_dev_only"]),
                                                       f3(v["mean_plan_jaccard_vs_default"]), f3(v["mean_changes"])]
                                                      for k, v in ph.get("devprior", {}).items()]), "",
               "Objective weighting:", "", table(["Variant", "Projects", "Mean changes", "Jaccard vs default", "Identical plans"],
                                                 [[k, v["projects"], f3(v["mean_changes"]), f3(v["mean_jaccard_vs_default"]),
                                                   v["identical_plans"]] for k, v in ph.get("weights", {}).items()]), "",
               "Candidate limits:", "", table(["k", "n", "Resolves", "Iterations", "Seconds", "Changes", "Candidates"],
                                              [[k, v.get("n"), f3(v.get("ok")), f3(v.get("iterations")), f3(v.get("seconds")),
                                                f3(v.get("changes")), f3(v.get("candidates"))]
                                               for k, v in ph.get("candidates", {}).items()]), "",
               "Reflection scopes (real world):", "", "```json\n" + json.dumps(ph.get("scopes"), indent=1) + "\n```", ""]
    out = ROOT / "docs" / "SUPPLEMENT.md"
    out.parent.mkdir(exist_ok=True)
    out.write_text("\n".join(md), "utf8")
    print("wrote", out)


if __name__ == "__main__":
    main()
