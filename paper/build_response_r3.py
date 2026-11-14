"""Point-by-point response to the third-round review -> docs/RESPONSE_TO_REVIEW_R3.md (numbers from data/results)."""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RES = ROOT / "data" / "results"


def J(n, d=None):
    p = RES / n
    return json.loads(p.read_text("utf8")) if p.exists() else d


def f3(x):
    return "n/a" if x is None else f"{x:.3f}"


def pct(x):
    return "n/a" if x is None else f"{100 * x:.0f}%"


def main():
    B, R, C, S = J("round3_bench.json", {}), J("round3_realworld.json", {}), J("round3_callgraph.json", {}), \
        J("round3_symbol_text.json", {})
    T, EV, REL = J("paper_tables.json", {}), J("bench_eval.json", {}), J("release.json", {})
    rn = T.get("realworld_n", {})
    sm = R["sample"]["tests_completed_vs_not_processed"]
    cv, cc, fz, rf = R["coverage"], C["common"], B["factorisation"], B["refutations"]
    dr, du = R["drift"]["evident"], R["drift"]["evident_vs_untouched_drift"]
    cf = R["confirmed_fixed"]
    tests = {(t["comparison"], t["metric"]): t for t in R["paired_tests"]["tests"]}
    lpo, ts, sg = B["leave_pattern_out"], B["time_split"], B["subgroups"]
    items = [
        ("Issue 1 — sampling of the real-world corpus",
         f"Done (no new runs). Completed ({rn.get('snapshots')}) vs unprocessed ({rn.get('not_run')}) applications are "
         f"compared in S14.1: stars p = {sm['stars']['mannwhitney_p']:.2f}, locked packages p = "
         f"{sm['locked']['mannwhitney_p']:.2f}, framework χ² p = {sm['framework']['chi2_p']:.2f}, lockfile kind χ² p = "
         f"{sm['lock_kind']['chi2_p']:.3f} (the completed prefix has more pinned requirements files). The "
         f"{rn.get('timeouts')} time-outs occurred while scanning (no findings were written; 62–86 locked packages). "
         "§4 and the threats now say that the sample does not represent the ecosystem. Not done: processing a "
         "stratified sample of the remaining applications (compute budget of this revision)."),
        ("Issue 2 — fairness of the PyCG/Jarvis comparison",
         f"Done. Table 4 now reports all metrics on the {C['common_subset']} applications every tool analysed, with "
         "F1, missed exposed applications and false alarms; failure rates are reported separately (PyCG "
         f"{pct(C['failure_rate']['PyCG'])}, Jarvis {pct(C['failure_rate']['Jarvis'])}). On identical inputs EVIDENT "
         f"strong edges perform like Jarvis (F1 {f3(cc['EVIDENT strong']['f1'])} vs {f3(cc['Jarvis']['f1'])}); with "
         f"weak edges no exposed application is missed at {cc['EVIDENT strong+weak']['false_alarms']} false alarms. The "
         "paper no longer claims superiority over Jarvis and states that it evaluates a reachability-derived security "
         "decision, not verdicts issued by PyCG or Jarvis. Full confusion matrices: S14.8."),
        ("Issue 3 — independent validation of mined symbols",
         f"Partly done. (a) A commit-independent cross-check against the advisories' own OSV text: of "
         f"{S['text_names_code']} advisories whose text names code, {pct(S['agreement'])} (95% CI "
         f"{pct(S['agreement_ci95'][0])}–{pct(S['agreement_ci95'][1])}) have a named function or class among the mined "
         "symbols; inspection shows most disagreements name the public entry point (e.g. a template filter) while "
         "the fix changes its implementation. (b) The check found 5 of 570 mined sets containing test functions from "
         "`tests.py` modules inside the package; the filter is corrected (these functions are never called by "
         "applications, so no verdict changes). (c) The two-annotator manual validation of the 40-advisory sample "
         "(sheet `data/results/symbol_annotation_sheet.csv`, disagreement list `symbol_text_disagreements.csv`) "
         "must be performed by the authors; it cannot be automated without becoming a further proxy. **Open.**"),
        ("Issue 4 — conditional-independence assumptions",
         f"Done. A joint model estimating P(Y|E) per complete static evidence configuration reaches Brier "
         f"{f3(fz['joint_configuration']['brier'])} vs {f3(fz['staged']['brier'])} for the staged model (difference CI "
         f"[{fz['staged_minus_joint_brier']['ci'][0]:+.4f}, {fz['staged_minus_joint_brier']['ci'][1]:+.4f}]); logistic "
         f"{f3(fz['logistic_iso']['brier'])}; a single-level L4 baseline {f3(fz['single_level_L4']['brier'])}. The "
         "factorisation costs no accuracy, and the paper states that the benchmark cannot test it more strongly "
         "because import refutation implies reachability refutation there. Subgroup calibration (S14.6): "
         + "; ".join(f"{k}: {v['mean_p']:.2f} vs {v['observed']:.2f} (n = {v['n']})" for k, v in sg.items() if v.get("n"))
         + ". Development-only findings do not occur in the benchmark (stated)."),
        ("Issue 5 — reflection scopes; 22 vs 144",
         f"Done. The {rf['L4_refuted_total']} REFUTED verdicts are {rf['L4_refuted_by_reason'].get('package not imported')} "
         f"import refutations (L3b R propagated to L4) plus {rf['imported_path_refuted']} path refutations; Table 3 "
         f"counts only the path refutations among the {rf['imported_without_strong_path']} imported pairs without a "
         f"strong path ({rf['imported_blocked_by_reflection']} are blocked). One-sided 95% upper bounds on the false-"
         f"refutation rate: {pct(rf['upper95_false_refutation_path'])} (path), {pct(rf['upper95_false_refutation_all'])} "
         "(all). The paper says narrower scopes are empirically evaluated, not proven sound."),
        ("Issue 6 — resolver drift, compatibility wording, confirmed-fixed, calibrated weighting",
         f"Done. (A) No planned pin deviated in any realised environment; the resolver adds "
         f"{dr['unplanned_changes']['mean']:.1f} changes (median {dr['unplanned_changes']['median']:.1f}), a median "
         f"{du['median_diff']:+.1f} more than re-resolving the untouched lockfile (p < 0.001), introducing "
         f"{dr['new_findings_from_unplanned']['mean']:.1f} new findings on average (median "
         f"{dr['new_findings_from_unplanned']['median']:.0f}). The objective gap is defined (realised minus planned "
         f"residual expected risk): {dr['objective_gap']['mean']:+.2f} (95% CI [{dr['objective_gap']['ci_mean'][0]:.2f}, "
         f"{dr['objective_gap']['ci_mean'][1]:.2f}]) against a planned objective of "
         f"{dr['objective_gap']['planned_objective_mean']:.1f}, zero in {dr['objective_gap']['zero_gap']} of {dr['n']}. "
         "(B) Compatibility is described as metadata and statically referenced API verification; behavioural "
         "compatibility is stated as unevaluated, and the conclusion says the static checks pass for only half of the "
         f"plans. (C) Confirmed-fixed is defined and reported as pooled k/n (EVIDENT {cf['evident']['fixed']}/"
         f"{cf['evident']['confirmed_findings']}); new findings are counted separately (S14.11). (D) Calibrated weighting "
         "is presented as a different risk-versus-change preference, not a better plan."),
        ("Issue 7 — the nine applications without remediation",
         f"Done. {cv['completed'] - cv['resolvable']} completed applications have no resolvable baseline: "
         + ", ".join(f"{k}: {v}" for k, v in cv["excluded_reasons"].items())
         + f" (per application in S14.2). End-to-end coverage {cv['resolvable']}/{cv['completed']} "
         f"({pct(cv['end_to_end_coverage'])}) is reported next to the conditional 24/24 in the abstract and §4."),
        ("Issue 8 — beyond significance",
         "Done. S14.12 reports, for 8 paired comparisons, n, medians, median paired difference, IQR, bootstrap CI, "
         "rank-biserial effect size, two-sided p and Holm-corrected p. In the text: EVIDENT vs uv-fix "
         f"p_Holm = {tests[('evident_vs_uv_fix', 'changed')]['p_holm']:.2f} (no advantage); calibrated vs version-match "
         f"weights: fewer changes (p_Holm = {tests[('evident_vs_vm_opt', 'changed')]['p_holm']:.3f}) and fewer removed "
         f"findings (p_Holm = {tests[('evident_vs_vm_opt', 'findings_removed')]['p_holm']:.3f}), framed as a trade-off."),
        ("Issue 9 — generalisation details",
         f"Done. Package-grouped bootstrap CIs: leave-one-pattern-out EVIDENT {f3(lpo['evident']['brier'])} "
         f"{[round(x, 3) for x in lpo['evident']['brier_ci']]}, logistic {f3(lpo['logistic_iso']['brier'])}, CORAL-style "
         f"{f3(lpo['coral_style']['brier'])} (reported: fixed coefficients lose nothing on unseen patterns); time split "
         f"EVIDENT {f3(ts['evident']['brier'])} {[round(x, 3) for x in ts['evident']['brier_ci']]}. The ablation now "
         "separates static levels (L4 alone, L3b+L4) from the L5 run (0.127), and Table 5's caption marks the L5 "
         "column as not comparable. The missingness generator is specified in §4 and S14.3 (levels, keys, rates, "
         "seeds, label independence, identical masks, real-world rates from the completed applications)."),
        ("Issue 10 — case study",
         f"Done. Figure S1 shows the end-to-end chain; the paper explains the major-version choice: "
         f"{R['case']['django_advisories_affecting_4.2.6']} Django advisories affect 4.2.6, the newest 4.2 release "
         f"(4.2.30) still carries {R['case']['remaining_advisories_if_upgraded_to']['4.2.30']}, 5.2.19 carries "
         f"{R['case']['remaining_advisories_if_upgraded_to']['5.2.19']}; the example is marked retrospective. The figure "
         "is in the supplement because the paper is at the 10-page limit."),
        ("Presentation items",
         "Table 1 unchanged in content; the experiment-to-data table became one sentence to stay within 10 pages; "
         "Table 5 distinguishes static and runtime settings; Table 7 defines its metrics and denominators; "
         f"equations were checked in the exported PDF; Data Availability names the immutable release tag "
         f"{REL.get('tag', 'v0.3.0')}; supplement sections S9–S15 regenerate from the released data."),
    ]
    md = ["# Response to the reviewer (round 3)", "",
          "Generated from `data/results/` by `paper/build_response_r3.py`; numbers match the manuscript and "
          "`docs/SUPPLEMENT.md` (section S14).", ""]
    for h, b in items:
        md += [f"**{h}.** {b}", ""]
    md += ["## Still open (authors)", "",
           "1. Manual two-annotator validation of mined symbols on the 40-advisory sample, with Cohen's kappa "
           "(Priority A1).",
           "2. Author names and affiliations.",
           "3. An archival DOI (e.g. Zenodo) for the release tag.",
           "4. Optional: process a stratified sample of the 84 unprocessed applications (compute).",
           "5. Level-3 (test-based) compatibility needs an isolated sandbox; stated as not evaluated."]
    out = ROOT / "docs" / "RESPONSE_TO_REVIEW_R3.md"
    out.write_text("\n".join(md), "utf8")
    print("wrote", out)


if __name__ == "__main__":
    main()
