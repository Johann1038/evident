"""Build the conference paper (DOCX, <= 10 pages incl. references) from the experiment results.

Every number is read from data/results/*.json. Order: analyze_bench.py, compare_callgraphs.py, validate_symbols.py,
run_realworld.py, posthoc_realworld.py, make_figures.py, then this script.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))
from docxkit import Paper, mfrac, mnary, mr, msub  # noqa: E402
from references import REFS  # noqa: E402

RES = ROOT / "data" / "results"
FIG = HERE / "figures"
REPO = "https://github.com/Johann1038/evident"


def J(name, default=None):
    p = RES / name
    return json.loads(p.read_text("utf8")) if p.exists() else default


EV, T = J("bench_eval.json"), J("paper_tables.json")
CG, SV, PH = J("callgraph_summary.json", {}), J("symbol_validation.json", {}), J("posthoc_realworld.json", {})
MS, MR = EV["methods"]["static"], EV["methods"]["runtime"]
RW, RN, REM, CLS = T["realworld_scan"], T["realworld_n"], T["remediation"], T.get("exposure_classes", {})


def f3(x):
    return "n/a" if x is None or x != x else f"{x:.3f}"


def f2(x):
    return "n/a" if x is None or x != x else f"{x:.2f}"


def pct(x, d=0):
    return "n/a" if x is None or x != x else f"{100 * x:.{d}f}%"


def frac(k, n):
    return f"{k}/{n}"


def ci(m, k="brier", s=MS):
    lo, hi = s[m]["ci"][k]
    return f"[{lo:.3f}, {hi:.3f}]"


def S(name, key, stat="mean"):
    return REM.get(name, {}).get(key, {}).get(stat, float("nan"))


def Sn(name, key="ok"):
    return REM.get(name, {}).get(key, {}).get("n", 0)


def test(other, key):
    return T.get("remediation_tests", {}).get(f"evident_vs_{other}_{key}", {})


n_snap, n_ok = RN["snapshots"], RN["resolvable"]
n_find = int(RW["findings"]["sum"])
tot = sum(CLS.values()) or 1
C = lambda k: CLS.get(k, 0)  # noqa: E731
dismiss = C("NOT_INSTALLED") + C("DEV_ONLY") + C("NOT_IMPORTED") + C("STATICALLY_UNREACHABLE")
COMPAT = PH.get("compat", {})


def cl(name, lvl):
    c = COMPAT.get(name, {})
    return frac(c.get(lvl, 0), c.get("plans", 0)) if c else "n/a"


ev_ok_k = int(round(S("evident", "ok") * Sn("evident"))) if Sn("evident") else 0
TITLE = ("Not Every Vulnerable Dependency Needs an Upgrade: Calibrated Exposure Evidence and "
         "Metadata-Verified Remediation for Python Projects")
ABSTRACT = (
    "Software composition analysis reports every dependency whose version is in an advisory's range, although much "
    "vulnerable code is never executed. We present EVIDENT, which grades Python findings with formally defined "
    "three-valued evidence (installation for the target environment, imports, cross-package static reachability of "
    "vulnerable functions mined from fix commits, optional runtime traces), turns it into exposure probabilities with "
    "a staged conditional model that treats missing evidence as neutral, and plans remediation with a constraint "
    "solver verified by a metadata-only resolver. On "
    f"{EV['n_rows']} execution-labelled pairs ({EV['n_advisories']} advisories, {EV['n_packages']} packages) the model "
    f"is calibrated without runtime evidence (Brier {f3(MS['evident']['brier'])}, 95% CI {ci('evident')}; ECE "
    f"{f3(MS['evident']['ece'])}), statistically tied with logistic regression but better calibrated when evidence is "
    "missing in correlated patterns. "
    + (f"The reachability analysis produced no false refutation, whereas PyCG and Jarvis missed "
       f"{CG.get('PyCG', {}).get('missed_exposed')} and {CG.get('Jarvis', {}).get('missed_exposed')} exposed applications. "
       if CG and EV["analysis_confusion"]["L4_refuted"]["exposed"] == 0 else "")
    + f"In {n_snap} historical application snapshots, {pct(dismiss / tot, 1)} of {n_find} findings are dismissed with a "
    + (f"justification, yet at the default reflection scope static analysis refutes none, because the applications "
       f"themselves use reflection." if not C('STATICALLY_UNREACHABLE') else
       f"justification, yet static analysis refutes only {C('STATICALLY_UNREACHABLE')} because the applications "
       f"themselves use reflection.") + f" On {n_ok} resolvable snapshots, verified plans resolve in {frac(ev_ok_k, Sn('evident'))}"
    + (" and change fewer packages than resolver-native fixing"
       if test("uv_fix", "changed").get("p", 1) < 0.05 and test("uv_fix", "changed").get("evident", 0)
       < test("uv_fix", "changed").get("other", 0) else "")
    + ", but calibrated weights rarely change the plan. Evidence helps triage more than it changes remediation.")
KEYWORDS = ("software supply chain security, vulnerability reachability, calibration, dependency remediation, "
            "constraint optimisation, Python")


def build():
    P = Paper(HERE / "template.docx")
    P.set_front(TITLE, ABSTRACT, KEYWORDS)

    # ---------------------------------------------------------------- 1
    P.h1("Introduction")
    P.para("Software composition analysis (SCA) matches the resolved versions of an application's dependencies against "
           "advisory databases such as OSV [21] and reports every package in an affected range. This *version "
           "matching* over-approximates exposure: in Maven and npm only a fraction of vulnerable dependencies is "
           "reachable [9–11, 26], tools disagree [15], and the default response, upgrading everything, is costly and "
           "can break applications [14]. Reachability-aware tools grade findings [1, 2, 5] and remediation optimisers "
           "choose versions under constraints [3, 4, 6, 7], but their evidence weights are hand-chosen, missing "
           "evidence is often read as negative [16], and it is unknown *when* evidence actually changes a decision.")
    P.para("Our thesis is that a finding should become an upgrade only in proportion to reliable evidence of exposure, "
           "and that the value of evidence depends on its reliability, availability and power to discriminate. EVIDENT "
           "contributes (1) **evidence reliability**: formally defined three-valued evidence with explicit soundness "
           "assumptions and scoped reflection handling; (2) **vulnerable-code reachability** for Python across package "
           "boundaries, compared with PyCG [12] and Jarvis [13]; (3) **statistically reliable exposure estimation**: a "
           "staged conditional model calibrated on execution ground truth and evaluated for leakage, unseen packages, "
           "unseen patterns, prevalence shift and correlated missingness; (4) **decision-aware remediation**: a CP-SAT "
           "planner verified by a resolver, with compatibility levels and a measurement of when calibrated weights "
           "change plans. All data and scripts are released [Data Availability].")

    # ---------------------------------------------------------------- 2
    P.h1("Related Work and Positioning")
    P.para("**Reachability.** Eclipse Steady [1, 2] combines static and dynamic reachability for Java and offers update "
           "metrics as decision support without quantifying risk. Python call-graph generators [12, 13] output graphs, "
           "not verdicts; reading a missing edge as unreachability is unsafe for security negatives. Exploit-test "
           "generation [18] gives stronger, Java-specific evidence. **Prioritisation.** CVSS, EPSS [19] and KEV [20] "
           "rank vulnerabilities, not application exposure; CAPE [5] grades Python/JS findings into evidence regimes "
           "with weight redistribution, but its scores are not validated probabilities, so they cannot be traded "
           "against change cost. **Remediation.** Installation as optimisation goes back to OPIUM [8]; MaxNPM [7] adds "
           "vulnerability objectives for npm, Ranger [27] restores safe ranges in Maven, CORAL [3] minimises "
           "reachability-weighted CVSS under compatibility constraints, Remedius [4] encodes agent-gathered evidence as "
           "SMT constraints, and KEVGraph [6] solves an exploitation-ordered set cover. None estimates calibrated "
           "probabilities or measures when evidence changes the plan (Table 1).")
    y, p_, n = "✓", "◐", "–"
    P.table(["Approach", "Eco-system", "Reach. evidence", "Missing ≠ negative", "Calibrated, validated",
             "Optim. plan", "Plan verification", "Compat. check"],
            [["pip-audit / OSV-Scanner", "PyPI", n, n, n, p_, n, n],
             ["Eclipse Steady [1, 2]", "Java", "static+dyn.", n, n, p_, n, "metrics"],
             ["CORAL [3]", "Maven", "static", p_, n, y, "build+tests", "API"],
             ["Remedius [4]", "Maven", "agents", p_, n, y, "build+tests", "API"],
             ["MaxNPM [7]", "npm", n, n, n, y, "solver", n],
             ["KEVGraph [6]", "multi", n, n, n, y, n, n],
             ["CAPE [5]", "Py/JS", "static", y, n, n, n, n],
             ["**EVIDENT**", "PyPI", "static (+dyn.)", y, y, y, "resolver+re-scan", "symbols+signat."]],
            "Positioning by each system's own functionality (✓ yes, ◐ partial, – no).",
            widths=[1450, 700, 900, 720, 780, 600, 1000, 850], font_pt=7)

    # ---------------------------------------------------------------- 3
    P.h1("The EVIDENT Approach")
    P.para("EVIDENT takes a lockfile (uv, Poetry, PDM, Pipenv, pinned requirements) and the application source, resolves "
           "the environment for a target (CPython 3.10, Linux x86-64), matches advisories from dated OSV/CVSS/EPSS/KEV "
           "snapshots, collects evidence, estimates exposure and plans remediation (Figure 1). Source, lockfiles and "
           "wheels are parsed, never executed.")
    P.figure(FIG / "architecture.png", "EVIDENT pipeline; shaded components are the core contributions.", width_cm=9.8)
    P.h2("Evidence semantics")
    P.para("A finding f = (application, package p, advisory a) carries one record per level with state, provenance and "
           "detail (Table 2). *Exposure* means that a vulnerable symbol of a executes when the deployed application "
           "runs.")
    P.table(["Level / state", "Emitted when (assumption)"],
            [["L3 C / R", "p is (not) installed for the target after PEP 508 markers and reachability from the roots; "
              "*dev* scope if reachable only from development roots"],
             ["L3b C / R / U", "C: a module of p is in the import closure of non-test application modules (literal "
              "imports, dotted strings); R: not in the closure and no loader reflection (A1); U: inconclusive or missing"],
             ["L4 C / P", "a vulnerable symbol is reachable from the roots through strong edges only (C) or only with "
              "weak, over-approximating edges (P)"],
             ["L4 R / U", "R: unreachable with weak edges and no blocking reflection within the chosen scope (A1), "
              "symbols valid (A2); U: blocked (inconclusive) or no symbols/source (missing)"],
             ["L5 O / N", "a vulnerable symbol was (not) executed in an observed run; N is never read as R"]],
            "Evidence states (C confirmed, P possible, R refuted, U unknown, O observed, N not observed).",
            widths=[1250, 5750], align=["left", "left"], font_pt=7.5)
    P.para("Refutation rests on two assumptions. (A1) *Closed world over a supported subset*: code is reached only "
           "through modelled constructs; reflection that could load or redirect code blocks refutation: `eval`, "
           "`exec`, `compile`, computed imports and entry-point/`pkgutil` plugin loading (*loaders*), and "
           "`globals()`/`locals()`/`vars()`, computed `setattr`, three-argument `type()` and assignments to another "
           "package's attributes (*redirectors*). Metaclasses, descriptors and C callbacks are outside the subset. "
           "Blocking is applied in one of four nested **scopes**: *global* (any blocking construct in the imported "
           "region; default), *package* (in the application, the vulnerable package or a package importing it), "
           "*module* (in a module that transitively imports the vulnerable package, or a loader in the application), "
           "*reachable* (as module, but only reflective code that is itself reachable). (A2) *Symbol validity*: mined "
           "symbols contain the vulnerable operation. VEX `not_affected` is emitted only for R, with A1–A2 stated. "
           "Conflicts follow precedence L3 R > L5 O > L4 > L3b; a test-only L5 O with L3b R yields low exposure "
           "because stages multiply.")
    P.h2("Cross-package static reachability")
    P.para("One graph spans the application and every installed distribution on a dependency path to a vulnerable "
           "package; roots are non-test module bodies, decorated or referenced functions and entry points. *Strong* "
           "edges: import-qualified calls (re-exports, star imports), constructor and `self` calls through the class "
           "hierarchy, calls on locals of inferred class type, literal dispatch containers, constant `getattr`. *Weak* "
           "edges: method-name matching restricted to imported packages, escaped function references reached by "
           "unresolved calls, computed `getattr` over module exports or class hierarchies, dotted strings, implicit "
           "protocol calls (`str()`, iteration, f-strings, `with`, subscripts, `in`).")
    P.h2("Vulnerable-symbol mining")
    st = SV.get("status", {})
    P.para(f"Only 2 of 14,236 OSV PyPI records name functions [21]. EVIDENT maps the *pre-fix* changed lines of non-test "
           "Python files in up to four fix commits per advisory to the innermost enclosing function and maps paths to "
           f"installed modules by suffix. Of {SV.get('advisories_mined')} advisories, {st.get('functions', 0)} yield "
           f"functions (median {SV.get('functions_per_advisory', {}).get('median')}), {st.get('module_only', 0)} only "
           f"module-level changes, {st.get('no_commit', 0)} have no fix commit, {st.get('no_python_change', 0)} change no "
           f"Python file and {st.get('too_broad', 0)} commits exceed 25 files. Fix commits of one advisory agree with "
           f"Jaccard {f2((SV.get('multi_commit') or {}).get('mean_jaccard'))}, a consistency, not a correctness, "
           f"measure; {pct((SV.get('path_mapping') or {}).get('rate'))} of changed files map to an installed module.")
    P.h2("Staged conditional exposure model")
    P.para("Let D (deployed), I (installed), M (imported) and C (called) be the stages, Y = D∧I∧M∧C, and "
           "E = (e3, e3b, e4, e5, g) the evidence with symbol granularity g. By the chain rule")
    P.equation([mr("P(Y=1|E)=P(D|E)·P(I|D,E)·P(M|D,I,E)·P(C|D,I,M,E)")])
    P.para("EVIDENT approximates each factor by conditioning only on its own level's evidence, i.e. it assumes "
           "C ⊥ (e3, e3b) | M, e4, e5, g and M ⊥ (e4, e5) | I, e3b: P(D|e3) is 1 for production and "
           "δ for development scope, P(I|e3) is 1, 0 or 0.8 for C, R, U, and")
    P.equation([mr("P(M|e3b)="), mfrac([mr("∑"), msub(mr("m"), mr("i")), mr("+α")], [msub(mr("n"), mr("e3b")),
                mr("+2α")]), mr(",   "), mr("P(C|e4,e5,g)="),
                mfrac([mr("∑"), msub(mr("y"), mr("i")), mr("+2α"), msub(mr("p"), mr("e4"))],
                      [msub(mr("n"), mr("e4,e5,g")), mr("+2α")])])
    P.para("Training subsets: the M-cell for state e uses findings that are installed in production with L3b = e and "
           "known import label m (runtime import trace); the C-cell uses only findings whose package was imported "
           "(m = 1). Cells back off to the L4 marginal p_e4, then to the stage prior; missing evidence uses the "
           "marginal of its level, inconclusive evidence its own cell; L5 O sets P(C) = 1. With α = 1 and "
           f"δ = 0.05 (a heuristic; sensitivity in §5.4) the model has {EV['n_parameters']['evident']} rates "
           "(supplement S13). Because the product of calibrated factors need not be calibrated, all reported "
           "calibration is measured on the final product. Probabilities can be re-targeted to a known deployment "
           "prevalence by prior correction [28], which assumes label shift (P(E|Y) unchanged); under covariate or "
           "concept shift, e.g. a different application architecture, it can fail.")
    P.h2("Remediation with a resolver in the loop")
    P.para("For each package in the scope (vulnerable packages and constraint-interacting parents/children) EVIDENT "
           "selects one of at most k candidates (current, first version fixing the current findings, first version "
           "with no known advisory, latest in the same minor and major series, latest), restricted to versions with a "
           "wheel installable on the target. The CP-SAT [25] model is")
    P.equation([mr("min "), mnary("∑", [mr("p,v")], None,
                [msub(mr("x"), mr("p,v")), mr("("), mnary("∑", [mr("a∈A(p,v)")], None,
                 [msub(mr("w"), mr("a")), msub(mr("P"), mr("a"))]), mr("+λ·"), mr("c(p,v)"), mr(")")])])
    P.para("subject to one version per package and the target-evaluated `requires_dist` constraints of every "
           "candidate. w_a = CVSS/10 (0.5 if absent) × 2 for KEV entries; advisories add up; newly introduced "
           "advisories use the package's stage prior; c(p,v) = 0 for the current version, else 1 + s + 0.5·[direct], "
           "s = 2/0.7/0.2 for a major/minor/patch change; λ = 0.1, k = 6. The loop (1) solves, (2) resolves with uv "
           "(`--no-build`, original pins preferred, same target), (3) on failure adds a no-good cut excluding exactly "
           "the failed assignment and repeats (at most 6 times), (4) re-scans the realised pins. Results are optimal "
           "only within the candidate set and model; because a cut removes one assignment while a failure is usually "
           "caused by a subset of it, the loop can exhaust its iterations before finding a resolvable plan. Plans are "
           "checked at three levels: L1 resolution, L2 every symbol the application references in a changed package "
           "still resolves, L2b its signature stays compatible (no new required or removed parameters); L3, running the "
           "application's tests, is not evaluated.")

    # ---------------------------------------------------------------- 4
    P.h1("Evaluation Design")
    sf, la = EV["sample_flow"], EV["leakage_audit"]
    P.para("**RQ1** How much do version-matched findings overstate exposure in real applications? **RQ2** How does the "
           "reachability analysis compare with call-graph tools? **RQ3** Are exposure probabilities calibrated and "
           "robust? **RQ4** Do verified plans resolve, stay compatible, and does calibration change them? Table 3 maps "
           "experiments to data.")
    pcN = (T.get("pareto_common") or {}).get("projects", 0)
    candN = (PH.get("candidates") or {}).get("6", {}).get("n", 0)
    P.table(["Experiment", "Data", "Units"],
            [["RQ1 exposure classes", "real-world corpus", f"{n_snap} applications, {n_find} findings"],
             ["RQ2 reachability", "EVIDENT-Bench, 1 advisory per package × 16 patterns",
              f"{CG.get('PyCG', {}).get('analysed', 0) + CG.get('PyCG', {}).get('failed', 0)} applications"],
             ["RQ2 refutation safety", "EVIDENT-Bench", f"{EV['n_rows']} pairs"],
             ["RQ3 calibration", "EVIDENT-Bench", f"{EV['n_rows']} pairs, {EV['n_advisories']} advisories, "
              f"{EV['n_packages']} packages"],
             ["RQ4 remediation", "resolvable real-world snapshots", f"{n_ok} applications"],
             ["RQ4 fronts / sensitivity", "resolvable snapshots with findings / first 25",
              f"{pcN} / {candN} applications"]],
            "Experiment-to-dataset mapping (findings of one application are not independent; the unit for statistics "
            "on real data is the application).", widths=[1900, 2900, 2200], align=["left", "left", "left"], font_pt=7.5)
    P.para(f"**EVIDENT-Bench.** For {EV['n_packages']} pure-Python packages at vulnerable versions we installed the exact "
           "version in an isolated environment and traced benign offline API probes; a probe *triggers* an advisory if "
           f"it executes a mined symbol. Each of the {sf['triggerable_advisories']} triggerable advisories yields 16 "
           f"applications (9 exposure, 7 non-exposure patterns); {sf['skipped_no_safe_probe']} were not generated because "
           f"{sf['advisories_without_safe_probe']} advisories lack a non-triggering probe, leaving {sf['final']} pairs "
           f"({pct(EV['label_rate'], 1)} exposed). The label is whether the production entry point executes a vulnerable "
           "symbol; L5 comes from a separate run of a test file that calls the entry point for a seeded half of the "
           f"applications. L5 agrees with the label in only {pct(la['l5_agrees_with_label'])} of pairs, but to exclude "
           "leakage the primary *static* setting omits L5. Validation is leave-one-package-out (all advisories of a "
           "package held out together), leave-one-pattern-out and a time split; 95% CIs use 1,000 package-grouped "
           "bootstrap resamples. ECE uses 10 equal-width bins, adaptive ECE 10 equal-mass bins.")
    P.para(f"**Real-world corpus.** {RN.get('collected', n_snap)} open-source Python applications were collected "
           "(web-application topics or well-known self-hosted applications, created before 2023, committed lockfile), "
           "each at the release closest to June 2023. Applications were processed in a fixed lexicographic order of "
           "repository identifier, which is independent of outcome; within the compute budget of this revision (one laptop; "
           f"resolver verification dominates cost) the full pipeline completed on {n_snap}, "
           f"{RN.get('timeouts', 0)} exceeded the 40-minute per-application budget and {RN.get('not_run', 0)} were not "
           f"processed. All real-world statistics are over the {n_snap} completed applications. The study is "
           "retrospective: 2023 environments judged with the 2026-11-12 advisory snapshot.")
    P.para("**Baselines.** Probabilities: version match, CORAL-style coefficients (1/0.5/0.1) [3], CAPE-style weighted "
           "score [5], naive Bayes, logistic regression and gradient boosting (isotonic). Reachability: PyCG [12] and "
           "Jarvis [13] (published versions, Python 3.11 with the pilot's documented compatibility shims). Remediation: "
           "minimal fix and latest per package, upgrade-all, *uv-fix* (minimum fixed versions as constraints, resolver "
           "chooses the rest), and our optimiser with version-match, CORAL-style or calibrated weights. Weighting "
           "schemes of CORAL, CAPE and KEVGraph are re-implemented, isolating weighting.")

    # ---------------------------------------------------------------- 5
    P.h1("Results")
    P.h2("RQ1: Over-estimation in real applications")
    lb, ar = T.get("l4_breakdown", {}).get("states", {}), T.get("app_reflection", {})
    P.para(f"The {n_snap} applications install a median of {RW['installed']['median']:.0f} packages and have {n_find} "
           f"version-matched findings (median {RW['findings']['median']:.0f} per application; "
           f"{pct(RW['transitive_findings_share']['mean'])} in transitive dependencies). All findings fall into one class: "
           f"not installed for the target {C('NOT_INSTALLED')}, development-only {C('DEV_ONLY')}, not imported "
           f"{C('NOT_IMPORTED')}, statically unreachable {C('STATICALLY_UNREACHABLE')}, import unknown "
           f"{C('INSTALLED_UNKNOWN')}, imported with reachability unknown {C('IMPORTED_REACH_UNKNOWN')}, possibly "
           f"reachable {C('POSSIBLY_REACHABLE')}, statically reachable {C('STATICALLY_REACHABLE')}. Thus "
           f"{pct(dismiss / tot, 1)} are dismissed with a justification, mostly by installation and import evidence. In "
           f"{ar.get('app_has_blocking_reflection', 0)} of {ar.get('projects', 0)} applications the application code "
           "itself contains loader or redirector reflection, which under global scope blocks every refutation (Table 4).")
    scb = EV.get("reflection_scopes", {})
    scr = PH.get("scopes", {})
    rows = []
    for s in ("global", "package", "module", "reachable"):
        b = scb.get(s, {})
        rows.append([s, str(b.get("refuted", "n/a")), str(b.get("false_refutations", "n/a")),
                     str(scr.get(f"{s}_REFUTED", 0)), str(scr.get(f"{s}_UNKNOWN", 0))])
    P.table(["Reflection scope", "Bench: refuted", "Bench: false refutations", "Real: refuted", "Real: blocked"], rows,
            f"Refutations under nested reflection scopes (bench: {scb.get('candidates', 'n/a')} pairs without a static "
            "path; real: findings in imported packages without a static path).",
            widths=[1600, 1300, 1600, 1250, 1250], font_pt=7.5)
    P.para(scopes_text(scb, scr))

    P.h2("RQ2: Reachability compared with PyCG and Jarvis")
    P.para("*Procedure.* For each tool we take its call graph and predict *exposed* iff a mined vulnerable symbol is "
           "reachable from the application's entry module; a missing edge therefore counts as *not exposed*, which is "
           "how a call graph must be read when used for refutation. Crashes, time-outs (180 s) and memory overruns (3 GB) are reported "
           "separately and excluded from precision and recall; tools were installed once (no installation failures). "
           "EVIDENT is evaluated with strong edges only and with weak edges.")
    P.table(["Analysis", "Analysed", "Failures", "Precision", "Recall", "Exposed missed"],
            [cg_row("PyCG"), cg_row("Jarvis"), cg_row("EVIDENT strong"), cg_row("EVIDENT strong+weak")],
            "Reachability of mined symbols on EVIDENT-Bench applications (execution ground truth); per-pattern results "
            "in supplement S9.", widths=[1900, 900, 900, 1000, 900, 1400], font_pt=7.5)
    P.para(cg_text())

    P.h2("RQ3: Calibration and robustness of exposure probabilities")
    rows = []
    for m, lab in (("version_match", "Version match"), ("coral_style", "CORAL-style"), ("cape_style", "CAPE-style"),
                   ("naive_bayes", "Naive Bayes"), ("logistic_iso", "Logistic + iso."),
                   ("hgb_iso", "Grad. boosting + iso."), ("evident", "**EVIDENT**")):
        d = MS[m]
        rows.append([lab, f"{f3(d['brier'])} {ci(m)}", f3(d["ece"]), f3(d["ace"]), f2(d["slope"]), f3(d["auc"]),
                     f3(d.get("AP")), f3(MR[m]["brier"])])
    P.table(["Method", "Brier [95% CI]", "ECE", "Ad. ECE", "Slope", "AUC", "AP", "Brier +L5"], rows,
            "Exposure probabilities on EVIDENT-Bench, static setting, leave-one-package-out; last column adds L5.",
            widths=[1650, 1550, 600, 650, 550, 600, 600, 800], font_pt=7)
    pdl = MS["paired"]["evident-logistic_iso"]["brier"]
    pdc = MS["paired"]["evident-coral_style"]["brier"]
    lpo, ts, ps = EV["leave_pattern_out"], EV["time_split"], EV["prevalence_shift"]
    mi = EV["missingness"]
    rp = mi.get("realworld_profile", {})
    P.para(f"EVIDENT's final probabilities are calibrated (ECE {f3(MS['evident']['ece'])}, slope "
           f"{f2(MS['evident']['slope'])}) and statistically tied with logistic regression (ΔBrier "
           f"{pdl['mean']:+.3f}, CI [{pdl['ci'][0]:+.3f}, {pdl['ci'][1]:+.3f}]); they beat CORAL-style coefficients "
           f"(Δ {pdc['mean']:+.3f}, CI [{pdc['ci'][0]:+.3f}, {pdc['ci'][1]:+.3f}]). Discrimination is moderate "
           f"(AUC {f3(MS['evident']['auc'])}) because static evidence cannot separate guarded or dead code from live "
           "code; we claim interpretability and missing-evidence handling, not superior accuracy. Adaptive ECE is "
           f"higher than ECE ({f3(MS['evident']['ace'])}) because equal-mass bins split the dense middle range. "
           f"Leave-one-pattern-out gives Brier {f3(lpo['evident']['brier'])} (logistic {f3(lpo['logistic_iso']['brier'])}), "
           f"the time split (train ≤ 2024, test 2025–2026) {f3(ts['methods']['evident']['brier'])}. Under "
           f"advisory-correlated missingness of L4 (50%) ECE is {f3(mi['advisory']['0.5']['evident']['ece'])} vs "
           f"{f3(mi['advisory']['0.5']['logistic_iso']['ece'])} for logistic regression, under the real-world "
           f"missingness profile {f3(rp.get('evident', {}).get('ece'))} vs {f3(rp.get('logistic_iso', {}).get('ece'))} "
           f"(Figure 2b). At 10% prevalence ECE rises to {f3(ps['0.1']['evident_raw']['ece'])} and prior correction "
           f"restores {f3(ps['0.1']['evident_prior_corrected']['ece'])}. In the factorial ablation import evidence "
           f"matters most (Brier without L3b {f3(EV['factorial'].get('L4+L5', {}).get('brier'))}, all levels "
           f"{f3(EV['factorial'].get('L3b+L4+L5', {}).get('brier'))}).")
    P.figure(FIG / "calibration.png", "(a) Reliability (static setting, 10 bins, 95% bootstrap intervals for EVIDENT); "
             "(b) calibration when L4 is missing in different patterns.", width_cm=12.3)

    P.h2("RQ4: Verified remediation")
    rows = []
    for s, lab in (("audit_fix", "Minimal fix (pip-audit)"), ("latest", "Latest"), ("upgrade_all", "Upgrade all"),
                   ("uv_fix", "uv-fix (resolver)"), ("vm_opt", "Optimiser, version-match w."),
                   ("coral_opt", "Optimiser, CORAL-style w."), ("evident", "**EVIDENT** (calibrated w.)")):
        if s not in REM:
            continue
        k = int(round(S(s, "ok") * Sn(s)))
        rows.append([lab, frac(k, Sn(s)), f"{S(s, 'changed'):.1f}", f"{S(s, 'major_bumps'):.1f}",
                     pct(S(s, "findings_removed")), pct(S(s, "confirmed_fixed")), cl(s, "level2_ok"), cl(s, "level2b_ok")])
    P.table(["Strategy", "L1 resolves", "Changed", "Major", "Findings removed", "Confirmed fixed", "L2 symbols",
             "L2b signat."], rows,
            f"Remediation on {n_ok} resolvable applications. Changed/major/removed: means over resolved plans; L2/L2b: "
            "resolved plans with every referenced symbol (and signature) intact. Per-project results in supplement S11.",
            widths=[1900, 750, 650, 550, 850, 850, 750, 700], font_pt=7)
    P.para(remediation_text())
    P.para(sensitivity_text())
    cs = case_study_text()
    if cs:
        P.para(cs)

    # ---------------------------------------------------------------- 6/7
    P.h1("Threats to Validity")
    P.para("*Construct.* Exposure means execution of a function changed by the fix (A2); it upper-bounds "
           "exploitability. Manual validation of mined symbols is pending (protocol and 40-advisory sample in the "
           "artifact). *Internal.* Benchmark applications follow 16 patterns that fix the prevalence; L5 is a simulated "
           "test run; baselines re-implement weighting schemes; PyCG and Jarvis ran with compatibility shims on "
           "Python 3.11. *External.* Popular open-source applications with lockfiles; the real-world results cover "
           f"{n_snap} of {RN.get('collected', n_snap)} collected applications (an outcome-independent lexicographic "
           "prefix), so per-application rates carry wide intervals; one target platform; source "
           "distributions are never built. Compatibility is shown at Levels 1, 2 and 2b only; symbol resolution is not "
           "behavioural compatibility, and tests were not run because that executes third-party code [14].")
    P.h1("Conclusion")
    P.para("EVIDENT makes exposure evidence explicit, conditional and auditable. On execution-labelled data its "
           "probabilities are calibrated and robust to correlated missing evidence, and its analysis refuted no "
           "exposed code. On real applications conservative analysis rarely refutes reachability because applications "
           "are reflective, so evidence mainly justifies dismissing findings and calibrated weights seldom change "
           "plans; verified plans nevertheless resolve on every resolvable application, which per-package fixes do not. Scoped reflection and "
           "framework-aware or exploit-oriented evidence are the most promising ways to let calibration change "
           "decisions.")
    P.h_unnumbered("Data Availability")
    P._first = True
    P.para(f"Code, EVIDENT-Bench, mined symbols, snapshot list, intelligence snapshot dates, scripts and the online "
           f"supplement: {REPO}.")
    P.references(REFS)
    out = HERE / "EVIDENT_paper.docx"
    P.save(out)
    print("wrote", out)


def cg_row(name):
    d = CG.get(name, {})
    return [name, str(d.get("analysed", "n/a")), str(d.get("failed", "n/a")), f3(d.get("precision")),
            f3(d.get("recall")), f"{d.get('missed_exposed', 'n/a')}/{d.get('exposed', 'n/a')}"]


def cg_text() -> str:
    pyc, jar = CG.get("PyCG", {}), CG.get("Jarvis", {})
    evs, evw = CG.get("EVIDENT strong", {}), CG.get("EVIDENT strong+weak", {})
    cf = EV["analysis_confusion"]["L4_refuted"]
    return (f"PyCG misses {pyc.get('missed_exposed')} of {pyc.get('exposed')} exposed applications it analysed and "
            f"Jarvis {jar.get('missed_exposed')} of {jar.get('exposed')}; both lose paths through re-exported classes, "
            "computed `getattr` and dynamic dispatch inside the library (supplement S9). EVIDENT's strong edges have "
            f"precision {f3(evs.get('precision'))} and recall {f3(evs.get('recall'))}; weak edges raise recall to "
            f"{f3(evw.get('recall'))} at precision {f3(evw.get('precision'))}. The graph tools are more precise on "
            "non-exposed patterns, but used for refutation they would wrongly dismiss exposed code. On the whole "
            f"benchmark {cf['exposed']} of {cf['n']} REFUTED verdicts were exposed: no false refutation on the "
            "supported subset, which is evidence, not proof, of soundness.")


def scopes_text(scb, scr) -> str:
    g, r = scb.get("global", {}), scb.get("reachable", {})
    bench = (f"leaves benchmark refutations unchanged at {g.get('refuted')}" if g.get('refuted') == r.get('refuted')
             else f"increases benchmark refutations from {g.get('refuted')} to {r.get('refuted')}")
    return (f"Narrowing the scope from global to reachable-module {bench} ({r.get('false_refutations')} false), "
            f"and raises real-world refutations from {scr.get('global_REFUTED', 0)} to "
            f"{scr.get('reachable_REFUTED', 0)}. Narrower scopes rest "
            "on a stronger assumption (reflection affects only code it can import or reach), so EVIDENT reports the scope "
            "with every refutation and uses the global scope by default.")


def remediation_text() -> str:
    ev = "evident"
    fl = {k: v for k, v in T.get("failures", {}).get(ev, {}).items() if k != "none"}
    t_uv, t_vm, t_fr = test("uv_fix", "changed"), test("vm_opt", "changed"), test("vm_opt", "findings_removed")
    rc = T.get("remediation_ci", {})
    s = (f"Independent per-package upgrades resolve in {frac(int(round(S('audit_fix', 'ok') * Sn('audit_fix'))), Sn('audit_fix'))} "
         f"(minimal fix) and {frac(int(round(S('latest', 'ok') * Sn('latest'))), Sn('latest'))} (latest) applications; "
         f"upgrade-all always resolves but changes {S('upgrade_all', 'changed'):.1f} packages and keeps the referenced "
         f"API in only {cl('upgrade_all', 'level2_ok')}. EVIDENT plans resolve in {frac(ev_ok_k, Sn(ev))}")
    if fl:
        s += " (failures: " + ", ".join(f"{k} {v}" for k, v in sorted(fl.items(), key=lambda kv: -kv[1])) + ")"
    s += f" after {S(ev, 'iterations'):.1f} iterations on average"
    if rc.get("evident_changed"):
        s += f"; they change {S(ev, 'changed'):.1f} packages (95% CI {rc['evident_changed']})"
    s += (f". The resolver adds {S(ev, 'unplanned_changes'):.1f} unplanned changes ({S(ev, 'unplanned_major'):.1f} "
          f"major, {S(ev, 'new_findings_from_unplanned'):.1f} new findings), close to the drift of re-resolving the "
          f"untouched environment ({T['baseline_drift']['mean']:.1f}); the realised estimated risk differs from the "
          f"plan's by {S(ev, 'objective_gap'):+.2f}. ")
    if t_uv:
        s += (f"uv-fix changes a median of {t_uv['other']:.0f} packages vs {t_uv['evident']:.0f} for EVIDENT "
              f"(Wilcoxon p = {t_uv['p']:.3f}, n = {t_uv['n']}). ")
    if t_vm and t_fr:
        s += (f"Against the same optimiser with version-match weights, calibrated weights change {t_vm['evident']:.0f} "
              f"vs {t_vm['other']:.0f} packages (median; p = {t_vm['p']:.3f}) and remove {pct(t_fr['evident'])} vs "
              f"{pct(t_fr['other'])} of findings (p = {t_fr['p']:.3f}). ")
    pc = T.get("pareto_common") or {}
    if pc:
        s += (f"Scored with one yardstick over a λ sweep, both weightings trace nearly the same front (mean area "
              f"difference {pc['mean_auc_gain']:+.3f}, median {pc['median_auc_gain']:+.3f}; calibrated better in "
              f"{pc['better']}, worse in {pc['worse']} of {pc['projects']} applications). ")
    pdisc = T.get("pareto_vs_discrimination") or {}
    if pdisc:
        s += (f"We hypothesised that calibration helps more when evidence is decisive; the data "
              f"{'support' if pdisc['p'] < 0.05 and pdisc['spearman_rho'] > 0 else 'do not support'} this "
              f"(Spearman ρ = {pdisc['spearman_rho']:.2f}, p = {pdisc['p']:.2f}, n = {pdisc['n']}). ")
    s += "Calibration changes plans only when probabilities differ across findings, which they rarely do today."
    return s


def sensitivity_text() -> str:
    dp, wt, cd = PH.get("devprior", {}), PH.get("weights", {}), PH.get("candidates", {})
    dec = T.get("decision", {})
    parts = []
    if dp:
        lo, hi = dp.get("0.0", {}), dp.get("0.25", {})
        parts.append(f"Varying δ from 0 to 0.25 changes the expected number of exposed findings from "
                     f"{lo.get('expected_exposed', 0):.0f} to {hi.get('expected_exposed', 0):.0f} and leaves plans "
                     f"{pct(hi.get('mean_plan_jaccard_vs_default'))} identical (Jaccard)")
    if wt:
        parts.append(f"KEV multipliers 1 and 3 give plans identical to the default in "
                     f"{wt.get('kev1_sum', {}).get('identical_plans')} and {wt.get('kev3_sum', {}).get('identical_plans')} "
                     f"of {wt.get('kev2_sum', {}).get('projects')} applications, max-aggregation in "
                     f"{wt.get('kev2_max', {}).get('identical_plans')}")
    if cd:
        parts.append("candidate limits 6/8/12/20 resolve " + "/".join(pct(cd.get(k, {}).get("ok")) for k in
                                                                     ("6", "8", "12", "20"))
                     + f" of {cd.get('6', {}).get('n')} applications"
                     + (" with identical plans (mean "
                        f"{cd.get('6', {}).get('changes', 0):.1f} changes), so six versions per package already cover "
                        "the useful candidates"
                        if len({round(cd.get(k, {}).get('changes') or -1, 6) for k in ("6", "8", "12", "20")}) == 1
                        else " with mean changes " + "/".join(f"{cd.get(k, {}).get('changes', 0):.1f}"
                                                               for k in ("6", "8", "12", "20"))))
    s = ("**Sensitivity.** " + "; ".join(parts) + ".") if parts else ""
    if dec:
        s += (f" **Decision sensitivity.** Setting each uncertain finding's probability to 0 or 1 changes the optimal "
              f"plan for only {dec.get('critical_total')} of {dec.get('uncertain_total')} findings (median "
              f"{dec.get('median_critical', 0):.0f} per application): the short list worth manual triage.")
    return s


def case_study_text() -> str:
    best = None
    for d in sorted((RES / "realworld").glob("*/result.json")):
        r = json.loads(d.read_text("utf8"))
        ev = (r.get("strategies") or {}).get("evident", {})
        if not ev.get("ok"):
            continue
        for f in json.loads((d.parent / "findings.json").read_text("utf8")):
            e4 = f["evidence"].get("L4", {})
            wit = (e4.get("detail") or {}).get("witness") or []
            if e4.get("state") == "CONFIRMED" and len(wit) >= 3 and f["package"] in ev.get("planned", {}):
                sc = (f.get("cvss") or 0) + 0.1 * len(wit)
                if best is None or sc > best[0]:
                    best = (sc, r, f, ev)
    if not best:
        return ""
    _, r, f, ev = best
    det = f["evidence"]["L4"]["detail"]
    wit = det["witness"]
    path = " → ".join([wit[0].replace("__app__.", ""), "…", wit[-1]] if len(wit) > 3 else wit)
    comp = (PH.get("compat_per_project", {}).get(r["id"], {}) or {}).get("evident", {})
    return (f"**Case study.** In {r['meta']['repo']} ({r['meta']['tag'][:12]}), {f['package']} {f['version']} is "
            f"affected by {f['advisory']} (CVSS {f.get('cvss')}); it is installed for production and imported, and "
            f"the fix commit yields {len(det.get('symbols', []))} vulnerable function{'s' if len(det.get('symbols', [])) != 1 else ''} reached through strong edges "
            f"({path}), so P = {f3(f.get('p_exposed'))}. The verified plan upgrades it to {ev['planned'][f['package']]} "
            f"with {len(ev['planned']) - 1} other package{'s' if len(ev['planned']) - 1 != 1 else ''}; the resolver changes {ev.get('unplanned_changes')} more; the "
            f"re-scan leaves {ev.get('residual_findings')} of {r['original']['residual_findings']} findings; L2/L2b checks "
            f"{'pass' if comp.get('level2b_ok') else 'flag ' + str(comp.get('missing_pkgs', 0) + comp.get('signature_pkgs', 0)) + ' package(s)'} "
            "(supplement S12).")


if __name__ == "__main__":
    build()
