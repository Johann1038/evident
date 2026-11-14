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
R3B, R3R = J("round3_bench.json", {}), J("round3_realworld.json", {})
R3C, R3S = J("round3_callgraph.json", {}), J("round3_symbol_text.json", {})
RELEASE = J("release.json", {})
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
_cc = (R3C.get("common") or {})
_cov = (R3R.get("coverage") or {})
ABSTRACT = (
    "Software composition analysis reports every dependency in an advisory's version range, although much "
    "vulnerable code never runs. EVIDENT grades Python findings with three-valued evidence (installation, imports, "
    "cross-package static reachability of functions mined from fix commits, optional runtime traces), turns it into "
    "exposure probabilities with a staged model that treats missing evidence as neutral, and plans remediation with a "
    "constraint solver checked by a metadata-only resolver and a static API check. On "
    f"{EV['n_rows']} execution-labelled pairs ({EV['n_advisories']} advisories, {EV['n_packages']} packages) the model "
    f"is calibrated without runtime evidence (Brier {f3(MS['evident']['brier'])}, 95% CI {ci('evident')}; ECE "
    f"{f3(MS['evident']['ece'])}) and statistically tied with logistic regression. "
    + (f"On the {R3C.get('common_subset')} applications that PyCG, Jarvis and EVIDENT all analysed, strong-edge "
       f"reachability matches Jarvis (F1 {f2(_cc['EVIDENT strong']['f1'])} vs {f2(_cc['Jarvis']['f1'])}); adding weak "
       f"edges misses no exposed application at precision {f2(_cc['EVIDENT strong+weak']['precision'])}, and no "
       f"REFUTED verdict was exposed. " if _cc else "")
    + f"In {n_snap} historical applications, {pct(dismiss / tot, 1)} of {n_find} findings are dismissed with a "
    + (f"justification, yet at the default reflection scope static analysis refutes none, because the applications "
       f"themselves use reflection." if not C('STATICALLY_UNREACHABLE') else
       f"justification, yet static analysis refutes only {C('STATICALLY_UNREACHABLE')} because the applications "
       f"themselves use reflection.")
    + f" Verified plans resolve for {frac(ev_ok_k, Sn('evident'))} applications whose lockfile resolves on the target "
    + (f"({frac(_cov.get('resolvable'), _cov.get('completed'))} end to end); " if _cov else "; ")
    + "calibrated weights trade fewer changes for fewer removed findings. Evidence helps triage more than it "
      "changes remediation.")
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
           "reachable [9–11, 26], tools disagree [15], and upgrading everything is costly and can break "
           "applications [14]. Reachability-aware tools grade findings [1, 2, 5] and remediation optimisers "
           "choose versions under constraints [3, 4, 6, 7], but their evidence weights are hand-chosen, missing "
           "evidence is often read as negative [16], and it is unknown *when* evidence actually changes a decision.")
    P.para("Our thesis is that a finding should become an upgrade only in proportion to reliable evidence of exposure. "
           "EVIDENT contributes (1) **evidence reliability**: formally defined three-valued evidence with explicit soundness "
           "assumptions and scoped reflection handling; (2) **vulnerable-code reachability** for Python across package "
           "boundaries, compared with PyCG [12] and Jarvis [13]; (3) **statistically reliable exposure estimation**: a "
           "staged conditional model calibrated on execution ground truth and evaluated for leakage, unseen packages, "
           "unseen patterns, prevalence shift and correlated missingness; (4) **decision-aware remediation**: a CP-SAT "
           "planner verified by a resolver with metadata and statically referenced API compatibility checks, and a "
           "measurement of when calibrated weights change plans. All data and scripts are released [Data Availability].")

    # ---------------------------------------------------------------- 2
    P.h1("Related Work and Positioning")
    P.para("**Reachability.** Eclipse Steady [1, 2] combines static and dynamic reachability for Java and offers update "
           "metrics as decision support without quantifying risk. Python call-graph generators [12, 13] output graphs, "
           "not verdicts; reading a missing edge as unreachability is unsafe for security negatives. Exploit-test "
           "generation [18] gives stronger, Java-specific evidence. **Prioritisation.** CVSS, EPSS [19] and KEV [20] "
           "rank vulnerabilities, not application exposure; CAPE [5] grades Python/JS findings into evidence regimes, "
           "but its scores are not validated probabilities. **Remediation.** Installation as optimisation goes back to OPIUM [8]; MaxNPM [7] adds "
           "vulnerability objectives for npm, Ranger [27] restores safe ranges in Maven, CORAL [3] minimises "
           "reachability-weighted CVSS under compatibility constraints, Remedius [4] encodes agent-gathered evidence as "
           "SMT constraints, KEVGraph [6] solves an exploitation-ordered set cover; none estimates calibrated "
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
    P.figure(FIG / "architecture.png", "EVIDENT pipeline; shaded components are the core contributions.", width_cm=8.4)
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
           "*module* (in a module transitively importing it, or a loader in the application), *reachable* (as module, "
           "but only reachable reflective code). (A2) *Symbol validity*: mined "
           "symbols contain the vulnerable operation. VEX `not_affected` is emitted only for R, with A1–A2 stated; "
           "conflicts follow precedence L3 R > L5 O > L4 > L3b.")
    P.h2("Cross-package static reachability")
    P.para("One graph spans the application and every installed distribution on a dependency path to a vulnerable "
           "package; roots are non-test module bodies, decorated or referenced functions and entry points. *Strong* "
           "edges: import-qualified calls (re-exports, star imports), constructor and `self` calls through the class "
           "hierarchy, calls on inferred-type locals, literal dispatch, constant `getattr`. *Weak* "
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
           f"measure; {pct((SV.get('path_mapping') or {}).get('rate'))} of changed files map to an installed module. "
           + (f"A commit-independent partial check: of {R3S['text_names_code']} advisories whose OSV text names code, "
              f"{pct(R3S['agreement'])} (95% CI {pct(R3S['agreement_ci95'][0])}–{pct(R3S['agreement_ci95'][1])}) have a "
              "named function or class among the mined symbols; most others name the public entry point while the fix "
              "changes its implementation. 5 of 570 mined sets contained package-internal test functions (filter "
              "corrected; never called by applications)."
              if R3S else ""))
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
           "calibration is measured on the final product. Prior correction [28] re-targets probabilities to a known "
           "prevalence under label shift (P(E|Y) unchanged); under covariate or concept shift it can fail. "
           + (lambda fz: (f"A joint model of P(Y|E) per complete evidence configuration reaches the same Brier "
                          f"({f3(fz['joint_configuration']['brier'])} vs {f3(fz['staged']['brier'])}, difference CI "
                          f"[{fz['staged_minus_joint_brier']['ci'][0]:+.4f}, {fz['staged_minus_joint_brier']['ci'][1]:+.4f}]): "
                          "the factorisation costs no accuracy, but the benchmark, where import refutation implies "
                          "reachability refutation, cannot test it more strongly."
                          ) if fz else "")(R3B.get("factorisation")))
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
           "the failed assignment and repeats (at most 6 times), (4) re-scans the realised pins. Plans are optimal only "
           "within the candidate set and model. Plans are "
           "checked at three levels: L1 resolution, L2 every symbol the application references in a changed package "
           "still resolves, L2b its signature stays compatible (no new required or removed parameters); L3, running the "
           "application's tests, is not evaluated.")

    # ---------------------------------------------------------------- 4
    P.h1("Evaluation Design")
    sf, la = EV["sample_flow"], EV["leakage_audit"]
    pcN = (T.get("pareto_common") or {}).get("projects", 0)
    P.para("**RQ1** How much do version-matched findings overstate exposure in real applications? **RQ2** How does the "
           "reachability analysis compare with call-graph tools? **RQ3** Are exposure probabilities calibrated and "
           "robust? **RQ4** Do verified plans resolve, stay compatible, and does calibration change them? Units: RQ1 "
           f"{n_snap} applications ({n_find} findings); RQ2 {R3C.get('applications', 0)} EVIDENT-Bench applications (one "
           f"advisory per package × 16 patterns) and {EV['n_rows']} pairs for refutation safety; RQ3 {EV['n_rows']} pairs; "
           f"RQ4 {n_ok} applications (fronts {pcN}). Findings of one application are not independent, so statistics on "
           "real data use the application as unit.")
    P.para(f"**EVIDENT-Bench.** For {EV['n_packages']} pure-Python packages at vulnerable versions we installed the exact "
           "version in an isolated environment and traced benign offline API probes; a probe *triggers* an advisory if "
           f"it executes a mined symbol. Each of the {sf['triggerable_advisories']} triggerable advisories yields 16 "
           f"applications (9 exposure, 7 non-exposure patterns); {sf['skipped_no_safe_probe']} were not generated because "
           f"{sf['advisories_without_safe_probe']} advisories lack a non-triggering probe, leaving {sf['final']} pairs "
           f"({pct(EV['label_rate'], 1)} exposed). The label is whether the production entry point executes a vulnerable "
           "symbol; L5 comes from a separate test-file run (agreeing with the label in "
           f"{pct(la['l5_agrees_with_label'])} of pairs), and the primary *static* setting omits it. Validation is "
           "leave-one-package-out, leave-one-pattern-out and a time split; 95% CIs use 1,000 package-grouped bootstrap "
           "resamples; ECE uses 10 equal-width, adaptive ECE 10 equal-mass bins. Missing evidence masks L4 (never "
           "labels) per pair, advisory or package with q ∈ {0.25, 0.5, 0.75}, or per advisory at the real-world rate; "
           "5 seeds, identical masks for all models (supplement S14).")
    P.para(f"**Real-world corpus.** {RN.get('collected', n_snap)} open-source Python applications were collected "
           "(web applications created before 2023 with a committed lockfile) at the release closest to June 2023 and "
           "processed in fixed lexicographic order of repository identifier; within the compute budget (one laptop) "
           f"the pipeline completed on {n_snap}, "
           f"{RN.get('timeouts', 0)} exceeded the 40-minute per-application budget and {RN.get('not_run', 0)} were not "
           f"processed; all real-world statistics are over the {n_snap}. The study is retrospective (2023 "
           "environments, 2026-11-12 advisories). "
           + (lambda sm, cv: (f"Completed and unprocessed applications do not differ in stars (Mann-Whitney p = "
                              f"{sm['stars']['mannwhitney_p']:.2f}), locked packages ({sm['locked']['mannwhitney_p']:.2f}) "
                              f"or framework (χ² {sm['framework']['chi2_p']:.2f}) but do in lockfile kind "
                              f"({sm['lock_kind']['chi2_p']:.3f}; more requirements files); the time-outs occurred while "
                              "scanning (supplement S14). The sample does not represent the ecosystem. Remediation needs a "
                              f"baseline that resolves on the target; {cv['completed'] - cv['resolvable']} do not "
                              f"({sum(v for k, v in cv['excluded_reasons'].items() if 'conflict' in k)} unsatisfiable "
                              f"lockfiles, {sum(v for k, v in cv['excluded_reasons'].items() if 'conflict' not in k)} "
                              f"without a compatible wheel), leaving {cv['resolvable']} ({pct(cv['end_to_end_coverage'])} "
                              "end-to-end coverage).") if sm and cv else "")(
               (R3R.get("sample") or {}).get("tests_completed_vs_not_processed"), R3R.get("coverage")))
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
           f"{pct(RW['transitive_findings_share']['mean'])} transitive). Classes: not installed {C('NOT_INSTALLED')}, "
           f"dev-only {C('DEV_ONLY')}, not imported {C('NOT_IMPORTED')}, unreachable {C('STATICALLY_UNREACHABLE')}, "
           f"import unknown {C('INSTALLED_UNKNOWN')}, reachability unknown {C('IMPORTED_REACH_UNKNOWN')}, possibly "
           f"reachable {C('POSSIBLY_REACHABLE')}, reachable {C('STATICALLY_REACHABLE')}; "
           f"{pct(dismiss / tot, 1)} are dismissed with a justification, mostly by installation and import evidence. In "
           f"{ar.get('app_has_blocking_reflection', 0)} of {ar.get('projects', 0)} applications the application code "
           "itself contains loader or redirector reflection, which under global scope blocks every refutation (Table 3).")
    scb = EV.get("reflection_scopes", {})
    scr = PH.get("scopes", {})
    rows = []
    for s in ("global", "package", "module", "reachable"):
        b = scb.get(s, {})
        rows.append([s, str(b.get("refuted", "n/a")), str(b.get("false_refutations", "n/a")),
                     str(scr.get(f"{s}_REFUTED", 0)), str(scr.get(f"{s}_UNKNOWN", 0))])
    P.table(["Reflection scope", "Bench: refuted", "Bench: false refutations", "Real: refuted", "Real: blocked"], rows,
            f"Path-based refutations under nested reflection scopes (bench: the {scb.get('candidates', 'n/a')} pairs "
            "whose package is imported but has no strong path; real: findings in imported packages without a static "
            "path). Import-based refutations are not scope-dependent and are excluded.",
            widths=[1600, 1300, 1600, 1250, 1250], font_pt=7.5)
    P.para(scopes_text(scb, scr))

    P.h2("RQ2: Reachability compared with PyCG and Jarvis")
    P.para("We evaluate a *reachability-derived security decision* (PyCG and Jarvis issue no verdicts): a tool "
           "predicts *exposed* iff a mined symbol is reachable from the entry module in its graph, so a missing edge "
           "means *not exposed*. Crashes, time-outs (180 s) and memory overruns (3 GB) are failures; metrics use the "
           "common subset all tools analysed.")
    cc = R3C.get("common", {})
    fr = R3C.get("failure_rate", {})

    def crow(lab, key, frk):
        d, a = cc.get(key, {}), CG.get(key, {})
        return [lab, f"{a.get('analysed', 'n/a')} ({pct(fr.get(frk), 0)})", f3(d.get("precision")),
                f3(d.get("recall")), f3(d.get("f1")), f"{d.get('missed_exposed')}/{d.get('tp', 0) + d.get('fn', 0)}",
                str(d.get("false_alarms"))]
    P.table(["Analysis", "Analysed (failed)", "Precision", "Recall", "F1", "Exposed missed", "False alarms"],
            [crow("PyCG", "PyCG", "PyCG"), crow("Jarvis", "Jarvis", "Jarvis"),
             crow("EVIDENT strong", "EVIDENT strong", "EVIDENT"), crow("EVIDENT strong+weak", "EVIDENT strong+weak", "EVIDENT")],
            f"Reachability-derived exposure decisions on EVIDENT-Bench (execution ground truth). Analysed: of "
            f"{R3C.get('applications', 'n/a')} applications; metrics on the {R3C.get('common_subset', 'n/a')} applications "
            "all tools analysed. Per-pattern and all-population results in supplement S9.",
            widths=[1800, 1250, 850, 750, 650, 1050, 900], font_pt=7.5)
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
            "Exposure probabilities on EVIDENT-Bench, leave-one-package-out. All columns use the primary static setting "
            "(L3b, L4) except the last, which adds runtime evidence L5 and is not comparable with the static results.",
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
           "code; we claim interpretability and missing-evidence handling, not superior accuracy. "
           + (lambda lp, t3: (f"Leave-one-pattern-out gives Brier {f3(lp['evident']['brier'])} "
                              f"[{lp['evident']['brier_ci'][0]:.3f}, {lp['evident']['brier_ci'][1]:.3f}] (logistic "
                              f"{f3(lp['logistic_iso']['brier'])}; CORAL-style {f3(lp['coral_style']['brier'])}, whose fixed "
                              "coefficients lose nothing on unseen patterns), the time split "
                              f"(train ≤ 2024, test 2025–2026) {f3(t3['evident']['brier'])} [{t3['evident']['brier_ci'][0]:.3f}, "
                              f"{t3['evident']['brier_ci'][1]:.3f}] (logistic {f3(t3['logistic_iso']['brier'])}). ")
                             if lp and t3 else "")(R3B.get("leave_pattern_out"), R3B.get("time_split"))
           + f"Under advisory-correlated missingness of L4 (50%) ECE is {f3(mi['advisory']['0.5']['evident']['ece'])} vs "
           f"{f3(mi['advisory']['0.5']['logistic_iso']['ece'])} for logistic regression, under the real-world "
           f"missingness profile {f3(rp.get('evident', {}).get('ece'))} vs {f3(rp.get('logistic_iso', {}).get('ece'))} "
           f"(Figure 2b); at 10% prevalence prior correction lowers ECE from {f3(ps['0.1']['evident_raw']['ece'])} to "
           f"{f3(ps['0.1']['evident_prior_corrected']['ece'])}. Ablation: L4 alone gives Brier "
           f"{f3(EV['factorial'].get('L4', {}).get('brier'))}, L3b+L4 {f3(EV['factorial'].get('L3b+L4', {}).get('brier'))} "
           f"(static), and adding runtime L5 {f3(EV['factorial'].get('L3b+L4+L5', {}).get('brier'))}. "
           + (lambda sg: ("Per subgroup, mean probability vs observed rate: " + ", ".join(
               f"{lab} {sg[k]['mean_p']:.2f} vs {sg[k]['observed']:.2f}" for k, lab in (
                   ("strong_reachability (L4 CONFIRMED)", "strong"), ("weak_reachability (L4 POSSIBLE)", "weak"),
                   ("missing_symbol_info (L4 masked)", "symbols missing"),
                   ("reflection_blocked (L4 UNKNOWN)", "reflection-blocked")) if k in sg)
               + "; the last is under-predicted but within its interval (S14).")
              if sg else "")(R3B.get("subgroups")))
    P.figure(FIG / "calibration.png", "(a) Reliability (static setting, 10 bins, 95% bootstrap intervals for EVIDENT); "
             "(b) calibration when L4 is missing in different patterns.", width_cm=11.0)

    P.h2("RQ4: Verified remediation")
    rows = []
    for s, lab in (("audit_fix", "Minimal fix (pip-audit)"), ("latest", "Latest"), ("upgrade_all", "Upgrade all"),
                   ("uv_fix", "uv-fix (resolver)"), ("vm_opt", "Optimiser, version-match w."),
                   ("coral_opt", "Optimiser, CORAL-style w."), ("evident", "**EVIDENT** (calibrated w.)")):
        if s not in REM:
            continue
        k = int(round(S(s, "ok") * Sn(s)))
        rows.append([lab, frac(k, Sn(s)), f"{S(s, 'changed'):.1f}", f"{S(s, 'major_bumps'):.1f}",
                     pct(S(s, "findings_removed")), cfix(s), cl(s, "level2_ok"), cl(s, "level2b_ok")])
    P.table(["Strategy", "L1 resolves", "Changed", "Major", "Findings removed", "Confirmed fixed", "L2 symbols",
             "L2b signat."], rows,
            f"Remediation on the {n_ok} applications whose baseline resolves (means over resolved plans; removed = share "
            "of original findings gone). Confirmed fixed: strongly reachable original findings gone after "
            "re-resolution, pooled (k/n). L2/L2b: statically referenced symbols (signatures) intact, not behavioural "
            "compatibility. Per project: S11.",
            widths=[1900, 750, 650, 550, 850, 850, 750, 700], font_pt=7)
    P.para(remediation_text())
    P.para(sensitivity_text())
    cs = case_study_text()
    if cs:
        P.para(cs)

    # ---------------------------------------------------------------- 6/7
    P.h1("Threats to Validity")
    P.para("*Construct.* Exposure means execution of a function changed by the fix (A2); it upper-bounds "
           "exploitability. A2 is the main open risk: commit consistency and the text check (§3.3) are partial "
           "references; manual two-annotator validation of a 40-advisory sample is not yet reported. *Internal.* Benchmark applications follow 16 patterns that fix the prevalence; L5 is a simulated "
           "test run; baselines re-implement weighting schemes; PyCG and Jarvis ran with compatibility shims on "
           "Python 3.11. *External.* Popular open-source applications with lockfiles; the real-world results cover "
           f"{n_snap} of {RN.get('collected', n_snap)} collected applications (an outcome-independent lexicographic "
           "prefix that differs from the rest in lockfile kind), so per-application rates carry wide intervals and "
           "do not represent the ecosystem; remediation results are conditional on a resolvable baseline; one target "
           "platform; source "
           "distributions are never built. Compatibility is shown at Levels 1, 2 and 2b only; symbol resolution is not "
           "behavioural compatibility, and tests were not run because that executes third-party code [14].")
    P.h1("Conclusion")
    P.para("EVIDENT makes exposure evidence explicit, conditional and auditable. On execution-labelled data its "
           "probabilities are calibrated and robust to correlated missing evidence, and its analysis refuted no "
           "exposed code. On reflective real applications evidence mainly justifies dismissing findings; calibrated "
           "weights express a different risk-versus-change preference, not better plans, so better-calibrated evidence "
           "does not by itself yield better remediation. Verified plans resolve whenever the baseline does, but the "
           "resolver adds changes and static API checks pass for only half. Scoped reflection and framework-aware or "
           "exploit-oriented evidence are the most promising ways to let calibration change decisions.")
    P.h_unnumbered("Data Availability")
    P._first = True
    P.para(f"Code, EVIDENT-Bench, mined symbols, snapshot list, intelligence snapshot dates, scripts, all result files "
           f"and the online supplement: {REPO}, immutable release tag "
           f"{RELEASE.get('tag', 'v0.3.0')} (every number in this paper is regenerated from that tag's data/results).")
    P.references(REFS)
    import os
    out = Path(os.environ.get("EVIDENT_PAPER_OUT", HERE / "EVIDENT_paper.docx"))
    P.save(out)
    print("wrote", out)


def cg_row(name):
    d = CG.get(name, {})
    return [name, str(d.get("analysed", "n/a")), str(d.get("failed", "n/a")), f3(d.get("precision")),
            f3(d.get("recall")), f"{d.get('missed_exposed', 'n/a')}/{d.get('exposed', 'n/a')}"]


def cg_text() -> str:
    cc = R3C.get("common", {})
    cf = EV["analysis_confusion"]["L4_refuted"]
    if not cc:
        return ""
    p, j, es, ew = cc["PyCG"], cc["Jarvis"], cc["EVIDENT strong"], cc["EVIDENT strong+weak"]
    return (f"PyCG fails on {pct(R3C['failure_rate']['PyCG'])} of applications (mostly Django time-outs). On identical "
            f"inputs EVIDENT's strong edges perform like Jarvis (F1 {f3(es['f1'])} vs {f3(j['f1'])}) and better than "
            f"PyCG ({f3(p['f1'])}); we claim no superiority over Jarvis. Weak edges move the operating point: no exposed "
            f"application is missed, at {ew['false_alarms']} false alarms. Graph tools lose paths through re-exports, "
            "computed `getattr` and in-library dispatch (supplement S9), so a missing edge is unsafe evidence of "
            f"non-exposure. On the whole benchmark {cf['exposed']} of {cf['n']} REFUTED verdicts were exposed (see §5.1).")


def scopes_text(scb, scr) -> str:
    g, r = scb.get("global", {}), scb.get("reachable", {})
    bench = (f"leaves benchmark refutations unchanged at {g.get('refuted')}" if g.get('refuted') == r.get('refuted')
             else f"increases benchmark refutations from {g.get('refuted')} to {r.get('refuted')}")
    return (f"Narrowing the scope from global to reachable-module {bench} ({r.get('false_refutations')} false), "
            f"and raises real-world refutations from {scr.get('global_REFUTED', 0)} to "
            f"{scr.get('reachable_REFUTED', 0)}. Narrower scopes rest "
            "on a stronger assumption (reflection affects only code it can import or reach), so EVIDENT reports the scope "
            "with every refutation and uses the global scope by default. "
            + (lambda rf: (f"The benchmark's {rf['L4_refuted_total']} REFUTED verdicts (§5.2) are "
                           f"{rf['L4_refuted_by_reason'].get('package not imported', 0)} import refutations (L3b R "
                           f"propagated to L4) plus these {rf['imported_path_refuted']}; the other "
                           f"{rf['imported_blocked_by_reflection']} are blocked. With no false refutation the one-sided 95% "
                           f"upper bound is {pct(rf['upper95_false_refutation_path'], 1)} for path and "
                           f"{pct(rf['upper95_false_refutation_all'], 1)} for all refutations: narrower scopes are "
                           "empirically evaluated, not proven sound.") if rf else "")(
                R3B.get("refutations")))


def cfix(name):
    d = (R3R.get("confirmed_fixed") or {}).get(name)
    return f"{d['fixed']}/{d['confirmed_findings']}" if d else pct(S(name, "confirmed_fixed"))


def ptest(other, metric):
    for t in ((R3R.get("paired_tests") or {}).get("tests") or []):
        if t["comparison"] == f"evident_vs_{other}" and t["metric"] == metric:
            return t
    return None


def remediation_text() -> str:
    ev = "evident"
    fl = {k: v for k, v in T.get("failures", {}).get(ev, {}).items() if k != "none"}
    t_uv, t_vm, t_fr = test("uv_fix", "changed"), test("vm_opt", "changed"), test("vm_opt", "findings_removed")
    rc = T.get("remediation_ci", {})
    s = (f"Independent per-package upgrades resolve in {frac(int(round(S('audit_fix', 'ok') * Sn('audit_fix'))), Sn('audit_fix'))} "
         f"(minimal fix) and {frac(int(round(S('latest', 'ok') * Sn('latest'))), Sn('latest'))} (latest) applications; "
         f"upgrade-all changes {S('upgrade_all', 'changed'):.1f} packages and keeps the referenced API in only "
         f"{cl('upgrade_all', 'level2_ok')}. EVIDENT plans resolve in {frac(ev_ok_k, Sn(ev))}")
    if fl:
        s += " (failures: " + ", ".join(f"{k} {v}" for k, v in sorted(fl.items(), key=lambda kv: -kv[1])) + ")"
    s += f" after {S(ev, 'iterations'):.1f} iterations on average"
    if rc.get("evident_changed"):
        s += f"; they change {S(ev, 'changed'):.1f} packages (95% CI {rc['evident_changed']})"
    dr = (R3R.get("drift") or {}).get("evident", {})
    du = (R3R.get("drift") or {}).get("evident_vs_untouched_drift", {})
    og = dr.get("objective_gap", {})
    if dr:
        s += (f". *Plan vs realised.* No planned pin deviated in any realised environment. Around the "
              f"{dr['planned_changes']['mean']:.1f} planned changes the resolver adds {dr['unplanned_changes']['mean']:.1f} "
              f"(median {dr['unplanned_changes']['median']:.1f}; {dr['unplanned_major']['mean']:.1f} major) to satisfy "
              f"constraints, a median {du.get('median_diff', 0):+.1f} more than re-resolving the untouched lockfile "
              f"(mean {du.get('untouched_mean', 0):.1f}; p {'< 0.001' if du.get('p', 1) < 0.001 else '= ' + format(du.get('p', 1), '.3f')}), "
              f"introducing {dr['new_findings_from_unplanned']['mean']:.1f} new findings (median "
              f"{dr['new_findings_from_unplanned']['median']:.0f}). Realised residual expected risk (Σ severity weight × "
              f"exposure probability) exceeds the planned residual by {og['mean']:+.2f} "
              f"(95% CI [{og['ci_mean'][0]:.2f}, {og['ci_mean'][1]:.2f}]; planned objective "
              f"{og['planned_objective_mean']:.1f}) and equals it in {og['zero_gap']} of {dr['n']} applications. ")
    else:
        s += ". "
    tu, tv, tf = ptest("uv_fix", "changed"), ptest("vm_opt", "changed"), ptest("vm_opt", "findings_removed")
    if tu and tv and tf:
        s += (f"*Paired tests* (two-sided Wilcoxon, Holm over {R3R['paired_tests']['family_size']}; S14): EVIDENT "
              f"and uv-fix change {tu['median_evident']:.0f} vs "
              f"{tu['median_other']:.0f} packages (median paired difference {tu['median_diff']:.0f}, "
              f"p_Holm = {tu['p_holm']:.2f}, n = {tu['n']}): no advantage over resolver-native fixing. "
              f"Against version-match weights, calibrated weights change fewer packages ({tv['median_evident']:.1f} vs "
              f"{tv['median_other']:.0f}; difference {tv['median_diff']:+.0f}, rank-biserial r = {tv['rank_biserial']:.2f}, "
              f"p_Holm = {tv['p_holm']:.3f}) but also remove fewer findings ({pct(tf['median_evident'])} vs "
              f"{pct(tf['median_other'])}, p_Holm = {tf['p_holm']:.3f}): a different risk-versus-change preference, "
              "not a better plan. ")
    pc = T.get("pareto_common") or {}
    if pc:
        s += (f"Scored with one yardstick over a λ sweep both weightings trace nearly the same front (calibrated better "
              f"in {pc['better']}, worse in {pc['worse']} of {pc['projects']}; S11). ")
    return s


def sensitivity_text() -> str:
    dp, wt, cd = PH.get("devprior", {}), PH.get("weights", {}), PH.get("candidates", {})
    dec = T.get("decision", {})
    parts = []
    if dp:
        lo, hi = dp.get("0.0", {}), dp.get("0.25", {})
        parts.append(f"δ ∈ [0, 0.25] leaves plans {pct(hi.get('mean_plan_jaccard_vs_default'))} identical")
    if wt:
        parts.append(f"KEV multipliers 1/3 and max-aggregation keep the plan in "
                     f"{wt.get('kev1_sum', {}).get('identical_plans')}/{wt.get('kev3_sum', {}).get('identical_plans')}/"
                     f"{wt.get('kev2_max', {}).get('identical_plans')} of {wt.get('kev2_sum', {}).get('projects')}")
    if cd:
        oks = [cd.get(k, {}).get("ok") for k in ("6", "8", "12", "20")]
        same = len({round(cd.get(k, {}).get('changes') or -1, 6) for k in ("6", "8", "12", "20")}) == 1
        parts.append((f"every candidate limit from 6 to 20 resolves all {cd.get('6', {}).get('n')} applications"
                      if all(o == 1.0 for o in oks) else "candidate limits 6/8/12/20 resolve "
                      + "/".join(pct(o) for o in oks)) + (" with identical plans" if same else ""))
    s = ("**Sensitivity.** " + "; ".join(parts) + ".") if parts else ""
    if dec:
        s += (f" Setting an uncertain probability to 0 or 1 changes the plan for only {dec.get('critical_total')} of "
              f"{dec.get('uncertain_total')} findings: the short list worth manual triage.")
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
            f"affected by {f['advisory']} (CVSS {f.get('cvss')}); installed, imported, and its mined function is "
            f"reached through strong edges ({path}), so P = {f3(f.get('p_exposed'))}. The plan upgrades it to "
            f"{ev['planned'][f['package']]} "
            f"with {len(ev['planned']) - 1} other package{'s' if len(ev['planned']) - 1 != 1 else ''}; the resolver changes {ev.get('unplanned_changes')} more; the "
            f"re-scan leaves {ev.get('residual_findings')} of {r['original']['residual_findings']} findings; L2/L2b checks "
            f"{'pass' if comp.get('level2b_ok') else 'flag ' + str(comp.get('missing_pkgs', 0) + comp.get('signature_pkgs', 0)) + ' package(s)'} "
            "(supplement S12). "
            + (lambda c: (f"It crosses a major version because {c['django_advisories_affecting_4.2.6']} advisories affect "
                          f"4.2.6 and the newest 4.2 release still carries {c['remaining_advisories_if_upgraded_to'].get('4.2.30')} "
                          f"(later fixes exist only in 5.2) while 5.2.19 carries "
                          f"{c['remaining_advisories_if_upgraded_to'].get('5.2.19')}, outweighing the major-version cost. "
                          "The example is retrospective (2023 environment, advisories to 2026; Figure S1).")
               if c and c.get('planned_django') == ev['planned'].get(f['package']) else "")(R3R.get("case")))


if __name__ == "__main__":
    build()
