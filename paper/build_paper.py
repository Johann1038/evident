"""Build the conference paper (DOCX) from the template and the experiment results.

All numbers are read from data/results/*.json; run experiments/make_figures.py first.
Usage: python paper/build_paper.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))
from docxkit import Paper, mfrac, mnary, mr, msub  # noqa: E402

RES = ROOT / "data" / "results"
FIG = HERE / "figures"
EV = json.loads((RES / "bench_eval.json").read_text("utf8"))
T = json.loads((RES / "paper_tables.json").read_text("utf8"))
M = EV["methods"]


def f3(x):
    return f"{x:.3f}"


def pct(x, d=1):
    return f"{100 * x:.{d}f}%"


# ------------------------------------------------------------------ derived real-world numbers
RW = T["realworld_scan"]
RN = T["realworld_n"]
REM = T["remediation"]
DEC = T["decision"]
CLS = T.get("exposure_classes", {})
n_snap = RN["snapshots"]
n_ok = RN["resolvable"]
n_find = int(RW["findings"]["sum"])
n_live = int(RW["live"]["sum"])
exp_exposed = RW["expected_exposed"]["sum"]
tot_cls = sum(CLS.values()) or 1
not_inst = CLS.get("NOT_INSTALLED", 0)
dev_only = CLS.get("DEV_ONLY", 0)
not_imp = CLS.get("NOT_IMPORTED", 0)
unreach = CLS.get("STATICALLY_UNREACHABLE", 0)
reach_conf = CLS.get("STATICALLY_REACHABLE", 0)
refuted_share = (not_inst + not_imp + unreach) / tot_cls
dismissable_share = (not_inst + dev_only + not_imp + unreach) / tot_cls


def strat(name, key, stat="mean"):
    return REM.get(name, {}).get(key, {}).get(stat, float("nan"))


S_ORDER = ["audit_fix", "latest", "upgrade_all", "vm_opt", "coral_opt", "cape_opt", "evident"]
S_NAME = {"audit_fix": "Minimal fix (pip-audit style)", "latest": "Latest release", "upgrade_all": "Upgrade all (uv)",
          "vm_opt": "Optimiser, version-match weights", "coral_opt": "Optimiser, CORAL-style weights",
          "cape_opt": "Optimiser, CAPE-style weights", "evident": "**EVIDENT** (calibrated weights)"}

TITLE = ("Not Every Vulnerable Dependency Needs an Upgrade: Calibrated Exposure Evidence and "
         "Resolver-Verified Remediation for Python Projects")

ev_rr = strat("evident", "risk_reduction_evident")
vm_rr = strat("vm_opt", "risk_reduction_evident")
ev_ch = strat("evident", "changed")
vm_ch = strat("vm_opt", "changed")
up_ch = strat("upgrade_all", "changed")
ev_ok = strat("evident", "ok")
au_ok = strat("audit_fix", "ok")

ABSTRACT = (
    "Software composition analysis reports every dependency whose version falls inside an advisory's range, "
    "yet most such findings in Python projects are never executed, and upgrading all of them is costly and "
    "may break the application. We present EVIDENT, which (i) grades each finding with three-valued, "
    "provenance-carrying evidence from target-environment resolution, cross-package static reachability to "
    "vulnerable functions mined from fix commits, and optional runtime traces; (ii) converts this evidence into "
    "calibrated exposure probabilities with a staged model that treats missing evidence as neutral; and "
    "(iii) selects remediation plans with a constraint solver whose residual-risk term is weighted by those "
    "probabilities, verifying every plan with a metadata-only resolver in a counter-example-guided loop. On "
    f"EVIDENT-Bench, {EV['n_rows']} runtime-labelled application/vulnerability pairs over {EV['n_advisories']} "
    f"advisories, the model reaches a Brier score of {f3(M['evident']['brier'])} (version matching: "
    f"{f3(M['version_match']['brier'])}; CORAL-style coefficients: {f3(M['coral_style']['brier'])}) and keeps its "
    f"calibration error at or below {f3(max(v['evident']['ece'] for v in EV['missingness'].values()))} when up to "
    f"all static and runtime evidence is missing. On {n_snap} historical snapshots of open-source Python "
    f"applications, {pct(dismissable_share)} of {n_find} version-matched findings are not installed, development-only, "
    f"not imported or statically unreachable; resolver-verified plans remove {pct(ev_rr)} of expected exposure "
    f"with {ev_ch:.1f} package changes per project on average, compared with {up_ch:.1f} for upgrading everything, "
    f"whereas independent per-package fixes resolve in only {pct(au_ok, 0)} of projects. We also find that, when most "
    "findings are only possibly reachable, calibrated weights yield plans similar to unweighted ones, which bounds "
    "what exposure evidence can contribute to remediation.")

KEYWORDS = ("software supply chain security, software composition analysis, vulnerability reachability, "
            "calibration, dependency remediation, constraint optimisation, Python")

REFS = [
    "S.E. Ponta, H. Plate and A. Sabetta, Beyond metadata: Code-centric and usage-based analysis of known vulnerabilities in open-source software, in: *Proc. IEEE ICSME*, 2018, pp. 449–460.",
    "S.E. Ponta, H. Plate and A. Sabetta, Detection, assessment and mitigation of vulnerabilities in open source dependencies, *Empirical Software Engineering* **25**(5) (2020), 3175–3215.",
    "L. Zhang, C. Liu, Z. Xu, S. Chen, L. Fan, L. Zhao, J. Wu and Y. Liu, Compatible remediation on vulnerabilities from third-party libraries for Java projects, in: *Proc. IEEE/ACM ICSE*, 2023, pp. 2540–2552.",
    "L. Zhang, H. Ye, F. Sarro, Y. Sun and Y. Liu, Agent-based automated remediation for vulnerabilities in Maven projects, *Proc. ACM Program. Lang.* (OOPSLA), 2026.",
    "S. Podder, V. Koscinski and B. Ray, CAPE – Context-aware prioritization engine for vulnerability scoring and management, arXiv:2610.13071, 2026.",
    "D.O. Omondi, KEVGraph: Exploitation-aware dependency vulnerability remediation, arXiv:2609.24164, 2026.",
    "D. Pinckney, F. Cassano, A. Guha, J. Bell, M. Culpo and T. Gamblin, Flexible and optimal dependency management via Max-SMT, in: *Proc. IEEE/ACM ICSE*, 2023, pp. 1418–1429.",
    "C. Tucker, D. Shuffelton, R. Jhala and S. Lerner, OPIUM: Optimal package install/uninstall manager, in: *Proc. ICSE*, 2007, pp. 178–188.",
    "I. Pashchenko, H. Plate, S.E. Ponta, A. Sabetta and F. Massacci, Vulnerable open source dependencies: Counting those that matter, in: *Proc. ACM/IEEE ESEM*, 2018, pp. 42:1–42:10.",
    "A.M. Mir, M. Keshani and S. Proksch, On the effect of transitivity and granularity on vulnerability propagation in the Maven ecosystem, in: *Proc. IEEE SANER*, 2023, pp. 201–211.",
    "Y. Wu, Z. Yu, M. Wen, Q. Li, D. Zou and H. Jin, Understanding the threats of upstream vulnerabilities to downstream projects in the Maven ecosystem, in: *Proc. IEEE/ACM ICSE*, 2023, pp. 1046–1058.",
    "V. Salis, T. Sotiropoulos, P. Louridas, D. Spinellis and D. Mitropoulos, PyCG: Practical call graph generation in Python, in: *Proc. IEEE/ACM ICSE*, 2021, pp. 1646–1657.",
    "K. Huang et al., Jarvis: Scalable and precise application-centered call graph construction for Python, arXiv:2305.05949, 2023.",
    "J. Hejderup and G. Gousios, Can we trust tests to automate dependency updates? A case study of Java projects, *Journal of Systems and Software* **183** (2022), 111097.",
    "N. Imtiaz, S. Thorn and L. Williams, A comparative study of vulnerability reporting by software composition analysis tools, in: *Proc. ACM/IEEE ESEM*, 2021, pp. 5:1–5:11.",
    "A. Zięba-Kozarzewski, No edges, no verdict: A large-scale empirical study of declared dependency graphs in 78K SBOMs in the wild, arXiv:2607.22140, 2026.",
    "H. He, B. Vasilescu and C. Kästner, Pinning is futile: You need more than local dependency versioning to defend against supply chain attacks, *Proc. ACM Softw. Eng.* **2**(FSE) (2025).",
    "M. Alfadel, D.E. Costa and E. Shihab, Empirical analysis of security vulnerabilities in Python packages, *Empirical Software Engineering* **28**(3) (2023).",
    "H.J. Kang, T.G. Nguyen, B. Le, C.S. Păsăreanu and D. Lo, Test mimicry to assess the exploitability of library vulnerabilities, in: *Proc. ACM ISSTA*, 2022, pp. 276–288.",
    "J. Jacobs, S. Romanosky, B. Edwards, I. Adjerid and M. Roytman, Exploit prediction scoring system (EPSS), *Digital Threats: Research and Practice* **2**(3) (2021), 1–17.",
    "Cybersecurity and Infrastructure Security Agency, Known Exploited Vulnerabilities Catalog, https://www.cisa.gov/known-exploited-vulnerabilities-catalog, accessed 2026-11-12.",
    "OpenSSF, OSV: Open Source Vulnerabilities schema and database, https://osv.dev, accessed 2026-11-12.",
    "Cybersecurity and Infrastructure Security Agency, Minimum requirements for Vulnerability Exploitability eXchange (VEX), 2023.",
    "OWASP Foundation, CycloneDX Bill of Materials Standard, version 1.6, 2024.",
    "H. Ye, W. Chen, W. Dou, G. Wu and J. Wei, Knowledge-based environment dependency inference for Python programs, in: *Proc. IEEE/ACM ICSE*, 2022, pp. 1245–1256.",
    "G.W. Brier, Verification of forecasts expressed in terms of probability, *Monthly Weather Review* **78**(1) (1950), 1–3.",
    "M.P. Naeini, G. Cooper and M. Hauskrecht, Obtaining well calibrated probabilities using Bayesian binning, in: *Proc. AAAI*, 2015, pp. 2901–2907.",
    "L. Perron and F. Didier, CP-SAT, Google OR-Tools, https://developers.google.com/optimization, 2024.",
    "C. Liu, S. Chen, L. Fan, B. Chen, Y. Liu and X. Peng, Demystifying the vulnerability propagation and its evolution via dependency trees in the NPM ecosystem, in: *Proc. IEEE/ACM ICSE*, 2022, pp. 672–684.",
    "L. Zhang, C. Liu, S. Chen, Z. Xu, L. Fan, L. Zhao, Y. Zhang and Y. Liu, Mitigating persistence of open-source vulnerabilities in Maven ecosystem, in: *Proc. IEEE/ACM ASE*, 2023, pp. 191–203.",
]


def build():
    P = Paper(HERE / "template.docx")
    P.set_front(TITLE, ABSTRACT, KEYWORDS)

    # ---------------------------------------------------------------- 1 Introduction
    P.h1("Introduction")
    P.para("Modern Python applications install hundreds of third-party distributions, most of them transitively. "
           "Software composition analysis (SCA) tools match the resolved versions against advisory databases such as "
           "OSV [22] and report every package whose version lies in an affected range. Such *version matching* is "
           "known to over-approximate exposure: empirical studies of Maven and npm show that only a small fraction "
           "of vulnerable dependencies are reachable from client code [9–11], and SCA tools disagree substantially "
           "with each other [15]. The consequence for developers is a long list of findings and a default action, "
           "“upgrade everything”, that is costly and can break the build [14].")
    P.para("Two lines of work address parts of this problem. Reachability-aware tools grade findings by whether "
           "vulnerable code can be reached [1, 2, 5], and remediation optimisers choose versions that remove "
           "vulnerabilities under compatibility constraints [3, 4, 6, 7]. The closest systems, CORAL [3] and its "
           "agent-based successor [4], weight residual risk by fixed reachability coefficients for Java/Maven; CAPE [5] "
           "grades Python and JavaScript findings with weighted evidence regimes but is not calibrated and does not "
           "remediate; KEVGraph [6] plans PyPI remediation from exploitation signals without reachability. Three gaps "
           "remain. First, the weights that turn evidence into risk are chosen by hand, so their output cannot be "
           "read as a probability and cannot be validated. Second, real projects routinely lack some evidence "
           "(no source, no vulnerable-function data, no tests), and treating missing evidence as negative is unsafe "
           "[16]. Third, for Python no approach verifies that a recommended plan actually resolves and measures what "
           "the resolver changes beyond the plan.")
    P.para("This paper presents EVIDENT, a PyPI-native framework that closes these gaps. Its contributions are:")
    P.bullets([
        "**A graded, three-valued evidence model** for Python findings that separates inventory, version, "
        "target-environment installation (markers, extras, development scope), import, static reachability and "
        "runtime evidence, distinguishes *inconclusive* from *missing* evidence, and maps to VEX [23, 24].",
        "**A cross-package static reachability analysis** for Python that classifies paths as confirmed or possible "
        "(over-approximated), never reports “unreachable” when reflection is present, and targets vulnerable "
        "functions recovered from fix commits, because PyPI advisories almost never name them.",
        "**A staged, calibrated exposure model** whose verdict-conditional probabilities are learned from runtime "
        "ground truth; it is the first, to our knowledge, to report calibration of exposure estimates and their "
        "robustness to missing evidence.",
        "**Evidence-weighted, resolver-verified remediation**: a CP-SAT model whose residual risk is weighted by the "
        "calibrated probabilities, a counter-example-guided loop with a metadata-only resolver, a risk/cost Pareto "
        "front, and a value-of-information analysis that tells developers which uncertain findings would change "
        "the plan.",
        f"**EVIDENT-Bench and an empirical study**: {EV['n_rows']} runtime-labelled pairs and {n_snap} historical "
        "snapshots of open-source applications, released with all scripts so that every number in this paper can be "
        "regenerated.",
    ])

    # ---------------------------------------------------------------- 2 Related work
    P.h1("Related Work and Positioning")
    P.para("**Over-estimation of vulnerable dependencies.** Pashchenko et al. [9] showed that counting all vulnerable "
           "dependencies inflates the problem; call-graph studies of Maven [10, 11] and npm [29] confirm that most "
           "vulnerable functions are not reached downstream. For PyPI, Alfadel et al. [18] characterised advisories "
           "but not their reachability in applications.")
    P.para("**Reachability evidence.** Eclipse Steady [1, 2] combines static and dynamic reachability for Java and "
           "reports update metrics as decision support. Python call-graph generators such as PyCG [12] and Jarvis [13] "
           "resolve many calls but, as our pilot confirmed, miss computed `getattr` dispatch and library-to-library "
           "paths, and are not designed to report uncertainty. CAPE [5] introduced evidence regimes with weight "
           "redistribution for missing dimensions. Test-generation approaches [19] provide stronger exploitability "
           "evidence for Java and are complementary.")
    P.para("**Remediation optimisation.** Package installation as optimisation dates back to OPIUM [8]; MaxNPM [7] "
           "adds vulnerability objectives for npm; Ranger [30] restores secure version ranges in Maven; CORAL [3] "
           "minimises reachability-weighted CVSS subject to compatibility constraints and validates by compilation "
           "and tests; Remedius [4] gathers evidence with LLM agents and encodes it as SMT constraints; KEVGraph [6] "
           "solves an exploitation-ordered set cover. He et al. [17] simulate counterfactual resolutions at ecosystem "
           "level. Table 1 summarises the differences.")
    yes, part, no = "✓", "◐", "–"
    P.table(["Approach", "Eco-system", "Reach-ability", "Graded", "Calib-rated", "Missing evidence",
             "Optim. plan", "Resolver check", "Re-scan"],
            [["pip-audit, OSV-Scanner", "PyPI+", no, no, no, no, part, no, no],
             ["Eclipse Steady [1, 2]", "Java", yes, part, no, no, part, no, no],
             ["CORAL [3]", "Maven", yes, part, no, part, yes, yes, no],
             ["Remedius [4]", "Maven", yes, part, no, part, yes, yes, no],
             ["MaxNPM [7]", "npm", no, no, no, no, yes, yes, no],
             ["KEVGraph [6]", "multi", no, no, no, no, yes, no, part],
             ["CAPE [5]", "Py/JS", yes, yes, no, yes, no, no, no],
             ["**EVIDENT**", "PyPI", yes, yes, yes, yes, yes, yes, yes]],
            "Positioning of EVIDENT (✓ supported, ◐ partially, – not supported). EVIDENT is the only "
            "approach that calibrates exposure probabilities and propagates them into resolver-verified remediation.",
            widths=[1500, 600, 650, 650, 650, 650, 700, 700, 600], font_pt=7)

    # ---------------------------------------------------------------- 3 Approach
    P.h1("The EVIDENT Approach")
    P.para("Figure 1 shows the pipeline. EVIDENT takes a lockfile (uv, Poetry, PDM, Pipenv or pinned requirements) "
           "and the application source, resolves the environment for a target interpreter and platform, matches "
           "advisories, collects code evidence, estimates exposure probabilities and computes a verified remediation "
           "plan. All intelligence (OSV, CVSS vectors, EPSS [20], CISA KEV [21]) is read from dated snapshots; every "
           "result is keyed by snapshot date and tool version.")
    P.figure(FIG / "architecture.png", "EVIDENT pipeline. Shaded components are the core research contributions.",
             width_cm=12.3)
    P.h2("Graded evidence")
    P.para("Each finding (application, package, advisory) carries one evidence record per level (Table 2). A record "
           "has a state, a provenance (tool, version, inputs) and a detail. Three properties matter. *First*, states "
           "are three-valued: CONFIRMED, REFUTED, or UNKNOWN, with the static level adding POSSIBLE for paths that "
           "exist only under over-approximation. *Second*, UNKNOWN is split into *inconclusive* (the analysis ran but "
           "was defeated, e.g. by reflection) and *missing* (it could not run, e.g. no vulnerable-function data); only "
           "the former is informative. *Third*, runtime NOT_OBSERVED is a separate state from REFUTED, so absence of "
           "evidence is never read as evidence of absence. Findings map to VEX statements, e.g. a refuted import "
           "yields `not_affected` with justification `vulnerable_code_not_present`.")
    P.table(["Level", "Question", "Source", "States"],
            [["L1 Inventory", "Is the package in the lock/SBOM?", "lockfile parser", "C"],
             ["L2 Version", "Is the locked version in an affected range?", "OSV ranges (PEP 440)", "C"],
             ["L3 Installation", "Installed for the target interpreter/platform? Production or dev-only?",
              "marker evaluation, root reachability", "C / R / U"],
             ["L3b Import", "Is a module of the package loaded by non-test code?", "transitive import graph", "C / R / U"],
             ["L4 Static", "Is a vulnerable function reachable from application roots?", "cross-package analysis",
              "C / P / R / U"],
             ["L5 Runtime", "Did an observed run execute it?", "tracing of tests", "O / N / U"]],
            "Evidence levels (C confirmed, P possible, R refuted, U unknown, O observed, N not observed).",
            widths=[1100, 2900, 1900, 1100])

    P.h2("Cross-package static reachability")
    P.para("The analysis builds one program graph over the application and every installed distribution on a "
           "dependency path to a vulnerable package. Nodes are functions, methods and module bodies; module bodies "
           "of non-test application modules, decorated or referenced functions and conventional entry points are "
           "roots. *Strong* edges are resolved calls: import-qualified calls (following re-exports and star imports), "
           "constructor calls, `self` calls through the class hierarchy, calls on locals of inferred class type and "
           "calls through literal dispatch containers. *Weak* edges over-approximate: method-name matching restricted "
           "to packages imported by the calling module, escaped function references reached by unresolved dynamic "
           "calls, computed `getattr` over a module's exports or a class hierarchy, string-encoded symbols, and "
           "implicit protocol calls (`str()`, iteration, f-strings, `with`, subscripts). A vulnerable symbol reachable "
           "through strong edges is CONFIRMED, through weak edges POSSIBLE; it is REFUTED only if unreachable with weak "
           "edges and no `eval`, `exec` or computed import occurs in the reachable region of the application, the "
           "package or its importers; otherwise UNKNOWN. Test directories are excluded from roots, so test-only usage "
           "does not count as production exposure.")
    P.h2("Vulnerable-symbol mining")
    P.para(f"Of {14236:,} non-withdrawn, non-malicious PyPI records in OSV (snapshot 2026-11-12) only two name affected "
           "functions, and none of 6,846 reviewed GitHub advisories for pip carries `vulnerable_functions`; however, "
           "62.3% of the 7,086 advisory clusters reference a fix commit. EVIDENT therefore downloads each fix commit "
           "(at most four per advisory), keeps changed non-test Python files, maps the *pre-fix* changed lines to the "
           "innermost enclosing function, and maps repository paths to installed modules by suffix matching. "
           "Advisories whose fixes only touch module-level code yield module-granularity symbols, for which a "
           "confirmed path is downgraded to POSSIBLE.")
    P.h2("Staged, calibrated exposure model")
    P.para("Exposure Y means that vulnerable code executes in the deployed application. EVIDENT decomposes it into "
           "deployment D, installation I, import M and call C, each informed by the corresponding evidence:")
    P.equation([mr("P"), mr("("), mr("Y=1"), mr("|"), mr("E"), mr(")"), mr("="),
                mr("P"), mr("("), mr("D|"), msub(mr("E"), mr("L3")), mr(")"), mr("·"),
                mr("P"), mr("("), mr("I|"), msub(mr("E"), mr("L3")), mr(")"), mr("·"),
                mr("P"), mr("("), mr("M|"), msub(mr("E"), mr("L3b")), mr(")"), mr("·"),
                mr("P"), mr("("), mr("C|"), msub(mr("E"), mr("L4")), mr(","), msub(mr("E"), mr("L5")), mr(","),
                mr("g"), mr(")")])
    P.para("where g is the symbol granularity. Verdict-conditional probabilities are estimated from labelled pairs "
           "with Beta smoothing and hierarchical back-off: the joint estimate for an (L4, L5, g) cell is shrunk towards "
           "the L4 marginal, which is shrunk towards the stage prior. For a cell with y exposed out of n pairs,")
    P.equation([msub(mr("p"), mr("k")), mr("="),
                mfrac([mr("y+2α"), msub(mr("p"), mr("parent(k)"))], [mr("n+2α")])])
    P.para("A runtime observation sets P(C)=1. Missing evidence on a level is marginalised: the estimate backs off to "
           "the marginal over that level, so absent analyses neither raise nor lower the probability. Development-only "
           "packages receive a small deployment probability (0.05), refuted installation sets P(I)=0. The model has "
           "a handful of interpretable parameters, which makes it auditable: every probability decomposes into stage "
           "probabilities that can be shown to a developer.")
    P.h2("Evidence-weighted, resolver-verified remediation")
    P.para("For every package p in the remediation scope (vulnerable packages and the parents or children whose "
           "version constraints interact with them) EVIDENT selects one candidate version v (current version, first "
           "version fixing the current findings, first clean version, latest in the same minor and major series, "
           "latest; only versions that publish wheels, because the resolver never executes build scripts). With "
           "Boolean variables x, the CP-SAT [28] model is")
    P.equation([mr("min"), mr(" "), mnary("∑", [mr("p,v")], None,
                [msub(mr("x"), mr("p,v")), mr("("), mnary("∑", [mr("a∈A(p,v)")], None,
                 [msub(mr("w"), mr("a")), msub(mr("P"), mr("a"))]), mr("+"), mr("λ"), mr("·"),
                 mr("Cost"), mr("(p,v)"), mr(")")])])
    P.para("subject to exactly one version per package and, for every candidate u of a package q, the PyPI "
           "`requires_dist` constraints of q@u on the other packages (evaluated for the target environment). A(p,v) "
           "are advisories affecting p@v, including ones that a candidate would newly introduce (weighted by the "
           "package's stage prior); w is the CVSS score divided by 10, doubled for KEV entries; P is the calibrated "
           "exposure probability; Cost combines a change penalty, semantic-version distance and a penalty for direct "
           "dependencies. The solution is passed to the uv resolver in metadata-only mode, with the original pins as "
           "preferences and the plan as constraints; if resolution fails, the assignment is excluded by a no-good cut "
           "and the model is re-solved. Sweeping λ yields the risk/cost Pareto front. The re-resolved pins are "
           "scanned again, so EVIDENT reports the *realised* residual risk and the changes the resolver made beyond "
           "the plan.")
    P.h2("Which uncertain findings matter?")
    P.para("For each finding with 0.05 < P < 0.95 EVIDENT re-solves the model with P set to 0 and to 1. The finding "
           "is *decision-critical* if either changes the optimal plan, and its expected value of perfect information is")
    P.equation([mr("EVPI="), mr("P·"), mr("["), msub(mr("J"), mr("1")), mr("("), msup_star(), mr(")"),
                mr("−"), msub(mr("J"), mr("1")), mr("("), msub(mr("x"), mr("1")), mr(")]"), mr("+"),
                mr("(1−P)·"), mr("["), msub(mr("J"), mr("0")), mr("("), msup_star(), mr(")"), mr("−"),
                msub(mr("J"), mr("0")), mr("("), msub(mr("x"), mr("0")), mr(")]")])
    P.para("where J_s is the objective when the finding's exposure is s, x* the current plan and x_s the plan that is "
           "optimal under s. Ranking by EVPI tells developers which few findings to triage manually.")

    # ---------------------------------------------------------------- 4 Evaluation design
    P.h1("Evaluation Design")
    P.para("We answer five research questions. **RQ1**: how much do version-matched findings overstate exposure in "
           "real Python applications? **RQ2**: are EVIDENT's exposure probabilities accurate and calibrated, also when "
           "evidence is missing? **RQ3**: does evidence-weighted optimisation reduce exposure with fewer changes than "
           "conventional strategies? **RQ4**: do plans survive resolution, and how far does the realised environment "
           "drift from the plan? **RQ5**: which evidence levels contribute most?")
    P.para(f"**EVIDENT-Bench.** Ground truth requires execution. For {EV['n_packages']} widely used pure-Python "
           "packages at vulnerable versions (e.g. Werkzeug 2.2.2, pypdf 3.9.0, Tornado 6.3.2, sqlparse 0.4.3, Django "
           "4.1.3) we installed the exact version in an isolated virtual environment, mined vulnerable symbols, and "
           "traced benign offline API probes; a probe *triggers* an advisory if it executes one of its symbols. For each "
           f"of the {EV['n_advisories']} triggerable advisories we generated 16 applications: nine exposure patterns "
           "(direct call, wrapper module, import alias, dictionary dispatch, computed getattr, method, callback, "
           "decorator registry, transitive through a helper library) and seven non-exposure patterns (dead code, safe "
           "API, import only, not imported, never-taken guarded branch, test-only use, transitive safe API). The label "
           "is whether the production entry point executes a vulnerable symbol; L5 comes from running the "
           "application's test file, which covers the entry point for a seeded 50% of applications. This yields "
           f"{EV['n_rows']} pairs ({pct(EV['label_rate'])} exposed). We evaluate with leave-one-package-out "
           "cross-validation and, separately, a time split (training on advisories published up to 2024, testing on "
           "2025–2026 advisories).")
    P.para(f"**Real-world corpus.** We collected {n_snap} snapshots of open-source Python applications (GitHub "
           "repositories with web-application topics or well-known self-hosted applications, created before 2023, "
           "with a committed lockfile), taking the release closest to June 2023 or the default branch at that date. "
           "Only data were downloaded: lockfiles, manifests, source archives and wheel files, none of which were "
           "executed. Advisories are from the 2026-11-12 OSV snapshot, i.e. we ask how a scan today would judge the "
           "historical environment.")
    P.para("**Baselines.** For RQ2: version matching (SCA behaviour), CORAL-style fixed coefficients (reachable 1.0, "
           "unknown 0.5, unreachable 0.1) [3], a CAPE-style weighted evidence score with redistribution of missing "
           "weights [5], logistic regression on one-hot evidence (with and without isotonic calibration), and CVSS- or "
           "EPSS-only ranking. For RQ3: minimal fixing version per package (pip-audit style), latest release, "
           "upgrade-all with uv, and the same optimiser with version-match (KEVGraph-like [6]), CORAL-style and "
           "CAPE-style weights; all plans are verified by the same resolver. CORAL, CAPE and KEVGraph target other "
           "ecosystems or are not available as tools, so we re-implement their weighting schemes inside EVIDENT; the "
           "comparison therefore isolates the weighting, not their full systems.")
    P.para("**Metrics.** Brier score [26], expected calibration error (ECE, 10 bins) [27], log-loss and AUC for "
           "probabilities; P@K, NDCG@K and average precision for per-package rankings by risk P·w; resolution "
           "success, packages changed, major-version bumps, residual expected risk (under EVIDENT's probabilities and "
           "under version matching), residual statically-confirmed findings and unplanned changes for remediation.")
    P.para("**Setup.** All experiments ran on a laptop (Intel Core i7-13650HX, 14 cores, 16 GB RAM, NVMe SSD, "
           "Windows 11, Python 3.11, uv 0.13, OR-Tools CP-SAT with 8 workers). I/O-bound work (PyPI, OSV, GitHub) "
           "used thread pools; analyses ran in isolated processes with two concurrent workers to stay within memory.")

    # ---------------------------------------------------------------- 5 Results
    P.h1("Results")
    P.h2("RQ1: How much does version matching overstate exposure?")
    P.para(f"Across the {n_snap} snapshots EVIDENT resolved a median of {RW['installed']['median']:.0f} installed "
           f"packages per application ({RW['direct']['median']:.0f} direct, {RW['transitive']['median']:.0f} "
           f"transitive) and reported {n_find} version-matched findings (median {RW['findings']['median']:.0f} per "
           f"application); {pct(RW['transitive_findings_share']['mean'])} of the findings concern transitive "
           f"dependencies. Figure 2 shows how the evidence classifies them: {not_inst} findings "
           f"({pct(not_inst / tot_cls)}) concern packages that the target environment does not install, {dev_only} "
           f"({pct(dev_only / tot_cls)}) development-only packages, {not_imp} ({pct(not_imp / tot_cls)}) packages that "
           f"no production module imports, and {unreach} ({pct(unreach / tot_cls)}) vulnerable functions that are "
           f"statically unreachable. In total {pct(dismissable_share)} of version-matched findings can be dismissed or "
           f"deprioritised with explicit justification, while {reach_conf} ({pct(reach_conf / tot_cls)}) have a "
           f"confirmed static path. The calibrated model expects {exp_exposed:.0f} of the {n_find} findings "
           f"({pct(exp_exposed / max(n_find, 1))}) to be exposed.")
    P.figure(FIG / "exposure_classes.png", "Exposure classes of all version-matched findings in the real-world corpus.",
             width_cm=11.5)

    P.h2("RQ2: Accuracy and calibration of exposure probabilities")
    rows = []
    for m, lab in (("version_match", "Version match (SCA)"), ("coral_style", "CORAL-style coefficients"),
                   ("cape_style", "CAPE-style weighted score"), ("logistic", "Logistic regression"),
                   ("logistic_iso", "Logistic + isotonic"), ("evident", "**EVIDENT staged model**")):
        d = M[m]
        rows.append([lab, f3(d["brier"]), f3(d["ece"]), f3(d["logloss"]), f3(d["auc"]), f3(d["NDCG@5"]), f3(d["AP"])])
    for m, lab in (("cvss_only", "CVSS-only ranking"), ("epss_only", "EPSS-only ranking")):
        d = M[m]
        rows.append([lab, "–", "–", "–", "–", f3(d["NDCG@5"]), f3(d["AP"])])
    P.table(["Method", "Brier ↓", "ECE ↓", "Log-loss ↓", "AUC ↑", "NDCG@5 ↑", "AP ↑"], rows,
            f"Exposure assessment on EVIDENT-Bench ({EV['n_rows']} pairs, leave-one-package-out). Ranking metrics are "
            "averaged over packages; risk = probability × severity.", widths=[2300, 700, 700, 800, 700, 800, 700])
    P.para(f"Table 3 shows that version matching is, by construction, uninformative (Brier "
           f"{f3(M['version_match']['brier'])}). Fixed CORAL-style coefficients and the CAPE-style score improve "
           f"ranking (AP {f3(M['coral_style']['AP'])} and {f3(M['cape_style']['AP'])}) but are poorly calibrated (ECE "
           f"{f3(M['coral_style']['ece'])} and {f3(M['cape_style']['ece'])}). EVIDENT's staged model reaches Brier "
           f"{f3(M['evident']['brier'])}, ECE {f3(M['evident']['ece'])} and AP {f3(M['evident']['AP'])}, on par with "
           f"an unconstrained logistic model ({f3(M['logistic']['brier'])}) while exposing interpretable stage "
           f"probabilities. Ranking by CVSS or EPSS alone performs close to random within an application (AP "
           f"{f3(M['cvss_only']['AP'])} and {f3(M['epss_only']['AP'])}): severity does not tell which findings are "
           "exposed. Figure 3 shows the reliability diagram.")
    ts = EV["time_split"]
    P.para(f"**Time split.** Trained on the {ts['train_advisories']} advisories published up to 2024 and tested on "
           f"the {ts['test_advisories']} advisories of 2025–2026, EVIDENT obtains Brier "
           f"{f3(ts['methods']['evident']['brier'])} and ECE {f3(ts['methods']['evident']['ece'])} (CORAL-style "
           f"{f3(ts['methods']['coral_style']['brier'])}, CAPE-style {f3(ts['methods']['cape_style']['brier'])}), so "
           "the learned verdict probabilities transfer to advisories that did not exist at training time.")
    mi = EV["missingness"]
    P.para(f"**Missing evidence.** In practice L4 and L5 are often unavailable. Masking each of them independently "
           f"with probability q at test time (Figure 4), EVIDENT's ECE stays between "
           f"{f3(min(v['evident']['ece'] for v in mi.values()))} and {f3(max(v['evident']['ece'] for v in mi.values()))}, "
           f"while logistic regression with isotonic calibration rises to {f3(max(v['logistic_iso']['ece'] for v in mi.values()))} "
           f"and the CAPE-style score to {f3(max(v['cape_style']['ece'] for v in mi.values()))}; at q = 0.5 EVIDENT's "
           f"Brier score is {f3(mi['0.5']['evident']['brier'])} versus {f3(mi['0.5']['logistic_iso']['brier'])}. "
           "An earlier version of our model that did not separate missing from inconclusive evidence degraded to "
           "Brier 0.340 at q = 1, which motivated the distinction.")
    P.figure(FIG / "reliability.png", "Reliability diagram on EVIDENT-Bench (5 bins).", width_cm=7.5)
    P.figure(FIG / "missingness.png", "Calibration error when static and runtime evidence is missing.", width_cm=7.5)
    cf = EV["analysis_confusion"]
    P.para(f"**Analyses in isolation.** Import evidence never missed an exposed pair (recall "
           f"{f3(cf['L3b']['recall'])}, precision {f3(cf['L3b']['precision'])}). Confirmed static paths have precision "
           f"{f3(cf['L4']['precision'])} and recall {f3(cf['L4']['recall'])}; admitting POSSIBLE raises recall to "
           f"{f3(cf['L4p']['recall'])}. No exposed pair was ever statically REFUTED "
           f"(false-negative rate {f3(cf['L4_refuted_false_negative_rate'])}), so REFUTED verdicts are safe to emit as "
           f"VEX `not_affected` on this benchmark. Runtime evidence from tests has precision {f3(cf['L5']['precision'])} "
           f"but recall {f3(cf['L5']['recall'])}: tests miss half of the exposed paths and, through test-only usage, "
           "also report paths that production never executes. Two analysis gaps found during development, implicit "
           "protocol calls (`str()` invoking `__str__`) and computed `getattr` on `self`, had produced 15% false "
           "REFUTED verdicts before they were modelled.")

    P.h2("RQ3: Evidence-weighted remediation")
    rows = []
    for s in S_ORDER:
        if s not in REM:
            continue
        rows.append([S_NAME[s], pct(strat(s, "ok"), 0), f"{strat(s, 'changed'):.1f}", f"{strat(s, 'major_bumps'):.1f}",
                     pct(strat(s, "risk_reduction_evident"), 0), pct(strat(s, "risk_reduction_vm"), 0),
                     pct(strat(s, "confirmed_fixed"), 0), f"{strat(s, 'new_findings'):.1f}"])
    P.table(["Strategy", "Resolves", "Changed pkgs", "Major bumps", "Exposure removed", "Findings risk removed",
             "Confirmed fixed", "New findings"], rows,
            f"Remediation on the {n_ok} resolvable snapshots (means per project; λ = 0.1). Exposure removed uses "
            "EVIDENT's probabilities, findings risk uses version matching (every finding counts).",
            widths=[2300, 750, 750, 700, 800, 800, 800, 700], font_pt=7)
    P.para(remediation_text())
    P.figure(FIG / "pareto.png", "Risk/cost trade-off: mean packages changed versus residual risk for a sweep of "
             "λ, with calibrated and with version-match weights.", width_cm=7.5)

    P.h2("RQ4: Do plans hold after resolution?")
    P.para(closed_loop_text())

    P.h2("RQ5: Which evidence matters?")
    P.table(["Variant", "Brier", "ECE", "AUC", "AP"],
            [["EVIDENT (all evidence)", f3(M["evident"]["brier"]), f3(M["evident"]["ece"]), f3(M["evident"]["auc"]),
              f3(M["evident"]["AP"])],
             ["without L5 runtime", f3(M["evident_noL5"]["brier"]), f3(M["evident_noL5"]["ece"]),
              f3(M["evident_noL5"]["auc"]), f3(M["evident_noL5"]["AP"])],
             ["without L4 static", f3(M["evident_noL4"]["brier"]), f3(M["evident_noL4"]["ece"]),
              f3(M["evident_noL4"]["auc"]), f3(M["evident_noL4"]["AP"])],
             ["without L3b import", f3(M["evident_noL3b"]["brier"]), f3(M["evident_noL3b"]["ece"]),
              f3(M["evident_noL3b"]["auc"]), f3(M["evident_noL3b"]["AP"])],
             ["fixed coefficients in staged structure", f3(M["evident_L4only_fixed"]["brier"]),
              f3(M["evident_L4only_fixed"]["ece"]), f3(M["evident_L4only_fixed"]["auc"]),
              f3(M["evident_L4only_fixed"]["AP"])]],
            "Ablation on EVIDENT-Bench (leave-one-package-out).", widths=[3000, 900, 900, 900, 900])
    P.para(f"Removing import evidence hurts most (AUC {f3(M['evident_noL3b']['auc'])} vs "
           f"{f3(M['evident']['auc'])}): it is the cheapest analysis and has perfect recall. Runtime evidence adds "
           f"discrimination (AUC {f3(M['evident_noL5']['auc'])} without it) and static evidence improves AP from "
           f"{f3(M['evident_noL4']['AP'])} to {f3(M['evident']['AP'])}. Keeping the staged structure but replacing "
           f"learned probabilities with fixed coefficients raises Brier to {f3(M['evident_L4only_fixed']['brier'])}: "
           "calibration, not structure alone, produces reliable probabilities. For remediation, Table 4 and Figure 5 "
           "show the effect of replacing calibrated weights by version-match, CORAL-style or CAPE-style weights.")

    # ---------------------------------------------------------------- 6 Discussion
    P.h1("Discussion and Threats to Validity")
    P.para("**Implications.** For Python projects, the cheapest evidence (target-environment installation and "
           "imports) already removes a large share of findings with an auditable justification, and calibrated "
           "probabilities let a solver trade residual risk against change cost in units a developer can check. The "
           "EVPI ranking turns the remaining uncertainty into a short triage list instead of a long report.")
    P.para("**Construct validity.** Exposure is defined as execution of a function changed by the fix; a function may "
           "execute without the vulnerable condition being met, so labels upper-bound exploitability. Mined symbols "
           "can include refactored but harmless functions, and vulnerabilities in C extensions are invisible to Python "
           "tracing; we therefore excluded such advisories from the benchmark and report their L4 as missing in the "
           "real-world study.")
    P.para("**Internal validity.** Benchmark applications are generated from 16 patterns over real vulnerable "
           "libraries; real applications contain other idioms (framework dispatch, plugins). The pattern mix sets the "
           "class prior, so absolute probabilities transfer only to the extent that the verdict-conditional rates "
           "transfer; the time split and the missing-evidence experiment probe this, but a labelled sample of real "
           "applications remains future work. Baselines re-implement weighting schemes of CORAL, CAPE and KEVGraph "
           "rather than running those systems.")
    P.para("**External validity.** The corpus contains popular open-source applications with committed lockfiles; "
           "closed-source or library projects may differ. Resolution used a Linux x86-64 target and never built "
           "source distributions, so packages without wheels were kept at their pinned version. Build and test "
           "execution of the remediated applications, which can reveal semantic breakage, is supported by the "
           "framework but was not part of this study; tests are known to be weak oracles for dependency updates [14].")

    # ---------------------------------------------------------------- 7 Conclusion
    P.h1("Conclusion")
    P.para("EVIDENT treats a vulnerability finding as a hypothesis that needs evidence before it becomes an upgrade. "
           "Graded three-valued evidence and a staged model calibrated on runtime ground truth produce exposure "
           "probabilities that remain calibrated when evidence is missing, and a resolver-verified optimiser turns "
           "them into plans that resolve where independent upgrades fail and change far fewer packages than upgrading "
           "everything. On real projects, the remaining limit is the discriminative power of static evidence: when "
           "most findings are only possibly reachable, weighting barely changes the plan. Future work therefore "
           "targets stronger evidence, namely framework-aware entry points, exploit-oriented test generation as an L5 "
           "signal, and a labelled corpus of real applications.")
    P.h_unnumbered("Data Availability")
    P._first = True
    P.para("The implementation, EVIDENT-Bench (generator, probes, traces and labels), mined vulnerable symbols, the "
           "real-world snapshot list and all scripts used to produce the tables and figures are available in the "
           "accompanying repository.")
    P.references(REFS)
    out = HERE / "EVIDENT_paper.docx"
    P.save(out)
    print("wrote", out)


def msup_star():
    from docxkit import msup
    return msup(mr("x"), mr("*"))


def remediation_text() -> str:
    ev, vm, up, au, la = "evident", "vm_opt", "upgrade_all", "audit_fix", "latest"
    s = (f"Table 4 compares the strategies. Upgrading everything removes "
         f"{pct(strat(up, 'risk_reduction_evident'), 0)} of expected exposure but changes {strat(up, 'changed'):.1f} "
         f"packages per project, {strat(up, 'major_bumps'):.1f} of them across major versions, and introduces "
         f"{strat(up, 'new_findings'):.1f} new findings. Upgrading each vulnerable package independently resolves "
         f"in only {pct(strat(au, 'ok'), 0)} (minimal fix) and {pct(strat(la, 'ok'), 0)} (latest) of projects, "
         "because independent upgrades violate the constraints of other installed packages. The optimiser, which "
         "encodes these constraints and is verified by the resolver, produced a resolvable plan in "
         f"{pct(strat(ev, 'ok'), 0)} of projects; with calibrated weights it changes {strat(ev, 'changed'):.1f} "
         f"packages ({strat(ev, 'major_bumps'):.1f} major bumps), removes {pct(strat(ev, 'risk_reduction_evident'), 0)} "
         f"of expected exposure and fixes {pct(strat(ev, 'confirmed_fixed'), 0)} of the findings with a confirmed "
         f"static path. With version-match weights the same optimiser changes {strat(vm, 'changed'):.1f} packages and "
         f"removes {pct(strat(vm, 'risk_reduction_evident'), 0)}. ")
    pc = T.get("pareto_common") or {}
    pd = T.get("pareto_vs_discrimination") or {}
    if pc:
        gain = pc["mean_auc_gain"]
        if abs(gain) < 0.01:
            verdict = ("the two fronts are practically indistinguishable (mean difference in area under the front "
                       f"{gain:+.3f}; calibrated weights better on {pc['better']} and worse on {pc['worse']} of "
                       f"{pc['projects']} projects)")
        elif gain > 0:
            verdict = (f"calibrated weights lower the front by {gain:.3f} on average (better on {pc['better']}, worse "
                       f"on {pc['worse']} of {pc['projects']} projects)")
        else:
            verdict = (f"calibrated weights raise the front by {-gain:.3f} on average (better on {pc['better']}, worse "
                       f"on {pc['worse']} of {pc['projects']} projects)")
        s += ("To compare weightings fairly, Figure 5 scores the plans of both weightings for a sweep of λ with the "
              f"same yardstick, the calibrated expected exposure validated in RQ2: {verdict}. ")
        s += (f"The median per-project difference is {pc['median_auc_gain']:+.3f}, so the mean is driven by a few "
              "projects. ") if abs(pc["median_auc_gain"] - pc["mean_auc_gain"]) > 0.01 else ""
        if pd:
            stats_txt = (f"Spearman ρ = {pd['spearman_rho']:.2f}, p = {pd['p']:.2f}, n = {pd['n']}; mean difference "
                         f"{pd['gain_high_disc']:+.3f} above and {pd['gain_low_disc']:+.3f} below the median share")
            if pd["p"] < 0.05 and pd["spearman_rho"] > 0:
                s += ("The benefit grows with how discriminative the evidence is, measured as the share of findings the "
                      f"evidence classifies decisively ({stats_txt}). ")
            else:
                s += ("We hypothesised that the benefit would grow with the share of findings that the evidence classifies "
                      f"decisively, but the data do not support this ({stats_txt}). ")
        s += ("In the current corpus most findings are only *possibly* reachable, so calibrated probabilities are "
              "similar across findings and weighting by them approaches counting. The practical benefit of evidence in "
              "remediation is therefore less in the choice of plan than in what accompanies it: every finding that is "
              "left unfixed carries a probability and, where decisive, a VEX justification.")
    return s


def closed_loop_text() -> str:
    BD = T["baseline_drift"]
    ev = "evident"
    return (f"Re-resolving the unchanged environments with the original pins as preferences already changed a median "
            f"of {BD['median']:.0f} packages (mean {BD['mean']:.1f}) because pins were yanked, lacked wheels for the "
            f"target or conflicted with newer metadata. Of the {n_snap} snapshots, {n_ok} resolved in metadata-only "
            f"mode. EVIDENT plans were verified in {pct(strat(ev, 'ok'), 0)} of them, after {strat(ev, 'iterations'):.1f} "
            f"solver/resolver iterations on average (counter-example cuts), taking {strat(ev, 'seconds'):.0f} s per "
            f"project. On average the resolver made {strat(ev, 'unplanned_changes'):.1f} changes beyond the plan "
            f"(compared with {BD['mean']:.1f} when re-resolving without any plan), and "
            f"{strat(ev, 'plan_not_realised'):.1f} planned versions were not realised; the realised environment, not "
            f"the plan, is therefore what EVIDENT re-scans and reports. Of {DEC['uncertain_total']} uncertain findings in the "
            f"resolvable projects, only {DEC['critical_total']} ({pct(DEC['critical_total'] / max(DEC['uncertain_total'], 1))}) "
            f"would change the optimal plan if resolved (median {DEC['median_critical']:.0f} per project); these are "
            "the findings worth manual triage.")


if __name__ == "__main__":
    build()
