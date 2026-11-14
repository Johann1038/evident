# EVIDENT

**Evidence-graded exposure assessment and resolver-verified remediation of transitive vulnerabilities in Python projects.**

> *Not every vulnerable dependency needs an upgrade.* EVIDENT treats each vulnerability finding as a hypothesis:
> it gathers graded evidence that the vulnerable code can actually run in your application, turns that evidence
> into a **calibrated probability of exposure**, and then computes the **smallest set of dependency changes** that
> removes the most exposure, a plan that a real resolver has already verified.

---

## Contents

1. [Why EVIDENT](#why-evident)
2. [How it differs from existing work](#how-it-differs-from-existing-work)
3. [How it works](#how-it-works)
4. [Installation](#installation)
5. [Usage](#usage)
6. [Reproducing the experiments](#reproducing-the-experiments)
7. [Results](#results)
8. [Repository layout](#repository-layout)
9. [Running efficiently on a laptop](#running-efficiently-on-a-laptop)
10. [Safety model](#safety-model)
11. [Limitations](#limitations)
12. [Citation and license](#citation-and-license)

---

## Why EVIDENT

Software composition analysis (SCA) tools report every dependency whose version falls inside an advisory's range.
In Python applications most of these findings are never executed: the package is only installed on another
platform, used only in development, never imported, or the vulnerable function is unreachable. Upgrading
everything is expensive and can break the application. Existing tools either **grade** findings with hand-chosen
weights or **optimise** upgrades with fixed reachability coefficients, mostly for Java or npm.

EVIDENT contributes:

| # | Contribution | What is new |
|---|---|---|
| 1 | **Graded, three-valued evidence** (L1-L5) | Separates inventory, version, target-environment installation, import, static reachability and runtime evidence; distinguishes *inconclusive* from *missing* evidence; maps to CycloneDX/OpenVEX. |
| 2 | **Cross-package static reachability for Python** | Strong (resolved) vs. weak (over-approximated) edges; never claims "unreachable" when reflection is present; vulnerable functions mined from fix commits. |
| 3 | **Staged, calibrated exposure model** | `P(exposed) = P(deployed)·P(installed)·P(imported)·P(called)`, learned from runtime ground truth; missing evidence is neutral. |
| 4 | **Evidence-weighted, resolver-verified remediation** | CP-SAT optimisation of calibrated residual risk vs. change cost, a counter-example-guided loop with the `uv` resolver, Pareto fronts, and a re-scan of the realised environment. |
| 5 | **Decision sensitivity (EVPI)** | Tells you which few uncertain findings would change the plan and are worth manual triage. |
| 6 | **EVIDENT-Bench + empirical study** | 962 runtime-labelled pairs and 120 historical snapshots of open-source Python applications. |

## How it differs from existing work

| Approach | Ecosystem | Reachability | Graded / 3-valued | Calibrated | Missing-evidence handling | Optimised plan | Resolver-verified | Re-scan of result |
|---|---|---|---|---|---|---|---|---|
| pip-audit, OSV-Scanner, Dependabot | PyPI + others | – | – | – | – | partial | – | – |
| Eclipse Steady (Ponta et al.) | Java | ✓ | partial | – | – | partial | – | – |
| CORAL (ICSE'23) | Maven | ✓ | partial | – | partial | ✓ | ✓ | – |
| Remedius (OOPSLA'26) | Maven | ✓ | partial | – | partial | ✓ | ✓ | – |
| MaxNPM / PacSolve (ICSE'23) | npm | – | – | – | – | ✓ | ✓ | – |
| KEVGraph (arXiv'26) | multi | – | – | – | – | ✓ | – | partial |
| CAPE (arXiv'26) | Python/JS | ✓ | ✓ | – | ✓ | – | – | – |
| **EVIDENT** | **PyPI** | **✓** | **✓** | **✓** | **✓** | **✓** | **✓** | **✓** |

EVIDENT is the only approach that **calibrates** exposure probabilities against runtime ground truth and
**propagates** them into resolver-verified remediation. The paper compares against re-implementations of the
CORAL, CAPE and KEVGraph weighting schemes inside the same optimiser, so the comparison isolates the weighting.

## How it works

```
 lockfile + manifest ─► target-env resolution ─► findings (L1 L2 L3) ─┐
 OSV / CVSS / EPSS / KEV (dated snapshot) ─────────────────────────────┤
 fix-commit symbol mining ─► cross-package static analysis (L3b L4) ───┼─► staged exposure model ─► CP-SAT plan ◄─► uv resolver
 runtime traces (L5, optional) ────────────────────────────────────────┘        P(Y|E) calibrated        │
                                                                                         VEX + SBOM, EVPI ◄── re-resolve, SBOM, re-scan
```

| Level | Question | States |
|---|---|---|
| L1 Inventory | Is the package in the lock/SBOM? | confirmed |
| L2 Version | Is the locked version in an affected range? | confirmed |
| L3 Installation | Installed for the target interpreter/platform? Production or dev-only? | confirmed / refuted / unknown |
| L3b Import | Is a module of the package loaded by non-test code? | confirmed / refuted / unknown |
| L4 Static | Is a vulnerable function reachable from application roots? | confirmed / possible / refuted / unknown |
| L5 Runtime | Did an observed run execute it? | observed / not observed / unknown |

**Remediation model:**

```
minimise   Σ_p,v x[p,v] · ( Σ_{a ∈ A(p,v)} w_a · P_a  +  λ · Cost(p,v) )
subject to one version per package, PyPI requires_dist constraints, verified by uv (no-good cuts on failure)
```

## Installation

Requires Python ≥ 3.11 and `git`. The resolver (`uv`) is installed as a dependency.

```bash
git clone <this repository>
cd <repository>
python -m venv .venv
# Windows: .venv\Scripts\activate      Linux/macOS: source .venv/bin/activate
pip install -e ".[paper,dev]"
pytest -q          # unit tests (offline)
```

Vulnerability intelligence is read from dated local snapshots in `data/intel/`:

```bash
mkdir -p data/intel
curl -L -o data/intel/osv_pypi_all.zip https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip
curl -L -o data/intel/kev.json https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
curl -L -o data/intel/epss_scores-current.csv.gz https://epss.empiricalsecurity.com/epss_scores-current.csv.gz
```

Fix-commit mining uses the GitHub API through an authenticated `gh` CLI (`gh auth login`).

## Usage

Scan a project that contains a lockfile (`uv.lock`, `poetry.lock`, `pdm.lock`, `Pipfile.lock` or pinned `requirements.txt`):

```bash
evident scan path/to/project            # evidence-graded findings + CycloneDX 1.6 SBOM with VEX
evident scan path/to/project --no-code  # skip source analysis (L3b/L4)
evident plan path/to/project            # resolver-verified remediation plan + what to triage first
evident plan path/to/project --lambda 0.3   # prefer fewer changes
```

Real output on Red-DiscordBot 3.5.2 (a project from the study corpus, scanned against the 2026-11-12 advisory snapshot):

```
$ evident scan red-discordbot --top 5
38 installed packages (12 direct, 26 transitive), target Python 3.10; 61 version-matched findings
exposure classes: {'IMPORTED_REACH_UNKNOWN': 19, 'STATICALLY_REACHABLE': 5, 'POSSIBLY_REACHABLE': 36, 'NOT_INSTALLED': 1}
p_exposed  cvss  package                  advisory               class
    0.656   9.8  brotli==1.0.9            CVE-2026-111497        IMPORTED_REACH_UNKNOWN
    0.807   8.7  aiohttp==3.8.4           CVE-2026-123817        STATICALLY_REACHABLE
    0.807   7.5  aiohttp==3.8.4           CVE-2026-34513         STATICALLY_REACHABLE
    0.807   6.9  aiohttp==3.8.4           CVE-2026-22815         STATICALLY_REACHABLE
    0.574   9.1  aiohttp==3.8.4           CVE-2026-34520         POSSIBLY_REACHABLE
wrote evident-out/findings.json and evident-out/sbom.cdx.json (CycloneDX 1.6 with VEX)

$ evident plan red-discordbot
plan verified by resolver: True (iterations: 1)
  aiohttp: 3.8.4 -> 3.14.5
  aiosignal: 1.3.1 -> 1.4.0
  brotli: 1.0.9 -> 1.2.1
  idna: 3.4 -> 3.20
  markdown: 3.4.3 -> 3.8.1
  orjson: 3.8.12 -> 3.11.6
  pycares: 4.3.0 -> 4.9.0
  pygments: 2.15.1 -> 2.20.0
  yarl: 1.9.2 -> 1.25.1
  resolver-induced changes: aiohappyeyeballs->2.7.1, propcache->0.5.4
expected residual risk 0.000, change cost 15.30
investigate first (uncertain findings that would change this plan):
  pycares CVE-2025-48945  p=0.57  EVPI=0.072
  pygments CVE-2026-4539  p=0.57  EVPI=0.072
  markdown CVE-2025-69534  p=0.66  EVPI=0.058
```

Ranking uses `p_exposed × severity`, where severity is CVSS/10, doubled for CISA KEV entries.

## Reproducing the experiments

Every number in the paper is produced by these scripts from data under `data/`:

| Step | Command | Output |
|---|---|---|
| Collect historical snapshots (data only) | `python experiments/collect_dataset.py --mode topics --target 120` | `data/snapshots/` |
| Build EVIDENT-Bench (isolated venvs, traced runs) | `python experiments/bench/build_bench.py --workers 4` | `data/results/bench_records.jsonl` |
| RQ2/RQ5: calibration, missing evidence, time split, ablations | `python experiments/analyze_bench.py` | `data/results/bench_eval.json`, `staged_model.json` |
| RQ1/RQ3/RQ4: real-world study | `python experiments/run_realworld.py --workers 2` | `data/results/realworld/*/` |
| Tables and figures | `python experiments/make_figures.py` | `data/results/paper_tables.json`, `paper/figures/` |
| Paper (DOCX, conference template) | `python paper/build_paper.py` | `paper/EVIDENT_paper.docx` |

`build_bench.py --reuse` recomputes static evidence from recorded traces without re-running applications.

## Results

### EVIDENT-Bench (962 runtime-labelled pairs, 61 advisories, 14 packages; leave-one-package-out)

| Method | Brier ↓ | ECE ↓ | AUC ↑ | AP ↑ |
|---|---|---|---|---|
| Version match (SCA scanner) | 0.426 | 0.426 | 0.500 | 0.618 |
| CORAL-style coefficients | 0.186 | 0.117 | 0.782 | 0.815 |
| CAPE-style weighted score | 0.248 | 0.259 | 0.752 | 0.780 |
| Logistic regression + isotonic | 0.127 | 0.052 | 0.877 | 0.930 |
| **EVIDENT staged model** | **0.127** | **0.049** | **0.879** | 0.923 |
| CVSS-only / EPSS-only ranking | – | – | – | 0.608 / 0.623 |

**Robustness to missing evidence** (L4 and L5 hidden with probability q, expected calibration error):

| q | 0 | 0.25 | 0.5 | 0.75 | 1.0 |
|---|---|---|---|---|---|
| **EVIDENT** | **0.049** | **0.035** | **0.030** | **0.025** | **0.003** |
| Logistic + isotonic | 0.052 | 0.093 | 0.106 | 0.084 | 0.026 |
| CORAL-style | 0.117 | 0.103 | 0.099 | 0.083 | 0.074 |
| CAPE-style | 0.259 | 0.286 | 0.315 | 0.343 | 0.373 |

**Time split** (train on advisories ≤ 2024, test on 41 advisories from 2025-2026): EVIDENT Brier 0.122 / ECE 0.024;
CORAL-style 0.181; CAPE-style 0.245.

**Static analysis:** no exposed pair was ever statically *refuted*; import evidence has recall 1.0.

### Real-world study

<!-- REALWORLD-RESULTS -->
33 historical snapshots of open-source Python applications (lockfiles from mid-2023, scanned against the 2026-11-12 advisory snapshot); 24 re-resolve in metadata-only mode.

- **3863 version-matched findings**, median 110 per application; 55% concern transitive dependencies.
- **13.3%** are not installed for the target, development-only, not imported, or statically unreachable (each with a VEX justification); 132 have a confirmed static path.
- The calibrated model expects **1829** of them to be exposed.

| Strategy | Resolves | Packages changed | Major bumps | Expected exposure removed | Confirmed-reachable fixed |
|---|---|---|---|---|---|
| Minimal fix per package (pip-audit style) | 54% | 36.2 | 3.9 | 61% | 92% |
| Latest release per package | 92% | 38.8 | 7.8 | 71% | 93% |
| Upgrade everything (uv) | 96% | 72.3 | 22.3 | 74% | 92% |
| Optimiser + version-match weights (KEVGraph-like) | 100% | 36.2 | 6.0 | 71% | 91% |
| Optimiser + CORAL-style weights | 100% | 35.2 | 5.5 | 66% | 91% |
| Optimiser + CAPE-style weights | 100% | 36.2 | 6.2 | 70% | 91% |
| **EVIDENT** (optimiser + calibrated weights) | 100% | 34.0 | 4.9 | 66% | 91% |

Scored with the same yardstick, calibrated and version-match weights give similar risk/change fronts (mean area difference -0.008, median +0.001; calibrated better on 11, worse on 3 of 24 projects): with mostly *possibly reachable* findings, weighting approaches counting. The main remediation gains come from constraint-aware, resolver-verified planning.

Only 98 of 2332 uncertain findings (4.2%) would change the optimal plan if resolved: these are the ones EVIDENT asks you to triage.
<!-- /REALWORLD-RESULTS -->

## Repository layout

```
src/evident/
  lockfiles.py   uv / Poetry / PDM / Pipenv / requirements parsers
  graph.py       dependency graph, PEP 508 markers, target environment, dev scope (L3)
  intel.py       OSV (alias clusters, PEP 440 ranges), CVSS, EPSS, KEV
  symbols.py     vulnerable-function mining from fix commits
  reach.py       cross-package static reachability (L3b, L4)
  runtime.py     runtime tracer (L5)
  evidence.py    evidence model, exposure classes, VEX mapping
  exposure.py    staged calibrated model, baselines, metrics
  optimize.py    CP-SAT remediation, resolver loop, Pareto front, EVPI
  resolve.py     metadata-only uv resolution
  sbom.py        CycloneDX 1.6 SBOM + VEX
  pipeline.py    end-to-end scan;  cli.py  command-line interface
experiments/     dataset collection, EVIDENT-Bench, analyses, figures
paper/           template, figure files, paper builder
data/results/    benchmark records, evaluations, real-world results (versioned)
data/symbols/    mined vulnerable symbols per advisory (versioned)
tests/           unit tests
```

## Running efficiently on a laptop

The reference machine for the paper was a 14-core laptop with 16 GB RAM. Memory, not CPU, is the bottleneck:

- **I/O-bound work** (PyPI, OSV, GitHub) runs in thread pools (16 threads); results are cached under `data/cache/`.
- **Static analysis** of large applications can use 1-2 GB per project; `run_realworld.py` runs every project in its
  own process with a timeout, so a crash or out-of-memory error affects only that project. Use `--workers 2` on 16 GB
  machines, `--workers 4` with 32 GB.
- **CP-SAT** uses 8 search workers with a 20 s limit per solve.
- Close memory-heavy applications (browsers, IDE instances, local databases) before long runs, keep the machine on
  mains power, and disable sleep; every stage is resumable.
- On Windows, keep the repository on a local SSD path excluded from cloud sync; on Linux/WSL, keep it on the native
  file system (not `/mnt/c`).

## Safety model

- Project source code, lockfiles and wheels are treated as **data**: they are parsed, never executed.
- Resolution runs `uv pip compile --no-build`: build scripts of source distributions are never run.
- Only EVIDENT-Bench executes code: our generated applications calling pinned library versions, each in an
  isolated virtual environment, offline.

## Limitations

- Exposure means "a function changed by the fix executes"; it upper-bounds exploitability.
- Vulnerabilities fixed only in C/Rust extensions have no Python-level symbols; their L4 evidence is reported as missing.
- Benchmark applications follow 16 generated patterns; framework-specific dispatch (e.g. URL routing by string) is
  handled by over-approximation only.
- Remediated environments are verified by resolution and re-scanning; build/test execution is not part of the study.

## Citation and license

If you use EVIDENT, please cite the accompanying paper (venue details will be added after publication):

> J. S. George, F. K. Renu, A. Sajikumar, R. J. A, G. N. Sundar and D. Narmadha, *Not Every Vulnerable Dependency
> Needs an Upgrade: Calibrated Exposure Evidence and Metadata-Verified Remediation for Python Projects*.
> Department of Computer Science and Engineering, Karunya Institute of Technology and Sciences, Coimbatore, India.

Licensed under the Apache License 2.0 (see `LICENSE`).
