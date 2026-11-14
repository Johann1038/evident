"""Third-round real-world analyses on the saved results (no new runs, no network).

  sample        completed vs timed-out vs unprocessed applications (stars, year, lockfile kind, locked packages,
                framework), with Mann-Whitney / chi-square tests
  coverage      why completed applications were not resolvable (remediation eligibility), end-to-end coverage
  drift         planned vs resolver-realised plans: pins realised, unplanned changes, new findings, objective gap
  fixed         confirmed-fixed defined per project and pooled, with denominators
  tests         paired comparisons with median difference, IQR, rank-biserial effect size, bootstrap CI, Holm
  case          the case-study advisory set (why the optimiser chose its Django version)
Writes data/results/round3_realworld.json.
"""
from __future__ import annotations

import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np
from scipy.stats import chi2_contingency, mannwhitneyu, wilcoxon

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
RES = ROOT / "data" / "results"
RW = RES / "realworld"
SNAP = ROOT / "data" / "snapshots"
FRAMEWORKS = ("django", "flask", "fastapi", "aiohttp", "tornado", "starlette", "streamlit")


def boot_ci(v, stat=np.median, B=2000, seed=5):
    v = np.asarray(v, float)
    if len(v) < 3:
        return None
    rs = np.random.default_rng(seed)
    bs = [stat(rs.choice(v, len(v))) for _ in range(B)]
    return [float(np.percentile(bs, 2.5)), float(np.percentile(bs, 97.5))]


def locked_count(sd: Path, meta: dict):
    from evident.lockfiles import load_snapshot
    try:
        env = load_snapshot(sd, meta["lock_file"])
        return len(getattr(env, "packages", None) or getattr(env, "pins", None) or {})
    except Exception:
        return None


def framework(sd: Path, meta: dict) -> str:
    txt = " ".join(meta.get("topics") or []) + " " + (meta.get("description") or "")
    lock = sd / meta.get("lock_file", "")
    try:
        txt += " " + lock.read_text("utf8", errors="replace")[:400000].lower()
    except OSError:
        pass
    txt = txt.lower()
    for fw in FRAMEWORKS:
        if f'"{fw}"' in txt or f"name = \"{fw}\"" in txt or f"\n{fw}==" in txt or f" {fw} " in f" {txt} ":
            return fw
    return "other"


def part_sample(out):
    rows = []
    for sd in sorted(p for p in SNAP.iterdir() if (p / "meta.json").exists()):
        meta = json.loads((sd / "meta.json").read_text("utf8"))
        d = RW / sd.name
        if (d / "result.json").exists():
            grp = "completed"
        elif (d / "error.txt").exists() and (d / "error.txt").read_text("utf8", errors="replace").startswith("timeout"):
            grp = "timeout"
        else:
            grp = "not_processed"
        rows.append({"id": sd.name, "group": grp, "stars": meta.get("stars") or 0,
                     "year": int((meta.get("published_at") or "2023")[:4]), "lock_kind": meta.get("lock_kind"),
                     "locked": locked_count(sd, meta), "framework": framework(sd, meta),
                     "scan_done": (d / "findings.json").exists()})
    by = defaultdict(list)
    for r in rows:
        by[r["group"]].append(r)
    summ = {}
    for g, rs in by.items():
        loc = [r["locked"] for r in rs if r["locked"] is not None]
        summ[g] = {"n": len(rs), "stars_median": float(np.median([r["stars"] for r in rs])),
                   "locked_median": float(np.median(loc)) if loc else None,
                   "locked_iqr": [float(np.percentile(loc, 25)), float(np.percentile(loc, 75))] if loc else None,
                   "lock_kind": dict(Counter(r["lock_kind"] for r in rs)),
                   "framework": dict(Counter(r["framework"] for r in rs)),
                   "year": dict(Counter(r["year"] for r in rs))}
    comp, rest = by["completed"], by["not_processed"]
    tests = {}
    for k in ("stars", "locked"):
        a = [r[k] for r in comp if r[k] is not None]
        b = [r[k] for r in rest if r[k] is not None]
        tests[k] = {"mannwhitney_p": float(mannwhitneyu(a, b).pvalue)}
    for k in ("lock_kind", "framework"):
        cats = sorted({r[k] for r in comp + rest})
        tab = np.array([[sum(1 for r in grp if r[k] == c) for c in cats] for grp in (comp, rest)])
        tab = tab[:, tab.sum(0) > 0]
        tests[k] = {"chi2_p": float(chi2_contingency(tab)[1]), "categories": cats}
    out["sample"] = {"groups": summ, "tests_completed_vs_not_processed": tests,
                     "timeouts": [{k: r[k] for k in ("id", "stars", "locked", "lock_kind", "framework", "scan_done")}
                                  for r in by["timeout"]]}


def load_results():
    return [json.loads((d / "result.json").read_text("utf8")) for d in sorted(RW.iterdir()) if (d / "result.json").exists()]


def categorize(err: str) -> str:
    e = (err or "").lower()
    if "no solution found" in e or "unsatisfiable" in e or "because" in e and "depends on" in e:
        return "baseline dependency conflict (lockfile unsatisfiable for the target platform)"
    if "no wheel" in e or "only source" in e or "sdist" in e or "build" in e:
        return "required package has no compatible wheel (source builds disabled)"
    if "python" in e and ("requires" in e or "version" in e):
        return "Python version constraint"
    if "timeout" in e:
        return "resolver timeout"
    return "other: " + e[:80]


def part_drift_fixed_tests(out, rw):
    ok = [r for r in rw if r.get("status") == "ok"]
    notok = [r for r in rw if r.get("status") != "ok"]
    out["coverage"] = {
        "completed": len(rw), "resolvable": len(ok), "end_to_end_coverage": len(ok) / len(rw),
        "excluded": [{"id": r["id"], "status": r.get("status"),
                      "reason": categorize((r.get("baseline_resolution") or {}).get("error", ""))} for r in notok],
        "excluded_reasons": dict(Counter(categorize((r.get("baseline_resolution") or {}).get("error", "")) for r in notok))}
    lam = 0.1
    drift = {}
    for name in ("evident", "vm_opt", "coral_opt", "uv_fix", "latest", "audit_fix"):
        rows = [r["strategies"][name] for r in ok if r["strategies"].get(name, {}).get("ok")]
        if not rows:
            continue
        d = {"n": len(rows)}
        for k in ("planned_changes", "plan_not_realised", "unplanned_changes", "unplanned_major",
                  "new_findings_from_unplanned", "residual_findings", "new_findings"):
            v = [s[k] for s in rows if s.get(k) is not None]
            if v:
                d[k] = {"mean": float(np.mean(v)), "median": float(np.median(v)), "ci_mean": boot_ci(v, np.mean)}
        pr = [1 - s["plan_not_realised"] / s["planned_changes"] for s in rows
              if s.get("planned_changes")]
        if pr:
            d["planned_pins_realised"] = {"mean": float(np.mean(pr)), "all_realised": int(sum(x == 1 for x in pr))}
        if name in ("evident", "vm_opt", "coral_opt"):
            gap = [s["residual_risk_evident"] - s["model_residual"] for s in rows if s.get("model_residual") is not None]
            obj_plan = [s["model_residual"] + lam * s["model_cost"] for s in rows if s.get("model_cost") is not None]
            d["objective_gap"] = {"definition": "realised residual expected risk (sum over remaining advisories of "
                                                "severity weight x exposure probability) minus the optimiser's "
                                                "planned residual",
                                  "mean": float(np.mean(gap)), "median": float(np.median(gap)),
                                  "ci_mean": boot_ci(gap, np.mean), "zero_gap": int(sum(abs(g) < 1e-9 for g in gap)),
                                  "planned_objective_mean": float(np.mean(obj_plan)) if obj_plan else None}
        drift[name] = d
    # untouched re-resolution drift, paired with EVIDENT's unplanned changes
    pairs = [(r["strategies"]["evident"]["unplanned_changes"], r["baseline_drift"]) for r in ok
             if r["strategies"].get("evident", {}).get("ok") and r.get("baseline_drift") is not None]
    if pairs:
        a, b = np.array(pairs, float).T
        drift["evident_vs_untouched_drift"] = {"n": len(pairs), "median_diff": float(np.median(a - b)),
                                               "p": float(wilcoxon(a, b).pvalue) if np.any(a != b) else 1.0,
                                               "unplanned_mean": float(a.mean()), "untouched_mean": float(b.mean())}
    out["drift"] = drift
    # confirmed-fixed: per-project mean (projects with >= 1 confirmed finding) and pooled ratio
    fixed = {}
    for name in ("evident", "vm_opt", "coral_opt", "uv_fix", "latest", "audit_fix", "upgrade_all"):
        num = den = 0
        per = []
        for r in ok:
            s, o = r["strategies"].get(name, {}), r["original"]
            if not s.get("ok") or not o.get("residual_confirmed"):
                continue
            num += o["residual_confirmed"] - s["residual_confirmed"]
            den += o["residual_confirmed"]
            per.append(1 - s["residual_confirmed"] / o["residual_confirmed"])
        if den:
            fixed[name] = {"projects_with_confirmed": len(per), "confirmed_findings": den, "fixed": num,
                           "pooled": num / den, "per_project_mean": float(np.mean(per))}
    out["confirmed_fixed"] = {"definition": "share of the original findings with strong static reachability (L4 "
                                            "CONFIRMED) whose affected version is no longer installed in the "
                                            "resolver-realised environment; newly introduced findings are counted "
                                            "separately (new_findings); advisories are counted per (package, advisory)",
                              **fixed}
    # paired tests with effect sizes and Holm correction
    fam = []
    for other in ("uv_fix", "vm_opt", "coral_opt", "upgrade_all"):
        for k in ("changed", "findings_removed"):
            a, b = [], []
            for r in ok:
                se, so, o = r["strategies"].get("evident", {}), r["strategies"].get(other, {}), r["original"]
                if not (se.get("ok") and so.get("ok")):
                    continue
                if k == "findings_removed":
                    if not o["residual_findings"]:
                        continue
                    a.append(1 - se["residual_findings"] / o["residual_findings"])
                    b.append(1 - so["residual_findings"] / o["residual_findings"])
                else:
                    a.append(se[k])
                    b.append(so[k])
            a, b = np.array(a, float), np.array(b, float)
            d = a - b
            nz = d[d != 0]
            if len(nz) < 3:
                continue
            p = float(wilcoxon(a, b).pvalue)
            ranks = np.argsort(np.argsort(np.abs(nz))) + 1
            rbc = float((ranks[nz > 0].sum() - ranks[nz < 0].sum()) / ranks.sum())
            fam.append({"comparison": f"evident_vs_{other}", "metric": k, "n": int(len(d)), "n_nonzero": int(len(nz)),
                        "median_evident": float(np.median(a)), "median_other": float(np.median(b)),
                        "median_diff": float(np.median(d)), "iqr_diff": [float(np.percentile(d, 25)),
                                                                          float(np.percentile(d, 75))],
                        "ci_median_diff": boot_ci(d), "rank_biserial": rbc, "p": p, "sides": "two-sided"})
    order = np.argsort([t["p"] for t in fam])
    m = len(fam)
    running = 0.0
    for rank, i in enumerate(order):
        running = max(running, min(1.0, (m - rank) * fam[i]["p"]))
        fam[i]["p_holm"] = running
    out["paired_tests"] = {"family_size": m, "correction": "Holm", "tests": fam}


def part_case(out, rw):
    from evident import intel
    from packaging.version import Version
    cs = next((r for r in rw if r["id"].startswith("Ehco1996__django-sspanel")), None)
    if cs is None:
        return
    advs = intel.load_osv().get("django", [])
    cur = "4.2.6"
    aff = [a for a in advs if intel.is_affected(a, cur)] if hasattr(intel, "is_affected") else \
        list(intel.advisories_for("django", cur))
    cand = {}
    for v in ("4.2.26", "4.2.30", "5.2.8", "5.2.19"):
        try:
            cand[v] = len(list(intel.advisories_for("django", v)))
        except Exception:
            cand[v] = None
    ev = cs["strategies"]["evident"]
    out["case"] = {"id": cs["id"], "django_advisories_affecting_4.2.6": len(aff),
                   "remaining_advisories_if_upgraded_to": cand,
                   "planned_django": ev["planned"].get("django"),
                   "planned_changes": ev.get("planned_changes"), "unplanned_changes": ev.get("unplanned_changes"),
                   "residual_findings": ev.get("residual_findings"),
                   "original_findings": cs["original"]["residual_findings"]}


def main():
    out = {}
    part_sample(out)
    rw = load_results()
    part_drift_fixed_tests(out, rw)
    try:
        part_case(out, rw)
    except Exception as e:  # case-study detail is optional
        out["case_error"] = repr(e)
    (RES / "round3_realworld.json").write_text(json.dumps(out, indent=1, default=float), "utf8")
    print(json.dumps({k: v for k, v in out.items() if k != "paired_tests"}, indent=1, default=float)[:9000])
    for t in out["paired_tests"]["tests"]:
        print(t["comparison"], t["metric"], "n", t["n"], "med", round(t["median_evident"], 3), "vs",
              round(t["median_other"], 3), "diff", round(t["median_diff"], 3), "r", round(t["rank_biserial"], 2),
              "p", round(t["p"], 4), "holm", round(t["p_holm"], 4))


if __name__ == "__main__":
    main()
