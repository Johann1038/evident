"""Post-hoc analyses on the saved real-world results (run after run_realworld.py).

  fronts       plans for a lambda sweep with calibrated vs version-match weights, scored by one yardstick
  compat       Level-2 (symbol existence) and Level-2b (signature) compatibility of every realised plan
  devprior     sensitivity of exposure estimates and plans to P(deployed | dev-only)
  weights      sensitivity of plans to the KEV multiplier and to sum vs max aggregation
  candidates   candidate limits 6/8/12/20 with resolver verification (resolvable projects)
  scopes       reflection-scope verdicts of findings (static evidence recomputed where missing)
Writes data/results/posthoc_realworld.json and pareto_common.json.
Usage: python experiments/posthoc_realworld.py [--parts fronts,compat,devprior,weights,candidates,scopes]
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from evident import intel  # noqa: E402
from evident.evidence import Evidence, Finding  # noqa: E402
from evident.exposure import StagedModel  # noqa: E402
from evident.graph import TargetEnv  # noqa: E402
from evident.optimize import Remediator  # noqa: E402

TODAY = "2026-11-12"
LAMS = (0.0, 0.02, 0.05, 0.1, 0.2, 0.5, 1.0, 2.0, 5.0, 100.0)
RW = ROOT / "data" / "results" / "realworld"
RES = ROOT / "data" / "results"
MODEL = StagedModel.from_json((RES / "staged_model.json").read_text("utf8"))


def load(snap: Path):
    res = json.loads((snap / "result.json").read_text("utf8"))
    rows = json.loads((snap / "findings.json").read_text("utf8"))
    bom = json.loads((snap / "sbom.cdx.json").read_text("utf8"))
    pins = {c["name"]: c["version"] for c in bom["components"]}
    app = next(d for d in bom["dependencies"] if d["ref"] == "app")
    direct = {r.split("/")[-1].split("@")[0] for r in app["dependsOn"]}
    fnd = []
    for r in rows:
        if r.get("L3_state") != "CONFIRMED" or r["package"] not in pins:
            continue
        f = Finding(**{k: r[k] for k in ("snapshot", "package", "version", "advisory", "ids", "cves", "cvss", "epss",
                                          "kev", "severity_w", "published", "fixed", "depth", "direct")})
        f.evidence = {k: Evidence(**v) for k, v in r["evidence"].items()}
        f.p_exposed = r["p_exposed"]
        fnd.append(f)
    return res, rows, pins, direct, fnd


def p_new_factory(fnd, model=MODEL):
    stage = {}
    for f in fnd:
        s = model.stage_probs(f)
        stage[f.package] = s["D"] * s["I"] * s["M"] * model.prior_call
    return lambda p: stage.get(p, model.p_import_marg * model.prior_call)


def jacc(a: dict, b: dict) -> float:
    A, B = set(a.items()), set(b.items())
    return 1.0 if not A and not B else len(A & B) / len(A | B)


def snaps_ok():
    for s in sorted(RW.iterdir()):
        if (s / "result.json").exists():
            res = json.loads((s / "result.json").read_text("utf8"))
            if res.get("status") == "ok":
                yield s


def part_fronts(out):
    fronts = {}
    for snap in snaps_ok():
        res, rows, pins, direct, fnd = load(snap)
        if not fnd:
            continue
        tenv = TargetEnv(python=res["python"])
        pn = p_new_factory(fnd)
        ev = Remediator(pins, direct, fnd, tenv, today=TODAY, p_of=lambda f: f.p_exposed, p_new_of=pn)
        vm = Remediator(pins, direct, fnd, tenv, today=TODAY, p_of=lambda f: 1.0, p_new_of=lambda p: 1.0)
        pk = sorted({f.package for f in fnd})

        def score(ch):
            chosen = {p: ch.get(p, pins[p]) for p in set(pk) | set(ch)}
            return (sum(ev._risk(p, v) for p, v in chosen.items()), sum(vm._risk(p, v) for p, v in chosen.items()))
        r0 = score({})
        pts = {"evident": [], "vm": []}
        for name, rem in (("evident", ev), ("vm", vm)):
            for lam in LAMS:
                pl = rem.solve(lam, time_limit=10.0)
                if pl is not None:
                    e, v = score(pl.changes)
                    pts[name].append({"lambda": lam, "exposure": e, "vm_risk": v, "changes": len(pl.changes)})
        fronts[snap.name] = {"r0_exposure": r0[0], "r0_vm": r0[1], "fronts": pts}
        print("fronts", snap.name, flush=True)
    (RES / "pareto_common.json").write_text(json.dumps(fronts, indent=1), "utf8")
    out["fronts_projects"] = len(fronts)


def part_compat(out):
    from evident.compat import plan_compatibility_levels
    per = {}
    for snap in snaps_ok():
        res = json.loads((snap / "result.json").read_text("utf8"))
        refs = (res.get("stats") or {}).get("app_refs", {})
        per[snap.name] = {}
        for name, s in res["strategies"].items():
            if not s.get("ok") or s.get("realised_changes") is None:
                continue
            ch = {p: tuple(v) for p, v in s["realised_changes"].items()}
            per[snap.name][name] = plan_compatibility_levels(ch, refs)
        print("compat", snap.name, flush=True)
    agg = defaultdict(lambda: Counter())
    for proj in per.values():
        for name, r in proj.items():
            agg[name]["plans"] += 1
            agg[name]["level2_ok"] += int(r["level2_ok"])
            agg[name]["level2b_ok"] += int(r["level2b_ok"])
            agg[name]["no_used_package_changed"] += int(r["used_changed"] == 0)
    out["compat"] = {n: dict(c) for n, c in agg.items()}
    out["compat_per_project"] = per


def part_devprior(out):
    res_ = {}
    for pd in (0.0, 0.01, 0.05, 0.10, 0.25):
        m = StagedModel.from_json(MODEL.to_json())
        m.p_dev_deployed = pd
        tot_exp, tot_dev_exp, plan_j, nproj, changes = 0.0, 0.0, [], 0, []
        for snap in snaps_ok():
            res, rows, pins, direct, fnd = load(snap)
            if not fnd:
                continue
            nproj += 1
            p = {(f.package, f.advisory): m.predict(f) for f in fnd}
            tot_exp += sum(p.values())
            tot_dev_exp += sum(v for f, v in zip(fnd, p.values())
                               if f.evidence.get("L3") and f.evidence["L3"].detail.get("scope") == "dev")
            tenv = TargetEnv(python=res["python"])
            rem = Remediator(pins, direct, fnd, tenv, today=TODAY, p_of=lambda f: p[(f.package, f.advisory)],
                             p_new_of=p_new_factory(fnd, m))
            base = Remediator(pins, direct, fnd, tenv, today=TODAY, p_of=lambda f: f.p_exposed,
                              p_new_of=p_new_factory(fnd))
            a, b = rem.solve(0.1, time_limit=10.0), base.solve(0.1, time_limit=10.0)
            if a and b:
                plan_j.append(jacc(a.changes, b.changes))
                changes.append(len(a.changes))
        res_[str(pd)] = {"expected_exposed": tot_exp, "expected_exposed_dev_only": tot_dev_exp,
                         "mean_plan_jaccard_vs_default": sum(plan_j) / max(len(plan_j), 1),
                         "mean_changes": sum(changes) / max(len(changes), 1), "projects": nproj}
        print("devprior", pd, res_[str(pd)], flush=True)
    out["devprior"] = res_


def part_weights(out):
    def sev(mult):
        return lambda a: ((a.cvss if a.cvss is not None else 5.0) / 10.0) * (mult if intel.in_kev(a) else 1.0)
    variants = {"kev1_sum": (sev(1), "sum"), "kev2_sum": (sev(2), "sum"), "kev3_sum": (sev(3), "sum"),
                "kev2_max": (sev(2), "max")}
    res_ = {}
    plans = defaultdict(dict)
    for snap in snaps_ok():
        res, rows, pins, direct, fnd = load(snap)
        if not fnd:
            continue
        tenv = TargetEnv(python=res["python"])
        for name, (sf, agg) in variants.items():
            rem = Remediator(pins, direct, fnd, tenv, today=TODAY, p_of=lambda f: f.p_exposed,
                             p_new_of=p_new_factory(fnd), sev_fn=sf, agg=agg)
            pl = rem.solve(0.1, time_limit=10.0)
            if pl:
                plans[name][snap.name] = pl.changes
        print("weights", snap.name, flush=True)
    for name in variants:
        common = [s for s in plans[name] if s in plans["kev2_sum"]]
        res_[name] = {"projects": len(plans[name]),
                      "mean_changes": sum(len(v) for v in plans[name].values()) / max(len(plans[name]), 1),
                      "mean_jaccard_vs_default": sum(jacc(plans[name][s], plans["kev2_sum"][s]) for s in common)
                      / max(len(common), 1),
                      "identical_plans": sum(1 for s in common if plans[name][s] == plans["kev2_sum"][s])}
    out["weights"] = res_


def part_candidates(out, limit_projects: int = 25):
    from evident import pypi
    from evident.resolve import Resolution, compile_env, requirement_set
    res_ = defaultdict(lambda: defaultdict(list))
    done = 0
    for snap in snaps_ok():
        if done >= limit_projects:
            break
        res, rows, pins, direct, fnd = load(snap)
        if not fnd:
            continue
        done += 1
        tenv = TargetEnv(python=res["python"])
        reqs, sdist_only = requirement_set(pins, tenv)
        prefer = {p: v for p, v in pins.items() if p not in sdist_only}

        def verify(ch):
            extra = [p for p in ch if p in sdist_only]
            if any(not pypi.has_wheel(p, ch[p]) for p in extra):
                return Resolution(False, error="no wheel")
            return compile_env(reqs + extra, constraints=ch, prefer=prefer, python=res["python"], exclude_newer=TODAY)
        for k in (6, 8, 12, 20):
            rem = Remediator(pins, direct, fnd, tenv, today=TODAY, p_of=lambda f: f.p_exposed,
                             p_new_of=p_new_factory(fnd), max_cands=k)
            t0 = time.time()
            pl = rem.plan_verified(0.1, verify)
            res_[k]["ok"].append(int(bool(pl.verified)))
            res_[k]["seconds"].append(time.time() - t0)
            res_[k]["iterations"].append(pl.iterations)
            if pl.verified:
                res_[k]["changes"].append(len(pl.changes))
                res_[k]["objective"].append(pl.objective)
            res_[k]["candidates"].append(sum(len(rem.candidates(p)) for p in rem.scope()))
        print("candidates", snap.name, flush=True)
    out["candidates"] = {str(k): {m: (sum(v) / len(v) if v else None) for m, v in d.items()} | {"n": len(d["ok"])}
                         for k, d in res_.items()}


def part_scopes(out):
    """Reflection scope verdicts for findings in imported packages with no static path."""
    from evident.pipeline import scan_snapshot
    def no_path(r):
        """Imported package, and the static analysis found no path (refuted or blocked by reflection)."""
        e4 = r["evidence"].get("L4", {})
        reason = (e4.get("detail") or {}).get("reason", "")
        return r.get("L3b_state") == "CONFIRMED" and (
            e4.get("state") == "REFUTED" or (e4.get("state") == "UNKNOWN" and reason.startswith("reflection")))
    cnt = Counter()
    per_project = {}
    for snap in sorted(RW.iterdir()):
        if not (snap / "findings.json").exists():
            continue
        rows = json.loads((snap / "findings.json").read_text("utf8"))
        need = [r for r in rows if no_path(r)]
        if need and not any((r["evidence"]["L4"].get("detail") or {}).get("scopes") for r in need):
            # recompute static evidence for snapshots analysed before scopes were recorded
            sc = scan_snapshot(ROOT / "data" / "snapshots" / snap.name, model=MODEL, code=True)
            need = [r for r in (f.to_row() for f in sc["findings"]) if no_path(r)]
        pc = Counter()
        for r in need:
            sc = (r["evidence"]["L4"].get("detail") or {}).get("scopes") or {}
            for s, v in sc.items():
                pc[f"{s}_{v}"] += 1
                cnt[f"{s}_{v}"] += 1
        per_project[snap.name] = dict(pc)
        print("scopes", snap.name, dict(pc), flush=True)
    out["scopes"] = dict(cnt)
    out["scopes_per_project"] = per_project


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--parts", default="fronts,compat,devprior,weights,candidates,scopes")
    a = ap.parse_args()
    p = RES / "posthoc_realworld.json"
    out = json.loads(p.read_text("utf8")) if p.exists() else {}
    for part in a.parts.split(","):
        globals()[f"part_{part}"](out)
        p.write_text(json.dumps(out, indent=1, default=float), "utf8")
    print("wrote", p)


if __name__ == "__main__":
    main()
