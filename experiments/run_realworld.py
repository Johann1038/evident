"""Real-world study over historical lockfile snapshots (RQ1, RQ3, RQ4 and the closed loop).

For each snapshot: scan (L1-L4 evidence), score exposure with the staged model trained on
EVIDENT-Bench, then compute remediation plans with every strategy, verify each plan with the uv
resolver (metadata only), and evaluate the *realised* environment (re-resolved pins, regenerated
SBOM, re-scan).
Usage: python experiments/run_realworld.py [--limit N] [--workers 3]
"""
from __future__ import annotations

import argparse
import json
import sys
import time


from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

TODAY = "2026-11-12"
LAMBDA = 0.1
OUT = ROOT / "data" / "results" / "realworld"


def evaluate(pins_new, pins_old, fidx, p_new_of, planned: dict | None):
    from evident import intel
    from evident.optimize import semver_cost
    res_f = []
    for p, v in pins_new.items():
        for a in intel.advisories_for(p, v):
            res_f.append((p, a))
    risk_ev = risk_vm = 0.0
    carried_conf = new_f = 0
    for p, a in res_f:
        w = intel.severity_weight(a)
        f = fidx.get((p, a.id))
        pe = f.p_exposed if f is not None else p_new_of(p)
        risk_ev += w * pe
        risk_vm += w
        if f is None:
            new_f += 1
        elif f.state("L4") == "CONFIRMED":
            carried_conf += 1
    changed = {p for p in set(pins_new) | set(pins_old) if pins_new.get(p) != pins_old.get(p)}
    majors = sum(1 for p in changed if p in pins_new and p in pins_old and semver_cost(pins_old[p], pins_new[p]) >= 2)
    out = {"residual_findings": len(res_f), "residual_risk_evident": risk_ev, "residual_risk_vm": risk_vm,
           "residual_confirmed": carried_conf, "new_findings": new_f, "changed": len(changed),
           "major_bumps": majors, "added": len(set(pins_new) - set(pins_old)),
           "removed": len(set(pins_old) - set(pins_new))}
    if planned is not None:
        out["planned_changes"] = len(planned)
        out["unplanned_changes"] = len(changed - set(planned))
        out["plan_not_realised"] = sum(1 for p, v in planned.items() if pins_new.get(p) != v)
    return out


def one(snap: str, model_json: str) -> dict:
    from evident import intel, pypi
    from evident.evidence import CONFIRMED
    from evident.exposure import StagedModel, p_cape_style, p_coral_style
    from evident.graph import TargetEnv
    from evident.optimize import Remediator, plan_audit_fix, plan_latest
    from evident.pipeline import scan_snapshot
    from evident.resolve import compile_env, requirement_set
    from evident.sbom import cyclonedx
    from evident.util import write_json

    t0 = time.time()
    model = StagedModel.from_json(model_json)
    sd = ROOT / "data" / "snapshots" / snap
    r = scan_snapshot(sd, model=model, code=True)
    g, fnd, meta = r["graph"], r["findings"], r["meta"]
    rec = {"id": snap, "meta": meta, "python": r["python"], "summary": r["summary"], "stats": r["stats"],
           "scan_seconds": round(time.time() - t0, 1)}
    rows = [f.to_row() for f in fnd]
    write_json(OUT / snap / "findings.json", rows)
    write_json(OUT / snap / "sbom.cdx.json", cyclonedx(meta["repo"], g, fnd))

    pins = {n: g.nodes[n]["version"] for n in g.nodes if n != "__app__" and g.nodes[n].get("installed")
            and g.nodes[n].get("source") in (None, "pypi")}
    direct = {n for n in pins if g.nodes[n].get("direct")}
    live = [f for f in fnd if f.state("L3") == CONFIRMED and f.package in pins]
    fidx = {(f.package, f.advisory): f for f in live}
    stage = {}
    for f in live:
        s = model.stage_probs(f)
        stage[f.package] = s["D"] * s["I"] * s["M"] * model.prior_call

    def p_new_of(p):
        return stage.get(p, 1.0 * model.p_import["UNKNOWN"] * model.prior_call)

    t1 = time.time()
    tenv = TargetEnv(python=r["python"])
    reqs, sdist_only = requirement_set(pins, tenv)
    prefer = {p: v for p, v in pins.items() if p not in sdist_only}
    rec["sdist_only"] = sorted(sdist_only)

    def _with_carried(res):
        if res.ok:
            for p in sdist_only:
                res.pins.setdefault(p, pins[p])
        return res

    base = _with_carried(compile_env(reqs, prefer=prefer, python=r["python"], exclude_newer=TODAY))
    rec["baseline_resolution"] = {"ok": base.ok, "seconds": round(base.seconds, 1), "error": base.error[-400:]}
    if not base.ok:
        rec["status"] = "baseline_unresolvable"
        write_json(OUT / snap / "result.json", rec)
        return rec
    rec["baseline_drift"] = sum(1 for p in set(base.pins) | set(pins) if base.pins.get(p) != pins.get(p))

    def verify(changes):
        extra = [p for p in changes if p in sdist_only]
        if any(not pypi.has_wheel(p, changes[p]) for p in extra):
            from evident.resolve import Resolution
            return Resolution(False, error="upgrade target publishes no wheel (build scripts are never executed)")
        res = _with_carried(compile_env(reqs + extra, constraints=changes, prefer=prefer, python=r["python"],
                                        exclude_newer=TODAY))
        if res.ok:
            for p in extra:
                res.pins[p] = changes[p]
        return res

    pypi.prefetch([(p, v) for p, v in pins.items()] + [(p, None) for p in {f.package for f in live}])
    strategies = {}
    # conventional strategies
    for name, planfn in (("audit_fix", plan_audit_fix), ("latest", plan_latest)):
        ch = planfn(pins, live, TODAY, r["python"])
        res = verify(ch) if ch else base
        strategies[name] = {"planned": ch, "ok": res.ok, "error": res.error[-300:], "seconds": round(res.seconds, 1),
                            **(evaluate(res.pins, pins, fidx, p_new_of, ch) if res.ok else {})}
    up = _with_carried(compile_env(reqs, python=r["python"], exclude_newer=TODAY, upgrade=True))
    strategies["upgrade_all"] = {"planned": None, "ok": up.ok, "error": up.error[-300:], "seconds": round(up.seconds, 1),
                                 **(evaluate(up.pins, pins, fidx, p_new_of, None) if up.ok else {})}
    # optimisation strategies (same optimiser, different exposure weights)
    weights = {"vm_opt": lambda f: 1.0, "coral_opt": p_coral_style, "cape_opt": p_cape_style,
               "evident": lambda f: f.p_exposed}
    rem_by = {}
    for name, pf in weights.items():
        rem = Remediator(pins, direct, live, tenv, today=TODAY, p_of=pf,
                         p_new_of=(lambda p: 1.0) if name == "vm_opt" else p_new_of)
        ts = time.time()
        pl = rem.plan_verified(LAMBDA, verify, name=name)
        strategies[name] = {"planned": pl.changes, "ok": bool(pl.verified), "iterations": pl.iterations,
                            "error": pl.error[-300:], "seconds": round(time.time() - ts, 1),
                            "model_residual": pl.residual_model, "model_cost": pl.cost_model,
                            "scope": len(rem.scope()),
                            **(evaluate(pl.realised, pins, fidx, p_new_of, pl.changes) if pl.verified else {})}
        rem_by[name] = rem
    rec["strategies"] = strategies
    rec["original"] = evaluate(pins, pins, fidx, p_new_of, None)
    # Pareto front and decision sensitivity for EVIDENT
    try:
        rec["pareto_evident"] = rem_by["evident"].pareto()
        rec["pareto_vm"] = rem_by["vm_opt"].pareto()
        crit = rem_by["evident"].decision_critical(live, LAMBDA, lambda f: f.p_exposed)
        rec["decision"] = {"uncertain": len(crit), "critical": sum(1 for c in crit if c["critical"]),
                           "evpi_total": sum(c["evpi"] for c in crit),
                           "top": sorted(crit, key=lambda c: -c["evpi"])[:5]}
    except Exception as e:  # analysis extras must not lose the main result
        rec["decision_error"] = repr(e)
    rec["remediation_seconds"] = round(time.time() - t1, 1)
    rec["status"] = "ok"
    write_json(OUT / snap / "result.json", rec)
    return rec


def _isolated(snap: str, timeout: int) -> str:
    """Run one snapshot in its own interpreter so that a crash or OOM cannot affect the others."""
    import subprocess
    try:
        r = subprocess.run([sys.executable, str(Path(__file__).resolve()), "--single", snap],
                           capture_output=True, text=True, encoding="utf8", errors="replace", timeout=timeout)
        if r.returncode != 0 or not (OUT / snap / "result.json").exists():
            (OUT / snap).mkdir(parents=True, exist_ok=True)
            (OUT / snap / "error.txt").write_text(f"exit={r.returncode}\n{r.stdout[-3000:]}\n{r.stderr[-6000:]}", "utf8")
            return f"{snap}: ERROR exit={r.returncode}"
        return r.stdout.strip().splitlines()[-1] if r.stdout.strip() else f"{snap}: ok"
    except subprocess.TimeoutExpired:
        (OUT / snap).mkdir(parents=True, exist_ok=True)
        (OUT / snap / "error.txt").write_text(f"timeout after {timeout}s", "utf8")
        return f"{snap}: TIMEOUT"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--workers", type=int, default=3)
    ap.add_argument("--only", default="")
    ap.add_argument("--force", action="store_true")
    ap.add_argument("--single", default="")
    ap.add_argument("--timeout", type=int, default=2400)
    a = ap.parse_args()
    model_json = (ROOT / "data" / "results" / "staged_model.json").read_text("utf8")
    if a.single:
        rec = one(a.single, model_json)
        print(f"{a.single}: {rec.get('status')} findings={rec.get('original', {}).get('residual_findings')} "
              f"scan={rec.get('scan_seconds')}s rem={rec.get('remediation_seconds')}s", flush=True)
        return
    from concurrent.futures import ThreadPoolExecutor
    snaps = sorted(p.name for p in (ROOT / "data" / "snapshots").iterdir() if (p / "meta.json").exists())
    if a.only:
        snaps = [s for s in snaps if s in a.only.split(",")]
    if not a.force:
        snaps = [s for s in snaps if not (OUT / s / "result.json").exists()]
    if a.limit:
        snaps = snaps[: a.limit]
    print(f"{len(snaps)} snapshots to process", flush=True)
    with ThreadPoolExecutor(a.workers) as ex:
        for line in ex.map(lambda s: _isolated(s, a.timeout), snaps):
            print(line, flush=True)
    print("ALL DONE", flush=True)


if __name__ == "__main__":
    main()
