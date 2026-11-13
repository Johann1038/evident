"""Risk/cost fronts evaluated under a common yardstick.

For every resolvable snapshot, plans are computed for a sweep of lambda with (a) calibrated EVIDENT weights and
(b) version-match weights; *both* sets of plans are then scored by the same expected-exposure measure (EVIDENT's
calibrated probabilities) and by version-matched risk. Reads saved findings/SBOMs; uses cached PyPI metadata.
Usage: python experiments/pareto_posthoc.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from evident.evidence import Evidence, Finding  # noqa: E402
from evident.exposure import StagedModel  # noqa: E402
from evident.graph import TargetEnv  # noqa: E402
from evident.optimize import Remediator  # noqa: E402

TODAY = "2026-11-12"
LAMS = (0.0, 0.02, 0.05, 0.1, 0.2, 0.5, 1.0, 2.0, 5.0, 100.0)
RW = ROOT / "data" / "results" / "realworld"


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
    return res, pins, direct, fnd


def main():
    model = StagedModel.from_json((ROOT / "data" / "results" / "staged_model.json").read_text("utf8"))
    out = {}
    for snap in sorted(RW.iterdir()):
        if not (snap / "result.json").exists():
            continue
        res, pins, direct, fnd = load(snap)
        if res.get("status") != "ok" or not fnd:
            continue
        tenv = TargetEnv(python=res["python"])
        stage = {}
        for f in fnd:
            s = model.stage_probs(f)
            stage[f.package] = s["D"] * s["I"] * s["M"] * model.prior_call

        def p_new(p):
            return stage.get(p, model.p_import_marg * model.prior_call)
        ev = Remediator(pins, direct, fnd, tenv, today=TODAY, p_of=lambda f: f.p_exposed, p_new_of=p_new)
        vm = Remediator(pins, direct, fnd, tenv, today=TODAY, p_of=lambda f: 1.0, p_new_of=lambda p: 1.0)
        pk = sorted({f.package for f in fnd})

        def score(plan):
            chosen = {p: plan.changes.get(p, pins[p]) for p in set(pk) | set(plan.changes)}
            return (sum(ev._risk(p, v) for p, v in chosen.items()), sum(vm._risk(p, v) for p, v in chosen.items()),
                    len(plan.changes))
        r0 = score(type("P", (), {"changes": {}})())
        pts = {"evident": [], "vm": []}
        for name, rem in (("evident", ev), ("vm", vm)):
            for lam in LAMS:
                pl = rem.solve(lam, time_limit=10.0)
                if pl is not None:
                    e, v, c = score(pl)
                    pts[name].append({"lambda": lam, "exposure": e, "vm_risk": v, "changes": c})
        out[snap.name] = {"r0_exposure": r0[0], "r0_vm": r0[1], "fronts": pts}
        print(snap.name, len(pts["evident"]), len(pts["vm"]), flush=True)
    (ROOT / "data" / "results" / "pareto_common.json").write_text(json.dumps(out, indent=1), "utf8")


if __name__ == "__main__":
    main()
