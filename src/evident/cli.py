"""Command-line interface.

  evident scan PROJECT_DIR [--no-code] [--out DIR]     evidence-graded findings, SBOM + VEX
  evident plan PROJECT_DIR [--lambda 0.1]              resolver-verified remediation plan
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from collections import Counter
from pathlib import Path

from .exposure import StagedModel
from .util import DATA, write_json

DEFAULT_MODEL = DATA / "results" / "staged_model.json"


def _model(path: str | None) -> StagedModel:
    p = Path(path) if path else DEFAULT_MODEL
    if p.exists():
        return StagedModel.from_json(p.read_text("utf8"))
    print(f"[evident] model {p} not found: using uninformed defaults", file=sys.stderr)
    return StagedModel()


def cmd_scan(a) -> int:
    from .pipeline import scan_project
    from .sbom import cyclonedx
    model = _model(a.model)
    r = scan_project(Path(a.project).resolve(), model=model, code=not a.no_code)
    fnd = sorted(r["findings"], key=lambda f: -(f.p_exposed or 0) * f.severity_w)
    s = r["summary"]
    print(f"{s['installed']} installed packages ({s['direct']} direct, {s['transitive']} transitive), "
          f"target Python {r['python']}; {len(fnd)} version-matched findings")
    print("exposure classes:", dict(Counter(f.exposure_class for f in fnd)))
    print(f"{'p_exposed':>9}  {'cvss':>4}  {'package':24} {'advisory':22} class")
    for f in fnd[: a.top]:
        print(f"{(f.p_exposed or 0):9.3f}  {(f.cvss or 0):4.1f}  {f.package + '==' + f.version:24.24} "
              f"{f.advisory:22.22} {f.exposure_class}")
    out = Path(a.out)
    write_json(out / "findings.json", [f.to_row() for f in fnd])
    write_json(out / "sbom.cdx.json", cyclonedx(r["meta"]["repo"], r["graph"], fnd))
    print(f"wrote {out / 'findings.json'} and {out / 'sbom.cdx.json'} (CycloneDX 1.6 with VEX)")
    return 0


def cmd_plan(a) -> int:
    from .evidence import CONFIRMED
    from .graph import TargetEnv
    from .optimize import Remediator
    from .pipeline import scan_project
    from .resolve import compile_env
    model = _model(a.model)
    r = scan_project(Path(a.project).resolve(), model=model, code=not a.no_code)
    g = r["graph"]
    pins = {n: g.nodes[n]["version"] for n in g.nodes if n != "__app__" and g.nodes[n].get("installed")
            and g.nodes[n].get("source") in (None, "pypi")}
    live = [f for f in r["findings"] if f.state("L3") == CONFIRMED and f.package in pins]
    from .resolve import requirement_set
    today = dt.date.today().isoformat()
    reqs, sdist_only = requirement_set(pins, TargetEnv(python=r["python"]))
    prefer = {p: v for p, v in pins.items() if p not in sdist_only}

    def verify(ch):
        res = compile_env(reqs + [p for p in ch if p in sdist_only], constraints=ch, prefer=prefer,
                          python=r["python"], exclude_newer=today)
        if res.ok:
            for p in sdist_only:
                res.pins.setdefault(p, ch.get(p, pins[p]))
        return res

    rem = Remediator(pins, {n for n in pins if g.nodes[n].get("direct")}, live, TargetEnv(python=r["python"]),
                     today=today, p_of=lambda f: f.p_exposed,
                     p_new_of=lambda p: model.p_import["UNKNOWN"] * model.prior_call)
    pl = rem.plan_verified(a.lam, verify)
    print(f"plan verified by resolver: {pl.verified} (iterations: {pl.iterations})")
    for p, v in sorted(pl.changes.items()):
        print(f"  {p}: {pins[p]} -> {v}")
    extra = {p: v for p, v in pl.realised.items() if pins.get(p) != v and p not in pl.changes}
    if extra:
        print("  resolver-induced changes:", ", ".join(f"{p}->{v}" for p, v in sorted(extra.items())))
    print(f"expected residual risk {pl.residual_model:.3f}, change cost {pl.cost_model:.2f}")
    crit = rem.decision_critical(live, a.lam, lambda f: f.p_exposed)
    crit = [c for c in crit if c["critical"]]
    if crit:
        print("investigate first (uncertain findings that would change this plan):")
        for c in sorted(crit, key=lambda c: -c["evpi"])[:5]:
            print(f"  {c['package']} {c['advisory']}  p={c['p']:.2f}  EVPI={c['evpi']:.3f}")
    write_json(Path(a.out) / "plan.json", {"changes": pl.changes, "verified": pl.verified, "realised": pl.realised,
                                          "residual": pl.residual_model, "cost": pl.cost_model, "critical": crit})
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="evident", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("scan", "plan"):
        s = sub.add_parser(name)
        s.add_argument("project")
        s.add_argument("--no-code", action="store_true", help="skip source analysis (L3b/L4)")
        s.add_argument("--model", default=None)
        s.add_argument("--out", default="evident-out")
        s.add_argument("--top", type=int, default=25)
        if name == "plan":
            s.add_argument("--lambda", dest="lam", type=float, default=0.1)
    a = ap.parse_args(argv)
    return {"scan": cmd_scan, "plan": cmd_plan}[a.cmd](a)


if __name__ == "__main__":
    raise SystemExit(main())
