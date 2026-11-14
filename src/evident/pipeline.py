"""End-to-end scan of one project snapshot: lock -> graph -> findings -> code evidence -> exposure."""
from __future__ import annotations

import time
from pathlib import Path

import networkx as nx

from . import intel, reach, source, symbols
from .evidence import CONFIRMED, REFUTED, UNKNOWN, Finding, exposure_class, vex_statement
from .graph import TargetEnv, build_graph, choose_python
from .lockfiles import load_snapshot
from .util import gh_api, read_json

MAX_PKGS_ANALYSED = 80


def findings_for(sid: str, g: nx.DiGraph, env, before: str | None = None) -> list[Finding]:
    out = []
    for n in g.nodes:
        if n == "__app__":
            continue
        nd = g.nodes[n]
        if nd.get("source") not in (None, "pypi"):
            continue
        for a in intel.advisories_for(n, nd["version"], before=before):
            f = Finding(snapshot=sid, package=n, version=nd["version"], advisory=a.id, ids=a.ids, cves=a.cves,
                        cvss=a.cvss, epss=intel.epss_of(a), kev=intel.in_kev(a), severity_w=intel.severity_weight(a),
                        published=a.published, fixed=a.fixed, depth=nd.get("depth"), direct=nd.get("direct", False))
            f.add("L1", CONFIRMED, source=env.kind)
            f.add("L2", CONFIRMED, ranges=len(a.ranges))
            if nd.get("installed"):
                f.add("L3", CONFIRMED, scope="prod" if nd.get("prod") else "dev", depth=nd.get("depth"))
            else:
                f.add("L3", REFUTED, reason="marker/target-environment excludes package", scope="none")
            out.append(f)
    return out


def code_evidence(findings: list[Finding], g: nx.DiGraph, app_dir: Path | None, *, mine_symbols: bool = True,
                  log=print) -> dict:
    """Attach L3b/L4 evidence. Returns statistics for the analysis."""
    stats = {"app_modules": 0, "pkgs_analysed": 0, "pkgs_no_source": 0, "seconds": 0.0}
    live = [f for f in findings if f.state("L3") == CONFIRMED]
    if app_dir is None:
        for f in live:
            f.add("L3b", UNKNOWN, reason="application source unavailable", missing=True)
            f.add("L4", UNKNOWN, reason="application source unavailable", granularity="none", missing=True)
        return stats
    t0 = time.time()
    vuln = {f.package for f in live}
    inst = nx.DiGraph(g.subgraph([n for n in g.nodes if n == "__app__" or g.nodes[n].get("installed")]))
    need: dict[str, int] = {}
    for p in vuln:
        need[p] = 0
        try:
            anc = nx.ancestors(inst, p)
        except nx.NetworkXError:
            anc = set()
        for a in anc:
            if a != "__app__":
                d = g.nodes[a].get("depth") or 9
                need[a] = min(need.get(a, 99), d)
    chosen = sorted(need, key=lambda n: (n not in vuln, need[n]))[:MAX_PKGS_ANALYSED]
    dirs = {}
    for n in chosen:
        d = source.package_source(n, g.nodes[n]["version"])
        if d is None:
            stats["pkgs_no_source"] += 1
        dirs[n] = d
    prog = reach.Program()
    for n, d in dirs.items():
        if d is not None:
            prog.add_tree(d, n)
    stats["app_modules"] = prog.add_tree(app_dir, "__app__", app=True)
    prog.build()
    an = reach.Analysis(prog)
    stats["pkgs_analysed"] = sum(1 for d in dirs.values() if d is not None)
    stats["funcs"] = len(prog.funcs)
    stats["roots"] = len(prog.roots)
    # package APIs used by application code (resolved edges only), for post-remediation API checks
    refs: dict[str, set] = {}
    for node, tgts in prog.strong.items():
        if prog.pkg_of(node) != "__app__":
            continue
        for t in tgts:
            p = prog.pkg_of(t)
            if p and p != "__app__":
                refs.setdefault(p, set()).add(t)
    stats["app_refs"] = {p: sorted(s)[:400] for p, s in refs.items()}
    stats["reflection_kinds"] = {p: sorted(k) for p, k in getattr(prog, "reflection_kinds", {}).items()}
    for f in live:
        imp = an.import_evidence(f.package) if dirs.get(f.package) is not None else UNKNOWN
        nosrc = dirs.get(f.package) is None
        f.add("L3b", imp, reason="" if imp != UNKNOWN else ("no source" if nosrc else "reflection"),
              missing=imp == UNKNOWN and nosrc)
        if imp == REFUTED:
            f.add("L4", REFUTED, reason="package not imported", granularity="import")
            continue
        adv = next((a for a in intel.load_osv().get(f.package, []) if a.id == f.advisory), None)
        mined = symbols.mine(adv) if (adv is not None and mine_symbols) else {"files": [], "status": "skipped"}
        syms, gran = symbols.symbols_for(mined, dirs.get(f.package))
        if not syms:
            f.add("L4", UNKNOWN, reason=f"no vulnerable symbols ({mined.get('status')})", granularity="none",
                  missing=True)
            continue
        r = an.symbol_evidence(f.package, syms)
        state = r.verdict
        if gran == "module" and state == "CONFIRMED":
            state = "POSSIBLE"   # module-level change: imported != vulnerable code executed
        f.add("L4", state, reason=r.reason, granularity=gran, symbols=syms[:20], witness=r.witness[:12],
              missing=state == UNKNOWN and "reflection" not in r.reason, scopes=r.scopes)
    stats["seconds"] = round(time.time() - t0, 2)
    return stats


LOCK_NAMES = ("uv.lock", "poetry.lock", "pdm.lock", "Pipfile.lock", "requirements.txt")


def scan_project(project_dir: Path, *, model=None, code: bool = True) -> dict:
    """Scan a local project directory (lockfile + source in place)."""
    lock = next((n for n in LOCK_NAMES if (project_dir / n).exists()), None)
    if lock is None:
        raise FileNotFoundError(f"no lockfile ({', '.join(LOCK_NAMES)}) in {project_dir}")
    meta = {"id": project_dir.name, "repo": project_dir.name, "tag": "local", "lock_file": lock, "subdir": ""}
    return scan_snapshot(project_dir, model=model, code=code, meta=meta, app_dir=project_dir)


def scan_snapshot(snap_dir: Path, *, model=None, code: bool = True, log=print, meta: dict | None = None,
                  app_dir: Path | None = None) -> dict:
    meta = meta or read_json(snap_dir / "meta.json")
    env = load_snapshot(snap_dir, meta["lock_file"])
    py = choose_python(env.requires_python or meta.get("requires_python"))
    tenv = TargetEnv(python=py)
    g = build_graph(env, tenv)
    fnd = findings_for(meta["id"], g, env)
    stats = {}
    if code and app_dir is not None:
        stats = code_evidence(fnd, g, app_dir, log=log)
    elif code:
        info = gh_api(f"repos/{meta['repo']}") or {}
        app_dir = None
        if (info.get("size") or 0) < 1_500_000:   # repo size incl. history (KB); archives are far smaller
            app_dir = source.app_source(meta["repo"], meta["tag"], meta["id"])
            if app_dir is not None and meta.get("subdir"):
                sub = app_dir / meta["subdir"].strip("/")
                app_dir = sub if sub.is_dir() else app_dir
        stats = code_evidence(fnd, g, app_dir, log=log)
    for f in fnd:
        f.add("L5", UNKNOWN, reason="no runtime traces collected")
        f.exposure_class = exposure_class(f)
        if model is not None:
            f.p_exposed = model.predict(f)
        f.vex = vex_statement(f)
    inst = [n for n in g.nodes if n != "__app__" and g.nodes[n].get("installed")]
    return {"meta": meta, "python": py, "env": env, "graph": g, "findings": fnd, "stats": stats,
            "summary": {"locked": len(env.packages), "installed": len(inst),
                        "direct": sum(1 for n in inst if g.nodes[n].get("direct")),
                        "transitive": sum(1 for n in inst if not g.nodes[n].get("direct")),
                        "edges": g.number_of_edges(), "edges_from_lock": env.edges_from_lock}}
