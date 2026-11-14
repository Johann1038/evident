"""E2: reachability comparison of EVIDENT with PyCG and Jarvis on EVIDENT-Bench applications.

For one advisory per package and every pattern, each tool analyses the same code (application, helper library,
vulnerable package). A tool predicts "exposed" if a mined vulnerable symbol is reachable in its call graph from the
application's entry module. Ground truth is the runtime label.
Tools are taken from a separate virtualenv (TOOL_PY) with the wrappers used in the feasibility pilot.
Usage: python experiments/compare_callgraphs.py --tool-py <python> --pycg <wrapper> --jarvis <wrapper> --jarvis-dir <dir>
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from collections import defaultdict, deque
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(HERE / "bench"))
from evident import intel, symbols  # noqa: E402

APPS = ROOT / "bench" / "apps"
ENVS = ROOT / "bench" / "envs"
WORK = ROOT / "data" / "work" / "cg"
RES = ROOT / "data" / "results"


def _only_py(d, names):
    """Link only Python sources (call-graph tools read nothing else); keeps hard-link count low."""
    return [n for n in names if n == "__pycache__" or (not n.endswith((".py", ".pyi")) and not os.path.isdir(os.path.join(d, n)))]


def link_tree(src: Path, dst: Path):
    if src.is_dir():
        shutil.copytree(src, dst, copy_function=shutil.copyfile, dirs_exist_ok=True, ignore=_only_py)
    elif src.exists():
        dst.parent.mkdir(parents=True, exist_ok=True)
        if not dst.exists():
            shutil.copyfile(src, dst)


def reach(cg: dict, roots: set[str]) -> set[str]:
    seen, dq = set(roots), deque(roots)
    while dq:
        u = dq.popleft()
        for v in cg.get(u, ()):
            if v not in seen:
                seen.add(v)
                dq.append(v)
    return seen


MEM_LIMIT_MB = 3072      # per tool run; exceeding it counts as a tool failure, like a time-out


def _tree_mb(p) -> float:
    import psutil
    tot = 0
    try:
        procs = [p, *p.children(recursive=True)]
    except psutil.Error:                      # process exited between poll() and here
        return 0.0
    for q in procs:
        try:
            tot += q.memory_info().private if hasattr(q.memory_info(), "private") else q.memory_info().rss
        except psutil.Error:
            pass
    return tot / 2**20


def run_tool(cmd, cwd, env, out: Path, timeout):
    import psutil
    t0 = time.time()
    log = out.with_suffix(".log")
    with open(log, "w", encoding="utf8", errors="replace") as fh:
        proc = subprocess.Popen(cmd, cwd=cwd, env=env, stdout=fh, stderr=subprocess.STDOUT)
        ps, err = psutil.Process(proc.pid), ""
        while proc.poll() is None:
            if time.time() - t0 > timeout:
                err = "timeout"
            elif _tree_mb(ps) > MEM_LIMIT_MB:
                err = f"memory > {MEM_LIMIT_MB} MB"
            if err:
                try:
                    victims = [*ps.children(recursive=True), ps]
                except psutil.Error:
                    victims = [ps]
                for q in victims:
                    try:
                        q.kill()
                    except psutil.Error:
                        pass
                proc.wait()
                break
            time.sleep(0.5)
    ok = not err and proc.returncode == 0 and out.exists()
    if not ok and not err:
        err = log.read_text("utf8", errors="replace")[-300:]
    return ok, err, time.time() - t0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tool-py", required=True)
    ap.add_argument("--pycg", required=True)
    ap.add_argument("--jarvis", required=True)
    ap.add_argument("--jarvis-dir", required=True)
    ap.add_argument("--timeout", type=int, default=180)
    a = ap.parse_args()
    rows = [json.loads(ln) for ln in (RES / "bench_records.jsonl").read_text("utf8").splitlines() if ln.strip()]
    first_adv = {}
    for r in rows:
        first_adv.setdefault(r["dist"], r["advisory"])
    sample = [r for r in rows if r["advisory"] == first_adv[r["dist"]]]
    print(f"{len(sample)} applications", flush=True)
    out_rows = []
    tops_cache, syms_cache = {}, {}
    for r in sample:
        dist, ver, aid, pat = r["dist"], r["version"], r["advisory"], r["pattern"]
        site = ENVS / f"{dist}-{ver}" / "Lib" / "site-packages"
        base = APPS / f"{dist}-{ver}" / aid.replace("/", "_") / pat
        if not base.exists():
            import re
            base = APPS / f"{dist}-{ver}" / re.sub(r"[^A-Za-z0-9_-]", "_", aid) / pat
        if dist not in tops_cache:
            from build_bench import tops_of
            tops_cache[dist] = tops_of(site, dist, ver, dist)
        if (dist, aid) not in syms_cache:
            adv = next(x for x in intel.load_osv()[dist] if x.id == aid)
            syms_cache[(dist, aid)] = symbols.symbols_for(symbols.mine(adv), site)[0]
        syms = set(syms_cache[(dist, aid)])
        root = WORK / f"{dist}-{ver}" / pat
        done = root / "result.json"
        if done.exists():                       # resumable: keep finished applications
            out_rows.append(json.loads(done.read_text("utf8")))
            continue
        if root.exists():
            shutil.rmtree(root)
        for t in tops_cache[dist]:
            link_tree(site / t, root / t)
            link_tree(site / f"{t}.py", root / f"{t}.py")
        if (base / "lib" / "benchlib").exists():
            link_tree(base / "lib" / "benchlib", root / "benchlib")
        for f in (base / "app").glob("*.py"):
            link_tree(f, root / f.name)
        entries = [str(root / f.name) for f in (base / "app").glob("*.py")]
        env = {**os.environ, "JARVIS_DIR": a.jarvis_dir, "PYTHONIOENCODING": "utf8"}
        res = {"dist": dist, "advisory": aid, "pattern": pat, "label": r["label"],
               "evident_strong": int(r["L4"] == "CONFIRMED"),
               "evident_weak": int(r["L4"] in ("CONFIRMED", "POSSIBLE")),
               "evident_unknown": int(r["L4"] == "UNKNOWN"), "evident_refuted": int(r["L4"] == "REFUTED")}
        for tool, cmd in (("pycg", [a.tool_py, a.pycg, *entries, "--package", str(root), "-o", str(root / "pycg.json")]),
                          ("jarvis", [a.tool_py, a.jarvis, "--winfix", *entries, "--package", str(root),
                                      "-o", str(root / "jarvis.json")])):
            out = root / f"{tool}.json"
            ok, err, secs = run_tool(cmd, str(root), env, out, a.timeout)
            res[f"{tool}_ok"] = int(ok)
            res[f"{tool}_seconds"] = round(secs, 2)
            res[f"{tool}_error"] = err
            pred = None
            if ok:
                cg = json.loads(out.read_text("utf8"))
                reached = reach(cg, {"main"})
                pred = int(bool(syms & reached))
            res[f"{tool}_pred"] = pred
        done.write_text(json.dumps(res), "utf8")
        out_rows.append(res)
        print(f"{dist} {pat} y={r['label']} pycg={res['pycg_pred']} jarvis={res['jarvis_pred']} "
              f"ev={res['evident_strong']}/{res['evident_weak']}", flush=True)
    (RES / "callgraph_comparison.json").write_text(json.dumps(out_rows, indent=1), "utf8")
    summary = {}
    for name, key in (("PyCG", "pycg_pred"), ("Jarvis", "jarvis_pred"), ("EVIDENT strong", "evident_strong"),
                      ("EVIDENT strong+weak", "evident_weak")):
        ok = [x for x in out_rows if x.get(key) is not None]
        tp = sum(1 for x in ok if x[key] and x["label"])
        fp = sum(1 for x in ok if x[key] and not x["label"])
        fn = sum(1 for x in ok if not x[key] and x["label"])
        fails = len(out_rows) - len(ok)
        secs = [x[f"{key.split('_')[0]}_seconds"] for x in ok
                if x.get(f"{key.split('_')[0]}_seconds") is not None] if key.endswith("pred") else []
        summary[name] = {"analysed": len(ok), "failed": fails, "precision": tp / (tp + fp) if tp + fp else None,
                         "recall": tp / (tp + fn) if tp + fn else None,
                         "missed_exposed": fn, "exposed": tp + fn,
                         "median_seconds": sorted(secs)[len(secs) // 2] if secs else None}
    # EVIDENT never claims "unreachable" for UNKNOWN; report its REFUTED-based miss rate separately
    ex = [x for x in out_rows if x["label"]]
    summary["EVIDENT strong+weak"]["refuted_exposed"] = sum(x["evident_refuted"] for x in ex)
    (RES / "callgraph_summary.json").write_text(json.dumps(summary, indent=1), "utf8")
    print(json.dumps(summary, indent=1))


if __name__ == "__main__":
    main()
