"""Runtime evidence (L5): record which functions of selected packages execute.

`tracer_source()` returns a self-contained runner script that is executed by the *target*
interpreter (e.g. a benchmark virtualenv). It uses sys.setprofile and records
(module, co_qualname) for frames whose module belongs to the watched top-level packages.
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

RUNNER = r'''
import json, os, runpy, sys
out_path, watch, entry = sys.argv[1], set(sys.argv[2].split(",")), sys.argv[3]
paths = sys.argv[4:]
for p in reversed(paths):
    sys.path.insert(0, p)
seen = set()
def prof(frame, event, arg):
    if event == "call":
        g = frame.f_globals.get("__name__", "") or ""
        if g.split(".")[0] in watch:
            q = getattr(frame.f_code, "co_qualname", frame.f_code.co_name).replace(".<locals>", "")
            seen.add(g + "." + q)
    return None
err = None
sys.setprofile(prof)
try:
    if entry.endswith(".py"):
        runpy.run_path(entry, run_name="__main__")
    else:
        mod, _, fn = entry.partition(":")
        m = __import__(mod, fromlist=["x"])
        for name in fn.split(","):
            try:
                getattr(m, name)()
            except Exception as e:
                err = f"{name}: {type(e).__name__}: {e}"
except SystemExit:
    pass
except BaseException as e:
    err = f"{type(e).__name__}: {e}"
finally:
    sys.setprofile(None)
json.dump({"executed": sorted(seen), "error": err}, open(out_path, "w"))
'''


def run_traced(python: str, entry: str, watch: set[str], paths: list[str], workdir: Path,
               timeout: int = 120) -> dict:
    workdir.mkdir(parents=True, exist_ok=True)
    runner = workdir / "_evident_runner.py"
    runner.write_text(RUNNER, "utf8")
    out = workdir / "_trace.json"
    if out.exists():
        out.unlink()
    env = {"PYTHONDONTWRITEBYTECODE": "1", "PYTHONHASHSEED": "0", "SYSTEMROOT": __import__("os").environ.get("SYSTEMROOT", ""),
           "PATH": __import__("os").environ.get("PATH", "")}
    try:
        r = subprocess.run([python, "-I", str(runner), str(out), ",".join(sorted(watch)), entry, *paths],
                           cwd=str(workdir), capture_output=True, text=True, timeout=timeout, env=env)
    except subprocess.TimeoutExpired:
        return {"executed": [], "error": "timeout"}
    if not out.exists():
        return {"executed": [], "error": (r.stderr or "")[-800:]}
    return json.loads(out.read_text("utf8"))


def hits(executed: list[str], symbols: list[str]) -> list[str]:
    s = set(executed)
    return [x for x in symbols if x in s]
