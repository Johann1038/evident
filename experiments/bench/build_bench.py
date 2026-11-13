"""Build and run EVIDENT-Bench: labelled (application, vulnerability) pairs with runtime ground truth.

For every vulnerable package version in probes.PACKAGES:
  1. create an isolated virtualenv and install exactly that version (wheels only, no builds);
  2. mine vulnerable symbols for each advisory from its fix commits (symbols.py);
  3. trace every API probe; a probe *triggers* an advisory if it executes one of its symbols;
  4. for each triggerable advisory, generate 16 small applications (9 exposure patterns,
     7 non-exposure patterns), run each application's production entry point under the tracer
     (ground-truth label) and its test file (L5 evidence), and run EVIDENT's static analysis
     (L3b/L4 evidence).
Usage: python experiments/bench/build_bench.py [--only pyjwt,...] [--workers 4]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
import textwrap
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(HERE))
from evident import intel, reach, symbols  # noqa: E402
from evident.resolve import UV  # noqa: E402
from evident.runtime import hits, run_traced  # noqa: E402
from probes import PACKAGES  # noqa: E402

ENVS = ROOT / "bench" / "envs"
APPS = ROOT / "bench" / "apps"
OUT = ROOT / "data" / "results"
PY = sys.executable


def sh(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def make_env(dist, ver) -> tuple[Path, Path] | None:
    env = ENVS / f"{dist}-{ver}"
    py = env / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
    ok = env / ".ok"
    if not ok.exists():
        if env.exists():
            shutil.rmtree(env)
        r = sh([UV, "venv", str(env), "--python", sys.executable, "--quiet"])
        if r.returncode:
            print("venv failed", dist, r.stderr[-300:])
            return None
        r = sh([UV, "pip", "install", "--python", str(py), f"{dist}=={ver}", "--only-binary", ":all:", "--quiet",
                "--exclude-newer", "2026-11-12"])
        if r.returncode:
            print("install failed", dist, ver, r.stderr[-400:])
            return None
        ok.write_text("ok")
    site = env / ("Lib/site-packages" if sys.platform == "win32" else f"lib/python{sys.version_info.major}.{sys.version_info.minor}/site-packages")
    return py, site


def tops_of(site: Path, dist: str, ver: str, fallback: str) -> set[str]:
    for d in site.glob("*.dist-info"):
        name = d.name[: -len(".dist-info")].rsplit("-", 1)[0]
        if re.sub(r"[-_.]+", "-", name).lower() == dist:
            tl = d / "top_level.txt"
            if tl.exists():
                t = {x.strip() for x in tl.read_text().splitlines() if x.strip() and not x.startswith("_")}
                if t:
                    return t
            rec = d / "RECORD"
            if rec.exists():
                t = set()
                for ln in rec.read_text("utf8").splitlines():
                    p = ln.split(",")[0]
                    if p.endswith(".py") and ".dist-info" not in p and not p.startswith(".."):
                        t.add(p.split("/")[0].removesuffix(".py"))
                t = {x for x in t if not x.startswith("_")}
                if t:
                    return t
    return {fallback}


def body(lines, alias, indent=4):
    txt = "\n".join(re.sub(r"\bM\.", alias + ".", ln) for ln in lines)
    return textwrap.indent(txt, " " * indent)


def header(pkg, alias):
    top = pkg["top"]
    lines = [f"import {top}" if alias == top else f"import {top} as {alias}"]
    lines += [f"import {s}" for s in pkg["imports"]]
    return "\n".join(lines) + "\n"


FOOT = "\n\ndef main():\n    return run()\n\n\nif __name__ == '__main__':\n    main()\n"


def gen_app(pkg, pattern, trig, safe) -> dict[str, str] | None:
    """Return {relative_path: source} for the application (app/...) and helper library (lib/...)."""
    t = pkg["top"]
    H = header(pkg, t)
    f = {}
    if pattern == "E1_direct":
        f["app/main.py"] = H + "\n\ndef run():\n" + body(trig, t) + FOOT
    elif pattern == "E2_wrapper":
        f["app/helpers.py"] = H + "\n\ndef do_work():\n" + body(trig, t) + "\n"
        f["app/main.py"] = "import helpers\n\n\ndef run():\n    return helpers.do_work()\n" + FOOT
    elif pattern == "E3_alias":
        f["app/main.py"] = header(pkg, "zz_lib") + "\n\ndef run():\n" + body(trig, "zz_lib") + FOOT
    elif pattern == "E4_dict_dispatch":
        f["app/main.py"] = H + "\n\ndef _handler():\n" + body(trig, t) + \
            "\n\n\nHANDLERS = {'k': _handler, 'noop': str}\n\n\ndef run(kind='k'):\n    return HANDLERS[kind]()\n" + FOOT
    elif pattern == "E5_getattr_computed":
        f["app/helpers.py"] = H + "\n\ndef impl_fast():\n" + body(trig, t) + "\n"
        f["app/main.py"] = "import helpers\n\n\ndef run(kind='fast'):\n    return getattr(helpers, 'impl_' + kind)()\n" + FOOT
    elif pattern == "E6_class_method":
        f["app/main.py"] = H + "\n\nclass Service:\n    def go(self):\n" + body(trig, t, 8) + \
            "\n\n\ndef run():\n    return Service().go()\n" + FOOT
    elif pattern == "E7_callback":
        f["app/main.py"] = H + "\n\ndef _handler():\n" + body(trig, t) + \
            "\n\n\ndef apply(fn):\n    return fn()\n\n\ndef run():\n    return apply(_handler)\n" + FOOT
    elif pattern == "E8_decorator_registry":
        f["app/main.py"] = H + "\n\nREG = {}\n\n\ndef route(name):\n    def deco(fn):\n        REG[name] = fn\n" \
            "        return fn\n    return deco\n\n\n@route('x')\ndef handler():\n" + body(trig, t) + \
            "\n\n\ndef run():\n    return REG['x']()\n" + FOOT
    elif pattern == "E9_transitive":
        f["lib/benchlib/__init__.py"] = H + "\n\ndef do():\n" + body(trig, t) + "\n"
        f["app/main.py"] = "import benchlib\n\n\ndef run():\n    return benchlib.do()\n" + FOOT
    elif pattern == "N1_dead_code":
        f["app/main.py"] = H + "\n\ndef _unused():\n" + body(trig, t) + "\n\n\ndef run():\n    return None\n" + FOOT
    elif pattern == "N2_safe_api":
        if not safe:
            return None
        f["app/main.py"] = H + "\n\ndef run():\n" + body(safe, t) + FOOT
    elif pattern == "N3_import_only":
        f["app/main.py"] = H + "\n\ndef run():\n    return None\n" + FOOT
    elif pattern == "N4_not_imported":
        f["app/main.py"] = "\n\ndef run():\n    return sum(range(3))\n" + FOOT
    elif pattern == "N5_guarded_branch":
        f["app/main.py"] = "import os\n" + H + "\n\ndef _handler():\n" + body(trig, t) + \
            "\n\n\ndef run():\n    if os.environ.get('EVIDENT_NEVER_SET') == '1':\n        return _handler()\n    return None\n" + FOOT
    elif pattern == "N6_test_only":
        f["app/main.py"] = "\n\ndef run():\n    return None\n" + FOOT
        f["app/tests/__init__.py"] = ""
        f["app/tests/test_main.py"] = H + "\n\ndef test_vuln():\n" + body(trig, t) + "\n"
    elif pattern == "N7_transitive_safe":
        if not safe:
            return None
        f["lib/benchlib/__init__.py"] = H + "\n\ndef do_safe():\n" + body(safe, t) + "\n"
        f["app/main.py"] = "import benchlib\n\n\ndef run():\n    return benchlib.do_safe()\n" + FOOT
    return f


PATTERNS = ["E1_direct", "E2_wrapper", "E3_alias", "E4_dict_dispatch", "E5_getattr_computed", "E6_class_method",
            "E7_callback", "E8_decorator_registry", "E9_transitive", "N1_dead_code", "N2_safe_api",
            "N3_import_only", "N4_not_imported", "N5_guarded_branch", "N6_test_only", "N7_transitive_safe"]


REUSE = False


def static_row(pkg, a, aid, pat, syms, gran, trig, safe, prod, test, site, tops, base) -> dict:
    """Ground truth from the production trace, L5 from the test trace, L3b/L4 from static analysis."""
    dist, ver = pkg["dist"], pkg["version"]
    app_dir, lib_dir = base / "app", base / "lib"
    label = 1 if hits(prod["executed"], syms) else 0
    l5 = "OBSERVED" if hits(test["executed"], syms) else "NOT_OBSERVED"
    prog = reach.Program()
    prog.add_tree(site, dist, only_tops=tops)
    if (lib_dir / "benchlib").exists():
        prog.add_tree(lib_dir, "benchlib")
    prog.add_tree(app_dir, "__app__", app=True)
    prog.build()
    an = reach.Analysis(prog)
    l3b = an.import_evidence(dist)
    if l3b == "REFUTED":
        l4, reason, wit = "REFUTED", "package not imported", []
    else:
        rr = an.symbol_evidence(dist, syms)
        l4, reason, wit = rr.verdict, rr.reason, rr.witness
    return {
        "dist": dist, "version": ver, "advisory": aid, "cves": a.cves, "cvss": a.cvss,
        "epss": intel.epss_of(a), "kev": intel.in_kev(a), "pattern": pat, "label": label,
        "label_imported": int(any(e.split(".")[0] in tops for e in prod["executed"])),
        "L3b": l3b, "L4": l4, "L4_reason": reason, "L5": l5, "granularity": gran,
        "n_symbols": len(syms), "trigger_probe": trig[0], "safe_probe": safe[0] if safe else None,
        "prod_error": prod.get("error"), "witness": wit[:8],
    }


def covered(key: str) -> bool:
    return int(hashlib.sha256(key.encode()).hexdigest(), 16) % 2 == 0


def run_package(pkg) -> list[dict]:
    dist, ver = pkg["dist"], pkg["version"]
    r = make_env(dist, ver)
    if not r:
        return []
    py, site = r
    tops = tops_of(site, dist, ver, pkg["top"])
    advs = intel.advisories_for(dist, ver)
    pdir = APPS / f"{dist}-{ver}" / "_probes"
    pdir.mkdir(parents=True, exist_ok=True)
    # 1) symbols per advisory
    advsyms = {}
    for a in advs:
        mined = symbols.mine(a)
        syms, gran = symbols.symbols_for(mined, site)
        advsyms[a.id] = (a, syms, gran, mined.get("status"))
    # 2) probe tracing
    probe_exec = {}
    for name, lines in pkg["probes"].items():
        (pdir / f"probe_{name}.py").write_text(header(pkg, pkg["top"]) + "\n\ndef run():\n" + body(lines, pkg["top"]) + "\n", "utf8")
        tr = run_traced(str(py), f"probe_{name}:run", tops, [str(pdir)], pdir / f"w_{name}")
        probe_exec[name] = tr
    rows = []
    summary = {"dist": dist, "version": ver, "advisories": len(advs), "tops": sorted(tops),
               "probe_errors": {k: v.get("error") for k, v in probe_exec.items() if v.get("error")},
               "advisory_symbols": {k: {"gran": v[2], "n": len(v[1]), "status": v[3]} for k, v in advsyms.items()}}
    for aid, (a, syms, gran, status) in advsyms.items():
        if gran != "function":
            continue
        trig = [n for n, tr in probe_exec.items() if hits(tr["executed"], syms)]
        safe = [n for n, tr in probe_exec.items() if tr["executed"] and not hits(tr["executed"], syms)]
        summary.setdefault("triggerable", {})[aid] = {"trigger": trig, "safe": safe}
        if not trig:
            continue
        T = pkg["probes"][trig[0]]
        S = pkg["probes"][safe[0]] if safe else None
        for pat in PATTERNS:
            files = gen_app(pkg, pat, T, S)
            if files is None:
                continue
            base = APPS / f"{dist}-{ver}" / re.sub(r"[^A-Za-z0-9_-]", "_", aid) / pat
            if REUSE and (base / "w_prod" / "_trace.json").exists() and (base / "w_test" / "_trace.json").exists():
                prod = json.loads((base / "w_prod" / "_trace.json").read_text("utf8"))
                test = json.loads((base / "w_test" / "_trace.json").read_text("utf8"))
                rows.append(static_row(pkg, a, aid, pat, syms, gran, trig, safe, prod, test, site, tops, base))
                continue
            if base.exists():
                shutil.rmtree(base)
            for rel, src in files.items():
                p = base / rel
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(src, "utf8")
            app_dir, lib_dir = base / "app", base / "lib"
            lib_dir.mkdir(exist_ok=True)
            tests = app_dir / "tests"
            key = f"{dist}{ver}{aid}{pat}"
            if pat != "N6_test_only":
                tests.mkdir(exist_ok=True)
                (tests / "__init__.py").write_text("", "utf8")
                cov = covered(key)
                (tests / "test_main.py").write_text(
                    ("import main\n\n\ndef test_run():\n    main.run()\n" if cov else
                     "import main\n\n\ndef test_import():\n    assert main\n"), "utf8")
                tfn = "test_run" if cov else "test_import"
            else:
                tfn = "test_vuln"
            prod = run_traced(str(py), str(app_dir / "main.py"), tops, [str(app_dir), str(lib_dir)], base / "w_prod")
            test = run_traced(str(py), f"tests.test_main:{tfn}", tops, [str(app_dir), str(lib_dir)], base / "w_test")
            rows.append(static_row(pkg, a, aid, pat, syms, gran, trig, safe, prod, test, site, tops, base))
    (OUT / "bench_summaries").mkdir(parents=True, exist_ok=True)
    (OUT / "bench_summaries" / f"{dist}-{ver}.json").write_text(json.dumps(summary, indent=1, default=str), "utf8")
    print(f"{dist}=={ver}: {len(advs)} advisories, {len(summary.get('triggerable', {}))} function-level, "
          f"{len({r['advisory'] for r in rows})} triggerable, {len(rows)} apps", flush=True)
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", default="")
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--reuse", action="store_true", help="reuse recorded traces; recompute static evidence only")
    a = ap.parse_args()
    global REUSE
    REUSE = a.reuse
    pk = [p for p in PACKAGES if not a.only or p["dist"] in a.only.split(",")]
    OUT.mkdir(parents=True, exist_ok=True)
    with ThreadPoolExecutor(a.workers) as ex:
        res = list(ex.map(run_package, pk))
    rows = [r for rs in res for r in rs]
    out = OUT / ("bench_records.jsonl" if not a.only else f"bench_records_{a.only.replace(',', '_')}.jsonl")
    with out.open("w", encoding="utf8") as fh:
        for r in rows:
            fh.write(json.dumps(r, default=str) + "\n")
    print(f"wrote {len(rows)} rows to {out}")


if __name__ == "__main__":
    main()
