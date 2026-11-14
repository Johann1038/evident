"""Vulnerable-symbol mining from fix commits.

PyPI advisories almost never name the vulnerable function (measured: 2 / 14,236 OSV records; 0 GHSA
pip advisories with vulnerable_functions). We recover symbols from the fix commits that advisories
reference: for every changed .py file (tests/docs excluded) we map the *pre-fix* changed lines to
the innermost enclosing function or method of the pre-fix file.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

from .intel import Advisory
from .reach import TEST_RX

# fix commits also touch test modules inside the package directory (e.g. contrib/x/tests.py)
MINING_TEST_RX = re.compile(TEST_RX.pattern + r"|(^|/)tests?\.py$")
from .util import DATA, gh_api, http_get, read_json, write_json

SYM = DATA / "symbols"
HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


def _old_lines(patch: str) -> set[int]:
    """Old-side line numbers touched by a unified diff (deleted lines, or insertion points)."""
    out = set()
    old = 0
    for ln in patch.splitlines():
        m = HUNK.match(ln)
        if m:
            old = int(m.group(1))
            continue
        if ln.startswith("-"):
            out.add(old)
            old += 1
        elif ln.startswith("+"):
            out.add(max(old - 1, 1))
            out.add(old)
        else:
            old += 1
    return out


def _enclosing(src: str, lines: set[int]) -> tuple[set[str], bool]:
    """Qualified names (Class.method / func / outer.inner) enclosing the lines; flag module-level hits."""
    try:
        tree = ast.parse(src)
    except (SyntaxError, ValueError):
        return set(), False
    spans = []

    def walk(node, prefix):
        for ch in ast.iter_child_nodes(node):
            if isinstance(ch, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                q = f"{prefix}.{ch.name}" if prefix else ch.name
                start = min([ch.lineno] + [d.lineno for d in getattr(ch, "decorator_list", [])])
                spans.append((start, ch.end_lineno or ch.lineno, q, isinstance(ch, ast.ClassDef)))
                walk(ch, q)
    walk(tree, "")
    funcs, module_hit = set(), False
    for ln in lines:
        best = None
        for s, e, q, is_cls in spans:
            if s <= ln <= e and not is_cls and (best is None or (e - s) < (best[1] - best[0])):
                best = (s, e, q)
        if best:
            funcs.add(best[2])
        else:
            module_hit = True
    return funcs, module_hit


def _repo_sha(url: str):
    m = re.match(r"https?://github\.com/([^/]+/[^/]+)/commit/([0-9a-f]{7,40})", url)
    return (m.group(1), m.group(2)) if m else (None, None)


def mine(adv: Advisory, max_commits: int = 4) -> dict:
    """Return {'status', 'files': [{'path', 'functions', 'module_level'}], 'commits': [...]} (cached)."""
    out_p = SYM / f"{adv.package}__{adv.id}.json"
    if out_p.exists():
        return read_json(out_p)
    res = {"advisory": adv.id, "package": adv.package, "commits": [], "files": [], "status": "no_commit"}
    commits = [c for c in adv.commits if "github.com" in c][:max_commits]
    for c in commits:
        repo, sha = _repo_sha(c)
        if not repo:
            continue
        j = gh_api(f"repos/{repo}/commits/{sha}")
        if not j or "files" not in j:
            continue
        parent = (j.get("parents") or [{}])[0].get("sha")
        pyfiles = [f for f in j["files"] if f["filename"].endswith(".py") and not MINING_TEST_RX.search(f["filename"])
                   and f.get("status") in ("modified", "renamed", "removed", "changed")]
        res["commits"].append({"repo": repo, "sha": sha, "parent": parent, "py_files": len(pyfiles)})
        if len(pyfiles) > 25 or not parent:
            res["status"] = "too_broad" if len(pyfiles) > 25 else res["status"]
            continue
        for f in pyfiles:
            patch = f.get("patch")
            if not patch:
                continue
            path = f.get("previous_filename") or f["filename"]
            try:
                src = http_get(f"https://raw.githubusercontent.com/{repo}/{parent}/{path}", kind="raw")
            except RuntimeError:
                src = None
            if not src:
                continue
            funcs, mod_hit = _enclosing(src, _old_lines(patch))
            res["files"].append({"path": path, "functions": sorted(funcs), "module_level": mod_hit})
    if res["files"]:
        res["status"] = "functions" if any(f["functions"] for f in res["files"]) else "module_only"
    elif res["commits"] and res["status"] == "no_commit":
        res["status"] = "no_python_change"
    write_json(out_p, res)
    return res


def module_for_path(repo_path: str, pkg_src: Path) -> str | None:
    """Map a repository path (e.g. lib/yaml/constructor.py) to an installed module (yaml.constructor)."""
    rp = repo_path.replace("\\", "/")
    parts = rp[:-3].split("/") if rp.endswith(".py") else rp.split("/")
    for i in range(len(parts)):
        cand = parts[i:]
        rel = "/".join(cand)
        if (pkg_src / (rel + ".py")).exists():
            mod = [p for p in cand if p != "__init__"]
            return ".".join(mod) if mod else None
    return None


def symbols_for(mined: dict, pkg_src: Path | None) -> tuple[list[str], str]:
    """Fully-qualified vulnerable symbols for the installed package; (symbols, granularity)."""
    if pkg_src is None or not mined.get("files"):
        return [], "none"
    syms, mods = [], []
    for f in mined["files"]:
        mod = module_for_path(f["path"], pkg_src)
        if not mod:
            continue
        for fn in f["functions"]:
            syms.append(f"{mod}.{fn}")
        if f["module_level"] and not f["functions"]:
            mods.append(f"{mod}.<module>")
    if syms:
        return sorted(set(syms)), "function"
    if mods:
        return sorted(set(mods)), "module"
    return [], "none"
