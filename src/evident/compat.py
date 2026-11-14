"""Execution-free API compatibility check for remediation plans.

For every package whose version a plan changes, the symbols that application code references in that package
(resolved static edges) must still resolve in the new version's source. Missing symbols indicate a likely
breaking change; their absence is necessary, not sufficient, for compatibility (behavioural changes are invisible).
"""
from __future__ import annotations

from functools import lru_cache

from .reach import Program
from .source import package_source


@lru_cache(maxsize=256)
def _program(pkg: str, version: str):
    d = package_source(pkg, version)
    if d is None:
        return None
    p = Program()
    p.add_tree(d, pkg)
    try:
        p.build()
    except RecursionError:
        return None
    return p


def missing_symbols(pkg: str, new_version: str, refs: list[str]) -> list[str] | None:
    """Referenced symbols that no longer resolve in pkg==new_version (None if source unavailable)."""
    if not refs:
        return []
    prog = _program(pkg, new_version)
    if prog is None:
        return None
    out = []
    for r in refs:
        q = r[:-9] if r.endswith(".<module>") else r
        if prog.resolve(q) is None:
            out.append(q)
    return out


def _sig(prog, q):
    r = prog.resolve(q)
    if r in prog.classes:
        r = prog.lookup_method(r, "__init__")
    return prog.sigs.get(r) if r else None


def signature_breaks(pkg: str, old: str, new: str, refs: list[str]) -> list[str] | None:
    """Referenced callables whose signature changed incompatibly between old and new (None if no source).

    Incompatible: more required positional parameters, new required keyword-only parameters, removed parameter
    names (unless the new version accepts **kwargs), or dropped *args/**kwargs.
    """
    po, pn = _program(pkg, old), _program(pkg, new)
    if po is None or pn is None:
        return None
    out = []
    for r in refs:
        so, sn = _sig(po, r), _sig(pn, r)
        if not so or not sn:
            continue
        names_o = set(so["pos"]) | set(so["kwonly"])
        names_n = set(sn["pos"]) | set(sn["kwonly"])
        if (sn["required"] > so["required"] and not so["vararg"]) or \
                (set(sn["kwonly_required"]) - set(so["kwonly_required"])) or \
                ((names_o - names_n) - {"self", "cls"} and not sn["kwarg"]) or \
                (so["vararg"] and not sn["vararg"]) or (so["kwarg"] and not sn["kwarg"]):
            out.append(r)
    return out


def plan_compatibility_levels(changes: dict[str, tuple[str, str]], app_refs: dict[str, list[str]]) -> dict:
    """Level-2 (symbol existence) and Level-2b (signature) checks for {pkg: (old, new)}."""
    used = {p: ov for p, ov in changes.items() if app_refs.get(p) and ov[0] and ov[1]}
    res = {"used_changed": len(used), "checked": 0, "unknown": 0, "missing_pkgs": 0, "signature_pkgs": 0,
           "missing_symbols": 0, "signature_breaks": 0, "examples": []}
    for p, (old, new) in used.items():
        m = missing_symbols(p, new, app_refs[p])
        s = signature_breaks(p, old, new, app_refs[p])
        if m is None or s is None:
            res["unknown"] += 1
            continue
        res["checked"] += 1
        if m:
            res["missing_pkgs"] += 1
            res["missing_symbols"] += len(m)
        if s:
            res["signature_pkgs"] += 1
            res["signature_breaks"] += len(s)
        if (m or s) and len(res["examples"]) < 6:
            res["examples"].append({"package": p, "old": old, "new": new, "missing": m[:4], "signature": s[:4]})
    res["level2_ok"] = res["missing_pkgs"] == 0 and res["unknown"] == 0
    res["level2b_ok"] = res["level2_ok"] and res["signature_pkgs"] == 0
    return res


def plan_compatibility(changes: dict[str, str], app_refs: dict[str, list[str]]) -> dict:
    """Summary over all changed packages that the application uses directly."""
    used = {p: v for p, v in changes.items() if app_refs.get(p)}
    checked, unknown, broken, missing_total, refs_total = 0, 0, [], 0, 0
    for p, v in used.items():
        m = missing_symbols(p, v, app_refs[p])
        if m is None:
            unknown += 1
            continue
        checked += 1
        refs_total += len(app_refs[p])
        if m:
            broken.append({"package": p, "version": v, "missing": m[:10], "n_missing": len(m)})
            missing_total += len(m)
    return {"used_changed": len(used), "checked": checked, "unknown": unknown, "packages_with_missing": len(broken),
            "missing_symbols": missing_total, "refs_checked": refs_total, "details": broken[:10],
            "api_compatible": len(broken) == 0 and unknown == 0}
