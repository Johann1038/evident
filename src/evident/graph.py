"""Dependency graph construction, target-environment marker evaluation and installation evidence."""
from __future__ import annotations

from dataclasses import dataclass

import networkx as nx
from packaging.markers import InvalidMarker, Marker, UndefinedComparison, UndefinedEnvironmentName
from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import InvalidSpecifier, SpecifierSet

from . import pypi
from .lockfiles import LockedEnv
from .util import norm

PY_CANDIDATES = ["3.11", "3.10", "3.9", "3.8", "3.12", "3.7"]


@dataclass
class TargetEnv:
    python: str = "3.10"
    platform: str = "linux"

    def marker_env(self) -> dict:
        full = self.python + ".12"
        return {
            "python_version": self.python, "python_full_version": full,
            "implementation_name": "cpython", "platform_python_implementation": "CPython",
            "sys_platform": self.platform, "os_name": "posix", "platform_system": "Linux",
            "platform_machine": "x86_64", "platform_release": "", "platform_version": "",
            "implementation_version": full, "extra": "",
        }


def poetry_to_pep440(spec: str) -> str:
    out = []
    for part in [p.strip() for p in spec.replace("||", "|").split("|")][:1]:
        for tok in part.replace(",", " ").split():
            if tok.startswith("^"):
                v = tok[1:].split(".")
                major = int(v[0])
                upper = f"{major + 1}.0" if major > 0 else f"0.{int(v[1]) + 1 if len(v) > 1 else 1}"
                out += [f">={tok[1:]}", f"<{upper}"]
            elif tok.startswith("~") and not tok.startswith("~="):
                v = tok[1:].split(".")
                upper = f"{v[0]}.{int(v[1]) + 1}" if len(v) > 1 else f"{int(v[0]) + 1}"
                out += [f">={tok[1:]}", f"<{upper}"]
            elif tok[0].isdigit():
                out.append(f"=={tok}")
            else:
                out.append(tok)
    return ",".join(out)


def choose_python(requires_python: str | None) -> str:
    if not requires_python:
        return "3.10"
    rp = requires_python.strip()
    try:
        ss = SpecifierSet(rp)
    except InvalidSpecifier:
        try:
            ss = SpecifierSet(poetry_to_pep440(rp))
        except InvalidSpecifier:
            return "3.10"
    for py in ["3.10", "3.11", "3.9", "3.8", "3.12", "3.7"]:
        if ss.contains(py + ".0", prereleases=True):
            return py
    return "3.10"


def marker_ok(marker: str, tenv: TargetEnv, extras_true: bool = True) -> bool:
    if not marker:
        return True
    try:
        m = Marker(marker)
    except InvalidMarker:
        return True
    env = tenv.marker_env()
    if "extra" in marker and extras_true:
        # extras are satisfied by construction for locked packages: evaluate marker ignoring 'extra'
        try:
            return any(m.evaluate({**env, "extra": e}) for e in ("", "__any__")) or _strip_extra_eval(marker, env)
        except (UndefinedComparison, UndefinedEnvironmentName):
            return True
    try:
        return m.evaluate(env)
    except (UndefinedComparison, UndefinedEnvironmentName):
        return True


def _strip_extra_eval(marker: str, env: dict) -> bool:
    import re
    s = re.sub(r"extra\s*==\s*['\"][^'\"]+['\"]", "python_version >= '0'", marker)
    try:
        return Marker(s).evaluate(env)
    except Exception:
        return True


def complete_edges(env: LockedEnv) -> None:
    """Locks without edges (Pipfile.lock, requirements.txt): derive edges from PyPI requires_dist."""
    if env.edges_from_lock:
        return
    pypi.prefetch((p.name, p.version) for p in env.packages.values())
    for p in env.packages.values():
        deps = []
        for s in pypi.requires_dist(p.name, p.version):
            try:
                r = Requirement(s)
            except InvalidRequirement:
                continue
            n = norm(r.name)
            if n in env.packages:
                deps.append((n, str(r.specifier), str(r.marker or "")))
        p.deps = deps


def build_graph(env: LockedEnv, tenv: TargetEnv) -> nx.DiGraph:
    """Nodes: '__app__' plus locked packages. Edge attr 'active' says if the marker holds in tenv."""
    complete_edges(env)
    g = nx.DiGraph()
    g.add_node("__app__", version="", kind="app")
    for p in env.packages.values():
        g.add_node(p.name, version=p.version, kind="pkg", lock_marker=p.markers, dev_only_lock=p.dev_only,
                   source=p.source)
    for p in env.packages.values():
        for d, spec, mk in p.deps:
            if d in env.packages and d != p.name:
                g.add_edge(p.name, d, spec=spec, marker=mk, active=marker_ok(mk, tenv))
    roots = env.roots
    if not roots:  # no manifest info: roots are packages without incoming edges
        roots = {n for n in env.packages if g.in_degree(n) == 0}
        prod_roots = roots
    else:
        prod_roots = env.direct & set(env.packages) or roots
    for r in roots:
        g.add_edge("__app__", r, spec="", marker="", active=True, dev=r not in prod_roots)
    annotate(g, tenv)
    return g


def annotate(g: nx.DiGraph, tenv: TargetEnv) -> None:
    active = nx.DiGraph()
    active.add_nodes_from(g.nodes)
    for u, v, d in g.edges(data=True):
        if d.get("active", True) and marker_ok(g.nodes[v].get("lock_marker", ""), tenv):
            active.add_edge(u, v)
    prod = nx.DiGraph(active)
    for u, v, d in g.edges(data=True):
        if u == "__app__" and d.get("dev") and prod.has_edge(u, v):
            prod.remove_edge(u, v)
    inst = nx.single_source_shortest_path_length(active, "__app__")
    prodr = nx.single_source_shortest_path_length(prod, "__app__")
    anyr = nx.single_source_shortest_path_length(g, "__app__")
    for n in g.nodes:
        if n == "__app__":
            continue
        nd = g.nodes[n]
        nd["installed"] = n in inst
        nd["depth"] = inst.get(n, anyr.get(n))
        nd["direct"] = g.has_edge("__app__", n)
        nd["prod"] = n in prodr
        if nd.get("dev_only_lock") is True and n not in prodr:
            nd["prod"] = False
        nd["in_lock_unreachable"] = n not in anyr


def paths_to(g: nx.DiGraph, target: str, limit: int = 3) -> list[list[str]]:
    try:
        gen = nx.all_shortest_paths(g, "__app__", target)
        out = []
        for p in gen:
            out.append(p[1:])
            if len(out) >= limit:
                break
        return out
    except (nx.NetworkXNoPath, nx.NodeNotFound):
        return []
