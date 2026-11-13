"""Lockfile and manifest parsing into a uniform environment model.

Supported: uv.lock, poetry.lock, Pipfile.lock, pdm.lock, pinned requirements.txt.
For each locked package we keep version, declared dependency edges (with PEP 508 markers),
and whether it is reachable from production (non-dev) roots.
"""
from __future__ import annotations

import json
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from packaging.requirements import InvalidRequirement, Requirement

from .util import norm


@dataclass
class Pkg:
    name: str
    version: str
    deps: list[tuple[str, str, str]] = field(default_factory=list)  # (name, specifier, marker)
    dev_only: bool | None = None   # from lock metadata when available
    markers: str = ""              # marker under which the lock installs it (if recorded)
    source: str = "pypi"           # pypi | git | path | url


@dataclass
class LockedEnv:
    kind: str
    packages: dict[str, Pkg]
    direct: set[str]
    direct_dev: set[str]
    edges_from_lock: bool
    requires_python: str | None = None

    @property
    def roots(self) -> set[str]:
        return (self.direct | self.direct_dev) & set(self.packages)


def _req(s: str):
    try:
        r = Requirement(s)
        return norm(r.name), str(r.specifier), str(r.marker or ""), sorted(r.extras)
    except InvalidRequirement:
        m = re.match(r"\s*([A-Za-z0-9][A-Za-z0-9._-]*)", s)
        return (norm(m.group(1)), "", "", []) if m else None


def _poetry_dep_spec(v) -> tuple[str, str]:
    if isinstance(v, str):
        return v, ""
    if isinstance(v, dict):
        return v.get("version", ""), v.get("markers", "")
    if isinstance(v, list):  # multiple constraints: take union of markers loosely
        return "", " or ".join(f"({d.get('markers')})" for d in v if isinstance(d, dict) and d.get("markers"))
    return "", ""


def manifest_direct(snapshot_dir: Path) -> tuple[set[str], set[str], str | None]:
    """Direct (prod) and direct-dev dependency names from pyproject.toml / Pipfile."""
    prod, dev, rp = set(), set(), None
    pp = snapshot_dir / "pyproject.toml"
    if pp.exists():
        try:
            t = tomllib.loads(pp.read_text("utf8"))
        except Exception:
            t = {}
        po = t.get("tool", {}).get("poetry", {})
        prod |= {norm(k) for k in po.get("dependencies", {}) if k.lower() != "python"}
        dev |= {norm(k) for k in po.get("dev-dependencies", {})}
        for g, gv in (po.get("group") or {}).items():
            tgt = prod if g == "main" else dev
            tgt |= {norm(k) for k in (gv.get("dependencies") or {})}
        pr = t.get("project", {})
        rp = pr.get("requires-python") or (po.get("dependencies", {}).get("python")
                                            if isinstance(po.get("dependencies", {}).get("python"), str) else None)
        for s in pr.get("dependencies", []) or []:
            r = _req(s)
            if r:
                prod.add(r[0])
        for _, lst in (pr.get("optional-dependencies") or {}).items():
            for s in lst:
                r = _req(s)
                if r:
                    prod.add(r[0])
        for _, lst in (t.get("dependency-groups") or {}).items():
            for s in lst:
                if isinstance(s, str):
                    r = _req(s)
                    if r:
                        dev.add(r[0])
        for s in t.get("tool", {}).get("uv", {}).get("dev-dependencies", []) or []:
            r = _req(s)
            if r:
                dev.add(r[0])
        for _, lst in (t.get("tool", {}).get("pdm", {}).get("dev-dependencies") or {}).items():
            for s in lst:
                r = _req(s)
                if r:
                    dev.add(r[0])
    pf = snapshot_dir / "Pipfile"
    if pf.exists():
        try:
            t = tomllib.loads(pf.read_text("utf8"))
            prod |= {norm(k) for k in t.get("packages", {})}
            dev |= {norm(k) for k in t.get("dev-packages", {})}
            rp = rp or (t.get("requires", {}).get("python_version"))
        except Exception:
            pass
    return prod, dev - prod, rp


def parse_lock(path: Path) -> LockedEnv:
    name = path.name
    text = path.read_text("utf8", errors="replace")
    pk: dict[str, Pkg] = {}
    edges = True
    kind = "requirements"
    if name == "uv.lock":
        kind = "uv"
        t = tomllib.loads(text)
        virtual = set()
        for p in t.get("package", []):
            src = p.get("source", {})
            n = norm(p["name"])
            if "virtual" in src or "editable" in src or ("directory" in src) or ("workspace" in src):
                virtual.add(n)
            deps = [(norm(d["name"]), "", d.get("marker", "")) for d in p.get("dependencies", [])]
            for grp in (p.get("optional-dependencies") or {}).values():
                deps += [(norm(d["name"]), "", d.get("marker", "")) for d in grp]
            devdeps = []
            for grp in (p.get("dev-dependencies") or {}).values():
                devdeps += [(norm(d["name"]), "", d.get("marker", "")) for d in grp]
            if "version" not in p:
                virtual.add(n)
            pk[n] = Pkg(n, p.get("version", "0"), deps + devdeps,
                        source="git" if "git" in src else "pypi")
            pk[n].__dict__["_devdeps"] = {d[0] for d in devdeps}
        # the project itself is virtual: its deps are the roots
        prod, dev = set(), set()
        for v in virtual:
            if v in pk:
                devd = pk[v].__dict__.get("_devdeps", set())
                for d, _, _ in pk[v].deps:
                    (dev if d in devd else prod).add(d)
                del pk[v]
        env = LockedEnv(kind, pk, prod - virtual, dev - prod - virtual, True,
                        t.get("requires-python"))
        return env
    if name == "poetry.lock":
        kind = "poetry"
        t = tomllib.loads(text)
        for p in t.get("package", []):
            n = norm(p["name"])
            deps = []
            for dn, dv in (p.get("dependencies") or {}).items():
                spec, mk = _poetry_dep_spec(dv)
                deps.append((norm(dn), spec if isinstance(spec, str) else "", mk))
            cat = p.get("category")
            groups = p.get("groups")
            dev_only = None
            if cat:
                dev_only = cat == "dev"
            elif groups:
                dev_only = "main" not in groups
            src = (p.get("source") or {}).get("type", "")
            pk[n] = Pkg(n, p["version"], deps, dev_only, p.get("markers", "") if isinstance(p.get("markers"), str) else "",
                        source="git" if src == "git" else ("path" if src in ("directory", "file") else "pypi"))
        rp = (t.get("metadata") or {}).get("python-versions")
        return LockedEnv(kind, pk, set(), set(), True, rp)
    if name == "pdm.lock":
        kind = "pdm"
        t = tomllib.loads(text)
        for p in t.get("package", []):
            n = norm(p["name"])
            deps = []
            for s in p.get("dependencies", []) or []:
                r = _req(s)
                if r:
                    deps.append((r[0], r[1], r[2]))
            groups = p.get("groups")
            pk[n] = Pkg(n, p.get("version", "0"), deps,
                        (("default" not in groups) if groups else None), p.get("marker", "") or "")
        return LockedEnv(kind, pk, set(), set(), True, (t.get("metadata") or {}).get("requires_python"))
    if name == "Pipfile.lock":
        kind = "pipfile"
        j = json.loads(text)
        for sec in ("default", "develop"):
            for n0, v in (j.get(sec) or {}).items():
                n = norm(n0)
                ver = v.get("version", "")
                if not ver.startswith("=="):
                    continue
                if n in pk:
                    if sec == "default":
                        pk[n].dev_only = False
                    continue
                pk[n] = Pkg(n, ver[2:], [], sec == "develop", v.get("markers", "") or "")
        edges = False
        rp = ((j.get("_meta") or {}).get("requires") or {}).get("python_version")
        return LockedEnv(kind, pk, set(), set(), edges, rp)
    # pinned requirements.txt
    for ln in text.splitlines():
        ln = ln.split(" #")[0].strip().rstrip("\\").strip()
        if not ln or ln.startswith(("#", "-")):
            continue
        m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*==\s*([^\s;]+)\s*(;\s*(.*))?$", ln)
        if m:
            pk[norm(m.group(1))] = Pkg(norm(m.group(1)), m.group(3), [], None, m.group(5) or "")
    return LockedEnv("requirements", pk, set(), set(), False, None)


def load_snapshot(snapshot_dir: Path, lock_file: str) -> LockedEnv:
    env = parse_lock(snapshot_dir / lock_file)
    prod, dev, rp = manifest_direct(snapshot_dir)
    if env.kind != "uv" or not env.direct:
        env.direct = (prod & set(env.packages)) or env.direct
        env.direct_dev = (dev & set(env.packages)) - env.direct
    env.requires_python = env.requires_python or rp
    return env
