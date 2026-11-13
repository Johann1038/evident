"""Vulnerability intelligence: OSV (PyPI) advisories, CVSS, EPSS and CISA KEV.

All sources are loaded from dated local snapshots so that every result is reproducible.
Advisories that describe the same vulnerability (GHSA / PYSEC / CVE aliases) are merged
into one *cluster* so that a vulnerability is never counted twice.
"""
from __future__ import annotations

import csv
import gzip
import io
import json
import zipfile
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

from packaging.version import InvalidVersion, Version

from .util import DATA, norm

INTEL = DATA / "intel"


def _v(s: str):
    try:
        return Version(s)
    except InvalidVersion:
        return None


@dataclass
class Range:
    introduced: list[str] = field(default_factory=list)
    fixed: list[str] = field(default_factory=list)
    last_affected: list[str] = field(default_factory=list)
    events: list[dict] = field(default_factory=list)


@dataclass
class Advisory:
    id: str                    # cluster id (preferred: CVE, else GHSA, else PYSEC)
    ids: list[str]             # all OSV ids in the cluster
    cves: list[str]
    package: str               # normalised PyPI name
    published: str
    summary: str
    cvss: float | None         # base score (max across vectors)
    cvss_vector: str | None
    ranges: list[list[dict]]   # list of ECOSYSTEM event lists
    versions: set[str]         # explicit affected versions
    fixed: list[str]           # all fixed versions mentioned
    commits: list[str]         # fix-commit URLs (github)
    repos: list[str]           # repository URLs mentioned
    platforms: list[str] = field(default_factory=list)

    def affects(self, version: str) -> bool:
        if version in self.versions:
            return True
        v = _v(version)
        if v is None:
            return False
        for events in self.ranges:
            if _in_events(v, events):
                return True
        return False

    def fixed_versions(self) -> list[Version]:
        out = [x for x in (_v(f) for f in self.fixed) if x is not None]
        return sorted(set(out))


def _in_events(v: Version, events: list[dict]) -> bool:
    """OSV ECOSYSTEM range semantics (sorted event walk)."""
    pts = []
    for e in events:
        for k in ("introduced", "fixed", "last_affected", "limit"):
            if k in e:
                ver = Version("0") if e[k] == "0" else _v(e[k])
                if ver is not None:
                    pts.append((ver, k))
    pts.sort(key=lambda t: (t[0], 0 if t[1] == "fixed" else 1))
    affected = False
    for ver, k in pts:
        if k == "introduced":
            if v >= ver:
                affected = True
            else:
                break
        elif k == "fixed":
            if v >= ver:
                affected = False
            else:
                break
        elif k == "last_affected":
            if v > ver:
                affected = False
            else:
                break
        elif k == "limit":
            if v >= ver:
                affected = False
                break
    return affected


def _cvss_score(vector: str) -> float | None:
    try:
        if vector.startswith("CVSS:4"):
            from cvss import CVSS4
            return float(CVSS4(vector).base_score)
        if vector.startswith("CVSS:3"):
            from cvss import CVSS3
            return float(CVSS3(vector).scores()[0])
        from cvss import CVSS2
        return float(CVSS2(vector).scores()[0])
    except Exception:
        return None


class _UF:
    def __init__(self):
        self.p = {}

    def f(self, x):
        self.p.setdefault(x, x)
        while self.p[x] != x:
            self.p[x] = self.p[self.p[x]]
            x = self.p[x]
        return x

    def u(self, a, b):
        self.p[self.f(a)] = self.f(b)


@lru_cache(maxsize=1)
def load_osv(path: str | None = None) -> dict[str, list[Advisory]]:
    """Return {package: [Advisory clusters]} from the OSV PyPI dump (MAL-* and withdrawn excluded)."""
    import pickle
    zpath = Path(path) if path else INTEL / "osv_pypi_all.zip"
    cache = zpath.with_suffix(".index.pkl")
    if cache.exists() and cache.stat().st_mtime >= zpath.stat().st_mtime:
        return pickle.loads(cache.read_bytes())
    recs = []
    with zipfile.ZipFile(io.BytesIO(zpath.read_bytes())) as z:   # one sequential read, then in-memory
        for n in z.namelist():
            if not n.endswith(".json"):
                continue
            r = json.loads(z.read(n))
            if r.get("withdrawn") or r["id"].startswith("MAL-"):
                continue
            recs.append(r)
    uf = _UF()
    for r in recs:
        for a in r.get("aliases", []) or []:
            uf.u(r["id"], a)
        uf.f(r["id"])
    groups: dict[tuple[str, str], list[dict]] = {}
    for r in recs:
        root = uf.f(r["id"])
        for aff in r.get("affected", []):
            pkg = aff.get("package", {})
            if pkg.get("ecosystem") != "PyPI":
                continue
            groups.setdefault((root, norm(pkg["name"])), []).append((r, aff))
    out: dict[str, list[Advisory]] = {}
    for (root, pkg), items in groups.items():
        ids, cves, ranges, versions, fixed, commits, repos = set(), set(), [], set(), set(), set(), set()
        published, summary, best, bestvec = None, "", None, None
        for r, aff in items:
            ids.add(r["id"])
            for a in [r["id"]] + (r.get("aliases") or []):
                if a.startswith("CVE-"):
                    cves.add(a)
            p = r.get("published") or r.get("modified") or ""
            if p and (published is None or p < published):
                published = p
            summary = summary or r.get("summary") or (r.get("details") or "")[:200]
            for s in (r.get("severity") or []) + (aff.get("severity") or []):
                sc = _cvss_score(s.get("score", ""))
                if sc is not None and (best is None or sc > best):
                    best, bestvec = sc, s["score"]
            versions |= set(aff.get("versions") or [])
            for rg in aff.get("ranges", []):
                if rg.get("type") == "ECOSYSTEM":
                    ranges.append(rg.get("events", []))
                    fixed |= {e["fixed"] for e in rg.get("events", []) if "fixed" in e}
                elif rg.get("type") == "GIT":
                    for e in rg.get("events", []):
                        if "fixed" in e and "github.com" in rg.get("repo", ""):
                            commits.add(rg["repo"].rstrip("/").removesuffix(".git") + "/commit/" + e["fixed"])
                    repos.add(rg.get("repo", ""))
            for ref in r.get("references", []) or []:
                u = ref.get("url", "")
                if "github.com" in u and "/commit/" in u:
                    commits.add(u.split("#")[0].split("?")[0])
                if ref.get("type") in ("PACKAGE", "WEB") and "github.com" in u:
                    repos.add(u)
        cid = sorted(cves)[0] if cves else sorted(ids, key=lambda i: (not i.startswith("GHSA"), i))[0]
        out.setdefault(pkg, []).append(Advisory(
            id=cid, ids=sorted(ids), cves=sorted(cves), package=pkg, published=published or "",
            summary=summary, cvss=best, cvss_vector=bestvec, ranges=ranges, versions=versions,
            fixed=sorted(fixed), commits=sorted(c for c in commits if c), repos=sorted(r for r in repos if r)))
    try:
        cache.write_bytes(pickle.dumps(out, protocol=pickle.HIGHEST_PROTOCOL))
    except OSError:
        pass
    return out


def advisories_for(pkg: str, version: str, before: str | None = None) -> list[Advisory]:
    """Advisories affecting pkg==version (optionally only those published before a date)."""
    res = []
    for a in load_osv().get(norm(pkg), []):
        if before and a.published and a.published[:10] > before:
            continue
        if a.affects(version):
            res.append(a)
    return res


@lru_cache(maxsize=1)
def load_epss() -> dict[str, tuple[float, float]]:
    p = INTEL / "epss_scores-current.csv.gz"
    out = {}
    if not p.exists():
        return out
    with gzip.open(p, "rt") as f:
        lines = [ln for ln in f if not ln.startswith("#")]
    for row in csv.DictReader(io.StringIO("".join(lines))):
        out[row["cve"]] = (float(row["epss"]), float(row["percentile"]))
    return out


@lru_cache(maxsize=1)
def load_kev() -> set[str]:
    p = INTEL / "kev.json"
    if not p.exists():
        return set()
    return {v["cveID"] for v in json.loads(p.read_text("utf8")).get("vulnerabilities", [])}


def epss_of(adv: Advisory) -> float:
    e = load_epss()
    return max((e.get(c, (0.0, 0.0))[0] for c in adv.cves), default=0.0)


def in_kev(adv: Advisory) -> bool:
    k = load_kev()
    return any(c in k for c in adv.cves)


def severity_weight(adv: Advisory) -> float:
    """Impact weight used by the optimiser: CVSS/10 (default 0.5 when unknown), x2 if in KEV."""
    base = (adv.cvss if adv.cvss is not None else 5.0) / 10.0
    return base * (2.0 if in_kev(adv) else 1.0)
