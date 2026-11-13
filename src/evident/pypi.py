"""PyPI metadata (JSON API) with caching: releases, upload dates, requires_dist, wheel files."""
from __future__ import annotations

from functools import lru_cache

from packaging.version import InvalidVersion, Version

from .util import http_json, norm


@lru_cache(maxsize=20000)
def project(name: str):
    return http_json(f"https://pypi.org/pypi/{norm(name)}/json", kind="pypi")


@lru_cache(maxsize=50000)
def release(name: str, version: str):
    return http_json(f"https://pypi.org/pypi/{norm(name)}/{version}/json", kind="pypi")


def prefetch(pairs, workers: int = 16) -> None:
    """Warm the cache concurrently for [(name, version|None)] (I/O bound: threads)."""
    from concurrent.futures import ThreadPoolExecutor

    def one(pv):
        try:
            return release(*pv) if pv[1] else project(pv[0])
        except Exception:
            return None
    with ThreadPoolExecutor(workers) as ex:
        list(ex.map(one, list(pairs)))


def releases(name: str, *, before: str | None = None, include_pre: bool = False) -> list[tuple[Version, str]]:
    """Sorted [(Version, first_upload_iso)] of non-yanked releases that have files."""
    j = project(name)
    if not j:
        return []
    out = []
    for v, files in (j.get("releases") or {}).items():
        if not files or all(f.get("yanked") for f in files):
            continue
        try:
            V = Version(v)
        except InvalidVersion:
            continue
        if V.is_prerelease and not include_pre:
            continue
        up = min((f.get("upload_time_iso_8601") or f.get("upload_time") or "") for f in files)
        if before and up and up[:10] > before:
            continue
        out.append((V, up))
    out.sort()
    return out


def requires_dist(name: str, version: str) -> list[str]:
    j = release(name, version)
    if not j:
        return []
    return list((j.get("info") or {}).get("requires_dist") or [])


def has_wheel(name: str, version: str) -> bool:
    j = release(name, version)
    return bool(j) and any(f.get("packagetype") == "bdist_wheel" for f in j.get("urls", []))


def best_file(name: str, version: str, py: str = "310"):
    """Pick a downloadable file whose *source* we can read: pure wheel > cpXY linux wheel > sdist."""
    j = release(name, version)
    if not j:
        return None
    files = j.get("urls", [])

    def rank(f):
        fn = f["filename"]
        if f.get("packagetype") == "bdist_wheel":
            if fn.endswith("-none-any.whl"):
                return 0
            if f"cp{py}" in fn and "manylinux" in fn and "x86_64" in fn:
                return 1
            if "manylinux" in fn and "x86_64" in fn:
                return 2
            return 3
        if f.get("packagetype") == "sdist":
            return 4
        return 9
    files = sorted(files, key=rank)
    return files[0] if files and rank(files[0]) < 9 else None
