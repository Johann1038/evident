"""Fetch source code as *data* (never executed): PyPI wheels/sdists and GitHub app archives.

Only .py files are extracted, with path sanitisation (no absolute paths, no '..').
"""
from __future__ import annotations

import io
import tarfile
import zipfile
from pathlib import Path, PurePosixPath

from . import pypi
from .util import DATA, http_get, norm

SRC = DATA / "sources"
MAX_ARCHIVE = 60 * 1024 * 1024  # skip giant binary wheels (e.g. tensorflow)


def _safe(rel: str) -> str | None:
    p = PurePosixPath(rel.replace("\\", "/"))
    if p.is_absolute() or ".." in p.parts:
        return None
    return str(p)


def _extract_py(blob: bytes, filename: str, dest: Path, strip_first: bool) -> int:
    n = 0
    dest.mkdir(parents=True, exist_ok=True)
    if filename.endswith((".whl", ".zip")):
        with zipfile.ZipFile(io.BytesIO(blob)) as z:
            for info in z.infolist():
                name = info.filename
                if not name.endswith(".py") or info.file_size > 3_000_000:
                    continue
                if strip_first:
                    name = name.split("/", 1)[1] if "/" in name else name
                rel = _safe(name)
                if not rel:
                    continue
                out = dest / rel
                out.parent.mkdir(parents=True, exist_ok=True)
                out.write_bytes(z.read(info))
                n += 1
    elif filename.endswith((".tar.gz", ".tgz")):
        with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as t:
            for m in t.getmembers():
                if not m.isfile() or not m.name.endswith(".py") or m.size > 3_000_000:
                    continue
                name = m.name.split("/", 1)[1] if "/" in m.name else m.name
                if name.startswith(("src/", "lib/")):   # flatten src-layout: import roots at top level
                    name = name.split("/", 1)[1]
                rel = _safe(name)
                if not rel:
                    continue
                f = t.extractfile(m)
                if f is None:
                    continue
                out = dest / rel
                out.parent.mkdir(parents=True, exist_ok=True)
                out.write_bytes(f.read())
                n += 1
    return n


def package_source(name: str, version: str) -> Path | None:
    """Directory with the package's .py files (import roots at top level), or None."""
    name = norm(name)
    dest = SRC / "pkgs" / name / version
    marker = dest / ".done"
    if marker.exists():
        return dest if marker.read_text() != "none" else None
    f = pypi.best_file(name, version)
    if not f or (f.get("size") or 0) > MAX_ARCHIVE:
        dest.mkdir(parents=True, exist_ok=True)
        marker.write_text("none")
        return None
    try:
        blob = http_get(f["url"], kind="dist", binary=True, timeout=180)
    except RuntimeError:
        return None
    if blob is None:
        dest.mkdir(parents=True, exist_ok=True)
        marker.write_text("none")
        return None
    n = _extract_py(blob, f["filename"], dest, strip_first=f.get("packagetype") == "sdist")
    marker.write_text(str(n) if n else "none")
    return dest if n else None


def app_source(repo: str, tag: str, sid: str) -> Path | None:
    dest = SRC / "apps" / sid
    marker = dest / ".done"
    if marker.exists():
        return dest if marker.read_text() != "none" else None
    blob = None
    for ref in (f"refs/tags/{tag}", tag):
        try:
            blob = http_get(f"https://codeload.github.com/{repo}/zip/{ref}", kind="apps", binary=True,
                            timeout=300)
        except RuntimeError:
            blob = None
        if blob:
            break
    if not blob:
        dest.mkdir(parents=True, exist_ok=True)
        marker.write_text("none")
        return None
    n = _extract_py(blob, "a.zip", dest, strip_first=True)
    marker.write_text(str(n) if n else "none")
    return dest if n else None
