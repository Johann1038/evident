"""Shared helpers: paths, name normalisation, cached HTTP, GitHub API access."""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(os.environ.get("EVIDENT_HOME", Path(__file__).resolve().parents[2]))
DATA = ROOT / "data"
CACHE = DATA / "cache"
UA = "evident-research-client/0.1"


def norm(name: str) -> str:
    """PEP 503 normalised distribution name."""
    return re.sub(r"[-_.]+", "-", name).lower()


def sha(*parts: str) -> str:
    h = hashlib.sha256()
    for p in parts:
        h.update(p.encode("utf8"))
        h.update(b"\0")
    return h.hexdigest()[:24]


def _cache_path(url: str, kind: str) -> Path:
    return CACHE / kind / sha(url)[:2] / sha(url)


def http_get(url: str, *, kind: str = "http", binary: bool = False, ttl: float | None = None,
             headers: dict | None = None, retries: int = 4, timeout: int = 60):
    """GET with an on-disk cache. Returns bytes/str, or None on 404."""
    p = _cache_path(url, kind)
    if p.exists() and (ttl is None or time.time() - p.stat().st_mtime < ttl):
        b = p.read_bytes()
        if b == b"__404__":
            return None
        return b if binary else b.decode("utf8", "replace")
    h = {"User-Agent": UA}
    h.update(headers or {})
    last = None
    for i in range(retries):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=h), timeout=timeout) as r:
                b = r.read()
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(b)
            return b if binary else b.decode("utf8", "replace")
        except urllib.error.HTTPError as e:
            if e.code in (404, 410):
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_bytes(b"__404__")
                return None
            last = e
            time.sleep(2 ** i + (30 if e.code in (403, 429) else 0))
        except Exception as e:  # network hiccup
            last = e
            time.sleep(2 ** i)
    raise RuntimeError(f"GET failed {url}: {last}")


def http_json(url: str, **kw):
    t = http_get(url, **kw)
    return None if t is None else json.loads(t)


def gh_api(path: str, *, cache: bool = True):
    """Read-only GitHub REST call through the authenticated `gh` CLI (cached)."""
    key = "gh:" + path
    p = _cache_path(key, "gh")
    if cache and p.exists():
        t = p.read_text("utf8")
        return None if t == "__404__" else json.loads(t)
    for i in range(4):
        r = subprocess.run(["gh", "api", "-H", "Accept: application/vnd.github+json", path],
                           capture_output=True, text=True, encoding="utf8")
        if r.returncode == 0:
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(r.stdout, "utf8")
            return json.loads(r.stdout) if r.stdout.strip() else None
        err = (r.stderr or "") + (r.stdout or "")
        if "404" in err or "Not Found" in err or "422" in err or "409" in err:
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text("__404__", "utf8")
            return None
        time.sleep(5 * (i + 1) + (60 if "rate limit" in err.lower() else 0))
    return None


def write_json(path: Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=1, default=str), "utf8")


def read_json(path: Path):
    return json.loads(Path(path).read_text("utf8"))
