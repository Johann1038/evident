"""uv as the resolution oracle (metadata-only: --no-build, nothing is executed).

`verify` re-resolves an environment while *preferring* the original pins, so the only changes are
those the plan forces plus whatever the resolver needs to restore consistency (the realised drift).
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from .util import norm

UV = shutil.which("uv") or str(Path(sys.executable).parent / ("uv.exe" if os.name == "nt" else "uv"))


def requirement_set(pins: dict[str, str], tenv) -> tuple[list[str], set[str]]:
    """Requirements for metadata-only re-resolution.

    Packages that publish no wheel for their pinned version cannot be resolved without running their
    build scripts, which EVIDENT never does. They stay pinned outside the resolver, and their declared
    requirements (PyPI metadata) are injected as constraints so that the resolution remains exact.
    """
    from packaging.requirements import InvalidRequirement, Requirement

    from . import pypi
    from .graph import marker_ok
    pypi.prefetch(pins.items())
    sdist_only = {p for p, v in pins.items() if not pypi.has_wheel(p, v)}
    reqs = sorted(p for p in pins if p not in sdist_only)
    extra = []
    for p in sorted(sdist_only):
        for s in pypi.requires_dist(p, pins[p]):
            try:
                r = Requirement(s)
            except InvalidRequirement:
                continue
            mk = str(r.marker or "")
            n = norm(r.name)
            if "extra" in mk or not marker_ok(mk, tenv, extras_true=False) or n in sdist_only:
                continue
            if str(r.specifier):
                extra.append(f"{n}{r.specifier}")
    return reqs + sorted(set(extra)), sdist_only


@dataclass
class Resolution:
    ok: bool
    pins: dict[str, str] = field(default_factory=dict)
    error: str = ""
    seconds: float = 0.0


def compile_env(requirements: list[str], *, constraints: dict[str, str] | None = None,
                prefer: dict[str, str] | None = None, python: str = "3.10",
                exclude_newer: str | None = None, upgrade: bool = False, timeout: int = 600,
                specs: list[str] | None = None) -> Resolution:
    import time
    t0 = time.time()
    with tempfile.TemporaryDirectory(prefix="evident-uv-") as td:
        td = Path(td)
        (td / "req.in").write_text("\n".join(requirements) + "\n", "utf8")
        out = td / "out.txt"
        if prefer:
            out.write_text("\n".join(f"{k}=={v}" for k, v in sorted(prefer.items())) + "\n", "utf8")
        cmd = [UV, "pip", "compile", str(td / "req.in"), "-o", str(out), "--python-version", python,
               "--python-platform", "x86_64-unknown-linux-gnu", "--no-build", "--quiet", "--no-header",
               "--no-annotate", "--no-strip-markers"]
        lines = [f"{k}=={v}" for k, v in sorted((constraints or {}).items())] + list(specs or [])
        if lines:
            (td / "c.txt").write_text("\n".join(lines) + "\n", "utf8")
            cmd += ["-c", str(td / "c.txt")]
        if exclude_newer:
            cmd += ["--exclude-newer", exclude_newer]
        if upgrade:
            cmd += ["--upgrade"]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, encoding="utf8", timeout=timeout,
                               env={**os.environ, "UV_NO_PROGRESS": "1"})
        except subprocess.TimeoutExpired:
            return Resolution(False, error="timeout", seconds=time.time() - t0)
        if r.returncode != 0:
            return Resolution(False, error=(r.stderr or r.stdout)[-1500:], seconds=time.time() - t0)
        pins = {}
        for ln in out.read_text("utf8").splitlines():
            ln = ln.split(";")[0].strip()
            if "==" in ln and not ln.startswith("#"):
                n, v = ln.split("==", 1)
                pins[norm(n.split("[")[0])] = v.strip()
        return Resolution(True, pins, seconds=time.time() - t0)
