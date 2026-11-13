"""Graded, three-valued, provenance-carrying evidence for (application, vulnerability) findings.

Levels
  L1  inventory      package appears in the lock/SBOM                          CONFIRMED
  L2  version        locked version inside the advisory's affected range       CONFIRMED
  L3  installation   installed in the *target* environment (markers, extras,   CONFIRMED/REFUTED/UNKNOWN
                     reachability from roots) and its deployment scope (prod/dev)
  L3b import         vulnerable package transitively imported by non-test code CONFIRMED/REFUTED/UNKNOWN
  L4  static         vulnerable symbol reachable from application roots       CONFIRMED/POSSIBLE/REFUTED/UNKNOWN
  L5  runtime        vulnerable symbol executed by an observed run (tests)    OBSERVED/NOT_OBSERVED/UNKNOWN

Absence of evidence is never treated as evidence of absence: L5 NOT_OBSERVED and L4 POSSIBLE are
distinct states, and UNKNOWN is the default whenever an analysis cannot run.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field

CONFIRMED, REFUTED, UNKNOWN, POSSIBLE = "CONFIRMED", "REFUTED", "UNKNOWN", "POSSIBLE"
OBSERVED, NOT_OBSERVED = "OBSERVED", "NOT_OBSERVED"


@dataclass
class Evidence:
    level: str
    state: str
    detail: dict = field(default_factory=dict)
    tool: str = "evident"


@dataclass
class Finding:
    snapshot: str
    package: str
    version: str
    advisory: str
    ids: list[str]
    cves: list[str]
    cvss: float | None
    epss: float
    kev: bool
    severity_w: float
    published: str
    fixed: list[str]
    depth: int | None
    direct: bool
    evidence: dict[str, Evidence] = field(default_factory=dict)
    p_exposed: float | None = None
    exposure_class: str | None = None
    vex: dict | None = None

    def state(self, level: str) -> str:
        e = self.evidence.get(level)
        return e.state if e else UNKNOWN

    def add(self, level: str, state: str, **detail) -> None:
        self.evidence[level] = Evidence(level, state, detail)

    def to_row(self) -> dict:
        d = {k: v for k, v in asdict(self).items() if k != "evidence"}
        for k, e in self.evidence.items():
            d[f"{k}_state"] = e.state
        d["evidence"] = {k: asdict(e) for k, e in self.evidence.items()}
        return d


def exposure_class(f: Finding) -> str:
    """Ordinal exposure class derived from the strongest decisive evidence."""
    if f.state("L3") == REFUTED:
        return "NOT_INSTALLED"
    if f.evidence.get("L3") and f.evidence["L3"].detail.get("scope") == "dev":
        return "DEV_ONLY"
    if f.state("L5") == OBSERVED:
        return "RUNTIME_OBSERVED"
    if f.state("L4") == CONFIRMED:
        return "STATICALLY_REACHABLE"
    if f.state("L3b") == REFUTED:
        return "NOT_IMPORTED"
    if f.state("L4") == REFUTED:
        return "STATICALLY_UNREACHABLE"
    if f.state("L4") == POSSIBLE:
        return "POSSIBLY_REACHABLE"
    if f.state("L3b") == CONFIRMED:
        return "IMPORTED_REACH_UNKNOWN"
    return "INSTALLED_UNKNOWN"


def vex_statement(f: Finding) -> dict:
    """Map to CycloneDX/OpenVEX analysis states with justification."""
    c = f.exposure_class or exposure_class(f)
    if c == "NOT_INSTALLED":
        return {"state": "not_affected", "justification": "component_not_present"}
    if c == "NOT_IMPORTED":
        return {"state": "not_affected", "justification": "vulnerable_code_not_present"}
    if c == "STATICALLY_UNREACHABLE":
        return {"state": "not_affected", "justification": "vulnerable_code_not_in_execute_path"}
    if c in ("RUNTIME_OBSERVED", "STATICALLY_REACHABLE"):
        return {"state": "exploitable"}
    return {"state": "in_triage"}
