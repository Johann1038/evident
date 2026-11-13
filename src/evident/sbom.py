"""CycloneDX 1.6 SBOM with dependency edges and embedded VEX analysis."""
from __future__ import annotations

import datetime as dt
import uuid

import networkx as nx

from .evidence import Finding, vex_statement


def purl(name: str, version: str) -> str:
    return f"pkg:pypi/{name}@{version}"


def cyclonedx(app: str, g: nx.DiGraph, findings: list[Finding] | None = None, pins: dict | None = None) -> dict:
    nodes = [n for n in g.nodes if n != "__app__" and g.nodes[n].get("installed", True)]
    ver = {n: (pins or {}).get(n, g.nodes[n].get("version", "")) for n in nodes}
    comps = [{"type": "library", "bom-ref": purl(n, ver[n]), "name": n, "version": ver[n], "purl": purl(n, ver[n]),
              "scope": "required" if g.nodes[n].get("prod", True) else "optional"} for n in nodes]
    deps = [{"ref": "app", "dependsOn": [purl(v, ver[v]) for v in g.successors("__app__") if v in ver]}]
    for n in nodes:
        deps.append({"ref": purl(n, ver[n]), "dependsOn": [purl(v, ver[v]) for v in g.successors(n) if v in ver]})
    bom = {
        "bomFormat": "CycloneDX", "specVersion": "1.6", "serialNumber": f"urn:uuid:{uuid.uuid4()}", "version": 1,
        "metadata": {"timestamp": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
                     "tools": {"components": [{"type": "application", "name": "evident", "version": "0.1.0"}]},
                     "component": {"type": "application", "bom-ref": "app", "name": app}},
        "components": comps, "dependencies": deps,
    }
    if findings:
        vulns = []
        for f in findings:
            v = f.vex or vex_statement(f)
            vulns.append({
                "id": f.advisory, "source": {"name": "OSV", "url": f"https://osv.dev/vulnerability/{f.ids[0]}"},
                "ratings": ([{"score": f.cvss, "method": "CVSSv31" if f.cvss else "other"}] if f.cvss else []),
                "affects": [{"ref": purl(f.package, f.version)}],
                "analysis": {"state": v["state"], **({"justification": v["justification"]} if "justification" in v else {}),
                             "detail": f"EVIDENT p_exposed={f.p_exposed:.3f} class={f.exposure_class}"
                             if f.p_exposed is not None else f"class={f.exposure_class}"},
                "properties": [{"name": f"evident:{k}", "value": e.state} for k, e in f.evidence.items()],
            })
        bom["vulnerabilities"] = vulns
    return bom
