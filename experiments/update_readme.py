"""Fill the README's real-world results section from data/results/paper_tables.json."""
from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
T = json.loads((ROOT / "data" / "results" / "paper_tables.json").read_text("utf8"))
REM, RW, RN, CLS = T["remediation"], T["realworld_scan"], T["realworld_n"], T.get("exposure_classes", {})
NAMES = {"audit_fix": "Minimal fix per package (pip-audit style)", "latest": "Latest release per package",
         "upgrade_all": "Upgrade everything (uv)", "vm_opt": "Optimiser + version-match weights (KEVGraph-like)",
         "coral_opt": "Optimiser + CORAL-style weights", "cape_opt": "Optimiser + CAPE-style weights",
         "evident": "**EVIDENT** (optimiser + calibrated weights)"}


def g(s, k, stat="mean"):
    return REM.get(s, {}).get(k, {}).get(stat, float("nan"))


tot = sum(CLS.values()) or 1
dismiss = sum(CLS.get(k, 0) for k in ("NOT_INSTALLED", "DEV_ONLY", "NOT_IMPORTED", "STATICALLY_UNREACHABLE"))
lines = [
    f"{RN['snapshots']} historical snapshots of open-source Python applications (lockfiles from mid-2023, scanned "
    f"against the 2026-11-12 advisory snapshot); {RN['resolvable']} re-resolve in metadata-only mode.",
    "",
    f"- **{int(RW['findings']['sum'])} version-matched findings**, median {RW['findings']['median']:.0f} per application; "
    f"{100 * RW['transitive_findings_share']['mean']:.0f}% concern transitive dependencies.",
    f"- **{100 * dismiss / tot:.1f}%** are not installed for the target, development-only, not imported, or statically "
    f"unreachable (each with a VEX justification); {CLS.get('STATICALLY_REACHABLE', 0)} have a confirmed static path.",
    f"- The calibrated model expects **{RW['expected_exposed']['sum']:.0f}** of them to be exposed.",
    "",
    "| Strategy | Resolves | Packages changed | Major bumps | Expected exposure removed | Confirmed-reachable fixed |",
    "|---|---|---|---|---|---|",
]
for s in ("audit_fix", "latest", "upgrade_all", "vm_opt", "coral_opt", "cape_opt", "evident"):
    if s in REM:
        lines.append(f"| {NAMES[s]} | {100 * g(s, 'ok'):.0f}% | {g(s, 'changed'):.1f} | {g(s, 'major_bumps'):.1f} | "
                     f"{100 * g(s, 'risk_reduction_evident'):.0f}% | {100 * g(s, 'confirmed_fixed'):.0f}% |")
pc = T.get("pareto_common") or {}
if pc:
    lines += ["", f"Scored with the same yardstick, calibrated and version-match weights give similar risk/change fronts "
              f"(mean area difference {pc['mean_auc_gain']:+.3f}, median {pc['median_auc_gain']:+.3f}; calibrated better on "
              f"{pc['better']}, worse on {pc['worse']} of {pc['projects']} projects): with mostly *possibly reachable* "
              "findings, weighting approaches counting. The main remediation gains come from constraint-aware, "
              "resolver-verified planning."]
dec = T.get("decision", {})
if dec:
    lines += ["", f"Only {dec['critical_total']} of {dec['uncertain_total']} uncertain findings "
              f"({100 * dec['critical_total'] / max(dec['uncertain_total'], 1):.1f}%) would change the optimal plan "
              "if resolved: these are the ones EVIDENT asks you to triage."]
body = "\n".join(lines)
p = ROOT / "README.md"
txt = p.read_text("utf8")
txt = re.sub(r"<!-- REALWORLD-RESULTS -->.*?<!-- /REALWORLD-RESULTS -->",
             "<!-- REALWORLD-RESULTS -->\n" + body + "\n<!-- /REALWORLD-RESULTS -->", txt, flags=re.S)
p.write_text(txt, "utf8")
print(body)
