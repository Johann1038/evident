"""Figure S1: end-to-end case study (evidence -> probability -> plan -> realised environment), from saved results."""
from __future__ import annotations

import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.patches import FancyBboxPatch  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
RES = ROOT / "data" / "results"
SID = "Ehco1996__django-sspanel@v2023.12.26"


def main():
    r = json.loads((RES / "realworld" / SID / "result.json").read_text("utf8"))
    fs = json.loads((RES / "realworld" / SID / "findings.json").read_text("utf8"))
    f = next(x for x in fs if x["advisory"] == "CVE-2025-64459" and x["package"] == "django")
    case = json.loads((RES / "round3_realworld.json").read_text("utf8"))["case"]
    ev = r["strategies"]["evident"]
    st = {lvl: (f["evidence"].get(lvl) or {}).get("state", "–") for lvl in ("L3", "L3b", "L4", "L5")}
    wit = (f["evidence"]["L4"].get("detail") or {}).get("witness") or []
    rem = case["remaining_advisories_if_upgraded_to"]
    boxes = [
        ("Original environment", [r['meta']['repo'], r['meta']['tag'], f"django {f['version']}",
                                  f"{f['advisory']}", f"CVSS {f.get('cvss')}",
                                  f"{r['original']['residual_findings']} findings in total"]),
        ("Evidence", [f"L3 installed (prod): {st['L3']}", f"L3b imported: {st['L3b']}",
                      f"L4 reachable: {st['L4']}", f"(strong edges, path {len(wit)})",
                      "L5 runtime: not used", "(static setting)"]),
        ("Exposure estimate", [f"P(exposed) = {f.get('p_exposed', 0):.3f}", "staged model,", "static setting"]),
        ("Plan (CP-SAT)", [f"django → {ev['planned'].get('django')}", f"+{len(ev['planned']) - 1} other changes",
                           "newest 4.2 (4.2.30) keeps", f"{rem.get('4.2.30')} of {case['django_advisories_affecting_4.2.6']} advisories;",
                           f"5.2.19 keeps {rem.get('5.2.19')}"]),
        ("Realised + verified", [f"resolver adds {ev.get('unplanned_changes')} changes",
                                 f"re-scan: {ev.get('residual_findings')} of {r['original']['residual_findings']} remain",
                                 "L1 resolves;", "L2/L2b API checks pass;", "tests not run"]),
    ]
    fig, ax = plt.subplots(figsize=(11, 3.1))
    ax.set_xlim(0, 100)
    ax.set_ylim(0, 30)
    ax.axis("off")
    w, gap = 17.8, 2.2
    for i, (title, lines) in enumerate(boxes):
        x = 0.5 + i * (w + gap)
        ax.add_patch(FancyBboxPatch((x, 2), w, 25, boxstyle="round,pad=0.3",
                                    fc="0.93" if i not in (2, 3) else "0.85", ec="0.25", lw=0.8))
        ax.text(x + w / 2, 24.8, title, ha="center", va="center", fontsize=8.5, weight="bold")
        for j, ln in enumerate(lines):
            ax.text(x + 0.8, 20.8 - j * 3.1, ln, ha="left", va="center", fontsize=6.4)
        if i < len(boxes) - 1:
            ax.annotate("", xy=(x + w + gap - 0.2, 14.5), xytext=(x + w + 0.4, 14.5),
                        arrowprops=dict(arrowstyle="-|>", lw=1.0, color="0.2"))
    ax.text(50, 0.2, "Retrospective example: a 2023 environment judged with advisories published up to 2026-11-12.",
            ha="center", fontsize=6.5, style="italic")
    out = ROOT / "paper" / "figures" / "case_study.png"
    fig.savefig(out, dpi=220, bbox_inches="tight")
    print("wrote", out)


if __name__ == "__main__":
    main()
