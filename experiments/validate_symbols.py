"""E3: validation of vulnerable-symbol mining.

Automatic part (reported in the paper):
  - yield by status (function / module-only / no commit / too broad / no Python change)
  - functions per advisory, multi-commit consistency (Jaccard of function sets across fix commits)
  - repository-path -> installed-module mapping success on every installed version we analysed
  - triggerability on EVIDENT-Bench (fraction of function-level advisories executed by a benign probe)
Manual part: a seeded random sample of advisories is written to data/results/symbol_annotation_sheet.csv for
human annotation (is the vulnerable operation inside the mined functions? which functions are missing?).
"""
from __future__ import annotations

import csv
import json
import random
import statistics as st
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from evident.symbols import module_for_path  # noqa: E402

SYM = ROOT / "data" / "symbols"
SRC = ROOT / "data" / "sources" / "pkgs"
RES = ROOT / "data" / "results"


def main():
    recs = [json.loads(p.read_text("utf8")) for p in sorted(SYM.glob("*.json"))]
    status = Counter(r["status"] for r in recs)
    nfun = [len({f for fl in r["files"] for f in fl["functions"]}) for r in recs if r["status"] == "functions"]
    # multi-commit consistency
    jac = []
    for r in recs:
        if len(r.get("commits", [])) < 2 or r["status"] != "functions":
            continue
        # files are appended per commit in order; approximate per-commit sets by splitting on commit py_files counts
        sets, i = [], 0
        for c in r["commits"]:
            k = c.get("py_files", 0)
            fs = r["files"][i:i + k]
            i += k
            s = {f["path"] + "::" + fn for fl in [fs] for f in fl for fn in f["functions"]}
            if s:
                sets.append(s)
        if len(sets) >= 2:
            a, b = sets[0], sets[1]
            jac.append(len(a & b) / len(a | b))
    # mapping success against installed sources we have on disk
    mapped = unmapped = 0
    unmapped_examples = []
    for r in recs:
        pdir = SRC / r["package"]
        if not pdir.exists() or not r["files"]:
            continue
        vers = [v for v in pdir.iterdir() if v.is_dir() and (v / ".done").exists() and (v / ".done").read_text() != "none"]
        if not vers:
            continue
        src = sorted(vers)[-1]
        for f in r["files"]:
            if module_for_path(f["path"], src):
                mapped += 1
            else:
                unmapped += 1
                if len(unmapped_examples) < 15:
                    unmapped_examples.append(f"{r['package']}: {f['path']}")
    # benchmark triggerability
    trig = {"function_level": 0, "triggerable": 0}
    for s in (RES / "bench_summaries").glob("*.json"):
        d = json.loads(s.read_text("utf8"))
        for aid, v in (d.get("triggerable") or {}).items():
            trig["function_level"] += 1
            trig["triggerable"] += int(bool(v["trigger"]))
    out = {"advisories_mined": len(recs), "status": dict(status),
           "functions_per_advisory": {"median": st.median(nfun) if nfun else 0, "mean": st.mean(nfun) if nfun else 0,
                                      "max": max(nfun) if nfun else 0,
                                      "share_more_than_5": sum(1 for n in nfun if n > 5) / max(len(nfun), 1)},
           "multi_commit": {"advisories": len(jac), "mean_jaccard": st.mean(jac) if jac else None},
           "path_mapping": {"mapped_files": mapped, "unmapped_files": unmapped,
                            "rate": mapped / max(mapped + unmapped, 1), "unmapped_examples": unmapped_examples},
           "bench_triggerability": trig}
    (RES / "symbol_validation.json").write_text(json.dumps(out, indent=1), "utf8")
    # annotation sheet (seeded sample of function-level advisories)
    pool = [r for r in recs if r["status"] == "functions"]
    random.Random(2026).shuffle(pool)
    with (RES / "symbol_annotation_sheet.csv").open("w", newline="", encoding="utf8") as fh:
        wr = csv.writer(fh)
        wr.writerow(["advisory", "package", "fix_commits", "mined_functions",
                     "ANNOTATE: vulnerable operation inside mined functions? (yes/partial/no)",
                     "ANNOTATE: missed vulnerable functions", "ANNOTATE: notes", "annotator"])
        for r in pool[:40]:
            fns = sorted({f"{fl['path']}::{fn}" for fl in r["files"] for fn in fl["functions"]})
            wr.writerow([r["advisory"], r["package"],
                         " ".join(f"https://github.com/{c['repo']}/commit/{c['sha']}" for c in r["commits"]),
                         "; ".join(fns[:15]), "", "", "", ""])
    print(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
