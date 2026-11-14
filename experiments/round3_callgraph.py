"""Third-round call-graph comparison on a common subset: every approach scored on the same applications.

Prediction semantics: a reachability-derived security decision ("exposed" iff a mined vulnerable symbol is reachable
from the entry module in the tool's graph); PyCG and Jarvis do not themselves issue security verdicts.
Writes data/results/round3_callgraph.json.
"""
import json
from pathlib import Path

RES = Path(__file__).resolve().parents[1] / "data" / "results"


def scores(rows, key):
    tp = sum(1 for r in rows if r[key] and r["label"])
    fp = sum(1 for r in rows if r[key] and not r["label"])
    fn = sum(1 for r in rows if not r[key] and r["label"])
    tn = sum(1 for r in rows if not r[key] and not r["label"])
    p = tp / (tp + fp) if tp + fp else None
    rc = tp / (tp + fn) if tp + fn else None
    f1 = 2 * p * rc / (p + rc) if p and rc else None
    return {"n": len(rows), "tp": tp, "fp": fp, "fn": fn, "tn": tn, "precision": p, "recall": rc, "f1": f1,
            "false_refutation_rate": fn / (tp + fn) if tp + fn else None,
            "missed_exposed": fn, "false_alarms": fp}


def main():
    rows = json.loads((RES / "callgraph_comparison.json").read_text("utf8"))
    common = [r for r in rows if r.get("pycg_pred") is not None and r.get("jarvis_pred") is not None]
    keys = {"PyCG": "pycg_pred", "Jarvis": "jarvis_pred", "EVIDENT strong": "evident_strong",
            "EVIDENT strong+weak": "evident_weak"}
    out = {"applications": len(rows), "common_subset": len(common),
           "failure_rate": {"PyCG": sum(r.get("pycg_pred") is None for r in rows) / len(rows),
                            "Jarvis": sum(r.get("jarvis_pred") is None for r in rows) / len(rows),
                            "EVIDENT": 0.0},
           "common": {k: scores(common, v) for k, v in keys.items()},
           "failed_by_pycg_label_rate": (sum(r["label"] for r in rows if r.get("pycg_pred") is None)
                                         / max(1, sum(r.get("pycg_pred") is None for r in rows))),
           "all_label_rate": sum(r["label"] for r in rows) / len(rows)}
    (RES / "round3_callgraph.json").write_text(json.dumps(out, indent=1), "utf8")
    print(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
