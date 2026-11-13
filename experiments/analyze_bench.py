"""RQ2: exposure assessment on EVIDENT-Bench (runtime ground truth).

Leave-one-package-out cross-validation (all advisories of a package are held out together) of:
  version-match (SBOM scanner), CORAL-style coefficients, CAPE-style weighted score,
  logistic regression on one-hot evidence (+ isotonic calibration), and EVIDENT's staged model.
Also: per-pattern verdict tables for every analysis (L3b, L4, L5) and ablations of the staged model.
Writes data/results/bench_eval.json and data/results/staged_model.json (fit on all data).
"""
from __future__ import annotations

import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from evident.evidence import CONFIRMED, Finding  # noqa: E402
from evident.exposure import (StagedModel, auc, brier, ece, features, log_loss, p_cape_style,  # noqa: E402
                              p_coral_style, p_version_match, ranking_metrics)
from evident.intel import severity_weight, load_osv  # noqa: E402

RES = ROOT / "data" / "results"


def to_finding(r: dict, drop: set[str] = frozenset()) -> Finding:
    f = Finding(snapshot=f"bench/{r['dist']}/{r['pattern']}", package=r["dist"], version=r["version"],
                advisory=r["advisory"], ids=[r["advisory"]], cves=r["cves"], cvss=r["cvss"], epss=r["epss"],
                kev=r["kev"], severity_w=0.0, published="", fixed=[], depth=1, direct=True)
    f.add("L1", CONFIRMED)
    f.add("L2", CONFIRMED)
    f.add("L3", CONFIRMED, scope="prod")
    if "L3b" not in drop:
        f.add("L3b", r["L3b"], label_imported=r.get("label_imported"))
    if "L4" not in drop:
        f.add("L4", r["L4"], granularity=r["granularity"], missing=bool(r.get("L4_missing")))
    if "L5" not in drop:
        f.add("L5", r["L5"])
    return f


def logistic_cv(train_rows, test_rows, calibrate: bool):
    from sklearn.isotonic import IsotonicRegression
    from sklearn.linear_model import LogisticRegression
    Xtr = np.array([features(to_finding(r)) for r in train_rows])
    ytr = np.array([r["label"] for r in train_rows])
    Xte = np.array([features(to_finding(r)) for r in test_rows])
    if len(set(ytr)) < 2:
        return np.full(len(test_rows), ytr.mean())
    clf = LogisticRegression(C=1.0, max_iter=2000).fit(Xtr, ytr)
    p = clf.predict_proba(Xte)[:, 1]
    if calibrate:
        iso = IsotonicRegression(out_of_bounds="clip").fit(clf.predict_proba(Xtr)[:, 1], ytr)
        p = iso.predict(p)
    return p


def main():
    rows = [json.loads(ln) for ln in (RES / "bench_records.jsonl").read_text("utf8").splitlines() if ln.strip()]
    rows = [r for r in rows if not (r.get("prod_error") and r["label"] == 0 and r["pattern"].startswith("E"))]
    pk = sorted({r["dist"] for r in rows})
    osv = load_osv()
    sev = {}
    for p in pk:
        for a in osv.get(p, []):
            sev[(p, a.id)] = severity_weight(a)
    out = {"n_rows": len(rows), "n_packages": len(pk), "n_advisories": len({(r["dist"], r["advisory"]) for r in rows}),
           "label_rate": float(np.mean([r["label"] for r in rows])),
           "patterns": dict(Counter(r["pattern"] for r in rows))}
    # verdict tables per pattern
    tab = defaultdict(lambda: defaultdict(Counter))
    for r in rows:
        for lvl in ("L3b", "L4", "L5"):
            tab[r["pattern"]][lvl][r[lvl]] += 1
        tab[r["pattern"]]["label"][str(r["label"])] += 1
    out["verdicts_by_pattern"] = {p: {k: dict(v) for k, v in d.items()} for p, d in sorted(tab.items())}
    # analysis-level confusion vs ground truth
    conf = {}
    for lvl, pos in (("L3b", {"CONFIRMED"}), ("L4", {"CONFIRMED"}), ("L4p", {"CONFIRMED", "POSSIBLE"}),
                     ("L5", {"OBSERVED"})):
        key = "L4" if lvl == "L4p" else lvl
        tp = sum(1 for r in rows if r[key] in pos and r["label"] == 1)
        fp = sum(1 for r in rows if r[key] in pos and r["label"] == 0)
        fn = sum(1 for r in rows if r[key] not in pos and r["label"] == 1)
        tn = sum(1 for r in rows if r[key] not in pos and r["label"] == 0)
        conf[lvl] = {"tp": tp, "fp": fp, "fn": fn, "tn": tn,
                     "precision": tp / (tp + fp) if tp + fp else None, "recall": tp / (tp + fn) if tp + fn else None}
    ref = [r for r in rows if r["L4"] == "REFUTED"]
    conf["L4_refuted_false_negative_rate"] = (sum(r["label"] for r in ref) / len(ref)) if ref else None
    out["analysis_confusion"] = conf

    methods = ["version_match", "coral_style", "cape_style", "logistic", "logistic_iso", "evident",
               "evident_noL5", "evident_noL4", "evident_noL3b", "evident_L4only_fixed"]
    preds = {m: np.zeros(len(rows)) for m in methods}
    idx = defaultdict(list)
    for i, r in enumerate(rows):
        idx[r["dist"]].append(i)
    for hold in pk:
        te = idx[hold]
        tr = [i for i in range(len(rows)) if rows[i]["dist"] != hold]
        trr = [rows[i] for i in tr]
        ter = [rows[i] for i in te]
        model = StagedModel().fit([to_finding(r) for r in trr], [r["label"] for r in trr])
        abl = {}
        for name, drop in (("evident_noL5", {"L5"}), ("evident_noL4", {"L4"}), ("evident_noL3b", {"L3b"})):
            abl[name] = (StagedModel().fit([to_finding(r, drop) for r in trr], [r["label"] for r in trr]), drop)
        lr = logistic_cv(trr, ter, False)
        lri = logistic_cv(trr, ter, True)
        for j, i in enumerate(te):
            r = rows[i]
            f = to_finding(r)
            preds["version_match"][i] = p_version_match(f)
            preds["coral_style"][i] = p_coral_style(f)
            preds["cape_style"][i] = p_cape_style(f)
            preds["logistic"][i] = lr[j]
            preds["logistic_iso"][i] = lri[j]
            preds["evident"][i] = model.predict(f)
            for name, (m, drop) in abl.items():
                preds[name][i] = m.predict(to_finding(r, drop))
            # fixed (uncalibrated) staged structure: CORAL coefficients inside EVIDENT's stage structure
            pm = 1.0 if r["L3b"] == "CONFIRMED" else (0.0 if r["L3b"] == "REFUTED" else 0.5)
            preds["evident_L4only_fixed"][i] = pm * p_coral_style(f)
    y = np.array([r["label"] for r in rows])
    w = np.array([sev.get((r["dist"], r["advisory"]), 0.5) for r in rows])
    res = {}
    rng = np.random.default_rng(7)
    for m in methods:
        p = preds[m]
        d = {"brier": brier(p, y), "ece": ece(p, y), "logloss": log_loss(p, y), "auc": auc(p, y)}
        # ranking: findings ranked by risk = p * severity within each package (an "application")
        rk = defaultdict(list)
        for hold in pk:
            ii = idx[hold]
            rm = ranking_metrics(p[ii] * w[ii] + 1e-9 * rng.random(len(ii)), y[ii], ks=(5, 10))
            for k, v in rm.items():
                rk[k].append(v)
        d.update({k: float(np.nanmean(v)) for k, v in rk.items()})
        # bootstrap CI for Brier
        bs = []
        for _ in range(500):
            s = rng.integers(0, len(y), len(y))
            bs.append(brier(p[s], y[s]))
        d["brier_ci"] = [float(np.percentile(bs, 2.5)), float(np.percentile(bs, 97.5))]
        res[m] = d
    # severity-only rankings (CVSS / EPSS) for prioritisation comparison
    for m, sc in (("cvss_only", np.array([(r["cvss"] or 5.0) for r in rows])),
                  ("epss_only", np.array([r["epss"] for r in rows]))):
        rk = defaultdict(list)
        for hold in pk:
            ii = idx[hold]
            rm = ranking_metrics(sc[ii] + 1e-9 * rng.random(len(ii)), y[ii], ks=(5, 10))
            for k, v in rm.items():
                rk[k].append(v)
        res[m] = {k: float(np.nanmean(v)) for k, v in rk.items()}
    out["methods"] = res
    # reliability diagram data
    rel = {}
    for m in ("version_match", "coral_style", "cape_style", "logistic_iso", "evident"):
        p = preds[m]
        bins = np.linspace(0, 1, 6)
        pts = []
        for i in range(5):
            mk = (p >= bins[i]) & ((p < bins[i + 1]) if i < 4 else (p <= 1))
            if mk.any():
                pts.append([float(p[mk].mean()), float(y[mk].mean()), int(mk.sum())])
        rel[m] = pts
    out["reliability"] = rel
    # robustness to missing evidence: at test time, L4/L5 become UNKNOWN with probability q
    rob = {}
    for q in (0.0, 0.25, 0.5, 0.75, 1.0):
        acc = defaultdict(list)
        for seed in range(5):
            rs = np.random.default_rng(100 + seed)
            masked = []
            for r in rows:
                r2 = dict(r)
                if rs.random() < q:
                    r2["L4"] = "UNKNOWN"
                    r2["L4_missing"] = True
                if rs.random() < q:
                    r2["L5"] = "UNKNOWN"
                masked.append(r2)
            pm = {m: np.zeros(len(rows)) for m in ("evident", "logistic_iso", "logistic", "coral_style", "cape_style")}
            for hold in pk:
                te = idx[hold]
                trr = [rows[i] for i in range(len(rows)) if rows[i]["dist"] != hold]
                ter = [masked[i] for i in te]
                model = StagedModel().fit([to_finding(r) for r in trr], [r["label"] for r in trr])
                lr = logistic_cv(trr, ter, False)
                lri = logistic_cv(trr, ter, True)
                for j, i in enumerate(te):
                    f = to_finding(masked[i])
                    pm["evident"][i] = model.predict(f)
                    pm["logistic"][i] = lr[j]
                    pm["logistic_iso"][i] = lri[j]
                    pm["coral_style"][i] = p_coral_style(f)
                    pm["cape_style"][i] = p_cape_style(f)
            for m, p in pm.items():
                acc[m].append((brier(p, y), ece(p, y), auc(p, y)))
        rob[str(q)] = {m: {"brier": float(np.mean([a[0] for a in v])), "ece": float(np.mean([a[1] for a in v])),
                           "auc": float(np.mean([a[2] for a in v]))} for m, v in acc.items()}
    out["missingness"] = rob
    for q, d in rob.items():
        print("missing q=" + q, " ".join(f"{m}:B={v['brier']:.3f}/E={v['ece']:.3f}" for m, v in d.items()))
    # time-separated evaluation: train on advisories published <= 2024, test on 2025-2026 advisories
    pub = {}
    for p in pk:
        for a in osv.get(p, []):
            pub[(p, a.id)] = (a.published or "9999")[:4]
    tr = [r for r in rows if pub.get((r["dist"], r["advisory"]), "9999") <= "2024"]
    te = [r for r in rows if pub.get((r["dist"], r["advisory"]), "9999") >= "2025"]
    ts = {"train_rows": len(tr), "test_rows": len(te),
          "train_advisories": len({(r["dist"], r["advisory"]) for r in tr}),
          "test_advisories": len({(r["dist"], r["advisory"]) for r in te})}
    if tr and te:
        mdl = StagedModel().fit([to_finding(r) for r in tr], [r["label"] for r in tr])
        yt = np.array([r["label"] for r in te])
        cand = {"evident": [mdl.predict(to_finding(r)) for r in te],
                "logistic_iso": list(logistic_cv(tr, te, True)),
                "coral_style": [p_coral_style(to_finding(r)) for r in te],
                "cape_style": [p_cape_style(to_finding(r)) for r in te],
                "version_match": [1.0] * len(te)}
        ts["methods"] = {m: {"brier": brier(p, yt), "ece": ece(p, yt), "auc": auc(p, yt)} for m, p in cand.items()}
        print("time split", json.dumps(ts))
    out["time_split"] = ts
    final = StagedModel().fit([to_finding(r) for r in rows], [r["label"] for r in rows])
    (RES / "staged_model.json").write_text(final.to_json(), "utf8")
    out["final_model"] = json.loads(final.to_json())
    (RES / "bench_eval.json").write_text(json.dumps(out, indent=1, default=float), "utf8")
    for m, d in res.items():
        print(f"{m:22s} " + " ".join(f"{k}={v:.3f}" for k, v in d.items() if isinstance(v, float)))
    print(json.dumps(conf, indent=1))


if __name__ == "__main__":
    main()
