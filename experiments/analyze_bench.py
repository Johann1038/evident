"""RQ2/RQ5: exposure assessment on EVIDENT-Bench (runtime ground truth), with leakage audit and statistics.

Settings
  static  : evidence L3/L3b/L4 only (primary; no runtime evidence, hence no possible label leakage)
  runtime : additionally L5 from a separate test run (secondary)
Validation: leave-one-package-out (all advisories, apps and templates of a package are held out together);
uncertainty: package-grouped bootstrap (resample packages); paired bootstrap for differences.
Also: probability baselines, calibration diagnostics, prevalence shift, factorial ablation, per-pattern results,
correlated / realistic missingness, time split, sample flow. Writes data/results/bench_eval.json and
data/results/staged_model.json (static setting, fit on all data, used by the real-world study).
"""
from __future__ import annotations

import itertools
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from evident.evidence import CONFIRMED, Finding  # noqa: E402
from evident.exposure import (StagedModel, auc, brier, ece, features, log_loss, p_cape_style,  # noqa: E402
                              p_coral_style, ranking_metrics)
from evident.intel import load_osv, severity_weight  # noqa: E402

RES = ROOT / "data" / "results"
RNG = np.random.default_rng(7)
LEVELS = ("L3b", "L4", "L5")


def to_finding(r: dict, drop=frozenset()) -> Finding:
    f = Finding(snapshot=f"bench/{r['dist']}/{r['pattern']}", package=r["dist"], version=r["version"],
                advisory=r["advisory"], ids=[r["advisory"]], cves=r["cves"], cvss=r["cvss"], epss=r["epss"],
                kev=r["kev"], severity_w=0.0, published="", fixed=[], depth=1, direct=True)
    f.add("L1", CONFIRMED)
    f.add("L2", CONFIRMED)
    f.add("L3", CONFIRMED, scope="prod")
    if "L3b" not in drop:
        f.add("L3b", r["L3b"], label_imported=r.get("label_imported"), missing=bool(r.get("L3b_missing")))
    if "L4" not in drop:
        f.add("L4", r["L4"], granularity=r["granularity"], missing=bool(r.get("L4_missing")))
    if "L5" not in drop:
        f.add("L5", r["L5"])
    return f


# ------------------------------------------------------------------ models
def fit_predict(method: str, tr: list[dict], te: list[dict], drop=frozenset()) -> np.ndarray:
    if method == "version_match":
        return np.ones(len(te))
    if method == "coral_style":
        return np.array([p_coral_style(to_finding(r, drop)) for r in te])
    if method == "cape_style":
        return np.array([p_cape_style(to_finding(r, drop)) for r in te])
    if method == "evident":
        m = StagedModel().fit([to_finding(r, drop) for r in tr], [r["label"] for r in tr])
        return np.array([m.predict(to_finding(r, drop)) for r in te])
    Xtr = np.array([features(to_finding(r, drop)) for r in tr])
    ytr = np.array([r["label"] for r in tr])
    Xte = np.array([features(to_finding(r, drop)) for r in te])
    if len(set(ytr)) < 2:
        return np.full(len(te), ytr.mean())
    from sklearn.isotonic import IsotonicRegression
    if method.startswith("logistic"):
        from sklearn.linear_model import LogisticRegression
        clf = LogisticRegression(C=1.0, max_iter=2000).fit(Xtr, ytr)
    elif method.startswith("hgb"):
        from sklearn.ensemble import HistGradientBoostingClassifier
        clf = HistGradientBoostingClassifier(max_depth=3, max_iter=150, random_state=0).fit(Xtr, ytr)
    elif method == "naive_bayes":
        from sklearn.naive_bayes import BernoulliNB
        clf = BernoulliNB().fit(Xtr, ytr)
    else:
        raise ValueError(method)
    p = clf.predict_proba(Xte)[:, 1]
    if method.endswith("_iso"):
        p = IsotonicRegression(out_of_bounds="clip").fit(clf.predict_proba(Xtr)[:, 1], ytr).predict(p)
    return p


METHODS = ["version_match", "coral_style", "cape_style", "naive_bayes", "logistic", "logistic_iso", "hgb_iso",
           "evident"]


def lopo(rows, method, drop=frozenset(), te_rows=None):
    """Leave-one-package-out predictions; te_rows optionally replaces test rows (e.g. masked evidence)."""
    te_rows = te_rows or rows
    p = np.zeros(len(rows))
    by = defaultdict(list)
    for i, r in enumerate(rows):
        by[r["dist"]].append(i)
    for hold, idx in by.items():
        tr = [r for r in rows if r["dist"] != hold]
        p[idx] = fit_predict(method, tr, [te_rows[i] for i in idx], drop)
    return p


# ------------------------------------------------------------------ metrics
def calib_slope_intercept(p, y):
    from sklearn.linear_model import LogisticRegression
    q = np.clip(p, 1e-4, 1 - 1e-4)
    z = np.log(q / (1 - q)).reshape(-1, 1)
    if len(set(y)) < 2 or np.std(z) < 1e-9:
        return float("nan"), float("nan")
    m = LogisticRegression(C=1e6, max_iter=1000).fit(z, y)
    return float(m.coef_[0][0]), float(m.intercept_[0])


def adaptive_ece(p, y, bins=10):
    order = np.argsort(p)
    tot = 0.0
    for chunk in np.array_split(order, bins):
        if len(chunk):
            tot += len(chunk) / len(p) * abs(p[chunk].mean() - y[chunk].mean())
    return float(tot)


def brier_decomposition(p, y, bins=10):
    edges = np.linspace(0, 1, bins + 1)
    ybar = y.mean()
    rel = res = 0.0
    for i in range(bins):
        m = (p >= edges[i]) & ((p < edges[i + 1]) if i < bins - 1 else (p <= 1))
        if m.any():
            w = m.mean()
            rel += w * (p[m].mean() - y[m].mean()) ** 2
            res += w * (y[m].mean() - ybar) ** 2
    return {"reliability": float(rel), "resolution": float(res), "uncertainty": float(ybar * (1 - ybar))}


def metric_set(p, y, rows=None, w=None):
    d = {"brier": brier(p, y), "ece": ece(p, y), "ace": adaptive_ece(p, y), "logloss": log_loss(p, y),
         "auc": auc(p, y), "citl": float(p.mean() - y.mean())}
    d["slope"], d["intercept"] = calib_slope_intercept(p, y)
    if rows is not None and w is not None:
        rk = defaultdict(list)
        by = defaultdict(list)
        for i, r in enumerate(rows):
            by[r["dist"]].append(i)
        for idx in by.values():
            idx = np.array(idx)
            rm = ranking_metrics(p[idx] * w[idx] + 1e-9 * RNG.random(len(idx)), y[idx], ks=(5, 10))
            for k, v in rm.items():
                rk[k].append(v)
        d.update({k: float(np.nanmean(v)) for k, v in rk.items()})
    return d


def grouped_bootstrap(rows, preds: dict, y, B=1000, pairs=()):
    """Resample packages with replacement; CIs for Brier/ECE/AUC and paired differences."""
    by = defaultdict(list)
    for i, r in enumerate(rows):
        by[r["dist"]].append(i)
    groups = list(by.values())
    stats = {m: defaultdict(list) for m in preds}
    diffs = {f"{a}-{b}": defaultdict(list) for a, b in pairs}
    for _ in range(B):
        pick = RNG.integers(0, len(groups), len(groups))
        idx = np.concatenate([groups[k] for k in pick])
        yy = y[idx]
        cur = {}
        for m, p in preds.items():
            pp = p[idx]
            cur[m] = (brier(pp, yy), ece(pp, yy), auc(pp, yy))
            for k, v in zip(("brier", "ece", "auc"), cur[m]):
                stats[m][k].append(v)
        for a, b in pairs:
            for j, k in enumerate(("brier", "ece", "auc")):
                diffs[f"{a}-{b}"][k].append(cur[a][j] - cur[b][j])

    def ci(v):
        v = np.array([x for x in v if x == x])
        return [float(np.percentile(v, 2.5)), float(np.percentile(v, 97.5))]
    out = {m: {k: ci(v) for k, v in d.items()} for m, d in stats.items()}
    dd = {}
    for name, d in diffs.items():
        dd[name] = {}
        for k, v in d.items():
            v = np.array([x for x in v if x == x])
            p_two = 2 * min((v <= 0).mean(), (v >= 0).mean())
            dd[name][k] = {"mean": float(v.mean()), "ci": ci(v), "p": float(min(1.0, p_two))}
    return out, dd


def reliability_points(p, y, bins=10, B=300):
    edges = np.linspace(0, 1, bins + 1)
    pts = []
    for i in range(bins):
        m = (p >= edges[i]) & ((p < edges[i + 1]) if i < bins - 1 else (p <= 1))
        if m.sum() >= 5:
            idx = np.where(m)[0]
            bs = [y[RNG.choice(idx, len(idx))].mean() for _ in range(B)]
            pts.append([float(p[m].mean()), float(y[m].mean()), int(m.sum()),
                        float(np.percentile(bs, 2.5)), float(np.percentile(bs, 97.5))])
    return pts


# ------------------------------------------------------------------ main
def main():
    raw = [json.loads(ln) for ln in (RES / "bench_records.jsonl").read_text("utf8").splitlines() if ln.strip()]
    rows = [r for r in raw if not (r.get("prod_error") and r["label"] == 0 and r["pattern"].startswith("E"))]
    pk = sorted({r["dist"] for r in rows})
    osv = load_osv()
    sev = {(p, a.id): severity_weight(a) for p in pk for a in osv.get(p, [])}
    y = np.array([r["label"] for r in rows])
    w = np.array([sev.get((r["dist"], r["advisory"]), 0.5) for r in rows])
    advs = {(r["dist"], r["advisory"]) for r in rows}
    out = {"n_rows": len(rows), "n_packages": len(pk), "n_advisories": len(advs), "label_rate": float(y.mean()),
           "patterns": dict(Counter(r["pattern"] for r in rows))}

    # ---- sample flow
    per_adv = Counter((r["dist"], r["advisory"]) for r in raw)
    out["sample_flow"] = {"triggerable_advisories": len(advs), "possible_apps": 16 * len(advs),
                          "generated_apps": len(raw),
                          "skipped_no_safe_probe": 16 * len(advs) - len(raw),
                          "advisories_without_safe_probe": sum(1 for v in per_adv.values() if v < 16),
                          "excluded_runtime_errors": len(raw) - len(rows), "final": len(rows)}

    # ---- leakage audit
    l5o = np.array([r["L5"] == "OBSERVED" for r in rows])
    same = np.array([(r["L5"] == "OBSERVED") == bool(r["label"]) for r in rows])
    out["leakage_audit"] = {
        "l5_agrees_with_label": float(same.mean()),
        "p_label_given_l5_observed": float(y[l5o].mean()) if l5o.any() else None,
        "p_label_given_l5_not_observed": float(y[~l5o].mean()) if (~l5o).any() else None,
        "l5_observed_but_not_exposed": int((l5o & (y == 0)).sum()),
        "exposed_not_observed": int((~l5o & (y == 1)).sum()),
        "note": "L5 comes from a separate process running the test file; the label from the production entry point."}

    # ---- verdict tables and analysis confusion
    tab = defaultdict(lambda: defaultdict(Counter))
    for r in rows:
        for lvl in LEVELS:
            tab[r["pattern"]][lvl][r[lvl]] += 1
        tab[r["pattern"]]["label"][str(r["label"])] += 1
    out["verdicts_by_pattern"] = {p: {k: dict(v) for k, v in d.items()} for p, d in sorted(tab.items())}
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
    conf["L4_refuted"] = {"n": len(ref), "exposed": sum(r["label"] for r in ref)}
    conf["L4_unknown"] = dict(Counter(r["L4_reason"].split(" (")[0] for r in rows if r["L4"] == "UNKNOWN"))
    out["analysis_confusion"] = conf

    # ---- main comparison in both settings
    results = {}
    preds_by = {}
    for setting, drop in (("static", frozenset({"L5"})), ("runtime", frozenset())):
        preds = {m: lopo(rows, m, drop) for m in METHODS}
        preds_by[setting] = preds
        results[setting] = {m: metric_set(p, y, rows, w) for m, p in preds.items()}
        for m, sc in (("cvss_only", np.array([(r["cvss"] or 5.0) for r in rows])),
                      ("epss_only", np.array([r["epss"] for r in rows]))):
            rk = defaultdict(list)
            by = defaultdict(list)
            for i, r in enumerate(rows):
                by[r["dist"]].append(i)
            for idx in by.values():
                idx = np.array(idx)
                for k, v in ranking_metrics(sc[idx] + 1e-9 * RNG.random(len(idx)), y[idx], ks=(5, 10)).items():
                    rk[k].append(v)
            results[setting][m] = {k: float(np.nanmean(v)) for k, v in rk.items()}
        cis, diffs = grouped_bootstrap(rows, {m: preds[m] for m in METHODS}, y,
                                       pairs=(("evident", "logistic_iso"), ("evident", "hgb_iso"),
                                              ("evident", "coral_style"), ("evident", "cape_style")))
        for m in METHODS:
            results[setting][m]["ci"] = cis[m]
        results[setting]["paired"] = diffs
    out["methods"] = results
    out["reliability"] = {s: {m: reliability_points(preds_by[s][m], y)
                              for m in ("coral_style", "cape_style", "logistic_iso", "evident")}
                          for s in ("static", "runtime")}
    out["brier_decomposition"] = {s: {m: brier_decomposition(preds_by[s][m], y)
                                      for m in ("coral_style", "logistic_iso", "hgb_iso", "evident")}
                                  for s in ("static", "runtime")}
    out["per_pattern"] = {}
    for pat in sorted({r["pattern"] for r in rows}):
        idx = np.array([i for i, r in enumerate(rows) if r["pattern"] == pat])
        out["per_pattern"][pat] = {m: {"mean_p": float(preds_by["static"][m][idx].mean()),
                                       "brier": brier(preds_by["static"][m][idx], y[idx])}
                                   for m in ("coral_style", "logistic_iso", "evident")}
        out["per_pattern"][pat]["label_rate"] = float(y[idx].mean())

    # ---- factorial ablation (static setting has L5 off; here all 8 subsets of L3b/L4/L5)
    fac = {}
    for keep in itertools.chain.from_iterable(itertools.combinations(LEVELS, k) for k in range(4)):
        drop = frozenset(set(LEVELS) - set(keep))
        p = lopo(rows, "evident", drop)
        fac["+".join(keep) or "none"] = {"brier": brier(p, y), "ece": ece(p, y), "auc": auc(p, y)}
    out["factorial"] = fac

    # ---- prevalence shift: reweight test set to target prevalence; with and without prior correction
    pi0 = y.mean()
    shift = {}
    for pi in (0.1, 0.3, 0.5, 0.7):
        wt = np.where(y == 1, pi / pi0, (1 - pi) / (1 - pi0))
        wt = wt / wt.sum()
        r_odds = (pi / (1 - pi)) / (pi0 / (1 - pi0))
        d = {}
        for m in ("coral_style", "logistic_iso", "evident"):
            p = preds_by["static"][m]
            pc = p * r_odds / (p * r_odds + (1 - p))
            for tag, q in (("raw", p), ("prior_corrected", pc)):
                bins = np.linspace(0, 1, 11)
                e = 0.0
                for i in range(10):
                    mk = (q >= bins[i]) & ((q < bins[i + 1]) if i < 9 else (q <= 1))
                    if mk.any():
                        e += wt[mk].sum() * abs(np.average(q[mk], weights=wt[mk]) - np.average(y[mk], weights=wt[mk]))
                d[f"{m}_{tag}"] = {"brier": float(np.sum(wt * (q - y) ** 2)), "ece": float(e)}
        shift[str(pi)] = d
    out["prevalence_shift"] = shift

    # ---- missing evidence: independent, advisory-correlated, package-correlated, real-world profile
    def masked(mode, q, seed):
        rs = np.random.default_rng(seed)
        keyf = {"independent": lambda r, i: i, "advisory": lambda r, i: (r["dist"], r["advisory"]),
                "package": lambda r, i: r["dist"]}[mode]
        dec = {}
        res = []
        for i, r in enumerate(rows):
            k = keyf(r, i)
            if k not in dec:
                dec[k] = rs.random() < q
            r2 = dict(r)
            if dec[k]:
                r2["L4"], r2["L4_missing"] = "UNKNOWN", True
            res.append(r2)
        return res
    miss = {}
    for mode in ("independent", "advisory", "package"):
        miss[mode] = {}
        for q in (0.25, 0.5, 0.75):
            acc = defaultdict(list)
            for seed in range(5):
                te = masked(mode, q, 100 + seed)
                for m in ("evident", "logistic_iso", "coral_style", "cape_style"):
                    p = lopo(rows, m, frozenset({"L5"}), te)
                    acc[m].append((brier(p, y), ece(p, y)))
            miss[mode][str(q)] = {m: {"brier": float(np.mean([a for a, _ in v])), "ece": float(np.mean([b for _, b in v]))}
                                  for m, v in acc.items()}
    # real-world profile: per-package L4-missing rates observed in the real-world corpus (advisory-correlated)
    rates, overall = realworld_missing_rates()
    if rates is not None:
        acc = defaultdict(list)
        for seed in range(5):
            rs = np.random.default_rng(200 + seed)
            dec, te = {}, []
            for r in rows:
                k = (r["dist"], r["advisory"])
                if k not in dec:
                    dec[k] = rs.random() < rates.get(r["dist"], overall)
                r2 = dict(r)
                if dec[k]:
                    r2["L4"], r2["L4_missing"] = "UNKNOWN", True
                te.append(r2)
            for m in ("evident", "logistic_iso", "coral_style", "cape_style"):
                p = lopo(rows, m, frozenset({"L5"}), te)
                acc[m].append((brier(p, y), ece(p, y)))
        miss["realworld_profile"] = {"overall_rate": overall, "package_rates": {p: rates.get(p, overall) for p in pk},
                                     **{m: {"brier": float(np.mean([a for a, _ in v])),
                                            "ece": float(np.mean([b for _, b in v]))} for m, v in acc.items()}}
    out["missingness"] = miss

    # ---- leave-one-pattern-out (static): generalisation to unseen code patterns
    lpo = {}
    for m in ("coral_style", "logistic_iso", "hgb_iso", "evident"):
        p = np.zeros(len(rows))
        for pat in sorted({r["pattern"] for r in rows}):
            idx = [i for i, r in enumerate(rows) if r["pattern"] == pat]
            tr = [r for r in rows if r["pattern"] != pat]
            p[idx] = fit_predict(m, tr, [rows[i] for i in idx], frozenset({"L5"}))
        lpo[m] = {"brier": brier(p, y), "ece": ece(p, y), "ace": adaptive_ece(p, y), "auc": auc(p, y)}
    out["leave_pattern_out"] = lpo

    # ---- reflection scope on the benchmark: refutations gained vs false refutations
    sc = {}
    for s in ("global", "package", "module", "reachable"):
        ref = [r for r in rows if (r.get("scopes") or {}).get(s) == "REFUTED"]
        sc[s] = {"refuted": len(ref), "false_refutations": sum(r["label"] for r in ref)}
    sc["candidates"] = sum(1 for r in rows if r.get("scopes"))
    out["reflection_scopes"] = sc

    # ---- time split (static setting)
    pub = {(p, a.id): (a.published or "9999")[:4] for p in pk for a in osv.get(p, [])}
    tr = [r for r in rows if pub.get((r["dist"], r["advisory"]), "9999") <= "2024"]
    te = [r for r in rows if pub.get((r["dist"], r["advisory"]), "9999") >= "2025"]
    ts = {"train_rows": len(tr), "test_rows": len(te), "train_advisories": len({(r["dist"], r["advisory"]) for r in tr}),
          "test_advisories": len({(r["dist"], r["advisory"]) for r in te})}
    if tr and te:
        yt = np.array([r["label"] for r in te])
        ts["methods"] = {}
        for m in ("version_match", "coral_style", "cape_style", "logistic_iso", "hgb_iso", "evident"):
            p = fit_predict(m, tr, te, frozenset({"L5"}))
            ts["methods"][m] = {"brier": brier(p, yt), "ece": ece(p, yt), "auc": auc(p, yt)}
    out["time_split"] = ts

    # ---- parameters: interpretability
    final = StagedModel().fit([to_finding(r, frozenset({"L5"})) for r in rows], [r["label"] for r in rows])
    final_rt = StagedModel().fit([to_finding(r) for r in rows], [r["label"] for r in rows])
    out["final_model_static"] = json.loads(final.to_json())
    out["final_model_runtime"] = json.loads(final_rt.to_json())
    out["n_parameters"] = {"evident": 1 + len(final.p_import) + len(final.p_call) + len(final.p_call_l4) +
                           len(final.p_call_l5) + 2,
                           "logistic": len(features(to_finding(rows[0]))) + 1}
    (RES / "staged_model.json").write_text(final.to_json(), "utf8")
    (RES / "staged_model_runtime.json").write_text(final_rt.to_json(), "utf8")
    (RES / "bench_eval.json").write_text(json.dumps(out, indent=1, default=float), "utf8")
    for s in ("static", "runtime"):
        print("==", s)
        for m in METHODS:
            d = results[s][m]
            print(f"  {m:14s} brier={d['brier']:.3f} {d['ci']['brier']} ece={d['ece']:.3f} auc={d['auc']:.3f} "
                  f"AP={d['AP']:.3f} slope={d['slope']:.2f}")
        print("  paired", json.dumps(results[s]["paired"]["evident-logistic_iso"]))
    print("leave-pattern-out", json.dumps(lpo))
    print("reflection scopes", json.dumps(sc))
    print("sample flow", out["sample_flow"])
    print("leakage", out["leakage_audit"])
    print("missing realworld", json.dumps(miss.get("realworld_profile", {}))[:400])


def realworld_missing_rates():
    d = RES / "realworld"
    if not d.exists():
        return None, None
    cnt = defaultdict(lambda: [0, 0])
    for f in d.glob("*/findings.json"):
        for r in json.loads(f.read_text("utf8")):
            if r.get("L3_state") != "CONFIRMED" or r.get("L3b_state") != "CONFIRMED":
                continue
            ev = r["evidence"].get("L4", {})
            miss = ev.get("state") == "UNKNOWN" and ev.get("detail", {}).get("missing")
            cnt[r["package"]][0] += int(bool(miss))
            cnt[r["package"]][1] += 1
    if not cnt:
        return None, None
    tot = sum(v[0] for v in cnt.values()) / max(sum(v[1] for v in cnt.values()), 1)
    return {p: v[0] / v[1] for p, v in cnt.items() if v[1] >= 3}, tot


if __name__ == "__main__":
    main()
