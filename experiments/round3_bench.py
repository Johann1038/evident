"""Third-round benchmark analyses (static setting, no L5), on the saved EVIDENT-Bench records.

  refutations    REFUTED verdicts by level/reason; exact (Clopper-Pearson) upper bounds on false-refutation rates
  factorisation  staged model vs a joint evidence-configuration model, logistic regression and a single-level
                 baseline, all leave-one-package-out: isolates the cost of the conditional-independence factorisation
  subgroups      calibration of the staged model's final probability within evidence subgroups
  uncertainty    package-grouped bootstrap CIs for leave-one-pattern-out and the time split
  missingness    exact description of the L4-masking generator (written out for reproducibility)
Writes data/results/round3_bench.json. Runtime: about a minute.
"""
from __future__ import annotations

import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np
from scipy.stats import beta

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import analyze_bench as AB  # noqa: E402
from evident.exposure import auc, brier, ece  # noqa: E402

RES = AB.RES
STATIC = frozenset({"L5"})
B = 1000


def cp_upper(k: int, n: int, a: float = 0.05) -> float:
    """One-sided 95% Clopper-Pearson upper bound for a binomial rate."""
    return 1.0 if n == 0 else float(beta.ppf(1 - a, k + 1, n - k))


def joint_predict(tr, te, a0: float = 1.0, min_n: int = 5):
    """Joint model: P(Y | full static evidence configuration), Beta-smoothed, backed off to the marginal."""
    key = lambda r: (r["L3b"], r["L4"], bool(r.get("L4_missing")))
    cnt = defaultdict(lambda: [0, 0])
    for r in tr:
        cnt[key(r)][0] += r["label"]
        cnt[key(r)][1] += 1
    base = np.mean([r["label"] for r in tr])
    out = []
    for r in te:
        k, n = cnt.get(key(r), (0, 0))
        out.append((k + a0 * 2 * base) / (n + 2 * a0) if n >= min_n else base)
    return np.array(out)


def single_level_predict(tr, te, a0: float = 1.0):
    """Simpler conditional baseline: P(Y | L4 verdict) only."""
    cnt = defaultdict(lambda: [0, 0])
    for r in tr:
        cnt[r["L4"]][0] += r["label"]
        cnt[r["L4"]][1] += 1
    base = np.mean([r["label"] for r in tr])
    return np.array([(cnt[r["L4"]][0] + a0 * 2 * base) / (cnt[r["L4"]][1] + 2 * a0) for r in te])


def lopo_custom(rows, fn):
    p = np.zeros(len(rows))
    by = defaultdict(list)
    for i, r in enumerate(rows):
        by[r["dist"]].append(i)
    for hold, idx in by.items():
        p[idx] = fn([r for r in rows if r["dist"] != hold], [rows[i] for i in idx])
    return p


def grouped_ci(rows, preds: dict, y, stat=brier, seed=7):
    """Package-grouped bootstrap: resample packages with replacement."""
    rs = np.random.default_rng(seed)
    by = defaultdict(list)
    for i, r in enumerate(rows):
        by[r["dist"]].append(i)
    groups = list(by.values())
    acc = defaultdict(list)
    for _ in range(B):
        idx = np.concatenate([groups[j] for j in rs.integers(0, len(groups), len(groups))])
        for m, p in preds.items():
            acc[m].append(stat(p[idx], y[idx]))
    return {m: [float(np.percentile(v, 2.5)), float(np.percentile(v, 97.5))] for m, v in acc.items()}


def main():
    raw = [json.loads(ln) for ln in (RES / "bench_records.jsonl").read_text("utf8").splitlines() if ln.strip()]
    rows = [r for r in raw if not (r.get("prod_error") and r["label"] == 0 and r["pattern"].startswith("E"))]
    y = np.array([r["label"] for r in rows])
    out = {"n": len(rows)}

    # ---- refutation reconciliation
    ref = [r for r in rows if r["L4"] == "REFUTED"]
    reasons = Counter(r["L4_reason"].split(" (")[0] for r in ref)
    imp_nopath = [r for r in rows if r["L3b"] == "CONFIRMED" and r.get("scopes")]
    out["refutations"] = {
        "L3b_refuted": sum(1 for r in rows if r["L3b"] == "REFUTED"),
        "L3b_refuted_exposed": sum(r["label"] for r in rows if r["L3b"] == "REFUTED"),
        "L4_refuted_total": len(ref), "L4_refuted_exposed": int(sum(r["label"] for r in ref)),
        "L4_refuted_by_reason": dict(reasons),
        "imported_without_strong_path": len(imp_nopath),
        "imported_path_refuted": sum(1 for r in imp_nopath if r["L4"] == "REFUTED"),
        "imported_blocked_by_reflection": sum(1 for r in imp_nopath if r["L4"] == "UNKNOWN"),
        "upper95_false_refutation_all": cp_upper(int(sum(r["label"] for r in ref)), len(ref)),
        "upper95_false_refutation_path": cp_upper(0, reasons.get("no path even with over-approximation", 0)),
        "upper95_false_refutation_L3b": cp_upper(0, sum(1 for r in rows if r["L3b"] == "REFUTED")),
    }

    # ---- factorisation: staged vs joint vs logistic vs single level (static, leave-one-package-out)
    preds = {"staged": AB.lopo(rows, "evident", STATIC),
             "joint_configuration": lopo_custom(rows, joint_predict),
             "logistic_iso": AB.lopo(rows, "logistic_iso", STATIC),
             "single_level_L4": lopo_custom(rows, single_level_predict)}
    ci = grouped_ci(rows, preds, y)
    out["factorisation"] = {m: {"brier": brier(p, y), "brier_ci": ci[m], "ece": ece(p, y), "auc": auc(p, y)}
                            for m, p in preds.items()}
    d = preds["staged"] - preds["joint_configuration"]
    rs = np.random.default_rng(11)
    by = defaultdict(list)
    for i, r in enumerate(rows):
        by[r["dist"]].append(i)
    groups = list(by.values())
    diffs = []
    for _ in range(B):
        idx = np.concatenate([groups[j] for j in rs.integers(0, len(groups), len(groups))])
        diffs.append(brier(preds["staged"][idx], y[idx]) - brier(preds["joint_configuration"][idx], y[idx]))
    out["factorisation"]["staged_minus_joint_brier"] = {
        "mean": float(brier(preds["staged"], y) - brier(preds["joint_configuration"], y)),
        "ci": [float(np.percentile(diffs, 2.5)), float(np.percentile(diffs, 97.5))],
        "max_abs_prob_diff": float(np.abs(d).max())}

    # ---- subgroup calibration of the staged model's final probability
    p = preds["staged"]
    groups_def = {
        "strong_reachability (L4 CONFIRMED)": lambda r: r["L4"] == "CONFIRMED",
        "weak_reachability (L4 POSSIBLE)": lambda r: r["L4"] == "POSSIBLE",
        "reflection_blocked (L4 UNKNOWN)": lambda r: r["L4"] == "UNKNOWN",
        "path_refuted (L4 REFUTED, imported)": lambda r: r["L4"] == "REFUTED" and r["L3b"] == "CONFIRMED",
        "not_imported (L3b REFUTED)": lambda r: r["L3b"] == "REFUTED",
    }
    sub = {}
    for name, fn in groups_def.items():
        idx = np.array([i for i, r in enumerate(rows) if fn(r)])
        if not len(idx):
            continue
        k = int(y[idx].sum())
        lo = float(beta.ppf(0.025, k, len(idx) - k + 1)) if k > 0 else 0.0
        hi = float(beta.ppf(0.975, k + 1, len(idx) - k)) if k < len(idx) else 1.0
        sub[name] = {"n": int(len(idx)), "mean_p": float(p[idx].mean()), "observed": float(y[idx].mean()),
                     "observed_ci": [lo, hi], "abs_gap": float(abs(p[idx].mean() - y[idx].mean()))}
    # missing symbol information: mask L4 per advisory at the real-world rate and evaluate those masked rows
    rates, overall = AB.realworld_missing_rates()
    rs = np.random.default_rng(300)
    dec, te = {}, []
    for r in rows:
        k_ = (r["dist"], r["advisory"])
        if k_ not in dec:
            dec[k_] = rs.random() < (overall if overall is not None else 0.5)
        r2 = dict(r)
        if dec[k_]:
            r2["L4"], r2["L4_missing"] = "UNKNOWN", True
        te.append(r2)
    pm = AB.lopo(rows, "evident", STATIC, te)
    idx = np.array([i for i, r in enumerate(te) if r.get("L4_missing")])
    if len(idx):
        k = int(y[idx].sum())
        sub["missing_symbol_info (L4 masked)"] = {
            "n": int(len(idx)), "mean_p": float(pm[idx].mean()), "observed": float(y[idx].mean()),
            "observed_ci": [float(beta.ppf(0.025, k, len(idx) - k + 1)), float(beta.ppf(0.975, k + 1, len(idx) - k))],
            "abs_gap": float(abs(pm[idx].mean() - y[idx].mean())), "mask_rate": overall}
    sub["development_only"] = {"n": 0, "note": "not present in EVIDENT-Bench (all applications install the package "
                                                "for production); evaluated only through the delta sensitivity"}
    out["subgroups"] = sub

    # ---- uncertainty for leave-one-pattern-out and time split
    lpo = {}
    for m in ("coral_style", "logistic_iso", "evident"):
        pp = np.zeros(len(rows))
        for pat in sorted({r["pattern"] for r in rows}):
            ix = [i for i, r in enumerate(rows) if r["pattern"] == pat]
            pp[ix] = AB.fit_predict(m, [r for r in rows if r["pattern"] != pat], [rows[i] for i in ix], STATIC)
        lpo[m] = pp
    lci = grouped_ci(rows, lpo, y)
    out["leave_pattern_out"] = {m: {"brier": brier(pp, y), "brier_ci": lci[m]} for m, pp in lpo.items()}
    osv = AB.load_osv()
    pub = {(r["dist"], r["advisory"]): next(((a.published or "9999")[:4] for a in osv.get(r["dist"], [])
                                             if a.id == r["advisory"]), "9999") for r in rows}
    tr = [r for r in rows if pub[(r["dist"], r["advisory"])] <= "2024"]
    te_ = [r for r in rows if pub[(r["dist"], r["advisory"])] >= "2025"]
    yt = np.array([r["label"] for r in te_])
    tsp = {m: AB.fit_predict(m, tr, te_, STATIC) for m in ("coral_style", "logistic_iso", "evident")}
    tci = grouped_ci(te_, tsp, yt)
    out["time_split"] = {m: {"brier": brier(pp, yt), "brier_ci": tci[m]} for m, pp in tsp.items()} | {
        "train_rows": len(tr), "test_rows": len(te_)}

    # ---- missingness generator (documentation of the procedure used in analyze_bench.py)
    out["missingness_generator"] = {
        "level_masked": "L4 only (state set to UNKNOWN with missing=True); L3b and labels untouched",
        "modes": {"independent": "each (application, advisory) pair masked i.i.d. with probability q",
                  "advisory": "one Bernoulli(q) draw per (package, advisory); all its applications share it",
                  "package": "one Bernoulli(q) draw per package; all its advisories and applications share it",
                  "realworld_profile": "one draw per (package, advisory) with q = that package's share of imported "
                                       "real-world findings whose L4 is missing (packages with >= 3 such findings; "
                                       "otherwise the corpus-wide share)"},
        "rates": [0.25, 0.5, 0.75], "seeds_per_setting": 5, "label_independent": True,
        "same_masks_for_all_models": True,
        "realworld_rate_overall": overall, "realworld_packages_with_rate": len(rates or {}),
        "training": "models are trained on unmasked rows of the other packages (leave-one-package-out); only the "
                    "held-out package's rows are masked"}
    (RES / "round3_bench.json").write_text(json.dumps(out, indent=1, default=float), "utf8")
    print(json.dumps({k: out[k] for k in ("refutations", "factorisation", "subgroups")}, indent=1, default=float))
    print(json.dumps({k: out[k] for k in ("leave_pattern_out", "time_split")}, indent=1, default=float))


if __name__ == "__main__":
    main()
