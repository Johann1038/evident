"""Evidence-calibrated exposure probabilities.

EVIDENT decomposes exposure Y ("vulnerable code executes in the deployed application") into stages

    Y = D * I * M * C
        D deployed      the package is part of the production (non-dev) environment
        I installed     the package is installed in the target environment
        M imported      a module of the package is loaded by application code
        C called        a vulnerable symbol executes, given the package is imported

Each analysis emits a verdict about one stage. Verdicts are noisy (static analysis is neither sound
nor precise for Python), so the model learns, from labelled data, the verdict-conditional stage
probabilities P(stage | verdict) with Beta(1,1) smoothing. UNKNOWN verdicts fall back to the stage
prior, so missing evidence is neutral rather than negative. A runtime observation (L5 OBSERVED) is
treated as decisive for C; NOT_OBSERVED is an ordinary, learned verdict (absence of evidence is
not evidence of absence unless the data say so).

    P(Y=1 | E) = P(D|E_D) * P(I|E_I) * P(M|E_M) * P(C | E_L4, E_L5, granularity)

The baselines compared in the paper are implemented here as well.
"""
from __future__ import annotations

import json
import math
from collections import defaultdict
from dataclasses import dataclass, field

import numpy as np

from .evidence import CONFIRMED, NOT_OBSERVED, OBSERVED, POSSIBLE, REFUTED, UNKNOWN, Finding


MISSING = "MISSING"


def _key_c(l4: str, l5: str, gran: str) -> str:
    return f"{l4}|{l5}|{gran}"


def _st(f: Finding, level: str) -> str:
    """Verdict, distinguishing *inconclusive* (UNKNOWN: the analysis ran but could not decide) from
    *missing* evidence (the analysis did not run / had no input), which must not shift the estimate."""
    e = f.evidence.get(level)
    if e is None:
        return MISSING
    if e.state == UNKNOWN and (e.detail.get("missing") or level == "L5"):
        return MISSING
    return e.state


@dataclass
class StagedModel:
    """Learned verdict-conditional probabilities with hierarchical back-off."""
    p_dev_deployed: float = 0.05
    p_import: dict = field(default_factory=lambda: {CONFIRMED: 0.97, REFUTED: 0.03, UNKNOWN: 0.6})
    p_call: dict = field(default_factory=dict)    # key l4|l5|gran -> prob
    p_call_l4: dict = field(default_factory=dict)  # back-off by L4 only (marginal over L5)
    p_call_l5: dict = field(default_factory=dict)  # back-off by L5 only (marginal over L4)
    p_import_marg: float = 0.6
    prior_call: float = 0.35
    counts: dict = field(default_factory=dict)

    def fit(self, findings: list[Finding], labels: list[int], a: float = 1.0, b: float = 1.0) -> "StagedModel":
        """Fit P(M|L3b) and P(C|L4,L5,gran) from labelled findings (labels: 1 exposed, 0 not)."""
        imp = defaultdict(lambda: [0, 0])
        call = defaultdict(lambda: [0, 0])
        call4 = defaultdict(lambda: [0, 0])
        call5 = defaultdict(lambda: [0, 0])
        for f, y in zip(findings, labels):
            if f.state("L3") == REFUTED or (f.evidence.get("L3") and f.evidence["L3"].detail.get("scope") == "dev"):
                continue
            m_state = _st(f, "L3b")
            # stage label for M: exposed implies imported; for non-exposed we use the import label if known
            m_lab = f.evidence["L3b"].detail.get("label_imported") if f.evidence.get("L3b") else None
            if m_lab is None:
                # exposed implies imported; otherwise fall back to a confirmed import verdict
                m_lab = 1 if (y or m_state == CONFIRMED) else None
            if m_lab is not None and m_state != MISSING:
                imp[m_state][0] += m_lab
                imp[m_state][1] += 1
            if m_lab == 1 or y == 1:
                l4, l5 = _st(f, "L4"), _st(f, "L5")
                if l4 != MISSING and l5 != MISSING:
                    k = _key_c(l4, l5, _gran(f))
                    call[k][0] += y
                    call[k][1] += 1
                if l4 != MISSING:
                    call4[l4][0] += y
                    call4[l4][1] += 1
                if l5 != MISSING:
                    call5[l5][0] += y
                    call5[l5][1] += 1
        tot_y = sum(v[0] for v in call4.values())
        tot_n = sum(v[1] for v in call4.values())
        self.prior_call = (tot_y + a) / (tot_n + a + b) if tot_n else self.prior_call
        iy, inn = sum(v[0] for v in imp.values()), sum(v[1] for v in imp.values())
        self.p_import_marg = (iy + a) / (inn + a + b) if inn else self.p_import_marg
        for s, (y, n) in imp.items():
            self.p_import[s] = (y + a) / (n + a + b)
        for k, (y, n) in call4.items():
            self.p_call_l4[k] = (y + a * self.prior_call * 2) / (n + 2 * a)
        for k, (y, n) in call5.items():
            self.p_call_l5[k] = (y + a * self.prior_call * 2) / (n + 2 * a)
        for k, (y, n) in call.items():
            l4 = k.split("|")[0]
            base = self.p_call_l4.get(l4, self.prior_call)
            self.p_call[k] = (y + 2 * a * base) / (n + 2 * a)   # shrink towards the L4 back-off
        self.counts = {"import": {k: list(v) for k, v in imp.items()},
                       "call": {k: list(v) for k, v in call.items()}}
        return self

    def stage_probs(self, f: Finding) -> dict:
        l3 = f.evidence.get("L3")
        if f.state("L3") == REFUTED:
            p_i = 0.0
        elif f.state("L3") == CONFIRMED:
            p_i = 1.0
        else:
            p_i = 0.8
        p_d = self.p_dev_deployed if (l3 and l3.detail.get("scope") == "dev") else 1.0
        m_state = _st(f, "L3b")
        p_m = self.p_import_marg if m_state == MISSING else self.p_import.get(m_state, self.p_import_marg)
        l4, l5 = _st(f, "L4"), _st(f, "L5")
        if l5 == OBSERVED:
            p_c = 1.0
        elif l4 != MISSING and l5 != MISSING:
            p_c = self.p_call.get(_key_c(l4, l5, _gran(f)), self.p_call_l4.get(l4, self.prior_call))
        elif l4 != MISSING:
            p_c = self.p_call_l4.get(l4, self.prior_call)
        elif l5 != MISSING:
            p_c = self.p_call_l5.get(l5, self.prior_call)
        else:
            p_c = self.prior_call
        return {"D": p_d, "I": p_i, "M": p_m, "C": p_c}

    def predict(self, f: Finding) -> float:
        s = self.stage_probs(f)
        return float(s["D"] * s["I"] * s["M"] * s["C"])

    def to_json(self) -> str:
        return json.dumps({"p_dev_deployed": self.p_dev_deployed, "p_import": self.p_import,
                           "p_import_marg": self.p_import_marg, "p_call": self.p_call, "p_call_l4": self.p_call_l4,
                           "p_call_l5": self.p_call_l5, "prior_call": self.prior_call, "counts": self.counts},
                          indent=1)

    @classmethod
    def from_json(cls, s: str) -> "StagedModel":
        d = json.loads(s)
        m = cls()
        m.p_dev_deployed = d["p_dev_deployed"]
        m.p_import = d["p_import"]
        m.p_call = d["p_call"]
        m.p_call_l4 = d["p_call_l4"]
        m.p_call_l5 = d.get("p_call_l5", {})
        m.p_import_marg = d.get("p_import_marg", m.p_import_marg)
        m.prior_call = d["prior_call"]
        m.counts = d.get("counts", {})
        return m


def _gran(f: Finding) -> str:
    e = f.evidence.get("L4")
    return (e.detail.get("granularity") if e else None) or "none"


# ------------------------------------------------------------------ baselines
def p_version_match(f: Finding) -> float:
    """Conventional SBOM scanner: every version match is treated as exposed."""
    return 1.0


def p_coral_style(f: Finding) -> float:
    """Fixed ordinal reachability coefficients (CORAL-style: reachable > unknown > unreachable)."""
    s = f.state("L4")
    return {CONFIRMED: 1.0, POSSIBLE: 0.5, UNKNOWN: 0.5, REFUTED: 0.1}.get(s, 0.5)


CAPE_W = {"version": 0.15, "install": 0.20, "import": 0.25, "reach": 0.40}


def p_cape_style(f: Finding) -> float:
    """Weighted evidence score with weight redistribution over missing dimensions (CAPE-style)."""
    vals = {"version": 1.0}
    if f.state("L3") != UNKNOWN:
        vals["install"] = 0.0 if f.state("L3") == REFUTED else (0.3 if f.evidence["L3"].detail.get("scope") == "dev" else 1.0)
    if f.state("L3b") != UNKNOWN:
        vals["import"] = 1.0 if f.state("L3b") == CONFIRMED else 0.0
    if f.state("L4") != UNKNOWN:
        vals["reach"] = {CONFIRMED: 1.0, POSSIBLE: 0.5, REFUTED: 0.0}[f.state("L4")]
    w = sum(CAPE_W[k] for k in vals)
    return sum(CAPE_W[k] * v for k, v in vals.items()) / w


def features(f: Finding) -> list[float]:
    """One-hot evidence features for the unstructured (logistic) baseline."""
    out = []
    for lvl, states in (("L3", (CONFIRMED, REFUTED, UNKNOWN)), ("L3b", (CONFIRMED, REFUTED, UNKNOWN)),
                        ("L4", (CONFIRMED, POSSIBLE, REFUTED, UNKNOWN)), ("L5", (OBSERVED, NOT_OBSERVED))):
        s = f.state(lvl) if lvl == "L3" else _st(f, lvl)   # MISSING -> all-zero block
        out += [1.0 if s == x else 0.0 for x in states]
    out.append(1.0 if (f.evidence.get("L3") and f.evidence["L3"].detail.get("scope") == "dev") else 0.0)
    out.append({"function": 1.0, "module": 0.5}.get(_gran(f), 0.0))
    return out


# ------------------------------------------------------------------ metrics
def brier(p, y) -> float:
    p, y = np.asarray(p, float), np.asarray(y, float)
    return float(np.mean((p - y) ** 2))


def ece(p, y, bins: int = 10) -> float:
    p, y = np.asarray(p, float), np.asarray(y, float)
    edges = np.linspace(0, 1, bins + 1)
    tot = 0.0
    for i in range(bins):
        m = (p >= edges[i]) & ((p < edges[i + 1]) if i < bins - 1 else (p <= edges[i + 1]))
        if m.any():
            tot += m.mean() * abs(p[m].mean() - y[m].mean())
    return float(tot)


def log_loss(p, y) -> float:
    p = np.clip(np.asarray(p, float), 1e-4, 1 - 1e-4)
    y = np.asarray(y, float)
    return float(-np.mean(y * np.log(p) + (1 - y) * np.log(1 - p)))


def auc(p, y) -> float:
    p, y = np.asarray(p, float), np.asarray(y, int)
    pos, neg = p[y == 1], p[y == 0]
    if len(pos) == 0 or len(neg) == 0:
        return float("nan")
    gt = (pos[:, None] > neg[None, :]).sum() + 0.5 * (pos[:, None] == neg[None, :]).sum()
    return float(gt / (len(pos) * len(neg)))


def ranking_metrics(scores, rel, ks=(5, 10, 20)) -> dict:
    order = np.argsort(-np.asarray(scores, float), kind="stable")
    rel = np.asarray(rel, float)[order]
    out = {}
    npos = rel.sum()
    for k in ks:
        k2 = min(k, len(rel))
        out[f"P@{k}"] = float(rel[:k2].mean()) if k2 else float("nan")
        out[f"R@{k}"] = float(rel[:k2].sum() / npos) if npos else float("nan")
        dcg = float(sum(r / math.log2(i + 2) for i, r in enumerate(rel[:k2])))
        ideal = sorted(rel, reverse=True)[:k2]
        idcg = float(sum(r / math.log2(i + 2) for i, r in enumerate(ideal)))
        out[f"NDCG@{k}"] = dcg / idcg if idcg else float("nan")
    hits, ap = 0, 0.0
    for i, r in enumerate(rel):
        if r:
            hits += 1
            ap += hits / (i + 1)
    out["AP"] = ap / npos if npos else float("nan")
    return out
