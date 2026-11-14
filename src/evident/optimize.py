"""Evidence-weighted, constraint-aware remediation with a resolver in the loop.

Decision variables x[p,v] choose one version v for every package p in the remediation scope
(vulnerable packages plus the parents/children whose version constraints interact with them).

    minimise   sum_{p,v} x[p,v] * ( R(p,v) + lambda * Cost(p,v) )
    R(p,v)   = sum_{a affects p@v} w_a * P_a        (expected residual risk; P_a from the exposure model)
    Cost(p,v)= change + semver distance + direct-dependency + usage-aware API-break penalty

subject to PyPI requires_dist constraints between scope members (evaluated for the target
environment). The plan is verified by uv; on failure the assignment is excluded with a no-good cut
and the model is re-solved (counter-example guided). A lambda sweep gives the risk/cost Pareto front.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ortools.sat.python import cp_model
from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

from . import pypi
from .graph import TargetEnv, marker_ok
from .intel import advisories_for, load_osv, severity_weight
from .util import norm

SCALE = 1000


def _V(s):
    try:
        return Version(s)
    except InvalidVersion:
        return None


def _spec(s: str) -> SpecifierSet | None:
    try:
        return SpecifierSet(s or "")
    except InvalidSpecifier:
        return None


def deps_of(name: str, version: str, tenv: TargetEnv) -> dict[str, SpecifierSet]:
    """Non-extra runtime requirements of name==version under the target environment."""
    out = {}
    for s in pypi.requires_dist(name, version):
        try:
            r = Requirement(s)
        except InvalidRequirement:
            continue
        mk = str(r.marker or "")
        if "extra" in mk:
            continue
        if not marker_ok(mk, tenv, extras_true=False):
            continue
        out[norm(r.name)] = r.specifier
    return out


_TAGS: dict[str, frozenset] = {}


def supported_tags(python: str) -> frozenset:
    """Wheel tags installable on CPython `python` / Linux x86-64 / manylinux2014 (glibc 2.17), the resolver's target."""
    if python not in _TAGS:
        from packaging import tags
        major, minor = (int(x) for x in python.split(".")[:2])
        plats = [f"manylinux_2_{g}_x86_64" for g in range(17, 4, -1)] + \
                ["manylinux2014_x86_64", "manylinux2010_x86_64", "manylinux1_x86_64", "linux_x86_64"]
        ts = set(tags.cpython_tags((major, minor), platforms=plats))
        ts |= set(tags.compatible_tags((major, minor), interpreter=f"cp{major}{minor}", platforms=plats))
        _TAGS[python] = frozenset(ts)
    return _TAGS[python]


def usable_wheel(files: list[dict], python: str) -> bool:
    """True if some non-yanked wheel installs on the target interpreter and platform."""
    from packaging.utils import InvalidWheelFilename, parse_wheel_filename
    sup = supported_tags(python)
    full = python + ".12"
    for f in files:
        if f.get("packagetype") != "bdist_wheel" or f.get("yanked"):
            continue
        rp = f.get("requires_python")
        if rp:
            spec = _spec(rp)
            if spec is not None and not spec.contains(full, prereleases=True):
                continue
        try:
            _, _, _, tg = parse_wheel_filename(f["filename"])
        except (InvalidWheelFilename, KeyError):
            continue
        if tg & sup:
            return True
    return False


def wheel_releases_after(p: str, cur: str, today: str, python: str = "3.10") -> list[Version]:
    """Releases newer than `cur` with a wheel usable on the target (resolution never builds sdists)."""
    cv = _V(cur)
    later = [v for v, _ in pypi.releases(p, before=today) if cv is None or v > cv]
    j = pypi.project(p) or {}
    files = j.get("releases") or {}
    out = []
    for v in later:
        fl = files.get(str(v)) or next((f for k, f in files.items() if _V(k) == v), [])
        if usable_wheel(fl, python):
            out.append(v)
    return out


def semver_cost(cur: str, new: str) -> float:
    a, b = _V(cur), _V(new)
    if a is None or b is None or a == b:
        return 0.0
    if b.major != a.major:
        return 2.0
    if b.minor != a.minor:
        return 0.7
    return 0.2


@dataclass
class Plan:
    name: str
    changes: dict[str, str]
    objective: float = 0.0
    residual_model: float = 0.0
    cost_model: float = 0.0
    verified: bool | None = None
    realised: dict[str, str] = field(default_factory=dict)
    iterations: int = 0
    error: str = ""


class Remediator:
    def __init__(self, pins: dict[str, str], direct: set[str], findings, tenv: TargetEnv, *,
                 today: str, p_of, p_new_of, max_cands: int = 6, api_breaks=None, sev_fn=None,
                 agg: str = "sum"):
        """
        pins       installed versions {pkg: version} in the target env
        findings   current findings (with .package, .advisory, .severity_w)
        p_of(f)    exposure probability for a finding
        p_new_of(p) exposure probability for a *new* advisory on package p (stage prior)
        api_breaks optional f(pkg, cur, new) -> number of app-used symbols missing in new
        """
        self.pins, self.direct, self.tenv, self.today = pins, direct, tenv, today
        self.p_of, self.p_new_of = p_of, p_new_of
        self.max_cands = max_cands
        self.api_breaks = api_breaks
        self.sev_fn = sev_fn or severity_weight
        self.agg = agg
        self.cur_p: dict[tuple[str, str], float] = {}
        for f in findings:
            self.cur_p[(f.package, f.advisory)] = max(self.cur_p.get((f.package, f.advisory), 0.0), p_of(f))
        self.vuln_pkgs = sorted({f.package for f in findings})
        self.cands: dict[str, list[str]] = {}
        self.req: dict[tuple[str, str], dict[str, SpecifierSet]] = {}
        self.risk: dict[tuple[str, str], float] = {}
        self.cost: dict[tuple[str, str], float] = {}
        self._parents = None

    # ------------------------------------------------------------ candidates
    def candidates(self, p: str) -> list[str]:
        if p in self.cands:
            return self.cands[p]
        cur = self.pins[p]
        cv = _V(cur)
        later = wheel_releases_after(p, cur, self.today, self.tenv.python)
        advs = load_osv().get(p, [])
        cand = {cur}

        def clean(v, only=None):
            return not any(a.affects(str(v)) for a in advs if (only is None or a.id in only))
        cur_ids = {a for (pp, a) in self.cur_p if pp == p}
        first_fix = next((v for v in later if clean(v, cur_ids)), None)
        first_clean = next((v for v in later if clean(v)), None)
        if first_fix:
            cand.add(str(first_fix))
        if first_clean:
            cand.add(str(first_clean))
        if cv is not None:
            same_minor = [v for v in later if v.major == cv.major and v.minor == cv.minor]
            same_major = [v for v in later if v.major == cv.major]
            if same_minor:
                cand.add(str(same_minor[-1]))
            if same_major:
                cand.add(str(same_major[-1]))
        if later:
            cand.add(str(later[-1]))
        out = sorted(cand, key=lambda s: _V(s) or Version("0"))
        if len(out) > self.max_cands:
            keep = {cur, str(first_fix) if first_fix else cur, str(later[-1]) if later else cur}
            rest = [v for v in out if v not in keep]
            out = sorted(keep | set(rest[: self.max_cands - len(keep)]), key=lambda s: _V(s) or Version("0"))
        self.cands[p] = out
        return out

    def _req(self, p: str, v: str) -> dict[str, SpecifierSet]:
        k = (p, v)
        if k not in self.req:
            self.req[k] = deps_of(p, v, self.tenv)
        return self.req[k]

    def parents(self) -> dict[str, set[str]]:
        if self._parents is None:
            par: dict[str, set[str]] = {}
            for q, v in self.pins.items():
                for c in self._req(q, v):
                    if c in self.pins:
                        par.setdefault(c, set()).add(q)
            self._parents = par
        return self._parents

    def _risk(self, p: str, v: str) -> float:
        k = (p, v)
        if k not in self.risk:
            terms = []
            for a in advisories_for(p, v):
                pa = self.cur_p.get((p, a.id))
                if pa is None:
                    pa = self.p_new_of(p)
                terms.append(self.sev_fn(a) * pa)
            self.risk[k] = (max(terms) if terms else 0.0) if self.agg == "max" else sum(terms)
        return self.risk[k]

    def _cost(self, p: str, v: str) -> float:
        k = (p, v)
        if k not in self.cost:
            cur = self.pins[p]
            if v == cur:
                c = 0.0
            else:
                c = 1.0 + semver_cost(cur, v) + (0.5 if p in self.direct else 0.0)
                if self.api_breaks and p in self.direct and semver_cost(cur, v) >= 0.7:
                    c += 0.5 * self.api_breaks(p, cur, v)
            self.cost[k] = c
        return self.cost[k]

    # ------------------------------------------------------------ scope
    def scope(self, rounds: int = 2) -> list[str]:
        sc = set(p for p in self.vuln_pkgs if p in self.pins)
        par = self.parents()
        for _ in range(rounds):
            add = set()
            for p in sc:
                cands = self.candidates(p)
                for q in par.get(p, ()):
                    if q in sc:
                        continue
                    spec = self._req(q, self.pins[q]).get(p)
                    if spec is not None and any(not spec.contains(v, prereleases=True) for v in cands):
                        add.add(q)
                for v in cands:
                    for c, spec in self._req(p, v).items():
                        if c in self.pins and c not in sc and not spec.contains(self.pins[c], prereleases=True):
                            add.add(c)
            if not add:
                break
            sc |= add
        return sorted(sc)

    # ------------------------------------------------------------ model
    def solve(self, lam: float, *, nogoods=(), p_override: dict | None = None, time_limit: float = 20.0):
        sc = self.scope()
        if p_override:
            saved = dict(self.cur_p)
            self.cur_p.update(p_override)
            self.risk.clear()
        m = cp_model.CpModel()
        x = {}
        for p in sc:
            for v in self.candidates(p):
                x[p, v] = m.NewBoolVar(f"x_{p}_{v}")
            m.AddExactlyOne(x[p, v] for v in self.candidates(p))
        scs = set(sc)
        # requirement constraints: q@u requires p in spec
        for q in sc:
            for u in self.candidates(q):
                for p, spec in self._req(q, u).items():
                    if p not in self.pins:
                        continue
                    if p in scs:
                        allowed = [x[p, v] for v in self.candidates(p) if spec.contains(v, prereleases=True)]
                        if allowed:
                            m.AddBoolOr(allowed).OnlyEnforceIf(x[q, u])
                        else:
                            m.Add(x[q, u] == 0)
                    elif not spec.contains(self.pins[p], prereleases=True):
                        m.Add(x[q, u] == 0)   # would require changing an out-of-scope package
        # out-of-scope parents constrain in-scope children
        par = self.parents()
        for p in sc:
            for q in par.get(p, ()):
                if q in scs:
                    continue
                spec = self._req(q, self.pins[q]).get(p)
                if spec is None:
                    continue
                for v in self.candidates(p):
                    if not spec.contains(v, prereleases=True):
                        m.Add(x[p, v] == 0)
        for ng in nogoods:
            lits = [x[p, v] for p, v in ng if (p, v) in x]
            if lits:
                m.AddBoolOr([lit.Not() for lit in lits])
        obj = []
        for (p, v), var in x.items():
            coef = int(round(SCALE * (self._risk(p, v) + lam * self._cost(p, v))))
            if coef:
                obj.append(coef * var)
        m.Minimize(sum(obj) if obj else 0)
        s = cp_model.CpSolver()
        s.parameters.max_time_in_seconds = time_limit
        s.parameters.num_workers = 8
        st = s.Solve(m)
        if p_override:
            self.cur_p = saved
            self.risk.clear()
        if st not in (cp_model.OPTIMAL, cp_model.FEASIBLE):
            return None
        ch, R, C = {}, 0.0, 0.0
        for (p, v), var in x.items():
            if s.Value(var):
                R += self._risk(p, v)
                C += self._cost(p, v)
                if v != self.pins[p]:
                    ch[p] = v
        return Plan("evident", ch, objective=R + lam * C, residual_model=R, cost_model=C)

    def plan_verified(self, lam: float, verify, max_iter: int = 6, name: str = "evident") -> Plan:
        """Counter-example-guided loop: solve, verify with the resolver, add no-good cut on failure."""
        nogoods = []
        last = None
        for it in range(1, max_iter + 1):
            pl = self.solve(lam, nogoods=nogoods)
            if pl is None:
                return Plan(name, {}, verified=False, iterations=it, error="model infeasible")
            pl.name, pl.iterations = name, it
            if not pl.changes:
                pl.verified, pl.realised = True, dict(self.pins)
                return pl
            res = verify(pl.changes)
            if res.ok:
                pl.verified, pl.realised = True, res.pins
                return pl
            pl.error = res.error
            last = pl
            nogoods.append(tuple(pl.changes.items()))
        last.verified = False
        return last

    def pareto(self, lams=(0.0, 0.02, 0.05, 0.1, 0.2, 0.5, 1.0, 2.0, 5.0, 100.0)) -> list[dict]:
        out = []
        for lam in lams:
            pl = self.solve(lam)
            if pl:
                out.append({"lambda": lam, "risk": pl.residual_model, "cost": pl.cost_model,
                            "changes": len(pl.changes)})
        return out

    # ------------------------------------------------------------ decision sensitivity
    def decision_critical(self, findings, lam: float, p_of, eps: float = 0.05) -> list[dict]:
        """Findings whose (uncertain) exposure would change the optimal plan; EVPI per finding."""
        base = self.solve(lam)
        if base is None:
            return []
        out = []
        seen = set()
        for f in findings:
            k = (f.package, f.advisory)
            if k in seen:
                continue
            seen.add(k)
            p = p_of(f)
            if p <= eps or p >= 1 - eps:
                continue
            hi = self.solve(lam, p_override={k: 1.0})
            lo = self.solve(lam, p_override={k: 0.0})
            if hi is None or lo is None:
                continue
            changed = hi.changes != base.changes or lo.changes != base.changes

            def J(plan, pk):
                # objective of `plan` when finding k has exposure pk
                self.cur_p[k], old = pk, self.cur_p[k]
                self.risk.clear()
                val = sum(self._risk(pp, plan.changes.get(pp, self.pins[pp])) for pp in self.scope()) \
                    + lam * sum(self._cost(pp, vv) for pp, vv in plan.changes.items())
                self.cur_p[k] = old
                self.risk.clear()
                return val
            evpi = p * (J(base, 1.0) - J(hi, 1.0)) + (1 - p) * (J(base, 0.0) - J(lo, 0.0))
            out.append({"package": f.package, "advisory": f.advisory, "p": p, "critical": changed,
                        "evpi": max(0.0, evpi)})
        return out


# ---------------------------------------------------------------- baseline strategies
def plan_audit_fix(pins, findings, today, python: str = "3.10") -> dict[str, str]:
    """pip-audit --fix style: each vulnerable package to the smallest version fixing all its findings."""
    out = {}
    by = {}
    for f in findings:
        by.setdefault(f.package, set()).add(f.advisory)
    for p, ids in by.items():
        advs = [a for a in load_osv().get(p, []) if a.id in ids]
        for v in wheel_releases_after(p, pins[p], today, python):
            if not any(a.affects(str(v)) for a in advs):
                out[p] = str(v)
                break
    return out


def plan_latest(pins, findings, today, python: str = "3.10") -> dict[str, str]:
    """Upgrade every vulnerable package to its latest (wheel-published) release."""
    out = {}
    for p in {f.package for f in findings}:
        rels = wheel_releases_after(p, pins[p], today, python)
        if rels:
            out[p] = str(rels[-1])
    return out
