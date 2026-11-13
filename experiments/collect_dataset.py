"""Collect historical lockfile snapshots of popular Python repositories (data only).

For each candidate repository (GitHub search, Python, by stars) we pick the release
published closest to MID within [LO, HI], and download - as plain data - the lockfile
and manifest at that tag, plus the application source archive. Nothing is executed.

Usage: python experiments/collect_dataset.py [--target 80]
"""
from __future__ import annotations

import argparse
import datetime as dt
import re
import sys
import tomllib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from evident.util import DATA, gh_api, http_get, write_json  # noqa: E402

LO, MID, HI = "2022-07-01", "2023-06-01", "2024-06-30"
LOCKS = [("uv.lock", "uv"), ("poetry.lock", "poetry"), ("Pipfile.lock", "pipfile"), ("pdm.lock", "pdm")]
REQS = ["requirements.txt", "requirements/prod.txt", "requirements/base.txt", "requirements/production.txt",
        "requirements-frozen.txt", "requirements/main.txt"]
SUBDIRS = ["", "backend/", "server/", "api/"]
SNAP = DATA / "snapshots"


def raw(repo, ref, path):
    try:
        return http_get(f"https://raw.githubusercontent.com/{repo}/{ref}/{path}", kind="raw")
    except RuntimeError:
        return None


def pinned_fraction(txt: str):
    lines = [ln.strip() for ln in txt.splitlines()]
    lines = [ln for ln in lines if ln and not ln.startswith(("#", "-", "git+", "http"))]
    if not lines:
        return 0.0, 0
    pinned = sum(1 for ln in lines if re.match(r"^[A-Za-z0-9._\-\[\],]+\s*==\s*[^\s;,]+", ln))
    return pinned / len(lines), len(lines)


def pick_release(repo):
    rels = gh_api(f"repos/{repo}/releases?per_page=100") or []
    best, bestd = None, None
    mid = dt.datetime.fromisoformat(MID)
    for r in rels:
        d = (r.get("published_at") or "")[:10]
        if not d or r.get("draft") or r.get("prerelease") or not (LO <= d <= HI):
            continue
        dd = abs((dt.datetime.fromisoformat(d) - mid).days)
        if bestd is None or dd < bestd:
            best, bestd = r, dd
    return best


def find_lock(repo, tag):
    for sub in SUBDIRS:
        for name, kind in LOCKS:
            t = raw(repo, tag, sub + name)
            if t and len(t) > 200:
                return sub, name, kind, t
    for sub in SUBDIRS[:2]:
        for name in REQS:
            t = raw(repo, tag, sub + name)
            if t:
                frac, n = pinned_fraction(t)
                if frac >= 0.8 and n >= 10:
                    return sub, name, "requirements", t
    return None


def commit_at(repo, until=MID):
    j = gh_api(f"repos/{repo}/commits?until={until}T00:00:00Z&per_page=1")
    if not j:
        return None
    c = j[0]
    d = (c.get("commit", {}).get("committer", {}) or {}).get("date", "")
    return {"tag_name": c["sha"], "published_at": d} if d[:10] >= "2022-06-01" else None


LOCK_PATHS: dict[str, set[str]] = {}


def discover_codesearch(max_pages: int = 10) -> dict[str, int]:
    """Repositories that commit a lockfile (GitHub code search), biased towards applications."""
    import time
    from evident.util import CACHE, sha
    repos: dict[str, int] = {}
    for lock in ("poetry.lock", "Pipfile.lock", "pdm.lock"):
        for kw in ("", "django", "fastapi", "flask", "celery"):
            q = (kw + "+" if kw else "") + f"filename:{lock}"
            for page in range(1, max_pages + 1):
                path = f"search/code?q={q}&per_page=100&page={page}"
                key = "gh:" + path
                cached = (CACHE / "gh" / sha(key)[:2] / sha(key)).exists()
                res = gh_api(path)
                if not cached:
                    time.sleep(6.5)
                items = (res or {}).get("items", [])
                for it in items:
                    if it.get("path", "").count("/") <= 1:
                        fn = it["repository"]["full_name"]
                        repos[fn] = repos.get(fn, 0) + 1
                        LOCK_PATHS.setdefault(fn, set()).add(it["path"])
                if len(items) < 100:
                    break
    print(f"  discovered {len(repos)} repos", flush=True)
    return repos


def find_lock_known(repo, ref):
    kinds = dict(LOCKS)
    for path in sorted(LOCK_PATHS.get(repo, ())):
        name = path.rsplit("/", 1)[-1]
        if name in kinds:
            t = raw(repo, ref, path)
            if t and len(t) > 200:
                sub = path[: -len(name)]
                return sub, name, kinds[name], t
    return None


def inspect(r):
    info = gh_api(f"repos/{r}")
    if not info or info.get("fork") or info.get("language") != "Python":
        return None
    if info.get("stargazers_count", 0) < 20 or info.get("created_at", "9")[:10] > "2022-12-31":
        return None
    repo = info["full_name"]
    rel = pick_release(repo) or commit_at(repo)
    if not rel:
        return None
    hit = find_lock_known(repo, rel["tag_name"])
    if not hit:
        return None
    return repo, rel, info, hit


def main_codesearch(target: int, max_lookups: int = 1800):
    SNAP.mkdir(parents=True, exist_ok=True)
    have = {p.name.split("@")[0] for p in SNAP.iterdir() if (p / "meta.json").exists()}
    hits = discover_codesearch()
    # repos matched by several application-oriented queries first; deterministic tie-break by name
    cands = sorted(hits, key=lambda r: (-hits[r], r))[:max_lookups]
    print(f"{len(hits)} repos discovered; inspecting top {len(cands)}", flush=True)
    from concurrent.futures import ThreadPoolExecutor
    n = len(have)
    cands = [r for r in cands if r.replace("/", "__") not in have]
    with ThreadPoolExecutor(8) as ex:
        for i in range(0, len(cands), 48):
            if n >= target:
                break
            for res in ex.map(inspect, cands[i:i + 48]):
                if res is None or n >= target:
                    continue
                repo, rel, info, (sub, name, kind, text) = res
                n += save(repo, rel["tag_name"], rel, info, sub, name, kind, text)
                print(f"[{n}] {repo}@{rel['tag_name'][:12]} {kind} ({i + 48} inspected)", flush=True)
    print(f"done: {n} snapshots")


def save(repo, tag, rel, item, sub, name, kind, text) -> int:
    sid = f"{repo.replace('/', '__')}@{re.sub(r'[^A-Za-z0-9._-]', '_', tag)[:40]}"
    d = SNAP / sid
    d.mkdir(parents=True, exist_ok=True)
    (d / Path(name).name).write_text(text, "utf8")
    manifest = None
    for m in ("pyproject.toml", "Pipfile"):
        mt = raw(repo, tag, sub + m)
        if mt:
            (d / m).write_text(mt, "utf8")
            manifest = manifest or m
    req_python = None
    if (d / "pyproject.toml").exists():
        try:
            t = tomllib.loads((d / "pyproject.toml").read_text("utf8"))
            req_python = (t.get("project", {}).get("requires-python")
                          or t.get("tool", {}).get("poetry", {}).get("dependencies", {}).get("python"))
        except Exception:
            pass
    write_json(d / "meta.json", {
        "id": sid, "repo": repo, "tag": tag, "published_at": rel["published_at"],
        "stars": item["stargazers_count"], "lock_kind": kind, "lock_file": Path(name).name,
        "lock_path": sub + name, "subdir": sub, "manifest": manifest,
        "requires_python": req_python if isinstance(req_python, str) else None,
        "description": (item.get("description") or "")[:200], "topics": item.get("topics", []),
    })
    return 1


SEEDS = ["paperless-ngx/paperless-ngx", "saleor/saleor", "goauthentik/authentik", "mealie-recipes/mealie",
         "HumanSignal/label-studio", "getredash/redash", "zulip/zulip", "apache/superset", "PostHog/posthog",
         "netbox-community/netbox", "wagtail/wagtail", "healthchecks/healthchecks", "Kozea/Radicale",
         "babybuddy/babybuddy", "TandoorRecipes/recipes", "mathesar-foundation/mathesar", "frappe/frappe",
         "ckan/ckan", "pretix/pretix", "inventree/InvenTree", "openedx/edx-platform", "sentry/sentry",
         "home-assistant/core", "jumpserver/jumpserver", "lnbits/lnbits", "ajenti/ajenti", "plone/volto",
         "archivy/archivy", "linkding/linkding", "sissbruecker/linkding", "wger-project/wger", "MobSF/Mobile-Security-Framework-MobSF",
         "DefectDojo/django-DefectDojo", "makeplane/plane", "langgenius/dify", "Chainlit/chainlit", "reflex-dev/reflex",
         "polarsource/polar", "fastapi/full-stack-fastapi-template", "netbox-community/netbox", "OWASP/Nettacker",
         "ArchiveBox/ArchiveBox", "grafana/oncall", "getsentry/sentry", "openwisp/openwisp-controller",
         "CTFd/CTFd", "mitmproxy/mitmproxy", "Flexget/Flexget", "pi-hole/web", "spiderfoot/spiderfoot"]
TOPICS = ["django", "fastapi", "flask", "self-hosted", "web-application", "saas", "rest-api", "dashboard",
          "chatbot", "automation", "selfhosted", "backend"]


def main_topics(target: int):
    import time
    from concurrent.futures import ThreadPoolExecutor
    from evident.util import CACHE, sha
    SNAP.mkdir(parents=True, exist_ok=True)
    have = {p.name.split("@")[0] for p in SNAP.iterdir() if (p / "meta.json").exists()}
    items: dict[str, dict] = {}
    for s in SEEDS:
        info = gh_api(f"repos/{s}")
        if info:
            items.setdefault(info["full_name"], info)
    for topic in TOPICS:
        for page in range(1, 11):
            path = (f"search/repositories?q=topic:{topic}+language:python+stars:%3E80+pushed:%3E2023-06-01"
                    f"&sort=stars&order=desc&per_page=100&page={page}")
            key = "gh:" + path
            cached = (CACHE / "gh" / sha(key)[:2] / sha(key)).exists()
            res = gh_api(path)
            if not cached:
                time.sleep(2.2)
            its = (res or {}).get("items", [])
            for it in its:
                items.setdefault(it["full_name"], it)
            if len(its) < 100:
                break
    cands = [i for i in items.values() if not i.get("fork") and i.get("created_at", "9")[:10] <= "2022-12-31"
             and i["full_name"].replace("/", "__") not in have]
    cands.sort(key=lambda i: -i.get("stargazers_count", 0))
    print(f"{len(items)} repos discovered; {len(cands)} candidates", flush=True)

    def insp(info):
        repo = info["full_name"]
        rel = pick_release(repo) or commit_at(repo)
        if not rel:
            return None
        hit = find_lock(repo, rel["tag_name"])
        return (repo, rel, info, hit) if hit else None
    n = len(have)
    with ThreadPoolExecutor(8) as ex:
        for i in range(0, len(cands), 48):
            if n >= target:
                break
            for res in ex.map(insp, cands[i:i + 48]):
                if res is None or n >= target:
                    continue
                repo, rel, info, (sub, name, kind, text) = res
                n += save(repo, rel["tag_name"], rel, info, sub, name, kind, text)
                print(f"[{n}] {repo}@{rel['tag_name'][:12]} {kind} ({min(i + 48, len(cands))} inspected)", flush=True)
    print(f"done: {n} snapshots")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", type=int, default=80)
    ap.add_argument("--pages", type=int, default=10)
    ap.add_argument("--mode", choices=["stars", "codesearch", "topics"], default="topics")
    a = ap.parse_args()
    if a.mode == "codesearch":
        return main_codesearch(a.target)
    if a.mode == "topics":
        return main_topics(a.target)
    SNAP.mkdir(parents=True, exist_ok=True)
    have = {p.name for p in SNAP.iterdir() if (p / "meta.json").exists()}
    n = len(have)
    seen = 0
    for page in range(1, a.pages + 1):
        res = gh_api(f"search/repositories?q=language:python+stars:%3E500+pushed:%3E2024-01-01"
                     f"&sort=stars&order=desc&per_page=100&page={page}")
        for item in (res or {}).get("items", []):
            if n >= a.target:
                break
            repo = item["full_name"]
            seen += 1
            if any(h.startswith(repo.replace("/", "__") + "@") for h in have):
                continue
            rel = pick_release(repo)
            if not rel:
                continue
            tag = rel["tag_name"]
            hit = find_lock(repo, tag)
            if not hit:
                continue
            sub, name, kind, text = hit
            sid = f"{repo.replace('/', '__')}@{re.sub(r'[^A-Za-z0-9._-]', '_', tag)}"
            d = SNAP / sid
            d.mkdir(parents=True, exist_ok=True)
            (d / Path(name).name).write_text(text, "utf8")
            manifest = None
            for m in ("pyproject.toml", "Pipfile"):
                mt = raw(repo, tag, sub + m)
                if mt:
                    (d / m).write_text(mt, "utf8")
                    manifest = manifest or m
            req_python = None
            if (d / "pyproject.toml").exists():
                try:
                    t = tomllib.loads((d / "pyproject.toml").read_text("utf8"))
                    req_python = (t.get("project", {}).get("requires-python")
                                  or t.get("tool", {}).get("poetry", {}).get("dependencies", {}).get("python"))
                except Exception:
                    pass
            write_json(d / "meta.json", {
                "id": sid, "repo": repo, "tag": tag, "published_at": rel["published_at"],
                "stars": item["stargazers_count"], "lock_kind": kind, "lock_file": Path(name).name,
                "lock_path": sub + name, "subdir": sub, "manifest": manifest,
                "requires_python": req_python if isinstance(req_python, str) else None,
                "description": (item.get("description") or "")[:200],
                "topics": item.get("topics", []),
            })
            n += 1
            print(f"[{n}] {sid} {kind} ({seen} seen)", flush=True)
        if n >= a.target:
            break
    print(f"done: {n} snapshots, {seen} repos inspected")


if __name__ == "__main__":
    main()
