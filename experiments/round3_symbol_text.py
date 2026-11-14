"""Automated, commit-independent cross-check of mined vulnerable symbols against advisory text.

For each advisory whose fix commits yielded functions, code identifiers named in the advisory's own OSV summary and
details (backticked names, names followed by "(", dotted names, snake_case or CamelCase-with-lowercase tokens) form a
text reference. The check reports how often the mined set contains a function or class with that name. It is a
partial reference: advisories describe behaviour and often name no code, and a named identifier may be the entry
point rather than the vulnerable operation. It complements, and does not replace, the manual annotation.
Writes data/results/round3_symbol_text.json and data/results/symbol_text_disagreements.csv.
"""
from __future__ import annotations

import csv
import json
import re
import sys
import zipfile
from pathlib import Path

from scipy.stats import beta

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from evident import intel  # noqa: E402

RES = ROOT / "data" / "results"
SYM = ROOT / "data" / "symbols"
ZIP = ROOT / "data" / "intel" / "osv_pypi_all.zip"
STOP = {"python", "pypi", "github", "http", "https", "url", "json", "html", "xml", "api", "cve", "ghsa", "pysec",
        "dos", "redos", "xss", "csrf", "ssrf", "regex", "utf", "unicode", "windows", "linux", "macos", "null",
        "true", "false", "none", "the", "and"}
IDENT = r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*"


def code_identifiers(text: str, package: str) -> set[str]:
    found = set()
    found |= set(re.findall(rf"`({IDENT})(?:\(\))?`", text))
    found |= set(re.findall(rf"\b({IDENT})\(", text))
    for tok in re.findall(rf"\b({IDENT})\b", text):
        last = tok.split(".")[-1]
        if "." in tok and not re.match(r"^\d", last):
            found.add(tok)
        elif "_" in last.strip("_"):
            found.add(tok)
        elif re.match(r"^[A-Z][a-z]+[A-Z][A-Za-z]*$", last):
            found.add(tok)
    pk = package.replace("-", "_").lower()
    out = set()
    for t in found:
        last = t.split(".")[-1]
        low = t.lower()
        if last.lower() in STOP or last.lower() in BUILTINS or last.lower() == pk or len(last) < 3:
            continue
        if re.match(r"^v?\d", last) or re.match(r"^[0-9a-f]{7,}$", last) or last.isupper():
            continue
        if re.match(r"^(CVE|GHSA|PYSEC)", t, re.I) or low.startswith(("www.", "http")) or last == "PoC":
            continue
        if re.search(r"\.(com|org|io|net|dev|html|md|py|txt|rst)\b", low):
            continue
        if re.search(r"\.[A-Z][a-z]+$", t) and "_" not in t:   # sentence joined by a missing space: "foo.This"
            continue
        out.add(t)
    return out


BUILTINS = {"int", "str", "bytes", "dict", "list", "set", "tuple", "float", "bool", "object", "type", "len", "print",
            "printf", "open", "eval", "exec", "input", "range", "self", "cls", "kwargs", "args", "token", "version",
            "headers", "header", "request", "response", "value", "data", "path", "file", "name", "key"}


def main():
    osv = intel.load_osv()
    zf = zipfile.ZipFile(ZIP)
    names = set(zf.namelist())
    rows, disagree = [], []
    for f in sorted(SYM.glob("*.json")):
        d = json.loads(f.read_text("utf8"))
        if d.get("status") != "functions":
            continue
        pkg, aid = d["package"], d["advisory"]
        adv = next((a for a in osv.get(pkg, []) if a.id == aid), None)
        if adv is None:
            continue
        text = ""
        for oid in adv.ids:
            n = f"{oid}.json"
            if n in names:
                j = json.loads(zf.read(n))
                text += " " + (j.get("summary") or "") + " " + (j.get("details") or "")
        ids = code_identifiers(text, pkg)
        mined = set()
        for fl in d.get("files", []):
            for fn in fl.get("functions", []):
                parts = fn.split(".")
                mined |= set(parts) | {fn}
        if not ids:
            rows.append({"advisory": aid, "package": pkg, "anchored": False})
            continue
        hit = {t for t in ids if t.split(".")[-1] in mined or t in mined}
        rows.append({"advisory": aid, "package": pkg, "anchored": True, "named": sorted(ids), "matched": sorted(hit)})
        if not hit:
            disagree.append({"advisory": aid, "package": pkg, "named_in_text": "; ".join(sorted(ids)),
                             "mined_functions": "; ".join(sorted(fn for fl in d.get("files", [])
                                                                 for fn in fl.get("functions", [])))[:600]})
    anch = [r for r in rows if r["anchored"]]
    k = sum(1 for r in anch if r["matched"])
    n = len(anch)
    out = {"advisories_with_functions": len(rows), "text_names_code": n,
           "mined_contains_named": k, "agreement": k / n if n else None,
           "agreement_ci95": [float(beta.ppf(0.025, k, n - k + 1)) if k else 0.0,
                              float(beta.ppf(0.975, k + 1, n - k)) if k < n else 1.0] if n else None,
           "disagreements_file": "data/results/symbol_text_disagreements.csv",
           "note": "commit-independent partial reference; not a substitute for manual annotation"}
    (RES / "round3_symbol_text.json").write_text(json.dumps(out | {"rows": rows}, indent=1), "utf8")
    with open(RES / "symbol_text_disagreements.csv", "w", newline="", encoding="utf8") as fh:
        w = csv.DictWriter(fh, fieldnames=["advisory", "package", "named_in_text", "mined_functions"])
        w.writeheader()
        w.writerows(disagree)
    print(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
