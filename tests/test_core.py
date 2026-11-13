"""Unit tests for the offline parts of EVIDENT (no network)."""
from pathlib import Path

from evident.evidence import CONFIRMED, NOT_OBSERVED, OBSERVED, POSSIBLE, REFUTED, Finding, exposure_class, vex_statement
from evident.exposure import StagedModel, auc, brier, ece, ranking_metrics
from evident.graph import TargetEnv, choose_python, marker_ok, poetry_to_pep440
from evident.intel import Advisory, _in_events
from evident.lockfiles import parse_lock
from evident.reach import Analysis, Program
from evident.symbols import _enclosing, _old_lines
from packaging.version import Version


def adv(events):
    return Advisory("X", ["X"], [], "p", "", "", None, None, [events], set(), [], [], [])


def test_osv_ranges():
    ev = [{"introduced": "0"}, {"fixed": "1.2"}, {"introduced": "2.0"}, {"last_affected": "2.3"}]
    a = adv(ev)
    assert a.affects("1.0") and not a.affects("1.2") and not a.affects("1.9")
    assert a.affects("2.0") and a.affects("2.3") and not a.affects("2.4")
    assert _in_events(Version("0.1"), [{"introduced": "0"}])


def test_markers_and_python():
    t = TargetEnv(python="3.10")
    assert marker_ok('python_version < "3.11"', t)
    assert not marker_ok('sys_platform == "win32"', t)
    assert marker_ok('extra == "socks"', t)
    assert poetry_to_pep440("^3.8") == ">=3.8,<4.0"
    assert choose_python(">=3.8,<3.10") == "3.9"


def test_poetry_lock(tmp_path: Path):
    p = tmp_path / "poetry.lock"
    p.write_text('''
[[package]]
name = "Flask"
version = "2.0.0"
category = "main"
[package.dependencies]
Werkzeug = ">=2.0"
colorama = {version = "*", markers = "platform_system == \\"Windows\\""}

[[package]]
name = "werkzeug"
version = "2.0.1"
category = "main"

[[package]]
name = "pytest"
version = "7.0.0"
category = "dev"
''')
    env = parse_lock(p)
    assert set(env.packages) == {"flask", "werkzeug", "pytest"}
    assert env.packages["pytest"].dev_only is True
    assert ("werkzeug", ">=2.0", "") in env.packages["flask"].deps


def test_fix_commit_line_mapping():
    patch = "@@ -3,3 +3,4 @@\n def f():\n-    return 1\n+    x = 2\n+    return x\n"
    assert 4 in _old_lines(patch)
    src = "import os\n\ndef f():\n    return 1\n\nclass C:\n    def m(self):\n        pass\n"
    funcs, mod = _enclosing(src, {4, 8, 1})
    assert funcs == {"f", "C.m"} and mod


def _prog(tmp_path: Path, app_src: str) -> Analysis:
    lib = tmp_path / "lib" / "vlib"
    lib.mkdir(parents=True)
    (lib / "__init__.py").write_text("from .core import api, safe\n")
    (lib / "core.py").write_text(
        "def _vuln(x):\n    return x\n\ndef api(x):\n    return _vuln(x)\n\ndef safe(x):\n    return x\n")
    app = tmp_path / "app"
    app.mkdir()
    (app / "main.py").write_text(app_src)
    p = Program()
    p.add_tree(tmp_path / "lib", "vlib")
    p.add_tree(app, "__app__", app=True)
    p.build()
    return Analysis(p)


def test_reach_confirmed(tmp_path: Path):
    a = _prog(tmp_path, "import vlib\n\ndef main():\n    return vlib.api(1)\n")
    assert a.import_evidence("vlib") == CONFIRMED
    assert a.symbol_evidence("vlib", ["vlib.core._vuln"]).verdict == CONFIRMED


def test_reach_refuted_and_possible(tmp_path: Path):
    a = _prog(tmp_path, "import vlib\n\ndef main():\n    return vlib.safe(1)\n")
    assert a.symbol_evidence("vlib", ["vlib.core._vuln"]).verdict == REFUTED
    (tmp_path / "x").mkdir()
    b = _prog(tmp_path / "x", "import vlib\n\ndef main(k='api'):\n    return getattr(vlib, k)(1)\n")
    assert b.symbol_evidence("vlib", ["vlib.core._vuln"]).verdict == POSSIBLE


def _f(l3b, l4, l5, gran="function"):
    f = Finding("s", "p", "1", "A", ["A"], [], 7.5, 0.1, False, 0.75, "", [], 1, True)
    f.add("L3", CONFIRMED, scope="prod")
    f.add("L3b", l3b)
    f.add("L4", l4, granularity=gran)
    f.add("L5", l5)
    return f


def test_exposure_classes_and_vex():
    f = _f(REFUTED, REFUTED, NOT_OBSERVED)
    f.exposure_class = exposure_class(f)
    assert f.exposure_class == "NOT_IMPORTED"
    assert vex_statement(f)["justification"] == "vulnerable_code_not_present"
    g = _f(CONFIRMED, POSSIBLE, OBSERVED)
    assert exposure_class(g) == "RUNTIME_OBSERVED"


def test_staged_model_learns():
    fs = [_f(CONFIRMED, CONFIRMED, NOT_OBSERVED)] * 20 + [_f(CONFIRMED, REFUTED, NOT_OBSERVED)] * 20
    ys = [1] * 18 + [0] * 2 + [0] * 19 + [1]
    m = StagedModel().fit(fs, ys)
    assert m.predict(fs[0]) > 0.7 > 0.2 > m.predict(fs[-1])
    assert m.predict(_f(CONFIRMED, POSSIBLE, OBSERVED)) > 0.9


def test_metrics():
    assert brier([1, 0], [1, 0]) == 0
    assert ece([0.5, 0.5], [1, 0]) == 0
    assert auc([0.9, 0.1], [1, 0]) == 1
    r = ranking_metrics([0.9, 0.8, 0.1], [1, 0, 1], ks=(2,))
    assert r["P@2"] == 0.5 and 0 < r["NDCG@2"] < 1
