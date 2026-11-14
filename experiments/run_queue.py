"""Run analysis steps sequentially (one heavy job at a time); log to data/queue.log."""
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PY = sys.executable
S = os.environ.get("EVIDENT_TOOLS", str(ROOT / "tools" / "reachability"))  # PyCG/Jarvis venv + wrappers
STEPS = [
    [PY, "experiments/compare_callgraphs.py", "--tool-py", rf"{S}\venv\Scripts\python.exe", "--pycg",
     rf"{S}\scripts\run_pycg_winfix.py", "--jarvis", rf"{S}\scripts\run_jarvis.py", "--jarvis-dir",
     rf"{S}\tools\jarvis\Jarvis\tool\Jarvis", "--timeout", "180"],
    [PY, "experiments/bench/build_bench.py", "--reuse", "--workers", "1"],
    [PY, "experiments/analyze_bench.py"],
    [PY, "experiments/validate_symbols.py"],
]
log = open(ROOT / "data" / "queue.log", "a", encoding="utf8")
for step in STEPS:
    t = time.time()
    log.write(f"START {step[1]} {time.ctime()}\n"); log.flush()
    r = subprocess.run(step, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT)
    log.write(f"END {step[1]} exit={r.returncode} {time.time() - t:.0f}s\n"); log.flush()
log.write("QUEUE DONE\n"); log.close()
