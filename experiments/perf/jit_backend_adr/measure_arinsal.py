"""Measure existing Arinsal command wall times under a hard timeout."""

import os
import statistics
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
TEMP = ROOT / "tmp/jit_backend_adr"
DEMO = ROOT / "examples/arinsal_demo"
CASES = [
    ("elixir_ok", ["elixir", "-e", ":ok"], ROOT, "dev"),
    ("mix_test", ["mix", "test"], DEMO, "test"),
    ("mix_compile_force", ["mix", "compile", "--force"], DEMO, "dev"),
]

for name, argv, cwd, mix_env in CASES:
    samples = {"current": [], "interpreter": []}
    for _ in range(5):
        for mode in samples:
            env = dict(os.environ)
            env.update(
                PATH=str(TEMP / "shim") + os.pathsep + env["PATH"],
                MIX_ENV=mix_env,
                MIX_DEPS_PATH=str(TEMP / "deps"),
                MIX_BUILD_PATH=str(TEMP / ("build_" + mix_env)),
                ARINSAL_JIT="0" if mode == "interpreter" else "1",
            )
            start = time.perf_counter()
            run = subprocess.run(["timeout", "60", *argv], cwd=cwd,
                                 env=env, capture_output=True, text=True,
                                 timeout=65)
            elapsed = (time.perf_counter() - start) * 1000
            if run.returncode:
                raise RuntimeError(f"{name} {mode} exit={run.returncode}: "
                                   f"{run.stderr[-1000:]}")
            samples[mode].append(elapsed)
    for mode, times in samples.items():
        print(f"{name} {mode}: median_ms={statistics.median(times):.1f} "
              f"range_ms={min(times):.1f}-{max(times):.1f}", flush=True)
