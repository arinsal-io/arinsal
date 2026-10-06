"""Repeat one-shot startup commands and print median wall time."""

import os
import statistics
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
DEMO = ROOT / "examples/arinsal_demo"
TEMP = ROOT / "tmp/jit_backend_adr"
ENV = os.environ.copy()
ENV.update(
    MIX_DEPS_PATH=str(TEMP / "deps"),
)

CASES = [
    ("erl_boot", ["erl", "-noshell", "-eval", "halt()."], ROOT),
    ("elixir_ok", ["elixir", "-e", ":ok"], ROOT),
    ("mix_test", ["mix", "test"], DEMO),
    ("mix_compile_force", ["mix", "compile", "--force"], DEMO),
]

for name, argv, cwd in CASES:
    samples = []
    for _ in range(5):
        mix_env = "test" if name == "mix_test" else "dev"
        env = dict(ENV, MIX_ENV=mix_env,
                   MIX_BUILD_PATH=str(TEMP / ("build_" + mix_env)))
        start = time.perf_counter()
        run = subprocess.run(argv, cwd=cwd, env=env, capture_output=True, timeout=180)
        elapsed = time.perf_counter() - start
        if run.returncode:
            raise RuntimeError(f"{name}: {run.stderr.decode()[-1000:]}")
        samples.append(elapsed)
    print(f"{name}: median_ms={statistics.median(samples)*1000:.1f} "
          f"range_ms={min(samples)*1000:.1f}-{max(samples)*1000:.1f}")
