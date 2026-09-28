"""Repeat current-JIT compilation on a fixed OTP/Elixir BEAM corpus."""

import os
import re
import statistics
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
OTP = Path("$HOME/.asdf/installs/erlang/29.1.1/lib")
ELIXIR = Path("$HOME/.asdf/installs/elixir/1.20.4-otp-29/lib")
CORPUS = sorted(
    list(OTP.glob("kernel-*/ebin/*.beam"))
    + list(OTP.glob("stdlib-*/ebin/*.beam"))
    + list(OTP.glob("compiler-*/ebin/*.beam"))
    + list(ELIXIR.glob("elixir/ebin/*.beam"))
)
BIN = ROOT / "experiments/perf/jit_backend_adr/target/release/real_jit"
print(f"corpus_files={len(CORPUS)}", flush=True)
for mode in ("default", "fast", "reuse", "fast_reuse"):
    records = []
    for _ in range(5):
        output = subprocess.check_output(
            [BIN, *CORPUS], env=dict(os.environ, ADR_JIT_MODE=mode),
            text=True, timeout=180,
        )
        line = output.splitlines()[-1]
        fields = dict(re.findall(r"([a-z_]+)=([0-9.]+)", line))
        records.append(fields)
    print(
        f"{mode}: functions={records[0]['functions']} ops={records[0]['ops']} "
        f"compile_us_median={statistics.median(int(r['compile_us']) for r in records):.0f} "
        f"compile_us_range={min(int(r['compile_us']) for r in records)}-"
        f"{max(int(r['compile_us']) for r in records)} "
        f"init_us_median={statistics.median(int(r['init_us']) for r in records):.0f} "
        f"code_bytes={records[0]['code_bytes']}", flush=True,
    )
