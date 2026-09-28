"""Measure OTP 29 one-shot load_file cost and BeamAsm text bytes."""

import os
import re
import statistics
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
TEMP = ROOT / "tmp/jit_backend_adr"
OTP = Path("$HOME/.asdf/installs/erlang/29.1.1")
ELIXIR = Path("$HOME/.asdf/installs/elixir/1.20.4-otp-29")
MODULES = [
    ("compile", OTP / "lib/compiler-10.0.6/ebin"),
    ("beam_ssa_opt", OTP / "lib/compiler-10.0.6/ebin"),
    ("beam_ssa_codegen", OTP / "lib/compiler-10.0.6/ebin"),
    ("elixir_expand", ELIXIR / "lib/elixir/ebin"),
]


def text_bytes(path):
    section = "text"
    offset = 0
    for line in path.read_text().splitlines():
        line = line.strip()
        if line.startswith(".section"):
            section = "text" if ".text" in line else "other"
        elif section == "text":
            if line.startswith("align "):
                boundary = int(line.split()[1])
                offset = (offset + boundary - 1) // boundary * boundary
            elif line.startswith(".byte"):
                offset += len(re.findall(r"0x[0-9a-fA-F]+", line))
            elif line.startswith(".word"):
                offset += 4
            elif line.startswith(".xword"):
                offset += 8
            elif line and not line.startswith("#") and not line.endswith(":"):
                offset += 4
    return offset


for name, ebin in MODULES:
    expression = (
        "timer:tc(fun()->ok end), B=erlang:memory(code), "
        f"{{T,R}}=timer:tc(code,load_file,[{name}]), "
        "A=erlang:memory(code), "
        'io:format("LOAD_US=~p DELTA_BYTES=~p RESULT=~p~n",[T,A-B,R]), halt().'
    )
    times, deltas = [], []
    for i in range(6):
        argv = ["erl", "-noshell", "-pa", str(ebin)]
        if i == 0:
            argv += ["+JDdump", "true"]
        run = subprocess.run(argv + ["-eval", expression], cwd=TEMP,
                             capture_output=True, text=True, timeout=30)
        if run.returncode:
            raise RuntimeError(run.stderr)
        match = re.search(r"LOAD_US=(\d+) DELTA_BYTES=(\d+)", run.stdout)
        if not match:
            raise RuntimeError(run.stdout)
        times.append(int(match[1]))
        deltas.append(int(match[2]))
    print(f"{name}: load_us_median={statistics.median(times[1:]):.0f} "
          f"nondump_range={min(times[1:])}-{max(times[1:])} "
          f"memory_code_delta_median={statistics.median(deltas):.0f} "
          f"beamasm_text_bytes={text_bytes(TEMP / (name + '.asm'))}")
