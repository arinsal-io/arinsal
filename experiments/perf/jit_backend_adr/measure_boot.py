"""Reproduce OTP boot wall, loaded operations, and BeamAsm text size."""

import re
import statistics
import subprocess
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
TEMP = ROOT / "tmp/jit_backend_adr"
PRELOADED = ROOT / "ref/otp-29/erts/preloaded/ebin"
SCAN = ROOT / "experiments/perf/jit_backend_adr/target/release/jit-backend-adr"


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


TEMP.mkdir(parents=True, exist_ok=True)
walls = []
for _ in range(5):
    start = time.perf_counter()
    subprocess.run(["erl", "-noshell", "-eval", "halt()."], check=True,
                   capture_output=True, timeout=30)
    walls.append((time.perf_counter() - start) * 1000)
internal_expr = (
    "io:format('MEM_CODE=~p START_US=~p LOADED=~p~n',"
    "[erlang:memory(code),erlang:convert_time_unit("
    "erlang:monotonic_time()-erlang:system_info(start_time),"
    "native,microsecond),length(code:all_loaded())]),halt()."
)
internals = []
code_bytes = []
for _ in range(5):
    result = subprocess.run(["erl", "-noshell", "-eval", internal_expr],
                            check=True, capture_output=True, text=True, timeout=30)
    code_bytes.append(int(re.search(r"MEM_CODE=(\d+)", result.stdout)[1]))
    internals.append(int(re.search(r"START_US=(\d+)", result.stdout)[1]))
expr = (
    "Modules=code:all_loaded(), "
    "lists:foreach(fun({M,P})->case P of "
    "preloaded->io:format('PRELOADED ~p~n',[M]); "
    "S when is_list(S)->io:format('BEAM_LOADED ~s~n',[S]); "
    "_->ok end end,Modules), halt()."
)
with tempfile.TemporaryDirectory(prefix="boot-", dir=TEMP) as directory:
    dump = Path(directory)
    result = subprocess.run(["erl", "-noshell", "+JDdump", "true", "-eval", expr],
                            cwd=dump, check=True, capture_output=True,
                            text=True, timeout=30)
    lines = result.stdout.splitlines()
    paths = [line for line in lines if line.startswith("BEAM_LOADED ")]
    names = {Path(line[12:]).stem for line in paths}
    for line in lines:
        if line.startswith("PRELOADED "):
            name = line.removeprefix("PRELOADED ")
            names.add(name)
            paths.append("BEAM_LOADED " + str(PRELOADED / (name + ".beam")))
    scanned = subprocess.check_output([SCAN], input="\n".join(paths),
                                      text=True, timeout=30).splitlines()[-1]
    native = sum(text_bytes(dump / (name + ".asm")) for name in names)
    print(f"boot_external_median_ms={statistics.median(walls):.1f} "
          f"range={min(walls):.1f}-{max(walls):.1f}")
    print(f"boot_internal_median_ms={statistics.median(internals)/1000:.1f} "
          f"range={min(internals)/1000:.1f}-{max(internals)/1000:.1f} "
          f"memory_code_median_bytes={statistics.median(code_bytes):.0f}")
    print(scanned)
    print(f"beamasm_text_bytes={native} "
          f"text_bytes_per_resolved_op={native/int(re.search(r'ops=(\d+)', scanned)[1]):.2f}")
