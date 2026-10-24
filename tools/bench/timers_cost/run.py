#!/usr/bin/env python3
"""Compare timer and receive timeout costs on OTP 29.1.1 and Arinsal."""

from __future__ import annotations

import re
import statistics
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
OPS = {
    "send_after_cancel": 1_000_000,
    "start_timer_cancel": 1_000_000,
    "receive_after_0": 10_000_000,
    "receive_after_1_message": 1_000_000,
    "concurrent_10000": 10_000,
}
RUNS = 7
LAT_RUNS = 5
SCHEDULERS = 4


def run(command: list[str]) -> str:
    return subprocess.run(
        ["timeout", "300", *command],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
        timeout=310,
    ).stdout


def sample(
    runtime: str, op: str, n: int, run_index: int, ebin: Path, binary: Path
) -> tuple[int, int]:
    expression = f"io:format(\"~p\",[timers_cost_bench:run({op},{n},{run_index})]),halt()."
    if runtime == "erts":
        output = run([
            "erl", "+S", f"{SCHEDULERS}:{SCHEDULERS}", "-noshell", "-noinput",
            "-pa", str(ebin), "-eval", expression,
        ])
    else:
        output = run([
            str(binary), "eval", "--schedulers", str(SCHEDULERS), "-pa", str(ebin),
            "-pa", str(ROOT / "tmp" / "stdlib_ebin"),
            "-pa", str(ROOT / "tmp" / "kernel_ebin"),
            "timers_cost_bench", "run", op, str(n), str(run_index),
        ])
    match = re.search(rf"\{{{op},\s*{n},\s*(\d+),\s*(\d+)\}}", output)
    if not match:
        raise RuntimeError(f"could not parse {runtime} output: {output!r}")
    return tuple(map(int, match.groups()))


def sample_lateness(runtime: str, kind: str, ebin: Path, binary: Path) -> tuple[int, int]:
    n = 10_000
    if runtime == "erts":
        output = run([
            "erl", "+S", f"{SCHEDULERS}:{SCHEDULERS}", "-noshell", "-noinput",
            "-pa", str(ebin), "-eval",
            f"io:format(\"~p\",[timers_cost_bench:lateness({kind},{n})]),halt().",
        ])
    else:
        output = run([
            str(binary), "eval", "--schedulers", str(SCHEDULERS), "-pa", str(ebin),
            "-pa", str(ROOT / "tmp" / "stdlib_ebin"),
            "-pa", str(ROOT / "tmp" / "kernel_ebin"),
            "timers_cost_bench", "lateness", kind, str(n),
        ])
    match = re.search(rf"\{{{kind},\s*{n},\s*(\d+),\s*(\d+)\}}", output)
    if not match:
        raise RuntimeError(f"could not parse {runtime} lateness output: {output!r}")
    return tuple(map(int, match.groups()))


def main() -> None:
    subprocess.run([
        "erlc", "-Werror", "-o", str(ROOT / "tmp"),
        str(ROOT / "tools/bench/timers_cost/timers_cost_bench.erl"),
    ], cwd=ROOT, check=True, timeout=30)
    otp_root = Path(run(["erl", "-noshell", "-noinput", "-eval", "io:format(\"~s\",[code:root_dir()]),halt()."]).strip())
    lib = otp_root / "lib"
    stdlib = next(lib.glob("stdlib-*/ebin"))
    kernel = next(lib.glob("kernel-*/ebin"))
    for link, target in ((ROOT / "tmp/stdlib_ebin", stdlib), (ROOT / "tmp/kernel_ebin", kernel)):
        if not link.exists():
            link.symlink_to(target, target_is_directory=True)
    binary = ROOT / "target/release/arinsal"
    results: dict[tuple[str, str], list[float]] = {}
    for op, n in OPS.items():
        for runtime in ("erts", "arinsal"):
            values = []
            for run_index in range(RUNS):
                empty, work = sample(runtime, op, n, run_index, ROOT / "tmp", binary)
                denom = 10_000 if op == "concurrent_10000" else n
                values.append((work - empty) / denom)
            results[(runtime, op)] = values
    print(f"load label: {SCHEDULERS} schedulers, 2 busy Erlang workers; N >= 1,000,000 except concurrent timer batch")
    print("| operation | OTP ns/op median [min–max] | Arinsal ns/op median [min–max] |")
    print("|---|---:|---:|")
    for op in OPS:
        cells = []
        for runtime in ("erts", "arinsal"):
            values = results[(runtime, op)]
            cells.append(f"{statistics.median(values):.2f} [{min(values):.2f}–{max(values):.2f}]")
        print(f"| {op} | {cells[0]} | {cells[1]} |")
    print("lateness: send_after/start_timer, 10,000 concurrent timers each, 100 ms requested, nanoseconds late (p50/p99)")
    print("| timer kind | OTP p50 ns median [min–max] / p99 ns median [min–max] | Arinsal p50 ns median [min–max] / p99 ns median [min–max] |")
    print("|---|---:|---:|")
    for kind in ("send_after", "start_timer"):
        cells = []
        for runtime in ("erts", "arinsal"):
            samples = [sample_lateness(runtime, kind, ROOT / "tmp", binary) for _ in range(LAT_RUNS)]
            p50s = [sample[0] for sample in samples]
            p99s = [sample[1] for sample in samples]
            cells.append(
                f"{statistics.median(p50s):.0f} [{min(p50s)}–{max(p50s)}] / "
                f"{statistics.median(p99s):.0f} [{min(p99s)}–{max(p99s)}]"
            )
        print(f"| {kind} | {cells[0]} | {cells[1]} |")


if __name__ == "__main__":
    main()
