#!/usr/bin/env python3
"""Collect JIT coverage stats, kernel ns/op, and two-scenario time attribution.

Stats are read from `ARINSAL_JIT_STATS` lines on stderr. Instruction counters
use `ARINSAL_JIT_STATS=1`. Wall-clock buckets use a separate
`ARINSAL_JIT_TIME=1` run, without the per-instruction native counter.

Arinsal is always started under `timeout`. This script does not start `erl`
nodes of its own except the one-shot `timer:tc` kernel runs, which halt.
"""

from __future__ import annotations

import argparse
import os
import re
import statistics
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DEMO = ROOT / "examples/arinsal_demo"
OUT = ROOT / "tmp/jit-coverage"
SUITES = [
    "pure",
    "maps",
    "lists",
    "text",
    "binary",
    "tuples",
    "control",
    "processes",
    "ets",
    "cache",
    "work",
    "json",
]
KERNELS = [
    ("tail", 200_000, 200_000),
    ("list", 20_000, 20_000),
    ("fib", 22, 57_313),
    ("tuple", 50_000, 50_000),
    ("binary", 20_000, 80_000),
]
COUNT_KEYS = [
    "compiled",
    "rejected",
    "entered",
    "entries",
    "resumed",
    "native",
    "helper",
    "interpreted",
    "enter_native",
    "leave_native",
    "bails",
    "compile_us",
    "code_bytes",
]
TIME_KEYS = ["native_us", "sync_us", "interp_us", "call_us", "runtime_us"]

def run(cmd: list[str], cwd: Path, env: dict[str, str] | None, timeout: int) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        cwd=cwd,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        check=False,
    )


def parse_kv(body: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for part in body.split():
        if "=" not in part:
            continue
        key, value = part.split("=", 1)
        fields[key] = value.rstrip("%")
    return fields


def parse_stats(text: str) -> dict:
    """Sum execution counters across scheduler VMs. Function counts are also kept per replica."""
    summary = Counter()
    per_replica: list[dict[str, int]] = []
    helpers: Counter[str] = Counter()
    bails: Counter[str] = Counter()
    time = Counter()
    for line in text.splitlines():
        if "ARINSAL_JIT_STATS " not in line:
            continue
        line = line[line.index("ARINSAL_JIT_STATS ") + len("ARINSAL_JIT_STATS ") :]
        if line.startswith("helper "):
            name, count = line[len("helper ") :].split("=", 1)
            helpers[name] += int(count)
        elif line.startswith("bail "):
            name, count = line[len("bail ") :].split("=", 1)
            bails[name] += int(count)
        elif line.startswith("time "):
            for key, value in parse_kv(line[len("time ") :]).items():
                time[key] += int(float(value))
        else:
            fields = {key: int(float(value)) for key, value in parse_kv(line).items()}
            per_replica.append(fields)
            for key in COUNT_KEYS:
                summary[key] += fields.get(key, 0)
    total = summary["native"] + summary["helper"] + summary["interpreted"]
    return {
        "replicas": len(per_replica),
        "summary": summary,
        "per_replica": per_replica,
        "helpers": helpers,
        "bails": bails,
        "time": time,
        "total": total,
    }


def share(count: int, total: int) -> float:
    return 0.0 if total == 0 else 100.0 * count / total


def replica_max(parsed: dict, key: str) -> int:
    values = [row.get(key, 0) for row in parsed["per_replica"]]
    return max(values) if values else 0


def fmt_summary(parsed: dict) -> str:
    summary: Counter = parsed["summary"]
    total = parsed["total"]
    parts = [f"{key}={summary[key]}" for key in COUNT_KEYS]
    parts.append(f"entered_max={replica_max(parsed, 'entered')}")
    parts.append(f"compiled_max={replica_max(parsed, 'compiled')}")
    parts.append(f"native_share={share(summary['native'], total):.1f}%")
    parts.append(f"helper_share={share(summary['helper'], total):.1f}%")
    parts.append(f"interp_share={share(summary['interpreted'], total):.1f}%")
    parts.append(f"replicas={parsed['replicas']}")
    return " ".join(parts)


def write_parsed(path: Path, parsed: dict) -> None:
    lines = [fmt_summary(parsed)]
    for name, count in parsed["helpers"].most_common():
        lines.append(f"helper {name}={count}")
    for name, count in parsed["bails"].most_common():
        lines.append(f"bail {name}={count}")
    if parsed["time"]:
        lines.append("time " + " ".join(f"{key}={parsed['time'][key]}" for key in TIME_KEYS))
    path.write_text("\n".join(lines) + "\n")


def compare_phase(suite: str, phase: str, extra_env: dict[str, str], label: str) -> int:
    """One Arinsal phase of `make compare`, after beams and the erts check exist."""
    OUT.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env["BENCH_QUICK"] = "1"
    env["MIX_ENV"] = "bench"
    env["SUITE"] = suite
    env.update(extra_env)
    if phase == "check":
        env["RUNTIME"] = "arinsal"
        env["BENCH_MODE"] = "check"
        reference = DEMO / "bench/out/check-erts.txt"
        expected = OUT / f"check-erts-{suite}.txt"
        selected = [line for line in reference.read_text().splitlines() if line.startswith(f"{suite}\t")]
        if not selected:
            raise SystemExit(f"no erts check results for suite {suite} in {reference}")
        expected.write_text("\n".join(selected) + "\n")
        env["BENCH_EXPECT"] = str(expected)
    elif phase == "cold":
        env["RUNTIME"] = "arinsal_cold"
        env["BENCH_MODE"] = "run"
    elif phase == "warm":
        env["RUNTIME"] = "arinsal_warm"
        env["BENCH_MODE"] = "run"
    else:
        raise SystemExit(f"unknown phase {phase}")
    shim = ROOT / "tmp/shim-release"
    path = f"{shim}:{env.get('PATH', '')}"
    env["PATH"] = path
    log = OUT / f"{label}-{suite}-{phase}.log"
    print(f"{label} {suite} {phase}", flush=True)
    completed = run(
        ["timeout", "600", "mix", "run", "--no-compile", "--no-deps-check", "bench/run.exs"],
        DEMO,
        env,
        timeout=620,
    )
    text = completed.stdout + "\n----- stderr -----\n" + completed.stderr
    log.write_text(text)
    parsed = parse_stats(text)
    write_parsed(OUT / f"{label}-{suite}-{phase}.stats", parsed)
    print(f"  exit {completed.returncode} {fmt_summary(parsed)}", flush=True)
    if completed.returncode != 0:
        tail = "\n".join((completed.stderr or completed.stdout).splitlines()[-8:])
        print(tail, flush=True)
    return completed.returncode


def ensure_compare_baseline() -> None:
    """Compile bench beams and record the erts check file once."""
    env = os.environ.copy()
    env["MIX_ENV"] = "bench"
    print("shim + bench compile + erts check", flush=True)
    build = run(["make", "shim"], DEMO, env, timeout=900)
    if build.returncode != 0:
        sys.stderr.write(build.stderr)
        raise SystemExit(f"make shim failed: {build.returncode}")
    compile_env = env.copy()
    compiled = run(["mix", "compile"], DEMO, compile_env, timeout=600)
    if compiled.returncode != 0:
        sys.stderr.write(compiled.stderr[-2000:])
        raise SystemExit(f"mix compile failed: {compiled.returncode}")
    if (DEMO / "bench/out/check-erts.txt").exists():
        return
    erts = run(
        [
            "mix",
            "run",
            "--no-deps-check",
            "bench/run.exs",
        ],
        DEMO,
        {**env, "BENCH_QUICK": "1", "RUNTIME": "erts", "BENCH_MODE": "check_and_run", "SUITE": "all"},
        timeout=900,
    )
    (OUT / "erts-check.log").write_text(erts.stdout + "\n" + erts.stderr)
    if erts.returncode != 0:
        raise SystemExit(f"erts check failed: {erts.returncode}")


def kernels(runs: int) -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    beam = ROOT / "tmp/pf_exec"
    beam.mkdir(parents=True, exist_ok=True)
    compiled = run(
        ["erlc", "-o", str(beam), str(ROOT / "crates/vm/tests/fixtures/kernels.erl")],
        ROOT,
        None,
        timeout=60,
    )
    if compiled.returncode != 0:
        raise SystemExit(compiled.stderr)
    cli = ROOT / "target/release/arinsal"
    modes = [("off", {"ARINSAL_JIT": "0"}), ("default", {}), ("threshold1", {"ARINSAL_JIT_THRESHOLD": "1"})]
    rows = ["kernel,mode,median_ns,min_ns,max_ns,result"]
    for name, n, units in KERNELS:
        expected = None
        for mode, extra in modes:
            values = []
            result = None
            for _ in range(runs):
                env = os.environ.copy()
                env.update(extra)
                completed = run(
                    [
                        "timeout",
                        "120",
                        str(cli),
                        "eval",
                        "--schedulers",
                        "1",
                        "-pa",
                        str(beam),
                        "kernels",
                        name,
                        str(n),
                    ],
                    ROOT,
                    env,
                    timeout=130,
                )
                match = re.search(rf"{name} (\d+\.\d+)ms", completed.stdout)
                if completed.returncode != 0 or not match:
                    raise SystemExit(f"{name} {mode} failed\n{completed.stdout}\n{completed.stderr}")
                result = completed.stdout.splitlines()[0].strip()
                if expected is None:
                    expected = result
                if result != expected:
                    raise SystemExit(f"{name} {mode} result {result} != {expected}")
                values.append(float(match.group(1)) * 1_000_000 / units)
            rows.append(
                f"{name},{mode},{statistics.median(values):.3f},{min(values):.3f},{max(values):.3f},{result}"
            )
            print(rows[-1], flush=True)
        # erts, one-shot, after Arinsal so a mismatch fails against the same result.
        values = []
        for _ in range(runs):
            expr = f"{{Us,V}}=timer:tc(kernels,{name},[{n}]),io:format(\"~p ~p~n\",[Us,V]),halt()."
            completed = run(
                ["erl", "-noshell", "-pa", str(beam), "-eval", expr],
                ROOT,
                None,
                timeout=60,
            )
            match = re.search(r"(\d+)\s+([^\s]+)", completed.stdout)
            if completed.returncode != 0 or not match:
                raise SystemExit(f"erts {name} failed\n{completed.stdout}\n{completed.stderr}")
            if match.group(2) != expected:
                raise SystemExit(f"erts {name} result {match.group(2)} != Arinsal {expected}")
            values.append(int(match.group(1)) * 1000 / units)
        rows.append(
            f"{name},erts,{statistics.median(values):.3f},{min(values):.3f},{max(values):.3f},{expected}"
        )
        print(rows[-1], flush=True)
        # One instrumented pass at threshold 1 for the opcode mix. Not a timing.
        env = os.environ.copy()
        env["ARINSAL_JIT_THRESHOLD"] = "1"
        env["ARINSAL_JIT_STATS"] = "1"
        completed = run(
            ["timeout", "120", str(cli), "eval", "--schedulers", "1", "-pa", str(beam), "kernels", name, str(n)],
            ROOT,
            env,
            timeout=130,
        )
        parsed = parse_stats(completed.stderr)
        write_parsed(OUT / f"kernel-{name}.stats", parsed)
        print(f"  stats {name} {fmt_summary(parsed)}", flush=True)
    (OUT / "kernels.csv").write_text("\n".join(rows) + "\n")


def code_paths() -> list[str]:
    ebin = DEMO / "_build/bench/lib/arinsal_demo/ebin"
    if not ebin.is_dir():
        raise SystemExit(f"missing {ebin}; run compare or mix compile MIX_ENV=bench first")
    configured = os.environ.get("ARINSAL_ELIXIR_ROOT")
    if configured:
        elixir = Path(configured)
        if elixir.name != "lib":
            elixir = elixir / "lib"
    else:
        ebin = subprocess.check_output(
            ["elixir", "-e", "IO.write(:code.lib_dir(:elixir))"], text=True
        )
        elixir = Path(ebin).parent.parent
    dirs = [ebin, OUT]
    if elixir.is_dir():
        dirs.extend(path / "ebin" for path in sorted(elixir.iterdir()) if (path / "ebin").is_dir())
    pa: list[str] = []
    for directory in dirs:
        pa.extend(["-pa", str(directory)])
    return pa


def attribute(reps: int) -> None:
    """Enum pipeline and Map.put 1k at threshold 1, with timers.

    `jit_attrib` tail-calls the demo function `reps` times. Timers include
    one compile of the hot functions plus the loop. A separate reps=1 run is
    the control subtracted in the report.
    """
    OUT.mkdir(parents=True, exist_ok=True)
    compiled = run(
        ["erlc", "-o", str(OUT), str(ROOT / "tools/profile/jit_attrib.erl")],
        ROOT,
        None,
        timeout=60,
    )
    if compiled.returncode != 0:
        raise SystemExit(compiled.stderr)
    pa = code_paths()
    cli = ROOT / "target/release/arinsal"
    scenarios = [("enum_pipeline", "enum_n"), ("map_put_1k", "map_n")]
    for label, function in scenarios:
        expected = run(
            ["erl", "-noshell", *pa, "-eval", f'io:format("~p~n",[jit_attrib:{function}(1)]),halt().'],
            ROOT, None, timeout=60,
        )
        if expected.returncode != 0:
            raise SystemExit(f"erts {label} failed: {expected.stderr}")
        expected_result = expected.stdout.strip().splitlines()[-1]
        for tag, count in (("once", 1), ("loop", reps)):
            for measure, instrument in (("counts", "ARINSAL_JIT_STATS"), ("time", "ARINSAL_JIT_TIME")):
                env = os.environ.copy()
                env["ARINSAL_JIT_THRESHOLD"] = "1"
                env[instrument] = "1"
                cmd = [
                    "timeout", "180", str(cli), "eval", "--schedulers", "1",
                    *pa, "jit_attrib", function, str(count),
                ]
                print(f"attrib {label} {tag} {measure} n={count}", flush=True)
                completed = run(cmd, ROOT, env, timeout=190)
                output = completed.stdout.splitlines()
                if completed.returncode != 0 or not output or output[0].strip() != expected_result:
                    raise SystemExit(f"attrib {label} {tag} {measure} mismatch/failed: {completed.stdout}\n{completed.stderr[-2000:]}")
                text = completed.stdout + "\n----- stderr -----\n" + completed.stderr
                (OUT / f"attrib-{label}-{tag}-{measure}.log").write_text(text)
                parsed = parse_stats(completed.stderr)
                write_parsed(OUT / f"attrib-{label}-{tag}-{measure}.stats", parsed)
                print(f"  result={output[0]} elapsed={output[1]} {fmt_summary(parsed)}", flush=True)
                if parsed["time"]:
                    print("  time " + " ".join(f"{k}={parsed['time'][k]}" for k in TIME_KEYS), flush=True)


def sample_scenarios() -> None:
    """Sample repeated standalone calls without counter or timer probes."""
    OUT.mkdir(parents=True, exist_ok=True)
    pa = code_paths()
    cli = ROOT / "target/release/arinsal"
    failed = False
    for label, function in (("enum", "enum_n"), ("map", "map_n")):
        env = os.environ.copy()
        env["ARINSAL_JIT_THRESHOLD"] = "1"
        process = subprocess.Popen(
            ["timeout", "12", "sh", "-c", 'printf "PID=%s\\n" "$$"; exec "$@"',
             "sh", str(cli), "eval", "--schedulers", "1", *pa,
             "jit_attrib", function, "100000"],
            cwd=ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True,
        )
        try:
            assert process.stdout is not None
            pid_line = process.stdout.readline().strip()
            if not pid_line.startswith("PID="):
                raise SystemExit(f"sample {label}: child PID missing: {pid_line}")
            time.sleep(0.5)
            sampled = run(
                ["sample", pid_line[4:], "3", "1", "-file", str(OUT / f"{label}-final.sample")],
                ROOT, None, timeout=15,
            )
            (OUT / f"{label}-final.sample.log").write_text(sampled.stdout + sampled.stderr)
            print(f"sample {label}: exit {sampled.returncode}", flush=True)
            if sampled.returncode != 0:
                failed = True
                print(sampled.stderr[-2000:], flush=True)
        finally:
            process.wait(timeout=15)
    if failed:
        raise SystemExit("sample failed for one or more scenarios")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "command",
        choices=["baseline", "phase", "kernels", "attrib", "sample", "suites"],
    )
    parser.add_argument("--suite", default="pure")
    parser.add_argument("--phase", default="warm", choices=["check", "cold", "warm"])
    parser.add_argument("--label", default="default")
    parser.add_argument("--threshold", default="")
    parser.add_argument("--runs", type=int, default=5)
    parser.add_argument("--reps", type=int, default=1)
    args = parser.parse_args()
    extra: dict[str, str] = {"ARINSAL_JIT_STATS": "1"}
    if args.threshold:
        extra["ARINSAL_JIT_THRESHOLD"] = args.threshold
    if args.command == "baseline":
        ensure_compare_baseline()
    elif args.command == "phase":
        code = compare_phase(args.suite, args.phase, extra, args.label)
        raise SystemExit(code)
    elif args.command == "suites":
        failed = 0
        for suite in SUITES:
            for phase in ("check", "cold", "warm"):
                failed |= compare_phase(suite, phase, extra, args.label) != 0
        raise SystemExit(1 if failed else 0)
    elif args.command == "kernels":
        kernels(args.runs)
    elif args.command == "attrib":
        attribute(args.reps)
    elif args.command == "sample":
        sample_scenarios()


if __name__ == "__main__":
    main()
