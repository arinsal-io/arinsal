#!/usr/bin/env python3
"""Compare identical benchmark kernels on Rust, Go, erts, and Arinsal."""

import argparse
import datetime as dt
import functools
import json
import math
import os
from pathlib import Path
import platform
import re
import shlex
import statistics
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
BENCH = ROOT / "tools/bench"
KERNELS = BENCH / "kernels"
GO = BENCH / "vs-go"
RUST = BENCH / "vs-rust"
OUT = BENCH / "out"
RUNTIMES = ("rust", "go", "erts", "arinsal")
# The first six arguments preserve the original suite's workload sizes.
CASES = {
    "fib": ([35], [20]),
    "trees": ([18], [12]),
    "nbody": ([2000000], [10000]),
    "idle": ([0], [0]),
    "tasks_100k": ([100000], [1000]),
    "tasks_1m": ([1000000], [10000]),
    "ring": ([1000, 2000000], [100, 1000]),
    "pingpong": ([1000000], [1000]),
    "bigmsg": ([200], [2]),
    "map_update": ([4000000], [10000]),
    "map_update_small": ([4000000], [10000]),
    "binary_parse": ([128], [1]),
    "ets": ([12000000], [10000]),
    "fanin": ([2000000], [10000]),
    "fanout": ([1000000], [10000]),
    "forward": ([1500], [20]),
    "broadcast": ([12], [2]),
}


def call(args, **kwargs):
    return subprocess.run(args, cwd=ROOT, text=True, capture_output=True, **kwargs)


def build(runtimes):
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "ebin").mkdir(exist_ok=True)
    steps = []
    if "go" in runtimes:
        steps.append(["go", "build", "-o", str(OUT / "gob"), str(GO / "bench.go")])
    if "rust" in runtimes:
        steps.append(["cargo", "build", "--manifest-path", str(RUST / "Cargo.toml"), "--release"])
    if "erts" in runtimes or "arinsal" in runtimes:
        steps.append(["erlc", "-o", str(OUT / "ebin"), str(KERNELS / "bench.erl")])
    for command in steps:
        print("Building:", shlex.join(command), flush=True)
        result = call(command)
        if result.returncode:
            raise RuntimeError(result.stdout + result.stderr)


def command_for(runtime, name, arguments):
    fn = "tasks" if name.startswith("tasks_") else name
    suffix = [fn, *map(str, arguments)]
    if runtime == "rust":
        return [str(RUST / "target/release/bench"), *suffix]
    if runtime == "go":
        return [str(OUT / "gob"), *suffix]
    if runtime == "erts":
        return ["erl", "-noshell", "+S", "4:4", "+P", "2000000", "-pa", str(OUT / "ebin"), "-run", "bench", "main", *suffix]
    return [str(ROOT / "target/release/arinsal"), "eval", "bench", *suffix]


def parse_output(output, name):
    lines = output.strip().splitlines()
    fn = "tasks" if name.startswith("tasks_") else name
    if len(lines) < 2 or "unsupported" in output.lower():
        raise ValueError(f"missing result or unsupported: {output[:200]!r}")
    match = re.fullmatch(rf"{re.escape(fn)}\s+([0-9]+(?:\.[0-9]+)?)ms", lines[-1].strip())
    if not match:
        raise ValueError(f"missing kernel time: {output[:200]!r}")
    value = lines[-2].strip()
    try:
        parsed = float(value) if name == "nbody" else int(value)
    except ValueError as exc:
        raise ValueError(f"invalid result: {value!r}") from exc
    return parsed, float(match.group(1))


def rss_command(command):
    if platform.system() == "Darwin" and bsd_time_available():
        return ["/usr/bin/time", "-l", *command], "bytes"
    return ["gtime", "-f", "MAX_RSS_KB=%M", *command], "kb"


@functools.cache
def bsd_time_available():
    probe = call(["/usr/bin/time", "-l", "true"])
    return probe.returncode == 0 and "maximum resident set size" in probe.stderr


def parse_rss(stderr, unit):
    if unit == "bytes":
        match = re.search(r"^\s*(\d+)\s+maximum resident set size\s*$", stderr, re.M)
        if match:
            return int(match.group(1))
    else:
        match = re.search(r"^MAX_RSS_KB=(\d+)\s*$", stderr, re.M)
        if match:
            return int(match.group(1)) * 1024
    raise ValueError(f"peak RSS missing: {stderr[:300]!r}")


def version(command):
    try:
        result = call(command, timeout=10)
        if result.returncode:
            return "unavailable"
        return (result.stdout + result.stderr).strip().splitlines()[0]
    except (OSError, subprocess.SubprocessError, IndexError):
        return "unavailable"


def machine_info():
    info = {"system": platform.platform(), "machine": platform.machine(), "logical_cores": os.cpu_count(),
            "go": version(["go", "version"]), "rustc": version(["rustc", "--version"]),
            "hyperfine": version(["hyperfine", "--version"]),
            "erts": version(["erl", "-noshell", "-eval", 'io:format("OTP ~s ERTS ~s~n",[erlang:system_info(otp_release), erlang:system_info(version)]),halt().'])}
    if platform.system() == "Darwin":
        info["cpu"] = version(["sysctl", "-n", "machdep.cpu.brand_string"])
        if info["cpu"] == "unavailable":
            info["cpu"] = "Apple Silicon (machine specification)"
        info["macos"] = version(["sw_vers", "-productVersion"])
    else:
        info["cpu"] = platform.processor()
    info["rss_tool"] = "/usr/bin/time -l" if platform.system() == "Darwin" and bsd_time_available() else "gtime -f %M"
    return info


def runtime_versions():
    """Return tool versions stored with each compact history entry."""
    otp_script = (
        'case file:read_file(filename:join([code:root_dir(), "releases", '
        'erlang:system_info(otp_release), "OTP_VERSION"])) of '
        '{ok, B} -> io:format("~s", [string:trim(binary_to_list(B))]); '
        '_ -> io:format("unavailable") end, '
        'io:format("|~s", [erlang:system_info(version)]), halt().'
    )
    otp_erts = version(["erl", "-noshell", "-eval", otp_script])
    if "|" in otp_erts:
        otp, erts = otp_erts.split("|", 1)
    else:
        otp, erts = "unavailable", "unavailable"
    elixir_output = call(["elixir", "--version"], timeout=10)
    elixir = "unavailable"
    if elixir_output.returncode == 0:
        elixir = next((line.strip() for line in (elixir_output.stdout + elixir_output.stderr).splitlines()
                       if line.strip().startswith("Elixir ")), "unavailable")
    return {"otp": otp, "erts": erts, "elixir": elixir,
            "go": version(["go", "version"]), "rust": version(["rustc", "--version"])}


def git_sha(root=ROOT):
    """Return HEAD with a suffix when tracked or untracked work is present."""
    result = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, text=True, capture_output=True)
    if result.returncode:
        return "unknown"
    sha = result.stdout.strip()
    status = subprocess.run(["git", "status", "--porcelain"], cwd=root, text=True, capture_output=True)
    return sha + ("-dirty" if status.returncode == 0 and status.stdout.strip() else "")


HISTORY_FIELDS = ("date", "sha", "machine", "otp", "erts", "elixir", "go", "rust", "suite",
                 "benchmark", "runtime", "median_wall_ms", "stddev_wall_ms", "median_kernel_ms",
                 "peak_rss_mib", "runs", "schedulers", "cooldown", "quick", "ok")


def history_record(name, runtime, data, *, machine, versions, runs, schedulers, cooldown, quick, sha):
    good = data.get("status") == "ok"
    record = {
        "date": dt.datetime.now(dt.timezone.utc).isoformat(), "sha": sha, "machine": machine,
        **versions, "suite": "kernels", "benchmark": name, "runtime": runtime,
        "median_wall_ms": data.get("wall_median_ms") if good else None,
        "stddev_wall_ms": data.get("wall_stddev_ms") if good else None,
        "median_kernel_ms": data.get("kernel_median_ms") if good else None,
        "peak_rss_mib": data.get("peak_rss_median_bytes") / 1048576 if good else None,
        "runs": runs, "schedulers": schedulers, "cooldown": cooldown,
        "quick": quick, "ok": good,
    }
    return {field: record[field] for field in HISTORY_FIELDS}


def append_history(name, runtime, data, *, machine, versions, runs, schedulers, cooldown, quick, sha):
    record = history_record(name, runtime, data, machine=machine, versions=versions, runs=runs,
                            schedulers=schedulers, cooldown=cooldown, quick=quick, sha=sha)
    path = BENCH / "history" / machine / f"otp-{versions['otp']}" / "results.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(record, separators=(",", ":")) + "\n")
    return path


# Benchmarks whose gate is not Go (docs/benchmarking.md): ETS has no Go equivalent.
GATES = {"ets": "erts"}


def scoreboard_verdict(arinsal, go):
    if not arinsal or not go or arinsal.get("median_kernel_ms") is None or go.get("median_kernel_ms") is None:
        return "FAIL (n/a)"
    if arinsal.get("peak_rss_mib") is None or go.get("peak_rss_mib") is None:
        return "FAIL (n/a)"
    time_ratio = arinsal["median_kernel_ms"] / go["median_kernel_ms"] if go["median_kernel_ms"] else math.inf
    rss_ratio = arinsal["peak_rss_mib"] / go["peak_rss_mib"] if go["peak_rss_mib"] else math.inf
    verdict = "PASS" if time_ratio < 1 and rss_ratio < 1 else "FAIL"
    return f"{verdict} (time {time_ratio:.2f}×, RSS {rss_ratio:.2f}×)"


def gate_runtime(benchmark):
    return GATES.get(benchmark, "go")


def format_score_cell(record):
    if not record or not record.get("ok") or record.get("median_kernel_ms") is None:
        return "—"
    return f"{record['median_kernel_ms']:.2f} ms, {record['peak_rss_mib']:.2f} MiB"


def generate_scoreboard(history_root=None):
    history_root = history_root or BENCH / "history"
    latest = {}
    for path in sorted(history_root.glob("**/results.jsonl")):
        with path.open(encoding="utf-8") as stream:
            for line in stream:
                if not line.strip():
                    continue
                record = json.loads(line)
                key = (record["benchmark"], record["runtime"])
                current = latest.get(key)
                if current is None or record["date"] >= current["date"]:
                    latest[key] = record
    benchmarks = sorted({name for name, _runtime in latest})
    newest = max(latest.values(), key=lambda record: record["date"], default=None)
    if newest:
        versions = ", ".join(f"{name} {newest[name]}" for name in ("otp", "erts", "elixir", "go", "rust"))
        header = f"Date: {newest['date'][:10]} · SHA: `{newest['sha']}` · Versions: {versions}"
    else:
        header = "Date: — · SHA: — · Versions: —"
    rows = ["<!-- generated — do not edit -->", "# Benchmark scoreboard", "", header, "",
            "| Benchmark | Go (kernel, RSS) | Arinsal (kernel, RSS) | erts (kernel, RSS) | Rust (kernel, RSS) | Gate | Verdict |",
            "|---|---:|---:|---:|---:|---|---|"]
    for name in benchmarks:
        cells = {runtime: latest.get((name, runtime)) for runtime in ("go", "arinsal", "erts", "rust")}
        rows.append("| " + " | ".join([name, *(format_score_cell(cells[runtime]) for runtime in
                                               ("go", "arinsal", "erts", "rust")),
                                               gate_runtime(name),
                                               scoreboard_verdict(cells["arinsal"], cells[gate_runtime(name)])]) + " |")
    return "\n".join(rows) + "\n"


def write_scoreboard():
    path = ROOT / "docs/bench/scoreboard.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(generate_scoreboard(), encoding="utf-8")
    print(f"Generated scoreboard: {path.relative_to(ROOT)}")


def warn_environment():
    try:
        load = os.getloadavg()[0]
        if load > 2:
            print(f"WARNING: load average {load:.2f} exceeds 2", file=sys.stderr)
    except OSError:
        pass
    if platform.system() == "Darwin":
        batt = call(["pmset", "-g", "batt"])
        if "Battery Power" in batt.stdout:
            print("WARNING: running on battery power", file=sys.stderr)


def equal_result(left, right, name):
    if name == "nbody":
        return math.isclose(left, right, rel_tol=1e-9, abs_tol=1e-7)
    return left == right


def run_case(runtime, name, arguments, runs, warmup, cooldown):
    command = command_for(runtime, name, arguments)
    if runtime == "arinsal" and not Path(command[0]).exists():
        return {"status": "n/a", "reason": "Arinsal executable missing", "command": command}
    try:
        probe = call(command, timeout=180)
    except subprocess.TimeoutExpired:
        if runtime == "arinsal":
            return {"status": "n/a", "reason": "Arinsal probe timed out", "command": command}
        raise
    if probe.returncode or "unsupported" in (probe.stdout + probe.stderr).lower():
        reason = (probe.stdout + probe.stderr).strip()[:300] or f"exit {probe.returncode}"
        if runtime == "arinsal":
            return {"status": "n/a", "reason": reason, "command": command}
        raise RuntimeError(f"{name}/{runtime}: {reason}")
    try:
        expected, _ = parse_output(probe.stdout, name)
    except ValueError as exc:
        if runtime == "arinsal":
            return {"status": "n/a", "reason": str(exc), "command": command}
        raise
    env = os.environ.copy()
    if runtime == "go":
        env["GOMAXPROCS"] = "4"
    with tempfile.NamedTemporaryFile(suffix=".json", dir=OUT, delete=False) as temp:
        export = Path(temp.name)
    try:
        hyperfine = ["hyperfine", "--warmup", str(warmup), "--runs", str(runs), "--export-json", str(export)]
        if cooldown:
            hyperfine += ["--prepare", f"sleep {cooldown}"]
        hyperfine += [shlex.join(command)]
        measured = call(hyperfine, env=env)
        if measured.returncode:
            if runtime == "arinsal":
                return {"status": "n/a", "reason": (measured.stdout + measured.stderr)[-300:], "command": command}
            raise RuntimeError(f"hyperfine {name}/{runtime}: {measured.stdout}\n{measured.stderr}")
        hyperfine_data = json.loads(export.read_text())["results"][0]
    finally:
        export.unlink(missing_ok=True)
    wall = hyperfine_data["times"]
    rss_runs = []
    measured_command, unit = rss_command(command)
    for index in range(runs):
        if cooldown and index:
            time.sleep(cooldown)
        result = call(measured_command, env=env, timeout=300)
        if result.returncode:
            if runtime == "arinsal":
                return {"status": "n/a", "reason": (result.stdout + result.stderr)[-300:], "command": command}
            raise RuntimeError(f"RSS {name}/{runtime}: {result.stdout}\n{result.stderr}")
        try:
            value, kernel_ms = parse_output(result.stdout, name)
            rss_bytes = parse_rss(result.stderr, unit)
        except ValueError as exc:
            if runtime == "arinsal":
                return {"status": "n/a", "reason": str(exc), "command": command}
            raise
        rss_runs.append({"result": value, "kernel_ms": kernel_ms, "peak_rss_bytes": rss_bytes, "stdout": result.stdout})
    for value in [expected, *(run["result"] for run in rss_runs)]:
        if not equal_result(expected, value, name):
            raise RuntimeError(f"result varied in {name}/{runtime}: {expected} vs {value}")
    cv = statistics.stdev(wall) / statistics.mean(wall) if len(wall) > 1 else 0.0
    if cv > 0.05:
        print(f"WARNING: {name}/{runtime} wall-time CV {cv:.1%} exceeds 5%", file=sys.stderr)
    return {"status": "ok", "command": command, "result": expected, "probe_stdout": probe.stdout,
            "hyperfine": hyperfine_data, "wall_seconds": wall, "rss_runs": rss_runs,
            "wall_median_ms": statistics.median(wall)*1000,
            "wall_stddev_ms": statistics.stdev(wall)*1000 if len(wall)>1 else 0,
            "kernel_median_ms": statistics.median(r["kernel_ms"] for r in rss_runs),
            "peak_rss_median_bytes": statistics.median(r["peak_rss_bytes"] for r in rss_runs), "wall_cv": cv}


def cell(data, name, arguments):
    if not data or data["status"] != "ok":
        return "n/a"
    wall = data["wall_median_ms"]
    sigma = data["wall_stddev_ms"]
    kernel = data["kernel_median_ms"]
    rss = data["peak_rss_median_bytes"] / 1048576
    extra = ""
    if name == "pingpong":
        extra = f", {kernel*1e6/arguments[0]:.0f} ns/RT"
    return f"{wall:.1f}±{sigma:.1f} ms wall; {kernel:.1f} ms kernel; {rss:.1f} MiB{extra}"


def markdown(results, runtimes, baseline=None):
    rows = ["| bench | rust | go | erts | arinsal | arinsal/go | arinsal/erts |",
            "|---|---|---|---|---|---|---|"]
    regressions = []
    for name, entry in results.items():
        cells = entry["runtimes"]
        def ratio(denom):
            if cells.get("arinsal", {}).get("status") != "ok" or cells.get(denom, {}).get("status") != "ok":
                return "n/a"
            return f'{cells["arinsal"]["wall_median_ms"] / cells[denom]["wall_median_ms"]:.2f}×'
        rows.append("| " + " | ".join([name, *(cell(cells.get(runtime), name, entry["arguments"]) for runtime in RUNTIMES), ratio("go"), ratio("erts")]) + " |")
        if baseline and name in baseline["benchmarks"]:
            previous = baseline["benchmarks"][name]["runtimes"]
            for runtime in runtimes:
                now, old = cells.get(runtime), previous.get(runtime)
                if not now or not old or now["status"] != "ok" or old["status"] != "ok":
                    continue
                for key in ("wall_median_ms", "kernel_median_ms", "peak_rss_median_bytes"):
                    if now[key] > 1.05 * old[key]:
                        change = f"+{(now[key]/old[key]-1)*100:.1f}%" if old[key] else "above zero baseline"
                        regressions.append(f"{name}/{runtime} {key}: {change}")
    if regressions:
        rows += ["", "Regressions >5%:", *(f"- {item}" for item in regressions)]
    return "\n".join(rows) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtimes", default=",".join(RUNTIMES))
    parser.add_argument("--bench", default=",".join(CASES))
    parser.add_argument("--runs", type=int, default=5)
    parser.add_argument("--warmup", type=int, default=1)
    parser.add_argument("--quick", action="store_true")
    parser.add_argument("--cooldown", type=float, default=2)
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--machine", default="arm64")
    parser.add_argument("--no-history", action="store_true")
    parser.add_argument("--scoreboard", action="store_true")
    args = parser.parse_args()
    if args.scoreboard:
        write_scoreboard()
        return 0
    runtimes = args.runtimes.split(",")
    names = args.bench.split(",")
    if set(runtimes)-set(RUNTIMES) or set(names)-set(CASES) or args.runs<1 or args.warmup<0 or args.cooldown<0:
        parser.error("invalid runtime, benchmark, runs, warmup, or cooldown")
    if args.quick:
        args.runs, args.warmup, args.cooldown = 1, 0, 0
    warn_environment()
    build(runtimes)
    versions = runtime_versions() if not args.quick and not args.no_history else None
    sha = git_sha() if versions else None
    results = {}
    mismatch = False
    for name in names:
        arguments = CASES[name][1 if args.quick else 0]
        cells = {}
        for runtime in runtimes:
            print(f"Running {name}/{runtime} {arguments}", flush=True)
            cells[runtime] = run_case(runtime, name, arguments, args.runs, args.warmup, args.cooldown)
            if cells[runtime]["status"] == "n/a":
                print(f"  n/a: {cells[runtime]['reason']}", flush=True)
            if versions:
                append_history(name, runtime, cells[runtime], machine=args.machine, versions=versions,
                               runs=args.runs, schedulers=4, cooldown=args.cooldown, quick=False, sha=sha)
        good = [(runtime, cell) for runtime, cell in cells.items() if cell["status"] == "ok"]
        if good:
            reference_runtime, reference = good[0]
            for runtime, value in good[1:]:
                if not equal_result(reference["result"], value["result"], name):
                    print(f"MISMATCH {name}: {reference_runtime}={reference['result']} {runtime}={value['result']}", file=sys.stderr)
                    mismatch = True
        results[name] = {"arguments": arguments, "runtimes": cells}
    payload = {"schema": 1, "timestamp_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
               "machine": machine_info(), "settings": {"runtimes": runtimes, "benchmarks": names,
               "runs": args.runs, "warmup": args.warmup, "cooldown_seconds": args.cooldown, "quick": args.quick},
               "benchmarks": results, "result_mismatch": mismatch}
    baseline = json.loads(args.baseline.read_text()) if args.baseline else None
    table = markdown(results, runtimes, baseline)
    path = args.output or OUT / f"results-{dt.datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n")
    (OUT / "latest.md").write_text(table)
    print(table)
    print(f"Raw results: {path}")
    return 1 if mismatch else 0


if __name__ == "__main__":
    sys.exit(main())
