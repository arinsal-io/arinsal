#!/usr/bin/env python3
"""Build and measure the HTTP reference services with oha."""

import argparse
import ctypes
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone
from urllib.error import URLError
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[2]
SERVICES = {
    "go": {"port": 8081, "build": ["go", "build", "-o", str(ROOT / "bench/out/http-go"), "."], "cwd": ROOT / "examples/http/go", "run": [str(ROOT / "bench/out/http-go")]},
    "rust": {"port": 8082, "build": ["cargo", "build", "--release", "--manifest-path", "examples/http/rust/Cargo.toml"], "cwd": ROOT, "run": [str(ROOT / "examples/http/rust/target/release/arinsal-http-rust")]},
    "elixir": {"port": 8083, "build": ["mix", "deps.get", "--only", "prod"], "cwd": ROOT / "examples/http/elixir_bandit", "run": ["mix", "run", "--no-halt"]},
    "arinsal": {"port": 8083, "build": ["mix", "deps.get", "--only", "prod"], "cwd": ROOT / "examples/http/elixir_bandit", "run": ["mix", "run", "--no-halt"]},
}
ENDPOINTS = {"plaintext": ("/plaintext", "GET"), "json": ("/json", "GET"), "work": ("/work?n=20", "GET"), "echo": ("/echo", "POST")}


def run(command, *, cwd, env=None):
    subprocess.run(command, cwd=cwd, env=env, check=True)


def cpu_timebase():
    class Timebase(ctypes.Structure):
        _fields_ = [("numer", ctypes.c_uint32), ("denom", ctypes.c_uint32)]
    info = Timebase()
    ctypes.CDLL("/usr/lib/libSystem.B.dylib").mach_timebase_info(ctypes.byref(info))
    return info.numer / info.denom


def task_times(pid):
    """Read Darwin task counters directly because sandboxed macOS blocks ps."""
    try:
        libproc = ctypes.CDLL("/usr/lib/libproc.dylib")
        info = ctypes.create_string_buffer(256)
        size = libproc.proc_pidinfo(pid, 4, 0, info, len(info))  # PROC_PIDTASKINFO
        if size < 32:
            return None
        virtual, resident, user_ns, system_ns = (int.from_bytes(info.raw[i:i + 8], "little") for i in (0, 8, 16, 24))
        return {"rss": resident, "cpu_ticks": user_ns + system_ns}
    except (OSError, AttributeError):
        return None


def wait_ready(port, process):
    url = f"http://127.0.0.1:{port}/plaintext"
    deadline = time.monotonic() + 40
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"server exited during startup (status {process.returncode})")
        try:
            with urlopen(url, timeout=1) as response:
                if response.read() == b"Hello, World!":
                    return
        except (URLError, TimeoutError, OSError):
            time.sleep(0.1)
    raise TimeoutError(f"server on port {port} did not become ready")


def find_arinsal():
    shim_dir = ROOT / "target/release/arinsal-erl-shim"
    shim = shim_dir / "erl"
    if not shim.exists():
        return None
    return shim_dir


def parse_oha(raw):
    data = json.loads(raw)
    metrics = data.get("metrics", {})
    latency = metrics.get("latency_ms", {})
    return {
        "achieved_rps": metrics.get("requests_per_sec", data.get("summary", {}).get("requestsPerSec")),
        "p50_ms": latency.get("p50"),
        "p90_ms": data.get("latencyPercentiles", {}).get("p90", latency.get("p95")),
        "p99_ms": latency.get("p99"),
        "p999_ms": data.get("latencyPercentiles", {}).get("p99.9"),
        "error_rate": 1 - metrics.get("success_rate", data.get("summary", {}).get("successRate", 1)),
        "raw": data,
    }


def measure(name, service, rates, duration, connections, workers, warmup):
    port = service["port"]
    runtime_env = os.environ.copy()
    runtime_env.update({"PORT": str(port), "GOMAXPROCS": "4", "MIX_ENV": "prod", "ELIXIR_ERL_OPTIONS": "+S 4:4"})
    if name == "arinsal":
        runtime_env["PATH"] = str(find_arinsal()) + os.pathsep + runtime_env.get("PATH", "")
    print(f"Building {name}...", flush=True)
    run(service["build"], cwd=service["cwd"], env=runtime_env)
    log = ROOT / "bench/out" / f"{name}.log"
    with log.open("w") as output:
        process = subprocess.Popen(service["run"], cwd=service["cwd"], env=runtime_env, stdout=output, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            wait_ready(port, process)
            idle = task_times(process.pid)
            idle_rss = idle["rss"] if idle else None
            steps = []
            for endpoint, (path, method) in ENDPOINTS.items():
                endpoint_steps = []
                url = f"http://127.0.0.1:{port}{path}"
                for rate in rates:
                    if warmup:
                        subprocess.run(["oha", "-z", f"{warmup}s", "-q", str(rate), "-c", str(connections), "--worker-threads", str(workers), "--latency-correction", "--no-tui", url], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
                    step_connections = min(4096, max(connections, rate // 20))
                    command = ["oha", "-z", f"{duration}s", "-q", str(rate), "-c", str(step_connections), "--worker-threads", str(workers), "--latency-correction", "--no-tui", "--output-format", "json"]
                    if method == "POST":
                        command += ["-m", "POST", "-T", "application/json", "-d", '{"message":"Hello, World!"}']
                    command.append(url)
                    peak_rss, peak_cpu, samples = idle_rss or 0, 0.0, 0
                    started = time.monotonic()
                    previous = task_times(process.pid)
                    previous_time = started
                    with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) as load:
                        while load.poll() is None:
                            sample_time = time.monotonic()
                            current = task_times(process.pid)
                            if current:
                                peak_rss = max(peak_rss, current["rss"])
                                if previous and sample_time > previous_time:
                                    cpu = ((current["cpu_ticks"] - previous["cpu_ticks"]) * cpu_timebase()) / ((sample_time - previous_time) * 10_000_000)
                                    peak_cpu = max(peak_cpu, cpu)
                                previous = current
                                previous_time = sample_time
                            samples += 1
                            time.sleep(0.25)
                        stdout, stderr = load.communicate()
                    if load.returncode:
                        raise RuntimeError(f"oha failed ({load.returncode}): {stderr[-500:]}")
                    parsed = parse_oha(stdout)
                    step = {"requested_rps": rate, "connections": step_connections, **parsed, "peak_rss_bytes": peak_rss or None, "peak_cpu_percent": peak_cpu, "samples": samples, "duration_seconds": time.monotonic() - started}
                    endpoint_steps.append(step)
                    print(f"  {endpoint:9} {rate:>7} rps -> achieved={step['achieved_rps']} p99={step['p99_ms']}", flush=True)
                    if (step["p99_ms"] is not None and step["p99_ms"] > 50) or (step["error_rate"] or 0) > 0.01:
                        break
                steps.append({"endpoint": endpoint, "steps": endpoint_steps})
            return {"implementation": name, "pid": process.pid, "idle_rss_bytes": idle_rss, "endpoints": steps}
        finally:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--quick", action="store_true", help="short sweep for smoke/baseline in under five minutes")
    parser.add_argument("--implementations", default="go,rust,elixir,arinsal")
    parser.add_argument("--rates", help="comma-separated open-model rates")
    parser.add_argument("--duration", type=int)
    parser.add_argument("--warmup", type=int)
    parser.add_argument("--connections", type=int, default=256)
    parser.add_argument("--workers", type=int, default=2)
    args = parser.parse_args()
    if not shutil.which("oha"):
        parser.error("oha is required (install with brew install oha)")
    if args.quick:
        rates = [int(value) for value in (args.rates or "1000,5000").split(",")]
        duration, warmup = args.duration or 2, args.warmup if args.warmup is not None else 1
    else:
        rates = [int(value) for value in (args.rates or "5000,10000,20000,40000,80000,160000").split(",")]
        duration, warmup = args.duration or 20, args.warmup if args.warmup is not None else 10
    services = dict(SERVICES)
    if "arinsal" in args.implementations.split(",") and find_arinsal() is None:
        print("Skipping arinsal: target/release/arinsal-erl-shim/erl is unavailable.", file=sys.stderr)
        services.pop("arinsal")
    results = []
    out_dir = ROOT / "bench/out"
    out_dir.mkdir(parents=True, exist_ok=True)
    for name in args.implementations.split(","):
        if name not in services:
            continue
        results.append(measure(name, services[name], rates, duration, args.connections, args.workers, warmup))
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output = out_dir / f"http-{stamp}.json"
    output.write_text(json.dumps({"timestamp_utc": stamp, "quick": args.quick, "rates": rates, "duration_seconds": duration, "warmup_seconds": warmup, "workers": args.workers, "results": results}, indent=2) + "\n")
    print(f"Wrote {output.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
