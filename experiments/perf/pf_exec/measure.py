#!/usr/bin/env python3
"""Measure one-shot OTP and Arinsal kernel runs with bounded child processes."""

import argparse
import os
import re
import statistics
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
CASES = [("tail", 200_000, 200_000), ("list", 20_000, 20_000),
         ("fib", 22, 57_313), ("tuple", 50_000, 50_000),
         ("binary", 20_000, 80_000)]


def run(cmd, env=None):
    return subprocess.run(cmd, cwd=ROOT, env=env, text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          timeout=310, check=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--runs", type=int, default=5)
    args = parser.parse_args()
    beam_dir = ROOT / "tmp/pf_exec"
    beam_dir.mkdir(parents=True, exist_ok=True)
    run(["erlc", "-o", str(beam_dir), str(Path(__file__).with_name("kernels.erl"))])
    go_binary = beam_dir / "go_kernels"
    run(["go", "build", "-o", str(go_binary), str(Path(__file__).with_name("go_kernels.go"))])
    cli = ROOT / "target/release/arinsal"
    print("kernel,engine,median_ns_per_unit,min_ns_per_unit,max_ns_per_unit,result")
    for name, n, units in CASES:
        expected_result = None
        for engine in ("erts", "go", "off", "default", "always"):
            values = []
            result = None
            for _ in range(args.runs):
                if engine == "erts":
                    expr = (f"{{Us,V}}=timer:tc(kernels,{name},[{n}]),"
                            'io:format("~p ~p~n",[Us,V]),halt().')
                    completed = run(["erl", "-noshell", "-pa", str(beam_dir), "-eval", expr])
                    match = re.search(r"(\d+)\s+(\d+)", completed.stdout)
                    assert match, completed.stdout
                    ns = int(match.group(1)) * 1000
                    result = match.group(2)
                elif engine == "go":
                    completed = run([str(go_binary), name, str(n)])
                    result, ns = completed.stdout.split()
                    ns = float(ns)
                else:
                    env = os.environ.copy()
                    env["ARINSAL_JIT"] = {"off": "0", "default": "1", "always": "always"}[engine]
                    completed = run(["timeout", "300", str(cli), "eval", "--schedulers", "1",
                                     "-pa", str(beam_dir), "kernels", name, str(n)], env)
                    match = re.search(rf"{name} (\d+\.\d+)ms", completed.stdout)
                    assert match, (completed.stdout, completed.stderr)
                    ns = float(match.group(1)) * 1_000_000
                    result = completed.stdout.splitlines()[0]
                if expected_result is None:
                    expected_result = result
                assert result == expected_result, (name, engine, result, expected_result)
                values.append(ns / units)
            print(f"{name},{engine},{statistics.median(values):.3f},"
                  f"{min(values):.3f},{max(values):.3f},{result}", flush=True)


if __name__ == "__main__":
    main()
