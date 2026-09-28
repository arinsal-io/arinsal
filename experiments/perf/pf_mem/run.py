#!/usr/bin/env python3
"""Run paired OTP/Arinsal BEAM probes and print per-operation medians."""

import os
from pathlib import Path
import re
import statistics
import subprocess


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
ARINSAL = ROOT / "target/release/arinsal"
CASES = [
    ("cons", 100_000, 1),
    ("tuple", 100_000, 1),
    ("spawn_exit", 10_000, 1),
    ("monitor_down", 10_000, 1),
    ("pingpong", 10_000, 1),
    ("pingpong", 10_000, 4),
    ("gen_call", 1_000, 4),
    ("throw_catch", 10_000, 1),
    ("throw_conditional", 10_000, 1),
    ("try_no_throw", 10_000, 1),
    ("make_ref_loop", 10_000, 1),
    ("timer", 1_000, 1),
    ("gc_dead", 20, 1),
    ("gc_live", 20, 1),
]


def run(kind, function, n, schedulers):
    if kind == "erts":
        eval_code = (
            f'io:format("~p~n", [micro:{function}({n})]), halt().'
        )
        cmd = ["erl", "-noshell", "+S", f"{schedulers}:{schedulers}",
               "-pa", str(HERE), "-eval", eval_code]
    else:
        cmd = ["timeout", "300", str(ARINSAL), "eval", "-pa", str(HERE),
               "--schedulers", str(schedulers), "micro", function, str(n)]
    proc = subprocess.run(cmd, text=True, capture_output=True, timeout=310,
                          env=os.environ.copy())
    if proc.returncode:
        return f"FAIL({proc.returncode}): {(proc.stderr or proc.stdout).strip()[:140]}"
    match = re.search(r"^\{(.+),(\d+)\}$", proc.stdout, re.MULTILINE)
    if not match:
        return f"PARSE: {proc.stdout.strip()[:140]}"
    return match.group(1), int(match.group(2)) / n


def main():
    subprocess.run(["erlc", "-o", str(HERE), str(HERE / "micro.erl")],
                   check=True)
    print("case,n,schedulers,erts_ns_op,arinsal_ns_op,ratio")
    failed = False
    for function, n, schedulers in CASES:
        results = {"erts": [], "arinsal": []}
        terms = {}
        for repeat in range(3):
            for kind in (["erts", "arinsal"] if repeat % 2 else ["arinsal", "erts"]):
                value = run(kind, function, n, schedulers)
                if isinstance(value, str):
                    results[kind] = [value]
                    break
                term, elapsed = value
                terms[kind] = term
                if len(terms) == 2 and terms["erts"] != terms["arinsal"]:
                    results[kind] = [f"MISMATCH: {terms}"]
                    break
                results[kind].append(elapsed)
            if any(values and isinstance(values[0], str) for values in results.values()):
                break
        def display(kind):
            values = results[kind]
            return f"{statistics.median(values):.1f}" if values and isinstance(values[0], float) else (values[0] if values else "-")
        left, right = display("erts"), display("arinsal")
        ratio = (f"{float(left) / float(right):.3f}"
                 if left.replace(".", "", 1).isdigit() and right.replace(".", "", 1).isdigit()
                 else "-")
        failed |= ratio == "-"
        print(f"{function},{n},{schedulers},{left},{right},{ratio}", flush=True)
    if failed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
