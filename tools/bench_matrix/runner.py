#!/usr/bin/env python3
"""Runner for erts vs Arinsal vs Go workload matrix."""

import argparse
import json
import os
from pathlib import Path
import platform
import re
import statistics
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
BENCH_DIR = ROOT / "tools" / "bench_matrix"
TMP_DIR = ROOT / "tmp"
BUILD_DIR = TMP_DIR / "bench_matrix"
EBIN_DIR = BUILD_DIR / "ebin"
GOB_BIN = BUILD_DIR / "gob"
ARINSAL_BIN = ROOT / "target" / "release" / "arinsal"

# 10 Kernels definitions matching the required names, exact semantics, and operation counts
KERNELS = [
    {
        "id": "int_loop_sum",
        "display_name": "int loop sum",
        "semantics_note": "tail recursion vs for-loop, 1..10M, int64",
        "expected_checksum": 50000005000000,
        "op_count": 10000000,
    },
    {
        "id": "fib_27",
        "display_name": "fib(27)",
        "semantics_note": "naive recursive calls, 635k calls",
        "expected_checksum": 196418,
        "op_count": 635621,
    },
    {
        "id": "list_100k",
        "display_name": "list build+map+fold 100k",
        "semantics_note": "build+map(+1)+fold; Go: boxed linked list",
        "expected_checksum": 5000150000,
        "op_count": 100000,
    },
    {
        "id": "tuple_loop",
        "display_name": "tuple setelement loop",
        "semantics_note": "setelement(2, Tuple, I) 100k; Go: 3-elem struct copy",
        "expected_checksum": 5000050000,
        "op_count": 100000,
    },
    {
        "id": "binary_scan",
        "display_name": "binary byte scan 1 MiB",
        "semantics_note": "1 MiB binary byte-by-byte scan",
        "expected_checksum": 262144,
        "op_count": 1048576,
    },
    {
        "id": "map_put_get",
        "display_name": "map put/get 100k",
        "semantics_note": "insert & lookup 100k small ints; Go map[int]int",
        "expected_checksum": 5000050000,
        "op_count": 100000,
    },
    {
        "id": "ets_insert_lookup",
        "display_name": "ets hash table",
        "semantics_note": "insert & lookup 100k items; Go map + sync.Mutex",
        "expected_checksum": 5000050000,
        "op_count": 100000,
    },
    {
        "id": "spawn_exit",
        "display_name": "spawn+exit 100k",
        "semantics_note": "spawn 100k, backlog 100k msgs before recv (measures on-heap msgq GC)",
        "expected_checksum": 100000,
        "op_count": 100000,
        "concurrent": True,
    },
    {
        "id": "spawn_exit_recv",
        "display_name": "spawn+exit+recv 100k",
        "semantics_note": "spawn 100k, recv each immediately (no backlog, pure spawn+msg roundtrip)",
        "expected_checksum": 100000,
        "op_count": 100000,
        "concurrent": True,
    },
    {
        "id": "ping_pong",
        "display_name": "ping-pong 1M",
        "semantics_note": "1M ping-pong round-trips; Go unbuffered chan",
        "expected_checksum": 1000000,
        "op_count": 1000000,
        "concurrent": True,
    },
    {
        "id": "fan_in",
        "display_name": "fan-in 8 producers",
        "semantics_note": "8 producers x 125k msgs -> 1 consumer",
        "expected_checksum": 1000000,
        "op_count": 1000000,
        "concurrent": True,
    },
    {
        "id": "float_math",
        "display_name": "float math",
        "semantics_note": "1M iterations x = x*1.0000001 + 0.5 (boxed float vs Go float64)",
        "expected_checksum": 525854,
        "op_count": 1000000,
        "concurrent": False,
    },
    {
        "id": "closure_calls",
        "display_name": "closure calls",
        "semantics_note": "1M calls of captured fun F(X)->X+K via lists:foldl vs Go closure",
        "expected_checksum": 500010500000,
        "op_count": 1000000,
        "concurrent": False,
    },
    {
        "id": "binary_build",
        "display_name": "binary build",
        "semantics_note": "build 1 MiB via <<Acc/binary, B>> (private_append) vs Go append []byte",
        "expected_checksum": 1048576,
        "op_count": 1048576,
        "concurrent": False,
    },
    {
        "id": "record_update",
        "display_name": "record/tuple update",
        "semantics_note": "1M updates of 5-field record (setelement) vs Go struct copy",
        "expected_checksum": 500000500000,
        "op_count": 1000000,
        "concurrent": False,
    },
    {
        "id": "string_atom_string",
        "display_name": "string→atom→string",
        "semantics_note": "100k list_to_atom/atom_to_list of existing atoms vs Go map[string]int interning",
        "expected_checksum": 789000,
        "op_count": 100000,
        "concurrent": False,
    },
    {
        "id": "sort_100k",
        "display_name": "sort 100k ints",
        "semantics_note": "lists:sort 100k pseudo-random ints (fixed seed) vs Go sort.Ints on copy",
        "expected_checksum": 3227487306,
        "op_count": 100000,
        "concurrent": False,
    },
    {
        "id": "gen_server_call",
        "display_name": "gen_server call",
        "semantics_note": "100k gen_server:call round-trips to local server vs Go 2 unbuffered chans",
        "expected_checksum": 100000,
        "op_count": 100000,
        "concurrent": True,
    },
]


def format_ns(ns: float) -> str:
    """Format nanoseconds per operation with appropriate precision."""
    if ns < 10.0:
        return f"{ns:.2f}"
    if ns < 1000.0:
        return f"{ns:.1f}"
    if ns < 100000.0:
        return f"{ns:,.0f}"
    return f"{ns:.2e}"


def format_stat(record) -> str:
    if not record or record.get("status") != "ok":
        return record.get("status", "FAIL") if record else "FAIL"
    med = record["median_ns_per_op"]
    low = record["min_ns_per_op"]
    high = record["max_ns_per_op"]
    return f"{format_ns(med)} ({format_ns(low)}..{format_ns(high)})"


def parse_output(output: str, expected_checksum: int, op_count: int):
    match = re.search(r"\{ok,\s*(-?\d+),\s*\[([^\]]*)\]\}", output)
    if not match:
        if "MISMATCH" in output:
            return {"status": "MISMATCH", "raw": output[:300]}
        if "exception error" in output or "panic:" in output:
            return {"status": "CRASH", "raw": output[:300]}
        return {"status": "FAIL", "raw": output[:300]}

    checksum = int(match.group(1))
    times_str = match.group(2).strip()
    if not times_str:
        return {"status": "FAIL", "reason": "empty times"}

    times_ns = [int(x.strip()) for x in times_str.split(",") if x.strip()]
    if checksum != expected_checksum:
        print(f"MISMATCH: got {checksum}, expected {expected_checksum}", file=sys.stderr)
        return {"status": "MISMATCH", "checksum": checksum, "expected": expected_checksum}

    ns_per_op = [t / op_count for t in times_ns]
    return {
        "status": "ok",
        "checksum": checksum,
        "times_ns": times_ns,
        "ns_per_op": ns_per_op,
        "median_ns_per_op": statistics.median(ns_per_op),
        "min_ns_per_op": min(ns_per_op),
        "max_ns_per_op": max(ns_per_op),
    }


def run_cmd(cmd, env=None, timeout_sec=300):
    try:
        res = subprocess.run(
            cmd,
            cwd=str(ROOT),
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout_sec,
        )
        if res.returncode == 124:
            return "TIMEOUT", ""
        return res.stdout, res.stderr
    except subprocess.TimeoutExpired:
        return "TIMEOUT", ""
    except Exception as e:
        return f"CRASH: {e}", ""


def run_erts(kernel_id: str, expected: int, op_count: int, warmup: int, repeats: int, sched: str = "default"):
    cmd = ["erl", "-noshell"]
    if sched == "1":
        cmd.extend(["+S", "1:1"])
    cmd.extend([
        "+P",
        "2000000",
        "-pa",
        str(EBIN_DIR),
        "-run",
        "kernels",
        "main",
        kernel_id,
        str(warmup),
        str(repeats),
    ])
    stdout, stderr = run_cmd(cmd, timeout_sec=300)
    if stdout == "TIMEOUT":
        return {"status": "TIMEOUT"}
    combined = stdout + "\n" + stderr
    return parse_output(combined, expected, op_count)


def run_arinsal(kernel_id: str, expected: int, op_count: int, warmup: int, repeats: int, beamasm: bool, sched: str = "default"):
    cmd = [str(ARINSAL_BIN), "eval"]
    if sched == "1":
        cmd.extend(["+S", "1"])
    cmd.extend([
        "-pa",
        str(EBIN_DIR),
        "kernels",
        "run_bench",
        kernel_id,
        str(warmup),
        str(repeats),
    ])
    env = os.environ.copy()
    if beamasm:
        env["ARINSAL_BEAMASM"] = "1"
    else:
        env.pop("ARINSAL_BEAMASM", None)

    stdout, stderr = run_cmd(cmd, env=env, timeout_sec=300)
    if stdout == "TIMEOUT":
        return {"status": "TIMEOUT"}
    combined = stdout + "\n" + stderr
    return parse_output(combined, expected, op_count)


def run_go(kernel_id: str, expected: int, op_count: int, warmup: int, repeats: int, sched: str = "default"):
    cmd = [str(GOB_BIN), kernel_id, str(warmup), str(repeats)]
    env = os.environ.copy()
    if sched == "1":
        env["GOMAXPROCS"] = "1"
    else:
        env["GOMAXPROCS"] = str(os.cpu_count() or 10)

    stdout, stderr = run_cmd(cmd, env=env, timeout_sec=300)
    if stdout == "TIMEOUT":
        return {"status": "TIMEOUT"}
    combined = stdout + "\n" + stderr
    return parse_output(combined, expected, op_count)


def main():
    parser = argparse.ArgumentParser(description="Runner for erts vs Arinsal vs Go workload matrix.")
    parser.add_argument("--quick", action="store_true", help="Run fewer repeats (3 instead of 5)")
    parser.add_argument(
        "--sched",
        choices=["1", "default", "both"],
        default="both",
        help="Scheduler configuration: 1, default, or both (default: both)",
    )
    parser.add_argument(
        "--kernels",
        type=str,
        default=None,
        help="Comma-separated kernel IDs or name substrings to filter (e.g. spawn,ping,fan)",
    )
    args = parser.parse_args()

    quick = args.quick
    warmup = 1
    repeats = 3 if quick else 5

    TMP_DIR.mkdir(parents=True, exist_ok=True)

    # Filter kernels
    if args.kernels:
        filters = [f.strip().lower() for f in args.kernels.split(",") if f.strip()]
        selected_kernels = []
        for k in KERNELS:
            kid = k["id"].lower()
            name = k["display_name"].lower()
            if any(f == kid or f in kid or f in name for f in filters):
                selected_kernels.append(k)
        if not selected_kernels:
            print(f"Error: no kernels matched filter '{args.kernels}'", file=sys.stderr)
            sys.exit(1)
    else:
        selected_kernels = KERNELS

    results_list = []
    results_by_kernel = {}
    has_mismatch = False

    for k in selected_kernels:
        kid = k["id"]
        name = k["display_name"]
        expected = k["expected_checksum"]
        op_count = k["op_count"]
        semantics_note = k["semantics_note"]
        is_concurrent = k.get("concurrent", False)

        if args.sched == "1":
            kernel_scheds = ["1"]
        elif args.sched == "default":
            kernel_scheds = ["default"]
        else:
            kernel_scheds = ["1", "default"] if is_concurrent else ["default"]

        for s in kernel_scheds:
            erts_res = run_erts(kid, expected, op_count, warmup, repeats, sched=s)
            arinsal_def_res = run_arinsal(kid, expected, op_count, warmup, repeats, beamasm=False, sched=s)
            arinsal_asm_res = run_arinsal(kid, expected, op_count, warmup, repeats, beamasm=True, sched=s)
            go_res = run_go(kid, expected, op_count, warmup, repeats, sched=s)

            for r in (erts_res, arinsal_def_res, arinsal_asm_res, go_res):
                if r.get("status") == "MISMATCH":
                    has_mismatch = True

            arinsal_ratio_str = "n/a"
            if arinsal_def_res.get("status") == "ok" and erts_res.get("status") == "ok":
                ratio = arinsal_def_res["median_ns_per_op"] / erts_res["median_ns_per_op"]
                arinsal_ratio_str = f"{ratio:.2f}x"

            go_ratio_str = "n/a"
            if go_res.get("status") == "ok" and erts_res.get("status") == "ok":
                ratio = go_res["median_ns_per_op"] / erts_res["median_ns_per_op"]
                go_ratio_str = f"{ratio:.2f}x"

            run_entry = {
                "kernel": name,
                "kernel_id": kid,
                "sched": s,
                "semantics_note": semantics_note,
                "op_count": op_count,
                "expected_checksum": expected,
                "runtimes": {
                    "erts": erts_res,
                    "arinsal_default": arinsal_def_res,
                    "arinsal_beamasm": arinsal_asm_res,
                    "go": go_res,
                },
                "ratios": {
                    "arinsal_to_erts": arinsal_ratio_str,
                    "go_to_erts": go_ratio_str,
                },
            }
            results_list.append(run_entry)

            if name not in results_by_kernel:
                results_by_kernel[name] = {
                    "semantics_note": semantics_note,
                    "op_count": op_count,
                    "expected_checksum": expected,
                    "sched": {},
                }
            results_by_kernel[name]["sched"][s] = {
                "runtimes": run_entry["runtimes"],
                "ratios": run_entry["ratios"],
            }

    # Write JSON output to tmp/bench_matrix.json
    json_path = TMP_DIR / "bench_matrix.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(
            {
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "machine": platform.machine(),
                "system": platform.system(),
                "quick": quick,
                "sched": args.sched,
                "warmup": warmup,
                "repeats": repeats,
                "runs": results_list,
                "kernels": results_by_kernel,
            },
            f,
            indent=2,
        )

    # Print Markdown Table
    headers = [
        "kernel",
        "sched",
        "semantics note",
        "erts ns/op",
        "Arinsal default ns/op",
        "Arinsal ARINSAL_BEAMASM=1 ns/op",
        "Go ns/op",
        "Arinsal/erts",
        "Go/erts",
    ]
    print("| " + " | ".join(headers) + " |")
    print("| " + " | ".join(["---"] * len(headers)) + " |")

    for entry in results_list:
        r = entry["runtimes"]
        row = [
            entry["kernel"],
            entry["sched"],
            entry["semantics_note"],
            format_stat(r["erts"]),
            format_stat(r["arinsal_default"]),
            format_stat(r["arinsal_beamasm"]),
            format_stat(r["go"]),
            entry["ratios"]["arinsal_to_erts"],
            entry["ratios"]["go_to_erts"],
        ]
        print("| " + " | ".join(row) + " |")

    if has_mismatch:
        print("\nMISMATCH DETECTED")
        sys.exit(1)


if __name__ == "__main__":
    main()
