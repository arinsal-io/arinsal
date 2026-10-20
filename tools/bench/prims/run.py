#!/usr/bin/env python3
"""Run the canonical OTP process-primitives benchmark against OTP and Arinsal."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import platform
import re
import statistics
import subprocess
import sys
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[3]
BENCH_DIR = Path(__file__).resolve().parent
OPS = [
    "monitor_demonitor",
    "link_unlink",
    "spawn_link_exit",
    "spawn_monitor_down",
    "ping_atom",
    "ping_tuple",
    "ping_list_100",
    "ping_binary_1k",
    "ping_binary_64k",
    "ping_map_20",
    "selective_last_10",
    "selective_last_100",
    "make_ref_receive",
    "send_after_cancel",
    "gen_server_call",
    "ets_lookup_insert_1000",
]
KS = [1, 8, 16]
RUNS = 7


def checked_run(command: list[str], timeout: int, **kwargs) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        check=True,
        text=True,
        capture_output=True,
        timeout=timeout,
        **kwargs,
    )


def otp_paths(erl: str, timeout: int) -> tuple[str, str, str, str]:
    expression = (
        'io:format("~s|~s|~s|~s", '
        '[code:root_dir(), code:lib_dir(stdlib, ebin), '
        'code:lib_dir(kernel, ebin), erlang:system_info(version)]), halt().'
    )
    output = checked_run(
        [erl, "-noshell", "-noinput", "-eval", expression], timeout
    ).stdout.strip()
    parts = output.split("|")
    if len(parts) != 4:
        raise RuntimeError(f"could not identify OTP installation: {output!r}")
    root, stdlib, kernel, erts_version = parts
    version_file = Path(root) / "releases" / "29" / "OTP_VERSION"
    otp_version = version_file.read_text(encoding="utf-8").strip()
    if otp_version != "29.1.1" or erts_version != "17.1":
        raise RuntimeError(
            f"expected OTP 29.1.1 / ERTS 17.1, got OTP {otp_version} / ERTS {erts_version}"
        )
    return root, stdlib, kernel, otp_version


def compile_beam(erlc: str, ebin: Path, timeout: int) -> None:
    ebin.mkdir(parents=True, exist_ok=True)
    checked_run(
        [erlc, "-Werror", "-o", str(ebin), str(BENCH_DIR / "prims_bench.erl")],
        timeout,
    )


def sample_command(
    runtime: str,
    binary: str,
    erl: str,
    ebin: Path,
    stdlib: str,
    kernel: str,
    k: int,
    run: int,
    timeout: int,
) -> dict[str, dict[str, int]]:
    schedulers = 2 * k
    if runtime == "erts":
        expression = f"prims_bench:run(erts,{k},{run}), halt()."
        command = [
            erl,
            "+S",
            f"{schedulers}:{schedulers}",
            "-noshell",
            "-noinput",
            "-pa",
            str(ebin),
            "-eval",
            expression,
        ]
    else:
        command = [
            binary,
            "eval",
            "--schedulers",
            str(schedulers),
            "-pa",
            str(ebin),
            "-pa",
            stdlib,
            "-pa",
            kernel,
            "prims_bench",
            "run",
            "arinsal",
            str(k),
            str(run),
        ]
    result = checked_run(command, timeout)
    parsed: dict[str, dict[str, int]] = {}
    if runtime == "erts":
        for line in result.stdout.splitlines():
            fields = line.split("|")
            if len(fields) == 8 and fields[0] == "PRIMS":
                _, found_runtime, found_k, found_run, op, n, empty_ns, work_ns = fields
                if found_runtime != runtime or int(found_k) != k or int(found_run) != run:
                    raise RuntimeError(f"sample identity mismatch: {line}")
                parsed[op] = {
                    "iterations": int(n),
                    "empty_loop_ns": int(empty_ns),
                    "operation_ns": int(work_ns),
                }
    else:
        for match in re.finditer(
            r"\{\s*([a-z][a-zA-Z0-9_]*)\s*,\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*\}",
            result.stdout,
        ):
            op, n, empty_ns, work_ns = match.groups()
            parsed[op] = {
                "iterations": int(n),
                "empty_loop_ns": int(empty_ns),
                "operation_ns": int(work_ns),
            }
    missing = set(OPS) - set(parsed)
    extra = set(parsed) - set(OPS)
    if missing or extra:
        raise RuntimeError(
            f"{runtime} K={k} run={run} output mismatch; missing={sorted(missing)}, "
            f"extra={sorted(extra)}; stdout={result.stdout!r}; stderr={result.stderr!r}"
        )
    return parsed


def ns_per_op(sample: dict[str, int], k: int) -> float:
    return (sample["operation_ns"] - sample["empty_loop_ns"]) / (
        k * sample["iterations"]
    )


def build_report(raw: dict, args: argparse.Namespace, otp_version: str) -> dict:
    results = []
    for op in OPS:
        for k in KS:
            runtime_stats = {}
            for runtime in ("erts", "arinsal"):
                samples = raw[op][str(k)][runtime]
                values = [ns_per_op(sample, k) for sample in samples]
                runtime_stats[runtime] = {
                    "samples_ns_per_op": values,
                    "median_ns_per_op": statistics.median(values),
                    "min_ns_per_op": min(values),
                    "max_ns_per_op": max(values),
                    "samples": samples,
                }
            results.append(
                {
                    "operation": op,
                    "iterations_per_pair": raw[op][str(k)]["erts"][0]["iterations"],
                    "pairs": k,
                    "schedulers": 2 * k,
                    "runtimes": runtime_stats,
                }
            )
    return {
        "metadata": {
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "otp": otp_version,
            "erts": "17.1",
            "arinsal_binary": Path(args.arinsal).name,
            "platform": platform.platform(),
            "runs": RUNS,
            "concurrent_pairs": KS,
            "schedulers_per_runtime": "2*K",
            "normalization": "(operation_ns - empty_loop_ns) / (K * N)",
            "warmup": "one empty-loop and one operation pass at min(N, 1000) per worker",
            "runtime_order": "alternates by run and K; operation/baseline order alternates by run and operation",
        },
        "results": results,
    }


def format_cell(stats: dict) -> str:
    return f"{stats['median_ns_per_op']:.2f} [{stats['min_ns_per_op']:.2f}–{stats['max_ns_per_op']:.2f}]"


def markdown(report: dict) -> str:
    lines = [
        "| Operation | K pairs | Schedulers | N / pair | OTP 29.1.1 ns/op median [min–max] | Arinsal ns/op median [min–max] |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for result in report["results"]:
        lines.append(
            "| {operation} | {pairs} | {schedulers} | {iterations_per_pair} | {erts} | {arinsal} |".format(
                **result,
                erts=format_cell(result["runtimes"]["erts"]),
                arinsal=format_cell(result["runtimes"]["arinsal"]),
            )
        )
    return "\n".join(lines)


def scaling_summary(report: dict) -> str:
    by_op: dict[str, dict[int, float]] = {op: {} for op in OPS}
    for result in report["results"]:
        by_op[result["operation"]][result["pairs"]] = result["runtimes"]["erts"][
            "median_ns_per_op"
        ]
    grew = any(by_op[op][k] > by_op[op][1] for op in OPS for k in KS[1:])
    verdict = "REVIEW" if grew else "PASS"
    lines = [
        f"ERTS K scaling sanity: {verdict} — per-op cost did not grow at K=8 or K=16" if not grew else
        f"ERTS K scaling sanity: {verdict} — one or more per-op costs grew from K=1",
        "ERTS K scaling (median per-op cost relative to K=1):",
    ]
    for op in OPS:
        baseline = by_op[op][1]
        ratios = [by_op[op][k] / baseline for k in KS]
        lines.append(
            f"- {op}: K=1 {ratios[0]:.2f}x, K=8 {ratios[1]:.2f}x, K=16 {ratios[2]:.2f}x"
        )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--arinsal", required=True, help="path to the Arinsal executable")
    parser.add_argument("--erl", default=os.environ.get("ERL", "erl"))
    parser.add_argument("--erlc", default=os.environ.get("ERLC", "erlc"))
    parser.add_argument("--output-dir", type=Path, default=ROOT / "tmp" / "bench_prims")
    parser.add_argument("--timeout", type=int, default=300, help="per-runtime sample timeout in seconds")
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    binary = str(Path(args.arinsal).expanduser().resolve())
    if not Path(binary).is_file():
        parser.error(f"Arinsal executable does not exist: {binary}")
    args.arinsal = binary
    _root, stdlib, kernel, otp_version = otp_paths(args.erl, args.timeout)
    ebin = args.output_dir.resolve() / "ebin"
    compile_beam(args.erlc, ebin, args.timeout)
    raw = {
        op: {
            str(k): {"erts": [], "arinsal": []}
            for k in KS
        }
        for op in OPS
    }
    for run in range(RUNS):
        for k_index, k in enumerate(KS):
            order = ("erts", "arinsal") if (run + k_index) % 2 == 0 else ("arinsal", "erts")
            for runtime in order:
                print(f"Running {runtime} K={k} run={run + 1}/{RUNS}...", file=sys.stderr, flush=True)
                samples = sample_command(
                    runtime,
                    binary,
                    args.erl,
                    ebin,
                    stdlib,
                    kernel,
                    k,
                    run,
                    args.timeout,
                )
                for op, sample in samples.items():
                    raw[op][str(k)][runtime].append(sample)
    report = build_report(raw, args, otp_version)
    table = markdown(report)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    json_path = args.output_dir / "prims.json"
    markdown_path = args.output_dir / "prims.md"
    json_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    markdown_path.write_text(table + "\n", encoding="utf-8")
    print(table)
    print()
    print(scaling_summary(report))
    try:
        json_display = json_path.relative_to(ROOT)
        markdown_display = markdown_path.relative_to(ROOT)
    except ValueError:
        json_display = json_path
        markdown_display = markdown_path
    print(f"\nJSON: {json_display}")
    print(f"Markdown: {markdown_display}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except subprocess.TimeoutExpired as exc:
        print(f"ERROR: command timed out after {exc.timeout}s: {exc.cmd}", file=sys.stderr)
        raise SystemExit(124)
    except subprocess.CalledProcessError as exc:
        print(f"ERROR: command failed ({exc.returncode}): {exc.cmd}", file=sys.stderr)
        if exc.stdout:
            print(exc.stdout, file=sys.stderr)
        if exc.stderr:
            print(exc.stderr, file=sys.stderr)
        raise SystemExit(exc.returncode or 1)
