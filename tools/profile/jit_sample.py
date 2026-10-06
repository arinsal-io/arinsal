#!/usr/bin/env python3
"""Classify exclusive `sample` stack counts for a threshold-1 eval workload.

The input is macOS `sample PID 3 -file FILE` output. The result excludes the
waiting CLI thread and startup frames outside `run_slice`. Categories are
stack-based estimates; use JIT timers for precise callback boundaries.
"""

from __future__ import annotations

import argparse
import re
from collections import Counter
from pathlib import Path


def category(symbol: str, ancestry: list[str]) -> str:
    path = " ".join(ancestry)
    helper = "8jit_hook8jit_step" in path
    native = "8jit_hook3run" in path
    runtime = any(x in symbol for x in (
        "arinsal_bifs", "arinsal_maps", "arinsal_term4heap", "libsystem_malloc",
        "_malloc", "_free", "arinsal_gc", "jit_hook10jit_ensure",
    ))
    call = any(x in symbol for x in (
        "signals4call", "11call_import", "funs", "5calls", "__findenv_locked",
        "JitHook8on_entry", "bif_lookup", "sync_module",
    ))
    if runtime:
        return "runtime"
    if call:
        return "call/tier"
    if helper:
        helper_index = next(i for i, frame in enumerate(ancestry) if "8jit_hook8jit_step" in frame)
        if any("run_slice_inner" in frame for frame in ancestry[:helper_index]):
            return "interpreter in helper"
        return "helper sync"
    if native:
        return "inline native"
    return "interpreter"


def read(path: Path) -> Counter[str]:
    graph = path.read_text().split("Call graph:\n", 1)[1].split("Total number in stack", 1)[0]
    nodes: list[list] = []
    stack: list[tuple[int, int]] = []
    for line in graph.splitlines():
        match = re.match(r"^(.*?)(\d+)\s+(.+)$", line)
        if not match:
            continue
        prefix, number, symbol = match.groups()
        depth = len(prefix)
        while stack and stack[-1][0] >= depth:
            stack.pop()
        parent = stack[-1][1] if stack else None
        count = int(number)
        index = len(nodes)
        nodes.append([count, count, symbol, parent])
        if parent is not None:
            nodes[parent][1] -= count
        stack.append((depth, index))
    out: Counter[str] = Counter()
    for index, (_, exclusive, symbol, parent) in enumerate(nodes):
        if exclusive <= 0:
            continue
        ancestry = [symbol]
        while parent is not None:
            ancestry.append(nodes[parent][2])
            parent = nodes[parent][3]
        if not any("run_slice" in frame for frame in ancestry):
            continue
        out[category(symbol, ancestry)] += exclusive
    return out


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("sample", type=Path, nargs="+")
    args = parser.parse_args()
    for path in args.sample:
        counts = read(path)
        total = sum(counts.values())
        print(path, "active_samples", total)
        for name, count in counts.most_common():
            print(f"  {name}: {count} ({100 * count / total:.1f}%)")


if __name__ == "__main__":
    main()
