#!/usr/bin/env python3
"""
analyze.py - Parse and analyze macOS `sample` profiling data for Arinsal JIT and Interpreter.
"""

import sys
import re
import os
import subprocess
from collections import defaultdict

def demangle(symbol):
    """Demangle Rust symbols using /usr/bin/c++filt."""
    if symbol.startswith('_R'):
        try:
            res = subprocess.run(['/usr/bin/c++filt', symbol], capture_output=True, text=True)
            if res.returncode == 0 and res.stdout.strip():
                return res.stdout.strip()
        except Exception:
            pass
    return symbol

def parse_sample_file(filepath):
    """
    Parse macOS `sample` output file.
    Returns per-thread call trees and identifies the active worker execution thread.
    """
    with open(filepath, 'r') as f:
        lines = f.readlines()

    in_callgraph = False
    thread_trees = {}
    current_thread = None
    line_re = re.compile(r'^([+!:| ]*)\s+(\d+)\s+(.+)$')
    thread_re = re.compile(r'^\s*(\d+)\s+(Thread_\S+)')

    current_stack = []

    for line in lines:
        if line.startswith('Call graph:'):
            in_callgraph = True
            continue
        if line.startswith('Total number in stack') or line.startswith('Sort by top of stack'):
            break
        if not in_callgraph:
            continue

        th_match = thread_re.match(line)
        if th_match:
            if current_thread:
                while current_stack:
                    d, sym, bin_name, cnt, c_sum = current_stack.pop()
                    self_cnt = max(0, cnt - c_sum)
                    thread_trees[current_thread]['self'][sym] += self_cnt
                    thread_trees[current_thread]['bin'][sym] = bin_name
            current_thread = th_match.group(2)
            thread_trees[current_thread] = {
                'samples': int(th_match.group(1)),
                'inclusive': defaultdict(int),
                'self': defaultdict(int),
                'bin': {}
            }
            current_stack = []
            continue

        if not current_thread:
            continue

        m = line_re.match(line)
        if not m:
            continue

        prefix = m.group(1)
        count = int(m.group(2))
        rest = m.group(3)

        depth = len(prefix)

        bin_match = re.search(r'\(in\s+([^)]+)\)', rest)
        bin_name = bin_match.group(1).strip() if bin_match else 'unknown'

        sym_match = re.match(r'^(.*?)(?:\s+\(in\s+|\s+\+|\s+\[|$)', rest)
        sym = sym_match.group(1).strip() if sym_match else rest.strip()

        while current_stack and current_stack[-1][0] >= depth:
            d, s, b, c, c_sum = current_stack.pop()
            self_cnt = max(0, c - c_sum)
            thread_trees[current_thread]['self'][s] += self_cnt
            thread_trees[current_thread]['bin'][s] = b

        if current_stack:
            current_stack[-1][4] += count

        thread_trees[current_thread]['inclusive'][sym] += count
        thread_trees[current_thread]['bin'][sym] = bin_name
        current_stack.append([depth, sym, bin_name, count, 0])

    if current_thread:
        while current_stack:
            d, s, b, c, c_sum = current_stack.pop()
            self_cnt = max(0, c - c_sum)
            thread_trees[current_thread]['self'][s] += self_cnt
            thread_trees[current_thread]['bin'][s] = b

    # Identify the active execution worker thread (not sleeping in semaphore_wait_trap)
    active_thread = None
    max_active_samples = -1
    for th, data in thread_trees.items():
        score = sum(data['self'][s] for s in data['self'] if 'semaphore_wait_trap' not in s and 'park' not in s)
        if score > max_active_samples:
            max_active_samples = score
            active_thread = th

    th_data = thread_trees[active_thread]
    total_samples = th_data['samples']

    jit_self = 0
    rust_self = 0
    system_self = 0

    for sym, count in th_data['self'].items():
        bin_name = th_data['bin'].get(sym, '')
        if sym == '???' or '<unknown binary>' in bin_name or '0x' in sym:
            jit_self += count
        elif 'arinsal' in bin_name or sym.startswith('_R'):
            rust_self += count
        else:
            system_self += count

    return {
        'filepath': filepath,
        'active_thread': active_thread,
        'total_samples': total_samples,
        'self_time': th_data['self'],
        'inclusive_time': th_data['inclusive'],
        'bin': th_data['bin'],
        'jit_self': jit_self,
        'rust_self': rust_self,
        'system_self': system_self,
    }

def format_markdown_table_self(data, top_n=25):
    lines = [
        "| Rank | Symbol (Demangled) | Binary / Module | Self Samples | Self % | Inclusive Samples | Inclusive % |",
        "| :--- | :--- | :--- | :---: | :---: | :---: | :---: |"
    ]
    ranked = sorted(data['self_time'].items(), key=lambda x: x[1], reverse=True)[:top_n]
    for i, (sym, count) in enumerate(ranked, 1):
        pct = count / data['total_samples'] * 100
        inc = data['inclusive_time'].get(sym, count)
        inc_pct = inc / data['total_samples'] * 100
        b = data['bin'].get(sym, 'unknown')
        d_sym = demangle(sym)
        lines.append(f"| {i} | `{d_sym}` | `{b}` | {count} | {pct:.2f}% | {inc} | {inc_pct:.2f}% |")
    return "\n".join(lines)

def format_markdown_table_inclusive(data, top_n=25):
    lines = [
        "| Rank | Symbol (Demangled) | Binary / Module | Inclusive Samples | Inclusive % | Self Samples | Self % |",
        "| :--- | :--- | :--- | :---: | :---: | :---: | :---: |"
    ]
    ranked = sorted(data['inclusive_time'].items(), key=lambda x: x[1], reverse=True)[:top_n]
    for i, (sym, count) in enumerate(ranked, 1):
        pct = count / data['total_samples'] * 100
        self_cnt = data['self_time'].get(sym, 0)
        self_pct = self_cnt / data['total_samples'] * 100
        b = data['bin'].get(sym, 'unknown')
        d_sym = demangle(sym)
        lines.append(f"| {i} | `{d_sym}` | `{b}` | {count} | {pct:.2f}% | {self_cnt} | {self_pct:.2f}% |")
    return "\n".join(lines)

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <sample_file>")
        sys.exit(1)

    res = parse_sample_file(sys.argv[1])
    print(f"File: {res['filepath']}")
    print(f"Active Thread: {res['active_thread']} (Samples: {res['total_samples']})")
    print(f"JIT Self: {res['jit_self']} ({res['jit_self']/res['total_samples']*100:.2f}%)")
    print(f"Rust Runtime Self: {res['rust_self']} ({res['rust_self']/res['total_samples']*100:.2f}%)")
    print(f"OS/System Self: {res['system_self']} ({res['system_self']/res['total_samples']*100:.2f}%)")
    print("\n--- Top 25 by Self Time ---")
    print(format_markdown_table_self(res, 25))
    print("\n--- Top 25 by Inclusive Time ---")
    print(format_markdown_table_inclusive(res, 25))
