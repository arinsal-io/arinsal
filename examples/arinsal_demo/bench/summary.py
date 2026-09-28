#!/usr/bin/env python3
"""Print a Markdown comparison of erts, Arinsal cold, and Arinsal warm ips."""

import argparse
import datetime as dt
import json
import math
import subprocess
import sys
from pathlib import Path

# Keep in sync with ArinsalDemo.BenchJobs.suites/0.
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
TAGS = ("erts", "arinsal_cold", "arinsal_warm")
DEMO = Path(__file__).resolve().parents[1]
ROOT = DEMO.parent.parent
OUT = DEMO / "bench" / "out"

FOOTER = (
    "Memory and reduction counts are not compared. "
    "D1 (exact reduction counts) and D2 (memory sizes) in `docs/differences.md` "
    "are intentional differences between Arinsal and erts."
)


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite", default="all", help="suite name or all")
    parser.add_argument("--baseline", help="previous compare markdown file or a directory of JSON")
    parser.add_argument("--quick", action="store_true")
    return parser.parse_args()


def selected_suites(name):
    if name in (None, "", "all"):
        return SUITES
    if name not in SUITES:
        raise SystemExit(f"unknown suite: {name}")
    return [name]


def load_json(path):
    scenarios = json.loads(path.read_text())
    if isinstance(scenarios, dict):
        scenarios = scenarios.get("scenarios", scenarios.get("jobs", []))
    rows = []
    for scenario in scenarios:
        stats = scenario["run_time_data"]["statistics"]
        rows.append(
            {
                "name": scenario.get("job_name") or scenario["name"],
                "ips": stats.get("ips"),
                "dev": stats.get("std_dev_ratio"),
            }
        )
    return rows


def index_rows(rows):
    return {row["name"]: row for row in rows}


def git_sha():
    return subprocess.check_output(
        ["git", "rev-parse", "--short=12", "HEAD"], cwd=ROOT, text=True
    ).strip()


def parse_num(text):
    text = text.strip().replace(",", "")
    if text in {"", "—", "-", "n/a"}:
        return None
    mult = 1.0
    if text.endswith("M"):
        mult = 1_000_000.0
        text = text[:-1].strip()
    elif text.endswith("K"):
        mult = 1_000.0
        text = text[:-1].strip()
    elif text.endswith("×"):
        text = text[:-1].strip()
    elif text.endswith("%"):
        mult = 0.01
        text = text[:-1].strip()
    return float(text) * mult


def fmt_ips(value):
    if value is None:
        return "n/a"
    if value >= 1_000_000:
        return f"{value / 1_000_000:.2f} M"
    if value >= 1_000:
        return f"{value / 1_000:.2f} K"
    return f"{value:.2f}"


def fmt_x(value):
    if value is None:
        return "n/a"
    return f"{value:.2f}×"


def fmt_dev(value):
    if value is None:
        return "n/a"
    return f"{value * 100:.2f}%"


def ratio(num, den):
    if num is None or den is None or den == 0:
        return None
    return num / den


def geomean(values):
    usable = [value for value in values if value is not None and value > 0]
    if not usable:
        return None
    return math.exp(sum(math.log(value) for value in usable) / len(usable))


def load_baseline(path):
    if path is None:
        return None
    baseline = Path(path)
    if not baseline.exists():
        raise SystemExit(f"baseline not found: {baseline}")
    if baseline.is_dir():
        found = {}
        for file in sorted(baseline.glob("*-arinsal_warm.json")):
            suite = file.name[: -len("-arinsal_warm.json")]
            for row in load_json(file):
                found[(suite, row["name"])] = row["ips"]
        if not found:
            raise SystemExit(f"no *-arinsal_warm.json files in {baseline}")
        return found
    found = {}
    for line in baseline.read_text().splitlines():
        if not line.startswith("|"):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) < 5:
            continue
        suite, scenario = cells[0], cells[1]
        if suite in {"suite", "---"} or scenario in {"scenario", "geomean"}:
            continue
        if scenario.startswith("-") or suite.startswith("-"):
            continue
        ips = parse_num(cells[4])
        if ips is not None:
            found[(suite, scenario)] = ips
    if not found:
        raise SystemExit(f"no scenario rows in {baseline}")
    return found


def scenario_rows(suites):
    grouped = []
    for suite in suites:
        paths = {tag: OUT / f"{suite}-{tag}.json" for tag in TAGS}
        missing = [str(path) for path in paths.values() if not path.exists()]
        if missing:
            raise SystemExit("missing benchmark JSON:\n" + "\n".join(missing))
        by_tag = {tag: index_rows(load_json(path)) for tag, path in paths.items()}
        names = [row["name"] for row in load_json(paths["erts"])]
        for name in names:
            if any(name not in by_tag[tag] for tag in TAGS):
                raise SystemExit(f"{suite}/{name} is missing from one runtime")
            grouped.append(
                (
                    suite,
                    name,
                    by_tag["erts"][name],
                    by_tag["arinsal_cold"][name],
                    by_tag["arinsal_warm"][name],
                )
            )
    return grouped


def configuration_header():
    lines = ["## Effective configuration", ""]
    for tag in TAGS:
        path = OUT / f"config-{tag}.txt"
        if not path.exists():
            raise SystemExit(f"missing configuration: {path}")
        config = dict(line.split("=", 1) for line in path.read_text().splitlines())
        required = ("mix_env", "otp", "elixir", "schedulers", "schedulers_online",
                    "dirty_cpu_schedulers", "dirty_cpu_schedulers_online",
                    "dirty_io_schedulers", "jit", "erl_aflags", "erl_flags",
                    "erl_zflags", "benchee_time", "benchee_warmup",
                    "benchee_memory_time", "benchee_reduction_time")
        missing = [key for key in required if key not in config]
        if missing:
            raise SystemExit(f"missing {missing} in {path}")
        lines.append(
            f"- **{tag}**: OTP {config['otp']}, Elixir {config['elixir']}, "
            f"MIX_ENV={config['mix_env']}, schedulers={config['schedulers']}:"
            f"{config['schedulers_online']}, dirty CPU="
            f"{config['dirty_cpu_schedulers']}:"
            f"{config['dirty_cpu_schedulers_online']}, "
            f"dirty IO={config['dirty_io_schedulers']}, JIT={config['jit']}; "
            f"ERL_AFLAGS={config['erl_aflags']!r}, ERL_FLAGS={config['erl_flags']!r}, "
            f"ERL_ZFLAGS={config['erl_zflags']!r}; "
            f"Benchee time={config['benchee_time']}s, warmup="
            f"{config['benchee_warmup']}s, memory="
            f"{config['benchee_memory_time']}s, reductions="
            f"{config['benchee_reduction_time']}s"
        )
    return lines + [""]


def build_table(suites, baseline, quick):
    headers = [
        "suite",
        "scenario",
        "erts ips",
        "arinsal cold ips",
        "arinsal warm ips",
        "cold/erts",
        "warm/erts",
        "erts dev%",
        "warm dev%",
    ]
    if baseline is not None:
        headers.append("vs baseline")

    body = []
    overall_cold = []
    overall_warm = []
    overall_base = []

    rows = scenario_rows(suites)
    for suite in suites:
        suite_rows = [row for row in rows if row[0] == suite]
        cold_ratios = []
        warm_ratios = []
        base_ratios = []
        for suite_name, name, erts, cold, warm in suite_rows:
            cold_ratio = ratio(cold["ips"], erts["ips"])
            warm_ratio = ratio(warm["ips"], erts["ips"])
            cold_ratios.append(cold_ratio)
            warm_ratios.append(warm_ratio)
            overall_cold.append(cold_ratio)
            overall_warm.append(warm_ratio)
            cells = [
                suite_name,
                name,
                fmt_ips(erts["ips"]),
                fmt_ips(cold["ips"]),
                fmt_ips(warm["ips"]),
                fmt_x(cold_ratio),
                fmt_x(warm_ratio),
                fmt_dev(erts["dev"]),
                fmt_dev(warm["dev"]),
            ]
            if baseline is not None:
                base_ratio = ratio(warm["ips"], baseline.get((suite_name, name)))
                base_ratios.append(base_ratio)
                overall_base.append(base_ratio)
                cells.append(fmt_x(base_ratio))
            body.append(cells)
        mean = [
            suite,
            "geomean",
            "—",
            "—",
            "—",
            fmt_x(geomean(cold_ratios)),
            fmt_x(geomean(warm_ratios)),
            "—",
            "—",
        ]
        if baseline is not None:
            mean.append(fmt_x(geomean(base_ratios)))
        body.append(mean)

    overall = [
        "all",
        "geomean",
        "—",
        "—",
        "—",
        fmt_x(geomean(overall_cold)),
        fmt_x(geomean(overall_warm)),
        "—",
        "—",
    ]
    if baseline is not None:
        overall.append(fmt_x(geomean(overall_base)))
    body.append(overall)

    widths = [len(header) for header in headers]
    for cells in body:
        for index, cell in enumerate(cells):
            widths[index] = max(widths[index], len(cell))

    def emit(cells):
        padded = [cell.ljust(widths[index]) for index, cell in enumerate(cells)]
        return "| " + " | ".join(padded) + " |"

    lines = [
        "# erts vs Arinsal",
        "",
        f"Date: {dt.date.today().isoformat()}  ",
        f"Git: `{git_sha()}`  ",
        f"Quick: {'yes' if quick else 'no'}",
        "",
        *configuration_header(),
        emit(headers),
        "| " + " | ".join("-" * width for width in widths) + " |",
    ]
    lines.extend(emit(cells) for cells in body)
    lines.extend(["", FOOTER, ""])
    return "\n".join(lines)


def main():
    args = parse_args()
    suites = selected_suites(args.suite)
    baseline = load_baseline(args.baseline)
    text = build_table(suites, baseline, args.quick)
    OUT.mkdir(parents=True, exist_ok=True)
    dest = OUT / f"compare-{dt.date.today().isoformat()}-{git_sha()}.md"
    dest.write_text(text)
    sys.stdout.write(text)
    print(f"wrote {dest.relative_to(DEMO)}")


if __name__ == "__main__":
    main()
