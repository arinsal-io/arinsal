#!/usr/bin/env python3
"""Summarize the smolquery ingest profiling runs (erts vs Arinsal).

Python 3 standard library only. Run it isolated:

    python3 -I experiments/perf/smolquery_ingest/analyze.py \
        [--results /Users/sts/dev/sq/ingest-profile/results] \
        [--logs /Users/sts/dev/sq/ingest-profile/logs] \
        [--out experiments/perf/smolquery_ingest/data]

Input (read only): results/<run>/{load.json,cpu_end.json,samples.jsonl,
latencies_ms.json,driver.log,server.log,prof/events.jsonl} and
results/idle-*/{after_boot.json,idle.json,prof/events.jsonl}.

Output: CSV files and tables.md under --out. Every number in README.md comes
from these files. No raw logs are copied, only two short crash excerpts.

Definitions used throughout
  window         the measured phase: the collector's `start`..`stop` marks for
                 events, the cpu_start..cpu_stop snapshots in load.json for CPU.
  pre            process CPU from boot up to the window start (boot, schema
                 creation, warm-up of 50 bodies).
  after          process CPU between the window stop and cpu_end.json
                 (seal wait of up to 180 s, the count query, shutdown prep).
  lifetime       cpu_end.json absolute values (pre + window + after).
  flush          one `encode` event with ok=true whose t_us lies inside the
                 window. task_us is the whole encode task.
"""
import argparse
import collections
import csv
import glob
import json
import os
import re
import statistics
import sys

CONFIGS = ["erts", "arinsal-patched", "arinsal-fast"]
RUN_RE = re.compile(r"^(full|rate90k|idle|crashed)-(erts|arinsal-patched|arinsal-fast)(?:-(\d+))?$")
MiB = 1048576.0

CLASSES = ["normal_sched", "dirty_cpu", "dirty_io", "poll_checkio", "arinsal_inet",
           "other_runtime", "native_unnamed", "exited_unattributed"]
CLASS_LABEL = {
    "normal_sched": "normal schedulers (erts_sched_N / N_scheduler)",
    "dirty_cpu": "dirty CPU (erts_dcpus_N / N_dirty_cpu_scheduler)",
    "dirty_io": "dirty IO (erts_dios_N / N_dirty_io_scheduler)",
    "poll_checkio": "poll / check-io (erts_poll_N / arinsal-check-io)",
    "arinsal_inet": "arinsal-inet",
    "other_runtime": "other runtime threads (aux, async, dispatch, main, arinsal-*)",
    "native_unnamed": "native unnamed (DuckDB, Polars)",
    "exited_unattributed": "exited threads (process total minus live threads)",
}


def classify(name):
    if re.fullmatch(r"erts_sched_\d+|\d+_scheduler", name):
        return "normal_sched"
    if re.fullmatch(r"erts_dcpus_\d+|\d+_dirty_cpu_scheduler", name):
        return "dirty_cpu"
    if re.fullmatch(r"erts_dios_\d+|\d+_dirty_io_scheduler", name):
        return "dirty_io"
    if re.fullmatch(r"erts_poll_\d+", name) or name == "arinsal-check-io":
        return "poll_checkio"
    if name == "arinsal-inet":
        return "arinsal_inet"
    if name == "":
        return "native_unnamed"
    return "other_runtime"


def jload(path):
    with open(path) as f:
        return json.load(f)


def jlines(path):
    out = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    out.append(json.loads(line))
                except ValueError:
                    pass
    return out


def median(xs):
    xs = [x for x in xs if x is not None]
    return statistics.median(xs) if xs else None


def pct(sorted_vals, p):
    # same index rule as scripts/load.py in the ingest-profile harness
    n = len(sorted_vals)
    return sorted_vals[min(n - 1, int(round(p / 100 * (n - 1))))]


def sec(hms):
    h, m, s = hms.split(":")
    return int(h) * 3600 + int(m) * 60 + float(s)


def cpu_ns(snap):
    return snap["user_ns"] + snap["sys_ns"]


def thread_cpu(snap):
    return {t["id"]: t for t in snap["threads"]}


def split_cpu(cur, prev=None):
    """CPU seconds by class for `cur` minus `prev` (both threadcpu snapshots)."""
    pt = thread_cpu(prev) if prev else {}
    acc = collections.defaultdict(lambda: [0.0, 0.0])
    groups = collections.defaultdict(lambda: [0.0, set()])
    live_u = live_s = 0.0
    for t in cur["threads"]:
        p = pt.get(t["id"], {"user_ns": 0, "sys_ns": 0})
        u = (t["user_ns"] - p["user_ns"]) / 1e9
        s = (t["sys_ns"] - p["sys_ns"]) / 1e9
        c = classify(t["name"])
        acc[c][0] += u
        acc[c][1] += s
        live_u += u
        live_s += s
        g = re.sub(r"\d+", "N", t["name"]) or "(unnamed)"
        groups[g][0] += u + s
        groups[g][1].add(t["id"])
    tot_u = (cur["user_ns"] - (prev["user_ns"] if prev else 0)) / 1e9
    tot_s = (cur["sys_ns"] - (prev["sys_ns"] if prev else 0)) / 1e9
    acc["exited_unattributed"] = [tot_u - live_u, tot_s - live_s]
    return ({c: tuple(acc[c]) for c in CLASSES},
            {g: (v[0], len(v[1])) for g, v in groups.items()}, tot_u + tot_s)


def marks_of(ev):
    return {e["name"]: e for e in ev if e["kind"] == "mark"}


def flush_stats(ev, marks):
    t0, t1 = marks["start"]["mono_us"], marks["stop"]["mono_us"]
    enc = [e for e in ev if e["kind"] == "encode" and e.get("ok") and t0 <= e["t_us"] <= t1]
    if not enc:
        return None
    parts = {}

    def col(f):
        return [f(e) for e in enc]

    task = col(lambda e: e.get("task_us", 0))
    parts["spool"] = col(lambda e: e.get("spool_us", 0))
    parts["probe"] = col(lambda e: e.get("probe_us", 0))
    parts["copy"] = col(lambda e: e.get("copy_us", 0))
    parts["footer"] = col(lambda e: e.get("footer_us", 0))
    parts["stats"] = col(lambda e: e.get("stats_us", 0))
    parts["fsync"] = col(lambda e: e.get("fsync_us", 0))
    parts["link"] = col(lambda e: e.get("link_us", 0))
    parts["discard"] = col(lambda e: e.get("discard_us", 0))
    parts["put_other"] = col(lambda e: e.get("put_total_us", 0) - e.get("copy_us", 0) - e.get("footer_us", 0)
                             - e.get("stats_us", 0) - e.get("fsync_us", 0) - e.get("link_us", 0))
    # whatever task_us holds besides the parts above (scheduling, glue)
    named = ("spool", "probe", "copy", "footer", "stats", "fsync", "link", "discard", "put_other")
    parts["other"] = [task[i] - sum(parts[k][i] for k in named) for i in range(len(enc))]
    out = {"flushes": len(enc), "window_s": (t1 - t0) / 1e6,
           "rows_per_flush": median(col(lambda e: e["rows"])),
           "ndjson_mib_per_flush": median(col(lambda e: e["bytes"])) / MiB,
           "segment_mib_per_flush": median(col(lambda e: e.get("segment_bytes", 0))) / MiB,
           "bodies_per_flush": median(col(lambda e: e.get("chunks", 0))),
           "task_ms": median(task) / 1000}
    tsum = sum(task)
    nbytes = col(lambda e: e["bytes"] / MiB)
    out["task_mean_ms"] = tsum / len(enc) / 1000
    out["task_ms_per_ndjson_mib"] = median([t / 1000 / b for t, b in zip(task, nbytes)])
    for k, v in parts.items():
        out[k + "_ms"] = median(v) / 1000
        out[k + "_mean_ms"] = sum(v) / len(enc) / 1000
        out[k + "_pct"] = 100.0 * sum(v) / tsum          # share of mean task_us
        out[k + "_median_pct"] = 100.0 * median(v) / median(task)
        out[k + "_ms_per_ndjson_mib"] = median([x / 1000 / b for x, b in zip(v, nbytes)])
    return out


def seal_rows(ev, marks):
    t0 = marks["start"]["mono_us"]
    res = []
    for e in ev:
        if e["kind"] == "seal_attempt":
            res.append({"result": e.get("result"), "segments": e.get("segments"),
                        "duration_s": e["duration_us"] / 1e6,
                        "start_s_after_window_start": (e["t_us"] - e["duration_us"] - t0) / 1e6})
    segs = [e for e in ev if e["kind"] == "seal_segment"]
    return res, len(segs), sum(e.get("rows", 0) for e in segs), sum(e.get("bytes", 0) for e in segs) / MiB


def bandit_timeouts(server_log, driver_log):
    drv = open(driver_log).read()
    m = re.search(r"(\d\d:\d\d:\d\d) measure \d+ bodies", drv)
    t0 = sec(m.group(1)) if m else None
    ts = []
    pat = re.compile(r"(\d\d:\d\d:\d\d\.\d+) \[error\] \*\* \(Bandit\.TransportError\) Unrecoverable error: timeout")
    other = 0
    for line in open(server_log, errors="replace"):
        m = pat.search(line)
        if m:
            ts.append(sec(m.group(1)) - (t0 or 0))
        elif "Bandit.TransportError" in line:
            other += 1
    bursts = []
    for t in sorted(ts):
        if bursts and t - bursts[-1][-1] <= 5:
            bursts[-1].append(t)
        else:
            bursts.append([t])
    return {"timeouts": len(ts), "other_transport_errors": other,
            "first_s": min(ts) if ts else None, "last_s": max(ts) if ts else None,
            "bursts": len(bursts), "burst_sizes": "/".join(str(len(b)) for b in bursts)}


def mem_series(ev, marks, key):
    t0, t1 = marks["start"]["t_us"], marks["stop"]["t_us"]
    return [e["memory"][key] for e in ev if e["kind"] == "mem" and t0 <= e["t_us"] <= t1]


def analyze_run(rdir, name, kind, cfg, n):
    rec = {"run": name, "config": cfg, "kind": kind, "n": n}
    ev = jlines(os.path.join(rdir, "prof", "events.jsonl"))
    marks = marks_of(ev)
    boot = next((e for e in ev if e["kind"] == "boot"), {})
    rec["runtime"] = boot.get("runtime", "").strip()
    if kind == "crashed":
        return rec, ev, marks, None
    load = jload(os.path.join(rdir, "load.json"))
    m = load["measure_phase"]
    lat = sorted(jload(os.path.join(rdir, "latencies_ms.json")))
    rec.update({
        "rows": m["rows"], "bytes": m["bytes"], "duration_s": m["duration_s"],
        "rows_per_s": m["rows_per_s"], "mib_per_s": m["mib_per_s"],
        "ack_p50_ms": pct(lat, 50), "ack_p99_ms": pct(lat, 99), "ack_max_ms": lat[-1],
        "warmup_rows_per_s": load["warmup_phase"]["rows_per_s"],
        "non200": sum(v for k, v in m["statuses"].items() if k != "200"),
        "retries_429": m["retries_429"], "retries_other": m["retries_other"],
        "offered_rate": load.get("rate"),
    })
    assert abs(rec["ack_p50_ms"] - m["latency_ms"]["p50"]) < 1e-6, name
    sw = load.get("seal_wait")
    rec["seal_wait_s"] = sw["waited_s"] if sw else None
    rec["hot_files_left"] = sw["hot_files_left"] if sw else None
    cnt = load.get("count")
    rec["count_rows"] = cnt if isinstance(cnt, int) else None
    rec["count_error"] = None if isinstance(cnt, int) else "400 database is locked"
    sealed, nseg, seg_rows, seg_mib = seal_rows(ev, marks)
    rec.update({"seal_attempts": len(sealed), "seal_ok": sum(1 for s in sealed if s["result"] == "ok"),
                "seal_error": sum(1 for s in sealed if s["result"] == "error"),
                "seal_segments_written": nseg, "seal_rows_written": seg_rows, "seal_mib_written": seg_mib})
    rec.update({"bandit_" + k: v for k, v in bandit_timeouts(os.path.join(rdir, "server.log"),
                                                             os.path.join(rdir, "driver.log")).items()})
    samples = [s for s in jlines(os.path.join(rdir, "samples.jsonl")) if "phys_footprint" in s]
    end = jload(os.path.join(rdir, "cpu_end.json"))
    a, b = load["cpu_start"], load["cpu_stop"]
    rec.update({
        "peak_footprint_mib_window": max(s["phys_footprint"] for s in samples) / MiB,
        "peak_rss_mib_window": max(s["rss"] for s in samples) / MiB,
        "footprint_at_window_start_mib": a["phys_footprint"] / MiB,
        "footprint_at_window_stop_mib": b["phys_footprint"] / MiB,
        "end_footprint_mib": end["phys_footprint"] / MiB,
        "end_rss_mib": end["rss"] / MiB,
        "lifetime_max_footprint_mib": end["lifetime_max_phys_footprint"] / MiB,
        "erlang_memory_peak_window_mib": marks["stop"].get("memory_peak_sampled", 0) / MiB,
        "window_cpu_s": (cpu_ns(b) - cpu_ns(a)) / 1e9,
        "pre_cpu_s": cpu_ns(a) / 1e9,
        "after_cpu_s": (cpu_ns(end) - cpu_ns(b)) / 1e9,
        "lifetime_cpu_s": cpu_ns(end) / 1e9,
        "window_wall_s": (b["t_ms"] - a["t_ms"]) / 1000,
        "after_wall_s": (end["t_ms"] - b["t_ms"]) / 1000,
    })
    rec["window_cores"] = rec["window_cpu_s"] / rec["window_wall_s"]
    rec["after_cores"] = rec["after_cpu_s"] / rec["after_wall_s"]
    rec["window_cpu_s_per_mrow"] = rec["window_cpu_s"] / (rec["rows"] / 1e6)
    for key in ("total", "processes", "binary", "ets", "system", "code", "atom"):
        s = mem_series(ev, marks, key)
        if s:
            rec["erlang_memory_%s_peak_mib" % key] = max(s) / MiB
    cpu = {"pre": split_cpu(a), "window": split_cpu(b, a), "after": split_cpu(end, b), "lifetime": split_cpu(end)}
    fl = flush_stats(ev, marks)
    return rec, ev, marks, (cpu, fl, sealed)


def analyze_idle(rdir, name, cfg):
    a, b = jload(os.path.join(rdir, "after_boot.json")), jload(os.path.join(rdir, "idle.json"))
    ev = jlines(os.path.join(rdir, "prof", "events.jsonl"))
    idle = marks_of(ev)["idle"]
    mem = idle["memory"]
    rec = {"run": name, "config": cfg,
           "after_boot_footprint_mib": a["phys_footprint"] / MiB, "after_boot_rss_mib": a["rss"] / MiB,
           "idle_footprint_mib": b["phys_footprint"] / MiB, "idle_rss_mib": b["rss"] / MiB,
           "lifetime_max_footprint_mib": b["lifetime_max_phys_footprint"] / MiB,
           "boot_cpu_s": cpu_ns(a) / 1e9, "boot_cpu_user_s": a["user_ns"] / 1e9, "boot_cpu_sys_s": a["sys_ns"] / 1e9,
           "idle_interval_s": (b["t_ms"] - a["t_ms"]) / 1000,
           "idle_cpu_s": (cpu_ns(b) - cpu_ns(a)) / 1e9, "nthreads": b["nthreads"]}
    rec["idle_cores"] = rec["idle_cpu_s"] / rec["idle_interval_s"]
    for k in ("total", "processes", "binary", "ets", "system", "code", "atom"):
        rec["erlang_memory_%s_mib" % k] = mem[k] / MiB
    return rec


def write_csv(path, rows, cols=None):
    if not rows:
        return
    if cols is None:
        cols = []
        for r in rows:
            for k in r:
                if k not in cols:
                    cols.append(k)

    def fmt(v):
        if isinstance(v, float):
            return "%.4f" % v
        return "" if v is None else str(v)

    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(cols)
        for r in rows:
            w.writerow([fmt(r.get(c)) for c in cols])


def crash_info(results):
    d = os.path.join(results, "crashed-arinsal-fast-2")
    ev = jlines(os.path.join(d, "prof", "events.jsonl"))
    marks = marks_of(ev)
    t0 = marks["start"]["mono_us"]
    enc = [e for e in ev if e["kind"] == "encode" and e.get("ok")]
    last = max(e["t_us"] for e in enc)
    inwin = [e for e in enc if e["t_us"] >= t0]
    log = open(os.path.join(d, "server.log"), errors="replace").read().splitlines()
    keep, i = [], 0
    while i < len(log):
        if "panicked at" in log[i]:
            keep.append(log[i])
            j = i + 1
            while j < len(log) and not log[j].startswith("thread "):
                keep.append(log[j])
                j += 1
            keep.append("")
            i = j
        else:
            i += 1
    # keep only the frames without std/core internals' source lines
    short = [l for l in keep if not re.match(r"\s+at /rustc/", l)]
    drv = open(os.path.join(d, "driver.log")).read()
    mm = re.search(r"(\d\d:\d\d:\d\d) measure \d+ bodies", drv)
    err = re.search(r"(\d\d:\d\d:\d\d) request error", drv)
    n_err = len(re.findall(r"request error", drv))
    return {"last_encode_s_after_window_start": (last - t0) / 1e6,
            "flushes_in_window_before_crash": len(inwin),
            "rows_in_window_before_crash": sum(e["rows"] for e in inwin),
            "measure_start": mm.group(1) if mm else None, "first_request_error": err.group(1) if err else None,
            "request_errors": n_err, "excerpt": short}


def boot_panic_excerpt(logs):
    path = os.path.join(logs, "boot-ar13.log")
    if not os.path.exists(path):
        return []
    lines = open(path, errors="replace").read().splitlines()
    for i, l in enumerate(lines):
        if "panicked at" in l:
            out = []
            for x in lines[i:i + 40]:
                if re.match(r"\s+at /rustc/", x):
                    continue
                out.append(x)
                if "run_task" in x:
                    break
            return out
    return []


def crosscheck_matrix(logs, runs):
    path = os.path.join(logs, "matrix.log")
    if not os.path.exists(path):
        return "matrix.log not found"
    pending, found = [], {}
    for line in open(path, errors="replace"):
        m = re.search(r"measure done (\d+) rows/s p50 (\d+) p99 (\d+)", line)
        if m:
            pending.append(tuple(int(x) for x in m.groups()))
        m = re.match(r"done (\S+)", line)
        if m and pending:
            found[m.group(1)] = pending.pop()
            pending = []
    bad, ok = [], 0
    for name, (r, p50, p99) in found.items():
        rec = runs.get(name)
        if not rec or "rows_per_s" not in rec:
            continue
        if abs(round(rec["rows_per_s"]) - r) > 1 or abs(round(rec["ack_p50_ms"]) - p50) > 1 or abs(round(rec["ack_p99_ms"]) - p99) > 1:
            bad.append((name, (r, p50, p99), (round(rec["rows_per_s"]), round(rec["ack_p50_ms"]), round(rec["ack_p99_ms"]))))
        else:
            ok += 1
    return "matrix.log cross-check: %d runs agree with load.json/latencies, mismatches: %s" % (ok, bad or "none")


# ---------------------------------------------------------------- tables

def ms(vals, nd=0):
    """median (min-max) of a list."""
    vals = [v for v in vals if v is not None]
    if not vals:
        return "n/a"
    f = "{:,.%df}" % nd
    med = statistics.median(vals)
    if len(vals) == 1 or min(vals) == max(vals):
        return f.format(med)
    return "%s (%s–%s)" % (f.format(med), f.format(min(vals)), f.format(max(vals)))


def md(headers, rows, align=None):
    align = align or ["l"] + ["r"] * (len(headers) - 1)
    sep = ["---:" if a == "r" else "---" for a in align]
    out = ["| " + " | ".join(headers) + " |", "|" + "|".join(sep) + "|"]
    for r in rows:
        out.append("| " + " | ".join(str(c) for c in r) + " |")
    return "\n".join(out)


def build_tables(recs, cpu, fl, idle, seals):
    T = collections.OrderedDict()
    full = [r for r in recs if r["kind"] == "full"]
    r90 = [r for r in recs if r["kind"] == "rate90k"]
    by_cfg = lambda rs, c: [r for r in rs if r["config"] == c]

    rows = []
    for r in sorted(full + r90, key=lambda r: (r["kind"], CONFIGS.index(r["config"]), r["n"] or 0)):
        rows.append([r["run"], "%.0f" % r["rows_per_s"], "%.0f" % r["mib_per_s"], "%.0f" % r["ack_p50_ms"],
                     "%.0f" % r["ack_p99_ms"], "%.0f" % r["warmup_rows_per_s"], r["bandit_timeouts"],
                     "%d/%d" % (r["seal_ok"], r["seal_error"]) if r["seal_attempts"] else "0",
                     "n/a" if r["hot_files_left"] is None else r["hot_files_left"]])
    T["runs"] = md(["run", "rows/s", "NDJSON MiB/s", "ack p50 ms", "ack p99 ms", "warm-up rows/s", "Bandit timeouts",
                    "seal attempts ok/error", "hot files left after wait"], rows)

    def cfg_table(rs, cols):
        rows = []
        for c in CONFIGS:
            x = by_cfg(rs, c)
            rows.append([c, len(x)] + [ms([f(r) for r in x], nd) for (_, f, nd) in cols])
        return md(["config", "n"] + [h for (h, _, _) in cols], rows)

    T["cfg_full"] = cfg_table(full, [
        ("rows/s", lambda r: r["rows_per_s"], 0), ("ack p50 ms", lambda r: r["ack_p50_ms"], 0),
        ("ack p99 ms", lambda r: r["ack_p99_ms"], 0), ("warm-up rows/s", lambda r: r["warmup_rows_per_s"], 0),
        ("Bandit timeouts", lambda r: r["bandit_timeouts"], 0)])
    T["cfg_rate90k"] = cfg_table(r90, [
        ("rows/s", lambda r: r["rows_per_s"], 0), ("ack p50 ms", lambda r: r["ack_p50_ms"], 0),
        ("ack p99 ms", lambda r: r["ack_p99_ms"], 0), ("Bandit timeouts", lambda r: r["bandit_timeouts"], 0)])

    # flush breakdown
    parts = [("spool", "spool write"), ("probe", "probe"), ("copy", "DuckDB COPY"), ("footer", "footer row count"),
             ("stats", "stats query"), ("fsync", "Store.put fsync"), ("link", "Store.put link"),
             ("put_other", "Store.put other"), ("discard", "spool delete"), ("other", "other in task")]
    for kind, rs_all in (("full", full), ("rate90k", r90)):
        rows = []
        for c in CONFIGS:
            fs = [fl[r["run"]] for r in by_cfg(rs_all, c)]
            rows.append([c, len(fs), ms([f["flushes"] for f in fs]), ms([f["rows_per_flush"] for f in fs]),
                         ms([f["ndjson_mib_per_flush"] for f in fs], 1), ms([f["segment_mib_per_flush"] for f in fs], 1),
                         ms([f["bodies_per_flush"] for f in fs], 1), ms([f["task_ms"] for f in fs], 1)])
        T["flush_size_" + kind] = md(["config", "n", "flushes in window", "rows/flush (median)", "NDJSON MiB/flush",
                                      "segment MiB/flush", "bodies/flush", "task ms (median)"], rows)
        rows = []
        for k, label in parts:
            row = [label]
            for c in CONFIGS:
                fs = [fl[r["run"]] for r in by_cfg(rs_all, c)]
                row.append("%.1f / %.1f (%.1f%%)" % (median([f[k + "_ms"] for f in fs]), median([f[k + "_mean_ms"] for f in fs]),
                                                     median([f[k + "_pct"] for f in fs])))
            rows.append(row)
        row = ["**task_us (whole flush)**"]
        for c in CONFIGS:
            fs = [fl[r["run"]] for r in by_cfg(rs_all, c)]
            row.append("**%.1f / %.1f**" % (median([f["task_ms"] for f in fs]), median([f["task_mean_ms"] for f in fs])))
        rows.append(row)
        T["flush_parts_" + kind] = md(["part: median ms / mean ms (share of mean task_us)"] + CONFIGS, rows)
        rows = []
        for k, label in [("task", "whole task"), ("spool", "spool write"), ("copy", "DuckDB COPY"), ("stats", "stats query")]:
            row = [label]
            for c in CONFIGS:
                fs = [fl[r["run"]] for r in by_cfg(rs_all, c)]
                key = "task_ms_per_ndjson_mib" if k == "task" else k + "_ms_per_ndjson_mib"
                row.append("%.2f" % median([f[key] for f in fs]))
            rows.append(row)
        T["flush_permib_" + kind] = md(["ms per NDJSON MiB of the flush (median over flushes)"] + CONFIGS, rows)
    rows = []
    for r in sorted(full + r90, key=lambda r: (r["kind"], CONFIGS.index(r["config"]), r["n"] or 0)):
        f = fl[r["run"]]
        rows.append([r["run"], f["flushes"], "%.0f" % f["rows_per_flush"], "%.1f" % f["ndjson_mib_per_flush"],
                     "%.1f" % f["task_ms"], "%.1f" % f["spool_ms"], "%.1f" % f["copy_ms"], "%.1f" % f["stats_ms"],
                     "%.1f" % f["footer_ms"], "%.1f" % f["discard_ms"]])
    T["flush_runs"] = md(["run", "flushes", "rows/flush", "NDJSON MiB/flush", "task ms", "spool ms", "COPY ms",
                          "stats ms", "footer ms", "spool delete ms"], rows)

    # CPU by class
    for scope in ("window", "lifetime", "after"):
        for kind, rs_all in (("full", full), ("rate90k", r90)):
            rows = []
            for cl in CLASSES:
                row = [CLASS_LABEL[cl]]
                for c in CONFIGS:
                    xs = by_cfg(rs_all, c)
                    vals = [sum(cpu[r["run"]][scope][0][cl]) for r in xs]
                    tots = [cpu[r["run"]][scope][2] for r in xs]
                    pcts = [100 * v / t for v, t in zip(vals, tots)]
                    row.append("%s s, %.0f%%" % (ms(vals, 1), median(pcts)))
                rows.append(row)
            row = ["**total process CPU**"]
            for c in CONFIGS:
                row.append("**%s s**" % ms([cpu[r["run"]][scope][2] for r in by_cfg(rs_all, c)], 1))
            rows.append(row)
            T["cpu_%s_%s" % (scope, kind)] = md(["thread class"] + CONFIGS, rows)
    rows = []
    for r in sorted(full + r90, key=lambda r: (r["kind"], CONFIGS.index(r["config"]), r["n"] or 0)):
        rows.append([r["run"], "%.1f" % r["pre_cpu_s"], "%.1f" % r["window_cpu_s"], "%.1f" % r["window_wall_s"],
                     "%.2f" % r["window_cores"], "%.2f" % r["window_cpu_s_per_mrow"], "%.1f" % r["after_cpu_s"],
                     "%.0f" % r["after_wall_s"], "%.2f" % r["after_cores"], "%.1f" % r["lifetime_cpu_s"]])
    T["cpu_runs"] = md(["run", "pre-window CPU s", "window CPU s", "window wall s", "window cores", "window CPU s per 1M rows",
                        "after-window CPU s", "after wall s", "after cores", "lifetime CPU s (cpu_end.json)"], rows)
    for kind, rs_all in (("full", full), ("rate90k", r90)):
        rows = []
        for c in CONFIGS:
            xs = by_cfg(rs_all, c)
            rows.append([c, len(xs), ms([r["pre_cpu_s"] for r in xs], 1), ms([r["window_cpu_s"] for r in xs], 1),
                         ms([r["window_cores"] for r in xs], 2), ms([r["window_cpu_s_per_mrow"] for r in xs], 1),
                         ms([r["after_cpu_s"] for r in xs], 1), ms([r["lifetime_cpu_s"] for r in xs], 1)])
        T["cpu_cfg_" + kind] = md(["config", "n", "pre-window s", "window s", "window cores", "window s per 1M rows",
                                   "after-window s", "lifetime s"], rows)

    # thread groups in window (config median by group)
    for kind, rs_all in (("full", full), ("rate90k", r90)):
        rows = []
        for c in CONFIGS:
            xs = by_cfg(rs_all, c)
            agg = collections.defaultdict(list)
            for r in xs:
                for g, (s, n) in cpu[r["run"]]["window"][1].items():
                    agg[g].append(s)
            top = sorted(agg.items(), key=lambda kv: -median(kv[1]))[:8]
            for g, v in top:
                rows.append([c, g, ms(v, 1)])
        T["threads_" + kind] = md(["config", "thread name (digits -> N)", "window CPU s, summed over threads"], rows, ["l", "l", "r"])

    # idle
    rows = []
    for r in idle:
        rows.append([r["config"], "%.0f" % r["idle_footprint_mib"], "%.0f" % r["idle_rss_mib"],
                     "%.0f" % r["after_boot_footprint_mib"], "%.1f" % r["boot_cpu_s"],
                     "%.2f" % r["idle_cpu_s"], "%.0f" % r["idle_interval_s"], "%.3f" % r["idle_cores"],
                     "%.0f" % r["erlang_memory_total_mib"], "%.0f" % r["erlang_memory_processes_mib"],
                     "%.1f" % r["erlang_memory_ets_mib"], "%.1f" % r["erlang_memory_atom_mib"], r["nthreads"]])
    T["idle"] = md(["config", "idle footprint MiB", "idle RSS MiB", "after-boot footprint MiB", "boot CPU s",
                    "CPU s while idle", "idle interval s", "idle cores", "erlang:memory total MiB", "processes MiB",
                    "ets MiB", "atom MiB", "threads"], rows)

    # memory under load
    rows = []
    for r in sorted(full + r90, key=lambda r: (r["kind"], CONFIGS.index(r["config"]), r["n"] or 0)):
        rows.append([r["run"], "%.0f" % r["peak_footprint_mib_window"], "%.0f" % r["peak_rss_mib_window"],
                     "%.0f" % r["lifetime_max_footprint_mib"], "%.0f" % r["end_footprint_mib"],
                     "%.0f" % r["end_rss_mib"], "%.0f" % r["erlang_memory_peak_window_mib"]])
    T["mem_runs"] = md(["run", "peak footprint in window MiB (1 Hz)", "peak RSS in window MiB", "lifetime max footprint MiB",
                        "footprint at end MiB", "RSS at end MiB", "erlang:memory total peak in window MiB (5 Hz)"], rows)
    for kind, rs_all in (("full", full), ("rate90k", r90)):
        rows = []
        for c in CONFIGS:
            xs = by_cfg(rs_all, c)
            rows.append([c, len(xs), ms([r["peak_footprint_mib_window"] for r in xs]), ms([r["peak_rss_mib_window"] for r in xs]),
                         ms([r["lifetime_max_footprint_mib"] for r in xs]), ms([r["end_footprint_mib"] for r in xs]),
                         ms([r["end_rss_mib"] for r in xs]), ms([r["erlang_memory_peak_window_mib"] for r in xs])])
        T["mem_cfg_" + kind] = md(["config", "n", "peak footprint in window", "peak RSS in window", "lifetime max footprint",
                                   "footprint at end", "RSS at end", "erlang:memory peak in window"], rows)
    rows = []
    for r in sorted(r90, key=lambda r: CONFIGS.index(r["config"])):
        g = lambda k: "%.0f" % r.get("erlang_memory_%s_peak_mib" % k, float("nan"))
        rows.append([r["config"], g("total"), g("processes"), g("binary"), g("ets"), g("system"), g("code"), g("atom")])
    T["erlang_memory_rate90k"] = md(["config", "total", "processes", "binary", "ets", "system", "code", "atom"], rows)

    # seals
    rows = []
    for r in sorted(full + r90, key=lambda r: (r["kind"], CONFIGS.index(r["config"]), r["n"] or 0)):
        for i, s in enumerate(seals[r["run"]], 1):
            rows.append([r["run"], i, s["result"], s["segments"], "%.1f" % s["start_s_after_window_start"],
                         "%.1f" % s["duration_s"]])
        if not seals[r["run"]]:
            rows.append([r["run"], "-", "no attempt finished", "-", "-", "-"])
    T["seals"] = md(["run", "attempt", "result", "segments", "start, s after window start", "duration s"], rows)
    rows = []
    for r in sorted(full + r90, key=lambda r: (r["kind"], CONFIGS.index(r["config"]), r["n"] or 0)):
        rows.append([r["run"], r["seal_attempts"], r["seal_ok"], r["seal_error"], r["seal_segments_written"],
                     "%.0f" % r["seal_rows_written"], "%.0f" % r["seal_mib_written"],
                     "n/a" if r["seal_wait_s"] is None else "%.0f" % r["seal_wait_s"],
                     "n/a" if r["hot_files_left"] is None else r["hot_files_left"],
                     r["bandit_timeouts"], "n/a" if r["bandit_first_s"] is None else "%.0f" % r["bandit_first_s"],
                     "n/a" if r["bandit_last_s"] is None else "%.0f" % r["bandit_last_s"], r["bandit_bursts"],
                     r["bandit_burst_sizes"] or "-"])
    T["seal_runs"] = md(["run", "seal attempts", "ok", "error", "sealed segments", "sealed rows", "sealed MiB",
                         "seal wait s", "hot files left", "Bandit timeouts", "first, s after measure start",
                         "last", "bursts", "burst sizes"], rows)
    return T


def main():
    ip = "/Users/sts/dev/sq/ingest-profile"
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", default=os.path.join(ip, "results"))
    ap.add_argument("--logs", default=os.path.join(ip, "logs"))
    ap.add_argument("--out", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "data"))
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)

    recs, cpu, fl, seals, idle, runs = [], {}, {}, {}, [], {}
    for d in sorted(glob.glob(os.path.join(a.results, "*"))):
        name = os.path.basename(d)
        m = RUN_RE.match(name)
        if not m:
            continue
        kind, cfg, n = m.group(1), m.group(2), m.group(3)
        if kind == "idle":
            idle.append(analyze_idle(d, name, cfg))
            continue
        if kind == "crashed":
            continue
        rec, ev, marks, extra = analyze_run(d, name, kind, cfg, int(n) if n else None)
        c, f, s = extra
        recs.append(rec)
        runs[name] = rec
        cpu[name], fl[name], seals[name] = c, f, s
    idle.sort(key=lambda r: CONFIGS.index(r["config"]))

    # ---- CSV outputs
    order = lambda r: (r["kind"], CONFIGS.index(r["config"]), r["n"] or 0)
    recs.sort(key=order)
    write_csv(os.path.join(a.out, "runs.csv"), recs)
    write_csv(os.path.join(a.out, "flush_breakdown.csv"),
              [dict(run=r["run"], config=r["config"], kind=r["kind"], **fl[r["run"]]) for r in recs])
    cls_rows, grp_rows = [], []
    for r in recs:
        for scope, (cl, groups, total) in cpu[r["run"]].items():
            for c in CLASSES:
                u, s = cl[c]
                cls_rows.append({"run": r["run"], "config": r["config"], "kind": r["kind"], "scope": scope, "class": c,
                                 "user_s": u, "sys_s": s, "total_s": u + s, "pct_of_scope": 100 * (u + s) / total})
            if scope in ("window", "lifetime"):
                for g, (s, nthr) in sorted(groups.items(), key=lambda kv: -kv[1][0]):
                    grp_rows.append({"run": r["run"], "config": r["config"], "kind": r["kind"], "scope": scope,
                                     "thread_name_pattern": g, "threads": nthr, "total_s": s})
    write_csv(os.path.join(a.out, "cpu_by_class.csv"), cls_rows)
    write_csv(os.path.join(a.out, "cpu_by_thread_name.csv"), grp_rows)
    write_csv(os.path.join(a.out, "idle.csv"), idle)
    seal_rows_out = []
    for r in recs:
        for i, s in enumerate(seals[r["run"]], 1):
            seal_rows_out.append(dict(run=r["run"], attempt=i, **s))
    write_csv(os.path.join(a.out, "seal_attempts.csv"), seal_rows_out)
    # per configuration summary: median / min / max over runs of each numeric metric
    summ = []
    for kind in ("full", "rate90k"):
        for c in CONFIGS:
            xs = [r for r in recs if r["kind"] == kind and r["config"] == c]
            keys = [k for k, v in xs[0].items() if isinstance(v, (int, float)) and k != "n"]
            for k in keys:
                vals = [x[k] for x in xs if isinstance(x.get(k), (int, float))]
                if vals:
                    summ.append({"kind": kind, "config": c, "metric": k, "n": len(vals),
                                 "median": statistics.median(vals), "min": min(vals), "max": max(vals)})
            for k in ("task_ms", "spool_ms", "copy_ms", "stats_ms", "footer_ms", "rows_per_flush"):
                vals = [fl[x["run"]][k] for x in xs]
                summ.append({"kind": kind, "config": c, "metric": "flush_" + k, "n": len(vals),
                             "median": statistics.median(vals), "min": min(vals), "max": max(vals)})
            for cl in CLASSES:
                for scope in ("window", "lifetime", "after"):
                    vals = [sum(cpu[x["run"]][scope][0][cl]) for x in xs]
                    summ.append({"kind": kind, "config": c, "metric": "cpu_%s_%s_s" % (scope, cl), "n": len(vals),
                                 "median": statistics.median(vals), "min": min(vals), "max": max(vals)})
    write_csv(os.path.join(a.out, "summary_by_config.csv"), summ)

    # crash and boot-panic excerpts
    crash = crash_info(a.results)
    with open(os.path.join(a.out, "crash_excerpt.txt"), "w") as f:
        f.write("# crashed-arinsal-fast-2/server.log, panic messages and frames (std/core source lines removed)\n")
        f.write("\n".join(crash["excerpt"]) + "\n")
    bp = boot_panic_excerpt(a.logs)
    if bp:
        with open(os.path.join(a.out, "literal_area_panic_excerpt.txt"), "w") as f:
            f.write("# logs/boot-ar13.log, first panic (std/core source lines removed)\n")
            f.write("\n".join(bp) + "\n")
    crow = {k: v for k, v in crash.items() if k != "excerpt"}
    write_csv(os.path.join(a.out, "crash_run.csv"), [crow])

    T = build_tables(recs, cpu, fl, idle, seals)
    with open(os.path.join(a.out, "tables.md"), "w") as f:
        for k, v in T.items():
            f.write("<!-- table:%s -->\n%s\n\n" % (k, v))
    print(crosscheck_matrix(a.logs, runs))
    print("runs: %d full/rate90k, %d idle; crash run: %s" % (len(recs), len(idle), json.dumps(crow)))
    print("wrote", a.out)


if __name__ == "__main__":
    main()
