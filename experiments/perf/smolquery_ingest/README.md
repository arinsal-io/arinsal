# smolquery ingest on Arinsal vs erts

Question: what happens when a real Elixir/OTP 29 application with native dependencies (smolquery:
DuckDB through the ADBC NIF, Explorer/Polars through Rustler, Bandit, gen_rpc) ingests a sustained
stream of wide rows on Arinsal instead of erts, which parts of the gap belong to the runtime, and
which Arinsal fixes follow from it.

This document is for the person who will fix things in Arinsal. Every number below is computed by
`analyze.py` from the raw per-run data of one measurement session (2026-10-13, local time
17:42 to 18:51). The generated tables are in `data/tables.md`, the same numbers as CSV in `data/`.
Where the data disagrees with an expectation, the data is used and the difference is stated.

## 1. Summary

- **What was run.** smolquery ingesting the ClickBench `hits` table (105 columns, about 2.33 KB per
  row as NDJSON) over HTTP with 8 closed-loop workers: 3,000,000 measured rows in 294 bodies of about
  10,200 rows, after a 488,010-row warm-up. Three runtimes, interleaved: erts (Homebrew OTP 29.1),
  `arinsal-patched` (Arinsal e49d55f plus compatibility patches) and `arinsal-fast` (the same plus one
  byte-copy fast path). 3 valid runs each (a fourth `arinsal-fast` run crashed), plus one run per
  runtime at a fixed offered load of 90,000 rows/s, plus idle boots.
- **Throughput.** erts 390,287 rows/s (379,627 to 395,162), ack p50 167 ms, p99 364 ms.
  `arinsal-patched` 105,817 rows/s (27% of erts), p50 765 ms, p99 1,093 ms.
  `arinsal-fast` 254,917 rows/s (65% of erts), p50 305 ms, p99 479 ms.
  At the same offered 90,000 rows/s all three keep up, with ack p50 of 94 ms (erts), 222 ms
  (`arinsal-fast`) and 489 ms (`arinsal-patched`).
- **Largest single cause: `prim_file` writes.** The spool write of one flush (about 46 MiB) takes
  456 ms on `arinsal-patched` against 5.6 ms on erts, 72% of the whole flush task. Arinsal's file NIF
  converts its arguments with `to_owned`, which copies a binary one bit at a time (about 9.5 ns per
  byte) on a normal scheduler. The byte-copy fast path brings it to 7.5 ms for a 23 MiB flush. The real fix is
  T-PRIMFILE (iovec by reference, dirty IO).
- **CPU goes to different threads.** For the same 3,000,000 rows the window CPU is 39.4 s (erts),
  66.3 s (`arinsal-fast`) and 132.4 s (`arinsal-patched`). On erts 68% is dirty IO (DuckDB inside the
  ADBC NIF) and 20% native DuckDB threads; normal schedulers use 13%. On Arinsal normal schedulers use
  50% (fast) and 79% (patched), and the two network helper threads `arinsal-check-io` and
  `arinsal-inet` add 16% (fast). At equal offered load the window CPU is 92.2 s (erts), 93.4 s
  (`arinsal-fast`), 138.0 s (`arinsal-patched`), but see the next point.
- **Read every CPU and memory comparison under load with this bias in mind: Arinsal never completed a
  seal.** In every Arinsal run the background seal (merge of the hot micro-segments into one Parquet
  file, DuckDB reading the segments over `httpfs` from smolquery's Bandit hot server) ended with a
  merge timeout after 121 to 145 s, and each run logged 34 to 69 `Bandit.TransportError ... timeout`
  lines (erts: 0). erts completed the seals in 2 of 3 full runs (3,488,010 rows sealed), and the
  first seal (28 to 32 segments, 3 to 15 s) starts inside the measured window. So erts' window CPU
  and memory include DuckDB merge work that Arinsal's do not. Comparisons are biased in Arinsal's
  favour.
- **Idle footprint.** 481 MiB on Arinsal against 172 MiB on erts after boot (RSS 622 against 211 MiB),
  with `erlang:memory(total)` of 33 against 76 MiB, so the extra memory is outside the VM's own
  accounting. Boot CPU is 6.0 s against 3.4 s.
- **After the window Arinsal spins.** While the failed merge is retried, `arinsal-check-io` and
  `arinsal-inet` together use 0.8 to 1.05 cores for the 3 minutes of the seal wait (erts: none).
- **Stability.** One of 9 loaded Arinsal runs aborted: a non-unwinding panic in `direct_bif_light`
  (an ETS `update_counter` default object whose key hashed as an `Invalid` term) 8.8 s into the
  measured window. Booting at all needed seven experimental compatibility patches; six became PRs #6 to #11. A
  literal-area heap scan panic (`invalid boxed subtag 0x4`) was observed and worked around in the
  experimental build; its root cause is under investigation (T-LITAREA) and is not attributed to smolquery.

## 2. Setup

### Machine and runtimes

| item | value |
|---|---|
| machine | Apple M4 Pro, 12 cores (8P + 4E), 24 GiB RAM, macOS 15.7.5 (Darwin 24.6), local APFS SSD |
| erts | Homebrew Erlang/OTP 29.1 (`erts-17.1`, JIT, dtrace), Elixir 1.20.4, 12 schedulers, 12 dirty CPU, 10 dirty IO |
| Arinsal base | `arinsal-io/arinsal` origin/main at `e49d55f` (what `arinsal-wt` was checked out at), `cargo build --release -p arinsal-cli` |
| `arinsal-patched` | `e49d55f` + `patches/patches-compat.diff` + `patches/patches-threadnames.diff` |
| `arinsal-fast` | `arinsal-patched` + `patches/patches-fastcopy.diff` |
| smolquery | `v0.22.0-16-gaf7ae2e` (branch `perf/raw-spool-io`, "write and delete spool files in raw mode") plus uncommitted timing instrumentation (see below) |
| smolquery dependencies | Bandit 1.12.5, adbc 0.12.1 (DuckDB 1.5.3), explorer 0.12.0, DuckLake on a SQLite catalog |
| same beams for all | `mix run --no-compile --no-deps-check`; the runtime is chosen by a `PATH` shim whose `erl` is the Arinsal binary |
| load generator | `harness/load.py`, Python `http.client`, 8 worker threads, closed loop (or paced to a row rate) |

Notes on the table. erts is OTP 29.1, Arinsal ports OTP-29.1.1; the difference is not relevant to the
paths measured here. Background load on the machine during the session was not recorded.
`arinsal-patched` and `arinsal-fast` both name scheduler threads (`N_scheduler`) so CPU per thread
class can be separated from the unnamed DuckDB threads.

### Experimental patches (not the same as the fix PRs)

The patches were applied to the working tree only to get smolquery to boot and run. Each is a quick
local version of a fix; the real fixes are in section 5.

| patch | file and change | became |
|---|---|---|
| compat | `crates/ets/src/lib.rs` skip the `max_arity` shortcut in `lookup_element` | PR #6 |
| compat | `crates/vm/src/natives/nif.rs` `declared_nifs` reads `-nifs` from the loaded module | PR #7 |
| compat | `crates/vm/build.rs` and `natives/nif.rs`: NIF trampoline table 160 to 1024 | PR #8 (stopgap) |
| compat | `crates/vm/src/inet_drv.rs`: `TCP_REQ_SENDFILE` (45) answers `enotsup` | PR #9 (stopgap) |
| compat | `crates/bifs/src/sys.rs`: `system_info(system_architecture)` | PR #10 |
| compat | `crates/bifs/src/pure.rs`: forward `retain_external_binary` for resource binaries | PR #11 |
| compat | `crates/vm/src/natives/sys.rs`: `has_literal_area_roots` assumes the heap references the area instead of scanning it | T-LITAREA |
| threadnames | `crates/sched/src/lib.rs`: name normal scheduler threads `N_scheduler` | instrumentation only |
| fastcopy | `crates/term/src/owned.rs`: byte-aligned `copy_from_slice` fast path in `to_owned` for binaries | stopgap for T-PRIMFILE |

### Workload

- Data: ClickBench `hits_0..3.parquet`, converted to NDJSON with the bench-matrix SELECT
  (`harness/prep/convert.exs`), split on line boundaries into bodies of at most 24,000,000 bytes
  (`harness/prep/split.py`; the largest body in the data is 23,999,998 bytes).
- Schema: `harness/clickbench-schema.json`: 105 columns (73 INT64, 28 STRING, 3 TIMESTAMP, 1 DATE),
  clustering key `CounterID, EventDate, UserID, EventTime`. The rows are web analytics events, not
  OpenTelemetry records. They average 2,335 bytes as NDJSON, similar in width to OTel logs but with many
  integer columns.
- Warm-up: the first 50 bodies of partition `h3` (488,010 rows, 1.2 GB), not measured.
- Measured phase: every body of `h0`, `h1`, `h2` (294 bodies, 3,000,000 rows, 7,003,920,236 bytes).
  `POST /v1/datasets/bench/tables/hits/insert`, one body per request, response is the ack.
  Ack latency is client side, from request start to the full response.
- Closed-loop runs (`full-*`): 8 workers send as fast as acks return. In a closed loop the ack
  latency follows from throughput (8 requests in flight, about 10,200 rows each), so p50 and
  throughput are not independent. The `rate90k-*` runs pace the offered load to 90,000 rows/s and
  isolate latency at equal throughput.
- After the measured phase `--seal-wait 180` waits up to 180 s for the hot tier to be sealed
  (`hot_files_left == 0`), then runs `SELECT count(*)`, then `cpu_end.json` is captured.
- smolquery settings (from the server log): `flush_max_bytes=32000000`, `flush_interval_ms=1000`,
  `encode_concurrency=12`, `write_pool_size=12`, `write_engine_threads=1`, `write_engine_memory_limit=2GB`,
  `seal_max_bytes=67108864`, `max_concurrent_seals=2`, `compact_engine_threads=7`,
  `merge_inputs_per_call=12`, `merge_engine_memory_limit=2GB`, `merge_describe_timeout_ms=120000`,
  `merge_staging_timeout_ms=120000`, `merge_copy_timeout_ms=300000`, store `Local`, zstd.
- Instrumentation: a local, uncommitted diff in smolquery (new `lib/smolquery/profile.ex`, plus small
  timers in `committer.ex`, `segments/writer.ex`, `segments/store/local.ex`, `hot_manifest.ex`,
  `application.ex`, `smolquery_api/errors.ex`) writes `prof/events.jsonl`: one `encode` event per flush with
  `spool_us`, `copy_us` (DuckDB `COPY`), `footer_us`, `stats_us`, `fsync_us`, `link_us`, `discard_us`,
  `put_total_us`, `task_us`, `bytes`, `rows`; `commit` events; `seal_attempt` and `seal_segment`
  events; `mem` events (`erlang:memory()` once per second); `start` and `stop` marks that include
  `memory_peak_sampled` (peak of `erlang:memory(total)` sampled every 200 ms since `start`). The
  instrumentation is not part of this PR.
- Per-thread CPU: `harness/threadcpu.c` (macOS `proc_pidinfo`), called at the window start, the window
  stop and the end of the run, and once per second inside the window (`samples.jsonl`).

### Runs

| group | runs | what |
|---|---|---|
| `full-erts-1..3` | 3 | erts, closed loop, 3,000,000 rows |
| `full-arinsal-patched-1..3` | 3 | closed loop |
| `full-arinsal-fast-1,3,4` | 3 | closed loop. `-2` crashed (below) |
| `crashed-arinsal-fast-2` | 1 | `direct_bif_light` abort, no result |
| `rate90k-{erts,arinsal-patched,arinsal-fast}` | 3 | offered load 90,000 rows/s, no seal wait |
| `idle-{erts,arinsal-patched,arinsal-fast}` | 3 | boot, create the table, 30 s idle |

The closed-loop rounds were interleaved by `harness/matrix.sh` (erts, patched, fast per round). The
fast runs are numbered 1, 3, 4 because run 2 crashed. `full-arinsal-fast-4` is not in `matrix.log`
and its seal wait was shorter (4.8). The throughput and latency numbers in `logs/matrix.log` agree with the ones
recomputed here from `load.json` and `latencies_ms.json` for all 8 runs that appear in it.

### How to reproduce

The scripts in `harness/` read the ingest-profile directory from the environment variable `IP`
(set it before running them, for example `export IP=<dir>`); the benchmark credentials in
`harness/server.sh` and the `Bearer bench` header are placeholders for a local run. The raw results (7 MB) are not committed; `analyze.py` reads them
from `--results`.

```sh
# 1. data: ClickBench hits_0..3.parquet -> NDJSON -> bodies
mix run --no-start harness/prep/convert.exs hits_N.parquet hits_N.ndjson   # in the smolquery worktree
python3 -I harness/prep/split.py hits_N.ndjson data/bodies/hN hN 24000000

# 2. runtimes: erts is the Homebrew OTP 29.1 on PATH; Arinsal builds are shimmed
git -C arinsal checkout e49d55f && git apply patches/patches-compat.diff patches/patches-threadnames.diff
cargo build --release -p arinsal-cli        # bin/patched/arinsal (harness/build-arinsal-patched.sh)
git apply patches/patches-fastcopy.diff && cargo build --release -p arinsal-cli   # bin/fast/arinsal

# 3. closed-loop rounds, 3 rounds interleaved (results/full-<runtime>-<round>/)
harness/matrix.sh 3 erts arinsal-patched arinsal-fast
# 4. offered load 90,000 rows/s (one run per runtime)
harness/run.sh <runtime> rate90k-<runtime> --warmup h3:50 --measure h0,h1,h2 --rate 90000
# 5. idle memory
harness/idle.sh <runtime> idle-<runtime> 30
# 6. summaries
python3 -I experiments/perf/smolquery_ingest/analyze.py --results <results dir> --logs <logs dir>
```

`harness/server.sh <erts|arinsal-patched|arinsal-fast> <data_dir> [mix_env]` starts smolquery in the
foreground and is what `run.sh` uses. `analyze.py` is Python 3 standard library only; run it with
`python3 -I`. It also cross-checks the numbers against `logs/matrix.log`.

## 3. Results

Conventions: `n (min to max)` is median and range over runs of the same configuration. "Window" is the
measured phase (erts 7.6 to 7.9 s, `arinsal-fast` 11 to 12 s, `arinsal-patched` 28 s for the same
3,000,000 rows). CPU is user plus system seconds of the whole process, split by thread name class:
normal schedulers are `erts_sched_N` / `N_scheduler`, dirty CPU `erts_dcpus_N` /
`N_dirty_cpu_scheduler`, dirty IO `erts_dios_N` / `N_dirty_io_scheduler`, poll is `erts_poll_N` /
`arinsal-check-io`, and "native unnamed" is every thread without a name (DuckDB, Polars; also the
erts main thread, which is idle). "Exited threads" is the process total minus the live threads at the
second snapshot. Footprint is macOS `phys_footprint` (resident plus compressed), which is the number
to compare; RSS also counts clean and reclaimable pages.

### 3.1 Ingest rate and ack latency

Per run:

| run | rows/s | NDJSON MiB/s | ack p50 ms | ack p99 ms | warm-up rows/s | Bandit timeouts | seal attempts ok/error | hot files left after wait |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| full-erts-1 | 390287 | 869 | 167 | 324 | 373017 | 0 | 2/0 | 0 |
| full-erts-2 | 395162 | 880 | 167 | 374 | 366900 | 0 | 2/0 | 0 |
| full-erts-3 | 379627 | 845 | 177 | 364 | 311237 | 0 | 1/2 | 150 |
| full-arinsal-patched-1 | 105817 | 236 | 767 | 1093 | 94014 | 65 | 0/1 | 226 |
| full-arinsal-patched-2 | 105546 | 235 | 765 | 1090 | 86930 | 58 | 0/1 | 222 |
| full-arinsal-patched-3 | 107381 | 239 | 756 | 1199 | 93368 | 52 | 0/1 | 225 |
| full-arinsal-fast-1 | 267976 | 597 | 287 | 470 | 219407 | 56 | 0/1 | 268 |
| full-arinsal-fast-3 | 241333 | 537 | 310 | 556 | 212424 | 69 | 0/1 | 265 |
| full-arinsal-fast-4 | 254917 | 568 | 305 | 479 | 210618 | 34 | 0 | 269 |
| rate90k-erts | 89965 | 200 | 94 | 135 | 286793 | 0 | 1/0 | n/a |
| rate90k-arinsal-patched | 89120 | 198 | 489 | 736 | 92256 | 10 | 0 | n/a |
| rate90k-arinsal-fast | 89720 | 200 | 222 | 346 | 220223 | 12 | 0 | n/a |

Per configuration, closed loop (3,000,000 rows each):

| config | n | rows/s | ack p50 ms | ack p99 ms | warm-up rows/s | Bandit timeouts |
|---|---:|---:|---:|---:|---:|---:|
| erts | 3 | 390,287 (379,627–395,162) | 167 (167–177) | 364 (324–374) | 366,900 (311,237–373,017) | 0 |
| arinsal-patched | 3 | 105,817 (105,546–107,381) | 765 (756–767) | 1,093 (1,090–1,199) | 93,368 (86,930–94,014) | 58 (52–65) |
| arinsal-fast | 3 | 254,917 (241,333–267,976) | 305 (287–310) | 479 (470–556) | 212,424 (210,618–219,407) | 56 (34–69) |

Per configuration, offered load 90,000 rows/s (one run each):

| config | n | rows/s | ack p50 ms | ack p99 ms | Bandit timeouts |
|---|---:|---:|---:|---:|---:|
| erts | 1 | 89,965 | 94 | 135 | 0 |
| arinsal-patched | 1 | 89,120 | 489 | 736 | 10 |
| arinsal-fast | 1 | 89,720 | 222 | 346 | 12 |

Warm-up rows/s is the first 488,010 rows into a cold process.

### 3.2 Per-flush breakdown

A flush is one `encode` task in smolquery's buffer: spool the accumulated bodies to a file, run
DuckDB `COPY` to Parquet, read the footer, run the stats query, fsync and link the segment, delete the
spool. Parts are medians over the flushes inside the window, so they do not add to the median task.
The share in parentheses is the part's mean over the mean task, which does add to 100%; the heavy
tail of `footer row count` (a few flushes of 100 ms or more) is why its mean is much larger than its
median. In erts the median `COPY` is 105.8 ms of a 148.2 ms median task (71%).

Closed loop, flush size and the parts:

| config | n | flushes in window | rows/flush (median) | NDJSON MiB/flush | segment MiB/flush | bodies/flush | task ms (median) |
|---|---:|---:|---:|---:|---:|---:|---:|
| erts | 3 | 151 (150–154) | 20,440 (20,439–20,452) | 45.8 (45.8–45.8) | 2.0 (1.9–2.0) | 2.0 | 148.2 (146.9–153.4) |
| arinsal-patched | 3 | 193 (191–194) | 18,477 (18,469–19,953) | 45.8 (45.8–45.8) | 1.6 (1.5–1.6) | 2.0 | 587.5 (573.1–591.6) |
| arinsal-fast | 3 | 230 (230–231) | 10,522 (10,455–10,542) | 22.9 (22.9–22.9) | 1.3 (1.3–1.3) | 1.0 | 121.0 (114.5–141.4) |

| part: median ms / mean ms (share of mean task_us) | erts | arinsal-patched | arinsal-fast |
|---|---:|---:|---:|
| spool write | 5.6 / 6.5 (4.0%) | 456.4 / 348.7 (71.8%) | 7.5 / 10.3 (7.2%) |
| probe | 0.0 / 0.0 (0.0%) | 0.0 / 0.0 (0.0%) | 0.0 / 0.0 (0.0%) |
| DuckDB COPY | 105.8 / 110.0 (66.6%) | 96.4 / 91.8 (18.9%) | 71.3 / 83.1 (58.6%) |
| footer row count | 0.7 / 14.9 (9.0%) | 0.9 / 5.1 (1.1%) | 1.0 / 9.4 (6.5%) |
| stats query | 26.9 / 29.8 (17.7%) | 28.7 / 32.8 (6.8%) | 25.6 / 30.2 (22.1%) |
| Store.put fsync | 0.7 / 0.9 (0.6%) | 3.9 / 4.0 (0.8%) | 4.1 / 4.8 (3.5%) |
| Store.put link | 0.3 / 0.5 (0.3%) | 0.3 / 0.4 (0.1%) | 0.4 / 0.5 (0.3%) |
| Store.put other | 1.1 / 2.2 (1.4%) | 1.0 / 1.7 (0.4%) | 1.0 / 1.1 (0.8%) |
| spool delete | 1.0 / 1.2 (0.7%) | 0.5 / 0.6 (0.1%) | 0.6 / 0.8 (0.5%) |
| other in task | 0.0 / 0.0 (0.0%) | 0.1 / 0.1 (0.0%) | 0.1 / 0.1 (0.1%) |
| **task_us (whole flush)** | **148.2 / 166.4** | **587.5 / 485.5** | **121.0 / 141.8** |

The three configurations do not flush the same amount of data (erts and `arinsal-patched` hand 2
bodies to a flush, `arinsal-fast` 1). Per NDJSON MiB:

| ms per NDJSON MiB of the flush (median over flushes) | erts | arinsal-patched | arinsal-fast |
|---|---:|---:|---:|
| whole task | 3.27 | 14.05 | 4.61 |
| spool write | 0.13 | 10.10 | 0.30 |
| DuckDB COPY | 2.36 | 2.61 | 2.75 |
| stats query | 0.60 | 0.96 | 1.00 |

Per run:

| run | flushes | rows/flush | NDJSON MiB/flush | task ms | spool ms | COPY ms | stats ms | footer ms | spool delete ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| full-erts-1 | 151 | 20440 | 45.8 | 146.9 | 5.6 | 105.8 | 26.4 | 0.7 | 1.0 |
| full-erts-2 | 150 | 20452 | 45.8 | 148.2 | 5.5 | 105.7 | 27.1 | 0.7 | 1.0 |
| full-erts-3 | 154 | 20439 | 45.8 | 153.4 | 6.1 | 109.6 | 26.9 | 0.8 | 1.1 |
| full-arinsal-patched-1 | 194 | 18469 | 45.8 | 587.5 | 456.4 | 96.9 | 28.7 | 0.9 | 0.4 |
| full-arinsal-patched-2 | 191 | 19953 | 45.8 | 591.6 | 459.3 | 96.4 | 28.4 | 0.9 | 0.5 |
| full-arinsal-patched-3 | 193 | 18477 | 45.8 | 573.1 | 442.5 | 94.8 | 28.7 | 0.9 | 0.7 |
| full-arinsal-fast-1 | 230 | 10542 | 22.9 | 114.5 | 7.5 | 67.4 | 25.5 | 1.0 | 0.5 |
| full-arinsal-fast-3 | 230 | 10522 | 22.9 | 141.4 | 8.8 | 72.2 | 25.6 | 1.0 | 0.6 |
| full-arinsal-fast-4 | 231 | 10455 | 22.9 | 121.0 | 7.5 | 71.3 | 25.6 | 1.1 | 0.6 |
| rate90k-erts | 294 | 10229 | 22.9 | 73.8 | 2.6 | 50.9 | 16.4 | 0.6 | 0.5 |
| rate90k-arinsal-patched | 292 | 10230 | 22.9 | 333.2 | 231.2 | 64.8 | 25.9 | 0.9 | 0.5 |
| rate90k-arinsal-fast | 292 | 10230 | 22.9 | 95.0 | 6.2 | 59.2 | 20.9 | 0.8 | 0.5 |

Offered load 90,000 rows/s (same flush size in all three, 1 body):

| config | n | flushes in window | rows/flush (median) | NDJSON MiB/flush | segment MiB/flush | bodies/flush | task ms (median) |
|---|---:|---:|---:|---:|---:|---:|---:|
| erts | 1 | 294 | 10,229 | 22.9 | 1.0 | 1.0 | 73.8 |
| arinsal-patched | 1 | 292 | 10,230 | 22.9 | 1.0 | 1.0 | 333.2 |
| arinsal-fast | 1 | 292 | 10,230 | 22.9 | 1.0 | 1.0 | 95.0 |

| part: median ms / mean ms (share of mean task_us) | erts | arinsal-patched | arinsal-fast |
|---|---:|---:|---:|
| spool write | 2.6 / 2.8 (3.7%) | 231.2 / 232.7 (68.0%) | 6.2 / 6.3 (6.4%) |
| probe | 0.0 / 0.0 (0.0%) | 0.0 / 0.0 (0.0%) | 0.0 / 0.0 (0.0%) |
| DuckDB COPY | 50.9 / 51.1 (68.7%) | 64.8 / 69.5 (20.3%) | 59.2 / 61.8 (62.0%) |
| footer row count | 0.6 / 0.7 (0.9%) | 0.9 / 3.3 (1.0%) | 0.8 / 2.6 (2.6%) |
| stats query | 16.4 / 16.8 (22.6%) | 25.9 / 30.0 (8.8%) | 20.9 / 22.9 (23.0%) |
| Store.put fsync | 1.0 / 1.1 (1.4%) | 4.0 / 3.9 (1.2%) | 4.0 / 4.1 (4.1%) |
| Store.put link | 0.3 / 0.4 (0.5%) | 0.3 / 0.5 (0.2%) | 0.3 / 0.3 (0.3%) |
| Store.put other | 0.8 / 1.0 (1.4%) | 1.0 / 1.8 (0.5%) | 0.9 / 1.0 (1.0%) |
| spool delete | 0.5 / 0.5 (0.7%) | 0.5 / 0.5 (0.1%) | 0.5 / 0.5 (0.5%) |
| other in task | 0.0 / 0.0 (0.1%) | 0.1 / 0.1 (0.0%) | 0.1 / 0.1 (0.1%) |
| **task_us (whole flush)** | **73.8 / 74.3** | **333.2 / 342.4** | **95.0 / 99.7** |

| ms per NDJSON MiB of the flush (median over flushes) | erts | arinsal-patched | arinsal-fast |
|---|---:|---:|---:|
| whole task | 3.26 | 14.56 | 4.16 |
| spool write | 0.11 | 10.10 | 0.27 |
| DuckDB COPY | 2.24 | 2.83 | 2.59 |
| stats query | 0.72 | 1.13 | 0.92 |

### 3.3 CPU by thread class

Measured window, closed loop (3,000,000 rows):

| thread class | erts | arinsal-patched | arinsal-fast |
|---|---:|---:|---:|
| normal schedulers (erts_sched_N / N_scheduler) | 4.6 (4.5–5.1) s, 13% | 105.2 (102.1–105.5) s, 79% | 33.5 (32.7–34.4) s, 50% |
| dirty CPU (erts_dcpus_N / N_dirty_cpu_scheduler) | 0.0 (0.0–0.0) s, 0% | 0.2 (0.2–0.2) s, 0% | 0.2 (0.2–0.2) s, 0% |
| dirty IO (erts_dios_N / N_dirty_io_scheduler) | 26.4 (25.7–26.7) s, 68% | 20.0 (19.8–22.3) s, 15% | 21.7 (21.5–22.0) s, 33% |
| poll / check-io (erts_poll_N / arinsal-check-io) | 0.0 (0.0–0.0) s, 0% | 2.0 (1.8–2.5) s, 2% | 3.8 (3.6–4.2) s, 6% |
| arinsal-inet | 0.0 s, 0% | 4.8 (4.8–5.4) s, 4% | 6.6 (6.3–6.8) s, 10% |
| other runtime threads (aux, async, dispatch, main, arinsal-*) | 0.0 (0.0–0.1) s, 0% | 0.0 (0.0–0.0) s, 0% | 0.0 (0.0–0.0) s, 0% |
| native unnamed (DuckDB, Polars) | 8.0 (2.0–9.5) s, 20% | 0.1 (0.1–0.1) s, 0% | 0.1 (0.1–0.2) s, 0% |
| exited threads (process total minus live threads) | 0.0 (0.0–0.0) s, 0% | 0.0 (0.0–0.0) s, 0% | 0.0 (0.0–0.0) s, 0% |
| **total process CPU** | **39.4 (33.1–40.4) s** | **132.4 (131.3–133.4) s** | **66.3 (65.0–66.8) s** |

Measured window, offered load 90,000 rows/s (33 s):

| thread class | erts | arinsal-patched | arinsal-fast |
|---|---:|---:|---:|
| normal schedulers (erts_sched_N / N_scheduler) | 5.5 s, 6% | 108.4 s, 79% | 36.5 s, 39% |
| dirty CPU (erts_dcpus_N / N_dirty_cpu_scheduler) | 0.0 s, 0% | 0.2 s, 0% | 0.2 s, 0% |
| dirty IO (erts_dios_N / N_dirty_io_scheduler) | 51.4 s, 56% | 22.8 s, 17% | 22.3 s, 24% |
| poll / check-io (erts_poll_N / arinsal-check-io) | 0.0 s, 0% | 1.5 s, 1% | 17.9 s, 19% |
| arinsal-inet | 0.0 s, 0% | 4.9 s, 4% | 16.3 s, 17% |
| other runtime threads (aux, async, dispatch, main, arinsal-*) | 0.1 s, 0% | 0.0 s, 0% | 0.0 s, 0% |
| native unnamed (DuckDB, Polars) | 35.2 s, 38% | 0.1 s, 0% | 0.1 s, 0% |
| exited threads (process total minus live threads) | 0.0 s, 0% | 0.0 s, 0% | 0.0 s, 0% |
| **total process CPU** | **92.2 s** | **138.0 s** | **93.4 s** |

Total CPU per configuration, split into pre-window (boot, schema, warm-up), window and the time after
the window (seal wait, count query):

| config | n | pre-window s | window s | window cores | window s per 1M rows | after-window s | lifetime s |
|---|---:|---:|---:|---:|---:|---:|---:|
| erts | 3 | 8.3 (8.1–8.8) | 39.4 (33.1–40.4) | 5.11 (4.30–5.18) | 13.1 (11.0–13.5) | 150.3 (148.9–155.9) | 199.6 (190.3–203.5) |
| arinsal-patched | 3 | 27.6 (27.5–27.9) | 132.4 (131.3–133.4) | 4.70 (4.66–4.70) | 44.1 (43.8–44.5) | 213.1 (207.7–326.6) | 374.1 (368.0–485.4) |
| arinsal-fast | 3 | 15.9 (15.8–15.9) | 66.3 (65.0–66.8) | 5.63 (5.37–5.81) | 22.1 (21.7–22.3) | 228.8 (96.1–237.0) | 311.6 (178.4–317.8) |

| config | n | pre-window s | window s | window cores | window s per 1M rows | after-window s | lifetime s |
|---|---:|---:|---:|---:|---:|---:|---:|
| erts | 1 | 8.7 | 92.2 | 2.76 | 30.7 | 3.2 | 104.2 |
| arinsal-patched | 1 | 28.0 | 138.0 | 4.10 | 46.0 | 7.9 | 173.8 |
| arinsal-fast | 1 | 15.9 | 93.4 | 2.79 | 31.1 | 8.1 | 117.4 |

Per run:

| run | pre-window CPU s | window CPU s | window wall s | window cores | window CPU s per 1M rows | after-window CPU s | after wall s | after cores | lifetime CPU s (cpu_end.json) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| full-erts-1 | 8.3 | 33.1 | 7.7 | 4.30 | 11.03 | 148.9 | 124 | 1.20 | 190.3 |
| full-erts-2 | 8.1 | 39.4 | 7.6 | 5.18 | 13.13 | 155.9 | 125 | 1.25 | 203.5 |
| full-erts-3 | 8.8 | 40.4 | 7.9 | 5.11 | 13.46 | 150.3 | 182 | 0.83 | 199.6 |
| full-arinsal-patched-1 | 27.6 | 133.4 | 28.4 | 4.70 | 44.47 | 213.1 | 187 | 1.14 | 374.1 |
| full-arinsal-patched-2 | 27.9 | 132.4 | 28.4 | 4.66 | 44.14 | 207.7 | 182 | 1.14 | 368.0 |
| full-arinsal-patched-3 | 27.5 | 131.3 | 27.9 | 4.70 | 43.77 | 326.6 | 182 | 1.79 | 485.4 |
| full-arinsal-fast-1 | 15.8 | 65.0 | 11.2 | 5.81 | 21.67 | 237.0 | 185 | 1.28 | 317.8 |
| full-arinsal-fast-3 | 15.9 | 66.8 | 12.4 | 5.37 | 22.27 | 228.8 | 186 | 1.23 | 311.6 |
| full-arinsal-fast-4 | 15.9 | 66.3 | 11.8 | 5.63 | 22.11 | 96.1 | 68 | 1.42 | 178.4 |
| rate90k-erts | 8.7 | 92.2 | 33.4 | 2.76 | 30.74 | 3.2 | 1 | 3.55 | 104.2 |
| rate90k-arinsal-patched | 28.0 | 138.0 | 33.7 | 4.10 | 45.99 | 7.9 | 3 | 2.44 | 173.8 |
| rate90k-arinsal-fast | 15.9 | 93.4 | 33.4 | 2.79 | 31.12 | 8.1 | 3 | 2.42 | 117.4 |

Whole-process lifetime (`cpu_end.json`), closed loop. This includes the seal wait, during which erts
merges and Arinsal retries a merge that does not finish, so it is not a like-for-like number:

| thread class | erts | arinsal-patched | arinsal-fast |
|---|---:|---:|---:|
| normal schedulers (erts_sched_N / N_scheduler) | 12.2 (12.2–17.4) s, 6% | 159.7 (156.1–160.4) s, 43% | 79.9 (58.3–81.1) s, 26% |
| dirty CPU (erts_dcpus_N / N_dirty_cpu_scheduler) | 0.5 (0.5–0.7) s, 0% | 10.9 (10.6–11.2) s, 3% | 16.7 (6.1–17.7) s, 5% |
| dirty IO (erts_dios_N / N_dirty_io_scheduler) | 80.8 (78.5–95.5) s, 42% | 27.7 (27.5–148.1) s, 7% | 29.8 (27.5–41.1) s, 13% |
| poll / check-io (erts_poll_N / arinsal-check-io) | 0.0 (0.0–0.0) s, 0% | 93.5 (91.8–94.3) s, 25% | 97.5 (46.6–101.9) s, 31% |
| arinsal-inet | 0.0 s, 0% | 67.5 (64.9–70.9) s, 18% | 70.6 (34.4–72.1) s, 23% |
| other runtime threads (aux, async, dispatch, main, arinsal-*) | 0.1 (0.1–0.2) s, 0% | 0.1 (0.1–0.1) s, 0% | 0.1 (0.1–0.1) s, 0% |
| native unnamed (DuckDB, Polars) | 89.3 (74.2–104.4) s, 47% | 0.7 (0.6–0.8) s, 0% | 0.8 (0.5–0.8) s, 0% |
| exited threads (process total minus live threads) | 7.7 (7.5–11.5) s, 4% | 9.9 (9.7–10.1) s, 3% | 9.6 (4.9–9.6) s, 3% |
| **total process CPU** | **199.6 (190.3–203.5) s** | **374.1 (368.0–485.4) s** | **311.6 (178.4–317.8) s** |

Lifetime, offered load 90,000 rows/s (no seal wait, so this is boot + warm-up + window + count):

| thread class | erts | arinsal-patched | arinsal-fast |
|---|---:|---:|---:|
| normal schedulers (erts_sched_N / N_scheduler) | 8.4 s, 8% | 133.1 s, 77% | 49.0 s, 42% |
| dirty CPU (erts_dcpus_N / N_dirty_cpu_scheduler) | 0.0 s, 0% | 0.3 s, 0% | 0.3 s, 0% |
| dirty IO (erts_dios_N / N_dirty_io_scheduler) | 57.0 s, 55% | 27.1 s, 16% | 26.8 s, 23% |
| poll / check-io (erts_poll_N / arinsal-check-io) | 0.0 s, 0% | 3.5 s, 2% | 20.0 s, 17% |
| arinsal-inet | 0.0 s, 0% | 7.0 s, 4% | 18.5 s, 16% |
| other runtime threads (aux, async, dispatch, main, arinsal-*) | 0.1 s, 0% | 0.1 s, 0% | 0.1 s, 0% |
| native unnamed (DuckDB, Polars) | 36.3 s, 35% | 0.3 s, 0% | 0.3 s, 0% |
| exited threads (process total minus live threads) | 2.3 s, 2% | 2.4 s, 1% | 2.2 s, 2% |
| **total process CPU** | **104.2 s** | **173.8 s** | **117.4 s** |

After the window only (closed loop, seal wait of about 3 minutes):

| thread class | erts | arinsal-patched | arinsal-fast |
|---|---:|---:|---:|
| normal schedulers (erts_sched_N / N_scheduler) | 5.3 (5.2–9.7) s, 3% | 33.4 (33.1–34.3) s, 16% | 38.4 (15.1–38.7) s, 16% |
| dirty CPU (erts_dcpus_N / N_dirty_cpu_scheduler) | 0.5 (0.5–0.7) s, 0% | 10.7 (10.4–11.0) s, 5% | 16.5 (5.9–17.5) s, 7% |
| dirty IO (erts_dios_N / N_dirty_io_scheduler) | 50.3 (47.7–65.4) s, 34% | 3.7 (3.6–121.6) s, 2% | 3.5 (1.4–15.3) s, 2% |
| poll / check-io (erts_poll_N / arinsal-check-io) | 0.0 (0.0–0.0) s, 0% | 90.9 (89.9–92.2) s, 43% | 93.6 (42.9–97.7) s, 43% |
| arinsal-inet | 0.0 s, 0% | 62.1 (59.5–64.9) s, 29% | 63.1 (27.4–64.8) s, 28% |
| other runtime threads (aux, async, dispatch, main, arinsal-*) | 0.0 (0.0–0.1) s, 0% | 0.0 s, 0% | 0.0 s, 0% |
| native unnamed (DuckDB, Polars) | 87.1 (64.5–96.3) s, 58% | 0.5 (0.4–0.5) s, 0% | 0.4 (0.2–0.5) s, 0% |
| exited threads (process total minus live threads) | 6.1 (5.8–9.8) s, 4% | 8.2 (8.1–8.4) s, 4% | 8.0 (3.2–8.0) s, 3% |
| **total process CPU** | **150.3 (148.9–155.9) s** | **213.1 (207.7–326.6) s** | **228.8 (96.1–237.0) s** |

Busiest thread names in the window (digits replaced by N; `data/cpu_by_thread_name.csv` has all):

| config | thread name (digits -> N) | window CPU s, summed over threads |
|---|---|---:|
| erts | erts_dios_N | 26.4 (25.7–26.7) |
| erts | (unnamed) | 8.0 (2.0–9.5) |
| erts | erts_sched_N | 4.6 (4.5–5.1) |
| erts | erts_aux_N | 0.0 (0.0–0.1) |
| erts | erts_dcpus_N | 0.0 (0.0–0.0) |
| erts | erts_poll_N | 0.0 (0.0–0.0) |
| erts | erts_ssig_disp | 0.0 |
| erts | erts_smsg_disp | 0.0 |
| arinsal-patched | N_scheduler | 105.2 (102.1–105.5) |
| arinsal-patched | N_dirty_io_scheduler | 20.0 (19.8–22.3) |
| arinsal-patched | arinsal-inet | 4.8 (4.8–5.4) |
| arinsal-patched | arinsal-check-io | 2.0 (1.8–2.5) |
| arinsal-patched | N_dirty_cpu_scheduler | 0.2 (0.2–0.2) |
| arinsal-patched | (unnamed) | 0.1 (0.1–0.1) |
| arinsal-patched | arinsal-port-N | 0.0 (0.0–0.0) |
| arinsal-patched | main | 0.0 |
| arinsal-fast | N_scheduler | 33.5 (32.7–34.4) |
| arinsal-fast | N_dirty_io_scheduler | 21.7 (21.5–22.0) |
| arinsal-fast | arinsal-inet | 6.6 (6.3–6.8) |
| arinsal-fast | arinsal-check-io | 3.8 (3.6–4.2) |
| arinsal-fast | N_dirty_cpu_scheduler | 0.2 (0.2–0.2) |
| arinsal-fast | (unnamed) | 0.1 (0.1–0.2) |
| arinsal-fast | arinsal-port-N | 0.0 (0.0–0.0) |
| arinsal-fast | main | 0.0 |

### 3.4 Idle

Boot, create the table, 30 s idle. One run per runtime.

| config | idle footprint MiB | idle RSS MiB | after-boot footprint MiB | boot CPU s | CPU s while idle | idle interval s | idle cores | erlang:memory total MiB | processes MiB | ets MiB | atom MiB | threads |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| erts | 172 | 211 | 180 | 3.4 | 1.92 | 31 | 0.062 | 76 | 21 | 1.8 | 1.0 | 156 |
| arinsal-patched | 481 | 622 | 480 | 6.0 | 2.89 | 31 | 0.093 | 33 | 10 | 1.3 | 2.1 | 156 |
| arinsal-fast | 482 | 617 | 481 | 5.8 | 2.83 | 31 | 0.091 | 33 | 10 | 1.3 | 2.1 | 156 |

### 3.5 Memory under load

Peak footprint is the maximum of the 1 Hz samples taken inside the window; "lifetime max" is the
process-lifetime peak recorded by the kernel (warm-up, window, seal wait); "at end" is after the seal
wait and count query. The last column is `erlang:memory(total)` sampled every 200 ms inside the window.

| run | peak footprint in window MiB (1 Hz) | peak RSS in window MiB | lifetime max footprint MiB | footprint at end MiB | RSS at end MiB | erlang:memory total peak in window MiB (5 Hz) |
|---|---:|---:|---:|---:|---:|---:|
| full-erts-1 | 2885 | 3584 | 2997 | 375 | 3149 | 415 |
| full-erts-2 | 3130 | 3741 | 3166 | 406 | 3420 | 390 |
| full-erts-3 | 2560 | 3918 | 2638 | 1741 | 2979 | 423 |
| full-arinsal-patched-1 | 2001 | 3264 | 2350 | 2048 | 3421 | 520 |
| full-arinsal-patched-2 | 1839 | 3021 | 2205 | 1844 | 3144 | 630 |
| full-arinsal-patched-3 | 1900 | 3153 | 2172 | 1924 | 3347 | 471 |
| full-arinsal-fast-1 | 2418 | 3457 | 2783 | 2194 | 2637 | 616 |
| full-arinsal-fast-3 | 2205 | 2776 | 2495 | 2188 | 2813 | 602 |
| full-arinsal-fast-4 | 2088 | 3108 | 2358 | 2025 | 2442 | 633 |
| rate90k-erts | 2542 | 3745 | 2583 | 1832 | 3456 | 335 |
| rate90k-arinsal-patched | 1986 | 3180 | 2012 | 2012 | 3265 | 482 |
| rate90k-arinsal-fast | 1751 | 3065 | 1819 | 1740 | 3083 | 619 |

| config | n | peak footprint in window | peak RSS in window | lifetime max footprint | footprint at end | RSS at end | erlang:memory peak in window |
|---|---:|---:|---:|---:|---:|---:|---:|
| erts | 3 | 2,885 (2,560–3,130) | 3,741 (3,584–3,918) | 2,997 (2,638–3,166) | 406 (375–1,741) | 3,149 (2,979–3,420) | 415 (390–423) |
| arinsal-patched | 3 | 1,900 (1,839–2,001) | 3,153 (3,021–3,264) | 2,205 (2,172–2,350) | 1,924 (1,844–2,048) | 3,347 (3,144–3,421) | 520 (471–630) |
| arinsal-fast | 3 | 2,205 (2,088–2,418) | 3,108 (2,776–3,457) | 2,495 (2,358–2,783) | 2,188 (2,025–2,194) | 2,637 (2,442–2,813) | 616 (602–633) |

Offered load 90,000 rows/s:

| config | n | peak footprint in window | peak RSS in window | lifetime max footprint | footprint at end | RSS at end | erlang:memory peak in window |
|---|---:|---:|---:|---:|---:|---:|---:|
| erts | 1 | 2,542 | 3,745 | 2,583 | 1,832 | 3,456 | 335 |
| arinsal-patched | 1 | 1,986 | 3,180 | 2,012 | 2,012 | 3,265 | 482 |
| arinsal-fast | 1 | 1,751 | 3,065 | 1,819 | 1,740 | 3,083 | 619 |

`erlang:memory` peak per component in the 90,000 rows/s window (1 Hz `mem` events, MiB):

| config | total | processes | binary | ets | system | code | atom |
|---|---:|---:|---:|---:|---:|---:|---:|
| erts | 334 | 76 | 209 | 10 | 270 | 19 | 1 |
| arinsal-patched | 510 | 41 | 443 | 12 | 474 | 21 | 2 |
| arinsal-fast | 641 | 50 | 570 | 12 | 602 | 21 | 2 |

The two runtimes account `erlang:memory` differently (idle total 33 MiB on Arinsal against 76 MiB on
erts, while the process footprint is 481 against 172 MiB), so only changes within one runtime are
meaningful. Under load the binary component is 209 MiB on erts and 443 to 570 MiB on Arinsal.

### 3.6 Seals and Bandit timeouts

`seal attempts` counts `seal_attempt` events (one per finished attempt). Sealed segments and rows are
from `seal_segment` events. Bandit timeouts are lines
`[error] ** (Bandit.TransportError) Unrecoverable error: timeout` in `server.log`, counted per run
with the time of the first and last one in seconds after the start of the measured phase and the
size of each burst (errors less than 5 s apart).

| run | seal attempts | ok | error | sealed segments | sealed rows | sealed MiB | seal wait s | hot files left | Bandit timeouts | first, s after measure start | last | bursts | burst sizes |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| full-erts-1 | 2 | 2 | 0 | 2 | 3488010 | 360 | 118 | 0 | 0 | n/a | n/a | 0 | - |
| full-erts-2 | 2 | 2 | 0 | 2 | 3488010 | 360 | 123 | 0 | 0 | n/a | n/a | 0 | - |
| full-erts-3 | 3 | 1 | 2 | 1 | 538086 | 60 | 181 | 150 | 0 | n/a | n/a | 0 | - |
| full-arinsal-patched-1 | 1 | 0 | 1 | 0 | 0 | 0 | 185 | 226 | 65 | 56 | 244 | 6 | 12/12/10/9/12/10 |
| full-arinsal-patched-2 | 1 | 0 | 1 | 0 | 0 | 0 | 180 | 222 | 58 | 57 | 213 | 5 | 12/12/12/10/12 |
| full-arinsal-patched-3 | 1 | 0 | 1 | 0 | 0 | 0 | 181 | 225 | 52 | 57 | 213 | 5 | 10/10/10/10/12 |
| full-arinsal-fast-1 | 1 | 0 | 1 | 0 | 0 | 0 | 183 | 268 | 56 | 33 | 216 | 6 | 9/9/8/8/12/10 |
| full-arinsal-fast-3 | 1 | 0 | 1 | 0 | 0 | 0 | 184 | 265 | 69 | 33 | 216 | 6 | 12/12/12/12/11/10 |
| full-arinsal-fast-4 | 0 | 0 | 0 | 0 | 0 | 0 | 65 | 269 | 34 | 35 | 95 | 3 | 12/11/11 |
| rate90k-erts | 1 | 1 | 0 | 1 | 538081 | 60 | n/a | n/a | 0 | n/a | n/a | 0 | - |
| rate90k-arinsal-patched | 0 | 0 | 0 | 0 | 0 | 0 | n/a | n/a | 10 | 64 | 64 | 1 | 10 |
| rate90k-arinsal-fast | 0 | 0 | 0 | 0 | 0 | 0 | n/a | n/a | 12 | 32 | 32 | 1 | 12 |

Every seal attempt (`data/seal_attempts.csv`):

| run | attempt | result | segments | start, s after window start | duration s |
|---|---:|---:|---:|---:|---:|
| full-erts-1 | 1 | ok | 28 | 0.8 | 14.8 |
| full-erts-1 | 2 | ok | 148 | 15.6 | 110.9 |
| full-erts-2 | 1 | ok | 29 | 0.7 | 15.0 |
| full-erts-2 | 2 | ok | 147 | 15.7 | 114.3 |
| full-erts-3 | 1 | ok | 32 | 0.7 | 3.2 |
| full-erts-3 | 2 | error | 68 | 3.9 | 37.7 |
| full-erts-3 | 3 | error | 68 | 95.5 | 29.9 |
| full-arinsal-patched-1 | 1 | error | 36 | 1.7 | 143.7 |
| full-arinsal-patched-2 | 1 | error | 34 | 2.0 | 144.7 |
| full-arinsal-patched-3 | 1 | error | 35 | 1.9 | 144.8 |
| full-arinsal-fast-1 | 1 | error | 41 | 1.0 | 121.1 |
| full-arinsal-fast-3 | 1 | error | 38 | 0.9 | 122.3 |
| full-arinsal-fast-4 | - | no attempt finished | - | - | - |
| rate90k-erts | 1 | ok | 31 | 1.0 | 14.4 |
| rate90k-arinsal-patched | - | no attempt finished | - | - | - |
| rate90k-arinsal-fast | - | no attempt finished | - | - | - |

erts seal failures are of another kind: `full-erts-3` logged two
`Out of Memory Error: failed to allocate data of size 12.0 MiB (1.8 GiB/1.8 GiB used)` from DuckDB (the
2 GB merge engine limit), and `full-erts-1` could not run the final `count(*)`
(`database is locked`, the SQLite catalog). The other 11 runs counted 3,488,010 rows, which is the
488,010 warm-up rows plus the 3,000,000 measured rows, so no rows were lost on either runtime.

## 4. Findings

Code locations are in `arinsal-io/arinsal` at `e49d55f`, the commit the runs used.

### 4.1 `prim_file` write copies the payload bit by bit

- **Evidence.** Median spool write per flush: 5.6 ms (erts), 456.4 ms (`arinsal-patched`), 7.5 ms
  (`arinsal-fast`); 0.13, 10.10 and 0.30 ms per NDJSON MiB. 456 ms for a 45.8 MiB (48.0 MB) flush is 9.5 ns per
  byte. It is 72% of the flush task on `arinsal-patched` against 4% on erts. During the 28 s window
  `arinsal-patched` flushes 193 times, which makes 67.5 s of spool time, of the 105.2 s the normal
  schedulers spent. Per flush, the other parts match erts (COPY 96 against 106 ms, stats 29 against
  27 ms), so the spool write explains the difference between `arinsal-patched` (105,817 rows/s)
  and `arinsal-fast` (254,917 rows/s), a one-patch controlled change. It does not explain the
  remaining gap to erts (390,287 rows/s): `arinsal-fast` has a spool write of 7.5 ms against 5.6 ms
  on erts and is still at 65% of erts, see "What stays after the fix" below.
- **Code.** smolquery writes the spool file in raw mode (commit `af7ae2e`). In Arinsal
  `crates/nif-file/src/lib.rs:110-121` (`call`) converts every NIF argument with
  `arinsal_term::to_owned`, and the `TermKind::Bitstring` arm of `crates/term/src/owned.rs`
  (`:334-352`) copies a binary with `for i in 0..view.bit_len()` (`:339`), reading and writing one bit
  per iteration into a fresh `Vec`. The write then runs from that `Vec`, and the whole call runs on a
  normal scheduler (the normal scheduler CPU grows by the spool time, see the evidence above).
- **erts.** `write_nif_impl` (`erts/emulator/nifs/common/prim_file_nif.c:688`) takes the data with
  `enif_inspect_iovec` (`:694`), a reference to the binary, with no copy, and `write_nif` is a dirty
  IO NIF (`:182`). A separate micro-benchmark (`spool-bench/RESULTS.md`, 24 MiB binary, OTP 27.3.3)
  measures 4.2 ms for the whole write call on erts and 3.9 ms for Rust, which is page-cache copy speed.
- **Fastcopy patch.** The byte-aligned fast path (`patches/patches-fastcopy.diff`) reduces the spool
  write per MiB by 34 times (10.10 to 0.30 ms). It still takes 2.3 times as long as erts (0.30 against
  0.13 ms per MiB) because the payload is still copied once, which erts does not do. The real fix is T-PRIMFILE
  (iovec by reference, dirty IO scheduling).
- **What stays after the fix.** `arinsal-fast` is still at 65% of erts. Normal scheduler CPU in the
  window is 33.5 s against 4.6 s on erts for the same rows, and only 2.3 to 3.3 s of it is spool. The
  rest is outside the spool write; the data here does not say where (open question 3).

### 4.2 Where the CPU goes

- **erts** (window, 3,000,000 rows, 39.4 s): dirty IO 26.4 s (68%), native unnamed threads 8.0 s (20%,
  range 2.0 to 9.5 s), normal schedulers 4.6 s (13%). DuckDB runs inside the ADBC NIF on dirty IO
  threads. The `erts_poll_0` thread uses no measurable CPU.
- **`arinsal-fast`** (66.3 s): normal schedulers 33.5 s (50%), dirty IO 21.7 s (33%, comparable to
  erts), `arinsal-inet` 6.6 s (10%), `arinsal-check-io` 3.8 s (6%), native unnamed 0.1 s.
- **`arinsal-patched`** (132.4 s): normal schedulers 105.2 s (79%, of which 67.5 s is the spool write),
  dirty IO 20.0 s, `arinsal-inet` 4.8 s, `arinsal-check-io` 2.0 s.
- Dirty IO CPU is roughly the same in all three (20.0 to 26.4 s), so the DuckDB `COPY` and stats work
  costs about the same under both runtimes. The extra CPU is on normal schedulers (29 to 100 s more than erts)
  and in the two network threads.
- Native unnamed threads: erts 8.0 s (2.0 to 9.5), Arinsal 0.1 s. In the 90,000 rows/s run, where the
  seal completes inside the window on erts, it is 35.2 s against 0.1 s. The native threads' CPU
  follows the seal merge (DuckDB `compact_engine_threads=7`), which Arinsal never ran to completion.
  This data does not tie a thread to a query, so the split of that 8.0 s between `COPY` helpers and
  the merge is not measured.
- **`arinsal-check-io` and `arinsal-inet`.** In the window they use 0.06 to 0.09 and 0.17 to 0.19 cores
  on `arinsal-patched`, 0.31 to 0.34 and 0.54 to 0.59 cores on `arinsal-fast`. After the window they
  use 0.49 to 0.64 and 0.33 to 0.41 cores (0.82 to 1.05 together) in every closed-loop run for the whole
  seal wait: about 150 to 160 s of CPU in 182 to 187 s in the five runs with a full wait, 65 to 71 s of the
  `arinsal-check-io` time in the kernel. The whole idle Arinsal process uses 0.09 cores.
  Reading the code at `e49d55f`: `io_loop` (`crates/vm/src/inet_drv.rs:3435`) rebuilds the descriptor
  list from the whole socket registry on every wake-up, calls `try_io` on every socket before and
  after each wait, and waits through `check_io::wait_any_timeout` (`check_io.rs:193-290`), which sends
  one `Register` command per descriptor to the poll thread, wakes it and waits for its acknowledgement,
  then, after the wait, does the same for `Deregister` (`poll_loop`, `check_io.rs:319`). That is a
  cross-thread round trip per socket for every wake-up, plus two passes of `try_io` over all sockets.
  In erts, `erts_check_io` calls into the driver only for descriptors that are ready. This is a reading
  of the code, not a profile. T-INETCPU (progress log of the fix tasks, not measured here) lists three
  causes: (A) no `tcp_inet_output` flush on write readiness, (B) `io_loop` re-registers every
  descriptor on every event, which is the per-socket cost above, (C) the send queue is copied again on
  every write. Its standalone reproduction (a passive socket with queued send data and no pending
  recv) shows the sender blocked forever and the two threads at 5.3 s + 3.9 s CPU in 10 s, the same
  signature as the after-window spin here.

### 4.3 Seals never completed on Arinsal: the CPU and memory comparisons are biased

- **What happens.** Once the hot micro-segments reach `seal_max_bytes` (64 MiB; the first claims hold
  28 to 41 segments of about 2 MiB), smolquery's storage service seals them: one merge `COPY` in DuckDB (`lib/smolquery/storage_service/merge.ex`) reads the segments over `httpfs`
  from the buffer's own Bandit hot server (`lib/smolquery/buffer_service/hot_server.ex`: `HEAD`, then
  ranged `GET /v1/datasets/:d/tables/:t/segments/:id.parquet`), 12 inputs per call.
- **erts.** The first seal attempt starts 0.7 to 1.0 s into the window and takes 3.2 to 15.0 s for 28
  to 32 segments; in the two runs that finished, the second takes 111 and 114 s for 148 and 147
  segments. Those two closed-loop runs sealed everything (`hot_files_left = 0`) in 118 and 123 s, and
  `rate90k-erts` sealed 31 segments in 14.4 s inside its window. `full-erts-3` hit the DuckDB memory
  limit twice and sealed 538,086 rows (150 hot files left).
- **Arinsal.** The first (and only) attempt starts 0.9 to 2.0 s into the window and fails after 121 to
  145 s with `{:merge_failed, %Smolquery.Engine.CallExited{reason: :timeout}}`. That matches
  `merge_describe_timeout_ms=120000`. 222 to 269 hot files were left in every run. Every Arinsal run
  logs 34 to 69 `Bandit.TransportError ... timeout` errors (10 to 12 in the 33 s offered-load runs),
  as bursts of 8 to 12 errors roughly every 30 s, the first 32 to 64 s after the measured phase
  started; erts logs none. The burst size matches `merge_inputs_per_call=12` (up to 12 inputs per merge
  call). The failed `httpfs` requests are the most likely source of the Bandit errors; this is
  not proven by this data.
- **Context.** Before the experimental `enotsup` patch (the stopgap of PR #9) every segment response
  failed with `Bandit.TransportError ... exbadport` (`boot-ar7` to `-ar10`). With it the failure
  became timeouts: the response falls back to read-and-send in Elixir. Whether the fallback, the
  sockets, or DuckDB's `httpfs` is what stalls is not proven by this data. The fix tasks found a
  candidate: T-SENDFILE and T-INETCPU both reproduced, outside smolquery, queued send data on a passive
  socket that is never flushed on writable readiness (`try_io` only flushes inside a pull). A large
  segment response written through that path would never complete, which fits the Bandit read
  timeouts and the stuck merge. It has not been rerun against smolquery yet.
- **Why it biases the comparison.** In erts runs, window CPU includes a seal merge that is part way
  through and, at 90,000 rows/s, a finished one (DuckDB threads 35 s, DuckDB memory up to the 2 GB
  merge limit), and the lifetime CPU includes sealing all 3,488,010 rows (erts after-window CPU
  149 to 156 s, 137 s of it dirty IO and native threads). The Arinsal runs do none of that work, but
  spend the same time in the failed merge and the network threads (after-window CPU 208 to 237 s,
  327 s in `arinsal-patched-3`). Therefore:
  - erts' CPU and peak memory are overstated relative to a run in which Arinsal also seals;
  - Arinsal's CPU is understated by the cost of the seal merge itself, which is not known;
  - the like-for-like number is the ingest path alone (per-flush breakdown 3.2, spool 4.1), not
    the totals in 3.3 and 3.5.

### 4.4 Idle memory

- Idle footprint after boot and 30 s idle: erts 172 MiB, `arinsal-patched` 481 MiB, `arinsal-fast`
  482 MiB (+309 and +310 MiB); RSS 211 against 622 and 617 MiB (+411 and +406 MiB). Both have 156 threads. Idle CPU
  0.062 cores against 0.093 (about 2 to 3 s in 31 s).
- `erlang:memory(total)` is 76 MiB on erts and 33 MiB on Arinsal (processes 21 against 10, atom 1.0
  against 2.1), so the difference is in memory the VM does not account for. The data here does not
  break it down; a `vmmap` of both processes after boot would.
- Under load the peak footprint inside the window is 2,885 MiB (erts), 1,900 (`arinsal-patched`)
  and 2,205 (`arinsal-fast`), the opposite direction of idle; see the bias in 4.3 (erts merges with a
  2 GB DuckDB memory limit). RSS peaks are similar (3,108 to 3,741 MiB). At 90,000 rows/s the
  `erlang:memory` binary component is 2 to 2.7 times larger on Arinsal (443 to 570 against 209 MiB).

### 4.5 Crash: non-unwinding panic in `direct_bif_light`

`crashed-arinsal-fast-2` (the second `arinsal-fast` closed-loop run), 8.8 s into the measured window
and after 187 flushes (2,320,315 rows) the process aborted. The run's `cpu_end.json` is empty. Both panics are from the scheduler
thread `8_scheduler`; `data/crash_excerpt.txt` has the full frames.

```
thread '8_scheduler' panicked at crates/term/src/internal_hash.rs:404:26:
unsupported term kind in internal_hash: Invalid
   2: arinsal_term::internal_hash::internal_salted_hash   internal_hash.rs:404
   4: arinsal_ets::hash::ets_hash                         ets/src/hash.rs:31
   5: <arinsal_ets::Table>::insert                        ets/src/lib.rs:2514
   6: <arinsal_ets::Table>::update_counter_big            ets/src/lib.rs:3910
   7: arinsal_vm::natives::ets::call_inner               natives/ets.rs:2126
   9: arinsal_vm::natives::ets::direct_update_counter     natives/ets.rs:765
  12: arinsal_vm::native_helpers::call_direct_bif         native_helpers.rs:2367
  13: arinsal_vm::native_helpers::direct_bif_light        native_helpers.rs:1795
thread '8_scheduler' panicked at core/src/panicking.rs:225:5:
panic in a function that cannot unwind
  18: arinsal_vm::native_helpers::direct_bif_light        native_helpers.rs:1782
thread caused non-unwinding panic. aborting.
```

The defect is a use-after-free. The key term of an `ets:update_counter/4` (default object insert) hashes as `Invalid`
(a term whose tag is not a valid kind). The log alone does not say why; T-DIRECTBIF's root cause (from
its progress notes, [PR #12](https://github.com/arinsal-io/arinsal/pull/12)) is `update_counter` on an
`ordered_set` with `write_concurrency` (CA tree): `update_counter_big` keeps terms from a temporary
`StoredTerm` copy, a use-after-free, which its differential test reproduces on origin/main (every run of that test died). That
`direct_bif_light` is an `extern "C" fn` (`crates/vm/src/native_helpers.rs:1782`) turns the panic into an abort, but
this is not a second defect: per PR #12 the scheduler path also aborts the VM on a worker panic
(`abort_on_worker_panic`, `crates/vm/src/process.rs:7169-7183`), which is Arinsal's existing policy for ETS bodies. The driver kept retrying for
24 minutes (1,560 request errors, first disconnects, then `Connection refused`) until it was killed at
18:23. 1 of the 9 loaded Arinsal runs crashed (1 of 4 `arinsal-fast` closed-loop runs); no erts run
crashed. Owner: T-DIRECTBIF.

### 4.6 Literal-area heap scan panic

During boot attempts (`logs/boot-ar2.log`, `-ar6`, `-ar12`, `-ar13`):

```
thread '<unnamed>' panicked at crates/term/src/hamt.rs:48:18:
invalid boxed subtag 0x4
  <arinsal_term::heap::ProcessHeap>::has_heap_reference::<has_literal_area_roots::{closure#0}>
  arinsal_vm::natives::sys::has_literal_area_roots   natives/sys.rs:142
  arinsal_vm::natives::sys::copy_literal_area        natives/sys.rs:110
  <Process>::handle_signal                           process.rs:6056
```

The scan walks a smolquery process heap linearly (`has_literal_area_roots`,
`crates/vm/src/natives/sys.rs:141`) and meets a boxed word with subtag 4 that `boxed_object_words`
does not accept; that is the panic message. It happens while a process handles a literal-area copy
request (the experimental patch's comment names a `persistent_term` / literal-area release). The
experimental build replaces the scan with `heap = true`, so every process takes the collection path
(`rewrite_roots` and a full sweep) instead of being scanned; no boot after `boot-ar13`, and none of
the 15 measured and idle runs, shows it. The panic was observed and worked around; the root cause is
under investigation (T-LITAREA) and is not attributed to smolquery here. Which smolquery process
heap it scans, and why it holds a word the scan rejects, is not shown by these logs.
`data/literal_area_panic_excerpt.txt` has the frames.

### 4.7 Getting to a boot

The 17 boot attempts of the same session (`logs/boot-ar2..18.log`, 17:09 to 17:29) show what failed
in order; the patches in section 2 are what made them pass.

| log | symptom | related |
|---|---|---|
| `smoke-arinsal-1` | `:erlang.system_info(:system_architecture)`: "invalid system info item" | PR #10 |
| `boot-ar2`, `-ar3` | Phoenix.LiveReloader start: `ArgumentError argument error`; panic `invalid boxed subtag 0x4` | PR #6 (likely), T-LITAREA |
| `boot-ar4` | `Failed to load nif: {:bad_lib, "module Elixir.Adbc.Nif beam not found"}`, `Smolquery.Allocator` fails with `:not_loaded` | PR #7 |
| `boot-ar5` | `Smolquery.Allocator`: `SystemLimitError` | PR #11 (likely) |
| `boot-ar6`, `-ar12`, `-ar13` | boot succeeds then panic `invalid boxed subtag 0x4` | T-LITAREA |
| `boot-ar7` to `-ar10` | `Bandit.TransportError ... exbadport` on every segment response | PR #9 |
| `boot-ar14` | `Explorer.PolarsBackend.Native.df_from_arrow_stream_pointer/1 is undefined (module ... is not available)` | NIF table (PR #8, T-NIFSTUBS; likely) |
| `boot-ar15` | `database is locked` (DuckLake SQLite catalog), warm engine build crashed | also seen once on erts (`full-erts-1`), not Arinsal specific |
| `boot-ar16` to `-ar18` | no error lines | |

The attribution in the last column is from the patch comments and the PR descriptions. The logs do
not record which patch was active at each attempt.

### 4.8 Noise and variance

- **`arinsal-fast-4` CPU (178 s) against `-1` and `-3` (318 and 312 s): explained by run length.**
  All three have the same window CPU (65.0, 66.3 and 66.8 s) and pre-window CPU (15.8 to 15.9 s). The
  difference is the time after the window: `fast-4` waited 65.3 s for the seal against 183 and 184 s
  (`seal_wait.waited_s`; consistent with a 60 s seal wait, but the setting is not recorded: `fast-4`
  is not in `matrix.log`), and the after-window CPU is 96.1 s against 237.0 and 228.8 s, at 1.42, 1.28
  and 1.23 cores. Per second after the window the three are alike.
- **`arinsal-patched-3` lifetime CPU (485 s) against `-1` and `-2` (374 and 368 s): not explained.**
  Window and pre-window CPU are the same (131.3 against 133.4 and 132.4 s). After the window
  `-3` used 326.6 s against 213.1 and 207.7 s because one thread, `9_dirty_io_scheduler`, burned 117 s of
  user CPU (a dirty IO thread, not DuckDB's native threads); it happened in one run. No other run shows
  it (the dirty IO after-window CPU of `arinsal-fast` ranges from 1.4 to 15.3 s). The data does not say
  what that thread was doing.
- **erts lifetime CPU** (190 to 204 s) varies with the window CPU (33 to 40 s) and how far the seal
  got in the wait. `full-erts-1` has 6 to 7.5 s less native thread CPU in the window than the other two
  (2.0 against 8.0 and 9.5 s).
- **Throughput noise.** `arinsal-fast` ranges from 241,333 to 267,976 rows/s (11% between runs);
  erts from 379,627 to 395,162 (4%); `arinsal-patched` from 105,546 to 107,381 (2%). In a closed loop
  the p50 moves with it (`arinsal-fast`: 287 to 310 ms).
- **Footprint at the end of a run** is not stable on erts (375, 406 and 1,741 MiB): the macOS memory
  compressor and when DuckDB released its buffers decide it. Use the peak and lifetime maximum.
- All timings are from one machine, one session and 3 runs per configuration; there is no confidence
  interval beyond the range.

## 5. Fix PRs and tasks

| PR or task | problem | how it showed in smolquery | status |
|---|---|---|---|
| [#6](https://github.com/arinsal-io/arinsal/pull/6) `fix(ets)` | `ets:lookup_element/3` raised `badarg` for a present key in a `write_concurrency` set written only through shared paths; the table-level `max_arity` shortcut is not in erts | Elixir `Registry.lookup/2` returned `[]`, every `{:via, Registry, ...}` call failed | open |
| [#7](https://github.com/arinsal-io/arinsal/pull/7) `fix(nif)` | `load_nif` read `<M>.beam` from the boot paths instead of using the loaded module's `-nifs` | `Failed to load nif: {:bad_lib, "module Elixir.Adbc.Nif beam not found"}` (Mix adds deps with `code:add_paths`) | open |
| [#8](https://github.com/arinsal-io/arinsal/pull/8) `fix(nif)` | dynamic NIF table of 160 trampolines for all libraries; stopgap raising it to 1024 | the NIF count exceeded the 160-slot table (Explorer 436 + ADBC 30 + crypto about 100 exported stubs); the experimental build raised it to 1024 before booting | open; superseded by per-library NIF stubs (T-NIFSTUBS, in progress) |
| [#9](https://github.com/arinsal-io/arinsal/pull/9) `fix(inet)` | `TCP_REQ_SENDFILE` unknown, `file:sendfile/5` returned `exbadport`; stopgap answers `enotsup` so the caller reads and sends | every hot-tier segment response failed (`Bandit.TransportError ... exbadport`), DuckDB `httpfs` could not read unsealed data | open; superseded by the full `sendfile` port (T-SENDFILE, in progress) |
| [#10](https://github.com/arinsal-io/arinsal/pull/10) `fix(bifs)` | `system_info(system_architecture)` raised `badarg` | precompiled-NIF tooling (`rustler_precompiled`, `cc_precompiler`) could not pick a library | open |
| [#11](https://github.com/arinsal-io/arinsal/pull/11) `fix(bifs)` | `binary_part`, `split_binary`, `binary:part` on a resource binary raised `system_limit` | every DuckDB (ADBC Arrow) result decode failed | open |
| per-library NIF stubs (T-NIFSTUBS) | replaces the fixed trampoline table of #8 with per-library stubs as erts | see #8 | implemented on its branch, tests being written, no URL yet |
| full `sendfile` (T-SENDFILE) | native `HAVE_SENDFILE` port; its repro notes that queued send data on a passive socket is not flushed on writable readiness | see #9; part of the seal merge failure in 4.3 | in progress |
| `prim_file` iovec + dirty IO (T-PRIMFILE) | file NIFs copy binary arguments through `to_owned` bit by bit on a normal scheduler | spool 456 ms against 5.6 ms (4.1) | fixed on its branch (iovec by reference, dirty IO routing), no PR URL yet |
| literal-area heap scan (T-LITAREA) | `has_literal_area_roots` panics with `invalid boxed subtag 0x4`; root cause under investigation | panic observed and worked around in the experimental build (4.6) | in progress |
| [#12](https://github.com/arinsal-io/arinsal/pull/12) `direct_bif_light` panic (T-DIRECTBIF) | `ets:update_counter` on an `ordered_set` + `write_concurrency` table keeps terms from a temporary copy (use-after-free), and the resulting panic cannot unwind out of `extern "C" direct_bif_light` | crash of one run (4.5) | PR open |
| inet / check-io CPU and HTTP timeouts (T-INETCPU) | no `tcp_inet_output` flush on write readiness (sender blocks), `io_loop` re-registers every fd per event, send queue re-copied per write | `arinsal-check-io` and `arinsal-inet` at up to about 1 core while connections are stalled; Bandit timeouts that erts does not show (4.2, 4.3) | root causes found; first PR branch `fix/inet-tcp-output` has a failing-on-main test, no URL yet |

PR URLs that appeared in `PROGRESS.md` for tasks without a URL in the list above, at the time of writing: [#12](https://github.com/arinsal-io/arinsal/pull/12) (T-DIRECTBIF). No URL yet for T-NIFSTUBS, T-SENDFILE, T-PRIMFILE, T-LITAREA and T-INETCPU. Statuses of the in-progress tasks are from the progress log (19:36 to 19:49) and have not been re-verified here.

## 6. Open questions and next measurements

1. **Rerun after the fixes.** With T-PRIMFILE (no extra copy, dirty IO), T-SENDFILE, T-INETCPU and the NIF
   stubs merged, rerun `matrix.sh` and `rate90k` on a build without the compat patches. Target: spool
   at erts level (0.13 ms per MiB), `arinsal-check-io` and `arinsal-inet` near zero after the window.
2. **Equal-work memory and CPU with sealing working.** The seal must complete on Arinsal for the
   CPU and memory comparisons to mean anything. Wait for `hot_files_left == 0` on both and compare
   lifetime CPU, peak footprint and DuckDB memory.
3. **Where the remaining 29 s of normal-scheduler CPU goes** on `arinsal-fast` (33.5 s against 4.6 s
   on erts, after removing the spool): take a `sample` of the process during the window
   (macOS `sample`, as `sample-run.sh` of the original session did) and attribute it by function.
4. **Idle footprint.** A `vmmap` / heap breakdown after boot for both runtimes to find where the
   extra 309 MiB are.
5. **What `9_dirty_io_scheduler` did for 117 s** in `arinsal-patched-3`, and why only in that run.
6. **Crash frequency.** One crash in 9 loaded runs, now with a candidate cause (PR #12). Repeat 10 to 20
   runs of the fast configuration on a build with and without #12 to see whether the crash is gone.
7. **Linux.** All data is macOS (kqueue, `phys_footprint`). The inet / check-io costs and the
   `sendfile` path are platform specific; repeat on Linux arm64 and x86_64 (epoll, `sendfile(2)`).
8. **More runs.** n = 3 per configuration is enough to separate erts, `arinsal-fast` and
   `arinsal-patched`, not to measure a 5% difference. The offered-load runs (n = 1) need repeats at
   other rates (for example 150,000 and 250,000 rows/s) to find the rate where Arinsal's ack latency
   leaves its flat region.
9. **Instrumentation.** The smolquery timing patch (`profile.ex` and the timers) should be published
   as a branch so these runs can be repeated without recreating it.

## Files

| path | content |
|---|---|
| `analyze.py` | computes everything here from the raw results (stdlib only, `python3 -I`) |
| `data/runs.csv` | one row per run: throughput, latency, seals, timeouts, memory, CPU totals |
| `data/flush_breakdown.csv` | per run flush statistics (medians, means, shares, per-MiB values) |
| `data/cpu_by_class.csv`, `data/cpu_by_thread_name.csv` | CPU by thread class and by thread name for pre, window, after and lifetime scopes |
| `data/idle.csv` | idle runs |
| `data/seal_attempts.csv`, `data/crash_run.csv` | seal attempts, crash run summary |
| `data/summary_by_config.csv` | median, min and max per configuration for every metric |
| `data/tables.md` | every table in this document |
| `data/crash_excerpt.txt`, `data/literal_area_panic_excerpt.txt` | the two panic excerpts |
| `patches/` | the three experimental Arinsal diffs applied to `e49d55f` |
| `harness/` | the scripts that produced the runs (they read the ingest-profile directory from `$IP`) |
