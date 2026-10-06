# Process and memory cost probes

Question: which current Arinsal paths account for slow allocation, process
lifecycle, messages, exceptions, references, and timers, and which small
alternatives are worth pursuing?

The `micro.erl` kernel is compiled once with OTP 29.1.1 and run unchanged by
both engines. Its timer starts a 60-second timer and cancels it immediately;
the linked spawn probe traps and receives the normal exit, while the monitor
probe waits for `DOWN`. `cons` and
`tuple` retain a nested value until the timed region ends. `gc_dead` builds
16,384 cons cells and requests GC per repeat; `gc_live` keeps a 16,384-cell
list rooted through every collection. The `gc_*` result divided by the CLI
argument is time per *iteration*, not per cons.

```sh
cargo build -p arinsal-cli --release
python3 experiments/perf/pf_mem/run.py
CARGO_TARGET_DIR="$PWD/target" cargo run --manifest-path experiments/perf/pf_mem/Cargo.toml --release --locked
```

The runner alternates order, uses three paired repetitions, prints medians,
and runs every Arinsal invocation under `timeout 300`. It compiles
`micro.beam` locally; the generated file is not part of the experiment source.
The Rust harness uses five internal repetitions and reports the median for
each component. Run it multiple times when the machine is busy.

Measured on Apple Silicon, OTP 29.1.1, Rust 1.98.1, 2026-09-26, this worktree:

| BEAM kernel | erts ns/op | Arinsal ns/op |
|---|---:|---:|
| cons, 100k | 17.2 | 195.7 |
| nested two-tuple, 100k | 28.6 | 214.5 |
| linked spawn and normal exit, 10k | 2,826 | 2,923 |
| spawn, monitor, DOWN, 1k | 2,541 | 4,166 |
| same monitor cycle, 10k | 2,452 | 9,847 |
| same monitor cycle, 30k | 2,427 | 31,439 |
| atom ping-pong, one worker, 10k | 1,656 | 1,182 |
| atom ping-pong, four workers, 10k | 485 | 1,225 |
| `gen_server:call`, four workers, 1k | 1,100 | 11,309 |
| `gen_server:call`, four workers, 10k | 1,002 | 17,701 |
| direct `try throw catch`, 10k | 55 | 3,394 |
| conditional throw through `maybe_throw`, 10k | 28 | 1,442 |
| same conditional path without a throw, 10k | 12 | 559 |
| `make_ref`, 10k | 10.0 | 414 |
| timer start/cancel, 1k | 192 | 1,081 |

The same Rust harness measured these current/prototype pairs (typical range
over four full runs; ns/op):

| Question | Current | Prototype |
|---|---:|---:|
| Checked bump and two writes vs local cursor | 3.1–3.7 | 2.5–2.8 |
| Tuple builder and three writes vs local cursor | 4.2–5.2 | 3.4–4.0 |
| 64-word eager heap vs zero-word lazy heap creation/drop | 33.4–34.2 | 5.9–8.0 |
| `Process::new()` vs compact cold record creation/drop | 428–485 | 4.2–4.3 |
| `HashMap` monitor insert/remove vs four inline slots | 49–53 | 1.7–1.8 |
| Live 1 MiB minor GC with graph sizing vs same collector without sizing pass | 1.50–2.24 ms | 0.77–1.03 ms |
| Retained receive-marker key plus full position scan vs key removal on bind, 10k | 19,401–19,897 | 38–41 |

The public `Process::new()` probe uses 1,024 X and FR slots, a 64-word initial
heap, and an 8,192-word policy minimum. Spawned children instead use
argument-sized registers and a zero-word initial heap, so this probe does not
measure their constructor cost.
The feature-gated counter inside their constructor measured 10,001 calls and
1.15–1.29 ms total during 10k linked spawn/exit cycles (~115–130 ns/call,
including clock read).
The compact record models only cold storage and omits dynamic register growth,
persistent-term registration and other process obligations; its ratio is an
upper bound on a local mechanism, not an expected integrated speedup. The inline
monitor model has capacity four and requires a fallback. The local cursor
prototype commits before any collection and is not a GC-safe VM change. The
one-thread mailbox primitive (`Incoming<u64>` push, detach, pop) measured
about 23–26 ns per item; it omits process lookup, envelope copying and wakeup.
The direct collector copied 1 MiB of live cons cells in roughly 1.5–1.6 ms
versus 0.006 ms when all cells were dead. Setting the policy minimum to the
already allocated 1 MiB avoids the `reachable_words` graph sizing pass in this
specific path. It does not itself establish a safe general sizing policy or
an RSS improvement. A later busy-host run shifted the live pair to 2.24 ms
versus 1.03 ms while retaining about a 2× ratio. Values fluctuate with shared
machine load and are diagnostic rather than project gate results.

The monitor diagnostic entry points `monitor_windows/2` and
`monitor_backlog/1` show growing per-window time despite zero queued messages
and zero active monitors. With `arinsal-vm/pf-mem-counters`, the VM reported
1,025 retained marker keys after 1,024 `DOWN`s and 9,217 after 9,216.
Exit-reason scans were zero. The `recv_marker_bind` path keeps its temporary
reserve key; `remove_message` scans all marker positions. The marker prototype
models this exact map lifetime and scan but is not an integrated VM patch.
For `gen_server:call`, the counter found 1,002 markers after 1,000 calls and
10,002 after 10,000 calls, with zero active monitors.

To reproduce the counters without enabling them in a normal build:

```sh
cargo build -p arinsal-cli --release --features arinsal-vm/pf-mem-counters
erlc -o experiments/perf/pf_mem experiments/perf/pf_mem/micro.erl
timeout 300 target/release/arinsal eval -pa experiments/perf/pf_mem --schedulers 1 micro monitor_windows 10 1000
```
