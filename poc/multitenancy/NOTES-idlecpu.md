# NOTES: idle CPU (stream `idlecpu`)

## Result

Idle CPU came from the dirty schedulers, not from the per-tenant timers. Fixed in
`crates/sched/src/lib.rs` (`dirty_scheduler_loop`).

## Numbers (`bench/idle_cpu.sh <shim> <tenants> 60 20`, `mix run`, MIX_ENV=prod)

Machine shared with other agents, load average 13 to 37 during the runs.

| setup | before | after |
|---|---|---|
| bare VM `-noshell -eval 'receive after infinity -> ok end'` | ~4400 ms/min (2.2 s in 30 s) | 0 ms in 30 s |
| bench/rest, RT_TENANTS=0 | 2250 ms/min | 330 ms/min |
| bench/rest, RT_TENANTS=1000 | 2740 ms/min | 420 ms/min |

ERTS reference (baseline stream, release): 60 ms/min at 0 tenants, 110 ms/min at 1000.
The remaining gap is one normal scheduler running the 100 timer wakeups/s (about 15 us each) and
noise from the loaded machine; the dirty and I/O threads no longer show up.

## Profile

`sample` on the bare VM: 22 threads (12 `dirty_cpu_scheduler`, 10 `dirty_io_scheduler`) each
sit in `park_timeout` and each wake ~1.3% of wall time in the spin loop
(`swtch_pri` from `thread::yield_now`). The 12 normal schedulers, check-io, udp, tty-select and
signal-dispatch threads are blocked. `ps -M` over 30 s: every dirty thread gains ~40 ms,
normal schedulers 0.

## Root cause

`dirty_scheduler_loop` (`crates/sched/src/lib.rs`, the sleep after the spin) used
`thread::park_timeout(100 ms)`. Every 100 ms each of the 22 dirty threads woke, took the pool
queue lock, left and re-entered the sleepers list and ran the full `SCHED_TSE_SLEEP_SPINCOUNT`
(10000 iterations, a `yield_now` every 100) spin again: 220 spin windows per second.

## ERTS behavior

`scheduler_wait` for a dirty scheduler has no timer: `timeout_time` is `ERTS_MONOTONIC_TIME_MAX`
and the `erts_tse_twait` timeout is -1, so the thread sleeps until `ssi` is set by a wake up
(enqueue, online change, multi-scheduling blocking change, halt/stop). The spin happens once per
wake, not once per 100 ms.

## Fix

Sleep with `thread::park()` in a loop that exits on `thread.wake`, `stopped` or
`halt_requested` (a spurious return does not restart the spin). All state changes that a dirty
thread must observe already call `wake_thread` (`enqueue_dirty`, `set_dirty_cpu_online`,
msb switch, halt, stop), so the timeout was not needed for correctness.

## Verification

- `cargo test -p arinsal-sched dirty`, `cargo test -p arinsal-vm --test dirty_sched --test
  dirty_nif --test dirty_signals`: pass.
- `poc/multitenancy/bench/idle_cpu.sh` reproduces the table (needs the `erl` shim dir).

## Not done

Normal schedulers with local timers use `park_timeout(10 ms)` on the suspended/blocked path
(`worker_loop`, around the `has_local_timers` branch). It is not hit when idle and was left alone.
`nearest_wait_ms` scans `pending_waits` linearly per sleep; only matters with many pending
receive timeouts.

## Step 2: residual profile (0 tenants, after the dirty fix)

Measured under load average 90 to 150, so absolute numbers are inflated; shares are what counts.

- Per-thread `ps -M` over 60 s: one thread gains 360 ms, all others 0. `sample` (1 ms) maps it to
  the last normal scheduler, the one owning the app's timers. 9% of its samples sit in the
  pre-sleep spin (`yield_now` -> `swtch_pri`), the rest in `park_timeout` (timer wakeups).
- So the residual is the cost of each scheduler wakeup, not a spin or a poll in other threads:
  dirty schedulers, check-io, udp, tty, signal-dispatch are all blocked.
- Cost per wakeup is the full pre-sleep spin: 10000 `std::hint::spin_loop()` iterations plus
  a yield every 100. On aarch64 `spin_loop` emits `isb`, which is far slower than a plain loop
  iteration.
- ERTS: the spin count is the same (10000 for the medium busy-wait setting), but the spin body
  (`ETHR_SPIN_BODY`) is `rep;nop` on x86 and only a compiler barrier on every other architecture
  including aarch64, so one spin window costs microseconds there.

## Step 3: what is left after the dirty fix (0 tenants: 330-400 ms/min vs ERTS 80)

Measured with `idle_cpu.sh` back to back, same load (18 to 68):

| runtime | 0 tenants | 1000 tenants |
|---|---|---|
| ERTS (Homebrew OTP 29, `mix run`) | 80 | 120 |
| Arinsal, dirty fix only | 400 | 370 |

Findings:

- The sleep spin is not the cost. Instrumented spin windows take 50 to 150 us of CPU each
  and only a few happen per second. `spin_body` now matches the ERTS spin body (pause on x86,
  compiler barrier elsewhere); it is a small change, not the fix.
- A scheduler wake that finds work costs 0.1 to 4 ms of CPU, but only ~1 wake/s on the timer
  owner. Dirty, check-io, udp, tty and signal-dispatch threads stay at 0.
- The remaining burst is periodic (every ~1.9 s, 10 ms ticks of sys time on a scheduler thread)
  and comes from `persistent_term:put/2` of a heap term. Bandit's `Bandit.Clock` does one such
  put per second to refresh the date header. Reproduced without the app:
  `persistent_term:put(k, {I, "text"})` once per second costs 230-260 ms/min on Arinsal and 90
  ms/min on ERTS; the same loop with an immediate term costs 10 ms/min, and a plain
  `erlang:garbage_collect()` per second costs 10 ms/min.
- So the cost is the literal area release that follows a replaced heap-term entry: the old area
  is retired and the literal collector sends `copy_literals` to every process
  (`crates/vm/src/natives/sys.rs` `wake_literal_collector`), which wakes all 12 schedulers once
  per put (per-worker wake counts over 20 s: 6 to 33 on every scheduler). ERTS touches the
  same processes but only a few schedulers show CPU.
- Tried and dropped: replacing the stop-the-world `block_thread_progress(ZERO)` in
  `PersistentTermUpdate::finish` with a suspended updater plus `thread_progress_later` (the
  ERTS shape, as `suspend_for_code_barrier` does). It is closer to ERTS but did not change the
  numbers (230 vs 240-260 ms/min), so it was not kept.

## Staged plan for the rest

1. Find why the literal collector round touches every scheduler on Arinsal but few on ERTS:
   check how many processes receive `Signal::LiteralAreaCopy` per retired area and whether a
   process that does not reference the area still gets scheduled (ERTS answers the request as
   a system task without a full run). Count wakes per scheduler with the pt.exs-style loop
   above.
2. If processes are spread over all run queues at boot while ERTS keeps them on a few, compare
   the migration paths after startup (`check_emigration_need`), since every idle process
   wakes its own scheduler.
3. Keep the `persistent_term:put` once-per-second loop as the regression benchmark (target
   within 1.5x of 90 ms/min).

## Step 4: persistent_term puts in namespaces

Repro: `poc/multitenancy/bench/ptloop.erl` (`ptloop:root/0`, `ptloop:ns/1`): a loop (`persistent_term:put(clock, {I, "..."})` once per second, via
`receive after 1000` since `timer:sleep` needs a root process); N namespaces from
`arinsal_ns:create/3` + `arinsal_ns:spawn/4`, one looping process each. Idle CPU over 60 s windows,
load average 6 to 15, alternating A/B runs.

Premise check: a namespace store has no collector. `crates/pterm/src/lib.rs` (`arl_keep_alive`)
keeps every retired area and old table alive, and the collector process only ever runs
`release_area_switch` on the node store. So a namespace put never starts a literal round over
all processes; there is nothing to scope with a namespace filter. Measured: root put 1/s costs
~150 ms/min, 100 namespaces at 1 put/s each cost ~300 ms/min before this change, i.e. ~3 ms/min per
put per second (about 50x cheaper than a root put). ERTS root reference: 90 ms/min.

What the namespace put still paid for: it sent `copy_literals` to the node collector for an area
the collector never looks at (the collector wakes, runs `release_area_switch` on the node store,
and blocks thread progress for nothing).

Change (`crates/vm/src/natives/sys.rs`, `PersistentTermUpdate::finish`): a namespace process
(`process.ns != 0`) no longer wakes the collector. Root behavior is unchanged.

| setup | before | after |
|---|---|---|
| 100 namespaces, 1 put/s each | 306 ms/min (280, 310, 330) | 83 ms/min (80, 70, 100) |
| root, 1 put/s | ~145 | unchanged (not touched) |

Root's cost is the literal round (collector -> signal to every process -> every scheduler
wakes), which ERTS also does, so it is not a local fix.

Tried and dropped: replacing the stop-the-world `block_thread_progress(ZERO)` in `finish` with
a suspended updater plus `thread_progress_later` (the shape `suspend_for_code_barrier` uses).
It gave no gain over the skip alone (103 vs 83 ms/min for 100 namespaces, no change at root)
so it was not kept.

Test note: `literal_gc::literals_stay_shared_across_spawn_send_and_copy_shared` (one scheduler) does
not finish on this branch. It also hangs with the sleep spin change and the dirty-scheduler
change both reverted and without the update-path change, so it is not caused by this stream;
`literal_gc` `applied_get_all...` and `dirty_bif_results...` pass.

Open findings:
- Leak: each namespace put retains ~750 bytes for the life of the node (RSS +8.9 MB for 12000 puts
  across 200 namespaces over 60 s). A clock refreshed once per second leaks ~65 MB/day per
  namespace. Releasing namespace areas needs a collection scoped to the namespace's processes
  (the filter asked for in step 1 belongs there, not on the node collector): when a namespace
  store retires an area, visit only that namespace's processes with `LiteralAreaCopy`, then
  free it. That is a feature, not a tweak; plan: per-store active area for namespace stores,
  a Rust-side round over `process_pids_visible(ns)`, acknowledgement through the existing
  `acknowledge_copied`.
- ERTS does not skip the schedule of a process that does not reference the area: the copy
  request is a signal that the process handles on its own scheduler (`proc_queue_signal` with
  the adjust-message-queue op), so a process that does not reference the area still gets
  scheduled. That part is the same as here.
- Not investigated: why the root round wakes 12 schedulers here and about 4 under ERTS.
