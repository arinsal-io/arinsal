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
