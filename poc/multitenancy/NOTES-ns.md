# NOTES-ns: namespace word, delivery check, `arinsal_ns` core

## Done in this chunk
- `sched::Process.ns` (`AtomicU32`): low 31 bits ns id (0 is root), top bit `NS_SHARED`
  (crates/sched/src/ns.rs). The VM mirrors the id on `Process.ns`; `erl_create_process` inherits it.
- `Scheduler::spawn_unscheduled_in_ns(task, prio, scheduler_id, ns)`; the old spawn variants delegate with 0.
- `Inner.any_ns` (set by `Scheduler::ns_enable`, called by `arinsal_ns:create`). While false, delivery
  is unchanged apart from one relaxed load.
- Check (`Inner::ns_gate`): allowed when sender ns == receiver ns, sender is root, or receiver is SHARED.
  Refused: messages and exit signals are dropped, link, monitor, suspend and garbage_collect return noproc
  (a refused monitor bounces DOWN noproc through `bounce_monitors`).
  Not gated: signals that answer or undo an existing link or monitor, literal copies, sys tasks, dirty
  handler traffic, self sends and timers (a timer whose target is in a namespace the owner cannot reach is
  not armed).
- Where it runs: `Runner::deliver` (after the receiver lookup, covering the batch path),
  `publish_monitor`, `Inner::deliver_gated` (public `Scheduler::send/signal`, `native_send`).
  `Inner::deliver` stays unchecked and is only used for scheduler traffic.
- Sender ns comes from `RunCtx.ns` (borrowed from the running process); context-less callers
  (`signal_ordered`, `native_send`) look the sender up in the table, only when `any_ns` is set.
  A sender that is not in the table (a port) counts as root.
- Natives (crates/vm/src/natives/ns.rs): `arinsal_ns:create/2,3`, `spawn/4,5` (opt `{group_leader, Pid}`),
  `of/1` (`undefined` for a dead pid). Root only, `notsup` inside a namespace. Erlang needs `arinsal_ns:'of'(Pid)`.
  `create/3` stores `max_processes`/`max_bytes` but nothing enforces them yet.

## Chunk 2: replies, aliases, expose, destroy
- Runtime replies are not tenant traffic. `RunCtx::send_runtime` / `Scheduler::send_runtime` send a message that
  skips the check. Used for: replies to process_info, group_leader, garbage_collect, check_process_code and
  system-task requests (`reply_request`, `process_exiting`, system task `deliver`), the sync-suspend reply,
  literal-area copy replies and the wake of the literal collector.
- Requests are admitted at submit time instead: `submit_from` asks `Scheduler::ns_may_signal(requester, target)`
  and a refused request answers like a dead target. The direct process_info reads
  (`inspect_signal_free` paths in natives/proc.rs) ask the same. So root can query any ns process, a ns process
  can query only its own ns or SHARED processes, and the reply needs no sender rule.
- Aliases: `SignalMessage::via_alias()` (VM: `Message.alias != 0`); a message sent to an alias passes the check.
  `gen_server:call` from root to a ns gen_server works. Raw-pid sends ns to root are still refused.
- `try_send_on_heap` skips the receiver-heap fast path when the check refuses, so a refused sender never
  allocates on the receiver's heap.
- `arinsal_ns:expose/1` (root pid only, `badarg` otherwise) sets SHARED. `arinsal_ns:destroy/1` marks the entry
  dead, sends `kill` to every process of the ns (two scans) and returns `ok`; the processes exit asynchronously.
  Spawning into a dead ns raises `badarg` from `arinsal_ns:spawn`, `system_limit` for a child of a dying ns process.
  Destroy is idempotent. A spawn racing the second scan could in theory leave a child; the counters/cap step
  closes that at the scheduler.

## Gaps
- Logger events from ns processes go to the root `logger` process by plain message and are dropped unless it is
  exposed (process.rs, sys.rs `ctx.send(logger, ..)`). Expose `logger`, or route them with `send_runtime`.
- Direct-state BIFs outside process_info (erl_debugger, erts_debug, trace) are not gated; they belong to the
  RootOnly step.
- `group_leader(Leader, Pid)` accepts a root `Leader`; only the request to the target is checked.

## Not in this chunk
info, list, process caps, counters, `processes/0` filter, microbench at ns 0.

## Run
```
export CARGO_TARGET_DIR=/Users/sts/dev/sq/arinsal-prs/target-mt-ns
export PATH=/Users/sts/dev/sq/arinsal-prs/bin:/opt/homebrew/opt/erlang@29/bin:/opt/homebrew/opt/elixir/bin:$PATH
cargo test -p arinsal-vm --test ns_core
cargo test -p arinsal-sched --lib
```
