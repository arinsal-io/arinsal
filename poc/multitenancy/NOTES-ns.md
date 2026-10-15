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

## Findings for the other streams
- A request/reply from root to a namespace process hangs: the reply is a message from ns to root, which is
  refused unless the root caller is SHARED. Seen with `process_info(NsPid, links)` and
  `is_process_alive(NsPid)` from root. The manager must `expose` itself, and root code that queries ns
  processes must run in an exposed process (or the reply path needs an exemption).
- After a refused link the caller keeps its half of the link (as for a dead target). When the caller exits,
  an ExitLinked reaches the other namespace; the target has no matching link and ignores it (checked by
  `ns_link_cross_ns_noproc`, which sees the target survive).

## Not in this chunk
destroy, expose, info, list, process caps, counters, `processes/0` filter, microbench at ns 0.

## Run
```
export CARGO_TARGET_DIR=/Users/sts/dev/sq/arinsal-prs/target-mt-ns
export PATH=/Users/sts/dev/sq/arinsal-prs/bin:/opt/homebrew/opt/erlang@29/bin:/opt/homebrew/opt/elixir/bin:$PATH
cargo test -p arinsal-vm --test ns_core
cargo test -p arinsal-sched --lib
```
