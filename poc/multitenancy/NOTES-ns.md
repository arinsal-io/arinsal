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
  Destroy is idempotent. A racing spawn is refused by the scheduler-level close (see chunk 3).

## Chunk 3: cap, close, counters, info, list, processes/0, microbench
- `sched::NsCounters` (processes, reductions, `max_processes`, `closed`) is registered per ns with
  `Scheduler::ns_register(id, max_processes)`. `Inner::insert_process` takes one slot (`try_acquire`) before the
  table insert: a ns at its cap, or closed, gets `Error::SystemLimit`, which `erl_create_process` raises as
  `system_limit`. The slot is released once per process (`Process::release_ns`) from `mark_exited` and from the
  forced-exit path, so the count cannot leak or go negative. `try_acquire` re-checks `closed` after the
  increment, so a spawn racing `destroy` fails or is counted and then killed by destroy's scan.
- `destroy` closes the counters (via `NsTable::close`) before its scans.
- Reductions: `counters.add_reductions(consumed)` at slice accounting when the process has counters (one
  `Option` test at ns 0).
- `arinsal_ns:info/1` returns `#{tenant, project, processes, reductions, heap_words, max_processes, max_bytes}`;
  an unset cap is `infinity`, `heap_words` stays 0 until the heap accounting step. It also answers for a
  destroyed ns so its process count can be watched draining. `arinsal_ns:list/0` lists live ns ids.
- `erlang:processes/0` and `erts_internal:processes_next/1` show a ns process only the processes of its own
  ns (`Runtime::process_pids_visible`). `registered/0` is left to the names stream.
- Tests: ns_process_cap_system_limit, ns_destroy_closes_spawns, ns_info_counts, ns_list, ns_processes_filtered.

## Chunk 4: RootOnly natives, halt, group_leader
- List: `crates/vm/src/natives/root_only.rs` (`ROOT_ONLY` plus whole modules `erts_debug`, `erl_debugger`,
  `erts_trace_cleaner`, `erts_literal_area_collector`, `erl_ddll`). It names the lowest-level native of each
  feature, so the `erlang` wrappers (`halt/1`, `trace/3`, `open_port/2`, `suspend_process/1`, `system_monitor/2`,
  `os:cmd` through open_port, ...) end in it. Kept out on purpose: code loading natives (code-domain stream),
  `os:getenv/putenv` (env overlay, names stream), `erlang:statistics`/`system_info` (known gap), `display`.
- Error: `notsup`, the error OTP gives for a feature the node lacks. The check is one `p.ns != 0` test at
  each entry, so root pays nothing.
- Entries that must carry the check, all marked `// arl:`:
  1. `Vm::dispatch_native_source` (every native: static calls, apply fallback, JIT export dispatch).
  2. `bif_traps::execute_named` (trapping BIFs, e.g. `erts_debug:set_internal_state`, `erlang:halt/2`).
  3. `call_named_untraced` resolved-handler branch (apply of a signal handler such as
     `erts_internal:dirty_process_handle_signals`).
  4. JIT: `natives::process_bif` returns `None` for a root-only native, and `intern_identity` drops `bif` and
     `direct_ets` and the trap light entry for it, so native code never calls a root-only body directly.
  `natives::tests::root_only_natives_reach_the_dispatcher` checks every `ROOT_ONLY` entry is a listed native
  and not a light process BIF or ETS handler. Both the JIT and `ARINSAL_INTERP=1` pass the ns_core tests.
- `open_port` and the port natives were root only in this chunk; chunk 5 relaxed them to the inet drivers and
  own-namespace ports.
- `erlang:halt/0,1,2` from a namespace destroys that namespace (`destroy_namespace`: close, kill both scans) and
  ends the caller with `killed`; the node keeps running. `init:stop/0` from a ns sends to root `init`, which
  drops it; a ns-local init comes with the boot step.
- `group_leader(Leader, Pid)` from a ns: `badarg` when `Leader` is in another ns and not SHARED. Checked in
  `group_leader_call`, in the light self path (`group_leader_self_light` declines, the executor path refuses)
  and in the target's request handler (replies `{Ref, badarg}`). `spawn_opt(..., {group_leader, _})` is not
  checked yet.
- `catch erlang:ports()` and other calls the compiler knows cannot fail lose their `catch`; tests call them
  through `apply` with variables.

## Chunk 5: ports in a namespace, spawn_opt group_leader
- `PortHandle.arl_ns` is the namespace of the opener (taken from the owner pid in `make_handle`), so accepted
  sockets and other ports of a ns process carry it too.
- Open: from a ns, `open_port`/`erts_internal:open_port` accepts only `{spawn_driver, "tcp_inet" | "udp_inet" |
  "sctp_inet"}` (what `prim_inet:open` uses for gen_tcp, gen_udp, gen_sctp); everything else (`spawn`,
  `spawn_executable`, `fd`, other drivers, `os:cmd`) raises `notsup`. The port natives and `ports/0` left the
  root-only list; `port.rs` holds the policy (`arl_ns_may_open`, `arl_port_guard`, `arl_port_ns_ok`).
- Use: `port_command/control/call/close/connect/info/get_data/set_data` on a port of another namespace (and on
  port 0) answer like a missing port: `badarg`, `undefined` for `port_info`. `port_connect` to a pid of another
  ns is `badarg`. `Port ! Msg`, `exit(Port, _)` to a foreign port are dropped, `link(Port)` gives `noproc`,
  `monitor(port, P)` gives DOWN `noproc`. `erlang:ports/0` lists only the caller's ns (port 0 is root's).
  Root is unchanged.
- Port to owner messages are sent as the owner itself, so they pass the delivery check unchanged.
- gen_tcp on OTP 29 uses the inet driver (`inet_backend` default); the socket NIF (`prim_socket`) is a static NIF
  outside the native list, so it is not root-only, but its resources are not ns-tagged (they are unguessable
  refs, not ids). Revisit if a project selects `{inet_backend, socket}`.
- The kernel apps do not run in the test VM, so the echo test drives `prim_inet` directly (`inet_db` needs the
  application controller). A real project boot gets the usual `gen_tcp`.
- `spawn_opt(..., [{group_leader, L}])` is now parsed (it was `badarg` before) and refused with `badarg` for a
  foreign non-shared `L` from a ns. `spawn_request/5` options are not parsed for it.
- Tests: ns_port_tcp_listen_accept_in_ns, ns_port_cross_ns_refused, ns_ports_filtered,
  ns_port_spawn_driver_refused, ns_spawn_opt_group_leader_foreign.

## Chunk 6: narrower RootOnly
- `root_only()` is false for `module_info/0,1` of every module, so code loading, `code_server` and the module
  table can introspect a module even when the rest of its natives are root only.
- `erl_ddll` is no longer a whole-module entry: only `try_load/3`, `try_unload/2`, `monitor/2`, `demonitor/1` are
  root only; `info/2`, `loaded_drivers/0` and `format_error_int/1` read and stay open (kernel code calls `info`).
- Whole modules left: `erts_debug`, `erl_debugger`, `erts_trace_cleaner`, `erts_literal_area_collector`.
  `erts_internal` is an explicit list only (system_monitor, spawn_system_process, system_check,
  scheduler_wall_time, gather_*, trace*, suspend_process, process_flag/3, dirty_process_handle_signals,
  notify_breakpoint_hit, the dist entries). I grepped kernel and stdlib for `erts_internal:` calls
  (dynamic_node_name, get_dflags, get_creation, map_next, map_hashmap_children, map_to_tuple_keys, term_type,
  cmp_term, list_to_integer, beamfile_chunk): none of them is on the list; the listed ones are tracing, dist
  connection setup and statistics that a project does not run inside a namespace.
- Tests: `ns_rootonly_module_info_allowed` (module_info/0,1 of the covered modules, `erl_ddll` readers) and
  `poc/multitenancy/tests/ns_rootonly_e2e.sh`, which boots a node with the `arinsal` binary and, from a ns
  process (root's code_server, application_controller and friends exposed, root's persistent terms copied the way
  the boot does), calls `code:ensure_loaded/1` for a stdlib module that was not loaded yet, `application:load(sasl)`
  and `module_info(module)` of `erl_ddll`, `erts_debug`, `erts_internal`, `erl_debugger`. The in-process VM tests
  have no code_server, so this one needs the binary (`ARINSAL_BIN`, default `target-mt-ns/debug/arinsal`).
- Without root's persistent terms in the ns, `code:ensure_loaded` and a module autoload fail with `badarg` in
  `code_server:get_mode/0` (the per-namespace persistent_term store is empty). The boot copies them.

## Microbench at ns 0
`cargo run -r -p arinsal-sched --example bench -- <name>` (4 workers), 3 runs each on a busy machine, base is
8ee3755 (before this work), new is the branch head. ns/op, best of 3:

| bench | base | new |
|---|---|---|
| pingpong | 150.9 | 152.7 |
| ring | 81.5 | 82.4 |
| fanin 1000->1 | 76.1 | 71.2 |
| fanout 1->1000 | 108.5 (409.8, 419.6) | 301.3 (435.7, 459.0) |

pingpong, ring and fanin are within 1% to 7% noise. fanout is bimodal on this machine (about 110 or about 420
ns on either build), so its best-of-3 is not a comparison; the typical runs match (410 to 420 vs 436 to 459, a
few percent). No measurable cost at ns 0 from the `any_ns` load and the `Option` tests.

## Gaps
- Logger events from ns processes go to the root `logger` process by plain message and are dropped unless it is
  exposed (process.rs, sys.rs `ctx.send(logger, ..)`). Expose `logger`, or route them with `send_runtime`.
- Direct-state BIFs outside process_info (erl_debugger, erts_debug, trace) are not gated; they belong to the
  RootOnly step.
- `group_leader(Leader, Pid)` accepts a root `Leader`; only the request to the target is checked.

## Not in this chunk
Heap accounting (`heap_words`, `max_bytes`) and the RootOnly natives.

## Run
```
export CARGO_TARGET_DIR=/Users/sts/dev/sq/arinsal-prs/target-mt-ns
export PATH=/Users/sts/dev/sq/arinsal-prs/bin:/opt/homebrew/opt/erlang@29/bin:/opt/homebrew/opt/elixir/bin:$PATH
cargo test -p arinsal-vm --test ns_core
cargo test -p arinsal-sched --lib
```
