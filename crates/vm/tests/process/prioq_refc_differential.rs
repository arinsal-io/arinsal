//! Prio queue refcount differential cases against erl 29.1.1: the prio queue stays installed
//! while priority aliases, links and monitors exist (erl_proc_sig_queue.c
//! erts_proc_sig_prio_item_added / erts_proc_sig_prio_item_deleted); removing one of two
//! priority items keeps priority delivery, removing the last ends it, and priority messages
//! already queued stay ahead after the last item is gone. A monitor's `priority` option makes
//! its DOWN a priority message but not its alias, and a link's `priority` option applies only
//! to the linker's half.

use arinsal_difftest::{CallResult, RefErl};
use arinsal_term::Term;

const MODULE: &str = "prioq_refc_diff";
const SOURCE: &str = r#"
-module(prioq_refc_diff).
-export([all/0]).

run(S) ->
    Parent = self(),
    P = spawn(fun() -> Parent ! {self(), try scenario(S) catch C:E -> {C, E} end} end),
    receive {P, R} -> R after 5000 -> timeout end.

all() -> [{S, run(S)} || S <- [two_aliases, monitor_alias_not_prio, prio_monitors,
                               noproc_down, link_sides, link_option_change,
                               items_gone_queue_kept, reply_alias_once, exit_alias,
                               spawn_link_prio, selective_marker]].

flush() -> receive M -> [M | flush()] after 0 -> [] end.
%% Handle all pending signals without taking a message.
sync() -> receive '$never' -> ok after 0 -> ok end.

scenario(two_aliases) ->
    Self = self(),
    A1 = alias([priority]), A2 = alias([priority]),
    true = unalias(A1),
    Self ! n1, erlang:send(A2, p1, [priority]), erlang:send(A1, p0, [priority]),
    R1 = flush(),
    true = unalias(A2),
    Self ! n2, erlang:send(A2, p2, [priority]),
    R2 = flush(),
    A3 = alias([priority]),
    Self ! n3, erlang:send(A3, p3, [priority]),
    R3 = flush(),
    {R1, R2, R3, unalias(A3), unalias(A3)};
scenario(monitor_alias_not_prio) ->
    P = spawn(fun() -> receive stop -> ok end end),
    M = monitor(process, P, [{alias, demonitor}, priority]),
    self() ! a, erlang:send(M, b, [priority]),
    R = flush(),
    true = demonitor(M, [flush]), P ! stop,
    R;
scenario(prio_monitors) ->
    P1 = spawn(fun() -> receive stop -> ok end end),
    P2 = spawn(fun() -> receive stop -> ok end end),
    M1 = monitor(process, P1, [priority]),
    M2 = monitor(process, P2, [priority]),
    true = demonitor(M1),
    self() ! n1, P1 ! stop, P2 ! stop,
    timer:sleep(50),
    R1 = [case X of {'DOWN', M2, process, P2, normal} -> down2; _ -> X end || X <- flush()],
    P3 = spawn(fun() -> receive stop -> ok end end),
    self() ! n2, P3 ! stop, timer:sleep(50),
    R2 = [case X of {'DOWN', _, process, P3, normal} -> down3; _ -> X end || X <- flush()],
    {R1, R2};
scenario(noproc_down) ->
    P = spawn(fun() -> ok end), timer:sleep(20),
    self() ! n1,
    M = monitor(process, P, [priority]),
    [case X of {'DOWN', M, process, P, noproc} -> down; _ -> X end || X <- begin timer:sleep(20), flush() end];
scenario(link_sides) ->
    process_flag(trap_exit, true),
    Q = self(),
    P1 = spawn(fun() -> link(Q, [priority]), Q ! linked, receive go -> exit(boom) end end),
    receive linked -> ok end,
    Q ! a, P1 ! go, timer:sleep(50),
    R1 = [case X of {'EXIT', P1, boom} -> exit1; _ -> X end || X <- flush()],
    P2 = spawn(fun() -> receive go -> exit(boom) end end),
    true = link(P2, [priority]),
    Q ! b, P2 ! go, timer:sleep(50),
    R2 = [case X of {'EXIT', P2, boom} -> exit2; _ -> X end || X <- flush()],
    {R1, R2};
scenario(link_option_change) ->
    process_flag(trap_exit, true),
    P = spawn(fun() -> receive go -> exit(boom) end end),
    true = link(P, [priority]), true = link(P),
    self() ! a, P ! go, timer:sleep(50),
    R1 = [case X of {'EXIT', P, boom} -> exit; _ -> X end || X <- flush()],
    P2 = spawn(fun() -> receive go -> exit(boom) end end),
    true = link(P2, [priority]), true = unlink(P2), true = link(P2),
    self() ! b, P2 ! go, timer:sleep(50),
    R2 = [case X of {'EXIT', P2, boom} -> exit; _ -> X end || X <- flush()],
    P3 = spawn(fun() -> receive go -> exit(boom) end end),
    true = link(P3), true = link(P3, [priority]),
    self() ! c, P3 ! go, timer:sleep(50),
    R3 = [case X of {'EXIT', P3, boom} -> exit; _ -> X end || X <- flush()],
    {R1, R2, R3};
scenario(items_gone_queue_kept) ->
    Self = self(),
    A = alias([priority]),
    Self ! n1, erlang:send(A, p1, [priority]), erlang:send(A, p2, [priority]),
    sync(),
    true = unalias(A),
    Self ! n2,
    R1 = flush(),
    B = alias([priority]),
    Self ! n3, erlang:send(B, p3, [priority]),
    sync(),
    true = unalias(B),
    R2 = receive n3 -> got_n3 after 0 -> none end,
    R3 = flush(),
    C = alias([priority]),
    Self ! n4, erlang:send(C, p4, [priority]),
    R4 = flush(),
    {R1, R2, R3, R4, unalias(C)};
scenario(reply_alias_once) ->
    Self = self(),
    A = alias([reply, priority]),
    B = alias([priority]),
    Self ! n1, erlang:send(A, p1, [priority]), erlang:send(A, p2, [priority]),
    erlang:send(B, p3, [priority]),
    R1 = flush(),
    true = unalias(B),
    Self ! n2, erlang:send(B, p4, [priority]),
    {R1, flush(), unalias(A)};
scenario(exit_alias) ->
    process_flag(trap_exit, true),
    Self = self(),
    A = alias([priority]),
    Self ! n1, exit(A, r1, [priority]),
    R1 = [case X of {'EXIT', Self, R} -> {exit, R}; _ -> X end || X <- flush()],
    true = unalias(A),
    B = alias(),
    Self ! n2, exit(B, r2, [priority]),
    R2 = [case X of {'EXIT', Self, R} -> {exit, R}; _ -> X end || X <- flush()],
    {R1, R2};
scenario(spawn_link_prio) ->
    process_flag(trap_exit, true),
    P = spawn_opt(fun() -> receive go -> exit(boom) end end, [{link, [priority]}]),
    {P2, M} = spawn_opt(fun() -> receive go -> exit(boom2) end end, [{monitor, [priority]}]),
    self() ! a, P ! go, P2 ! go, timer:sleep(50),
    [case X of {'EXIT', P, boom} -> exit; {'DOWN', M, process, P2, boom2} -> down; _ -> X end
     || X <- flush()];
scenario(selective_marker) ->
    Self = self(),
    A = alias([priority]),
    Ref = make_ref(),
    Self ! n1, Self ! {Ref, n2},
    erlang:send(A, {Ref, p1}, [priority]),
    erlang:send(A, p2, [priority]),
    R1 = receive {Ref, X} -> X end,
    true = unalias(A),
    R2 = receive {Ref, Y} -> Y end,
    {R1, R2, flush()}.
"#;

#[test]
fn prioq_refc_cases_match_erl() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping prio queue refcount differential");
        return;
    };
    let beam = reference.compile_named(MODULE, SOURCE, &[]).unwrap();
    reference.load(MODULE, &beam).unwrap();
    let expected = reference.call(MODULE, "all", &[]);
    let mut vm = crate::common::node();
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled(MODULE, "all", &[] as &[Term], 4)
        .unwrap_or_else(|error| panic!("{MODULE}:all: {error}"));
    assert_eq!(expected, CallResult::Ok(actual.term));
}
