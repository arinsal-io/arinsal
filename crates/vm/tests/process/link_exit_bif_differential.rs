//! `link/1,2`, `unlink/1`, `exit/2,3` and `exit_signal/2,3` (bif.c `link_opt`, `unlink_1`,
//! `send_exit_signal_bif`) against erl: self, local, dead, port, trapping and alias targets, the
//! `exit/2` suicide cases, and the badarg/badopt/noproc errors with their `error_info`.

use arinsal_difftest::{CallResult, CompareMode, RefErl, compare};
use arinsal_vm::VmError;

const SOURCE: &str = r#"
-module(link_exit_bif).
-export([run/0]).

%% Runs in a fresh process: the caller's trap_exit and leftover messages stay out of it.
run() ->
    {P, R} = spawn_monitor(fun() -> exit({result, run1()}) end),
    receive {'DOWN', R, process, P, Reason} -> Reason after 10000 -> timeout end.

norm(T) when is_pid(T) -> pid;
norm(T) when is_port(T) -> port;
norm(T) when is_reference(T) -> ref;
norm(T) when is_list(T) -> [norm(E) || E <- T];
norm(T) when is_tuple(T) -> list_to_tuple(norm(tuple_to_list(T)));
norm(T) -> T.

catching(F) ->
    try F() of
        V -> {ok, V}
    catch C:R:St ->
        [{M, Fn, A, Info} | _] = St,
        {C, R, M, Fn, arity(A), proplists:get_value(error_info, Info)}
    end.

arity(A) when is_list(A) -> length(A);
arity(A) -> A.

msgs() -> receive X -> [norm(X) | msgs()] after 50 -> [] end.

dead() ->
    Dead = spawn(fun() -> ok end),
    R = monitor(process, Dead),
    receive {'DOWN', R, process, _, _} -> Dead end.

waiter() -> spawn(fun() -> receive stop -> ok end end).

%% Exit reason of a process that runs F, as seen by a monitor.
outcome(F) ->
    {P, R} = spawn_monitor(F),
    receive {'DOWN', R, process, P, Reason} -> norm(Reason) after 2000 -> timeout end.

run1() ->
    M = erlang,
    Dead = dead(),
    Port = open_port({spawn, "cat"}, []),
    Links = [
        {link_self, link(self())},
        {link_dead, catching(fun() -> link(Dead) end)},
        {link_dead_fresh, outcome(fun() -> exit(catching(fun() -> link(Dead) end)) end)},
        {link_dead_apply, catching(fun() -> M:link(Dead) end)},
        {link_bad, catching(fun() -> M:link(foo) end)},
        {link2_badopt, catching(fun() -> M:link(self(), [bad]) end)},
        {link2_improper, catching(fun() -> M:link(self(), [priority | x]) end)},
        {link2_prio, M:link(self(), [priority])},
        {link_dead_trap, outcome(fun() ->
            process_flag(trap_exit, true), R = link(Dead), exit({R, msgs()}) end)},
        {link_live, outcome(fun() ->
            W = waiter(), true = link(W), {links, L} = process_info(self(), links),
            true = unlink(W), {links, L2} = process_info(self(), links),
            exit({lists:member(W, L), L2}) end)},
        {link_port, outcome(fun() ->
            P = open_port({spawn, "cat"}, []), true = link(P), true = unlink(P),
            {links, L} = process_info(self(), links), port_close(P), exit(L) end)},
        {unlink_bad, catching(fun() -> M:unlink(foo) end)},
        {unlink_dead, unlink(Dead)},
        {unlink_remote_port, catching(fun() -> M:unlink(make_ref()) end)}
    ],
    Exits = [
        {exit_self_normal, outcome(fun() -> exit(self(), normal), exit(survived) end)},
        {exit_self_kill, outcome(fun() -> exit(self(), kill), exit(survived) end)},
        {exit_self_other, outcome(fun() -> exit(self(), boom), exit(survived) end)},
        {exit_self_trap_normal, outcome(fun() ->
            process_flag(trap_exit, true), exit(self(), normal), exit(msgs()) end)},
        {exit_self_trap_other, outcome(fun() ->
            process_flag(trap_exit, true), exit(self(), boom), exit(msgs()) end)},
        {exit_self_trap_kill, outcome(fun() ->
            process_flag(trap_exit, true), exit(self(), kill), exit(survived) end)},
        {exit_dead, M:exit(Dead, boom)},
        {exit_local_normal, outcome(fun() ->
            W = waiter(), R = monitor(process, W), true = exit(W, normal),
            W ! stop, receive {'DOWN', R, _, _, Why} -> exit(Why) end end)},
        {exit_local_kill, outcome(fun() ->
            W = waiter(), R = monitor(process, W), true = M:exit(W, kill),
            receive {'DOWN', R, _, _, Why} -> exit(Why) end end)},
        {exit_local_other, outcome(fun() ->
            W = waiter(), R = monitor(process, W), true = exit(W, boom),
            receive {'DOWN', R, _, _, Why} -> exit(Why) end end)},
        {exit_trapper, outcome(fun() ->
            Me = self(),
            W = spawn(fun() -> process_flag(trap_exit, true), Me ! ready,
                               receive X -> Me ! {got, X} end end),
            receive ready -> ok end,
            true = exit(W, boom),
            receive {got, X} -> exit(norm(X)) after 1000 -> exit(timeout) end end)},
        {exit_port, outcome(fun() ->
            P = open_port({spawn, "cat"}, []), process_flag(trap_exit, true),
            true = exit(P, boom), exit(msgs()) end)},
        {exit3_prio, catching(fun() -> M:exit(Dead, x, [priority]) end)},
        {exit3_badopt, catching(fun() -> M:exit(Dead, x, [bad]) end)},
        {exit_bad, catching(fun() -> M:exit(foo, x) end)},
        {exit_ref, catching(fun() -> M:exit(make_ref(), x) end)},
        {exit_signal2_self, outcome(fun() ->
            process_flag(trap_exit, true), true = M:exit_signal(self(), boom), exit(msgs()) end)},
        {exit_signal2_self_untrapped, outcome(fun() ->
            true = M:exit_signal(self(), normal), exit(survived) end)},
        {exit_signal3_badopt, catching(fun() -> M:exit_signal(self(), x, foo) end)},
        {exit_alias, outcome(fun() ->
            process_flag(trap_exit, true), A = alias(), true = exit(A, via_alias),
            exit(msgs()) end)}
    ],
    port_close(Port),
    {Links, Exits, msgs()}.
"#;

#[test]
fn link_exit_bifs_match_otp() {
    let reference = RefErl::start().expect("OTP 29.1.1");
    let beam = reference
        .compile_named("link_exit_bif", SOURCE, &[])
        .expect("compile differential");
    reference
        .load("link_exit_bif", &beam)
        .expect("load reference module");
    let expected = reference.call("link_exit_bif", "run", &[]);
    let mut vm = crate::common::node();
    vm.load_bytes(&beam).expect("load VM module");
    let actual = match vm.eval_scheduled("link_exit_bif", "run", &[], 2) {
        Ok(outcome) => CallResult::Ok(outcome.term),
        Err(VmError::Raised(raised)) => CallResult::Exception {
            class: format!("{:?}", raised.class).to_lowercase(),
            reason: raised.reason,
            stack_top: Some(raised.stack),
        },
        Err(error) => CallResult::TransportError(error.to_string()),
    };
    compare(&expected, &actual, CompareMode::Exact)
        .unwrap_or_else(|diff| panic!("link/exit BIFs differ: {diff}"));
}
