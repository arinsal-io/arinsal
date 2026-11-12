//! MSGQ-2 differential cases against erl 29.1.1: a garbage collection a process requests on
//! itself is a system task (erl_process.c request_system_task), not an inline collection; a
//! port DOWN with a non-immediate reason carries the monitor tag; `link/1,2` on a port it is
//! already linked to does not reach the port again (bif.c link_opt).

use arinsal_difftest::{CallResult, RefErl};
use arinsal_term::Term;
use arinsal_vm::Vm;

const MODULE: &str = "msgq2_diff";
const SOURCE: &str = r#"
-module(msgq2_diff).
-export([all/0]).

run(S) ->
    Parent = self(),
    P = spawn(fun() -> Parent ! {self(), try scenario(S) catch C:E -> {C, E} end} end),
    receive {P, R} -> R end.

all() -> [{S, run(S)} || S <- [gc_self_task, port_down_tag, port_link_twice]].

flush() -> receive M -> [M | flush()] after 0 -> [] end.

scenario(gc_self_task) ->
    R1 = make_ref(),
    async = erlang:garbage_collect(self(), [{async, R1}]),
    self() ! after1,
    A = flush(),
    self() ! before2,
    R2 = make_ref(),
    async = erlang:garbage_collect(self(), [{async, R2}, {type, minor}]),
    self() ! after2,
    B = flush(),
    R3 = make_ref(),
    ok = erts_internal:request_system_task(self(), inherit, {garbage_collect, R3, major}),
    self() ! after3,
    C = flush(),
    D = [receive {garbage_collect, R, V} -> {N, V} after 2000 -> {N, timeout} end
         || {N, R} <- [{gc1, R1}, {gc2, R2}, {gc3, R3}]],
    {A, B, C, D};
scenario(port_down_tag) ->
    F = fun(Tag, Kill) ->
        P = open_port({spawn, "cat"}, []), true = unlink(P),
        R = erlang:monitor(port, P, [{tag, Tag}]),
        Kill(P),
        receive {T, R, port, P, Reason} -> {T, Reason} after 2000 -> lost end
    end,
    [F(mytag, fun port_close/1),
     F({a, "b", <<"c">>}, fun(P) -> exit(P, {big, reason}) end),
     F(t3, fun(P) -> exit(P, kill) end)];
scenario(port_link_twice) ->
    Self = self(),
    Tracer = spawn(fun() ->
        T = fun Loop(Acc) -> receive {done, P} -> P ! {events, lists:reverse(Acc)}; M -> Loop([M | Acc]) end end,
        T([]) end),
    P = open_port({spawn, "cat"}, []),
    1 = erlang:trace(P, true, [ports, {tracer, Tracer}]),
    true = link(P), true = link(P), true = link(P, [priority]),
    true = link(P),
    1 = erlang:trace(P, false, [ports]),
    receive after 100 -> ok end,
    Tracer ! {done, Self},
    Ev = receive {events, E} -> [element(3, X) || X <- E] after 2000 -> lost end,
    true = port_close(P),
    Ev.
"#;

#[test]
fn msgq2_cases_match_erl() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping msgq2 differential");
        return;
    };
    let beam = reference.compile_named(MODULE, SOURCE, &[]).unwrap();
    reference.load(MODULE, &beam).unwrap();
    let expected = reference.call(MODULE, "all", &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled(MODULE, "all", &[] as &[Term], 4, None)
        .unwrap_or_else(|error| panic!("{MODULE}:all: {error}"));
    assert_eq!(expected, CallResult::Ok(actual.term));
}
