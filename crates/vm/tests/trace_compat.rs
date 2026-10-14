//! Call tracing of exports with global breakpoints, of trapping BIFs and the session form of
//! `system_monitor` behave like erts (differential against the reference `erl`).

use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_vm::Vm;

const SOURCE: &str = r#"
-module(trace_compat_diff).
-compile(nowarn_unused_function).
-export([global_return/0, global_tail_call/0, global_session_local_return/0,
         trapped_bif_return/0, trapped_bif_exception/0, system_monitor_session/0,
         system_monitor_old_api/0, port_tracer_gone/0]).
-export([k/1, f/1, g/1, w/1]).

k(X) -> [X].
f(X) -> g(X).
g(X) -> [X].
w(L) -> L ++ [a].

collect(Acc) ->
    receive M -> collect([M | Acc]) after 300 -> lists:reverse(Acc) end.

%% Trace messages of `Worker` without its pid.
messages(Worker) ->
    [list_to_tuple([trace | tl(tl(tuple_to_list(M)))]) || M <- collect([]),
                                                        element(2, M) =:= Worker].

traced(Fun, Flags) ->
    Self = self(),
    Worker = spawn_link(fun() -> receive go -> Self ! {done, catch Fun()} end end),
    erlang:trace(Worker, true, Flags),
    {Worker, fun() -> Worker ! go, receive {done, R} -> R end end}.

run_traced(Fun, Flags) ->
    {Worker, Go} = traced(Fun, Flags),
    R = Go(),
    {R, messages(Worker)}.

off(Kind) ->
    erlang:trace_pattern({trace_compat_diff, '_', '_'}, false, [Kind]),
    erlang:trace_pattern({erlang, '++', 2}, false, [Kind]).

global_return() ->
    Ms = [{'_', [], [{return_trace}]}],
    1 = erlang:trace_pattern({trace_compat_diff, k, 1}, Ms, [global]),
    R = run_traced(fun() -> k(1) end, [call]),
    R2 = run_traced(fun() -> trace_compat_diff:k(1) end, [call, return_to]),
    off(global),
    {R, R2}.

%% An export with a global breakpoint that tail calls a local function.
global_tail_call() ->
    Ms = [{'_', [], [{return_trace}]}],
    1 = erlang:trace_pattern({trace_compat_diff, f, 1}, Ms, [global]),
    R = run_traced(fun() -> trace_compat_diff:f(1) end, [call, return_to]),
    off(global),
    R.

%% A session breakpoint on an export beside a legacy local return_trace on its callee.
global_session_local_return() ->
    Tracer = spawn_link(fun() -> receive stop -> ok end end),
    S = trace:session_create(compat, Tracer, []),
    1 = trace:function(S, {trace_compat_diff, f, 1}, true, [global]),
    Ms = [{'_', [], [{return_trace}]}],
    1 = erlang:trace_pattern({trace_compat_diff, g, 1}, Ms, [local]),
    R = run_traced(fun() -> trace_compat_diff:f(1) end, [call]),
    off(local),
    trace:session_destroy(S),
    R.

%% erlang:'++'/2 traps for long lists; its return and exception belong to the last slice.
trapped_bif_return() ->
    Ms = [{'_', [], [{exception_trace}]}],
    1 = erlang:trace_pattern({erlang, '++', 2}, Ms, [local]),
    1 = erlang:trace_pattern({trace_compat_diff, w, 1}, Ms, [local]),
    L = lists:seq(1, 200000),
    {R, Msgs} = run_traced(fun() -> w(L) end, [call, return_to]),
    off(local),
    {length(R), [shorten(M) || M <- Msgs]}.

trapped_bif_exception() ->
    Ms = [{'_', [], [{exception_trace}]}],
    1 = erlang:trace_pattern({erlang, '++', 2}, Ms, [local]),
    1 = erlang:trace_pattern({trace_compat_diff, w, 1}, Ms, [local]),
    L = lists:seq(1, 199999) ++ 200000,
    {R, Msgs} = run_traced(fun() -> w(L) end, [call, return_to]),
    off(local),
    {element(1, R), [shorten(M) || M <- Msgs]}.

shorten({trace, call, {M, F, Args}}) -> {trace, call, {M, F, length(Args)}};
shorten({trace, return_from, MFA, V}) when is_list(V) -> {trace, return_from, MFA, length(V)};
shorten(M) -> M.

system_monitor_session() ->
    S = trace:session_create(sysmon, undefined, []),
    Me = self(),
    A = erts_internal:system_monitor(S),
    B = erts_internal:system_monitor(S, Me, [{long_gc, 500}]),
    C = erts_internal:system_monitor(S),
    D = erts_internal:system_monitor(S, Me, [{long_schedule, 500}, busy_port]),
    E = erts_internal:system_monitor(S),
    F = erts_internal:system_monitor(S, Me, [{long_message_queue, {10, 20}}]),
    G = erts_internal:system_monitor(S),
    H = catch erts_internal:system_monitor(S, Me, [{long_message_queue, {20, 10}}]),
    I = erts_internal:system_monitor(S, undefined, []),
    J = erts_internal:system_monitor(S),
    trace:session_destroy(S),
    rep(Me, {A, B, C, D, E, F, G, element(1, element(2, H)), I, J}).

system_monitor_old_api() ->
    Me = self(),
    Old = erlang:system_monitor(),
    A = erlang:system_monitor(Me, [{large_heap, 0}, {long_gc, 0}, busy_dist_port]),
    B = erlang:system_monitor(),
    C = catch erlang:system_monitor(Me, [{long_message_queue, disabled}]),
    D = catch erlang:system_monitor(Me, [{long_gc, a}]),
    E = erlang:system_monitor(undefined),
    F = erlang:system_monitor(),
    case Old of
        undefined -> ok;
        {OldPid, OldOpts} -> erlang:system_monitor(OldPid, OldOpts)
    end,
    rep(Me, {Old, A, B, element(1, C), element(1, D), E, F}).

%% The tracer of a port is gone once its process exits, whatever the exit order.
port_tracer_gone() ->
    Tracer = spawn(fun() -> receive stop -> ok end end),
    Ref = erlang:monitor(process, Tracer),
    P1 = open_port({spawn, "cat"}, [binary]),
    _ = erlang:trace(new_ports, true, ['receive', {tracer, Tracer}]),
    P2 = open_port({spawn, "cat"}, [binary]),
    Before = {erlang:trace_info(P1, tracer), erlang:trace_info(P1, flags),
              erlang:trace_info(P2, flags)},
    Tracer ! stop,
    receive {'DOWN', Ref, process, Tracer, normal} -> ok end,
    After = {erlang:trace_info(P1, tracer), erlang:trace_info(P2, tracer),
             erlang:trace_info(P2, flags)},
    port_close(P1),
    port_close(P2),
    erlang:trace(new_ports, false, [all]),
    {Before, After}.

relay(To) -> receive M -> To ! {ts, M}, relay(To) end.

rep(S, S) -> self;
rep(S, T) when is_tuple(T) -> list_to_tuple([rep(S, E) || E <- tuple_to_list(T)]);
rep(S, [H | T]) -> [rep(S, H) | rep(S, T)];
rep(_, T) -> T.
"#;

fn run(reference: &RefErl, function: &str) -> (CallResult, OwnedTerm) {
    let beam = reference
        .compile_named("trace_compat_diff", SOURCE, &[])
        .expect("compile fixture");
    reference
        .load("trace_compat_diff", &beam)
        .expect("load reference");
    let expected = reference.call("trace_compat_diff", function, &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).expect("load VM fixture");
    let actual = vm
        .eval_scheduled("trace_compat_diff", function, &[], 1, None)
        .unwrap_or_else(|error| panic!("{function}: {error}"));
    (expected, actual.term)
}

fn check(function: &str) {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping trace_compat test");
        return;
    };
    let (expected, actual) = run(&reference, function);
    assert_eq!(expected, CallResult::Ok(actual), "{function}");
}

#[test]
fn global_return_trace_returns_to_the_caller() {
    check("global_return");
}

#[test]
fn global_breakpoint_tail_call_keeps_trace_frames() {
    check("global_tail_call");
}

#[test]
fn session_global_with_legacy_local_return_trace() {
    check("global_session_local_return");
}

#[test]
fn trapped_bif_reports_return_from() {
    check("trapped_bif_return");
}

#[test]
fn trapped_bif_reports_exception_from() {
    check("trapped_bif_exception");
}

#[test]
fn session_system_monitor_returns_the_old_state() {
    check("system_monitor_session");
}

#[test]
fn dead_port_tracer_is_dropped_by_trace_info() {
    check("port_tracer_gone");
}

#[test]
fn legacy_system_monitor_replaces_the_state() {
    check("system_monitor_old_api");
}
