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
         system_monitor_old_api/0, port_tracer_gone/0, seq_token_counters/0,
         call_match_self/0, seq_receive_states/0, call_match_set_seq_token/0,
         alias_reply_once/0, big_call_message_tracer/0, new_tracing_dies_with_tracer/0,
         nocatch_stack_with_trace_frames/0, bif_session_global_destroyed/0,
         link_events_in_signal_order/0]).
-export([d1/1, d2/1]).
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

%% The serial counters of a process survive unsetting its token.
seq_token_counters() ->
    Self = self(),
    seq_trace:reset_trace(),
    A = seq_trace:get_token(),
    B = seq_trace:set_token(label, {my_label, 1}),
    C = seq_trace:set_token(send, true),
    D = seq_trace:set_token(serial, {3, 5}),
    E = seq_trace:get_token(),
    F = seq_trace:set_token([]),
    G = seq_trace:set_token(label, 17),
    H = seq_trace:get_token(),
    I = catch seq_trace:set_token(bogus, true),
    seq_trace:reset_trace(),
    J = seq_trace:get_token(),
    rep(Self, {A, B, C, D, E, F, G, H, element(1, I), J}).

%% A tokenless process message clears the receiver's token; a port message leaves it.
seq_receive_states() ->
    Me = self(),
    seq_trace:reset_trace(),
    seq_trace:set_token(label, 5),
    spawn(fun() -> seq_trace:set_token([]), Me ! plain end),
    receive plain -> ok end,
    A = seq_trace:get_token(label),
    seq_trace:set_token(label, 6),
    P = open_port({spawn, "cat"}, [binary]),
    P ! {Me, {command, <<"x">>}},
    receive {P, {data, _}} -> ok end,
    B = seq_trace:get_token(label),
    port_close(P),
    seq_trace:reset_trace(),
    {A, B}.

%% `{set_seq_token, Item, Value}` in a trace match specification edits the tracee's token.
call_match_set_seq_token() ->
    Ms = [{'_', [], [{set_seq_token, label, 17}, {message, {get_seq_token}}]}],
    1 = erlang:trace_pattern({trace_compat_diff, k, 1}, Ms, [local]),
    {R, Msgs} = run_traced(fun() -> k(1), seq_trace:get_token(label) end, [call]),
    off(local),
    {R, [setelement(4, element(4, M), pid) || M <- Msgs, tuple_size(M) =:= 4]}.

%% A `reply` alias is dead after the first message through it.
alias_reply_once() ->
    Me = self(),
    R = spawn(fun() ->
                      A = alias([reply]),
                      Me ! {alias, A},
                      receive M1 -> Me ! {got, M1} end,
                      receive M2 -> Me ! {got, M2} end
              end),
    A = receive {alias, X} -> X end,
    A ! one,
    A ! two,
    R ! three,
    collect([]).

%% `{self}` in a trace match specification is the tracee.
call_match_self() ->
    Ms = [{'_', [], [{message, {{{self}, {get_seq_token}, {const, x}}}}]}],
    1 = erlang:trace_pattern({trace_compat_diff, k, 1}, Ms, [local]),
    {R, Msgs} = run_traced(fun() -> k(1) end, [call]),
    off(local),
    {R, [{element(2, M), {is_pid(P), T, X}} || M <- Msgs, tuple_size(M) =:= 4,
                                              {P, T, X} <- [element(4, M)]]}.

%% The tracer prints a large call message while the tracee unwinds through a traced BIF; the
%% tracer's collection goes to a dirty scheduler, so the traced call keeps its arguments live.
big_call_message_tracer() ->
    Me = self(),
    Fd = spawn_link(fun io_device/0),
    Imp = lists:foldl(fun(X, Acc) -> [X | Acc] end, 5, lists:seq(1, 200000)),
    erlang:trace_pattern({lists, reverse, 2}, [{'_', [], [{exception_trace}]}], [local]),
    P = spawn(fun() ->
                      receive go -> ok end,
                      _ = (catch lists:reverse(Imp, [])),
                      Me ! done
              end),
    erlang:trace(P, true, [call, return_to, {tracer, Me}]),
    P ! go,
    R = big_loop(Fd, []),
    erlang:trace_pattern({lists, reverse, 2}, false, [local]),
    unlink(Fd),
    exit(Fd, kill),
    R.

io_device() ->
    receive {io_request, From, Ref, _} -> From ! {io_reply, Ref, ok}, io_device() end.

big_loop(Fd, Acc) ->
    receive
        done -> lists:reverse(Acc);
        M ->
            [io:format(Fd, "~w ~w~n", [element(3, M), N]) || N <- lists:seq(1, 50)],
            big_loop(Fd, [element(3, M) | Acc])
    end.

d1(X) -> trace_compat_diff:d2(X).
d2(X) -> erlang:throw(X).

%% Trace frames are not frames of the exit reason's stack trace.
nocatch_stack_with_trace_frames() ->
    Ms = [{'_', [], [{exception_trace}]}],
    erlang:trace_pattern({trace_compat_diff, d1, 1}, Ms, [global]),
    erlang:trace_pattern({trace_compat_diff, d2, 1}, Ms, [global]),
    Go = make_ref(),
    P = spawn(fun() -> receive Go -> trace_compat_diff:d1(42) end end),
    erlang:trace(P, true, [call, return_to, procs, {tracer, self()}]),
    P ! Go,
    R = nocatch_exit(P),
    erlang:trace_pattern({trace_compat_diff, d1, 1}, false, [global]),
    erlang:trace_pattern({trace_compat_diff, d2, 1}, false, [global]),
    R.

nocatch_exit(P) ->
    receive
        {trace, P, exit, Reason} -> Reason;
        _ -> nocatch_exit(P)
    after 2000 -> timeout
    end.

%% A BIF traced locally by one session stays traced when another session's global trace of it
%% is destroyed.
bif_session_global_destroyed() ->
    Me = self(),
    Relay = fun F() -> receive M -> Me ! {relayed, self(), M} end, F() end,
    T2 = spawn_link(Relay),
    S2 = trace:session_create(two, T2, []),
    trace:function(S2, {erlang, phash2, 1}, true, [global]),
    trace:process(S2, self(), true, [call]),
    T3 = spawn_link(Relay),
    S3 = trace:session_create(three, T3, []),
    trace:function(S3, {erlang, phash2, 1}, true, [local]),
    trace:process(S3, self(), true, [call]),
    erlang:phash2("a"),
    A = bif_drain(),
    trace:session_destroy(S2),
    erlang:phash2("b"),
    B = bif_drain(),
    trace:session_destroy(S3),
    erlang:phash2("c"),
    C = bif_drain(),
    {length(A), length(B), length(C)}.

bif_drain() -> receive M -> [M | bif_drain()] after 100 -> [] end.

%% getting_linked and getting_unlinked are reported in order with the traced messages.
link_events_in_signal_order() ->
    Receiver = spawn(fun F() -> receive stop -> ok; _ -> F() end end),
    process_flag(trap_exit, true),
    1 = erlang:trace(Receiver, true, ['receive', procs, timestamp]),
    [begin
         if N rem 2 == 0 -> link(Receiver); true -> unlink(Receiver) end,
         Receiver ! N
     end || N <- lists:seq(20, 1, -1)],
    Receiver ! stop,
    Ref = erlang:monitor(process, Receiver),
    receive {'DOWN', Ref, _, _, _} -> ok end,
    T = erlang:trace_delivered(Receiver),
    receive {trace_delivered, _, T} -> ok end,
    [case M of
         {trace_ts, _, 'receive', Msg, _} -> {'receive', Msg};
         {trace_ts, _, Event, _, _} -> Event
     end || M <- collect([]), element(3, M) =/= exit].

%% Tracing of new processes ends when its tracer exits.
new_tracing_dies_with_tracer() ->
    Tracer = spawn(fun() -> receive stop -> ok end end),
    0 = erlang:trace(new, true, [send, {tracer, Tracer}]),
    A = {erlang:trace_info(new, flags), erlang:trace_info(new, tracer)},
    Ref = erlang:monitor(process, Tracer),
    exit(Tracer, done),
    receive {'DOWN', Ref, _, _, _} -> ok end,
    B = {erlang:trace_info(new, flags), erlang:trace_info(new, tracer)},
    rep(Tracer, {A, B}).

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
fn seq_trace_counters_survive_unset_token() {
    check("seq_token_counters");
}

#[test]
fn match_spec_self_is_the_tracee() {
    check("call_match_self");
}

#[test]
fn seq_trace_receive_states() {
    check("seq_receive_states");
}

#[test]
fn match_spec_sets_the_seq_token() {
    check("call_match_set_seq_token");
}

#[test]
fn reply_alias_dies_with_its_first_message() {
    check("alias_reply_once");
}

#[test]
fn big_call_message_survives_a_dirty_collection_of_the_tracer() {
    check("big_call_message_tracer");
}

#[test]
fn new_process_tracing_is_cleared_when_the_tracer_exits() {
    check("new_tracing_dies_with_tracer");
}

#[test]
fn trace_frames_are_not_stack_trace_frames() {
    check("nocatch_stack_with_trace_frames");
}

#[test]
fn bif_stays_traced_when_only_the_global_session_is_destroyed() {
    check("bif_session_global_destroyed");
}

#[test]
fn link_events_follow_message_order() {
    check("link_events_in_signal_order");
}

#[test]
fn legacy_system_monitor_replaces_the_state() {
    check("system_monitor_old_api");
}
