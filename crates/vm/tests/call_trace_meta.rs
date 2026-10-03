//! Meta call tracing, call_time/call_memory/call_count patterns and `trace_info` of local
//! breakpoints behave like erts (differential against the reference `erl`).

use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_vm::Vm;

const SOURCE: &str = r#"
-module(call_trace_meta_diff).
-export([meta_calls/0, meta_info/0, call_time_info/0, bif_local/0, on_load_info/0,
         call_memory_info/0, timestamps/0]).
-export([outer/1, inner/1]).

outer(X) -> inner(X) + 1.
inner(X) -> X * 2.

rep(S, S) -> self;
rep(S, T) when is_tuple(T) -> list_to_tuple([rep(S, E) || E <- tuple_to_list(T)]);
rep(S, [H | T]) -> [rep(S, H) | rep(S, T)];
rep(_, T) -> T.

collect(Acc) ->
    receive M -> collect([M | Acc]) after 200 -> lists:reverse(Acc) end.

strip(T) ->
    L = tuple_to_list(T),
    L1 = case hd(L) of trace_ts -> lists:droplast(L); trace -> L end,
    list_to_tuple(tl(tl(L1))).

meta_calls() ->
    Self = self(),
    Worker = spawn_link(fun() -> receive go -> outer(3), Self ! done end end),
    1 = erlang:trace_pattern({call_trace_meta_diff, outer, 1}, [{'_', [], [{return_trace}]}],
                             [{meta, Self}]),
    1 = erlang:trace_pattern({call_trace_meta_diff, inner, 1}, true, [{meta, Self}]),
    Worker ! go,
    Result = [strip(M) || M <- collect([]), M =/= done],
    erlang:trace_pattern({call_trace_meta_diff, '_', '_'}, false, [meta]),
    Result.

meta_info() ->
    Self = self(),
    Ms = [{'_', [], [{return_trace}]}],
    erlang:trace_pattern({call_trace_meta_diff, outer, 1}, Ms, [{meta, Self}]),
    R = {erlang:trace_info({call_trace_meta_diff, outer, 1}, meta),
         erlang:trace_info({call_trace_meta_diff, outer, 1}, meta_match_spec),
         erlang:trace_info({call_trace_meta_diff, outer, 1}, traced),
         erlang:trace_info({call_trace_meta_diff, inner, 1}, meta),
         erlang:trace_info({call_trace_meta_diff, inner, 1}, call_time),
         element(2, lists:keyfind(meta, 1,
                  element(2, erlang:trace_info({call_trace_meta_diff, outer, 1}, all))))},
    erlang:trace_pattern({call_trace_meta_diff, '_', '_'}, false, [meta]),
    rep(Self, R).

call_time_info() ->
    Self = self(),
    erlang:trace_pattern({call_trace_meta_diff, outer, 1}, true, [call_time]),
    erlang:trace_pattern({call_trace_meta_diff, inner, 1}, true, [call_time, call_count]),
    1 = erlang:trace(Self, true, [call]),
    outer(1), outer(2), inner(3),
    erlang:trace(Self, false, [call]),
    {call_time, TimeOuter} = erlang:trace_info({call_trace_meta_diff, outer, 1}, call_time),
    {call_time, TimeInner} = erlang:trace_info({call_trace_meta_diff, inner, 1}, call_time),
    Counts = {erlang:trace_info({call_trace_meta_diff, inner, 1}, call_count),
              erlang:trace_info({call_trace_meta_diff, outer, 1}, call_count)},
    erlang:trace_pattern({call_trace_meta_diff, '_', '_'}, pause, [call_time]),
    outer(1),
    {call_time, Paused} = erlang:trace_info({call_trace_meta_diff, outer, 1}, call_time),
    erlang:trace_pattern({call_trace_meta_diff, '_', '_'}, false, [call_time, call_count]),
    rep(Self,
        {[{P, C, is_integer(S), is_integer(U)} || {P, C, S, U} <- TimeOuter] =:=
             [{Self, 2, true, true}],
         [{P, C} || {P, C, _, _} <- TimeInner],
         Counts,
         [{P, C} || {P, C, _, _} <- Paused],
         erlang:trace_info({call_trace_meta_diff, outer, 1}, call_time)}).

call_memory_info() ->
    Self = self(),
    erlang:trace_pattern({call_trace_meta_diff, inner, 1}, true, [call_memory]),
    1 = erlang:trace(Self, true, [call]),
    inner(1),
    erlang:trace(Self, false, [call]),
    R = case erlang:trace_info({call_trace_meta_diff, inner, 1}, call_memory) of
            {call_memory, [{Self, 1, W}]} when is_integer(W) -> ok;
            Other -> Other
        end,
    erlang:trace_pattern({call_trace_meta_diff, '_', '_'}, false, [call_memory]),
    {R, erlang:trace_info({call_trace_meta_diff, inner, 1}, call_memory)}.

bif_local() ->
    Self = self(),
    Tracer = spawn_link(fun() -> relay(Self) end),
    erlang:trace_pattern({erlang, phash2, 2}, [{'_', [], [{return_trace}]}], [local]),
    1 = erlang:trace(Self, true, [call, return_to, {tracer, Tracer}]),
    erlang:phash2(a, 100),
    erlang:trace(Self, false, [call, return_to]),
    erlang:trace_pattern({erlang, phash2, 2}, false, [local]),
    [strip(M) || {ts, M} <- collect([])].

timestamps() ->
    Self = self(),
    Tracer = spawn_link(fun() -> relay(Self) end),
    erlang:trace_pattern({call_trace_meta_diff, inner, 1}, true, [local]),
    Flags = [[timestamp], [monotonic_timestamp], [strict_monotonic_timestamp],
             [timestamp, strict_monotonic_timestamp, monotonic_timestamp]],
    Shapes = [begin
                  1 = erlang:trace(Self, true, [call, {tracer, Tracer} | F]),
                  inner(1),
                  erlang:trace(Self, false, [call | F]),
                  receive {ts, {trace_ts, _, call, _, Ts}} -> shape(Ts) after 1000 -> none end
              end || F <- Flags],
    erlang:trace_pattern({call_trace_meta_diff, '_', '_'}, false, [local]),
    Shapes.

relay(To) -> receive M -> To ! {ts, M}, relay(To) end.

shape({A, B, C}) when is_integer(A), is_integer(B), is_integer(C) -> now_tuple;
shape({A, B}) when is_integer(A), is_integer(B) -> strict_pair;
shape(T) when is_integer(T) -> monotonic.

on_load_info() ->
    Self = self(),
    0 = erlang:trace_pattern(on_load, true, [call_time, call_memory]),
    A = erlang:trace_info(on_load, all),
    0 = erlang:trace_pattern(on_load, [{'_', [], []}], [local, {meta, Self}]),
    B = erlang:trace_info(on_load, all),
    {call_time, CallTime} = erlang:trace_info(on_load, call_time),
    erlang:trace_pattern(on_load, false, [local, meta, call_time, call_memory]),
    C = erlang:trace_info(on_load, traced),
    rep(Self, {A, B, CallTime, C}).
"#;

fn run(reference: &RefErl, function: &str) -> (CallResult, OwnedTerm) {
    let beam = reference
        .compile_named("call_trace_meta_diff", SOURCE, &[])
        .expect("compile fixture");
    reference
        .load("call_trace_meta_diff", &beam)
        .expect("load reference");
    let expected = reference.call("call_trace_meta_diff", function, &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).expect("load VM fixture");
    let actual = vm
        .eval_scheduled("call_trace_meta_diff", function, &[], 1, None)
        .unwrap_or_else(|error| panic!("{function}: {error}"));
    (expected, actual.term)
}

fn check(function: &str) {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping call_trace_meta test");
        return;
    };
    let (expected, actual) = run(&reference, function);
    assert_eq!(expected, CallResult::Ok(actual), "{function}");
}

#[test]
fn meta_trace_reports_calls_and_returns() {
    check("meta_calls");
}

#[test]
fn meta_trace_info() {
    check("meta_info");
}

#[test]
fn call_time_and_call_count_info() {
    check("call_time_info");
}

#[test]
fn call_memory_info() {
    check("call_memory_info");
}

#[test]
fn local_bif_trace_with_return_to() {
    check("bif_local");
}

#[test]
fn timestamp_flag_priority() {
    check("timestamps");
}

#[test]
fn on_load_pattern_flags() {
    check("on_load_info");
}
