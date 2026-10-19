//! BIF call tracing and accounting match OTP's export-entry breakpoints.

use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_vm::Vm;

const SOURCE: &str = r#"
-module(tprof_bif_diff).
-export([accounting/0, call_messages/0, memory/0, guard_accounting/0]).

relay(To) -> receive M -> To ! {ts, M}, relay(To) end.

accounting() ->
    Table = ets:new(tprof_bif_table, [named_table, set]),
    true = ets:insert(Table, {key, value}),
    Me = self(),
    Tracer = spawn_link(fun() -> relay(Me) end),
    Patterns = [{ets, lookup, 2}, {erlang, phash2, 1}, {lists, keyfind, 3}],
    [1 = erlang:trace_pattern(P, true, [local, call_count, call_time]) || P <- Patterns],
    1 = erlang:trace(Me, true, [call, {tracer, Tracer}]),
    ets:lookup(Table, key),
    ets:lookup(Table, key),
    ets:lookup(Table, key),
    erlang:phash2(alpha),
    erlang:phash2(beta),
    erlang:phash2(gamma),
    lists:keyfind(alpha, 1, [{alpha, one}, {beta, two}]),
    lists:keyfind(beta, 1, [{alpha, one}, {beta, two}]),
    lists:keyfind(missing, 1, [{alpha, one}, {beta, two}]),
    erlang:trace(Me, false, [call, {tracer, Tracer}]),
    Counts = [element(2, erlang:trace_info(P, call_count)) || P <- Patterns],
    Times = [time_count(P, Me) || P <- Patterns],
    [1 = erlang:trace_pattern(P, false, [local, call_count, call_time]) || P <- Patterns],
    Messages = [strip(M) || {ts, M} <- collect([])],
    ets:delete(Table),
    normalize(Me, Tracer, {Counts, Times, Messages}).

time_count(Pattern, Me) ->
    {call_time, [{Me, Count, Total, SinceLast}]} = erlang:trace_info(Pattern, call_time),
    {Count, is_integer(Total), is_integer(SinceLast)}.

call_messages() ->
    Me = self(),
    Tracer = spawn_link(fun() -> relay(Me) end),
    Table = ets:new(tprof_bif_table, [named_table, set]),
    true = ets:insert(Table, {key, value}),
    Patterns = [{ets, lookup, 2}, {erlang, phash2, 1}, {lists, keyfind, 3}],
    [1 = erlang:trace_pattern(P, true, [local]) || P <- Patterns],
    1 = erlang:trace(Me, true, [call, {tracer, Tracer}]),
    ets:lookup(Table, key),
    erlang:phash2(alpha),
    lists:keyfind(alpha, 1, [{alpha, one}]),
    erlang:trace(Me, false, [call, {tracer, Tracer}]),
    [1 = erlang:trace_pattern(P, false, [local]) || P <- Patterns],
    Messages = [strip(M) || {ts, M} <- collect([])],
    ets:delete(Table),
    normalize(Me, Tracer, Messages).

memory() ->
    Me = self(),
    Tracer = spawn_link(fun() -> relay(Me) end),
    Table = ets:new(tprof_bif_table, [named_table, set]),
    true = ets:insert(Table, {key, value}),
    1 = erlang:trace_pattern({ets, lookup, 2}, true, [call_memory]),
    1 = erlang:trace(Me, true, [call, {tracer, Tracer}]),
    ets:lookup(Table, key),
    ets:lookup(Table, key),
    ets:lookup(Table, key),
    erlang:trace(Me, false, [call, {tracer, Tracer}]),
    {call_memory, [{Me, Count, Words}]} = erlang:trace_info({ets, lookup, 2}, call_memory),
    1 = erlang:trace_pattern({ets, lookup, 2}, false, [call_memory]),
    ets:delete(Table),
    {Count, is_integer(Words)}.

guard_accounting() ->
    Pattern = {erlang, is_atom, 1},
    1 = erlang:trace_pattern(Pattern, true, [call_count]),
    Guard = fun(Value) when is_atom(Value) -> true; (_) -> false end,
    Results = [Guard(atom), Guard(1)],
    {call_count, Count} = erlang:trace_info(Pattern, call_count),
    1 = erlang:trace_pattern(Pattern, false, [call_count]),
    {Results, Count}.

collect(Acc) -> receive M -> collect([M | Acc]) after 200 -> lists:reverse(Acc) end.

strip(T) ->
    L = tuple_to_list(T),
    L1 = case hd(L) of trace_ts -> lists:droplast(L); trace -> L end,
    list_to_tuple(tl(tl(L1))).

normalize(First, Second, Term) -> rep(Second, rep(First, Term)).

rep(S, S) -> self;
rep(S, T) when is_tuple(T) -> list_to_tuple([rep(S, E) || E <- tuple_to_list(T)]);
rep(S, [H | T]) -> [rep(S, H) | rep(S, T)];
rep(_, T) -> T.
"#;

fn run(reference: &RefErl, function: &str) -> (CallResult, OwnedTerm) {
    let beam = reference
        .compile_named("tprof_bif_diff", SOURCE, &[])
        .expect("compile fixture");
    reference
        .load("tprof_bif_diff", &beam)
        .expect("load reference");
    let expected = reference.call("tprof_bif_diff", function, &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).expect("load VM fixture");
    let actual = vm
        .eval_scheduled("tprof_bif_diff", function, &[], 1, None)
        .unwrap_or_else(|error| panic!("{function}: {error}"));
    (expected, actual.term)
}

fn check(function: &str) {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping tprof BIF differential test");
        return;
    };
    let (expected, actual) = run(&reference, function);
    similar_asserts::assert_eq!(expected, CallResult::Ok(actual), "{function}");
}

#[test]
fn bif_call_count_and_time_match_erts() {
    check("accounting");
}

#[test]
fn bif_call_trace_messages_match_erts() {
    check("call_messages");
}

#[test]
fn bif_call_memory_is_reported() {
    check("memory");
}

#[test]
fn guard_bif_call_count_matches_erts() {
    check("guard_accounting");
}
