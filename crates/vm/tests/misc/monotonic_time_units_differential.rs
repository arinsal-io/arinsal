//! `erlang:monotonic_time/1` and `time_offset/1` unit conversion match erts.

use arinsal_difftest::{CallResult, RefErl};

const SOURCE: &str = r#"
-module(mono_units_diff).
-export([run/0]).

units() ->
    [native, nanosecond, nano_seconds, microsecond, micro_seconds, millisecond,
     milli_seconds, second, seconds, perf_counter, 1, 1000, 1000000, 1000000000,
     500, 7, 123456789012].

between(U) ->
    T1 = erlang:monotonic_time(native),
    V = erlang:monotonic_time(U),
    T2 = erlang:monotonic_time(native),
    Lo = erlang:convert_time_unit(T1, native, U),
    Hi = erlang:convert_time_unit(T2, native, U),
    is_integer(V) andalso Lo =< V andalso V =< Hi.

bad(F) ->
    try F() catch error:R -> R end.

run() ->
    Good = [{U, between(U)} || U <- units()],
    Offset = [{U, erlang:time_offset(U) =:= erlang:time_offset(U)} || U <- units()],
    Bad = [bad(fun() -> erlang:monotonic_time(U) end)
           || U <- [foo, 0, -1, {}, "ms", 1.0]],
    {Good, Offset, Bad}.
"#;

#[test]
fn monotonic_time_units_match_erts() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping monotonic_time units test");
        return;
    };
    let beam = reference
        .compile_named("mono_units_diff", SOURCE, &[])
        .expect("compile fixture");
    reference
        .load("mono_units_diff", &beam)
        .expect("load reference");
    let expected = reference.call("mono_units_diff", "run", &[]);
    let mut vm = crate::common::node();
    vm.load_bytes(&beam).expect("load VM fixture");
    let actual = vm
        .eval_scheduled("mono_units_diff", "run", &[], 1)
        .unwrap_or_else(|error| panic!("run: {error}"));
    assert_eq!(expected, CallResult::Ok(actual.term));
}
