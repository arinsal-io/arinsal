use arinsal_difftest::{CallResult, RefErl};
use arinsal_vm::Vm;
use similar_asserts::assert_eq;

const SOURCE: &str = r#"
-module(ets_point_ops_diff).
-export([set_ops/0, ordered_ops/0, shared_ordered_ops/0, overflow/0, errors/0,
         resize_list/0]).

set_ops() ->
    T = ets:new(point_set, [set, public]),
    true = ets:insert(T, {a, 0, 0}),
    Single = ets:update_counter(T, a, 1),
    Threshold = ets:update_counter(T, a, {3, 2, 1, 0}),
    List = ets:update_counter(T, a, [{2, 4}, {3, 2}]),
    Default = ets:update_counter(T, b, {3, 7}, {b, 0, 0}),
    Before = {ets:lookup(T, a), ets:lookup(T, b)},
    true = ets:insert(T, {a, 9, 9}),
    Replaced = ets:lookup(T, a),
    true = ets:delete(T, a),
    After = ets:lookup(T, a),
    true = ets:delete(T, missing),
    {Single, Threshold, List, Default, Before, Replaced, After}.

ordered_ops() ->
    T = ets:new(point_ordered, [ordered_set, public]),
    true = ets:insert(T, {k, 0, 1}),
    Single = ets:update_counter(T, k, 3),
    List = ets:update_counter(T, k, [{2, 4}, {3, -2, -1, 8}]),
    Found = ets:lookup(T, k),
    true = ets:delete(T, k),
    {Single, List, Found, ets:lookup(T, k)}.

shared_ordered_ops() ->
    T = ets:new(point_shared_ordered,
                [ordered_set, public, {write_concurrency, true}]),
    Big = 1 bsl 100,
    Inc = 1 bsl 85,
    true = ets:insert(T, {k, Big, Big}),
    One = ets:update_counter(T, k, {2, Inc}),
    Many = ets:update_counter(T, k, [{2, -Inc}, {3, Inc}]),
    Default = ets:update_counter(T, absent, {2, Inc}, {absent, Big, 0}),
    {One, Many, Default, ets:lookup(T, k), ets:lookup(T, absent)}.

overflow() ->
    T = ets:new(point_overflow, [set, public]),
    Big = 1 bsl 100,
    Inc = 1 bsl 90,
    true = ets:insert(T, {k, Big, 0}),
    One = ets:update_counter(T, k, {2, Inc}),
    Many = ets:update_counter(T, k, [{2, -Inc}, {3, 1 bsl 80}]),
    Default = ets:update_counter(T, absent, {2, Inc}, {absent, Big, 0}),
    {One, Many, Default, ets:lookup(T, k)}.

top(F) ->
    try F() of
        V -> {ok, V}
    catch
        error:R:S ->
            [{M, Fn, Args, Info} | _] = S,
            {R, M, Fn, length(Args), Info}
    end.

errors() ->
    T = ets:new(point_errors, [set]),
    true = ets:insert(T, {k, 1}),
    B = ets:new(point_bag, [bag]),
    [top(fun() -> ets:update_counter(T, missing, 1) end),
     top(fun() -> ets:update_counter(T, k, {1, 1}) end),
     top(fun() -> ets:update_counter(T, k, {3, 1}) end),
     top(fun() -> ets:update_counter(T, k, [{2, 1} | improper]) end),
     top(fun() -> ets:update_counter(T, missing, 1, {}) end),
     top(fun() -> ets:update_counter(B, key, 1) end)].

resize_list() ->
    T = ets:new(point_resize_list, [set, public]),
    L = [1 | {tail, 2}],
    true = ets:insert(T, {k, L, 0}),
    Big = 1 bsl 100,
    Updated = ets:update_counter(T, k, {3, Big}),
    {Updated, ets:lookup(T, k)}.
"#;

fn run(function: &str, reference: &RefErl, beam: &[u8]) {
    let expected = reference.call("ets_point_ops_diff", function, &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(beam).unwrap();
    let actual = vm
        .eval_scheduled("ets_point_ops_diff", function, &[], 2, Some(91))
        .unwrap_or_else(|error| panic!("{function}: {error}"));
    assert_eq!(expected, CallResult::Ok(actual.term), "{function}");
}

#[test]
fn set_lookup_insert_delete_and_counter_forms_match_otp() {
    let reference = RefErl::start().expect("OTP 29.1.1 reference runtime");
    let beam = reference
        .compile_named("ets_point_ops_diff", SOURCE, &[])
        .unwrap();
    reference.load("ets_point_ops_diff", &beam).unwrap();
    run("set_ops", &reference, &beam);
}

#[test]
fn ordered_set_counter_lookup_and_delete_match_otp() {
    let reference = RefErl::start().expect("OTP 29.1.1 reference runtime");
    let beam = reference
        .compile_named("ets_point_ops_diff", SOURCE, &[])
        .unwrap();
    reference.load("ets_point_ops_diff", &beam).unwrap();
    run("ordered_ops", &reference, &beam);
}

#[test]
fn shared_ordered_set_bignum_counter_and_default_match_otp() {
    let reference = RefErl::start().expect("OTP 29.1.1 reference runtime");
    let beam = reference
        .compile_named("ets_point_ops_diff", SOURCE, &[])
        .unwrap();
    reference.load("ets_point_ops_diff", &beam).unwrap();
    run("shared_ordered_ops", &reference, &beam);
}

#[test]
fn counter_bignum_overflow_and_defaults_match_otp() {
    let reference = RefErl::start().expect("OTP 29.1.1 reference runtime");
    let beam = reference
        .compile_named("ets_point_ops_diff", SOURCE, &[])
        .unwrap();
    reference.load("ets_point_ops_diff", &beam).unwrap();
    run("overflow", &reference, &beam);
}

#[test]
fn counter_badarg_error_info_matches_otp() {
    let reference = RefErl::start().expect("OTP 29.1.1 reference runtime");
    let beam = reference
        .compile_named("ets_point_ops_diff", SOURCE, &[])
        .unwrap();
    reference.load("ets_point_ops_diff", &beam).unwrap();
    run("errors", &reference, &beam);
}

#[test]
fn counter_resize_preserves_immediate_head_list_field_layout() {
    let reference = RefErl::start().expect("OTP 29.1.1 reference runtime");
    let beam = reference
        .compile_named("ets_point_ops_diff", SOURCE, &[])
        .unwrap();
    reference.load("ets_point_ops_diff", &beam).unwrap();
    run("resize_list", &reference, &beam);
}
