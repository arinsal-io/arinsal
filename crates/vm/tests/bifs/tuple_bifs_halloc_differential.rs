use arinsal_difftest::{CallResult, RefErl};
use similar_asserts::assert_eq;

const MODULE: &str = "tuple_bifs_halloc_differential";
const SOURCE: &str = r#"
-module(tuple_bifs_halloc_differential).
-export([run/0]).

safe(F) -> try {ok, F()} catch C:R -> {C, R} end.

run() ->
    Large = lists:seq(1, 4096),
    Results = [
        safe(fun() -> erlang:append_element({}, last) end),
        safe(fun() -> erlang:append_element({a, 2}, last) end),
        safe(fun() -> erlang:append_element(list_to_tuple(Large), last) end),
        safe(fun() -> erlang:append_element(not_tuple, last) end),
        safe(fun() -> erlang:delete_element(1, {}) end),
        safe(fun() -> erlang:delete_element(1, {one}) end),
        safe(fun() -> erlang:delete_element(2, {a, b, c}) end),
        safe(fun() -> erlang:delete_element(2048, list_to_tuple(Large)) end),
        safe(fun() -> erlang:delete_element(0, {a}) end),
        safe(fun() -> erlang:delete_element(a, {a}) end),
        safe(fun() -> erlang:delete_element(1, not_tuple) end),
        safe(fun() -> erlang:insert_element(1, {}, first) end),
        safe(fun() -> erlang:insert_element(3, {a, b}, last) end),
        safe(fun() -> erlang:insert_element(2049, list_to_tuple(Large), middle) end),
        safe(fun() -> erlang:insert_element(0, {a}, bad) end),
        safe(fun() -> erlang:insert_element(a, {a}, bad) end),
        safe(fun() -> erlang:insert_element(1, not_tuple, bad) end),
        safe(fun() -> erlang:tuple_to_list({}) end),
        safe(fun() -> erlang:tuple_to_list({one}) end),
        safe(fun() -> erlang:tuple_to_list(list_to_tuple(Large)) end),
        safe(fun() -> erlang:list_to_tuple([]) end),
        safe(fun() -> erlang:list_to_tuple([one]) end),
        safe(fun() -> erlang:list_to_tuple(Large) end),
        safe(fun() -> erlang:list_to_tuple([one | tail]) end),
        safe(fun() -> erlang:list_to_tuple(not_list) end),
        safe(fun() -> erlang:make_tuple(0, fill) end),
        safe(fun() -> erlang:make_tuple(1, fill) end),
        safe(fun() -> erlang:make_tuple(4096, fill) end),
        safe(fun() -> erlang:make_tuple(-1, fill) end),
        safe(fun() -> erlang:make_tuple(1 bsl 24, fill) end),
        safe(fun() -> erlang:make_tuple(3, fill, [{2, updated}, {1, first}]) end),
        safe(fun() -> erlang:make_tuple(4096, fill, [{4096, last}]) end),
        safe(fun() -> erlang:make_tuple(0, fill, []) end),
        safe(fun() -> erlang:make_tuple(3, fill, [{4, bad}]) end),
        safe(fun() -> erlang:make_tuple(3, fill, [not_pair]) end),
        safe(fun() -> erlang:make_tuple(3, fill, [{x, bad}]) end),
        safe(fun() -> erlang:make_tuple(3, fill, [{1, ok} | improper]) end)
    ],
    %% Keep every newly allocated result live across a collection.
    garbage_collect(),
    Results.
"#;

#[test]
fn tuple_bifs_use_halloc_and_match_otp_after_gc() {
    let reference = RefErl::start().expect("OTP 29.1.1 is required for this test");
    let beam = reference
        .compile_named(MODULE, SOURCE, &[])
        .expect("compile tuple BIF differential module");
    reference
        .load(MODULE, &beam)
        .expect("load reference module");
    let expected = reference.call(MODULE, "run", &[]);
    let mut vm = crate::common::node();
    vm.load_bytes(&beam).expect("load tuple BIF module");
    let actual = vm
        .eval_scheduled(MODULE, "run", &[], 1)
        .expect("run tuple BIF differential module");
    assert_eq!(CallResult::Ok(actual.term), expected);
}
