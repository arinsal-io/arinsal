//! `erlang:make_fun/3` called from native code (the light BIF entry) matches erts.

use arinsal_difftest::{CallResult, RefErl};
use arinsal_vm::Vm;

const SOURCE: &str = r#"
-module(make_fun_diff).
-export([run/0]).

bad(F) ->
    try F() catch error:R -> R end.

run() ->
    M = lists, F = seq,
    Fun = erlang:make_fun(M, F, 2),
    Missing = erlang:make_fun(no_such_module_xyz, nope, 3),
    Info = [erlang:fun_info(Fun, K) || K <- [arity, type, module, name, env]],
    Bad = [bad(fun() -> erlang:make_fun(A, B, C) end)
           || {A, B, C} <- [{1, F, 2}, {M, "f", 2}, {M, F, a}, {M, F, -1}, {M, F, 256},
                            {M, F, 1 bsl 70}, {M, F, 2.0}]],
    Edge = [erlang:fun_info(erlang:make_fun(M, F, N), arity) || N <- [0, 255]],
    {Fun =:= fun lists:seq/2, Fun(1, 3), Info, Bad, Edge,
     is_function(Missing, 3), bad(fun() -> Missing(1, 2, 3) end),
     erlang:make_fun(M, F, 2) =:= Fun}.
"#;

#[test]
fn make_fun_matches_erts() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping make_fun light test");
        return;
    };
    let beam = reference
        .compile_named("make_fun_diff", SOURCE, &[])
        .expect("compile fixture");
    reference
        .load("make_fun_diff", &beam)
        .expect("load reference");
    let expected = reference.call("make_fun_diff", "run", &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).expect("load VM fixture");
    let actual = vm
        .eval_scheduled("make_fun_diff", "run", &[], 1, None)
        .unwrap_or_else(|error| panic!("run: {error}"));
    assert_eq!(expected, CallResult::Ok(actual.term));
}
