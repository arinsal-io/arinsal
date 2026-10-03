//! Regressions for VM crashes found by the erts suite run: a handler installed after a failing
//! BIF that exhausted the slice, and a stack trace whose arguments are a deeply nested term.

use arinsal_difftest::{CallResult, RefErl};
use arinsal_vm::Vm;

const SOURCE: &str = r#"
-module(crash_reg).
-export([limit_catch/0, limit_try/0, limit_class/0, deep_args/0]).

%% A negative maximum bignum minus one fails with system_limit after a huge reduction
%% charge; the handler must still see x0-x3 and keep the saved stack trace alive.
limit_catch() ->
    M = -erlang:system_info(max_integer),
    {'EXIT', {Reason, Stack}} = (catch M - 1),
    {Reason, is_list(Stack)}.
limit_try() ->
    M = -erlang:system_info(max_integer),
    try M - 1 catch C:E:S -> {C, E, is_list(S), length(S) > 0} end.
limit_class() ->
    M = -erlang:system_info(max_integer),
    try M - 1 catch C:E -> {C, E} end.

nest(0, Acc) -> Acc;
nest(N, Acc) -> nest(N - 1, [Acc, $a]).

%% Rebuilding the stack trace used to deep-clone the 300000-level argument and overflow the
%% native stack.
deep_args() ->
    A = [[nest(300000, []), oops]],
    erlang:yield(),
    try erlang:list_to_binary(A) catch error:E:S -> [{M, F, _, _} | _] = S, {E, M, F} end.
"#;

#[test]
fn crashes_match_otp() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping crash regression test");
        return;
    };
    let beam = reference.compile_named("crash_reg", SOURCE, &[]).unwrap();
    reference.load("crash_reg", &beam).unwrap();
    for function in ["limit_catch", "limit_try", "limit_class", "deep_args"] {
        let expected = reference.call("crash_reg", function, &[]);
        let mut vm = Vm::new([]);
        vm.load_bytes(&beam).unwrap();
        let actual = vm
            .eval_scheduled("crash_reg", function, &[], 1, None)
            .map(|result| result.term)
            .unwrap_or_else(|error| panic!("{function}: VM error {error:?}"));
        assert_eq!(expected, CallResult::Ok(actual), "{function}");
    }
}
