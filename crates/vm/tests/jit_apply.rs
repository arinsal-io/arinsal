//! Differential test: `apply/2`, `apply/3`, `node/0` and `os:perf_counter/0` compiled as
//! instructions (OTP-29.1.1 jit/arm/ops.tab:605-735) behave like erts, for successful
//! applies of every target kind and for every error case.

use arinsal_difftest::{CallResult, RefErl};
use arinsal_vm::Vm;

const SOURCE: &str = r#"-module(jit_apply).
-export([run/0, f/0, f/1, f/2, f/7, f/8, many/10]).
f() -> zero.
f(X) -> {one, X}.
f(X, Y) -> {two, X, Y}.
f(A, B, C, D, E, F, G) -> [A, B, C, D, E, F, G].
f(A, B, C, D, E, F, G, H) -> [A, B, C, D, E, F, G, H].
many(A, B, C, D, E, F, G, H, I, J) -> lists:sum([A, B, C, D, E, F, G, H, I, J]).
%% Funs differ between nodes only in identity; errors keep the reason's shape and the top frame.
shape(F) when is_function(F) -> 'fun';
shape(T) when is_tuple(T) -> list_to_tuple([shape(E) || E <- tuple_to_list(T)]);
shape(L) when is_list(L) -> [shape(E) || E <- L];
shape(T) -> T.
top([{M, F, A, _} | _]) when is_list(A) -> {M, F, length(A)};
top([{M, F, A, _} | _]) -> {M, F, A}.
r(F) -> try F() of V -> {ok, shape(V)} catch C:R:S -> {C, shape(R), top(S)} end.
a3(M, F, A) -> apply(M, F, A).
a3l(M, F, A) -> X = apply(M, F, A), {X}.
a2(F, A) -> apply(F, A).
a2l(F, A) -> X = apply(F, A), {X}.
n() -> node().
run() ->
    L = lists:seq(1, 10),
    Fun7 = fun(A, B, C, D, E, F, G) -> {A, B, C, D, E, F, G} end,
    Y = 5,
    Clo = fun(A, B) -> A + B + Y end,
    Tests = [
      fun() -> a3(jit_apply, f, []) end,
      fun() -> a3(jit_apply, f, [1]) end,
      fun() -> a3l(jit_apply, f, [1, 2]) end,
      fun() -> a3(jit_apply, f, [1, 2, 3, 4, 5, 6, 7]) end,
      fun() -> a3l(jit_apply, f, [1, 2, 3, 4, 5, 6, 7, 8]) end,
      fun() -> a3(jit_apply, many, L) end,
      fun() -> a3(erlang, apply, [jit_apply, f, [x]]) end,
      fun() -> a3(erlang, apply, [erlang, apply, [jit_apply, f, [x, y]]]) end,
      fun() -> a3(erlang, apply, [jit_apply, f]) end,
      fun() -> a3(lists, reverse, [[1, 2, 3]]) end,
      fun() -> a3(erlang, put, [k, v]) end,
      fun() -> a3(erlang, length, [[1, 2]]) end,
      fun() -> a3(jit_apply, nope, []) end,
      fun() -> a3(jit_apply, r, [1]) end,
      fun() -> a3(nomod, f, [1]) end,
      fun() -> a3(jit_apply, f, [1 | 2]) end,
      fun() -> a3(jit_apply, f, x) end,
      fun() -> a3({jit_apply}, f, [1]) end,
      fun() -> a3(jit_apply, "f", [1]) end,
      fun() -> a3(1, f, [1]) end,
      fun() -> a3(jit_apply, f, lists:seq(1, 2000)) end,
      fun() -> a2(fun jit_apply:f/1, [1]) end,
      fun() -> a2l(fun jit_apply:f/2, [1, 2]) end,
      fun() -> a2(fun jit_apply:f/7, [1, 2, 3, 4, 5, 6, 7]) end,
      fun() -> a2(Fun7, [1, 2, 3, 4, 5, 6, 7]) end,
      fun() -> a2l(Clo, [1, 2]) end,
      fun() -> a2(Clo, [1]) end,
      fun() -> a2(Clo, [1 | 2]) end,
      fun() -> a2(Clo, x) end,
      fun() -> a2(notfun, [1]) end,
      fun() -> a2({a, b}, [1]) end,
      fun() -> a2(fun jit_apply:nope/1, [1]) end,
      fun() -> a2(fun erlang:length/1, [[1, 2, 3]]) end,
      fun() -> a2(fun lists:seq/2, [1, 3]) end,
      fun() -> a2(fun() -> ok end, []) end,
      fun() -> a2(Clo, lists:seq(1, 300)) end,
      fun() -> a2(Clo, lists:seq(1, 2000)) end,
      fun() -> n() =:= node() end,
      fun() -> P = os:perf_counter(), Q = os:perf_counter(), is_integer(P) andalso Q >= P end,
      fun() -> erlang:yield() end
    ],
    [r(T) || T <- Tests].
"#;

#[test]
fn apply_node_and_perf_counter_instructions_match_erts() {
    let reference = RefErl::start().expect("OTP 29.1.1 is required for this test");
    let beam = reference.compile_named("jit_apply", SOURCE, &[]).unwrap();
    reference.load("jit_apply", &beam).unwrap();
    let CallResult::Ok(expected) = reference.call("jit_apply", "run", &[]) else {
        panic!("reference run failed");
    };
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm.eval_scheduled("jit_apply", "run", &[], 1, None).unwrap();
    assert_eq!(actual.term, expected);
}
