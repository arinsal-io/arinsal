//! Stack traces of exceptions raised by a function or BIF reached through a tail `apply/2`,
//! `apply/3`, fixed `M:F(Args)` apply or tail fun call: the apply deallocates the caller's frame
//! first (BeamAsm `emit_i_apply_last`, `emit_i_apply_fun_last`), so the caller's function must not
//! appear in the trace, except for `error`/`exit`/`throw` applied through `apply/3` or a fixed
//! apply, which erts adjusts (`apply_bif_error_adjustment`). Compared with erl.

use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;

const MODULE: &str = "tail_apply_trace";

const SOURCE: &str = r#"-module(tail_apply_trace).
-export([run/0, run_jit/0, thrower/1]).
id(X) -> X.
run() ->
    [{K, st(K)} || K <- [apply3, apply2, funlast, applyfixed, fixedmf, extlast, applybif,
                         applyfunbif, funbif, self_ext_last, fixederr, fixedexit, fixedthrow,
                         funerr, applyfunerr, apply3throw, apply2_arith, apply3_badarg,
                         funlast_badarg, fixedbad, apply3bad, apply2badlist]].
%% Failures of the fun call itself in tail position.
run_jit() -> [{K, st(K)} || K <- [funbadarity, funbadfun]].
st(K) ->
    try outer(K) of _ -> none
    catch _:_:S ->
        [{M, F, A} || {M, F, A, _} <- lists:takewhile(fun({M, F, _, _}) -> {M, F} =/= {tail_apply_trace, st} end, S)]
    end.
outer(K) -> X = id(K), inner(X), ok.
inner(apply3) -> Z = id(1), _ = Z, erlang:apply(tail_apply_trace, thrower, id([a]));
inner(apply2) -> Z = id(1), _ = Z, erlang:apply(fun tail_apply_trace:thrower/1, id([a]));
inner(funlast) -> Z = id(1), _ = Z, F = id(fun tail_apply_trace:thrower/1), F(a);
inner(applyfixed) -> Z = id(1), _ = Z, M = id(tail_apply_trace), M:thrower(a);
inner(fixedmf) -> Z = id(1), _ = Z, M = id(erlang), M:'+'(1, a);
inner(extlast) -> Z = id(1), _ = Z, erlang:'+'(1, id(a));
inner(applybif) -> Z = id(1), _ = Z, erlang:apply(erlang, '+', id([1, a]));
inner(applyfunbif) -> Z = id(1), _ = Z, erlang:apply(fun erlang:'+'/2, id([1, a]));
inner(funbif) -> Z = id(1), _ = Z, F = id(fun erlang:'+'/2), F(1, a);
inner(fixederr) -> Z = id(1), _ = Z, M = id(erlang), M:error(oops);
inner(fixedexit) -> Z = id(1), _ = Z, M = id(erlang), M:exit(oops);
inner(fixedthrow) -> Z = id(1), _ = Z, M = id(erlang), M:throw(oops);
inner(funerr) -> Z = id(1), _ = Z, F = id(fun erlang:error/1), F(oops);
inner(applyfunerr) -> Z = id(1), _ = Z, erlang:apply(fun erlang:error/1, id([oops]));
inner(apply3throw) -> Z = id(1), _ = Z, erlang:apply(erlang, throw, id([oops]));
inner(apply2_arith) -> Z = id(1), _ = Z, erlang:apply(fun erlang:'-'/2, id([a, 1]));
inner(apply3_badarg) -> Z = id(1), _ = Z, erlang:apply(erlang, length, id([a]));
inner(funlast_badarg) -> Z = id(1), _ = Z, F = id(fun erlang:length/1), F(a);
inner(fixedbad) -> Z = id(1), _ = Z, M = id(1), M:foo();
inner(apply3bad) -> Z = id(1), _ = Z, erlang:apply(id(1), foo, id([]));
inner(apply2badlist) -> Z = id(1), _ = Z, erlang:apply(fun tail_apply_trace:thrower/1, id(foo));
inner(funbadarity) -> Z = id(1), _ = Z, F = id(fun tail_apply_trace:thrower/1), F(1, 2);
inner(funbadfun) -> Z = id(1), _ = Z, F = id(not_a_fun), F(1);
inner(self_ext_last) -> Z = id(1), _ = Z, erlang:apply(erlang, error, id([oops])).
thrower(_) -> erlang:error(oops).
"#;

fn run_here(beam: &[u8], function: &str) -> String {
    let mut vm = crate::common::node();
    vm.load_bytes(beam).unwrap();
    let actual = vm.eval_scheduled(MODULE, function, &[], 2).unwrap();
    format!("{:?}", actual.term)
}

#[test]
fn tail_apply_stacktraces_match_erl() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping tail apply stacktrace test");
        return;
    };
    let beam = reference
        .compile_named(MODULE, SOURCE, &[])
        .expect("compile tail_apply_trace");
    reference.load(MODULE, &beam).expect("load into erl");
    let want: OwnedTerm = match reference.call(MODULE, "run", &[]) {
        CallResult::Ok(term) => term,
        other => panic!("{MODULE}:run on erl: {other:?}"),
    };
    let want = format!("{want:?}");

    similar_asserts::assert_eq!(run_here(&beam, "run"), want, "{MODULE}:run");
    // badfun and badarity of the tail fun call itself.
    let want_jit = match reference.call(MODULE, "run_jit", &[]) {
        CallResult::Ok(term) => format!("{term:?}"),
        other => panic!("{MODULE}:run_jit on erl: {other:?}"),
    };
    similar_asserts::assert_eq!(run_here(&beam, "run_jit"), want_jit, "{MODULE}:run_jit");
}
