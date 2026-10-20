//! Stack traces of exceptions raised by a function or BIF reached through a tail `apply/2`,
//! `apply/3`, fixed `M:F(Args)` apply or tail fun call: the apply deallocates the caller's frame
//! first (BeamAsm `emit_i_apply_last`, `emit_i_apply_fun_last`), so the caller's function must not
//! appear in the trace, except for `error`/`exit`/`throw` applied through `apply/3` or a fixed
//! apply, which erts adjusts (`apply_bif_error_adjustment`). Compared with erl under the JIT and
//! `ARINSAL_INTERP=1`.

use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_vm::Vm;
use std::process::Command;

const CHILD: &str = "ARINSAL_TAIL_APPLY_TRACE_CHILD";
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
    let mut vm = Vm::new([]);
    vm.load_bytes(beam).unwrap();
    let actual = vm.eval_scheduled(MODULE, function, &[], 2, None).unwrap();
    format!("{:?}", actual.term)
}

fn child() -> bool {
    let Some(beam_path) = std::env::var_os(CHILD) else {
        return false;
    };
    println!(
        "RESULT:{}",
        run_here(&std::fs::read(&beam_path).unwrap(), "run")
    );
    true
}

#[test]
fn tail_apply_stacktraces_match_erl() {
    if child() {
        return;
    }
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

    // The JIT is the default: run in this process.
    similar_asserts::assert_eq!(run_here(&beam, "run"), want, "JIT {MODULE}:run");
    // badfun and badarity of the tail fun call itself: the interpreter reports one frame more
    // than erts (a gap that predates this test), so only the JIT is compared.
    let want_jit = match reference.call(MODULE, "run_jit", &[]) {
        CallResult::Ok(term) => format!("{term:?}"),
        other => panic!("{MODULE}:run_jit on erl: {other:?}"),
    };
    similar_asserts::assert_eq!(run_here(&beam, "run_jit"), want_jit, "JIT {MODULE}:run_jit");

    // The interpreter: the flavour is fixed per process, so run in a child.
    let dir = std::env::temp_dir().join(format!("arinsal-tail-apply-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(format!("{MODULE}.beam"));
    std::fs::write(&path, &beam).unwrap();
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "tail_apply_stacktraces_match_erl",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD, &path)
        .env("ARINSAL_INTERP", "1")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    assert!(
        output.status.success(),
        "interpreter child failed: {stdout} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let _ = std::fs::remove_dir_all(&dir);
    let start = stdout.find("RESULT:").expect("interpreter result") + "RESULT:".len();
    let line = stdout[start..].lines().next().unwrap_or_default();
    similar_asserts::assert_eq!(line, want, "interpreter {MODULE}:run");
}
