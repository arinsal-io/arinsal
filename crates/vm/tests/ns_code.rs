//! Code domains: module lookup per namespace chain (`arinsal_code` natives).
//!
//! Erlang sources are compiled at test time with the reference `erlc` on PATH; a test that
//! cannot compile is skipped with a message.

use arinsal_etf::OwnedTerm;
use arinsal_term::Term;
use arinsal_vm::Vm;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

fn compile(name: &str, source: &str) -> Option<Vec<u8>> {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "arinsal-ns-code-{}-{name}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).ok()?;
    let file = dir.join(format!("{name}.erl"));
    std::fs::write(&file, source).ok()?;
    let status = Command::new("erlc")
        .arg("-o")
        .arg(&dir)
        .arg(&file)
        .status()
        .ok()?;
    let bytes = status
        .success()
        .then(|| std::fs::read(dir.join(format!("{name}.beam"))).ok())
        .flatten();
    let _ = std::fs::remove_dir_all(&dir);
    bytes
}

fn int(term: &OwnedTerm) -> i64 {
    match term {
        OwnedTerm::Int(value) => *value,
        other => panic!("expected an integer, got {other:?}"),
    }
}

/// An Erlang binary literal of `bytes`.
fn binary_literal(bytes: &[u8]) -> String {
    let body: Vec<String> = bytes.iter().map(u8::to_string).collect();
    format!("<<{}>>", body.join(","))
}

/// Calls `w` statically, so the call resolves through the chain of this instance's domain.
const CALLER: &str =
    "-module(a).\n-export([run/0]).\nrun() -> {static, w:f(), lists:reverse([1, 2])}.\n";

fn worker_module(result: &str) -> String {
    format!(
        "-module(w).\n-export([f/0, g/1, h/0]).\n\
         f() -> {result}.\n\
         g(Parent) -> Parent ! {{g, f()}}.\n\
         h() -> fun() -> {{fun_result, f()}} end.\n"
    )
}

const DRIVER: &str = r#"
-module(ns_code_drv).
-export([two_domains/0, worker/2, lookups/0, lookup_worker/2]).
two_domains() ->
    A = arinsal_code:new_domain(0),
    B = arinsal_code:new_domain([0]),
    ok = arinsal_code:load(A, [{w, beam_a()}, {a, beam_caller()}]),
    ok = arinsal_code:load(B, [{a, beam_caller()}, {w, beam_b()}]),
    Self = self(),
    arinsal_code:spawn([A, 0], ns_code_drv, worker, [Self, {w, a}]),
    arinsal_code:spawn([B], ns_code_drv, worker, [Self, {w, a}]),
    Results = [receive {worker, R} -> R after 5000 -> timeout end || _ <- [1, 2]],
    Root = erlang:module_loaded(w),
    {lists:sort(Results), [A, B], Root, arinsal_code:chain(self())}.
worker(Parent, M) ->
    Parent ! {worker, try work(M) catch Class:Reason:Stack -> {Class, Reason, Stack} end}.
work({M, Caller}) ->
    Variable = M:f(),
    Apply = apply(M, f, []),
    Nested = erlang:apply(erlang, apply, [M, f, []]),
    spawn(M, g, [self()]),
    Spawned = receive {g, G} -> G after 5000 -> timeout end,
    Fun = M:h(),
    FunResult = Fun(),
    Static = Caller:run(),
    {Variable, Apply, Nested, Spawned, FunResult, Static, arinsal_code:chain(self())}.
lookups() ->
    A = arinsal_code:new_domain(0),
    ok = arinsal_code:load(A, [{w, beam_a()}]),
    arinsal_code:spawn([A, 0], ns_code_drv, lookup_worker, [self(), w]),
    Domain = receive {lookups, R} -> R after 5000 -> timeout end,
    {Domain, lookup(w)}.
lookup_worker(Parent, M) ->
    Parent ! {lookups, try lookup(M) catch Class:Reason:Stack -> {Class, Reason, Stack} end}.
lookup(M) ->
    {erlang:module_loaded(M),
     erlang:function_exported(M, f, 0),
     erlang:function_exported(M, nope, 0),
     try lists:sort(erlang:get_module_info(M, exports)) catch error:badarg -> badarg end}.
"#;

fn driver_vm(beam_a: &[u8], beam_b: &[u8]) -> Vm {
    let caller = compile("a", CALLER).expect("compile the caller module");
    let driver = format!(
        "{DRIVER}\nbeam_a() -> {}.\nbeam_b() -> {}.\nbeam_caller() -> {}.\n",
        binary_literal(beam_a),
        binary_literal(beam_b),
        binary_literal(&caller)
    );
    let driver = compile("ns_code_drv", &driver).expect("compile the driver");
    let mut vm = Vm::new([]);
    vm.load_bytes(&driver).unwrap();
    vm
}

/// Domains A and B each load their own `w`; processes with chains `[A, 0]` and `[B, 0]` reach
/// their own `w` through variable-module calls, `apply`, spawn MFAs, funs and static calls from
/// their domain's module `a`; root does not see `w`.
#[test]
fn ns_code_two_domains_same_module_name() {
    let (Some(beam_a), Some(beam_b)) = (
        compile("w", &worker_module("a")),
        compile("w", &worker_module("b")),
    ) else {
        eprintln!("erlc unavailable; skipping ns_code_two_domains_same_module_name");
        return;
    };
    let mut vm = driver_vm(&beam_a, &beam_b);
    let result = vm
        .eval_scheduled("ns_code_drv", "two_domains", &[], 2, None)
        .unwrap();
    assert_eq!(
        result.text,
        "{[{a,a,a,a,{fun_result,a},{static,a,[2,1]},[1,0]},\
          {b,b,b,b,{fun_result,b},{static,b,[2,1]},[2,0]}],[1,2],false,[0]}"
    );
}

/// `module_loaded/1`, `function_exported/3` and `get_module_info/2` answer through the calling
/// process's chain: a domain process sees its `w`, root does not.
#[test]
fn ns_code_lookup_natives_follow_chain() {
    let (Some(beam_a), Some(beam_b)) = (
        compile("w", &worker_module("a")),
        compile("w", &worker_module("b")),
    ) else {
        eprintln!("erlc unavailable; skipping ns_code_lookup_natives_follow_chain");
        return;
    };
    let mut vm = driver_vm(&beam_a, &beam_b);
    let result = vm
        .eval_scheduled("ns_code_drv", "lookups", &[], 2, None)
        .unwrap();
    assert_eq!(
        result.text,
        "{{true,true,false,[{f,0},{g,1},{h,0},{module_info,0},{module_info,1}]},\
          {false,false,false,badarg}}"
    );
}

const BENCH: &str = r#"
-module(ns_code_bench).
-export([apply_loop/1, static_loop/1, f/1]).
f(N) -> N.
apply_loop(N) ->
    T0 = erlang:monotonic_time(nanosecond),
    apply_loop(N, ?MODULE, f),
    erlang:monotonic_time(nanosecond) - T0.
apply_loop(0, _, _) -> ok;
apply_loop(N, M, F) -> M:F(N), apply(M, F, [N]), apply_loop(N - 1, M, F).
static_loop(N) ->
    T0 = erlang:monotonic_time(nanosecond),
    static_loop1(N),
    erlang:monotonic_time(nanosecond) - T0.
static_loop1(0) -> ok;
static_loop1(N) -> ?MODULE:f(N), static_loop1(N - 1).
"#;

/// Root (ns 0) dynamic and static calls; prints a timing of 2M dynamic and 1M static calls.
#[test]
fn ns_code_root_unchanged() {
    let Some(beam) = compile("ns_code_bench", BENCH) else {
        eprintln!("erlc unavailable; skipping ns_code_root_unchanged");
        return;
    };
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let n = Term::small(1_000_000).unwrap();
    let mut best_apply = i64::MAX;
    let mut best_static = i64::MAX;
    for _ in 0..5 {
        let apply = vm
            .eval_scheduled("ns_code_bench", "apply_loop", &[n], 1, None)
            .unwrap();
        best_apply = best_apply.min(int(&apply.term));
        let stat = vm
            .eval_scheduled("ns_code_bench", "static_loop", &[n], 1, None)
            .unwrap();
        best_static = best_static.min(int(&stat.term));
    }
    eprintln!(
        "ns_code_root_unchanged: 2M dynamic calls {:.2} ms, 1M static calls {:.2} ms",
        best_apply as f64 / 1e6,
        best_static as f64 / 1e6
    );
}
