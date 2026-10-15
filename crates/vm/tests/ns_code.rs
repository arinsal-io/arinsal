//! Code domains: module lookup per namespace chain (`arinsal_code` natives).
//!
//! Erlang sources are compiled at test time with the reference `erlc` on PATH; a test that
//! cannot compile is skipped with a message.

mod common;

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
-export([two_domains/0, worker/2, lookups/0, lookup_worker/2, dedup/0, load_worker/2, shadow/0, shadow_worker/2, ns_spawn/0, ns_worker/3, unloaded_base/0]).
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
dedup() ->
    D = arinsal_code:new_domain(0),
    ok = arinsal_code:load(D, [{dep, beam_dep()}]),
    A = arinsal_code:new_domain(D),
    Same = [{dd, beam_dd()}, {dep, beam_dep()}],
    Before = erlang:memory(code),
    SameResult = load_in([A, D, 0], Same),
    SameGrowth = erlang:memory(code) - Before,
    FreshResult = load_in([A, D, 0], [{w, beam_a()}]),
    FreshGrowth = erlang:memory(code) - Before,
    {SameResult, SameGrowth, FreshResult, FreshGrowth > 0}.
load_in(Chain, Modules) ->
    arinsal_code:spawn(Chain, ns_code_drv, load_worker, [self(), Modules]),
    receive {loaded, R} -> R after 5000 -> timeout end.
load_worker(Parent, {nocall, Modules}) ->
    Parent ! {loaded, [erlang:load_module(M, B) || {M, B} <- Modules]};
load_worker(Parent, Modules) ->
    Loaded = [erlang:load_module(M, B) || {M, B} <- Modules],
    Calls = [M:f() || {M, _} <- Modules],
    Parent ! {loaded, {Loaded, Calls}}.
shadow() ->
    [2, 1] = lists:reverse([1, 2]),
    A = arinsal_code:new_domain(0),
    arinsal_code:spawn([A, 0], ns_code_drv, shadow_worker, [self(), pp]),
    Domain = receive {shadow, R} -> R after 5000 -> timeout end,
    {Domain, lists:reverse([1, 2]), pp:'__protocol__'(x)}.
shadow_worker(Parent, P) ->
    Lists = erlang:load_module(lists, beam_fake_lists()),
    Protocol = erlang:load_module(P, beam_pp_domain()),
    Parent ! {shadow, {Lists, lists:reverse([1, 2]), Protocol, P:'__protocol__'(x)}}.
ns_spawn() ->
    true = arinsal_ns:expose(self()) =:= ok,
    D = arinsal_code:new_domain(0),
    ok = arinsal_code:load(D, [{dep, beam_dep()}]),
    {ok, Ns} = arinsal_ns:create(<<"acme">>, <<"shop">>, #{dep_domain => D}),
    #{code_chain := [Own | _] = Chain} = arinsal_ns:info(Ns),
    ok = arinsal_code:load(Own, [{w, beam_a()}, {a, beam_caller()}]),
    arinsal_ns:spawn(Ns, ns_code_drv, ns_worker, [self(), {w, a}, dep]),
    Result = receive {ns_worker, R} -> R after 5000 -> timeout end,
    {ok, Plain} = arinsal_ns:create(<<"acme">>, <<"plain">>, #{code_chain => [0]}),
    #{code_chain := PlainChain} = arinsal_ns:info(Plain),
    {Chain =:= [Own, D, 0], Result, PlainChain}.
ns_worker(Parent, Modules, Dep) ->
    Parent ! {ns_worker, try ns_work(Modules, Dep) catch Class:Reason:Stack -> {Class, Reason, Stack} end}.
ns_work(Modules, Dep) ->
    Self = self(),
    Child = spawn(fun() -> Self ! {child, arinsal_code:chain(self())} end),
    ChildChain = receive {child, C} -> C after 5000 -> Child end,
    {work(Modules), Dep:f(), ChildChain =:= arinsal_code:chain(self())}.
unloaded_base() ->
    false = erlang:module_loaded(orddict),
    A = arinsal_code:new_domain(0),
    Fake = load_in([A, 0], {nocall, [{orddict, beam_fake_orddict()}]}),
    Before = erlang:memory(code),
    Real = load_in([A, 0], {nocall, [{orddict, beam_real_orddict()}]}),
    Grown = erlang:memory(code) > Before,
    B = arinsal_code:new_domain(0),
    Again = erlang:memory(code),
    Second = load_in([B, 0], {nocall, [{orddict, beam_real_orddict()}]}),
    {Fake, Real, erlang:module_loaded(orddict), Grown, Second, erlang:memory(code) - Again}.
lookup(M) ->
    {erlang:module_loaded(M),
     erlang:function_exported(M, f, 0),
     erlang:function_exported(M, nope, 0),
     try lists:sort(erlang:get_module_info(M, exports)) catch error:badarg -> badarg end}.
"#;

const DEP: &str = "-module(dep).\n-export([f/0]).\nf() -> dep.\n";
const DD: &str = "-module(dd).\n-export([f/0]).\nf() -> dd.\n";
const FAKE_LISTS: &str = "-module(lists).\n-export([reverse/1]).\nreverse(_) -> fake.\n";

fn protocol(result: &str) -> String {
    format!("-module(pp).\n-export(['__protocol__'/1]).\n'__protocol__'(_) -> {result}.\n")
}

/// The bytes of OTP's own `module.beam`, as the reference `erl` on PATH finds it.
fn otp_beam(module: &str) -> Vec<u8> {
    let output = Command::new("erl")
        .args(["-noshell", "-eval"])
        .arg(format!(
            "io:format(\"~s\", [code:which({module})]), halt()."
        ))
        .output()
        .expect("run erl");
    std::fs::read(String::from_utf8_lossy(&output.stdout).trim()).expect("read the OTP beam")
}

/// Beams the driver embeds and the base ones loaded before it runs: `dd` and the base `pp`.
fn driver_vm(beam_a: &[u8], beam_b: &[u8]) -> Vm {
    let caller = compile("a", CALLER).expect("compile the caller module");
    let dep = compile("dep", DEP).expect("compile dep");
    let dd = compile("dd", DD).expect("compile dd");
    let fake_lists = compile("lists", FAKE_LISTS).expect("compile the fake lists");
    let pp_base = compile("pp", &protocol("base")).expect("compile pp");
    let pp_domain = compile("pp", &protocol("domain")).expect("compile pp");
    let fake_orddict = compile(
        "orddict",
        "-module(orddict).\n-export([f/0]).\nf() -> fake.\n",
    )
    .expect("compile the fake orddict");
    let real_orddict = otp_beam("orddict");
    let driver = format!(
        "{DRIVER}\nbeam_a() -> {}.\nbeam_b() -> {}.\nbeam_caller() -> {}.\nbeam_dep() -> {}.\n\
         beam_dd() -> {}.\nbeam_fake_lists() -> {}.\nbeam_pp_domain() -> {}.\n\
         beam_fake_orddict() -> {}.\nbeam_real_orddict() -> {}.\n",
        binary_literal(beam_a),
        binary_literal(beam_b),
        binary_literal(&caller),
        binary_literal(&dep),
        binary_literal(&dd),
        binary_literal(&fake_lists),
        binary_literal(&pp_domain),
        binary_literal(&fake_orddict),
        binary_literal(&real_orddict)
    );
    let driver = compile("ns_code_drv", &driver).expect("compile the driver");
    let mut vm = Vm::new([]);
    vm.load_bytes(&driver).unwrap();
    vm.load_bytes(&dd).unwrap();
    vm.load_bytes(&pp_base).unwrap();
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

/// A domain process loading a module identical (same md5) to the one its chain already sees,
/// in the base (`dd`) or an outer domain (`dep`), gets success and code memory does not grow;
/// a new module does grow it.
#[test]
fn ns_code_md5_dedup() {
    let (Some(beam_a), Some(beam_b)) = (
        compile("w", &worker_module("a")),
        compile("w", &worker_module("b")),
    ) else {
        eprintln!("erlc unavailable; skipping ns_code_md5_dedup");
        return;
    };
    let mut vm = driver_vm(&beam_a, &beam_b);
    let result = vm
        .eval_scheduled("ns_code_drv", "dedup", &[], 2, None)
        .unwrap();
    assert_eq!(
        result.text,
        "{{[{module,dd},{module,dep}],[dd,dep]},0,{[{module,w}],[a]},true}"
    );
}

/// A domain cannot replace a base module with different code (`not_allowed`), and both the
/// domain and root keep the base `lists`; a consolidated protocol may shadow the base one in
/// the domain only.
#[test]
fn ns_code_base_not_shadowable() {
    let (Some(beam_a), Some(beam_b)) = (
        compile("w", &worker_module("a")),
        compile("w", &worker_module("b")),
    ) else {
        eprintln!("erlc unavailable; skipping ns_code_base_not_shadowable");
        return;
    };
    let mut vm = driver_vm(&beam_a, &beam_b);
    let result = vm
        .eval_scheduled("ns_code_drv", "shadow", &[], 2, None)
        .unwrap();
    assert_eq!(
        result.text,
        "{{{error,not_allowed},[2,1],{module,pp},domain},[2,1],base}"
    );
}

/// `arinsal_ns:create/3` gives the namespace a fresh domain over its `dep_domain`; a process
/// spawned with `arinsal_ns:spawn/4` (and its own children) has that chain, reaching the
/// namespace's `w` and `a` and the dep domain's `dep`. `code_chain => [0]` is the base only.
#[test]
fn ns_code_ns_spawn_gets_chain() {
    let (Some(beam_a), Some(beam_b)) = (
        compile("w", &worker_module("a")),
        compile("w", &worker_module("b")),
    ) else {
        eprintln!("erlc unavailable; skipping ns_code_ns_spawn_gets_chain");
        return;
    };
    let mut vm = driver_vm(&beam_a, &beam_b);
    let result = vm
        .eval_scheduled("ns_code_drv", "ns_spawn", &[], 2, None)
        .unwrap();
    assert_eq!(
        result.text,
        "{true,{{a,a,a,a,{fun_result,a},{static,a,[2,1]},[2,1,0]},dep,true},[0]}"
    );
}

/// A domain load of a name the base has not loaded but finds on the node's code path compares
/// with that beam: different code is `not_allowed`; the same code loads into the base, once,
/// and a second domain loading it again adds no code.
#[test]
fn ns_code_unloaded_base_name_not_allowed() {
    let (Some(beam_a), Some(beam_b)) = (
        compile("w", &worker_module("a")),
        compile("w", &worker_module("b")),
    ) else {
        eprintln!("erlc unavailable; skipping ns_code_unloaded_base_name_not_allowed");
        return;
    };
    let mut vm = driver_vm(&beam_a, &beam_b);
    let result = vm
        .eval_scheduled("ns_code_drv", "unloaded_base", &[], 2, None)
        .unwrap();
    assert_eq!(
        result.text,
        "{[{error,not_allowed}],[{module,orddict}],true,true,[{module,orddict}],0}"
    );
}

const CLI_PROBE: &str = r#"
-module(ns_code_cli).
-export([run/0, child/2]).
run() ->
    D = arinsal_code:new_domain(0),
    arinsal_code:spawn([D], ?MODULE, child, [self(), w]),
    Child = receive {child, R} -> R after 10000 -> timeout end,
    {Child, erlang:module_loaded(w), code:is_loaded(w), try w:f() catch error:undef -> undef end}.
child(Parent, M) ->
    Result = try
        {code:load_binary(M, "w.beam", beam_w()), M:f(), erlang:module_loaded(M)}
    catch
        Class:Reason:Stack -> {Class, Reason, Stack}
    end,
    Parent ! {child, Result}.
"#;

/// On a booted node, a process with a chain loads `w` with `code:load_binary/3` (the code
/// server finishes the load) into its own domain and calls it; root does not see the module.
#[test]
fn ns_code_load_into_caller_domain() {
    let Some(beam_w) = compile("w", &worker_module("a")) else {
        eprintln!("erlc unavailable; skipping ns_code_load_into_caller_domain");
        return;
    };
    let source = format!("{CLI_PROBE}\nbeam_w() -> {}.\n", binary_literal(&beam_w));
    let probe = compile("ns_code_cli", &source).expect("compile the probe");
    let result = common::arinsal_once("ns_code_cli", &probe, "ns_code_cli:run()");
    // `code:is_loaded/1` answers from the code server's table, which records every module it
    // finished loading, whatever the domain.
    assert_eq!(
        format!("{result:?}"),
        "Tuple([Tuple([Tuple([Atom(\"module\"), Atom(\"w\")]), Atom(\"a\"), Atom(\"true\")]), \
         Atom(\"false\"), Tuple([Atom(\"file\"), List { elems: [Int(119), Int(46), Int(98), \
         Int(101), Int(97), Int(109)], tail: Nil }]), Atom(\"undef\")])"
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
