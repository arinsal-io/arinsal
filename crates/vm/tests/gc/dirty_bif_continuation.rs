//! Dirty BIF completion enters the same trace-visible continuation as erts.

use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_vm::Vm;

const SOURCE: &str = r#"
-module(dirty_bif_continuation).
-export([run/0, worker/1, caller/0, reschedule/1, current_info/0, info_worker/1, exception/0,
         exception_run/0, exception_worker/1, heap_args_run/0]).

run() ->
    Parent = self(),
    Tracer = spawn(fun() -> relay(Parent) end),
    Pid = spawn(dirty_bif_continuation, worker, [Parent]),
    erlang:trace_pattern({dirty_bif_continuation, caller, 0}, [{'_', [], [{return_trace}]}], [local]),
    erlang:trace(Pid, true, [call, return_to, {tracer, Tracer}]),
    Pid ! go,
    receive {done, Pid} -> ok after 5000 -> timeout end,
    Events = collect([]),
    erlang:trace_pattern({dirty_bif_continuation, caller, 0}, false, [local]),
    Events.

worker(Parent) ->
    receive go -> caller(), Parent ! {done, self()} end.

caller() ->
    erts_debug:dirty_cpu(wait, 5),
    ok.

reschedule(Rounds) -> erts_debug:dirty_cpu(reschedule, Rounds).

exception() ->
    try erts_debug:dirty_cpu(error, badarith)
    catch Class:Reason:Stacktrace ->
        {Class, Reason, [{M, F, A} || {M, F, A, _} <- Stacktrace]}
    end.

%% The caller chain of the trace must not depend on the harness, so the exception runs in
%% a spawned worker in both runtimes.
exception_worker(Parent) ->
    Parent ! {exception, self(), exception()}.

exception_run() ->
    Pid = spawn(dirty_bif_continuation, exception_worker, [self()]),
    receive {exception, Pid, Result} -> Result after 5000 -> timeout end.

info_worker(Parent) ->
    Parent ! {ready, self()},
    erts_debug:dirty_cpu(wait, 500),
    Parent ! done.

current_info() ->
    Pid = spawn(dirty_bif_continuation, info_worker, [self()]),
    receive {ready, Pid} -> timer:sleep(50) end,
    Info = {process_info(Pid, current_function),
            process_info(Pid, current_stacktrace)},
    receive done -> Info end.

%% Heap arguments of a scheduled dirty BIF stay GC roots: a collection after the schedule
%% (more likely with some heap sizes) must not leave them stale in the exception trace.
heap_args_run() ->
    Parent = self(),
    [begin
         {Pid, Ref} = spawn_opt(fun() -> Parent ! {heap_args, self(), heap_args(20)} end,
                                [monitor, {min_heap_size, H}]),
         receive
             {heap_args, Pid, R} -> {H, R};
             {'DOWN', Ref, _, _, Why} -> {H, down, Why}
         end
     end || H <- [233, 1000, 2000, 5000, 10000]].

heap_args(0) -> ok;
heap_args(N) ->
    Terms = [make_ref(), {another, "heap", term_to_binary("term")}],
    Calls = [{dirty_cpu, [error, T]} || T <- Terms] ++ [{dirty_io, [error, T]} || T <- Terms]
        ++ [{dirty, [S, error, T]} || S <- [dirty_cpu, dirty_io], T <- Terms],
    Bad = [{F, A} || {F, A} <- Calls,
                     not (heap_args_ok(F, A, fun() -> apply(erts_debug, F, A) end)
                          andalso heap_args_ok(F, A, fun() -> direct(F, A) end))],
    case Bad of [] -> heap_args(N - 1); _ -> {bad, Bad} end.

direct(dirty_cpu, [X, Y]) -> erts_debug:dirty_cpu(X, Y);
direct(dirty_io, [X, Y]) -> erts_debug:dirty_io(X, Y);
direct(dirty, [X, Y, Z]) -> erts_debug:dirty(X, Y, Z).

heap_args_ok(F, A, Fun) ->
    try Fun() of _ -> false
    catch error:badarg:Stk ->
        case Stk of [{erts_debug, F, A1, _} | _] -> A1 =:= A; _ -> false end
    end.

relay(Parent) -> receive Event -> Parent ! {trace_event, Event}, relay(Parent) end.

collect(Acc) ->
    receive
        {trace_event, {trace, _, call, {dirty_bif_continuation, caller, _}}} -> collect([call | Acc]);
        {trace_event, {trace, _, return_to, {M, F, A}}} -> collect([{return_to, M, F, A} | Acc]);
        {trace_event, {trace, _, return_from, {dirty_bif_continuation, caller, A}, _}} ->
            collect([{return_from, A} | Acc]);
        {trace_event, _} -> collect(Acc)
    after 100 -> lists:reverse(Acc)
    end.
"#;

#[test]
fn dirty_bif_resume_trace_matches_erts() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping dirty BIF continuation trace test");
        return;
    };
    let beam = reference
        .compile_named("dirty_bif_continuation", SOURCE, &[])
        .expect("compile dirty BIF continuation test");
    reference
        .load("dirty_bif_continuation", &beam)
        .expect("load reference module");
    let expected = reference.call("dirty_bif_continuation", "run", &[]);
    assert!(
        matches!(
            &expected,
            CallResult::Ok(OwnedTerm::List { elems, .. }) if !elems.is_empty()
        ),
        "reference trace must contain events: {expected:?}"
    );

    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).expect("load Arinsal module");
    let actual = vm
        .eval_scheduled("dirty_bif_continuation", "run", &[], 2, None)
        .expect("run dirty BIF trace test");
    similar_asserts::assert_eq!(expected, CallResult::Ok(actual.term));
}

#[test]
fn dirty_bif_multischedule_matches_erts() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping dirty BIF multischedule test");
        return;
    };
    let beam = reference
        .compile_named("dirty_bif_continuation", SOURCE, &[])
        .expect("compile dirty BIF continuation test");
    reference
        .load("dirty_bif_continuation", &beam)
        .expect("load reference module");
    let expected = reference.call(
        "dirty_bif_continuation",
        "reschedule",
        &[OwnedTerm::Int(12)],
    );

    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).expect("load Arinsal module");
    let actual = vm
        .eval_scheduled(
            "dirty_bif_continuation",
            "reschedule",
            &[arinsal_term::Term::small(12).unwrap()],
            2,
            None,
        )
        .expect("run dirty BIF multischedule test");
    similar_asserts::assert_eq!(expected, CallResult::Ok(actual.term));
}

#[test]
fn dirty_bif_inflight_process_info_matches_erts() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping dirty BIF in-flight process info test");
        return;
    };
    let beam = reference
        .compile_named("dirty_bif_continuation", SOURCE, &[])
        .expect("compile dirty BIF process info test");
    reference
        .load("dirty_bif_continuation", &beam)
        .expect("load reference module");
    let expected = reference.call("dirty_bif_continuation", "current_info", &[]);

    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).expect("load Arinsal module");
    let actual = vm
        .eval_scheduled("dirty_bif_continuation", "current_info", &[], 2, None)
        .expect("run dirty BIF process info test");
    similar_asserts::assert_eq!(expected, CallResult::Ok(actual.term));
}

#[test]
fn dirty_bif_exception_trace_matches_erts() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping dirty BIF exception trace test");
        return;
    };
    let beam = reference
        .compile_named("dirty_bif_continuation", SOURCE, &[])
        .expect("compile dirty BIF exception test");
    reference
        .load("dirty_bif_continuation", &beam)
        .expect("load reference module");
    let expected = reference.call("dirty_bif_continuation", "exception_run", &[]);

    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).expect("load Arinsal module");
    let actual = vm
        .eval_scheduled("dirty_bif_continuation", "exception_run", &[], 2, None)
        .expect("run dirty BIF exception test");
    similar_asserts::assert_eq!(expected, CallResult::Ok(actual.term));
}

#[test]
fn dirty_bif_heap_args_survive_collection() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping dirty BIF heap argument test");
        return;
    };
    let beam = reference
        .compile_named("dirty_bif_continuation", SOURCE, &[])
        .expect("compile dirty BIF heap argument test");
    reference
        .load("dirty_bif_continuation", &beam)
        .expect("load reference module");
    let expected = reference.call("dirty_bif_continuation", "heap_args_run", &[]);

    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).expect("load Arinsal module");
    let actual = vm
        .eval_scheduled("dirty_bif_continuation", "heap_args_run", &[], 2, None)
        .expect("run dirty BIF heap argument test");
    similar_asserts::assert_eq!(expected, CallResult::Ok(actual.term));
}
