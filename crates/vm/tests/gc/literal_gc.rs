//! Differential checks for trapped persistent-term literal access.

use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_vm::Vm;

const SOURCE: &str = r#"
-module(literal_gc_diff).
-export([applied_get_all/0, shared_literals/0, dirty_results/0]).

applied_get_all() ->
    Keys = lists:seq(1, 5000),
    [persistent_term:put({literal_gc_diff, N}, N) || N <- Keys],
    All = erlang:apply(persistent_term, get, []),
    Count = length([ok || {{literal_gc_diff, _}, _} <- All]),
    [persistent_term:erase({literal_gc_diff, N}) || N <- Keys],
    Count.

%% Literals (here a persistent-term area) are not copied by spawn, send or
%% erts_debug:copy_shared/2 unless copy_literals is requested.
shared_literals() ->
    Key = {literal_gc_diff, shared},
    persistent_term:put(Key, {[1, 2, 3], <<"bin">>, 3.5}),
    Lit = persistent_term:get(Key),
    Self = self(),
    Wrapped = {Lit, [Lit | Lit], self()},
    Child = spawn(fun () ->
                          Self ! {spawned, erts_debug:size_shared(Lit)},
                          receive {msg, M} -> Self ! {received, erts_debug:size_shared(M)} end
                  end),
    Child ! {msg, Wrapped},
    S1 = receive {spawned, A} -> A end,
    S2 = receive {received, B} -> B end,
    Shared = erts_debug:copy_shared(Wrapped, false),
    Copied = erts_debug:copy_shared(Wrapped, true),
    Result = {erts_debug:size_shared(Lit), S1, S2, erts_debug:size_shared(Wrapped),
              erts_debug:size_shared(Shared), erts_debug:size_shared(Copied),
              erts_debug:size(Wrapped), Shared =:= Wrapped, Copied =:= Wrapped},
    persistent_term:erase(Key),
    Result.

%% Workers with large heaps (so no collection follows the BIF) take dirty BIF results while
%% another process retires persistent-term literal areas. A literal-area request that
%% arrives during the dirty job is collected after the job returns and before the BIF call
%% is executed again; the finished result must be one of that collection's roots.
dirty_results() ->
    Self = self(),
    Eraser = spawn_link(fun() -> erase_loop(0) end),
    Workers = [spawn_opt(fun() -> Self ! {dirty_results, self(), dirty_worker(300)} end,
                         [monitor, {min_heap_size, 100000}])
               || _ <- lists:seq(1, 4)],
    Results = [receive
                   {dirty_results, Pid, Result} -> erlang:demonitor(Ref, [flush]), Result;
                   {'DOWN', Ref, process, Pid, Reason} -> {down, Reason}
               end || {Pid, Ref} <- Workers],
    unlink(Eraser),
    exit(Eraser, kill),
    lists:usort(Results).

erase_loop(N) ->
    persistent_term:put({literal_gc_diff, erase, N}, {N, [N]}),
    persistent_term:erase({literal_gc_diff, erase, N}),
    receive after 1 -> ok end,
    erase_loop(N + 1).

dirty_worker(0) -> ok;
dirty_worker(N) ->
    Value = {binary:copy(<<N:32>>, 10), [N, N + 1]},
    Copies = erts_debug:dirty_cpu(copy, Value),
    case length(Copies) =:= 1000 andalso lists:all(fun(C) -> C =:= Value end, Copies) of
        true -> dirty_worker(N - 1);
        false -> {corrupt, N}
    end.
"#;

#[test]
fn applied_get_all_keeps_outer_arguments_across_yields() {
    let reference = RefErl::start().expect("OTP 29.1.1 erl is required");
    let beam = reference
        .compile_named("literal_gc_diff", SOURCE, &[])
        .expect("compile");
    reference.load("literal_gc_diff", &beam).expect("load");
    let expected = reference.call("literal_gc_diff", "applied_get_all", &[]);
    assert_eq!(expected, CallResult::Ok(OwnedTerm::Int(5000)));

    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).expect("load bytes");
    let actual = vm
        .eval_scheduled("literal_gc_diff", "applied_get_all", &[], 1, None)
        .expect("scheduled evaluation");
    assert_eq!(expected, CallResult::Ok(actual.term));
}

#[test]
fn literals_stay_shared_across_spawn_send_and_copy_shared() {
    let reference = RefErl::start().expect("OTP 29.1.1 erl is required");
    let beam = reference
        .compile_named("literal_gc_diff", SOURCE, &[])
        .expect("compile");
    reference.load("literal_gc_diff", &beam).expect("load");
    let expected = reference.call("literal_gc_diff", "shared_literals", &[]);
    assert!(matches!(expected, CallResult::Ok(_)), "{expected:?}");

    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).expect("load bytes");
    let actual = vm
        .eval_scheduled("literal_gc_diff", "shared_literals", &[], 1, None)
        .expect("scheduled evaluation");
    assert_eq!(expected, CallResult::Ok(actual.term));
}

#[test]
fn dirty_bif_results_are_roots_of_literal_area_collections() {
    let reference = RefErl::start().expect("OTP 29.1.1 erl is required");
    let beam = reference
        .compile_named("literal_gc_diff", SOURCE, &[])
        .expect("compile");
    reference.load("literal_gc_diff", &beam).expect("load");
    let expected = reference.call("literal_gc_diff", "dirty_results", &[]);
    assert_eq!(
        expected,
        CallResult::Ok(OwnedTerm::List {
            elems: vec![OwnedTerm::Atom("ok".into())],
            tail: Box::new(OwnedTerm::Nil),
        })
    );

    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).expect("load bytes");
    let actual = vm
        .eval_scheduled("literal_gc_diff", "dirty_results", &[], 2, None)
        .expect("scheduled evaluation");
    assert_eq!(expected, CallResult::Ok(actual.term));
}
