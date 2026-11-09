//! Differential tests (against the reference `erl`) for native record operations,
//! `hibernate` called through `apply/3`, and heap accounting of parked processes.

use arinsal_difftest::{CallResult, RefErl};
use arinsal_vm::Vm;
use std::sync::Mutex;

static TEST_LOCK: Mutex<()> = Mutex::new(());

const RECORDS: &str = r#"
-module(sg_records).
-export([local/0, server/0, bump/1]).
-export_record([exp]).
-record #exp{a=1, b}.
-record #loc{x=1, y=2}.
-record #nodef{a, b=0}.

local() -> #loc{x=3}.
server() -> #exp{b=7}.
bump(R) -> R#exp{a = 5}.
"#;

const SOURCE: &str = r#"
-module(sg_probe).
-export([awake/1, record_ops/0, record_errors/0, deleted_external/0,
         dynamic_hibernate/0, hibernate_heap/0, in_place_heap/0]).

-record #loc{x=1, y=2}.
-record #nodef{a, b=0}.

id(X) -> X.
err(F) -> try F(), no_error catch error:R -> R end.

record_ops() ->
    L = id(#loc{x=3}),
    #loc{x = X, y = Y} = L,
    E = id(#sg_records:exp{b = 7}),
    {X, Y, L#loc.y, E#sg_records:exp.a, E#sg_records:exp.b,
     is_record(L, loc), erlang:is_map(L),
     case E of #sg_records:exp{a = A} -> A end,
     (id(#nodef{a = 1}))#nodef.b,
     L#loc{x = 9, y = 8}}.

record_errors() ->
    E = id(#sg_records:exp{b = 7}),
    N = id(not_a_record),
    {err(fun() -> #sg_records:exp{a = 1} end),
     err(fun() -> #sg_records:exp{zzz = 1, b = 1} end),
     err(fun() -> E#sg_records:exp{zzz = 1} end),
     err(fun() -> E#sg_records:exp{a = 2, zzz = 1} end),
     err(fun() -> E#sg_records:exp.zzz end),
     err(fun() -> N#sg_records:exp.a end),
     err(fun() -> N#loc.x end),
     err(fun() -> #sg_records:hidden{} end),
     err(fun() -> (sg_records:local())#sg_records:loc.x end)}.

deleted_external() ->
    _ = sg_records:server(),
    D = (catch erlang:delete_module(sg_records)),
    R = err(fun() -> #sg_records:exp{b = 1} end),
    {D, R}.

%% apply(erlang, hibernate, _) from a function that has a stack frame.
dynamic_hibernate() ->
    Self = self(),
    P = spawn(fun() -> dyn(Self, hibernate) end),
    P ! {go, 1},
    wait_hibernated(P),
    Before = process_info(P, [current_function, status]),
    P ! wake,
    Woke = receive {woke, P} -> true after 5000 -> false end,
    exit(P, kill),
    {Before, Woke}.

dyn(Parent, F) ->
    receive
        {go, _} -> dyn_msg(Parent, F)
    end.

dyn_msg(Parent, F) ->
    try apply(erlang, F, [sg_probe, awake, [Parent]]) catch _:_ -> ok end,
    exit(hibernate_returned).

awake(Parent) ->
    receive wake -> Parent ! {woke, self()}, awake(Parent) end.

wait_hibernated(P) ->
    case process_info(P, current_function) of
        {current_function, {erlang, hibernate, _}} -> ok;
        _ -> timer:sleep(5), wait_hibernated(P)
    end.

%% Parked processes must not accumulate process_info replies on their heap.
hibernate_heap() ->
    Self = self(),
    P = spawn(fun() -> hib_loop(Self) end),
    wait_hibernated(P),
    Sizes = [begin
                 timer:sleep(2),
                 [{heap_size, H}, {total_heap_size, T}] =
                     process_info(P, [heap_size, total_heap_size]),
                 {H =:= T, T < 50}
             end || _ <- lists:seq(1, 50)],
    exit(P, kill),
    lists:usort(Sizes).

hib_loop(Parent) ->
    receive _ -> ok after 0 -> ok end,
    erlang:hibernate(sg_probe, hib_loop, [Parent]).

%% hibernate/0 shrinks the heap like hibernate/3 but keeps the stack.
in_place_heap() ->
    Parent = self(),
    Fun = fun(F) ->
                  Data = lists:seq(1, 1024),
                  F(),
                  lists:foreach(fun(_) -> ok end, Data)
          end,
    Ref = spawn(fun() -> Fun(fun() -> Parent ! {ready, ref}, receive done -> ok end end) end),
    Hib = spawn(fun() -> Fun(fun() -> Parent ! {ready, hib}, erlang:hibernate(), receive done -> ok end end) end),
    receive {ready, ref} -> ok end,
    receive {ready, hib} -> ok end,
    timer:sleep(300),
    [{status, S1}, {_, RefSize}] = process_info(Ref, [status, total_heap_size]),
    [{status, S2}, {_, HibSize}] = process_info(Hib, [status, total_heap_size]),
    Ref ! done, Hib ! done,
    {S1, S2, HibSize < 2100, HibSize =< RefSize}.
"#;

fn compare(function: &str) {
    let _lock = TEST_LOCK
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping small gaps differential test");
        return;
    };
    let records = reference
        .compile_named("sg_records", RECORDS, &[])
        .expect("compile records fixture");
    let probe = reference
        .compile_named("sg_probe", SOURCE, &[])
        .expect("compile probe fixture");
    reference
        .load("sg_records", &records)
        .expect("load reference records");
    reference.load("sg_probe", &probe).expect("load reference");
    let expected = reference.call("sg_probe", function, &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&records).expect("load VM records");
    vm.load_bytes(&probe).expect("load VM fixture");
    let actual = vm
        .eval_scheduled("sg_probe", function, &[], 2, None)
        .unwrap_or_else(|error| panic!("{function}: {error}"));
    assert_eq!(expected, CallResult::Ok(actual.term), "{function}");
}

#[test]
fn small_gaps_native_record_operations_match_otp() {
    compare("record_ops");
}

#[test]
fn small_gaps_native_record_errors_match_otp() {
    compare("record_errors");
}

#[test]
fn small_gaps_deleted_module_records_are_not_external() {
    compare("deleted_external");
}

#[test]
fn small_gaps_hibernate_through_apply_parks_the_process() {
    compare("dynamic_hibernate");
}

#[test]
fn small_gaps_parked_process_heap_does_not_grow_with_process_info() {
    compare("hibernate_heap");
}

#[test]
fn small_gaps_hibernate_zero_shrinks_the_heap() {
    compare("in_place_heap");
}
