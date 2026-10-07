//! Differential coverage for self-initiated long collections on dirty CPU schedulers.

use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_vm::Vm;

const SOURCE: &str = r#"
-module(dirty_major_gc).
-export([run/0]).

%% A worker that grows a heap past ERTS_POTENTIALLY_LONG_GC_HSIZE (128K words) has its own
%% collections moved to a dirty CPU scheduler. The observer busy-polls so it sees one.
run() ->
    Schedulers = erlang:system_info(schedulers),
    DirtySchedulers = erlang:system_info(dirty_cpu_schedulers),
    false = erlang:system_flag(scheduler_wall_time, true),
    Before = statistics(scheduler_wall_time_all),
    Runs = [once() || _ <- lists:seq(1, 3)],
    After = statistics(scheduler_wall_time_all),
    true = erlang:system_flag(scheduler_wall_time, false),
    DirtyBusy = lists:any(fun(Id) ->
        active(Id, After) > active(Id, Before)
    end, lists:seq(Schedulers + 1, Schedulers + DirtySchedulers)),
    {Runs, DirtyBusy}.

once() ->
    Parent = self(),
    {Worker, Monitor} = spawn_opt(fun() ->
        try length(grow(1000000, [])) of
            Length -> Parent ! {done, self(), Length}
        catch Class:Reason:Stack -> Parent ! {failed, self(), Class, Reason, Stack}
        end
    end, [{min_heap_size, 262144}, monitor]),
    Deadline = erlang:monotonic_time(millisecond) + 60000,
    observe(Worker, Monitor, Deadline, false, undefined).

grow(0, Acc) -> Acc;
grow(N, Acc) -> grow(N - 1, [N | Acc]).

observe(Worker, Monitor, Deadline, DirtySeen, StatusSeen) ->
    DirtyNow = erts_internal:is_process_executing_dirty(Worker),
    StatusNow = case DirtyNow of
        true -> element(2, process_info(Worker, status));
        false -> StatusSeen
    end,
    receive
        {done, Worker, Length} ->
            erlang:demonitor(Monitor, [flush]),
            {Length, DirtySeen orelse DirtyNow, StatusNow};
        {failed, Worker, Class, Reason, Stack} ->
            erlang:demonitor(Monitor, [flush]),
            {failed, Class, Reason, Stack};
        {'DOWN', Monitor, process, Worker, Reason} ->
            {worker_down, Reason}
    after 0 ->
        case erlang:monotonic_time(millisecond) > Deadline of
            true -> {timeout, DirtySeen, StatusNow};
            false ->
                observe(Worker, Monitor, Deadline, DirtySeen orelse DirtyNow, StatusNow)
        end
    end.

active(Id, Stats) ->
    case lists:keyfind(Id, 1, Stats) of
        {Id, Active, _Total} -> Active;
        false -> 0
    end.
"#;

#[test]
fn self_initiated_long_gc_matches_otp_and_uses_dirty_cpu() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping dirty major GC differential test");
        return;
    };
    let beam = reference
        .compile_named("dirty_major_gc", SOURCE, &[])
        .expect("compile dirty_major_gc");
    reference
        .load("dirty_major_gc", &beam)
        .expect("load into erl");
    let expected = reference.call("dirty_major_gc", "run", &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).expect("load into arinsal");
    let actual = vm
        .eval_scheduled("dirty_major_gc", "run", &[], 2, None)
        .expect("scheduled dirty major GC run");
    assert_eq!(expected, CallResult::Ok(actual.term.clone()));
    let run = OwnedTerm::Tuple(vec![
        OwnedTerm::Int(1_000_000),
        OwnedTerm::Atom("true".into()),
        OwnedTerm::Atom("running".into()),
    ]);
    assert_eq!(
        actual.term,
        OwnedTerm::Tuple(vec![
            OwnedTerm::List {
                elems: vec![run.clone(), run.clone(), run],
                tail: Box::new(OwnedTerm::Nil),
            },
            OwnedTerm::Atom("true".into()),
        ])
    );
}
