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

const REDS_SOURCE: &str = r#"
-module(dirty_gc_reds).
-export([run/0]).

run() ->
    Small = [case_(N, 0, live) || N <- [0, 1000, 10000]],
    Large = [case_(N, 0, live) || N <- [100000, 800000], _ <- [1, 2, 3]],
    Spin = [case_(100000, K, live) || K <- [0, 1500, 3000], _ <- [1, 2, 3]],
    Dead = [case_(100000, 0, dead) || _ <- [1, 2, 3]],
    {Small, Large, Spin, Dead}.

spin(0) -> ok;
spin(N) -> spin(N - 1).

body(Parent, N, K, live) ->
    L = lists:seq(1, N),
    erlang:garbage_collect(),
    receive go -> ok end,
    spin(K),
    {reductions, R0} = process_info(self(), reductions),
    erlang:garbage_collect(),
    {reductions, R1} = process_info(self(), reductions),
    Parent ! {done, R1 - R0, length(L)};
body(Parent, N, K, dead) ->
    L = lists:seq(1, N),
    Len = length(L),
    receive go -> ok end,
    spin(K),
    {reductions, R0} = process_info(self(), reductions),
    erlang:garbage_collect(),
    {reductions, R1} = process_info(self(), reductions),
    Parent ! {done, R1 - R0, Len}.

case_(N, K, Kind) ->
    Parent = self(),
    P = spawn(fun() -> body(Parent, N, K, Kind) end),
    receive after 50 -> ok end,
    erlang:trace(P, true, [garbage_collection, monotonic_timestamp]),
    P ! go,
    receive {done, Delta, _} ->
        receive after 50 -> ok end,
        Events = flush([]),
        Starts = [T || {gc_major_start, T} <- Events],
        Ends = [T || {gc_major_end, T} <- Events],
        Dur = case {Starts, Ends} of
            {[_ | _], [_ | _]} -> (lists:last(Ends) - lists:last(Starts)) div 1000;
            _ -> -1
        end,
        {N, K, Delta, length(Starts), length(Ends), Dur}
    end.

flush(Acc) ->
    receive
        {trace_ts, _, Event, _, T} -> flush([{Event, T} | Acc]);
        {trace_ts, _, Event, T} -> flush([{Event, T} | Acc])
    after 0 -> lists:reverse(Acc)
    end.
"#;

#[derive(Debug, Clone, Copy)]
struct GcCase {
    n: i64,
    k: i64,
    delta: i64,
    starts: i64,
    ends: i64,
    dur_us: i64,
}

fn int(term: &OwnedTerm) -> i64 {
    match term {
        OwnedTerm::Int(value) => *value,
        other => panic!("integer expected, got {other:?}"),
    }
}

fn cases(term: &OwnedTerm) -> Vec<GcCase> {
    let OwnedTerm::List { elems, .. } = term else {
        panic!("list expected, got {term:?}");
    };
    elems
        .iter()
        .map(|elem| {
            let OwnedTerm::Tuple(fields) = elem else {
                panic!("tuple expected, got {elem:?}");
            };
            GcCase {
                n: int(&fields[0]),
                k: int(&fields[1]),
                delta: int(&fields[2]),
                starts: int(&fields[3]),
                ends: int(&fields[4]),
                dur_us: int(&fields[5]),
            }
        })
        .collect()
}

fn groups(term: &OwnedTerm) -> [Vec<GcCase>; 4] {
    let OwnedTerm::Tuple(parts) = term else {
        panic!("tuple expected, got {term:?}");
    };
    [
        cases(&parts[0]),
        cases(&parts[1]),
        cases(&parts[2]),
        cases(&parts[3]),
    ]
}

/// The reductions of a dirty explicit collection: the call and `min(reds_left, 10)` on the normal
/// scheduler, then four per whole microsecond on the dirty CPU scheduler.
const DIRTY_BASE: i64 = 13;
const SLACK_US: i64 = 100;

fn check_dirty(runtime: &str, label: &str, group: &[GcCase]) {
    for case in group {
        assert!(
            case.starts >= 1 && case.starts == case.ends,
            "{runtime} {label} {case:?}"
        );
        let extra = case.delta - DIRTY_BASE;
        assert!(
            extra % 4 == 0 || case.delta == DIRTY_BASE + 1,
            "{runtime} {label} residue {case:?}"
        );
        assert!(
            extra >= 4 * case.dur_us,
            "{runtime} {label} below trace {case:?}"
        );
    }
    assert!(
        group
            .iter()
            .any(|case| case.delta - DIRTY_BASE <= 4 * (case.dur_us + SLACK_US)),
        "{runtime} {label} above trace in every run {group:?}"
    );
}

fn check_all(runtime: &str, [_, large, spin, dead]: &[Vec<GcCase>; 4]) {
    for n in [100_000, 800_000] {
        let group: Vec<GcCase> = large.iter().copied().filter(|case| case.n == n).collect();
        check_dirty(runtime, &format!("live n={n}"), &group);
    }
    for k in [0, 1500, 3000] {
        let group: Vec<GcCase> = spin.iter().copied().filter(|case| case.k == k).collect();
        check_dirty(runtime, &format!("spin k={k}"), &group);
    }
    check_dirty(runtime, "dead", dead);
}

#[test]
fn explicit_dirty_gc_reductions_match_otp_formula() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping dirty GC reductions differential test");
        return;
    };
    let beam = reference
        .compile_named("dirty_gc_reds", REDS_SOURCE, &[])
        .expect("compile dirty_gc_reds");
    reference
        .load("dirty_gc_reds", &beam)
        .expect("load into erl");
    let CallResult::Ok(expected) = reference.call("dirty_gc_reds", "run", &[]) else {
        panic!("erl run failed");
    };
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).expect("load into arinsal");
    let actual = vm
        .eval_scheduled("dirty_gc_reds", "run", &[], 2, None)
        .expect("scheduled dirty GC reductions run");
    let expected = groups(&expected);
    let actual = groups(&actual.term);
    let small = |groups: &[Vec<GcCase>; 4]| -> Vec<(i64, i64)> {
        groups[0].iter().map(|case| (case.n, case.delta)).collect()
    };
    assert_eq!(
        small(&expected),
        small(&actual),
        "small heaps match exactly"
    );
    check_all("erl", &expected);
    check_all("arinsal", &actual);
}

const SIZES_SOURCE: &str = r#"
-module(dirty_gc_sizes).
-export([run/0]).

run() -> [case_(N, Kind) || Kind <- [self_gc, other_gc, other_gc_minor], N <- [100000, 400000, 800000]].

grow(0, Acc) -> Acc;
grow(N, Acc) -> grow(N - 1, [N | Acc]).

sizes() ->
    {garbage_collection_info, Info} = process_info(self(), garbage_collection_info),
    {total_heap_size, Total} = process_info(self(), total_heap_size),
    {heap_size, Heap} = process_info(self(), heap_size),
    {Total, Heap, [proplists:get_value(K, Info) ||
        K <- [heap_block_size, old_heap_block_size, old_heap_size, recent_size, mbuf_size]]}.

body(Parent, N, Kind) ->
    L = grow(N, []),
    Parent ! ready,
    receive go -> ok end,
    case Kind of
        self_gc -> erlang:garbage_collect();
        _ -> ok
    end,
    Parent ! collected,
    receive go2 -> ok end,
    First = sizes(),
    Second = sizes(),
    Parent ! {done, {First, Second, length(L)}}.

case_(N, Kind) ->
    Parent = self(),
    P = spawn(fun() -> body(Parent, N, Kind) end),
    receive ready -> ok end,
    erlang:trace(P, true, [garbage_collection]),
    P ! go,
    case Kind of
        self_gc -> ok;
        other_gc ->
            receive collected -> ok end,
            true = erlang:garbage_collect(P);
        other_gc_minor ->
            receive collected -> ok end,
            true = erlang:garbage_collect(P, [{type, minor}])
    end,
    case Kind of
        self_gc -> receive collected -> ok end;
        _ -> ok
    end,
    P ! go2,
    receive {done, Sizes} ->
        receive after 50 -> ok end,
        {N, Kind, Sizes, [{Event, [proplists:get_value(K, Info) ||
            K <- [heap_block_size, old_heap_block_size, old_heap_size, recent_size]]}
            || {Event, Info} <- flush([])]}
    end.

flush(Acc) ->
    receive
        {trace, _, Event, Info} -> flush([{Event, Info} | Acc])
    after 0 -> lists:reverse(Acc)
    end.
"#;

#[test]
fn explicit_gc_heap_sizes_and_events_match_otp() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping dirty GC heap sizing differential test");
        return;
    };
    let beam = reference
        .compile_named("dirty_gc_sizes", SIZES_SOURCE, &[])
        .expect("compile dirty_gc_sizes");
    reference
        .load("dirty_gc_sizes", &beam)
        .expect("load into erl");
    let CallResult::Ok(expected) = reference.call("dirty_gc_sizes", "run", &[]) else {
        panic!("erl run failed");
    };
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).expect("load into arinsal");
    let actual = vm
        .eval_scheduled("dirty_gc_sizes", "run", &[], 2, None)
        .expect("scheduled dirty GC sizes run");
    assert_eq!(expected, actual.term);
}
