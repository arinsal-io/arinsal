//! Scheduler-path statistics, memory, and persistent-term retirement.

use std::sync::{Mutex, MutexGuard};

use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_pterm::global_store;
use arinsal_vm::Vm;

const SOURCE: &str = r#"
-module(stats_diff).
-export([shapes/0, errors/0, enabled/0, toggle/0, gc_snapshot/0, grow/0, retire/0]).

shapes() ->
    erlang:system_flag(scheduler_wall_time, false),
    erlang:system_flag(microstate_accounting, false),
    Keys = [runtime, wall_clock, reductions, exact_reductions, context_switches,
            garbage_collection, io, run_queue, run_queue_lengths,
            total_run_queue_lengths, run_queue_lengths_all, active_tasks,
            active_tasks_all, total_active_tasks, total_active_tasks_all,
            run_queues, scheduler_wall_time, scheduler_wall_time_all],
    Stats = [{K, erlang:statistics(K)} || K <- Keys],
    {Stats, erlang:memory(), erlang:memory(ets),
     erlang:memory([processes_used, code, ets, processes_used]), erlang:memory([])}.

enabled() ->
    erlang:system_flag(scheduler_wall_time, true),
    Wall = erlang:statistics(scheduler_wall_time),
    All = erlang:statistics(scheduler_wall_time_all),
    erlang:system_flag(scheduler_wall_time, false),
    erlang:system_flag(microstate_accounting, true),
    Micro = erlang:statistics(microstate_accounting),
    Msacc = msacc:stats(),
    erlang:system_flag(microstate_accounting, false),
    {Wall, All, Micro, Msacc}.

toggle() ->
    erlang:system_flag(microstate_accounting, false),
    erlang:system_flag(microstate_accounting, reset),
    erlang:system_flag(microstate_accounting, true),
    receive after 5 -> ok end,
    First = microstate_total(),
    erlang:system_flag(microstate_accounting, false),
    receive after 5 -> ok end,
    erlang:system_flag(microstate_accounting, true),
    receive after 5 -> ok end,
    Second = microstate_total(),
    erlang:system_flag(microstate_accounting, false),
    {First, Second}.

gc_snapshot() ->
    erlang:system_flag(microstate_accounting, false),
    erlang:system_flag(microstate_accounting, reset),
    erlang:system_flag(microstate_accounting, true),
    Before = microstate_gc_total(),
    true = erts_internal:garbage_collect(major),
    After = microstate_gc_total(),
    erlang:system_flag(microstate_accounting, false),
    {Before, After}.

microstate_gc_total() ->
    lists:sum([maps:get(gc, maps:get(counters, Entry)) ||
               Entry <- erlang:statistics(microstate_accounting)]).

microstate_total() ->
    lists:sum([lists:sum(maps:values(maps:get(counters, Entry))) ||
               Entry <- erlang:statistics(microstate_accounting)]).

errors() ->
    {catch_call(fun() -> erlang:statistics(nope) end),
     catch_call(fun() -> erlang:statistics(1) end),
     catch_call(fun() -> erlang:memory(nope) end),
     catch_call(fun() -> erlang:memory([total, nope]) end),
     catch_call(fun() -> erlang:system_flag(scheduler_wall_time, other) end),
     catch_call(fun() -> erlang:system_flag(microstate_accounting, extra) end),
     catch_call(fun() -> erts_internal:garbage_collect(other) end)}.

catch_call(F) ->
    try F() of V -> {ok, V} catch Class:Reason -> {Class, Reason} end.

grow() ->
    erlang:system_flag(scheduler_wall_time, false),
    erlang:system_flag(microstate_accounting, false),
    R0 = element(1, erlang:statistics(reductions)),
    X0 = element(1, erlang:statistics(exact_reductions)),
    W0 = element(1, erlang:statistics(wall_clock)),
    C0 = element(1, erlang:statistics(runtime)),
    S0 = element(1, erlang:statistics(context_switches)),
    G0 = element(1, erlang:statistics(garbage_collection)),
    M0 = erlang:memory(ets),
    T = ets:new(stats_grow, [public, set]),
    fill(T, 10000),
    burn(50000, []),
    receive after 30 -> ok end,
    true = erts_internal:garbage_collect(major),
    R1 = element(1, erlang:statistics(reductions)),
    X1 = element(1, erlang:statistics(exact_reductions)),
    W1 = element(1, erlang:statistics(wall_clock)),
    C1 = element(1, erlang:statistics(runtime)),
    S1 = element(1, erlang:statistics(context_switches)),
    G1 = element(1, erlang:statistics(garbage_collection)),
    M1 = erlang:memory(ets),
    erlang:system_flag(scheduler_wall_time, true),
    Wa = erlang:statistics(scheduler_wall_time),
    receive after 20 -> ok end,
    Wb = erlang:statistics(scheduler_wall_time),
    erlang:system_flag(scheduler_wall_time, false),
    Before = erlang:statistics(microstate_accounting),
    erlang:system_flag(microstate_accounting, true),
    After = erlang:statistics(microstate_accounting),
    erlang:system_flag(microstate_accounting, false),
    {R0, R1, X0, X1, W0, W1, C0, C1, S0, S1, G0, G1, M0, M1, Wa, Wb, Before, After}.

fill(_T, 0) -> ok;
fill(T, N) ->
    true = ets:insert(T, {N, N}),
    fill(T, N - 1).

burn(0, _) -> ok;
burn(N, Acc) -> burn(N - 1, [N | Acc]).

retire() ->
    Key = {stats_retire, 1},
    ok = persistent_term:put(Key, {left, right}),
    Old = persistent_term:get(Key),
    ok = persistent_term:put(Key, {newer, term}),
    true = erts_internal:garbage_collect(major),
    Old.
"#;

fn guard() -> MutexGuard<'static, ()> {
    static LOCK: Mutex<()> = Mutex::new(());
    LOCK.lock().expect("stats test lock")
}

fn run(reference: &RefErl, function: &str) -> (CallResult, OwnedTerm) {
    let beam = reference
        .compile_named("stats_diff", SOURCE, &[])
        .expect("compile");
    reference.load("stats_diff", &beam).expect("load");
    let expected = reference.call("stats_diff", function, &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).expect("load bytes");
    let actual = vm
        .eval_scheduled("stats_diff", function, &[], 1, None)
        .unwrap_or_else(|error| panic!("{function}: {error}"));
    (expected, actual.term)
}

fn as_int(term: &OwnedTerm) -> i64 {
    match term {
        OwnedTerm::Int(value) => *value,
        OwnedTerm::BigInt(value) => value.to_string().parse().unwrap_or(i64::MAX),
        other => panic!("expected integer, got {other:?}"),
    }
}

fn is_int(term: &OwnedTerm) -> bool {
    matches!(term, OwnedTerm::Int(_) | OwnedTerm::BigInt(_))
}

fn list_elems(term: &OwnedTerm) -> &[OwnedTerm] {
    match term {
        OwnedTerm::List { elems, tail } if matches!(tail.as_ref(), OwnedTerm::Nil) => elems,
        OwnedTerm::Nil => &[],
        other => panic!("expected list, got {other:?}"),
    }
}

fn same_shape(actual: &OwnedTerm, expected: &OwnedTerm) -> bool {
    match (actual, expected) {
        (OwnedTerm::Int(_) | OwnedTerm::BigInt(_), OwnedTerm::Int(_) | OwnedTerm::BigInt(_)) => {
            true
        }
        (OwnedTerm::Atom(left), OwnedTerm::Atom(right)) => left == right,
        (OwnedTerm::Nil, OwnedTerm::Nil) => true,
        (
            OwnedTerm::List {
                elems: left,
                tail: left_tail,
            },
            OwnedTerm::List {
                elems: right,
                tail: right_tail,
            },
        ) => {
            left.len() == right.len()
                && left
                    .iter()
                    .zip(right)
                    .all(|(left, right)| same_shape(left, right))
                && same_shape(left_tail, right_tail)
        }
        (OwnedTerm::Tuple(left), OwnedTerm::Tuple(right)) => {
            left.len() == right.len()
                && left
                    .iter()
                    .zip(right)
                    .all(|(left, right)| same_shape(left, right))
        }
        (OwnedTerm::Map(left), OwnedTerm::Map(right)) => {
            left.len() == right.len()
                && left.iter().all(|(key, value)| {
                    right.iter().any(|(other_key, other_value)| {
                        same_shape(key, other_key) && same_shape(value, other_value)
                    })
                })
        }
        _ => false,
    }
}

fn assert_shape(actual: &OwnedTerm, expected: &OwnedTerm) {
    assert!(
        same_shape(actual, expected),
        "shape mismatch\n actual: {actual:?}\n expected: {expected:?}"
    );
}

fn map_get<'a>(term: &'a OwnedTerm, key: &str) -> &'a OwnedTerm {
    let OwnedTerm::Map(entries) = term else {
        panic!("expected map, got {term:?}");
    };
    entries
        .iter()
        .find(|(candidate, _)| matches!(candidate, OwnedTerm::Atom(name) if name == key))
        .map(|(_, value)| value)
        .unwrap_or_else(|| panic!("missing {key} in {term:?}"))
}

fn assert_microstate(actual: &OwnedTerm, expected: &OwnedTerm) {
    let actual_items = list_elems(actual);
    let expected_items = list_elems(expected);
    assert_eq!(
        actual_items.len(),
        expected_items.len(),
        "microstate length"
    );
    let mut actual_types = Vec::new();
    let mut expected_types = Vec::new();
    for (item, types) in [
        (actual_items, &mut actual_types),
        (expected_items, &mut expected_types),
    ] {
        for entry in item {
            let counters = map_get(entry, "counters");
            let OwnedTerm::Map(fields) = counters else {
                panic!("counters: {counters:?}");
            };
            let mut names: Vec<_> = fields
                .iter()
                .map(|(key, value)| {
                    assert!(is_int(value), "counter {key:?} = {value:?}");
                    match key {
                        OwnedTerm::Atom(name) => name.clone(),
                        other => panic!("counter key {other:?}"),
                    }
                })
                .collect();
            names.sort();
            assert_eq!(
                names,
                [
                    "aux", "check_io", "emulator", "gc", "other", "port", "sleep"
                ]
                .map(str::to_string)
                .to_vec()
            );
            assert!(is_int(map_get(entry, "id")));
            let OwnedTerm::Atom(kind) = map_get(entry, "type") else {
                panic!("type");
            };
            types.push(kind.clone());
        }
    }
    actual_types.sort();
    expected_types.sort();
    assert_eq!(actual_types, expected_types);
}

fn wall_total(term: &OwnedTerm) -> i64 {
    list_elems(term)
        .iter()
        .map(|entry| {
            let OwnedTerm::Tuple(fields) = entry else {
                panic!("wall entry {entry:?}");
            };
            assert_eq!(fields.len(), 3);
            assert!(fields.iter().all(is_int));
            as_int(&fields[2])
        })
        .sum()
}

fn memory_pairs(term: &OwnedTerm) -> Vec<(String, i64)> {
    list_elems(term)
        .iter()
        .map(|entry| {
            let OwnedTerm::Tuple(fields) = entry else {
                panic!("memory entry {entry:?}");
            };
            let OwnedTerm::Atom(key) = &fields[0] else {
                panic!("memory key {entry:?}");
            };
            (key.clone(), as_int(&fields[1]))
        })
        .collect()
}

#[test]
fn sched_acct_statistics_and_memory_shapes_match_otp() {
    let _guard = guard();
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping statistics shape test");
        return;
    };
    let (expected, actual) = run(&reference, "shapes");
    let CallResult::Ok(expected) = expected else {
        panic!("erl shapes: {expected:?}");
    };
    assert_shape(&actual, &expected);
    let OwnedTerm::Tuple(fields) = &actual else {
        panic!("shapes tuple");
    };
    let pairs = memory_pairs(&fields[1]);
    let value = |name: &str| pairs.iter().find(|(key, _)| key == name).unwrap().1;
    assert_eq!(value("total"), value("processes") + value("system"));
    assert!(value("processes_used") <= value("processes"));
    assert!(value("atom_used") <= value("atom"));
    assert!(value("system") >= value("atom") + value("binary") + value("code") + value("ets"));
}

#[test]
fn sched_acct_statistics_and_memory_errors_match_otp() {
    let _guard = guard();
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping statistics error test");
        return;
    };
    let (expected, actual) = run(&reference, "errors");
    assert_eq!(expected, CallResult::Ok(actual));
}

#[test]
fn sched_acct_enabled_scheduler_accounting_matches_otp_shape() {
    let _guard = guard();
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping enabled statistics test");
        return;
    };
    let (expected, actual) = run(&reference, "enabled");
    let CallResult::Ok(expected) = expected else {
        panic!("erl enabled: {expected:?}");
    };
    let OwnedTerm::Tuple(expected) = &expected else {
        panic!("erl enabled tuple");
    };
    let OwnedTerm::Tuple(actual) = &actual else {
        panic!("enabled tuple");
    };
    assert_eq!(list_elems(&actual[0]).len(), list_elems(&expected[0]).len());
    assert_eq!(list_elems(&actual[1]).len(), list_elems(&expected[1]).len());
    assert!(list_elems(&actual[0]).iter().all(|entry| {
        matches!(entry, OwnedTerm::Tuple(fields) if fields.len() == 3 && fields.iter().all(is_int))
    }));
    assert_microstate(&actual[2], &expected[2]);
    assert_shape(&actual[3], &expected[3]);
}

#[test]
fn sched_acct_microstate_counters_survive_disable_and_enable() {
    let _guard = guard();
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping microstate toggle test");
        return;
    };
    let (expected, actual) = run(&reference, "toggle");
    assert!(
        matches!(expected, CallResult::Ok(_)),
        "erl toggle: {expected:?}"
    );
    let OwnedTerm::Tuple(values) = &actual else {
        panic!("toggle tuple: {actual:?}");
    };
    assert!(as_int(&values[1]) >= as_int(&values[0]), "{values:?}");
}

#[test]
fn sched_acct_gc_is_visible_to_same_turn_microstate_snapshot() {
    let _guard = guard();
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping GC microstate test");
        return;
    };
    let (expected, actual) = run(&reference, "gc_snapshot");
    assert!(
        matches!(expected, CallResult::Ok(_)),
        "erl GC snapshot: {expected:?}"
    );
    let OwnedTerm::Tuple(values) = &actual else {
        panic!("GC snapshot tuple: {actual:?}");
    };
    assert!(as_int(&values[1]) > as_int(&values[0]), "{values:?}");
}

#[test]
fn sched_acct_counters_and_ets_memory_grow_after_work() {
    let _guard = guard();
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping statistics growth test");
        return;
    };
    let (expected, actual) = run(&reference, "grow");
    assert!(
        matches!(expected, CallResult::Ok(_)),
        "erl grow: {expected:?}"
    );
    let OwnedTerm::Tuple(fields) = &actual else {
        panic!("grow tuple");
    };
    let nums: Vec<i64> = fields[..14].iter().map(as_int).collect();
    let (r0, r1, x0, x1, w0, w1, c0, c1, s0, s1, g0, g1, m0, m1) = (
        nums[0], nums[1], nums[2], nums[3], nums[4], nums[5], nums[6], nums[7], nums[8], nums[9],
        nums[10], nums[11], nums[12], nums[13],
    );
    assert!(r1 > r0, "reductions {r0} -> {r1}");
    assert!(x1 > x0, "exact_reductions {x0} -> {x1}");
    assert!(w1 > w0, "wall_clock {w0} -> {w1}");
    assert!(c1 > c0, "runtime {c0} -> {c1}");
    assert!(s1 > s0, "context_switches {s0} -> {s1}");
    assert!(g1 > g0, "garbage_collection {g0} -> {g1}");
    assert!(m1 > m0, "memory(ets) {m0} -> {m1}");
    assert!(wall_total(&fields[15]) > wall_total(&fields[14]));
    // erl 29.1.1 returns the per-thread counter list even while microstate accounting is disabled.
    assert!(!list_elems(&fields[16]).is_empty());
    assert!(!list_elems(&fields[17]).is_empty());
}

#[test]
fn sched_acct_replaced_persistent_term_is_freed_after_gc() {
    let _guard = guard();
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping persistent-term retirement test");
        return;
    };
    let (expected, actual) = run(&reference, "retire");
    assert_eq!(
        expected,
        CallResult::Ok(OwnedTerm::tuple(vec![
            OwnedTerm::atom("left"),
            OwnedTerm::atom("right")
        ]))
    );
    assert_eq!(expected, CallResult::Ok(actual));
    let trace = global_store().last_retirement();
    assert!(
        trace.pending_before >= 1,
        "pending_before {}",
        trace.pending_before
    );
    assert_eq!(trace.pending_after, 0);
    assert!(trace.freed >= 1, "freed {}", trace.freed);
    assert!(
        trace.copied_roots >= 1,
        "copied_roots {}",
        trace.copied_roots
    );
}
