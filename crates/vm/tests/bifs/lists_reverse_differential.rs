//! `lists:reverse/2` of 1k, 100k and 800k element lists in a fresh process against OTP.
//!
//! The BIF reverses on the unused part of the young heap, then in heap fragments, and traps
//! when its reductions are spent. A collection runs after every call that left fragments
//! larger than the free heap, with the trap's arguments as roots, and it costs reductions.
//! Collections of a large heap run on a dirty scheduler. The probe counts what the child
//! consumes from the call to the end of its reductions: reductions, scheduler-outs, minor and
//! major collection events. Collections, heap sizes and the reductions of the small and medium
//! lists are deterministic in OTP; the reductions of a large list are not compared.

use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_vm::Vm;

const MODULE: &str = "lists_reverse_differential";
const SOURCE: &str = r#"
-module(lists_reverse_differential).
-export([k1/0, k100/0, k800/0]).

k1() -> run(1000).
k100() -> run(100000).
k800() -> run(800000).

run(N) ->
    Me = self(),
    Pid = spawn(fun() -> child(Me, N) end),
    receive {ready, Pid} -> ok end,
    erlang:trace(Pid, true, [running, garbage_collection, {tracer, self()}]),
    Pid ! go,
    receive {done, Pid, Info} -> ok end,
    timer:sleep(100),
    Counts = events(Pid, #{out => 0, minor => 0, major => 0}),
    exit(Pid, kill),
    {Reds, HeapAfter, TotalAfter, HeapBefore} = Info,
    #{out := Outs, minor := Minor, major := Major} = Counts,
    {Reds, Outs - 1, Minor, Major, HeapBefore, HeapAfter, TotalAfter}.

events(Pid, Acc) ->
    receive
        {trace, Pid, out, _} -> events(Pid, bump(out, Acc));
        {trace, Pid, gc_minor_start, _} -> events(Pid, bump(minor, Acc));
        {trace, Pid, gc_major_start, _} -> events(Pid, bump(major, Acc));
        {trace, Pid, _, _} -> events(Pid, Acc)
    after 1000 -> Acc
    end.

bump(K, M) -> maps:update_with(K, fun(V) -> V + 1 end, M).

child(Me, N) ->
    L = lists:seq(1, N),
    Me ! {ready, self()},
    receive go -> ok end,
    {reductions, R0} = process_info(self(), reductions),
    {heap_size, H0} = process_info(self(), heap_size),
    Rev = lists:reverse(L, []),
    {reductions, R1} = process_info(self(), reductions),
    receive after 200 -> ok end,
    {heap_size, H1} = process_info(self(), heap_size),
    {total_heap_size, T1} = process_info(self(), total_heap_size),
    _ = Rev,
    Me ! {done, self(), {R1 - R0, H1, T1, H0}},
    receive stop -> ok end.
"#;

const RUNS: usize = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Probe {
    reds: i64,
    outs: i64,
    minor: i64,
    major: i64,
    heap_before: i64,
    heap_after: i64,
    total_after: i64,
}

fn integer(term: &OwnedTerm) -> i64 {
    match term {
        OwnedTerm::Int(value) => *value,
        OwnedTerm::BigInt(value) => value.to_string().parse().expect("integer"),
        other => panic!("expected integer, got {other:?}"),
    }
}

fn probe(term: &OwnedTerm) -> Probe {
    let OwnedTerm::Tuple(values) = term else {
        panic!("expected tuple, got {term:?}");
    };
    let v: Vec<i64> = values.iter().map(integer).collect();
    Probe {
        reds: v[0],
        outs: v[1],
        minor: v[2],
        major: v[3],
        heap_before: v[4],
        heap_after: v[5],
        total_after: v[6],
    }
}

fn otp_runs(reference: &RefErl, function: &str) -> Vec<Probe> {
    (0..RUNS)
        .map(|_| match reference.call(MODULE, function, &[]) {
            CallResult::Ok(term) => probe(&term),
            other => panic!("reference {function} failed: {other:?}"),
        })
        .collect()
}

fn arinsal_runs(beam: &[u8], function: &str) -> Vec<Probe> {
    let mut vm = Vm::new([]);
    vm.load_bytes(beam).expect("load probe into Arinsal");
    (0..RUNS)
        .map(|_| {
            let outcome = vm
                .eval_scheduled(MODULE, function, &[], 2, None)
                .unwrap_or_else(|error| panic!("Arinsal {function} failed: {error:?}"));
            probe(&outcome.term)
        })
        .collect()
}

fn spread(runs: &[Probe], field: fn(&Probe) -> i64) -> (i64, i64) {
    let values: Vec<i64> = runs.iter().map(field).collect();
    (
        *values.iter().min().expect("runs"),
        *values.iter().max().expect("runs"),
    )
}

fn check_same(
    problems: &mut Vec<String>,
    runs: &[Probe],
    expected: &[Probe],
    name: &str,
    field: fn(&Probe) -> i64,
) {
    let (lo, hi) = spread(expected, field);
    if lo != hi {
        problems.push(format!("{name}: OTP is not deterministic: {expected:?}"));
        return;
    }
    if runs.iter().any(|run| field(run) != lo) {
        problems.push(format!("{name}: Arinsal {runs:?} vs OTP {expected:?}"));
    }
}

#[test]
fn lists_reverse_matches_otp() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping lists:reverse differential test");
        return;
    };
    let beam = reference
        .compile_named(MODULE, SOURCE, &[])
        .expect("compile lists:reverse probe");
    reference
        .load(MODULE, &beam)
        .expect("load lists:reverse probe");

    let mut problems = Vec::new();
    for (function, size, cells) in [
        ("k1", "1k", 1_000),
        ("k100", "100k", 100_000),
        ("k800", "800k", 800_000),
    ] {
        let expected = otp_runs(&reference, function);
        let actual = arinsal_runs(&beam, function);
        eprintln!("{size}: OTP {expected:?}\n{size}: Arinsal {actual:?}");

        check_same(
            &mut problems,
            &actual,
            &expected,
            &format!("{size} minor"),
            |p| p.minor,
        );
        check_same(
            &mut problems,
            &actual,
            &expected,
            &format!("{size} major"),
            |p| p.major,
        );
        check_same(
            &mut problems,
            &actual,
            &expected,
            &format!("{size} heap before"),
            |p| p.heap_before,
        );
        check_same(
            &mut problems,
            &actual,
            &expected,
            &format!("{size} heap after"),
            |p| p.heap_after,
        );
        check_same(
            &mut problems,
            &actual,
            &expected,
            &format!("{size} total heap after"),
            |p| p.total_after,
        );
        let (outs_lo, outs_hi) = spread(&expected, |p| p.outs);
        let (reds_lo, reds_hi) = spread(&expected, |p| p.reds);
        let floor = cells / 60;
        for run in &actual {
            if run.outs < outs_lo || run.outs > outs_hi + 2 {
                problems.push(format!(
                    "{size} scheduler-outs: Arinsal {actual:?} vs OTP {expected:?}"
                ));
            }
            if run.reds < floor {
                problems.push(format!(
                    "{size} reductions below the cost of the reversal: Arinsal {actual:?}"
                ));
            }
            if size != "800k" {
                let slack = ((reds_hi - reds_lo) + reds_hi / 50).max(8);
                if run.reds < reds_lo - slack || run.reds > reds_hi + slack {
                    problems.push(format!(
                        "{size} reductions: Arinsal {actual:?} vs OTP {expected:?}"
                    ));
                }
            }
        }
    }
    assert!(problems.is_empty(), "{problems:#?}");
}
