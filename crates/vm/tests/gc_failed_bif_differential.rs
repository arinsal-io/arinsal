//! A BIF that fails still goes through the GC-desired test (erts_gc_after_bif_call_lhf), so a
//! caught-exception loop collects as often as erts instead of piling stacktraces into heap
//! fragments.

use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_vm::Vm;

const MODULE: &str = "gc_failed_bif_differential";
const SOURCE: &str = r#"
-module(gc_failed_bif_differential).
-export([run/0]).

run() ->
    Self = self(),
    spawn_opt(fun() ->
        {Count0, _, _} = erlang:statistics(garbage_collection),
        loop(100000),
        {Count1, _, _} = erlang:statistics(garbage_collection),
        {_, Info} = process_info(self(), garbage_collection_info),
        Self ! {done, Count1 - Count0, proplists:get_value(heap_size, Info)}
    end, [{min_heap_size, 233}]),
    receive {done, Count, _Heap} -> Count end.

loop(0) -> ok;
loop(N) ->
    try ets:lookup(gc_failed_bif_missing, k) catch error:_ -> ok end,
    loop(N - 1).
"#;

fn count(term: &OwnedTerm) -> i64 {
    match term {
        OwnedTerm::Int(value) => *value,
        other => panic!("expected integer, got {other:?}"),
    }
}

#[test]
fn caught_failing_bif_loop_collects_as_often_as_otp() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping failed-BIF GC differential test");
        return;
    };
    let beam = reference
        .compile_named(MODULE, SOURCE, &[])
        .expect("compile probe");
    reference.load(MODULE, &beam).expect("load probe");
    let references = (0..3)
        .map(|_| match reference.call(MODULE, "run", &[]) {
            CallResult::Ok(term) => count(&term),
            other => panic!("reference loop failed: {other:?}"),
        })
        .collect::<Vec<_>>();
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).expect("load probe into Arinsal");
    let actual = count(
        &vm.eval_scheduled(MODULE, "run", &[], 1, None)
            .expect("Arinsal loop")
            .term,
    );
    let (low, high) = (
        *references.iter().min().unwrap(),
        *references.iter().max().unwrap(),
    );
    // Before the fix Arinsal collected ~60x less often (stacktraces went to fragments).
    assert!(
        actual >= low * 8 / 10 && actual <= high * 12 / 10,
        "Arinsal GCs={actual}, OTP={references:?}"
    );
}
