//! Scheduler-path differential checks for global refcounted binary memory.

use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::{EncodeOptions, decode, encode};
use arinsal_vm::Vm;

const SOURCE: &str = r#"
-module(bin_accounting_diff).
-export([run/0, badarg/0]).

run() ->
    Before = erlang:memory(binary),
    TotalBefore = erlang:memory(total),
    _ = ets:new(bin_accounting, [named_table, public, set]),
    {Allocated, TotalAllocated, EtsRetained, PersistentRetained} = retain(Before, TotalBefore),
    _ = erlang:garbage_collect(),
    AfterProcessGc = erlang:memory(binary),
    _ = ets:delete(bin_accounting),
    _ = persistent_term:erase({bin_accounting, key}),
    _ = erlang:garbage_collect(),
    AfterOwnersRemoved = erlang:memory(binary),
    {Allocated > Before, TotalAllocated > TotalBefore,
     EtsRetained >= Allocated, PersistentRetained >= EtsRetained,
     AfterProcessGc >= Allocated, AfterOwnersRemoved < AfterProcessGc}.

retain(Before, TotalBefore) ->
    Bin = binary:copy(<<1>>, 200000),
    Allocated = erlang:memory(binary),
    TotalAllocated = erlang:memory(total),
    _ = ets:insert(bin_accounting, {key, Bin}),
    EtsRetained = erlang:memory(binary),
    _ = persistent_term:put({bin_accounting, key}, Bin),
    PersistentRetained = erlang:memory(binary),
    {Allocated, TotalAllocated, EtsRetained, PersistentRetained}.

badarg() -> try erlang:memory(not_a_category) catch error:badarg -> badarg end.
"#;

fn call(vm: &mut Vm, function: &str) -> CallResult {
    let actual = vm
        .eval_scheduled("bin_accounting_diff", function, &[], 2, None)
        .unwrap();
    let canonical = decode(&encode(&actual.term, EncodeOptions::default())).unwrap();
    CallResult::Ok(canonical)
}

#[test]
fn binary_memory_lifetime_matches_erts() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping binary memory differential test");
        return;
    };
    let beam = reference
        .compile_named("bin_accounting_diff", SOURCE, &[])
        .unwrap();
    reference.load("bin_accounting_diff", &beam).unwrap();
    let expected = reference.call("bin_accounting_diff", "run", &[]);
    let expected_error = reference.call("bin_accounting_diff", "badarg", &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();

    assert_eq!(expected, call(&mut vm, "run"));
    assert_eq!(expected_error, call(&mut vm, "badarg"));
}

#[test]
fn module_literal_binary_memory_matches_erts() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping module literal binary differential test");
        return;
    };
    let source = r#"
-module(bin_accounting_literal).
-export([value/0]).
value() -> {literal, <<16#5a:1600000>>}.
"#;
    let beam = reference
        .compile_named("bin_accounting_literal", source, &[])
        .unwrap();
    let reference_before = reference.eval("erlang:memory(binary)").unwrap();
    reference.load("bin_accounting_literal", &beam).unwrap();
    let reference_after = reference.eval("erlang:memory(binary)").unwrap();

    let local_before = arinsal_term::binary_memory_bytes();
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let expected_value = reference.call("bin_accounting_literal", "value", &[]);
    let actual_value = vm
        .eval_scheduled("bin_accounting_literal", "value", &[], 1, None)
        .unwrap();
    let canonical_value = decode(&encode(&actual_value.term, EncodeOptions::default())).unwrap();
    assert_eq!(expected_value, CallResult::Ok(canonical_value));
    let local_after = arinsal_term::binary_memory_bytes();
    let increased = |before: &arinsal_etf::OwnedTerm, after: &arinsal_etf::OwnedTerm| {
        let (arinsal_etf::OwnedTerm::Int(before), arinsal_etf::OwnedTerm::Int(after)) =
            (before, after)
        else {
            panic!("memory(binary) must return integers: {before:?} {after:?}");
        };
        after > before
    };
    assert_eq!(
        increased(&reference_before, &reference_after),
        local_after > local_before
    );
}

const CROSS_SCHEDULER_SOURCE: &str = r#"
-module(bin_accounting_cross).
-export([run/0]).

run() ->
    _ = erts_debug:set_internal_state(available_internal_state, true),
    Base = erlang:memory(binary),
    Self = self(),
    Consumer = spawn_opt(fun() ->
                                 receive {bin, Bin} -> Self ! {held, byte_size(Bin)} end,
                                 receive stop -> ok end
                         end, [{scheduler, 2}]),
    Producer = spawn_opt(fun() ->
                                 Bin = binary:copy(<<1>>, 400000),
                                 Consumer ! {bin, Bin},
                                 Self ! produced
                         end, [{scheduler, 1}]),
    receive produced -> ok end,
    receive {held, Size} -> ok end,
    Allocated = erlang:memory(binary),
    MRef = erlang:monitor(process, Consumer),
    Consumer ! stop,
    receive {'DOWN', MRef, process, Consumer, _} -> ok end,
    _ = Producer,
    _ = erts_debug:set_internal_state(wait, deallocations),
    After = erlang:memory(binary),
    {Size, Allocated >= Base + 400000, After < Base + 100000}.
"#;

#[test]
fn binary_freed_on_another_scheduler_is_gone_after_wait_deallocations() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping cross-scheduler binary differential test");
        return;
    };
    let beam = reference
        .compile_named("bin_accounting_cross", CROSS_SCHEDULER_SOURCE, &[])
        .unwrap();
    reference.load("bin_accounting_cross", &beam).unwrap();
    let expected = reference.call("bin_accounting_cross", "run", &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled("bin_accounting_cross", "run", &[], 2, None)
        .unwrap();
    let canonical = decode(&encode(&actual.term, EncodeOptions::default())).unwrap();
    assert_eq!(expected, CallResult::Ok(canonical));
}
