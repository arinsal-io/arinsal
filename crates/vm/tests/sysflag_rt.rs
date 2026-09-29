use arinsal_difftest::{CallResult, RefErl};
use arinsal_vm::Vm;
use std::sync::Mutex;

static FLAG_TEST_LOCK: Mutex<()> = Mutex::new(());

const SOURCE: &str = r#"
-module(sysflag_rt).
-export([online/0, heap_defaults/0, control_flags/0,
         topology/0, bind_type/0, allocator/0, invalid_topology/0,
         topology_round_trip/0]).

online() ->
    Current = erlang:system_info(schedulers_online),
    Previous = erlang:system_flag(schedulers_online, Current),
    Blocked = erlang:system_flag(multi_scheduling, block),
    Enabled = erlang:system_flag(multi_scheduling, unblock),
    {Current, Previous, erlang:system_info(schedulers_online), Blocked, Enabled}.

heap_defaults() ->
    Full = erlang:system_flag(fullsweep_after, 42),
    erlang:system_flag(fullsweep_after, Full),
    MinHeap = erlang:system_flag(min_heap_size, 377),
    erlang:system_flag(min_heap_size, MinHeap),
    MinBinaryHeap = erlang:system_flag(min_bin_vheap_size, 46422),
    erlang:system_flag(min_bin_vheap_size, MinBinaryHeap),
    {Full, MinHeap, MinBinaryHeap}.

control_flags() ->
    Trace = erlang:system_flag(trace_control_word, 3),
    erlang:system_flag(trace_control_word, Trace),
    Limit = erlang:system_flag(outstanding_system_requests_limit, 64),
    erlang:system_flag(outstanding_system_requests_limit, Limit),
    {Trace, Limit}.

topology() ->
    Old = erlang:system_flag(cpu_topology, undefined),
    {Old, erlang:system_info(cpu_topology),
     erlang:system_info({cpu_topology, defined}),
     erlang:system_info({cpu_topology, detected}),
     erlang:system_info({cpu_topology, used}),
     erlang:system_info(scheduler_bindings),
     erlang:system_info(scheduler_bind_type),
     erlang:system_info(logical_processors),
     erlang:system_info(logical_processors_available),
     erlang:system_info(logical_processors_online)}.

bind_type() ->
    {erlang:system_flag(scheduler_bind_type, unbound),
     outcome(fun() -> erlang:system_flag(scheduler_bind_type, invalid) end),
     outcome(fun() -> erlang:system_flag(scheduler_bind_type, spread) end)}.

allocator() ->
    Allocators = [temp_alloc, sl_alloc, std_alloc, ll_alloc, eheap_alloc,
                  ets_alloc, fix_alloc, literal_alloc, binary_alloc,
                  driver_alloc, sys_alloc, test_alloc, mseg_alloc,
                  unknown_alloc],
    { [{Allocator,
        outcome(fun() -> erlang:system_flag(erts_alloc,
                                            {Allocator, sbct, 123}) end)}
       || Allocator <- Allocators],
      outcome(fun() -> erlang:system_flag(erts_alloc,
                                          {temp_alloc, other, 123}) end),
      outcome(fun() -> erlang:system_flag(erts_alloc,
                                          {temp_alloc, sbct, -1}) end),
      outcome(fun() -> erlang:system_flag(erts_alloc,
                                          {temp_alloc, sbct, not_integer}) end)}.

invalid_topology() ->
    outcome(fun() -> erlang:system_flag(cpu_topology, []) end).

topology_round_trip() ->
    Topology = [{processor, {logical, 0}}],
    Previous = erlang:system_flag(cpu_topology, Topology),
    Current = {erlang:system_info(cpu_topology),
               erlang:system_info({cpu_topology, defined}),
               erlang:system_info({cpu_topology, used}),
               erlang:system_info({cpu_topology, detected})},
    Restored = erlang:system_flag(cpu_topology, undefined),
    {Previous, Current, Restored, erlang:system_info(cpu_topology)}.

outcome(Fun) ->
    try Fun() catch
        Class:Reason:Stack ->
            {Class, Reason,
             proplists:get_value(error_info, element(3, hd(Stack)), undefined)}
    end.
"#;

fn compare(function: &str) {
    let _lock = FLAG_TEST_LOCK.lock().expect("system flag test lock");
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping system flag differential test");
        return;
    };
    let beam = reference
        .compile_named("sysflag_rt", SOURCE, &[])
        .expect("compile system flag fixture");
    reference.load("sysflag_rt", &beam).expect("load reference");
    let expected = reference.call("sysflag_rt", function, &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).expect("load VM fixture");
    let actual = vm
        .eval_scheduled("sysflag_rt", function, &[], 1, None)
        .unwrap_or_else(|error| panic!("{function}: {error}"));
    assert_eq!(expected, CallResult::Ok(actual.term), "{function}");
}

#[test]
fn sysflag_rt_scheduler_and_blocking_round_trip_matches_otp() {
    compare("online");
}

#[test]
fn sysflag_rt_heap_defaults_round_trip_matches_otp() {
    compare("heap_defaults");
}

#[test]
fn sysflag_rt_control_flags_round_trip_matches_otp() {
    compare("control_flags");
}

#[test]
fn sysflag_rt_cpu_topology_and_system_info_match_otp() {
    compare("topology");
}

#[test]
fn sysflag_rt_scheduler_bind_type_matches_otp() {
    compare("bind_type");
}

#[test]
fn sysflag_rt_allocator_results_match_otp() {
    compare("allocator");
}

#[test]
fn sysflag_rt_invalid_cpu_topology_matches_otp() {
    compare("invalid_topology");
}

#[test]
fn sysflag_rt_user_cpu_topology_round_trip_matches_otp() {
    compare("topology_round_trip");
}
