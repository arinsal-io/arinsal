use arinsal_difftest::{CallResult, RefErl};
use arinsal_vm::Vm;
use std::sync::Mutex;

static FLAG_TEST_LOCK: Mutex<()> = Mutex::new(());

const SOURCE: &str = r#"
-module(sysflag_rt).
-export([online/0, heap_defaults/0, control_flags/0,
         topology/0, bind_type/0, allocator/0, invalid_topology/0,
         topology_round_trip/0, blocked_scheduler_run_queue/0,
         microstate_after_disable/0, blocker_exit/0, change_flags/0,
         runtime_defaults/0]).

%% erts_continue_exit_process releases the blocks an exiting process holds.
blocker_exit() ->
    S = self(),
    P = spawn(fun() ->
                  R = erlang:system_flag(multi_scheduling, block),
                  S ! {r, R},
                  receive stop -> ok end
              end),
    R1 = receive {r, R} -> R end,
    A = {R1, erlang:system_info(multi_scheduling),
         erlang:system_info(multi_scheduling_blockers) =:= [P],
         erlang:system_flag(multi_scheduling, unblock)},
    M = monitor(process, P),
    P ! stop,
    receive {'DOWN', M, _, _, _} -> ok end,
    B = {erlang:system_info(multi_scheduling),
         erlang:system_info(multi_scheduling_blockers)},
    C1 = erlang:system_flag(multi_scheduling, block),
    C2 = erlang:system_flag(multi_scheduling, block),
    C3 = erlang:system_flag(multi_scheduling, unblock),
    C4 = erlang:system_info(multi_scheduling_blockers) =:= [self()],
    C5 = erlang:system_flag(multi_scheduling, unblock),
    D1 = erlang:system_flag(multi_scheduling, block_normal),
    D2 = erlang:system_info(normal_multi_scheduling_blockers) =:= [self()],
    D3 = erlang:system_flag(multi_scheduling, block),
    D4 = erlang:system_flag(multi_scheduling, unblock_normal),
    D5 = erlang:system_flag(multi_scheduling, unblock),
    D6 = erlang:system_flag(multi_scheduling, unblock),
    E = spawn(fun() ->
                  blocked_normal = erlang:system_flag(multi_scheduling, block_normal),
                  exit(kill_me)
              end),
    EM = monitor(process, E),
    receive {'DOWN', EM, _, _, _} -> ok end,
    {A, B, {C1, C2, C3, C4, C5}, {D1, D2, D3, D4, D5, D6},
     erlang:system_info(multi_scheduling),
     erlang:system_info(normal_multi_scheduling_blockers)}.

%% Leaves every flag changed; a later runtime must not see these values.
change_flags() ->
    erlang:system_flag(fullsweep_after, 7),
    erlang:system_flag(min_heap_size, 1000),
    erlang:system_flag(min_bin_vheap_size, 100000),
    erlang:system_flag(trace_control_word, 5),
    erlang:system_flag(outstanding_system_requests_limit, 3),
    erlang:system_flag(schedulers_online, 1),
    erlang:system_flag(multi_scheduling, block_normal),
    ok.

runtime_defaults() ->
    {erlang:system_info(fullsweep_after), erlang:system_info(min_heap_size),
     erlang:system_info(min_bin_vheap_size),
     erlang:system_flag(trace_control_word, 0),
     erlang:system_flag(outstanding_system_requests_limit, 1 bsl 20),
     erlang:system_info(schedulers_online),
     erlang:system_info(dirty_cpu_schedulers_online),
     erlang:system_info(multi_scheduling),
     element(2, process_info(spawn(fun() -> receive _ -> ok end end),
                             min_bin_vheap_size))}.

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

blocked_scheduler_run_queue() ->
    Previous = erlang:system_flag(multi_scheduling, block),
    Pid = spawn(fun Hog() -> Hog() end),
    receive after 20 -> ok end,
    Queue = erlang:statistics(run_queue),
    exit(Pid, kill),
    Enabled = erlang:system_flag(multi_scheduling, unblock),
    {Previous, Queue > 0, Enabled}.

microstate_after_disable() ->
    Previous = erlang:system_flag(microstate_accounting, true),
    WasEnabled = is_list(erlang:statistics(microstate_accounting)),
    Stopped = erlang:system_flag(microstate_accounting, false),
    IsRetained = is_list(erlang:statistics(microstate_accounting)),
    Reset = erlang:system_flag(microstate_accounting, reset),
    ResetIsZero = lists:all(
        fun(#{counters := Counters}) ->
            lists:all(fun(Value) -> Value =:= 0 end, maps:values(Counters))
        end,
        erlang:statistics(microstate_accounting)),
    {Previous, WasEnabled, Stopped, IsRetained, Reset, ResetIsZero}.

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
fn sysflag_rt_microstate_counters_remain_readable_after_disable() {
    compare("microstate_after_disable");
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

#[test]
fn sysflag_rt_blocked_scheduler_keeps_the_caller_runnable() {
    compare("blocked_scheduler_run_queue");
}

#[test]
fn sysflag_rt_exiting_blocker_releases_multi_scheduling() {
    compare("blocker_exit");
}

/// Several runtimes share this OS process; erts keeps these flags per emulator.
#[test]
fn sysflag_rt_flags_are_per_runtime() {
    let _lock = FLAG_TEST_LOCK.lock().expect("system flag test lock");
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping per-runtime system flag test");
        return;
    };
    let beam = reference
        .compile_named("sysflag_rt", SOURCE, &[])
        .expect("compile system flag fixture");
    reference.load("sysflag_rt", &beam).expect("load reference");
    let expected = reference.call("sysflag_rt", "runtime_defaults", &[]);
    let mut first = Vm::new([]);
    first.load_bytes(&beam).expect("load first VM");
    let changed = first
        .eval_scheduled("sysflag_rt", "change_flags", &[], 1, None)
        .unwrap_or_else(|error| panic!("change_flags: {error}"));
    assert_eq!(changed.term, arinsal_etf::OwnedTerm::Atom("ok".into()));
    let mut second = Vm::new([]);
    second.load_bytes(&beam).expect("load second VM");
    let actual = second
        .eval_scheduled("sysflag_rt", "runtime_defaults", &[], 1, None)
        .unwrap_or_else(|error| panic!("runtime_defaults: {error}"));
    assert_eq!(expected, CallResult::Ok(actual.term));
}
