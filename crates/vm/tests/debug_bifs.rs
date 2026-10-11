use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_vm::Vm;

const SOURCE: &str = r#"
-module(debug_bifs_diff).
-export([map_layout/0, hash_children/0, bits/0, misc/0, errors/0, term_types/0,
         instructions/0, internal_state/0, monitor/0, monitor_large_heap/0,
         internal_state_gets/0, internal_state_sets/0, internal_state_errors/0,
         internal_state_get_tuples/0, internal_state_more_get_tuples/0,
         internal_state_ets_and_magic_ref/0,
         internal_state_set_remaining/0,
         internal_state_get_ported/0, internal_state_get_ported_tuples/0,
         internal_state_set_ported/0, internal_state_multizero_timer/0,
         internal_state_fill_heap/0,
         internal_state_get_remaining_tuples/0,
         internal_state_proc_sig_block/0,
         internal_state_inconsistent/0, internal_state_abort/0, internal_state_broken_halt/0,
         reader_group_maps/0,
         monitor_long_schedule/0, monitor_long_gc/0, monitor_long_message_queue/0,
         allocator_info/0]).

map_layout() ->
    Flat = #{1 => 1, 2 => 2, 3 => 3},
    Large = #{1 => 2, 2 => 4, 3 => 6, 4 => 8, 5 => 10, 6 => 12, 7 => 14, 8 => 16,
              9 => 18, 10 => 20, 11 => 22, 12 => 24, 13 => 26, 14 => 28, 15 => 30,
              16 => 32, 17 => 34, 18 => 36, 19 => 38, 20 => 40, 21 => 42, 22 => 44,
              23 => 46, 24 => 48, 25 => 50, 26 => 52, 27 => 54, 28 => 56, 29 => 58,
              30 => 60, 31 => 62, 32 => 64, 33 => 66, 34 => 68, 35 => 70, 36 => 72,
              37 => 74, 38 => 76, 39 => 78, 40 => 80},
    {erts_internal:term_type(Flat), erts_internal:map_to_tuple_keys(Flat),
     erts_internal:term_type(Large), erts_debug:map_info(Large)}.
hash_children() -> erts_internal:map_hashmap_children(#{1 => 2, 2 => 4, 3 => 6, 4 => 8,
                                         5 => 10, 6 => 12, 7 => 14, 8 => 16, 9 => 18, 10 => 20,
                                         11 => 22, 12 => 24, 13 => 26, 14 => 28, 15 => 30,
                                         16 => 32, 17 => 34, 18 => 36, 19 => 38, 20 => 40,
                                         21 => 42, 22 => 44, 23 => 46, 24 => 48, 25 => 50,
                                         26 => 52, 27 => 54, 28 => 56, 29 => 58, 30 => 60,
                                         31 => 62, 32 => 64, 33 => 66, 34 => 68, 35 => 70,
                                         36 => 72, 37 => 74, 38 => 76, 39 => 78, 40 => 80}).

bits() -> erts_debug:unaligned_bitstring(<<101:13>>, 3).

misc() ->
    {erts_debug:interpreter_size(), erts_debug:disassemble({debug_bifs_diff, maps, 0}),
     erts_debug:lcnt_clear(), erts_debug:lcnt_collect(),
     erts_internal:system_check(schedulers), erts_internal:system_monitor(legacy),
     erts_debug:dirty(normal, scheduler, type),
     erts_debug:dirty_cpu(scheduler, type), erts_debug:dirty_io(scheduler, type)}.

errors() ->
    {caught(fun() -> erts_debug:copy_shared(a, not_valid) end),
     caught(fun() -> erts_debug:lcnt_control(unknown) end),
     caught(fun() -> erts_internal:map_hashmap_children(not_a_map) end),
     caught(fun() -> erts_internal:map_to_tuple_keys(#{a => 1}) end),
     caught(fun() -> erts_internal:system_check(no_such_check) end)}.

term_types() ->
    {erts_internal:term_type(self()),
     erts_internal:term_type(open_port),
     erts_internal:term_type(fun erlang:abs/1),
     erts_internal:term_type(fun(X) -> X end)}.

instructions() -> erts_debug:instructions().

internal_state() ->
    erts_debug:set_internal_state(available_internal_state, true),
    Values = {erts_debug:get_internal_state(available_internal_state),
              erts_debug:get_internal_state(force_heap_frags),
              erts_debug:get_internal_state(scheduler_dump),
              erts_debug:get_internal_state(lc_graph),
              erts_debug:get_internal_state(flxctr_memory_usage),
              erts_debug:get_internal_state(re_yield_coverage),
              erts_debug:get_internal_state(debugger_support),
              erts_debug:get_internal_state(dirty_gc_limit),
              erts_debug:get_internal_state(hashmap_collision_bonanza),
              erts_debug:get_internal_state(process_info_args)},
    {Values, ok}.

internal_state_gets() ->
    erts_debug:set_internal_state(available_internal_state, true),
    Result = {erts_debug:get_internal_state(mmap),
              erts_debug:get_internal_state(unique_monotonic_integer_state),
              erts_debug:get_internal_state(min_unique_monotonic_integer),
              erts_debug:get_internal_state(min_unique_integer),
              erts_debug:get_internal_state(stack_check),
              erts_debug:get_internal_state({check_time_config, true, multi_time_warp}),
              erts_debug:get_internal_state(max_atom_out_cache_index),
              erts_debug:get_internal_state(scheduler_dump),
              erts_debug:get_internal_state(lc_graph),
              erts_debug:get_internal_state('flxctr_memory_usage')},
    Result.

internal_state_get_tuples() ->
    erts_debug:set_internal_state(available_internal_state, true),
    {erts_debug:get_internal_state({reader_groups_map, 1}),
              erts_debug:get_internal_state({atom_out_cache_index, true}),
              erts_debug:get_internal_state({atom, 3}),
              erts_debug:get_internal_state({make_unique_integer, 0, 1}),
              erts_debug:get_internal_state({term_to_binary, abc, []}),
     caught(fun() -> erts_debug:get_internal_state({connection_id, foo}) end)}.

reader_group_maps() ->
    erts_debug:set_internal_state(available_internal_state, true),
    Topology = [p([c(l(0)),c(l(1)),c(l(2)),c(l(3)),c(l(4))]),
                p([t(l(5)),t(l(6)),t(l(7)),t(l(8)),t(l(9))]),
                p([t(l(10))]),
                p([c(l(11)),c(l(12)),c(l(13))]),
                p([c(l(14)),c(l(15))])],
    erlang:system_flag(cpu_topology, Topology),
    Result1 = [erts_debug:get_internal_state({reader_groups_map, N}) || N <- [2,5,6,7,8,9,10,100]],
    Topology2 = [{processor,[{node,[{core,l(20)},{core,l(21)}]},
                             {node,[{core,l(22)},{core,l(23)}]},
                             {node,[{core,l(24)},{core,l(25)}]}]}],
    erlang:system_flag(cpu_topology, Topology2),
    Result2 = [erts_debug:get_internal_state({reader_groups_map, N}) || N <- [2,3,5]],
    Topology3 = [p([t(l(0)),t(l(1)),t(l(2)),t(l(3)),t(l(4))]),
                 p([t(l(5))]),
                 p([c(l(6)),c(l(7)),c(l(8))]),
                 p([c(l(9)),c(l(10))]),
                 p([c(l(11)),c(l(12)),c(l(13)),c(l(14)),c(l(15))])],
    erlang:system_flag(cpu_topology, Topology3),
    Result3 = [erts_debug:get_internal_state({reader_groups_map, N}) || N <- [6,7]],
    erlang:system_flag(cpu_topology, undefined),
    {Result1, Result2, Result3}.

p(Children) -> {processor, Children}.
c(Child) -> {core, Child}.
t(Child) -> {thread, Child}.
l(Id) -> {logical, Id}.

internal_state_more_get_tuples() ->
    erts_debug:set_internal_state(available_internal_state, true),
    {erts_debug:get_internal_state({make_unique_integer, 0, 0}),
     erts_debug:get_internal_state({magic_ref, not_a_reference}),
     erts_debug:set_internal_state(colliding_names, {foo, 0}),
     caught(fun() -> erts_debug:set_internal_state(colliding_names, invalid) end)}.

internal_state_ets_and_magic_ref() ->
    erts_debug:set_internal_state(available_internal_state, true),
    Tab = ets:new(internal_state_catree, [ordered_set, {write_concurrency, auto}]),
    Split = erts_debug:set_internal_state(ets_force_split, {Tab, true}),
    Random = erts_debug:set_internal_state(ets_debug_random_split_join, {Tab, true}),
    {MagicRef, Address} = erts_debug:set_internal_state(make, magic_ref),
    ets:delete(Tab),
    {Split, Random, is_reference(MagicRef), is_integer(Address)}.

internal_state_set_remaining() ->
    erts_debug:set_internal_state(available_internal_state, true),
    Self = self(),
    {erts_debug:set_internal_state(force_gc, Self),
     erts_debug:set_internal_state(force_gc, make_ref()),
     erts_debug:set_internal_state(mbuf, {a, b}),
     erts_debug:set_internal_state(remove_dflags, 0),
     erts_debug:set_internal_state(node_tab_delayed_delete, 0),
     erts_debug:set_internal_state(code_mod_permission, true),
     erts_debug:set_internal_state(code_mod_permission, false),
     erts_debug:set_internal_state(node_tab_delayed_delete, -1),
     erts_debug:set_internal_state(multizero_timeout_in_timeout, 0),
     erts_debug:set_internal_state(process_uniq_counter, 17),
     erts_debug:set_internal_state(wait, deallocations),
     erts_debug:set_internal_state(wait, timer_cancellations),
     erts_debug:set_internal_state(wait, aux_work),
     erts_debug:set_internal_state(wait, thread_progress),
     erts_debug:set_internal_state(proc_sig_block, {Self, 0}),
     erts_debug:set_internal_state(kill_dist_connection, internal_state_no_node)}.

internal_state_fill_heap() ->
    erts_debug:set_internal_state(available_internal_state, true),
    erts_debug:set_internal_state(fill_heap, false).

internal_state_get_remaining_tuples() ->
    erts_debug:set_internal_state(available_internal_state, true),
    Parent = self(),
    Probe = spawn(fun() -> Parent ! ready, receive stop -> ok end end),
    receive ready -> ok end,
    Result = {erts_debug:get_internal_state({process_status, Probe}),
     erts_debug:get_internal_state({link_list, Probe}),
     erts_debug:get_internal_state({monitor_list, Probe}),
     erts_debug:get_internal_state({channel_number, nonode@nohost}),
     erts_debug:get_internal_state({dist_ctrl, nonode@nohost}),
     erts_debug:get_internal_state({binary_info, <<1>>}),
     erts_debug:get_internal_state({fake_scheduler_bindings, default_bind}),
     caught(fun() -> erts_debug:get_internal_state({fake_scheduler_bindings, invalid}) end)},
    Probe ! stop,
    Result.

internal_state_get_ported() ->
    erts_debug:set_internal_state(available_internal_state, true),
    Memory = erts_debug:get_internal_state(memory),
    Processes = erts_debug:get_internal_state(processes),
    Nodes = erts_debug:get_internal_state(monitoring_nodes),
    References = erts_debug:get_internal_state(node_and_dist_references),
    {lists:sort([K || {K, _} <- Memory]),
     lists:member(self(), Processes), is_list(Nodes), References}.

internal_state_get_ported_tuples() ->
    erts_debug:set_internal_state(available_internal_state, true),
    Binary = binary:copy(<<7>>, 128),
    Refc = erts_debug:get_internal_state({binary_info, Binary}),
    _ = erlang:system_flag(multi_scheduling, block),
    BlockedReferences = try
        erts_debug:get_internal_state({node_and_dist_references, blocked})
    after
        erlang:system_flag(multi_scheduling, unblock)
    end,
    {{erts_debug:get_internal_state({process_status, self()}),
      is_list(erts_debug:get_internal_state({link_list, self()})),
      is_list(erts_debug:get_internal_state({monitor_list, self()})),
      erts_debug:get_internal_state({dist_ctrl, nonode@nohost})},
     {element(1, Refc), element(2, Refc), element(3, Refc), element(4, Refc)},
     caught(fun() -> erts_debug:get_internal_state({node_and_dist_references, blocked}) end),
     BlockedReferences}.

internal_state_set_ported() ->
    erts_debug:set_internal_state(available_internal_state, true),
    {garbage_collection, Before} = process_info(self(), garbage_collection),
    Gc = erts_debug:set_internal_state(force_gc, self()),
    {garbage_collection, After} = process_info(self(), garbage_collection),
    {Gc, proplists:get_value(minor_gcs, After) - proplists:get_value(minor_gcs, Before)}.

internal_state_multizero_timer() ->
    erts_debug:set_internal_state(available_internal_state, true),
    ok = erts_debug:set_internal_state(multizero_timeout_in_timeout, 0),
    receive multizero_timeout_in_timeout_done -> ok
    after 1000 -> timeout
    end.

internal_state_proc_sig_block() ->
    erts_debug:set_internal_state(available_internal_state, true),
    Parent = self(),
    {Probe, Monitor} = spawn_monitor(fun() -> Parent ! ready, receive stop -> ok end end),
    receive ready -> ok end,
    Accepted = erts_debug:set_internal_state(proc_sig_block, {Probe, 50}),
    Probe ! stop,
    {Accepted, receive {'DOWN', Monitor, process, Probe, _} -> done after 1000 -> timeout end}.

internal_state_sets() ->
    erts_debug:set_internal_state(available_internal_state, true),
    Result = {erts_debug:set_internal_state(reds_left, 1000),
              erts_debug:set_internal_state(block, -1),
              erts_debug:set_internal_state(block, 1),
              erts_debug:set_internal_state(sleep, 0),
              erts_debug:set_internal_state(sleep, 1),
              erts_debug:set_internal_state(block_scheduler, 0),
              erts_debug:set_internal_state(block_scheduler, 1),
              erts_debug:set_internal_state(test_long_gc_sleep, 0),
              erts_debug:set_internal_state(jit_asm_dump, false),
              erts_debug:set_internal_state(proc_sig_buffers, true),
              erts_debug:set_internal_state(ets_force_trap, true),
              erts_debug:set_internal_state(binary_loop_limit, default),
              erts_debug:set_internal_state(re_loop_limit, default),
              erts_debug:set_internal_state(unicode_loop_limit, default),
              erts_debug:set_internal_state(binary, 0),
              erts_debug:set_internal_state(binary, 3),
              {erts_debug:set_internal_state(gc_state, false),
               erts_debug:set_internal_state(gc_state, true)},
              erts_debug:set_internal_state(proc_sig_block, {self(), 0}),
              erts_debug:set_internal_state(process_uniq_counter, 17),
              erts_debug:set_internal_state(unique_monotonic_integer_state,
                  erts_debug:get_internal_state(unique_monotonic_integer_state))},
    Result.

internal_state_errors() ->
    erts_debug:set_internal_state(available_internal_state, true),
    Result = {caught(fun() -> erts_debug:get_internal_state(no_such_internal_state) end),
              caught(fun() -> erts_debug:set_internal_state(reds_left, invalid) end),
              caught(fun() -> erts_debug:set_internal_state(gc_state, invalid) end),
              caught(fun() -> erts_debug:set_internal_state(test_long_gc_sleep, invalid) end)},
    erts_debug:set_internal_state(available_internal_state, false),
    Result.

internal_state_inconsistent() ->
    erts_debug:set_internal_state(available_internal_state, true),
    Broken = erts_debug:set_internal_state(inconsistent_heap, start),
    erts_debug:set_internal_state(inconsistent_heap, Broken).

internal_state_abort() ->
    erts_debug:set_internal_state(available_internal_state, true),
    erts_debug:set_internal_state(abort, why).

internal_state_broken_halt() ->
    erts_debug:set_internal_state(available_internal_state, true),
    erts_debug:set_internal_state(broken_halt, why).

monitor() ->
    Cleared = erlang:system_monitor(undefined),
    Old = erlang:system_monitor({self(), [busy_port, busy_dist_port,
        {long_gc, 0}, {long_schedule, 0}, {large_heap, 0},
        {long_message_queue, {0, 5}}]}),
    Current = erlang:system_monitor(),
    Removed = erlang:system_monitor(undefined),
    {Cleared, monitor_view(Old), monitor_view(Current), monitor_view(Removed)}.

monitor_large_heap() ->
    Parent = self(),
    Receiver = spawn(fun() -> receive M -> Parent ! {monitor_event, M} end end),
    erlang:system_monitor(Receiver, [{large_heap, 16384}]),
    spawn(fun() -> L = lists:seq(1, 25000), erlang:garbage_collect(), Parent ! {finished, length(L)} end),
    Result = receive {monitor_event, {monitor, _, large_heap, _}} -> large_heap
    after 1000 -> no_event
    end,
    erlang:system_monitor(undefined),
    Result.

monitor_long_schedule() ->
    Parent = self(),
    Receiver = spawn(fun() -> receive M -> Parent ! {monitor_event, M} end end),
    erlang:system_monitor(Receiver, [{long_schedule, 1}]),
    spawn(fun() -> erts_debug:dirty(normal, wait, 20) end),
    Result = receive {monitor_event, {monitor, _, long_schedule, _}} -> long_schedule
    after 1000 -> no_event
    end,
    erlang:system_monitor(undefined),
    Result.

monitor_long_gc() ->
    erts_debug:set_internal_state(available_internal_state, true),
    erts_debug:set_internal_state(test_long_gc_sleep, 10),
    Parent = self(),
    Receiver = spawn(fun() -> receive M -> Parent ! {monitor_event, M} end end),
    erlang:system_monitor(Receiver, [{long_gc, 1}]),
    spawn(fun() -> erlang:garbage_collect() end),
    Result = receive {monitor_event, {monitor, _, long_gc, _}} -> long_gc
    after 1000 -> no_event
    end,
    erlang:system_monitor(undefined),
    erts_debug:set_internal_state(test_long_gc_sleep, 0),
    erts_debug:set_internal_state(available_internal_state, false),
    Result.

monitor_long_message_queue() ->
    Parent = self(),
    Receiver = spawn(fun() -> receive M -> Parent ! {monitor_event, M} end end),
    erlang:system_monitor(Receiver, [{long_message_queue, {0, 5}}]),
    Target = spawn(fun() -> receive stop -> ok end end),
    [Target ! {data, N} || N <- lists:seq(1, 10)],
    Result = receive {monitor_event, {monitor, _, long_message_queue, true}} -> long_message_queue
    after 1000 -> no_event
    end,
    erlang:system_monitor(undefined),
    Result.

monitor_view(undefined) -> undefined;
monitor_view({Pid, Options}) -> {is_pid(Pid), Options}.

allocator_info() ->
    Ref1 = make_ref(),
    Count1 = erts_internal:gather_alloc_histograms({std_alloc, 0, 18, 128, 0, Ref1}),
    Hist = receive {Ref1, Start, Values} -> {Start, Values} end,
    Ref2 = make_ref(),
    Count2 = erts_internal:gather_carrier_info({ets_alloc, 0, 18, 128, 0, Ref2}),
    Carriers = receive {Ref2, Values2} -> Values2 end,
    {Count1, Hist, Count2, Carriers}.

caught(F) -> try F() of V -> {ok, V} catch error:R -> {error, R} end.
"#;

fn run(reference: &RefErl, function: &str) -> (CallResult, OwnedTerm) {
    let beam = reference
        .compile_named("debug_bifs_diff", SOURCE, &[])
        .expect("compile debug BIF fixture");
    reference
        .load("debug_bifs_diff", &beam)
        .expect("load reference");
    let expected = reference.call("debug_bifs_diff", function, &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).expect("load VM fixture");
    let actual = vm
        .eval_scheduled("debug_bifs_diff", function, &[], 1, None)
        .unwrap_or_else(|error| panic!("{function}: {error}"));
    (expected, actual.term)
}

fn assert_reference(expected: CallResult, actual: OwnedTerm) {
    similar_asserts::assert_eq!(expected, CallResult::Ok(actual));
}

fn run_vm(beam: &[u8], function: &str) -> OwnedTerm {
    let mut vm = Vm::new([]);
    vm.load_bytes(beam).expect("load VM fixture");
    vm.eval_scheduled("debug_bifs_diff", function, &[], 1, None)
        .unwrap_or_else(|error| panic!("{function}: {error}"))
        .term
}

#[test]
fn debug_bifs_hashmap_children_match_one_shot_otp() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping debug BIF HAMT child test");
        return;
    };
    let beam = reference
        .compile_named("debug_bifs_diff", SOURCE, &[])
        .expect("compile map children fixture");
    let actual = run_vm(&beam, "hash_children");
    let expression = "M=#{1=>2,2=>4,3=>6,4=>8,5=>10,6=>12,7=>14,8=>16,9=>18,10=>20,11=>22,12=>24,13=>26,14=>28,15=>30,16=>32,17=>34,18=>36,19=>38,20=>40,21=>42,22=>44,23=>46,24=>48,25=>50,26=>52,27=>54,28=>56,29=>58,30=>60,31=>62,32=>64,33=>66,34=>68,35=>70,36=>72,37=>74,38=>76,39=>78,40=>80}, io:put_chars([case is_map(C) of true->$M; false->$L end || C <- erts_internal:map_hashmap_children(M)]), halt().";
    let output = std::process::Command::new("erl")
        .args(["-noshell", "-eval", expression])
        .output()
        .expect("run one-shot OTP map child probe");
    assert!(
        output.status.success(),
        "erl failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let expected = output.stdout;
    let OwnedTerm::List { elems, tail } = &actual else {
        panic!("expected hashmap child list, got {actual:?}");
    };
    assert_eq!(**tail, OwnedTerm::Nil);
    let actual_kinds: Vec<_> = elems
        .iter()
        .map(|child| match child {
            OwnedTerm::Map(_) => b'M',
            OwnedTerm::List { .. } => b'L',
            other => panic!("unexpected HAMT child {other:?}"),
        })
        .collect();
    assert_eq!(expected, actual_kinds);
}

#[test]
fn debug_bifs_map_layout_matches_otp() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping debug BIF map layout test");
        return;
    };
    let (expected, actual) = run(&reference, "map_layout");
    assert_reference(expected, actual);
    let (expected, actual) = run(&reference, "bits");
    assert_reference(expected, actual);
    let (expected, actual) = run(&reference, "term_types");
    assert_reference(expected, actual);
    let (expected, actual) = run(&reference, "instructions");
    assert_reference(expected, actual);
}

#[test]
fn debug_bifs_feature_defaults_match_otp() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping debug BIF feature test");
        return;
    };
    let (expected, actual) = run(&reference, "misc");
    assert_reference(expected, actual);
}

#[test]
fn debug_bifs_errors_match_otp() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping debug BIF error test");
        return;
    };
    let (expected, actual) = run(&reference, "errors");
    assert_reference(expected, actual);
}

#[test]
fn debug_bifs_internal_state_matches_otp() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping debug BIF internal-state test");
        return;
    };
    let (expected, actual) = run(&reference, "internal_state");
    assert_reference(expected, actual);
}

#[test]
fn internal_state_get_dispatch_matches_otp() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping internal-state get test");
        return;
    };
    let (expected, actual) = run(&reference, "internal_state_gets");
    assert_reference(expected, actual);
}

#[test]
fn internal_state_set_dispatch_matches_otp() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping internal-state set test");
        return;
    };
    let (expected, actual) = run(&reference, "internal_state_sets");
    assert_reference(expected, actual);
}

#[test]
fn internal_state_tuple_get_dispatch_matches_otp() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping internal-state tuple-get test");
        return;
    };
    let (expected, actual) = run(&reference, "internal_state_get_tuples");
    assert_reference(expected, actual);
}

#[test]
fn debug_reader_group_maps_match_otp() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping reader-group map differential test");
        return;
    };
    let (expected, actual) = run(&reference, "reader_group_maps");
    assert_reference(expected, actual);
}

#[test]
fn internal_state_remaining_tuple_dispatch_matches_otp() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping remaining internal-state tuple test");
        return;
    };
    let (expected, actual) = run(&reference, "internal_state_more_get_tuples");
    assert_reference(expected, actual);
}

#[test]
fn internal_state_get_ported_dispatch_matches_otp() {
    let reference = RefErl::start().expect("reference Erlang runtime");
    let (expected, actual) = run(&reference, "internal_state_get_ported");
    assert_reference(expected, actual);
}

#[test]
fn internal_state_get_ported_tuples_match_otp() {
    let reference = RefErl::start().expect("reference Erlang runtime");
    let (expected, actual) = run(&reference, "internal_state_get_ported_tuples");
    assert_reference(expected, actual);
}

#[test]
fn internal_state_set_ported_dispatch_matches_otp() {
    let reference = RefErl::start().expect("reference Erlang runtime");
    let (expected, actual) = run(&reference, "internal_state_set_ported");
    assert_reference(expected, actual);
}

#[test]
fn internal_state_multizero_timer_callbacks_match_otp() {
    let reference = RefErl::start().expect("reference Erlang runtime");
    let (expected, actual) = run(&reference, "internal_state_multizero_timer");
    assert_reference(expected, actual);
}

#[test]
fn internal_state_proc_sig_block_runs_on_target() {
    let reference = RefErl::start().expect("reference Erlang runtime");
    let (expected, actual) = run(&reference, "internal_state_proc_sig_block");
    assert_reference(expected, actual);
}

#[test]
fn internal_state_ets_and_magic_ref_dispatch_matches_otp() {
    let reference = RefErl::start().expect("reference Erlang runtime");
    let (expected, actual) = run(&reference, "internal_state_ets_and_magic_ref");
    assert_reference(expected, actual);
}

#[test]
fn internal_state_set_remaining_dispatch_matches_otp() {
    let reference = RefErl::start().expect("reference Erlang runtime");
    let (expected, actual) = run(&reference, "internal_state_set_remaining");
    assert_reference(expected, actual);
}

#[test]
fn internal_state_fill_heap_dispatch_matches_otp() {
    let reference = RefErl::start().expect("reference Erlang runtime");
    let (expected, actual) = run(&reference, "internal_state_fill_heap");
    assert_reference(expected, actual);
}

#[test]
fn internal_state_get_remaining_tuples_dispatch_matches_otp() {
    let reference = RefErl::start().expect("reference Erlang runtime");
    let (expected, actual) = run(&reference, "internal_state_get_remaining_tuples");
    assert_reference(expected, actual);
}

#[test]
fn internal_state_invalid_arguments_match_otp() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping internal-state error test");
        return;
    };
    let (expected, actual) = run(&reference, "internal_state_errors");
    assert_reference(expected, actual);
}

#[test]
fn internal_state_inconsistent_heap_matches_otp() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping inconsistent-heap test");
        return;
    };
    let (expected, actual) = run(&reference, "internal_state_inconsistent");
    assert_reference(expected, actual);
}

#[test]
fn internal_state_abort_matches_otp_in_child_process() {
    if std::env::var_os("ARINSAL_INTERNAL_STATE_ABORT_CHILD").is_some() {
        let Ok(reference) = RefErl::start() else {
            panic!("erl unavailable for abort child");
        };
        let beam = reference
            .compile_named("debug_bifs_diff", SOURCE, &[])
            .expect("compile abort child fixture");
        let _ = run_vm(&beam, "internal_state_abort");
        panic!("abort BIF returned");
    }
    use std::os::unix::process::ExitStatusExt;
    let output = std::process::Command::new("timeout")
        .args([
            "20",
            &std::env::current_exe().unwrap().display().to_string(),
            "--exact",
            "internal_state_abort_matches_otp_in_child_process",
            "--nocapture",
        ])
        .env("ARINSAL_INTERNAL_STATE_ABORT_CHILD", "1")
        .output()
        .expect("run abort child");
    assert_eq!(output.status.signal(), Some(6), "{output:?}");
    let reference = std::process::Command::new("timeout")
        .args(["20", "erl", "-noshell", "+S", "1", "-eval",
            "erts_debug:set_internal_state(available_internal_state,true),erts_debug:set_internal_state(abort,why)."])
        .output()
        .expect("run OTP abort child");
    assert_eq!(reference.status.signal(), Some(6), "{reference:?}");
}

#[test]
fn internal_state_broken_halt_matches_otp_in_child_process() {
    if std::env::var_os("ARINSAL_INTERNAL_STATE_BROKEN_HALT_CHILD").is_some() {
        let Ok(reference) = RefErl::start() else {
            panic!("erl unavailable for broken-halt child");
        };
        let beam = reference
            .compile_named("debug_bifs_diff", SOURCE, &[])
            .expect("compile broken-halt child fixture");
        let _ = run_vm(&beam, "internal_state_broken_halt");
        panic!("broken_halt BIF returned");
    }
    let output = std::process::Command::new("timeout")
        .args([
            "20",
            &std::env::current_exe().unwrap().display().to_string(),
            "--exact",
            "internal_state_broken_halt_matches_otp_in_child_process",
            "--nocapture",
        ])
        .env("ARINSAL_INTERNAL_STATE_BROKEN_HALT_CHILD", "1")
        .output()
        .expect("run broken-halt child");
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let reference = std::process::Command::new("timeout")
        .args(["20", "erl", "-noshell", "+S", "1", "-eval",
            "erts_debug:set_internal_state(available_internal_state,true),erts_debug:set_internal_state(broken_halt,why)."])
        .output()
        .expect("run OTP broken-halt child");
    assert_eq!(reference.status.code(), Some(1), "{reference:?}");
    assert_eq!(
        String::from_utf8_lossy(&output.stderr).lines().next(),
        String::from_utf8_lossy(&reference.stderr).lines().next()
    );
}

#[test]
fn debug_bifs_system_monitor_matches_otp() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping debug BIF system-monitor test");
        return;
    };
    let (expected, actual) = run(&reference, "monitor");
    assert_reference(expected, actual);
    let (expected, actual) = run(&reference, "monitor_large_heap");
    assert_reference(expected, actual);
    let (expected, actual) = run(&reference, "monitor_long_schedule");
    assert_reference(expected, actual);
    let (expected, actual) = run(&reference, "monitor_long_gc");
    assert_reference(expected, actual);
    let (expected, actual) = run(&reference, "monitor_long_message_queue");
    assert_reference(expected, actual);
}

#[test]
fn debug_bifs_allocator_info_matches_otp() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping debug BIF allocator-info test");
        return;
    };
    let (expected, actual) = run(&reference, "allocator_info");
    assert_reference(expected, actual);
}
