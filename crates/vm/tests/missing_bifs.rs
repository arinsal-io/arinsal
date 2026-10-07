use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_term::Term;
use arinsal_vm::Vm;

const SOURCE: &str = r#"
-module(missing_bifs).
-export([run/1]).
run(0) ->
    {erlang:dt_spread_tag(true), err(fun() -> erlang:dt_spread_tag(other) end)};
run(1) ->
    {erlang:dt_restore_tag(true), err(fun() -> erlang:dt_restore_tag(false) end)};
run(2) ->
    Local = erlang:fun_info_mfa(fun() -> ok end),
    Export = erlang:fun_info_mfa(fun lists:reverse/1),
    {Local, Export, err(fun() -> erlang:fun_info_mfa(1) end)};
run(3) ->
    {0, []} = erlang:processes_iterator(),
    {member_self(erlang:processes_iterator()),
     err(fun() -> erlang:processes_next(foo) end),
     err(fun() -> erts_internal:processes_next(-1) end)};
run(4) ->
    {err(fun() -> erts_internal:dirty_process_handle_signals(self()) end),
     err(fun() -> erts_internal:dirty_process_handle_signals(1) end)};
run(5) ->
    P = open_port({spawn, "true"}, [eof]),
    Get0 = erlang:port_get_data(P),
    Set = erlang:port_set_data(P, {a, 1}),
    Get1 = erlang:port_get_data(P),
    SetI = erlang:port_set_data(P, hi),
    GetI = erlang:port_get_data(P),
    Ctrl = erts_internal:port_control(P, 1, <<>>),
    CtrlE = err(fun() -> erlang:port_control(P, 1, <<>>) end),
    Bad = err(fun() -> erlang:port_get_data(self()) end),
    port_close(P),
    Closed = err(fun() -> erlang:port_get_data(P) end),
    {Get0, Set, Get1, SetI, GetI, Ctrl, CtrlE, Bad, Closed};
run(6) ->
    Bd = erlang:system_flag(backtrace_depth, 4),
    erlang:system_flag(backtrace_depth, Bd),
    Fs = erlang:system_flag(fullsweep_after, 10),
    erlang:system_flag(fullsweep_after, Fs),
    Mh = erlang:system_flag(min_heap_size, 233),
    Mb = erlang:system_flag(min_bin_vheap_size, 46422),
    Mx = erlang:system_flag(max_heap_size, #{size => 0}),
    MxOk = map_get(size, Mx) =:= 0 andalso map_get(kill, Mx) =:= true
        andalso map_get(error_logger, Mx) =:= true
        andalso map_get(include_shared_binaries, Mx) =:= false,
    Blocked = erlang:system_flag(multi_scheduling, block),
    Enabled = erlang:system_flag(multi_scheduling, unblock),
    _ = erlang:system_flag(scheduler_wall_time, false),
    Sw = erlang:system_flag(scheduler_wall_time, true),
    Sw2 = erlang:system_flag(scheduler_wall_time, false),
    Dbg = erlang:system_flag(debug_flags, false),
    Rst = erlang:system_flag(reset_seq_trace, true),
    Tcw = erlang:system_flag(trace_control_word, 1),
    erlang:system_flag(trace_control_word, 0),
    Seq = erlang:system_flag(sequential_tracer, false),
    Max = erlang:system_info(schedulers),
    So = erlang:system_flag(schedulers_online, Max),
    erlang:system_flag(schedulers_online, So),
    DirtyMax = erlang:system_info(dirty_cpu_schedulers),
    Dirty = erlang:system_flag(dirty_cpu_schedulers_online, DirtyMax),
    erlang:system_flag(dirty_cpu_schedulers_online, Dirty),
    OldLim = erlang:system_flag(outstanding_system_requests_limit, 32),
    LimBack = erlang:system_flag(outstanding_system_requests_limit, OldLim),
    Stat = erlang:system_flag(scheduling_statistics, enable),
    erlang:system_flag(scheduling_statistics, disable),
    _ = erlang:system_flag(microstate_accounting, false),
    Ms = erlang:system_flag(microstate_accounting, true),
    erlang:system_flag(microstate_accounting, false),
    {Bd, Fs, Mh, Mb, MxOk, Blocked, Enabled, Sw, Sw2, Dbg, Rst, Tcw, Seq,
     So =:= Max, Dirty =:= DirtyMax, is_integer(OldLim) andalso OldLim > 0, LimBack, Stat, Ms,
     err(fun() -> erlang:system_flag(backtrace_depth, -1) end),
     err(fun() -> erlang:system_flag(no_such_flag, true) end),
     err(fun() -> erlang:system_flag(trap_exit, true) end),
     err(fun() -> erlang:system_flag(scheduling_statistics, nope) end)};
run(7) ->
    _ = erlang:system_flag(scheduler_wall_time, false),
    {erts_internal:scheduler_wall_time(true),
     erts_internal:scheduler_wall_time(false),
     erts_internal:scheduler_wall_time(other)};
run(8) ->
    On = erts_internal:trace(self(), true, [send]),
    Info = process_info(self(), trace),
    Off = erts_internal:trace(self(), false, [send]),
    Clear = process_info(self(), trace),
    {On, Info, Off, Clear,
     err(fun() -> erts_internal:trace(self(), true, [nope]) end),
     err(fun() -> erts_internal:trace(self(), 'maybe', [send]) end)};
run(9) ->
    R1 = make_ref(),
    ok = erts_internal:request_system_task(self(), normal, {garbage_collect, R1, major}),
    Gc = receive {garbage_collect, R1, V1} -> V1 after 2000 -> timeout end,
    R2 = make_ref(),
    ok = erts_internal:request_system_task(self(), max, {system_task_test, R2}),
    Test = receive {system_task_test, R2, V2} -> V2 after 2000 -> timeout end,
    R3 = make_ref(),
    ok = erts_internal:request_system_task(self(), low, {check_process_code, R3, lists}),
    Cpc = receive {check_process_code, R3, V3} -> V3 after 2000 -> timeout end,
    R4 = make_ref(),
    ok = erts_internal:request_system_task(self(), self(), high, {system_task_test, R4}),
    Four = receive {system_task_test, R4, V4} -> V4 after 2000 -> timeout end,
    P = spawn(fun() -> ok end),
    M = monitor(process, P),
    receive {'DOWN', M, process, P, _} -> ok after 2000 -> down_timeout end,
    R5 = make_ref(),
    DeadCall = erts_internal:request_system_task(P, inherit, {garbage_collect, R5, minor}),
    Dead = receive {garbage_collect, R5, V5} -> V5 after 2000 -> timeout end,
    Bad = err(fun() -> erts_internal:request_system_task(self(), weird, {garbage_collect, R1, major}) end),
    {Gc, Test, Cpc, Four, DeadCall, Dead, Bad};
run(10) ->
    {err(fun() -> erts_literal_area_collector:release_area_switch() end),
     err(fun() -> erts_literal_area_collector:send_copy_request(self(), x, init) end)};
run(11) ->
    T = ets:new(missing_bifs, [public, set]),
    ets:insert(T, [{a, 1}, {b, 2}, {c, 3}]),
    N = ets:internal_select_delete(T, [{{b, '_'}, [], [true]}]),
    Left = lists:sort(ets:tab2list(T)),
    All = ets:internal_select_delete(T, [{'_', [], [true]}]),
    Empty = ets:internal_select_delete(T, []),
    {N, Left, All, Empty, err(fun() -> ets:internal_select_delete(nope, []) end)}.
member_self(Iter) ->
    case erlang:processes_next(Iter) of
        none -> false;
        {Pid, _} when Pid =:= self() -> true;
        {_, Next} -> member_self(Next)
    end.
err(F) ->
    try F() of
        Value -> {ok, Value}
    catch
        error:Reason -> Reason
    end.
"#;

#[test]
fn missing_bifs_match_otp_29() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping missing BIF differential test");
        return;
    };
    let beam = reference
        .compile_named("missing_bifs", SOURCE, &[])
        .unwrap();
    reference.load("missing_bifs", &beam).unwrap();
    for scenario in 0..12 {
        let expected = reference.call("missing_bifs", "run", &[OwnedTerm::Int(scenario)]);
        let mut vm = Vm::new([]);
        vm.load_bytes(&beam).unwrap();
        let actual = vm.eval_scheduled(
            "missing_bifs",
            "run",
            &[Term::small(scenario).unwrap()],
            1,
            Some(15),
        );
        assert_eq!(
            expected,
            CallResult::Ok(
                actual
                    .unwrap_or_else(|error| panic!("scenario {scenario}: {error}"))
                    .term
            ),
            "scenario {scenario}"
        );
    }
}
