use arinsal_difftest::{CallOptions, CallResult, RefErl};
use arinsal_etf::{EncodeOptions, OwnedTerm, decode, encode};
use arinsal_vm::Vm;

#[test]
fn aux_work_debug_wait_returns_after_scheduler_auxiliary_work() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping aux_work debug-wait differential test");
        return;
    };
    let source = r#"-module(aux_work_debug_wait).
        -export([run/0]).
        run() ->
            erts_debug:set_internal_state(available_internal_state, true),
            Parent = self(),
            _ = spawn(fun() ->
                Results = [erts_debug:set_internal_state(wait, Kind)
                           || Kind <- [deallocations, timer_cancellations, thread_progress]],
                Parent ! {wait_completed, Results}
            end),
            receive {wait_completed, Results} -> Results after 5000 -> timeout end."#;
    let beam = reference
        .compile_named("aux_work_debug_wait", source, &[])
        .unwrap();
    reference.load("aux_work_debug_wait", &beam).unwrap();
    let expected = reference.call("aux_work_debug_wait", "run", &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled("aux_work_debug_wait", "run", &[], 2, None)
        .unwrap();
    let canonical = decode(&encode(&actual.term, EncodeOptions::default())).unwrap();
    assert_eq!(expected, CallResult::Ok(canonical));
}

#[test]
fn aux_work_allocator_replies_match_erts_shapes() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping aux_work allocator differential test");
        return;
    };
    let source = r#"-module(aux_work_allocator).
        -export([run/0]).
        run() ->
            {lists:sort([K || {K, _} <- erlang:memory()]),
             lists:sort([K || {K, _} <- erlang:memory([total, processes, system, atom,
                                                       atom_used, binary, code, ets])])}."#;
    let beam = reference
        .compile_named("aux_work_allocator", source, &[])
        .unwrap();
    reference.load("aux_work_allocator", &beam).unwrap();
    let expected = reference.call("aux_work_allocator", "run", &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled("aux_work_allocator", "run", &[], 2, None)
        .unwrap();
    let canonical = decode(&encode(&actual.term, EncodeOptions::default())).unwrap();
    assert_eq!(expected, CallResult::Ok(canonical));
}

#[test]
fn aux_work_async_timer_cancel_reply_matches_erts() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping aux_work async-cancel differential test");
        return;
    };
    let source = r#"-module(aux_work_async_timer_cancel).
        -export([run/0]).
        run() ->
            process_flag(scheduler, 1),
            Ref = erlang:start_timer(10000, self(), timer_message),
            process_flag(scheduler, 2),
            ok = erlang:read_timer(Ref, [{async, true}]),
            ok = erlang:cancel_timer(Ref, [{async, true}, {info, true}]),
            ok = erlang:read_timer(Ref, [{async, true}]),
            First = receive {read_timer, Ref, V1} -> V1 after 5000 -> timeout end,
            Remaining = receive {cancel_timer, Ref, V2} -> V2 after 5000 -> timeout end,
            Last = receive {read_timer, Ref, V3} -> V3 after 5000 -> timeout end,
            ExpiredRef = erlang:start_timer(1, self(), expired_timer_message),
            receive {timeout, ExpiredRef, expired_timer_message} -> ok
            after 5000 -> timeout end,
            ok = erlang:cancel_timer(ExpiredRef, [{async, true}, {info, true}]),
            ExpiredReply = receive {cancel_timer, ExpiredRef, V4} -> V4
                           after 5000 -> timeout end,
            is_integer(First) andalso is_integer(Remaining) andalso Last =:= false
                andalso ExpiredReply =:= false
                andalso (First =:= Remaining orelse First =:= Remaining + 1)."#;
    let beam = reference
        .compile_named("aux_work_async_timer_cancel", source, &[])
        .unwrap();
    reference
        .load("aux_work_async_timer_cancel", &beam)
        .unwrap();
    let expected = reference.call("aux_work_async_timer_cancel", "run", &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled("aux_work_async_timer_cancel", "run", &[], 2, None)
        .unwrap();
    let canonical = decode(&encode(&actual.term, EncodeOptions::default())).unwrap();
    assert_eq!(expected, CallResult::Ok(canonical));
}

#[test]
fn aux_work_bulk_cross_scheduler_timer_cancellation_matches_erts() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping aux_work bulk-cancel differential test");
        return;
    };
    let source = r#"-module(aux_work_bulk_timer_cancel).
        -export([run/0]).
        run() ->
            Refs = [begin
                process_flag(scheduler, (I rem 2) + 1),
                erlang:start_timer(10000, self(), I)
            end || I <- lists:seq(1, 2408)],
            process_flag(scheduler, 1),
            lists:foreach(fun(Ref) ->
                ok = erlang:cancel_timer(Ref, [{async, true}, {info, true}])
            end, Refs),
            collect(length(Refs), 0).
        collect(0, Count) -> Count;
        collect(N, Count) ->
            receive
                {cancel_timer, _Ref, Remaining} when is_integer(Remaining) ->
                    collect(N - 1, Count + 1)
            after 30000 -> timeout end."#;
    let beam = reference
        .compile_named("aux_work_bulk_timer_cancel", source, &[])
        .unwrap();
    reference.load("aux_work_bulk_timer_cancel", &beam).unwrap();
    let expected = reference.call("aux_work_bulk_timer_cancel", "run", &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled("aux_work_bulk_timer_cancel", "run", &[], 2, None)
        .unwrap();
    let canonical = decode(&encode(&actual.term, EncodeOptions::default())).unwrap();
    assert_eq!(expected, CallResult::Ok(canonical));
}

#[test]
fn aux_work_abs_timer_cancellation_at_deadline_matches_erts() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping aux_work deadline-cancel differential test");
        return;
    };
    let source = r#"-module(aux_work_deadline_timer_cancel).
        -export([run/0]).
        run() ->
            SchedulersOnline = erlang:system_info(schedulers_online),
            SchedulersToUse = erlang:max(1, erlang:min(8, SchedulersOnline) - 1),
            PerScheduler = (100 * 3 + 1),
            Count = PerScheduler * SchedulersToUse,
            TimeoutAt = erlang:monotonic_time(millisecond) + 3000,
            Refs = [begin
                SchedulerId = ((I div PerScheduler) rem SchedulersToUse) + 2,
                process_flag(scheduler, SchedulerId),
                erlang:start_timer(TimeoutAt, self(), timer_message, [{abs, true}])
            end || I <- lists:seq(1, Count)],
            process_flag(scheduler, 1),
            BeginCancel = TimeoutAt * 1000 - 500,
            busy_wait_until(fun() ->
                erlang:monotonic_time(microsecond) >= BeginCancel
            end),
            lists:foreach(fun(Ref) ->
                ok = erlang:cancel_timer(Ref, [{async, true}, {info, true}])
            end, Refs),
            collect(Count, 0, 0).
        busy_wait_until(Predicate) ->
            case Predicate() of true -> ok; false -> busy_wait_until(Predicate) end.
        collect(0, Timeouts, Cancels) -> {Timeouts, Cancels};
        collect(N, Timeouts, Cancels) ->
            receive
                {timeout, Ref, timer_message} ->
                    receive {cancel_timer, Ref, false} ->
                        collect(N - 1, Timeouts + 1, Cancels)
                    end;
                {cancel_timer, Ref, false} ->
                    receive {timeout, Ref, timer_message} ->
                        collect(N - 1, Timeouts + 1, Cancels)
                    end;
                {cancel_timer, Ref, Remaining} when is_integer(Remaining) ->
                    collect(N - 1, Timeouts, Cancels + 1)
            after 15000 -> timeout end."#;
    let beam = reference
        .compile_named("aux_work_deadline_timer_cancel", source, &[])
        .unwrap();
    reference
        .load("aux_work_deadline_timer_cancel", &beam)
        .unwrap();
    let expected = reference.call("aux_work_deadline_timer_cancel", "run", &[]);
    eprintln!("reference deadline-cancel result: {expected:?}");
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    eprintln!("starting Arinsal deadline-cancel run");
    let actual = vm
        .eval_scheduled("aux_work_deadline_timer_cancel", "run", &[], 8, None)
        .unwrap();
    let canonical = decode(&encode(&actual.term, EncodeOptions::default())).unwrap();
    // How many timers beat their cancellation depends on thread wake-up latency; erts and
    // Arinsal must agree that every timer ended exactly once, as a timeout or as a cancel.
    let total = |value: &OwnedTerm| match value {
        OwnedTerm::Tuple(parts) => parts
            .iter()
            .map(|part| match part {
                OwnedTerm::Int(count) => *count,
                _ => -1,
            })
            .sum::<i64>(),
        _ => -1,
    };
    let CallResult::Ok(expected_term) = &expected else {
        panic!("reference failed: {expected:?}");
    };
    assert!(total(expected_term) > 0);
    assert_eq!(total(expected_term), total(&canonical));
}

#[test]
fn aux_work_process_exit_cancels_owned_timer_memory() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping aux_work timer memory differential test");
        return;
    };
    let source = r#"-module(aux_work_timer_memory).
        -export([run/0]).
        run() ->
            erts_debug:set_internal_state(available_internal_state, true),
            %% Warm fixed-size timer allocator bins before measuring the baseline.
            warm_up(),
            Baseline = mem(),
            Parent = self(),
            Pid = spawn(fun() -> start_owner(Parent) end),
            receive timers_started -> ok after 30000 -> exit(start_timeout) end,
            During = mem(),
            Larger = Baseline =:= -1 orelse During > Baseline,
            stop_owner(Pid),
            RestoreDeadline = erlang:monotonic_time(millisecond) + 60000,
            Restored = wait_until(fun() -> mem() =:= Baseline end, RestoreDeadline),
            {Larger, Restored}.
        warm_up() ->
            Parent = self(),
            Pid = spawn(fun() -> start_owner(Parent) end),
            receive timers_started -> ok after 30000 -> exit(warmup_start_timeout) end,
            stop_owner(Pid),
            _ = mem(),
            ok.
        start_owner(Parent) ->
            Online = 2,
            lists:foreach(fun(I) ->
                process_flag(scheduler, (I rem Online) + 1),
                erlang:start_timer((1 bsl 28) + I * 10, self(), timer_message)
            end, lists:seq(1, 301 * Online)),
            Parent ! timers_started,
            receive after infinity -> ok end.
        stop_owner(Pid) ->
            Monitor = erlang:monitor(process, Pid),
            exit(Pid, kill),
            receive {'DOWN', Monitor, process, Pid, killed} -> ok
            after 30000 -> exit(process_exit_timeout) end.
        mem() ->
            erts_debug:set_internal_state(wait, timer_cancellations),
            erts_debug:set_internal_state(wait, deallocations),
            Ref = make_ref(),
            erlang:system_info({memory_internal, Ref, [fix_alloc]}),
            mem_recv(erts_internal:no_aux_work_threads() - 1, Ref, 0).
        mem_recv(0, _Ref, Memory) -> Memory;
        mem_recv(N, Ref, Memory) ->
            receive {Ref, _, Data} ->
                Value = mem_fix(Data),
                case Value of
                    -1 -> mem_recv(N - 1, Ref, -1);
                    _ when Memory =:= -1 -> mem_recv(N - 1, Ref, -1);
                    _ -> mem_recv(N - 1, Ref, Memory + Value)
                end
            after 5000 -> timeout end.
        mem_fix([{fix_alloc, false}]) -> -1;
        mem_fix([{fix_alloc, _, Data}]) -> mem_find_fix_types(Data);
        mem_fix(_) -> 0.
        mem_find_fix_types([{fix_types, Types} | _]) -> mem_types(Types);
        mem_find_fix_types([{fix_types, _Mask, Types} | _]) -> mem_types(Types);
        mem_find_fix_types([_ | Rest]) -> mem_find_fix_types(Rest);
        mem_find_fix_types([]) -> 0.
        mem_types(Types) -> lists:sum(
            [Allocated + Used || {Type, Allocated, Used} <- Types,
                Type =:= bif_timer orelse Type =:= accessor_bif_timer]).
        wait_until(Predicate, Deadline) ->
            case catch Predicate() of
                true -> true;
                _ ->
                    case erlang:monotonic_time(millisecond) >= Deadline of
                        true -> false;
                        false -> timer:sleep(5), wait_until(Predicate, Deadline)
                    end
            end."#;
    let beam = reference
        .compile_named("aux_work_timer_memory", source, &[])
        .unwrap();
    reference.load("aux_work_timer_memory", &beam).unwrap();
    let expected = reference
        .call_opts(
            "aux_work_timer_memory",
            "run",
            &[],
            &CallOptions {
                timeout_ms: Some(120_000),
                ..CallOptions::default()
            },
        )
        .result;
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled("aux_work_timer_memory", "run", &[], 2, None)
        .unwrap();
    let canonical = decode(&encode(&actual.term, EncodeOptions::default())).unwrap();
    assert_eq!(expected, CallResult::Ok(canonical));
}
