//! Differential tests for the sig_bifs task (process/signal BIFs).

use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_term::Term;
use arinsal_vm::Vm;

const SOURCE: &str = r##"
-module(sig_bifs).
-export([run/1]).

err(F) ->
    try F() of
        Value -> {ok, Value}
    catch
        error:Reason -> Reason;
        exit:Reason -> {exit, Reason}
    end.

run(0) ->
    Msg = {sig_bifs_bang, make_ref()},
    Msg = erlang:apply(erlang, '!', [self(), Msg]),
    Got = receive Msg -> ok after 500 -> timeout end,
    Dead = list_to_pid("<0.9999.0>"),
    {Got,
     erlang:exit_signal(Dead, reason),
     erlang:exit_signal(Dead, reason, []),
     erlang:exit_signal(Dead, reason, [priority]),
     erlang:exit(Dead, reason, []),
     erlang:exit(Dead, reason, [priority]),
     err(fun() -> erlang:exit(Dead, reason, [foo]) end),
     err(fun() -> erlang:exit_signal(Dead, reason, [foo]) end)};

run(1) ->
    Self = self(),
    {erlang:link(Self, []),
     erlang:link(Self, [priority]),
     err(fun() -> erlang:link(Self, [foo]) end),
     err(fun() -> erlang:link(list_to_pid("<0.9999.0>"), []) end),
     begin
         process_flag(trap_exit, true),
         true = erlang:exit_signal(Self, bye),
         receive
             {'EXIT', Self, bye} -> trapped
         after 500 -> timeout
         end
     end};

run(2) ->
    Self = self(),
    Text = pid_to_list(Self),
    Port = open_port({spawn, "true"}, [eof]),
    PortText = port_to_list(Port),
    Ref = make_ref(),
    RefText = ref_to_list(Ref),
    RoundPid = list_to_pid(Text) =:= Self,
    RoundPort = list_to_port(PortText) =:= Port,
    RoundRef = list_to_ref(RefText) =:= Ref,
    port_close(Port),
    {RoundPid, RoundPort, RoundRef,
     err(fun() -> list_to_pid("nope") end),
     err(fun() -> list_to_pid("<1.0.0>") end),
     err(fun() -> list_to_port("#Port<1.0>") end),
     err(fun() -> list_to_ref("#Ref<1.0.0.0>") end),
     err(fun() -> list_to_ref("nope") end)};

run(3) ->
    R = make_ref(),
    AliveOk = erts_internal:is_process_alive(self(), R),
    AliveReply = receive {R, true} -> true after 1000 -> timeout end,
    Dead = list_to_pid("<0.9999.0>"),
    R2 = make_ref(),
    DeadOk = erts_internal:is_process_alive(Dead, R2),
    DeadReply = receive {R2, false} -> false after 1000 -> timeout end,
    Td = erlang:trace_delivered(all),
    TdMsg = receive {trace_delivered, all, Td} -> ok after 1000 -> timeout end,
    TdPid = erlang:trace_delivered(self()),
    TdPidMsg = receive {trace_delivered, Pid, TdPid} when Pid =:= self() -> ok
               after 1000 -> timeout end,
    Port = open_port({spawn, "true"}, [eof]),
    Call = erts_internal:port_call(Port, 1, []),
    port_close(Port),
    {AliveOk, AliveReply, DeadOk, DeadReply,
     is_reference(Td), TdMsg, is_reference(TdPid), TdPidMsg,
     erts_internal:is_process_executing_dirty(self()),
     err(fun() -> erts_internal:is_process_executing_dirty(1) end),
     err(fun() -> erts_internal:is_process_alive(self(), self()) end),
     err(fun() -> erlang:trace_delivered(1) end),
     Call,
     erts_trace_cleaner:check(),
     err(fun() -> erts_trace_cleaner:send_trace_clean_signal(self()) end)};

%% Priority messages via priority alias + send/3 [priority].
run(4) ->
    Parent = self(),
    Child = spawn(fun() ->
        Alias = erlang:alias([priority]),
        Parent ! {ready, Alias},
        receive go -> ok end,
        Parent ! {order, drain([])}
    end),
    Alias = receive {ready, A} -> A after 2000 -> error(ready) end,
    Child ! {ord, 1},
    Child ! {ord, 2},
    Child ! {ord, 3},
    erlang:send(Alias, {prio, a}, [priority]),
    Child ! {ord, 4},
    erlang:send(Alias, {prio, b}, [priority]),
    Alias ! {via_alias_plain, x},
    erlang:send(Child, {prio_to_pid, y}, [priority]),
    Child ! go,
    receive {order, Msgs} -> Msgs after 3000 -> timeout end;

%% Priority EXIT via link/2 [priority].
run(5) ->
    process_flag(trap_exit, true),
    Victim = spawn(fun() -> receive stop -> exit(boom) end end),
    true = erlang:link(Victim, [priority]),
    self() ! {ord, 1},
    self() ! {ord, 2},
    Victim ! stop,
    self() ! {ord, 3},
    receive
        {'EXIT', Victim, boom} -> drain([])
    after 2000 -> timeout
    end;

%% Priority EXIT via exit_signal to priority alias.
run(6) ->
    Parent = self(),
    Child = spawn(fun() ->
        process_flag(trap_exit, true),
        Alias = erlang:alias([priority]),
        Parent ! {ready, Alias},
        receive go -> ok end,
        Parent ! {order, drain([])}
    end),
    Alias = receive {ready, A} -> A after 2000 -> error(ready) end,
    Child ! {ord, 1},
    Child ! {ord, 2},
    erlang:exit_signal(Alias, boom, [priority]),
    Child ! {ord, 3},
    Child ! go,
    receive {order, Msgs} -> normalize_exits(Msgs) after 3000 -> timeout end;

%% A priority signal arriving after the receive save cursor moved past old messages.
run(7) ->
    Parent = self(),
    Child = spawn(fun() ->
        Alias = erlang:alias([priority]),
        Parent ! {ready, Alias},
        receive
            {wanted, Value} -> Parent ! {got, Value}
        after 2000 -> Parent ! missed
        end
    end),
    Alias = receive {ready, A} -> A after 2000 -> error(ready) end,
    Child ! skipped,
    timer:sleep(50),
    erlang:send(Alias, {wanted, reached}, [priority]),
    receive
        {got, Value} -> Value;
        missed -> missed
    after 2500 -> timeout
    end;

%% Priority monitor DOWN messages precede ordinary messages already in the mailbox.
run(8) ->
    Child = spawn(fun() -> receive stop -> ok end end),
    Ref = erlang:monitor(process, Child, [priority]),
    self() ! {ordinary, 1},
    Child ! stop,
    receive
        {'DOWN', Ref, process, Child, normal} -> drain([])
    after 2000 -> timeout
    end.

drain(Acc) ->
    receive
        M -> drain([M | Acc])
    after 0 ->
        lists:reverse(Acc)
    end.

normalize_exits(Messages) ->
    [case Message of
         {'EXIT', _Pid, Reason} -> {exit, Reason};
         Message -> Message
     end || Message <- Messages].
"##;

fn assert_scenario(reference: &RefErl, scenario: i64) {
    let beam = reference
        .compile_named("sig_bifs", SOURCE, &[])
        .expect("compile sig_bifs");
    reference.load("sig_bifs", &beam).expect("load into erl");
    let expected = reference.call("sig_bifs", "run", &[OwnedTerm::Int(scenario)]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).expect("load into arinsal");
    let actual = vm
        .eval_scheduled(
            "sig_bifs",
            "run",
            &[Term::small(scenario).unwrap()],
            1,
            Some(15),
        )
        .unwrap_or_else(|error| panic!("scenario {scenario}: {error}"));
    assert_eq!(expected, CallResult::Ok(actual.term), "scenario {scenario}");
}

#[test]
fn sig_bifs_exit_signal_and_bang() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping sig_bifs exit/bang test");
        return;
    };
    assert_scenario(&reference, 0);
}

#[test]
fn sig_bifs_link_and_trap_exit() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping sig_bifs link test");
        return;
    };
    assert_scenario(&reference, 1);
}

#[test]
fn sig_bifs_list_to_pid_port_ref() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping sig_bifs list_to_* test");
        return;
    };
    assert_scenario(&reference, 2);
}

#[test]
fn sig_bifs_alive_trace_port_cleaner() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping sig_bifs alive/trace test");
        return;
    };
    assert_scenario(&reference, 3);
}

#[test]
fn sig_bifs_priority_alias_send_order() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping sig_bifs priority alias test");
        return;
    };
    assert_scenario(&reference, 4);
}

#[test]
fn sig_bifs_priority_link_exit_order() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping sig_bifs priority link test");
        return;
    };
    assert_scenario(&reference, 5);
}

#[test]
fn sig_bifs_priority_exit_signal_alias_order() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping sig_bifs priority exit_signal test");
        return;
    };
    assert_scenario(&reference, 6);
}

#[test]
fn sig_bifs_priority_late_arrival_preserves_receive_cursor() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping sig_bifs late priority test");
        return;
    };
    assert_scenario(&reference, 7);
}

#[test]
fn sig_bifs_priority_monitor_down_order() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping sig_bifs priority monitor test");
        return;
    };
    assert_scenario(&reference, 8);
}
