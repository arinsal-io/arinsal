use arinsal_difftest::{CallResult, RefErl};
use arinsal_vm::Vm;

#[test]
fn port_lifecycle_matches_otp() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping port lifecycle differential scenarios");
        return;
    };
    let source = r#"
-module(port_life).
-export([connect/0, linked/0, monitored/0, demonitor/0, info/0, exit_port/0,
         bad_connect/0, bad_close/0, bang_connect/0, owner_exit/0, detached_child_survives/0,
         bad_port_connect/0, bad_port_info/0]).
connect() ->
    P = open_port({spawn, "cat"}, []),
    true = port_connect(P, self()),
    true = port_close(P),
    ok.
linked() ->
    P = open_port({spawn, "cat"}, []),
    true = link(P),
    true = unlink(P),
    true = port_close(P).
monitored() ->
    P = open_port({spawn, "cat"}, []),
    R = erlang:monitor(port, P),
    true = port_close(P),
    receive {'DOWN', R, port, P, normal} -> ok after 1000 -> timeout end.
demonitor() ->
    P = open_port({spawn, "cat"}, []),
    R = erlang:monitor(port, P),
    true = erlang:demonitor(R),
    true = port_close(P).
info() ->
    P = open_port({spawn, "cat"}, []),
    Info = erlang:port_info(P),
    Keys = [element(1, I) || I <- Info],
    Values = [{name, element(2, erlang:port_info(P, name))},
        {links, length(element(2, erlang:port_info(P, links)))},
        {id, is_integer(element(2, erlang:port_info(P, id)))},
        {connected, element(2, erlang:port_info(P, connected)) =:= self()},
        {input, element(2, erlang:port_info(P, input))},
        {output, element(2, erlang:port_info(P, output))},
        {os_pid, is_integer(element(2, erlang:port_info(P, os_pid)))}],
    Ref = erlang:monitor(port, P),
    More = [{monitors, element(2, erlang:port_info(P, monitors))},
        {monitored_by, length(element(2, erlang:port_info(P, monitored_by)))},
        {memory, is_integer(element(2, erlang:port_info(P, memory)))},
        {queue_size, element(2, erlang:port_info(P, queue_size))},
        {locking, element(2, erlang:port_info(P, locking))},
        {parallelism, element(2, erlang:port_info(P, parallelism))}],
    true = erlang:demonitor(Ref),
    true = port_close(P),
    {Keys, Values, More}.
exit_port() ->
    process_flag(trap_exit, true),
    P = open_port({spawn, "cat"}, []),
    R = erlang:monitor(port, P),
    true = link(P),
    true = exit(P, custom_reason),
    A = receive {'EXIT', P, custom_reason} -> linked_exit after 1000 -> no_link_exit end,
    B = receive {'DOWN', R, port, P, Reason} -> {monitored_down, Reason} after 1000 -> no_down end,
    {A, B}.
bad_connect() ->
    P = open_port({spawn, "cat"}, []),
    Parent = self(),
    Ref = make_ref(),
    NewOwner = spawn(fun() ->
        Parent ! {Ref, catch port_connect(P, self())},
        receive stop -> Parent ! {Ref, port_close(P)} end
    end),
    Result = receive {Ref, R} -> R after 1000 -> timeout end,
    NewOwner ! stop,
    Closed = receive {Ref, R2} -> R2 after 1000 -> timeout end,
    {Result, Closed}.
bad_close() ->
    P = open_port({spawn, "cat"}, []),
    Parent = self(),
    spawn(fun() -> Parent ! (catch port_close(P)) end),
    receive R -> R after 1000 -> timeout end.
bang_connect() ->
    P = open_port({spawn, "cat"}, []),
    Parent = self(),
    Child = spawn(fun() ->
        Parent ! ready,
        receive stop -> Parent ! port_close(P) end
    end),
    receive ready -> ok after 1000 -> timeout end,
    P ! {self(), {connect, Child}},
    Connected = receive {P, connected} -> true after 1000 -> false end,
    Child ! stop,
    Closed = receive true -> true after 1000 -> false end,
    {Connected, Closed}.
owner_exit() ->
    Parent = self(),
    Owner = spawn(fun() ->
        P = open_port({spawn, "cat"}, []),
        Parent ! {ready, P, proplists:get_value(os_pid, erlang:port_info(P))},
        receive stop -> ok end
    end),
    receive
        {ready, P, OsPid} ->
            Ref = erlang:monitor(port, P),
            Owner ! stop,
            receive {'DOWN', Ref, port, P, normal} -> OsPid after 1000 -> 0 end
    after 1000 -> 0
    end.
detached_child_survives() ->
    Path = filename:join("/private/tmp", "port_life_detached_" ++ os:getpid()),
    P = open_port({spawn_executable, "/bin/sh"},
                  [{args, ["-c", "sleep 0.2; /usr/bin/touch " ++ Path]}]),
    true = port_close(P),
    timer:sleep(500),
    Exists = port_exit_status("test -f " ++ Path) =:= 0,
    0 = port_exit_status("rm -f " ++ Path),
    Exists.
port_exit_status(Command) ->
    P = open_port({spawn_executable, "/bin/sh"},
                  [{args, ["-c", Command]}, exit_status]),
    receive {P, {exit_status, Status}} -> Status after 2000 -> timeout end.
bad_port_connect() ->
    try port_connect(self(), self()) catch error:badarg -> badarg end.
bad_port_info() ->
    try erlang:port_info(self()) catch error:badarg -> badarg end.
"#;
    let beam = reference.compile_named("port_life", source, &[]).unwrap();
    reference.load("port_life", &beam).unwrap();
    for function in [
        "connect",
        "linked",
        "monitored",
        "demonitor",
        "info",
        "exit_port",
        "bad_connect",
        "bad_close",
        "bang_connect",
        "bad_port_connect",
        "bad_port_info",
        "detached_child_survives",
    ] {
        let expected = reference.call("port_life", function, &[]);
        let mut vm = Vm::new([]);
        vm.load_bytes(&beam).unwrap();
        let actual = vm.eval_scheduled("port_life", function, &[], 1, None);
        let actual = actual.unwrap_or_else(|error| panic!("{function}: {error:?}"));
        assert_eq!(expected, CallResult::Ok(actual.term), "{function}");
    }

    let expected = reference.call("port_life", "owner_exit", &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled("port_life", "owner_exit", &[], 1, None)
        .unwrap()
        .term;
    let arinsal_etf::OwnedTerm::Int(actual) = actual else {
        panic!("OS pid is not an integer: {actual:?}");
    };
    assert!(matches!(expected, CallResult::Ok(arinsal_etf::OwnedTerm::Int(pid)) if pid > 0));
    assert!(actual > 0, "owner exit must return the child OS pid");
}
