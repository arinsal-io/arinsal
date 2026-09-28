use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_term::Term;
use arinsal_vm::Vm;

const SOURCE: &str = r#"
-module(proc_remote).
-export([run/1, park/1, spin/1, spin_loop/0]).

run(0) -> wait_info();
run(1) -> run_info();
run(2) -> dead_info();
run(3) -> membership();
run(4) -> alive();
run(5) -> leader();
run(6) -> collect();
run(7) -> collect_async();
run(8) -> display();
run(9) -> leader_bad();
run(10) -> collect_bad();
run(11) -> linked().

park(Parent) ->
    put(k, v),
    process_flag(trap_exit, true),
    Parent ! ready,
    receive stop -> ok end.

spin(Parent) ->
    put(n, 1),
    Parent ! ready,
    spin_loop().

spin_loop() ->
    put(n, 2),
    spin_loop().

stop(Pid) ->
    Mon = monitor(process, Pid),
    exit(Pid, kill),
    receive {'DOWN', Mon, process, Pid, _} -> ok end.

clear_name() ->
    case whereis(proc_remote_park) of
        undefined -> ok;
        Old -> stop(Old)
    end,
    try unregister(proc_remote_park) catch error:badarg -> ok end,
    ok.

wait_info() ->
    clear_name(),
    Parent = self(),
    W = spawn(proc_remote, park, [Parent]),
    true = register(proc_remote_park, W),
    receive ready -> ok end,
    W ! keep,
    Info = wait_until(W, 1000),
    stop(W),
    try unregister(proc_remote_park) catch error:badarg -> ok end,
    Info.

wait_until(_W, 0) -> timeout;
wait_until(W, N) ->
    case process_info(W, [status, message_queue_len, links, dictionary, registered_name, current_function, trap_exit, group_leader]) of
        undefined -> dead;
        Info ->
            case lists:keyfind(status, 1, Info) of
                {status, waiting} -> norm_wait(Info);
                _ -> wait_until(W, N - 1)
            end
    end.

norm_wait(Info) ->
    {message_queue_len, N} = lists:keyfind(message_queue_len, 1, Info),
    {links, L} = lists:keyfind(links, 1, Info),
    {dictionary, D} = lists:keyfind(dictionary, 1, Info),
    {registered_name, Name} = lists:keyfind(registered_name, 1, Info),
    {current_function, Cf} = lists:keyfind(current_function, 1, Info),
    {trap_exit, Trap} = lists:keyfind(trap_exit, 1, Info),
    {group_leader, G} = lists:keyfind(group_leader, 1, Info),
    {waiting, N, length(L), D, Name, Cf, Trap, G =:= group_leader()}.

run_info() ->
    Parent = self(),
    R = spawn(proc_remote, spin, [Parent]),
    receive ready -> ok end,
    Info = wait_spin(R, 1000),
    stop(R),
    Info.

wait_spin(_R, 0) -> timeout;
wait_spin(R, N) ->
    case process_info(R, [status, message_queue_len, links, dictionary, registered_name, current_function, trap_exit, group_leader]) of
        undefined -> dead;
        Info ->
            case lists:keyfind(dictionary, 1, Info) of
                {dictionary, [{n, 2}]} -> norm_run(Info);
                _ -> wait_spin(R, N - 1)
            end
    end.

norm_run(Info) ->
    {status, S} = lists:keyfind(status, 1, Info),
    {message_queue_len, N} = lists:keyfind(message_queue_len, 1, Info),
    {links, L} = lists:keyfind(links, 1, Info),
    {dictionary, D} = lists:keyfind(dictionary, 1, Info),
    {registered_name, Name} = lists:keyfind(registered_name, 1, Info),
    {current_function, Cf} = lists:keyfind(current_function, 1, Info),
    {trap_exit, Trap} = lists:keyfind(trap_exit, 1, Info),
    {group_leader, G} = lists:keyfind(group_leader, 1, Info),
    {S =:= running orelse S =:= runnable, N, length(L), D, Name, Cf, Trap, G =:= group_leader()}.

dead_info() ->
    {D, Mon} = spawn_monitor(fun() -> ok end),
    receive {'DOWN', Mon, process, D, _} -> ok end,
    {process_info(D),
     process_info(D, status),
     try process_info(D, nope) catch error:badarg -> badarg end,
     try process_info(foo, status) catch error:badarg -> badarg end}.

membership() ->
    Live = spawn(fun() -> receive stop -> ok end end),
    {Dead, Mon} = spawn_monitor(fun() -> ok end),
    receive {'DOWN', Mon, process, Dead, _} -> ok end,
    Result = {lists:member(Live, processes()),
              lists:member(Dead, processes()),
              lists:member(self(), processes())},
    stop(Live),
    Result.

alive() ->
    Live = spawn(fun() -> receive stop -> ok end end),
    {Dead, Mon} = spawn_monitor(fun() -> ok end),
    receive {'DOWN', Mon, process, Dead, _} -> ok end,
    Result = {is_process_alive(Live), is_process_alive(Dead), is_process_alive(self())},
    stop(Live),
    Result.

leader() ->
    Gl = spawn(fun() -> receive stop -> ok end end),
    Other = spawn(fun() -> receive stop -> ok end end),
    true = group_leader(Gl, Other),
    {group_leader, Got} = process_info(Other, group_leader),
    Result = Got =:= Gl,
    stop(Gl),
    stop(Other),
    Result.

collect() ->
    Other = spawn(fun() -> receive stop -> ok end end),
    {Dead, Mon} = spawn_monitor(fun() -> ok end),
    receive {'DOWN', Mon, process, Dead, _} -> ok end,
    Result = {garbage_collect(Other), garbage_collect(Dead)},
    stop(Other),
    Result.

collect_async() ->
    Other = spawn(fun() -> receive stop -> ok end end),
    {Dead, Mon} = spawn_monitor(fun() -> ok end),
    receive {'DOWN', Mon, process, Dead, _} -> ok end,
    Ref = make_ref(),
    async = garbage_collect(Other, [{async, Ref}, {type, minor}]),
    async = garbage_collect(Dead, [{async, gone}]),
    Live = receive {garbage_collect, Ref, LiveValue} -> LiveValue after 5000 -> timeout end,
    Gone = receive {garbage_collect, gone, GoneValue} -> GoneValue after 5000 -> timeout end,
    stop(Other),
    {Live, Gone}.

display() ->
    Other = spawn(fun() -> receive stop -> ok end end),
    {Dead, Mon} = spawn_monitor(fun() -> ok end),
    receive {'DOWN', Mon, process, Dead, _} -> ok end,
    Shown = erlang:process_display(Other, backtrace),
    DeadRes = try erlang:process_display(Dead, backtrace) catch error:badarg -> badarg end,
    Bad = try erlang:process_display(Other, nope) catch error:badarg -> badarg end,
    stop(Other),
    {Shown, DeadRes, Bad}.

leader_bad() ->
    Other = spawn(fun() -> receive stop -> ok end end),
    {Dead, Mon} = spawn_monitor(fun() -> ok end),
    receive {'DOWN', Mon, process, Dead, _} -> ok end,
    true = group_leader(Dead, Other),
    {group_leader, Got} = process_info(Other, group_leader),
    DeadTarget = try group_leader(Other, Dead) catch error:badarg -> badarg end,
    NotPid = try group_leader(foo, Other) catch error:badarg -> badarg end,
    stop(Other),
    {Got =:= Dead, DeadTarget, NotPid}.

collect_bad() ->
    Other = spawn(fun() -> receive stop -> ok end end),
    Bad = try garbage_collect(Other, [nope]) catch error:badarg -> badarg end,
    stop(Other),
    Bad.

linked() ->
    W = spawn(fun() -> receive stop -> ok end end),
    link(W),
    {links, L} = process_info(W, links),
    unlink(W),
    stop(W),
    length(L).
"#;

#[test]
fn remote_process_requests_match_otp_29() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping remote process BIF differential test");
        return;
    };
    let beam = reference.compile_named("proc_remote", SOURCE, &[]).unwrap();
    reference.load("proc_remote", &beam).unwrap();
    for scenario in 0..12 {
        let expected = reference.call("proc_remote", "run", &[OwnedTerm::Int(scenario)]);
        let mut vm = Vm::new([]);
        vm.load_bytes(&beam).unwrap();
        let actual = vm.eval_scheduled(
            "proc_remote",
            "run",
            &[Term::small(scenario).unwrap()],
            1,
            Some(91),
        );
        let actual = actual.unwrap_or_else(|error| panic!("scenario {scenario}: {error}"));
        assert_eq!(expected, CallResult::Ok(actual.term), "scenario {scenario}");
    }
}
