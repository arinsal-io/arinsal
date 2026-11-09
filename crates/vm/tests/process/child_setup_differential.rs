use arinsal_difftest::{CallOptions, CallResult, RefErl};
use arinsal_vm::Vm;

const SOURCE: &str = r#"
-module(child_setup_diff).
-export([sigchld/0]).

sigchld() ->
    Original = whereis(erl_signal_server),
    case Original of
        undefined -> ok;
        _ -> true = unregister(erl_signal_server)
    end,
    Server = spawn(fun() -> collect([]) end),
    true = register(erl_signal_server, Server),
    ok = os:set_signal(sigchld, handle),
    Pid = os:getpid(),
    [run_kill("/bin/kill", Pid) || _ <- lists:seq(1, 3)],
    Server ! {self(), fetch_msgs},
    Messages = receive {Server, Ms} -> Ms after 5000 -> timeout end,
    ok = os:set_signal(sigchld, ignore),
    case Original of
        undefined -> ok;
        _ -> true = register(erl_signal_server, Original)
    end,
    {length(Messages), Messages}.

run_kill(Kill, Pid) ->
    Port = open_port({spawn_executable, Kill},
                     [{args, ["-s", "CHLD", Pid]}, exit_status, hide]),
    receive
        {Port, {exit_status, 0}} -> ok;
        {Port, {exit_status, Status}} -> {kill_failed, Status}
    after 5000 -> kill_timeout
    end,
    receive after 200 -> ok end.

collect(Messages) ->
    receive
        {Pid, fetch_msgs} -> Pid ! {self(), lists:reverse(Messages)};
        Message -> collect([Message | Messages])
    end.
"#;

#[test]
fn port_child_sigchld_notifications_match_otp() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping child-setup differential test");
        return;
    };
    let beam = reference
        .compile_named("child_setup_diff", SOURCE, &[])
        .expect("compile child-setup differential");
    reference
        .load("child_setup_diff", &beam)
        .expect("load child-setup differential");

    let options = CallOptions {
        timeout_ms: Some(60_000),
        ..CallOptions::default()
    };
    let expected = reference
        .call_opts("child_setup_diff", "sigchld", &[], &options)
        .result;

    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).expect("load child-setup differential");
    let actual = vm
        .eval_scheduled("child_setup_diff", "sigchld", &[], 2, None)
        .expect("run child-setup differential");
    similar_asserts::assert_eq!(expected, CallResult::Ok(actual.term));
}

const CONCURRENT_SOURCE: &str = r#"
-module(child_setup_concurrent_diff).
-export([run/2]).

run(Spawners, Rounds) ->
    Me = self(),
    Pids = [spawn(fun() -> Me ! {self(), spawner(Rounds)} end) || _ <- lists:seq(1, Spawners)],
    [receive {P, R} -> R after 30000 -> timeout end || P <- Pids].

spawner(0) -> ok;
spawner(N) ->
    Port = open_port({spawn_executable, "/usr/bin/true"}, [exit_status, hide]),
    receive
        {Port, {exit_status, 0}} -> spawner(N - 1)
    after 30000 -> timeout
    end.
"#;

/// Start requests that reach the child-setup helper together must all be served: the helper's
/// poll registration is edge-triggered, so a request queued behind another one used to stay
/// unread and its spawner waited for the `Go` frame forever.
#[test]
fn concurrent_port_spawns_all_complete_like_otp() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping concurrent child-setup differential test");
        return;
    };
    let beam = reference
        .compile_named("child_setup_concurrent_diff", CONCURRENT_SOURCE, &[])
        .expect("compile concurrent child-setup differential");
    reference
        .load("child_setup_concurrent_diff", &beam)
        .expect("load concurrent child-setup differential");
    let args = [
        arinsal_etf::OwnedTerm::Int(16),
        arinsal_etf::OwnedTerm::Int(25),
    ];
    let options = CallOptions {
        timeout_ms: Some(60_000),
        ..CallOptions::default()
    };
    let expected = reference
        .call_opts("child_setup_concurrent_diff", "run", &args, &options)
        .result;

    let mut vm = Vm::new([]);
    vm.load_bytes(&beam)
        .expect("load concurrent child-setup differential");
    let mut heap = arinsal_term::VecHeap::new();
    let terms: Vec<_> = args
        .iter()
        .map(|arg| arinsal_term::from_owned(arg, &mut heap).unwrap())
        .collect();
    let actual = vm
        .eval_scheduled("child_setup_concurrent_diff", "run", &terms, 4, None)
        .expect("run concurrent child-setup differential");
    similar_asserts::assert_eq!(expected, CallResult::Ok(actual.term));
}

const START_SOURCE: &str = r#"
-module(child_setup_start_diff).
-export([run/0]).

run() ->
    Sh = open_port({spawn_executable, "/bin/sh"}, [{args, ["-c", "echo hi"]}, in, binary, eof]),
    Cmd = receive {Sh, {data, SD}} -> SD after 5000 -> timeout end,
    Cat = open_port({spawn, "cat"}, [binary]),
    Cat ! {self(), {command, <<"x\n">>}},
    Echo = receive {Cat, {data, D}} -> D after 5000 -> timeout end,
    true = port_close(Cat),
    {'EXIT', {MissingReason, _}} = (catch open_port({spawn_executable, "/nonexistent/prog"}, [])),
    NoRead = open_port({spawn, "cat"}, [binary, in]),
    Info = erlang:port_info(NoRead, os_pid),
    true = port_close(NoRead),
    {Cmd, Echo, MissingReason, element(1, Info)}.
"#;

/// The spawn driver answers `open_port` through `erl_drv_init_ack` once the forker's `Go`
/// arrived: the first command, a failed launch and `port_info(os_pid)` behave as in erts.
#[test]
fn port_start_results_match_otp() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping port start differential test");
        return;
    };
    let beam = reference
        .compile_named("child_setup_start_diff", START_SOURCE, &[])
        .expect("compile port start differential");
    reference
        .load("child_setup_start_diff", &beam)
        .expect("load port start differential");
    let options = CallOptions {
        timeout_ms: Some(60_000),
        ..CallOptions::default()
    };
    let expected = reference
        .call_opts("child_setup_start_diff", "run", &[], &options)
        .result;
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).expect("load port start differential");
    let actual = vm
        .eval_scheduled("child_setup_start_diff", "run", &[], 2, None)
        .expect("run port start differential");
    similar_asserts::assert_eq!(expected, CallResult::Ok(actual.term));
}
