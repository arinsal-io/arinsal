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
