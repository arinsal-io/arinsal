//! Linking to a process that is exiting must always produce its exit signal.
//!
//! `test_server_ctrl:wait_finish/0` links to a gen_server that replies and stops at once;
//! a lost exit signal left Common Test (and the whole node) waiting forever after a suite.

use arinsal_difftest::{CallResult, RefErl};
use arinsal_vm::Vm;

const SOURCE: &str = r#"
-module(link_exit_race).
-export([reply_then_exit/0, dead_link/0]).

%% Link right after the target replied and started to exit (the wait_finish pattern).
reply_then_exit() ->
    process_flag(trap_exit, true),
    Before = links(),
    Result = reply_then_exit(3000, 0),
    flush_exits(),
    {Result, links() -- Before}.

reply_then_exit(0, Lost) -> {lost, Lost};
reply_then_exit(N, Lost) ->
    Self = self(),
    P = spawn(fun() -> receive {go, From} -> From ! {ok, self()}, exit(shutdown) end end),
    P ! {go, Self},
    receive {ok, P} -> ok end,
    true = link(P),
    receive
        {'EXIT', P, Reason} when Reason =:= shutdown; Reason =:= noproc ->
            reply_then_exit(N - 1, Lost)
    after 1000 ->
        reply_then_exit(N - 1, Lost + 1)
    end.

%% A link to a process that is gone dissolves itself with a noproc exit.
dead_link() ->
    process_flag(trap_exit, true),
    Before = links(),
    {P, Ref} = spawn_monitor(fun() -> ok end),
    receive {'DOWN', Ref, process, P, normal} -> ok end,
    true = link(P),
    Exit = receive {'EXIT', P, R} -> R after 1000 -> timeout end,
    {Exit, links() -- Before}.

links() -> element(2, process_info(self(), links)).

flush_exits() ->
    receive {'EXIT', _, _} -> flush_exits() after 0 -> ok end.
"#;

#[test]
fn link_to_exiting_process_matches_otp_29() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping link_exit_race differential");
        return;
    };
    let beam = reference
        .compile_named("link_exit_race", SOURCE, &[])
        .expect("compile link_exit_race");
    reference
        .load("link_exit_race", &beam)
        .expect("load link_exit_race");
    for function in ["reply_then_exit", "dead_link"] {
        let expected = reference.call("link_exit_race", function, &[]);
        let mut vm = Vm::new([]);
        vm.load_bytes(&beam).expect("load");
        let actual = vm
            .eval_scheduled("link_exit_race", function, &[], 4, None)
            .unwrap_or_else(|error| panic!("{function}: {error}"));
        assert_eq!(expected, CallResult::Ok(actual.term), "{function}");
    }
}
