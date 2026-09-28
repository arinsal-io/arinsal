use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_term::Term;
use arinsal_vm::Vm;

const SOURCE: &str = r#"
-module(recv_marker_diff).
-behaviour(gen_server).
-export([scenario/2, init/1, handle_call/3, handle_cast/2,
         handle_info/2, terminate/2, code_change/3]).

scenario(0, N) ->
    self() ! {old, N},
    Ref = make_ref(),
    self() ! {Ref, N + 1},
    Value = receive {Ref, X1} -> X1 after 1000 -> timeout end,
    Old = receive {old, X2} -> X2 after 1000 -> timeout end,
    {Value, Old, process_info(self(), message_queue_len)};
scenario(1, N) ->
    monitor_loop(N, 0);
scenario(2, N) ->
    {ok, Server} = gen_server:start_link(recv_marker_diff, [], []),
    Value = call_loop(Server, N, 0),
    ok = gen_server:stop(Server),
    Value;
scenario(3, N) ->
    self() ! {old, N},
    Ref = make_ref(),
    Timed = receive {Ref, _} -> wrong after 0 -> timed_out end,
    self() ! {Ref, N + 1},
    Value = receive {Ref, X1} -> X1 after 1000 -> timeout end,
    Old = receive {old, X2} -> X2 after 1000 -> timeout end,
    {Timed, Value, Old};
scenario(4, N) ->
    self() ! {old, N},
    Ref = make_ref(),
    self() ! {Ref, N + 1},
    receive {Ref, X} ->
        Inner = receive {old, Y} -> Y after 1000 -> timeout end,
        {X, Inner}
    after 1000 -> timeout end;
scenario(5, N) ->
    self() ! {first, N},
    Ref = make_ref(),
    self() ! {skip, N},
    self() ! {Ref, N + 1},
    Match = receive {Ref, X1} -> X1 after 1000 -> timeout end,
    First = receive {first, X2} -> X2 after 1000 -> timeout end,
    Skip = receive {skip, X3} -> X3 after 1000 -> timeout end,
    {Match, First, Skip};
scenario(6, N) ->
    self() ! {old, N},
    Ref = make_ref(),
    Timed = receive {Ref, _} -> wrong after 5 -> timed_out end,
    self() ! {Ref, N + 1},
    Value = receive {Ref, X1} -> X1 after 1000 -> timeout end,
    Old = receive {old, X2} -> X2 after 1000 -> timeout end,
    {Timed, Value, Old};
scenario(7, N) ->
    self() ! {old, N},
    Ref1 = make_ref(),
    Ref2 = make_ref(),
    self() ! {Ref1, N + 1},
    self() ! {Ref2, N + 2},
    First = receive {Ref1, X1} -> X1 after 1000 -> timeout end,
    Second = receive {Ref2, X2} -> X2 after 1000 -> timeout end,
    Old = receive {old, X3} -> X3 after 1000 -> timeout end,
    {First, Second, Old}.

monitor_loop(0, Count) -> Count;
monitor_loop(N, Count) ->
    {Pid, Ref} = spawn_monitor(fun() -> ok end),
    receive {'DOWN', Ref, process, Pid, normal} ->
        monitor_loop(N - 1, Count + 1)
    after 5000 -> timeout end.

call_loop(_, 0, Count) -> Count;
call_loop(Server, N, Count) ->
    pong = gen_server:call(Server, ping),
    call_loop(Server, N - 1, Count + 1).

init([]) -> {ok, undefined}.
handle_call(ping, _From, State) -> {reply, pong, State}.
handle_cast(_, State) -> {noreply, State}.
handle_info(_, State) -> {noreply, State}.
terminate(_, _) -> ok.
code_change(_, State, _) -> {ok, State}.
"#;

#[test]
fn receive_marker_scenarios_match_otp_29() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping receive-marker differential scenarios");
        return;
    };
    let beam = reference
        .compile_named("recv_marker_diff", SOURCE, &[])
        .unwrap();
    reference.load("recv_marker_diff", &beam).unwrap();
    for (scenario, n) in [
        (0, 13),
        (1, 256),
        (2, 256),
        (3, 13),
        (4, 13),
        (5, 13),
        (6, 13),
        (7, 13),
    ] {
        let expected = reference.call(
            "recv_marker_diff",
            "scenario",
            &[OwnedTerm::Int(scenario), OwnedTerm::Int(n)],
        );
        let mut vm = Vm::new([]);
        vm.load_bytes(&beam).unwrap();
        let actual = vm
            .eval_scheduled(
                "recv_marker_diff",
                "scenario",
                &[Term::small(scenario).unwrap(), Term::small(n).unwrap()],
                4,
                Some(0x5eed),
            )
            .unwrap_or_else(|error| panic!("scenario {scenario}: {error}"));
        assert_eq!(expected, CallResult::Ok(actual.term), "scenario {scenario}");
    }
}
