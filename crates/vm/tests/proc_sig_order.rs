//! Signal order per sender and receiver pair, for the process BIFs that send signals
//! (monitor, demonitor, link, exit): a later message from the same sender is handled after the
//! earlier signal, as erts orders them. Compared with erl, under the JIT and `ARINSAL_INTERP=1`.

use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_term::{Term, global_atoms};
use arinsal_vm::Vm;
use std::process::Command;

const CHILD: &str = "ARINSAL_PROC_SIG_ORDER_CHILD";
const MODULE: &str = "proc_sig_order";
const CASES: &[&str] = &[
    "monitor_then_send",
    "demonitor_then_send",
    "link_then_exit",
    "message_exit_message",
    "message_exit_message_running",
    "info_reply_after_unmatched_message",
    "monitor_then_message_to_parent",
    "alive_after_exit_signal",
    "alive_after_exit_signal_running",
    "alive_sees_message_before_exit",
    "alive_live_idle",
];

const SOURCE: &str = r#"-module(proc_sig_order).
-export([run/1]).

run(monitor_then_send) ->
    Self = self(),
    P = spawn(fun target/0),
    M = erlang:monitor(process, P),
    P ! {probe, Self},
    Seen = receive {P, Found} -> Found after 5000 -> timeout end,
    P ! stop,
    erlang:demonitor(M, [flush]),
    Seen;
run(demonitor_then_send) ->
    Self = self(),
    P = spawn(fun target/0),
    M = erlang:monitor(process, P),
    erlang:demonitor(M, [flush]),
    P ! {probe, Self},
    Seen = receive {P, Found} -> Found after 5000 -> timeout end,
    P ! stop,
    Seen;
run(monitor_then_message_to_parent) ->
    %% The monitor is held on the sender's scheduler; a native message send to the same
    %% receiver must publish it first.
    process_flag(priority, high),
    process_flag(scheduler, 1),
    Lost = [monitor_then_message() || _ <- lists:seq(1, 5000)],
    length([L || L <- Lost, L =/= ok]);
run(alive_after_exit_signal) ->
    %% is_process_alive/1 must order itself after an exit signal this process sent earlier
    %% (erl_bif_info.c: a target with queued signals gets an 'is alive' request).
    count_alive(3000, fun idle/0, 0);
run(alive_after_exit_signal_running) ->
    count_alive(1000, fun busy/0, 0);
run(alive_sees_message_before_exit) ->
    %% A message the inspected process sent before it exited is receivable once
    %% is_process_alive/1 says false.
    Self = self(),
    Lost = [begin
                P = spawn(fun() -> Self ! {m, I} end),
                wait_dead(P),
                receive {m, I} -> ok after 0 -> lost end
            end || I <- lists:seq(1, 3000)],
    length([L || L <- Lost, L =/= ok]);
run(alive_live_idle) ->
    P = spawn(fun idle/0),
    R = [is_process_alive(P) || _ <- lists:seq(1, 1000)],
    exit(P, kill),
    wait_dead(P),
    {lists:usort(R), is_process_alive(P), is_process_alive(self())};
run(link_then_exit) ->
    Self = self(),
    P = spawn(fun() -> trapping_target(Self) end),
    receive {P, ready} -> ok end,
    link(P),
    exit(P, boom),
    Seen = receive {P, Found} -> Found after 5000 -> timeout end,
    P ! stop,
    unlink(P),
    Seen;
run(message_exit_message) ->
    Self = self(),
    P = spawn(fun() -> collecting_target(Self) end),
    receive {P, ready} -> ok end,
    link(P),
    P ! first,
    exit(P, boom),
    P ! second,
    receive {P, Seen} -> Seen after 5000 -> timeout end;
run(message_exit_message_running) ->
    Self = self(),
    P = spawn(fun() -> running_target(Self) end),
    receive {P, ready} -> ok end,
    link(P),
    P ! go,
    P ! first,
    exit(P, boom),
    P ! second,
    receive {P, Seen} -> Seen after 5000 -> timeout end;
run(info_reply_after_unmatched_message) ->
    Self = self(),
    P = spawn(fun() -> Self ! {self(), ready}, receive stop -> ok end end),
    receive {P, ready} -> ok end,
    wait_waiting(P),
    P ! unmatched,
    {message_queue_len, Len} = process_info(P, message_queue_len),
    {memory, Memory} = process_info(P, memory),
    exit(P, kill),
    {Len, is_integer(Memory)}.

monitor_then_message() ->
    Self = self(),
    P = spawn_opt(fun() ->
                          erlang:monitor(process, Self),
                          Self ! {self(), ready},
                          receive stop -> ok end
                  end, [{priority, high}, {scheduler, 2}]),
    receive {P, ready} -> ok end,
    {monitored_by, Mons} = process_info(self(), monitored_by),
    P ! stop,
    case lists:member(P, Mons) of true -> ok; false -> lost end.

count_alive(0, _, Acc) -> Acc;
count_alive(N, Body, Acc) ->
    case alive_after_kill(Body) of
        false -> count_alive(N - 1, Body, Acc);
        true -> count_alive(N - 1, Body, Acc + 1)
    end.

alive_after_kill(Body) ->
    P = spawn(Body),
    exit(P, kill),
    case is_process_alive(P) of
        Alive when is_boolean(Alive) -> Alive
    end.

idle() -> receive stop -> ok end.

busy() -> busy().

wait_dead(P) ->
    case is_process_alive(P) of
        true -> erlang:yield(), wait_dead(P);
        false -> ok
    end.

wait_waiting(P) ->
    case process_info(P, status) of
        {status, waiting} -> ok;
        _ -> timer:sleep(1), wait_waiting(P)
    end.

%% Reports the order in which messages and the exit signal of the parent are received.
collecting_target(Parent) ->
    process_flag(trap_exit, true),
    Parent ! {self(), ready},
    receive
        first -> ok
    end,
    Parent ! {self(), [first | drain(Parent)]}.

drain(Parent) ->
    receive
        {'EXIT', Parent, Reason} -> [{exit, Reason} | drain(Parent)];
        Message -> [Message | drain(Parent)]
    after 200 -> []
    end.

%% Like collecting_target, but the process is runnable when the signals arrive.
running_target(Parent) ->
    process_flag(trap_exit, true),
    Parent ! {self(), ready},
    receive go -> ok end,
    spin(2000),
    Parent ! {self(), drain(Parent)}.

spin(0) -> ok;
spin(N) -> erlang:yield(), spin(N - 1).

%% Replies with whether the probing parent is among the monitors it has when the probe is handled.
target() ->
    receive
        {probe, Parent} ->
            {monitored_by, Mons} = process_info(self(), monitored_by),
            Parent ! {self(), lists:member(Parent, Mons)},
            target();
        stop -> ok
    end.

%% Replies with whether the parent is among its links when the exit signal is handled.
trapping_target(Parent) ->
    process_flag(trap_exit, true),
    Parent ! {self(), ready},
    trapping_loop(Parent).

trapping_loop(Parent) ->
    receive
        {'EXIT', Parent, _} ->
            {links, Links} = process_info(self(), links),
            Parent ! {self(), lists:member(Parent, Links)},
            trapping_loop(Parent);
        stop -> ok
    end.
"#;

fn child() -> bool {
    let Some(beam_path) = std::env::var_os(CHILD) else {
        return false;
    };
    for case in CASES {
        let mut vm = Vm::new([]);
        vm.load_bytes(&std::fs::read(&beam_path).unwrap()).unwrap();
        let arg = Term::atom(global_atoms().intern(case).unwrap());
        let actual = vm.eval_scheduled(MODULE, "run", &[arg], 2, None).unwrap();
        println!("RESULT:{case}:{:?}", actual.term);
    }
    true
}

#[test]
fn process_signal_order_matches_erl() {
    if child() {
        return;
    }
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping signal order test");
        return;
    };
    let beam = reference
        .compile_named(MODULE, SOURCE, &[])
        .expect("compile proc_sig_order");
    reference.load(MODULE, &beam).expect("load into erl");
    let expected: Vec<(String, OwnedTerm)> = CASES
        .iter()
        .map(
            |case| match reference.call(MODULE, "run", &[OwnedTerm::Atom((*case).into())]) {
                CallResult::Ok(term) => (case.to_string(), term),
                other => panic!("{MODULE}:run({case}) on erl: {other:?}"),
            },
        )
        .collect();

    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).expect("load into arinsal");
    for (case, want) in &expected {
        let arg = Term::atom(global_atoms().intern(case).unwrap());
        let actual = vm
            .eval_scheduled(MODULE, "run", &[arg], 2, None)
            .expect("scheduled run");
        assert_eq!(actual.term, *want, "JIT {MODULE}:run({case})");
    }

    let dir = std::env::temp_dir().join(format!("arinsal-proc-sig-order-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(format!("{MODULE}.beam"));
    std::fs::write(&path, &beam).unwrap();
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "process_signal_order_matches_erl",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD, &path)
        .env("ARINSAL_INTERP", "1")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    assert!(
        output.status.success(),
        "interpreter child failed: {stdout} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let _ = std::fs::remove_dir_all(&dir);
    for (case, want) in &expected {
        let marker = format!("RESULT:{case}:");
        let start = stdout
            .find(&marker)
            .unwrap_or_else(|| panic!("no interpreter result for {case}: {stdout}"))
            + marker.len();
        let line = stdout[start..].lines().next().unwrap_or_default();
        assert_eq!(
            line,
            format!("{want:?}"),
            "interpreter {MODULE}:run({case}) stdout={stdout}"
        );
    }
}
