//! `is_process_alive/1` of a target with queued signals sends an alive request and parks the
//! caller on the reply. The reply can be handled (and fetched into the caller's message queue)
//! before the caller finishes parking; the caller must not sleep on it. Regression for the
//! `logger_disk_log_h_SUITE:op_switch_to_flush` hang: high priority senders hammer a normal
//! priority server that asks `process_info(self(), message_queue_len)` for every message.

use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
#[allow(dead_code)]
#[path = "common/mod.rs"]
mod common;

use similar_asserts::assert_eq;
use std::sync::mpsc;
use std::time::Duration;

const MODULE: &str = "alive_request_wakeup";
const SOURCE: &str = r#"-module(alive_request_wakeup).
-export([run/1]).

run(Rounds) ->
    Srv = spawn(fun() -> srv() end),
    Ps = [spawn_monitor(fun() ->
                case X rem 2 of 0 -> process_flag(priority, high); _ -> ok end,
                loop(Srv, Rounds)
            end) || X <- lists:seq(1, 10)],
    [receive {'DOWN', M, _, _, normal} -> ok end || {_, M} <- Ps],
    Srv ! stop,
    ok.

srv() ->
    receive
        stop -> ok;
        {call, From, Ref} ->
            {_, _} = process_info(self(), message_queue_len),
            From ! {Ref, ok},
            srv();
        _ ->
            {_, _} = process_info(self(), message_queue_len),
            srv()
    end.

loop(_, 0) -> ok;
loop(Srv, N) ->
    Srv ! hi,
    true = is_process_alive(Srv),
    case N rem 3 of
        0 -> R = make_ref(), Srv ! {call, self(), R}, receive {R, ok} -> ok end;
        _ -> ok
    end,
    loop(Srv, N - 1).
"#;

#[test]
fn alive_request_reply_fetched_before_park_wakes_the_caller() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping alive request wakeup test");
        return;
    };
    let beam = reference
        .compile_named(MODULE, SOURCE, &[])
        .expect("compile alive_request_wakeup");
    reference.load(MODULE, &beam).expect("load into erl");
    let rounds = OwnedTerm::Int(3000);
    let want = match reference.call(MODULE, "run", &[rounds]) {
        CallResult::Ok(term) => term,
        other => panic!("{MODULE}:run on erl: {other:?}"),
    };
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut vm = common::node();
        common::load_fresh(&mut vm, &beam);
        for _ in 0..6 {
            let arg = arinsal_term::Term::small(20_000).unwrap();
            let result = vm.eval_scheduled(MODULE, "run", &[arg], 2);
            if tx.send(result.map(|r| r.term)).is_err() {
                return;
            }
        }
    });
    for round in 0..6 {
        let actual = rx
            .recv_timeout(Duration::from_secs(60))
            .unwrap_or_else(|_| panic!("round {round}: callers never woke (lost alive reply)"))
            .unwrap_or_else(|error| panic!("{MODULE}:run: {error}"));
        assert_eq!(actual, want, "{MODULE}:run round {round}");
    }
}
