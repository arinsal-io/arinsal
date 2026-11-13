use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;

const SOURCE: &str = r#"
-module(proc_receive_timeout_diff).
-export([run/0]).

run() -> [fails(T) || T <- [
    -1, 0.0, 3.14, 16#100000000,
    392347129847294724972398472984729847129874,
    16#3fffffffffffffff, 16#ffffffffffffffff,
    -16#100000000, -3891278094774921784123987129848, invalid_timeout
]].

fails(Timeout) ->
    {'EXIT', {timeout_value, _}} = (catch receive after Timeout -> ok end),
    true.
"#;

#[test]
fn invalid_receive_timeouts_match_erts() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping receive timeout differential");
        return;
    };
    let beam = reference
        .compile_named("proc_receive_timeout_diff", SOURCE, &[])
        .expect("compile receive timeout differential");
    reference
        .load("proc_receive_timeout_diff", &beam)
        .expect("load receive timeout differential");
    let expected = reference.call("proc_receive_timeout_diff", "run", &[]);

    let mut vm = crate::common::node();
    vm.load_bytes(&beam)
        .expect("load receive timeout differential");
    let actual = vm
        .eval_scheduled("proc_receive_timeout_diff", "run", &[], 2)
        .expect("run receive timeout differential")
        .term;

    let all_invalid = OwnedTerm::List {
        elems: vec![OwnedTerm::atom("true"); 10],
        tail: Box::new(OwnedTerm::Nil),
    };
    similar_asserts::assert_eq!(expected, CallResult::Ok(all_invalid), "erts timeout errors");
    similar_asserts::assert_eq!(expected, CallResult::Ok(actual), "Arinsal timeout errors");
}

const FLOOD_SOURCE: &str = r#"
-module(proc_receive_flood_diff).
-export([run/0]).

run() ->
    Parent = self(),
    Receiver = spawn(fun() ->
        Start = erlang:monotonic_time(millisecond),
        Result = receive never_sent -> matched after 200 -> timed_out end,
        Parent ! {self(), Result, erlang:monotonic_time(millisecond) - Start}
    end),
    Flooders = [spawn(fun() -> flood(Receiver) end) || _ <- [1, 2, 3]],
    receive
        {Receiver, Result, Elapsed} ->
            [exit(F, kill) || F <- Flooders],
            exit(Receiver, kill),
            {Result, Elapsed >= 200, Elapsed < 1000}
    after 5000 ->
        [exit(F, kill) || F <- Flooders],
        exit(Receiver, kill),
        no_timeout
    end.

flood(Pid) ->
    Pid ! junk,
    flood(Pid).
"#;

#[test]
fn receive_flooded_by_non_matching_messages_times_out_on_time() {
    // The receive timer stays set while non-matching messages keep the receiver runnable;
    // the timeout is not lost because the receiver never sleeps.
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping receive flood differential");
        return;
    };
    let beam = reference
        .compile_named("proc_receive_flood_diff", FLOOD_SOURCE, &[])
        .expect("compile receive flood differential");
    reference
        .load("proc_receive_flood_diff", &beam)
        .expect("load receive flood differential");
    let expected = reference.call("proc_receive_flood_diff", "run", &[]);

    let mut vm = crate::common::node();
    vm.load_bytes(&beam)
        .expect("load receive flood differential");
    let actual = vm
        .eval_scheduled("proc_receive_flood_diff", "run", &[], 4)
        .expect("run receive flood differential")
        .term;

    let on_time = OwnedTerm::Tuple(vec![
        OwnedTerm::atom("timed_out"),
        OwnedTerm::atom("true"),
        OwnedTerm::atom("true"),
    ]);
    similar_asserts::assert_eq!(expected, CallResult::Ok(on_time), "erts flood timeout");
    similar_asserts::assert_eq!(expected, CallResult::Ok(actual), "Arinsal flood timeout");
}
