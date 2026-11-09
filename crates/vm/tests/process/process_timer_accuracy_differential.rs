use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_vm::Vm;

const SOURCE: &str = r#"
-module(proc_timer_accuracy_diff).
-export([run/0, absolute/0]).

run() -> [measure() || _ <- lists:seq(1, 32)].

measure() ->
    Start = erlang:monotonic_time(nanosecond),
    _ = erlang:send_after(4, self(), timer_tick),
    receive
        timer_tick ->
            erlang:monotonic_time(nanosecond) - Start >= 3900000
    after 1000 ->
        erlang:error(timer_timeout)
    end.

absolute() ->
    Started = (erlang:monotonic_time(microsecond) + 999) div 1000,
    Ref = erlang:start_timer(Started + 100, self(), absolute_tick, [{abs, true}]),
    receive
        {timeout, Ref, absolute_tick} -> delivered
    after 400 ->
        missed
    end.
"#;

#[test]
fn relative_timer_deadlines_do_not_fire_early() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping timer accuracy differential");
        return;
    };
    let beam = reference
        .compile_named("proc_timer_accuracy_diff", SOURCE, &[])
        .expect("compile timer accuracy differential");
    reference
        .load("proc_timer_accuracy_diff", &beam)
        .expect("load timer accuracy differential");
    let expected = reference.call("proc_timer_accuracy_diff", "run", &[]);

    let mut vm = Vm::new([]);
    vm.load_bytes(&beam)
        .expect("load timer accuracy differential");
    let actual = vm
        .eval_scheduled("proc_timer_accuracy_diff", "run", &[], 2, None)
        .expect("run timer accuracy differential")
        .term;

    let all_pass = OwnedTerm::List {
        elems: vec![OwnedTerm::atom("true"); 32],
        tail: Box::new(OwnedTerm::Nil),
    };
    similar_asserts::assert_eq!(expected, CallResult::Ok(all_pass), "erts timer accuracy");
    similar_asserts::assert_eq!(expected, CallResult::Ok(actual), "Arinsal timer accuracy");
}

#[test]
fn absolute_timer_deadlines_follow_erts_monotonic_milliseconds() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping absolute timer differential");
        return;
    };
    let beam = reference
        .compile_named("proc_timer_accuracy_diff", SOURCE, &[])
        .expect("compile absolute timer differential");
    reference
        .load("proc_timer_accuracy_diff", &beam)
        .expect("load absolute timer differential");
    let expected = reference.call("proc_timer_accuracy_diff", "absolute", &[]);

    let mut vm = Vm::new([]);
    vm.load_bytes(&beam)
        .expect("load absolute timer differential");
    let actual = vm
        .eval_scheduled("proc_timer_accuracy_diff", "absolute", &[], 2, None)
        .expect("run absolute timer differential")
        .term;

    similar_asserts::assert_eq!(expected, CallResult::Ok(OwnedTerm::atom("delivered")));
    similar_asserts::assert_eq!(expected, CallResult::Ok(actual), "absolute timer outcome");
}
