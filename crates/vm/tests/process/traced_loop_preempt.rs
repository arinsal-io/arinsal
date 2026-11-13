//! A busy loop whose entry carries a local call-trace breakpoint must still be switched out when
//! its reductions run out, so `exit(Pid, kill)` reaches it.

use arinsal_difftest::{CallResult, RefErl};

const SPIN: &str = r#"
-module(tlp_spin).
-export([run/0, spin/0]).

run() ->
    1 = erlang:trace_pattern({tlp_spin, spin, 0}, true, [local]),
    {Spinner, Mon} = spawn_monitor(fun tlp_spin:spin/0),
    Sum = lists:sum(lists:seq(1, 100000)),
    exit(Spinner, kill),
    Result = receive {'DOWN', Mon, process, Spinner, Reason} -> {Reason, Sum} end,
    erlang:trace_pattern({tlp_spin, spin, 0}, false, [local]),
    Result.

spin() -> spin().
"#;

#[test]
fn traced_loop_is_preempted() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping traced loop preemption test");
        return;
    };
    let spin = reference
        .compile_named("tlp_spin", SPIN, &[])
        .expect("compile spin");
    reference.load("tlp_spin", &spin).expect("load spin");
    let expected = reference.call("tlp_spin", "run", &[]);
    let actual = crate::common::peer_eval(&[], &[&spin], "tlp_spin:run()");
    similar_asserts::assert_eq!(expected, CallResult::Ok(actual));
}
