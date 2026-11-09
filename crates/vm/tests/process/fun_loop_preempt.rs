//! A process that only tail-calls funs must still be switched out when its
//! reductions run out: `call_fun` is a switch-out point with an exact live count.

use arinsal_difftest::{CallResult, RefErl};
use arinsal_vm::Vm;

const SPIN: &str = r#"
-module(sol_spin).
-export([run/0]).

%% The spinner only ever tail-calls a fun, so its slice must still end at
%% `call_fun` once the reductions run out.
run() ->
    Loop = fun(G) -> G(G) end,
    {Spinner, Mon} = spawn_monitor(fun() -> Loop(Loop) end),
    Sum = lists:sum(lists:seq(1, 100000)),
    exit(Spinner, kill),
    receive {'DOWN', Mon, process, Spinner, killed} -> Sum end.
"#;

#[test]
fn fun_tail_loop_is_preempted() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping fun tail loop preemption test");
        return;
    };
    let spin = reference
        .compile_named("sol_spin", SPIN, &[])
        .expect("compile spin");
    reference.load("sol_spin", &spin).expect("load spin");
    let expected = reference.call("sol_spin", "run", &[]);
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut vm = Vm::new([]);
        vm.load_bytes(&spin).expect("load VM spin");
        let actual = vm
            .eval_scheduled("sol_spin", "run", &[], 1, None)
            .map(|value| value.term)
            .map_err(|error| error.to_string());
        let _ = sender.send(actual);
    });
    let actual = receiver
        .recv_timeout(std::time::Duration::from_secs(60))
        .expect("sol_spin:run did not finish (spinner never preempted)")
        .unwrap_or_else(|error| panic!("sol_spin:run: {error}"));
    assert_eq!(expected, CallResult::Ok(actual));
}
