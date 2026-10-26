//! An interpreted busy loop whose entry carries a local call-trace breakpoint must still be
//! switched out when its reductions run out, so `exit(Pid, kill)` reaches it. A test of the
//! interpreter flavor: it re-runs itself in a child started with `-emu_flavor emu` (its
//! `ARINSAL_INTERP` alias).

use arinsal_difftest::{CallResult, RefErl};
use arinsal_vm::Vm;

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
fn traced_interpreted_loop_is_preempted() {
    if std::env::var_os("ARINSAL_INTERP").is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "traced_interpreted_loop_is_preempted",
                "--nocapture",
            ])
            .env("ARINSAL_INTERP", "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "interpreter flavor child failed:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping traced loop preemption test");
        return;
    };
    let spin = reference
        .compile_named("tlp_spin", SPIN, &[])
        .expect("compile spin");
    reference.load("tlp_spin", &spin).expect("load spin");
    let expected = reference.call("tlp_spin", "run", &[]);
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut vm = Vm::new([]);
        // The breakpoint instruction itself is the loop's only switch-out point.
        vm.load_bytes(&spin).expect("load VM spin");
        let actual = vm
            .eval_scheduled("tlp_spin", "run", &[], 1, None)
            .map(|value| value.term)
            .map_err(|error| error.to_string());
        let _ = sender.send(actual);
    });
    let actual = receiver
        .recv_timeout(std::time::Duration::from_secs(60))
        .expect("tlp_spin:run did not finish (traced spinner never preempted)")
        .unwrap_or_else(|error| panic!("tlp_spin:run: {error}"));
    assert_eq!(expected, CallResult::Ok(actual));
}
