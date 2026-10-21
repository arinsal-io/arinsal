//! A process that exits while it monitors another process demonitors it: erts sends the origin
//! half to the target from the exit monitor walk (erl_process.c, erts_proc_exit_handle_monitor),
//! so the target keeps no stale `monitored_by` entry for a dead watcher.

use arinsal_difftest::{CallResult, CompareMode, RefErl, compare};
use arinsal_vm::{Vm, VmError};

const SOURCE: &str = r#"
-module(exit_demonitor).
-export([run/0]).

run() ->
    Self = self(),
    Target = spawn(fun() -> receive stop -> ok end end),
    Watchers = [spawn(fun() -> watcher(Self, Target) end) || _ <- lists:seq(1, 3)],
    [receive {ready, W} -> ok end || W <- Watchers],
    {monitored_by, Before} = process_info(Target, monitored_by),
    Refs = [erlang:monitor(process, W) || W <- Watchers],
    [W ! go || W <- Watchers],
    [receive {'DOWN', Ref, process, _, normal} -> ok end || Ref <- Refs],
    {monitored_by, After} = process_info(Target, monitored_by),
    Target ! stop,
    {length(Before), After}.

watcher(Parent, Target) ->
    erlang:monitor(process, Target),
    Parent ! {ready, self()},
    receive go -> ok end.
"#;

#[test]
fn exiting_watcher_demonitors_its_target_like_otp() {
    let reference = RefErl::start().expect("OTP 29.1.1");
    let beam = reference
        .compile_named("exit_demonitor", SOURCE, &[])
        .expect("compile differential");
    reference
        .load("exit_demonitor", &beam)
        .expect("load reference module");
    let expected = reference.call("exit_demonitor", "run", &[]);
    for workers in [1, 4] {
        let mut vm = Vm::new([]);
        vm.load_bytes(&beam).expect("load VM module");
        let actual = match vm.eval_scheduled("exit_demonitor", "run", &[], workers, None) {
            Ok(outcome) => CallResult::Ok(outcome.term),
            Err(VmError::Raised(raised)) => CallResult::Exception {
                class: format!("{:?}", raised.class).to_lowercase(),
                reason: raised.reason,
                stack_top: Some(raised.stack),
            },
            Err(error) => CallResult::TransportError(error.to_string()),
        };
        compare(&expected, &actual, CompareMode::Exact).unwrap_or_else(|diff| {
            panic!("exit demonitor differs with {workers} schedulers: {diff}")
        });
    }
}
