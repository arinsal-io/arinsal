//! A global call trace on a function of a module that has no interpreter form (an OTP module
//! loaded from the code path) must not strand an interpreted caller in `int_code_end`.

use arinsal_difftest::{CallResult, RefErl};
use arinsal_vm::Vm;

const SOURCE: &str = r#"
-module(trace_native_only).
-export([run/0]).

run() ->
    Tracer = spawn(fun() -> sink() end),
    erlang:trace(all, true, [call, {tracer, Tracer}]),
    erlang:trace_pattern({timer, '_', '_'}, [{'_', [], []}], [global]),
    {Pid, Ref} = spawn_monitor(fun() -> timer:sleep(5) end),
    Reason = receive {'DOWN', Ref, process, Pid, R} -> R after 5000 -> timeout end,
    erlang:trace(all, false, [call]),
    Reason.

sink() -> receive _ -> sink() end.
"#;

#[test]
fn traced_native_only_function_called_from_interpreter() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping native-only trace test");
        return;
    };
    let beam = reference
        .compile_named("trace_native_only", SOURCE, &[])
        .expect("compile");
    reference
        .load("trace_native_only", &beam)
        .expect("load reference");
    let expected = reference.call("trace_native_only", "run", &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).expect("load VM fixture");
    let actual = vm
        .eval_scheduled("trace_native_only", "run", &[], 1, None)
        .map(|value| value.term)
        .unwrap_or_else(|error| panic!("run: {error}"));
    assert_eq!(expected, CallResult::Ok(actual));
}
