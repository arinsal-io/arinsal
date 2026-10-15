//! Differential test: `erlang:resume_process/1` releases a suspend while call tracing is
//! active. A tracer that suspends and resumes the traced process, as `dbg` does, hangs the
//! traced process otherwise.

use arinsal_difftest::{CallResult, RefErl};
use arinsal_vm::Vm;

const SOURCE: &str = r#"
-module(resume_process_traced_diff).
-export([resume_while_tracing/0, suspend_resume_counts/0]).
status(Pid) -> {status, Status} = erlang:process_info(Pid, status), Status.
resume_while_tracing() ->
  Target = spawn(fun() -> receive stop -> ok end end),
  1 = erlang:trace(Target, true, [call]),
  Suspend = erlang:suspend_process(Target),
  Suspended = status(Target),
  Resume = erlang:resume_process(Target),
  Resumed = status(Target),
  Again = try erlang:resume_process(Target) catch error:badarg -> badarg end,
  Target ! stop,
  {Suspend, Suspended, Resume, Resumed, Again}.
suspend_resume_counts() ->
  Target = spawn(fun() -> receive stop -> ok end end),
  1 = erlang:trace(Target, true, [call]),
  true = erlang:suspend_process(Target),
  true = erlang:suspend_process(Target),
  {suspending, [{Target, Active, _}]} = erlang:process_info(self(), suspending),
  true = erlang:resume_process(Target),
  StillSuspended = status(Target),
  true = erlang:resume_process(Target),
  Released = status(Target),
  Target ! stop,
  {Active, StillSuspended, Released}.
"#;

#[test]
fn resume_process_while_tracing_matches_otp_29() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping resume_process_traced differential scenarios");
        return;
    };
    let beam = reference
        .compile_named("resume_process_traced_diff", SOURCE, &[])
        .unwrap();
    reference.load("resume_process_traced_diff", &beam).unwrap();
    for function in ["resume_while_tracing", "suspend_resume_counts"] {
        let expected = reference.call("resume_process_traced_diff", function, &[]);
        let mut vm = Vm::new([]);
        vm.load_bytes(&beam).unwrap();
        let actual = vm
            .eval_scheduled("resume_process_traced_diff", function, &[], 2, Some(81))
            .unwrap_or_else(|error| panic!("{function}: {error}"));
        assert_eq!(expected, CallResult::Ok(actual.term), "{function}");
    }
}
