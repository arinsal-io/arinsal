use arinsal_difftest::{CallResult, CompareMode, RefErl, compare};
use arinsal_vm::{Vm, VmError};

const SOURCE: &str = r#"
-module(spawn_monitor_tag).
-export([run/0]).

run() ->
    Ref = erlang:spawn_request(erlang, node, [], [{monitor, [{tag, custom_down}]}]),
    Pid = receive
        {spawn_reply, Ref, ok, Child} -> Child
    after 2000 -> timeout
    end,
    receive
        {custom_down, Ref, process, Pid, normal} -> ok
    after 2000 -> timeout
    end.
"#;

#[test]
fn spawn_request_monitor_tag_matches_otp() {
    let reference = RefErl::start().expect("OTP 29.1.1");
    let beam = reference
        .compile_named("spawn_monitor_tag", SOURCE, &[])
        .expect("compile differential");
    reference
        .load("spawn_monitor_tag", &beam)
        .expect("load reference module");
    let expected = reference.call("spawn_monitor_tag", "run", &[]);

    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).expect("load VM module");
    let actual = match vm.eval_scheduled("spawn_monitor_tag", "run", &[], 1, None) {
        Ok(outcome) => CallResult::Ok(outcome.term),
        Err(VmError::Raised(raised)) => CallResult::Exception {
            class: format!("{:?}", raised.class).to_lowercase(),
            reason: raised.reason,
            stack_top: Some(raised.stack),
        },
        Err(error) => CallResult::TransportError(error.to_string()),
    };
    compare(&expected, &actual, CompareMode::Exact)
        .unwrap_or_else(|diff| panic!("spawn monitor tag differs: {diff}"));
}
