//! A process spawned with an MFA starts in the module instance current at spawn time, not in
//! some other loaded version of that module (erl_process.c erl_create_process sets `I` from the
//! export), so a reloaded module's old native code is never entered by new processes.

use arinsal_difftest::{CallResult, RefErl};
use arinsal_vm::Vm;

const TARGET_V1: &str = r#"
-module(sev_target).
-export([report/1]).
report(Parent) -> Parent ! {version, 1}.
"#;

const TARGET_V2: &str = r#"
-module(sev_target).
-export([report/1]).
report(Parent) -> Parent ! {version, 2}.
"#;

const DRIVER: &str = r#"
-module(sev_driver).
-export([run/0]).
run() ->
    {module, sev_target} = erlang:load_module(sev_target, ?V1),
    {module, sev_target} = erlang:load_module(sev_target, ?V2),
    Parent = self(),
    Pids = [spawn(sev_target, report, [Parent]) || _ <- lists:seq(1, 4)],
    [receive {version, V} -> V after 2000 -> timeout end || _ <- Pids].
"#;

fn binary_literal(bytes: &[u8]) -> String {
    let body = bytes
        .iter()
        .map(u8::to_string)
        .collect::<Vec<_>>()
        .join(",");
    format!("<<{body}>>")
}

#[test]
fn spawned_process_enters_current_module_version() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping spawn entry version test");
        return;
    };
    let v1 = reference
        .compile_named("sev_target", TARGET_V1, &[])
        .expect("compile v1");
    let v2 = reference
        .compile_named("sev_target", TARGET_V2, &[])
        .expect("compile v2");
    let source = DRIVER
        .replace("?V1", &binary_literal(&v1))
        .replace("?V2", &binary_literal(&v2));
    let driver = reference
        .compile_named("sev_driver", &source, &[])
        .expect("compile driver");
    reference.load("sev_driver", &driver).expect("load driver");
    let expected = reference.call("sev_driver", "run", &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&driver).expect("load VM driver");
    let actual = vm
        .eval_scheduled("sev_driver", "run", &[], 2, None)
        .map(|value| value.term)
        .unwrap_or_else(|error| panic!("sev_driver:run: {error}"));
    assert_eq!(expected, CallResult::Ok(actual));
}
