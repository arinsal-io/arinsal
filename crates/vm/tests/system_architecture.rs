//! `erlang:system_info(system_architecture)` against erl 29.1.1.

use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_vm::Vm;

const SOURCE: &str = r#"
-module(system_architecture_diff).
-export([run/0]).

run() ->
    Triple = erlang:system_info(system_architecture),
    [Arch, Vendor, Os | _] = string:split(Triple, "-", all),
    {io_lib:printable_list(Triple), Arch, Vendor, string:trim(Os, trailing, "0123456789.")}.
"#;

#[test]
fn system_architecture_names_the_same_target_as_erts() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping system_architecture differential test");
        return;
    };
    let beam = reference
        .compile_named("system_architecture_diff", SOURCE, &[])
        .expect("compile system_architecture_diff");
    reference
        .load("system_architecture_diff", &beam)
        .expect("load reference module");
    let expected = reference.call("system_architecture_diff", "run", &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).expect("load arinsal module");
    let actual = vm
        .eval_scheduled("system_architecture_diff", "run", &[], 1, None)
        .unwrap_or_else(|error| panic!("system_architecture_diff:run/0: {error}"));
    assert_eq!(expected, CallResult::Ok(actual.term.clone()));
    let OwnedTerm::Tuple(ref fields) = actual.term else {
        panic!("expected a tuple");
    };
    assert_eq!(fields[0], OwnedTerm::Atom("true".into()));
}
