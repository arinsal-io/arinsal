//! Differential checks for trapped persistent-term literal access.

use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_vm::Vm;

const SOURCE: &str = r#"
-module(literal_gc_diff).
-export([applied_get_all/0]).

applied_get_all() ->
    Keys = lists:seq(1, 5000),
    [persistent_term:put({literal_gc_diff, N}, N) || N <- Keys],
    All = erlang:apply(persistent_term, get, []),
    Count = length([ok || {{literal_gc_diff, _}, _} <- All]),
    [persistent_term:erase({literal_gc_diff, N}) || N <- Keys],
    Count.
"#;

#[test]
fn applied_get_all_keeps_outer_arguments_across_yields() {
    let reference = RefErl::start().expect("OTP 29.1.1 erl is required");
    let beam = reference
        .compile_named("literal_gc_diff", SOURCE, &[])
        .expect("compile");
    reference.load("literal_gc_diff", &beam).expect("load");
    let expected = reference.call("literal_gc_diff", "applied_get_all", &[]);
    assert_eq!(expected, CallResult::Ok(OwnedTerm::Int(5000)));

    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).expect("load bytes");
    let actual = vm
        .eval_scheduled("literal_gc_diff", "applied_get_all", &[], 1, None)
        .expect("scheduled evaluation");
    assert_eq!(expected, CallResult::Ok(actual.term));
}
