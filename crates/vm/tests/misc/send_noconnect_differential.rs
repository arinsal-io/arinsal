use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_vm::Vm;

const MODULE: &str = "send_noconnect_diff";
const SOURCE: &str = r#"
-module(send_noconnect_diff).
-export([run/0]).

run() -> {
    erlang:send({not_registered, 'nonexistent@nohost'}, message, [noconnect]),
    apply(erlang, send, [{not_registered, 'nonexistent@nohost'}, message, [noconnect]]),
    erlang:send({not_registered, 'nonexistent@nohost'}, message, [nosuspend]),
    erlang:send({not_registered, 'nonexistent@nohost'}, message, [noconnect, nosuspend])
}.
"#;

#[test]
fn remote_name_send_with_noconnect_reports_noconnect_without_connecting() {
    let reference = RefErl::start().expect("OTP 29.1.1 is required for this test");
    let beam = reference.compile_named(MODULE, SOURCE, &[]).unwrap();
    reference.load(MODULE, &beam).unwrap();
    let expected = reference.call(MODULE, "run", &[]);

    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled(MODULE, "run", &[], 1, Some(0x4E43))
        .unwrap();

    let expected_value = OwnedTerm::tuple(vec![
        OwnedTerm::atom("noconnect"),
        OwnedTerm::atom("noconnect"),
        OwnedTerm::atom("ok"),
        OwnedTerm::atom("noconnect"),
    ]);
    similar_asserts::assert_eq!(expected, CallResult::Ok(expected_value));
    similar_asserts::assert_eq!(expected, CallResult::Ok(actual.term));
}
