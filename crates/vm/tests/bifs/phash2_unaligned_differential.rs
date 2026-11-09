use arinsal_difftest::{CallResult, RefErl};
use arinsal_vm::Vm;
use similar_asserts::assert_eq;

const MODULE: &str = "phash2_unaligned_test";
const SOURCE: &str = r#"
-module(phash2_unaligned_test).
-export([hash/0]).

hash() ->
    Size = 5_000_000,
    Binary = binary:copy(<<16#A5>>, Size),
    <<_:1, Unaligned:Size/binary, _:7>> = <<0:1, Binary/binary, 0:7>>,
    erlang:phash2(Unaligned).
"#;

#[test]
fn unaligned_sub_binary_phash2_matches_otp_while_trapping() {
    let reference = RefErl::start().expect("OTP 29.1.1 is required for this test");
    let beam = reference.compile_named(MODULE, SOURCE, &[]).unwrap();
    reference.load(MODULE, &beam).unwrap();

    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();

    let CallResult::Ok(expected) = reference.call(MODULE, "hash", &[]) else {
        panic!("OTP phash2 failed");
    };
    let actual = vm
        .eval_scheduled_reductions(MODULE, "hash", &[], 1, Some(0xB5FF), 4_000)
        .unwrap();
    assert_eq!(expected, actual.term);
}
