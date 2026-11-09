use arinsal_difftest::{CallResult, RefErl};
use arinsal_vm::Vm;

#[test]
fn binary_replace_large_subjects_resume_after_search_traps() {
    const MODULE: &str = "binary_replace_search_trap_test";
    let reference = RefErl::start().expect("OTP 29.1.1 is required for this test");
    let source = r#"-module(binary_replace_search_trap_test).
        -export([run/0]).
        result(Subject, Pattern, Options) ->
            Replaced = binary:replace(Subject, Pattern, <<"x">>, Options),
            {byte_size(Replaced),
             binary:part(Replaced, {byte_size(Replaced) - 2, 2})}.
        run() ->
            Pattern = binary:copy(<<$z>>, 16),
            Small = <<(binary:copy(<<$a>>, 65520))/binary, Pattern/binary>>,
            Large = <<(binary:copy(<<$a>>, 1048560))/binary, Pattern/binary>>,
            {result(Small, Pattern, []),
             result(Small, Pattern, [global]),
             result(Large, Pattern, []),
             result(Large, Pattern, [global])}.
    "#;
    let beam = reference.compile_named(MODULE, source, &[]).unwrap();
    reference.load(MODULE, &beam).unwrap();
    let expected = reference.call(MODULE, "run", &[]);

    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled_reductions(MODULE, "run", &[], 1, Some(0x7C0), 4_000)
        .unwrap();
    let canonical = arinsal_etf::decode(&arinsal_etf::encode(
        &actual.term,
        arinsal_etf::EncodeOptions::default(),
    ))
    .unwrap();
    similar_asserts::assert_eq!(expected, CallResult::Ok(canonical));
}
