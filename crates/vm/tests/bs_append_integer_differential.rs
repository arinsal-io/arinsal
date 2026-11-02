//! `bs_create_bin` append followed by native byte integer stores.

use arinsal_difftest::{CallResult, RefErl};
use arinsal_vm::Vm;

const MODULE: &str = "bs_append_integer_differential";
const SOURCE: &str = r#"
-module(bs_append_integer_differential).
-export([many/0, unaligned/0]).
many() -> lists:foldl(fun(I, Acc) -> <<Acc/binary,I:8>> end, <<>>, lists:seq(1, 320)).
unaligned() ->
    <<_Prefix:3, Acc:40/bitstring>> = <<5:3, 1, 2, 3, 4, 5>>,
    lists:foldl(fun(I, Bin) -> <<Bin/binary,I:8>> end, Acc, [6, 7, 8]).
"#;

#[test]
fn append_integer_matches_erts_for_growth_and_unaligned_sources() {
    for function in ["many", "unaligned"] {
        let reference = RefErl::start().expect("OTP 29.1.1");
        let beam = reference.compile_named(MODULE, SOURCE, &[]).unwrap();
        reference.load(MODULE, &beam).unwrap();
        let expected = reference.call(MODULE, function, &[]);
        let mut vm = Vm::new([]);
        vm.load_bytes(&beam).unwrap();
        let actual = vm
            .eval_scheduled(MODULE, function, &[], 1, Some(82))
            .map(|outcome| CallResult::Ok(outcome.term))
            .unwrap_or_else(|error| CallResult::TransportError(format!("{error:?}")));
        similar_asserts::assert_eq!(expected, actual, "{function}");
    }
}
