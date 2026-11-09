use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_term::Term;
use arinsal_vm::{Vm, VmError};

const MODULE: &str = "vm_map_update_exact";
const SOURCE: &str = r#"
-module(vm_map_update_exact).
-export([run/1, run_size/2, missing/0]).

run(N) -> loop(N, #{count => 0}).
run_size(N, Size) -> maps:get(count, loop(N, initial(Size))).
initial(1) -> #{count => 0};
initial(Size) -> maps:from_list([{count, 0} | [{I, I} || I <- lists:seq(1, Size - 1)]]).
loop(0, Map) -> Map;
loop(N, Map) ->
    #{count := Count} = Map,
    loop(N - 1, Map#{count := Count + 1}).
missing() ->
    Map = #{},
    Map#{count := 1}.
"#;

#[test]
fn atom_key_single_exact_updates_match_otp() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping exact map update differential test");
        return;
    };
    let beam = reference.compile_named(MODULE, SOURCE, &[]).unwrap();
    reference.load(MODULE, &beam).unwrap();

    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let input = OwnedTerm::Int(100_000);
    let expected = reference.call(MODULE, "run", std::slice::from_ref(&input));
    let actual = vm
        .eval_exported(MODULE, "run", &[Term::small(100_000).unwrap()])
        .map(|outcome| arinsal_term::to_owned(outcome.term).unwrap());

    match (expected, actual) {
        (CallResult::Ok(expected), Ok(actual)) => assert_eq!(actual, expected),
        (expected, actual) => panic!("reference {expected:?}, VM {actual:?}"),
    }

    for size in [8, 32, 1_000] {
        let iterations = OwnedTerm::Int(100);
        let size_arg = OwnedTerm::Int(size);
        let expected = reference.call(MODULE, "run_size", &[iterations.clone(), size_arg]);
        let actual = vm
            .eval_exported(
                MODULE,
                "run_size",
                &[Term::small(100).unwrap(), Term::small(size).unwrap()],
            )
            .map(|outcome| arinsal_term::to_owned(outcome.term).unwrap());
        match (expected, actual) {
            (CallResult::Ok(expected), Ok(actual)) => {
                assert_eq!(actual, expected, "map size {size}")
            }
            (expected, actual) => panic!("map size {size}: reference {expected:?}, VM {actual:?}"),
        }
    }

    let expected = reference.call(MODULE, "missing", &[]);
    let actual = vm.eval_exported(MODULE, "missing", &[]);
    let CallResult::Exception { reason, .. } = expected else {
        panic!("missing-key update unexpectedly succeeded in OTP: {expected:?}");
    };
    let raised = match actual {
        Err(VmError::Raised(raised)) => raised,
        Err(error) => panic!("missing-key update raised the wrong error: {error:?}"),
        Ok(_) => panic!("missing-key update unexpectedly succeeded in Arinsal"),
    };
    assert_eq!(raised.reason, reason);
}
