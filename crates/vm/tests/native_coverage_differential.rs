use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_term::{Term, global_atoms};
use arinsal_vm::Vm;
use similar_asserts::assert_eq;

const TARGET: &str = "native_coverage_differential_target";
const DRIVER: &str = "native_coverage_differential_driver";

const TARGET_SOURCE: &str = "-module(native_coverage_differential_target). -export([fact/1,fib/1]). fact(N) when is_integer(N), N >= 0 -> fact(N, 1). fact(0, P) -> P; fact(N, P) -> fact(N - 1, P * N). fib(N) -> fib(N, 0, 1). fib(0, _, B) -> B; fib(N, A, B) -> fib(N - 1, B, A + B).";
const DRIVER_SOURCE: &str = "-module(native_coverage_differential_driver). -export([set_mode/1,coverage/1]). set_mode(Mode) -> code:set_coverage_mode(Mode). coverage(Kind) -> code:get_coverage(Kind, native_coverage_differential_target).";

#[test]
fn native_coverage_modes_match_otp() {
    for (mode, kind, with_lines) in [
        ("function", "function", false),
        ("function_counters", "function", false),
        ("line", "line", true),
        ("line_counters", "line", true),
    ] {
        let Ok(reference) = RefErl::start() else {
            eprintln!("erl unavailable; skipping native coverage differential test");
            return;
        };
        let options = if with_lines {
            vec![OwnedTerm::Atom("line_coverage".into())]
        } else {
            Vec::new()
        };
        let target = reference
            .compile_named(TARGET, TARGET_SOURCE, &options)
            .unwrap();
        let driver = reference.compile_named(DRIVER, DRIVER_SOURCE, &[]).unwrap();
        reference.load(DRIVER, &driver).unwrap();
        reference
            .eval(&format!("code:set_coverage_mode({mode})"))
            .unwrap();
        reference.load(TARGET, &target).unwrap();
        let expected_result = reference.call(TARGET, "fib", &[OwnedTerm::Int(5)]);
        let expected_coverage = reference
            .eval(&format!("code:get_coverage({kind}, {TARGET})"))
            .unwrap();

        let mut vm = Vm::new([]);
        vm.load_bytes(&driver).unwrap();
        let mode_term = Term::atom(global_atoms().intern(mode).unwrap());
        vm.eval_scheduled(DRIVER, "set_mode", &[mode_term], 1, None)
            .unwrap();
        vm.load_bytes(&target).unwrap();
        let actual_result = vm
            .eval_scheduled(TARGET, "fib", &[Term::small(5).unwrap()], 1, None)
            .unwrap()
            .term;
        let actual_coverage = vm
            .eval_scheduled(
                DRIVER,
                "coverage",
                &[Term::atom(global_atoms().intern(kind).unwrap())],
                1,
                None,
            )
            .unwrap()
            .term;

        assert_eq!(CallResult::Ok(actual_result), expected_result);
        assert_eq!(actual_coverage, expected_coverage, "mode={mode}");
    }
}
