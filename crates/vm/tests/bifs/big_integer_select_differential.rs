use arinsal_difftest::{CallResult, RefErl};
use arinsal_vm::Vm;
use similar_asserts::assert_eq;

#[test]
fn select_matches_bignums_created_at_runtime() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping bignum select differential test");
        return;
    };
    let module = "big_integer_select_differential";
    let source = "-module(big_integer_select_differential). -export([run/0]). run() -> {match_value(binary_to_integer(<<\"576460752303423488\">>)), match_value(binary_to_integer(<<\"-966394677364879734\">>))}. match_value(576460752303423488) -> positive; match_value(-966394677364879734) -> negative; match_value(_) -> other.";
    let beam = reference.compile_named(module, source, &[]).unwrap();
    reference.load(module, &beam).unwrap();
    let expected = reference.call(module, "run", &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm.eval_scheduled(module, "run", &[], 1, None).unwrap().term;

    assert_eq!(CallResult::Ok(actual), expected);
}

#[test]
fn select_splits_small_integers_from_bignums_at_the_immediate_boundary() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping mixed integer select differential test");
        return;
    };
    let module = "mixed_integer_select_differential";
    let boundary = 1_i64 << 59;
    let keys = (-40..=40).step_by(5).map(|offset| boundary + offset);
    let clauses = keys
        .clone()
        .enumerate()
        .map(|(index, value)| format!("match({value}) -> {index};"))
        .collect::<String>();
    let results = keys
        .map(|value| format!("match({value})"))
        .chain([
            format!("match({})", boundary - 100),
            format!("match({})", boundary + 100),
        ])
        .collect::<Vec<_>>()
        .join(",");
    let source = format!(
        "-module({module}). -export([run/0,match/1]). run() -> [{results}]. {clauses} match(_) -> other."
    );
    let beam = reference.compile_named(module, &source, &[]).unwrap();
    reference.load(module, &beam).unwrap();
    let expected = reference.call(module, "run", &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm.eval_scheduled(module, "run", &[], 1, None).unwrap().term;

    assert_eq!(CallResult::Ok(actual), expected);
}
