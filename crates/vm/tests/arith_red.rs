use arinsal_difftest::{CallResult, CompareMode, RefErl, compare};
use arinsal_etf::OwnedTerm;
use arinsal_vm::Vm;
use std::fmt::Write as _;

#[test]
fn arith_red_late_export_calls_reuse_the_resolved_target() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping arithmetic export-index regression");
        return;
    };

    let mut exports = String::new();
    let mut functions = String::new();
    for index in 0..384 {
        write!(exports, "f{index:03}/0,").unwrap();
        writeln!(functions, "f{index:03}() -> {index}.").unwrap();
    }
    let target = format!(
        "-module(arith_red_export_target). -export([{}]). {}",
        exports.trim_end_matches(','),
        functions
    );
    let caller = "-module(arith_red_export_caller). -export([run/0]). run() -> loop(1000, 0). loop(0, Sum) -> Sum; loop(N, Sum) -> loop(N - 1, Sum + arith_red_export_target:f383()).";
    let target_beam = reference
        .compile_named("arith_red_export_target", &target, &[])
        .expect("compile target");
    let caller_beam = reference
        .compile_named("arith_red_export_caller", caller, &[])
        .expect("compile caller");
    reference
        .load("arith_red_export_target", &target_beam)
        .unwrap();
    reference
        .load("arith_red_export_caller", &caller_beam)
        .unwrap();
    let expected = reference.call("arith_red_export_caller", "run", &[]);

    let mut vm = Vm::new([]);
    vm.load_bytes(&target_beam).unwrap();
    vm.load_bytes(&caller_beam).unwrap();
    let actual = vm
        .eval_scheduled("arith_red_export_caller", "run", &[], 1, None)
        .unwrap();
    compare(&CallResult::Ok(actual.term), &expected, CompareMode::Exact).unwrap();
}

#[test]
fn arith_red_cached_export_targets_follow_code_epoch() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping cached export reload regression");
        return;
    };
    let target_v1 = reference
        .compile_named(
            "arith_red_reload_target",
            "-module(arith_red_reload_target). -export([value/0]). value() -> 1.",
            &[],
        )
        .expect("compile initial target");
    let target_v2 = reference
        .compile_named(
            "arith_red_reload_target",
            "-module(arith_red_reload_target). -export([value/0]). value() -> 2.",
            &[],
        )
        .expect("compile replacement target");
    let caller = reference
        .compile_named(
            "arith_red_reload_caller",
            "-module(arith_red_reload_caller). -export([run/1]). run(Bin) -> 1 = arith_red_reload_target:value(), {module, arith_red_reload_target} = erlang:load_module(arith_red_reload_target, Bin), arith_red_reload_target:value().",
            &[],
        )
        .expect("compile caller");
    reference
        .load("arith_red_reload_target", &target_v1)
        .unwrap();
    reference.load("arith_red_reload_caller", &caller).unwrap();
    let expected = reference.call(
        "arith_red_reload_caller",
        "run",
        &[OwnedTerm::Binary(target_v2.clone())],
    );

    let mut vm = Vm::new([]);
    vm.load_bytes(&target_v1).unwrap();
    vm.load_bytes(&caller).unwrap();
    let mut heap = arinsal_term::VecHeap::new();
    let argument = arinsal_term::from_owned(&OwnedTerm::Binary(target_v2), &mut heap).unwrap();
    let actual = vm
        .eval_scheduled("arith_red_reload_caller", "run", &[argument], 1, None)
        .unwrap();
    assert_eq!(expected, CallResult::Ok(actual.term));
}

#[test]
fn arith_red_flatmap_merge_matches_otp_across_size_boundary() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping flatmap merge differential regression");
        return;
    };
    let source = r#"
        -module(arith_red_flatmap_merge).
        -export([run/0]).
        run() ->
            A = maps:from_list([{N, N * 2} || N <- lists:seq(1, 20)]),
            B = maps:from_list([{N, N * 3} || N <- lists:seq(11, 30)]),
            C = maps:from_list([{N, N} || N <- lists:seq(21, 33)]),
            {maps:merge(A, B), maps:merge(B, A), maps:merge(A, A),
             maps:merge(A, C), maps:merge(C, A), maps:merge(#{}, B)}.
    "#;
    let beam = reference
        .compile_named("arith_red_flatmap_merge", source, &[])
        .expect("compile flatmap merge fixture");
    reference.load("arith_red_flatmap_merge", &beam).unwrap();
    let expected = reference.call("arith_red_flatmap_merge", "run", &[]);

    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled("arith_red_flatmap_merge", "run", &[], 1, None)
        .unwrap();
    compare(&CallResult::Ok(actual.term), &expected, CompareMode::Exact).unwrap();
}

fn assert_reduction_minimums(result: &OwnedTerm, minimums: &[i64], runtime: &str) {
    let OwnedTerm::List { elems, tail } = result else {
        panic!("{runtime} returned a non-list reduction result: {result:?}");
    };
    assert!(matches!(tail.as_ref(), OwnedTerm::Nil));
    assert_eq!(elems.len(), minimums.len());
    for (index, (measurement, minimum)) in elems.iter().zip(minimums).enumerate() {
        let OwnedTerm::Tuple(values) = measurement else {
            panic!("{runtime} returned a non-tuple measurement: {measurement:?}");
        };
        assert_eq!(values.len(), 2);
        let OwnedTerm::Int(actual) = values[0] else {
            panic!(
                "{runtime} returned a non-integer reduction result: {:?}",
                values[0]
            );
        };
        let result_bits = match &values[1] {
            OwnedTerm::Int(value) => {
                value.unsigned_abs().checked_ilog2().unwrap_or(0) as u64 + u64::from(*value != 0)
            }
            OwnedTerm::BigInt(value) => value.bits(),
            _ => 0,
        };
        assert!(matches!(
            values[1],
            OwnedTerm::Int(_) | OwnedTerm::BigInt(_)
        ));
        assert!(
            actual >= *minimum,
            "{runtime} operation {index} produced {result_bits} bits and charged {actual} reductions, expected at least {minimum}"
        );
    }
}

#[test]
fn arith_red_bignum_instruction_and_bif_reductions_meet_otp_minimums() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping arithmetic reduction differential test");
        return;
    };
    let source = r#"
        -module(arith_red_reductions).
        -export([run/0]).
        measure(Op, A, B) ->
            erlang:yield(),
            {reductions, Before} = process_info(self(), reductions),
            Result = eval_op(Op, A, B),
            {reductions, After} = process_info(self(), reductions),
            {After - Before - 1, Result}.
        measure1(Op, A) ->
            erlang:yield(),
            {reductions, Before} = process_info(self(), reductions),
            Result = eval_op(Op, A),
            {reductions, After} = process_info(self(), reductions),
            {After - Before - 1, Result}.
        measure_bif(Op, A, B) ->
            erlang:yield(),
            {reductions, Before} = process_info(self(), reductions),
            Result = apply(erlang, Op, [A, B]),
            {reductions, After} = process_info(self(), reductions),
            {After - Before - 1, Result}.
        measure_bif1(Op, A) ->
            erlang:yield(),
            {reductions, Before} = process_info(self(), reductions),
            Result = apply(erlang, Op, [A]),
            {reductions, After} = process_info(self(), reductions),
            {After - Before - 1, Result}.
        eval_op('-', A) -> -A;
        eval_op('bnot', A) -> bnot A.
        eval_op('+', A, B) -> A + B;
        eval_op('-', A, B) -> A - B;
        eval_op('*', A, B) -> A * B;
        eval_op('div', A, B) -> A div B;
        eval_op('rem', A, B) -> A rem B;
        eval_op('band', A, B) -> A band B;
        eval_op('bor', A, B) -> A bor B;
        eval_op('bxor', A, B) -> A bxor B;
        eval_op('bsl', A, B) -> A bsl B;
        eval_op('bsr', A, B) -> A bsr B.
        id(Value) -> Value.
        run() ->
            A = id(1) bsl (64 * 100), B = id(1) bsl (64 * 75),
            MaxInt = erlang:system_info(max_integer),
            [measure('+', A, B), measure('-', A, B),
             measure('*', A, 7), measure('div', A, 7),
             measure('rem', A, 7), measure('band', A, B),
             measure('bor', A, B), measure('bxor', A, B),
             measure('bsl', A, 1), measure('bsr', A, 1),
             measure1('bnot', A), measure1('-', A),
             measure_bif('+', A, B), measure_bif('*', A, 7),
             measure_bif('div', A, 7), measure_bif('rem', A, 7),
             measure_bif('band', A, B), measure_bif('bor', A, B),
             measure_bif('bxor', A, B), measure_bif('bsl', A, 1),
             measure_bif('bsr', A, 1), measure_bif1('bnot', A),
             measure_bif1('-', A), measure('div', MaxInt, 7),
             measure_bif('div', MaxInt, 7)].
    "#;
    let beam = reference
        .compile_named("arith_red_reductions", source, &[])
        .expect("compile arithmetic reduction fixture");
    reference.load("arith_red_reductions", &beam).unwrap();
    let expected = reference.call("arith_red_reductions", "run", &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled("arith_red_reductions", "run", &[], 1, None)
        .unwrap();
    let CallResult::Ok(expected) = expected else {
        panic!("OTP arithmetic reduction fixture failed: {expected:?}");
    };
    let minimums = [7; 23]
        .into_iter()
        .chain([3_900, 3_900])
        .collect::<Vec<_>>();
    assert_reduction_minimums(&actual.term, &minimums, "Arinsal");
    assert_eq!(
        measurement_values(&expected),
        measurement_values(&actual.term)
    );
}

fn measurement_values(result: &OwnedTerm) -> Vec<OwnedTerm> {
    let OwnedTerm::List { elems, tail } = result else {
        panic!("arithmetic fixture returned a non-list result: {result:?}");
    };
    assert!(matches!(tail.as_ref(), OwnedTerm::Nil));
    elems
        .iter()
        .map(|measurement| {
            let OwnedTerm::Tuple(values) = measurement else {
                panic!("arithmetic fixture returned a non-tuple measurement: {measurement:?}");
            };
            assert_eq!(values.len(), 2);
            values[1].clone()
        })
        .collect()
}
