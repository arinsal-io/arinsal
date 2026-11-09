//! Differential test: integer arithmetic and bitwise operations with constant and typed
//! operands behave like erts, for small, boundary and bignum values and for every error case.

use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_vm::Vm;

const OPS: [&str; 10] = [
    "+", "-", "*", "band", "bor", "bxor", "bsl", "bsr", "rem", "div",
];

const CONSTANTS: [&str; 16] = [
    "0",
    "1",
    "-1",
    "2",
    "3",
    "8",
    "-8",
    "59",
    "60",
    "255",
    "4095",
    "4096",
    "1099511627776",
    "576460752303423487",
    "-576460752303423488",
    "576460752303423488",
];

/// Integers in the `i64` range come back as `Int` from the reference node and may be
/// `BigInt` from the VM when they are bignums; compare them by value.
fn normalize(term: &OwnedTerm) -> OwnedTerm {
    match term {
        OwnedTerm::BigInt(value) => {
            i64::try_from(value.clone()).map_or_else(|_| term.clone(), OwnedTerm::Int)
        }
        OwnedTerm::Tuple(items) => OwnedTerm::Tuple(items.iter().map(normalize).collect()),
        OwnedTerm::List { elems, tail } => OwnedTerm::List {
            elems: elems.iter().map(normalize).collect(),
            tail: Box::new(normalize(tail)),
        },
        other => other.clone(),
    }
}

fn source() -> String {
    let mut functions = Vec::new();
    let mut names = Vec::new();
    for (op_index, op) in OPS.iter().enumerate() {
        for (k, constant) in CONSTANTS.iter().enumerate() {
            let rhs = format!("r_{op_index}_{k}");
            functions.push(format!("{rhs}(X) -> X {op} {constant}."));
            names.push(rhs);
            let lhs = format!("l_{op_index}_{k}");
            functions.push(format!("{lhs}(X) -> {constant} {op} X."));
            names.push(lhs);
            // Operand types from the compiler's type pass: bounded and unbounded integers.
            let bounded = format!("b_{op_index}_{k}");
            functions.push(format!(
                "{bounded}(X) when is_integer(X), X >= -50, X =< 50 -> X {op} {constant}."
            ));
            names.push(bounded);
            let positive = format!("p_{op_index}_{k}");
            functions.push(format!(
                "{positive}(X) when is_integer(X), X >= 0, X =< 1000000 -> X {op} {constant}."
            ));
            names.push(positive);
            let integer = format!("i_{op_index}_{k}");
            functions.push(format!(
                "{integer}(X) when is_integer(X) -> X {op} {constant}."
            ));
            names.push(integer);
            let number = format!("n_{op_index}_{k}");
            functions.push(format!(
                "{number}(X) when is_number(X) -> X {op} {constant}."
            ));
            names.push(number);
        }
    }
    let mut binary = Vec::new();
    for (op_index, op) in OPS.iter().enumerate() {
        let plain = format!("pp_{op_index}");
        functions.push(format!("{plain}(X, Y) -> X {op} Y."));
        binary.push(plain);
        let integers = format!("ii_{op_index}");
        functions.push(format!(
            "{integers}(X, Y) when is_integer(X), is_integer(Y) -> X {op} Y."
        ));
        binary.push(integers);
        let bounded = format!("bb_{op_index}");
        functions.push(format!(
            "{bounded}(X, Y) when is_integer(X), X >= -100, X =< 100, is_integer(Y), Y >= 0, Y =< 20 -> X {op} Y."
        ));
        binary.push(bounded);
        let mixed = format!("bi_{op_index}");
        functions.push(format!(
            "{mixed}(X, Y) when is_integer(X), X >= 0, X =< 255, is_integer(Y) -> X {op} Y."
        ));
        binary.push(mixed);
        let guard = format!("gd_{op_index}");
        functions.push(format!(
            "{guard}(X, Y) when X {op} Y > 5 -> big; {guard}(_, _) -> small."
        ));
        binary.push(guard);
    }
    let unary_list = names
        .iter()
        .map(|name| name.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    let binary_list = binary.join(", ");
    let exports = names
        .iter()
        .map(|name| format!("{name}/1"))
        .chain(binary.iter().map(|name| format!("{name}/2")))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        r#"-module(jit_const_arith).
-export([run/0, {exports}]).
values() -> [0, 1, -1, 2, 3, 7, 8, -8, 15, 16, 17, 59, 60, 61, 255, 256, 4095, 4096, -4096,
  1099511627776, 576460752303423487, -576460752303423488, 576460752303423488,
  -576460752303423489, 18446744073709551619, -18446744073709551619, 1.5, -2.0, a, [], {{}}].
pairs() -> [0, 1, -1, 3, 8, 255, 4096, 576460752303423487, -576460752303423488, 576460752303423488,
  18446744073709551619, 1.5, a].
shifts() -> [0, 2, 5, 20, 58, 59, 60, 64, -1, -60, 1000000000000000000000].
attempt(M, F, Args) ->
    try apply(M, F, Args) of V -> V catch C:R -> {{C, R}} end.
run() ->
    Unary = [{{N, V, attempt(jit_const_arith, N, [V])}} || N <- [{unary_list}], V <- values()],
    Binary = [{{N, X, Y, attempt(jit_const_arith, N, [X, Y])}}
              || N <- [{binary_list}], X <- pairs(), Y <- shifts() ++ pairs()],
    {{Unary, Binary}}.
{functions}
"#,
        functions = functions.join("\n")
    )
}

#[test]
fn constant_and_typed_integer_arithmetic_matches_erts() {
    let reference = RefErl::start().expect("OTP 29.1.1 is required for this test");
    let beam = reference
        .compile_named("jit_const_arith", &source(), &[])
        .unwrap();
    reference.load("jit_const_arith", &beam).unwrap();
    let expected = reference.call("jit_const_arith", "run", &[]);

    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled("jit_const_arith", "run", &[], 1, None)
        .unwrap();
    let CallResult::Ok(expected) = expected else {
        panic!("reference run failed: {expected:?}");
    };
    let mut differences = Vec::new();
    let (OwnedTerm::Tuple(expected), OwnedTerm::Tuple(actual)) = (&expected, &actual.term) else {
        panic!("unexpected result shape");
    };
    for (expected, actual) in expected.iter().zip(actual) {
        let (
            OwnedTerm::List {
                elems: expected, ..
            },
            OwnedTerm::List { elems: actual, .. },
        ) = (expected, actual)
        else {
            panic!("unexpected result list");
        };
        assert_eq!(expected.len(), actual.len());
        for (expected, actual) in expected.iter().zip(actual) {
            if normalize(expected) != normalize(actual) {
                differences.push(format!("expected {expected:?}\n   actual {actual:?}"));
            }
        }
    }
    assert!(
        differences.is_empty(),
        "{} differences, first ones:\n{}",
        differences.len(),
        differences
            .iter()
            .take(12)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn mul_add_fused_div_rem_and_typed_shift_match_erts() {
    let reference = RefErl::start().expect("OTP 29.1.1 is required for this test");
    let source = r#"
        -module(jit_mul_fuse).
        -export([run/0]).
        mul3(X) -> X * 3.
        mul8(X) -> X * 8.
        mulneg(X) -> X * -8.
        xy(X, Y) -> X * Y.
        ma(X) -> X * 3 + 5.
        ma2(X) -> 1 + X * 8.
        ma3(X, Y) -> X * Y + 2.
        dr(X, Y) -> {X div Y, X rem Y}.
        rd(X, Y) -> {X rem Y, X div Y}.
        typed(X) when is_integer(X), X >= 0, X =< 1000 -> X * 8 + 3.
        guard(X) when X * 3 > 10 -> big; guard(_) -> small.
        deep(0) -> 0;
        deep(N) -> 1 + deep(N - 1).
        attempt(M, F, Args) -> try apply(M, F, Args) of V -> V catch C:R -> {C, R} end.
        run() ->
            Vs = [0, 1, -1, 2, 7, 8, 40, 255, 4096, 576460752303423487,
                  -576460752303423488, 576460752303423488, 1.5, a],
            Ps = [0, 1, -1, 3, 8, -8, 255, 4096],
            {[{mul3, V, attempt(jit_mul_fuse, mul3, [V])} || V <- Vs],
             [{mul8, V, attempt(jit_mul_fuse, mul8, [V])} || V <- Vs],
             [{mulneg, V, attempt(jit_mul_fuse, mulneg, [V])} || V <- Vs],
             [{xy, X, Y, attempt(jit_mul_fuse, xy, [X, Y])} || X <- Ps, Y <- Vs],
             [{ma, V, attempt(jit_mul_fuse, ma, [V])} || V <- Vs],
             [{ma2, V, attempt(jit_mul_fuse, ma2, [V])} || V <- Vs],
             [{ma3, X, Y, attempt(jit_mul_fuse, ma3, [X, Y])} || X <- Ps, Y <- Vs],
             [{dr, X, Y, attempt(jit_mul_fuse, dr, [X, Y])} || X <- Vs, Y <- Ps ++ [0, -1]],
             [{rd, X, Y, attempt(jit_mul_fuse, rd, [X, Y])} || X <- Vs, Y <- Ps ++ [0]],
             [{typed, V, attempt(jit_mul_fuse, typed, [V])} || V <- Vs],
             [{guard, V, attempt(jit_mul_fuse, guard, [V])} || V <- Vs],
             deep(40)}.
    "#;
    let beam = reference
        .compile_named("jit_mul_fuse", source, &[])
        .unwrap();
    reference.load("jit_mul_fuse", &beam).unwrap();
    let expected = reference.call("jit_mul_fuse", "run", &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled("jit_mul_fuse", "run", &[], 1, None)
        .unwrap();
    let CallResult::Ok(expected) = expected else {
        panic!("reference run failed: {expected:?}");
    };
    assert_eq!(
        normalize(&expected),
        normalize(&actual.term),
        "fused arithmetic diverged"
    );
}
