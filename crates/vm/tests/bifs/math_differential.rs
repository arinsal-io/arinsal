use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm as O;
use arinsal_term::{VecHeap, from_owned};
use num_bigint::BigInt;
use similar_asserts::assert_eq;

const MODULE: &str = "math_differential";
const SOURCE: &str = r#"
-module(math_differential).
-export([run/2]).

run(Function, Arguments) ->
    try apply(math, Function, Arguments) of
        Value -> {ok, Value}
    catch
        Class:Reason:Stack ->
            [{Module, Name, Args, Location} | _] = Stack,
            {error, Class, Reason, Module, Name, Args,
             proplists:get_value(error_info, Location, undefined)}
    end.
"#;

const UNARY: &[&str] = &[
    "cos", "cosh", "sin", "sinh", "tan", "tanh", "acos", "acosh", "asin", "asinh", "atan", "atanh",
    "erf", "erfc", "exp", "log", "log2", "log10", "sqrt", "ceil", "floor",
];
const BINARY: &[&str] = &["atan2", "pow", "fmod"];

fn atom(value: &str) -> O {
    O::atom(value)
}

fn list(values: Vec<O>) -> O {
    O::list(values)
}

fn unary_arguments() -> Vec<O> {
    let values = vec![
        O::Float(-0.0),
        O::Float(0.0),
        O::Float(0.5),
        O::Float(-0.5),
        O::Float(1.0),
        O::Float(-1.0),
        O::Float(2.0),
        O::Float(-2.0),
        O::Float(f64::MIN_POSITIVE),
        O::Float(f64::MAX),
        O::Int(17),
        O::Int(-17),
        O::BigInt(BigInt::from(1_u8) << 100_u32),
        O::BigInt(-(BigInt::from(1_u8) << 100_u32)),
        O::BigInt(BigInt::from(1_u8) << 1024_u32),
        atom("not_a_number"),
    ];
    values
}

fn cases() -> Vec<(&'static str, Vec<O>)> {
    let unary = unary_arguments();
    let mut calls = Vec::new();
    for function in UNARY {
        calls.extend(
            unary
                .iter()
                .cloned()
                .map(|argument| (*function, vec![argument])),
        );
    }
    let binary = [
        vec![O::Float(-0.0), O::Float(0.0)],
        vec![O::Float(1.0), O::Float(-0.0)],
        vec![O::Float(-1.0), O::Float(2.0)],
        vec![O::Float(9.0), O::Float(0.0)],
        vec![O::Int(7), O::Int(-3)],
        vec![O::BigInt(BigInt::from(1_u8) << 100_u32), O::Int(3)],
        vec![O::Int(3), O::BigInt(BigInt::from(1_u8) << 100_u32)],
        vec![O::BigInt(BigInt::from(1_u8) << 1024_u32), O::Int(3)],
        vec![O::Int(3), atom("not_a_number")],
    ];
    for function in BINARY {
        calls.extend(
            binary
                .iter()
                .cloned()
                .map(|arguments| (*function, arguments)),
        );
    }
    calls
}

#[test]
fn math_bifs_match_otp_29_values_and_error_info() {
    let reference = RefErl::start().expect("OTP 29.1.1 reference");
    let beam = reference.compile_named(MODULE, SOURCE, &[]).unwrap();
    reference.load(MODULE, &beam).unwrap();

    let cases = cases();
    let reference_calls = cases
        .iter()
        .map(|(function, arguments)| (MODULE, "run", vec![atom(function), list(arguments.clone())]))
        .collect::<Vec<_>>();
    let expected = reference.call_batch(&reference_calls);
    assert_eq!(expected.len(), cases.len());

    let mut vm = crate::common::node();
    vm.load_bytes(&beam).unwrap();
    let mut heap = VecHeap::new();
    for ((function, arguments), expected) in cases.iter().zip(expected) {
        let vm_arguments = [
            from_owned(&atom(function), &mut heap).unwrap(),
            from_owned(&list(arguments.clone()), &mut heap).unwrap(),
        ];
        let actual = vm
            .eval_scheduled(MODULE, "run", &vm_arguments, 1)
            .unwrap_or_else(|error| panic!("math:{function} {arguments:?}: {error}"));
        assert_eq!(
            expected,
            CallResult::Ok(actual.term.clone()),
            "math:{function} {arguments:?}"
        );
        if let (CallResult::Ok(O::Tuple(expected)), O::Tuple(actual)) = (&expected, &actual.term)
            && let ([O::Atom(tag), O::Float(expected)], [O::Atom(actual_tag), O::Float(actual)]) =
                (expected.as_slice(), actual.as_slice())
            && tag == "ok"
            && actual_tag == "ok"
        {
            assert_eq!(
                expected.to_bits(),
                actual.to_bits(),
                "math:{function} {arguments:?}"
            );
        }
    }

    // OTP's ETF decoder and NIF enif_make_double reject non-finite floats, so they cannot be
    // supplied to the reference BIF through RefErl. These synthetic process arguments verify
    // the erl_math.c result check directly: cos/sin of either value produce a non-finite result.
    for (function, value) in [
        ("cos", f64::INFINITY),
        ("sin", f64::NEG_INFINITY),
        ("cos", f64::NAN),
        ("sin", f64::NAN),
    ] {
        let vm_arguments = [
            from_owned(&atom(function), &mut heap).unwrap(),
            from_owned(&list(vec![O::Float(value)]), &mut heap).unwrap(),
        ];
        let actual = vm
            .eval_scheduled(MODULE, "run", &vm_arguments, 1)
            .unwrap_or_else(|error| panic!("math:{function}({value:?}): {error}"));
        let O::Tuple(parts) = &actual.term else {
            panic!("math:{function}({value:?}) did not return captured error");
        };
        assert_eq!(parts[0], atom("error"));
        assert_eq!(parts[2], atom("badarith"));
        assert_eq!(parts[3], atom("math"));
        assert_eq!(parts[4], atom(function));
    }
}
