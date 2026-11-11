mod support;

use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm as O;
use similar_asserts::assert_eq;
use support::{call, equivalent};

const UNARY: &[&str] = &[
    "sin", "cos", "tan", "asin", "acos", "atan", "sinh", "cosh", "tanh", "asinh", "acosh", "atanh",
    "erf", "erfc", "exp", "log", "log2", "log10", "sqrt", "ceil", "floor",
];
const BINARY: &[&str] = &["atan2", "pow", "fmod"];

fn inputs() -> Vec<f64> {
    let mut values = vec![
        0.0,
        -0.0,
        f64::from_bits(1),
        -f64::from_bits(1),
        f64::MIN_POSITIVE,
        -f64::MIN_POSITIVE,
        1.0,
        -1.0,
        2.0,
        -2.0,
        f64::MAX,
        -f64::MAX,
        f64::from_bits(0x3fefffffffffffff),
        -f64::from_bits(0x3fefffffffffffff),
        f64::from_bits(0x3ff0000000000001),
        -f64::from_bits(0x3ff0000000000001),
        std::f64::consts::FRAC_PI_2,
        -std::f64::consts::FRAC_PI_2,
        std::f64::consts::PI,
        709.0,
        -745.0,
    ];
    let mut state = 0x8f3d_9a21_4c76_b5e1_u64;
    while values.len() < 2000 {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let exponent = ((state >> 52) % 2040) + 3;
        let bits = (state & (1_u64 << 63)) | (exponent << 52) | (state & ((1_u64 << 52) - 1));
        values.push(f64::from_bits(bits));
    }
    values
}

fn as_args(function: &str, values: &[f64], index: usize) -> Vec<O> {
    let x = values[index];
    if BINARY.contains(&function) {
        let y = values[(index * 7919 + 37) % values.len()];
        vec![O::Float(x), O::Float(y)]
    } else {
        vec![O::Float(x)]
    }
}

fn assert_same(actual: CallResult, expected: CallResult, function: &str, args: &[O]) {
    assert!(equivalent(&actual, &expected), "math:{function} {args:?}");
    match (actual, expected) {
        (CallResult::Ok(O::Float(a)), CallResult::Ok(O::Float(b))) => {
            assert_eq!(a.to_bits(), b.to_bits(), "math:{function} {args:?}");
        }
        (
            CallResult::Exception {
                class: a,
                reason: ar,
                ..
            },
            CallResult::Exception {
                class: b,
                reason: br,
                ..
            },
        ) => {
            assert_eq!((a, ar), (b, br), "math:{function} {args:?}");
        }
        (actual, expected) => assert_eq!(actual, expected, "math:{function} {args:?}"),
    }
}

#[test]
fn math_bifs_match_otp_libm_bits_and_errors() {
    let reference = match RefErl::start() {
        Ok(reference) => reference,
        Err(error) => {
            eprintln!("skipping libm differential test: erl unavailable: {error}");
            return;
        }
    };
    let values = inputs();
    for function in UNARY.iter().chain(BINARY) {
        let arguments = (0..2000)
            .map(|index| as_args(function, &values, index))
            .collect::<Vec<_>>();
        let calls = arguments
            .iter()
            .map(|args| ("math", *function, args.clone()))
            .collect::<Vec<_>>();
        let expected = reference.call_batch(&calls);
        assert_eq!(expected.len(), arguments.len());
        for (args, expected) in arguments.iter().zip(expected) {
            assert_same(call("math", function, args), expected, function, args);
        }
    }
}
