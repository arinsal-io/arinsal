mod support;

use arinsal_difftest::RefErl;
use arinsal_etf::OwnedTerm as O;
use support::{call, equivalent};

fn atom(name: &str) -> O {
    O::atom(name)
}

fn compare(reference: &RefErl, module: &str, name: &str, args: &[O]) {
    let actual = call(module, name, args);
    let expected = reference.call(module, name, args);
    assert!(
        equivalent(&actual, &expected),
        "{module}:{name} {args:?}: {actual:?} != {expected:?}"
    );
}

#[test]
fn key_bifs_match_otp_for_tuple_shapes_and_positions() {
    let reference = RefErl::start().expect("OTP 29 reference");
    let tuples2 = O::list(
        (1..=5)
            .map(|n| O::Tuple(vec![O::Int(n), atom("value")]))
            .collect(),
    );
    let tuples5 = O::list(
        (1..=5)
            .map(|n| O::Tuple(vec![O::Int(n), atom("a"), atom("b"), atom("c"), atom("d")]))
            .collect(),
    );

    for tuples in [tuples2, tuples5] {
        for key in [O::Int(1), O::Int(5), O::Int(99)] {
            for name in ["keyfind", "keymember", "keysearch"] {
                compare(
                    &reference,
                    "lists",
                    name,
                    &[key.clone(), O::Int(1), tuples.clone()],
                );
            }
        }
    }
}

#[test]
fn list_bifs_match_otp_for_equality_and_badarg_shapes() {
    let reference = RefErl::start().expect("OTP 29 reference");
    let nested_key = O::Tuple(vec![O::Int(7), atom("x")]);
    let boxed_key_list = O::list(vec![O::Tuple(vec![
        O::Tuple(vec![O::Int(7), atom("x")]),
        atom("value"),
    ])]);
    compare(
        &reference,
        "lists",
        "keyfind",
        &[nested_key.clone(), O::Int(1), boxed_key_list.clone()],
    );
    compare(
        &reference,
        "lists",
        "keysearch",
        &[nested_key, O::Int(1), boxed_key_list],
    );

    let improper = O::List {
        elems: vec![O::Int(1)],
        tail: Box::new(atom("tail")),
    };
    let cases: &[(&str, &str, Vec<O>)] = &[
        ("lists", "member", vec![O::Int(1), improper.clone()]),
        ("lists", "keyfind", vec![atom("k"), O::Int(0), O::Nil]),
        (
            "lists",
            "keyfind",
            vec![O::Int(9), O::Int(1), improper.clone()],
        ),
        (
            "lists",
            "keymember",
            vec![atom("k"), O::Int(1), improper.clone()],
        ),
        ("lists", "keysearch", vec![atom("k"), atom("pos"), O::Nil]),
        ("erlang", "length", vec![improper.clone()]),
        ("lists", "reverse", vec![improper, O::Nil]),
    ];
    for (module, name, args) in cases {
        compare(&reference, module, name, args);
    }
}
