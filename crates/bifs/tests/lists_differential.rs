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

// The erl_bif_lists.c BIFs are `bif_table` bodies in arinsal-vm and are compared there
// (crates/vm/tests/bifs/lists_bifs_differential.rs); `length/1` stays a body of this crate.
#[test]
fn length_matches_otp_for_improper_lists() {
    let reference = RefErl::start().expect("OTP 29 reference");
    let improper = O::List {
        elems: vec![O::Int(1)],
        tail: Box::new(atom("tail")),
    };
    compare(&reference, "erlang", "length", &[improper]);
}
