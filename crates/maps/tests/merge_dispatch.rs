use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_maps::{MapError, from_list, merge};
use arinsal_term::{Term, VecHeap, to_owned};

#[test]
fn merge_badmap_argument_order_matches_otp() {
    let reference = RefErl::start().expect("OTP 29.1.1 is required for this differential test");
    let invalid = OwnedTerm::Int(42);
    let empty = OwnedTerm::Map(Vec::new());
    let cases = [
        (invalid.clone(), empty.clone(), 42),
        (empty.clone(), invalid.clone(), 42),
        (invalid.clone(), invalid, 42),
    ];

    for (left, right, expected_badmap) in cases {
        let expected = reference.call("maps", "merge", &[left.clone(), right.clone()]);
        let CallResult::Exception { class, reason, .. } = expected else {
            panic!("maps:merge/2 should raise badmap: {expected:?}");
        };
        assert!(class == "error", "unexpected exception class: {class}");
        assert!(
            reason
                == OwnedTerm::Tuple(vec![
                    OwnedTerm::atom("badmap"),
                    OwnedTerm::Int(expected_badmap),
                ]),
            "unexpected OTP badmap reason: {reason:?}"
        );

        let mut heap = VecHeap::new();
        let rust_empty = from_list(&[], &mut heap).expect("empty flatmap");
        let rust_invalid = Term::small(expected_badmap).expect("small integer");
        let (rust_left, rust_right) = match (left, right) {
            (OwnedTerm::Int(_), OwnedTerm::Map(_)) => (rust_invalid, rust_empty),
            (OwnedTerm::Map(_), OwnedTerm::Int(_)) => (rust_empty, rust_invalid),
            _ => (rust_invalid, rust_invalid),
        };
        let Err(MapError::Badmap(badmap)) = merge(rust_left, rust_right, &mut heap) else {
            panic!("Arinsal should return the badmap argument");
        };
        assert!(to_owned(badmap).expect("badmap term") == OwnedTerm::Int(expected_badmap));
    }
}
