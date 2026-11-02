mod support;

use arinsal_bifs::{BifState, Ctx, ProcessHeapHandle, lookup};
use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm as O;
use arinsal_term::{ProcessHeap, Term, TermBuilder, to_owned};
use similar_asserts::assert_eq;
use support::call;

#[test]
fn binary_to_integer_aligned_and_unaligned_match_otp() {
    let reference = RefErl::shared().expect("OTP 29 reference");
    let cases = [
        (b"1234567".as_slice(), 10),
        (b"+00123".as_slice(), 10),
        (b"-000".as_slice(), 10),
        (b"7fffff".as_slice(), 16),
        (b"Bad".as_slice(), 16),
    ];
    for (bytes, base) in cases {
        let args = [O::Binary(bytes.to_vec()), O::Int(base)];
        let expected = reference.call("erts_internal", "binary_to_integer", &args);
        let actual = call("erts_internal", "binary_to_integer", &args);
        assert!(support::equivalent(&actual, &expected));
        assert_eq!(actual, expected, "binary={bytes:?}, base={base}");
    }

    let value = b"1234567";
    let mut shifted = [0_u8; 8];
    for bit in 0..value.len() * 8 {
        let set = (value[bit / 8] >> (7 - bit % 8)) & 1;
        let destination = bit + 1;
        shifted[destination / 8] |= set << (7 - destination % 8);
    }

    let mut heap = ProcessHeap::with_words(128);
    let mut allocator = ProcessHeapHandle(&mut heap);
    let backing = TermBuilder::new(&mut allocator)
        .binary(&shifted)
        .expect("backing binary");
    let unaligned = TermBuilder::new(&mut allocator)
        .sub_binary(backing, 1, value.len() * 8)
        .expect("unaligned byte-aligned subbinary");
    let bif = lookup("erts_internal", "binary_to_integer", 2).unwrap();
    let result = {
        let mut state = BifState::default();
        let mut ctx = Ctx::new(&mut allocator, &mut state);
        bif(&mut ctx, &[unaligned, Term::small(10).unwrap()]).unwrap()
    };
    let actual = to_owned(result).expect("integer result");
    let expected = reference.call(
        "erts_internal",
        "binary_to_integer",
        &[O::Binary(value.to_vec()), O::Int(10)],
    );
    assert_eq!(expected, CallResult::Ok(actual));
}
