mod support;

use arinsal_difftest::RefErl;
use arinsal_etf::OwnedTerm as O;
use num_bigint::BigInt;
use support::{call, equivalent};

#[test]
fn bignum_integer_to_list_matches_otp() {
    let reference = RefErl::shared().expect("OTP 29 reference");
    let values = [
        BigInt::from(1u8) << 64,
        -(BigInt::from(1u8) << 127usize) + BigInt::from(17),
        (BigInt::from(1u8) << 511) + 0xdead_beef_u64,
    ];
    for value in values {
        for base in [2, 8, 10, 16, 36] {
            let args = [O::BigInt(value.clone()), O::Int(base)];
            let actual = call("erlang", "integer_to_list", &args);
            let expected = reference.call("erlang", "integer_to_list", &args);
            assert!(
                equivalent(&actual, &expected),
                "integer_to_list({value}, {base}): {actual:?} != {expected:?}"
            );
        }
    }
}
