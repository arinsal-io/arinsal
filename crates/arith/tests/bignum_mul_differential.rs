use arinsal_arith::mul;
use arinsal_difftest::RefErl;
use arinsal_etf::OwnedTerm;
use arinsal_term::{Term, TermBuilder, VecHeap, from_owned, to_owned};
use num_bigint::BigInt;

#[test]
fn bignum_multiplication_matches_otp_across_dispatch_paths() {
    let Ok(reference) = RefErl::shared() else {
        eprintln!("Skipping bignum multiplication differential: erl is unavailable");
        return;
    };

    for bits in [200_usize, 959, 1_023, 1_087, 4_095] {
        let value = (BigInt::from(1_u8) << bits) - 1_u8;
        for value in [value.clone(), -value] {
            let expression = format!("{value} * {value}");
            let expected = reference.eval(&expression).unwrap();
            let mut heap = VecHeap::new();
            let operand = TermBuilder::new(&mut heap).int_from_bigint(&value).unwrap();
            let actual = mul(operand, operand, &mut heap).unwrap();
            assert_same_integer(actual, expected, &expression);
        }
    }

    for (left, right) in [
        ((1_i64 << 58) - 1, 2),
        (1_i64 << 58, 2),
        (-(1_i64 << 58), 2),
        (-(1_i64 << 58), -2),
    ] {
        let expression = format!("{left} * {right}");
        let expected = reference.eval(&expression).unwrap();
        let mut heap = VecHeap::new();
        let left = Term::small(left).unwrap();
        let right = Term::small(right).unwrap();
        let actual = mul(left, right, &mut heap).unwrap();
        assert_same_integer(actual, expected, &expression);
    }

    let one_digit_left = (BigInt::from(1_u8) << 60_usize) + 17_u8;
    let one_digit_right = (BigInt::from(1_u8) << 63_usize) - 5_u8;
    let expression = format!("{one_digit_left} * {one_digit_right}");
    let expected = reference.eval(&expression).unwrap();
    let mut heap = VecHeap::new();
    let left = TermBuilder::new(&mut heap)
        .int_from_bigint(&one_digit_left)
        .unwrap();
    let right = TermBuilder::new(&mut heap)
        .int_from_bigint(&one_digit_right)
        .unwrap();
    let actual = mul(left, right, &mut heap).unwrap();
    assert_same_integer(actual, expected, &expression);

    let schoolbook_left = (BigInt::from(1_u8) << 200_usize) - 1_u8;
    let schoolbook_right = (BigInt::from(1_u8) << 128_usize) + 0xdead_beef_u64;
    let expression = format!("{schoolbook_left} * {schoolbook_right}");
    let expected = reference.eval(&expression).unwrap();
    let mut heap = VecHeap::new();
    let left = TermBuilder::new(&mut heap)
        .int_from_bigint(&schoolbook_left)
        .unwrap();
    let right = TermBuilder::new(&mut heap)
        .int_from_bigint(&schoolbook_right)
        .unwrap();
    let actual = mul(left, right, &mut heap).unwrap();
    assert_same_integer(actual, expected, &expression);

    let value = (BigInt::from(1_u8) << 1_023) - 1_u8;
    let other: BigInt = (BigInt::from(1_u8) << 1_022_usize) + 0xdead_beef_u64;
    let expression = format!("{value} * (-{other})");
    let expected = reference.eval(&expression).unwrap();
    let mut heap = VecHeap::new();
    let left = TermBuilder::new(&mut heap).int_from_bigint(&value).unwrap();
    let right = TermBuilder::new(&mut heap)
        .int_from_bigint(&-other)
        .unwrap();
    let actual = mul(left, right, &mut heap).unwrap();
    assert_same_integer(actual, expected, &expression);

    let large = (BigInt::from(1_u8) << 200) + 17_u8;
    for small in [-3, -1, 0, 1, 2] {
        let expression = format!("{large} * {small}");
        let expected = reference.eval(&expression).unwrap();
        let mut heap = VecHeap::new();
        let big = TermBuilder::new(&mut heap).int_from_bigint(&large).unwrap();
        let small = Term::small(small).unwrap();
        let actual = mul(big, small, &mut heap).unwrap();
        assert_same_integer(actual, expected, &expression);
    }

    for (left, right) in [(1, 1), (0, i64::MIN), (i64::MIN, -1), (i64::MAX, i64::MAX)] {
        let expression = format!("{left} * {right}");
        let expected = reference.eval(&expression).unwrap();
        let mut heap = VecHeap::new();
        let left = from_owned(&OwnedTerm::Int(left), &mut heap).unwrap();
        let right = from_owned(&OwnedTerm::Int(right), &mut heap).unwrap();
        let actual = mul(left, right, &mut heap).unwrap();
        assert_same_integer(actual, expected, &expression);
    }
}

fn assert_same_integer(actual: Term, expected: OwnedTerm, expression: &str) {
    fn value(term: &OwnedTerm) -> BigInt {
        match term {
            OwnedTerm::Int(value) => BigInt::from(*value),
            OwnedTerm::BigInt(value) => value.clone(),
            other => panic!("expected integer, got {other:?}"),
        }
    }

    similar_asserts::assert_eq!(
        value(&to_owned(actual).unwrap()),
        value(&expected),
        "{expression}"
    );
}
