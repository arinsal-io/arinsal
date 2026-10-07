//! Numeric fast paths for decoded arithmetic instructions.

use arinsal_loader::FastBif;
use arinsal_term::{Term, small_add, small_mul, small_sub};

/// Tagged small arithmetic; a miss goes to the bound BIF.
// Port of erts/emulator/beam/erl_arith.c:166-244, OTP-29.1.1.
#[inline(always)]
pub(super) fn small(kind: FastBif, a: Term, b: Term) -> Option<Term> {
    match kind {
        FastBif::Add => small_add(a, b),
        FastBif::Sub => small_sub(a, b),
        FastBif::Mul => small_mul(a, b),
        FastBif::Band => small_bitwise(a, b, |x, y| x & y),
        FastBif::Bor => small_bitwise(a, b, |x, y| x | y),
        FastBif::Bxor => small_bitwise(a, b, |x, y| x ^ y),
        FastBif::Bsl => small_shift(a, b, true),
        FastBif::Bsr => small_shift(a, b, false),
        FastBif::None => None,
    }
}

#[inline(always)]
fn small_bitwise(a: Term, b: Term, operation: impl FnOnce(i64, i64) -> i64) -> Option<Term> {
    Term::small(operation(a.as_small()?, b.as_small()?))
}

#[inline(always)]
fn small_shift(value: Term, count: Term, left_operator: bool) -> Option<Term> {
    let value = value.as_small()?;
    let count = count.as_small()?;
    let shift_left = (count >= 0) == left_operator;
    let amount = count.unsigned_abs();
    if shift_left {
        if value == 0 {
            return Term::small(0);
        }
        if amount >= 60 {
            return None;
        }
        let result = i128::from(value) * (1_i128 << amount);
        Term::small(i64::try_from(result).ok()?)
    } else if amount >= 64 {
        Term::small(value >> 63)
    } else {
        Term::small(value >> amount)
    }
}

#[cfg(test)]
mod tests {
    use super::small;
    use arinsal_loader::FastBif;
    use arinsal_term::{MAX_SMALL, MIN_SMALL, Term, VecHeap, exact_eq};

    #[test]
    fn small_bitwise_and_shift_paths_match_arithmetic_bifs() {
        let values = [MIN_SMALL, -9, -2, -1, 0, 1, 2, 9, MAX_SMALL];
        for kind in [FastBif::Band, FastBif::Bor, FastBif::Bxor] {
            for left in values {
                for right in values {
                    compare_fast_with_bif(kind, left, right);
                }
            }
        }
        for left in values {
            for count in [-65, -60, -59, -1, 0, 1, 59, 60, 65] {
                compare_fast_with_bif(FastBif::Bsl, left, count);
                compare_fast_with_bif(FastBif::Bsr, left, count);
            }
        }
    }

    fn compare_fast_with_bif(kind: FastBif, left: i64, right: i64) {
        let a = Term::small(left).unwrap();
        let b = Term::small(right).unwrap();
        let mut heap = VecHeap::new();
        let expected = match kind {
            FastBif::Band => arinsal_arith::band(a, b, &mut heap),
            FastBif::Bor => arinsal_arith::bor(a, b, &mut heap),
            FastBif::Bxor => arinsal_arith::bxor(a, b, &mut heap),
            FastBif::Bsl => arinsal_arith::bsl(a, b, &mut heap),
            FastBif::Bsr => arinsal_arith::bsr(a, b, &mut heap),
            _ => unreachable!(),
        }
        .unwrap();
        match small(kind, a, b) {
            Some(actual) => assert!(exact_eq(actual, expected)),
            None => assert!(expected.as_small().is_none()),
        }
    }
}
