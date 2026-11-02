//! In-place multiplication of the little-endian digits stored in boxed integers.

use crate::heap::{load, store};
use arinsal_alloc::typed::{AllocBlock, ErtsAlcType};

#[derive(Clone, Copy)]
struct Digits {
    ptr: *const u64,
    len: usize,
}

impl Digits {
    #[inline(always)]
    fn from_slice(words: &[u64]) -> Self {
        Self {
            ptr: words.as_ptr(),
            len: words.len(),
        }
    }

    #[inline(always)]
    fn from_raw(ptr: *const u64, len: usize) -> Self {
        Self { ptr, len }
    }

    #[inline(always)]
    fn get(self, index: usize) -> u64 {
        debug_assert!(index < self.len);
        load(self.ptr.wrapping_add(index))
    }

    #[inline(always)]
    fn subslice(self, start: usize, len: usize) -> Self {
        debug_assert!(start <= self.len && len <= self.len - start);
        Self::from_raw(self.ptr.wrapping_add(start), len)
    }
}

// Port of erts/emulator/beam/big.c (DSUMc), OTP-29.1.1.
#[inline(always)]
fn sum_c(a: u64, b: u64, carry: u64) -> (u64, u64) {
    let (sum, carry_a) = a.overflowing_add(carry);
    let (sum, carry_b) = sum.overflowing_add(b);
    (sum, u64::from(carry_a) + u64::from(carry_b))
}

// Port of erts/emulator/beam/big.c (DMULc), OTP-29.1.1.
#[inline(always)]
fn mul_c(a: u64, b: u64, carry: u64) -> (u64, u64) {
    let product = (a as u128) * (b as u128) + carry as u128;
    (product as u64, (product >> 64) as u64)
}

// Port of erts/emulator/beam/big.c (DMUL), OTP-29.1.1.
#[inline(always)]
fn mul_full(a: u64, b: u64) -> (u64, u64) {
    let product = (a as u128) * (b as u128);
    (product as u64, (product >> 64) as u64)
}

// Port of erts/emulator/beam/big.c (D_mul), OTP-29.1.1.
#[inline]
fn d_mul(x: Digits, digit: u64, r: *mut u64) -> usize {
    let mut carry = 0;

    match digit {
        0 => {
            store(r, 0);
            return 1;
        }
        1 => {
            if x.ptr != r.cast_const() {
                for index in 0..x.len {
                    store(r.wrapping_add(index), x.get(index));
                }
            }
            return x.len;
        }
        2 => {
            for index in 0..x.len {
                let (product, next_carry) = sum_c(x.get(index), x.get(index), carry);
                store(r.wrapping_add(index), product);
                carry = next_carry;
            }
        }
        _ => {
            for index in 0..x.len {
                let (product, next_carry) = mul_c(digit, x.get(index), carry);
                store(r.wrapping_add(index), product);
                carry = next_carry;
            }
        }
    }

    if carry == 0 {
        x.len
    } else {
        store(r.wrapping_add(x.len), carry);
        x.len + 1
    }
}

// Port of erts/emulator/beam/big.c (I_mul), OTP-29.1.1.
#[inline]
fn i_mul(x: Digits, y: Digits, r: *mut u64) -> usize {
    debug_assert!(x.len >= y.len);
    for index in 0..x.len {
        store(r.wrapping_add(index), 0);
    }

    let mut last = r;
    for x_index in 0..x.len {
        let digit = x.get(x_index);
        let mut carry_product = 0;
        let mut carry_sum = 0;
        let mut output = r.wrapping_add(x_index);

        match digit {
            0 => output = output.wrapping_add(y.len),
            1 => {
                for y_index in 0..y.len {
                    let (product, next_carry) = sum_c(y.get(y_index), load(output), carry_sum);
                    store(output, product);
                    output = output.wrapping_add(1);
                    carry_sum = next_carry;
                }
            }
            2 => {
                for y_index in 0..y.len {
                    let (doubled, next_carry_product) =
                        sum_c(y.get(y_index), y.get(y_index), carry_product);
                    let (product, next_carry_sum) = sum_c(doubled, load(output), carry_sum);
                    store(output, product);
                    output = output.wrapping_add(1);
                    carry_product = next_carry_product;
                    carry_sum = next_carry_sum;
                }
            }
            _ => {
                for y_index in 0..y.len {
                    let (partial, next_carry_product) = mul_c(digit, y.get(y_index), carry_product);
                    let (product, next_carry_sum) = sum_c(partial, load(output), carry_sum);
                    store(output, product);
                    output = output.wrapping_add(1);
                    carry_product = next_carry_product;
                    carry_sum = next_carry_sum;
                }
            }
        }

        store(output, carry_sum + carry_product);
        last = output;
    }

    let size = x.len + y.len - 1;
    if load(last) == 0 { size } else { size + 1 }
}

// Port of erts/emulator/beam/big.c (I_sqr), OTP-29.1.1.
#[inline]
fn i_sqr(x: Digits, r: *mut u64) -> usize {
    let mut remaining = x.len;
    let mut input_index = 0;
    let mut output_offset = 0;
    let mut last_index = 0;

    for index in 0..x.len + 1 {
        store(r.wrapping_add(index), 0);
    }

    while remaining != 0 {
        remaining -= 1;
        let mut cross_terms = remaining;
        let digit = x.get(input_index);
        input_index += 1;
        last_index = output_offset;

        if digit == 0 {
            last_index += cross_terms + 1;
            if remaining != 0 {
                last_index += 1;
                store(r.wrapping_add(last_index), 0);
                output_offset += 2;
            }
        } else {
            let mut carry0 = 0;
            let mut carry1 = 0;
            let mut carry2 = 0;
            let mut carry3 = 0;
            let (lower, upper) = mul_full(digit, digit);

            let (value, next_carry3) = sum_c(load(r.wrapping_add(last_index)), lower, carry3);
            store(r.wrapping_add(last_index), value);
            last_index += 1;
            carry3 = next_carry3;
            let mut high_sum = upper;

            let mut y_index = input_index;
            while cross_terms != 0 {
                let (product_low, product_high) = mul_full(digit, x.get(y_index));
                y_index += 1;
                let (doubled_low, next_carry0) = sum_c(product_low, product_low, carry0);
                let (middle, next_carry2) = sum_c(doubled_low, high_sum, carry2);
                let (value, next_carry3) = sum_c(load(r.wrapping_add(last_index)), middle, carry3);
                store(r.wrapping_add(last_index), value);
                last_index += 1;
                let (next_high_sum, next_carry1) = sum_c(product_high, product_high, carry1);
                carry0 = next_carry0;
                carry1 = next_carry1;
                carry2 = next_carry2;
                carry3 = next_carry3;
                high_sum = next_high_sum;
                cross_terms -= 1;
            }

            let (middle, next_carry2) = sum_c(carry0, high_sum, carry2);
            let (value, next_carry3) = sum_c(load(r.wrapping_add(last_index)), middle, carry3);
            store(r.wrapping_add(last_index), value);
            carry2 = next_carry2;
            carry3 = next_carry3;

            if remaining != 0 {
                last_index += 1;
                store(
                    r.wrapping_add(last_index),
                    carry1.wrapping_add(carry2).wrapping_add(carry3),
                );
                output_offset += 2;
            } else {
                debug_assert_eq!(carry1.wrapping_add(carry2).wrapping_add(carry3), 0);
            }
        }
    }

    if load(r.wrapping_add(last_index)) == 0 {
        last_index
    } else {
        last_index + 1
    }
}

// Port of erts/emulator/beam/big.c (I_comp), OTP-29.1.1.
fn i_comp(x: Digits, y: Digits) -> std::cmp::Ordering {
    match x.len.cmp(&y.len) {
        std::cmp::Ordering::Equal if x.ptr == y.ptr => std::cmp::Ordering::Equal,
        std::cmp::Ordering::Equal => (0..x.len)
            .rev()
            .map(|index| x.get(index).cmp(&y.get(index)))
            .find(|order| *order != std::cmp::Ordering::Equal)
            .unwrap_or(std::cmp::Ordering::Equal),
        order => order,
    }
}

// Port of erts/emulator/beam/big.c (I_add), OTP-29.1.1.
fn i_add(x: Digits, y: Digits, r: *mut u64) -> usize {
    debug_assert!(x.len >= y.len);
    debug_assert!(y.len != 0);
    let mut carry = 0;

    for index in 0..y.len {
        let (sum, next_carry) = sum_c(x.get(index), y.get(index), carry);
        store(r.wrapping_add(index), sum);
        carry = next_carry;
    }
    for index in y.len..x.len {
        let (sum, next_carry) = x.get(index).overflowing_add(carry);
        store(r.wrapping_add(index), sum);
        carry = u64::from(next_carry);
    }
    if carry != 0 {
        store(r.wrapping_add(x.len), 1);
        x.len + 1
    } else {
        x.len
    }
}

// Port of erts/emulator/beam/big.c (I_sub), OTP-29.1.1.
fn i_sub(x: Digits, y: Digits, r: *mut u64) -> usize {
    debug_assert!(i_comp(x, y) != std::cmp::Ordering::Less);
    debug_assert!(y.len != 0);
    let mut borrow = 0;

    for index in 0..y.len {
        let y_digit = y.get(index).wrapping_add(borrow);
        let mut next_borrow = u64::from(y_digit < borrow);
        let x_digit = x.get(index);
        let difference = x_digit.wrapping_sub(y_digit);
        next_borrow += u64::from(difference > x_digit);
        store(r.wrapping_add(index), difference);
        borrow = next_borrow;
    }
    for index in y.len..x.len {
        let x_digit = x.get(index);
        let difference = x_digit.wrapping_sub(borrow);
        borrow = u64::from(difference > x_digit);
        store(r.wrapping_add(index), difference);
    }

    let mut size = x.len;
    while size > 1 && load(r.wrapping_add(size - 1)) == 0 {
        size -= 1;
    }
    size
}

// Port of I_OPERATION in erts/emulator/beam/big.c (I_mul_karatsuba), OTP-29.1.1.
#[inline]
fn i_mul_operation(x: Digits, y: Digits, r: *mut u64) -> usize {
    if x.len >= y.len {
        i_mul_karatsuba(x, y, r)
    } else {
        i_mul_karatsuba(y, x, r)
    }
}

// Port of erts/emulator/beam/big.c (I_mul_karatsuba), OTP-29.1.1.
fn i_mul_karatsuba(x: Digits, y: Digits, r: *mut u64) -> usize {
    debug_assert!(x.len >= y.len);
    debug_assert!(x.len == 1 || x.get(x.len - 1) != 0);
    debug_assert!(y.len == 1 || y.get(y.len - 1) != 0);

    if y.len < 16 {
        if x.ptr == y.ptr && x.len > 1 {
            debug_assert_eq!(x.len, y.len);
            return i_sqr(x, r);
        }
        return i_mul(x, y, r);
    }

    let m = x.len.div_ceil(2);
    let mut low_x_len = m;
    while low_x_len > 1 && x.get(low_x_len - 1) == 0 {
        low_x_len -= 1;
    }
    let low_x = x.subslice(0, low_x_len);
    let high_x = x.subslice(m, x.len - m);

    let zero = [0_u64];
    let (mut low_y, high_y, high_y_is_zero) = if y.len <= m {
        (y, Digits::from_slice(&zero), true)
    } else {
        (y.subslice(0, m), y.subslice(m, y.len - m), false)
    };
    let mut low_y_len = low_y.len;
    while low_y_len > 1 && low_y.get(low_y_len - 1) == 0 {
        low_y_len -= 1;
    }
    low_y = low_y.subslice(0, low_y_len);

    let scratch_words = 4 * m + 1;
    let mut scratch = AllocBlock::new(ErtsAlcType::TMP, scratch_words)
        .expect("ERTS bignum scratch allocation failed");
    let scratch = scratch.as_mut_ptr();
    let z1 = scratch;
    let diff0 = scratch.wrapping_add(1);
    let diff1 = diff0.wrapping_add(m);
    let tmp = diff1.wrapping_add(m);
    let z0 = r;
    let z2 = r.wrapping_add(2 * m);

    let mut z0_len = i_mul_operation(low_x, low_y, z0);
    for index in z0_len..2 * m {
        store(z0.wrapping_add(index), 0);
    }
    while z0_len > 1 && load(z0.wrapping_add(z0_len - 1)) == 0 {
        z0_len -= 1;
    }

    let z2_len = if high_y_is_zero {
        store(z2, 0);
        1
    } else {
        let mut len = i_mul_operation(high_x, high_y, z2);
        while len > 1 && load(z2.wrapping_add(len - 1)) == 0 {
            len -= 1;
        }
        len
    };

    let mut tmp_product_negative = false;
    let diff0_len = if i_comp(low_x, high_x) != std::cmp::Ordering::Less {
        i_sub(low_x, high_x, diff0)
    } else {
        tmp_product_negative = true;
        i_sub(high_x, low_x, diff0)
    };

    let (diff1_ptr, diff1_len) = if x.ptr == y.ptr {
        debug_assert_eq!(x.len, y.len);
        tmp_product_negative = true;
        (diff0.cast_const(), diff0_len)
    } else if i_comp(high_y, low_y) != std::cmp::Ordering::Less {
        (diff1.cast_const(), i_sub(high_y, low_y, diff1))
    } else {
        tmp_product_negative = !tmp_product_negative;
        if high_y_is_zero {
            (low_y.ptr, low_y.len)
        } else {
            (diff1.cast_const(), i_sub(low_y, high_y, diff1))
        }
    };
    let diff0 = Digits::from_raw(diff0.cast_const(), diff0_len);
    let diff1 = Digits::from_raw(diff1_ptr, diff1_len);

    let mut tmp_len = i_mul_operation(diff0, diff1, tmp);
    while tmp_len > 1 && load(tmp.wrapping_add(tmp_len - 1)) == 0 {
        tmp_len -= 1;
    }

    let z0_digits = Digits::from_raw(z0.cast_const(), z0_len);
    let z2_digits = Digits::from_raw(z2.cast_const(), z2_len);
    let mut z1_len = i_add_operation(z0_digits, z2_digits, z1);
    let z1_digits = Digits::from_raw(z1.cast_const(), z1_len);
    let tmp_digits = Digits::from_raw(tmp.cast_const(), tmp_len);
    z1_len = if tmp_product_negative {
        i_sub(z1_digits, tmp_digits, z1)
    } else {
        i_add_operation(z1_digits, tmp_digits, z1)
    };

    let z0_upper = Digits::from_raw(z0.wrapping_add(m).cast_const(), z2_len + m);
    let z1_digits = Digits::from_raw(z1.cast_const(), z1_len);
    let mut result_len = i_add_operation(z0_upper, z1_digits, z0.wrapping_add(m));
    result_len += m;
    while result_len > 1 && load(r.wrapping_add(result_len - 1)) == 0 {
        result_len -= 1;
    }

    result_len
}

// Port of I_OPERATION in erts/emulator/beam/big.c (I_mul_karatsuba), OTP-29.1.1.
fn i_add_operation(x: Digits, y: Digits, r: *mut u64) -> usize {
    if x.len >= y.len {
        i_add(x, y, r)
    } else {
        i_add(y, x, r)
    }
}

// Port of erts/emulator/beam/big.c (big_times), OTP-29.1.1.
pub(crate) fn times_into(x: &[u64], y: &[u64], r: *mut u64) -> usize {
    let x = Digits::from_slice(x);
    let y = Digits::from_slice(y);
    if y.len == 1 {
        d_mul(x, y.get(0), r)
    } else if x.len == 1 {
        d_mul(y, x.get(0), r)
    } else {
        i_mul_operation(x, y, r)
    }
}

#[cfg(test)]
mod tests {
    use super::{Digits, i_sqr};
    use num_bigint::{BigInt, Sign};

    #[test]
    fn square_matches_bigint_for_dense_and_sparse_digits() {
        let cases = [
            vec![u64::MAX],
            vec![u64::MAX; 2],
            vec![u64::MAX; 3],
            vec![u64::MAX; 4],
            vec![0, 0, 0, 0xff],
        ];
        for digits in cases {
            let bytes = digits
                .iter()
                .flat_map(|digit| digit.to_le_bytes())
                .collect::<Vec<_>>();
            let input = BigInt::from_bytes_le(Sign::Plus, &bytes);
            let expected = (input.clone() * input).to_u64_digits().1;
            let mut output = [u64::MAX; 16];
            let size = i_sqr(Digits::from_slice(&digits), output.as_mut_ptr());
            similar_asserts::assert_eq!(&output[..size], expected.as_slice());
        }
    }
}
