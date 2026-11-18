//! Fused quotient/remainder over the little-endian digits of boxed integers.
// Port of erts/emulator/beam/big.c (D_div, I_div, I_div_bz, I_div_dispatch,
// big_div_rem), OTP-29.1.1.

use arinsal_alloc::typed::{AllocBlock, ErtsAlcType};

const DIGIT_BITS: usize = 64;
const BZ_DIV_THRESHOLD: usize = 8;
const BZ_DIV_QUOTIENT_THRESHOLD: usize = 64;

#[inline(always)]
fn load(ptr: *const u64, index: usize) -> u64 {
    crate::heap::load(ptr.wrapping_add(index))
}

#[inline(always)]
fn store(ptr: *mut u64, index: usize, value: u64) {
    crate::heap::store(ptr.wrapping_add(index), value);
}

fn compare(x: *const u64, xl: usize, y: *const u64, yl: usize) -> std::cmp::Ordering {
    match xl.cmp(&yl) {
        std::cmp::Ordering::Equal => {
            for index in (0..xl).rev() {
                match load(x, index).cmp(&load(y, index)) {
                    std::cmp::Ordering::Equal => {}
                    order => return order,
                }
            }
            std::cmp::Ordering::Equal
        }
        order => order,
    }
}

// Port of erts/emulator/beam/big.c:I_sub, OTP-29.1.1.
fn subtract(x: *const u64, xl: usize, y: *const u64, yl: usize, result: *mut u64) -> usize {
    debug_assert!(compare(x, xl, y, yl) != std::cmp::Ordering::Less);
    let mut borrow = 0_u64;
    for index in 0..yl {
        let y_digit = load(y, index).wrapping_add(borrow);
        let mut next_borrow = u64::from(y_digit < borrow);
        let x_digit = load(x, index);
        let difference = x_digit.wrapping_sub(y_digit);
        next_borrow += u64::from(difference > x_digit);
        store(result, index, difference);
        borrow = next_borrow;
    }
    for index in yl..xl {
        let x_digit = load(x, index);
        let difference = x_digit.wrapping_sub(borrow);
        borrow = u64::from(difference > x_digit);
        store(result, index, difference);
    }
    let mut size = xl;
    while size > 1 && load(result, size - 1) == 0 {
        size -= 1;
    }
    size
}

fn subtract_digit(x: *const u64, xl: usize, digit: u64, result: *mut u64) -> usize {
    let mut borrow = digit;
    for index in 0..xl {
        let value = load(x, index);
        let difference = value.wrapping_sub(borrow);
        borrow = u64::from(difference > value);
        store(result, index, difference);
    }
    let mut size = xl;
    while size > 1 && load(result, size - 1) == 0 {
        size -= 1;
    }
    size
}

fn zero_subtract(y: *const u64, yl: usize, result: *mut u64) -> usize {
    let mut borrow = 0_u64;
    for index in 0..yl {
        let digit = load(y, index).wrapping_add(borrow);
        borrow = u64::from(digit < borrow);
        let difference = 0_u64.wrapping_sub(digit);
        borrow += u64::from(difference > 0);
        store(result, index, difference);
    }
    let mut size = yl;
    while size > 1 && load(result, size - 1) == 0 {
        size -= 1;
    }
    size
}

// Port of erts/emulator/beam/big.c:D_mulsub, OTP-29.1.1.
fn multiply_subtract(
    x: *const u64,
    xl: usize,
    digit: u64,
    y: *const u64,
    yl: usize,
    result: *mut u64,
) -> usize {
    debug_assert!(xl == yl || xl == yl + 1);
    let mut carry = 0_u64;
    let mut borrow = 0_u64;
    for index in 0..yl {
        let product = (digit as u128) * (load(y, index) as u128) + carry as u128;
        carry = (product >> 64) as u64;
        let x_digit = load(x, index);
        let subtrahend = product as u64;
        let first = x_digit.wrapping_sub(subtrahend);
        let borrow_a = u64::from(first > x_digit);
        let value = first.wrapping_sub(borrow);
        let borrow_b = u64::from(value > first);
        store(result, index, value);
        borrow = borrow_a + borrow_b;
    }
    if xl == yl {
        if carry != 0 || borrow != 0 {
            return 0;
        }
    } else {
        let x_digit = load(x, yl);
        let value = x_digit.wrapping_sub(carry).wrapping_sub(borrow);
        borrow = u64::from(value > x_digit);
        store(result, yl, value);
    }
    if borrow != 0 {
        return 0;
    }
    let mut size = xl;
    while size > 1 && load(result, size - 1) == 0 {
        size -= 1;
    }
    size
}

// Port of erts/emulator/beam/big.c:D_div, OTP-29.1.1.
fn divide_digit(x: *const u64, xl: usize, divisor: u64, q: *mut u64, r: *mut u64) -> usize {
    debug_assert_ne!(divisor, 0);
    let mut remainder = 0_u64;
    for index in (0..xl).rev() {
        let numerator = ((remainder as u128) << 64) | load(x, index) as u128;
        store(q, index, (numerator / divisor as u128) as u64);
        remainder = (numerator % divisor as u128) as u64;
    }
    store(r, 0, remainder);
    let mut size = xl;
    while size > 1 && load(q, size - 1) == 0 {
        size -= 1;
    }
    size
}

// Port of erts/emulator/beam/big.c:I_div, OTP-29.1.1.
fn divide_digits(
    x: *const u64,
    xl: usize,
    y: *const u64,
    yl: usize,
    q: *mut u64,
    r: *mut u64,
    remainder_size: &mut usize,
) -> usize {
    debug_assert!(yl >= 2);
    debug_assert!(xl >= yl);
    if x != r.cast_const() {
        for index in 0..xl {
            store(r, index, load(x, index));
        }
    }
    let mut rp = r.wrapping_add(xl - yl);
    let mut qp = q.wrapping_add(xl - yl);
    let mut q_size = 0_usize;
    let mut r_size = xl;
    let divisor_high = load(y, yl - 1);
    let divisor_next = load(y, yl - 2);
    for index in 0..(xl - yl + 1) {
        store(q, index, 0);
    }
    let first_high = load(rp, yl - 1);
    let first_next = load(rp, yl - 2);
    if divisor_high < first_high || (divisor_high == first_high && divisor_next <= first_next) {
        q_size = 1;
    }
    let mut remainder_negative = false;
    while compare(r, r_size, y, yl) != std::cmp::Ordering::Less {
        let mut numerator_size = yl;
        let high = load(rp, yl - 1);
        let next = load(rp, yl - 2);
        let quotient_digit = if divisor_high < high {
            let numerator = ((high as u128) << 64) | next as u128;
            (numerator / (((divisor_high as u128) << 64) | divisor_next as u128)) as u64
        } else if divisor_high > high {
            let numerator = ((high as u128) << 64) | next as u128;
            let digit = (numerator / divisor_high as u128) as u64;
            numerator_size += 1;
            rp = rp.wrapping_sub(1);
            qp = qp.wrapping_sub(1);
            q_size += 1;
            digit
        } else if divisor_next <= next {
            1
        } else {
            numerator_size += 1;
            rp = rp.wrapping_sub(1);
            qp = qp.wrapping_sub(1);
            q_size += 1;
            u64::MAX
        };

        q_size = if remainder_negative {
            subtract_digit(qp, q_size, quotient_digit, qp)
        } else {
            let mut carry = quotient_digit;
            let mut index = 0;
            while carry != 0 {
                let (sum, next_carry) = load(qp, index).overflowing_add(carry);
                store(qp, index, sum);
                carry = u64::from(next_carry);
                index += 1;
            }
            q_size.max(index)
        };

        let reduced = multiply_subtract(rp, numerator_size, quotient_digit, y, yl, rp);
        let normalized_size = if reduced == 0 {
            let difference_size = zero_subtract(r, r_size, r);
            if numerator_size > r_size - difference_size {
                numerator_size - (r_size - difference_size)
            } else {
                1
            }
        } else {
            reduced
        };
        if reduced == 0 {
            remainder_negative = !remainder_negative;
        }
        let normalized_size = if normalized_size == 1 && load(rp, 0) == 0 {
            0
        } else {
            normalized_size
        };
        let adjust = yl - normalized_size;
        rp = rp.wrapping_sub(adjust);
        r_size -= numerator_size - normalized_size;
        qp = qp.wrapping_sub(adjust);
        q_size += adjust;
    }

    if qp as usize >= q as usize {
        q_size += (qp as usize - q as usize) / std::mem::size_of::<u64>();
    } else {
        q_size -= (q as usize - qp as usize) / std::mem::size_of::<u64>();
    }
    if r_size == 0 {
        r_size = 1;
    }
    while r_size > 1 && load(r, r_size - 1) == 0 {
        r_size -= 1;
    }
    if remainder_negative && (r_size > 1 || load(r, 0) != 0) {
        r_size = subtract(y, yl, r, r_size, r);
        q_size = subtract_digit(q, q_size, 1, q);
    }
    *remainder_size = r_size;
    q_size
}

// Port of erts/emulator/beam/big.c:I_lshift, OTP-29.1.1.
fn shift_digits(x: *const u64, xl: usize, shift: isize, result: *mut u64) -> usize {
    if shift == 0 {
        for index in 0..xl {
            store(result, index, load(x, index));
        }
        return xl;
    }
    if xl == 1 && load(x, 0) == 0 {
        store(result, 0, 0);
        return 1;
    }
    let amount = shift.unsigned_abs();
    let whole = amount / DIGIT_BITS;
    let part = amount % DIGIT_BITS;
    if shift > 0 {
        for index in 0..whole {
            store(result, index, 0);
        }
        let mut carry = 0_u64;
        for index in 0..xl {
            let digit = load(x, index);
            store(
                result,
                whole + index,
                if part == 0 {
                    digit
                } else {
                    (digit << part) | carry
                },
            );
            carry = if part == 0 {
                0
            } else {
                digit >> (DIGIT_BITS - part)
            };
        }
        if carry == 0 {
            xl + whole
        } else {
            store(result, xl + whole, carry);
            xl + whole + 1
        }
    } else if xl <= whole {
        store(result, 0, 0);
        1
    } else {
        let len = xl - whole;
        let mut carry = 0_u64;
        for index in (0..len).rev() {
            let digit = load(x, whole + index);
            store(
                result,
                index,
                if part == 0 {
                    digit
                } else {
                    (digit >> part) | carry
                },
            );
            carry = if part == 0 {
                0
            } else {
                digit << (DIGIT_BITS - part)
            };
        }
        let mut len = len;
        while len > 1 && load(result, len - 1) == 0 {
            len -= 1;
        }
        len
    }
}

fn fixed_compare(x: *const u64, y: *const u64, len: usize) -> std::cmp::Ordering {
    compare(x, len, y, len)
}

fn fixed_add(x: *const u64, y: *const u64, result: *mut u64, len: usize) -> u64 {
    let mut carry = 0_u64;
    for index in 0..len {
        let (sum, carry_a) = load(x, index).overflowing_add(carry);
        let (sum, carry_b) = sum.overflowing_add(load(y, index));
        store(result, index, sum);
        carry = u64::from(carry_a) + u64::from(carry_b);
    }
    carry
}

fn fixed_subtract(x: *const u64, y: *const u64, result: *mut u64, len: usize) -> u64 {
    let mut borrow = 0_u64;
    for index in 0..len {
        let y_digit = load(y, index).wrapping_add(borrow);
        let mut next_borrow = u64::from(y_digit < borrow);
        let x_digit = load(x, index);
        let difference = x_digit.wrapping_sub(y_digit);
        next_borrow += u64::from(difference > x_digit);
        store(result, index, difference);
        borrow = next_borrow;
    }
    borrow
}

fn scratch_size_2n_1n(n: usize) -> usize {
    if n < BZ_DIV_THRESHOLD {
        n + 2 + 2 * n
    } else {
        6 * n + scratch_size_2n_1n(n / 2)
    }
}

// Port of erts/emulator/beam/big.c:bz_div_2n_1n, OTP-29.1.1.
fn div_2n_1n(
    value: *mut u64,
    divisor: *const u64,
    n: usize,
    quotient: *mut u64,
    remainder: *mut u64,
    scratch: *mut u64,
) {
    if n < BZ_DIV_THRESHOLD || n & 1 != 0 {
        let quotient_buffer = scratch;
        let remainder_buffer = scratch.wrapping_add(n + 1);
        let mut remainder_size = 0;
        let quotient_size = divide_digits(
            value,
            2 * n,
            divisor,
            n,
            quotient_buffer,
            remainder_buffer,
            &mut remainder_size,
        );
        let quotient_size = quotient_size.min(n);
        let remainder_size = remainder_size.min(n);
        for index in 0..quotient_size {
            store(quotient, index, load(quotient_buffer, index));
        }
        for index in quotient_size..n {
            store(quotient, index, 0);
        }
        for index in 0..remainder_size {
            store(remainder, index, load(remainder_buffer, index));
        }
        for index in remainder_size..n {
            store(remainder, index, 0);
        }
        return;
    }

    let half = n / 2;
    let first_remainder = scratch;
    let sub_scratch = scratch.wrapping_add(n);
    div_3n_2n(
        value.wrapping_add(half),
        divisor,
        half,
        quotient.wrapping_add(half),
        first_remainder,
        sub_scratch,
    );
    for index in 0..n {
        store(value, half + index, load(first_remainder, index));
    }
    div_3n_2n(value, divisor, half, quotient, remainder, sub_scratch);
}

// Port of erts/emulator/beam/big.c:bz_div_3n_2n, OTP-29.1.1.
fn div_3n_2n(
    value: *mut u64,
    divisor: *const u64,
    n: usize,
    quotient: *mut u64,
    remainder: *mut u64,
    scratch: *mut u64,
) {
    let high_value = value.wrapping_add(2 * n);
    let middle_value = value.wrapping_add(n);
    let low_value = value;
    let high_divisor = divisor.wrapping_add(n);
    let low_divisor = divisor;
    let product = scratch;
    let sub_scratch = scratch.wrapping_add(2 * n);
    let mut quotient_overflow = false;

    if fixed_compare(high_value, high_divisor, n) == std::cmp::Ordering::Less {
        div_2n_1n(
            middle_value,
            high_divisor,
            n,
            quotient,
            remainder.wrapping_add(n),
            sub_scratch,
        );
    } else {
        for index in 0..n {
            store(quotient, index, u64::MAX);
        }
        quotient_overflow =
            fixed_add(middle_value, high_divisor, remainder.wrapping_add(n), n) != 0;
    }

    let quotient_size = {
        let mut size = n;
        while size > 1 && load(quotient, size - 1) == 0 {
            size -= 1;
        }
        size
    };
    let divisor_size = {
        let mut size = n;
        while size > 1 && load(low_divisor, size - 1) == 0 {
            size -= 1;
        }
        size
    };
    let product_size =
        crate::bignum::times_into_raw(quotient, quotient_size, low_divisor, divisor_size, product);
    for index in product_size..2 * n {
        store(product, index, 0);
    }
    for index in 0..n {
        store(remainder, index, load(low_value, index));
    }
    let borrow = fixed_subtract(remainder, product, remainder, 2 * n);
    let mut borrow = if quotient_overflow && borrow != 0 {
        0
    } else {
        borrow
    };
    while borrow != 0 {
        let mut index = 0;
        loop {
            let digit = load(quotient, index);
            if digit != 0 {
                store(quotient, index, digit - 1);
                break;
            }
            store(quotient, index, u64::MAX);
            index += 1;
            debug_assert!(index < n);
        }
        let carry = fixed_add(remainder, divisor, remainder, 2 * n);
        if carry != 0 {
            debug_assert!(borrow != 0);
            borrow -= 1;
        }
    }
    debug_assert!(!quotient_overflow);
}

// Port of erts/emulator/beam/big.c:I_div_bz, OTP-29.1.1.
fn divide_bz(
    x: *const u64,
    xl: usize,
    y: *const u64,
    yl: usize,
    quotient: *mut u64,
    remainder: *mut u64,
    remainder_size: &mut usize,
) -> usize {
    debug_assert!(yl >= BZ_DIV_THRESHOLD);
    let mut n = 1_usize;
    while n < yl {
        n *= 2;
    }
    let top = load(y, yl - 1);
    let shift = (DIGIT_BITS - 1) - (u64::BITS as usize - 1 - top.leading_zeros() as usize);
    let shift_total = (n - yl) * DIGIT_BITS + shift;
    let mut y_norm = AllocBlock::new(ErtsAlcType::TMP, n + 2)
        .expect("ERTS bignum division scratch allocation failed");
    let y_norm_ptr = y_norm.as_mut_ptr();
    let y_size = shift_digits(y, yl, shift_total as isize, y_norm_ptr).min(n);
    for index in y_size..n {
        store(y_norm_ptr, index, 0);
    }

    let shift_overflow = shift_total.div_ceil(DIGIT_BITS);
    let padded_x = xl + shift_overflow;
    let k = padded_x.div_ceil(n);
    let target = (k + 1) * n;
    let x_norm_capacity = target + 4;
    let mut x_norm = AllocBlock::new(ErtsAlcType::TMP, x_norm_capacity)
        .expect("ERTS bignum division scratch allocation failed");
    let x_norm_ptr = x_norm.as_mut_ptr();
    for index in 0..x_norm_capacity {
        store(x_norm_ptr, index, 0);
    }
    shift_digits(x, xl, shift_total as isize, x_norm_ptr);

    let mut q_buf = AllocBlock::new(ErtsAlcType::TMP, k * n + 1)
        .expect("ERTS bignum division scratch allocation failed");
    let q_buf_ptr = q_buf.as_mut_ptr();
    for index in 0..k * n + 1 {
        store(q_buf_ptr, index, 0);
    }
    let mut scratch = AllocBlock::new(ErtsAlcType::TMP, scratch_size_2n_1n(n))
        .expect("ERTS bignum division scratch allocation failed");
    let scratch_ptr = scratch.as_mut_ptr();
    let mut temp = AllocBlock::new(ErtsAlcType::TMP, 2 * n)
        .expect("ERTS bignum division scratch allocation failed");
    let temp_ptr = temp.as_mut_ptr();
    let remainder_slot = x_norm_ptr.wrapping_add(k * n);

    for chunk in (0..k).rev() {
        for index in 0..n {
            store(temp_ptr, index, load(x_norm_ptr, chunk * n + index));
            store(temp_ptr, n + index, load(remainder_slot, index));
        }
        div_2n_1n(
            temp_ptr,
            y_norm_ptr,
            n,
            q_buf_ptr.wrapping_add(chunk * n),
            remainder_slot,
            scratch_ptr,
        );
    }

    let mut q_size = k * n;
    while q_size > 1 && load(q_buf_ptr, q_size - 1) == 0 {
        q_size -= 1;
    }
    q_size = q_size.min(xl - yl + 1);
    for index in 0..q_size {
        store(quotient, index, load(q_buf_ptr, index));
    }
    let denormalize = ((n - yl) * DIGIT_BITS + shift) as isize;
    let mut r_size = shift_digits(remainder_slot, n, -denormalize, remainder);
    while r_size > 1 && load(remainder, r_size - 1) == 0 {
        r_size -= 1;
    }
    *remainder_size = r_size.max(1);
    q_size
}

/// Divide magnitudes from `x` and `y` into the caller's adjacent quotient/remainder buffers.
// Port of erts/emulator/beam/big.c:3883-3927 (`big_div_rem`), OTP-29.1.1.
pub(crate) fn div_rem_into(
    x: &[u64],
    y: &[u64],
    quotient: *mut u64,
    remainder: *mut u64,
) -> (usize, usize) {
    debug_assert!(!y.is_empty() && y.iter().any(|digit| *digit != 0));
    debug_assert!(compare(x.as_ptr(), x.len(), y.as_ptr(), y.len()) == std::cmp::Ordering::Greater);
    let mut remainder_size = 0;
    let quotient_size = if y.len() == 1 {
        divide_digit(x.as_ptr(), x.len(), y[0], quotient, remainder)
    } else if y.len() >= BZ_DIV_THRESHOLD
        && (x.len() >= 2 * y.len() || x.len() - y.len() > BZ_DIV_QUOTIENT_THRESHOLD)
    {
        divide_bz(
            x.as_ptr(),
            x.len(),
            y.as_ptr(),
            y.len(),
            quotient,
            remainder,
            &mut remainder_size,
        )
    } else {
        divide_digits(
            x.as_ptr(),
            x.len(),
            y.as_ptr(),
            y.len(),
            quotient,
            remainder,
            &mut remainder_size,
        )
    };
    if y.len() == 1 {
        remainder_size = 1;
    }
    (quotient_size, remainder_size)
}
