//! OTP 29 arithmetic over small integers, bignums, and floats.

#![forbid(unsafe_code)]

use arinsal_etf::OwnedTerm;
use arinsal_term::{
    HeapAlloc, MAX_SMALL, MIN_SMALL, Term, TermBuilder, TermError, TermKind, to_owned,
};
use num_bigint::{BigInt, Sign};
use num_traits::{FromPrimitive, Signed, ToPrimitive, Zero};
use std::sync::Arc;

/// An arithmetic exception or a request to collect garbage and retry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArithError {
    /// `error:badarith`.
    Badarith,
    /// `error:badarg`.
    Badarg,
    /// `error:system_limit`.
    SystemLimit,
    /// Retry with at least this many free heap words.
    HeapFull { need_words: usize },
}

/// Result of an arithmetic BIF.
pub type ArithResult = Result<Term, ArithError>;

/// Estimate OTP's reduction charge for a bignum arithmetic operation.
///
/// Port of `bump_reds_linear` and `bump_reds_quadratic` in `erl_arith.c`, plus `BUMP_REDS` in
/// `bif.h` and the bignum arithmetic instruction in `arith_instrs.tab`, OTP-29.1.1. `args` must
/// be the operation's original integer operands.
pub fn reduction_charge(operation: &str, args: &[Term]) -> u32 {
    const WORDS_PER_REDUCTION: usize = 16;
    const MAX_REDUCTIONS: usize = 4_000;
    let words = |term: Term| {
        term.as_small()
            .map(|_| 1)
            .or_else(|| term.bignum_digit_count())
    };
    let linear = |size: usize| {
        if size >= MAX_REDUCTIONS * WORDS_PER_REDUCTION {
            MAX_REDUCTIONS as u32
        } else {
            (size / WORDS_PER_REDUCTION + 1) as u32
        }
    };
    let quadratic = |left: usize, right: usize| {
        if left >= MAX_REDUCTIONS * WORDS_PER_REDUCTION
            || right >= MAX_REDUCTIONS * WORDS_PER_REDUCTION
        {
            MAX_REDUCTIONS as u32
        } else {
            (left.saturating_mul(right) / WORDS_PER_REDUCTION + 1) as u32
        }
    };
    let (Some(&left), right) = (args.first(), args.get(1)) else {
        return 0;
    };
    let Some(left_words) = words(left) else {
        return 0;
    };
    let Some(right) = right.copied() else {
        return match operation {
            "bnot" if left.bignum_digit_count().is_some() => linear(left_words + 2),
            "-" if left.bignum_digit_count().is_some() => linear(left_words),
            _ => 0,
        };
    };
    let Some(right_words) = words(right) else {
        return 0;
    };
    let has_bignum = left.bignum_digit_count().is_some() || right.bignum_digit_count().is_some();
    if matches!(operation, "bsl" | "bsr") {
        let Some(count) = right.as_small() else {
            return if left.as_small() == Some(0) {
                0
            } else {
                MAX_REDUCTIONS as u32
            };
        };
        if count == 0 || left.as_small() == Some(0) {
            return 0;
        }
        let shift_left = (count >= 0) == (operation == "bsl");
        let amount = count.unsigned_abs().min(usize::MAX as u64) as usize;
        let result_words = if shift_left {
            left_words.saturating_add(amount / 64)
        } else if left.bignum_digit_count().is_some() {
            left_words.saturating_sub(amount / 64).max(3)
        } else {
            return 0;
        };
        return linear(result_words + 2);
    }
    if !has_bignum {
        return 0;
    }
    match operation {
        "+" if left.as_small() == Some(0) || right.as_small() == Some(0) => 0,
        "+" => linear(left_words.max(right_words) + 2),
        "-" if right.as_small() == Some(0) => 0,
        "-" => linear(left_words.max(right_words) + 1),
        "*" if matches!(left.as_small(), Some(0 | 1))
            || matches!(right.as_small(), Some(0 | 1)) =>
        {
            0
        }
        "*" if left.as_small() == Some(0) || right.as_small() == Some(0) => 0,
        "*" => quadratic(left_words, right_words),
        "band" | "bor" | "bxor" => linear(left_words.max(right_words) + 2),
        "div" | "rem" => {
            // Port of erts/emulator/beam/erl_arith.c:1208-1213 (big_ucomp branch), OTP-29.1.1.
            if arinsal_term::integer_magnitude_cmp(left, right) != Some(std::cmp::Ordering::Greater)
            {
                0
            } else {
                quadratic(left_words.saturating_sub(right_words) + 1, right_words)
            }
        }
        _ => 0,
    }
}

// TermBuilder is sized; this proxy preserves the frozen ?Sized heap API.
struct HeapProxy<'a, H: HeapAlloc + ?Sized>(&'a mut H);
impl<H: HeapAlloc + ?Sized> HeapAlloc for HeapProxy<'_, H> {
    fn alloc(&mut self, words: usize) -> Option<*mut u64> {
        self.0.alloc(words)
    }
    fn alloc_with_extra(&mut self, words: usize, extra: usize) -> Option<*mut u64> {
        self.0.alloc_with_extra(words, extra)
    }
    fn alloc_fragment_only(&mut self, words: usize) -> Option<*mut u64> {
        self.0.alloc_fragment_only(words)
    }
    fn words_left(&self) -> Option<usize> {
        self.0.words_left()
    }
    fn retain_binary(&mut self, binary: Arc<arinsal_term::RefcBinary>) {
        self.0.retain_binary(binary)
    }
    fn link_bin_ref(
        &mut self,
        bin_ref: *mut u64,
        writable: bool,
        overhead_words: u64,
        owner: Option<arinsal_term::OwnedBinaryRef>,
    ) -> Result<(), TermError> {
        self.0
            .link_bin_ref(bin_ref, writable, overhead_words, owner)
    }
    fn add_bin_vheap(&mut self, words: u64) {
        self.0.add_bin_vheap(words)
    }
    fn retain_writable_binary(
        &mut self,
        binary: Arc<arinsal_term::WritableBinary>,
    ) -> Result<(), TermError> {
        self.0.retain_writable_binary(binary)
    }
    fn retain_writable_binary_with_apparent_size(
        &mut self,
        binary: Arc<arinsal_term::WritableBinary>,
        apparent_size_bits: usize,
    ) -> Result<(), TermError> {
        self.0
            .retain_writable_binary_with_apparent_size(binary, apparent_size_bits)
    }
    fn update_writable_binary_overhead(
        &mut self,
        source: Term,
        old_size_bits: usize,
        new_size_bits: usize,
    ) {
        self.0
            .update_writable_binary_overhead(source, old_size_bits, new_size_bits)
    }
    fn supports_writable_binary(&self) -> bool {
        self.0.supports_writable_binary()
    }
    fn retain_external_binary(
        &mut self,
        binary: Arc<arinsal_term::ExternalBinary>,
    ) -> Result<(), TermError> {
        self.0.retain_external_binary(binary)
    }
    fn supports_external_binary(&self) -> bool {
        self.0.supports_external_binary()
    }
    fn retain_node(&mut self, node: Arc<arinsal_term::Node>) {
        self.0.retain_node(node)
    }
    fn retain_fun(&mut self, entry: Arc<arinsal_term::FunEntry>) {
        self.0.retain_fun(entry)
    }
    fn retain_export(&mut self, entry: Arc<arinsal_term::ExportEntry>) {
        self.0.retain_export(entry)
    }
    fn link_magic_ref(
        &mut self,
        thing: *mut u64,
        owner: Arc<arinsal_term::MagicRef>,
    ) -> Result<(), arinsal_term::TermError> {
        self.0.link_magic_ref(thing, owner)
    }
    fn supports_magic(&self) -> bool {
        self.0.supports_magic()
    }
    fn release(&mut self, end: *mut u64, start: *mut u64) {
        self.0.release(end, start)
    }
}

fn construction_error(error: TermError, need_words: usize) -> ArithError {
    match error {
        TermError::HeapFull => ArithError::HeapFull { need_words },
        TermError::SystemLimit => ArithError::SystemLimit,
        TermError::BadArg | TermError::Unsupported(_) => ArithError::Badarg,
    }
}
fn integer<H: HeapAlloc + ?Sized>(value: &BigInt, heap: &mut H) -> ArithResult {
    // Port of erts/emulator/beam/erl_term.h:466 (BIG_ARITY_MAX), OTP-29.1.1.
    let digits = value.bits().div_ceil(64) as usize;
    if digits > 65_535 {
        return Err(ArithError::SystemLimit);
    }
    let need = if value
        .to_i64()
        .is_some_and(|v| (MIN_SMALL..=MAX_SMALL).contains(&v))
    {
        0
    } else {
        digits + 1
    };
    TermBuilder::new(&mut HeapProxy(heap))
        .int_from_bigint(value)
        .map_err(|e| construction_error(e, need))
}
fn int128<H: HeapAlloc + ?Sized>(value: i128, heap: &mut H) -> ArithResult {
    if let Ok(v) = i64::try_from(value)
        && let Some(t) = Term::small(v)
    {
        return Ok(t);
    }
    integer(&BigInt::from(value), heap)
}
fn floating<H: HeapAlloc + ?Sized>(value: f64, heap: &mut H) -> ArithResult {
    if !value.is_finite() {
        return Err(ArithError::Badarith);
    }
    TermBuilder::new(&mut HeapProxy(heap))
        .float(value)
        .map_err(|e| construction_error(e, 2))
}
fn owned_number(term: Term) -> Option<OwnedTerm> {
    if term.classify() != TermKind::Number || term.as_small().is_some() {
        return None;
    }
    to_owned(term).ok()
}
fn as_integer(term: Term) -> Option<BigInt> {
    if let Some(v) = term.as_small() {
        return Some(BigInt::from(v));
    }
    let owned = owned_number(term)?;
    match &owned {
        OwnedTerm::BigInt(value) => Some(value.clone()),
        OwnedTerm::Int(value) => Some(BigInt::from(*value)),
        _ => None,
    }
}
fn as_float(term: Term) -> Option<f64> {
    let owned = owned_number(term)?;
    match &owned {
        OwnedTerm::Float(value) => Some(*value),
        _ => None,
    }
}
fn number_float(term: Term) -> Result<f64, ArithError> {
    if let Some(f) = as_float(term) {
        return Ok(f);
    }
    let i = as_integer(term).ok_or(ArithError::Badarith)?;
    // Port of erts/emulator/beam/big.c:2412-2525 (big_to_double), OTP-29.1.1.
    big_to_double(&i).ok_or(ArithError::Badarith)
}

/// Convert an Erlang integer or float to a finite `f64` using OTP arithmetic rules.
pub fn number_to_f64(term: Term) -> Result<f64, ArithError> {
    number_float(term)
}

fn big_to_double(value: &BigInt) -> Option<f64> {
    if value.is_zero() {
        return Some(0.0);
    }
    let (sign, digits) = value.to_u64_digits();
    let most = *digits.last()?;
    let bit_len = (digits.len() - 1) * 64 + (64 - most.leading_zeros() as usize);
    if bit_len > 1024 {
        return None;
    }
    let negative = sign == Sign::Minus;
    if bit_len <= 53 {
        let magnitude = digits.first().copied().unwrap_or(0) as f64;
        return Some(if negative { -magnitude } else { magnitude });
    }

    let guard = bit_len - 54;
    let top = (value.magnitude() >> guard).to_u64()?;
    let half_bit = top & 1 != 0;
    let mut mantissa = top >> 1;
    let full_digits = guard / 64;
    let trailing_bits = guard % 64;
    let lesser_bits = digits[..full_digits].iter().any(|digit| *digit != 0)
        || (trailing_bits != 0
            && digits
                .get(full_digits)
                .is_some_and(|digit| digit & ((1_u64 << trailing_bits) - 1) != 0));
    let mut exponent = guard + 1;
    if half_bit && (mantissa & 1 != 0 || lesser_bits) {
        mantissa += 1;
        if mantissa == 1_u64 << 53 {
            mantissa >>= 1;
            exponent += 1;
        }
    }
    let biased = exponent.checked_add(52)?.checked_add(1023)?;
    if biased >= 0x7ff {
        return None;
    }
    let sign_bit = if negative { 1_u64 << 63 } else { 0 };
    let fraction = mantissa & ((1_u64 << 52) - 1);
    Some(f64::from_bits(
        sign_bit | ((biased as u64) << 52) | fraction,
    ))
}
fn binary_arith<H: HeapAlloc + ?Sized>(
    a: Term,
    b: Term,
    heap: &mut H,
    integer_op: impl FnOnce(BigInt, BigInt) -> BigInt,
    float_op: impl FnOnce(f64, f64) -> f64,
) -> ArithResult {
    if as_float(a).is_some() || as_float(b).is_some() {
        return floating(float_op(number_float(a)?, number_float(b)?), heap);
    }
    integer(
        &integer_op(
            as_integer(a).ok_or(ArithError::Badarith)?,
            as_integer(b).ok_or(ArithError::Badarith)?,
        ),
        heap,
    )
}
/// `A + B`.
pub fn add<H: HeapAlloc + ?Sized>(a: Term, b: Term, heap: &mut H) -> ArithResult {
    if let (Some(x), Some(y)) = (a.as_small(), b.as_small()) {
        return int128(x as i128 + y as i128, heap);
    }
    if let Some(k) = b.as_small().filter(|n| *n >= 0)
        && let Some(words) = positive_words(a)
    {
        return add_small_to_positive(words, k as u64, heap);
    }
    if let Some(k) = a.as_small().filter(|n| *n >= 0)
        && let Some(words) = positive_words(b)
    {
        return add_small_to_positive(words, k as u64, heap);
    }
    // Port of erts/emulator/beam/erl_arith.c:358 (erts_mixed_plus), OTP-29.1.1.
    binary_arith(a, b, heap, |x, y| x + y, |x, y| x + y)
}
/// `A - B`.
pub fn sub<H: HeapAlloc + ?Sized>(a: Term, b: Term, heap: &mut H) -> ArithResult {
    if let (Some(x), Some(y)) = (a.as_small(), b.as_small()) {
        return int128(x as i128 - y as i128, heap);
    }
    // Port of erts/emulator/beam/erl_arith.c:571 (erts_mixed_minus), OTP-29.1.1.
    binary_arith(a, b, heap, |x, y| x - y, |x, y| x - y)
}
/// `A * B`.
pub fn mul<H: HeapAlloc + ?Sized>(a: Term, b: Term, heap: &mut H) -> ArithResult {
    if let (Some(x), Some(y)) = (a.as_small(), b.as_small()) {
        return int128(x as i128 * y as i128, heap);
    }
    if let Some(k) = b.as_small().filter(|n| *n >= 0)
        && let Some(words) = positive_words(a)
    {
        return mul_small_positive(words, k as u64, heap);
    }
    if let Some(k) = a.as_small().filter(|n| *n >= 0)
        && let Some(words) = positive_words(b)
    {
        return mul_small_positive(words, k as u64, heap);
    }
    // Port of erts/emulator/beam/erl_arith.c:716 (erts_mixed_times), OTP-29.1.1.
    binary_arith(a, b, heap, |x, y| x * y, |x, y| x * y)
}
/// `A / B`, always a float.
pub fn fdiv<H: HeapAlloc + ?Sized>(a: Term, b: Term, heap: &mut H) -> ArithResult {
    // Port of erts/emulator/beam/erl_arith.c:1015 (erts_mixed_div), OTP-29.1.1.
    floating(number_float(a)? / number_float(b)?, heap)
}
/// `A div B`, truncated toward zero.
pub fn int_div<H: HeapAlloc + ?Sized>(a: Term, b: Term, heap: &mut H) -> ArithResult {
    let x = as_integer(a).ok_or(ArithError::Badarith)?;
    let y = as_integer(b)
        .filter(|v| !v.is_zero())
        .ok_or(ArithError::Badarith)?;
    // Port of erts/emulator/beam/erl_arith.c:122 (div_2), OTP-29.1.1.
    integer(&(x / y), heap)
}
/// `A rem B`, with the dividend's sign.
pub fn rem<H: HeapAlloc + ?Sized>(a: Term, b: Term, heap: &mut H) -> ArithResult {
    let x = as_integer(a).ok_or(ArithError::Badarith)?;
    let y = as_integer(b)
        .filter(|v| !v.is_zero())
        .ok_or(ArithError::Badarith)?;
    // Port of erts/emulator/beam/erl_arith.c:145 (rem_2), OTP-29.1.1.
    integer(&(x % y), heap)
}
/// `A band B`.
pub fn band<H: HeapAlloc + ?Sized>(a: Term, b: Term, heap: &mut H) -> ArithResult {
    bitop(a, b, heap, BitOp::And)
}
/// `A bor B`.
pub fn bor<H: HeapAlloc + ?Sized>(a: Term, b: Term, heap: &mut H) -> ArithResult {
    bitop(a, b, heap, BitOp::Or)
}
/// `A bxor B`.
pub fn bxor<H: HeapAlloc + ?Sized>(a: Term, b: Term, heap: &mut H) -> ArithResult {
    bitop(a, b, heap, BitOp::Xor)
}
enum BitOp {
    And,
    Or,
    Xor,
}
fn add_small_to_positive<H: HeapAlloc + ?Sized>(
    mut words: Vec<u64>,
    small: u64,
    heap: &mut H,
) -> ArithResult {
    // Port of erts/emulator/beam/big.c:4010 (big_plus_small), OTP-29.1.1.
    if words.is_empty() {
        words.push(0);
    }
    let mut carry = small;
    for word in &mut words {
        let (sum, overflow) = word.overflowing_add(carry);
        *word = sum;
        carry = u64::from(overflow);
        if carry == 0 {
            break;
        }
    }
    if carry != 0 {
        words.push(carry);
    }
    positive_result(words, heap)
}
fn mul_small_positive<H: HeapAlloc + ?Sized>(
    mut words: Vec<u64>,
    small: u64,
    heap: &mut H,
) -> ArithResult {
    // Port of erts/emulator/beam/big.c:3827 (big_times), OTP-29.1.1.
    if small == 0 || words.is_empty() {
        return Ok(Term::small(0).unwrap());
    }
    let mut carry = 0u128;
    for word in &mut words {
        let product = (*word as u128) * (small as u128) + carry;
        *word = product as u64;
        carry = product >> 64;
    }
    if carry != 0 {
        words.push(carry as u64);
    }
    positive_result(words, heap)
}
fn positive_words(term: Term) -> Option<Vec<u64>> {
    if let Some(n) = term.as_small() {
        return (n >= 0).then(|| if n == 0 { Vec::new() } else { vec![n as u64] });
    }
    let owned = owned_number(term)?;
    let OwnedTerm::BigInt(value) = &owned else {
        return None;
    };
    (!value.is_negative()).then(|| value.to_u64_digits().1)
}
fn positive_result<H: HeapAlloc + ?Sized>(mut words: Vec<u64>, heap: &mut H) -> ArithResult {
    while words.last() == Some(&0) {
        words.pop();
    }
    if words.is_empty() {
        return Ok(Term::small(0).unwrap());
    }
    if words.len() == 1 && words[0] <= MAX_SMALL as u64 {
        return Ok(Term::small(words[0] as i64).unwrap());
    }
    if words.len() > 65_535 {
        return Err(ArithError::SystemLimit);
    }
    let bytes: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
    integer(&BigInt::from_bytes_le(Sign::Plus, &bytes), heap)
}
fn bitop<H: HeapAlloc + ?Sized>(a: Term, b: Term, heap: &mut H, op: BitOp) -> ArithResult {
    // Port of erts/emulator/beam/erl_arith.c:164 (band_2/bor_2/bxor_2), OTP-29.1.1.
    let x = as_integer(a).ok_or(ArithError::Badarith)?;
    let y = as_integer(b).ok_or(ArithError::Badarith)?;
    integer(
        &match op {
            BitOp::And => x & y,
            BitOp::Or => x | y,
            BitOp::Xor => x ^ y,
        },
        heap,
    )
}
fn shift<H: HeapAlloc + ?Sized>(a: Term, b: Term, heap: &mut H, right: bool) -> ArithResult {
    let y = as_integer(b).ok_or(ArithError::Badarith)?;
    // Port of erts/emulator/beam/erl_arith.c:190 (erts_shift), OTP-29.1.1.
    let direction = if right { -y } else { y };
    let x = as_integer(a).ok_or(ArithError::Badarith)?;
    if x.is_zero() || direction.is_zero() {
        return Ok(a);
    }
    if direction.is_negative() {
        let count = direction.abs().to_usize().unwrap_or(usize::MAX);
        if count >= x.bits() as usize {
            return integer(&BigInt::from(if x.is_negative() { -1 } else { 0 }), heap);
        }
        return integer(&(x >> count), heap);
    }
    let count = direction.to_usize().ok_or(ArithError::SystemLimit)?;
    if count > 4_194_240 || x.bits().saturating_add(count as u64) > 4_194_240 {
        return Err(ArithError::SystemLimit);
    }
    integer(&(x << count), heap)
}
/// `A bsl B`.
pub fn bsl<H: HeapAlloc + ?Sized>(a: Term, b: Term, heap: &mut H) -> ArithResult {
    shift(a, b, heap, false)
}
/// `A bsr B`.
pub fn bsr<H: HeapAlloc + ?Sized>(a: Term, b: Term, heap: &mut H) -> ArithResult {
    shift(a, b, heap, true)
}
/// Unary minus.
pub fn neg<H: HeapAlloc + ?Sized>(a: Term, heap: &mut H) -> ArithResult {
    if let Some(v) = as_float(a) {
        return floating(-v, heap);
    }
    integer(&-as_integer(a).ok_or(ArithError::Badarith)?, heap)
}
/// Unary plus.
pub fn plus<H: HeapAlloc + ?Sized>(a: Term, _heap: &mut H) -> ArithResult {
    if as_integer(a).is_some() || as_float(a).is_some() {
        Ok(a)
    } else {
        Err(ArithError::Badarith)
    }
}
/// Absolute value.
pub fn abs<H: HeapAlloc + ?Sized>(a: Term, heap: &mut H) -> ArithResult {
    // Port of erts/emulator/beam/erl_bif_guard.c:57 (abs_1), OTP-29.1.1.
    if let Some(v) = as_float(a) {
        return if v.is_sign_negative() {
            floating(v.abs(), heap)
        } else {
            Ok(a)
        };
    }
    let i = as_integer(a).ok_or(ArithError::Badarg)?;
    if i.is_negative() {
        integer(&i.abs(), heap)
    } else {
        Ok(a)
    }
}
/// Bitwise complement.
pub fn bnot<H: HeapAlloc + ?Sized>(a: Term, heap: &mut H) -> ArithResult {
    integer(&!as_integer(a).ok_or(ArithError::Badarith)?, heap)
}
/// `float(A)`.
pub fn to_float<H: HeapAlloc + ?Sized>(a: Term, heap: &mut H) -> ArithResult {
    // Port of erts/emulator/beam/erl_bif_guard.c:107 (float_1), OTP-29.1.1.
    if as_float(a).is_some() {
        return Ok(a);
    }
    let i = as_integer(a).ok_or(ArithError::Badarg)?;
    floating(big_to_double(&i).ok_or(ArithError::Badarg)?, heap)
}
fn float_integer<H: HeapAlloc + ?Sized>(
    a: Term,
    heap: &mut H,
    op: impl FnOnce(f64) -> f64,
) -> ArithResult {
    if as_integer(a).is_some() {
        return Ok(a);
    }
    let v = op(as_float(a).ok_or(ArithError::Badarg)?);
    let i = BigInt::from_f64(v).ok_or(ArithError::Badarg)?;
    integer(&i, heap)
}
/// `trunc(A)`.
pub fn trunc<H: HeapAlloc + ?Sized>(a: Term, heap: &mut H) -> ArithResult {
    float_integer(a, heap, f64::trunc)
}
/// `round(A)`, ties away from zero.
pub fn round<H: HeapAlloc + ?Sized>(a: Term, heap: &mut H) -> ArithResult {
    float_integer(a, heap, f64::round)
}
/// `ceil(A)`.
pub fn ceil<H: HeapAlloc + ?Sized>(a: Term, heap: &mut H) -> ArithResult {
    float_integer(a, heap, f64::ceil)
}
/// `floor(A)`.
pub fn floor<H: HeapAlloc + ?Sized>(a: Term, heap: &mut H) -> ArithResult {
    float_integer(a, heap, f64::floor)
}
fn base_value(base: Term) -> Result<u32, ArithError> {
    base.as_small()
        .filter(|b| (2..=36).contains(b))
        .map(|b| b as u32)
        .ok_or(ArithError::Badarg)
}
fn text(int: Term, base: Term) -> Result<String, ArithError> {
    let radix = base_value(base)?;
    let n = as_integer(int).ok_or(ArithError::Badarg)?;
    // Port of erts/emulator/beam/bif.c:3266 (integer_to_list), OTP-29.1.1.
    Ok(n.to_str_radix(radix).to_ascii_uppercase())
}
/// `integer_to_list(Int, Base)`.
pub fn integer_to_list<H: HeapAlloc + ?Sized>(int: Term, base: Term, heap: &mut H) -> ArithResult {
    let s = text(int, base)?;
    let need = s.len().checked_mul(2).ok_or(ArithError::SystemLimit)?;
    TermBuilder::new(&mut HeapProxy(heap))
        .string_to_list(&s)
        .map_err(|e| construction_error(e, need))
}
/// `integer_to_binary(Int, Base)`.
pub fn integer_to_binary<H: HeapAlloc + ?Sized>(
    int: Term,
    base: Term,
    heap: &mut H,
) -> ArithResult {
    // Port of erts/emulator/beam/binary.c:80-116 (integer_to_binary), OTP-29.1.1.
    // A small uses a stack buffer (`Sint_to_buf` into `char s[128]`), then
    // `erts_new_binary_from_data`. A bignum still goes through a digit string.
    let radix = base_value(base)?;
    if let Some(value) = int.as_small() {
        let mut buf = [0_u8; 128];
        let digits = format_small(value, radix, &mut buf);
        let need = 2 + digits.len().div_ceil(8);
        return TermBuilder::new(&mut HeapProxy(heap))
            .binary(digits)
            .map_err(|e| construction_error(e, need));
    }
    let s = text(int, base)?;
    let len = s.len();
    let need = if len <= 64 { 2 + len.div_ceil(8) } else { 8 };
    TermBuilder::new(&mut HeapProxy(heap))
        .binary(s.as_bytes())
        .map_err(|e| construction_error(e, need))
}

/// Decimal or other-base digits of a small, written into `buf` from the end.
// Port of erts/emulator/beam/utils.c:2994-3035 (`Sint_to_buf`), OTP-29.1.1.
fn format_small(value: i64, base: u32, buf: &mut [u8; 128]) -> &[u8] {
    const DIGITS: &[u8; 36] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let mut index = buf.len();
    let mut magnitude = value;
    let mut negative = false;
    if magnitude == 0 {
        index -= 1;
        buf[index] = b'0';
    } else if magnitude < 0 {
        negative = true;
        magnitude = -magnitude;
    }
    while magnitude != 0 {
        index -= 1;
        let digit = (magnitude % i64::from(base)) as usize;
        buf[index] = DIGITS[digit];
        magnitude /= i64::from(base);
    }
    if negative {
        index -= 1;
        buf[index] = b'-';
    }
    &buf[index..]
}
fn parse_bytes(bytes: &[u8], base: u32) -> Result<BigInt, ArithError> {
    // Port of erts/emulator/beam/big.c:4162 (chars_to_integer), OTP-29.1.1.
    let (negative, digits) = match bytes.first() {
        Some(b'-') => (true, &bytes[1..]),
        Some(b'+') => (false, &bytes[1..]),
        _ => (false, bytes),
    };
    if digits.is_empty()
        || digits.iter().any(|b| match b {
            b'0'..=b'9' => (*b - b'0') as u32 >= base,
            b'A'..=b'Z' => (*b - b'A' + 10) as u32 >= base,
            b'a'..=b'z' => (*b - b'a' + 10) as u32 >= base,
            _ => true,
        })
    {
        return Err(ArithError::Badarg);
    }
    let value = BigInt::parse_bytes(digits, base).ok_or(ArithError::Badarg)?;
    Ok(if negative { -value } else { value })
}
/// `list_to_integer(List, Base)`.
pub fn list_to_integer<H: HeapAlloc + ?Sized>(list: Term, base: Term, heap: &mut H) -> ArithResult {
    let radix = base_value(base)?;
    integer(&parse_bytes(&list_bytes(list)?, radix)?, heap)
}
fn list_bytes(list: Term) -> Result<Vec<u8>, ArithError> {
    if list == Term::NIL {
        return Ok(Vec::new());
    }
    if list.classify() != TermKind::List {
        return Err(ArithError::Badarg);
    }
    let owned = to_owned(list).map_err(|_| ArithError::Badarg)?;
    let OwnedTerm::List { elems, tail } = &owned else {
        return Err(ArithError::Badarg);
    };
    if !matches!(tail.as_ref(), OwnedTerm::Nil) {
        return Err(ArithError::Badarg);
    }
    let mut bytes = Vec::with_capacity(elems.len());
    for elem in elems {
        let OwnedTerm::Int(value) = elem else {
            return Err(ArithError::Badarg);
        };
        bytes.push(u8::try_from(*value).map_err(|_| ArithError::Badarg)?);
    }
    Ok(bytes)
}
/// `binary_to_integer(Bin, Base)`.
pub fn binary_to_integer<H: HeapAlloc + ?Sized>(
    bin: Term,
    base: Term,
    heap: &mut H,
) -> ArithResult {
    let radix = base_value(base)?;
    if bin.classify() != TermKind::Bitstring {
        return Err(ArithError::Badarg);
    }
    // `to_owned` aligns a sub-binary onto whole bytes and rejects a partial last byte.
    let owned = to_owned(bin).map_err(|_| ArithError::Badarg)?;
    let OwnedTerm::Binary(bytes) = &owned else {
        return Err(ArithError::Badarg);
    };
    integer(&parse_bytes(bytes, radix)?, heap)
}

/// `integer_to_list(Int)` in decimal.
pub fn integer_to_list_decimal<H: HeapAlloc + ?Sized>(int: Term, heap: &mut H) -> ArithResult {
    integer_to_list(int, Term::small(10).unwrap(), heap)
}
/// `integer_to_binary(Int)` in decimal.
pub fn integer_to_binary_decimal<H: HeapAlloc + ?Sized>(int: Term, heap: &mut H) -> ArithResult {
    // Port of erts/emulator/beam/binary.c:80-99 (`integer_to_binary`'s small decimal path),
    // OTP-29.1.1. The /1 BIF supplies base 10 directly rather than decoding a base argument.
    if let Some(value) = int.as_small() {
        let mut buf = [0_u8; 128];
        let digits = format_small(value, 10, &mut buf);
        let need = 2 + digits.len().div_ceil(8);
        return TermBuilder::new(&mut HeapProxy(heap))
            .binary(digits)
            .map_err(|error| construction_error(error, need));
    }
    integer_to_binary(int, Term::small(10).unwrap(), heap)
}
/// `list_to_integer(List)` in decimal.
pub fn list_to_integer_decimal<H: HeapAlloc + ?Sized>(list: Term, heap: &mut H) -> ArithResult {
    list_to_integer(list, Term::small(10).unwrap(), heap)
}
/// `binary_to_integer(Bin)` in decimal.
pub fn binary_to_integer_decimal<H: HeapAlloc + ?Sized>(bin: Term, heap: &mut H) -> ArithResult {
    binary_to_integer(bin, Term::small(10).unwrap(), heap)
}

#[cfg(test)]
mod arithmetic_reduction_tests {
    use super::reduction_charge;
    use arinsal_term::{Term, TermBuilder, VecHeap};
    use num_bigint::BigInt;

    #[test]
    fn arith_red_max_bignum_division_uses_the_context_cap() {
        let value = (BigInt::from(1_u8) << (65_535 * 64)) - 1;
        let mut heap = VecHeap::new();
        let left = TermBuilder::new(&mut heap).int_from_bigint(&value).unwrap();
        let right = Term::small(7).unwrap();
        assert_eq!(left.bignum_digit_count(), Some(65_535));
        assert_eq!(reduction_charge("div", &[left, right]), 4_000);
    }
}
