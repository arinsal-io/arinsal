//! OTP 29 bit syntax construction and matching.
//!
//! The interpreter resolves register operands and sizes before calling this API.
//! For `bs_create_bin`, map each six-operand group to a [`Segment`], then call
//! [`create_bin_size`] before GC and [`create_bin`] after GC:
//!
//! ```
//! use arinsal_bits::{Segment, SegType, SegFlags, SegSize, SegmentValue, create_bin_size, create_bin};
//! use arinsal_term::{Term, VecHeap};
//! let mut heap = VecHeap::new();
//! let segments = [Segment { ty: SegType::Integer, index: 1, unit: 1,
//!     flags: SegFlags::default(), value: SegmentValue::Term(Term::small(42).unwrap()),
//!     size: SegSize::Units(8) }];
//! let need = create_bin_size(&segments).unwrap();
//! assert_eq!(need.bits, 8);
//! let binary = create_bin(&segments, &mut heap).unwrap();
//! assert_eq!(unsafe { binary.binary_ref() }.unwrap().bytes(), &[42]);
//! ```
//!
//! `bs_start_match4` maps to [`start_match`], which returns a `SUB_BITS` term.
//! Import [`MatchOps`] for `bs_match` commands and the legacy get/skip forms.
//! The term's mutable offset follows register copies and can be read through
//! [`get_position`] or restored through [`set_position_term`].
//! `bs_init_writable` maps to [`init_writable`].
//!
//! ```
//! use arinsal_bits::{start_match, SegFlags, MatchOps};
//! use arinsal_term::{TermBuilder, VecHeap};
//! let mut heap = VecHeap::new();
//! let binary = TermBuilder::new(&mut heap).binary(&[0, 0, 0, 3, 9, 8, 7]).unwrap();
//! let ctx = start_match(binary, &mut heap).unwrap().unwrap();
//! // {ensure_at_least,32,8}; the interpreter supplies the fail label.
//! assert!(ctx.ensure_at_least(32, 8));
//! // {integer,Live,Flags,32,1,Dst}: Live/Dst are handled by the interpreter.
//! let len = ctx.get_integer(32, SegFlags::default(), &mut heap).unwrap().unwrap();
//! let saved = ctx.position(); // bs_get_position
//! assert!(ctx.match_integer(8, 9)); // {'=:=',nil,8,9}
//! assert!(ctx.set_position(saved)); // bs_set_position
//! // {binary,Live,Flags,Len,8,Dst}
//! let payload = ctx.get_binary(len.as_small().unwrap() as usize * 8, &mut heap).unwrap().unwrap();
//! assert_eq!(unsafe { payload.binary_ref() }.unwrap().bit_len(), 24);
//! assert!(ctx.ensure_exactly(0)); // {ensure_exactly,0} / bs_test_tail2
//! let tail = ctx.get_tail_unit(8, &mut heap).unwrap().unwrap(); // {get_tail,Live,8,Dst}
//! assert_eq!(unsafe { tail.binary_ref() }.unwrap().bit_len(), 0);
//! assert!(ctx.set_position(saved));
//! assert!(ctx.skip(24)); // {skip,24} / bs_skip_bits2
//! assert!(ctx.test_unit(8)); // bs_test_unit
//! ```

use arinsal_etf::OwnedTerm;
use arinsal_term::{
    HeapAlloc, Term, TermBuilder, TermError, TermKind, is_match_context, is_writable_binary,
    match_position, set_match_position, to_owned, writable_bytes_mut, writable_extend_private,
    writable_finalize,
};
use num_bigint::{BigInt, BigUint, Sign};
use num_traits::{ToPrimitive, Zero};

/// BEAM segment type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SegType {
    /// Integer bit field.
    Integer,
    /// IEEE binary16, binary32, or binary64 field.
    Float,
    /// Bitstring copy.
    Binary,
    /// Writable binary append.
    Append,
    /// Private writable binary append.
    PrivateAppend,
    /// Literal bytes from the module string table.
    String,
    /// UTF-8 code point.
    Utf8,
    /// UTF-16 code point.
    Utf16,
    /// UTF-32 code point.
    Utf32,
}

/// Field flags. `native` takes precedence over `little`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SegFlags {
    /// Little-endian byte order.
    pub little: bool,
    /// Signed integer extraction.
    pub signed: bool,
    /// Host byte order.
    pub native: bool,
}
impl SegFlags {
    fn little(self) -> bool {
        if self.native {
            cfg!(target_endian = "little")
        } else {
            self.little
        }
    }
}

/// Segment size as encoded in a BEAM operand, before multiplying by `unit`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SegSize {
    /// Copy the entire bitstring.
    All,
    /// Number of units in the field.
    Units(u64),
    /// Register size; negative/noninteger terms raise `badarg`, positive bignums `system_limit`.
    Term(Term),
}

/// A source register term or module string-table bytes.
#[derive(Clone, Copy, Debug)]
pub enum SegmentValue<'a> {
    /// Resolved register, literal, or immediate.
    Term(Term),
    /// Literal byte sequence for a `string` segment.
    String(&'a [u8]),
}

/// One resolved six-operand `bs_create_bin` segment.
#[derive(Clone, Copy, Debug)]
pub struct Segment<'a> {
    /// Segment type.
    pub ty: SegType,
    /// One-based source segment index, used in rich `error_info` later.
    pub index: usize,
    /// Bits per size unit.
    pub unit: u8,
    /// Endian and signedness flags.
    pub flags: SegFlags,
    /// Resolved source operand.
    pub value: SegmentValue<'a>,
    /// Resolved size operand.
    pub size: SegSize,
}

/// Construction size and minimum destination heap words.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BinSize {
    /// Significant bits in the result.
    pub bits: usize,
    /// Term words, excluding the instruction's other `Alloc` words.
    pub heap_words: usize,
}

/// BEAM exception or allocation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BitsError {
    /// `error:badarg`; the segment index identifies the failing operand.
    BadArg { segment: usize },
    /// `error:system_limit`; the bit count cannot fit in erts' signed size.
    SystemLimit { segment: usize },
    /// A construction error with the metadata attached by erts to the stack frame.
    Detailed {
        /// One-based failing source segment.
        segment: usize,
        /// Exception class reason.
        reason: &'static str,
        /// Segment type atom.
        ty: &'static str,
        /// Failure category atom.
        field: &'static str,
        /// Source term attached to the failure.
        value: Term,
    },
    /// GC is required before retrying.
    HeapFull { need_words: usize },
}

fn segment_name(ty: SegType) -> &'static str {
    match ty {
        SegType::Integer => "integer",
        SegType::Float => "float",
        SegType::Binary | SegType::Append | SegType::PrivateAppend => "binary",
        SegType::String => "string",
        SegType::Utf8 => "utf8",
        SegType::Utf16 => "utf16",
        SegType::Utf32 => "utf32",
    }
}

fn detailed(segment: &Segment<'_>, field: &'static str, value: Term) -> BitsError {
    detailed_reason(segment, "badarg", field, value)
}

fn detailed_reason(
    segment: &Segment<'_>,
    reason: &'static str,
    field: &'static str,
    value: Term,
) -> BitsError {
    BitsError::Detailed {
        segment: segment.index,
        reason,
        ty: segment_name(segment.ty),
        field,
        value,
    }
}

fn size_term(segment: &Segment<'_>) -> Option<Term> {
    match segment.size {
        SegSize::Term(term) => Some(term),
        SegSize::Units(size) => i64::try_from(size).ok().and_then(Term::small),
        SegSize::All => None,
    }
}

fn term_error(error: TermError, segment: usize, words: usize) -> BitsError {
    match error {
        TermError::HeapFull => BitsError::HeapFull { need_words: words },
        TermError::SystemLimit => BitsError::SystemLimit { segment },
        _ => BitsError::BadArg { segment },
    }
}

// Port of erts/emulator/beam/erl_bits.c:72 (`GROW_PROC_BIN_SIZE`), OTP-29.1.1.
fn grow_proc_binary_size(size: usize) -> Result<usize, BitsError> {
    if size <= 1 << 24 {
        size.checked_mul(2)
            .ok_or(BitsError::SystemLimit { segment: 1 })
    } else {
        let grown = (1.2 * size as f64) as usize;
        if grown < size {
            return Err(BitsError::SystemLimit { segment: 1 });
        }
        Ok(grown)
    }
}

/// Borrow a bitstring's backing bytes for `f`.
///
/// `start` is the first significant bit and `bits` is its length. The slice
/// includes surrounding bytes when the window is unaligned. Copying the owner
/// on every append would be quadratic (`<<Acc::binary, Byte>>`).
#[inline]
fn with_binary<R>(term: Term, f: impl FnOnce(&[u8], usize, usize) -> R) -> Option<R> {
    // SAFETY: the owner heap stays live for `f`. Callers do not append through
    // this owner while the slice is borrowed, and the slice does not escape `f`.
    let view = unsafe { term.binary_ref() }?;
    Some(f(view.bytes(), view.start_bit(), view.bit_len()))
}

/// Return the significant bit length of a binary or bitstring term.
pub fn bit_size(term: Term) -> Option<usize> {
    with_binary(term, |_, _, bits| bits)
}

fn owned_number(term: Term) -> Option<OwnedTerm> {
    if term.classify() != TermKind::Number || term.as_small().is_some() {
        return None;
    }
    to_owned(term).ok()
}

/// Heap words a binary slice may need: a `HeapBits` copy, or a `BinRef` plus
/// `SubBits`. Callers GC with this hint, so it must cover both representations.
fn binary_slice_words(bits: usize) -> usize {
    let count = bits.div_ceil(8);
    if count <= 64 {
        (2 + count.div_ceil(8)).max(8)
    } else {
        8
    }
}

fn source(segment: &Segment<'_>) -> Result<Term, BitsError> {
    match segment.value {
        SegmentValue::Term(term) => Ok(term),
        SegmentValue::String(_) => Err(BitsError::BadArg {
            segment: segment.index,
        }),
    }
}

fn as_integer(term: Term) -> Option<BigInt> {
    if let Some(n) = term.as_small() {
        return Some(BigInt::from(n));
    }
    let owned = owned_number(term)?;
    match &owned {
        OwnedTerm::BigInt(value) => Some(value.clone()),
        OwnedTerm::Int(value) => Some(BigInt::from(*value)),
        _ => None,
    }
}

fn is_integer(term: Term) -> bool {
    if term.as_small().is_some() {
        return true;
    }
    let owned = owned_number(term);
    matches!(owned, Some(OwnedTerm::BigInt(_) | OwnedTerm::Int(_)))
}

fn as_float(term: Term) -> Option<f64> {
    let owned = owned_number(term);
    let value = match &owned {
        Some(OwnedTerm::Float(value)) => Some(*value),
        Some(OwnedTerm::BigInt(value)) => value.to_f64(),
        Some(OwnedTerm::Int(value)) => Some(*value as f64),
        _ => None,
    };
    value
        .or_else(|| as_integer(term)?.to_f64())
        .filter(|f| f.is_finite())
}

fn codepoint(segment: &Segment<'_>) -> Result<char, BitsError> {
    let value = source(segment)?;
    let Some(n) = value.as_small().and_then(|n| u32::try_from(n).ok()) else {
        return Err(detailed(segment, "type", value));
    };
    char::from_u32(n).ok_or_else(|| detailed(segment, "type", value))
}

fn size_of(segment: &Segment<'_>) -> Result<usize, BitsError> {
    // Port of erts/emulator/beam/erl_bits.c:707 (segment size validation), OTP-29.1.1.
    let bad = BitsError::BadArg {
        segment: segment.index,
    };
    let limit = BitsError::SystemLimit {
        segment: segment.index,
    };
    match segment.ty {
        SegType::Utf8 => Ok(codepoint(segment)?.len_utf8() * 8),
        SegType::Utf16 => Ok(codepoint(segment)?.len_utf16() * 16),
        SegType::Utf32 => {
            codepoint(segment)?;
            Ok(32)
        }
        SegType::String => match segment.value {
            SegmentValue::String(s) => s.len().checked_mul(8).ok_or(limit),
            _ => Err(bad),
        },
        SegType::Binary | SegType::Append | SegType::PrivateAppend => {
            let requested = if matches!(segment.size, SegSize::All) {
                None
            } else {
                Some(units_bits(segment)?)
            };
            let t = source(segment)?;
            let Some(bit_len) = with_binary(t, |_, _, bits| bits) else {
                return Err(detailed(segment, "type", t));
            };
            if matches!(segment.size, SegSize::All) {
                if segment.unit == 0 || bit_len % usize::from(segment.unit) != 0 {
                    return Err(detailed(segment, "unit", t));
                }
                Ok(bit_len)
            } else {
                let bits = requested.expect("non-all size was calculated");
                if bits > bit_len {
                    Err(detailed(segment, "short", t))
                } else {
                    Ok(bits)
                }
            }
        }
        SegType::Integer | SegType::Float => {
            let bits = units_bits(segment)?;
            let t = source(segment)?;
            if segment.ty == SegType::Integer {
                if !is_integer(t) {
                    return Err(detailed(segment, "type", t));
                }
            } else if as_float(t).is_none() {
                return Err(detailed(
                    segment,
                    if is_integer(t) { "no_float" } else { "type" },
                    t,
                ));
            } else if !matches!(bits, 16 | 32 | 64) {
                return Err(detailed(
                    segment,
                    "invalid",
                    size_term(segment).unwrap_or(t),
                ));
            }
            Ok(bits)
        }
    }
}

fn units_bits(segment: &Segment<'_>) -> Result<usize, BitsError> {
    // Port of erts/emulator/beam/erl_bits.c:736 (size and system_limit checks), OTP-29.1.1.
    let size = match segment.size {
        SegSize::Units(size) => size,
        SegSize::Term(term) => {
            if let Some(value) = term.as_small() {
                u64::try_from(value).map_err(|_| detailed(segment, "size", term))?
            } else {
                let owned = owned_number(term);
                match &owned {
                    Some(OwnedTerm::BigInt(value)) if value.sign() != Sign::Minus => {
                        return Err(detailed_reason(segment, "system_limit", "size", term));
                    }
                    _ => return Err(detailed(segment, "size", term)),
                }
            }
        }
        SegSize::All => {
            return Err(BitsError::BadArg {
                segment: segment.index,
            });
        }
    };
    if size > arinsal_term::MAX_SMALL as u64 {
        if let Some(value) = size_term(segment) {
            return Err(detailed_reason(segment, "system_limit", "size", value));
        }
        return Err(BitsError::SystemLimit {
            segment: segment.index,
        });
    }
    let bits = size.checked_mul(u64::from(segment.unit)).ok_or_else(|| {
        size_term(segment).map_or(
            BitsError::SystemLimit {
                segment: segment.index,
            },
            |value| detailed_reason(segment, "system_limit", "size", value),
        )
    })?;
    if bits > isize::MAX as u64 {
        if let Some(value) = size_term(segment) {
            return Err(detailed_reason(segment, "system_limit", "size", value));
        }
        return Err(BitsError::SystemLimit {
            segment: segment.index,
        });
    }
    Ok(bits as usize)
}

/// Validate every segment and calculate destination size before allocation.
pub fn create_bin_size(segments: &[Segment<'_>]) -> Result<BinSize, BitsError> {
    // Port of erts/emulator/beam/erl_bits.c:1566 (binary size calculation), OTP-29.1.1.
    let mut bits = 0usize;
    for segment in segments {
        bits = bits
            .checked_add(size_of(segment)?)
            .filter(|n| *n <= isize::MAX as usize)
            .ok_or(BitsError::SystemLimit {
                segment: segment.index,
            })?;
    }
    let heap_words = if let Some(first) = segments.first()
        && matches!(first.ty, SegType::Append | SegType::PrivateAppend)
    {
        // A writable result is always a BinRef plus SUB_BITS. A shortened
        // prefix also needs a temporary slice before appending.
        let source_bits = source(first)
            .ok()
            .and_then(|term| with_binary(term, |_, _, bits| bits));
        if source_bits.is_some_and(|length| size_of(first).ok() != Some(length)) {
            16
        } else {
            8
        }
    } else if bits.div_ceil(8) <= 64 {
        2 + bits.div_ceil(8).div_ceil(8)
    } else {
        8
    };
    Ok(BinSize { bits, heap_words })
}

#[inline]
fn bit(bytes: &[u8], position: usize) -> u8 {
    (bytes[position / 8] >> (7 - position % 8)) & 1
}
#[inline]
fn put_bit(bytes: &mut [u8], position: usize, value: u8) {
    bytes[position / 8] |= value << (7 - position % 8);
}

fn copy_bits(dst: &mut [u8], dst_pos: usize, src: &[u8], src_pos: usize, count: usize) {
    // Port of erts/emulator/beam/erl_bits.c:2389 (erts_copy_bits_fwd), OTP-29.1.1.
    if dst_pos.is_multiple_of(8) && src_pos.is_multiple_of(8) && count.is_multiple_of(8) {
        dst[dst_pos / 8..(dst_pos + count) / 8]
            .copy_from_slice(&src[src_pos / 8..(src_pos + count) / 8]);
    } else {
        for i in 0..count {
            put_bit(dst, dst_pos + i, bit(src, src_pos + i));
        }
    }
}

fn write_int(dst: &mut [u8], pos: usize, bits: usize, value: &BigInt, little: bool) {
    // Port of erts/emulator/beam/erl_bits.c:926/1031 (put_integer_be/le), OTP-29.1.1.
    if bits == 0 {
        return;
    }
    // Two's complement truncation is the same for signed and unsigned construction.
    let modulus = BigInt::from(1u8) << bits;
    let mut value = value % &modulus;
    if value.sign() == Sign::Minus {
        value += &modulus;
    }
    let unsigned = value.to_biguint().unwrap_or_else(BigUint::zero);
    if little {
        // Port of erts/emulator/beam/erl_bits.c:686 (fmt_small_le), OTP-29.1.1.
        // The final partial little-endian byte keeps its bits at the high end.
        let bytes = unsigned.to_bytes_le();
        for i in 0..bits {
            let b = bytes.get(i / 8).copied().unwrap_or(0);
            let width = (bits - (i / 8) * 8).min(8);
            put_bit(dst, pos + i, (b >> (width - 1 - i % 8)) & 1);
        }
    } else {
        let bytes = unsigned.to_bytes_be();
        for i in 0..bits {
            let from_lsb = bits - 1 - i;
            let idx = from_lsb / 8;
            let b = bytes
                .get(bytes.len().wrapping_sub(1 + idx))
                .copied()
                .unwrap_or(0);
            put_bit(dst, pos + i, (b >> (from_lsb % 8)) & 1);
        }
    }
}

/// Build one UTF segment directly in the young heap without constructing a segment vector.
// Port of erts/emulator/beam/erl_bits.c:1162/1222 (UTF scalar construction), OTP-29.1.1.
pub fn create_utf_segment<H: HeapAlloc>(
    value: Term,
    ty: SegType,
    flags: SegFlags,
    heap: &mut H,
) -> Result<Term, BitsError> {
    if !matches!(ty, SegType::Utf8 | SegType::Utf16 | SegType::Utf32) {
        return Err(BitsError::BadArg { segment: 1 });
    }
    let segment = Segment {
        ty,
        index: 1,
        unit: 0,
        flags,
        value: SegmentValue::Term(value),
        size: SegSize::Units(0),
    };
    let bits = size_of(&segment)?;
    let mut bytes = [0; 4];
    write_segments(std::slice::from_ref(&segment), &mut bytes, 0)?;
    TermBuilder::new(heap)
        .bitstring(&bytes, bits)
        .map_err(|error| term_error(error, 1, 3))
}

/// Concatenate byte-aligned payloads directly into their final heap or Binary allocation.
// Port of erts/emulator/beam/erl_bits.c:72,1812-1917 (`GROW_PROC_BIN_SIZE` and
// `erts_bs_append_checked`), OTP-29.1.1.
pub fn concat_byte_binary<H: HeapAlloc>(
    prefix: Term,
    extra: Term,
    heap: &mut H,
) -> Result<Option<Term>, BitsError> {
    let Some(result) = with_binary(prefix, |left, left_start, left_bits| {
        if !left_start.is_multiple_of(8) || !left_bits.is_multiple_of(8) {
            return Ok(None);
        }
        let left = &left[left_start / 8..left_start / 8 + left_bits / 8];
        let Some(result) = with_binary(extra, |right, right_start, right_bits| {
            if !right_start.is_multiple_of(8) || !right_bits.is_multiple_of(8) {
                return Ok(None);
            }
            let right = &right[right_start / 8..right_start / 8 + right_bits / 8];
            let total = left
                .len()
                .checked_add(right.len())
                .ok_or(BitsError::SystemLimit { segment: 1 })?;
            let mut builder = TermBuilder::new(heap);
            let term = if total <= 64 {
                builder.heap_bitstring_from_parts(left, right, total * 8)
            } else {
                let capacity = grow_proc_binary_size(total)?.max(256);
                builder.writable_binary_from_parts(left, right, capacity)
            }
            .map_err(|error| term_error(error, 1, 8))?;
            Ok(Some(term))
        }) else {
            return Ok(None);
        };
        result
    }) else {
        return Ok(None);
    };
    result
}

/// Concatenate two whole byte binaries into the storage that will hold the result.
// Port of erts/emulator/beam/jit/arm/instr_bs.cpp:1442-1845 (`bs_create_bin`), OTP-29.1.1.
fn concat_regular_byte_binaries<H: HeapAlloc>(
    prefix: Term,
    extra: Term,
    heap: &mut H,
) -> Result<Option<Term>, BitsError> {
    let Some(prefix_bits) = bit_size(prefix) else {
        return Ok(None);
    };
    let Some(extra_bits) = bit_size(extra) else {
        return Ok(None);
    };
    if !prefix_bits.is_multiple_of(8) || !extra_bits.is_multiple_of(8) {
        return Ok(None);
    }
    let total = prefix_bits
        .checked_add(extra_bits)
        .ok_or(BitsError::SystemLimit { segment: 1 })?;
    let Some(result) = with_binary(prefix, |left, left_start, left_bits| {
        if !left_start.is_multiple_of(8) || left_bits != prefix_bits {
            return Ok(None);
        }
        let left = &left[left_start / 8..left_start / 8 + left_bits / 8];
        let Some(result) = with_binary(extra, |right, right_start, right_bits| {
            if !right_start.is_multiple_of(8) || right_bits != extra_bits {
                return Ok(None);
            }
            let right = &right[right_start / 8..right_start / 8 + right_bits / 8];
            let mut builder = TermBuilder::new(heap);
            let term = if total / 8 <= 64 {
                builder.heap_bitstring_from_parts(left, right, total)
            } else {
                builder.binary_from_fn(total / 8, |output| {
                    output[..left.len()].copy_from_slice(left);
                    output[left.len()..].copy_from_slice(right);
                })
            }
            .map_err(|error| term_error(error, 1, 8))?;
            Ok(Some(term))
        }) else {
            return Ok(None);
        };
        result
    }) else {
        return Ok(None);
    };
    result
}

pub fn create_bin<H: HeapAlloc>(segments: &[Segment<'_>], heap: &mut H) -> Result<Term, BitsError> {
    // Port of erts/emulator/beam/erl_bits.c:1523 (new binary construction), OTP-29.1.1.
    if let [segment] = segments
        && matches!(segment.ty, SegType::Utf8 | SegType::Utf16 | SegType::Utf32)
    {
        // Port of erts/emulator/beam/erl_bits.c:1162/1222 (single UTF segment), OTP-29.1.1.
        let ch = codepoint(segment)?;
        let mut bytes = [0u8; 4];
        let bits = match segment.ty {
            SegType::Utf8 => {
                let encoded = ch.encode_utf8(&mut bytes);
                encoded.len() * 8
            }
            SegType::Utf16 => {
                let mut words = [0u16; 2];
                let encoded = ch.encode_utf16(&mut words);
                for (index, word) in encoded.iter().enumerate() {
                    let pair = if segment.flags.little() {
                        word.to_le_bytes()
                    } else {
                        word.to_be_bytes()
                    };
                    bytes[index * 2..index * 2 + 2].copy_from_slice(&pair);
                }
                encoded.len() * 16
            }
            SegType::Utf32 => {
                let bytes = if segment.flags.little() {
                    (ch as u32).to_le_bytes()
                } else {
                    (ch as u32).to_be_bytes()
                };
                return TermBuilder::new(heap)
                    .bitstring(&bytes, 32)
                    .map_err(|e| term_error(e, segment.index, 8));
            }
            _ => unreachable!(),
        };
        return TermBuilder::new(heap)
            .bitstring(&bytes[..bits / 8], bits)
            .map_err(|e| term_error(e, segment.index, 2 + bits.div_ceil(64)));
    }
    if let [segment] = segments
        && segment.ty == SegType::Integer
        && let SegmentValue::Term(value) = segment.value
        && let Some(value) = value.as_small()
        && let SegSize::Units(units) = segment.size
        && let Some(bits) = units
            .checked_mul(u64::from(segment.unit))
            .filter(|bits| *bits <= arinsal_term::MAX_SMALL as u64 && *bits <= isize::MAX as u64)
        && bits <= 64
        && bits.is_multiple_of(8)
    {
        // Port of erts/emulator/beam/erl_bits.c:926/951/1056 (aligned small integer byte stores), OTP-29.1.1.
        let bits = bits as usize;
        let mut bytes = [0u8; 8];
        let count = bits / 8;
        let raw = value as u64;
        for (i, byte) in bytes.iter_mut().enumerate().take(count) {
            let shift = if segment.flags.little() {
                i * 8
            } else {
                (count - 1 - i) * 8
            };
            *byte = (raw >> shift) as u8;
        }
        return TermBuilder::new(heap)
            .bitstring(&bytes[..count], bits)
            .map_err(|e| term_error(e, segment.index, 2 + count.div_ceil(8)));
    }
    let size = create_bin_size(segments)?;
    if let [prefix, extra] = segments
        && prefix.ty == SegType::Binary
        && extra.ty == SegType::Binary
        && prefix.unit == 8
        && extra.unit == 8
        && matches!(prefix.size, SegSize::All)
        && matches!(extra.size, SegSize::All)
        && let SegmentValue::Term(prefix) = prefix.value
        && let SegmentValue::Term(extra) = extra.value
        && let Some(result) = concat_regular_byte_binaries(prefix, extra, heap)?
    {
        return Ok(result);
    }
    if let Some(first) = segments.first()
        && matches!(first.ty, SegType::Append | SegType::PrivateAppend)
    {
        let mut prefix = source(first)?;
        let prefix_bits = size_of(first)?;
        // An explicit size can select a prefix shorter than the source.
        if prefix_bits != with_binary(prefix, |_, _, bits| bits).unwrap() {
            prefix = TermBuilder::new(heap)
                .sub_binary(prefix, 0, prefix_bits)
                .map_err(|e| term_error(e, first.index, 8))?;
        }
        let suffix_bits = size.bits - prefix_bits;
        // A fresh (non-writable) prefix is copied once into the result buffer, then the
        // remaining segments are written there. Writable sources keep append_inner, which
        // extends the existing buffer and only copies the suffix.
        // Port of erts/emulator/beam/erl_bits.c:1725 (erts_bs_append_checked), OTP-29.1.1.
        if !is_writable_binary(prefix) {
            // One buffer and two payload copies, matching erts_bs_append_checked
            // plus erts_bs_put_binary for `<<Bin/binary, Bin2/binary>>`.
            if let [suffix] = &segments[1..]
                && suffix.ty == SegType::Binary
                && matches!(suffix.size, SegSize::All)
                && let Ok(extra) = source(suffix)
                && let Some(built) = concat_byte_binary(prefix, extra, heap)?
            {
                return Ok(built);
            }
            let total_bytes = size.bits.div_ceil(8);
            let mut bytes = Vec::with_capacity(total_bytes.max(256));
            bytes.resize(total_bytes, 0);
            with_binary(prefix, |payload, start, _| {
                copy_bits(&mut bytes, 0, payload, start, prefix_bits);
            })
            .ok_or(BitsError::BadArg {
                segment: first.index,
            })?;
            write_segments(&segments[1..], &mut bytes, prefix_bits)?;
            return TermBuilder::new(heap)
                .writable_from_vec(bytes, size.bits)
                .map_err(|e| term_error(e, first.index, 8));
        }
        let mut suffix = vec![0; suffix_bits.div_ceil(8)];
        write_segments(&segments[1..], &mut suffix, 0)?;
        return append_inner(
            prefix,
            &suffix,
            suffix_bits,
            heap,
            first.ty == SegType::PrivateAppend,
        );
    }
    let mut bytes = vec![0u8; size.bits.div_ceil(8)];
    write_segments(segments, &mut bytes, 0)?;
    TermBuilder::new(heap)
        .bitstring(&bytes, size.bits)
        .map_err(|e| term_error(e, segments.last().map_or(0, |s| s.index), size.heap_words))
}

fn fresh_append<H: HeapAlloc>(
    source: Term,
    prefix_bits: usize,
    total_bits: usize,
    heap: &mut H,
    index: usize,
    private: bool,
) -> Result<Term, BitsError> {
    // Port of erts/emulator/beam/erl_bits.c:1812 (copy-on-write append), OTP-29.1.1.
    writable_finalize(source);
    let mut bytes = vec![0u8; total_bits.div_ceil(8)];
    with_binary(source, |payload, start, _| {
        copy_bits(&mut bytes, 0, payload, start, prefix_bits);
    })
    .ok_or(BitsError::BadArg { segment: index })?;
    let capacity = total_bits.div_ceil(8).max(256);
    let mut builder = TermBuilder::new(heap);
    let result = if private {
        builder.writable_binary_in_fragment(&bytes, total_bits, capacity, total_bits)
    } else {
        builder.writable_binary_with_apparent_size(&bytes, total_bits, capacity, total_bits)
    };
    result.map_err(|e| term_error(e, index, 8))
}

fn write_segments(
    segments: &[Segment<'_>],
    bytes: &mut [u8],
    mut pos: usize,
) -> Result<(), BitsError> {
    // Port of erts/emulator/beam/erl_bits.c:1162/1222/1285/1311/1341 (put UTF/binary/float), OTP-29.1.1.
    for segment in segments {
        let bits = size_of(segment)?;
        match segment.ty {
            SegType::Integer => write_int(
                bytes,
                pos,
                bits,
                &as_integer(source(segment)?).unwrap(),
                segment.flags.little(),
            ),
            SegType::Float => {
                // Port of erts/emulator/beam/erl_bits.c:1341 (erts_bs_put_float), OTP-29.1.1.
                let value = as_float(source(segment)?).unwrap();
                let raw = match bits {
                    16 => u64::from(f64_to_f16(value)),
                    32 => u64::from((value as f32).to_bits()),
                    64 => value.to_bits(),
                    _ => unreachable!(),
                };
                write_int(bytes, pos, bits, &BigInt::from(raw), segment.flags.little());
            }
            SegType::Binary | SegType::Append | SegType::PrivateAppend => {
                let term = source(segment)?;
                writable_finalize(term);
                with_binary(term, |payload, start, _| {
                    copy_bits(bytes, pos, payload, start, bits);
                })
                .unwrap();
            }
            SegType::String => {
                let SegmentValue::String(s) = segment.value else {
                    unreachable!()
                };
                copy_bits(bytes, pos, s, 0, bits);
            }
            SegType::Utf8 | SegType::Utf16 | SegType::Utf32 => {
                // Port of erts/emulator/beam/erl_bits.c:1162/1222 (UTF scalar validation and encoding), OTP-29.1.1.
                let ch = codepoint(segment)?;
                let mut buffer = [0u8; 4];
                let encoded: &[u8] = match segment.ty {
                    SegType::Utf8 => ch.encode_utf8(&mut buffer).as_bytes(),
                    SegType::Utf16 => {
                        let mut words = [0u16; 2];
                        let result = ch.encode_utf16(&mut words);
                        for (i, word) in result.iter().enumerate() {
                            let pair = if segment.flags.little() {
                                word.to_le_bytes()
                            } else {
                                word.to_be_bytes()
                            };
                            buffer[i * 2..i * 2 + 2].copy_from_slice(&pair);
                        }
                        &buffer[..bits / 8]
                    }
                    SegType::Utf32 => {
                        buffer = if segment.flags.little() {
                            (ch as u32).to_le_bytes()
                        } else {
                            (ch as u32).to_be_bytes()
                        };
                        &buffer
                    }
                    _ => unreachable!(),
                };
                copy_bits(bytes, pos, encoded, 0, bits);
            }
        }
        pos += bits;
    }
    Ok(())
}

/// Build `bs_init_writable`'s empty binary with OTP's default capacity.
pub fn init_writable<H: HeapAlloc>(heap: &mut H) -> Result<Term, BitsError> {
    init_writable_with_size(None, heap)
}

/// Build `bs_init_writable`'s empty binary using its optional byte capacity.
// Port of erts/emulator/beam/erl_bits.c:2021-2046 (`erts_bs_init_writable`), OTP-29.1.1.
pub fn init_writable_with_size<H: HeapAlloc>(
    size: Option<i64>,
    heap: &mut H,
) -> Result<Term, BitsError> {
    let capacity = size
        .filter(|size| *size >= 0)
        .and_then(|size| usize::try_from(size).ok())
        .unwrap_or(1024);
    let apparent_size_bits = capacity
        .checked_mul(8)
        .filter(|size| *size <= isize::MAX as usize)
        .ok_or(BitsError::SystemLimit { segment: 0 })?;
    TermBuilder::new(heap)
        .writable_binary_with_apparent_size(&[], 0, capacity, apparent_size_bits)
        .map_err(|e| term_error(e, 0, 8))
}

/// Append bits through `bs_private_append`. The caller must ensure the source
/// is its sole observable term handle, as the compiler does for private append.
pub fn private_append<H: HeapAlloc>(
    source: Term,
    suffix: &[u8],
    suffix_bits: usize,
    heap: &mut H,
) -> Result<Term, BitsError> {
    append_inner(source, suffix, suffix_bits, heap, true)
}

/// Append an eight-bit integer to a private writable binary.
/// The integer follows BEAM's low-eight-bit truncation rule.
pub fn private_append_byte<H: HeapAlloc>(
    source: Term,
    value: i64,
    heap: &mut H,
) -> Result<Term, BitsError> {
    private_append(source, &[value as u8], 8, heap)
}

/// Append bits through `bs_append`, preserving the old term's visible length.
pub fn append<H: HeapAlloc>(
    source: Term,
    suffix: &[u8],
    suffix_bits: usize,
    heap: &mut H,
) -> Result<Term, BitsError> {
    append_inner(source, suffix, suffix_bits, heap, false)
}

fn append_inner<H: HeapAlloc>(
    source: Term,
    suffix: &[u8],
    suffix_bits: usize,
    heap: &mut H,
    private: bool,
) -> Result<Term, BitsError> {
    // Port of erts/emulator/beam/erl_bits.c:1725/1928 (checked/private append), OTP-29.1.1.
    if suffix_bits > suffix.len().saturating_mul(8) {
        return Err(BitsError::BadArg { segment: 1 });
    }
    // Length only. The borrow ends before the writer is extended.
    let prefix = with_binary(source, |_, _, bits| bits).ok_or(BitsError::BadArg { segment: 1 })?;
    let total = prefix
        .checked_add(suffix_bits)
        .filter(|n| *n <= isize::MAX as usize)
        .ok_or(BitsError::SystemLimit { segment: 1 })?;
    if suffix_bits == 0 {
        return Ok(source);
    }
    let output =
        if private && writable_extend_private(source, total).map_err(|e| term_error(e, 1, 8))? {
            heap.update_writable_binary_overhead(source, prefix, total);
            source
        } else if !private {
            match TermBuilder::new(heap)
                .writable_successor(source, total)
                .map_err(|e| term_error(e, 1, 5))?
            {
                Some(next) => next,
                None => fresh_append(source, prefix, total, heap, 1, false)?,
            }
        } else {
            fresh_append(source, prefix, total, heap, 1, true)?
        };
    // SAFETY: output is the active unique writer and no source view is live.
    let bytes = unsafe { writable_bytes_mut(output) }.ok_or(BitsError::BadArg { segment: 1 })?;
    copy_bits(bytes, prefix, suffix, 0, suffix_bits);
    Ok(output)
}

// Port of erts/emulator/beam/erl_bits.c:439 (f64_to_f16), OTP-29.1.1.
fn f64_to_f16(value: f64) -> u16 {
    let raw = value.to_bits();
    let sign = ((raw >> 48) & 0x8000) as u16;
    let exp = ((raw >> 52) & 0x7ff) as i32;
    if exp == 0 {
        return sign;
    }
    let e = exp - 1023;
    let mantissa = (raw & ((1u64 << 52) - 1)) | (1u64 << 52);
    if e >= -14 {
        if e > 15 {
            return sign | 0x7c00;
        }
        let mut kept = mantissa >> 42;
        let guard = (mantissa >> 41) & 1 != 0;
        let sticky = mantissa & ((1u64 << 41) - 1) != 0;
        if guard && (sticky || kept & 1 != 0) {
            kept += 1;
        }
        let mut exponent = e;
        if kept == 2048 {
            kept = 1024;
            exponent += 1;
        }
        if exponent > 15 {
            return sign | 0x7c00;
        }
        sign | (((exponent + 15) as u16) << 10) | (kept as u16 & 0x3ff)
    } else {
        let shift = 28 - e;
        if shift > 63 {
            return sign;
        }
        let mut kept = mantissa >> shift;
        let guard = (mantissa >> (shift - 1)) & 1 != 0;
        let sticky = mantissa & ((1u64 << (shift - 1)) - 1) != 0;
        if guard && (sticky || kept & 1 != 0) {
            kept += 1;
        }
        sign | kept as u16
    }
}

fn f16_to_f64(raw: u16) -> f64 {
    // Port of erts/emulator/beam/erl_bits.c:533 (f16_to_f32 conversion semantics), OTP-29.1.1.
    let sign = if raw & 0x8000 != 0 { -1.0 } else { 1.0 };
    let exponent = (raw >> 10) & 0x1f;
    let mantissa = raw & 0x3ff;
    match exponent {
        0 => sign * f64::from(mantissa) * 2f64.powi(-24),
        31 => {
            if mantissa == 0 {
                sign * f64::INFINITY
            } else {
                f64::NAN
            }
        }
        _ => sign * f64::from(1024 + mantissa) * 2f64.powi(i32::from(exponent) - 25),
    }
}

/// Start `bs_start_match4`, returning a heap term that survives register moves.
pub fn start_match<H: HeapAlloc>(source: Term, heap: &mut H) -> Result<Option<Term>, BitsError> {
    // Port of erts/emulator/beam/erl_bits.c:81 (erts_bs_start_match_3), OTP-29.1.1.
    if source.classify() != arinsal_term::TermKind::Bitstring {
        return Ok(None);
    }
    TermBuilder::new(heap)
        .match_context(source)
        .map(Some)
        .map_err(|e| term_error(e, 0, 5))
}

/// Encode `bs_get_position` as a small integer, or a positive bignum if needed.
pub fn get_position<H: HeapAlloc>(context: Term, heap: &mut H) -> Result<Term, BitsError> {
    let position = match_position(context).ok_or(BitsError::BadArg { segment: 0 })?;
    if let Ok(value) = i64::try_from(position)
        && let Some(small) = Term::small(value)
    {
        return Ok(small);
    }
    TermBuilder::new(heap)
        .int_from_bigint(&BigInt::from(position))
        .map_err(|e| term_error(e, 0, 2))
}

/// Restore a `bs_get_position` term into a live context.
pub fn set_position_term(context: Term, position: Term) -> bool {
    let offset = if let Some(small) = position.as_small() {
        usize::try_from(small).ok()
    } else {
        let owned = owned_number(position);
        match &owned {
            Some(OwnedTerm::BigInt(value)) => value.to_usize(),
            _ => None,
        }
    };
    offset.is_some_and(|offset| set_match_position(context, offset))
}

/// Read the common unsigned 32-bit big-endian match field from a context.
/// The cursor advances only after the whole field is available.
pub fn match_u32_be(context: Term) -> Option<u32> {
    if !is_match_context(context) {
        return None;
    }
    context.update(|cursor| {
        if cursor.remaining() < 32 {
            return None;
        }
        let value = cursor.read_u64(32) as u32;
        cursor.position += 32;
        Some(value)
    })
}

/// Read a bounded unsigned big-endian field from an existing match context.
/// A failed bound, unit, or field check leaves the context unchanged.
pub fn match_uint_be(
    context: Term,
    ensure_bits: usize,
    unit: usize,
    field_bits: usize,
) -> Option<u32> {
    if !is_match_context(context) || field_bits > 32 {
        return None;
    }
    context.update(|cursor| {
        if !cursor.ensure_at_least(ensure_bits, unit) || field_bits > cursor.remaining() {
            return None;
        }
        let value = cursor.read_u64(field_bits) as u32;
        cursor.position += field_bits;
        Some(value)
    })
}

// An operation-local cursor. `bytes` is borrowed from the match context for
// the duration of one command; durable state lives in the SUB_BITS term.
struct Cursor<'a> {
    source: Term,
    bytes: &'a [u8],
    start: usize,
    position: usize,
    end: usize,
}

#[inline]
fn with_cursor<R>(term: Term, f: impl FnOnce(&mut Cursor<'_>) -> R) -> R {
    assert!(is_match_context(term));
    with_binary(term, |bytes, start, len| {
        let mut cursor = Cursor {
            source: term,
            bytes,
            start,
            position: start,
            end: start + len,
        };
        f(&mut cursor)
    })
    .expect("match context")
}

impl Cursor<'_> {
    /// Bits remaining in the context.
    #[inline]
    pub fn remaining(&self) -> usize {
        self.end - self.position
    }
    /// Significant bits from the cursor, MSB first. Used for unaligned fields.
    fn bit_iter(&self, count: usize) -> impl Iterator<Item = u8> + '_ {
        let bytes = self.bytes;
        let origin = self.position;
        (0..count).map(move |i| bit(bytes, origin + i))
    }
    /// `ensure_at_least`: enough bits and remaining tail divisible by `unit`.
    #[inline]
    pub fn ensure_at_least(&self, bits: usize, unit: usize) -> bool {
        unit != 0 && self.remaining() >= bits && (self.remaining() - bits).is_multiple_of(unit)
    }
    /// `ensure_exactly` and `bs_test_tail2`.
    #[inline]
    pub fn ensure_exactly(&self, bits: usize) -> bool {
        self.remaining() == bits
    }

    /// Compare a constant bit string without materializing a sub-bitstring.
    // Port of erts/emulator/beam/erl_bits.c:2293-2375 (erts_cmp_bits__), OTP-29.1.1.
    fn match_string(&mut self, expected: &[u8], bits: usize) -> bool {
        if bits > self.remaining() || bits > expected.len().saturating_mul(8) {
            return false;
        }

        let byte_offset = self.position / 8;
        let bit_offset = self.position % 8;
        let whole_bytes = bits / 8;
        for (index, expected_byte) in expected.iter().enumerate().take(whole_bytes) {
            let actual = if bit_offset == 0 {
                self.bytes[byte_offset + index]
            } else {
                (self.bytes[byte_offset + index] << bit_offset)
                    | (self.bytes[byte_offset + index + 1] >> (8 - bit_offset))
            };
            if actual != *expected_byte {
                return false;
            }
        }

        let remaining_bits = bits % 8;
        let tail_start = whole_bytes * 8;
        for index in 0..remaining_bits {
            let wanted = (expected[whole_bytes] >> (7 - index)) & 1;
            if bit(self.bytes, self.position + tail_start + index) != wanted {
                return false;
            }
        }

        self.position += bits;
        true
    }
    /// `bs_test_unit`: remaining bit count is divisible by `unit`.
    #[inline]
    pub fn test_unit(&self, unit: usize) -> bool {
        unit != 0 && self.remaining().is_multiple_of(unit)
    }
    /// `skip` or `bs_skip_bits2`; a failed match leaves the cursor unchanged.
    #[inline]
    pub fn skip(&mut self, bits: usize) -> bool {
        if bits > self.remaining() {
            return false;
        }
        self.position += bits;
        true
    }
    /// `bs_match` equality command; a failed comparison leaves the cursor unchanged.
    pub fn match_integer(&mut self, bits: usize, value: u64) -> bool {
        if bits > 64 || bits > self.remaining() {
            return false;
        }
        let got = self.read_u64(bits);
        if got != value {
            return false;
        }
        self.position += bits;
        true
    }
    fn read_u64(&self, bits: usize) -> u64 {
        if bits == 0 {
            return 0;
        }
        if self.position.is_multiple_of(8) && bits.is_multiple_of(8) && bits <= 64 {
            let bytes = self.bytes;
            if bits == 8 {
                return u64::from(bytes[self.position / 8]);
            }
            if bits == 32 {
                let start = self.position / 8;
                return u64::from(u32::from_be_bytes(
                    bytes[start..start + 4].try_into().unwrap(),
                ));
            }
            return bytes[self.position / 8..(self.position + bits) / 8]
                .iter()
                .fold(0u64, |v, &b| (v << 8) | u64::from(b));
        }
        self.bit_iter(bits)
            .fold(0u64, |value, bit| (value << 1) | u64::from(bit))
    }
    /// Extract a signed or unsigned integer field. A short field returns `Ok(None)`.
    pub fn get_integer<H: HeapAlloc>(
        &mut self,
        bits: usize,
        flags: SegFlags,
        heap: &mut H,
    ) -> Result<Option<Term>, BitsError> {
        // Port of erts/emulator/beam/erl_bits.c:170 (erts_bs_get_integer_2), OTP-29.1.1.
        if bits > self.remaining() {
            return Ok(None);
        }
        if bits <= 59 {
            // This common case includes `binary_parse`'s 32-bit frame length.
            // It needs no host allocation and no term heap words.
            let raw = self.read_small_integer(bits, flags.little());
            let signed = if flags.signed && bits != 0 && raw & (1u64 << (bits - 1)) != 0 {
                (raw as i64) - (1i64 << bits)
            } else {
                raw as i64
            };
            self.position += bits;
            return Ok(Some(Term::small(signed).unwrap()));
        }
        let value = if bits == 0 {
            BigInt::zero()
        } else if bits <= 64 {
            let raw = self.read_small_integer(bits, flags.little());
            let unsigned = BigInt::from(raw);
            if flags.signed && raw & (1u64 << (bits - 1)) != 0 {
                unsigned - (BigInt::from(1u8) << bits)
            } else {
                unsigned
            }
        } else {
            // Port of erts/emulator/beam/erl_bits.c:273 (temporary bignum byte buffer), OTP-29.1.1.
            let mut bytes = vec![0u8; bits.div_ceil(8)];
            copy_bits(&mut bytes, 0, self.bytes, self.position, bits);
            let mut unsigned = if flags.little() {
                if !bits.is_multiple_of(8) {
                    let last = bytes.last_mut().unwrap();
                    *last >>= 8 - bits % 8;
                }
                BigInt::from_bytes_le(Sign::Plus, &bytes)
            } else {
                BigInt::from_bytes_be(Sign::Plus, &bytes) >> (bytes.len() * 8 - bits)
            };
            if flags.signed && (&unsigned & (BigInt::from(1u8) << (bits - 1))) != BigInt::zero() {
                unsigned -= BigInt::from(1u8) << bits;
            }
            unsigned
        };
        let term = match TermBuilder::new(heap).int_from_bigint(&value) {
            Ok(term) => term,
            // Port of erts/emulator/beam/erl_bits.c:341-346 (oversized bignum
            // extraction returns THE_NON_VALUE), OTP-29.1.1.
            Err(TermError::SystemLimit) => {
                self.position += bits;
                return Ok(None);
            }
            Err(error) => return Err(term_error(error, 0, 1 + bits.div_ceil(64))),
        };
        self.position += bits;
        Ok(Some(term))
    }
    fn read_small_integer(&self, bits: usize, little: bool) -> u64 {
        // Port of erts/emulator/beam/erl_bits.c:204 (aligned/unaligned small integer paths), OTP-29.1.1.
        if !little {
            if bits == 32 && !self.position.is_multiple_of(8) {
                // Port of erts/emulator/beam/erl_bits.c:250-286 (unaligned small big-endian extraction), OTP-29.1.1.
                let offset = self.position % 8;
                let start = self.position / 8;
                let value = (u64::from(self.bytes[start]) << 32)
                    | (u64::from(self.bytes[start + 1]) << 24)
                    | (u64::from(self.bytes[start + 2]) << 16)
                    | (u64::from(self.bytes[start + 3]) << 8)
                    | u64::from(self.bytes[start + 4]);
                return (value >> (8 - offset)) & u64::from(u32::MAX);
            }
            return self.read_u64(bits);
        }
        let mut value = 0u64;
        for i in 0..bits {
            let width = (bits - (i / 8) * 8).min(8);
            let shift = (i / 8) * 8 + width - 1 - i % 8;
            value |= u64::from(bit(self.bytes, self.position + i)) << shift;
        }
        value
    }
    /// Extract a bitstring slice. The caller may GC and retry on `HeapFull`.
    pub fn get_binary<H: HeapAlloc>(
        &mut self,
        bits: usize,
        heap: &mut H,
    ) -> Result<Option<Term>, BitsError> {
        // Port of erts/emulator/beam/erl_bits.c:306 (erts_bs_get_binary_2), OTP-29.1.1.
        if bits > self.remaining() {
            return Ok(None);
        }
        let relative = self.position - self.start;
        let term = TermBuilder::new(heap)
            .sub_binary(self.source, relative, bits)
            .map_err(|e| term_error(e, 0, binary_slice_words(bits)))?;
        self.position += bits;
        Ok(Some(term))
    }
    /// Return the remaining bitstring without advancing (`bs_get_tail`).
    pub fn get_tail<H: HeapAlloc>(&self, heap: &mut H) -> Result<Term, BitsError> {
        // Port of erts/emulator/beam/erl_bits.c:349 (erts_bs_get_binary_all_2), OTP-29.1.1.
        let bits = self.remaining();
        TermBuilder::new(heap)
            .sub_binary(self.source, self.position - self.start, bits)
            .map_err(|e| term_error(e, 0, binary_slice_words(bits)))
    }
    /// `bs_match` `get_tail` command, including its unit constraint.
    pub fn get_tail_unit<H: HeapAlloc>(
        &self,
        unit: usize,
        heap: &mut H,
    ) -> Result<Option<Term>, BitsError> {
        if !self.test_unit(unit) {
            return Ok(None);
        }
        self.get_tail(heap).map(Some)
    }
    /// Extract binary16, binary32, or binary64; malformed or nonfinite values fail.
    pub fn get_float<H: HeapAlloc>(
        &mut self,
        bits: usize,
        flags: SegFlags,
        heap: &mut H,
    ) -> Result<Option<Term>, BitsError> {
        // Port of erts/emulator/beam/erl_bits.c:456 (erts_bs_get_float_2), OTP-29.1.1.
        if !matches!(bits, 16 | 32 | 64) || bits > self.remaining() {
            return Ok(None);
        }
        let mut raw = [0u8; 8];
        copy_bits(&mut raw, 0, self.bytes, self.position, bits);
        let field = &raw[..bits / 8];
        let mut value = 0u64;
        if flags.little() {
            for (i, &b) in field.iter().enumerate() {
                value |= u64::from(b) << (i * 8);
            }
        } else {
            for &b in field {
                value = (value << 8) | u64::from(b);
            }
        }
        let f = match bits {
            16 => f16_to_f64(value as u16),
            32 => f64::from(f32::from_bits(value as u32)),
            _ => f64::from_bits(value),
        };
        if !f.is_finite() {
            return Ok(None);
        }
        let term = TermBuilder::new(heap)
            .float(f)
            .map_err(|e| term_error(e, 0, 2))?;
        self.position += bits;
        Ok(Some(term))
    }
    /// Extract one UTF-8 scalar; invalid encodings fail without advancing.
    pub fn get_utf8(&mut self) -> Option<Term> {
        // Port of erts/emulator/beam/erl_bits.c:580 (UTF-8 match), OTP-29.1.1.
        if self.remaining() < 8 {
            return None;
        }
        let first = self.read_u64(8) as u8;
        let count = match first {
            0..=0x7f => 1,
            0xc2..=0xdf => 2,
            0xe0..=0xef => 3,
            0xf0..=0xf4 => 4,
            _ => return None,
        };
        if self.remaining() < count * 8 {
            return None;
        }
        let mut bytes = [0u8; 4];
        for (i, byte) in bytes.iter_mut().enumerate().take(count) {
            for j in 0..8 {
                *byte = (*byte << 1) | bit(self.bytes, self.position + i * 8 + j);
            }
        }
        let s = std::str::from_utf8(&bytes[..count]).ok()?;
        let ch = s.chars().next().unwrap();
        self.position += count * 8;
        Some(Term::small(ch as i64).unwrap())
    }
    /// Extract one UTF-16 scalar in the requested byte order.
    pub fn get_utf16(&mut self, flags: SegFlags) -> Option<Term> {
        // Port of erts/emulator/beam/erl_bits.c:622 (UTF-16 match), OTP-29.1.1.
        if self.remaining() < 16 {
            return None;
        }
        let first = self.read_u64(16) as u16;
        let first = if flags.little() {
            first.swap_bytes()
        } else {
            first
        };
        let (code, count) = if (0xd800..=0xdbff).contains(&first) {
            if self.remaining() < 32 {
                return None;
            }
            let mut second = 0u16;
            for i in 0..16 {
                second = (second << 1) | u16::from(bit(self.bytes, self.position + 16 + i));
            }
            if flags.little() {
                second = second.swap_bytes();
            }
            if !(0xdc00..=0xdfff).contains(&second) {
                return None;
            }
            (
                0x10000 + ((u32::from(first) - 0xd800) << 10) + u32::from(second) - 0xdc00,
                32,
            )
        } else {
            (u32::from(first), 16)
        };
        let ch = char::from_u32(code)?;
        self.position += count;
        Some(Term::small(ch as i64).unwrap())
    }
    /// Extract one UTF-32 scalar in the requested byte order.
    pub fn get_utf32(&mut self, flags: SegFlags) -> Option<Term> {
        // Port of erts/emulator/beam/erl_bits.c:681 (UTF-32 match), OTP-29.1.1.
        if self.remaining() < 32 {
            return None;
        }
        let raw = self.read_u64(32) as u32;
        let code = if flags.little() {
            raw.swap_bytes()
        } else {
            raw
        };
        let ch = char::from_u32(code)?;
        self.position += 32;
        Some(Term::small(ch as i64).unwrap())
    }
    /// Skip one valid UTF-8 scalar (`bs_skip_utf8`).
    pub fn skip_utf8(&mut self) -> bool {
        self.get_utf8().is_some()
    }
    /// Skip one valid UTF-16 scalar (`bs_skip_utf16`).
    pub fn skip_utf16(&mut self, flags: SegFlags) -> bool {
        self.get_utf16(flags).is_some()
    }
    /// Skip one valid UTF-32 scalar (`bs_skip_utf32`).
    pub fn skip_utf32(&mut self, flags: SegFlags) -> bool {
        self.get_utf32(flags).is_some()
    }
}

/// Match instructions operating on a mutable `SUB_BITS` term. Copying the Term
/// word aliases the same cursor, as copying an Erlang register does.
pub trait MatchOps {
    /// Remaining bits.
    fn remaining(&self) -> usize;
    /// Absolute bit offset as encoded by `bs_get_position`.
    fn position(&self) -> usize;
    /// Restore an absolute `bs_get_position` result.
    fn set_position(&self, position: usize) -> bool;
    /// Check a minimum length and tail unit.
    fn ensure_at_least(&self, bits: usize, unit: usize) -> bool;
    /// Check an exact remaining length.
    fn ensure_exactly(&self, bits: usize) -> bool;
    /// Check divisibility of the tail.
    fn test_unit(&self, unit: usize) -> bool;
    /// Advance when enough bits remain.
    fn skip(&self, bits: usize) -> bool;
    /// Match a literal integer field.
    fn match_integer(&self, bits: usize, value: u64) -> bool;
    /// Compare a constant bit string at the current cursor, advancing on success.
    fn match_string(&self, expected: &[u8], bits: usize) -> bool;
    /// Extract an integer field.
    fn get_integer<H: HeapAlloc>(
        &self,
        bits: usize,
        flags: SegFlags,
        heap: &mut H,
    ) -> Result<Option<Term>, BitsError>;
    /// Extract a binary field.
    fn get_binary<H: HeapAlloc>(
        &self,
        bits: usize,
        heap: &mut H,
    ) -> Result<Option<Term>, BitsError>;
    /// Extract the tail without advancing.
    fn get_tail<H: HeapAlloc>(&self, heap: &mut H) -> Result<Term, BitsError>;
    /// Extract the tail if its length fits a unit.
    fn get_tail_unit<H: HeapAlloc>(
        &self,
        unit: usize,
        heap: &mut H,
    ) -> Result<Option<Term>, BitsError>;
    /// Extract a floating point field.
    fn get_float<H: HeapAlloc>(
        &self,
        bits: usize,
        flags: SegFlags,
        heap: &mut H,
    ) -> Result<Option<Term>, BitsError>;
    /// Extract a UTF-8 scalar.
    fn get_utf8(&self) -> Option<Term>;
    /// Extract a UTF-16 scalar.
    fn get_utf16(&self, flags: SegFlags) -> Option<Term>;
    /// Extract a UTF-32 scalar.
    fn get_utf32(&self, flags: SegFlags) -> Option<Term>;
    /// Skip a UTF-8 scalar.
    fn skip_utf8(&self) -> bool;
    /// Skip a UTF-16 scalar.
    fn skip_utf16(&self, flags: SegFlags) -> bool;
    /// Skip a UTF-32 scalar.
    fn skip_utf32(&self, flags: SegFlags) -> bool;
}
impl MatchOps for Term {
    fn remaining(&self) -> usize {
        with_cursor(*self, |cursor| cursor.remaining())
    }
    fn position(&self) -> usize {
        match_position(*self).expect("match context")
    }
    fn set_position(&self, position: usize) -> bool {
        set_match_position(*self, position)
    }
    fn ensure_at_least(&self, bits: usize, unit: usize) -> bool {
        with_cursor(*self, |cursor| cursor.ensure_at_least(bits, unit))
    }
    fn ensure_exactly(&self, bits: usize) -> bool {
        with_cursor(*self, |cursor| cursor.ensure_exactly(bits))
    }
    fn test_unit(&self, unit: usize) -> bool {
        with_cursor(*self, |cursor| cursor.test_unit(unit))
    }
    fn skip(&self, bits: usize) -> bool {
        self.update(|c| c.skip(bits))
    }
    fn match_integer(&self, bits: usize, value: u64) -> bool {
        self.update(|c| c.match_integer(bits, value))
    }
    fn match_string(&self, expected: &[u8], bits: usize) -> bool {
        if !is_match_context(*self) {
            return false;
        }
        let adjustment = arinsal_term::binary_offset_adjustment(*self) * 8;
        self.update(|cursor| {
            let Some(position) =
                match_position(*self).and_then(|position| position.checked_sub(adjustment))
            else {
                return false;
            };
            cursor.position = position;
            cursor.match_string(expected, bits)
        })
    }
    fn get_integer<H: HeapAlloc>(
        &self,
        bits: usize,
        flags: SegFlags,
        heap: &mut H,
    ) -> Result<Option<Term>, BitsError> {
        self.update(|c| c.get_integer(bits, flags, heap))
    }
    fn get_binary<H: HeapAlloc>(
        &self,
        bits: usize,
        heap: &mut H,
    ) -> Result<Option<Term>, BitsError> {
        self.update(|c| c.get_binary(bits, heap))
    }
    fn get_tail<H: HeapAlloc>(&self, heap: &mut H) -> Result<Term, BitsError> {
        with_cursor(*self, |cursor| cursor.get_tail(heap))
    }
    fn get_tail_unit<H: HeapAlloc>(
        &self,
        unit: usize,
        heap: &mut H,
    ) -> Result<Option<Term>, BitsError> {
        with_cursor(*self, |cursor| cursor.get_tail_unit(unit, heap))
    }
    fn get_float<H: HeapAlloc>(
        &self,
        bits: usize,
        flags: SegFlags,
        heap: &mut H,
    ) -> Result<Option<Term>, BitsError> {
        self.update(|c| c.get_float(bits, flags, heap))
    }
    fn get_utf8(&self) -> Option<Term> {
        self.update(|c| c.get_utf8())
    }
    fn get_utf16(&self, flags: SegFlags) -> Option<Term> {
        self.update(|c| c.get_utf16(flags))
    }
    fn get_utf32(&self, flags: SegFlags) -> Option<Term> {
        self.update(|c| c.get_utf32(flags))
    }
    fn skip_utf8(&self) -> bool {
        self.update(|c| c.skip_utf8())
    }
    fn skip_utf16(&self, flags: SegFlags) -> bool {
        self.update(|c| c.skip_utf16(flags))
    }
    fn skip_utf32(&self, flags: SegFlags) -> bool {
        self.update(|c| c.skip_utf32(flags))
    }
}
trait UpdateContext {
    fn update<R>(&self, f: impl FnOnce(&mut Cursor<'_>) -> R) -> R;
}
impl UpdateContext for Term {
    fn update<R>(&self, f: impl FnOnce(&mut Cursor<'_>) -> R) -> R {
        with_cursor(*self, |cursor| {
            let result = f(cursor);
            assert!(set_match_position(
                *self,
                cursor.position + arinsal_term::binary_offset_adjustment(*self) * 8
            ));
            result
        })
    }
}
