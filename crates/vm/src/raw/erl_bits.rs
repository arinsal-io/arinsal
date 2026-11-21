//! Pointer access for OTP's bit construction helpers.
// Port of erts/emulator/beam/erl_bits.c, erl_bits.h, and jit/beam_jit_common.cpp,
// OTP-29.1.1.

use arinsal_alloc::raw::BinaryView;
use arinsal_alloc::typed::BinaryBlock;
use arinsal_beamasm::{ProcessHeader, SchedulerRegisters};
use arinsal_bits::{SegFlags, SegSize, SegType, Segment, SegmentValue};
use arinsal_term::{HeapAlloc, Term, TermBuilder};

const ERTS_ON_HEAP_BITS_LIMIT: usize = 64 * 8;
const ERTS_HEAP_BITS_TAG: u64 = 0x20;
const ERTS_SUB_BITS_HEADER: u64 = (4 << 6) | 0x24;
const ERTS_HEADER_BIN_REF: u64 = (2 << 6) | 0x28;
const ERTS_BOXED_TAG: u64 = 2;
const ERTS_SUB_BITS_FLAG_MUTABLE: u64 = 1 << 0;
const ERTS_SUB_BITS_FLAG_VOLATILE: u64 = 1 << 1;
const ERTS_SUB_BITS_FLAGS_WRITABLE: u64 = ERTS_SUB_BITS_FLAG_MUTABLE | ERTS_SUB_BITS_FLAG_VOLATILE;
const ERTS_BINARY_FLAG_WRITABLE: u64 = 1 << 2;
const ERTS_BINARY_FLAG_ACTIVE_WRITER: u64 = 1 << 3;
const ERTS_BINARY_HEADER_WORDS: usize = 4;

/// `NBYTES` in erts/emulator/beam/erl_bits.h:27, OTP-29.1.1.
fn nbytes(bits: u64) -> u64 {
    bits.wrapping_add(7) >> 3
}

/// `GROW_PROC_BIN_SIZE` in erts/emulator/beam/erl_bits.c:72, OTP-29.1.1.
fn grow_proc_bin_size(size: usize) -> usize {
    if size > (1 << 24) {
        (1.2 * size as f64) as usize
    } else {
        size.wrapping_mul(2)
    }
}

/// Uses the two-word `ErlBitsState` supplied by BeamAsm.
fn with_state<R>(state: *mut u64, body: impl FnOnce(&mut [u64; 2]) -> R) -> Option<R> {
    if state.is_null() || !(state as usize).is_multiple_of(core::mem::align_of::<u64>()) {
        return None;
    }
    // SAFETY: `ErlBitsState` is two aligned words owned by the current scheduler; the C helper
    // ABI supplies that live state for the duration of this call.
    Some(body(unsafe { &mut *state.cast::<[u64; 2]>() }))
}

/// Uses the scheduler registers addressed by `reg`, with their erts bit cursor.
fn with_registers<R>(reg: *mut u64, body: impl FnOnce(&mut SchedulerRegisters) -> R) -> Option<R> {
    if reg.is_null() || !(reg as usize).is_multiple_of(core::mem::align_of::<u64>()) {
        return None;
    }
    let registers = SchedulerRegisters::from_reg(reg);
    // SAFETY: native BeamAsm passes the active scheduler's X-register array, which remains
    // stationary and exclusively borrowed for the duration of the runtime helper.
    Some(body(unsafe { &mut *registers }))
}

fn with_destination<R>(
    state: &mut [u64; 2],
    end_bits: usize,
    body: impl FnOnce(&mut [u8]) -> R,
) -> Option<R> {
    let bytes = end_bits.div_ceil(8);
    if bytes == 0 {
        return Some(body(&mut []));
    }
    let address = usize::try_from(state[0]).ok()?;
    if address == 0 {
        return None;
    }
    // SAFETY: BeamAsm allocated the current bitstring before these field helpers; `end_bits`
    // is the current cursor plus the validated field size, within that allocation.
    Some(body(unsafe {
        std::slice::from_raw_parts_mut(address as *mut u8, bytes)
    }))
}

fn write_segment(
    state: &mut [u64; 2],
    segment: &Segment<'_>,
) -> Result<usize, arinsal_bits::BitsError> {
    let size = arinsal_bits::create_bin_size(std::slice::from_ref(segment))?.bits;
    if size == 0 {
        return Ok(0);
    }
    let offset = usize::try_from(state[1]).map_err(|_| arinsal_bits::BitsError::SystemLimit {
        segment: segment.index,
    })?;
    let end = offset
        .checked_add(size)
        .ok_or(arinsal_bits::BitsError::SystemLimit {
            segment: segment.index,
        })?;
    let written = with_destination(state, end, |bytes| {
        arinsal_bits::write_segment_at(segment, bytes, offset)
    })
    .ok_or(arinsal_bits::BitsError::SystemLimit {
        segment: segment.index,
    })??;
    state[1] = end as u64;
    Ok(written)
}

fn integer_segment(value: u64, bits: u64, little: bool) -> Segment<'static> {
    Segment {
        ty: SegType::Integer,
        index: 1,
        unit: 1,
        flags: SegFlags {
            little,
            ..SegFlags::default()
        },
        value: SegmentValue::Term(crate::native_hooks::from_raw(value)),
        size: SegSize::Units(bits),
    }
}

fn binary_segment(value: u64, size: SegSize) -> Segment<'static> {
    Segment {
        ty: SegType::Binary,
        index: 1,
        unit: 1,
        flags: SegFlags::default(),
        value: SegmentValue::Term(crate::native_hooks::from_raw(value)),
        size,
    }
}

fn set_fvalue(process: &mut crate::Process, value: u64) {
    process.heap.abi.exc.fvalue = value;
}

fn charge_binary_reductions(process: &mut crate::Process, bits: usize) {
    let reductions = (bits / (8 * 1024)).min(i32::MAX as usize) as i32;
    process.heap.abi.fcalls = process.heap.abi.fcalls.saturating_sub(reductions).max(0);
}

/// Copies a source range with erts' forward bit-copy order.
// Port of erts/emulator/beam/erl_bits.h:535-557 (`copy_binary_to_buffer` and `erts_copy_bits_fwd`), OTP-29.1.1.
fn copy_binary_to_buffer(
    dst: &mut [u8],
    dst_offset: usize,
    src: &[u8],
    src_offset: usize,
    size: usize,
) {
    if size == 0 {
        return;
    }
    if (dst_offset | src_offset | size) & 7 == 0 {
        let count = size / 8;
        dst[dst_offset / 8..dst_offset / 8 + count]
            .copy_from_slice(&src[src_offset / 8..src_offset / 8 + count]);
        return;
    }
    for bit in 0..size {
        let source = (src[(src_offset + bit) / 8] >> (7 - (src_offset + bit) % 8)) & 1;
        let position = dst_offset + bit;
        let mask = 1 << (7 - position % 8);
        let byte = &mut dst[position / 8];
        *byte = (*byte & !mask) | (source << (7 - position % 8));
    }
}

/// `erts_bs_put_integer_be`: write the integer and advance `ErlBitsState` on success.
// Port of erts/emulator/beam/erl_bits.c:926-1030 (erts_bs_put_integer_be), OTP-29.1.1.
#[unsafe(no_mangle)]
pub extern "C" fn erts_bs_put_integer_be(ebs: *mut u64, value: u64, num_bits: u64) -> i32 {
    with_state(ebs, |state| {
        write_segment(state, &integer_segment(value, num_bits, false))
            .is_ok()
            .into()
    })
    .unwrap_or(0)
}

/// `erts_bs_put_integer_le`: write the integer and advance `ErlBitsState` on success.
// Port of erts/emulator/beam/erl_bits.c:1031-1156 (erts_bs_put_integer_le), OTP-29.1.1.
#[unsafe(no_mangle)]
pub extern "C" fn erts_bs_put_integer_le(ebs: *mut u64, value: u64, num_bits: u64) -> i32 {
    with_state(ebs, |state| {
        write_segment(state, &integer_segment(value, num_bits, true))
            .is_ok()
            .into()
    })
    .unwrap_or(0)
}

/// `erts_bs_put_utf16`: encode one scalar in the current destination byte order.
// Port of erts/emulator/beam/erl_bits.c:1222-1280 (erts_bs_put_utf16), OTP-29.1.1.
#[unsafe(no_mangle)]
pub extern "C" fn erts_bs_put_utf16(ebs: *mut u64, value: u64, flags: u64) -> i32 {
    let segment = Segment {
        ty: SegType::Utf16,
        index: 1,
        unit: 1,
        flags: SegFlags {
            little: flags & 2 != 0,
            ..SegFlags::default()
        },
        value: SegmentValue::Term(crate::native_hooks::from_raw(value)),
        size: SegSize::Units(0),
    };
    with_state(ebs, |state| write_segment(state, &segment).is_ok().into()).unwrap_or(0)
}

/// `erts_bs_put_binary`: copy the requested range, set `fvalue` on type/size failure, and charge
/// the reductions for bits copied.
// Port of erts/emulator/beam/erl_bits.c:1285-1310 (erts_bs_put_binary), OTP-29.1.1.
#[unsafe(no_mangle)]
pub extern "C" fn erts_bs_put_binary(
    ebs: *mut u64,
    c_p: *mut ProcessHeader,
    value: u64,
    num_bits: u64,
) -> i32 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    let segment = binary_segment(value, SegSize::Units(num_bits));
    let Some(result) = with_state(ebs, |state| write_segment(state, &segment)) else {
        return 0;
    };
    match result {
        Ok(bits) => {
            charge_binary_reductions(process, bits);
            1
        }
        Err(_) => {
            set_fvalue(process, value);
            0
        }
    }
}

/// `erts_bs_put_binary_all`: validate its unit, copy the full bitstring, and charge reductions.
// Port of erts/emulator/beam/erl_bits.c:1311-1332 (erts_bs_put_binary_all), OTP-29.1.1.
#[unsafe(no_mangle)]
pub extern "C" fn erts_bs_put_binary_all(
    ebs: *mut u64,
    c_p: *mut ProcessHeader,
    value: u64,
    unit: u64,
) -> i32 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    let segment = binary_segment(value, SegSize::All);
    let Ok(size) = arinsal_bits::create_bin_size(std::slice::from_ref(&segment)) else {
        set_fvalue(process, value);
        return 0;
    };
    if unit != 1 && !(size.bits as u64).is_multiple_of(unit) {
        set_fvalue(process, value);
        return 0;
    }
    let Some(result) = with_state(ebs, |state| write_segment(state, &segment)) else {
        return 0;
    };
    match result {
        Ok(bits) => {
            charge_binary_reductions(process, bits);
            1
        }
        Err(_) => {
            set_fvalue(process, value);
            0
        }
    }
}

/// The common full-bitstring copy used by the C and BeamAsm helpers.
// Port of erts/emulator/beam/erl_bits.c:1311-1332 and jit/beam_jit_common.cpp:1043-1057,
// OTP-29.1.1.
fn put_binary_all(ebs: *mut u64, c_p: *mut ProcessHeader, value: u64) {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return;
    };
    let segment = binary_segment(value, SegSize::All);
    if let Some(Ok(bits)) = with_state(ebs, |state| write_segment(state, &segment)) {
        charge_binary_reductions(process, bits);
    }
}

/// BeamAsm's already-validated full-bitstring copy.
// Port of erts/emulator/beam/jit/beam_jit_common.cpp:1043-1057 (beam_jit_bs_put_binary_all),
// OTP-29.1.1.
#[unsafe(no_mangle)]
pub extern "C" fn beam_jit_bs_put_binary_all(ebs: *mut u64, c_p: *mut ProcessHeader, value: u64) {
    put_binary_all(ebs, c_p, value);
}

/// `erts_bs_put_float`: write a float and preserve its specific fvalue failure.
// Port of erts/emulator/beam/erl_bits.c:1341-1637 (erts_bs_put_float), OTP-29.1.1.
#[unsafe(no_mangle)]
pub extern "C" fn erts_bs_put_float(
    ebs: *mut u64,
    c_p: *mut ProcessHeader,
    value: u64,
    num_bits: u64,
    flags: i32,
) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    let segment = Segment {
        ty: SegType::Float,
        index: 1,
        unit: 1,
        flags: SegFlags {
            little: flags & 2 != 0,
            native: flags & 16 != 0,
            ..SegFlags::default()
        },
        value: SegmentValue::Term(crate::native_hooks::from_raw(value)),
        size: SegSize::Units(num_bits),
    };
    let Some(result) = with_state(ebs, |state| write_segment(state, &segment)) else {
        return value;
    };
    match result {
        Ok(_) => 0,
        Err(arinsal_bits::BitsError::Detailed { field, .. }) => {
            set_fvalue(process, crate::atom_cache::put(field).tagged_word());
            if field == "invalid" {
                Term::small(i64::try_from(num_bits).unwrap_or(0))
                    .map(Term::tagged_word)
                    .unwrap_or(0)
            } else {
                value
            }
        }
        Err(_) => {
            set_fvalue(process, crate::atom_cache::put("invalid").tagged_word());
            Term::small(i64::try_from(num_bits).unwrap_or(0))
                .map(Term::tagged_word)
                .unwrap_or(0)
        }
    }
}

/// `erts_bs_put_string`: copy literal bytes at the current bit offset.
// Port of erts/emulator/beam/erl_bits.c:1641-1656 (erts_bs_put_string), OTP-29.1.1.
#[unsafe(no_mangle)]
pub extern "C" fn erts_bs_put_string(ebs: *mut u64, source: *const u8, num_bytes: u64) {
    let Some(result) = with_state(ebs, |state| {
        let Ok(num_bytes) = usize::try_from(num_bytes) else {
            return None;
        };
        let Ok(offset) = usize::try_from(state[1]) else {
            return None;
        };
        let bits = num_bytes.checked_mul(8)?;
        if bits == 0 {
            return Some(0);
        }
        if source.is_null() {
            return None;
        }
        // SAFETY: the module string table owns `num_bytes` bytes for this generated call.
        let bytes = unsafe { std::slice::from_raw_parts(source, num_bytes) };
        let end = offset.checked_add(bits)?;
        let written = with_destination(state, end, |destination| {
            let segment = Segment {
                ty: SegType::String,
                index: 1,
                unit: 1,
                flags: SegFlags::default(),
                value: SegmentValue::String(bytes),
                size: SegSize::Units(num_bytes as u64),
            };
            arinsal_bits::write_segment_at(&segment, destination, offset)
        })?;
        let Ok(written) = written else {
            return None;
        };
        state[1] = (offset + written) as u64;
        Some(written)
    }) else {
        return;
    };
    let _ = result;
}

/// `erts_bs_start_match_3` returns the untagged address of the new `ErlSubBits`.
// Port of erts/emulator/beam/erl_bits.c:81-101 (erts_bs_start_match_3), OTP-29.1.1.
#[unsafe(no_mangle)]
pub extern "C" fn erts_bs_start_match_3(c_p: *mut ProcessHeader, value: u64) -> *mut u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return core::ptr::null_mut();
    };
    let value = crate::native_hooks::from_raw(value);
    let mut heap = crate::ProcessHeapHandle(&mut process.heap);
    match arinsal_bits::start_match(value, &mut heap) {
        Ok(Some(context)) => (context.tagged_word() & !7) as *mut u64,
        Ok(None) | Err(_) => core::ptr::null_mut(),
    }
}

/// `erts_bs_append_checked` uses the scheduler bit state associated with `reg`.
// Port of erts/emulator/beam/erl_bits.c:1725-1917 (erts_bs_append_checked), OTP-29.1.1.
#[unsafe(no_mangle)]
pub extern "C" fn erts_bs_append_checked(
    c_p: *mut ProcessHeader,
    reg: *mut u64,
    live: u64,
    build_size_in_bits: u64,
    extra_words: u64,
    unit: u64,
) -> u64 {
    let Some(result) = with_registers(reg, |registers| {
        crate::native_helpers::bs_append_checked(
            c_p,
            &mut registers.erl_bits_state,
            &mut registers.x_reg_array,
            build_size_in_bits,
            unit,
            live,
            extra_words,
        )
    }) else {
        return 0;
    };
    result
}

/// Private append of `extra_bits` into the unique writable `bin`.
///
/// Cannot fail on this 64-bit BeamAsm path: the size was validated by the caller,
/// `HeapFragOnlyAlloc` and `erts_bin_realloc` never return failure to the caller.
// Port of erts/emulator/beam/erl_bits.c:1928-2017 (`erts_bs_private_append_checked`), OTP-29.1.1.
#[unsafe(no_mangle)]
pub extern "C" fn erts_bs_private_append_checked(
    ebs: *mut u64,
    c_p: *mut ProcessHeader,
    bin: u64,
    extra_bits: u64,
) -> u64 {
    let process =
        crate::native_hooks::enter_runtime(c_p).expect("erts_bs_private_append_checked: Process *");
    // SAFETY: BeamAsm `am_private_append` passes the live scheduler `ErlBitsState`, a
    // `HEADER_SUB_BITS` whose `orig` is a `HEADER_BIN_REF`, and that BinRef's `Binary`.
    // `sb->start == 0` and overflow are erts ASSERTs on BEAMASM; realloc and
    // `HeapFragOnlyAlloc` cannot fail back to this caller.
    unsafe {
        let sb = (bin - ERTS_BOXED_TAG) as *mut u64;
        debug_assert_eq!(sb.read(), ERTS_SUB_BITS_HEADER);
        let orig = sb.add(4).read();
        let br = (orig - ERTS_BOXED_TAG) as *mut u64;
        debug_assert_eq!(br.read(), ERTS_HEADER_BIN_REF);
        debug_assert_eq!(sb.add(2).read(), 0);
        let old_position = sb.add(3).read();
        ebs.add(1).write(old_position);
        debug_assert!(u64::MAX - extra_bits >= old_position);
        let new_position = old_position.wrapping_add(extra_bits);
        let used_size = nbytes(new_position) as usize;
        let mut header = br.add(1).read() as *mut u64;
        let orig_size = header.add(3).read() as usize;
        let view =
            BinaryView::from_header(header, ERTS_BINARY_HEADER_WORDS + orig_size.div_ceil(8));
        process.heap.update_writable_binary_overhead_at(
            crate::native_hooks::from_raw(bin),
            br as usize,
            old_position as usize,
            new_position as usize,
        );
        let (result, current_bin) = if view.has_flags(ERTS_BINARY_FLAG_WRITABLE) {
            debug_assert_eq!(sb.add(1).read() & 3, ERTS_SUB_BITS_FLAGS_WRITABLE);
            debug_assert_eq!(header.add(2).read(), 1);
            if orig_size < used_size {
                let new_size = grow_proc_bin_size(used_size);
                let mut allocation = BinaryBlock::borrow_from_view(view)
                    .expect("live writable Binary has allocator metadata");
                allocation.realloc(new_size);
                header = allocation.header_ptr().cast_mut();
                br.add(1).write(header as u64);
                charge_binary_reductions(process, old_position as usize);
            }
            sb.add(3).write(new_position);
            let capacity = header.add(3).read() as usize;
            let view =
                BinaryView::from_header(header, ERTS_BINARY_HEADER_WORDS + capacity.div_ceil(8));
            view.set_flags(ERTS_BINARY_FLAG_ACTIVE_WRITER);
            view.set_apparent_size(used_size);
            (bin, view.bytes_ptr() as u64)
        } else {
            let new_size = grow_proc_bin_size(used_size);
            let copy = orig_size.min(new_size);
            let prefix = view.bytes(copy).expect("orig_bytes of the traced Binary");
            let (term, data_address) = TermBuilder::new(&mut process.heap)
                .writable_binary_copy_in_fragment_with_address(
                    prefix,
                    new_position as usize,
                    new_size,
                )
                .expect("HeapFragOnlyAlloc never fails");
            charge_binary_reductions(process, old_position as usize);
            (term.tagged_word(), data_address as u64)
        };
        debug_assert!({
            let flags = (current_bin as *const u8)
                .wrapping_sub(4 * core::mem::size_of::<u64>())
                .cast::<u64>()
                .read();
            flags & ERTS_BINARY_FLAG_WRITABLE != 0
        });
        ebs.write(current_bin);
        result
    }
}

/// `erts_build_sub_bitstring` copies small ranges and otherwise allocates a `SUB_BITS` pointing
/// at the supplied `BinRef`.
// Port of erts/emulator/beam/erl_bits.c:2635-2673 (erts_build_sub_bitstring), OTP-29.1.1.
#[unsafe(no_mangle)]
pub extern "C" fn erts_build_sub_bitstring(
    hp: *mut *mut u64,
    br_flags: u64,
    br: *const u64,
    base: *const u8,
    offset: u64,
    size: u64,
) -> u64 {
    if hp.is_null() || !(hp as usize).is_multiple_of(core::mem::align_of::<*mut u64>()) {
        return 0;
    }
    let (Ok(offset), Ok(size)) = (usize::try_from(offset), usize::try_from(size)) else {
        return 0;
    };
    // `hp` is the caller's heap-top pointer, not a Process pointer. `erts_build_sub_bitstring`
    // advances precisely this pointer and does not consult process state.
    // SAFETY: the C ABI supplies a live writable heap-top slot for this allocation.
    let heap = unsafe { hp.read() };
    if heap.is_null() || !(heap as usize).is_multiple_of(core::mem::align_of::<u64>()) {
        return 0;
    }
    if size <= ERTS_ON_HEAP_BITS_LIMIT {
        let Some(source_len) = offset.checked_add(size).map(|bits| bits.div_ceil(8)) else {
            return 0;
        };
        if source_len != 0 && base.is_null() {
            return 0;
        }
        let bytes = size.div_ceil(8);
        let words = 2 + bytes.div_ceil(core::mem::size_of::<u64>());
        let Some(header_size) = u64::try_from(words - 1).ok().and_then(|n| n.checked_shl(6)) else {
            return 0;
        };
        // SAFETY: `heap` has the BUILD_SUB_BITSTRING_HEAP_NEED words reserved by its caller;
        // the source range names `offset + size` live bits in the source binary.
        unsafe {
            heap.write(header_size | ERTS_HEAP_BITS_TAG);
            heap.add(1).write(size as u64);
            let destination = std::slice::from_raw_parts_mut(heap.add(2).cast::<u8>(), bytes);
            if bytes != 0 {
                let source = std::slice::from_raw_parts(base, source_len);
                copy_binary_to_buffer(destination, 0, source, offset, size);
            }
            hp.write(heap.add(words));
            return Term::from_raw_bits(heap as u64 | ERTS_BOXED_TAG).tagged_word();
        }
    }
    if br.is_null() || base.is_null() {
        return 0;
    }
    let bin_ref = br.cast::<u64>();
    // SAFETY: the C caller supplies a live BinRef; word one is its Binary pointer/tag.
    let binary = unsafe { bin_ref.add(1).read() };
    let writable = if binary & 1 == 0 {
        // SAFETY: non-resource BinRef word one points at a live Binary, whose first word is
        // `intern.flags` in erl_binary.h.
        unsafe { (binary as *const u64).read() & ERTS_BINARY_FLAG_WRITABLE != 0 }
    } else {
        false
    };
    let adjustment = (base as usize) & 3;
    let Some(start) = offset.checked_add(adjustment * 8) else {
        return 0;
    };
    let Some(end) = start.checked_add(size) else {
        return 0;
    };
    let object = heap;
    let base_flags = ((base as usize - adjustment) as u64)
        | if writable {
            ERTS_SUB_BITS_FLAG_VOLATILE
        } else {
            0
        };
    // SAFETY: `alloc(5)` reserved the complete five-word ErlSubBits. The BinRef remains
    // reachable from the caller's live source term, and flags/offsets match erl_sub_bits_init.
    unsafe {
        object.write(ERTS_SUB_BITS_HEADER);
        object.add(1).write(base_flags);
        object.add(2).write(start as u64);
        object.add(3).write(end as u64);
        object.add(4).write((br as u64) | br_flags);
        hp.write(heap.add(5));
        Term::from_raw_bits(object as u64 | ERTS_BOXED_TAG).tagged_word()
    }
}

/// `erts_cmp_bits` compares the exact ranges and returns the first byte/bit difference.
// Port of erts/emulator/beam/erl_bits.h:560-577 and erl_bits.c:2293-2375
// (`erts_cmp_bits` / `erts_cmp_bits__`), OTP-29.1.1.
#[unsafe(no_mangle)]
pub extern "C" fn erts_cmp_bits(
    a_ptr: *const u8,
    a_offset: u64,
    b_ptr: *const u8,
    b_offset: u64,
    size: u64,
) -> i32 {
    if size == 0 {
        return 0;
    }
    let (Ok(a_offset), Ok(b_offset), Ok(size)) = (
        usize::try_from(a_offset),
        usize::try_from(b_offset),
        usize::try_from(size),
    ) else {
        return 0;
    };
    let (Some(a_len), Some(b_len)) = (
        a_offset.checked_add(size).map(|bits| bits.div_ceil(8)),
        b_offset.checked_add(size).map(|bits| bits.div_ceil(8)),
    ) else {
        return 0;
    };
    if a_ptr.is_null() || b_ptr.is_null() {
        return 0;
    }
    // SAFETY: erts' comparison caller passes live binary bases and the bit offsets/length name
    // ranges inside them for this non-allocating helper call.
    let (a, b) = unsafe {
        (
            std::slice::from_raw_parts(a_ptr, a_len),
            std::slice::from_raw_parts(b_ptr, b_len),
        )
    };
    arinsal_bits::cmp_bits(a, a_offset, b, b_offset, size)
}

/// `beam_jit_bs_field_size_argument_error` distinguishes an oversized positive size from badarg.
// Port of erts/emulator/beam/jit/beam_jit_common.cpp:792-803
// (beam_jit_bs_field_size_argument_error), OTP-29.1.1.
#[unsafe(no_mangle)]
pub extern "C" fn beam_jit_bs_field_size_argument_error(c_p: *mut ProcessHeader, size: u64) {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return;
    };
    let size = crate::native_hooks::from_raw(size);
    let nonnegative_integer = size.as_small().is_some_and(|value| value >= 0)
        || (size.bignum_digit_count().is_some() && !size.is_negative_bignum());
    process.heap.abi.exc.freason = if nonnegative_integer {
        arinsal_beamasm::exc::EXC_SYSTEM_LIMIT
    } else {
        arinsal_beamasm::exc::EXC_BADARG
    };
}

/// Initializes `ErlBitsState` for the binary construction emitted by BeamAsm.
// Port of erts/emulator/beam/jit/beam_jit_common.cpp:816-858 (beam_jit_bs_init_bits), OTP-29.1.1.
#[unsafe(no_mangle)]
pub extern "C" fn beam_jit_bs_init_bits(
    c_p: *mut ProcessHeader,
    reg: *mut u64,
    ebs: *mut u64,
    num_bits: u64,
    alloc: u64,
    live: u32,
) -> u64 {
    let Some((process, registers)) = crate::native_hooks::enter_runtime_reg(c_p, reg) else {
        return 0;
    };
    let (Ok(bits), Ok(alloc)) = (usize::try_from(num_bits), usize::try_from(alloc)) else {
        crate::native_hooks::set_error(process, "system_limit");
        return 0;
    };
    let heap_words = if bits <= 64 * 8 {
        2 + bits.div_ceil(8).div_ceil(8)
    } else {
        8
    };
    let Some(roots) = registers.x_reg_array.get_mut(..live as usize) else {
        crate::native_hooks::set_error(process, "system_limit");
        return 0;
    };
    process.ensure_native_roots(heap_words.saturating_add(alloc), roots);
    let mut heap = crate::ProcessHeapHandle(&mut process.heap);
    let (term, address) = match TermBuilder::new(&mut heap).bitstring_with_address(bits) {
        Ok(result) => result,
        Err(_) => {
            crate::native_hooks::set_error(process, "system_limit");
            return 0;
        }
    };
    let Some(()) = with_state(ebs, |state| *state = [address as u64, 0]) else {
        crate::native_hooks::set_error(process, "system_limit");
        return 0;
    };
    crate::native_hooks::raw(term)
}

/// Returns a bitstring's size in bits or `-1` when the term is not a bitstring.
// Port of erts/emulator/beam/jit/beam_jit_common.cpp:1011 (`beam_jit_bs_bit_size`), OTP-29.1.1.
#[unsafe(no_mangle)]
pub extern "C" fn beam_jit_bs_bit_size(term: u64) -> i64 {
    arinsal_bits::bit_size(crate::native_hooks::from_raw(term))
        .and_then(|bits| i64::try_from(bits).ok())
        .unwrap_or(-1)
}

/// Builds `badarg` or `system_limit` extended error info for a binary construction failure.
// Port of erts/emulator/beam/jit/beam_jit_common.cpp:911-1010
// (`beam_jit_bs_construct_fail_info`), OTP-29.1.1.
#[unsafe(no_mangle)]
pub extern "C" fn beam_jit_bs_construct_fail_info(
    c_p: *mut ProcessHeader,
    packed: u64,
    arg3: u64,
    arg1: u64,
) {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return;
    };
    let segment = (packed >> 10) as i64;
    let operation = match (packed >> 7) & 7 {
        1 => "float",
        2 => "integer",
        3 => "utf8",
        4 => "utf16",
        5 => "utf32",
        _ => "binary",
    };
    let value = match (packed >> 2) & 3 {
        0 => crate::native_hooks::from_raw(arg1),
        1 => crate::native_hooks::from_raw(arg3),
        _ => crate::native_hooks::from_raw(process.heap.abi.exc.fvalue),
    };
    let info = match (packed >> 4) & 7 {
        0 => arinsal_term::to_owned(crate::native_hooks::from_raw(process.heap.abi.exc.fvalue)),
        1 => Ok(arinsal_etf::OwnedTerm::atom("type")),
        2 => Ok(arinsal_etf::OwnedTerm::atom("size")),
        3 => Ok(arinsal_etf::OwnedTerm::atom("unit")),
        4 => Ok(arinsal_etf::OwnedTerm::atom(
            if arinsal_bits::bit_size(value).is_some() {
                "short"
            } else {
                "type"
            },
        )),
        _ => Err(arinsal_term::TermError::BadArg),
    };
    let (Ok(value), Ok(info)) = (arinsal_term::to_owned(value), info) else {
        crate::native_hooks::set_error(process, "badarg");
        return;
    };
    let reason = match packed & 3 {
        1 => "system_limit",
        2 => {
            let nonnegative = match &value {
                arinsal_etf::OwnedTerm::Int(number) => *number >= 0,
                arinsal_etf::OwnedTerm::BigInt(number) => number.sign() != num_bigint::Sign::Minus,
                _ => false,
            };
            if nonnegative {
                "system_limit"
            } else {
                "badarg"
            }
        }
        _ => "badarg",
    };
    let error_info = arinsal_etf::OwnedTerm::Map(vec![
        (
            arinsal_etf::OwnedTerm::atom("cause"),
            arinsal_etf::OwnedTerm::Tuple(vec![
                arinsal_etf::OwnedTerm::Int(segment),
                arinsal_etf::OwnedTerm::atom(operation),
                info,
                value,
            ]),
        ),
        (
            arinsal_etf::OwnedTerm::atom("function"),
            arinsal_etf::OwnedTerm::atom("format_bs_fail"),
        ),
        (
            arinsal_etf::OwnedTerm::atom("module"),
            arinsal_etf::OwnedTerm::atom("erl_erts_errors"),
        ),
    ]);
    crate::native_helpers::set_native_error_info(process, reason, Some(Box::new(error_info)));
}
