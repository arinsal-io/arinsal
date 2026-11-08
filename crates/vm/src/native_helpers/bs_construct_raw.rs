//! Raw cursor access for BeamAsm's per-segment bitstring writers.

use arinsal_beamasm::{ProcessHeader, SchedulerRegisters};
use arinsal_bits::{SegFlags, SegSize, SegType, Segment, SegmentValue, write_segment_at};
use arinsal_term::TermBuilder;

/// Calls the checked append allocator after the emitted size pass.
// Port of erts/emulator/beam/jit/arm/instr_bs.cpp:1808-1858, OTP-29.1.1.
pub(crate) extern "C" fn append_checked(
    header: *mut ProcessHeader,
    registers: *mut SchedulerRegisters,
    source_index: u64,
    extra_bits: u64,
    unit: u64,
    live: u64,
    alloc: u64,
) -> u64 {
    if header.is_null() || registers.is_null() {
        return 0;
    }
    // SAFETY: the native call ABI supplies live process and scheduler-register pointers.
    unsafe {
        crate::native_helpers::arinsal_beamasm_bs_append_checked(
            &mut *header,
            &mut *registers,
            source_index,
            extra_bits,
            unit,
            live,
            alloc,
        )
    }
}

/// Runs the checked private append against the scheduler's live write cursor.
// Port of erts/emulator/beam/jit/arm/instr_bs.cpp:1865-1880, OTP-29.1.1.
pub(crate) extern "C" fn private_append(
    header: *mut ProcessHeader,
    registers: *mut SchedulerRegisters,
    source: u64,
    extra_bits: u64,
) -> u64 {
    if header.is_null() || registers.is_null() {
        return 0;
    }
    // SAFETY: native code passes the live process header and its scheduler register area.
    unsafe {
        let state = std::ptr::addr_of_mut!((*registers).erl_bits_state).cast::<u64>();
        crate::native_helpers::arinsal_beamasm_bs_private_append_checked(
            state,
            &mut *header,
            source,
            extra_bits,
        )
    }
}

/// Allocates one final bitstring and publishes its write cursor.
// Port of instr_bs.cpp:1855-1979 (`emit_bs_init_bits_shared`), OTP-29.1.1.
pub(crate) extern "C" fn init_bits(
    header: *mut ProcessHeader,
    registers: *mut SchedulerRegisters,
    bits: u64,
    alloc: u64,
    live: u64,
) -> u64 {
    if header.is_null() || registers.is_null() {
        return 0;
    }
    // SAFETY: generated code passes the active process header and its scheduler register area.
    let Some((process, registers)) = (unsafe {
        crate::native_hooks::enter_runtime_with_registers(&mut *header, &mut *registers)
    }) else {
        return 0;
    };
    let (Ok(bits), Ok(alloc), Ok(live)) = (
        usize::try_from(bits),
        usize::try_from(alloc),
        usize::try_from(live),
    ) else {
        crate::native_hooks::set_error(process, "system_limit");
        return 0;
    };
    let heap_words = if bits.div_ceil(8) <= 64 {
        2 + bits.div_ceil(8).div_ceil(8)
    } else {
        8
    };
    let ensured = process.ensure_native_roots(heap_words.saturating_add(alloc), live);
    if ensured.is_err() {
        crate::native_hooks::set_error(process, "system_limit");
        return 0;
    }
    match TermBuilder::new(&mut process.heap).bitstring_with_address(bits) {
        Ok((term, address)) => {
            registers.erl_bits_state = [address as u64, 0];
            crate::native_hooks::raw(term)
        }
        Err(_) => {
            crate::native_hooks::set_error(process, "system_limit");
            0
        }
    }
}

/// Returns the bit size of a term and `u64::MAX` for a non-bitstring.
// Port of erts/emulator/beam/jit/beam_jit_common.cpp:1011 (`beam_jit_bs_bit_size`), OTP-29.1.1.
pub(crate) extern "C" fn bit_size(
    header: *mut ProcessHeader,
    _registers: *mut SchedulerRegisters,
    source: u64,
    _index: u64,
) -> u64 {
    let Some((process, _registers)) = crate::native_hooks::enter_runtime(header) else {
        return u64::MAX;
    };
    match arinsal_bits::bit_size(crate::native_hooks::from_raw(source)) {
        Some(bits) => bits as u64,
        None => {
            crate::native_hooks::set_error(process, "badarg");
            u64::MAX
        }
    }
}

/// Returns an encoded UTF segment size in bits or raises badarg.
pub(crate) extern "C" fn utf8_size(
    header: *mut ProcessHeader,
    _registers: *mut SchedulerRegisters,
    source: u64,
    _index: u64,
) -> u64 {
    utf_size(header, source, 8)
}

/// Returns an encoded UTF-16 segment size in bits or raises badarg.
pub(crate) extern "C" fn utf16_size(
    header: *mut ProcessHeader,
    _registers: *mut SchedulerRegisters,
    source: u64,
    _index: u64,
) -> u64 {
    utf_size(header, source, 16)
}

/// Returns an encoded UTF-32 segment size in bits or raises badarg.
pub(crate) extern "C" fn utf32_size(
    header: *mut ProcessHeader,
    _registers: *mut SchedulerRegisters,
    source: u64,
    _index: u64,
) -> u64 {
    utf_size(header, source, 32)
}

fn utf_size(header: *mut ProcessHeader, source: u64, unit_bits: u64) -> u64 {
    let Some((process, _registers)) = crate::native_hooks::enter_runtime(header) else {
        return u64::MAX;
    };
    let value = crate::native_hooks::from_raw(source);
    let Some(point) = value.as_small().and_then(|n| u32::try_from(n).ok()) else {
        crate::native_hooks::set_error(process, "badarg");
        return u64::MAX;
    };
    let Some(character) = char::from_u32(point) else {
        crate::native_hooks::set_error(process, "badarg");
        return u64::MAX;
    };
    match unit_bits {
        8 => u64::from(character.len_utf8() as u32) * 8,
        16 => u64::from(character.len_utf16() as u32) * 16,
        _ => 32,
    }
}

/// Sets the native exception state for an emitted size check failure.
// Port of erts/emulator/beam/jit/beam_jit_common.cpp:911-1010 (`beam_jit_bs_construct_fail_info`), OTP-29.1.1.
pub(crate) extern "C" fn fail(
    header: *mut ProcessHeader,
    _registers: *mut SchedulerRegisters,
    packed: u64,
    arg3: u64,
    arg1: u64,
) -> u64 {
    let Some((process, _registers)) = crate::native_hooks::enter_runtime(header) else {
        return 0;
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
    let Ok(value) = arinsal_term::to_owned(value) else {
        crate::native_hooks::set_error(process, "badarg");
        return 0;
    };
    let Ok(info) = info else {
        crate::native_hooks::set_error(process, "badarg");
        return 0;
    };
    let reason = match packed & 3 {
        1 => "system_limit",
        2 => {
            let nonnegative_integer = match &value {
                arinsal_etf::OwnedTerm::Int(number) => *number >= 0,
                arinsal_etf::OwnedTerm::BigInt(number) => number.sign() != num_bigint::Sign::Minus,
                _ => false,
            };
            if nonnegative_integer {
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
    0
}

#[allow(clippy::too_many_arguments)]
fn put_segment(
    header: *mut ProcessHeader,
    registers: *mut SchedulerRegisters,
    kind: SegType,
    source: u64,
    bits: u64,
    metadata: u64,
    index: u64,
    total_bits: u64,
) -> u64 {
    if header.is_null() || registers.is_null() {
        return 0;
    }
    // SAFETY: generated code passes the active process header and its scheduler register area.
    let Some((process, registers)) = (unsafe {
        crate::native_hooks::enter_runtime_with_registers(&mut *header, &mut *registers)
    }) else {
        return 0;
    };
    let (Ok(bits), Ok(index), Ok(total_bits), Ok(offset)) = (
        usize::try_from(bits),
        usize::try_from(index),
        usize::try_from(total_bits),
        usize::try_from(registers.erl_bits_state[1]),
    ) else {
        crate::native_hooks::set_error(process, "system_limit");
        return 0;
    };
    let string_bytes = if kind == SegType::String {
        let Some(string_id) = crate::native_hooks::from_raw(source)
            .as_small()
            .and_then(|n| usize::try_from(n).ok())
        else {
            crate::native_hooks::set_error(process, "badarg");
            return 0;
        };
        let strings = match_strings()
            .read()
            .unwrap_or_else(|error| error.into_inner());
        let Some(bytes) = strings.get(string_id).cloned() else {
            crate::native_hooks::set_error(process, "badarg");
            return 0;
        };
        Some(bytes)
    } else {
        None
    };
    let value = string_bytes.as_deref().map_or_else(
        || SegmentValue::Term(crate::native_hooks::from_raw(source)),
        SegmentValue::String,
    );
    let all = metadata >> 63 != 0;
    let unit = ((metadata >> 32) & 0x7fff_ffff) as u8;
    let segment = Segment {
        ty: kind,
        index,
        unit: if kind == SegType::Binary && all {
            unit
        } else {
            1
        },
        flags: SegFlags {
            little: metadata & 2 != 0,
            signed: metadata & 4 != 0,
            native: metadata & 16 != 0,
        },
        value,
        size: if kind == SegType::Binary && all {
            SegSize::All
        } else {
            SegSize::Units(bits as u64)
        },
    };
    let address = registers.erl_bits_state[0] as usize;
    let bytes_len = total_bits.div_ceil(8);
    let mut empty_destination = [];
    let zero_cursor = address == 0 && bits == 0;
    let destination = if bytes_len == 0 || zero_cursor {
        &mut empty_destination[..]
    } else if address == 0 {
        crate::native_hooks::set_error(process, "system_limit");
        return 0;
    } else {
        // SAFETY: init_bits allocated `total_bits` payload bytes, and no segment writer collects
        // or relocates the process heap. The cursor is bounded by that allocation before this
        // slice is created, and write_segment_at checks the segment end against its length.
        unsafe { std::slice::from_raw_parts_mut(address as *mut u8, bytes_len) }
    };
    let write_offset = if zero_cursor { 0 } else { offset };
    match write_segment_at(&segment, destination, write_offset) {
        Ok(written) => {
            registers.erl_bits_state[1] = (offset + written) as u64;
            if kind == SegType::Binary {
                process.heap.abi.fcalls = process
                    .heap
                    .abi
                    .fcalls
                    .saturating_sub((written / (8 * 1024)).min(i32::MAX as usize) as i32)
                    .max(0);
            }
            1
        }
        Err(error) => {
            let (reason, info) = crate::bits::native_error(error);
            crate::native_helpers::set_native_error_info(process, &reason, info);
            0
        }
    }
}

macro_rules! put_primitive {
    ($name:ident, $kind:ident) => {
        pub(crate) extern "C" fn $name(
            header: *mut ProcessHeader,
            registers: *mut SchedulerRegisters,
            source: u64,
            bits: u64,
            metadata: u64,
            index: u64,
            total_bits: u64,
        ) -> u64 {
            put_segment(
                header,
                registers,
                SegType::$kind,
                source,
                bits,
                metadata,
                index,
                total_bits,
            )
        }
    };
}

put_primitive!(put_integer, Integer);
put_primitive!(put_binary, Binary);
put_primitive!(put_binary_all, Binary);
put_primitive!(put_float, Float);
put_primitive!(put_utf8, Utf8);
put_primitive!(put_utf16, Utf16);
put_primitive!(put_utf32, Utf32);
put_primitive!(put_string, String);

use super::match_strings;
