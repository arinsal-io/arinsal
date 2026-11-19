//! Runtime helpers for BeamAsm binary construction.
//!
//! Port of erts/emulator/beam/erl_bits.c:1725 (`erts_bs_append_checked`) for the
//! `<<Bin/binary, Bin2/binary>>` shape the compiler lowers to append + one binary.

use crate::native_hooks::{raw, set_error};
use arinsal_beamasm::ProcessHeader;
use arinsal_bits::{BitsError, MatchOps, SegFlags, SegSize, SegType, Segment, SegmentValue};
use arinsal_term::Term;

/// Appends the whole of `X[extra]` onto `X[src]` and returns the new bitstring.
/// Zero means the construction failed and the process error registers are set.
// Port of erts/emulator/beam/jit/arm/instr_bs.cpp:1812-1890 (append to binary) and
// erl_bits.c:1725, OTP-29.1.1.
pub extern "C" fn append_binary(
    header: *mut ProcessHeader,
    src_index: u64,
    extra_index: u64,
    live: u64,
    alloc: u64,
    reg: *mut u64,
) -> u64 {
    let Some((process, registers)) = crate::native_hooks::enter_runtime_reg(header, reg) else {
        return 0;
    };
    let (Ok(src_index), Ok(extra_index), Ok(live), Ok(alloc)) = (
        usize::try_from(src_index),
        usize::try_from(extra_index),
        usize::try_from(live),
        usize::try_from(alloc),
    ) else {
        return 0;
    };
    let root_live = live
        .max(src_index.saturating_add(1))
        .max(extra_index.saturating_add(1));
    if root_live > crate::proc_create::ATTACHED_X_REGS
        || src_index >= root_live
        || extra_index >= root_live
    {
        set_error(process, "system_limit");
        return 0;
    }
    let build = |src: Term, extra: Term| {
        [
            Segment {
                ty: SegType::Append,
                index: 1,
                unit: 8,
                flags: SegFlags::default(),
                value: SegmentValue::Term(src),
                size: SegSize::All,
            },
            Segment {
                ty: SegType::Binary,
                index: 2,
                unit: 8,
                flags: SegFlags::default(),
                value: SegmentValue::Term(extra),
                size: SegSize::All,
            },
        ]
    };
    // Port of erts/emulator/beam/erl_bits.c (`erts_bs_put_binary_all` and
    // `erts_bs_append_checked` call BUMP_REDS with the bits they copy per ERL_BITS_PER_REDUCTION).
    // The call site stores FCALLS and reloads it (`Update::eReductions`), so the charge goes
    // through `process.reductions`, which `enter_runtime` started from the stored FCALLS. BUMP_REDS
    // clamps FCALLS at zero.
    let copy_reductions = arinsal_bits::create_bin_reductions(&build(
        registers.x_reg_array[src_index],
        registers.x_reg_array[extra_index],
    ))
    .unwrap_or(0);
    let charge = |process: &mut crate::Process| {
        process.heap.abi.fcalls = process
            .heap
            .abi
            .fcalls
            .saturating_sub(copy_reductions.min(i32::MAX as usize) as i32)
            .max(0);
    };
    // Port of `erts_bs_append_checked`'s ERL_REFC_BITS_SIZE heap request: BinRef + SubBits.
    // `<<Bin/binary, Bin2/binary>>` fills one destination with the two source ranges.
    // The heap bitstring of a result up to 64 bytes takes up to 10 words, more than a BinRef plus
    // SubBits, so the request follows what the builder writes. `Alloc` is the heap the
    // instruction's following stores use without their own test (`extra_words` in erts).
    if let Some(words) = arinsal_bits::concat_byte_binary_heap_words(
        registers.x_reg_array[src_index],
        registers.x_reg_array[extra_index],
    )
    .and_then(|words| words.checked_add(alloc))
        && let Ok(_) = process.ensure_native_roots(words, &mut registers.x_reg_array[..root_live])
        && let Ok(Some(term)) = arinsal_bits::concat_byte_binary(
            registers.x_reg_array[src_index],
            registers.x_reg_array[extra_index],
            &mut process.heap,
        )
    {
        charge(process);
        return raw(term);
    }
    let initial = build(
        registers.x_reg_array[src_index],
        registers.x_reg_array[extra_index],
    );
    let mut request = match arinsal_bits::create_bin_size(&initial) {
        Ok(size) => size.heap_words.saturating_add(alloc),
        Err(error) => return fail(process, error),
    };
    let result = loop {
        if process
            .ensure_objv(request, &mut registers.x_reg_array[..root_live])
            .is_err()
        {
            set_error(process, "system_limit");
            return 0;
        }
        let segments = build(
            registers.x_reg_array[src_index],
            registers.x_reg_array[extra_index],
        );
        match arinsal_bits::create_bin(&segments, &mut process.heap) {
            Err(BitsError::HeapFull { need_words }) => {
                request = need_words
                    .saturating_add(alloc)
                    .max(request.saturating_mul(2));
            }
            other => break other,
        }
    };
    if result.is_ok() {
        charge(process);
    }
    match result {
        Ok(term) => raw(term),
        Err(error) => fail(process, error),
    }
}

fn fail(process: &mut crate::Process, error: BitsError) -> u64 {
    // An earlier collection of this helper may have moved the heap.
    let (reason, info) = crate::bits::native_error(error);
    crate::native_helpers::set_native_error_info(process, &reason, info);
    0
}

/// Creates the empty writable binary for a native `bs_init_writable`.
// Port of erts/emulator/beam/jit/arm/instr_bs.cpp:985-1000 and erl_bits.c:2002
// (erts_bs_init_writable), OTP-29.1.1.
#[unsafe(no_mangle)]
pub extern "C" fn erts_bs_init_writable(header: *mut ProcessHeader, size: u64) -> u64 {
    let Some(process) = crate::native_hooks::enter_runtime(header) else {
        return 0;
    };
    let size = crate::native_hooks::from_raw(size).as_small();
    if process.ensure_objv(8, &mut []).is_err() {
        crate::native_hooks::set_error(process, "system_limit");
        return 0;
    }
    let result = arinsal_bits::init_writable_with_size(size, &mut process.heap);
    match result {
        Ok(value) => crate::native_hooks::raw(value),
        Err(_) => {
            crate::native_hooks::set_error(process, "system_limit");
            0
        }
    }
}

/// Extracts an integer from a live native match context.
// Port of erts/emulator/beam/erl_bits.c:170-347 (erts_bs_get_integer_2), OTP-29.1.1.
#[unsafe(no_mangle)]
pub extern "C" fn erts_bs_get_integer_2(
    header: *mut ProcessHeader,
    num_bits: u64,
    flags: u32,
    sub_bits: *mut u64,
) -> u64 {
    let Some(process) = crate::native_hooks::enter_runtime(header) else {
        return crate::native_hooks::raw(Term::NON_VALUE);
    };
    let Some(context) = crate::raw::runtime_ffi::match_context(sub_bits) else {
        return crate::native_hooks::raw(Term::NON_VALUE);
    };
    get_integer_inner(process, context, num_bits, flags)
}

/// Extracts a bitstring slice and advances the match context after allocation.
// Port of erts/emulator/beam/erl_bits.c:401-427 (erts_bs_get_binary_2), OTP-29.1.1.
#[unsafe(no_mangle)]
pub extern "C" fn erts_bs_get_binary_2(
    header: *mut ProcessHeader,
    num_bits: u64,
    sub_bits: *mut u64,
) -> u64 {
    let Some(process) = crate::native_hooks::enter_runtime(header) else {
        return crate::native_hooks::raw(Term::NON_VALUE);
    };
    let Some(context) = crate::raw::runtime_ffi::match_context(sub_bits) else {
        return crate::native_hooks::raw(Term::NON_VALUE);
    };
    let Ok(num_bits) = usize::try_from(num_bits) else {
        return crate::native_hooks::raw(Term::NON_VALUE);
    };
    match context.get_binary(num_bits, &mut process.heap) {
        Ok(Some(term)) => crate::native_hooks::raw(term),
        Ok(None) | Err(_) => crate::native_hooks::raw(Term::NON_VALUE),
    }
}

/// Extracts a floating-point field from a live native match context.
// Port of erts/emulator/beam/erl_bits.c:550-609 (erts_bs_get_float_2), OTP-29.1.1.
#[unsafe(no_mangle)]
pub extern "C" fn erts_bs_get_float_2(
    header: *mut ProcessHeader,
    num_bits: u64,
    flags: u32,
    sub_bits: *mut u64,
) -> u64 {
    let Some(process) = crate::native_hooks::enter_runtime(header) else {
        return crate::native_hooks::raw(Term::NON_VALUE);
    };
    let Some(context) = crate::raw::runtime_ffi::match_context(sub_bits) else {
        return crate::native_hooks::raw(Term::NON_VALUE);
    };
    let Ok(num_bits) = usize::try_from(num_bits) else {
        return crate::native_hooks::raw(Term::NON_VALUE);
    };
    let Some(term) = context
        .get_float(num_bits, segment_flags(flags), &mut process.heap)
        .ok()
        .flatten()
    else {
        return crate::native_hooks::raw(Term::NON_VALUE);
    };
    crate::native_hooks::raw(term)
}

/// Extracts one UTF-8 scalar from a live native match context.
// Port of erts/emulator/beam/erl_bits.c:2129-2221 (erts_bs_get_utf8), OTP-29.1.1.
#[unsafe(no_mangle)]
pub extern "C" fn erts_bs_get_utf8(sub_bits: *mut u64) -> u64 {
    let Some(context) = crate::raw::runtime_ffi::match_context(sub_bits) else {
        return crate::native_hooks::raw(Term::NON_VALUE);
    };
    context
        .get_utf8()
        .map(crate::native_hooks::raw)
        .unwrap_or_else(|| crate::native_hooks::raw(Term::NON_VALUE))
}

/// Extracts one UTF-16 scalar from a live native match context.
// Port of erts/emulator/beam/erl_bits.c:2224-2290 (erts_bs_get_utf16), OTP-29.1.1.
#[unsafe(no_mangle)]
pub extern "C" fn erts_bs_get_utf16(sub_bits: *mut u64, flags: u64) -> u64 {
    let Some(context) = crate::raw::runtime_ffi::match_context(sub_bits) else {
        return crate::native_hooks::raw(Term::NON_VALUE);
    };
    context
        .get_utf16(segment_flags(flags as u32))
        .map(crate::native_hooks::raw)
        .unwrap_or_else(|| crate::native_hooks::raw(Term::NON_VALUE))
}

/// Integer extraction after the C ABI entry has entered the process.
// Port of erts/emulator/beam/erl_bits.c:170-347 (erts_bs_get_integer_2), OTP-29.1.1.
fn get_integer_inner(
    process: &mut crate::Process,
    context: Term,
    num_bits: u64,
    flags: u32,
) -> u64 {
    let Ok(num_bits) = usize::try_from(num_bits) else {
        return crate::native_hooks::raw(Term::NON_VALUE);
    };
    match context.get_integer(num_bits, segment_flags(flags), &mut process.heap) {
        Ok(Some(term)) => crate::native_hooks::raw(term),
        Ok(None) | Err(_) => crate::native_hooks::raw(Term::NON_VALUE),
    }
}

fn segment_flags(flags: u32) -> SegFlags {
    SegFlags {
        little: flags & 2 != 0,
        signed: flags & 4 != 0,
        native: flags & 16 != 0,
    }
}

/// Integer getter slow path, rooting large match contexts across `gc_test`.
// Port of erts/emulator/beam/jit/beam_jit_common.cpp:875-908 (beam_jit_bs_get_integer), OTP-29.1.1.
#[unsafe(no_mangle)]
pub extern "C" fn beam_jit_bs_get_integer(
    header: *mut ProcessHeader,
    reg: *mut u64,
    context: u64,
    flags: u64,
    size: u64,
    live: u64,
) -> u64 {
    const SMALL_BITS: usize = 60;

    let Some((process, registers)) = crate::native_hooks::enter_runtime_reg(header, reg) else {
        return crate::native_hooks::raw(Term::NON_VALUE);
    };
    let (Ok(size), Ok(live)) = (usize::try_from(size), usize::try_from(live)) else {
        return crate::native_hooks::raw(Term::NON_VALUE);
    };
    let context = crate::native_hooks::from_raw(context);
    if !arinsal_term::is_match_context(context) {
        return crate::native_hooks::raw(Term::NON_VALUE);
    }
    if size >= SMALL_BITS {
        if context.remaining() < size || live >= registers.x_reg_array.len() {
            return crate::native_hooks::raw(Term::NON_VALUE);
        }
        registers.x_reg_array[live] = context;
        let words_needed = 1 + size.div_ceil(64);
        let Some(root_count) = live.checked_add(1) else {
            return crate::native_hooks::raw(Term::NON_VALUE);
        };
        if process
            .ensure_native_roots(words_needed, &mut registers.x_reg_array[..root_count])
            .is_err()
        {
            crate::native_hooks::set_error(process, "system_limit");
            return crate::native_hooks::raw(Term::NON_VALUE);
        }
        let context = registers.x_reg_array[live];
        return get_integer_inner(process, context, size as u64, flags as u32);
    }
    get_integer_inner(process, context, size as u64, flags as u32)
}
