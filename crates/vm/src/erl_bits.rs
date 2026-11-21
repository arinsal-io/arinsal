//! Rust ports of the erts bit-syntax runtime functions.
//!
//! Port of erts/emulator/beam/erl_bits.c, OTP-29.1.1.

use arinsal_beamasm::ProcessHeader;
use arinsal_bits::{MatchOps, SegFlags};
use arinsal_term::Term;

/// Creates the empty writable binary for a native `bs_init_writable`.
// Port of erts/emulator/beam/jit/arm/instr_bs.cpp:985-1000 and erl_bits.c:2002
// (erts_bs_init_writable), OTP-29.1.1.
#[unsafe(no_mangle)]
pub extern "C" fn erts_bs_init_writable(header: *mut ProcessHeader, size: u64) -> u64 {
    let Some(process) = crate::native_hooks::enter_runtime(header) else {
        return 0;
    };
    let size = crate::native_hooks::from_raw(size).as_small();
    process.ensure_objv(8, &mut []);
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
    let mut heap = crate::ProcessHeapHandle(&mut process.heap);
    match context.get_binary(num_bits, &mut heap) {
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
    let mut heap = crate::ProcessHeapHandle(&mut process.heap);
    let Some(term) = context
        .get_float(num_bits, segment_flags(flags), &mut heap)
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
    let mut heap = crate::ProcessHeapHandle(&mut process.heap);
    match context.get_integer(num_bits, segment_flags(flags), &mut heap) {
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
        process.ensure_native_roots(words_needed, &mut registers.x_reg_array[..root_count]);
        let context = registers.x_reg_array[live];
        return get_integer_inner(process, context, size as u64, flags as u32);
    }
    get_integer_inner(process, context, size as u64, flags as u32)
}
