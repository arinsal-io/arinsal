//! The debug BIFs of beam_debug.c.
//!
//! Port of erts/emulator/beam/beam_debug.c (erts_debug_copy_shared_2,
//! erts_debug_size_shared_1, erts_debug_unaligned_bitstring_2,
//! erts_debug_instructions_0, erts_debug_disassemble_1,
//! erts_debug_interpreter_size_0), OTP-29.1.1. Each BIF is `bif_table[].f` with
//! `(c_p, reg, I)`. Dirty-scheduler test BIFs stay in the erts_debug family.

use crate::natives::bif::{bif_badarg, bif_system_limit};
use arinsal_beamasm::ProcessHeader;
use arinsal_bifs::ProcessHeapHandle;
use arinsal_term::raw::BinRef;
use arinsal_term::{Term, TermBuilder, atoms};

/// `BIF_ERROR(c_p, BADARG)`.
fn badarg(c_p: *mut ProcessHeader) -> u64 {
    bif_badarg(c_p)
}

/// `erts_debug:copy_shared/2`.
// Port of erts/emulator/beam/beam_debug.c (erts_debug_copy_shared_2), OTP-29.1.1.
pub(crate) extern "C" fn erts_debug_copy_shared_2(
    c_p: *mut ProcessHeader,
    reg: *mut u64,
    _i: u64,
) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let [term, flag] = crate::bif_table::bif_args::<2>(reg);
    let copy_literals = if flag == Term::atom(atoms::TRUE) {
        true
    } else if flag == Term::atom(atoms::FALSE) {
        false
    } else {
        return badarg(c_p);
    };
    match arinsal_term::copy_shared(
        term,
        &mut ProcessHeapHandle(&mut process.heap),
        copy_literals,
    ) {
        Ok(copy) => crate::native_hooks::raw(copy),
        Err(_) => bif_system_limit(c_p),
    }
}

/// `erts_debug:size_shared/1`.
// Port of erts/emulator/beam/beam_debug.c (erts_debug_size_shared_1), OTP-29.1.1.
pub(crate) extern "C" fn erts_debug_size_shared_1(
    c_p: *mut ProcessHeader,
    reg: *mut u64,
    _i: u64,
) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let [term] = crate::bif_table::bif_args::<1>(reg);
    match TermBuilder::new(&mut ProcessHeapHandle(&mut process.heap))
        .int_from_u64(arinsal_term::size_shared(term) as u64)
    {
        Ok(result) => crate::native_hooks::raw(result),
        Err(_) => bif_system_limit(c_p),
    }
}

/// `erts_debug:unaligned_bitstring/2`.
// Port of erts/emulator/beam/beam_debug.c (erts_debug_unaligned_bitstring_2), OTP-29.1.1.
pub(crate) extern "C" fn erts_debug_unaligned_bitstring_2(
    c_p: *mut ProcessHeader,
    reg: *mut u64,
    _i: u64,
) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let [bitstring, offset] = crate::bif_table::bif_args::<2>(reg);
    let Ok(view) = BinRef::try_from(bitstring) else {
        return badarg(c_p);
    };
    let Some(offset) = offset.as_small().filter(|offset| (1..8).contains(offset)) else {
        return badarg(c_p);
    };
    let offset = offset as usize;
    let source_size = view.bit_len();
    let source_offset = view.start_bit();
    let source_bytes = view.window();
    // Port of beam_debug.c:140 (`MAX(source_size + offset, ERL_ONHEAP_BITS_LIMIT + 1)`).
    let target_size = source_size.saturating_add(offset).max(64 * 8 + 1);
    let mut target = vec![0u8; target_size.div_ceil(8)];
    for index in 0..source_size {
        let src = source_offset + index;
        let bit = (source_bytes[src / 8] >> (7 - src % 8)) & 1;
        let dest = index + offset;
        target[dest / 8] |= bit << (7 - dest % 8);
    }
    let mut heap = ProcessHeapHandle(&mut process.heap);
    let mut builder = TermBuilder::new(&mut heap);
    let Ok(binary) = builder.binary(&target) else {
        return bif_system_limit(c_p);
    };
    match builder.sub_binary(binary, offset, source_size) {
        Ok(result) => crate::native_hooks::raw(result),
        Err(_) => bif_system_limit(c_p),
    }
}

/// `erts_debug:instructions/0`.
// Port of erts/emulator/beam/beam_debug.c (erts_debug_instructions_0), OTP-29.1.1.
pub(crate) extern "C" fn erts_debug_instructions_0(
    c_p: *mut ProcessHeader,
    _reg: *mut u64,
    _i: u64,
) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let mut heap = ProcessHeapHandle(&mut process.heap);
    let mut builder = TermBuilder::new(&mut heap);
    let mut names = Vec::new();
    for name in include_str!("erts_debug_instructions.txt").lines() {
        let bytes = name
            .bytes()
            .map(|byte| Term::small(i64::from(byte)).expect("instruction name byte"));
        match builder.list_from_iter(bytes) {
            Ok(string) => names.push(string),
            Err(_) => return bif_system_limit(c_p),
        }
    }
    match builder.list_from_iter(names) {
        Ok(result) => crate::native_hooks::raw(result),
        Err(_) => bif_system_limit(c_p),
    }
}

/// `erts_debug:disassemble/1`.
// Port of erts/emulator/beam/beam_debug.c (erts_debug_disassemble_1), OTP-29.1.1.
pub(crate) extern "C" fn erts_debug_disassemble_1(
    _c_p: *mut ProcessHeader,
    _reg: *mut u64,
    _i: u64,
) -> u64 {
    // `#ifdef BEAMASM`: the interpreter disassembler is not compiled.
    crate::native_hooks::raw(Term::atom(atoms::FALSE))
}

/// `erts_debug:interpreter_size/0`.
// Port of erts/emulator/beam/beam_debug.c (erts_debug_interpreter_size_0), OTP-29.1.1.
pub(crate) extern "C" fn erts_debug_interpreter_size_0(
    _c_p: *mut ProcessHeader,
    _reg: *mut u64,
    _i: u64,
) -> u64 {
    // `#ifdef BEAMASM`: there is no `process_main` opcode range.
    crate::native_hooks::raw(Term::small(0).expect("zero is a small integer"))
}
