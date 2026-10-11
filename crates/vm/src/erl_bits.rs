//! Runtime helpers for BeamAsm binary construction.
//!
//! Port of erts/emulator/beam/erl_bits.c:1725 (`erts_bs_append_checked`) for the
//! `<<Bin/binary, Bin2/binary>>` shape the compiler lowers to append + one binary.

use crate::native_hooks::{from_raw, process_from_header, raw, set_error};
use arinsal_beamasm::{ProcessHeader, SchedulerRegisters};
use arinsal_bits::{BitsError, SegFlags, SegSize, SegType, Segment, SegmentValue};
use arinsal_term::{HeapAlloc, Term, TermBuilder, TermError};

/// `erts_bs_private_append` charges the used-size delta on the process vheap.
/// Port of erts/emulator/beam/erl_bits.c:1961 (`update_wb_overhead`), OTP-29.1.1.
pub extern "C" fn private_append_overhead(
    header: *mut core::ffi::c_void,
    bin: u64,
    old_bits: u64,
    new_bits: u64,
) {
    let Some(process) = process_from_header(header.cast()) else {
        return;
    };
    process.heap.update_writable_binary_overhead(
        from_raw(bin),
        old_bits as usize,
        new_bits as usize,
    );
}

/// Appends the whole of `X[extra]` onto `X[src]` and returns the new bitstring.
/// Zero means the construction failed and the process error registers are set.
// Port of erts/emulator/beam/jit/arm/instr_bs.cpp:1812-1890 (append to binary) and
// erl_bits.c:1725, OTP-29.1.1.
pub extern "C" fn append_binary(
    header: *mut ProcessHeader,
    src_index: u64,
    extra_index: u64,
    live: u64,
) -> u64 {
    let Some((process, registers)) = crate::native_hooks::process_and_registers(header) else {
        return 0;
    };
    process
        .heap
        .set_frame_pointer(registers.tmp_mem[2] as usize);
    let (Ok(src_index), Ok(extra_index), Ok(live)) = (
        usize::try_from(src_index),
        usize::try_from(extra_index),
        usize::try_from(live),
    ) else {
        return 0;
    };
    let root_live = live
        .max(src_index.saturating_add(1))
        .max(extra_index.saturating_add(1));
    if root_live > registers.x_reg_array.len() || src_index >= root_live || extra_index >= root_live
    {
        set_error(process, "system_limit");
        return 0;
    }
    if process.x.len() < root_live {
        let mut x = process.x.to_vec();
        x.resize(root_live, Term::NIL);
        process.x = x.into();
    }
    for (index, slot) in registers.x_reg_array[..root_live].iter().enumerate() {
        process.x[index] = *slot;
    }
    // `<<Bin/binary, Bin2/binary>>`: one buffer and two copies, then the
    // generic builder if the pieces are not whole bytes or the heap is short.
    if process.ensure(8, root_live).is_ok()
        && let Some(bytes) =
            arinsal_bits::concat_byte_buffers(process.x[src_index], process.x[extra_index])
    {
        let bits = bytes.len() * 8;
        match TermBuilder::new(&mut process.heap).writable_from_vec(bytes, bits) {
            Ok(term) => {
                for (slot, term) in registers.x_reg_array[..root_live]
                    .iter_mut()
                    .zip(process.x.iter())
                {
                    *slot = *term;
                }
                registers.tmp_mem[2] = process.heap.frame_pointer() as u64;
                process.sync_native_header();
                return raw(term);
            }
            Err(TermError::HeapFull) => {}
            Err(TermError::SystemLimit) => {
                set_error(process, "system_limit");
                registers.tmp_mem[2] = process.heap.frame_pointer() as u64;
                return 0;
            }
            Err(TermError::BadArg | TermError::Unsupported(_)) => {
                set_error(process, "badarg");
                registers.tmp_mem[2] = process.heap.frame_pointer() as u64;
                return 0;
            }
        }
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
    let initial = build(process.x[src_index], process.x[extra_index]);
    let mut request = match arinsal_bits::create_bin_size(&initial) {
        Ok(size) => size.heap_words,
        Err(error) => return fail(process, registers, error),
    };
    let result = loop {
        if process.ensure(request, root_live).is_err() {
            set_error(process, "system_limit");
            registers.tmp_mem[2] = process.heap.frame_pointer() as u64;
            return 0;
        }
        let segments = build(process.x[src_index], process.x[extra_index]);
        match arinsal_bits::create_bin(&segments, &mut process.heap) {
            Err(BitsError::HeapFull { need_words }) => {
                request = need_words.max(request.saturating_mul(2));
            }
            other => break other,
        }
    };
    for (slot, term) in registers.x_reg_array[..root_live]
        .iter_mut()
        .zip(process.x.iter())
    {
        *slot = *term;
    }
    registers.tmp_mem[2] = process.heap.frame_pointer() as u64;
    process.sync_native_header();
    match result {
        Ok(term) => raw(term),
        Err(error) => fail(process, registers, error),
    }
}

fn fail(process: &mut crate::Process, registers: &mut SchedulerRegisters, error: BitsError) -> u64 {
    let (reason, info) = crate::bits::native_error(error);
    process.cold_mut().native_error_info = info;
    set_error(process, &reason);
    registers.tmp_mem[2] = process.heap.frame_pointer() as u64;
    0
}
