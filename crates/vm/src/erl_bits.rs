//! Runtime helpers for BeamAsm binary construction.
//!
//! Port of erts/emulator/beam/erl_bits.c:1725 (`erts_bs_append_checked`) for the
//! `<<Bin/binary, Bin2/binary>>` shape the compiler lowers to append + one binary.

use crate::native_hooks::{enter_runtime, raw, set_error};
use arinsal_beamasm::{ProcessHeader, SchedulerRegisters};
use arinsal_bits::{BitsError, SegFlags, SegSize, SegType, Segment, SegmentValue};
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
) -> u64 {
    let Some((process, registers)) = enter_runtime(header) else {
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
        process.x[src_index],
        process.x[extra_index],
    ))
    .unwrap_or(0);
    let charge = |process: &mut crate::Process| {
        process.reductions = process
            .reductions
            .saturating_sub(copy_reductions.min(i32::MAX as usize) as i32)
            .max(0);
    };
    // Port of `erts_bs_append_checked`'s ERL_REFC_BITS_SIZE heap request: BinRef + SubBits.
    // `<<Bin/binary, Bin2/binary>>` fills one destination with the two source ranges.
    if let Ok(collected) = process.ensure_native_roots(8, root_live)
        && let Ok(Some(term)) = arinsal_bits::concat_byte_binary(
            process.x[src_index],
            process.x[extra_index],
            &mut process.heap,
        )
    {
        registers.tmp_mem[2] = process.heap.frame_pointer() as u64;
        charge(process);
        if collected {
            process.sync_native_header();
        } else {
            process.sync_native_cursors();
        }
        return raw(term);
    }
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
    registers.tmp_mem[2] = process.heap.frame_pointer() as u64;
    if result.is_ok() {
        charge(process);
    }
    process.sync_native_cursors();
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
