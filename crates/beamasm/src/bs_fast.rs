//! Inline `bs_create_bin` shapes that BeamAsm builds without the generic helper.
//!
//! Port of erts/emulator/beam/jit/arm/instr_bs.cpp:1076-2494 and
//! erts/emulator/beam/jit/beam_jit_bs.cpp:162-250, OTP-29.1.1.

use crate::bs_construct::{BsCreateBinHelper, BsSegment, BsSegmentKind};
use crate::module::{ArgVal, BeamModuleAssembler, ModuleError};
use arinsal_a64::enc::{Cond, Gpr, Shift, Shifted};
use std::sync::atomic::{AtomicUsize, Ordering};

const HTOP: Gpr = Gpr::x(23);
const E: Gpr = Gpr::x(20);
const C_P: Gpr = Gpr::x(21);
const SCHEDULER_REGS: Gpr = Gpr::x(19);
const ACC: Gpr = Gpr::x(7);
const TMP: Gpr = Gpr::x(10);
const XREGS: [Gpr; 6] = [
    Gpr::x(25),
    Gpr::x(26),
    Gpr::x(27),
    Gpr::x(28),
    Gpr::x(15),
    Gpr::x(16),
];
/// On-heap bitstring limit in bits (erl_bits.h, `ERL_ONHEAP_BITS_LIMIT`).
const ONHEAP_BITS: u64 = 64 * 8;
const HEAP_BITS_TAG: u64 = 0x20;
const BSF_LITTLE_OR_NATIVE: u32 = 2;
const TMP_MEM0: u32 = 16384;

static APPEND_BINARY: AtomicUsize = AtomicUsize::new(0);
static BS_GC: AtomicUsize = AtomicUsize::new(0);

/// Publishes the runtime used for `<<Bin/binary, Bin2/binary>>` (append + one binary).
pub fn install_bs_append_binary(function: usize) {
    APPEND_BINARY.store(function, Ordering::Relaxed);
}

/// Publishes the GC hook `emit_gc_test` calls (`garbage_collect` in BeamAsm).
pub fn install_bs_gc(hook: crate::construct::GcHook) {
    BS_GC.store(hook as usize, Ordering::Relaxed);
}

fn gc_addr() -> usize {
    BS_GC.load(Ordering::Relaxed)
}

fn tmp_at(index: u32) -> u32 {
    std::mem::offset_of!(crate::SchedulerRegisters, tmp_mem) as u32 + index * 8
}

fn bits_state() -> u32 {
    std::mem::offset_of!(crate::SchedulerRegisters, erl_bits_state) as u32
}

struct AccSeg {
    src: ArgVal,
    bits: u64,
    offset: u64,
}

struct Group {
    bits: u64,
    segs: Vec<AccSeg>,
}

struct FixedPlan {
    bits: u64,
    header: u64,
    heap_words: u32,
    data_bytes: u32,
    groups: Vec<Group>,
}

struct PrivatePlan {
    bin: ArgVal,
    extra_bits: u64,
    groups: Vec<Group>,
}

/// Emits a specialized construction when the segment list matches one BeamAsm fast shape.
/// Returns whether this call emitted the whole instruction, including its slow fallback.
#[allow(clippy::too_many_arguments)]
pub(crate) fn emit_fast_bs_create_bin(
    asm: &mut BeamModuleAssembler,
    fail: u32,
    alloc: u32,
    live: u32,
    dst: ArgVal,
    segments: &[BsSegment],
    helper: BsCreateBinHelper,
) -> Result<bool, ModuleError> {
    if let Some(plan) = private_plan(segments) {
        emit_private(asm, fail, alloc, live, dst, segments, helper, &plan)?;
        return Ok(true);
    }
    if let Some(plan) = fixed_plan(segments, alloc) {
        emit_fixed(asm, fail, alloc, live, dst, segments, helper, &plan)?;
        return Ok(true);
    }
    if let Some(src) = utf8_plan(segments) {
        emit_utf8(asm, fail, alloc, live, dst, segments, helper, src)?;
        return Ok(true);
    }
    if APPEND_BINARY.load(Ordering::Relaxed) != 0
        && let Some((src, extra)) = append_binary_plan(segments)
    {
        emit_append_binary(asm, fail, alloc, live, dst, segments, helper, src, extra)?;
        return Ok(true);
    }
    Ok(false)
}

fn private_plan(segments: &[BsSegment]) -> Option<PrivatePlan> {
    let (first, rest) = segments.split_first()?;
    if first.kind != BsSegmentKind::PrivateAppend || first.unit == 0 || first.unit % 8 != 0 {
        return None;
    }
    if !is_all(first) {
        return None;
    }
    let raw = integer_group(rest)?;
    let groups = combine(&raw.segs);
    Some(PrivatePlan {
        bin: first.src,
        extra_bits: raw.bits,
        groups,
    })
}

fn fixed_plan(segments: &[BsSegment], alloc: u32) -> Option<FixedPlan> {
    let group_src = integer_group(segments)?;
    let bits = group_src.bits;
    if bits > ONHEAP_BITS {
        return None;
    }
    let (header, heap_words, data_bytes) = heap_layout(bits)?;
    let _need = heap_words
        .checked_add(alloc)?
        .checked_add(arinsal_term::S_RESERVED as u32)?;
    // One group when the fields fit in the accumulator; otherwise several stores.
    let groups = combine(&group_src.segs);
    Some(FixedPlan {
        bits,
        header,
        heap_words,
        data_bytes,
        groups,
    })
}

fn utf8_plan(segments: &[BsSegment]) -> Option<ArgVal> {
    match segments {
        [seg] if seg.kind == BsSegmentKind::Utf8 => Some(seg.src),
        _ => None,
    }
}

fn append_binary_plan(segments: &[BsSegment]) -> Option<(u32, u32)> {
    match segments {
        [head, tail]
            if head.kind == BsSegmentKind::Append
                && tail.kind == BsSegmentKind::Binary
                && head.unit % 8 == 0
                && tail.unit % 8 == 0
                && is_all(head)
                && is_all(tail) =>
        {
            Some((x_index(head.src)?, x_index(tail.src)?))
        }
        _ => None,
    }
}

fn integer_group(segments: &[BsSegment]) -> Option<Group> {
    if segments.is_empty() {
        return None;
    }
    let mut segs = Vec::with_capacity(segments.len());
    let mut bits = 0u64;
    for seg in segments {
        if seg.kind != BsSegmentKind::Integer || seg.flags & BSF_LITTLE_OR_NATIVE != 0 {
            return None;
        }
        let width = integer_bits(seg)?;
        bits = bits.checked_add(width)?;
        segs.push(AccSeg {
            src: seg.src,
            bits: width,
            offset: 0,
        });
    }
    if bits == 0 || bits > ONHEAP_BITS {
        return None;
    }
    Some(Group { bits, segs })
}

fn integer_bits(seg: &BsSegment) -> Option<u64> {
    let units = match seg.size {
        ArgVal::Immediate(word) | ArgVal::Literal(word) if seg.size_is_units => word,
        ArgVal::Immediate(word) | ArgVal::Literal(word) if word & 0xf == 0xf => {
            u64::try_from((word as i64) >> 4).ok()?
        }
        _ => return None,
    };
    let bits = units.checked_mul(u64::from(seg.unit))?;
    (bits > 0 && bits <= 64 && bits % 8 == 0).then_some(bits)
}

fn is_all(seg: &BsSegment) -> bool {
    match seg.size {
        ArgVal::Immediate(word) | ArgVal::Literal(word) if !seg.size_is_units => {
            word & 0x3f == 0x0b
        }
        _ => false,
    }
}

fn x_index(src: ArgVal) -> Option<u32> {
    match src {
        ArgVal::X(index) => Some(u32::from(index)),
        ArgVal::XMemory(index) => Some(index),
        _ => None,
    }
}

/// Groups big-endian integer fields into 64-bit accumulator stores.
// Port of erts/emulator/beam/jit/beam_jit_bs.cpp:162-250 (beam_jit_bsc_combine_segments).
fn combine(segs: &[AccSeg]) -> Vec<Group> {
    let mut out = Vec::new();
    let mut start = 0;
    let mut combined = 0u64;
    for (index, seg) in segs.iter().enumerate() {
        if index == start {
            combined = seg.bits;
            continue;
        }
        if combined + seg.bits <= 64 {
            combined += seg.bits;
            continue;
        }
        out.push(finish_group(segs, start, index, combined));
        start = index;
        combined = seg.bits;
    }
    if start < segs.len() {
        out.push(finish_group(segs, start, segs.len(), combined));
    }
    out
}

fn finish_group(segs: &[AccSeg], start: usize, end: usize, bits: u64) -> Group {
    let mut offset = 64 - bits;
    let mut grouped = Vec::with_capacity(end - start);
    for seg in segs[start..end].iter().rev() {
        grouped.push(AccSeg {
            src: seg.src,
            bits: seg.bits,
            offset,
        });
        offset += seg.bits;
    }
    grouped.reverse();
    Group {
        bits,
        segs: grouped,
    }
}

fn heap_layout(bits: u64) -> Option<(u64, u32, u32)> {
    if bits > ONHEAP_BITS {
        return None;
    }
    let nbytes = bits.div_ceil(8);
    let data_words = nbytes.div_ceil(8);
    let heap_words = 2 + data_words;
    let header = ((heap_words - 1) << 6) | HEAP_BITS_TAG;
    Some((header, heap_words as u32, (data_words * 8) as u32))
}

#[allow(clippy::too_many_arguments)]
fn emit_private(
    asm: &mut BeamModuleAssembler,
    fail: u32,
    alloc: u32,
    live: u32,
    dst: ArgVal,
    segments: &[BsSegment],
    helper: BsCreateBinHelper,
    plan: &PrivatePlan,
) -> Result<(), ModuleError> {
    let slow = asm.code.new_label();
    let done = asm.code.new_label();
    for group in &plan.groups {
        for seg in &group.segs {
            emit_is_small(asm, seg.src, slow)?;
        }
    }
    // Port of instr_bs.cpp:1865-1880 (private append to binary).
    // The callee is a C function. X4/X5 are caller-saved, so the call sits
    // inside emit_enter_runtime / emit_leave_runtime like erts' checked entry.
    // erts: `add x0, x19, #48; mov x1, c_p; mov x2, bin; mov x3, #bits; bl`.
    let bin = asm.source_reg(plan.bin)?;
    let ebs = std::mem::offset_of!(crate::SchedulerRegisters, erl_bits_state) as u64;
    let update = crate::Update::HEAP_ALLOC.union(crate::Update::X_REGS);
    asm.code.emit(|e| {
        e.mov_const(Gpr::x(0), ebs)?;
        e.add_reg(Gpr::x(0), SCHEDULER_REGS, Gpr::x(0), Shift::Lsl, 0)?;
        e.mov_reg(Gpr::x(1), C_P)?;
        e.mov_reg(Gpr::x(2), bin)?;
        e.mov_const(Gpr::x(3), plan.extra_bits)
    })?;
    crate::emit_enter_runtime(&mut asm.code, live as usize, update)?;
    asm.code.emit(|e| {
        e.mov_const(
            Gpr::x(17),
            arinsal_term::erts_bs_private_append_fast as *const () as usize as u64,
        )?;
        e.blr(Gpr::x(17))
    })?;
    crate::emit_leave_runtime(&mut asm.code, live as usize, update)?;
    // `u64::MAX` is the grow sentinel from the leaf. The reallocating entry is
    // off the byte loop (instr_bs.cpp calls one function; the leaf split keeps
    // that function's no-realloc path frameless).
    let grow = asm.code.new_label();
    let store = asm.code.new_label();
    asm.code.cbz(Gpr::x(0), slow)?;
    asm.code.emit(|e| e.cmn_imm(Gpr::x(0), 1, false))?;
    asm.code.b_cond(Cond::Eq, grow)?;
    asm.code.bind(store)?;
    asm.code
        .emit(|e| e.str_uoff(Gpr::x(0), SCHEDULER_REGS, TMP_MEM0))?;
    let ebs_off = std::mem::offset_of!(crate::SchedulerRegisters, erl_bits_state) as u32;
    asm.code.emit(|e| {
        e.ldr_uoff(Gpr::x(8), SCHEDULER_REGS, ebs_off)?;
        e.ldr_uoff(Gpr::x(9), SCHEDULER_REGS, ebs_off + 8)?;
        e.lsr_imm(TMP, Gpr::x(9), 3)?;
        e.add_reg(Gpr::x(8), Gpr::x(8), TMP, Shift::Lsl, 0)?;
        e.add_imm(
            Gpr::x(9),
            Gpr::x(9),
            u16::try_from(plan.extra_bits).unwrap_or(0),
            false,
        )?;
        e.str_uoff(Gpr::x(9), SCHEDULER_REGS, ebs_off + 8)?;
        e.mov_reg(Gpr::x(14), Gpr::x(8))
    })?;
    let mut bit_at = 0u64;
    for group in &plan.groups {
        emit_group(asm, group)?;
        let ptr = if bit_at == 0 {
            Gpr::x(14)
        } else {
            asm.code
                .emit(|e| e.add_imm(TMP, Gpr::x(14), (bit_at / 8) as u16, false))?;
            TMP
        };
        // Room is the field itself: the resized buffer has no spare byte past this group
        // when the following group, or the end, begins at the next byte.
        emit_store(asm, ptr, group.bits, group.bits)?;
        bit_at += group.bits;
    }
    reload_boxed(asm, dst, TMP_MEM0)?;
    // Grow and the generic builder sit with the yield stubs. Success falls through;
    // erts' private-append body has no trailing branch (instr_bs.cpp:1865-1881).
    asm.code.bind(done)?;
    let segments = segments.to_vec();
    let extra_bits = plan.extra_bits;
    asm.push_bs_cold(Box::new(move |asm| {
        asm.code.bind(grow)?;
        asm.code.emit(|e| {
            e.mov_const(Gpr::x(0), ebs)?;
            e.add_reg(Gpr::x(0), SCHEDULER_REGS, Gpr::x(0), Shift::Lsl, 0)?;
            e.mov_reg(Gpr::x(1), C_P)?;
            e.mov_reg(Gpr::x(2), bin)?;
            e.mov_const(Gpr::x(3), extra_bits)
        })?;
        crate::emit_enter_runtime(&mut asm.code, live as usize, update)?;
        asm.code.emit(|e| {
            e.mov_const(
                Gpr::x(17),
                arinsal_term::erts_bs_private_append_checked as *const () as usize as u64,
            )?;
            e.blr(Gpr::x(17))
        })?;
        crate::emit_leave_runtime(&mut asm.code, live as usize, update)?;
        asm.code.cbz(Gpr::x(0), slow)?;
        asm.code.b(store)?;
        asm.code.bind(slow)?;
        asm.emit_generic_bs_create_bin(fail, alloc, live, dst, &segments, helper)?;
        asm.code.b(done)?;
        Ok(())
    }));
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn emit_fixed(
    asm: &mut BeamModuleAssembler,
    fail: u32,
    alloc: u32,
    live: u32,
    dst: ArgVal,
    segments: &[BsSegment],
    helper: BsCreateBinHelper,
    plan: &FixedPlan,
) -> Result<(), ModuleError> {
    let slow = asm.code.new_label();
    let done = asm.code.new_label();
    // Port of instr_bs.cpp:1933-1958 (allocate heap bitstring of static size)
    // and instr_common.cpp:137-157 (emit_gc_test). A failed check collects and
    // continues; it does not rebuild the binary in the generic helper.
    let gc_stub = emit_static_gc(asm, plan.heap_words, alloc, live, slow)?;
    let ebs = bits_state();
    let saved = tmp_at(1);
    asm.code.emit(|e| {
        e.mov_const(Gpr::x(8), plan.header)?;
        e.mov_const(Gpr::x(9), plan.bits)?;
        e.add_imm(Gpr::x(0), HTOP, 2, false)?;
        e.stp_post(Gpr::x(8), Gpr::x(9), HTOP, 16)?;
        e.str_uoff(HTOP, SCHEDULER_REGS, ebs)?;
        e.str_uoff(Gpr::xzr(), SCHEDULER_REGS, ebs + 8)?;
        e.add_imm(HTOP, HTOP, plan.data_bytes as u16, false)?;
        e.str_uoff(Gpr::x(0), SCHEDULER_REGS, saved)
    })?;
    let mut bit_at = 0u64;
    for group in &plan.groups {
        // Port of instr_bs.cpp:2116-2192: the small test and bfi run after the
        // header store, so that store-to-load of erts_current_bin is covered by
        // the same instructions. A non-small still takes the generic builder;
        // the header already bumped is an unreachable heap bitstring the next
        // GC skips (erts instead extracts via get_sint64 into this binary).
        for seg in &group.segs {
            emit_is_small(asm, seg.src, slow)?;
            emit_accumulate(asm, seg)?;
        }
        // Port of instr_bs.cpp:1102-1119 (update_bin_state, byte-aligned) and
        // 2260-2318 (one store of the accumulator).
        asm.code.emit(|e| {
            e.ldr_uoff(Gpr::x(8), SCHEDULER_REGS, ebs)?;
            e.mov_const(Gpr::x(9), bit_at + group.bits)?;
            e.str_uoff(Gpr::x(9), SCHEDULER_REGS, ebs + 8)?;
            if bit_at != 0 {
                e.add_imm(Gpr::x(8), Gpr::x(8), (bit_at / 8) as u16, false)?;
            }
            Ok(())
        })?;
        let room = plan.data_bytes as u64 * 8 - bit_at;
        emit_store(asm, Gpr::x(8), group.bits, room)?;
        bit_at += group.bits;
    }
    reload_boxed(asm, dst, saved)?;
    // The generic builder and the GC stub are emitted with the yield stubs, after this
    // function, so the success path falls into the next instruction. erts does the same:
    // `b.ls` skips `mov ARG4, Live; bl garbage_collect` and the body has no trailing branch
    // (instr_bs.cpp:1941-1958, instr_common.cpp:150-157).
    asm.code.bind(done)?;
    let segments = segments.to_vec();
    let stub = gc_stub;
    asm.push_bs_cold(Box::new(move |asm| {
        asm.code.bind(slow)?;
        asm.emit_generic_bs_create_bin(fail, alloc, live, dst, &segments, helper)?;
        asm.code.b(done)?;
        if let Some(stub) = stub {
            asm.code.bind(stub)?;
            emit_gc_stub(asm, live, gc_addr())?;
        }
        Ok(())
    }));
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn emit_utf8(
    asm: &mut BeamModuleAssembler,
    fail: u32,
    alloc: u32,
    live: u32,
    dst: ArgVal,
    segments: &[BsSegment],
    helper: BsCreateBinHelper,
    src: ArgVal,
) -> Result<(), ModuleError> {
    let slow = asm.code.new_label();
    let done = asm.code.new_label();
    let reg = asm.source_reg(src)?;
    let shared = asm.code.new_label();
    let after_gc = asm.code.new_label();
    let prepare = asm.code.new_label();
    let sized = asm.code.new_label();
    // Port of instr_bs.cpp:1692-1748 (size utf8). num_bits starts at 0 (ARG8).
    asm.code.emit(|e| {
        e.mov_reg(Gpr::x(7), Gpr::xzr())?;
        e.mov_reg(Gpr::x(2), reg)?;
        e.and_imm(Gpr::x(8), Gpr::x(2), 0xf)?;
        e.cmp_imm(Gpr::x(8), 0xf, false)
    })?;
    asm.code.b_cond(Cond::Ne, slow)?;
    asm.code.emit(|e| {
        e.asr_imm(Gpr::x(8), Gpr::x(2), 4)?;
        e.mov_const(Gpr::x(9), 1)?;
        e.cmp_imm(Gpr::x(8), 0x7f, false)
    })?;
    asm.code.b_cond(Cond::Ls, sized)?;
    asm.code.emit(|e| {
        e.mov_const(Gpr::x(9), 2)?;
        e.cmp_imm(Gpr::x(8), 0x7ff, false)
    })?;
    asm.code.b_cond(Cond::Ls, sized)?;
    asm.code.emit(|e| {
        e.lsr_imm(Gpr::x(10), Gpr::x(8), 11)?;
        e.cmp_imm(Gpr::x(10), 0x1b, false)
    })?;
    asm.code.b_cond(Cond::Eq, slow)?;
    // 65536 = 16 << 12. cset HS then +3 selects 3 or 4 bytes.
    asm.code.emit(|e| e.cmp_imm(Gpr::x(8), 16, true))?;
    asm.code.emit(|e| e.cset(Gpr::x(9), Cond::Cs))?;
    asm.code
        .emit(|e| e.add_imm(Gpr::x(9), Gpr::x(9), 3, false))?;
    // 0x110000 = 272 << 12.
    asm.code.emit(|e| e.cmp_imm(Gpr::x(8), 272, true))?;
    asm.code.b_cond(Cond::Cs, slow)?;
    asm.code.bind(sized)?;
    asm.code
        .emit(|e| e.add_reg(Gpr::x(7), Gpr::x(7), Gpr::x(9), Shift::Lsl, 3))?;

    // Port of instr_bs.cpp:1890-1932 (heap bitstring of dynamic size).
    // x10 = bit size rounded up to a term. Header is that plus header_heap_bits(0).
    let extra_bits = (2 + u64::from(alloc) + arinsal_term::S_RESERVED as u64) * 64;
    asm.code
        .emit(|e| e.add_imm(Gpr::x(10), Gpr::x(7), 63, false))?;
    asm.code
        .emit(|e| e.and_imm(Gpr::x(10), Gpr::x(10), !63u64))?;
    if extra_bits <= 4095 {
        asm.code
            .emit(|e| e.add_imm(Gpr::x(8), Gpr::x(10), extra_bits as u16, false))?;
    } else {
        asm.code.emit(|e| {
            e.mov_const(Gpr::x(8), extra_bits)?;
            e.add_reg(Gpr::x(8), Gpr::x(10), Gpr::x(8), Shift::Lsl, 0)
        })?;
    }
    asm.code
        .emit(|e| e.add_reg(Gpr::x(2), HTOP, Gpr::x(8), Shift::Lsr, 3))?;
    asm.code.emit(|e| e.cmp_reg(Gpr::x(2), E, Shift::Lsl, 0))?;
    asm.code.b_cond(Cond::Ls, after_gc)?;
    let hook = gc_addr();
    if hook == 0 {
        asm.code.b(slow)?;
    } else {
        asm.code.emit(|e| {
            e.lsr_imm(Gpr::x(12), Gpr::x(10), 6)?;
            e.add_imm(
                Gpr::x(12),
                Gpr::x(12),
                (2 + alloc + arinsal_term::S_RESERVED as u32) as u16,
                false,
            )
        })?;
        emit_gc_call(asm, live, hook, Gpr::x(12), &[Gpr::x(7), Gpr::x(10)])?;
    }
    asm.code.bind(after_gc)?;
    let ebs = bits_state();
    // instr_bs.cpp:1979 stores the boxed pointer at TMP_MEM1q (tmp_mem[0]).
    // tmp_mem[1] is the div/rem remainder slot and the GC keep slot for the
    // rounded size, so the pointer must not stay there.
    let saved = tmp_at(0);
    asm.code.emit(|e| {
        e.add_imm(Gpr::x(8), Gpr::x(10), 96, false)?;
        e.add_imm(Gpr::x(0), HTOP, 2, false)?;
        e.stp_post(Gpr::x(8), Gpr::x(7), HTOP, 16)?;
        e.str_uoff(HTOP, SCHEDULER_REGS, ebs)?;
        e.str_uoff(Gpr::xzr(), SCHEDULER_REGS, ebs + 8)?;
        // The 4-byte store below covers only the low half of a rounded word.
        e.str_uoff(Gpr::xzr(), HTOP, 0)?;
        e.add_reg(HTOP, HTOP, Gpr::x(10), Shift::Lsr, 3)?;
        e.str_uoff(Gpr::x(0), SCHEDULER_REGS, saved)
    })?;

    // Port of instr_bs.cpp:1268-1352 (emit_construct_utf8). load_source runs at
    // the encode site; the size path above clobbers the scratch that held a Y
    // source. >= 0x80 goes through the shared encoder; the store is 4 bytes.
    let reg = asm.source_reg(src)?;
    asm.code.emit(|e| {
        e.lsr_imm(Gpr::x(0), reg, 4)?;
        e.mov_const(Gpr::x(3), 8)?;
        e.cmp_imm(Gpr::x(0), 0x80, false)
    })?;
    asm.code.b_cond(Cond::Cc, prepare)?;
    asm.code.bl(shared)?;
    asm.code.bind(prepare)?;
    asm.code.emit(|e| {
        e.ldr_uoff(Gpr::x(8), SCHEDULER_REGS, ebs)?;
        e.str_uoff(Gpr::x(3), SCHEDULER_REGS, ebs + 8)?;
        e.str_uoff(Gpr::w(0), Gpr::x(8), 0)?;
        e.ldr_uoff(Gpr::x(0), SCHEDULER_REGS, saved)?;
        e.str_uoff(Gpr::xzr(), SCHEDULER_REGS, saved)
    })?;
    asm.store_register(dst, Gpr::x(0))?;
    asm.code.bind(done)?;
    let segments = segments.to_vec();
    asm.push_bs_cold(Box::new(move |asm| {
        asm.code.bind(slow)?;
        asm.emit_generic_bs_create_bin(fail, alloc, live, dst, &segments, helper)?;
        asm.code.b(done)?;
        asm.code.bind(shared)?;
        emit_construct_utf8_shared(asm)
    }));
    Ok(())
}

/// Port of instr_bs.cpp:1220-1266 (`emit_construct_utf8_shared`), OTP-29.1.1.
///
/// In: x0 = code point (>= 0x80). Out: x0 = UTF-8 bytes, x3 = bit count.
fn emit_construct_utf8_shared(asm: &mut BeamModuleAssembler) -> Result<(), ModuleError> {
    let more = asm.code.new_label();
    let four = asm.code.new_label();
    asm.code.emit(|e| e.cmp_imm(Gpr::x(0), 0x800, false))?;
    asm.code.b_cond(Cond::Cs, more)?;
    asm.code.emit(|e| {
        e.ubfiz(Gpr::x(8), Gpr::x(0), 8, 6)?;
        e.mov_const(Gpr::x(9), 0x80c0)?;
        e.orr_reg(
            Gpr::x(8),
            Gpr::x(8),
            Shifted {
                reg: Gpr::x(0),
                shift: Shift::Lsr,
                amount: 6,
            },
        )?;
        e.mov_const(Gpr::x(3), 16)?;
        e.orr_reg(
            Gpr::x(0),
            Gpr::x(8),
            Shifted {
                reg: Gpr::x(9),
                shift: Shift::Lsl,
                amount: 0,
            },
        )?;
        e.ret(Gpr::x(30))
    })?;
    asm.code.bind(more)?;
    asm.code.emit(|e| e.lsr_imm(Gpr::x(8), Gpr::x(0), 16))?;
    asm.code.cbnz(Gpr::x(8), four)?;
    asm.code.emit(|e| {
        e.lsl_imm(Gpr::x(8), Gpr::x(0), 2)?;
        e.ubfiz(Gpr::x(9), Gpr::x(0), 16, 6)?;
        e.and_imm(Gpr::x(8), Gpr::x(8), 0x3f00)?;
        e.mov_const(Gpr::x(3), 24)?;
        e.orr_reg(
            Gpr::x(8),
            Gpr::x(8),
            Shifted {
                reg: Gpr::x(0),
                shift: Shift::Lsr,
                amount: 12,
            },
        )?;
        e.orr_reg(
            Gpr::x(8),
            Gpr::x(8),
            Shifted {
                reg: Gpr::x(9),
                shift: Shift::Lsl,
                amount: 0,
            },
        )?;
        e.mov_const(Gpr::x(9), 0x8080e0)?;
        e.orr_reg(
            Gpr::x(0),
            Gpr::x(8),
            Shifted {
                reg: Gpr::x(9),
                shift: Shift::Lsl,
                amount: 0,
            },
        )?;
        e.ret(Gpr::x(30))
    })?;
    asm.code.bind(four)?;
    asm.code.emit(|e| {
        e.lsl_imm(Gpr::x(8), Gpr::x(0), 10)?;
        e.lsr_imm(Gpr::x(9), Gpr::x(0), 4)?;
        e.and_imm(Gpr::x(8), Gpr::x(8), 0x3f_0000)?;
        e.and_imm(Gpr::x(9), Gpr::x(9), 0x3f00)?;
        e.bfxil(Gpr::x(8), Gpr::x(0), 18, 14)?;
        e.mov_const(Gpr::x(3), 32)?;
        e.bfi(Gpr::x(8), Gpr::x(0), 24, 6)?;
        e.orr_reg(
            Gpr::x(8),
            Gpr::x(8),
            Shifted {
                reg: Gpr::x(9),
                shift: Shift::Lsl,
                amount: 0,
            },
        )?;
        e.mov_const(Gpr::x(9), 0x8080_80f0)?;
        e.orr_reg(
            Gpr::x(0),
            Gpr::x(8),
            Shifted {
                reg: Gpr::x(9),
                shift: Shift::Lsl,
                amount: 0,
            },
        )?;
        e.ret(Gpr::x(30))
    })?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn emit_append_binary(
    asm: &mut BeamModuleAssembler,
    fail: u32,
    alloc: u32,
    live: u32,
    dst: ArgVal,
    segments: &[BsSegment],
    helper: BsCreateBinHelper,
    src: u32,
    extra: u32,
) -> Result<(), ModuleError> {
    let slow = asm.code.new_label();
    let done = asm.code.new_label();
    let function = APPEND_BINARY.load(Ordering::Relaxed);
    let roots = live.max(src.saturating_add(1)).max(extra.saturating_add(1));
    let update = crate::Update::HEAP_ALLOC
        .union(crate::Update::X_REGS)
        .union(crate::Update::REDUCTIONS);
    crate::emit_enter_runtime(&mut asm.code, roots as usize, update)?;
    asm.code.emit(|e| {
        e.mov_reg(Gpr::x(0), C_P)?;
        e.mov_const(Gpr::x(1), u64::from(src))?;
        e.mov_const(Gpr::x(2), u64::from(extra))?;
        e.mov_const(Gpr::x(3), u64::from(roots))?;
        e.mov_const(Gpr::x(17), function as u64)?;
        e.str_uoff(Gpr::x(30), C_P, 72)?;
        e.blr(Gpr::x(17))
    })?;
    crate::emit_leave_runtime(&mut asm.code, roots as usize, update)?;
    asm.code.emit(|e| e.ldr_uoff(Gpr::x(30), C_P, 72))?;
    asm.code.cbz(Gpr::x(0), slow)?;
    asm.store_register(dst, Gpr::x(0))?;
    asm.code.bind(done)?;
    let segments = segments.to_vec();
    asm.push_bs_cold(Box::new(move |asm| {
        asm.code.bind(slow)?;
        asm.emit_generic_bs_create_bin(fail, alloc, live, dst, &segments, helper)?;
        asm.code.b(done)?;
        Ok(())
    }));
    Ok(())
}

/// Port of instr_common.cpp:150-157 (`emit_gc_test`).
///
/// Hot path: `add ARG3, HTOP, #bytes; cmp ARG3, E; b.ls cont`. A miss is
/// `mov ARG4, Live; bl garbage_collect` with the body of that fragment out of
/// line, so the header setup is the next straight-line instruction. Returns the
/// stub label when a hook is installed.
fn emit_static_gc(
    asm: &mut BeamModuleAssembler,
    heap_words: u32,
    alloc: u32,
    live: u32,
    slow: arinsal_a64::buf::Label,
) -> Result<Option<arinsal_a64::buf::Label>, ModuleError> {
    let need = heap_words
        .checked_add(alloc)
        .and_then(|words| words.checked_add(arinsal_term::S_RESERVED as u32))
        .ok_or(ModuleError::InvalidOperand("heap check size overflow"))?;
    let bytes = u64::from(need) * 8;
    let ok = asm.code.new_label();
    // ARG3 is x2 (beam_asm.hpp). OTP's fragment reads this register.
    if bytes <= 4095 {
        asm.code
            .emit(|e| e.add_imm(Gpr::x(2), HTOP, bytes as u16, false))?;
    } else {
        asm.code.emit(|e| {
            e.mov_const(Gpr::x(2), bytes)?;
            e.add_reg(Gpr::x(2), HTOP, Gpr::x(2), Shift::Lsl, 0)
        })?;
    }
    asm.code.emit(|e| e.cmp_reg(Gpr::x(2), E, Shift::Lsl, 0))?;
    asm.code.b_cond(Cond::Ls, ok)?;
    let hook = gc_addr();
    let stub = if hook == 0 {
        asm.code.b(slow)?;
        None
    } else {
        let stub = asm.code.new_label();
        asm.code.emit(|e| e.mov_const(Gpr::x(3), u64::from(live)))?;
        asm.code.bl(stub)?;
        Some(stub)
    };
    asm.code.bind(ok)?;
    Ok(stub)
}

/// Out-of-line `garbage_collect` fragment for the static heap check.
///
/// x2 is `HTOP + (heap + alloc + S_RESERVED) * 8`, the value `emit_gc_test` leaves
/// in ARG3. beam_asm_global.cpp:107-109 turns that into a word count and subtracts
/// `S_RESERVED` because `erts_garbage_collect_nobump` adds it again (erl_gc.c:1429).
/// The installed hook is `emit_test_heap`'s contract: the count already includes
/// `S_RESERVED`, and `Process::ensure` adds only the redzone. Subtracting here
/// would skip a collection when fewer than `S_RESERVED` words remain.
fn emit_gc_stub(asm: &mut BeamModuleAssembler, live: u32, hook: usize) -> Result<(), ModuleError> {
    asm.code.emit(|e| {
        e.sub_reg(Gpr::x(12), Gpr::x(2), HTOP, Shift::Lsl, 0)?;
        e.lsr_imm(Gpr::x(12), Gpr::x(12), 3)
    })?;
    emit_gc_call(asm, live, hook, Gpr::x(12), &[])?;
    asm.code.emit(|e| e.ret(Gpr::x(30)))?;
    Ok(())
}

/// `ldr Xdst, [scheduler, saved]` — erts reloads the boxed pointer straight into the
/// destination (`ldr x25, [x19, #8]`), not via a scratch and a move.
fn reload_boxed(
    asm: &mut BeamModuleAssembler,
    dst: ArgVal,
    offset: u32,
) -> Result<(), ModuleError> {
    match dst {
        ArgVal::X(index) if index < 6 => {
            asm.code
                .emit(|e| e.ldr_uoff(XREGS[index as usize], SCHEDULER_REGS, offset))?;
            Ok(())
        }
        _ => {
            asm.code
                .emit(|e| e.ldr_uoff(Gpr::x(0), SCHEDULER_REGS, offset))?;
            asm.store_register(dst, Gpr::x(0))
        }
    }
}

/// Calls the installed GC hook. `words` includes `S_RESERVED`, as `emit_test_heap` does.
/// `keep` is restored afterwards; the frame-pointer slot (`tmp_mem[2]`) is left alone.
fn emit_gc_call(
    asm: &mut BeamModuleAssembler,
    live: u32,
    hook: usize,
    words: Gpr,
    keep: &[Gpr],
) -> Result<(), ModuleError> {
    asm.code
        .emit(|e| e.str_uoff(words, SCHEDULER_REGS, tmp_at(3)))?;
    let mut slot = 0u32;
    for reg in keep {
        if slot == 2 || slot == 3 {
            slot = 4;
        }
        asm.code
            .emit(|e| e.str_uoff(*reg, SCHEDULER_REGS, tmp_at(slot)))?;
        slot += 1;
    }
    let update = crate::Update::HEAP_ALLOC.union(crate::Update::X_REGS);
    crate::emit_enter_runtime(&mut asm.code, live as usize, update)?;
    asm.code.emit(|e| {
        e.str_uoff(Gpr::x(30), C_P, 72)?;
        e.mov_reg(Gpr::x(0), C_P)?;
        e.mov_reg(Gpr::x(1), SCHEDULER_REGS)?;
        e.ldr_uoff(Gpr::x(2), SCHEDULER_REGS, tmp_at(3))?;
        e.mov_const(Gpr::x(3), u64::from(live))?;
        e.mov_reg(Gpr::w(4), Gpr::w(22))?;
        e.mov_const(Gpr::x(17), hook as u64)?;
        e.blr(Gpr::x(17))
    })?;
    // The word count lived in tmp_mem[3], which the native-return bridge treats
    // as a handoff marker. A leftover count would be consumed as that marker.
    asm.code
        .emit(|e| e.str_uoff(Gpr::xzr(), SCHEDULER_REGS, tmp_at(3)))?;
    crate::emit_leave_runtime(&mut asm.code, live as usize, update)?;
    asm.code.emit(|e| {
        e.sub_reg(Gpr::w(22), Gpr::w(22), Gpr::w(0), Shift::Lsl, 0)?;
        e.ldr_uoff(Gpr::x(30), C_P, 72)?;
        e.ldr_uoff(Gpr::x(9), C_P, 40)
    })?;
    asm.error_if_nonzero(Gpr::x(9))?;
    let mut slot = 0u32;
    for reg in keep {
        if slot == 2 || slot == 3 {
            slot = 4;
        }
        asm.code
            .emit(|e| e.ldr_uoff(*reg, SCHEDULER_REGS, tmp_at(slot)))?;
        slot += 1;
    }
    Ok(())
}

fn emit_is_small(
    asm: &mut BeamModuleAssembler,
    src: ArgVal,
    not_small: arinsal_a64::buf::Label,
) -> Result<(), ModuleError> {
    match src {
        ArgVal::Immediate(word) | ArgVal::Literal(word) if word & 0xf == 0xf => Ok(()),
        ArgVal::Immediate(_) | ArgVal::Literal(_) => {
            asm.code.b(not_small)?;
            Ok(())
        }
        _ => {
            let reg = asm.source_reg(src)?;
            asm.code.emit(|e| {
                e.and_imm(TMP, reg, 0xf)?;
                e.cmp_imm(TMP, 0xf, false)
            })?;
            asm.code.b_cond(Cond::Ne, not_small)?;
            Ok(())
        }
    }
}

fn emit_group(asm: &mut BeamModuleAssembler, group: &Group) -> Result<(), ModuleError> {
    // erts does not clear ARG8 when the inserted field covers the only byte
    // `strb` writes (instr_bs.cpp append: bfi at bit 52, rev64, strb).
    let covered =
        group.segs.len() == 1 && group.bits <= 8 && group.segs[0].offset + group.segs[0].bits == 64;
    if !covered {
        asm.code.emit(|e| e.mov_reg(ACC, Gpr::xzr()))?;
    }
    for seg in &group.segs {
        emit_accumulate(asm, seg)?;
    }
    Ok(())
}

// Port of instr_bs.cpp:2164-2212 (accumulate a small integer into ARG8).
fn emit_accumulate(asm: &mut BeamModuleAssembler, seg: &AccSeg) -> Result<(), ModuleError> {
    let reg = asm.source_reg(seg.src)?;
    if seg.bits == 64 {
        asm.code.emit(|e| e.asr_imm(ACC, reg, 4))?;
        return Ok(());
    }
    if seg.offset >= 4 {
        let lsb = (seg.offset - 4) as u8;
        let width = (seg.bits + 4) as u8;
        asm.code.emit(|e| e.bfi(ACC, reg, lsb, width))?;
    } else if seg.offset == 0 && seg.bits <= 60 {
        asm.code.emit(|e| e.bfxil(ACC, reg, 4, seg.bits as u8))?;
    } else {
        asm.code.emit(|e| {
            e.asr_imm(Gpr::x(11), reg, 4)?;
            e.bfi(ACC, Gpr::x(11), seg.offset as u8, seg.bits as u8)
        })?;
    }
    Ok(())
}

/// Stores the reversed accumulator. `room_bits` is how many bits may be written
/// past the logical field (the rounded heap object); a private append passes the
/// field width so the store stays inside the resized buffer.
// Port of instr_bs.cpp:2213-2366 (construct integer segment from accumulator).
fn emit_store(
    asm: &mut BeamModuleAssembler,
    ptr: Gpr,
    num_bits: u64,
    room_bits: u64,
) -> Result<(), ModuleError> {
    let mut num_bytes = num_bits.div_ceil(8);
    if num_bytes == 3 && room_bits >= 32 {
        num_bytes = 4;
    } else if matches!(num_bytes, 5..=7) && room_bits >= 64 {
        num_bytes = 8;
    }
    asm.code.emit(|e| e.rev64(ACC, ACC))?;
    match num_bytes {
        1 => asm.code.emit(|e| e.strb_uoff(Gpr::w(7), ptr, 0))?,
        2 => asm.code.emit(|e| e.strh_uoff(Gpr::w(7), ptr, 0))?,
        4 => asm.code.emit(|e| e.str_uoff(Gpr::w(7), ptr, 0))?,
        8 => asm.code.emit(|e| e.str_uoff(ACC, ptr, 0))?,
        3 => asm.code.emit(|e| {
            e.strh_uoff(Gpr::w(7), ptr, 0)?;
            e.lsr_imm(ACC, ACC, 16)?;
            e.strb_uoff(Gpr::w(7), ptr, 2)
        })?,
        5 => asm.code.emit(|e| {
            e.str_uoff(Gpr::w(7), ptr, 0)?;
            e.lsr_imm(ACC, ACC, 32)?;
            e.strb_uoff(Gpr::w(7), ptr, 4)
        })?,
        6 => asm.code.emit(|e| {
            e.str_uoff(Gpr::w(7), ptr, 0)?;
            e.lsr_imm(ACC, ACC, 32)?;
            e.strh_uoff(Gpr::w(7), ptr, 4)
        })?,
        7 => asm.code.emit(|e| {
            e.str_uoff(Gpr::w(7), ptr, 0)?;
            e.lsr_imm(ACC, ACC, 32)?;
            e.strh_uoff(Gpr::w(7), ptr, 4)?;
            e.lsr_imm(ACC, ACC, 16)?;
            e.strb_uoff(Gpr::w(7), ptr, 6)
        })?,
        _ => return Err(ModuleError::InvalidOperand("integer store width")),
    }
    Ok(())
}
