//! Inline `bs_create_bin` shapes that BeamAsm builds without the generic helper.
//!
//! Port of erts/emulator/beam/jit/arm/instr_bs.cpp:1076-2494, OTP-29.1.1.

use crate::bs_construct::{BsSegment, BsSegmentKind};
use crate::common::bs::{BscAction, BscSegment, beam_jit_bsc_combine_segments};
use crate::module::{ArgVal, BeamModuleAssembler, ModuleError};
use arinsal_a64::enc::{Cond, Gpr, Shift, Shifted};
use arinsal_term::{Term, atoms};

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
const TMP_MEM0: u32 = crate::arm::beam_asm::tmp_mem_ref(0);

fn tmp_at(index: usize) -> u32 {
    crate::arm::beam_asm::tmp_mem_ref(index)
}

fn bits_state() -> u32 {
    crate::arm::beam_asm::ERL_BITS_STATE_REF
}

struct FixedPlan {
    bits: u64,
    header: u64,
    heap_words: u32,
    data_bytes: u32,
    segments: Vec<BscSegment>,
}

struct PrivatePlan {
    bin: ArgVal,
    extra_bits: u64,
    segments: Vec<BscSegment>,
}

struct AppendPlan {
    bin: ArgVal,
    unit: u64,
    extra_bits: u64,
    segments: Vec<BscSegment>,
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
) -> Result<bool, ModuleError> {
    if let Some(plan) = private_plan(asm, segments) {
        emit_private(asm, fail, alloc, live, dst, segments, &plan)?;
        return Ok(true);
    }
    // The slow path rebuilds from the source register, so a collection inside the helper
    // must have updated it: only a source among the live roots takes this path.
    if let Some(plan) = append_plan(asm, segments)
        && x_index(plan.bin).is_some_and(|index| index < live)
    {
        emit_append(asm, fail, alloc, live, dst, segments, &plan)?;
        return Ok(true);
    }
    if let Some(plan) = fixed_plan(asm, segments, alloc) {
        emit_fixed(asm, fail, alloc, live, dst, segments, &plan)?;
        return Ok(true);
    }
    if let Some(src) = utf8_plan(segments) {
        emit_utf8(asm, fail, alloc, live, dst, segments, src)?;
        return Ok(true);
    }
    Ok(false)
}

fn private_plan(asm: &BeamModuleAssembler, segments: &[BsSegment]) -> Option<PrivatePlan> {
    let (first, rest) = segments.split_first()?;
    if first.kind != BsSegmentKind::PrivateAppend || first.unit == 0 || first.unit % 8 != 0 {
        return None;
    }
    if !is_all(first) {
        return None;
    }
    let (extra_bits, segments) = integer_group(asm, rest)?;
    Some(PrivatePlan {
        bin: first.src,
        extra_bits,
        segments,
    })
}

// Port of erts/emulator/beam/jit/arm/instr_bs.cpp:1810-1845 (`am_append`), OTP-29.1.1.
fn append_plan(asm: &BeamModuleAssembler, segments: &[BsSegment]) -> Option<AppendPlan> {
    let (first, rest) = segments.split_first()?;
    if first.kind != BsSegmentKind::Append
        || first.unit == 0
        || first.unit % 8 != 0
        || !is_all(first)
        || x_index(first.src).is_none()
    {
        return None;
    }
    let (extra_bits, segments) = integer_group(asm, rest)?;
    Some(AppendPlan {
        bin: first.src,
        unit: u64::from(first.unit),
        extra_bits,
        segments,
    })
}

fn fixed_plan(asm: &BeamModuleAssembler, segments: &[BsSegment], alloc: u32) -> Option<FixedPlan> {
    let (bits, combined) = integer_group(asm, segments)?;
    if bits > ONHEAP_BITS {
        return None;
    }
    let (header, heap_words, data_bytes) = heap_layout(bits)?;
    let _need = heap_words
        .checked_add(alloc)?
        .checked_add(arinsal_term::S_RESERVED as u32)?;
    // One group when the fields fit in the accumulator; otherwise several stores.
    Some(FixedPlan {
        bits,
        header,
        heap_words,
        data_bytes,
        segments: combined,
    })
}

fn utf8_plan(segments: &[BsSegment]) -> Option<ArgVal> {
    match segments {
        [seg] if seg.kind == BsSegmentKind::Utf8 => Some(seg.src),
        _ => None,
    }
}

fn integer_group(
    asm: &BeamModuleAssembler,
    segments: &[BsSegment],
) -> Option<(u64, Vec<BscSegment>)> {
    if segments.is_empty() {
        return None;
    }
    let mut segs = Vec::with_capacity(segments.len());
    let mut bits = 0u64;
    for seg in segments {
        if seg.kind != BsSegmentKind::Integer || seg.flags & BSF_LITTLE_OR_NATIVE != 0 {
            return None;
        }
        let width = integer_bits(asm, seg)?;
        bits = bits.checked_add(width)?;
        segs.push(BscSegment {
            type_: ArgVal::Immediate(Term::atom(atoms::INTEGER).word()),
            unit: u64::from(seg.unit),
            flags: u64::from(seg.flags),
            src: seg.src,
            size: seg.size,
            error_info: 0,
            offset_in_accumulator: 0,
            effective_size: width as i64,
            action: BscAction::Direct,
        });
    }
    if bits == 0 || bits > ONHEAP_BITS {
        return None;
    }
    Some((bits, beam_jit_bsc_combine_segments(&segs)))
}

fn integer_bits(asm: &BeamModuleAssembler, seg: &BsSegment) -> Option<u64> {
    let word = asm.constant_word(seg.size)?;
    let units = if seg.size_is_units {
        word
    } else if word & 0xf == 0xf {
        u64::try_from((word as i64) >> 4).ok()?
    } else {
        return None;
    };
    let bits = units.checked_mul(u64::from(seg.unit))?;
    (bits > 0 && bits <= 64 && bits % 8 == 0).then_some(bits)
}

fn is_all(seg: &BsSegment) -> bool {
    seg.size_is_all
}

fn x_index(src: ArgVal) -> Option<u32> {
    match src {
        ArgVal::X(index) => Some(index),
        _ => None,
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
    plan: &PrivatePlan,
) -> Result<(), ModuleError> {
    let slow = asm.code.new_label();
    let done = asm.code.new_label();
    for seg in &plan.segments {
        if matches!(
            seg.action,
            BscAction::AccumulateFirst | BscAction::Accumulate
        ) {
            emit_is_small(asm, seg.src, slow)?;
        }
    }
    // Port of erts/emulator/beam/jit/arm/instr_bs.cpp:1865-1880 (`am_private_append`), OTP-29.1.1.
    let bin = asm.source_reg(plan.bin)?;
    let ebs = crate::arm::beam_asm::ERL_BITS_STATE_REF as u16;
    let update = crate::Update::HEAP_ALLOC
        .union(crate::Update::X_REGS)
        .union(crate::Update::REDUCTIONS);
    asm.code.emit(|e| {
        e.add_imm(Gpr::x(0), SCHEDULER_REGS, ebs, false)?;
        e.mov_reg(Gpr::x(1), C_P)?;
        e.mov_reg(Gpr::x(2), bin)?;
        e.mov_const(Gpr::x(3), plan.extra_bits)
    })?;
    crate::emit_enter_runtime(&mut asm.code, live as usize, update)?;
    emit_direct_call(
        asm,
        crate::raw::erts_bs_private_append_checked as *const () as usize,
    )?;
    crate::emit_leave_runtime(&mut asm.code, live as usize, update)?;
    // Port of erts/emulator/beam/jit/arm/instr_bs.cpp:1881, OTP-29.1.1:
    // "There is no way the call can fail on a 64-bit architecture."
    asm.code
        .emit(|e| e.str_uoff(Gpr::x(0), SCHEDULER_REGS, TMP_MEM0))?;
    let ebs_off = crate::arm::beam_asm::ERL_BITS_STATE_REF;
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
    for group in plan
        .segments
        .split_inclusive(|seg| seg.action == BscAction::Store)
    {
        emit_group(asm, group)?;
        let bits = group
            .last()
            .expect("stored accumulator group")
            .effective_size as u64;
        let ptr = if bit_at == 0 {
            Gpr::x(14)
        } else {
            asm.code
                .emit(|e| e.add_imm(TMP, Gpr::x(14), (bit_at / 8) as u16, false))?;
            TMP
        };
        // Room is the field itself: the resized buffer has no spare byte past this group
        // when the following group, or the end, begins at the next byte.
        emit_store(asm, ptr, bits, bits)?;
        bit_at += bits;
    }
    reload_boxed(asm, dst, TMP_MEM0)?;
    asm.code.bind(done)?;
    let segments = segments.to_vec();
    asm.push_bs_cold(Box::new(move |asm| {
        asm.code.bind(slow)?;
        asm.emit_generic_bs_create_bin(fail, alloc, live, dst, &segments)?;
        asm.code.b(done)?;
        Ok(())
    }));
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn emit_append(
    asm: &mut BeamModuleAssembler,
    fail: u32,
    alloc: u32,
    live: u32,
    dst: ArgVal,
    segments: &[BsSegment],
    plan: &AppendPlan,
) -> Result<(), ModuleError> {
    let slow = asm.code.new_label();
    let failed = asm.code.new_label();
    let done = asm.code.new_label();
    for seg in &plan.segments {
        if matches!(
            seg.action,
            BscAction::AccumulateFirst | BscAction::Accumulate
        ) {
            emit_is_small(asm, seg.src, slow)?;
        }
    }
    // Port of erts/emulator/beam/jit/arm/instr_bs.cpp:1810-1845 (`am_append`), OTP-29.1.1:
    // `mov_arg(ArgXRegister(Live), src)`, then `erts_bs_append_checked(c_p, reg, Live, ...)`.
    let append_source = ArgVal::X(live);
    let source = asm.source_reg(plan.bin)?;
    asm.store_register(append_source, source)?;
    let update = crate::Update::HEAP_ALLOC
        .union(crate::Update::X_REGS)
        .union(crate::Update::REDUCTIONS);
    crate::emit_enter_runtime(&mut asm.code, live as usize + 1, update)?;
    asm.code.emit(|e| {
        e.mov_reg(Gpr::x(0), C_P)?;
        crate::arm::beam_asm::load_x_reg_array(e, Gpr::x(1))?;
        e.mov_const(Gpr::x(2), u64::from(live))?;
        e.mov_const(Gpr::x(3), plan.extra_bits)?;
        e.mov_const(Gpr::x(4), u64::from(alloc))?;
        e.mov_const(Gpr::x(5), plan.unit)
    })?;
    emit_direct_call(
        asm,
        crate::raw::erts_bs_append_checked as *const () as usize,
    )?;
    crate::emit_leave_runtime(&mut asm.code, live as usize + 1, update)?;
    asm.code.cbz(Gpr::x(0), slow)?;
    asm.code.emit(|e| e.cmn_imm(Gpr::x(0), 1, false))?;
    asm.code.b_cond(Cond::Eq, failed)?;
    asm.code
        .emit(|e| e.str_uoff(Gpr::x(0), SCHEDULER_REGS, TMP_MEM0))?;
    let ebs_off = crate::arm::beam_asm::ERL_BITS_STATE_REF;
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
    for group in plan
        .segments
        .split_inclusive(|seg| seg.action == BscAction::Store)
    {
        emit_group(asm, group)?;
        let bits = group
            .last()
            .expect("stored accumulator group")
            .effective_size as u64;
        let ptr = if bit_at == 0 {
            Gpr::x(14)
        } else {
            asm.code
                .emit(|e| e.add_imm(TMP, Gpr::x(14), (bit_at / 8) as u16, false))?;
            TMP
        };
        emit_store(asm, ptr, bits, bits)?;
        bit_at += bits;
    }
    reload_boxed(asm, dst, TMP_MEM0)?;
    asm.code.bind(done)?;
    let segments = segments.to_vec();
    asm.push_bs_cold(Box::new(move |asm| {
        asm.code.bind(failed)?;
        asm.branch_error()?;
        asm.code.bind(slow)?;
        asm.emit_generic_bs_create_bin(fail, alloc, live, dst, &segments)?;
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
    plan: &FixedPlan,
) -> Result<(), ModuleError> {
    let slow = asm.code.new_label();
    let done = asm.code.new_label();
    // Port of instr_bs.cpp:1933-1958 (allocate heap bitstring of static size)
    // and instr_common.cpp:137-157 (emit_gc_test). A failed check collects and
    // continues; it does not rebuild the binary in the generic helper.
    let need = plan
        .heap_words
        .checked_add(alloc)
        .ok_or(ModuleError::InvalidOperand("heap check size overflow"))?;
    asm.emit_test_heap(need, live)?;
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
    for group in plan
        .segments
        .split_inclusive(|seg| seg.action == BscAction::Store)
    {
        // Port of instr_bs.cpp:2116-2192: the small test and bfi run after the
        // header store, so that store-to-load of erts_current_bin is covered by
        // the same instructions. A non-small still takes the generic builder;
        // the header already bumped is an unreachable heap bitstring the next
        // GC skips (erts instead extracts via get_sint64 into this binary).
        for seg in group {
            if matches!(
                seg.action,
                BscAction::AccumulateFirst | BscAction::Accumulate
            ) {
                emit_is_small(asm, seg.src, slow)?;
                emit_accumulate(asm, seg)?;
            }
        }
        let bits = group
            .last()
            .expect("stored accumulator group")
            .effective_size as u64;
        // Port of instr_bs.cpp:1102-1119 (update_bin_state, byte-aligned) and
        // 2260-2318 (one store of the accumulator).
        asm.code.emit(|e| {
            e.ldr_uoff(Gpr::x(8), SCHEDULER_REGS, ebs)?;
            e.mov_const(Gpr::x(9), bit_at + bits)?;
            e.str_uoff(Gpr::x(9), SCHEDULER_REGS, ebs + 8)?;
            if bit_at != 0 {
                e.add_imm(Gpr::x(8), Gpr::x(8), (bit_at / 8) as u16, false)?;
            }
            Ok(())
        })?;
        let room = plan.data_bytes as u64 * 8 - bit_at;
        emit_store(asm, Gpr::x(8), bits, room)?;
        bit_at += bits;
    }
    reload_boxed(asm, dst, saved)?;
    // The generic builder is emitted with the yield stubs, after this function, so the
    // success path falls into the next instruction.
    asm.code.bind(done)?;
    let segments = segments.to_vec();
    asm.push_bs_cold(Box::new(move |asm| {
        asm.code.bind(slow)?;
        asm.emit_generic_bs_create_bin(fail, alloc, live, dst, &segments)?;
        asm.code.b(done)?;
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
    // sizeReg (x7) and TMP3 (x10) survive the collection in TMP_MEM1q/TMP_MEM2q.
    asm.code
        .emit(|e| e.stp(Gpr::x(7), Gpr::x(10), SCHEDULER_REGS, tmp_at(0) as i16))?;
    asm.code.emit(|e| e.mov_const(Gpr::x(3), u64::from(live)))?;
    asm.gc_fragment_call()?;
    asm.code
        .emit(|e| e.ldp(Gpr::x(7), Gpr::x(10), SCHEDULER_REGS, tmp_at(0) as i16))?;
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
        asm.emit_generic_bs_create_bin(fail, alloc, live, dst, &segments)?;
        asm.code.b(done)?;
        asm.code.bind(shared)?;
        emit_construct_utf8_shared(asm)
    }));
    Ok(())
}

/// `runtime_call<Function>()`: load the erts runtime entry and issue its ABI call.
fn emit_direct_call(asm: &mut BeamModuleAssembler, target: usize) -> Result<(), ModuleError> {
    asm.code.emit(|e| {
        e.mov_const(Gpr::x(17), target as u64)?;
        e.blr(Gpr::x(17))
    })?;
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

/// `ldur Xdst, [scheduler, saved]` — erts reloads the boxed pointer straight into the
/// destination (`ldr x25, TMP_MEM1q`), not via a scratch and a move.
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

fn emit_is_small(
    asm: &mut BeamModuleAssembler,
    src: ArgVal,
    not_small: arinsal_a64::buf::Label,
) -> Result<(), ModuleError> {
    if let Some(word) = asm.constant_word(src) {
        if word & 0xf == 0xf {
            return Ok(());
        }
        asm.code.b(not_small)?;
        Ok(())
    } else {
        let reg = asm.source_reg(src)?;
        asm.code.emit(|e| {
            e.and_imm(TMP, reg, 0xf)?;
            e.cmp_imm(TMP, 0xf, false)
        })?;
        asm.code.b_cond(Cond::Ne, not_small)?;
        Ok(())
    }
}

fn emit_group(asm: &mut BeamModuleAssembler, group: &[BscSegment]) -> Result<(), ModuleError> {
    // erts does not clear ARG8 when the inserted field covers the only byte
    // `strb` writes (instr_bs.cpp append: bfi at bit 52, rev64, strb).
    let stored = group.last().expect("group ends in a STORE action");
    let accumulates = &group[..group.len() - 1];
    let covered = accumulates.len() == 1
        && stored.effective_size <= 8
        && accumulates[0].offset_in_accumulator + accumulates[0].effective_size as u64 == 64;
    if !covered {
        asm.code.emit(|e| e.mov_reg(ACC, Gpr::xzr()))?;
    }
    for seg in accumulates {
        if matches!(
            seg.action,
            BscAction::AccumulateFirst | BscAction::Accumulate
        ) {
            emit_accumulate(asm, seg)?;
        }
    }
    Ok(())
}

// Port of instr_bs.cpp:2164-2212 (accumulate a small integer into ARG8).
fn emit_accumulate(asm: &mut BeamModuleAssembler, seg: &BscSegment) -> Result<(), ModuleError> {
    let reg = asm.source_reg(seg.src)?;
    let bits = seg.effective_size as u64;
    let offset = seg.offset_in_accumulator;
    if bits == 64 {
        asm.code.emit(|e| e.asr_imm(ACC, reg, 4))?;
        return Ok(());
    }
    if offset >= 4 {
        let lsb = (offset - 4) as u8;
        let width = (bits + 4) as u8;
        asm.code.emit(|e| e.bfi(ACC, reg, lsb, width))?;
    } else if offset == 0 && bits <= 60 {
        asm.code.emit(|e| e.bfxil(ACC, reg, 4, bits as u8))?;
    } else {
        asm.code.emit(|e| {
            e.asr_imm(Gpr::x(11), reg, 4)?;
            e.bfi(ACC, Gpr::x(11), offset as u8, bits as u8)
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
