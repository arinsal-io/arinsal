//! AArch64 emitters for BEAM bit syntax construction.
//!
//! Port of erts/emulator/beam/jit/arm/instr_bs.cpp (`emit_i_bs_create_bin`), OTP-29.1.1.

use super::beam_asm::NUM_REGISTER_BACKED_XREGS;

use crate::module::{ArgVal, BeamModuleAssembler, ModuleError};
use arinsal_a64::enc::{Cond, Gpr, Shift};

/// Construction segment kind, in the numbering shared with the runtime hook.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum BsSegmentKind {
    /// Integer segment.
    Integer = 0,
    /// Floating point segment.
    Float = 1,
    /// Binary or bitstring segment.
    Binary = 2,
    /// Append to a binary.
    Append = 3,
    /// Private append into a unique writable binary.
    PrivateAppend = 4,
    /// UTF-8 code point.
    Utf8 = 5,
    /// UTF-16 code point.
    Utf16 = 6,
    /// UTF-32 code point.
    Utf32 = 7,
    /// Literal bytes from the module string table.
    String = 8,
}

/// One segment operand group (`Type Seg Unit Flags Src Size`) of `bs_create_bin`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BsSegment {
    /// Segment operation.
    pub kind: BsSegmentKind,
    /// One-based source segment index for construction error metadata.
    pub index: u32,
    /// Value source.
    pub src: ArgVal,
    /// Size operand: a term, or an untagged unit count when `size_is_units`.
    pub size: ArgVal,
    /// Whether `size` is the `all` atom.
    pub size_is_all: bool,
    /// Whether `size` is an untagged unit count rather than a term.
    pub size_is_units: bool,
    /// Size multiplier.
    pub unit: u32,
    /// `BSF_*` flag bits.
    pub flags: u32,
}

const C_P: Gpr = Gpr::x(21);
const SCHEDULER_REGS: Gpr = Gpr::x(19);
// BeamAsm's create-bin size accumulator is ARG8, which is x7 on AArch64.
// Port of erts/emulator/beam/jit/arm/beam_asm.hpp:160, OTP-29.1.1.
const BITS: Gpr = Gpr::x(7);
const SEG_BITS: Gpr = Gpr::x(11);
const SCRATCH: Gpr = Gpr::x(12);
const RELOADED_ARG: Gpr = Gpr::x(9);
const SAVED_BITS: u32 = crate::arm::beam_asm::tmp_mem_ref(0);
const SAVED_RESULT: u32 = crate::arm::beam_asm::tmp_mem_ref(1);
const BITSTRING_HEADER_MASK: u64 = 0x38;
const TAG_HEADER_HEAP_BITS: u16 = 0x20;
const HEADER_SUB_BITS: u16 = 0x124;

#[derive(Clone, Copy)]
struct SegmentFailureLabels {
    size_badarg: arinsal_a64::buf::Label,
    type_badarg: arinsal_a64::buf::Label,
    system_limit: arinsal_a64::buf::Label,
    write_badarg: arinsal_a64::buf::Label,
}

#[derive(Clone, Copy)]
enum FailReason {
    BadArg,
    Depends,
    SystemLimit,
}

#[derive(Clone, Copy)]
enum FailInfo {
    Fvalue,
    Type,
    Size,
    Unit,
    Depends,
}

#[derive(Clone, Copy)]
enum FailValue {
    Arg1,
    SizeArg3,
    SourceArg3,
    Fvalue,
    RuntimeResult,
}

fn inverse_cond(condition: Cond) -> Cond {
    match condition {
        Cond::Eq => Cond::Ne,
        Cond::Ne => Cond::Eq,
        Cond::Cs => Cond::Cc,
        Cond::Cc => Cond::Cs,
        Cond::Mi => Cond::Pl,
        Cond::Pl => Cond::Mi,
        Cond::Vs => Cond::Vc,
        Cond::Vc => Cond::Vs,
        Cond::Hi => Cond::Ls,
        Cond::Ls => Cond::Hi,
        Cond::Ge => Cond::Lt,
        Cond::Lt => Cond::Ge,
        Cond::Gt => Cond::Le,
        Cond::Le => Cond::Gt,
        Cond::Al => Cond::Al,
    }
}

fn branch_if_condition(
    asm: &mut BeamModuleAssembler,
    condition: Cond,
    target: arinsal_a64::buf::Label,
) -> Result<(), ModuleError> {
    let fallthrough = asm.code.new_label();
    asm.code.b_cond(inverse_cond(condition), fallthrough)?;
    asm.code.b(target)?;
    asm.code.bind(fallthrough)?;
    Ok(())
}

fn branch_if_bit_set(
    asm: &mut BeamModuleAssembler,
    register: Gpr,
    bit: u8,
    target: arinsal_a64::buf::Label,
) -> Result<(), ModuleError> {
    let fallthrough = asm.code.new_label();
    asm.code.tbz(register, bit, fallthrough)?;
    asm.code.b(target)?;
    asm.code.bind(fallthrough)?;
    Ok(())
}

fn source_reg_after_allocation(
    asm: &mut BeamModuleAssembler,
    source: ArgVal,
) -> Result<Gpr, ModuleError> {
    source_reg_after_allocation_into(asm, source, RELOADED_ARG)
}

fn source_reg_after_allocation_into(
    asm: &mut BeamModuleAssembler,
    source: ArgVal,
    destination: Gpr,
) -> Result<Gpr, ModuleError> {
    match source {
        ArgVal::X(index) if index < NUM_REGISTER_BACKED_XREGS => asm.source_reg(source),
        ArgVal::X(index) if index < 1024 => {
            let offset = crate::arm::beam_asm::x_ref(index);
            asm.code
                .emit(|e| e.ldr_uoff(destination, SCHEDULER_REGS, offset))?;
            Ok(destination)
        }
        ArgVal::Y(index) => {
            let offset = index
                .checked_mul(8)
                .ok_or(ModuleError::InvalidOperand("Y register offset overflow"))?;
            asm.code
                .emit(|e| e.ldr_uoff(destination, Gpr::x(20), offset))?;
            Ok(destination)
        }
        _ => asm.source_reg_into(source, destination),
    }
}

// Port of erts/emulator/beam/jit/arm/instr_bs.cpp:1442-2494 (emit_i_bs_create_bin), OTP-29.1.1.
fn emit_bs_create_bin_generic(
    asm: &mut BeamModuleAssembler,
    fail: u32,
    alloc: u32,
    live: u32,
    dst: ArgVal,
    segments: &[BsSegment],
) -> Result<(), ModuleError> {
    let route_failure = asm.code.new_label();
    let success = asm.code.new_label();
    let failures = segments
        .iter()
        .map(|_| {
            if fail == 0 {
                SegmentFailureLabels {
                    size_badarg: asm.code.new_label(),
                    type_badarg: asm.code.new_label(),
                    system_limit: asm.code.new_label(),
                    write_badarg: asm.code.new_label(),
                }
            } else {
                SegmentFailureLabels {
                    size_badarg: route_failure,
                    type_badarg: route_failure,
                    system_limit: route_failure,
                    write_badarg: route_failure,
                }
            }
        })
        .collect::<Vec<_>>();
    asm.code.emit(|e| e.mov_const(BITS, 0))?;

    for (segment, &segment_failures) in segments.iter().zip(&failures) {
        if matches!(
            segment.kind,
            BsSegmentKind::Append | BsSegmentKind::PrivateAppend
        ) {
            continue;
        }
        emit_segment_size(asm, segment, true, segment_failures)?;
    }

    asm.code
        .emit(|e| e.str_uoff(BITS, SCHEDULER_REGS, SAVED_BITS))?;
    asm.code.emit(|e| {
        e.mov_const(Gpr::x(3), u64::from(alloc))?;
        e.mov_const(Gpr::x(4), u64::from(live))
    })?;
    if let Some(segment) = segments.first().filter(|s| s.kind == BsSegmentKind::Append) {
        let source = asm.source_reg(segment.src)?;
        let append_source = ArgVal::X(live);
        asm.store_register(append_source, source)?;
        asm.code.emit(|e| {
            crate::arm::beam_asm::load_x_reg_array(e, Gpr::x(9))?;
            e.mov_const(Gpr::x(10), u64::from(live))?;
            e.mov_reg(Gpr::x(11), BITS)?;
            e.mov_const(Gpr::x(12), u64::from(alloc))?;
            e.mov_const(Gpr::x(13), u64::from(segment.unit))
        })?;
        emit_runtime_call(
            asm,
            crate::raw::erts_bs_append_checked as *const () as usize,
            (live + 1) as usize,
            crate::Update::HEAP_ALLOC
                .union(crate::Update::X_REGS)
                .union(crate::Update::REDUCTIONS),
            &[
                C_P,
                Gpr::x(9),
                Gpr::x(10),
                Gpr::x(11),
                Gpr::x(12),
                Gpr::x(13),
            ],
        )?;
        let append_ok = asm.code.new_label();
        let append_failed = asm.code.new_label();
        asm.code.cbz(Gpr::x(0), append_failed)?;
        asm.code.b(append_ok)?;
        asm.code.bind(append_failed)?;
        if fail == 0 {
            let error_segment = BsSegment {
                src: append_source,
                ..*segment
            };
            emit_bs_fail_info(
                asm,
                live as usize,
                &error_segment,
                FailReason::BadArg,
                FailInfo::Fvalue,
                FailValue::SourceArg3,
            )?;
        }
        asm.code.b(route_failure)?;
        asm.code.bind(append_ok)?;
        let bits_state = crate::arm::beam_asm::ERL_BITS_STATE_REF;
        asm.code.emit(|e| {
            e.ldr_uoff(Gpr::x(8), SCHEDULER_REGS, bits_state + 8)?;
            e.ldr_uoff(BITS, SCHEDULER_REGS, SAVED_BITS)?;
            e.add_reg(BITS, BITS, Gpr::x(8), Shift::Lsl, 0)?;
            e.str_uoff(BITS, SCHEDULER_REGS, SAVED_BITS)
        })?;
    } else if let Some(segment) = segments
        .first()
        .filter(|s| s.kind == BsSegmentKind::PrivateAppend)
    {
        // Port of erts/emulator/beam/jit/arm/instr_bs.cpp:1865-1880 (`am_private_append`),
        // OTP-29.1.1: `load_erl_bits_state(ARG1); mov(ARG2, c_p); mov_arg(ARG3, seg.src);
        // mov(ARG4, sizeReg)`. The source goes straight into ARG3: a Y or memory X source loads
        // through the module scratch register (x9), which a staged argument copy would overwrite.
        let ebs = crate::arm::beam_asm::ERL_BITS_STATE_REF;
        asm.code.emit(|e| {
            e.add_imm(Gpr::x(0), SCHEDULER_REGS, ebs as u16, false)?;
            e.mov_reg(Gpr::x(1), C_P)?;
            e.mov_reg(Gpr::x(3), BITS)
        })?;
        asm.mov_arg_to_reg(Gpr::x(2), segment.src)?;
        emit_runtime_call(
            asm,
            crate::raw::erts_bs_private_append_checked as *const () as usize,
            live as usize,
            crate::Update::NONE,
            &[Gpr::x(0), Gpr::x(1), Gpr::x(2), Gpr::x(3)],
        )?;
        // Port of erts/emulator/beam/jit/arm/instr_bs.cpp:1881, OTP-29.1.1:
        // "There is no way the call can fail on a 64-bit architecture."
        let bits_state = crate::arm::beam_asm::ERL_BITS_STATE_REF;
        asm.code.emit(|e| {
            e.ldr_uoff(Gpr::x(8), SCHEDULER_REGS, bits_state + 8)?;
            e.ldr_uoff(BITS, SCHEDULER_REGS, SAVED_BITS)?;
            e.add_reg(BITS, BITS, Gpr::x(8), Shift::Lsl, 0)?;
            e.str_uoff(BITS, SCHEDULER_REGS, SAVED_BITS)
        })?;
    } else {
        let ebs = crate::arm::beam_asm::ERL_BITS_STATE_REF;
        asm.code.emit(|e| {
            crate::arm::beam_asm::load_x_reg_array(e, Gpr::x(9))?;
            e.mov_reg(Gpr::x(11), BITS)?;
            e.add_imm(Gpr::x(10), SCHEDULER_REGS, ebs as u16, false)?;
            e.mov_const(Gpr::x(12), u64::from(alloc))?;
            e.mov_const(Gpr::x(13), u64::from(live))
        })?;
        emit_runtime_call(
            asm,
            crate::raw::beam_jit_bs_init_bits as *const () as usize,
            live as usize,
            crate::Update::HEAP_ALLOC
                .union(crate::Update::X_REGS)
                .union(crate::Update::REDUCTIONS),
            &[
                C_P,
                Gpr::x(9),
                Gpr::x(10),
                Gpr::x(11),
                Gpr::x(12),
                Gpr::x(13),
            ],
        )?;
    }
    // erts tests ARG1 only for `am_append` (above) and never for `am_private_append`.
    // Port of erts/emulator/beam/jit/arm/instr_bs.cpp:1881 and :1979 (`a.str(ARG1, TMP_MEM1q)`).
    if segments
        .first()
        .is_none_or(|segment| segment.kind != BsSegmentKind::PrivateAppend)
    {
        asm.code.cbz(Gpr::x(0), route_failure)?;
    }
    asm.code
        .emit(|e| e.str_uoff(Gpr::x(0), SCHEDULER_REGS, SAVED_RESULT))?;

    let mut bit_offset = 0i64;
    let mut is_byte_aligned = true;
    for (segment, &segment_failures) in segments.iter().zip(&failures) {
        if matches!(
            segment.kind,
            BsSegmentKind::Append | BsSegmentKind::PrivateAppend
        ) {
            bit_offset = -1;
            is_byte_aligned = false;
            continue;
        }
        emit_segment_size(asm, segment, false, segment_failures)?;
        // Re-load the value after allocation, since allocation can collect the process heap.
        let source = source_reg_after_allocation(asm, segment.src)?;
        emit_segment_write(
            asm,
            segment,
            source,
            live as usize,
            bit_offset,
            is_byte_aligned,
            segment_failures,
        )?;

        let effective_size = static_segment_size_bits(segment);
        if bit_offset >= 0 {
            bit_offset = effective_size
                .and_then(|bits| bit_offset.checked_add(bits))
                .unwrap_or(-1);
        }
        if bit_offset % 8 == 0 {
            is_byte_aligned = true;
        } else if effective_size.is_some_and(|bits| bits % 8 != 0) || gcd(segment.unit, 8) != 8 {
            is_byte_aligned = false;
        }
    }
    asm.code.emit(|e| {
        e.ldr_uoff(Gpr::x(0), SCHEDULER_REGS, SAVED_RESULT)?;
        e.str_uoff(Gpr::xzr(), SCHEDULER_REGS, SAVED_RESULT)
    })?;
    asm.store_register(dst, Gpr::x(0))?;
    asm.code.b(success)?;

    if fail == 0 {
        for (segment, &segment_failures) in segments.iter().zip(&failures) {
            let type_value = if segment.size_is_all {
                FailValue::Arg1
            } else if matches!(
                segment.kind,
                BsSegmentKind::Utf8 | BsSegmentKind::Utf16 | BsSegmentKind::Utf32
            ) {
                FailValue::SourceArg3
            } else {
                FailValue::SizeArg3
            };
            asm.code.bind(segment_failures.size_badarg)?;
            emit_bs_fail_info(
                asm,
                live as usize,
                segment,
                FailReason::Depends,
                if segment.size_is_all {
                    FailInfo::Depends
                } else {
                    FailInfo::Size
                },
                FailValue::SizeArg3,
            )?;
            asm.code.b(route_failure)?;
            asm.code.bind(segment_failures.type_badarg)?;
            emit_bs_fail_info(
                asm,
                live as usize,
                segment,
                FailReason::BadArg,
                if segment.size_is_all {
                    FailInfo::Depends
                } else {
                    FailInfo::Type
                },
                type_value,
            )?;
            asm.code.b(route_failure)?;
            asm.code.bind(segment_failures.system_limit)?;
            emit_bs_fail_info(
                asm,
                live as usize,
                segment,
                FailReason::SystemLimit,
                FailInfo::Size,
                FailValue::SizeArg3,
            )?;
            asm.code.b(route_failure)?;
            asm.code.bind(segment_failures.write_badarg)?;
            let (reason, info, value) = match segment.kind {
                BsSegmentKind::Binary if segment.size_is_all => {
                    (FailReason::BadArg, FailInfo::Unit, FailValue::Fvalue)
                }
                BsSegmentKind::Binary => (FailReason::BadArg, FailInfo::Depends, FailValue::Fvalue),
                BsSegmentKind::Float => (
                    FailReason::BadArg,
                    FailInfo::Fvalue,
                    FailValue::RuntimeResult,
                ),
                BsSegmentKind::Utf16 | BsSegmentKind::Utf32 | BsSegmentKind::Integer => {
                    (FailReason::BadArg, FailInfo::Type, FailValue::Arg1)
                }
                _ => (FailReason::BadArg, FailInfo::Type, FailValue::SourceArg3),
            };
            emit_bs_fail_info(asm, live as usize, segment, reason, info, value)?;
            asm.code.b(route_failure)?;
        }
    }
    asm.code.bind(route_failure)?;
    if fail != 0 {
        let label = asm.label(fail);
        asm.code.b(label)?;
    } else {
        asm.branch_error()?;
    }
    asm.code.bind(success)?;
    Ok(())
}

fn emit_bs_fail_info(
    asm: &mut BeamModuleAssembler,
    live: usize,
    segment: &BsSegment,
    reason: FailReason,
    info: FailInfo,
    value: FailValue,
) -> Result<(), ModuleError> {
    let operation = match segment.kind {
        BsSegmentKind::Float => 1,
        BsSegmentKind::Integer => 2,
        BsSegmentKind::Utf8 => 3,
        BsSegmentKind::Utf16 => 4,
        BsSegmentKind::Utf32 => 5,
        _ => 0,
    };
    let reason = match reason {
        FailReason::BadArg => 0,
        FailReason::SystemLimit => 1,
        FailReason::Depends => 2,
    };
    let info = match info {
        FailInfo::Fvalue => 0,
        FailInfo::Type => 1,
        FailInfo::Size => 2,
        FailInfo::Unit => 3,
        FailInfo::Depends => 4,
    };
    let value_bits = match value {
        FailValue::Arg1 => 0,
        FailValue::SizeArg3 | FailValue::SourceArg3 => 1,
        FailValue::Fvalue => 2,
        FailValue::RuntimeResult => 0,
    };
    let packed = (u64::from(segment.index) << 10)
        | (operation << 7)
        | (value_bits << 2)
        | (info << 4)
        | reason;
    let error_value = match value {
        FailValue::Arg1 => asm.source_reg_into(segment.src, Gpr::x(9))?,
        FailValue::SizeArg3 => asm.source_reg_into(segment.size, Gpr::x(9))?,
        FailValue::SourceArg3 => asm.source_reg_into(segment.src, Gpr::x(9))?,
        FailValue::Fvalue => Gpr::xzr(),
        FailValue::RuntimeResult => Gpr::x(0),
    };
    let (arg3, arg1) = match value {
        FailValue::Arg1 => (Gpr::xzr(), error_value),
        FailValue::SizeArg3 | FailValue::SourceArg3 => (error_value, Gpr::xzr()),
        FailValue::Fvalue => (Gpr::xzr(), Gpr::xzr()),
        FailValue::RuntimeResult => (Gpr::xzr(), error_value),
    };
    asm.code.emit(|e| {
        e.mov_const(Gpr::x(8), packed)?;
        if arg3 != Gpr::x(10) {
            e.mov_reg(Gpr::x(10), arg3)?;
        }
        if arg1 != Gpr::x(11) {
            e.mov_reg(Gpr::x(11), arg1)?;
        }
        Ok(())
    })?;
    emit_runtime_call(
        asm,
        crate::raw::beam_jit_bs_construct_fail_info as *const () as usize,
        live,
        crate::Update::HEAP_ALLOC,
        &[C_P, Gpr::x(8), Gpr::x(10), Gpr::x(11)],
    )
}

/// Emits one direct `runtime_call<erts function>()` with its C ABI arguments.
// Port of erts/emulator/beam/jit/arm/beam_asm.hpp (`runtime_call`), OTP-29.1.1.
fn emit_runtime_call(
    asm: &mut BeamModuleAssembler,
    target: usize,
    live: usize,
    update: crate::Update,
    args: &[Gpr],
) -> Result<(), ModuleError> {
    if args.len() > 8 {
        return Err(ModuleError::InvalidOperand("too many runtime arguments"));
    }
    crate::emit_enter_runtime(&mut asm.code, live, update)?;
    asm.code.emit(|e| {
        for (index, arg) in args.iter().copied().enumerate() {
            let dst = Gpr::x(index as u8);
            if arg != dst {
                e.mov_reg(dst, arg)?;
            }
        }
        e.str_uoff(Gpr::x(30), C_P, 72)?;
        e.mov_const(Gpr::x(17), target as u64)?;
        e.blr(Gpr::x(17))
    })?;
    crate::emit_leave_runtime(&mut asm.code, live, update)?;
    asm.code.emit(|e| e.ldr_uoff(Gpr::x(30), C_P, 72))?;
    Ok(())
}

// Port of erts/emulator/beam/jit/arm/instr_bs.cpp:2460-2494 (segment cursor tracking), OTP-29.1.1.
fn gcd(mut lhs: u32, mut rhs: u32) -> u32 {
    while rhs != 0 {
        (lhs, rhs) = (rhs, lhs % rhs);
    }
    lhs
}

/// Carries compile-time-known segment sizes into the cursor alignment state.
// Port of erts/emulator/beam/jit/arm/instr_bs.cpp:2460-2494 (`emit_i_bs_create_bin`), OTP-29.1.1.
fn static_segment_size_bits(segment: &BsSegment) -> Option<i64> {
    let units = if segment.size_is_all {
        return None;
    } else {
        match segment.kind {
            BsSegmentKind::Utf8 | BsSegmentKind::Utf16 => return None,
            BsSegmentKind::Utf32 => return Some(32),
            _ => {}
        }
        if segment.size_is_units {
            i64::try_from(segment.size.word()?).ok()?
        } else {
            segment.size.small_signed()?
        }
    };
    units.checked_mul(i64::from(segment.unit))
}

/// Emits one already-sized construction segment through its erts runtime or inline writer.
// Port of erts/emulator/beam/jit/arm/instr_bs.cpp:1990-2448 (`emit_i_bs_create_bin`), OTP-29.1.1.
fn emit_segment_write(
    asm: &mut BeamModuleAssembler,
    segment: &BsSegment,
    source: Gpr,
    live: usize,
    bit_offset: i64,
    is_byte_aligned: bool,
    failures: SegmentFailureLabels,
) -> Result<(), ModuleError> {
    let ebs = crate::arm::beam_asm::ERL_BITS_STATE_REF;
    asm.code
        .emit(|e| e.add_imm(Gpr::x(8), SCHEDULER_REGS, ebs as u16, false))?;
    let bits = SEG_BITS;
    let flags = Gpr::x(13);
    match segment.kind {
        BsSegmentKind::Integer | BsSegmentKind::Utf32 => {
            let bits = if segment.kind == BsSegmentKind::Utf32 {
                asm.code.emit(|e| e.mov_const(Gpr::x(11), 32))?;
                Gpr::x(11)
            } else {
                bits
            };
            let target = if segment.flags & 2 != 0 {
                crate::raw::erts_bs_put_integer_le as *const () as usize
            } else {
                crate::raw::erts_bs_put_integer_be as *const () as usize
            };
            emit_runtime_call(
                asm,
                target,
                live,
                crate::Update::NONE,
                &[Gpr::x(8), source, bits],
            )?;
            asm.code.cbz(Gpr::x(0), failures.write_badarg)?;
        }
        BsSegmentKind::Binary => {
            if segment.size_is_all {
                asm.code
                    .emit(|e| e.mov_const(flags, u64::from(segment.unit)))?;
                emit_runtime_call(
                    asm,
                    crate::raw::erts_bs_put_binary_all as *const () as usize,
                    live,
                    crate::Update::REDUCTIONS,
                    &[Gpr::x(8), C_P, source, flags],
                )?;
            } else {
                emit_runtime_call(
                    asm,
                    crate::raw::erts_bs_put_binary as *const () as usize,
                    live,
                    crate::Update::REDUCTIONS,
                    &[Gpr::x(8), C_P, source, bits],
                )?;
            }
            asm.code.cbz(Gpr::x(0), failures.write_badarg)?;
        }
        BsSegmentKind::Float => {
            asm.code
                .emit(|e| e.mov_const(flags, u64::from(segment.flags)))?;
            emit_runtime_call(
                asm,
                crate::raw::erts_bs_put_float as *const () as usize,
                live,
                crate::Update::NONE,
                &[Gpr::x(8), C_P, source, bits, flags],
            )?;
            // erts returns THE_NON_VALUE on success and the invalid value/size on failure.
            asm.code.cbnz(Gpr::x(0), failures.write_badarg)?;
        }
        BsSegmentKind::Utf16 => {
            asm.code
                .emit(|e| e.mov_const(flags, u64::from(segment.flags)))?;
            emit_runtime_call(
                asm,
                crate::raw::erts_bs_put_utf16 as *const () as usize,
                live,
                crate::Update::NONE,
                &[Gpr::x(8), source, flags],
            )?;
            asm.code.cbz(Gpr::x(0), failures.write_badarg)?;
        }
        BsSegmentKind::String => {
            let bytes = if segment.size_is_units {
                source_reg_after_allocation_into(asm, segment.size, Gpr::x(14))?
            } else {
                return Err(ModuleError::InvalidOperand("string size must be literal"));
            };
            let byte_count = if segment.size_is_all {
                return Err(ModuleError::InvalidOperand("string size cannot be all"));
            } else if segment.unit == 8 {
                bytes
            } else {
                return Err(ModuleError::InvalidOperand("string unit must be 8"));
            };
            emit_runtime_call(
                asm,
                crate::raw::erts_bs_put_string as *const () as usize,
                live,
                crate::Update::NONE,
                &[Gpr::x(8), source, byte_count],
            )?;
        }
        BsSegmentKind::Append | BsSegmentKind::PrivateAppend => {
            return Err(ModuleError::InvalidOperand(
                "append segment is written during allocation",
            ));
        }
        BsSegmentKind::Utf8 => {
            emit_construct_utf8(asm, source, bit_offset, is_byte_aligned)?;
        }
    }
    Ok(())
}

/// Encodes and stores one UTF-8 scalar in the current writable binary.
// Port of erts/emulator/beam/jit/arm/instr_bs.cpp:1220-1349
// (`emit_construct_utf8_shared`, `emit_construct_utf8`), OTP-29.1.1.
fn emit_construct_utf8(
    asm: &mut BeamModuleAssembler,
    source: Gpr,
    bit_offset: i64,
    is_byte_aligned: bool,
) -> Result<(), ModuleError> {
    let ebs = crate::arm::beam_asm::ERL_BITS_STATE_REF;
    let value = Gpr::x(1);
    let offset = Gpr::x(3);
    let num_bits = Gpr::x(4);
    let tmp1 = Gpr::x(8);
    let tmp2 = Gpr::x(9);
    let tmp4 = Gpr::x(11);
    let tmp5 = Gpr::x(12);
    let state = Gpr::x(10);
    let more_than_two = asm.code.new_label();
    let four_bytes = asm.code.new_label();
    let prepare_store = asm.code.new_label();
    let store = asm.code.new_label();
    let next = asm.code.new_label();

    asm.code.emit(|e| {
        e.asr_imm(value, source, 4)?;
        e.mov_const(num_bits, 8)?;
        e.cmp_imm(value, 0x80, false)
    })?;
    asm.code.b_cond(Cond::Cc, prepare_store)?;
    asm.code.emit(|e| e.cmp_imm(value, 0x800, false))?;
    asm.code.b_cond(Cond::Cs, more_than_two)?;

    // Port of `emit_construct_utf8_shared`: two-byte encoding.
    asm.code.emit(|e| {
        e.ubfiz(tmp1, value, 8, 6)?;
        e.mov_const(tmp2, 0x80c0)?;
        e.orr_reg(
            tmp1,
            tmp1,
            arinsal_a64::enc::Shifted {
                reg: value,
                shift: Shift::Lsr,
                amount: 6,
            },
        )?;
        e.mov_const(num_bits, 16)?;
        e.orr_reg(
            value,
            tmp1,
            arinsal_a64::enc::Shifted {
                reg: tmp2,
                shift: Shift::Lsl,
                amount: 0,
            },
        )
    })?;
    asm.code.b(prepare_store)?;

    asm.code.bind(more_than_two)?;
    asm.code.emit(|e| e.lsr_imm(tmp1, value, 16))?;
    asm.code.cbnz(tmp1, four_bytes)?;
    // Port of `emit_construct_utf8_shared`: three-byte encoding.
    asm.code.emit(|e| {
        e.lsl_imm(tmp1, value, 2)?;
        e.ubfiz(tmp2, value, 16, 6)?;
        e.and_imm(tmp1, tmp1, 0x3f00)?;
        e.orr_reg(
            tmp1,
            tmp1,
            arinsal_a64::enc::Shifted {
                reg: value,
                shift: Shift::Lsr,
                amount: 12,
            },
        )?;
        e.orr_reg(
            tmp1,
            tmp1,
            arinsal_a64::enc::Shifted {
                reg: tmp2,
                shift: Shift::Lsl,
                amount: 0,
            },
        )?;
        e.mov_const(tmp2, 0x8080e0)?;
        e.orr_reg(
            value,
            tmp1,
            arinsal_a64::enc::Shifted {
                reg: tmp2,
                shift: Shift::Lsl,
                amount: 0,
            },
        )?;
        e.mov_const(num_bits, 24)
    })?;
    asm.code.b(prepare_store)?;

    asm.code.bind(four_bytes)?;
    // Port of `emit_construct_utf8_shared`: four-byte encoding.
    asm.code.emit(|e| {
        e.lsl_imm(tmp1, value, 10)?;
        e.lsr_imm(tmp2, value, 4)?;
        e.and_imm(tmp1, tmp1, 0x3f0000)?;
        e.and_imm(tmp2, tmp2, 0x3f00)?;
        e.bfxil(tmp1, value, 18, 14)?;
        e.mov_const(num_bits, 32)?;
        e.bfi(tmp1, value, 24, 6)?;
        e.orr_reg(
            tmp1,
            tmp1,
            arinsal_a64::enc::Shifted {
                reg: tmp2,
                shift: Shift::Lsl,
                amount: 0,
            },
        )?;
        e.mov_const(tmp2, 0x8080_80f0)?;
        e.orr_reg(
            value,
            tmp1,
            arinsal_a64::enc::Shifted {
                reg: tmp2,
                shift: Shift::Lsl,
                amount: 0,
            },
        )
    })?;

    asm.code.bind(prepare_store)?;
    asm.code
        .emit(|e| e.add_imm(state, SCHEDULER_REGS, ebs as u16, false))?;
    if bit_offset % 8 != 0 {
        asm.code.emit(|e| {
            e.ldp(tmp2, offset, state, 0)?;
            e.add_reg(tmp1, offset, num_bits, Shift::Lsl, 0)?;
            e.str_uoff(tmp1, state, 8)?;
            e.add_reg(tmp1, tmp2, offset, Shift::Lsr, 3)
        })?;
    } else {
        asm.code.emit(|e| {
            e.ldr_uoff(tmp1, state, 0)?;
            if bit_offset == 0 {
                e.str_uoff(num_bits, state, 8)?;
            } else {
                e.mov_const(tmp2, bit_offset as u64)?;
                e.add_reg(tmp2, num_bits, tmp2, Shift::Lsl, 0)?;
                e.str_uoff(tmp2, state, 8)?;
            }
            if bit_offset != 0 {
                e.mov_const(tmp2, (bit_offset / 8) as u64)?;
                e.add_reg(tmp1, tmp1, tmp2, Shift::Lsl, 0)?;
            }
            Ok(())
        })?;
    }

    if !is_byte_aligned {
        asm.code.emit(|e| e.ands_imm(tmp2, offset, 7))?;
        asm.code.b_cond(Cond::Eq, store)?;
        asm.code.emit(|e| e.ldrb_uoff(tmp5, tmp1, 0))?;
        asm.code.emit(|e| {
            e.rev64(tmp4, value)?;
            e.lsr_reg(tmp4, tmp4, tmp2)?;
            e.rev64(tmp4, tmp4)?;
            e.lsl_reg(tmp5, tmp5, tmp2)?;
            e.and_imm(tmp5, tmp5, !0xff)?;
            e.lsr_reg(tmp5, tmp5, tmp2)?;
            e.orr_reg(
                value,
                tmp4,
                arinsal_a64::enc::Shifted {
                    reg: tmp5,
                    shift: Shift::Lsl,
                    amount: 0,
                },
            )?;
            e.add_imm(num_bits, num_bits, 8, false)
        })?;
    }

    asm.code.bind(store)?;
    if bit_offset % (4 * 8) == 0 {
        asm.code.emit(|e| e.str_uoff(Gpr::w(1), tmp1, 0))?;
    } else {
        let do_store_1 = asm.code.new_label();
        let do_store_2 = asm.code.new_label();
        asm.code.emit(|e| e.cmp_imm(num_bits, 8, false))?;
        asm.code.b_cond(Cond::Ne, do_store_1)?;
        asm.code.emit(|e| e.strb_uoff(Gpr::w(1), tmp1, 0))?;
        asm.code.b(next)?;
        asm.code.bind(do_store_1)?;
        asm.code.emit(|e| e.cmp_imm(num_bits, 24, false))?;
        asm.code.b_cond(Cond::Hi, do_store_2)?;
        asm.code.emit(|e| e.strh_uoff(Gpr::w(1), tmp1, 0))?;
        asm.code.emit(|e| e.cmp_imm(num_bits, 16, false))?;
        asm.code.b_cond(Cond::Eq, next)?;
        asm.code.emit(|e| {
            e.lsr_imm(value, value, 16)?;
            e.strb_uoff(Gpr::w(1), tmp1, 2)
        })?;
        asm.code.b(next)?;
        asm.code.bind(do_store_2)?;
        asm.code.emit(|e| e.str_uoff(Gpr::w(1), tmp1, 0))?;
        if !is_byte_aligned {
            asm.code.emit(|e| e.cmp_imm(num_bits, 32, false))?;
            asm.code.b_cond(Cond::Eq, next)?;
            asm.code.emit(|e| {
                e.lsr_imm(value, value, 32)?;
                e.strb_uoff(Gpr::w(1), tmp1, 4)
            })?;
        }
    }
    asm.code.bind(next)?;
    Ok(())
}

fn emit_segment_size(
    asm: &mut BeamModuleAssembler,
    segment: &BsSegment,
    accumulate: bool,
    failures: SegmentFailureLabels,
) -> Result<(), ModuleError> {
    if matches!(
        segment.kind,
        BsSegmentKind::Utf8 | BsSegmentKind::Utf16 | BsSegmentKind::Utf32
    ) {
        let source = if accumulate {
            asm.source_reg(segment.src)?
        } else {
            source_reg_after_allocation(asm, segment.src)?
        };
        let invalid = failures.type_badarg;
        match segment.kind {
            BsSegmentKind::Utf8 => {
                let sized = asm.code.new_label();
                asm.code.emit(|e| {
                    e.and_imm(SCRATCH, source, 0xf)?;
                    e.cmp_imm(SCRATCH, 0xf, false)
                })?;
                branch_if_condition(asm, Cond::Ne, invalid)?;
                asm.code.emit(|e| {
                    e.asr_imm(Gpr::x(8), source, 4)?;
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
                branch_if_condition(asm, Cond::Eq, invalid)?;
                asm.code.emit(|e| {
                    e.mov_const(Gpr::x(13), 0x10000)?;
                    e.cmp_reg(Gpr::x(8), Gpr::x(13), Shift::Lsl, 0)
                })?;
                asm.code.emit(|e| e.cset(Gpr::x(9), Cond::Cs))?;
                asm.code
                    .emit(|e| e.add_imm(Gpr::x(9), Gpr::x(9), 3, false))?;
                asm.code.emit(|e| {
                    e.mov_const(Gpr::x(13), 0x110000)?;
                    e.cmp_reg(Gpr::x(8), Gpr::x(13), Shift::Lsl, 0)
                })?;
                branch_if_condition(asm, Cond::Cs, invalid)?;
                asm.code.bind(sized)?;
                asm.code.emit(|e| e.lsl_imm(SEG_BITS, Gpr::x(9), 3))?;
            }
            BsSegmentKind::Utf16 => {
                asm.code.emit(|e| {
                    e.asr_imm(Gpr::x(8), source, 4)?;
                    e.mov_const(Gpr::x(13), 0x10000)?;
                    e.cmp_reg(Gpr::x(8), Gpr::x(13), Shift::Lsl, 0)?;
                    e.mov_const(Gpr::x(9), 16)?;
                    e.mov_const(Gpr::x(10), 32)?;
                    e.csel(Gpr::x(9), Gpr::x(9), Gpr::x(10), Cond::Cc)?;
                    e.mov_reg(SEG_BITS, Gpr::x(9))
                })?;
            }
            BsSegmentKind::Utf32 => {
                let next = asm.code.new_label();
                let word = |value: u64| (value << 4) | 0xf;
                asm.code.emit(|e| {
                    e.mov_const(SEG_BITS, 32)?;
                    e.and_imm(SCRATCH, source, 0xf)?;
                    e.cmp_imm(SCRATCH, 0xf, false)
                })?;
                branch_if_condition(asm, Cond::Ne, invalid)?;
                asm.code.emit(|e| e.mov_const(SCRATCH, word(0xd800)))?;
                asm.code
                    .emit(|e| e.cmp_reg(source, SCRATCH, Shift::Lsl, 0))?;
                asm.code.b_cond(Cond::Cc, next)?;
                asm.code.emit(|e| e.mov_const(SCRATCH, word(0xdfff)))?;
                asm.code
                    .emit(|e| e.cmp_reg(source, SCRATCH, Shift::Lsl, 0))?;
                branch_if_condition(asm, Cond::Ls, invalid)?;
                asm.code.emit(|e| e.mov_const(SCRATCH, word(0x10ffff)))?;
                asm.code
                    .emit(|e| e.cmp_reg(source, SCRATCH, Shift::Lsl, 0))?;
                branch_if_condition(asm, Cond::Hi, invalid)?;
                asm.code.bind(next)?;
            }
            _ => unreachable!(),
        }
        if accumulate {
            asm.code
                .emit(|e| e.adds_reg(BITS, BITS, SEG_BITS, Shift::Lsl, 0))?;
            branch_if_condition(asm, Cond::Cs, failures.system_limit)?;
        }
        return Ok(());
    }

    if segment.size_is_all {
        let source = if accumulate {
            asm.source_reg(segment.src)?
        } else {
            source_reg_after_allocation(asm, segment.src)?
        };
        // Port of erts/emulator/beam/jit/arm/instr_bs.cpp:1594-1639
        // (`emit_i_bs_create_bin`), OTP-29.1.1.  erts reads the common bitstring header inline;
        // keeping this inline also leaves every live X register untouched during size summation.
        let not_sub_bits = asm.code.new_label();
        branch_if_bit_set(asm, source, 0, failures.type_badarg)?;
        asm.code.emit(|e| {
            e.and_imm(Gpr::x(8), source, !7)?;
            e.ldp(SCRATCH, SEG_BITS, Gpr::x(8), 0)
        })?;
        asm.code.emit(|e| {
            e.and_imm(Gpr::x(13), SCRATCH, BITSTRING_HEADER_MASK)?;
            e.cmp_imm(Gpr::x(13), TAG_HEADER_HEAP_BITS, false)
        })?;
        branch_if_condition(asm, Cond::Ne, failures.type_badarg)?;
        asm.code
            .emit(|e| e.cmp_imm(SCRATCH, HEADER_SUB_BITS, false))?;
        asm.code.b_cond(Cond::Ne, not_sub_bits)?;
        asm.code.emit(|e| {
            e.ldp(Gpr::x(12), Gpr::x(13), Gpr::x(8), 16)?;
            e.sub_reg(SEG_BITS, Gpr::x(13), Gpr::x(12), Shift::Lsl, 0)
        })?;
        asm.code.bind(not_sub_bits)?;
        if accumulate {
            asm.code
                .emit(|e| e.adds_reg(BITS, BITS, SEG_BITS, Shift::Lsl, 0))?;
            branch_if_condition(asm, Cond::Cs, failures.system_limit)?;
        }
        return Ok(());
    }

    if segment.size_is_units {
        let units = if accumulate {
            asm.source_reg(segment.size)?
        } else {
            source_reg_after_allocation(asm, segment.size)?
        };
        if units != SEG_BITS {
            asm.code.emit(|e| e.mov_reg(SEG_BITS, units))?;
        }
    } else {
        let size = if accumulate {
            asm.source_reg(segment.size)?
        } else {
            source_reg_after_allocation(asm, segment.size)?
        };
        asm.code.emit(|e| {
            e.and_imm(SCRATCH, size, 0xf)?;
            e.cmp_imm(SCRATCH, 0xf, false)
        })?;
        branch_if_condition(asm, Cond::Ne, failures.size_badarg)?;
        branch_if_bit_set(asm, size, 63, failures.size_badarg)?;
        asm.code.emit(|e| e.asr_imm(SEG_BITS, size, 4))?;
    }
    if segment.unit != 1 {
        asm.code.emit(|e| {
            e.mov_const(SCRATCH, u64::from(segment.unit))?;
            e.umulh(Gpr::x(13), SEG_BITS, SCRATCH)?;
            e.cmp_imm(Gpr::x(13), 0, false)
        })?;
        branch_if_condition(asm, Cond::Ne, failures.system_limit)?;
        asm.code.emit(|e| e.mul(SEG_BITS, SEG_BITS, SCRATCH))?;
    }
    if accumulate {
        asm.code
            .emit(|e| e.adds_reg(BITS, BITS, SEG_BITS, Shift::Lsl, 0))?;
        branch_if_condition(asm, Cond::Cs, failures.system_limit)?;
        branch_if_bit_set(asm, BITS, 63, failures.system_limit)?;
    }
    Ok(())
}

impl BeamModuleAssembler {
    /// Calls the erts runtime function that initializes the current writable binary.
    // Port of erts/emulator/beam/jit/arm/instr_bs.cpp:985-1000, OTP-29.1.1.
    pub fn emit_bs_init_writable(&mut self, src: ArgVal) -> Result<(), ModuleError> {
        let src = self.source_reg(src)?;
        emit_runtime_call(
            self,
            crate::raw::erts_bs_init_writable as *const () as usize,
            0,
            crate::Update::HEAP_ALLOC.union(crate::Update::REDUCTIONS),
            &[C_P, src],
        )?;
        self.code.emit(|e| e.mov_reg(Gpr::x(25), Gpr::x(0)))?;
        Ok(())
    }

    /// Builds a binary with the same size, allocation, and segment-write sequence as BeamAsm.
    // Port of erts/emulator/beam/jit/arm/instr_bs.cpp:1442-2494 (emit_i_bs_create_bin), OTP-29.1.1.
    #[allow(clippy::too_many_arguments)]
    pub fn emit_i_bs_create_bin(
        &mut self,
        fail: u32,
        alloc: u32,
        live: u32,
        dst: ArgVal,
        segments: &[BsSegment],
    ) -> Result<(), ModuleError> {
        if crate::bs_fast::emit_fast_bs_create_bin(self, fail, alloc, live, dst, segments)? {
            return Ok(());
        }
        self.emit_generic_bs_create_bin(fail, alloc, live, dst, segments)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn emit_generic_bs_create_bin(
        &mut self,
        fail: u32,
        alloc: u32,
        live: u32,
        dst: ArgVal,
        segments: &[BsSegment],
    ) -> Result<(), ModuleError> {
        emit_bs_create_bin_generic(self, fail, alloc, live, dst, segments)
    }
}
