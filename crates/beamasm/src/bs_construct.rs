//! AArch64 emitters for BEAM bit syntax construction.

pub use crate::bs_fast::{
    install_bs_append_binary, install_bs_append_checked, install_bs_gc, install_bs_private_append,
};

use crate::module::{ArgVal, BeamModuleAssembler, ModuleError};
use arinsal_a64::enc::{Cond, Gpr, Shift};

/// Runtime hook used to initialize a writable bitstring.
pub type BsInitWritableHelper = extern "C" fn(*mut crate::ProcessHeader, u64) -> u64;

/// Allocates the final bitstring and initializes `erl_bits_state` after the emitted GC check.
pub type BsInitBitsHelper =
    extern "C" fn(*mut crate::ProcessHeader, *mut crate::SchedulerRegisters, u64, u64, u64) -> u64;

/// A per-segment `erts_bs_put_*` equivalent writing at the current bit cursor.
pub type BsPutSegmentHelper = extern "C" fn(
    *mut crate::ProcessHeader,
    *mut crate::SchedulerRegisters,
    u64,
    u64,
    u64,
    u64,
    u64,
) -> u64;

/// `beam_jit_bs_bit_size` for a register or literal bitstring.
pub type BsBitSizeHelper =
    extern "C" fn(*mut crate::ProcessHeader, *mut crate::SchedulerRegisters, u64, u64) -> u64;

/// Size helper for UTF codepoint segments.
pub type BsUtfSizeHelper =
    extern "C" fn(*mut crate::ProcessHeader, *mut crate::SchedulerRegisters, u64, u64) -> u64;

/// Builds the extended failure information for a failed construction segment.
pub type BsFailHelper =
    extern "C" fn(*mut crate::ProcessHeader, *mut crate::SchedulerRegisters, u64, u64, u64) -> u64;

/// Checked append allocation helper from `erts_bs_append_checked`.
pub type BsAppendCheckedHelper = extern "C" fn(
    *mut crate::ProcessHeader,
    *mut crate::SchedulerRegisters,
    u64,
    u64,
    u64,
    u64,
    u64,
) -> u64;

/// Checked private append helper from `erts_bs_private_append_checked`.
pub type BsPrivateAppendHelper =
    extern "C" fn(*mut crate::ProcessHeader, *mut crate::SchedulerRegisters, u64, u64) -> u64;

/// Runtime primitives used by the generic `bs_create_bin` emitter.
#[derive(Clone, Copy)]
pub struct BsCreateBinHelpers {
    /// `erts_bs_append_checked` allocation path.
    pub append_checked: BsAppendCheckedHelper,
    /// `erts_bs_private_append_checked` allocation path.
    pub private_append: BsPrivateAppendHelper,
    /// `erts_bs_init_bits` allocation path.
    pub init_bits: BsInitBitsHelper,
    /// `beam_jit_bs_bit_size`.
    pub bit_size: BsBitSizeHelper,
    /// `erts_bs_get_utf8_size`.
    pub utf8_size: BsUtfSizeHelper,
    /// `erts_bs_get_utf16_size` equivalent.
    pub utf16_size: BsUtfSizeHelper,
    /// `erts_bs_get_utf32_size` equivalent.
    pub utf32_size: BsUtfSizeHelper,
    /// `beam_jit_bs_construct_fail_info` failure-state builder.
    pub fail: BsFailHelper,
    /// `erts_bs_put_integer_{be,le}`.
    pub put_integer: BsPutSegmentHelper,
    /// `erts_bs_put_binary`.
    pub put_binary: BsPutSegmentHelper,
    /// `beam_jit_bs_put_binary_all` / `erts_bs_put_binary_all`.
    pub put_binary_all: BsPutSegmentHelper,
    /// `erts_bs_put_float`.
    pub put_float: BsPutSegmentHelper,
    /// `erts_bs_put_utf8`.
    pub put_utf8: BsPutSegmentHelper,
    /// `erts_bs_put_utf16`.
    pub put_utf16: BsPutSegmentHelper,
    /// `erts_bs_put_integer_{be,le}` for UTF-32.
    pub put_utf32: BsPutSegmentHelper,
    /// `erts_new_bs_put_string`.
    pub put_string: BsPutSegmentHelper,
}

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
const BITS: Gpr = Gpr::x(10);
const SEG_BITS: Gpr = Gpr::x(11);
const SCRATCH: Gpr = Gpr::x(12);
const RELOADED_ARG: Gpr = Gpr::x(9);
const TMP_MEMORY: u32 = std::mem::offset_of!(crate::SchedulerRegisters, tmp_mem) as u32;
const SAVED_BITS: u32 = TMP_MEMORY;
const SAVED_RESULT: u32 = TMP_MEMORY + 8;

#[derive(Clone, Copy)]
struct SegmentFailureLabels {
    size_badarg: arinsal_a64::buf::Label,
    type_badarg: arinsal_a64::buf::Label,
    system_limit: arinsal_a64::buf::Label,
}

#[derive(Clone, Copy)]
enum FailReason {
    BadArg,
    Depends,
    SystemLimit,
}

#[derive(Clone, Copy)]
enum FailInfo {
    Type,
    Size,
}

#[derive(Clone, Copy)]
enum FailValue {
    Arg1,
    SizeArg3,
    SourceArg3,
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
    match source {
        ArgVal::X(index) => asm.source_reg(ArgVal::X(index)),
        ArgVal::XMemory(index) if index < 1024 => {
            let offset = index
                .checked_mul(8)
                .ok_or(ModuleError::InvalidOperand("X register offset overflow"))?;
            asm.code
                .emit(|e| e.ldr_uoff(RELOADED_ARG, SCHEDULER_REGS, offset))?;
            Ok(RELOADED_ARG)
        }
        ArgVal::Y(index) => {
            let offset = index
                .checked_mul(8)
                .ok_or(ModuleError::InvalidOperand("Y register offset overflow"))?;
            asm.code
                .emit(|e| e.ldr_uoff(RELOADED_ARG, Gpr::x(20), offset))?;
            Ok(RELOADED_ARG)
        }
        _ => asm.source_reg(source),
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
    helpers: BsCreateBinHelpers,
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
                }
            } else {
                SegmentFailureLabels {
                    size_badarg: route_failure,
                    type_badarg: route_failure,
                    system_limit: route_failure,
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
        emit_segment_size(asm, segment, helpers, live as usize, true, segment_failures)?;
    }

    asm.code
        .emit(|e| e.str_uoff(BITS, SCHEDULER_REGS, SAVED_BITS))?;
    asm.code.emit(|e| {
        e.mov_const(Gpr::x(3), u64::from(alloc))?;
        e.mov_const(Gpr::x(4), u64::from(live))
    })?;
    if let Some(segment) = segments.first().filter(|s| s.kind == BsSegmentKind::Append) {
        let source = asm.source_reg(segment.src)?;
        let append_source = if live < 6 {
            ArgVal::X(live as u8)
        } else {
            ArgVal::XMemory(live)
        };
        asm.store_register(append_source, source)?;
        asm.code.emit(|e| {
            e.mov_const(Gpr::x(2), u64::from(live))?;
            e.mov_reg(Gpr::x(3), BITS)?;
            e.mov_const(Gpr::x(4), u64::from(segment.unit))?;
            e.mov_const(Gpr::x(5), u64::from(live + 1))?;
            e.mov_const(Gpr::x(6), u64::from(alloc))
        })?;
        emit_bs_helper_call(
            asm,
            helpers.append_checked as usize,
            (live + 1) as usize,
            crate::Update::HEAP_ALLOC
                .union(crate::Update::X_REGS)
                .union(crate::Update::REDUCTIONS),
            &[Gpr::x(2), Gpr::x(3), Gpr::x(4), Gpr::x(5), Gpr::x(6)],
        )?;
        let append_ok = asm.code.new_label();
        let append_failed = asm.code.new_label();
        asm.code.cbz(Gpr::x(0), append_failed)?;
        asm.code.b(append_ok)?;
        asm.code.bind(append_failed)?;
        if fail == 0 {
            let error_info = (u64::from(segment.index) << 10) | (1 << 2);
            let source = source_reg_after_allocation(asm, append_source)?;
            asm.code.emit(|e| e.mov_const(Gpr::x(2), error_info))?;
            emit_bs_helper_call(
                asm,
                helpers.fail as usize,
                (live + 1) as usize,
                crate::Update::HEAP_ALLOC,
                &[Gpr::x(2), source, Gpr::xzr()],
            )?;
        }
        asm.code.b(route_failure)?;
        asm.code.bind(append_ok)?;
        let bits_state = std::mem::offset_of!(crate::SchedulerRegisters, erl_bits_state) as u32;
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
        let source = asm.source_reg(segment.src)?;
        emit_bs_helper_call(
            asm,
            helpers.private_append as usize,
            live as usize,
            crate::Update::HEAP_ALLOC
                .union(crate::Update::X_REGS)
                .union(crate::Update::REDUCTIONS),
            &[source, BITS],
        )?;
        asm.code.cbz(Gpr::x(0), route_failure)?;
        asm.code
            .emit(|e| e.str_uoff(Gpr::x(0), SCHEDULER_REGS, SAVED_RESULT))?;
        let bits_state = std::mem::offset_of!(crate::SchedulerRegisters, erl_bits_state) as u32;
        asm.code.emit(|e| {
            e.ldr_uoff(Gpr::x(8), SCHEDULER_REGS, bits_state + 8)?;
            e.ldr_uoff(BITS, SCHEDULER_REGS, SAVED_BITS)?;
            e.add_reg(BITS, BITS, Gpr::x(8), Shift::Lsl, 0)?;
            e.str_uoff(BITS, SCHEDULER_REGS, SAVED_BITS)
        })?;
    } else {
        emit_bs_helper_call(
            asm,
            helpers.init_bits as usize,
            live as usize,
            crate::Update::HEAP_ALLOC
                .union(crate::Update::X_REGS)
                .union(crate::Update::REDUCTIONS),
            &[BITS, Gpr::x(3), Gpr::x(4)],
        )?;
    }
    asm.code.cbz(Gpr::x(0), route_failure)?;
    asm.code
        .emit(|e| e.str_uoff(Gpr::x(0), SCHEDULER_REGS, SAVED_RESULT))?;

    for (segment, &segment_failures) in segments.iter().zip(&failures) {
        if matches!(
            segment.kind,
            BsSegmentKind::Append | BsSegmentKind::PrivateAppend
        ) {
            continue;
        }
        emit_segment_size(
            asm,
            segment,
            helpers,
            live as usize,
            false,
            segment_failures,
        )?;
        // Re-load the value after allocation, since allocation can collect the process heap.
        let source = source_reg_after_allocation(asm, segment.src)?;
        let metadata = u64::from(segment.flags)
            | (u64::from(segment.unit) << 32)
            | (u64::from(segment.size_is_all) << 63);
        let helper = segment_helper(helpers, segment);
        asm.code.emit(|e| {
            e.mov_reg(Gpr::x(2), source)?;
            e.mov_reg(Gpr::x(3), SEG_BITS)?;
            e.mov_const(Gpr::x(4), metadata)?;
            e.mov_const(Gpr::x(5), u64::from(segment.index))?;
            e.ldr_uoff(Gpr::x(6), SCHEDULER_REGS, SAVED_BITS)
        })?;
        emit_bs_helper_call(
            asm,
            helper as usize,
            live as usize,
            crate::Update::HEAP_ALLOC.union(crate::Update::REDUCTIONS),
            &[Gpr::x(2), Gpr::x(3), Gpr::x(4), Gpr::x(5), Gpr::x(6)],
        )?;
        asm.code.cbz(Gpr::x(0), route_failure)?;
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
                helpers.fail,
                live as usize,
                segment,
                FailReason::Depends,
                FailInfo::Size,
                FailValue::SizeArg3,
            )?;
            asm.code.b(route_failure)?;
            asm.code.bind(segment_failures.type_badarg)?;
            emit_bs_fail_info(
                asm,
                helpers.fail,
                live as usize,
                segment,
                FailReason::BadArg,
                FailInfo::Type,
                type_value,
            )?;
            asm.code.b(route_failure)?;
            asm.code.bind(segment_failures.system_limit)?;
            emit_bs_fail_info(
                asm,
                helpers.fail,
                live as usize,
                segment,
                FailReason::SystemLimit,
                FailInfo::Size,
                FailValue::SizeArg3,
            )?;
            asm.code.b(route_failure)?;
        }
    }
    asm.code.bind(route_failure)?;
    if fail != 0 {
        let label = asm.label(fail);
        asm.code.emit(|e| e.str_uoff(Gpr::xzr(), C_P, 40))?;
        asm.code.b(label)?;
    } else {
        asm.branch_error()?;
    }
    asm.code.bind(success)?;
    Ok(())
}

fn emit_bs_fail_info(
    asm: &mut BeamModuleAssembler,
    helper: BsFailHelper,
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
        FailInfo::Type => 1,
        FailInfo::Size => 2,
    };
    let value_bits = match value {
        FailValue::Arg1 => 0,
        FailValue::SizeArg3 | FailValue::SourceArg3 => 1,
    };
    let packed = (u64::from(segment.index) << 10)
        | (operation << 7)
        | (value_bits << 2)
        | (info << 4)
        | reason;
    let error_value = match value {
        FailValue::Arg1 => asm.source_reg(segment.src)?,
        FailValue::SizeArg3 => asm.source_reg(segment.size)?,
        FailValue::SourceArg3 => asm.source_reg(segment.src)?,
    };
    let (arg3, arg1) = match value {
        FailValue::Arg1 => (Gpr::xzr(), error_value),
        FailValue::SizeArg3 | FailValue::SourceArg3 => (error_value, Gpr::xzr()),
    };
    asm.code.emit(|e| e.mov_const(Gpr::x(2), packed))?;
    emit_bs_helper_call(
        asm,
        helper as usize,
        live,
        crate::Update::HEAP_ALLOC,
        &[Gpr::x(2), arg3, arg1],
    )
}

fn segment_helper(helpers: BsCreateBinHelpers, segment: &BsSegment) -> BsPutSegmentHelper {
    match segment.kind {
        BsSegmentKind::Integer => helpers.put_integer,
        BsSegmentKind::Float => helpers.put_float,
        BsSegmentKind::Binary => {
            if segment.size_is_all {
                helpers.put_binary_all
            } else {
                helpers.put_binary
            }
        }
        BsSegmentKind::String => helpers.put_string,
        BsSegmentKind::Utf8 => helpers.put_utf8,
        BsSegmentKind::Utf16 => helpers.put_utf16,
        BsSegmentKind::Utf32 => helpers.put_utf32,
        BsSegmentKind::Append | BsSegmentKind::PrivateAppend => helpers.put_binary_all,
    }
}

fn emit_segment_size(
    asm: &mut BeamModuleAssembler,
    segment: &BsSegment,
    helpers: BsCreateBinHelpers,
    live: usize,
    accumulate: bool,
    failures: SegmentFailureLabels,
) -> Result<(), ModuleError> {
    if segment.kind == BsSegmentKind::Utf8
        || segment.kind == BsSegmentKind::Utf16
        || segment.kind == BsSegmentKind::Utf32
    {
        let helper = match segment.kind {
            BsSegmentKind::Utf8 => helpers.utf8_size,
            BsSegmentKind::Utf16 => helpers.utf16_size,
            _ => helpers.utf32_size,
        };
        let source = if accumulate {
            asm.source_reg(segment.src)?
        } else {
            source_reg_after_allocation(asm, segment.src)?
        };
        if accumulate {
            asm.code
                .emit(|e| e.str_uoff(BITS, SCHEDULER_REGS, SAVED_BITS))?;
        }
        asm.code
            .emit(|e| e.mov_const(Gpr::x(3), u64::from(segment.index)))?;
        emit_bs_helper_call(
            asm,
            helper as usize,
            live,
            crate::Update::NONE,
            &[source, Gpr::x(3)],
        )?;
        asm.code.emit(|e| {
            e.mov_const(SCRATCH, u64::MAX)?;
            e.cmp_reg(Gpr::x(0), SCRATCH, Shift::Lsl, 0)
        })?;
        branch_if_condition(asm, Cond::Eq, failures.type_badarg)?;
        asm.code.emit(|e| e.mov_reg(SEG_BITS, Gpr::x(0)))?;
        if accumulate {
            asm.code
                .emit(|e| e.ldr_uoff(BITS, SCHEDULER_REGS, SAVED_BITS))?;
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
        if accumulate {
            asm.code
                .emit(|e| e.str_uoff(BITS, SCHEDULER_REGS, SAVED_BITS))?;
        }
        asm.code
            .emit(|e| e.mov_const(Gpr::x(3), u64::from(segment.index)))?;
        emit_bs_helper_call(
            asm,
            helpers.bit_size as usize,
            live,
            crate::Update::NONE,
            &[source, Gpr::x(3)],
        )?;
        asm.code.emit(|e| {
            e.mov_const(SCRATCH, u64::MAX)?;
            e.cmp_reg(Gpr::x(0), SCRATCH, Shift::Lsl, 0)
        })?;
        branch_if_condition(asm, Cond::Eq, failures.type_badarg)?;
        asm.code.emit(|e| e.mov_reg(SEG_BITS, Gpr::x(0)))?;
        if accumulate {
            asm.code
                .emit(|e| e.ldr_uoff(BITS, SCHEDULER_REGS, SAVED_BITS))?;
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

fn emit_bs_helper_call(
    asm: &mut BeamModuleAssembler,
    helper: usize,
    live: usize,
    update: crate::Update,
    args: &[Gpr],
) -> Result<(), ModuleError> {
    if args.len() > 6 {
        return Err(ModuleError::InvalidOperand(
            "too many bs_create_bin helper arguments",
        ));
    }
    crate::emit_enter_runtime(&mut asm.code, live, update)?;
    asm.code.emit(|e| {
        e.mov_reg(Gpr::x(0), C_P)?;
        e.mov_reg(Gpr::x(1), SCHEDULER_REGS)?;
        for (index, arg) in args.iter().copied().enumerate() {
            let dst = Gpr::x(index as u8 + 2);
            if arg != dst {
                e.mov_reg(dst, arg)?;
            }
        }
        Ok(())
    })?;
    asm.fragment_call(helper)?;
    crate::emit_leave_runtime(&mut asm.code, live, update)?;
    Ok(())
}

impl BeamModuleAssembler {
    fn emit_bs_construct_runtime_hook(
        &mut self,
        helper: usize,
        args: &[Gpr],
        live: usize,
        update: crate::Update,
    ) -> Result<(), ModuleError> {
        if args.len() > 5 {
            return Err(ModuleError::InvalidOperand(
                "runtime hook has too many arguments",
            ));
        }
        crate::emit_enter_runtime(&mut self.code, live, update)?;
        self.code.emit(|e| {
            e.mov_reg(Gpr::x(0), C_P)?;
            for (index, arg) in args.iter().copied().enumerate() {
                e.mov_reg(Gpr::x(index as u8 + 1), arg)?;
            }
            Ok(())
        })?;
        self.fragment_call(helper)?;
        crate::emit_leave_runtime(&mut self.code, live, update)?;
        self.code.emit(|e| e.ldr_uoff(Gpr::x(9), C_P, 40))?;
        self.error_if_nonzero(Gpr::x(9))?;
        Ok(())
    }

    /// Calls the runtime helper that initializes the current writable binary.
    // Port of erts/emulator/beam/jit/arm/instr_bs.cpp:985-1000, OTP-29.1.1.
    pub fn emit_bs_init_writable(
        &mut self,
        src: ArgVal,
        helper: BsInitWritableHelper,
    ) -> Result<(), ModuleError> {
        let src = self.source_reg(src)?;
        // Port of erts/emulator/beam/jit/arm/instr_bs.cpp:985-1000, OTP-29.1.1.
        self.emit_bs_construct_runtime_hook(
            helper as usize,
            &[src],
            0,
            crate::Update::HEAP_ALLOC.union(crate::Update::REDUCTIONS),
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
        helpers: BsCreateBinHelpers,
    ) -> Result<(), ModuleError> {
        if crate::bs_fast::emit_fast_bs_create_bin(self, fail, alloc, live, dst, segments, helpers)?
        {
            return Ok(());
        }
        self.emit_generic_bs_create_bin(fail, alloc, live, dst, segments, helpers)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn emit_generic_bs_create_bin(
        &mut self,
        fail: u32,
        alloc: u32,
        live: u32,
        dst: ArgVal,
        segments: &[BsSegment],
        helpers: BsCreateBinHelpers,
    ) -> Result<(), ModuleError> {
        emit_bs_create_bin_generic(self, fail, alloc, live, dst, segments, helpers)
    }
}
