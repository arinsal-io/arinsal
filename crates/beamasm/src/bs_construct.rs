//! AArch64 emitters for BEAM bit syntax construction.

pub use crate::bs_fast::{install_bs_append_binary, install_bs_gc};

use crate::module::{ArgVal, BeamModuleAssembler, ModuleError};
use arinsal_a64::enc::Gpr;

/// Runtime hook used to initialize a writable bitstring.
pub type BsInitWritableHelper = extern "C" fn(*mut crate::ProcessHeader, u64) -> u64;

/// Runtime hook that builds the binary from the staged segments; zero means failure.
pub type BsCreateBinHelper = extern "C" fn(*mut crate::ProcessHeader, u64, u64, u64) -> u64;

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
    /// Whether `size` is an untagged unit count rather than a term.
    pub size_is_units: bool,
    /// Size multiplier.
    pub unit: u32,
    /// `BSF_*` flag bits.
    pub flags: u32,
}

/// First X register array slot used to stage segments for the runtime hook when fewer than six
/// X registers are live; otherwise staging starts at the live count, past every live register.
pub const STAGING_BASE: u32 = 6;
/// Words staged per segment: kind, index, unit, flags, size-is-units, source, size.
pub const STAGING_WORDS: u32 = 7;

const C_P: Gpr = Gpr::x(21);
const SCHEDULER_REGS: Gpr = Gpr::x(19);

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
            e.mov_const(Gpr::x(17), helper as u64)?;
            e.str_uoff(Gpr::x(30), C_P, 72)?;
            e.blr(Gpr::x(17))
        })?;
        crate::emit_leave_runtime(&mut self.code, live, update)?;
        self.code.emit(|e| {
            e.ldr_uoff(Gpr::x(30), C_P, 72)?;
            e.ldr_uoff(Gpr::x(9), C_P, 40)
        })?;
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

    /// Builds a binary from the segment list of `bs_create_bin`.
    ///
    /// Fixed on-heap integers, a private append of byte fields, a single UTF-8 segment, and an
    /// append of one binary are emitted inline the way BeamAsm does. Every other shape falls
    /// through to the runtime hook: the segments are staged in the X register array so that the
    /// collector sees them as roots. A zero result with `fail` set clears the pending exception
    /// and branches to `fail`, otherwise the exception propagates.
    // Port of erts/emulator/beam/jit/arm/instr_bs.cpp:1442-2494 (emit_i_bs_create_bin), OTP-29.1.1.
    #[allow(clippy::too_many_arguments)]
    pub fn emit_i_bs_create_bin(
        &mut self,
        fail: u32,
        alloc: u32,
        live: u32,
        dst: ArgVal,
        segments: &[BsSegment],
        helper: BsCreateBinHelper,
    ) -> Result<(), ModuleError> {
        if crate::bs_fast::emit_fast_bs_create_bin(self, fail, alloc, live, dst, segments, helper)?
        {
            return Ok(());
        }
        self.emit_generic_bs_create_bin(fail, alloc, live, dst, segments, helper)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn emit_generic_bs_create_bin(
        &mut self,
        fail: u32,
        alloc: u32,
        live: u32,
        dst: ArgVal,
        segments: &[BsSegment],
        helper: BsCreateBinHelper,
    ) -> Result<(), ModuleError> {
        let words = u32::try_from(segments.len())
            .ok()
            .and_then(|n| n.checked_mul(STAGING_WORDS))
            .and_then(|n| n.checked_add(STAGING_BASE.max(live) + 1))
            .filter(|n| *n < 1000)
            .ok_or(ModuleError::InvalidOperand("too many binary segments"))?;
        let _ = words;
        for (index, segment) in segments.iter().enumerate() {
            let base = STAGING_BASE.max(live) + index as u32 * STAGING_WORDS;
            let small = |value: u64| (value << 4) | 0xf;
            for (slot, value) in [
                (0, small(segment.kind as u64)),
                (1, small(u64::from(segment.index))),
                (2, small(u64::from(segment.unit))),
                (3, small(u64::from(segment.flags))),
                (4, small(u64::from(segment.size_is_units))),
            ] {
                self.code.emit(|e| {
                    e.mov_const(Gpr::x(9), value)?;
                    e.str_uoff(Gpr::x(9), SCHEDULER_REGS, (base + slot) * 8)
                })?;
            }
            for (slot, operand) in [(5, segment.src), (6, segment.size)] {
                let operand = if slot == 6 && segment.size_is_units {
                    match segment.size {
                        ArgVal::Immediate(units) => ArgVal::Immediate(small(units)),
                        other => other,
                    }
                } else {
                    operand
                };
                let register = self.source_reg(operand)?;
                self.code
                    .emit(|e| e.str_uoff(register, SCHEDULER_REGS, (base + slot) * 8))?;
            }
        }
        let update = crate::Update::HEAP_ALLOC
            .union(crate::Update::X_REGS)
            .union(crate::Update::REDUCTIONS);
        crate::emit_enter_runtime(&mut self.code, 6, update)?;
        self.code.emit(|e| {
            e.mov_reg(Gpr::x(0), C_P)?;
            e.mov_const(Gpr::x(1), segments.len() as u64)?;
            // Bit 32 marks a guard with a fail label: no error_info is kept for it.
            e.mov_const(Gpr::x(2), u64::from(live) | (u64::from(fail != 0) << 32))?;
            e.mov_const(Gpr::x(3), u64::from(alloc))?;
            e.mov_const(Gpr::x(17), helper as usize as u64)?;
            e.str_uoff(Gpr::x(30), C_P, 72)?;
            e.blr(Gpr::x(17))
        })?;
        crate::emit_leave_runtime(&mut self.code, 6, update)?;
        let ok = self.code.new_label();
        let failed = self.code.new_label();
        self.code.cbz(Gpr::x(0), failed)?;
        self.code.emit(|e| e.ldr_uoff(Gpr::x(30), C_P, 72))?;
        self.code.b(ok)?;
        self.code.bind(failed)?;
        // The error position is this instruction (the shared error path reads LR).
        self.code.adr(Gpr::x(30), failed)?;
        if fail != 0 {
            let label = self.label(fail);
            self.code.emit(|e| e.str_uoff(Gpr::xzr(), C_P, 40))?;
            self.code.emit(|e| e.ldr_uoff(Gpr::x(30), C_P, 72))?;
            self.code.b(label)?;
        } else {
            self.branch_error()?;
        }
        self.code.bind(ok)?;
        self.store_register(dst, Gpr::x(0))
    }
}
