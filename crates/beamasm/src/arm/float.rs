//! Native BeamAsm floating point instruction emission.

use arinsal_a64::enc::{Cond, Gpr, VecReg};

use crate::module::{ArgVal, BeamModuleAssembler, ModuleError};

const C_P: Gpr = Gpr::x(21);
const HTOP: Gpr = Gpr::x(23);
const TAG_PRIMARY_BOXED: u64 = 2;
const TAG_IMMED1_MASK: u64 = 0x0f;
const TAG_IMMED1_SMALL: u16 = 0x0f;
const HEADER_FLONUM: u64 = (1 << 6) | 0x18;
const HEADER_POS_BIG: u64 = (1 << 6) | 0x08;
const HEADER_NEG_BIG: u64 = (1 << 6) | 0x0c;
const MAX_FINITE_BITS: u64 = 0x7fefffffffffffff;

/// Runtime conversion hook for a validated bignum term to IEEE-754 bits.
pub type BigToFloat = extern "C" fn(*mut crate::ProcessHeader, u64) -> u64;

/// Selects an operation emitted by [`BeamModuleAssembler::emit_float_instr`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FloatOp {
    /// IEEE-754 addition.
    Add,
    /// IEEE-754 subtraction.
    Sub,
    /// IEEE-754 multiplication.
    Mul,
    /// IEEE-754 division.
    Div,
}

const SCHEDULER_REGS: Gpr = Gpr::x(19);
/// The float registers kept in d8-d15 (`num_register_backed_fregs`).
const REGISTER_BACKED_FREGS: u32 = 8;

/// Where a BEAM float register lives: d8-d15 for the first eight, `f_reg_array` of the
/// scheduler registers for the rest.
// Port of erts/emulator/beam/jit/arm/beam_asm.hpp:190 (register_backed_fregs) and :245
// (getFRef), OTP-29.1.1.
#[derive(Clone, Copy)]
enum FloatLoc {
    Reg(VecReg),
    Mem(u32),
}

fn freg(index: u32) -> Result<FloatLoc, ModuleError> {
    if index < REGISTER_BACKED_FREGS {
        Ok(FloatLoc::Reg(VecReg(index as u8 + 8)))
    } else if index < 1024 {
        let base = std::mem::offset_of!(crate::SchedulerRegisters, f_reg_array) as u32;
        Ok(FloatLoc::Mem(base + 8 * index))
    } else {
        Err(ModuleError::InvalidOperand(
            "float register index must be below 1024",
        ))
    }
}

impl BeamModuleAssembler {
    /// The register holding float register `loc`: itself when register backed, else `tmp`
    /// loaded from memory.
    fn float_source(&mut self, loc: FloatLoc, tmp: VecReg) -> Result<VecReg, ModuleError> {
        match loc {
            FloatLoc::Reg(reg) => Ok(reg),
            FloatLoc::Mem(offset) => {
                self.code
                    .emit(|e| e.ldr_d_uoff(tmp, SCHEDULER_REGS, offset))?;
                Ok(tmp)
            }
        }
    }

    /// The register to compute float register `loc` in: itself, or `tmp` until it is flushed.
    fn float_target(loc: FloatLoc, tmp: VecReg) -> VecReg {
        match loc {
            FloatLoc::Reg(reg) => reg,
            FloatLoc::Mem(_) => tmp,
        }
    }

    /// Stores `value` to a memory-backed float register.
    fn float_flush(&mut self, loc: FloatLoc, value: VecReg) -> Result<(), ModuleError> {
        if let FloatLoc::Mem(offset) = loc {
            self.code
                .emit(|e| e.str_d_uoff(value, SCHEDULER_REGS, offset))?;
        }
        Ok(())
    }

    fn emit_float_runtime_hook(&mut self, helper: usize, args: &[Gpr]) -> Result<(), ModuleError> {
        if args.len() > 5 {
            return Err(ModuleError::InvalidOperand(
                "runtime hook has too many arguments",
            ));
        }
        // Port of erts/emulator/beam/jit/arm/instr_float.cpp:114-122, OTP-29.1.1.
        let update = crate::Update::HEAP;
        crate::emit_enter_runtime(&mut self.code, 6, update)?;
        self.code.emit(|e| {
            e.mov_reg(Gpr::x(0), C_P)?;
            for (index, arg) in args.iter().copied().enumerate() {
                e.mov_reg(Gpr::x(index as u8 + 1), arg)?;
            }
            Ok(())
        })?;
        self.fragment_call(helper)?;
        crate::emit_leave_runtime(&mut self.code, 6, update)?;
        self.code.emit(|e| e.ldr_uoff(Gpr::x(9), C_P, 40))?;
        self.error_if_nonzero(Gpr::x(9))?;
        Ok(())
    }

    fn badarith(&mut self) -> Result<(), ModuleError> {
        // Port of erts BADARITH: `freason = EXC_BADARITH`; the reason atom also goes in
        // `fvalue`, which the stacktrace saver matches the failure by.
        let badarith = arinsal_term::Term::atom(
            arinsal_term::global_atoms()
                .intern("badarith")
                .map_err(|_| ModuleError::InvalidOperand("badarith atom"))?,
        )
        .tagged_word();
        self.code.emit(|e| {
            e.mov_const(Gpr::x(9), crate::exc::EXC_BADARITH)?;
            e.str_uoff(Gpr::x(9), C_P, 40)?;
            e.mov_const(Gpr::x(9), badarith)?;
            e.str_uoff(Gpr::x(9), C_P, 48)?;
            e.mov_reg(Gpr::x(0), Gpr::xzr())?;
            Ok(())
        })?;
        self.branch_error()?;
        Ok(())
    }

    fn emit_finite_check(&mut self) -> Result<(), ModuleError> {
        let finite = self.code.new_label();
        self.code.emit(|e| {
            e.fabs(VecReg(30), VecReg(0))?;
            e.mov_const(Gpr::x(9), MAX_FINITE_BITS)?;
            e.fmov_d_from_x(VecReg(31), Gpr::x(9))?;
            e.fcmp(VecReg(30), VecReg(31))
        })?;
        self.code.b_cond(Cond::Ls, finite)?;
        self.badarith()?;
        self.code.bind(finite)?;
        Ok(())
    }

    /// Loads the payload of a boxed float into a d8-d15 float register.
    // Port of erts/emulator/beam/jit/arm/instr_float.cpp:71-79, OTP-29.1.1
    pub fn emit_fload_native(
        &mut self,
        source: ArgVal,
        destination: u32,
    ) -> Result<(), ModuleError> {
        let loc = freg(destination)?;
        let dst = Self::float_target(loc, VecReg(0));
        let source = self.source_reg(source)?;
        self.code.emit(|e| {
            e.and_imm(Gpr::x(9), source, !7)?;
            e.ldur_d(dst, Gpr::x(9), 8)
        })?;
        self.float_flush(loc, dst)
    }

    /// Boxes a d8-d15 value in the process young heap and stores its term.
    // Port of erts/emulator/beam/jit/arm/instr_float.cpp:81-94, OTP-29.1.1
    pub fn emit_fstore_native(
        &mut self,
        source: u32,
        destination: ArgVal,
    ) -> Result<(), ModuleError> {
        let loc = freg(source)?;
        let src = self.float_source(loc, VecReg(0))?;
        let boxed = match destination {
            ArgVal::X(index) if index < 6 => {
                Gpr::x(if index < 4 { 25 + index } else { 11 + index })
            }
            ArgVal::Y(_) | ArgVal::XMemory(_) => {
                self.code
                    .emit(|e| e.add_imm(Gpr::x(9), HTOP, TAG_PRIMARY_BOXED as u16, false))?;
                self.code.emit(|e| {
                    e.mov_const(Gpr::x(10), HEADER_FLONUM)?;
                    e.str_post(Gpr::x(10), HTOP, 8)?;
                    e.str_d_post(src, HTOP, 8)
                })?;
                return self.store_operand(destination, Gpr::x(9));
            }
            _ => {
                return Err(ModuleError::InvalidOperand(
                    "float store destination must be X or Y",
                ));
            }
        };
        self.code
            .emit(|e| e.add_imm(boxed, HTOP, TAG_PRIMARY_BOXED as u16, false))?;
        self.code.emit(|e| {
            e.mov_const(Gpr::x(10), HEADER_FLONUM)?;
            e.str_post(Gpr::x(10), HTOP, 8)?;
            e.str_d_post(src, HTOP, 8)
        })?;
        Ok(())
    }

    /// Converts a small integer inline and delegates validated bignums to the runtime hook.
    // Port of erts/emulator/beam/jit/arm/instr_float.cpp:103-195, OTP-29.1.1
    pub fn emit_fconv_native(
        &mut self,
        source: ArgVal,
        destination: u32,
        big_to_float: BigToFloat,
    ) -> Result<(), ModuleError> {
        let loc = freg(destination)?;
        let dst = Self::float_target(loc, VecReg(1));
        let source = self.source_reg(source)?;
        let small = self.code.new_label();
        let done = self.code.new_label();
        let boxed = self.code.new_label();
        let flonum = self.code.new_label();
        let bignum = self.code.new_label();
        self.code.emit(|e| {
            e.and_imm(Gpr::x(12), source, TAG_IMMED1_MASK)?;
            e.cmp_imm(Gpr::x(12), TAG_IMMED1_SMALL, false)
        })?;
        self.code.b_cond(Cond::Eq, small)?;
        self.code.emit(|e| {
            e.and_imm(Gpr::x(12), source, 3)?;
            e.cmp_imm(Gpr::x(12), TAG_PRIMARY_BOXED as u16, false)
        })?;
        self.code.b_cond(Cond::Eq, boxed)?;
        self.badarith()?;
        self.code.bind(small)?;
        self.code.emit(|e| {
            e.asr_imm(Gpr::x(10), source, 4)?;
            e.scvtf_d_x(dst, Gpr::x(10))
        })?;
        self.code.b(done)?;
        self.code.bind(boxed)?;
        self.code.emit(|e| {
            e.and_imm(Gpr::x(10), source, !7)?;
            e.ldr_uoff(Gpr::x(11), Gpr::x(10), 0)?;
            e.cmp_imm(Gpr::x(11), HEADER_FLONUM as u16, false)
        })?;
        self.code.b_cond(Cond::Eq, flonum)?;
        // A bignum header carries its digit count, so only the subtag bits identify it.
        self.code.emit(|e| {
            e.and_imm(Gpr::x(12), Gpr::x(11), 0x3f)?;
            e.cmp_imm(Gpr::x(12), HEADER_POS_BIG as u16 & 0x3f, false)
        })?;
        self.code.b_cond(Cond::Eq, bignum)?;
        self.code
            .emit(|e| e.cmp_imm(Gpr::x(12), HEADER_NEG_BIG as u16 & 0x3f, false))?;
        self.code.b_cond(Cond::Eq, bignum)?;
        self.badarith()?;
        self.code.bind(flonum)?;
        self.code.emit(|e| e.ldur_d(dst, Gpr::x(10), 8))?;
        self.code.b(done)?;
        self.code.bind(bignum)?;
        self.emit_float_runtime_hook(big_to_float as usize, &[source])?;
        self.code.emit(|e| e.fmov_d_from_x(dst, Gpr::x(0)))?;
        self.code.bind(done)?;
        self.float_flush(loc, dst)
    }

    /// Emits one native float arithmetic instruction, rejecting non-finite results.
    // Port of erts/emulator/beam/jit/arm/instr_float.cpp:55-69,198-220, OTP-29.1.1
    pub fn emit_float_instr(
        &mut self,
        op: FloatOp,
        lhs: u32,
        rhs: u32,
        destination: u32,
    ) -> Result<(), ModuleError> {
        let left = self.float_source(freg(lhs)?, VecReg(1))?;
        let right = self.float_source(freg(rhs)?, VecReg(2))?;
        let loc = freg(destination)?;
        let dst = Self::float_target(loc, VecReg(0));
        self.code.emit(|e| match op {
            FloatOp::Add => e.fadd(VecReg(0), left, right),
            FloatOp::Sub => e.fsub(VecReg(0), left, right),
            FloatOp::Mul => e.fmul(VecReg(0), left, right),
            FloatOp::Div => e.fdiv(VecReg(0), left, right),
        })?;
        self.emit_finite_check()?;
        if dst != VecReg(0) {
            self.code.emit(|e| e.fmov_d(dst, VecReg(0)))?;
        }
        self.float_flush(loc, VecReg(0))
    }

    /// Emits floating point addition (`i_fadd`).
    // Port of erts/emulator/beam/jit/arm/instr_float.cpp:198-202, OTP-29.1.1
    pub fn emit_i_fadd(&mut self, lhs: u32, rhs: u32, dst: u32) -> Result<(), ModuleError> {
        self.emit_float_instr(FloatOp::Add, lhs, rhs, dst)
    }

    /// Emits floating point subtraction (`i_fsub`).
    // Port of erts/emulator/beam/jit/arm/instr_float.cpp:204-208, OTP-29.1.1
    pub fn emit_i_fsub(&mut self, lhs: u32, rhs: u32, dst: u32) -> Result<(), ModuleError> {
        self.emit_float_instr(FloatOp::Sub, lhs, rhs, dst)
    }

    /// Emits floating point multiplication (`i_fmul`).
    // Port of erts/emulator/beam/jit/arm/instr_float.cpp:210-214, OTP-29.1.1
    pub fn emit_i_fmul(&mut self, lhs: u32, rhs: u32, dst: u32) -> Result<(), ModuleError> {
        self.emit_float_instr(FloatOp::Mul, lhs, rhs, dst)
    }

    /// Emits floating point division (`i_fdiv`).
    // Port of erts/emulator/beam/jit/arm/instr_float.cpp:216-220, OTP-29.1.1
    pub fn emit_i_fdiv(&mut self, lhs: u32, rhs: u32, dst: u32) -> Result<(), ModuleError> {
        self.emit_float_instr(FloatOp::Div, lhs, rhs, dst)
    }

    /// Negates a finite floating point register without an arithmetic error check.
    // Port of erts/emulator/beam/jit/arm/instr_float.cpp:222-232, OTP-29.1.1
    pub fn emit_i_fnegate(&mut self, source: u32, destination: u32) -> Result<(), ModuleError> {
        let src = self.float_source(freg(source)?, VecReg(1))?;
        let loc = freg(destination)?;
        self.code.emit(|e| e.fneg(VecReg(0), src))?;
        if let FloatLoc::Reg(dst) = loc {
            self.code.emit(|e| e.fmov_d(dst, VecReg(0)))?;
        }
        self.float_flush(loc, VecReg(0))
    }
}

/// Emits the native boxed-float load path.
// Port of erts/emulator/beam/jit/arm/instr_float.cpp:71-79, OTP-29.1.1
pub fn emit_fload(
    assembler: &mut BeamModuleAssembler,
    source: ArgVal,
    destination: u32,
) -> Result<(), ModuleError> {
    assembler.emit_fload_native(source, destination)
}

/// Emits the native young-heap boxed-float store path.
// Port of erts/emulator/beam/jit/arm/instr_float.cpp:81-94, OTP-29.1.1
pub fn emit_fstore(
    assembler: &mut BeamModuleAssembler,
    source: u32,
    destination: ArgVal,
) -> Result<(), ModuleError> {
    assembler.emit_fstore_native(source, destination)
}

/// Emits native small conversion and the bignum conversion runtime path.
// Port of erts/emulator/beam/jit/arm/instr_float.cpp:97-195, OTP-29.1.1
pub fn emit_fconv(
    assembler: &mut BeamModuleAssembler,
    source: ArgVal,
    destination: u32,
    big_to_float: BigToFloat,
) -> Result<(), ModuleError> {
    assembler.emit_fconv_native(source, destination, big_to_float)
}
