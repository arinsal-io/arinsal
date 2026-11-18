//! Indirect control-transfer and return forms.
//!
//! Port of asmjit `x86::Assembler::_emit` cases `kEncodingX86Call`, `kEncodingX86Jmp`, and
//! `kEncodingX86Ret` in `erts/emulator/asmjit/x86/x86assembler.cpp`, OTP-29.1.1. Indirect forms
//! encode through asmjit's `EmitX86R` / `EmitX86M`; relative and label targets belong to the label
//! layer.

use super::core::{Imm, Opcode, Rm};
use super::{Emitter, EncodeError, Gp, Mem};

impl Emitter {
    /// `call r64` (asmjit `a.call(Gp)`), encoded as `FF /2`.
    ///
    /// Asmjit uses the physical register id and treats the target as 64-bit in long mode.
    pub fn call_r(&mut self, target: Gp) -> Result<(), EncodeError> {
        let reg = raw_gp_id(target)?;
        self.x86_rm(
            Opcode::legacy(0xFF),
            2,
            Rm::Reg(reg),
            Default::default(),
            Imm::NONE,
        )
    }

    /// `call [mem]` (asmjit `a.call(Mem)`), encoded as `FF /2`.
    pub fn call_m(&mut self, target: Mem) -> Result<(), EncodeError> {
        self.x86_rm(
            Opcode::legacy(0xFF),
            2,
            Rm::Mem(&target),
            Default::default(),
            Imm::NONE,
        )
    }

    /// `jmp r64` (asmjit `a.jmp(Gp)`), encoded as `FF /4`.
    ///
    /// Asmjit uses the physical register id and treats the target as 64-bit in long mode.
    pub fn jmp_r(&mut self, target: Gp) -> Result<(), EncodeError> {
        let reg = raw_gp_id(target)?;
        self.x86_rm(
            Opcode::legacy(0xFF),
            4,
            Rm::Reg(reg),
            Default::default(),
            Imm::NONE,
        )
    }

    /// `jmp [mem]` (asmjit `a.jmp(Mem)`), encoded as `FF /4`.
    pub fn jmp_m(&mut self, target: Mem) -> Result<(), EncodeError> {
        self.x86_rm(
            Opcode::legacy(0xFF),
            4,
            Rm::Mem(&target),
            Default::default(),
            Imm::NONE,
        )
    }

    /// `ret` (asmjit `a.ret()`), encoded as `C3`.
    pub fn ret(&mut self) -> Result<(), EncodeError> {
        self.x86_op(Opcode::legacy(0xC3), Imm::NONE)
    }

    /// `ret imm16` (asmjit `a.ret(Imm)`). A zero immediate uses the shorter `C3` form; other
    /// values emit their low 16 bits, as asmjit's two-byte immediate writer does.
    pub fn ret_i(&mut self, adjustment: i64) -> Result<(), EncodeError> {
        if adjustment == 0 {
            self.ret()
        } else {
            self.x86_op(Opcode::legacy(0xC2), Imm::new(adjustment as u64, 2))
        }
    }
}

fn raw_gp_id(reg: Gp) -> Result<u8, EncodeError> {
    if reg.id <= 15 {
        Ok(reg.id)
    } else {
        Err(EncodeError::InvalidRegister(reg))
    }
}
