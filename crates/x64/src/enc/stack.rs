//! Stack instruction forms.
//!
//! Port of `x86::Assembler::_emit` cases `kEncodingX86Push` and `kEncodingX86Pop` in
//! `erts/emulator/asmjit/x86/x86assembler.cpp`, OTP-29.1.1.

use super::core::{ByteRex, Imm, Opcode, Rm};
use super::{Emitter, EncodeError, Gp, Mem};

impl Emitter {
    /// `push reg` (asmjit `a.push(Gp)`); 16-bit operands select the 66h form.
    pub fn push_r(&mut self, src: Gp) -> Result<(), EncodeError> {
        if !matches!(src.size(), 2 | 4 | 8) {
            return Err(EncodeError::InvalidInstruction);
        }
        let mut rex = ByteRex::default();
        let reg = Self::gp_id(src, &mut rex)?;
        let mut opcode = Opcode::legacy(0x50);
        if src.size() == 2 {
            opcode.pp = super::core::Pp::P66;
        }
        self.x86_op_reg(opcode, reg, rex, Imm::NONE)
    }

    /// `push mem` (asmjit `a.push(Mem)`); memory operands must be word or native-sized.
    pub fn push_m(&mut self, src: Mem) -> Result<(), EncodeError> {
        let size = Self::mem_size(&src)?;
        if !matches!(size, 2 | 8) {
            return Err(EncodeError::InvalidInstruction);
        }
        let mut opcode = Opcode::legacy(0xFF);
        if size == 2 {
            opcode.pp = super::core::Pp::P66;
        }
        self.x86_rm(opcode, 6, Rm::Mem(&src), ByteRex::default(), Imm::NONE)
    }

    /// `pop reg` (asmjit `a.pop(Gp)`); 16-bit operands select the 66h form.
    pub fn pop_r(&mut self, dst: Gp) -> Result<(), EncodeError> {
        if !matches!(dst.size(), 2 | 4 | 8) {
            return Err(EncodeError::InvalidInstruction);
        }
        let mut rex = ByteRex::default();
        let reg = Self::gp_id(dst, &mut rex)?;
        let mut opcode = Opcode::legacy(0x58);
        if dst.size() == 2 {
            opcode.pp = super::core::Pp::P66;
        }
        self.x86_op_reg(opcode, reg, rex, Imm::NONE)
    }

    /// `pop mem` (asmjit `a.pop(Mem)`); memory operands must be word or native-sized.
    pub fn pop_m(&mut self, dst: Mem) -> Result<(), EncodeError> {
        let size = Self::mem_size(&dst)?;
        if !matches!(size, 2 | 8) {
            return Err(EncodeError::InvalidInstruction);
        }
        let mut opcode = Opcode::legacy(0x8F);
        if size == 2 {
            opcode.pp = super::core::Pp::P66;
        }
        self.x86_rm(opcode, 0, Rm::Mem(&dst), ByteRex::default(), Imm::NONE)
    }

    /// `leave` (asmjit `a.leave()`).
    pub fn leave(&mut self) -> Result<(), EncodeError> {
        self.x86_op(Opcode::legacy(0xC9), Imm::NONE)
    }
}
