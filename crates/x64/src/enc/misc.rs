//! Prefix, atomic, string, trap, and code-padding forms.
//!
//! Port of `x86::Assembler::_emit` cases `kEncodingX86Xchg`, `kEncodingX86M_Only`, and the
//! lock/rep prefix emission in `erts/emulator/asmjit/x86/x86assembler.cpp`, plus
//! `x86::Assembler::align`'s optimized code fill, OTP-29.1.1.

use super::core::{ByteRex, Imm, Opcode, Rm};
use super::{Emitter, EncodeError, Gp, Mem};

impl Emitter {
    /// `xchg reg, reg` (asmjit `a.xchg(Gp, Gp)`).
    pub fn xchg_rr(&mut self, dst: Gp, src: Gp) -> Result<(), EncodeError> {
        let size = Self::same_size(dst, src)?;
        if !matches!(size, 1 | 2 | 4 | 8) {
            return Err(EncodeError::InvalidInstruction);
        }
        let mut rex = ByteRex::default();
        let dst_id = Self::gp_id(dst, &mut rex)?;
        let src_id = Self::gp_id(src, &mut rex)?;

        if size != 1 && (dst.id == 0 || src.id == 0) {
            if dst.id != src.id || size == 2 {
                let opcode = Opcode::legacy(0x90).prefix_by_size(size);
                let other = if dst.id == 0 { src_id } else { dst_id };
                return self.x86_op_reg(opcode, other, ByteRex::default(), Imm::NONE);
            }
            if size == 8 {
                return self.x86_op(Opcode::legacy(0x90).with_w(true), Imm::NONE);
            }
        }

        let opcode = Opcode::legacy(0x86).arith_by_size(size);
        self.x86_rm(opcode, src_id, Rm::Reg(dst_id), rex, Imm::NONE)
    }

    /// `xchg reg, mem` (asmjit `a.xchg(Gp, Mem)`).
    pub fn xchg_rm(&mut self, dst: Gp, src: Mem) -> Result<(), EncodeError> {
        self.xchg_mem(dst, &src)
    }

    /// `xchg mem, reg` (asmjit `a.xchg(Mem, Gp)`).
    pub fn xchg_mr(&mut self, dst: Mem, src: Gp) -> Result<(), EncodeError> {
        self.xchg_mem(src, &dst)
    }

    fn xchg_mem(&mut self, reg: Gp, mem: &Mem) -> Result<(), EncodeError> {
        let size = reg.size();
        if !matches!(size, 1 | 2 | 4 | 8) {
            return Err(EncodeError::InvalidInstruction);
        }
        let mut rex = ByteRex::default();
        let reg = Self::gp_id(reg, &mut rex)?;
        let opcode = Opcode::legacy(0x86).arith_by_size(size);
        self.x86_rm(opcode, reg, Rm::Mem(mem), rex, Imm::NONE)
    }

    /// `stosq` (asmjit `a.stosq()`), storing RAX to `[RDI]` and advancing RDI.
    pub fn stosq(&mut self) -> Result<(), EncodeError> {
        self.x86_op(Opcode::legacy(0xAB).with_w(true), Imm::NONE)
    }

    /// `rep stosq` (asmjit `a.rep().stosq()`).
    pub fn rep_stosq(&mut self) -> Result<(), EncodeError> {
        self.x86_op_with_prefix(Some(0xF3), Opcode::legacy(0xAB).with_w(true), Imm::NONE)
    }

    /// `lock inc qword ptr [mem]` (asmjit `a.lock().inc(Mem)`).
    pub fn lock_inc_m(&mut self, dst: Mem) -> Result<(), EncodeError> {
        if dst.size != 0 && dst.size != 8 {
            return Err(EncodeError::InvalidInstruction);
        }
        self.x86_rm_with_prefix(
            Some(0xF0),
            Opcode::legacy(0xFF).with_w(true),
            0,
            Rm::Mem(&dst),
            ByteRex::default(),
            Imm::NONE,
        )
    }

    /// `ud2` (asmjit `a.ud2()`).
    pub fn ud2(&mut self) -> Result<(), EncodeError> {
        self.x86_op(Opcode::m0f(0x0B), Imm::NONE)
    }

    /// `hlt` (asmjit `a.hlt()`).
    pub fn hlt(&mut self) -> Result<(), EncodeError> {
        self.x86_op(Opcode::legacy(0xF4), Imm::NONE)
    }

    /// `int3` (asmjit `a.int3()`).
    pub fn int3(&mut self) -> Result<(), EncodeError> {
        self.x86_op(Opcode::legacy(0xCC), Imm::NONE)
    }

    /// Single-byte `nop` (asmjit `a.nop()`).
    pub fn nop(&mut self) -> Result<(), EncodeError> {
        self.x86_op(Opcode::legacy(0x90), Imm::NONE)
    }

    /// Aligns the current code offset, using asmjit's optimized 1-to-9-byte NOP fill.
    pub fn align_code(&mut self, alignment: u32) -> Result<(), EncodeError> {
        self.code_align(alignment)
    }
}
