//! Multiply, divide, and sign-extension forms.
//!
//! Port of `x86::Assembler::_emit` cases `kEncodingX86M_GPB_MulDiv` and `kEncodingX86Imul` in
//! `erts/emulator/asmjit/x86/x86assembler.cpp`, OTP-29.1.1.

use super::core::{ByteRex, Imm, Opcode, Rm, is_int};
use super::{Emitter, EncodeError, Gp, Mem};

enum ImulSource<'a> {
    Reg(Gp),
    Mem(&'a Mem),
}

fn width_opcode(byte: u8, size: u8) -> Opcode {
    Opcode::legacy(byte).prefix_by_size(size)
}

impl Emitter {
    fn muldiv_r(&mut self, src: Gp, extension: u8) -> Result<(), EncodeError> {
        let size = src.size();
        if !matches!(size, 1 | 2 | 4 | 8) {
            return Err(EncodeError::InvalidInstruction);
        }
        let mut rex = ByteRex::default();
        let src = Self::gp_id(src, &mut rex)?;
        self.x86_rm(
            width_opcode(if size == 1 { 0xF6 } else { 0xF7 }, size),
            extension,
            Rm::Reg(src),
            rex,
            Imm::NONE,
        )
    }

    fn muldiv_m(&mut self, src: Mem, extension: u8) -> Result<(), EncodeError> {
        let size = src.size;
        if size == 0 {
            return Err(EncodeError::AmbiguousOperandSize);
        }
        self.x86_rm(
            Opcode::legacy(0xF6).arith_by_size(size),
            extension,
            Rm::Mem(&src),
            ByteRex::default(),
            Imm::NONE,
        )
    }

    fn imul_imm(
        &mut self,
        dst: Gp,
        src: ImulSource<'_>,
        imm: i64,
        sign_extend_i32_for_short: bool,
    ) -> Result<(), EncodeError> {
        let size = dst.size();
        let imm_size = if size == 2 { 2 } else { 4 };
        let imm_value = if size == 4 && sign_extend_i32_for_short {
            imm as i32 as i64
        } else {
            imm
        };
        let short = is_int(imm_value, 8);
        let opcode = width_opcode(if short { 0x6B } else { 0x69 }, size);
        let dst_id = raw_gp_id(dst)?;
        let rex = ByteRex::default();
        let rm = match src {
            ImulSource::Reg(src) => Rm::Reg(raw_gp_id(src)?),
            ImulSource::Mem(mem) => Rm::Mem(mem),
        };
        let output_imm_size = if short { 1 } else { imm_size };
        let value = Imm::new(imm_value as u64, output_imm_size);
        self.x86_rm(opcode, dst_id, rm, rex, value)
    }

    /// `mul reg` (asmjit `a.mul(Gp)`), using the implicit RAX/RDX result.
    pub fn mul_r(&mut self, src: Gp) -> Result<(), EncodeError> {
        self.muldiv_r(src, 4)
    }

    /// `mul mem` (asmjit `a.mul(Mem)`), using the implicit RAX/RDX result.
    pub fn mul_m(&mut self, src: Mem) -> Result<(), EncodeError> {
        self.muldiv_m(src, 4)
    }

    /// One-operand signed `imul reg` (asmjit `a.imul(Gp)`), using implicit RAX/RDX.
    pub fn imul_r(&mut self, src: Gp) -> Result<(), EncodeError> {
        self.muldiv_r(src, 5)
    }

    /// One-operand signed `imul mem` (asmjit `a.imul(Mem)`), using implicit RAX/RDX.
    pub fn imul_m(&mut self, src: Mem) -> Result<(), EncodeError> {
        self.muldiv_m(src, 5)
    }

    /// Two-operand signed `imul dst, src` (asmjit `a.imul(Gp, Gp)`).
    pub fn imul_rr(&mut self, dst: Gp, src: Gp) -> Result<(), EncodeError> {
        if src.size() == 1 {
            if dst.id != 0 || dst.size() != 2 {
                return Err(EncodeError::InvalidInstruction);
            }
            let mut rex = ByteRex::default();
            let src_id = Self::gp_id(src, &mut rex)?;
            return self.x86_rm(Opcode::legacy(0xF6), 5, Rm::Reg(src_id), rex, Imm::NONE);
        }
        let size = Self::same_size(dst, src)?;
        if !matches!(size, 2 | 4 | 8) {
            return Err(EncodeError::InvalidInstruction);
        }
        let mut rex = ByteRex::default();
        let dst_id = Self::gp_id(dst, &mut rex)?;
        let src_id = Self::gp_id(src, &mut rex)?;
        self.x86_rm(
            Opcode::m0f(0xAF).prefix_by_size(size),
            dst_id,
            Rm::Reg(src_id),
            rex,
            Imm::NONE,
        )
    }

    /// Two-operand signed `imul dst, src` with memory source (asmjit `a.imul(Gp, Mem)`).
    pub fn imul_rm(&mut self, dst: Gp, src: Mem) -> Result<(), EncodeError> {
        let size = dst.size();
        if src.size == 1 {
            if dst.id != 0 || size != 2 {
                return Err(EncodeError::InvalidInstruction);
            }
            return self.x86_rm(
                Opcode::legacy(0xF6),
                5,
                Rm::Mem(&src),
                ByteRex::default(),
                Imm::NONE,
            );
        }
        let dst_id = raw_gp_id(dst)?;
        self.x86_rm(
            Opcode::m0f(0xAF).prefix_by_size(size),
            dst_id,
            Rm::Mem(&src),
            ByteRex::default(),
            Imm::NONE,
        )
    }

    /// Three-operand signed `imul dst, src, imm` (asmjit `a.imul(Gp, Gp, Imm)`).
    pub fn imul_rri(&mut self, dst: Gp, src: Gp, imm: i64) -> Result<(), EncodeError> {
        self.imul_imm(dst, ImulSource::Reg(src), imm, false)
    }

    /// Three-operand signed `imul dst, mem, imm` (asmjit `a.imul(Gp, Mem, Imm)`).
    pub fn imul_rmi(&mut self, dst: Gp, src: Mem, imm: i64) -> Result<(), EncodeError> {
        self.imul_imm(dst, ImulSource::Mem(&src), imm, true)
    }

    /// Two-operand immediate `imul dst, imm` shorthand (asmjit `a.imul(Gp, Imm)`).
    pub fn imul_ri(&mut self, dst: Gp, imm: i64) -> Result<(), EncodeError> {
        self.imul_imm(dst, ImulSource::Reg(dst), imm, true)
    }

    /// Unsigned `div reg` (asmjit `a.div(Gp)`), dividing implicit RDX:RAX.
    pub fn div_r(&mut self, src: Gp) -> Result<(), EncodeError> {
        self.muldiv_r(src, 6)
    }

    /// Unsigned `div mem` (asmjit `a.div(Mem)`), dividing implicit RDX:RAX.
    pub fn div_m(&mut self, src: Mem) -> Result<(), EncodeError> {
        self.muldiv_m(src, 6)
    }

    /// Signed `idiv reg` (asmjit `a.idiv(Gp)`), dividing implicit RDX:RAX.
    pub fn idiv_r(&mut self, src: Gp) -> Result<(), EncodeError> {
        self.muldiv_r(src, 7)
    }

    /// Signed `idiv mem` (asmjit `a.idiv(Mem)`), dividing implicit RDX:RAX.
    pub fn idiv_m(&mut self, src: Mem) -> Result<(), EncodeError> {
        self.muldiv_m(src, 7)
    }

    /// Sign-extends RAX into RDX:RAX (asmjit `a.cqo()`).
    pub fn cqo(&mut self) -> Result<(), EncodeError> {
        self.x86_op(Opcode::legacy(0x99).with_w(true), Imm::NONE)
    }

    /// Sign-extends EAX into EDX:EAX (asmjit `a.cdq()`).
    pub fn cdq(&mut self) -> Result<(), EncodeError> {
        self.x86_op(Opcode::legacy(0x99), Imm::NONE)
    }
}

fn raw_gp_id(reg: Gp) -> Result<u8, EncodeError> {
    if reg.id <= 15 {
        Ok(reg.id)
    } else {
        Err(EncodeError::InvalidRegister(reg))
    }
}
