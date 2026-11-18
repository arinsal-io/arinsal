//! BMI/ABM integer forms.
//!
//! Port of the matching `x86::Assembler::_emit` cases (`VexRvm_Wx`, `VexRmv_Wx`, and
//! `X86Rm_Raw66H`) and instruction rows in `erts/emulator/asmjit/x86/x86instdb.cpp`, OTP-29.1.1.

use super::core::{ByteRex, Imm, Opcode, Pp, Rm};
use super::{Emitter, EncodeError, Gp};

const ANDN: Opcode = Opcode::m0f38(0xF2);
const BZHI: Opcode = Opcode::m0f38(0xF5);
const MULX: Opcode = Opcode::m0f38(0xF6).with_pp(Pp::PF2);
const PEXT: Opcode = Opcode::m0f38(0xF5).with_pp(Pp::PF3);
const SARX: Opcode = Opcode::m0f38(0xF7).with_pp(Pp::PF3);
const SHLX: Opcode = Opcode::m0f38(0xF7).with_pp(Pp::P66);
const SHRX: Opcode = Opcode::m0f38(0xF7).with_pp(Pp::PF2);

impl Emitter {
    fn bmi_id(reg: Gp) -> Result<(u8, u8), EncodeError> {
        if !matches!(reg.size(), 4 | 8) {
            return Err(EncodeError::InvalidInstruction);
        }
        let id = Self::gp_id(reg, &mut ByteRex::default())?;
        Ok((id, reg.size()))
    }

    fn bmi_three(
        &mut self,
        opcode: Opcode,
        dst: Gp,
        src: Gp,
        control: Gp,
    ) -> Result<(), EncodeError> {
        let (d, size) = Self::bmi_id(dst)?;
        let (s, src_size) = Self::bmi_id(src)?;
        let (c, control_size) = Self::bmi_id(control)?;
        if size != src_size || size != control_size {
            return Err(EncodeError::OperandSizeMismatch);
        }
        self.vex_rm(opcode.with_w(size == 8), false, d, s, Rm::Reg(c), Imm::NONE)
    }

    fn bmi_unary(&mut self, opcode: u8, dst: Gp, src: Gp) -> Result<(), EncodeError> {
        let (d, size) = Self::bmi_id(dst)?;
        let (s, src_size) = Self::bmi_id(src)?;
        if size != src_size {
            return Err(EncodeError::OperandSizeMismatch);
        }
        self.x86_rm(
            Opcode::m0f(opcode).with_pp(Pp::PF3).with_w(size == 8),
            d,
            Rm::Reg(s),
            ByteRex::default(),
            Imm::NONE,
        )
    }

    fn bmi_shift(
        &mut self,
        opcode: Opcode,
        dst: Gp,
        src: Gp,
        count: Gp,
    ) -> Result<(), EncodeError> {
        let (d, size) = Self::bmi_id(dst)?;
        let (s, src_size) = Self::bmi_id(src)?;
        let (c, count_size) = Self::bmi_id(count)?;
        if size != src_size || size != count_size {
            return Err(EncodeError::OperandSizeMismatch);
        }
        // asmjit `VexRmv_Wx` encodes count in VEX.vvvv and src in r/m.
        self.vex_rm(opcode.with_w(size == 8), false, d, c, Rm::Reg(s), Imm::NONE)
    }

    /// `andn dst, src, mask` (asmjit `a.andn(Gp, Gp, Gp)`; BMI1).
    pub fn andn_rrr(&mut self, dst: Gp, src: Gp, mask: Gp) -> Result<(), EncodeError> {
        self.bmi_three(ANDN, dst, src, mask)
    }

    /// `bzhi dst, src, index` (asmjit `a.bzhi(Gp, Gp, Gp)`; BMI2).
    pub fn bzhi_rrr(&mut self, dst: Gp, src: Gp, index: Gp) -> Result<(), EncodeError> {
        let (d, size) = Self::bmi_id(dst)?;
        let (s, src_size) = Self::bmi_id(src)?;
        let (i, index_size) = Self::bmi_id(index)?;
        if size != src_size || size != index_size {
            return Err(EncodeError::OperandSizeMismatch);
        }
        // asmjit `VexRmv_Wx` puts the third operand in VEX.vvvv and the second in r/m.
        self.vex_rm(BZHI.with_w(size == 8), false, d, i, Rm::Reg(s), Imm::NONE)
    }

    /// `mulx high, low, src` with implicit `rdx` (asmjit `a.mulx(Gp, Gp, Gp)`; BMI2).
    pub fn mulx_rrr(&mut self, high: Gp, low: Gp, src: Gp) -> Result<(), EncodeError> {
        let (h, hs) = Self::bmi_id(high)?;
        let (l, ls) = Self::bmi_id(low)?;
        let (s, ss) = Self::bmi_id(src)?;
        if hs != 8 || ls != 8 || ss != 8 {
            return Err(EncodeError::InvalidInstruction);
        }
        if hs != ls || hs != ss {
            return Err(EncodeError::OperandSizeMismatch);
        }
        self.vex_rm(MULX.with_w(true), false, h, l, Rm::Reg(s), Imm::NONE)
    }

    /// `pext dst, src, mask` (asmjit `a.pext(Gp, Gp, Gp)`; BMI2).
    pub fn pext_rrr(&mut self, dst: Gp, src: Gp, mask: Gp) -> Result<(), EncodeError> {
        self.bmi_three(PEXT, dst, src, mask)
    }

    /// `sarx dst, src, count` (asmjit `a.sarx(Gp, Gp, Gp)`; BMI2).
    pub fn sarx_rrr(&mut self, dst: Gp, src: Gp, count: Gp) -> Result<(), EncodeError> {
        self.bmi_shift(SARX, dst, src, count)
    }

    /// `shlx dst, src, count` (asmjit `a.shlx(Gp, Gp, Gp)`; BMI2).
    pub fn shlx_rrr(&mut self, dst: Gp, src: Gp, count: Gp) -> Result<(), EncodeError> {
        self.bmi_shift(SHLX, dst, src, count)
    }

    /// `shrx dst, src, count` (asmjit `a.shrx(Gp, Gp, Gp)`; BMI2).
    pub fn shrx_rrr(&mut self, dst: Gp, src: Gp, count: Gp) -> Result<(), EncodeError> {
        self.bmi_shift(SHRX, dst, src, count)
    }

    /// `lzcnt dst, src` (asmjit `a.lzcnt(Gp, Gp)`; LZCNT).
    pub fn lzcnt_rr(&mut self, dst: Gp, src: Gp) -> Result<(), EncodeError> {
        self.bmi_unary(0xBD, dst, src)
    }

    /// `tzcnt dst, src` (asmjit `a.tzcnt(Gp, Gp)`; BMI1).
    pub fn tzcnt_rr(&mut self, dst: Gp, src: Gp) -> Result<(), EncodeError> {
        self.bmi_unary(0xBC, dst, src)
    }

    /// `popcnt dst, src` (asmjit `a.popcnt(Gp, Gp)`; POPCNT).
    pub fn popcnt_rr(&mut self, dst: Gp, src: Gp) -> Result<(), EncodeError> {
        self.bmi_unary(0xB8, dst, src)
    }
}
