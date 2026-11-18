//! SSE2 scalar-double and packed-integer forms.
//!
//! Port of `x86::Assembler::_emit` cases `X86Rm_Raw66H`, `ExtRm`, `ExtRm_P`, `ExtMov`, and
//! `ExtMovq` plus their `x86instdb.cpp` rows, OTP-29.1.1.

use super::core::{ByteRex, Imm, Opcode, Pp, Rm};
use super::{Emitter, EncodeError, Gp, Mem, Xmm};

const MOVSD_LOAD: Opcode = Opcode::m0f(0x10).with_pp(Pp::PF2);
const MOVSD_STORE: Opcode = Opcode::m0f(0x11).with_pp(Pp::PF2);
const MOVQ_GP_LOAD: Opcode = Opcode::m0f(0x6E).with_pp(Pp::P66).with_w(true);
const MOVQ_GP_STORE: Opcode = Opcode::m0f(0x7E).with_pp(Pp::P66).with_w(true);
const MOVQ_XMM_LOAD: Opcode = Opcode::m0f(0x7E).with_pp(Pp::PF3);
const MOVQ_XMM_STORE: Opcode = Opcode::m0f(0xD6).with_pp(Pp::P66);
const MOVDQA_LOAD: Opcode = Opcode::m0f(0x6F).with_pp(Pp::P66);
const MOVDQA_STORE: Opcode = Opcode::m0f(0x7F).with_pp(Pp::P66);
const MOVDQU_LOAD: Opcode = Opcode::m0f(0x6F).with_pp(Pp::PF3);
const MOVDQU_STORE: Opcode = Opcode::m0f(0x7F).with_pp(Pp::PF3);
const MOVUPS_LOAD: Opcode = Opcode::m0f(0x10);
const MOVUPS_STORE: Opcode = Opcode::m0f(0x11);
const PXOR: Opcode = Opcode::m0f(0xEF).with_pp(Pp::P66);
const PUNPCKLQDQ: Opcode = Opcode::m0f(0x6C).with_pp(Pp::P66);
const ANDPD: Opcode = Opcode::m0f(0x54).with_pp(Pp::P66);
const UCOMISD: Opcode = Opcode::m0f(0x2E).with_pp(Pp::P66);
const COMISD: Opcode = Opcode::m0f(0x2F).with_pp(Pp::P66);
const ADDSD: Opcode = Opcode::m0f(0x58).with_pp(Pp::PF2);
const SUBSD: Opcode = Opcode::m0f(0x5C).with_pp(Pp::PF2);
const MULSD: Opcode = Opcode::m0f(0x59).with_pp(Pp::PF2);
const DIVSD: Opcode = Opcode::m0f(0x5E).with_pp(Pp::PF2);
const SQRTSD: Opcode = Opcode::m0f(0x51).with_pp(Pp::PF2);
const CVTSI2SD: Opcode = Opcode::m0f(0x2A).with_pp(Pp::PF2);
const CVTTSD2SI: Opcode = Opcode::m0f(0x2C).with_pp(Pp::PF2);
const BTC: Opcode = Opcode::m0f(0xBA);
const ADDPD: Opcode = Opcode::m0f(0x58).with_pp(Pp::P66);
const SUBPD: Opcode = Opcode::m0f(0x5C).with_pp(Pp::P66);
const MULPD: Opcode = Opcode::m0f(0x59).with_pp(Pp::P66);
const DIVPD: Opcode = Opcode::m0f(0x5E).with_pp(Pp::P66);

impl Emitter {
    fn xmm_id(reg: Xmm) -> Result<u8, EncodeError> {
        Self::vec_id(reg.0)
    }

    /// `btc dst, imm8` (asmjit `a.btc(Gp, Imm)`).
    pub fn btc_ri(&mut self, dst: Gp, bit: i64) -> Result<(), EncodeError> {
        let size = dst.size();
        if !matches!(size, 2 | 4 | 8) {
            return Err(EncodeError::InvalidInstruction);
        }
        let mut rex = ByteRex::default();
        let dst = Self::gp_id(dst, &mut rex)?;
        self.x86_rm(
            BTC.prefix_by_size(size),
            7,
            Rm::Reg(dst),
            rex,
            Imm::new(bit as u64, 1),
        )
    }

    /// `btc size ptr [dst], imm8` (asmjit `a.btc(Mem, Imm)`).
    pub fn btc_mi(&mut self, dst: Mem, bit: i64) -> Result<(), EncodeError> {
        let size = Self::mem_size(&dst)?;
        if !matches!(size, 2 | 4 | 8) {
            return Err(EncodeError::InvalidInstruction);
        }
        self.x86_rm(
            BTC.prefix_by_size(size),
            7,
            Rm::Mem(&dst),
            ByteRex::default(),
            Imm::new(bit as u64, 1),
        )
    }

    fn gp_id_width(reg: Gp) -> Result<(u8, u8), EncodeError> {
        if reg.id > 15 {
            return Err(EncodeError::InvalidRegister(reg));
        }
        Ok((reg.id, reg.size()))
    }

    fn xmm_rm(&mut self, opcode: Opcode, dst: Xmm, src: Xmm) -> Result<(), EncodeError> {
        let (d, s) = (Self::xmm_id(dst)?, Self::xmm_id(src)?);
        self.x86_rm(opcode, d, Rm::Reg(s), ByteRex::default(), Imm::NONE)
    }

    fn xmm_mem(&mut self, opcode: Opcode, dst: Xmm, src: Mem) -> Result<(), EncodeError> {
        let d = Self::xmm_id(dst)?;
        self.x86_rm(opcode, d, Rm::Mem(&src), ByteRex::default(), Imm::NONE)
    }

    fn mem_xmm(&mut self, opcode: Opcode, dst: Mem, src: Xmm) -> Result<(), EncodeError> {
        let s = Self::xmm_id(src)?;
        self.x86_rm(opcode, s, Rm::Mem(&dst), ByteRex::default(), Imm::NONE)
    }

    fn xmm_gp(&mut self, opcode: Opcode, dst: Xmm, src: Gp) -> Result<(), EncodeError> {
        let d = Self::xmm_id(dst)?;
        let (s, size) = Self::gp_id_width(src)?;
        self.x86_rm(
            opcode.with_w(size == 8),
            d,
            Rm::Reg(s),
            ByteRex::default(),
            Imm::NONE,
        )
    }

    fn scalar_binary(&mut self, opcode: Opcode, dst: Xmm, src: Xmm) -> Result<(), EncodeError> {
        self.xmm_rm(opcode, dst, src)
    }

    /// `addpd dst, src` (asmjit `a.addpd(Xmm, Xmm)`).
    pub fn addpd_xx(&mut self, dst: Xmm, src: Xmm) -> Result<(), EncodeError> {
        self.xmm_rm(ADDPD, dst, src)
    }

    /// `subpd dst, src` (asmjit `a.subpd(Xmm, Xmm)`).
    pub fn subpd_xx(&mut self, dst: Xmm, src: Xmm) -> Result<(), EncodeError> {
        self.xmm_rm(SUBPD, dst, src)
    }

    /// `mulpd dst, src` (asmjit `a.mulpd(Xmm, Xmm)`).
    pub fn mulpd_xx(&mut self, dst: Xmm, src: Xmm) -> Result<(), EncodeError> {
        self.xmm_rm(MULPD, dst, src)
    }

    /// `divpd dst, src` (asmjit `a.divpd(Xmm, Xmm)`).
    pub fn divpd_xx(&mut self, dst: Xmm, src: Xmm) -> Result<(), EncodeError> {
        self.xmm_rm(DIVPD, dst, src)
    }

    fn scalar_binary_mem(&mut self, opcode: Opcode, dst: Xmm, src: Mem) -> Result<(), EncodeError> {
        self.xmm_mem(opcode, dst, src)
    }

    /// `movsd dst, src` with XMM operands (asmjit `a.movsd(Xmm, Xmm)`).
    pub fn movsd_xx(&mut self, dst: Xmm, src: Xmm) -> Result<(), EncodeError> {
        self.xmm_rm(MOVSD_LOAD, dst, src)
    }

    /// `movsd dst, [src]` (asmjit `a.movsd(Xmm, Mem)`).
    pub fn movsd_xm(&mut self, dst: Xmm, src: Mem) -> Result<(), EncodeError> {
        self.xmm_mem(MOVSD_LOAD, dst, src)
    }

    /// `movsd [dst], src` (asmjit `a.movsd(Mem, Xmm)`).
    pub fn movsd_mx(&mut self, dst: Mem, src: Xmm) -> Result<(), EncodeError> {
        self.mem_xmm(MOVSD_STORE, dst, src)
    }

    /// `movq xmm, gp` (asmjit `a.movq(Xmm, Gp64)`).
    pub fn movq_xr(&mut self, dst: Xmm, src: Gp) -> Result<(), EncodeError> {
        let (id, _) = Self::gp_id_width(src)?;
        let d = Self::xmm_id(dst)?;
        self.x86_rm(MOVQ_GP_LOAD, d, Rm::Reg(id), ByteRex::default(), Imm::NONE)
    }

    /// `movq xmm, xmm` (asmjit `a.movq(Xmm, Xmm)`).
    pub fn movq_xx(&mut self, dst: Xmm, src: Xmm) -> Result<(), EncodeError> {
        self.xmm_rm(MOVQ_XMM_LOAD, dst, src)
    }

    /// `movq xmm, [mem]` (asmjit `a.movq(Xmm, Mem)`).
    pub fn movq_xm(&mut self, dst: Xmm, src: Mem) -> Result<(), EncodeError> {
        self.xmm_mem(MOVQ_XMM_LOAD, dst, src)
    }

    /// `movq gp, xmm` (asmjit `a.movq(Gp64, Xmm)`).
    pub fn movq_rx(&mut self, dst: Gp, src: Xmm) -> Result<(), EncodeError> {
        let (id, _) = Self::gp_id_width(dst)?;
        let s = Self::xmm_id(src)?;
        self.x86_rm(MOVQ_GP_STORE, s, Rm::Reg(id), ByteRex::default(), Imm::NONE)
    }

    /// `movq [mem], xmm` (asmjit `a.movq(Mem, Xmm)`).
    pub fn movq_mx(&mut self, dst: Mem, src: Xmm) -> Result<(), EncodeError> {
        self.mem_xmm(MOVQ_XMM_STORE, dst, src)
    }

    /// `movdqa xmm, xmm` (asmjit `a.movdqa(Xmm, Xmm)`).
    pub fn movdqa_xx(&mut self, dst: Xmm, src: Xmm) -> Result<(), EncodeError> {
        self.xmm_rm(MOVDQA_LOAD, dst, src)
    }

    /// `movdqa xmm, [mem]` (asmjit `a.movdqa(Xmm, Mem)`).
    pub fn movdqa_xm(&mut self, dst: Xmm, src: Mem) -> Result<(), EncodeError> {
        self.xmm_mem(MOVDQA_LOAD, dst, src)
    }

    /// `movdqa [mem], xmm` (asmjit `a.movdqa(Mem, Xmm)`).
    pub fn movdqa_mx(&mut self, dst: Mem, src: Xmm) -> Result<(), EncodeError> {
        self.mem_xmm(MOVDQA_STORE, dst, src)
    }

    /// `movdqu xmm, xmm` (asmjit `a.movdqu(Xmm, Xmm)`).
    pub fn movdqu_xx(&mut self, dst: Xmm, src: Xmm) -> Result<(), EncodeError> {
        self.xmm_rm(MOVDQU_LOAD, dst, src)
    }

    /// `movdqu xmm, [mem]` (asmjit `a.movdqu(Xmm, Mem)`).
    pub fn movdqu_xm(&mut self, dst: Xmm, src: Mem) -> Result<(), EncodeError> {
        self.xmm_mem(MOVDQU_LOAD, dst, src)
    }

    /// `movdqu [mem], xmm` (asmjit `a.movdqu(Mem, Xmm)`).
    pub fn movdqu_mx(&mut self, dst: Mem, src: Xmm) -> Result<(), EncodeError> {
        self.mem_xmm(MOVDQU_STORE, dst, src)
    }

    /// `movups xmm, xmm` (asmjit `a.movups(Xmm, Xmm)`).
    pub fn movups_xx(&mut self, dst: Xmm, src: Xmm) -> Result<(), EncodeError> {
        self.xmm_rm(MOVUPS_LOAD, dst, src)
    }

    /// `movups xmm, [mem]` (asmjit `a.movups(Xmm, Mem)`).
    pub fn movups_xm(&mut self, dst: Xmm, src: Mem) -> Result<(), EncodeError> {
        self.xmm_mem(MOVUPS_LOAD, dst, src)
    }

    /// `movups [mem], xmm` (asmjit `a.movups(Mem, Xmm)`).
    pub fn movups_mx(&mut self, dst: Mem, src: Xmm) -> Result<(), EncodeError> {
        self.mem_xmm(MOVUPS_STORE, dst, src)
    }

    /// `pxor xmm, xmm` (asmjit `a.pxor(Xmm, Xmm)`).
    pub fn pxor_xx(&mut self, dst: Xmm, src: Xmm) -> Result<(), EncodeError> {
        self.xmm_rm(PXOR, dst, src)
    }

    /// `pxor xmm, [mem]` (asmjit `a.pxor(Xmm, Mem)`).
    pub fn pxor_xm(&mut self, dst: Xmm, src: Mem) -> Result<(), EncodeError> {
        self.xmm_mem(PXOR, dst, src)
    }

    /// `punpcklqdq xmm, xmm` (asmjit `a.punpcklqdq(Xmm, Xmm)`).
    pub fn punpcklqdq_xx(&mut self, dst: Xmm, src: Xmm) -> Result<(), EncodeError> {
        self.xmm_rm(PUNPCKLQDQ, dst, src)
    }

    /// `punpcklqdq xmm, [mem]` (asmjit `a.punpcklqdq(Xmm, Mem)`).
    pub fn punpcklqdq_xm(&mut self, dst: Xmm, src: Mem) -> Result<(), EncodeError> {
        self.xmm_mem(PUNPCKLQDQ, dst, src)
    }

    /// `andpd xmm, xmm` (asmjit `a.andpd(Xmm, Xmm)`).
    pub fn andpd_xx(&mut self, dst: Xmm, src: Xmm) -> Result<(), EncodeError> {
        self.xmm_rm(ANDPD, dst, src)
    }

    /// `andpd xmm, [mem]` (asmjit `a.andpd(Xmm, Mem)`).
    pub fn andpd_xm(&mut self, dst: Xmm, src: Mem) -> Result<(), EncodeError> {
        self.xmm_mem(ANDPD, dst, src)
    }

    /// `ucomisd xmm, xmm` (asmjit `a.ucomisd(Xmm, Xmm)`).
    pub fn ucomisd_xx(&mut self, dst: Xmm, src: Xmm) -> Result<(), EncodeError> {
        self.xmm_rm(UCOMISD, dst, src)
    }

    /// `ucomisd xmm, [mem]` (asmjit `a.ucomisd(Xmm, Mem)`).
    pub fn ucomisd_xm(&mut self, dst: Xmm, src: Mem) -> Result<(), EncodeError> {
        self.xmm_mem(UCOMISD, dst, src)
    }

    /// `comisd xmm, xmm` (asmjit `a.comisd(Xmm, Xmm)`).
    pub fn comisd_xx(&mut self, dst: Xmm, src: Xmm) -> Result<(), EncodeError> {
        self.xmm_rm(COMISD, dst, src)
    }

    /// `comisd xmm, [mem]` (asmjit `a.comisd(Xmm, Mem)`).
    pub fn comisd_xm(&mut self, dst: Xmm, src: Mem) -> Result<(), EncodeError> {
        self.xmm_mem(COMISD, dst, src)
    }

    /// `addsd xmm, xmm` (asmjit `a.addsd(Xmm, Xmm)`).
    pub fn addsd_xx(&mut self, dst: Xmm, src: Xmm) -> Result<(), EncodeError> {
        self.scalar_binary(ADDSD, dst, src)
    }

    /// `addsd xmm, [mem]` (asmjit `a.addsd(Xmm, Mem)`).
    pub fn addsd_xm(&mut self, dst: Xmm, src: Mem) -> Result<(), EncodeError> {
        self.scalar_binary_mem(ADDSD, dst, src)
    }

    /// `subsd xmm, xmm` (asmjit `a.subsd(Xmm, Xmm)`).
    pub fn subsd_xx(&mut self, dst: Xmm, src: Xmm) -> Result<(), EncodeError> {
        self.scalar_binary(SUBSD, dst, src)
    }

    /// `subsd xmm, [mem]` (asmjit `a.subsd(Xmm, Mem)`).
    pub fn subsd_xm(&mut self, dst: Xmm, src: Mem) -> Result<(), EncodeError> {
        self.scalar_binary_mem(SUBSD, dst, src)
    }

    /// `mulsd xmm, xmm` (asmjit `a.mulsd(Xmm, Xmm)`).
    pub fn mulsd_xx(&mut self, dst: Xmm, src: Xmm) -> Result<(), EncodeError> {
        self.scalar_binary(MULSD, dst, src)
    }

    /// `mulsd xmm, [mem]` (asmjit `a.mulsd(Xmm, Mem)`).
    pub fn mulsd_xm(&mut self, dst: Xmm, src: Mem) -> Result<(), EncodeError> {
        self.scalar_binary_mem(MULSD, dst, src)
    }

    /// `divsd xmm, xmm` (asmjit `a.divsd(Xmm, Xmm)`).
    pub fn divsd_xx(&mut self, dst: Xmm, src: Xmm) -> Result<(), EncodeError> {
        self.scalar_binary(DIVSD, dst, src)
    }

    /// `divsd xmm, [mem]` (asmjit `a.divsd(Xmm, Mem)`).
    pub fn divsd_xm(&mut self, dst: Xmm, src: Mem) -> Result<(), EncodeError> {
        self.scalar_binary_mem(DIVSD, dst, src)
    }

    /// `sqrtsd xmm, xmm` (asmjit `a.sqrtsd(Xmm, Xmm)`).
    pub fn sqrtsd_xx(&mut self, dst: Xmm, src: Xmm) -> Result<(), EncodeError> {
        self.scalar_binary(SQRTSD, dst, src)
    }

    /// `sqrtsd xmm, [mem]` (asmjit `a.sqrtsd(Xmm, Mem)`).
    pub fn sqrtsd_xm(&mut self, dst: Xmm, src: Mem) -> Result<(), EncodeError> {
        self.scalar_binary_mem(SQRTSD, dst, src)
    }

    /// `cvtsi2sd xmm, gp` (asmjit `a.cvtsi2sd(Xmm, Gp32|Gp64)`).
    pub fn cvtsi2sd_xr(&mut self, dst: Xmm, src: Gp) -> Result<(), EncodeError> {
        self.xmm_gp(CVTSI2SD, dst, src)
    }

    /// `cvtsi2sd xmm, [mem]` (asmjit `a.cvtsi2sd(Xmm, Mem)`).
    pub fn cvtsi2sd_xm(&mut self, dst: Xmm, src: Mem) -> Result<(), EncodeError> {
        let d = Self::xmm_id(dst)?;
        self.x86_rm(
            CVTSI2SD.with_w(src.size == 8),
            d,
            Rm::Mem(&src),
            ByteRex::default(),
            Imm::NONE,
        )
    }

    /// `cvttsd2si gp, xmm` (asmjit `a.cvttsd2si(Gp32|Gp64, Xmm)`).
    pub fn cvttsd2si_rx(&mut self, dst: Gp, src: Xmm) -> Result<(), EncodeError> {
        let (d, size) = Self::gp_id_width(dst)?;
        let s = Self::xmm_id(src)?;
        self.x86_rm(
            CVTTSD2SI.with_w(size == 8),
            d,
            Rm::Reg(s),
            ByteRex::default(),
            Imm::NONE,
        )
    }

    /// `cvttsd2si gp, [mem]` (asmjit `a.cvttsd2si(Gp32|Gp64, Mem)`).
    pub fn cvttsd2si_rm(&mut self, dst: Gp, src: Mem) -> Result<(), EncodeError> {
        let (d, size) = Self::gp_id_width(dst)?;
        let opcode = CVTTSD2SI.with_w(size == 8);
        self.x86_rm(opcode, d, Rm::Mem(&src), ByteRex::default(), Imm::NONE)
    }
}
