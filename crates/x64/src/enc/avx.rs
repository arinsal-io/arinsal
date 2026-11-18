//! VEX-encoded AVX scalar and packed forms.
//!
//! Port of `x86::Assembler::_emit` cases `VexRvm*`, `VexRmv*`, `VexRmMr_Lx`,
//! `VexMovdMovq`, `VexMovssMovsd`, `VexRvmRmi_Lx`, `VexRvmi`, `VexRm_Lx`, and `VexOp` in
//! `erts/emulator/asmjit/x86/x86assembler.cpp`, with opcodes from `x86instdb.cpp`, OTP-29.1.1.

use super::core::{Imm, Opcode, Pp, Rm};
use super::{Emitter, EncodeError, Gp, Mem, Xmm, Ymm};

const VPXOR: Opcode = Opcode::m0f(0xEF).with_pp(Pp::P66);
const VANDPD: Opcode = Opcode::m0f(0x54).with_pp(Pp::P66);
const VCVTSI2SD: Opcode = Opcode::m0f(0x2A).with_pp(Pp::PF2);
const VMOVDQU_LOAD: Opcode = Opcode::m0f(0x6F).with_pp(Pp::PF3);
const VMOVDQU_STORE: Opcode = Opcode::m0f(0x7F).with_pp(Pp::PF3);
const VMOVUPS_LOAD: Opcode = Opcode::m0f(0x10);
const VMOVUPS_STORE: Opcode = Opcode::m0f(0x11);
const VMOVSD_LOAD: Opcode = Opcode::m0f(0x10).with_pp(Pp::PF2);
const VMOVSD_STORE: Opcode = Opcode::m0f(0x11).with_pp(Pp::PF2);
const VMOVQ_GP_LOAD: Opcode = Opcode::m0f(0x6E).with_pp(Pp::P66);
const VMOVQ_XMM_LOAD: Opcode = Opcode::m0f(0x7E).with_pp(Pp::PF3);
const VMOVQ_GP_STORE: Opcode = Opcode::m0f(0x7E).with_pp(Pp::P66);
const VMOVQ_XMM_STORE: Opcode = Opcode::m0f(0xD6).with_pp(Pp::P66);
const VPERMILPD: Opcode = Opcode::m0f3a(0x05).with_pp(Pp::P66);
const VPERMQ: Opcode = Opcode::m0f3a(0x00).with_pp(Pp::P66).with_w(true);
const VPINSRQ: Opcode = Opcode::m0f3a(0x22).with_pp(Pp::P66).with_w(true);
const VINSERTI128: Opcode = Opcode::m0f3a(0x38).with_pp(Pp::P66);
const VPTEST: Opcode = Opcode::m0f38(0x17).with_pp(Pp::P66);
const VUCOMISD: Opcode = Opcode::m0f(0x2E).with_pp(Pp::P66);
const VZEROUPPER: Opcode = Opcode::m0f(0x77);

impl Emitter {
    fn avx_gp_id(reg: Gp) -> Result<(u8, u8), EncodeError> {
        if reg.id > 15 {
            return Err(EncodeError::InvalidRegister(reg));
        }
        Ok((reg.id, reg.size()))
    }

    fn avx_l_by_size(size: u8) -> bool {
        (size / 16) & 2 != 0
    }

    fn vex_xx(
        &mut self,
        opcode: Opcode,
        l256: bool,
        dst: Xmm,
        src: Xmm,
    ) -> Result<(), EncodeError> {
        let (d, s) = (Self::vec_id(dst.0)?, Self::vec_id(src.0)?);
        self.vex_rm(opcode, l256, d, 0, Rm::Reg(s), Imm::NONE)
    }

    fn vex_xm(
        &mut self,
        opcode: Opcode,
        l256: bool,
        dst: Xmm,
        src: Mem,
    ) -> Result<(), EncodeError> {
        let d = Self::vec_id(dst.0)?;
        self.vex_rm(opcode, l256, d, 0, Rm::Mem(&src), Imm::NONE)
    }

    fn vex_mx(
        &mut self,
        opcode: Opcode,
        l256: bool,
        dst: Mem,
        src: Xmm,
    ) -> Result<(), EncodeError> {
        let s = Self::vec_id(src.0)?;
        self.vex_rm(opcode, l256, s, 0, Rm::Mem(&dst), Imm::NONE)
    }
}

impl Emitter {
    /// `vpxor dst, a, b` with xmm operands (asmjit `a.vpxor(Xmm, Xmm, Xmm)`, AVX).
    pub fn vpxor_xxx(&mut self, dst: Xmm, a: Xmm, b: Xmm) -> Result<(), EncodeError> {
        let (d, v, r) = (Self::vec_id(dst.0)?, Self::vec_id(a.0)?, Self::vec_id(b.0)?);
        self.vex_rm(VPXOR, false, d, v, Rm::Reg(r), Imm::NONE)
    }
    /// `vpxor dst, a, [mem]` with xmm operands (asmjit `a.vpxor(Xmm, Xmm, Mem)`, AVX).
    pub fn vpxor_xxm(&mut self, dst: Xmm, a: Xmm, b: Mem) -> Result<(), EncodeError> {
        let (d, v) = (Self::vec_id(dst.0)?, Self::vec_id(a.0)?);
        self.vex_rm(VPXOR, false, d, v, Rm::Mem(&b), Imm::NONE)
    }
    /// `vpxor dst, a, b` with ymm operands (asmjit `a.vpxor(Ymm, Ymm, Ymm)`, AVX2).
    pub fn vpxor_yyy(&mut self, dst: Ymm, a: Ymm, b: Ymm) -> Result<(), EncodeError> {
        let (d, v, r) = (Self::vec_id(dst.0)?, Self::vec_id(a.0)?, Self::vec_id(b.0)?);
        self.vex_rm(VPXOR, true, d, v, Rm::Reg(r), Imm::NONE)
    }

    /// `vpxor ymm, ymm, [mem]` (asmjit `a.vpxor(Ymm, Ymm, Mem)`, AVX2).
    pub fn vpxor_yym(&mut self, dst: Ymm, a: Ymm, b: Mem) -> Result<(), EncodeError> {
        let (d, v) = (Self::vec_id(dst.0)?, Self::vec_id(a.0)?);
        self.vex_rm(VPXOR, true, d, v, Rm::Mem(&b), Imm::NONE)
    }

    /// `vandpd xmm, xmm, xmm` (asmjit `a.vandpd(Xmm, Xmm, Xmm)`, AVX).
    pub fn vandpd_xxx(&mut self, dst: Xmm, a: Xmm, b: Xmm) -> Result<(), EncodeError> {
        let (d, v, r) = (Self::vec_id(dst.0)?, Self::vec_id(a.0)?, Self::vec_id(b.0)?);
        self.vex_rm(VANDPD, false, d, v, Rm::Reg(r), Imm::NONE)
    }

    /// `vandpd xmm, xmm, [mem]` (asmjit `a.vandpd(Xmm, Xmm, Mem)`, AVX).
    pub fn vandpd_xxm(&mut self, dst: Xmm, a: Xmm, b: Mem) -> Result<(), EncodeError> {
        let (d, v) = (Self::vec_id(dst.0)?, Self::vec_id(a.0)?);
        self.vex_rm(VANDPD, false, d, v, Rm::Mem(&b), Imm::NONE)
    }

    /// `vandpd ymm, ymm, ymm` (asmjit `a.vandpd(Ymm, Ymm, Ymm)`, AVX).
    pub fn vandpd_yyy(&mut self, dst: Ymm, a: Ymm, b: Ymm) -> Result<(), EncodeError> {
        let (d, v, r) = (Self::vec_id(dst.0)?, Self::vec_id(a.0)?, Self::vec_id(b.0)?);
        self.vex_rm(VANDPD, true, d, v, Rm::Reg(r), Imm::NONE)
    }

    /// `vandpd ymm, ymm, [mem]` (asmjit `a.vandpd(Ymm, Ymm, Mem)`, AVX).
    pub fn vandpd_yym(&mut self, dst: Ymm, a: Ymm, b: Mem) -> Result<(), EncodeError> {
        let (d, v) = (Self::vec_id(dst.0)?, Self::vec_id(a.0)?);
        self.vex_rm(VANDPD, true, d, v, Rm::Mem(&b), Imm::NONE)
    }

    /// `vcvtsi2sd xmm, xmm, gp` (asmjit `a.vcvtsi2sd(Xmm, Xmm, Gp32|Gp64)`, AVX).
    pub fn vcvtsi2sd_xxr(&mut self, dst: Xmm, a: Xmm, src: Gp) -> Result<(), EncodeError> {
        let (d, v, (r, size)) = (
            Self::vec_id(dst.0)?,
            Self::vec_id(a.0)?,
            Self::avx_gp_id(src)?,
        );
        self.vex_rm(
            VCVTSI2SD.with_w(size == 8),
            false,
            d,
            v,
            Rm::Reg(r),
            Imm::NONE,
        )
    }

    /// `vcvtsi2sd xmm, xmm, [mem]` (asmjit `a.vcvtsi2sd(Xmm, Xmm, Mem)`, AVX).
    pub fn vcvtsi2sd_xxm(&mut self, dst: Xmm, a: Xmm, src: Mem) -> Result<(), EncodeError> {
        let (d, v) = (Self::vec_id(dst.0)?, Self::vec_id(a.0)?);
        self.vex_rm(
            VCVTSI2SD.with_w(src.size == 8),
            false,
            d,
            v,
            Rm::Mem(&src),
            Imm::NONE,
        )
    }

    /// `vmovdqu xmm, xmm` (asmjit `a.vmovdqu(Xmm, Xmm)`, AVX).
    pub fn vmovdqu_xx(&mut self, dst: Xmm, src: Xmm) -> Result<(), EncodeError> {
        self.vex_xx(VMOVDQU_LOAD, false, dst, src)
    }

    /// `vmovdqu xmm, [mem]` (asmjit `a.vmovdqu(Xmm, Mem)`, AVX).
    pub fn vmovdqu_xm(&mut self, dst: Xmm, src: Mem) -> Result<(), EncodeError> {
        let d = Self::vec_id(dst.0)?;
        self.vex_rm(
            VMOVDQU_LOAD,
            Self::avx_l_by_size(16 | src.size),
            d,
            0,
            Rm::Mem(&src),
            Imm::NONE,
        )
    }

    /// `vmovdqu [mem], xmm` (asmjit `a.vmovdqu(Mem, Xmm)`, AVX).
    pub fn vmovdqu_mx(&mut self, dst: Mem, src: Xmm) -> Result<(), EncodeError> {
        let s = Self::vec_id(src.0)?;
        self.vex_rm(
            VMOVDQU_STORE,
            Self::avx_l_by_size(dst.size | 16),
            s,
            0,
            Rm::Mem(&dst),
            Imm::NONE,
        )
    }

    /// `vmovdqu ymm, ymm` (asmjit `a.vmovdqu(Ymm, Ymm)`, AVX).
    pub fn vmovdqu_yy(&mut self, dst: Ymm, src: Ymm) -> Result<(), EncodeError> {
        let (d, s) = (Self::vec_id(dst.0)?, Self::vec_id(src.0)?);
        self.vex_rm(VMOVDQU_LOAD, true, d, 0, Rm::Reg(s), Imm::NONE)
    }

    /// `vmovdqu ymm, [mem]` (asmjit `a.vmovdqu(Ymm, Mem)`, AVX).
    pub fn vmovdqu_ym(&mut self, dst: Ymm, src: Mem) -> Result<(), EncodeError> {
        let d = Self::vec_id(dst.0)?;
        self.vex_rm(VMOVDQU_LOAD, true, d, 0, Rm::Mem(&src), Imm::NONE)
    }

    /// `vmovdqu [mem], ymm` (asmjit `a.vmovdqu(Mem, Ymm)`, AVX).
    pub fn vmovdqu_my(&mut self, dst: Mem, src: Ymm) -> Result<(), EncodeError> {
        let s = Self::vec_id(src.0)?;
        self.vex_rm(VMOVDQU_STORE, true, s, 0, Rm::Mem(&dst), Imm::NONE)
    }

    /// `vmovq xmm, gp` (asmjit `a.vmovq(Xmm, Gp64)`, AVX).
    pub fn vmovq_xr(&mut self, dst: Xmm, src: Gp) -> Result<(), EncodeError> {
        let (r, size) = Self::avx_gp_id(src)?;
        let d = Self::vec_id(dst.0)?;
        self.vex_rm(
            VMOVQ_GP_LOAD.with_w(size == 8),
            false,
            d,
            0,
            Rm::Reg(r),
            Imm::NONE,
        )
    }

    /// `vmovq xmm, xmm` (asmjit `a.vmovq(Xmm, Xmm)`, AVX).
    pub fn vmovq_xx(&mut self, dst: Xmm, src: Xmm) -> Result<(), EncodeError> {
        self.vex_xx(VMOVQ_XMM_LOAD, false, dst, src)
    }

    /// `vmovq xmm, [mem]` (asmjit `a.vmovq(Xmm, Mem)`, AVX).
    pub fn vmovq_xm(&mut self, dst: Xmm, src: Mem) -> Result<(), EncodeError> {
        self.vex_xm(VMOVQ_XMM_LOAD, false, dst, src)
    }

    /// `vmovq gp, xmm` (asmjit `a.vmovq(Gp64, Xmm)`, AVX).
    pub fn vmovq_rx(&mut self, dst: Gp, src: Xmm) -> Result<(), EncodeError> {
        let (r, size) = Self::avx_gp_id(dst)?;
        let s = Self::vec_id(src.0)?;
        self.vex_rm(
            VMOVQ_GP_STORE.with_w(size == 8),
            false,
            s,
            0,
            Rm::Reg(r),
            Imm::NONE,
        )
    }

    /// `vmovq [mem], xmm` (asmjit `a.vmovq(Mem, Xmm)`, AVX).
    pub fn vmovq_mx(&mut self, dst: Mem, src: Xmm) -> Result<(), EncodeError> {
        self.vex_mx(VMOVQ_XMM_STORE, false, dst, src)
    }

    /// `vmovsd xmm, xmm, xmm` (asmjit `a.vmovsd(Xmm, Xmm, Xmm)`, AVX).
    pub fn vmovsd_xxx(&mut self, dst: Xmm, a: Xmm, b: Xmm) -> Result<(), EncodeError> {
        let (d, v, r) = (Self::vec_id(dst.0)?, Self::vec_id(a.0)?, Self::vec_id(b.0)?);
        self.vex_rm(VMOVSD_LOAD, false, d, v, Rm::Reg(r), Imm::NONE)
    }

    /// `vmovsd xmm, [mem]` (asmjit `a.vmovsd(Xmm, Mem)`, AVX).
    pub fn vmovsd_xm(&mut self, dst: Xmm, src: Mem) -> Result<(), EncodeError> {
        self.vex_xm(VMOVSD_LOAD, false, dst, src)
    }

    /// `vmovsd [mem], xmm` (asmjit `a.vmovsd(Mem, Xmm)`, AVX).
    pub fn vmovsd_mx(&mut self, dst: Mem, src: Xmm) -> Result<(), EncodeError> {
        self.vex_mx(VMOVSD_STORE, false, dst, src)
    }

    /// `vmovups xmm, xmm` (asmjit `a.vmovups(Xmm, Xmm)`, AVX).
    pub fn vmovups_xx(&mut self, dst: Xmm, src: Xmm) -> Result<(), EncodeError> {
        self.vex_xx(VMOVUPS_LOAD, false, dst, src)
    }

    /// `vmovups xmm, [mem]` (asmjit `a.vmovups(Xmm, Mem)`, AVX).
    pub fn vmovups_xm(&mut self, dst: Xmm, src: Mem) -> Result<(), EncodeError> {
        let d = Self::vec_id(dst.0)?;
        self.vex_rm(
            VMOVUPS_LOAD,
            Self::avx_l_by_size(16 | src.size),
            d,
            0,
            Rm::Mem(&src),
            Imm::NONE,
        )
    }

    /// `vmovups [mem], xmm` (asmjit `a.vmovups(Mem, Xmm)`, AVX).
    pub fn vmovups_mx(&mut self, dst: Mem, src: Xmm) -> Result<(), EncodeError> {
        let s = Self::vec_id(src.0)?;
        self.vex_rm(
            VMOVUPS_STORE,
            Self::avx_l_by_size(dst.size | 16),
            s,
            0,
            Rm::Mem(&dst),
            Imm::NONE,
        )
    }

    /// `vmovups ymm, ymm` (asmjit `a.vmovups(Ymm, Ymm)`, AVX).
    pub fn vmovups_yy(&mut self, dst: Ymm, src: Ymm) -> Result<(), EncodeError> {
        let (d, s) = (Self::vec_id(dst.0)?, Self::vec_id(src.0)?);
        self.vex_rm(VMOVUPS_LOAD, true, d, 0, Rm::Reg(s), Imm::NONE)
    }

    /// `vmovups ymm, [mem]` (asmjit `a.vmovups(Ymm, Mem)`, AVX).
    pub fn vmovups_ym(&mut self, dst: Ymm, src: Mem) -> Result<(), EncodeError> {
        let d = Self::vec_id(dst.0)?;
        self.vex_rm(VMOVUPS_LOAD, true, d, 0, Rm::Mem(&src), Imm::NONE)
    }

    /// `vmovups [mem], ymm` (asmjit `a.vmovups(Mem, Ymm)`, AVX).
    pub fn vmovups_my(&mut self, dst: Mem, src: Ymm) -> Result<(), EncodeError> {
        let s = Self::vec_id(src.0)?;
        self.vex_rm(VMOVUPS_STORE, true, s, 0, Rm::Mem(&dst), Imm::NONE)
    }

    /// `vpermilpd xmm, xmm, imm8` (asmjit `a.vpermilpd(Xmm, Xmm, Imm)`, AVX).
    pub fn vpermilpd_xxi(&mut self, dst: Xmm, src: Xmm, imm: i64) -> Result<(), EncodeError> {
        let (d, s) = (Self::vec_id(dst.0)?, Self::vec_id(src.0)?);
        self.vex_rm(VPERMILPD, false, d, 0, Rm::Reg(s), Imm::new(imm as u64, 1))
    }

    /// `vpermilpd xmm, [mem], imm8` (asmjit `a.vpermilpd(Xmm, Mem, Imm)`, AVX).
    pub fn vpermilpd_xmi(&mut self, dst: Xmm, src: Mem, imm: i64) -> Result<(), EncodeError> {
        let d = Self::vec_id(dst.0)?;
        self.vex_rm(
            VPERMILPD,
            Self::avx_l_by_size(16 | src.size),
            d,
            0,
            Rm::Mem(&src),
            Imm::new(imm as u64, 1),
        )
    }

    /// `vpermilpd ymm, ymm, imm8` (asmjit `a.vpermilpd(Ymm, Ymm, Imm)`, AVX).
    pub fn vpermilpd_yyi(&mut self, dst: Ymm, src: Ymm, imm: i64) -> Result<(), EncodeError> {
        let (d, s) = (Self::vec_id(dst.0)?, Self::vec_id(src.0)?);
        self.vex_rm(VPERMILPD, true, d, 0, Rm::Reg(s), Imm::new(imm as u64, 1))
    }

    /// `vpermilpd ymm, [mem], imm8` (asmjit `a.vpermilpd(Ymm, Mem, Imm)`, AVX).
    pub fn vpermilpd_ymi(&mut self, dst: Ymm, src: Mem, imm: i64) -> Result<(), EncodeError> {
        let d = Self::vec_id(dst.0)?;
        self.vex_rm(
            VPERMILPD,
            Self::avx_l_by_size(32 | src.size),
            d,
            0,
            Rm::Mem(&src),
            Imm::new(imm as u64, 1),
        )
    }

    /// `vpermq ymm, ymm, imm8` (asmjit `a.vpermq(Ymm, Ymm, Imm)`, AVX2).
    pub fn vpermq_yyi(&mut self, dst: Ymm, src: Ymm, imm: i64) -> Result<(), EncodeError> {
        let (d, s) = (Self::vec_id(dst.0)?, Self::vec_id(src.0)?);
        self.vex_rm(VPERMQ, true, d, 0, Rm::Reg(s), Imm::new(imm as u64, 1))
    }

    /// `vpermq ymm, [mem], imm8` (asmjit `a.vpermq(Ymm, Mem, Imm)`, AVX2).
    pub fn vpermq_ymi(&mut self, dst: Ymm, src: Mem, imm: i64) -> Result<(), EncodeError> {
        let d = Self::vec_id(dst.0)?;
        self.vex_rm(
            VPERMQ,
            Self::avx_l_by_size(32 | src.size),
            d,
            0,
            Rm::Mem(&src),
            Imm::new(imm as u64, 1),
        )
    }

    /// `vpinsrq xmm, xmm, gp, imm8` (asmjit `a.vpinsrq(Xmm, Xmm, Gp64, Imm)`, AVX).
    pub fn vpinsrq_xxri(&mut self, dst: Xmm, a: Xmm, src: Gp, imm: i64) -> Result<(), EncodeError> {
        let (r, _) = Self::avx_gp_id(src)?;
        let (d, v) = (Self::vec_id(dst.0)?, Self::vec_id(a.0)?);
        self.vex_rm(VPINSRQ, false, d, v, Rm::Reg(r), Imm::new(imm as u64, 1))
    }

    /// `vpinsrq xmm, xmm, [mem], imm8` (asmjit `a.vpinsrq(Xmm, Xmm, Mem, Imm)`, AVX).
    pub fn vpinsrq_xxmi(
        &mut self,
        dst: Xmm,
        a: Xmm,
        src: Mem,
        imm: i64,
    ) -> Result<(), EncodeError> {
        let (d, v) = (Self::vec_id(dst.0)?, Self::vec_id(a.0)?);
        self.vex_rm(VPINSRQ, false, d, v, Rm::Mem(&src), Imm::new(imm as u64, 1))
    }

    /// `vinserti128 ymm, ymm, xmm, imm8` (asmjit `a.vinserti128(Ymm, Ymm, Xmm, Imm)`, AVX2).
    pub fn vinserti128_yyxi(
        &mut self,
        dst: Ymm,
        a: Ymm,
        src: Xmm,
        imm: i64,
    ) -> Result<(), EncodeError> {
        let (d, v, r) = (
            Self::vec_id(dst.0)?,
            Self::vec_id(a.0)?,
            Self::vec_id(src.0)?,
        );
        self.vex_rm(VINSERTI128, true, d, v, Rm::Reg(r), Imm::new(imm as u64, 1))
    }

    /// `vinserti128 ymm, ymm, [mem], imm8` (asmjit `a.vinserti128(Ymm, Ymm, Mem, Imm)`, AVX2).
    pub fn vinserti128_yymi(
        &mut self,
        dst: Ymm,
        a: Ymm,
        src: Mem,
        imm: i64,
    ) -> Result<(), EncodeError> {
        let (d, v) = (Self::vec_id(dst.0)?, Self::vec_id(a.0)?);
        self.vex_rm(
            VINSERTI128,
            true,
            d,
            v,
            Rm::Mem(&src),
            Imm::new(imm as u64, 1),
        )
    }

    /// `vptest xmm, xmm` (asmjit `a.vptest(Xmm, Xmm)`, AVX).
    pub fn vptest_xx(&mut self, dst: Xmm, src: Xmm) -> Result<(), EncodeError> {
        self.vex_xx(VPTEST, false, dst, src)
    }

    /// `vptest xmm, [mem]` (asmjit `a.vptest(Xmm, Mem)`, AVX).
    pub fn vptest_xm(&mut self, dst: Xmm, src: Mem) -> Result<(), EncodeError> {
        let d = Self::vec_id(dst.0)?;
        self.vex_rm(
            VPTEST,
            Self::avx_l_by_size(16 | src.size),
            d,
            0,
            Rm::Mem(&src),
            Imm::NONE,
        )
    }

    /// `vptest ymm, ymm` (asmjit `a.vptest(Ymm, Ymm)`, AVX).
    pub fn vptest_yy(&mut self, dst: Ymm, src: Ymm) -> Result<(), EncodeError> {
        let (d, s) = (Self::vec_id(dst.0)?, Self::vec_id(src.0)?);
        self.vex_rm(VPTEST, true, d, 0, Rm::Reg(s), Imm::NONE)
    }

    /// `vptest ymm, [mem]` (asmjit `a.vptest(Ymm, Mem)`, AVX).
    pub fn vptest_ym(&mut self, dst: Ymm, src: Mem) -> Result<(), EncodeError> {
        let d = Self::vec_id(dst.0)?;
        self.vex_rm(
            VPTEST,
            Self::avx_l_by_size(32 | src.size),
            d,
            0,
            Rm::Mem(&src),
            Imm::NONE,
        )
    }

    /// `vucomisd xmm, xmm` (asmjit `a.vucomisd(Xmm, Xmm)`, AVX).
    pub fn vucomisd_xx(&mut self, dst: Xmm, src: Xmm) -> Result<(), EncodeError> {
        self.vex_xx(VUCOMISD, false, dst, src)
    }

    /// `vucomisd xmm, [mem]` (asmjit `a.vucomisd(Xmm, Mem)`, AVX).
    pub fn vucomisd_xm(&mut self, dst: Xmm, src: Mem) -> Result<(), EncodeError> {
        self.vex_xm(VUCOMISD, false, dst, src)
    }

    /// `vzeroupper` (asmjit `a.vzeroupper()`, AVX).
    pub fn vzeroupper(&mut self) -> Result<(), EncodeError> {
        self.vex_op(VZEROUPPER, false)
    }
}
