//! Checked AArch64 instruction encodings used by the BeamAsm port.

use std::fmt;

/// Register width for general purpose registers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Width {
    /// 32-bit W register.
    W32,
    /// 64-bit X register.
    X64,
}

/// General-purpose register identity. `SP` and `ZR` remain distinct even though both encode as 31.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GprKind {
    /// Ordinary numbered register.
    General,
    /// Stack pointer (or zero register in instruction positions that interpret 31 as SP).
    Sp,
    /// Zero register (or stack pointer in instruction positions that interpret 31 as ZR).
    Zr,
}

/// A 32-bit or 64-bit AArch64 general-purpose register.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Gpr {
    /// Register width.
    pub width: Width,
    /// Register number, 0 through 30; 31 is reserved for SP/ZR.
    pub number: u8,
    /// Meaning of encoding 31.
    pub kind: GprKind,
}

impl Gpr {
    /// Constructs `Xn`.
    pub const fn x(number: u8) -> Self {
        Self {
            width: Width::X64,
            number,
            kind: GprKind::General,
        }
    }
    /// Constructs `Wn`.
    pub const fn w(number: u8) -> Self {
        Self {
            width: Width::W32,
            number,
            kind: GprKind::General,
        }
    }
    /// Constructs `SP`.
    pub const fn sp() -> Self {
        Self {
            width: Width::X64,
            number: 31,
            kind: GprKind::Sp,
        }
    }
    /// Constructs `WSP`.
    pub const fn wsp() -> Self {
        Self {
            width: Width::W32,
            number: 31,
            kind: GprKind::Sp,
        }
    }
    /// Constructs `XZR`.
    pub const fn xzr() -> Self {
        Self {
            width: Width::X64,
            number: 31,
            kind: GprKind::Zr,
        }
    }
    /// Constructs `WZR`.
    pub const fn wzr() -> Self {
        Self {
            width: Width::W32,
            number: 31,
            kind: GprKind::Zr,
        }
    }
}

/// SIMD/floating-point register Dn or Vn.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VecReg(pub u8);

/// AArch64 condition code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Cond {
    /// Equal.
    Eq = 0,
    /// Not equal.
    Ne = 1,
    /// Carry set / unsigned higher or same.
    Cs = 2,
    /// Carry clear / unsigned lower.
    Cc = 3,
    /// Minus.
    Mi = 4,
    /// Plus.
    Pl = 5,
    /// Overflow.
    Vs = 6,
    /// No overflow.
    Vc = 7,
    /// Unsigned higher.
    Hi = 8,
    /// Unsigned lower or same.
    Ls = 9,
    /// Signed greater or equal.
    Ge = 10,
    /// Signed less than.
    Lt = 11,
    /// Signed greater than.
    Gt = 12,
    /// Signed less or equal.
    Le = 13,
    /// Always.
    Al = 14,
}

/// Shift operation used by shifted-register instructions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Shift {
    /// Logical shift left.
    Lsl = 0,
    /// Logical shift right.
    Lsr = 1,
    /// Arithmetic shift right.
    Asr = 2,
    /// Rotate right.
    Ror = 3,
}

/// Extension operation used by extended-register instructions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Extend {
    /// Unsigned byte.
    Uxtb = 0,
    /// Unsigned halfword.
    Uxth = 1,
    /// Unsigned word.
    Uxtw = 2,
    /// Unsigned doubleword.
    Uxtx = 3,
    /// Signed byte.
    Sxtb = 4,
    /// Signed halfword.
    Sxth = 5,
    /// Signed word.
    Sxtw = 6,
    /// Signed doubleword.
    Sxtx = 7,
}

/// Encoding validation failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EncodeError {
    /// Register number must be in 0..=31 and register kind/width must match the form.
    InvalidRegister(Gpr),
    /// Operands have incompatible widths.
    WidthMismatch,
    /// Immediate does not fit the selected instruction form.
    ImmediateOutOfRange { value: i64, min: i64, max: i64 },
    /// Immediate is not a logical bitmask encoding.
    UnencodableLogicalImmediate(u64),
    /// Floating-point immediate cannot be represented by the AArch64 imm8 format.
    UnencodableFpImmediate(u64),
    /// Shift amount is outside the permitted range.
    InvalidShift(u8),
    /// Misaligned immediate.
    Misaligned { value: i64, alignment: u8 },
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for EncodeError {}

/// A memory operand for common base-register addressing forms.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Mem {
    /// Base register.
    pub base: Gpr,
    /// Signed byte displacement.
    pub offset: i64,
}

/// Shifted register operand.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Shifted {
    /// Source register.
    pub reg: Gpr,
    /// Shift kind.
    pub shift: Shift,
    /// Shift amount.
    pub amount: u8,
}

/// Extended register operand.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Extended {
    /// Source register.
    pub reg: Gpr,
    /// Extension kind.
    pub extend: Extend,
    /// Left shift, 0 through 4.
    pub amount: u8,
}

/// Instructions emitted so far, in little-endian target word order.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Emitter {
    /// Encoded instruction words.
    pub words: Vec<u32>,
}

impl Emitter {
    /// Creates an empty emitter.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates an emitter with a reserved instruction buffer.
    pub fn with_capacity(words: usize) -> Self {
        Self {
            words: Vec::with_capacity(words),
        }
    }
    /// Returns the current instruction count.
    pub fn len(&self) -> usize {
        self.words.len()
    }
    /// Returns whether no instruction has been emitted.
    pub fn is_empty(&self) -> bool {
        self.words.is_empty()
    }
    /// Emits raw instruction bits (useful for explicitly specified directives).
    pub fn word(&mut self, word: u32) {
        self.words.push(word);
    }

    fn reg(reg: Gpr, width: Width, allow_sp: bool, allow_zr: bool) -> Result<u32, EncodeError> {
        if reg.number > 31
            || reg.width != width
            || (reg.kind == GprKind::Sp && !allow_sp)
            || (reg.kind == GprKind::Zr && !allow_zr)
            || (reg.number == 31 && reg.kind == GprKind::General)
            || (reg.number < 31 && reg.kind != GprKind::General)
        {
            return Err(EncodeError::InvalidRegister(reg));
        }
        Ok(reg.number as u32)
    }
    fn same(a: Gpr, b: Gpr) -> Result<Width, EncodeError> {
        if a.width == b.width {
            Ok(a.width)
        } else {
            Err(EncodeError::WidthMismatch)
        }
    }
    fn checked_signed(value: i64, bits: u8) -> Result<u32, EncodeError> {
        let min = -(1i64 << (bits - 1));
        let max = (1i64 << (bits - 1)) - 1;
        if value < min || value > max {
            return Err(EncodeError::ImmediateOutOfRange { value, min, max });
        }
        Ok((value as u32) & ((1u32 << bits) - 1))
    }
    fn checked_unsigned(value: u64, bits: u8) -> Result<u32, EncodeError> {
        if value >= (1u64 << bits) {
            return Err(EncodeError::ImmediateOutOfRange {
                value: value as i64,
                min: 0,
                max: ((1i64 << bits) - 1),
            });
        }
        Ok(value as u32)
    }
    fn emit(&mut self, word: u32) {
        self.words.push(word);
    }
    fn add_sub_imm(
        &mut self,
        rd: Gpr,
        rn: Gpr,
        imm: u16,
        shift12: bool,
        op: u32,
        flags: bool,
    ) -> Result<(), EncodeError> {
        let width = Self::same(rd, rn)?;
        let d = Self::reg(rd, width, !flags, flags)?;
        let n = Self::reg(rn, width, true, false)?;
        let imm = Self::checked_unsigned(imm as u64, 12)?;
        let sf = if width == Width::X64 { 1 << 31 } else { 0 };
        self.emit(
            sf | 0x1100_0000
                | (op << 30)
                | ((flags as u32) << 29)
                | (n << 5)
                | (d)
                | (imm << 10)
                | ((shift12 as u32) << 22),
        );
        Ok(())
    }
    #[allow(clippy::too_many_arguments)]
    fn add_sub_reg(
        &mut self,
        rd: Gpr,
        rn: Gpr,
        rm: Gpr,
        op: u32,
        flags: bool,
        shift: Shift,
        amount: u8,
    ) -> Result<(), EncodeError> {
        let width = Self::same(rd, rn)?;
        if rm.width != width {
            return Err(EncodeError::WidthMismatch);
        }
        let d = Self::reg(rd, width, false, true)?;
        let n = Self::reg(rn, width, false, true)?;
        let m = Self::reg(rm, width, false, true)?;
        let max = if width == Width::X64 { 63 } else { 31 };
        if amount > max {
            return Err(EncodeError::InvalidShift(amount));
        }
        let sf = if width == Width::X64 { 1 << 31 } else { 0 };
        self.emit(
            sf | 0x0b00_0000
                | (op << 30)
                | ((flags as u32) << 29)
                | (m << 16)
                | ((shift as u32) << 22)
                | ((amount as u32) << 10)
                | (n << 5)
                | d,
        );
        Ok(())
    }
    /// ADD immediate (12-bit, optionally shifted by 12).
    // Port of erts/emulator/beam/jit/arm/beam_asm.hpp:296, OTP-29.1.1.
    pub fn add_imm(
        &mut self,
        rd: Gpr,
        rn: Gpr,
        imm: u16,
        shift12: bool,
    ) -> Result<(), EncodeError> {
        self.add_sub_imm(rd, rn, imm, shift12, 0, false)
    }
    /// ADDS immediate.
    pub fn adds_imm(
        &mut self,
        rd: Gpr,
        rn: Gpr,
        imm: u16,
        shift12: bool,
    ) -> Result<(), EncodeError> {
        self.add_sub_imm(rd, rn, imm, shift12, 0, true)
    }
    /// SUB immediate.
    pub fn sub_imm(
        &mut self,
        rd: Gpr,
        rn: Gpr,
        imm: u16,
        shift12: bool,
    ) -> Result<(), EncodeError> {
        self.add_sub_imm(rd, rn, imm, shift12, 1, false)
    }
    /// SUBS immediate.
    pub fn subs_imm(
        &mut self,
        rd: Gpr,
        rn: Gpr,
        imm: u16,
        shift12: bool,
    ) -> Result<(), EncodeError> {
        self.add_sub_imm(rd, rn, imm, shift12, 1, true)
    }
    /// ADD shifted register.
    pub fn add_reg(
        &mut self,
        rd: Gpr,
        rn: Gpr,
        rm: Gpr,
        shift: Shift,
        amount: u8,
    ) -> Result<(), EncodeError> {
        self.add_sub_reg(rd, rn, rm, 0, false, shift, amount)
    }
    /// ADDS shifted register.
    pub fn adds_reg(
        &mut self,
        rd: Gpr,
        rn: Gpr,
        rm: Gpr,
        shift: Shift,
        amount: u8,
    ) -> Result<(), EncodeError> {
        self.add_sub_reg(rd, rn, rm, 0, true, shift, amount)
    }
    /// SUB shifted register.
    pub fn sub_reg(
        &mut self,
        rd: Gpr,
        rn: Gpr,
        rm: Gpr,
        shift: Shift,
        amount: u8,
    ) -> Result<(), EncodeError> {
        self.add_sub_reg(rd, rn, rm, 1, false, shift, amount)
    }
    /// SUBS shifted register.
    pub fn subs_reg(
        &mut self,
        rd: Gpr,
        rn: Gpr,
        rm: Gpr,
        shift: Shift,
        amount: u8,
    ) -> Result<(), EncodeError> {
        self.add_sub_reg(rd, rn, rm, 1, true, shift, amount)
    }
    /// ADD extended register operand.
    pub fn add_ext(&mut self, rd: Gpr, rn: Gpr, op: Extended) -> Result<(), EncodeError> {
        self.add_sub_ext(rd, rn, op, 0, false)
    }
    /// SUB extended register operand.
    pub fn sub_ext(&mut self, rd: Gpr, rn: Gpr, op: Extended) -> Result<(), EncodeError> {
        self.add_sub_ext(rd, rn, op, 1, false)
    }
    /// CMP extended register operand (`SUBS XZR, Rn, Rm{, extend}`).
    pub fn cmp_ext(&mut self, rn: Gpr, op: Extended) -> Result<(), EncodeError> {
        let width = rn.width;
        if op.reg.width != Width::W32 && op.reg.width != Width::X64 {
            return Err(EncodeError::WidthMismatch);
        }
        let n = Self::reg(rn, width, true, false)?;
        let m = Self::reg(op.reg, op.reg.width, false, true)?;
        if op.amount > 4 {
            return Err(EncodeError::InvalidShift(op.amount));
        }
        let sf = if width == Width::X64 { 1 << 31 } else { 0 };
        self.emit(
            sf | 0x6b20_0000
                | (m << 16)
                | ((op.extend as u32) << 13)
                | ((op.amount as u32) << 10)
                | (n << 5)
                | 31,
        );
        Ok(())
    }
    fn add_sub_ext(
        &mut self,
        rd: Gpr,
        rn: Gpr,
        op: Extended,
        opc: u32,
        flags: bool,
    ) -> Result<(), EncodeError> {
        let width = Self::same(rd, rn)?;
        if op.reg.width != Width::W32 && op.reg.width != Width::X64 {
            return Err(EncodeError::WidthMismatch);
        }
        let d = Self::reg(rd, width, true, false)?;
        let n = Self::reg(rn, width, true, false)?;
        let m = Self::reg(op.reg, op.reg.width, false, true)?;
        if op.amount > 4 {
            return Err(EncodeError::InvalidShift(op.amount));
        }
        let sf = if width == Width::X64 { 1 << 31 } else { 0 };
        self.emit(
            sf | 0x0b20_0000
                | (opc << 30)
                | ((flags as u32) << 29)
                | (m << 16)
                | ((op.extend as u32) << 13)
                | ((op.amount as u32) << 10)
                | (n << 5)
                | d,
        );
        Ok(())
    }
    /// ADC register.
    pub fn adc(&mut self, rd: Gpr, rn: Gpr, rm: Gpr) -> Result<(), EncodeError> {
        self.carry(rd, rn, rm, 0)
    }
    /// SBC register.
    pub fn sbc(&mut self, rd: Gpr, rn: Gpr, rm: Gpr) -> Result<(), EncodeError> {
        self.carry(rd, rn, rm, 1)
    }
    fn carry(&mut self, rd: Gpr, rn: Gpr, rm: Gpr, opc: u32) -> Result<(), EncodeError> {
        let w = Self::same(rd, rn)?;
        if rm.width != w {
            return Err(EncodeError::WidthMismatch);
        }
        let (d, n, m) = (
            Self::reg(rd, w, false, true)?,
            Self::reg(rn, w, false, true)?,
            Self::reg(rm, w, false, true)?,
        );
        let sf = if w == Width::X64 { 1 << 31 } else { 0 };
        self.emit(sf | 0x1a00_0000 | (opc << 30) | (m << 16) | (n << 5) | d);
        Ok(())
    }

    /// AND logical immediate; `is_logical_immediate` can preflight the value.
    pub fn and_imm(&mut self, rd: Gpr, rn: Gpr, value: u64) -> Result<(), EncodeError> {
        self.logical_imm(rd, rn, value, 0)
    }
    /// ORR logical immediate.
    pub fn orr_imm(&mut self, rd: Gpr, rn: Gpr, value: u64) -> Result<(), EncodeError> {
        self.logical_imm(rd, rn, value, 1)
    }
    /// EOR logical immediate.
    pub fn eor_imm(&mut self, rd: Gpr, rn: Gpr, value: u64) -> Result<(), EncodeError> {
        self.logical_imm(rd, rn, value, 2)
    }
    /// ANDS logical immediate.
    pub fn ands_imm(&mut self, rd: Gpr, rn: Gpr, value: u64) -> Result<(), EncodeError> {
        self.logical_imm(rd, rn, value, 3)
    }
    fn logical_imm(&mut self, rd: Gpr, rn: Gpr, value: u64, opc: u32) -> Result<(), EncodeError> {
        let w = Self::same(rd, rn)?;
        let bits = if w == Width::X64 { 64u8 } else { 32u8 };
        let (d, n) = (
            Self::reg(rd, w, false, true)?,
            Self::reg(rn, w, false, true)?,
        );
        let (nbit, immr, imms) = encode_logical_immediate(value, bits)
            .ok_or(EncodeError::UnencodableLogicalImmediate(value))?;
        let sf = if bits == 64 { 1 << 31 } else { 0 };
        self.emit(
            sf | 0x1200_0000
                | (opc << 29)
                | (nbit << 22)
                | (immr << 16)
                | (imms << 10)
                | (n << 5)
                | d,
        );
        Ok(())
    }
    /// AND shifted register.
    pub fn and_reg(&mut self, rd: Gpr, rn: Gpr, op: Shifted) -> Result<(), EncodeError> {
        self.logical_reg(rd, rn, op, 0, false)
    }
    /// ANDS shifted register.
    pub fn ands_reg(&mut self, rd: Gpr, rn: Gpr, op: Shifted) -> Result<(), EncodeError> {
        self.logical_reg(rd, rn, op, 3, false)
    }
    /// ORR shifted register.
    pub fn orr_reg(&mut self, rd: Gpr, rn: Gpr, op: Shifted) -> Result<(), EncodeError> {
        self.logical_reg(rd, rn, op, 1, false)
    }
    /// EOR shifted register.
    pub fn eor_reg(&mut self, rd: Gpr, rn: Gpr, op: Shifted) -> Result<(), EncodeError> {
        self.logical_reg(rd, rn, op, 2, false)
    }
    /// BIC shifted register.
    pub fn bic_reg(&mut self, rd: Gpr, rn: Gpr, op: Shifted) -> Result<(), EncodeError> {
        self.logical_reg(rd, rn, op, 0, true)
    }
    fn logical_reg(
        &mut self,
        rd: Gpr,
        rn: Gpr,
        op: Shifted,
        opc: u32,
        invert: bool,
    ) -> Result<(), EncodeError> {
        let w = Self::same(rd, rn)?;
        if op.reg.width != w {
            return Err(EncodeError::WidthMismatch);
        }
        let (d, n, m) = (
            Self::reg(rd, w, false, true)?,
            Self::reg(rn, w, false, true)?,
            Self::reg(op.reg, w, false, true)?,
        );
        let max = if w == Width::X64 { 63 } else { 31 };
        if op.amount > max {
            return Err(EncodeError::InvalidShift(op.amount));
        }
        let sf = if w == Width::X64 { 1 << 31 } else { 0 };
        self.emit(
            sf | 0x0a00_0000
                | (opc << 29)
                | ((invert as u32) << 21)
                | (m << 16)
                | ((op.shift as u32) << 22)
                | ((op.amount as u32) << 10)
                | (n << 5)
                | d,
        );
        Ok(())
    }

    /// CMP immediate (SUBS to zero register).
    pub fn cmp_imm(&mut self, rn: Gpr, imm: u16, shift12: bool) -> Result<(), EncodeError> {
        let zr = if rn.width == Width::X64 {
            Gpr::xzr()
        } else {
            Gpr::wzr()
        };
        self.subs_imm(zr, rn, imm, shift12)
    }
    /// CMP shifted register.
    pub fn cmp_reg(
        &mut self,
        rn: Gpr,
        rm: Gpr,
        shift: Shift,
        amount: u8,
    ) -> Result<(), EncodeError> {
        let zr = if rn.width == Width::X64 {
            Gpr::xzr()
        } else {
            Gpr::wzr()
        };
        self.subs_reg(zr, rn, rm, shift, amount)
    }
    /// CMN immediate.
    pub fn cmn_imm(&mut self, rn: Gpr, imm: u16, shift12: bool) -> Result<(), EncodeError> {
        let zr = if rn.width == Width::X64 {
            Gpr::xzr()
        } else {
            Gpr::wzr()
        };
        self.adds_imm(zr, rn, imm, shift12)
    }
    /// CMN shifted register.
    pub fn cmn_reg(
        &mut self,
        rn: Gpr,
        rm: Gpr,
        shift: Shift,
        amount: u8,
    ) -> Result<(), EncodeError> {
        let zr = if rn.width == Width::X64 {
            Gpr::xzr()
        } else {
            Gpr::wzr()
        };
        self.adds_reg(zr, rn, rm, shift, amount)
    }
    /// TST logical immediate.
    pub fn tst_imm(&mut self, rn: Gpr, value: u64) -> Result<(), EncodeError> {
        let zr = if rn.width == Width::X64 {
            Gpr::xzr()
        } else {
            Gpr::wzr()
        };
        self.ands_imm(zr, rn, value)
    }
    /// TST shifted register.
    pub fn tst_reg(
        &mut self,
        rn: Gpr,
        rm: Gpr,
        shift: Shift,
        amount: u8,
    ) -> Result<(), EncodeError> {
        let zr = if rn.width == Width::X64 {
            Gpr::xzr()
        } else {
            Gpr::wzr()
        };
        self.ands_reg(
            zr,
            rn,
            Shifted {
                reg: rm,
                shift,
                amount,
            },
        )
    }
    /// CCMP register with NZCV fallback.
    pub fn ccmp_reg(&mut self, rn: Gpr, rm: Gpr, nzcv: u8, cond: Cond) -> Result<(), EncodeError> {
        self.conditional_compare(rn, rm, nzcv, cond, 0)
    }
    /// CCMN register with NZCV fallback.
    pub fn ccmn_reg(&mut self, rn: Gpr, rm: Gpr, nzcv: u8, cond: Cond) -> Result<(), EncodeError> {
        self.conditional_compare(rn, rm, nzcv, cond, 1)
    }
    /// CCMP immediate.
    pub fn ccmp_imm(&mut self, rn: Gpr, imm: u8, nzcv: u8, cond: Cond) -> Result<(), EncodeError> {
        self.conditional_compare_imm(rn, imm, nzcv, cond, 0)
    }
    /// CCMN immediate.
    pub fn ccmn_imm(&mut self, rn: Gpr, imm: u8, nzcv: u8, cond: Cond) -> Result<(), EncodeError> {
        self.conditional_compare_imm(rn, imm, nzcv, cond, 1)
    }
    fn conditional_compare_imm(
        &mut self,
        rn: Gpr,
        imm: u8,
        nzcv: u8,
        cond: Cond,
        op: u32,
    ) -> Result<(), EncodeError> {
        if imm > 31 || nzcv > 15 {
            return Err(EncodeError::ImmediateOutOfRange {
                value: imm.max(nzcv) as i64,
                min: 0,
                max: 31,
            });
        }
        let n = Self::reg(rn, rn.width, false, true)?;
        let sf = if rn.width == Width::X64 { 1 << 31 } else { 0 };
        self.emit(
            sf | 0x3a40_0800
                | ((1 - op) << 30)
                | ((imm as u32) << 16)
                | ((cond as u32) << 12)
                | (n << 5)
                | nzcv as u32,
        );
        Ok(())
    }
    fn conditional_compare(
        &mut self,
        rn: Gpr,
        rm: Gpr,
        nzcv: u8,
        cond: Cond,
        op: u32,
    ) -> Result<(), EncodeError> {
        let w = Self::same(rn, rm)?;
        if nzcv > 15 {
            return Err(EncodeError::ImmediateOutOfRange {
                value: nzcv as i64,
                min: 0,
                max: 15,
            });
        }
        let (n, m) = (
            Self::reg(rn, w, false, true)?,
            Self::reg(rm, w, false, true)?,
        );
        let sf = if w == Width::X64 { 1 << 31 } else { 0 };
        self.emit(
            sf | 0x3a40_0000
                | ((1 - op) << 30)
                | (m << 16)
                | ((cond as u32) << 12)
                | (n << 5)
                | nzcv as u32,
        );
        Ok(())
    }

    /// MOV register alias (ORR with zero register).
    pub fn mov_reg(&mut self, rd: Gpr, rm: Gpr) -> Result<(), EncodeError> {
        let w = Self::same(rd, rm)?;
        if rd.kind == GprKind::Sp || rm.kind == GprKind::Sp {
            return self.add_imm(rd, rm, 0, false);
        }
        let zr = if w == Width::X64 {
            Gpr::xzr()
        } else {
            Gpr::wzr()
        };
        self.orr_reg(
            rd,
            zr,
            Shifted {
                reg: rm,
                shift: Shift::Lsl,
                amount: 0,
            },
        )
    }
    /// Emits an arbitrary constant using the shortest MOVZ/MOVN plus MOVK sequence.
    pub fn mov_const(&mut self, rd: Gpr, value: u64) -> Result<(), EncodeError> {
        let w = rd.width;
        let d = Self::reg(rd, w, false, true)?;
        let halfs = if w == Width::X64 { 4 } else { 2 };
        let value = if w == Width::W32 {
            value & 0xffff_ffff
        } else {
            value
        };
        // A 33 to 48 bit constant, which is what a code or data address is, always takes three
        // instructions: how many halfwords of an address are zero changes from run to run, and
        // the layout of a module must not (BeamAsm loads such addresses with a fixed sequence).
        if w == Width::X64 && value >> 32 != 0 && value >> 48 == 0 {
            self.emit(0xd280_0000 | (((value & 0xffff) as u32) << 5) | d);
            self.emit(0xf280_0000 | (1 << 21) | ((((value >> 16) & 0xffff) as u32) << 5) | d);
            self.emit(0xf280_0000 | (2 << 21) | ((((value >> 32) & 0xffff) as u32) << 5) | d);
            return Ok(());
        }
        let chunks: Vec<u16> = (0..halfs)
            .map(|i| ((value >> (i * 16)) & 0xffff) as u16)
            .collect();
        let zeros = chunks.iter().filter(|&&v| v == 0).count();
        let ones = chunks.iter().filter(|&&v| v == 0xffff).count();
        let use_n = ones > zeros;
        let seed = if use_n {
            chunks.iter().position(|&v| v != 0xffff)
        } else {
            chunks.iter().position(|&v| v != 0)
        };
        let sf = if w == Width::X64 { 1 << 31 } else { 0 };
        let opc = if use_n { 0x1280_0000 } else { 0x5280_0000 };
        if let Some(seed) = seed {
            let imm = if use_n { !chunks[seed] } else { chunks[seed] };
            self.emit(sf | opc | ((seed as u32) << 21) | ((imm as u32) << 5) | d);
            for (i, &v) in chunks.iter().enumerate() {
                if i != seed && (if use_n { v != 0xffff } else { v != 0 }) {
                    self.emit(sf | 0x7280_0000 | ((i as u32) << 21) | ((v as u32) << 5) | d)
                }
            }
        } else if use_n {
            self.emit(sf | 0x1280_0000 | d);
        } else {
            self.emit(sf | 0x5280_0000 | d);
        }
        Ok(())
    }
    /// MOVZ wide immediate.
    pub fn movz(&mut self, rd: Gpr, imm: u16, shift: u8) -> Result<(), EncodeError> {
        self.move_wide(rd, imm, shift, 2)
    }
    /// MOVN wide immediate.
    pub fn movn(&mut self, rd: Gpr, imm: u16, shift: u8) -> Result<(), EncodeError> {
        self.move_wide(rd, imm, shift, 0)
    }
    /// MOVK wide immediate.
    pub fn movk(&mut self, rd: Gpr, imm: u16, shift: u8) -> Result<(), EncodeError> {
        self.move_wide(rd, imm, shift, 3)
    }
    fn move_wide(&mut self, rd: Gpr, imm: u16, shift: u8, opc: u32) -> Result<(), EncodeError> {
        let max = if rd.width == Width::X64 { 48 } else { 16 };
        if shift > max || !shift.is_multiple_of(16) {
            return Err(EncodeError::InvalidShift(shift));
        }
        let d = Self::reg(rd, rd.width, false, true)?;
        let sf = if rd.width == Width::X64 { 1 << 31 } else { 0 };
        self.emit(
            sf | 0x1280_0000
                | (opc << 29)
                | (((shift / 16) as u32) << 21)
                | ((imm as u32) << 5)
                | d,
        );
        Ok(())
    }

    /// LSL immediate alias.
    pub fn lsl_imm(&mut self, rd: Gpr, rn: Gpr, amount: u8) -> Result<(), EncodeError> {
        self.bitfield_shift(rd, rn, amount, 0)
    }
    /// LSR immediate alias.
    pub fn lsr_imm(&mut self, rd: Gpr, rn: Gpr, amount: u8) -> Result<(), EncodeError> {
        self.bitfield_shift(rd, rn, amount, 1)
    }
    /// ASR immediate alias.
    pub fn asr_imm(&mut self, rd: Gpr, rn: Gpr, amount: u8) -> Result<(), EncodeError> {
        self.bitfield_shift(rd, rn, amount, 2)
    }
    /// ROR immediate alias.
    pub fn ror_imm(&mut self, rd: Gpr, rn: Gpr, amount: u8) -> Result<(), EncodeError> {
        self.extr(rd, rn, rn, amount)
    }
    /// LSL by a register.
    pub fn lsl_reg(&mut self, rd: Gpr, rn: Gpr, rm: Gpr) -> Result<(), EncodeError> {
        self.variable_shift(rd, rn, rm, 0)
    }
    /// LSR by a register.
    pub fn lsr_reg(&mut self, rd: Gpr, rn: Gpr, rm: Gpr) -> Result<(), EncodeError> {
        self.variable_shift(rd, rn, rm, 1)
    }
    /// ASR by a register.
    pub fn asr_reg(&mut self, rd: Gpr, rn: Gpr, rm: Gpr) -> Result<(), EncodeError> {
        self.variable_shift(rd, rn, rm, 2)
    }
    /// ROR by a register.
    pub fn ror_reg(&mut self, rd: Gpr, rn: Gpr, rm: Gpr) -> Result<(), EncodeError> {
        self.variable_shift(rd, rn, rm, 3)
    }
    fn variable_shift(&mut self, rd: Gpr, rn: Gpr, rm: Gpr, kind: u32) -> Result<(), EncodeError> {
        let w = Self::same(rd, rn)?;
        if rm.width != w {
            return Err(EncodeError::WidthMismatch);
        }
        let (d, n, m) = (
            Self::reg(rd, w, false, true)?,
            Self::reg(rn, w, false, true)?,
            Self::reg(rm, w, false, true)?,
        );
        let sf = if w == Width::X64 { 1 << 31 } else { 0 };
        self.emit(sf | 0x1ac0_2000 | (kind << 10) | (m << 16) | (n << 5) | d);
        Ok(())
    }
    fn bitfield_shift(
        &mut self,
        rd: Gpr,
        rn: Gpr,
        amount: u8,
        kind: u32,
    ) -> Result<(), EncodeError> {
        let w = Self::same(rd, rn)?;
        let bits = if w == Width::X64 { 64u32 } else { 32u32 };
        if amount as u32 >= bits {
            return Err(EncodeError::InvalidShift(amount));
        }
        let (d, n) = (
            Self::reg(rd, w, false, true)?,
            Self::reg(rn, w, false, true)?,
        );
        let sf = if bits == 64 { 1 << 31 } else { 0 };
        let immr = if kind == 0 {
            (bits - amount as u32) % bits
        } else {
            amount as u32
        };
        let imms = if kind == 0 {
            bits - 1 - amount as u32
        } else {
            bits - 1
        };
        let opc = if kind == 2 { 0x1300_0000 } else { 0x5300_0000 };
        let n_bit = if bits == 64 { 1 << 22 } else { 0 };
        self.emit(sf | opc | n_bit | ((immr & 63) << 16) | ((imms & 63) << 10) | (n << 5) | d);
        Ok(())
    }
    /// EXTR, used for rotate-right aliases.
    pub fn extr(&mut self, rd: Gpr, rn: Gpr, rm: Gpr, lsb: u8) -> Result<(), EncodeError> {
        let w = Self::same(rd, rn)?;
        if rm.width != w {
            return Err(EncodeError::WidthMismatch);
        }
        let bits = if w == Width::X64 { 64 } else { 32 };
        if lsb >= bits {
            return Err(EncodeError::InvalidShift(lsb));
        }
        let (d, n, m) = (
            Self::reg(rd, w, false, true)?,
            Self::reg(rn, w, false, true)?,
            Self::reg(rm, w, false, true)?,
        );
        let sf = if bits == 64 { 1 << 31 } else { 0 };
        let n_bit = if bits == 64 { 1 << 22 } else { 0 };
        self.emit(sf | 0x1380_0000 | n_bit | (m << 16) | ((lsb as u32) << 10) | (n << 5) | d);
        Ok(())
    }
    /// BFI bitfield insert.
    pub fn bfi(&mut self, rd: Gpr, rn: Gpr, lsb: u8, width: u8) -> Result<(), EncodeError> {
        self.bitfield(rd, rn, lsb, width, 1)
    }
    /// BFXIL bitfield extract/insertion alias.
    pub fn bfxil(&mut self, rd: Gpr, rn: Gpr, lsb: u8, width: u8) -> Result<(), EncodeError> {
        self.bitfield(rd, rn, lsb, width, 0)
    }
    /// UBFX unsigned bitfield extract.
    pub fn ubfx(&mut self, rd: Gpr, rn: Gpr, lsb: u8, width: u8) -> Result<(), EncodeError> {
        self.bitfield(rd, rn, lsb, width, 2)
    }
    /// SBFX signed bitfield extract.
    pub fn sbfx(&mut self, rd: Gpr, rn: Gpr, lsb: u8, width: u8) -> Result<(), EncodeError> {
        self.bitfield(rd, rn, lsb, width, 3)
    }
    /// UBFIZ unsigned bitfield insert in zero.
    pub fn ubfiz(&mut self, rd: Gpr, rn: Gpr, lsb: u8, width: u8) -> Result<(), EncodeError> {
        self.bitfield(rd, rn, lsb, width, 4)
    }
    fn bitfield(
        &mut self,
        rd: Gpr,
        rn: Gpr,
        lsb: u8,
        width: u8,
        kind: u32,
    ) -> Result<(), EncodeError> {
        let w = Self::same(rd, rn)?;
        let bits = if w == Width::X64 { 64 } else { 32 };
        if width == 0 || lsb as u32 + width as u32 > bits {
            return Err(EncodeError::InvalidShift(lsb));
        }
        let (d, n) = (
            Self::reg(rd, w, false, true)?,
            Self::reg(rn, w, false, true)?,
        );
        let (immr, imms) = if kind == 0 {
            (lsb as u32, (lsb as u32 + width as u32 - 1) & (bits - 1))
        } else if kind == 1 {
            (
                (bits - lsb as u32) & (bits - 1),
                (width as u32 - 1) & (bits - 1),
            )
        } else if kind == 4 {
            ((bits - lsb as u32) & (bits - 1), width as u32 - 1)
        } else {
            (lsb as u32, (lsb as u32 + width as u32 - 1) & (bits - 1))
        };
        let base = match kind {
            1 => 0x3300_0000,
            3 => 0x1300_0000,
            _ => 0x5300_0000,
        };
        let sf = if bits == 64 { 1 << 31 } else { 0 };
        let n_bit = if bits == 64 { 1 << 22 } else { 0 };
        let base = if kind == 0 || kind == 1 {
            0x3300_0000
        } else {
            base
        };
        self.emit(sf | base | n_bit | ((immr & 63) << 16) | ((imms & 63) << 10) | (n << 5) | d);
        Ok(())
    }

    /// MUL alias (MADD with zero addend).
    pub fn mul(&mut self, rd: Gpr, rn: Gpr, rm: Gpr) -> Result<(), EncodeError> {
        self.madd(
            rd,
            rn,
            rm,
            if rd.width == Width::X64 {
                Gpr::xzr()
            } else {
                Gpr::wzr()
            },
            false,
        )
    }
    /// MADD.
    pub fn madd(
        &mut self,
        rd: Gpr,
        rn: Gpr,
        rm: Gpr,
        ra: Gpr,
        subtract: bool,
    ) -> Result<(), EncodeError> {
        let w = Self::same(rd, rn)?;
        if rm.width != w || ra.width != w {
            return Err(EncodeError::WidthMismatch);
        }
        let (d, n, m, a) = (
            Self::reg(rd, w, false, true)?,
            Self::reg(rn, w, false, true)?,
            Self::reg(rm, w, false, true)?,
            Self::reg(ra, w, false, true)?,
        );
        let sf = if w == Width::X64 { 1 << 31 } else { 0 };
        self.emit(
            sf | 0x1b00_0000 | (m << 16) | ((subtract as u32) << 15) | (a << 10) | (n << 5) | d,
        );
        Ok(())
    }
    /// MSUB.
    pub fn msub(&mut self, rd: Gpr, rn: Gpr, rm: Gpr, ra: Gpr) -> Result<(), EncodeError> {
        self.madd(rd, rn, rm, ra, true)
    }
    /// Signed high-half multiply.
    pub fn smulh(&mut self, rd: Gpr, rn: Gpr, rm: Gpr) -> Result<(), EncodeError> {
        self.mul_high(rd, rn, rm, true)
    }
    /// Unsigned high-half multiply.
    pub fn umulh(&mut self, rd: Gpr, rn: Gpr, rm: Gpr) -> Result<(), EncodeError> {
        self.mul_high(rd, rn, rm, false)
    }
    fn mul_high(&mut self, rd: Gpr, rn: Gpr, rm: Gpr, signed: bool) -> Result<(), EncodeError> {
        if rd.width != Width::X64 || rn.width != Width::X64 || rm.width != Width::X64 {
            return Err(EncodeError::WidthMismatch);
        }
        let (d, n, m) = (
            Self::reg(rd, Width::X64, false, true)?,
            Self::reg(rn, Width::X64, false, true)?,
            Self::reg(rm, Width::X64, false, true)?,
        );
        self.emit((if signed { 0x9b40_7c00 } else { 0x9bc0_7c00 }) | (m << 16) | (n << 5) | d);
        Ok(())
    }
    /// SDIV.
    pub fn sdiv(&mut self, rd: Gpr, rn: Gpr, rm: Gpr) -> Result<(), EncodeError> {
        self.divide(rd, rn, rm, true)
    }
    /// UDIV.
    pub fn udiv(&mut self, rd: Gpr, rn: Gpr, rm: Gpr) -> Result<(), EncodeError> {
        self.divide(rd, rn, rm, false)
    }
    fn divide(&mut self, rd: Gpr, rn: Gpr, rm: Gpr, signed: bool) -> Result<(), EncodeError> {
        let w = Self::same(rd, rn)?;
        if rm.width != w {
            return Err(EncodeError::WidthMismatch);
        }
        let (d, n, m) = (
            Self::reg(rd, w, false, true)?,
            Self::reg(rn, w, false, true)?,
            Self::reg(rm, w, false, true)?,
        );
        let sf = if w == Width::X64 { 1 << 31 } else { 0 };
        self.emit(sf | (if signed { 0x1ac0_0c00 } else { 0x1ac0_0800 }) | (m << 16) | (n << 5) | d);
        Ok(())
    }

    /// LDR unsigned scaled offset (byte offset is scaled by transfer width).
    pub fn ldr_uoff(&mut self, rt: Gpr, rn: Gpr, byte_off: u32) -> Result<(), EncodeError> {
        self.mem_uoff(rt, rn, byte_off, false)
    }
    /// STR unsigned scaled offset.
    pub fn str_uoff(&mut self, rt: Gpr, rn: Gpr, byte_off: u32) -> Result<(), EncodeError> {
        self.mem_uoff(rt, rn, byte_off, true)
    }
    fn mem_uoff(&mut self, rt: Gpr, rn: Gpr, off: u32, store: bool) -> Result<(), EncodeError> {
        let size = match rt.width {
            Width::W32 => 4,
            Width::X64 => 8,
        };
        if !off.is_multiple_of(size) {
            return Err(EncodeError::Misaligned {
                value: off as i64,
                alignment: size as u8,
            });
        }
        let imm = off / size;
        if imm > 4095 {
            return Err(EncodeError::ImmediateOutOfRange {
                value: off as i64,
                min: 0,
                max: (4095 * size) as i64,
            });
        }
        let t = Self::reg(rt, rt.width, false, true)?;
        let n = Self::reg(rn, Width::X64, true, false)?;
        let base = match (rt.width, store) {
            (Width::X64, false) => 0xf940_0000,
            (Width::X64, true) => 0xf900_0000,
            (Width::W32, false) => 0xb940_0000,
            (Width::W32, true) => 0xb900_0000,
        };
        self.emit(base | (imm << 10) | (n << 5) | t);
        Ok(())
    }
    /// LDUR signed unscaled offset.
    pub fn ldur(&mut self, rt: Gpr, rn: Gpr, byte_off: i16) -> Result<(), EncodeError> {
        self.mem_unscaled(rt, rn, byte_off, false)
    }
    /// STUR signed unscaled offset.
    pub fn stur(&mut self, rt: Gpr, rn: Gpr, byte_off: i16) -> Result<(), EncodeError> {
        self.mem_unscaled(rt, rn, byte_off, true)
    }
    fn mem_unscaled(&mut self, rt: Gpr, rn: Gpr, off: i16, store: bool) -> Result<(), EncodeError> {
        if !(-256..=255).contains(&off) {
            return Err(EncodeError::ImmediateOutOfRange {
                value: off as i64,
                min: -256,
                max: 255,
            });
        }
        let t = Self::reg(rt, rt.width, false, true)?;
        let n = Self::reg(rn, Width::X64, true, false)?;
        let base = match (rt.width, store) {
            (Width::X64, false) => 0xf840_0000,
            (Width::X64, true) => 0xf800_0000,
            (Width::W32, false) => 0xb840_0000,
            (Width::W32, true) => 0xb800_0000,
        };
        self.emit(base | (((off as u16 as u32) & 0x1ff) << 12) | (n << 5) | t);
        Ok(())
    }
    /// LDR pre-index.
    pub fn ldr_pre(&mut self, rt: Gpr, rn: Gpr, off: i16) -> Result<(), EncodeError> {
        self.mem_index(rt, rn, off, false, true)
    }
    /// STR pre-index.
    pub fn str_pre(&mut self, rt: Gpr, rn: Gpr, off: i16) -> Result<(), EncodeError> {
        self.mem_index(rt, rn, off, true, true)
    }
    /// LDR post-index.
    pub fn ldr_post(&mut self, rt: Gpr, rn: Gpr, off: i16) -> Result<(), EncodeError> {
        self.mem_index(rt, rn, off, false, false)
    }
    /// STR post-index.
    pub fn str_post(&mut self, rt: Gpr, rn: Gpr, off: i16) -> Result<(), EncodeError> {
        self.mem_index(rt, rn, off, true, false)
    }
    fn mem_index(
        &mut self,
        rt: Gpr,
        rn: Gpr,
        off: i16,
        store: bool,
        pre: bool,
    ) -> Result<(), EncodeError> {
        if !(-256..=255).contains(&off) {
            return Err(EncodeError::ImmediateOutOfRange {
                value: off as i64,
                min: -256,
                max: 255,
            });
        }
        let t = Self::reg(rt, rt.width, false, true)?;
        let n = Self::reg(rn, Width::X64, true, false)?;
        let base = match (rt.width, store) {
            (Width::X64, false) => 0xf840_0400,
            (Width::X64, true) => 0xf800_0400,
            (Width::W32, false) => 0xb840_0400,
            (Width::W32, true) => 0xb800_0400,
        };
        self.emit(
            base | (((off as u16 as u32) & 0x1ff) << 12) | ((pre as u32) << 11) | (n << 5) | t,
        );
        Ok(())
    }
    /// LDP signed scaled offset.
    pub fn ldp(&mut self, rt: Gpr, rt2: Gpr, rn: Gpr, byte_off: i16) -> Result<(), EncodeError> {
        self.pair(rt, rt2, rn, byte_off, 0)
    }
    /// STP signed scaled offset.
    pub fn stp(&mut self, rt: Gpr, rt2: Gpr, rn: Gpr, byte_off: i16) -> Result<(), EncodeError> {
        self.pair(rt, rt2, rn, byte_off, 1)
    }
    /// LDP pre-index.
    pub fn ldp_pre(
        &mut self,
        rt: Gpr,
        rt2: Gpr,
        rn: Gpr,
        byte_off: i16,
    ) -> Result<(), EncodeError> {
        self.pair(rt, rt2, rn, byte_off, 2)
    }
    /// STP pre-index.
    pub fn stp_pre(
        &mut self,
        rt: Gpr,
        rt2: Gpr,
        rn: Gpr,
        byte_off: i16,
    ) -> Result<(), EncodeError> {
        self.pair(rt, rt2, rn, byte_off, 3)
    }
    /// LDP post-index.
    pub fn ldp_post(
        &mut self,
        rt: Gpr,
        rt2: Gpr,
        rn: Gpr,
        byte_off: i16,
    ) -> Result<(), EncodeError> {
        self.pair(rt, rt2, rn, byte_off, 4)
    }
    /// STP post-index.
    pub fn stp_post(
        &mut self,
        rt: Gpr,
        rt2: Gpr,
        rn: Gpr,
        byte_off: i16,
    ) -> Result<(), EncodeError> {
        self.pair(rt, rt2, rn, byte_off, 5)
    }
    fn pair(&mut self, rt: Gpr, rt2: Gpr, rn: Gpr, off: i16, kind: u8) -> Result<(), EncodeError> {
        let w = Self::same(rt, rt2)?;
        if !(-64..=63).contains(&((off as i32) / (if w == Width::X64 { 8 } else { 4 })))
            || off % (if w == Width::X64 { 8 } else { 4 }) != 0
        {
            return Err(EncodeError::ImmediateOutOfRange {
                value: off as i64,
                min: -512,
                max: 504,
            });
        }
        let (t, t2, n) = (
            Self::reg(rt, w, false, true)?,
            Self::reg(rt2, w, false, true)?,
            Self::reg(rn, Width::X64, true, false)?,
        );
        let imm = ((off / (if w == Width::X64 { 8 } else { 4 })) as u32) & 0x7f;
        let base = if w == Width::X64 {
            0xa800_0000
        } else {
            0x2800_0000
        };
        let mode = match kind {
            0 | 1 => 2,
            2 | 3 => 3,
            4 | 5 => 1,
            _ => 0,
        };
        let load = ((kind & 1) == 0) as u32;
        self.emit(base | (mode << 23) | (load << 22) | (imm << 15) | (t2 << 10) | (n << 5) | t);
        Ok(())
    }
    /// Register-offset LDR with optional LSL scale (shift 0, 2, or 3).
    pub fn ldr_regoff(&mut self, rt: Gpr, rn: Gpr, rm: Gpr, shift: u8) -> Result<(), EncodeError> {
        self.mem_regoff(rt, rn, rm, shift, false)
    }
    /// Register-offset STR with optional LSL scale (shift 0, 2, or 3).
    pub fn str_regoff(&mut self, rt: Gpr, rn: Gpr, rm: Gpr, shift: u8) -> Result<(), EncodeError> {
        self.mem_regoff(rt, rn, rm, shift, true)
    }
    fn mem_regoff(
        &mut self,
        rt: Gpr,
        rn: Gpr,
        rm: Gpr,
        shift: u8,
        store: bool,
    ) -> Result<(), EncodeError> {
        if rm.width != Width::X64 {
            return Err(EncodeError::WidthMismatch);
        }
        let size = if rt.width == Width::X64 { 3 } else { 2 };
        if shift != 0 && shift != size {
            return Err(EncodeError::InvalidShift(shift));
        }
        let (t, n, m) = (
            Self::reg(rt, rt.width, false, true)?,
            Self::reg(rn, Width::X64, true, false)?,
            Self::reg(rm, Width::X64, false, true)?,
        );
        let base = if rt.width == Width::X64 {
            0xf860_0800
        } else {
            0xb860_0800
        };
        self.emit(
            base | (3 << 13)
                | ((store as u32) << 22)
                | (m << 16)
                | (((shift != 0) as u32) << 12)
                | (n << 5)
                | t,
        );
        Ok(())
    }

    /// B immediate, displacement in words from current instruction.
    pub fn b(&mut self, words: i32) -> Result<(), EncodeError> {
        self.branch(words, 0x1400_0000, 26)
    }
    /// BL immediate.
    pub fn bl(&mut self, words: i32) -> Result<(), EncodeError> {
        self.branch(words, 0x9400_0000, 26)
    }
    fn branch(&mut self, words: i32, base: u32, bits: u8) -> Result<(), EncodeError> {
        let imm = Self::checked_signed(words as i64, bits)?;
        self.emit(base | imm);
        Ok(())
    }
    /// Conditional branch immediate.
    pub fn b_cond(&mut self, cond: Cond, words: i32) -> Result<(), EncodeError> {
        let imm = Self::checked_signed(words as i64, 19)?;
        self.emit(0x5400_0000 | (imm << 5) | cond as u32);
        Ok(())
    }
    /// CBZ immediate.
    pub fn cbz(&mut self, rt: Gpr, words: i32) -> Result<(), EncodeError> {
        self.cb(rt, words, false)
    }
    /// CBNZ immediate.
    pub fn cbnz(&mut self, rt: Gpr, words: i32) -> Result<(), EncodeError> {
        self.cb(rt, words, true)
    }
    fn cb(&mut self, rt: Gpr, words: i32, nonzero: bool) -> Result<(), EncodeError> {
        let t = Self::reg(rt, rt.width, false, true)?;
        let imm = Self::checked_signed(words as i64, 19)?;
        let sf = if rt.width == Width::X64 { 1 << 31 } else { 0 };
        self.emit(sf | 0x3400_0000 | ((nonzero as u32) << 24) | (imm << 5) | t);
        Ok(())
    }
    /// TBZ immediate.
    pub fn tbz(&mut self, rt: Gpr, bit: u8, words: i32) -> Result<(), EncodeError> {
        self.tb(rt, bit, words, false)
    }
    /// TBNZ immediate.
    pub fn tbnz(&mut self, rt: Gpr, bit: u8, words: i32) -> Result<(), EncodeError> {
        self.tb(rt, bit, words, true)
    }
    fn tb(&mut self, rt: Gpr, bit: u8, words: i32, nonzero: bool) -> Result<(), EncodeError> {
        let max = if rt.width == Width::X64 { 63 } else { 31 };
        if bit > max {
            return Err(EncodeError::InvalidShift(bit));
        }
        let t = Self::reg(rt, rt.width, false, true)?;
        let imm = Self::checked_signed(words as i64, 14)?;
        self.emit(
            0x3600_0000
                | (((bit as u32 >> 5) & 1) << 31)
                | ((nonzero as u32) << 24)
                | ((bit as u32 & 31) << 19)
                | (imm << 5)
                | t,
        );
        Ok(())
    }
    /// BR register.
    pub fn br(&mut self, rn: Gpr) -> Result<(), EncodeError> {
        self.indirect(rn, 0xd61f_0000)
    }
    /// BLR register.
    pub fn blr(&mut self, rn: Gpr) -> Result<(), EncodeError> {
        self.indirect(rn, 0xd63f_0000)
    }
    /// RET register.
    pub fn ret(&mut self, rn: Gpr) -> Result<(), EncodeError> {
        self.indirect(rn, 0xd65f_0000)
    }
    fn indirect(&mut self, rn: Gpr, base: u32) -> Result<(), EncodeError> {
        let n = Self::reg(rn, Width::X64, false, false)?;
        self.emit(base | (n << 5));
        Ok(())
    }

    /// ADR with signed byte displacement.
    pub fn adr(&mut self, rd: Gpr, byte_off: i32) -> Result<(), EncodeError> {
        if !(-(1 << 20)..(1 << 20)).contains(&byte_off) {
            return Err(EncodeError::ImmediateOutOfRange {
                value: byte_off as i64,
                min: -(1 << 20),
                max: (1 << 20) - 1,
            });
        }
        let d = Self::reg(rd, Width::X64, false, true)?;
        let imm = (byte_off as u32) & 0x1f_ffff;
        self.emit(0x1000_0000 | ((imm & 3) << 29) | (((imm >> 2) & 0x7ffff) << 5) | d);
        Ok(())
    }
    /// ADRP with signed page displacement.
    pub fn adrp(&mut self, rd: Gpr, page_off: i32) -> Result<(), EncodeError> {
        if !(-(1 << 20)..(1 << 20)).contains(&page_off) {
            return Err(EncodeError::ImmediateOutOfRange {
                value: page_off as i64,
                min: -(1 << 20),
                max: (1 << 20) - 1,
            });
        }
        let d = Self::reg(rd, Width::X64, false, true)?;
        let imm = (page_off as u32) & 0x1f_ffff;
        self.emit(0x9000_0000 | ((imm & 3) << 29) | (((imm >> 2) & 0x7ffff) << 5) | d);
        Ok(())
    }
    /// Literal LDR, signed word displacement.
    pub fn ldr_literal(&mut self, rt: Gpr, words: i32) -> Result<(), EncodeError> {
        let imm = Self::checked_signed(words as i64, 19)?;
        let t = Self::reg(rt, rt.width, false, true)?;
        let base = if rt.width == Width::X64 {
            0x5800_0000
        } else {
            0x1800_0000
        };
        self.emit(base | (imm << 5) | t);
        Ok(())
    }

    /// CSEL.
    pub fn csel(&mut self, rd: Gpr, rn: Gpr, rm: Gpr, cond: Cond) -> Result<(), EncodeError> {
        self.conditional_select(rd, rn, rm, cond, 0, 0)
    }
    /// CSINV.
    pub fn csinv(&mut self, rd: Gpr, rn: Gpr, rm: Gpr, cond: Cond) -> Result<(), EncodeError> {
        self.conditional_select(rd, rn, rm, cond, 1, 0)
    }
    /// CINC alias.
    pub fn cinc(&mut self, rd: Gpr, rn: Gpr, cond: Cond) -> Result<(), EncodeError> {
        self.conditional_select(rd, rn, rn, cond, 0, 1)
    }
    /// CSET alias.
    pub fn cset(&mut self, rd: Gpr, cond: Cond) -> Result<(), EncodeError> {
        let zr = if rd.width == Width::X64 {
            Gpr::xzr()
        } else {
            Gpr::wzr()
        };
        self.conditional_select(rd, zr, zr, cond, 0, 2)
    }
    /// CSETM alias.
    pub fn csetm(&mut self, rd: Gpr, cond: Cond) -> Result<(), EncodeError> {
        let zr = if rd.width == Width::X64 {
            Gpr::xzr()
        } else {
            Gpr::wzr()
        };
        self.conditional_select(rd, zr, zr, cond, 1, 2)
    }
    fn conditional_select(
        &mut self,
        rd: Gpr,
        rn: Gpr,
        rm: Gpr,
        cond: Cond,
        op: u32,
        alias: u8,
    ) -> Result<(), EncodeError> {
        let w = Self::same(rd, rn)?;
        if rm.width != w {
            return Err(EncodeError::WidthMismatch);
        }
        let (d, n, mut m) = (
            Self::reg(rd, w, false, true)?,
            Self::reg(rn, w, false, true)?,
            Self::reg(rm, w, false, true)?,
        );
        let mut c = cond as u32;
        if alias == 1 {
            m = Self::reg(rm, w, false, true)?;
        }
        if alias != 0 {
            c ^= 1;
        }
        let sf = if w == Width::X64 { 1 << 31 } else { 0 };
        let o2 = alias == 1 || (alias == 2 && op == 0);
        self.emit(
            sf | 0x1a80_0000
                | (m << 16)
                | (c << 12)
                | (op << 30)
                | ((o2 as u32) << 10)
                | (n << 5)
                | d,
        );
        Ok(())
    }

    /// NEG alias (SUB from zero register).
    pub fn neg(&mut self, rd: Gpr, rn: Gpr) -> Result<(), EncodeError> {
        let zr = if rd.width == Width::X64 {
            Gpr::xzr()
        } else {
            Gpr::wzr()
        };
        self.sub_reg(rd, zr, rn, Shift::Lsl, 0)
    }
    /// NEGS alias.
    pub fn negs(&mut self, rd: Gpr, rn: Gpr) -> Result<(), EncodeError> {
        let zr = if rd.width == Width::X64 {
            Gpr::xzr()
        } else {
            Gpr::wzr()
        };
        self.subs_reg(rd, zr, rn, Shift::Lsl, 0)
    }
    /// NGC alias (SBC from zero register).
    pub fn ngc(&mut self, rd: Gpr, rn: Gpr) -> Result<(), EncodeError> {
        let zr = if rd.width == Width::X64 {
            Gpr::xzr()
        } else {
            Gpr::wzr()
        };
        self.sbc(rd, zr, rn)
    }
    /// REV16.
    pub fn rev16(&mut self, rd: Gpr, rn: Gpr) -> Result<(), EncodeError> {
        self.reverse(rd, rn, 0x5ac0_0400)
    }
    /// REV32.
    pub fn rev32(&mut self, rd: Gpr, rn: Gpr) -> Result<(), EncodeError> {
        self.reverse(rd, rn, 0x5ac0_0800)
    }
    /// REV64.
    pub fn rev64(&mut self, rd: Gpr, rn: Gpr) -> Result<(), EncodeError> {
        self.reverse(rd, rn, 0xdac0_0c00)
    }
    /// CLS.
    pub fn cls(&mut self, rd: Gpr, rn: Gpr) -> Result<(), EncodeError> {
        self.reverse(rd, rn, 0x5ac0_1400)
    }
    fn reverse(&mut self, rd: Gpr, rn: Gpr, base: u32) -> Result<(), EncodeError> {
        let w = Self::same(rd, rn)?;
        let (d, n) = (
            Self::reg(rd, w, false, true)?,
            Self::reg(rn, w, false, true)?,
        );
        let b = if w == Width::X64 {
            base | 0x8000_0000
        } else {
            base & !0x8000_0000
        };
        self.emit(b | (n << 5) | d);
        Ok(())
    }

    /// LDRB unsigned byte offset.
    pub fn ldrb_uoff(&mut self, rt: Gpr, rn: Gpr, byte_off: u16) -> Result<(), EncodeError> {
        self.small_mem(rt, rn, byte_off as i16, 0, false, 0)
    }
    /// STRB unsigned byte offset.
    pub fn strb_uoff(&mut self, rt: Gpr, rn: Gpr, byte_off: u16) -> Result<(), EncodeError> {
        self.small_mem(rt, rn, byte_off as i16, 0, true, 0)
    }
    /// LDRH unsigned halfword offset.
    pub fn ldrh_uoff(&mut self, rt: Gpr, rn: Gpr, byte_off: u16) -> Result<(), EncodeError> {
        self.small_mem(rt, rn, byte_off as i16, 1, false, 0)
    }
    /// STRH unsigned halfword offset.
    pub fn strh_uoff(&mut self, rt: Gpr, rn: Gpr, byte_off: u16) -> Result<(), EncodeError> {
        self.small_mem(rt, rn, byte_off as i16, 1, true, 0)
    }
    /// LDURB signed unscaled byte offset.
    pub fn ldurb(&mut self, rt: Gpr, rn: Gpr, off: i16) -> Result<(), EncodeError> {
        self.small_mem(rt, rn, off, 0, false, 1)
    }
    /// STURB signed unscaled byte offset.
    pub fn sturb(&mut self, rt: Gpr, rn: Gpr, off: i16) -> Result<(), EncodeError> {
        self.small_mem(rt, rn, off, 0, true, 1)
    }
    /// LDURH signed unscaled halfword offset.
    pub fn ldurh(&mut self, rt: Gpr, rn: Gpr, off: i16) -> Result<(), EncodeError> {
        self.small_mem(rt, rn, off, 1, false, 1)
    }
    /// STURH signed unscaled halfword offset.
    pub fn sturh(&mut self, rt: Gpr, rn: Gpr, off: i16) -> Result<(), EncodeError> {
        self.small_mem(rt, rn, off, 1, true, 1)
    }
    fn small_mem(
        &mut self,
        rt: Gpr,
        rn: Gpr,
        off: i16,
        size: u8,
        store: bool,
        mode: u8,
    ) -> Result<(), EncodeError> {
        let scale = 1i16 << size;
        let unscaled = mode == 1;
        if unscaled && !(-256..=255).contains(&off) {
            return Err(EncodeError::ImmediateOutOfRange {
                value: off as i64,
                min: -256,
                max: 255,
            });
        }
        if !unscaled && (off < 0 || off % scale != 0 || off as u32 / scale as u32 > 4095) {
            return Err(EncodeError::ImmediateOutOfRange {
                value: off as i64,
                min: 0,
                max: (4095 * scale) as i64,
            });
        }
        let t = Self::reg(rt, rt.width, false, true)?;
        let n = Self::reg(rn, Width::X64, true, false)?;
        let base = match (size, unscaled, store) {
            (0, false, false) => 0x3940_0000,
            (0, false, true) => 0x3900_0000,
            (1, false, false) => 0x7940_0000,
            (1, false, true) => 0x7900_0000,
            (0, true, false) => 0x3840_0000,
            (0, true, true) => 0x3800_0000,
            (1, true, false) => 0x7840_0000,
            _ => 0x7800_0000,
        };
        let imm = if unscaled {
            ((off as u16 as u32) & 0x1ff) << 12
        } else {
            (off as u32 / scale as u32) << 10
        };
        self.emit(base | imm | (n << 5) | t);
        Ok(())
    }
    /// LDAXR acquire exclusive load.
    pub fn ldaxr(&mut self, rt: Gpr, rn: Gpr) -> Result<(), EncodeError> {
        let t = Self::reg(rt, rt.width, false, true)?;
        let n = Self::reg(rn, Width::X64, true, false)?;
        self.emit(
            (if rt.width == Width::X64 {
                0xc85f_fc00
            } else {
                0x885f_fc00
            }) | (n << 5)
                | t,
        );
        Ok(())
    }
    /// STLXR release exclusive store.
    pub fn stlxr(&mut self, status: Gpr, rt: Gpr, rn: Gpr) -> Result<(), EncodeError> {
        if status.width != Width::W32 {
            return Err(EncodeError::WidthMismatch);
        }
        let (s, t, n) = (
            Self::reg(status, Width::W32, false, true)?,
            Self::reg(rt, rt.width, false, true)?,
            Self::reg(rn, Width::X64, true, false)?,
        );
        self.emit(
            (if rt.width == Width::X64 {
                0xc800_fc00
            } else {
                0x8800_fc00
            }) | (s << 16)
                | (n << 5)
                | t,
        );
        Ok(())
    }
    /// LDADDAL atomic add with acquire/release ordering.
    pub fn ldaddal(&mut self, add: Gpr, result: Gpr, rn: Gpr) -> Result<(), EncodeError> {
        let w = Self::same(add, result)?;
        let (a, t, n) = (
            Self::reg(add, w, false, true)?,
            Self::reg(result, w, false, true)?,
            Self::reg(rn, Width::X64, true, false)?,
        );
        self.emit(
            (if w == Width::X64 {
                0xf8e0_0000
            } else {
                0xb8e0_0000
            }) | (a << 16)
                | (n << 5)
                | t,
        );
        Ok(())
    }
    /// LDR D register from scaled unsigned byte offset.
    // Port of erts/emulator/beam/jit/arm/instr_float.cpp:37, OTP-29.1.1.
    pub fn ldr_d_uoff(&mut self, rt: VecReg, rn: Gpr, byte_off: u32) -> Result<(), EncodeError> {
        self.fp_mem(rt, rn, byte_off, false)
    }
    /// STR D register to scaled unsigned byte offset.
    pub fn str_d_uoff(&mut self, rt: VecReg, rn: Gpr, byte_off: u32) -> Result<(), EncodeError> {
        self.fp_mem(rt, rn, byte_off, true)
    }
    /// LDR Q register from a scaled unsigned byte offset.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:878, OTP-29.1.1.
    pub fn ldr_q_uoff(&mut self, rt: VecReg, rn: Gpr, byte_off: u32) -> Result<(), EncodeError> {
        self.q_mem(rt, rn, byte_off, false)
    }
    /// STR Q register to a scaled unsigned byte offset.
    pub fn str_q_uoff(&mut self, rt: VecReg, rn: Gpr, byte_off: u32) -> Result<(), EncodeError> {
        self.q_mem(rt, rn, byte_off, true)
    }
    /// LDUR Q register from a signed, unscaled byte offset.
    pub fn ldur_q(&mut self, rt: VecReg, rn: Gpr, byte_off: i16) -> Result<(), EncodeError> {
        self.fp_mem_unscaled(rt, rn, byte_off, 0x3cc0_0000)
    }
    /// STUR Q register to a signed, unscaled byte offset.
    pub fn stur_q(&mut self, rt: VecReg, rn: Gpr, byte_off: i16) -> Result<(), EncodeError> {
        self.fp_mem_unscaled(rt, rn, byte_off, 0x3c80_0000)
    }
    /// LDR Q register with pre-indexed addressing.
    pub fn ldr_q_pre(&mut self, rt: VecReg, rn: Gpr, byte_off: i16) -> Result<(), EncodeError> {
        self.fp_mem_index(rt, rn, byte_off, 0x3cc0_0c00)
    }
    /// STR Q register with pre-indexed addressing.
    pub fn str_q_pre(&mut self, rt: VecReg, rn: Gpr, byte_off: i16) -> Result<(), EncodeError> {
        self.fp_mem_index(rt, rn, byte_off, 0x3c80_0c00)
    }
    /// LDR Q register with post-indexed addressing.
    pub fn ldr_q_post(&mut self, rt: VecReg, rn: Gpr, byte_off: i16) -> Result<(), EncodeError> {
        self.fp_mem_index(rt, rn, byte_off, 0x3cc0_0400)
    }
    /// STR Q register with post-indexed addressing.
    pub fn str_q_post(&mut self, rt: VecReg, rn: Gpr, byte_off: i16) -> Result<(), EncodeError> {
        self.fp_mem_index(rt, rn, byte_off, 0x3c80_0400)
    }
    /// LDR D register from a signed, unscaled byte offset.
    pub fn ldur_d(&mut self, rt: VecReg, rn: Gpr, byte_off: i16) -> Result<(), EncodeError> {
        self.fp_mem_unscaled(rt, rn, byte_off, 0xfc40_0000)
    }
    /// STR D register to a signed, unscaled byte offset.
    pub fn stur_d(&mut self, rt: VecReg, rn: Gpr, byte_off: i16) -> Result<(), EncodeError> {
        self.fp_mem_unscaled(rt, rn, byte_off, 0xfc00_0000)
    }
    /// LDR D register with pre-indexed addressing.
    pub fn ldr_d_pre(&mut self, rt: VecReg, rn: Gpr, byte_off: i16) -> Result<(), EncodeError> {
        self.fp_mem_index(rt, rn, byte_off, 0xfc40_0c00)
    }
    /// STR D register with pre-indexed addressing.
    pub fn str_d_pre(&mut self, rt: VecReg, rn: Gpr, byte_off: i16) -> Result<(), EncodeError> {
        self.fp_mem_index(rt, rn, byte_off, 0xfc00_0c00)
    }
    /// LDR D register with post-indexed addressing.
    pub fn ldr_d_post(&mut self, rt: VecReg, rn: Gpr, byte_off: i16) -> Result<(), EncodeError> {
        self.fp_mem_index(rt, rn, byte_off, 0xfc40_0400)
    }
    /// STR D register with post-indexed addressing.
    pub fn str_d_post(&mut self, rt: VecReg, rn: Gpr, byte_off: i16) -> Result<(), EncodeError> {
        self.fp_mem_index(rt, rn, byte_off, 0xfc00_0400)
    }
    /// LDR D register from a register offset, optionally scaled by eight.
    pub fn ldr_d_regoff(
        &mut self,
        rt: VecReg,
        rn: Gpr,
        rm: Gpr,
        scaled: bool,
    ) -> Result<(), EncodeError> {
        self.fp_mem_regoff(rt, rn, rm, scaled, false)
    }
    /// STR D register to a register offset, optionally scaled by eight.
    pub fn str_d_regoff(
        &mut self,
        rt: VecReg,
        rn: Gpr,
        rm: Gpr,
        scaled: bool,
    ) -> Result<(), EncodeError> {
        self.fp_mem_regoff(rt, rn, rm, scaled, true)
    }
    /// LDR D register from a PC-relative literal at a signed word displacement.
    pub fn ldr_d_literal(&mut self, rt: VecReg, words: i32) -> Result<(), EncodeError> {
        Self::check_vec(rt)?;
        if !(-(1 << 18)..(1 << 18)).contains(&words) {
            return Err(EncodeError::ImmediateOutOfRange {
                value: words as i64,
                min: -(1 << 18),
                max: (1 << 18) - 1,
            });
        }
        self.emit(0x5c00_0000 | (((words as u32) & 0x7ffff) << 5) | rt.0 as u32);
        Ok(())
    }
    /// LDR D pair from a signed, scaled byte offset.
    pub fn ldp_d(
        &mut self,
        rt: VecReg,
        rt2: VecReg,
        rn: Gpr,
        byte_off: i16,
    ) -> Result<(), EncodeError> {
        self.fp_pair(rt, rt2, rn, byte_off, 0x6d40_0000)
    }
    /// STR D pair to a signed, scaled byte offset.
    pub fn stp_d(
        &mut self,
        rt: VecReg,
        rt2: VecReg,
        rn: Gpr,
        byte_off: i16,
    ) -> Result<(), EncodeError> {
        self.fp_pair(rt, rt2, rn, byte_off, 0x6d00_0000)
    }
    /// LDP D pair with pre-indexed addressing.
    pub fn ldp_d_pre(
        &mut self,
        rt: VecReg,
        rt2: VecReg,
        rn: Gpr,
        byte_off: i16,
    ) -> Result<(), EncodeError> {
        self.fp_pair(rt, rt2, rn, byte_off, 0x6dc0_0000)
    }
    /// STP D pair with pre-indexed addressing.
    pub fn stp_d_pre(
        &mut self,
        rt: VecReg,
        rt2: VecReg,
        rn: Gpr,
        byte_off: i16,
    ) -> Result<(), EncodeError> {
        self.fp_pair(rt, rt2, rn, byte_off, 0x6d80_0000)
    }
    /// LDP D pair with post-indexed addressing.
    pub fn ldp_d_post(
        &mut self,
        rt: VecReg,
        rt2: VecReg,
        rn: Gpr,
        byte_off: i16,
    ) -> Result<(), EncodeError> {
        self.fp_pair(rt, rt2, rn, byte_off, 0x6cc0_0000)
    }
    /// STP D pair with post-indexed addressing.
    pub fn stp_d_post(
        &mut self,
        rt: VecReg,
        rt2: VecReg,
        rn: Gpr,
        byte_off: i16,
    ) -> Result<(), EncodeError> {
        self.fp_pair(rt, rt2, rn, byte_off, 0x6c80_0000 | (1 << 23))
    }
    /// LDP Q pair from a signed, scaled byte offset.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:857, OTP-29.1.1.
    pub fn ldp_q(
        &mut self,
        rt: VecReg,
        rt2: VecReg,
        rn: Gpr,
        byte_off: i16,
    ) -> Result<(), EncodeError> {
        self.fp_pair_scaled(rt, rt2, rn, byte_off, 16, 0xad40_0000)
    }
    /// STP Q pair to a signed, scaled byte offset.
    pub fn stp_q(
        &mut self,
        rt: VecReg,
        rt2: VecReg,
        rn: Gpr,
        byte_off: i16,
    ) -> Result<(), EncodeError> {
        self.fp_pair_scaled(rt, rt2, rn, byte_off, 16, 0xad00_0000)
    }
    /// LDP Q pair with pre-indexed addressing.
    pub fn ldp_q_pre(
        &mut self,
        rt: VecReg,
        rt2: VecReg,
        rn: Gpr,
        byte_off: i16,
    ) -> Result<(), EncodeError> {
        self.fp_pair_scaled(rt, rt2, rn, byte_off, 16, 0xadc0_0000)
    }
    /// STP Q pair with pre-indexed addressing.
    pub fn stp_q_pre(
        &mut self,
        rt: VecReg,
        rt2: VecReg,
        rn: Gpr,
        byte_off: i16,
    ) -> Result<(), EncodeError> {
        self.fp_pair_scaled(rt, rt2, rn, byte_off, 16, 0xad80_0000)
    }
    /// LDP Q pair with post-indexed addressing.
    pub fn ldp_q_post(
        &mut self,
        rt: VecReg,
        rt2: VecReg,
        rn: Gpr,
        byte_off: i16,
    ) -> Result<(), EncodeError> {
        self.fp_pair_scaled(rt, rt2, rn, byte_off, 16, 0xacc0_0000)
    }
    /// STP Q pair with post-indexed addressing.
    pub fn stp_q_post(
        &mut self,
        rt: VecReg,
        rt2: VecReg,
        rn: Gpr,
        byte_off: i16,
    ) -> Result<(), EncodeError> {
        self.fp_pair_scaled(rt, rt2, rn, byte_off, 16, 0xac80_0000)
    }
    fn fp_mem(&mut self, rt: VecReg, rn: Gpr, off: u32, store: bool) -> Result<(), EncodeError> {
        if rt.0 > 31 {
            return Err(EncodeError::InvalidShift(rt.0));
        }
        if !off.is_multiple_of(8) || off / 8 > 4095 {
            return Err(EncodeError::ImmediateOutOfRange {
                value: off as i64,
                min: 0,
                max: 32760,
            });
        }
        let n = Self::reg(rn, Width::X64, true, false)?;
        self.emit(
            (if store { 0xfd00_0000 } else { 0xfd40_0000 })
                | ((off / 8) << 10)
                | (n << 5)
                | rt.0 as u32,
        );
        Ok(())
    }
    fn q_mem(&mut self, rt: VecReg, rn: Gpr, off: u32, store: bool) -> Result<(), EncodeError> {
        Self::check_vec(rt)?;
        if !off.is_multiple_of(16) || off / 16 > 4095 {
            return Err(EncodeError::ImmediateOutOfRange {
                value: off as i64,
                min: 0,
                max: 65520,
            });
        }
        let n = Self::reg(rn, Width::X64, true, false)?;
        self.emit(
            (if store { 0x3d80_0000 } else { 0x3dc0_0000 })
                | ((off / 16) << 10)
                | (n << 5)
                | rt.0 as u32,
        );
        Ok(())
    }
    fn fp_mem_unscaled(
        &mut self,
        rt: VecReg,
        rn: Gpr,
        off: i16,
        base: u32,
    ) -> Result<(), EncodeError> {
        Self::check_vec(rt)?;
        Self::check_range(off as i64, -256, 255)?;
        let n = Self::reg(rn, Width::X64, true, false)?;
        self.emit(base | (((off as i32 as u32) & 0x1ff) << 12) | (n << 5) | rt.0 as u32);
        Ok(())
    }
    fn fp_mem_index(
        &mut self,
        rt: VecReg,
        rn: Gpr,
        off: i16,
        base: u32,
    ) -> Result<(), EncodeError> {
        Self::check_vec(rt)?;
        Self::check_range(off as i64, -256, 255)?;
        let n = Self::reg(rn, Width::X64, true, false)?;
        self.emit(base | (((off as i32 as u32) & 0x1ff) << 12) | (n << 5) | rt.0 as u32);
        Ok(())
    }
    fn fp_mem_regoff(
        &mut self,
        rt: VecReg,
        rn: Gpr,
        rm: Gpr,
        scaled: bool,
        store: bool,
    ) -> Result<(), EncodeError> {
        Self::check_vec(rt)?;
        let n = Self::reg(rn, Width::X64, true, false)?;
        let m = Self::reg(rm, Width::X64, false, true)?;
        self.emit(
            (if store { 0xfc20_6800 } else { 0xfc60_6800 })
                | ((m & 31) << 16)
                | ((scaled as u32) << 12)
                | (3 << 13)
                | (n << 5)
                | rt.0 as u32,
        );
        Ok(())
    }
    fn fp_pair(
        &mut self,
        rt: VecReg,
        rt2: VecReg,
        rn: Gpr,
        off: i16,
        base: u32,
    ) -> Result<(), EncodeError> {
        Self::check_vec(rt)?;
        Self::check_vec(rt2)?;
        Self::check_range(off as i64, -1024, 1008)?;
        if off % 8 != 0 {
            return Err(EncodeError::Misaligned {
                value: off as i64,
                alignment: 8,
            });
        }
        let n = Self::reg(rn, Width::X64, true, false)?;
        let imm7 = ((off / 8) as i32 as u32) & 0x7f;
        self.emit(base | (imm7 << 15) | ((rt2.0 as u32) << 10) | (n << 5) | rt.0 as u32);
        Ok(())
    }
    fn fp_pair_scaled(
        &mut self,
        rt: VecReg,
        rt2: VecReg,
        rn: Gpr,
        off: i16,
        scale: i16,
        base: u32,
    ) -> Result<(), EncodeError> {
        Self::check_vec(rt)?;
        Self::check_vec(rt2)?;
        Self::check_range(off as i64, -1024, 1008)?;
        if off % scale != 0 {
            return Err(EncodeError::Misaligned {
                value: off as i64,
                alignment: scale as u8,
            });
        }
        let n = Self::reg(rn, Width::X64, true, false)?;
        let imm7 = ((off / scale) as i32 as u32) & 0x7f;
        self.emit(base | (imm7 << 15) | ((rt2.0 as u32) << 10) | (n << 5) | rt.0 as u32);
        Ok(())
    }
    fn check_vec(reg: VecReg) -> Result<(), EncodeError> {
        if reg.0 > 31 {
            return Err(EncodeError::InvalidShift(reg.0));
        }
        Ok(())
    }
    fn check_range(value: i64, min: i64, max: i64) -> Result<(), EncodeError> {
        if !(min..=max).contains(&value) {
            return Err(EncodeError::ImmediateOutOfRange { value, min, max });
        }
        Ok(())
    }
    /// FMOV Dd, Dn.
    pub fn fmov_d(&mut self, rd: VecReg, rn: VecReg) -> Result<(), EncodeError> {
        self.fp_rr(rd, rn, 0x1e60_4000)
    }
    /// FABS Dd, Dn.
    // Port of erts/emulator/beam/jit/arm/instr_float.cpp:36, OTP-29.1.1.
    pub fn fabs(&mut self, rd: VecReg, rn: VecReg) -> Result<(), EncodeError> {
        self.fp_rr(rd, rn, 0x1e60_c000)
    }
    /// FNEG Dd, Dn.
    // Port of erts/emulator/beam/jit/arm/instr_float.cpp:229, OTP-29.1.1.
    pub fn fneg(&mut self, rd: VecReg, rn: VecReg) -> Result<(), EncodeError> {
        self.fp_rr(rd, rn, 0x1e61_4000)
    }
    fn fp_rr(&mut self, rd: VecReg, rn: VecReg, base: u32) -> Result<(), EncodeError> {
        if rd.0 > 31 || rn.0 > 31 {
            return Err(EncodeError::InvalidShift(rd.0.max(rn.0)));
        }
        self.emit(base | ((rn.0 as u32) << 5) | rd.0 as u32);
        Ok(())
    }
    /// FCMP Dn, Dm.
    // Port of erts/emulator/beam/jit/arm/instr_float.cpp:38, OTP-29.1.1.
    pub fn fcmp(&mut self, rn: VecReg, rm: VecReg) -> Result<(), EncodeError> {
        self.fp_cmp(rn, rm, false)
    }
    /// FCMPE Dn, Dm.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:2135, OTP-29.1.1.
    pub fn fcmpe(&mut self, rn: VecReg, rm: VecReg) -> Result<(), EncodeError> {
        self.fp_cmp(rn, rm, true)
    }
    fn fp_cmp(&mut self, rn: VecReg, rm: VecReg, signal: bool) -> Result<(), EncodeError> {
        if rn.0 > 31 || rm.0 > 31 {
            return Err(EncodeError::InvalidShift(rn.0.max(rm.0)));
        }
        self.emit(
            0x1e60_2000 | ((rm.0 as u32) << 16) | ((signal as u32) << 4) | ((rn.0 as u32) << 5),
        );
        Ok(())
    }
    /// SCVTF Dd, Xn.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:2476, OTP-29.1.1.
    pub fn scvtf_d_x(&mut self, rd: VecReg, rn: Gpr) -> Result<(), EncodeError> {
        let n = Self::reg(rn, Width::X64, false, true)?;
        if rd.0 > 31 {
            return Err(EncodeError::InvalidShift(rd.0));
        }
        self.emit(0x9e62_0000 | (n << 5) | rd.0 as u32);
        Ok(())
    }
    /// FMOV Dd, Xn.
    // Port of erts/emulator/beam/jit/arm/instr_map.cpp:132, OTP-29.1.1.
    pub fn fmov_d_from_x(&mut self, rd: VecReg, rn: Gpr) -> Result<(), EncodeError> {
        let n = Self::reg(rn, Width::X64, false, true)?;
        if rd.0 > 31 {
            return Err(EncodeError::InvalidShift(rd.0));
        }
        self.emit(0x9e67_0000 | (n << 5) | rd.0 as u32);
        Ok(())
    }
    /// FMOV Xd, Dn.
    // Port of erts/emulator/beam/jit/arm/instr_map.cpp:137, OTP-29.1.1.
    pub fn fmov_x_from_d(&mut self, rd: Gpr, rn: VecReg) -> Result<(), EncodeError> {
        let d = Self::reg(rd, Width::X64, false, true)?;
        if rn.0 > 31 {
            return Err(EncodeError::InvalidShift(rn.0));
        }
        self.emit(0x9e66_0000 | ((rn.0 as u32) << 5) | d);
        Ok(())
    }
    /// FMOV Dd, #imm8 in the architectural floating-point immediate format.
    pub fn fmov_d_imm8(&mut self, rd: VecReg, imm8: u8) -> Result<(), EncodeError> {
        Self::check_vec(rd)?;
        let encoded_imm = (((imm8 & 0xf8) as u32) << 13) | (((imm8 & 0x07) as u32) << 5);
        self.emit(0x1e60_1000 | encoded_imm | rd.0 as u32);
        Ok(())
    }
    /// FMOV Dd, #value when value is exactly representable by FP imm8.
    pub fn fmov_d_imm(&mut self, rd: VecReg, value: f64) -> Result<(), EncodeError> {
        let bits = value.to_bits();
        for imm8 in 0..=u8::MAX {
            if expand_fp_imm8(imm8) == bits {
                return self.fmov_d_imm8(rd, imm8);
            }
        }
        Err(EncodeError::UnencodableFpImmediate(bits))
    }
    /// FADD Dd, Dn, Dm.
    pub fn fadd(&mut self, rd: VecReg, rn: VecReg, rm: VecReg) -> Result<(), EncodeError> {
        self.fp_bin(rd, rn, rm, 0x1e60_2800)
    }
    /// FSUB Dd, Dn, Dm.
    pub fn fsub(&mut self, rd: VecReg, rn: VecReg, rm: VecReg) -> Result<(), EncodeError> {
        self.fp_bin(rd, rn, rm, 0x1e60_3800)
    }
    /// FMUL Dd, Dn, Dm.
    pub fn fmul(&mut self, rd: VecReg, rn: VecReg, rm: VecReg) -> Result<(), EncodeError> {
        self.fp_bin(rd, rn, rm, 0x1e60_0800)
    }
    /// FDIV Dd, Dn, Dm.
    pub fn fdiv(&mut self, rd: VecReg, rn: VecReg, rm: VecReg) -> Result<(), EncodeError> {
        self.fp_bin(rd, rn, rm, 0x1e60_1800)
    }
    fn fp_bin(&mut self, rd: VecReg, rn: VecReg, rm: VecReg, base: u32) -> Result<(), EncodeError> {
        Self::check_vec(rd)?;
        Self::check_vec(rn)?;
        Self::check_vec(rm)?;
        self.emit(base | ((rm.0 as u32) << 16) | ((rn.0 as u32) << 5) | rd.0 as u32);
        Ok(())
    }
    /// FSQRT Dd, Dn.
    pub fn fsqrt(&mut self, rd: VecReg, rn: VecReg) -> Result<(), EncodeError> {
        self.fp_rr(rd, rn, 0x1e61_c000)
    }
    /// FCVTZS Xd, Dn.
    pub fn fcvtzs_x_from_d(&mut self, rd: Gpr, rn: VecReg) -> Result<(), EncodeError> {
        self.fp_to_gpr(rd, rn, 0x9e78_0000)
    }
    /// FCVTZS Wd, Dn.
    pub fn fcvtzs_w_from_d(&mut self, rd: Gpr, rn: VecReg) -> Result<(), EncodeError> {
        self.fp_to_gpr(rd, rn, 0x1e78_0000)
    }
    /// FCVTMS Xd, Dn (round toward minus infinity).
    pub fn fcvtms_x_from_d(&mut self, rd: Gpr, rn: VecReg) -> Result<(), EncodeError> {
        self.fp_to_gpr(rd, rn, 0x9e70_0000)
    }
    /// FCVTMS Wd, Dn (round toward minus infinity).
    pub fn fcvtms_w_from_d(&mut self, rd: Gpr, rn: VecReg) -> Result<(), EncodeError> {
        self.fp_to_gpr(rd, rn, 0x1e70_0000)
    }
    /// FCVTPS Xd, Dn (round toward plus infinity).
    pub fn fcvtps_x_from_d(&mut self, rd: Gpr, rn: VecReg) -> Result<(), EncodeError> {
        self.fp_to_gpr(rd, rn, 0x9e68_0000)
    }
    /// FCVTPS Wd, Dn (round toward plus infinity).
    pub fn fcvtps_w_from_d(&mut self, rd: Gpr, rn: VecReg) -> Result<(), EncodeError> {
        self.fp_to_gpr(rd, rn, 0x1e68_0000)
    }
    fn fp_to_gpr(&mut self, rd: Gpr, rn: VecReg, base: u32) -> Result<(), EncodeError> {
        let width = if base & 0x8000_0000 != 0 {
            Width::X64
        } else {
            Width::W32
        };
        let d = Self::reg(rd, width, false, true)?;
        Self::check_vec(rn)?;
        self.emit(base | ((rn.0 as u32) << 5) | d);
        Ok(())
    }
    /// FRINTZ Dd, Dn (round toward zero).
    pub fn frintz(&mut self, rd: VecReg, rn: VecReg) -> Result<(), EncodeError> {
        self.fp_rr(rd, rn, 0x1e65_c000)
    }
    /// FRINTM Dd, Dn (round toward minus infinity).
    pub fn frintm(&mut self, rd: VecReg, rn: VecReg) -> Result<(), EncodeError> {
        self.fp_rr(rd, rn, 0x1e65_4000)
    }
    /// FRINTP Dd, Dn (round toward plus infinity).
    pub fn frintp(&mut self, rd: VecReg, rn: VecReg) -> Result<(), EncodeError> {
        self.fp_rr(rd, rn, 0x1e64_c000)
    }
    /// FCCMP Dn, Dm, #nzcv, cond.
    pub fn fccmp(
        &mut self,
        rn: VecReg,
        rm: VecReg,
        nzcv: u8,
        cond: Cond,
    ) -> Result<(), EncodeError> {
        Self::check_vec(rn)?;
        Self::check_vec(rm)?;
        if nzcv > 15 {
            return Err(EncodeError::ImmediateOutOfRange {
                value: nzcv as i64,
                min: 0,
                max: 15,
            });
        }
        self.emit(
            0x1e60_0400
                | ((rm.0 as u32) << 16)
                | ((cond as u32) << 12)
                | ((rn.0 as u32) << 5)
                | nzcv as u32,
        );
        Ok(())
    }
    /// FCSEL Dd, Dn, Dm, cond.
    pub fn fcsel(
        &mut self,
        rd: VecReg,
        rn: VecReg,
        rm: VecReg,
        cond: Cond,
    ) -> Result<(), EncodeError> {
        Self::check_vec(rd)?;
        Self::check_vec(rn)?;
        Self::check_vec(rm)?;
        self.emit(
            0x1e60_0c00
                | ((rm.0 as u32) << 16)
                | ((cond as u32) << 12)
                | ((rn.0 as u32) << 5)
                | rd.0 as u32,
        );
        Ok(())
    }
    /// MOVI Vd.16B, replicated byte immediate.
    pub fn movi_16b(&mut self, rd: VecReg, imm: u8) -> Result<(), EncodeError> {
        self.movi_bytes(rd, imm, true)
    }
    /// MOVI Vd.8B, replicated byte immediate.
    pub fn movi_8b(&mut self, rd: VecReg, imm: u8) -> Result<(), EncodeError> {
        self.movi_bytes(rd, imm, false)
    }
    /// MOVI Dd, #0 or #all-ones.
    // Port of erts/emulator/beam/jit/arm/instr_bs.cpp:1137, OTP-29.1.1.
    pub fn movi_d(&mut self, rd: VecReg, value: u64) -> Result<(), EncodeError> {
        self.movi_2d_form(rd, value, false)
    }
    /// MOVI Vd.2D, #0 or #all-ones.
    pub fn movi_2d(&mut self, rd: VecReg, value: u64) -> Result<(), EncodeError> {
        self.movi_2d_form(rd, value, true)
    }
    fn movi_2d_form(&mut self, rd: VecReg, value: u64, q: bool) -> Result<(), EncodeError> {
        if rd.0 > 31 {
            return Err(EncodeError::InvalidShift(rd.0));
        }
        let base = match (q, value) {
            (false, 0) => 0x2f00_e400,
            (true, 0) => 0x6f00_e400,
            (false, u64::MAX) => 0x2f07_e7e0,
            (true, u64::MAX) => 0x6f07_e7e0,
            _ => {
                return Err(EncodeError::ImmediateOutOfRange {
                    value: value as i64,
                    min: 0,
                    max: i64::MAX,
                });
            }
        };
        self.emit(base | rd.0 as u32);
        Ok(())
    }
    fn movi_bytes(&mut self, rd: VecReg, imm: u8, q: bool) -> Result<(), EncodeError> {
        if rd.0 > 31 {
            return Err(EncodeError::InvalidShift(rd.0));
        }
        let qbit = if q { 1 << 30 } else { 0 };
        let encoded = (((imm as u32) & 0xe0) << 11) | (((imm as u32) & 0x1f) << 5);
        self.emit(0x0f00_e400 | qbit | encoded | rd.0 as u32);
        Ok(())
    }
    /// CNT Vd.8B, Vn.8B.
    // Port of erts/emulator/beam/jit/arm/instr_map.cpp:133, OTP-29.1.1.
    pub fn cnt_8b(&mut self, rd: VecReg, rn: VecReg) -> Result<(), EncodeError> {
        self.simd_unary(rd, rn, 0x0e20_5800)
    }
    /// ADDV Bd, Vn.8B.
    // Port of erts/emulator/beam/jit/arm/instr_map.cpp:134, OTP-29.1.1.
    pub fn addv_8b(&mut self, rd: VecReg, rn: VecReg) -> Result<(), EncodeError> {
        self.simd_unary(rd, rn, 0x0e31_b800)
    }
    fn simd_unary(&mut self, rd: VecReg, rn: VecReg, base: u32) -> Result<(), EncodeError> {
        if rd.0 > 31 || rn.0 > 31 {
            return Err(EncodeError::InvalidShift(rd.0.max(rn.0)));
        }
        self.emit(base | ((rn.0 as u32) << 5) | rd.0 as u32);
        Ok(())
    }

    /// NOP.
    pub fn nop(&mut self) {
        self.emit(0xd503_201f)
    }
    /// UDF with 16-bit immediate.
    pub fn udf(&mut self, imm: u16) {
        self.emit(u32::from(imm))
    }
    /// Emits a 64-bit data word in little-endian word order.
    pub fn embed_uint64(&mut self, value: u64) {
        self.emit(value as u32);
        self.emit((value >> 32) as u32)
    }
    /// Emits a 32-bit data word.
    pub fn embed_uint32(&mut self, value: u32) {
        self.emit(value)
    }
    /// Emits a resolved label address as a 64-bit data word; label resolution belongs to task 2.
    pub fn embed_label(&mut self, resolved_address: u64) {
        self.embed_uint64(resolved_address)
    }
    /// Pads with NOPs until instruction count is aligned to `words`.
    pub fn align(&mut self, words: usize) -> Result<(), EncodeError> {
        if words == 0 {
            return Err(EncodeError::ImmediateOutOfRange {
                value: 0,
                min: 1,
                max: i64::MAX,
            });
        }
        while !self.words.len().is_multiple_of(words) {
            self.nop()
        }
        Ok(())
    }
}

/// Returns `true` when `value` has an AArch64 logical-immediate bitmask encoding.
pub fn is_logical_immediate(value: u64, bits: u8) -> bool {
    encode_logical_immediate(value, bits).is_some()
}

/// Produces `(N, immr, imms)` for an AArch64 logical-immediate bitmask.
///
/// Constant time: find the smallest replicating element, then read the run of ones and its
/// rotation from the element's leading and trailing bits, as the assembler of the
/// architecture reference does (`DecodeBitMasks` inverted), instead of trying every element
/// size, run length and rotation.
pub fn encode_logical_immediate(value: u64, bits: u8) -> Option<(u32, u32, u32)> {
    if bits != 32 && bits != 64 {
        return None;
    }
    let mask = if bits == 64 {
        u64::MAX
    } else {
        u32::MAX as u64
    };
    let value = value & mask;
    if value == 0 || value == mask {
        return None;
    }
    // Smallest element size whose repetition is the value.
    let mut size = u32::from(bits);
    while size > 2 {
        let half = size / 2;
        let half_mask = (1u64 << half) - 1;
        if (value & half_mask) != ((value >> half) & half_mask) {
            break;
        }
        size = half;
    }
    let element_mask = if size == 64 {
        u64::MAX
    } else {
        (1u64 << size) - 1
    };
    let element = value & element_mask;
    // The element must be a rotated run of ones: a shifted mask, or the complement of one.
    let (rotation_base, ones) = if is_shifted_mask(element) {
        (
            element.trailing_zeros(),
            (element >> element.trailing_zeros()).trailing_ones(),
        )
    } else {
        let inverted = !element & element_mask;
        if !is_shifted_mask(inverted) {
            return None;
        }
        // Ones wrap around the top: the run starts after the zeros.
        let zeros = inverted.count_ones();
        (
            size - (inverted.leading_zeros() - (64 - size)),
            size - zeros,
        )
    };
    let immr = (size - rotation_base) & (size - 1);
    let n_imms = (!(size - 1) << 1) | (ones - 1);
    let n = ((n_imms >> 6) & 1) ^ 1;
    Some((n, immr, n_imms & 0x3f))
}

fn is_shifted_mask(value: u64) -> bool {
    value != 0 && {
        let shifted = value >> value.trailing_zeros();
        shifted & (shifted + 1) == 0
    }
}
fn expand_fp_imm8(imm8: u8) -> u64 {
    let sign = ((imm8 >> 7) as u64) << 63;
    let encoded_exponent = ((imm8 >> 4) & 0x07) as i32;
    let exponent = ((encoded_exponent ^ 0x04) - 3 + 1023) as u64;
    let fraction = ((imm8 & 0x0f) as u64) << 48;
    sign | (exponent << 52) | fraction
}
#[cfg(test)]
fn replicate(pattern: u64, esize: u8, bits: u8) -> u64 {
    let mut out = 0;
    for i in (0..bits).step_by(esize as usize) {
        out |= (pattern & ((1u64 << esize.min(63)) - 1)) << i
    }
    if esize == 64 { pattern } else { out }
}
#[cfg(test)]
fn rotate_right(value: u64, amount: u8, bits: u8) -> u64 {
    let mask = if bits == 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    };
    let n = (amount % bits) as u32;
    if n == 0 {
        return value & mask;
    }
    ((value >> n) | (value << (bits as u32 - n))) & mask
}

#[cfg(test)]
mod logical_tests {
    use super::*;
    #[test]
    fn bitmask_examples() {
        assert!(is_logical_immediate(0xff, 64));
        assert!(is_logical_immediate(0xff00_ff00_ff00_ff00, 64));
        assert!(!is_logical_immediate(0, 64));
        assert!(!is_logical_immediate(u64::MAX, 64));
        assert!(!is_logical_immediate(0x1234, 64));
    }
}

#[cfg(test)]
mod logical_reference_tests {
    use super::*;

    fn encode_logical_immediate_reference(value: u64, bits: u8) -> Option<(u32, u32, u32)> {
        if bits != 32 && bits != 64 {
            return None;
        }
        let mask = if bits == 64 {
            u64::MAX
        } else {
            u32::MAX as u64
        };
        let value = value & mask;
        if value == 0 || value == mask {
            return None;
        }
        for esize in [2u8, 4, 8, 16, 32, 64].into_iter().filter(|&s| s <= bits) {
            let emask = if esize == 64 {
                u64::MAX
            } else {
                (1u64 << esize) - 1
            };
            let pattern = value & emask;
            if replicate(pattern, esize, bits) != value {
                continue;
            }
            for ones in 1..esize {
                let run = (1u64 << ones) - 1;
                for r in 0..esize {
                    if rotate_right(run, r, esize) == pattern {
                        let n = if esize == 64 { 1 } else { 0 };
                        let imms = (!(2 * esize as u32 - 1) & 0x3f) | ((ones as u32 - 1) & 0x3f);
                        return Some((n, (r as u32) & 0x3f, imms));
                    }
                }
            }
        }
        None
    }

    #[test]
    fn constant_time_encoder_matches_the_search() {
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for bits in [32u8, 64] {
            // Every rotated run of every element size.
            for esize in [2u32, 4, 8, 16, 32, 64] {
                if esize > u32::from(bits) {
                    continue;
                }
                for ones in 1..esize {
                    for rotation in 0..esize {
                        let emask = if esize == 64 {
                            u64::MAX
                        } else {
                            (1u64 << esize) - 1
                        };
                        let run = (1u64 << ones) - 1;
                        let element = if rotation == 0 {
                            run
                        } else {
                            ((run >> rotation) | (run << (esize - rotation))) & emask
                        };
                        let mut value = 0u64;
                        let mut at = 0;
                        while at < u32::from(bits) {
                            value |= element << at;
                            at += esize;
                        }
                        assert_eq!(
                            encode_logical_immediate(value, bits),
                            encode_logical_immediate_reference(value, bits),
                            "{value:#x} / {bits}"
                        );
                    }
                }
            }
            for _ in 0..200_000 {
                let value = next() >> (next() % 64);
                assert_eq!(
                    encode_logical_immediate(value, bits),
                    encode_logical_immediate_reference(value, bits),
                    "{value:#x} / {bits}"
                );
            }
        }
    }
}
