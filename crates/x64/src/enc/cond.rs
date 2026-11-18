//! x86 condition codes, conditional moves, and conditional byte stores.
//!
//! Port of asmjit `CondCode` in `erts/emulator/asmjit/x86/x86globals.h` and the
//! `kEncodingX86Rm` / `kEncodingX86Set` cases in `x86assembler.cpp`, OTP-29.1.1. The condition
//! value is the low opcode nibble; CMOV derives size prefixes from its destination, and SET uses
//! asmjit's `FIXUP_GPB` register-id and REX rules.

use super::core::{ByteRex, Imm, Opcode, Rm};
use super::{Emitter, EncodeError, Gp, GpKind, Mem};

/// x86 condition-code nibble shared by conditional branches and conditional data instructions.
///
/// The canonical discriminants match asmjit `x86::CondCode` and the low four bits of the
/// corresponding `0F 8x`, `0F 4x`, and `0F 9x` opcodes.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum CondCode {
    /// Overflow set.
    O = 0x0,
    /// Overflow clear.
    NO = 0x1,
    /// Carry set / unsigned below.
    B = 0x2,
    /// Carry clear / unsigned above or equal.
    AE = 0x3,
    /// Zero set / equal.
    E = 0x4,
    /// Zero clear / not equal.
    NE = 0x5,
    /// Carry or zero set / unsigned below or equal.
    BE = 0x6,
    /// Carry and zero clear / unsigned above.
    A = 0x7,
    /// Sign set.
    S = 0x8,
    /// Sign clear.
    NS = 0x9,
    /// Parity set / parity even.
    P = 0xA,
    /// Parity clear / parity odd.
    NP = 0xB,
    /// Signed less.
    L = 0xC,
    /// Signed greater or equal.
    GE = 0xD,
    /// Signed less or equal.
    LE = 0xE,
    /// Signed greater.
    G = 0xF,
}

#[allow(non_upper_case_globals)]
impl CondCode {
    /// Carry alias for [`Self::B`].
    pub const C: Self = Self::B;
    /// Not-above-or-equal alias for [`Self::B`].
    pub const NAE: Self = Self::B;
    /// Not-carry alias for [`Self::AE`].
    pub const NC: Self = Self::AE;
    /// Not-below alias for [`Self::AE`].
    pub const NB: Self = Self::AE;
    /// Zero alias for [`Self::E`].
    pub const Z: Self = Self::E;
    /// Not-zero alias for [`Self::NE`].
    pub const NZ: Self = Self::NE;
    /// Not-above alias for [`Self::BE`].
    pub const NA: Self = Self::BE;
    /// Not-below-or-equal alias for [`Self::A`].
    pub const NBE: Self = Self::A;
    /// Parity-even alias for [`Self::P`].
    pub const PE: Self = Self::P;
    /// Parity-odd alias for [`Self::NP`].
    pub const PO: Self = Self::NP;
    /// Not-greater-or-equal alias for [`Self::L`].
    pub const NGE: Self = Self::L;
    /// Not-less alias for [`Self::GE`].
    pub const NL: Self = Self::GE;
    /// Not-greater alias for [`Self::LE`].
    pub const NG: Self = Self::LE;
    /// Not-less-or-equal alias for [`Self::G`].
    pub const NLE: Self = Self::G;

    /// Zero-flag semantic alias for [`Self::E`].
    pub const Zero: Self = Self::E;
    /// Not-zero semantic alias for [`Self::NE`].
    pub const NotZero: Self = Self::NE;
    /// Equality semantic alias for [`Self::E`].
    pub const Equal: Self = Self::E;
    /// Inequality semantic alias for [`Self::NE`].
    pub const NotEqual: Self = Self::NE;
    /// Carry-flag semantic alias for [`Self::B`].
    pub const Carry: Self = Self::B;
    /// Not-carry semantic alias for [`Self::AE`].
    pub const NotCarry: Self = Self::AE;
    /// Sign semantic alias for [`Self::S`].
    pub const Sign: Self = Self::S;
    /// Not-sign semantic alias for [`Self::NS`].
    pub const NotSign: Self = Self::NS;
    /// Negative semantic alias for [`Self::S`].
    pub const Negative: Self = Self::S;
    /// Positive semantic alias for [`Self::NS`].
    pub const Positive: Self = Self::NS;
    /// Overflow semantic alias for [`Self::O`].
    pub const Overflow: Self = Self::O;
    /// Not-overflow semantic alias for [`Self::NO`].
    pub const NotOverflow: Self = Self::NO;
    /// Signed less-than semantic alias for [`Self::L`].
    pub const SignedLT: Self = Self::L;
    /// Signed less-than-or-equal semantic alias for [`Self::LE`].
    pub const SignedLE: Self = Self::LE;
    /// Signed greater-than semantic alias for [`Self::G`].
    pub const SignedGT: Self = Self::G;
    /// Signed greater-than-or-equal semantic alias for [`Self::GE`].
    pub const SignedGE: Self = Self::GE;
    /// Unsigned less-than semantic alias for [`Self::B`].
    pub const UnsignedLT: Self = Self::B;
    /// Unsigned less-than-or-equal semantic alias for [`Self::BE`].
    pub const UnsignedLE: Self = Self::BE;
    /// Unsigned greater-than semantic alias for [`Self::A`].
    pub const UnsignedGT: Self = Self::A;
    /// Unsigned greater-than-or-equal semantic alias for [`Self::AE`].
    pub const UnsignedGE: Self = Self::AE;
    /// Tested bit clear semantic alias for [`Self::AE`].
    pub const BTZero: Self = Self::AE;
    /// Tested bit set semantic alias for [`Self::B`].
    pub const BTNotZero: Self = Self::B;
    /// Even parity semantic alias for [`Self::P`].
    pub const ParityEven: Self = Self::P;
    /// Odd parity semantic alias for [`Self::NP`].
    pub const ParityOdd: Self = Self::NP;
    /// Largest encoded condition-code value, matching asmjit `kMaxValue`.
    pub const MAX_VALUE: u8 = 0x0F;

    pub(crate) const fn nibble(self) -> u8 {
        self as u8
    }
}

impl Emitter {
    /// `cmovcc r, r` (asmjit `a.cmov(cc, dst, src)`), with the operation size taken from `dst`.
    pub fn cmovcc_rr(&mut self, cc: CondCode, dst: Gp, src: Gp) -> Result<(), EncodeError> {
        let dst_id = raw_gp_id(dst)?;
        let src_id = raw_gp_id(src)?;
        self.x86_rm(
            cmov_opcode(cc, dst.size()),
            dst_id,
            Rm::Reg(src_id),
            ByteRex::default(),
            Imm::NONE,
        )
    }

    /// `cmovcc r, [mem]` (asmjit `a.cmov(cc, dst, src)`), sized from `dst`.
    pub fn cmovcc_rm(&mut self, cc: CondCode, dst: Gp, src: Mem) -> Result<(), EncodeError> {
        let dst_id = raw_gp_id(dst)?;
        self.x86_rm(
            cmov_opcode(cc, dst.size()),
            dst_id,
            Rm::Mem(&src),
            ByteRex::default(),
            Imm::NONE,
        )
    }

    /// `setcc r8` (asmjit `a.set(cc, dst)`). Asmjit fixes a general-purpose register id to its
    /// byte-register encoding, including the high-byte and REX rules.
    pub fn setcc_r(&mut self, cc: CondCode, dst: Gp) -> Result<(), EncodeError> {
        let mut byte_rex = ByteRex::default();
        let mut dst_id = raw_gp_id(dst)?;
        if dst.kind == GpKind::B8Hi {
            if dst_id > 3 {
                return Err(EncodeError::InvalidRegister(dst));
            }
            dst_id += 4;
            byte_rex.invalid = true;
        } else {
            byte_rex.force = dst_id >= 4;
        }
        self.x86_rm(setcc_opcode(cc), 0, Rm::Reg(dst_id), byte_rex, Imm::NONE)
    }

    /// `setcc [mem]` (asmjit `a.set(cc, dst)`), encoded as an implicit byte store.
    pub fn setcc_m(&mut self, cc: CondCode, dst: Mem) -> Result<(), EncodeError> {
        self.x86_rm(
            setcc_opcode(cc),
            0,
            Rm::Mem(&dst),
            ByteRex::default(),
            Imm::NONE,
        )
    }
}

fn raw_gp_id(reg: Gp) -> Result<u8, EncodeError> {
    if reg.id <= 15 {
        Ok(reg.id)
    } else {
        Err(EncodeError::InvalidRegister(reg))
    }
}

const fn cmov_opcode(cc: CondCode, size: u8) -> Opcode {
    Opcode::m0f(0x40 + cc.nibble()).prefix_by_size(size)
}

const fn setcc_opcode(cc: CondCode) -> Opcode {
    Opcode::m0f(0x90 + cc.nibble())
}
