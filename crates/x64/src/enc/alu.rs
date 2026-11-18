//! Integer ALU forms: `add/or/adc/sbb/and/sub/xor/cmp`, `test`, `neg/not`, `inc/dec`.
//!
//! Port of `x86::Assembler::_emit` cases `kEncodingX86Arith`, `kEncodingX86Test`,
//! `kEncodingX86M_GPB` and `kEncodingX86IncDec` in
//! `erts/emulator/asmjit/x86/x86assembler.cpp`, OTP-29.1.1, with erts' `kOptimizeForSize`.

use super::core::{ByteRex, Imm, Opcode, Rm, is_int, is_uint};
use super::{Emitter, EncodeError, Gp, Mem};

/// `/n` of the eight arithmetic instructions; the reg/mem opcodes are `n * 8 + {0..3}`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum Arith {
    Add = 0,
    Or = 1,
    Adc = 2,
    Sbb = 3,
    And = 4,
    Sub = 5,
    Xor = 6,
    Cmp = 7,
}

impl Emitter {
    // Arith: Reg, Reg -- MR encoding (asmjit default without kX86_ModRM).
    fn arith_rr(&mut self, op: Arith, dst: Gp, src: Gp) -> Result<(), EncodeError> {
        let size = Self::same_size(dst, src)?;
        let mut rex = ByteRex::default();
        let rb = Self::gp_id(dst, &mut rex)?;
        let reg = Self::gp_id(src, &mut rex)?;
        let opcode = Opcode::legacy((op as u8) << 3).arith_by_size(size);
        self.x86_rm(opcode, reg, Rm::Reg(rb), rex, Imm::NONE)
    }

    fn arith_rm(&mut self, op: Arith, dst: Gp, src: &Mem) -> Result<(), EncodeError> {
        let mut rex = ByteRex::default();
        let reg = Self::gp_id(dst, &mut rex)?;
        let opcode = Opcode::legacy(((op as u8) << 3) + 2).arith_by_size(dst.size());
        self.x86_rm(opcode, reg, Rm::Mem(src), rex, Imm::NONE)
    }

    fn arith_mr(&mut self, op: Arith, dst: &Mem, src: Gp) -> Result<(), EncodeError> {
        let mut rex = ByteRex::default();
        let reg = Self::gp_id(src, &mut rex)?;
        let opcode = Opcode::legacy((op as u8) << 3).arith_by_size(src.size());
        self.x86_rm(opcode, reg, Rm::Mem(dst), rex, Imm::NONE)
    }

    fn arith_ri(&mut self, op: Arith, dst: Gp, value: i64) -> Result<(), EncodeError> {
        let mut rex = ByteRex::default();
        let rb = Self::gp_id(dst, &mut rex)?;
        let mut size = dst.size();
        let mut value = value;
        let mut opcode = Opcode::legacy(0x80);
        let mut imm_size;
        if size == 1 {
            imm_size = 1;
        } else {
            match size {
                2 => opcode = opcode.prefix_by_size(2),
                4 => {
                    // Sign extend so is_int_n<8> returns the right result.
                    value = value as i32 as i64;
                }
                _ => {
                    let can_transform_to_32bit = op == Arith::And && is_uint(value, 32);
                    if !is_int(value, 32) {
                        if !can_transform_to_32bit {
                            return Err(EncodeError::InvalidImmediate(value));
                        }
                        size = 4;
                    } else if can_transform_to_32bit {
                        // EncodingOptions::kOptimizeForSize (beam_jit_common.cpp).
                        size = 4;
                    }
                    opcode = opcode.with_w(size == 8);
                }
            }
            imm_size = size.min(4);
            if is_int(value, 8) {
                imm_size = 1;
            }
        }
        // Short form - AL, AX, EAX, RAX.
        if rb == 0 && (size == 1 || imm_size != 1) {
            opcode.byte = ((op as u8) << 3) | (0x04 + (size != 1) as u8);
            return self.x86_op(opcode, Imm::new(value as u64, size.min(4)));
        }
        if size != 1 {
            opcode.byte += if imm_size != 1 { 1 } else { 3 };
        }
        self.x86_rm(
            opcode,
            op as u8,
            Rm::Reg(rb),
            rex,
            Imm::new(value as u64, imm_size),
        )
    }

    fn arith_mi(&mut self, op: Arith, dst: &Mem, value: i64) -> Result<(), EncodeError> {
        let size = Self::mem_size(dst)?;
        let mut value = value;
        // asmjit never rejects the immediate here: it writes the low `min(size, 4)` bytes.
        if size == 4 {
            value = value as i32 as i64;
        }
        let mut imm_size = size.min(4);
        if is_int(value, 8) {
            imm_size = 1;
        }
        let mut opcode = Opcode::legacy(0x80);
        if size != 1 {
            opcode.byte += if imm_size != 1 { 1 } else { 3 };
        }
        let opcode = opcode.prefix_by_size(size);
        self.x86_rm(
            opcode,
            op as u8,
            Rm::Mem(dst),
            ByteRex::default(),
            Imm::new(value as u64, imm_size),
        )
    }
}

macro_rules! arith_family {
    ($($op:ident: $rr:ident, $ri:ident, $rm:ident, $mr:ident, $mi:ident, $name:literal;)*) => {
        impl Emitter {
            $(
                #[doc = concat!("`", $name, " dst, src` (asmjit `a.", $name, "(Gp, Gp)`).")]
                pub fn $rr(&mut self, dst: Gp, src: Gp) -> Result<(), EncodeError> {
                    self.arith_rr(Arith::$op, dst, src)
                }
                #[doc = concat!("`", $name, " dst, imm` (asmjit `a.", $name, "(Gp, Imm)`): imm8 when it fits, short `rAX` form otherwise.")]
                pub fn $ri(&mut self, dst: Gp, imm: i64) -> Result<(), EncodeError> {
                    self.arith_ri(Arith::$op, dst, imm)
                }
                #[doc = concat!("`", $name, " dst, [mem]` (asmjit `a.", $name, "(Gp, Mem)`).")]
                pub fn $rm(&mut self, dst: Gp, src: Mem) -> Result<(), EncodeError> {
                    self.arith_rm(Arith::$op, dst, &src)
                }
                #[doc = concat!("`", $name, " [mem], src` (asmjit `a.", $name, "(Mem, Gp)`).")]
                pub fn $mr(&mut self, dst: Mem, src: Gp) -> Result<(), EncodeError> {
                    self.arith_mr(Arith::$op, &dst, src)
                }
                #[doc = concat!("`", $name, " size ptr [mem], imm` (asmjit `a.", $name, "(Mem, Imm)`); `dst.size` is required.")]
                pub fn $mi(&mut self, dst: Mem, imm: i64) -> Result<(), EncodeError> {
                    self.arith_mi(Arith::$op, &dst, imm)
                }
            )*
        }
    };
}

arith_family! {
    Add: add_rr, add_ri, add_rm, add_mr, add_mi, "add";
    Or: or_rr, or_ri, or_rm, or_mr, or_mi, "or";
    Adc: adc_rr, adc_ri, adc_rm, adc_mr, adc_mi, "adc";
    Sbb: sbb_rr, sbb_ri, sbb_rm, sbb_mr, sbb_mi, "sbb";
    And: and_rr, and_ri, and_rm, and_mr, and_mi, "and";
    Sub: sub_rr, sub_ri, sub_rm, sub_mr, sub_mi, "sub";
    Xor: xor_rr, xor_ri, xor_rm, xor_mr, xor_mi, "xor";
    Cmp: cmp_rr, cmp_ri, cmp_rm, cmp_mr, cmp_mi, "cmp";
}

impl Emitter {
    /// `test a, b` (asmjit `a.test(Gp, Gp)`): `84|85 /r` with `a` in ModRM.rm.
    pub fn test_rr(&mut self, a: Gp, b: Gp) -> Result<(), EncodeError> {
        let size = Self::same_size(a, b)?;
        let mut rex = ByteRex::default();
        let rb = Self::gp_id(a, &mut rex)?;
        let reg = Self::gp_id(b, &mut rex)?;
        let opcode = Opcode::legacy(0x84).arith_by_size(size);
        self.x86_rm(opcode, reg, Rm::Reg(rb), rex, Imm::NONE)
    }

    /// `test [mem], b` (asmjit `a.test(Mem, Gp)`).
    pub fn test_mr(&mut self, a: Mem, b: Gp) -> Result<(), EncodeError> {
        let mut rex = ByteRex::default();
        let reg = Self::gp_id(b, &mut rex)?;
        let opcode = Opcode::legacy(0x84).arith_by_size(b.size());
        self.x86_rm(opcode, reg, Rm::Mem(&a), rex, Imm::NONE)
    }

    /// `test a, imm` (asmjit `a.test(Gp, Imm)`): `F6|F7 /0` with a full-width immediate
    /// (32-bit for 64-bit registers), `A8|A9` for `rAX`. A 64-bit form needs an int32 immediate.
    pub fn test_ri(&mut self, a: Gp, imm: i64) -> Result<(), EncodeError> {
        let mut rex = ByteRex::default();
        let rb = Self::gp_id(a, &mut rex)?;
        let size = a.size();
        // asmjit writes the low `min(size, 4)` bytes without validating the value.
        let imm = Imm::new(imm as u64, size.min(4));
        let opcode = Opcode::legacy(0xF6).arith_by_size(size);
        // Short form - AL, AX, EAX, RAX.
        if rb == 0 {
            let short = Opcode {
                byte: 0xA8 + (size != 1) as u8,
                ..opcode
            };
            return self.x86_op(short, imm);
        }
        self.x86_rm(opcode, 0, Rm::Reg(rb), rex, imm)
    }

    /// `test size ptr [mem], imm` (asmjit `a.test(Mem, Imm)`); `a.size` is required.
    pub fn test_mi(&mut self, a: Mem, imm: i64) -> Result<(), EncodeError> {
        let size = Self::mem_size(&a)?;
        let opcode = Opcode::legacy(0xF6).arith_by_size(size);
        self.x86_rm(
            opcode,
            0,
            Rm::Mem(&a),
            ByteRex::default(),
            Imm::new(imm as u64, size.min(4)),
        )
    }

    // kEncodingX86M_GPB / kEncodingX86IncDec (64-bit mode): `base /ext`, `+1` for non-byte.
    fn unary_r(&mut self, base: u8, ext: u8, reg: Gp) -> Result<(), EncodeError> {
        let mut rex = ByteRex::default();
        let rb = Self::gp_id(reg, &mut rex)?;
        let opcode = Opcode::legacy(base).arith_by_size(reg.size());
        self.x86_rm(opcode, ext, Rm::Reg(rb), rex, Imm::NONE)
    }

    fn unary_m(&mut self, base: u8, ext: u8, mem: &Mem) -> Result<(), EncodeError> {
        let size = Self::mem_size(mem)?;
        let opcode = Opcode::legacy(base).arith_by_size(size);
        self.x86_rm(opcode, ext, Rm::Mem(mem), ByteRex::default(), Imm::NONE)
    }

    /// `neg reg` (asmjit `a.neg(Gp)`): `F6|F7 /3`.
    pub fn neg_r(&mut self, reg: Gp) -> Result<(), EncodeError> {
        self.unary_r(0xF6, 3, reg)
    }
    /// `neg size ptr [mem]` (asmjit `a.neg(Mem)`).
    pub fn neg_m(&mut self, mem: Mem) -> Result<(), EncodeError> {
        self.unary_m(0xF6, 3, &mem)
    }
    /// `not reg` (asmjit `a.not_(Gp)`): `F6|F7 /2`.
    pub fn not_r(&mut self, reg: Gp) -> Result<(), EncodeError> {
        self.unary_r(0xF6, 2, reg)
    }
    /// `not size ptr [mem]` (asmjit `a.not_(Mem)`).
    pub fn not_m(&mut self, mem: Mem) -> Result<(), EncodeError> {
        self.unary_m(0xF6, 2, &mem)
    }
    /// `inc reg` (asmjit `a.inc(Gp)`): `FE|FF /0` (the `40+r` form is a REX prefix in 64-bit mode).
    pub fn inc_r(&mut self, reg: Gp) -> Result<(), EncodeError> {
        self.unary_r(0xFE, 0, reg)
    }
    /// `inc size ptr [mem]` (asmjit `a.inc(Mem)`).
    pub fn inc_m(&mut self, mem: Mem) -> Result<(), EncodeError> {
        self.unary_m(0xFE, 0, &mem)
    }
    /// `dec reg` (asmjit `a.dec(Gp)`): `FE|FF /1`.
    pub fn dec_r(&mut self, reg: Gp) -> Result<(), EncodeError> {
        self.unary_r(0xFE, 1, reg)
    }
    /// `dec size ptr [mem]` (asmjit `a.dec(Mem)`).
    pub fn dec_m(&mut self, mem: Mem) -> Result<(), EncodeError> {
        self.unary_m(0xFE, 1, &mem)
    }
}
