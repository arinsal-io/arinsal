//! Data movement forms: `mov`, `lea`, `movzx/movsx/movsxd`, `bswap`, `movbe`.
//!
//! Port of `x86::Assembler::_emit` cases `kEncodingX86Mov`, `kEncodingX86Lea`,
//! `kEncodingX86MovsxMovzx`, `kEncodingX86Rm` (`movsxd`), `kEncodingX86Bswap` and
//! `kEncodingExtMovbe` in `erts/emulator/asmjit/x86/x86assembler.cpp`, OTP-29.1.1, with erts'
//! `kOptimizeForSize` and no base address.

use super::core::{ByteRex, Imm, Opcode, Rm, is_int, is_uint};
use super::{Emitter, EncodeError, Gp, Mem};

impl Emitter {
    /// `op_reg = o0.id()` without `FIXUP_GPB`: the destination of the forms where asmjit does not
    /// fix up byte registers (`ah` encodes as id 0, `spl` needs no REX).
    fn raw_id(reg: Gp) -> Result<u8, EncodeError> {
        if reg.id > 15 {
            Err(EncodeError::InvalidRegister(reg))
        } else {
            Ok(reg.id)
        }
    }

    /// `mov dst, src` (asmjit `a.mov(Gp, Gp)`): `88|89 /r` (MR form).
    pub fn mov_rr(&mut self, dst: Gp, src: Gp) -> Result<(), EncodeError> {
        if dst.size() != src.size() {
            return Err(EncodeError::InvalidInstruction);
        }
        let mut rex = ByteRex::default();
        let rb = Self::gp_id(dst, &mut rex)?;
        let reg = Self::gp_id(src, &mut rex)?;
        let opcode = Opcode::legacy(0x88).arith_by_size(dst.size());
        self.x86_rm(opcode, reg, Rm::Reg(rb), rex, Imm::NONE)
    }

    /// `mov dst, [mem]` (asmjit `a.mov(Gp, Mem)`): `8A|8B /r`; the load width is the register's.
    pub fn mov_rm(&mut self, dst: Gp, src: Mem) -> Result<(), EncodeError> {
        let mut rex = ByteRex::default();
        let reg = Self::gp_id(dst, &mut rex)?;
        let opcode = Opcode::legacy(0x8A).arith_by_size(dst.size());
        self.x86_rm(opcode, reg, Rm::Mem(&src), rex, Imm::NONE)
    }

    /// `mov [mem], src` (asmjit `a.mov(Mem, Gp)`): `88|89 /r`; the store width is the register's.
    pub fn mov_mr(&mut self, dst: Mem, src: Gp) -> Result<(), EncodeError> {
        let mut rex = ByteRex::default();
        let reg = Self::gp_id(src, &mut rex)?;
        let opcode = Opcode::legacy(0x88).arith_by_size(src.size());
        self.x86_rm(opcode, reg, Rm::Mem(&dst), rex, Imm::NONE)
    }

    /// `mov dst, imm` (asmjit `a.mov(Gp, Imm)`). For a 64-bit register asmjit picks
    /// `mov r32, imm32` (`B8+r`, zero-extending) for uint32 values, `C7 /0` with a sign-extended
    /// imm32 for int32 values, and `movabs` (`REX.W B8+r imm64`) otherwise.
    pub fn mov_ri(&mut self, dst: Gp, imm: i64) -> Result<(), EncodeError> {
        let mut rex = ByteRex::default();
        let reg = Self::gp_id(dst, &mut rex)?;
        let size = dst.size();
        if size == 1 {
            // value_as<uint8_t>: the low byte, never rejected.
            return self.x86_op_reg(Opcode::legacy(0xB0), reg, rex, Imm::new(imm as u64, 1));
        }
        let mut imm_size = size;
        if size == 8 {
            if is_uint(imm, 32) {
                // EncodingOptions::kOptimizeForSize: zero-extend through a 32-bit destination.
                imm_size = 4;
            } else if is_int(imm, 32) {
                // Sign-extend, uses 'C7 /0' opcode.
                let opcode = Opcode::legacy(0xC7).with_w(true);
                return self.x86_rm(opcode, 0, Rm::Reg(reg), rex, Imm::new(imm as u64, 4));
            }
        }
        let opcode = Opcode::legacy(0xB8).prefix_by_size(imm_size);
        self.x86_op_reg(opcode, reg, rex, Imm::new(imm as u64, imm_size))
    }

    /// `mov size ptr [mem], imm` (asmjit `a.mov(Mem, Imm)`): `C6|C7 /0`; `dst.size` is required and
    /// a 64-bit store takes a sign-extended int32.
    pub fn mov_mi(&mut self, dst: Mem, imm: i64) -> Result<(), EncodeError> {
        let size = Self::mem_size(&dst)?;
        let opcode = Opcode::legacy(0xC6 + (size != 1) as u8).prefix_by_size(size);
        self.x86_rm(
            opcode,
            0,
            Rm::Mem(&dst),
            ByteRex::default(),
            Imm::new(imm as u64, size.min(4)),
        )
    }

    /// `lea dst, [mem]` (asmjit `a.lea(Gp, Mem)`): `8D /r`, operand size from `dst`.
    pub fn lea(&mut self, dst: Gp, src: Mem) -> Result<(), EncodeError> {
        // kEncodingX86Lea: `op_reg = o0.id()` with no FIXUP_GPB and no operand validation, so a
        // byte destination encodes as its plain id (asmjit validates only under DEBUG).
        if dst.id > 15 {
            return Err(EncodeError::InvalidRegister(dst));
        }
        let opcode = Opcode::legacy(0x8D).prefix_by_size(dst.size());
        self.x86_rm(opcode, dst.id, Rm::Mem(&src), ByteRex::default(), Imm::NONE)
    }

    // kEncodingX86MovsxMovzx: `0F base` for a byte source, `0F base+1` for any other source
    // size, prefix by the destination size. Like asmjit (validation is DEBUG-only) no operand
    // size combination is rejected.
    fn movx_rr(&mut self, base: u8, dst: Gp, src: Gp) -> Result<(), EncodeError> {
        let mut rex = ByteRex::default();
        let reg = Self::raw_id(dst)?;
        let rb = Self::gp_id(src, &mut rex)?;
        let opcode = Opcode::m0f(base + (src.size() != 1) as u8).prefix_by_size(dst.size());
        self.x86_rm(opcode, reg, Rm::Reg(rb), rex, Imm::NONE)
    }

    fn movx_rm(&mut self, base: u8, dst: Gp, src: &Mem) -> Result<(), EncodeError> {
        let rex = ByteRex::default();
        let reg = Self::raw_id(dst)?;
        let opcode = Opcode::m0f(base + (src.size != 1) as u8).prefix_by_size(dst.size());
        self.x86_rm(opcode, reg, Rm::Mem(src), rex, Imm::NONE)
    }

    /// `movzx dst, src` (asmjit `a.movzx(Gp, Gp)`): `0F B6|B7 /r`.
    pub fn movzx_rr(&mut self, dst: Gp, src: Gp) -> Result<(), EncodeError> {
        self.movx_rr(0xB6, dst, src)
    }
    /// `movzx dst, byte|word ptr [mem]` (asmjit `a.movzx(Gp, Mem)`); `src.size` selects the width.
    pub fn movzx_rm(&mut self, dst: Gp, src: Mem) -> Result<(), EncodeError> {
        self.movx_rm(0xB6, dst, &src)
    }
    /// `movsx dst, src` (asmjit `a.movsx(Gp, Gp)`): `0F BE|BF /r`.
    pub fn movsx_rr(&mut self, dst: Gp, src: Gp) -> Result<(), EncodeError> {
        self.movx_rr(0xBE, dst, src)
    }
    /// `movsx dst, byte|word ptr [mem]` (asmjit `a.movsx(Gp, Mem)`); `src.size` selects the width.
    pub fn movsx_rm(&mut self, dst: Gp, src: Mem) -> Result<(), EncodeError> {
        self.movx_rm(0xBE, dst, &src)
    }

    /// `movsxd dst64, src32` (asmjit `a.movsxd(Gp, Gp)`): `REX.W 63 /r`.
    pub fn movsxd_rr(&mut self, dst: Gp, src: Gp) -> Result<(), EncodeError> {
        // kEncodingX86Rm: prefix by the destination size, no operand validation.
        let mut rex = ByteRex::default();
        let reg = Self::raw_id(dst)?;
        let rb = Self::gp_id(src, &mut rex)?;
        let opcode = Opcode::legacy(0x63).prefix_by_size(dst.size());
        self.x86_rm(opcode, reg, Rm::Reg(rb), rex, Imm::NONE)
    }

    /// `movsxd dst64, dword ptr [mem]` (asmjit `a.movsxd(Gp, Mem)`).
    pub fn movsxd_rm(&mut self, dst: Gp, src: Mem) -> Result<(), EncodeError> {
        let rex = ByteRex::default();
        let reg = Self::raw_id(dst)?;
        let opcode = Opcode::legacy(0x63).prefix_by_size(dst.size());
        self.x86_rm(opcode, reg, Rm::Mem(&src), rex, Imm::NONE)
    }

    /// `bswap reg` (asmjit `a.bswap(Gp)`): `0F C8+r`; 16/32/64-bit as asmjit allows.
    pub fn bswap(&mut self, reg: Gp) -> Result<(), EncodeError> {
        if reg.size() == 1 {
            return Err(EncodeError::InvalidInstruction);
        }
        let mut rex = ByteRex::default();
        let id = Self::gp_id(reg, &mut rex)?;
        let opcode = Opcode::m0f(0xC8).prefix_by_size(reg.size());
        self.x86_op_reg(opcode, id, rex, Imm::NONE)
    }

    /// `movbe dst, [mem]` (asmjit `a.movbe(Gp, Mem)`, MOVBE): `0F 38 F0 /r`.
    pub fn movbe_rm(&mut self, dst: Gp, src: Mem) -> Result<(), EncodeError> {
        if dst.size() == 1 {
            return Err(EncodeError::InvalidInstruction);
        }
        let rex = ByteRex::default();
        let reg = Self::raw_id(dst)?;
        let opcode = Opcode::m0f38(0xF0).prefix_by_size(dst.size());
        self.x86_rm(opcode, reg, Rm::Mem(&src), rex, Imm::NONE)
    }

    /// `movbe [mem], src` (asmjit `a.movbe(Mem, Gp)`, MOVBE): `0F 38 F1 /r`.
    pub fn movbe_mr(&mut self, dst: Mem, src: Gp) -> Result<(), EncodeError> {
        if src.size() == 1 {
            return Err(EncodeError::InvalidInstruction);
        }
        let mut rex = ByteRex::default();
        let reg = Self::gp_id(src, &mut rex)?;
        let opcode = Opcode::m0f38(0xF1).prefix_by_size(src.size());
        self.x86_rm(opcode, reg, Rm::Mem(&dst), rex, Imm::NONE)
    }
}
