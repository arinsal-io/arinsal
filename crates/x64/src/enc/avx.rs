//! VEX-encoded AVX forms. `vpxor` is the reference VEX family; E24/E25 add the rest here.
//!
//! Port of `x86::Assembler::_emit` case `kEncodingVexRvm_Lx` (`vpxor`: `VEX.66.0F.WIG EF /r`) in
//! `erts/emulator/asmjit/x86/x86assembler.cpp`, OTP-29.1.1.

use super::core::{Imm, Opcode, Pp, Rm};
use super::{Emitter, EncodeError, Mem, Xmm, Ymm};

const VPXOR: Opcode = Opcode::m0f(0xEF).with_pp(Pp::P66);

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
}
