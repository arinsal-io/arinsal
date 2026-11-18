//! EVEX forms used by OTP's x86 `emit_copy_words` implementation.
//!
//! Port of `BeamModuleAssembler::emit_copy_words` in
//! `erts/emulator/beam/jit/x86/beam_asm.hpp` and asmjit
//! `InstDB::kEncodingVexRmMr_Lx` / `EmitVexEvexM` in
//! `erts/emulator/asmjit/x86/x86assembler.cpp`, OTP-29.1.1.

use super::core::{Imm, Opcode};
use super::{Emitter, EncodeError, Mem, Zmm};

const VMOVUPS_LOAD: Opcode = Opcode::m0f(0x10);
const VMOVUPS_STORE: Opcode = Opcode::m0f(0x11);

impl Emitter {
    fn zmm_id(reg: Zmm) -> Result<u8, EncodeError> {
        if reg.0 > 31 {
            return Err(EncodeError::InvalidVecRegister(reg.0));
        }
        Ok(reg.0)
    }

    /// Emits asmjit `a.vmovups(zmm, Mem)` as used by x86 `emit_copy_words`.
    pub fn vmovups_zm(&mut self, dst: Zmm, src: Mem) -> Result<(), EncodeError> {
        self.evex_rm_512(VMOVUPS_LOAD, Self::zmm_id(dst)?, &src, Imm::NONE)
    }

    /// Emits asmjit `a.vmovups(Mem, zmm)` as used by x86 `emit_copy_words`.
    pub fn vmovups_mz(&mut self, dst: Mem, src: Zmm) -> Result<(), EncodeError> {
        self.evex_rm_512(VMOVUPS_STORE, Self::zmm_id(src)?, &dst, Imm::NONE)
    }
}
