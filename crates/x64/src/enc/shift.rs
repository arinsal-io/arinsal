//! Shift and rotate instruction forms.
//!
//! Port of `x86::Assembler::_emit` case `kEncodingX86Rot` in
//! `erts/emulator/asmjit/x86/x86assembler.cpp`, OTP-29.1.1.

use super::core::{ByteRex, Imm, Opcode, Rm};
use super::{Emitter, EncodeError, Gp};

#[derive(Clone, Copy)]
enum Operation {
    Shl,
    Shr,
    Sar,
    Rol,
    Ror,
}

impl Operation {
    const fn extension(self) -> u8 {
        match self {
            Self::Shl => 4,
            Self::Shr => 5,
            Self::Sar => 7,
            Self::Rol => 0,
            Self::Ror => 1,
        }
    }
}

impl Emitter {
    fn shift_imm(&mut self, dst: Gp, count: i64, operation: Operation) -> Result<(), EncodeError> {
        if !matches!(dst.size(), 1 | 2 | 4 | 8) {
            return Err(EncodeError::InvalidInstruction);
        }
        let count = count as u8;
        let mut opcode = Opcode::legacy(0xD0).arith_by_size(dst.size());
        let mut rex = ByteRex::default();
        let dst = Self::gp_id(dst, &mut rex)?;
        let imm = if count == 1 {
            Imm::NONE
        } else {
            opcode.byte -= 0x10;
            Imm::new(count.into(), 1)
        };
        self.x86_rm(opcode, operation.extension(), Rm::Reg(dst), rex, imm)
    }

    fn shift_cl(&mut self, dst: Gp, count: Gp, operation: Operation) -> Result<(), EncodeError> {
        if count.id != 1 {
            return Err(EncodeError::InvalidInstruction);
        }
        if !matches!(dst.size(), 1 | 2 | 4 | 8) {
            return Err(EncodeError::InvalidInstruction);
        }
        let mut opcode = Opcode::legacy(0xD0).arith_by_size(dst.size());
        opcode.byte += 2;
        let mut rex = ByteRex::default();
        let dst = Self::gp_id(dst, &mut rex)?;
        self.x86_rm(opcode, operation.extension(), Rm::Reg(dst), rex, Imm::NONE)
    }
}

macro_rules! shift_methods {
    ($imm:ident, $cl:ident, $name:literal, $operation:ident) => {
        impl Emitter {
            #[doc = concat!("`", $name, " reg, imm` (asmjit `a.", $name, "(Gp, Imm)`).")]
            pub fn $imm(&mut self, dst: Gp, count: i64) -> Result<(), EncodeError> {
                self.shift_imm(dst, count, Operation::$operation)
            }

            #[doc = concat!("`", $name, " reg, cl` (asmjit `a.", $name, "(Gp, Gp)`); asmjit selects the CL form by register id.")]
            pub fn $cl(&mut self, dst: Gp, count: Gp) -> Result<(), EncodeError> {
                self.shift_cl(dst, count, Operation::$operation)
            }
        }
    };
}

shift_methods!(shl_ri, shl_rr, "shl", Shl);
shift_methods!(shr_ri, shr_rr, "shr", Shr);
shift_methods!(sar_ri, sar_rr, "sar", Sar);
shift_methods!(rol_ri, rol_rr, "rol", Rol);
shift_methods!(ror_ri, ror_rr, "ror", Ror);
