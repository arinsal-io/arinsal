//! Checked x86_64 instruction encodings used by the BeamAsm port.
//!
//! Port of the asmjit x86 assembler that erts' `jit/x86` emits through
//! (`erts/emulator/asmjit/x86/x86assembler.cpp`, `x86::Assembler::_emit`, OTP-29.1.1),
//! configured as erts configures it (`beam_jit_common.cpp`: `EncodingOptions::kOptimizeForSize`,
//! no base address). Every method picks the same encoding asmjit picks for that call, so the
//! `jit/x86/*.cpp` emitters port 1:1. Families live in their own files as `impl Emitter` blocks;
//! the shared prefix/ModRM/SIB/immediate machinery is in `core`. See `docs/design/x86_encoder_api.md`.
//!
//! Method names are the asmjit mnemonic plus an operand-shape suffix: `r` = [`Gp`], `m` = [`Mem`],
//! `i` = immediate, `x` = [`Xmm`], `y` = [`Ymm`] (`add_ri` is asmjit `a.add(Gp, Imm)`).

mod alu;
mod avx;
mod branch;
mod cond;
mod core;
mod misc;
mod mov;
mod muldiv;
mod operand;
mod shift;
mod stack;

pub use cond::CondCode;
pub use operand::*;

use std::fmt;

/// Encoding validation failure, named after the asmjit error asmjit returns for the same input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EncodeError {
    /// Register id out of range, or a view the form does not accept (asmjit `kInvalidPhysId` /
    /// `kInvalidInstruction`).
    InvalidRegister(Gp),
    /// Vector register id out of range.
    InvalidVecRegister(u8),
    /// Register operands of different sizes (asmjit `kOperandSizeMismatch`).
    OperandSizeMismatch,
    /// Immediate not encodable in the form (asmjit `kInvalidImmediate`).
    InvalidImmediate(i64),
    /// `ah`/`ch`/`dh`/`bh` combined with an operand that needs a REX prefix (asmjit `kInvalidRexPrefix`).
    InvalidRexPrefix,
    /// Base/index combination not encodable in 64-bit mode (asmjit `kInvalidAddress`).
    InvalidAddress,
    /// `rsp` as index, or index of the wrong width (asmjit `kInvalidAddressIndex`).
    InvalidAddressIndex,
    /// Memory operand without a size where the form needs one (asmjit `kAmbiguousOperandSize`).
    AmbiguousOperandSize,
    /// Code alignment is not a power of two from 1 through 64 (asmjit `kInvalidArgument`).
    InvalidAlignment,
    /// Operand combination the instruction has no encoding for (asmjit `kInvalidInstruction`).
    InvalidInstruction,
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for EncodeError {}

/// Position of a RIP-relative displacement in the last emitted instruction.
///
/// asmjit encodes `[label]` as `[rip + disp32]` with `disp32 = label - end_of_instruction + disp`
/// (`EmitModSib`, `kX86MemInfo_BaseLabel`). The label layer emits with [`Mem::rip`]`(disp)` and
/// patches the four bytes at `disp_at` with `label_offset - end + disp` once the label is bound.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RipFixup {
    /// Byte offset of the 32-bit displacement in [`Emitter::bytes`].
    pub disp_at: usize,
    /// Byte offset just past the instruction (the RIP value the displacement is relative to).
    pub end: usize,
}

/// Instruction bytes emitted so far.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Emitter {
    /// Encoded bytes.
    pub bytes: Vec<u8>,
    last_rip: Option<RipFixup>,
}

impl Emitter {
    /// Creates an empty emitter.
    pub fn new() -> Self {
        Self::default()
    }
    /// Creates an emitter with a reserved byte buffer.
    pub fn with_capacity(bytes: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(bytes),
            last_rip: None,
        }
    }
    /// Returns the current byte length.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }
    /// Returns whether nothing has been emitted.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
    /// The RIP-relative displacement of the instruction emitted last, if it had a `[rip]` operand.
    pub fn last_rip_fixup(&self) -> Option<RipFixup> {
        self.last_rip
    }
}
