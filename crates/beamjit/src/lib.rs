#![forbid(unsafe_code)]
//! The loader side of BeamAsm. As erts builds erts/emulator/beam/jit/ with exactly one of
//! jit/arm or jit/x86, the target-independent part (asm_load.c's operand massaging, the
//! literals the load adds, beam_jit_main.cpp's shared types) is `beam_asm`, and the module
//! assembler driver of the target is `arm` or `x86`, re-exported here as one facade.

mod beam_asm;
pub use beam_asm::*;

#[cfg(target_arch = "aarch64")]
mod arm;
#[cfg(target_arch = "aarch64")]
pub use arm::*;

#[cfg(target_arch = "x86_64")]
mod x86;
#[cfg(target_arch = "x86_64")]
pub use x86::*;
