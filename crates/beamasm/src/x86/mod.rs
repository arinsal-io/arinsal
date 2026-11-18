//! Port of erts/emulator/beam/jit/x86/: the x86-64 BeamAsm ABI (register map, runtime call
//! convention, frame layout) and native entry/return, selected at build time like erts
//! selects jit/x86 versus jit/arm.

pub(crate) mod beam_asm;
#[allow(unsafe_code)]
pub mod rt;

pub use beam_asm::*;
pub use rt::enter_native_raw;
