//! Port of erts/emulator/beam/jit/x86/: the x86-64 BeamAsm assemblers (`BeamAssembler`,
//! `BeamGlobalAssembler`, `BeamModuleAssembler`), ABI and native entry/return, selected at
//! build time like erts selects jit/x86 versus jit/arm.

pub mod beam_asm;
pub mod beam_asm_global;
pub mod beam_asm_module;
#[allow(unsafe_code)]
pub mod rt;

pub use beam_asm::*;
pub use rt::enter_native_raw;
