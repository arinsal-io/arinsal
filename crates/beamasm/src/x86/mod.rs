//! Port of erts/emulator/beam/jit/x86/: the x86-64 BeamAsm assemblers (`BeamAssembler`,
//! `BeamGlobalAssembler`, `BeamModuleAssembler`), ABI and native entry/return, selected at
//! build time like erts selects jit/x86 versus jit/arm.

pub mod beam_asm;
pub mod beam_asm_global;
pub mod beam_asm_module;
#[cfg(test)]
#[allow(unsafe_code)]
mod codegen_tests;
pub mod instr_arith;
pub mod instr_bif;
pub mod instr_bs;
pub mod instr_call;
pub mod instr_common;
pub mod instr_float;
pub mod instr_fun;
pub mod instr_guard_bifs;
pub mod instr_map;
pub mod instr_msg;
pub mod instr_select;
#[cfg(test)]
mod jdump;
pub mod process_main;
#[allow(unsafe_code)]
pub mod rt;

pub use beam_asm::*;
pub use rt::enter_native_raw;
