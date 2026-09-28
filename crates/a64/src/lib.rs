//! AArch64 machine-code support for Arinsal's BeamAsm port (`docs/arch/beamasm-port.md`).
//!
//! `enc` encodes instructions, `exec` owns executable memory.

pub mod buf;
pub mod enc;
pub mod exec;
