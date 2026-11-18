//! x86_64 machine-code support for Arinsal's BeamAsm port.
//!
//! `buf` owns code and data sections, `enc` encodes instructions (`docs/design/x86_encoder_api.md`).

pub mod buf;
pub mod enc;
#[cfg(target_arch = "x86_64")]
pub mod exec;
