//! x86_64 machine-code support for Arinsal's BeamAsm port.
//!
//! `buf` owns code and data sections, `enc` encodes instructions (`docs/design/x86_encoder_api.md`).
//! Port of `erts/emulator/beam/jit/beam_jit_main.cpp` executable-memory APIs, OTP-29.1.1.

#![deny(unsafe_code)]

pub mod buf;
pub mod enc;
#[cfg(target_arch = "x86_64")]
#[allow(unsafe_code)]
pub mod exec;
