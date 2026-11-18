//! Golden-byte tests of `arinsal_x64::enc`, one module per instruction family
//! (`docs/design/x86_encoder_api.md`).

mod golden;

mod alu;
mod avx;
mod branch;
mod cond;
mod mem;
mod mov;
mod operand;
