//! Golden-byte tests of `arinsal_x64::enc`, one module per instruction family
//! (`docs/design/x86_encoder_api.md`).

mod golden;

mod alu;
mod asmjit_oracle;
mod avx;
mod bmi;
mod branch;
mod cond;
mod cpu;
mod mem;
mod misc;
mod mov;
mod muldiv;
mod operand;
mod oracle_cases;
mod oracle_run;
mod shift;
mod sse;
mod stack;
