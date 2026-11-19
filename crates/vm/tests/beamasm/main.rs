#[allow(dead_code)]
#[path = "../common/mod.rs"]
mod common;

#[cfg(target_arch = "aarch64")]
mod asm_corpus;
#[cfg(target_arch = "x86_64")]
#[path = "asm_corpus_x86.rs"]
mod asm_corpus;
mod beamasm_kernels;
mod jit_apply;
mod jit_bs_match_heap;
mod jit_const_arith;
mod jit_gc_header;
mod jit_spawn;
mod jit_trap_args;
mod jit_update_record;
mod jit_xmem;
mod native_abi;
mod native_coverage_differential;
#[cfg(target_arch = "aarch64")]
mod native_hooks;
mod native_regress;
mod native_sig_fetch;
mod records_jit;
mod xreg_poison;
mod xreg_yield;
