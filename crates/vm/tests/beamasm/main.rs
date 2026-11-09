#[allow(dead_code)]
#[path = "../common/mod.rs"]
mod common;

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
mod native_hooks;
mod native_regress;
mod native_sig_fetch;
mod records_jit;
mod xreg_poison;
mod xreg_yield;
