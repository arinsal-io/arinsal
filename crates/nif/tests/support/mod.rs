//! Test-only stand-in for the VM's `enif_schedule_nif` in the VM-less NIF harness.
//!
//! erts' `enif_schedule_nif` (erl_nif.c:3539-3583, OTP-29.1.1) installs an `ErtsNativeFunc`
//! trampoline in the calling process; Arinsal ports it in `arinsal-vm` (natives/nif.rs). These
//! test binaries load real NIF libraries with no VM and no process, so they provide the symbol
//! themselves: the continuation runs at once in the same environment, which is what the
//! process observes once its trampoline has run.

use arinsal_nif::{ErlNifEnv, NifFn};
use arinsal_term::Term;
use std::ffi::{c_char, c_int};

#[unsafe(no_mangle)]
pub extern "C" fn enif_schedule_nif(
    env: *mut ErlNifEnv,
    _fun_name: *const c_char,
    _flags: c_int,
    fp: Option<NifFn>,
    argc: c_int,
    argv: *const Term,
) -> Term {
    let Some(fp) = fp else {
        return arinsal_nif::enif_make_badarg(env);
    };
    // SAFETY: the NIF passes its live environment and an array of `argc` terms.
    unsafe { fp(env, argc, argv) }
}
