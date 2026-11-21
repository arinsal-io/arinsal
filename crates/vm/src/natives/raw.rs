//! Checked raw-term access needed by native BIF bodies.
//!
//! Port of erts/emulator/beam/erl_term.h (typed term accessors), OTP-29.1.1. Heap terms passed
//! here are live in the running process and stay unmoved until the accessor returns.

use arinsal_term::Term;
use num_bigint::BigInt;

/// Copy the first `N` terms and the arity of a live tuple.
pub(crate) fn tuple_prefix<const N: usize>(term: Term) -> Option<(usize, [Term; N])> {
    // SAFETY: callers pass a BIF argument rooted in the running process heap, which stays live
    // and unmoved until the BIF returns.
    let tuple = unsafe { term.tuple_ref() }?;
    let mut prefix = [Term::NIL; N];
    for (index, slot) in prefix.iter_mut().enumerate() {
        let Some(element) = tuple.get(index) else {
            break;
        };
        *slot = element;
    }
    Some((tuple.len(), prefix))
}

/// The integer represented by a small integer or live bignum.
pub(crate) fn integer(term: Term) -> Option<BigInt> {
    if let Some(value) = term.as_small() {
        return Some(BigInt::from(value));
    }
    big_integer(term)
}

fn big_integer(term: Term) -> Option<BigInt> {
    // SAFETY: BIF arguments are rooted in the running process heap for the whole call.
    unsafe { term.big_ref() }.map(|value| value.to_bigint())
}

/// The IEEE 754 value of a live float term.
pub(crate) fn float(term: Term) -> Option<f64> {
    // SAFETY: BIF arguments are rooted in the running process heap for the whole call.
    unsafe { term.float_ref() }.map(|value| value.get())
}

/// Arity of a local or exported function term.
pub(crate) fn fun_arity(term: Term) -> Option<u32> {
    term.fun_arity().map(u32::from)
}

/// The `ErtsCodeMFA` at `address`: inside the `ErtsCodeInfo` of loaded native code or of an
/// `ErtsNifBeamStub`.
// Port of erts/emulator/beam/code_ix.h (erts_code_to_codemfa), OTP-29.1.1.
pub(crate) fn code_mfa(address: usize) -> &'static arinsal_term::ErtsCodeMfa {
    // SAFETY: callers pass the MFA of an `ErtsCodeInfo` that stays allocated while its code
    // runs: module code until purge, an `ErtsNifBeamStub` until load_nif_3rd_finisher.
    unsafe { &*(address as *const arinsal_term::ErtsCodeMfa) }
}

/// The `ErtsCodeInfo` at `ci`: in front of loaded native code.
pub(crate) fn code_info(ci: usize) -> &'static arinsal_beamasm::common::beam_asm_h::ErtsCodeInfo {
    // SAFETY: callers pass the `ErtsCodeInfo` of a function of a loaded module, which stays
    // allocated until the module is purged.
    unsafe { &*(ci as *const arinsal_beamasm::common::beam_asm_h::ErtsCodeInfo) }
}

/// The export entry whose `info` is at `ci` (`ErtsContainerStruct(ci, Export, info)`).
pub(crate) fn export_of_info(ci: usize) -> &'static arinsal_term::ExportEntry {
    // SAFETY: callers pass the address of an `Export.info`, the field at `EXPORT_INFO_OFFSET`
    // of an export entry, which the export table never frees.
    unsafe {
        &*((ci - arinsal_term::EXPORT_INFO_OFFSET as usize) as *const arinsal_term::ExportEntry)
    }
}

/// The NIF function signature of `ErlNifFunc.fptr`.
pub(crate) type NifFptr = arinsal_nif::NifFn;

/// The NIF function a `call_nif` sequence calls (`Func` of erts).
pub(crate) fn nif_fptr(fp: usize) -> Option<NifFptr> {
    // SAFETY: `fp` is the `Func` word beamasm_emit_call_nif wrote: an `ErlNifFunc.fptr` of a
    // loaded library or a static_schedule_dirty_*_nif function, both with the NIF signature.
    unsafe { std::mem::transmute::<usize, Option<NifFptr>>(fp) }
}

/// A reference to the `struct erl_module_nif` a `call_nif` sequence was built with.
pub(crate) fn nif_mod(nif_mod: usize) -> std::sync::Arc<crate::natives::nif::ModuleNif> {
    let pointer = nif_mod as *const crate::natives::nif::ModuleNif;
    // SAFETY: `call_nif` code carries `Arc::as_ptr` of the library loaded into its module
    // instance, which MODULE_NIFS keeps until the instance is purged; purged code is not run,
    // so the count is above zero while the code calls in.
    unsafe {
        std::sync::Arc::increment_strong_count(pointer);
        std::sync::Arc::from_raw(pointer)
    }
}

/// Take back the `dynlib_refc` reference an `ErtsNativeFunc.m` holds (`nfunc_cleanup_nif_mod`).
pub(crate) fn nif_mod_from_raw(m: usize) -> std::sync::Arc<crate::natives::nif::ModuleNif> {
    // SAFETY: `m` was produced by `Arc::into_raw` in erl_nif.c `schedule()` and is taken back
    // once, when the wrapper is restored or destroyed (the caller zeroes `m`).
    unsafe { std::sync::Arc::from_raw(m as *const crate::natives::nif::ModuleNif) }
}

/// `c_p` of `esdp->current_nif` on a normal scheduler.
pub(crate) fn current_nif_proc<'a>(c_p: *mut crate::Process) -> Option<&'a mut crate::Process> {
    // SAFETY: `beam_jit_call_nif` sets `c_p` to the process it runs for the span of the NIF
    // call on this thread; the NIF code runs inside that call.
    unsafe { c_p.as_mut() }
}

/// `esdp->registers->x_reg_array` of the running NIF call.
pub(crate) fn current_nif_reg<'a>(reg: *mut Term, len: usize) -> &'a mut [Term] {
    // SAFETY: the register array the NIF call was entered with, live for the call.
    unsafe { std::slice::from_raw_parts_mut(reg, len) }
}

/// The dirty shadow process of the running dirty NIF call.
pub(crate) fn shadow_heap<'a>(
    shadow: *mut arinsal_term::ProcessHeap,
) -> &'a mut arinsal_term::ProcessHeap {
    // SAFETY: the dirty job's shadow heap, live for the span of the dirty NIF call.
    unsafe { &mut *shadow }
}

/// `(*fp)(env, argc, argv)` for the function word of an `ErtsNativeFunc`.
pub(crate) fn call_nif_fn(
    fp: usize,
    env: *mut arinsal_nif::ErlNifEnv,
    argc: std::ffi::c_int,
    argv: *const Term,
) -> Term {
    let Some(fp) = nif_fptr(fp) else {
        return arinsal_nif::enif_make_badarg(env);
    };
    // SAFETY: `fp` is the NIF `enif_schedule_nif` scheduled; `env` and `argv` are the live
    // arguments the call_nif trampoline passed.
    unsafe { fp(env, argc, argv) }
}

/// `argv[0 .. argc]` of a NIF call.
pub(crate) fn nif_argv<'a>(argv: *const Term, argc: usize) -> &'a [Term] {
    if argc == 0 || argv.is_null() {
        return &[];
    }
    // SAFETY: a NIF passes a live array of `argc` terms.
    unsafe { std::slice::from_raw_parts(argv, argc) }
}
