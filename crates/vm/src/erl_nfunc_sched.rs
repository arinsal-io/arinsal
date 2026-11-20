//! Native function (BIF/NIF) trap wrapper: a call that reschedules itself keeps its original
//! state here while the process runs the trampoline.
//!
//! Port of erts/emulator/beam/erl_nfunc_sched.c and erl_nfunc_sched.h, OTP-29.1.1.

mod raw;

use crate::Process;
use arinsal_beamasm::common::beam_asm_h::{BEAM_ASM_NFUNC_SIZE, ErtsCodeInfo};
use arinsal_term::{ErtsCodeMfa, Term};
pub(crate) use raw::{
    NativeFuncBox, NfuncPtr, code_word, container_func, i_beam_op_to_nfunc, nfunc_argv, nfunc_at,
};

/// `ErtsNativeFunc.trampoline`: laid out like the head of a `call_nif` sequence, so
/// `dispatch_nif` reaches `call_nif_shared` with `I = &call_bif_nif`.
#[repr(C)]
pub(crate) struct Trampoline {
    pub(crate) info: ErtsCodeInfo,
    pub(crate) call_bif_nif: [u8; BEAM_ASM_NFUNC_SIZE],
    pub(crate) dfunc: usize,
}

/// `ErtsNativeFunc` (erl_nfunc_sched.h). `argc >= 0` while in use, `< 0` when not.
#[repr(C)]
pub(crate) struct ErtsNativeFunc {
    pub(crate) trampoline: Trampoline,
    /// `struct erl_module_nif *`: a `dynlib_refc` reference to the NIF library, or 0 for a BIF.
    pub(crate) m: usize,
    /// Indirect NIF or BIF to execute.
    pub(crate) func: usize,
    /// `current` as set when originally called.
    pub(crate) current: *const ErtsCodeMfa,
    pub(crate) pc: usize,
    pub(crate) mfa: *const ErtsCodeMfa,
    pub(crate) argc: i32,
    pub(crate) argv_size: i32,
    pub(crate) argv: [Term; 0],
}

// `call_nif_shared` reads `Func` at I+16 and `NifMod` at I+24; `static_schedule_dirty_nif`
// reads `func` at I+32 (erl_nfunc_sched.h with BEAMASM, beam_asm.h BEAM_ASM_NFUNC_SIZE).
const _: () = {
    let i = std::mem::offset_of!(ErtsNativeFunc, trampoline.call_bif_nif);
    assert!(std::mem::offset_of!(ErtsNativeFunc, trampoline.info.mfa) + 24 == i);
    assert!(std::mem::offset_of!(ErtsNativeFunc, trampoline.dfunc) == i + 16);
    assert!(std::mem::offset_of!(ErtsNativeFunc, m) == i + 24);
    assert!(std::mem::offset_of!(ErtsNativeFunc, func) == i + 32);
};

impl ErtsNativeFunc {
    /// `&nep->trampoline.call_bif_nif`, the `c_p->i` of a scheduled call.
    pub(crate) fn trampoline_i(&self) -> usize {
        std::ptr::from_ref(&self.trampoline.call_bif_nif) as usize
    }
}

/// `ERTS_PROC_GET_NFUNC_TRAP_WRAPPER(p)`.
pub(crate) fn get_nfunc_trap_wrapper(p: &mut Process) -> Option<&mut NativeFuncBox> {
    crate::proc_create::raw::erts_psd_get_mut(
        &mut p.psd,
        crate::proc_create::raw::ERTS_PSD_NFUNC_TRAP_WRAPPER,
    )
}

/// Port of erts/emulator/beam/erl_nfunc_sched.c (erts_new_proc_nfunc), OTP-29.1.1.
pub(crate) fn erts_new_proc_nfunc(c_p: &mut Process, argc: usize) -> &mut NativeFuncBox {
    // ERTS_PROC_SET_NFUNC_TRAP_WRAPPER frees the old wrapper.
    crate::proc_create::raw::erts_psd_set(
        &mut c_p.psd,
        crate::proc_create::raw::ERTS_PSD_NFUNC_TRAP_WRAPPER,
        Some(Box::new(NativeFuncBox::new(argc))),
    );
    get_nfunc_trap_wrapper(c_p).expect("new process NIF wrapper")
}

/// Port of erts/emulator/beam/erl_nfunc_sched.c (erts_destroy_nfunc), OTP-29.1.1.
pub(crate) fn erts_destroy_nfunc(p: &mut Process) {
    let nep = crate::proc_create::raw::erts_psd_set::<NativeFuncBox>(
        &mut p.psd,
        crate::proc_create::raw::ERTS_PSD_NFUNC_TRAP_WRAPPER,
        None,
    );
    if let Some(mut nep) = nep.map(|nep| *nep)
        && nep.get().m != 0
    {
        crate::natives::nif::erts_nfunc_cleanup_nif_mod(nep.get_mut());
    }
}

/// Port of erts/emulator/beam/erl_nfunc_sched.h (erts_get_proc_nfunc), OTP-29.1.1.
pub(crate) fn erts_get_proc_nfunc(c_p: &mut Process, argc: usize) -> &mut NativeFuncBox {
    let fits = get_nfunc_trap_wrapper(c_p)
        .is_some_and(|nep| !(nep.get().argc < 0 && (nep.get().argv_size as usize) < argc));
    if !fits {
        return erts_new_proc_nfunc(c_p, argc);
    }
    get_nfunc_trap_wrapper(c_p).expect("wrapper checked above")
}

/// The process fields `erts_nfunc_schedule` writes: `c_p` on a normal scheduler, the dirty
/// shadow process on a dirty one.
pub(crate) struct UsedProc<'a> {
    pub(crate) i: &'a mut *const core::ffi::c_void,
    pub(crate) arity: &'a mut u8,
    pub(crate) freason: &'a mut u64,
}

/// Port of erts/emulator/beam/erl_nfunc_sched.c (erts_nfunc_schedule), OTP-29.1.1. `nep` is
/// `erts_get_proc_nfunc(c_p, mfa->arity)` (first schedule) or the wrapper in use; `reg` is
/// `esdp->registers->x_reg_array`. The caller does `ERTS_VBUMP_ALL_REDS` on a normal
/// scheduler.
#[allow(clippy::too_many_arguments)]
pub(crate) fn erts_nfunc_schedule(
    nep: &mut ErtsNativeFunc,
    first: Option<(&mut [Term], &ErtsCodeMfa, usize, *const ErtsCodeMfa)>,
    used_proc: UsedProc<'_>,
    reg: &mut [Term],
    (instr, dfunc, ifunc): (usize, usize, usize),
    (module, func): (Term, Term),
    argv: &[Term],
) {
    if nep.argc < 0 {
        // First schedule; save things that might need to be restored.
        let (saved, mfa, pc, current) = first.expect("first erts_nfunc_schedule has an mfa");
        let arity = mfa.arity;
        saved[..arity].copy_from_slice(&reg[..arity]);
        nep.pc = pc;
        nep.mfa = std::ptr::from_ref(mfa);
        nep.current = current;
        nep.argc = arity as i32;
        nep.m = 0;
    }
    // Copy new arguments into the register array if necessary.
    if reg.as_ptr() != argv.as_ptr() {
        reg[..argv.len()].copy_from_slice(argv);
    }
    nep.trampoline.info.mfa.module = crate::native_hooks::raw(module);
    nep.trampoline.info.mfa.function = crate::native_hooks::raw(func);
    nep.trampoline.info.mfa.arity = argv.len();
    nep.trampoline.dfunc = dfunc;
    nep.func = ifunc;
    *used_proc.arity = argv.len() as u8;
    *used_proc.freason = arinsal_term::exc::TRAP;
    // call_bif || call_nif
    nep.trampoline.call_bif_nif[..std::mem::size_of::<usize>()]
        .copy_from_slice(&instr.to_ne_bytes());
    *used_proc.i = nep.trampoline_i() as *const _;
}

/// Port of erts/emulator/beam/erl_nfunc_sched.h (erts_setup_nfunc_rootset), OTP-29.1.1: the
/// saved arguments of a wrapper in use are GC roots.
pub(crate) fn erts_setup_nfunc_rootset(wrapper: Option<&mut NativeFuncBox>) -> Option<&mut [Term]> {
    let nep = wrapper?;
    let argc = nep.get().argc;
    if argc <= 0 {
        return None;
    }
    Some(&mut nep.argv_mut()[..argc as usize])
}

/// Port of erts/emulator/beam/erl_nfunc_sched.h (erts_check_nfunc_in_area), OTP-29.1.1.
pub(crate) fn erts_check_nfunc_in_area(p: &mut Process, in_area: impl Fn(usize) -> bool) -> bool {
    let Some(nep) = get_nfunc_trap_wrapper(p) else {
        return false;
    };
    let nep = nep.get();
    if nep.argc < 0 {
        return false;
    }
    in_area(nep.pc) || in_area(nep.mfa as usize) || in_area(nep.current as usize)
}

/// Port of erts/emulator/beam/erl_nfunc_sched.h (erts_nfunc_restore), OTP-29.1.1.
pub(crate) fn erts_nfunc_restore(current: &mut *const core::ffi::c_void, ep: &mut ErtsNativeFunc) {
    *current = ep.current.cast();
    ep.argc = -1; // Unused nif-export marker.
}

/// Port of erts/emulator/beam/erl_nfunc_sched.h (erts_nfunc_restore_error), OTP-29.1.1:
/// `pc`, the original MFA and arguments of the call for `handle_error`.
pub(crate) fn erts_nfunc_restore_error(
    c_p: &mut Process,
    pc: &mut usize,
    reg: &mut [Term],
    nif_mfa: &mut u64,
) {
    let mut current = c_p.heap.abi.current;
    let nep = get_nfunc_trap_wrapper(c_p).expect("EXF_RESTORE_NFUNC with a wrapper");
    *pc = nep.get().pc;
    *nif_mfa = nep.get().mfa as u64;
    let argc = nep.get().argc.max(0) as usize;
    reg[..argc].copy_from_slice(&nep.argv_mut()[..argc]);
    erts_nfunc_restore(&mut current, nep.get_mut());
    c_p.heap.abi.current = current;
}

/// Whether `c_p->i` is the trampoline of the process's wrapper in use:
/// `BeamIsOpCode(*c_p->i, op_call_nif_WWW)` for the dirty scheduler loop.
pub(crate) fn i_is_call_nif(p: &mut Process) -> bool {
    let i = p.heap.abi.i as usize;
    get_nfunc_trap_wrapper(p)
        .is_some_and(|nep| nep.get().argc >= 0 && nep.get().trampoline_i() == i)
        && code_word(i) == arinsal_term::OP_CALL_NIF_WWW
}

/// The MFA of the trampoline `c_p->i` is at, when the process is about to run a scheduled
/// wrapper call.
pub(crate) fn trampoline_mfa(p: &mut Process) -> Option<(&'static str, &'static str, u32)> {
    if !i_is_call_nif(p) {
        return None;
    }
    let mfa = &get_nfunc_trap_wrapper(p)?.get().trampoline.info.mfa;
    let atoms = arinsal_term::global_atoms();
    let module = atoms.text(crate::native_hooks::from_raw(mfa.module).as_atom()?)?;
    let function = atoms.text(crate::native_hooks::from_raw(mfa.function).as_atom()?)?;
    Some((module, function, mfa.arity as u32))
}
