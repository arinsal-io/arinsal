//! Raw allocation of the `ErtsNativeFunc` trap wrapper.
//!
//! Port of erts/emulator/beam/erl_nfunc_sched.c (erts_new_proc_nfunc, erts_destroy_nfunc:
//! `erts_alloc(ERTS_ALC_T_NFUNC_TRAP_WRAPPER, sizeof(ErtsNativeFunc) + (argc-1)*sizeof(Eterm))`),
//! OTP-29.1.1. Callers get a safe handle; every access to the variable-length block is here.

use super::ErtsNativeFunc;
use arinsal_term::Term;
use std::alloc::Layout;

/// An owned `ErtsNativeFunc` with room for `argv_size` saved arguments.
pub(crate) struct NativeFuncBox(std::ptr::NonNull<ErtsNativeFunc>);

// SAFETY: the wrapper belongs to one process; only the thread running that process (or its
// dirty job, while the process is not running elsewhere) touches it.
unsafe impl Send for NativeFuncBox {}

/// A wrapper address a dirty job carries while its process is scheduled out.
#[derive(Clone, Copy)]
pub(crate) struct NfuncPtr(pub(crate) *mut ErtsNativeFunc);
// SAFETY: the process is dirty-running; only its dirty job touches the wrapper meanwhile.
unsafe impl Send for NfuncPtr {}

fn layout(argv_size: usize) -> Layout {
    Layout::from_size_align(
        std::mem::size_of::<ErtsNativeFunc>() + argv_size.max(1) * std::mem::size_of::<Term>(),
        std::mem::align_of::<ErtsNativeFunc>(),
    )
    .expect("ErtsNativeFunc layout")
}

impl NativeFuncBox {
    /// `erts_alloc` of a wrapper for `argc` arguments, marked unused (`argc = -1`).
    pub(crate) fn new(argc: usize) -> Self {
        let layout = layout(argc);
        // SAFETY: the layout is non-zero sized; zeroed memory is a valid `ErtsNativeFunc`
        // (integers, null pointers and NIL-free argument words that are never read before
        // erts_nfunc_schedule writes them).
        let raw = unsafe { std::alloc::alloc_zeroed(layout) }.cast::<ErtsNativeFunc>();
        let Some(ptr) = std::ptr::NonNull::new(raw) else {
            std::alloc::handle_alloc_error(layout);
        };
        let mut nep = Self(ptr);
        nep.get_mut().argc = -1;
        nep.get_mut().argv_size = argc as i32;
        nep
    }

    pub(crate) fn get(&self) -> &ErtsNativeFunc {
        // SAFETY: the box owns a live, initialised wrapper.
        unsafe { self.0.as_ref() }
    }

    pub(crate) fn get_mut(&mut self) -> &mut ErtsNativeFunc {
        // SAFETY: the box owns a live, initialised wrapper, borrowed uniquely here.
        unsafe { self.0.as_mut() }
    }

    /// The wrapper's address (`ERTS_I_BEAM_OP_TO_NFUNC` inverts `&trampoline.call_bif_nif`).
    pub(crate) fn as_ptr(&self) -> *mut ErtsNativeFunc {
        self.0.as_ptr()
    }

    /// `nep->argv[0 .. argv_size]`.
    pub(crate) fn argv_mut(&mut self) -> &mut [Term] {
        let size = self.get().argv_size.max(0) as usize;
        // SAFETY: the allocation holds `argv_size` argument words after the fixed part.
        unsafe { std::slice::from_raw_parts_mut(self.get_mut().argv.as_mut_ptr(), size) }
    }
}

impl Drop for NativeFuncBox {
    fn drop(&mut self) {
        let layout = layout(self.get().argv_size.max(0) as usize);
        // SAFETY: allocated by `new` with this layout.
        unsafe { std::alloc::dealloc(self.0.as_ptr().cast(), layout) };
    }
}

/// The wrapper whose `trampoline.call_bif_nif` is at `i` (`ERTS_I_BEAM_OP_TO_NFUNC(I)`).
pub(crate) fn i_beam_op_to_nfunc(i: usize) -> *mut ErtsNativeFunc {
    i.wrapping_sub(std::mem::offset_of!(
        ErtsNativeFunc,
        trampoline.call_bif_nif
    )) as *mut _
}

/// The wrapper at `nep`, for the dirty job that runs while its process is scheduled out.
pub(crate) fn nfunc_at<'a>(nep: *mut ErtsNativeFunc) -> &'a mut ErtsNativeFunc {
    // SAFETY: `nep` is the process's `ERTS_PSD_NFUNC_TRAP_WRAPPER`, which stays allocated while
    // the process is dirty-running; only the dirty job touches it then.
    unsafe { &mut *nep }
}

/// `ErtsContainerStruct(current, ErtsNativeFunc, trampoline.info.mfa)->func`, read from code
/// laid out like a wrapper (a `call_nif` sequence) or from a live wrapper.
pub(crate) fn container_func(current: usize) -> usize {
    let mfa_offset = std::mem::offset_of!(ErtsNativeFunc, trampoline.info.mfa);
    let func_offset = std::mem::offset_of!(ErtsNativeFunc, func);
    // SAFETY: `current` is the MFA of a function whose body is `call_nif` code
    // (load_nif_1st_finisher), of its `ErtsNifBeamStub`, or of a live wrapper; all hold the
    // `func` word at this offset.
    unsafe { *((current - mfa_offset + func_offset) as *const usize) }
}

/// `*(BeamInstr *) I`: the first word of the code at `i`.
pub(crate) fn code_word(i: usize) -> usize {
    if i == 0 {
        return 0;
    }
    // SAFETY: `i` is a process's `c_p->i`: live code or a live wrapper trampoline.
    unsafe { *(i as *const usize) }
}

/// `nep->argv[0 .. argv_size]` of the wrapper at `nep`.
pub(crate) fn nfunc_argv<'a>(nep: *mut ErtsNativeFunc) -> &'a mut [Term] {
    // SAFETY: `nep` is a live wrapper allocated by `NativeFuncBox::new` with `argv_size` words.
    unsafe {
        let size = (*nep).argv_size.max(0) as usize;
        std::slice::from_raw_parts_mut(std::ptr::addr_of_mut!((*nep).argv).cast::<Term>(), size)
    }
}
