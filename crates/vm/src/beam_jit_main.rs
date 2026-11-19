//! Port of erts/emulator/beam/jit/beam_jit_main.cpp (the code pointers of beam_common.h and
//! `beamasm_init`), OTP-29.1.1: the arch-neutral addresses the emulator enters the JIT's
//! shared code through. `beamasm_init` of the target backend (jit/arm or jit/x86, chosen at
//! build time) fills them once, before `init_emulator` installs the BIF exports; the rest of
//! the VM reads them and never names a backend item.

use std::sync::atomic::{AtomicUsize, Ordering};

// Port of erts/emulator/beam/jit/beam_jit_main.cpp:56-65 (the `ErtsCodePtr` globals declared
// in beam_common.h:280-289), OTP-29.1.1. Written once by `beamasm_init` before any code index
// exists; every reader reaches them through the code indexes created after it.
static BEAM_RUN_PROCESS: AtomicUsize = AtomicUsize::new(0);
static BEAM_EXPORT_TRAMPOLINE: AtomicUsize = AtomicUsize::new(0);
static BEAM_SAVE_CALLS_EXPORT: AtomicUsize = AtomicUsize::new(0);
static BEAM_SAVE_CALLS_FUN: AtomicUsize = AtomicUsize::new(0);
static BEAM_UNLOADED_FUN: AtomicUsize = AtomicUsize::new(0);
static BEAM_I_LINE_BREAKPOINT_CLEANUP: AtomicUsize = AtomicUsize::new(0);

/// The code pointers `beamasm_init` of a backend publishes (beam_jit_main.cpp:373-397).
pub(crate) struct BeamCodePtrs {
    /// `beam_run_process`.
    pub(crate) run_process: usize,
    /// `beam_export_trampoline`.
    pub(crate) export_trampoline: usize,
    /// `beam_save_calls_export`.
    pub(crate) save_calls_export: usize,
    /// `beam_save_calls_fun`.
    pub(crate) save_calls_fun: usize,
    /// `beam_unloaded_fun`.
    pub(crate) unloaded_fun: usize,
    /// `beam_i_line_breakpoint_cleanup`.
    pub(crate) i_line_breakpoint_cleanup: usize,
}

/// Stores the code pointers of the backend's global code.
// Port of erts/emulator/beam/jit/beam_jit_main.cpp:373-397 (beamasm_init: the
// `beam_* = bga->get_*()` assignments), OTP-29.1.1.
pub(crate) fn publish(ptrs: &BeamCodePtrs) {
    BEAM_RUN_PROCESS.store(ptrs.run_process, Ordering::Relaxed);
    BEAM_EXPORT_TRAMPOLINE.store(ptrs.export_trampoline, Ordering::Relaxed);
    BEAM_SAVE_CALLS_EXPORT.store(ptrs.save_calls_export, Ordering::Relaxed);
    BEAM_SAVE_CALLS_FUN.store(ptrs.save_calls_fun, Ordering::Relaxed);
    BEAM_UNLOADED_FUN.store(ptrs.unloaded_fun, Ordering::Relaxed);
    BEAM_I_LINE_BREAKPOINT_CLEANUP.store(ptrs.i_line_breakpoint_cleanup, Ordering::Relaxed);
    crate::fun_dispatch::init(ptrs.unloaded_fun, ptrs.save_calls_fun);
}

/// `beam_run_process`: where a process scheduled in for the first time enters `apply/3`.
pub(crate) fn beam_run_process() -> usize {
    BEAM_RUN_PROCESS.load(Ordering::Relaxed)
}

/// `beam_export_trampoline`: the address of an export without code.
pub(crate) fn beam_export_trampoline() -> usize {
    BEAM_EXPORT_TRAMPOLINE.load(Ordering::Relaxed)
}

/// `beam_save_calls_export`: the address of every export in the save-calls code index.
pub(crate) fn beam_save_calls_export() -> usize {
    BEAM_SAVE_CALLS_EXPORT.load(Ordering::Relaxed)
}

/// `beam_i_line_breakpoint_cleanup`: the return address of a line breakpoint hit.
pub(crate) fn beam_i_line_breakpoint_cleanup() -> usize {
    BEAM_I_LINE_BREAKPOINT_CLEANUP.load(Ordering::Relaxed)
}

/// `beamasm_init()`: the global code of the backend, generated once per OS process.
///
/// erts runs `beamasm_init` (erl_init.c:292) before `init_emulator` installs the BIF exports
/// (erl_init.c:296): every export entry starts at the trampoline. A node's code indexes are
/// created only after this returns.
// Port of erts/emulator/beam/erl_init.c:292-296 (erl_init: beamasm_init before
// init_emulator) and jit/beam_jit_main.cpp:243-397 (beamasm_init), OTP-29.1.1.
pub(crate) fn beamasm_init() {
    #[cfg(target_arch = "aarch64")]
    crate::beamasm_integration::beamasm_init();
    #[cfg(target_arch = "x86_64")]
    x86::beamasm_init();
}

/// Emits the `ErtsCodeInfo`, breakpoint trampoline and `call_nif normal_fptr lib dirty_fptr`
/// of a NIF stub for the function of `info` into `buff` (`ErtsNifBeamStub.info` followed by
/// `.code`).
// Port of erts/emulator/beam/jit/beam_jit_main.cpp:542-574 (beamasm_emit_call_nif),
// OTP-29.1.1.
pub(crate) fn beamasm_emit_call_nif(
    info: &arinsal_beamasm::common::beam_asm_h::ErtsCodeInfo,
    (normal_fptr, lib, dirty_fptr): (usize, usize, usize),
    buff: &mut [u8; arinsal_beamasm::common::beam_asm_h::FUNC_INFO_BYTES
             + arinsal_beamasm::common::beam_asm_h::NIF_STUB_CODE_BYTES],
) -> Result<(), crate::VmError> {
    #[cfg(target_arch = "aarch64")]
    {
        let helper = crate::beamasm_integration::call_nif_yield_helper()
            .ok_or_else(|| crate::VmError::Unsupported("call_nif_yield_helper fragment".into()))?;
        arinsal_beamasm::module::beamasm_emit_call_nif(
            (info.mfa.module, info.mfa.function, info.mfa.arity as u8),
            normal_fptr as u64,
            lib as u64,
            dirty_fptr as u64,
            helper,
            buff,
        )
        .map_err(|error| crate::VmError::Unsupported(format!("beamasm_emit_call_nif: {error:?}")))
    }
    #[cfg(target_arch = "x86_64")]
    {
        bga()
            .bga
            .beamasm_emit_call_nif(info, normal_fptr, lib, dirty_fptr, buff)
            .map(drop)
            .map_err(|error| {
                crate::VmError::Unsupported(format!("beamasm_emit_call_nif: {error:?}"))
            })
    }
}

#[cfg(target_arch = "x86_64")]
pub(crate) use x86::bga;

#[cfg(target_arch = "x86_64")]
mod x86 {
    use arinsal_beamasm::beam_asm_global::{GlobalLabels, ProcessOffsets};
    use std::sync::OnceLock;

    /// `static BeamGlobalAssembler *bga` of beam_jit_main.cpp:49, with the executable memory
    /// of its code.
    static BGA: OnceLock<arinsal_beamjit::BeamAsm> = OnceLock::new();

    /// `bga` once `beamasm_init` has run: every module assembler resolves its fragment calls
    /// against it.
    pub(crate) fn bga() -> &'static arinsal_beamjit::BeamAsm {
        BGA.get()
            .expect("beamasm_init runs before any module is loaded")
    }

    // Port of erts/emulator/beam/jit/beam_jit_main.cpp:243-397 (beamasm_init), OTP-29.1.1.
    pub(super) fn beamasm_init() {
        let mut first = false;
        let jit = BGA.get_or_init(|| {
            first = true;
            arinsal_beamjit::beamasm_init(ProcessOffsets {
                state: crate::PROCESS_STATE_OFFSET as u32,
                sig_qs_save: crate::PROCESS_SIGQ_SAVE_OFFSET as u32,
                message_term: crate::ERTS_MESSAGE_TERM_OFFSET as u32,
            })
            // erts_exit(ERTS_ABORT_EXIT, ...) when the global code cannot be generated.
            .unwrap_or_else(|error| panic!("beamasm_init: {error}"))
        });
        if !first {
            return;
        }
        let get = |label| jit.bga.get_ptr(label).unwrap_or(0);
        super::publish(&super::BeamCodePtrs {
            // `beam_run_process` is code of the `erts_beamasm` stub module, which
            // beamasm_init emits after `bga` (beam_jit_main.cpp:327-371).
            run_process: 0,
            export_trampoline: get(GlobalLabels::ExportTrampoline),
            save_calls_export: get(GlobalLabels::DispatchSaveCallsExport),
            save_calls_fun: get(GlobalLabels::DispatchSaveCallsFun),
            unloaded_fun: get(GlobalLabels::UnloadedFun),
            i_line_breakpoint_cleanup: get(GlobalLabels::ILineBreakpointCleanup),
        });
        arinsal_beamasm::set_process_main_labels(get(GlobalLabels::DispatchNif));
    }
}
