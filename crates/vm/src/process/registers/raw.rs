//! Raw storage of `esdp->registers`.

use arinsal_beamasm::SchedulerRegisters;
#[cfg(not(target_arch = "x86_64"))]
use std::cell::UnsafeCell;

/// The register file of one scheduler, at a fixed address for the scheduler's lifetime.
/// `UnsafeCell` keeps the scheduler data `!Sync`: only its own scheduler thread reaches it.
#[cfg(not(target_arch = "x86_64"))]
#[derive(Default)]
pub(crate) struct RegisterBlock(Box<UnsafeCell<SchedulerRegisters>>);

/// The register file of one scheduler. A normal scheduler's lives on its own C stack, in the
/// frame of the generated `process_main`, which stores its address here before running any
/// process; a dirty scheduler's is allocated for good on first use.
// Port of erts/emulator/beam/erl_process.c:5972 (init_scheduler_registers: no allocation for
// a normal scheduler under BEAMASM, `erts_alloc_permanent_cache_aligned` for a dirty one) and
// jit/x86/process_main.cpp:64-77, OTP-29.1.1.
#[cfg(target_arch = "x86_64")]
pub(crate) struct RegisterBlock(std::cell::Cell<*mut SchedulerRegisters>);

#[cfg(target_arch = "x86_64")]
impl Default for RegisterBlock {
    fn default() -> Self {
        Self(std::cell::Cell::new(std::ptr::null_mut()))
    }
}

impl RegisterBlock {
    /// Runs `f` with the register file. Callers are the scheduler loop's steps in
    /// `crate::process` only: `copy_in_registers` / `copy_out_registers` around the slice and
    /// the slice itself (`process_main`, which hands the file to generated code as erts'
    /// process_main hands `reg`). None of them nests in another; native code inside the slice
    /// reaches the file through the address the slice stored (`Vm::esdp_registers`), derived
    /// from the `&mut` this lends.
    #[cfg(not(target_arch = "x86_64"))]
    #[inline(always)]
    pub(crate) fn with<R>(&self, f: impl FnOnce(&mut SchedulerRegisters) -> R) -> R {
        // SAFETY: the block is owned by this scheduler data, which is `!Sync` and reached only
        // by its scheduler thread; the callers listed above never nest, so this is the one
        // live `&mut` to the file for the duration of `f`.
        f(unsafe { &mut *self.0.get() })
    }

    /// Runs `f` with the register file (see the aarch64 variant for the callers).
    #[cfg(target_arch = "x86_64")]
    #[inline(always)]
    pub(crate) fn with<R>(&self, f: impl FnOnce(&mut SchedulerRegisters) -> R) -> R {
        let mut block = self.0.get();
        if block.is_null() {
            // A dirty scheduler: erts_alloc_permanent_cache_aligned, never freed.
            block = Box::into_raw(Box::<SchedulerRegisters>::default());
            self.0.set(block);
        }
        // SAFETY: `block` is this scheduler's register file (its process_main frame, which
        // outlives every slice, or the permanent allocation above); the scheduler data is
        // `!Sync`, and the callers never nest, so this is the one live `&mut` during `f`.
        f(unsafe { &mut *block })
    }

    /// `process_main(esdp)` of the normal scheduler owning this block: the generated loop
    /// allocates the file on this thread's stack and stores its address here.
    #[cfg(target_arch = "x86_64")]
    pub(crate) fn process_main(&self) -> ! {
        type PmainType = extern "C" fn(*mut *mut SchedulerRegisters) -> !;
        // Port of erts/emulator/beam/jit/beam_jit_main.cpp:413-418 (process_main: `pmain =
        // bga->get_process_main(); pmain(esdp)`), OTP-29.1.1.
        let pmain = crate::beam_jit_main::process_main_ptr();
        // SAFETY: `pmain` is the emitted `process_main` fragment (System V, `ARG1` =
        // `&esdp->registers`), alive for the emulator's life (erts never releases global
        // code). It is called once, from the scheduler thread's outermost frame
        // (sched_thread_func), with the scheduler data (and so this cell) alive for the
        // thread's life.
        let pmain = unsafe { core::mem::transmute::<usize, PmainType>(pmain) };
        pmain(self.0.as_ptr())
    }
}
