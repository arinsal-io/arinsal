//! Raw storage of `esdp->registers`.

use arinsal_beamasm::SchedulerRegisters;
use std::cell::UnsafeCell;

/// The register file of one scheduler, at a fixed address for the scheduler's lifetime.
/// `UnsafeCell` keeps the scheduler data `!Sync`: only its own scheduler thread reaches it.
#[derive(Default)]
pub(crate) struct RegisterBlock(Box<UnsafeCell<SchedulerRegisters>>);

impl RegisterBlock {
    /// Runs `f` with the register file. Callers are the scheduler loop's steps in
    /// `crate::process` only: `copy_in_registers` / `copy_out_registers` around the slice and
    /// the slice itself (`process_main`, which hands the file to generated code as erts'
    /// process_main hands `reg`). None of them nests in another; native code inside the slice
    /// reaches the file through the address the slice stored (`Vm::esdp_registers`), derived
    /// from the `&mut` this lends.
    #[inline(always)]
    pub(crate) fn with<R>(&self, f: impl FnOnce(&mut SchedulerRegisters) -> R) -> R {
        // SAFETY: the block is owned by this scheduler data, which is `!Sync` and reached only
        // by its scheduler thread; the callers listed above never nest, so this is the one
        // live `&mut` to the file for the duration of `f`.
        f(unsafe { &mut *self.0.get() })
    }
}
