//! Code indexes: the active and staging generations of a node's export dispatch.
//!
//! Port of erts/emulator/beam/code_ix.c and code_ix.h, OTP-29.1.1. Native code calls an
//! export through `addresses[active_code_ix]`; code changes write the staging index and a
//! commit makes it active, so a running process sees either the old or the new generation of
//! every export, never a mix. A process saving calls runs with `ERTS_SAVE_CALLS_CODE_IX`,
//! whose address of every export is the save_calls dispatch fragment.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, OnceLock, RwLock};

pub(crate) use arinsal_beamasm::bif::{ERTS_NUM_CODE_IX, ERTS_SAVE_CALLS_CODE_IX};

/// One node's code index state (`the_active_code_index`, `the_staging_code_index`).
pub(crate) struct CodeIndexes {
    active: AtomicU32,
    staging: AtomicU32,
}

impl CodeIndexes {
    // Port of erts/emulator/beam/code_ix.c:100-118 (erts_code_ix_init), OTP-29.1.1: preloading
    // runs with active and staging both zero, and its commit sets things straight.
    fn new() -> Self {
        Self {
            active: AtomicU32::new(0),
            staging: AtomicU32::new(0),
        }
    }

    /// `erts_active_code_ix`.
    pub(crate) fn active(&self) -> usize {
        self.active.load(Ordering::Acquire) as usize
    }

    /// `erts_staging_code_ix`.
    pub(crate) fn staging(&self) -> usize {
        self.staging.load(Ordering::Acquire) as usize
    }

    /// Makes the staging index active and opens the next one for staging.
    // Port of erts/emulator/beam/code_ix.c:142-171 (erts_commit_staging_code_ix), OTP-29.1.1.
    pub(crate) fn commit(&self) {
        let ix = self.staging();
        self.active.store(ix as u32, Ordering::Release);
        self.staging
            .store(((ix + 1) % ERTS_NUM_CODE_IX) as u32, Ordering::Release);
        CODE_BARRIER_PENDING.set(true);
    }

    /// The code index a process runs native code with: `ERTS_SAVE_CALLS_CODE_IX` while it
    /// saves calls, otherwise the active one.
    // Port of erts/emulator/beam/jit/arm/process_main.cpp:235-247, OTP-29.1.1.
    pub(crate) fn process_code_ix(&self, saves_calls: bool) -> usize {
        if saves_calls {
            ERTS_SAVE_CALLS_CODE_IX
        } else {
            self.active()
        }
    }
}

thread_local! {
    /// Set by a commit on this thread until the scheduler runs the code barrier.
    static CODE_BARRIER_PENDING: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Whether this thread committed a code index since the last call, which owes a code
/// barrier: processes that still run native code with the previous code index must be
/// rescheduled before the committing process continues.
// Port of erts/emulator/beam/code_ix.c:558-575 (erts_schedule_code_barrier) and beam_bif_load.c:551-560, OTP-29.1.1.
pub(crate) fn take_code_barrier() -> bool {
    CODE_BARRIER_PENDING.replace(false)
}

fn scopes() -> &'static RwLock<HashMap<u64, Arc<CodeIndexes>>> {
    static SCOPES: OnceLock<RwLock<HashMap<u64, Arc<CodeIndexes>>>> = OnceLock::new();
    SCOPES.get_or_init(Default::default)
}

/// The code indexes of the node with code scope `scope`.
pub(crate) fn for_scope(scope: u64) -> Arc<CodeIndexes> {
    if let Some(indexes) = scopes()
        .read()
        .ok()
        .and_then(|scopes| scopes.get(&scope).cloned())
    {
        return indexes;
    }
    let mut scopes = scopes().write().unwrap_or_else(|error| error.into_inner());
    Arc::clone(
        scopes
            .entry(scope)
            .or_insert_with(|| Arc::new(CodeIndexes::new())),
    )
}

/// Forgets the code indexes of a node whose code is gone.
pub(crate) fn release_scope(scope: u64) {
    if let Ok(mut scopes) = scopes().write() {
        scopes.remove(&scope);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commit_rotates_through_the_code_indexes() {
        let indexes = CodeIndexes::new();
        assert_eq!((indexes.active(), indexes.staging()), (0, 0));
        indexes.commit();
        assert_eq!((indexes.active(), indexes.staging()), (0, 1));
        indexes.commit();
        assert_eq!((indexes.active(), indexes.staging()), (1, 2));
        indexes.commit();
        assert_eq!((indexes.active(), indexes.staging()), (2, 0));
        assert_eq!(indexes.process_code_ix(false), 2);
        assert_eq!(indexes.process_code_ix(true), ERTS_SAVE_CALLS_CODE_IX);
    }
}
