//! Code indexes: the active and staging generations of a node's code tables.
//!
//! Port of erts/emulator/beam/code_ix.c and code_ix.h, OTP-29.1.1. Every table erts keeps per
//! code index (module.c `module_tables`, export.c export tables, beam_ranges.c ranges) is a
//! [`CodeTables`] here, one per code index. Readers use the tables of
//! `erts_active_code_ix()`; a loader holding the code modification permission copies the
//! active tables into the staging index, changes them there, and a commit makes them active,
//! so a running process sees either the old or the new generation of every table, never a mix.
//! Native code calls an export through `addresses[active_code_ix]`; a process saving calls
//! runs with `ERTS_SAVE_CALLS_CODE_IX`, whose address of every export is the save_calls
//! dispatch fragment.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock, RwLock};

use arc_swap::ArcSwap;

use crate::load::CodeTables;

pub(crate) use arinsal_beamasm::bif::{ERTS_NUM_CODE_IX, ERTS_SAVE_CALLS_CODE_IX};

/// Identity of one published version of a code index's tables. Interpreter caches (resolved
/// imports, fun dispatch, return addresses) are only valid for the generation they were made
/// in; generations never repeat, across nodes too, because modules outlive the tables that
/// loaded them.
pub(crate) fn next_generation() -> u64 {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

/// The code modification permission and the staging area it guards.
#[derive(Default)]
struct Permission {
    owner: Option<std::thread::ThreadId>,
    depth: usize,
    /// The staging index's tables while staging is open (`erts_start_staging_code_ix` to
    /// `erts_end_staging_code_ix`).
    work: Option<CodeTables>,
    aborted: bool,
    /// Ticket of a staging area that ended (`erts_end_staging_code_ix`) and waits for its code
    /// barrier before the commit; `work` holds its tables and the permission stays taken.
    ended: Option<u64>,
}

/// One node's code index state (`the_active_code_index`, `the_staging_code_index`).
pub(crate) struct CodeIndexes {
    scope: u64,
    active: AtomicU32,
    staging: AtomicU32,
    /// `module_tables[ERTS_NUM_CODE_IX]`, the export tables and the ranges of each code index.
    tables: [ArcSwap<CodeTables>; ERTS_NUM_CODE_IX],
    permission: Mutex<Permission>,
    released: Condvar,
    /// Bodies of loader-bound static NIFs and `load_nif` functions. `NativeBody` instructions
    /// patched into code index them; the code they patch is shared by every code index, so
    /// this table is too. It only grows.
    native_fns: RwLock<Arc<Vec<arinsal_bifs::BifFn>>>,
    /// `erts_coverage_mode`: applies to modules loaded after it is set.
    coverage_mode: Mutex<arinsal_loader::CoverageMode>,
    pub(crate) purge_state: Arc<crate::natives::code::PurgeState>,
}

impl CodeIndexes {
    // Port of erts/emulator/beam/code_ix.c:100-118 (erts_code_ix_init), OTP-29.1.1: preloading
    // runs with active and staging both zero, and its commit sets things straight.
    fn new(scope: u64) -> Self {
        let initial = Arc::new(CodeTables::new(scope));
        Self {
            scope,
            active: AtomicU32::new(0),
            staging: AtomicU32::new(0),
            tables: std::array::from_fn(|_| ArcSwap::new(Arc::clone(&initial))),
            permission: Mutex::default(),
            released: Condvar::new(),
            native_fns: RwLock::default(),
            coverage_mode: Mutex::new(arinsal_loader::CoverageMode::None),
            purge_state: Arc::default(),
        }
    }

    /// The tables of `erts_active_code_ix()`.
    pub(crate) fn active_tables(&self) -> Arc<CodeTables> {
        self.tables[self.active()].load_full()
    }

    /// Generation of the active tables.
    pub(crate) fn active_generation(&self) -> u64 {
        self.tables[self.active()].load().generation
    }

    /// Takes the code modification permission, waiting while another thread holds it.
    /// Returns whether this thread already held it.
    // Port of erts/emulator/beam/code_ix.c:251-300 (try_seize_code_mod_permission), OTP-29.1.1.
    fn seize(&self) -> bool {
        let me = std::thread::current().id();
        let mut permission = self.lock_permission();
        loop {
            // The stager of an ended staging area is suspended until its code barrier; a
            // seizer that comes first completes the barrier and commit on its behalf
            // (beam_bif_load.c:301 commit_code_ix) instead of blocking its scheduler thread,
            // which may be the one that has to resume the stager.
            if permission.ended.take().is_some() {
                let tables = permission.work.take();
                permission.owner = None;
                permission.depth = 0;
                permission.aborted = false;
                if let Some(tables) = tables {
                    self.commit_tables(tables);
                }
                self.released.notify_all();
            }
            match permission.owner {
                Some(owner) if owner == me => {
                    permission.depth += 1;
                    return true;
                }
                Some(_) => {
                    permission = self
                        .released
                        .wait(permission)
                        .unwrap_or_else(|error| error.into_inner());
                }
                None => {
                    permission.owner = Some(me);
                    permission.depth = 1;
                    return false;
                }
            }
        }
    }

    fn release(&self) {
        let mut permission = self.lock_permission();
        permission.depth = permission.depth.saturating_sub(1);
        if permission.depth == 0 {
            permission.owner = None;
            permission.work = None;
            permission.aborted = false;
            drop(permission);
            self.released.notify_all();
        }
    }

    fn lock_permission(&self) -> std::sync::MutexGuard<'_, Permission> {
        self.permission
            .lock()
            .unwrap_or_else(|error| error.into_inner())
    }

    /// Opens the staging area: the active tables are copied to the staging code index, where
    /// the returned guard's changes stay invisible to running code until it commits them when
    /// dropped. A thread that already stages joins its open staging area.
    // Port of erts/emulator/beam/code_ix.c:120-129 (erts_start_staging_code_ix), module.c
    // (module_start_staging) and export.c:277-280 (export_start_staging), OTP-29.1.1.
    pub(crate) fn start_staging(self: &Arc<Self>) -> Staging {
        let nested = self.seize();
        if !nested {
            let copy = CodeTables::clone(&self.active_tables());
            self.lock_permission().work = Some(copy);
            crate::beamasm_integration::stage_dispatch(self.scope);
        }
        Staging {
            code: Arc::clone(self),
            ended: false,
        }
    }

    /// Commits the ended staging area `ticket` unless a seizer already did, and releases the
    /// code modification permission.
    // Port of erts/emulator/beam/beam_bif_load.c:301-320 (commit_code_ix), OTP-29.1.1.
    fn commit_ended(&self, ticket: u64) {
        let mut permission = self.lock_permission();
        if permission.ended != Some(ticket) {
            return;
        }
        permission.ended = None;
        permission.owner = None;
        permission.depth = 0;
        permission.aborted = false;
        if let Some(tables) = permission.work.take() {
            self.commit_tables(tables);
        }
        drop(permission);
        self.released.notify_all();
    }

    /// Publishes `tables` as the staging code index's tables and makes that index active.
    // Port of erts/emulator/beam/code_ix.c:142-171 (erts_commit_staging_code_ix), OTP-29.1.1.
    fn commit_tables(&self, mut tables: CodeTables) {
        tables.generation = next_generation();
        let tables = Arc::new(tables);
        self.tables[self.staging()].store(Arc::clone(&tables));
        self.commit();
        // The oldest code index is only read again once staging copies into it.
        self.tables[self.staging()].store(tables);
    }

    /// Changes the active tables in place under the code modification permission, the way
    /// erts updates fields of the active index's entries that need no new code index: purging
    /// old code (beam_bif_load.c:2112-2330), binding a NIF library to the current instance
    /// (erl_nif.c:4748) and export stubs (export.c:228-242). Inside this thread's own staging
    /// area the change goes to the staging tables, which it commits next.
    pub(crate) fn update_active<R>(&self, change: impl FnOnce(&mut CodeTables) -> R) -> R {
        let nested = self.seize();
        let work = if nested {
            self.lock_permission().work.take()
        } else {
            None
        };
        let result = if let Some(mut work) = work {
            let result = change(&mut work);
            self.lock_permission().work = Some(work);
            result
        } else {
            let mut tables = CodeTables::clone(&self.tables[self.active()].load());
            let result = change(&mut tables);
            self.publish_everywhere(tables);
            result
        };
        self.release();
        result
    }

    /// Applies a change of code memory, which every code index shares (breakpoints and NIF
    /// bodies are patched in place in erts), to the active tables and an open staging area.
    pub(crate) fn patch_all(&self, mut change: impl FnMut(&mut CodeTables)) {
        self.seize();
        let mut tables = CodeTables::clone(&self.tables[self.active()].load());
        change(&mut tables);
        self.publish_everywhere(tables);
        let work = self.lock_permission().work.take();
        if let Some(mut work) = work {
            change(&mut work);
            self.lock_permission().work = Some(work);
        }
        self.release();
    }

    /// Publishes `tables` changed in place as the active tables. The tables of the other code
    /// indexes are only read again after the next staging area copies the active ones into
    /// them (readers that already hold them keep their own reference), so they take the new
    /// tables too: in erts purged code is freed even though older code indexes still point
    /// at it, and here they must not keep purged code alive.
    fn publish_everywhere(&self, mut tables: CodeTables) {
        tables.generation = next_generation();
        let tables = Arc::new(tables);
        for slot in &self.tables {
            slot.store(Arc::clone(&tables));
        }
    }

    /// The NIF bodies `NativeBody` instructions index.
    pub(crate) fn native_fns(&self) -> Arc<Vec<arinsal_bifs::BifFn>> {
        Arc::clone(
            &self
                .native_fns
                .read()
                .unwrap_or_else(|error| error.into_inner()),
        )
    }

    /// Appends a NIF body and returns its index.
    pub(crate) fn push_native_fn(&self, function: arinsal_bifs::BifFn) -> Option<u32> {
        let mut table = self
            .native_fns
            .write()
            .unwrap_or_else(|error| error.into_inner());
        let index = u32::try_from(table.len()).ok()?;
        Arc::make_mut(&mut table).push(function);
        Some(index)
    }

    pub(crate) fn coverage_mode(&self) -> arinsal_loader::CoverageMode {
        *self
            .coverage_mode
            .lock()
            .unwrap_or_else(|error| error.into_inner())
    }

    pub(crate) fn set_coverage_mode(&self, mode: arinsal_loader::CoverageMode) {
        *self
            .coverage_mode
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = mode;
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

/// An open staging area (`erts_start_staging_code_ix` .. `erts_end_staging_code_ix`) holding
/// the code modification permission. Dropping it commits the staging code index
/// (`erts_commit_staging_code_ix`) unless [`Staging::abort`] was called.
pub(crate) struct Staging {
    code: Arc<CodeIndexes>,
    /// Set by [`Staging::end`]: the commit is left to the returned [`EndedStaging`].
    ended: bool,
}

/// A staging area after `erts_end_staging_code_ix`, still holding the code modification
/// permission until its commit. Dropping it commits (`commit_code_ix`), which also happens
/// when its stager exits while suspended, as erts commits without resuming an exiting stager.
pub(crate) struct EndedStaging {
    code: Arc<CodeIndexes>,
    ticket: u64,
}

impl EndedStaging {
    /// Makes the staged code active: the code barrier of the stager passed.
    pub(crate) fn commit(self) {
        drop(self);
    }
}

impl Drop for EndedStaging {
    fn drop(&mut self) {
        self.code.commit_ended(self.ticket);
    }
}

impl Staging {
    /// Changes the staging code index's tables.
    pub(crate) fn with<R>(&self, change: impl FnOnce(&mut CodeTables) -> R) -> R {
        // Only the permission holder touches the staging tables, so they are taken out while
        // `change` runs: dropping code inside it may stage export changes of its own.
        let mut work = self
            .code
            .lock_permission()
            .work
            .take()
            .expect("the staging tables exist while staging is open");
        let result = change(&mut work);
        self.code.lock_permission().work = Some(work);
        result
    }

    /// The staging code index (`erts_staging_code_ix`).
    pub(crate) fn ix(&self) -> usize {
        self.code.staging()
    }

    /// Ends staging without committing (`erts_end_staging_code_ix`): running code keeps the
    /// active code index until the returned area commits after the stager's code barrier.
    /// A staging area nested in an outer one, or an aborted one, finishes as on drop.
    // Port of erts/emulator/beam/beam_bif_load.c:539-571 (staging_epilogue), OTP-29.1.1.
    pub(crate) fn end(mut self) -> Option<EndedStaging> {
        static TICKETS: AtomicU64 = AtomicU64::new(1);
        {
            let mut permission = self.code.lock_permission();
            if permission.depth != 1 || permission.aborted || permission.work.is_none() {
                return None;
            }
            let ticket = TICKETS.fetch_add(1, Ordering::Relaxed);
            // The permission now belongs to the suspended stager, not to this thread, so
            // other processes on this scheduler never join the ended staging area.
            permission.owner = None;
            permission.depth = 0;
            permission.ended = Some(ticket);
            self.ended = true;
            Some(EndedStaging {
                code: Arc::clone(&self.code),
                ticket,
            })
        }
    }

    /// Discards every change of this staging area.
    // Port of erts/emulator/beam/code_ix.c:173-182 (erts_abort_staging_code_ix), OTP-29.1.1.
    pub(crate) fn abort(self) {
        self.code.lock_permission().aborted = true;
    }
}

impl Drop for Staging {
    // Port of erts/emulator/beam/code_ix.c:131-171 (erts_end_staging_code_ix,
    // erts_commit_staging_code_ix), OTP-29.1.1.
    fn drop(&mut self) {
        if self.ended {
            return;
        }
        let committed = {
            let mut permission = self.code.lock_permission();
            if permission.depth == 1 && !permission.aborted {
                permission.work.take()
            } else {
                None
            }
        };
        if let Some(tables) = committed {
            self.code.commit_tables(tables);
        }
        self.code.release();
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
            .or_insert_with(|| Arc::new(CodeIndexes::new(scope))),
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
        let indexes = CodeIndexes::new(0);
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

    fn node() -> (u64, Arc<CodeIndexes>) {
        let scope = crate::beamasm_integration::new_code_scope();
        (scope, for_scope(scope))
    }

    #[test]
    fn staged_changes_become_active_only_on_commit() {
        let (scope, code) = node();
        let before = code.active_tables();
        let (active, staging_ix) = (code.active(), code.staging());
        let staging = code.start_staging();
        assert_eq!(staging.ix(), staging_ix);
        staging.with(|tables| {
            tables.loaded.insert("staged_mod".into(), 7);
        });
        // Running code still sees the active index without the change.
        assert!(!code.active_tables().loaded.contains_key("staged_mod"));
        assert_eq!(code.active(), active);
        drop(staging);
        assert_eq!(code.active(), staging_ix);
        let after = code.active_tables();
        assert_eq!(after.loaded.get("staged_mod"), Some(&7));
        assert_ne!(after.generation, before.generation);
        // A reader holding the previous generation keeps its consistent view.
        assert!(!before.loaded.contains_key("staged_mod"));
        // The next staging area starts from the new active tables.
        let next = code.start_staging();
        assert_eq!(
            next.with(|tables| tables.loaded.get("staged_mod").copied()),
            Some(7)
        );
        drop(next);
        crate::beamasm_integration::release_code_scope(scope);
    }

    #[test]
    fn aborted_staging_changes_nothing() {
        let (scope, code) = node();
        let before = code.active_tables();
        let (active, staging_ix) = (code.active(), code.staging());
        let staging = code.start_staging();
        staging.with(|tables| {
            tables.loaded.insert("aborted_mod".into(), 1);
        });
        staging.abort();
        assert_eq!((code.active(), code.staging()), (active, staging_ix));
        assert_eq!(code.active_generation(), before.generation);
        assert!(!code.active_tables().loaded.contains_key("aborted_mod"));
        // A later staging area does not see the aborted change either.
        let staging = code.start_staging();
        assert!(!staging.with(|tables| tables.loaded.contains_key("aborted_mod")));
        drop(staging);
        crate::beamasm_integration::release_code_scope(scope);
    }

    #[test]
    fn nested_staging_joins_and_commits_once() {
        let (scope, code) = node();
        let generation = code.active_generation();
        let outer = code.start_staging();
        let inner = code.start_staging();
        inner.with(|tables| {
            tables.loaded.insert("inner_mod".into(), 2);
        });
        drop(inner);
        assert_eq!(code.active_generation(), generation);
        assert!(!code.active_tables().loaded.contains_key("inner_mod"));
        drop(outer);
        assert_ne!(code.active_generation(), generation);
        assert!(code.active_tables().loaded.contains_key("inner_mod"));
        crate::beamasm_integration::release_code_scope(scope);
    }

    #[test]
    fn staging_holds_the_code_modification_permission() {
        let (scope, code) = node();
        let staging = code.start_staging();
        let other = Arc::clone(&code);
        let (sender, receiver) = std::sync::mpsc::channel();
        let waiter = std::thread::spawn(move || {
            let staging = other.start_staging();
            let seen = staging.with(|tables| tables.loaded.get("first_mod").copied());
            sender.send(seen).unwrap();
        });
        assert!(
            receiver
                .recv_timeout(std::time::Duration::from_millis(100))
                .is_err()
        );
        staging.with(|tables| {
            tables.loaded.insert("first_mod".into(), 3);
        });
        drop(staging);
        // The second loader stages on top of the first one's committed tables.
        assert_eq!(
            receiver
                .recv_timeout(std::time::Duration::from_secs(10))
                .unwrap(),
            Some(3)
        );
        waiter.join().unwrap();
        crate::beamasm_integration::release_code_scope(scope);
    }

    #[test]
    fn active_updates_keep_the_code_index() {
        let (scope, code) = node();
        let before = code.active_tables();
        let (active, staging_ix) = (code.active(), code.staging());
        code.update_active(|tables| {
            tables.old.insert("purged_mod".into(), 4);
        });
        assert_eq!((code.active(), code.staging()), (active, staging_ix));
        let after = code.active_tables();
        assert_eq!(after.old.get("purged_mod"), Some(&4));
        assert_ne!(after.generation, before.generation);
        // Inside a staging area the update lands in the staging tables.
        let staging = code.start_staging();
        code.update_active(|tables| {
            tables.old.insert("staged_purge".into(), 5);
        });
        assert!(!code.active_tables().old.contains_key("staged_purge"));
        drop(staging);
        assert_eq!(code.active_tables().old.get("staged_purge"), Some(&5));
        crate::beamasm_integration::release_code_scope(scope);
    }
}
