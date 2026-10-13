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
use arinsal_term::FunEntry;

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
    /// barrier before the commit; `work` holds its tables until the stager commits them.
    ended: Option<u64>,
}

/// One node's code index state (`the_active_code_index`, `the_staging_code_index`).
pub(crate) struct CodeIndexes {
    scope: u64,
    active: AtomicU32,
    staging: AtomicU32,
    /// `module_tables[ERTS_NUM_CODE_IX]`, the export tables and the ranges of each code index.
    tables: [ArcSwap<CodeTables>; ERTS_NUM_CODE_IX],
    /// Generation of each slot's tables, published after the tables: a scheduled-in process
    /// compares its code index with one atomic read, like `erts_active_code_ix()`.
    generations: [AtomicU64; ERTS_NUM_CODE_IX],
    /// `bccix[ERTS_NUM_CODE_IX]`: one immutable catch table per code index. Readers load the
    /// active slot; a staging area copies the active table and publishes its own.
    catches: [ArcSwap<Vec<Option<crate::native_bridge::CatchTarget>>>; ERTS_NUM_CODE_IX],
    /// `r[ERTS_NUM_CODE_IX]` in beam_ranges.c: sorted module ranges. Readers load the
    /// active slot and binary-search it; publishing a new `Arc` takes no reader lock.
    ranges: [ArcSwap<Vec<crate::native_bridge::ModuleRange>>; ERTS_NUM_CODE_IX],
    /// Serializes clone-and-publish of a catch table. The hot path does not take it.
    catch_publish: Mutex<()>,
    permission: Mutex<Permission>,
    released: Condvar,
    /// Bodies of loader-bound static NIFs and `load_nif` functions. `NativeBody` instructions
    /// patched into code index them; released slots are reused after code purge.
    native_fns: RwLock<Arc<Vec<Option<arinsal_bifs::BifFn>>>>,
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
            generations: std::array::from_fn(|_| AtomicU64::new(initial.generation)),
            tables: std::array::from_fn(|_| ArcSwap::new(Arc::clone(&initial))),
            catches: std::array::from_fn(|_| ArcSwap::new(Arc::new(Vec::new()))),
            ranges: std::array::from_fn(|_| {
                ArcSwap::new(crate::native_bridge::scope0_code_ranges())
            }),
            catch_publish: Mutex::default(),
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

    /// Reads the tables visible to a process running `code_ix` without a reader lock.
    // Port of erts/emulator/beam/code_ix.c:51-79 (code-indexed module and export tables), OTP-29.1.1.
    #[inline(always)]
    pub(crate) fn with_tables_for_code_ix<R>(
        &self,
        code_ix: usize,
        read: impl FnOnce(&CodeTables) -> R,
    ) -> Option<R> {
        let table_ix = if code_ix == ERTS_SAVE_CALLS_CODE_IX {
            self.active()
        } else {
            code_ix
        };
        self.tables.get(table_ix).map(|tables| read(&tables.load()))
    }

    /// Generation of the active tables.
    // Port of erts/emulator/beam/code_ix.h (erts_active_code_ix: one atomic read), OTP-29.1.1.
    pub(crate) fn active_generation(&self) -> u64 {
        self.generations[self.active()].load(Ordering::Acquire)
    }

    fn store_slot(&self, ix: usize, tables: Arc<CodeTables>) {
        let generation = tables.generation;
        self.tables[ix].store(tables);
        self.generations[ix].store(generation, Ordering::Release);
    }

    /// Catch table of `erts_active_code_ix()`. The `Arc` is the published generation;
    /// indexing it takes no lock.
    // Port of erts/emulator/beam/beam_catches.c:146-154 (`beam_catches_car`), OTP-29.1.1.
    pub(crate) fn active_catch_table(&self) -> Arc<Vec<Option<crate::native_bridge::CatchTarget>>> {
        self.catches[self.active()].load_full()
    }

    /// Module ranges of `erts_active_code_ix()`.
    // Port of erts/emulator/beam/beam_ranges.c:307-327 (`find_range` reads `r[erts_active_code_ix()]`
    // with no lock), OTP-29.1.1.
    pub(crate) fn code_ranges(&self) -> Arc<Vec<crate::native_bridge::ModuleRange>> {
        self.ranges[self.active()].load_full()
    }

    /// Publishes `ranges` on every code index. The active index is what readers load;
    /// the other slots must already hold it when a commit rotates `erts_active_code_ix`.
    pub(crate) fn store_code_ranges(&self, ranges: Arc<Vec<crate::native_bridge::ModuleRange>>) {
        for slot in &self.ranges {
            slot.store(Arc::clone(&ranges));
        }
    }

    /// Copies the active catch table into the staging code index.
    // Port of erts/emulator/beam/beam_catches.c:89-99 (beam_catches_start_staging), OTP-29.1.1.
    fn stage_catches(&self) {
        let copy = Arc::new(self.catches[self.active()].load_full().as_ref().clone());
        self.catches[self.staging()].store(copy);
    }

    /// Replaces one code index's catch table. Callers hold [`CodeIndexes::catch_publish`].
    pub(crate) fn store_catch_table(
        &self,
        index: usize,
        table: Vec<Option<crate::native_bridge::CatchTarget>>,
    ) {
        self.catches[index].store(Arc::new(table));
    }

    /// The catch table currently published at `index` (active or staging).
    pub(crate) fn catch_table_at(
        &self,
        index: usize,
    ) -> Arc<Vec<Option<crate::native_bridge::CatchTarget>>> {
        self.catches[index].load_full()
    }

    /// Lock that orders clone-and-publish of catch tables. Not taken by readers.
    pub(crate) fn lock_catch_publish(&self) -> std::sync::MutexGuard<'_, ()> {
        self.catch_publish
            .lock()
            .unwrap_or_else(|error| error.into_inner())
    }

    /// Takes the staging tables for this thread, waiting while another thread holds them.
    /// While an ended staging area waits for its commit only callers that change code in
    /// place (`join_ended`) get them: a new staging area waits for that commit, which the
    /// stager makes once its code barrier passed, never another thread on its behalf.
    /// Returns whether this thread already held them.
    // Port of erts/emulator/beam/code_ix.c:214-290 (try_seize_code_permission), OTP-29.1.1.
    // Processes queue on the process-based code modification permission
    // (natives/code.rs) before they get here; this only orders the threads that run them.
    fn seize(&self, join_ended: bool) -> bool {
        let me = std::thread::current().id();
        let mut permission = self.lock_permission();
        loop {
            match permission.owner {
                Some(owner) if owner == me => {
                    permission.depth += 1;
                    return true;
                }
                None if join_ended || permission.ended.is_none() => {
                    permission.owner = Some(me);
                    permission.depth = 1;
                    return false;
                }
                _ => {
                    // The thread that runs a queued process still waits here for the owner
                    // thread or for an ended staging area's commit, which its stager makes
                    // only after its code barrier (block_thread_progress). The waiting thread
                    // must not hold back that thread progress, and drops the permission lock
                    // before re-entering it.
                    // Port of erts/emulator/beam/erl_thr_progress.c:884-913
                    // (erts_thr_progress_prepare_wait / finalize_wait), OTP-29.1.1.
                    // The wait deactivates this thread first, which can park it for a thread
                    // that blocks progress: the permission lock must not be held across that,
                    // so the wait relocks and rechecks the state under the lock.
                    drop(permission);
                    arinsal_sched::thread_progress_wait(|| {
                        let guard = self.lock_permission();
                        let free = match guard.owner {
                            Some(owner) => owner == me,
                            None => join_ended || guard.ended.is_none(),
                        };
                        if !free {
                            drop(
                                self.released
                                    .wait(guard)
                                    .unwrap_or_else(|error| error.into_inner()),
                            );
                        }
                    });
                    permission = self.lock_permission();
                }
            }
        }
    }

    fn release(&self) {
        let mut permission = self.lock_permission();
        permission.depth = permission.depth.saturating_sub(1);
        if permission.depth == 0 {
            permission.owner = None;
            // The tables of an ended staging area stay until its commit.
            if permission.ended.is_none() {
                permission.work = None;
                permission.aborted = false;
            }
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
    // Purge markers also hold erts' stage permission (beam_bif_load.c:2112-2118).
    pub(crate) fn start_staging(self: &Arc<Self>) -> Staging {
        let nested = loop {
            let nested = self.seize(false);
            if nested || !self.purge_state.stage_permission_held() {
                break nested;
            }
            self.release();
            self.purge_state.wait_for_stage_permission();
        };
        if !nested {
            let copy = CodeTables::clone(&self.active_tables());
            copy.stage_fun_entries(self.active(), self.staging());
            self.lock_permission().work = Some(copy);
            crate::beamasm_integration::stage_dispatch(self.scope);
            // Port of erts/emulator/beam/beam_catches.c:89-99 (beam_catches_start_staging),
            // OTP-29.1.1: the staging code index starts as a copy of the active pool.
            self.stage_catches();
        }
        Staging {
            code: Arc::clone(self),
            ended: false,
        }
    }

    /// Commits the ended staging area `ticket` and lets threads stage again.
    // Port of erts/emulator/beam/beam_bif_load.c:301-320 (commit_code_ix), OTP-29.1.1.
    fn commit_ended(&self, ticket: u64) {
        let mut permission = self.lock_permission();
        // A thread changing code in place also changes the ended tables: wait for it.
        while permission.owner.is_some() {
            permission = self
                .released
                .wait(permission)
                .unwrap_or_else(|error| error.into_inner());
        }
        if permission.ended != Some(ticket) {
            return;
        }
        permission.ended = None;
        permission.aborted = false;
        let tables = permission.work.take();
        // Commit under the lock: no thread may copy the active tables into a new staging
        // area before they are the committed ones.
        if let Some(tables) = tables {
            self.commit_tables(tables, false);
        }
        drop(permission);
        self.released.notify_all();
    }

    /// Publishes `tables` as the staging code index's tables and makes that index active.
    // Port of erts/emulator/beam/code_ix.c:142-171 (erts_commit_staging_code_ix), OTP-29.1.1.
    fn commit_tables(&self, mut tables: CodeTables, code_barrier_pending: bool) {
        tables.generation = next_generation();
        let tables = Arc::new(tables);
        self.store_slot(self.staging(), Arc::clone(&tables));
        // Ended staging commits from the thread-progress later operation, which already
        // supplied this code change's barrier.
        self.commit_with_barrier(code_barrier_pending);
        // The oldest code index is only read again once staging copies into it.
        self.store_slot(self.staging(), tables);
    }

    /// Changes the active tables in place under the code modification permission, the way
    /// erts updates fields of the active index's entries that need no new code index: purging
    /// old code (beam_bif_load.c:2112-2330), binding a NIF library to the current instance
    /// (erl_nif.c:4748) and export stubs (export.c:228-242). Inside this thread's own staging
    /// area the change goes to the staging tables, which it commits next.
    pub(crate) fn update_active<R>(&self, mut change: impl FnMut(&mut CodeTables) -> R) -> R {
        let nested = self.seize(true);
        let (work, ended) = {
            let mut permission = self.lock_permission();
            let ended = permission.ended.is_some();
            (
                (nested || ended).then(|| permission.work.take()).flatten(),
                ended,
            )
        };
        let result = match work {
            Some(mut work) if !ended => {
                let result = change(&mut work);
                self.lock_permission().work = Some(work);
                result
            }
            work => {
                let mut tables = CodeTables::clone(&self.tables[self.active()].load());
                let result = change(&mut tables);
                self.publish_everywhere(tables);
                // An ended staging area commits a copy of the active tables made before this
                // change: it takes the change too.
                if let Some(mut work) = work {
                    change(&mut work);
                    self.lock_permission().work = Some(work);
                }
                result
            }
        };
        self.release();
        result
    }

    /// Inserts or finds a local fun stub in the active or in-flight staged fun table.
    // Port of erts/emulator/beam/erl_fun.c:299-309 (erts_fun_entry_get_or_make_stub), OTP-29.1.1.
    pub(crate) fn intern_fun_entry(&self, candidate: Arc<FunEntry>) -> Arc<FunEntry> {
        let nested = self.seize(true);
        let (work, ended) = {
            let mut permission = self.lock_permission();
            let ended = permission.ended.is_some();
            (
                (nested || ended).then(|| permission.work.take()).flatten(),
                ended,
            )
        };
        let result = match work {
            Some(mut work) if !ended => {
                let result = work.intern_fun_entry(candidate);
                self.lock_permission().work = Some(work);
                result
            }
            mut work => {
                let candidate = work.as_mut().map_or(candidate.clone(), |staging| {
                    staging.intern_fun_entry(candidate.clone())
                });
                let mut tables = CodeTables::clone(&self.tables[self.active()].load());
                let result = tables.intern_fun_entry(candidate);
                self.tables[self.active()].store(Arc::new(tables));
                if let Some(mut staging) = work {
                    staging.intern_fun_entry(Arc::clone(&result));
                    self.lock_permission().work = Some(staging);
                }
                result
            }
        };
        self.release();
        result
    }

    /// Applies a change of code memory, which every code index shares (breakpoints and NIF
    /// bodies are patched in place in erts), to the active tables and an open staging area.
    pub(crate) fn patch_all(&self, mut change: impl FnMut(&mut CodeTables)) {
        self.seize(true);
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
        for ix in 0..ERTS_NUM_CODE_IX {
            self.store_slot(ix, Arc::clone(&tables));
        }
        crate::natives::nif::invalidate_tracer_callbacks(self.scope);
    }

    /// The NIF bodies `NativeBody` instructions index.
    pub(crate) fn native_fns(&self) -> Arc<Vec<Option<arinsal_bifs::BifFn>>> {
        Arc::clone(
            &self
                .native_fns
                .read()
                .unwrap_or_else(|error| error.into_inner()),
        )
    }

    /// Stores a NIF body in a free slot or appends one and returns its index.
    // Port of erts/emulator/beam/erl_nif.c:5334-5360 (erts_unload_nif), OTP-29.1.1.
    pub(crate) fn push_native_fn(&self, function: arinsal_bifs::BifFn) -> Option<u32> {
        let mut table = self
            .native_fns
            .write()
            .unwrap_or_else(|error| error.into_inner());
        let functions = Arc::make_mut(&mut table);
        if let Some(index) = functions.iter().position(Option::is_none) {
            functions[index] = Some(function);
            return u32::try_from(index).ok();
        }
        let index = u32::try_from(functions.len()).ok()?;
        functions.push(Some(function));
        Some(index)
    }

    /// Releases bodies patched into a code instance that has completed purge.
    // Port of erts/emulator/beam/erl_nif.c:5334-5360 (erts_unload_nif), OTP-29.1.1.
    pub(crate) fn release_native_fns(&self, module: &arinsal_loader::Module) {
        let mut table = self
            .native_fns
            .write()
            .unwrap_or_else(|error| error.into_inner());
        let functions = Arc::make_mut(&mut table);
        for instruction in &module.code {
            if let arinsal_loader::Instr::NativeBody { index } = instruction
                && let Some(function) = functions.get_mut(*index as usize)
            {
                *function = None;
            }
        }
    }

    #[cfg(test)]
    fn release_native_fn(&self, index: usize) {
        if let Some(function) = Arc::make_mut(
            &mut *self
                .native_fns
                .write()
                .unwrap_or_else(|error| error.into_inner()),
        )
        .get_mut(index)
        {
            *function = None;
        }
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
    fn commit_with_barrier(&self, code_barrier_pending: bool) {
        let ix = self.staging();
        self.active.store(ix as u32, Ordering::Release);
        self.staging
            .store(((ix + 1) % ERTS_NUM_CODE_IX) as u32, Ordering::Release);
        if code_barrier_pending {
            CODE_BARRIER_PENDING.set(true);
        }
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
            // The stager keeps the process-based code modification permission until the
            // commit; the thread is free for other processes, which may change code in
            // place but not stage before the commit.
            permission.owner = None;
            permission.depth = 0;
            permission.ended = Some(ticket);
            self.ended = true;
            drop(permission);
            self.code.released.notify_all();
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
            self.code.commit_tables(tables, true);
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

/// The code indexes of `scope` when that node already exists.
pub(crate) fn existing_scope(scope: u64) -> Option<Arc<CodeIndexes>> {
    scopes()
        .read()
        .ok()
        .and_then(|scopes| scopes.get(&scope).cloned())
}

/// Every node's code indexes. Used while the native-function registry lock is held
/// to publish a range; it does not take that lock itself.
pub(crate) fn with_all_scopes(mut visit: impl FnMut(&CodeIndexes)) {
    let Ok(nodes) = scopes().read() else {
        return;
    };
    for indexes in nodes.values() {
        visit(indexes);
    }
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
        indexes.commit_with_barrier(true);
        assert_eq!((indexes.active(), indexes.staging()), (0, 1));
        indexes.commit_with_barrier(true);
        assert_eq!((indexes.active(), indexes.staging()), (1, 2));
        indexes.commit_with_barrier(true);
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
    fn ended_staging_committed_after_thread_progress_does_not_schedule_a_second_barrier() {
        let (scope, code) = node();
        let staging = code.start_staging();
        staging.with(|tables| {
            tables.loaded.insert("barrier_mod".into(), 11);
        });
        let ended = staging.end().unwrap();
        assert!(!take_code_barrier());
        ended.commit();
        assert!(code.active_tables().loaded.contains_key("barrier_mod"));
        assert!(!take_code_barrier());

        drop(code.start_staging());
        assert!(take_code_barrier());
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
    fn purged_native_body_slots_are_reused() {
        let (scope, code) = node();
        let native = arinsal_bifs::lookup("erlang", "length", 1).unwrap();
        let first = code.push_native_fn(native).unwrap();
        let second = code.push_native_fn(native).unwrap();
        assert_eq!((first, second), (0, 1));
        code.release_native_fn(first as usize);
        assert_eq!(code.native_fns().len(), 2);
        assert!(code.native_fns()[first as usize].is_none());
        assert_eq!(code.push_native_fn(native), Some(first));
        assert_eq!(code.native_fns().len(), 2);
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
