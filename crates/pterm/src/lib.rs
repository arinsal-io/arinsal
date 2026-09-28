//! Persistent terms and the literal-retirement handshake.
//!
//! A process handle is published through a lock-free queue. After a replacement
//! or erase, the writer snapshots the handles that predate that retirement.
//! Their next GC scans roots and heap objects, copies references into the
//! process heap, then acknowledges the area. Dropping a handle means its roots
//! are gone; it takes the writer lock only while retired areas exist.

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::ops::{Deref, DerefMut};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock, Mutex, MutexGuard, Weak};

use arinsal_bifs::{BifError, BifFn, Ctx};
use arinsal_term::{
    ExportEntry, FunEntry, HeapAlloc, LiteralArea, Node, Term, TermBuilder, TermError, copy_term,
    exact_eq, global_atoms, internal_hash, size_object,
};
use crossbeam_epoch::{Atomic, Owned, pin};
use crossbeam_queue::SegQueue;

static GLOBAL: LazyLock<Store> = LazyLock::new(Store::new);
thread_local! {
    static WRITER_DEPTH: Cell<usize> = const { Cell::new(0) };
    static DEFERRED_UNREGISTER: RefCell<Vec<(*const Store, u64)>> = const { RefCell::new(Vec::new()) };
}

/// The table used by BIF calls; the VM registers processes with this store.
pub fn global_store() -> &'static Store {
    &GLOBAL
}

struct Stored {
    area: LiteralArea,
    key: Term,
    value: Term,
}
#[allow(dead_code)]
fn assert_stored_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Stored>();
}

fn deref_table<'g>(shared: crossbeam_epoch::Shared<'g, Table>) -> &'g Table {
    assert!(
        !shared.is_null(),
        "persistent-term tables are installed before any load"
    );
    // SAFETY: Store::new and publish store a non-null Owned table with Release.
    // Callers load under the guard that produced `shared`, so the table stays
    // initialized for 'g. Acquire loads synchronize with that publication.
    unsafe { shared.deref() }
}

// Port of erts/emulator/beam/erl_bif_persistent.c:42 (Parameters for the hash table), OTP-29.1.1
const INITIAL_SIZE: usize = 8;
const LOAD_FACTOR: usize = 50;

#[derive(Clone)]
struct Table {
    allocated: usize,
    num_entries: usize,
    // Port of erts/emulator/beam/erl_bif_persistent.c:58 (hash_table), OTP-29.1.1
    term: Vec<Option<Arc<Stored>>>,
}

impl Table {
    fn new() -> Self {
        // Port of erts/emulator/beam/erl_bif_persistent.c:786 (create_initial_table), OTP-29.1.1
        Self {
            allocated: INITIAL_SIZE,
            num_entries: 0,
            term: vec![None; INITIAL_SIZE],
        }
    }

    // Port of erts/emulator/beam/erl_bif_persistent.c:46 (MUST_GROW), OTP-29.1.1
    fn must_grow(&self) -> bool {
        100 * self.num_entries >= LOAD_FACTOR * self.allocated
    }

    // Port of erts/emulator/beam/erl_bif_persistent.c:47 (MUST_SHRINK), OTP-29.1.1
    // Port of erts/emulator/beam/erl_bif_persistent.c:47 (MUST_SHRINK), OTP-29.1.1
    fn must_shrink(&self) -> bool {
        200 * self.num_entries <= LOAD_FACTOR * self.allocated && self.allocated > INITIAL_SIZE
    }

    // Port of erts/emulator/beam/erl_bif_persistent.c:1005 (lookup), OTP-29.1.1
    fn lookup(&self, key: Term, hash: u64) -> usize {
        let mask = self.allocated - 1;
        let mut idx = hash as usize;
        loop {
            let i = idx & mask;
            let bucket = &self.term[i];
            match bucket {
                None => return i,
                Some(stored) => {
                    if exact_eq(stored.key, key) {
                        return i;
                    }
                }
            }
            idx = idx.wrapping_add(1);
        }
    }
}

// Port of erts/emulator/beam/erl_bif_persistent.c:1006 (lookup), OTP-29.1.1
#[inline]
fn lookup_hash(term: Term) -> u64 {
    internal_hash(term)
}

struct Pending {
    stored: Arc<Stored>,
    waiting: HashMap<u64, Weak<ProcessAccount>>,
}
struct ProcessAccount {
    id: u64,
    generation: u64,
    capacity: AtomicU64,
    used: AtomicU64,
    binary: AtomicU64,
}
/// Counters from the latest process collection that owed retired literal areas.
#[derive(Clone, Copy, Debug, Default)]
pub struct RetirementTrace {
    /// Areas this process still had to scan.
    pub pending_before: usize,
    /// Areas still outstanding after acknowledgement.
    pub pending_after: usize,
    /// Areas released because this process was the last waiter.
    pub freed: u64,
    /// Live roots copied out of retired areas before the release.
    pub copied_roots: u64,
}
struct Writer {
    next_area: u64,
    retired: HashMap<u64, Pending>,
    last_trace: RetirementTrace,
}

/// A process-independent persistent-term table.
///
/// Reads pin an epoch and load a single immutable table. Writers serialize,
/// clone the table, and publish it atomically. Term pointers returned by reads
/// remain valid through the VM protocol described in this module.
pub struct Store {
    table: Atomic<Table>,
    writer: Mutex<Writer>,
    processes: SegQueue<Weak<ProcessAccount>>,
    next_process: AtomicU64,
    registration_generation: AtomicU64,
    registrations_in_flight: AtomicUsize,
    process_scan: Mutex<()>,
    /// Areas waiting for process GC. Lock-free so collection can skip the scan.
    retired_len: AtomicUsize,
    /// Areas whose last waiter has acknowledged them.
    freed: AtomicU64,
}
struct WriterGuard<'a> {
    store: &'a Store,
    guard: MutexGuard<'a, Writer>,
}
impl Deref for WriterGuard<'_> {
    type Target = Writer;
    fn deref(&self) -> &Writer {
        &self.guard
    }
}
impl DerefMut for WriterGuard<'_> {
    fn deref_mut(&mut self) -> &mut Writer {
        &mut self.guard
    }
}
impl Drop for WriterGuard<'_> {
    fn drop(&mut self) {
        let store = self.store;
        store.drain_deferred(&mut self.guard);
        // The mutex guard drops after this impl, so the lock is held through the drain.
        WRITER_DEPTH.with(|depth| depth.set(depth.get().saturating_sub(1)));
    }
}

impl Store {
    fn lock_writer(&self) -> WriterGuard<'_> {
        let guard = self.writer.lock().expect("persistent-term writer poisoned");
        WRITER_DEPTH.with(|depth| depth.set(depth.get() + 1));
        WriterGuard { store: self, guard }
    }
    fn drain_deferred(&self, writer: &mut Writer) {
        loop {
            let mine = self as *const Store;
            let ids: Vec<u64> = DEFERRED_UNREGISTER.with(|queue| {
                let mut queue = queue.borrow_mut();
                let mut ids = Vec::new();
                queue.retain(|(store, id)| {
                    if *store == mine {
                        ids.push(*id);
                        false
                    } else {
                        true
                    }
                });
                ids
            });
            if ids.is_empty() {
                break;
            }
            for id in ids {
                unregister_process(self, writer, id);
            }
        }
    }
    /// Create an empty store.
    pub fn new() -> Self {
        Self {
            table: Atomic::new(Table::new()),
            writer: Mutex::new(Writer {
                next_area: 1,
                retired: HashMap::new(),
                last_trace: RetirementTrace::default(),
            }),
            processes: SegQueue::new(),
            next_process: AtomicU64::new(1),
            registration_generation: AtomicU64::new(0),
            registrations_in_flight: AtomicUsize::new(0),
            process_scan: Mutex::new(()),
            retired_len: AtomicUsize::new(0),
            freed: AtomicU64::new(0),
        }
    }
    /// Whether any literal area is waiting for a process collection.
    pub fn has_retired(&self) -> bool {
        self.retired_len.load(Ordering::Acquire) != 0
    }
    /// Areas released after their last process acknowledged them.
    pub fn freed_literal_areas(&self) -> u64 {
        self.freed.load(Ordering::Relaxed)
    }
    /// Latest GC retirement trace. Zero until a collection owed an area.
    pub fn last_retirement(&self) -> RetirementTrace {
        self.lock_writer().last_trace
    }
    /// Register a process for literal retirement before its first read.
    pub fn register_process(&self) -> ProcessRegistration<'_> {
        self.registrations_in_flight.fetch_add(1, Ordering::SeqCst);
        let generation = self.registration_generation.load(Ordering::Acquire);
        let id = self.next_process.fetch_add(1, Ordering::Relaxed);
        let account = Arc::new(ProcessAccount {
            id,
            generation,
            capacity: AtomicU64::new(0),
            used: AtomicU64::new(0),
            binary: AtomicU64::new(0),
        });
        self.processes.push(Arc::downgrade(&account));
        self.registrations_in_flight.fetch_sub(1, Ordering::SeqCst);
        ProcessRegistration {
            store: self,
            id,
            account: Some(account),
        }
    }
    /// Record this process's heap and binary bytes for `erlang:memory/0,1`.
    pub fn set_process_memory(
        &self,
        process: &ProcessRegistration<'_>,
        capacity: u64,
        used: u64,
        binary: u64,
    ) {
        assert!(std::ptr::eq(self, process.store));
        let account = process.account.as_ref().expect("live process registration");
        account.capacity.store(capacity, Ordering::Relaxed);
        account.used.store(used.min(capacity), Ordering::Relaxed);
        account.binary.store(binary, Ordering::Relaxed);
    }
    /// Sum the latest heap snapshot of every live registered process.
    pub fn process_memory_totals(&self) -> (u64, u64, u64) {
        let _scan = self.process_scan.lock().expect("process scan poisoned");
        let mut capacity = 0;
        let mut used = 0;
        let mut binary = 0;
        let mut live = Vec::new();
        while let Some(account) = self.processes.pop() {
            if let Some(account) = account.upgrade() {
                capacity += account.capacity.load(Ordering::Relaxed);
                used += account.used.load(Ordering::Relaxed);
                binary += account.binary.load(Ordering::Relaxed);
                live.push(Arc::downgrade(&account));
            }
        }
        for account in live {
            self.processes.push(account);
        }
        (capacity, used, binary)
    }
    /// Return the stored value pointer, with no copy or lock.
    #[inline]
    // Port of erts/emulator/beam/erl_bif_persistent.c:358 (persistent_term_get), OTP-29.1.1
    pub fn get(&self, key: Term) -> Option<Term> {
        let hash = lookup_hash(key);
        let guard = pin();
        let table = self
            .table
            .load(std::sync::atomic::Ordering::Acquire, &guard);
        let table = deref_table(table);
        let idx = table.lookup(key, hash);
        table.term[idx].as_ref().map(|item| item.value)
    }
    /// Insert or replace a value. An exactly equal value is a no-op.
    // Port of erts/emulator/beam/erl_bif_persistent.c:314 (persistent_term_put_2), OTP-29.1.1
    pub fn put(&self, key: Term, value: Term) -> Result<(), TermError> {
        self.put_inner(key, value, false).map(|_| ())
    }
    /// Insert only if absent. Equal existing values also succeed, as in erts.
    /// Return false for an existing unequal value.
    // Port of erts/emulator/beam/erl_bif_persistent.c:319 (persistent_term_put_new_2), OTP-29.1.1
    pub fn put_new(&self, key: Term, value: Term) -> Result<bool, TermError> {
        self.put_inner(key, value, true)
    }
    fn put_inner(&self, key: Term, value: Term, only_new: bool) -> Result<bool, TermError> {
        let hash = lookup_hash(key);
        let mut writer = self.lock_writer();
        let guard = pin();
        let current = self
            .table
            .load(std::sync::atomic::Ordering::Acquire, &guard);
        let current_table = deref_table(current);

        let idx = current_table.lookup(key, hash);
        if let Some(old) = &current_table.term[idx] {
            if exact_eq(old.value, value) {
                // Port of erts/emulator/beam/erl_bif_persistent.c:726 (same value), OTP-29.1.1
                return Ok(true);
            }
            if only_new {
                return Ok(false);
            }
        }

        let mut area = LiteralArea::with_capacity_words(size_object(key) + size_object(value) + 3);
        let key = area.copy_from(key)?;
        let value = area.copy_from(value)?;
        area.builder().tuple(&[key, value])?;
        let entry = Arc::new(Stored { area, key, value });

        // Port of erts/emulator/beam/erl_bif_persistent.c:275 (TRAPPING_COPY_TABLE), OTP-29.1.1
        let mut next = if current_table.term[idx].is_none() && current_table.must_grow() {
            let mut new_table = Table {
                allocated: current_table.allocated * 2,
                num_entries: current_table.num_entries,
                term: vec![None; current_table.allocated * 2],
            };
            // Port of erts/emulator/beam/erl_bif_persistent.c:1100 (copy_table_place_3), OTP-29.1.1
            for item in current_table.term.iter().flatten() {
                let new_idx = new_table.lookup(item.key, lookup_hash(item.key));
                new_table.term[new_idx] = Some(Arc::clone(item));
            }
            new_table
        } else {
            current_table.clone()
        };

        let new_idx = next.lookup(key, hash);
        if let Some(old) = next.term[new_idx].replace(entry) {
            self.retire(&mut writer, old);
        } else {
            next.num_entries += 1;
        }

        // Port of erts/emulator/beam/erl_bif_persistent.c:275 (TRAPPING_COPY_TABLE), OTP-29.1.1
        // Table copying is completed before publication; the frozen BIF ABI has no trap result.
        self.publish(next, current, &guard);
        Ok(true)
    }
    /// Remove a key; return whether it existed.
    // Port of erts/emulator/beam/erl_bif_persistent.c:417 (persistent_term_erase_1), OTP-29.1.1
    pub fn erase(&self, key: Term) -> bool {
        let hash = lookup_hash(key);
        let mut writer = self.lock_writer();
        let guard = pin();
        let current = self
            .table
            .load(std::sync::atomic::Ordering::Acquire, &guard);
        let current_table = deref_table(current);

        let idx = current_table.lookup(key, hash);
        if current_table.term[idx].is_none() {
            return false;
        }

        // Port of erts/emulator/beam/erl_bif_persistent.c:1025 (is_erasable), OTP-29.1.1
        let is_erasable = current_table.term[(idx + 1) & (current_table.allocated - 1)].is_none();

        let mut next;
        let old;

        if !current_table.must_shrink() && is_erasable {
            // Port of erts/emulator/beam/erl_bif_persistent.c:478 (fast erase), OTP-29.1.1
            next = current_table.clone();
            old = next.term[idx].take().unwrap();
            next.num_entries -= 1;
        } else {
            // Rehash
            let new_size = if current_table.must_shrink() {
                current_table.allocated / 2
            } else {
                current_table.allocated
            };
            next = Table {
                allocated: new_size,
                num_entries: current_table.num_entries - 1,
                term: vec![None; new_size],
            };
            old = current_table.term[idx].clone().unwrap();

            for (i, item) in current_table.term.iter().enumerate() {
                if i != idx
                    && let Some(stored) = item
                {
                    let new_idx = next.lookup(stored.key, lookup_hash(stored.key));
                    next.term[new_idx] = Some(Arc::clone(stored));
                }
            }
        }
        self.retire(&mut writer, old);
        self.publish(next, current, &guard);
        true
    }
    /// Atomically erase all persistent terms, as `erts_internal:erase_persistent_terms/0`.
    // Port of erts/emulator/beam/erl_bif_persistent.c:1142 (mark_for_deletion), OTP-29.1.1
    pub fn clear(&self) {
        let mut writer = self.lock_writer();
        let guard = pin();
        let current = self
            .table
            .load(std::sync::atomic::Ordering::Acquire, &guard);
        for stored in deref_table(current).term.iter().flatten() {
            self.retire(&mut writer, Arc::clone(stored));
        }
        self.publish(Table::new(), current, &guard);
    }
    fn retire(&self, writer: &mut Writer, old: Arc<Stored>) {
        // Port of erts/emulator/beam/erl_bif_persistent.c:1229 (delete_tuple), OTP-29.1.1
        if old.value.is_pointer() {
            // Port of erts/emulator/beam/beam_bif_load.c:1794-1946
            // (release_literal_area_switch), OTP-29.1.1. A generation cutoff
            // replaces the per-process writer-locked registration snapshot;
            // processes that existed before this area retired acknowledge it
            // only after their next GC rewrites all roots.
            let _scan = self.process_scan.lock().expect("process scan poisoned");
            // Publish retirement before taking the process snapshot. A process
            // dropped during the scan then waits for this writer and removes
            // its weak handle from the completed snapshot.
            self.retired_len.fetch_add(1, Ordering::Release);
            let generation = self.registration_generation.fetch_add(1, Ordering::SeqCst);
            while self.registrations_in_flight.load(Ordering::SeqCst) != 0 {
                std::hint::spin_loop();
            }
            let mut waiting = HashMap::new();
            let mut live = Vec::new();
            while let Some(account) = self.processes.pop() {
                if let Some(account) = account.upgrade() {
                    if account.generation <= generation {
                        waiting.insert(account.id, Arc::downgrade(&account));
                    }
                    live.push(Arc::downgrade(&account));
                }
            }
            for account in live {
                self.processes.push(account);
            }
            let id = writer.next_area;
            writer.next_area += 1;
            writer.retired.insert(
                id,
                Pending {
                    stored: old,
                    waiting,
                },
            );
        }
    }
    fn publish(
        &self,
        next: Table,
        current: crossbeam_epoch::Shared<'_, Table>,
        guard: &crossbeam_epoch::Guard,
    ) {
        // Port of erts/emulator/beam/erl_bif_persistent.c:1175 (table_updater), OTP-29.1.1
        self.table
            .store(Owned::new(next), std::sync::atomic::Ordering::Release);
        // SAFETY: only the writer publishes tables; pinned readers may finish
        // before the old table and its Arc owners are destroyed.
        unsafe { guard.defer_destroy(current) };
        guard.flush();
    }
    /// Snapshot count and allocated bytes, including the table and live areas.
    // Port of erts/emulator/beam/erl_bif_persistent.c:569 (persistent_term_info_0), OTP-29.1.1
    pub fn info(&self) -> (usize, usize) {
        let guard = pin();
        let current = self
            .table
            .load(std::sync::atomic::Ordering::Acquire, &guard);
        let table = deref_table(current);
        // Port of erts/emulator/beam/erl_bif_persistent.c:970 (memory), OTP-29.1.1
        let bytes = 96 // sizeof(HashTable) + offsetof(HashTable, term) is 96 in erl
            + (table.allocated - 1) * 8 // term array inside HashTable
            + table
                .term
                .iter()
                .flatten()
                .map(|item| 16 + item.area.used_words() * 8) // size of literal area struct + words
                .sum::<usize>();
        (table.num_entries, bytes)
    }
    /// Visit a consistent snapshot of all key/value pairs.
    pub fn for_each(&self, mut visit: impl FnMut(Term, Term)) {
        let guard = pin();
        let current = self
            .table
            .load(std::sync::atomic::Ordering::Acquire, &guard);
        let table = deref_table(current);
        for item in table.term.iter().flatten() {
            visit(item.key, item.value);
        }
    }
    /// Return retired areas this process still needs to scan and copy.
    pub fn retired_areas(&self, process: &ProcessRegistration<'_>) -> Vec<RetiredArea> {
        assert!(std::ptr::eq(self, process.store));
        let writer = self.lock_writer();
        writer
            .retired
            .iter()
            .filter(|(_, pending)| {
                pending
                    .waiting
                    .get(&process.id)
                    .is_some_and(|account| account.strong_count() > 0)
            })
            .map(|(&id, pending)| RetiredArea {
                id,
                stored: Arc::clone(&pending.stored),
            })
            .collect()
    }
    /// Acknowledge after scanning all process roots and copying live references.
    pub fn acknowledge(&self, process: &ProcessRegistration<'_>, area_id: u64) -> bool {
        assert!(std::ptr::eq(self, process.store));
        let mut writer = self.lock_writer();
        let Some(pending) = writer.retired.get_mut(&area_id) else {
            return false;
        };
        if pending.waiting.remove(&process.id).is_none() {
            return false;
        }
        if pending.waiting.is_empty() {
            writer.retired.remove(&area_id);
            self.retired_len.fetch_sub(1, Ordering::AcqRel);
            self.freed.fetch_add(1, Ordering::Relaxed);
        }
        true
    }
    /// Acknowledge every retired area this process still owes, after its GC
    /// has copied live roots out of those areas.
    pub fn release_retired(
        &self,
        process: &ProcessRegistration<'_>,
        copied_roots: u64,
    ) -> RetirementTrace {
        assert!(std::ptr::eq(self, process.store));
        let ids: Vec<u64> = self
            .retired_areas(process)
            .into_iter()
            .map(|area| area.id())
            .collect();
        let pending_before = ids.len();
        let freed_before = self.freed.load(Ordering::Relaxed);
        for id in ids {
            self.acknowledge(process, id);
        }
        let pending_after = self.retired_areas(process).len();
        let trace = RetirementTrace {
            pending_before,
            pending_after,
            freed: self
                .freed
                .load(Ordering::Relaxed)
                .saturating_sub(freed_before),
            copied_roots,
        };
        if pending_before > 0 {
            self.lock_writer().last_trace = trace;
        }
        trace
    }
    /// Number of retained areas awaiting VM acknowledgements.
    pub fn retired_count(&self) -> usize {
        self.lock_writer().retired.len()
    }
}
impl Default for Store {
    fn default() -> Self {
        Self::new()
    }
}
impl Drop for Store {
    fn drop(&mut self) {
        let guard = pin();
        let current = self
            .table
            .load(std::sync::atomic::Ordering::Relaxed, &guard);
        // SAFETY: dropping Store requires exclusive ownership; no reader can still use it.
        unsafe { drop(current.into_owned()) };
    }
}

/// A live VM process, registered for literal-area collection.
pub struct ProcessRegistration<'a> {
    store: &'a Store,
    id: u64,
    account: Option<Arc<ProcessAccount>>,
}
fn unregister_process(store: &Store, writer: &mut Writer, id: u64) {
    let mut released = 0_usize;
    writer.retired.retain(|_, pending| {
        let was_waiting = pending.waiting.remove(&id).is_some();
        let release = was_waiting && pending.waiting.is_empty();
        if release {
            released += 1;
        }
        !release
    });
    if released > 0 {
        store.retired_len.fetch_sub(released, Ordering::AcqRel);
        store.freed.fetch_add(released as u64, Ordering::Relaxed);
    }
}
impl Drop for ProcessRegistration<'_> {
    fn drop(&mut self) {
        drop(self.account.take());
        if !self.store.has_retired() {
            return;
        }
        // Process teardown is lock-free unless there are literal areas to retire.
        if WRITER_DEPTH.with(|depth| depth.get() > 0) {
            let store = self.store as *const Store;
            let id = self.id;
            DEFERRED_UNREGISTER.with(|queue| queue.borrow_mut().push((store, id)));
            return;
        }
        let mut writer = self.store.lock_writer();
        unregister_process(self.store, &mut writer, self.id);
    }
}

/// A retired area held alive while the VM scans process roots.
pub struct RetiredArea {
    id: u64,
    stored: Arc<Stored>,
}
impl RetiredArea {
    /// Stable retirement ID to pass to `Store::acknowledge`.
    pub fn id(&self) -> u64 {
        self.id
    }
    /// Whether a term pointer directly belongs to this area.
    pub fn contains(&self, term: Term) -> bool {
        self.stored.area.is_literal(term)
    }
    /// Copy a direct reference into the process heap; callers scan nested roots.
    pub fn copy_root<H: HeapAlloc>(&self, term: Term, heap: &mut H) -> Result<Term, TermError> {
        if self.contains(term) {
            copy_term(term, heap)
        } else {
            Ok(term)
        }
    }
}

struct DynHeap<'a>(&'a mut dyn HeapAlloc);
impl HeapAlloc for DynHeap<'_> {
    fn alloc(&mut self, words: usize) -> Option<*mut u64> {
        self.0.alloc(words)
    }
    fn retain_binary(&mut self, binary: Arc<Vec<u8>>) {
        self.0.retain_binary(binary);
    }
    fn retain_writable_binary(
        &mut self,
        binary: Arc<arinsal_term::WritableBinary>,
    ) -> Result<(), TermError> {
        self.0.retain_writable_binary(binary)
    }
    fn supports_writable_binary(&self) -> bool {
        self.0.supports_writable_binary()
    }
    fn retain_node(&mut self, node: Arc<Node>) {
        self.0.retain_node(node);
    }
    fn retain_fun(&mut self, entry: Arc<FunEntry>) {
        self.0.retain_fun(entry);
    }
    fn retain_export(&mut self, entry: Arc<ExportEntry>) {
        self.0.retain_export(entry);
    }
}
fn system_limit(_: TermError) -> BifError {
    BifError::SystemLimit
}
fn number(ctx: &mut Ctx<'_>, number: usize) -> Result<Term, BifError> {
    TermBuilder::new(&mut DynHeap(ctx.heap))
        .int_from_i128(number as i128)
        .map_err(system_limit)
}
fn put(_: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    // Port of erts/emulator/beam/erl_bif_persistent.c:314 (persistent_term_put_2), OTP-29.1.1
    GLOBAL.put(args[0], args[1]).map_err(system_limit)?;
    Ok(Term::atom(arinsal_term::atoms::OK))
}
fn put_new(_: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    // Port of erts/emulator/beam/erl_bif_persistent.c:319 (persistent_term_put_new_2), OTP-29.1.1
    if !GLOBAL.put_new(args[0], args[1]).map_err(system_limit)? {
        return Err(BifError::BADARG);
    }
    Ok(Term::atom(arinsal_term::atoms::OK))
}
fn get_one(_: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    // Port of erts/emulator/beam/erl_bif_persistent.c:380 (persistent_term_get_1), OTP-29.1.1
    GLOBAL.get(args[0]).ok_or(BifError::BADARG)
}
fn get_two(_: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    // Port of erts/emulator/beam/erl_bif_persistent.c:390 (persistent_term_get_2), OTP-29.1.1
    Ok(GLOBAL.get(args[0]).unwrap_or(args[1]))
}
fn erase(_: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    // Port of erts/emulator/beam/erl_bif_persistent.c:417 (persistent_term_erase_1), OTP-29.1.1
    let atom = if GLOBAL.erase(args[0]) {
        arinsal_term::atoms::TRUE
    } else {
        arinsal_term::atoms::FALSE
    };
    Ok(Term::atom(atom))
}
fn info(ctx: &mut Ctx<'_>, _: &[Term]) -> Result<Term, BifError> {
    // Port of erts/emulator/beam/erl_bif_persistent.c:569 (persistent_term_info_0), OTP-29.1.1
    let (count, memory) = GLOBAL.info();
    let count = number(ctx, count)?;
    let memory = number(ctx, memory)?;
    let atoms = global_atoms();
    arinsal_maps::from_list(
        &[
            (Term::atom(atoms.intern("count").expect("OTP atom")), count),
            (
                Term::atom(atoms.intern("memory").expect("OTP atom")),
                memory,
            ),
        ],
        ctx.heap,
    )
    .map_err(|_| BifError::SystemLimit)
}
fn get_all(ctx: &mut Ctx<'_>, _: &[Term]) -> Result<Term, BifError> {
    let mut result = Ok(Term::NIL);
    GLOBAL.for_each(|key, value| {
        if let Ok(tail) = result {
            result = (|| {
                let key = copy_term(key, &mut DynHeap(ctx.heap)).map_err(system_limit)?;
                let pair = TermBuilder::new(&mut DynHeap(ctx.heap))
                    .tuple(&[key, value])
                    .map_err(system_limit)?;
                TermBuilder::new(&mut DynHeap(ctx.heap))
                    .cons(pair, tail)
                    .map_err(system_limit)
            })();
        }
    });
    result
}
fn erase_all(_: &mut Ctx<'_>, _: &[Term]) -> Result<Term, BifError> {
    GLOBAL.clear();
    Ok(Term::atom(arinsal_term::atoms::TRUE))
}
/// Resolve the persistent-term BIFs listed in OTP 29.1.1 `bif.tab`.
pub fn lookup(module: &str, name: &str, arity: u8) -> Option<BifFn> {
    match (module, name, arity) {
        ("persistent_term", "put", 2) => Some(put),
        ("persistent_term", "put_new", 2) => Some(put_new),
        ("persistent_term", "get", 1) => Some(get_one),
        ("persistent_term", "get", 2) => Some(get_two),
        ("persistent_term", "get", 0) => Some(get_all),
        ("persistent_term", "erase", 1) => Some(erase),
        ("persistent_term", "info", 0) => Some(info),
        ("erts_internal", "erase_persistent_terms", 0) => Some(erase_all),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use arinsal_term::VecHeap;
    use std::sync::mpsc;
    use std::time::Duration;

    #[test]
    fn process_registration_does_not_take_the_writer_lock() {
        let store = Store::new();
        let writer = store.lock_writer();
        let (sent, received) = mpsc::channel();
        std::thread::scope(|scope| {
            scope.spawn(|| {
                let _process = store.register_process();
                sent.send(()).unwrap();
            });
            received
                .recv_timeout(Duration::from_secs(1))
                .expect("registration blocked behind the table writer");
        });
        drop(writer);
    }

    #[test]
    fn retirement_waits_only_for_processes_present_at_the_cutoff() {
        let store = Store::new();
        let before = store.register_process();
        let key = Term::small(2).unwrap();
        let mut heap = VecHeap::new();
        let value = TermBuilder::new(&mut heap).tuple(&[key]).unwrap();
        store.put(key, value).unwrap();
        store.put(key, key).unwrap();
        let after = store.register_process();

        let old_areas = store.retired_areas(&before);
        assert_eq!(old_areas.len(), 1);
        assert!(store.retired_areas(&after).is_empty());
        let id = old_areas[0].id();
        drop(old_areas);
        assert!(store.acknowledge(&before, id));
        assert!(!store.has_retired());
    }

    #[test]
    fn retired_storage_drops_after_all_acknowledge_and_epoch_grace() {
        let store = Store::new();
        let first = store.register_process();
        let second = store.register_process();
        let key = Term::small(1).unwrap();
        let mut heap = VecHeap::new();
        let value = TermBuilder::new(&mut heap).tuple(&[key]).unwrap();
        store.put(key, value).unwrap();
        store.put(key, Term::small(2).unwrap()).unwrap();
        let (area_id, weak) = {
            let writer = store.writer.lock().unwrap();
            let (&id, pending) = writer.retired.iter().next().unwrap();
            (id, Arc::downgrade(&pending.stored))
        };
        assert!(weak.upgrade().is_some());
        assert!(store.acknowledge(&first, area_id));
        assert!(weak.upgrade().is_some());
        assert!(store.acknowledge(&second, area_id));
        for _ in 0..32 {
            let guard = pin();
            guard.flush();
            if weak.upgrade().is_none() {
                return;
            }
            drop(guard);
            std::thread::yield_now();
        }
        assert!(
            weak.upgrade().is_none(),
            "epoch-retired table kept old area"
        );
    }
}
