//! Persistent terms and the literal-retirement handshake.
//!
//! A process handle is published through a lock-free queue. The literal-area
//! collector activates one retired area at a time, snapshots its process
//! barrier, and publishes that area for concurrent signal handling. Each
//! process copies live references before atomically acknowledging its barrier.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock, Mutex, OnceLock, RwLock, Weak};

use arinsal_bifs::{BifError, BifFn, Ctx};
use arinsal_term::{
    ExportEntry, FunEntry, HeapAlloc, LiteralArea, Node, Term, TermBuilder, TermError, VecHeap,
    copy_term, exact_eq, global_atoms, internal_hash, size_object,
};
#[cfg(test)]
use crossbeam_epoch::pin;
use crossbeam_queue::SegQueue;

static GLOBAL: LazyLock<Store> = LazyLock::new(Store::new);

fn literal_trace() -> bool {
    static FLAG: OnceLock<bool> = OnceLock::new();
    *FLAG.get_or_init(|| std::env::var_os("ARINSAL_LITERAL_TRACE").is_some())
}

/// The table used by BIF calls; the VM registers processes with this store.
pub fn global_store() -> &'static Store {
    &GLOBAL
}

// The most recent retirement of any node's store, for tests that cannot name the node.
static LAST_TRACE: [AtomicU64; 4] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];

/// The most recent literal-area retirement trace of any node's store.
pub fn last_retirement_of_any_store() -> RetirementTrace {
    RetirementTrace {
        pending_before: LAST_TRACE[0].load(Ordering::Relaxed) as usize,
        pending_after: LAST_TRACE[1].load(Ordering::Relaxed) as usize,
        freed: LAST_TRACE[2].load(Ordering::Relaxed),
        copied_roots: LAST_TRACE[3].load(Ordering::Relaxed),
    }
}

/// The store of one node (code scope). Like erts, each node has its own persistent-term
/// table and literal-area collector queue; scope 0 is the process-wide default store.
// A node's store lives for the rest of the OS process: processes and native code hold
// `'static` references into it.
pub fn store_for(scope: u64) -> &'static Store {
    // arl: a namespace scope turns on the leak-instead-of-free rule of `arl_keep_alive`
    if scope >> ARL_NS_SHIFT != 0 {
        ARL_ANY_NS.store(true, Ordering::Release);
    }
    static STORES: LazyLock<Mutex<HashMap<u64, &'static Store>>> =
        LazyLock::new(|| Mutex::new(HashMap::new()));
    if scope == 0 {
        return &GLOBAL;
    }
    let mut stores = STORES.lock().unwrap_or_else(|poison| poison.into_inner());
    stores
        .entry(scope)
        .or_insert_with(|| Box::leak(Box::new(Store::new())))
}

// arl: namespaces keep their persistent terms in a store of their own, named by a scope that
// carries the namespace id above the node's code scope.
const ARL_NS_SHIFT: u32 = 40;

// arl: set once any namespace store exists
static ARL_ANY_NS: AtomicBool = AtomicBool::new(false);

/// Modules whose keys root publishes for their client code, which runs in the caller. A
/// namespace process that misses in its own store reads these from the node store.
// arl: read-through of OTP system keys for namespaces
pub const ARL_SYSTEM_KEY_MODULES: &[&str] = &[
    "erl_prim_loader",
    "code_server",
    "kernel_os_cmd_shell",
    "global_group",
    "rex_nodes_observer",
    "prim_socket",
    "prim_net",
    "prim_file",
    "socket",
    "inet_db",
    "erl_features",
];

/// The store scope of namespace `ns` on the node with code scope `base`; `ns == 0` is the node.
pub fn arl_ns_scope(base: u64, ns: u32) -> u64 {
    debug_assert!(
        base >> ARL_NS_SHIFT == 0,
        "code scope overflows the namespace bits"
    );
    base | (u64::from(ns) << ARL_NS_SHIFT)
}

/// Keep `value` alive for the rest of the OS process once namespaces exist.
///
/// A namespace process can hold a reference into an area of another store (a literal or a
/// term sent from root) that no collector of its own store tracks, so the areas of the node
/// store are never released after the first namespace store appears. Namespace stores have no
/// collector at all, so their areas are kept too.
fn arl_keep_alive<T>(value: &Arc<T>) {
    if ARL_ANY_NS.load(Ordering::Acquire) {
        std::mem::forget(Arc::clone(value));
    }
}

/// A stable table view held across a yielding `persistent_term:get/0` call.
pub struct Snapshot {
    allocated: usize,
    num_entries: usize,
    term: Arc<Vec<Arc<BucketChunk>>>,
}

impl Snapshot {
    /// Number of key/value pairs in the captured table.
    pub fn len(&self) -> usize {
        self.num_entries
    }

    /// Whether the captured table was empty.
    pub fn is_empty(&self) -> bool {
        self.num_entries == 0
    }

    /// Find the next occupied bucket from a persistent hash-table cursor.
    pub fn entry_from(&self, cursor: usize) -> Option<(usize, (Term, Term))> {
        (cursor..self.allocated).find_map(|index| {
            self.term[index / BUCKET_CHUNK_SIZE][index % BUCKET_CHUNK_SIZE]
                .as_ref()
                .map(|item| (index + 1, (item.key, item.value)))
        })
    }
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

fn deref_table<'a>(ptr: *const Table) -> &'a Table {
    assert!(
        !ptr.is_null(),
        "persistent-term tables are installed before any load"
    );
    // SAFETY: Store::new and publish store a non-null Box with Release.
    // The table is not freed until reclaim_old_tables (after thread progress)
    // or Drop. Callers do not hold this reference across that reclaim.
    // Acquire loads synchronize with that publication.
    unsafe { &*ptr }
}

// Port of erts/emulator/beam/erl_bif_persistent.c:42 (Parameters for the hash table), OTP-29.1.1
const INITIAL_SIZE: usize = 8;
const LOAD_FACTOR: usize = 50;
const BUCKET_CHUNK_SIZE: usize = 256;

type BucketChunk = Vec<Option<Arc<Stored>>>;

#[derive(Clone)]
struct Table {
    allocated: usize,
    num_entries: usize,
    // Port of erts/emulator/beam/erl_bif_persistent.c:58 (hash_table), OTP-29.1.1
    term: Arc<Vec<Arc<BucketChunk>>>,
}

impl Table {
    fn new() -> Self {
        // Port of erts/emulator/beam/erl_bif_persistent.c:786 (create_initial_table), OTP-29.1.1
        Self {
            allocated: INITIAL_SIZE,
            num_entries: 0,
            term: Self::empty_buckets(INITIAL_SIZE),
        }
    }

    fn empty_buckets(allocated: usize) -> Arc<Vec<Arc<BucketChunk>>> {
        let chunks = allocated.div_ceil(BUCKET_CHUNK_SIZE);
        Arc::new(
            (0..chunks)
                .map(|chunk| {
                    let len = (allocated - chunk * BUCKET_CHUNK_SIZE).min(BUCKET_CHUNK_SIZE);
                    Arc::new(vec![None; len])
                })
                .collect(),
        )
    }

    fn bucket(&self, index: usize) -> &Option<Arc<Stored>> {
        &self.term[index / BUCKET_CHUNK_SIZE][index % BUCKET_CHUNK_SIZE]
    }

    fn bucket_mut(&mut self, index: usize) -> &mut Option<Arc<Stored>> {
        let chunks = Arc::make_mut(&mut self.term);
        Arc::make_mut(&mut chunks[index / BUCKET_CHUNK_SIZE])
            .get_mut(index % BUCKET_CHUNK_SIZE)
            .expect("bucket index is within the allocated table")
    }

    fn entries(&self) -> impl Iterator<Item = (usize, &Arc<Stored>)> {
        self.term
            .iter()
            .flat_map(|chunk| chunk.iter())
            .enumerate()
            .filter_map(|(index, item)| item.as_ref().map(|item| (index, item)))
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
            let bucket = self.bucket(i);
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
    area: RetiredStorage,
    generation: u64,
}
#[derive(Clone)]
enum RetiredStorage {
    Persistent(Arc<Stored>),
    Module(Arc<VecHeap>),
}
impl RetiredStorage {
    fn pointer_ranges(&self) -> Vec<(usize, usize)> {
        match self {
            Self::Persistent(stored) => stored.area.pointer_ranges(),
            Self::Module(area) => area.pointer_ranges(),
        }
    }
}
struct ProcessAccount {
    generation: u64,
    exited: AtomicBool,
    waiting_area: AtomicU64,
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
    retired_order: VecDeque<u64>,
}
struct ActiveArea {
    id: u64,
    area: RetiredStorage,
    pointer_ranges: Arc<[(usize, usize)]>,
    outstanding: AtomicUsize,
}

/// A process-independent persistent-term table.
///
/// Reads load the table pointer with acquire and do not pin an epoch. Writers
/// serialize, clone the table, and publish it atomically. The previous table is
/// freed only after thread progress, the same window erts uses for
/// `erts_schedule_thr_prgr_later_op`. Term pointers returned by reads stay
/// valid through the VM protocol described in this module.
pub struct Store {
    table: AtomicPtr<Table>,
    /// Tables replaced by `publish`, freed by [`Store::reclaim_old_tables`].
    old_tables: Mutex<Vec<usize>>,
    writer: Mutex<Writer>,
    active_area: RwLock<Option<Arc<ActiveArea>>>,
    /// Set before `active_area` becomes `Some`, cleared after it becomes `None`.
    /// Exit skips the lock when no literal release is in progress
    /// (erl_process.c:14374, `block_rla_ref` stays 0 for an immediate reason).
    active_set: AtomicBool,
    last_trace: [AtomicU64; 4],
    processes: SegQueue<Weak<ProcessAccount>>,
    registration_generation: AtomicU64,
    registrations_in_flight: AtomicUsize,
    process_scan: Mutex<()>,
    /// Areas waiting for process GC. Lock-free so collection can skip the scan.
    retired_len: AtomicUsize,
    retired_generation: AtomicU64,
    /// Areas whose last waiter has acknowledged them.
    freed: AtomicU64,
    /// Published table updates; a change tells the caller to wait for thread progress.
    updates: AtomicU64,
    /// Account of the process holding the update permission (0 when free).
    updater: AtomicUsize,
}

impl Store {
    fn lock_writer(&self) -> std::sync::MutexGuard<'_, Writer> {
        self.writer.lock().expect("persistent-term writer poisoned")
    }
    /// Create an empty store.
    pub fn new() -> Self {
        Self {
            table: AtomicPtr::new(Box::into_raw(Box::new(Table::new()))),
            old_tables: Mutex::new(Vec::new()),
            writer: Mutex::new(Writer {
                next_area: 1,
                retired: HashMap::new(),
                retired_order: VecDeque::new(),
            }),
            active_area: RwLock::new(None),
            active_set: AtomicBool::new(false),
            last_trace: std::array::from_fn(|_| AtomicU64::new(0)),
            processes: SegQueue::new(),
            registration_generation: AtomicU64::new(0),
            registrations_in_flight: AtomicUsize::new(0),
            process_scan: Mutex::new(()),
            retired_len: AtomicUsize::new(0),
            retired_generation: AtomicU64::new(0),
            freed: AtomicU64::new(0),
            updates: AtomicU64::new(0),
            updater: AtomicUsize::new(0),
        }
    }
    /// Whether any literal area is waiting for a process collection.
    pub fn has_retired(&self) -> bool {
        self.retired_len.load(Ordering::Acquire) != 0
    }
    /// Monotonic generation advanced whenever a new area needs collector work.
    pub fn retired_generation(&self) -> u64 {
        self.retired_generation.load(Ordering::Acquire)
    }
    /// Monotonic count of published table updates (`put`, `erase`, `clear`).
    pub fn table_updates(&self) -> u64 {
        self.updates.load(Ordering::Acquire)
    }
    /// Areas released after their last process acknowledged them.
    pub fn freed_literal_areas(&self) -> u64 {
        self.freed.load(Ordering::Relaxed)
    }
    /// Latest GC retirement trace. Zero until a collection owed an area.
    pub fn last_retirement(&self) -> RetirementTrace {
        RetirementTrace {
            pending_before: self.last_trace[0].load(Ordering::Relaxed) as usize,
            pending_after: self.last_trace[1].load(Ordering::Relaxed) as usize,
            freed: self.last_trace[2].load(Ordering::Relaxed),
            copied_roots: self.last_trace[3].load(Ordering::Relaxed),
        }
    }
    /// A handle that is not in the retirement barrier yet.
    ///
    /// `set_runtime` registers the process with its node's store. Registering
    /// with the global store first would enqueue and then drop that account.
    pub fn unregistered(&self) -> ProcessRegistration<'_> {
        ProcessRegistration {
            store: self,
            account: None,
        }
    }

    /// Register a process for literal retirement before its first read.
    pub fn register_process(&self) -> ProcessRegistration<'_> {
        self.registrations_in_flight.fetch_add(1, Ordering::SeqCst);
        let generation = self.registration_generation.load(Ordering::Acquire);
        let account = Arc::new(ProcessAccount {
            generation,
            exited: AtomicBool::new(false),
            waiting_area: AtomicU64::new(0),
            capacity: AtomicU64::new(0),
            used: AtomicU64::new(0),
            binary: AtomicU64::new(0),
        });
        self.processes.push(Arc::downgrade(&account));
        self.registrations_in_flight.fetch_sub(1, Ordering::SeqCst);
        ProcessRegistration {
            store: self,
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
                live.push(Arc::downgrade(&account));
                // Port of erts/emulator/beam/erl_process.c (delete_process), OTP-29.1.1: an
                // exited process has freed its heap and off-heap list even while its
                // registration lingers.
                if account.exited.load(Ordering::Acquire) {
                    continue;
                }
                capacity += account.capacity.load(Ordering::Relaxed);
                used += account.used.load(Ordering::Relaxed);
                binary += account.binary.load(Ordering::Relaxed);
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
        // Port of erts/emulator/beam/erl_bif_persistent.c:358 (`erts_atomic_read_nob`
        // of `the_hash_table`), OTP-29.1.1. The load is not pinned: `publish` does
        // not destroy the previous table until `reclaim_old_tables`, which runs
        // only after thread progress or when this `Store` is dropped. `get` does
        // not yield, so it cannot overlap that reclaim.
        let table = deref_table(self.table.load(Ordering::Acquire));
        let idx = table.lookup(key, hash);
        table.bucket(idx).as_ref().map(|item| item.value)
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
        let current = self.table.load(Ordering::Acquire);
        let current_table = deref_table(current);

        let idx = current_table.lookup(key, hash);
        if let Some(old) = current_table.bucket(idx) {
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
        let mut next = if current_table.bucket(idx).is_none() && current_table.must_grow() {
            let mut new_table = Table {
                allocated: current_table.allocated * 2,
                num_entries: current_table.num_entries,
                term: Table::empty_buckets(current_table.allocated * 2),
            };
            // Port of erts/emulator/beam/erl_bif_persistent.c:1100 (copy_table_place_3), OTP-29.1.1
            for (_, item) in current_table.entries() {
                let new_idx = new_table.lookup(item.key, lookup_hash(item.key));
                *new_table.bucket_mut(new_idx) = Some(Arc::clone(item));
            }
            new_table
        } else {
            current_table.clone()
        };

        let new_idx = next.lookup(key, hash);
        if let Some(old) = next.bucket_mut(new_idx).replace(entry) {
            self.retire(&mut writer, old);
        } else {
            next.num_entries += 1;
        }

        // Port of erts/emulator/beam/erl_bif_persistent.c:275 (TRAPPING_COPY_TABLE), OTP-29.1.1
        // Table copying is completed before publication; the frozen BIF ABI has no trap result.
        self.publish(next, current);
        Ok(true)
    }
    /// Remove a key; return whether it existed.
    // Port of erts/emulator/beam/erl_bif_persistent.c:417 (persistent_term_erase_1), OTP-29.1.1
    pub fn erase(&self, key: Term) -> bool {
        let hash = lookup_hash(key);
        let mut writer = self.lock_writer();
        let current = self.table.load(Ordering::Acquire);
        let current_table = deref_table(current);

        let idx = current_table.lookup(key, hash);
        if current_table.bucket(idx).is_none() {
            return false;
        }

        // Port of erts/emulator/beam/erl_bif_persistent.c:1025 (is_erasable), OTP-29.1.1
        let is_erasable = current_table
            .bucket((idx + 1) & (current_table.allocated - 1))
            .is_none();

        let mut next;
        let old;

        if !current_table.must_shrink() && is_erasable {
            // Port of erts/emulator/beam/erl_bif_persistent.c:478 (fast erase), OTP-29.1.1
            next = current_table.clone();
            old = next.bucket_mut(idx).take().unwrap();
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
                term: Table::empty_buckets(new_size),
            };
            old = current_table.bucket(idx).clone().unwrap();

            for (i, stored) in current_table.entries() {
                if i != idx {
                    let new_idx = next.lookup(stored.key, lookup_hash(stored.key));
                    *next.bucket_mut(new_idx) = Some(Arc::clone(stored));
                }
            }
        }
        self.retire(&mut writer, old);
        self.publish(next, current);
        true
    }
    /// Atomically erase all persistent terms, as `erts_internal:erase_persistent_terms/0`.
    // Port of erts/emulator/beam/erl_bif_persistent.c:1142 (mark_for_deletion), OTP-29.1.1
    pub fn clear(&self) {
        let mut writer = self.lock_writer();
        let current = self.table.load(Ordering::Acquire);
        for (_, stored) in deref_table(current).entries() {
            self.retire(&mut writer, Arc::clone(stored));
        }
        self.publish(Table::new(), current);
    }
    fn retire(&self, writer: &mut Writer, old: Arc<Stored>) {
        // arl: see arl_keep_alive
        arl_keep_alive(&old);
        // Port of erts/emulator/beam/erl_bif_persistent.c:1229 (delete_tuple), OTP-29.1.1
        if old.value.is_pointer() {
            // Port of erts/emulator/beam/beam_bif_load.c:1794-1946
            // (release_literal_area_switch), OTP-29.1.1. A generation cutoff
            // replaces the per-process writer-locked registration snapshot;
            // processes that existed before this area retired acknowledge it
            // only after their next GC rewrites all roots.
            let generation = self.start_retirement();
            self.finish_retirement(writer, RetiredStorage::Persistent(old), generation);
        }
    }

    /// Retain a purged module's literal heap until every existing process has copied its roots.
    pub fn retire_module_area(&self, area: Arc<VecHeap>) {
        // arl: see arl_keep_alive
        arl_keep_alive(&area);
        let mut writer = self.lock_writer();
        let generation = self.start_retirement();
        self.finish_retirement(&mut writer, RetiredStorage::Module(area), generation);
    }

    fn start_retirement(&self) -> u64 {
        // Port of erts/emulator/beam/erl_bif_persistent.c:1191-1203, OTP-29.1.1.
        // The preloaded collector owns one process snapshot at a time; queued
        // areas retain only this cutoff until release_literal_area_switch.
        self.retired_len.fetch_add(1, Ordering::Release);
        let generation = self.registration_generation.fetch_add(1, Ordering::SeqCst);
        while self.registrations_in_flight.load(Ordering::SeqCst) != 0 {
            std::hint::spin_loop();
        }
        generation
    }

    fn finish_retirement(&self, writer: &mut Writer, area: RetiredStorage, generation: u64) {
        let id = writer.next_area;
        writer.next_area += 1;
        writer.retired.insert(id, Pending { area, generation });
        writer.retired_order.push_back(id);
        self.retired_generation.fetch_add(1, Ordering::Release);
    }
    fn publish(&self, next: Table, current: *mut Table) {
        self.table
            .store(Box::into_raw(Box::new(next)), Ordering::Release);
        self.updates.fetch_add(1, Ordering::Release);
        // Port of erts/emulator/beam/erl_bif_persistent.c:1175 (`table_updater` frees
        // the old table from a thread-progress later op, not from the publisher),
        // OTP-29.1.1. The pointer stays live for any `get` that already loaded it.
        self.old_tables
            .lock()
            .expect("persistent-term old tables poisoned")
            .push(current as usize);
    }

    /// Drop tables queued by [`Store::publish`].
    ///
    /// Call only after thread progress (every scheduler has left `get`) or from
    /// `Drop`, when no reader can still hold a queued pointer.
    pub fn reclaim_old_tables(&self) {
        let pending = std::mem::take(
            &mut *self
                .old_tables
                .lock()
                .expect("persistent-term old tables poisoned"),
        );
        for bits in pending {
            // SAFETY: `bits` is a Box `publish` replaced. No `get` still holds it:
            // the caller waited for thread progress, or this `Store` is being dropped.
            unsafe { drop(Box::from_raw(bits as *mut Table)) };
        }
    }
    /// Snapshot count and allocated bytes, including the table and live areas.
    // Port of erts/emulator/beam/erl_bif_persistent.c:569 (persistent_term_info_0), OTP-29.1.1
    pub fn info(&self) -> (usize, usize) {
        let table = deref_table(self.table.load(Ordering::Acquire));
        // Port of erts/emulator/beam/erl_bif_persistent.c:970 (memory), OTP-29.1.1
        let bytes = 96 // sizeof(HashTable) + offsetof(HashTable, term) is 96 in erl
            + (table.allocated - 1) * 8 // term array inside HashTable
            + table
                .entries()
                .map(|(_, item)| 16 + item.area.used_words() * 8) // size of literal area struct + words
                .sum::<usize>();
        (table.num_entries, bytes)
    }
    /// Visit a consistent snapshot of all key/value pairs.
    pub fn for_each(&self, mut visit: impl FnMut(Term, Term)) {
        let table = deref_table(self.table.load(Ordering::Acquire));
        for (_, item) in table.entries() {
            visit(item.key, item.value);
        }
    }
    /// Capture the current table without retaining the table epoch guard.
    pub fn snapshot(&self) -> Snapshot {
        let table = deref_table(self.table.load(Ordering::Acquire));
        Snapshot {
            allocated: table.allocated,
            num_entries: table.num_entries,
            term: Arc::clone(&table.term),
        }
    }
    /// Return retired areas this process still needs to scan and copy.
    pub fn retired_areas(&self, process: &ProcessRegistration<'_>) -> Vec<RetiredArea> {
        assert!(std::ptr::eq(self, process.store));
        let Some(account) = process.account.as_ref() else {
            return Vec::new();
        };
        let Some(active) = self
            .active_area
            .read()
            .expect("active literal area poisoned")
            .as_ref()
            .cloned()
        else {
            return Vec::new();
        };
        (account.waiting_area.load(Ordering::Acquire) == active.id)
            .then(|| RetiredArea {
                id: active.id,
                _area: active.area.clone(),
                pointer_ranges: Arc::clone(&active.pointer_ranges),
            })
            .into_iter()
            .collect()
    }
    /// Whether a live process predates any area still waiting for collector release.
    pub fn has_pending_for(&self, process: &ProcessRegistration<'_>) -> bool {
        assert!(std::ptr::eq(self, process.store));
        let Some(account) = process.account.as_ref() else {
            return false;
        };
        let writer = self.lock_writer();
        writer
            .retired
            .values()
            .any(|pending| account.generation <= pending.generation)
    }
    /// Switch the collector to the oldest area that still has process references.
    // Port of erts/emulator/beam/beam_bif_load.c:1801 (release_literal_area_switch), OTP-29.1.1.
    pub fn collector_switch_area(&self) -> bool {
        let mut writer = self.lock_writer();
        let current_active = {
            self.active_area
                .read()
                .expect("active literal area poisoned")
                .as_ref()
                .cloned()
        };
        if let Some(active) = current_active {
            if active.outstanding.load(Ordering::Acquire) != 0 {
                return true;
            }
            let mut slot = self
                .active_area
                .write()
                .expect("active literal area poisoned");
            if slot
                .as_ref()
                .is_some_and(|current| Arc::ptr_eq(current, &active))
            {
                slot.take();
                self.active_set.store(false, Ordering::Release);
                arinsal_term::set_literal_purge_area(&active.pointer_ranges, false);
            }
            if literal_trace()
                && let RetiredStorage::Persistent(stored) = &active.area
            {
                eprintln!(
                    "literal_release area={} stored_refs={}",
                    active.id,
                    Arc::strong_count(stored)
                );
            }
            if literal_trace()
                && let RetiredStorage::Module(area) = &active.area
            {
                eprintln!(
                    "literal_release module_area={} words={} area_refs={}",
                    active.id,
                    area.used_words(),
                    Arc::strong_count(area)
                );
            }
            writer.retired.remove(&active.id);
            self.note_area_freed();
            if writer.retired_order.front() == Some(&active.id) {
                writer.retired_order.pop_front();
            }
        }
        loop {
            let Some(id) = writer.retired_order.front().copied() else {
                return false;
            };
            let Some((generation, area)) = writer
                .retired
                .get(&id)
                .map(|pending| (pending.generation, pending.area.clone()))
            else {
                writer.retired_order.pop_front();
                continue;
            };
            if generation > self.registration_generation.load(Ordering::Acquire) {
                return false;
            }
            let _scan = self.process_scan.lock().expect("process scan poisoned");
            while self.registrations_in_flight.load(Ordering::SeqCst) != 0 {
                std::hint::spin_loop();
            }
            let mut live = Vec::new();
            let mut waiting = Vec::new();
            while let Some(account) = self.processes.pop() {
                if let Some(account) = account.upgrade() {
                    // Port of erts/preloaded/src/erts_literal_area_collector.erl:
                    // every live process gets a copy-literals request, not only
                    // those that existed at retirement; younger processes may
                    // have received references in messages or spawn arguments.
                    if !account.exited.load(Ordering::Acquire) {
                        waiting.push(Arc::clone(&account));
                    }
                    live.push(Arc::downgrade(&account));
                }
            }
            for account in live {
                self.processes.push(account);
            }
            if waiting.is_empty() {
                writer.retired.remove(&id);
                writer.retired_order.pop_front();
                self.note_area_freed();
                continue;
            }
            for account in &waiting {
                account.waiting_area.store(id, Ordering::Release);
            }
            let active = Arc::new(ActiveArea {
                id,
                pointer_ranges: Arc::from(area.pointer_ranges()),
                area,
                outstanding: AtomicUsize::new(waiting.len()),
            });
            // Port of erts/emulator/beam/beam_bif_load.c:1715 (rla_switch_area):
            // literal-aware copies now copy this area instead of sharing it.
            arinsal_term::set_literal_purge_area(&active.pointer_ranges, true);
            // Publish the flag before the slot so an exiting process either sees the area
            // or has already stored `exited`, which the scan below acknowledges.
            self.active_set.store(true, Ordering::Release);
            *self
                .active_area
                .write()
                .expect("active literal area poisoned") = Some(Arc::clone(&active));
            if literal_trace() {
                eprintln!("literal_switch area={} waiting={}", id, waiting.len());
            }
            for account in &waiting {
                if account.exited.load(Ordering::Acquire) {
                    self.acknowledge_account(&active, account, 0);
                }
            }
            if active.outstanding.load(Ordering::Acquire) != 0 {
                return true;
            }
        }
    }
    fn note_area_freed(&self) {
        self.retired_len.fetch_sub(1, Ordering::AcqRel);
        self.freed.fetch_add(1, Ordering::Relaxed);
        self.last_trace[2].fetch_add(1, Ordering::Relaxed);
        LAST_TRACE[2].fetch_add(1, Ordering::Relaxed);
    }
    /// Internal identifier for the area currently being copied by the collector.
    pub fn collector_area(&self) -> Option<u64> {
        self.active_area
            .read()
            .expect("active literal area poisoned")
            .as_ref()
            .map(|active| active.id)
    }
    /// Whether every process has completed copying the active area.
    pub fn collector_area_complete(&self) -> bool {
        self.active_area
            .read()
            .expect("active literal area poisoned")
            .as_ref()
            .is_some_and(|active| active.outstanding.load(Ordering::Acquire) == 0)
    }
    /// Return one area this process still owes to the collector.
    pub fn retired_area(
        &self,
        process: &ProcessRegistration<'_>,
        area_id: u64,
    ) -> Option<RetiredArea> {
        assert!(std::ptr::eq(self, process.store));
        let active = self
            .active_area
            .read()
            .expect("active literal area poisoned")
            .as_ref()
            .filter(|active| active.id == area_id)?
            .clone();
        Some(RetiredArea {
            id: area_id,
            _area: active.area.clone(),
            pointer_ranges: Arc::clone(&active.pointer_ranges),
        })
    }
    /// Acknowledge after scanning all process roots and copying live references.
    pub fn acknowledge(&self, process: &ProcessRegistration<'_>, area_id: u64) -> bool {
        self.acknowledge_copied(process, area_id, 0)
    }
    /// Acknowledge one collector area and record the process's scan result.
    pub fn acknowledge_copied(
        &self,
        process: &ProcessRegistration<'_>,
        area_id: u64,
        copied_roots: u64,
    ) -> bool {
        assert!(std::ptr::eq(self, process.store));
        let Some(account) = process.account.as_ref() else {
            return false;
        };
        let Some(active) = self
            .active_area
            .read()
            .expect("active literal area poisoned")
            .as_ref()
            .filter(|active| active.id == area_id)
            .cloned()
        else {
            return false;
        };
        self.acknowledge_account(&active, account, copied_roots)
    }

    fn acknowledge_account(
        &self,
        active: &ActiveArea,
        account: &ProcessAccount,
        copied_roots: u64,
    ) -> bool {
        if account
            .waiting_area
            .compare_exchange(active.id, 0, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return false;
        }
        let before = active.outstanding.fetch_sub(1, Ordering::AcqRel);
        if literal_trace() {
            eprintln!(
                "literal_ack area={} before={} copied={}",
                active.id, before, copied_roots
            );
        }
        self.last_trace[0].store(before as u64, Ordering::Relaxed);
        self.last_trace[1].store(before.saturating_sub(1) as u64, Ordering::Relaxed);
        self.last_trace[3].store(copied_roots, Ordering::Relaxed);
        LAST_TRACE[0].store(before as u64, Ordering::Relaxed);
        LAST_TRACE[1].store(before.saturating_sub(1) as u64, Ordering::Relaxed);
        LAST_TRACE[3].store(copied_roots, Ordering::Relaxed);
        true
    }
    /// Take the global update permission for `process`; `true` when it already holds it.
    // Port of erts/emulator/beam/erl_bif_persistent.c:1312 (try_seize_update_permission),
    // OTP-29.1.1. A process that fails yields and retries instead of joining a wait queue.
    pub fn try_seize_update_permission(&self, process: &ProcessRegistration<'_>) -> bool {
        assert!(std::ptr::eq(self, process.store));
        let owner = registration_owner(process);
        match self
            .updater
            .compare_exchange(0, owner, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) => true,
            Err(current) => current == owner,
        }
    }
    /// Release the update permission if `process` holds it.
    // Port of erts/emulator/beam/erl_bif_persistent.c:1338 (release_update_permission),
    // OTP-29.1.1.
    pub fn release_update_permission(&self, process: &ProcessRegistration<'_>) {
        assert!(std::ptr::eq(self, process.store));
        let owner = registration_owner(process);
        let _ = self
            .updater
            .compare_exchange(owner, 0, Ordering::AcqRel, Ordering::Acquire);
    }
    /// Remove a terminated process from the active retirement barrier.
    pub fn process_exited(&self, process: &ProcessRegistration<'_>) {
        assert!(std::ptr::eq(self, process.store));
        // erts finishes a suspended updater's table_updater even when the process is
        // killed, which releases the permission; the update is already published here.
        self.release_update_permission(process);
        process
            .account
            .as_ref()
            .expect("live process registration")
            .exited
            .store(true, Ordering::Release);
        if !self.active_set.load(Ordering::Acquire) {
            return;
        }
        if let Some(account) = process.account.as_ref()
            && let Some(active) = self
                .active_area
                .read()
                .expect("active literal area poisoned")
                .as_ref()
                .cloned()
        {
            self.acknowledge_account(&active, account, 0);
        }
    }
    /// Acknowledge the active area after this process has copied its live roots.
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
            self.last_trace[0].store(trace.pending_before as u64, Ordering::Relaxed);
            self.last_trace[1].store(trace.pending_after as u64, Ordering::Relaxed);
            self.last_trace[2].store(trace.freed, Ordering::Relaxed);
            self.last_trace[3].store(trace.copied_roots, Ordering::Relaxed);
        }
        trace
    }
    /// Number of retained areas queued for or awaiting collector release.
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
        self.reclaim_old_tables();
        let current = self.table.load(Ordering::Relaxed);
        // SAFETY: dropping Store requires exclusive ownership; no reader can still use it.
        unsafe { drop(Box::from_raw(current)) };
    }
}

/// A live VM process, registered for literal-area collection.
pub struct ProcessRegistration<'a> {
    store: &'a Store,
    account: Option<Arc<ProcessAccount>>,
}
impl<'a> ProcessRegistration<'a> {
    /// The node store this process is registered with.
    pub fn store(&self) -> &'a Store {
        self.store
    }

    /// Whether [`Store::register_process`] built this handle.
    pub fn is_registered(&self) -> bool {
        self.account.is_some()
    }
}

impl Drop for ProcessRegistration<'_> {
    fn drop(&mut self) {
        self.store.release_update_permission(self);
        if let Some(account) = self.account.take() {
            account.exited.store(true, Ordering::Release);
            if !self.store.active_set.load(Ordering::Acquire) {
                return;
            }
            if let Some(active) = self
                .store
                .active_area
                .read()
                .expect("active literal area poisoned")
                .as_ref()
                .cloned()
            {
                self.store.acknowledge_account(&active, &account, 0);
            }
        }
    }
}

fn registration_owner(process: &ProcessRegistration<'_>) -> usize {
    process
        .account
        .as_ref()
        .map_or(0, |account| Arc::as_ptr(account) as usize)
}

/// A retired area held alive while the VM scans process roots.
pub struct RetiredArea {
    id: u64,
    _area: RetiredStorage,
    pointer_ranges: Arc<[(usize, usize)]>,
}
impl RetiredArea {
    /// Stable retirement ID to pass to `Store::acknowledge`.
    pub fn id(&self) -> u64 {
        self.id
    }
    /// Whether a term pointer directly belongs to this area.
    pub fn contains(&self, term: Term) -> bool {
        if !term.is_pointer() {
            return false;
        }
        let address = (term.tagged_word() & !7) as usize;
        self.pointer_ranges
            .iter()
            .any(|&(start, end)| address >= start && address < end)
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

struct HeapAdapter<'a, H: HeapAlloc + ?Sized>(&'a mut H);
impl<H: HeapAlloc + ?Sized> HeapAlloc for HeapAdapter<'_, H> {
    fn alloc(&mut self, words: usize) -> Option<*mut u64> {
        self.0.alloc(words)
    }
    fn retain_binary(&mut self, binary: Arc<arinsal_term::RefcBinary>) {
        self.0.retain_binary(binary);
    }
    fn link_bin_ref(
        &mut self,
        bin_ref: *mut u64,
        writable: bool,
        overhead_words: u64,
        owner: Option<arinsal_term::OwnedBinaryRef>,
    ) -> Result<(), TermError> {
        HeapAlloc::link_bin_ref(self.0, bin_ref, writable, overhead_words, owner)
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
    TermBuilder::new(&mut HeapAdapter(&mut ctx.heap))
        .int_from_i128(number as i128)
        .map_err(system_limit)
}
fn put_in(store: &Store, _: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    // Port of erts/emulator/beam/erl_bif_persistent.c:314 (persistent_term_put_2), OTP-29.1.1
    store.put(args[0], args[1]).map_err(system_limit)?;
    Ok(Term::atom(arinsal_term::atoms::OK))
}
fn put_new_in(store: &Store, _: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    // Port of erts/emulator/beam/erl_bif_persistent.c:319 (persistent_term_put_new_2), OTP-29.1.1
    if !store.put_new(args[0], args[1]).map_err(system_limit)? {
        return Err(BifError::BADARG);
    }
    Ok(Term::atom(arinsal_term::atoms::OK))
}
fn get_one_in(store: &Store, _: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    // Port of erts/emulator/beam/erl_bif_persistent.c:380 (persistent_term_get_1), OTP-29.1.1
    store.get(args[0]).ok_or(BifError::BADARG)
}
fn get_two_in(store: &Store, _: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    // Port of erts/emulator/beam/erl_bif_persistent.c:390 (persistent_term_get_2), OTP-29.1.1
    Ok(store.get(args[0]).unwrap_or(args[1]))
}
fn erase_in(store: &Store, _: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    // Port of erts/emulator/beam/erl_bif_persistent.c:417 (persistent_term_erase_1), OTP-29.1.1
    let atom = if store.erase(args[0]) {
        arinsal_term::atoms::TRUE
    } else {
        arinsal_term::atoms::FALSE
    };
    Ok(Term::atom(atom))
}
fn info_in(store: &Store, ctx: &mut Ctx<'_>, _: &[Term]) -> Result<Term, BifError> {
    // Port of erts/emulator/beam/erl_bif_persistent.c:569 (persistent_term_info_0), OTP-29.1.1
    let (count, memory) = store.info();
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
        &mut ctx.heap,
    )
    .map_err(|_| BifError::SystemLimit)
}
fn get_all_in(store: &Store, ctx: &mut Ctx<'_>, _: &[Term]) -> Result<Term, BifError> {
    let mut result = Ok(Term::NIL);
    store.for_each(|key, value| {
        if let Ok(tail) = result {
            result = (|| {
                let key = copy_term(key, &mut HeapAdapter(&mut ctx.heap)).map_err(system_limit)?;
                let pair = TermBuilder::new(&mut HeapAdapter(&mut ctx.heap))
                    .tuple(&[key, value])
                    .map_err(system_limit)?;
                TermBuilder::new(&mut HeapAdapter(&mut ctx.heap))
                    .cons(pair, tail)
                    .map_err(system_limit)
            })();
        }
    });
    result
}
fn erase_all_in(store: &Store, _: &mut Ctx<'_>, _: &[Term]) -> Result<Term, BifError> {
    store.clear();
    Ok(Term::atom(arinsal_term::atoms::TRUE))
}
fn put(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    put_in(&GLOBAL, ctx, args)
}
fn put_new(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    put_new_in(&GLOBAL, ctx, args)
}
fn get_one(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    get_one_in(&GLOBAL, ctx, args)
}
fn get_two(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    get_two_in(&GLOBAL, ctx, args)
}
fn erase(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    erase_in(&GLOBAL, ctx, args)
}
fn info(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    info_in(&GLOBAL, ctx, args)
}
fn get_all(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    get_all_in(&GLOBAL, ctx, args)
}
fn erase_all(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    erase_all_in(&GLOBAL, ctx, args)
}
/// A persistent-term BIF that operates on a given node's store.
pub type StoreBif = fn(&Store, &mut Ctx<'_>, &[Term]) -> Result<Term, BifError>;

/// Resolve the persistent-term BIFs listed in OTP 29.1.1 `bif.tab` for a node's store.
pub fn lookup_in(module: &str, name: &str, arity: u8) -> Option<StoreBif> {
    match (module, name, arity) {
        ("persistent_term", "put", 2) => Some(put_in),
        ("persistent_term", "put_new", 2) => Some(put_new_in),
        ("persistent_term", "get", 1) => Some(get_one_in),
        ("persistent_term", "get", 2) => Some(get_two_in),
        ("persistent_term", "get", 0) => Some(get_all_in),
        ("persistent_term", "erase", 1) => Some(erase_in),
        ("persistent_term", "info", 0) => Some(info_in),
        ("erts_internal", "erase_persistent_terms", 0) => Some(erase_all_in),
        _ => None,
    }
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
    fn retirement_waits_for_every_live_process_at_the_switch() {
        // A process registered after the erase may have received the literal in a
        // message or as a spawn argument, so the collector waits for it too.
        let store = Store::new();
        let before = store.register_process();
        let key = Term::small(2).unwrap();
        let mut heap = VecHeap::new();
        let value = TermBuilder::new(&mut heap).tuple(&[key]).unwrap();
        store.put(key, value).unwrap();
        store.put(key, key).unwrap();
        let after = store.register_process();

        assert!(store.collector_switch_area());
        let old_areas = store.retired_areas(&before);
        assert_eq!(old_areas.len(), 1);
        assert_eq!(store.retired_areas(&after).len(), 1);
        let id = old_areas[0].id();
        drop(old_areas);
        assert!(store.acknowledge(&before, id));
        assert!(store.collector_switch_area());
        assert!(store.acknowledge(&after, id));
        assert!(!store.collector_switch_area());
        assert!(!store.has_retired());
    }

    #[test]
    fn purged_module_literals_wait_for_all_existing_processes() {
        let store = Store::new();
        let first = store.register_process();
        let second = store.register_process();
        let mut area = VecHeap::new();
        let literal = TermBuilder::new(&mut area)
            .tuple(&[Term::small(23).unwrap()])
            .unwrap();
        let area = Arc::new(area);
        store.retire_module_area(Arc::clone(&area));

        assert!(store.collector_switch_area());
        let retired = store.retired_areas(&first);
        assert_eq!(retired.len(), 1);
        assert!(retired[0].contains(literal));
        assert!(store.retired_areas(&second)[0].contains(literal));
        let id = retired[0].id();
        drop(retired);
        assert!(store.collector_switch_area());
        assert!(store.acknowledge(&first, id));
        assert!(store.has_retired());
        assert!(store.acknowledge(&second, id));
        assert!(!store.collector_switch_area());
        assert!(!store.has_retired());
    }

    #[test]
    fn concurrent_processes_acknowledge_one_active_area() {
        let store = Store::new();
        let processes: Vec<_> = (0..64).map(|_| store.register_process()).collect();
        let area = Arc::new(VecHeap::new());
        store.retire_module_area(area);
        assert!(store.collector_switch_area());
        let area_id = store.collector_area().unwrap();

        std::thread::scope(|scope| {
            let store = &store;
            for process in &processes {
                scope.spawn(move || assert!(store.acknowledge(process, area_id)));
            }
        });

        assert!(!store.collector_switch_area());
        assert!(!store.has_retired());
    }

    #[test]
    fn exited_processes_are_not_added_to_later_retirement_barriers() {
        let store = Store::new();
        let process = store.register_process();
        store.process_exited(&process);
        let mut area = VecHeap::new();
        let literal = TermBuilder::new(&mut area)
            .tuple(&[Term::small(23).unwrap()])
            .unwrap();
        store.retire_module_area(Arc::new(area));
        assert!(store.has_retired());
        assert!(!store.collector_switch_area());
        assert!(!store.has_retired());
        assert!(store.retired_areas(&process).is_empty());
        assert!(literal.is_pointer());
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
        assert!(store.collector_switch_area());
        let (area_id, weak) = {
            let writer = store.writer.lock().unwrap();
            let (&id, pending) = writer.retired.iter().next().unwrap();
            let RetiredStorage::Persistent(stored) = &pending.area else {
                unreachable!("persistent-term test stores a persistent area")
            };
            (id, Arc::downgrade(stored))
        };
        assert!(weak.upgrade().is_some());
        assert!(store.collector_switch_area());
        assert!(store.acknowledge(&first, area_id));
        assert!(weak.upgrade().is_some());
        assert!(store.acknowledge(&second, area_id));
        assert!(!store.collector_switch_area());
        // The replaced table still owns an `Arc` of the retired area until thread
        // progress frees it. This test has no concurrent reader, so reclaim here.
        store.reclaim_old_tables();
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
