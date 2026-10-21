//! Persistent terms and the literal-retirement handshake.
//!
//! Erased terms and purged module literals queue as retired areas. The literal-area
//! collector process (erts_literal_area_collector.erl) activates one at a time, sends every
//! process a copy request and, once every process answered, switches to the next area, which
//! releases the previous one. As in erts, no process is registered with the store: the
//! collector walks the process table.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock, Mutex, OnceLock, RwLock};

use arinsal_bifs::{BifError, BifFn, Ctx};
use arinsal_term::{
    HeapAlloc, LiteralArea, Node, Term, TermBuilder, TermError, VecHeap, copy_term, exact_eq,
    global_atoms, internal_hash, size_object,
};
#[cfg(test)]
use crossbeam_epoch::pin;

static GLOBAL: LazyLock<Store> = LazyLock::new(Store::new);

fn literal_trace() -> bool {
    static FLAG: OnceLock<bool> = OnceLock::new();
    *FLAG.get_or_init(|| std::env::var_os("ARINSAL_LITERAL_TRACE").is_some())
}

/// The table used by BIF calls outside a node.
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
    /// Areas waiting for process GC. Lock-free so collection can skip the scan.
    retired_len: AtomicUsize,
    retired_generation: AtomicU64,
    /// Areas whose last waiter has acknowledged them.
    freed: AtomicU64,
    /// Published table updates; a change tells the caller to wait for thread progress.
    updates: AtomicU64,
    /// `updater_process`: the process holding the update permission, 0 when free.
    updater: AtomicU64,
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
            retired_len: AtomicUsize::new(0),
            retired_generation: AtomicU64::new(0),
            freed: AtomicU64::new(0),
            updates: AtomicU64::new(0),
            updater: AtomicU64::new(0),
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
        // Port of erts/emulator/beam/erl_bif_persistent.c:1229 (delete_tuple), OTP-29.1.1
        if old.value.is_pointer() {
            // Port of erts/emulator/beam/erl_bif_persistent.c (delete_tuple queues the
            // literal area with erts_queue_release_literals), OTP-29.1.1.
            self.queue_release(writer, RetiredStorage::Persistent(old));
        }
    }

    /// Retain a purged module's literal heap until every existing process has copied its roots.
    pub fn retire_module_area(&self, area: Arc<VecHeap>) {
        let mut writer = self.lock_writer();
        self.queue_release(&mut writer, RetiredStorage::Module(area));
    }

    /// Queue an area for the literal-area collector.
    ///
    /// Port of erts/emulator/beam/beam_bif_load.c (erts_queue_release_literals), OTP-29.1.1.
    fn queue_release(&self, writer: &mut Writer, area: RetiredStorage) {
        self.retired_len.fetch_add(1, Ordering::Release);
        let id = writer.next_area;
        writer.next_area += 1;
        writer.retired.insert(id, Pending { area });
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
    /// Release the area the collector finished, if any, and activate the next queued one;
    /// `false` when no area is left.
    ///
    /// Port of erts/emulator/beam/beam_bif_load.c (erts_literal_area_collector_release_area_switch_0
    /// and rla_switch_area), OTP-29.1.1: the collector calls this again only after every process
    /// answered its copy request, so the previous area has no references left. The caller waits
    /// for thread progress around the switch.
    pub fn collector_switch_area(&self) -> bool {
        let mut writer = self.lock_writer();
        let previous = self
            .active_area
            .write()
            .expect("active literal area poisoned")
            .take();
        if let Some(active) = previous {
            self.active_set.store(false, Ordering::Release);
            arinsal_term::set_literal_purge_area(&active.pointer_ranges, false);
            if literal_trace() {
                eprintln!("literal_release area={}", active.id);
            }
            writer.retired.remove(&active.id);
            if writer.retired_order.front() == Some(&active.id) {
                writer.retired_order.pop_front();
            }
            self.note_area_freed();
        }
        loop {
            let Some(id) = writer.retired_order.front().copied() else {
                return false;
            };
            let Some(area) = writer.retired.get(&id).map(|pending| pending.area.clone()) else {
                writer.retired_order.pop_front();
                continue;
            };
            let active = Arc::new(ActiveArea {
                id,
                pointer_ranges: Arc::from(area.pointer_ranges()),
                area,
            });
            // Port of erts/emulator/beam/beam_bif_load.c (rla_switch_area): literal-aware copies
            // now copy this area instead of sharing it.
            arinsal_term::set_literal_purge_area(&active.pointer_ranges, true);
            self.active_set.store(true, Ordering::Release);
            *self
                .active_area
                .write()
                .expect("active literal area poisoned") = Some(active);
            if literal_trace() {
                eprintln!("literal_switch area={id}");
            }
            return true;
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
    /// Whether an area is active: the collector switches again only after every process
    /// handled it.
    pub fn collector_area_complete(&self) -> bool {
        self.active_set.load(Ordering::Acquire)
    }
    /// The active area, when it is `area_id`, for a process handling a copy request.
    pub fn retired_area(&self, area_id: u64) -> Option<RetiredArea> {
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
    /// Record that a process handled the copy request for `area_id`, after copying
    /// `copied_roots` live references out of it.
    pub fn acknowledge_copied(&self, area_id: u64, copied_roots: u64) -> bool {
        if self.collector_area() != Some(area_id) {
            return false;
        }
        if literal_trace() {
            eprintln!("literal_ack area={area_id} copied={copied_roots}");
        }
        // The process owed this one area and owes nothing after the acknowledgement.
        for (slot, value) in [(0, 1), (1, 0), (3, copied_roots)] {
            self.last_trace[slot].store(value, Ordering::Relaxed);
            LAST_TRACE[slot].store(value, Ordering::Relaxed);
        }
        true
    }
    /// Take the global update permission for process `owner` (a nonzero process
    /// identifier); `true` when it already holds it.
    // Port of erts/emulator/beam/erl_bif_persistent.c (try_seize_update_permission),
    // OTP-29.1.1. A process that fails yields and retries instead of joining a wait queue.
    pub fn try_seize_update_permission(&self, owner: u64) -> bool {
        match self
            .updater
            .compare_exchange(0, owner, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) => true,
            Err(current) => current == owner,
        }
    }
    /// Release the update permission if process `owner` holds it.
    // Port of erts/emulator/beam/erl_bif_persistent.c (release_update_permission), OTP-29.1.1.
    pub fn release_update_permission(&self, owner: u64) {
        // Only the updater clears the word; every other process reads it and leaves its
        // cache line shared.
        if self.updater.load(Ordering::Acquire) != owner {
            return;
        }
        let _ = self
            .updater
            .compare_exchange(owner, 0, Ordering::AcqRel, Ordering::Acquire);
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
    fn link_node(&mut self, thing: *mut u64, node: Arc<Node>) {
        self.0.link_node(thing, node);
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

    #[test]
    fn the_collector_activates_queued_areas_in_order_and_releases_on_the_next_switch() {
        let store = Store::new();
        let key = Term::small(2).unwrap();
        let mut heap = VecHeap::new();
        let value = TermBuilder::new(&mut heap).tuple(&[key]).unwrap();
        store.put(key, value).unwrap();
        store.put(key, key).unwrap();
        let mut area = VecHeap::new();
        let literal = TermBuilder::new(&mut area)
            .tuple(&[Term::small(23).unwrap()])
            .unwrap();
        store.retire_module_area(Arc::new(area));
        assert_eq!(store.retired_count(), 2);

        assert!(store.collector_switch_area());
        let first = store.collector_area().unwrap();
        assert!(store.collector_area_complete());
        assert!(store.retired_area(first).is_some());
        assert!(store.acknowledge_copied(first, 0));
        assert!(store.collector_switch_area());
        let second = store.collector_area().unwrap();
        assert_ne!(first, second);
        assert!(store.retired_area(first).is_none());
        assert!(!store.acknowledge_copied(first, 0));
        assert!(store.retired_area(second).unwrap().contains(literal));
        assert!(store.has_retired());
        assert!(!store.collector_switch_area());
        assert!(!store.has_retired());
        assert!(!store.collector_area_complete());
        assert_eq!(store.freed_literal_areas(), 2);
    }

    #[test]
    fn immediate_values_need_no_collection() {
        let store = Store::new();
        let key = Term::small(1).unwrap();
        store.put(key, Term::small(5).unwrap()).unwrap();
        assert!(store.erase(key));
        assert!(!store.has_retired());
        assert!(!store.collector_switch_area());
    }

    #[test]
    fn update_permission_belongs_to_one_process() {
        let store = Store::new();
        assert!(store.try_seize_update_permission(7));
        assert!(store.try_seize_update_permission(7));
        assert!(!store.try_seize_update_permission(8));
        store.release_update_permission(8);
        assert!(!store.try_seize_update_permission(8));
        store.release_update_permission(7);
        assert!(store.try_seize_update_permission(8));
    }

    #[test]
    fn retired_storage_drops_after_the_switch_and_thread_progress() {
        let store = Store::new();
        let key = Term::small(1).unwrap();
        let mut heap = VecHeap::new();
        let value = TermBuilder::new(&mut heap).tuple(&[key]).unwrap();
        store.put(key, value).unwrap();
        store.put(key, Term::small(2).unwrap()).unwrap();
        assert!(store.collector_switch_area());
        let weak = {
            let writer = store.writer.lock().unwrap();
            let (_, pending) = writer.retired.iter().next().unwrap();
            let RetiredStorage::Persistent(stored) = &pending.area else {
                unreachable!("persistent-term test stores a persistent area")
            };
            Arc::downgrade(stored)
        };
        assert!(weak.upgrade().is_some());
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
