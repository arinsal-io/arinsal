//! Chained hash and index table. Port of `erts/emulator/beam/hash.c`, `hash.h`, `index.c`
//! and `index.h`, OTP-29.1.1.
//!
//! `Hash` is `hash.c`: an array of bucket-chain heads under a fibonacci slot map, grown at 160% load
//! and shrunk at 20%. `IndexTable` is `index.c`: that hash plus `seg_table`, a two-level array that
//! maps an index back to its entry, so readers reach entry `i` without a lock.
//!
//! Entries start with an `IndexSlot` (`HashBucket` + `index`), are allocated by the table's
//! `HashFunctions` through `erts_alloc`, and are linked by address, exactly as the C objects are
//! linked by pointer. All raw-address access of the atom table lives in this module.
//!
//! Deviation from the C structure: erts keeps the table lock (`atom_table_lock`) beside the
//! table. Rust cannot hand out `&mut Hash` without a guard type, so the lock owns the `Hash` and
//! `IndexTable` returns its read and write guards; the lock itself is the same frequent-read
//! rwmtx.

use std::sync::atomic::{AtomicI32, AtomicU64, AtomicUsize, Ordering};

use arinsal_alloc::typed::{AllocBlock, ErtsAlcType};

use crate::rwmutex::{FrequentReadGuard, FrequentReadRwLock, FrequentWriteGuard};

/// `HashValue` of this 64-bit build.
pub(crate) type HashValue = u64;

const MAX_SHIFT: i32 = 64; // ERTS_SIZEOF_TERM * 8
const FIBONACCI: u64 = 11_400_714_819_323_198_485;
/// `INDEX_PAGE_SHIFT` (index.h).
pub(crate) const INDEX_PAGE_SHIFT: usize = 10;
/// `INDEX_PAGE_SIZE` (index.h).
pub(crate) const INDEX_PAGE_SIZE: usize = 1 << INDEX_PAGE_SHIFT;
const INDEX_PAGE_MASK: usize = INDEX_PAGE_SIZE - 1;
const WORD: usize = std::mem::size_of::<u64>();

/// `HashBucket` (hash.h): the chain link and the stored hash value. `next` holds the address of
/// the next entry. Both fields change only under the write lock; they are atomics because lock-free
/// readers hold shared references to the entries meanwhile.
#[repr(C)]
pub(crate) struct HashBucket {
    next: AtomicUsize,
    hvalue: AtomicU64,
}

impl HashBucket {
    /// A bucket not yet linked, as `atom_alloc` leaves it before `hash_put` fills it in.
    pub(crate) const fn new() -> Self {
        Self {
            next: AtomicUsize::new(0),
            hvalue: AtomicU64::new(0),
        }
    }

    /// The hash value `hash_put` stored.
    #[inline(always)]
    pub(crate) fn hvalue(&self) -> HashValue {
        self.hvalue.load(Ordering::Relaxed)
    }
}

/// `IndexSlot` (index.h): the first member of every entry of an index table.
#[repr(C)]
pub(crate) struct IndexSlot {
    bucket: HashBucket,
    index: AtomicI32,
}

impl IndexSlot {
    /// A slot with `index == -1`, the state of an entry that `index_put_entry` has not published.
    pub(crate) const fn new() -> Self {
        Self {
            bucket: HashBucket::new(),
            index: AtomicI32::new(-1),
        }
    }

    /// The stored hash value (`slot.bucket.hvalue`).
    #[inline(always)]
    pub(crate) fn hvalue(&self) -> HashValue {
        self.bucket.hvalue()
    }

    /// The published index, -1 before `index_put_entry` assigned one.
    #[inline(always)]
    pub(crate) fn index(&self) -> i32 {
        self.index.load(Ordering::Relaxed)
    }
}

/// An object stored in a [`Hash`]: `#[repr(C)]` with an [`IndexSlot`] as its first field, so the
/// address of the entry is the address of its bucket.
pub(crate) trait IndexEntry {
    /// The leading slot.
    fn slot(&self) -> &IndexSlot;
}

/// `HashFunctions` (hash.h), minus the meta allocator callbacks: the table allocates its own
/// bucket arrays and segments from [`IndexTable::new`]'s type.
pub(crate) trait HashFunctions {
    /// The stored object.
    type Entry: IndexEntry;
    /// What a lookup is keyed by (`tmpl`).
    type Template<'a>;
    /// `HashFunctions.hash`.
    fn hash(&self, tmpl: &Self::Template<'_>) -> HashValue;
    /// `HashFunctions.cmp`; true when `obj` matches `tmpl` (the C function returns 0).
    fn cmp(&self, tmpl: &Self::Template<'_>, obj: &Self::Entry) -> bool;
    /// `HashFunctions.alloc`: a new entry with `index == -1`, never freed while the table lives.
    fn alloc(&self, tmpl: &Self::Template<'_>) -> *mut Self::Entry;
    /// `HashFunctions.free`. The atom table's is empty: entries seen by lock-free readers are
    /// never released.
    fn free(&self, obj: &Self::Entry);
}

/// `hash_get_info` result.
pub(crate) struct HashStats {
    pub(crate) size: i32,
    pub(crate) used: i32,
    pub(crate) objs: i32,
    pub(crate) depth: i32,
}

/// `Hash` (hash.h). `bucket` is the address of `1 << (MAX_SHIFT - shift)` chain-head addresses
/// allocated from `ty`.
pub(crate) struct Hash {
    ty: ErtsAlcType,
    shift: i32,
    max_shift: i32,
    grow_threshold: i32,
    shrink_threshold: i32,
    nobjs: i32,
    bucket: usize,
}

impl Hash {
    fn slots_for(shift: i32) -> usize {
        // Port of hash.c:41 (hash_get_slots).
        1_usize << (MAX_SHIFT - shift)
    }

    fn slots(&self) -> usize {
        Self::slots_for(self.shift)
    }

    fn set_thresholds(&mut self) {
        // Port of hash.c:108 (set_thresholds).
        let slots = self.slots() as i32;
        self.grow_threshold = (8 * slots) / 5;
        self.shrink_threshold = if self.shift < self.max_shift {
            slots / 5
        } else {
            -1
        };
    }

    /// Port of hash.c:121 (hash_init), without the `is_allocated` / meta allocator parts.
    fn init(ty: ErtsAlcType, size: i32) -> Self {
        let mut shift = 1;
        while (1_i64 << shift) < i64::from(size) {
            shift += 1;
        }
        let shift = MAX_SHIFT - shift;
        let mut hash = Self {
            ty,
            shift,
            max_shift: shift,
            grow_threshold: 0,
            shrink_threshold: -1,
            nobjs: 0,
            bucket: 0,
        };
        hash.set_thresholds();
        hash.bucket = alloc_zeroed(ty, hash.slots());
        hash
    }

    #[inline(always)]
    fn slot_of(&self, mut hv: HashValue) -> usize {
        // Port of hash.h:108 (hash_get_slot), the fibonacci mapping.
        let shift = self.shift as u32;
        hv ^= hv >> shift;
        (FIBONACCI.wrapping_mul(hv) >> shift) as usize
    }

    #[inline(always)]
    fn head(&self, ix: usize) -> usize {
        debug_assert!(ix < self.slots());
        // SAFETY: `bucket` is a live array of `slots()` words and `ix` is a slot index. The array
        // is replaced only by `rehash` under the write lock, and this reference is reached only
        // through a guard of that lock.
        unsafe { (self.bucket as *const usize).add(ix).read() }
    }

    fn set_head(&mut self, ix: usize, addr: usize) {
        debug_assert!(ix < self.slots());
        // SAFETY: as `head`; `&mut self` is the write guard.
        unsafe { (self.bucket as *mut usize).add(ix).write(addr) }
    }

    /// Port of hash.c:43 (hash_get_info).
    pub(crate) fn stats(&self) -> HashStats {
        let size = self.slots();
        let mut max_depth = 0;
        let mut used = 0;
        for ix in 0..size {
            let mut depth = 0;
            let mut b = self.head(ix);
            while b != 0 {
                depth += 1;
                b = bucket_ref(b).next.load(Ordering::Relaxed);
            }
            if depth > 0 {
                used += 1;
                max_depth = max_depth.max(depth);
            }
        }
        HashStats {
            size: size as i32,
            used,
            objs: self.nobjs,
            depth: max_depth,
        }
    }

    /// Bytes of the bucket array of `hash_table_sz`, without the `Hash` header and name.
    pub(crate) fn bucket_bytes(&self) -> usize {
        self.slots() * std::mem::size_of::<usize>()
    }

    /// Port of hash.c:187 (rehash).
    fn rehash(&mut self, grow: bool) {
        let old_size = self.slots();
        if grow {
            self.shift -= 1;
        } else {
            if self.shift == self.max_shift {
                return;
            }
            self.shift += 1;
        }
        let new_bucket = alloc_zeroed(self.ty, self.slots());
        let old_bucket = std::mem::replace(&mut self.bucket, new_bucket);
        for ix in 0..old_size {
            // SAFETY: `old_bucket` is the live array just replaced; `ix < old_size`.
            let mut b = unsafe { (old_bucket as *const usize).add(ix).read() };
            while b != 0 {
                let bucket = bucket_ref(b);
                let b_next = bucket.next.load(Ordering::Relaxed);
                let slot = self.slot_of(bucket.hvalue());
                bucket.next.store(self.head(slot), Ordering::Relaxed);
                self.set_head(slot, b);
                b = b_next;
            }
        }
        free_words(self.ty, old_bucket, old_size);
        self.set_thresholds();
    }

    /// Port of hash.h:133 (hash_fetch) / hash.c:226 (hash_get).
    #[inline]
    fn get<F: HashFunctions>(&self, fun: &F, tmpl: &F::Template<'_>) -> Option<&F::Entry> {
        let hval = fun.hash(tmpl);
        let mut b = self.head(self.slot_of(hval));
        while b != 0 {
            let bucket = bucket_ref(b);
            if bucket.hvalue() == hval {
                let obj = entry_ref::<F::Entry>(b);
                if fun.cmp(tmpl, obj) {
                    return Some(obj);
                }
            }
            b = bucket.next.load(Ordering::Relaxed);
        }
        None
    }

    /// Port of hash.c:235 (hash_put).
    fn put<F: HashFunctions>(&mut self, fun: &F, tmpl: &F::Template<'_>) -> usize {
        let hval = fun.hash(tmpl);
        let ix = self.slot_of(hval);
        let mut b = self.head(ix);
        while b != 0 {
            let bucket = bucket_ref(b);
            if bucket.hvalue() == hval && fun.cmp(tmpl, entry_ref::<F::Entry>(b)) {
                return b;
            }
            b = bucket.next.load(Ordering::Relaxed);
        }
        let addr = fun.alloc(tmpl) as usize;
        let bucket = bucket_ref(addr);
        bucket.hvalue.store(hval, Ordering::Relaxed);
        bucket.next.store(self.head(ix), Ordering::Relaxed);
        self.set_head(ix, addr);
        self.nobjs += 1;
        if self.nobjs > self.grow_threshold {
            self.rehash(true);
        }
        addr
    }

    /// Port of hash.c:262 (hash_erase). The entry is its own template: the object is found by
    /// address, which is what `cmp(obj, obj)` establishes for unique keys.
    fn erase<F: HashFunctions>(&mut self, fun: &F, addr: usize) {
        let bucket = bucket_ref(addr);
        let ix = self.slot_of(bucket.hvalue());
        let mut b = self.head(ix);
        let mut prev = 0;
        while b != 0 {
            let next = bucket_ref(b).next.load(Ordering::Relaxed);
            if b == addr {
                if prev != 0 {
                    bucket_ref(prev).next.store(next, Ordering::Relaxed);
                } else {
                    self.set_head(ix, next);
                }
                fun.free(entry_ref::<F::Entry>(b));
                self.nobjs -= 1;
                if self.nobjs < self.shrink_threshold {
                    self.rehash(false);
                }
                return;
            }
            prev = b;
            b = next;
        }
    }
}

/// `IndexTable` (index.h). `seg_table` is the address of `ceil(limit / INDEX_PAGE_SIZE)` words,
/// each the address of a page of `INDEX_PAGE_SIZE` entry addresses.
pub(crate) struct IndexTable<F: HashFunctions> {
    fun: F,
    ty: ErtsAlcType,
    name: &'static str,
    htable: FrequentReadRwLock<Hash>,
    size: AtomicI32,
    limit: i32,
    entries: AtomicI32,
    seg_table: usize,
    seg_len: usize,
}

impl<F: HashFunctions> IndexTable<F> {
    /// Port of index.c:52 (erts_index_init). `size` is the expected number of entries.
    pub(crate) fn new(ty: ErtsAlcType, name: &'static str, size: i32, limit: i32, fun: F) -> Self {
        let seg_len = (limit as usize).div_ceil(INDEX_PAGE_SIZE);
        Self {
            fun,
            ty,
            name,
            htable: FrequentReadRwLock::new(Hash::init(ty, 3 * size / 4)),
            size: AtomicI32::new(0),
            limit,
            entries: AtomicI32::new(0),
            seg_table: alloc_zeroed(ty, seg_len),
            seg_len,
        }
    }

    /// The table's callbacks.
    pub(crate) fn fun(&self) -> &F {
        &self.fun
    }

    /// The table name (`t->htable.name`).
    pub(crate) fn name(&self) -> &'static str {
        self.name
    }

    /// `atom_read_lock`.
    pub(crate) fn read(&self) -> IndexReadGuard<'_, F> {
        IndexReadGuard {
            table: self,
            hash: self.htable.read(),
        }
    }

    /// `atom_write_lock`.
    pub(crate) fn write(&self) -> IndexWriteGuard<'_, F> {
        IndexWriteGuard {
            table: self,
            hash: self.htable.write(),
        }
    }

    fn seg_word(&self, seg: usize) -> Option<&AtomicUsize> {
        if seg >= self.seg_len {
            return None;
        }
        // SAFETY: `seg_table` is a live, never freed array of `seg_len` aligned words and `seg` is
        // in range; every access to its words is atomic.
        Some(unsafe { AtomicUsize::from_ptr((self.seg_table as *mut usize).add(seg)) })
    }

    /// Port of index.h:81 (erts_index_lookup): the entry published at `ix`, without any lock. The
    /// writer publishes the entry address before it advances `entries`, and pages are zero until
    /// then, so an index that was never assigned is `None`.
    #[inline(always)]
    pub(crate) fn lookup(&self, ix: usize) -> Option<&F::Entry> {
        let page = self
            .seg_word(ix >> INDEX_PAGE_SHIFT)?
            .load(Ordering::Acquire);
        if page == 0 {
            return None;
        }
        // SAFETY: a nonzero page word is a page of `INDEX_PAGE_SIZE` words that is never freed;
        // the mask keeps the offset inside it; its words are atomics.
        let slot = unsafe { AtomicUsize::from_ptr((page as *mut usize).add(ix & INDEX_PAGE_MASK)) };
        let addr = slot.load(Ordering::Acquire);
        if addr == 0 {
            None
        } else {
            Some(entry_ref::<F::Entry>(addr))
        }
    }

    /// Port of index.h:90 (erts_index_num_entries).
    pub(crate) fn num_entries(&self) -> i32 {
        self.entries.load(Ordering::Acquire)
    }

    /// Port of index.c:32 (`index_info`) counters: `size`, `limit`, `entries`.
    pub(crate) fn info(&self) -> (i32, i32, i32) {
        (
            self.size.load(Ordering::Relaxed),
            self.limit,
            self.entries.load(Ordering::Relaxed),
        )
    }

    /// Bytes of the segments allocated so far, plus the `seg_table` base array.
    pub(crate) fn seg_bytes(&self) -> usize {
        self.size.load(Ordering::Relaxed) as usize * std::mem::size_of::<usize>()
            + self.seg_len * std::mem::size_of::<usize>()
    }
}

/// Holder of the read side of the table lock.
pub(crate) struct IndexReadGuard<'a, F: HashFunctions> {
    table: &'a IndexTable<F>,
    hash: FrequentReadGuard<'a, Hash>,
}

impl<F: HashFunctions> IndexReadGuard<'_, F> {
    /// Port of index.c:116 (index_get): the index of the matching entry, or -1.
    #[inline]
    pub(crate) fn get(&self, tmpl: &F::Template<'_>) -> i32 {
        match self.hash.get(&self.table.fun, tmpl) {
            Some(p) => p.slot().index(),
            None => -1,
        }
    }

    /// The hash under the lock.
    pub(crate) fn hash(&self) -> &Hash {
        &self.hash
    }
}

/// Holder of the write side of the table lock.
pub(crate) struct IndexWriteGuard<'a, F: HashFunctions> {
    table: &'a IndexTable<F>,
    hash: FrequentWriteGuard<'a, Hash>,
}

impl<F: HashFunctions> IndexWriteGuard<'_, F> {
    /// Port of index.c:78 (index_put_entry).
    pub(crate) fn put_entry(&mut self, tmpl: &F::Template<'_>) -> &F::Entry {
        let t = self.table;
        let addr = self.hash.put(&t.fun, tmpl);
        let p = entry_ref::<F::Entry>(addr);
        if p.slot().index() >= 0 {
            return p;
        }
        let ix = t.entries.load(Ordering::Relaxed);
        if ix >= t.size.load(Ordering::Relaxed) {
            if ix >= t.limit {
                index_exhausted(t.name, t.limit);
            }
            let page = alloc_zeroed(t.ty, INDEX_PAGE_SIZE);
            t.seg_word((ix as usize) >> INDEX_PAGE_SHIFT)
                .expect("segment table covers the limit")
                .store(page, Ordering::Release);
            t.size.fetch_add(INDEX_PAGE_SIZE as i32, Ordering::Relaxed);
        }
        p.slot().index.store(ix, Ordering::Relaxed);
        let page = t
            .seg_word((ix as usize) >> INDEX_PAGE_SHIFT)
            .expect("segment table covers the limit")
            .load(Ordering::Relaxed);
        // SAFETY: the page was allocated above or by an earlier put under this write lock, and
        // `ix & INDEX_PAGE_MASK` is inside it.
        unsafe { AtomicUsize::from_ptr((page as *mut usize).add((ix as usize) & INDEX_PAGE_MASK)) }
            .store(addr, Ordering::Release);
        // The Release store orders the slot before the count, as ERTS_THR_WRITE_MEMORY_BARRIER.
        t.entries.store(ix + 1, Ordering::Release);
        p
    }

    /// Port of index.c:119 (index_erase_latest_from).
    pub(crate) fn erase_latest_from(&mut self, from_ix: usize) {
        let t = self.table;
        let entries = t.entries.load(Ordering::Relaxed);
        if from_ix < entries as usize {
            for ix in from_ix..entries as usize {
                let addr = t.lookup(ix).map(|obj| obj as *const F::Entry as usize);
                if let Some(addr) = addr {
                    self.hash.erase(&t.fun, addr);
                }
            }
            t.entries.store(from_ix as i32, Ordering::Release);
        }
    }
}

fn index_exhausted(name: &str, limit: i32) -> ! {
    // Port of index.c:89 and erl_init.c:2718 (`ERTS_DUMP_EXIT` then exit status 1).
    // erl_crash_dump.c:509 and :697 print the banner. The dump body is left for
    // the crash-dump agent; the message and status match erts on this platform
    // (`erts_fprintf` writes `\r\n`).
    let message = format!(
        "no more index entries in {name} (max={limit})\r\n\r\nCrash dump is being written to: erl_crash.dump...done\r\n"
    );
    let _ = std::io::Write::write_all(&mut std::io::stderr(), message.as_bytes());
    let _ = std::io::Write::flush(&mut std::io::stderr());
    std::process::exit(1);
}

/// `erts_alloc(type, words * 8)` followed by `memzero`; returns the address. `erts_alloc` exits
/// the emulator when memory is exhausted, as `expect` does here.
fn alloc_zeroed(ty: ErtsAlcType, words: usize) -> usize {
    let mut block = AllocBlock::new(ty, words).expect("erts_alloc: out of memory");
    block.as_mut_slice().fill(0);
    block.into_raw().as_ptr() as usize
}

/// `erts_free` of a block `alloc_zeroed` returned.
fn free_words(ty: ErtsAlcType, addr: usize, words: usize) {
    let ptr = std::ptr::NonNull::new(addr as *mut u8).expect("live block address");
    // SAFETY: `addr` and `words` describe a block `alloc_zeroed` made with type `ty` and nothing
    // else owns or reads it: the caller holds the write lock that guards every reader of bucket
    // arrays.
    drop(unsafe { AllocBlock::from_raw(ptr, ty, words) });
}

/// Allocate one entry of `T` from `ty`; the caller initialises it with `write`.
pub(crate) fn alloc_entry<T>(ty: ErtsAlcType) -> *mut T {
    let words = std::mem::size_of::<T>().div_ceil(WORD);
    let block = AllocBlock::new(ty, words).expect("erts_alloc: out of memory");
    block.into_raw().as_ptr().cast()
}

/// Initialise the entry returned by [`alloc_entry`].
pub(crate) fn init_entry<T>(ptr: *mut T, value: T) {
    // SAFETY: `ptr` is a fresh, word aligned allocation of at least `size_of::<T>()` bytes from
    // `alloc_entry` that no one else can see yet.
    unsafe { ptr.write(value) }
}

#[inline(always)]
fn bucket_ref<'a>(addr: usize) -> &'a HashBucket {
    entry_ref::<HashBucket>(addr)
}

#[inline(always)]
fn entry_ref<'a, E>(addr: usize) -> &'a E {
    // SAFETY: every nonzero address that the table stores is an entry made by
    // `HashFunctions::alloc` and initialised before `hash_put` links it. Entries are
    // never released while the table lives (`HashFunctions::free` keeps the memory for the
    // lock-free readers), and the `repr(C)` entry begins with its `HashBucket`.
    unsafe { &*(addr as *const E) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slot_map_matches_hash_h() {
        // hash.h:108 (hash_get_slot) with the shift `hash_init` picks for the atom table.
        let hash = Hash::init(ErtsAlcType::ATOM_TABLE, 3 * 3000 / 4);
        assert_eq!(hash.shift, 52);
        assert_eq!(hash.slot_of(crate::atom::atom_hash(b"false")), 3389);
        assert_eq!(hash.slot_of(crate::atom::atom_hash(b"ok")), 3104);
    }
}
