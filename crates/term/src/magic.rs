//! Opaque reference owners retained by process and standalone heaps.

use std::any::Any;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{OnceLock, RwLock, Weak};

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

/// Offset from `Binary.orig_bytes` to data in an aligned OTP magic binary on 64-bit targets.
pub const MAGIC_BIN_DATA_OFFSET: usize = 24;

/// A reference payload whose lifetime follows every copied term and GC owner.
pub struct MagicRef {
    id: u64,
    /// `mb->orig_size`: what the owning heap charges to its virtual binary heap.
    orig_size: usize,
    /// Whether the reference numbers are in the lazily filled table (`erts_magic_ref_save_bin`).
    saved: AtomicBool,
    payload: Box<dyn Any + Send + Sync>,
}

impl MagicRef {
    /// Allocate an opaque reference with a process-wide unique identity.
    pub fn new<T: Any + Send + Sync>(payload: T) -> Arc<Self> {
        Self::allocate(NEXT_ID.fetch_add(1, Ordering::Relaxed), payload)
    }

    /// Allocate an opaque reference whose `mb->orig_size` is `orig_size` bytes instead of
    /// the payload's own size, for payloads that stand in for a fixed erts structure.
    // Port of erts/emulator/beam/erl_binary.h (erts_create_magic_binary_x), OTP-29.1.1:
    // `orig_size` is `ERTS_MAGIC_BIN_ORIG_SIZE(size)`, the data offset plus the payload size.
    pub fn with_orig_size<T: Any + Send + Sync>(payload: T, orig_size: usize) -> Arc<Self> {
        Self::allocate_sized(NEXT_ID.fetch_add(1, Ordering::Relaxed), payload, orig_size)
    }

    /// Allocate a reference backed by `erts_create_magic_binary(payload_size, ...)`.
    ///
    /// The reported `orig_size` includes the aligned magic binary data offset.
    // Port of erts/emulator/beam/erl_binary.h (ERTS_MAGIC_BIN_ORIG_SIZE), OTP-29.1.1.
    pub fn with_erts_payload_size<T: Any + Send + Sync>(
        payload: T,
        payload_size: usize,
    ) -> Arc<Self> {
        Self::with_orig_size(payload, MAGIC_BIN_DATA_OFFSET + payload_size)
    }

    fn allocate<T: Any + Send + Sync>(id: u64, payload: T) -> Arc<Self> {
        Self::allocate_sized(id, payload, std::mem::size_of::<T>())
    }

    fn allocate_sized<T: Any + Send + Sync>(id: u64, payload: T, orig_size: usize) -> Arc<Self> {
        // erts keeps no registry of magic binaries: the reference thing points at the
        // refcounted binary and the destructor runs on the last release.
        Arc::new(Self {
            id,
            orig_size,
            saved: AtomicBool::new(false),
            payload: Box::new(payload),
        })
    }

    /// `mb->orig_size` of the magic binary: the payload's size in bytes.
    pub fn orig_size(&self) -> usize {
        self.orig_size
    }

    /// The owner behind a magic reference thing's pointer word. With `clone` the thing keeps
    /// its counted reference and the result is a new one; without it the thing's own count
    /// moves to the result (an `erts_bin_release` when the result is dropped).
    // Port of erts/emulator/beam/erl_bif_unique.h (ErtsMRefThing `mb`), OTP-29.1.1.
    pub(crate) fn thing_owner(word: u64, clone: bool) -> Arc<Self> {
        let ptr = word as *const Self;
        // SAFETY: the pointer word of a live magic reference thing is an `Arc::into_raw`
        // reference that the thing's off-heap list entry owns.
        unsafe {
            if clone {
                Arc::increment_strong_count(ptr);
            }
            Arc::from_raw(ptr)
        }
    }

    /// Return the reference identity used for term ordering and hashing.
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Borrow the payload if it has the requested Rust type.
    pub fn downcast_ref<T: Any>(&self) -> Option<&T> {
        self.payload.downcast_ref()
    }
}

// Port of erts/emulator/beam/erl_bif_unique.c (magic_ref_table), OTP-29.1.1: a table from
// reference numbers to the magic binary, sharded like erts' per-scheduler tables. Creating a
// magic reference never touches it. It is filled only when the numbers leave the term
// (`term_to_binary`, `ref_to_list`), so that decoding or `list_to_ref` on this node finds the
// binary again, and the entry goes away when the binary is freed.
const TABLE_SHARDS: usize = 64;
type Shard = RwLock<HashMap<u64, Weak<MagicRef>>>;

fn shard(id: u64) -> &'static Shard {
    static TABLE: OnceLock<Vec<Shard>> = OnceLock::new();
    &TABLE.get_or_init(|| (0..TABLE_SHARDS).map(|_| RwLock::default()).collect())
        [(id as usize) % TABLE_SHARDS]
}

impl MagicRef {
    /// `erts_magic_ref_save_bin`: make the reference numbers resolvable on this node.
    pub fn save_in_table(self: &Arc<Self>) {
        if self.saved.load(Ordering::Acquire) {
            return;
        }
        shard(self.id)
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(self.id, Arc::downgrade(self));
        self.saved.store(true, Ordering::Release);
    }

    /// `erts_magic_ref_lookup_bin`: the live magic binary saved under these reference numbers.
    pub fn lookup_saved(id: u64) -> Option<Arc<Self>> {
        shard(id)
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&id)?
            .upgrade()
    }
}

impl Drop for MagicRef {
    /// `erts_magic_binary_free` calls `erts_magic_ref_remove_bin`; the flag only spares the
    /// lock for the references that were never saved.
    fn drop(&mut self) {
        if self.saved.load(Ordering::Acquire) {
            shard(self.id)
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(&self.id);
        }
    }
}

impl crate::Term {
    /// `erts_magic_ref_save_bin` for a reference term; other terms are left alone.
    pub fn save_magic_ref(self) {
        if let Some(owner) = self.magic_owner() {
            owner.save_in_table();
        }
    }

    /// A counted reference to the magic owner of a live magic reference term, like
    /// `erts_refc_inc` on `ErtsMRefThing.mb`.
    pub fn magic_owner(self) -> Option<Arc<MagicRef>> {
        self.magic_word()
            .map(|word| MagicRef::thing_owner(word, true))
    }

    /// Borrow the magic owner from a live reference term.
    ///
    /// # Safety
    /// The term's heap and its off-heap owners must stay live for the borrow.
    pub unsafe fn magic_ref<'a>(self) -> Option<&'a MagicRef> {
        if !self.is_magic_ref() {
            return None;
        }
        // SAFETY: ErtsMRefThing word one holds the Arc-owned magic binary pointer retained
        // by the heap's off-heap list.
        Some(unsafe { &*(*self.raw_ptr().add(1) as *const MagicRef) })
    }
}
