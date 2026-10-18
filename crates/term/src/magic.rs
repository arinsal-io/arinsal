//! Opaque reference owners retained by process and standalone heaps.

use std::any::Any;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock, Weak};

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

/// Offset from `Binary.orig_bytes` to data in an aligned OTP magic binary on 64-bit targets.
pub const MAGIC_BIN_DATA_OFFSET: usize = 24;

/// A reference payload whose lifetime follows every copied term and GC owner.
pub struct MagicRef {
    id: u64,
    restored_from_external_term: bool,
    /// `mb->orig_size`: what the owning heap charges to its virtual binary heap.
    orig_size: usize,
    payload: Box<dyn Any + Send + Sync>,
}

impl MagicRef {
    /// Allocate an opaque reference with a process-wide unique identity.
    pub fn new<T: Any + Send + Sync>(payload: T) -> Arc<Self> {
        Self::allocate(NEXT_ID.fetch_add(1, Ordering::Relaxed), payload, false)
    }

    /// Allocate an opaque reference whose `mb->orig_size` is `orig_size` bytes instead of
    /// the payload's own size, for payloads that stand in for a fixed erts structure.
    // Port of erts/emulator/beam/erl_binary.h (erts_create_magic_binary_x), OTP-29.1.1:
    // `orig_size` is `ERTS_MAGIC_BIN_ORIG_SIZE(size)`, the data offset plus the payload size.
    pub fn with_orig_size<T: Any + Send + Sync>(payload: T, orig_size: usize) -> Arc<Self> {
        Self::allocate_sized(
            NEXT_ID.fetch_add(1, Ordering::Relaxed),
            payload,
            false,
            orig_size,
        )
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

    /// Recreate an opaque reference using an identity retained in an external term.
    pub fn new_with_id<T: Any + Send + Sync>(id: u64, payload: T) -> Arc<Self> {
        NEXT_ID.fetch_max(id.saturating_add(1), Ordering::Relaxed);
        Self::allocate(id, payload, true)
    }

    fn allocate<T: Any + Send + Sync>(
        id: u64,
        payload: T,
        restored_from_external_term: bool,
    ) -> Arc<Self> {
        Self::allocate_sized(
            id,
            payload,
            restored_from_external_term,
            std::mem::size_of::<T>(),
        )
    }

    fn allocate_sized<T: Any + Send + Sync>(
        id: u64,
        payload: T,
        restored_from_external_term: bool,
        orig_size: usize,
    ) -> Arc<Self> {
        let owner = Arc::new(Self {
            id,
            restored_from_external_term,
            orig_size,
            payload: Box::new(payload),
        });
        registry()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(id, Arc::downgrade(&owner));
        owner
    }

    /// Whether this identity has no process-local native resource owner.
    pub fn is_external_only(&self) -> bool {
        self.restored_from_external_term
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

impl MagicRef {
    /// Find a live magic-reference owner by its term identity.
    pub fn live_by_id(id: u64) -> Option<Arc<Self>> {
        let entry = registry()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&id)
            .cloned();
        entry?.upgrade()
    }

    /// Whether the identity still has an entry in the process-wide registry.
    ///
    /// The entry is removed when the last reference to the owner is released.
    pub fn is_registered(id: u64) -> bool {
        registry()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains_key(&id)
    }
}

impl Drop for MagicRef {
    fn drop(&mut self) {
        let mut owners = registry()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if owners
            .get(&self.id)
            .is_some_and(|entry| entry.strong_count() == 0)
        {
            owners.remove(&self.id);
        }
    }
}

fn registry() -> &'static Mutex<HashMap<u64, Weak<MagicRef>>> {
    static OWNERS: OnceLock<Mutex<HashMap<u64, Weak<MagicRef>>>> = OnceLock::new();
    OWNERS.get_or_init(|| Mutex::new(HashMap::new()))
}

impl crate::Term {
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
