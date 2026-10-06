//! Opaque reference owners retained by process and standalone heaps.

use std::any::Any;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock, Weak};

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

/// A reference payload whose lifetime follows every copied term and GC owner.
pub struct MagicRef {
    id: u64,
    restored_from_external_term: bool,
    payload: Box<dyn Any + Send + Sync>,
}

impl MagicRef {
    /// Allocate an opaque reference with a process-wide unique identity.
    pub fn new<T: Any + Send + Sync>(payload: T) -> Arc<Self> {
        Self::allocate(NEXT_ID.fetch_add(1, Ordering::Relaxed), payload, false)
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
        let owner = Arc::new(Self {
            id,
            restored_from_external_term,
            payload: Box::new(payload),
        });
        registry()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(Arc::downgrade(&owner));
        owner
    }

    /// Whether this identity has no process-local native resource owner.
    pub fn is_external_only(&self) -> bool {
        self.restored_from_external_term
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
        let mut owners = registry()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut found = None;
        owners.retain(|entry| {
            if let Some(owner) = entry.upgrade() {
                if owner.id == id {
                    found = Some(owner);
                }
                true
            } else {
                false
            }
        });
        found
    }
}

fn registry() -> &'static Mutex<Vec<Weak<MagicRef>>> {
    static OWNERS: OnceLock<Mutex<Vec<Weak<MagicRef>>>> = OnceLock::new();
    OWNERS.get_or_init(|| Mutex::new(Vec::new()))
}

impl crate::Term {
    /// Borrow the magic owner from a live reference term.
    ///
    /// # Safety
    /// The term's heap and its off-heap owners must stay live for the borrow.
    pub unsafe fn magic_ref<'a>(self) -> Option<&'a MagicRef> {
        if self.header()? & 63 != crate::MAGIC_REF {
            return None;
        }
        // SAFETY: MagicRef word one holds an Arc-owned pointer retained by the heap.
        Some(unsafe { &*(*self.raw_ptr().add(1) as *const MagicRef) })
    }
}
