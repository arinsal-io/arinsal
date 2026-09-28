//! Opaque reference owners retained by process and standalone heaps.

use std::any::Any;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

/// A reference payload whose lifetime follows every copied term and GC owner.
pub struct MagicRef {
    id: u64,
    payload: Box<dyn Any + Send + Sync>,
}

impl MagicRef {
    /// Allocate an opaque reference with a process-wide unique identity.
    pub fn new<T: Any + Send + Sync>(payload: T) -> Arc<Self> {
        Arc::new(Self {
            id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
            payload: Box::new(payload),
        })
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
