//! The type-erased owner of a signal node: the only `unsafe` of the scheduler's pending
//! signal slot.
//!
//! Port of erts/emulator/beam/erl_process.h (`esdp->pending_signal.sig`, a `void *` the
//! scheduler holds until its next send), OTP-29.1.1. The slot is not generic over the
//! message type, so the node is held as a raw pointer plus the drop glue of its type.

use std::ptr::NonNull;

use super::OwnedSignal;

/// A signal node held outside any queue with its type erased, for the scheduler's pending
/// signal slot, which is not generic (`esdp->pending_signal.sig`, erl_process.h:735).
pub(crate) struct HeldNode {
    node: NonNull<u8>,
    type_id: std::any::TypeId,
    drop_node: unsafe fn(NonNull<u8>),
}

/// # Safety
///
/// `node` came from `OwnedSignal::<T>::into_raw` and has no other owner.
unsafe fn drop_held_node<T>(node: NonNull<u8>) {
    // SAFETY: guaranteed by the caller.
    drop(unsafe { OwnedSignal::<T>::from_raw(node.cast()) });
}

impl HeldNode {
    pub(crate) fn new<T: 'static>(signal: OwnedSignal<T>) -> Self {
        Self {
            node: signal.into_raw().cast(),
            type_id: std::any::TypeId::of::<T>(),
            drop_node: drop_held_node::<T>,
        }
    }

    /// The node back as its signal; panics when it was held as another type.
    pub(crate) fn into_signal<T: 'static>(self) -> OwnedSignal<T> {
        assert_eq!(
            self.type_id,
            std::any::TypeId::of::<T>(),
            "held signal type changed"
        );
        let node = self.node;
        std::mem::forget(self);
        // SAFETY: `new` took the node from `OwnedSignal::<T>::into_raw` (the type id matches)
        // and this handle was its only owner.
        unsafe { OwnedSignal::from_raw(node.cast()) }
    }
}

impl Drop for HeldNode {
    fn drop(&mut self) {
        // SAFETY: `drop_node` is `drop_held_node` of the type `new` took the node from.
        unsafe { (self.drop_node)(self.node) }
    }
}
