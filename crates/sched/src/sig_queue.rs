//! Intrusive signal queues: singly linked lists of signal nodes with a tail pointer, so that a
//! queue is appended to another in O(1) without copying a signal.
//!
//! Port of the list handling of erts/emulator/beam/erl_proc_sig_queue.c/.h and erl_message.h
//! (`ErtsSignalCommon.next`, `ErtsSignalInQueue`/`ErtsSignalPrivQueues` `first`/`last`,
//! `enqueue_signals`, the splice of `erts_proc_sig_fetch__`), OTP-29.1.1.
//!
//! All raw-pointer work on queue nodes is confined to this module. Deviation from erts, for a
//! queue that may move in memory: `last` points to the last node rather than to the last `next`
//! field (`ErtsMessage **last`); an empty queue has no `last`.

use std::marker::PhantomData;
use std::ptr::NonNull;

use crate::mailbox::InSignal;

/// One queued signal (`ErtsSignalCommon`: `next`, then the signal itself).
#[repr(C)]
pub struct SignalNode<T> {
    next: Option<NonNull<SignalNode<T>>>,
    value: T,
}

/// A signal node owned outside any queue: the sender before it enqueues, or the receiver after
/// it took the node out.
pub struct OwnedSignal<T> {
    node: NonNull<SignalNode<T>>,
    _value: PhantomData<T>,
}

// SAFETY: the handle owns its node like a `Box` owns its value.
unsafe impl<T: Send> Send for OwnedSignal<T> {}

impl<T> OwnedSignal<T> {
    /// Allocate a node for `value` (erts allocates the signal structure before it enqueues).
    pub fn new(value: T) -> Self {
        let node = Box::new(SignalNode { next: None, value });
        Self {
            node: NonNull::from(Box::leak(node)),
            _value: PhantomData,
        }
    }

    /// Free the node, giving back the signal.
    pub fn into_value(self) -> T {
        let node = self.node;
        std::mem::forget(self);
        // SAFETY: the handle owned the node, allocated by `Box` in `new`.
        let node = unsafe { Box::from_raw(node.as_ptr()) };
        node.value
    }

    fn into_node(self) -> NonNull<SignalNode<T>> {
        let node = self.node;
        std::mem::forget(self);
        node
    }

    fn from_node(node: NonNull<SignalNode<T>>) -> Self {
        Self {
            node,
            _value: PhantomData,
        }
    }
}

impl<T> std::ops::Deref for OwnedSignal<T> {
    type Target = T;

    fn deref(&self) -> &T {
        // SAFETY: the handle owns the node, so it is live and not borrowed elsewhere.
        unsafe { &self.node.as_ref().value }
    }
}

impl<T> std::ops::DerefMut for OwnedSignal<T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: as in `deref`, and the handle is borrowed exclusively.
        unsafe { &mut self.node.as_mut().value }
    }
}

impl<T> Drop for OwnedSignal<T> {
    fn drop(&mut self) {
        // SAFETY: the handle owned the node, allocated by `Box` in `new`.
        drop(unsafe { Box::from_raw(self.node.as_ptr()) });
    }
}

/// A queue of signal nodes (`first`/`last` of `ErtsSignalInQueue` and of the private queues),
/// with the count of its signals and of its non-message signals (erts tracks the latter with
/// `nmsigs`).
pub struct SignalQueue<T> {
    first: Option<NonNull<SignalNode<T>>>,
    last: Option<NonNull<SignalNode<T>>>,
    len: usize,
    non_messages: usize,
    _values: PhantomData<T>,
}

// SAFETY: the queue owns its nodes like a `Vec` owns its values.
unsafe impl<T: Send> Send for SignalQueue<T> {}

impl<T> Default for SignalQueue<T> {
    fn default() -> Self {
        Self {
            first: None,
            last: None,
            len: 0,
            non_messages: 0,
            _values: PhantomData,
        }
    }
}

impl<T> Drop for SignalQueue<T> {
    fn drop(&mut self) {
        while let Some(node) = self.pop_front_node() {
            drop(OwnedSignal::from_node(node));
        }
    }
}

impl<T: std::fmt::Debug> std::fmt::Debug for SignalQueue<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list().entries(self.iter()).finish()
    }
}

impl<T> SignalQueue<T> {
    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.first.is_none()
    }

    /// Non-message signals in the queue.
    pub fn non_messages(&self) -> usize {
        self.non_messages
    }

    pub fn front(&self) -> Option<&T> {
        // SAFETY: the queue owns its nodes; the borrow of the queue covers the node.
        self.first.map(|node| unsafe { &(*node.as_ptr()).value })
    }

    pub fn front_mut(&mut self) -> Option<&mut T> {
        // SAFETY: as in `front`, with the queue borrowed exclusively.
        self.first
            .map(|node| unsafe { &mut (*node.as_ptr()).value })
    }

    /// Unlink the first node.
    fn pop_front_node(&mut self) -> Option<NonNull<SignalNode<T>>> {
        let first = self.first?;
        // SAFETY: `first` is a node this queue owns.
        let next = unsafe { (*first.as_ptr()).next.take() };
        self.first = next;
        if next.is_none() {
            self.last = None;
        }
        self.len -= 1;
        Some(first)
    }

    /// Append the whole of `other`, leaving it empty (the splice of erts_proc_sig_fetch__ and
    /// enqueue_signals: `*last = first; last = other_last`).
    pub fn append(&mut self, other: &mut Self) {
        let Some(other_first) = other.first.take() else {
            return;
        };
        match self.last {
            // SAFETY: `last` is a node this queue owns, and has no successor.
            Some(last) => unsafe { (*last.as_ptr()).next = Some(other_first) },
            None => self.first = Some(other_first),
        }
        self.last = other.last.take();
        self.len += std::mem::take(&mut other.len);
        self.non_messages += std::mem::take(&mut other.non_messages);
    }

    pub fn iter(&self) -> Iter<'_, T> {
        Iter {
            node: self.first,
            _queue: PhantomData,
        }
    }

    pub fn iter_mut(&mut self) -> IterMut<'_, T> {
        IterMut {
            node: self.first,
            _queue: PhantomData,
        }
    }
}

impl<T: InSignal> SignalQueue<T> {
    /// Link an allocated node at the end.
    pub fn push_back_node(&mut self, signal: OwnedSignal<T>) {
        let non_message = !signal.is_message();
        let node = signal.into_node();
        match self.last {
            // SAFETY: `last` is a node this queue owns, and has no successor.
            Some(last) => unsafe { (*last.as_ptr()).next = Some(node) },
            None => self.first = Some(node),
        }
        self.last = Some(node);
        self.len += 1;
        self.non_messages += usize::from(non_message);
    }

    /// Allocate a node for `value` and link it at the end.
    pub fn push_back(&mut self, value: T) {
        self.push_back_node(OwnedSignal::new(value));
    }

    /// Take the first node out.
    pub fn pop_front_signal(&mut self) -> Option<OwnedSignal<T>> {
        let node = self.pop_front_node()?;
        let signal = OwnedSignal::from_node(node);
        self.non_messages -= usize::from(!signal.is_message());
        Some(signal)
    }

    /// Take the first signal out and free its node.
    pub fn pop_front(&mut self) -> Option<T> {
        self.pop_front_signal().map(OwnedSignal::into_value)
    }
}

/// Signals of a queue, first to last.
pub struct Iter<'a, T> {
    node: Option<NonNull<SignalNode<T>>>,
    _queue: PhantomData<&'a SignalQueue<T>>,
}

impl<'a, T> Iterator for Iter<'a, T> {
    type Item = &'a T;

    fn next(&mut self) -> Option<&'a T> {
        let node = self.node?;
        // SAFETY: the iterator borrows the queue, which owns the node.
        let node = unsafe { &*node.as_ptr() };
        self.node = node.next;
        Some(&node.value)
    }
}

/// Signals of a queue, first to last, mutably.
pub struct IterMut<'a, T> {
    node: Option<NonNull<SignalNode<T>>>,
    _queue: PhantomData<&'a mut SignalQueue<T>>,
}

impl<'a, T> Iterator for IterMut<'a, T> {
    type Item = &'a mut T;

    fn next(&mut self) -> Option<&'a mut T> {
        let node = self.node?;
        // SAFETY: the iterator borrows the queue exclusively, and yields each node once.
        let node = unsafe { &mut *node.as_ptr() };
        self.node = node.next;
        Some(&mut node.value)
    }
}

impl<'a, T> IntoIterator for &'a SignalQueue<T> {
    type Item = &'a T;
    type IntoIter = Iter<'a, T>;

    fn into_iter(self) -> Iter<'a, T> {
        self.iter()
    }
}

impl<'a, T> IntoIterator for &'a mut SignalQueue<T> {
    type Item = &'a mut T;
    type IntoIter = IterMut<'a, T>;

    fn into_iter(self) -> IterMut<'a, T> {
        self.iter_mut()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    impl InSignal for i64 {
        fn is_message(&self) -> bool {
            *self >= 0
        }
    }

    #[test]
    fn push_pop_and_append_keep_order_and_counts() {
        let mut first = SignalQueue::default();
        let mut second = SignalQueue::default();
        for value in [1_i64, -2, 3] {
            first.push_back(value);
        }
        for value in [4_i64, -5] {
            second.push_back(value);
        }
        assert_eq!((first.len(), first.non_messages()), (3, 1));
        first.append(&mut second);
        assert!(second.is_empty());
        assert_eq!((first.len(), first.non_messages()), (5, 2));
        assert_eq!(first.iter().copied().collect::<Vec<_>>(), [1, -2, 3, 4, -5]);
        for value in first.iter_mut() {
            *value *= 10;
        }
        assert_eq!(first.pop_front(), Some(10));
        assert_eq!(first.pop_front(), Some(-20));
        assert_eq!(first.non_messages(), 1);
        second.push_back(6);
        first.append(&mut second);
        assert_eq!(first.iter().copied().collect::<Vec<_>>(), [30, 40, -50, 6]);
        while first.pop_front().is_some() {}
        assert!(first.is_empty());
        first.push_back(7);
        assert_eq!(first.front(), Some(&7));
    }

    #[test]
    fn dropping_a_queue_frees_its_values() {
        let counter = std::sync::Arc::new(());
        struct Counted(#[allow(dead_code)] std::sync::Arc<()>);
        impl InSignal for Counted {
            fn is_message(&self) -> bool {
                true
            }
        }
        let mut queue = SignalQueue::default();
        for _ in 0..10 {
            queue.push_back(Counted(counter.clone()));
        }
        let taken = queue.pop_front_signal().expect("node");
        assert_eq!(std::sync::Arc::strong_count(&counter), 11);
        drop(queue);
        assert_eq!(std::sync::Arc::strong_count(&counter), 2);
        drop(taken);
        assert_eq!(std::sync::Arc::strong_count(&counter), 1);
    }
}
