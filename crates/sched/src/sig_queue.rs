//! Intrusive signal queues: singly linked lists of signal nodes with a tail pointer, so that a
//! queue is appended to another in O(1) without copying a signal.
//!
//! Port of the list handling of erts/emulator/beam/erl_proc_sig_queue.c/.h and erl_message.h
//! (`ErtsSignalCommon.next`, `ErtsSignalInQueue`/`ErtsSignalPrivQueues` `first`/`last`,
//! `enqueue_signals`, the splice of `erts_proc_sig_fetch__`), OTP-29.1.1.
//!
//! The queue links of nodes are only touched in this module; node allocation is in
//! `arinsal_term::message`. Deviation from erts, for a
//! queue that may move in memory: `last` points to the last node rather than to the last `next`
//! field (`ErtsMessage **last`); an empty queue has no `last`.

use std::marker::PhantomData;
use std::ptr::NonNull;

pub use arinsal_term::message::{OwnedSignal, SignalNode};

use crate::mailbox::InSignal;

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
            // SAFETY: the queue owned the node, which came from `OwnedSignal::into_raw`.
            drop(unsafe { OwnedSignal::from_raw(node) });
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
        let node = signal.into_raw();
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
        // SAFETY: the queue owned the node, which came from `OwnedSignal::into_raw`.
        let signal = unsafe { OwnedSignal::from_raw(node) };
        self.non_messages -= usize::from(!signal.is_message());
        Some(signal)
    }

    /// Take the first signal out and free its node.
    pub fn pop_front(&mut self) -> Option<T> {
        self.pop_front_signal().map(OwnedSignal::into_value)
    }
}

/// The message queue of a process (the inner queue of `ErtsSignalPrivQueues`): message nodes
/// linked in arrival order, reached by position. The receive loop walks it one message at a
/// time from its save position (`sig_qs.save`); a cursor remembers the node before the last
/// position reached, so stepping on, reading at, and unlinking at the save position cost O(1)
/// like erts' `**save`. Other positions are reached by walking from the cursor or the start.
pub struct MessageQueueList<T> {
    queue: SignalQueue<T>,
    /// Position `.0` and the node before it (`None` before the first node).
    cursor: std::cell::Cell<(usize, Option<NonNull<SignalNode<T>>>)>,
}

// SAFETY: the list owns its nodes like `SignalQueue`; the cursor only names one of them.
unsafe impl<T: Send> Send for MessageQueueList<T> {}

impl<T> Default for MessageQueueList<T> {
    fn default() -> Self {
        Self {
            queue: SignalQueue::default(),
            cursor: std::cell::Cell::new((0, None)),
        }
    }
}

impl<T> MessageQueueList<T> {
    pub fn len(&self) -> usize {
        self.queue.len()
    }

    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    /// The node before position `index` (`None` for position 0); `index <= len`.
    fn prev_of(&self, index: usize) -> Option<NonNull<SignalNode<T>>> {
        debug_assert!(index <= self.queue.len);
        if index == 0 {
            return None;
        }
        let (at, prev) = self.cursor.get();
        let (mut position, mut node) = if at <= index && at != 0 {
            (at - 1, prev.expect("a cursor past 0 has a node before it"))
        } else {
            (
                0,
                self.queue.first.expect("a nonempty list has a first node"),
            )
        };
        while position + 1 < index {
            // SAFETY: the list owns its nodes, and `position + 1 < index <= len` keeps the
            // walk inside the list.
            node = unsafe { (*node.as_ptr()).next }.expect("position within the list");
            position += 1;
        }
        self.cursor.set((index, Some(node)));
        Some(node)
    }

    fn node_at(&self, index: usize) -> Option<NonNull<SignalNode<T>>> {
        if index >= self.queue.len {
            return None;
        }
        match self.prev_of(index) {
            None => self.queue.first,
            // SAFETY: `prev` is a node of this list.
            Some(prev) => unsafe { (*prev.as_ptr()).next },
        }
    }

    pub fn get(&self, index: usize) -> Option<&T> {
        // SAFETY: the node belongs to this list, which the borrow of `self` covers.
        self.node_at(index)
            .map(|node| unsafe { &(*node.as_ptr()).value })
    }

    pub fn get_mut(&mut self, index: usize) -> Option<&mut T> {
        // SAFETY: as in `get`, with the list borrowed exclusively.
        self.node_at(index)
            .map(|node| unsafe { &mut (*node.as_ptr()).value })
    }

    /// The words of the data inline in the node at `index`.
    pub fn fragment_words(&self, index: usize) -> Option<&[u64]> {
        let node = self.node_at(index)?;
        // SAFETY: the node belongs to this list, which the borrow of `self` keeps unchanged.
        unsafe { OwnedSignal::fragment_words_of(node) }
    }

    pub fn front_mut(&mut self) -> Option<&mut T> {
        self.queue.front_mut()
    }

    pub fn iter(&self) -> Iter<'_, T> {
        self.queue.iter()
    }

    pub fn iter_mut(&mut self) -> IterMut<'_, T> {
        self.queue.iter_mut()
    }

    /// Each signal with the words of its inline data.
    pub fn iter_with_fragments(&self) -> impl Iterator<Item = (&T, Option<&[u64]>)> {
        let mut node = self.queue.first;
        std::iter::from_fn(move || {
            let current = node?;
            // SAFETY: the node belongs to this list, which the borrow of `self` keeps unchanged.
            unsafe {
                node = (*current.as_ptr()).next;
                Some((
                    &(*current.as_ptr()).value,
                    OwnedSignal::fragment_words_of(current),
                ))
            }
        })
    }
}

impl<T: InSignal> MessageQueueList<T> {
    pub fn push_back(&mut self, signal: OwnedSignal<T>) {
        self.queue.push_back_node(signal);
    }

    /// Link `signal` at position `index` (`index <= len`).
    pub fn insert(&mut self, index: usize, signal: OwnedSignal<T>) {
        if index >= self.queue.len {
            self.push_back(signal);
            return;
        }
        let prev = self.prev_of(index);
        let non_message = !signal.is_message();
        let node = signal.into_raw();
        // SAFETY: `prev` and its successor are nodes of this list; `node` is unlinked.
        unsafe {
            match prev {
                None => {
                    (*node.as_ptr()).next = self.queue.first;
                    self.queue.first = Some(node);
                }
                Some(prev) => {
                    (*node.as_ptr()).next = (*prev.as_ptr()).next;
                    (*prev.as_ptr()).next = Some(node);
                }
            }
        }
        self.queue.len += 1;
        self.queue.non_messages += usize::from(non_message);
        self.cursor.set((index + 1, Some(node)));
    }

    /// Unlink the node at `index` (`erts_msgq_unlink_msg`).
    pub fn remove(&mut self, index: usize) -> Option<OwnedSignal<T>> {
        if index >= self.queue.len {
            return None;
        }
        let prev = self.prev_of(index);
        // SAFETY: `prev` (or `first`) and the node after it belong to this list.
        let node = unsafe {
            let node = match prev {
                None => self.queue.first,
                Some(prev) => (*prev.as_ptr()).next,
            }
            .expect("index within the list");
            let next = (*node.as_ptr()).next.take();
            match prev {
                None => self.queue.first = next,
                Some(prev) => (*prev.as_ptr()).next = next,
            }
            if next.is_none() {
                self.queue.last = prev;
            }
            node
        };
        self.queue.len -= 1;
        self.cursor.set((index, prev));
        // SAFETY: the node was linked in this list, which owned it; it is unlinked now.
        let signal = unsafe { OwnedSignal::from_raw(node) };
        self.queue.non_messages -= usize::from(!signal.is_message());
        Some(signal)
    }

    /// Put `signal` in place of the node at `index`, giving that node back.
    pub fn replace(&mut self, index: usize, signal: OwnedSignal<T>) -> Option<OwnedSignal<T>> {
        let old = self.remove(index)?;
        self.insert(index, signal);
        Some(old)
    }

    pub fn pop_front(&mut self) -> Option<OwnedSignal<T>> {
        self.remove(0)
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
    fn message_queue_list_matches_a_vec_deque_under_random_operations() {
        let mut list = MessageQueueList::default();
        let mut model = std::collections::VecDeque::new();
        let mut state = 0x2545_F491_4F6C_DD1D_u64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for step in 0..20_000_i64 {
            let len = model.len();
            match next() % 6 {
                0 | 1 => {
                    list.push_back(OwnedSignal::new(step));
                    model.push_back(step);
                }
                2 => {
                    let index = (next() as usize) % (len + 1);
                    list.insert(index, OwnedSignal::new(step));
                    model.insert(index, step);
                }
                3 if len != 0 => {
                    let index = (next() as usize) % len;
                    assert_eq!(
                        list.remove(index).map(OwnedSignal::into_value),
                        model.remove(index)
                    );
                }
                4 if len != 0 => {
                    // The receive loop: step through a run of positions, then unlink one.
                    let start = (next() as usize) % len;
                    for index in start..len.min(start + 4) {
                        assert_eq!(list.get(index), model.get(index));
                    }
                    let at = len.min(start + 2) - 1;
                    assert_eq!(
                        list.remove(at).map(OwnedSignal::into_value),
                        model.remove(at)
                    );
                }
                _ => {
                    let index = (next() as usize) % (len + 1);
                    assert_eq!(list.get(index), model.get(index));
                }
            }
            assert_eq!(list.len(), model.len());
        }
        assert!(list.iter().eq(model.iter()));
        while let Some(value) = list.pop_front() {
            assert_eq!(Some(value.into_value()), model.pop_front());
        }
        assert!(list.is_empty());
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
