//! The message queue of a process: the inner queue of `ErtsSignalPrivQueues` with its
//! `first`, `last` and `save` pointers. The only `unsafe` of the message queue.
//!
//! Port of erts/emulator/beam/erl_message.h (`ErtsSignalPrivQueues`: `ErtsMessage *first`,
//! `ErtsMessage **last`, `ErtsMessage **save`, `mq_len`) and erl_proc_sig_queue.h
//! (`erts_msgq_peek_msg`, `erts_msgq_unlink_msg`, `erts_msgq_set_save_first`,
//! `erts_msgq_set_save_next`, `erts_msgq_set_save_end`) and erl_proc_sig_queue.c
//! (erts_proc_sig_fetch__: `*sig_qs.last = sig_inq.first`), OTP-29.1.1.
//!
//! `last` and `save` point at a `next` field: either `first` of the queue itself or `next` of
//! a node. Like erts, which sets them to `&p->sig_qs.first` in erl_create_process once the
//! process block is placed, the queue must be anchored with [`MessageQueueList::init_in_place`]
//! where it stays and must not move while anchored.

use std::marker::PhantomData;
use std::ptr::NonNull;

use super::{Iter, IterMut, OwnedSignal, SignalNode, SignalQueue};

/// A `next` field: `&first` or `&node.next` (`ErtsMessage **`).
type NextPtr<T> = *mut Option<NonNull<SignalNode<T>>>;

/// A `next` field of a message queue (`ErtsMessage **`), as callers hold it: the save pointer,
/// `last`, or the `prev_next` of a marker. Only this module reads through it.
pub struct NextField<T>(NextPtr<T>);

impl<T> Clone for NextField<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> Copy for NextField<T> {}

impl<T> PartialEq for NextField<T> {
    fn eq(&self, other: &Self) -> bool {
        std::ptr::eq(self.0, other.0)
    }
}

impl<T> Eq for NextField<T> {}

impl<T> std::fmt::Debug for NextField<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "NextField({:p})", self.0)
    }
}

/// `ERTS_RECV_MARKER_TYPE_RECV`.
pub const RECV_MARKER_TYPE_RECV: i8 = 0;
/// `ERTS_RECV_MARKER_TYPE_YIELD`.
pub const RECV_MARKER_TYPE_YIELD: i8 = 1;
/// `ERTS_RECV_MARKER_TYPE_PRIO_Q_END`.
pub const RECV_MARKER_TYPE_PRIO_Q_END: i8 = 2;
/// `ERTS_RECV_MARKER_TYPE_PRIO_Q_CONT`.
pub const RECV_MARKER_TYPE_PRIO_Q_CONT: i8 = 3;

const LAZY_HEADER_WORDS: usize =
    arinsal_term::message::LAZY_HEADER_BYTES / std::mem::size_of::<usize>();

/// `ErtsRecvMarker`: a marker of the process's marker block. While queued, its header is the
/// signal node (a lazy node with [`crate::LAZY_RECV_MARKER`] meta) linked in the middle queue
/// or the message queue; the block owns it, the queues never free it.
// Port of erts/emulator/beam/erl_message.h (ErtsRecvMarker), OTP-29.1.1.
#[repr(C)]
pub struct RecvMarker<T> {
    /// `sig`: the queue header, written when the marker is inserted.
    header: [usize; LAZY_HEADER_WORDS],
    /// `prev_next`: the `next` field that points at this marker in the message queue.
    prev_next: NextPtr<T>,
    pub mark_type: i8,
    pub pass: i8,
    pub set_save: i8,
    pub in_prioq: i8,
    pub in_sigq: i8,
    pub in_msgq: i8,
    pub prev_ix: i8,
    pub next_ix: i8,
}

// SAFETY: a marker is owned by its block; `prev_next` only names a field of the same process's
// queues.
unsafe impl<T: Send> Send for RecvMarker<T> {}

impl<T> Default for RecvMarker<T> {
    fn default() -> Self {
        Self {
            header: [0; LAZY_HEADER_WORDS],
            prev_next: std::ptr::null_mut(),
            mark_type: RECV_MARKER_TYPE_RECV,
            pass: 0,
            set_save: 0,
            in_prioq: 0,
            in_sigq: 0,
            in_msgq: 0,
            prev_ix: 0,
            next_ix: 0,
        }
    }
}

impl<T> RecvMarker<T> {
    /// The signal node of the marker, to link into a queue (`markp->sig.common.tag =
    /// ERTS_RECV_MARKER_TAG`). `materialise` is never called for a marker: the queues hand
    /// marker nodes back to the block.
    pub fn signal(&mut self, materialise: unsafe fn(NonNull<u8>) -> T) -> OwnedSignal<T> {
        OwnedSignal::lazy(
            NonNull::from(&mut self.header).cast(),
            crate::LAZY_RECV_MARKER,
            materialise,
        )
    }

    /// `prev_next`.
    pub fn prev_next(&self) -> NextField<T> {
        NextField(self.prev_next)
    }

    /// The `next` field of the marker's node (`&markp->sig.common.next`).
    pub fn next_field(&mut self) -> NextField<T> {
        NextField(
            NonNull::from(&mut self.header)
                .cast::<SignalNode<T>>()
                .as_ptr() as NextPtr<T>,
        )
    }

    /// The marker whose header is `node`, when `node` is a marker node.
    fn of(node: NonNull<SignalNode<T>>) -> Option<NonNull<RecvMarker<T>>> {
        OwnedSignal::lazy_meta_of(node)
            .is_some_and(crate::is_recv_marker_meta)
            .then(|| node.cast())
    }

    /// The address of the marker of a marker node taken out of a queue; the block keeps
    /// owning the marker and finds it by the address.
    pub fn from_signal(signal: OwnedSignal<T>) -> usize {
        let node = signal.into_raw();
        Self::of(node).expect("a recv marker node").as_ptr() as usize
    }

    /// Whether `signal` is a marker node.
    pub fn is_marker(signal: &OwnedSignal<T>) -> bool {
        signal.lazy_meta().is_some_and(crate::is_recv_marker_meta)
    }
}

/// The message queue (`sig_qs.first`/`last`/`save`/`mq_len`).
#[repr(C)]
pub struct MessageQueueList<T> {
    first: Option<NonNull<SignalNode<T>>>,
    /// `sig_qs.last`: the `next` field of the last node, `&first` when empty.
    last: NextPtr<T>,
    /// `sig_qs.save`: the `next` field pointing at the message a receive looks at next.
    save: NextPtr<T>,
    /// `sig_qs.mq_len`.
    len: usize,
    _values: PhantomData<T>,
}

// SAFETY: the list owns its nodes like a `Vec` owns its values; `last` and `save` only name
// fields of the list or of its nodes.
unsafe impl<T: Send> Send for MessageQueueList<T> {}

impl<T> Default for MessageQueueList<T> {
    /// A queue not yet anchored: erts' process block before erl_create_process sets
    /// `last = save = &first`.
    fn default() -> Self {
        Self {
            first: None,
            last: std::ptr::null_mut(),
            save: std::ptr::null_mut(),
            len: 0,
            _values: PhantomData,
        }
    }
}

impl<T> Drop for MessageQueueList<T> {
    fn drop(&mut self) {
        let mut node = self.first.take();
        while let Some(current) = node {
            // SAFETY: the list owned the node, which came from `OwnedSignal::into_raw`; a marker
            // node is the block's and is only unlinked.
            unsafe {
                node = (*current.as_ptr()).next.take();
                if RecvMarker::of(current).is_none() {
                    drop(OwnedSignal::from_raw(current));
                }
            }
        }
    }
}

impl<T> MessageQueueList<T> {
    /// Byte offset of `save`, for generated code (`offsetof(Process, sig_qs.save)`).
    pub const SAVE_OFFSET: usize = std::mem::offset_of!(MessageQueueList<T>, save);

    /// Anchor the queue where it stays: `last = save = &first`.
    // Port of erts/emulator/beam/erl_process.c:12723-12727 (erl_create_process), OTP-29.1.1.
    pub fn init_in_place(&mut self) {
        debug_assert!(self.first.is_none(), "a queue is anchored while empty");
        self.last = &raw mut self.first;
        self.save = &raw mut self.first;
    }

    #[inline(always)]
    fn debug_check_anchor(&self) {
        debug_assert!(
            !self.last.is_null() && (self.first.is_some() || std::ptr::eq(self.last, &self.first)),
            "message queue used unanchored or after a move"
        );
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.first.is_none()
    }

    /// `erts_msgq_peek_msg`: the message at the save pointer.
    #[inline(always)]
    pub fn peek(&self) -> Option<&T> {
        self.debug_check_anchor();
        // SAFETY: `save` names `first` or the `next` of a node of this list.
        let node = unsafe { *self.save }?;
        OwnedSignal::value_of(node)
    }

    /// The node at the save pointer, for reading its term without a borrow of the value type.
    #[inline(always)]
    pub fn peek_node(&self) -> Option<NonNull<SignalNode<T>>> {
        self.debug_check_anchor();
        // SAFETY: as in `peek`.
        unsafe { *self.save }
    }

    /// [`MessageQueueList::peek`], mutably.
    pub fn peek_mut(&mut self) -> Option<&mut T> {
        self.debug_check_anchor();
        // SAFETY: as in `peek`, with the list borrowed exclusively.
        let node = unsafe { *self.save }?;
        OwnedSignal::value_mut_of(node)
    }

    /// Whether the save pointer is at the first message (`save == &first`).
    pub fn save_is_first(&self) -> bool {
        std::ptr::eq(self.save, &self.first)
    }

    /// `erts_msgq_set_save_first`.
    #[inline(always)]
    pub fn set_save_first(&mut self) {
        self.save = &raw mut self.first;
    }

    /// `erts_msgq_set_save_next`: step past the message at the save pointer.
    #[inline(always)]
    pub fn set_save_next(&mut self) {
        self.debug_check_anchor();
        // SAFETY: `save` names a `next` field of this list; a message is at it.
        unsafe {
            let node = (*self.save).expect("set_save_next at a message");
            self.save = &raw mut (*node.as_ptr()).next;
        }
    }

    /// `erts_msgq_set_save_end`: the save pointer at the end of the queue.
    #[inline(always)]
    pub fn set_save_end(&mut self) {
        self.debug_check_anchor();
        self.save = self.last;
    }

    /// The last signal: the node whose `next` field `last` names (`next` is the first field of
    /// a node).
    pub fn back(&self) -> Option<&T> {
        self.debug_check_anchor();
        self.first?;
        // SAFETY: a nonempty queue's `last` is the `next` field of its last node, which is at
        // offset 0 of the `#[repr(C)]` node.
        OwnedSignal::value_of(NonNull::new(self.last.cast::<SignalNode<T>>())?)
    }

    /// Walk the queue once, letting `f` put a node of its own in place of each node; `last`
    /// and `save` follow a node that is replaced.
    // Port of erts/emulator/beam/erl_proc_sig_queue.c (move_msgs_to_heap: each message of the
    // queue is relinked in place as the walk passes it), OTP-29.1.1.
    pub fn relink_each(&mut self, mut f: impl FnMut(usize, OwnedSignal<T>) -> OwnedSignal<T>) {
        self.debug_check_anchor();
        let mut field: NextPtr<T> = &raw mut self.first;
        let mut index = 0;
        // SAFETY: `field` is always `first` or the `next` of a node of this list; each node is
        // unlinked before `f` owns it and the node `f` gives back is linked in its place.
        unsafe {
            while let Some(node) = *field {
                if let Some(marker) = RecvMarker::of(node) {
                    (*marker.as_ptr()).prev_next = field;
                    field = &raw mut (*node.as_ptr()).next;
                    continue;
                }
                let old_next: NextPtr<T> = &raw mut (*node.as_ptr()).next;
                let next = (*old_next).take();
                let new = f(index, OwnedSignal::from_raw(node)).into_raw();
                let new_next: NextPtr<T> = &raw mut (*new.as_ptr()).next;
                *new_next = next;
                *field = Some(new);
                if std::ptr::eq(self.save, old_next) {
                    self.save = new_next;
                }
                if std::ptr::eq(self.last, old_next) {
                    self.last = new_next;
                }
                field = new_next;
                index += 1;
            }
        }
    }

    pub fn front_mut(&mut self) -> Option<&mut T> {
        OwnedSignal::value_mut_of(self.first?)
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

    /// Each message with the words of its inline data; marker nodes, which have neither, are
    /// passed.
    pub fn iter_with_fragments(&self) -> impl Iterator<Item = (&T, Option<&[u64]>)> {
        let mut node = self.first;
        std::iter::from_fn(move || {
            loop {
                let current = node?;
                // SAFETY: the node belongs to this list, which the borrow of `self` keeps
                // unchanged; a marker node's header is not read as a value or a fragment.
                unsafe {
                    node = (*current.as_ptr()).next;
                    if RecvMarker::of(current).is_some() {
                        continue;
                    }
                    return Some((
                        &(*current.as_ptr()).value,
                        OwnedSignal::fragment_words_of(current),
                    ));
                }
            }
        })
    }

    /// Link an allocated node at the end (`*last = msg; last = &msg->next`).
    #[inline]
    pub fn push_back(&mut self, signal: OwnedSignal<T>) {
        self.debug_check_anchor();
        let node = signal.into_raw();
        // SAFETY: `last` names the `next` field of the last node or `first`; `node` is unlinked
        // and its `next` is empty.
        unsafe {
            match RecvMarker::of(node) {
                Some(marker) => (*marker.as_ptr()).prev_next = self.last,
                None => self.len += 1,
            }
            *self.last = Some(node);
            self.last = &raw mut (*node.as_ptr()).next;
        }
    }

    /// Splice `other` onto the end, leaving it empty (erts_proc_sig_fetch__:
    /// `*sig_qs.last = sig_inq.first; sig_qs.last = sig_inq.last`).
    pub fn append(&mut self, other: &mut SignalQueue<T>) {
        self.debug_check_anchor();
        debug_assert_eq!(other.non_messages, 0, "the message queue holds messages");
        let Some(other_first) = other.first.take() else {
            return;
        };
        let other_last = other.last.take().expect("a nonempty queue has a last node");
        // SAFETY: `last` names a `next` field of this list; `other_last` is the last node of
        // the spliced chain.
        unsafe {
            *self.last = Some(other_first);
            self.last = &raw mut (*other_last.as_ptr()).next;
        }
        self.len += std::mem::take(&mut other.len);
        other.non_messages = 0;
    }

    /// Unlink the node `field` points at; `last` follows. The save pointer is the caller's.
    ///
    /// # Safety
    ///
    /// `field` is a `next` field of this list that points at a node.
    unsafe fn unlink_at(&mut self, field: NextPtr<T>) -> OwnedSignal<T> {
        // SAFETY: guaranteed by the caller.
        unsafe {
            let node = (*field).expect("a node at the field");
            let old_next: NextPtr<T> = &raw mut (*node.as_ptr()).next;
            let next = (*old_next).take();
            *field = next;
            if std::ptr::eq(self.last, old_next) {
                self.last = field;
            }
            if std::ptr::eq(self.save, old_next) {
                self.save = field;
            }
            if let Some(marker) = next.and_then(RecvMarker::of) {
                (*marker.as_ptr()).prev_next = field;
            }
            if RecvMarker::of(node).is_none() {
                self.len -= 1;
            }
            OwnedSignal::from_raw(node)
        }
    }

    /// The node `field` names; `None` at the end.
    pub fn at(&self, field: NextField<T>) -> Option<Option<&T>> {
        // SAFETY: a `NextField` of this list names `first` or the `next` of one of its nodes.
        let node = unsafe { *field.0 }?;
        Some(OwnedSignal::value_of(node))
    }

    /// The address of the marker `field` names, when it names a marker node: its block finds
    /// the marker by it.
    pub fn marker_at(&self, field: NextField<T>) -> Option<usize> {
        // SAFETY: as in `at`.
        unsafe { RecvMarker::of((*field.0)?).map(|marker| marker.as_ptr() as usize) }
    }

    /// The `next` field after the node `field` names.
    pub fn next_of(&self, field: NextField<T>) -> Option<NextField<T>> {
        // SAFETY: as in `at`.
        unsafe {
            let node = (*field.0)?;
            Some(NextField(&raw mut (*node.as_ptr()).next))
        }
    }

    /// `sig_qs.save`.
    pub fn save_field(&self) -> NextField<T> {
        NextField(self.save)
    }

    /// Set `sig_qs.save` to a `next` field of this list.
    pub fn set_save_field(&mut self, field: NextField<T>) {
        self.save = field.0;
    }

    /// `sig_qs.last`.
    pub fn last_field(&self) -> NextField<T> {
        NextField(self.last)
    }

    /// `&sig_qs.first`.
    pub fn first_field(&mut self) -> NextField<T> {
        NextField(&raw mut self.first)
    }

    /// `insert_prio_q_marker`: link `marker` at `field`; `last`, `save` and the `prev_next`
    /// of a marker that followed move past it.
    // Port of erts/emulator/beam/erl_proc_sig_queue.c:8970 (insert_prio_q_marker), OTP-29.1.1.
    pub fn insert_marker_at(
        &mut self,
        field: NextField<T>,
        marker: &mut RecvMarker<T>,
        materialise: unsafe fn(NonNull<u8>) -> T,
    ) {
        let node = marker.signal(materialise).into_raw();
        // SAFETY: `field` is a `next` field of this list; `node` is the marker's unlinked node.
        unsafe {
            let mark_next: NextPtr<T> = &raw mut (*node.as_ptr()).next;
            if std::ptr::eq(self.last, field.0) {
                self.last = mark_next;
            }
            if std::ptr::eq(self.save, field.0) {
                self.save = mark_next;
            }
            if let Some(next) = (*field.0).and_then(RecvMarker::of) {
                (*next.as_ptr()).prev_next = mark_next;
            }
            marker.prev_next = field.0;
            *mark_next = *field.0;
            *field.0 = Some(node);
        }
        marker.in_sigq = 1;
        marker.in_msgq = 1;
    }

    /// Link a message right before `marker` (`*pq_end->prev_next = sig; pq_end->prev_next =
    /// &sig->next; sig->next = pq_end`); a save pointer at that field then names it.
    // Port of erts/emulator/beam/erl_proc_sig_queue.c:9475-9480
    // (insert_prepared_prio_msg_attached), OTP-29.1.1.
    pub fn insert_before_marker(&mut self, marker: &mut RecvMarker<T>, signal: OwnedSignal<T>) {
        let node = signal.into_raw();
        let field = marker.prev_next;
        // SAFETY: a queued marker is named by its `prev_next`, a `next` field of this list;
        // `node` is unlinked.
        unsafe {
            debug_assert!(RecvMarker::of((*field).expect("a queued marker")).is_some());
            (*node.as_ptr()).next = *field;
            *field = Some(node);
            marker.prev_next = &raw mut (*node.as_ptr()).next;
        }
        self.len += 1;
    }

    /// `remove_innerq_sig` of a marker: unlink it from the message queue at its `prev_next`;
    /// `save`, `last` and the `prev_next` of a following marker move to that field.
    // Port of erts/emulator/beam/erl_proc_sig_queue.c (remove_innerq_sig), OTP-29.1.1.
    pub fn remove_marker(&mut self, marker: &mut RecvMarker<T>) {
        let field = marker.prev_next;
        // SAFETY: a marker in the message queue is named by its `prev_next`.
        let signal = unsafe {
            debug_assert!(RecvMarker::of((*field).expect("a queued marker")).is_some());
            self.unlink_at(field)
        };
        RecvMarker::from_signal(signal);
        marker.prev_next = std::ptr::null_mut();
    }

    /// `erts_msgq_unlink_msg`: unlink the message at the save pointer, which stays at the
    /// `next` field that now names the following message.
    #[inline]
    pub fn unlink_at_save(&mut self) -> Option<OwnedSignal<T>> {
        self.debug_check_anchor();
        // SAFETY: `save` is a `next` field of this list, checked to point at a node.
        unsafe { (*self.save).is_some().then(|| self.unlink_at(self.save)) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mailbox::InSignal;

    impl InSignal for u32 {
        fn is_message(&self) -> bool {
            true
        }
    }

    fn values(list: &MessageQueueList<u32>) -> Vec<u32> {
        list.iter().copied().collect()
    }

    #[test]
    fn save_pointer_follows_push_unlink_and_splice() {
        let mut list = MessageQueueList::<u32>::default();
        list.init_in_place();
        assert!(list.peek().is_none());
        list.push_back(OwnedSignal::new(1));
        assert_eq!(list.peek(), Some(&1));
        list.push_back(OwnedSignal::new(2));
        list.set_save_next();
        assert_eq!(list.peek(), Some(&2));
        list.set_save_next();
        assert!(list.peek().is_none());
        // A message linked at the end arrives at a save pointer at the end.
        list.push_back(OwnedSignal::new(3));
        assert_eq!(list.peek(), Some(&3));
        let mut other = SignalQueue::default();
        other.push_back(4);
        other.push_back(5);
        list.append(&mut other);
        assert!(other.is_empty());
        assert_eq!(values(&list), [1, 2, 3, 4, 5]);
        assert_eq!(list.unlink_at_save().map(OwnedSignal::into_value), Some(3));
        assert_eq!(list.peek(), Some(&4));
        list.set_save_end();
        assert!(list.peek().is_none());
        list.set_save_first();
        for _ in 0..3 {
            list.set_save_next();
        }
        assert_eq!(list.unlink_at_save().map(OwnedSignal::into_value), Some(5));
        // `last` moved back to the node before the removed one.
        list.push_back(OwnedSignal::new(6));
        assert_eq!(values(&list), [1, 2, 4, 6]);
        list.set_save_first();
        assert!(list.save_is_first());
        while list.unlink_at_save().is_some() {}
        assert!(list.is_empty());
        list.push_back(OwnedSignal::new(7));
        assert_eq!((list.len(), list.peek()), (1, Some(&7)));
    }

    /// Never called: the list hands marker nodes back to their block.
    unsafe fn no_value(_: NonNull<u8>) -> u32 {
        unreachable!("a marker node has no value")
    }

    #[test]
    fn markers_are_linked_passed_and_removed_without_counting() {
        let mut markers: Box<[RecvMarker<u32>; 2]> = Box::default();
        let mut list = MessageQueueList::<u32>::default();
        list.init_in_place();
        list.push_back(OwnedSignal::new(1));
        let [first_marker, second_marker] = &mut *markers;
        list.push_back(first_marker.signal(no_value));
        list.push_back(second_marker.signal(no_value));
        list.push_back(OwnedSignal::new(2));
        assert_eq!((list.len(), values(&list)), (1 + 1, vec![1, 2]));
        assert_eq!(
            list.iter_with_fragments()
                .map(|(value, words)| (*value, words.is_none()))
                .collect::<Vec<_>>(),
            [(1, true), (2, true)]
        );
        // The save pointer after message 1 names the first marker.
        list.set_save_next();
        let save = list.save_field();
        assert_eq!(first_marker.prev_next(), save);
        assert_eq!(
            list.marker_at(save),
            Some(std::ptr::from_ref(&*first_marker) as usize)
        );
        // Pass both markers by their `next` fields.
        let after_first = first_marker.next_field();
        assert_eq!(second_marker.prev_next(), after_first);
        let after_second = second_marker.next_field();
        list.set_save_field(after_second);
        assert_eq!(list.peek(), Some(&2));
        // Unlinking message 1 moves the first marker's `prev_next` to `first`.
        list.set_save_first();
        assert_eq!(list.unlink_at_save().map(OwnedSignal::into_value), Some(1));
        let first = list.first_field();
        assert_eq!(first_marker.prev_next(), first);
        // Removing a marker whose `next` field is `save` moves `save` back.
        list.set_save_field(after_first);
        list.remove_marker(first_marker);
        assert_eq!(list.save_field(), first);
        assert_eq!(second_marker.prev_next(), first);
        list.set_save_field(after_second);
        assert_eq!(list.unlink_at_save().map(OwnedSignal::into_value), Some(2));
        assert_eq!(list.last_field(), after_second);
        list.remove_marker(second_marker);
        assert_eq!((list.last_field(), list.len()), (first, 0));
        assert!(list.is_empty());
        // A queue dropped with a marker in it leaves the marker to its block.
        list.push_back(second_marker.signal(no_value));
        list.push_back(OwnedSignal::new(3));
        drop(list);
    }
}
