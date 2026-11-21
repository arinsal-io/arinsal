//! Raw `ErtsProcList` node ownership and link updates.
// Port of erts/emulator/beam/erl_process.c (`ErtsProcList` operations), OTP-29.1.1.

use super::SchedulerProcListEntry;
use std::marker::PhantomData;
use std::ptr::NonNull;

struct Node {
    entry: SchedulerProcListEntry,
    previous: Option<NonNull<Node>>,
    next: Option<NonNull<Node>>,
}

#[derive(Default)]
pub(super) struct ErtsProcList {
    first: Option<NonNull<Node>>,
    last: Option<NonNull<Node>>,
    len: usize,
}

// SAFETY: the list uniquely owns every linked Box node. Its links are accessed only while the
// enclosing scheduler suspend mutex is held, and moving the list transfers that ownership.
unsafe impl Send for ErtsProcList {}

impl ErtsProcList {
    pub(super) fn is_empty(&self) -> bool {
        self.first.is_none()
    }

    pub(super) fn len(&self) -> usize {
        self.len
    }

    pub(super) fn iter(&self) -> Iter<'_> {
        Iter {
            next: self.first,
            _list: PhantomData,
        }
    }

    pub(super) fn pop_first(&mut self) -> Option<SchedulerProcListEntry> {
        let first = self.first?;
        // SAFETY: `first` is the live head node uniquely owned by this list.
        let next = unsafe { first.as_ref().next };
        if let Some(mut next_node) = next {
            // SAFETY: `next_node` is the live successor and becomes the new head.
            unsafe { next_node.as_mut().previous = None };
        } else {
            self.last = None;
        }
        self.first = next;
        self.len -= 1;
        // SAFETY: `first` is still live and is no longer linked in this list.
        let entry = unsafe { first.as_ref().entry };
        // SAFETY: `first` originated from `Box::leak` in `push_last` and is no longer linked.
        unsafe { drop(Box::from_raw(first.as_ptr())) };
        Some(entry)
    }

    pub(super) fn push_last(&mut self, entry: SchedulerProcListEntry) {
        let node = NonNull::from(Box::leak(Box::new(Node {
            entry,
            previous: self.last,
            next: None,
        })));
        if let Some(mut last) = self.last {
            // SAFETY: `last` is the live tail node uniquely owned by this list.
            unsafe { last.as_mut().next = Some(node) };
        } else {
            self.first = Some(node);
        }
        self.last = Some(node);
        self.len += 1;
    }

    pub(super) fn remove(&mut self, pid: crate::Pid, all: bool) {
        let mut found = false;
        let mut current = self.first;
        while let Some(node) = current {
            // SAFETY: every linked node remains live until it is unlinked below.
            let entry = unsafe { node.as_ref().entry };
            // SAFETY: `node` remains live until after its successor is saved.
            let next = unsafe { node.as_ref().next };
            if entry.pid == pid && (all || !found) {
                found = true;
                // SAFETY: `node` is still live and linked in this list.
                let previous = unsafe { node.as_ref().previous };
                if let Some(mut previous) = previous {
                    // SAFETY: `previous` is the live predecessor; replacing its next link unlinks `node`.
                    unsafe { previous.as_mut().next = next };
                } else {
                    self.first = next;
                }
                if let Some(mut next_node) = next {
                    // SAFETY: `next_node` is the live successor; replacing its previous link unlinks `node`.
                    unsafe { next_node.as_mut().previous = previous };
                } else {
                    self.last = previous;
                }
                self.len -= 1;
                // SAFETY: `node` came from `Box::leak` in `push_last` and is no longer linked.
                unsafe { drop(Box::from_raw(node.as_ptr())) };
            }
            current = next;
        }
    }

    pub(super) fn append(&mut self, other: &mut Self) {
        let Some(other_first) = other.first else {
            return;
        };
        if let Some(mut last) = self.last {
            // SAFETY: `last` is this list's live tail; `other_first` is the other list's live head.
            unsafe { last.as_mut().next = Some(other_first) };
            let mut other_first = other_first;
            // SAFETY: `other_first` is live and becomes adjacent to `last` after the splice.
            unsafe { other_first.as_mut().previous = Some(last) };
        } else {
            self.first = Some(other_first);
        }
        self.last = other.last;
        self.len += other.len;
        other.first = None;
        other.last = None;
        other.len = 0;
    }
}

impl Drop for ErtsProcList {
    fn drop(&mut self) {
        let mut current = self.first;
        while let Some(node) = current {
            // SAFETY: each node is live and owned by this list until reconstructed as a Box below.
            current = unsafe { node.as_ref().next };
            // SAFETY: each linked node originated from `Box::leak` and is freed exactly once here.
            unsafe { drop(Box::from_raw(node.as_ptr())) };
        }
    }
}

pub(super) struct Iter<'a> {
    next: Option<NonNull<Node>>,
    _list: PhantomData<&'a ErtsProcList>,
}

impl Iterator for Iter<'_> {
    type Item = SchedulerProcListEntry;

    fn next(&mut self) -> Option<Self::Item> {
        let node = self.next?;
        // SAFETY: the iterator borrows its list immutably, so linked nodes remain live.
        let node_ref = unsafe { node.as_ref() };
        self.next = node_ref.next;
        Some(node_ref.entry)
    }
}
