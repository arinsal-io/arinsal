//! Signal and message nodes: one allocation per queued signal, which for a message also holds
//! the heap words of its data.
//!
//! Port of erts/emulator/beam/erl_message.h/.c (`ErtsMessage` with `ErlHeapFragment hfrag`
//! inline, `erts_alloc_message`, `ERTS_MSG_COMBINED_HFRAG`, `erts_free_message`), OTP-29.1.1.
//! The queue links (`next`) are used by the scheduler's signal queues; this module owns the
//! allocation and release of nodes. All raw allocation work on nodes is confined here.

use std::alloc::Layout;
use std::marker::PhantomData;
use std::ptr::NonNull;

/// One signal (`ErtsSignalCommon`): the queue link, then the signal value. A message node may
/// be followed in the same allocation by the words of its heap fragment
/// (`ERTS_MSG_COMBINED_HFRAG`).
#[repr(C)]
pub struct SignalNode<T> {
    /// The next node of the queue holding this one (`next`).
    pub next: Option<NonNull<SignalNode<T>>>,
    /// Words of the inline heap fragment after the node (`hfrag.alloc_size`), 0 for none.
    fragment_words: usize,
    /// The signal.
    pub value: T,
}

impl<T> SignalNode<T> {
    /// The layout of a node with `words` inline heap words, and the offset of those words.
    fn layout(words: usize) -> (Layout, usize) {
        let words_layout = Layout::array::<u64>(words).expect("message size fits");
        let (layout, offset) = Layout::new::<Self>()
            .extend(words_layout)
            .expect("message size fits");
        (layout.pad_to_align(), offset)
    }
}

/// A signal node owned outside any queue: the sender before it enqueues, or the receiver after
/// it took the node out of a queue.
pub struct OwnedSignal<T> {
    node: NonNull<SignalNode<T>>,
    _value: PhantomData<T>,
}

// SAFETY: the handle owns its node like a `Box` owns its value.
unsafe impl<T: Send> Send for OwnedSignal<T> {}

impl<T> OwnedSignal<T> {
    /// A node for `value` without heap words (`erts_alloc_message(0, NULL)`).
    pub fn new(value: T) -> Self {
        Self::with_heap_words(value, 0)
    }

    /// A node for `value` with `words` inline heap words after it (`erts_alloc_message(sz, &hp)`).
    pub fn with_heap_words(value: T, words: usize) -> Self {
        let (layout, _) = SignalNode::<T>::layout(words);
        // SAFETY: the layout has a nonzero size (it holds at least the `next` link).
        let raw = unsafe { std::alloc::alloc(layout) }.cast::<SignalNode<T>>();
        let Some(node) = NonNull::new(raw) else {
            std::alloc::handle_alloc_error(layout);
        };
        // SAFETY: `node` is a fresh allocation of the node's layout.
        unsafe {
            node.as_ptr().write(SignalNode {
                next: None,
                fragment_words: words,
                value,
            });
        }
        Self {
            node,
            _value: PhantomData,
        }
    }

    /// The inline heap words of this node (`hfrag.mem`), uninitialized until written.
    pub fn heap_words(&mut self) -> &mut [std::mem::MaybeUninit<u64>] {
        // SAFETY: the handle owns the node; the words follow it in the same allocation, as
        // `with_heap_words` laid it out, and no other reference to them is alive.
        unsafe {
            let words = (*self.node.as_ptr()).fragment_words;
            let (_, offset) = SignalNode::<T>::layout(words);
            let start = self.node.as_ptr().cast::<u8>().add(offset).cast();
            std::slice::from_raw_parts_mut(start, words)
        }
    }

    /// Free the node, giving back the signal (`erts_free_message`).
    pub fn into_value(self) -> T {
        let node = self.into_raw();
        // SAFETY: the handle owned the node, allocated by `with_heap_words`; the value is read
        // out exactly once before the memory is released.
        unsafe {
            let value = std::ptr::addr_of!((*node.as_ptr()).value).read();
            Self::release(node);
            value
        }
    }

    /// Give up ownership to a queue.
    pub fn into_raw(self) -> NonNull<SignalNode<T>> {
        let node = self.node;
        std::mem::forget(self);
        node
    }

    /// Take back ownership of a node a queue held.
    ///
    /// # Safety
    ///
    /// `node` came from [`OwnedSignal::into_raw`] of this type and no other owner is left.
    pub unsafe fn from_raw(node: NonNull<SignalNode<T>>) -> Self {
        Self {
            node,
            _value: PhantomData,
        }
    }

    /// Release the memory of a node whose value was moved out or dropped.
    ///
    /// # Safety
    ///
    /// `node` is an allocation of `with_heap_words` that nothing refers to any more.
    unsafe fn release(node: NonNull<SignalNode<T>>) {
        // SAFETY: the caller guarantees the node is live and unshared; its size is recorded in
        // `fragment_words`, so the layout matches the allocation.
        unsafe {
            let words = (*node.as_ptr()).fragment_words;
            let (layout, _) = SignalNode::<T>::layout(words);
            std::alloc::dealloc(node.as_ptr().cast(), layout);
        }
    }
}

impl<T> std::ops::Deref for OwnedSignal<T> {
    type Target = T;

    fn deref(&self) -> &T {
        // SAFETY: the handle owns the node, so it is live and not borrowed elsewhere.
        unsafe { &(*self.node.as_ptr()).value }
    }
}

impl<T> std::ops::DerefMut for OwnedSignal<T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: as in `deref`, and the handle is borrowed exclusively.
        unsafe { &mut (*self.node.as_ptr()).value }
    }
}

impl<T> Drop for OwnedSignal<T> {
    /// `erts_cleanup_messages` of one node: drop the signal, then free the node.
    fn drop(&mut self) {
        // SAFETY: the handle owns the node; the value is dropped once and the memory is
        // released after it.
        unsafe {
            std::ptr::drop_in_place(std::ptr::addr_of_mut!((*self.node.as_ptr()).value));
            Self::release(self.node);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inline_heap_words_follow_the_value() {
        let mut node = OwnedSignal::with_heap_words(String::from("value"), 5);
        let words = node.heap_words();
        assert_eq!(words.len(), 5);
        for (index, word) in words.iter_mut().enumerate() {
            word.write(index as u64);
        }
        assert_eq!(node.as_str(), "value");
        assert_eq!(node.into_value(), "value");
        let empty = OwnedSignal::new(vec![1, 2, 3]);
        assert_eq!(*empty, vec![1, 2, 3]);
    }
}
