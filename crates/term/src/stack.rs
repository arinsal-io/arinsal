//! Explicit work stacks for iterative term walkers.
use crate::Term;
use arrayvec::ArrayVec;
use std::ops::{Index, IndexMut};

/// Work stack with an inline buffer that moves to one growing heap buffer.
///
/// Port of DECLARE_WSTACK / DECLARE_ESTACK in erts/emulator/beam/global.h
/// (WSTACK_PUSH, WSTACK_POP, WSTACK_COUNT, WSTACK_ROLLBACK, erl_grow_wstack),
/// and erts/emulator/beam/utils.c (erl_grow_wstack), OTP-29.1.1. The first
/// growth moves every inline entry into a buffer with twice the inline capacity,
/// matching erts' single active `start/sp/end` range.
#[derive(Clone, Debug)]
pub struct WStack<T, const N: usize> {
    storage: Storage<T, N>,
}

#[derive(Clone, Debug)]
enum Storage<T, const N: usize> {
    Inline(ArrayVec<T, N>),
    Heap(Vec<T>),
}

/// Stack of terms: the Rust form of ESTACK (a WSTACK whose words are `Eterm`s).
pub type EStack<const N: usize> = WStack<Term, N>;

impl<T, const N: usize> Default for WStack<T, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T, const N: usize> WStack<T, N> {
    /// An empty stack; allocates nothing.
    #[inline(always)]
    pub fn new() -> Self {
        Self {
            storage: Storage::Inline(ArrayVec::new()),
        }
    }

    /// Push a value (WSTACK_PUSH).
    #[inline(always)]
    pub fn push(&mut self, value: T) {
        let overflow = match &mut self.storage {
            Storage::Inline(inline) => inline.try_push(value).err().map(|full| full.element()),
            Storage::Heap(heap) => {
                heap.push(value);
                None
            }
        };
        if let Some(value) = overflow {
            self.grow(value);
        }
    }

    #[cold]
    #[inline(never)]
    fn grow(&mut self, value: T) {
        let old = std::mem::replace(&mut self.storage, Storage::Heap(Vec::new()));
        let Storage::Inline(inline) = old else {
            unreachable!("only inline storage can require its first growth")
        };
        let mut heap = Vec::with_capacity(N.saturating_mul(2));
        heap.extend(inline);
        heap.push(value);
        self.storage = Storage::Heap(heap);
    }

    /// Pop the top value (WSTACK_POP).
    #[inline(always)]
    pub fn pop(&mut self) -> Option<T> {
        // The enum branch selects the one active buffer, then its pop checks emptiness.
        match &mut self.storage {
            Storage::Inline(inline) => inline.pop(),
            Storage::Heap(heap) => heap.pop(),
        }
    }

    /// Number of entries (WSTACK_COUNT).
    #[inline(always)]
    pub fn len(&self) -> usize {
        match &self.storage {
            Storage::Inline(inline) => inline.len(),
            Storage::Heap(heap) => heap.len(),
        }
    }

    /// Whether the stack holds no entries (WSTACK_ISEMPTY).
    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        match &self.storage {
            Storage::Inline(inline) => inline.is_empty(),
            Storage::Heap(heap) => heap.is_empty(),
        }
    }

    /// Drop every entry, keeping the spill capacity.
    #[inline]
    pub fn clear(&mut self) {
        self.truncate(0);
    }

    /// Top entry without popping.
    #[inline(always)]
    pub fn last(&self) -> Option<&T> {
        match &self.storage {
            Storage::Inline(inline) => inline.last(),
            Storage::Heap(heap) => heap.last(),
        }
    }

    /// Mutable top entry.
    #[inline(always)]
    pub fn last_mut(&mut self) -> Option<&mut T> {
        match &mut self.storage {
            Storage::Inline(inline) => inline.last_mut(),
            Storage::Heap(heap) => heap.last_mut(),
        }
    }

    /// Entry `index` counted from the bottom.
    #[inline(always)]
    pub fn get(&self, index: usize) -> Option<&T> {
        match &self.storage {
            Storage::Inline(inline) => inline.get(index),
            Storage::Heap(heap) => heap.get(index),
        }
    }

    /// Mutable entry `index` counted from the bottom.
    #[inline(always)]
    pub fn get_mut(&mut self, index: usize) -> Option<&mut T> {
        match &mut self.storage {
            Storage::Inline(inline) => inline.get_mut(index),
            Storage::Heap(heap) => heap.get_mut(index),
        }
    }

    /// Entries from the bottom to the top.
    #[inline]
    pub fn iter(&self) -> impl DoubleEndedIterator<Item = &T> + '_ {
        let active = match &self.storage {
            Storage::Inline(inline) => inline.as_slice(),
            Storage::Heap(heap) => heap.as_slice(),
        };
        active.iter()
    }

    /// Roll back to `len` entries (WSTACK_ROLLBACK); spill capacity is retained.
    #[inline(always)]
    pub fn truncate(&mut self, len: usize) {
        match &mut self.storage {
            Storage::Inline(inline) => inline.truncate(len),
            Storage::Heap(heap) => heap.truncate(len),
        }
    }
}

impl<T, const N: usize> Index<usize> for WStack<T, N> {
    type Output = T;

    #[inline]
    fn index(&self, index: usize) -> &Self::Output {
        self.get(index).expect("stack index is in range")
    }
}

impl<T, const N: usize> IndexMut<usize> for WStack<T, N> {
    #[inline]
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        self.get_mut(index).expect("stack index is in range")
    }
}

impl<T, const N: usize> Extend<T> for WStack<T, N> {
    #[inline]
    fn extend<I: IntoIterator<Item = T>>(&mut self, items: I) {
        for item in items {
            self.push(item);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spills_and_unwinds_in_order() {
        let mut stack = WStack::<u64, 4>::new();
        for value in 0..20 {
            stack.push(value);
            assert_eq!(stack.len(), value as usize + 1);
        }
        assert_eq!(stack[3], 3);
        assert_eq!(stack[19], 19);
        assert_eq!(stack.last(), Some(&19));
        stack.truncate(6);
        assert_eq!(stack.len(), 6);
        stack.push(100);
        for expected in [100, 5, 4, 3, 2, 1, 0] {
            assert_eq!(stack.pop(), Some(expected));
        }
        assert!(stack.is_empty());
        assert_eq!(stack.pop(), None);
    }

    #[test]
    fn heap_storage_remains_active_after_it_drains() {
        let mut stack = WStack::<u8, 2>::new();
        for value in 0..5 {
            stack.push(value);
        }
        assert_eq!(stack.pop(), Some(4));
        assert_eq!(stack.pop(), Some(3));
        assert_eq!(stack.pop(), Some(2));
        stack.push(9);
        stack.push(8);
        assert_eq!(stack.pop(), Some(8));
        assert_eq!(stack.pop(), Some(9));
        assert_eq!(stack.pop(), Some(1));
    }

    #[test]
    fn grows_past_sixteen_and_thirty_two_entries() {
        let mut stack = WStack::<usize, 16>::new();
        stack.extend(0..33);
        assert_eq!(stack.len(), 33);
        assert_eq!(stack.get(16), Some(&16));
        assert_eq!(stack.get(32), Some(&32));
        assert!(matches!(stack.storage, Storage::Heap(_)));
        for expected in (0..33).rev() {
            assert_eq!(stack.pop(), Some(expected));
        }
        assert!(stack.is_empty());
    }

    #[test]
    fn truncate_crosses_inline_boundary_and_retains_active_buffer() {
        let mut stack = WStack::<usize, 16>::new();
        stack.extend(0..40);
        stack.truncate(12);
        assert_eq!(stack.len(), 12);
        assert_eq!(stack.last(), Some(&11));
        stack.push(99);
        assert_eq!(stack.pop(), Some(99));
        assert_eq!(stack.pop(), Some(11));
        assert!(matches!(stack.storage, Storage::Heap(_)));
    }
}
