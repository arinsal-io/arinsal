//! Explicit work stacks for iterative term walkers.
//!
//! Port of DECLARE_WSTACK / DECLARE_ESTACK in erts/emulator/beam/global.h and
//! erl_grow_estack / erl_grow_wstack in erts/emulator/beam/utils.c, OTP-29.1.1. The stack and
//! its memory live in [`crate::raw::estack`]; this module adds the safe conveniences.
use crate::Term;
use std::ops::{Index, IndexMut};

pub use crate::raw::estack::WStack;

/// Stack of terms: the Rust form of ESTACK (a WSTACK whose words are `Eterm`s).
pub type EStack<const N: usize> = WStack<Term, N>;

impl<T, const N: usize> WStack<T, N> {
    /// Drop every entry, keeping a grown array.
    #[inline]
    pub fn clear(&mut self) {
        self.truncate(0);
    }

    /// Top entry without popping.
    #[inline(always)]
    pub fn last(&self) -> Option<&T> {
        self.as_slice().last()
    }

    /// Mutable top entry.
    #[inline(always)]
    pub fn last_mut(&mut self) -> Option<&mut T> {
        self.as_mut_slice().last_mut()
    }

    /// Entry `index` counted from the bottom.
    #[inline(always)]
    pub fn get(&self, index: usize) -> Option<&T> {
        self.as_slice().get(index)
    }

    /// Mutable entry `index` counted from the bottom.
    #[inline(always)]
    pub fn get_mut(&mut self, index: usize) -> Option<&mut T> {
        self.as_mut_slice().get_mut(index)
    }

    /// Entries from the bottom to the top.
    #[inline]
    pub fn iter(&self) -> impl DoubleEndedIterator<Item = &T> + '_ {
        self.as_slice().iter()
    }
}

impl<T: Clone, const N: usize> Clone for WStack<T, N> {
    fn clone(&self) -> Self {
        let mut copy = Self::new();
        copy.extend(self.iter().cloned());
        copy
    }
}

impl<T: std::fmt::Debug, const N: usize> std::fmt::Debug for WStack<T, N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list().entries(self.iter()).finish()
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
    }
}
