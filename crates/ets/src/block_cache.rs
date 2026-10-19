//! Per-thread cache of the small word blocks that hold stored objects.
//!
//! erts allocates a stored object from `ets_alloc`, whose size-class free lists make a small
//! block cost a few dozen instructions. The system allocator here costs several hundred per
//! allocate-and-free pair, so freed object blocks are kept per size class and reused.

use std::cell::RefCell;

/// Largest block, in words, that is cached.
const MAX_CACHED_WORDS: usize = 32;
/// Blocks kept per size class on one thread.
const PER_CLASS_LIMIT: usize = 512;

thread_local! {
    static BLOCKS: RefCell<Vec<Vec<Box<[u64]>>>> =
        RefCell::new((0..=MAX_CACHED_WORDS).map(|_| Vec::new()).collect());
}

/// A zeroed block of `words` words.
pub(crate) fn take(words: usize) -> Box<[u64]> {
    if words <= MAX_CACHED_WORDS
        && let Some(mut block) = BLOCKS
            .try_with(|blocks| blocks.borrow_mut()[words].pop())
            .ok()
            .flatten()
    {
        block.fill(0);
        return block;
    }
    vec![0_u64; words].into_boxed_slice()
}

/// Keep a freed block for reuse by this thread.
pub(crate) fn give(block: Box<[u64]>) {
    let words = block.len();
    if words > MAX_CACHED_WORDS {
        return;
    }
    let _ = BLOCKS.try_with(|blocks| {
        let mut blocks = blocks.borrow_mut();
        if blocks[words].len() < PER_CLASS_LIMIT {
            blocks[words].push(block);
        }
    });
}
