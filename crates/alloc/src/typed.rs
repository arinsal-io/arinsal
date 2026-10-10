//! Typed ERTS allocations with pointer-stable ownership.

use crate::alloc_util::AllocError;
use crate::instances::{InstanceAllocation, ThreadSpecificAllocators};
use crate::raw::WordView;
use std::sync::OnceLock;

/// An ERTS allocation type name from `erl_alloc.types`.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ErtsAlcType(&'static str, u8);

impl ErtsAlcType {
    /// Process young heap (`ERTS_ALC_T_HEAP`).
    pub const HEAP: Self = Self("HEAP", 4);
    /// Process old heap (`ERTS_ALC_T_OLD_HEAP`).
    pub const OLD_HEAP: Self = Self("OLD_HEAP", 4);
    /// Heap fragments (`ERTS_ALC_T_HEAP_FRAG`).
    pub const HEAP_FRAG: Self = Self("HEAP_FRAG", 4);
    /// Reference counted binaries (`ERTS_ALC_T_BINARY`).
    pub const BINARY: Self = Self("BINARY", 8);
    /// ETS table descriptors (`ERTS_ALC_T_DB_TABLE`).
    pub const DB_TABLE: Self = Self("DB_TABLE", 5);
    /// ETS stored terms (`ERTS_ALC_T_DB_TERM`).
    pub const DB_TERM: Self = Self("DB_TERM", 5);
    /// ETS segments (`ERTS_ALC_T_DB_SEG`).
    pub const DB_SEG: Self = Self("DB_SEG", 5);
    /// ETS stacks (`ERTS_ALC_T_DB_STK`).
    pub const DB_STK: Self = Self("DB_STK", 5);
    /// Message queue references (`ERTS_ALC_T_MSG_REF`).
    pub const MSG_REF: Self = Self("MSG_REF", 6);
    /// Message payloads (`ERTS_ALC_T_MSG`).
    pub const MSG: Self = Self("MSG", 4);
    /// Port records (`ERTS_ALC_T_PORT`).
    pub const PORT: Self = Self("PORT", 9);
    /// Driver-owned allocations (`ERTS_ALC_T_DRV`).
    pub const DRV: Self = Self("DRV", 9);
    /// Driver instances (`ERTS_ALC_T_DRIVER`).
    pub const DRIVER: Self = Self("DRIVER", 9);
    /// Driver binary payloads (`ERTS_ALC_T_DRV_BINARY`).
    pub const DRV_BINARY: Self = Self("DRV_BINARY", 8);
    /// Loaded module entries (`ERTS_ALC_T_MODULE`).
    pub const MODULE: Self = Self("MODULE", 3);
    /// Atom entries (`ERTS_ALC_T_ATOM`).
    pub const ATOM: Self = Self("ATOM", 3);
    /// Atom text (`ERTS_ALC_T_ATOM_TXT`).
    pub const ATOM_TXT: Self = Self("ATOM_TXT", 3);
    /// Function entries (`ERTS_ALC_T_FUN_ENTRY`).
    pub const FUN_ENTRY: Self = Self("FUN_ENTRY", 3);

    /// Name generated from `erl_alloc.types`.
    pub const fn name(self) -> &'static str {
        self.0
    }

    /// Index of the allocator serving this type in `ALLOCATOR_NAMES`, mapped like erl_alloc.types.
    const fn allocator(self) -> usize {
        self.1 as usize
    }
}

/// One stable allocator payload, released through its owning typed instance.
pub struct AllocBlock {
    memory: WordView,
    allocation_type: ErtsAlcType,
    // None for zero-word blocks: erts never allocates an absent old heap or empty fragment.
    handle: Option<InstanceAllocation>,
    allocators: &'static ThreadSpecificAllocators,
}

impl AllocBlock {
    /// Allocates `words` from the allocator assigned to `allocation_type`.
    pub fn new(allocation_type: ErtsAlcType, words: usize) -> Result<Self, AllocError> {
        let allocators = allocator_for(allocation_type)?;
        let bytes = words
            .checked_mul(std::mem::size_of::<u64>())
            .ok_or(AllocError::OutOfBounds)?;
        let (handle, ptr) = if words == 0 {
            (None, std::ptr::NonNull::<u64>::dangling().as_ptr())
        } else {
            let (handle, ptr) = allocators.alloc_with_ptr(bytes)?;
            (Some(handle), ptr)
        };
        Ok(Self {
            memory: WordView::new(ptr, words),
            allocation_type,
            handle,
            allocators,
        })
    }

    /// Resizes the payload while preserving its prefix.
    pub fn realloc(&mut self, words: usize) -> Result<(), AllocError> {
        let bytes = words
            .checked_mul(std::mem::size_of::<u64>())
            .ok_or(AllocError::OutOfBounds)?;
        match (self.handle, words) {
            (Some(handle), 0) => {
                self.allocators.free(handle)?;
                self.handle = None;
                self.memory
                    .reset(std::ptr::NonNull::<u64>::dangling().as_ptr(), 0);
            }
            (Some(handle), _) => {
                let (handle, ptr) = self.allocators.realloc_with_ptr(handle, bytes)?;
                self.handle = Some(handle);
                self.memory.reset(ptr, words);
            }
            (None, 0) => {}
            (None, _) => {
                let (handle, ptr) = self.allocators.alloc_with_ptr(bytes)?;
                self.handle = Some(handle);
                self.memory.reset(ptr, words);
            }
        }
        Ok(())
    }

    /// Number of addressable words in this block.
    pub fn len(&self) -> usize {
        self.memory.len()
    }

    /// Whether the block has no addressable words.
    pub fn is_empty(&self) -> bool {
        self.memory.len() == 0
    }

    /// ERTS allocation type associated with this block.
    pub const fn allocation_type(&self) -> ErtsAlcType {
        self.allocation_type
    }

    /// Original allocator instance assigned when the block was created.
    pub fn instance(&self) -> usize {
        self.handle.map_or(0, InstanceAllocation::instance)
    }

    /// Returns a shared view of the allocated words.
    pub fn as_slice(&self) -> &[u64] {
        self.memory.as_slice()
    }

    /// Returns an exclusive view of the allocated words.
    pub fn as_mut_slice(&mut self) -> &mut [u64] {
        self.memory.as_mut_slice()
    }

    /// Returns the block address for existing pointer-based heap code.
    pub fn as_mut_ptr(&mut self) -> *mut u64 {
        self.memory.as_mut_ptr()
    }

    /// Returns the block address without granting mutable access to the owner.
    pub fn as_ptr(&self) -> *const u64 {
        self.memory.as_ptr()
    }

    /// Allocates `user_words` and returns the user pointer.
    ///
    /// The handle lives in a prefix of the same allocation, so the caller stores one
    /// pointer the way `ERTS_HEAP_ALLOC` stores `Eterm *heap` — no side descriptor.
    /// Port of erts/emulator/beam/erl_process.h:88 (`ERTS_HEAP_ALLOC`), OTP-29.1.1.
    pub fn detach_heap(
        allocation_type: ErtsAlcType,
        user_words: usize,
    ) -> Result<*mut u64, AllocError> {
        if user_words == 0 {
            return Ok(std::ptr::null_mut());
        }
        let total = user_words
            .checked_add(HEAP_PREFIX_WORDS)
            .ok_or(AllocError::OutOfBounds)?;
        let mut block = Self::new(allocation_type, total)?;
        let handle = block
            .handle
            .expect("a non-empty heap block has an allocator handle");
        let tag = heap_type_tag(allocation_type);
        {
            let slice = block.as_mut_slice();
            slice[0] = handle.instance() as u64;
            slice[1] = handle.allocation_id();
            slice[2] = user_words as u64;
            slice[3] = tag;
        }
        let user = block.as_ptr().wrapping_add(HEAP_PREFIX_WORDS) as *mut u64;
        // The prefix now owns the handle; dropping `block` would free the heap.
        std::mem::forget(block);
        Ok(user)
    }

    /// Frees a block produced by [`AllocBlock::detach_heap`].
    pub fn free_detached_heap(user: *mut u64) {
        if user.is_null() {
            return;
        }
        let Some(prefix) = heap_prefix(user) else {
            return;
        };
        let allocation_type = heap_type_from_tag(prefix.tag);
        let Ok(allocators) = allocator_for(allocation_type) else {
            return;
        };
        let handle = InstanceAllocation::from_parts(prefix.instance, prefix.id, prefix.bytes);
        let _ = allocators.free(handle);
    }

    /// `ERTS_HEAP_REALLOC`: resize, preserving the user prefix, and return the user pointer.
    /// Port of erts/emulator/beam/erl_process.h:91 (`ERTS_HEAP_REALLOC`), OTP-29.1.1.
    pub fn realloc_detached_heap(
        user: *mut u64,
        new_user_words: usize,
    ) -> Result<*mut u64, AllocError> {
        if user.is_null() {
            return Self::detach_heap(ErtsAlcType::HEAP, new_user_words);
        }
        if new_user_words == 0 {
            Self::free_detached_heap(user);
            return Ok(std::ptr::null_mut());
        }
        let prefix = heap_prefix(user).ok_or(AllocError::Corrupt)?;
        let allocation_type = heap_type_from_tag(prefix.tag);
        let allocators = allocator_for(allocation_type)?;
        let handle = InstanceAllocation::from_parts(prefix.instance, prefix.id, prefix.bytes);
        let new_bytes = new_user_words
            .checked_add(HEAP_PREFIX_WORDS)
            .and_then(|words| words.checked_mul(std::mem::size_of::<u64>()))
            .ok_or(AllocError::OutOfBounds)?;
        let (handle, base) = allocators.realloc_with_ptr(handle, new_bytes)?;
        let mut view = crate::raw::WordView::new(base, HEAP_PREFIX_WORDS);
        let slice = view.as_mut_slice();
        slice[0] = handle.instance() as u64;
        slice[1] = handle.allocation_id();
        slice[2] = new_user_words as u64;
        slice[3] = prefix.tag;
        Ok(base.wrapping_add(HEAP_PREFIX_WORDS))
    }

    /// Rebuilds an owned block for a detached user pointer. `as_ptr` is the user words;
    /// dropping the block frees the whole allocation, prefix included.
    pub fn reattach_heap(user: *mut u64) -> Result<Self, AllocError> {
        if user.is_null() {
            return Self::new(ErtsAlcType::OLD_HEAP, 0);
        }
        let prefix = heap_prefix(user).ok_or(AllocError::Corrupt)?;
        let allocation_type = heap_type_from_tag(prefix.tag);
        let allocators = allocator_for(allocation_type)?;
        Ok(Self {
            memory: crate::raw::WordView::new(user, prefix.user_words),
            allocation_type,
            handle: Some(InstanceAllocation::from_parts(
                prefix.instance,
                prefix.id,
                prefix.bytes,
            )),
            allocators,
        })
    }

    /// User words of a detached heap block. A null pointer is an empty block.
    pub fn heap_user_slice<'a>(user: *const u64) -> &'a [u64] {
        match heap_prefix(user) {
            Some(prefix) => crate::raw::words_at(user, prefix.user_words),
            None => &[],
        }
    }

    /// Exclusive user words of a detached heap block. A null pointer is an empty block.
    pub fn heap_user_slice_mut<'a>(user: *mut u64) -> &'a mut [u64] {
        match heap_prefix(user) {
            Some(prefix) => crate::raw::words_at_mut(user, prefix.user_words),
            None => &mut [],
        }
    }

    /// User-word count of a detached heap block.
    pub fn heap_user_len(user: *const u64) -> usize {
        heap_prefix(user).map_or(0, |prefix| prefix.user_words)
    }
}

/// Words stored ahead of the user payload so a heap block is one pointer.
const HEAP_PREFIX_WORDS: usize = 4;

struct HeapPrefix {
    instance: usize,
    id: u64,
    user_words: usize,
    tag: u64,
    bytes: usize,
}

fn heap_prefix(user: *const u64) -> Option<HeapPrefix> {
    if user.is_null() {
        return None;
    }
    let base = user.wrapping_sub(HEAP_PREFIX_WORDS);
    let words = crate::raw::words_at(base, HEAP_PREFIX_WORDS);
    let user_words = words[2] as usize;
    let bytes = user_words
        .checked_add(HEAP_PREFIX_WORDS)?
        .checked_mul(std::mem::size_of::<u64>())?;
    Some(HeapPrefix {
        instance: words[0] as usize,
        id: words[1],
        user_words,
        tag: words[3],
        bytes,
    })
}

fn heap_type_tag(allocation_type: ErtsAlcType) -> u64 {
    if allocation_type == ErtsAlcType::HEAP {
        1
    } else if allocation_type == ErtsAlcType::OLD_HEAP {
        2
    } else if allocation_type == ErtsAlcType::HEAP_FRAG {
        3
    } else {
        0
    }
}

fn heap_type_from_tag(tag: u64) -> ErtsAlcType {
    match tag {
        2 => ErtsAlcType::OLD_HEAP,
        3 => ErtsAlcType::HEAP_FRAG,
        _ => ErtsAlcType::HEAP,
    }
}

impl Drop for AllocBlock {
    fn drop(&mut self) {
        if let Some(handle) = self.handle {
            let _ = self.allocators.free(handle);
        }
    }
}

/// Allocators indexed by `ErtsAlcType::allocator`.
const ALLOCATOR_NAMES: [&str; 10] = [
    "temp_alloc",
    "sl_alloc",
    "std_alloc",
    "ll_alloc",
    "eheap_alloc",
    "ets_alloc",
    "fix_alloc",
    "literal_alloc",
    "binary_alloc",
    "driver_alloc",
];

#[inline]
fn allocator_for(
    allocation_type: ErtsAlcType,
) -> Result<&'static ThreadSpecificAllocators, AllocError> {
    static ALLOCATORS: OnceLock<Vec<Option<ThreadSpecificAllocators>>> = OnceLock::new();
    let registry = ALLOCATORS.get_or_init(|| {
        let schedulers = std::thread::available_parallelism().map_or(1, usize::from);
        let mut registry: Vec<Option<ThreadSpecificAllocators>> =
            ALLOCATOR_NAMES.iter().map(|_| None).collect();
        for spec in crate::allocator::defaults(schedulers) {
            let Some(index) = ALLOCATOR_NAMES.iter().position(|name| *name == spec.name) else {
                continue;
            };
            let count = crate::allocator::instance_count(&spec, schedulers, 0);
            registry[index] = Some(ThreadSpecificAllocators::new_for_type(
                count,
                spec.thread_specific,
                spec.strategy,
                spec.options,
                spec.name,
            ));
        }
        registry
    });
    registry
        .get(allocation_type.allocator())
        .and_then(Option::as_ref)
        .ok_or(AllocError::InvalidAllocation)
}

#[cfg(test)]
mod tests {
    use super::{AllocBlock, ErtsAlcType};

    #[test]
    fn typed_block_views_survive_reallocation() {
        let mut block = AllocBlock::new(ErtsAlcType::HEAP, 8).unwrap();
        assert_eq!(block.as_mut_ptr() as usize % std::mem::align_of::<u64>(), 0);
        block
            .as_mut_slice()
            .copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        block.realloc(1024).unwrap();
        assert_eq!(&block.as_slice()[..8], &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(block.allocation_type(), ErtsAlcType::HEAP);
        assert_eq!(block.len(), 1024);
    }

    #[test]
    fn typed_block_can_be_dropped_on_another_thread() {
        let block = AllocBlock::new(ErtsAlcType::HEAP_FRAG, 8).unwrap();
        std::thread::spawn(move || drop(block)).join().unwrap();
    }
}
