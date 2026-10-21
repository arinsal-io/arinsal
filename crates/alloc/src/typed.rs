//! Typed ERTS allocations with pointer-stable ownership.

use crate::alloc_util::AllocError;
use crate::instances::{InstanceAllocation, ThreadSpecificAllocators};
use crate::raw::WordView;
use std::sync::OnceLock;
use std::sync::atomic::Ordering;

/// An ERTS allocation type name from `erl_alloc.types`.
///
/// One byte indexing the name and allocator tables below, like the `ERTS_ALC_T_*` numbers of erts,
/// so a block that records its type stays one word.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct ErtsAlcType(u8);

impl std::fmt::Debug for ErtsAlcType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("ErtsAlcType").field(&self.name()).finish()
    }
}

/// Name and serving allocator (index in `ALLOCATOR_NAMES`, mapped like erl_alloc.types) of each
/// type, indexed by the type number.
const ALC_TYPES: [(&str, u8); 20] = [
    ("HEAP", 4),
    ("OLD_HEAP", 4),
    ("HEAP_FRAG", 4),
    ("BINARY", 8),
    ("DB_TABLE", 5),
    ("DB_TERM", 5),
    ("DB_SEG", 5),
    ("DB_STK", 5),
    ("MSG_REF", 6),
    ("MSG", 4),
    ("PORT", 9),
    ("DRV", 9),
    ("DRIVER", 9),
    ("DRV_BINARY", 8),
    ("MODULE", 3),
    ("ATOM", 3),
    ("ATOM_TXT", 3),
    ("FUN_ENTRY", 3),
    ("TMP", 0),
    ("PROC", 6),
];

impl ErtsAlcType {
    /// Process young heap (`ERTS_ALC_T_HEAP`).
    pub const HEAP: Self = Self(0);
    /// Process old heap (`ERTS_ALC_T_OLD_HEAP`).
    pub const OLD_HEAP: Self = Self(1);
    /// Heap fragments (`ERTS_ALC_T_HEAP_FRAG`).
    pub const HEAP_FRAG: Self = Self(2);
    /// Reference counted binaries (`ERTS_ALC_T_BINARY`).
    pub const BINARY: Self = Self(3);
    /// ETS table descriptors (`ERTS_ALC_T_DB_TABLE`).
    pub const DB_TABLE: Self = Self(4);
    /// ETS stored terms (`ERTS_ALC_T_DB_TERM`).
    pub const DB_TERM: Self = Self(5);
    /// ETS segments (`ERTS_ALC_T_DB_SEG`).
    pub const DB_SEG: Self = Self(6);
    /// ETS stacks (`ERTS_ALC_T_DB_STK`).
    pub const DB_STK: Self = Self(7);
    /// Message queue references (`ERTS_ALC_T_MSG_REF`).
    pub const MSG_REF: Self = Self(8);
    /// Message payloads (`ERTS_ALC_T_MSG`).
    pub const MSG: Self = Self(9);
    /// Port records (`ERTS_ALC_T_PORT`).
    pub const PORT: Self = Self(10);
    /// Driver-owned allocations (`ERTS_ALC_T_DRV`).
    pub const DRV: Self = Self(11);
    /// Driver instances (`ERTS_ALC_T_DRIVER`).
    pub const DRIVER: Self = Self(12);
    /// Driver binary payloads (`ERTS_ALC_T_DRV_BINARY`).
    pub const DRV_BINARY: Self = Self(13);
    /// Loaded module entries (`ERTS_ALC_T_MODULE`).
    pub const MODULE: Self = Self(14);
    /// Atom entries (`ERTS_ALC_T_ATOM`).
    pub const ATOM: Self = Self(15);
    /// Atom text (`ERTS_ALC_T_ATOM_TXT`).
    pub const ATOM_TXT: Self = Self(16);
    /// Function entries (`ERTS_ALC_T_FUN_ENTRY`).
    pub const FUN_ENTRY: Self = Self(17);
    /// Short-lived scratch (`ERTS_ALC_T_TMP`), the temporary allocator.
    pub const TMP: Self = Self(18);
    /// Process structures (`ERTS_ALC_T_PROC`), a fixed-size type of fix_alloc.
    pub const PROC: Self = Self(19);

    /// Name generated from `erl_alloc.types`.
    pub const fn name(self) -> &'static str {
        ALC_TYPES[self.0 as usize].0
    }

    /// Index of this type among the fixed-size types (`ERTS_ALC_FIX_TYPE_IX`), `None` for a type
    /// of another class.
    const fn fix_index(self) -> Option<usize> {
        match self.0 {
            19 => Some(0),
            _ => None,
        }
    }

    /// Index of the allocator serving this type in `ALLOCATOR_NAMES`, mapped like erl_alloc.types.
    const fn allocator(self) -> usize {
        ALC_TYPES[self.0 as usize].1 as usize
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

/// One erts `Binary` allocation with its allocator handle stored in a private prefix.
/// Cloning adjusts the binary header's reference count; no Rust control block is allocated.
pub struct BinaryBlock {
    memory: WordView,
    allocators: &'static ThreadSpecificAllocators,
    owned: bool,
}

impl BinaryBlock {
    const PREFIX_WORDS: usize = 4;
    const HEADER_WORDS: usize = 4;

    /// Allocate one binary header and byte payload from the `BINARY` allocator.
    pub fn new(size: usize, flags: u64, apparent_size: usize) -> Result<Self, AllocError> {
        let payload_words = size.div_ceil(std::mem::size_of::<u64>());
        let words = Self::PREFIX_WORDS
            .checked_add(Self::HEADER_WORDS)
            .and_then(|header| header.checked_add(payload_words))
            .ok_or(AllocError::OutOfBounds)?;
        let bytes = words
            .checked_mul(std::mem::size_of::<u64>())
            .ok_or(AllocError::OutOfBounds)?;
        let mut allocation = AllocBlock::new(ErtsAlcType::BINARY, words)?;
        let handle = allocation.handle.ok_or(AllocError::InvalidAllocation)?;
        let memory = &mut allocation.memory;
        for (index, value) in [
            handle.instance() as u64,
            handle.allocation_id(),
            bytes as u64,
            words as u64,
        ]
        .into_iter()
        .enumerate()
        {
            memory.write_word(index, value);
        }
        for (index, value) in [flags, apparent_size as u64, 1, size as u64]
            .into_iter()
            .enumerate()
        {
            memory.write_word(Self::PREFIX_WORDS + index, value);
        }
        let allocators = allocation.allocators;
        let memory = WordView::new(allocation.memory.as_mut_ptr(), allocation.memory.len());
        allocation.handle = None;
        Ok(Self {
            memory,
            allocators,
            owned: true,
        })
    }

    /// Create one owning handle for a live binary view.
    pub fn clone_from_view(view: crate::raw::BinaryView<'_>) -> Result<Self, AllocError> {
        let allocators = allocator_for(ErtsAlcType::BINARY)?;
        let previous = view
            .fetch_add(2, 1, Ordering::Relaxed)
            .ok_or(AllocError::Corrupt)?;
        if previous == 0 || previous == u64::MAX {
            view.fetch_sub(2, 1, Ordering::Relaxed);
            return Err(AllocError::Corrupt);
        }
        let header = view.header_ptr().wrapping_sub(Self::PREFIX_WORDS);
        let words = Self::PREFIX_WORDS
            .checked_add(view.allocation_words())
            .ok_or(AllocError::OutOfBounds)?;
        // The source view is bounded by a live Binary allocation.
        let memory = WordView::new(header.cast_mut(), words);
        Ok(Self {
            memory,
            allocators,
            owned: true,
        })
    }

    /// Borrow a live binary through its header without changing the erts refcount.
    pub fn borrow_from_view(view: crate::raw::BinaryView<'_>) -> Result<Self, AllocError> {
        let allocators = allocator_for(ErtsAlcType::BINARY)?;
        let words = Self::PREFIX_WORDS
            .checked_add(view.allocation_words())
            .ok_or(AllocError::OutOfBounds)?;
        let header = view.header_ptr().wrapping_sub(Self::PREFIX_WORDS);
        Ok(Self {
            memory: WordView::new(header.cast_mut(), words),
            allocators,
            owned: false,
        })
    }

    /// Release one Binary reference after its BinRef is swept.
    pub fn release_view(view: crate::raw::BinaryView<'_>) -> Result<(), AllocError> {
        let mut handle = Self::borrow_from_view(view)?;
        handle.owned = true;
        drop(handle);
        Ok(())
    }

    /// Transfer this reference to a heap BinRef without decrementing its refcount.
    pub fn into_raw(mut self) -> *const u64 {
        self.owned = false;
        self.header_ptr()
    }

    /// Relinquish this handle to the owning BinRef and return its Binary header.
    pub fn disarm(&mut self) -> *const u64 {
        self.owned = false;
        self.header_ptr()
    }

    /// A shared view of the binary payload.
    pub fn bytes(&self) -> &[u8] {
        let size = self
            .memory
            .atomic_load(Self::PREFIX_WORDS + 3, Ordering::Relaxed)
            .unwrap() as usize;
        let begin = (Self::PREFIX_WORDS + Self::HEADER_WORDS) * std::mem::size_of::<u64>();
        &self.memory.bytes()[begin..begin + size]
    }

    /// Address of the four-word binary header.
    pub fn as_ptr(&self) -> *const u64 {
        self.header_ptr()
    }

    /// Mutable address of the four-word binary header.
    pub fn as_mut_ptr(&mut self) -> *mut u64 {
        self.memory.as_mut_ptr().wrapping_add(Self::PREFIX_WORDS)
    }

    /// Header words followed by the payload capacity.
    pub fn as_slice(&self) -> &[u64] {
        &self.memory.as_slice()[Self::PREFIX_WORDS..]
    }

    /// Mutably borrow header words and payload capacity.
    pub fn as_mut_slice(&mut self) -> &mut [u64] {
        &mut self.memory.as_mut_slice()[Self::PREFIX_WORDS..]
    }

    /// Borrow the erts header and payload view.
    pub fn view(&self) -> crate::raw::BinaryView<'_> {
        self.memory
            .binary_view_at(Self::PREFIX_WORDS)
            .expect("binary allocation includes its header")
    }

    /// Transfer this Binary reference from the allocator handle to its BinRef.
    pub fn into_reference(mut self) -> crate::raw::OwnedBinaryRef {
        let owner = crate::raw::OwnedBinaryRef::from_owned_view(self.view());
        self.owned = false;
        owner
    }

    /// A shared view of the reserved payload capacity.
    pub fn capacity_bytes(&self) -> &[u8] {
        let size = self
            .memory
            .atomic_load(Self::PREFIX_WORDS + 3, Ordering::Relaxed)
            .unwrap() as usize;
        let begin = (Self::PREFIX_WORDS + Self::HEADER_WORDS) * std::mem::size_of::<u64>();
        &self.memory.bytes()[begin..begin + size]
    }

    /// Exclusive payload view when this is the sole owning reference.
    pub fn bytes_mut_unique(&mut self) -> Option<&mut [u8]> {
        if self.reference_count() != 1 {
            return None;
        }
        let size = self
            .memory
            .atomic_load(Self::PREFIX_WORDS + 3, Ordering::Relaxed)? as usize;
        let begin = (Self::PREFIX_WORDS + Self::HEADER_WORDS) * std::mem::size_of::<u64>();
        Some(&mut self.memory.bytes_mut()[begin..begin + size])
    }

    /// Current payload size recorded in the binary header.
    pub fn size(&self) -> usize {
        self.memory
            .atomic_load(Self::PREFIX_WORDS + 3, Ordering::Relaxed)
            .unwrap() as usize
    }

    /// ERTS apparent size recorded in the binary header.
    pub fn apparent_size(&self) -> usize {
        self.memory
            .atomic_load(Self::PREFIX_WORDS + 1, Ordering::Relaxed)
            .unwrap() as usize
    }

    /// Set the ERTS apparent size in bytes.
    pub fn set_apparent_size(&self, size: usize) {
        self.memory
            .atomic_store(Self::PREFIX_WORDS + 1, size as u64, Ordering::Relaxed);
    }

    /// Binary flag word.
    pub fn flags(&self) -> u64 {
        self.memory
            .atomic_load(Self::PREFIX_WORDS, Ordering::Relaxed)
            .unwrap()
    }

    /// Replace the binary flag word.
    pub fn set_flags(&self, flags: u64) {
        self.memory
            .atomic_store(Self::PREFIX_WORDS, flags, Ordering::Relaxed);
    }

    /// Atomically set binary flags.
    pub fn set_flag_bits(&self, flags: u64) {
        self.memory
            .atomic_fetch_or(Self::PREFIX_WORDS, flags, Ordering::Relaxed);
    }

    /// Atomically clear binary flags.
    pub fn clear_flag_bits(&self, flags: u64) {
        self.memory
            .atomic_fetch_and(Self::PREFIX_WORDS, !flags, Ordering::Relaxed);
    }

    /// Refcount stored in the binary header.
    pub fn reference_count(&self) -> u64 {
        self.memory
            .atomic_load(Self::PREFIX_WORDS + 2, Ordering::Relaxed)
            .unwrap()
    }

    /// Address of the erts `Binary` header.
    pub fn header_ptr(&self) -> *const u64 {
        self.memory.as_ptr().wrapping_add(Self::PREFIX_WORDS)
    }

    /// Resize the single allocation while this is its unique owner.
    pub fn realloc(&mut self, size: usize) -> Result<(), AllocError> {
        if self.reference_count() != 1 {
            return Err(AllocError::Corrupt);
        }
        let words = Self::PREFIX_WORDS
            .checked_add(Self::HEADER_WORDS)
            .and_then(|header| header.checked_add(size.div_ceil(std::mem::size_of::<u64>())))
            .ok_or(AllocError::OutOfBounds)?;
        let bytes = words
            .checked_mul(std::mem::size_of::<u64>())
            .ok_or(AllocError::OutOfBounds)?;
        let old = InstanceAllocation::from_parts(
            self.memory.read_word(0).ok_or(AllocError::Corrupt)? as usize,
            self.memory.read_word(1).ok_or(AllocError::Corrupt)?,
            self.memory.read_word(2).ok_or(AllocError::Corrupt)? as usize,
        );
        let (handle, ptr) = self.allocators.realloc_with_ptr(old, bytes)?;
        self.memory.reset(ptr, words);
        self.memory.write_word(0, handle.instance() as u64);
        self.memory.write_word(1, handle.allocation_id());
        self.memory.write_word(2, bytes as u64);
        self.memory.write_word(3, words as u64);
        self.memory
            .atomic_store(Self::PREFIX_WORDS + 3, size as u64, Ordering::Relaxed);
        Ok(())
    }
}

impl Clone for BinaryBlock {
    fn clone(&self) -> Self {
        let old = self
            .memory
            .atomic_fetch_add(Self::PREFIX_WORDS + 2, 1, Ordering::Relaxed)
            .expect("live binary refcount header");
        assert!(old > 0 && old < u64::MAX, "binary refcount overflow");
        Self {
            memory: WordView::new(self.memory.as_ptr().cast_mut(), self.memory.len()),
            allocators: self.allocators,
            owned: true,
        }
    }
}

impl Drop for BinaryBlock {
    fn drop(&mut self) {
        if !self.owned {
            return;
        }
        let Some(previous) =
            self.memory
                .atomic_fetch_sub(Self::PREFIX_WORDS + 2, 1, Ordering::Relaxed)
        else {
            return;
        };
        if previous != 1 {
            return;
        }
        let handle = InstanceAllocation::from_parts(
            self.memory.read_word(0).unwrap() as usize,
            self.memory.read_word(1).unwrap(),
            self.memory.read_word(2).unwrap() as usize,
        );
        let _ = self.allocators.free(handle);
    }
}

impl AllocBlock {
    /// Allocates `words` from the allocator assigned to `allocation_type`.
    pub fn new(allocation_type: ErtsAlcType, words: usize) -> Result<Self, AllocError> {
        Self::new_at(crate::instances::thread_alloc_ix(), allocation_type, words)
    }

    /// [`AllocBlock::new`] for a scheduler that knows its allocator index
    /// ([`crate::instances::thread_alloc_ix`]) and hands it down instead of reading it from
    /// thread-local storage; `ix` must belong to the calling thread.
    pub fn new_at(
        ix: usize,
        allocation_type: ErtsAlcType,
        words: usize,
    ) -> Result<Self, AllocError> {
        let allocators = allocator_for(allocation_type)?;
        let bytes = words
            .checked_mul(std::mem::size_of::<u64>())
            .ok_or(AllocError::OutOfBounds)?;
        let (handle, ptr) = if words == 0 {
            (None, std::ptr::NonNull::<u64>::dangling().as_ptr())
        } else {
            let (handle, ptr) = allocators.alloc_with_ptr_at(ix, bytes)?;
            (Some(handle), ptr)
        };
        Ok(Self {
            memory: WordView::new(ptr, words),
            allocation_type,
            handle,
            allocators,
        })
    }

    /// Frees the block through the allocator index `ix` of the calling thread, without reading it
    /// from thread-local storage.
    pub fn release_at(mut self, ix: usize) {
        self.release_in_place_at(ix);
    }

    /// [`AllocBlock::release_at`] for a block that stays in its container: the payload is gone
    /// afterwards and the later drop frees nothing.
    #[inline]
    pub fn release_in_place_at(&mut self, ix: usize) {
        if let Some(handle) = self.handle.take() {
            let _ = self.allocators.free_at(ix, handle);
        }
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
        Self::detach_heap_at(
            crate::instances::thread_alloc_ix(),
            allocation_type,
            user_words,
        )
    }

    /// [`AllocBlock::detach_heap`] on the allocator index `ix` of the calling thread.
    pub fn detach_heap_at(
        ix: usize,
        allocation_type: ErtsAlcType,
        user_words: usize,
    ) -> Result<*mut u64, AllocError> {
        if user_words == 0 {
            return Ok(std::ptr::null_mut());
        }
        let total = user_words
            .checked_add(HEAP_PREFIX_WORDS)
            .ok_or(AllocError::OutOfBounds)?;
        let mut block = Self::new_at(ix, allocation_type, total)?;
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
        Self::free_detached_heap_at(crate::instances::thread_alloc_ix(), user);
    }

    /// [`AllocBlock::free_detached_heap`] on the allocator index `ix` of the calling thread.
    pub fn free_detached_heap_at(ix: usize, user: *mut u64) {
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
        let _ = allocators.free_at(ix, handle);
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
    } else if allocation_type == ErtsAlcType::DB_TERM {
        4
    } else {
        0
    }
}

fn heap_type_from_tag(tag: u64) -> ErtsAlcType {
    match tag {
        2 => ErtsAlcType::OLD_HEAP,
        3 => ErtsAlcType::HEAP_FRAG,
        4 => ErtsAlcType::DB_TERM,
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

/// The configured scheduler and dirty allocator instance counts.
#[derive(Clone, Copy)]
struct InstanceConfig {
    schedulers: usize,
    dirty_instances: usize,
}

static CONFIG: OnceLock<InstanceConfig> = OnceLock::new();

/// The instance configuration was already fixed, by `configure` or by the first allocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AlreadyConfigured;

/// Fixes how many scheduler and dirty allocator instances every thread specific allocator has.
///
/// Port of the instance sizing in `erts_alloc_init` (erl_alloc.c), OTP-29.1.1: `schedulers` is the
/// configured `+S` total and `dirty_instances` the `+Mdai` count. Must run before the first
/// allocation; afterwards the counts are fixed and the call fails. Without a call the first
/// allocation sizes the instances from the available parallelism and no dirty instances.
pub fn configure(schedulers: usize, dirty_instances: usize) -> Result<(), AlreadyConfigured> {
    CONFIG
        .set(InstanceConfig {
            schedulers: schedulers.max(1),
            dirty_instances,
        })
        .map_err(|_| AlreadyConfigured)
}

/// Scheduler and dirty instance counts, if `configure` ran or the allocators exist.
pub(crate) fn configured() -> Option<(usize, usize)> {
    CONFIG
        .get()
        .map(|config| (config.schedulers, config.dirty_instances))
}

/// Number of instances of the allocator `name`, `None` for an unknown or absent allocator.
pub fn instance_count(name: &str) -> Option<usize> {
    let index = ALLOCATOR_NAMES.iter().position(|known| *known == name)?;
    registry()
        .get(index)
        .and_then(Option::as_ref)
        .map(ThreadSpecificAllocators::instance_count)
}

fn registry() -> &'static Vec<Option<ThreadSpecificAllocators>> {
    static ALLOCATORS: OnceLock<Vec<Option<ThreadSpecificAllocators>>> = OnceLock::new();
    ALLOCATORS.get_or_init(|| {
        let config = *CONFIG.get_or_init(|| InstanceConfig {
            schedulers: crate::cpuinfo::default_schedulers().0,
            dirty_instances: 0,
        });
        let schedulers = config.schedulers;
        let mut registry: Vec<Option<ThreadSpecificAllocators>> =
            ALLOCATOR_NAMES.iter().map(|_| None).collect();
        for spec in crate::allocator::defaults(schedulers) {
            let Some(index) = ALLOCATOR_NAMES.iter().position(|name| *name == spec.name) else {
                continue;
            };
            let count = crate::allocator::instance_count(&spec, schedulers, config.dirty_instances);
            registry[index] = Some(ThreadSpecificAllocators::new_with_global(
                count,
                spec.thread_specific,
                spec.strategy,
                spec.global_strategy,
                spec.options,
                spec.name,
            ));
        }
        registry
    })
}

/// `system_flag(erts_alloc, {Allocator, sbct, Value})` for the alloc_util allocator `name`;
/// `None` when no such allocator exists.
pub fn try_set_dyn_sbct(name: &str, value: usize) -> Option<bool> {
    let index = ALLOCATOR_NAMES.iter().position(|known| *known == name)?;
    registry()
        .get(index)
        .and_then(Option::as_ref)
        .map(|allocators| allocators.try_set_dyn_sbct(value))
}

#[inline]
fn allocator_for(
    allocation_type: ErtsAlcType,
) -> Result<&'static ThreadSpecificAllocators, AllocError> {
    registry()
        .get(allocation_type.allocator())
        .and_then(Option::as_ref)
        .ok_or(AllocError::InvalidAllocation)
}

/// Allocates one block of the fixed-size type `allocation_type` (`bytes` long, the same on every
/// call) on the instance of the calling thread, whose allocator index is `ix`; returns the handle
/// that frees it and the payload address.
///
/// Port of erts/emulator/beam/erl_alloc.h (erts_alloc of a FIXED_SIZE type, served by fix_alloc
/// through fix_cpool_alloc), OTP-29.1.1.
pub fn fix_alloc_at(
    ix: usize,
    allocation_type: ErtsAlcType,
    bytes: usize,
) -> Result<(InstanceAllocation, *mut u64), AllocError> {
    let fix_ix = allocation_type
        .fix_index()
        .ok_or(AllocError::InvalidAllocation)?;
    allocator_for(allocation_type)?.fix_alloc_with_ptr_at(ix, fix_ix, bytes)
}

/// Frees a block from [`fix_alloc_at`] from the thread with allocator index `ix`.
///
/// Port of erts/emulator/beam/erl_alloc.h (erts_free of a FIXED_SIZE type), OTP-29.1.1.
pub fn fix_free_at(
    ix: usize,
    allocation_type: ErtsAlcType,
    handle: InstanceAllocation,
) -> Result<(), AllocError> {
    let fix_ix = allocation_type
        .fix_index()
        .ok_or(AllocError::InvalidAllocation)?;
    allocator_for(allocation_type)?.fix_free_at(ix, fix_ix, handle)
}

/// Blocks of the fixed-size type `allocation_type` in use and allocated on `instance`.
pub fn fix_info(allocation_type: ErtsAlcType, instance: usize) -> Option<(usize, usize)> {
    let fix_ix = allocation_type.fix_index()?;
    Some(
        allocator_for(allocation_type)
            .ok()?
            .fix_info(instance, fix_ix),
    )
}

fn for_each_allocator(mut visit: impl FnMut(&ThreadSpecificAllocators)) {
    for allocators in registry().iter().flatten() {
        visit(allocators);
    }
}

/// Bytes in front of a `driver_alloc` payload: the owning instance, which erts reads from the
/// carrier header (`BLK_TO_MBC(blk)->allctr`) and which a block here does not carry.
const DRV_PREFIX_BYTES: usize = 8;
/// Distance from a block's allocation id (its address) to its payload (`BLOCK_HEADER`).
const DRV_BLOCK_HEADER: usize = 16;

fn driver_handle(user: *mut u8) -> InstanceAllocation {
    let base = user.wrapping_sub(DRV_PREFIX_BYTES).cast::<u64>();
    let instance = crate::raw::words_at(base, 1)[0] as usize;
    let id = base as usize - DRV_BLOCK_HEADER;
    InstanceAllocation::from_parts(instance, id as u64, 0)
}

fn driver_publish(handle: InstanceAllocation, base: *mut u64) -> *mut u8 {
    crate::raw::words_at_mut(base, 1)[0] = handle.instance() as u64;
    base.cast::<u8>().wrapping_add(DRV_PREFIX_BYTES)
}

/// `erts_alloc(ERTS_ALC_T_DRV, bytes)`, which `driver_alloc` and `enif_alloc` (ERTS_ALC_T_NIF,
/// also the driver allocator) both use. Null when the request cannot be served.
// Port of erts/emulator/beam/io.c (driver_alloc) and erl_nif.c (enif_alloc), OTP-29.1.1.
pub fn driver_alloc(bytes: usize) -> *mut u8 {
    let Some(total) = bytes.checked_add(DRV_PREFIX_BYTES) else {
        return std::ptr::null_mut();
    };
    let Ok(allocators) = allocator_for(ErtsAlcType::DRV) else {
        return std::ptr::null_mut();
    };
    match allocators.alloc_with_ptr_at(crate::instances::thread_alloc_ix(), total) {
        Ok((handle, base)) => driver_publish(handle, base),
        Err(_) => std::ptr::null_mut(),
    }
}

/// `erts_realloc` of a block from [`driver_alloc`]; a null `ptr` allocates.
pub fn driver_realloc(ptr: *mut u8, bytes: usize) -> *mut u8 {
    if ptr.is_null() {
        return driver_alloc(bytes);
    }
    let Some(total) = bytes.checked_add(DRV_PREFIX_BYTES) else {
        return std::ptr::null_mut();
    };
    let Ok(allocators) = allocator_for(ErtsAlcType::DRV) else {
        return std::ptr::null_mut();
    };
    match allocators.realloc_with_ptr(driver_handle(ptr), total) {
        Ok((handle, base)) => driver_publish(handle, base),
        Err(_) => std::ptr::null_mut(),
    }
}

/// `erts_free` of a block from [`driver_alloc`]; null is ignored.
pub fn driver_free(ptr: *mut u8) {
    if ptr.is_null() {
        return;
    }
    if let Ok(allocators) = allocator_for(ErtsAlcType::DRV) {
        let _ = allocators.free_at(crate::instances::thread_alloc_ix(), driver_handle(ptr));
    }
}

/// Apply the queued cross-thread frees of the instances no scheduler owns.
///
/// Port of `handle_delayed_dealloc` (erl_process.c) and
/// erl_alloc.c (`erts_alloc_handle_delayed_dealloc`), OTP-29.1.1, for instance 0 and the dirty
/// instances, whose frees the aux and dirty threads handle. Scheduler instances drain on their
/// owners through [`drain_owned_deallocations`]. A literal area released on the collector thread
/// queues its refc binaries on the allocating scheduler; `wait, deallocations` does not return
/// until those frees land.
pub fn drain_shared_deallocations() -> usize {
    let mut total = 0;
    for_each_allocator(|allocators| {
        total += allocators.drain_shared_deallocations().unwrap_or(0);
    });
    total
}

/// Apply the queued cross-thread frees of scheduler instance `instance`, on its owner.
///
/// Port of the `ERTS_SSI_AUX_WORK_DD` aux-work handler (erl_process.c, `handle_delayed_dealloc`),
/// OTP-29.1.1. The owning scheduler calls this from its aux work; any other thread waits for it.
pub fn drain_owned_deallocations(instance: usize) -> usize {
    let mut total = 0;
    for_each_allocator(|allocators| {
        if instance < allocators.instance_count() {
            total += allocators.drain_deallocations(instance).unwrap_or(0);
        }
    });
    total
}

/// Runs the owner work of scheduler instance `instance` for every allocator: queued requests and
/// a bounded number of delayed frees. True while any allocator still has frees queued.
///
/// Port of `erts_alloc_handle_delayed_dealloc`, OTP-29.1.1, as run by the owner's aux work after
/// [`notify_owner`](crate::notify_owner).
pub fn handle_owner_work(instance: usize) -> bool {
    let mut more = false;
    for_each_allocator(|allocators| {
        if instance < allocators.instance_count() {
            more |= allocators.handle_owner_work(instance).unwrap_or(false);
        }
    });
    more
}

/// Runs only the queued requests of scheduler instance `instance` for every allocator.
pub fn run_owner_requests(instance: usize) {
    for_each_allocator(|allocators| {
        if instance < allocators.instance_count() {
            allocators.run_owner_requests(instance);
        }
    });
}

/// Bytes of the process heap and process struct allocators (`eheap_alloc` and the process
/// struct blocks of `fix_alloc`), the PROCESSES class of `erlang:memory/0`.
pub fn process_allocation_bytes() -> u64 {
    [ErtsAlcType::HEAP, ErtsAlcType::PROC]
        .into_iter()
        .filter_map(|allocation_type| allocator_for(allocation_type).ok())
        .map(|allocators| allocators.current_blocks_size() as u64)
        .sum()
}

/// Current allocated bytes belonging to the erts `BINARY` allocation type.
// Port of erts/emulator/beam/erl_alloc.c:2124 (alcu_size), OTP-29.1.1.
pub fn binary_allocation_bytes() -> u64 {
    allocator_for(ErtsAlcType::BINARY)
        .expect("the BINARY allocator is configured")
        .current_blocks_size() as u64
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

    #[test]
    fn fixed_size_blocks_come_back_from_the_free_list() {
        use super::{ErtsAlcType, fix_alloc_at, fix_free_at};
        let ix = crate::instances::thread_alloc_ix();
        let (first, first_ptr) = fix_alloc_at(ix, ErtsAlcType::PROC, 1200).unwrap();
        fix_free_at(ix, ErtsAlcType::PROC, first).unwrap();
        let (second, second_ptr) = fix_alloc_at(ix, ErtsAlcType::PROC, 1200).unwrap();
        assert_eq!(first_ptr, second_ptr);
        let handle = std::thread::spawn(move || {
            let ix = crate::instances::thread_alloc_ix();
            fix_free_at(ix, ErtsAlcType::PROC, second).unwrap();
        });
        handle.join().unwrap();
        let (third, third_ptr) = fix_alloc_at(ix, ErtsAlcType::PROC, 1200).unwrap();
        assert_eq!(third_ptr, second_ptr);
        fix_free_at(ix, ErtsAlcType::PROC, third).unwrap();
        assert!(fix_alloc_at(ix, ErtsAlcType::HEAP, 8).is_err());
    }
}
