//! The ETS stored object as one allocation, as erts lays out a `DbTerm`.
//!
//! Port of the layout of erts/emulator/beam/erl_db_util.h (`DbTerm`), erl_db_hash.h
//! (`HashDbTerm`) and erl_db_util.c (`db_store_term`, `db_free_term`), OTP-29.1.1: the table's
//! link fields, the `DbTerm` bookkeeping and the term's heap words are one block that is
//! allocated once and freed once. This module holds the only raw allocation of the crate's
//! stored objects; everything else reaches the words through the safe slice field.

use super::{EtsError, OffHeap};
use arinsal_term::{
    ExternalBinary, HeapAlloc, MagicRef, Node as TermNode, Term, TermError, WritableBinary,
};
use std::alloc::{Layout, alloc_zeroed, handle_alloc_error};
use std::sync::Arc;

use super::Compressed;

/// A stored object: the table links, the `DbTerm` fields and, after them, the words of the
/// term. `W = [u64]` is the unsized form every table works with.
// Port of erts/emulator/beam/erl_db_util.h (DbTerm) and erl_db_hash.h (HashDbTerm), OTP-29.1.1.
#[repr(C)]
pub(crate) struct StoredTermG<W: ?Sized> {
    /// `HashDbTerm.next`; the left child of a tree node.
    pub(crate) next: Option<Box<StoredTermG<[u64]>>>,
    /// `HashDbTerm.hvalue`.
    pub(crate) hvalue: u64,
    /// The stored tuple, a pointer into `words`.
    pub(crate) term: Term,
    /// `DbTerm.size`-based memory accounting, in words (`ets:info(T, memory)`).
    pub(crate) db_size_words: usize,
    /// Words `copy_struct` needs to copy the stored term out.
    pub(crate) term_size_words: usize,
    /// `DbTerm.first_oh` owners.
    pub(crate) off_heap: Option<Box<OffHeap>>,
    // ETS compressed tables retain only ETF bytes for non-key boxed elements. The tuple
    // contains NIL sentinels in those positions and never keeps the original values alive.
    pub(crate) compressed: Option<Box<Compressed>>,
    pub(crate) order: u64,
    pub(crate) group_order: u64,
    /// The stored block can be copied out word by word (`copy_shallow`).
    pub(crate) shallow: bool,
    /// `HashDbTerm.pseudo_deleted`.
    pub(crate) pseudo_deleted: bool,
    /// The heap words of the term.
    pub(crate) words: W,
}

/// A stored object of any size.
pub(crate) type StoredTerm = StoredTermG<[u64]>;
/// The owner of a stored object, as erts' `DbTerm *` / `HashDbTerm *`.
pub(crate) type DbTerm = Box<StoredTerm>;

/// Allocate a block for `nwords` words of term data, zeroed.
// Port of erts/emulator/beam/erl_db_util.c (new_dbterm / db_store_term allocation), OTP-29.1.1.
pub(crate) fn new_block(nwords: usize) -> DbTerm {
    type Head = StoredTermG<[u64; 0]>;
    let layout = Layout::new::<Head>()
        .extend(Layout::array::<u64>(nwords).expect("object size fits an allocation"))
        .expect("object size fits an allocation")
        .0
        .pad_to_align();
    // SAFETY: the layout holds at least the header, so its size is not zero.
    let raw = unsafe { alloc_zeroed(layout) };
    if raw.is_null() {
        handle_alloc_error(layout);
    }
    // SAFETY: `raw` is a fresh allocation, aligned for and large enough for the header.
    unsafe {
        raw.cast::<Head>().write(Head {
            next: None,
            hvalue: 0,
            term: Term::NIL,
            db_size_words: 0,
            term_size_words: 0,
            off_heap: None,
            compressed: None,
            order: 0,
            group_order: 0,
            shallow: false,
            pseudo_deleted: false,
            words: [],
        });
    }
    let fat = std::ptr::slice_from_raw_parts_mut(raw.cast::<u64>(), nwords) as *mut StoredTerm;
    // SAFETY: the allocation has the size and alignment `Box` frees an unsized `StoredTerm` with
    // (header plus `nwords` words, 8-aligned); the header is initialised and zero is a valid word.
    unsafe { Box::from_raw(fat) }
}

/// Allocate a block of `nwords` words and let `fill` copy the term into it; `fill` returns the
/// stored term. The off-heap owners it links belong to the block.
// Port of erts/emulator/beam/erl_db_util.c (db_store_term), OTP-29.1.1.
pub(crate) fn build_block(
    nwords: usize,
    fill: impl FnOnce(&mut BlockHeap) -> Result<Term, EtsError>,
) -> Result<DbTerm, EtsError> {
    let mut block = new_block(nwords);
    let mut heap = BlockHeap {
        base: block.words.as_mut_ptr(),
        cap: nwords,
        used: 0,
        off_heap: None,
    };
    let term = fill(&mut heap)?;
    debug_assert!(heap.used <= nwords, "object copy overran its block");
    block.term = term;
    block.off_heap = heap.off_heap.take();
    Ok(block)
}

/// The words of one stored block, handed out in order, as erts' `db_store_term` bumps `top`.
pub(crate) struct BlockHeap {
    base: *mut u64,
    cap: usize,
    used: usize,
    off_heap: Option<Box<OffHeap>>,
}

impl BlockHeap {
    fn off_heap(&mut self) -> &mut OffHeap {
        self.off_heap
            .get_or_insert_with(|| Box::new(OffHeap::default()))
    }

    /// Link the off-heap object at `address` (three words) at the head of the DbTerm's
    /// `first_oh` chain.
    fn chain_first_oh(&mut self, address: usize) -> Result<(), TermError> {
        let start = self.base as usize;
        let end = start + self.cap * 8;
        if address < start || address.checked_add(24).is_none_or(|tail| tail > end) {
            return Err(TermError::BadArg);
        }
        let word_index = (address - start) / 8;
        let first_oh = self
            .off_heap
            .as_ref()
            .map_or(0, |off_heap| off_heap.first_oh);
        // SAFETY: the three words at `address` lie inside this block (checked above), which
        // `base` addresses and which no reference is using while `fill` runs.
        unsafe { self.base.add(word_index + 2).write(first_oh as u64) };
        self.off_heap().first_oh = address;
        Ok(())
    }
}

impl HeapAlloc for BlockHeap {
    fn alloc(&mut self, words: usize) -> Option<*mut u64> {
        if words > self.cap - self.used {
            return None;
        }
        let ptr = self.base.wrapping_add(self.used);
        self.used += words;
        Some(ptr)
    }

    fn retain_binary(&mut self, binary: Arc<arinsal_term::RefcBinary>) {
        drop(binary);
    }
    // Port of erts/emulator/beam/erl_db_util.c (db_store_term), OTP-29.1.1.
    fn link_bin_ref(
        &mut self,
        bin_ref: *mut u64,
        _writable: bool,
        _overhead_words: u64,
        owner: Option<arinsal_term::OwnedBinaryRef>,
    ) -> Result<(), TermError> {
        self.chain_first_oh(bin_ref as usize)?;
        let off_heap = self.off_heap();
        if let Some(mut owner) = owner {
            owner.attach_to_bin_ref(bin_ref);
            off_heap.binary_refs.push(owner);
        }
        Ok(())
    }
    fn retain_writable_binary(&mut self, binary: Arc<WritableBinary>) -> Result<(), TermError> {
        drop(binary);
        Ok(())
    }
    fn supports_writable_binary(&self) -> bool {
        true
    }
    fn link_external_binary(
        &mut self,
        bin_ref: *mut u64,
        binary: Arc<ExternalBinary>,
    ) -> Result<(), TermError> {
        let _ = self.chain_first_oh(bin_ref as usize);
        self.off_heap().external.push(binary);
        Ok(())
    }
    fn supports_external_binary(&self) -> bool {
        true
    }
    // The DbTerm's first_oh chain links the thing; the token stands in for the counted
    // reference the thing holds until db_free_term.
    fn link_node(&mut self, thing: *mut u64, node: Arc<TermNode>) {
        let _ = self.chain_first_oh(thing as usize);
        self.off_heap().nodes.push(node);
    }
    fn link_magic_ref(&mut self, thing: *mut u64, owner: Arc<MagicRef>) -> Result<(), TermError> {
        self.chain_first_oh(thing as usize)?;
        self.off_heap().magic.push(owner);
        Ok(())
    }
    fn supports_magic(&self) -> bool {
        true
    }
}
