//! The ETS stored object as one allocation, as erts lays out a `DbTerm`.
//!
//! Port of the layout of erts/emulator/beam/erl_db_util.h (`DbTerm`), erl_db_hash.h
//! (`HashDbTerm`) and erl_db_util.c (`db_store_term`, `db_free_term`), OTP-29.1.1: the table's
//! link fields, the `DbTerm` bookkeeping and the term's heap words are one block that is
//! allocated once and freed once. This module holds the only raw allocation of the crate's
//! stored objects; everything else reaches the words through the safe slice field.

use super::{Compressed, EtsError, OffHeap};
use arinsal_alloc::typed::{ets_alloc_words, ets_free_words, ets_realloc_words};
use arinsal_term::{
    ExternalBinary, HeapAlloc, MagicRef, Node as TermNode, Term, TermError, WritableBinary, cmp,
};
use std::cmp::Ordering;
use std::ptr::NonNull;
use std::sync::Arc;

const PSEUDO_DELETED_BIT: u64 = 1 << 63;

const TERM_WORDS_BITS: u32 = 48;
const TERM_WORDS_MASK: u64 = (1 << TERM_WORDS_BITS) - 1;
const PREFIX_WORDS_SHIFT: u32 = 48;
const PREFIX_WORDS_MASK: u64 = 0x7 << PREFIX_WORDS_SHIFT;
const SHALLOW_BIT: u64 = 1 << 62;
const ROOT_AT_BASE_BIT: u64 = 1 << 63;

/// Cold metadata for rows that retain off-heap objects, compressed ETF elements, or a non-tuple
/// root (`PlainDbTerm`). Ordinary uncompressed ETS rows keep `extra: None` (a single null word,
/// matching `DbTerm.first_oh == NULL` in `erl_db_util.h:69`).
#[derive(Default)]
pub(crate) struct DbTermExtra {
    pub(crate) off_heap: Option<OffHeap>,
    pub(crate) compressed: Option<Compressed>,
    pub(crate) alt_term: Option<Term>,
    pub(crate) alloc_words: Option<usize>,
    pub(crate) db_size_words_override: Option<usize>,
}

/// The `DbTerm` of erts (`erl_db_util.h:68-82`): two header words (`first_oh`/extra pointer +
/// `size`/flags word), followed immediately in the same `ets_alloc` block by `tpl[]` (`words`),
/// where the top tuple always starts at word 0 for uncompressed ETS objects.
// Port of erts/emulator/beam/erl_db_util.h (DbTerm), OTP-29.1.1.
#[repr(C, align(8))]
pub(crate) struct StoredTerm {
    extra: Option<Box<DbTermExtra>>,
    meta: u64,
}

impl StoredTerm {
    #[inline]
    fn words_mut_ptr(&mut self) -> *mut u64 {
        std::ptr::from_mut(self).wrapping_add(1).cast::<u64>()
    }

    #[inline]
    pub(crate) fn term_size_words(&self) -> usize {
        (self.meta & TERM_WORDS_MASK) as usize
    }

    #[inline]
    pub(crate) fn prefix_words(&self) -> usize {
        ((self.meta & PREFIX_WORDS_MASK) >> PREFIX_WORDS_SHIFT) as usize
    }

    #[inline]
    pub(crate) fn alloc_words(&self) -> usize {
        if self.meta & ROOT_AT_BASE_BIT != 0 {
            return self.term_size_words();
        }
        self.extra
            .as_ref()
            .and_then(|extra| extra.alloc_words)
            .unwrap_or_else(|| self.term_size_words())
    }

    #[inline]
    pub(crate) fn db_size_words(&self) -> usize {
        if self.meta & ROOT_AT_BASE_BIT == 0
            && let Some(words) = self.extra.as_ref().and_then(|e| e.db_size_words_override)
        {
            return words;
        }
        self.prefix_words() + 2 + self.term_size_words()
    }

    #[inline]
    pub(crate) fn shallow(&self) -> bool {
        self.meta & SHALLOW_BIT != 0
    }

    #[inline]
    fn raw_words_and_root(&self) -> (&[u64], Term) {
        let ptr = std::ptr::from_ref(self).wrapping_add(1).cast::<u64>();
        let len = self.alloc_words();
        // SAFETY: every `StoredTerm` is followed in its `ets_alloc` block by `alloc_words`
        // initialized `u64` words; when `ROOT_AT_BASE_BIT` is set, `ptr` addresses a valid boxed
        // tuple header in those words.
        unsafe {
            let slice = std::slice::from_raw_parts(ptr, len);
            let term = if self.meta & ROOT_AT_BASE_BIT != 0 {
                Term::from_raw_bits((ptr as u64) | 2)
            } else {
                self.extra
                    .as_ref()
                    .and_then(|extra| extra.alt_term)
                    .unwrap_or(Term::NIL)
            };
            (slice, term)
        }
    }

    #[inline]
    pub(crate) fn words(&self) -> &[u64] {
        self.raw_words_and_root().0
    }

    #[inline]
    pub(crate) fn words_mut(&mut self) -> &mut [u64] {
        let len = self.alloc_words();
        let ptr = self.words_mut_ptr();
        // SAFETY: as in `raw_words_and_root`, with exclusive `&mut self` access.
        unsafe { std::slice::from_raw_parts_mut(ptr, len) }
    }

    #[inline]
    pub(crate) fn term(&self) -> Term {
        self.raw_words_and_root().1
    }

    #[inline]
    pub(crate) fn off_heap(&self) -> Option<&OffHeap> {
        self.extra.as_ref()?.off_heap.as_ref()
    }

    #[inline]
    pub(crate) fn compressed(&self) -> Option<&Compressed> {
        self.extra.as_ref()?.compressed.as_ref()
    }

    fn extra_mut(&mut self) -> &mut DbTermExtra {
        self.extra
            .get_or_insert_with(|| Box::new(DbTermExtra::default()))
    }

    fn clear_payload(&mut self, current_alloc_words: usize) {
        self.extra = None;
        self.meta = current_alloc_words as u64;
    }

    #[inline]
    pub(crate) fn set_uncompressed_meta(
        &mut self,
        prefix_words: usize,
        term_size_words: usize,
        shallow: bool,
    ) {
        debug_assert!(term_size_words < (1usize << TERM_WORDS_BITS));
        debug_assert!(prefix_words <= 7);
        let root_bit = self.meta & ROOT_AT_BASE_BIT;
        self.meta = (term_size_words as u64)
            | ((prefix_words as u64) << PREFIX_WORDS_SHIFT)
            | if shallow { SHALLOW_BIT } else { 0 }
            | root_bit;
    }

    pub(crate) fn set_copied_meta(
        &mut self,
        prefix_words: usize,
        term_size_words: usize,
        db_size_words: usize,
        shallow: bool,
    ) {
        self.set_uncompressed_meta(prefix_words, term_size_words, shallow);
        if db_size_words != prefix_words + 2 + term_size_words {
            self.meta &= !ROOT_AT_BASE_BIT;
            let term = self.term();
            let extra = self.extra_mut();
            if extra.alt_term.is_none() {
                extra.alt_term = Some(term);
            }
            extra.db_size_words_override = Some(db_size_words);
        }
    }

    pub(crate) fn set_compressed_meta(
        &mut self,
        term_size_words: usize,
        alloc_words: usize,
        db_size_words: usize,
        shallow: bool,
        compressed: Compressed,
    ) {
        let term = self.term();
        debug_assert!(term_size_words < (1usize << TERM_WORDS_BITS));
        self.meta = (term_size_words as u64) | if shallow { SHALLOW_BIT } else { 0 };
        let extra = self.extra_mut();
        extra.alt_term = Some(term);
        extra.alloc_words = Some(alloc_words);
        extra.db_size_words_override = Some(db_size_words);
        extra.compressed = Some(compressed);
    }
}

/// A table's block: the table-specific prefix (`HashDbTerm` / `TreeDbTerm` fields before
/// `dbterm`) and the `DbTerm` header, followed immediately in memory by `tpl[]`.
#[repr(C)]
pub(crate) struct Node<P> {
    pub(crate) prefix: P,
    pub(crate) data: StoredTerm,
}

impl<P> std::ops::Deref for Node<P> {
    type Target = StoredTerm;

    #[inline]
    fn deref(&self) -> &StoredTerm {
        &self.data
    }
}

impl<P> std::ops::DerefMut for Node<P> {
    #[inline]
    fn deref_mut(&mut self) -> &mut StoredTerm {
        &mut self.data
    }
}

/// `HashDbTerm` before the `dbterm` field (`erl_db_hash.h:41-49`), OTP-29.1.1:
/// `next` bucket pointer plus 63-bit `hvalue` and 1-bit `pseudo_deleted` packed in one word.
// Port of erts/emulator/beam/erl_db_hash.h:41-49 (HashDbTerm), OTP-29.1.1.
#[repr(C)]
pub(crate) struct HashPrefix {
    pub(crate) next: Option<HashDbTerm>,
    hvalue_and_flg: u64,
}

impl HashPrefix {
    #[inline]
    pub(crate) fn hvalue(&self) -> u64 {
        self.hvalue_and_flg & !PSEUDO_DELETED_BIT
    }

    #[inline]
    pub(crate) fn set_hvalue(&mut self, hvalue: u64) {
        debug_assert!(hvalue & PSEUDO_DELETED_BIT == 0);
        self.hvalue_and_flg =
            (self.hvalue_and_flg & PSEUDO_DELETED_BIT) | (hvalue & !PSEUDO_DELETED_BIT);
    }

    #[inline]
    pub(crate) fn pseudo_deleted(&self) -> bool {
        self.hvalue_and_flg & PSEUDO_DELETED_BIT != 0
    }

    #[inline]
    pub(crate) fn set_pseudo_deleted(&mut self, deleted: bool) {
        if deleted {
            self.hvalue_and_flg |= PSEUDO_DELETED_BIT;
        } else {
            self.hvalue_and_flg &= !PSEUDO_DELETED_BIT;
        }
    }
}

/// `TreeDbTerm` before the `dbterm` field (`erl_db_tree.h:28-32`), OTP-29.1.1.
// Port of erts/emulator/beam/erl_db_tree.h:28-32 (TreeDbTerm), OTP-29.1.1.
#[repr(C)]
pub(crate) struct TreePrefix {
    pub(crate) left: Option<TreeDbTerm>,
    pub(crate) right: Option<TreeDbTerm>,
    pub(crate) balance: i8,
}

/// A prefix a block can be made with: all fields empty.
pub(crate) trait Prefix: Sized {
    fn empty() -> Self;
}

impl Prefix for () {
    fn empty() -> Self {}
}

impl Prefix for HashPrefix {
    fn empty() -> Self {
        Self {
            next: None,
            hvalue_and_flg: 0,
        }
    }
}

impl Prefix for TreePrefix {
    fn empty() -> Self {
        Self {
            left: None,
            right: None,
            balance: 0,
        }
    }
}

/// The owner of a stored block, as erts' `DbTerm *` / `HashDbTerm *` / `TreeDbTerm *`: one thin
/// non-null pointer to an `ERTS_ALC_T_DB_TERM` allocation holding the prefix, the `DbTerm` header
/// and the words of the term.
#[repr(transparent)]
pub(crate) struct DbTerm<P> {
    ptr: NonNull<Node<P>>,
}

pub(crate) type HashDbTerm = DbTerm<HashPrefix>;
pub(crate) type TreeDbTerm = DbTerm<TreePrefix>;
/// A block with no table prefix (`offset` 0).
pub(crate) type PlainDbTerm = DbTerm<()>;
/// The block of a tree node as the tree code sees it.
pub(crate) type TreeNode = Node<TreePrefix>;

const _: () = {
    assert!(std::mem::size_of::<StoredTerm>() == 16);
    assert!(std::mem::size_of::<HashPrefix>() == 16);
    assert!(std::mem::size_of::<TreePrefix>() == 24);
    assert!(std::mem::size_of::<Node<HashPrefix>>() == 32);
    assert!(std::mem::size_of::<Node<TreePrefix>>() == 40);
    assert!(std::mem::size_of::<HashDbTerm>() == 8);
    assert!(std::mem::size_of::<Option<HashDbTerm>>() == 8);
    assert!(std::mem::size_of::<TreeDbTerm>() == 8);
    assert!(std::mem::size_of::<Option<TreeDbTerm>>() == 8);
};

// SAFETY: a `DbTerm` owns its block exclusively, like a `Box`, and its contents are `Send + Sync`.
unsafe impl<P: Send> Send for DbTerm<P> {}
// SAFETY: see above.
unsafe impl<P: Sync> Sync for DbTerm<P> {}

impl<P> std::ops::Deref for DbTerm<P> {
    type Target = Node<P>;

    #[inline]
    fn deref(&self) -> &Self::Target {
        // SAFETY: `ptr` addresses the live block this value owns.
        unsafe { self.ptr.as_ref() }
    }
}

impl<P> std::ops::DerefMut for DbTerm<P> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        // SAFETY: as above, and `&mut self` is the only access path.
        unsafe { self.ptr.as_mut() }
    }
}

impl<P> Drop for DbTerm<P> {
    // Port of erts/emulator/beam/erl_db_util.c (db_free_term), OTP-29.1.1.
    fn drop(&mut self) {
        let base = self.ptr.as_ptr();
        let total_words = std::mem::size_of::<Node<P>>() / 8 + self.data.alloc_words();
        // SAFETY: the block is live and owned; its fields are dropped once, then its memory is
        // returned to `ets_alloc`.
        unsafe { std::ptr::drop_in_place(base) };
        ets_free_words(base.cast::<u64>(), total_words);
    }
}

impl<P: Prefix> DbTerm<P> {
    const HEAD_WORDS: usize = {
        assert!(
            std::mem::size_of::<Node<P>>()
                == std::mem::offset_of!(Node<P>, data) + std::mem::size_of::<StoredTerm>()
        );
        std::mem::size_of::<Node<P>>() / 8
    };

    fn from_user(user: *mut u64) -> Self {
        Self {
            ptr: NonNull::new(user.cast::<Node<P>>()).expect("ets_alloc returned null"),
        }
    }

    /// Make the block hold `nwords` words of term data, keeping the header; the words are
    /// cleared. `erts_db_realloc` when the size changes.
    // Port of erts/emulator/beam/erl_db_util.c (db_realloc_term), OTP-29.1.1.
    fn resize(&mut self, old_nwords: usize, nwords: usize) {
        if old_nwords != nwords {
            let user = ets_realloc_words(
                self.ptr.as_ptr().cast::<u64>(),
                Self::HEAD_WORDS + old_nwords,
                Self::HEAD_WORDS + nwords,
            )
            .expect("ets_alloc out of memory");
            self.ptr = NonNull::new(user.cast::<Node<P>>()).expect("ets_realloc returned null");
        }
        self.data.meta = nwords as u64;
        self.data.words_mut().fill(0);
    }
}

/// Allocate a block for `nwords` words of term data.
// Port of erts/emulator/beam/erl_db_util.c (db_store_term allocation:
// erts_db_alloc(ERTS_ALC_T_DB_TERM)), OTP-29.1.1.
pub(crate) fn new_block<P: Prefix>(nwords: usize) -> DbTerm<P> {
    debug_assert!(nwords < (1usize << TERM_WORDS_BITS));
    let head_words = DbTerm::<P>::HEAD_WORDS;
    let user = ets_alloc_words(head_words + nwords).expect("ets_alloc out of memory");
    // SAFETY: `user` addresses `head_words + nwords` fresh words, 8-aligned: room for the
    // header, and the term words after it are zeroed here.
    unsafe {
        user.cast::<Node<P>>().write(Node {
            prefix: P::empty(),
            data: StoredTerm {
                extra: None,
                meta: nwords as u64,
            },
        });
        std::ptr::write_bytes(user.add(head_words), 0, nwords);
    }
    DbTerm::from_user(user)
}

/// Allocate a block of `nwords` words and let `fill` copy the term into it; `fill` returns the
/// stored term. The off-heap owners it links belong to the block.
// Port of erts/emulator/beam/erl_db_util.c (db_store_term), OTP-29.1.1.
pub(crate) fn build_block<P: Prefix>(
    nwords: usize,
    fill: impl FnOnce(&mut BlockHeap) -> Result<Term, EtsError>,
) -> Result<DbTerm<P>, EtsError> {
    let mut block = new_block(nwords);
    fill_block(&mut block, fill)?;
    Ok(block)
}

/// `db_store_term` with an old DbTerm: the old term's off-heap owners are released and the block
/// is reused when the size is unchanged, else reallocated; the links and hash value stay.
// Port of erts/emulator/beam/erl_db_util.c (db_store_term), OTP-29.1.1.
pub(crate) fn rebuild_block<P: Prefix>(
    old: &mut DbTerm<P>,
    nwords: usize,
    fill: impl FnOnce(&mut BlockHeap) -> Result<Term, EtsError>,
) -> Result<(), EtsError> {
    let old_nwords = old.data.alloc_words();
    // erts_cleanup_offheap_list(old->first_oh)
    old.data.clear_payload(old_nwords);
    old.resize(old_nwords, nwords);
    fill_block(old, fill)
}

fn fill_block<P: Prefix>(
    block: &mut DbTerm<P>,
    fill: impl FnOnce(&mut BlockHeap) -> Result<Term, EtsError>,
) -> Result<(), EtsError> {
    let nwords = block.data.alloc_words();
    let base = block.data.words_mut_ptr();
    let mut heap = BlockHeap {
        base,
        cap: nwords,
        used: 0,
        off_heap: None,
    };
    let term = fill(&mut heap)?;
    debug_assert!(heap.used <= nwords, "object copy overran its block");
    let root_at_base = nwords > 0 && term.tagged_word() == (base as u64) | 2;
    if root_at_base {
        block.data.meta = (nwords as u64) | ROOT_AT_BASE_BIT;
        if let Some(off_heap) = heap.off_heap.take() {
            block.data.extra_mut().off_heap = Some(*off_heap);
        }
    } else {
        block.data.meta = nwords as u64;
        let extra = block.data.extra_mut();
        extra.alt_term = Some(term);
        extra.alloc_words = Some(nwords);
        if let Some(off_heap) = heap.off_heap.take() {
            extra.off_heap = Some(*off_heap);
        }
    }
    Ok(())
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

// ---------------------------------------------------------------------------------------------
// The AVL tree of an ordered_set: nodes are `TreeDbTerm` blocks linked through `left` and
// `right`. The algorithms below keep erts' stacks of `TreeDbTerm **` slots, raw pointers to the
// link fields of the nodes above the one being changed.
// ---------------------------------------------------------------------------------------------

/// A `TreeDbTerm *`.
pub(crate) type Link = Option<TreeDbTerm>;

// Port of erl_db_tree_util.h (STACK_NEED): 90 entries on 64-bit, 50 on 32-bit.
pub(crate) const STACK_NEED: usize = if usize::BITS == 64 { 90 } else { 50 };
const DIR_LEFT: u8 = 0;
const DIR_RIGHT: u8 = 1;
const DIR_END: u8 = 2;

/// Result of one `db_put_dbterm_tree_common` descent.
#[derive(Clone, Copy)]
pub(crate) enum InsertResult {
    Inserted,
    /// An object with the key was replaced; its accounted size in words.
    Replaced(usize),
    Exists,
}

/// The `tstack`/`dstack` pair of erts' non-recursive AVL routines: the slots of the nodes on the
/// path from the root and the direction taken at each.
struct Path {
    slots: [Slot; STACK_NEED],
    dirs: [u8; STACK_NEED + 1],
    tpos: usize,
    dpos: usize,
}

impl Path {
    fn new() -> Self {
        let mut dirs = [DIR_END; STACK_NEED + 1];
        dirs[0] = DIR_END;
        Self {
            slots: [Slot::NULL; STACK_NEED],
            dirs,
            tpos: 0,
            dpos: 1,
        }
    }

    fn push(&mut self, slot: Slot, dir: u8) {
        self.slots[self.tpos] = slot;
        self.tpos += 1;
        self.dirs[self.dpos] = dir;
        self.dpos += 1;
    }

    /// `dir = dstack[--dpos]; this = tstack[--tpos]`, or `None` at `DIR_END`.
    fn pop(&mut self) -> Option<(Slot, u8)> {
        if self.dpos <= 1 {
            return None;
        }
        self.dpos -= 1;
        self.tpos -= 1;
        Some((self.slots[self.tpos], self.dirs[self.dpos]))
    }
}

/// A `TreeDbTerm **`: the address of a link field of a node (or of the root) that an AVL
/// routine keeps on its stack while it changes the nodes below.
#[derive(Clone, Copy)]
struct Slot(*mut Link);

impl Slot {
    const NULL: Self = Self(std::ptr::null_mut());

    fn of(link: &mut Link) -> Self {
        Self(link)
    }

    /// The link the slot addresses. Slots are only made from, and used within, one AVL routine
    /// that holds `&mut` to the whole tree, and rotations only exchange which block sits in a
    /// slot, so every slot on the stack stays valid and is not otherwise referenced.
    fn link<'a>(self) -> &'a mut Link {
        // SAFETY: see above; the pointer is non-null because only `of` makes slots that are used.
        unsafe { &mut *self.0 }
    }
}

fn node(link: &mut Link) -> &mut TreeDbTerm {
    link.as_mut().expect("AVL slot holds a node")
}

/// Port of erts/emulator/beam/erl_db_tree.c (tree_balance_left), OTP-29.1.1. Returns whether
/// the height of the subtree decreased.
pub(crate) fn tree_balance_left(this: &mut Link) -> bool {
    match node(this).prefix.balance {
        -1 => {
            node(this).prefix.balance = 0;
            true
        }
        0 => {
            node(this).prefix.balance = 1;
            false
        }
        _ => {
            let mut p = this.take().expect("AVL slot holds a node");
            let mut p1 = p
                .prefix
                .right
                .take()
                .expect("right-heavy node has a right child");
            let b1 = p1.prefix.balance;
            let mut h = true;
            if b1 >= 0 {
                // Single RR rotation
                p.prefix.right = p1.prefix.left.take();
                if b1 == 0 {
                    p.prefix.balance = 1;
                    p1.prefix.balance = -1;
                    h = false;
                } else {
                    p.prefix.balance = 0;
                    p1.prefix.balance = 0;
                }
                p1.prefix.left = Some(p);
                *this = Some(p1);
            } else {
                // Double RL rotation
                let mut p2 = p1
                    .prefix
                    .left
                    .take()
                    .expect("RL rotation needs a grandchild");
                let b2 = p2.prefix.balance;
                p1.prefix.left = p2.prefix.right.take();
                p.prefix.right = p2.prefix.left.take();
                p.prefix.balance = if b2 == 1 { -1 } else { 0 };
                p1.prefix.balance = if b2 == -1 { 1 } else { 0 };
                p2.prefix.balance = 0;
                p2.prefix.right = Some(p1);
                p2.prefix.left = Some(p);
                *this = Some(p2);
            }
            h
        }
    }
}

/// Port of erts/emulator/beam/erl_db_tree.c (tree_balance_right), OTP-29.1.1.
pub(crate) fn tree_balance_right(this: &mut Link) -> bool {
    match node(this).prefix.balance {
        1 => {
            node(this).prefix.balance = 0;
            true
        }
        0 => {
            node(this).prefix.balance = -1;
            false
        }
        _ => {
            let mut p = this.take().expect("AVL slot holds a node");
            let mut p1 = p
                .prefix
                .left
                .take()
                .expect("left-heavy node has a left child");
            let b1 = p1.prefix.balance;
            let mut h = true;
            if b1 <= 0 {
                // Single LL rotation
                p.prefix.left = p1.prefix.right.take();
                if b1 == 0 {
                    p.prefix.balance = -1;
                    p1.prefix.balance = 1;
                    h = false;
                } else {
                    p.prefix.balance = 0;
                    p1.prefix.balance = 0;
                }
                p1.prefix.right = Some(p);
                *this = Some(p1);
            } else {
                // Double LR rotation
                let mut p2 = p1
                    .prefix
                    .right
                    .take()
                    .expect("LR rotation needs a grandchild");
                let b2 = p2.prefix.balance;
                p1.prefix.right = p2.prefix.left.take();
                p.prefix.left = p2.prefix.right.take();
                p.prefix.balance = if b2 == -1 { 1 } else { 0 };
                p1.prefix.balance = if b2 == 1 { -1 } else { 0 };
                p2.prefix.balance = 0;
                p2.prefix.left = Some(p1);
                p2.prefix.right = Some(p);
                *this = Some(p2);
            }
            h
        }
    }
}

/// The rebalancing loop of `db_put_dbterm_tree_common` after a node was linked in, which
/// `join_trees` also runs "as if this was during the insert".
// Port of erts/emulator/beam/erl_db_tree.c (db_put_dbterm_tree_common), OTP-29.1.1.
fn rebalance_after_insert(path: &mut Path) {
    while let Some((this, dir)) = path.pop() {
        let this = this.link();
        let balance = node(this).prefix.balance;
        if dir == DIR_LEFT {
            match balance {
                1 => {
                    node(this).prefix.balance = 0;
                    return;
                }
                0 => node(this).prefix.balance = -1,
                _ => {
                    let mut p = this.take().expect("AVL slot holds a node");
                    let mut p1 = p
                        .prefix
                        .left
                        .take()
                        .expect("left-heavy node has a left child");
                    if p1.prefix.balance == -1 {
                        // Single LL rotation
                        p.prefix.left = p1.prefix.right.take();
                        p.prefix.balance = 0;
                        p1.prefix.right = Some(p);
                        *this = Some(p1);
                    } else {
                        // Double RR rotation
                        let mut p2 = p1
                            .prefix
                            .right
                            .take()
                            .expect("RR rotation needs a grandchild");
                        p1.prefix.right = p2.prefix.left.take();
                        p.prefix.left = p2.prefix.right.take();
                        p.prefix.balance = if p2.prefix.balance == -1 { 1 } else { 0 };
                        p1.prefix.balance = if p2.prefix.balance == 1 { -1 } else { 0 };
                        p2.prefix.left = Some(p1);
                        p2.prefix.right = Some(p);
                        *this = Some(p2);
                    }
                    node(this).prefix.balance = 0;
                    return;
                }
            }
        } else {
            match balance {
                -1 => {
                    node(this).prefix.balance = 0;
                    return;
                }
                0 => node(this).prefix.balance = 1,
                _ => {
                    let mut p = this.take().expect("AVL slot holds a node");
                    let mut p1 = p
                        .prefix
                        .right
                        .take()
                        .expect("right-heavy node has a right child");
                    if p1.prefix.balance == 1 {
                        // Single RR rotation
                        p.prefix.right = p1.prefix.left.take();
                        p.prefix.balance = 0;
                        p1.prefix.left = Some(p);
                        *this = Some(p1);
                    } else {
                        // Double RL rotation
                        let mut p2 = p1
                            .prefix
                            .left
                            .take()
                            .expect("RL rotation needs a grandchild");
                        p1.prefix.left = p2.prefix.right.take();
                        p.prefix.right = p2.prefix.left.take();
                        p.prefix.balance = if p2.prefix.balance == 1 { -1 } else { 0 };
                        p1.prefix.balance = if p2.prefix.balance == -1 { 1 } else { 0 };
                        p2.prefix.right = Some(p1);
                        p2.prefix.left = Some(p);
                        *this = Some(p2);
                    }
                    node(this).prefix.balance = 0;
                    return;
                }
            }
        }
    }
}

/// The rebalancing loop shared by the `linkout` routines: `state` says the subtree under the
/// slot popped next got shorter.
fn rebalance_after_delete(path: &mut Path, mut state: bool) {
    while state {
        let Some((this, dir)) = path.pop() else { break };
        let this = this.link();
        state = if dir == DIR_LEFT {
            tree_balance_left(this)
        } else {
            tree_balance_right(this)
        };
    }
}

/// Insert `value` (a block with no links yet), replacing an object with an equal key unless
/// `key_clash_fail`.
// Port of erts/emulator/beam/erl_db_tree.c (db_put_dbterm_tree_common), OTP-29.1.1.
pub(crate) fn tree_insert(
    root: &mut Link,
    value: TreeDbTerm,
    key: Term,
    keypos: usize,
    key_clash_fail: bool,
) -> InsertResult {
    let mut value = Some(value);
    tree_put(root, key, keypos, key_clash_fail, |old| match old {
        Some(old) => {
            // Equal key: the new block takes the old one's place and links.
            let mut value = value.take().expect("value is consumed once");
            value.prefix.balance = old.prefix.balance;
            value.prefix.left = old.prefix.left.take();
            value.prefix.right = old.prefix.right.take();
            *old = value;
            Ok(None)
        }
        None => Ok(value.take()),
    })
    .expect("storing an existing block cannot fail")
}

/// Find the place of `key` and let `make` store the object there: with the old block of an
/// equal key (rewritten in place, `None` returned) or without one (the new block is returned and
/// linked in). Returns what happened, with the replaced block's accounting size.
// Port of erts/emulator/beam/erl_db_tree.c (db_put_tree_common: new_dbterm / replace_dbterm),
// OTP-29.1.1.
pub(crate) fn tree_put(
    root: &mut Link,
    key: Term,
    keypos: usize,
    key_clash_fail: bool,
    make: impl FnOnce(Option<&mut TreeDbTerm>) -> Result<Option<TreeDbTerm>, EtsError>,
) -> Result<InsertResult, EtsError> {
    let mut path = Path::new();
    let mut this = Slot::of(root);
    loop {
        let slot = this.link();
        let order = match slot.as_ref() {
            None => {
                let mut new = make(None)?.expect("a new block is made without an old one");
                new.prefix.balance = 0;
                new.prefix.left = None;
                new.prefix.right = None;
                *slot = Some(new);
                rebalance_after_insert(&mut path);
                return Ok(InsertResult::Inserted);
            }
            Some(current) => cmp(key, current.key(keypos)),
        };
        match order {
            Ordering::Less => {
                path.push(this, DIR_LEFT);
                this = Slot::of(&mut node(slot).prefix.left);
            }
            Ordering::Greater => {
                path.push(this, DIR_RIGHT);
                this = Slot::of(&mut node(slot).prefix.right);
            }
            Ordering::Equal if !key_clash_fail => {
                let old = node(slot);
                let words = old.db_size_words();
                make(Some(old))?;
                return Ok(InsertResult::Replaced(words));
            }
            Ordering::Equal => return Ok(InsertResult::Exists),
        }
    }
}

/// Port of erts/emulator/beam/erl_db_tree.c (delsub), OTP-29.1.1: replace the node in `this`,
/// which has two children, by its in-order predecessor; returns the removed node and whether
/// the left subtree got shorter.
fn delsub(this: &mut Link) -> (TreeDbTerm, bool) {
    let mut q = this.take().expect("AVL slot holds a node");
    let mut slots = [Slot::NULL; STACK_NEED];
    let mut tpos = 0;
    let mut r = Slot::of(&mut q.prefix.left);
    // Walk down to the right looking for a void right child.
    while r.link().as_ref().is_some_and(|n| n.prefix.right.is_some()) {
        slots[tpos] = r;
        tpos += 1;
        r = Slot::of(&mut node(r.link()).prefix.right);
    }
    let mut pred = r.link().take().expect("predecessor exists");
    *r.link() = pred.prefix.left.take();
    pred.prefix.left = q.prefix.left.take();
    pred.prefix.right = q.prefix.right.take();
    pred.prefix.balance = q.prefix.balance;
    *this = Some(pred);
    slots[0] = Slot::of(&mut node(this).prefix.left);
    let mut h = true;
    while tpos > 0 && h {
        tpos -= 1;
        h = tree_balance_right(slots[tpos].link());
    }
    (q, h)
}

/// Unlink the object with `key` for which `matches` holds and return its block.
// Port of erts/emulator/beam/erl_db_tree.c (linkout_tree, linkout_object_tree), OTP-29.1.1.
pub(crate) fn tree_linkout(
    root: &mut Link,
    key: Term,
    keypos: usize,
    matches: &mut dyn FnMut(&StoredTerm) -> bool,
) -> Option<TreeDbTerm> {
    let mut path = Path::new();
    let mut this = Slot::of(root);
    let removed;
    let state;
    loop {
        let slot = this.link();
        let order = cmp(key, slot.as_ref()?.key(keypos));
        match order {
            Ordering::Less => {
                path.push(this, DIR_LEFT);
                this = Slot::of(&mut node(slot).prefix.left);
            }
            Ordering::Greater => {
                path.push(this, DIR_RIGHT);
                this = Slot::of(&mut node(slot).prefix.right);
            }
            Ordering::Equal => {
                if !matches(slot.as_ref().expect("slot checked above")) {
                    return None;
                }
                let q = node(slot);
                if q.prefix.right.is_none() {
                    let mut q = slot.take().expect("slot checked above");
                    *slot = q.prefix.left.take();
                    removed = q;
                    state = true;
                } else if q.prefix.left.is_none() {
                    let mut q = slot.take().expect("slot checked above");
                    *slot = q.prefix.right.take();
                    removed = q;
                    state = true;
                } else {
                    path.push(this, DIR_LEFT);
                    (removed, state) = delsub(slot);
                }
                break;
            }
        }
    }
    rebalance_after_delete(&mut path, state);
    Some(removed)
}

/// Port of erts/emulator/beam/erl_db_catree.c (linkout_min_or_max_tree_node), OTP-29.1.1.
fn linkout_min_or_max(root: &mut Link, is_min: bool) -> Option<TreeDbTerm> {
    let mut path = Path::new();
    let mut this = Slot::of(root);
    let removed;
    let state;
    loop {
        let slot = this.link();
        let current = slot.as_mut()?;
        if is_min && current.prefix.left.is_some() {
            path.push(this, DIR_LEFT);
            this = Slot::of(&mut current.prefix.left);
        } else if !is_min && current.prefix.right.is_some() {
            path.push(this, DIR_RIGHT);
            this = Slot::of(&mut current.prefix.right);
        } else {
            let mut q = slot.take().expect("slot checked above");
            if q.prefix.right.is_none() {
                *slot = q.prefix.left.take();
            } else {
                *slot = q.prefix.right.take();
            }
            removed = q;
            state = true;
            break;
        }
    }
    rebalance_after_delete(&mut path, state);
    Some(removed)
}

/// Port of erts/emulator/beam/erl_db_catree.c (compute_tree_hight), OTP-29.1.1.
pub(crate) fn compute_tree_height(root: &Link) -> usize {
    let Some(mut current) = root.as_deref() else {
        return 0;
    };
    let mut height = 1;
    while current.prefix.left.is_some() || current.prefix.right.is_some() {
        current = if current.prefix.balance == -1 {
            current
                .prefix
                .left
                .as_deref()
                .expect("left-heavy node has a left child")
        } else {
            current
                .prefix
                .right
                .as_deref()
                .expect("node has a right child")
        };
        height += 1;
    }
    height
}

/// Join two trees where every key of `left` is smaller than every key of `right`.
// Port of erts/emulator/beam/erl_db_catree.c (join_trees), OTP-29.1.1, after Knuth, TAOCP vol.
// 3, p. 474.
pub(crate) fn join_trees(mut left: Link, mut right: Link) -> Link {
    if left.is_none() {
        return right;
    }
    if right.is_none() {
        return left;
    }
    let left_height = compute_tree_height(&left);
    let right_height = compute_tree_height(&right);
    let mut path = Path::new();
    if left_height >= right_height {
        let mut new_root = linkout_min_or_max(&mut right, true).expect("right tree is not empty");
        let new_right_height = compute_tree_height(&right);
        let mut this = Slot::of(&mut left);
        let mut current_height = left_height;
        while current_height > new_right_height + 1 {
            let slot = this.link();
            if node(slot).prefix.balance == -1 {
                current_height -= 2;
            } else {
                current_height -= 1;
            }
            path.push(this, DIR_RIGHT);
            this = Slot::of(&mut node(slot).prefix.right);
        }
        let slot = this.link();
        new_root.prefix.left = slot.take();
        new_root.prefix.right = right;
        new_root.prefix.balance = (new_right_height as isize - current_height as isize) as i8;
        *slot = Some(new_root);
        rebalance_after_insert(&mut path);
        left
    } else {
        // Symmetric to the previous case.
        let mut new_root = linkout_min_or_max(&mut left, false).expect("left tree is not empty");
        let new_left_height = compute_tree_height(&left);
        let mut this = Slot::of(&mut right);
        let mut current_height = right_height;
        while current_height > new_left_height + 1 {
            let slot = this.link();
            if node(slot).prefix.balance == 1 {
                current_height -= 2;
            } else {
                current_height -= 1;
            }
            path.push(this, DIR_LEFT);
            this = Slot::of(&mut node(slot).prefix.left);
        }
        let slot = this.link();
        new_root.prefix.right = slot.take();
        new_root.prefix.left = left;
        new_root.prefix.balance = (current_height as isize - new_left_height as isize) as i8;
        *slot = Some(new_root);
        rebalance_after_insert(&mut path);
        right
    }
}

/// Split a tree into the objects below the split node, the split node's key and the rest.
// Port of erts/emulator/beam/erl_db_catree.c (split_tree), OTP-29.1.1.
pub(crate) fn split_tree(mut root: TreeDbTerm, keypos: usize) -> (Link, Link, Term) {
    if root.prefix.left.is_none() {
        // To get a non-empty split.
        let right = root.prefix.right.take();
        let split_key = right
            .as_ref()
            .expect("a splittable CA-tree base has at least two objects")
            .key(keypos);
        root.prefix.balance = 0;
        return (Some(root), right, split_key);
    }
    let split_key = root.key(keypos);
    let left = root.prefix.left.take();
    let mut right = root.prefix.right.take();
    // insert_TreeDbTerm: the old root goes into the right tree.
    tree_insert(&mut right, root, split_key, keypos, false);
    (left, right, split_key)
}

/// Storage operations shared by the table stack and the CA-tree call-local stack.
pub(crate) trait StackStorage {
    fn clear(&mut self);
    fn push(&mut self, pos: usize, node: NonNull<TreeNode>);
    fn pop(&mut self, pos: usize) -> Option<NonNull<TreeNode>>;
    fn top(&self, pos: usize) -> Option<NonNull<TreeNode>>;
}

pub(crate) struct OwnedStackSlots(Vec<NonNull<TreeNode>>);

pub(crate) struct InlineStackSlots<'a>(&'a mut [Option<NonNull<TreeNode>>]);

impl StackStorage for OwnedStackSlots {
    fn clear(&mut self) {
        self.0.clear();
    }

    fn push(&mut self, _pos: usize, node: NonNull<TreeNode>) {
        self.0.push(node);
    }

    fn pop(&mut self, _pos: usize) -> Option<NonNull<TreeNode>> {
        self.0.pop()
    }

    fn top(&self, _pos: usize) -> Option<NonNull<TreeNode>> {
        self.0.last().copied()
    }
}

impl StackStorage for InlineStackSlots<'_> {
    fn clear(&mut self) {}

    fn push(&mut self, pos: usize, node: NonNull<TreeNode>) {
        self.0[pos] = Some(node);
    }

    fn pop(&mut self, pos: usize) -> Option<NonNull<TreeNode>> {
        self.0.get(pos).and_then(Option::as_ref).copied()
    }

    fn top(&self, pos: usize) -> Option<NonNull<TreeNode>> {
        self.0.get(pos.checked_sub(1)?)?.as_ref().copied()
    }
}

/// The root-to-slot path of `slot_search`, or the call-local path used by CA-tree next/prev.
///
/// Node pointers are dereferenced only while their tree is unchanged. The owner resets the
/// table stack after mutation; CA-tree next/prev resets the local stack at each base.
pub(crate) struct DbTreeStack<S = OwnedStackSlots> {
    entries: S,
    pos: usize,
    slot: usize,
    /// The tree version the entries were taken from.
    pub(crate) version: u64,
}

// SAFETY: the entries point into the tree that owns the stack and are only used under the
// owner's lock with a matching version, like the nodes themselves (`TreeDbTerm` is `Send + Sync`).
unsafe impl Send for DbTreeStack<OwnedStackSlots> {}

/// What `slot_search` found.
pub(crate) enum SlotSearch<'a> {
    Found(&'a TreeNode),
    /// The slot is one past the last object (`is_EOT`).
    EndOfTable,
    /// The slot is further out.
    Out,
}

impl DbTreeStack<OwnedStackSlots> {
    pub(crate) fn new() -> Self {
        Self {
            entries: OwnedStackSlots(Vec::new()),
            pos: 0,
            slot: 0,
            version: 0,
        }
    }
}

impl DbTreeStack<OwnedStackSlots> {
    /// Port of erts/emulator/beam/erl_db_catree.c:1615 (`db_next_catree_common`) and :1679
    /// (`db_prev_catree_common`), OTP-29.1.1: each call owns a `stack_array[STACK_NEED]`.
    pub(crate) fn inline_storage() -> [Option<NonNull<TreeNode>>; STACK_NEED] {
        [None; STACK_NEED]
    }

    /// Bind this stack to the `stack_array` for one CA-tree next/prev call.
    // Port of erts/emulator/beam/erl_db_catree.c:1205 (init_tree_stack), OTP-29.1.1.
    pub(crate) fn with_inline<'storage>(
        storage: &'storage mut [Option<NonNull<TreeNode>>],
    ) -> DbTreeStack<InlineStackSlots<'storage>> {
        DbTreeStack {
            entries: InlineStackSlots(storage),
            pos: 0,
            slot: 0,
            version: 0,
        }
    }
}

impl<S: StackStorage> DbTreeStack<S> {
    /// `reset_stack`.
    pub(crate) fn reset(&mut self, version: u64) {
        self.clear();
        self.slot = 0;
        self.version = version;
    }

    fn clear(&mut self) {
        self.entries.clear();
        self.pos = 0;
    }

    fn push(&mut self, node: &TreeNode) {
        self.entries.push(self.pos, NonNull::from(node));
        self.pos += 1;
    }

    fn pop(&mut self) -> Option<NonNull<TreeNode>> {
        if self.pos == 0 {
            return None;
        }
        self.pos -= 1;
        self.entries.pop(self.pos)
    }

    fn top<'tree>(&self, _tree: &'tree Link) -> Option<&'tree TreeNode> {
        let node = self.entries.top(self.pos)?;
        // SAFETY: entries point into the tree borrowed by `_tree` and that has not been
        // changed since they were pushed (see the type's contract).
        Some(unsafe { node.as_ref() })
    }
}

impl<S: StackStorage> DbTreeStack<S> {
    /// The `slot` the stack top stands for.
    pub(crate) fn slot(&self) -> usize {
        self.slot
    }

    pub(crate) fn set_slot(&mut self, slot: usize) {
        self.slot = slot;
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.pos == 0
    }

    /// Push the path from `root` down to its first object (`db_first_tree_common`'s walk);
    /// false for an empty tree.
    pub(crate) fn push_left_spine(&mut self, root: &Link) -> bool {
        let Some(mut this) = root.as_deref() else {
            return false;
        };
        while let Some(left) = this.prefix.left.as_deref() {
            self.push(this);
            this = left;
        }
        self.push(this);
        true
    }

    /// Push the path from `root` down to its last object (`db_last_tree_common`'s walk).
    pub(crate) fn push_right_spine(&mut self, root: &Link) -> bool {
        let Some(mut this) = root.as_deref() else {
            return false;
        };
        while let Some(right) = this.prefix.right.as_deref() {
            self.push(this);
            this = right;
        }
        self.push(this);
        true
    }

    /// Move the stack top to `slot`, forward or back, inside the tree whose nodes the stack
    /// holds; `None` when the tree has no such object (the stack is then left empty).
    // Port of erts/emulator/beam/erl_db_tree.c (slot_search, the `while (stack->slot != slot)`
    // loop), OTP-29.1.1.
    pub(crate) fn walk_to<'a>(&mut self, slot: usize, tree: &'a Link) -> Option<&'a TreeNode> {
        let mut this = self.top(tree)?;
        while self.slot != slot {
            if slot > self.slot {
                if let Some(right) = this.prefix.right.as_deref() {
                    this = right;
                    while let Some(left) = this.prefix.left.as_deref() {
                        self.push(this);
                        this = left;
                    }
                    self.push(this);
                } else {
                    loop {
                        let tmp = self.pop().expect("stack is not empty here");
                        this = self.top(tree)?;
                        if this
                            .prefix
                            .left
                            .as_deref()
                            .is_some_and(|left| std::ptr::eq(left, tmp.as_ptr()))
                        {
                            break;
                        }
                    }
                }
                self.slot += 1;
            } else {
                if let Some(left) = this.prefix.left.as_deref() {
                    this = left;
                    while let Some(right) = this.prefix.right.as_deref() {
                        self.push(this);
                        this = right;
                    }
                    self.push(this);
                } else {
                    loop {
                        let tmp = self.pop().expect("stack is not empty here");
                        this = self.top(tree)?;
                        if this
                            .prefix
                            .right
                            .as_deref()
                            .is_some_and(|right| std::ptr::eq(right, tmp.as_ptr()))
                        {
                            break;
                        }
                    }
                }
                self.slot -= 1;
            }
        }
        Some(this)
    }

    /// Find the strict successor, reusing the path when its top is the supplied key.
    // Port of erts/emulator/beam/erl_db_tree.c:3167 (find_next), OTP-29.1.1.
    pub(crate) fn find_next<'a>(
        &mut self,
        root: &'a Link,
        key: Term,
        keypos: usize,
    ) -> Option<&'a TreeNode> {
        let mut this = match self.top(root) {
            Some(node) if cmp(key, node.key(keypos)) == Ordering::Equal => node,
            Some(_) => {
                self.clear();
                self.slot = 0;
                root.as_deref()?
            }
            None => root.as_deref()?,
        };
        let mut found_next = false;
        if self.is_empty() {
            loop {
                self.push(this);
                match cmp(key, this.key(keypos)) {
                    Ordering::Greater => match this.prefix.right.as_deref() {
                        Some(right) => this = right,
                        None => break,
                    },
                    Ordering::Less => match this.prefix.left.as_deref() {
                        Some(left) => this = left,
                        None => {
                            found_next = true;
                            break;
                        }
                    },
                    Ordering::Equal => break,
                }
            }
        }

        if !found_next {
            if let Some(right) = this.prefix.right.as_deref() {
                this = right;
                self.push(this);
                while let Some(left) = this.prefix.left.as_deref() {
                    this = left;
                    self.push(this);
                }
            } else {
                let mut child = self.pop()?;
                loop {
                    let Some(parent) = self.top(root) else {
                        self.slot = 0;
                        return None;
                    };
                    if !parent
                        .prefix
                        .right
                        .as_deref()
                        .is_some_and(|right| std::ptr::eq(right, child.as_ptr()))
                    {
                        this = parent;
                        break;
                    }
                    child = self.pop()?;
                }
            }
        }

        if self.slot > 0 {
            self.slot += 1;
        }
        Some(this)
    }

    /// Find the strict predecessor, reusing the path when its top is the supplied key.
    // Port of erts/emulator/beam/erl_db_tree.c:3225 (find_prev), OTP-29.1.1.
    pub(crate) fn find_prev<'a>(
        &mut self,
        root: &'a Link,
        key: Term,
        keypos: usize,
    ) -> Option<&'a TreeNode> {
        let mut this = match self.top(root) {
            Some(node) if cmp(key, node.key(keypos)) == Ordering::Equal => node,
            Some(_) => {
                self.clear();
                self.slot = 0;
                root.as_deref()?
            }
            None => root.as_deref()?,
        };
        let mut found_prev = false;
        if self.is_empty() {
            loop {
                self.push(this);
                match cmp(key, this.key(keypos)) {
                    Ordering::Less => match this.prefix.left.as_deref() {
                        Some(left) => this = left,
                        None => break,
                    },
                    Ordering::Greater => match this.prefix.right.as_deref() {
                        Some(right) => this = right,
                        None => {
                            found_prev = true;
                            break;
                        }
                    },
                    Ordering::Equal => break,
                }
            }
        }

        if !found_prev {
            if let Some(left) = this.prefix.left.as_deref() {
                this = left;
                self.push(this);
                while let Some(right) = this.prefix.right.as_deref() {
                    this = right;
                    self.push(this);
                }
            } else {
                let mut child = self.pop()?;
                loop {
                    let Some(parent) = self.top(root) else {
                        self.slot = 0;
                        return None;
                    };
                    if !parent
                        .prefix
                        .left
                        .as_deref()
                        .is_some_and(|left| std::ptr::eq(left, child.as_ptr()))
                    {
                        this = parent;
                        break;
                    }
                    child = self.pop()?;
                }
            }
        }

        if self.slot > 0 {
            self.slot -= 1;
        }
        Some(this)
    }
}

/// Port of erts/emulator/beam/erl_db_tree.c (slot_search, without a CA-tree iterator),
/// OTP-29.1.1. `slot` counts from 1.
pub(crate) fn slot_search<'a, S: StackStorage>(
    root: &'a Link,
    slot: usize,
    stack: &mut DbTreeStack<S>,
) -> SlotSearch<'a> {
    let end = |stack: &DbTreeStack<S>| {
        if stack.slot == slot - 1 {
            SlotSearch::EndOfTable
        } else {
            SlotSearch::Out
        }
    };
    if slot == 1 {
        // Don't search from where we are if we are looking for the first slot.
        stack.slot = 0;
    }
    if stack.slot == 0 {
        stack.clear();
    }
    if stack.is_empty() {
        if !stack.push_left_spine(root) {
            return end(stack);
        }
        stack.slot += 1;
    }
    match stack.walk_to(slot, root) {
        Some(found) => SlotSearch::Found(found),
        None => end(stack),
    }
}
