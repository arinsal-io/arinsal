//! The ETS stored object as one allocation, as erts lays out a `DbTerm`.
//!
//! Port of the layout of erts/emulator/beam/erl_db_util.h (`DbTerm`), erl_db_hash.h
//! (`HashDbTerm`) and erl_db_util.c (`db_store_term`, `db_free_term`), OTP-29.1.1: the table's
//! link fields, the `DbTerm` bookkeeping and the term's heap words are one block that is
//! allocated once and freed once. This module holds the only raw allocation of the crate's
//! stored objects; everything else reaches the words through the safe slice field.

use super::{EtsError, OffHeap};
use arinsal_term::{
    ExternalBinary, HeapAlloc, MagicRef, Node as TermNode, Term, TermError, WritableBinary, cmp,
};
use std::alloc::{Layout, alloc_zeroed, handle_alloc_error};
use std::cmp::Ordering;
use std::ptr::NonNull;
use std::sync::Arc;

use super::Compressed;

/// A stored object: the table links, the `DbTerm` fields and, after them, the words of the
/// term. `W = [u64]` is the unsized form every table works with.
// Port of erts/emulator/beam/erl_db_util.h (DbTerm) and erl_db_hash.h (HashDbTerm), OTP-29.1.1.
#[repr(C)]
pub(crate) struct StoredTermG<W: ?Sized> {
    /// `HashDbTerm.next`; `TreeDbTerm.left` of a tree node.
    pub(crate) next: Option<Box<StoredTermG<[u64]>>>,
    /// `TreeDbTerm.right`.
    pub(crate) right: Option<Box<StoredTermG<[u64]>>>,
    /// `TreeDbTerm.balance`.
    pub(crate) balance: i8,
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
            right: None,
            balance: 0,
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

// ---------------------------------------------------------------------------------------------
// The AVL tree of an ordered_set: nodes are `StoredTerm` blocks linked through `next` (left) and
// `right`. The algorithms below keep erts' stacks of `TreeDbTerm **` slots, raw pointers to the
// link fields of the nodes above the one being changed.
// ---------------------------------------------------------------------------------------------

/// A `TreeDbTerm *`.
pub(crate) type Link = Option<DbTerm>;

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
    slots: [*mut Link; STACK_NEED],
    dirs: [u8; STACK_NEED + 1],
    tpos: usize,
    dpos: usize,
}

impl Path {
    fn new() -> Self {
        let mut dirs = [DIR_END; STACK_NEED + 1];
        dirs[0] = DIR_END;
        Self {
            slots: [std::ptr::null_mut(); STACK_NEED],
            dirs,
            tpos: 0,
            dpos: 1,
        }
    }

    fn push(&mut self, slot: *mut Link, dir: u8) {
        self.slots[self.tpos] = slot;
        self.tpos += 1;
        self.dirs[self.dpos] = dir;
        self.dpos += 1;
    }

    /// `dir = dstack[--dpos]; this = tstack[--tpos]`, or `None` at `DIR_END`.
    fn pop(&mut self) -> Option<(*mut Link, u8)> {
        if self.dpos <= 1 {
            return None;
        }
        self.dpos -= 1;
        self.tpos -= 1;
        Some((self.slots[self.tpos], self.dirs[self.dpos]))
    }
}

fn node(link: &mut Link) -> &mut DbTerm {
    link.as_mut().expect("AVL slot holds a node")
}

/// Port of erts/emulator/beam/erl_db_tree.c (tree_balance_left), OTP-29.1.1. Returns whether
/// the height of the subtree decreased.
pub(crate) fn tree_balance_left(this: &mut Link) -> bool {
    match node(this).balance {
        -1 => {
            node(this).balance = 0;
            true
        }
        0 => {
            node(this).balance = 1;
            false
        }
        _ => {
            let mut p = this.take().expect("AVL slot holds a node");
            let mut p1 = p.right.take().expect("right-heavy node has a right child");
            let b1 = p1.balance;
            let mut h = true;
            if b1 >= 0 {
                // Single RR rotation
                p.right = p1.next.take();
                if b1 == 0 {
                    p.balance = 1;
                    p1.balance = -1;
                    h = false;
                } else {
                    p.balance = 0;
                    p1.balance = 0;
                }
                p1.next = Some(p);
                *this = Some(p1);
            } else {
                // Double RL rotation
                let mut p2 = p1.next.take().expect("RL rotation needs a grandchild");
                let b2 = p2.balance;
                p1.next = p2.right.take();
                p.right = p2.next.take();
                p.balance = if b2 == 1 { -1 } else { 0 };
                p1.balance = if b2 == -1 { 1 } else { 0 };
                p2.balance = 0;
                p2.right = Some(p1);
                p2.next = Some(p);
                *this = Some(p2);
            }
            h
        }
    }
}

/// Port of erts/emulator/beam/erl_db_tree.c (tree_balance_right), OTP-29.1.1.
pub(crate) fn tree_balance_right(this: &mut Link) -> bool {
    match node(this).balance {
        1 => {
            node(this).balance = 0;
            true
        }
        0 => {
            node(this).balance = -1;
            false
        }
        _ => {
            let mut p = this.take().expect("AVL slot holds a node");
            let mut p1 = p.next.take().expect("left-heavy node has a left child");
            let b1 = p1.balance;
            let mut h = true;
            if b1 <= 0 {
                // Single LL rotation
                p.next = p1.right.take();
                if b1 == 0 {
                    p.balance = -1;
                    p1.balance = 1;
                    h = false;
                } else {
                    p.balance = 0;
                    p1.balance = 0;
                }
                p1.right = Some(p);
                *this = Some(p1);
            } else {
                // Double LR rotation
                let mut p2 = p1.right.take().expect("LR rotation needs a grandchild");
                let b2 = p2.balance;
                p1.right = p2.next.take();
                p.next = p2.right.take();
                p.balance = if b2 == -1 { 1 } else { 0 };
                p1.balance = if b2 == 1 { -1 } else { 0 };
                p2.balance = 0;
                p2.next = Some(p1);
                p2.right = Some(p);
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
        // SAFETY: `this` is a link field of a node on the path from the root (or the root
        // slot); rotations below it only exchange which block sits in a slot and free nothing.
        let this = unsafe { &mut *this };
        let balance = node(this).balance;
        if dir == DIR_LEFT {
            match balance {
                1 => {
                    node(this).balance = 0;
                    return;
                }
                0 => node(this).balance = -1,
                _ => {
                    let mut p = this.take().expect("AVL slot holds a node");
                    let mut p1 = p.next.take().expect("left-heavy node has a left child");
                    if p1.balance == -1 {
                        // Single LL rotation
                        p.next = p1.right.take();
                        p.balance = 0;
                        p1.right = Some(p);
                        *this = Some(p1);
                    } else {
                        // Double RR rotation
                        let mut p2 = p1.right.take().expect("RR rotation needs a grandchild");
                        p1.right = p2.next.take();
                        p.next = p2.right.take();
                        p.balance = if p2.balance == -1 { 1 } else { 0 };
                        p1.balance = if p2.balance == 1 { -1 } else { 0 };
                        p2.next = Some(p1);
                        p2.right = Some(p);
                        *this = Some(p2);
                    }
                    node(this).balance = 0;
                    return;
                }
            }
        } else {
            match balance {
                -1 => {
                    node(this).balance = 0;
                    return;
                }
                0 => node(this).balance = 1,
                _ => {
                    let mut p = this.take().expect("AVL slot holds a node");
                    let mut p1 = p.right.take().expect("right-heavy node has a right child");
                    if p1.balance == 1 {
                        // Single RR rotation
                        p.right = p1.next.take();
                        p.balance = 0;
                        p1.next = Some(p);
                        *this = Some(p1);
                    } else {
                        // Double RL rotation
                        let mut p2 = p1.next.take().expect("RL rotation needs a grandchild");
                        p1.next = p2.right.take();
                        p.right = p2.next.take();
                        p.balance = if p2.balance == 1 { -1 } else { 0 };
                        p1.balance = if p2.balance == -1 { 1 } else { 0 };
                        p2.right = Some(p1);
                        p2.next = Some(p);
                        *this = Some(p2);
                    }
                    node(this).balance = 0;
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
        // SAFETY: as in `rebalance_after_insert`.
        let this = unsafe { &mut *this };
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
    mut value: DbTerm,
    key: Term,
    keypos: usize,
    key_clash_fail: bool,
) -> InsertResult {
    let mut path = Path::new();
    let mut this: *mut Link = root;
    loop {
        // SAFETY: `this` is the root slot or a child link of a node reached from it; nothing
        // else refers to the tree during this call.
        let slot = unsafe { &mut *this };
        let order = match slot.as_ref() {
            None => {
                value.balance = 0;
                value.next = None;
                value.right = None;
                *slot = Some(value);
                rebalance_after_insert(&mut path);
                return InsertResult::Inserted;
            }
            Some(current) => cmp(key, current.key(keypos)),
        };
        match order {
            Ordering::Less => {
                path.push(this, DIR_LEFT);
                this = &mut node(slot).next;
            }
            Ordering::Greater => {
                path.push(this, DIR_RIGHT);
                this = &mut node(slot).right;
            }
            Ordering::Equal if !key_clash_fail => {
                let mut old = slot.take().expect("slot checked above");
                value.balance = old.balance;
                value.next = old.next.take();
                value.right = old.right.take();
                let words = old.db_size_words;
                *slot = Some(value);
                return InsertResult::Replaced(words);
            }
            Ordering::Equal => return InsertResult::Exists,
        }
    }
}

/// Port of erts/emulator/beam/erl_db_tree.c (delsub), OTP-29.1.1: replace the node in `this`,
/// which has two children, by its in-order predecessor; returns the removed node and whether
/// the left subtree got shorter.
fn delsub(this: &mut Link) -> (DbTerm, bool) {
    let mut q = this.take().expect("AVL slot holds a node");
    let mut slots = [std::ptr::null_mut::<Link>(); STACK_NEED];
    let mut tpos = 0;
    let mut r: *mut Link = &mut q.next;
    // Walk down to the right looking for a void right child.
    // SAFETY: `r` is the left link of `q` or a right link of a node below it.
    while unsafe { &*r }.as_ref().is_some_and(|n| n.right.is_some()) {
        slots[tpos] = r;
        tpos += 1;
        // SAFETY: as above.
        r = &mut node(unsafe { &mut *r }).right;
    }
    // SAFETY: as above.
    let mut pred = unsafe { &mut *r }.take().expect("predecessor exists");
    // SAFETY: as above.
    *unsafe { &mut *r } = pred.next.take();
    pred.next = q.next.take();
    pred.right = q.right.take();
    pred.balance = q.balance;
    *this = Some(pred);
    slots[0] = &mut node(this).next;
    let mut h = true;
    while tpos > 0 && h {
        tpos -= 1;
        // SAFETY: a slot of the predecessor's left subtree or its own left link.
        h = tree_balance_right(unsafe { &mut *slots[tpos] });
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
) -> Option<DbTerm> {
    let mut path = Path::new();
    let mut this: *mut Link = root;
    let removed;
    let state;
    loop {
        // SAFETY: as in `tree_insert`.
        let slot = unsafe { &mut *this };
        let order = cmp(key, slot.as_ref()?.key(keypos));
        match order {
            Ordering::Less => {
                path.push(this, DIR_LEFT);
                this = &mut node(slot).next;
            }
            Ordering::Greater => {
                path.push(this, DIR_RIGHT);
                this = &mut node(slot).right;
            }
            Ordering::Equal => {
                if !matches(slot.as_ref().expect("slot checked above")) {
                    return None;
                }
                let q = node(slot);
                if q.right.is_none() {
                    let mut q = slot.take().expect("slot checked above");
                    *slot = q.next.take();
                    removed = q;
                    state = true;
                } else if q.next.is_none() {
                    let mut q = slot.take().expect("slot checked above");
                    *slot = q.right.take();
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
fn linkout_min_or_max(root: &mut Link, is_min: bool) -> Option<DbTerm> {
    let mut path = Path::new();
    let mut this: *mut Link = root;
    let removed;
    let state;
    loop {
        // SAFETY: as in `tree_insert`.
        let slot = unsafe { &mut *this };
        let current = slot.as_mut()?;
        if is_min && current.next.is_some() {
            path.push(this, DIR_LEFT);
            this = &mut current.next;
        } else if !is_min && current.right.is_some() {
            path.push(this, DIR_RIGHT);
            this = &mut current.right;
        } else {
            let mut q = slot.take().expect("slot checked above");
            if q.right.is_none() {
                *slot = q.next.take();
            } else {
                *slot = q.right.take();
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
    while current.next.is_some() || current.right.is_some() {
        current = if current.balance == -1 {
            current
                .next
                .as_deref()
                .expect("left-heavy node has a left child")
        } else {
            current.right.as_deref().expect("node has a right child")
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
        let mut this: *mut Link = &mut left;
        let mut current_height = left_height;
        while current_height > new_right_height + 1 {
            // SAFETY: `this` is the `left` slot or a right link of a node below it.
            let slot = unsafe { &mut *this };
            if node(slot).balance == -1 {
                current_height -= 2;
            } else {
                current_height -= 1;
            }
            path.push(this, DIR_RIGHT);
            this = &mut node(slot).right;
        }
        // SAFETY: as above.
        let slot = unsafe { &mut *this };
        new_root.next = slot.take();
        new_root.right = right;
        new_root.balance = (new_right_height as isize - current_height as isize) as i8;
        *slot = Some(new_root);
        rebalance_after_insert(&mut path);
        left
    } else {
        // Symmetric to the previous case.
        let mut new_root = linkout_min_or_max(&mut left, false).expect("left tree is not empty");
        let new_left_height = compute_tree_height(&left);
        let mut this: *mut Link = &mut right;
        let mut current_height = right_height;
        while current_height > new_left_height + 1 {
            // SAFETY: `this` is the `right` slot or a left link of a node below it.
            let slot = unsafe { &mut *this };
            if node(slot).balance == 1 {
                current_height -= 2;
            } else {
                current_height -= 1;
            }
            path.push(this, DIR_LEFT);
            this = &mut node(slot).next;
        }
        // SAFETY: as above.
        let slot = unsafe { &mut *this };
        new_root.right = slot.take();
        new_root.next = left;
        new_root.balance = (current_height as isize - new_left_height as isize) as i8;
        *slot = Some(new_root);
        rebalance_after_insert(&mut path);
        right
    }
}

/// Split a tree into the objects below the split node, the split node's key and the rest.
// Port of erts/emulator/beam/erl_db_catree.c (split_tree), OTP-29.1.1.
pub(crate) fn split_tree(mut root: DbTerm, keypos: usize) -> (Link, Link, Term) {
    if root.next.is_none() {
        // To get a non-empty split.
        let right = root.right.take();
        let split_key = right
            .as_ref()
            .expect("a splittable CA-tree base has at least two objects")
            .key(keypos);
        root.balance = 0;
        return (Some(root), right, split_key);
    }
    let split_key = root.key(keypos);
    let left = root.next.take();
    let mut right = root.right.take();
    // insert_TreeDbTerm: the old root goes into the right tree.
    tree_insert(&mut right, root, split_key, keypos, false);
    (left, right, split_key)
}

/// `DbTreeStack` of erl_db_tree_util.h: the nodes from the root down to the last slot visited
/// by `slot_search`, kept between `ets:slot/2` calls.
///
/// The node pointers are only dereferenced while the tree is unchanged: the owner resets the
/// stack on every change (`TreeRoot::version`).
pub(crate) struct DbTreeStack {
    entries: Vec<NonNull<StoredTerm>>,
    slot: usize,
    /// The tree version the entries were taken from.
    pub(crate) version: u64,
}

// SAFETY: the entries point into the tree that owns the stack and are only used under the
// owner's lock with a matching version, like the nodes themselves (`DbTerm` is `Send + Sync`).
unsafe impl Send for DbTreeStack {}

/// What `slot_search` found.
pub(crate) enum SlotSearch<'a> {
    Found(&'a StoredTerm),
    /// The slot is one past the last object (`is_EOT`).
    EndOfTable,
    /// The slot is further out.
    Out,
}

impl DbTreeStack {
    pub(crate) fn new() -> Self {
        Self {
            entries: Vec::new(),
            slot: 0,
            version: 0,
        }
    }

    /// `reset_stack`.
    pub(crate) fn reset(&mut self, version: u64) {
        self.entries.clear();
        self.slot = 0;
        self.version = version;
    }

    fn push(&mut self, node: &StoredTerm) {
        self.entries.push(NonNull::from(node));
    }

    fn top<'a>(&self) -> Option<&'a StoredTerm> {
        // SAFETY: entries point into the tree the caller borrows for `'a` and that has not been
        // changed since they were pushed (see the type's contract).
        self.entries.last().map(|node| unsafe { node.as_ref() })
    }
}

/// Port of erts/emulator/beam/erl_db_tree.c (slot_search, without a CA-tree iterator),
/// OTP-29.1.1. `slot` counts from 1.
pub(crate) fn slot_search<'a>(
    root: &'a Link,
    slot: usize,
    stack: &mut DbTreeStack,
) -> SlotSearch<'a> {
    let end = |stack: &DbTreeStack| {
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
        stack.entries.clear();
    }
    if stack.entries.is_empty() {
        let Some(mut this) = root.as_deref() else {
            return end(stack);
        };
        while let Some(left) = this.next.as_deref() {
            stack.push(this);
            this = left;
        }
        stack.push(this);
        stack.slot += 1;
    }
    let mut this = stack.top().expect("stack holds the leftmost node");
    while stack.slot != slot {
        if slot > stack.slot {
            if let Some(right) = this.right.as_deref() {
                this = right;
                while let Some(left) = this.next.as_deref() {
                    stack.push(this);
                    this = left;
                }
                stack.push(this);
            } else {
                loop {
                    let tmp = stack.entries.pop().expect("stack is not empty here");
                    let Some(parent) = stack.top() else {
                        return end(stack);
                    };
                    this = parent;
                    if this
                        .next
                        .as_deref()
                        .is_some_and(|left| std::ptr::eq(left, tmp.as_ptr()))
                    {
                        break;
                    }
                }
            }
            stack.slot += 1;
        } else {
            if let Some(left) = this.next.as_deref() {
                this = left;
                while let Some(right) = this.right.as_deref() {
                    stack.push(this);
                    this = right;
                }
                stack.push(this);
            } else {
                loop {
                    let tmp = stack.entries.pop().expect("stack is not empty here");
                    let Some(parent) = stack.top() else {
                        return end(stack);
                    };
                    this = parent;
                    if this
                        .right
                        .as_deref()
                        .is_some_and(|right| std::ptr::eq(right, tmp.as_ptr()))
                    {
                        break;
                    }
                }
            }
            stack.slot -= 1;
        }
    }
    SlotSearch::Found(this)
}
