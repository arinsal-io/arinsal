//! Monitor and link nodes and the per-process containers that hold them: red-black trees keyed
//! by reference or pid, and doubly linked circular lists. A monitor keeps both of its halves in
//! one allocation, so the origin and the target process each own one node of it; a local link is
//! one node per process.
//!
//! Port of erts/emulator/beam/erl_monitor_link.h/.c (`ErtsMonLnkNode`, `ErtsMonitorData`,
//! `ErtsILink`, the `erts_monitor_tree_*`, `erts_monitor_list_*`, `erts_link_tree_*` operations,
//! `erts_monitor_release`) and the tree operations erl_rbtree.h instantiates for them as
//! `mon_lnk_rbt_*` (insert, delete, lookup, unordered foreach and foreach_destroy), OTP-29.1.1.
//!
//! All raw-pointer work on nodes is confined to this module. Nodes are reached only through:
//! - owned handles ([`Monitor`], [`Link`]), each owning one node (erts: the half a process holds
//!   and releases with `erts_monitor_release` / `erts_link_release`);
//! - containers ([`MonLnkTree`], [`MonitorList`]) that take handles in and give them back out;
//! - borrowed views ([`MonitorRef`], [`MonitorMut`], [`LinkRef`], [`LinkMut`]) whose lifetime is
//!   tied to the container or handle they came from.
//!
//! Deviations from erts, both for a sound safe interface:
//! - The keys are the VM's 64-bit reference ids and pid data rather than terms; references
//!   compare as erts `ml_cmp_keys` compares internal references (memcmp of the reference
//!   number words), pids by value.
//! - A [`MonitorData`] records which [`MonitorList`] holds its target half (`target_list`), so
//!   removing the target through the origin half can check that the node is in this list.

use std::cell::UnsafeCell;
use std::cmp::Ordering;
use std::marker::PhantomData;
use std::mem::offset_of;
use std::ptr::NonNull;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering as AtomicOrdering};

type NodePtr = NonNull<MonLnkNode>;

/// Monitor and link node types (`ERTS_MON_TYPE_*`, `ERTS_LNK_TYPE_*`).
#[allow(dead_code)]
pub(crate) mod node_type {
    pub(crate) const MONITOR_PROC: u32 = 0;
    pub(crate) const MONITOR_PORT: u32 = 1;
    pub(crate) const MONITOR_TIME_OFFSET: u32 = 2;
    pub(crate) const MONITOR_DIST_PROC: u32 = 3;
    pub(crate) const MONITOR_DIST_PORT: u32 = 4;
    pub(crate) const MONITOR_RESOURCE: u32 = 5;
    pub(crate) const MONITOR_NODE: u32 = 6;
    pub(crate) const MONITOR_NODES: u32 = 7;
    pub(crate) const MONITOR_SUSPEND: u32 = 8;
    pub(crate) const MONITOR_ALIAS: u32 = 9;
    pub(crate) const LINK_PROC: u32 = MONITOR_ALIAS + 1;
    pub(crate) const LINK_PORT: u32 = MONITOR_ALIAS + 2;
    pub(crate) const LINK_DIST_PROC: u32 = MONITOR_ALIAS + 3;
    pub(crate) const LINK_DIST_PORT: u32 = MONITOR_ALIAS + 4;
}

/// Node flags (`ERTS_ML_*` in erl_monitor_link.h).
#[allow(dead_code)]
pub(crate) mod node_flag {
    const TYPE_BITS: u32 = 5;
    pub(crate) const TYPE_MASK: u32 = (1 << TYPE_BITS) - 1;
    const STATE_ALIAS_BITS: u32 = 2;
    const STATE_ALIAS_SHIFT: u32 = TYPE_BITS;
    pub(crate) const STATE_ALIAS_MASK: u32 = ((1 << STATE_ALIAS_BITS) - 1) << STATE_ALIAS_SHIFT;
    pub(crate) const STATE_ALIAS_NONE: u32 = 0;
    pub(crate) const STATE_ALIAS_UNALIAS: u32 = 1 << STATE_ALIAS_SHIFT;
    pub(crate) const STATE_ALIAS_DEMONITOR: u32 = 2 << STATE_ALIAS_SHIFT;
    pub(crate) const STATE_ALIAS_ONCE: u32 = 3 << STATE_ALIAS_SHIFT;
    const BASE: u32 = TYPE_BITS + STATE_ALIAS_BITS;
    pub(crate) const TARGET: u32 = 1 << BASE;
    pub(crate) const IN_TABLE: u32 = 1 << (BASE + 1);
    pub(crate) const IN_SUBTABLE: u32 = 1 << (BASE + 2);
    pub(crate) const NAME: u32 = 1 << (BASE + 3);
    pub(crate) const EXTENDED: u32 = 1 << (BASE + 4);
    pub(crate) const SPAWN_PENDING: u32 = 1 << (BASE + 5);
    pub(crate) const SPAWN_MONITOR: u32 = 1 << (BASE + 6);
    pub(crate) const SPAWN_LINK: u32 = 1 << (BASE + 7);
    pub(crate) const SPAWN_ABANDONED: u32 = 1 << (BASE + 8);
    pub(crate) const SPAWN_NO_SMSG: u32 = 1 << (BASE + 9);
    pub(crate) const SPAWN_NO_EMSG: u32 = 1 << (BASE + 10);
    pub(crate) const TAG: u32 = 1 << (BASE + 11);
    pub(crate) const PRIO_ML: u32 = 1 << (BASE + 12);
    pub(crate) const PRIO_ALIAS: u32 = 1 << (BASE + 13);
    pub(crate) const SPAWN_LINK_PRIO: u32 = 1 << (BASE + 14);
    /// The monitor key is a PID reference; its creator is the other pid in `MonitorData`.
    pub(crate) const PID_REF: u32 = 1 << (BASE + 15);
    /// Flags a holder may not change: the container state and the half's identity.
    pub(crate) const RESERVED: u32 = TYPE_MASK | TARGET | IN_TABLE;
}

/// `ERTS_ML_TPFLG_RED`: the colour bit kept in the low bit of the parent word.
const RED: usize = 1;

/// Tree links (`ErtsMonLnkTreeNode`): parent pointer and colour, right, left.
#[repr(C)]
#[derive(Clone, Copy)]
struct TreeLinks {
    parent: usize,
    right: Option<NodePtr>,
    left: Option<NodePtr>,
}

/// List links (`ErtsMonLnkListNode`).
#[repr(C)]
#[derive(Clone, Copy)]
struct ListLinks {
    next: Option<NodePtr>,
    prev: Option<NodePtr>,
}

/// The container links of a node: a node is in at most one tree or list at a time.
#[repr(C)]
union NodeLinks {
    tree: TreeLinks,
    list: ListLinks,
}

/// One monitor half or link (`ErtsMonLnkNode`).
#[repr(C)]
pub(crate) struct MonLnkNode {
    node: NodeLinks,
    /// `other.item`: the pid (data) or other id at the far end.
    other: u64,
    /// Offset from the start of the containing structure to this node.
    offset: u16,
    /// Offset from this node to its key.
    key_offset: u16,
    flags: u32,
}

impl MonLnkNode {
    fn new(other: u64, offset: usize, key_offset: usize, flags: u32) -> Self {
        Self {
            node: NodeLinks {
                tree: TreeLinks {
                    parent: 0,
                    right: None,
                    left: None,
                },
            },
            other,
            offset: u16::try_from(offset).expect("node offset fits"),
            key_offset: u16::try_from(key_offset).expect("key offset fits"),
            flags,
        }
    }
}

/// Order of keys in a tree (erts `ml_cmp_keys` for the key kinds this tree holds).
pub(crate) trait KeyOrder {
    fn compare(left: u64, right: u64) -> Ordering;
}

/// References compare as erts compares internal references: memcmp of the reference number
/// words (`internal_non_magic_ref_thing_numbers`).
pub(crate) struct ReferenceOrder;

impl KeyOrder for ReferenceOrder {
    fn compare(left: u64, right: u64) -> Ordering {
        let bytes = |reference: u64| {
            arinsal_bifs::ordinary_ref_words(reference)
                .into_iter()
                .flat_map(u32::to_le_bytes)
        };
        bytes(left).cmp(bytes(right))
    }
}

/// Pids compare by value, as erts compares immediate keys of one tag.
pub(crate) struct PidOrder;

impl KeyOrder for PidOrder {
    /// Port of erts/emulator/beam/erl_monitor_link.c (ml_cmp_keys), OTP-29.1.1: immediate
    /// keys by value before boxed external pid keys, which compare by their contents.
    fn compare(left: u64, right: u64) -> Ordering {
        match (is_external_key(left), is_external_key(right)) {
            (false, false) => left.cmp(&right),
            (false, true) => Ordering::Less,
            (true, false) => Ordering::Greater,
            (true, true) => {
                let pid = |key: u64| (key & !EXTERNAL_KEY) as *const ExternalPid;
                // SAFETY: a key with `EXTERNAL_KEY` is made only by `ExternalPid::key`, from an
                // external pid inside a live `ELink` in the tree or one the looking-up caller
                // borrows for the whole lookup.
                unsafe { external_ml_cmp(&*pid(left), &*pid(right)) }
            }
        }
    }
}

/// A handle that owns one node.
pub(crate) trait NodeHandle: Sized {
    /// Key order of the trees holding this kind of node.
    type Order: KeyOrder;
    /// Give up ownership of the node to a container.
    fn into_node(self) -> NodePtr;
    /// Take ownership of a node a container held, which came from `into_node` of this type.
    fn from_node(node: ContainedNode<Self>) -> Self;
}

/// A node taken out of a container, to be turned back into its handle type.
pub(crate) struct ContainedNode<H> {
    node: NodePtr,
    _handle: PhantomData<H>,
}

/// Read a node's key through its key offset (`ml_get_key`).
fn node_key(node: NodePtr) -> u64 {
    // SAFETY: `node` points to a live node inside the allocation it was created in, with the
    // full provenance of that allocation; `key_offset` was set at creation to the distance from
    // the node to a `u64` key in the same allocation that is never written after creation.
    unsafe {
        let key_offset = (*node.as_ptr()).key_offset as usize;
        node.as_ptr()
            .cast::<u8>()
            .add(key_offset)
            .cast::<u64>()
            .read()
    }
}

fn node_flags(node: NodePtr) -> u32 {
    // SAFETY: `node` is live and only the process that owns it reads or writes its flags.
    unsafe { (*node.as_ptr()).flags }
}

fn set_node_flags(node: NodePtr, flags: u32) {
    // SAFETY: as in `node_flags`; the caller holds exclusive access to the node.
    unsafe { (*node.as_ptr()).flags = flags }
}

fn node_other(node: NodePtr) -> u64 {
    // SAFETY: as in `node_flags`.
    unsafe { (*node.as_ptr()).other }
}

/// The containing structure of a node (`erts_ml_node_to_main_struct__`).
fn node_to_main(node: NodePtr) -> NonNull<u8> {
    // SAFETY: `offset` is the distance from the start of the containing allocation to the node,
    // set at creation, and `node` carries that allocation's provenance.
    unsafe {
        let offset = (*node.as_ptr()).offset as usize;
        NonNull::new_unchecked(node.as_ptr().cast::<u8>().sub(offset))
    }
}

// Tree link accessors (`ERTS_RBT_GET_*` / `ERTS_RBT_SET_*` of erl_monitor_link.c). Every node
// passed here is in the tree the caller holds exclusively, so its links are the tree links.

fn tree_links(node: NodePtr) -> TreeLinks {
    // SAFETY: see the comment above the tree link accessors.
    unsafe { (*node.as_ptr()).node.tree }
}

fn tree_links_mut<'a>(node: NodePtr) -> &'a mut TreeLinks {
    // SAFETY: see the comment above the tree link accessors; no other reference to these links
    // is alive while the tree operation that holds the returned one runs.
    unsafe { &mut (*node.as_ptr()).node.tree }
}

fn parent(node: NodePtr) -> Option<NodePtr> {
    NonNull::new((tree_links(node).parent & !RED) as *mut MonLnkNode)
}

fn set_parent(node: NodePtr, parent: Option<NodePtr>) {
    let links = tree_links_mut(node);
    links.parent = (links.parent & RED) | parent.map_or(0, |parent| parent.as_ptr() as usize);
}

fn left(node: NodePtr) -> Option<NodePtr> {
    tree_links(node).left
}

fn right(node: NodePtr) -> Option<NodePtr> {
    tree_links(node).right
}

fn set_left(node: NodePtr, child: Option<NodePtr>) {
    tree_links_mut(node).left = child;
}

fn set_right(node: NodePtr, child: Option<NodePtr>) {
    tree_links_mut(node).right = child;
}

fn is_red(node: NodePtr) -> bool {
    tree_links(node).parent & RED != 0
}

fn is_black(node: Option<NodePtr>) -> bool {
    node.is_none_or(|node| !is_red(node))
}

fn set_red(node: NodePtr) {
    tree_links_mut(node).parent |= RED;
}

fn set_black(node: NodePtr) {
    tree_links_mut(node).parent &= !RED;
}

fn color(node: NodePtr) -> usize {
    tree_links(node).parent & RED
}

fn set_color(node: NodePtr, color: usize) {
    let links = tree_links_mut(node);
    links.parent = (links.parent & !RED) | color;
}

/// A red-black tree of monitor or link nodes (`ERTS_P_MONITORS`, `ERTS_P_LINKS`).
pub(crate) struct MonLnkTree<H: NodeHandle> {
    root: Option<NodePtr>,
    _handles: PhantomData<H>,
}

// SAFETY: the tree owns its nodes as the handles it took in did; it is as `Send` as they are.
unsafe impl<H: NodeHandle + Send> Send for MonLnkTree<H> {}

impl<H: NodeHandle> Default for MonLnkTree<H> {
    fn default() -> Self {
        Self {
            root: None,
            _handles: PhantomData,
        }
    }
}

impl<H: NodeHandle> Drop for MonLnkTree<H> {
    fn drop(&mut self) {
        for handle in self.drain() {
            drop(handle);
        }
    }
}

impl<H: NodeHandle> MonLnkTree<H> {
    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.root.is_none()
    }

    /// `mon_lnk_rbt_lookup`.
    fn lookup_node(&self, key: u64) -> Option<NodePtr> {
        let mut x = self.root?;
        loop {
            match H::Order::compare(key, node_key(x)) {
                Ordering::Equal => return Some(x),
                Ordering::Less => x = left(x)?,
                Ordering::Greater => x = right(x)?,
            }
        }
    }

    /// `left_rotate__`.
    fn left_rotate(&mut self, x: NodePtr) {
        let y = right(x).expect("left rotation needs a right child");
        let l = left(y);
        set_right(x, l);
        if let Some(l) = l {
            set_parent(l, Some(x));
        }
        let p = parent(x);
        set_parent(y, p);
        match p {
            None => self.root = Some(y),
            Some(p) if left(p) == Some(x) => set_left(p, Some(y)),
            Some(p) => set_right(p, Some(y)),
        }
        set_left(y, Some(x));
        set_parent(x, Some(y));
    }

    /// `right_rotate__`.
    fn right_rotate(&mut self, x: NodePtr) {
        let y = left(x).expect("right rotation needs a left child");
        let r = right(y);
        set_left(x, r);
        if let Some(r) = r {
            set_parent(r, Some(x));
        }
        let p = parent(x);
        set_parent(y, p);
        match p {
            None => self.root = Some(y),
            Some(p) if right(p) == Some(x) => set_right(p, Some(y)),
            Some(p) => set_left(p, Some(y)),
        }
        set_right(y, Some(x));
        set_parent(x, Some(y));
    }

    /// `replace__`: put `y` where `x` is.
    fn replace_node(&mut self, x: NodePtr, y: NodePtr) {
        let p = parent(x);
        match p {
            None => self.root = Some(y),
            Some(p) if left(p) == Some(x) => set_left(p, Some(y)),
            Some(p) => set_right(p, Some(y)),
        }
        let l = left(x);
        if let Some(l) = l {
            set_parent(l, Some(y));
        }
        let r = right(x);
        if let Some(r) = r {
            set_parent(r, Some(y));
        }
        set_color(y, color(x));
        set_parent(y, p);
        set_right(y, r);
        set_left(y, l);
    }

    /// `insert_fixup__`.
    fn insert_fixup(&mut self, n: NodePtr) {
        let mut x = n;
        loop {
            let mut p = parent(x).expect("red node has a parent");
            let mut pp = parent(p).expect("red parent has a parent");
            if Some(p) == left(pp) {
                let y = right(pp);
                if let Some(y) = y.filter(|y| is_red(*y)) {
                    set_black(y);
                    set_black(p);
                    set_red(pp);
                    x = pp;
                } else {
                    if Some(x) == right(p) {
                        x = p;
                        self.left_rotate(x);
                        p = parent(x).expect("rotated node has a parent");
                        pp = parent(p).expect("rotated parent has a parent");
                    }
                    set_black(p);
                    set_red(pp);
                    self.right_rotate(pp);
                    break;
                }
            } else {
                let y = left(pp);
                if let Some(y) = y.filter(|y| is_red(*y)) {
                    set_black(y);
                    set_black(p);
                    set_red(pp);
                    x = pp;
                } else {
                    if Some(x) == left(p) {
                        x = p;
                        self.right_rotate(x);
                        p = parent(x).expect("rotated node has a parent");
                        pp = parent(p).expect("rotated parent has a parent");
                    }
                    set_black(p);
                    set_red(pp);
                    self.left_rotate(pp);
                    break;
                }
            }
            if Some(x) == self.root || parent(x).is_none_or(|p| !is_red(p)) {
                break;
            }
        }
        set_black(self.root.expect("tree has a root"));
    }

    /// `insert_aux__`: insert `n`, or with `lookup` return the node already holding its key.
    fn insert_aux(&mut self, n: NodePtr, lookup: bool) -> Option<NodePtr> {
        let key = node_key(n);
        *tree_links_mut(n) = TreeLinks {
            parent: 0,
            right: None,
            left: None,
        };
        let Some(mut x) = self.root else {
            set_black(n);
            self.root = Some(n);
            return None;
        };
        let p = loop {
            let order = H::Order::compare(key, node_key(x));
            if lookup && order == Ordering::Equal {
                return Some(x);
            }
            if order == Ordering::Less {
                match left(x) {
                    Some(child) => x = child,
                    None => {
                        set_parent(n, Some(x));
                        set_left(x, Some(n));
                        break x;
                    }
                }
            } else {
                match right(x) {
                    Some(child) => x = child,
                    None => {
                        set_parent(n, Some(x));
                        set_right(x, Some(n));
                        break x;
                    }
                }
            }
        };
        set_red(n);
        if is_red(p) {
            self.insert_fixup(n);
        }
        None
    }

    /// `ml_rbt_insert`: the key must not be in the tree.
    pub(crate) fn insert(&mut self, handle: H) {
        let node = handle.into_node();
        debug_assert_eq!(node_flags(node) & node_flag::IN_TABLE, 0);
        debug_assert!(self.lookup_node(node_key(node)).is_none());
        self.insert_aux(node, false);
        set_node_flags(node, node_flags(node) | node_flag::IN_TABLE);
    }

    /// `ml_rbt_lookup_insert`: insert unless the key is present; then the handle comes back.
    pub(crate) fn lookup_insert(&mut self, handle: H) -> Result<(), H> {
        let node = handle.into_node();
        debug_assert_eq!(node_flags(node) & node_flag::IN_TABLE, 0);
        match self.insert_aux(node, true) {
            None => {
                set_node_flags(node, node_flags(node) | node_flag::IN_TABLE);
                Ok(())
            }
            Some(_) => Err(H::from_node(ContainedNode {
                node,
                _handle: PhantomData,
            })),
        }
    }

    /// `mon_lnk_rbt_delete`.
    fn delete_node(&mut self, z: NodePtr) {
        // `null_x` gets the fixup started when a node without children is spliced out.
        let mut null_x = MonLnkNode::new(0, 0, 0, 0);
        let null_node = NonNull::from(&mut null_x);
        let y = if left(z).is_none() || right(z).is_none() {
            z
        } else {
            let mut y = right(z).expect("checked right child");
            while let Some(t) = left(y) {
                y = t;
            }
            y
        };
        let mut x = left(y).or(right(y));
        let spliced_is_black = !is_red(y);
        let mut p = parent(y);
        if let Some(x) = x {
            set_parent(x, p);
        } else if spliced_is_black {
            x = Some(null_node);
            set_black(null_node);
            set_parent(null_node, p);
            set_left(y, x);
        }
        match p {
            None => self.root = x,
            Some(p) if Some(y) == left(p) => set_left(p, x),
            Some(p) => set_right(p, x),
        }
        if y != z {
            self.replace_node(z, y);
        }
        if spliced_is_black {
            let mut x = x.expect("a black splice leaves x or null_x");
            p = parent(x);
            while !is_red(x) {
                let Some(mut pn) = p else { break };
                if Some(x) == left(pn) {
                    let mut y = right(pn).expect("sibling exists");
                    if is_red(y) {
                        set_black(y);
                        set_red(pn);
                        self.left_rotate(pn);
                        pn = parent(x).expect("parent after rotation");
                        y = right(pn).expect("sibling after rotation");
                    }
                    let l = left(y);
                    let r = right(y);
                    if is_black(l) && is_black(r) {
                        set_red(y);
                        x = pn;
                        p = parent(x);
                    } else {
                        if is_black(r) {
                            set_black(l.expect("red left child"));
                            set_red(y);
                            self.right_rotate(y);
                            pn = parent(x).expect("parent after rotation");
                            y = right(pn).expect("sibling after rotation");
                        }
                        if is_red(pn) {
                            set_black(pn);
                            set_red(y);
                        }
                        set_black(right(y).expect("red right child"));
                        self.left_rotate(pn);
                        x = self.root.expect("tree has a root");
                        break;
                    }
                } else {
                    let mut y = left(pn).expect("sibling exists");
                    if is_red(y) {
                        set_black(y);
                        set_red(pn);
                        self.right_rotate(pn);
                        pn = parent(x).expect("parent after rotation");
                        y = left(pn).expect("sibling after rotation");
                    }
                    let l = left(y);
                    let r = right(y);
                    if is_black(r) && is_black(l) {
                        set_red(y);
                        x = pn;
                        p = parent(x);
                    } else {
                        if is_black(l) {
                            set_black(r.expect("red right child"));
                            set_red(y);
                            self.left_rotate(y);
                            pn = parent(x).expect("parent after rotation");
                            y = left(pn).expect("sibling after rotation");
                        }
                        if is_red(pn) {
                            set_black(pn);
                            set_red(y);
                        }
                        set_black(left(y).expect("red left child"));
                        self.right_rotate(pn);
                        x = self.root.expect("tree has a root");
                        break;
                    }
                }
            }
            set_black(x);
            match parent(null_node) {
                Some(p) => {
                    if left(p) == Some(null_node) {
                        set_left(p, None);
                    } else {
                        set_right(p, None);
                    }
                }
                None => {
                    if self.root == Some(null_node) {
                        self.root = None;
                    }
                }
            }
        }
    }

    /// `erts_monitor_tree_delete` / `erts_link_tree_delete` of the node with `key`.
    pub(crate) fn remove(&mut self, key: u64) -> Option<H> {
        let node = self.lookup_node(key)?;
        self.delete_node(node);
        set_node_flags(node, node_flags(node) & !node_flag::IN_TABLE);
        Some(H::from_node(ContainedNode {
            node,
            _handle: PhantomData,
        }))
    }

    /// Port of erts/emulator/beam/erl_monitor_link.c (`erts_monitor_tree_lookup`,
    /// `erts_monitor_tree_delete`), OTP-29.1.1: delete the node found by the reference lookup.
    pub(crate) fn remove_if(
        &mut self,
        key: u64,
        predicate: impl FnOnce(u32) -> bool,
    ) -> Result<Option<H>, u32> {
        let Some(node) = self.lookup_node(key) else {
            return Ok(None);
        };
        let flags = node_flags(node);
        if !predicate(flags) {
            return Err(flags);
        }
        self.delete_node(node);
        set_node_flags(node, node_flags(node) & !node_flag::IN_TABLE);
        Ok(Some(H::from_node(ContainedNode {
            node,
            _handle: PhantomData,
        })))
    }

    /// The nodes in the order erts `mon_lnk_rbt_foreach` visits them (`foreach_unordered__`:
    /// both subtrees before the node).
    fn nodes(&self) -> smallvec::SmallVec<[NodePtr; 4]> {
        let mut nodes = smallvec::SmallVec::new();
        let Some(mut x) = self.root else {
            return nodes;
        };
        'down: loop {
            loop {
                while let Some(c) = left(x) {
                    x = c;
                }
                match right(x) {
                    Some(c) => x = c,
                    None => break,
                }
            }
            loop {
                let p = parent(x);
                nodes.push(x);
                let Some(p) = p else {
                    break 'down;
                };
                if let Some(c) = right(p).filter(|c| *c != x) {
                    x = c;
                    continue 'down;
                }
                x = p;
            }
        }
        nodes
    }

    /// Walk the tree in erts' postorder without first materializing its node pointers.
    // Port of erts/emulator/beam/erl_monitor_link.c:1353 (`erts_link_tree_foreach`), OTP-29.1.1.
    fn iter_nodes(&self) -> impl Iterator<Item = NodePtr> {
        fn first_postorder(mut node: NodePtr) -> NodePtr {
            loop {
                while let Some(child) = left(node) {
                    node = child;
                }
                match right(node) {
                    Some(child) => node = child,
                    None => return node,
                }
            }
        }

        fn next_postorder(node: NodePtr) -> Option<NodePtr> {
            let parent = parent(node)?;
            match right(parent).filter(|child| *child != node) {
                Some(child) => Some(first_postorder(child)),
                None => Some(parent),
            }
        }

        let mut node = self.root.map(first_postorder);
        std::iter::from_fn(move || {
            let current = node?;
            node = next_postorder(current);
            Some(current)
        })
    }

    /// `erts_monitor_tree_foreach_delete` / `erts_link_tree_foreach_delete`: empty the tree,
    /// handing out its nodes in foreach order.
    pub(crate) fn drain(&mut self) -> smallvec::IntoIter<[H; 4]> {
        if self.root.is_none() {
            return smallvec::SmallVec::<[H; 4]>::new().into_iter();
        }
        let nodes = self.nodes();
        self.root = None;
        nodes
            .into_iter()
            .map(|node| {
                set_node_flags(node, node_flags(node) & !node_flag::IN_TABLE);
                H::from_node(ContainedNode {
                    node,
                    _handle: PhantomData,
                })
            })
            .collect::<smallvec::SmallVec<[H; 4]>>()
            .into_iter()
    }
}

/// A doubly linked circular list of monitor target halves (`ERTS_P_LT_MONITORS`).
pub(crate) struct MonitorList<I, O, S = ()> {
    first: Option<NodePtr>,
    /// Identity checked when a target half is removed through its origin half.
    id: u64,
    _handles: PhantomData<Monitor<I, O, S>>,
}

// SAFETY: as for `MonLnkTree`, the list owns its nodes as the handles it took in did.
unsafe impl<I: Send + Sync, O: Send, S: Send> Send for MonitorList<I, O, S> {}

impl<I, O, S> Default for MonitorList<I, O, S> {
    fn default() -> Self {
        static NEXT_LIST_ID: AtomicU64 = AtomicU64::new(1);
        Self {
            first: None,
            id: NEXT_LIST_ID.fetch_add(1, AtomicOrdering::Relaxed),
            _handles: PhantomData,
        }
    }
}

impl<I, O, S> Drop for MonitorList<I, O, S> {
    fn drop(&mut self) {
        for handle in self.drain() {
            drop(handle);
        }
    }
}

fn list_links(node: NodePtr) -> ListLinks {
    // SAFETY: the node is in the list the caller holds exclusively, so its links are list links.
    unsafe { (*node.as_ptr()).node.list }
}

fn list_links_mut<'a>(node: NodePtr) -> &'a mut ListLinks {
    // SAFETY: as in `list_links`; no other reference to these links is alive meanwhile.
    unsafe { &mut (*node.as_ptr()).node.list }
}

impl<I, O, S> MonitorList<I, O, S> {
    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.first.is_none()
    }

    /// `erts_ml_dl_list_insert__`: append before the first node.
    pub(crate) fn insert(&mut self, monitor: Monitor<I, O, S>) {
        debug_assert!(monitor.view().is_target());
        let ml = monitor.into_node();
        debug_assert_eq!(node_flags(ml) & node_flag::IN_TABLE, 0);
        match self.first {
            None => {
                *list_links_mut(ml) = ListLinks {
                    next: Some(ml),
                    prev: Some(ml),
                };
                self.first = Some(ml);
            }
            Some(first) => {
                let last = list_links(first).prev.expect("circular list");
                *list_links_mut(ml) = ListLinks {
                    next: Some(first),
                    prev: Some(last),
                };
                list_links_mut(first).prev = Some(ml);
                list_links_mut(last).next = Some(ml);
            }
        }
        set_node_flags(ml, node_flags(ml) | node_flag::IN_TABLE);
        MonitorData::<I, O, S>::from_node(ml).set_target_list(self.id);
    }

    /// `erts_ml_dl_list_delete__`.
    fn delete_node(&mut self, ml: NodePtr) {
        let links = list_links(ml);
        let next = links.next.expect("circular list");
        if next == ml {
            self.first = None;
        } else {
            let prev = links.prev.expect("circular list");
            if self.first == Some(ml) {
                self.first = Some(next);
            }
            list_links_mut(prev).next = Some(next);
            list_links_mut(next).prev = Some(prev);
        }
        set_node_flags(ml, node_flags(ml) & !node_flag::IN_TABLE);
        MonitorData::<I, O, S>::from_node(ml).set_target_list(0);
    }

    /// Take the target half of `origin`'s monitor out of this list, if it is here (the
    /// demonitor and monitor-down paths of erts reach `&mdp->u.target` through the data).
    pub(crate) fn remove_target_of(
        &mut self,
        origin: &Monitor<I, O, S>,
    ) -> Option<Monitor<I, O, S>> {
        let data = MonitorData::<I, O, S>::from_node(origin.node);
        let target = data.target_node();
        if node_flags(target) & node_flag::IN_TABLE == 0 || data.target_list() != self.id {
            return None;
        }
        self.delete_node(target);
        Some(Monitor::from_node(ContainedNode {
            node: target,
            _handle: PhantomData,
        }))
    }

    fn nodes(&self) -> smallvec::SmallVec<[NodePtr; 4]> {
        let mut nodes = smallvec::SmallVec::new();
        if let Some(first) = self.first {
            let mut node = first;
            loop {
                nodes.push(node);
                node = list_links(node).next.expect("circular list");
                if node == first {
                    break;
                }
            }
        }
        nodes
    }

    /// The target halves in list order (`erts_monitor_list_foreach`).
    pub(crate) fn iter(&self) -> impl Iterator<Item = MonitorRef<'_, I, O, S>> {
        self.nodes().into_iter().map(|node| MonitorRef {
            node,
            _monitor: PhantomData,
        })
    }

    /// `erts_monitor_list_foreach_delete`: empty the list in list order.
    pub(crate) fn drain(&mut self) -> smallvec::IntoIter<[Monitor<I, O, S>; 4]> {
        let nodes = self.nodes();
        self.first = None;
        nodes
            .into_iter()
            .map(|node| {
                set_node_flags(node, node_flags(node) & !node_flag::IN_TABLE);
                MonitorData::<I, O, S>::from_node(node).set_target_list(0);
                Monitor::from_node(ContainedNode {
                    node,
                    _handle: PhantomData,
                })
            })
            .collect::<smallvec::SmallVec<[Monitor<I, O, S>; 4]>>()
            .into_iter()
    }
}

/// Both halves of one monitor in one allocation (`ErtsMonitorData`). `info` is shared by both
/// halves and never changes; `origin_state` belongs to the origin half and is reached only
/// through it.
///
/// The allocation is a `MONITOR` fix_alloc block whose in-payload strong count is erts' `refc`:
/// each held half owns one count, as does a half in transit as a monitor or demonitor signal.
#[repr(C)]
pub struct MonitorData<I, O, S = ()> {
    /// The halves are written by the process that holds each of them while the other process
    /// may read the shared fields, so they are interior-mutable.
    origin: UnsafeCell<MonLnkNode>,
    target: UnsafeCell<MonLnkNode>,
    /// `ref`: the key of both halves.
    reference: u64,
    /// References held by both halves and any in-flight signal (`ErtsMonitorData.refc`).
    reference_count: AtomicU32,
    /// Which halves have a [`Monitor`] handle ([`ORIGIN_HELD`], [`TARGET_HELD`]), so a half
    /// in transit becomes a handle again at most once. The bits only decide which handle owns
    /// a half, so every access is relaxed: the half's contents reach the other process through
    /// the signal queue that carried it (or the reference count), not through this word.
    held: AtomicU32,
    /// The id of the list holding the target half, 0 when none.
    target_list: AtomicU64,
    info: I,
    origin_state: UnsafeCell<O>,
    _signal: PhantomData<fn() -> S>,
}

const ORIGIN_HELD: u32 = 1;
const TARGET_HELD: u32 = 2;
/// A half is queued as a signal (its links are the queue header); at most once at a time.
const ORIGIN_QUEUED: u32 = 4;
const TARGET_QUEUED: u32 = 8;

/// A signal value that a monitor half in transit stands for. The target half is the monitor
/// signal, the origin half the demonitor signal; both are made when the receiver takes them
/// out of its queue (erl_proc_sig_queue.c, handle_incoming reads the `ErtsMonitor` itself).
pub(crate) trait HalfSignal<I, O>: Sized {
    /// The signal of `data`'s `target` or origin half, which owns the in-flight reference.
    fn from_half(
        data: arinsal_alloc::typed::FixAllocArc<MonitorData<I, O, Self>>,
        target: bool,
    ) -> Self;

    /// Value made when a link allocation's lazy signal header is materialised for disposal.
    fn from_link_signal(header: NonNull<u8>) -> Self;

    /// Value made when a queued unlink operation is materialised for disposal.
    fn from_unlink_signal(from: arinsal_sched::Pid, id: u64, ack: bool) -> Self;
}

/// `ErtsSigUnlinkOp`: `ErtsNonMsgSignal`, sender and unlink id.
// Port of erts/emulator/beam/erl_proc_sig_queue.h (ErtsNonMsgSignal, ErtsSigUnlinkOp), OTP-29.1.1.
#[repr(C)]
struct UnlinkOpData {
    next: Option<NonNull<u8>>,
    specific: Option<NonNull<u8>>,
    tag: usize,
    message_offsets: isize,
    from: u64,
    id: u64,
}

/// Unique owner of a `SIG_DATA` unlink operation while it is outside a signal queue.
pub(crate) struct UnlinkOp {
    header: NonNull<u8>,
}

const UNLINK_OP_WORDS: usize =
    std::mem::size_of::<UnlinkOpData>().div_ceil(std::mem::size_of::<u64>());
pub(crate) const LAZY_UNLINK: u64 = arinsal_sched::LAZY_UNLINK;
const _: () = assert!(std::mem::size_of::<UnlinkOpData>() == 6 * std::mem::size_of::<u64>());

impl UnlinkOp {
    /// Allocate and queue the `ErtsSigUnlinkOp` itself, with its operation marker in the tag.
    // Port of erts/emulator/beam/erl_proc_sig_queue.c
    // (erts_proc_sig_make_unlink_op, erts_proc_sig_send_unlink), OTP-29.1.1.
    pub(crate) fn signal<I, O, S>(
        from: arinsal_sched::Pid,
        id: u64,
        ack: bool,
    ) -> arinsal_sched::OwnedSignal<S>
    where
        S: HalfSignal<I, O>,
    {
        let mut block = arinsal_alloc::typed::AllocBlock::new(
            arinsal_alloc::typed::ErtsAlcType::SIG_DATA,
            UNLINK_OP_WORDS,
        )
        .expect("short-lived unlink signal allocation");
        let op = block.as_mut_ptr().cast::<UnlinkOpData>();
        // SAFETY: the allocator returned aligned storage for `UNLINK_OP_WORDS`; this writes the
        // exact `ErtsSigUnlinkOp` header before transferring ownership to the queue node.
        unsafe {
            op.write(UnlinkOpData {
                next: None,
                specific: None,
                tag: 0,
                message_offsets: 0,
                from: from.data(),
                id,
            });
        }
        let header = block.into_raw();
        Self { header }.into_signal::<I, O, S>(from, ack)
    }

    /// Take an unlink operation directly from its popped queue node.
    pub(crate) fn take_signal<S>(
        signal: arinsal_sched::OwnedSignal<S>,
    ) -> Option<(Self, arinsal_sched::Pid, u64, bool)> {
        let meta = signal.lazy_meta()?;
        if meta & LAZY_UNLINK == 0 {
            return None;
        }
        let header = signal.into_raw().cast::<u8>();
        let op = Self { header };
        let (from, id) = op.read_fields();
        let ack = meta & arinsal_sched::LAZY_MONITOR != 0;
        Some((op, from, id, ack))
    }

    /// Forward the same operation allocation as the unlink acknowledgement.
    // Port of erts/emulator/beam/erl_proc_sig_queue.c (erts_proc_sig_send_unlink_ack), OTP-29.1.1.
    pub(crate) fn into_ack_signal<I, O, S>(
        self,
        from: arinsal_sched::Pid,
    ) -> arinsal_sched::OwnedSignal<S>
    where
        S: HalfSignal<I, O>,
    {
        self.into_signal::<I, O, S>(from, true)
    }

    fn into_signal<I, O, S>(
        self,
        from: arinsal_sched::Pid,
        ack: bool,
    ) -> arinsal_sched::OwnedSignal<S>
    where
        S: HalfSignal<I, O>,
    {
        let header = self.header;
        let op = header.cast::<UnlinkOpData>();
        // SAFETY: `self` uniquely owns this live unlink operation and updates its sender before
        // the same allocation is transferred back to the signal queue.
        unsafe { (*op.as_ptr()).from = from.data() };
        std::mem::forget(self);
        arinsal_sched::OwnedSignal::lazy(
            header,
            from.data() | LAZY_UNLINK | if ack { arinsal_sched::LAZY_MONITOR } else { 0 },
            Self::materialise::<I, O, S>,
        )
    }

    /// # Safety
    ///
    /// `header` must point to the live allocation passed to [`Self::signal`] and must be taken
    /// only once after its queue ownership ends.
    unsafe fn materialise<I, O, S>(header: NonNull<u8>) -> S
    where
        S: HalfSignal<I, O>,
    {
        let op = Self { header };
        let (from, id) = op.read_fields();
        // `OwnedSignal::lazy` overlays its marker in the `specific` word of `ErtsNonMsgSignal`.
        // SAFETY: `header` is a live lazy unlink operation whose marker shares this second word.
        let marker = unsafe {
            header
                .as_ptr()
                .add(std::mem::size_of::<usize>())
                .cast::<usize>()
                .read()
        };
        let ack = marker as u64 & arinsal_sched::LAZY_MONITOR != 0;
        drop(op);
        S::from_unlink_signal(from, id, ack)
    }

    fn read_fields(&self) -> (arinsal_sched::Pid, u64) {
        let op = self.header.cast::<UnlinkOpData>();
        // SAFETY: `header` is a live `UnlinkOp` allocation transferred by `signal`; queue
        // ownership has ended or the caller owns this unique handle.
        unsafe {
            (
                arinsal_sched::Pid::from_data((*op.as_ptr()).from),
                (*op.as_ptr()).id,
            )
        }
    }
}

impl Drop for UnlinkOp {
    fn drop(&mut self) {
        // SAFETY: this allocation was transferred by `AllocBlock::into_raw` and is unique here.
        drop(unsafe {
            arinsal_alloc::typed::AllocBlock::from_raw(
                self.header,
                arinsal_alloc::typed::ErtsAlcType::SIG_DATA,
                UNLINK_OP_WORDS,
            )
        });
    }
}

// SAFETY: each half's node and the origin state are only touched through the one handle that
// holds that half (`held`), and the rest is atomics or the immutable `info`; so the data may be
// shared between the two processes that hold its halves.
unsafe impl<I: Send + Sync, O: Send, S: Send> Sync for MonitorData<I, O, S> {}
// SAFETY: as above; moving the data moves the `info` and origin state with it.
unsafe impl<I: Send + Sync, O: Send, S: Send> Send for MonitorData<I, O, S> {}

impl<I, O, S> MonitorData<I, O, S> {
    /// The data of a monitor node, borrowed for as long as one of its halves is held.
    fn from_node_impl<'a>(
        node: NodePtr,
        adopt: bool,
    ) -> (&'a Self, Option<arinsal_alloc::typed::FixAllocArc<Self>>) {
        let data = node_to_main(node).cast::<Self>();
        // SAFETY: monitor nodes are created only by `Monitor::create`, inside a `MonitorData`
        // of this type, with `offset` pointing back to its start. The data lives while either
        // half is held, and the caller holds one. `adopt` is true only when a tree returns the
        // reference transferred by `Monitor::into_node`; shared fields use interior mutability.
        unsafe {
            let value = data.as_ref();
            let owner = adopt.then(|| arinsal_alloc::typed::FixAllocArc::from_raw(data));
            (value, owner)
        }
    }

    fn from_node<'a>(node: NodePtr) -> &'a Self {
        Self::from_node_impl(node, false).0
    }

    fn owner_from_node(node: NodePtr) -> arinsal_alloc::typed::FixAllocArc<Self> {
        Self::from_node_impl(node, true)
            .1
            .expect("a monitor tree node transfers one fix_alloc owner")
    }

    fn node_of(data: *const Self, target: bool) -> NodePtr {
        // SAFETY: `data` points to a live `MonitorData`; this only forms a pointer to one of its
        // fields, keeping the provenance of the whole allocation.
        let node = unsafe {
            if target {
                std::ptr::addr_of!((*data).target)
            } else {
                std::ptr::addr_of!((*data).origin)
            }
        };
        NonNull::new(node.cast_mut().cast()).expect("field pointer is not null")
    }

    fn target_node(&self) -> NodePtr {
        Self::node_of(self, true)
    }

    fn target_list(&self) -> u64 {
        self.target_list.load(AtomicOrdering::Relaxed)
    }

    fn set_target_list(&self, id: u64) {
        self.target_list.store(id, AtomicOrdering::Relaxed);
    }

    /// The reference of the monitor in transit.
    pub(crate) fn reference(&self) -> u64 {
        self.reference
    }

    /// The pid (data) that originates the monitor: the `other` of the target half.
    pub(crate) fn origin_id(&self) -> u64 {
        // SAFETY: `other` is written when the halves are created and never changes.
        unsafe { (*self.target.get()).other }
    }

    /// The queue node of a half in transit: the half itself, queued as its signal (erts
    /// queues the `ErtsMonitor` node, erl_proc_sig_queue.c, erts_proc_sig_send_monitor and
    /// erts_proc_sig_send_demonitor), so it allocates nothing. The signal value is made from the
    /// half when the node is taken out of its queue. Gives the data back when the half is
    /// already queued. `meta` is what the delivery path reads before the signal exists.
    pub(crate) fn half_signal(
        this: arinsal_alloc::typed::FixAllocArc<Self>,
        target: bool,
        meta: u64,
    ) -> Result<arinsal_term::message::OwnedSignal<S>, arinsal_alloc::typed::FixAllocArc<Self>>
    where
        S: HalfSignal<I, O>,
    {
        let bit = if target { TARGET_QUEUED } else { ORIGIN_QUEUED };
        if this.held.fetch_or(bit, AtomicOrdering::Relaxed) & bit != 0 {
            return Err(this);
        }
        let header = Self::node_of(this.as_ptr(), target).cast::<u8>();
        // The signal owns this reference until `materialise` takes it back.
        let _ = this.into_raw();
        // A half given up for transit has no handle, so its container links, which are the
        // first words of the node, are unused until `materialise` resets them; `bit` keeps a
        // second signal from using them meanwhile.
        Ok(arinsal_term::message::OwnedSignal::lazy(
            header,
            meta,
            Self::materialise,
        ))
    }

    /// The signal of a half queued by [`MonitorData::half_signal`], made when it is taken out.
    ///
    /// # Safety
    ///
    /// `header` is the node of a half queued by `half_signal` for this data type, not used again.
    unsafe fn materialise(header: NonNull<u8>) -> S
    where
        S: HalfSignal<I, O>,
    {
        let node = header.cast::<MonLnkNode>();
        // SAFETY: the node is the half's, in a live `MonitorData` that the signal's reference
        // keeps; `offset` points back to its start. The container links are reset to the state
        // a fresh half has, as the queue header overlaid them.
        let (link_signal, data, target) = unsafe {
            let marker = header.cast::<usize>().as_ptr().add(1).read();
            if marker as u64 & arinsal_sched::LAZY_LINK != 0 {
                (true, None, false)
            } else {
                let offset = usize::from((*node.as_ptr()).offset);
                let target = (*node.as_ptr()).flags & node_flag::TARGET != 0;
                (*node.as_ptr()).node = NodeLinks {
                    tree: TreeLinks {
                        parent: 0,
                        right: None,
                        left: None,
                    },
                };
                let data = NonNull::new_unchecked(header.as_ptr().sub(offset).cast::<Self>());
                (
                    false,
                    Some(arinsal_alloc::typed::FixAllocArc::from_raw(data)),
                    target,
                )
            }
        };
        if link_signal {
            return S::from_link_signal(header);
        }
        let data = data.expect("monitor signal has monitor data");
        let bit = if target { TARGET_QUEUED } else { ORIGIN_QUEUED };
        data.held.fetch_and(!bit, AtomicOrdering::Relaxed);
        S::from_half(data, target)
    }

    /// Queue a local link allocation using the monitor half's existing lazy-node materialiser.
    pub(crate) fn link_signal(link: Link, meta: u64) -> arinsal_term::message::OwnedSignal<S>
    where
        S: HalfSignal<I, O>,
    {
        arinsal_term::message::OwnedSignal::lazy(link.into_signal_header(), meta, Self::materialise)
    }

    /// Take a queued monitor or demonitor half back from its intrusive signal node.
    // Port of erts/emulator/beam/erl_proc_sig_queue.c (erts_proc_sig_handle_incoming), OTP-29.1.1.
    pub(crate) fn take_signal_half(
        signal: arinsal_term::message::OwnedSignal<S>,
    ) -> Option<Monitor<I, O, S>>
    where
        S: HalfSignal<I, O>,
    {
        let meta = signal.lazy_meta()?;
        let target = meta & arinsal_sched::LAZY_MONITOR != 0;
        let header = signal.into_raw().cast::<u8>();
        let node = header.cast::<MonLnkNode>();
        // SAFETY: the lazy signal owns this monitor half; its node is not used again after it is
        // taken from the queue, and the offset identifies the shared allocation's start.
        let data = unsafe {
            let offset = usize::from((*node.as_ptr()).offset);
            (*node.as_ptr()).node = NodeLinks {
                tree: TreeLinks {
                    parent: 0,
                    right: None,
                    left: None,
                },
            };
            let data = NonNull::new_unchecked(header.as_ptr().sub(offset).cast::<Self>());
            arinsal_alloc::typed::FixAllocArc::from_raw(data)
        };
        // The queued half becomes a held half in one read-modify-write: erts takes the node out
        // of the queue and inserts it without any atomic operation on it.
        let (queued, bit) = if target {
            (TARGET_QUEUED, TARGET_HELD)
        } else {
            (ORIGIN_QUEUED, ORIGIN_HELD)
        };
        let old = data.held.fetch_xor(queued | bit, AtomicOrdering::Relaxed);
        debug_assert!(old & queued != 0);
        if old & bit != 0 {
            data.held.fetch_or(bit, AtomicOrdering::Relaxed);
            return None;
        }
        Some(Monitor {
            node: Self::node_of(data.as_ptr(), target),
            _data: data,
        })
    }

    /// Turn a half in transit back into its handle. `None` when that half already has one.
    pub(crate) fn take_half(
        this: arinsal_alloc::typed::FixAllocArc<Self>,
        target: bool,
    ) -> Option<Monitor<I, O, S>> {
        let bit = if target { TARGET_HELD } else { ORIGIN_HELD };
        if this.held.fetch_or(bit, AtomicOrdering::Relaxed) & bit != 0 {
            return None;
        }
        Some(Monitor {
            node: Self::node_of(this.as_ptr(), target),
            _data: this,
        })
    }
}

impl<I, O, S> arinsal_alloc::typed::FixAllocRefCount for MonitorData<I, O, S> {
    const ALLOCATION_TYPE: arinsal_alloc::typed::ErtsAlcType =
        arinsal_alloc::typed::ErtsAlcType::MONITOR;

    fn reference_count(&self) -> &AtomicU32 {
        &self.reference_count
    }
}

/// One half of a monitor, owned by the process that holds it (`ErtsMonitor`).
pub(crate) struct Monitor<I, O, S = ()> {
    node: NodePtr,
    _data: arinsal_alloc::typed::FixAllocArc<MonitorData<I, O, S>>,
}

/// The identity in a monitor key, including the creator stored by a PID reference.
#[derive(Clone, Copy)]
pub(crate) struct MonitorReference {
    pub(crate) id: u64,
    flags: u32,
}

impl MonitorReference {
    pub(crate) fn ordinary(id: u64) -> Self {
        Self { id, flags: 0 }
    }

    pub(crate) fn pid_ref(id: u64) -> Self {
        Self {
            id,
            flags: node_flag::PID_REF,
        }
    }

    pub(crate) fn is_pid_ref(self) -> bool {
        self.flags & node_flag::PID_REF != 0
    }

    // Port of erts/emulator/beam/erl_monitor_link.h (ERTS_ML_STATE_ALIAS_*), OTP-29.1.1.
    pub(crate) fn with_alias_mode(mut self, mode: crate::proc_create::AliasMode) -> Self {
        self.flags |= match mode {
            crate::proc_create::AliasMode::ExplicitUnalias => node_flag::STATE_ALIAS_UNALIAS,
            crate::proc_create::AliasMode::Demonitor => node_flag::STATE_ALIAS_DEMONITOR,
            crate::proc_create::AliasMode::ReplyDemonitor => node_flag::STATE_ALIAS_ONCE,
        };
        self
    }

    // Port of erts/emulator/beam/erl_monitor_link.h (ERTS_ML_FLG_PRIO_ALIAS), OTP-29.1.1.
    pub(crate) fn with_alias_priority(mut self) -> Self {
        self.flags |= node_flag::PRIO_ALIAS;
        self
    }
}

// SAFETY: a half is moved between processes only as a whole; the data it shares with the other
// half is `Sync` (see `MonitorData`).
unsafe impl<I: Send + Sync, O: Send, S: Send> Send for Monitor<I, O, S> {}

impl<I, O, S> NodeHandle for Monitor<I, O, S> {
    type Order = ReferenceOrder;

    fn into_node(self) -> NodePtr {
        let node = self.node;
        std::mem::forget(self);
        node
    }

    fn from_node(node: ContainedNode<Self>) -> Self {
        Self {
            node: node.node,
            _data: MonitorData::owner_from_node(node.node),
        }
    }
}

impl<I, O, S> Monitor<I, O, S> {
    /// `erts_monitor_create`: both halves of a new monitor. The origin half's `other` is the
    /// target, the target half's `other` the origin.
    pub(crate) fn create(
        kind: u32,
        reference: MonitorReference,
        origin: u64,
        target: u64,
        flags: u32,
        info: I,
        origin_state: O,
    ) -> (Self, Self) {
        Self::create_at(
            None,
            kind,
            reference,
            origin,
            target,
            flags,
            info,
            origin_state,
        )
    }

    /// [`Monitor::create`] allocating on the creating scheduler's allocator index `ix`
    /// (`esdp->no`) when the caller has it, else on the thread's.
    #[allow(clippy::too_many_arguments)] // `erts_monitor_create` takes the same set.
    pub(crate) fn create_at(
        ix: Option<usize>,
        kind: u32,
        reference: MonitorReference,
        origin: u64,
        target: u64,
        flags: u32,
        info: I,
        origin_state: O,
    ) -> (Self, Self) {
        debug_assert!(kind <= node_type::MONITOR_ALIAS);
        debug_assert_eq!(flags & node_flag::RESERVED, 0);
        let origin_flags = flags | reference.flags;
        let target_flags = flags | (reference.flags & node_flag::PID_REF);
        let key_offset = offset_of!(MonitorData<I, O, S>, reference);
        let origin_offset = offset_of!(MonitorData<I, O, S>, origin);
        let target_offset = offset_of!(MonitorData<I, O, S>, target);
        let data = MonitorData {
            origin: UnsafeCell::new(MonLnkNode::new(
                target,
                origin_offset,
                key_offset - origin_offset,
                kind | origin_flags,
            )),
            target: UnsafeCell::new(MonLnkNode::new(
                origin,
                target_offset,
                key_offset - target_offset,
                kind | target_flags | node_flag::TARGET,
            )),
            reference: reference.id,
            reference_count: AtomicU32::new(2),
            held: AtomicU32::new(ORIGIN_HELD | TARGET_HELD),
            target_list: AtomicU64::new(0),
            info,
            origin_state: UnsafeCell::new(origin_state),
            _signal: PhantomData,
        };
        let (origin_owner, target_owner) = match ix {
            Some(ix) => arinsal_alloc::typed::FixAllocArc::new_pair_at(ix, data),
            None => arinsal_alloc::typed::FixAllocArc::new_pair(data),
        }
        .expect("the MONITOR fixed-size allocation must be available");
        (
            Self {
                node: MonitorData::node_of(origin_owner.as_ptr(), false),
                _data: origin_owner,
            },
            Self {
                node: MonitorData::node_of(target_owner.as_ptr(), true),
                _data: target_owner,
            },
        )
    }

    pub(crate) fn view(&self) -> MonitorRef<'_, I, O, S> {
        MonitorRef {
            node: self.node,
            _monitor: PhantomData,
        }
    }

    #[cfg(test)]
    fn view_mut(&mut self) -> MonitorMut<'_, I, O, S> {
        MonitorMut {
            node: self.node,
            _monitor: PhantomData,
        }
    }

    /// The origin state; `None` on a target half.
    pub(crate) fn state(&self) -> Option<&O> {
        let view: MonitorRef<'_, I, O, S> = MonitorRef {
            node: self.node,
            _monitor: PhantomData,
        };
        view.origin_state()
    }

    #[cfg(test)]
    /// Whether `self` and `other` are the two halves of one monitor.
    pub(crate) fn is_other_half_of(&self, other: &Self) -> bool {
        self.node != other.node && node_to_main(self.node) == node_to_main(other.node)
    }

    /// Give the half up for transit as a signal; [`MonitorData::take_half`] turns it back.
    pub(crate) fn into_shared(self) -> arinsal_alloc::typed::FixAllocArc<MonitorData<I, O, S>> {
        let target = self.view().is_target();
        let bit = if target { TARGET_HELD } else { ORIGIN_HELD };
        self._data.held.fetch_and(!bit, AtomicOrdering::Relaxed);
        self._data
    }

    /// Releases both halves after a local demonitor removed each from its owning table.
    // Port of erts/emulator/beam/erl_proc_sig_queue.c (ERTS_SIG_Q_OP_DEMONITOR), OTP-29.1.1.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn release_both(origin: Self, target: Self) {
        debug_assert!(!origin.view().is_target());
        debug_assert!(target.view().is_target());
        let Self {
            _data: origin_data, ..
        } = origin;
        let Self {
            _data: target_data, ..
        } = target;
        arinsal_alloc::typed::FixAllocArc::release_pair(origin_data, target_data);
    }
}

/// A borrowed monitor half.
pub(crate) struct MonitorRef<'a, I, O, S = ()> {
    node: NodePtr,
    _monitor: PhantomData<&'a Monitor<I, O, S>>,
}

impl<I, O, S> Clone for MonitorRef<'_, I, O, S> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<I, O, S> Copy for MonitorRef<'_, I, O, S> {}

impl<'a, I, O, S> MonitorRef<'a, I, O, S> {
    pub(crate) fn kind(self) -> u32 {
        node_flags(self.node) & node_flag::TYPE_MASK
    }

    pub(crate) fn is_target(self) -> bool {
        node_flags(self.node) & node_flag::TARGET != 0
    }

    /// `other.item`: the far end.
    pub(crate) fn other(self) -> u64 {
        node_other(self.node)
    }

    pub(crate) fn reference(self) -> u64 {
        MonitorData::<I, O, S>::from_node(self.node).reference
    }

    pub(crate) fn reference_creator(self) -> Option<u64> {
        let node = node_flags(self.node);
        if node & node_flag::PID_REF == 0 {
            return None;
        }
        Some(MonitorData::<I, O, S>::from_node(self.node).origin_id())
    }

    // Port of erts/emulator/beam/erl_monitor_link.h (ERTS_ML_STATE_ALIAS_*), OTP-29.1.1.
    pub(crate) fn alias_mode(self) -> Option<crate::proc_create::AliasMode> {
        match node_flags(self.node) & node_flag::STATE_ALIAS_MASK {
            node_flag::STATE_ALIAS_UNALIAS => Some(crate::proc_create::AliasMode::ExplicitUnalias),
            node_flag::STATE_ALIAS_DEMONITOR => Some(crate::proc_create::AliasMode::Demonitor),
            node_flag::STATE_ALIAS_ONCE => Some(crate::proc_create::AliasMode::ReplyDemonitor),
            _ => None,
        }
    }

    pub(crate) fn alias_priority(self) -> bool {
        node_flags(self.node) & node_flag::PRIO_ALIAS != 0
    }

    pub(crate) fn info(self) -> &'a I {
        &MonitorData::<I, O, S>::from_node(self.node).info
    }

    /// The origin state; `None` on a target half.
    pub(crate) fn origin_state(self) -> Option<&'a O> {
        if self.is_target() {
            return None;
        }
        let data = MonitorData::<I, O, S>::from_node(self.node);
        // SAFETY: only the origin half reaches the origin state, and this view borrows it
        // shared, so no `&mut` to the state is alive.
        Some(unsafe { &*data.origin_state.get() })
    }
}

/// A mutably borrowed monitor half.
pub(crate) struct MonitorMut<'a, I, O, S = ()> {
    node: NodePtr,
    _monitor: PhantomData<&'a mut Monitor<I, O, S>>,
}

impl<'a, I, O, S> MonitorMut<'a, I, O, S> {
    /// The origin state; `None` on a target half.
    pub(crate) fn origin_state(self) -> Option<&'a mut O> {
        if node_flags(self.node) & node_flag::TARGET != 0 {
            return None;
        }
        let data = MonitorData::<I, O, S>::from_node(self.node);
        // SAFETY: only the origin half reaches the origin state, and this view borrows that
        // half exclusively.
        Some(unsafe { &mut *data.origin_state.get() })
    }

    // Port of erts/emulator/beam/bif.c (unalias_1), OTP-29.1.1.
    pub(crate) fn clear_alias_flags(&mut self) {
        let flags = node_flags(self.node) & !(node_flag::STATE_ALIAS_MASK | node_flag::PRIO_ALIAS);
        set_node_flags(self.node, flags);
    }
}

impl<I, O, S> MonLnkTree<Monitor<I, O, S>> {
    /// `erts_monitor_tree_lookup`.
    pub(crate) fn get(&self, reference: u64) -> Option<MonitorRef<'_, I, O, S>> {
        self.lookup_node(reference).map(|node| MonitorRef {
            node,
            _monitor: PhantomData,
        })
    }

    pub(crate) fn get_mut(&mut self, reference: u64) -> Option<MonitorMut<'_, I, O, S>> {
        self.lookup_node(reference).map(|node| MonitorMut {
            node,
            _monitor: PhantomData,
        })
    }

    /// The origin state of the origin half with `reference`; `None` when there is none or the
    /// node with that key is a target half.
    pub(crate) fn get_state(&self, reference: u64) -> Option<&O> {
        self.get(reference)?.origin_state()
    }

    pub(crate) fn get_state_mut(&mut self, reference: u64) -> Option<&mut O> {
        let mut entry = self.get_mut(reference)?;
        entry.clear_alias_flags();
        entry.origin_state()
    }

    /// Port of erts/emulator/beam/erl_monitor_link.c:710 (`erts_monitor_tree_foreach`), OTP-29.1.1.
    pub(crate) fn iter(&self) -> impl Iterator<Item = MonitorRef<'_, I, O, S>> {
        self.iter_nodes().map(|node| MonitorRef {
            node,
            _monitor: PhantomData,
        })
    }
}

/// A local link (`ErtsILink`).
#[repr(C)]
struct ILink {
    link: MonLnkNode,
    /// The id of the unlink operation in progress, 0 when none.
    unlinking: u64,
    reference_count: AtomicU32,
}

impl arinsal_alloc::typed::FixAllocRefCount for ILink {
    const ALLOCATION_TYPE: arinsal_alloc::typed::ErtsAlcType =
        arinsal_alloc::typed::ErtsAlcType::LINK;

    fn reference_count(&self) -> &AtomicU32 {
        &self.reference_count
    }
}

/// Tag of a link key that is a boxed external pid (erts: a boxed `Eterm` key pointing into
/// `ErtsELink::heap`). Internal pid keys are 60-bit table data and port keys set only bit 63
/// (`proc_create::port_link_key`), so with both top bits external pids sort after both, as in
/// erts `ml_cmp_keys`: internal pid < internal port < external pid.
const EXTERNAL_KEY: u64 = 3 << 62;

fn is_external_key(key: u64) -> bool {
    key & EXTERNAL_KEY == EXTERNAL_KEY
}

/// The external pid an external link is keyed by: the `ExternalThing` erts copies into
/// `ErtsELink::heap` with `STORE_NC` (node sysname and creation, then the data words).
pub(crate) use arinsal_sched::ExternalPid;

/// Port of erts/emulator/beam/erl_monitor_link.c (ml_cmp_keys, external keys), OTP-29.1.1:
/// node sysname atom, then creation, then the data words. Like erts this is not term order.
fn external_ml_cmp(left: &ExternalPid, right: &ExternalPid) -> Ordering {
    left.sysname
        .cmp(&right.sysname)
        .then(left.creation.cmp(&right.creation))
        .then(left.number.cmp(&right.number))
        .then(left.serial.cmp(&right.serial))
}

/// The boxed key of `pid` while it stays in place.
fn external_key(pid: &ExternalPid) -> u64 {
    EXTERNAL_KEY | std::ptr::from_ref(pid) as u64
}

/// Distribution state attached to an external link or monitor (`ErtsMonLnkDist`): the
/// connection the dist half was inserted in, or the dead-dist record of a link made while the
/// node was not alive or not connected.
pub(crate) struct MonLnkDist {
    /// `nodename`: the node name atom index.
    pub(crate) nodename: u32,
    /// `connection_id`; `!0` until a connection sets it.
    pub(crate) connection_id: u32,
    /// `mtx` and what it protects.
    state: std::sync::Mutex<MonLnkDistState>,
}

/// The fields of `ErtsMonLnkDist` under `mtx`.
struct MonLnkDistState {
    /// `alive`.
    alive: bool,
    /// `links`: a circular list of dist halves, each owning one reference to its `ELink`.
    links: Option<NodePtr>,
}

// SAFETY: the list nodes are dist halves of `ELink`s whose shared fields are atomic or
// immutable; they are reached only under the mutex.
unsafe impl Send for MonLnkDistState {}

impl std::fmt::Debug for MonLnkDist {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MonLnkDist")
            .field("nodename", &self.nodename)
            .field("connection_id", &self.connection_id)
            .finish_non_exhaustive()
    }
}

impl MonLnkDist {
    /// Port of erts/emulator/beam/erl_monitor_link.c (erts_mon_link_dist_create), OTP-29.1.1.
    pub(crate) fn new(nodename: u32) -> Self {
        Self::with_connection(nodename, !0)
    }

    /// `erts_mon_link_dist_create` followed by `mld->connection_id = dep->connection_id`
    /// (erl_node_tables.c, erts_set_dist_entry_pending).
    pub(crate) fn with_connection(nodename: u32, connection_id: u32) -> Self {
        Self {
            nodename,
            connection_id,
            state: std::sync::Mutex::new(MonLnkDistState {
                alive: true,
                links: None,
            }),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, MonLnkDistState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// `mld->alive`.
    #[cfg(test)]
    pub(crate) fn is_alive(&self) -> bool {
        self.lock().alive
    }

    /// Port of erts/emulator/beam/dist.c (con_monitor_link_seq_cleanup, the links state),
    /// OTP-29.1.1: mark the connection dead and take its link list, in list order.
    pub(crate) fn take_links(&self) -> Vec<Link> {
        let mut state = self.lock();
        state.alive = false;
        let mut links = Vec::new();
        if let Some(first) = state.links.take() {
            let mut node = first;
            loop {
                let next = list_links(node).next.expect("circular list");
                set_node_flags(node, node_flags(node) & !node_flag::IN_TABLE);
                links.push(Link { node });
                if next == first {
                    break;
                }
                node = next;
            }
        }
        links
    }
}

/// An external link (`ErtsELink`): both halves in one allocation shared by reference count.
#[repr(C)]
struct ELink {
    /// `ld.proc`: held in the process link tree, keyed by the external pid.
    proc_half: MonLnkNode,
    /// `ld.dist`: held by the dist entry; its other item is the local pid.
    dist_half: MonLnkNode,
    /// `ld.refc`.
    reference_count: AtomicU32,
    /// `dist`.
    dist: Option<std::sync::Arc<MonLnkDist>>,
    /// `unlinking`.
    unlinking: u64,
    /// `heap`: the key of `proc_half`.
    pid: ExternalPid,
}

/// A link half owned by the process at one end, or by a dist entry (`ErtsLink`): one node of
/// an `ErtsILink` (local link) or of an `ErtsELink` (external link, `ERTS_ML_FLG_EXTENDED`).
pub(crate) struct Link {
    node: NodePtr,
}

// SAFETY: a link node holds plain data and is moved between processes only as a whole; the
// two halves of an external link share only their atomic reference count and immutable data.
unsafe impl Send for Link {}

impl Drop for Link {
    /// `erts_link_release`.
    fn drop(&mut self) {
        if node_flags(self.node) & node_flag::EXTENDED != 0 {
            elink_release(self.node, 1);
        } else {
            // SAFETY: an unextended link node is the first field of an `ILink` that
            // `Link::create` allocated, and this handle owns one transferred reference to it.
            drop(unsafe {
                arinsal_alloc::typed::FixAllocArc::<ILink>::from_raw(node_to_main(self.node).cast())
            });
        }
    }
}

impl NodeHandle for Link {
    type Order = PidOrder;

    fn into_node(self) -> NodePtr {
        let node = self.node;
        std::mem::forget(self);
        node
    }

    fn from_node(node: ContainedNode<Self>) -> Self {
        Self { node: node.node }
    }
}

impl Link {
    /// `erts_link_internal_create`: a link to `other`.
    pub(crate) fn create(kind: u32, other: u64, flags: u32) -> Self {
        debug_assert!((node_type::LINK_PROC..=node_type::LINK_DIST_PORT).contains(&kind));
        debug_assert_eq!(flags & node_flag::RESERVED, 0);
        debug_assert!(!is_external_key(other));
        let data = arinsal_alloc::typed::FixAllocArc::new(ILink {
            link: MonLnkNode::new(other, 0, offset_of!(MonLnkNode, other), kind | flags),
            unlinking: 0,
            reference_count: AtomicU32::new(0),
        })
        .expect("fixed-size link allocation");
        let main = data.into_raw();
        Self {
            node: main.cast::<MonLnkNode>(),
        }
    }

    /// Port of erts/emulator/beam/erl_monitor_link.c (erts_link_external_create), OTP-29.1.1:
    /// an external link from local process `this` to `other`. The first half (`ld.proc`) is
    /// keyed by `other` and goes into the process link tree; the second (`ld.dist`) has
    /// `this` as its other item and goes into the dist entry's link list.
    pub(crate) fn create_external(kind: u32, this: u64, other: ExternalPid) -> (Self, Self) {
        debug_assert!(kind == node_type::LINK_DIST_PROC || kind == node_type::LINK_DIST_PORT);
        debug_assert!(!is_external_key(this));
        let flags = node_flag::EXTENDED | kind;
        let elink = Box::new(ELink {
            proc_half: MonLnkNode::new(
                0,
                offset_of!(ELink, proc_half),
                offset_of!(MonLnkNode, other),
                flags,
            ),
            dist_half: MonLnkNode::new(
                this,
                offset_of!(ELink, dist_half),
                offset_of!(MonLnkNode, other),
                flags,
            ),
            reference_count: AtomicU32::new(2),
            dist: None,
            unlinking: 0,
            pid: other,
        });
        let main = NonNull::from(Box::leak(elink));
        // SAFETY: `main` is the only pointer to the fresh allocation; the proc half's key is
        // a boxed pointer to the external pid in the same allocation, as erts stores the key
        // `Eterm` into `elnk->heap`. Neither field is written again while the link lives.
        unsafe {
            let pid = std::ptr::addr_of!((*main.as_ptr()).pid);
            (*main.as_ptr()).proc_half.other = EXTERNAL_KEY | pid as u64;
        }
        // SAFETY: as above; these form pointers to the two node fields of the live allocation.
        let (proc_half, dist_half) = unsafe {
            (
                NonNull::new_unchecked(std::ptr::addr_of_mut!((*main.as_ptr()).proc_half)),
                NonNull::new_unchecked(std::ptr::addr_of_mut!((*main.as_ptr()).dist_half)),
            )
        };
        (Self { node: proc_half }, Self { node: dist_half })
    }

    /// Port of erts/emulator/beam/erl_monitor_link.h (erts_link_release_both), OTP-29.1.1.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn release_both(first: Self, second: Self) {
        debug_assert_eq!(node_to_main(first.node), node_to_main(second.node));
        let node = first.into_node();
        let _ = second.into_node();
        if node_flags(node) & node_flag::EXTENDED != 0 {
            elink_release(node, 2);
        } else {
            unreachable!("only an external link has two halves");
        }
    }

    /// Port of erts/emulator/beam/erl_monitor_link.h (erts_link_dist_insert), OTP-29.1.1:
    /// put this dist half into the connection's link list unless the connection is dead, in
    /// which case the half comes back.
    pub(crate) fn dist_insert(self, dist: &std::sync::Arc<MonLnkDist>) -> Result<(), Self> {
        let elink = elink_of(self.node).expect("dist insert of an external link");
        debug_assert_eq!(
            node_flags(self.node) & node_flag::TYPE_MASK,
            node_type::LINK_DIST_PROC
        );
        let mut state = dist.lock();
        if !state.alive {
            return Err(self);
        }
        // SAFETY: the dist half is not published yet, so nothing reads `dist` meanwhile.
        unsafe {
            debug_assert!((*elink.as_ptr()).dist.is_none());
            (*elink.as_ptr()).dist = Some(dist.clone());
        }
        let node = self.into_node();
        match state.links {
            None => {
                *list_links_mut(node) = ListLinks {
                    next: Some(node),
                    prev: Some(node),
                };
                state.links = Some(node);
            }
            Some(first) => {
                let last = list_links(first).prev.expect("circular list");
                *list_links_mut(node) = ListLinks {
                    next: Some(first),
                    prev: Some(last),
                };
                list_links_mut(first).prev = Some(node);
                list_links_mut(last).next = Some(node);
            }
        }
        set_node_flags(node, node_flags(node) | node_flag::IN_TABLE);
        Ok(())
    }

    /// `erts_link_dist_delete(erts_link_to_other(lnk))` on the proc half of an external link:
    /// whether the dist half left its connection's list now (or never had a connection), so
    /// that its reference passes to the caller.
    pub(crate) fn dist_delete_other(&self) -> bool {
        let elink = elink_of(self.node).expect("dist delete of an external link");
        // SAFETY: `dist` is written only before the dist half is published.
        let dist = unsafe { (*elink.as_ptr()).dist.as_ref() };
        let Some(dist) = dist else {
            return true;
        };
        // SAFETY: the dist half lives in the same allocation; this forms a field pointer.
        let node =
            unsafe { NonNull::new_unchecked(std::ptr::addr_of_mut!((*elink.as_ptr()).dist_half)) };
        let mut state = dist.lock();
        let delete = state.alive && node_flags(node) & node_flag::IN_TABLE != 0;
        if delete {
            let links = list_links(node);
            let next = links.next.expect("circular list");
            if next == node {
                state.links = None;
            } else {
                let prev = links.prev.expect("circular list");
                if state.links == Some(node) {
                    state.links = Some(next);
                }
                list_links_mut(prev).next = Some(next);
                list_links_mut(next).prev = Some(prev);
            }
            set_node_flags(node, node_flags(node) & !node_flag::IN_TABLE);
        }
        delete
    }

    /// Release the proc half of an external link after [`Link::dist_delete_other`]:
    /// `erts_link_release_both` when the dist half's reference came along, else
    /// `erts_link_release`.
    pub(crate) fn release_external(self, other_deleted: bool) {
        let node = self.into_node();
        elink_release(node, if other_deleted { 2 } else { 1 });
    }

    pub(crate) fn view(&self) -> LinkRef<'_> {
        LinkRef {
            node: self.node,
            _link: PhantomData,
        }
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn view_mut(&mut self) -> LinkMut<'_> {
        LinkMut {
            node: self.node,
            _link: PhantomData,
        }
    }

    /// Give this half's allocation to an intrusive signal queue.
    // Port of erts/emulator/beam/erl_proc_sig_queue.c (erts_proc_sig_send_link), OTP-29.1.1.
    pub(crate) fn into_signal_header(self) -> NonNull<u8> {
        debug_assert_eq!(node_flags(self.node) & node_flag::EXTENDED, 0);
        self.into_node().cast()
    }

    /// Take back a link half whose tree links were overlaid by a signal queue header.
    // Port of erts/emulator/beam/erl_proc_sig_queue.c (erts_proc_sig_handle_incoming), OTP-29.1.1.
    pub(crate) fn from_signal_header(header: NonNull<u8>) -> Self {
        Self::from_node(ContainedNode {
            node: header.cast(),
            _handle: PhantomData,
        })
    }
}

/// Drop `count` owners of the external link holding `node` (`erts_link_release`,
/// `erts_link_release_both`, `erts_link_destroy_elink__`).
fn elink_release(node: NodePtr, count: u32) {
    let main = node_to_main(node).cast::<ELink>();
    // SAFETY: an extended link node lives in an `ELink` that `Link::create_external`
    // leaked from a `Box`; the caller gives up `count` owners of it.
    let old = unsafe { main.as_ref() }
        .reference_count
        .fetch_sub(count, AtomicOrdering::AcqRel);
    debug_assert!(old >= count);
    if old == count {
        // SAFETY: these were the last owners, so nothing else reaches the allocation.
        drop(unsafe { Box::from_raw(main.as_ptr()) });
    }
}

fn ilink_unlinking(node: NodePtr) -> *mut u64 {
    if node_flags(node) & node_flag::EXTENDED != 0 {
        let main = node_to_main(node).cast::<ELink>();
        // SAFETY: extended link nodes live in an `ELink`; this only forms a field pointer.
        return unsafe { std::ptr::addr_of_mut!((*main.as_ptr()).unlinking) };
    }
    let main = node_to_main(node).cast::<ILink>();
    // SAFETY: unextended link nodes are created only by `Link::create` as the first field of
    // a live `ILink`; this only forms a pointer to its `unlinking` field.
    unsafe { std::ptr::addr_of_mut!((*main.as_ptr()).unlinking) }
}

fn elink_of(node: NodePtr) -> Option<NonNull<ELink>> {
    (node_flags(node) & node_flag::EXTENDED != 0).then(|| node_to_main(node).cast::<ELink>())
}

/// A borrowed link.
#[derive(Clone, Copy)]
pub(crate) struct LinkRef<'a> {
    node: NodePtr,
    _link: PhantomData<&'a Link>,
}

impl<'a> LinkRef<'a> {
    #[cfg(test)]
    pub(crate) fn flags(self) -> u32 {
        node_flags(self.node)
    }

    pub(crate) fn other(self) -> u64 {
        node_other(self.node)
    }

    /// The link type (`ERTS_LNK_TYPE_*`).
    pub(crate) fn kind(self) -> u32 {
        node_flags(self.node) & node_flag::TYPE_MASK
    }

    /// `ERTS_ML_FLG_PRIO_ML`: exit signals from the other end are priority messages.
    pub(crate) fn is_priority(self) -> bool {
        node_flags(self.node) & node_flag::PRIO_ML != 0
    }

    pub(crate) fn unlinking(self) -> u64 {
        // SAFETY: the view borrows the link, so the field is live and not written meanwhile.
        unsafe { ilink_unlinking(self.node).read() }
    }

    /// `ERTS_ML_FLG_EXTENDED`: a half of an external link.
    pub(crate) fn is_external(self) -> bool {
        node_flags(self.node) & node_flag::EXTENDED != 0
    }

    /// The external pid of an external link (`erts_link_to_elink(lnk)->ld.proc.other.item`).
    pub(crate) fn external_pid(self) -> Option<ExternalPid> {
        // SAFETY: the view borrows the link; `pid` is never written after creation.
        elink_of(self.node).map(|elink| unsafe { elink.as_ref() }.pid)
    }

    /// The local pid of an external link (`ld.dist.other.item`).
    pub(crate) fn external_local(self) -> Option<u64> {
        // SAFETY: as in `external_pid`.
        elink_of(self.node).map(|elink| unsafe { elink.as_ref() }.dist_half.other)
    }

    /// `elnk->dist`: the connection or dead-dist record of an external link.
    pub(crate) fn external_dist(self) -> Option<&'a MonLnkDist> {
        // SAFETY: as in `external_pid`; `dist` is written only through a `LinkMut`.
        elink_of(self.node).and_then(|elink| unsafe { (*elink.as_ptr()).dist.as_deref() })
    }
}

/// A mutably borrowed link.
pub(crate) struct LinkMut<'a> {
    node: NodePtr,
    _link: PhantomData<&'a mut Link>,
}

impl LinkMut<'_> {
    pub(crate) fn view(&self) -> LinkRef<'_> {
        LinkRef {
            node: self.node,
            _link: PhantomData,
        }
    }

    pub(crate) fn set_priority(&mut self, priority: bool) {
        let flags = node_flags(self.node) & !node_flag::PRIO_ML;
        let priority = if priority { node_flag::PRIO_ML } else { 0 };
        set_node_flags(self.node, flags | priority);
    }

    pub(crate) fn set_unlinking(&mut self, unlinking: u64) {
        // SAFETY: the view borrows the link exclusively, so nothing else reads the field.
        unsafe { ilink_unlinking(self.node).write(unlinking) }
    }

    /// Port of erts/emulator/beam/erl_monitor_link.c (erts_link_set_dead_dist), OTP-29.1.1.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn set_dead_dist(&mut self, nodename: u32) {
        let elink = elink_of(self.node).expect("dead dist on an external link");
        debug_assert_eq!(
            node_flags(self.node) & node_flag::TYPE_MASK,
            node_type::LINK_DIST_PROC
        );
        let dist = MonLnkDist::new(nodename);
        dist.lock().alive = false;
        // SAFETY: the view borrows this half exclusively; the other half is not yet
        // published, as erts sets dead dist before the link reaches a dist entry.
        unsafe {
            debug_assert!((*elink.as_ptr()).dist.is_none());
            (*elink.as_ptr()).dist = Some(std::sync::Arc::new(dist));
        }
    }
}

impl MonLnkTree<Link> {
    /// `erts_link_tree_lookup`.
    pub(crate) fn get(&self, other: u64) -> Option<LinkRef<'_>> {
        self.lookup_node(other).map(|node| LinkRef {
            node,
            _link: PhantomData,
        })
    }

    pub(crate) fn get_mut(&mut self, other: u64) -> Option<LinkMut<'_>> {
        self.lookup_node(other).map(|node| LinkMut {
            node,
            _link: PhantomData,
        })
    }

    /// `erts_link_tree_lookup` of an external pid key.
    pub(crate) fn get_external(&self, pid: &ExternalPid) -> Option<LinkRef<'_>> {
        self.lookup_node(external_key(pid)).map(|node| LinkRef {
            node,
            _link: PhantomData,
        })
    }

    pub(crate) fn get_external_mut(&mut self, pid: &ExternalPid) -> Option<LinkMut<'_>> {
        self.lookup_node(external_key(pid)).map(|node| LinkMut {
            node,
            _link: PhantomData,
        })
    }

    pub(crate) fn remove_external(&mut self, pid: &ExternalPid) -> Option<Link> {
        self.remove(external_key(pid))
    }

    /// Port of erts/emulator/beam/erl_monitor_link.c (erts_link_external_tree_lookup_create),
    /// OTP-29.1.1: the link to `other`, created and inserted when missing. A created link
    /// comes back with its dist half, which the caller inserts into the dist entry or
    /// releases, as erts does with `&elnk->ld.dist`.
    pub(crate) fn lookup_create_external(
        &mut self,
        kind: u32,
        this: u64,
        other: ExternalPid,
    ) -> (LinkMut<'_>, Option<Link>) {
        if let Some(node) = self.lookup_node(external_key(&other)) {
            return (
                LinkMut {
                    node,
                    _link: PhantomData,
                },
                None,
            );
        }
        let (proc_half, dist_half) = Link::create_external(kind, this, other);
        let node = proc_half.node;
        self.insert(proc_half);
        (
            LinkMut {
                node,
                _link: PhantomData,
            },
            Some(dist_half),
        )
    }

    /// Port of erts/emulator/beam/erl_monitor_link.c:1353 (`erts_link_tree_foreach`), OTP-29.1.1.
    pub(crate) fn iter(&self) -> impl Iterator<Item = LinkRef<'_>> {
        self.iter_nodes().map(|node| LinkRef {
            node,
            _link: PhantomData,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    type TestMonitor = Monitor<u32, u32>;

    fn black_height(node: Option<NodePtr>) -> usize {
        let Some(node) = node else { return 1 };
        let left_height = black_height(left(node));
        assert_eq!(
            left_height,
            black_height(right(node)),
            "equal black heights"
        );
        if is_red(node) {
            assert!(left(node).is_none_or(|child| !is_red(child)));
            assert!(right(node).is_none_or(|child| !is_red(child)));
        }
        for child in [left(node), right(node)].into_iter().flatten() {
            assert_eq!(parent(child), Some(node));
        }
        left_height + usize::from(!is_red(node))
    }

    fn check_tree<H: NodeHandle>(tree: &MonLnkTree<H>) {
        if let Some(root) = tree.root {
            assert!(!is_red(root));
            assert_eq!(parent(root), None);
        }
        black_height(tree.root);
    }

    fn next_random(state: &mut u64) -> u64 {
        *state ^= *state << 13;
        *state ^= *state >> 7;
        *state ^= *state << 17;
        *state
    }

    fn external(number: u32) -> ExternalPid {
        ExternalPid {
            sysname: 7,
            creation: 3,
            number,
            serial: 0,
        }
    }

    #[test]
    fn external_links_share_the_link_tree_with_internal_ones() {
        let mut tree = MonLnkTree::<Link>::default();
        for other in [5_u64, 1, 9] {
            tree.insert(Link::create(node_type::LINK_PROC, other, 0));
        }
        let mut dist_halves = Vec::new();
        for number in [40_u32, 2, 17] {
            let (link, dist) =
                tree.lookup_create_external(node_type::LINK_DIST_PROC, 5, external(number));
            assert!(link.view().is_external());
            dist_halves.push(dist.expect("created"));
        }
        check_tree(&tree);
        tree.insert(Link::create(node_type::LINK_PORT, (1 << 63) | 4, 0));
        // A second lookup-create finds the link by an equal pid stored elsewhere.
        let probe = external(17);
        let (found, dist) = tree.lookup_create_external(node_type::LINK_DIST_PROC, 5, probe);
        assert!(dist.is_none());
        assert_eq!(found.view().external_pid(), Some(probe));
        assert_eq!(found.view().external_local(), Some(5));
        // ml_cmp_keys: internal pids before external pids.
        let order = tree
            .iter()
            .map(|link| link.is_external())
            .collect::<Vec<_>>();
        assert_eq!(order.iter().filter(|external| **external).count(), 3);
        assert_eq!(tree.nodes().len(), 7);
        assert!(PidOrder::compare((1 << 63) | 4, external_key(&probe)).is_lt());
        assert!(PidOrder::compare(9, (1 << 63) | 4).is_lt());
        assert!(tree.get(9).is_some_and(|link| !link.is_external()));
        assert!(tree.get_external(&external(3)).is_none());
        let removed = tree.remove_external(&external(2)).expect("present");
        let dist = dist_halves.remove(1);
        Link::release_both(removed, dist);
        assert!(tree.get_external(&external(2)).is_none());
        check_tree(&tree);
        // The tree drops the proc halves; the dist halves are released on their own.
        drop(dist_halves);
    }

    #[test]
    fn dist_halves_enter_and_leave_the_connection_list() {
        let mld = std::sync::Arc::new(MonLnkDist::with_connection(42, 7));
        let mut tree = MonLnkTree::<Link>::default();
        for number in [1_u32, 2, 3] {
            let (_, dist) =
                tree.lookup_create_external(node_type::LINK_DIST_PROC, 11, external(number));
            assert!(dist.expect("created").dist_insert(&mld).is_ok());
        }
        // erts_link_dist_delete through the proc half: removed once, then not in the list.
        let link = tree.remove_external(&external(2)).expect("present");
        assert_eq!(
            link.view().external_dist().map(|d| d.connection_id),
            Some(7)
        );
        assert!(link.dist_delete_other());
        assert!(!link.dist_delete_other());
        link.release_external(true);
        // Connection down: the remaining dist halves come out in insertion order, and a
        // later delete through a proc half finds the connection dead.
        let taken = mld.take_links();
        let pids = taken
            .iter()
            .map(|half| half.view().external_pid().map(|pid| pid.number))
            .collect::<Vec<_>>();
        assert_eq!(pids, [Some(1), Some(3)]);
        assert!(!mld.is_alive());
        let link = tree.remove_external(&external(1)).expect("present");
        assert!(!link.dist_delete_other());
        link.release_external(false);
        let (_, dist) = tree.lookup_create_external(node_type::LINK_DIST_PROC, 11, external(9));
        assert!(dist.expect("created").dist_insert(&mld).is_err());
        drop(taken);
    }

    #[test]
    fn dead_dist_and_unlinking_live_in_the_external_link() {
        let mut tree = MonLnkTree::<Link>::default();
        let (mut link, dist) =
            tree.lookup_create_external(node_type::LINK_DIST_PROC, 11, external(1));
        link.set_dead_dist(42);
        link.set_unlinking(99);
        let mut dist = dist.expect("created");
        let view = dist.view();
        let mld = view.external_dist().expect("dead dist");
        assert_eq!(mld.nodename, 42);
        assert_eq!(mld.connection_id, !0);
        assert!(!mld.is_alive());
        assert_eq!(view.unlinking(), 99);
        dist.view_mut().set_unlinking(0);
        assert_eq!(
            tree.get_external(&external(1))
                .expect("present")
                .unlinking(),
            0
        );
    }

    #[test]
    fn link_tree_matches_a_btree_map_under_random_inserts_and_removes() {
        let mut tree = MonLnkTree::<Link>::default();
        let mut model = BTreeMap::new();
        let mut state = 0x9E37_79B9_7F4A_7C15;
        for step in 0..20_000u64 {
            let key = next_random(&mut state) % 512;
            if next_random(&mut state).is_multiple_of(3) {
                let removed = tree.remove(key).map(|link| link.view().unlinking());
                assert_eq!(removed, model.remove(&key));
            } else if let std::collections::btree_map::Entry::Vacant(entry) = model.entry(key) {
                let mut link = Link::create(node_type::LINK_PROC, key, 0);
                link.view_mut().set_unlinking(step);
                tree.insert(link);
                entry.insert(step);
            }
            if step % 257 == 0 {
                check_tree(&tree);
            }
            assert_eq!(
                tree.get(key).map(LinkRef::unlinking),
                model.get(&key).copied()
            );
        }
        check_tree(&tree);
        let mut keys: Vec<u64> = tree.iter().map(LinkRef::other).collect();
        keys.sort_unstable();
        assert_eq!(keys, model.keys().copied().collect::<Vec<_>>());
        assert_eq!(tree.drain().count(), model.len());
        assert!(tree.is_empty());
    }

    #[test]
    fn foreach_visits_both_subtrees_before_the_node() {
        let mut tree = MonLnkTree::<Link>::default();
        for key in 1..=7 {
            tree.insert(Link::create(node_type::LINK_PROC, key, 0));
        }
        // Inserting 1..=7 in order gives root 2 with subtrees {1} and {4: 3, {6: 5, 7}}.
        let order: Vec<u64> = tree.iter().map(LinkRef::other).collect();
        assert_eq!(order, vec![1, 3, 5, 7, 6, 4, 2]);
    }

    #[test]
    fn lookup_insert_returns_the_duplicate() {
        let mut tree = MonLnkTree::<Link>::default();
        tree.insert(Link::create(node_type::LINK_PROC, 5, 0));
        let duplicate = tree
            .lookup_insert(Link::create(node_type::LINK_PROC, 5, node_flag::PRIO_ML))
            .unwrap_err();
        assert_eq!(duplicate.view().flags() & node_flag::IN_TABLE, 0);
        assert_eq!(tree.get(5).unwrap().flags() & node_flag::PRIO_ML, 0);
    }

    #[test]
    fn monitor_halves_share_one_allocation_and_free_with_the_last() {
        let (origin, target) = TestMonitor::create(
            node_type::MONITOR_PROC,
            MonitorReference::ordinary(77),
            1,
            2,
            node_flag::TAG,
            9,
            3,
        );
        assert!(origin.is_other_half_of(&target));
        assert_eq!(origin.view().other(), 2);
        assert_eq!(target.view().other(), 1);
        assert!(target.view().is_target());
        assert_eq!(*target.view().info(), 9);
        assert_eq!(origin.view().origin_state(), Some(&3));
        assert_eq!(target.view().origin_state(), None);
        assert_eq!(origin.view().reference(), 77);
        drop(origin);
        assert_eq!(*target.view().info(), 9);
        drop(target);
    }

    #[test]
    fn monitor_tree_and_list_hold_the_two_halves() {
        let mut origins = MonLnkTree::<TestMonitor>::default();
        let mut targets = MonitorList::<u32, u32>::default();
        let mut sent = Vec::new();
        for reference in 0..64u64 {
            let (origin, target) = TestMonitor::create(
                node_type::MONITOR_PROC,
                MonitorReference::ordinary(arinsal_bifs::ordinary_ref_key([
                    reference as u32,
                    1,
                    0,
                ])),
                1,
                2,
                0,
                reference as u32,
                0,
            );
            origins.insert(origin);
            targets.insert(target);
            sent.push(arinsal_bifs::ordinary_ref_key([reference as u32, 1, 0]));
        }
        check_tree(&origins);
        assert_eq!(targets.iter().count(), 64);
        for (index, reference) in sent.iter().enumerate() {
            let mut origin = origins.remove(*reference).expect("origin half");
            *origin.view_mut().origin_state().unwrap() += 1;
            let target = targets.remove_target_of(&origin).expect("target half");
            assert!(target.is_other_half_of(&origin));
            assert_eq!(*target.view().info(), index as u32);
            assert!(targets.remove_target_of(&origin).is_none());
            if index % 2 == 0 {
                drop(origin);
                drop(target);
            } else {
                drop(target);
                drop(origin);
            }
        }
        assert!(origins.is_empty());
        assert!(targets.is_empty());
    }

    #[test]
    fn a_half_in_transit_becomes_a_handle_once() {
        let (origin, target) = TestMonitor::create(
            node_type::MONITOR_PROC,
            MonitorReference::ordinary(5),
            1,
            2,
            0,
            7,
            0,
        );
        let shared = target.into_shared();
        let copy = shared.clone();
        let target = MonitorData::take_half(shared, true).expect("target half");
        assert!(MonitorData::take_half(copy, true).is_none());
        assert!(target.is_other_half_of(&origin));
        let shared = origin.into_shared();
        assert_eq!(shared.reference(), 5);
        drop(target);
        let origin = MonitorData::take_half(shared, false).expect("origin half");
        assert_eq!(*origin.view().info(), 7);
    }

    #[test]
    fn a_target_in_another_list_is_not_removed() {
        let mut first = MonitorList::<u32, u32>::default();
        let mut second = MonitorList::<u32, u32>::default();
        let (origin, target) = TestMonitor::create(
            node_type::MONITOR_PROC,
            MonitorReference::ordinary(1),
            1,
            2,
            0,
            0,
            0,
        );
        first.insert(target);
        assert!(second.remove_target_of(&origin).is_none());
        assert!(first.remove_target_of(&origin).is_some());
        assert!(second.is_empty());
        drop(origin);
    }

    #[test]
    fn reference_order_is_memcmp_of_the_reference_words() {
        let low = arinsal_bifs::ordinary_ref_key([0x0100, 0, 0]);
        let high = arinsal_bifs::ordinary_ref_key([0x0001, 0, 0]);
        // Little-endian memcmp: the low byte of the first word decides first.
        assert_eq!(ReferenceOrder::compare(low, high), Ordering::Less);
    }
}
