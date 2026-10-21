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
    fn compare(left: u64, right: u64) -> Ordering {
        left.cmp(&right)
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

fn set_node_other(node: NodePtr, other: u64) {
    // SAFETY: as in `set_node_flags`.
    unsafe { (*node.as_ptr()).other = other }
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

    pub(crate) fn contains_key(&self, key: u64) -> bool {
        self.lookup_node(key).is_some()
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

    /// The nodes in the order erts `mon_lnk_rbt_foreach` visits them (`foreach_unordered__`:
    /// both subtrees before the node).
    fn nodes(&self) -> Vec<NodePtr> {
        let mut nodes = Vec::new();
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

    /// `erts_monitor_tree_foreach_delete` / `erts_link_tree_foreach_delete`: empty the tree,
    /// handing out its nodes in foreach order.
    pub(crate) fn drain(&mut self) -> std::vec::IntoIter<H> {
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
            .collect::<Vec<_>>()
            .into_iter()
    }
}

/// A doubly linked circular list of monitor target halves (`ERTS_P_LT_MONITORS`).
pub(crate) struct MonitorList<I, O> {
    first: Option<NodePtr>,
    /// Identity checked when a target half is removed through its origin half.
    id: u64,
    _handles: PhantomData<Monitor<I, O>>,
}

// SAFETY: as for `MonLnkTree`, the list owns its nodes as the handles it took in did.
unsafe impl<I: Send + Sync, O: Send> Send for MonitorList<I, O> {}

impl<I, O> Default for MonitorList<I, O> {
    fn default() -> Self {
        static NEXT_LIST_ID: AtomicU64 = AtomicU64::new(1);
        Self {
            first: None,
            id: NEXT_LIST_ID.fetch_add(1, AtomicOrdering::Relaxed),
            _handles: PhantomData,
        }
    }
}

impl<I, O> Drop for MonitorList<I, O> {
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

impl<I, O> MonitorList<I, O> {
    pub(crate) fn is_empty(&self) -> bool {
        self.first.is_none()
    }

    /// `erts_ml_dl_list_insert__`: append before the first node.
    pub(crate) fn insert(&mut self, monitor: Monitor<I, O>) {
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
        MonitorData::<I, O>::from_node(ml).set_target_list(self.id);
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
        MonitorData::<I, O>::from_node(ml).set_target_list(0);
    }

    /// Take the target half of `origin`'s monitor out of this list, if it is here (the
    /// demonitor and monitor-down paths of erts reach `&mdp->u.target` through the data).
    pub(crate) fn remove_target_of(&mut self, origin: &Monitor<I, O>) -> Option<Monitor<I, O>> {
        let data = MonitorData::<I, O>::from_node(origin.node);
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

    fn nodes(&self) -> Vec<NodePtr> {
        let mut nodes = Vec::new();
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
    pub(crate) fn iter(&self) -> impl Iterator<Item = MonitorRef<'_, I, O>> {
        self.nodes().into_iter().map(|node| MonitorRef {
            node,
            _monitor: PhantomData,
        })
    }

    /// `erts_monitor_list_foreach_delete`: empty the list in list order.
    pub(crate) fn drain(&mut self) -> std::vec::IntoIter<Monitor<I, O>> {
        let nodes = self.nodes();
        self.first = None;
        nodes
            .into_iter()
            .map(|node| {
                set_node_flags(node, node_flags(node) & !node_flag::IN_TABLE);
                MonitorData::<I, O>::from_node(node).set_target_list(0);
                Monitor::from_node(ContainedNode {
                    node,
                    _handle: PhantomData,
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
    }
}

/// Both halves of one monitor in one allocation (`ErtsMonitorData`). `info` is shared by both
/// halves and never changes; `origin_state` belongs to the origin half and is reached only
/// through it.
#[repr(C)]
pub(crate) struct MonitorData<I, O> {
    /// The halves are written by the process that holds each of them while the other process
    /// may read the shared fields, so they are interior-mutable.
    origin: UnsafeCell<MonLnkNode>,
    target: UnsafeCell<MonLnkNode>,
    /// `ref`: the key of both halves.
    reference: u64,
    /// `refc`: one for each half still held.
    refc: AtomicU32,
    /// The id of the list holding the target half, 0 when none.
    target_list: AtomicU64,
    info: I,
    origin_state: UnsafeCell<O>,
}

impl<I, O> MonitorData<I, O> {
    /// The data of a monitor node, borrowed for as long as one of its halves is held.
    fn from_node<'a>(node: NodePtr) -> &'a Self {
        // SAFETY: monitor nodes are created only by `Monitor::create`, inside a `MonitorData`
        // of this type, with `offset` pointing back to its start. The data lives while either
        // half is held, and the caller holds one. The fields written while it is shared (the
        // nodes, the origin state, the atomics) are interior-mutable, and `info` is immutable.
        unsafe { node_to_main(node).cast::<Self>().as_ref() }
    }

    fn target_node(&self) -> NodePtr {
        NonNull::new(self.target.get()).expect("field pointer is not null")
    }

    fn target_list(&self) -> u64 {
        self.target_list.load(AtomicOrdering::Relaxed)
    }

    fn set_target_list(&self, id: u64) {
        self.target_list.store(id, AtomicOrdering::Relaxed);
    }
}

/// One half of a monitor, owned by the process that holds it (`ErtsMonitor`).
pub(crate) struct Monitor<I, O> {
    node: NodePtr,
    _data: PhantomData<MonitorData<I, O>>,
}

// SAFETY: a half is moved between processes only as a whole (the monitor and demonitor signals);
// the data it shares with the other half is `info`, which must be `Sync`, and atomics.
unsafe impl<I: Send + Sync, O: Send> Send for Monitor<I, O> {}

impl<I, O> NodeHandle for Monitor<I, O> {
    type Order = ReferenceOrder;

    fn into_node(self) -> NodePtr {
        let node = self.node;
        std::mem::forget(self);
        node
    }

    fn from_node(node: ContainedNode<Self>) -> Self {
        Self {
            node: node.node,
            _data: PhantomData,
        }
    }
}

impl<I, O> Monitor<I, O> {
    /// `erts_monitor_create`: both halves of a new monitor. The origin half's `other` is the
    /// target, the target half's `other` the origin.
    pub(crate) fn create(
        kind: u32,
        reference: u64,
        origin: u64,
        target: u64,
        flags: u32,
        info: I,
        origin_state: O,
    ) -> (Self, Self) {
        debug_assert!(kind <= node_type::MONITOR_ALIAS);
        debug_assert_eq!(flags & node_flag::RESERVED, 0);
        let key_offset = offset_of!(MonitorData<I, O>, reference);
        let origin_offset = offset_of!(MonitorData<I, O>, origin);
        let target_offset = offset_of!(MonitorData<I, O>, target);
        let data = Box::new(MonitorData {
            origin: UnsafeCell::new(MonLnkNode::new(
                target,
                origin_offset,
                key_offset - origin_offset,
                kind | flags,
            )),
            target: UnsafeCell::new(MonLnkNode::new(
                origin,
                target_offset,
                key_offset - target_offset,
                kind | flags | node_flag::TARGET,
            )),
            reference,
            refc: AtomicU32::new(2),
            target_list: AtomicU64::new(0),
            info,
            origin_state: UnsafeCell::new(origin_state),
        });
        let data = Box::into_raw(data);
        // SAFETY: `data` was just allocated and is valid; the node pointers keep the provenance
        // of the whole allocation so a node can reach its key and its data.
        let (origin, target) = unsafe {
            (
                NonNull::new_unchecked(std::ptr::addr_of_mut!((*data).origin).cast()),
                NonNull::new_unchecked(std::ptr::addr_of_mut!((*data).target).cast()),
            )
        };
        (
            Self {
                node: origin,
                _data: PhantomData,
            },
            Self {
                node: target,
                _data: PhantomData,
            },
        )
    }

    pub(crate) fn view(&self) -> MonitorRef<'_, I, O> {
        MonitorRef {
            node: self.node,
            _monitor: PhantomData,
        }
    }

    pub(crate) fn view_mut(&mut self) -> MonitorMut<'_, I, O> {
        MonitorMut {
            node: self.node,
            _monitor: PhantomData,
        }
    }

    /// Whether `self` and `other` are the two halves of one monitor.
    pub(crate) fn is_other_half_of(&self, other: &Self) -> bool {
        self.node != other.node && node_to_main(self.node) == node_to_main(other.node)
    }
}

impl<I, O> Drop for Monitor<I, O> {
    /// `erts_monitor_release`: the data is destroyed with the last half.
    fn drop(&mut self) {
        let data = MonitorData::<I, O>::from_node(self.node);
        if data.refc.fetch_sub(1, AtomicOrdering::Release) != 1 {
            return;
        }
        std::sync::atomic::fence(AtomicOrdering::Acquire);
        let main = node_to_main(self.node).cast::<MonitorData<I, O>>();
        // SAFETY: this was the last half, so nothing else reaches the data; it was allocated by
        // `Box::new` in `Monitor::create`.
        drop(unsafe { Box::from_raw(main.as_ptr()) });
    }
}

/// A borrowed monitor half.
pub(crate) struct MonitorRef<'a, I, O> {
    node: NodePtr,
    _monitor: PhantomData<&'a Monitor<I, O>>,
}

impl<I, O> Clone for MonitorRef<'_, I, O> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<I, O> Copy for MonitorRef<'_, I, O> {}

impl<'a, I, O> MonitorRef<'a, I, O> {
    pub(crate) fn kind(self) -> u32 {
        node_flags(self.node) & node_flag::TYPE_MASK
    }

    pub(crate) fn flags(self) -> u32 {
        node_flags(self.node)
    }

    pub(crate) fn is_target(self) -> bool {
        node_flags(self.node) & node_flag::TARGET != 0
    }

    /// `other.item`: the far end.
    pub(crate) fn other(self) -> u64 {
        node_other(self.node)
    }

    pub(crate) fn reference(self) -> u64 {
        MonitorData::<I, O>::from_node(self.node).reference
    }

    pub(crate) fn info(self) -> &'a I {
        &MonitorData::<I, O>::from_node(self.node).info
    }

    /// The origin state; `None` on a target half.
    pub(crate) fn origin_state(self) -> Option<&'a O> {
        if self.is_target() {
            return None;
        }
        let data = MonitorData::<I, O>::from_node(self.node);
        // SAFETY: only the origin half reaches the origin state, and this view borrows it
        // shared, so no `&mut` to the state is alive.
        Some(unsafe { &*data.origin_state.get() })
    }
}

/// A mutably borrowed monitor half.
pub(crate) struct MonitorMut<'a, I, O> {
    node: NodePtr,
    _monitor: PhantomData<&'a mut Monitor<I, O>>,
}

impl<'a, I, O> MonitorMut<'a, I, O> {
    pub(crate) fn view(&self) -> MonitorRef<'_, I, O> {
        MonitorRef {
            node: self.node,
            _monitor: PhantomData,
        }
    }

    /// Set the holder flags (alias state, spawn and priority flags); the container state and
    /// the half's identity stay.
    pub(crate) fn set_flags(&mut self, flags: u32) {
        let reserved = node_flags(self.node) & node_flag::RESERVED;
        set_node_flags(self.node, reserved | (flags & !node_flag::RESERVED));
    }

    pub(crate) fn set_other(&mut self, other: u64) {
        set_node_other(self.node, other);
    }

    /// The origin state; `None` on a target half.
    pub(crate) fn origin_state(self) -> Option<&'a mut O> {
        if node_flags(self.node) & node_flag::TARGET != 0 {
            return None;
        }
        let data = MonitorData::<I, O>::from_node(self.node);
        // SAFETY: only the origin half reaches the origin state, and this view borrows that
        // half exclusively.
        Some(unsafe { &mut *data.origin_state.get() })
    }
}

impl<I, O> MonLnkTree<Monitor<I, O>> {
    /// `erts_monitor_tree_lookup`.
    pub(crate) fn get(&self, reference: u64) -> Option<MonitorRef<'_, I, O>> {
        self.lookup_node(reference).map(|node| MonitorRef {
            node,
            _monitor: PhantomData,
        })
    }

    pub(crate) fn get_mut(&mut self, reference: u64) -> Option<MonitorMut<'_, I, O>> {
        self.lookup_node(reference).map(|node| MonitorMut {
            node,
            _monitor: PhantomData,
        })
    }

    /// `erts_monitor_tree_foreach`.
    pub(crate) fn iter(&self) -> impl Iterator<Item = MonitorRef<'_, I, O>> {
        self.nodes().into_iter().map(|node| MonitorRef {
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
}

/// A local link owned by the process at one end (`ErtsLink` of an `ErtsILink`).
pub(crate) struct Link {
    node: NodePtr,
}

// SAFETY: a link node holds plain data and is moved between processes only as a whole.
unsafe impl Send for Link {}

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
        let link = Box::new(ILink {
            link: MonLnkNode::new(other, 0, offset_of!(MonLnkNode, other), kind | flags),
            unlinking: 0,
        });
        let link = Box::into_raw(link);
        // SAFETY: `link` was just allocated; the node is its first field.
        let node = unsafe { NonNull::new_unchecked(std::ptr::addr_of_mut!((*link).link)) };
        Self { node }
    }

    pub(crate) fn view(&self) -> LinkRef<'_> {
        LinkRef {
            node: self.node,
            _link: PhantomData,
        }
    }

    pub(crate) fn view_mut(&mut self) -> LinkMut<'_> {
        LinkMut {
            node: self.node,
            _link: PhantomData,
        }
    }
}

impl Drop for Link {
    /// `erts_link_release` of an internal link.
    fn drop(&mut self) {
        let main = node_to_main(self.node).cast::<ILink>();
        // SAFETY: the node is the first field of an `ILink` allocated by `Box::new` in
        // `Link::create`, and this handle owned it.
        drop(unsafe { Box::from_raw(main.as_ptr()) });
    }
}

fn ilink_unlinking(node: NodePtr) -> *mut u64 {
    let main = node_to_main(node).cast::<ILink>();
    // SAFETY: link nodes are created only by `Link::create` as the first field of a live
    // `ILink`; this only forms a pointer to its `unlinking` field.
    unsafe { std::ptr::addr_of_mut!((*main.as_ptr()).unlinking) }
}

/// A borrowed link.
#[derive(Clone, Copy)]
pub(crate) struct LinkRef<'a> {
    node: NodePtr,
    _link: PhantomData<&'a Link>,
}

impl LinkRef<'_> {
    pub(crate) fn kind(self) -> u32 {
        node_flags(self.node) & node_flag::TYPE_MASK
    }

    pub(crate) fn flags(self) -> u32 {
        node_flags(self.node)
    }

    pub(crate) fn other(self) -> u64 {
        node_other(self.node)
    }

    pub(crate) fn unlinking(self) -> u64 {
        // SAFETY: the view borrows the link, so the field is live and not written meanwhile.
        unsafe { ilink_unlinking(self.node).read() }
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

    pub(crate) fn set_flags(&mut self, flags: u32) {
        let reserved = node_flags(self.node) & node_flag::RESERVED;
        set_node_flags(self.node, reserved | (flags & !node_flag::RESERVED));
    }

    pub(crate) fn set_unlinking(&mut self, unlinking: u64) {
        // SAFETY: the view borrows the link exclusively, so nothing else reads the field.
        unsafe { ilink_unlinking(self.node).write(unlinking) }
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

    /// `erts_link_tree_foreach`.
    pub(crate) fn iter(&self) -> impl Iterator<Item = LinkRef<'_>> {
        self.nodes().into_iter().map(|node| LinkRef {
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
        let (origin, target) =
            TestMonitor::create(node_type::MONITOR_PROC, 77, 1, 2, node_flag::TAG, 9, 3);
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
                arinsal_bifs::ordinary_ref_key([reference as u32, 1, 0]),
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
    fn a_target_in_another_list_is_not_removed() {
        let mut first = MonitorList::<u32, u32>::default();
        let mut second = MonitorList::<u32, u32>::default();
        let (origin, target) = TestMonitor::create(node_type::MONITOR_PROC, 1, 1, 2, 0, 0, 0);
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
