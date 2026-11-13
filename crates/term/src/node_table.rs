//! The node table: one `ErlNode` per `(sysname, creation)`, shared by every external pid, port
//! and reference that names that node.
//!
//! Port of erts/emulator/beam/erl_node_tables.c (`erts_node_table`, `erts_node_table_rwmtx`,
//! `node_table_hash`, `node_table_cmp`, `node_table_alloc`, `node_table_free`,
//! `erts_find_or_insert_node`, `try_delete_node`, `erts_schedule_delete_node`,
//! `erts_this_node`, `erts_set_this_node`, the node part of `erts_init_node_tables`) and
//! erl_node_tables.h (`ErlNode`, `erts_init_node_entry`, `erts_ref_node_entry`,
//! `erts_deref_node_entry`, `erts_node_refc`), OTP-29.1.1.
//!
//! An `ExternalThing` holds the address of its `ErlNode` in its node word and one counted
//! reference on it; the reference is released when the thing's off-heap list is swept.

use std::sync::atomic::{AtomicIsize, AtomicUsize, Ordering};
use std::sync::{OnceLock, RwLock};

use arinsal_alloc::typed::ErtsAlcType;

use crate::index_table::{
    Hash, HashBucket, HashEntry, HashFunctions, HashValue, alloc_entry, free_entry, init_entry,
};
use crate::{Atom, Term, atoms};

/// `ErlNode` (erl_node_tables.h). `dist_entry` is not yet a member: the dist table lives in
/// `crates/vm`.
#[repr(C)]
pub struct ErlNode {
    /// `hash_bucket`: first member, so the entry address is its bucket address.
    hash_bucket: HashBucket,
    /// `refc`: -1 while only the table holds the entry, as `erts_init_node_entry(enp, -1)`.
    refc: AtomicIsize,
    /// `sysname`: the tagged atom word (`Eterm`), which generated code for `node/0` loads at
    /// [`ERL_NODE_SYSNAME_OFFSET`] through `erts_this_node`.
    sysname: u64,
    /// `creation`.
    creation: u32,
}

impl HashEntry for ErlNode {}

impl ErlNode {
    /// `np->sysname`.
    pub fn sysname(&self) -> Atom {
        Term(self.sysname)
            .as_atom()
            .expect("ErlNode sysname is an atom")
    }

    /// `np->creation`.
    pub fn creation(&self) -> u32 {
        self.creation
    }

    /// `erts_node_refc`.
    pub fn refc(&self) -> isize {
        self.refc.load(Ordering::Acquire)
    }

    /// `erts_ref_node_entry` (`erts_refc_inctest`): the new count, at least `min_val`.
    fn ref_entry(&self, min_val: isize) -> isize {
        let refc = self.refc.fetch_add(1, Ordering::AcqRel) + 1;
        debug_assert!(
            refc >= min_val,
            "erts_ref_node_entry: refc {refc} < {min_val}"
        );
        refc
    }
}

/// Some large primes (erl_node_tables.c).
const PRIME0: HashValue = 268_438_039;

/// `HashFunctions` of `erts_node_table`.
struct NodeTableFunctions;

impl HashFunctions for NodeTableFunctions {
    type Entry = ErlNode;
    type Template<'a> = (Atom, u32);

    // Port of erl_node_tables.c (node_table_hash).
    fn hash(&self, &(sysname, creation): &(Atom, u32)) -> HashValue {
        let h = crate::global_atoms().hvalue(sysname).unwrap_or(0);
        h.wrapping_add(HashValue::from(creation))
            .wrapping_mul(PRIME0)
    }

    // Port of erl_node_tables.c (node_table_cmp).
    fn cmp(&self, &(sysname, creation): &(Atom, u32), obj: &ErlNode) -> bool {
        obj.sysname == Term::atom(sysname).tagged_word() && obj.creation == creation
    }

    // Port of erl_node_tables.c (node_table_alloc).
    fn alloc(&self, &(sysname, creation): &(Atom, u32)) -> *mut ErlNode {
        let enp = alloc_entry::<ErlNode>(ErtsAlcType::NODE_ENTRY);
        init_entry(
            enp,
            ErlNode {
                hash_bucket: HashBucket::new(),
                refc: AtomicIsize::new(-1),
                sysname: Term::atom(sysname).tagged_word(),
                creation,
            },
        );
        enp
    }

    // Port of erl_node_tables.c (node_table_free).
    fn free(&self, obj: &ErlNode) {
        free_entry(std::ptr::from_ref(obj).cast_mut(), ErtsAlcType::NODE_ENTRY);
    }
}

/// `offsetof(ErlNode, sysname)`.
pub const ERL_NODE_SYSNAME_OFFSET: usize = std::mem::offset_of!(ErlNode, sysname);

/// `erts_this_node`: the entry of the local node, holding one reference. Set by
/// `erts_init_node_tables` and replaced only by [`set_this_node`].
static ERTS_THIS_NODE: AtomicUsize = AtomicUsize::new(0);

/// `erts_node_table` under `erts_node_table_rwmtx`.
fn node_table() -> &'static RwLock<Hash> {
    static TABLE: OnceLock<RwLock<Hash>> = OnceLock::new();
    TABLE.get_or_init(init_node_tables)
}

/// The node part of `erts_init_node_tables`: the table and `erts_this_node` for
/// `nonode@nohost` with creation 0, referenced once by `erts_this_node`.
// Port of erl_node_tables.c (erts_init_node_tables), OTP-29.1.1.
fn init_node_tables() -> RwLock<Hash> {
    let mut table = Hash::init(ErtsAlcType::NODE_TABLE, 11);
    let addr = table.put(&NodeTableFunctions, &(atoms::NONAME, 0));
    // +1 for erts_this_node (`erts_init_node_entry(erts_this_node, 1)`).
    crate::raw::node_entry(addr)
        .refc
        .store(1, Ordering::Release);
    ERTS_THIS_NODE.store(addr, Ordering::Release);
    RwLock::new(table)
}

fn read_table() -> std::sync::RwLockReadGuard<'static, Hash> {
    node_table()
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn write_table() -> std::sync::RwLockWriteGuard<'static, Hash> {
    node_table()
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// One counted reference on a node table entry (`ErlNode *` plus one `erts_ref_node_entry`).
/// Cloning takes another reference, dropping one is `erts_deref_node_entry`.
#[derive(Debug, PartialEq, Eq)]
pub struct Node(usize);

impl Node {
    /// `erts_find_or_insert_node(sysname, creation, book)`: the entry for this node, with one
    /// reference taken for the caller.
    // Port of erl_node_tables.c (erts_find_or_insert_node), OTP-29.1.1.
    pub fn new(sysname: Atom, creation: u32) -> Self {
        let tmpl = (sysname, creation);
        {
            let table = read_table();
            if let Some(res) = table.get(&NodeTableFunctions, &tmpl) {
                if res.ref_entry(1) < 2 {
                    // Pending delete: the scheduled `try_delete_node` releases one count.
                    res.ref_entry(1);
                }
                return Self(std::ptr::from_ref(res) as usize);
            }
        }
        let mut table = write_table();
        let addr = table.put(&NodeTableFunctions, &tmpl);
        let res = crate::raw::node_entry(addr);
        if res.ref_entry(0) < 2 {
            // New (refc was -1) or pending delete.
            res.ref_entry(1);
        }
        Self(addr)
    }

    /// The entry.
    pub fn entry(&self) -> &ErlNode {
        crate::raw::node_entry(self.0)
    }

    /// `np->sysname`.
    pub fn sysname(&self) -> Atom {
        self.entry().sysname()
    }

    /// `np->creation`.
    pub fn creation(&self) -> u32 {
        self.entry().creation
    }

    /// The entry address an `ExternalThing` stores in its node word; the thing takes over this
    /// reference.
    pub(crate) fn into_raw(self) -> u64 {
        let addr = self.0 as u64;
        std::mem::forget(self);
        addr
    }

    /// Take over the reference an `ExternalThing`'s node word holds.
    ///
    /// Contract: `word` is the node word of an external thing whose off-heap list entry owns its
    /// reference, and that list entry gives the reference up.
    pub(crate) fn from_raw(word: u64) -> Self {
        Self(word as usize)
    }

    /// `erts_ref_node_entry(word, 2, ...)` for a copy of a live external thing: a new reference
    /// on the entry the source thing already references.
    ///
    /// Contract: `word` is the node word of a live external thing.
    // Port of erts/emulator/beam/copy.c (copy_struct_x, `erts_ref_node_entry(etp->node, 2, ..)`).
    pub(crate) fn ref_raw(word: u64) -> Self {
        crate::raw::node_entry(word as usize).ref_entry(2);
        Self(word as usize)
    }

    /// `erts_node_refc`.
    pub fn refc(&self) -> isize {
        self.entry().refc()
    }
}

impl Clone for Node {
    fn clone(&self) -> Self {
        self.entry().ref_entry(2);
        Self(self.0)
    }
}

impl Drop for Node {
    // Port of erl_node_tables.h (erts_deref_node_entry), OTP-29.1.1.
    fn drop(&mut self) {
        if self.entry().refc.fetch_sub(1, Ordering::AcqRel) - 1 == 0 {
            schedule_delete_node(self.0);
        }
    }
}

/// `erts_schedule_delete_node`.
///
/// erts defers the delete by `node_tab_delete_delay` through `erts_start_timer_callback`; the
/// timer wheel and the delay live in `crates/vm` and are not reachable from here yet, so the
/// delete runs at once, as erts does for a delay of 0.
// Port of erl_node_tables.c (erts_schedule_delete_node), OTP-29.1.1.
fn schedule_delete_node(enp: usize) {
    try_delete_node(enp);
}

/// `try_delete_node`.
// Port of erl_node_tables.c (try_delete_node), OTP-29.1.1.
fn try_delete_node(enp: usize) {
    let refc = {
        let mut table = write_table();
        // Another thread may have looked the node up after refc became zero; it then took two
        // counts, one of which is this thread's to release.
        let entry = crate::raw::node_entry(enp);
        let refc = entry.refc.fetch_sub(1, Ordering::AcqRel) - 1;
        if refc == -1 {
            table.erase(&NodeTableFunctions, enp);
        }
        refc
    };
    if refc == 0 {
        schedule_delete_node(enp);
    }
}

/// The address of `erts_this_node`, which generated code loads to reach the local node entry.
/// Initialises the node tables first, so the word is never null once code can read it.
pub fn erts_this_node_addr() -> usize {
    node_table();
    std::ptr::from_ref(&ERTS_THIS_NODE) as usize
}

/// `erts_this_node`.
fn this_node_entry() -> &'static ErlNode {
    node_table();
    crate::raw::node_entry(ERTS_THIS_NODE.load(Ordering::Acquire))
}

/// `erts_this_node->sysname` and `erts_this_node->creation`.
pub fn this_node() -> (Atom, u32) {
    let np = this_node_entry();
    (np.sysname(), np.creation)
}

/// `erts_set_this_node`: the local node becomes the entry for `(sysname, creation)`. The only
/// writer of `erts_this_node`; callers hold the thread-progress block, so no thread is reading
/// the old entry when its reference is released.
// Port of erl_node_tables.c (erts_set_this_node), OTP-29.1.1.
pub fn set_this_node(sysname: Atom, creation: u32) {
    node_table();
    let old = ERTS_THIS_NODE.load(Ordering::Acquire);
    // `erts_refc_dectest(&erts_this_node->refc, 0) == 0` → `try_delete_node`.
    if crate::raw::node_entry(old)
        .refc
        .fetch_sub(1, Ordering::AcqRel)
        - 1
        == 0
    {
        try_delete_node(old);
    }
    ERTS_THIS_NODE.store(0, Ordering::Release);
    let np = Node::new(sysname, creation);
    ERTS_THIS_NODE.store(np.into_raw() as usize, Ordering::Release);
}

/// `(sysname, creation)` of every entry of `erts_node_table`, read under its lock
/// (`hash_foreach`).
pub fn node_table_entries() -> Vec<(Atom, u32)> {
    let table = read_table();
    let mut entries = Vec::new();
    table.foreach::<ErlNode>(|enp| entries.push((enp.sysname(), enp.creation)));
    entries
}

/// `erts_node_table_size`-style count of entries (`node_entries`).
pub fn node_table_len() -> usize {
    let table = read_table();
    let mut n = 0;
    table.foreach::<ErlNode>(|_| n += 1);
    n
}

#[cfg(test)]
mod tests {
    use super::*;

    fn atom(name: &str) -> Atom {
        crate::global_atoms().intern(name).unwrap()
    }

    #[test]
    fn one_entry_per_sysname_and_creation() {
        let name = atom("node_table_unit_a@127.0.0.1");
        let a = Node::new(name, 7);
        let b = Node::new(name, 7);
        assert_eq!(a, b);
        assert_eq!(a.refc(), 2);
        let c = Node::new(name, 8);
        assert_ne!(a, c);
        drop(b);
        assert_eq!(a.refc(), 1);
        let d = a.clone();
        assert_eq!(a.refc(), 2);
        drop(d);
        assert!(node_table_entries().contains(&(name, 7)));
        drop(a);
        drop(c);
        assert!(!node_table_entries().contains(&(name, 7)));
        assert!(!node_table_entries().contains(&(name, 8)));
    }

    #[test]
    fn deleted_entry_is_recreated() {
        let name = atom("node_table_unit_b@127.0.0.1");
        drop(Node::new(name, 1));
        assert!(!node_table_entries().contains(&(name, 1)));
        let again = Node::new(name, 1);
        assert_eq!(again.refc(), 1);
        assert_eq!((again.sysname(), again.creation()), (name, 1));
    }
}
