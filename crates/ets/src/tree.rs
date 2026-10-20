use super::{EtsError, HeapAlloc, RangeSelection, StoredTerm, Term, TreeDbTerm, cmp};
pub(super) use crate::dbterm::InsertResult;
use crate::dbterm::{
    DbTreeStack, Link, SlotSearch, join_trees, slot_search, split_tree, tree_insert, tree_linkout,
    tree_put,
};
use smallvec::SmallVec;
use std::cmp::Ordering;

// Port of erl_db_tree_util.h (STACK_NEED): 90 entries on 64-bit, 50 on 32-bit.
const TREE_STACK_NEED: usize = crate::dbterm::STACK_NEED;

struct TreeStack<T> {
    entries: SmallVec<[T; TREE_STACK_NEED]>,
}

impl<T> TreeStack<T> {
    fn new() -> Self {
        Self {
            entries: SmallVec::new(),
        }
    }

    fn push(&mut self, entry: T) {
        self.entries.push(entry);
    }

    fn pop(&mut self) -> Option<T> {
        self.entries.pop()
    }
}

/// The root of an AVL tree of `TreeDbTerm` blocks (`DbTableTree.root`) with the item count and
/// the static slot stack (`DbTableTree.static_stack`) the `ets:slot/2` walk keeps between calls.
pub(super) struct TreeRoot {
    root: Link,
    nitems: usize,
    /// Bumped by every change of the tree; the stack is only valid for the version it was made at.
    version: u64,
    stack: parking_lot::Mutex<DbTreeStack>,
}

impl Default for TreeRoot {
    fn default() -> Self {
        Self::new()
    }
}

impl TreeRoot {
    pub(super) fn new() -> Self {
        Self::from_link(None, 0)
    }

    pub(super) fn from_link(root: Link, nitems: usize) -> Self {
        Self {
            root,
            nitems,
            version: 0,
            stack: parking_lot::Mutex::new(DbTreeStack::new()),
        }
    }

    /// The tree's root link.
    pub(super) fn link(&self) -> &Link {
        &self.root
    }

    /// `NITEMS` of a plain tree table. CA-tree base nodes do not keep it.
    pub(super) fn count(&self) -> usize {
        self.nitems
    }

    /// Detach the whole tree.
    pub(super) fn take(&mut self) -> (Link, usize) {
        self.version += 1;
        (self.root.take(), std::mem::take(&mut self.nitems))
    }

    /// Port of erts/emulator/beam/erl_db_tree.c (db_put_dbterm_tree_common), OTP-29.1.1.
    pub(super) fn insert(&mut self, object: TreeDbTerm, keypos: usize) {
        let key = object.key(keypos);
        self.insert_with_key(object, key, keypos, false);
    }

    /// Insert or replace using the key already read by the caller. `key_clash_fail` ports
    /// `insert_new`'s single-path check.
    // Port of erts/emulator/beam/erl_db_tree.c (db_put_dbterm_tree_common), OTP-29.1.1.
    pub(super) fn insert_with_key(
        &mut self,
        object: TreeDbTerm,
        key: Term,
        keypos: usize,
        key_clash_fail: bool,
    ) -> InsertResult {
        self.version += 1;
        let result = tree_insert(&mut self.root, object, key, keypos, key_clash_fail);
        if matches!(result, InsertResult::Inserted) {
            self.nitems = self.nitems.wrapping_add(1);
        }
        result
    }

    /// Store the source object `term` under `key` in place, as `db_put_tree_common` does: an
    /// equal key's block is reused (`replace_dbterm`), a new key gets a new block. Returns the
    /// outcome and the accounting size of the stored object.
    // Port of erts/emulator/beam/erl_db_tree.c (db_put_tree_common), OTP-29.1.1.
    pub(super) fn put_term(
        &mut self,
        term: Term,
        key: Term,
        keypos: usize,
        compressed: bool,
        key_clash_fail: bool,
    ) -> Result<(InsertResult, usize), EtsError> {
        const PREFIX_WORDS: usize = 3;
        self.version += 1;
        let mut new_words = 0;
        let result = tree_put(
            &mut self.root,
            key,
            keypos,
            key_clash_fail,
            |old| match old {
                Some(old) => {
                    StoredTerm::overwrite_from_input(old, term, compressed, keypos, PREFIX_WORDS)?;
                    new_words = old.db_size_words;
                    Ok(None)
                }
                None => {
                    let new = StoredTerm::copy_for_table(term, compressed, keypos, PREFIX_WORDS)?;
                    new_words = new.db_size_words;
                    Ok(Some(new))
                }
            },
        )?;
        if matches!(result, InsertResult::Inserted) {
            self.nitems = self.nitems.wrapping_add(1);
        }
        Ok((result, new_words))
    }

    /// Unlink the object with `key` and return it.
    // Port of erts/emulator/beam/erl_db_tree.c (linkout_tree), OTP-29.1.1.
    pub(super) fn linkout(&mut self, key: Term, keypos: usize) -> Option<TreeDbTerm> {
        self.linkout_matching(key, keypos, |_| true)
    }

    /// Unlink the object with `key` for which `matches` holds, and return it.
    // Port of erts/emulator/beam/erl_db_tree.c (linkout_tree / linkout_object_tree),
    // OTP-29.1.1.
    pub(super) fn linkout_matching(
        &mut self,
        key: Term,
        keypos: usize,
        mut matches: impl FnMut(&StoredTerm) -> bool,
    ) -> Option<TreeDbTerm> {
        let removed = tree_linkout(&mut self.root, key, keypos, &mut matches)?;
        self.version += 1;
        self.nitems = self.nitems.wrapping_sub(1);
        Some(removed)
    }

    /// Remove by key; the removed object's accounting size, for CA-tree memory updates.
    pub(super) fn remove_matching(
        &mut self,
        key: Term,
        keypos: usize,
        matches: impl FnMut(&StoredTerm) -> bool,
    ) -> Option<usize> {
        self.linkout_matching(key, keypos, matches)
            .map(|removed| removed.db_size_words)
    }

    /// The object at `key`, for an update in place.
    ///
    /// Port of erts/emulator/beam/erl_db_tree.c (find_node), OTP-29.1.1.
    pub(super) fn get_mut(&mut self, key: Term, keypos: usize) -> Option<&mut StoredTerm> {
        let mut node = self.root.as_deref_mut();
        while let Some(current) = node {
            match cmp(key, current.key(keypos)) {
                Ordering::Equal => return Some(current),
                Ordering::Less => node = current.prefix.left.as_deref_mut(),
                Ordering::Greater => node = current.prefix.right.as_deref_mut(),
            }
        }
        None
    }

    /// Prime the slot stack as `db_first_tree_common` / `db_last_tree_common` do.
    // Port of erts/emulator/beam/erl_db_tree.c (db_first_tree_common, db_last_tree_common),
    // OTP-29.1.1.
    pub(super) fn prime_stack(&self, last: bool) {
        let mut stack = self.stack.lock();
        stack.reset(self.version);
        if last {
            if stack.push_right_spine(&self.root) {
                stack.set_slot(self.nitems);
            }
        } else if stack.push_left_spine(&self.root) {
            stack.set_slot(1);
        }
    }

    /// Port of erts/emulator/beam/erl_db_tree.c (slot_search), OTP-29.1.1; `slot` counts from 1.
    pub(super) fn slot_search(&self, slot: usize) -> SlotSearch<'_> {
        let mut stack = self.stack.lock();
        if stack.version != self.version {
            stack.reset(self.version);
        }
        slot_search(&self.root, slot, &mut stack)
    }

    /// Split into the objects below the split key, the rest and the split key.
    // Port of erts/emulator/beam/erl_db_catree.c (split_tree), OTP-29.1.1.
    pub(super) fn split_for_catree(mut self, keypos: usize) -> (Self, Self, Term) {
        let root = self.root.take().expect("non-empty CA-tree base");
        let (left, right, split_key) = split_tree(root, keypos);
        // CA-tree base nodes keep no item count: the table counts (`DbTableCATree` counters).
        (
            Self::from_link(left, 0),
            Self::from_link(right, 0),
            split_key,
        )
    }

    /// Port of erts/emulator/beam/erl_db_catree.c (join_trees), OTP-29.1.1.
    pub(super) fn join_ordered(left: Self, right: Self) -> Self {
        Self::from_link(join_trees(left.root, right.root), 0)
    }
}

/// Read access to an AVL tree of `TreeDbTerm` blocks.
pub(super) struct Node;

impl Node {
    /// Port of erts/emulator/beam/erl_db_tree.c (find_node), OTP-29.1.1.
    pub(super) fn get(root: &TreeRoot, key: Term, keypos: usize) -> Option<&StoredTerm> {
        let mut node = root.link().as_deref();
        while let Some(current) = node {
            match cmp(key, current.key(keypos)) {
                Ordering::Equal => return Some(current),
                Ordering::Less => node = current.prefix.left.as_deref(),
                Ordering::Greater => node = current.prefix.right.as_deref(),
            }
        }
        None
    }

    /// The first or last object in key order.
    // Port of erts/emulator/beam/erl_db_tree.c (db_first_tree_common / db_last_tree_common),
    // OTP-29.1.1.
    pub(super) fn edge(root: &TreeRoot, last: bool) -> Option<&StoredTerm> {
        let mut node = root.link().as_deref()?;
        loop {
            let child = if last {
                &node.prefix.right
            } else {
                &node.prefix.left
            };
            match child.as_deref() {
                Some(child) => node = child,
                None => return Some(node),
            }
        }
    }

    /// Port of erts/emulator/beam/erl_db_tree.c (traverse_forward), OTP-29.1.1.
    pub(super) fn walk<'a>(root: &'a TreeRoot, out: &mut Vec<&'a StoredTerm>) {
        let mut pending = TreeStack::new();
        let mut current = root.link().as_deref();
        loop {
            while let Some(node) = current {
                pending.push(node);
                current = node.prefix.left.as_deref();
            }
            let Some(node) = pending.pop() else { break };
            out.push(node);
            current = node.prefix.right.as_deref();
        }
    }

    /// Visit each object in key order without materializing an object-reference vector.
    // Port of erts/emulator/beam/erl_db_tree.c (traverse_forward), OTP-29.1.1.
    pub(super) fn walk_each<F>(root: &TreeRoot, visit: &mut F) -> Result<(), EtsError>
    where
        F: FnMut(&StoredTerm) -> Result<(), EtsError>,
    {
        let mut pending = TreeStack::new();
        let mut current = root.link().as_deref();
        loop {
            while let Some(node) = current {
                pending.push(node);
                current = node.prefix.left.as_deref();
            }
            let Some(node) = pending.pop() else { break };
            visit(node)?;
            current = node.prefix.right.as_deref();
        }
        Ok(())
    }

    /// Port of erts/emulator/beam/erl_db_tree.c (find_next) and :3232 (find_prev), OTP-29.1.1.
    pub(super) fn scan_after<F>(
        root: &TreeRoot,
        cursor: Option<Term>,
        reverse: bool,
        keypos: usize,
        visit: &mut F,
    ) -> Result<bool, EtsError>
    where
        F: FnMut(&StoredTerm) -> Result<bool, EtsError>,
    {
        Self::scan_where(
            root,
            reverse,
            &|key| {
                cursor.is_none_or(|cursor| {
                    let order = cmp(key, cursor);
                    if reverse {
                        order == Ordering::Less
                    } else {
                        order == Ordering::Greater
                    }
                })
            },
            keypos,
            visit,
        )
    }

    /// Visit the objects whose keys `eligible` accepts in key order (descending when `reverse`)
    /// until `visit` returns true. The accepted keys must be a prefix of that order.
    ///
    /// Port of erts/emulator/beam/erl_db_tree.c, traverse_forward, traverse_backwards,
    /// find_next and find_prev, OTP-29.1.1.
    pub(super) fn scan_where<F>(
        root: &TreeRoot,
        reverse: bool,
        eligible: &dyn Fn(Term) -> bool,
        keypos: usize,
        visit: &mut F,
    ) -> Result<bool, EtsError>
    where
        F: FnMut(&StoredTerm) -> Result<bool, EtsError>,
    {
        let mut pending = TreeStack::new();
        let mut current = root.link().as_deref();
        while let Some(node) = current {
            if eligible(node.key(keypos)) {
                pending.push(node);
                current = if reverse {
                    node.prefix.right.as_deref()
                } else {
                    node.prefix.left.as_deref()
                };
            } else {
                current = if reverse {
                    node.prefix.left.as_deref()
                } else {
                    node.prefix.right.as_deref()
                };
            }
        }
        while let Some(node) = pending.pop() {
            if visit(node)? {
                return Ok(true);
            }
            let mut branch = if reverse {
                node.prefix.left.as_deref()
            } else {
                node.prefix.right.as_deref()
            };
            while let Some(next) = branch {
                pending.push(next);
                branch = if reverse {
                    next.prefix.right.as_deref()
                } else {
                    next.prefix.left.as_deref()
                };
            }
        }
        Ok(false)
    }

    /// Port of erts/emulator/beam/erl_db_tree.c (analyze_pattern), OTP-29.1.1.
    pub(super) fn select_range<H: HeapAlloc>(
        root: &TreeRoot,
        state: &mut RangeSelection<'_, '_, H>,
    ) -> Result<(), EtsError> {
        Self::select_range_checked(root.link(), state, true, true)
    }

    // A subtree whose parent key is inside a bound needs no further test against it, so the
    // interior of the range costs one object run per key like erts's in-order walk.
    fn select_range_checked<H: HeapAlloc>(
        root: &Link,
        state: &mut RangeSelection<'_, '_, H>,
        check_below: bool,
        check_above: bool,
    ) -> Result<(), EtsError> {
        let Some(node) = root else { return Ok(()) };
        let key = node.key(state.keypos);
        let below = check_below && state.bounds.is_below(key);
        let above = check_above && state.bounds.is_above(key);
        // Keys left of `node` are below `key`, so they are inside the upper bound once `key` is.
        let (left_below, left_above) = (check_below, above);
        let (right_below, right_above) = (below, check_above);
        let (first, first_checks, second, second_checks) = if state.reverse {
            (
                &node.prefix.right,
                (right_below, right_above),
                &node.prefix.left,
                (left_below, left_above),
            )
        } else {
            (
                &node.prefix.left,
                (left_below, left_above),
                &node.prefix.right,
                (right_below, right_above),
            )
        };
        if if state.reverse { !above } else { !below } {
            Self::select_range_checked(first, state, first_checks.0, first_checks.1)?;
        }
        if state.out.len() >= state.limit {
            return Ok(());
        }
        if !below && !above {
            let (term, size) = node.term_for_filter_with_size(state.dst)?;
            if let Some(result) = state.runner.run_sized(term, state.dst, size)? {
                state.out.push(result);
            }
        }
        if state.out.len() >= state.limit {
            return Ok(());
        }
        if if state.reverse { !below } else { !above } {
            Self::select_range_checked(second, state, second_checks.0, second_checks.1)?;
        }
        Ok(())
    }

    /// Check the balance factors against the subtree heights, and the number of objects.
    pub(super) fn validate(root: &TreeRoot) -> bool {
        Self::validate_links(root).is_some()
    }

    /// The number of objects when the balance factors are right.
    pub(super) fn validate_links(root: &TreeRoot) -> Option<usize> {
        fn check(node: &Link) -> Option<(i32, usize)> {
            let Some(node) = node else {
                return Some((0, 0));
            };
            let (lh, ls) = check(&node.prefix.left)?;
            let (rh, rs) = check(&node.prefix.right)?;
            (i32::from(node.prefix.balance) == rh - lh && (lh - rh).abs() <= 1)
                .then_some((1 + lh.max(rh), 1 + ls + rs))
        }
        check(root.link()).map(|(_, count)| count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use arinsal_term::{TermBuilder, VecHeap};
    use std::collections::BTreeSet;

    struct Lcg(u64);

    impl Lcg {
        fn next(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            self.0 >> 33
        }
    }

    fn object(heap: &mut VecHeap, key: i64) -> TreeDbTerm {
        let tuple = TermBuilder::new(heap)
            .tuple(&[Term::small(key).unwrap(), Term::small(key * 2).unwrap()])
            .unwrap();
        StoredTerm::copy_for_table::<crate::TreePrefix>(tuple, false, 1, 3).unwrap()
    }

    fn keys(root: &TreeRoot) -> Vec<i64> {
        let mut objects = Vec::new();
        Node::walk(root, &mut objects);
        objects
            .iter()
            .map(|object| object.key(1).as_small().unwrap())
            .collect()
    }

    /// Random inserts, replacements and deletes keep the AVL invariants, the item count and
    /// the in-order sequence, and `slot_search` agrees with the sequence from any stack state.
    #[test]
    fn avl_operations_match_a_sorted_set() {
        let mut heap = VecHeap::new();
        let mut rng = Lcg(7);
        let mut tree = TreeRoot::new();
        let mut model = BTreeSet::new();
        for round in 0..4000 {
            let key = (rng.next() % 600) as i64;
            if !rng.next().is_multiple_of(3) {
                let result = tree.insert_with_key(
                    object(&mut heap, key),
                    Term::small(key).unwrap(),
                    1,
                    false,
                );
                assert_eq!(model.insert(key), matches!(result, InsertResult::Inserted));
            } else {
                let removed = tree.linkout(Term::small(key).unwrap(), 1);
                assert_eq!(model.remove(&key), removed.is_some());
            }
            assert!(Node::validate(&tree), "round {round}");
            if round % 50 == 0 {
                let expected: Vec<_> = model.iter().copied().collect();
                assert_eq!(keys(&tree), expected);
                assert_eq!(tree.count(), model.len());
                // Callers range-check the slot against the item count first (db_slot_tree_common).
                for _ in 0..20 {
                    if expected.is_empty() {
                        break;
                    }
                    let slot = (rng.next() as usize % expected.len()) + 1;
                    match tree.slot_search(slot) {
                        SlotSearch::Found(found) => {
                            assert_eq!(found.key(1).as_small(), Some(expected[slot - 1]));
                        }
                        _ => panic!("slot {slot} of {} not found", expected.len()),
                    }
                }
            }
        }
    }

    /// Splitting a tree and joining the halves again gives back the same sequence in a valid tree.
    #[test]
    fn split_and_join_round_trip() {
        let mut heap = VecHeap::new();
        for size in [2_i64, 3, 10, 100, 777] {
            let mut tree = TreeRoot::new();
            for key in 0..size {
                tree.insert(object(&mut heap, key), 1);
            }
            let (left, right, split_key) = tree.split_for_catree(1);
            assert!(Node::validate(&left) && Node::validate(&right));
            let split = split_key.as_small().unwrap();
            assert!(keys(&left).iter().all(|&key| key < split));
            assert_eq!(keys(&right).first().copied(), Some(split));
            assert_eq!(keys(&left).len() + keys(&right).len(), size as usize);
            let joined = TreeRoot::join_ordered(left, right);
            assert!(Node::validate(&joined));
            assert_eq!(keys(&joined), (0..size).collect::<Vec<_>>());
        }
        // Unbalanced halves exercise the descent of `join_trees`.
        let mut small = TreeRoot::new();
        let mut big = TreeRoot::new();
        for key in 0..3 {
            small.insert(object(&mut heap, key), 1);
        }
        for key in 3..500 {
            big.insert(object(&mut heap, key), 1);
        }
        let joined = TreeRoot::join_ordered(small, big);
        assert!(Node::validate(&joined));
        assert_eq!(keys(&joined), (0..500).collect::<Vec<_>>());
        let mut left = TreeRoot::new();
        let mut right = TreeRoot::new();
        for key in 0..500 {
            left.insert(object(&mut heap, key), 1);
        }
        for key in 500..503 {
            right.insert(object(&mut heap, key), 1);
        }
        let joined = TreeRoot::join_ordered(left, right);
        assert!(Node::validate(&joined));
        assert_eq!(keys(&joined), (0..503).collect::<Vec<_>>());
    }
}
