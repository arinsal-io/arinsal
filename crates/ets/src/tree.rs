use super::{EtsError, HeapAlloc, RangeSelection, StoredTerm, Term, cmp};
use smallvec::SmallVec;
use std::cmp::Ordering;

// Port of erl_db_tree_util.h (STACK_NEED): 90 entries on 64-bit, 50 on 32-bit.
const TREE_STACK_NEED: usize = if usize::BITS == 64 { 90 } else { 50 };

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

/// Result of one `db_put_dbterm_tree_common` descent.
#[derive(Clone, Copy)]
pub(super) enum InsertResult {
    Inserted,
    Replaced(usize),
    Exists,
}

/// One AVL node. The stored subtree size gives `ets:slot/2` logarithmic lookup.
// Port of erts/emulator/beam/erl_db_tree_util.h (TreeDbTerm): the links and balance precede the
// object, so one descent step reads one node cache line.
#[repr(C)]
pub(super) struct Node {
    pub(super) left: Option<Box<Node>>,
    pub(super) right: Option<Box<Node>>,
    size: usize,
    pub(super) balance: i8,
    height: u8,
    pub(super) object: StoredTerm,
}

impl Node {
    fn new(object: StoredTerm) -> Box<Self> {
        Box::new(Self {
            object,
            balance: 0,
            size: 1,
            height: 1,
            left: None,
            right: None,
        })
    }

    /// Port of erts/emulator/beam/erl_db_tree.c (db_put_dbterm_tree_common), OTP-29.1.1.
    pub(super) fn insert(root: Option<Box<Self>>, object: StoredTerm, keypos: usize) -> Box<Self> {
        let key = object.key(keypos);
        Self::insert_with_key(root, object, key, keypos, false)
            .0
            .expect("inserting into an AVL tree returns a root")
    }

    /// Insert or replace using the key already read by the caller, as the C path does before it
    /// descends. `key_clash_fail` ports `insert_new`'s single-path check.
    // Port of erts/emulator/beam/erl_db_tree.c (db_put_dbterm_tree_common), OTP-29.1.1.
    pub(super) fn insert_with_key(
        root: Option<Box<Self>>,
        object: StoredTerm,
        key: Term,
        keypos: usize,
        key_clash_fail: bool,
    ) -> (Option<Box<Self>>, InsertResult) {
        let (root, result, _) = Self::insert_branch(root, object, key, keypos, key_clash_fail);
        (root, result)
    }

    /// Port of erts/emulator/beam/erl_db_catree.c (split_tree), OTP-29.1.1.
    pub(super) fn split_for_catree(
        mut root: Box<Self>,
        keypos: usize,
    ) -> (Box<Self>, Option<Box<Self>>, Term) {
        if root.left.is_none() {
            let right = root.right.take();
            let split_key = right
                .as_ref()
                .expect("a splittable CA-tree base has at least two objects")
                .object
                .key(keypos);
            root.balance = 0;
            Self::refresh(&mut root);
            (root, right, split_key)
        } else {
            let split_key = root.object.key(keypos);
            let left = root.left.take().expect("left subtree checked above");
            let right = root.right.take();
            let right = Some(Self::insert(right, root.object, keypos));
            (left, right, split_key)
        }
    }

    /// Port of erts/emulator/beam/erl_db_catree.c (join_trees), OTP-29.1.1.
    pub(super) fn join_ordered(
        left: Option<Box<Self>>,
        right: Option<Box<Self>>,
    ) -> Option<Box<Self>> {
        match (left, right) {
            (None, right) => right,
            (left, None) => left,
            (left, Some(right)) => {
                let (right, mut pivot) = Self::take_min(right);
                pivot.left = None;
                pivot.right = None;
                Some(Self::join_with_pivot(left, pivot, right))
            }
        }
    }

    fn join_with_pivot(
        left: Option<Box<Self>>,
        mut pivot: Box<Self>,
        right: Option<Box<Self>>,
    ) -> Box<Self> {
        let left_height = Self::height(&left);
        let right_height = Self::height(&right);
        if left_height > right_height + 1 {
            let mut left = left.expect("height comparison requires a left subtree");
            left.right = Some(Self::join_with_pivot(left.right.take(), pivot, right));
            Self::rebalance(left)
        } else if right_height > left_height + 1 {
            let mut right = right.expect("height comparison requires a right subtree");
            right.left = Some(Self::join_with_pivot(left, pivot, right.left.take()));
            Self::rebalance(right)
        } else {
            pivot.left = left;
            pivot.right = right;
            Self::refresh(&mut pivot);
            pivot
        }
    }

    fn take_min(mut root: Box<Self>) -> (Option<Box<Self>>, Box<Self>) {
        let Some(left) = root.left.take() else {
            let right = root.right.take();
            return (right, root);
        };
        let (left, min) = Self::take_min(left);
        root.left = left;
        (Some(Self::rebalance(root)), min)
    }

    /// Port of erts/emulator/beam/erl_db_tree.c (db_put_dbterm_tree_common), OTP-29.1.1.
    ///
    /// The descent only reads: a node is written on the way back up only when its balance
    /// changes, and a replaced object is overwritten at the node that holds it.
    fn insert_branch(
        mut root: Option<Box<Self>>,
        object: StoredTerm,
        key: Term,
        keypos: usize,
        key_clash_fail: bool,
    ) -> (Option<Box<Self>>, InsertResult, bool) {
        // A key already in the tree is found by a plain loop; only a new key needs the
        // rebalancing walk back up.
        let mut cursor = &mut root;
        while let Some(node) = cursor {
            match cmp(key, node.object.key(keypos)) {
                Ordering::Equal if key_clash_fail => return (root, InsertResult::Exists, false),
                Ordering::Equal => {
                    let old_words = node.object.db_size_words;
                    node.object = object;
                    return (root, InsertResult::Replaced(old_words), false);
                }
                Ordering::Less => cursor = &mut node.left,
                Ordering::Greater => cursor = &mut node.right,
            }
        }
        let mut object = Some(object);
        let (result, grew) = Self::insert_at(&mut root, &mut object, key, keypos, key_clash_fail);
        (root, result, grew)
    }

    fn insert_at(
        slot: &mut Option<Box<Self>>,
        object: &mut Option<StoredTerm>,
        key: Term,
        keypos: usize,
        key_clash_fail: bool,
    ) -> (InsertResult, bool) {
        let Some(node) = slot.as_mut() else {
            *slot = Some(Self::new(object.take().expect("object consumed once")));
            return (InsertResult::Inserted, true);
        };
        let went_left = match cmp(key, node.object.key(keypos)) {
            Ordering::Equal if key_clash_fail => return (InsertResult::Exists, false),
            Ordering::Equal => {
                let old_words = node.object.db_size_words;
                node.object = object.take().expect("object consumed once");
                return (InsertResult::Replaced(old_words), false);
            }
            Ordering::Less => true,
            Ordering::Greater => false,
        };
        let child = if went_left {
            &mut node.left
        } else {
            &mut node.right
        };
        let (result, child_grew) = Self::insert_at(child, object, key, keypos, key_clash_fail);
        if !matches!(result, InsertResult::Inserted) {
            return (result, false);
        }
        node.size += 1;
        if !child_grew {
            return (result, false);
        }
        let balance = node.balance + if went_left { -1 } else { 1 };
        match balance {
            -1 | 1 => {
                node.balance = balance;
                node.height += 1;
                (result, true)
            }
            0 => {
                node.balance = 0;
                (result, false)
            }
            -2 | 2 => {
                node.balance = balance;
                let node = slot.take().expect("slot holds the node");
                *slot = Some(Self::rebalance(node));
                (result, false)
            }
            _ => unreachable!("AVL balance factor is bounded"),
        }
    }

    /// Port of erts/emulator/beam/erl_db_tree.c (linkout_tree), OTP-29.1.1.
    pub(super) fn remove(root: Option<Box<Self>>, key: Term, keypos: usize) -> Option<Box<Self>> {
        Self::remove_matching(root, key, keypos, |_| true).0
    }

    /// Remove by key and optional object predicate in one descent, returning the removed
    /// object's accounting size for CA-tree memory updates.
    // Port of erts/emulator/beam/erl_db_tree.c (linkout_tree/linkout_object_tree), OTP-29.1.1.
    pub(super) fn remove_matching<F>(
        root: Option<Box<Self>>,
        key: Term,
        keypos: usize,
        mut matches: F,
    ) -> (Option<Box<Self>>, Option<usize>)
    where
        F: FnMut(&StoredTerm) -> bool,
    {
        Self::remove_branch(root, key, keypos, &mut matches)
    }

    fn remove_branch<F>(
        mut root: Option<Box<Self>>,
        key: Term,
        keypos: usize,
        matches: &mut F,
    ) -> (Option<Box<Self>>, Option<usize>)
    where
        F: FnMut(&StoredTerm) -> bool,
    {
        let removed = Self::remove_at(&mut root, key, keypos, matches);
        (root, removed)
    }

    // The descent only reads; ancestors are rebalanced on the way back only when an object
    // was actually unlinked.
    fn remove_at<F>(
        slot: &mut Option<Box<Self>>,
        key: Term,
        keypos: usize,
        matches: &mut F,
    ) -> Option<usize>
    where
        F: FnMut(&StoredTerm) -> bool,
    {
        let node = slot.as_mut()?;
        let removed = match cmp(key, node.object.key(keypos)) {
            Ordering::Less => Self::remove_at(&mut node.left, key, keypos, matches)?,
            Ordering::Greater => Self::remove_at(&mut node.right, key, keypos, matches)?,
            Ordering::Equal if !matches(&node.object) => return None,
            Ordering::Equal => {
                let mut node = slot.take().expect("slot holds the node");
                let words = node.object.db_size_words;
                *slot = match (node.left.take(), node.right.take()) {
                    (None, right) => right,
                    (left, None) => left,
                    (Some(left), Some(right)) => {
                        let (new_left, mut predecessor) = Self::take_max(left);
                        predecessor.left = new_left;
                        predecessor.right = Some(right);
                        Some(Self::rebalance(predecessor))
                    }
                };
                return Some(words);
            }
        };
        let node = slot.take().expect("slot holds the node");
        *slot = Some(Self::rebalance(node));
        Some(removed)
    }

    /// Port of erts/emulator/beam/erl_db_tree.c (delsub), OTP-29.1.1.
    fn take_max(mut root: Box<Self>) -> (Option<Box<Self>>, Box<Self>) {
        let mut path = TreeStack::new();
        while let Some(right) = root.right.take() {
            path.push(root);
            root = right;
        }
        let mut current = root.left.take();
        while let Some(mut node) = path.pop() {
            node.right = current.take();
            current = Some(Self::rebalance(node));
        }
        (current, root)
    }

    /// Port of erts/emulator/beam/erl_db_tree.c (tree_balance_left) and :2954 (tree_balance_right), OTP-29.1.1.
    fn rebalance(mut root: Box<Self>) -> Box<Self> {
        Self::refresh(&mut root);
        if root.balance < -1 {
            if root.left.as_ref().unwrap().balance > 0 {
                root.left = Some(Self::rotate_left(root.left.take().unwrap()));
            }
            return Self::rotate_right(root);
        }
        if root.balance > 1 {
            if root.right.as_ref().unwrap().balance < 0 {
                root.right = Some(Self::rotate_right(root.right.take().unwrap()));
            }
            return Self::rotate_left(root);
        }
        root
    }

    /// Port of erts/emulator/beam/erl_db_tree.c (tree_balance_left), OTP-29.1.1.
    fn rotate_right(mut root: Box<Self>) -> Box<Self> {
        let mut top = root
            .left
            .take()
            .expect("left-heavy AVL node has a left child");
        root.left = top.right.take();
        Self::refresh(&mut root);
        top.right = Some(root);
        Self::refresh(&mut top);
        top
    }

    /// Port of erts/emulator/beam/erl_db_tree.c (tree_balance_right), OTP-29.1.1.
    fn rotate_left(mut root: Box<Self>) -> Box<Self> {
        let mut top = root
            .right
            .take()
            .expect("right-heavy AVL node has a right child");
        root.right = top.left.take();
        Self::refresh(&mut root);
        top.left = Some(root);
        Self::refresh(&mut top);
        top
    }

    /// Port of erts/emulator/beam/erl_db_tree.c (cmp_key_eq), OTP-29.1.1.
    fn refresh(root: &mut Box<Self>) {
        let left_height = Self::height(&root.left);
        let right_height = Self::height(&root.right);
        root.height = 1 + left_height.max(right_height);
        root.balance = right_height as i8 - left_height as i8;
        root.size = 1 + Self::count(&root.left) + Self::count(&root.right);
    }

    /// Port of erts/emulator/beam/erl_db_tree.c (find_next), OTP-29.1.1.
    pub(super) fn get(root: &Option<Box<Self>>, key: Term, keypos: usize) -> Option<&StoredTerm> {
        let mut node = root.as_deref();
        while let Some(current) = node {
            match cmp(key, current.object.key(keypos)) {
                Ordering::Equal => return Some(&current.object),
                Ordering::Less => node = current.left.as_deref(),
                Ordering::Greater => node = current.right.as_deref(),
            }
        }
        None
    }

    /// The object at `key`, for an update in place.
    ///
    /// Port of erts/emulator/beam/erl_db_tree.c (find_node), OTP-29.1.1.
    pub(super) fn get_mut(
        root: &mut Option<Box<Self>>,
        key: Term,
        keypos: usize,
    ) -> Option<&mut StoredTerm> {
        let mut node = root.as_deref_mut();
        while let Some(current) = node {
            match cmp(key, current.object.key(keypos)) {
                Ordering::Equal => return Some(&mut current.object),
                Ordering::Less => node = current.left.as_deref_mut(),
                Ordering::Greater => node = current.right.as_deref_mut(),
            }
        }
        None
    }

    /// Port of erts/emulator/beam/erl_db_tree.c (slot_search), OTP-29.1.1.
    pub(super) fn nth(root: &Option<Box<Self>>, index: usize) -> Option<&StoredTerm> {
        let mut node = root.as_deref()?;
        let mut index = index;
        loop {
            let left = Self::count(&node.left);
            match index.cmp(&left) {
                Ordering::Less => node = node.left.as_deref()?,
                Ordering::Equal => return Some(&node.object),
                Ordering::Greater => {
                    index -= left + 1;
                    node = node.right.as_deref()?;
                }
            }
        }
    }

    /// Port of erts/emulator/beam/erl_db_tree.c (find_next) and :3232 (find_prev), OTP-29.1.1.
    pub(super) fn count(root: &Option<Box<Self>>) -> usize {
        root.as_ref().map_or(0, |node| node.size)
    }

    fn height(root: &Option<Box<Self>>) -> u8 {
        root.as_ref().map_or(0, |node| node.height)
    }

    /// Port of erts/emulator/beam/erl_db_tree.c (traverse_forward), OTP-29.1.1.
    pub(super) fn walk<'a>(root: &'a Option<Box<Self>>, out: &mut Vec<&'a StoredTerm>) {
        let mut pending = TreeStack::new();
        let mut current = root.as_deref();
        loop {
            while let Some(node) = current {
                pending.push(node);
                current = node.left.as_deref();
            }
            let Some(node) = pending.pop() else { break };
            out.push(&node.object);
            current = node.right.as_deref();
        }
    }

    /// Visit each object in key order without materializing an object-reference vector.
    // Port of erts/emulator/beam/erl_db_tree.c (traverse_forward), OTP-29.1.1.
    pub(super) fn walk_each<F>(root: &Option<Box<Self>>, visit: &mut F) -> Result<(), EtsError>
    where
        F: FnMut(&StoredTerm) -> Result<(), EtsError>,
    {
        let mut pending = TreeStack::new();
        let mut current = root.as_deref();
        loop {
            while let Some(node) = current {
                pending.push(node);
                current = node.left.as_deref();
            }
            let Some(node) = pending.pop() else { break };
            visit(&node.object)?;
            current = node.right.as_deref();
        }
        Ok(())
    }

    /// Port of erts/emulator/beam/erl_db_tree.c (find_next) and :3232 (find_prev), OTP-29.1.1.
    pub(super) fn scan_after<F>(
        root: &Option<Box<Self>>,
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
        root: &Option<Box<Self>>,
        reverse: bool,
        eligible: &dyn Fn(Term) -> bool,
        keypos: usize,
        visit: &mut F,
    ) -> Result<bool, EtsError>
    where
        F: FnMut(&StoredTerm) -> Result<bool, EtsError>,
    {
        let mut pending = TreeStack::new();
        let mut current = root.as_deref();
        while let Some(node) = current {
            if eligible(node.object.key(keypos)) {
                pending.push(node);
                current = if reverse {
                    node.right.as_deref()
                } else {
                    node.left.as_deref()
                };
            } else {
                current = if reverse {
                    node.left.as_deref()
                } else {
                    node.right.as_deref()
                };
            }
        }
        while let Some(node) = pending.pop() {
            if visit(&node.object)? {
                return Ok(true);
            }
            let mut branch = if reverse {
                node.left.as_deref()
            } else {
                node.right.as_deref()
            };
            while let Some(next) = branch {
                pending.push(next);
                branch = if reverse {
                    next.right.as_deref()
                } else {
                    next.left.as_deref()
                };
            }
        }
        Ok(false)
    }

    /// Port of erts/emulator/beam/erl_db_tree.c (analyze_pattern), OTP-29.1.1.
    pub(super) fn select_range<H: HeapAlloc>(
        root: &Option<Box<Self>>,
        state: &mut RangeSelection<'_, '_, H>,
    ) -> Result<(), EtsError> {
        Self::select_range_checked(root, state, true, true)
    }

    // A subtree whose parent key is inside a bound needs no further test against it, so the
    // interior of the range costs one object run per key like erts's in-order walk.
    fn select_range_checked<H: HeapAlloc>(
        root: &Option<Box<Self>>,
        state: &mut RangeSelection<'_, '_, H>,
        check_below: bool,
        check_above: bool,
    ) -> Result<(), EtsError> {
        let Some(node) = root else { return Ok(()) };
        let key = node.object.key(state.keypos);
        let below = check_below && state.bounds.is_below(key);
        let above = check_above && state.bounds.is_above(key);
        // Keys left of `node` are below `key`, so they are inside the upper bound once `key` is.
        let (left_below, left_above) = (check_below, above);
        let (right_below, right_above) = (below, check_above);
        let (first, first_checks, second, second_checks) = if state.reverse {
            (
                &node.right,
                (right_below, right_above),
                &node.left,
                (left_below, left_above),
            )
        } else {
            (
                &node.left,
                (left_below, left_above),
                &node.right,
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
            let (term, size) = node.object.term_for_filter_with_size(state.dst)?;
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

    /// Port of erts/emulator/beam/erl_db_tree.c (tree_balance_left), OTP-29.1.1.
    pub(super) fn validate(root: &Option<Box<Self>>) -> bool {
        fn check(node: &Option<Box<Node>>) -> Option<(u8, usize)> {
            let Some(node) = node else {
                return Some((0, 0));
            };
            let (lh, ls) = check(&node.left)?;
            let (rh, rs) = check(&node.right)?;
            let height = 1 + lh.max(rh);
            (i16::from(node.balance) == i16::from(rh) - i16::from(lh)
                && (lh as i16 - rh as i16).abs() <= 1
                && node.height == height
                && node.size == 1 + ls + rs)
                .then_some((height, node.size))
        }
        check(root).is_some()
    }
}
