use super::{EtsError, HeapAlloc, RangeSelection, StoredTerm, Term, cmp};
use std::cmp::Ordering;

/// One AVL node. The stored subtree size gives `ets:slot/2` logarithmic lookup.
pub(super) struct Node {
    pub(super) object: StoredTerm,
    pub(super) balance: i8,
    size: usize,
    height: u8,
    pub(super) left: Option<Box<Node>>,
    pub(super) right: Option<Box<Node>>,
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

    /// Port of erts/emulator/beam/erl_db_tree.c:773 (db_put_dbterm_tree_common), OTP-29.1.1.
    pub(super) fn insert(root: Option<Box<Self>>, object: StoredTerm, keypos: usize) -> Box<Self> {
        Self::insert_branch(root, object, keypos).0.unwrap()
    }

    /// Port of erts/emulator/beam/erl_db_catree.c:448 (split_tree), OTP-29.1.1.
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

    /// Port of erts/emulator/beam/erl_db_catree.c:560 (join_trees), OTP-29.1.1.
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

    /// Port of erts/emulator/beam/erl_db_tree.c:773 (db_put_dbterm_tree_common), OTP-29.1.1.
    fn insert_branch(
        root: Option<Box<Self>>,
        object: StoredTerm,
        keypos: usize,
    ) -> (Option<Box<Self>>, bool, bool) {
        let Some(mut root) = root else {
            return (Some(Self::new(object)), true, true);
        };
        let order = cmp(object.key(keypos), root.object.key(keypos));
        if order == Ordering::Equal {
            root.object = object;
            return (Some(root), false, false);
        }
        let left = order == Ordering::Less;
        let old_balance = root.balance;
        let (child, inserted, child_grew) = if left {
            Self::insert_branch(root.left.take(), object, keypos)
        } else {
            Self::insert_branch(root.right.take(), object, keypos)
        };
        if left {
            root.left = child;
        } else {
            root.right = child;
        }
        if !inserted {
            return (Some(root), false, false);
        }
        root.size += 1;
        if !child_grew {
            return (Some(root), true, false);
        }
        let delta = if left { -1 } else { 1 };
        let balance = old_balance + delta;
        match balance {
            -1 | 1 => {
                root.balance = balance;
                root.height += 1;
                (Some(root), true, true)
            }
            0 => {
                root.balance = 0;
                (Some(root), true, false)
            }
            -2 | 2 => {
                root.balance = balance;
                (Some(Self::rebalance(root)), true, false)
            }
            _ => unreachable!("AVL balance factor is bounded"),
        }
    }

    /// Port of erts/emulator/beam/erl_db_tree.c:2639 (linkout_tree), OTP-29.1.1.
    pub(super) fn remove(root: Option<Box<Self>>, key: Term, keypos: usize) -> Option<Box<Self>> {
        let mut root = root?;
        match cmp(key, root.object.key(keypos)) {
            Ordering::Less => root.left = Self::remove(root.left.take(), key, keypos),
            Ordering::Greater => root.right = Self::remove(root.right.take(), key, keypos),
            Ordering::Equal => {
                return match (root.left.take(), root.right.take()) {
                    (None, right) => right,
                    (left, None) => left,
                    (Some(left), Some(right)) => {
                        let (new_left, mut predecessor) = Self::take_max(left);
                        predecessor.left = new_left;
                        predecessor.right = Some(right);
                        Some(Self::rebalance(predecessor))
                    }
                };
            }
        }
        Some(Self::rebalance(root))
    }

    /// Port of erts/emulator/beam/erl_db_tree.c:3026 (delsub), OTP-29.1.1.
    fn take_max(mut root: Box<Self>) -> (Option<Box<Self>>, Box<Self>) {
        match root.right.take() {
            None => (root.left.take(), root),
            Some(right) => {
                let (new_right, max) = Self::take_max(right);
                root.right = new_right;
                (Some(Self::rebalance(root)), max)
            }
        }
    }

    /// Port of erts/emulator/beam/erl_db_tree.c:2909 (tree_balance_left) and :2954 (tree_balance_right), OTP-29.1.1.
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

    /// Port of erts/emulator/beam/erl_db_tree.c:2909 (tree_balance_left), OTP-29.1.1.
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

    /// Port of erts/emulator/beam/erl_db_tree.c:2954 (tree_balance_right), OTP-29.1.1.
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

    /// Port of erts/emulator/beam/erl_db_tree.c:758 (cmp_key_eq), OTP-29.1.1.
    fn refresh(root: &mut Box<Self>) {
        let left_height = Self::height(&root.left);
        let right_height = Self::height(&root.right);
        root.height = 1 + left_height.max(right_height);
        root.balance = right_height as i8 - left_height as i8;
        root.size = 1 + Self::count(&root.left) + Self::count(&root.right);
    }

    /// Port of erts/emulator/beam/erl_db_tree.c:3174 (find_next), OTP-29.1.1.
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
    /// Port of erts/emulator/beam/erl_db_tree.c:3388 (find_node), OTP-29.1.1.
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

    /// Port of erts/emulator/beam/erl_db_tree.c:3396 (slot_search), OTP-29.1.1.
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

    /// Port of erts/emulator/beam/erl_db_tree.c:3174 (find_next) and :3232 (find_prev), OTP-29.1.1.
    pub(super) fn count(root: &Option<Box<Self>>) -> usize {
        root.as_ref().map_or(0, |node| node.size)
    }

    fn height(root: &Option<Box<Self>>) -> u8 {
        root.as_ref().map_or(0, |node| node.height)
    }

    /// Port of erts/emulator/beam/erl_db_tree.c:3663 (traverse_forward), OTP-29.1.1.
    pub(super) fn walk<'a>(root: &'a Option<Box<Self>>, out: &mut Vec<&'a StoredTerm>) {
        let mut pending = Vec::new();
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

    /// Port of erts/emulator/beam/erl_db_tree.c:3174 (find_next) and :3232 (find_prev), OTP-29.1.1.
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
        let mut pending = Vec::new();
        let mut current = root.as_deref();
        while let Some(node) = current {
            let eligible = cursor.is_none_or(|key| {
                let order = cmp(node.object.key(keypos), key);
                if reverse {
                    order == Ordering::Less
                } else {
                    order == Ordering::Greater
                }
            });
            if eligible {
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

    /// Port of erts/emulator/beam/erl_db_tree.c:2753 (analyze_pattern), OTP-29.1.1.
    pub(super) fn select_range<H: HeapAlloc>(
        root: &Option<Box<Self>>,
        state: &mut RangeSelection<'_, H>,
    ) -> Result<(), EtsError> {
        Self::select_range_checked(root, state, true, true)
    }

    // A subtree whose parent key is inside a bound needs no further test against it, so the
    // interior of the range costs one object run per key like erts's in-order walk.
    fn select_range_checked<H: HeapAlloc>(
        root: &Option<Box<Self>>,
        state: &mut RangeSelection<'_, H>,
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
        if !below
            && !above
            && let Some(result) = state
                .program
                .run(node.object.term_for_filter(state.dst)?, state.dst)?
        {
            state.out.push(result);
        }
        if state.out.len() >= state.limit {
            return Ok(());
        }
        if if state.reverse { !below } else { !above } {
            Self::select_range_checked(second, state, second_checks.0, second_checks.1)?;
        }
        Ok(())
    }

    /// Port of erts/emulator/beam/erl_db_tree.c:2909 (tree_balance_left), OTP-29.1.1.
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
