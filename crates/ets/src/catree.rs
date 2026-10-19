//! Safe contention-adapting ordered storage built from the ETS AVL tree.

use super::{EtsError, HeapAlloc, RangeSelection, StoredTerm, Term, cmp};
use crate::tree::Node;
use arc_swap::ArcSwap;
use arinsal_term::{TermBuilder, VecHeap};
use std::cmp::Ordering;
use std::sync::atomic::{
    AtomicBool, AtomicI64, AtomicIsize, AtomicUsize, Ordering as AtomicOrdering,
};
use std::sync::{Arc, Mutex, RwLock};

const LOCK_FAILURE_CONTRIBUTION: i64 = 250;
const LOCK_SUCCESS_CONTRIBUTION: i64 = -1;
const LOCK_GRAVITY_CONTRIBUTION: i64 = -500;
const LOCK_GRAVITY_PATTERN: u32 = 0xFF80_0000;
const HIGH_CONTENTION_LIMIT: i64 = 1000;
const LOW_CONTENTION_LIMIT: i64 = -1000;
const MAX_ROUTE_NODE_LAYER_HEIGHT: usize = 16;
const LOW_NO_CONTRIBUTION_LIMIT: i64 = -20_000;
const HIGH_NO_CONTRIBUTION_LIMIT: i64 = 20_000;

struct BaseNode {
    root: RwLock<Option<Box<Node>>>,
    lock_statistics: AtomicI64,
    is_valid: AtomicBool,
}

impl BaseNode {
    fn new(root: Option<Box<Node>>) -> Arc<Self> {
        Arc::new(Self {
            root: RwLock::new(root),
            lock_statistics: AtomicI64::new(0),
            is_valid: AtomicBool::new(true),
        })
    }

    /// Port of erts/emulator/beam/erl_db_catree.c (wlock_base_node), OTP-29.1.1.
    fn write(&self) -> std::sync::RwLockWriteGuard<'_, Option<Box<Node>>> {
        match self.root.try_write() {
            Ok(guard) => {
                // Port of erts/emulator/beam/erl_db_catree.c (wlock_base_node), OTP-29.1.1.
                // OTP subtracts the negative success contribution, so an uncontended write adds one.
                self.adjust_stat(-LOCK_SUCCESS_CONTRIBUTION);
                guard
            }
            Err(_) => {
                self.adjust_stat(LOCK_FAILURE_CONTRIBUTION);
                self.root.write().expect("CA-tree base lock poisoned")
            }
        }
    }

    fn write_no_stats(&self) -> std::sync::RwLockWriteGuard<'_, Option<Box<Node>>> {
        self.root.write().expect("CA-tree base lock poisoned")
    }

    /// Port of erts/emulator/beam/erl_db_catree.c (rlock_base_node), OTP-29.1.1.
    fn read(&self) -> std::sync::RwLockReadGuard<'_, Option<Box<Node>>> {
        match self.root.try_read() {
            Ok(guard) => guard,
            Err(_) => {
                self.adjust_stat(LOCK_FAILURE_CONTRIBUTION);
                self.root.read().expect("CA-tree base lock poisoned")
            }
        }
    }

    fn adjust_stat(&self, amount: i64) {
        let _ = self.lock_statistics.fetch_update(
            AtomicOrdering::Relaxed,
            AtomicOrdering::Relaxed,
            |value| {
                let can_add = if amount > 0 {
                    value < HIGH_NO_CONTRIBUTION_LIMIT
                } else {
                    value > LOW_NO_CONTRIBUTION_LIMIT
                };
                can_add.then(|| value.saturating_add(amount))
            },
        );
    }
}

#[derive(Clone)]
struct RouteEntry {
    /// The first key in this base node; the first route entry has no lower bound.
    first_key: Option<Arc<StoredTerm>>,
    base: Arc<BaseNode>,
}

struct RouteSnapshot {
    entries: Vec<RouteEntry>,
    root: Box<RouteNode>,
}

enum RouteNode {
    Base(Arc<BaseNode>),
    Branch {
        key: Arc<StoredTerm>,
        left: Box<RouteNode>,
        right: Box<RouteNode>,
    },
}

impl RouteSnapshot {
    fn new(entries: Vec<RouteEntry>) -> Self {
        let root = Self::build(&entries);
        Self { entries, root }
    }

    fn build(entries: &[RouteEntry]) -> Box<RouteNode> {
        if entries.len() == 1 {
            return Box::new(RouteNode::Base(Arc::clone(&entries[0].base)));
        }
        let middle = entries.len() / 2;
        Box::new(RouteNode::Branch {
            key: Arc::clone(
                entries[middle]
                    .first_key
                    .as_ref()
                    .expect("all non-first routes have a lower-bound key"),
            ),
            left: Self::build(&entries[..middle]),
            right: Self::build(&entries[middle..]),
        })
    }

    fn find_base(&self, key: Term) -> &Arc<BaseNode> {
        let mut node = self.root.as_ref();
        loop {
            match node {
                RouteNode::Base(base) => return base,
                RouteNode::Branch {
                    key: route_key,
                    left,
                    right,
                } => {
                    node = if cmp(key, route_key.key(1)) == Ordering::Less {
                        left
                    } else {
                        right
                    };
                }
            }
        }
    }

    fn random_base(&self, random: u32) -> &Arc<BaseNode> {
        let mut node = self.root.as_ref();
        let mut level = 0;
        loop {
            match node {
                RouteNode::Base(base) => return base,
                RouteNode::Branch { left, right, .. } => {
                    node = if random & (1 << level) == 0 {
                        left
                    } else {
                        right
                    };
                    level += 1;
                }
            }
        }
    }
}

impl std::ops::Deref for RouteSnapshot {
    type Target = [RouteEntry];

    fn deref(&self) -> &Self::Target {
        &self.entries
    }
}

/// Ordered ETS storage whose AVL leaves split and join as lock contention changes.
pub(crate) struct CATree {
    keypos: usize,
    routes: ArcSwap<RouteSnapshot>,
    adaptation: Mutex<()>,
    split_count: AtomicUsize,
    join_count: AtomicUsize,
    low_stat_join_count: AtomicUsize,
    gravity_join_count: AtomicUsize,
    force_split: AtomicBool,
    debug_random_split_join: AtomicBool,
    memory_words: AtomicIsize,
}

impl CATree {
    /// Port of erts/emulator/beam/erl_db_catree.c (db_initialize_catree), OTP-29.1.1.
    pub(crate) fn new(keypos: usize) -> Self {
        Self {
            keypos,
            routes: ArcSwap::from_pointee(RouteSnapshot::new(vec![RouteEntry {
                first_key: None,
                base: BaseNode::new(None),
            }])),
            adaptation: Mutex::new(()),
            split_count: AtomicUsize::new(0),
            join_count: AtomicUsize::new(0),
            low_stat_join_count: AtomicUsize::new(0),
            gravity_join_count: AtomicUsize::new(0),
            force_split: AtomicBool::new(false),
            debug_random_split_join: AtomicBool::new(false),
            memory_words: AtomicIsize::new(0),
        }
    }

    pub(crate) fn object_memory_words(&self) -> isize {
        self.memory_words.load(AtomicOrdering::Relaxed)
    }

    /// Port of erts/emulator/beam/erl_db_catree.c (catree_find_root), OTP-29.1.1.
    fn route_index(&self, routes: &[RouteEntry], key: Term) -> usize {
        routes[1..].partition_point(|route| {
            route
                .first_key
                .as_ref()
                .is_some_and(|first| cmp(key, first.key(1)) != Ordering::Less)
        })
    }

    /// Port of erts/emulator/beam/erl_db_catree.c (db_put_catree), OTP-29.1.1.
    pub(crate) fn insert(&self, object: StoredTerm) {
        let key = object.key(self.keypos);
        let mut object = Some(object);
        loop {
            let routes = self.routes.load();
            let base = routes.find_base(key);
            let mut root = base.write();
            if !base.is_valid.load(AtomicOrdering::Acquire) {
                drop(root);
                drop(routes);
                std::thread::yield_now();
                continue;
            }
            let old_words = Node::get(&root, key, self.keypos)
                .map_or(0, |stored| stored.db_size_words as isize);
            let new_words = object.as_ref().unwrap().db_size_words as isize;
            *root = Some(Node::insert(
                root.take(),
                object.take().unwrap(),
                self.keypos,
            ));
            self.memory_words
                .fetch_add(new_words - old_words, AtomicOrdering::Relaxed);
            let stat = base.lock_statistics.load(AtomicOrdering::Relaxed);
            drop(root);
            self.adapt(base, stat);
            break;
        }
    }

    /// Insert an object only when its ordered key is absent.
    // Port of erts/emulator/beam/erl_db_catree.c (db_put_catree with key_clash_fail), OTP-29.1.1.
    pub(crate) fn insert_new(&self, object: StoredTerm) -> bool {
        let key = object.key(self.keypos);
        let mut object = Some(object);
        loop {
            let routes = self.routes.load();
            let base = routes.find_base(key);
            let mut root = base.write();
            if !base.is_valid.load(AtomicOrdering::Acquire) {
                drop(root);
                drop(routes);
                std::thread::yield_now();
                continue;
            }
            let inserted = if Node::get(&root, key, self.keypos).is_some() {
                false
            } else {
                let stored = object
                    .take()
                    .expect("CA-tree insert object retained on retry");
                self.memory_words
                    .fetch_add(stored.db_size_words as isize, AtomicOrdering::Relaxed);
                *root = Some(Node::insert(root.take(), stored, self.keypos));
                true
            };
            let stat = base.lock_statistics.load(AtomicOrdering::Relaxed);
            drop(root);
            self.adapt(base, stat);
            return inserted;
        }
    }

    /// Update an existing object while holding its CA-tree base-node write lock.
    // Port of erts/emulator/beam/erl_db_catree.c (db_lookup_dbterm_catree and
    // db_finalize_dbterm_catree), OTP-29.1.1.
    pub(crate) fn with_object_mut<R>(
        &self,
        key: Term,
        update: impl FnOnce(&mut StoredTerm) -> Option<R>,
    ) -> Option<R> {
        let mut update = Some(update);
        loop {
            let routes = self.routes.load();
            let base = routes.find_base(key);
            let mut root = base.write();
            if !base.is_valid.load(AtomicOrdering::Acquire) {
                drop(root);
                drop(routes);
                std::thread::yield_now();
                continue;
            }
            let result = Node::get_mut(&mut root, key, self.keypos).and_then(|object| {
                update.take().expect("CA-tree update retained on retry")(object)
            });
            let stat = base.lock_statistics.load(AtomicOrdering::Relaxed);
            drop(root);
            self.adapt(base, stat);
            return result;
        }
    }

    /// Port of erts/emulator/beam/erl_db_catree.c (db_put_catree), OTP-29.1.1.
    pub(crate) fn insert_many(&self, objects: Vec<StoredTerm>) {
        for object in objects {
            self.insert(object);
        }
    }

    /// Port of erts/emulator/beam/erl_db_catree.c (db_get_binary_info_catree), OTP-29.1.1.
    /// Reads the stored term in place so the reference counts are not inflated by a copy.
    pub(crate) fn binary_info<H: HeapAlloc>(
        &self,
        key: Term,
        dst: &mut H,
    ) -> Result<Vec<Term>, EtsError> {
        loop {
            let routes = self.routes.load();
            let base = routes.find_base(key);
            let root = base.write();
            if !base.is_valid.load(AtomicOrdering::Acquire) {
                drop(root);
                drop(routes);
                std::thread::yield_now();
                continue;
            }
            return Node::get(&root, key, self.keypos)
                .map(|object| object.refc_binaries(dst))
                .unwrap_or_else(|| Ok(Vec::new()));
        }
    }

    /// Port of erts/emulator/beam/erl_db_catree.c (db_get_catree), OTP-29.1.1.
    pub(crate) fn lookup<H: HeapAlloc>(
        &self,
        key: Term,
        dst: &mut H,
    ) -> Result<Vec<Term>, EtsError> {
        loop {
            let routes = self.routes.load();
            let base = routes.find_base(key);
            let root = base.read();
            if !base.is_valid.load(AtomicOrdering::Acquire) {
                drop(root);
                drop(routes);
                std::thread::yield_now();
                continue;
            }
            let result = Node::get(&root, key, self.keypos)
                .map(|object| object.copy_out(dst))
                .transpose()
                .map(|object| object.into_iter().collect());
            drop(root);
            self.random_join();
            return result;
        }
    }

    /// Copy the one ordered object for a key without allocating a result vector.
    // Port of erts/emulator/beam/erl_db_catree.c (db_get_catree), OTP-29.1.1.
    pub(crate) fn lookup_one<H: HeapAlloc>(
        &self,
        key: Term,
        dst: &mut H,
    ) -> Result<Option<Term>, EtsError> {
        loop {
            let routes = self.routes.load();
            let base = routes.find_base(key);
            let root = base.read();
            if !base.is_valid.load(AtomicOrdering::Acquire) {
                drop(root);
                drop(routes);
                std::thread::yield_now();
                continue;
            }
            let result = Node::get(&root, key, self.keypos)
                .map(|object| object.copy_out(dst))
                .transpose();
            drop(root);
            self.random_join();
            return result;
        }
    }

    /// Port of erts/emulator/beam/erl_db_catree.c (db_member_catree), OTP-29.1.1.
    pub(crate) fn member(&self, key: Term) -> bool {
        loop {
            let routes = self.routes.load();
            let base = routes.find_base(key);
            let root = base.read();
            if !base.is_valid.load(AtomicOrdering::Acquire) {
                drop(root);
                drop(routes);
                std::thread::yield_now();
                continue;
            }
            let found = Node::get(&root, key, self.keypos).is_some();
            drop(root);
            self.random_join();
            return found;
        }
    }

    /// Copy one object element while holding the base read lock.
    ///
    /// Port of erts/emulator/beam/erl_db_catree.c (`db_get_element_catree`), OTP-29.1.1.
    pub(crate) fn lookup_element<H: HeapAlloc>(
        &self,
        key: Term,
        index: usize,
        dst: &mut H,
    ) -> Result<Term, EtsError> {
        loop {
            let routes = self.routes.load();
            let base = routes.find_base(key);
            let root = base.read();
            if !base.is_valid.load(AtomicOrdering::Acquire) {
                drop(root);
                drop(routes);
                std::thread::yield_now();
                continue;
            }
            let result = Node::get(&root, key, self.keypos)
                .ok_or(EtsError::BadArgCause("badkey"))?
                .copy_element_out(index, dst);
            drop(root);
            self.random_join();
            return result;
        }
    }

    /// Port of erts/emulator/beam/erl_db_catree.c (db_get_catree), OTP-29.1.1.
    pub(crate) fn matching(&self, key: Term) -> Result<Vec<StoredTerm>, EtsError> {
        loop {
            let routes = self.routes.load();
            let base = routes.find_base(key);
            let root = base.read();
            if !base.is_valid.load(AtomicOrdering::Acquire) {
                drop(root);
                drop(routes);
                std::thread::yield_now();
                continue;
            }
            let result = Node::get(&root, key, self.keypos)
                .map(StoredTerm::copy_stored)
                .transpose()
                .map(|object| object.into_iter().collect());
            drop(root);
            self.random_join();
            return result;
        }
    }

    /// Port of erts/emulator/beam/erl_db_catree.c (db_get_element_catree), OTP-29.1.1.
    pub(crate) fn delete_object(&self, key: Term, object: Term) {
        loop {
            let routes = self.routes.load();
            let base = routes.find_base(key);
            let mut root = base.write();
            if !base.is_valid.load(AtomicOrdering::Acquire) {
                drop(root);
                drop(routes);
                std::thread::yield_now();
                continue;
            }
            let removed_words = Node::get(&root, key, self.keypos)
                .filter(|found| found.exact_eq_input(object))
                .map_or(0, |found| found.db_size_words as isize);
            if removed_words != 0 {
                *root = Node::remove(root.take(), key, self.keypos);
                self.memory_words
                    .fetch_sub(removed_words, AtomicOrdering::Relaxed);
            }
            let stat = base.lock_statistics.load(AtomicOrdering::Relaxed);
            drop(root);
            self.adapt(base, stat);
            return;
        }
    }

    /// Port of erts/emulator/beam/erl_db_catree.c (db_erase_catree), OTP-29.1.1.
    pub(crate) fn delete(&self, key: Term) {
        loop {
            let routes = self.routes.load();
            let base = routes.find_base(key);
            let mut root = base.write();
            if !base.is_valid.load(AtomicOrdering::Acquire) {
                drop(root);
                drop(routes);
                std::thread::yield_now();
                continue;
            }
            let removed_words =
                Node::get(&root, key, self.keypos).map_or(0, |found| found.db_size_words as isize);
            *root = Node::remove(root.take(), key, self.keypos);
            self.memory_words
                .fetch_sub(removed_words, AtomicOrdering::Relaxed);
            let stat = base.lock_statistics.load(AtomicOrdering::Relaxed);
            drop(root);
            self.adapt(base, stat);
            return;
        }
    }

    /// Detach every base node's tree for incremental release, leaving one empty base node.
    ///
    /// Port of erts/emulator/beam/erl_db_catree.c (db_free_table_continue_catree), OTP-29.1.1.
    #[expect(clippy::vec_box, reason = "tree links already own boxed nodes")]
    pub(crate) fn take_all(&self) -> Vec<Box<Node>> {
        let _adaptation = self.adaptation.lock().expect("CA-tree adaptation poisoned");
        let routes = self.routes.load_full();
        let mut roots = Vec::new();
        for route in routes.iter() {
            route.base.is_valid.store(false, AtomicOrdering::Release);
            if let Some(root) = route
                .base
                .root
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take()
            {
                roots.push(root);
            }
        }
        self.memory_words.store(0, AtomicOrdering::Relaxed);
        self.routes
            .store(Arc::new(RouteSnapshot::new(vec![RouteEntry {
                first_key: None,
                base: BaseNode::new(None),
            }])));
        roots
    }

    /// Remove every object.
    pub(crate) fn clear(&self) {
        drop(self.take_all());
    }

    /// Read-lock every base node of a consistent route snapshot. A split or join invalidates its
    /// bases under their write locks before publishing new routes, so when all bases are valid
    /// the held guards cover the table exactly once.
    // Port of erts/emulator/beam/erl_db_catree.c (lock_all_bases for
    // db_calc_stats_catree / db_select_catree), OTP-29.1.1.
    fn with_all_bases<R>(
        &self,
        visit: impl FnOnce(&[std::sync::RwLockReadGuard<'_, Option<Box<Node>>>]) -> R,
    ) -> R {
        loop {
            let routes = self.routes.load_full();
            let guards: Vec<_> = routes.iter().map(|route| route.base.read()).collect();
            if routes
                .iter()
                .all(|route| route.base.is_valid.load(AtomicOrdering::Acquire))
            {
                return visit(&guards);
            }
            drop(guards);
            std::thread::yield_now();
        }
    }

    /// Port of erts/emulator/beam/erl_db_catree.c (db_calc_stats_catree), OTP-29.1.1.
    pub(crate) fn count(&self) -> usize {
        self.with_all_bases(|bases| bases.iter().map(|root| Node::count(root)).sum())
    }

    /// Port of erts/emulator/beam/erl_db_catree.c (db_calc_stats_catree), OTP-29.1.1.
    pub(crate) fn validate(&self) -> bool {
        self.with_all_bases(|bases| bases.iter().all(|root| Node::validate(root)))
    }

    /// Port of erts/emulator/beam/erl_db_catree.c (db_next_catree), OTP-29.1.1.
    pub(crate) fn edge<H: HeapAlloc>(
        &self,
        last: bool,
        dst: &mut H,
    ) -> Result<Option<Term>, EtsError> {
        let routes = self.routes.load();
        let iter: Box<dyn Iterator<Item = &RouteEntry>> = if last {
            Box::new(routes.iter().rev())
        } else {
            Box::new(routes.iter())
        };
        for route in iter {
            let root = route.base.read();
            let count = Node::count(&root);
            if count > 0 {
                let object = Node::nth(&root, if last { count - 1 } else { 0 }).unwrap();
                return Ok(Some(arinsal_term::copy_term(object.key(self.keypos), dst)?));
            }
        }
        Ok(None)
    }

    /// Port of erts/emulator/beam/erl_db_catree.c (catree_find_nextprev_root), OTP-29.1.1.
    pub(crate) fn scan_after<F>(
        &self,
        cursor: Option<Term>,
        reverse: bool,
        visit: F,
    ) -> Result<bool, EtsError>
    where
        F: FnMut(&StoredTerm) -> Result<bool, EtsError>,
    {
        self.scan_where(
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
            visit,
        )
    }

    /// Visit the objects whose keys `eligible` accepts base node after base node in key order
    /// (descending when `reverse`) until `visit` returns true.
    // Port of erts/emulator/beam/erl_db_catree.c, catree_find_next_root and
    // catree_find_prev_root, OTP-29.1.1.
    pub(crate) fn scan_where<F>(
        &self,
        reverse: bool,
        eligible: &dyn Fn(Term) -> bool,
        mut visit: F,
    ) -> Result<bool, EtsError>
    where
        F: FnMut(&StoredTerm) -> Result<bool, EtsError>,
    {
        let routes = self.routes.load();
        let iter: Box<dyn Iterator<Item = &RouteEntry>> = if reverse {
            Box::new(routes.iter().rev())
        } else {
            Box::new(routes.iter())
        };
        for route in iter {
            let root = route.base.read();
            if Node::scan_where(&root, reverse, eligible, self.keypos, &mut visit)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Port of erts/emulator/beam/erl_db_catree.c (db_slot_catree), OTP-29.1.1.
    pub(crate) fn nth<H: HeapAlloc>(
        &self,
        mut index: usize,
        dst: &mut H,
    ) -> Result<Option<Term>, EtsError> {
        let routes = self.routes.load();
        for route in routes.iter() {
            let root = route.base.read();
            let count = Node::count(&root);
            if index < count {
                return Node::nth(&root, index)
                    .map(|object| copy_term_for_catree(object, dst))
                    .transpose();
            }
            index -= count;
        }
        Ok(None)
    }

    /// Port of erts/emulator/beam/erl_db_catree.c (db_next_catree_common), OTP-29.1.1.
    pub(crate) fn next<H: HeapAlloc>(
        &self,
        key: Term,
        reverse: bool,
        dst: &mut H,
    ) -> Result<Option<Term>, EtsError> {
        // Port of erts/emulator/beam/erl_db_catree.c (db_next_catree /
        // db_prev_catree), OTP-29.1.1: search the base node that routes the key, then
        // the following (or preceding) base nodes, instead of scanning every object.
        'retry: loop {
            let routes = self.routes.load();
            let entries = &routes.entries;
            let start = entries
                .partition_point(|entry| {
                    entry
                        .first_key
                        .as_ref()
                        .is_none_or(|first| cmp(first.key(1), key) != Ordering::Greater)
                })
                .saturating_sub(1);
            let mut index = start;
            loop {
                let base = &entries[index].base;
                let root = base.read();
                if !base.is_valid.load(AtomicOrdering::Acquire) {
                    drop(root);
                    drop(routes);
                    std::thread::yield_now();
                    continue 'retry;
                }
                let mut found = None;
                Node::scan_after(&root, Some(key), reverse, self.keypos, &mut |object| {
                    found = Some(arinsal_term::copy_term(object.key(self.keypos), dst)?);
                    Ok(true)
                })?;
                if found.is_some() {
                    return Ok(found);
                }
                if reverse {
                    if index == 0 {
                        return Ok(None);
                    }
                    index -= 1;
                } else {
                    index += 1;
                    if index == entries.len() {
                        return Ok(None);
                    }
                }
            }
        }
    }

    /// Port of erts/emulator/beam/erl_db_catree.c (db_select_catree), OTP-29.1.1.
    pub(crate) fn select_range<H: HeapAlloc>(
        &self,
        state: &mut RangeSelection<'_, '_, H>,
    ) -> Result<(), EtsError> {
        let routes = self.routes.load();
        let iter: Box<dyn Iterator<Item = &RouteEntry>> = if state.reverse {
            Box::new(routes.iter().rev())
        } else {
            Box::new(routes.iter())
        };
        for route in iter {
            if state.out.len() >= state.limit {
                break;
            }
            let root = route.base.read();
            Node::select_range(&root, state)?;
        }
        Ok(())
    }

    /// Port of erts/emulator/beam/erl_db_catree.c (db_select_catree) and
    /// erl_db_tree.c (db_select_tree_common): visit a locked base in key order.
    pub(crate) fn walk<H: HeapAlloc>(
        &self,
        reverse: bool,
        dst: &mut H,
    ) -> Result<Vec<Term>, EtsError> {
        let routes = self.routes.load();
        let iter: Box<dyn Iterator<Item = &RouteEntry>> = if reverse {
            Box::new(routes.iter().rev())
        } else {
            Box::new(routes.iter())
        };
        let mut out = Vec::new();
        for route in iter {
            let root = route.base.read();
            Node::scan_where(&root, reverse, &|_| true, self.keypos, &mut |object| {
                out.push(object.copy_out(dst)?);
                Ok(false)
            })?;
        }
        Ok(out)
    }

    /// Port of erts/emulator/beam/erl_db_catree.c (wunlock_adapt_base_node), OTP-29.1.1.
    fn adapt(&self, base: &Arc<BaseNode>, _stat: i64) {
        if self.force_split.load(AtomicOrdering::Relaxed) {
            base.lock_statistics
                .store(i64::MAX, AtomicOrdering::Relaxed);
        }
        let stat = base.lock_statistics.load(AtomicOrdering::Relaxed);
        if (LOW_CONTENTION_LIMIT..=HIGH_CONTENTION_LIMIT).contains(&stat) {
            return;
        }
        let _adaptation = self.adaptation.lock().expect("CA-tree adaptation poisoned");
        let routes = self.routes.load();
        let Some(index) = routes
            .iter()
            .position(|route| Arc::ptr_eq(&route.base, base))
        else {
            return;
        };
        if stat < LOW_CONTENTION_LIMIT && routes.len() == 1 && index == 0 {
            // A parentless base cannot join; erts resets its statistics and releases it.
            base.lock_statistics.store(0, AtomicOrdering::Relaxed);
            return;
        }
        drop(routes);
        if stat > HIGH_CONTENTION_LIMIT {
            self.split(base);
        } else if stat < LOW_CONTENTION_LIMIT {
            self.join(base, JoinCause::LowStatistic);
        }
    }

    /// Port of erts/emulator/beam/erl_db_catree.c (split_catree), OTP-29.1.1.
    fn split(&self, base: &Arc<BaseNode>) {
        let routes = self.routes.load_full();
        let Some(index) = routes
            .iter()
            .position(|route| Arc::ptr_eq(&route.base, base))
        else {
            return;
        };
        let mut root = base.write_no_stats();
        if !base.is_valid.load(AtomicOrdering::Acquire) {
            return;
        }
        if routes.len().next_power_of_two().trailing_zeros() as usize >= MAX_ROUTE_NODE_LAYER_HEIGHT
        {
            return;
        }
        if Node::count(&root) < 2 {
            base.lock_statistics.store(0, AtomicOrdering::Relaxed);
            return;
        }
        base.is_valid.store(false, AtomicOrdering::Release);
        let (left_root, right_root, first_right_key) =
            Node::split_for_catree(root.take().expect("non-empty CA-tree base"), self.keypos);
        let first_key = Some(Arc::new(
            key_object(first_right_key).expect("copying a route key succeeds"),
        ));
        base.lock_statistics.store(0, AtomicOrdering::Relaxed);
        let left_base = BaseNode::new(Some(left_root));
        let right_base = BaseNode::new(right_root);
        let mut updated = routes.entries.clone();
        updated[index] = RouteEntry {
            first_key: routes[index].first_key.clone(),
            base: left_base,
        };
        updated.insert(
            index + 1,
            RouteEntry {
                first_key,
                base: right_base,
            },
        );
        self.routes.store(Arc::new(RouteSnapshot::new(updated)));
        self.split_count.fetch_add(1, AtomicOrdering::Relaxed);
    }

    /// Port of erts/emulator/beam/erl_db_catree.c (join_catree), OTP-29.1.1.
    fn join(&self, base: &Arc<BaseNode>, cause: JoinCause) {
        let routes = self.routes.load_full();
        let Some(index) = routes
            .iter()
            .position(|route| Arc::ptr_eq(&route.base, base))
        else {
            return;
        };
        if routes.len() < 2 {
            base.lock_statistics.store(0, AtomicOrdering::Relaxed);
            return;
        }
        let right_index = if index == 0 { 1 } else { index };
        let left_index = right_index - 1;
        let left = Arc::clone(&routes[left_index].base);
        let right = Arc::clone(&routes[right_index].base);
        let Ok(mut left_root) = left.root.try_write() else {
            base.lock_statistics.store(0, AtomicOrdering::Relaxed);
            return;
        };
        let Ok(mut right_root) = right.root.try_write() else {
            base.lock_statistics.store(0, AtomicOrdering::Relaxed);
            return;
        };
        if !left.is_valid.load(AtomicOrdering::Acquire)
            || !right.is_valid.load(AtomicOrdering::Acquire)
        {
            base.lock_statistics.store(0, AtomicOrdering::Relaxed);
            return;
        }
        left.is_valid.store(false, AtomicOrdering::Release);
        right.is_valid.store(false, AtomicOrdering::Release);
        let left_tree = left_root.take();
        let right_tree = right_root.take();
        // erts publishes the replacement route only after the merged tree is ready.
        // Keeping the old route entries installed makes operations on these two
        // bases retry while readers of unrelated bases remain independent.
        let merged_root = Node::join_ordered(left_tree, right_tree);
        let joined = BaseNode::new(merged_root);
        let mut updated = routes.entries.clone();
        updated[left_index].base = Arc::clone(&joined);
        updated.remove(right_index);
        self.routes.store(Arc::new(RouteSnapshot::new(updated)));
        self.join_count.fetch_add(1, AtomicOrdering::Relaxed);
        match cause {
            JoinCause::LowStatistic => {
                self.low_stat_join_count
                    .fetch_add(1, AtomicOrdering::Relaxed);
            }
            JoinCause::RandomGravity => {
                self.gravity_join_count
                    .fetch_add(1, AtomicOrdering::Relaxed);
            }
        }
    }

    pub(crate) fn base_count(&self) -> usize {
        self.routes.load().len()
    }

    /// Port of erts/emulator/beam/erl_db_catree.c, OTP-29.1.1.
    pub(crate) fn force_split(&self, on: bool) {
        self.force_split.store(on, AtomicOrdering::Relaxed);
        for route in self.routes.load().iter() {
            route
                .base
                .lock_statistics
                .store(if on { i64::MAX } else { 0 }, AtomicOrdering::Relaxed);
        }
    }

    /// Port of erts/emulator/beam/erl_db_catree.c, OTP-29.1.1.
    pub(crate) fn debug_random_split_join(&self, on: bool) {
        self.debug_random_split_join
            .store(on, AtomicOrdering::Relaxed);
    }

    pub(crate) fn adaptation_counts(&self) -> (usize, usize, usize, usize, Vec<i64>) {
        let routes = self.routes.load();
        (
            self.split_count.load(AtomicOrdering::Relaxed),
            self.join_count.load(AtomicOrdering::Relaxed),
            self.low_stat_join_count.load(AtomicOrdering::Relaxed),
            self.gravity_join_count.load(AtomicOrdering::Relaxed),
            routes
                .iter()
                .map(|route| route.base.lock_statistics.load(AtomicOrdering::Relaxed))
                .collect(),
        )
    }

    /// Port of erts/emulator/beam/erl_db_catree.c (do_random_join_with_low_probability), OTP-29.1.1.
    fn random_join(&self) {
        if !self.debug_random_split_join.load(AtomicOrdering::Relaxed) {
            return;
        }
        let random = scheduler_local_random();
        if random & LOCK_GRAVITY_PATTERN != 0 {
            return;
        }
        let routes = self.routes.load();
        let base = Arc::clone(routes.random_base(random));
        base.adjust_stat(LOCK_GRAVITY_CONTRIBUTION);
        let stat = base.lock_statistics.load(AtomicOrdering::Relaxed);
        if (LOW_CONTENTION_LIMIT..=HIGH_CONTENTION_LIMIT).contains(&stat) {
            return;
        }
        let Ok(root) = base.root.try_write() else {
            return;
        };
        if !base.is_valid.load(AtomicOrdering::Acquire) {
            drop(root);
            return;
        }
        drop(root);
        self.adapt_with_cause(&base, stat, JoinCause::RandomGravity);
    }

    fn adapt_with_cause(&self, base: &Arc<BaseNode>, stat: i64, cause: JoinCause) {
        if (LOW_CONTENTION_LIMIT..=HIGH_CONTENTION_LIMIT).contains(&stat) {
            return;
        }
        let _adaptation = self.adaptation.lock().expect("CA-tree adaptation poisoned");
        if stat > HIGH_CONTENTION_LIMIT {
            self.split(base);
        } else {
            self.join(base, cause);
        }
    }

    pub(crate) fn adjust_contention(&self, key: Term, amount: i64) {
        let routes = self.routes.load();
        let index = self.route_index(&routes, key);
        let base = Arc::clone(&routes[index].base);
        base.adjust_stat(amount);
        let stat = base.lock_statistics.load(AtomicOrdering::Relaxed);
        drop(routes);
        self.adapt(&base, stat);
    }
}

#[derive(Clone, Copy)]
enum JoinCause {
    LowStatistic,
    RandomGravity,
}

thread_local! {
    static SCHEDULER_RANDOM: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

fn scheduler_local_random() -> u32 {
    SCHEDULER_RANDOM.with(|state| {
        let mut value = state.get();
        if value == 0 {
            use std::hash::{Hash, Hasher};
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            std::thread::current().id().hash(&mut hasher);
            value = hasher.finish() | 1;
        }
        value ^= value << 13;
        value ^= value >> 7;
        value ^= value << 17;
        state.set(value);
        (value >> 16) as u32
    })
}

/// Port of erts/emulator/beam/erl_db_catree.c (join_trees), OTP-29.1.1.
fn key_object(key: Term) -> Result<StoredTerm, EtsError> {
    let mut heap = VecHeap::new();
    let tuple = TermBuilder::new(&mut heap)
        .tuple(&[key])
        .map_err(EtsError::Term)?;
    StoredTerm::copy(tuple)
}

fn copy_term_for_catree<H: HeapAlloc>(object: &StoredTerm, dst: &mut H) -> Result<Term, EtsError> {
    object.copy_out(dst)
}
