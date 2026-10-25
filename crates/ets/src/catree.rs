//! Safe contention-adapting ordered storage built from the ETS AVL tree.

use super::{EtsError, HeapAlloc, RangeSelection, StoredTerm, Term, TreeDbTerm, cmp};
use crate::dbterm::DbTreeStack;
use crate::rwmtx::{RwMtxLock, RwMtxReadGuard, RwMtxWriteGuard};
use crate::tree::{InsertResult, Node, TreeRoot};
use arc_swap::ArcSwap;
use arinsal_term::{TermBuilder, VecHeap};
use std::cmp::Ordering;
use std::sync::atomic::{
    AtomicBool, AtomicI64, AtomicIsize, AtomicU64, AtomicUsize, Ordering as AtomicOrdering,
};
use std::sync::{Arc, Mutex};

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
    root: RwMtxLock<TreeRoot>,
    frequent_read: bool,
    lock_statistics: AtomicI64,
    is_valid: AtomicBool,
}

impl BaseNode {
    // Port of erts/emulator/beam/erl_db_catree.c:1034 (create_base_node: the lock is a
    // frequent-read rwmutex when the table has DB_FREQ_READ), OTP-29.1.1.
    fn new(root: TreeRoot, frequent_read: bool) -> Arc<Self> {
        Arc::new(Self {
            root: if frequent_read {
                RwMtxLock::new_freq_read(root)
            } else {
                RwMtxLock::new(root)
            },
            frequent_read,
            lock_statistics: AtomicI64::new(0),
            is_valid: AtomicBool::new(true),
        })
    }

    /// Port of erts/emulator/beam/erl_db_catree.c (wlock_base_node), OTP-29.1.1.
    fn write(&self) -> RwMtxWriteGuard<'_, TreeRoot> {
        match self.root.try_write() {
            Some(guard) => {
                // Port of erts/emulator/beam/erl_db_catree.c (wlock_base_node), OTP-29.1.1.
                // BASE_NODE_STAT_SUB adds the negative success contribution: an uncontended
                // write lowers the statistics by one.
                self.adjust_stat(LOCK_SUCCESS_CONTRIBUTION);
                guard
            }
            None => {
                self.adjust_stat(LOCK_FAILURE_CONTRIBUTION);
                self.root.write()
            }
        }
    }

    fn write_no_stats(&self) -> RwMtxWriteGuard<'_, TreeRoot> {
        self.root.write()
    }

    /// Port of erts/emulator/beam/erl_db_catree.c:842 (rlock_base_node), OTP-29.1.1.
    fn read(&self) -> RwMtxReadGuard<'_, TreeRoot> {
        self.read_at(if self.frequent_read {
            arinsal_term::current_reader_group()
        } else {
            0
        })
    }

    /// Port of erts/emulator/beam/erl_db_catree.c (rlock_base_node), OTP-29.1.1, in reader
    /// group `group`.
    #[inline]
    fn read_at(&self, group: usize) -> RwMtxReadGuard<'_, TreeRoot> {
        match self.root.try_read_at(group) {
            Some(guard) => guard,
            None => {
                self.adjust_stat(LOCK_FAILURE_CONTRIBUTION);
                self.root.read_at(group)
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
    first_key: Option<Arc<crate::PlainDbTerm>>,
    base: Arc<BaseNode>,
}

struct RouteSnapshot {
    entries: Vec<RouteEntry>,
    root: Box<RouteNode>,
}

enum RouteNode {
    Base(Arc<BaseNode>),
    Branch {
        key: Arc<crate::PlainDbTerm>,
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
    /// The table has DB_FREQ_READ: its base-node locks are frequent-read rwmutexes.
    frequent_read: bool,
    routes: ArcSwap<RouteSnapshot>,
    adaptation: Mutex<()>,
    split_count: AtomicUsize,
    join_count: AtomicUsize,
    low_stat_join_count: AtomicUsize,
    gravity_join_count: AtomicUsize,
    force_split: AtomicBool,
    debug_random_split_join: AtomicBool,
    memory_words: AtomicIsize,
    /// `tb->common.counters` NITEMS: the table-wide object count.
    nitems: AtomicIsize,
    /// Bumped by every change of a base node's tree, split and join; the slot stack is only
    /// valid for the version it was made at.
    version: AtomicU64,
    /// `DbTableCATree.static_stack`: the slot walk kept between `ets:slot/2` calls.
    slot_stack: Mutex<SlotWalk>,
}

/// The table-wide slot stack: the nodes of the base node `base` down to the last slot visited,
/// with `stack.slot` counting objects over all base nodes.
struct SlotWalk {
    routes: Option<Arc<RouteSnapshot>>,
    version: u64,
    base: usize,
    stack: DbTreeStack,
}

impl CATree {
    /// Port of erts/emulator/beam/erl_db_catree.c (db_initialize_catree), OTP-29.1.1.
    pub(crate) fn new(keypos: usize, frequent_read: bool) -> Self {
        Self {
            keypos,
            frequent_read,
            routes: ArcSwap::from_pointee(RouteSnapshot::new(vec![RouteEntry {
                first_key: None,
                base: BaseNode::new(TreeRoot::new(), frequent_read),
            }])),
            adaptation: Mutex::new(()),
            split_count: AtomicUsize::new(0),
            join_count: AtomicUsize::new(0),
            low_stat_join_count: AtomicUsize::new(0),
            gravity_join_count: AtomicUsize::new(0),
            force_split: AtomicBool::new(false),
            debug_random_split_join: AtomicBool::new(false),
            memory_words: AtomicIsize::new(0),
            nitems: AtomicIsize::new(0),
            version: AtomicU64::new(0),
            slot_stack: Mutex::new(SlotWalk {
                routes: None,
                version: 0,
                base: 0,
                stack: DbTreeStack::new(),
            }),
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
    pub(crate) fn insert(&self, object: TreeDbTerm) {
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
            let new_words = object.as_ref().unwrap().db_size_words() as isize;
            let result = root.insert_with_key(object.take().unwrap(), key, self.keypos, false);
            self.version.fetch_add(1, AtomicOrdering::Release);
            let old_words = match result {
                crate::tree::InsertResult::Inserted => {
                    self.nitems.fetch_add(1, AtomicOrdering::Relaxed);
                    0
                }
                crate::tree::InsertResult::Replaced(words) => words as isize,
                crate::tree::InsertResult::Exists => unreachable!("replacement cannot clash"),
            };
            self.memory_words
                .fetch_add(new_words - old_words, AtomicOrdering::Relaxed);
            let stat = base.lock_statistics.load(AtomicOrdering::Relaxed);
            drop(root);
            self.adapt(base, stat);
            break;
        }
    }

    /// Insert the source object `term` under its base-node lock, reusing an overwritten block.
    // Port of erts/emulator/beam/erl_db_catree.c (db_put_catree with db_put_tree_common),
    // OTP-29.1.1.
    pub(crate) fn insert_term(
        &self,
        term: Term,
        key: Term,
        compressed: bool,
        new_only: bool,
    ) -> Result<bool, EtsError> {
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
            let put = root.put_term(term, key, self.keypos, compressed, new_only);
            self.version.fetch_add(1, AtomicOrdering::Release);
            let (result, new_words) = put?;
            let inserted = match result {
                crate::tree::InsertResult::Inserted => {
                    self.nitems.fetch_add(1, AtomicOrdering::Relaxed);
                    self.memory_words
                        .fetch_add(new_words as isize, AtomicOrdering::Relaxed);
                    true
                }
                crate::tree::InsertResult::Replaced(old_words) => {
                    self.memory_words.fetch_add(
                        new_words as isize - old_words as isize,
                        AtomicOrdering::Relaxed,
                    );
                    true
                }
                crate::tree::InsertResult::Exists => false,
            };
            let stat = base.lock_statistics.load(AtomicOrdering::Relaxed);
            drop(root);
            self.adapt(base, stat);
            return Ok(inserted);
        }
    }

    /// Insert an object only when its ordered key is absent.
    // Port of erts/emulator/beam/erl_db_catree.c (db_put_catree with key_clash_fail), OTP-29.1.1.
    pub(crate) fn insert_new(&self, object: TreeDbTerm) -> bool {
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
            let stored = object
                .take()
                .expect("CA-tree insert object retained on retry");
            let words = stored.db_size_words() as isize;
            let result = root.insert_with_key(stored, key, self.keypos, true);
            self.version.fetch_add(1, AtomicOrdering::Release);
            let inserted = matches!(result, crate::tree::InsertResult::Inserted);
            if inserted {
                self.nitems.fetch_add(1, AtomicOrdering::Relaxed);
                self.memory_words.fetch_add(words, AtomicOrdering::Relaxed);
            }
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
            let result = root.get_mut(key, self.keypos).and_then(|object| {
                update.take().expect("CA-tree update retained on retry")(object)
            });
            let stat = base.lock_statistics.load(AtomicOrdering::Relaxed);
            drop(root);
            self.adapt(base, stat);
            return result;
        }
    }

    /// Run `db_update_counter` under one CA-tree route lock and tree descent.
    // Port of erts/emulator/beam/erl_db_catree.c:db_lookup_dbterm_catree and
    // db_finalize_dbterm_catree, OTP-29.1.1.
    pub(crate) fn update_counter(
        &self,
        key: Term,
        update: impl FnOnce(Option<&mut TreeDbTerm>) -> Result<(Option<TreeDbTerm>, isize), EtsError>,
    ) -> Result<InsertResult, EtsError> {
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
            let mut memory_delta = 0;
            let result = root.update_counter(key, self.keypos, |found| {
                let (replacement, delta) = update
                    .take()
                    .expect("CA-tree counter update retained on retry")(
                    found
                )?;
                memory_delta = delta;
                Ok(replacement)
            });
            self.version.fetch_add(1, AtomicOrdering::Release);
            let result = result?;
            if matches!(result, InsertResult::Inserted) {
                self.nitems.fetch_add(1, AtomicOrdering::Relaxed);
            }
            self.memory_words
                .fetch_add(memory_delta, AtomicOrdering::Relaxed);
            let stat = base.lock_statistics.load(AtomicOrdering::Relaxed);
            drop(root);
            self.adapt(base, stat);
            return Ok(result);
        }
    }

    /// Port of erts/emulator/beam/erl_db_catree.c (db_put_catree), OTP-29.1.1.
    pub(crate) fn insert_many(&self, objects: Vec<TreeDbTerm>) {
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

    /// `lookup_one` in reader group `group`.
    pub(crate) fn lookup_one_at<H: HeapAlloc>(
        &self,
        key: Term,
        group: usize,
        dst: &mut H,
    ) -> Result<Option<Term>, EtsError> {
        loop {
            let routes = self.routes.load();
            let base = routes.find_base(key);
            let root = base.read_at(group);
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
        self.member_at(key, arinsal_term::current_reader_group())
    }

    /// `member` in reader group `group`.
    pub(crate) fn member_at(&self, key: Term, group: usize) -> bool {
        loop {
            let routes = self.routes.load();
            let base = routes.find_base(key);
            let root = base.read_at(group);
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

    /// `lookup_element` in reader group `group`.
    pub(crate) fn lookup_element_at<H: HeapAlloc>(
        &self,
        key: Term,
        index: usize,
        group: usize,
        dst: &mut H,
    ) -> Result<Term, EtsError> {
        loop {
            let routes = self.routes.load();
            let base = routes.find_base(key);
            let root = base.read_at(group);
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
    pub(crate) fn matching(&self, key: Term) -> Result<Vec<TreeDbTerm>, EtsError> {
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
                .map(StoredTerm::copy_stored::<crate::TreePrefix>)
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
            let removed_words =
                root.remove_matching(key, self.keypos, |found| found.exact_eq_input(object));
            if let Some(removed_words) = removed_words {
                self.version.fetch_add(1, AtomicOrdering::Release);
                self.nitems.fetch_sub(1, AtomicOrdering::Relaxed);
                self.memory_words
                    .fetch_sub(removed_words as isize, AtomicOrdering::Relaxed);
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
            let removed_words = root.remove_matching(key, self.keypos, |_| true);
            if let Some(removed_words) = removed_words {
                self.version.fetch_add(1, AtomicOrdering::Release);
                self.nitems.fetch_sub(1, AtomicOrdering::Relaxed);
                self.memory_words
                    .fetch_sub(removed_words as isize, AtomicOrdering::Relaxed);
            }
            let stat = base.lock_statistics.load(AtomicOrdering::Relaxed);
            drop(root);
            self.adapt(base, stat);
            return;
        }
    }

    /// Detach every base node's tree for incremental release, leaving one empty base node.
    ///
    /// Port of erts/emulator/beam/erl_db_catree.c (db_free_table_continue_catree), OTP-29.1.1.
    pub(crate) fn take_all(&self) -> Vec<TreeDbTerm> {
        let _adaptation = self.adaptation.lock().expect("CA-tree adaptation poisoned");
        let routes = self.routes.load_full();
        let mut roots = Vec::new();
        for route in routes.iter() {
            route.base.is_valid.store(false, AtomicOrdering::Release);
            if let (Some(root), _) = route.base.root.write().take() {
                roots.push(root);
            }
        }
        self.memory_words.store(0, AtomicOrdering::Relaxed);
        self.nitems.store(0, AtomicOrdering::Relaxed);
        self.version.fetch_add(1, AtomicOrdering::Release);
        self.routes
            .store(Arc::new(RouteSnapshot::new(vec![RouteEntry {
                first_key: None,
                base: BaseNode::new(TreeRoot::new(), self.frequent_read),
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
    fn with_all_bases<R>(&self, visit: impl FnOnce(&[RwMtxReadGuard<'_, TreeRoot>]) -> R) -> R {
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
        self.nitems.load(AtomicOrdering::Relaxed).max(0) as usize
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
            if let Some(object) = Node::edge(&root, last) {
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
        if reverse {
            for route in routes.iter().rev() {
                let root = route.base.read();
                if Node::scan_where(&root, reverse, eligible, self.keypos, &mut visit)? {
                    return Ok(true);
                }
            }
        } else {
            for route in routes.iter() {
                let root = route.base.read();
                if Node::scan_where(&root, reverse, eligible, self.keypos, &mut visit)? {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    /// Port of erts/emulator/beam/erl_db_catree.c (db_slot_catree) and erl_db_tree.c
    /// (slot_search with a CA-tree root iterator), OTP-29.1.1: one stack walks the base nodes in
    /// key order, so a sequential `ets:slot/2` walk is amortized constant time.
    pub(crate) fn nth<H: HeapAlloc>(
        &self,
        index: usize,
        dst: &mut H,
    ) -> Result<Option<Term>, EtsError> {
        let slot = index + 1;
        let mut walk = self.slot_stack.lock().expect("CA-tree slot stack poisoned");
        'restart: loop {
            let routes = self.routes.load_full();
            let version = self.version.load(AtomicOrdering::Acquire);
            let fresh = walk.version != version
                || !walk
                    .routes
                    .as_ref()
                    .is_some_and(|saved| Arc::ptr_eq(saved, &routes));
            if fresh || slot == 1 {
                walk.routes = Some(Arc::clone(&routes));
                walk.version = version;
                walk.base = 0;
                walk.stack = DbTreeStack::new();
            }
            let mut base = walk.base;
            loop {
                let Some(route) = routes.entries.get(base) else {
                    // Past the last object: the next walk starts over.
                    walk.routes = None;
                    return Ok(None);
                };
                let root = route.base.read();
                if !route.base.is_valid.load(AtomicOrdering::Acquire)
                    || self.version.load(AtomicOrdering::Acquire) != version
                {
                    drop(root);
                    walk.routes = None;
                    std::thread::yield_now();
                    continue 'restart;
                }
                walk.base = base;
                let stack = &mut walk.stack;
                if stack.is_empty() {
                    // Entering this base node: its first object is the next slot.
                    if root.link().is_none() {
                        base += 1;
                        continue;
                    }
                    stack.push_left_spine(root.link());
                    stack.set_slot(stack.slot() + 1);
                }
                match stack.walk_to(slot, root.link()) {
                    Some(object) => {
                        return Some(copy_term_for_catree(object, dst)).transpose();
                    }
                    None if slot > stack.slot() => {
                        // This base node ran out: continue with the next one.
                        base += 1;
                    }
                    None => {
                        // Walked back past the first object of the base node: start over.
                        walk.routes = None;
                        continue 'restart;
                    }
                }
            }
        }
    }

    /// Port of erts/emulator/beam/erl_db_catree.c:1615 (db_next_catree_common), :1679
    /// (db_prev_catree_common), and :1868/:1873 (catree_find_next_root /
    /// catree_find_prev_root), OTP-29.1.1.
    pub(crate) fn next<H: HeapAlloc>(
        &self,
        key: Term,
        reverse: bool,
        dst: &mut H,
    ) -> Result<Option<Term>, EtsError> {
        // Port of erts/emulator/beam/erl_db_catree.c (db_next_catree /
        // db_prev_catree), OTP-29.1.1: search the base node that routes the key, then
        // the following (or preceding) base nodes, instead of scanning every object.
        let mut stack_array = DbTreeStack::inline_storage();
        let mut stack = DbTreeStack::with_inline(&mut stack_array);
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
                if let Some(object) =
                    root.find_next_prev_in_base_with_stack(key, reverse, self.keypos, &mut stack)
                {
                    return Ok(Some(arinsal_term::copy_term(object.key(self.keypos), dst)?));
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
        if state.reverse {
            for route in routes.iter().rev() {
                if state.out.len() >= state.limit {
                    break;
                }
                let root = route.base.read();
                Node::select_range(&root, state)?;
            }
        } else {
            for route in routes.iter() {
                if state.out.len() >= state.limit {
                    break;
                }
                let root = route.base.read();
                Node::select_range(&root, state)?;
            }
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
        let mut out = Vec::new();
        if reverse {
            for route in routes.iter().rev() {
                let root = route.base.read();
                Node::scan_where(&root, reverse, &|_| true, self.keypos, &mut |object| {
                    out.push(object.copy_out(dst)?);
                    Ok(false)
                })?;
            }
        } else {
            for route in routes.iter() {
                let root = route.base.read();
                Node::scan_where(&root, reverse, &|_| true, self.keypos, &mut |object| {
                    out.push(object.copy_out(dst)?);
                    Ok(false)
                })?;
            }
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
        if root.count() < 2 {
            base.lock_statistics.store(0, AtomicOrdering::Relaxed);
            return;
        }
        base.is_valid.store(false, AtomicOrdering::Release);
        let (left_root, right_root, first_right_key) =
            std::mem::take(&mut *root).split_for_catree(self.keypos);
        let first_key = Some(Arc::new(
            key_object(first_right_key).expect("copying a route key succeeds"),
        ));
        base.lock_statistics.store(0, AtomicOrdering::Relaxed);
        let left_base = BaseNode::new(left_root, self.frequent_read);
        let right_base = BaseNode::new(right_root, self.frequent_read);
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
        let Some(mut left_root) = left.root.try_write() else {
            base.lock_statistics.store(0, AtomicOrdering::Relaxed);
            return;
        };
        let Some(mut right_root) = right.root.try_write() else {
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
        let left_tree = std::mem::take(&mut *left_root);
        let right_tree = std::mem::take(&mut *right_root);
        // erts publishes the replacement route only after the merged tree is ready.
        // Keeping the old route entries installed makes operations on these two
        // bases retry while readers of unrelated bases remain independent.
        let merged_root = TreeRoot::join_ordered(left_tree, right_tree);
        let joined = BaseNode::new(merged_root, self.frequent_read);
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
        let Some(root) = base.root.try_write() else {
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
fn key_object(key: Term) -> Result<crate::PlainDbTerm, EtsError> {
    let mut heap = VecHeap::new();
    let tuple = TermBuilder::new(&mut heap)
        .tuple(&[key])
        .map_err(EtsError::Term)?;
    StoredTerm::copy(tuple)
}

fn copy_term_for_catree<H: HeapAlloc>(object: &StoredTerm, dst: &mut H) -> Result<Term, EtsError> {
    object.copy_out(dst)
}
