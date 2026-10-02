//! Scheduler-local timer wheel and long timer index.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::mpsc::SyncSender;

use crate::Pid;

const SOON_BITS: u32 = 14;
const SOON_SIZE: usize = 1 << SOON_BITS;
const SOON_MASK: u64 = (SOON_SIZE - 1) as u64;
const LATER_SHIFT: u32 = SOON_BITS - 1;
const LATER_SLOT_SIZE: u64 = 1 << LATER_SHIFT;
const LATER_REVOLUTION: u64 = (SOON_SIZE as u64) * LATER_SLOT_SIZE;
const SLOT_AT_ONCE: usize = SOON_SIZE * 2;
const BUMP_YIELD_LIMIT: usize = 10_000;
const COST_SLOT: usize = 1;
const COST_SLOT_MOVE: usize = 5;
const COST_TIMEOUT: usize = 100;
const NIL: u32 = u32::MAX;
const TIMER_PENDING: u8 = 0;
const TIMER_CANCELED: u8 = 1;
const TIMER_FIRED: u8 = 2;

struct TreeNode {
    key: u64,
    parent: u32,
    left: u32,
    right: u32,
    red: bool,
    head: u64,
    tail: u64,
}

/// Safe arena-backed form of OTP's intrusive red-black tree.
struct TimerTree {
    nodes: Vec<Option<TreeNode>>,
    free: Vec<u32>,
    root: u32,
}

impl TimerTree {
    // Port of erts/emulator/beam/erl_hl_timer.c:343-347, OTP-29.1.1.
    fn new() -> Self {
        Self {
            nodes: Vec::new(),
            free: Vec::new(),
            root: NIL,
        }
    }

    // Port of erts/emulator/beam/erl_hl_timer.c:349-378, OTP-29.1.1.
    fn node(&self, index: u32) -> &TreeNode {
        self.nodes[index as usize]
            .as_ref()
            .expect("live timer tree node")
    }

    // Port of erts/emulator/beam/erl_hl_timer.c:349-378, OTP-29.1.1.
    fn node_mut(&mut self, index: u32) -> &mut TreeNode {
        self.nodes[index as usize]
            .as_mut()
            .expect("live timer tree node")
    }

    // Port of erts/emulator/beam/erl_hl_timer.c:365-376, OTP-29.1.1.
    fn parent(&self, index: u32) -> u32 {
        if index == NIL {
            NIL
        } else {
            self.node(index).parent
        }
    }

    // Port of erts/emulator/beam/erl_hl_timer.c:373-376, OTP-29.1.1.
    fn left(&self, index: u32) -> u32 {
        if index == NIL {
            NIL
        } else {
            self.node(index).left
        }
    }

    // Port of erts/emulator/beam/erl_hl_timer.c:373-376, OTP-29.1.1.
    fn right(&self, index: u32) -> u32 {
        if index == NIL {
            NIL
        } else {
            self.node(index).right
        }
    }

    // Port of erts/emulator/beam/erl_hl_timer.c:349-356, OTP-29.1.1.
    fn red(&self, index: u32) -> bool {
        index != NIL && self.node(index).red
    }

    // Port of erts/emulator/beam/erl_rbtree.h: insert and left/right rotations, OTP-29.1.1.
    fn insert_node(&mut self, key: u64) -> u32 {
        let mut parent = NIL;
        let mut cursor = self.root;
        while cursor != NIL {
            parent = cursor;
            match key.cmp(&self.node(cursor).key) {
                std::cmp::Ordering::Less => cursor = self.node(cursor).left,
                std::cmp::Ordering::Greater => cursor = self.node(cursor).right,
                std::cmp::Ordering::Equal => return cursor,
            }
        }
        let index = self.free.pop().unwrap_or_else(|| {
            let index = u32::try_from(self.nodes.len()).expect("timer tree index overflow");
            self.nodes.push(None);
            index
        });
        self.nodes[index as usize] = Some(TreeNode {
            key,
            parent,
            left: NIL,
            right: NIL,
            red: true,
            head: 0,
            tail: 0,
        });
        if parent == NIL {
            self.root = index;
        } else if key < self.node(parent).key {
            self.node_mut(parent).left = index;
        } else {
            self.node_mut(parent).right = index;
        }
        self.insert_fixup(index);
        index
    }

    // Port of erts/emulator/beam/erl_rbtree.h:565-599, OTP-29.1.1.
    fn rotate_left(&mut self, x: u32) {
        let y = self.right(x);
        let beta = self.left(y);
        self.node_mut(x).right = beta;
        if beta != NIL {
            self.node_mut(beta).parent = x;
        }
        let parent = self.parent(x);
        self.node_mut(y).parent = parent;
        if parent == NIL {
            self.root = y;
        } else if x == self.left(parent) {
            self.node_mut(parent).left = y;
        } else {
            self.node_mut(parent).right = y;
        }
        self.node_mut(y).left = x;
        self.node_mut(x).parent = y;
    }

    // Port of erts/emulator/beam/erl_rbtree.h:602-637, OTP-29.1.1.
    fn rotate_right(&mut self, x: u32) {
        let y = self.left(x);
        let beta = self.right(y);
        self.node_mut(x).left = beta;
        if beta != NIL {
            self.node_mut(beta).parent = x;
        }
        let parent = self.parent(x);
        self.node_mut(y).parent = parent;
        if parent == NIL {
            self.root = y;
        } else if x == self.right(parent) {
            self.node_mut(parent).right = y;
        } else {
            self.node_mut(parent).left = y;
        }
        self.node_mut(y).right = x;
        self.node_mut(x).parent = y;
    }

    // Port of erts/emulator/beam/erl_rbtree.h: insert balancing, OTP-29.1.1.
    fn insert_fixup(&mut self, mut z: u32) {
        while self.red(self.parent(z)) {
            let parent = self.parent(z);
            let grand = self.parent(parent);
            if parent == self.left(grand) {
                let uncle = self.right(grand);
                if self.red(uncle) {
                    self.node_mut(parent).red = false;
                    self.node_mut(uncle).red = false;
                    self.node_mut(grand).red = true;
                    z = grand;
                } else {
                    if z == self.right(parent) {
                        z = parent;
                        self.rotate_left(z);
                    }
                    let parent = self.parent(z);
                    let grand = self.parent(parent);
                    self.node_mut(parent).red = false;
                    self.node_mut(grand).red = true;
                    self.rotate_right(grand);
                }
            } else {
                let uncle = self.left(grand);
                if self.red(uncle) {
                    self.node_mut(parent).red = false;
                    self.node_mut(uncle).red = false;
                    self.node_mut(grand).red = true;
                    z = grand;
                } else {
                    if z == self.left(parent) {
                        z = parent;
                        self.rotate_right(z);
                    }
                    let parent = self.parent(z);
                    let grand = self.parent(parent);
                    self.node_mut(parent).red = false;
                    self.node_mut(grand).red = true;
                    self.rotate_left(grand);
                }
            }
        }
        if self.root != NIL {
            self.node_mut(self.root).red = false;
        }
    }

    // Port of erts/emulator/beam/erl_rbtree.h:718-726, OTP-29.1.1.
    fn minimum(&self, mut node: u32) -> u32 {
        while self.left(node) != NIL {
            node = self.left(node);
        }
        node
    }

    // Port of erts/emulator/beam/erl_rbtree.h:649-682, OTP-29.1.1.
    fn transplant(&mut self, old: u32, new: u32) {
        let parent = self.parent(old);
        if parent == NIL {
            self.root = new;
        } else if old == self.left(parent) {
            self.node_mut(parent).left = new;
        } else {
            self.node_mut(parent).right = new;
        }
        if new != NIL {
            self.node_mut(new).parent = parent;
        }
    }

    // Port of erts/emulator/beam/erl_rbtree.h:705-925, OTP-29.1.1.
    fn delete(&mut self, z: u32) {
        let mut y = z;
        let mut y_red = self.red(y);
        let x;
        let x_parent;
        if self.left(z) == NIL {
            x = self.right(z);
            x_parent = self.parent(z);
            self.transplant(z, x);
        } else if self.right(z) == NIL {
            x = self.left(z);
            x_parent = self.parent(z);
            self.transplant(z, x);
        } else {
            y = self.minimum(self.right(z));
            y_red = self.red(y);
            x = self.right(y);
            if self.parent(y) == z {
                x_parent = y;
                if x != NIL {
                    self.node_mut(x).parent = y;
                }
            } else {
                x_parent = self.parent(y);
                self.transplant(y, x);
                let z_right = self.right(z);
                self.node_mut(y).right = z_right;
                self.node_mut(z_right).parent = y;
            }
            self.transplant(z, y);
            let z_left = self.left(z);
            self.node_mut(y).left = z_left;
            self.node_mut(z_left).parent = y;
            self.node_mut(y).red = self.red(z);
        }
        if !y_red {
            self.delete_fixup(x, x_parent);
        }
        self.nodes[z as usize] = None;
        self.free.push(z);
    }

    // Port of erts/emulator/beam/erl_rbtree.h:774-919, OTP-29.1.1.
    fn delete_fixup(&mut self, mut x: u32, mut parent: u32) {
        while x != self.root && !self.red(x) {
            if parent == NIL {
                break;
            }
            if x == self.left(parent) {
                let mut sibling = self.right(parent);
                if self.red(sibling) {
                    self.node_mut(sibling).red = false;
                    self.node_mut(parent).red = true;
                    self.rotate_left(parent);
                    sibling = self.right(parent);
                }
                if !self.red(self.left(sibling)) && !self.red(self.right(sibling)) {
                    if sibling != NIL {
                        self.node_mut(sibling).red = true;
                    }
                    x = parent;
                    parent = self.parent(x);
                } else {
                    if !self.red(self.right(sibling)) {
                        let left = self.left(sibling);
                        if left != NIL {
                            self.node_mut(left).red = false;
                        }
                        if sibling != NIL {
                            self.node_mut(sibling).red = true;
                            self.rotate_right(sibling);
                        }
                        sibling = self.right(parent);
                    }
                    if sibling != NIL {
                        self.node_mut(sibling).red = self.red(parent);
                    }
                    self.node_mut(parent).red = false;
                    let right = self.right(sibling);
                    if right != NIL {
                        self.node_mut(right).red = false;
                    }
                    self.rotate_left(parent);
                    x = self.root;
                    parent = NIL;
                }
            } else {
                let mut sibling = self.left(parent);
                if self.red(sibling) {
                    self.node_mut(sibling).red = false;
                    self.node_mut(parent).red = true;
                    self.rotate_right(parent);
                    sibling = self.left(parent);
                }
                if !self.red(self.right(sibling)) && !self.red(self.left(sibling)) {
                    if sibling != NIL {
                        self.node_mut(sibling).red = true;
                    }
                    x = parent;
                    parent = self.parent(x);
                } else {
                    if !self.red(self.left(sibling)) {
                        let right = self.right(sibling);
                        if right != NIL {
                            self.node_mut(right).red = false;
                        }
                        if sibling != NIL {
                            self.node_mut(sibling).red = true;
                            self.rotate_left(sibling);
                        }
                        sibling = self.left(parent);
                    }
                    if sibling != NIL {
                        self.node_mut(sibling).red = self.red(parent);
                    }
                    self.node_mut(parent).red = false;
                    let left = self.left(sibling);
                    if left != NIL {
                        self.node_mut(left).red = false;
                    }
                    self.rotate_right(parent);
                    x = self.root;
                    parent = NIL;
                }
            }
        }
        if x != NIL {
            self.node_mut(x).red = false;
        }
    }

    // Port of erts/emulator/beam/erl_rbtree.h: smallest and lookup, OTP-29.1.1.
    fn first_at_or_before(&self, limit: u64) -> Option<u32> {
        if self.root == NIL {
            return None;
        }
        let first = self.minimum(self.root);
        (self.node(first).key <= limit).then_some(first)
    }
}

/// Reference returned by a timer operation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct TimerRef {
    pub(crate) worker: usize,
    pub(crate) id: u64,
}

impl TimerRef {
    /// One-based scheduler that owns this timer's wheel.
    pub fn worker_id(self) -> usize {
        self.worker + 1
    }

    /// Stable numeric identity for the VM's reference representation.
    pub fn id(self) -> u64 {
        self.id
    }
}

/// Work emitted when a timer expires.
pub(crate) enum TimerPayload<M> {
    Message(Pid, M, bool),
    ResolvedMessage(Arc<dyn Fn() -> Option<Pid> + Send + Sync>, M, bool),
    Wake(Pid, u64),
    /// Runtime callback owned by a process (erts `erts_start_timer_callback`).
    Callback(Pid, crate::TimerCallback<M>),
}

pub(crate) enum TimerCommand<M> {
    Insert {
        id: u64,
        deadline: u64,
        payload: TimerPayload<M>,
        reply: SyncSender<()>,
    },
    Read {
        id: u64,
        reply: Option<SyncSender<Option<u64>>>,
        callback: Option<Box<dyn FnOnce(Option<u64>) + Send>>,
    },
    Cancel {
        id: u64,
        callback: Box<dyn FnOnce(Option<u64>) + Send>,
    },
    CancelTarget {
        pid: Pid,
    },
    /// Hold the BIF timers aimed at `pid` (a suspended process).
    PauseTarget {
        pid: Pid,
    },
    /// Re-arm the held timers of `pid` with their remaining time.
    ResumeTarget {
        pid: Pid,
    },
}

pub(crate) struct CanceledTimer {
    pub(crate) id: u64,
    pub(crate) reply: Option<SyncSender<Option<u64>>>,
    pub(crate) callback: Option<Box<dyn FnOnce(Option<u64>) + Send>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WheelKind {
    Soon,
    Later,
    AtOnce,
    HighLevel,
    Pending,
}

struct Entry<M> {
    deadline: u64,
    order: u64,
    kind: WheelKind,
    slot: usize,
    position: usize,
    tree_node: u32,
    tree_prev: u64,
    tree_next: u64,
    state: AtomicU8,
    payload: TimerPayload<M>,
}

/// A timer wheel owned by one scheduler. The scheduler serializes mutations
/// that cross worker boundaries; this structure itself has no locking.
pub(crate) struct Wheel<M> {
    now: u64,
    next_order: u64,
    soon: Vec<Vec<u64>>,
    later: Vec<Vec<u64>>,
    at_once: Vec<u64>,
    pending: Vec<u64>,
    bump_pending: Vec<u64>,
    bump_cursor: usize,
    high_level: TimerTree,
    entries: HashMap<u64, Entry<M>>,
    target_entries: HashMap<Pid, HashSet<u64>>,
    /// Cached [`Wheel::next_timeout`]; valid until the wheel reaches it or its timers change.
    next_timeout: Option<u64>,
    /// Timers held while their destination is suspended, with the time they had left.
    paused: HashMap<Pid, Vec<(u64, TimerPayload<M>)>>,
}

impl<M> Wheel<M> {
    // Port of erts/emulator/beam/time.c:1190-1218, OTP-29.1.1.
    pub(crate) fn new(now: u64) -> Self {
        Self {
            now,
            next_order: 0,
            soon: (0..SOON_SIZE).map(|_| Vec::new()).collect(),
            later: (0..SOON_SIZE).map(|_| Vec::new()).collect(),
            at_once: Vec::new(),
            pending: Vec::new(),
            bump_pending: Vec::new(),
            bump_cursor: 0,
            high_level: TimerTree::new(),
            entries: HashMap::new(),
            target_entries: HashMap::new(),
            next_timeout: None,
            paused: HashMap::new(),
        }
    }

    // Port of erts/emulator/beam/time.c:445-464, OTP-29.1.1.
    fn soon_slot(deadline: u64) -> usize {
        (deadline & SOON_MASK) as usize
    }

    // Port of erts/emulator/beam/time.c:445-464, OTP-29.1.1.
    fn later_slot(deadline: u64) -> usize {
        ((deadline >> LATER_SHIFT) as usize) & (SOON_SIZE - 1)
    }

    // Port of erts/emulator/beam/time.c:1256-1291, OTP-29.1.1.
    fn insert_slot(&mut self, id: u64, mut entry: Entry<M>, kind: WheelKind, slot: usize) {
        self.next_timeout = None;
        let bucket = match kind {
            WheelKind::Soon => &mut self.soon[slot],
            WheelKind::Later => &mut self.later[slot],
            WheelKind::AtOnce => &mut self.at_once,
            WheelKind::HighLevel | WheelKind::Pending => unreachable!(),
        };
        entry.kind = kind;
        entry.slot = slot;
        entry.position = bucket.len();
        bucket.push(id);
        self.entries.insert(id, entry);
    }

    // Port of erts/emulator/beam/time.c:1256-1291, OTP-29.1.1.
    fn place(&mut self, id: u64, entry: Entry<M>) {
        let deadline = entry.deadline;
        if deadline <= self.now {
            self.insert_slot(id, entry, WheelKind::AtOnce, SLOT_AT_ONCE);
        } else if deadline - self.now < SOON_SIZE as u64 {
            // Port of erts/emulator/beam/time.c:1274-1280, OTP-29.1.1.
            self.insert_slot(id, entry, WheelKind::Soon, Self::soon_slot(deadline));
        } else if deadline - self.now < LATER_REVOLUTION {
            // Port of erts/emulator/beam/time.c:1281-1291, OTP-29.1.1.
            self.insert_slot(id, entry, WheelKind::Later, Self::later_slot(deadline));
        } else {
            self.insert_long(id, entry);
        }
    }

    // Port of erts/emulator/beam/erl_hl_timer.c:1219-1323, OTP-29.1.1.
    fn insert_long(&mut self, id: u64, mut entry: Entry<M>) {
        self.next_timeout = None;
        let node = self.high_level.insert_node(entry.deadline);
        let tail = self.high_level.node(node).tail;
        entry.kind = WheelKind::HighLevel;
        entry.slot = 0;
        entry.tree_node = node;
        entry.tree_prev = tail;
        entry.tree_next = 0;
        if tail == 0 {
            self.high_level.node_mut(node).head = id;
        } else {
            self.entries
                .get_mut(&tail)
                .expect("tree tail has entry")
                .tree_next = id;
        }
        self.high_level.node_mut(node).tail = id;
        self.entries.insert(id, entry);
    }

    // Port of erts/emulator/beam/erl_hl_timer.c:2661-2695, OTP-29.1.1.
    pub(crate) fn insert(&mut self, id: u64, deadline: u64, payload: TimerPayload<M>) {
        // Port of erts/emulator/beam/erl_hl_timer.c:1838 (setup_bif_timer), OTP-29.1.1: a timer
        // started for a process whose timers are paused is created paused.
        if let TimerPayload::Message(target, _, _) = &payload
            && let Some(held) = self.paused.get_mut(target)
        {
            held.push((deadline.saturating_sub(self.now), payload));
            return;
        }
        let order = self.next_order;
        self.next_order = self.next_order.wrapping_add(1);
        if let TimerPayload::Message(target, _, _) = &payload {
            self.target_entries.entry(*target).or_default().insert(id);
        }
        let entry = Entry {
            deadline,
            order,
            kind: WheelKind::AtOnce,
            slot: SLOT_AT_ONCE,
            position: 0,
            tree_node: NIL,
            tree_prev: 0,
            tree_next: 0,
            state: AtomicU8::new(TIMER_PENDING),
            payload,
        };
        self.place(id, entry);
    }

    // Port of erts/emulator/beam/time.c:705-738, OTP-29.1.1.
    fn bucket_mut(&mut self, kind: WheelKind, slot: usize) -> Option<&mut Vec<u64>> {
        match kind {
            WheelKind::Soon => Some(&mut self.soon[slot]),
            WheelKind::Later => Some(&mut self.later[slot]),
            WheelKind::AtOnce => Some(&mut self.at_once),
            WheelKind::Pending => Some(&mut self.pending),
            WheelKind::HighLevel => None,
        }
    }

    // Port of erts/emulator/beam/time.c:705-738, OTP-29.1.1.
    fn remove_slot_entry(&mut self, entry: &Entry<M>, id: u64) {
        if let Some(bucket) = self.bucket_mut(entry.kind, entry.slot) {
            let removed = bucket.swap_remove(entry.position);
            debug_assert_eq!(removed, id);
            if let Some(&moved) = bucket.get(entry.position) {
                self.entries
                    .get_mut(&moved)
                    .expect("bucket id has entry")
                    .position = entry.position;
            }
        }
    }

    // Port of erts/emulator/beam/erl_hl_timer.c:3340-3362, OTP-29.1.1.
    fn remove_long_entry(&mut self, entry: &Entry<M>, id: u64) {
        let node = entry.tree_node;
        debug_assert_ne!(node, NIL);
        if entry.tree_prev == 0 {
            self.high_level.node_mut(node).head = entry.tree_next;
        } else {
            self.entries
                .get_mut(&entry.tree_prev)
                .expect("tree predecessor exists")
                .tree_next = entry.tree_next;
        }
        if entry.tree_next == 0 {
            self.high_level.node_mut(node).tail = entry.tree_prev;
        } else {
            self.entries
                .get_mut(&entry.tree_next)
                .expect("tree successor exists")
                .tree_prev = entry.tree_prev;
        }
        if self.high_level.node(node).head == 0 {
            debug_assert_eq!(self.high_level.node(node).tail, 0);
            self.high_level.delete(node);
        }
        let _ = id;
    }

    // Port of erts/emulator/beam/time.c:705-738 and erl_hl_timer.c:3340-3362, OTP-29.1.1.
    fn detach(&mut self, id: u64) -> Option<Entry<M>> {
        self.next_timeout = None;
        let entry = self.entries.remove(&id)?;
        if entry.kind == WheelKind::HighLevel {
            self.remove_long_entry(&entry, id);
        } else {
            self.remove_slot_entry(&entry, id);
        }
        Some(entry)
    }

    // Port of erts/emulator/beam/erl_hl_timer.c:2210-2248, OTP-29.1.1.
    #[cfg(test)]
    pub(crate) fn cancel(&mut self, id: u64) -> Option<(u64, TimerPayload<M>)> {
        self.cancel_at(id, self.now)
    }

    pub(crate) fn cancel_at(&mut self, id: u64, now: u64) -> Option<(u64, TimerPayload<M>)> {
        // Port of erts/emulator/beam/time.c:1311-1324, OTP-29.1.1.
        let entry = self.detach(id)?;
        let canceled = entry
            .state
            .compare_exchange(
                TIMER_PENDING,
                TIMER_CANCELED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok();
        self.remove_target_entry(id, &entry.payload);
        canceled.then(|| (entry.deadline.saturating_sub(now), entry.payload))
    }

    // Port of erts/emulator/beam/erl_hl_timer.c:67-68 and erl_process.c:14300-14304,
    // OTP-29.1.1. Process exit cancels all BIF timers whose destination is the exiting process.
    pub(crate) fn cancel_target(&mut self, pid: Pid) -> usize {
        // erts_destroy_paused_bif_timers (erl_hl_timer.c:2988): paused timers die with the process.
        self.paused.remove(&pid);
        let ids = self.target_entries.remove(&pid).unwrap_or_default();
        ids.into_iter()
            .filter(|id| self.cancel_at(*id, self.now).is_some())
            .count()
    }

    // Port of erts/emulator/beam/erl_hl_timer.c:2874 (erts_pause_bif_timers), OTP-29.1.1.
    pub(crate) fn pause_target(&mut self, pid: Pid, now: u64) {
        let ids = self.target_entries.remove(&pid).unwrap_or_default();
        let mut held = Vec::new();
        for id in ids {
            if let Some(timer) = self.cancel_at(id, now) {
                held.push(timer);
            }
        }
        self.paused.entry(pid).or_default().extend(held);
    }

    // Port of erts/emulator/beam/erl_hl_timer.c:2949 (erts_resume_paused_bif_timers), OTP-29.1.1:
    // each held timer is re-armed with a fresh identity and its remaining time.
    pub(crate) fn resume_target(&mut self, pid: Pid, now: u64, mut next_id: impl FnMut() -> u64) {
        for (remaining, payload) in self.paused.remove(&pid).unwrap_or_default() {
            self.insert(next_id(), now.saturating_add(remaining.max(1)), payload);
        }
    }

    fn remove_target_entry(&mut self, id: u64, payload: &TimerPayload<M>) {
        let TimerPayload::Message(target, _, _) = payload else {
            return;
        };
        if let Some(ids) = self.target_entries.get_mut(target) {
            ids.remove(&id);
            if ids.is_empty() {
                self.target_entries.remove(target);
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn remaining(&self, id: u64) -> Option<u64> {
        self.remaining_at(id, self.now)
    }

    pub(crate) fn remaining_at(&self, id: u64, now: u64) -> Option<u64> {
        // Port of erts/emulator/beam/erl_hl_timer.c:2013-2042, OTP-29.1.1.
        self.entries
            .get(&id)
            .map(|entry| entry.deadline.saturating_sub(now))
    }

    /// Earliest wheel position at which [`Wheel::advance`] has work: a due timer, a later
    /// wheel slot that moves into the soon wheel, or a long timer that cascades into the
    /// wheels. `None` when the wheel holds no timers.
    ///
    /// Port of erts/emulator/beam/time.c:477 (find_next_timeout), OTP-29.1.1: the soon wheel
    /// gives an exact timeout; the later wheel and the high-level tree give a pre-timeout.
    pub(crate) fn next_timeout(&mut self) -> Option<u64> {
        if self.entries.is_empty() {
            return None;
        }
        if !self.at_once.is_empty()
            || !self.pending.is_empty()
            || self.bump_cursor < self.bump_pending.len()
        {
            return Some(self.now);
        }
        // Removed timers only make the cached position early, never late.
        if let Some(cached) = self.next_timeout.filter(|&cached| cached > self.now) {
            return Some(cached);
        }
        let mut next = u64::MAX;
        for offset in 1..SOON_SIZE as u64 {
            let bucket = &self.soon[Self::soon_slot(self.now + offset)];
            if !bucket.is_empty() {
                next = bucket
                    .iter()
                    .filter_map(|id| self.entries.get(id))
                    .map(|entry| entry.deadline)
                    .min()
                    .unwrap_or(self.now + offset);
                break;
            }
        }
        // `advance` drains the later slot one ahead of each LATER_SLOT_SIZE boundary; the
        // slot drained at the current boundary is never refilled.
        let base = self.now & !(LATER_SLOT_SIZE - 1);
        for index in 1..SOON_SIZE as u64 {
            let boundary = base + index * LATER_SLOT_SIZE;
            if boundary >= next {
                break;
            }
            let slot = (Self::later_slot(boundary) + 1) & (SOON_SIZE - 1);
            if !self.later[slot].is_empty() {
                next = boundary;
                break;
            }
        }
        if let Some(node) = self.high_level.first_at_or_before(u64::MAX) {
            let cascade = self
                .high_level
                .node(node)
                .key
                .saturating_sub(LATER_REVOLUTION - 1);
            next = next.min(cascade);
        }
        let next = next.max(self.now + 1);
        self.next_timeout = Some(next);
        Some(next)
    }

    // Port of erts/emulator/beam/time.c:1270-1291, OTP-29.1.1.
    pub(crate) fn has_timers(&self) -> bool {
        !self.entries.is_empty()
    }

    // Port of erts/emulator/beam/erl_hl_timer.c:1219-1323, OTP-29.1.1.
    fn cascade_high_level(&mut self, work: &mut usize) {
        let limit = self.now.saturating_add(LATER_REVOLUTION - 1);
        while *work < BUMP_YIELD_LIMIT
            && let Some(node) = self.high_level.first_at_or_before(limit)
        {
            let id = self.high_level.node(node).head;
            if id == 0 {
                break;
            }
            if let Some(mut entry) = self.detach(id) {
                *work += COST_SLOT_MOVE;
                entry.kind = WheelKind::AtOnce;
                self.place(id, entry);
            }
        }
    }

    // Port of erts/emulator/beam/time.c:670-738, OTP-29.1.1.
    fn drain_slot(
        &mut self,
        kind: WheelKind,
        slot: usize,
        due: &mut Vec<(u64, u64, u64, TimerPayload<M>)>,
        work: &mut usize,
    ) {
        let ids = match kind {
            WheelKind::Soon => std::mem::take(&mut self.soon[slot]),
            WheelKind::Later => std::mem::take(&mut self.later[slot]),
            WheelKind::AtOnce => std::mem::take(&mut self.at_once),
            WheelKind::Pending => std::mem::take(&mut self.pending),
            WheelKind::HighLevel => unreachable!(),
        };
        let mut ids = ids.into_iter();
        while let Some(id) = ids.next() {
            if *work >= BUMP_YIELD_LIMIT {
                self.queue_pending(id);
                for pending in ids {
                    self.queue_pending(pending);
                }
                break;
            }
            let Some(mut entry) = self.entries.remove(&id) else {
                continue;
            };
            if entry.deadline <= self.now {
                *work += COST_TIMEOUT;
                if entry
                    .state
                    .compare_exchange(
                        TIMER_PENDING,
                        TIMER_FIRED,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    )
                    .is_ok()
                {
                    self.remove_target_entry(id, &entry.payload);
                    due.push((entry.deadline, entry.order, id, entry.payload));
                }
            } else {
                *work += COST_SLOT_MOVE;
                entry.kind = WheelKind::AtOnce;
                self.place(id, entry);
            }
            if *work >= BUMP_YIELD_LIMIT {
                for pending in ids {
                    self.queue_pending(pending);
                }
                break;
            }
        }
    }

    // Port of erts/emulator/beam/time.c:916-1000, OTP-29.1.1.
    fn queue_pending(&mut self, id: u64) {
        let position = self.pending.len();
        self.pending.push(id);
        if let Some(entry) = self.entries.get_mut(&id) {
            entry.kind = WheelKind::Pending;
            entry.position = position;
        }
    }

    // Port of erts/emulator/beam/time.c:784-1000, OTP-29.1.1.
    fn drain_fast_forward(
        &mut self,
        to: u64,
        due: &mut Vec<(u64, u64, u64, TimerPayload<M>)>,
        work: &mut usize,
    ) {
        while self.bump_cursor < self.bump_pending.len() && *work < BUMP_YIELD_LIMIT {
            let id = self.bump_pending[self.bump_cursor];
            self.bump_cursor += 1;
            let Some(entry) = self.detach(id) else {
                continue;
            };
            if entry.deadline <= to {
                *work += COST_TIMEOUT;
                if entry
                    .state
                    .compare_exchange(
                        TIMER_PENDING,
                        TIMER_FIRED,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    )
                    .is_ok()
                {
                    self.remove_target_entry(id, &entry.payload);
                    due.push((entry.deadline, entry.order, id, entry.payload));
                }
            } else {
                *work += COST_SLOT_MOVE;
                self.place(id, entry);
            }
        }
        if self.bump_cursor == self.bump_pending.len() {
            self.bump_pending.clear();
            self.bump_cursor = 0;
        }
    }

    // Port of erts/emulator/beam/time.c:784-1000, OTP-29.1.1.
    pub(crate) fn advance(&mut self, to: u64) -> Vec<(u64, TimerPayload<M>)> {
        let mut due = Vec::new();
        let mut work = 0;
        if !self.pending.is_empty() && work < BUMP_YIELD_LIMIT {
            self.drain_slot(WheelKind::Pending, 0, &mut due, &mut work);
        }
        if work >= BUMP_YIELD_LIMIT {
            due.sort_unstable_by_key(|(deadline, order, _, _)| (*deadline, *order));
            return due
                .into_iter()
                .map(|(_, _, id, payload)| (id, payload))
                .collect();
        }
        if !self.at_once.is_empty() {
            self.drain_slot(WheelKind::AtOnce, SLOT_AT_ONCE, &mut due, &mut work);
        }
        if !self.bump_pending.is_empty() {
            self.drain_fast_forward(self.now, &mut due, &mut work);
            if !self.bump_pending.is_empty() {
                due.sort_unstable_by_key(|(deadline, order, _, _)| (*deadline, *order));
                return due
                    .into_iter()
                    .map(|(_, _, id, payload)| (id, payload))
                    .collect();
            }
        }
        if to.saturating_sub(self.now) > SOON_SIZE as u64 {
            self.now = to;
            let mut timers: Vec<(u64, u64, u64)> = self
                .entries
                .iter()
                .map(|(&id, entry)| (entry.deadline, entry.order, id))
                .collect();
            timers.sort_unstable();
            self.bump_pending = timers.into_iter().map(|(_, _, id)| id).collect();
            self.bump_cursor = 0;
            self.drain_fast_forward(to, &mut due, &mut work);
            due.sort_unstable_by_key(|(deadline, order, _, _)| (*deadline, *order));
            return due
                .into_iter()
                .map(|(_, _, id, payload)| (id, payload))
                .collect();
        }
        self.cascade_high_level(&mut work);
        while self.now < to && work < BUMP_YIELD_LIMIT {
            self.now += 1;
            if self.now.is_multiple_of(LATER_SLOT_SIZE) {
                work += COST_SLOT;
                // `later.pos` is one slot ahead of the current clock position.
                let slot = (Self::later_slot(self.now) + 1) & (SOON_SIZE - 1);
                self.drain_slot(WheelKind::Later, slot, &mut due, &mut work);
            }
            work += COST_SLOT;
            let slot = Self::soon_slot(self.now);
            self.drain_slot(WheelKind::Soon, slot, &mut due, &mut work);
            if self.now.is_multiple_of(LATER_SLOT_SIZE) {
                self.cascade_high_level(&mut work);
            }
        }
        due.sort_unstable_by_key(|(deadline, order, _, _)| (*deadline, *order));
        due.into_iter()
            .map(|(_, _, id, payload)| (id, payload))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn validate_tree(tree: &TimerTree) {
        fn walk(tree: &TimerTree, node: u32, low: Option<u64>, high: Option<u64>) -> usize {
            if node == NIL {
                return 1;
            }
            let current = tree.node(node);
            assert!(low.is_none_or(|value| value < current.key));
            assert!(high.is_none_or(|value| current.key < value));
            if current.left != NIL {
                assert_eq!(tree.node(current.left).parent, node);
            }
            if current.right != NIL {
                assert_eq!(tree.node(current.right).parent, node);
            }
            if current.red {
                assert!(!tree.red(current.left) && !tree.red(current.right));
            }
            let left = walk(tree, current.left, low, Some(current.key));
            let right = walk(tree, current.right, Some(current.key), high);
            assert_eq!(left, right, "black height differs at key {}", current.key);
            left + usize::from(!current.red)
        }
        if tree.root != NIL {
            assert!(!tree.node(tree.root).red);
            assert_eq!(tree.node(tree.root).parent, NIL);
        }
        walk(tree, tree.root, None, None);
    }

    #[test]
    fn deadlines_and_cancel() {
        let pid = Pid {
            index: 0,
            generation: 0,
        };
        let mut wheel = Wheel::<u8>::new(0);
        wheel.insert(1, 1, TimerPayload::Message(pid, 1, true));
        wheel.insert(2, 257, TimerPayload::Message(pid, 2, true));
        wheel.insert(3, 65_537, TimerPayload::Message(pid, 3, true));
        assert_eq!(wheel.cancel(3).map(|x| x.0), Some(65_537));
        assert_eq!(wheel.advance(1).len(), 1);
        assert_eq!(wheel.remaining(2), Some(256));
        assert_eq!(wheel.advance(257).len(), 1);
    }

    #[test]
    fn process_exit_cancels_timers_targeting_that_process() {
        let target = Pid {
            index: 3,
            generation: 1,
        };
        let other = Pid {
            index: 4,
            generation: 1,
        };
        let mut wheel = Wheel::<u8>::new(0);
        wheel.insert(1, 10, TimerPayload::Message(target, 1, false));
        wheel.insert(2, 20, TimerPayload::Message(target, 2, true));
        wheel.insert(3, 30, TimerPayload::Message(other, 3, false));

        assert_eq!(wheel.cancel_target(target), 2);
        assert_eq!(wheel.remaining(1), None);
        assert_eq!(wheel.remaining(2), None);
        assert_eq!(wheel.remaining(3), Some(30));
    }

    #[test]
    fn rb_tree_insert_delete_fixups_preserve_invariants() {
        let mut tree = TimerTree::new();
        let mut keys: Vec<u64> = (1..=2_000).collect();
        let mut seed = 0x1234_5678_u64;
        for i in (1..keys.len()).rev() {
            seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            keys.swap(i, seed as usize % (i + 1));
        }
        for key in &keys {
            tree.insert_node(*key);
            validate_tree(&tree);
        }
        for key in keys {
            let node = tree.first_at_or_before(key).unwrap();
            let found = if tree.node(node).key == key {
                node
            } else {
                let mut cursor = tree.root;
                while cursor != NIL && tree.node(cursor).key != key {
                    cursor = if key < tree.node(cursor).key {
                        tree.left(cursor)
                    } else {
                        tree.right(cursor)
                    };
                }
                cursor
            };
            assert_ne!(found, NIL);
            tree.delete(found);
            validate_tree(&tree);
        }
        assert_eq!(tree.root, NIL);
    }

    #[test]
    fn same_deadline_long_timers_keep_insertion_order_after_cancel() {
        let pid = Pid {
            index: 0,
            generation: 0,
        };
        let mut wheel = Wheel::<u8>::new(0);
        let deadline = LATER_REVOLUTION + 100;
        for id in 1..=3 {
            wheel.insert(id, deadline, TimerPayload::Message(pid, id as u8, true));
        }
        assert_eq!(wheel.cancel(2).map(|timer| timer.0), Some(deadline));
        let due = wheel.advance(deadline);
        let ids: Vec<_> = due.into_iter().map(|(id, _)| id).collect();
        assert_eq!(ids, [1, 3]);
    }

    #[test]
    fn later_slot_cascades_when_soon_window_reaches_it() {
        let pid = Pid {
            index: 0,
            generation: 0,
        };
        let mut wheel = Wheel::<u8>::new(0);
        let deadline = 17_000;
        wheel.insert(1, deadline, TimerPayload::Message(pid, 1, true));
        assert_eq!(wheel.entries.get(&1).unwrap().kind, WheelKind::Later);
        assert!(wheel.advance(LATER_SLOT_SIZE).is_empty());
        assert_eq!(wheel.entries.get(&1).unwrap().kind, WheelKind::Soon);
    }

    #[test]
    fn bump_resumes_large_fast_forward_after_limit() {
        let pid = Pid {
            index: 0,
            generation: 0,
        };
        let mut wheel = Wheel::<u8>::new(0);
        let deadline = SOON_SIZE as u64 + 123;
        for id in 1..=20_050 {
            wheel.insert(id, deadline, TimerPayload::Message(pid, 1, true));
        }
        let first = wheel.advance(deadline);
        let second = wheel.advance(deadline);
        assert_eq!(first.len(), BUMP_YIELD_LIMIT / COST_TIMEOUT);
        assert_eq!(second.len(), BUMP_YIELD_LIMIT / COST_TIMEOUT);
        assert_eq!(first.first().map(|timer| timer.0), Some(1));
        let mut total = first.len() + second.len();
        let mut last = Vec::new();
        while total < 20_050 {
            last = wheel.advance(deadline);
            assert!(!last.is_empty());
            total += last.len();
        }
        assert_eq!(total, 20_050);
        assert_eq!(last.len(), 50);
        assert_eq!(last.last().map(|timer| timer.0), Some(20_050));
    }
}
