//! The scheduler's timer service on top of its timer wheel.
//!
//! Port of erts/emulator/beam/erl_hl_timer.c (the timer service: `ErtsHLTimerService` with its
//! wheel timers, the time tree of timers too far ahead for the wheel and the service timer that
//! fires the earliest of them), OTP-29.1.1. The wheel itself is [`crate::twheel`] (time.c).

use std::any::Any;
use std::pin::Pin;
use std::sync::Arc;

use crate::twheel::{TIMER_WHEEL_MSEC, TWheelTimer, TimerWheel};

use crate::Pid;

const NIL: u32 = u32::MAX;

struct TreeNode {
    key: u64,
    parent: u32,
    left: u32,
    right: u32,
    red: bool,
    head: u32,
    tail: u32,
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
            head: NIL,
            tail: NIL,
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

    fn find(&self, key: u64) -> Option<u32> {
        let mut cursor = self.root;
        while cursor != NIL {
            let node = self.node(cursor);
            match key.cmp(&node.key) {
                std::cmp::Ordering::Less => cursor = node.left,
                std::cmp::Ordering::Greater => cursor = node.right,
                std::cmp::Ordering::Equal => return Some(cursor),
            }
        }
        None
    }
}

/// Marks a timer id taken from an Erlang reference key, apart from the sequential ids.
pub(crate) const REF_KEY_TIMER_BIT: u64 = 1 << 63;

/// Reference returned by a timer operation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct TimerRef {
    pub(crate) worker: usize,
    pub(crate) id: u64,
}

impl TimerRef {
    /// The reference as one word (worker in the top 16 bits, timer id below), for owners that
    /// keep it outside this crate.
    pub fn to_bits(self) -> u64 {
        ((self.worker as u64) << 48) | (self.id & ((1 << 48) - 1))
    }

    /// Inverse of [`TimerRef::to_bits`].
    pub fn from_bits(bits: u64) -> Self {
        Self {
            worker: (bits >> 48) as usize,
            id: bits & ((1 << 48) - 1),
        }
    }

    /// One-based scheduler that owns this timer's wheel.
    pub fn worker_id(self) -> usize {
        self.worker + 1
    }

    /// Stable numeric identity for the VM's reference representation.
    pub fn id(self) -> u64 {
        self.id
    }

    /// The reference key a BIF timer was started with, `None` for other timers.
    pub fn ref_key(self) -> Option<u64> {
        self.timer_id().ref_key()
    }

    /// The timer's identity without its owning wheel.
    pub fn timer_id(self) -> TimerId {
        TimerId(self.id)
    }

    /// The timer a reference key names: its wheel is the scheduler whose thread id the key
    /// carries, so no table maps references to timers.
    // Port of erts/emulator/beam/erl_hl_timer.c:2237 (access_bif_timer): the scheduler is
    // found through erts_get_ref_numbers_thr_id, OTP-29.1.1. `workers` is the scheduler count;
    // keys made on other threads (dirty schedulers) are spread by their counter.
    pub fn from_ref_key(key: u64, workers: usize) -> TimerRef {
        let thr_id = (key >> 48) as usize;
        let worker = if (1..=workers).contains(&thr_id) {
            thr_id - 1
        } else {
            (key & ((1 << 48) - 1)) as usize % workers
        };
        TimerRef {
            worker,
            id: key | REF_KEY_TIMER_BIT,
        }
    }
}

/// A fired timer as its timeout event names it: the timer id without the owning wheel, which
/// only a cancel or a read of a running timer needs. One word, so a queued timeout event is no
/// wider than a monitor DOWN signal.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct TimerId(pub(crate) u64);

impl TimerId {
    /// Stable numeric identity for the VM's reference representation.
    pub fn id(self) -> u64 {
        self.0
    }

    /// The reference key a BIF timer was started with, `None` for other timers.
    pub fn ref_key(self) -> Option<u64> {
        (self.0 & REF_KEY_TIMER_BIT != 0).then_some(self.0 & !REF_KEY_TIMER_BIT)
    }
}

fn payload_message<M>(payload: &TimerPayload<M>) -> Option<&M> {
    match payload {
        TimerPayload::Message(_, message, _) | TimerPayload::ResolvedMessage(_, message, _) => {
            Some(message)
        }
        _ => None,
    }
}

/// A change of a receiver's bif-timer tree (`p->bif_timers`, erl_hl_timer.c).
pub(crate) enum LinkEvent<M> {
    Link(Pid, u64),
    Unlink(Pid, u64),
    /// A timer taken off the wheel for a suspended receiver, with the time it had left.
    Stash(Pid, u64, TimerPayload<M>),
}

/// Work emitted when a timer expires.
pub(crate) enum TimerPayload<M> {
    Message(Pid, M, bool),
    ResolvedMessage(Arc<dyn Fn() -> Option<Pid> + Send + Sync>, M, bool),
    Wake(Pid),
    /// Runtime callback owned by a process (erts `erts_start_timer_callback`).
    Callback(Pid, crate::TimerCallback<M>),
    /// A port timer (`erts_set_port_timer`): the callback queues the port's timeout task.
    Port(Box<dyn FnOnce() + Send>),
}

pub(crate) enum TimerCommand<M> {
    Insert {
        id: u64,
        deadline: u64,
        payload: TimerPayload<M>,
    },
    Read {
        id: u64,
        callback: Box<dyn FnOnce(Option<u64>) + Send>,
    },
    Cancel {
        id: u64,
        callback: Box<dyn FnOnce(Option<u64>) + Send>,
    },
    /// Cancel the timers of `ids` (this wheel's entries of the receiver's bif-timer tree).
    CancelTarget { ids: Vec<u64> },
    /// Hold the BIF timers aimed at `pid` (a suspended process).
    PauseTarget { pid: Pid, ids: Vec<u64> },
}

/// A receive timeout cancelled by another thread (erts canceled-timer queue).
pub(crate) struct CanceledTimer {
    pub(crate) id: u64,
}

/// One timer of the service (`ErtsTWTimer` / `ErtsHLTimer` with its payload): a wheel timer
/// for timeouts within [`TIMER_WHEEL_MSEC`], a time-tree entry for later ones.
struct Entry<M> {
    /// `u.tw_tmr`; boxed so the slab may grow while the wheel links it.
    tw: Pin<Box<TWheelTimer>>,
    id: u64,
    deadline: u64,
    /// In the time tree (`ERTS_TMR_ROFLG_HLT`) rather than the wheel.
    hlt: bool,
    tree_node: u32,
    tree_prev: u32,
    tree_next: u32,
    /// `None` while the slab entry is free.
    payload: Option<TimerPayload<M>>,
}

/// The `arg` of the service timer (`srv->service_timer`); timer slab indices are below it.
const SERVICE_TIMER_ARG: usize = u32::MAX as usize;

/// Timeouts the wheel triggered during one bump, in trigger order: slab indices, or
/// [`SERVICE_TIMER_ARG`] for the service timer.
struct Triggered(Vec<usize>);

// Port of erts/emulator/beam/erl_hl_timer.c (tw_proc_timeout, tw_bif_timer_timeout,
// tw_callback_timeout, hlt_service_timeout), OTP-29.1.1: the wheel hands the timeout to the
// service, which runs it once the bump returns.
fn timer_timeout(_wheel: &mut TimerWheel, esdp: &mut dyn Any, arg: *mut ()) {
    esdp.downcast_mut::<Triggered>()
        .expect("timer service bump context")
        .0
        .push(arg.addr());
}

/// The timer service of one scheduler (`ErtsHLTimerService`) with its timer wheel
/// (`esdp->timer_wheel`). The scheduler serializes requests from other threads into it.
pub(crate) struct Wheel<M> {
    /// Declared first: dropping the wheel unlinks the timers before the entries go.
    tw: TimerWheel,
    /// `srv->service_timer`: set at the earliest time-tree timeout.
    service_timer: Pin<Box<TWheelTimer>>,
    /// `srv->time_tree`: timers too far ahead for the wheel.
    high_level: TimerTree,
    /// `srv->btm_tree` generalised to every timer id.
    id_index: TimerTree,
    /// Timer structures (`tw_timer` / `bif_timer_pre` pre-allocators): reused, never freed.
    entries: Vec<Entry<M>>,
    free_entries: Vec<u32>,
    entry_count: usize,
    triggered: Triggered,
    /// The time of the latest bump; timeouts are measured from it to pick wheel or tree.
    now: u64,
    /// Link and unlink events for the receivers' bif-timer trees, applied by the scheduler
    /// after each operation (the service itself does not see processes).
    link_events: std::collections::VecDeque<LinkEvent<M>>,
    /// The scheduler that owns this service; it is the value of the receivers' tree entries.
    worker: usize,
}

impl<M> Wheel<M> {
    // Port of erts/emulator/beam/erl_hl_timer.c (erts_create_timer_service) and time.c
    // (erts_create_timer_wheel), OTP-29.1.1. Created on the scheduler's own thread, as
    // erts_sched_init_time_sup does.
    pub(crate) fn new(now: u64) -> Self {
        Self {
            tw: TimerWheel::new(now as i64),
            service_timer: Box::pin(TWheelTimer::new()),
            high_level: TimerTree::new(),
            id_index: TimerTree::new(),
            entries: Vec::new(),
            free_entries: Vec::new(),
            entry_count: 0,
            triggered: Triggered(Vec::new()),
            now,
            link_events: std::collections::VecDeque::new(),
            worker: 0,
        }
    }

    pub(crate) fn for_worker(mut self, worker: usize) -> Self {
        self.worker = worker;
        self
    }

    pub(crate) fn worker(&self) -> usize {
        self.worker
    }

    fn index_for_id(&self, id: u64) -> Option<u32> {
        let node = self.id_index.find(id)?;
        Some(self.id_index.node(node).head)
    }

    // Port of erts/emulator/beam/erl_hl_timer.c (create_tw_timer, create_hl_timer), OTP-29.1.1:
    // a timeout below ERTS_TIMER_WHEEL_MSEC goes into the wheel, a later one into the time tree.
    pub(crate) fn insert(&mut self, id: u64, deadline: u64, payload: TimerPayload<M>) {
        if let TimerPayload::Message(target, _, _) = &payload {
            self.link_events.push_back(LinkEvent::Link(*target, id));
        }
        let index = match self.free_entries.pop() {
            Some(index) => index,
            None => {
                let index = u32::try_from(self.entries.len()).expect("timer slab index overflow");
                self.entries.push(Entry {
                    tw: Box::pin(TWheelTimer::new()),
                    id: 0,
                    deadline: 0,
                    hlt: false,
                    tree_node: NIL,
                    tree_prev: NIL,
                    tree_next: NIL,
                    payload: None,
                });
                index
            }
        };
        let hlt = deadline.saturating_sub(self.now) >= TIMER_WHEEL_MSEC as u64;
        {
            let entry = &mut self.entries[index as usize];
            entry.id = id;
            entry.deadline = deadline;
            entry.hlt = hlt;
            entry.payload = Some(payload);
        }
        let id_node = self.id_index.insert_node(id);
        assert_eq!(self.id_index.node(id_node).head, NIL, "duplicate timer id");
        self.id_index.node_mut(id_node).head = index;
        self.id_index.node_mut(id_node).tail = index;
        self.entry_count += 1;
        if hlt {
            self.insert_hl_timer(index);
        } else {
            let pos = deadline.min(i64::MAX as u64) as i64;
            self.tw.set_timer(
                self.entries[index as usize].tw.as_ref(),
                timer_timeout,
                std::ptr::without_provenance_mut(index as usize),
                pos,
            );
        }
    }

    // Port of erts/emulator/beam/erl_hl_timer.c (insert_hl_timer: same-time timers are kept in
    // insertion order; the service timer moves when the timer becomes the earliest), OTP-29.1.1.
    fn insert_hl_timer(&mut self, index: u32) {
        let deadline = self.entries[index as usize].deadline;
        let node = self.high_level.insert_node(deadline);
        let tail = self.high_level.node(node).tail;
        {
            let entry = &mut self.entries[index as usize];
            entry.tree_node = node;
            entry.tree_prev = tail;
            entry.tree_next = NIL;
        }
        if tail == NIL {
            self.high_level.node_mut(node).head = index;
        } else {
            self.entries[tail as usize].tree_next = index;
        }
        self.high_level.node_mut(node).tail = index;
        self.set_service_timer();
    }

    // Port of erts/emulator/beam/erl_hl_timer.c (hlt_delete_timer), OTP-29.1.1.
    fn remove_hl_timer(&mut self, index: u32) {
        let (node, prev, next) = {
            let entry = &self.entries[index as usize];
            (entry.tree_node, entry.tree_prev, entry.tree_next)
        };
        if prev == NIL {
            self.high_level.node_mut(node).head = next;
        } else {
            self.entries[prev as usize].tree_next = next;
        }
        if next == NIL {
            self.high_level.node_mut(node).tail = prev;
        } else {
            self.entries[next as usize].tree_prev = prev;
        }
        if self.high_level.node(node).head == NIL {
            self.high_level.delete(node);
        }
        let entry = &mut self.entries[index as usize];
        entry.tree_node = NIL;
        entry.tree_prev = NIL;
        entry.tree_next = NIL;
    }

    /// Sets the service timer at the earliest time-tree timeout (`srv->next_timeout`).
    fn set_service_timer(&mut self) {
        let first = self
            .high_level
            .first_at_or_before(u64::MAX)
            .map(|node| self.high_level.node(node).key);
        let current = self
            .service_timer
            .is_active()
            .then(|| self.service_timer.read_timeout());
        let wanted = first.map(|key| key.min(i64::MAX as u64) as i64);
        if current == wanted {
            return;
        }
        self.tw.cancel_timer(self.service_timer.as_ref());
        if let Some(pos) = wanted {
            self.tw.set_timer(
                self.service_timer.as_ref(),
                timer_timeout,
                std::ptr::without_provenance_mut(SERVICE_TIMER_ARG),
                pos,
            );
        }
    }

    /// Unlinks the timer of `index` from the wheel or the time tree and frees its entry.
    fn take(&mut self, index: u32) -> (u64, u64, TimerPayload<M>) {
        if self.entries[index as usize].hlt {
            self.remove_hl_timer(index);
            self.set_service_timer();
        } else {
            self.tw
                .cancel_timer(self.entries[index as usize].tw.as_ref());
        }
        self.free(index)
    }

    fn free(&mut self, index: u32) -> (u64, u64, TimerPayload<M>) {
        let entry = &mut self.entries[index as usize];
        let payload = entry.payload.take().expect("live timer slab entry");
        let (id, deadline) = (entry.id, entry.deadline);
        let tree = self.id_index.find(id).expect("timer id index");
        self.id_index.delete(tree);
        self.free_entries.push(index);
        self.entry_count -= 1;
        (id, deadline, payload)
    }

    // Port of erts/emulator/beam/erl_hl_timer.c:2210-2248, OTP-29.1.1.
    #[cfg(test)]
    pub(crate) fn cancel(&mut self, id: u64) -> Option<(u64, TimerPayload<M>)> {
        self.cancel_at(id, self.now)
    }

    // Port of erts/emulator/beam/erl_hl_timer.c (cancel_bif_timer, cancel_proc_timer),
    // OTP-29.1.1: a timer still set is removed and its time left returned.
    pub(crate) fn cancel_at(&mut self, id: u64, now: u64) -> Option<(u64, TimerPayload<M>)> {
        let index = self.index_for_id(id)?;
        let (_, deadline, payload) = self.take(index);
        self.remove_target_entry(id, &payload);
        Some((deadline.saturating_sub(now), payload))
    }

    // Port of erts/emulator/beam/erl_hl_timer.c:67-68 and erl_process.c:14300-14304,
    // OTP-29.1.1. Process exit cancels all BIF timers whose destination is the exiting process;
    // `ids` are the timers of this wheel in the receiver's bif-timer tree.
    pub(crate) fn cancel_target(&mut self, ids: &[u64]) -> usize {
        ids.iter()
            .filter(|id| self.cancel_at(**id, self.now).is_some())
            .count()
    }

    // Port of erts/emulator/beam/erl_hl_timer.c:2874 (erts_pause_bif_timers), OTP-29.1.1: each
    // timer leaves the service and is stored, with the time it had left, in the receiver's
    // paused list (create_paused_bif_timer + access_btm cancel).
    pub(crate) fn pause_target(&mut self, pid: Pid, ids: &[u64], now: u64) {
        for id in ids {
            if let Some((remaining, payload)) = self.cancel_at(*id, now) {
                self.link_events
                    .push_back(LinkEvent::Stash(pid, remaining, payload));
            }
        }
    }

    /// Messages of the BIF timers (`send_after`, `start_timer`) of this service, for the
    /// debug node-reference accounting.
    pub(crate) fn bif_timer_messages(&self) -> Vec<&M> {
        self.entries
            .iter()
            .filter(|entry| entry.id & REF_KEY_TIMER_BIT != 0)
            .filter_map(|entry| entry.payload.as_ref().and_then(payload_message))
            .collect()
    }

    fn remove_target_entry(&mut self, id: u64, payload: &TimerPayload<M>) {
        if let TimerPayload::Message(target, _, _) = payload {
            self.link_events.push_back(LinkEvent::Unlink(*target, id));
        }
    }

    /// The oldest unapplied link change; the queue keeps its capacity, so creating a timer
    /// does not allocate for it.
    pub(crate) fn pop_link_event(&mut self) -> Option<LinkEvent<M>> {
        self.link_events.pop_front()
    }

    /// Receiver-tree changes recorded since the last [`Wheel::pop_link_event`] drain.
    #[inline]
    pub(crate) fn has_link_events(&self) -> bool {
        !self.link_events.is_empty()
    }

    #[cfg(test)]
    pub(crate) fn remaining(&self, id: u64) -> Option<u64> {
        self.remaining_at(id, self.now)
    }

    pub(crate) fn remaining_at(&self, id: u64, now: u64) -> Option<u64> {
        // Port of erts/emulator/beam/erl_hl_timer.c:2013-2042, OTP-29.1.1.
        self.index_for_id(id)
            .map(|index| self.entries[index as usize].deadline.saturating_sub(now))
    }

    pub(crate) fn has_timers(&self) -> bool {
        self.entry_count != 0
    }

    /// The cached next timeout time (`erts_next_timeout_time(esdp->next_tmo_ref)`): the
    /// scheduler bumps the timers once its time reaches it.
    #[inline]
    pub(crate) fn next_timeout_time(&self) -> u64 {
        self.tw.next_timeout_time().max(0) as u64
    }

    /// Port of erts/emulator/beam/time.c (erts_check_next_timeout_time), OTP-29.1.1.
    pub(crate) fn check_next_timeout_time(&mut self, now: impl FnOnce() -> u64) -> u64 {
        self.tw
            .check_next_timeout_time(|| now().min(i64::MAX as u64) as i64)
            .max(0) as u64
    }

    /// Port of erts/emulator/beam/time.c (erts_bump_timers) with the service's timeout
    /// callbacks, OTP-29.1.1: the timers due at `now` in trigger order. A bump that reached
    /// its yield limit leaves the next timeout time at `now`, so the scheduler bumps again.
    pub(crate) fn bump_timers(&mut self, now: u64) -> Vec<(u64, TimerPayload<M>)> {
        let mut due = Vec::new();
        self.now = self.now.max(now);
        let mut triggered = std::mem::replace(&mut self.triggered, Triggered(Vec::new()));
        self.tw
            .bump_timers(now.min(i64::MAX as u64) as i64, &mut triggered);
        for arg in triggered.0.drain(..) {
            if arg == SERVICE_TIMER_ARG {
                self.hlt_service_timeout(now, &mut due);
            } else {
                let (id, _, payload) = self.free(arg as u32);
                self.remove_target_entry(id, &payload);
                due.push((id, payload));
            }
        }
        self.triggered = triggered;
        due
    }

    // Port of erts/emulator/beam/erl_hl_timer.c (hlt_service_timeout), OTP-29.1.1: every
    // time-tree timer due at `now` times out in timeout order; the service timer moves to the
    // next one.
    fn hlt_service_timeout(&mut self, now: u64, due: &mut Vec<(u64, TimerPayload<M>)>) {
        while let Some(node) = self.high_level.first_at_or_before(now) {
            let index = self.high_level.node(node).head;
            self.remove_hl_timer(index);
            let (id, _, payload) = self.free(index);
            self.remove_target_entry(id, &payload);
            due.push((id, payload));
        }
        self.set_service_timer();
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

    fn bump(wheel: &mut Wheel<u8>, now: u64) -> Vec<u64> {
        let mut ids = Vec::new();
        loop {
            let due = wheel.bump_timers(now);
            ids.extend(due.into_iter().map(|(id, _)| id));
            if wheel.next_timeout_time() > now || !wheel.has_timers() {
                return ids;
            }
        }
    }

    #[test]
    fn deadlines_and_cancel() {
        let pid = Pid::new(0, 0);
        let mut wheel = Wheel::<u8>::new(0);
        wheel.insert(1, 1, TimerPayload::Message(pid, 1, true));
        wheel.insert(2, 257, TimerPayload::Message(pid, 2, true));
        wheel.insert(3, 65_537, TimerPayload::Message(pid, 3, true));
        assert_eq!(wheel.cancel(3).map(|x| x.0), Some(65_537));
        assert_eq!(bump(&mut wheel, 1), [1]);
        assert_eq!(wheel.remaining(2), Some(256));
        assert_eq!(bump(&mut wheel, 256), Vec::<u64>::new());
        assert_eq!(bump(&mut wheel, 257), [2]);
    }

    #[test]
    fn process_exit_cancels_timers_targeting_that_process() {
        let target = Pid::new(3, 1);
        let other = Pid::new(4, 1);
        let mut wheel = Wheel::<u8>::new(0);
        wheel.insert(1, 10, TimerPayload::Message(target, 1, false));
        wheel.insert(2, 20, TimerPayload::Message(target, 2, true));
        wheel.insert(3, 30, TimerPayload::Message(other, 3, false));

        assert_eq!(wheel.cancel_target(&[1, 2]), 2);
        assert_eq!(wheel.remaining(1), None);
        assert_eq!(wheel.remaining(2), None);
        assert_eq!(wheel.remaining(3), Some(30));
    }

    #[test]
    fn time_tree_timers_fire_through_the_service_timer_in_order() {
        let pid = Pid::new(0, 0);
        let mut wheel = Wheel::<u8>::new(0);
        let deadline = TIMER_WHEEL_MSEC as u64 + 100;
        for id in 1..=3 {
            wheel.insert(id, deadline, TimerPayload::Message(pid, id as u8, true));
        }
        wheel.insert(4, deadline + 5, TimerPayload::Message(pid, 4, true));
        wheel.insert(5, 50, TimerPayload::Message(pid, 5, true));
        assert!(wheel.entries.iter().filter(|entry| entry.hlt).count() == 4);
        assert_eq!(wheel.cancel(2).map(|timer| timer.0), Some(deadline));
        assert_eq!(bump(&mut wheel, 50), [5]);
        assert!(wheel.check_next_timeout_time(|| 50) <= deadline);
        assert_eq!(bump(&mut wheel, deadline - 1), Vec::<u64>::new());
        assert_eq!(bump(&mut wheel, deadline), [1, 3]);
        assert_eq!(wheel.remaining(4), Some(5));
        assert_eq!(bump(&mut wheel, deadline + 5), [4]);
        assert!(!wheel.has_timers());
        assert!(!wheel.service_timer.is_active());
    }

    #[test]
    fn a_large_bump_yields_and_continues_in_order() {
        let pid = Pid::new(0, 0);
        let mut wheel = Wheel::<u8>::new(0);
        let deadline = 16_384 + 123;
        for id in 1..=20_050 {
            wheel.insert(id, deadline, TimerPayload::Message(pid, 1, true));
        }
        let first = wheel.bump_timers(deadline);
        assert!(first.len() < 20_050);
        assert!(wheel.next_timeout_time() <= deadline);
        let mut ids: Vec<u64> = first.into_iter().map(|(id, _)| id).collect();
        ids.extend(bump(&mut wheel, deadline));
        assert_eq!(ids, (1..=20_050).collect::<Vec<_>>());
    }

    #[test]
    fn slab_entries_are_reused_after_timeout_and_cancel() {
        let pid = Pid::new(0, 0);
        let mut wheel = Wheel::<u8>::new(0);
        for round in 0..10u64 {
            for id in 0..100 {
                let id = round * 1000 + id;
                wheel.insert(id, round * 10 + 5, TimerPayload::Message(pid, 0, true));
            }
            for id in 0..50 {
                wheel.cancel(round * 1000 + id);
            }
            assert_eq!(bump(&mut wheel, round * 10 + 5).len(), 50);
        }
        assert_eq!(wheel.entries.len(), 100);
        assert!(!wheel.has_timers());
    }
}
