//! The delayed-dealloc queue of an allocator instance, over the freed blocks themselves.
//!
//! Port of `ddq_enqueue`, `ddq_managed_thread_enqueue`, `ddq_dequeue`, `ddq_check_incoming`,
//! `check_insert_marker` and `init_dd_queue` in erts/emulator/beam/erl_alloc_util.c, OTP-29.1.1.
//! A block another thread frees becomes a node of the owner's queue: word 0 is the atomic `next`
//! link, word 1 is [`DdBlock`]'s `type`/`flags` word. Producers append with one CAS on the last
//! node; the owner reads the queue only up to `unref_end`, which moves forward once no producer
//! can still hold a pointer to a node before it (the unmanaged-thread reference counters
//! `um_refc` and thread progress for managed threads).
//!
//! This is the module that owns the raw memory access of the queue, so callers stay safe: a
//! node is named by the payload address of a block the caller owns and has just freed.

use crate::sspa::ProgressOps;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering, fence};

const NULL: usize = 0;

/// Smallest payload that can hold a queue node (`sizeof(ErtsAllctrDDBlock_t)`).
#[cfg(test)]
pub(crate) const NODE_BYTES: usize = 2 * std::mem::size_of::<usize>();

/// `ErtsAllctrDDBlock_t`: the first two words of a queued block's payload.
#[repr(C)]
struct DdBlock {
    next: AtomicUsize,
    info: AtomicUsize,
}

/// The enqueue side of the queue (`ErtsDDTail_t`), written by every thread that frees a block of
/// the instance. Aligned apart from the head like the cache-line aligned union in erts.
#[repr(C, align(128))]
pub(crate) struct DdTail {
    marker: DdBlock,
    last: AtomicUsize,
    um_refc: [AtomicUsize; 2],
    um_refc_ix: AtomicU32,
    /// Blocks enqueued minus blocks dequeued, for tests.
    #[cfg(test)]
    queued: AtomicUsize,
}

/// The dequeue side (`ErtsAllctrDDQueue_t.head`), owned by whoever holds the instance.
pub(crate) struct DdHead {
    first: usize,
    unref_end: usize,
    next_thr_progress: u64,
    next_thr_progress_reached: bool,
    next_um_refc_ix: usize,
    next_unref_end: usize,
    used_marker: bool,
}

/// What a pass over the queue found out, for the owner's aux work.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DdStatus {
    /// A block waits behind the limit of the pass (`need_more_work`).
    pub more_work: bool,
    /// Blocks wait for thread progress (`need_thr_progress`).
    pub need_thr_progress: bool,
}

impl DdTail {
    pub(crate) fn new() -> Self {
        Self {
            marker: DdBlock {
                next: AtomicUsize::new(NULL),
                info: AtomicUsize::new(0),
            },
            last: AtomicUsize::new(NULL),
            um_refc: [AtomicUsize::new(0), AtomicUsize::new(0)],
            um_refc_ix: AtomicU32::new(0),
            #[cfg(test)]
            queued: AtomicUsize::new(0),
        }
    }

    /// Blocks in the queue, markers excluded; counted in test builds only.
    #[cfg(test)]
    pub(crate) fn queued(&self) -> usize {
        self.queued.load(Ordering::Relaxed)
    }

    /// Port of `init_dd_queue` (tail half): the queue holds only its marker. The tail must not
    /// move afterwards, as the marker's address is the queue's empty value.
    pub(crate) fn init(&self) {
        self.last.store(self.marker_address(), Ordering::Relaxed);
    }

    fn marker_address(&self) -> usize {
        std::ptr::addr_of!(self.marker) as usize
    }

    /// Whether the owner has anything to look at: the negation of the early exit of
    /// `ddq_check_incoming` ("nothing more to do") plus blocks it can dequeue.
    #[inline(always)]
    pub(crate) fn pending(&self, head: &DdHead) -> bool {
        let marker = self.marker_address();
        head.first != head.unref_end
            || self.last.load(Ordering::Relaxed) != marker
            || head.first != marker
    }

    /// Port of `ddq_enqueue`: appends the block whose payload starts at `node`, which the caller
    /// owns and just freed, and returns whether it went to the end of the queue (then the
    /// caller notifies the owner). `info` is stored in the node's second word.
    pub(crate) fn enqueue(
        &self,
        node: usize,
        info: usize,
        cinit: usize,
        progress: &ProgressOps,
    ) -> bool {
        debug_assert!(node.is_multiple_of(std::mem::align_of::<DdBlock>()));
        let managed = (progress.is_managed)();
        let mut um_refc_ix = 0;
        if !managed {
            um_refc_ix = self.um_refc_ix.load(Ordering::Acquire) as usize;
            loop {
                self.um_refc[um_refc_ix].fetch_add(1, Ordering::Acquire);
                let current = self.um_refc_ix.load(Ordering::Acquire) as usize;
                if current == um_refc_ix {
                    break;
                }
                self.um_refc[um_refc_ix].fetch_sub(1, Ordering::Release);
                um_refc_ix = current;
            }
        }
        #[cfg(test)]
        self.queued.fetch_add(1, Ordering::Relaxed);
        // SAFETY: `node` is the payload of a block this caller owns (its contract), at least
        // `NODE_BYTES` long and word aligned.
        let last_elem = unsafe { self.managed_thread_enqueue(node, info, cinit) };
        if !managed {
            self.um_refc[um_refc_ix].fetch_sub(1, Ordering::Release);
        }
        last_elem
    }

    /// Port of `ddq_managed_thread_enqueue`.
    ///
    /// # Safety
    ///
    /// `this` is the exclusively owned payload of a block of at least `NODE_BYTES`, and every
    /// node reachable from `last` is either the marker or a queued block that stays allocated
    /// until the owner dequeues it past `unref_end`, which cannot happen while the calling
    /// thread is counted in `um_refc` or has not passed a thread progress point.
    #[allow(unsafe_code)]
    unsafe fn managed_thread_enqueue(&self, this: usize, info: usize, cinit: usize) -> bool {
        // SAFETY: see the function contract.
        let block = unsafe { node_ref(this) };
        block.next.store(NULL, Ordering::Relaxed);
        block.info.store(info, Ordering::Relaxed);
        // Enqueue at end of list...
        let mut enq = self.last.load(Ordering::Relaxed);
        // SAFETY: `enq` was `last`, so it is the marker or a node not yet released (see above).
        let first_try = unsafe { node_ref(enq) }.next.compare_exchange(
            NULL,
            this,
            Ordering::Release,
            Ordering::Relaxed,
        );
        let mut itmp = match first_try {
            Ok(_) => {
                // We are required to move last pointer.
                self.last.store(this, Ordering::Release);
                return true;
            }
            Err(itmp) => itmp,
        };
        // We *need* to insert the element somewhere in between the last element we read
        // earlier and the actual last element.
        let mut i = cinit;
        loop {
            block.next.store(itmp, Ordering::Relaxed);
            // SAFETY: `enq` is a node reached from `last` through `next` links (see above).
            let itmp2 = match unsafe { node_ref(enq) }.next.compare_exchange(
                itmp,
                this,
                Ordering::Release,
                Ordering::Relaxed,
            ) {
                Ok(_) => return false, // inserted this
                Err(itmp2) => itmp2,
            };
            if i & 1 == 0 {
                itmp = itmp2;
            } else {
                enq = itmp2;
                // SAFETY: as above, `itmp2` was linked from a live node.
                itmp = unsafe { node_ref(enq) }.next.load(Ordering::Acquire);
                debug_assert_ne!(itmp, NULL);
            }
            i = i.wrapping_add(1);
        }
    }
}

impl DdHead {
    /// Port of `init_dd_queue` (head half) for the queue whose tail is `tail`.
    pub(crate) fn new(tail: &DdTail, progress: &ProgressOps) -> Self {
        let marker = tail.marker_address();
        Self {
            first: marker,
            unref_end: marker,
            next_thr_progress: (progress.current)(0),
            next_thr_progress_reached: true,
            next_um_refc_ix: 1,
            next_unref_end: marker,
            used_marker: true,
        }
    }

    /// Whether blocks wait before `unref_end` (`ddq->head.first != ddq->head.unref_end`).
    pub(crate) fn has_dequeueable(&self) -> bool {
        self.first != self.unref_end
    }

    /// Port of `ddq_dequeue`: the payload address of the next block that no producer can still
    /// reach, or `None`.
    #[allow(unsafe_code)]
    pub(crate) fn dequeue(&mut self, tail: &DdTail) -> Option<usize> {
        if self.first == self.unref_end {
            return None;
        }
        let mut blk = self.first;
        if blk == tail.marker_address() {
            debug_assert!(self.used_marker);
            self.used_marker = false;
            // SAFETY: the marker lives as long as the tail.
            blk = unsafe { node_ref(blk) }.next.load(Ordering::Relaxed);
            if blk == self.unref_end {
                self.first = blk;
                return None;
            }
        }
        // SAFETY: `blk` precedes `unref_end`, so no producer holds it (the owner's side of the
        // protocol of `managed_thread_enqueue`) and its link was published before `unref_end`
        // moved past it.
        self.first = unsafe { node_ref(blk) }.next.load(Ordering::Relaxed);
        debug_assert_ne!(self.first, NULL);
        #[cfg(test)]
        tail.queued.fetch_sub(1, Ordering::Relaxed);
        Some(blk)
    }

    /// Port of `ddq_check_incoming`: moves `unref_end` forward when the producers that could
    /// reference the nodes before it are gone. Returns whether blocks still wait for thread
    /// progress (the `need_thr_progress` result).
    pub(crate) fn check_incoming(&mut self, tail: &DdTail, progress: &ProgressOps) -> bool {
        let marker = tail.marker_address();
        let mut ilast = tail.last.load(Ordering::Relaxed);
        if ilast == marker && self.first == marker {
            // Nothing more to do...
            return false;
        }
        if self.next_thr_progress_reached || (progress.has_reached)(0, self.next_thr_progress) {
            self.next_thr_progress_reached = true;
            let um_refc_ix = self.next_um_refc_ix;
            if tail.um_refc[um_refc_ix].load(Ordering::Relaxed) == 0 {
                // Move unreferenced end pointer forward...
                fence(Ordering::Acquire);
                self.unref_end = self.next_unref_end;
                ilast = self.check_insert_marker(tail, ilast);
                if self.unref_end != ilast {
                    self.next_unref_end = ilast;
                    self.next_thr_progress = crate::sspa::progress_later((progress.current)(0));
                    tail.um_refc_ix.store(um_refc_ix as u32, Ordering::Release);
                    self.next_um_refc_ix = if um_refc_ix == 0 { 1 } else { 0 };
                    self.next_thr_progress_reached = false;
                }
            }
        }
        true
    }

    /// Port of `check_insert_marker`.
    #[allow(unsafe_code)]
    fn check_insert_marker(&mut self, tail: &DdTail, ilast: usize) -> usize {
        if !self.used_marker && self.unref_end == ilast {
            tail.marker.next.store(NULL, Ordering::Relaxed);
            // SAFETY: `ilast` is the node `unref_end` points at, which the owner has not
            // released, or the marker.
            let appended = unsafe { node_ref(ilast) }.next.compare_exchange(
                NULL,
                tail.marker_address(),
                Ordering::Release,
                Ordering::Relaxed,
            );
            if appended.is_ok() {
                self.used_marker = true;
                tail.last.store(tail.marker_address(), Ordering::Release);
                return tail.marker_address();
            }
        }
        ilast
    }

    /// Whether the queue waits for thread progress (`!thr_progress_reached`).
    #[cfg(test)]
    pub(crate) fn waiting_for_progress(&self) -> bool {
        !self.next_thr_progress_reached
    }
}

/// Reads the second word of a dequeued node.
#[allow(unsafe_code)]
pub(crate) fn node_info(node: usize) -> usize {
    // SAFETY: the owner dequeued `node` (precondition of this module's callers), so it is a
    // block of the owner's instance with a word-aligned payload of at least `NODE_BYTES`.
    unsafe { node_ref(node) }.info.load(Ordering::Relaxed)
}

/// # Safety
///
/// `node` is the marker of a live tail or the word-aligned payload of a block of at least
/// `NODE_BYTES` that stays allocated for the duration of the returned reference.
#[allow(unsafe_code)]
unsafe fn node_ref<'a>(node: usize) -> &'a DdBlock {
    // SAFETY: see the function contract.
    unsafe { &*(node as *const DdBlock) }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_progress() -> ProgressOps {
        ProgressOps {
            current: |_| 0,
            has_reached: |_, _| true,
            is_managed: || false,
        }
    }

    /// Passes of `check_incoming` and `dequeue`, as `handle_delayed_dealloc` runs them.
    fn pass(head: &mut DdHead, tail: &DdTail, progress: &ProgressOps) -> Vec<usize> {
        let mut out = Vec::new();
        let mut checked = false;
        loop {
            match head.dequeue(tail) {
                Some(node) => out.push(node),
                None if checked => return out,
                None => {
                    head.check_incoming(tail, progress);
                    checked = true;
                }
            }
        }
    }

    #[test]
    fn queue_delivers_in_order_after_the_unref_protocol() {
        let progress = no_progress();
        let tail = Box::new(DdTail::new());
        tail.init();
        let mut head = DdHead::new(&tail, &progress);
        assert!(!tail.pending(&head));
        let nodes: Vec<Box<[usize; 2]>> = (0..5).map(|_| Box::new([0usize; 2])).collect();
        let addresses: Vec<usize> = nodes.iter().map(|node| node.as_ptr() as usize).collect();
        for (index, &node) in addresses.iter().enumerate() {
            assert!(tail.enqueue(node, index + 100, 0, &progress));
        }
        assert!(tail.pending(&head));
        let mut got = Vec::new();
        for _ in 0..4 {
            got.extend(pass(&mut head, &tail, &progress));
        }
        assert_eq!(got, addresses);
        for (index, &node) in got.iter().enumerate() {
            assert_eq!(node_info(node), index + 100);
        }
        assert!(!tail.pending(&head));
    }

    #[test]
    fn a_node_stays_queued_until_progress_passes() {
        let tail = Box::new(DdTail::new());
        tail.init();
        let gate = ProgressOps {
            current: |_| 0,
            has_reached: |_, _| false,
            is_managed: || true,
        };
        let mut head = DdHead::new(&tail, &gate);
        let node = Box::new([0usize; 2]);
        tail.enqueue(node.as_ptr() as usize, 1, 0, &gate);
        for _ in 0..5 {
            assert!(pass(&mut head, &tail, &gate).is_empty());
        }
        assert!(head.waiting_for_progress());
        let open = no_progress();
        let mut got = Vec::new();
        for _ in 0..4 {
            got.extend(pass(&mut head, &tail, &open));
        }
        assert_eq!(got, vec![node.as_ptr() as usize]);
    }

    #[test]
    fn concurrent_producers_lose_nothing() {
        let progress = no_progress();
        let tail = std::sync::Arc::new(DdTail::new());
        tail.init();
        let mut head = DdHead::new(&tail, &progress);
        let per_thread = 20_000usize;
        let threads = 4usize;
        let storage: Vec<Vec<[usize; 2]>> = (0..threads)
            .map(|_| vec![[0usize; 2]; per_thread])
            .collect();
        let bases: Vec<usize> = storage.iter().map(|v| v.as_ptr() as usize).collect();
        let handles: Vec<_> = bases
            .into_iter()
            .enumerate()
            .map(|(t, base)| {
                let tail = std::sync::Arc::clone(&tail);
                std::thread::spawn(move || {
                    let progress = no_progress();
                    for i in 0..per_thread {
                        tail.enqueue(base + i * NODE_BYTES, t, t, &progress);
                    }
                })
            })
            .collect();
        let mut seen = 0usize;
        let mut seen_nodes = std::collections::HashSet::new();
        let mut done = false;
        while seen < per_thread * threads {
            for node in pass(&mut head, &tail, &progress) {
                let t = node_info(node);
                let base = storage[t].as_ptr() as usize;
                let index = (node - base) / NODE_BYTES;
                assert!(index < per_thread);
                assert!(seen_nodes.insert(node), "a node is delivered once");
                seen += 1;
            }
            if !done && handles.iter().all(|handle| handle.is_finished()) {
                done = true;
            }
        }
        for handle in handles {
            handle.join().unwrap();
        }
        assert_eq!(seen, per_thread * threads);
    }
}
