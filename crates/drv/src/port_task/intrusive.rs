//! Intrusive singly linked queues used by the port scheduler.

use std::marker::PhantomData;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

/// One queue membership embedded in a task.
pub(super) struct Link<T> {
    next: AtomicUsize,
    owner: AtomicUsize,
    marker: PhantomData<fn() -> T>,
}

impl<T> Default for Link<T> {
    fn default() -> Self {
        Self {
            next: AtomicUsize::new(0),
            owner: AtomicUsize::new(0),
            marker: PhantomData,
        }
    }
}

/// An allocation-free-when-empty intrusive FIFO. The list owns one strong task reference
/// per link; callers serialize every operation with the port scheduler lock.
pub(super) struct Queue<T> {
    first: usize,
    last: usize,
    marker: PhantomData<fn() -> T>,
}

struct BusyCaller<T> {
    next: usize,
    caller: u64,
    count: usize,
    last: usize,
    marker: PhantomData<fn() -> T>,
}

impl<T> Default for BusyCaller<T> {
    fn default() -> Self {
        Self {
            next: 0,
            caller: u64::MAX,
            count: 0,
            last: 0,
            marker: PhantomData,
        }
    }
}

/// Lazily allocated `ErtsPortTaskBusyCallerTable` with 17 buckets and one inline caller entry.
pub(super) struct BusyCallerTable<T> {
    buckets: [usize; 17],
    preallocated: BusyCaller<T>,
    preallocated_used: bool,
}

impl<T> Default for BusyCallerTable<T> {
    fn default() -> Self {
        Self {
            buckets: [0; 17],
            preallocated: BusyCaller::default(),
            preallocated_used: false,
        }
    }
}

impl<T> BusyCallerTable<T> {
    // Port of erts/emulator/beam/erl_port_task.c:252 (caller2bix), OTP-29.1.1.
    fn bucket(caller: u64) -> usize {
        (caller % 17) as usize
    }

    // Port of erts/emulator/beam/erl_port_task.c:308-351 (busy_wait_move_to_busy_queue), OTP-29.1.1.
    pub(super) fn add(&mut self, caller: u64, link: &Link<T>) {
        let bucket = Self::bucket(caller);
        let mut current = self.buckets[bucket];
        while current != 0 {
            // SAFETY: bucket entries are either the stable inline entry or Box allocations
            // owned by this table; the scheduler lock serializes access.
            let entry = unsafe { &mut *(current as *mut BusyCaller<T>) };
            if entry.caller == caller {
                entry.count += 1;
                entry.last = link as *const Link<T> as usize;
                return;
            }
            current = entry.next;
        }
        let entry = if !self.preallocated_used {
            self.preallocated_used = true;
            &mut self.preallocated as *mut BusyCaller<T>
        } else {
            Box::into_raw(Box::new(BusyCaller::default()))
        };
        // SAFETY: entry points to either the table's stable inline slot or a Box allocation
        // just created; it is linked into exactly one bucket under the scheduler lock.
        unsafe {
            (*entry).next = self.buckets[bucket];
            (*entry).caller = caller;
            (*entry).count = 1;
            (*entry).last = link as *const Link<T> as usize;
        }
        self.buckets[bucket] = entry as usize;
    }

    // Port of erts/emulator/beam/erl_port_task.c:376-421 (check_sig_dep_move_to_busy_queue), OTP-29.1.1.
    pub(super) fn last_link(&self, caller: u64) -> Option<usize> {
        self.find(caller).map(|entry| {
            // SAFETY: find returns a live entry owned by this table under the scheduler lock.
            unsafe { (*entry).last }
        })
    }

    // Port of erts/emulator/beam/erl_port_task.c:258-305 (popped_from_busy_queue), OTP-29.1.1.
    pub(super) fn remove(&mut self, caller: u64) {
        let bucket = Self::bucket(caller);
        let mut previous = &mut self.buckets[bucket] as *mut usize;
        loop {
            // SAFETY: previous points into this table or a live entry's next field; the
            // scheduler lock excludes concurrent updates.
            let current = unsafe { *previous };
            if current == 0 {
                break;
            }
            let entry = current as *mut BusyCaller<T>;
            // SAFETY: current is a live entry in this table's bucket chain.
            let entry_ref = unsafe { &mut *entry };
            if entry_ref.caller == caller {
                assert!(entry_ref.count > 0, "busy caller count underflow");
                entry_ref.count -= 1;
                if entry_ref.count > 0 {
                    return;
                }
                // SAFETY: previous points to the bucket head or this entry's `next` field.
                unsafe { *previous = entry_ref.next };
                let preallocated = std::ptr::addr_of_mut!(self.preallocated);
                if self.preallocated_used && std::ptr::eq(entry, preallocated) {
                    *entry_ref = BusyCaller::default();
                    self.preallocated_used = false;
                } else {
                    // SAFETY: non-inline entries were allocated by Box::into_raw in add and
                    // have now been unlinked exactly once.
                    drop(unsafe { Box::from_raw(entry) });
                }
                return;
            }
            previous = &mut entry_ref.next;
        }
        panic!("missing busy caller table entry");
    }

    // Port of erts/emulator/beam/erl_port_task.c:308-351 (busy caller last-task update), OTP-29.1.1.
    pub(super) fn set_last(&mut self, caller: u64, link: &Link<T>) {
        if let Some(entry) = self.find(caller) {
            // SAFETY: find returned a live entry owned by this table under the lock.
            unsafe { (*entry).last = link as *const Link<T> as usize };
        }
    }

    pub(super) fn is_empty(&self) -> bool {
        self.buckets.iter().all(|bucket| *bucket == 0)
    }

    fn find(&self, caller: u64) -> Option<*mut BusyCaller<T>> {
        let mut current = self.buckets[Self::bucket(caller)];
        while current != 0 {
            // SAFETY: each pointer is a live inline or Box entry owned by this table; callers
            // hold the scheduler lock for the entire lookup.
            let entry = unsafe { &*(current as *const BusyCaller<T>) };
            if entry.caller == caller {
                return Some(current as *mut BusyCaller<T>);
            }
            current = entry.next;
        }
        None
    }
}

impl<T> Drop for BusyCallerTable<T> {
    fn drop(&mut self) {
        let preallocated = std::ptr::addr_of_mut!(self.preallocated) as usize;
        for bucket in &mut self.buckets {
            let mut current = *bucket;
            while current != 0 {
                // SAFETY: all non-inline pointers remaining in buckets were allocated by Box
                // and are exclusively owned by this table; the inline slot is never freed.
                let next = unsafe { (*(current as *mut BusyCaller<T>)).next };
                if current != preallocated {
                    // SAFETY: the entry was Box::into_raw allocated and is unlinked from this
                    // bucket before its unique Box is reconstructed.
                    drop(unsafe { Box::from_raw(current as *mut BusyCaller<T>) });
                }
                current = next;
            }
            *bucket = 0;
        }
    }
}

impl<T> Default for Queue<T> {
    fn default() -> Self {
        Self {
            first: 0,
            last: 0,
            marker: PhantomData,
        }
    }
}

impl<T> Queue<T> {
    pub(super) fn is_empty(&self) -> bool {
        self.first == 0
    }

    // Port of erts/emulator/beam/erl_port_task.c:990-1028 (enqueue_task), OTP-29.1.1.
    pub(super) fn push_back(&mut self, task: &Arc<T>, link: &Link<T>) {
        let link_ptr = link as *const Link<T> as usize;
        assert_eq!(link.owner.load(Ordering::Relaxed), 0, "link already queued");
        let task_ptr = Arc::into_raw(Arc::clone(task)) as usize;
        link.owner.store(task_ptr, Ordering::Relaxed);
        link.next.store(0, Ordering::Relaxed);
        if self.last == 0 {
            self.first = link_ptr;
        } else {
            // SAFETY: the tail link is owned by this list, remains alive through its raw
            // Arc owner, and the caller holds the scheduler lock for this mutation.
            unsafe { &*(self.last as *const Link<T>) }
                .next
                .store(link_ptr, Ordering::Relaxed);
        }
        self.last = link_ptr;
    }

    // Port of erts/emulator/beam/erl_port_task.c:308-351 (busy_wait_move_to_busy_queue), OTP-29.1.1.
    pub(super) fn push_back_owned(&mut self, task: Arc<T>, link_of: impl Fn(&T) -> &Link<T>) {
        let link_ptr = link_of(&task) as *const Link<T> as usize;
        assert_eq!(
            link_of(&task).owner.load(Ordering::Relaxed),
            0,
            "link already queued"
        );
        let task_ptr = Arc::into_raw(task) as usize;
        // SAFETY: the raw Arc owner just created keeps the task and embedded link alive;
        // the port scheduler lock excludes concurrent membership changes.
        let link = unsafe { &*(link_ptr as *const Link<T>) };
        link.owner.store(task_ptr, Ordering::Relaxed);
        link.next.store(0, Ordering::Relaxed);
        if self.last == 0 {
            self.first = link_ptr;
        } else {
            // SAFETY: the tail link is owned by this list, remains alive through its raw
            // Arc owner, and the caller holds the scheduler lock for this mutation.
            unsafe { &*(self.last as *const Link<T>) }
                .next
                .store(link_ptr, Ordering::Relaxed);
        }
        self.last = link_ptr;
    }

    // Port of erts/emulator/beam/erl_port_task.c:423-480 (no_sig_dep_move_from_busyq), OTP-29.1.1.
    pub(super) fn front_matches(&self, mut matches: impl FnMut(&T) -> bool) -> bool {
        if self.first == 0 {
            return false;
        }
        // SAFETY: the head is kept alive by its owner Arc and the caller holds the
        // scheduler lock, so it cannot be removed while inspected.
        let link = unsafe { &*(self.first as *const Link<T>) };
        let owner = link.owner.load(Ordering::Relaxed);
        assert_ne!(owner, 0, "queued link has no owner");
        // SAFETY: owner is the strong Arc pointer held by this list membership.
        matches(unsafe { &*(owner as *const T) })
    }

    // Port of erts/emulator/beam/erl_port_task.c:1225-1252 (fetch_in_queue), OTP-29.1.1.
    pub(super) fn pop_front(&mut self) -> Option<Arc<T>> {
        if self.first == 0 {
            return None;
        }
        let link_ptr = self.first;
        // SAFETY: the head belongs to this list and its raw Arc owner keeps it alive; callers
        // hold the scheduler lock, so the link cannot be concurrently removed or reused.
        let link = unsafe { &*(link_ptr as *const Link<T>) };
        let next = link.next.load(Ordering::Relaxed);
        let owner = link.owner.swap(0, Ordering::Relaxed);
        link.next.store(0, Ordering::Relaxed);
        self.first = next;
        if next == 0 {
            self.last = 0;
        }
        assert_ne!(owner, 0, "queued link has no owner");
        // SAFETY: push_back converted exactly one Arc strong reference into this owner slot;
        // popping removes the slot exactly once.
        Some(unsafe { Arc::from_raw(owner as *const T) })
    }

    // Port of erts/emulator/beam/erl_port_task.c:376-421 (check_sig_dep_move_to_busy_queue), OTP-29.1.1.
    pub(super) fn insert_after_link(
        &mut self,
        task: Arc<T>,
        link_of: impl Fn(&T) -> &Link<T>,
        previous: usize,
    ) {
        assert_ne!(previous, 0, "busy caller has no last task");
        let link_ptr = link_of(&task) as *const Link<T> as usize;
        assert_eq!(
            link_of(&task).owner.load(Ordering::Relaxed),
            0,
            "link already queued"
        );
        let task_ptr = Arc::into_raw(task) as usize;
        // SAFETY: the raw Arc owner just created keeps the task and embedded link alive;
        // the port scheduler lock excludes concurrent membership changes.
        let link = unsafe { &*(link_ptr as *const Link<T>) };
        link.owner.store(task_ptr, Ordering::Relaxed);
        // SAFETY: `previous` is the live last task link stored in the busy caller table; the
        // scheduler lock protects both that table and the queue.
        let previous = unsafe { &*(previous as *const Link<T>) };
        let next = previous.next.load(Ordering::Relaxed);
        link.next.store(next, Ordering::Relaxed);
        previous.next.store(link_ptr, Ordering::Relaxed);
        if next == 0 {
            self.last = link_ptr;
        }
    }

    /// Move the matching head prefix to another queue without changing task ownership.
    // Port of erts/emulator/beam/erl_port_task.c:423-480 (no_sig_dep_move_from_busyq), OTP-29.1.1.
    pub(super) fn move_prefix_to_front(
        &mut self,
        destination: &mut Self,
        mut matches: impl FnMut(&T) -> bool,
        mut moved: impl FnMut(&T),
    ) {
        let first = self.first;
        if first == 0 {
            return;
        }
        let mut last = 0;
        let mut cursor = first;
        while cursor != 0 {
            // SAFETY: cursor belongs to this list and its Arc owner remains held while the
            // scheduler lock prevents removal or relinking.
            let link = unsafe { &*(cursor as *const Link<T>) };
            let owner = link.owner.load(Ordering::Relaxed);
            assert_ne!(owner, 0, "queued link has no owner");
            // SAFETY: owner is the strong Arc pointer held by this queue membership.
            let task = unsafe { &*(owner as *const T) };
            if !matches(task) {
                break;
            }
            moved(task);
            last = cursor;
            cursor = link.next.load(Ordering::Relaxed);
        }
        if last == 0 {
            return;
        }
        // SAFETY: last is in the detached prefix; the lock keeps it alive and exclusive.
        unsafe { &*(last as *const Link<T>) }
            .next
            .store(destination.first, Ordering::Relaxed);
        self.first = cursor;
        if cursor == 0 {
            self.last = 0;
        }
        if destination.last == 0 {
            destination.last = last;
        }
        destination.first = first;
    }

    /// Append every node to another queue without reallocating or touching task references.
    // Port of erts/emulator/beam/erl_port_task.c:1225-1252 (fetch_in_queue), OTP-29.1.1.
    pub(super) fn append_to(&mut self, destination: &mut Self) {
        if self.first == 0 {
            return;
        }
        if destination.last == 0 {
            destination.first = self.first;
        } else {
            // SAFETY: destination's tail is owned by that list and remains alive through its
            // task owner Arc; the scheduler lock excludes concurrent queue mutation.
            unsafe { &*(destination.last as *const Link<T>) }
                .next
                .store(self.first, Ordering::Relaxed);
        }
        destination.last = self.last;
        self.first = 0;
        self.last = 0;
    }

    // Port of erts/emulator/beam/erl_port_task.c:1225-1252 (nosuspend handle cleanup), OTP-29.1.1.
    pub(super) fn retain(
        &mut self,
        link_of: impl Fn(&T) -> &Link<T>,
        mut keep: impl FnMut(&T) -> bool,
    ) {
        let mut kept = Self::default();
        while let Some(task) = self.pop_front() {
            let link = link_of(&task);
            if keep(&task) {
                kept.push_back(&task, link);
            }
        }
        *self = kept;
    }

    // Port of inet_drv.c:tcp_inet_timeout over the port's queued send callbacks, OTP-29.1.1.
    pub(super) fn for_each(&self, mut visit: impl FnMut(&T)) {
        let mut cursor = self.first;
        while cursor != 0 {
            // SAFETY: every link reachable from this list is kept alive by its owning Arc;
            // the scheduler lock prevents removal while the task is borrowed.
            let link = unsafe { &*(cursor as *const Link<T>) };
            let owner = link.owner.load(Ordering::Relaxed);
            assert_ne!(owner, 0, "queued link has no owner");
            // SAFETY: owner is the Arc strong reference recorded when this link was inserted.
            visit(unsafe { &*(owner as *const T) });
            cursor = link.next.load(Ordering::Relaxed);
        }
    }

    // Port of inet_drv.c:tcp_inet_timeout (expire timed send wait tasks), OTP-29.1.1.
    pub(super) fn take_matching(
        &mut self,
        link_of: impl Fn(&T) -> &Link<T>,
        mut matches: impl FnMut(&T) -> bool,
    ) -> Vec<Arc<T>> {
        let mut kept = Self::default();
        let mut taken = Vec::new();
        while let Some(task) = self.pop_front() {
            if matches(&task) {
                taken.push(task);
            } else {
                kept.push_back(&task, link_of(&task));
            }
        }
        *self = kept;
        taken
    }
}

impl<T> Drop for Queue<T> {
    fn drop(&mut self) {
        while self.pop_front().is_some() {}
    }
}

#[cfg(test)]
mod tests {
    use super::{BusyCallerTable, Link, Queue};
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering},
    };
    use std::thread;

    struct Item {
        link: Link<Item>,
        aborted: AtomicBool,
        state: AtomicU8,
    }

    #[test]
    fn busy_caller_table_uses_inline_entry_then_releases_callers() {
        let mut table = BusyCallerTable::<Item>::default();
        let first = Item {
            link: Link::default(),
            aborted: AtomicBool::new(false),
            state: AtomicU8::new(0),
        };
        let second = Item {
            link: Link::default(),
            aborted: AtomicBool::new(false),
            state: AtomicU8::new(0),
        };
        table.add(1, &first.link);
        table.add(18, &second.link);
        table.add(1, &second.link);
        assert_eq!(
            table.last_link(1),
            Some(&second.link as *const Link<Item> as usize)
        );
        table.remove(1);
        assert!(table.last_link(1).is_some());
        table.remove(1);
        table.remove(18);
        assert!(table.is_empty());
    }

    #[test]
    fn enqueue_dequeue_abort_stress_under_scheduler_lock() {
        const THREADS: usize = 8;
        const EACH: usize = 2_000;
        let queue = Arc::new(Mutex::new(Queue::<Item>::default()));
        let done = Arc::new(AtomicUsize::new(0));
        let mut workers = Vec::new();
        for thread_ix in 0..THREADS {
            let queue = Arc::clone(&queue);
            let done = Arc::clone(&done);
            workers.push(thread::spawn(move || {
                for ix in 0..EACH {
                    let item = Arc::new(Item {
                        link: Link::default(),
                        aborted: AtomicBool::new((ix + thread_ix) % 5 == 0),
                        state: AtomicU8::new(0),
                    });
                    let mut queue = queue.lock().unwrap();
                    queue.push_back(&item, &item.link);
                    if item.aborted.load(Ordering::Relaxed) {
                        item.state
                            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
                            .unwrap();
                    }
                    let popped = queue.pop_front().expect("enqueued item");
                    assert_eq!(
                        popped.aborted.load(Ordering::Relaxed),
                        item.aborted.load(Ordering::Relaxed)
                    );
                    assert_eq!(
                        popped.state.load(Ordering::Acquire),
                        u8::from(item.aborted.load(Ordering::Relaxed))
                    );
                    assert_eq!(popped.link.owner.load(Ordering::Relaxed), 0);
                    done.fetch_add(1, Ordering::Relaxed);
                }
            }));
        }
        for worker in workers {
            worker.join().unwrap();
        }
        assert_eq!(done.load(Ordering::Relaxed), THREADS * EACH);
        assert!(queue.lock().unwrap().is_empty());
    }
}
