//! Ordered-block MPSC ingress and a receiver-owned selective-receive queue.

use crossbeam_queue::SegQueue;
use std::collections::VecDeque;
use std::ptr;
use std::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};

const RECYCLED_BLOCK_LIMIT: usize = 64;

struct Node<T> {
    next: *mut Node<T>,
    values: Vec<T>,
    single: bool,
    single_value: Option<T>,
}

enum Chunk<T> {
    Single(T),
    Block(VecDeque<T>),
}

/// Incoming events are detached by the receiver with one atomic exchange.
///
/// Producers for one logical sender must serialize their calls to preserve
/// sender order, just as execution of one Erlang process serializes sends.
pub struct Incoming<T> {
    head: AtomicPtr<Node<T>>,
    spare_single: AtomicPtr<Node<T>>,
    recycled: SegQueue<Box<Node<T>>>,
    recycled_count: AtomicUsize,
}

// SAFETY: producers only publish owned nodes; the sole receiver owns detached nodes.
unsafe impl<T: Send> Send for Incoming<T> {}
// SAFETY: producers mutate the list head atomically and never dereference prior heads.
unsafe impl<T: Send> Sync for Incoming<T> {}

impl<T> Default for Incoming<T> {
    fn default() -> Self {
        Self {
            head: AtomicPtr::new(ptr::null_mut()),
            spare_single: AtomicPtr::new(ptr::null_mut()),
            recycled: SegQueue::new(),
            recycled_count: AtomicUsize::new(0),
        }
    }
}

impl<T> Incoming<T> {
    /// Append an event without acquiring the receiver's task lock.
    // Port of erts/emulator/beam/erl_proc_sig_queue.c:712 (signal enqueue), OTP-29.1.1.
    pub fn push(&self, value: T) {
        let spare = self.spare_single.swap(ptr::null_mut(), Ordering::AcqRel);
        let mut node = if spare.is_null() {
            self.take_recycled().unwrap_or_else(|| {
                Box::new(Node {
                    next: ptr::null_mut(),
                    values: Vec::new(),
                    single: true,
                    single_value: None,
                })
            })
        } else {
            // SAFETY: the atomic swap gives this producer exclusive ownership.
            unsafe { Box::from_raw(spare) }
        };
        node.single = true;
        node.single_value = Some(value);
        self.publish(node);
    }

    /// Publish a sender-ordered block with one ingress operation.
    // Port of erts/emulator/beam/erl_proc_sig_queue.c:1385 (signal block publication), OTP-29.1.1.
    pub fn push_block(&self, values: Vec<T>) {
        let mut values = values;
        self.push_block_reuse(&mut values);
    }

    /// Publish a block and return an empty slab to the producer when available.
    pub fn push_block_reuse(&self, values: &mut Vec<T>) {
        if values.is_empty() {
            return;
        }
        let mut node = self.take_recycled().unwrap_or_else(|| {
            Box::new(Node {
                next: ptr::null_mut(),
                values: Vec::new(),
                single: false,
                single_value: None,
            })
        });
        node.single = false;
        node.single_value = None;
        std::mem::swap(&mut node.values, values);
        self.publish(node);
    }

    fn publish(&self, node: Box<Node<T>>) {
        let node = Box::into_raw(node);
        let mut old = self.head.load(Ordering::Relaxed);
        loop {
            // SAFETY: `node` is unpublished and owned by this producer until CAS succeeds.
            unsafe { (*node).next = old };
            // The wait-state publication and pending probe share this total order,
            // closing the push-before-wait lost-wakeup race.
            match self
                .head
                .compare_exchange_weak(old, node, Ordering::SeqCst, Ordering::Relaxed)
            {
                Ok(_) => return,
                Err(actual) => old = actual,
            }
        }
    }

    fn take_recycled(&self) -> Option<Box<Node<T>>> {
        let node = self.recycled.pop()?;
        self.recycled_count.fetch_sub(1, Ordering::AcqRel);
        Some(node)
    }

    fn recycle(&self, node: Box<Node<T>>) {
        if node.single {
            let ptr = Box::into_raw(node);
            if self
                .spare_single
                .compare_exchange(ptr::null_mut(), ptr, Ordering::Release, Ordering::Relaxed)
                .is_err()
            {
                // SAFETY: the failed CAS did not publish this node.
                drop(unsafe { Box::from_raw(ptr) });
            }
            return;
        }
        let count = self.recycled_count.fetch_add(1, Ordering::AcqRel);
        if count < RECYCLED_BLOCK_LIMIT {
            self.recycled.push(node);
        } else {
            self.recycled_count.fetch_sub(1, Ordering::AcqRel);
        }
    }

    /// Whether any event is pending in the shared ingress.
    // Port of erts/emulator/beam/erl_proc_sig_queue.c:1547 (pending signal probe), OTP-29.1.1.
    pub fn has_pending(&self) -> bool {
        !self.head.load(Ordering::SeqCst).is_null()
    }

    /// Move a snapshot of incoming events to the receiver's private queue.
    // Port of erts/emulator/beam/erl_proc_sig_queue.c:1568 (receiver signal fetch), OTP-29.1.1.
    pub fn drain_into(&self, private: &mut Private<T>) -> usize {
        let mut node = self.head.swap(ptr::null_mut(), Ordering::AcqRel);
        let mut reversed = ptr::null_mut();
        let mut count = 0;
        while !node.is_null() {
            // SAFETY: swap detached the list; only this receiver traverses it.
            unsafe {
                let next = (*node).next;
                (*node).next = reversed;
                reversed = node;
                node = next;
            }
        }
        while !reversed.is_null() {
            // SAFETY: the reversed list is receiver-owned and each node is freed once.
            unsafe {
                let mut boxed = Box::from_raw(reversed);
                reversed = boxed.next;
                if boxed.single {
                    count += 1;
                    if let Some(value) = boxed.single_value.take() {
                        private.queue.push_back(Chunk::Single(value));
                        private.len += 1;
                    }
                } else {
                    count += boxed.values.len();
                    private.len += boxed.values.len();
                    if !boxed.values.is_empty() {
                        private
                            .queue
                            .push_back(Chunk::Block(std::mem::take(&mut boxed.values).into()));
                    }
                }
                self.recycle(boxed);
            }
        }
        count
    }
}

impl<T> Drop for Incoming<T> {
    fn drop(&mut self) {
        let spare = *self.spare_single.get_mut();
        if !spare.is_null() {
            // SAFETY: exclusive drop access owns the unpublished spare node.
            drop(unsafe { Box::from_raw(spare) });
        }
        let mut node = *self.head.get_mut();
        while !node.is_null() {
            // SAFETY: exclusive drop access prevents concurrent producers.
            unsafe {
                let boxed = Box::from_raw(node);
                node = boxed.next;
            }
        }
    }
}

/// Receiver-owned queue with a save position for selective receive.
pub struct Private<T> {
    queue: VecDeque<Chunk<T>>,
    len: usize,
    save: usize,
    markers: Vec<MarkerPosition>,
    next_marker: u64,
}

/// Opaque handle returned by `recv_marker_reserve`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReceiveMarker(u64);

struct MarkerPosition {
    handle: ReceiveMarker,
    reference: Option<u64>,
    position: usize,
}

impl<T> Default for Private<T> {
    fn default() -> Self {
        Self {
            queue: VecDeque::new(),
            len: 0,
            save: 0,
            markers: Vec::new(),
            next_marker: 0,
        }
    }
}

impl<T> Private<T> {
    /// Number of events available to the receiver.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether the private queue is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Whether an event remains at or after the selective receive save cursor.
    pub fn has_saved(&self) -> bool {
        self.save < self.len
    }

    /// Pop the first event, preserving ordinary FIFO receive.
    pub fn pop(&mut self) -> Option<T> {
        let result = match self.queue.front_mut()? {
            Chunk::Single(_) => match self.queue.pop_front() {
                Some(Chunk::Single(value)) => Some(value),
                _ => unreachable!(),
            },
            Chunk::Block(values) => {
                let value = values.pop_front()?;
                if values.is_empty() {
                    self.queue.pop_front();
                }
                Some(value)
            }
        };
        if result.is_some() {
            self.len -= 1;
            self.save = self.save.saturating_sub(1);
            self.shift_markers(0);
        }
        result
    }

    /// Remove the first event at the selective receive save position.
    pub fn pop_saved(&mut self) -> Option<T> {
        let index = self.save;
        let result = self.remove(index)?;
        self.len -= 1;
        self.shift_markers(index);
        Some(result)
    }

    /// Begin a selective-receive scan at the current save position.
    // Port of erts/emulator/beam/erl_proc_sig_queue.c:7135 (msgq save scan), OTP-29.1.1.
    pub fn find_remove(&mut self, mut matches: impl FnMut(&T) -> bool) -> Option<T> {
        let index = (self.save..self.len).find(|&i| self.get(i).is_some_and(&mut matches));
        match index {
            Some(index) => {
                let result = self.remove(index);
                self.len -= 1;
                self.save = 0;
                self.shift_markers(index);
                result
            }
            None => {
                self.save = self.len;
                None
            }
        }
    }

    /// Re-scan previously skipped events after changing a receive pattern.
    pub fn reset_save(&mut self) {
        self.save = 0;
    }

    /// Position after the last event already scanned by selective receive.
    pub fn save_position(&self) -> usize {
        self.save
    }

    /// Reserve a position after all events currently in the private queue.
    // Port of erts/emulator/beam/erl_proc_sig_queue.c:4351 (recv marker insertion), OTP-29.1.1.
    pub fn marker_reserve(&mut self) -> ReceiveMarker {
        let marker = ReceiveMarker(self.next_marker);
        self.next_marker = self.next_marker.wrapping_add(1);
        self.markers.push(MarkerPosition {
            handle: marker,
            reference: None,
            position: self.len,
        });
        marker
    }

    /// Associate a reference key with a reserved marker.
    // Port of erts/emulator/beam/erl_proc_sig_queue.c:4366 (recv marker binding), OTP-29.1.1.
    pub fn marker_bind(&mut self, marker: ReceiveMarker, reference: u64) -> bool {
        if let Some(entry) = self.markers.iter_mut().find(|entry| entry.handle == marker) {
            entry.reference = Some(reference);
            true
        } else {
            false
        }
    }

    /// Set the save position to a bound marker.
    // Port of erts/emulator/beam/erl_proc_sig_queue.c:4545 (recv marker save), OTP-29.1.1.
    pub fn marker_use(&mut self, reference: u64) -> bool {
        if let Some(entry) = self
            .markers
            .iter()
            .find(|entry| entry.reference == Some(reference))
        {
            self.save = entry.position;
            true
        } else {
            self.save = 0;
            false
        }
    }

    /// Whether an event remains between the save cursor and a marker.
    pub fn marker_has_saved_before(&self, marker: ReceiveMarker) -> bool {
        self.markers
            .iter()
            .find(|entry| entry.handle == marker)
            .is_some_and(|entry| entry.position > self.save)
    }

    /// Remove the marker associated with a reference key.
    // Port of erts/emulator/beam/erl_proc_sig_queue.c:3999 (recv marker release), OTP-29.1.1.
    pub fn marker_clear(&mut self, reference: u64) -> bool {
        if let Some(index) = self
            .markers
            .iter()
            .position(|entry| entry.reference == Some(reference))
        {
            self.markers.swap_remove(index);
            true
        } else {
            false
        }
    }

    fn shift_markers(&mut self, removed: usize) {
        for marker in &mut self.markers {
            if marker.position > removed {
                marker.position -= 1;
            }
        }
    }

    fn get(&self, mut index: usize) -> Option<&T> {
        if self.len == self.queue.len() {
            return match self.queue.get(index)? {
                Chunk::Single(value) => Some(value),
                Chunk::Block(values) => values.front(),
            };
        }
        for chunk in &self.queue {
            match chunk {
                Chunk::Single(value) if index == 0 => return Some(value),
                Chunk::Single(_) => index -= 1,
                Chunk::Block(values) if index < values.len() => return values.get(index),
                Chunk::Block(values) => index -= values.len(),
            }
        }
        None
    }

    fn remove(&mut self, mut index: usize) -> Option<T> {
        if self.len == self.queue.len() {
            return match self.queue.remove(index)? {
                Chunk::Single(value) => Some(value),
                Chunk::Block(mut values) => {
                    if values.len() == 1 {
                        values.pop_front()
                    } else {
                        None
                    }
                }
            };
        }
        for chunk_index in 0..self.queue.len() {
            match &mut self.queue[chunk_index] {
                Chunk::Single(_) if index == 0 => {
                    return match self.queue.remove(chunk_index) {
                        Some(Chunk::Single(value)) => Some(value),
                        _ => unreachable!(),
                    };
                }
                Chunk::Single(_) => index -= 1,
                Chunk::Block(values) if index < values.len() => {
                    let value = values.remove(index)?;
                    if values.is_empty() {
                        self.queue.remove(chunk_index);
                    }
                    return Some(value);
                }
                Chunk::Block(values) => index -= values.len(),
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn batch_order_and_save() {
        let input = Incoming::default();
        let mut private = Private::default();
        for i in 0..10 {
            input.push(i);
        }
        assert_eq!(input.drain_into(&mut private), 10);
        assert_eq!(private.find_remove(|&x| x == 20), None);
        assert_eq!(private.save_position(), 10);
        input.push(20);
        input.drain_into(&mut private);
        assert_eq!(private.find_remove(|&x| x == 20), Some(20));
        assert_eq!(
            (0..10).map(|_| private.pop().unwrap()).collect::<Vec<_>>(),
            (0..10).collect::<Vec<_>>()
        );
    }

    #[test]
    fn concurrent_producers_keep_sender_order() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};
        let input = Arc::new(Incoming::default());
        let done = Arc::new(AtomicUsize::new(0));
        let mut private = Private::default();
        std::thread::scope(|scope| {
            for sender in 0..4 {
                let input = input.clone();
                let done = done.clone();
                scope.spawn(move || {
                    for sequence in 0..32 {
                        input.push((sender, sequence));
                    }
                    done.fetch_add(1, Ordering::Release);
                });
            }
            while done.load(Ordering::Acquire) < 4 || input.has_pending() {
                input.drain_into(&mut private);
                std::thread::yield_now();
            }
        });
        input.drain_into(&mut private);
        let mut expected = [0; 4];
        while let Some((sender, sequence)) = private.pop() {
            assert_eq!(sequence, expected[sender]);
            expected[sender] += 1;
        }
        assert_eq!(expected, [32; 4]);
    }

    #[test]
    fn marker_survives_detached_blocks_and_removal() {
        let input = Incoming::default();
        let mut private = Private::default();
        input.push_block(vec![1, 2, 3]);
        input.drain_into(&mut private);
        let marker = private.marker_reserve();
        assert!(private.marker_bind(marker, 19));
        input.push_block(vec![4, 5]);
        input.drain_into(&mut private);
        assert_eq!(private.pop(), Some(1));
        assert!(private.marker_use(19));
        assert_eq!(private.find_remove(|&value| value == 4), Some(4));
        assert_eq!(private.save_position(), 0);
        assert!(private.marker_use(19));
        assert_eq!(private.find_remove(|&value| value == 5), Some(5));
        assert_eq!(private.pop(), Some(2));
        assert_eq!(private.pop(), Some(3));
        assert!(private.marker_clear(19));
        assert!(!private.marker_use(19));
    }
}
