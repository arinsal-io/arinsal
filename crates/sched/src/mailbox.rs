//! The process signal in-queue (erts `ErtsSignalInQueue`) and the receiver-owned middle
//! queue with selective-receive save positions.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, TryLockError};

const SIGNAL_BUFFER_COUNT: usize = 64;
const BUFFER_CONTENTION_INSTALL_LIMIT: usize = 50;
const BUFFER_FLUSH_ROUNDS: usize = 8192;
const BUFFER_ENQUEUES_TO_KEEP: usize = BUFFER_FLUSH_ROUNDS + BUFFER_FLUSH_ROUNDS / 2;

/// One parallel sender buffer (erts `ErtsSignalInQueueBuffer`).
struct SignalBuffer<T> {
    /// Cleared when the buffers are uninstalled; a sender then enqueues directly.
    alive: bool,
    queue: VecDeque<T>,
}

type SignalBuffers<T> = [Mutex<SignalBuffer<T>>; SIGNAL_BUFFER_COUNT];

enum Chunk<T> {
    Single(T),
    Block(VecDeque<T>),
}

/// The outer signal queue of a process.
///
/// Port of erts/emulator/beam/erl_proc_sig_queue.h (`ErtsSignalInQueue`, `sig_inq` in
/// `Process`) and erl_proc_sig_queue.c:712-800 (enqueue_signals), OTP-29.1.1: senders
/// append at the tail under the msgq lock; the receiver splices the whole queue into its
/// private queue under the same lock (erts_proc_sig_fetch).
///
/// Producers for one logical sender must serialize their calls to preserve
/// sender order, just as execution of one Erlang process serializes sends.
pub struct Incoming<T> {
    /// `ERTS_PROC_LOCK_MSGQ` together with the queue it protects.
    msgq: Mutex<VecDeque<T>>,
    /// Signals in the queue and the buffers. Non-zero plays the role of the
    /// `ERTS_PSFLG_SIG_IN_Q`/`ERTS_PSFLG_MSG_SIG_IN_Q` state bits: it is updated with the
    /// enqueue and read without the lock. It is SeqCst so that it orders with the
    /// receiver's WAITING store (see the wake protocol in lib.rs).
    pending: AtomicUsize,
    /// Signals delivered but not yet consumed by the receiver (send pressure).
    pub(crate) backlog: AtomicUsize,
    buffering_allowed: AtomicBool,
    buffers_enabled: AtomicBool,
    buffers: Mutex<Option<Arc<SignalBuffers<T>>>>,
    contention_count: AtomicUsize,
    buffer_enqueues: AtomicUsize,
    enqueues_since_decision: AtomicUsize,
    flush_rounds_left: AtomicUsize,
}

impl<T> Default for Incoming<T> {
    fn default() -> Self {
        Self {
            msgq: Mutex::new(VecDeque::new()),
            pending: AtomicUsize::new(0),
            backlog: AtomicUsize::new(0),
            buffering_allowed: AtomicBool::new(false),
            buffers_enabled: AtomicBool::new(false),
            buffers: Mutex::new(None),
            contention_count: AtomicUsize::new(0),
            buffer_enqueues: AtomicUsize::new(0),
            enqueues_since_decision: AtomicUsize::new(0),
            flush_rounds_left: AtomicUsize::new(BUFFER_FLUSH_ROUNDS),
        }
    }
}

impl<T> Incoming<T> {
    /// Take the msgq lock; a busy lock counts as contention like erts' failed trylock.
    // Port of erts/emulator/beam/erl_proc_sig_queue.c:10661-10694, OTP-29.1.1.
    fn lock_msgq(&self) -> (std::sync::MutexGuard<'_, VecDeque<T>>, usize) {
        match self.msgq.try_lock() {
            Ok(queue) => (queue, 0),
            Err(TryLockError::WouldBlock) => (self.msgq.lock().unwrap(), 1),
            Err(TryLockError::Poisoned(error)) => panic!("signal in-queue poisoned: {error}"),
        }
    }

    /// Append an event, flushing the sender buffers first so it cannot overtake them.
    // Port of erts/emulator/beam/erl_proc_sig_queue.c:712 (signal enqueue), OTP-29.1.1.
    pub fn push(&self, value: T) {
        let (mut queue, _) = self.lock_msgq();
        if self.buffers_enabled.load(Ordering::Acquire) {
            self.flush_buffers_locked(&mut queue, true);
        }
        queue.push_back(value);
        self.pending.fetch_add(1, Ordering::SeqCst);
    }

    /// Publish a signal through its sender's parallel buffer when buffering is enabled.
    // Port of erts/emulator/beam/erl_proc_sig_queue.c:10261 (erts_proc_sig_queue_try_enqueue_to_buffer)
    // and :712 (enqueue_signals), OTP-29.1.1.
    pub fn push_routed(&self, slot: usize, value: T) {
        let value = match self.try_push_buffer(slot, value) {
            Ok(()) => return,
            Err(value) => value,
        };
        let (mut queue, contended) = self.lock_msgq();
        queue.push_back(value);
        self.pending.fetch_add(1, Ordering::SeqCst);
        drop(queue);
        self.note_contention(contended);
    }

    fn try_push_buffer(&self, slot: usize, value: T) -> Result<(), T> {
        if !self.buffers_enabled.load(Ordering::Acquire) {
            return Err(value);
        }
        let Some(buffers) = self.buffers.lock().unwrap().clone() else {
            return Err(value);
        };
        let mut buffer = buffers[slot % SIGNAL_BUFFER_COUNT].lock().unwrap();
        if !buffer.alive {
            return Err(value);
        }
        buffer.queue.push_back(value);
        self.pending.fetch_add(1, Ordering::SeqCst);
        self.buffer_enqueues.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Enable the per sender buffers, or flush and disable them.
    // Port of erts/emulator/beam/erl_proc_sig_queue.c:10600-10694, OTP-29.1.1.
    pub fn set_buffers_enabled(&self, enabled: bool) {
        if !enabled {
            let mut queue = self.msgq.lock().unwrap();
            self.uninstall_buffers_locked(&mut queue);
        }
        self.buffering_allowed.store(enabled, Ordering::Release);
    }

    /// Force installation for the test hook that enables OTP's adaptive optimization.
    // Port of erts/emulator/beam/erl_proc_sig_queue.c:10700-10718, OTP-29.1.1.
    pub fn force_buffers_enabled(&self) {
        let _queue = self.msgq.lock().unwrap();
        self.buffering_allowed.store(true, Ordering::Release);
        self.install_buffers_locked();
    }

    // Port of erts/emulator/beam/erl_proc_sig_queue.c:10661-10694, OTP-29.1.1.
    fn note_contention(&self, retries: usize) {
        if retries == 0 || !self.buffering_allowed.load(Ordering::Acquire) {
            return;
        }
        let count = self.contention_count.fetch_add(retries, Ordering::AcqRel) + retries;
        if count > BUFFER_CONTENTION_INSTALL_LIMIT {
            let _queue = self.msgq.lock().unwrap();
            if self.buffering_allowed.load(Ordering::Acquire)
                && !self.buffers_enabled.load(Ordering::Acquire)
            {
                self.install_buffers_locked();
            }
        }
    }

    /// Install fresh buffers; the caller holds the msgq lock.
    fn install_buffers_locked(&self) {
        let mut buffers = self.buffers.lock().unwrap();
        if buffers.is_none() {
            *buffers = Some(Arc::new(std::array::from_fn(|_| {
                Mutex::new(SignalBuffer {
                    alive: true,
                    queue: VecDeque::new(),
                })
            })));
        }
        self.flush_rounds_left
            .store(BUFFER_FLUSH_ROUNDS, Ordering::Relaxed);
        self.buffer_enqueues.store(0, Ordering::Relaxed);
        self.enqueues_since_decision.store(0, Ordering::Relaxed);
        self.buffers_enabled.store(true, Ordering::Release);
    }

    /// Flush, mark dead and drop the buffers; the caller holds the msgq lock.
    fn uninstall_buffers_locked(&self, queue: &mut VecDeque<T>) {
        let taken = self.buffers.lock().unwrap().take();
        self.buffers_enabled.store(false, Ordering::Release);
        if let Some(buffers) = taken {
            for buffer in buffers.iter() {
                let mut buffer = buffer.lock().unwrap();
                buffer.alive = false;
                queue.extend(buffer.queue.drain(..));
            }
        }
        self.contention_count.store(0, Ordering::Relaxed);
        self.buffer_enqueues.store(0, Ordering::Relaxed);
        self.enqueues_since_decision.store(0, Ordering::Relaxed);
        self.flush_rounds_left
            .store(BUFFER_FLUSH_ROUNDS, Ordering::Relaxed);
    }

    /// Move buffered signals to the queue tail; the caller holds the msgq lock.
    // Port of erts/emulator/beam/erl_proc_sig_queue.c:10532 (sig_inq_buffers flush), OTP-29.1.1.
    fn flush_buffers_locked(&self, queue: &mut VecDeque<T>, adapt: bool) {
        let Some(buffers) = self.buffers.lock().unwrap().clone() else {
            return;
        };
        for buffer in buffers.iter() {
            queue.extend(buffer.lock().unwrap().queue.drain(..));
        }
        if adapt && self.buffers_enabled.load(Ordering::Acquire) {
            let count = self.buffer_enqueues.swap(0, Ordering::AcqRel);
            let total = self
                .enqueues_since_decision
                .fetch_add(count, Ordering::AcqRel)
                + count;
            if self.flush_rounds_left.fetch_sub(1, Ordering::AcqRel) == 1 {
                if total < BUFFER_ENQUEUES_TO_KEEP {
                    self.uninstall_buffers_locked(queue);
                    return;
                }
                self.enqueues_since_decision.store(0, Ordering::Relaxed);
                self.flush_rounds_left
                    .store(BUFFER_FLUSH_ROUNDS, Ordering::Relaxed);
            }
        }
    }

    /// Publish a sender-ordered block with one enqueue.
    // Port of erts/emulator/beam/erl_proc_sig_queue.c:1385 (signal block publication), OTP-29.1.1.
    pub fn push_block(&self, values: Vec<T>) {
        let mut values = values;
        self.push_block_reuse(&mut values);
    }

    /// Publish a block, leaving the producer's (now empty) vector for reuse.
    pub fn push_block_reuse(&self, values: &mut Vec<T>) {
        if values.is_empty() {
            return;
        }
        let (mut queue, _) = self.lock_msgq();
        if self.buffers_enabled.load(Ordering::Acquire) {
            self.flush_buffers_locked(&mut queue, true);
        }
        let count = values.len();
        queue.extend(values.drain(..));
        self.pending.fetch_add(count, Ordering::SeqCst);
    }

    /// Publish a sender ordered block through the matching per sender buffers.
    // Port of erts/emulator/beam/erl_proc_sig_queue.c:10261, OTP-29.1.1.
    pub fn push_block_routed(&self, values: &mut Vec<T>, sender_slot: impl Fn(&T) -> usize) {
        if values.is_empty() {
            return;
        }
        if !self.buffers_enabled.load(Ordering::Acquire) {
            let (mut queue, contended) = self.lock_msgq();
            let count = values.len();
            queue.extend(values.drain(..));
            self.pending.fetch_add(count, Ordering::SeqCst);
            drop(queue);
            self.note_contention(contended);
            return;
        }
        for value in values.drain(..) {
            let slot = sender_slot(&value);
            if let Err(value) = self.try_push_buffer(slot, value) {
                let (mut queue, _) = self.lock_msgq();
                queue.push_back(value);
                self.pending.fetch_add(1, Ordering::SeqCst);
            }
        }
    }

    /// Whether any signal waits in the in-queue or its buffers.
    // Port of erts/emulator/beam/erl_proc_sig_queue.c:1547 (pending signal probe), OTP-29.1.1.
    pub fn has_pending(&self) -> bool {
        self.pending.load(Ordering::SeqCst) != 0
    }

    /// Move the whole in-queue to the receiver's private queue.
    // Port of erts/emulator/beam/erl_proc_sig_queue.h:1997 (erts_proc_sig_fetch), OTP-29.1.1.
    pub fn drain_into(&self, private: &mut Private<T>) -> usize {
        let mut queue = self.msgq.lock().unwrap();
        if self.buffers_enabled.load(Ordering::Acquire) {
            self.flush_buffers_locked(&mut queue, true);
        }
        let count = queue.len();
        match count {
            0 => return 0,
            1 => private
                .queue
                .push_back(Chunk::Single(queue.pop_front().expect("one signal"))),
            _ => private
                .queue
                .push_back(Chunk::Block(std::mem::take(&mut *queue))),
        }
        self.pending.fetch_sub(count, Ordering::SeqCst);
        drop(queue);
        private.len += count;
        count
    }

    /// Fetch the oldest signal when `accept` takes it, for a receiver whose private queue
    /// is empty. The receiver handles it in place, like erts' receive helper fetching
    /// the outer queue before matching.
    // Port of erts/emulator/beam/erl_proc_sig_queue.c:7730-7790 (erts_proc_sig_receive_helper),
    // OTP-29.1.1.
    pub fn fetch_first_if(&self, accept: impl FnOnce(&T) -> bool) -> Option<T> {
        let mut queue = self.msgq.lock().unwrap();
        if self.buffers_enabled.load(Ordering::Acquire) {
            self.flush_buffers_locked(&mut queue, true);
        }
        if !accept(queue.front()?) {
            return None;
        }
        let value = queue.pop_front();
        self.pending.fetch_sub(1, Ordering::SeqCst);
        drop(queue);
        if self.backlog.load(Ordering::Relaxed) != 0 {
            self.backlog.fetch_sub(1, Ordering::Relaxed);
        }
        value
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
    /// No events and no receive markers: nothing orders against the outer queue.
    pub fn is_idle(&self) -> bool {
        self.len == 0 && self.markers.is_empty()
    }

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
    fn parallel_sender_buffer_flush_preserves_sender_order() {
        let input = Incoming::default();
        let mut private = Private::default();
        input.force_buffers_enabled();
        for sequence in 0..128 {
            input.push_routed(17, sequence);
        }
        assert!(input.has_pending());
        assert_eq!(input.drain_into(&mut private), 128);
        assert_eq!(
            (0..128).map(|_| private.pop().unwrap()).collect::<Vec<_>>(),
            (0..128).collect::<Vec<_>>()
        );

        input.push_routed(17, 128);
        input.set_buffers_enabled(false);
        input.push_routed(17, 129);
        assert_eq!(input.drain_into(&mut private), 2);
        assert_eq!(private.pop(), Some(128));
        assert_eq!(private.pop(), Some(129));
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
