//! The process signal in-queue (erts `ErtsSignalInQueue`) and the receiver-owned middle
//! queue with selective-receive save positions.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, TryLockError};

const SIGNAL_BUFFER_COUNT: usize = 64;
const BUFFER_CONTENTION_INSTALL_LIMIT: usize = 50;
const BUFFER_FLUSH_ROUNDS: usize = 8192;
const BUFFER_ENQUEUES_TO_KEEP: usize = BUFFER_FLUSH_ROUNDS + BUFFER_FLUSH_ROUNDS / 2;

/// The erts process state word bits (`ERTS_PSFLG_*`).
// Port of erts/emulator/beam/erl_process.h:1231-1340, OTP-29.1.1.
pub mod psflg {
    /// `ERTS_PSFLGS_ZERO_BIT_OFFSET`: three two-bit priority fields precede the flags.
    const ZERO_BIT_OFFSET: u32 = 3 * 2;
    const fn bit(n: u32) -> u32 {
        1 << (ZERO_BIT_OFFSET + n)
    }
    /// `ERTS_PSFLG_FREE`.
    pub const FREE: u32 = bit(4);
    /// `ERTS_PSFLG_EXITING`.
    pub const EXITING: u32 = bit(5);
    /// `ERTS_PSFLG_MSG_SIG_IN_Q`: message signals in the outer signal queue.
    pub const MSG_SIG_IN_Q: u32 = bit(6);
    /// `ERTS_PSFLG_ACTIVE`.
    pub const ACTIVE: u32 = bit(7);
    /// `ERTS_PSFLG_IN_RUNQ`.
    pub const IN_RUNQ: u32 = bit(8);
    /// `ERTS_PSFLG_RUNNING`.
    pub const RUNNING: u32 = bit(9);
    /// `ERTS_PSFLG_SUSPENDED`.
    pub const SUSPENDED: u32 = bit(10);
    /// `ERTS_PSFLG_NMSG_SIG_IN_Q`: non-message signals in the outer signal queue.
    pub const NMSG_SIG_IN_Q: u32 = bit(13);
    /// `ERTS_PSFLG_ACTIVE_SYS`.
    pub const ACTIVE_SYS: u32 = bit(14);
    /// `ERTS_PSFLG_RUNNING_SYS`.
    pub const RUNNING_SYS: u32 = bit(15);
    /// `ERTS_PSFLG_SIG_Q`: unhandled signals in the middle signal queue.
    pub const SIG_Q: u32 = bit(19);
    /// `ERTS_PSFLG_SIG_IN_Q`: either kind of signal in the outer signal queue.
    pub const SIG_IN_Q: u32 = MSG_SIG_IN_Q | NMSG_SIG_IN_Q;
}

/// How a queued signal sets the in-queue state bits.
pub trait InSignal {
    /// A message signal (`ERTS_PSFLG_MSG_SIG_IN_Q`); otherwise a non-message signal
    /// (`ERTS_PSFLG_NMSG_SIG_IN_Q`).
    fn is_message(&self) -> bool;
}

/// The receiver exited and closed its in-queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueueClosed;

/// One parallel sender buffer (erts `ErtsSignalInQueueBuffer`).
struct SignalBuffer<T> {
    /// Cleared when the buffers are uninstalled; a sender then enqueues directly.
    alive: bool,
    queue: VecDeque<T>,
}

type SignalBuffers<T> = [Mutex<SignalBuffer<T>>; SIGNAL_BUFFER_COUNT];

/// The outer signal queue of a process.
///
/// Port of erts/emulator/beam/erl_proc_sig_queue.h (`ErtsSignalInQueue`, `sig_inq` in
/// `Process`) and erl_proc_sig_queue.c:712-800 (enqueue_signals), OTP-29.1.1: senders
/// append at the tail under the msgq lock; the receiver splices the whole queue into its
/// inner queue under the same lock (erts_proc_sig_fetch).
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
    /// Set under the msgq lock once the receiver exited and took its last signals; later
    /// enqueues fail. Port of erts/emulator/beam/erl_proc_sig_queue.c:712-800
    /// (enqueue_signals checks the receiver's exiting state under the msgq lock), OTP-29.1.1.
    closed: AtomicBool,
    /// `p->state`: the erts process state word. It lives with the in-queue because every
    /// enqueuer, the receiver and its native probe reach the process through this shared
    /// structure.
    // Port of erts/emulator/beam/erl_process.h:1231-1340 (ERTS_PSFLG_*), OTP-29.1.1.
    state: AtomicU32,
    /// Non-message signals among `pending`; with it a fetch leaves exactly the
    /// MSG_SIG_IN_Q/NMSG_SIG_IN_Q bits of the signals still queued (erts re-sets them from
    /// `msgs_in_slots`/`nonmsgs_in_slots` after racing buffer inserts, erl_proc_sig_queue.c:1450).
    nmsgs: AtomicUsize,
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
            state: AtomicU32::new(0),
            nmsgs: AtomicUsize::new(0),
            closed: AtomicBool::new(false),
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
    /// The erts process state word (`p->state`).
    pub fn state(&self) -> &AtomicU32 {
        &self.state
    }

    /// Set `ERTS_PSFLG_SIG_Q` while the receiver's middle signal queue holds unhandled
    /// signals, and clear it once that queue is empty.
    // Port of erts/emulator/beam/erl_proc_sig_queue.c:1385, 1407 (erts_proc_sig_fetch__ sets
    // it) and 7017, 7110 (erts_proc_sig_handle_incoming clears it), OTP-29.1.1.
    pub fn set_sig_q(&self, unhandled: bool) {
        let state = self.state.load(Ordering::Relaxed);
        if unhandled && state & psflg::SIG_Q == 0 {
            self.state.fetch_or(psflg::SIG_Q, Ordering::Relaxed);
        } else if !unhandled && state & psflg::SIG_Q != 0 {
            self.state.fetch_and(!psflg::SIG_Q, Ordering::Relaxed);
        }
    }
}

impl<T: InSignal> Incoming<T> {
    /// Account `count` enqueued signals, `nmsgs` of them non-message signals, and set the
    /// matching in-queue state bits.
    /// Returns the state word with the in-queue bits set. The one read-modify-write both sets
    /// the bits and tells the sender whether the receiver was active, so the wake decision
    /// needs no further load of the word.
    // Port of erts/emulator/beam/erl_proc_sig_queue.c:911-935 and erl_proc_sig_queue.h:2080
    // (erts_proc_notify_new_message works from the state returned by the bor), OTP-29.1.1.
    fn enqueued(&self, count: usize, nmsgs: usize) -> u32 {
        if nmsgs != 0 {
            self.nmsgs.fetch_add(nmsgs, Ordering::Relaxed);
        }
        let mut set = 0;
        if count > nmsgs {
            set |= psflg::MSG_SIG_IN_Q;
        }
        if nmsgs != 0 {
            set |= psflg::NMSG_SIG_IN_Q;
        }
        // `erts_atomic32_read_bor_nob`. Every change of the word is a read-modify-write, so
        // this one and the receiver's transition to WAITING are totally ordered: either the
        // returned word is not active and the sender wakes the receiver, or the receiver's
        // transition returns the bit set here (the wake protocol in lib.rs).
        self.state.fetch_or(set, Ordering::Relaxed) | set
    }

    /// Account signals taken from the queue and leave the in-queue bits of what is still
    /// queued (signals racing into the buffers).
    // Port of erts/emulator/beam/erl_proc_sig_queue.c:1336-1495 (erts_proc_sig_fetch__
    // clear_flags, then re-set for racing buffer inserts), OTP-29.1.1.
    fn dequeued(&self, count: usize, nmsgs: usize) {
        let left = self.pending.fetch_sub(count, Ordering::SeqCst) - count;
        let left_nmsgs = if nmsgs != 0 {
            self.nmsgs.fetch_sub(nmsgs, Ordering::Relaxed) - nmsgs
        } else {
            self.nmsgs.load(Ordering::Relaxed)
        };
        let mut keep = 0;
        if left > left_nmsgs {
            keep |= psflg::MSG_SIG_IN_Q;
        }
        if left_nmsgs != 0 {
            keep |= psflg::NMSG_SIG_IN_Q;
        }
        let clear = psflg::SIG_IN_Q & !keep;
        // `erts_atomic32_read_band_nob`.
        // No read first: the word was just written by a sender, so a load would cost a second
        // coherence transfer before the read-modify-write.
        if clear != 0 {
            self.state.fetch_and(!clear, Ordering::Relaxed);
        }
    }

    fn count_nmsgs<'a>(values: impl IntoIterator<Item = &'a T>) -> usize
    where
        T: 'a,
    {
        values
            .into_iter()
            .filter(|value| !value.is_message())
            .count()
    }

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
        let nmsg = usize::from(!value.is_message());
        queue.push_back(value);
        self.pending.fetch_add(1, Ordering::SeqCst);
        self.enqueued(1, nmsg);
    }

    /// Publish a signal through its sender's parallel buffer when buffering is enabled.
    // Port of erts/emulator/beam/erl_proc_sig_queue.c:10261 (erts_proc_sig_queue_try_enqueue_to_buffer)
    // and :712 (enqueue_signals), OTP-29.1.1. The sender's buffer slot is hashed only when
    // buffers are installed (erl_proc_sig_queue.c:10271-10288).
    /// Fails, giving the signal back, once the receiver closed its queue.
    pub fn push_routed(&self, slot: impl FnOnce() -> usize, value: T) -> Result<u32, T> {
        let value = match self.try_push_buffer(slot, value) {
            Ok(state) => return Ok(state),
            Err(value) => value,
        };
        let (mut queue, contended) = self.lock_msgq();
        if self.closed.load(Ordering::Relaxed) {
            return Err(value);
        }
        let nmsg = usize::from(!value.is_message());
        queue.push_back(value);
        self.pending.fetch_add(1, Ordering::SeqCst);
        let state = self.enqueued(1, nmsg);
        drop(queue);
        self.note_contention(contended);
        Ok(state)
    }

    fn try_push_buffer(&self, slot: impl FnOnce() -> usize, value: T) -> Result<u32, T> {
        if !self.buffers_enabled.load(Ordering::Acquire) {
            return Err(value);
        }
        let slot = slot();
        let Some(buffers) = self.buffers.lock().unwrap().clone() else {
            return Err(value);
        };
        let mut buffer = buffers[slot % SIGNAL_BUFFER_COUNT].lock().unwrap();
        if !buffer.alive {
            return Err(value);
        }
        let nmsg = usize::from(!value.is_message());
        buffer.queue.push_back(value);
        self.pending.fetch_add(1, Ordering::SeqCst);
        let state = self.enqueued(1, nmsg);
        self.buffer_enqueues.fetch_add(1, Ordering::Relaxed);
        Ok(state)
    }

    /// Enable the per sender buffers, or flush and disable them.
    // Port of erts/emulator/beam/erl_proc_sig_queue.c:10600-10694, OTP-29.1.1.
    pub fn set_buffers_enabled(&self, enabled: bool) {
        // erts toggles the buffers only when the queue mode changes (process_flag or spawn).
        if self.buffering_allowed.load(Ordering::Acquire) == enabled
            && (enabled || !self.buffers_enabled.load(Ordering::Acquire))
        {
            return;
        }
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
        if self.closed.load(Ordering::Relaxed) {
            return;
        }
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
        let nmsgs = Self::count_nmsgs(values.iter());
        queue.extend(values.drain(..));
        self.pending.fetch_add(count, Ordering::SeqCst);
        self.enqueued(count, nmsgs);
    }

    /// Publish a sender ordered block through the matching per sender buffers.
    // Port of erts/emulator/beam/erl_proc_sig_queue.c:10261, OTP-29.1.1.
    /// Fails once the receiver closed its queue; the signals not enqueued stay in `values`.
    pub fn push_block_routed(
        &self,
        values: &mut Vec<T>,
        sender_slot: impl Fn(&T) -> usize,
    ) -> Result<(), QueueClosed> {
        if values.is_empty() {
            return Ok(());
        }
        if !self.buffers_enabled.load(Ordering::Acquire) {
            let (mut queue, contended) = self.lock_msgq();
            if self.closed.load(Ordering::Relaxed) {
                return Err(QueueClosed);
            }
            let count = values.len();
            let nmsgs = Self::count_nmsgs(values.iter());
            queue.extend(values.drain(..));
            self.pending.fetch_add(count, Ordering::SeqCst);
            self.enqueued(count, nmsgs);
            drop(queue);
            self.note_contention(contended);
            return Ok(());
        }
        let mut pending = std::mem::take(values).into_iter();
        while let Some(value) = pending.next() {
            let slot = sender_slot(&value);
            if let Err(value) = self.try_push_buffer(|| slot, value) {
                let (mut queue, _) = self.lock_msgq();
                if self.closed.load(Ordering::Relaxed) {
                    values.push(value);
                    values.extend(pending);
                    return Err(QueueClosed);
                }
                let nmsg = usize::from(!value.is_message());
                queue.push_back(value);
                self.pending.fetch_add(1, Ordering::SeqCst);
                self.enqueued(1, nmsg);
            }
        }
        Ok(())
    }

    /// Close the queue for an exited receiver and move every signal still queued, buffered
    /// ones included, to `into`; enqueues after this fail.
    // Port of erts/emulator/beam/erl_proc_sig_queue.c (erts_proc_sig_handle_exit takes the
    // remaining signals of an exiting process under the msgq lock), OTP-29.1.1.
    pub fn close_into(&self, into: &mut VecDeque<T>) -> usize {
        let mut queue = self.msgq.lock().unwrap();
        self.closed.store(true, Ordering::Relaxed);
        self.uninstall_buffers_locked(&mut queue);
        let count = queue.len();
        if count != 0 {
            let nmsgs = Self::count_nmsgs(queue.iter());
            into.extend(queue.drain(..));
            self.dequeued(count, nmsgs);
        }
        count
    }

    /// Whether any signal waits in the in-queue or its buffers.
    // Port of erts/emulator/beam/erl_proc_sig_queue.c:1547 (pending signal probe), OTP-29.1.1.
    pub fn has_pending(&self) -> bool {
        self.pending.load(Ordering::SeqCst) != 0
    }

    /// Whether a non-message signal waits in the in-queue or its buffers.
    // Port of erts/emulator/beam/erl_process.h (ERTS_PSFLG_NMSG_SIG_IN_Q), OTP-29.1.1.
    pub fn has_pending_nmsg(&self) -> bool {
        self.nmsgs.load(Ordering::SeqCst) != 0
    }

    /// Take the whole in-queue, in order, for the receiver's inner queue: the
    /// receiver handles the signals and moves the messages into its own message queue.
    // Port of erts/emulator/beam/erl_proc_sig_queue.h:1997 (erts_proc_sig_fetch: the outer
    // queue is spliced onto the end of the inner queue under the msgq lock), OTP-29.1.1.
    pub fn take_all(&self, into: &mut VecDeque<T>) {
        if !self.has_pending() {
            return;
        }
        let mut queue = self.msgq.lock().unwrap();
        if self.buffers_enabled.load(Ordering::Acquire) {
            self.flush_buffers_locked(&mut queue, true);
        }
        let count = queue.len();
        let nmsgs = Self::count_nmsgs(queue.iter());
        // Both queues keep their storage: a fetch allocates nothing, like erts splicing
        // the outer signal list onto the inner one.
        into.extend(queue.drain(..));
        self.dequeued(count, nmsgs);
    }

    /// Take the whole in-queue when `accept` takes every queued signal; otherwise leave it.
    /// Returns the number of signals taken.
    // Port of erts/emulator/beam/erl_proc_sig_queue.c:1332 (erts_proc_sig_fetch__: an outer
    // queue without non-message signals is spliced onto the message queue), OTP-29.1.1.
    pub fn take_all_if(&self, accept: impl Fn(&T) -> bool, into: &mut VecDeque<T>) -> usize {
        if !self.has_pending() {
            return 0;
        }
        let mut queue = self.msgq.lock().unwrap();
        if self.buffers_enabled.load(Ordering::Acquire) {
            self.flush_buffers_locked(&mut queue, true);
        }
        if !queue.iter().all(accept) {
            return 0;
        }
        let count = queue.len();
        into.extend(queue.drain(..));
        // `accept` took only messages.
        self.dequeued(count, 0);
        drop(queue);
        let backlog = self.backlog.load(Ordering::Relaxed);
        if backlog != 0 {
            self.backlog
                .fetch_sub(backlog.min(count), Ordering::Relaxed);
        }
        count
    }

    /// Fetch the oldest signal when `accept` takes it, for a receiver whose inner queue
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
        let nmsgs = Self::count_nmsgs(value.iter());
        self.dequeued(1, nmsgs);
        drop(queue);
        if self.backlog.load(Ordering::Relaxed) != 0 {
            self.backlog.fetch_sub(1, Ordering::Relaxed);
        }
        value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    impl InSignal for i32 {
        fn is_message(&self) -> bool {
            *self >= 0
        }
    }

    impl InSignal for (usize, usize) {
        fn is_message(&self) -> bool {
            true
        }
    }

    #[test]
    fn in_queue_state_bits_follow_enqueue_and_fetch() {
        let input = Incoming::default();
        let mut inner = VecDeque::new();
        let bits = |input: &Incoming<i32>| input.state().load(Ordering::SeqCst) & psflg::SIG_IN_Q;
        assert_eq!(bits(&input), 0);
        input.push(1);
        assert_eq!(bits(&input), psflg::MSG_SIG_IN_Q);
        input.push(-1);
        assert_eq!(bits(&input), psflg::SIG_IN_Q);
        assert_eq!(input.fetch_first_if(|_| true), Some(1));
        assert_eq!(bits(&input), psflg::NMSG_SIG_IN_Q);
        input.push(2);
        input.take_all(&mut inner);
        assert_eq!(bits(&input), 0);
        input.push_block(vec![3, 4]);
        assert_eq!(bits(&input), psflg::MSG_SIG_IN_Q);
        assert_eq!(input.take_all_if(|value| *value >= 0, &mut inner), 2);
        assert_eq!(bits(&input), 0);
        assert_eq!(inner, VecDeque::from([-1, 2, 3, 4]));
    }

    #[test]
    fn batch_order() {
        let input = Incoming::default();
        let mut inner = VecDeque::new();
        for i in 0..10 {
            input.push(i);
        }
        input.take_all(&mut inner);
        input.push(20);
        input.take_all(&mut inner);
        assert_eq!(
            inner.into_iter().collect::<Vec<_>>(),
            (0..10).chain([20]).collect::<Vec<_>>()
        );
    }

    #[test]
    fn concurrent_producers_keep_sender_order() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};
        let input = Arc::new(Incoming::default());
        let done = Arc::new(AtomicUsize::new(0));
        let mut inner = VecDeque::new();
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
                input.take_all(&mut inner);
                std::thread::yield_now();
            }
        });
        input.take_all(&mut inner);
        let mut expected = [0; 4];
        while let Some((sender, sequence)) = inner.pop_front() {
            assert_eq!(sequence, expected[sender]);
            expected[sender] += 1;
        }
        assert_eq!(expected, [32; 4]);
    }

    #[test]
    fn parallel_sender_buffer_flush_preserves_sender_order() {
        let input = Incoming::default();
        let mut inner = VecDeque::new();
        input.force_buffers_enabled();
        for sequence in 0..128 {
            input.push_routed(|| 17, sequence).unwrap();
        }
        assert!(input.has_pending());
        input.take_all(&mut inner);
        assert_eq!(
            inner.drain(..).collect::<Vec<_>>(),
            (0..128).collect::<Vec<_>>()
        );

        input.push_routed(|| 17, 128).unwrap();
        input.set_buffers_enabled(false);
        input.push_routed(|| 17, 129).unwrap();
        input.take_all(&mut inner);
        assert_eq!(inner.drain(..).collect::<Vec<_>>(), [128, 129]);
    }
}
