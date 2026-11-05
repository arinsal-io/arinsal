//! The process signal in-queue (erts `ErtsSignalInQueue`) and the receiver-owned middle
//! queue with selective-receive save positions.

use parking_lot::Mutex;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};

use crate::ptab_slot::{Progress, ProgressSlot};
use crate::sig_queue::{OwnedSignal, SignalQueue};
use crate::thr_progress;

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

/// Whether a node is a non-message signal. A lazy node (a monitor half queued as the signal
/// itself) is one without its value being made.
pub(crate) fn non_message_signal<T: InSignal>(signal: &crate::sig_queue::OwnedSignal<T>) -> bool {
    signal.is_lazy() || !signal.is_message()
}

const LOCK_SPIN_UNTIL_YIELD: u32 = 25;
const LOCK_SPIN_COUNT_BASE: u32 = 1000;
const LOCK_SPIN_COUNT_SCHED_INC: u32 = 32;
const LOCK_SPIN_COUNT_MAX: u32 = 2000;

static LOCK_SPIN_COUNT: std::sync::atomic::AtomicU32 =
    std::sync::atomic::AtomicU32::new(LOCK_SPIN_COUNT_BASE);

/// Set the message queue lock spin count for `schedulers` normal schedulers.
// Port of erts/emulator/beam/erl_process_lock.c (erts_init_proc_lock: proc_lock_spin_count),
// OTP-29.1.1; a machine with one cpu does not spin.
pub fn set_lock_spin_count(schedulers: usize) {
    let cpus = std::thread::available_parallelism().map_or(2, usize::from);
    let count = if cpus == 1 {
        0
    } else {
        (LOCK_SPIN_COUNT_BASE + LOCK_SPIN_COUNT_SCHED_INC * schedulers as u32)
            .min(LOCK_SPIN_COUNT_MAX)
    };
    LOCK_SPIN_COUNT.store(count, Ordering::Relaxed);
}

fn lock_spin_count() -> u32 {
    LOCK_SPIN_COUNT.load(Ordering::Relaxed)
}

/// The receiver exited and closed its in-queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueueClosed;

/// One parallel sender buffer (erts `ErtsSignalInQueueBuffer`).
struct SignalBuffer<T> {
    /// Cleared when the buffers are uninstalled; a sender then enqueues directly.
    alive: bool,
    queue: SignalQueue<T>,
}

/// One buffer on its own cache lines, as erts aligns `ErtsSignalInQueueBuffer`.
#[repr(align(128))]
struct PaddedBuffer<T>(Mutex<SignalBuffer<T>>);

/// The sender buffer array (erts `ErtsSignalInQueueBufferArray`). It is reached through an
/// atomic pointer in the process, installed and removed under the msgq lock, and freed after
/// thread progress; a managed thread reads it with a bare load, any other thread holds a
/// reference (erts `dirty_refc`) taken while it delays thread progress.
// Port of erts/emulator/beam/erl_proc_sig_queue.h (ErtsSignalInQueueBufferArray) and
// erl_proc_sig_queue.c:10600-10718, OTP-29.1.1.
struct SignalBuffers<T> {
    /// The thread progress domain that frees this array once it is removed.
    progress: Progress,
    /// Bit `i` is set while buffer `i` may hold signals (`nonempty_slots`).
    nonempty_slots: AtomicU64,
    /// A boxed slice: the array is 8 KiB and would otherwise be built on a small thread stack.
    slots: Box<[PaddedBuffer<T>]>,
}

/// The outer signal queue of a process.
///
/// Port of erts/emulator/beam/erl_proc_sig_queue.h (`ErtsSignalInQueue`, `sig_inq` in
/// `Process`) and erl_proc_sig_queue.c:712-800 (enqueue_signals), OTP-29.1.1: senders
/// append at the tail under the msgq lock; the receiver splices the whole queue into its
/// inner queue under the same lock (erts_proc_sig_fetch).
///
/// Producers for one logical sender must serialize their calls to preserve
/// sender order, just as execution of one Erlang process serializes sends.
pub struct Incoming<T: Send + 'static> {
    /// `ERTS_PROC_LOCK_MSGQ` together with the queue it protects.
    msgq: Mutex<SignalQueue<T>>,
    /// Signals in the sender buffers, counted under each buffer's lock. The signals in the
    /// msgq queue are counted by its length under the msgq lock, so an enqueue through the
    /// queue is one read-modify-write, the bor on `state`. A lock-free probe reads the
    /// `ERTS_PSFLG_SIG_IN_Q` bits of the state word, as erts reads `ERTS_PSFLG_MSG_SIG_IN_Q`.
    buffered: AtomicUsize,
    /// Set under the msgq lock once the receiver exited and took its last signals; later
    /// enqueues fail. Port of erts/emulator/beam/erl_proc_sig_queue.c:712-800
    /// (enqueue_signals checks the receiver's exiting state under the msgq lock), OTP-29.1.1.
    closed: AtomicBool,
    /// `p->state`: the erts process state word. It lives with the in-queue because every
    /// enqueuer, the receiver and its native probe reach the process through this shared
    /// structure.
    // Port of erts/emulator/beam/erl_process.h:1231-1340 (ERTS_PSFLG_*), OTP-29.1.1.
    state: AtomicU32,
    /// Non-message signals in the sender buffers, counted under each buffer's lock; those in
    /// the msgq queue are counted by the queue under the msgq lock (erts keeps `nmsigs` as
    /// plain fields under the lock). With both a fetch leaves exactly the
    /// MSG_SIG_IN_Q/NMSG_SIG_IN_Q bits of the signals still queued (erts re-sets them from
    /// `msgs_in_slots`/`nonmsgs_in_slots` after racing buffer inserts, erl_proc_sig_queue.c:1450).
    buffered_nmsgs: AtomicUsize,
    buffering_allowed: AtomicBool,
    /// `p->sig_inq_buffers`: null while the buffers are not installed.
    buffers: ProgressSlot<SignalBuffers<T>>,
    contention_count: AtomicUsize,
    buffer_enqueues: AtomicUsize,
    enqueues_since_decision: AtomicUsize,
    flush_rounds_left: AtomicUsize,
}

impl<T: Send + 'static> Default for Incoming<T> {
    fn default() -> Self {
        Self {
            msgq: Mutex::new(SignalQueue::default()),
            buffered: AtomicUsize::new(0),
            state: AtomicU32::new(0),
            buffered_nmsgs: AtomicUsize::new(0),
            closed: AtomicBool::new(false),
            buffering_allowed: AtomicBool::new(false),
            buffers: ProgressSlot::new(),
            contention_count: AtomicUsize::new(0),
            buffer_enqueues: AtomicUsize::new(0),
            enqueues_since_decision: AtomicUsize::new(0),
            flush_rounds_left: AtomicUsize::new(BUFFER_FLUSH_ROUNDS),
        }
    }
}

impl<T: Send + 'static> Incoming<T> {
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

impl<T: InSignal + Send + 'static> Incoming<T> {
    /// The in-queue state bits for `count` signals, `nmsgs` of them non-message.
    fn in_queue_flags(count: usize, nmsgs: usize) -> u32 {
        let mut set = 0;
        if count > nmsgs {
            set |= psflg::MSG_SIG_IN_Q;
        }
        if nmsgs != 0 {
            set |= psflg::NMSG_SIG_IN_Q;
        }
        set
    }

    /// Set the in-queue bits for `count` signals appended to the msgq queue, `nmsgs` of them
    /// non-message; the caller holds the msgq lock. Returns the state word with the bits set.
    ///
    /// Like erts, the sender writes the state word only when a bit is missing: `state` is
    /// read under the msgq lock and the bor runs only `if ((state & set_flags) != set_flags)`.
    /// The in-queue bits are cleared only by a fetch under the msgq lock, so bits seen set here
    /// belong to signals of the current queue and the fetch that clears them takes this
    /// signal too. Wake protocol, against the receiver `R` (lib.rs):
    /// 1. Bits missing: the bor is a read-modify-write of the one word `R`'s transition to
    ///    WAITING (`store_from_running`, an RMW as well) also modifies, so they are totally
    ///    ordered. Either the bor returns an inactive word and this sender wakes `R`, or `R`'s
    ///    transition returns the bit set here and its probe sees it.
    /// 2. Bits already set by an earlier signal `S1` (still unfetched, because the fetch that
    ///    clears them needs the lock this sender holds): this sender's load of the word
    ///    returns an active or inactive word. If `R` is inactive at that load, `R` already
    ///    probed (its transition returned, then it loads the bits `S1` set, which stay set)
    ///    and claims itself, or this sender's claim (`schedule_waiting`) wins the CAS: one of
    ///    the two schedules it. If `R` is active at the load, `R`'s later transition to
    ///    WAITING is followed by its probe, which sees `S1`'s bits still set, or a fetch
    ///    between has taken this signal along with `S1` (the fetch needs the lock, so it is
    ///    after this enqueue). erts relies on the same lock: `wait` clears ACTIVE under the
    ///    msgq lock after a failed fetch (emu/msg_instrs.tab, beam_common.c:1596), and
    ///    `enqueue_signals` reads the state under that lock.
    // Port of erts/emulator/beam/erl_proc_sig_queue.c:936-937 (enqueue_signals: conditional
    // erts_atomic32_read_bor_nob) and erl_proc_sig_queue.h:2080 (erts_proc_notify_new_message
    // works from the state read), OTP-29.1.1.
    fn enqueued_locked(&self, count: usize, nmsgs: usize) -> u32 {
        let set = Self::in_queue_flags(count, nmsgs);
        let state = self.state.load(Ordering::SeqCst);
        if state & set == set {
            return state;
        }
        // `erts_atomic32_read_bor_nob`. SeqCst on an RMW is the same instruction as AcqRel
        // and publishes what the sender wrote before the bor to a probe that reads the bit.
        self.state.fetch_or(set, Ordering::SeqCst) | set
    }

    /// Account one signal published into a sender buffer, `nmsgs` 0 or 1 non-message; the
    /// caller holds the buffer's lock, not the msgq lock, so the bits are set with an RMW.
    /// A sender buffer insert counts itself first, so `dequeued` re-checks the counters after
    /// it clears.
    // Port of erts/emulator/beam/erl_proc_sig_queue.c:10369 (enqueue_signals with
    // is_to_buffer), OTP-29.1.1.
    fn enqueued_buffered(&self, nmsgs: usize) -> u32 {
        let set = Self::in_queue_flags(1, nmsgs);
        self.state.fetch_or(set, Ordering::SeqCst) | set
    }

    /// Account signals taken from the queue and leave the in-queue bits of what is still
    /// queued (signals racing into the buffers).
    // Port of erts/emulator/beam/erl_proc_sig_queue.c:1336-1495 (erts_proc_sig_fetch__
    // clear_flags, then re-set for racing buffer inserts), OTP-29.1.1.
    fn dequeued(&self, queue: &SignalQueue<T>) {
        let keep = self.in_queue_bits(queue);
        let clear = psflg::SIG_IN_Q & !keep;
        // `erts_atomic32_read_band_nob`.
        // No read first: the word was just written by a sender, so a load would cost a second
        // coherence transfer before the read-modify-write.
        if clear != 0 {
            self.state.fetch_and(!clear, Ordering::SeqCst);
            // A sender buffer insert that counted itself after the counters were read above
            // sets its bits after the clear, so only one that counted before the read can
            // have lost them: set those again.
            let again = self.in_queue_bits(queue) & clear;
            if again != 0 {
                self.state.fetch_or(again, Ordering::SeqCst);
            }
        }
    }

    /// The in-queue state bits for the signals left in the msgq queue plus the buffered ones.
    fn in_queue_bits(&self, queue: &SignalQueue<T>) -> u32 {
        let left_nmsgs = queue.non_messages() + self.buffered_nmsgs.load(Ordering::SeqCst);
        let left = queue.len() + self.buffered.load(Ordering::SeqCst);
        let mut bits = 0;
        if left > left_nmsgs {
            bits |= psflg::MSG_SIG_IN_Q;
        }
        if left_nmsgs != 0 {
            bits |= psflg::NMSG_SIG_IN_Q;
        }
        bits
    }

    /// Take the msgq lock like `erts_proc_sig_queue_lock`: a busy lock counts as contention, a
    /// free one cancels one. The contention counter lives under the lock.
    // Port of erts/emulator/beam/erl_proc_sig_queue.c:10240 (erts_proc_sig_queue_lock), OTP-29.1.1.
    fn lock_msgq(&self) -> parking_lot::MutexGuard<'_, SignalQueue<T>> {
        if let Some(queue) = self.msgq.try_lock() {
            if self.contention_count.load(Ordering::Relaxed) > 0 {
                self.contention_count.fetch_sub(1, Ordering::Relaxed);
            }
            return queue;
        }
        let queue = self.lock_msgq_failed();
        self.contention_count.fetch_add(1, Ordering::Relaxed);
        queue
    }

    /// Spin on the lock word, yielding every `LOCK_SPIN_UNTIL_YIELD` rounds, and sleep for the
    /// lock when the spin count runs out.
    // Port of erts/emulator/beam/erl_process_lock.c (erts_proc_lock_failed), OTP-29.1.1: a normal
    // scheduler spins `ERTS_PROC_LOCK_SPIN_COUNT_BASE + 32 * schedulers` (at most 2000) rounds
    // of a pause, a thread yield every 25th, and takes the lock with a compare-exchange once the
    // word shows it free. `parking_lot` alone would yield after a handful of pauses.
    #[cold]
    fn lock_msgq_failed(&self) -> parking_lot::MutexGuard<'_, SignalQueue<T>> {
        let mut spin_count = lock_spin_count();
        let mut until_yield = LOCK_SPIN_UNTIL_YIELD;
        loop {
            if spin_count == 0 {
                return self.msgq.lock();
            }
            spin_count -= 1;
            std::hint::spin_loop();
            until_yield -= 1;
            if until_yield == 0 {
                until_yield = LOCK_SPIN_UNTIL_YIELD;
                std::thread::yield_now();
            }
            if !self.msgq.is_locked()
                && let Some(queue) = self.msgq.try_lock()
            {
                return queue;
            }
        }
    }

    /// Append an event, flushing the sender buffers first so it cannot overtake them.
    // Port of erts/emulator/beam/erl_proc_sig_queue.c:712 (signal enqueue), OTP-29.1.1.
    pub fn push(&self, value: T) {
        let signal = OwnedSignal::new(value);
        let nmsg = usize::from(non_message_signal(&signal));
        let mut queue = self.lock_msgq();
        if self.buffers.is_occupied() {
            self.flush_buffers_locked(&mut queue, true);
        }
        queue.push_back_node(signal);
        self.enqueued_locked(1, nmsg);
    }

    /// Publish a signal through its sender's parallel buffer when buffering is enabled.
    // Port of erts/emulator/beam/erl_proc_sig_queue.c:10261 (erts_proc_sig_queue_try_enqueue_to_buffer)
    // and :712 (enqueue_signals), OTP-29.1.1. The sender's buffer slot is hashed only when
    // buffers are installed (erl_proc_sig_queue.c:10271-10288).
    /// Fails, giving the signal back, once the receiver closed its queue.
    #[cfg(test)]
    pub(crate) fn push_routed(
        &self,
        progress: &Progress,
        slot: impl FnOnce() -> usize,
        value: T,
    ) -> Result<u32, T> {
        self.push_routed_node(progress, slot, OwnedSignal::new(value))
            .map_err(OwnedSignal::into_value)
    }

    /// [`Incoming::push_routed`] of a signal node the sender allocated (erts enqueues the
    /// `ErtsMessage` the sender built). Gives the node back once the receiver closed its queue.
    pub(crate) fn push_routed_node(
        &self,
        progress: &Progress,
        slot: impl FnOnce() -> usize,
        signal: OwnedSignal<T>,
    ) -> Result<u32, OwnedSignal<T>> {
        let signal = match self.try_push_buffer(progress, slot, signal) {
            Ok(state) => return Ok(state),
            Err(signal) => signal,
        };
        let mut queue = self.lock_msgq();
        self.maybe_install_buffers_locked(progress);
        if self.closed.load(Ordering::Relaxed) {
            return Err(signal);
        }
        let nmsg = usize::from(non_message_signal(&signal));
        queue.push_back_node(signal);
        let state = self.enqueued_locked(1, nmsg);
        drop(queue);
        Ok(state)
    }

    /// Run `f` on the installed buffer array, if any.
    // Port of erts/emulator/beam/erl_proc_sig_queue.h:1936 (erts_proc_sig_queue_get_buffers) and
    // :1957 (erts_proc_sig_queue_unget_buffers), OTP-29.1.1: a managed thread reads the pointer
    // and needs no reference; any other thread takes a reference while it delays thread progress.
    fn with_buffers<R>(
        &self,
        progress: &Progress,
        f: impl FnOnce(&SignalBuffers<T>) -> R,
    ) -> Option<R> {
        if thr_progress::is_managed_thread_of(&progress.0) {
            self.buffers.with_managed(f)
        } else {
            let buffers = self.buffers.load_arc(progress, false)?;
            Some(f(&buffers))
        }
    }

    // Port of erts/emulator/beam/erl_proc_sig_queue.c:10261 (erts_proc_sig_queue_try_enqueue_to_buffer),
    // OTP-29.1.1.
    fn try_push_buffer(
        &self,
        progress: &Progress,
        slot: impl FnOnce() -> usize,
        signal: OwnedSignal<T>,
    ) -> Result<u32, OwnedSignal<T>> {
        if !self.buffers.is_occupied() {
            return Err(signal);
        }
        let mut signal = Some(signal);
        let state = self.with_buffers(progress, |buffers| {
            let slot = slot() % SIGNAL_BUFFER_COUNT;
            let mut buffer = buffers.slots[slot].0.lock();
            if !buffer.alive {
                return None;
            }
            let signal = signal.take()?;
            let nmsg = usize::from(non_message_signal(&signal));
            if buffer.queue.is_empty() {
                // The slot becomes nonempty before the signal is in it, so a flush that
                // clears the mask finds the signal or the slot is visited again.
                buffers.nonempty_slots.fetch_or(1 << slot, Ordering::SeqCst);
            }
            buffer.queue.push_back_node(signal);
            self.buffered.fetch_add(1, Ordering::SeqCst);
            if nmsg != 0 {
                self.buffered_nmsgs.fetch_add(nmsg, Ordering::SeqCst);
            }
            let state = self.enqueued_buffered(nmsg);
            self.buffer_enqueues.fetch_add(1, Ordering::Relaxed);
            Some(state)
        });
        match state.flatten() {
            Some(state) => Ok(state),
            None => Err(signal.expect("a signal not buffered is still held")),
        }
    }

    /// Enable the per sender buffers, or flush and disable them.
    // Port of erts/emulator/beam/erl_proc_sig_queue.c:10600-10694, OTP-29.1.1.
    pub fn set_buffers_enabled(&self, enabled: bool) {
        // erts toggles the buffers only when the queue mode changes (process_flag or spawn).
        if self.buffering_allowed.load(Ordering::Acquire) == enabled
            && (enabled || !self.buffers.is_occupied())
        {
            return;
        }
        if !enabled {
            let mut queue = self.msgq.lock();
            self.uninstall_buffers_locked(&mut queue);
        }
        self.buffering_allowed.store(enabled, Ordering::Release);
    }

    /// Force installation for the test hook that enables OTP's adaptive optimization.
    // Port of erts/emulator/beam/erl_proc_sig_queue.c:10700-10718, OTP-29.1.1.
    pub(crate) fn force_buffers_enabled(&self, progress: &Progress) {
        let _queue = self.msgq.lock();
        self.buffering_allowed.store(true, Ordering::Release);
        self.install_buffers_locked(progress);
    }

    /// Install buffers once enough contention was counted; the caller holds the msgq lock.
    // Port of erts/emulator/beam/erl_proc_sig_queue.c:10658 (erts_proc_sig_queue_maybe_install_buffers),
    // OTP-29.1.1: the off-heap queue flag is `buffering_allowed`; the counter limit is checked
    // right after the lock is taken, before the signal is enqueued.
    fn maybe_install_buffers_locked(&self, progress: &Progress) {
        if self.buffering_allowed.load(Ordering::Acquire)
            && !self.buffers.is_occupied()
            && self.contention_count.load(Ordering::Relaxed) > BUFFER_CONTENTION_INSTALL_LIMIT
        {
            self.install_buffers_locked(progress);
        }
    }

    /// Install fresh buffers; the caller holds the msgq lock.
    // Port of erts/emulator/beam/erl_proc_sig_queue.c:10661-10694
    // (erts_proc_sig_queue_maybe_install_buffers), OTP-29.1.1: the pointer is published with
    // release order after the array is initialized.
    fn install_buffers_locked(&self, progress: &Progress) {
        if self.closed.load(Ordering::Relaxed) || self.buffers.is_occupied() {
            return;
        }
        self.contention_count.store(0, Ordering::Relaxed);
        self.flush_rounds_left
            .store(BUFFER_FLUSH_ROUNDS, Ordering::Relaxed);
        self.buffer_enqueues.store(0, Ordering::Relaxed);
        self.enqueues_since_decision.store(0, Ordering::Relaxed);
        self.buffers.store(
            Arc::new(SignalBuffers {
                progress: progress.clone(),
                nonempty_slots: AtomicU64::new(0),
                slots: (0..SIGNAL_BUFFER_COUNT)
                    .map(|_| {
                        PaddedBuffer(Mutex::new(SignalBuffer {
                            alive: true,
                            queue: SignalQueue::default(),
                        }))
                    })
                    .collect(),
            }),
            Some(progress),
        );
    }

    /// Flush, mark dead and remove the buffers; the caller holds the msgq lock.
    // Port of erts/emulator/beam/erl_proc_sig_queue.c:10596-10655
    // (erts_proc_sig_queue_flush_and_deinstall_buffers), OTP-29.1.1: only the msgq lock holder
    // installs or removes the array, so it reads the pointer without a reference; the array is
    // freed by a later operation after thread progress (`take`).
    fn uninstall_buffers_locked(&self, queue: &mut SignalQueue<T>) {
        let progress = self.buffers.with_managed(|buffers| {
            for buffer in &buffers.slots {
                let mut buffer = buffer.0.lock();
                buffer.alive = false;
                self.take_buffered(&mut buffer, queue);
            }
            // Nothing can be enqueued to the buffer array beyond this point.
            buffers.nonempty_slots.store(0, Ordering::SeqCst);
            buffers.progress.clone()
        });
        if let Some(progress) = progress {
            drop(self.buffers.take(&progress));
        }
        self.contention_count.store(0, Ordering::Relaxed);
        self.buffer_enqueues.store(0, Ordering::Relaxed);
        self.enqueues_since_decision.store(0, Ordering::Relaxed);
        self.flush_rounds_left
            .store(BUFFER_FLUSH_ROUNDS, Ordering::Relaxed);
    }

    /// Move one buffer's signals to the queue tail; the caller holds the msgq lock and the
    /// buffer's lock, under which the count of buffered signals changes with the buffer.
    fn take_buffered(&self, buffer: &mut SignalBuffer<T>, queue: &mut SignalQueue<T>) {
        let count = buffer.queue.len();
        if count != 0 {
            let nmsgs = buffer.queue.non_messages();
            queue.append(&mut buffer.queue);
            self.buffered.fetch_sub(count, Ordering::Relaxed);
            if nmsgs != 0 {
                self.buffered_nmsgs.fetch_sub(nmsgs, Ordering::Relaxed);
            }
        }
    }

    /// Move buffered signals to the queue tail; the caller holds the msgq lock.
    // Port of erts/emulator/beam/erl_proc_sig_queue.c:10532 (proc_sig_queue_flush_buffers),
    // OTP-29.1.1: the nonempty mask is exchanged to zero and only its buffers are visited.
    fn flush_buffers_locked(&self, queue: &mut SignalQueue<T>, adapt: bool) {
        let Some(()) = self.buffers.with_managed(|buffers| {
            let mut nonempty = buffers.nonempty_slots.swap(0, Ordering::SeqCst);
            while nonempty != 0 {
                let slot = nonempty.trailing_zeros() as usize;
                nonempty &= nonempty - 1;
                self.take_buffered(&mut buffers.slots[slot].0.lock(), queue);
            }
        }) else {
            return;
        };
        if adapt {
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
        let mut block = SignalQueue::default();
        for value in values.drain(..) {
            block.push_back(value);
        }
        let (count, nmsgs) = (block.len(), block.non_messages());
        let mut queue = self.lock_msgq();
        if self.buffers.is_occupied() {
            self.flush_buffers_locked(&mut queue, true);
        }
        queue.append(&mut block);
        self.enqueued_locked(count, nmsgs);
    }

    /// Publish a sender ordered block through the matching per sender buffers.
    // Port of erts/emulator/beam/erl_proc_sig_queue.c:10261, OTP-29.1.1.
    /// Fails once the receiver closed its queue; the signals not enqueued stay in `values`.
    pub(crate) fn push_block_routed(
        &self,
        progress: &Progress,
        values: &mut Vec<OwnedSignal<T>>,
        sender_slot: impl Fn(&OwnedSignal<T>) -> usize,
    ) -> Result<(), QueueClosed> {
        if values.is_empty() {
            return Ok(());
        }
        if !self.buffers.is_occupied() {
            let mut block = SignalQueue::default();
            let mut queue = self.lock_msgq();
            self.maybe_install_buffers_locked(progress);
            if self.closed.load(Ordering::Relaxed) {
                return Err(QueueClosed);
            }
            for signal in values.drain(..) {
                block.push_back_node(signal);
            }
            let (count, nmsgs) = (block.len(), block.non_messages());
            queue.append(&mut block);
            self.enqueued_locked(count, nmsgs);
            drop(queue);
            return Ok(());
        }
        let mut pending = std::mem::take(values).into_iter();
        while let Some(signal) = pending.next() {
            let slot = sender_slot(&signal);
            if let Err(signal) = self.try_push_buffer(progress, || slot, signal) {
                let mut queue = self.lock_msgq();
                if self.closed.load(Ordering::Relaxed) {
                    values.push(signal);
                    values.extend(pending);
                    return Err(QueueClosed);
                }
                let nmsg = usize::from(non_message_signal(&signal));
                queue.push_back_node(signal);
                self.enqueued_locked(1, nmsg);
            }
        }
        Ok(())
    }

    /// Publish two signals of one sender with one enqueue when no sender buffers are
    /// installed. Gives both back, in order, when the buffers are installed (the caller takes
    /// the block path) or the receiver closed its queue.
    // Port of erts/emulator/beam/erl_proc_sig_queue.c:1146-1165 (proc_queue_signal prepends the
    // pending signal to the new one and enqueues both), OTP-29.1.1.
    pub(crate) fn push_pair(
        &self,
        progress: &Progress,
        first: OwnedSignal<T>,
        second: OwnedSignal<T>,
    ) -> Result<(), (OwnedSignal<T>, OwnedSignal<T>)> {
        if self.buffers.is_occupied() {
            return Err((first, second));
        }
        let nmsgs =
            usize::from(non_message_signal(&first)) + usize::from(non_message_signal(&second));
        let mut queue = self.lock_msgq();
        self.maybe_install_buffers_locked(progress);
        if self.closed.load(Ordering::Relaxed) {
            return Err((first, second));
        }
        queue.push_back_node(first);
        queue.push_back_node(second);
        self.enqueued_locked(2, nmsgs);
        drop(queue);
        Ok(())
    }

    /// Close the queue for an exited receiver and move every signal still queued, buffered
    /// ones included, to `into`; enqueues after this fail.
    // Port of erts/emulator/beam/erl_proc_sig_queue.c (erts_proc_sig_handle_exit takes the
    // remaining signals of an exiting process under the msgq lock), OTP-29.1.1.
    pub fn close_into(&self, into: &mut SignalQueue<T>) -> usize {
        let mut queue = self.msgq.lock();
        self.closed.store(true, Ordering::Relaxed);
        self.uninstall_buffers_locked(&mut queue);
        let count = queue.len();
        if count != 0 {
            into.append(&mut queue);
            self.dequeued(&queue);
        }
        count
    }

    /// Whether any signal waits in the in-queue or its buffers.
    // Port of erts/emulator/beam/erl_proc_sig_queue.c:1547 (pending signal probe), OTP-29.1.1.
    pub fn has_pending(&self) -> bool {
        self.state.load(Ordering::SeqCst) & psflg::SIG_IN_Q != 0
    }

    /// Whether a non-message signal waits in the in-queue or its buffers.
    // Port of erts/emulator/beam/erl_process.h (ERTS_PSFLG_NMSG_SIG_IN_Q), OTP-29.1.1.
    pub fn has_pending_nmsg(&self) -> bool {
        self.state.load(Ordering::SeqCst) & psflg::NMSG_SIG_IN_Q != 0
    }

    /// Take the whole in-queue, in order, for the receiver's inner queue: the
    /// receiver handles the signals and moves the messages into its own message queue.
    // Port of erts/emulator/beam/erl_proc_sig_queue.h:1997 (erts_proc_sig_fetch: the outer
    // queue is spliced onto the end of the inner queue under the msgq lock), OTP-29.1.1.
    pub fn take_all(&self, into: &mut SignalQueue<T>) {
        if !self.has_pending() {
            return;
        }
        let mut queue = self.lock_msgq();
        if self.buffers.is_occupied() {
            self.flush_buffers_locked(&mut queue, true);
        }
        into.append(&mut queue);
        self.dequeued(&queue);
    }

    /// Take the whole in-queue when `accept` takes every queued signal; otherwise leave it.
    /// Returns the number of signals taken.
    // Port of erts/emulator/beam/erl_proc_sig_queue.c:1332 (erts_proc_sig_fetch__: an outer
    // queue without non-message signals is spliced onto the message queue), OTP-29.1.1.
    pub fn take_all_if(&self, _accept: impl Fn(&T) -> bool, into: &mut SignalQueue<T>) -> usize {
        if !self.has_pending() {
            return 0;
        }
        let mut queue = self.lock_msgq();
        if self.buffers.is_occupied() {
            self.flush_buffers_locked(&mut queue, true);
        }
        if queue.non_messages() != 0 {
            return 0;
        }
        let count = queue.len();
        into.append(&mut queue);
        // `accept` took only messages.
        self.dequeued(&queue);
        drop(queue);
        count
    }

    /// Fetch the oldest signal when `accept` takes it, for a receiver whose inner queue
    /// is empty. The receiver handles it in place, like erts' receive helper fetching
    /// the outer queue before matching.
    // Port of erts/emulator/beam/erl_proc_sig_queue.c:7730-7790 (erts_proc_sig_receive_helper),
    // OTP-29.1.1.
    pub fn fetch_first_if(&self, accept: impl FnOnce(&T) -> bool) -> Option<T> {
        let mut queue = self.lock_msgq();
        if self.buffers.is_occupied() {
            self.flush_buffers_locked(&mut queue, true);
        }
        if !accept(queue.front()?) {
            return None;
        }
        let signal = queue.pop_front_signal()?;
        self.dequeued(&queue);
        drop(queue);
        Some(signal.into_value())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_progress() -> Progress {
        Progress(Arc::new(thr_progress::ThrProgress::new(
            Arc::from([]),
            Arc::from([]),
        )))
    }

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
        let mut inner = SignalQueue::default();
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
        assert_eq!(inner.iter().copied().collect::<Vec<_>>(), [-1, 2, 3, 4]);
    }

    #[test]
    fn batch_order() {
        let input = Incoming::default();
        let mut inner = SignalQueue::default();
        for i in 0..10 {
            input.push(i);
        }
        input.take_all(&mut inner);
        input.push(20);
        input.take_all(&mut inner);
        assert_eq!(
            inner.iter().copied().collect::<Vec<_>>(),
            (0..10).chain([20]).collect::<Vec<_>>()
        );
    }

    #[test]
    fn concurrent_producers_keep_sender_order() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};
        let input = Arc::new(Incoming::default());
        let done = Arc::new(AtomicUsize::new(0));
        let mut inner = SignalQueue::default();
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
        let progress = test_progress();
        let mut inner = SignalQueue::default();
        input.force_buffers_enabled(&progress);
        for sequence in 0..128 {
            input.push_routed(&progress, || 17, sequence).unwrap();
        }
        assert!(input.has_pending());
        input.take_all(&mut inner);
        assert_eq!(
            std::iter::from_fn(|| inner.pop_front()).collect::<Vec<_>>(),
            (0..128).collect::<Vec<_>>()
        );

        input.push_routed(&progress, || 17, 128).unwrap();
        input.set_buffers_enabled(false);
        input.push_routed(&progress, || 17, 129).unwrap();
        input.take_all(&mut inner);
        assert_eq!(
            std::iter::from_fn(|| inner.pop_front()).collect::<Vec<_>>(),
            [128, 129]
        );
    }

    /// Senders race with the receiver installing, flushing and removing the buffer array:
    /// nothing is lost or duplicated and each sender's order is kept.
    #[test]
    fn buffer_array_lifetime_under_install_and_removal() {
        use std::sync::atomic::AtomicUsize;
        const SENDERS: usize = 4;
        const PER_SENDER: usize = 20_000;
        let input = Arc::new(Incoming::<(usize, usize)>::default());
        let progress = test_progress();
        let done = Arc::new(AtomicUsize::new(0));
        let mut inner = SignalQueue::default();
        let mut round = 0usize;
        std::thread::scope(|scope| {
            for sender in 0..SENDERS {
                let (input, progress, done) = (input.clone(), progress.clone(), done.clone());
                scope.spawn(move || {
                    for sequence in 0..PER_SENDER {
                        // Same slot per sender, as the hash of the sender pid does.
                        input
                            .push_routed(&progress, || sender, (sender, sequence))
                            .unwrap();
                    }
                    done.fetch_add(1, Ordering::Release);
                });
            }
            while done.load(Ordering::Acquire) < SENDERS || input.has_pending() {
                round += 1;
                match round % 4 {
                    0 => input.force_buffers_enabled(&progress),
                    1 => input.set_buffers_enabled(false),
                    _ => {}
                }
                input.take_all(&mut inner);
                std::thread::yield_now();
            }
        });
        input.take_all(&mut inner);
        let mut expected = [0; SENDERS];
        while let Some((sender, sequence)) = inner.pop_front() {
            assert_eq!(sequence, expected[sender]);
            expected[sender] += 1;
        }
        assert_eq!(expected, [PER_SENDER; SENDERS]);
    }
}
