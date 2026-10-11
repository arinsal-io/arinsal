//! Thread progress for the managed (normal scheduler) threads.
//!
//! Port of erts/emulator/beam/erl_thr_progress.c and erl_thr_progress.h, OTP-29.1.1. Each
//! managed thread confirms the global progress value it has observed in its own slot; the
//! leader advances the global value once every managed thread confirmed it or waits. A
//! thread that needs every managed thread to pass a point (`block`) sets a flag that the
//! managed threads honour at their next progress update. Operations scheduled with
//! [`schedule_later_op`] run once the global value has reached `confirmed + 2`.
//!
//! Unmanaged threads (dirty schedulers, the main thread) may block and unblock thread
//! progress and schedule later operations; erts' unmanaged delay handles
//! (`erts_thr_progress_unmanaged_delay`) have no user here and are not ported.

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering, fence};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::thread::Thread;

/// An operation that runs once every managed thread passed a thread progress point.
pub(crate) type LaterOp = Box<dyn FnOnce() + Send>;

/// `ERTS_THR_PRGR_VAL_WAITING`.
const VAL_WAITING: u64 = u64::MAX;
/// `ERTS_THR_PRGR_LFLG_BLOCK`.
const LFLG_BLOCK: u32 = 1 << 31;
/// `ERTS_THR_PRGR_LFLG_NO_LEADER`.
const LFLG_NO_LEADER: u32 = 1 << 30;
/// `ERTS_THR_PRGR_LFLG_WAITING_UM`; never set without unmanaged delay handles.
const LFLG_WAITING_UM: u32 = 1 << 29;
/// `ERTS_THR_PRGR_LFLG_ACTIVE_MASK`: the count of active managed threads.
const LFLG_ACTIVE_MASK: u32 = !(LFLG_NO_LEADER | LFLG_BLOCK | LFLG_WAITING_UM);
/// `ERTS_THR_PRGR_BC_FLG_NOT_BLOCKING`.
const BC_FLG_NOT_BLOCKING: u32 = 1 << 31;
/// `ERTS_THR_PRGR_WAKEUP_DATA_SIZE`.
const WAKEUP_DATA_SIZE: usize = 4;

fn next_val(val: u64) -> u64 {
    let next = val.wrapping_add(1);
    if next == VAL_WAITING { 0 } else { next }
}

// Port of erl_thr_progress.h (erts_thr_progress_current_to_later__), OTP-29.1.1.
fn current_to_later(val: u64) -> u64 {
    if val == VAL_WAITING - 2 {
        0
    } else if val == VAL_WAITING - 1 {
        1
    } else {
        val + 2
    }
}

// Port of erl_thr_progress.h (erts_thr_progress_has_passed__), OTP-29.1.1.
fn has_passed(val1: u64, val0: u64) -> bool {
    if ((1u64 << 63) & val1) ^ ((1u64 << 63) & val0) != 0
        && val1 < (1u64 << 62)
        && val0 > (3u64 << 62)
    {
        // `val1` has wrapped but `val0` has not yet wrapped.
        return true;
    }
    val1 > val0
}

// Port of erl_thr_progress.h (erts_thr_progress_has_reached_this), OTP-29.1.1.
fn has_reached_this(this: u64, val: u64) -> bool {
    this == val || has_passed(this, val)
}

// Port of erl_thr_progress.h (erts_thr_progress_cmp), OTP-29.1.1.
fn cmp(val1: u64, val2: u64) -> std::cmp::Ordering {
    if val1 == val2 {
        std::cmp::Ordering::Equal
    } else if has_passed(val1, val2) {
        std::cmp::Ordering::Greater
    } else {
        std::cmp::Ordering::Less
    }
}

/// One managed thread's confirmed value on its own cache line (erts `ErtsThrPrgrArray`).
#[repr(align(128))]
struct Slot(AtomicU64);

/// Managed threads to wake when the global value reaches an index (erts
/// `ErtsThrPrgrManagedWakeupData`).
struct WakeupData {
    len: AtomicU32,
    id: Box<[AtomicUsize]>,
}

/// Shared thread progress state (erts `ErtsThrPrgrInternalData` and `erts_thr_prgr__`).
pub(crate) struct ThrProgress {
    current: AtomicU64,
    thr: Box<[Slot]>,
    lflgs: AtomicU32,
    block_count: AtomicU32,
    /// The blocker's event (`blocker_event`) and the wait of unmanaged threads for an
    /// unblock.
    event: (Mutex<()>, Condvar),
    wakeup: [WakeupData; WAKEUP_DATA_SIZE],
    /// Worker sleep state shared with the scheduler: waking a managed thread ends its
    /// spin and unparks it (the managed `wakeup` callback, erl_process.c ssi_wake).
    parked: Arc<[AtomicBool]>,
    sleepers: Arc<[OnceLock<Thread>]>,
    /// Later operations scheduled from unmanaged threads, run by any managed thread.
    unmanaged_later: Mutex<VecDeque<(u64, LaterOp)>>,
    unmanaged_later_len: AtomicUsize,
}

/// Per thread data of a managed thread (erts `ErtsThrPrgrData`) and its later operations
/// (erts `ErtsAuxWorkData.later_op`).
struct ThrPrgrData {
    progress: Arc<ThrProgress>,
    id: usize,
    is_blocking: u32,
    leader: bool,
    active: bool,
    confirmed: u64,
    leader_current: u64,
    leader_next: u64,
    chk_next_ix: usize,
    wakeup_request: [u64; WAKEUP_DATA_SIZE],
    later_ops: VecDeque<(u64, LaterOp)>,
    latest_wakeup: u64,
}

thread_local! {
    /// erts `erts_thr_prgr_data_key__`.
    static TPD: RefCell<Option<ThrPrgrData>> = const { RefCell::new(None) };
    /// Block nesting of an unmanaged thread (erts temporary `ErtsThrPrgrData`).
    static UNMANAGED_BLOCKING: Cell<u32> = const { Cell::new(0) };
    /// Later operations of a runtime without managed threads (the simulated scheduler):
    /// no thread can be in the middle of a slice, so they run after the current one.
    static LATER_READY: RefCell<Vec<LaterOp>> = const { RefCell::new(Vec::new()) };
}

impl ThrProgress {
    /// Port of erl_thr_progress.c:396 (erts_thr_progress_init), OTP-29.1.1.
    pub(crate) fn new(parked: Arc<[AtomicBool]>, sleepers: Arc<[OnceLock<Thread>]>) -> Self {
        let managed = parked.len();
        let wakeup = std::array::from_fn(|_| WakeupData {
            len: AtomicU32::new(0),
            id: (0..managed).map(|_| AtomicUsize::new(0)).collect(),
        });
        Self {
            current: AtomicU64::new(0),
            thr: (0..managed).map(|_| Slot(AtomicU64::new(0))).collect(),
            lflgs: AtomicU32::new(LFLG_NO_LEADER),
            block_count: AtomicU32::new(BC_FLG_NOT_BLOCKING | managed as u32),
            event: (Mutex::new(()), Condvar::new()),
            wakeup,
            parked,
            sleepers,
            unmanaged_later: Mutex::new(VecDeque::new()),
            unmanaged_later_len: AtomicUsize::new(0),
        }
    }

    fn managed_no(&self) -> usize {
        self.thr.len()
    }

    /// The managed `wakeup` callback (erts wakeup_managed).
    fn wakeup_managed(&self, id: usize) {
        self.parked[id].store(false, Ordering::SeqCst);
        if let Some(thread) = self.sleepers[id].get() {
            thread.unpark();
        }
    }

    fn notify_event(&self) {
        let _guard = self.event.0.lock().unwrap();
        self.event.1.notify_all();
    }

    // Port of erl_thr_progress.c:361 (block_count_dec), OTP-29.1.1.
    fn block_count_dec(&self) -> bool {
        let block_count = self.block_count.fetch_sub(1, Ordering::SeqCst) - 1;
        if block_count == 0 {
            self.notify_event();
            return true;
        }
        block_count & BC_FLG_NOT_BLOCKING == 0
    }

    // Port of erl_thr_progress.c:378 (block_count_inc), OTP-29.1.1.
    fn block_count_inc(&self) -> bool {
        let block_count = self.block_count.fetch_add(1, Ordering::SeqCst) + 1;
        block_count & BC_FLG_NOT_BLOCKING == 0
    }

    // Port of erl_thr_progress.c:1048 (has_reached_wakeup), OTP-29.1.1.
    fn has_reached_wakeup(&self, wakeup: u64) -> bool {
        has_reached_this(self.current.load(Ordering::Acquire), wakeup)
    }

    // Port of erl_thr_progress.c:1268 (handle_wakeup_requests), OTP-29.1.1.
    fn handle_wakeup_requests(&self, current: u64) {
        let data = &self.wakeup[(current as usize) & (WAKEUP_DATA_SIZE - 1)];
        let len = data.len.load(Ordering::Acquire) as usize;
        if len != 0 {
            for id in &data.id[..len] {
                self.wakeup_managed(id.load(Ordering::Acquire));
            }
            data.len.store(0, Ordering::Relaxed);
        }
    }

    // Port of erl_thr_progress.c:1288 (got_sched_wakeups), OTP-29.1.1.
    fn got_sched_wakeups(&self) -> bool {
        fence(Ordering::SeqCst);
        self.wakeup
            .iter()
            .any(|data| data.len.load(Ordering::Relaxed) != 0)
    }

    /// Whether the global value has reached `val` (erts erts_thr_progress_has_reached).
    #[cfg(test)]
    fn has_reached(&self, val: u64) -> bool {
        has_reached_this(self.current.load(Ordering::Acquire), val)
    }
}

// Port of erl_thr_progress.c:1308 (block_thread), OTP-29.1.1: the managed `prepare_wait`
// and `wait` callbacks are the thread's own park.
fn block_thread(tpd: &mut ThrPrgrData) -> u32 {
    let progress = Arc::clone(&tpd.progress);
    let mut lflgs;
    loop {
        progress.block_count_dec();
        loop {
            lflgs = progress.lflgs.load(Ordering::Acquire);
            if lflgs & LFLG_BLOCK != 0 {
                std::thread::park();
            } else {
                break;
            }
        }
        if !progress.block_count_inc() {
            break;
        }
    }
    lflgs
}

// Port of erl_thr_progress.c:660 (leader_update), OTP-29.1.1, without unmanaged threads.
fn leader_update(tpd: &mut ThrPrgrData) -> bool {
    if !tpd.leader {
        // Probably need to block...
        block_thread(tpd);
        return tpd.leader;
    }
    let progress = Arc::clone(&tpd.progress);
    let my_ix = tpd.id;
    if tpd.leader_current == VAL_WAITING {
        // Took over as leader from another thread.
        tpd.leader_current = progress.current.load(Ordering::Relaxed);
        tpd.leader_next = next_val(tpd.leader_current);
        tpd.chk_next_ix = 0;
        if tpd.confirmed == tpd.leader_current {
            let val = next_val(tpd.leader_current);
            tpd.confirmed = val;
            progress.thr[my_ix].0.store(val, Ordering::SeqCst);
        }
    }
    let next = tpd.leader_next;
    let no_managed = progress.managed_no();
    let mut caught_up = true;
    for ix in tpd.chk_next_ix..no_managed {
        if ix == my_ix {
            continue;
        }
        let tmp = progress.thr[ix].0.load(Ordering::Acquire);
        if tmp != next && tmp != VAL_WAITING {
            tpd.chk_next_ix = ix;
            caught_up = false;
            break;
        }
    }
    if caught_up {
        // Make progress.
        let current = next;
        let next = next_val(next);
        progress.thr[my_ix].0.store(next, Ordering::Relaxed);
        progress.current.store(current, Ordering::SeqCst);
        tpd.confirmed = next;
        tpd.leader_next = next;
        tpd.leader_current = current;
        progress.handle_wakeup_requests(current);
        tpd.chk_next_ix = 0;
    }
    if tpd.active {
        if progress.lflgs.load(Ordering::Relaxed) & LFLG_BLOCK != 0 {
            block_thread(tpd);
        }
    } else {
        tpd.leader = false;
        tpd.leader_current = VAL_WAITING;
        let lflgs = progress.lflgs.fetch_or(LFLG_NO_LEADER, Ordering::Release) | LFLG_NO_LEADER;
        if lflgs & LFLG_BLOCK != 0 {
            block_thread(tpd);
        }
    }
    tpd.leader
}

// Port of erl_thr_progress.c:821 (update), OTP-29.1.1.
fn update(tpd: &mut ThrPrgrData) -> bool {
    if tpd.leader {
        return true;
    }
    let progress = &tpd.progress;
    let val = progress.current.load(Ordering::Acquire);
    if tpd.confirmed == val {
        let val = next_val(val);
        tpd.confirmed = val;
        progress.thr[tpd.id].0.store(val, Ordering::SeqCst);
    }
    let lflgs = progress.lflgs.load(Ordering::Relaxed);
    // Need to block in leader_update().
    let mut res = lflgs & LFLG_BLOCK != 0;
    if lflgs & LFLG_NO_LEADER != 0 && (tpd.active || lflgs & LFLG_ACTIVE_MASK == 0) {
        // Try to take over leadership.
        let old = progress.lflgs.fetch_and(!LFLG_NO_LEADER, Ordering::Acquire);
        if old & LFLG_NO_LEADER != 0 {
            tpd.leader = true;
        }
    }
    res |= tpd.leader;
    res
}

// Port of erl_thr_progress.c:884 (erts_thr_progress_prepare_wait), OTP-29.1.1.
fn prepare_wait(tpd: &mut ThrPrgrData) {
    let progress = Arc::clone(&tpd.progress);
    progress.block_count_dec();
    tpd.confirmed = VAL_WAITING;
    progress.thr[tpd.id].0.store(VAL_WAITING, Ordering::SeqCst);
    let lflgs = progress.lflgs.load(Ordering::Relaxed);
    if lflgs & (LFLG_NO_LEADER | LFLG_WAITING_UM | LFLG_ACTIVE_MASK) == LFLG_NO_LEADER
        && progress.got_sched_wakeups()
    {
        // Someone needs to make progress.
        progress.wakeup_managed(tpd.id);
    }
}

// Port of erl_thr_progress.c:913 (erts_thr_progress_finalize_wait), OTP-29.1.1.
fn finalize_wait(tpd: &mut ThrPrgrData) {
    let progress = Arc::clone(&tpd.progress);
    // Not allowed to continue until this thread's progress is past global current.
    let mut current = progress.current.load(Ordering::Acquire);
    let mut val = current;
    loop {
        val = next_val(val);
        tpd.confirmed = val;
        progress.thr[tpd.id].0.store(val, Ordering::SeqCst);
        val = progress.current.load(Ordering::Acquire);
        if current == val {
            break;
        }
        current = val;
    }
    if progress.block_count_inc() {
        block_thread(tpd);
    }
    if update(tpd) {
        leader_update(tpd);
    }
}

// Port of erl_thr_progress.c:952 (erts_thr_progress_active), OTP-29.1.1.
fn set_active(tpd: &mut ThrPrgrData, on: bool) {
    if on {
        tpd.active = true;
        tpd.progress.lflgs.fetch_add(1, Ordering::Relaxed);
    } else {
        tpd.active = false;
        tpd.progress.lflgs.fetch_sub(1, Ordering::Relaxed);
        if update(tpd) {
            leader_update(tpd);
        }
    }
}

// Port of erl_thr_progress.c:1093 (request_wakeup_managed), OTP-29.1.1.
fn request_wakeup_managed(tpd: &mut ThrPrgrData, mut value: u64) {
    let progress = Arc::clone(&tpd.progress);
    if progress.has_reached_wakeup(value) {
        progress.wakeup_managed(tpd.id);
        return;
    }
    let mut wix = (value as usize) & (WAKEUP_DATA_SIZE - 1);
    if tpd.wakeup_request[wix] == value {
        // Already got a request registered.
        return;
    }
    if tpd.confirmed == value {
        // Already confirmed: request a later value so progress cannot reach the
        // requested one while the request is written.
        value = next_val(value);
        wix = (value as usize) & (WAKEUP_DATA_SIZE - 1);
        if tpd.wakeup_request[wix] == value {
            return;
        }
    }
    tpd.wakeup_request[wix] = value;
    let data = &progress.wakeup[wix];
    let ix = data.len.fetch_add(1, Ordering::AcqRel) as usize;
    assert!(
        ix < progress.managed_no(),
        "too many thread progress wakeup requests"
    );
    data.id[ix].store(tpd.id, Ordering::Release);
}

// Port of erl_thr_progress.c:1337 (thr_progress_block), OTP-29.1.1.
fn thr_progress_block(progress: &ThrProgress, tpd: Option<&mut ThrPrgrData>) {
    let managed = tpd.is_some();
    match tpd {
        Some(tpd) => {
            tpd.is_blocking += 1;
            if tpd.is_blocking > 1 {
                return;
            }
            while progress.lflgs.fetch_or(LFLG_BLOCK, Ordering::Relaxed) & LFLG_BLOCK != 0 {
                block_thread(tpd);
            }
        }
        None => {
            let nested = UNMANAGED_BLOCKING.get();
            UNMANAGED_BLOCKING.set(nested + 1);
            if nested != 0 {
                return;
            }
            while progress.lflgs.fetch_or(LFLG_BLOCK, Ordering::Relaxed) & LFLG_BLOCK != 0 {
                // Another thread blocks: wait for its unblock like a blocked thread.
                let mut guard = progress.event.0.lock().unwrap();
                while progress.lflgs.load(Ordering::Acquire) & LFLG_BLOCK != 0 {
                    guard = progress.event.1.wait(guard).unwrap();
                }
            }
        }
    }
    if managed {
        progress.block_count.fetch_sub(1, Ordering::Relaxed);
    }
    progress
        .block_count
        .fetch_and(!BC_FLG_NOT_BLOCKING, Ordering::SeqCst);
    let mut guard = progress.event.0.lock().unwrap();
    while progress.block_count.load(Ordering::Acquire) != 0 {
        guard = progress.event.1.wait(guard).unwrap();
    }
}

// Port of erl_thr_progress.c:1441 (erts_thr_progress_unblock), OTP-29.1.1.
fn thr_progress_unblock(progress: &ThrProgress, tpd: Option<&mut ThrPrgrData>) {
    let size = progress.managed_no();
    let (mut id, break_id, wakeup) = match tpd {
        Some(tpd) => {
            tpd.is_blocking -= 1;
            if tpd.is_blocking != 0 {
                return;
            }
            let break_id = tpd.id;
            let id = if break_id + 1 >= size {
                0
            } else {
                break_id + 1
            };
            progress.block_count.fetch_add(1, Ordering::Relaxed);
            (id, break_id, id != break_id)
        }
        None => {
            let nested = UNMANAGED_BLOCKING.get() - 1;
            UNMANAGED_BLOCKING.set(nested);
            if nested != 0 {
                return;
            }
            (0, 0, size != 0)
        }
    };
    progress
        .block_count
        .fetch_or(BC_FLG_NOT_BLOCKING, Ordering::Release);
    progress.lflgs.fetch_and(!LFLG_BLOCK, Ordering::SeqCst);
    // Unmanaged threads waiting to block wait on the event.
    progress.notify_event();
    if wakeup {
        loop {
            if progress.thr[id].0.load(Ordering::Relaxed) != VAL_WAITING {
                progress.wakeup_managed(id);
            }
            id += 1;
            if id >= size {
                id = 0;
            }
            if id == break_id {
                break;
            }
        }
    }
}

fn with_tpd<R>(body: impl FnOnce(Option<&mut ThrPrgrData>) -> R) -> R {
    TPD.with(|tpd| body(tpd.borrow_mut().as_mut()))
}

/// Register the calling thread as managed thread `id` of `progress`.
// Port of erl_thr_progress.c:576 (erts_thr_progress_register_managed_thread), OTP-29.1.1.
pub(crate) fn register_managed_thread(progress: &Arc<ThrProgress>, id: usize) {
    progress.lflgs.fetch_add(1, Ordering::Relaxed);
    TPD.with(|tpd| {
        *tpd.borrow_mut() = Some(ThrPrgrData {
            progress: Arc::clone(progress),
            id,
            is_blocking: 0,
            leader: false,
            active: true,
            confirmed: 0,
            leader_current: VAL_WAITING,
            leader_next: 0,
            chk_next_ix: 0,
            // erl_thr_progress.c:499 (init_wakeup_request_array): no slot matches its index.
            wakeup_request: std::array::from_fn(|ix| (ix as u64).wrapping_sub(1)),
            later_ops: VecDeque::new(),
            latest_wakeup: VAL_WAITING,
        });
    });
}

/// Drop the calling thread's registration when its scheduler loop ends.
pub(crate) fn unregister_managed_thread() {
    TPD.with(|tpd| tpd.borrow_mut().take());
}

/// The scheduler's progress point: update, lead, block if requested, then run the
/// later operations that became ready.
// Port of erl_process.c:9857-9866 (schedule: erts_thr_progress_update and
// erts_thr_progress_leader_update) and :2281 (handle_thr_prgr_later_op), OTP-29.1.1.
pub(crate) fn scheduler_progress() {
    let ready = with_tpd(|tpd| {
        let tpd = tpd?;
        if update(tpd) {
            leader_update(tpd);
        }
        Some(take_ready_later_ops(tpd))
    });
    if let Some(ready) = ready {
        for op in ready {
            op();
        }
    }
}

fn take_ready_later_ops(tpd: &mut ThrPrgrData) -> Vec<LaterOp> {
    let progress = Arc::clone(&tpd.progress);
    let current = progress.current.load(Ordering::Acquire);
    let mut ready = Vec::new();
    while tpd
        .later_ops
        .front()
        .is_some_and(|(later, _)| has_reached_this(current, *later))
    {
        ready.extend(tpd.later_ops.pop_front().map(|(_, op)| op));
    }
    if progress.unmanaged_later_len.load(Ordering::Acquire) != 0 {
        let mut shared = progress.unmanaged_later.lock().unwrap();
        while shared
            .front()
            .is_some_and(|(later, _)| has_reached_this(current, *later))
        {
            ready.extend(shared.pop_front().map(|(_, op)| op));
        }
        progress
            .unmanaged_later_len
            .store(shared.len(), Ordering::Release);
        if let Some(&(later, _)) = shared.front() {
            drop(shared);
            request_wakeup_managed(tpd, later);
        }
    }
    ready
}

/// Before a managed thread sleeps: it stops counting as active and waits.
// Port of erl_process.c:3576-3579 (scheduler_wait: erts_thr_progress_active(0) and
// erts_thr_progress_prepare_wait), OTP-29.1.1.
pub(crate) fn scheduler_prepare_wait() {
    with_tpd(|tpd| {
        if let Some(tpd) = tpd {
            if tpd.active {
                set_active(tpd, false);
            }
            prepare_wait(tpd);
        }
    });
}

/// After a managed thread woke up.
// Port of erl_process.c:3611,3660 (scheduler_wait: erts_thr_progress_finalize_wait and
// erts_thr_progress_active(1)), OTP-29.1.1.
pub(crate) fn scheduler_finalize_wait() {
    with_tpd(|tpd| {
        if let Some(tpd) = tpd {
            finalize_wait(tpd);
            if !tpd.active {
                set_active(tpd, true);
            }
        }
    });
}

/// Block thread progress: return once every other managed thread is waiting or blocked.
// Port of erl_thr_progress.c:1386 (erts_thr_progress_block), OTP-29.1.1.
pub(crate) fn block(progress: &ThrProgress) {
    with_tpd(|tpd| {
        let tpd = tpd.filter(|tpd| std::ptr::eq(Arc::as_ptr(&tpd.progress), progress));
        thr_progress_block(progress, tpd);
    });
}

/// Release a [`block`].
// Port of erl_thr_progress.c:1441 (erts_thr_progress_unblock), OTP-29.1.1.
pub(crate) fn unblock(progress: &ThrProgress) {
    with_tpd(|tpd| {
        let tpd = tpd.filter(|tpd| std::ptr::eq(Arc::as_ptr(&tpd.progress), progress));
        thr_progress_unblock(progress, tpd);
    });
}

/// Run `op` once every managed thread passed a thread progress point.
// Port of erl_process.c:2351 (erts_schedule_thr_prgr_later_op, enqueue_later_op and
// haw_thr_prgr_wakeup) and erl_thr_progress.h (erts_thr_progress_later), OTP-29.1.1.
pub(crate) fn schedule_later_op(progress: &ThrProgress, op: LaterOp) {
    if progress.managed_no() == 0 {
        LATER_READY.with(|later| later.borrow_mut().push(op));
        return;
    }
    let op = with_tpd(|tpd| {
        let Some(tpd) = tpd.filter(|tpd| std::ptr::eq(Arc::as_ptr(&tpd.progress), progress)) else {
            return Some(op);
        };
        fence(Ordering::SeqCst);
        let later = current_to_later(tpd.confirmed);
        tpd.later_ops.push_back((later, op));
        if cmp(later, tpd.latest_wakeup) != std::cmp::Ordering::Equal {
            if tpd.latest_wakeup == VAL_WAITING
                || cmp(later, tpd.latest_wakeup) == std::cmp::Ordering::Greater
            {
                tpd.latest_wakeup = later;
            }
            request_wakeup_managed(tpd, later);
        }
        None
    });
    if let Some(op) = op {
        // An unmanaged thread: any managed thread runs it once progress reaches it.
        let later = current_to_later(progress.current.load(Ordering::SeqCst));
        let mut shared = progress.unmanaged_later.lock().unwrap();
        shared.push_back((later, op));
        progress
            .unmanaged_later_len
            .store(shared.len(), Ordering::Release);
        drop(shared);
        progress.wakeup_managed(0);
    }
}

/// Run the later operations of a runtime without managed threads.
pub(crate) fn run_unmanaged_later_ops() {
    loop {
        let ready = LATER_READY.with(|later| std::mem::take(&mut *later.borrow_mut()));
        if ready.is_empty() {
            return;
        }
        for op in ready {
            op();
        }
    }
}

/// Whether `val` was reached (used by tests).
#[cfg(test)]
fn reached(progress: &ThrProgress, val: u64) -> bool {
    progress.has_reached(val)
}

/// Run a blocking wait without holding back thread progress: a waiting managed thread
/// counts as waiting, so a thread blocking progress never waits for it.
///
/// Port of erts/emulator/beam/erl_thr_progress.c:884 (erts_thr_progress_prepare_wait) and
/// :913 (erts_thr_progress_finalize_wait), OTP-29.1.1; the caller must not hold locks that
/// a thread blocking progress needs.
pub fn thread_progress_wait<R>(wait: impl FnOnce() -> R) -> R {
    let managed = with_tpd(|tpd| {
        tpd.map(|tpd| {
            prepare_wait(tpd);
        })
        .is_some()
    });
    let result = wait();
    if managed {
        with_tpd(|tpd| {
            if let Some(tpd) = tpd {
                finalize_wait(tpd);
            }
        });
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn progress(managed: usize) -> Arc<ThrProgress> {
        Arc::new(ThrProgress::new(
            (0..managed).map(|_| AtomicBool::new(false)).collect(),
            (0..managed).map(|_| OnceLock::new()).collect(),
        ))
    }

    #[test]
    fn values_wrap_like_erts() {
        assert_eq!(next_val(VAL_WAITING - 1), 0);
        assert_eq!(current_to_later(VAL_WAITING - 2), 0);
        assert_eq!(current_to_later(5), 7);
        assert!(has_passed(1, 3u64 << 62 | 1));
        assert!(has_reached_this(7, 7));
        assert!(!has_reached_this(6, 7));
    }

    #[test]
    fn single_managed_thread_leads_and_runs_later_ops() {
        let progress = progress(1);
        std::thread::scope(|scope| {
            scope.spawn(|| {
                progress.sleepers[0].set(std::thread::current()).unwrap();
                register_managed_thread(&progress, 0);
                let ran = Arc::new(AtomicBool::new(false));
                let flag = Arc::clone(&ran);
                schedule_later_op(
                    &progress,
                    Box::new(move || flag.store(true, Ordering::SeqCst)),
                );
                for _ in 0..8 {
                    scheduler_progress();
                }
                assert!(ran.load(Ordering::SeqCst));
                assert!(reached(&progress, 2));
                unregister_managed_thread();
            });
        });
    }

    #[test]
    fn block_waits_for_managed_threads_at_their_progress_point() {
        let progress = progress(2);
        let stop = Arc::new(AtomicBool::new(false));
        let passes = Arc::new(AtomicU64::new(0));
        std::thread::scope(|scope| {
            for id in 0..2 {
                let progress = Arc::clone(&progress);
                let stop = Arc::clone(&stop);
                let passes = Arc::clone(&passes);
                scope.spawn(move || {
                    progress.sleepers[id].set(std::thread::current()).unwrap();
                    register_managed_thread(&progress, id);
                    while !stop.load(Ordering::SeqCst) {
                        scheduler_progress();
                        passes.fetch_add(1, Ordering::SeqCst);
                    }
                    scheduler_prepare_wait();
                    unregister_managed_thread();
                });
            }
            // An unmanaged thread blocks: both managed threads stop at a progress point.
            block(&progress);
            let frozen = passes.load(Ordering::SeqCst);
            std::thread::sleep(std::time::Duration::from_millis(20));
            assert!(passes.load(Ordering::SeqCst) <= frozen + 2);
            unblock(&progress);
            stop.store(true, Ordering::SeqCst);
        });
    }
}
