//! Thread progress for the managed (normal scheduler) threads.
//!
//! Port of erts/emulator/beam/erl_thr_progress.c and erl_thr_progress.h, OTP-29.1.1. Each
//! managed thread confirms the global progress value it has observed in its own slot; the
//! leader advances the global value once every managed thread confirmed it or waits. A
//! thread that needs every managed thread to pass a point (`block`) sets a flag that the
//! managed threads honour at their next progress update. Operations scheduled with
//! [`erts_schedule_thr_prgr_later_op`] run once the global value has reached `confirmed + 2`.
//!
//! Unmanaged threads (dirty schedulers, the main thread) may block and unblock thread
//! progress, and delay progress while they look at memory that a later operation frees
//! ([`unmanaged_delay`], erts `erts_thr_progress_unmanaged_delay`). They do not enqueue later
//! ops: erts `enqueue_later_op` asserts `esdp && !dirty`; those callers use
//! `erts_schedule_misc_aux_work` onto a normal scheduler.

use crate::ssi::{self, ErtsSchedulerSleepInfo};
use std::cell::{Cell, RefCell};
use std::sync::atomic::{AtomicI32, AtomicPtr, AtomicU32, AtomicU64, AtomicUsize, Ordering, fence};
use std::sync::{Arc, Condvar, Mutex, OnceLock};

pub(crate) mod raw;
pub use raw::ErtsThrPrgrLaterOp;
pub(crate) use raw::LaterOpHandle;

/// A delay of thread progress by an unmanaged thread (erts `ErtsThrPrgrDelayHandle`).
#[must_use]
pub(crate) enum DelayHandle {
    /// `ERTS_THR_PRGR_DHANDLE_MANAGED`: a managed thread delays progress by not passing a point.
    Managed,
    /// The index of the unmanaged reference count taken.
    Unmanaged(usize),
}

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
/// `ERTS_THR_PRGR_BM_BITS` / `ERTS_THR_PRGR_BM_SHIFT`.
const UNMANAGED_WAKEUP_BM_BITS: usize = 32;
/// `ERTS_MIN_THR_PRGR_LATER_OPS`: later operations run per pass at least.
const MIN_THR_PRGR_LATER_OPS: usize = 50;
/// `thr_prgr_later_cleanup_op_threshold` at its default
/// (`ERTS_THR_PRGR_LATER_CLEANUP_OP_THRESHOLD_MEDIUM`, `+swct medium`): bytes of later cleanup
/// operations queued before a thread progress wakeup is requested for them.
const LATER_CLEANUP_OP_THRESHOLD: usize = 64 * 1024;

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

/// Whether `val1` has passed `val0` in the wrapped thread-progress sequence.
// Port of erl_thr_progress.h (erts_thr_progress_has_passed), OTP-29.1.1.
pub(crate) fn erts_thr_progress_has_passed(val1: u64, val0: u64) -> bool {
    has_passed(val1, val0)
}

// Port of erl_thr_progress.h (erts_thr_progress_has_reached_this), OTP-29.1.1.
fn has_reached_this(this: u64, val: u64) -> bool {
    this == val || erts_thr_progress_has_passed(this, val)
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

/// Two-level unmanaged wakeup bitmap from `ErtsThrPrgrUnmanagedWakeupData`.
struct UnmanagedWakeupData {
    len: AtomicU32,
    high: Box<[AtomicU32]>,
    low: Box<[AtomicU32]>,
}

struct UnmanagedTpd {
    /// Used by `request_wakeup_unmanaged` (tests and erts unmanaged wait).
    #[allow(dead_code)]
    progress: Arc<ThrProgress>,
    id: usize,
    #[allow(dead_code)]
    wakeup_request: [u64; WAKEUP_DATA_SIZE],
}

type UnmanagedWakeupCallback = Arc<dyn Fn() + Send + Sync>;
type UnmanagedWakeupCallbackSlot = Mutex<Option<UnmanagedWakeupCallback>>;

/// The per-thread event erts exposes as `erts_tse_t`: reset before publishing a sleep, and
/// retain a signal that races with the wait.
#[derive(Debug)]
pub(crate) struct ThreadEvent {
    signaled: Mutex<bool>,
    event: Condvar,
}

impl ThreadEvent {
    pub(crate) fn new() -> Self {
        Self {
            signaled: Mutex::new(false),
            event: Condvar::new(),
        }
    }

    pub(crate) fn reset(&self) {
        *self
            .signaled
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = false;
    }

    pub(crate) fn signal(&self) {
        let mut signaled = self
            .signaled
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        *signaled = true;
        self.event.notify_one();
    }

    pub(crate) fn wait(&self) {
        let mut signaled = self
            .signaled
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        while !*signaled {
            signaled = self
                .event
                .wait(signaled)
                .unwrap_or_else(|error| error.into_inner());
        }
        *signaled = false;
    }

    /// `erts_tse_twait` for `timeout`: `true` when the event was set (and is consumed),
    /// `false` on timeout.
    pub(crate) fn twait(&self, timeout: std::time::Duration) -> bool {
        let signaled = self
            .signaled
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let (mut signaled, _) = self
            .event
            .wait_timeout_while(signaled, timeout, |signaled| !*signaled)
            .unwrap_or_else(|error| error.into_inner());
        std::mem::replace(&mut *signaled, false)
    }

    /// Consumes a pending set without waiting.
    pub(crate) fn try_take(&self) -> bool {
        std::mem::replace(
            &mut *self
                .signaled
                .lock()
                .unwrap_or_else(|error| error.into_inner()),
            false,
        )
    }
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
    /// `intrnl->misc.data.blocker_event`: the erts_tse the blocker waits on.
    blocker_event: AtomicPtr<ThreadEvent>,
    wakeup: [WakeupData; WAKEUP_DATA_SIZE],
    unmanaged_wakeup: [UnmanagedWakeupData; WAKEUP_DATA_SIZE],
    unmanaged_callbacks: Box<[UnmanagedWakeupCallbackSlot]>,
    unmanaged_next: AtomicUsize,
    /// `intrnl->managed.callbacks[id].arg`: the sleep info of each managed thread (the
    /// schedulers, then the aux thread), which the managed callbacks wake and wait on
    /// (erl_process.c thr_prgr_wakeup, thr_prgr_prep_wait, thr_prgr_wait, thr_prgr_fin_wait).
    callbacks: Box<[Arc<ErtsSchedulerSleepInfo>]>,
    /// `intrnl->umrefc`: unmanaged threads delaying progress, counted in one of two slots.
    umrefc: [AtomicUsize; 2],
    /// `intrnl->misc.data.umrefc_ix.current`: the slot new delays count in.
    umrefc_current: AtomicUsize,
    /// `intrnl->misc.data.umrefc_ix.waiting`: the slot a leader that gave up leadership was
    /// waiting to drain, `-1` for none.
    umrefc_waiting: std::sync::atomic::AtomicI32,
}

/// The thread progress of the OS process (erts `intrnl`, erl_thr_progress.c): one set of managed
/// threads for the whole process, created once by [`init`].
static INTRNL: OnceLock<Arc<ThrProgress>> = OnceLock::new();

/// Creates the thread progress of the OS process, managed by the threads whose sleep infos
/// `callbacks` holds, and gives the allocator's delayed-dealloc queues and pools access to it.
///
/// Port of erts/emulator/beam/erl_thr_progress.c (erts_thr_progress_init), OTP-29.1.1, which
/// `erl_start` runs once: erts has one runtime per OS process, so a second runtime in the same
/// process is refused here instead of getting a thread progress of its own.
pub(crate) fn init(
    callbacks: Box<[Arc<ErtsSchedulerSleepInfo>]>,
    unmanaged: usize,
) -> Arc<ThrProgress> {
    let progress = Arc::new(ThrProgress::new_with_callbacks(callbacks, unmanaged));
    assert!(
        INTRNL.set(Arc::clone(&progress)).is_ok(),
        "thread progress is initialized once per OS process (erts_thr_progress_init): \
         one runtime per process"
    );
    let installed = arinsal_alloc::sspa::install_progress_ops(arinsal_alloc::sspa::ProgressOps {
        current: sspa_current,
        has_reached: sspa_has_reached,
        is_managed: sspa_is_managed,
    });
    assert!(
        installed.is_ok(),
        "allocator thread progress installed twice"
    );
    progress
}

/// Print the current thread-progress value and each managed thread's confirmation.
// Port of erts/emulator/beam/erl_thr_progress.c (erts_thr_progress_dbg_print_state), OTP-29.1.1.
pub fn debug_print_state() {
    let Some(progress) = INTRNL.get() else {
        println!(
            "--- thread progress ---\ncurrent={}\n-----------------------",
            std::process::id()
        );
        return;
    };
    println!("--- thread progress ---\ncurrent={}", std::process::id());
    for (id, slot) in progress.thr.iter().enumerate() {
        let value = slot.0.load(Ordering::Acquire);
        if value == VAL_WAITING {
            println!("  id={id}, current=WAITING");
        } else {
            println!("  id={id}, current={value}");
        }
    }
    println!("-----------------------");
}

// Port of erl_thr_progress.h (erts_thr_progress_current): the global value of the process,
// read alike by managed and unmanaged threads.
fn sspa_current(_: usize) -> u64 {
    INTRNL
        .get()
        .map_or(0, |progress| progress.current.load(Ordering::Acquire))
}

fn sspa_has_reached(scheduler: usize, value: u64) -> bool {
    has_reached_this(sspa_current(scheduler), value)
}

fn sspa_is_managed() -> bool {
    MANAGED_OF.with(|of| of.get() != 0)
}

/// Per thread data of a managed thread (erts `ErtsThrPrgrData`).
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
    /// `leader_state.umrefc_ix.waiting`: the slot this leader waits to drain, `-1` for none.
    leader_umrefc_waiting: i32,
    /// `leader_state.umrefc_ix.current`.
    leader_umrefc_current: usize,
}

/// `ErtsAuxWorkData.later_op` first..last, size, list_len and cleanup progress counters.
// Port of erts/emulator/beam/erl_process.h (ErtsAuxWorkData.later_op), OTP-29.1.1.
#[derive(Default)]
pub(crate) struct LaterOpState {
    list: raw::LaterOpList,
    size: usize,
    thr_prgr: u64,
}

impl LaterOpState {
    pub(crate) fn is_empty(&self) -> bool {
        self.list.is_empty()
    }

    #[cfg(test)]
    pub(crate) fn list_len(&self) -> usize {
        self.list.list_len
    }
}

/// `ErtsAuxWorkData.latest_wakeup` next to `later_op` (erl_process.h).
///
/// Lives inline in `ErtsAuxWorkData` (`esdp->aux_work_data`). Thread progress reaches it
/// through that scheduler data, as `enqueue_later_op` / `haw_thr_prgr_wakeup` do in
/// erl_process.c; `ThrPrgrData` does not hold a copy.
// Port of erts/emulator/beam/erl_process.h (`ErtsAuxWorkData`), OTP-29.1.1.
#[derive(Default)]
pub(crate) struct AuxWorkLater {
    /// `ErtsAuxWorkData.latest_wakeup` (`ERTS_THR_PRGR_VAL_FIRST` at init).
    latest_wakeup: u64,
    /// `ErtsAuxWorkData.current_thr_prgr` (`ERTS_THR_PRGR_INVALID` until first read).
    current_thr_prgr: u64,
    /// `ErtsAuxWorkData.later_op`.
    later_op: LaterOpState,
}

impl AuxWorkLater {
    /// erts init_aux_work_data: `latest_wakeup = FIRST`, `current = INVALID`, empty list.
    pub(crate) fn new() -> Self {
        Self {
            latest_wakeup: 0,
            current_thr_prgr: VAL_WAITING,
            later_op: LaterOpState::default(),
        }
    }

    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.later_op.is_empty()
    }

    #[cfg(test)]
    pub(crate) fn list_len(&self) -> usize {
        self.later_op.list_len()
    }

    pub(crate) fn current_thr_prgr(&self) -> u64 {
        self.current_thr_prgr
    }
}

thread_local! {
    /// erts `erts_thr_prgr_data_key__`.
    static TPD: RefCell<Option<ManagedThread>> = const { RefCell::new(None) };
    /// `intrnl->unmanaged.callbacks` entry of the registered thread.
    static UNMANAGED_TPD: RefCell<Option<UnmanagedTpd>> = const { RefCell::new(None) };
    /// Block nesting of an unmanaged thread (erts temporary `ErtsThrPrgrData`).
    static UNMANAGED_BLOCKING: Cell<u32> = const { Cell::new(0) };
    /// The thread progress this thread is a managed thread of, compared by address only
    /// (erts_thr_progress_is_managed_thread).
    static MANAGED_OF: Cell<usize> = const { Cell::new(0) };
    /// Process lookups without a reference this thread is inside (debug builds).
    static LOOKUP_DEPTH: Cell<u32> = const { Cell::new(0) };
}

/// A process lookup that holds no reference: a managed thread must not wait (and so let
/// progress pass) until it ends. Debug builds check it, as erts' lock checker does.
pub(crate) struct LookupScope;

impl LookupScope {
    #[inline]
    pub(crate) fn enter() -> Self {
        if cfg!(debug_assertions) {
            LOOKUP_DEPTH.with(|depth| depth.set(depth.get() + 1));
        }
        Self
    }
}

impl Drop for LookupScope {
    #[inline]
    fn drop(&mut self) {
        if cfg!(debug_assertions) {
            LOOKUP_DEPTH.with(|depth| depth.set(depth.get() - 1));
        }
    }
}

impl ThrProgress {
    /// The state `erts_thr_progress_init` (erl_thr_progress.c:396, OTP-29.1.1) allocates. The
    /// runtime gets the one of the process through [`init`]; unit tests of the algorithm build
    /// their own.
    #[cfg(test)]
    pub(crate) fn new(managed: usize) -> Self {
        Self::new_with_callbacks(
            (0..managed)
                .map(|_| Arc::new(ErtsSchedulerSleepInfo::new(0)))
                .collect(),
            0,
        )
    }

    fn new_with_callbacks(callbacks: Box<[Arc<ErtsSchedulerSleepInfo>]>, unmanaged: usize) -> Self {
        let managed = callbacks.len();
        let wakeup = std::array::from_fn(|_| WakeupData {
            len: AtomicU32::new(0),
            id: (0..managed).map(|_| AtomicUsize::new(0)).collect(),
        });
        let low = unmanaged.div_ceil(UNMANAGED_WAKEUP_BM_BITS);
        let high = low.div_ceil(UNMANAGED_WAKEUP_BM_BITS);
        let unmanaged_wakeup = std::array::from_fn(|_| UnmanagedWakeupData {
            len: AtomicU32::new(0),
            high: (0..high).map(|_| AtomicU32::new(0)).collect(),
            low: (0..low).map(|_| AtomicU32::new(0)).collect(),
        });
        Self {
            current: AtomicU64::new(0),
            thr: (0..managed).map(|_| Slot(AtomicU64::new(0))).collect(),
            lflgs: AtomicU32::new(LFLG_NO_LEADER),
            block_count: AtomicU32::new(BC_FLG_NOT_BLOCKING | managed as u32),
            event: (Mutex::new(()), Condvar::new()),
            blocker_event: AtomicPtr::new(std::ptr::null_mut()),
            wakeup,
            unmanaged_wakeup,
            unmanaged_callbacks: (0..unmanaged).map(|_| Mutex::new(None)).collect(),
            unmanaged_next: AtomicUsize::new(0),
            callbacks,
            umrefc: [AtomicUsize::new(0), AtomicUsize::new(0)],
            umrefc_current: AtomicUsize::new(0),
            umrefc_waiting: std::sync::atomic::AtomicI32::new(-1),
        }
    }

    fn managed_no(&self) -> usize {
        self.thr.len()
    }

    /// The managed `wakeup` callback (erts wakeup_managed).
    // Port of erts/emulator/beam/erl_process.c:3121 (thr_prgr_wakeup: erts_sched_poke),
    // OTP-29.1.1.
    fn wakeup_managed(&self, id: usize) {
        ssi::erts_sched_poke(&self.callbacks[id], crate::sched_poll_interrupt);
    }

    // Port of erl_thr_progress.c:276 (wakeup_unmanaged), OTP-29.1.1.
    fn wakeup_unmanaged(&self, id: usize) {
        let callback = self.unmanaged_callbacks[id]
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clone();
        if let Some(callback) = callback {
            callback();
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
            let event = raw::blocker_event_load(&self.blocker_event);
            if !event.is_null() {
                raw::erts_tse_set(event);
            }
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
        let wix = (current as usize) & (WAKEUP_DATA_SIZE - 1);
        let data = &self.wakeup[wix];
        let len = data.len.load(Ordering::Acquire) as usize;
        if len != 0 {
            for id in &data.id[..len] {
                self.wakeup_managed(id.load(Ordering::Acquire));
            }
            data.len.store(0, Ordering::Relaxed);
        }
        let data = &self.unmanaged_wakeup[wix];
        if data.len.load(Ordering::Acquire) != 0 {
            for (hix, high) in data.high.iter().enumerate() {
                let mut hmask = high.load(Ordering::Relaxed);
                while hmask != 0 {
                    let hbit = hmask.trailing_zeros() as usize;
                    hmask &= hmask - 1;
                    let lix = hix * UNMANAGED_WAKEUP_BM_BITS + hbit;
                    if let Some(low) = data.low.get(lix) {
                        let mut lmask = low.load(Ordering::Relaxed);
                        while lmask != 0 {
                            let lbit = lmask.trailing_zeros() as usize;
                            lmask &= lmask - 1;
                            self.wakeup_unmanaged(lix * UNMANAGED_WAKEUP_BM_BITS + lbit);
                        }
                        low.store(0, Ordering::Relaxed);
                    }
                }
                high.store(0, Ordering::Relaxed);
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
            || self
                .unmanaged_wakeup
                .iter()
                .any(|data| data.len.load(Ordering::Relaxed) != 0)
    }

    /// Whether the global value has reached `val` (erts erts_thr_progress_has_reached).
    #[cfg(test)]
    fn has_reached(&self, val: u64) -> bool {
        has_reached_this(self.current.load(Ordering::Acquire), val)
    }

    /// Current thread progress value for intrusive retired-block lists.
    pub(crate) fn current_value(&self) -> u64 {
        self.current.load(Ordering::Acquire)
    }

    /// Progress point two steps beyond the current value, used by erts later operations.
    pub(crate) fn later_value(&self) -> u64 {
        current_to_later(self.current_value())
    }

    /// Whether thread progress has reached a value captured by a retired block.
    pub(crate) fn reached(&self, val: u64) -> bool {
        has_reached_this(self.current_value(), val)
    }
}

// Port of erl_thr_progress.c:1308 (block_thread), OTP-29.1.1: the managed `prepare_wait`,
// `wait` and `finalize_wait` callbacks are the thread's own
// (`cbp = &intrnl->managed.callbacks[tpd->id]`), on its scheduler sleep info.
fn block_thread(tpd: &mut ThrPrgrData) -> u32 {
    let progress = Arc::clone(&tpd.progress);
    let cbp = Arc::clone(&progress.callbacks[tpd.id]);
    let mut lflgs;
    loop {
        progress.block_count_dec();
        loop {
            ssi::thr_prgr_prep_wait(&cbp);
            lflgs = progress.lflgs.load(Ordering::Acquire);
            if lflgs & LFLG_BLOCK != 0 {
                ssi::thr_prgr_wait(&cbp);
            } else {
                break;
            }
        }
        if !progress.block_count_inc() {
            break;
        }
    }
    // Port of erl_thr_progress.c:1327 (`erts_code_ix_finalize_wait` in `block_thread`).
    erts_code_ix_finalize_wait();
    ssi::thr_prgr_fin_wait(&cbp);
    lflgs
}

/// `outstanding_blocking_code_barriers` (code_ix.c).
static OUTSTANDING_BLOCKING_CODE_BARRIERS: AtomicI32 = AtomicI32::new(0);

/// Port of erts/emulator/beam/erl_threads.h (`ERTS_THR_INSTRUCTION_BARRIER`), OTP-29.1.1.
pub fn erts_thr_instruction_barrier() {
    raw::instruction_barrier();
}

/// Port of erts/emulator/beam/code_ix.c:642 (`erts_code_ix_finalize_wait`), OTP-29.1.1.
pub fn erts_code_ix_finalize_wait() {
    if OUTSTANDING_BLOCKING_CODE_BARRIERS.load(Ordering::Relaxed) != 0 {
        erts_thr_instruction_barrier();
    }
}

/// Port of erts/emulator/beam/code_ix.c:46 (`outstanding_blocking_code_barriers`).
pub fn outstanding_blocking_code_barriers() -> &'static AtomicI32 {
    &OUTSTANDING_BLOCKING_CODE_BARRIERS
}

// Port of erts/emulator/beam/erl_thr_progress.c (leader_update), OTP-29.1.1.
fn leader_update(tpd: &mut ThrPrgrData) -> bool {
    if !tpd.leader {
        // Probably need to block...
        block_thread(tpd);
        return tpd.leader;
    }
    let progress = &*tpd.progress;
    let my_ix = tpd.id;
    if tpd.leader_current == VAL_WAITING {
        // Took over as leader from another thread.
        tpd.leader_current = progress.current.load(Ordering::Relaxed);
        tpd.leader_next = next_val(tpd.leader_current);
        tpd.chk_next_ix = 0;
        tpd.leader_umrefc_waiting = progress.umrefc_waiting.load(Ordering::Relaxed);
        tpd.leader_umrefc_current = progress.umrefc_current.load(Ordering::Relaxed);
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
        let tmp = progress.thr[ix].0.load(Ordering::Relaxed);
        if tmp != next && tmp != VAL_WAITING {
            tpd.chk_next_ix = ix;
            caught_up = false;
            break;
        }
    }
    // Check unmanaged threads.
    let mut waiting_unmanaged = tpd.leader_umrefc_waiting != -1;
    let umrefc_ix = if waiting_unmanaged {
        tpd.leader_umrefc_waiting as usize
    } else {
        tpd.leader_umrefc_current
    };
    if caught_up && progress.umrefc[umrefc_ix].load(Ordering::Relaxed) != 0 {
        if waiting_unmanaged {
            caught_up = false;
        } else {
            let new_umrefc_ix = (umrefc_ix + 1) & 1;
            tpd.leader_umrefc_waiting = umrefc_ix as i32;
            tpd.chk_next_ix = no_managed;
            progress
                .umrefc_current
                .store(new_umrefc_ix, Ordering::Relaxed);
            tpd.leader_umrefc_current = new_umrefc_ix;
            fence(Ordering::SeqCst);
            waiting_unmanaged = true;
            if progress.umrefc[umrefc_ix].load(Ordering::Relaxed) != 0 {
                caught_up = false;
            }
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
        if waiting_unmanaged {
            waiting_unmanaged = false;
            tpd.leader_umrefc_waiting = -1;
            progress
                .lflgs
                .fetch_and(!LFLG_WAITING_UM, Ordering::Relaxed);
        }
        tpd.chk_next_ix = 0;
    }
    if tpd.active {
        if progress.lflgs.load(Ordering::Relaxed) & LFLG_BLOCK != 0 {
            block_thread(tpd);
        }
    } else {
        tpd.leader = false;
        tpd.leader_current = VAL_WAITING;
        progress
            .umrefc_waiting
            .store(tpd.leader_umrefc_waiting, Ordering::Relaxed);
        let mut set_flags = LFLG_NO_LEADER;
        if waiting_unmanaged {
            set_flags |= LFLG_WAITING_UM;
        }
        let lflgs = progress.lflgs.fetch_or(set_flags, Ordering::Release) | set_flags;
        if lflgs & LFLG_BLOCK != 0 {
            block_thread(tpd);
        }
        if waiting_unmanaged {
            // Need to check umrefc again.
            fence(Ordering::SeqCst);
            let progress = &*tpd.progress;
            if progress.umrefc[umrefc_ix].load(Ordering::Relaxed) == 0
                && progress.got_sched_wakeups()
            {
                // Someone needs to make progress.
                progress.wakeup_managed(tpd.id);
            }
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

// Port of erl_thr_progress.c:1172 (request_wakeup_unmanaged), OTP-29.1.1.
#[cfg(test)]
fn request_wakeup_unmanaged(tpd: &mut UnmanagedTpd, value: u64) {
    let progress = Arc::clone(&tpd.progress);
    if progress.has_reached_wakeup(value) {
        progress.wakeup_unmanaged(tpd.id);
        return;
    }
    let wix = (value as usize) & (WAKEUP_DATA_SIZE - 1);
    if tpd.wakeup_request[wix] == value {
        return;
    }
    let data = &progress.unmanaged_wakeup[wix];
    let low_ix = tpd.id >> 5;
    let low_bit = tpd.id & 0x1f;
    let high_ix = low_ix >> 5;
    let high_bit = low_ix & 0x1f;
    data.low[low_ix].fetch_or(1 << low_bit, Ordering::Relaxed);
    data.high[high_ix].fetch_or(1 << high_bit, Ordering::Relaxed);
    data.len.fetch_add(1, Ordering::SeqCst);
    if progress.has_reached_wakeup(value) {
        progress.wakeup_unmanaged(tpd.id);
    } else {
        tpd.wakeup_request[wix] = value;
    }
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
    // Port of erl_thr_progress.c:1361-1377: `erts_tse_fetch`, publish `blocker_event`, wait.
    let event = raw::erts_tse_fetch();
    raw::erts_tse_reset(event);
    raw::blocker_event_store(&progress.blocker_event, event);
    if managed {
        progress.block_count.fetch_sub(1, Ordering::Relaxed);
    }
    let mut bc = progress
        .block_count
        .fetch_and(!BC_FLG_NOT_BLOCKING, Ordering::SeqCst)
        & !BC_FLG_NOT_BLOCKING;
    while bc != 0 {
        raw::erts_tse_wait(event);
        raw::erts_tse_reset(event);
        bc = progress.block_count.load(Ordering::Acquire);
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
    let event = raw::blocker_event_take(&progress.blocker_event);
    progress
        .block_count
        .fetch_or(BC_FLG_NOT_BLOCKING, Ordering::Release);
    progress.lflgs.fetch_and(!LFLG_BLOCK, Ordering::SeqCst);
    // Unmanaged threads waiting to take `LFLG_BLOCK` wait on this event.
    progress.notify_event();
    raw::erts_tse_return(event);
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
    let Some(tpd) = TPD.with(|tpd| tpd.borrow().clone()) else {
        return body(None);
    };
    body(Some(&mut tpd.0.borrow_mut()))
}

/// The thread progress data of a managed thread, shared by its thread-specific key and the
/// scheduler that owns it.
///
/// Port of erts/emulator/beam/erl_thr_progress.h:171-175 (erts_thr_prgr_data: a scheduler
/// reads `esdp->thr_progress_data`, other code the thread-specific key), OTP-29.1.1.
#[derive(Clone)]
pub(crate) struct ManagedThread(std::rc::Rc<RefCell<ThrPrgrData>>);

/// Register the calling thread as managed thread `id` of `progress`.
// Port of erl_thr_progress.c:576 (erts_thr_progress_register_managed_thread), OTP-29.1.1.
pub(crate) fn register_managed_thread(progress: &Arc<ThrProgress>, id: usize) -> ManagedThread {
    progress.lflgs.fetch_add(1, Ordering::Relaxed);
    let managed = ManagedThread(std::rc::Rc::new(RefCell::new(ThrPrgrData {
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
        leader_umrefc_waiting: -1,
        leader_umrefc_current: 0,
    })));
    TPD.with(|tpd| *tpd.borrow_mut() = Some(managed.clone()));
    MANAGED_OF.with(|of| of.set(Arc::as_ptr(progress) as usize));
    managed
}

/// Register a dirty scheduler as an unmanaged thread with its SSI poke callback.
// Port of erl_thr_progress.c:517 (erts_thr_progress_register_unmanaged_thread), OTP-29.1.1.
pub(crate) fn register_unmanaged_thread(
    progress: &Arc<ThrProgress>,
    wakeup: impl Fn() + Send + Sync + 'static,
) -> UnmanagedRegistration {
    assert!(TPD.with(|tpd| tpd.borrow().is_none()));
    assert!(UNMANAGED_TPD.with(|tpd| tpd.borrow().is_none()));
    let id = progress.unmanaged_next.fetch_add(1, Ordering::Relaxed);
    let callback = progress
        .unmanaged_callbacks
        .get(id)
        .expect("unmanaged thread count matches scheduler configuration");
    *callback.lock().unwrap_or_else(|error| error.into_inner()) = Some(Arc::new(wakeup));
    UNMANAGED_TPD.with(|tpd| {
        *tpd.borrow_mut() = Some(UnmanagedTpd {
            progress: Arc::clone(progress),
            id,
            wakeup_request: std::array::from_fn(|ix| (ix as u64).wrapping_sub(1)),
        });
    });
    UnmanagedRegistration {
        progress: Arc::clone(progress),
        id,
        _same_thread: std::marker::PhantomData,
    }
}

/// The dirty scheduler's process-local thread-progress registration.
pub(crate) struct UnmanagedRegistration {
    progress: Arc<ThrProgress>,
    id: usize,
    _same_thread: std::marker::PhantomData<std::rc::Rc<()>>,
}

impl Drop for UnmanagedRegistration {
    fn drop(&mut self) {
        UNMANAGED_TPD.with(|tpd| {
            let mut tpd = tpd.borrow_mut();
            if tpd.as_ref().is_some_and(|tpd| tpd.id == self.id) {
                tpd.take();
            }
        });
        *self.progress.unmanaged_callbacks[self.id]
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = None;
    }
}

/// Drop the calling test thread's registration (a scheduler never ends its loop).
#[cfg(test)]
pub(crate) fn unregister_managed_thread() {
    MANAGED_OF.with(|of| of.set(0));
    TPD.with(|tpd| tpd.borrow_mut().take());
}

/// Whether the calling thread is a managed thread of `progress`
/// (erts_thr_progress_is_managed_thread).
pub(crate) fn is_managed_thread_of(progress: &ThrProgress) -> bool {
    MANAGED_OF.with(Cell::get) == std::ptr::from_ref(progress) as usize
}

/// Delay thread progress while an unmanaged thread looks at memory a later operation may free;
/// a managed thread needs no delay.
///
/// Port of erts/emulator/beam/erl_thr_progress.c (erts_thr_progress_unmanaged_delay__) and
/// erl_thr_progress.h (erts_thr_progress_unmanaged_delay), OTP-29.1.1.
pub(crate) fn unmanaged_delay(progress: &ThrProgress) -> DelayHandle {
    if is_managed_thread_of(progress) {
        return DelayHandle::Managed;
    }
    let mut umrefc_ix = progress.umrefc_current.load(Ordering::Acquire);
    loop {
        progress.umrefc[umrefc_ix].fetch_add(1, Ordering::Acquire);
        let tmp_ix = progress.umrefc_current.load(Ordering::Acquire);
        if tmp_ix == umrefc_ix {
            break;
        }
        unmanaged_continue_ix(progress, umrefc_ix);
        umrefc_ix = tmp_ix;
    }
    DelayHandle::Unmanaged(umrefc_ix)
}

/// End a [`unmanaged_delay`].
///
/// Port of erts/emulator/beam/erl_thr_progress.c (unmanaged_continue), OTP-29.1.1.
pub(crate) fn unmanaged_continue(progress: &ThrProgress, handle: DelayHandle) {
    if let DelayHandle::Unmanaged(umrefc_ix) = handle {
        unmanaged_continue_ix(progress, umrefc_ix);
    }
}

fn unmanaged_continue_ix(progress: &ThrProgress, umrefc_ix: usize) {
    let refc = progress.umrefc[umrefc_ix].fetch_sub(1, Ordering::Release) - 1;
    if refc == 0 {
        fence(Ordering::Acquire);
        let lflgs = progress.lflgs.load(Ordering::Relaxed);
        if lflgs & (LFLG_NO_LEADER | LFLG_WAITING_UM | LFLG_ACTIVE_MASK)
            == (LFLG_NO_LEADER | LFLG_WAITING_UM)
            && progress.got_sched_wakeups()
        {
            // Others are waiting for us.
            progress.wakeup_managed(1.min(progress.managed_no().saturating_sub(1)));
        }
    }
}

/// The scheduler's progress point: update, lead and block if requested.
// Port of erl_process.c:9857-9866 (schedule: erts_thr_progress_update and
// erts_thr_progress_leader_update), OTP-29.1.1.
///
/// `run_queue_held` is the scheduler's run queue lock analogue. Port of
/// erts/emulator/beam/erl_process.c:9857-9866 (schedule), OTP-29.1.1: `erts_thr_progress_update`
/// runs with the run queue locked; `erts_thr_progress_leader_update`, which can block the thread
/// for a thread progress blocker, and the aux work run with it unlocked, so a thief retrying this
/// victim cannot keep the blocker waiting.
pub(crate) fn scheduler_progress(managed: &ManagedThread, run_queue: &mut dyn RunQueueHold) {
    let held = run_queue.is_held();
    let mut released = false;
    {
        let tpd = &mut *managed.0.borrow_mut();
        if update(tpd) {
            run_queue.release();
            released = true;
            leader_update(tpd);
        }
    }
    if released && held {
        run_queue.reacquire();
    }
}

/// Drain ready scheduler-owned later operations from `handle_aux_work`.
// Port of erts/emulator/beam/erl_process.c:2281 (handle_thr_prgr_later_op), OTP-29.1.1.
pub(crate) fn handle_thr_prgr_later_op(awdp: *mut AuxWorkLater, current: u64) -> LaterOpHandle {
    raw::handle_thr_prgr_later_op(
        awdp,
        current,
        MIN_THR_PRGR_LATER_OPS,
        LATER_CLEANUP_OP_THRESHOLD,
        has_reached_this,
    )
}

/// The scheduler's hold on its run queue lock across `erts_schedule`.
pub(crate) trait RunQueueHold {
    /// The scheduler holds the run queue lock now.
    fn is_held(&self) -> bool;
    /// `erts_runq_unlock`.
    fn release(&mut self);
    /// `erts_runq_lock`.
    fn reacquire(&mut self);
}

/// A thread without a run queue (tests, unmanaged callers).
impl RunQueueHold for () {
    fn is_held(&self) -> bool {
        false
    }
    fn release(&mut self) {}
    fn reacquire(&mut self) {}
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

// Port of erts/emulator/beam/erl_process.c (haw_chk_later_cleanup_op_wakeup), OTP-29.1.1.
fn haw_chk_later_cleanup_op_wakeup(awdp: &mut AuxWorkLater, val: u64) {
    if !awdp.later_op.is_empty() && cmp(val, awdp.later_op.thr_prgr) != std::cmp::Ordering::Less {
        awdp.later_op.size = LATER_CLEANUP_OP_THRESHOLD;
    }
}

// Port of erts/emulator/beam/erl_process.c (haw_thr_prgr_wakeup), OTP-29.1.1.
fn haw_thr_prgr_wakeup(tpd: &mut ThrPrgrData, awdp: &mut AuxWorkLater, val: u64) {
    let order = cmp(val, awdp.latest_wakeup);
    if order != std::cmp::Ordering::Equal {
        if order == std::cmp::Ordering::Greater {
            awdp.latest_wakeup = val;
            haw_chk_later_cleanup_op_wakeup(awdp, val);
        }
        request_wakeup_managed(tpd, val);
    }
}

// Port of erts/emulator/beam/erl_process.c (haw_thr_prgr_later_cleanup_op_wakeup), OTP-29.1.1:
// cleanup operations ask for a wakeup only once their bytes passed the threshold; until then
// they run when the thread passes its progress points anyway.
fn haw_thr_prgr_later_cleanup_op_wakeup(
    tpd: &mut ThrPrgrData,
    awdp: &mut AuxWorkLater,
    val: u64,
    size: usize,
) {
    if cmp(val, awdp.latest_wakeup) == std::cmp::Ordering::Greater {
        awdp.later_op.thr_prgr = val;
        if awdp.later_op.size > size {
            awdp.later_op.size -= size;
        } else {
            awdp.latest_wakeup = val;
            awdp.later_op.size = LATER_CLEANUP_OP_THRESHOLD;
            request_wakeup_managed(tpd, val);
        }
    }
}

/// Port of erts/emulator/beam/erl_process.c:1703 (`haw_thr_prgr_current_reset`).
pub(crate) fn haw_thr_prgr_current_reset(awdp: *mut AuxWorkLater) {
    raw::aux_work_later_current_reset(awdp);
}

/// Port of erts/emulator/beam/erl_process.c:1708 (`haw_thr_prgr_current`).
pub(crate) fn haw_thr_prgr_current(awdp: *mut AuxWorkLater, progress: &ThrProgress) -> u64 {
    raw::aux_work_later_current(awdp, progress.current.load(Ordering::Acquire))
}

/// Port of erts/emulator/beam/erl_process.c:1720 (`haw_thr_prgr_current_check_progress`).
pub(crate) fn haw_thr_prgr_current_check_progress(cached: u64, progress: &ThrProgress) -> bool {
    cached != VAL_WAITING && cached != progress.current.load(Ordering::Acquire)
}

/// Port of erts/emulator/beam/erl_process.c:2351 (`erts_schedule_thr_prgr_later_op`).
pub(crate) fn erts_schedule_thr_prgr_later_op(
    progress: &ThrProgress,
    awdp: &mut AuxWorkLater,
    aux_work: &AtomicU32,
    later_func: fn(*mut ()),
    later_data: *mut (),
    lop: *mut ErtsThrPrgrLaterOp,
) {
    enqueue_later_op(progress, awdp, aux_work, later_func, later_data, lop, None);
}

/// Port of erts/emulator/beam/erl_process.c:2361 (`erts_schedule_thr_prgr_later_cleanup_op`).
pub(crate) fn erts_schedule_thr_prgr_later_cleanup_op(
    progress: &ThrProgress,
    awdp: &mut AuxWorkLater,
    aux_work: &AtomicU32,
    later_func: fn(*mut ()),
    later_data: *mut (),
    lop: *mut ErtsThrPrgrLaterOp,
    size: usize,
) {
    enqueue_later_op(
        progress,
        awdp,
        aux_work,
        later_func,
        later_data,
        lop,
        Some(size),
    );
}

// Port of erl_process.c:2324 (`enqueue_later_op`), OTP-29.1.1.
pub(crate) fn enqueue_later_op(
    progress: &ThrProgress,
    awdp: &mut AuxWorkLater,
    aux_work: &AtomicU32,
    later_func: fn(*mut ()),
    later_data: *mut (),
    lop: *mut ErtsThrPrgrLaterOp,
    cleanup_size: Option<usize>,
) {
    with_tpd(|tpd| {
        let Some(tpd) = tpd.filter(|tpd| std::ptr::eq(Arc::as_ptr(&tpd.progress), progress)) else {
            debug_assert!(
                false,
                "enqueue_later_op requires a normal scheduler (erts ASSERT esdp && !dirty)"
            );
            return;
        };
        // erts_thr_progress_later: read confirmed, then a full barrier, then current_to_later.
        let later = current_to_later(tpd.confirmed);
        fence(Ordering::SeqCst);
        raw::enqueue(&mut awdp.later_op.list, later, later_func, later_data, lop);
        // Port of erl_process.c:2344 (`set_aux_work_flags_wakeup_nob` in `enqueue_later_op`).
        aux_work.fetch_or(1 << 5, Ordering::Release);
        match cleanup_size {
            Some(size) => haw_thr_prgr_later_cleanup_op_wakeup(tpd, awdp, later, size),
            None => haw_thr_prgr_wakeup(tpd, awdp, later),
        }
    });
}

/// Whether `val` was reached (used by tests).
#[cfg(test)]
fn reached(progress: &ThrProgress, val: u64) -> bool {
    progress.has_reached(val)
}

fn later_list_ready(list: &raw::LaterOpList, current: u64) -> bool {
    raw::first_later(list).is_some_and(|later| has_reached_this(current, later))
}

/// Whether the first later operation of this scheduler became runnable: the global
/// thread progress value reached it.
///
/// Port of erts/emulator/beam/erl_process.c:2285-2320 (handle_thr_prgr_later_op compares the
/// first operation with `erts_thr_progress_current()`), OTP-29.1.1. `scheduler_wait` publishes
/// its sleeping flags first and then looks at this again, so a wakeup that came before the
/// flags were set is not lost.
pub(crate) fn later_op_ready(awdp: &AuxWorkLater, current: u64) -> bool {
    later_list_ready(&awdp.later_op.list, current)
}

/// The next thread-progress value for work scheduled by the calling managed thread.
pub(crate) fn erts_thr_progress_later(managed: &ManagedThread) -> u64 {
    let mut tpd = managed.0.borrow_mut();
    fence(Ordering::SeqCst);
    let later = current_to_later(tpd.confirmed);
    request_wakeup_managed(&mut tpd, later);
    later
}

/// Whether the global thread-progress value reached `value`.
pub(crate) fn erts_thr_progress_has_reached(progress: &ThrProgress, value: u64) -> bool {
    has_reached_this(progress.current.load(Ordering::Acquire), value)
}

/// Run a blocking wait without holding back thread progress: a waiting managed thread
/// counts as waiting, so a thread blocking progress never waits for it.
///
/// Port of erts/emulator/beam/erl_thr_progress.c:884 (erts_thr_progress_prepare_wait) and
/// :913 (erts_thr_progress_finalize_wait), OTP-29.1.1; the caller must not hold locks that
/// a thread blocking progress needs.
pub fn thread_progress_wait<R>(wait: impl FnOnce() -> R) -> R {
    debug_assert!(
        MANAGED_OF.with(Cell::get) == 0 || LOOKUP_DEPTH.with(Cell::get) == 0,
        "a managed thread waits inside a process lookup that holds no reference"
    );
    // Port of erts/emulator/beam/erl_process.c:3576-3579,3611,3660 (scheduler_wait): a thread
    // that sleeps first stops counting as active, so the leader election sees no active
    // thread and a waking thread is not missed, then prepares to wait. Skipping the
    // deactivation leaves ERTS_THR_PRGR_LFLG_ACTIVE_MASK set, nobody becomes the leader,
    // and a later operation queued by a thread that went idle never runs.
    let managed = with_tpd(|tpd| {
        tpd.map(|tpd| {
            let was_active = tpd.active;
            if was_active {
                set_active(tpd, false);
            }
            prepare_wait(tpd);
            was_active
        })
    });
    let result = wait();
    if let Some(was_active) = managed {
        with_tpd(|tpd| {
            if let Some(tpd) = tpd {
                finalize_wait(tpd);
                if was_active && !tpd.active {
                    set_active(tpd, true);
                }
            }
        });
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;

    fn progress(managed: usize) -> Arc<ThrProgress> {
        Arc::new(ThrProgress::new(managed))
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

    struct FlagOp {
        later_op: ErtsThrPrgrLaterOp,
        flag: Arc<AtomicBool>,
    }

    fn set_flag(data: *mut ()) {
        // SAFETY: `data` is the live `FlagOp` the test owns until this later op runs.
        let op = unsafe { &*data.cast::<FlagOp>() };
        op.flag.store(true, Ordering::SeqCst);
    }

    static AUX_WORK_FLAGS: AtomicU32 = AtomicU32::new(0);

    fn schedule_flag(progress: &ThrProgress, awdp: &mut AuxWorkLater, op: &mut FlagOp) {
        erts_schedule_thr_prgr_later_op(
            progress,
            awdp,
            &AUX_WORK_FLAGS,
            set_flag,
            std::ptr::from_mut(op).cast(),
            op.later_op.as_list_node(),
        );
    }

    fn schedule_cleanup(
        progress: &ThrProgress,
        awdp: &mut AuxWorkLater,
        node: &mut ErtsThrPrgrLaterOp,
        size: usize,
    ) {
        erts_schedule_thr_prgr_later_cleanup_op(
            progress,
            awdp,
            &AUX_WORK_FLAGS,
            count_cleanup,
            std::ptr::null_mut(),
            node,
            size,
        );
    }

    fn drain(awdp: &mut AuxWorkLater, current: u64) {
        handle_thr_prgr_later_op(std::ptr::from_mut(awdp), current);
    }

    #[test]
    fn single_managed_thread_leads_and_runs_later_ops() {
        let progress = progress(1);
        std::thread::scope(|scope| {
            scope.spawn(|| {
                let managed = register_managed_thread(&progress, 0);
                let mut awdp = AuxWorkLater::new();
                let mut op = FlagOp {
                    later_op: ErtsThrPrgrLaterOp::new(),
                    flag: Arc::new(AtomicBool::new(false)),
                };
                schedule_flag(&progress, &mut awdp, &mut op);
                for _ in 0..8 {
                    scheduler_progress(&managed, &mut ());
                }
                drain(&mut awdp, progress.current.load(Ordering::Acquire));
                similar_asserts::assert_eq!(op.flag.load(Ordering::SeqCst), true);
                assert!(reached(&progress, 2));
                unregister_managed_thread();
            });
        });
    }

    static CLEANED: AtomicUsize = AtomicUsize::new(0);

    fn count_cleanup(_: *mut ()) {
        CLEANED.fetch_add(1, Ordering::SeqCst);
    }

    /// erl_process.c (haw_thr_prgr_later_cleanup_op_wakeup): the first cleanup operation asks
    /// for a wakeup, later ones only once their bytes pass the threshold; a pass runs at most
    /// `ERTS_MIN_THR_PRGR_LATER_OPS + list_len / 8` operations (handle_thr_prgr_later_op).
    #[test]
    fn cleanup_ops_wake_by_size_and_run_in_limited_batches() {
        let progress = progress(1);
        std::thread::scope(|scope| {
            scope.spawn(|| {
                let managed = register_managed_thread(&progress, 0);
                let mut awdp = AuxWorkLater::new();
                let mut nodes = vec![ErtsThrPrgrLaterOp::new(); 403];
                schedule_cleanup(&progress, &mut awdp, &mut nodes[0], 1024);
                let first = awdp.latest_wakeup;
                similar_asserts::assert_eq!(awdp.later_op.size, LATER_CLEANUP_OP_THRESHOLD);
                // Move progress on so later operations get a later value.
                for _ in 0..4 {
                    let tpd = &mut *managed.0.borrow_mut();
                    if update(tpd) {
                        leader_update(tpd);
                    }
                }
                schedule_cleanup(&progress, &mut awdp, &mut nodes[1], 1024);
                similar_asserts::assert_eq!(
                    awdp.latest_wakeup,
                    first,
                    "small cleanup requests no wakeup"
                );
                similar_asserts::assert_eq!(awdp.later_op.size, LATER_CLEANUP_OP_THRESHOLD - 1024);
                schedule_cleanup(
                    &progress,
                    &mut awdp,
                    &mut nodes[2],
                    LATER_CLEANUP_OP_THRESHOLD,
                );
                assert_ne!(awdp.latest_wakeup, first, "the threshold requests a wakeup");
                similar_asserts::assert_eq!(awdp.later_op.size, LATER_CLEANUP_OP_THRESHOLD);
                for node in &mut nodes[3..] {
                    schedule_cleanup(&progress, &mut awdp, node, 8);
                }
                let queued = awdp.list_len();
                CLEANED.store(0, Ordering::SeqCst);
                for _ in 0..4 {
                    let tpd = &mut *managed.0.borrow_mut();
                    if update(tpd) {
                        leader_update(tpd);
                    }
                }
                drain(&mut awdp, progress.current.load(Ordering::Acquire));
                similar_asserts::assert_eq!(
                    CLEANED.load(Ordering::SeqCst),
                    queued / 8 + MIN_THR_PRGR_LATER_OPS
                );
                while !awdp.is_empty() {
                    drain(&mut awdp, progress.current.load(Ordering::Acquire));
                }
                similar_asserts::assert_eq!(CLEANED.load(Ordering::SeqCst), queued);
                unregister_managed_thread();
            });
        });
    }

    #[test]
    fn unmanaged_delay_holds_back_later_ops() {
        let progress = progress(1);
        let delay = unmanaged_delay(&progress);
        assert!(matches!(delay, DelayHandle::Unmanaged(_)));
        let ran = Arc::new(AtomicBool::new(false));
        std::thread::scope(|scope| {
            scope.spawn(|| {
                let managed = register_managed_thread(&progress, 0);
                let mut awdp = AuxWorkLater::new();
                assert!(matches!(unmanaged_delay(&progress), DelayHandle::Managed));
                let mut op = FlagOp {
                    later_op: ErtsThrPrgrLaterOp::new(),
                    flag: Arc::clone(&ran),
                };
                schedule_flag(&progress, &mut awdp, &mut op);
                for _ in 0..8 {
                    scheduler_progress(&managed, &mut ());
                }
                drain(&mut awdp, progress.current.load(Ordering::Acquire));
                assert!(
                    !ran.load(Ordering::SeqCst),
                    "progress passed an unmanaged delay"
                );
                unmanaged_continue(&progress, delay);
                for _ in 0..8 {
                    scheduler_progress(&managed, &mut ());
                }
                drain(&mut awdp, progress.current.load(Ordering::Acquire));
                assert!(ran.load(Ordering::SeqCst));
                unregister_managed_thread();
            });
        });
    }

    #[test]
    fn later_op_list_is_intrusive_first_last_list_len() {
        let progress = progress(1);
        std::thread::scope(|scope| {
            scope.spawn(|| {
                let managed = register_managed_thread(&progress, 0);
                let mut awdp = AuxWorkLater::new();
                let mut nodes = [ErtsThrPrgrLaterOp::new(), ErtsThrPrgrLaterOp::new()];
                let first = std::ptr::from_mut(&mut nodes[0]);
                let second = std::ptr::from_mut(&mut nodes[1]);
                schedule_cleanup(&progress, &mut awdp, &mut nodes[0], 8);
                schedule_cleanup(&progress, &mut awdp, &mut nodes[1], 8);
                similar_asserts::assert_eq!(awdp.later_op.list_len(), 2);
                similar_asserts::assert_eq!(awdp.later_op.list.first, first);
                similar_asserts::assert_eq!(awdp.later_op.list.last, second);
                similar_asserts::assert_eq!(raw::first_later(&awdp.later_op.list).is_some(), true);
                for _ in 0..8 {
                    scheduler_progress(&managed, &mut ());
                }
                while !awdp.is_empty() {
                    drain(&mut awdp, progress.current.load(Ordering::Acquire));
                }
                unregister_managed_thread();
            });
        });
    }

    #[test]
    fn unmanaged_registration_uses_erts_wakeup_bitmap() {
        let progress = Arc::new(ThrProgress::new_with_callbacks(
            vec![Arc::new(ErtsSchedulerSleepInfo::new(0))].into(),
            1,
        ));
        let woke = Arc::new(AtomicBool::new(false));
        let callback_woke = Arc::clone(&woke);
        let registration = register_unmanaged_thread(&progress, move || {
            callback_woke.store(true, Ordering::SeqCst)
        });
        UNMANAGED_TPD.with(|tpd| {
            request_wakeup_unmanaged(tpd.borrow_mut().as_mut().unwrap(), 2);
        });
        std::thread::scope(|scope| {
            scope.spawn(|| {
                let managed = register_managed_thread(&progress, 0);
                for _ in 0..8 {
                    scheduler_progress(&managed, &mut ());
                }
                unregister_managed_thread();
            });
        });
        assert!(woke.load(Ordering::SeqCst));
        drop(registration);
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
                    let managed = register_managed_thread(&progress, id);
                    while !stop.load(Ordering::SeqCst) {
                        scheduler_progress(&managed, &mut ());
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

    /// erl_thr_progress.c block_thread waits on the blocked thread's own callbacks: the aux
    /// thread (a managed id past the schedulers) sleeps on its SSI event, the primitive its
    /// `wakeup` callback signals, so thr_progress_unblock wakes it.
    #[test]
    fn blocked_aux_thread_wakes_on_unblock() {
        let progress = Arc::new(ThrProgress::new(1));
        let stop = AtomicBool::new(false);
        let passes = AtomicU64::new(0);
        let woke = std::thread::scope(|scope| {
            scope.spawn(|| {
                let managed = register_managed_thread(&progress, 0);
                while !stop.load(Ordering::SeqCst) {
                    scheduler_progress(&managed, &mut ());
                    passes.fetch_add(1, Ordering::SeqCst);
                }
                scheduler_prepare_wait();
                unregister_managed_thread();
            });
            while passes.load(Ordering::SeqCst) == 0 {
                std::thread::yield_now();
            }
            block(&progress);
            let frozen = passes.load(Ordering::SeqCst);
            // block() returns once the aux thread counted itself blocked; let it reach its wait.
            std::thread::sleep(std::time::Duration::from_millis(50));
            unblock(&progress);
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            let woke = loop {
                if passes.load(Ordering::SeqCst) > frozen + 1 {
                    break true;
                }
                if std::time::Instant::now() >= deadline {
                    break false;
                }
                std::thread::yield_now();
            };
            stop.store(true, Ordering::SeqCst);
            if !woke {
                // Release the lost waiter so the scope can join and the test report.
                progress.lflgs.fetch_and(!LFLG_BLOCK, Ordering::SeqCst);
                progress.callbacks[0].event.signal();
            }
            woke
        });
        assert!(
            woke,
            "the blocked aux thread missed thr_progress_unblock's wakeup"
        );
    }
}
