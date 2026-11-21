//! The scheduler sleep info: the flags word a sleeping scheduler publishes and the thread
//! event it sleeps on, and the operations that sleep and wake through them.
// Port of erts/emulator/beam/erl_process.h:266-282 (ERTS_SSI_FLG_*, ErtsSchedulerSleepInfo)
// and erl_process.c:3029-3165, 3675-3700 (sched_prep_spin_wait, sched_prep_cont_spin_wait,
// sched_spin_wait, sched_set_sleeptype, thr_prgr_wakeup/prep_wait/wait/fin_wait,
// ssi_flags_set_wake, ssi_wake), erl_process.h:3020 (erts_sched_poke) and erl_process.c
// (erts_sched_finish_poke), OTP-29.1.1.

use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use crate::thr_progress::ThreadEvent;

pub(crate) const ERTS_SSI_FLG_SLEEPING: u32 = 1 << 0;
pub(crate) const ERTS_SSI_FLG_POLL_SLEEPING: u32 = 1 << 1;
pub(crate) const ERTS_SSI_FLG_TSE_SLEEPING: u32 = 1 << 2;
pub(crate) const ERTS_SSI_FLG_WAITING: u32 = 1 << 3;
pub(crate) const ERTS_SSI_FLG_SUSPENDED: u32 = 1 << 4;
pub(crate) const ERTS_SSI_FLG_MSB_EXEC: u32 = 1 << 5;
const ERTS_SSI_FLGS_SLEEP_TYPE: u32 = ERTS_SSI_FLG_TSE_SLEEPING | ERTS_SSI_FLG_POLL_SLEEPING;
const ERTS_SSI_FLGS_SLEEP: u32 = ERTS_SSI_FLG_SLEEPING | ERTS_SSI_FLGS_SLEEP_TYPE;

/// `ERTS_SCHED_SPIN_UNTIL_YIELD`.
const ERTS_SCHED_SPIN_UNTIL_YIELD: i32 = 100;

/// The per-scheduler sleep state that also owns the ERTS aux-work word.
// Port of erts/emulator/beam/erl_process.h:362 (ErtsSchedulerSleepInfo), OTP-29.1.1.
#[repr(align(64))]
pub(crate) struct ErtsSchedulerSleepInfo {
    pub(crate) flags: AtomicU32,
    /// `ssi->event`: the erts_tse the scheduler sleeps on.
    pub(crate) event: ThreadEvent,
    pub(crate) aux_work: AtomicU32,
}

impl ErtsSchedulerSleepInfo {
    pub(crate) fn new(flags: u32) -> Self {
        Self {
            flags: AtomicU32::new(flags),
            event: ThreadEvent::new(),
            aux_work: AtomicU32::new(0),
        }
    }

    /// Whether the scheduler published that it is about to sleep or sleeps.
    pub(crate) fn is_sleeping(&self) -> bool {
        self.flags.load(Ordering::SeqCst) & ERTS_SSI_FLG_SLEEPING != 0
    }
}

/// `ETHR_SPIN_BODY`: `pause` on x86, a compiler barrier on AArch64.
// Port of erts/include/internal/ethread.h:419-439 (ETHR_SPIN_BODY), OTP-29.1.1.
#[inline(always)]
fn ethr_spin_body() {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    std::hint::spin_loop();
    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
    std::sync::atomic::compiler_fence(Ordering::SeqCst);
}

/// `sched_prep_spin_wait`: publish SLEEPING|WAITING unless the scheduler is suspended.
pub(crate) fn sched_prep_spin_wait(ssi: &ErtsSchedulerSleepInfo) -> u32 {
    let mut xflgs = 0;
    loop {
        let nflgs = (xflgs & ERTS_SSI_FLG_MSB_EXEC) | ERTS_SSI_FLG_SLEEPING | ERTS_SSI_FLG_WAITING;
        match ssi
            .flags
            .compare_exchange(xflgs, nflgs, Ordering::SeqCst, Ordering::SeqCst)
        {
            Ok(_) => return nflgs,
            Err(oflgs) => {
                if oflgs & ERTS_SSI_FLG_SUSPENDED != 0 {
                    return oflgs;
                }
                xflgs = oflgs;
            }
        }
    }
}

/// `sched_prep_cont_spin_wait`: re-publish SLEEPING after a wait that left WAITING set.
pub(crate) fn sched_prep_cont_spin_wait(ssi: &ErtsSchedulerSleepInfo) -> u32 {
    let mut nflgs = ERTS_SSI_FLG_SLEEPING | ERTS_SSI_FLG_WAITING;
    let mut xflgs = ERTS_SSI_FLG_WAITING;
    loop {
        match ssi
            .flags
            .compare_exchange(xflgs, nflgs, Ordering::SeqCst, Ordering::SeqCst)
        {
            Ok(_) => return nflgs,
            Err(oflgs) => {
                if oflgs & ERTS_SSI_FLG_WAITING == 0 {
                    return oflgs;
                }
                xflgs = oflgs;
                nflgs |= oflgs & (ERTS_SSI_FLG_SUSPENDED | ERTS_SSI_FLG_MSB_EXEC);
            }
        }
    }
}

/// `sched_spin_wait`: spin while SLEEPING|WAITING stays set, `spincount` rounds at most.
pub(crate) fn sched_spin_wait(ssi: &ErtsSchedulerSleepInfo, spincount: u32) -> u32 {
    let mut until_yield = ERTS_SCHED_SPIN_UNTIL_YIELD;
    let mut sc = spincount;
    loop {
        let flgs = ssi.flags.load(Ordering::Acquire);
        if flgs & (ERTS_SSI_FLG_SLEEPING | ERTS_SSI_FLG_WAITING)
            != (ERTS_SSI_FLG_SLEEPING | ERTS_SSI_FLG_WAITING)
        {
            return flgs;
        }
        ethr_spin_body();
        until_yield -= 1;
        if until_yield == 0 {
            until_yield = ERTS_SCHED_SPIN_UNTIL_YIELD;
            std::thread::yield_now();
        }
        // `do { } while (--sc > 0)`: a zero count still reads the flags once.
        sc = sc.saturating_sub(1);
        if sc == 0 {
            return flgs;
        }
    }
}

/// `sched_set_sleeptype`: commit to `sleep_type` (TSE or poll) unless woken meanwhile.
/// For a TSE sleep the event is reset first; for a poll sleep `reset_poll` clears a stale
/// pollset interrupt (`erts_check_io_interrupt(ssi->psi, 0)`).
pub(crate) fn sched_set_sleeptype(
    ssi: &ErtsSchedulerSleepInfo,
    sleep_type: u32,
    reset_poll: impl FnOnce(),
) -> u32 {
    let mut nflgs = ERTS_SSI_FLG_SLEEPING | ERTS_SSI_FLG_WAITING | sleep_type;
    let mut xflgs = ERTS_SSI_FLG_SLEEPING | ERTS_SSI_FLG_WAITING;
    if sleep_type == ERTS_SSI_FLG_TSE_SLEEPING {
        ssi.event.reset();
    } else {
        debug_assert_eq!(sleep_type, ERTS_SSI_FLG_POLL_SLEEPING);
        reset_poll();
    }
    loop {
        match ssi
            .flags
            .compare_exchange(xflgs, nflgs, Ordering::SeqCst, Ordering::SeqCst)
        {
            Ok(_) => return nflgs,
            Err(oflgs) => {
                if oflgs & (ERTS_SSI_FLG_SLEEPING | ERTS_SSI_FLG_WAITING)
                    != (ERTS_SSI_FLG_SLEEPING | ERTS_SSI_FLG_WAITING)
                {
                    return oflgs;
                }
                xflgs = oflgs;
                nflgs |= oflgs & (ERTS_SSI_FLG_SUSPENDED | ERTS_SSI_FLG_MSB_EXEC);
            }
        }
    }
}

/// The end of `scheduler_wait`: clear every flag but SUSPENDED and MSB_EXEC.
pub(crate) fn sched_wait_clear(ssi: &ErtsSchedulerSleepInfo, flgs: u32) {
    if flgs & !(ERTS_SSI_FLG_SUSPENDED | ERTS_SSI_FLG_MSB_EXEC) != 0 {
        ssi.flags.fetch_and(
            ERTS_SSI_FLG_SUSPENDED | ERTS_SSI_FLG_MSB_EXEC,
            Ordering::SeqCst,
        );
    }
}

/// `erts_tse_twait(ssi->event, timeout)` repeated while it returns EINTR, as scheduler_wait
/// does: returns when the event is set or `deadline` passes.
///
/// macOS coalesces kernel timers (a timed condvar wait overshoots by about 1.5 ms, a full
/// extra millisecond on every Erlang timer); erts' ethr_event waits there with `select`,
/// which does not. The coarse part of the wait is shortened by that overshoot and the rest is
/// spent yielding until the deadline or the set.
// Port of erts/lib_src/pthread/ethr_event.c (wait__, ethr_event_twait), OTP-29.1.1.
pub(crate) fn tse_twait_until(ssi: &ErtsSchedulerSleepInfo, deadline: Instant) {
    const SLACK: Duration = if cfg!(target_os = "macos") {
        Duration::from_micros(2_500)
    } else {
        Duration::ZERO
    };
    loop {
        let now = Instant::now();
        if now >= deadline {
            return;
        }
        let left = deadline - now;
        let coarse = left.saturating_sub(SLACK);
        if coarse >= Duration::from_micros(200) || SLACK.is_zero() {
            if ssi.event.twait(coarse.max(Duration::from_micros(1))) {
                return;
            }
        } else {
            std::thread::yield_now();
            if ssi.event.try_take() {
                return;
            }
        }
    }
}

const ERTS_SSI_FLGS_SUSPENDED_WAIT: u32 =
    ERTS_SSI_FLG_SLEEPING | ERTS_SSI_FLG_WAITING | ERTS_SSI_FLG_SUSPENDED;

/// `ERTS_SCHED_SUSPEND_SLEEP_SPINCOUNT`.
const ERTS_SCHED_SUSPEND_SLEEP_SPINCOUNT: u32 = 0;

/// `sched_prep_spin_suspended`: publish SLEEPING|WAITING|SUSPENDED while SUSPENDED stays set;
/// returns the flags seen when the scheduler is no longer suspended.
// Port of erts/emulator/beam/erl_process.c:7366 (sched_prep_spin_suspended), OTP-29.1.1.
pub(crate) fn sched_prep_spin_suspended(ssi: &ErtsSchedulerSleepInfo, xpct: u32) -> u32 {
    let nflgs = ERTS_SSI_FLGS_SUSPENDED_WAIT;
    let mut xflgs = xpct;
    loop {
        match ssi
            .flags
            .compare_exchange(xflgs, nflgs, Ordering::SeqCst, Ordering::SeqCst)
        {
            Ok(_) => return nflgs,
            Err(oflgs) => {
                if oflgs & ERTS_SSI_FLG_SUSPENDED == 0 {
                    return oflgs;
                }
                xflgs = oflgs;
            }
        }
    }
}

/// `sched_spin_suspended`.
// Port of erts/emulator/beam/erl_process.c:7385 (sched_spin_suspended), OTP-29.1.1.
fn sched_spin_suspended(ssi: &ErtsSchedulerSleepInfo, spincount: u32) -> u32 {
    let mut until_yield = ERTS_SCHED_SPIN_UNTIL_YIELD;
    let mut sc = spincount;
    loop {
        let flgs = ssi.flags.load(Ordering::Acquire);
        if flgs & ERTS_SSI_FLGS_SUSPENDED_WAIT != ERTS_SSI_FLGS_SUSPENDED_WAIT {
            return flgs;
        }
        ethr_spin_body();
        until_yield -= 1;
        if until_yield == 0 {
            until_yield = ERTS_SCHED_SPIN_UNTIL_YIELD;
            std::thread::yield_now();
        }
        sc = sc.saturating_sub(1);
        if sc == 0 {
            return flgs;
        }
    }
}

/// `sched_set_suspended_sleeptype` with `ERTS_SSI_FLG_TSE_SLEEPING`.
// Port of erts/emulator/beam/erl_process.c:7409 (sched_set_suspended_sleeptype), OTP-29.1.1.
fn sched_set_suspended_sleeptype(ssi: &ErtsSchedulerSleepInfo) -> u32 {
    let nflgs = ERTS_SSI_FLGS_SUSPENDED_WAIT | ERTS_SSI_FLG_TSE_SLEEPING;
    let mut xflgs = ERTS_SSI_FLGS_SUSPENDED_WAIT;
    ssi.event.reset();
    loop {
        match ssi
            .flags
            .compare_exchange(xflgs, nflgs, Ordering::SeqCst, Ordering::SeqCst)
        {
            Ok(_) => return nflgs,
            Err(oflgs) => {
                if oflgs & ERTS_SSI_FLGS_SUSPENDED_WAIT != ERTS_SSI_FLGS_SUSPENDED_WAIT {
                    return oflgs;
                }
                xflgs = oflgs;
            }
        }
    }
}

/// `suspend_scheduler_sleep` of a dirty scheduler (`normal_sched == 0`): sleep on
/// `ssi->event` without a timeout until a wake clears the suspended wait flags.
// Port of erts/emulator/beam/erl_process.c:7742 (suspend_scheduler_sleep), OTP-29.1.1.
pub(crate) fn suspend_scheduler_sleep_dirty(ssi: &ErtsSchedulerSleepInfo) {
    let flgs = sched_spin_suspended(ssi, ERTS_SCHED_SUSPEND_SLEEP_SPINCOUNT);
    if flgs == ERTS_SSI_FLGS_SUSPENDED_WAIT {
        let flgs = sched_set_suspended_sleeptype(ssi);
        if flgs == ERTS_SSI_FLGS_SUSPENDED_WAIT | ERTS_SSI_FLG_TSE_SLEEPING {
            ssi.event.wait();
        }
    }
}

/// `sched_resume_wake__`: clear SUSPENDED (and the sleep flags) and wake the scheduler if it
/// slept.
// Port of erts/emulator/beam/erl_process.c:7330 (sched_resume_wake__), OTP-29.1.1.
pub(crate) fn sched_resume_wake(ssi: &ErtsSchedulerSleepInfo) {
    let mut xflgs = ERTS_SSI_FLG_SLEEPING
        | ERTS_SSI_FLG_TSE_SLEEPING
        | ERTS_SSI_FLG_WAITING
        | ERTS_SSI_FLG_SUSPENDED;
    loop {
        match ssi
            .flags
            .compare_exchange(xflgs, 0, Ordering::SeqCst, Ordering::SeqCst)
        {
            Ok(oflgs) => {
                erts_sched_finish_poke(ssi, oflgs, || {});
                return;
            }
            Err(oflgs) => {
                if oflgs & (ERTS_SSI_FLG_MSB_EXEC | ERTS_SSI_FLG_SUSPENDED) == 0 {
                    return;
                }
                xflgs = oflgs;
            }
        }
    }
}

/// `ssi_flags_set_wake`: reset every flag but SUSPENDED and MSB_EXEC, returning the old ones.
fn ssi_flags_set_wake(ssi: &ErtsSchedulerSleepInfo) -> u32 {
    let mut nflgs = 0;
    let mut xflgs = ERTS_SSI_FLG_SLEEPING | ERTS_SSI_FLG_WAITING;
    loop {
        match ssi
            .flags
            .compare_exchange(xflgs, nflgs, Ordering::SeqCst, Ordering::SeqCst)
        {
            Ok(oflgs) => return oflgs,
            Err(oflgs) => {
                nflgs = oflgs & (ERTS_SSI_FLG_SUSPENDED | ERTS_SSI_FLG_MSB_EXEC);
                xflgs = oflgs;
            }
        }
    }
}

/// `erts_sched_finish_poke`: signal the primitive the scheduler sleeps on. `interrupt_poll`
/// is `erts_check_io_interrupt(ssi->psi, 1)`.
pub(crate) fn erts_sched_finish_poke(
    ssi: &ErtsSchedulerSleepInfo,
    flags: u32,
    interrupt_poll: impl FnOnce(),
) {
    match flags & ERTS_SSI_FLGS_SLEEP_TYPE {
        ERTS_SSI_FLG_POLL_SLEEPING => interrupt_poll(),
        // Thread progress blocking while poll sleeping: signal both.
        ERTS_SSI_FLGS_SLEEP_TYPE => {
            interrupt_poll();
            ssi.event.signal();
        }
        ERTS_SSI_FLG_TSE_SLEEPING => ssi.event.signal(),
        _ => {}
    }
}

/// `ssi_wake`.
pub(crate) fn ssi_wake(ssi: &ErtsSchedulerSleepInfo, interrupt_poll: impl FnOnce()) {
    erts_sched_finish_poke(ssi, ssi_flags_set_wake(ssi), interrupt_poll);
}

/// `erts_sched_poke`: wake the thread only if it sleeps, leaving WAITING as it is.
pub(crate) fn erts_sched_poke(ssi: &ErtsSchedulerSleepInfo, interrupt_poll: impl FnOnce()) {
    std::sync::atomic::fence(Ordering::SeqCst);
    if ssi.flags.load(Ordering::Relaxed) & ERTS_SSI_FLG_SLEEPING != 0 {
        let flags = ssi.flags.fetch_and(!ERTS_SSI_FLGS_SLEEP, Ordering::SeqCst);
        erts_sched_finish_poke(ssi, flags, interrupt_poll);
    }
}

/// `thr_prgr_prep_wait`.
pub(crate) fn thr_prgr_prep_wait(ssi: &ErtsSchedulerSleepInfo) {
    ssi.flags.fetch_or(ERTS_SSI_FLG_SLEEPING, Ordering::SeqCst);
}

/// `thr_prgr_wait`.
pub(crate) fn thr_prgr_wait(ssi: &ErtsSchedulerSleepInfo) {
    let mut xflgs = ERTS_SSI_FLG_SLEEPING;
    ssi.event.reset();
    loop {
        let nflgs = xflgs | ERTS_SSI_FLG_TSE_SLEEPING;
        match ssi
            .flags
            .compare_exchange(xflgs, nflgs, Ordering::SeqCst, Ordering::SeqCst)
        {
            Ok(_) => {
                ssi.event.wait();
                break;
            }
            Err(aflgs) => {
                if aflgs & ERTS_SSI_FLG_SLEEPING == 0 {
                    break;
                }
                xflgs = aflgs;
            }
        }
    }
}

/// `thr_prgr_fin_wait`.
pub(crate) fn thr_prgr_fin_wait(ssi: &ErtsSchedulerSleepInfo) {
    ssi.flags.fetch_and(
        !(ERTS_SSI_FLG_SLEEPING | ERTS_SSI_FLG_TSE_SLEEPING),
        Ordering::Relaxed,
    );
}
