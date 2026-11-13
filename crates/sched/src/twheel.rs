//! The per-scheduler timer wheel: intrusive callback timers with no owner type.
//!
//! Port of erts/emulator/beam/time.c (the timer wheel: erts_create_timer_wheel,
//! erts_twheel_set_timer, erts_twheel_cancel_timer, erts_bump_timers, bump_later_wheel,
//! find_next_timeout, erts_check_next_timeout_time) and erl_time.h (ERTS_TW_* constants,
//! ErtsTWheelTimer), OTP-29.1.1. The wheel knows nothing of processes or messages: each timer
//! carries a callback and an argument, as `ErlTimeoutProc` and `void *arg` in erts.
//!
//! Positions are clock ticks. Arinsal's clock tick is one millisecond (erts with
//! `SYS_CLOCK_RESOLUTION == 1`), so `ERTS_MONOTONIC_TO_CLKTCKS` and its inverse are the identity
//! and `next_timeout_time` equals `next_timeout_pos`.

mod raw;

use std::any::Any;
use std::pin::Pin;

pub use raw::TWheelTimer;
use raw::{Sentinel, TimerPtr};

/// A timeout callback (`ErlTimeoutProc`): `(wheel, esdp, arg)`. erts callbacks reach their
/// scheduler's data, and through it the wheel, with `erts_get_scheduler_data()`; here the
/// bumping wheel and the scheduler context given to [`TimerWheel::bump_timers`] are passed in,
/// so a callback may set or cancel timers on the wheel.
pub type TimeoutProc = fn(&mut TimerWheel, &mut dyn Any, *mut ());

const SOON_WHEEL_BITS: u32 = 14;
const LATER_WHEEL_BITS: u32 = 14;
const SOON_WHEEL_SIZE: i32 = 1 << SOON_WHEEL_BITS;
const LATER_WHEEL_SIZE: i32 = 1 << LATER_WHEEL_BITS;

const SOON_WHEEL_FIRST_SLOT: i32 = 0;
const SOON_WHEEL_END_SLOT: i32 = SOON_WHEEL_FIRST_SLOT + SOON_WHEEL_SIZE;
const SOON_WHEEL_MASK: i64 = (SOON_WHEEL_SIZE - 1) as i64;

const LATER_WHEEL_SHIFT: u32 = SOON_WHEEL_BITS - 1;
const LATER_WHEEL_SLOT_SIZE: i64 = 1 << LATER_WHEEL_SHIFT;
const LATER_WHEEL_POS_MASK: i64 = !(LATER_WHEEL_SLOT_SIZE - 1);
const LATER_WHEEL_FIRST_SLOT: i32 = SOON_WHEEL_SIZE;
const LATER_WHEEL_END_SLOT: i32 = LATER_WHEEL_FIRST_SLOT + LATER_WHEEL_SIZE;
const LATER_WHEEL_MASK: i64 = (LATER_WHEEL_SIZE - 1) as i64;

const SCNT_BITS: u32 = 9;
const SCNT_SIZE: usize = ((SOON_WHEEL_SIZE + LATER_WHEEL_SIZE) >> SCNT_BITS) as usize;

const SLOT_AT_ONCE: i32 = -1;
const SLOT_INACTIVE: i32 = -2;

const BUMP_YIELD_LIMIT: i32 = 10_000;
const COST_SLOT: i32 = 1;
const COST_SLOT_MOVE: i32 = 5;
const COST_TIMEOUT: i32 = 100;

const MAX_CLKTCKS: i64 = i64::MAX;
const CLKTCKS_WEEK: i64 = 7 * 60 * 60 * 24 * 1000;

/// Milliseconds a timer can be ahead of the wheel position and still be set in the wheel
/// (`ERTS_TIMER_WHEEL_MSEC`); erl_hl_timer.c keeps longer timers in its own tree.
pub const TIMER_WHEEL_MSEC: i64 = (LATER_WHEEL_SIZE as i64) * (SOON_WHEEL_SIZE as i64) / 2;

#[derive(Clone, Copy)]
struct SoonState {
    min_tpos: i64,
    nto: usize,
}

#[derive(Clone, Copy)]
struct LaterState {
    min_tpos: i64,
    min_tpos_slot: i32,
    pos: i64,
    nto: usize,
}

/// One scheduler's timer wheel (`ErtsTimerWheel`).
pub struct TimerWheel {
    /// `slots`: the at-once slot, then the soon wheel, then the later wheel; `w(slot)` indexes
    /// it from `ERTS_TW_SLOT_AT_ONCE` as `tiw->w` does.
    slots: Box<[Option<TimerPtr>]>,
    scnt: [isize; SCNT_SIZE],
    bump_scnt: [isize; SCNT_SIZE],
    pos: i64,
    nto: usize,
    at_once_nto: usize,
    soon: SoonState,
    later: LaterState,
    yield_slot: i32,
    yield_slots_left: i32,
    sentinel: Sentinel,
    true_next_timeout_time: bool,
    next_timeout_pos: i64,
}

/// Where a bump enters its loop: from the top, or at the point a yield left it.
#[derive(Clone, Copy)]
enum BumpEntry {
    Start,
    AtOnce,
    Soon {
        slot: i32,
        slots: i32,
        scnt_ix: usize,
    },
    Later,
}

// Port of erts/emulator/beam/time.c (scnt_get_ix), OTP-29.1.1.
fn scnt_get_ix(slot: i32) -> usize {
    (slot >> SCNT_BITS) as usize
}

// Port of erts/emulator/beam/time.c (scnt_wheel_next), OTP-29.1.1.
#[allow(clippy::too_many_arguments)]
fn scnt_wheel_next(
    slotp: &mut i32,
    leftp: &mut i32,
    posp: Option<&mut i64>,
    sixp: Option<&mut usize>,
    scnt: &[isize; SCNT_SIZE],
    first_slot: i32,
    end_slot: i32,
    slot_sz: i64,
) {
    let mut slot = *slotp;
    let mut left = *leftp;
    debug_assert!(left >= 0);
    left -= 1;
    slot += 1;
    if slot == end_slot {
        slot = first_slot;
    }
    let mut ix = slot >> SCNT_BITS;
    while scnt[ix as usize] == 0 && left > 0 {
        let old_slot = slot;
        ix += 1;
        slot = ix << SCNT_BITS;
        let mut diff = slot - old_slot;
        if left < diff {
            slot = old_slot + left;
            diff = left;
        }
        if slot < end_slot {
            left -= diff;
        } else {
            left -= end_slot - old_slot;
            slot = first_slot;
            ix = slot >> SCNT_BITS;
        }
    }
    debug_assert!(left >= -1);
    if let Some(pos) = posp {
        *pos += slot_sz * i64::from(*leftp - left);
    }
    if let Some(six) = sixp {
        *six = scnt_get_ix(slot);
    }
    *leftp = left;
    *slotp = slot;
}

fn scnt_soon_wheel_next(
    slot: &mut i32,
    left: &mut i32,
    pos: Option<&mut i64>,
    six: Option<&mut usize>,
    scnt: &[isize; SCNT_SIZE],
) {
    scnt_wheel_next(
        slot,
        left,
        pos,
        six,
        scnt,
        SOON_WHEEL_FIRST_SLOT,
        SOON_WHEEL_END_SLOT,
        1,
    );
}

fn scnt_later_wheel_next(
    slot: &mut i32,
    left: &mut i32,
    pos: Option<&mut i64>,
    six: Option<&mut usize>,
    scnt: &[isize; SCNT_SIZE],
) {
    scnt_wheel_next(
        slot,
        left,
        pos,
        six,
        scnt,
        LATER_WHEEL_FIRST_SLOT,
        LATER_WHEEL_END_SLOT,
        LATER_WHEEL_SLOT_SIZE,
    );
}

// Port of erts/emulator/beam/time.c (soon_slot), OTP-29.1.1.
fn soon_slot(soon_pos: i64) -> i32 {
    (soon_pos & SOON_WHEEL_MASK) as i32
}

// Port of erts/emulator/beam/time.c (later_slot), OTP-29.1.1.
fn later_slot(later_pos: i64) -> i32 {
    (((later_pos >> LATER_WHEEL_SHIFT) & LATER_WHEEL_MASK) as i32) + LATER_WHEEL_FIRST_SLOT
}

impl TimerWheel {
    /// Port of erts/emulator/beam/time.c (erts_create_timer_wheel), OTP-29.1.1. `pos` is the
    /// current monotonic time in clock ticks.
    pub fn new(pos: i64) -> Self {
        Self {
            slots: vec![None; (1 + SOON_WHEEL_SIZE + LATER_WHEEL_SIZE) as usize].into_boxed_slice(),
            scnt: [0; SCNT_SIZE],
            bump_scnt: [0; SCNT_SIZE],
            pos,
            nto: 0,
            at_once_nto: 0,
            soon: SoonState {
                min_tpos: MAX_CLKTCKS,
                nto: 0,
            },
            later: LaterState {
                min_tpos: MAX_CLKTCKS,
                min_tpos_slot: LATER_WHEEL_END_SLOT,
                pos: (pos + i64::from(SOON_WHEEL_SIZE)) & LATER_WHEEL_POS_MASK,
                nto: 0,
            },
            yield_slot: SLOT_INACTIVE,
            yield_slots_left: 0,
            sentinel: Sentinel::new(),
            true_next_timeout_time: false,
            next_timeout_pos: pos + CLKTCKS_WEEK,
        }
    }

    fn w(&self, slot: i32) -> Option<TimerPtr> {
        self.slots[(slot + 1) as usize]
    }

    fn set_w(&mut self, slot: i32, timer: Option<TimerPtr>) {
        self.slots[(slot + 1) as usize] = timer;
    }

    /// The cached next timeout time (`erts_next_timeout_time` on the reference from
    /// `erts_get_next_timeout_reference`).
    pub fn next_timeout_time(&self) -> i64 {
        self.next_timeout_pos
    }

    /// Port of erts/emulator/beam/time.c (erts_check_next_timeout_time), OTP-29.1.1. `clock`
    /// reads the monotonic time in clock ticks; it is read only when the wheel is empty.
    pub fn check_next_timeout_time(&mut self, clock: impl FnOnce() -> i64) -> i64 {
        if self.true_next_timeout_time {
            return self.next_timeout_pos;
        }
        if self.next_timeout_pos > self.pos + i64::from(SOON_WHEEL_SIZE) {
            return self.next_timeout_pos;
        }
        self.find_next_timeout(clock)
    }

    // Port of erts/emulator/beam/time.c (find_next_timeout), OTP-29.1.1: an empty wheel moves
    // to the current time, read from `clock`.
    fn find_next_timeout(&mut self, clock: impl FnOnce() -> i64) -> i64 {
        let mut true_min_timeout = false;
        let mut min_timeout_pos;
        debug_assert_eq!(self.at_once_nto, 0);
        debug_assert_eq!(self.nto, self.soon.nto + self.later.nto);
        debug_assert_eq!(self.yield_slot, SLOT_INACTIVE);

        'done: {
            if self.nto == 0 {
                let curr = clock();
                self.pos = curr;
                min_timeout_pos = curr;
                self.later.pos = (curr + i64::from(SOON_WHEEL_SIZE)) & LATER_WHEEL_POS_MASK;
                min_timeout_pos += CLKTCKS_WEEK;
                break 'done;
            }

            if self.soon.nto == 0 {
                // Search the later wheel.
                let min_tpos = self.later.min_tpos & LATER_WHEEL_POS_MASK;
                let mut tpos;
                let mut slots;
                if min_tpos <= self.later.pos {
                    tpos = self.later.pos;
                    slots = LATER_WHEEL_SIZE;
                } else {
                    let tmp = (min_tpos - self.later.pos) / LATER_WHEEL_SLOT_SIZE;
                    if tmp >= i64::from(LATER_WHEEL_SIZE) {
                        // Pre-timeout for the move from the later to the soon wheel.
                        min_timeout_pos = min_tpos - LATER_WHEEL_SLOT_SIZE;
                        break 'done;
                    }
                    tpos = min_tpos;
                    slots = LATER_WHEEL_SIZE - tmp as i32;
                }
                let mut slot = later_slot(tpos);
                // The later wheel is never searched for an exact timeout; the first used scnt
                // range is enough.
                if self.w(slot).is_some() {
                    true_min_timeout = true;
                } else {
                    scnt_later_wheel_next(&mut slot, &mut slots, Some(&mut tpos), None, &self.scnt);
                }
                self.later.min_tpos = tpos;
                self.later.min_tpos_slot = slot;
                debug_assert_eq!(slot, later_slot(tpos));
                min_timeout_pos = tpos - LATER_WHEEL_SLOT_SIZE;
            } else {
                // Search the soon wheel.
                min_timeout_pos = self.pos + i64::from(SOON_WHEEL_SIZE);

                // Two later wheel slots can trigger timeouts before the soon wheel does.
                if self.later.min_tpos <= self.later.pos + 2 * LATER_WHEEL_SLOT_SIZE {
                    let mut tpos = self.later.pos - LATER_WHEEL_SLOT_SIZE;
                    let mut fslot = later_slot(self.later.pos);
                    if self.w(fslot).is_some() {
                        min_timeout_pos = tpos;
                    } else {
                        tpos += LATER_WHEEL_SLOT_SIZE;
                        if tpos < min_timeout_pos {
                            fslot += 1;
                            if fslot == LATER_WHEEL_END_SLOT {
                                fslot = LATER_WHEEL_FIRST_SLOT;
                            }
                            if self.w(fslot).is_some() {
                                min_timeout_pos = tpos;
                            }
                        }
                    }
                }

                let mut tpos;
                let mut slots;
                if self.soon.min_tpos <= self.pos {
                    tpos = self.pos;
                    slots = SOON_WHEEL_SIZE;
                } else {
                    let tmp = self.soon.min_tpos - self.pos;
                    debug_assert!(tmp < i64::from(SOON_WHEEL_SIZE));
                    slots = SOON_WHEEL_SIZE - tmp as i32;
                    tpos = self.soon.min_tpos;
                }
                let mut slot = soon_slot(tpos);
                // Find the next non-empty slot.
                while tpos < min_timeout_pos {
                    if let Some(p) = self.w(slot) {
                        debug_assert_eq!(p.timeout_pos(), tpos);
                        min_timeout_pos = tpos;
                        break;
                    }
                    scnt_soon_wheel_next(&mut slot, &mut slots, Some(&mut tpos), None, &self.scnt);
                }
                self.soon.min_tpos = min_timeout_pos;
                true_min_timeout = true;
            }
        }

        // A timeout further away than a week is never exposed (poll() and friends take a
        // limited timeout); the scheduler then rechecks once a week.
        let timeout_pos_limit = self.pos + CLKTCKS_WEEK;
        if min_timeout_pos > timeout_pos_limit {
            min_timeout_pos = timeout_pos_limit;
            true_min_timeout = false;
        }
        self.next_timeout_pos = min_timeout_pos;
        self.true_next_timeout_time = true_min_timeout;
        min_timeout_pos
    }

    // Port of erts/emulator/beam/time.c (insert_timer_into_slot), OTP-29.1.1.
    fn insert_timer_into_slot(&mut self, slot: i32, p: TimerPtr) {
        debug_assert!((SLOT_AT_ONCE..LATER_WHEEL_END_SLOT).contains(&slot));
        p.set_slot(slot);
        match self.w(slot) {
            None => {
                self.set_w(slot, Some(p));
                p.set_next(p);
                p.set_prev(p);
            }
            Some(next) => {
                let prev = next.prev();
                p.set_next(next);
                p.set_prev(prev);
                prev.set_next(p);
                next.set_prev(p);
            }
        }
        if slot == SLOT_AT_ONCE {
            self.at_once_nto += 1;
        } else {
            let tpos = p.timeout_pos();
            if slot < SOON_WHEEL_END_SLOT {
                debug_assert!(tpos < self.pos + i64::from(SOON_WHEEL_SIZE));
                self.soon.nto += 1;
                if self.soon.min_tpos > tpos {
                    self.soon.min_tpos = tpos;
                }
            } else {
                debug_assert!(tpos >= self.pos + i64::from(SOON_WHEEL_SIZE));
                self.later.nto += 1;
                if self.later.min_tpos > tpos {
                    self.later.min_tpos = tpos;
                    self.later.min_tpos_slot = slot;
                }
            }
            self.scnt[scnt_get_ix(slot)] += 1;
        }
    }

    // Port of erts/emulator/beam/time.c (remove_timer), OTP-29.1.1. The timer is in the
    // circular list of its slot, or of the sentinel while its slot is being triggered.
    fn remove_timer(&mut self, p: TimerPtr) {
        let slot = p.slot();
        debug_assert!((SLOT_AT_ONCE..LATER_WHEEL_END_SLOT).contains(&slot));
        let empty_slot = if p.next() == p {
            // Cannot be referred to by the sentinel, so it is the slot's only timer.
            debug_assert!(self.w(slot) == Some(p));
            self.set_w(slot, None);
            true
        } else {
            if self.w(slot) == Some(p) {
                self.set_w(slot, Some(p.next()));
            }
            p.prev().set_next(p.next());
            p.next().set_prev(p.prev());
            false
        };
        if slot == SLOT_AT_ONCE {
            debug_assert!(self.at_once_nto > 0);
            self.at_once_nto -= 1;
        } else {
            self.scnt[scnt_get_ix(slot)] -= 1;
            debug_assert!(self.scnt[scnt_get_ix(slot)] >= 0);
            if slot < SOON_WHEEL_END_SLOT {
                if empty_slot
                    && self.true_next_timeout_time
                    && p.timeout_pos() == self.next_timeout_pos
                    && self.yield_slot == SLOT_INACTIVE
                {
                    self.true_next_timeout_time = false;
                }
                self.soon.nto -= 1;
                if self.soon.nto == 0 {
                    self.soon.min_tpos = MAX_CLKTCKS;
                }
            } else {
                if empty_slot && self.true_next_timeout_time && self.later.min_tpos_slot == slot {
                    let tpos = (self.later.min_tpos & LATER_WHEEL_POS_MASK) - LATER_WHEEL_SLOT_SIZE;
                    if tpos == self.next_timeout_pos && self.yield_slot == SLOT_INACTIVE {
                        self.true_next_timeout_time = false;
                    }
                }
                self.later.nto -= 1;
                if self.later.nto == 0 {
                    self.later.min_tpos = MAX_CLKTCKS;
                    self.later.min_tpos_slot = LATER_WHEEL_END_SLOT;
                }
            }
        }
        p.detach();
    }

    // Port of erts/emulator/beam/time.c (timeout_timer), OTP-29.1.1.
    fn timeout_timer(&mut self, p: TimerPtr, esdp: &mut dyn Any) {
        let (timeout, arg) = p.deactivate();
        timeout(self, esdp, arg);
    }

    /// Moves the circular list of `slot`, minus its head `p`, onto the sentinel; `p` is then
    /// processed first (erts_bump_timers / bump_later_wheel).
    fn slot_to_sentinel(&mut self, slot: i32, p: TimerPtr) {
        let sentinel = self.sentinel.ptr();
        if p.next() == p {
            debug_assert!(sentinel.next() == sentinel && sentinel.prev() == sentinel);
        } else {
            sentinel.set_next(p.next());
            sentinel.set_prev(p.prev());
            sentinel.next().set_prev(sentinel);
            sentinel.prev().set_next(sentinel);
        }
        self.set_w(slot, None);
    }

    /// The next timer on the sentinel, or `None` when the triggered slot is done. `Err(())`
    /// when the yield limit is reached first (`yield_now`).
    fn sentinel_next(&mut self, yield_now: bool) -> Result<Option<TimerPtr>, ()> {
        let sentinel = self.sentinel.ptr();
        let p = sentinel.next();
        if p == sentinel {
            debug_assert!(sentinel.prev() == sentinel);
            return Ok(None);
        }
        if yield_now {
            return Err(());
        }
        sentinel.set_next(p.next());
        p.next().set_prev(sentinel);
        Ok(Some(p))
    }

    /// Port of erts/emulator/beam/time.c (erts_bump_timers), OTP-29.1.1: triggers every timer
    /// due at `curr_time`, yielding after `ERTS_TWHEEL_BUMP_YIELD_LIMIT` work; the next call
    /// continues where this one stopped. `esdp` is handed to every callback.
    pub fn bump_timers(&mut self, curr_time: i64, esdp: &mut dyn Any) {
        let mut yield_count = BUMP_YIELD_LIMIT;
        let slot = self.yield_slot;
        let mut restarted = slot != SLOT_INACTIVE;
        let mut bump_to = 0;
        let mut entry = BumpEntry::Start;
        if restarted {
            bump_to = self.pos;
            if slot >= LATER_WHEEL_FIRST_SLOT {
                entry = BumpEntry::Later;
            } else {
                self.yield_slot = SLOT_INACTIVE;
                entry = if slot == SLOT_AT_ONCE {
                    BumpEntry::AtOnce
                } else {
                    let slots = self.yield_slots_left;
                    debug_assert!((0..=SOON_WHEEL_SIZE).contains(&slots));
                    BumpEntry::Soon {
                        slot,
                        slots,
                        scnt_ix: scnt_get_ix(slot),
                    }
                };
            }
        }

        loop {
            if matches!(entry, BumpEntry::Start) {
                restarted = false;
                bump_to = curr_time;
                self.true_next_timeout_time = true;
                self.next_timeout_pos = bump_to;
            }

            loop {
                // At-once slot.
                match entry {
                    BumpEntry::Start => {
                        if self.nto == 0 {
                            self.empty_wheel(bump_to);
                            return;
                        }
                        if let Some(p) = self.w(SLOT_AT_ONCE) {
                            self.slot_to_sentinel(SLOT_AT_ONCE, p);
                            if self.trigger_at_once(Some(p), &mut yield_count, esdp) {
                                return;
                            }
                        }
                    }
                    BumpEntry::AtOnce => {
                        if self.trigger_at_once(None, &mut yield_count, esdp) {
                            return;
                        }
                    }
                    BumpEntry::Soon { .. } | BumpEntry::Later => {}
                }

                // Soon wheel.
                let resume_soon = match entry {
                    BumpEntry::Soon {
                        slot,
                        slots,
                        scnt_ix,
                    } => Some((slot, slots, scnt_ix)),
                    _ => None,
                };
                if !matches!(entry, BumpEntry::Later) {
                    let (mut slot, mut slots, mut scnt_ix, mut first) = match resume_soon {
                        Some((slot, slots, scnt_ix)) => (slot, slots, scnt_ix, false),
                        None => {
                            if self.pos >= bump_to {
                                if self.at_once_nto != 0 {
                                    entry = BumpEntry::Start;
                                    continue;
                                }
                                break;
                            }
                            if self.nto == 0 {
                                self.empty_wheel(bump_to);
                                return;
                            }
                            // The number of timers to trigger or move only decreases during
                            // this bump, even across yields; callbacks may add timers.
                            self.bump_scnt = self.scnt;

                            if self.soon.min_tpos > self.pos {
                                // Skip slots known to hold no timers to trigger.
                                let skip_until_pos = self.soon.min_tpos.min(bump_to) - 1;
                                if skip_until_pos > self.pos {
                                    self.pos = skip_until_pos;
                                }
                            }
                            let tmp_slots = bump_to - self.pos;
                            let slots = if tmp_slots < i64::from(SOON_WHEEL_SIZE) {
                                tmp_slots as i32
                            } else {
                                SOON_WHEEL_SIZE
                            };
                            let slot = soon_slot(self.pos + 1);
                            self.pos = bump_to;
                            self.next_timeout_pos = bump_to;
                            (slot, slots, scnt_get_ix(slot), true)
                        }
                    };

                    // Trigger the timers of the soon wheel.
                    while slots > 0 {
                        let head = if first {
                            yield_count -= COST_SLOT;
                            self.w(slot)
                        } else {
                            None
                        };
                        if (first && head.is_some()) || !first {
                            if let Some(p) = head {
                                // Timeout callbacks need `pos` up to date.
                                self.slot_to_sentinel(slot, p);
                            }
                            if self.trigger_soon_slot(
                                head,
                                slot,
                                slots,
                                scnt_ix,
                                bump_to,
                                &mut yield_count,
                                esdp,
                            ) {
                                return;
                            }
                        }
                        first = true;
                        scnt_soon_wheel_next(
                            &mut slot,
                            &mut slots,
                            None,
                            Some(&mut scnt_ix),
                            &self.bump_scnt,
                        );
                    }
                }

                // Later wheel.
                if (matches!(entry, BumpEntry::Later)
                    || self.pos + LATER_WHEEL_SLOT_SIZE >= self.later.pos)
                    && self.bump_later_wheel(&mut yield_count, esdp)
                {
                    return;
                }
                entry = BumpEntry::Start;
            }

            if !restarted {
                break;
            }
            entry = BumpEntry::Start;
        }

        self.true_next_timeout_time = false;
        debug_assert_eq!(self.next_timeout_pos, bump_to);
        let pos = self.pos;
        self.find_next_timeout(|| pos);
    }

    // The `empty_wheel` exit of erts_bump_timers.
    fn empty_wheel(&mut self, bump_to: i64) {
        self.true_next_timeout_time = false;
        self.next_timeout_pos = bump_to + CLKTCKS_WEEK;
        self.pos = bump_to;
        self.later.pos = (bump_to + i64::from(SOON_WHEEL_SIZE)) & LATER_WHEEL_POS_MASK;
        self.yield_slot = SLOT_INACTIVE;
    }

    /// The at-once loop of erts_bump_timers; `true` when it yielded.
    fn trigger_at_once(
        &mut self,
        mut p: Option<TimerPtr>,
        yield_count: &mut i32,
        esdp: &mut dyn Any,
    ) -> bool {
        loop {
            if let Some(timer) = p {
                debug_assert!(self.nto > 0 && self.at_once_nto > 0);
                self.nto -= 1;
                self.at_once_nto -= 1;
                self.timeout_timer(timer, esdp);
                *yield_count -= COST_TIMEOUT;
            }
            match self.sentinel_next(*yield_count <= 0) {
                Ok(None) => return false,
                Ok(next) => p = next,
                Err(()) => {
                    debug_assert!(self.nto > 0 && self.at_once_nto > 0);
                    self.yield_slot = SLOT_AT_ONCE;
                    return true;
                }
            }
        }
    }

    /// The soon-slot loop of erts_bump_timers; `true` when it yielded.
    #[allow(clippy::too_many_arguments)]
    fn trigger_soon_slot(
        &mut self,
        mut p: Option<TimerPtr>,
        slot: i32,
        slots: i32,
        scnt_ix: usize,
        bump_to: i64,
        yield_count: &mut i32,
        esdp: &mut dyn Any,
    ) -> bool {
        loop {
            if let Some(timer) = p {
                debug_assert!((SOON_WHEEL_FIRST_SLOT..SOON_WHEEL_END_SLOT).contains(&timer.slot()));
                self.soon.nto -= 1;
                if self.soon.nto == 0 {
                    self.soon.min_tpos = MAX_CLKTCKS;
                }
                self.scnt[scnt_ix] -= 1;
                if timer.timeout_pos() <= bump_to {
                    self.timeout_timer(timer, esdp);
                    self.nto -= 1;
                    self.bump_scnt[scnt_ix] -= 1;
                    *yield_count -= COST_TIMEOUT;
                } else {
                    // Uncommon: a timer a revolution ahead.
                    self.insert_timer_into_slot(slot, timer);
                    *yield_count -= COST_SLOT_MOVE;
                }
            }
            match self.sentinel_next(*yield_count <= 0) {
                Ok(None) => return false,
                Ok(next) => p = next,
                Err(()) => {
                    self.yield_slot = slot;
                    self.yield_slots_left = slots;
                    return true;
                }
            }
        }
    }

    // Port of erts/emulator/beam/time.c (bump_later_wheel), OTP-29.1.1. `true` when it yielded.
    fn bump_later_wheel(&mut self, ycount_p: &mut i32, esdp: &mut dyn Any) -> bool {
        let cpos = self.pos;
        let mut later_pos = self.later.pos;
        let mut ycount = *ycount_p;
        let mut fslot;
        let mut slots;
        let mut scnt_ix;
        let mut resume = false;

        if self.yield_slot >= LATER_WHEEL_FIRST_SLOT {
            fslot = self.yield_slot;
            scnt_ix = scnt_get_ix(fslot);
            slots = self.yield_slots_left;
            debug_assert!((0..=LATER_WHEEL_SIZE).contains(&slots));
            self.yield_slot = SLOT_INACTIVE;
            resume = true;
        } else {
            let min_tpos = self.later.min_tpos & LATER_WHEEL_POS_MASK;
            let end_later_pos = (cpos + i64::from(SOON_WHEEL_SIZE)) & LATER_WHEEL_POS_MASK;
            // Skip known empty slots.
            if min_tpos > later_pos {
                if min_tpos > end_later_pos {
                    self.later.pos = end_later_pos;
                    *ycount_p = ycount;
                    return false;
                }
                later_pos = min_tpos;
            }
            let tmp_slots = (end_later_pos - later_pos) / LATER_WHEEL_SLOT_SIZE;
            slots = if tmp_slots < i64::from(LATER_WHEEL_SIZE) {
                tmp_slots as i32
            } else {
                LATER_WHEEL_SIZE
            };
            fslot = later_slot(later_pos);
            scnt_ix = scnt_get_ix(fslot);
            self.later.pos = end_later_pos;
        }

        while slots > 0 {
            let mut p = None;
            if !resume {
                ycount -= COST_SLOT;
                p = self.w(fslot);
            }
            if resume || p.is_some() {
                if let Some(head) = p {
                    self.slot_to_sentinel(fslot, head);
                }
                resume = false;
                loop {
                    if let Some(timer) = p {
                        let tpos = timer.timeout_pos();
                        debug_assert_eq!(timer.slot(), fslot);
                        self.later.nto -= 1;
                        if self.later.nto == 0 {
                            self.later.min_tpos = MAX_CLKTCKS;
                            self.later.min_tpos_slot = LATER_WHEEL_END_SLOT;
                        }
                        self.scnt[scnt_ix] -= 1;
                        if tpos >= self.later.pos + LATER_WHEEL_SLOT_SIZE {
                            // Keep in the later slot; very uncommon.
                            self.insert_timer_into_slot(fslot, timer);
                            ycount -= COST_SLOT_MOVE;
                        } else {
                            self.bump_scnt[scnt_ix] -= 1;
                            debug_assert!(tpos < cpos + i64::from(SOON_WHEEL_SIZE));
                            if tpos > cpos {
                                // Move into the soon wheel.
                                self.insert_timer_into_slot(soon_slot(tpos), timer);
                                ycount -= COST_SLOT_MOVE;
                            } else {
                                // Trigger at once.
                                self.timeout_timer(timer, esdp);
                                self.nto -= 1;
                                ycount -= COST_TIMEOUT;
                            }
                        }
                    }
                    match self.sentinel_next(ycount < 0) {
                        Ok(None) => break,
                        Ok(next) => p = next,
                        Err(()) => {
                            self.yield_slot = fslot;
                            self.yield_slots_left = slots;
                            *ycount_p = 0;
                            return true;
                        }
                    }
                }
            }
            scnt_later_wheel_next(
                &mut fslot,
                &mut slots,
                None,
                Some(&mut scnt_ix),
                &self.bump_scnt,
            );
        }

        *ycount_p = ycount;
        false
    }

    /// Port of erts/emulator/beam/time.c (erts_twheel_set_timer), OTP-29.1.1: links `timer`,
    /// which must be inactive, to call `timeout(wheel, arg)` at `timeout_pos`.
    pub fn set_timer(
        &mut self,
        timer: Pin<&TWheelTimer>,
        timeout: TimeoutProc,
        arg: *mut (),
        timeout_pos: i64,
    ) {
        assert!(!timer.is_active(), "timer-wheel timer set twice");
        let p = TimerPtr::from_pin(timer);
        p.set_callback(timeout, arg);
        p.set_owner(self.sentinel.ptr());
        self.nto += 1;

        let slot;
        let mut timeout_pos = timeout_pos;
        if timeout_pos <= self.pos {
            // At once.
            timeout_pos = self.pos;
            p.set_timeout_pos(timeout_pos);
            slot = SLOT_AT_ONCE;
        } else if timeout_pos < self.pos + i64::from(SOON_WHEEL_SIZE) {
            // Soon wheel.
            p.set_timeout_pos(timeout_pos);
            slot = soon_slot(timeout_pos);
            if self.soon.min_tpos > timeout_pos {
                self.soon.min_tpos = timeout_pos;
            }
        } else {
            // Later wheel. The next timeout it causes is one later slot early, in time to
            // move it into the soon wheel.
            p.set_timeout_pos(timeout_pos);
            slot = later_slot(timeout_pos);
            timeout_pos &= LATER_WHEEL_POS_MASK;
            timeout_pos -= LATER_WHEEL_SLOT_SIZE;
        }

        self.insert_timer_into_slot(slot, p);

        if timeout_pos <= self.next_timeout_pos {
            self.true_next_timeout_time = true;
            if timeout_pos < self.next_timeout_pos {
                self.next_timeout_pos = timeout_pos;
            }
        }
    }

    /// Port of erts/emulator/beam/time.c (erts_twheel_cancel_timer), OTP-29.1.1: unlinks
    /// `timer` if it is set; an inactive timer is left alone.
    pub fn cancel_timer(&mut self, timer: Pin<&TWheelTimer>) {
        if timer.is_active() {
            let p = TimerPtr::from_pin(timer);
            assert!(
                std::ptr::eq(p.owner(), self.sentinel.ptr().as_ptr()),
                "timer-wheel timer cancelled through another wheel"
            );
            self.remove_timer(p);
            self.nto -= 1;
        }
    }
}

impl Drop for TimerWheel {
    fn drop(&mut self) {
        // Timers still set keep pointing at the sentinel; unlink them so they may be dropped.
        let sentinel = self.sentinel.ptr();
        let mut p = sentinel.next();
        while p != sentinel {
            let next = p.next();
            p.detach();
            p = next;
        }
        for slot in SLOT_AT_ONCE..LATER_WHEEL_END_SLOT {
            if let Some(head) = self.w(slot) {
                let mut p = head;
                loop {
                    let next = p.next();
                    p.detach();
                    if next == head {
                        break;
                    }
                    p = next;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests;
