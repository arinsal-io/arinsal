//! Raw access to the intrusive timer-wheel nodes. Every `unsafe` of the timer wheel is in this
//! module.
//!
//! Port of erts/emulator/beam/erl_time.h (ErtsTWheelTimer), OTP-29.1.1. The wheel links timers
//! that live in their owners' memory (erts embeds `ErtsTWheelTimer` in `ErtsTWTimer`, ports and
//! the hl-timer service); the wheel keeps pointers to them between calls.
//!
//! Soundness: a [`TimerPtr`] is only dereferenced while its timer is linked into a live wheel
//! (or is that wheel's sentinel). A linked timer cannot move (it is `!Unpin` and is linked
//! through `Pin`), cannot be dropped (its `Drop` aborts while linked) and cannot be linked into
//! or cancelled through another wheel (`owner` names the wheel it is linked into). A wheel that
//! is dropped first unlinks every timer it holds. All node fields are `Cell`s, so the wheel only
//! ever forms shared references to a timer.

use std::cell::Cell;
use std::marker::PhantomPinned;
use std::pin::Pin;
use std::ptr::NonNull;

use super::{SLOT_INACTIVE, TimeoutProc};

/// A timer-wheel timer (`ErtsTWheelTimer`): embedded in its owner, linked into one wheel at a
/// time by [`super::TimerWheel::set_timer`].
pub struct TWheelTimer {
    /// Timeout in absolute clock ticks.
    timeout_pos: Cell<i64>,
    next: Cell<TimerPtr>,
    prev: Cell<TimerPtr>,
    timeout: Cell<Option<TimeoutProc>>,
    arg: Cell<*mut ()>,
    slot: Cell<i32>,
    /// Sentinel of the wheel the timer is linked into; null while inactive. Not in erts: the
    /// C API trusts the caller to cancel through the right wheel, the safe Rust API checks it.
    owner: Cell<*const TWheelTimer>,
    _pinned: PhantomPinned,
}

impl TWheelTimer {
    /// An inactive timer (`erts_twheel_init_timer`).
    pub const fn new() -> Self {
        Self {
            timeout_pos: Cell::new(0),
            next: Cell::new(TimerPtr::DANGLING),
            prev: Cell::new(TimerPtr::DANGLING),
            timeout: Cell::new(None),
            arg: Cell::new(std::ptr::null_mut()),
            slot: Cell::new(SLOT_INACTIVE),
            owner: Cell::new(std::ptr::null()),
            _pinned: PhantomPinned,
        }
    }

    /// `true` while the timer is linked into a wheel (`slot != ERTS_TW_SLOT_INACTIVE`).
    pub fn is_active(&self) -> bool {
        self.slot.get() != SLOT_INACTIVE
    }

    /// The timeout position the timer was set with (`erts_tweel_read_timeout`).
    pub fn read_timeout(&self) -> i64 {
        self.timeout_pos.get()
    }
}

impl Default for TWheelTimer {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for TWheelTimer {
    fn drop(&mut self) {
        if self.is_active() {
            // The wheel still points at this memory; continuing would leave it dangling.
            eprintln!("arinsal: timer-wheel timer dropped while set");
            std::process::abort();
        }
    }
}

/// A pointer to a timer linked into a wheel, or to a wheel's sentinel.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct TimerPtr(NonNull<TWheelTimer>);

impl TimerPtr {
    const DANGLING: TimerPtr = TimerPtr(NonNull::dangling());

    pub(super) fn from_pin(timer: Pin<&TWheelTimer>) -> Self {
        Self(NonNull::from(timer.get_ref()))
    }

    fn node(&self) -> &TWheelTimer {
        // SAFETY: per the module invariant the pointee is a linked timer or a live sentinel:
        // pinned, not dropped while linked, and only accessed through `Cell` fields.
        unsafe { self.0.as_ref() }
    }

    pub(super) fn timeout_pos(self) -> i64 {
        self.node().timeout_pos.get()
    }
    pub(super) fn set_timeout_pos(self, pos: i64) {
        self.node().timeout_pos.set(pos);
    }
    pub(super) fn next(self) -> TimerPtr {
        self.node().next.get()
    }
    pub(super) fn set_next(self, next: TimerPtr) {
        self.node().next.set(next);
    }
    pub(super) fn prev(self) -> TimerPtr {
        self.node().prev.get()
    }
    pub(super) fn set_prev(self, prev: TimerPtr) {
        self.node().prev.set(prev);
    }
    pub(super) fn slot(self) -> i32 {
        self.node().slot.get()
    }
    pub(super) fn set_slot(self, slot: i32) {
        self.node().slot.set(slot);
    }
    pub(super) fn owner(self) -> *const TWheelTimer {
        self.node().owner.get()
    }
    pub(super) fn set_callback(self, timeout: TimeoutProc, arg: *mut ()) {
        self.node().timeout.set(Some(timeout));
        self.node().arg.set(arg);
    }

    /// Marks the timer inactive and returns its callback (`timeout_timer`). After this the
    /// pointer must not be used: the callback may free the timer.
    pub(super) fn deactivate(self) -> (TimeoutProc, *mut ()) {
        let node = self.node();
        node.slot.set(SLOT_INACTIVE);
        node.owner.set(std::ptr::null());
        (
            node.timeout.get().expect("active timer has a callback"),
            node.arg.get(),
        )
    }

    /// Links the timer to the wheel whose sentinel is `owner`.
    pub(super) fn set_owner(self, owner: TimerPtr) {
        self.node().owner.set(owner.0.as_ptr());
    }

    /// Unlinks the timer without touching any wheel (wheel teardown).
    pub(super) fn detach(self) {
        let node = self.node();
        node.slot.set(SLOT_INACTIVE);
        node.owner.set(std::ptr::null());
    }

    pub(super) fn as_ptr(self) -> *const TWheelTimer {
        self.0.as_ptr()
    }
}

/// The wheel's sentinel (`ErtsTimerWheel.sentinel`), boxed so its address outlives moves of the
/// wheel; timers being triggered link to it.
pub(super) struct Sentinel(TimerPtr);

impl Sentinel {
    pub(super) fn new() -> Self {
        let node = NonNull::from(Box::leak(Box::new(TWheelTimer::new())));
        let ptr = TimerPtr(node);
        ptr.set_next(ptr);
        ptr.set_prev(ptr);
        Sentinel(ptr)
    }

    pub(super) fn ptr(&self) -> TimerPtr {
        self.0
    }
}

impl Drop for Sentinel {
    fn drop(&mut self) {
        // SAFETY: the node was leaked from a Box in `Sentinel::new` and is freed only here; the
        // wheel unlinked every timer pointing at it before dropping the sentinel.
        drop(unsafe { Box::from_raw(self.0.0.as_ptr()) });
    }
}
