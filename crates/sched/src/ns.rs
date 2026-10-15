//! Namespace word and per-namespace counters.
//!
//! A process carries one `AtomicU32`: the low 31 bits hold its namespace id (0 is root) and the
//! top bit marks a root service that tenant processes may reach.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// Set on a process that processes of other namespaces may send to.
pub const NS_SHARED: u32 = 1 << 31;
/// Mask of the namespace id inside the namespace word.
pub const NS_ID_MASK: u32 = !NS_SHARED;

/// Counters of one namespace, shared between the scheduler and the VM's namespace table.
#[derive(Debug)]
pub struct NsCounters {
    processes: AtomicU64,
    reductions: AtomicU64,
    max_processes: AtomicU64,
    closed: AtomicBool,
}

impl NsCounters {
    /// Counters with a process cap; `u64::MAX` means no cap.
    pub fn new(max_processes: u64) -> Self {
        Self {
            processes: AtomicU64::new(0),
            reductions: AtomicU64::new(0),
            max_processes: AtomicU64::new(max_processes),
            closed: AtomicBool::new(false),
        }
    }

    /// Live processes of the namespace.
    pub fn processes(&self) -> u64 {
        self.processes.load(Ordering::Relaxed)
    }

    /// Reductions executed by processes of the namespace.
    pub fn reductions(&self) -> u64 {
        self.reductions.load(Ordering::Relaxed)
    }

    /// The process cap.
    pub fn max_processes(&self) -> u64 {
        self.max_processes.load(Ordering::Relaxed)
    }

    /// Refuse every later spawn into the namespace.
    pub fn close(&self) {
        self.closed.store(true, Ordering::Release);
    }

    /// Whether [`Self::close`] was called.
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    pub(crate) fn add_reductions(&self, count: u64) {
        self.reductions.fetch_add(count, Ordering::Relaxed);
    }

    /// Count one more process unless the namespace is closed or at its cap.
    pub(crate) fn try_acquire(&self) -> bool {
        if self.is_closed() {
            return false;
        }
        let max = self.max_processes.load(Ordering::Relaxed);
        if self.processes.fetch_add(1, Ordering::AcqRel) >= max {
            self.processes.fetch_sub(1, Ordering::AcqRel);
            return false;
        }
        // A close between the first check and the increment must not leave a process behind.
        if self.is_closed() {
            self.processes.fetch_sub(1, Ordering::AcqRel);
            return false;
        }
        true
    }

    pub(crate) fn release(&self) {
        self.processes.fetch_sub(1, Ordering::AcqRel);
    }
}

/// What delivery does with a signal that crosses namespaces.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NsGate {
    Allow,
    /// Drop silently, like a send to a dead pid.
    Drop,
    /// The sender sees `noproc`.
    NoProcess,
}
