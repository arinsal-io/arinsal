//! Ports with scheduled tasks on the normal scheduler run queues.
//!
//! Port of erts/emulator/beam/erl_port_task.c:941-987 (enqueue_port, pop_port) and
//! erl_port.h:209-249 (`prt->run_queue`), OTP-29.1.1. A port whose task queue became
//! non-empty is put at the end of the port queue of its run queue; the scheduler of that
//! run queue executes it between processes (erl_process.c:9977, schedule).

use crate::run_queue::raw::PortLink;
use std::sync::atomic::{AtomicUsize, Ordering};

/// A port as the run queues see it.
pub trait RunPort: Send + Sync + 'static {
    /// The run queue the port belongs to (`prt->run_queue`).
    fn run_queue(&self) -> &PortRunQueue;

    /// Execute the port's tasks on the calling scheduler until it runs out of tasks or
    /// reductions. `scheduler_id` is that normal scheduler's zero-based id.
    ///
    /// Port of erts/emulator/beam/erl_port_task.c:1677 (erts_port_task_execute) from
    /// pop_port up to the re-enqueue decision, OTP-29.1.1.
    fn execute(&self, scheduler_id: usize) -> PortExecution;
}

/// Outcome of [`RunPort::execute`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PortExecution {
    /// The port still has tasks and goes back to a run queue (`active`).
    pub active: bool,
    /// Reductions to account to the run queue (`pp->reds - vreds`).
    pub reds: i32,
}

/// `prt->run_queue`: index of the run queue of a port.
#[derive(Default)]
pub struct PortRunQueue {
    index: AtomicUsize,
    pub(crate) next: PortLink,
}

impl PortRunQueue {
    /// Port of erts/emulator/beam/erl_port.h:210 (erts_init_runq_port), OTP-29.1.1.
    pub fn new(ix: usize) -> Self {
        Self {
            index: AtomicUsize::new(ix),
            next: PortLink::default(),
        }
    }

    /// Port of erts/emulator/beam/erl_port.h:226 (erts_get_runq_port), OTP-29.1.1.
    pub fn get(&self) -> usize {
        self.index.load(Ordering::Acquire)
    }

    /// Port of erts/emulator/beam/erl_port.h:218 (erts_set_runq_port), OTP-29.1.1.
    pub fn set(&self, ix: usize) {
        self.index.store(ix, Ordering::Release);
    }
}
