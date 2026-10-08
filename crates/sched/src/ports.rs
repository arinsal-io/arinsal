//! Ports with scheduled tasks on the normal scheduler run queues.
//!
//! Port of erts/emulator/beam/erl_port_task.c:941-987 (enqueue_port, pop_port) and
//! erl_port.h:209-249 (`prt->run_queue`), OTP-29.1.1. A port whose task queue became
//! non-empty is put at the end of the port queue of its run queue; the scheduler of that
//! run queue executes it between processes (erl_process.c:9977, schedule).

use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use crate::balance::{PORT_PRIO_LEVEL, RunQueueBalance};

/// A port as the run queues see it.
pub trait RunPort: Send + Sync + 'static {
    /// The run queue the port belongs to (`prt->run_queue`).
    fn run_queue(&self) -> &PortRunQueue;

    /// Execute the port's tasks on the calling scheduler until it runs out of tasks or
    /// reductions.
    ///
    /// Port of erts/emulator/beam/erl_port_task.c:1677 (erts_port_task_execute) from
    /// pop_port up to the re-enqueue decision, OTP-29.1.1.
    fn execute(&self) -> PortExecution;
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
#[derive(Debug, Default)]
pub struct PortRunQueue(AtomicUsize);

impl PortRunQueue {
    /// Port of erts/emulator/beam/erl_port.h:210 (erts_init_runq_port), OTP-29.1.1.
    pub fn new(ix: usize) -> Self {
        Self(AtomicUsize::new(ix))
    }

    /// Port of erts/emulator/beam/erl_port.h:226 (erts_get_runq_port), OTP-29.1.1.
    pub fn get(&self) -> usize {
        self.0.load(Ordering::Acquire)
    }

    /// Port of erts/emulator/beam/erl_port.h:218 (erts_set_runq_port), OTP-29.1.1.
    pub fn set(&self, ix: usize) {
        self.0.store(ix, Ordering::Release);
    }
}

/// `rq->ports`: the scheduled ports of one run queue, in FIFO order.
#[derive(Default)]
pub(crate) struct PortQueue {
    ports: Mutex<VecDeque<Arc<dyn RunPort>>>,
}

impl PortQueue {
    fn lock(&self) -> MutexGuard<'_, VecDeque<Arc<dyn RunPort>>> {
        self.ports
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Port of erts/emulator/beam/erl_port_task.c:941 (enqueue_port), OTP-29.1.1.
    pub(crate) fn enqueue(&self, balance: &RunQueueBalance, port: Arc<dyn RunPort>) {
        let mut ports = self.lock();
        ports.push_back(port);
        balance.add_len(PORT_PRIO_LEVEL, 1);
    }

    /// Port of erts/emulator/beam/erl_port_task.c:964 (pop_port), OTP-29.1.1.
    pub(crate) fn pop(&self, balance: &RunQueueBalance) -> Option<Arc<dyn RunPort>> {
        let mut ports = self.lock();
        let port = ports.pop_front()?;
        balance.sub_len(PORT_PRIO_LEVEL, 1);
        Some(port)
    }

    /// `rq->ports.start != NULL`.
    pub(crate) fn is_empty(&self) -> bool {
        self.lock().is_empty()
    }
}
