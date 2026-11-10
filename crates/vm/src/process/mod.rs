//! Scheduler adapter and message envelopes for BEAM processes.

use crate::{Process, RunState, Vm, VmError};
use arinsal_beamasm::SchedulerRegisters;
use arinsal_pterm::RetiredArea;
use arinsal_sched::{
    Config, Event, Payload, Pid, RunCtx, RunOutcome, Scheduler, Signal, Task, proc_flags,
};
use arinsal_term::ptab::PtabIdRing;
use arinsal_term::{
    Atom, ProcessHeap, SharedCopyCache, Term, TermBuilder, VecHeap, copy_struct_litopt, copy_term,
    copy_term_preserving_sharing_with_cache, global_atoms, size_object,
};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock, mpsc};

mod executor;
mod executor_after_native;
mod executor_run;
mod exit;
mod gc;
mod gc_roots;
#[cfg(test)]
mod layout_tests;
mod links;
mod max_heap;
mod message;
mod message_queue;
mod receive;
mod runtime;
pub(crate) mod sched_data;
mod schedule;
mod send;
mod sig_queue;
mod spawn_eval;

pub(crate) use self::executor::*;
use self::exit::*;
pub(crate) use self::gc::*;
use self::links::*;
pub(crate) use self::max_heap::*;
pub(crate) use self::message::*;
pub(crate) use self::message_queue::*;
pub(crate) use self::receive::*;
pub use self::runtime::ScheduledResult;
pub(crate) use self::runtime::*;
use self::schedule::*;
pub(crate) use self::send::*;
pub(crate) use self::sig_queue::*;
use self::spawn_eval::*;

/// Port of erts/emulator/beam/erl_vm.h:53 (CONTEXT_REDS), OTP-29.1.1.
pub(crate) const CONTEXT_REDS: i32 = 4000;

/// Port of erts/emulator/beam/erl_process.h (erts_time2reds), OTP-29.1.1: the reductions
/// charged for `elapsed` on a dirty CPU scheduler. At least one, else four per whole
/// microsecond (`(CONTEXT_REDS - 1) / 1000 + 1`).
pub(crate) fn erts_time2reds(elapsed: std::time::Duration) -> u64 {
    let microseconds = u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX);
    if microseconds == 0 {
        return 1;
    }
    microseconds.saturating_mul(((CONTEXT_REDS - 1) / 1000 + 1) as u64)
}
