//! Scheduler adapter and message envelopes for BEAM processes.

use crate::{Process, RunState, Vm, VmError};
use arinsal_beamasm::SchedulerRegisters;
use arinsal_pterm::RetiredArea;
use arinsal_sched::{Config, Event, Payload, Pid, RunCtx, Scheduler, Signal, Task, proc_flags};

/// erts' `Process *c_p`: the running VM process, with whole-struct provenance.
// Port of erts/emulator/beam/erl_process.h (`Process *c_p`), OTP-29.1.1.
pub(crate) type CP<'a> = arinsal_sched::CP<'a, Process>;
/// erts' `ErtsSchedulerData *esdp` of the VM: monomorphic over the VM process, as erts' is.
// Port of erts/emulator/beam/erl_process.h:687 (struct ErtsSchedulerData_), OTP-29.1.1.
pub(crate) type ErtsSchedulerData = arinsal_sched::ErtsSchedulerData<Process>;
use arinsal_term::ptab::PtabIdRing;
use arinsal_term::{
    Atom, ProcessHeap, SharedCopyCache, Term, TermBuilder, VecHeap, copy_struct_litopt, copy_term,
    copy_term_preserving_sharing_with_cache, global_atoms, size_object,
};
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

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
mod registers;
mod runtime;
mod schedule;
mod send;
mod sig_queue;
pub(crate) use sig_queue::FlushSignals;
mod spawn_eval;
pub(crate) use self::spawn_eval::eval_carrier_args;

pub(crate) use self::executor::*;
#[cfg(target_arch = "aarch64")]
pub(crate) use self::executor_run::beam_exit_address;
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
pub(crate) use self::sig_queue::*;
pub use self::spawn_eval::EntryProcess;
use self::spawn_eval::*;

/// Offset of the process state word (`c_p->state`, [`arinsal_sched::psflg`]) from `c_p`, the
/// native prefix at the start of a process. Generated code tests `ERTS_PSFLG_*` bits at this
/// offset, as erts code reads `offsetof(Process, state)`.
// Port of erts/emulator/beam/erl_process.h (`erts_atomic32_t state` in `struct process`),
// OTP-29.1.1.
pub const PROCESS_STATE_OFFSET: usize = arinsal_sched::process_state_offset::<crate::Process>();
/// Offset of `c_p->flags` ([`arinsal_term::pflags`]) from `c_p`.
// Port of erts/emulator/beam/erl_process.h (`Uint32 flags` in `struct process`), OTP-29.1.1.
pub const PROCESS_FLAGS_OFFSET: usize =
    std::mem::offset_of!(crate::Process, heap) + arinsal_term::ProcessHeap::FLAGS_OFFSET;
const _: () = assert!(PROCESS_FLAGS_OFFSET == 0x60);
/// Offset of `c_p->mbuf` (the heap fragment list head) from `c_p`. Generated code compares it
/// with null after a light BIF, as erts does.
// Port of erts/emulator/beam/erl_process.h (`ErlHeapFragment* mbuf` in `struct process`),
// OTP-29.1.1.
pub const PROCESS_MBUF_OFFSET: usize =
    std::mem::offset_of!(crate::Process, heap) + arinsal_term::ProcessHeap::MBUF_OFFSET;
/// Offset of `c_p->mbuf_sz` from `c_p`.
// Port of erts/emulator/beam/erl_process.h (`Uint mbuf_sz` in `struct process`), OTP-29.1.1.
pub const PROCESS_MBUF_SZ_OFFSET: usize =
    std::mem::offset_of!(crate::Process, heap) + arinsal_term::ProcessHeap::MBUF_SZ_OFFSET;
const _: () = assert!(PROCESS_MBUF_OFFSET == 0x78 && PROCESS_MBUF_SZ_OFFSET == 0x80);
const _: () = assert!(std::mem::offset_of!(crate::Process, heap) == 0);

/// `sig_qs` of `struct process`: the message queue (`first`, `last`, `save`, `mq_len`) and the
/// middle queue (`cont`) at fixed offsets from `c_p`. Generated code loads `*sig_qs.save` to
/// peek the message a receive looks at, as erts reads `offsetof(Process, sig_qs.save)`.
// Port of erts/emulator/beam/erl_message.h (`ErtsSignalPrivQueues`) and erl_process.h
// (`ErtsSignalPrivQueues sig_qs` in `struct process`), OTP-29.1.1.
const PROCESS_SIGQ_OFFSET: usize =
    std::mem::offset_of!(crate::Process, inbox) + std::mem::offset_of!(MessageQueue, entries);
type MsgQList = arinsal_sched::MessageQueueList<arinsal_sched::Event<Message>>;
/// Offset of `c_p->sig_qs.first` from `c_p`.
pub const PROCESS_SIGQ_FIRST_OFFSET: usize = PROCESS_SIGQ_OFFSET + MsgQList::FIRST_OFFSET;
/// Offset of `c_p->sig_qs.last` from `c_p`.
pub const PROCESS_SIGQ_LAST_OFFSET: usize = PROCESS_SIGQ_OFFSET + MsgQList::LAST_OFFSET;
/// Offset of `c_p->sig_qs.save` from `c_p`.
pub const PROCESS_SIGQ_SAVE_OFFSET: usize = PROCESS_SIGQ_OFFSET + MsgQList::SAVE_OFFSET;
/// Offset of `c_p->sig_qs.mq_len` from `c_p`.
pub const PROCESS_SIGQ_MQ_LEN_OFFSET: usize = PROCESS_SIGQ_OFFSET + MsgQList::LEN_OFFSET;
/// Offset of `c_p->sig_qs.cont` (the first signal of the middle queue) from `c_p`.
pub const PROCESS_SIGQ_CONT_OFFSET: usize = std::mem::offset_of!(crate::Process, sig_cont)
    + arinsal_sched::SignalQueue::<arinsal_sched::Event<Message>>::FIRST_OFFSET;
/// `offsetof(ErtsMessage, m[0])`: the term of a message in its queue node.
// Port of erts/emulator/beam/erl_message.h (`ErtsMessage.m[0]`), OTP-29.1.1.
pub const ERTS_MESSAGE_TERM_OFFSET: usize = MESSAGE_TERM_OFFSET;
const _: () = assert!(
    PROCESS_SIGQ_LAST_OFFSET == PROCESS_SIGQ_FIRST_OFFSET + 8
        && PROCESS_SIGQ_SAVE_OFFSET == PROCESS_SIGQ_FIRST_OFFSET + 16
        && PROCESS_SIGQ_MQ_LEN_OFFSET == PROCESS_SIGQ_FIRST_OFFSET + 24
);

const _: () = assert!(std::mem::offset_of!(arinsal_term::ProcessHeap, abi) == 0);

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
