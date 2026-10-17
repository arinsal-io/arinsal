//! Dirty jobs executed without the process's task cell (the erts main process lock), so
//! the dirty signal handler processes can handle the process's signals meanwhile.
//!
//! Port of erts/emulator/beam/erl_nif.c:426 (erts_call_dirty_nif) and bif.c:5760
//! (erts_call_dirty_bif), OTP-29.1.1.

use std::any::Any;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use arinsal_sched::{DirtyJob, DirtyKind};
use arinsal_term::{ProcessHeap, Term};

use crate::Process;
use crate::natives::nif::PendingNif;

/// Body of a dirty BIF: it builds its result on the shadow heap it is given.
pub(crate) type DirtyBifBody = Box<dyn FnOnce(&mut ProcessHeap) -> DirtyBifResult + Send>;

/// Result of a dirty BIF body; the error is the `error` exception reason atom.
pub(crate) type DirtyBifResult = Result<Term, &'static str>;

/// A dirty BIF call waiting for its job, or its finished result.
pub(crate) enum DirtyBif {
    Job(DirtyKind, DirtyBifBody),
    Done(DirtyBifResult),
}

/// What a dirty job hands back to its process.
enum DirtyDone {
    Nif(PendingNif, ProcessHeap),
    Static(Result<Term, arinsal_bifs::BifError>, ProcessHeap),
    Bif(DirtyBifResult, ProcessHeap),
}

// erts shadow processes allocate in heap fragments; this is the first fragment's size.
const SHADOW_HEAP_WORDS: usize = 256;

fn shadow_heap() -> ProcessHeap {
    ProcessHeap::with_words_for_type(
        SHADOW_HEAP_WORDS,
        arinsal_alloc::typed::ErtsAlcType::HEAP_FRAG,
    )
}

fn scheduler_class(kind: DirtyKind) -> arinsal_bifs::SchedulerClass {
    match kind {
        DirtyKind::Cpu => arinsal_bifs::SchedulerClass::DirtyCpu,
        DirtyKind::Io => arinsal_bifs::SchedulerClass::DirtyIo,
    }
}

thread_local! {
    /// Exit flag of the process whose dirty job runs on this thread.
    static JOB_EXIT_FLAG: std::cell::RefCell<Option<Arc<AtomicBool>>> =
        const { std::cell::RefCell::new(None) };
}

/// Whether the process whose dirty job runs on this thread is exiting; NIF hook for
/// `enif_is_current_process_alive`. Outside dirty jobs the caller holds its process and
/// it is not exiting.
pub(crate) fn current_process_exiting() -> bool {
    JOB_EXIT_FLAG.with(|flag| {
        flag.borrow()
            .as_ref()
            .is_some_and(|flag| flag.load(Ordering::Acquire))
    })
}

/// Run `job` with `flag` as this thread's current dirty process exit flag.
fn with_exit_flag(flag: Arc<AtomicBool>, job: DirtyJob) -> DirtyJob {
    Box::new(move || {
        let previous = JOB_EXIT_FLAG.with(|slot| slot.replace(Some(flag)));
        let result = job();
        JOB_EXIT_FLAG.with(|slot| *slot.borrow_mut() = previous);
        result
    })
}

/// A static NIF body as a dirty job.
pub(crate) fn static_nif_job(
    body: impl FnOnce(&mut ProcessHeap) -> Result<Term, arinsal_bifs::BifError> + 'static,
) -> DirtyJob {
    Box::new(move || {
        let mut heap = shadow_heap();
        let result = body(&mut heap);
        Box::new(DirtyDone::Static(result, heap)) as Box<dyn Any>
    })
}

/// The terms of a finished dirty job's result: a dirty BIF value, or a static NIF value or
/// the terms of its exception.
fn dirty_result_slots<'a>(
    dirty_bif: Option<&'a mut DirtyBif>,
    static_nif_done: Option<&'a mut Result<Term, arinsal_bifs::BifError>>,
) -> Vec<&'a mut Term> {
    use arinsal_bifs::BifError;
    let mut slots = Vec::new();
    if let Some(DirtyBif::Done(Ok(value))) = dirty_bif {
        slots.push(value);
    }
    match static_nif_done {
        Some(Ok(value)) => slots.push(value),
        Some(Err(BifError::Badarg { cause: Some(term) } | BifError::Error(term))) => {
            slots.push(term)
        }
        Some(Err(BifError::Raise {
            reason, stacktrace, ..
        })) => {
            slots.push(reason);
            slots.extend(stacktrace.as_mut());
        }
        _ => {}
    }
    slots
}

impl Process {
    /// Whether [`Process::dirty_result_roots`] would return any term, without building them.
    #[inline]
    pub(crate) fn has_dirty_result_roots(&self) -> bool {
        let Some(cold) = self.cold.as_ref() else {
            return false;
        };
        matches!(&cold.dirty_bif, Some(DirtyBif::Done(Ok(_)))) || cold.static_nif_done.is_some()
    }

    /// The result of a finished dirty job that waits for its call to be executed again.
    ///
    /// erts schedules the result (or exception) as the argument of `erts_internal:
    /// dirty_bif_result/1`, `dirty_nif_finalizer/1` or their exception counterparts, so it
    /// sits in `c_p->arg_reg` with `c_p->arity` set, where a collection and the literal-area
    /// check find it. These slots are the same roots.
    // Port of erts/emulator/beam/bif.c:5814-5843 (erts_call_dirty_bif), erl_nif.c:509-535
    // (erts_call_dirty_nif) and erl_nfunc_sched.c:126-137 (erts_nfunc_schedule copies the
    // arguments into the registers), OTP-29.1.1.
    pub(crate) fn dirty_result_roots(&self) -> Vec<Term> {
        let Some(cold) = self.cold.as_ref() else {
            return Vec::new();
        };
        let mut dirty_bif = match &cold.dirty_bif {
            Some(DirtyBif::Done(Ok(value))) => Some(DirtyBif::Done(Ok(*value))),
            _ => None,
        };
        let mut static_nif_done = cold.static_nif_done;
        dirty_result_slots(dirty_bif.as_mut(), static_nif_done.as_mut())
            .into_iter()
            .map(|term| *term)
            .collect()
    }

    /// Mutable view of [`Process::dirty_result_roots`], in the same order.
    pub(crate) fn dirty_result_roots_mut(&mut self) -> Vec<&mut Term> {
        match self.cold.as_mut() {
            Some(cold) => {
                dirty_result_slots(cold.dirty_bif.as_mut(), cold.static_nif_done.as_mut())
            }
            None => Vec::new(),
        }
    }

    /// The dirty job this process executes next on a dirty scheduler of `kind`.
    pub(crate) fn take_dirty_job(&mut self, kind: DirtyKind) -> Option<DirtyJob> {
        let job = self.next_dirty_job(kind)?;
        Some(with_exit_flag(self.dirty_exit_flag(), job))
    }

    fn next_dirty_job(&mut self, kind: DirtyKind) -> Option<DirtyJob> {
        if self.dirty_exiting() {
            return None;
        }
        let cold = self.cold.as_mut()?;
        if matches!(&cold.dirty_bif, Some(DirtyBif::Job(wanted, _)) if *wanted == kind) {
            let Some(DirtyBif::Job(_, body)) = cold.dirty_bif.take() else {
                return None;
            };
            return Some(Box::new(move || {
                let mut heap = shadow_heap();
                let result = body(&mut heap);
                Box::new(DirtyDone::Bif(result, heap)) as Box<dyn Any>
            }));
        }
        if cold
            .nif_pending
            .as_ref()
            .is_some_and(|pending| !pending.is_done() && pending.class() == scheduler_class(kind))
        {
            let mut pending = cold.nif_pending.take()?;
            // The job runs on this thread; NIF services find the process through the hub.
            crate::natives::nif::refresh_hub_native(self);
            let runtime = self.runtime.clone();
            let pid = self.self_pid;
            let (module, function, arity) = pending.trace_mfa();
            let module = module.to_owned();
            let function = function.to_owned();
            return Some(Box::new(move || {
                let mut heap = shadow_heap();
                if let (Some(runtime), Some(pid)) = (&runtime, pid) {
                    let _ = crate::natives::nif::with_dirty_trace_emission(|| {
                        crate::trace::emit_dirty_running(
                            runtime, pid, "in", &module, &function, arity,
                        );
                    });
                }
                pending.run_dirty(&mut heap);
                if let (Some(runtime), Some(pid)) = (&runtime, pid) {
                    let (module, function, arity) =
                        pending.finalizer_mfa().expect("dirty callback completes");
                    let _ = crate::natives::nif::with_dirty_trace_emission(|| {
                        crate::trace::emit_dirty_running(
                            runtime, pid, "out", module, function, arity,
                        );
                    });
                }
                Box::new(DirtyDone::Nif(pending, heap)) as Box<dyn Any>
            }));
        }
        if let Some((identity, _, class)) = cold.native_dirty_nif
            && class == scheduler_class(kind)
            && cold.static_nif_done.is_none()
            && cold.nif_pending.is_none()
        {
            return crate::native_helpers::static_nif_job(self, identity);
        }
        None
    }

    /// Take back a finished dirty job: what its shadow heap holds moves onto the process heap
    /// when it fits, and stays in heap fragments otherwise.
    ///
    /// Port of erts/emulator/beam/erl_nif.c:551 (full_flush_env) and
    /// erl_nfunc_sched.h (erts_flush_dirty_shadow_proc), OTP-29.1.1.
    pub(crate) fn finish_dirty_job(&mut self, result: Box<dyn Any>) {
        let Ok(done) = result.downcast::<DirtyDone>() else {
            return;
        };
        let (heap, mut slot) = match *done {
            DirtyDone::Nif(pending, heap) => {
                self.cold_mut().nif_pending = Some(pending);
                (heap, None)
            }
            DirtyDone::Static(result, heap) => {
                self.cold_mut().static_nif_done = Some(result);
                (heap, None)
            }
            DirtyDone::Bif(result, heap) => (heap, Some(result)),
        };
        let flushed = {
            let mut roots: Vec<&mut Term> = Vec::new();
            if let Some(Ok(value)) = slot.as_mut() {
                roots.push(value);
            }
            if let Some(cold) = self.cold.as_mut() {
                if let Some(pending) = cold.nif_pending.as_mut() {
                    roots.extend(pending.done_slots());
                }
                roots.extend(dirty_result_slots(None, cold.static_nif_done.as_mut()));
            }
            self.heap.flush_dirty_shadow(heap, &mut roots)
        };
        if flushed.is_err() {
            // A shadow heap never has a stack or an old generation.
            unreachable!("dirty job shadow heap is standalone");
        }
        if let Some(result) = slot {
            self.cold_mut().dirty_bif = Some(DirtyBif::Done(result));
        }
    }

    /// Execute a dirty BIF `body` as a dirty job of `kind`, or take its finished result
    /// when the call is re-executed after the job.
    ///
    /// Port of erts/emulator/beam/bif.c:5760 (erts_call_dirty_bif), OTP-29.1.1.
    pub(crate) fn dirty_bif(
        &mut self,
        kind: DirtyKind,
        mfa: (&'static str, &'static str, u8),
        body: impl FnOnce(&mut ProcessHeap) -> DirtyBifResult + Send + 'static,
    ) -> Result<DirtyBifResult, crate::VmError> {
        if let Some(DirtyBif::Done(result)) =
            self.cold.as_mut().and_then(|cold| cold.dirty_bif.take())
        {
            self.cold_mut().dirty_bif_mfa = None;
            return Ok(result);
        }
        // Port of erts/emulator/beam/bif.c:5760 (erts_schedule_bif sets `c_p->i` to the BIF's
        // export), OTP-29.1.1: while the job is scheduled or runs the process is "in" the BIF.
        self.cold_mut().dirty_bif_mfa = Some(mfa);
        self.cold_mut().dirty_bif = Some(DirtyBif::Job(kind, Box::new(body)));
        Err(crate::VmError::Dirty(kind))
    }

    /// Flag a dirty job observes to see that its process is exiting.
    ///
    /// Port of erts/emulator/beam/erl_process.h (`ERTS_PROC_IS_EXITING` on the real
    /// process of a dirty shadow process), OTP-29.1.1.
    pub(crate) fn dirty_exit_flag(&mut self) -> Arc<AtomicBool> {
        let exited = self.dirty_exiting();
        Arc::clone(
            self.cold_mut()
                .dirty_exit_flag
                .get_or_insert_with(|| Arc::new(AtomicBool::new(exited))),
        )
    }

    /// Record that this process exited while executing a dirty job. Call it before the
    /// exit releases the cold state, so the running job's flag is seen.
    pub(crate) fn set_dirty_exited(&mut self) {
        let cold = self.cold_mut();
        cold.dirty_exited = true;
        if let Some(flag) = cold.dirty_exit_flag.as_ref() {
            flag.store(true, Ordering::Release);
        }
    }
}
