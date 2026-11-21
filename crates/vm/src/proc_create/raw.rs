use super::*;
use std::ffi::c_void;
use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicPtr, Ordering};

// Port of erts/emulator/beam/erl_process.h:889-908, OTP-29.1.1.
pub(crate) const ERTS_PSD_ERROR_HANDLER: usize = 0;
pub(crate) const ERTS_PSD_SAVED_CALLS_BUF: usize = 1;
pub(crate) const ERTS_PSD_SCHED_ID: usize = 2;
pub(crate) const ERTS_PSD_CALL_TIME_BP: usize = 3;
pub(crate) const ERTS_PSD_DELAYED_GC_TASK_QS: usize = 4;
pub(crate) const ERTS_PSD_NFUNC_TRAP_WRAPPER: usize = 5;
pub(crate) const ERTS_PSD_ETS_OWNED_TABLES: usize = 6;
pub(crate) const ERTS_PSD_ETS_FIXED_TABLES: usize = 7;
pub(crate) const ERTS_PSD_DIST_ENTRY: usize = 8;
pub(crate) const ERTS_PSD_CALL_MEMORY_BP: usize = 9;
pub(crate) const ERTS_PSD_TS_EVENT: usize = 10;
pub(crate) const ERTS_PSD_SYSMON_MSGQ_LEN_LOW: usize = 11;
pub(crate) const ERTS_PSD_PRIO_Q_INFO: usize = 12;
pub(crate) const ERTS_PSD_PENDING_SUSPEND: usize = 13;
pub(crate) const ERTS_PSD_SIZE: usize = 14;
const _: [usize; ERTS_PSD_SIZE] = [
    ERTS_PSD_ERROR_HANDLER,
    ERTS_PSD_SAVED_CALLS_BUF,
    ERTS_PSD_SCHED_ID,
    ERTS_PSD_CALL_TIME_BP,
    ERTS_PSD_DELAYED_GC_TASK_QS,
    ERTS_PSD_NFUNC_TRAP_WRAPPER,
    ERTS_PSD_ETS_OWNED_TABLES,
    ERTS_PSD_ETS_FIXED_TABLES,
    ERTS_PSD_DIST_ENTRY,
    ERTS_PSD_CALL_MEMORY_BP,
    ERTS_PSD_TS_EVENT,
    ERTS_PSD_SYSMON_MSGQ_LEN_LOW,
    ERTS_PSD_PRIO_Q_INFO,
    ERTS_PSD_PENDING_SUSPEND,
];

/// `ErtsPSD { void *data[ERTS_PSD_SIZE] }`.
#[repr(C)]
pub(crate) struct ErtsPSD {
    data: [*mut c_void; ERTS_PSD_SIZE],
}

/// Read one process-specific pointer (`erts_psd_get`).
// Port of erts/emulator/beam/erl_process.h:2307-2325, OTP-29.1.1.
pub(crate) fn erts_psd_get<T>(process_psd: &AtomicPtr<ErtsPSD>, ix: usize) -> Option<&T> {
    assert!(ix < ERTS_PSD_SIZE);
    let psd = process_psd.load(Ordering::Acquire);
    if psd.is_null() {
        return None;
    }
    // SAFETY: the published PSD allocation lives until Process drop; the slot is only changed
    // under its owning process lock, and the shared borrow prevents a local writer.
    unsafe { (*psd).data[ix].cast::<T>().as_ref() }
}

/// Mutably read one process-specific pointer (`erts_psd_get`).
// Port of erts/emulator/beam/erl_process.h:2307-2325, OTP-29.1.1.
pub(crate) fn erts_psd_get_mut<T>(
    process_psd: &mut AtomicPtr<ErtsPSD>,
    ix: usize,
) -> Option<&mut T> {
    assert!(ix < ERTS_PSD_SIZE);
    let psd = process_psd.load(Ordering::Acquire);
    if psd.is_null() {
        return None;
    }
    // SAFETY: the published PSD allocation lives until Process drop; `&mut Process` excludes
    // other Rust access to this process and the returned reference is tied to that borrow.
    unsafe { (*psd).data[ix].cast::<T>().as_mut() }
}

/// Replace an owned PSD value, returning its previous allocation.
// Port of erts/emulator/beam/erl_process.h:2330-2363 and erl_process.c:1552-1571,
// OTP-29.1.1.
pub(crate) fn erts_psd_set<T>(
    process_psd: &mut AtomicPtr<ErtsPSD>,
    ix: usize,
    value: Option<Box<T>>,
) -> Option<Box<T>> {
    let new = value.map_or(std::ptr::null_mut(), |value| Box::into_raw(value).cast());
    let old = erts_psd_set_ptr(process_psd, ix, new);
    if old.is_null() {
        None
    } else {
        // SAFETY: every non-immediate value in these slots was installed as `Box<T>` by this
        // function, and this replacement removes that unique pointer from the PSD.
        Some(unsafe { Box::from_raw(old.cast::<T>()) })
    }
}

/// Replace an `Arc`-owned PSD value while storing the pointer to its allocation directly.
// Port of erts/emulator/beam/erl_process.h (`erts_psd_set`), OTP-29.1.1.
pub(crate) fn erts_psd_set_arc<T>(
    process_psd: &mut AtomicPtr<ErtsPSD>,
    ix: usize,
    value: Option<std::sync::Arc<T>>,
) -> Option<std::sync::Arc<T>> {
    let new = value.map_or(std::ptr::null_mut(), |value| {
        std::sync::Arc::into_raw(value) as *mut c_void
    });
    let old = erts_psd_set_ptr(process_psd, ix, new);
    if old.is_null() {
        None
    } else {
        // SAFETY: `erts_psd_set_arc` is the only writer for this slot and removes the unique
        // strong reference previously transferred to the PSD.
        Some(unsafe { std::sync::Arc::from_raw(old.cast::<T>()) })
    }
}

/// Read an immediate stored in a PSD pointer slot (OTP's tagged-word/pointer convention).
// Port of erts/emulator/beam/erl_process.h (`ERTS_PROC_SCHED_ID`), OTP-29.1.1.
pub(crate) fn erts_psd_get_word(process_psd: &AtomicPtr<ErtsPSD>, ix: usize) -> usize {
    assert!(ix < ERTS_PSD_SIZE);
    let psd = process_psd.load(Ordering::Acquire);
    if psd.is_null() {
        return 0;
    }
    // SAFETY: the PSD allocation is published and remains alive for the process lifetime.
    unsafe { (*psd).data[ix] as usize }
}

/// Store an immediate in a PSD pointer slot and return its previous value.
// Port of erts/emulator/beam/erl_process.h (`ERTS_PROC_SCHED_ID`), OTP-29.1.1.
pub(crate) fn erts_psd_set_word(
    process_psd: &mut AtomicPtr<ErtsPSD>,
    ix: usize,
    value: usize,
) -> usize {
    erts_psd_set_ptr(process_psd, ix, value as *mut c_void) as usize
}

/// Read an immediate term stored directly in a PSD pointer slot.
// Port of erts/emulator/beam/erl_process.h (`erts_proc_get_error_handler`), OTP-29.1.1.
pub(crate) fn erts_psd_get_term(process_psd: &AtomicPtr<ErtsPSD>, ix: usize) -> Option<Term> {
    let word = erts_psd_get_word(process_psd, ix);
    (word != 0).then(|| {
        // SAFETY: the error-handler slot stores only `process_flag(error_handler, Atom)` values;
        // they are immediate atoms and do not contain pointers into the process heap.
        unsafe { Term::from_raw_bits(word as u64) }
    })
}

/// Store an immediate term directly in a PSD pointer slot and return its previous value.
// Port of erts/emulator/beam/erl_process.h (`erts_proc_set_error_handler`), OTP-29.1.1.
pub(crate) fn erts_psd_set_term(
    process_psd: &mut AtomicPtr<ErtsPSD>,
    ix: usize,
    value: Option<Term>,
) -> Option<Term> {
    let old = erts_psd_set_word(
        process_psd,
        ix,
        value.map_or(0, |term| term.word() as usize),
    );
    (old != 0).then(|| {
        // SAFETY: this slot is the error-handler atom, as in `erts_psd_get_term`.
        unsafe { Term::from_raw_bits(old as u64) }
    })
}

fn erts_psd_set_ptr(
    process_psd: &mut AtomicPtr<ErtsPSD>,
    ix: usize,
    data: *mut c_void,
) -> *mut c_void {
    assert!(ix < ERTS_PSD_SIZE);
    let mut psd = process_psd.load(Ordering::Relaxed);
    if psd.is_null() {
        if data.is_null() {
            return std::ptr::null_mut();
        }
        let new_psd = Box::into_raw(Box::new(ErtsPSD {
            data: [std::ptr::null_mut(); ERTS_PSD_SIZE],
        }));
        match process_psd.compare_exchange(
            std::ptr::null_mut(),
            new_psd,
            Ordering::SeqCst,
            Ordering::SeqCst,
        ) {
            Ok(_) => psd = new_psd,
            Err(winner) => {
                // SAFETY: this thread created `new_psd` and the failed compare-exchange
                // confirms no other thread can have observed or taken ownership of it.
                unsafe { drop(Box::from_raw(new_psd)) };
                psd = winner;
            }
        }
    }
    // SAFETY: the PSD pointer is live until process drop. Slot writes are protected by the
    // lock required for this slot in erl_process.h:913-950; process construction has no readers.
    unsafe {
        let old = (*psd).data[ix];
        std::sync::atomic::fence(Ordering::SeqCst);
        (*psd).data[ix] = data;
        old
    }
}

// Port of erts/emulator/beam/erl_process.c (`delete_process` PSD cleanup), OTP-29.1.1.
fn destroy_psd(process_psd: &mut AtomicPtr<ErtsPSD>) {
    let psd = process_psd.swap(std::ptr::null_mut(), Ordering::SeqCst);
    if psd.is_null() {
        return;
    }
    // The PSD pointer slots below hold Box allocations created by their typed setters.
    unsafe fn drop_slot<T>(psd: *mut ErtsPSD, ix: usize) {
        // SAFETY: caller owns the unique PSD pointer and each slot is cleared exactly once.
        let data = unsafe { std::mem::replace(&mut (*psd).data[ix], std::ptr::null_mut()) };
        if !data.is_null() {
            // SAFETY: this slot's setter installed the allocation as `Box<T>`.
            unsafe { drop(Box::from_raw(data.cast::<T>())) };
        }
    }
    unsafe fn drop_arc_slot<T>(psd: *mut ErtsPSD, ix: usize) {
        // SAFETY: caller owns the unique PSD pointer and each slot is cleared exactly once.
        let data = unsafe { std::mem::replace(&mut (*psd).data[ix], std::ptr::null_mut()) };
        if !data.is_null() {
            // SAFETY: this slot's setter transferred one strong `Arc<T>` reference into it.
            unsafe { drop(std::sync::Arc::from_raw(data.cast::<T>())) };
        }
    }

    // SAFETY: this destructor owns the PSD allocation and the following slot types match their
    // only writers: the process-level PSD accessors for the corresponding erts slots.
    unsafe {
        drop_slot::<crate::trace::SavedCalls>(psd, ERTS_PSD_SAVED_CALLS_BUF);
        drop_slot::<Vec<crate::trace_bp::ProcBpTrace>>(psd, ERTS_PSD_CALL_TIME_BP);
        drop_slot::<crate::signals::SysTaskQueues>(psd, ERTS_PSD_DELAYED_GC_TASK_QS);
        drop_slot::<crate::erl_nfunc_sched::NativeFuncBox>(psd, ERTS_PSD_NFUNC_TRAP_WRAPPER);
        drop_arc_slot::<crate::node_tables::DistEntry>(psd, ERTS_PSD_DIST_ENTRY);
        drop_slot::<Vec<crate::trace_bp::ProcBpTrace>>(psd, ERTS_PSD_CALL_MEMORY_BP);
        drop_slot::<crate::receive::PrioQInfo>(psd, ERTS_PSD_PRIO_Q_INFO);
        drop(Box::from_raw(psd));
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        destroy_psd(&mut self.psd);
    }
}

/// Initialize a spawned process in the process block allocated by the scheduler.
// Port of erts/emulator/beam/erl_process.c:erl_create_process, OTP-29.1.1.
pub(crate) fn initialize_spawned(
    slot: &mut MaybeUninit<Process>,
    x_registers: usize,
    heap_words: usize,
    alloc_ix: Option<usize>,
    min_heap: usize,
) -> &mut Process {
    #[cfg(feature = "pf-mem-counters")]
    let started = std::time::Instant::now();

    // Construct every owning or fallible value before the first field write. If any of these
    // operations panics, the allocated slot is still wholly uninitialized.
    let x = ArgRegs::new(x_registers);
    let seq_trace_epoch = crate::seq_trace::current_epoch();
    let stats = ProcessStats::default();
    let inbox = process::MessageQueue::default();
    let sig_cont = arinsal_sched::SignalQueue::default();
    let links = LinkTree::default();
    let monitors = MonitorTree::default();
    let lt_monitors = TargetMonitorList::default();
    let persistent_terms = arinsal_pterm::global_store();
    let apply_inline = [Term::NIL, Term::NIL, Term::NIL];
    let slow = Process::SLOW_NOT_STARTED | Process::SLOW_NO_NATIVE_PC | Process::SLOW_NO_PROBE;

    let process = slot.as_mut_ptr();
    // SAFETY: the scheduler allocated this slot for exactly one Process and has not made it
    // reachable. Every field is written exactly once below, and no operation in this write
    // sequence can panic. Any panic while preparing values above leaves the slot unused.
    unsafe {
        // The heap is built in its place in the block (erl_create_process sets p->heap,
        // p->htop, p->stop ... on the allocated Process), the last value that can fail and
        // the first field written.
        std::ptr::addr_of_mut!((*process).heap).write(ProcessHeap::spawned_at(
            heap_words,
            alloc_ix,
            min_heap,
            crate::process::CONTEXT_REDS,
            x_registers.min(usize::from(u8::MAX)) as u8,
        ));
        std::ptr::addr_of_mut!((*process).x).write(x);
        std::ptr::addr_of_mut!((*process).psd).write(AtomicPtr::new(std::ptr::null_mut()));
        std::ptr::addr_of_mut!((*process).dictionary).write(None);
        std::ptr::addr_of_mut!((*process).seq_trace_token).write(None);
        std::ptr::addr_of_mut!((*process).seq_token_root).write(Term::NIL);
        std::ptr::addr_of_mut!((*process).seq_trace_clock).write(0);
        std::ptr::addr_of_mut!((*process).seq_trace_lastcnt).write(0);
        std::ptr::addr_of_mut!((*process).seq_trace_epoch).write(seq_trace_epoch);
        std::ptr::addr_of_mut!((*process).seq_trace_spawn_pending).write(false);
        std::ptr::addr_of_mut!((*process).initial_mfa).write(None);
        std::ptr::addr_of_mut!((*process).native_pc).write(None);
        std::ptr::addr_of_mut!((*process).slow).write(slow);
        std::ptr::addr_of_mut!((*process).entry_started).write(false);
        std::ptr::addr_of_mut!((*process).gc_live).write(x_registers);
        std::ptr::addr_of_mut!((*process).virtual_reds).write(0);
        std::ptr::addr_of_mut!((*process).reductions_used).write(0);
        std::ptr::addr_of_mut!((*process).gc_deferred).write(false);
        std::ptr::addr_of_mut!((*process).uniq_counter).write(0);
        std::ptr::addr_of_mut!((*process).stats).write(stats);
        std::ptr::addr_of_mut!((*process).final_exit_reason).write(None);
        std::ptr::addr_of_mut!((*process).runtime).write(None);
        std::ptr::addr_of_mut!((*process).native).write(None);
        std::ptr::addr_of_mut!((*process).scheduler_data)
            .write(arinsal_sched::ProcSchedData::default());
        std::ptr::addr_of_mut!((*process).signal_probe).write(None);
        std::ptr::addr_of_mut!((*process).native_retry).write(None);
        std::ptr::addr_of_mut!((*process).native_apply).write(false);
        std::ptr::addr_of_mut!((*process).native_call_pc).write(0);
        std::ptr::addr_of_mut!((*process).native_retry_site).write(None);
        std::ptr::addr_of_mut!((*process).native_light_bif_call).write(false);
        std::ptr::addr_of_mut!((*process).native_transfer).write(false);
        std::ptr::addr_of_mut!((*process).native_resume_after_call).write(None);
        std::ptr::addr_of_mut!((*process).inbox).write(inbox);
        std::ptr::addr_of_mut!((*process).sig_cont).write(sig_cont);
        std::ptr::addr_of_mut!((*process).receive_timeout_pos).write(None);
        std::ptr::addr_of_mut!((*process).receive_timeout_next).write(0);
        std::ptr::addr_of_mut!((*process).receive_infinity).write(false);
        std::ptr::addr_of_mut!((*process).links).write(links);
        std::ptr::addr_of_mut!((*process).monitors).write(monitors);
        std::ptr::addr_of_mut!((*process).lt_monitors).write(lt_monitors);
        std::ptr::addr_of_mut!((*process).cold).write(None);
        std::ptr::addr_of_mut!((*process).group_leader).write(None);
        std::ptr::addr_of_mut!((*process).parent).write(None);
        std::ptr::addr_of_mut!((*process).exit_cont).write(None);
        std::ptr::addr_of_mut!((*process).apply_inline).write(apply_inline);
        std::ptr::addr_of_mut!((*process).apply_inline_len).write(0);
        std::ptr::addr_of_mut!((*process).persistent_terms).write(persistent_terms);
        std::ptr::addr_of_mut!((*process).exc_class).write(None);
        std::ptr::addr_of_mut!((*process).native_continuation_resume).write(false);
        std::ptr::addr_of_mut!((*process).native_arity_set).write(false);
        std::ptr::addr_of_mut!((*process).native_error_pc).write(0);
        // erl_process.c:12604 (erl_create_process: `p->return_trace_frames = 0`).
        std::ptr::addr_of_mut!((*process).return_trace_frames).write(0);

        #[cfg(feature = "pf-mem-counters")]
        if min_heap == 233 {
            PF_SPAWN_CONSTRUCTS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            PF_SPAWN_CONSTRUCT_NS.fetch_add(
                started.elapsed().as_nanos() as u64,
                std::sync::atomic::Ordering::Relaxed,
            );
        }

        &mut *process
    }
}

#[allow(dead_code)]
fn process_fields_are_initialized(process: Process) {
    drop(process);
}

/// The word `REDS_IN` leaves in `def_arg_reg[5]`, typed as the slot's `Term`.
// Port of erts/emulator/beam/jit/x86/process_main.cpp (`def_arg_reg[5] = REDS_IN`), OTP-29.1.1:
// erts stores the raw reduction count in the register slot.
pub(super) fn reds_in_word(reds: i32) -> Term {
    // SAFETY: the slot holds REDS_IN only while the X file is attached or past the saved arity;
    // no reader takes a term from it then (Deref, GC roots and copies see `len` registers),
    // and `detach_save` / `grow_owned` overwrite it before it becomes a register again.
    unsafe { Term::from_raw_bits(u64::from(reds as u32)) }
}

#[cfg(test)]
mod psd_tests {
    use super::*;
    use similar_asserts::assert_eq;

    #[test]
    fn array_is_lazy_and_set_returns_the_previous_slot() {
        let mut process = Process::new();
        assert!(process.psd.load(Ordering::Acquire).is_null());
        assert!(erts_psd_get::<u32>(&process.psd, ERTS_PSD_TS_EVENT).is_none());
        assert_eq!(
            erts_psd_set::<u32>(&mut process.psd, ERTS_PSD_TS_EVENT, None),
            None
        );
        assert!(process.psd.load(Ordering::Acquire).is_null());

        assert!(
            erts_psd_set(&mut process.psd, ERTS_PSD_TS_EVENT, Some(Box::new(17_u32)),).is_none()
        );
        assert_eq!(erts_psd_get(&process.psd, ERTS_PSD_TS_EVENT), Some(&17));
        assert_eq!(
            erts_psd_set(&mut process.psd, ERTS_PSD_TS_EVENT, Some(Box::new(23))),
            Some(Box::new(17)),
        );
        assert_eq!(
            erts_psd_set::<u32>(&mut process.psd, ERTS_PSD_TS_EVENT, None),
            Some(Box::new(23)),
        );
        assert!(erts_psd_get::<u32>(&process.psd, ERTS_PSD_TS_EVENT).is_none());
        assert!(!process.psd.load(Ordering::Acquire).is_null());
    }

    #[test]
    fn immediate_slots_store_and_return_the_previous_word() {
        let mut process = Process::new();
        assert_eq!(erts_psd_get_word(&process.psd, ERTS_PSD_SCHED_ID), 0);
        assert_eq!(erts_psd_set_word(&mut process.psd, ERTS_PSD_SCHED_ID, 3), 0);
        assert_eq!(erts_psd_get_word(&process.psd, ERTS_PSD_SCHED_ID), 3);
        assert_eq!(erts_psd_set_word(&mut process.psd, ERTS_PSD_SCHED_ID, 7), 3);
        assert_eq!(erts_psd_get_word(&process.psd, ERTS_PSD_SCHED_ID), 7);
    }
}
