use super::*;
use std::mem::MaybeUninit;

/// Initialize a spawned process in the process block allocated by the scheduler.
// Port of erts/emulator/beam/erl_process.c:erl_create_process, OTP-29.1.1.
pub(crate) fn initialize_spawned(
    slot: &mut MaybeUninit<Process>,
    x_registers: usize,
    mut heap: ProcessHeap,
) -> &mut Process {
    #[cfg(feature = "pf-mem-counters")]
    let started = std::time::Instant::now();
    #[cfg(feature = "pf-mem-counters")]
    let min_heap = heap.min_heap_size_words();

    heap.abi.fcalls = crate::process::CONTEXT_REDS;
    heap.abi.i = std::ptr::null();
    heap.abi.arity = x_registers.min(usize::from(u8::MAX)) as u8;
    heap.abi.current = std::ptr::null();

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
        std::ptr::addr_of_mut!((*process).heap).write(heap);
        std::ptr::addr_of_mut!((*process).x).write(x);
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
        std::ptr::addr_of_mut!((*process).max_heap_peak).write(0);
        std::ptr::addr_of_mut!((*process).native_reds_in).write(4000);
        std::ptr::addr_of_mut!((*process).trap_work).write(0);
        std::ptr::addr_of_mut!((*process).virtual_reds).write(0);
        std::ptr::addr_of_mut!((*process).reductions_used).write(0);
        std::ptr::addr_of_mut!((*process).gc_deferred).write(false);
        std::ptr::addr_of_mut!((*process).delay_gc).write(false);
        std::ptr::addr_of_mut!((*process).uniq_counter).write(0);
        std::ptr::addr_of_mut!((*process).stats).write(stats);
        std::ptr::addr_of_mut!((*process).final_exit_reason).write(None);
        std::ptr::addr_of_mut!((*process).runtime).write(None);
        std::ptr::addr_of_mut!((*process).self_pid).write(None);
        std::ptr::addr_of_mut!((*process).on_managed).write(false);
        std::ptr::addr_of_mut!((*process).native).write(None);
        std::ptr::addr_of_mut!((*process).scheduler_id).write(0);
        std::ptr::addr_of_mut!((*process).run_key).write(0);
        std::ptr::addr_of_mut!((*process).exec_key).write(0);
        std::ptr::addr_of_mut!((*process).scheduler_ref_state).write(None);
        std::ptr::addr_of_mut!((*process).hibernated).write(false);
        std::ptr::addr_of_mut!((*process).signal_probe).write(None);
        std::ptr::addr_of_mut!((*process).native_wait).write(None);
        std::ptr::addr_of_mut!((*process).native_retry).write(None);
        std::ptr::addr_of_mut!((*process).native_apply).write(false);
        std::ptr::addr_of_mut!((*process).native_call_pc).write(0);
        std::ptr::addr_of_mut!((*process).native_wait_timeout).write(None);
        std::ptr::addr_of_mut!((*process).native_wait_self).write(false);
        std::ptr::addr_of_mut!((*process).native_retry_site).write(None);
        std::ptr::addr_of_mut!((*process).native_light_bif_call).write(false);
        std::ptr::addr_of_mut!((*process).native_transfer).write(false);
        std::ptr::addr_of_mut!((*process).native_resume_after_call).write(None);
        std::ptr::addr_of_mut!((*process).inbox).write(inbox);
        std::ptr::addr_of_mut!((*process).sig_cont).write(sig_cont);
        std::ptr::addr_of_mut!((*process).sig_cont_taken).write(0);
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
        std::ptr::addr_of_mut!((*process).trap_exit).write(false);
        std::ptr::addr_of_mut!((*process).exc_class).write(None);
        std::ptr::addr_of_mut!((*process).entry).write(false);
        std::ptr::addr_of_mut!((*process).force_yield).write(false);
        std::ptr::addr_of_mut!((*process).native_continuation_resume).write(false);
        std::ptr::addr_of_mut!((*process).native_arity_set).write(false);
        std::ptr::addr_of_mut!((*process).native_error_pc).write(0);
        std::ptr::addr_of_mut!((*process).native_exit_kind).write(NativeExit::None);

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
    let Process {
        heap,
        x,
        dictionary,
        seq_trace_token,
        seq_token_root,
        seq_trace_clock,
        seq_trace_lastcnt,
        seq_trace_epoch,
        seq_trace_spawn_pending,
        initial_mfa,
        native_pc,
        slow,
        entry_started,
        gc_live,
        max_heap_peak,
        native_reds_in,
        trap_work,
        virtual_reds,
        reductions_used,
        gc_deferred,
        delay_gc,
        uniq_counter,
        stats,
        final_exit_reason,
        runtime,
        self_pid,
        on_managed,
        native,
        scheduler_id,
        run_key,
        exec_key,
        scheduler_ref_state,
        hibernated,
        signal_probe,
        native_wait,
        native_retry,
        native_apply,
        native_call_pc,
        native_wait_timeout,
        native_wait_self,
        native_retry_site,
        native_light_bif_call,
        native_transfer,
        native_resume_after_call,
        inbox,
        sig_cont,
        sig_cont_taken,
        receive_timeout_pos,
        receive_timeout_next,
        receive_infinity,
        links,
        monitors,
        lt_monitors,
        cold,
        group_leader,
        parent,
        exit_cont,
        apply_inline,
        apply_inline_len,
        persistent_terms,
        trap_exit,
        exc_class,
        entry,
        force_yield,
        native_continuation_resume,
        native_arity_set,
        native_error_pc,
        native_exit_kind,
    } = process;
    drop((
        heap,
        x,
        dictionary,
        seq_trace_token,
        seq_token_root,
        seq_trace_clock,
        seq_trace_lastcnt,
        seq_trace_epoch,
        seq_trace_spawn_pending,
        initial_mfa,
        native_pc,
        slow,
        entry_started,
        gc_live,
        max_heap_peak,
        native_reds_in,
        trap_work,
        virtual_reds,
        reductions_used,
        gc_deferred,
        delay_gc,
        uniq_counter,
        stats,
        final_exit_reason,
        runtime,
        self_pid,
        on_managed,
        native,
        scheduler_id,
        run_key,
        exec_key,
        scheduler_ref_state,
        hibernated,
        signal_probe,
        native_wait,
        native_retry,
        native_apply,
        native_call_pc,
        native_wait_timeout,
        native_wait_self,
        native_retry_site,
        native_light_bif_call,
        native_transfer,
        native_resume_after_call,
        inbox,
        sig_cont,
        sig_cont_taken,
        receive_timeout_pos,
        receive_timeout_next,
        receive_infinity,
        links,
        monitors,
        lt_monitors,
        cold,
        group_leader,
        parent,
        exit_cont,
        apply_inline,
        apply_inline_len,
        persistent_terms,
        trap_exit,
        exc_class,
        entry,
        force_yield,
        native_continuation_resume,
        native_arity_set,
        native_error_pc,
        native_exit_kind,
    ));
}
