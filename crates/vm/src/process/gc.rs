use super::*;

/// Scheduling state of a hibernating process; `apply(M, F, A)` waits in X0..X2.
///
/// g_proc_sched. Port of erts/emulator/beam/beam_common.c:1568 (`erts_hibernate`), OTP-29.1.1.
pub(crate) struct HibernateCont {
    /// The BIF has discarded the stack and the executor must leave the slice.
    pub stop: bool,
    /// elixir_loop1: `hibernate/0` resumes at its call site with the stack intact.
    pub resume_in_place: bool,
    /// `Process.current` survives `i_hibernate/0` in erts; retain that MFA across the scheduler
    /// handoff because Arinsal's interpreter position can point at its spawn trampoline.
    pub current_mfa: Option<(String, String, u8)>,
}

/// Collect when a slice starts and the heap wants it.
///
/// The caller has already drained the outer queue, so a message that woke this
/// process is an inbox root. The new heap is sized from that message, the same
/// way `scheduler_gc_proc` sizes from `mbuf` after `erts_proc_sig_handle_incoming`.
// Port of erts/emulator/beam/erl_process.c:10415-10418 and 9558 (`scheduler_gc_proc`),
// OTP-29.1.1.
#[inline]
pub(super) fn collect_on_schedule_in(process: &mut Process) -> Result<(), VmError> {
    // ERTS_IS_GC_DESIRED is tested before anything about the saved registers is computed.
    if !process.heap.gc_after_bif_desired() {
        return Ok(());
    }
    let live = switched_out_live(process);
    process.collect_bin_vheap_if_due(live)
}

// g_proc_sched
pub(super) fn hibernate_resumes_in_place(process: &Process) -> bool {
    process
        .cold
        .as_ref()
        .and_then(|cold| cold.hibernate.as_ref())
        .is_some_and(|cont| cont.resume_in_place)
}

/// `erts_hibernate`'s message check: fetch, and without messages collect and fetch again.
/// Returns whether the message queue is still empty, so the process stops being active.
// Port of erts/emulator/beam/beam_common.c:1584-1596 (erts_hibernate), OTP-29.1.1.
pub(super) fn hibernate_fetch_collect(
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
) -> Result<bool, VmError> {
    process.fetch_signals(ctx)?;
    if !process.inbox.is_empty() {
        return Ok(false);
    }
    hibernate_collect(process)?;
    process.fetch_signals(ctx)?;
    Ok(process.inbox.is_empty())
}

/// `hibernate/3` with no waiting messages: shrink the heap to the `apply(M, F, A)`
/// arguments in X0..X2. Run after the BIF has unwound so no caller keeps stale terms.
// Port of erts/emulator/beam/beam_common.c:1584-1592 (erts_hibernate), OTP-29.1.1.
fn hibernate_collect(process: &mut Process) -> Result<(), VmError> {
    // hibernate/0 reaches erts_hibernate with arity 0: no X register is live and the
    // stack stays a root. hibernate/3 keeps apply(M, F, A) in X0..X2.
    let live = if hibernate_resumes_in_place(process) {
        0
    } else {
        3
    };
    process.gc_live = live;
    process.heap.abi.arity = live as u8;
    if !process.heap.gc_enabled {
        return Ok(());
    }
    process.garbage_collect_hibernate(live).map(|_| ())
}

// Port of erts/emulator/beam/beam_common.c:1568 (erts_hibernate), OTP-29.1.1: the parked
// continuation is process state (`cold.hibernate`), read and cleared by the process itself.
pub(super) fn hibernate_stopped(process: &mut Process) -> bool {
    let Some(cont) = process
        .cold
        .as_mut()
        .and_then(|cold| cold.hibernate.as_mut())
    else {
        return false;
    };
    if !cont.stop {
        return false;
    }
    cont.stop = false;
    true
}

impl Process {
    /// Set this process's `F_DISABLE_GC` equivalent and return its previous state.
    /// Port of erts/emulator/beam/erl_process.c:11823 (`erts_set_gc_state`), OTP-29.1.1.
    pub(crate) fn set_gc_enabled(&mut self, enabled: bool) -> bool {
        let previous = self.heap.gc_enabled;
        self.heap.gc_enabled = enabled;
        previous
    }

    /// Collect after a BIF whose heap fragments outgrew the free young area.
    /// Port of erts/emulator/beam/erl_gc.c:418 (`erts_gc_after_bif_call_lhf`), OTP-29.1.1:
    /// the BIF result is the only live register.
    #[inline]
    pub(crate) fn gc_after_bif(&mut self, result: Term) -> Result<Term, VmError> {
        // ERTS_IS_GC_AFTER_BIF_DESIRED: heap fragments or a virtual binary heap over its size;
        // `F_DISABLE_GC` returns before any collection (erl_gc.c:403-415).
        if !self.heap.gc_after_bif_desired() {
            return Ok(result);
        }
        let mut roots = [result];
        let gc = self.collect_heap_roots(0, &mut roots, 0)?;
        crate::natives::sys::after_collection(self, gc.collections, gc.words_reclaimed);
        self.charge_gc_stats(&gc);
        Ok(roots[0])
    }

    /// Force a collection of the running process before the current BIF returns.
    /// Port of erts/emulator/beam/erl_gc.h:152 (`ERTS_FORCE_GC`), OTP-29.1.1.
    ///
    /// Roots the exact live count recorded at the current call or switch-out point;
    /// registers above it are dead and may hold stale pointers.
    pub(crate) fn force_gc(&mut self) -> Result<(), VmError> {
        self.force_gc_live(self.gc_live)
    }

    /// Force collection with the current BEAM live-register count.
    // Port of erts/emulator/beam/erl_gc.c:1136 (`erts_garbage_collect_literals`), OTP-29.1.1.
    pub(crate) fn force_gc_live(&mut self, live: usize) -> Result<(), VmError> {
        if !self.heap.gc_enabled {
            self.gc_deferred = true;
            return Ok(());
        }
        let live = live.min(self.x.len());
        let gc = self.collect_heap_roots(live, &mut [], 0)?;
        crate::natives::sys::after_collection(self, gc.collections, gc.words_reclaimed);
        Ok(())
    }

    /// Emit a `garbage_collection` trace event with the GC info list and `{wordsize, Size}`.
    /// Port of erts/emulator/beam/erl_trace.c:1439 (`trace_gc`), OTP-29.1.1.
    pub(super) fn trace_gc(&mut self, pid: arinsal_sched::Pid, tag: &str, size: usize) {
        let gc_info = self.heap.gc_info_words();
        let entries = [
            ("wordsize", size),
            ("old_heap_block_size", gc_info.old_heap_block_size),
            ("heap_block_size", gc_info.heap_block_size),
            ("mbuf_size", gc_info.mbuf_size),
            ("recent_size", gc_info.recent_size),
            ("stack_size", gc_info.stack_size),
            ("old_heap_size", gc_info.old_heap_size),
            ("heap_size", gc_info.heap_size),
            ("bin_vheap_size", self.heap.bin_vheap_used() as usize),
            (
                "bin_vheap_block_size",
                self.heap.bin_vheap_block_size() as usize,
            ),
            (
                "bin_old_vheap_size",
                self.heap.bin_old_vheap_used() as usize,
            ),
            (
                "bin_old_vheap_block_size",
                self.heap.bin_old_vheap_block_size() as usize,
            ),
        ];
        let mut tuples = Vec::with_capacity(entries.len());
        let mut scratch = VecHeap::new();
        for (name, value) in entries {
            let Some(value) = Term::small(value as i64) else {
                return;
            };
            let Ok(tuple) =
                TermBuilder::new(&mut scratch).tuple(&[crate::signals::atom(name), value])
            else {
                return;
            };
            tuples.push(tuple);
        }
        let Ok(info) = TermBuilder::new(&mut scratch).list_from_iter(tuples) else {
            return;
        };
        crate::trace::emit_process(None, self, pid, crate::trace::GC, tag, &[info]);
    }

    /// Collect live registers together with only on-heap mailbox message roots.
    // Port of erts/emulator/beam/erl_proc_sig_queue.c:8257 (message queue GC scan), OTP-29.1.1.
    pub(crate) fn collect_heap_roots(
        &mut self,
        live_x: usize,
        extra: &mut [Term],
        min_free: usize,
    ) -> Result<arinsal_term::GcStats, VmError> {
        // Port of erts/emulator/beam/erl_gc.c:934 (garbage_collect clears F_HIBERNATED),
        // OTP-29.1.1.
        self.hibernated = false;
        self.collect_roots(live_x, extra, min_free, false)
    }

    /// Shrink the heap to the live data of `x[..live_x]` and the mailbox.
    // Port of erts/emulator/beam/erl_gc.c:1004 (garbage_collect_hibernate), OTP-29.1.1.
    pub(crate) fn garbage_collect_hibernate(
        &mut self,
        live_x: usize,
    ) -> Result<arinsal_term::GcStats, VmError> {
        let stats = self.collect_roots(live_x, &mut [], 0, true)?;
        self.hibernated = true;
        Ok(stats)
    }

    /// A message copied onto the heap when it was sent is counted by `call_memory` when it is
    /// received, not when it arrives.
    // Port of erts/emulator/beam/erl_message.c:659 (erts_adjust_memory_break(pp, -sz)),
    // OTP-29.1.1.
    /// Allocated words before a message is queued, only when call_memory tracing needs it:
    /// summing the heap fragments for every message made draining a long queue quadratic.
    /// Fetch messages from the outer signal queue without the scheduler context.
    ///
    /// Native `loop_rec` calls this when its inner queue is exhausted, like erts'
    /// `i_loop_rec` calling the receive helper. Messages at the head of the outer queue
    /// move to the inner queue; the first non-message signal (or a message that needs
    /// tracing or priority handling) stops the fetch and is left for the scheduler.
    // Port of erts/emulator/beam/erl_proc_sig_queue.c:7730-7790 (erts_proc_sig_receive_helper)
    // and the message case of erts_proc_sig_handle_incoming, OTP-29.1.1.
    pub(crate) fn fetch_messages_in_place(&mut self) -> Result<usize, VmError> {
        // Only the `erts_proc_sig_fetch` case that splices messages straight onto the message
        // queue runs here: no unhandled signal in the middle queue, no receive tracing, and
        // an outer queue of ordinary messages only.
        if !self.sig_cont_empty() || crate::trace::active() {
            return Ok(0);
        }
        if self.slice().is_some_and(|work| !work.delayed_gc.is_empty()) {
            return Ok(0);
        }
        // Port of erts/emulator/beam/erl_proc_sig_queue.c:1332 (erts_proc_sig_fetch__): the outer
        // queue, messages only, is spliced onto the message queue as a whole.
        let traced_words = self
            .cold
            .as_ref()
            .is_some_and(|cold| !cold.call_memory.is_empty());
        if !traced_words {
            let old_len = self.inbox.len();
            let Some(fetched) = self.probe_fetch_messages_into_inbox() else {
                return Ok(0);
            };
            if fetched != 0 {
                self.sig_cont_taken += fetched as u64;
                self.inbox.spliced_at(old_len);
                crate::natives::erts_debug::after_message_queue_change(self);
            }
            return Ok(fetched);
        }
        let Some(fetched) = self.probe_fetch_messages() else {
            return Ok(0);
        };
        while let Some(node) = self.pop_sig_cont_signal() {
            self.sig_cont_taken += 1;
            debug_assert!(
                matches!(node.payload, Payload::Message(_)),
                "fetch_messages_if takes messages only"
            );
            let old_prio_len = self.cold.as_ref().map_or(0, |cold| cold.prio_len);
            let before = self.message_words_before();
            let new_prio_len = self.inbox.push_message_node(node, old_prio_len);
            self.uncount_message_words(before);
            if new_prio_len != old_prio_len {
                self.cold_mut().prio_len = new_prio_len;
            }
        }
        if fetched != 0 {
            crate::natives::erts_debug::after_message_queue_change(self);
        }
        Ok(fetched)
    }

    /// Fetch the outer signal queue before an on-heap collection: messages a sender
    /// installed on this heap while the process was not running are queued there and must
    /// be roots. Like `erts_proc_sig_fetch`, an outer queue of ordinary messages joins the
    /// message queue when the middle queue is empty; otherwise the whole queue is appended
    /// to the middle queue, whose on-heap messages are roots too.
    // Port of erts/emulator/beam/erl_gc.c:987-990 (`erts_garbage_collect` fetches when
    // `FS_ON_HEAP_MSGQ`) and erl_proc_sig_queue.c:1332 (erts_proc_sig_fetch__), OTP-29.1.1.
    pub(super) fn fetch_outer_queue_for_gc(&mut self) -> Result<(), VmError> {
        if self.message_queue_data() != MessageQueueData::OnHeap {
            return Ok(());
        }
        if self.fetch_messages_in_place()? != 0 {
            return Ok(());
        }
        self.probe_fetch_all();
        Ok(())
    }

    pub(super) fn sig_cont_message_mut(payload: &mut Payload<Message>) -> Option<&mut Message> {
        match payload {
            Payload::Message(message) => Some(message),
            _ => None,
        }
    }

    pub(super) fn message_words_before(&self) -> Option<i64> {
        self.cold
            .as_ref()
            .is_some_and(|cold| !cold.call_memory.is_empty())
            .then(|| self.allocated_words(0))
    }

    pub(super) fn uncount_message_words(&mut self, allocated_before: Option<i64>) {
        if let Some(allocated_before) = allocated_before
            && self
                .cold
                .as_ref()
                .is_some_and(|cold| !cold.call_memory.is_empty())
        {
            let delta = self.allocated_words(0) - allocated_before;
            if delta > 0 {
                crate::trace_bp::adjust_memory_break(self, -delta);
            }
        }
    }

    /// Collect after a BIF left heap fragments larger than the free area or pushed the
    /// virtual binary heap over its limit. Exactly `x[..live_x]` are roots; a BIF result
    /// in X0 needs `live_x >= 1`.
    // Port of erts/emulator/beam/erl_gc.h:132-139 (ERTS_IS_GC_DESIRED), OTP-29.1.1: the test
    // is three compares inline, the collection itself is out of line.
    #[inline(always)]
    pub(crate) fn collect_bin_vheap_if_due(&mut self, live_x: usize) -> Result<(), VmError> {
        if self.heap.gc_after_bif_desired() {
            return self.collect_bin_vheap_now(live_x);
        }
        Ok(())
    }

    #[inline(never)]
    fn collect_bin_vheap_now(&mut self, live_x: usize) -> Result<(), VmError> {
        let live_x = live_x.min(self.x.len());
        let stats = self.collect_heap_roots(live_x, &mut [], 0)?;
        crate::natives::sys::after_collection(self, stats.collections, stats.words_reclaimed);
        self.charge_gc_stats(&stats);
        Ok(())
    }
}
