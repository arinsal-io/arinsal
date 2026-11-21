use super::*;

/// Port of erts/emulator/beam/erl_proc_sig_queue.c:52 (ERTS_SIG_REDS_CNT_FACTOR), OTP-29.1.1.
pub(super) const SIG_REDS_CNT_FACTOR: i32 = 4;

/// Port of erts/emulator/beam/erl_proc_sig_queue.h:284 (ERTS_SIG_HANDLE_REDS_MAX_PREFERED),
/// OTP-29.1.1.
pub(crate) const SIG_HANDLE_REDS_MAX_PREFERED: i32 = CONTEXT_REDS / 40;

/// `ERTS_PROC_SIG_FLUSH_FLG_FROM_ALL`.
// Port of erts/emulator/beam/erl_proc_sig_queue.h:1345, OTP-29.1.1.
pub(crate) const ERTS_PROC_SIG_FLUSH_FLG_FROM_ALL: i32 = 1 << 1;
/// `ERTS_PROC_SIG_FLUSH_FLG_FROM_ID`.
// Port of erts/emulator/beam/erl_proc_sig_queue.h:1350, OTP-29.1.1.
pub(crate) const ERTS_PROC_SIG_FLUSH_FLG_FROM_ID: i32 = 1 << 2;

/// Result of `pi_maybe_flush_signals`.
// Port of erts/emulator/beam/erl_bif_info.c:1198-1271, OTP-29.1.1.
pub(crate) enum FlushSignals {
    /// All relevant signals handled (or none needed flushing).
    Done,
    /// Out of reductions: yield and retry the BIF.
    Yield,
    /// An exit signal made the process exiting.
    Exiting,
}

impl Process {
    /// Handle the signals left in the middle queue without fetching.
    pub(crate) fn handle_local_signals(
        &mut self,
        ctx: &mut RunCtx<'_, crate::Process>,
    ) -> Result<(), VmError> {
        loop {
            let mut reds = CONTEXT_REDS;
            let done = self.handle_incoming(ctx, &mut reds, CONTEXT_REDS, true)?;
            Self::erts_bif_chk_exited(self, ctx)?;
            if done {
                return Ok(());
            }
        }
    }

    /// Insert a flush signal and set `FS_FLUSHING_SIGS`.
    // Port of erts/emulator/beam/erl_proc_sig_queue.c:3520-3560
    // (`erts_proc_sig_init_flush_signals`), OTP-29.1.1.
    pub(crate) fn erts_proc_sig_init_flush_signals(
        &mut self,
        ctx: &mut RunCtx<'_, crate::Process>,
        flags: i32,
        from: Term,
    ) {
        debug_assert!(
            self.inbox.flags & (crate::receive::FS_FLUSHING_SIGS | crate::receive::FS_FLUSHED_SIGS)
                == 0
        );
        let (from_pid, force_flush, slot) = match flags {
            ERTS_PROC_SIG_FLUSH_FLG_FROM_ALL => (ctx.pid(), true, None),
            ERTS_PROC_SIG_FLUSH_FLG_FROM_ID => {
                if let Some(pid) = Pid::from_term(from) {
                    (pid, false, None)
                } else {
                    // Port identifier: hash the port term for the sender buffer slot.
                    (
                        ctx.pid(),
                        false,
                        Some(arinsal_term::internal_hash(from) as usize),
                    )
                }
            }
            _ => {
                self.set_gc_enabled(false);
                let _ = self.fetch_signals(ctx);
                self.inbox.flags |= crate::receive::FS_FLUSHING_SIGS;
                return;
            }
        };
        ctx.queue_self_flush(from_pid, force_flush, slot)
            .expect("Failed to send flush signal to ourselves");
        self.set_gc_enabled(false);
        let _ = self.fetch_signals(ctx);
        self.inbox.flags |= crate::receive::FS_FLUSHING_SIGS;
    }

    /// Flush signals the caller may have sent to itself before gathering `process_info`.
    // Port of erts/emulator/beam/erl_bif_info.c:1198-1271 (`pi_maybe_flush_signals`),
    // OTP-29.1.1.
    pub(crate) fn pi_maybe_flush_signals(
        &mut self,
        ctx: &mut RunCtx<'_, crate::Process>,
    ) -> Result<FlushSignals, VmError> {
        use crate::receive::{FS_FLUSHED_SIGS, FS_FLUSHING_SIGS};
        if self.inbox.flags & FS_FLUSHED_SIGS != 0 {
            debug_assert!(self.inbox.flags & FS_FLUSHING_SIGS != 0);
            self.inbox.flags &= !(FS_FLUSHED_SIGS | FS_FLUSHING_SIGS);
            self.set_gc_enabled(true);
            return Ok(FlushSignals::Done);
        }
        if self.inbox.flags & FS_FLUSHING_SIGS == 0 {
            if !ctx.maybe_self_sigs() {
                if ctx.proc_state().load(Ordering::Acquire) & arinsal_sched::psflg::MSG_SIG_IN_Q
                    != 0
                {
                    self.fetch_signals(ctx)?;
                }
                return Ok(FlushSignals::Done);
            }
            self.erts_proc_sig_init_flush_signals(
                ctx,
                ERTS_PROC_SIG_FLUSH_FLG_FROM_ID,
                ctx.pid().to_term().unwrap_or(Term::NIL),
            );
            if self.inbox.flags & FS_FLUSHED_SIGS != 0 {
                self.inbox.flags &= !(FS_FLUSHED_SIGS | FS_FLUSHING_SIGS);
                self.set_gc_enabled(true);
                return Ok(FlushSignals::Done);
            }
        }
        debug_assert!(self.inbox.flags & FS_FLUSHING_SIGS != 0);
        let mut reds_left = self.heap.abi.fcalls;
        while reds_left > 0 {
            let mut sreds = reds_left;
            let max = sreds;
            let _ = self.handle_incoming(ctx, &mut sreds, max, true)?;
            super::executor::bump_fcalls(self, sreds);
            if Self::erts_proc_is_exiting(ctx) {
                return Ok(FlushSignals::Exiting);
            }
            if self.inbox.flags & FS_FLUSHED_SIGS != 0 {
                self.inbox.flags &= !(FS_FLUSHED_SIGS | FS_FLUSHING_SIGS);
                self.set_gc_enabled(true);
                return Ok(FlushSignals::Done);
            }
            reds_left -= sreds;
        }
        Ok(FlushSignals::Yield)
    }

    /// `bif_handle_signals_return/2`: flush signals from `from` then return `value`.
    // Port of erts/emulator/beam/bif.c:5452-5498 (`bif_handle_signals_return`), OTP-29.1.1.
    pub(crate) fn bif_handle_signals_return(
        &mut self,
        ctx: &mut RunCtx<'_, crate::Process>,
        from: Term,
        value: Term,
    ) -> Result<Term, VmError> {
        use crate::receive::{FS_FLUSHED_SIGS, FS_FLUSHING_SIGS};
        if self.inbox.flags & FS_FLUSHED_SIGS != 0 {
            debug_assert!(self.inbox.flags & FS_FLUSHING_SIGS != 0);
            self.inbox.flags &= !(FS_FLUSHED_SIGS | FS_FLUSHING_SIGS);
            self.set_gc_enabled(true);
            return Ok(value);
        }
        if self.inbox.flags & FS_FLUSHING_SIGS == 0 {
            let flags = if from.is_pid() || from.is_port() {
                ERTS_PROC_SIG_FLUSH_FLG_FROM_ID
            } else {
                ERTS_PROC_SIG_FLUSH_FLG_FROM_ALL
            };
            self.erts_proc_sig_init_flush_signals(ctx, flags, from);
            if self.inbox.flags & FS_FLUSHED_SIGS != 0 {
                self.inbox.flags &= !(FS_FLUSHED_SIGS | FS_FLUSHING_SIGS);
                self.set_gc_enabled(true);
                return Ok(value);
            }
        }
        debug_assert!(self.inbox.flags & FS_FLUSHING_SIGS != 0);
        let mut reds_left = self.heap.abi.fcalls;
        while reds_left > 0 {
            let mut sreds = reds_left;
            let max = sreds;
            let _ = self.handle_incoming(ctx, &mut sreds, max, true)?;
            super::executor::bump_fcalls(self, sreds);
            Self::erts_bif_chk_exited(self, ctx)?;
            if self.inbox.flags & FS_FLUSHED_SIGS != 0 {
                self.inbox.flags &= !(FS_FLUSHED_SIGS | FS_FLUSHING_SIGS);
                self.set_gc_enabled(true);
                return Ok(value);
            }
            reds_left -= sreds;
        }
        crate::bif_traps::vbump_all_reds(self);
        Err(VmError::TrapExport(crate::ExportTrap::new(
            self,
            crate::natives::sys::BIF_HANDLE_SIGNALS_RETURN,
            vec![from, value],
        )))
    }

    /// `ERTS_BIF_CHK_EXITED(c_p)` of a BIF that handled its own signals: a process an exit
    /// signal made exiting fails with its catches killed and `freason = EXTAG_EXIT |
    /// EXF_PANIC`, `fvalue` the reason erts_set_self_exiting stored.
    // Port of erts/emulator/beam/bif.h (ERTS_BIF_CHK_EXITED, ERTS_BIF_EXITED), OTP-29.1.1.
    pub(crate) fn erts_bif_chk_exited(
        process: &mut Process,
        ctx: &RunCtx<'_, crate::Process>,
    ) -> Result<(), VmError> {
        if !Self::erts_proc_is_exiting(ctx) {
            return Ok(());
        }
        process.heap.abi.catches = 0;
        let reason = crate::native_hooks::from_raw(process.heap.abi.exc.fvalue);
        Err(VmError::Trap(crate::exceptions::Trap::untrappable_exit(
            reason,
        )))
    }

    /// Receive-trace a signal that was converted into a message.
    // Port of erts/emulator/beam/erl_proc_sig_queue.c:3804-3890 (convert_to_msg with
    // receive tracing) and 8627 (trace_receive), OTP-29.1.1.
    pub(super) fn trace_converted_signal(
        &mut self,
        ctx: &mut RunCtx<'_, crate::Process>,
        message: Term,
        from: Pid,
    ) {
        if crate::trace::active()
            && crate::trace::flags(self, ctx.pid()) & crate::trace::RECEIVE != 0
        {
            crate::trace::receive_event(None, self, ctx, message, Some(from));
        }
    }

    /// Receive-trace the message, if any, that a conversion appended after `queued` entries.
    fn trace_new_message(
        &mut self,
        ctx: &mut RunCtx<'_, crate::Process>,
        queued: usize,
        from: Pid,
    ) {
        if self.inbox.len() > queued
            && let Some(message) = self.inbox.back().copied()
        {
            self.trace_converted_signal(ctx, message, from);
        }
    }

    /// `erts_proc_notify_new_message(c_p, ERTS_PROC_LOCK_MAIN)` on the running process after a
    /// signal became a message: ERTS_PSFLG_ACTIVE is set (erts_schedule_process of a running
    /// process enqueues nothing), so a process scheduled for its signals alone
    /// (ERTS_PSFLG_RUNNING_SYS) goes on to run the receive that takes the message.
    // Port of erts/emulator/beam/erl_proc_sig_queue.h:2080 (erts_proc_notify_new_message),
    // OTP-29.1.1.
    fn erts_proc_notify_new_message(ctx: &RunCtx<'_, crate::Process>) {
        let state = ctx.proc_state();
        if state.load(Ordering::Relaxed) & arinsal_sched::psflg::ACTIVE == 0 {
            state.fetch_or(arinsal_sched::psflg::ACTIVE, Ordering::AcqRel);
        }
    }

    /// The notify at the end of convert_to_down_message (erl_proc_sig_queue.c:5058), when the
    /// monitor signal was converted (a message appended after `queued` entries).
    fn notify_converted(&self, ctx: &RunCtx<'_, crate::Process>, queued: usize) {
        if self.inbox.len() > queued {
            Self::erts_proc_notify_new_message(ctx);
        }
    }

    /// Move the outer signal queue into this process. Without unhandled signals in the
    /// middle queue, and when the batch holds only ordinary messages and receive tracing is
    /// off, the messages go straight to the message queue; otherwise the batch is appended to
    /// the middle queue (`sig_cont`) for [`Self::handle_incoming`].
    // Port of erts/emulator/beam/erl_proc_sig_queue.c:1332 (erts_proc_sig_fetch__), OTP-29.1.1.
    pub(crate) fn fetch_signals(
        &mut self,
        ctx: &mut RunCtx<'_, crate::Process>,
    ) -> Result<(), VmError> {
        let cont = !self.sig_cont_empty();
        let start = self.sig_cont().len();
        let recv_traced = crate::trace::active()
            && crate::trace::flags(self, ctx.pid()) & crate::trace::RECEIVE != 0;
        // The fetch sets `ERTS_PSFLG_SIG_Q` itself when it leaves signals to handle.
        ctx.fetch_signals(&mut self.sig_cont_mut(), recv_traced);
        self.fetched(ctx, cont, start, recv_traced)
    }

    /// The receive helper's fetch into an empty middle queue: `true` when nothing was queued,
    /// with the msgq lock kept for the wait (erts_proc_sig_receive_helper returns "with message
    /// queue locked"); otherwise as [`Self::fetch_signals`].
    // Port of erts/emulator/beam/erl_proc_sig_queue.c:7767-7795 (erts_proc_sig_receive_helper),
    // OTP-29.1.1.
    pub(crate) fn fetch_signals_receive(
        &mut self,
        ctx: &mut RunCtx<'_, crate::Process>,
    ) -> Result<bool, VmError> {
        let recv_traced = crate::trace::active()
            && crate::trace::flags(self, ctx.pid()) & crate::trace::RECEIVE != 0;
        if ctx.fetch_signals_receive(&mut self.sig_cont_mut(), recv_traced) {
            return Ok(true);
        }
        self.fetched(ctx, false, 0, recv_traced)?;
        Ok(false)
    }

    /// The fetched batch in the middle queue past `start`: without unhandled signals before
    /// it (`cont`), receive tracing or non-message signals it joins the message queue.
    // Port of erts/emulator/beam/erl_proc_sig_queue.c:1332 (erts_proc_sig_fetch__), OTP-29.1.1.
    fn fetched(
        &mut self,
        ctx: &mut RunCtx<'_, crate::Process>,
        cont: bool,
        start: usize,
        recv_traced: bool,
    ) -> Result<(), VmError> {
        if cont
            || self.sig_cont().len() == start
            || recv_traced
            // erts_proc_sig_fetch__ tests `nmsigs.next`: a fetched queue without non-message
            // signals goes straight onto the message queue.
            || self.sig_cont().non_messages() != 0
        {
            return Ok(());
        }
        // The whole batch is one splice onto the message queue in erts (LINK_MESSAGE of the
        // fetched list); a plain message needs no alias, priority or receive-trace handling.
        let count = self.sig_cont().len();
        ctx.consume_fetched_many(count);
        while let Some(node) = self.pop_sig_cont_signal() {
            match &node.payload {
                Payload::Message(message) if message.alias == 0 && !message.is_priority() => {
                    let before = self.message_words_before();
                    self.inbox.push_message_node(node);
                    self.uncount_message_words(before);
                }
                _ => {
                    self.move_message(ctx, node)?;
                }
            }
        }
        crate::natives::erts_debug::after_message_queue_change(self);
        Ok(())
    }

    /// An ordinary message signal: it joins the message queue without being handled. A
    /// priority message or a message sent through an alias is an `ERTS_SIG_Q_OP_ALTACT_MSG`
    /// non-message signal in erts.
    fn is_ordinary_message(payload: &Payload<Message>) -> bool {
        match payload {
            Payload::Message(message) => !message.is_altact_msg(),
            Payload::Timer { .. } => true,
            Payload::Signal(_) => false,
        }
    }

    /// Handle the signals of the middle queue (`sig_cont`) for at most `*reds` reductions
    /// (and `max_reds` when the limit is stretched), after fetching the outer queue unless
    /// `local_only`. Messages before the next unhandled signal move to the message queue; the
    /// rest stays in the middle queue. `*reds` returns the reductions used. Returns whether
    /// every signal was handled. An exit signal that terminates the process makes it exiting
    /// (erts_set_self_exiting) and stops the handling; callers read ERTS_PROC_IS_EXITING.
    // Port of erts/emulator/beam/erl_proc_sig_queue.c:6229-7178
    // (erts_proc_sig_handle_incoming), OTP-29.1.1.
    pub(crate) fn handle_incoming(
        &mut self,
        ctx: &mut RunCtx<'_, crate::Process>,
        reds: &mut i32,
        max_reds: i32,
        local_only: bool,
    ) -> Result<bool, VmError> {
        if !local_only && self.inbox.flags & crate::receive::FS_FLUSHING_SIGS == 0 {
            let state = ctx.proc_state().load(Ordering::Acquire);
            if state & arinsal_sched::psflg::SIG_IN_Q != 0 {
                self.fetch_signals(ctx)?;
            }
        }
        let limit_in = *reds;
        *reds = 0;
        if self.sig_cont_empty() {
            ctx.set_sig_q(false);
            return Ok(true);
        }
        let mut limit = limit_in.saturating_mul(SIG_REDS_CNT_FACTOR);
        let abs_lim = SIG_REDS_CNT_FACTOR.saturating_mul(max_reds);
        if limit > abs_lim {
            limit = abs_lim;
        }
        // The end of the message queue before this call: erts moves the handled part of the
        // middle queue there only when it stops, so `stretch_limit` looks at what precedes.
        let msgq_end = self.inbox.entries.last_field();
        let mut cnt = 0_i32;
        let mut yield_ = false;
        let mut handled = false;
        let result = loop {
            // Messages up to the next non-message signal or receive marker (a lazy node, which
            // has no value to look at).
            while let Some(event) = self.sig_cont().front()
                && Self::is_ordinary_message(&event.payload)
            {
                let node = self.pop_sig_cont_signal().expect("front checked");
                ctx.consume_fetched();
                self.move_message(ctx, node)?;
            }
            if self.sig_cont().is_empty() {
                break Ok(true);
            }
            if handled && !(cnt <= limit || self.stretch_limit(abs_lim, &mut limit, msgq_end)) {
                break Ok(false);
            }
            handled = true;
            let Some(mut node) = self.pop_sig_cont_signal() else {
                break Ok(true);
            };
            if arinsal_sched::RecvMarker::is_marker(&node) {
                // ERTS_SIG_Q_OP_RECV_MARK: inserted by this process, not fetched.
                self.recv_marker_enter_msgq(node);
                cnt += 1;
                continue;
            }
            if let Payload::Signal(Signal::LiteralAreaCopy(request)) = &mut node.payload {
                // `handle_cla` gets the adjustment limit chosen by erts: signals followed by
                // more queue entries receive the minimum adjustment budget; a last signal gets
                // the remaining budget, with that same minimum.
                let min_adj_limit =
                    SIG_REDS_CNT_FACTOR.saturating_mul(crate::process::CONTEXT_REDS) / 6;
                let adj_limit = if self.sig_cont_empty() {
                    limit.saturating_sub(cnt).max(min_adj_limit)
                } else {
                    min_adj_limit
                };
                match crate::natives::sys::handle_cla(self, request, adj_limit) {
                    Ok(crate::natives::sys::HandleClaResult::Yield { cnt: cla_cnt }) => {
                        self.sig_cont_mut().push_front_node(node);
                        cnt = cnt.saturating_add(cla_cnt);
                        break Ok(false);
                    }
                    Ok(crate::natives::sys::HandleClaResult::Complete {
                        result,
                        cnt: cla_cnt,
                    }) => {
                        ctx.consume_fetched();
                        let Event { payload, .. } = node.into_value();
                        let Payload::Signal(Signal::LiteralAreaCopy(copy)) = payload else {
                            unreachable!("the literal-copy signal is preserved while handled");
                        };
                        crate::natives::sys::reply_literal_area_copy(
                            ctx,
                            copy.request,
                            copy.requester,
                            result,
                        )?;
                        cnt = cnt.saturating_add(
                            cla_cnt.min(SIG_REDS_CNT_FACTOR * crate::process::CONTEXT_REDS),
                        );
                        continue;
                    }
                    Err(error) => break Err(error),
                }
            }
            ctx.consume_fetched();
            if matches!(node.payload, Payload::Signal(Signal::Flush)) {
                // Port of erl_proc_sig_queue.c:6853-6865 (`ERTS_SIG_Q_OP_FLUSH`): set
                // `FS_FLUSHED_SIGS` and `goto stop`. No `cnt++`.
                debug_assert!(self.inbox.flags & crate::receive::FS_FLUSHING_SIGS != 0);
                self.inbox.flags |= crate::receive::FS_FLUSHED_SIGS;
                break Ok(self.sig_cont_empty());
            }
            if !node.is_lazy() && !matches!(node.payload, Payload::Signal(_)) {
                // ERTS_SIG_Q_OP_ALTACT_MSG: a priority message enters the priority queue.
                match self.move_message(ctx, node) {
                    Ok(delivered) => {
                        if delivered {
                            // erl_proc_sig_queue.c:6219 (handle_altact_msg).
                            Self::erts_proc_notify_new_message(ctx);
                        }
                        cnt += 1;
                        continue;
                    }
                    Err(error) => break Err(error),
                }
            }
            if node.lazy_meta().is_some_and(|meta| {
                meta & arinsal_sched::LAZY_LINK != 0 && meta & crate::monitor_link::LAZY_UNLINK == 0
            }) {
                // Port of erts_proc_sig_queue.c (ERTS_SIG_Q_OP_LINK): the receiver inserts
                // the same ErtsLink allocation that arrived as the signal node.
                let link = crate::monitor_link::Link::from_signal_header(node.into_raw().cast());
                let link_from = link.view().other();
                let from = Pid::from_data(link_from);
                if let Err(duplicate) = self.links.lookup_insert(link) {
                    drop(duplicate);
                } else {
                    self.trace_getting_linked(ctx, from);
                }
                cnt += 1;
                continue;
            }
            if node
                .lazy_meta()
                .is_some_and(|meta| meta & crate::monitor_link::LAZY_UNLINK != 0)
            {
                let (unlink_op, from, id, ack) = crate::monitor_link::UnlinkOp::take_signal(node)
                    .expect("lazy unlink node has an unlink operation");
                let cost = if ack {
                    drop(unlink_op);
                    self.handle_unlink_ack_signal(from, id)
                } else {
                    self.handle_unlink_signal(ctx, from, id, Some(unlink_op))?
                };
                cnt += cost + 1;
                continue;
            }
            if node.lazy_meta().is_some() {
                // Port of erts_proc_sig_handle_incoming: an intrusive monitor node carries its
                // operation in the half's target flag and is consumed without materialising an
                // Event value.
                // Port of erl_proc_sig_queue.c (erts_proc_sig_handle_incoming), OTP-29.1.1: a
                // monitor costs 2; a demonitor 1, plus 1 when it released the target half.
                if let Some(half) = crate::proc_create::ProcessMonitorData::take_signal_half(node) {
                    if half.view().is_target() {
                        self.insert_target_process_monitor_half(half);
                        cnt += 2;
                    } else {
                        cnt += 1 + i32::from(self.remove_demonitored_target_half(half));
                    }
                    continue;
                }
                unreachable!("non-link lazy signal is a monitor half");
            }
            let Event { from, payload } = &*node;
            if let Payload::Signal(Signal::Demonitor(reference)) = payload {
                self.remove_target_monitor(*reference);
                cnt += 2;
                continue;
            }
            if let Payload::Signal(Signal::DistDemonitor(reference)) = payload {
                cnt += 1 + 2 * i32::from(crate::dist::handle_dist_demonitor(self, *reference));
                continue;
            }
            if let Payload::Signal(Signal::Unlink(id)) = payload {
                let cost = self.handle_unlink_signal(ctx, *from, *id, None)?;
                cnt += cost + 1;
                continue;
            }
            if let Payload::Signal(Signal::Link) = payload {
                if let Err(duplicate) = self
                    .links
                    .lookup_insert(crate::proc_create::process_link(*from, false))
                {
                    drop(duplicate);
                } else {
                    self.trace_getting_linked(ctx, *from);
                }
                cnt += 1;
                continue;
            }
            let Event { from, payload } = node.into_value();
            if let Payload::Signal(Signal::Rpc(rpc)) = payload {
                // ERTS_SIG_Q_OP_RPC: `cnt += handle_rpc(c_p, sig, cnt, limit, &yield)`.
                match self.handle_rpc(ctx, from, *rpc, cnt, limit, &mut yield_) {
                    Ok(cost) => cnt += cost + 1,
                    Err(error) => break Err(error),
                }
                continue;
            }
            let mut exited = false;
            match self.handle_signal(ctx, from, payload, &mut exited) {
                Ok(cost) => cnt += cost + 1,
                Err(error) => break Err(error),
            }
            if exited {
                // erl_proc_sig_queue.c:6349 (`if (exited) goto stop`): terminated by signal.
                break Ok(self.sig_cont_empty());
            }
        };
        // Port of erl_proc_sig_queue.c:7146-7150: the save pointer does not stay at a marker.
        self.pass_markers_at_save();
        // Port of erl_proc_sig_queue.c:7160 (`*redsp = cnt/ERTS_SIG_REDS_CNT_FACTOR + 1`).
        *reds = cnt / SIG_REDS_CNT_FACTOR + 1;
        if yield_ {
            // The virtual reductions (`esdp->virtual_reds`) are not counted.
            *reds = max_reds;
        }
        ctx.set_sig_q(!self.sig_cont_empty());
        // Port of erl_proc_sig_queue.c:7114-7122: no outstanding signals from ourselves.
        let state = ctx.proc_state().load(Ordering::Acquire);
        if state & (arinsal_sched::psflg::SIG_Q | arinsal_sched::psflg::SIG_IN_Q) == 0 {
            ctx.clear_maybe_self_sigs();
        }
        // Port of erl_proc_sig_queue.c:7151-7153: a hibernated process with messages is
        // made active.
        if !self.inbox.is_empty() && self.hibernated() {
            Self::erts_proc_notify_new_message(ctx);
        }
        let done = result?;
        crate::natives::erts_debug::after_message_queue_change(self);
        Ok(done)
    }

    /// Handle one non-message signal; returns its reduction count (`cnt`) in units of
    /// 1/`ERTS_SIG_REDS_CNT_FACTOR` reduction, without the `cnt++` every signal costs.
    /// `*exited` is set when an exit signal made the process exiting (handle_exit_signal's
    /// `*exited`).
    // Port of the signal cases of erts/emulator/beam/erl_proc_sig_queue.c:6336-6968
    // (erts_proc_sig_handle_incoming), OTP-29.1.1.
    fn handle_signal(
        &mut self,
        ctx: &mut RunCtx<'_, crate::Process>,
        from: Pid,
        payload: Payload<Message>,
        exited: &mut bool,
    ) -> Result<i32, VmError> {
        let Payload::Signal(signal) = payload else {
            unreachable!("message signals are moved to the message queue before this");
        };
        let cost = match signal {
            arinsal_sched::Signal::TraceChangeState(shared) => {
                // Port of erts/emulator/beam/erl_proc_sig_queue.c:8524-8565
                // (handle_trace_change_state), OTP-29.1.1.
                let change = shared
                    .0
                    .downcast_ref::<crate::trace::LinkedTraceChange>()
                    .expect("trace-change signal carries its trace state");
                crate::trace::apply_linked_trace_change(self, ctx.pid(), change);
                0
            }
            arinsal_sched::Signal::Link => {
                // Port of erts/emulator/beam/erl_proc_sig_queue.c:6636-6646 (ERTS_SIG_Q_OP_LINK):
                // the receiver reports getting_linked in signal order, for a new link only.
                if let Err(duplicate) = self
                    .links
                    .lookup_insert(crate::proc_create::process_link(from, false))
                {
                    drop(duplicate);
                } else {
                    self.trace_getting_linked(ctx, from);
                }
                0
            }
            // Port of erts/emulator/beam/erl_proc_sig_queue.c:6636-6646 (ERTS_SIG_Q_OP_LINK) for a
            // link whose origin is a port.
            arinsal_sched::Signal::PortLink(id) => {
                let _ = self.links.lookup_insert(crate::proc_create::port_link(id));
                0
            }
            // Port of erl_proc_sig_queue.c:6693-6713 (ERTS_SIG_Q_OP_UNLINK) for a port origin.
            arinsal_sched::Signal::PortUnlink(id) => {
                self.links.remove(crate::proc_create::port_link_key(id));
                0
            }
            arinsal_sched::Signal::PortUnlinkAck { port, unlink_id } => {
                let key = crate::proc_create::port_link_key(port);
                if self
                    .links
                    .get(key)
                    .is_some_and(|link| link.unlinking() == unlink_id)
                {
                    self.links.remove(key);
                }
                0
            }
            // Port of erl_bif_info.c:4998-5022 (proc_sig_block), OTP-29.1.1.
            arinsal_sched::Signal::ProcSigBlock(milliseconds) => {
                if milliseconds > 0 {
                    std::thread::sleep(std::time::Duration::from_millis(milliseconds as u64));
                }
                0
            }
            arinsal_sched::Signal::Unlink(id) => self.handle_unlink_signal(ctx, from, id, None)?,
            arinsal_sched::Signal::Suspend { shared } => {
                crate::suspend::activate(self, ctx.pid(), from, shared);
                2
            }
            arinsal_sched::Signal::SuspendRelease { shared } => {
                crate::suspend::release(self, ctx.pid(), from, shared);
                2
            }
            arinsal_sched::Signal::SuspendDown { shared } => {
                crate::suspend::suspendee_down(self, from, shared);
                2
            }
            arinsal_sched::Signal::SuspendResume => {
                crate::suspend::resume_self(self);
                2
            }
            arinsal_sched::Signal::SuspendInternal => {
                crate::suspend::suspend_self(self);
                2
            }
            arinsal_sched::Signal::SyncSuspend(sync) => {
                let arinsal_sched::SyncSuspendRequest {
                    requester,
                    tag,
                    reply,
                    async_,
                } = *sync;
                crate::suspend::sync_reply(self, ctx, requester, tag, reply, async_, false)?;
                2
            }
            arinsal_sched::Signal::Monitor {
                reference: _,
                shared,
            } => {
                self.insert_target_process_monitor(shared);
                1
            }
            arinsal_sched::Signal::MonitorOrigin { reference, shared } => {
                self.insert_spawn_origin_monitor(reference, shared);
                2
            }
            arinsal_sched::Signal::MonitorOpaque { reference, shared } => {
                self.insert_target_monitor(reference, *shared);
                2
            }
            arinsal_sched::Signal::Demonitor(reference) => {
                self.remove_target_monitor(reference);
                2
            }
            arinsal_sched::Signal::DistDemonitor(reference) => {
                1 + 2 * i32::from(crate::dist::handle_dist_demonitor(self, reference))
            }
            arinsal_sched::Signal::DemonitorOrigin(shared) => {
                i32::from(self.remove_demonitored_target(shared))
            }
            signal @ (arinsal_sched::Signal::Exit(_) | arinsal_sched::Signal::ExitLinked(_)) => {
                let (linked_exit, mut message) = match signal {
                    arinsal_sched::Signal::ExitLinked(message) => (true, message),
                    arinsal_sched::Signal::Exit(message) => (false, message),
                    _ => unreachable!(),
                };
                // Port of erts/emulator/beam/erl_proc_sig_queue.c:4632-4815
                // (handle_exit_signal), OTP-29.1.1: an exit through an alias checks active state
                // without consuming a reply-once alias; a linked exit removes the link, and a
                // priority link makes the `'EXIT'` a priority message. The removed link item is
                // deleted after insertion.
                let mut prio_link_removed = false;
                let mut priority = false;
                let mut was_linked = false;
                if message.alias != 0 {
                    let Some(alias_priority) = self.alias_exit_accepted(message.alias) else {
                        return Ok(2);
                    };
                    priority = alias_priority && message.is_priority();
                } else if linked_exit {
                    let Some(link) = self.links.remove(from.data()) else {
                        // A local EXIT_LINKED for a link that has already gone is ignored.
                        return Ok(2);
                    };
                    let unlinking = link.view().unlinking() != 0;
                    if link.view().is_priority() {
                        prio_link_removed = true;
                        priority = !unlinking;
                    }
                    if unlinking {
                        if prio_link_removed {
                            self.prio_item_deleted(crate::receive::PrioItemType::Link);
                        }
                        return Ok(2);
                    }
                    was_linked = true;
                }
                // erl_proc_sig_queue.c:4724-4736 (handle_exit_signal): an exit reason received
                // from another node is decoded now; one that does not decode removes the signal.
                if message.is_external()
                    && !super::message::erts_proc_sig_decode_dist(self.runtime, &mut message, true)
                {
                    if prio_link_removed {
                        self.prio_item_deleted(crate::receive::PrioItemType::Link);
                    }
                    return Ok(2);
                }
                let result: Result<i32, VmError> = 'exit: {
                    let seq_token = message.take_seq_token();
                    let reason = message.into_receiver(self)?;
                    if reason == Term::atom(arinsal_term::atoms::KILL) && !linked_exit {
                        // Port of erts/emulator/beam/erl_proc_sig_queue.c:4766-4782
                        // (handle_exit_signal), OTP-29.1.1: an untrappable `kill` terminates
                        // with `killed` through erts_set_self_exiting; `cnt++`.
                        self.erts_set_self_exiting(ctx, Term::atom(arinsal_term::atoms::KILLED));
                        *exited = true;
                        break 'exit Ok(1);
                    }
                    if self.trap_exit() {
                        // Port of erts/emulator/beam/external.c:3127-3141, OTP-29.1.1.
                        // A scheduler proxy stands in for a remote PID internally, but
                        // EXIT messages expose the peer's original PID to Erlang code.
                        let sender = from;
                        let from = crate::dist::remote_pid_term(self, from)?
                            .or_else(|| from.to_term())
                            .ok_or_else(|| {
                                VmError::Unsupported("invalid signal sender pid".into())
                            })?;
                        let tuple =
                            self.tuple(&[Term::atom(arinsal_term::atoms::EXIT_2), from, reason])?;
                        if priority {
                            self.push_priority_message(tuple)?;
                        } else if let Some(token) = seq_token {
                            self.inbox.push_back_token(tuple, token);
                        } else {
                            // A process exit without a token converts to a message with NIL.
                            self.inbox.push_back_nil(tuple);
                        }
                        // erl_proc_sig_queue.c:4790 (handle_exit_signal).
                        Self::erts_proc_notify_new_message(ctx);
                        self.trace_converted_signal(ctx, tuple, sender);
                        if was_linked {
                            self.trace_getting_unlinked(ctx, sender);
                        }
                        // handle_exit_signal (erl_proc_sig_queue.c:4633-4800): converted, `cnt = 1`.
                        break 'exit Ok(1);
                    }
                    if reason != Term::atom(arinsal_term::atoms::NORMAL) {
                        // handle_exit_signal (erl_proc_sig_queue.c:4763-4784): terminate
                        // through erts_set_self_exiting; `cnt++`.
                        self.erts_set_self_exiting(ctx, reason);
                        *exited = true;
                        break 'exit Ok(1);
                    }
                    if was_linked {
                        self.trace_getting_unlinked(ctx, from);
                    }
                    // Ignored: `cnt = 1` plus one for destroying the signal.
                    Ok(2)
                };
                if prio_link_removed {
                    self.prio_item_deleted(crate::receive::PrioItemType::Link);
                }
                result?
            }
            // Port of erts/emulator/beam/io.c:3841-3891 (erts_deliver_port_exit), OTP-29.1.1.
            arinsal_sched::Signal::PortExit(exit) => {
                let arinsal_sched::PortExitSignal { port, reason } = *exit;
                let port = port.into_receiver(self)?;
                let reason = reason.into_receiver(self)?;
                // Port of erts/emulator/beam/erl_proc_sig_queue.c:4674-4720 (handle_exit_signal,
                // ERTS_SIG_Q_OP_EXIT_LINKED), OTP-29.1.1: a link exit whose link is gone, or
                // that arrives after unlink was requested, is ignored; the link is removed and a
                // priority link (ERTS_ML_FLG_PRIO_ML) makes the `'EXIT'` a priority message.
                let mut prio = false;
                let mut prio_link_removed = false;
                if let Some(id) = port.as_port() {
                    let key = crate::proc_create::port_link_key(id);
                    let Some((unlinking, link_prio)) = self
                        .links
                        .get(key)
                        .map(|link| (link.unlinking() != 0, link.is_priority()))
                    else {
                        return Ok(2);
                    };
                    self.links.remove(key);
                    if link_prio {
                        // A priority link is never unlinking: unlink clears the flag first.
                        prio_link_removed = true;
                    }
                    if unlinking {
                        if prio_link_removed {
                            self.prio_item_deleted(crate::receive::PrioItemType::Link);
                        }
                        return Ok(2);
                    }
                    prio = link_prio;
                }
                // A link exit is never untrappable: `kill` only kills as an `exit/2` signal
                // (handle_exit_signal: `!linked && reason == am_kill`).
                let result: Result<i32, VmError> = 'exit: {
                    if self.trap_exit() {
                        let tuple =
                            self.tuple(&[Term::atom(arinsal_term::atoms::EXIT_2), port, reason])?;
                        if prio {
                            self.push_priority_message(tuple)?;
                        } else {
                            self.inbox.push_back(tuple);
                        }
                        // erl_proc_sig_queue.c:4790 (handle_exit_signal).
                        Self::erts_proc_notify_new_message(ctx);
                        break 'exit Ok(1);
                    }
                    if reason != Term::atom(arinsal_term::atoms::NORMAL) {
                        // handle_exit_signal (erl_proc_sig_queue.c:4763-4784): terminate
                        // through erts_set_self_exiting; `cnt++`.
                        self.erts_set_self_exiting(ctx, reason);
                        *exited = true;
                        break 'exit Ok(1);
                    }
                    Ok(2)
                };
                // handle_exit_signal: deleted after the message is inserted.
                if prio_link_removed {
                    self.prio_item_deleted(crate::receive::PrioItemType::Link);
                }
                result?
            }
            arinsal_sched::Signal::MonitorNoproc(reference) => {
                let queued = self.inbox.len();
                self.deliver_monitor_down(
                    from,
                    reference,
                    Term::atom(arinsal_term::atoms::NOPROC),
                )?;
                self.notify_converted(ctx, queued);
                self.trace_new_message(ctx, queued, from);
                // convert_to_down_message (erl_proc_sig_queue.c:4838-5056).
                8
            }
            arinsal_sched::Signal::MonitorDown {
                reference,
                mut reason,
            } => {
                // erl_proc_sig_queue.c:6381-6386 (ERTS_SIG_Q_TYPE_GEN_EXIT of a monitor-down):
                // a reason received from another node is decoded before the monitor lookup; a
                // failed decode just removes the signal.
                if reason.is_external()
                    && !super::message::erts_proc_sig_decode_dist(self.runtime, &mut reason, true)
                {
                    return Ok(8);
                }
                let reason = reason.into_receiver(self)?;
                let queued = self.inbox.len();
                self.deliver_monitor_down(from, reference, reason)?;
                self.notify_converted(ctx, queued);
                self.trace_new_message(ctx, queued, from);
                8
            }
            arinsal_sched::Signal::MonitorDownImmediate { reference, reason } => {
                let reason = Term::from_immed_word(reason).expect("an immediate reason");
                let queued = self.inbox.len();
                self.deliver_monitor_down(from, reference, reason)?;
                self.notify_converted(ctx, queued);
                self.trace_new_message(ctx, queued, from);
                8
            }
            arinsal_sched::Signal::MonitorDownMsg { reference, message } => {
                // The sender built the DOWN message (erl_proc_sig_queue.c:2836-2900). The origin
                // still drops it when its monitor is gone (erl_proc_sig_queue.c:6355).
                let queued = self.inbox.len();
                self.deliver_monitor_down_message(reference, *message)?;
                self.notify_converted(ctx, queued);
                self.trace_new_message(ctx, queued, from);
                8
            }
            arinsal_sched::Signal::ProcessInfo(request) => {
                // Port of erts/emulator/beam/erl_proc_sig_queue.c:6794
                // (ERTS_SIG_Q_OP_PROCESS_INFO, handle_process_info at :5312, which costs at
                // least 8), OTP-29.1.1.
                let arinsal_sched::ProcessInfoRequest { id, items } = *request;
                crate::signals::reply_request(
                    self,
                    ctx,
                    crate::signals::Pending {
                        id,
                        from,
                        op: crate::signals::RemoteOp::Info { items },
                    },
                )?;
                8
            }
            arinsal_sched::Signal::GroupLeader(request) => {
                // Port of erts/emulator/beam/erl_proc_sig_queue.c (ERTS_SIG_Q_OP_GROUP_LEADER:
                // erts_set_group_leader, then `{Ref, true | badarg}` to the sender), OTP-29.1.1.
                let arinsal_sched::GroupLeaderRequest { id, leader } = *request;
                crate::signals::reply_request(
                    self,
                    ctx,
                    crate::signals::Pending {
                        id,
                        from,
                        op: crate::signals::RemoteOp::GroupLeader { leader },
                    },
                )?;
                1
            }
            arinsal_sched::Signal::Rpc(_) => {
                unreachable!("rpc signals are handled with the loop's cnt and limit")
            }
            arinsal_sched::Signal::IsAlive(id) => {
                // Port of erts/emulator/beam/erl_proc_sig_queue.c:6787 (ERTS_SIG_Q_OP_IS_ALIVE)
                // and is_alive_response (:3625), OTP-29.1.1.
                crate::signals::alive_response(self, ctx, from, id, true)?;
                1
            }
            arinsal_sched::Signal::SysTask(task) => {
                // Port of erts/emulator/beam/erl_process.c:11518 (sched_sig_sys_task), OTP-29.1.1.
                crate::signals::handle_sys_task(self, ctx, &task)?;
                8
            }
            arinsal_sched::Signal::DistLink(shared) => {
                // Port of erts/emulator/beam/erl_proc_sig_queue.c (ERTS_SIG_Q_OP_LINK,
                // ERTS_LNK_TYPE_DIST_PROC), OTP-29.1.1: a duplicate takes its dist half out of
                // the connection.
                if let Some(link) = crate::dist::DistLinkHalf::take(&shared) {
                    let remote = link.view().external_pid();
                    match self.links.lookup_insert(link) {
                        Ok(()) => {
                            if let Some(remote) = remote {
                                self.trace_getting_linked_external(ctx, remote);
                            }
                        }
                        Err(duplicate) => {
                            let deleted = duplicate.dist_delete_other();
                            duplicate.release_external(deleted);
                        }
                    }
                }
                0
            }
            arinsal_sched::Signal::DistUnlink(op) => {
                // Port of erts/emulator/beam/erl_proc_sig_queue.c (ERTS_SIG_Q_OP_UNLINK,
                // ERTS_SIG_Q_TYPE_DIST_LINK), OTP-29.1.1.
                let mut cnt = 0;
                let active = self
                    .links
                    .get_external(&op.remote)
                    .is_some_and(|link| link.unlinking() == 0);
                if active && let Some(link) = self.links.remove_external(&op.remote) {
                    // erl_proc_sig_queue.c:6680-6684: a priority link is a priority item.
                    if link.view().is_priority() {
                        self.prio_item_deleted(crate::receive::PrioItemType::Link);
                    }
                    let deleted = link.dist_delete_other();
                    link.release_external(deleted);
                    cnt += 8;
                    self.trace_getting_unlinked_external(ctx, op.remote);
                }
                if let Some(runtime) = self.runtime {
                    crate::dist::reply_dist_unlink_ack(runtime, &op);
                }
                cnt + 1
            }
            arinsal_sched::Signal::DistUnlinkAck(op) => {
                // Port of erts/emulator/beam/erl_proc_sig_queue.c (ERTS_SIG_Q_OP_UNLINK_ACK,
                // ERTS_SIG_Q_TYPE_DIST_LINK), OTP-29.1.1.
                if self
                    .links
                    .get_external(&op.remote)
                    .is_some_and(|link| link.unlinking() == op.id)
                    && let Some(link) = self.links.remove_external(&op.remote)
                {
                    let deleted = link.dist_delete_other();
                    link.release_external(deleted);
                    8
                } else {
                    0
                }
            }
            arinsal_sched::Signal::DistExit(exit) => {
                self.handle_dist_exit_signal(ctx, from, *exit, exited)?
            }
            arinsal_sched::Signal::UnlinkAckSignal(id) => self.handle_unlink_ack_signal(from, id),
            // Port of erl_proc_sig_queue.c:6879 (ERTS_SIG_Q_OP_DIST_SPAWN_REPLY): the handler
            // counts the signal itself, so the caller's `cnt++` is taken back.
            arinsal_sched::Signal::DistSpawnReply(shared) => {
                self.handle_dist_spawn_reply(ctx, &shared)? - 1
            }
            arinsal_sched::Signal::Alias(_) | arinsal_sched::Signal::Unalias(_) => {
                return Err(VmError::Unsupported("process aliases".into()));
            }
            arinsal_sched::Signal::LiteralAreaCopy(_) => {
                unreachable!("handle_cla preserves the literal-copy signal while it yields")
            }
            arinsal_sched::Signal::Flush => {
                unreachable!("FLUSH is handled in handle_incoming before handle_signal")
            }
        };
        Ok(cost)
    }

    /// Create the link and monitor of a distributed spawn and queue its reply message, as one
    /// signal. Returns the reduction count including the signal itself.
    // Port of erts/emulator/beam/erl_proc_sig_queue.c:5690 (handle_dist_spawn_reply), OTP-29.1.1.
    fn handle_dist_spawn_reply(
        &mut self,
        ctx: &mut RunCtx<'_, crate::Process>,
        shared: &arinsal_sched::SharedPayload,
    ) -> Result<i32, VmError> {
        use crate::monitor_link::node_flag;
        let data = shared
            .0
            .downcast_ref::<crate::dist::DistSpawnReplyData>()
            .expect("dist spawn reply signal carries its reply data");
        let mut cnt = 1;
        let id = data.id();
        let omon = self
            .monitors
            .get(id)
            .filter(|omon| !omon.is_target() && omon.spawn_pending());
        let Some(omon) = omon else {
            // Stale reply; the link that was set up is released with the reply data.
            return Ok(cnt + 1);
        };
        let flags = omon.flags();
        // The tag to patch into the resulting message (`mdep->u.name`).
        let tag = crate::dist::spawn_reply_tag_of(omon.info());
        let tag = crate::dist::spawn_reply_tag(self, tag)?;
        let mut convert_to_message = true;
        let adjust_monitor;
        if !data.is_success() {
            // Spawn error; the distribution code created no link. Delete the monitor.
            adjust_monitor = false;
            if flags & (node_flag::SPAWN_ABANDONED | node_flag::SPAWN_NO_EMSG) != 0 {
                convert_to_message = false;
            }
            if flags & node_flag::PRIO_ML != 0 {
                self.prio_item_deleted(crate::receive::PrioItemType::Monitor);
            }
        } else if flags & node_flag::SPAWN_ABANDONED != 0 {
            debug_assert_eq!(flags & node_flag::PRIO_ML, 0);
            // Spawn operation has been abandoned and link option was passed: send exit
            // signal with exit reason `abandoned`, delete the monitor and drop the message.
            if let Some(link) = data.link() {
                crate::dist::proc_exit_handle_link(
                    self.runtime,
                    ctx.pid(),
                    link,
                    Term::atom(arinsal_term::atoms::ABANDONED),
                );
            }
            adjust_monitor = false;
            convert_to_message = false;
        } else {
            if flags & node_flag::SPAWN_NO_SMSG != 0 {
                convert_to_message = false;
            }
            if let Some(link) = data.link() {
                cnt += 1;
                let link_priority = flags & node_flag::SPAWN_LINK_PRIO != 0;
                let mut link = link;
                link.view_mut().set_priority(link_priority);
                if let Err(duplicate) = self.links.lookup_insert(link) {
                    let deleted = duplicate.dist_delete_other();
                    duplicate.release_external(deleted);
                } else {
                    if link_priority {
                        self.prio_item_added(crate::receive::PrioItemType::Link);
                    }
                    if crate::trace::active() {
                        // linking(c_p, result)
                        let result = crate::dist::spawn_reply_child_term(self, data)?;
                        crate::trace::emit(
                            None,
                            self,
                            ctx,
                            ctx.pid(),
                            crate::trace::PROCS,
                            "link",
                            &[result],
                        );
                    }
                }
            }
            adjust_monitor = flags & node_flag::SPAWN_MONITOR != 0;
            if adjust_monitor {
                // Insert the actual pid of the spawned process in the origin part of the
                // monitor: it becomes an ordinary monitor of the child.
                if let Some(mut omon) = self.monitors.get_mut(id) {
                    if let Some(target) = omon.info().dist_target() {
                        target.set_item(data.result());
                    }
                    omon.update_flags(0, node_flag::SPAWNS);
                }
                self.cold_mut().dist_monitors.insert(id);
                cnt += 2;
            }
        }
        if !adjust_monitor {
            // Delete monitor; either spawn error or no monitor requested.
            if let Some(omon) = self.monitors.remove(id) {
                crate::dist::release_origin(omon);
            }
            cnt += 2;
        }
        if convert_to_message {
            let message = crate::dist::spawn_reply_message(self, tag, data)?;
            self.inbox.push_back(message);
            // erl_proc_sig_queue.c:5910 (handle_dist_spawn_reply).
            Self::erts_proc_notify_new_message(ctx);
        }
        Ok(cnt)
    }

    fn handle_unlink_signal(
        &mut self,
        ctx: &mut RunCtx<'_, crate::Process>,
        from: Pid,
        id: u64,
        operation: Option<crate::monitor_link::UnlinkOp>,
    ) -> Result<i32, VmError> {
        // Port of erl_proc_sig_queue.c (ERTS_SIG_Q_OP_UNLINK), OTP-29.1.1: delete the link only
        // when no unlink is pending, then send the operation's acknowledgement.
        let removed = match self.links.get(from.data()) {
            Some(node) if node.unlinking() != 0 => false,
            Some(_) => match self.links.remove(from.data()) {
                Some(link) => {
                    // erl_proc_sig_queue.c:6700-6707: a priority link is a priority item.
                    if link.view().is_priority() {
                        self.prio_item_deleted(crate::receive::PrioItemType::Link);
                    }
                    true
                }
                None => false,
            },
            None => false,
        };
        if removed {
            self.trace_getting_unlinked(ctx, from);
        }
        if let Some(operation) = operation {
            let ack = operation.into_ack_signal::<
                crate::proc_create::MonitorInfo,
                crate::proc_create::OriginMonitor,
                Event<Message>,
            >(ctx.pid());
            let _ = ctx.send_node(from, ack);
        } else {
            let _ = ctx.signal(from, arinsal_sched::Signal::UnlinkAckSignal(id));
        }
        Ok(if removed { 4 } else { 0 })
    }

    fn handle_unlink_ack_signal(&mut self, from: Pid, id: u64) -> i32 {
        // Port of erl_proc_sig_queue.c (ERTS_SIG_Q_OP_UNLINK_ACK), OTP-29.1.1.
        if self
            .links
            .get(from.data())
            .is_some_and(|node| node.unlinking() == id)
        {
            self.links.remove(from.data());
            4
        } else {
            0
        }
    }
}

impl Process {
    /// `handle_exit_signal` for an exit signal from a remote process: the link is found by the
    /// external pid and, for a `noconnection` exit, kept when it belongs to a newer connection.
    // Port of erts/emulator/beam/erl_proc_sig_queue.c (handle_exit_signal), OTP-29.1.1.
    fn handle_dist_exit_signal(
        &mut self,
        ctx: &mut RunCtx<'_, crate::Process>,
        sender: Pid,
        exit: arinsal_sched::DistExitSignal<Message>,
        exited: &mut bool,
    ) -> Result<i32, VmError> {
        let arinsal_sched::DistExitSignal {
            from,
            linked,
            connection_lost,
            reason,
        } = exit;
        let mut prio = false;
        let mut was_linked = false;
        let mut prio_link_removed = false;
        if linked {
            let state = self.links.get_external(&from).map(|link| {
                let lost_elsewhere = connection_lost.is_some_and(|id| {
                    link.external_dist()
                        .is_some_and(|dist| dist.connection_id != id)
                });
                (link.unlinking() != 0, lost_elsewhere, link.is_priority())
            });
            let Some((unlinking, lost_elsewhere, link_prio)) = state else {
                // No longer active.
                return Ok(2);
            };
            if lost_elsewhere {
                // The link was made over a newer connection: drop the signal silently.
                return Ok(2);
            }
            if let Some(link) = self.links.remove_external(&from) {
                prio_link_removed = link.view().is_priority();
                let deleted = link.dist_delete_other();
                link.release_external(deleted);
            }
            if unlinking {
                if prio_link_removed {
                    self.prio_item_deleted(crate::receive::PrioItemType::Link);
                }
                return Ok(2);
            }
            was_linked = true;
            prio = link_prio;
        }
        let result = self
            .convert_dist_exit_signal(ctx, sender, from, linked, was_linked, prio, reason, exited);
        // handle_exit_signal: deleted after the message is inserted, so the prio queue is
        // still installed for it.
        if prio_link_removed {
            self.prio_item_deleted(crate::receive::PrioItemType::Link);
        }
        result
    }

    /// The `'EXIT'` message or the exit of a remote exit signal whose link (if any) is gone.
    // Port of erts/emulator/beam/erl_proc_sig_queue.c (handle_exit_signal), OTP-29.1.1.
    #[allow(clippy::too_many_arguments)]
    fn convert_dist_exit_signal(
        &mut self,
        ctx: &mut RunCtx<'_, crate::Process>,
        sender: Pid,
        from: crate::monitor_link::ExternalPid,
        linked: bool,
        was_linked: bool,
        prio: bool,
        reason: Message,
        exited: &mut bool,
    ) -> Result<i32, VmError> {
        let mut message = reason;
        // erl_proc_sig_queue.c:4724-4736 (handle_exit_signal): the reason of an exit received
        // from another node is decoded once the link checks passed; a bad one removes the
        // signal.
        if message.is_external()
            && !super::message::erts_proc_sig_decode_dist(self.runtime, &mut message, true)
        {
            return Ok(2);
        }
        let seq_token = message.take_seq_token();
        let reason = message.into_receiver(self)?;
        if self.trap_exit() && (linked || reason != Term::atom(arinsal_term::atoms::KILL)) {
            let from_term = crate::dist::external_pid_term(&mut self.heap, from)?;
            let tuple =
                self.tuple(&[Term::atom(arinsal_term::atoms::EXIT_2), from_term, reason])?;
            if prio {
                self.push_priority_message(tuple)?;
            } else if let Some(token) = seq_token {
                self.inbox.push_back_token(tuple, token);
            } else {
                self.inbox.push_back_nil(tuple);
            }
            // erl_proc_sig_queue.c:4790 (handle_exit_signal).
            Self::erts_proc_notify_new_message(ctx);
            self.trace_converted_signal(ctx, tuple, sender);
            if was_linked {
                self.trace_getting_unlinked_external(ctx, from);
            }
            return Ok(1);
        }
        // handle_exit_signal (erl_proc_sig_queue.c:4763-4784): an untrappable `kill`
        // terminates with `killed`, any other abnormal reason with itself, through
        // erts_set_self_exiting; `cnt++`.
        if !linked && reason == Term::atom(arinsal_term::atoms::KILL) {
            self.erts_set_self_exiting(ctx, Term::atom(arinsal_term::atoms::KILLED));
            *exited = true;
            return Ok(1);
        }
        if reason != Term::atom(arinsal_term::atoms::NORMAL) {
            self.erts_set_self_exiting(ctx, reason);
            *exited = true;
            return Ok(1);
        }
        if was_linked {
            self.trace_getting_unlinked_external(ctx, from);
        }
        Ok(2)
    }

    /// `getting_linked` with an external linker.
    fn trace_getting_linked_external(
        &mut self,
        ctx: &mut RunCtx<'_, crate::Process>,
        linker: crate::monitor_link::ExternalPid,
    ) {
        if crate::trace::active()
            && let Ok(linker) = crate::dist::external_pid_term(&mut self.heap, linker)
        {
            crate::trace::emit(
                None,
                self,
                ctx,
                ctx.pid(),
                crate::trace::PROCS,
                "getting_linked",
                &[linker],
            );
        }
    }

    /// `getting_unlinked` with an external unlinker.
    fn trace_getting_unlinked_external(
        &mut self,
        ctx: &mut RunCtx<'_, crate::Process>,
        unlinker: crate::monitor_link::ExternalPid,
    ) {
        if crate::trace::active()
            && let Ok(unlinker) = crate::dist::external_pid_term(&mut self.heap, unlinker)
        {
            crate::trace::emit(
                None,
                self,
                ctx,
                ctx.pid(),
                crate::trace::PROCS,
                "getting_unlinked",
                &[unlinker],
            );
        }
    }

    /// Port of erts/emulator/beam/erl_proc_sig_queue.c:8585 (getting_linked), OTP-29.1.1.
    fn trace_getting_linked(&mut self, ctx: &mut RunCtx<'_, crate::Process>, linker: Pid) {
        if let Some(linker) = linker.to_term() {
            crate::trace::emit(
                None,
                self,
                ctx,
                ctx.pid(),
                crate::trace::PROCS,
                "getting_linked",
                &[linker],
            );
        }
    }

    /// Port of erts/emulator/beam/erl_proc_sig_queue.c:8578 (getting_unlinked), OTP-29.1.1.
    fn trace_getting_unlinked(&mut self, ctx: &mut RunCtx<'_, crate::Process>, unlinker: Pid) {
        if let Some(unlinker) = unlinker.to_term() {
            crate::trace::emit(
                None,
                self,
                ctx,
                ctx.pid(),
                crate::trace::PROCS,
                "getting_unlinked",
                &[unlinker],
            );
        }
    }
}

impl Process {
    /// Handle incoming signals while this process is in a dirty state. A dirty signal
    /// handler process calls this with `ctx` acting as this process.
    ///
    /// Port of erts/emulator/beam/erl_proc_sig_queue.c:8893
    /// (erts_internal_dirty_process_handle_signals_1), OTP-29.1.1. Collections are deferred
    /// until the job returns, and an exit signal makes the process exiting: pending requests
    /// fail now and it terminates on a normal scheduler.
    ///
    /// Signals are handled within the handler's reductions; returns `false` when some are
    /// left (`more`), so the handler calls again.
    pub(crate) fn handle_dirty_signals(
        &mut self,
        vm: &mut Vm,
        ctx: &mut RunCtx<'_, crate::Process>,
        reds: i32,
    ) -> bool {
        if self.dirty_exiting() {
            return true;
        }
        let gc = self.set_gc_enabled(false);
        // `reds = ERTS_BIF_REDS_LEFT(BIF_P)` (the caller's) and one
        // `erts_proc_sig_handle_incoming`.
        let mut reds = reds.max(1);
        let max_reds = reds;
        let result = self
            .handle_incoming(ctx, &mut reds, max_reds, false)
            .and_then(|done| Self::erts_bif_chk_exited(self, ctx).map(|()| done));
        self.set_gc_enabled(gc);
        let done = !matches!(result, Ok(false));
        if let Err(error) = result {
            // Port of erts/emulator/beam/erl_process.c:10096 (need_forced_exit), OTP-29.1.1:
            // an exiting process is terminated while its dirty job keeps running.
            self.set_dirty_exited();
            crate::signals::process_exiting(self, ctx);
            let reason = exit_reason_from(self, &error);
            self.notify_exit(vm, ctx, reason);
            // `notify_exit` released the cold state; the process stays marked exited.
            self.slice_mut().dirty_exited = true;
        }
        // Replies, exit and DOWN signals must not wait for the dirty job to return.
        ctx.flush_pending();
        done
    }

    /// Drop the literal-release hold of a process that exited while executing dirty, and wake
    /// the collector when it waited for it.
    // Port of erts/emulator/beam/erl_process.c:13480 (delete_process calls erts_unblock_release_literal_area), OTP-29.1.1.
    pub(super) fn unblock_literal_release(&mut self) {
        // erts releases `trap_state->block_rla_ref` only when it is set; a process that never
        // blocked a literal area has no cold part to allocate for it.
        let Some(block) = self.take_work(|work| work.rla_block.take()) else {
            return;
        };
        if let Some(waiter) = self.persistent_terms.unblock_release(block)
            && let Some(runtime) = self.runtime
        {
            crate::natives::code::resume_suspended(runtime, Pid::from_data(waiter));
        }
    }

    /// Whether this process already exited while executing a dirty job.
    pub(crate) fn dirty_exiting(&self) -> bool {
        self.slice().is_some_and(|work| work.dirty_exited)
    }
}

/// `func` of an `ErtsProcSigRPC`: runs in the receiving process `c_p` with `arg`. `redsp` is
/// `NULL` for a direct call; on entry it holds the reductions left, on return the reductions
/// used (negative to force a yield). A non-immediate result lives in `*bpp`, or on `c_p`'s heap
/// for a direct call (`bpp == NULL`).
// Port of erts/emulator/beam/erl_proc_sig_queue.c:213 (ErtsProcSigRPC.func), OTP-29.1.1.
pub(crate) type RpcFunc = fn(
    &mut Process,
    &mut RunCtx<'_, crate::Process>,
    Option<Box<dyn std::any::Any + Send>>,
    Option<&mut i32>,
    Option<&mut Option<arinsal_term::message::MessageHeapBlock>>,
) -> Result<Term, VmError>;

/// The `func` and `arg` of an `ErtsProcSigRPC`, carried by [`arinsal_sched::RpcRequest::call`].
// Port of erts/emulator/beam/erl_proc_sig_queue.c:213 (ErtsProcSigRPC), OTP-29.1.1.
pub(crate) struct ProcSigRpc {
    func: RpcFunc,
    arg: Mutex<Option<Box<dyn std::any::Any + Send>>>,
}

/// Send `func(arg)` to run in process `to`. With `reply` the result is the reference the caller
/// receives `{Ref, Result}` on, else `ok`; `None` (`THE_NON_VALUE`) when `to` is gone.
// Port of erts/emulator/beam/erl_proc_sig_queue.c:3368 (erts_proc_sig_send_rpc_request,
// erts_proc_sig_send_rpc_request_prio with prio -1), OTP-29.1.1.
pub(crate) fn erts_proc_sig_send_rpc_request(
    c_p: &mut Process,
    ctx: &mut RunCtx<'_, crate::Process>,
    to: Pid,
    reply: bool,
    func: RpcFunc,
    arg: Option<Box<dyn std::any::Any + Send>>,
) -> Result<Option<Term>, VmError> {
    let (id, res) = if reply {
        let id = c_p.next_ref();
        let res = crate::signals::reference(c_p, id)?;
        crate::port::set_save_end(c_p, ctx);
        (Some(id), res)
    } else {
        (None, Term::atom(arinsal_term::atoms::OK))
    };
    let call = arinsal_sched::SharedPayload(Arc::new(ProcSigRpc {
        func,
        arg: Mutex::new(arg),
    }));
    let signal = arinsal_sched::Signal::Rpc(Box::new(arinsal_sched::RpcRequest { id, call }));
    match ctx.signal(to, signal) {
        Ok(()) => {
            // maybe_elevate_sig_handling_prio(c_p, -1, to)
            crate::signals::elevate_for_signal_request(c_p, ctx, to)?;
            Ok(Some(res))
        }
        Err(arinsal_sched::Error::NoProcess) => {
            if reply {
                c_p.msgq_set_save_first();
            }
            Ok(None)
        }
        Err(error) => Err(VmError::Unsupported(format!("rpc request: {error}"))),
    }
}

impl Process {
    /// Run an rpc request and answer `{Ref, Result}` to its requester; returns the signal's
    /// `cnt`. `yield_` is set when `func` asks for a yield.
    // Port of erts/emulator/beam/erl_proc_sig_queue.c:3564 (handle_rpc), OTP-29.1.1.
    pub(crate) fn handle_rpc(
        &mut self,
        ctx: &mut RunCtx<'_, crate::Process>,
        requester: Pid,
        rpc: arinsal_sched::RpcRequest,
        cnt: i32,
        limit: i32,
        yield_: &mut bool,
    ) -> Result<i32, VmError> {
        let arinsal_sched::RpcRequest { id, call } = rpc;
        let call = call
            .0
            .downcast_ref::<ProcSigRpc>()
            .expect("rpc signal carries ProcSigRpc");
        let arg = call.arg.lock().unwrap_or_else(|e| e.into_inner()).take();
        let mut reds = (limit - cnt) / SIG_REDS_CNT_FACTOR;
        if reds <= 0 {
            reds = 1;
        }
        let mut bp = None;
        let res = (call.func)(self, ctx, arg, Some(&mut reds), Some(&mut bp))?;
        if reds < 0 {
            // Force yield...
            *yield_ = true;
            reds = -reds;
        }
        let out_cnt = reds * SIG_REDS_CNT_FACTOR;
        // `rp = erts_proc_lookup(rpc->requester)`: the send below drops the reply of a gone
        // requester, and `bp` with it.
        if let Some(id) = id {
            // hsz = 3 + sizeof(ErtsORefThing)/sizeof(Eterm), plus the result copied out of `bp`
            // (Arinsal's message fragment holds one heap, erts chains `bp` as `hfrag.next`).
            let res_words = if bp.is_some() { size_object(res) } else { 0 };
            let mut heap = arinsal_term::message::MessageHeapBlock::with_words(3 + 3 + res_words);
            let res = if bp.is_some() {
                copy_term(res, &mut heap)
                    .map_err(|error| VmError::Unsupported(format!("rpc reply: {error:?}")))?
            } else {
                res
            };
            drop(bp);
            let reference =
                Term::local_ref(&mut heap, arinsal_sched::unique::ordinary_ref_words(id))
                    .map_err(|error| VmError::Unsupported(format!("rpc reply: {error:?}")))?;
            let msg = TermBuilder::new(&mut heap)
                .tuple(&[reference, res])
                .map_err(|error| VmError::Unsupported(format!("rpc reply: {error:?}")))?;
            match ctx.send(requester, Message::from_heap_block(msg, heap)) {
                Ok(()) | Err(arinsal_sched::Error::NoProcess) => {}
                Err(error) => {
                    return Err(VmError::Unsupported(format!("rpc reply: {error}")));
                }
            }
        }
        Ok(out_cnt)
    }
}
