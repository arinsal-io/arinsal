use super::*;

/// Port of erts/emulator/beam/erl_proc_sig_queue.c:52 (ERTS_SIG_REDS_CNT_FACTOR), OTP-29.1.1.
pub(super) const SIG_REDS_CNT_FACTOR: i32 = 4;

/// Port of erts/emulator/beam/erl_proc_sig_queue.h:284 (ERTS_SIG_HANDLE_REDS_MAX_PREFERED),
/// OTP-29.1.1.
pub(crate) const SIG_HANDLE_REDS_MAX_PREFERED: i32 = CONTEXT_REDS / 40;

impl Process {
    /// Handle the signals left in the middle queue without fetching.
    pub(crate) fn handle_local_signals(
        &mut self,
        ctx: &mut RunCtx<'_, Message>,
    ) -> Result<(), VmError> {
        loop {
            let mut reds = CONTEXT_REDS;
            if self.handle_incoming(ctx, &mut reds, CONTEXT_REDS, true)? {
                return Ok(());
            }
        }
    }

    /// Handle every signal queued for this process: fetch once, then handle the middle queue
    /// in `CONTEXT_REDS` rounds until it is empty.
    // Port of erts/emulator/beam/erl_bif_info.c:4643-4652 (process_info on a process that
    // handles its signals until done), OTP-29.1.1.
    pub(crate) fn drain(&mut self, ctx: &mut RunCtx<'_, Message>) -> Result<(), VmError> {
        let mut local_only = false;
        loop {
            let mut reds = CONTEXT_REDS;
            if self.handle_incoming(ctx, &mut reds, CONTEXT_REDS, local_only)? {
                return Ok(());
            }
            local_only = true;
        }
    }

    /// Receive-trace a signal that was converted into a message.
    // Port of erts/emulator/beam/erl_proc_sig_queue.c:3804-3890 (convert_to_msg with
    // receive tracing) and 8627 (trace_receive), OTP-29.1.1.
    pub(super) fn trace_converted_signal(
        &mut self,
        ctx: &mut RunCtx<'_, Message>,
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
    fn trace_new_message(&mut self, ctx: &mut RunCtx<'_, Message>, queued: usize, from: Pid) {
        if self.inbox.len() > queued
            && let Some(message) = self.inbox.get(self.inbox.len() - 1).copied()
        {
            self.trace_converted_signal(ctx, message, from);
        }
    }

    /// Move the outer signal queue into this process. Without unhandled signals in the
    /// middle queue, and when the batch holds only ordinary messages and receive tracing is
    /// off, the messages go straight to the message queue; otherwise the batch is appended to
    /// the middle queue (`sig_cont`) for [`Self::handle_incoming`].
    // Port of erts/emulator/beam/erl_proc_sig_queue.c:1332 (erts_proc_sig_fetch__), OTP-29.1.1.
    pub(crate) fn fetch_signals(&mut self, ctx: &mut RunCtx<'_, Message>) -> Result<(), VmError> {
        let cont = !self.sig_cont_empty();
        let start = self.sig_cont().len();
        ctx.fetch_signals(&mut self.sig_cont_mut());
        if cont
            || self.sig_cont().len() == start
            || (crate::trace::active()
                && crate::trace::flags(self, ctx.pid()) & crate::trace::RECEIVE != 0)
            // erts_proc_sig_fetch__ tests `nmsigs.next`: a fetched queue without non-message
            // signals goes straight onto the message queue.
            || self.sig_cont().non_messages() != 0
        {
            ctx.set_sig_q(!self.sig_cont_empty());
            return Ok(());
        }
        // The whole batch is one splice onto the message queue in erts (LINK_MESSAGE of the
        // fetched list); a plain message needs no alias, priority or receive-trace handling.
        let count = self.sig_cont().len();
        self.sig_cont_taken += count as u64;
        ctx.consume_fetched_many(count);
        while let Some(node) = self.pop_sig_cont_signal() {
            match &node.payload {
                Payload::Message(message) if message.alias == 0 && !message.is_priority() => {
                    let old_prio_len = self.cold.as_ref().map_or(0, |cold| cold.prio_len);
                    let before = self.message_words_before();
                    let new_prio_len = self.inbox.push_message_node(node, old_prio_len);
                    self.uncount_message_words(before);
                    debug_assert_eq!(new_prio_len, old_prio_len);
                }
                _ => self.move_message(ctx, node)?,
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

    /// Whether GC was enabled again with delayed GC tasks saved: erts moves them back to the
    /// system task queue and sets `ERTS_PSFLG_ACTIVE_SYS`, so they run at the next
    /// scheduling point even when the process waits.
    // Port of erts/emulator/beam/erl_process.c:11823-11935 (erts_set_gc_state), OTP-29.1.1.
    pub(crate) fn delayed_gc_due(&self) -> bool {
        self.heap.gc_enabled && self.slice().is_some_and(|work| !work.delayed_gc.is_empty())
    }

    /// Handle the signals of the middle queue (`sig_cont`) for at most `*reds` reductions
    /// (and `max_reds` when the limit is stretched), after fetching the outer queue unless
    /// `local_only`. Messages before the next unhandled signal move to the message queue; the
    /// rest stays in the middle queue. `*reds` returns the reductions used. Returns whether
    /// every signal was handled. An exit signal that terminates the process is the error.
    // Port of erts/emulator/beam/erl_proc_sig_queue.c:6229-7178
    // (erts_proc_sig_handle_incoming), OTP-29.1.1.
    pub(crate) fn handle_incoming(
        &mut self,
        ctx: &mut RunCtx<'_, Message>,
        reds: &mut i32,
        max_reds: i32,
        local_only: bool,
    ) -> Result<bool, VmError> {
        if !local_only {
            self.fetch_signals(ctx)?;
        }
        if self.delayed_gc_due() {
            for task in self.take_delayed_gc() {
                match task {
                    crate::proc_create::DelayedGc::Collect => self.force_gc()?,
                    crate::proc_create::DelayedGc::Request(pending) => {
                        crate::signals::reply_request(self, ctx, pending)?
                    }
                    crate::proc_create::DelayedGc::Literal {
                        area_id,
                        request,
                        how,
                        requester,
                    } => crate::natives::sys::copy_literal_area(
                        self, ctx, area_id, request, how, requester,
                    )?,
                }
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
        // The message queue as it was before this call: erts moves the handled part of the
        // middle queue there only when it stops, so `stretch_limit` looks at this prefix.
        let msgq_len = self.inbox.len();
        let mut cnt = 0_i32;
        let mut handled = false;
        let result = loop {
            // Messages up to the next non-message signal or receive marker.
            let marker = loop {
                if self.recv_marker_due() {
                    break true;
                }
                match self.sig_cont().front() {
                    Some(event) if Self::is_ordinary_message(&event.payload) => {
                        let node = self.pop_sig_cont_signal().expect("front checked");
                        self.sig_cont_taken += 1;
                        ctx.consume_fetched();
                        self.move_message(ctx, node)?;
                    }
                    _ => break false,
                }
            };
            if !marker && self.sig_cont().is_empty() {
                break Ok(true);
            }
            if handled && !(cnt <= limit || self.stretch_limit(abs_lim, &mut limit, msgq_len)) {
                break Ok(false);
            }
            handled = true;
            if marker {
                self.recv_marker_enter_msgq();
                cnt += 1;
                continue;
            }
            let Some(node) = self.pop_sig_cont_signal() else {
                break Ok(true);
            };
            self.sig_cont_taken += 1;
            ctx.consume_fetched();
            if !node.is_lazy() && !matches!(node.payload, Payload::Signal(_)) {
                // ERTS_SIG_Q_OP_ALTACT_MSG: a priority message enters the priority queue.
                match self.move_message(ctx, node) {
                    Ok(()) => {
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
            if let Payload::Signal(Signal::Link { priority }) = payload {
                if let Err(duplicate) = self
                    .links
                    .lookup_insert(crate::proc_create::process_link(*from, *priority))
                {
                    drop(duplicate);
                } else {
                    self.trace_getting_linked(ctx, *from);
                }
                cnt += 1;
                continue;
            }
            let Event { from, payload } = node.into_value();
            match self.handle_signal(ctx, from, payload) {
                Ok(cost) => cnt += cost + 1,
                Err(error) => break Err(error),
            }
        };
        // Port of erl_proc_sig_queue.c:7160 (`*redsp = cnt/ERTS_SIG_REDS_CNT_FACTOR + 1`).
        *reds = cnt / SIG_REDS_CNT_FACTOR + 1;
        ctx.set_sig_q(!self.sig_cont_empty());
        let done = result?;
        crate::natives::erts_debug::after_message_queue_change(self);
        Ok(done)
    }

    /// Handle one non-message signal; returns its reduction count (`cnt`) in units of
    /// 1/`ERTS_SIG_REDS_CNT_FACTOR` reduction, without the `cnt++` every signal costs.
    // Port of the signal cases of erts/emulator/beam/erl_proc_sig_queue.c:6336-6968
    // (erts_proc_sig_handle_incoming), OTP-29.1.1.
    fn handle_signal(
        &mut self,
        ctx: &mut RunCtx<'_, Message>,
        from: Pid,
        payload: Payload<Message>,
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
            arinsal_sched::Signal::Link { priority } => {
                // Port of erts/emulator/beam/erl_proc_sig_queue.c:6636-6646 (ERTS_SIG_Q_OP_LINK):
                // the receiver reports getting_linked in signal order, for a new link only.
                if let Err(duplicate) = self
                    .links
                    .lookup_insert(crate::proc_create::process_link(from, priority))
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
                if message.alias != 0 {
                    let Some(alias_priority) = self.alias_message_accepted(ctx, message.alias)?
                    else {
                        return Ok(1);
                    };
                    if !alias_priority {
                        message.priority = false;
                    }
                }
                // Port of erts/emulator/beam/erl_proc_sig_queue.c:4685-4795
                // (handle_exit_signal), OTP-29.1.1: a link exit removes the link and a
                // process that survives it traces getting_unlinked.
                let priority = message.is_priority()
                    || self
                        .links
                        .get(from.data())
                        .is_some_and(|node| node.is_priority());
                let was_linked = linked_exit && self.links.remove(from.data()).is_some();
                let seq_token = message.take_seq_token();
                let reason = message.into_receiver(self)?;
                if reason == Term::atom(arinsal_term::atoms::KILL) && !linked_exit {
                    // Port of erts/emulator/beam/erl_proc_sig_queue.c:4782
                    // (handle_exit_signal), OTP-29.1.1: `kill` exits without exception dispatch.
                    return Err(VmError::Trap(crate::exceptions::Trap::killed()));
                }
                if self.trap_exit {
                    // Port of erts/emulator/beam/external.c:3127-3141, OTP-29.1.1.
                    // A scheduler proxy stands in for a remote PID internally, but
                    // EXIT messages expose the peer's original PID to Erlang code.
                    let sender = from;
                    let from = crate::dist::remote_pid_term(self, from)?
                        .or_else(|| from.to_term())
                        .ok_or_else(|| VmError::Unsupported("invalid signal sender pid".into()))?;
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
                    self.trace_converted_signal(ctx, tuple, sender);
                    if was_linked {
                        self.trace_getting_unlinked(ctx, sender);
                    }
                    // handle_exit_signal (erl_proc_sig_queue.c:4633-4800): converted, `cnt = 1`.
                    return Ok(1);
                }
                if reason != Term::atom(arinsal_term::atoms::NORMAL) {
                    self.heap.abi.exc.fvalue = reason.tagged_word();
                    return Err(VmError::Trap(crate::exceptions::Trap::exit(reason)));
                }
                if was_linked {
                    self.trace_getting_unlinked(ctx, from);
                }
                // Ignored: `cnt = 1` plus one for destroying the signal.
                2
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
                    if unlinking {
                        return Ok(2);
                    }
                    prio = link_prio;
                }
                // A link exit is never untrappable: `kill` only kills as an `exit/2` signal
                // (handle_exit_signal: `!linked && reason == am_kill`).
                if self.trap_exit {
                    let tuple =
                        self.tuple(&[Term::atom(arinsal_term::atoms::EXIT_2), port, reason])?;
                    if prio {
                        self.push_priority_message(tuple)?;
                    } else {
                        self.inbox.push_back(tuple);
                    }
                    return Ok(1);
                }
                if reason != Term::atom(arinsal_term::atoms::NORMAL) {
                    self.heap.abi.exc.fvalue = reason.tagged_word();
                    return Err(VmError::Trap(crate::exceptions::Trap::exit(reason)));
                }
                2
            }
            arinsal_sched::Signal::MonitorNoproc(reference) => {
                let queued = self.inbox.len();
                self.deliver_monitor_down(
                    from,
                    reference,
                    Term::atom(arinsal_term::atoms::NOPROC),
                )?;
                self.trace_new_message(ctx, queued, from);
                // convert_to_down_message (erl_proc_sig_queue.c:4838-5056).
                8
            }
            arinsal_sched::Signal::MonitorDown { reference, reason } => {
                let reason = reason.into_receiver(self)?;
                let queued = self.inbox.len();
                self.deliver_monitor_down(from, reference, reason)?;
                self.trace_new_message(ctx, queued, from);
                8
            }
            arinsal_sched::Signal::MonitorDownImmediate { reference, reason } => {
                let reason = Term::from_immed_word(reason).expect("an immediate reason");
                let queued = self.inbox.len();
                self.deliver_monitor_down(from, reference, reason)?;
                self.trace_new_message(ctx, queued, from);
                8
            }
            arinsal_sched::Signal::MonitorDownMsg { reference, message } => {
                // The sender built the DOWN message (erl_proc_sig_queue.c:2836-2900). The origin
                // still drops it when its monitor is gone (erl_proc_sig_queue.c:6355).
                let queued = self.inbox.len();
                self.deliver_monitor_down_message(reference, *message)?;
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
            arinsal_sched::Signal::Rpc(request) => {
                // Port of erts/emulator/beam/erl_proc_sig_queue.c (ERTS_SIG_Q_OP_RPC,
                // handle_rpc), OTP-29.1.1.
                let arinsal_sched::RpcRequest { id, op } = *request;
                let op = match op {
                    arinsal_sched::RpcOp::SaveCalls(value) => {
                        crate::signals::RemoteOp::SaveCalls { value }
                    }
                    arinsal_sched::RpcOp::Display => crate::signals::RemoteOp::Display,
                };
                crate::signals::reply_request(self, ctx, crate::signals::Pending { id, from, op })?;
                1
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
                self.handle_dist_exit_signal(ctx, from, *exit)?
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
            arinsal_sched::Signal::GarbageCollect => {
                if self.heap.gc_enabled {
                    self.force_gc()?;
                } else {
                    self.slice_mut()
                        .delayed_gc
                        .push(crate::proc_create::DelayedGc::Collect);
                }
                0
            }
            arinsal_sched::Signal::LiteralAreaCopy(copy) => {
                let arinsal_sched::LiteralAreaCopyRequest {
                    area_id,
                    request,
                    how,
                    requester,
                } = *copy;
                if !self.heap.gc_enabled && how != arinsal_sched::LiteralCopyHow::Init {
                    self.slice_mut()
                        .delayed_gc
                        .push(crate::proc_create::DelayedGc::Literal {
                            area_id,
                            request,
                            how,
                            requester,
                        });
                } else {
                    crate::natives::sys::copy_literal_area(
                        self, ctx, area_id, request, how, requester,
                    )?;
                }
                0
            }
        };
        Ok(cost)
    }

    /// Create the link and monitor of a distributed spawn and queue its reply message, as one
    /// signal. Returns the reduction count including the signal itself.
    // Port of erts/emulator/beam/erl_proc_sig_queue.c:5690 (handle_dist_spawn_reply), OTP-29.1.1.
    fn handle_dist_spawn_reply(
        &mut self,
        ctx: &mut RunCtx<'_, Message>,
        shared: &arinsal_sched::SharedPayload,
    ) -> Result<i32, VmError> {
        if let Some(down) = shared
            .0
            .downcast_ref::<crate::dist::DistSpawnNoconnection>()
        {
            // The connection of a pending request went down (erl_proc_sig_queue.c:4864,
            // a monitor-down signal of a spawn-pending monitor).
            if let Some(message) = crate::dist::spawn_noconnection_message(self, down)? {
                self.inbox.push_back(message);
            }
            return Ok(5);
        }
        let data = shared
            .0
            .downcast_ref::<crate::dist::DistSpawnReplyData>()
            .expect("dist spawn reply signal carries its reply data");
        let mut cnt = 1;
        let Some(request) = crate::dist::take_spawn_request(ctx.pid(), data.id()) else {
            // Stale reply: the link was never inserted here, only the distribution half of
            // the monitor is released.
            crate::dist::spawn_reply_drop_monitor(data);
            return Ok(cnt + 1);
        };
        let mut convert_to_message = true;
        let mut adjust_monitor = false;
        if !data.is_success() {
            // Spawn error; the distribution code created no link.
            if request.abandoned || request.no_error_msg {
                convert_to_message = false;
            }
        } else if request.abandoned {
            // Spawn operation has been abandoned and link option was passed: send exit
            // signal with exit reason `abandoned` and drop the message.
            if let Some(link) = data.link() {
                crate::dist::proc_exit_handle_link(
                    self.runtime,
                    ctx.pid(),
                    link,
                    Term::atom(arinsal_term::atoms::ABANDONED),
                );
            }
            convert_to_message = false;
        } else {
            if request.no_success_msg {
                convert_to_message = false;
            }
            if let Some(link) = data.link() {
                cnt += 1;
                if let Err(duplicate) = self.links.lookup_insert(link) {
                    let deleted = duplicate.dist_delete_other();
                    duplicate.release_external(deleted);
                } else if crate::trace::active() {
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
            adjust_monitor = request.monitor;
            if adjust_monitor {
                crate::dist::spawn_reply_install_origin_monitor(self, data);
                cnt += 2;
            }
        }
        if !adjust_monitor {
            // Delete monitor; either spawn error or no monitor requested.
            crate::dist::spawn_reply_drop_monitor(data);
            cnt += 2;
        }
        if convert_to_message {
            let message = crate::dist::spawn_reply_message(self, &request.tag, data)?;
            self.inbox.push_back(message);
        }
        Ok(cnt)
    }

    fn handle_unlink_signal(
        &mut self,
        ctx: &mut RunCtx<'_, Message>,
        from: Pid,
        id: u64,
        operation: Option<crate::monitor_link::UnlinkOp>,
    ) -> Result<i32, VmError> {
        // Port of erl_proc_sig_queue.c (ERTS_SIG_Q_OP_UNLINK), OTP-29.1.1: delete the link only
        // when no unlink is pending, then send the operation's acknowledgement.
        let removed = match self.links.get(from.data()) {
            Some(node) if node.unlinking() != 0 => false,
            Some(_) => self.links.remove(from.data()).is_some(),
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
        ctx: &mut RunCtx<'_, Message>,
        sender: Pid,
        exit: arinsal_sched::DistExitSignal<Message>,
    ) -> Result<i32, VmError> {
        let arinsal_sched::DistExitSignal {
            from,
            linked,
            connection_lost,
            reason,
        } = exit;
        let mut prio = false;
        let mut was_linked = false;
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
                let deleted = link.dist_delete_other();
                link.release_external(deleted);
            }
            if unlinking {
                return Ok(2);
            }
            was_linked = true;
            prio = link_prio;
        }
        let mut message = reason;
        let seq_token = message.take_seq_token();
        let reason = message.into_receiver(self)?;
        if self.trap_exit && (linked || reason != Term::atom(arinsal_term::atoms::KILL)) {
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
            self.trace_converted_signal(ctx, tuple, sender);
            if was_linked {
                self.trace_getting_unlinked_external(ctx, from);
            }
            return Ok(1);
        }
        if !linked && reason == Term::atom(arinsal_term::atoms::KILL) {
            return Err(VmError::Trap(crate::exceptions::Trap::killed()));
        }
        if reason != Term::atom(arinsal_term::atoms::NORMAL) {
            self.heap.abi.exc.fvalue = reason.tagged_word();
            return Err(VmError::Trap(crate::exceptions::Trap::exit(reason)));
        }
        if was_linked {
            self.trace_getting_unlinked_external(ctx, from);
        }
        Ok(2)
    }

    /// `getting_linked` with an external linker.
    fn trace_getting_linked_external(
        &mut self,
        ctx: &mut RunCtx<'_, Message>,
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
        ctx: &mut RunCtx<'_, Message>,
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
    fn trace_getting_linked(&mut self, ctx: &mut RunCtx<'_, Message>, linker: Pid) {
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
    fn trace_getting_unlinked(&mut self, ctx: &mut RunCtx<'_, Message>, unlinker: Pid) {
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
        ctx: &mut RunCtx<'_, Message>,
    ) -> bool {
        if self.dirty_exiting() {
            return true;
        }
        let gc = self.set_gc_enabled(false);
        // `reds = ERTS_BIF_REDS_LEFT(BIF_P)` and one `erts_proc_sig_handle_incoming`.
        let mut reds = i32::try_from(ctx.remaining()).unwrap_or(i32::MAX).max(1);
        let max_reds = reds;
        let result = self.handle_incoming(ctx, &mut reds, max_reds, false);
        self.set_gc_enabled(gc);
        let done = !matches!(result, Ok(false));
        if let Err(error) = result {
            // Port of erts/emulator/beam/erl_process.c:10096 (need_forced_exit), OTP-29.1.1:
            // an exiting process is terminated while its dirty job keeps running.
            self.set_dirty_exited();
            crate::signals::process_exiting(self, ctx);
            let reason = exit_reason_from(self, &error);
            self.notify_exit(vm, ctx, reason);
            if self.entry
                && let Some(runtime) = self.runtime.as_ref()
            {
                let _ = runtime.result.lock().unwrap().send(Err(error));
            }
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
