use super::*;

/// Allocation policy for messages currently entering a process mailbox.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) enum MessageQueueData {
    #[default]
    OnHeap,
    OffHeap,
}

impl Process {
    /// A priority message the process built itself enters the prio queue.
    pub(crate) fn push_priority_message(&mut self, term: Term) -> Result<(), VmError> {
        self.insert_prio_message(MessageQueue::node_for(term))
            .map(|_| ())
    }

    // Port of erts/emulator/beam/erl_proc_sig_queue.h (FS_OFF_HEAP_MSGQ in sig_qs.flags),
    // OTP-29.1.1: the queue mode is a process flag bit.
    pub(crate) fn message_queue_data(&self) -> MessageQueueData {
        if self.cold.as_ref().is_some_and(|cold| cold.off_heap_msgq) {
            MessageQueueData::OffHeap
        } else {
            MessageQueueData::OnHeap
        }
    }

    /// Whether `erts_garbage_collect` must fetch the outer signal queue first.
    // Port of erts/emulator/beam/erl_gc.c:987-990, OTP-29.1.1: only an on-heap
    // queue (or a queue changing onto the heap) is fetched, and only when the
    // outer queue is non-empty (`sig_inq.first`).
    pub(crate) fn gc_outer_queue_pending(&self) -> bool {
        if self.message_queue_data() == MessageQueueData::OffHeap {
            return false;
        }
        self.signal_probe()
            .is_some_and(arinsal_sched::SignalProbe::has_pending)
    }
}

/// Outcome of [`Process::receive_helper`] (`*msgpp` / `*get_outp`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReceiveHelper {
    /// A message is available at the save pointer.
    Message,
    /// No message in any queue: continue to the wait instruction.
    Wait,
    /// Out of reductions: yield and rerun `loop_rec`.
    Yield,
}

impl Process {
    /// Stretch the limit by up to 100 reductions, to at most `abs_lim`, when `receive` has no
    /// message to inspect and handling more signals may make one available.
    // Port of erts/emulator/beam/erl_proc_sig_queue.c:7181-7250 (stretch_limit), OTP-29.1.1.
    pub(super) fn stretch_limit(
        &self,
        abs_lim: i32,
        limit: &mut i32,
        msgq_end: crate::process::SaveField,
    ) -> bool {
        if abs_lim == *limit {
            return false;
        }
        // From the save pointer, pass receive markers without punishing them; a message
        // before the part handled during this call is there to inspect.
        let entries = &self.inbox.entries;
        let mut field = entries.save_field();
        while field != msgq_end {
            match entries.at(field) {
                None => break,
                Some(Some(_)) => return false,
                Some(None) => field = entries.next_of(field).expect("a marker node"),
            }
        }
        if entries.at(field).is_none() && self.sig_cont().is_empty() {
            return false;
        }
        *limit = (*limit + SIG_REDS_CNT_FACTOR * 100).min(abs_lim);
        true
    }

    /// The receive helper `loop_rec` runs at the end of the message queue: fetch the outer
    /// queue and handle signals until a message is available at the save pointer, the queues
    /// are empty, or `fcalls` run out. Returns the reductions consumed. An exit signal that
    /// terminates the process is the error.
    // Port of erts/emulator/beam/erl_proc_sig_queue.c:7729-7860
    // (erts_proc_sig_receive_helper), OTP-29.1.1.
    pub(crate) fn receive_helper(
        &mut self,
        ctx: &mut RunCtx<'_, Message>,
        fcalls: i32,
    ) -> Result<(i32, ReceiveHelper), VmError> {
        // `neg_o_reds` is nonzero only while saving calls (`save_calls`).
        let mut left_reds = fcalls;
        let mut consumed_reds = 0;
        loop {
            if self.sig_cont_empty() {
                consumed_reds += 4;
                left_reds -= 4;
                self.fetch_signals(ctx)?;
                // Messages may have been moved directly to the message queue.
                if self.inbox.peek().is_some() {
                    return Ok((consumed_reds, ReceiveHelper::Message));
                }
                if self.sig_cont_empty() {
                    return Ok((consumed_reds, ReceiveHelper::Wait));
                }
                if left_reds <= 0 {
                    break;
                }
            }
            // At least the preferred amount of reductions.
            let mut reds = SIG_HANDLE_REDS_MAX_PREFERED;
            let max_reds = left_reds.max(reds);
            self.handle_incoming(ctx, &mut reds, max_reds, true)?;
            consumed_reds += reds;
            left_reds -= reds;
            if self.inbox.peek().is_some() {
                return Ok((consumed_reds, ReceiveHelper::Message));
            }
            if left_reds <= 0 {
                break;
            }
        }
        Ok((consumed_reds, ReceiveHelper::Yield))
    }

    /// A message sent through an alias is handled only while the alias is active, and a
    /// `reply` alias is deactivated by the first one. `None` drops the message; otherwise
    /// whether the alias is a priority alias, and whether this message deactivated it (its
    /// priority item is deleted once the message is in the queue).
    // Port of erts/emulator/beam/erl_proc_sig_queue.c (handle_alias_message, ERTS_ALIAS_ONCE),
    // OTP-29.1.1.
    pub(super) fn alias_message_accepted(
        &mut self,
        ctx: &mut RunCtx<'_, Message>,
        alias: u64,
    ) -> Result<Option<(bool, bool)>, VmError> {
        if alias == 0 {
            return Ok(Some((false, false)));
        }
        if self.monitors.get_state(alias).is_none() {
            return Ok(None);
        }
        let monitor = self.monitors.get(alias).expect("monitor state has a node");
        let priority = monitor.alias_priority();
        let mut prio_alias_deactivated = false;
        if monitor.alias_mode() == Some(crate::proc_create::AliasMode::ReplyDemonitor) {
            let prio_ml = monitor.prio_ml();
            let entry = self.monitors.remove(alias);
            prio_alias_deactivated = priority;
            // erl_proc_sig_queue.c:6058-6062: a priority monitor is deleted at once.
            if prio_ml {
                self.prio_item_deleted(crate::receive::PrioItemType::Monitor);
            }
            let state = entry.as_ref().and_then(|entry| entry.state()).cloned();
            match state {
                Some(crate::proc_create::OriginMonitor::Process(_)) => {
                    let origin = entry.expect("origin half of the entry");
                    let target = Pid::from_data(origin.view().other());
                    let shared = origin.into_shared();
                    let _ = ctx.signal(target, arinsal_sched::Signal::DemonitorOrigin(shared));
                }
                Some(crate::proc_create::OriginMonitor::Port {
                    port_id: Some(port_id),
                    ..
                }) => {
                    if let Some(origin) = entry {
                        crate::port::demonitor_port(self, ctx.pid(), port_id, origin);
                    }
                }
                Some(crate::proc_create::OriginMonitor::Alias) => {}
                Some(crate::proc_create::OriginMonitor::Distributed) => {
                    // Port of erts/emulator/beam/erl_proc_sig_queue.c (handle_alias_message,
                    // ERTS_MON_TYPE_DIST_PROC): demonitor of the remote process.
                    if let Some(cold) = self.cold.as_mut() {
                        cold.dist_monitors.remove(&alias);
                    }
                    let origin = entry.expect("origin half of the entry");
                    crate::dist::demonitor_remote(self.runtime, ctx.pid(), origin);
                }
                Some(
                    crate::proc_create::OriginMonitor::Port { .. }
                    | crate::proc_create::OriginMonitor::PortOrigin
                    | crate::proc_create::OriginMonitor::DistPort { .. },
                )
                | None => {}
            }
        }
        Ok(Some((priority, prio_alias_deactivated)))
    }

    /// Move a message signal into the message queue.
    pub(super) fn move_message(
        &mut self,
        ctx: &mut RunCtx<'_, Message>,
        mut node: MessageNode,
    ) -> Result<(), VmError> {
        let from = node.from;
        if let Payload::Message(message) = &mut node.payload {
            let (alias, receive_traced, mut priority) =
                (message.alias, message.receive_traced, message.is_priority());
            {
                let Some((alias_priority, prio_alias_deactivated)) =
                    self.alias_message_accepted(ctx, alias)?
                else {
                    return Ok(());
                };
                // erl_proc_sig_queue.c:6021-6045: only a priority alias delivers a priority
                // message.
                if alias == 0 || !alias_priority {
                    message.priority = false;
                    priority = false;
                }
                let sender = from;
                let before = self.message_words_before();
                // ERTS_SIG_Q_OP_ALTACT_MSG with a priority: insert_prepared_prio_msg.
                let term = if priority {
                    let term = self.insert_prio_message(node)?;
                    self.uncount_message_words(before);
                    term
                } else {
                    let term = queued_term(&node);
                    self.inbox.push_message_node(node);
                    self.uncount_message_words(before);
                    term
                };
                if !receive_traced
                    && crate::trace::flags(self, ctx.pid()) & crate::trace::RECEIVE != 0
                {
                    crate::trace::receive_event(None, self, ctx, term, Some(sender));
                }
                // erl_proc_sig_queue.c:6209-6217: after the message is inserted, so the prio
                // queue is still installed for it.
                if prio_alias_deactivated {
                    self.prio_item_deleted(crate::receive::PrioItemType::Alias);
                }
            }
            return Ok(());
        }
        let Event { from, payload } = node.into_value();
        match payload {
            Payload::Timer { reference, message } => {
                let timer_id = message.timer_id();
                let term = message.into_receiver(self)?;
                let id = timer_id.or(reference.ref_key()).unwrap_or(reference.id());
                let reference = crate::signals::reference(self, id)?;
                let tuple =
                    self.tuple(&[Term::atom(arinsal_term::atoms::TIMEOUT), reference, term])?;
                self.inbox.push_back(tuple);
                self.trace_converted_signal(ctx, tuple, from);
            }
            _ => unreachable!("move_message takes message signals"),
        }
        Ok(())
    }
}
