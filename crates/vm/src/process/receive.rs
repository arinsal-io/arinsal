use super::*;

/// Allocation policy for messages currently entering a process mailbox.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) enum MessageQueueData {
    #[default]
    OnHeap,
    OffHeap,
}

impl Process {
    pub(crate) fn push_priority_message(&mut self, term: Term) -> Result<(), VmError> {
        let old_prio_len = self.cold.as_ref().map_or(0, |cold| cold.prio_len);
        let new_prio_len = self.inbox.push_priority(term, old_prio_len);
        self.cold_mut().prio_len = new_prio_len;
        self.priority_item_inserted(old_prio_len, term)
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
    pub(super) fn stretch_limit(&self, abs_lim: i32, limit: &mut i32, msgq_len: usize) -> bool {
        if abs_lim == *limit {
            return false;
        }
        // The save pointer is in the message queue at a message (receive markers are not
        // queue entries here).
        if self.inbox.save() < msgq_len {
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
                if self.inbox.get(self.inbox.save()).is_some() {
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
            if self.inbox.get(self.inbox.save()).is_some() {
                return Ok((consumed_reds, ReceiveHelper::Message));
            }
            if left_reds <= 0 {
                break;
            }
        }
        Ok((consumed_reds, ReceiveHelper::Yield))
    }

    /// A message sent through an alias is handled only while the alias is active, and a
    /// `reply` alias is deactivated by the first one.
    // Port of erts/emulator/beam/erl_proc_sig_queue.c (handle_alias_message, ERTS_ALIAS_ONCE),
    // OTP-29.1.1.
    fn alias_message_accepted(
        &mut self,
        ctx: &mut RunCtx<'_, Message>,
        alias: u64,
    ) -> Result<bool, VmError> {
        if alias == 0 {
            return Ok(true);
        }
        let Some(runtime) = self.runtime else {
            return Ok(true);
        };
        let Some((Some(_), priority)) = runtime.alias_lookup_prio(alias) else {
            return Ok(false);
        };
        let Some(entry) = self.monitors.get_state(alias) else {
            return Ok(false);
        };
        if entry.alias_priority() != priority {
            return Ok(false);
        }
        if entry.alias_mode() == Some(crate::proc_create::AliasMode::ReplyDemonitor) {
            let entry = self.monitors.remove(alias);
            let state = entry.as_ref().and_then(|entry| entry.state()).cloned();
            match state {
                Some(crate::proc_create::OriginMonitor::Process(_)) => {
                    self.cold_mut().prio_monitors.remove(&alias);
                    let origin = entry.expect("origin half of the entry");
                    let target = Pid::from_data(origin.view().other());
                    let shared = origin.into_shared();
                    let _ = ctx.signal(target, arinsal_sched::Signal::DemonitorOrigin(shared));
                }
                Some(crate::proc_create::OriginMonitor::Port {
                    port_id: Some(port_id),
                    ..
                }) => {
                    crate::port::demonitor_port(self, ctx.pid(), port_id, alias);
                }
                Some(crate::proc_create::OriginMonitor::Alias { .. }) => {}
                Some(crate::proc_create::OriginMonitor::Distributed { .. }) => {
                    crate::dist::demonitor_alias(self, ctx, alias)?;
                }
                Some(
                    crate::proc_create::OriginMonitor::Port { .. }
                    | crate::proc_create::OriginMonitor::PortOrigin
                    | crate::proc_create::OriginMonitor::DistPort { .. },
                )
                | None => {}
            }
            runtime.alias_bind(alias, None);
        }
        Ok(true)
    }

    /// Move a message signal into the message queue.
    pub(super) fn move_message(
        &mut self,
        ctx: &mut RunCtx<'_, Message>,
        node: MessageNode,
    ) -> Result<(), VmError> {
        let from = node.from;
        if let Payload::Message(message) = &node.payload {
            let (alias, receive_traced, priority) =
                (message.alias, message.receive_traced, message.is_priority());
            {
                if !self.alias_message_accepted(ctx, alias)? {
                    return Ok(());
                }
                let old_prio_len = self.cold.as_ref().map_or(0, |cold| cold.prio_len);
                let sender = from;
                let before = self.message_words_before();
                let new_prio_len = self.inbox.push_message_node(node, old_prio_len);
                self.uncount_message_words(before);
                let trace_index = if priority {
                    old_prio_len
                } else {
                    self.inbox.len().saturating_sub(1)
                };
                if !receive_traced
                    && let Some(term) = self.inbox.get(trace_index).copied()
                    && crate::trace::flags(self, ctx.pid()) & crate::trace::RECEIVE != 0
                {
                    crate::trace::receive_event(None, self, ctx, term, Some(sender));
                }
                self.cold_mut().prio_len = new_prio_len;
                if priority {
                    let priority_term = self.inbox.get(old_prio_len).copied().ok_or_else(|| {
                        VmError::Unsupported("priority message missing after insertion".into())
                    })?;
                    self.priority_item_inserted(old_prio_len, priority_term)?;
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
                let tuple = self.tuple(&[crate::signals::atom("timeout"), reference, term])?;
                self.inbox.push_back(tuple);
                self.trace_converted_signal(ctx, tuple, from);
            }
            _ => unreachable!("move_message takes message signals"),
        }
        Ok(())
    }
}
