use super::*;

// Uncaught errors leave `{Reason, Stack}` so links and monitors match erts.
// boot_loop2: OTP sends that pair; other raised classes send the reason alone.
/// The origin entry of a port monitor, as needed to build its `'DOWN'` message.
enum PortObject {
    Local(Option<u64>, Option<arinsal_term::Atom>),
    Dist(arinsal_etf::OwnedTerm),
}

impl Process {
    /// Insert the target half a monitor signal carries (erl_proc_sig_queue.c
    /// erts_proc_sig_handle_incoming, ERTS_SIG_Q_OP_MONITOR): a remote origin's half goes into
    /// the monitor tree, a local one into the `ERTS_P_LT_MONITORS` list; or the
    /// `ERTS_MON_TYPE_RESOURCE` monitor of a NIF resource.
    pub(crate) fn insert_target_monitor(
        &mut self,
        reference: u64,
        shared: arinsal_sched::SharedPayload,
    ) {
        if let Ok(monitor) = shared.0.downcast::<arinsal_nif::ResourceMonitor>() {
            self.cold_mut().resource_monitors.insert(reference, monitor);
        }
    }

    pub(super) fn insert_target_process_monitor(
        &mut self,
        shared: arinsal_alloc::typed::FixAllocArc<crate::proc_create::ProcessMonitorData>,
    ) {
        let Some(target) = crate::proc_create::ProcessMonitorData::take_half(shared, true) else {
            return;
        };
        self.insert_target_process_monitor_half(target);
    }

    pub(super) fn insert_target_process_monitor_half(
        &mut self,
        target: crate::proc_create::ProcessMonitor,
    ) {
        if target.view().kind() == crate::monitor_link::node_type::MONITOR_DIST_PROC {
            self.monitors.insert(target);
        } else {
            self.lt_monitors.insert(target);
        }
    }

    /// A demonitor by reference: of a remote origin (its target half is in the monitor tree) or
    /// of a NIF resource.
    pub(super) fn remove_target_monitor(&mut self, reference: u64) {
        if self
            .monitors
            .get(reference)
            .is_some_and(|monitor| monitor.is_target())
        {
            self.monitors.remove(reference);
        }
        if let Some(cold) = self.cold.as_deref_mut() {
            cold.resource_monitors.remove(&reference);
        }
    }

    /// The demonitor signal of a local monitor carries its origin half; the target half is
    /// reached through the data they share (erl_proc_sig_queue.c erts_proc_sig_handle_incoming,
    /// ERTS_SIG_Q_OP_DEMONITOR): both are released.
    pub(super) fn remove_demonitored_target(
        &mut self,
        data: arinsal_alloc::typed::FixAllocArc<crate::proc_create::ProcessMonitorData>,
    ) {
        let Some(origin) = crate::proc_create::ProcessMonitorData::take_half(data, false) else {
            return;
        };
        self.remove_demonitored_target_half(origin);
    }

    pub(super) fn remove_demonitored_target_half(
        &mut self,
        origin: crate::proc_create::ProcessMonitor,
    ) {
        let target = self.lt_monitors.remove_target_of(&origin);
        if let Some(target) = target {
            crate::proc_create::ProcessMonitor::release_both(origin, target);
        } else {
            drop(origin);
        }
    }

    pub(super) fn absorb_exit_signals(&mut self, ctx: &mut RunCtx<'_, Message>) {
        // Port of erts/emulator/beam/erl_proc_sig_queue.c:7426 (erts_proc_exit_handle_signal),
        // OTP-29.1.1: the signals left in the inner queue come before the outer queue's.
        let mut unhandled = std::mem::take(&mut *self.sig_cont_mut());
        loop {
            let Event { from, payload } = match unhandled.pop_front() {
                Some(event) => {
                    ctx.consume_fetched();
                    event
                }
                None => match ctx.receive() {
                    Some(event) => event,
                    None => break,
                },
            };
            match payload {
                Payload::Signal(Signal::Monitor { reference, shared }) => {
                    // Port of erl_proc_sig_queue.c:7426 (erts_proc_exit_handle_signal),
                    // OTP-29.1.1: a monitor arriving after exit has begun is answered as noproc.
                    // A driver port's monitor (`ERTS_MON_TYPE_PORT`) fires at once instead
                    // (erts_proc_exit_handle_monitor).
                    let port_origin = crate::proc_create::ProcessMonitorData::take_half(
                        shared, true,
                    )
                    .filter(|half| {
                        half.view().kind() == crate::monitor_link::node_type::MONITOR_PORT
                    });
                    if let Some(half) = port_origin {
                        if let Some(runtime) = self.runtime.as_ref() {
                            crate::port::fire_port_monitor(runtime, half.view().other(), reference);
                        }
                    } else {
                        let _ = ctx.signal(from, Signal::MonitorNoproc(reference));
                    }
                }
                Payload::Signal(Signal::Demonitor(reference)) => {
                    self.remove_target_monitor(reference);
                }
                Payload::Signal(Signal::DemonitorOrigin(shared)) => {
                    self.remove_demonitored_target(shared);
                }
                Payload::Signal(Signal::Link { .. }) => {
                    // Port of erts/emulator/beam/erl_proc_sig_queue.c:7426
                    // (erts_proc_exit_handle_signal), OTP-29.1.1: a link reaching an
                    // exiting process is rejected with `noproc`.
                    if let Ok(reason) = Message::copy_from(crate::signals::atom("noproc")) {
                        let _ = ctx.signal(from, Signal::ExitLinked(Box::new(reason)));
                    }
                }
                Payload::Signal(Signal::Unlink(id)) => {
                    self.links.remove(from.data());
                    let _ = ctx.signal(from, Signal::UnlinkAckSignal(id));
                }
                Payload::Signal(Signal::LiteralAreaCopy(copy)) => {
                    let arinsal_sched::LiteralAreaCopyRequest {
                        request, requester, ..
                    } = *copy;
                    let _ = crate::natives::sys::reply_exiting_literal_area(
                        self, ctx, request, requester,
                    );
                }
                // Port of erl_proc_sig_queue.c:7347 (erts_proc_exit_handle_signal, monitor
                // signals): a suspend that arrives at an exiting process is dropped at once.
                Payload::Signal(Signal::Suspend { shared }) => {
                    let _ = ctx.signal(from, Signal::SuspendDown { shared });
                }
                // Port of erl_proc_sig_queue.c:7408 (erts_proc_exit_handle_signal,
                // ERTS_SIG_Q_OP_SYNC_SUSPEND), OTP-29.1.1: answered from the exiting state.
                Payload::Signal(Signal::SyncSuspend(sync)) => {
                    let arinsal_sched::SyncSuspendRequest {
                        requester,
                        tag,
                        reply,
                        async_,
                    } = *sync;
                    let _ =
                        crate::suspend::sync_reply(self, ctx, requester, tag, reply, async_, true);
                }
                _ => {}
            }
        }
    }
}

impl Process {
    /// Queues a DOWN message the sender built, if the origin monitor is still active.
    /// Port of erts/emulator/beam/erl_proc_sig_queue.c:6355 (ERTS_SIG_Q_OP_MONITOR_DOWN).
    pub(super) fn deliver_monitor_down_message(
        &mut self,
        reference: u64,
        message: Message,
    ) -> Result<(), VmError> {
        let origin = crate::signals::take_origin_monitor_down(self, reference);
        // erts reads the monitor type from the origin node in the process's own tree
        // (erl_proc_sig_queue.c handle_monitor_down); only a distributed monitor has
        // remote bookkeeping to release.
        let remote = matches!(
            origin.as_ref().and_then(|origin| origin.state()),
            Some(crate::proc_create::OriginMonitor::Distributed { .. })
        ) && crate::dist::take_monitor(reference).is_some();
        let active = origin.is_some() || remote;
        let priority = self
            .cold
            .as_mut()
            .is_some_and(|cold| cold.prio_monitors.remove(&reference));
        if !active {
            return Ok(());
        }
        let tuple = message.into_receiver(self)?;
        if priority {
            self.push_priority_message(tuple)?;
        } else {
            self.inbox.push_back(tuple);
        }
        Ok(())
    }

    pub(super) fn deliver_monitor_down(
        &mut self,
        from: Pid,
        reference: u64,
        reason: Term,
    ) -> Result<(), VmError> {
        #[cfg(feature = "pf-mem-counters")]
        {
            let count = PF_MONITOR_DOWN.fetch_add(1, Ordering::Relaxed) + 1;
            if count.is_multiple_of(1024) {
                let markers = self
                    .cold
                    .as_ref()
                    .and_then(|cold| cold.receive_markers.as_ref())
                    .map_or(0, |markers| markers.len());
                eprintln!("PF_MEM down={count} markers={markers}");
            }
        }
        // Port of erts/emulator/beam/erl_proc_sig_queue.c:6355 (ERTS_SIG_Q_OP_MONITOR_DOWN),
        // OTP-29.1.1: a DOWN whose origin monitor is no longer in the table (a demonitor
        // raced with the target's exit) is dropped instead of becoming a message.
        let entry = crate::signals::take_origin_monitor_down(self, reference);
        // erts takes the monitor type from the origin node in the process's own tree
        // (erl_proc_sig_queue.c handle_monitor_down): a local process monitor has no
        // distribution bookkeeping to release.
        let remote = !matches!(
            entry.as_ref().and_then(|entry| entry.state()),
            Some(crate::proc_create::OriginMonitor::Process(_))
        ) && crate::dist::take_monitor(reference).is_some();
        let active = entry.is_some() || remote;
        if !active {
            crate::dist::discard_disconnected_monitor_pid(from);
        }
        let priority = self
            .cold
            .as_mut()
            .is_some_and(|cold| cold.prio_monitors.remove(&reference));
        if !active {
            return Ok(());
        }
        let (info, port_object) = match entry.as_ref().and_then(|entry| entry.state()) {
            Some(
                crate::proc_create::OriginMonitor::Process(_)
                | crate::proc_create::OriginMonitor::Distributed { .. },
            ) => (entry.as_ref().map(|entry| entry.view().info()), None),
            Some(crate::proc_create::OriginMonitor::Port { port_id, name, .. }) => {
                (None, Some(PortObject::Local(*port_id, *name)))
            }
            Some(crate::proc_create::OriginMonitor::DistPort { object, .. }) => {
                (None, Some(PortObject::Dist((**object).clone())))
            }
            _ => (None, None),
        };
        let tag = if let Some(owned) = info.and_then(|info| info.tag()) {
            let mut heap = arinsal_bifs::ProcessHeapHandle(&mut self.heap);
            arinsal_term::from_owned(owned, &mut heap)
                .map_err(|error| VmError::Unsupported(format!("monitor tag: {error:?}")))?
        } else {
            crate::signals::atom("DOWN")
        };
        let name = info.and_then(|info| info.name().map(str::to_owned));
        let reference = crate::signals::reference(self, reference)?;
        let (from_type, from) = if let Some(object) = port_object {
            // Port of erts/emulator/beam/erl_proc_sig_queue.c:4838-5056
            // (convert_to_down_message), OTP-29.1.1.
            let mut heap = arinsal_bifs::ProcessHeapHandle(&mut self.heap);
            let object = match object {
                PortObject::Local(port_id, name) => {
                    crate::signals::port_monitor_object(&mut heap, port_id, name)?
                }
                PortObject::Dist(object) => {
                    arinsal_term::from_owned(&object, &mut heap).map_err(|error| {
                        VmError::Unsupported(format!("port monitor object: {error:?}"))
                    })?
                }
            };
            (crate::signals::atom("port"), object)
        } else {
            let from = crate::dist::remote_pid_term(self, from)?
                .or_else(|| from.to_term())
                .ok_or_else(|| VmError::Unsupported("invalid monitor sender pid".into()))?;
            (
                crate::signals::atom("process"),
                crate::signals::monitor_object(self, name.as_deref(), from)?,
            )
        };
        let tuple = self.tuple(&[tag, reference, from_type, from, reason])?;
        if priority {
            self.push_priority_message(tuple)?;
        } else {
            self.inbox.push_back(tuple);
        }
        Ok(())
    }
}

// Port of erts/emulator/beam/beam_common.c:685 (terminate_proc) and
// erts/emulator/beam/utils.c:802 (do_send_logger_message), OTP-29.1.1.
/// Builds the DOWN message on the sender for a non-immediate reason (erts
/// erl_proc_sig_queue.c:2880-2900, the `else` branch of erts_proc_sig_send_monitor_down): the tuple
/// `{Tag, Ref, process, Object, Reason}` is built on the exiting process and copied once.
pub(super) fn down_message_on_sender(
    process: &mut Process,
    reference: u64,
    data: &crate::proc_create::MonitorInfo,
    target: Pid,
    reason: Term,
) -> Result<Message, VmError> {
    let tag = match data.tag() {
        Some(owned) => {
            let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
            arinsal_term::from_owned(owned, &mut heap)
                .map_err(|error| VmError::Unsupported(format!("monitor tag: {error:?}")))?
        }
        None => crate::signals::atom("DOWN"),
    };
    let reference_term = crate::signals::reference(process, reference)?;
    let from = target
        .to_term()
        .ok_or_else(|| VmError::Unsupported("invalid monitor target pid".into()))?;
    let object = crate::signals::monitor_object(process, data.name(), from)?;
    let tuple = {
        let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
        arinsal_term::TermBuilder::new(&mut heap)
            .tuple(&[
                tag,
                reference_term,
                crate::signals::atom("process"),
                object,
                reason,
            ])
            .map_err(|error| VmError::Unsupported(format!("DOWN tuple: {error:?}")))?
    };
    Message::copy_from(tuple)
}
