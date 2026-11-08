use super::*;

/// A term already measured by `size_object_litopt` against `literals`.
#[derive(Clone, Copy)]
struct CountedSend<'a> {
    value: Term,
    words: usize,
    /// Words of the sequential trace token copied after the message, 0 without a token.
    token_words: usize,
    literals: &'a arinsal_term::LiteralAreas,
}

/// Allocate `value` on `receiver`'s young heap when `erts_try_alloc_message_on_heap` would.
///
/// `Ok(None)` means the caller should build a heap fragment. The seq-trace token
/// stays with the caller in that case.
fn message_on_receiver_heap(
    receiver: &mut Process,
    counted: CountedSend<'_>,
    priority: bool,
    seq_token: &mut SendMeta,
) -> Result<Option<Message>, VmError> {
    let CountedSend {
        value,
        words,
        token_words,
        literals,
    } = counted;
    let total_words = words + token_words;
    if total_words == 0
        || receiver.message_queue_data() != MessageQueueData::OnHeap
        || !receiver.heap.gc_enabled
        || receiver.heap.is_detached()
    {
        return Ok(None);
    }
    // erl_message.c:640: `HEAP_LIMIT - HEAP_TOP <= sz` uses a fragment.
    // One word stricter than `HAlloc`'s `HeapWordsLeft < sz`. Does not grow the heap.
    let Some(left) = receiver.heap.halloc_words_left() else {
        return Ok(None);
    };
    if left <= total_words {
        return Ok(None);
    }
    let term = if words == 0 {
        value
    } else {
        match copy_struct_litopt(value, &mut receiver.heap, words, literals) {
            Ok(term) => term,
            Err(arinsal_term::TermError::HeapFull) => return Ok(None),
            Err(error) => {
                return Err(VmError::Unsupported(format!("message copy: {error:?}")));
            }
        }
    };
    if let crate::seq_trace::SeqState::Token(token) = &mut seq_token.seq {
        match token.build_on(&mut arinsal_bifs::ProcessHeapHandle(&mut receiver.heap)) {
            Ok(copy) => *token.heap_ref_mut() = copy,
            Err(arinsal_term::TermError::HeapFull) => return Ok(None),
            Err(error) => {
                return Err(VmError::Unsupported(format!(
                    "message token copy: {error:?}"
                )));
            }
        }
    }
    let mut envelope = Message {
        term,
        fragment: None,
        priority: false,
        receive_traced: false,
        seq_nil: false,
        alias: 0,
        combined: false,
    };
    if priority {
        envelope = envelope.with_priority();
    }
    envelope.apply_seq_state(std::mem::take(&mut seq_token.seq));
    envelope.alias = seq_token.alias;
    Ok(Some(envelope))
}

/// Words of a sent message that cost one reduction of the sender.
///
/// Port of erts/emulator/beam/erl_message.h:33-35 (ERTS_MSG_COPY_WORDS_PER_REDUCTION), OTP-29.1.1.
pub(crate) const ERTS_MSG_COPY_WORDS_PER_REDUCTION: usize = 64;

/// Error text of a remote send attempted without a scheduler context (native code).
pub(crate) const REMOTE_SEND_NEEDS_CONTEXT: &str = "remote send requires a scheduler context";

impl Process {
    /// Place `value` on a waiting on-heap receiver and queue it before the main lock drops.
    ///
    /// Port of erts/emulator/beam/erl_message.c:621 (`erts_try_alloc_message_on_heap`)
    /// and erl_process.h:2878 (`erts_alloc_message_heap_state`), OTP-29.1.1.
    /// `Ok(false)` keeps the existing heap-fragment copy.
    #[allow(clippy::too_many_arguments)] // erts passes the scheduler data as one more.
    fn try_send_on_receiver_heap(
        &self,
        ctx: Option<&mut RunCtx<'_, Message>>,
        from: Pid,
        to: Pid,
        counted: CountedSend<'_>,
        priority: bool,
        seq_token: &mut SendMeta,
        handle: Option<&arinsal_sched::NativeHandle<Message>>,
    ) -> Result<bool, VmError> {
        if counted.words + counted.token_words == 0 {
            return Ok(false);
        }
        if ctx.is_none()
            && let Some(handle) = handle
        {
            let mut failure = None;
            let native = handle.try_send_on_heap(from, to, &mut |task: &mut dyn std::any::Any| {
                let receiver = task.downcast_mut::<Process>()?;
                match message_on_receiver_heap(receiver, counted, priority, seq_token) {
                    Ok(envelope) => envelope,
                    Err(error) => {
                        failure = Some(error);
                        None
                    }
                }
            });
            if let Some(error) = failure {
                return Err(error);
            }
            match native {
                Some(
                    arinsal_sched::OnHeapSend::Unavailable | arinsal_sched::OnHeapSend::Declined,
                ) => return Ok(false),
                Some(arinsal_sched::OnHeapSend::Queued) => return Ok(true),
                Some(arinsal_sched::OnHeapSend::Failed(error)) => {
                    return Err(VmError::Unsupported(format!("send: {error}")));
                }
                None => {}
            }
        }
        let Some(runtime) = self.runtime.as_ref() else {
            return Ok(false);
        };
        let Ok(scheduler) = runtime.scheduler() else {
            return Ok(false);
        };
        if let Some(ctx) = ctx {
            return match scheduler.try_with_task(to, |receiver| {
                let Some(envelope) =
                    message_on_receiver_heap(receiver, counted, priority, seq_token)?
                else {
                    return Ok(false);
                };
                let delivered = ctx.send(to, envelope);
                // A queued target buffers on this worker. Publish before the lock drops
                // so the term is in the signal queue while it still lives on that heap.
                ctx.flush_pending();
                match delivered {
                    Ok(()) | Err(arinsal_sched::Error::NoProcess) => Ok(true),
                    Err(error) => Err(VmError::Unsupported(format!("send: {error}"))),
                }
            }) {
                Some(result) => result,
                None => Ok(false),
            };
        }
        match scheduler.try_send_on_heap(from, to, |receiver| {
            message_on_receiver_heap(receiver, counted, priority, seq_token)
        })? {
            arinsal_sched::OnHeapSend::Unavailable | arinsal_sched::OnHeapSend::Declined => {
                Ok(false)
            }
            arinsal_sched::OnHeapSend::Queued => Ok(true),
            arinsal_sched::OnHeapSend::Failed(error) => {
                Err(VmError::Unsupported(format!("send: {error}")))
            }
        }
    }

    pub(crate) fn send_message(&mut self, target: Term, value: Term) -> Result<Term, VmError> {
        self.send_message_inner(None, target, value)
    }

    pub(crate) fn send_message_with_vm(
        &mut self,
        vm: &mut Vm,
        target: Term,
        value: Term,
    ) -> Result<Term, VmError> {
        self.send_message_inner(Some(vm), target, value)
    }

    fn send_message_inner(
        &mut self,
        vm: Option<&mut Vm>,
        target: Term,
        value: Term,
    ) -> Result<Term, VmError> {
        self.send_message_prio(vm, None, target, value, false)
    }

    /// Send from a running process: the scheduler context delivers the message (and its
    /// trace events) on the sender's worker, like erts' `erts_send_message`.
    pub(crate) fn send_message_in(
        &mut self,
        vm: &mut Vm,
        ctx: &mut RunCtx<'_, Message>,
        target: Term,
        value: Term,
    ) -> Result<Term, VmError> {
        self.send_message_prio(Some(vm), Some(ctx), target, value, false)
    }

    fn trace_send(
        &mut self,
        vm: Option<&mut Vm>,
        ctx: Option<&mut RunCtx<'_, Message>>,
        sender: Pid,
        event: &str,
        value: Term,
        target: Term,
    ) {
        match ctx {
            Some(ctx) => crate::trace::emit(
                vm,
                self,
                ctx,
                sender,
                crate::trace::SEND,
                event,
                &[value, target],
            ),
            None => crate::trace::emit_process(
                vm,
                self,
                sender,
                crate::trace::SEND,
                event,
                &[value, target],
            ),
        }
    }

    /// Send with an optional OTP 28+ `[priority]` request.
    // Port of erts/emulator/beam/erl_message.c / bif.c send with priority, OTP-29.1.1.
    pub(crate) fn send_message_prio(
        &mut self,
        vm: Option<&mut Vm>,
        ctx: Option<&mut RunCtx<'_, Message>>,
        target: Term,
        value: Term,
        want_priority: bool,
    ) -> Result<Term, VmError> {
        self.send_resolved(vm, ctx, target, value, want_priority, false)
    }

    /// `Name ! Msg` from native code. A registered port is redone by the scheduler,
    /// which can suspend the sender; the name is resolved once either way.
    pub(crate) fn send_message_native(
        &mut self,
        target: Term,
        value: Term,
    ) -> Result<Term, VmError> {
        self.send_resolved(None, None, target, value, false, true)
    }

    fn send_resolved(
        &mut self,
        mut vm: Option<&mut Vm>,
        mut ctx: Option<&mut RunCtx<'_, Message>>,
        target: Term,
        value: Term,
        want_priority: bool,
        defer_port: bool,
    ) -> Result<Term, VmError> {
        let sender = self
            .self_pid
            .ok_or_else(|| VmError::Unsupported("send requires a scheduled process".into()))?;
        if target.as_port().is_some() {
            crate::trace::emit_process(
                vm.as_deref_mut(),
                self,
                sender,
                crate::trace::SEND,
                "send",
                &[value, target],
            );
            if let Some(ctx) = ctx.as_deref_mut() {
                crate::port::process_send_in(self, ctx, target, value)?;
            } else {
                crate::port::process_send(self, target, value)?;
            }
            return Ok(value);
        }
        // Port of erts/emulator/beam/bif.c:2469-2480,2511 (do_send), OTP-29.1.1: internal pids
        // and atoms are local destinations and never reach the distribution checks.
        let local_destination = target.as_pid_data().is_some() || target.as_atom().is_some();
        // Port of erts/emulator/beam/erl_message.c (`erts_send` / remote_send), OTP-29.1.1.
        let remote = match ctx.as_deref_mut() {
            _ if local_destination => false,
            Some(ctx) => crate::dist::try_remote_send(self, ctx, target, value)?,
            // Native code sends without a scheduler context; a remote send is redone by the
            // scheduler, which owns the distribution output path.
            None if crate::dist::is_remote_target(target)? => {
                return Err(VmError::Unsupported(REMOTE_SEND_NEEDS_CONTEXT.into()));
            }
            None => false,
        };
        if remote {
            crate::trace::emit_process(
                vm.as_deref_mut(),
                self,
                sender,
                crate::trace::SEND,
                "send",
                &[value, target],
            );
            return Ok(value);
        }
        let local_name = if local_destination {
            None
        } else {
            crate::dist::local_reg_name(target)?
        };
        let local_name_tuple = local_name.is_some();
        let target = if let Some(name) = local_name {
            name
        } else {
            target
        };
        let mut via_prio_alias = false;
        let mut via_alias = 0u64;
        let pid = if let Some(pid) = Pid::from_term(target) {
            Some(pid)
        } else if let Some(id) = crate::signals::ref_id(target) {
            let known = self
                .runtime
                .as_ref()
                .and_then(|runtime| runtime.alias_lookup_prio(id));
            match known {
                Some((Some(pid), alias_prio)) => {
                    via_prio_alias = alias_prio && want_priority;
                    via_alias = id;
                    Some(pid)
                }
                Some((None, _)) => return Ok(value),
                None => {
                    return Err(VmError::Trap(crate::exceptions::Trap::error(
                        crate::signals::atom("badarg"),
                    )));
                }
            }
        } else if let Some(name) = target.as_atom() {
            let runtime = self
                .runtime
                .as_ref()
                .ok_or_else(|| VmError::Unsupported("send requires a scheduler".into()))?;
            // Port of erts/emulator/beam/bif.c (`ebif_bang_2` -> `erts_whereis_name`), OTP-29.1.1:
            // one atom-index lookup yields the process or the port.
            let pid = match runtime.reg.whereis(name) {
                // Port of erts/emulator/beam/bif.c:2506-2519 (do_send): one
                // whereis, then one raw process-table lookup. An exiting
                // process is not a destination (erts_whereis_name's alive test).
                Some(crate::register::RegId::Proc(pid))
                    if runtime
                        .scheduler()?
                        .with_proc_flags(pid, |flags| {
                            flags.load(Ordering::Acquire) & proc_flags::EXITING == 0
                        })
                        .unwrap_or(false) =>
                {
                    Some(pid)
                }
                Some(crate::register::RegId::Port(id)) if crate::port::is_live(self, id) => {
                    if defer_port {
                        return Err(VmError::Unsupported(REMOTE_SEND_NEEDS_CONTEXT.into()));
                    }
                    let port = Term::port(id).ok_or_else(|| {
                        VmError::Trap(crate::exceptions::Trap::error(crate::signals::atom(
                            "badarg",
                        )))
                    })?;
                    if let Some(ctx) = ctx.as_deref_mut() {
                        crate::port::process_send_in(self, ctx, port, value)?;
                    } else {
                        crate::port::process_send(self, port, value)?;
                    }
                    crate::trace::emit_process(
                        vm.as_deref_mut(),
                        self,
                        sender,
                        crate::trace::SEND,
                        "send",
                        &[value, target],
                    );
                    return Ok(value);
                }
                _ => None,
            };
            if pid.is_none() {
                // Port of erts/emulator/beam/bif.c:2532-2536 (do_send), OTP-29.1.1: a send to
                // an unregistered name is traced before it fails.
                self.trace_send(
                    vm.as_deref_mut(),
                    ctx.as_deref_mut(),
                    sender,
                    "send",
                    value,
                    target,
                );
                // Port of erts/emulator/beam/dist.c (`erts_send` registered-name handling), OTP-29.1.1.
                // A local {Name, Node} send silently drops the message when Name is absent.
                if local_name_tuple {
                    return Ok(value);
                }
            }
            pid
        } else {
            return Err(VmError::Trap(crate::exceptions::Trap::error(
                crate::signals::atom("badarg"),
            )));
        };
        let pid = pid.ok_or_else(|| {
            VmError::Trap(crate::exceptions::Trap::error(crate::signals::atom(
                "badarg",
            )))
        })?;
        // Port of erts/emulator/beam/erl_trace.c:824-832 (trace_send), OTP-29.1.1.
        let hooked = !crate::trace::send_hooks_idle(self);
        let event = if hooked
            && crate::trace::active()
            && self
                .runtime
                .as_ref()
                .and_then(|runtime| runtime.scheduler().ok())
                .is_some_and(|scheduler| !scheduler.lookup(pid))
        {
            "send_to_non_existing_process"
        } else {
            "send"
        };
        if hooked {
            self.trace_send(
                vm.as_deref_mut(),
                ctx.as_deref_mut(),
                sender,
                event,
                value,
                target,
            );
        }
        let seq_token = SendMeta {
            alias: via_alias,
            seq: if hooked && crate::seq_trace::has_token(self) {
                let state = {
                    // Port of erts/emulator/beam/erl_message.c:753-755, OTP-29.1.1: the event names the
                    // receiving process by pid, whatever name the sender used; an alias stays the alias.
                    let seq_receiver = if target.as_atom().is_some()
                        || target.classify() == arinsal_term::TermKind::Tuple
                    {
                        pid.to_term().unwrap_or(target)
                    } else {
                        target
                    };
                    crate::seq_trace::on_send(
                        vm,
                        self,
                        ctx.as_deref_mut(),
                        sender,
                        seq_receiver,
                        value,
                    )
                };
                state.map_or(crate::seq_trace::SeqState::Nil, |token| {
                    crate::seq_trace::SeqState::Token(token)
                })
            } else {
                crate::seq_trace::SeqState::Nil
            },
        };
        self.send_counted(ctx, sender, pid, value, via_prio_alias, seq_token)
    }

    /// `Pid ! Msg` from native code for a sender with no trace hooks (see
    /// `trace::send_hooks_idle`) and an internal pid as the destination: no destination
    /// resolution, no trace or token work.
    // Port of erts/emulator/beam/bif.c (do_send) and erl_message.c (erts_send_message), OTP-29.1.1.
    pub(crate) fn send_to_pid_idle(&mut self, pid: Pid, value: Term) -> Result<Term, VmError> {
        let sender = self
            .self_pid
            .ok_or_else(|| VmError::Unsupported("send requires a scheduled process".into()))?;
        // A sender without a token sends `Nil`: the message clears a token its receiver holds.
        let seq_token = SendMeta {
            alias: 0,
            seq: crate::seq_trace::SeqState::Nil,
        };
        self.send_counted(None, sender, pid, value, false, seq_token)
    }

    /// The part of a local send after the destination and the trace hooks are settled: size
    /// the term once, try the receiver's heap, else queue a copy.
    // Port of erts/emulator/beam/erl_message.c (erts_send_message from the size computation on),
    // OTP-29.1.1.
    /// A message envelope in a node of its own.
    fn message_node(from: Pid, envelope: Message) -> MessageNode {
        arinsal_sched::OwnedSignal::new(Event {
            from,
            payload: Payload::Message(envelope),
        })
    }

    fn send_counted(
        &mut self,
        mut ctx: Option<&mut RunCtx<'_, Message>>,
        sender: Pid,
        pid: Pid,
        value: Term,
        via_prio_alias: bool,
        mut seq_token: SendMeta,
    ) -> Result<Term, VmError> {
        // Port of erts/emulator/beam/erl_message.c (erts_send_message), OTP-29.1.1: a process
        // that sends to itself, with no sequential trace token and an on-heap message queue,
        // queues the term itself. It is neither sized nor copied, and no reductions are bumped
        // for its size.
        let shares_own_term = pid == sender
            && matches!(seq_token.seq, crate::seq_trace::SeqState::Nil)
            && self.message_queue_data() == MessageQueueData::OnHeap;
        let mut on_own_heap = shares_own_term;
        // Port of erts/emulator/beam/erl_process.h (erts_get_scheduler_data), OTP-29.1.1: the
        // scheduler data is read once per send and serves both the heap attempt and the node.
        let native = if ctx.is_none() && pid != sender {
            self.native_handle()
        } else {
            None
        };
        let (envelope, words) = if shares_own_term {
            let mut envelope = Message::immediate(value);
            if via_prio_alias {
                envelope = envelope.with_priority();
            }
            envelope.apply_seq_state(std::mem::take(&mut seq_token.seq));
            envelope.alias = seq_token.alias;
            (Self::message_node(sender, envelope), 0)
        } else {
            // Size once. The on-heap attempt and the fragment fallback both consume it
            // (erts_send_message: size_object_litopt, then alloc, then copy_struct_litopt).
            let literals = arinsal_term::LiteralAreas::current();
            let words = if value.is_pointer() {
                arinsal_term::size_object_litopt(value, &literals)
            } else {
                0
            };
            let token = match &seq_token.seq {
                crate::seq_trace::SeqState::Token(token) => Some(token.as_ref()),
                _ => None,
            };
            let token_words = token.map_or(0, crate::seq_trace::Token::heap_words);
            let counted = CountedSend {
                value,
                words,
                token_words,
                literals: &literals,
            };
            let mut on_heap = None;
            if pid == sender {
                // Port of erts/emulator/beam/erl_message.c (erts_try_alloc_message_on_heap),
                // OTP-29.1.1: a process that sends to itself holds its own main lock, so the
                // message and its token are allocated on its own young heap when they fit.
                on_heap = message_on_receiver_heap(self, counted, via_prio_alias, &mut seq_token)?;
                on_own_heap = on_heap.is_some();
            } else if self.try_send_on_receiver_heap(
                ctx.as_deref_mut(),
                sender,
                pid,
                counted,
                via_prio_alias,
                &mut seq_token,
                native.as_ref(),
            )? {
                self.bump_send_reds(ctx.as_deref_mut(), pid == sender, words);
                return Ok(value);
            }
            let node = if let Some(envelope) = on_heap {
                Self::message_node(sender, envelope)
            } else if let crate::seq_trace::SeqState::Token(token) = &mut seq_token.seq {
                let mut envelope =
                    Message::copy_counted(value, words, Some(token.as_mut()), &literals, None)?;
                if via_prio_alias {
                    envelope = envelope.with_priority();
                }
                envelope.apply_seq_state(std::mem::take(&mut seq_token.seq));
                envelope.alias = seq_token.alias;
                Self::message_node(sender, envelope)
            } else {
                // Port of erts/emulator/beam/erl_message.c (erts_send_message): the message
                // and its data in one allocation.
                let mut node = Message::node_counted(sender, value, words, &literals)?;
                if let Payload::Message(envelope) = &mut node.payload {
                    envelope.priority = via_prio_alias;
                    envelope.apply_seq_state(std::mem::take(&mut seq_token.seq));
                    envelope.alias = seq_token.alias;
                }
                node
            };
            (node, words)
        };
        let node = envelope;
        let delivered = match ctx.as_deref_mut() {
            Some(ctx) => {
                let shared = on_own_heap && value.is_pointer();
                let delivered = if pid == sender {
                    ctx.send_self_node(node)
                } else {
                    ctx.send_node(pid, node)
                };
                // A buffered message names a term on this heap. Publish it before anything
                // can collect, so the signal queue holds it as a root.
                if shared {
                    ctx.flush_pending();
                }
                delivered
            }
            // Port of erts/emulator/beam/erl_message.c:698 (erts_send_message from a BIF called
            // by JIT code, with the scheduler data of the calling scheduler), OTP-29.1.1. A
            // process sending to itself is running: erts_proc_notify_new_message
            // (erl_proc_sig_queue.h:2080) schedules nothing, so no run queue is needed.
            None => {
                if pid == sender
                    && let Some(probe) = self.signal_probe()
                {
                    probe.send_self_node(pid, node)
                } else {
                    match match (&native, pid == sender) {
                        (Some(handle), false) => handle.send_node(pid, node),
                        _ => Err(node),
                    } {
                        Ok(delivered) => delivered,
                        Err(node) => self
                            .runtime
                            .as_ref()
                            .ok_or_else(|| {
                                VmError::Unsupported("send requires a scheduler".into())
                            })?
                            .scheduler()?
                            .send_node(pid, node),
                    }
                }
            }
        };
        match delivered {
            Ok(()) | Err(arinsal_sched::Error::NoProcess) => {
                self.bump_send_reds(ctx, pid == sender, words);
                Ok(value)
            }
            Err(error) => Err(VmError::Unsupported(format!("send: {error}"))),
        }
    }

    /// Charge the sender one reduction per `ERTS_MSG_COPY_WORDS_PER_REDUCTION` words copied,
    /// at most one slice. A process sending to itself with an on-heap queue copies nothing.
    // Port of erts/emulator/beam/erl_message.c (erts_send_message, the `BUMP_REDS` after
    // `erts_queue_proc_message`), OTP-29.1.1.
    /// A new reference id from the running scheduler's counter, through the process.
    // Port of erts/emulator/beam/erl_bif_unique.h:170-177 (erts_sched_make_ref_in_array with
    // `esdp = erts_proc_sched_data(c_p)`), OTP-29.1.1: no thread lookup. A process that has not
    // been scheduled yet falls back to the thread's counters.
    #[inline]
    pub(crate) fn next_ref(&self) -> u64 {
        match self.scheduler_ref_state {
            Some(state) => state.bump_ref(),
            None => arinsal_bifs::next_ref_id(),
        }
    }

    /// The running scheduler's native sender: one thread-local read for the first use in a run,
    /// none after.
    // Port of erts/emulator/beam/erl_process.h (ERTS_PROC_GET_SCHDATA: `c_p->scheduler_data`),
    // OTP-29.1.1: a BIF reaches the scheduler through its process, not through the thread.
    pub(crate) fn native_handle(&mut self) -> Option<arinsal_sched::NativeHandle<Message>> {
        if self.native.is_none() {
            self.native = arinsal_sched::native_handle::<Message>();
        }
        self.native.clone()
    }

    fn bump_send_reds(
        &mut self,
        ctx: Option<&mut RunCtx<'_, Message>>,
        to_self: bool,
        words: usize,
    ) {
        if to_self
            && self.message_queue_data() != MessageQueueData::OffHeap
            && !crate::seq_trace::has_token(self)
        {
            return;
        }
        if words <= ERTS_MSG_COPY_WORDS_PER_REDUCTION {
            return;
        }
        let reds = (words / ERTS_MSG_COPY_WORDS_PER_REDUCTION).min(CONTEXT_REDS as usize) as i32;
        let applied = reds.min(self.heap.abi.fcalls.max(0));
        self.heap.abi.fcalls -= applied;
        if self.heap.native_active() {
            return;
        }
        self.reductions_used = self.reductions_used.saturating_add(applied as u64);
        if let Some(ctx) = ctx {
            ctx.consume(applied as u32);
        }
    }
}
