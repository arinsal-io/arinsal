use super::*;

/// A sender-owned copy that can cross scheduler threads without accessing the
/// destination process heap.
pub struct Message {
    pub(super) term: Term,
    pub(super) fragment: Option<MessageFragmentBox>,
    /// When set, the receiver inserts this into the priority section of its
    /// private message queue (OTP 28+ priority messages).
    pub(super) priority: bool,
    /// The port connected handshake traces receipt before unblocking the recipient.
    pub(super) receive_traced: bool,
    /// Sent by a process without a seq_trace token (`ERL_MESSAGE_TOKEN == NIL`).
    pub(super) seq_nil: bool,
    /// The alias the message was sent through, 0 for none (checked when it is handled).
    pub(super) alias: u64,
    /// The data is in the heap fragment inline in this message's own node
    /// (`data.attached == ERTS_MSG_COMBINED_HFRAG`).
    pub(super) combined: bool,
}

/// What the sender knows about a message beyond its term: the sequential trace token state
/// and the alias it was sent through.
#[derive(Default)]
pub(super) struct SendMeta {
    pub(super) seq: crate::seq_trace::SeqState,
    pub(super) alias: u64,
}

pub(super) struct MessageFragment {
    pub(super) heap: Option<arinsal_term::message::MessageHeap>,
    pub(super) seq_token: Option<Box<crate::seq_trace::Token>>,
    /// The VM timer id a timer-sent message carries until delivery, so expiry and cancellation
    /// release its message; kept here, not in `Message`, so the common message stays small.
    pub(super) timer_id: Option<u64>,
}

/// A message's fragment: an ordinary box, or for a timer message a `BIF_TIMER` fixed-size
/// block (`ERTS_ALC_T_BIF_TIMER`) that has a fix list of its own and never shares one with the
/// `PROC` blocks of another size. One word, so `Message` stays small.
pub(super) type MessageFragmentBox = arinsal_alloc::typed::FixOrBox<MessageFragment, 22>;

pub(super) fn system_fragment(fragment: MessageFragment) -> MessageFragmentBox {
    MessageFragmentBox::boxed(fragment)
}

fn timer_fragment(fragment: MessageFragment, alloc_ix: Option<usize>) -> MessageFragmentBox {
    match alloc_ix {
        Some(ix) => MessageFragmentBox::fixed_at(ix, fragment),
        None => MessageFragmentBox::fixed(fragment),
    }
    .expect("timer message fragment allocation")
}

pub(super) type RemovedMessage = (Term, crate::seq_trace::SeqState);

impl Message {
    /// A message whose term lives on the receiver's heap (sent there by
    /// `erts_try_alloc_message_on_heap`), not in its own fragment.
    fn is_heap_root(&self) -> bool {
        self.term.is_pointer()
            && !self.combined
            && self
                .fragment
                .as_ref()
                .is_none_or(|fragment| fragment.heap.is_none())
    }

    /// The copy of the sequential trace token that sits on the receiver's heap, a collection
    /// root like the message term.
    pub(super) fn append_heap_roots_mut<'a>(&'a mut self, roots: &mut arinsal_term::GcRootSet<'a>) {
        let heap_root = self.is_heap_root();
        let token_root = self
            .fragment
            .as_mut()
            .filter(|fragment| fragment.heap.is_none())
            .and_then(|fragment| fragment.seq_token.as_mut())
            .filter(|token| token.root().is_pointer())
            .map(|token| token.heap_ref_mut());
        if heap_root {
            roots.push_term(&mut self.term);
        }
        if let Some(token) = token_root {
            roots.push_term(token);
        }
    }

    /// Build a scheduler-safe message from a self-contained term snapshot.
    pub(crate) fn from_owned(term: &arinsal_etf::OwnedTerm) -> Result<Self, VmError> {
        let mut heap = ProcessHeap::with_words(4096);
        let term = arinsal_term::from_owned(term, &mut heap)
            .map_err(|error| VmError::Unsupported(format!("owned message term: {error:?}")))?;
        Self::copy_from(term)
    }

    /// Copy the reachable object graph into an envelope owned by the receiver.
    pub fn copy_from(term: Term) -> Result<Self, VmError> {
        if !term.is_pointer() {
            return Ok(Self::immediate(term));
        }
        // Port of erts/emulator/beam/erl_message.c:824 (erts_send_message),
        // OTP-29.1.1. Exact sizing keeps unused words out of long-lived
        // message fragments.
        // Literals outside the collector's purge area stay shared (copy_struct_litopt).
        let literals = arinsal_term::LiteralAreas::current();
        let words = arinsal_term::size_object_litopt(term, &literals);
        Self::copy_counted(term, words, None, &literals, None)
    }

    /// Copy a timer message into a PROC-allocated timer fragment.
    // Port of erts/emulator/beam/erl_hl_timer.c (setup_bif_timer), OTP-29.1.1.
    pub(crate) fn copy_from_timer(
        term: Term,
        timer_id: u64,
        alloc_ix: Option<usize>,
    ) -> Result<Self, VmError> {
        if !term.is_pointer() {
            let mut message = Self::immediate(term);
            message.fragment = Some(timer_fragment(
                MessageFragment {
                    heap: None,
                    seq_token: None,
                    timer_id: Some(timer_id),
                },
                alloc_ix,
            ));
            return Ok(message);
        }
        let literals = arinsal_term::LiteralAreas::current();
        let words = arinsal_term::size_object_litopt(term, &literals);
        Self::copy_counted(term, words, None, &literals, Some((timer_id, alloc_ix)))
    }

    /// `copy_from` when `words` is already `size_object_litopt(term, literals)`. A sequential
    /// trace `token` is copied into the same fragment after the message, and its words count
    /// towards the fragment size.
    // Port of erts/emulator/beam/erl_message.c (erts_send_message, seq trace): the fragment
    // holds the message and then the copied token, OTP-29.1.1.
    pub(super) fn copy_counted(
        term: Term,
        words: usize,
        token: Option<&mut crate::seq_trace::Token>,
        literals: &arinsal_term::LiteralAreas,
        timer_id: Option<(u64, Option<usize>)>,
    ) -> Result<Self, VmError> {
        let token_words = token
            .as_deref()
            .map_or(0, crate::seq_trace::Token::heap_words);
        if words + token_words == 0 {
            let mut message = Self::immediate(term);
            if let Some((timer_id, alloc_ix)) = timer_id {
                message.fragment = Some(timer_fragment(
                    MessageFragment {
                        heap: None,
                        seq_token: None,
                        timer_id: Some(timer_id),
                    },
                    alloc_ix,
                ));
            }
            return Ok(message);
        }
        let mut fragment = arinsal_term::message::MessageHeapBlock::with_words(words + token_words);
        // Size was computed by the caller; copy_struct must not walk the term again
        // (erts_send_message: size_object then copy_struct).
        let term = if words == 0 {
            term
        } else {
            copy_struct_litopt(term, &mut fragment, words, literals)
                .map_err(|error| VmError::Unsupported(format!("message copy: {error:?}")))?
        };
        if let Some(token) = token {
            let copy = token
                .build_on(&mut fragment)
                .map_err(|error| VmError::Unsupported(format!("message token copy: {error:?}")))?;
            *token.heap_ref_mut() = copy;
        }
        Ok(Self {
            term,
            fragment: Some(if let Some((timer_id, alloc_ix)) = timer_id {
                timer_fragment(
                    MessageFragment {
                        heap: Some(arinsal_term::message::MessageHeap::Heap(fragment)),
                        seq_token: None,
                        timer_id: Some(timer_id),
                    },
                    alloc_ix,
                )
            } else {
                system_fragment(MessageFragment {
                    heap: Some(arinsal_term::message::MessageHeap::Heap(fragment)),
                    seq_token: None,
                    timer_id: None,
                })
            }),
            priority: false,
            receive_traced: false,
            seq_nil: false,
            alias: 0,
            combined: false,
        })
    }

    /// The message node of a send: `erts_alloc_message(sz, &hp)` then `copy_struct` into the
    /// node's own heap fragment, so the message and its data are one allocation
    /// (`ERTS_MSG_COMBINED_HFRAG`). `words` is `size_object_litopt(term, literals)`.
    // Port of erts/emulator/beam/erl_message.c (erts_send_message) and erl_message.h
    // (erts_alloc_message), OTP-29.1.1.
    pub(super) fn node_counted(
        from: Pid,
        term: Term,
        words: usize,
        literals: &arinsal_term::LiteralAreas,
    ) -> Result<MessageNode, VmError> {
        let mut message = Self::immediate(term);
        if words == 0 {
            return Ok(arinsal_sched::OwnedSignal::new(Event {
                from,
                payload: Payload::Message(message),
            }));
        }
        message.combined = true;
        let mut node = arinsal_sched::OwnedSignal::with_heap_fragment(
            Event {
                from,
                payload: Payload::Message(message),
            },
            words,
        );
        let copied = {
            let mut fragment = node.heap_fragment().expect("inline heap fragment");
            copy_struct_litopt(term, &mut fragment, words, literals)
                .map_err(|error| VmError::Unsupported(format!("message copy: {error:?}")))?
        };
        if let Payload::Message(message) = &mut node.payload {
            message.term = copied;
        }
        Ok(node)
    }

    /// A node for a message built directly in its own inline heap fragment: the driver's
    /// `erts_factory_message_create` takes `erts_alloc_message_heap(need)`, builds the term
    /// there and keeps the combined node. `build` returns the term, or `None` when it cannot.
    // Port of erts/emulator/beam/erl_message.c (erts_factory_message_create, erts_alloc_message_heap)
    // and io.c (driver_deliver_term), OTP-29.1.1.
    pub(crate) fn node_built(
        words: usize,
        build: impl FnOnce(&mut arinsal_term::message::FragmentMut<'_>) -> Option<(Pid, Term)>,
    ) -> Option<(Pid, MessageNode)> {
        let mut message = Self::immediate(Term::NIL);
        message.combined = words != 0;
        let mut node = arinsal_sched::OwnedSignal::with_heap_fragment(
            Event {
                from: Pid::from_data(0),
                payload: Payload::Message(message),
            },
            words,
        );
        let (to, term) = build(&mut node.heap_fragment()?)?;
        node.from = to;
        if let Payload::Message(message) = &mut node.payload {
            message.term = term;
        }
        Some((to, node))
    }

    pub(super) fn immediate(term: Term) -> Self {
        Self {
            term,
            fragment: None,
            priority: false,
            receive_traced: false,
            seq_nil: false,
            alias: 0,
            combined: false,
        }
    }

    /// Build the signal envelope that the literal-copy handler will reuse as its reply.
    // Port of erts/emulator/beam/beam_bif_load.c:1750-1787 (`erts_proc_sig_send_cla_request`), OTP-29.1.1.
    pub(crate) fn literal_copy_request(
        area: Term,
        how: arinsal_sched::LiteralCopyHow,
        target: Pid,
    ) -> Result<Self, VmError> {
        let target = target
            .to_term()
            .ok_or_else(|| VmError::Unsupported("invalid literal-copy target pid".into()))?;
        let mut heap = arinsal_term::message::MessageHeapBlock::with_words(
            size_object(area).saturating_add(8),
        );
        let area = copy_term(area, &mut heap)
            .map_err(|error| VmError::Unsupported(format!("literal-copy area: {error:?}")))?;
        let request = TermBuilder::new(&mut heap)
            .tuple(&[
                area,
                crate::signals::atom(match how {
                    arinsal_sched::LiteralCopyHow::Init => "init",
                    arinsal_sched::LiteralCopyHow::CheckGc => "check_gc",
                    arinsal_sched::LiteralCopyHow::NeedGc => "need_gc",
                }),
                target,
            ])
            .map_err(|error| VmError::Unsupported(format!("literal-copy request: {error:?}")))?;
        Ok(Self {
            term: request,
            fragment: Some(system_fragment(MessageFragment {
                heap: Some(arinsal_term::message::MessageHeap::Heap(heap)),
                seq_token: None,
                timer_id: None,
            })),
            priority: false,
            receive_traced: false,
            seq_nil: false,
            alias: 0,
            combined: false,
        })
    }

    /// Append the collector reply to its original request fragment.
    // Port of erts/emulator/beam/erl_proc_sig_queue.c:8083 (`send_cla_reply`), OTP-29.1.1.
    pub(crate) fn literal_copy_reply(mut self, result: Term) -> Result<Self, VmError> {
        let Some(arinsal_term::message::MessageHeap::Heap(heap)) = self
            .fragment
            .as_mut()
            .and_then(|fragment| fragment.heap.as_mut())
        else {
            return Err(VmError::Unsupported(
                "literal-copy request lost its heap fragment".into(),
            ));
        };
        self.term = TermBuilder::new(heap)
            .tuple(&[crate::signals::atom("copy_literals"), self.term, result])
            .map_err(|error| VmError::Unsupported(format!("literal-copy reply: {error:?}")))?;
        Ok(self)
    }

    /// Mark this envelope for priority insertion at the receiver.
    pub(crate) fn with_priority(mut self) -> Self {
        self.priority = true;
        self
    }

    pub(crate) fn with_receive_traced(mut self) -> Self {
        self.receive_traced = true;
        self
    }

    /// The VM timer id this message carries, if it was sent by a timer.
    pub(super) fn timer_id(&self) -> Option<u64> {
        self.fragment
            .as_ref()
            .and_then(|fragment| fragment.timer_id)
    }

    pub(crate) fn is_priority(&self) -> bool {
        self.priority
    }

    /// A priority message or one sent through an alias: an `ERTS_SIG_Q_OP_ALTACT_MSG` signal
    /// that is handled, not spliced into the message queue, when the outer queue is fetched.
    pub(crate) fn is_altact_msg(&self) -> bool {
        self.priority || self.alias != 0
    }

    /// The seq_trace token the sender attached, if any.
    pub(crate) fn take_seq_token(&mut self) -> Option<Box<crate::seq_trace::Token>> {
        self.fragment
            .as_mut()
            .and_then(|fragment| fragment.seq_token.take())
    }

    /// Record what the sender's token state was.
    pub(crate) fn apply_seq_state(&mut self, state: crate::seq_trace::SeqState) {
        match state {
            crate::seq_trace::SeqState::Undefined => {}
            crate::seq_trace::SeqState::Nil => self.seq_nil = true,
            crate::seq_trace::SeqState::Token(token) => self.attach_seq_token(token),
        }
    }

    pub(crate) fn attach_seq_token(&mut self, token: Box<crate::seq_trace::Token>) {
        if let Some(fragment) = self.fragment.as_mut() {
            fragment.seq_token = Some(token);
        } else {
            self.fragment = Some(system_fragment(MessageFragment {
                heap: None,
                seq_token: Some(token),
                timer_id: None,
            }));
        }
    }

    pub(crate) fn into_receiver(self, process: &mut Process) -> Result<Term, VmError> {
        debug_assert!(
            !self.combined,
            "a message with inline data stays in its node"
        );
        if self.fragment.is_none() {
            // Immediate, literal, or already placed on this heap
            // (erl_message.c:657, `attached == NULL`).
            return Ok(self.term);
        }
        if process.message_queue_data() == MessageQueueData::OnHeap || process.heap.is_detached() {
            // Port of erts/emulator/beam/erl_message.c:943 (copy_message), OTP-29.1.1.
            // The receiver owns its process lock while draining, so queued terms
            // can be copied directly into its managed heap.
            let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
            let term = if self
                .fragment
                .as_ref()
                .is_some_and(|fragment| fragment.heap.is_some())
            {
                arinsal_term::copy_term_litopt(
                    self.term,
                    &mut heap,
                    &arinsal_term::LiteralAreas::current(),
                )
            } else {
                Ok(self.term)
            };
            return term
                .map_err(|error| VmError::Unsupported(format!("on-heap message copy: {error:?}")));
        }
        if let Some(mut fragment) = self.fragment
            && let Some(heap_fragment) = fragment.heap.take()
        {
            process
                .heap
                .adopt_message_heap(heap_fragment)
                .map_err(|error| {
                    VmError::Unsupported(format!("message fragment adoption: {error:?}"))
                })?;
        }
        Ok(self.term)
    }

    /// Install this envelope on `process` and return the term now rooted there.
    pub(crate) fn decode_into(self, process: &mut Process) -> Result<Term, VmError> {
        self.into_receiver(process)
    }
}

impl arinsal_sched::SignalMessage for Message {
    type MonitorData = crate::proc_create::ProcessMonitorData;
    fn is_altact_msg(&self) -> bool {
        self.priority || self.alias != 0
    }
    fn timer_ref_key(&self) -> Option<u64> {
        self.timer_id()
    }

    /// The monitor and demonitor signals are the monitor halves' own nodes, in the data both
    /// halves share (erl_proc_sig_queue.c, erts_proc_sig_send_monitor and
    /// erts_proc_sig_send_demonitor queue the `ErtsMonitor` itself), so they allocate nothing.
    fn signal_node(
        from: Pid,
        signal: arinsal_sched::Signal<Self>,
    ) -> arinsal_sched::OwnedSignal<Event<Self>> {
        use crate::proc_create::ProcessMonitorData;
        if let arinsal_sched::Signal::Link { priority } = signal {
            return ProcessMonitorData::link_signal(
                crate::proc_create::process_link(from, priority),
                arinsal_sched::lazy_link_meta(from),
            );
        }
        if let arinsal_sched::Signal::Unlink(id) = signal {
            return crate::monitor_link::UnlinkOp::signal::<
                crate::proc_create::MonitorInfo,
                crate::proc_create::OriginMonitor,
                Event<Message>,
            >(from, id, false);
        }
        if let arinsal_sched::Signal::UnlinkAckSignal(id) = signal {
            return crate::monitor_link::UnlinkOp::signal::<
                crate::proc_create::MonitorInfo,
                crate::proc_create::OriginMonitor,
                Event<Message>,
            >(from, id, true);
        }
        // A half stands for the signal only when the signal is what the half says: sent by the
        // origin, with the monitor's own reference.
        match signal {
            arinsal_sched::Signal::Monitor { reference, shared }
                if shared.origin_id() == from.data() && shared.reference() == reference =>
            {
                match ProcessMonitorData::half_signal(
                    shared,
                    true,
                    arinsal_sched::lazy_meta(from, true),
                ) {
                    Ok(node) => node,
                    Err(shared) => arinsal_sched::OwnedSignal::new(Event {
                        from,
                        payload: Payload::Signal(arinsal_sched::Signal::Monitor {
                            reference,
                            shared,
                        }),
                    }),
                }
            }
            arinsal_sched::Signal::DemonitorOrigin(shared) => {
                let shared = if shared.origin_id() == from.data() {
                    match ProcessMonitorData::half_signal(
                        shared,
                        false,
                        arinsal_sched::lazy_meta(from, false),
                    ) {
                        Ok(node) => return node,
                        Err(shared) => shared,
                    }
                } else {
                    shared
                };
                arinsal_sched::OwnedSignal::new(Event {
                    from,
                    payload: Payload::Signal(arinsal_sched::Signal::DemonitorOrigin(shared)),
                })
            }
            signal => arinsal_sched::OwnedSignal::new(Event {
                from,
                payload: Payload::Signal(signal),
            }),
        }
    }
}

impl
    crate::monitor_link::HalfSignal<
        crate::proc_create::MonitorInfo,
        crate::proc_create::OriginMonitor,
    > for Event<Message>
{
    fn from_half(
        data: arinsal_alloc::typed::FixAllocArc<crate::proc_create::ProcessMonitorData>,
        target: bool,
    ) -> Self {
        let from = Pid::from_data(data.origin_id());
        let signal = if target {
            arinsal_sched::Signal::Monitor {
                reference: data.reference(),
                shared: data,
            }
        } else {
            arinsal_sched::Signal::DemonitorOrigin(data)
        };
        Event {
            from,
            payload: Payload::Signal(signal),
        }
    }

    fn from_link_signal(header: std::ptr::NonNull<u8>) -> Self {
        let link = crate::monitor_link::Link::from_signal_header(header);
        let view = link.view();
        let from = Pid::from_data(view.other());
        let priority = view.is_priority();
        drop(link);
        Event {
            from,
            payload: Payload::Signal(arinsal_sched::Signal::Link { priority }),
        }
    }

    fn from_unlink_signal(from: Pid, id: u64, ack: bool) -> Self {
        Event {
            from,
            payload: Payload::Signal(if ack {
                arinsal_sched::Signal::UnlinkAckSignal(id)
            } else {
                arinsal_sched::Signal::Unlink(id)
            }),
        }
    }
}

impl Message {
    /// The message term for read-only inspection while it waits in a timer.
    pub(crate) fn term(&self) -> Term {
        self.term
    }
}
