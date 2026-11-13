use super::*;

/// Which part of a queued message a collection root stands for.
#[derive(Clone, Copy)]
pub(crate) struct RootSlot {
    entry: usize,
    token: bool,
}

/// The message queue (the inner queue of erts `ErtsSignalPrivQueues`): message nodes in
/// arrival order, each owning its data when that is not on the process heap.
///
/// Port of erts/emulator/beam/erl_proc_sig_queue.c (private message queue), OTP-29.1.1.
/// Priority messages lead, up to the prio queue's end marker (`ErtsPrioQInfo` in
/// `ProcessCold`).
#[derive(Default)]
pub(crate) struct MessageQueue {
    /// `sig_qs.first`/`last`/`save`/`mq_len`.
    pub(crate) entries: arinsal_sched::MessageQueueList<Event<Message>>,
    /// The prio queue and save-info bits of `sig_qs.flags` (see `crate::receive`).
    pub(crate) flags: u8,
}

/// A message in the message queue: the signal node it arrived in, relinked from the middle
/// queue without a copy (erl_proc_sig_queue.c, erts_proc_sig_handle_incoming moves message
/// signals onto the message queue as they are), or a node allocated for a message the process
/// built itself.
/// A `next` field of the message queue.
pub(crate) type SaveField = arinsal_sched::NextField<Event<Message>>;

pub(crate) type MessageNode = arinsal_sched::OwnedSignal<Event<Message>>;

/// The term of a message node.
pub(crate) fn queued_term(node: &MessageNode) -> Term {
    queued(node).term
}

/// The message of a message-queue node.
pub(super) fn queued(event: &Event<Message>) -> &Message {
    match &event.payload {
        Payload::Message(message) => message,
        _ => unreachable!("the message queue holds message nodes only"),
    }
}

fn queued_mut(event: &mut Event<Message>) -> &mut Message {
    match &mut event.payload {
        Payload::Message(message) => message,
        _ => unreachable!("the message queue holds message nodes only"),
    }
}

/// A message node outside the queue.
struct QueuedMessage(MessageNode);

impl QueuedMessage {
    fn node(term: Term, fragment: Option<MessageFragmentBox>, seq_nil: bool) -> MessageNode {
        let mut message = Message::immediate(term);
        message.fragment = fragment;
        message.seq_nil = seq_nil;
        arinsal_sched::OwnedSignal::new(Event {
            from: Pid::from_data(0),
            payload: Payload::Message(message),
        })
    }

    /// Move the inline data out as a fragment of its own, giving back the message in a node
    /// without data (erts_shrink_message to a message reference after
    /// erts_proc_sig_move_msgs_to_heap or a literal copy moved the data).
    fn detach_inline(self) -> (MessageNode, Option<arinsal_term::message::NodeFragment>) {
        if !queued(&self.0).combined {
            return (self.0, None);
        }
        let (mut value, fragment) = self.0.split_fragment();
        queued_mut(&mut value).combined = false;
        (arinsal_sched::OwnedSignal::new(value), fragment)
    }

    /// The node released into the receiver's heap: its inline data becomes a fragment of the
    /// process (`erts_save_message_in_proc`); any other data was adopted already.
    fn save_in_process(self, heap: &mut ProcessHeap) {
        if queued(&self.0).combined
            && let Some(fragment) = self.0.into_fragment()
        {
            heap.adopt_message_node(fragment);
        }
    }
}

impl MessageQueue {
    /// Byte offset of `sig_qs.save` in the queue, for generated code.
    pub(crate) const SAVE_OFFSET: usize = std::mem::offset_of!(MessageQueue, entries)
        + arinsal_sched::MessageQueueList::<Event<Message>>::SAVE_OFFSET;

    /// Byte offset of the term of a message in its node (`offsetof(ErtsMessage, m[0])`), for
    /// generated code. The variant's place in `Payload` is a property of the type; it is
    /// read off a value, which has the layout every node has.
    pub(crate) fn node_term_offset() -> usize {
        let event = Event {
            from: Pid::from_data(0),
            payload: Payload::Message(Message::immediate(Term::NIL)),
        };
        let term = std::ptr::addr_of!(queued(&event).term) as usize;
        std::mem::offset_of!(arinsal_term::message::SignalNode<Event<Message>>, value) + term
            - std::ptr::addr_of!(event) as usize
    }

    /// Bytes the queued messages occupy: each node and its on-heap data.
    // Port of erts/emulator/beam/erl_process_dump.c:117 (erts_process_memory, the message
    // queue loop: `sizeof(ErtsMessage)` plus `erts_msg_attached_data_size`), OTP-29.1.1.
    pub(crate) fn memory_bytes(&self) -> usize {
        let node = std::mem::size_of::<arinsal_term::message::SignalNode<Event<Message>>>();
        self.entries
            .iter_with_fragments()
            .map(|(_, words)| node + words.map_or(0, std::mem::size_of_val))
            .sum()
    }

    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    /// Move the save pointer past markers to `field`.
    pub(crate) fn pass_save_to(&mut self, field: SaveField) {
        self.entries.set_save_field(field);
    }

    /// Set the save pointer to a `next` field of the queue.
    pub(crate) fn set_save_field(&mut self, field: SaveField) {
        self.entries.set_save_field(field);
    }

    /// Anchor `last` and `save` at `first` where the process block stays.
    // Port of erts/emulator/beam/erl_process.c:12723-12727 (erl_create_process), OTP-29.1.1.
    pub(crate) fn init_in_place(&mut self) {
        self.entries.init_in_place();
    }

    /// `erts_msgq_peek_msg`: the message at the save pointer.
    #[inline(always)]
    pub(crate) fn peek(&self) -> Option<&Term> {
        self.entries.peek().map(|entry| &queued(entry).term)
    }

    /// `erts_msgq_set_save_first`.
    #[inline(always)]
    pub(crate) fn set_save_first(&mut self) {
        self.entries.set_save_first();
    }

    /// `erts_msgq_set_save_next`.
    #[inline(always)]
    pub(crate) fn set_save_next(&mut self) {
        self.entries.set_save_next();
    }

    /// `erts_msgq_set_save_end`.
    #[inline(always)]
    pub(crate) fn set_save_end(&mut self) {
        self.entries.set_save_end();
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Append a process-owned term, such as a locally generated control message.
    pub(crate) fn push_back(&mut self, term: Term) {
        self.entries
            .push_back(QueuedMessage::node(term, None, false));
    }

    /// Append a message that carries a seq_trace token.
    pub(crate) fn push_back_token(&mut self, term: Term, token: Box<crate::seq_trace::Token>) {
        self.entries.push_back(QueuedMessage::node(
            term,
            Some(system_fragment(MessageFragment {
                heap: None,
                seq_token: Some(token),
                timer_id: None,
            })),
            false,
        ));
    }

    /// Append a message from a process without a token (`ERL_MESSAGE_TOKEN == NIL`).
    pub(crate) fn push_back_nil(&mut self, term: Term) {
        self.entries
            .push_back(QueuedMessage::node(term, None, true));
    }

    /// A node for a message the process built itself.
    pub(crate) fn node_for(term: Term) -> MessageNode {
        QueuedMessage::node(term, None, false)
    }

    /// The queue the outer queue is spliced onto by `erts_proc_sig_fetch__`.
    pub(crate) fn fetch_target(&mut self) -> &mut arinsal_sched::MessageQueueList<Event<Message>> {
        &mut self.entries
    }

    /// After a splice onto the end.
    pub(crate) fn spliced(&mut self) {}

    /// Link an ordinary message node at the end of the queue.
    // Port of erts/emulator/beam/erl_proc_sig_queue.c (erts_proc_sig_handle_incoming: a
    // message signal is moved onto the message queue as it is), OTP-29.1.1.
    pub(crate) fn push_message_node(&mut self, node: MessageNode) {
        debug_assert!(
            !queued(&node).priority,
            "a priority message enters the prio queue"
        );
        self.entries.push_back(node);
    }

    #[cfg(test)]
    /// Append a scheduler message while applying the active queue policy.
    // Port of erts/emulator/beam/erl_message.c:698 (erts_send_message), OTP-29.1.1.
    pub(crate) fn push_message(&mut self, message: Message) -> Result<(), VmError> {
        debug_assert!(
            !message.combined,
            "a message with inline data stays in its node"
        );
        let node = QueuedMessage::node(message.term, message.fragment, message.seq_nil);
        self.push_message_node(node);
        Ok(())
    }

    /// The last message.
    pub(crate) fn back(&self) -> Option<&Term> {
        self.entries.back().map(|entry| &queued(entry).term)
    }

    /// Whether the data of the message at the save pointer lives on the receiver's heap (no
    /// off-heap fragment holds it).
    pub(crate) fn is_on_heap_at_save(&self) -> bool {
        self.entries.peek().map(queued).is_some_and(|entry| {
            !entry.combined && entry.fragment.as_ref().is_none_or(|f| f.heap.is_none())
        })
    }

    /// The fragment words of messages whose data is inline in their node, with the message.
    fn with_inline_words(&self) -> impl Iterator<Item = (&Message, Option<&[u64]>)> {
        self.entries.iter_with_fragments().map(|(entry, words)| {
            let message = queued(entry);
            (message, words.filter(|_| message.combined))
        })
    }

    /// Words in message fragments that `process_info(total_heap_size)` counts for on-heap queues.
    // Port of erts/emulator/beam/erl_message.h (erts_msg_attached_data_size), OTP-29.1.1.
    pub(crate) fn attached_message_words(&self) -> usize {
        self.with_inline_words()
            .map(|(entry, inline)| {
                inline.map_or(0, <[u64]>::len)
                    + entry
                        .fragment
                        .as_ref()
                        .and_then(|fragment| fragment.heap.as_ref())
                        .map_or(0, arinsal_term::message::MessageHeap::message_data_size)
            })
            .fold(0, usize::saturating_add)
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = &Term> {
        self.entries.iter().map(|entry| &queued(entry).term)
    }

    /// Remove a message, transferring any off-heap fragment into the process heap.
    // Port of erts/emulator/beam/erl_proc_sig_queue.c:7142 (message receive), OTP-29.1.1.
    #[cfg(test)]
    pub(crate) fn remove_to_heap(
        &mut self,
        heap: &mut ProcessHeap,
    ) -> Result<Option<Term>, VmError> {
        let removed = self.remove_to_heap_with_token(heap)?;
        Ok(removed.map(|(term, _token)| term))
    }

    /// Unlink the head message when it carries no seq_trace token to apply to the receiver.
    /// Returns `Ok(false)` and leaves the queue untouched otherwise.
    // Port of erts/emulator/beam/erl_proc_sig_queue.h (erts_msgq_unlink_msg_set_save_first for
    // the first message) and erl_message.c (erts_save_message_in_proc), OTP-29.1.1.
    #[inline]
    pub(crate) fn pop_front_untokened(
        &mut self,
        heap: &mut ProcessHeap,
        receiver_has_token: bool,
    ) -> Result<bool, VmError> {
        let Some(entry) = self.entries.front_mut().map(queued_mut) else {
            return Ok(false);
        };
        if (entry.seq_nil && receiver_has_token)
            || entry
                .fragment
                .as_ref()
                .is_some_and(|fragment| fragment.seq_token.is_some())
        {
            return Ok(false);
        }
        if let Some(heap_fragment) = entry
            .fragment
            .as_mut()
            .and_then(|fragment| fragment.heap.take())
        {
            heap.adopt_message_heap(heap_fragment).map_err(|error| {
                VmError::Unsupported(format!("message fragment adoption: {error:?}"))
            })?;
        }
        debug_assert!(self.entries.save_is_first());
        if let Some(node) = self.entries.unlink_at_save() {
            QueuedMessage(node).save_in_process(heap);
        }
        Ok(true)
    }

    /// Unlink the message at the save pointer (`erts_msgq_unlink_msg`) into the process heap,
    /// with the seq_trace state it carries.
    pub(crate) fn remove_to_heap_with_token(
        &mut self,
        heap: &mut ProcessHeap,
    ) -> Result<Option<RemovedMessage>, VmError> {
        let mut state = crate::seq_trace::SeqState::Undefined;
        if let Some(entry) = self.entries.peek_mut().map(queued_mut) {
            if entry.seq_nil {
                state = crate::seq_trace::SeqState::Nil;
            }
            if let Some(fragment) = entry.fragment.as_mut() {
                if let Some(token) = fragment.seq_token.take() {
                    state = crate::seq_trace::SeqState::Token(token);
                }
                if let Some(heap_fragment) = fragment.heap.take() {
                    heap.adopt_message_heap(heap_fragment).map_err(|error| {
                        VmError::Unsupported(format!("message fragment adoption: {error:?}"))
                    })?;
                }
            }
        }
        let removed = self.entries.unlink_at_save().map(|node| {
            let term = queued(&node).term;
            QueuedMessage(node).save_in_process(heap);
            (term, state)
        });
        Ok(removed)
    }

    /// Obtain and later rewrite only the mailbox entries scanned by process GC: the message
    /// terms that live on the heap and, like erts' `ERL_MESSAGE_TOKEN` roots, the copies of
    /// sequential trace tokens that live there.
    pub(crate) fn gc_root_snapshot(&self) -> (Vec<RootSlot>, Vec<Term>) {
        let mut roots = Vec::new();
        let slots = self.gc_root_slots();
        // The slots are in queue order, one walk reaches them all.
        let mut entries = self.entries.iter().map(queued).enumerate().peekable();
        for slot in &slots {
            while entries.next_if(|(index, _)| *index < slot.entry).is_some() {}
            let &(_, entry) = entries.peek().expect("root index");
            roots.push(if slot.token {
                entry
                    .fragment
                    .as_ref()
                    .unwrap()
                    .seq_token
                    .as_ref()
                    .unwrap()
                    .heap_ref()
            } else {
                entry.term
            });
        }
        (slots, roots)
    }

    /// Describe only message terms that already live on the process heap.
    fn gc_root_slots(&self) -> Vec<RootSlot> {
        let mut slots = Vec::new();
        for (index, entry) in self.entries.iter().map(queued).enumerate() {
            let on_heap = !entry.combined
                && entry
                    .fragment
                    .as_ref()
                    .is_none_or(|fragment| fragment.heap.is_none());
            if !on_heap {
                continue;
            }
            if entry.term.is_pointer() {
                slots.push(RootSlot {
                    entry: index,
                    token: false,
                });
            }
            if let Some(token) = entry
                .fragment
                .as_ref()
                .and_then(|fragment| fragment.seq_token.as_ref())
                && token.root().is_pointer()
            {
                slots.push(RootSlot {
                    entry: index,
                    token: true,
                });
            }
        }
        slots
    }

    /// Build root descriptors over live queue slots and detached fragments.
    // Port of erts/emulator/beam/erl_gc.c:2616 (`setup_rootset`), OTP-29.1.1.
    pub(super) fn gc_root_slots_and_moved_messages<'a>(
        &'a mut self,
        moved_indices: &[usize],
        moved_heaps: Vec<Option<arinsal_term::message::MessageHeap>>,
        roots: &mut arinsal_term::GcRootSet<'a>,
    ) -> Vec<arinsal_term::GcMessageRoot<'a>> {
        let mut messages = Vec::with_capacity(moved_indices.len());
        let mut moved = moved_indices.iter().copied().zip(moved_heaps).peekable();
        for (index, event) in self.entries.iter_mut().enumerate() {
            let entry = queued_mut(event);
            if moved
                .peek()
                .is_some_and(|(moved_index, _)| *moved_index == index)
            {
                let (_, heap) = moved.next().expect("peeked moved message");
                let token = entry
                    .fragment
                    .as_mut()
                    .and_then(|fragment| fragment.seq_token.as_mut())
                    .filter(|token| token.root().is_pointer())
                    .map(|token| token.heap_ref_mut());
                messages.push(arinsal_term::GcMessageRoot::new(
                    &mut entry.term,
                    token,
                    heap,
                ));
                continue;
            }
            let on_heap = !entry.combined
                && entry
                    .fragment
                    .as_ref()
                    .is_none_or(|fragment| fragment.heap.is_none());
            if on_heap {
                let token = entry
                    .fragment
                    .as_mut()
                    .and_then(|fragment| fragment.seq_token.as_mut())
                    .filter(|token| token.root().is_pointer())
                    .map(|token| token.heap_ref_mut());
                if entry.term.is_pointer() {
                    roots.push_term(&mut entry.term);
                }
                if let Some(token) = token {
                    roots.push_term(token);
                }
            }
        }
        assert!(moved.next().is_none(), "all moved messages were found");
        messages
    }

    /// Rewrite mailbox terms after an operation that explicitly snapshots and transforms them.
    pub(crate) fn update_gc_roots(&mut self, slots: &[RootSlot], roots: &[Term]) {
        // The slots are in queue order, one walk reaches them all.
        let mut entries = self.entries.iter_mut().enumerate().peekable();
        for (slot, &term) in slots.iter().zip(roots) {
            while entries.next_if(|(index, _)| *index < slot.entry).is_some() {}
            let (_, event) = entries.peek_mut().expect("root index");
            let entry = queued_mut(event);
            if slot.token {
                if let Some(token) = entry
                    .fragment
                    .as_mut()
                    .and_then(|fragment| fragment.seq_token.as_mut())
                {
                    *token.heap_ref_mut() = term;
                }
            } else {
                entry.term = term;
            }
        }
    }

    /// Whether a message's data refers to the retiring `area`.
    fn references_area(entry: &Message, inline: Option<&[u64]>, area: &RetiredArea) -> bool {
        area.contains(entry.term)
            || inline.is_some_and(|words| {
                arinsal_term::message::words_have_heap_reference(words, |term| area.contains(term))
            })
            || entry
                .fragment
                .as_ref()
                .and_then(|fragment| fragment.heap.as_ref())
                .is_some_and(|heap| heap.has_heap_reference(|term| area.contains(term)))
    }

    /// Check queue roots and detached fragments for pointers into a retiring area.
    // Port of erts/emulator/beam/beam_bif_load.c:1046-1092, OTP-29.1.1.
    pub(crate) fn has_literal_area_reference(&self, area: &RetiredArea) -> bool {
        self.with_inline_words()
            .any(|(entry, inline)| Self::references_area(entry, inline, area))
    }

    /// Maximum detached message words inspected by literal-copy checks.
    pub(crate) fn literal_scan_words(&self) -> usize {
        self.with_inline_words()
            .map(|(entry, inline)| {
                1 + inline.map_or(0, <[u64]>::len)
                    + entry
                        .fragment
                        .as_ref()
                        .and_then(|fragment| fragment.heap.as_ref())
                        .map_or(0, arinsal_term::message::MessageHeap::literal_scan_words)
            })
            .sum()
    }

    /// Move affected detached message terms into the process heap before releasing their area.
    // Port of erts/emulator/beam/erl_gc.c:1136 (`erts_garbage_collect_literals`), OTP-29.1.1.
    pub(crate) fn copy_literal_area_references(
        &mut self,
        heap: &mut ProcessHeap,
        area: &RetiredArea,
    ) -> Result<u32, VmError> {
        let mut shared_copy = SharedCopyCache::default();
        let mut copied = 0;
        let mut failure = None;
        self.entries.relink_each(|_, mut node| {
            if failure.is_some() {
                return node;
            }
            let inline = node.fragment_words().filter(|_| queued(&node).combined);
            if !Self::references_area(queued(&node), inline, area) {
                return node;
            }
            match copy_term_preserving_sharing_with_cache(
                queued(&node).term,
                &mut arinsal_bifs::ProcessHeapHandle(heap),
                &mut shared_copy,
            ) {
                Ok(updated) => {
                    let entry = queued_mut(&mut node);
                    entry.term = updated;
                    if let Some(fragment) = entry.fragment.as_mut() {
                        fragment.heap = None;
                    }
                    copied += 1;
                    QueuedMessage(node).detach_inline().0
                }
                Err(error) => {
                    failure = Some(VmError::Unsupported(format!(
                        "literal message copy {error:?}"
                    )));
                    node
                }
            }
        });
        match failure {
            Some(error) => Err(error),
            None => Ok(copied),
        }
    }

    /// Take the heap fragments of queued messages for a collection that moves them onto
    /// the heap (on-heap message queue). Each entry carries the message term and the copy of
    /// its sequential trace token that sits in the same fragment.
    // Port of erts/emulator/beam/erl_proc_sig_queue.c:8851-8880 (move_msg_to_heap), OTP-29.1.1.
    pub(crate) fn take_message_fragments(
        &mut self,
    ) -> (Vec<usize>, Vec<Option<arinsal_term::message::MessageHeap>>) {
        let mut indices = Vec::new();
        let mut fragments = Vec::new();
        self.entries.relink_each(|index, mut node| {
            if queued(&node).combined {
                let (node, fragment) = QueuedMessage(node).detach_inline();
                if let Some(fragment) = fragment {
                    indices.push(index);
                    fragments.push(Some(arinsal_term::message::MessageHeap::Node(fragment)));
                }
                return node;
            }
            if let Some(fragment) = queued_mut(&mut node).fragment.as_mut()
                && let Some(heap) = fragment.heap.take()
            {
                indices.push(index);
                fragments.push(Some(heap));
            }
            node
        });
        (indices, fragments)
    }

    /// Restore detached message heaps; collection rewrote their term slots in place.
    pub(crate) fn restore_moved_heaps(
        &mut self,
        indices: &[usize],
        heaps: Vec<Option<arinsal_term::message::MessageHeap>>,
    ) {
        let mut moved = indices.iter().copied().zip(heaps).peekable();
        for (index, event) in self.entries.iter_mut().enumerate() {
            let Some((_, heap)) = moved.next_if(|(moved_index, _)| *moved_index == index) else {
                continue;
            };
            let entry = queued_mut(event);
            if entry.fragment.is_none() && heap.is_some() {
                // A detached inline fragment the collection did not consume stays the
                // message's data as a fragment of its own.
                entry.fragment = Some(system_fragment(MessageFragment {
                    heap: None,
                    seq_token: None,
                    timer_id: None,
                }));
            }
            if let Some(fragment) = entry.fragment.as_mut() {
                fragment.heap = heap;
                if fragment.heap.is_none()
                    && fragment.seq_token.is_none()
                    && fragment.timer_id.is_none()
                {
                    entry.fragment = None;
                }
            }
        }
    }

    /// Return terms copied out of queue-owned storage for `process_info(messages)`.
    pub(crate) fn copied_terms(&self, heap: &mut ProcessHeap) -> Result<Vec<Term>, VmError> {
        let mut target = arinsal_bifs::ProcessHeapHandle(heap);
        self.entries
            .iter()
            .map(|entry| {
                copy_term(queued(entry).term, &mut target)
                    .map_err(|error| VmError::Unsupported(format!("message info copy: {error:?}")))
            })
            .collect()
    }
}
