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
/// Priority messages occupy the leading range recorded in `ProcessCold`.
#[derive(Default)]
pub(crate) struct MessageQueue {
    pub(super) entries: arinsal_sched::MessageQueueList<Event<Message>>,
    /// The save position (`sig_qs.save`): the next message a receive looks at.
    save: usize,
    /// The address of the term of the message at `save`, 0 when there is none: BeamAsm's
    /// `loop_rec` reads it without a call, as erts' `emit_i_loop_rec_shared` loads `*save`.
    save_term: usize,
}

/// A message in the message queue: the signal node it arrived in, relinked from the middle
/// queue without a copy (erl_proc_sig_queue.c, erts_proc_sig_handle_incoming moves message
/// signals onto the message queue as they are), or a node allocated for a message the process
/// built itself.
pub(crate) type MessageNode = arinsal_sched::OwnedSignal<Event<Message>>;

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
    /// Byte offset of the save term address, for generated code.
    pub(crate) const SAVE_TERM_OFFSET: usize = std::mem::offset_of!(MessageQueue, save_term);

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

    /// The save position (`sig_qs.save`).
    pub(crate) fn save(&self) -> usize {
        self.save
    }

    /// Move the save position (`erts_msgq_set_save_*`).
    pub(crate) fn set_save(&mut self, save: usize) {
        self.save = save;
        self.refresh_save_term();
    }

    #[inline(always)]
    fn refresh_save_term(&mut self) {
        self.save_term = self
            .entries
            .get(self.save)
            .map_or(0, |entry| std::ptr::addr_of!(queued(entry).term) as usize);
    }

    /// After a node was linked or unlinked at `index`: the message at the save position may
    /// have changed.
    fn structure_changed_at(&mut self, index: usize) {
        if index <= self.save {
            self.refresh_save_term();
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Append a process-owned term, such as a locally generated control message.
    pub(crate) fn push_back(&mut self, term: Term) {
        self.entries
            .push_back(QueuedMessage::node(term, None, false));
        self.structure_changed_at(self.entries.len() - 1);
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
        self.structure_changed_at(self.entries.len() - 1);
    }

    /// Append a message from a process without a token (`ERL_MESSAGE_TOKEN == NIL`).
    pub(crate) fn push_back_nil(&mut self, term: Term) {
        self.entries
            .push_back(QueuedMessage::node(term, None, true));
        self.structure_changed_at(self.entries.len() - 1);
    }

    /// Insert after the last accepted priority message.
    // Port of erts/emulator/beam/erl_proc_sig_queue.c (`insert_prepared_prio_msg`), OTP-29.1.1.
    pub(crate) fn push_priority(&mut self, term: Term, prio_len: usize) -> usize {
        self.entries
            .insert(prio_len, QueuedMessage::node(term, None, false));
        self.structure_changed_at(prio_len);
        prio_len + 1
    }

    /// The queue the outer queue is spliced onto by `erts_proc_sig_fetch__`.
    pub(crate) fn fetch_target(&mut self) -> &mut arinsal_sched::SignalQueue<Event<Message>> {
        self.entries.queue_mut()
    }

    /// After a splice onto the end that began at position `old_len`.
    pub(crate) fn spliced_at(&mut self, old_len: usize) {
        self.structure_changed_at(old_len);
    }

    /// Link a message node at the end of the queue, or after the last priority message.
    // Port of erts/emulator/beam/erl_proc_sig_queue.c (erts_proc_sig_handle_incoming: a
    // message signal is moved onto the message queue as it is), OTP-29.1.1.
    pub(crate) fn push_message_node(&mut self, node: MessageNode, prio_len: usize) -> usize {
        if queued(&node).priority {
            self.entries.insert(prio_len, node);
            self.structure_changed_at(prio_len);
            prio_len + 1
        } else {
            self.entries.push_back(node);
            self.structure_changed_at(self.entries.len() - 1);
            prio_len
        }
    }

    #[cfg(test)]
    /// Append a scheduler message while applying the active queue policy.
    // Port of erts/emulator/beam/erl_message.c:698 (erts_send_message), OTP-29.1.1.
    pub(crate) fn push_message(
        &mut self,
        message: Message,
        prio_len: usize,
    ) -> Result<usize, VmError> {
        debug_assert!(
            !message.combined,
            "a message with inline data stays in its node"
        );
        let node = QueuedMessage::node(message.term, message.fragment, message.seq_nil);
        let mut node = node;
        queued_mut(&mut node).priority = message.priority;
        Ok(self.push_message_node(node, prio_len))
    }

    pub(crate) fn get(&self, index: usize) -> Option<&Term> {
        self.entries.get(index).map(|entry| &queued(entry).term)
    }

    /// Whether the message's data lives on the receiver's heap (no off-heap fragment holds it).
    pub(crate) fn is_on_heap(&self, index: usize) -> bool {
        self.entries.get(index).map(queued).is_some_and(|entry| {
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
        index: usize,
        heap: &mut ProcessHeap,
        prio_len: usize,
    ) -> Result<(Option<Term>, usize), VmError> {
        let (removed, prio_len) = self.remove_to_heap_with_token(index, heap, prio_len)?;
        Ok((removed.map(|(term, _token)| term), prio_len))
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
        if let Some(node) = self.entries.pop_front() {
            QueuedMessage(node).save_in_process(heap);
        }
        self.structure_changed_at(0);
        Ok(true)
    }

    pub(crate) fn remove_to_heap_with_token(
        &mut self,
        index: usize,
        heap: &mut ProcessHeap,
        prio_len: usize,
    ) -> Result<(Option<RemovedMessage>, usize), VmError> {
        let mut state = crate::seq_trace::SeqState::Undefined;
        if let Some(entry) = self.entries.get_mut(index).map(queued_mut) {
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
        let removed = self.entries.remove(index).map(|node| {
            let term = queued(&node).term;
            QueuedMessage(node).save_in_process(heap);
            (term, state)
        });
        self.structure_changed_at(index);
        let prio_len = prio_len - usize::from(removed.is_some() && index < prio_len);
        Ok((removed, prio_len))
    }

    /// Obtain and later rewrite only the mailbox entries scanned by process GC: the message
    /// terms that live on the heap and, like erts' `ERL_MESSAGE_TOKEN` roots, the copies of
    /// sequential trace tokens that live there.
    pub(crate) fn gc_root_snapshot(&self) -> (Vec<RootSlot>, Vec<Term>) {
        let mut roots = Vec::new();
        let slots = self.gc_root_slots();
        for slot in &slots {
            let entry = queued(self.entries.get(slot.entry).expect("root index"));
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
        for (slot, &term) in slots.iter().zip(roots) {
            let entry = queued_mut(self.entries.get_mut(slot.entry).expect("root index"));
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

    /// Move the inline data of the message at `index` out of its node.
    fn detach_inline_at(&mut self, index: usize) -> Option<arinsal_term::message::NodeFragment> {
        if !self.entries.get(index).map(queued)?.combined {
            return None;
        }
        let node = self.entries.remove(index)?;
        let (node, fragment) = QueuedMessage(node).detach_inline();
        self.entries.insert(index, node);
        self.structure_changed_at(index);
        fragment
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
        for index in 0..self.entries.len() {
            let inline = self.entries.fragment_words(index).filter(|_| {
                self.entries
                    .get(index)
                    .is_some_and(|entry| queued(entry).combined)
            });
            let entry = queued(self.entries.get(index).expect("index within the queue"));
            if !Self::references_area(entry, inline, area) {
                continue;
            }
            let updated = copy_term_preserving_sharing_with_cache(
                entry.term,
                &mut arinsal_bifs::ProcessHeapHandle(heap),
                &mut shared_copy,
            )
            .map_err(|error| VmError::Unsupported(format!("literal message copy {error:?}")))?;
            let entry = queued_mut(self.entries.get_mut(index).expect("index within the queue"));
            entry.term = updated;
            if let Some(fragment) = entry.fragment.as_mut() {
                fragment.heap = None;
            }
            drop(self.detach_inline_at(index));
            copied += 1;
        }
        Ok(copied)
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
        for index in 0..self.entries.len() {
            if let Some(fragment) = self.detach_inline_at(index) {
                indices.push(index);
                fragments.push(Some(arinsal_term::message::MessageHeap::Node(fragment)));
                continue;
            }
            let entry = queued_mut(self.entries.get_mut(index).expect("index within the queue"));
            if let Some(fragment) = entry.fragment.as_mut()
                && let Some(heap) = fragment.heap.take()
            {
                indices.push(index);
                fragments.push(Some(heap));
            }
        }
        (indices, fragments)
    }

    /// Restore detached message heaps; collection rewrote their term slots in place.
    pub(crate) fn restore_moved_heaps(
        &mut self,
        indices: &[usize],
        heaps: Vec<Option<arinsal_term::message::MessageHeap>>,
    ) {
        for (&index, heap) in indices.iter().zip(heaps) {
            let entry = queued_mut(self.entries.get_mut(index).expect("moved message index"));
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
