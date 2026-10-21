//! Scheduler adapter and message envelopes for BEAM processes.

use crate::{Process, RunState, Vm, VmError};
use arinsal_beam::{BeamFile, Operand};
use arinsal_beamasm::SchedulerRegisters;
use arinsal_pterm::RetiredArea;
use arinsal_sched::{
    Config, Event, Payload, Pid, RunCtx, RunOutcome, Scheduler, Signal, Task, proc_flags,
};
use arinsal_spec::Opcode;
use arinsal_term::ptab::PtabIdRing;
use arinsal_term::{
    Atom, ProcessHeap, SharedCopyCache, Term, TermBuilder, VecHeap, copy_struct_litopt, copy_term,
    copy_term_preserving_sharing_with_cache, global_atoms, size_object,
};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock, mpsc};

/// Raises the error of a native call to an undefined function that has no error handler
/// (`undef`) at the call, like the interpreter's call_ext; the arguments are restored first.
// Port of erts/emulator/beam/beam_common.c (call_error_handler), OTP-29.1.1.
fn raise_undefined_call(
    vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    arguments: &[Term],
    error: VmError,
) -> Result<Option<VmError>, VmError> {
    for (register, value) in process.x.iter_mut().zip(arguments) {
        *register = *value;
    }
    let trap = match error {
        VmError::Exception { reason, frame } => legacy_exception_trap(process, &reason, &frame)?,
        VmError::Trap(trap) => trap,
        other => return Err(other),
    };
    let resumed = crate::exceptions::resume(vm, process, Some(ctx), trap)?;
    process.header.freason = 0;
    process.header.fvalue = 0;
    Ok(resumed)
}

/// Turns a legacy interpreter exception into a trap, attaching the `undef` call arguments.
fn legacy_exception_trap(
    process: &mut Process,
    reason: &str,
    frame: &str,
) -> Result<crate::exceptions::Trap, VmError> {
    let mut trap = crate::exceptions::from_legacy(reason)?;
    if reason == "undef"
        && let Some((mfa, arity)) = frame.rsplit_once('/')
        && let Some((module, function)) = mfa.split_once(':')
        && let Ok(arity) = arity.parse::<usize>()
        && arity <= process.x.len()
    {
        trap.top = Some(crate::stacktrace::TopFrame::Bif {
            module: global_atoms()
                .intern(module)
                .map_err(|_| VmError::Unsupported("undef module atom".into()))?,
            function: global_atoms()
                .intern(function)
                .map_err(|_| VmError::Unsupported("undef function atom".into()))?,
            args: crate::stacktrace::BifArgs::from_terms(&process.x[..arity])?,
            info: crate::stacktrace::BifErrorInfo::None,
        });
    }
    Ok(trap)
}

/// Whether an interpreted step yielded only to hand control to native code, which
/// erts does without a scheduling point. Native FCALLS stay within this slice's
/// quantum so that its reductions are charged to the scheduler.
fn native_transfer_continues(process: &mut Process, ctx: &RunCtx<'_, Message>) -> bool {
    let transfer = process
        .cold
        .as_mut()
        .is_some_and(|cold| std::mem::take(&mut cold.native_transfer));
    let remaining = i32::try_from(ctx.remaining()).unwrap_or(i32::MAX);
    if !transfer || remaining == 0 {
        return false;
    }
    process.reductions = process.reductions.min(remaining);
    true
}

#[inline]
fn trace_boot_enabled() -> bool {
    crate::calls::trace_boot_enabled()
}

#[cfg(feature = "pf-mem-counters")]
static PF_MONITOR_DOWN: AtomicU64 = AtomicU64::new(0);

/// A sender-owned copy that can cross scheduler threads without accessing the
/// destination process heap.
pub struct Message {
    term: Term,
    fragment: Option<Box<MessageFragment>>,
    /// When set, the receiver inserts this into the priority section of its
    /// private message queue (OTP 28+ priority messages).
    priority: bool,
    /// The VM timer id carried until delivery so expiry and cancellation release its message.
    timer_id: Option<u64>,
    /// The port connected handshake traces receipt before unblocking the recipient.
    receive_traced: bool,
    /// Sent by a process without a seq_trace token (`ERL_MESSAGE_TOKEN == NIL`).
    seq_nil: bool,
    /// The alias the message was sent through, 0 for none (checked when it is handled).
    alias: u64,
}

/// What the sender knows about a message beyond its term: the sequential trace token state
/// and the alias it was sent through.
#[derive(Default)]
struct SendMeta {
    seq: crate::seq_trace::SeqState,
    alias: u64,
}

struct MessageFragment {
    heap: Option<ProcessHeap>,
    seq_token: Option<Box<crate::seq_trace::Token>>,
}

type RemovedMessage = (Term, crate::seq_trace::SeqState);

/// A queued message whose data is still in its heap fragment, as an on-heap collection moves
/// it: the term, the copy of its sequential trace token in the same fragment, and the fragment.
pub(crate) type MovedMessage = (Term, Term, Option<ProcessHeap>);

/// Which part of a queued message a collection root stands for.
#[derive(Clone, Copy)]
pub(crate) struct RootSlot {
    entry: usize,
    token: bool,
}

/// Private message queue whose detached fragments remain owned by each entry.
///
/// Port of erts/emulator/beam/erl_proc_sig_queue.c:1285 (private message queue), OTP-29.1.1.
/// Priority messages occupy the leading range recorded in `ProcessCold`.
#[derive(Default)]
pub(crate) struct MessageQueue {
    entries: VecDeque<QueuedMessage>,
}

struct QueuedMessage {
    term: Term,
    fragment: Option<Box<MessageFragment>>,
    seq_nil: bool,
}

impl MessageQueue {
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Append a process-owned term, such as a locally generated control message.
    pub(crate) fn push_back(&mut self, term: Term) {
        self.entries.push_back(QueuedMessage {
            term,
            fragment: None,
            seq_nil: false,
        });
    }

    /// Append a message that carries a seq_trace token.
    pub(crate) fn push_back_token(&mut self, term: Term, token: Box<crate::seq_trace::Token>) {
        self.entries.push_back(QueuedMessage {
            term,
            fragment: Some(Box::new(MessageFragment {
                heap: None,
                seq_token: Some(token),
            })),
            seq_nil: false,
        });
    }

    /// Append a message from a process without a token (`ERL_MESSAGE_TOKEN == NIL`).
    pub(crate) fn push_back_nil(&mut self, term: Term) {
        self.entries.push_back(QueuedMessage {
            term,
            fragment: None,
            seq_nil: true,
        });
    }

    /// Insert after the last accepted priority message.
    // Port of erts/emulator/beam/erl_proc_sig_queue.c (`insert_prepared_prio_msg`), OTP-29.1.1.
    pub(crate) fn push_priority(&mut self, term: Term, prio_len: usize) -> usize {
        self.entries.insert(
            prio_len,
            QueuedMessage {
                term,
                fragment: None,
                seq_nil: false,
            },
        );
        prio_len + 1
    }

    /// Append a scheduler message while applying the active queue policy.
    // Port of erts/emulator/beam/erl_message.c:698 (erts_send_message), OTP-29.1.1.
    pub(crate) fn push_message(
        &mut self,
        message: Message,
        prio_len: usize,
    ) -> Result<usize, VmError> {
        let priority = message.priority;
        let mut new_prio_len = prio_len;
        let mut push = |queue: &mut Self, entry: QueuedMessage| {
            if priority {
                queue.entries.insert(new_prio_len, entry);
                new_prio_len += 1;
            } else {
                queue.entries.push_back(entry);
            }
        };
        if message.fragment.is_none() {
            push(
                self,
                QueuedMessage {
                    term: message.term,
                    fragment: None,
                    seq_nil: message.seq_nil,
                },
            );
            return Ok(new_prio_len);
        }
        // Port of erts/emulator/beam/erl_proc_sig_queue.c (erts_proc_sig_fetch), OTP-29.1.1:
        // fetching links the message into the private queue as is. Its data stays in the
        // heap fragment in both queue modes; with an on-heap queue the next collection
        // moves it onto the heap (move_msgs_to_heap), and receiving it first saves the
        // fragment in the process (erts_save_message_in_proc).
        push(
            self,
            QueuedMessage {
                term: message.term,
                fragment: message.fragment,
                seq_nil: message.seq_nil,
            },
        );
        Ok(new_prio_len)
    }

    pub(crate) fn get(&self, index: usize) -> Option<&Term> {
        self.entries.get(index).map(|entry| &entry.term)
    }

    /// Whether the message's data lives on the receiver's heap (no off-heap fragment holds it).
    pub(crate) fn is_on_heap(&self, index: usize) -> bool {
        self.entries
            .get(index)
            .is_some_and(|entry| entry.fragment.as_ref().is_none_or(|f| f.heap.is_none()))
    }

    /// Words in message fragments that `process_info(total_heap_size)` counts for on-heap queues.
    // Port of erts/emulator/beam/erl_message.h (erts_msg_attached_data_size), OTP-29.1.1.
    pub(crate) fn attached_message_words(&self) -> usize {
        self.entries
            .iter()
            .filter_map(|entry| entry.fragment.as_ref()?.heap.as_ref())
            .map(ProcessHeap::message_data_size)
            .fold(0, usize::saturating_add)
    }

    /// Index of the first message at or after `start` that matches.
    pub(crate) fn position_from(
        &self,
        start: usize,
        mut matches: impl FnMut(&Term) -> bool,
    ) -> Option<usize> {
        let start = start.min(self.entries.len());
        self.entries
            .range(start..)
            .position(|entry| matches(&entry.term))
            .map(|offset| start + offset)
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = &Term> {
        self.entries.iter().map(|entry| &entry.term)
    }

    /// Remove a message, transferring any off-heap fragment into the process heap.
    // Port of erts/emulator/beam/erl_proc_sig_queue.c:7142 (message receive), OTP-29.1.1.
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
        let Some(entry) = self.entries.front_mut() else {
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
            heap.adopt_message_fragment(heap_fragment)
                .map_err(|error| {
                    VmError::Unsupported(format!("message fragment adoption: {error:?}"))
                })?;
        }
        self.entries.pop_front();
        Ok(true)
    }

    pub(crate) fn remove_to_heap_with_token(
        &mut self,
        index: usize,
        heap: &mut ProcessHeap,
        prio_len: usize,
    ) -> Result<(Option<RemovedMessage>, usize), VmError> {
        let mut state = crate::seq_trace::SeqState::Undefined;
        if let Some(entry) = self.entries.get_mut(index)
            && entry.seq_nil
        {
            state = crate::seq_trace::SeqState::Nil;
        }
        if let Some(entry) = self.entries.get_mut(index)
            && let Some(fragment) = entry.fragment.as_mut()
        {
            if let Some(token) = fragment.seq_token.take() {
                state = crate::seq_trace::SeqState::Token(token);
            }
            if let Some(heap_fragment) = fragment.heap.take() {
                heap.adopt_message_fragment(heap_fragment)
                    .map_err(|error| {
                        VmError::Unsupported(format!("message fragment adoption: {error:?}"))
                    })?;
            }
        }
        let removed = self.entries.remove(index).map(|entry| (entry.term, state));
        let prio_len = prio_len - usize::from(removed.is_some() && index < prio_len);
        Ok((removed, prio_len))
    }

    /// Obtain and later rewrite only the mailbox entries scanned by process GC: the message
    /// terms that live on the heap and, like erts' `ERL_MESSAGE_TOKEN` roots, the copies of
    /// sequential trace tokens that live there.
    pub(crate) fn gc_root_snapshot(&self) -> (Vec<RootSlot>, Vec<Term>) {
        let mut slots = Vec::new();
        let mut roots = Vec::new();
        for (index, entry) in self.entries.iter().enumerate() {
            let on_heap = entry
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
                roots.push(entry.term);
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
                roots.push(token.heap_ref());
            }
        }
        (slots, roots)
    }

    /// Check queue roots and detached fragments for pointers into a retiring area.
    // Port of erts/emulator/beam/beam_bif_load.c:1046-1092, OTP-29.1.1.
    pub(crate) fn has_literal_area_reference(&self, area: &RetiredArea) -> bool {
        self.entries.iter().any(|entry| {
            area.contains(entry.term)
                || entry
                    .fragment
                    .as_ref()
                    .and_then(|fragment| fragment.heap.as_ref())
                    .is_some_and(|heap| heap.has_heap_reference(|term| area.contains(term)))
        })
    }

    /// Maximum detached message words inspected by literal-copy checks.
    pub(crate) fn literal_scan_words(&self) -> usize {
        self.entries
            .iter()
            .map(|entry| {
                1 + entry
                    .fragment
                    .as_ref()
                    .and_then(|fragment| fragment.heap.as_ref())
                    .map_or(0, ProcessHeap::literal_scan_words)
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
        for entry in &mut self.entries {
            let references_area = area.contains(entry.term)
                || entry
                    .fragment
                    .as_ref()
                    .and_then(|fragment| fragment.heap.as_ref())
                    .is_some_and(|fragment| {
                        fragment.has_heap_reference(|term| area.contains(term))
                    });
            if !references_area {
                continue;
            }
            let updated = copy_term_preserving_sharing_with_cache(
                entry.term,
                &mut arinsal_bifs::ProcessHeapHandle(heap),
                &mut shared_copy,
            )
            .map_err(|error| VmError::Unsupported(format!("literal message copy {error:?}")))?;
            entry.term = updated;
            if let Some(fragment) = entry.fragment.as_mut() {
                fragment.heap = None;
            }
            copied += 1;
        }
        Ok(copied)
    }

    /// Take the heap fragments of queued messages for a collection that moves them onto
    /// the heap (on-heap message queue). Each entry carries the message term and the copy of
    /// its sequential trace token that sits in the same fragment.
    // Port of erts/emulator/beam/erl_proc_sig_queue.c:8851-8880 (move_msg_to_heap), OTP-29.1.1.
    pub(crate) fn take_message_fragments(&mut self) -> (Vec<usize>, Vec<MovedMessage>) {
        let mut indices = Vec::new();
        let mut fragments = Vec::new();
        for (index, entry) in self.entries.iter_mut().enumerate() {
            if let Some(fragment) = entry.fragment.as_mut()
                && let Some(heap) = fragment.heap.take()
            {
                indices.push(index);
                let token = fragment
                    .seq_token
                    .as_ref()
                    .map_or(Term::NIL, |token| token.heap_ref());
                fragments.push((entry.term, token, Some(heap)));
            }
        }
        (indices, fragments)
    }

    /// Store the terms of messages moved onto the heap; their fragments are gone.
    pub(crate) fn restore_moved_messages(&mut self, indices: &[usize], moved: Vec<MovedMessage>) {
        for (&index, (term, token, heap)) in indices.iter().zip(moved) {
            let entry = &mut self.entries[index];
            entry.term = term;
            if let Some(fragment) = entry.fragment.as_mut() {
                if let Some(seq_token) = fragment.seq_token.as_mut() {
                    *seq_token.heap_ref_mut() = token;
                }
                fragment.heap = heap;
                if fragment.heap.is_none() && fragment.seq_token.is_none() {
                    entry.fragment = None;
                }
            }
        }
    }

    pub(crate) fn update_gc_roots(&mut self, slots: &[RootSlot], roots: &[Term]) {
        for (slot, &term) in slots.iter().zip(roots) {
            let entry = &mut self.entries[slot.entry];
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

    /// Return terms copied out of queue-owned storage for `process_info(messages)`.
    pub(crate) fn copied_terms(&self, heap: &mut ProcessHeap) -> Result<Vec<Term>, VmError> {
        let mut target = arinsal_bifs::ProcessHeapHandle(heap);
        self.entries
            .iter()
            .map(|entry| {
                copy_term(entry.term, &mut target)
                    .map_err(|error| VmError::Unsupported(format!("message info copy: {error:?}")))
            })
            .collect()
    }
}

impl Message {
    /// A message whose term lives on the receiver's heap (sent there by
    /// `erts_try_alloc_message_on_heap`), not in its own fragment.
    fn is_heap_root(&self) -> bool {
        self.term.is_pointer()
            && self
                .fragment
                .as_ref()
                .is_none_or(|fragment| fragment.heap.is_none())
    }

    /// The copy of the sequential trace token that sits on the receiver's heap, a collection
    /// root like the message term.
    fn heap_token_root(&self) -> Option<Term> {
        let fragment = self.fragment.as_ref()?;
        if fragment.heap.is_some() {
            return None;
        }
        let token = fragment.seq_token.as_ref()?;
        token.root().is_pointer().then_some(token.heap_ref())
    }

    fn set_heap_token_root(&mut self, root: Term) {
        if let Some(token) = self
            .fragment
            .as_mut()
            .and_then(|fragment| fragment.seq_token.as_mut())
        {
            *token.heap_ref_mut() = root;
        }
    }

    /// Build a scheduler-safe message from a self-contained term snapshot.
    pub(crate) fn from_owned(term: &arinsal_etf::OwnedTerm) -> Result<Self, VmError> {
        let mut heap = ProcessHeap::with_words(4096);
        let term = arinsal_term::from_owned(term, &mut heap)
            .map_err(|error| VmError::Unsupported(format!("owned message term: {error:?}")))?;
        Self::copy_from(term)
    }

    /// Queue a term built in a standalone message fragment without copying it again.
    // Port of erts/emulator/beam/io.c:5658 (driver_deliver_term), OTP-29.1.1.
    pub(crate) fn from_heap(term: Term, heap: ProcessHeap) -> Self {
        if !term.is_pointer() {
            return Self::immediate(term);
        }
        Self {
            term,
            fragment: Some(Box::new(MessageFragment {
                heap: Some(heap),
                seq_token: None,
            })),
            priority: false,
            timer_id: None,
            receive_traced: false,
            seq_nil: false,
            alias: 0,
        }
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
        Self::copy_counted(term, words, None, &literals)
    }

    /// `copy_from` when `words` is already `size_object_litopt(term, literals)`. A sequential
    /// trace `token` is copied into the same fragment after the message, and its words count
    /// towards the fragment size.
    // Port of erts/emulator/beam/erl_message.c (erts_send_message, seq trace): the fragment
    // holds the message and then the copied token, OTP-29.1.1.
    fn copy_counted(
        term: Term,
        words: usize,
        token: Option<&mut crate::seq_trace::Token>,
        literals: &arinsal_term::LiteralAreas,
    ) -> Result<Self, VmError> {
        let token_words = token
            .as_deref()
            .map_or(0, crate::seq_trace::Token::heap_words);
        if words + token_words == 0 {
            return Ok(Self::immediate(term));
        }
        let mut fragment = ProcessHeap::with_words_for_type(
            words + token_words,
            arinsal_alloc::typed::ErtsAlcType::HEAP_FRAG,
        );
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
                .build_on(&mut arinsal_bifs::ProcessHeapHandle(&mut fragment))
                .map_err(|error| VmError::Unsupported(format!("message token copy: {error:?}")))?;
            *token.heap_ref_mut() = copy;
        }
        Ok(Self {
            term,
            fragment: Some(Box::new(MessageFragment {
                heap: Some(fragment),
                seq_token: None,
            })),
            priority: false,
            timer_id: None,
            receive_traced: false,
            seq_nil: false,
            alias: 0,
        })
    }

    fn immediate(term: Term) -> Self {
        Self {
            term,
            fragment: None,
            priority: false,
            timer_id: None,
            receive_traced: false,
            seq_nil: false,
            alias: 0,
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
        let mut heap = ProcessHeap::with_words(size_object(area).saturating_add(8));
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
            fragment: Some(Box::new(MessageFragment {
                heap: Some(heap),
                seq_token: None,
            })),
            priority: false,
            timer_id: None,
            receive_traced: false,
            seq_nil: false,
            alias: 0,
        })
    }

    /// Append the collector reply to its original request fragment.
    // Port of erts/emulator/beam/erl_proc_sig_queue.c:8083 (`send_cla_reply`), OTP-29.1.1.
    pub(crate) fn literal_copy_reply(mut self, result: Term) -> Result<Self, VmError> {
        let heap = self
            .fragment
            .as_mut()
            .and_then(|fragment| fragment.heap.as_mut())
            .ok_or_else(|| {
                VmError::Unsupported("literal-copy request lost its heap fragment".into())
            })?;
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

    pub(crate) fn with_timer_id(mut self, id: u64) -> Self {
        self.timer_id = Some(id);
        self
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
            self.fragment = Some(Box::new(MessageFragment {
                heap: None,
                seq_token: Some(token),
            }));
        }
    }

    pub(crate) fn into_receiver(self, process: &mut Process) -> Result<Term, VmError> {
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
        if let Some(fragment) = self.fragment
            && let Some(heap_fragment) = fragment.heap
        {
            process
                .heap
                .adopt_message_fragment(heap_fragment)
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
        timer_id: None,
        receive_traced: false,
        seq_nil: false,
        alias: 0,
    };
    if priority {
        envelope = envelope.with_priority();
    }
    envelope.apply_seq_state(std::mem::take(&mut seq_token.seq));
    envelope.alias = seq_token.alias;
    Ok(Some(envelope))
}

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
        self.cold
            .as_ref()
            .and_then(|cold| cold.signal_probe.as_ref())
            .is_some_and(arinsal_sched::SignalProbe::has_pending)
    }
}

/// Port of erts/emulator/beam/erl_vm.h:53 (CONTEXT_REDS), OTP-29.1.1.
pub(crate) const CONTEXT_REDS: i32 = 4000;
/// Port of erts/emulator/beam/erl_gc.c (ERTS_ABANDON_HEAP_COST), OTP-29.1.1.
const ABANDON_HEAP_COST: i32 = 10;

/// Port of erts/emulator/beam/erl_process.h (erts_time2reds), OTP-29.1.1: the reductions
/// charged for `elapsed` on a dirty CPU scheduler. At least one, else four per whole
/// microsecond (`(CONTEXT_REDS - 1) / 1000 + 1`).
pub(crate) fn erts_time2reds(elapsed: std::time::Duration) -> u64 {
    let microseconds = u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX);
    if microseconds == 0 {
        return 1;
    }
    microseconds.saturating_mul(((CONTEXT_REDS - 1) / 1000 + 1) as u64)
}

/// Words of a sent message that cost one reduction of the sender.
///
/// Port of erts/emulator/beam/erl_message.h:33-35 (ERTS_MSG_COPY_WORDS_PER_REDUCTION), OTP-29.1.1.
pub(crate) const ERTS_MSG_COPY_WORDS_PER_REDUCTION: usize = 64;
/// Port of erts/emulator/beam/erl_proc_sig_queue.c:52 (ERTS_SIG_REDS_CNT_FACTOR), OTP-29.1.1.
const SIG_REDS_CNT_FACTOR: i32 = 4;
/// Port of erts/emulator/beam/erl_proc_sig_queue.h:284 (ERTS_SIG_HANDLE_REDS_MAX_PREFERED),
/// OTP-29.1.1.
pub(crate) const SIG_HANDLE_REDS_MAX_PREFERED: i32 = CONTEXT_REDS / 40;

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

const ALIAS_SLAB: usize = 4096;
const ALIAS_SLABS: usize = 256;
const ALIAS_INACTIVE: u64 = 1;

/// Alias → pid map. Dense reference ids use atomic slabs, so reply sends do
/// not acquire a global mutex after the slab's one-time allocation.
struct AliasTable {
    slabs: Box<[OnceLock<Box<[AtomicU64]>>]>,
    /// Ids beyond the dense slabs (per-scheduler reference counters): sharded by id so the
    /// scheduler threads of unrelated processes do not meet on one lock.
    overflow: Box<[AliasShard]>,
}

const ALIAS_SHARDS: usize = 64;

type AliasShard = parking_lot::Mutex<
    HashMap<u64, (Option<Pid>, bool), std::hash::BuildHasherDefault<AliasHasher>>,
>;

/// Multiplicative hash of the reference id; ids are not attacker chosen.
#[derive(Default)]
struct AliasHasher(u64);

impl std::hash::Hasher for AliasHasher {
    fn write(&mut self, bytes: &[u8]) {
        for byte in bytes {
            self.0 = (self.0 ^ u64::from(*byte)).wrapping_mul(0x0100_0000_01b3);
        }
    }

    fn write_u64(&mut self, value: u64) {
        self.0 = value.wrapping_mul(0x9e37_79b9_7f4a_7c15);
    }

    fn finish(&self) -> u64 {
        self.0 ^ (self.0 >> 32)
    }
}

fn alias_shard(id: u64) -> usize {
    ((id.wrapping_mul(0x9e37_79b9_7f4a_7c15) >> 40) as usize) % ALIAS_SHARDS
}

impl AliasTable {
    fn new() -> Self {
        Self {
            slabs: (0..ALIAS_SLABS).map(|_| OnceLock::new()).collect(),
            overflow: (0..ALIAS_SHARDS)
                .map(|_| parking_lot::Mutex::new(HashMap::default()))
                .collect(),
        }
    }

    fn encode(target: Option<Pid>, priority: bool) -> u64 {
        match target {
            None => ALIAS_INACTIVE,
            // Pid data is 60 bits. Bit 60 marks a live alias
            // so the inactive sentinel `1` cannot collide with pid 0. Bit 61
            // marks a priority alias (OTP 28+).
            Some(pid) => {
                const PRESENT: u64 = 1 << 60;
                const PRIORITY: u64 = 1 << 61;
                let mut raw = PRESENT | pid.data();
                if priority {
                    raw |= PRIORITY;
                }
                raw
            }
        }
    }

    fn decode(raw: u64) -> Option<(Option<Pid>, bool)> {
        if raw == 0 {
            return None;
        }
        if raw == ALIAS_INACTIVE {
            return Some((None, false));
        }
        const PRESENT: u64 = 1 << 60;
        const PRIORITY: u64 = 1 << 61;
        if raw & PRESENT == 0 {
            return None;
        }
        Some((Some(Pid::from_data(raw)), raw & PRIORITY != 0))
    }

    fn load(&self, id: u64) -> Option<(Option<Pid>, bool)> {
        if id / ALIAS_SLAB as u64 >= ALIAS_SLABS as u64 {
            return self.overflow[alias_shard(id)].lock().get(&id).copied();
        }
        let slab = self.slabs.get((id / ALIAS_SLAB as u64) as usize)?.get()?;
        let slot = (id % ALIAS_SLAB as u64) as usize;
        let raw = slab[slot].load(Ordering::Acquire);
        Self::decode(raw)
    }

    fn store(&self, id: u64, target: Option<Pid>, priority: bool) {
        if id / ALIAS_SLAB as u64 >= ALIAS_SLABS as u64 {
            self.overflow[alias_shard(id)]
                .lock()
                .insert(id, (target, priority && target.is_some()));
            return;
        }
        let slab = self.slabs[(id / ALIAS_SLAB as u64) as usize]
            .get_or_init(|| (0..ALIAS_SLAB).map(|_| AtomicU64::new(0)).collect());
        let slot = (id % ALIAS_SLAB as u64) as usize;
        slab[slot].store(
            Self::encode(target, priority && target.is_some()),
            Ordering::Release,
        );
    }
}

/// Shared interpreter and scheduler handles for a set of local processes.
pub(crate) struct Runtime {
    pub(crate) statistics: crate::natives::sys::StatisticsState,
    /// Node-wide backtrace depth shared by scheduler VM replicas.
    pub(crate) backtrace_depth: AtomicUsize,
    /// The node's code indexes and their code tables.
    code: Arc<crate::code_ix::CodeIndexes>,
    /// The node's code scope, which keys its native code registries.
    pub(crate) code_scope: u64,
    pub(crate) system_processes: Mutex<std::collections::HashSet<Pid>>,
    otp_root: Option<std::path::PathBuf>,
    pub(crate) dirty_signal_handlers: Mutex<std::collections::HashSet<Pid>>,
    /// Pid of `erts_literal_area_collector` (an unregistered system process).
    pub(crate) literal_collector: Mutex<Option<Pid>>,
    paths: Vec<std::path::PathBuf>,
    // Set once when the scheduler starts; read without a lock like erts' scheduler data.
    /// Held for the VM lifetime (erts reads its scheduler data through globals / `esdp`, no
    /// refcount per call); the cycle through the processes is broken by `Scheduler::shutdown`.
    scheduler: OnceLock<Arc<Scheduler<Process>>>,
    /// `process_reg` (`regtab_rwmtx`). Names are atom indexes, not strings.
    pub(crate) reg: crate::register::RegisterTable,
    aliases: AliasTable,
    pub(crate) next_trace_weak_id: AtomicU64,
    pub(crate) ports: crate::port::PortTable,
    /// Persistent `erl_child_setup` process; all OS port children are forked there.
    pub(crate) child_setup: Arc<crate::child_setup::ChildSetup>,
    pub(crate) system_monitor: Mutex<Option<crate::natives::erts_debug::SystemMonitorState>>,
    /// `system_monitor` state of dynamic trace sessions, keyed by session id.
    pub(crate) session_monitors: Mutex<Vec<(u64, crate::natives::erts_debug::SystemMonitorState)>>,
    pub(crate) system_monitor_flags: AtomicU8,
    pub(crate) long_message_queues: Mutex<Vec<(Pid, Option<u64>)>>,
    /// Port identifier table's free id ring, like `erts_port.ptab`.
    pub(crate) port_ids: PtabIdRing,
    pub(crate) simulated: bool,
    pub(crate) virtual_ms: AtomicU64,
    /// `meta_name_tab`, read without taking the global ETS registry lock.
    pub(crate) named_ets: Arc<arinsal_ets::NamedTableIndex>,
    pub(crate) ets: std::sync::RwLock<arinsal_ets::Registry>,
    result: mpsc::Sender<Result<ScheduledResult, VmError>>,
    // g_proc_sched: suspend counts and the status other processes can observe.
    /// Asynchronous suspends of a running process that it has not yet acted on.
    // Port of erts/emulator/beam/erl_process.c:9013 (`erts_internal_suspend_process_2` pending suspend), OTP-29.1.1.
    /// Replies owed to suspenders once their suspend is active (erts sync-suspend signal).
    /// The code modification permission (`code_ix.c` `code_mod_permission`) of this node.
    pub(crate) code_mod_permission: Mutex<crate::natives::code::CodeModPermission>,
    /// This node's breakpoint tables and active breakpoint index.
    pub(crate) breakpoints: Arc<crate::trace_bp::BpNode>,
    pub(crate) debug_wait_active: AtomicBool,
    /// `erlang:system_flag/2` settings of this runtime.
    pub(crate) system_flags: Mutex<crate::natives::sys::SystemFlags>,
    /// Spawn GC defaults, read without a lock (erts' `H_MIN_SIZE` and friends).
    pub(crate) gc_defaults: crate::natives::sys::GcDefaults,
    /// The persistent term store of this runtime's code scope, looked up once.
    pub(crate) persistent_terms: &'static arinsal_pterm::Store,
    /// Multi-scheduling block state of this runtime.
    pub(crate) multi_scheduling: Mutex<MultiScheduling>,
}

/// A `system_flag(multi_scheduling, _)` request.
#[derive(Clone, Copy, Debug)]
pub(crate) enum MsbChange {
    Block { normal: bool },
    Unblock { normal: bool },
}

/// `erlang:system_flag(multi_scheduling, _)` state of one runtime.
///
/// Port of erts/emulator/beam/erl_process.c:8484 (erts_block_multi_scheduling,
/// `schdlr_sspnd.msb.blckrs` / `schdlr_sspnd.nmsb.blckrs`), OTP-29.1.1: each block adds
/// the caller to the blocker list once more, each unblock removes one entry, and the
/// runtime stays blocked while a list is non-empty.
#[derive(Clone, Debug, Default)]
pub(crate) struct MultiScheduling {
    blockers: Vec<Pid>,
    normal_blockers: Vec<Pid>,
}

impl MultiScheduling {
    /// Port of erts/emulator/beam/erl_bif_info.c:2790 (system_info(multi_scheduling)),
    /// OTP-29.1.1.
    pub(crate) fn state(&self) -> &'static str {
        if !self.blockers.is_empty() {
            "blocked"
        } else if !self.normal_blockers.is_empty() {
            "blocked_normal"
        } else {
            "enabled"
        }
    }

    pub(crate) fn any_blocked(&self) -> bool {
        !self.blockers.is_empty() || !self.normal_blockers.is_empty()
    }

    /// Apply `change` for `pid`; true when `pid` now holds a block.
    pub(crate) fn change(&mut self, pid: Pid, change: MsbChange) -> bool {
        match change {
            MsbChange::Block { normal } => {
                self.list(normal).push(pid);
                true
            }
            MsbChange::Unblock { normal } => {
                let list = self.list(normal);
                if let Some(index) = list.iter().position(|blocker| *blocker == pid) {
                    list.remove(index);
                }
                self.holds(pid)
            }
        }
    }

    /// Drop every block of an exiting process.
    pub(crate) fn release(&mut self, pid: Pid) {
        self.blockers.retain(|blocker| *blocker != pid);
        self.normal_blockers.retain(|blocker| *blocker != pid);
    }

    /// Port of erts/emulator/beam/erl_process.c:8692 (erts_multi_scheduling_blockers),
    /// OTP-29.1.1: distinct blockers, the list built by consing in blocking order.
    pub(crate) fn blockers(&self, normal: bool) -> Vec<Pid> {
        let list = if normal {
            &self.normal_blockers
        } else {
            &self.blockers
        };
        let mut distinct = Vec::new();
        for pid in list {
            if !distinct.contains(pid) {
                distinct.push(*pid);
            }
        }
        distinct.reverse();
        distinct
    }

    fn holds(&self, pid: Pid) -> bool {
        self.blockers.contains(&pid) || self.normal_blockers.contains(&pid)
    }

    fn list(&mut self, normal: bool) -> &mut Vec<Pid> {
        if normal {
            &mut self.normal_blockers
        } else {
            &mut self.blockers
        }
    }
}

/// Fibonacci hashing of one `u64` or `u32` key (module atoms); not adversarial input.
#[derive(Default)]
pub(crate) struct IdHasher(u64);

impl std::hash::Hasher for IdHasher {
    fn finish(&self) -> u64 {
        self.0
    }
    fn write(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            self.0 = (self.0 << 8) ^ u64::from(byte);
        }
    }
    fn write_u64(&mut self, value: u64) {
        self.0 = value.wrapping_mul(0x9E37_79B9_7F4A_7C15);
    }
    fn write_u32(&mut self, value: u32) {
        self.write_u64(u64::from(value));
    }
}

impl Runtime {
    /// Read ranges and module tables from one active code index.
    pub(crate) fn with_active_code<R>(
        &self,
        read: impl FnOnce(&[crate::native_bridge::ModuleRange], &crate::load::CodeTables) -> R,
    ) -> R {
        self.code.with_active_code(read)
    }

    /// Runs a lookup against the BeamAsm version selected by a code index and module slot.
    // Port of erts/emulator/beam/code_ix.c:51-79 (code-indexed module tables), OTP-29.1.1.
    #[inline(always)]
    pub(crate) fn with_beamasm_module<R>(
        &self,
        code_ix: usize,
        module_id: usize,
        use_module: impl FnOnce(&crate::beamasm_integration::CompiledVersion) -> R,
    ) -> Option<R> {
        self.code.with_tables_for_code_ix(code_ix, |tables| {
            let module = tables
                .code_meta
                .get(module_id)?
                .as_ref()?
                .beamasm
                .as_deref()?;
            Some(use_module(module))
        })?
    }

    /// Catch table of this node's `erts_active_code_ix()`.
    // Port of erts/emulator/beam/code_ix.h:362 (`erts_active_code_ix` is one atomic, not
    // thread-local) and beam_catches.c:146 (`bccix[erts_active_code_ix()]`), OTP-29.1.1.
    pub(crate) fn code_indexes(&self) -> &Arc<crate::code_ix::CodeIndexes> {
        &self.code
    }

    pub(crate) fn with_active_catches<R>(
        &self,
        read: impl FnOnce(&[Option<crate::native_bridge::CatchTarget>]) -> R,
    ) -> R {
        self.code.with_active_catches(read)
    }

    /// Address of an export in the requested active code index.
    // Port of erts/emulator/beam/beam_common.c:1520-1530 (apply export dispatch), OTP-29.1.1.
    pub(crate) fn export_address(
        &self,
        mfa: (arinsal_term::Atom, arinsal_term::Atom, u8),
        code_ix: usize,
    ) -> Option<usize> {
        self.export_entry(mfa, code_ix)
            .map(|entry| entry.address(code_ix))
    }

    /// Export slot selected by the process-visible code index.
    pub(crate) fn export_entry(
        &self,
        mfa: (arinsal_term::Atom, arinsal_term::Atom, u8),
        code_ix: usize,
    ) -> Option<&'static arinsal_beamasm::bif::ExportEntry> {
        if code_ix >= arinsal_beamasm::bif::ERTS_ADDRESSV_SIZE {
            return None;
        }
        self.code
            .with_tables_for_code_ix(code_ix, |tables| tables.exports.dispatch(mfa))
            .flatten()
    }
}

/// Suspend-monitor pause of one process's receive timeout (erts `ErtsPausedProcTimer`): the
/// number of active suspends holding it and the time spent paused.
pub(crate) struct TimerPause {
    count: u32,
    since: std::time::Instant,
    /// `since` on the virtual clock of a simulated runtime.
    since_ms: u64,
    shift: std::time::Duration,
}

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

/// `max_heap_size` flag. Size 0 disables the check, matching `MAX_HEAP_SIZE_GET`.
///
/// g_proc_sched. Port of erts/emulator/beam/erl_gc.c:3824 (`erts_max_heap_size`), OTP-29.1.1.
#[derive(Clone, Copy, Debug)]
pub(crate) struct MaxHeap {
    pub size: u64,
    pub kill: bool,
    pub log: bool,
    pub include_shared_binaries: bool,
    pub reported: bool,
}

impl Default for MaxHeap {
    fn default() -> Self {
        Self {
            size: 0,
            kill: true,
            log: true,
            include_shared_binaries: false,
            reported: false,
        }
    }
}

/// VM part of one scheduler's data (`ErtsSchedulerData`): the scheduler's code replica and
/// register file, created on its first process turn and kept for the scheduler's lifetime.
///
/// Port of erts/emulator/beam/erl_process.h:687 (struct ErtsSchedulerData_: `registers`,
/// `current_process`) and erl_process.c:5994 (init_scheduler_data), OTP-29.1.1: one per
/// normal, dirty or simulated scheduler, handed down explicitly instead of looked up.
#[derive(Default)]
pub struct SchedulerData {
    executor: Option<Box<Executor>>,
    /// The record and code scopes of this scheduler's runtime are selected on its thread.
    scopes_selected: bool,
    /// `esdp->no` as the allocator numbers it: the allocator index of this scheduler's thread,
    /// read once on its first process turn and handed to the heap of each process it runs.
    alloc_ix: Option<usize>,
}

struct Executor {
    /// `esdp->current_process`, shared with this scheduler thread's NIF hub.
    current_process: crate::natives::nif::CurrentProcess,
    /// The scheduler thread's hub is bound to `current_process`.
    hub_bound: bool,
    vm: Vm,
    /// Native register backing is scheduler-local, as required by x19.
    native_registers: SchedulerRegisters,
}
/// Error text of a remote send attempted without a scheduler context (native code).
pub(crate) const REMOTE_SEND_NEEDS_CONTEXT: &str = "remote send requires a scheduler context";

impl Executor {
    /// Emit the trace events of the native frames a return left, and their return_to events
    /// for the caller at `resume_pc`.
    fn emit_native_return_frames(
        &mut self,
        process: &mut Process,
        ctx: &mut RunCtx<'_, Message>,
        frames: crate::trace::NativeTraceFrames,
        value: Term,
        resume_pc: usize,
    ) -> Result<(), VmError> {
        for (function_pc, actions) in frames {
            let Some(function) = crate::native_function_at(function_pc) else {
                continue;
            };
            crate::trace::native_return_events(
                &mut self.vm,
                process,
                ctx,
                &function,
                &actions,
                value,
                false,
            )?;
            for action in actions.iter().filter(|action| action.return_to) {
                crate::trace::native_return_to_event(
                    &mut self.vm,
                    process,
                    ctx,
                    action.session,
                    resume_pc,
                )?;
            }
        }
        Ok(())
    }

    fn run(
        &mut self,
        process: &mut Process,
        ctx: &mut RunCtx<'_, Message>,
        budget: u32,
    ) -> Result<RunState, VmError> {
        process.header.self_pid = ctx.pid().to_term().expect("valid pid").tagged_word();
        process.self_pid = Some(ctx.pid());
        // Port of erts/emulator/beam/erl_process.c:10180 (erts_schedule: esdp->current_process
        // = p), OTP-29.1.1. A simulated scheduler shares its thread with other runtimes, so
        // it binds the thread's hub on every turn.
        if self.hub_bound && !ctx.simulated() {
            self.current_process
                .store(ctx.pid().data(), Ordering::Relaxed);
        } else {
            self.hub_bound =
                crate::natives::nif::bind_scheduler_hub(process, &self.current_process);
        }
        process.scheduler_id = ctx.scheduler_id().map_or(0, |id| id as u32);
        // Port of erts/emulator/beam/erl_process.h:2595 (erts_proc_sched_data): the process
        // turn uses the scheduler thread's reference and unique-integer counters.
        let thr = arinsal_bifs::scheduler_thr_id(
            ctx.scheduler_id().map(|id| id as u32),
            ctx.scheduler_count() as u32,
        );
        if process
            .scheduler_ref_state
            .as_ref()
            .is_none_or(|state| state.thr_id() != thr)
        {
            process.scheduler_ref_state = Some(arinsal_bifs::bind_scheduler_ref_state(thr));
        }
        let schedule_started = crate::natives::erts_debug::long_schedule_monitored(process)
            .then(std::time::Instant::now);
        // A process runs with the code index active when it is scheduled in. The `in` trace
        // event resolves the current function against it, so this replica must be current
        // first (erts_find_function_from_pc reads the active code index).
        // Port of erts/emulator/beam/jit/arm/process_main.cpp:235-247, OTP-29.1.1.
        self.vm.refresh_code();
        self.vm.sync_module(process.module);
        // Port of erts/emulator/beam/erl_process.c:10539-10543 (schedule-in tests
        // ERTS_TRACE_FLAGS(p) before any trace work), OTP-29.1.1: the process flag word has
        // `proc_flags::TRACE` while the trace table holds an entry for this process.
        if ctx.exit_flags().load(Ordering::Acquire) & proc_flags::TRACE != 0 {
            let running = crate::trace::running_mfa(process, &self.vm, ctx.pid())?;
            let running_fields = [running.unwrap_or(Term::small(0).expect("small zero"))];
            crate::trace::emit(
                Some(&mut self.vm),
                process,
                ctx,
                ctx.pid(),
                crate::trace::RUNNING,
                "in",
                &running_fields,
            );
            // Port of erts/emulator/beam/erl_process.c:10541-10543 (trace_schedule_in),
            // OTP-29.1.1.
            if crate::trace::flags(process, ctx.pid()) & crate::trace::CALL != 0 {
                crate::trace_bp::schedule_time_break(process, ctx.pid(), false);
            }
        }
        // Port of erts/emulator/beam/erl_process.c:10435 (`p->fcalls = reds`), OTP-29.1.1.
        // A normal slice replaces leftover FCALLS so the send after a code-permission
        // release is not skipped by a reduction check that still sees only a few: that
        // yield lets the waiter run and send `{Pid, locked}` first.
        // A 1-reduction quantum is the scheduler budget that splits `loop_rec` from
        // `wait`. Light BIFs do `subs FCALLS, #1; b.le yield` and resume at the same
        // entry (instr_bif.cpp:399-400, OTP-29.1.1), so installing FCALLS=1 never
        // enters the BIF. Leave a positive count alone in that case.
        let reds = budget.min(i32::MAX as u32) as i32;
        if process.native_pc.is_some() {
            if reds > 1 || process.reductions <= 0 {
                process.reductions = reds;
            }
        } else if process.reductions <= 0 && reds > 0 {
            // Interpreted schedule-in. A trapping BIF charges FCALLS to 0 when it
            // yields; the continuation (lists:member/2) reads that counter as its
            // scan budget. Leaving it at 0 makes every resume yield without
            // scanning, and the process never reaches halt.
            process.reductions = reds;
        }
        // Port of erts/emulator/beam/erl_process.c:13152 (erl_create_process, sets I to the
        // export's code address), OTP-29.1.1: every process starts its function natively on
        // its first run; later runs continue wherever its interpreted or native continuation is.
        // erts starts a spawned process at beam_run_process; its first run applies the MFA.
        if !process.entry_started && process.module == RUN_PROCESS {
            match crate::beamasm_integration::run_process_entry()
                .filter(|_| crate::beamasm_integration::enabled())
            {
                // The native start is the beam_run_process stub, which applies X0..X2 itself. The
                // process meanwhile holds erlang:apply/3 with those arguments, so the stub's
                // interpreter fallback runs there (native_bridge.rs apply3 resolver).
                Some((start, _)) => {
                    let (module_id, entry) = erlang_apply_entry(&mut self.vm)?;
                    process.module = module_id;
                    process.ip = entry;
                    process.native_pc = Some(start);
                }
                None => {
                    self.vm.resolve_run_process(process)?;
                }
            }
        }
        let first_run = !std::mem::replace(&mut process.entry_started, true);
        if first_run
            && process.native_pc.is_none()
            && let Some(module) = self.vm.code.modules.get(process.module)
            && let Some((function, arity)) = module.function_at(process.ip)
            && module.entry_arity.get(process.ip).copied().unwrap_or(0) != 0
            // The entry belongs to the module instance the process was spawned in; another
            // loaded version of the same module (old or current) has its own code. A module
            // loaded for the interpreter only may have native functions registered separately.
            && let Some(start) = match self
                .vm
                .code
                .code_meta
                .get(process.module)
                .and_then(|meta| meta.as_ref())
                .and_then(|meta| meta.beamasm.as_ref())
            {
                // Port of erts/emulator/beam/erl_process.c:13152 (erl_create_process: I is the
                // export's address), OTP-29.1.1: an exported entry starts at its export's
                // native address when that address belongs to the spawned module instance.
                Some(version) => module
                    .function_atom_at(process.ip)
                    .and_then(|(function, arity)| {
                        crate::beamasm_integration::export_native_target(
                            self.vm.code_scope,
                            module.name_atom,
                            function,
                            arity,
                        )
                    })
                    .filter(|&address| version.contains_code(address))
                    .or_else(|| version.native_function_start(function, arity)),
                None => {
                    crate::native_function_for(self.vm.code_scope, &module.name, function, arity)
                        .map(|native| native.start)
                }
            }
        {
            process.native_pc = Some(start);
        }
        let need_x = self.vm.code.registers[process.module].0;
        if need_x > crate::proc_create::ATTACHED_X_REGS {
            return Err(VmError::Unsupported(format!(
                "module needs {need_x} X registers, the scheduler array has {}",
                crate::proc_create::ATTACHED_X_REGS
            )));
        }
        // Port of erts/emulator/beam/jit/arm/process_main.cpp (copy_in_registers) and
        // erl_process.c (erts_schedule), OTP-29.1.1: the scheduler's one X register array is
        // the process's file for the slice, loaded with the `c_p->arity` saved registers.
        let saved_len = process.x.saved_arity();
        // SAFETY: `self.native_registers` lives in this boxed `Executor`, which is not moved
        // or dropped during the call, and the epilogue below detaches before `run` returns.
        unsafe { process.x.attach(&mut self.native_registers) };
        if crate::xreg_poison_enabled() {
            process.x[saved_len..].fill(crate::XREG_POISON);
        }
        let result = (|| -> Result<RunState, VmError> {
            'execution: {
                // Port of erts/emulator/beam/erl_process.c:12940-13152 (erl_create_process), OTP-29.1.1.
                // A spawned MFA may name a BIF directly; execute it as the process entry so
                // exceptions such as exit/1 retain their BIF class and reason.
                let (initial_bif, dirty_sys_gc) = match process.cold.as_deref_mut() {
                    Some(cold) => (cold.initial_bif.take(), cold.dirty_sys_gc),
                    None => (None, false),
                };
                if let Some((module, function, arity)) = initial_bif {
                    // Both spawn paths (erl_create_process and the distributed spawn) place the
                    // BIF's arguments in X0..X(arity-1); the entry runs the BIF on them.
                    let mut args = process.x[..usize::from(arity)].to_vec();
                    let Some(bif) = arinsal_bifs::lookup(&module, &function, arity) else {
                        // A BIF implemented by a VM native (process-aware BIFs such as
                        // erlang:node/1 or register/2) runs through the native table.
                        let resolved = crate::natives::classify(&module, &function, arity, true);
                        match self.vm.dispatch_native(
                            process,
                            ctx,
                            &module,
                            &function,
                            usize::from(arity),
                            resolved,
                        ) {
                            Some(Ok(value)) => break 'execution Ok(RunState::Done(value)),
                            Some(Err(error)) => break 'execution Err(error),
                            None => {
                                break 'execution Err(VmError::Unsupported(format!(
                                    "spawned BIF entry {module}:{function}/{arity} has no native"
                                )));
                            }
                        }
                    };
                    let mut result = crate::calls::call_bif(
                        &mut process.heap,
                        &mut process.reductions,
                        bif,
                        &args,
                    );
                    crate::calls::gc_after_bif(process, &mut args, &mut result)?;
                    match result {
                        Ok(value) => break 'execution Ok(RunState::Done(value)),
                        Err(error) => {
                            break 'execution Err(crate::exceptions::direct_bif_error(
                                process, &module, &function, &args, error,
                            ));
                        }
                    }
                }
                // Port of erts/emulator/beam/erl_process.c:10318-10372 (ERTS_PSFLG_RUNNING_SYS:
                // handle signals and execute system tasks before Erlang code), OTP-29.1.1.
                // Port of erts/emulator/beam/erl_process.c:10363-10372 and 11018-11040
                // (a dirty scheduler executes the dirty GC system task, then the process
                // returns to a normal scheduler), OTP-29.1.1.
                if dirty_sys_gc {
                    if !ctx.scheduler_type().is_dirty() {
                        // ERTS_PSFLG_DIRTY_ACTIVE_SYS: the dirty work runs before Erlang code.
                        break 'execution Err(VmError::Dirty(arinsal_sched::DirtyKind::Cpu));
                    }
                    process.cold_mut().dirty_sys_gc = false;
                    process.run_dirty_gc()?;
                    // The signals are handled on the normal scheduler the process returns to.
                    break 'execution Ok(RunState::Yield);
                }
                // Port of erts/emulator/beam/erl_process.c:10318-10351 (schedule: a process
                // with signals queued handles them before Erlang code; with Erlang work to do
                // and no dirty work, at most ERTS_SIG_HANDLE_REDS_MAX_PREFERED), OTP-29.1.1.
                // A process parked on a request reply reads it from its message queue like
                // erts_internal:await_result's receive, so the reply message is fetched here.
                if ctx.sys_task_run()
                    || !process.sig_cont_empty()
                    || process.delayed_gc_due()
                    || ctx.has_pending_nmsg()
                    // A cross-process BIF's reply arrives as a message that only this fetch
                    // moves into the message queue.
                    || process.pending_signal_waiter.is_some()
                {
                    let reds = i32::try_from(ctx.remaining()).unwrap_or(i32::MAX);
                    let mut sig_reds =
                        if process.cold.as_ref().is_some_and(|cold| cold.dirty_sys_gc) {
                            reds
                        } else {
                            SIG_HANDLE_REDS_MAX_PREFERED
                        };
                    if ctx.sys_task_run() {
                        process.cold_mut().sys_task_point = true;
                    }
                    let max_reds = sig_reds;
                    let handled = process.handle_incoming(ctx, &mut sig_reds, max_reds, false);
                    ctx.consume(u32::try_from(sig_reds).unwrap_or(0));
                    // Port of erts/emulator/beam/erl_process.c (schedule: `reds -= sig_reds`,
                    // then `p->fcalls = reds`; the process's reductions are what the slice
                    // used), OTP-29.1.1: the signal handling is the process's own work.
                    process.reductions = process.reductions.saturating_sub(sig_reds.max(0));
                    process.reductions_used = process
                        .reductions_used
                        .saturating_add(u64::try_from(sig_reds).unwrap_or(0));
                    let executed = handled.and_then(|_| {
                        if ctx.sys_task_run() {
                            crate::signals::execute_sys_tasks(process, ctx)
                        } else {
                            Ok(())
                        }
                    });
                    if ctx.sys_task_run() {
                        process.cold_mut().sys_task_point = false;
                    }
                    executed?;
                }
                // erts collects a process that is being scheduled in once signals have
                // been fetched (erl_process.c:10415). One check per slice: later
                // iterations have already executed and their live X count is gc_live,
                // not the switch-out arity.
                let mut schedule_in_gc = true;
                // Native code that exited only for a fetch reenters without a scheduling point.
                let mut reenter = false;
                loop {
                    // Port of erts/emulator/beam/erl_process.c (schedule: the scheduler-type
                    // switch; check_dirty_enqueue_in_prio_queue), OTP-29.1.1: a process whose dirty NIF has not run yet carries its
                    // ERTS_PSFLG_DIRTY_*_PROC flag, so it executes only on that dirty scheduler
                    // class and every other scheduler sends it back to the dirty run queue.
                    // Yielding or running here would resume the dirty-NIF dispatch stub as if
                    // it were an unresolved export.
                    let pending_dirty = process
                        .cold
                        .as_ref()
                        .and_then(|cold| cold.native_dirty_nif)
                        .map(|(_, _, class)| class);
                    let dirty_here = pending_dirty
                        .is_some_and(|class| class == scheduler_class(ctx.scheduler_type()));
                    match pending_dirty {
                        Some(arinsal_bifs::SchedulerClass::DirtyCpu) if !dirty_here => {
                            break Err(VmError::Dirty(arinsal_sched::DirtyKind::Cpu));
                        }
                        Some(arinsal_bifs::SchedulerClass::DirtyIo) if !dirty_here => {
                            break Err(VmError::Dirty(arinsal_sched::DirtyKind::Io));
                        }
                        _ => {}
                    }
                    let reentered = std::mem::take(&mut reenter);
                    if !dirty_here && !reentered {
                        // A caught exception re-enters this loop without replenishing its process slice.
                        if ctx.remaining() == 0 {
                            break Ok(RunState::Yield);
                        }
                        if process.force_yield {
                            process.force_yield = false;
                            break Ok(RunState::Yield);
                        }
                        // g_proc_sched: a suspended process is not scheduled; a hibernating
                        // one stays waiting until a message arrives, then continues at apply/3.
                        if let Some(wait) = self.sched_preempt(process, ctx)? {
                            break Ok(wait);
                        }
                    }
                    if let Some(cold) = process.cold.as_mut() {
                        cold.native_transfer = false;
                    }
                    crate::dist::continue_fragmented_send(process, ctx)?;
                    // Port of erts/emulator/beam/erl_nif.c (erts_call_dirty_nif), OTP-29.1.1:
                    // the dirty scheduler runs the NIF, then the process returns to a normal
                    // scheduler to continue after the call.
                    if let Some((identity, resume_pc, class)) =
                        process.cold.as_ref().and_then(|cold| cold.native_dirty_nif)
                        && scheduler_class(ctx.scheduler_type()) == class
                    {
                        process.cold_mut().native_dirty_nif = None;
                        match crate::native_helpers::run_static_nif(process, identity) {
                            Ok(value) => {
                                process.x[0] = value;
                                process.native_continuation_resume = true;
                                process.set_native_resume_arity(1);
                                process.native_pc = Some(resume_pc);
                                if ctx.scheduler_type().is_dirty() {
                                    break Ok(RunState::Yield);
                                }
                                continue;
                            }
                            Err(error @ (VmError::Dirty(_) | VmError::Yield)) => {
                                // A continuation scheduled for another scheduler class.
                                let class = match error {
                                    VmError::Dirty(arinsal_sched::DirtyKind::Cpu) => {
                                        arinsal_bifs::SchedulerClass::DirtyCpu
                                    }
                                    VmError::Dirty(arinsal_sched::DirtyKind::Io) => {
                                        arinsal_bifs::SchedulerClass::DirtyIo
                                    }
                                    _ => arinsal_bifs::SchedulerClass::Normal,
                                };
                                process.cold_mut().native_dirty_nif =
                                    Some((identity, resume_pc, class));
                                break Err(error);
                            }
                            Err(VmError::Trap(trap)) => {
                                if let Some(error) = crate::exceptions::resume(
                                    &mut self.vm,
                                    process,
                                    Some(ctx),
                                    trap,
                                )? {
                                    break Err(error);
                                }
                                continue;
                            }
                            Err(error) => break Err(error),
                        }
                    }
                    if process.force_yield {
                        process.force_yield = false;
                        break Ok(RunState::Yield);
                    }
                    if process.native_pc
                        == Some(crate::native_bridge::native_trace_return_address())
                    {
                        // The interpreter returned into a traced native function's return
                        // frame: finish the frame here, as the stub does for native returns.
                        // Port of erts/emulator/beam/jit/arm/instr_trace.cpp:152-195,
                        // OTP-29.1.1.
                        process.native_pc = None;
                        let value = process.x[0];
                        let popped = crate::trace::pop_native_trace_frames(process, |p, words| {
                            p.heap.release_stack(words);
                        });
                        let Some((frames, caller)) = popped else {
                            break Err(VmError::Unsupported("native trace frame".into()));
                        };
                        let resume_pc = caller.tagged_word() as usize;
                        self.emit_native_return_frames(process, ctx, frames, value, resume_pc)?;
                        let bridge =
                            arinsal_beamasm::rt::arinsal_enter_native_return as *const () as usize;
                        if resume_pc == bridge {
                            if !resume_after_native_return(process) {
                                break Ok(RunState::Done(process.x[0]));
                            }
                        } else {
                            process.native_continuation_resume = true;
                            process.set_native_resume_arity(1);
                            process.native_pc = Some(resume_pc);
                        }
                        continue;
                    }
                    if let Some(code_ptr) = process.native_pc {
                        crate::beamasm_integration::count_native_call();
                        if schedule_in_gc {
                            schedule_in_gc = false;
                            collect_on_schedule_in(process)?;
                        }
                        process.native_pc = None;
                        let trace_boot = trace_boot_enabled();
                        let function = trace_boot
                            .then(|| crate::native_function_at(code_ptr))
                            .flatten();
                        if trace_boot {
                            eprintln!("arinsal boot: enter native {:?} pc={code_ptr:#x}", function);
                            if function.as_ref().is_some_and(|f| {
                                f.module == "prim_file" && f.function == "decode_path"
                            }) {
                                eprintln!(
                                    "arinsal boot: decode_path input={:?}",
                                    process.x.first()
                                );
                            }
                        }
                        // A native call to a BIF that parked the process (cross-process signal
                        // reply) is redone once the process wakes, like the interpreter re-executes
                        // the call instruction.
                        let retry = process
                            .cold
                            .as_mut()
                            .and_then(|cold| cold.native_retry.take());
                        let outcome = if let Some(target_pc) = retry {
                            if let Some(call_arity) =
                                retry_call_arity(target_pc, process.x.saved_arity())
                            {
                                process.header.arity = call_arity;
                            }
                            if process
                                .cold
                                .as_ref()
                                .and_then(|cold| cold.bif_trap.as_ref())
                                .is_some_and(|pending| {
                                    !pending.schedule_out && pending.import == target_pc
                                })
                            {
                                crate::native_helpers::debug_assert_native_heap(process);
                            }
                            // The redone call keeps its return address and call site, so a BIF
                            // that fails after trapping raises at the original call.
                            let (resume_pc, call_site_pc) = process
                                .cold
                                .as_mut()
                                .and_then(|cold| cold.native_retry_site.take())
                                .unwrap_or((0, 0));
                            if call_site_pc != 0 {
                                process.native_error_pc = call_site_pc;
                            }
                            arinsal_beamasm::ExitReason::CallUnported {
                                target_pc,
                                resume_pc,
                            }
                        } else {
                            // Port of erts/emulator/beam/erl_process.c (schedule: reductions
                            // used = CONTEXT_REDS - FCALLS), OTP-29.1.1: native code counts down
                            // FCALLS; the scheduler charges what it used.
                            // FCALLS and the scheduler budget are one counter in erts. A BIF
                            // charge can zero the process counter while the slice still
                            // has reductions; refilling avoids yielding before the next
                            // instruction (the send after a code-permission release).
                            if process.reductions <= 0
                                && let Ok(remaining) = i32::try_from(ctx.remaining())
                                && remaining > 0
                            {
                                process.reductions = remaining;
                            }
                            let fcalls_before = process.reductions;
                            // A code change this scheduler committed waits for thread
                            // progress first: every other scheduler then finishes the slice it
                            // runs with the previous code index (erts' code barrier).
                            if crate::code_ix::take_code_barrier() {
                                ctx.block_thread_progress(std::time::Duration::ZERO);
                            }
                            self.native_registers.active_code_ix = self
                                .vm
                                .code_ix
                                .process_code_ix(crate::trace::saves_calls(process))
                                as u64;
                            let native =
                                crate::run_native(process, &mut self.native_registers, code_ptr);
                            let consumed = fcalls_before.saturating_sub(process.reductions);
                            ctx.consume(u32::try_from(consumed).unwrap_or(0));
                            // Native `timeout` has no scheduler context to send its trace event.
                            if process.native_exit_kind != crate::proc_create::NativeExit::None
                                && process.cold.as_mut().is_some_and(|cold| {
                                    std::mem::take(&mut cold.native_timeout_trace)
                                })
                            {
                                crate::trace::timeout_event(Some(&mut self.vm), process, ctx);
                            }
                            // Port of erts/emulator/beam/erl_process.c (erts_current_reductions),
                            // OTP-29.1.1: the process's reduction count includes what its
                            // native code consumed from FCALLS.
                            // Reductions the slice gave up with `ERTS_VBUMP_ALL_REDS` ended
                            // the slice but are not the process's own.
                            let virtual_reds = std::mem::take(&mut process.virtual_reds);
                            process.reductions_used = process.reductions_used.saturating_add(
                                u64::try_from(consumed)
                                    .unwrap_or(0)
                                    .saturating_sub(u64::from(virtual_reds)),
                            );
                            match native {
                                Ok(outcome) => outcome,
                                Err(VmError::Trap(trap)) => {
                                    if let Some(error) = crate::exceptions::resume(
                                        &mut self.vm,
                                        process,
                                        Some(ctx),
                                        trap,
                                    )? {
                                        process.header.freason = 0;
                                        process.header.fvalue = 0;
                                        break Err(error);
                                    }
                                    process.header.freason = 0;
                                    process.header.fvalue = 0;
                                    if let Some(cold) = process.cold.as_mut() {
                                        cold.exit_reason = None;
                                    }
                                    continue;
                                }
                                Err(error) => return Err(error),
                            }
                        };
                        if trace_boot
                            && function.as_ref().is_some_and(|f| {
                                f.module == "prim_file" && f.function == "decode_path"
                            })
                        {
                            eprintln!(
                                "arinsal boot: decode_path exit={outcome:?} output={:?}",
                                process.x.first()
                            );
                        }
                        match outcome {
                            arinsal_beamasm::ExitReason::Yield => {
                                crate::beamasm_integration::count_native_yield();
                                let exit_kind = std::mem::take(&mut process.native_exit_kind);
                                if exit_kind != crate::proc_create::NativeExit::None {
                                    if exit_kind == crate::proc_create::NativeExit::ReserveFetch {
                                        // Native `recv_marker_reserve` needs the outer queue
                                        // fetched first. Port of erts/emulator/beam/
                                        // erl_proc_sig_queue.h:2226 (erts_msgq_recv_marker_insert),
                                        // OTP-29.1.1: fetch (no handling), then rerun the
                                        // instruction in place: erts does not schedule out there.
                                        if process
                                            .cold
                                            .as_ref()
                                            .is_some_and(|cold| cold.signal_probe.is_none())
                                        {
                                            process.cold_mut().signal_probe = ctx.signal_probe();
                                        }
                                        process.fetch_signals(ctx)?;
                                        reenter = true;
                                        continue;
                                    }
                                    if exit_kind == crate::proc_create::NativeExit::SignalFetch {
                                        // Native `loop_rec` reached the end of the message queue
                                        // with signals to fetch or handle. Port of
                                        // erts/emulator/beam/jit/arm/instr_msg.cpp:84-104
                                        // (i_loop_rec_shared calls erts_proc_sig_receive_helper),
                                        // OTP-29.1.1: the helper runs here, then the `loop_rec`
                                        // reruns; a yield schedules out there.
                                        if process
                                            .cold
                                            .as_ref()
                                            .is_some_and(|cold| cold.signal_probe.is_none())
                                        {
                                            process.cold_mut().signal_probe = ctx.signal_probe();
                                        }
                                        let fcalls =
                                            i32::try_from(ctx.remaining()).unwrap_or(i32::MAX);
                                        let (used, _) = process.receive_helper(ctx, fcalls)?;
                                        let used = u32::try_from(used).unwrap_or(0);
                                        ctx.consume(used);
                                        process.reductions_used =
                                            process.reductions_used.saturating_add(u64::from(used));
                                        continue;
                                    }
                                    if exit_kind == crate::proc_create::NativeExit::Wait
                                        && let Some(timeout_ms) = process
                                            .cold
                                            .as_mut()
                                            .and_then(|cold| cold.native_wait.take())
                                    {
                                        // A native receive found no matching message. Like the
                                        // interpreter's `wait`, sleep only if nothing arrived since the
                                        // slice began; the process resumes at the `loop_rec` label with
                                        // no live X registers.
                                        process.gc_live = 0;
                                        process.set_native_resume_arity(0);
                                        // A receive without clauses blocks even with messages queued,
                                        // like the interpreter's self-targeting `wait`.
                                        let self_wait = std::mem::take(
                                            &mut process.cold_mut().native_wait_self,
                                        );
                                        if self_wait {
                                            // Queued messages never match; fetch them so the outer
                                            // queue does not keep waking the process.
                                            process.fetch_signals(ctx)?;
                                        } else if !Vm::mailbox_ready_to_wait(
                                            process,
                                            &mut Some(&mut *ctx),
                                        )? {
                                            continue;
                                        }
                                        break Ok(RunState::Wait { timeout_ms });
                                    }
                                }
                                // A native `i_yield` is a scheduler boundary even when the
                                // interpreter left a deferred yield request in the process.
                                // Port of erts/emulator/beam/erl_process.c:10550
                                // (trace_schedule_out), OTP-29.1.1.
                                process.force_yield = false;
                                break Ok(RunState::Yield);
                            }
                            arinsal_beamasm::ExitReason::CallUnported {
                                target_pc,
                                resume_pc,
                            } => {
                                crate::beamasm_integration::count_call_unported();
                                // The native call site names the caller only if the called BIF
                                // raises; any other continuation must not inherit it.
                                let call_site_pc = std::mem::take(&mut process.native_error_pc);
                                process.cold_mut().native_retry_site =
                                    Some((resume_pc, call_site_pc));
                                if target_pc
                                    == arinsal_beamasm::dispatch::RETURN_TO_DISPATCH_IDENTITY
                                {
                                    // A traced native return: its return_from events are out
                                    // and its frame is gone; resume_pc is the caller.
                                    if let Some((frames, value)) = process
                                        .cold_mut()
                                        .native_return_events
                                        .take()
                                        .map(|boxed| *boxed)
                                    {
                                        self.emit_native_return_frames(
                                            process, ctx, frames, value, resume_pc,
                                        )?;
                                    }
                                    let bridge = arinsal_beamasm::rt::arinsal_enter_native_return
                                        as *const ()
                                        as usize;
                                    if resume_pc == bridge {
                                        if !resume_after_native_return(process) {
                                            break Ok(RunState::Done(process.x[0]));
                                        }
                                    } else {
                                        process.native_continuation_resume = true;
                                        process.set_native_resume_arity(1);
                                        process.native_pc = Some(resume_pc);
                                    }
                                    continue;
                                }
                                if target_pc
                                    == arinsal_beamasm::dispatch::DIRTY_NIF_DISPATCH_IDENTITY
                                {
                                    // The NIF body's return point resumes once the dirty
                                    // scheduler ran the NIF.
                                    if process.heap.stack_get(0).is_some_and(|word| {
                                        word.tagged_word() as usize == resume_pc
                                    }) {
                                        process.heap.release_stack(1);
                                    }
                                    let cold = process.cold_mut();
                                    let class =
                                        cold.native_dirty_nif.as_mut().map(|(_, resume, class)| {
                                            *resume = resume_pc;
                                            *class
                                        });
                                    break Err(match class {
                                        Some(arinsal_bifs::SchedulerClass::DirtyCpu) => {
                                            VmError::Dirty(arinsal_sched::DirtyKind::Cpu)
                                        }
                                        Some(arinsal_bifs::SchedulerClass::Normal) => {
                                            VmError::Yield
                                        }
                                        _ => VmError::Dirty(arinsal_sched::DirtyKind::Io),
                                    });
                                }
                                if let Some((line, live)) =
                                    arinsal_beamasm::dispatch::decode_line_breakpoint_identity(
                                        target_pc,
                                    )
                                {
                                    // Port of erts/emulator/beam/beam_bp.c:1821-1865
                                    // (erts_line_breakpoint_hit__prepare_call), OTP-29.1.1:
                                    // spill the live X registers, then call
                                    // erts_internal:breakpoint/4; the native code at
                                    // `resume_pc` restores them when it returns.
                                    let function =
                                        crate::native_function_at(resume_pc).ok_or_else(|| {
                                            VmError::Unsupported(format!(
                                                "native line breakpoint resume address is unregistered: {resume_pc:#x}"
                                            ))
                                        })?;
                                    if process.heap.stack_get(0).is_some_and(|word| {
                                        word.tagged_word() as usize == resume_pc
                                    }) {
                                        process.heap.release_stack(1);
                                    }
                                    let live = usize::from(live);
                                    let handler =
                                        self.vm.load_named("erts_internal").is_ok_and(|id| {
                                            self.vm.code.modules[id].functions.iter().any(
                                                |(_, name, arity)| {
                                                    name == "breakpoint" && *arity == 4
                                                },
                                            )
                                        });
                                    // The handler's own breakpoints are not reported.
                                    let cycle = function.module == "erts_internal"
                                        && function.function == "breakpoint"
                                        && function.arity == 4;
                                    // Port of erts/emulator/beam/emu/instrs.tab:1269-1286
                                    // (i_enabled_line_breakpoint), OTP-29.1.1: the frame's own
                                    // return address, then the spilled registers above it.
                                    let site = crate::beamasm_integration::line_breakpoint_site(
                                        resume_pc,
                                    )
                                    .ok_or_else(|| {
                                        VmError::Unsupported(format!(
                                            "native line breakpoint site is unregistered: {resume_pc:#x}"
                                        ))
                                    })?;
                                    // Port of erts/emulator/beam/jit/arm/beam_asm_module.cpp:276-292
                                    // (emit_i_line_breakpoint_trampoline_shared), OTP-29.1.1:
                                    // collect when the spilled registers and S_RESERVED do not fit.
                                    process.ensure(live + 2 + arinsal_term::S_RESERVED, live)?;
                                    if !process.heap.reserve_stack(1)
                                        || !process.heap.stack_set(
                                            0,
                                            crate::proc_create::native_continuation_term(site),
                                        )
                                        || !process.heap.reserve_stack(live)
                                    {
                                        break Err(VmError::Unsupported(
                                            "line breakpoint stack is full".into(),
                                        ));
                                    }
                                    for index in 0..live {
                                        let value = process.x[index];
                                        if !process.heap.stack_set(index, value) {
                                            break;
                                        }
                                    }
                                    if !handler || cycle {
                                        process.native_continuation_resume = true;
                                        process.set_native_resume_arity(1);
                                        process.native_pc = Some(resume_pc);
                                        continue;
                                    }
                                    if !process.heap.reserve_stack(1)
                                        || !process.heap.stack_set(
                                            0,
                                            crate::proc_create::native_continuation_term(resume_pc),
                                        )
                                    {
                                        break Err(VmError::Unsupported(
                                            "line breakpoint stack is full".into(),
                                        ));
                                    }
                                    let module_atom = arinsal_term::global_atoms()
                                        .intern(&function.module)
                                        .map_err(|_| VmError::Unsupported("atom table".into()))?;
                                    let function_atom = arinsal_term::global_atoms()
                                        .intern(&function.function)
                                        .map_err(|_| VmError::Unsupported("atom table".into()))?;
                                    let handler_module = arinsal_term::global_atoms()
                                        .intern("erts_internal")
                                        .map_err(|_| VmError::Unsupported("atom table".into()))?;
                                    let handler_function = arinsal_term::global_atoms()
                                        .intern("breakpoint")
                                        .map_err(|_| VmError::Unsupported("atom table".into()))?;
                                    process.x[0] = Term::atom(module_atom);
                                    process.x[1] = Term::atom(function_atom);
                                    process.x[2] = Term::small(i64::from(function.arity))
                                        .expect("arity is a small integer");
                                    process.x[3] = Term::small(i64::from(line))
                                        .expect("line is a small integer");
                                    process.x[4] = Term::atom(handler_module);
                                    process.x[5] = Term::atom(handler_function);
                                    process.gc_live = 4;
                                    process.cold_mut().native_apply = true;
                                    let result =
                                        self.vm.apply_fixed(process, 4, true, 0, Some(ctx));
                                    process.cold_mut().native_apply = false;
                                    match result? {
                                        crate::ImportOutcome::Jump(_) => {
                                            self.vm.enter_native_at_jump(process)
                                        }
                                        crate::ImportOutcome::Advanced => {}
                                        crate::ImportOutcome::Yield => {
                                            if process.native_pc.is_some()
                                                && native_transfer_continues(process, ctx)
                                            {
                                                continue;
                                            }
                                            break Ok(RunState::Yield);
                                        }
                                        crate::ImportOutcome::Returned(value) => {
                                            process.x[0] = value;
                                            if process.native_pc.is_none() {
                                                break Ok(RunState::Done(value));
                                            }
                                        }
                                    }
                                    continue;
                                }
                                if target_pc
                                    == arinsal_beamasm::dispatch::BREAKPOINT_DISPATCH_IDENTITY
                                {
                                    // Port of erts/emulator/beam/beam_bp.c (erts_generic_breakpoint),
                                    // OTP-29.1.1: count, then call/meta events in the interpreter's
                                    // order; the trap's CP is the native resume point.
                                    let function =
                                        crate::native_function_at(resume_pc).ok_or_else(|| {
                                            VmError::Unsupported(format!(
                                                "native breakpoint resume address is unregistered: {resume_pc:#x}"
                                            ))
                                        })?;
                                    if process.heap.stack_get(0).is_some_and(|word| {
                                        word.tagged_word() as usize == resume_pc
                                    }) {
                                        process.heap.release_stack(1);
                                    }
                                    // The trace callbacks read every argument from the scheduler
                                    // array, which is the process's X file.
                                    let arity = usize::from(function.arity).min(process.x.len());
                                    let actions = crate::trace::executor_native_call_event(
                                        &mut self.vm,
                                        process,
                                        ctx,
                                        &function,
                                    )?;
                                    crate::trace::push_native_trace_frame(
                                        process, resume_pc, &actions, arity,
                                    )?;
                                    process.native_continuation_resume = true;
                                    // Port of erts/emulator/beam/jit/arm/instr_trace.cpp (the
                                    // breakpoint stub saves the function's arguments in
                                    // `c_p->arity`), OTP-29.1.1: a collection while the process
                                    // is switched out, such as a delayed dirty one, roots them.
                                    process.set_native_resume_arity(function.arity);
                                    process.gc_live = usize::from(function.arity);
                                    process.native_pc = Some(resume_pc);
                                    // A loop of traced calls leaves native code on every call and
                                    // would never reach the end-of-slice check: preempt here once
                                    // the budget is used up (erts counts reductions per call).
                                    // The breakpoint left native code before its call's reduction was
                                    // charged.
                                    process.reductions = process.reductions.saturating_sub(1);
                                    process.reductions_used =
                                        process.reductions_used.saturating_add(1);
                                    if !ctx.consume(1) || process.reductions <= 0 {
                                        break Ok(RunState::Yield);
                                    }
                                    continue;
                                }
                                if target_pc == arinsal_beamasm::dispatch::SEND_DISPATCH_IDENTITY {
                                    let value = match process.send_message_prio(
                                        Some(&mut self.vm),
                                        Some(ctx),
                                        process.x[0],
                                        process.x[1],
                                        false,
                                    ) {
                                        Ok(value) => value,
                                        // Port of erts/emulator/beam/bif.c:2581 (SEND_YIELD): a
                                        // busy port suspended the sender; the send is redone
                                        // when it is resumed.
                                        Err(VmError::Trap(_))
                                            if crate::port::take_busy_suspend() =>
                                        {
                                            process.cold_mut().native_retry = Some(target_pc);
                                            process.native_pc = Some(code_ptr);
                                            break Ok(RunState::Wait { timeout_ms: None });
                                        }
                                        Err(error) => return Err(error),
                                    };
                                    // Port of erts/emulator/beam/jit/arm/instr_bif.cpp:612-624
                                    // (emit_send, call_light_bif_shared GC test), OTP-29.1.1.
                                    let value = process.gc_after_bif(value)?;
                                    process.x[0] = value;
                                    if !resume_after_native_return(process) {
                                        break Ok(RunState::Done(value));
                                    }
                                    continue;
                                }
                                if matches!(
                                    target_pc,
                                    arinsal_beamasm::dispatch::CALL_FUN_UNPORTED
                                        | arinsal_beamasm::dispatch::APPLY_FIXED_UNPORTED
                                        | arinsal_beamasm::dispatch::APPLY2_UNPORTED
                                        | arinsal_beamasm::dispatch::APPLY3_UNPORTED
                                ) {
                                    // The fragment pushed the native continuation as a CP, so the
                                    // interpreter performs these as tail calls.
                                    // The retry redoes the apply from its operands: the
                                    // arguments, the fun or module and function, and apply/3's
                                    // three. Registers above them are dead.
                                    let saved_live = (usize::from(process.header.arity) + 2)
                                        .max(3)
                                        .min(process.x.len());
                                    let saved_x = process.x[..saved_live].to_vec();
                                    let collections_before = process.stats.gc.collections;
                                    let result = match target_pc {
                                        arinsal_beamasm::dispatch::CALL_FUN_UNPORTED => {
                                            let arity = usize::from(process.header.arity);
                                            let fun =
                                                process.x.get(arity).copied().unwrap_or(Term::NIL);
                                            self.vm.call_fun_term(
                                                process,
                                                fun,
                                                arity,
                                                true,
                                                Some(ctx),
                                            )
                                        }
                                        _ => {
                                            process.cold_mut().native_apply = true;
                                            let result = match target_pc {
                                                arinsal_beamasm::dispatch::APPLY_FIXED_UNPORTED => {
                                                    let arity = usize::from(process.header.arity);
                                                    self.vm.apply_fixed(
                                                        process,
                                                        arity,
                                                        true,
                                                        0,
                                                        Some(ctx),
                                                    )
                                                }
                                                arinsal_beamasm::dispatch::APPLY2_UNPORTED => self
                                                    .vm
                                                    .apply_bif(process, 2, true, 0, Some(ctx)),
                                                _ => self.vm.apply_bif(
                                                    process,
                                                    3,
                                                    true,
                                                    0,
                                                    Some(ctx),
                                                ),
                                            };
                                            process.cold_mut().native_apply = false;
                                            result
                                        }
                                    };
                                    let trap = match result {
                                        Ok(outcome) => {
                                            match outcome {
                                                crate::ImportOutcome::Jump(_) => {
                                                    self.vm.enter_native_at_jump(process)
                                                }
                                                crate::ImportOutcome::Advanced => {}
                                                crate::ImportOutcome::Yield => {
                                                    if process.native_pc.is_some()
                                                        && native_transfer_continues(process, ctx)
                                                    {
                                                        continue;
                                                    }
                                                    // A trapping BIF yielded with its state pending: the apply is redone with
                                                    // its original operands when the process runs again.
                                                    if process
                                                        .cold
                                                        .as_ref()
                                                        .is_some_and(|cold| cold.bif_trap.is_some())
                                                    {
                                                        // Port of erts/emulator/beam/beam_common.c
                                                        // (BIF_TRAP: the trap export carries its own
                                                        // arguments), OTP-29.1.1: the operands saved
                                                        // before the call are stale once the BIF
                                                        // collected, so the redone apply is rebuilt
                                                        // from the arguments kept in the trap state.
                                                        let pending = process
                                                            .cold
                                                            .as_ref()
                                                            .and_then(|cold| cold.bif_trap.as_ref())
                                                            .map(|pending| {
                                                                (
                                                                    pending.callee,
                                                                    pending.args,
                                                                    pending.arity,
                                                                )
                                                            });
                                                        let retry_pc = if let Some((
                                                            (module, function),
                                                            args,
                                                            arity,
                                                        )) = pending
                                                        {
                                                            let list = {
                                                                let mut heap =
                                                                    arinsal_bifs::ProcessHeapHandle(
                                                                        &mut process.heap,
                                                                    );
                                                                TermBuilder::new(&mut heap)
                                                                    .list_from_slice(&args[..arity])
                                                            };
                                                            match list {
                                                                Ok(list) => {
                                                                    process.x[0] =
                                                                        Term::atom(module);
                                                                    process.x[1] =
                                                                        Term::atom(function);
                                                                    process.x[2] = list;
                                                                    arinsal_beamasm::dispatch::APPLY3_UNPORTED
                                                                }
                                                                Err(_) => {
                                                                    break Err(
                                                                        VmError::Unsupported(
                                                                            "trap state arguments"
                                                                                .into(),
                                                                        ),
                                                                    );
                                                                }
                                                            }
                                                        } else {
                                                            target_pc
                                                        };
                                                        process.cold_mut().native_retry =
                                                            Some(retry_pc);
                                                        process.native_pc = Some(code_ptr);
                                                    }
                                                    break Ok(RunState::Yield);
                                                }
                                                crate::ImportOutcome::Returned(value) => {
                                                    // The applied BIF ran through its export
                                                    // trampoline, which charges the call.
                                                    process.reductions_used =
                                                        process.reductions_used.saturating_add(1);
                                                    process.x[0] = value;
                                                    if process.native_pc.is_none() {
                                                        break Ok(RunState::Done(value));
                                                    }
                                                    if ctx.scheduler_type().is_dirty() {
                                                        break Ok(RunState::Yield);
                                                    }
                                                }
                                            }
                                            continue;
                                        }
                                        // A suspending or yielding applied BIF (busy port,
                                        // cross-process await, ERTS_BIF_YIELD) is redone when
                                        // the process runs again, as for direct native calls.
                                        Err(VmError::Trap(_))
                                            if crate::port::take_busy_suspend() =>
                                        {
                                            for (register, value) in
                                                process.x.iter_mut().zip(&saved_x)
                                            {
                                                *register = *value;
                                            }
                                            process.cold_mut().native_retry = Some(target_pc);
                                            process.native_pc = Some(code_ptr);
                                            break Ok(RunState::Wait { timeout_ms: None });
                                        }
                                        Err(VmError::Unsupported(message))
                                            if crate::signals::is_await_message(&message) =>
                                        {
                                            for (register, value) in
                                                process.x.iter_mut().zip(&saved_x)
                                            {
                                                *register = *value;
                                            }
                                            process.cold_mut().native_retry = Some(target_pc);
                                            process.native_pc = Some(code_ptr);
                                            break Ok(RunState::Wait { timeout_ms: None });
                                        }
                                        Err(VmError::Yield) => {
                                            // A collection the call ran (the epilogue of a
                                            // yielding BIF that allocated) moved the registers;
                                            // the copies taken before it are stale.
                                            if process.stats.gc.collections == collections_before {
                                                for (register, value) in
                                                    process.x.iter_mut().zip(&saved_x)
                                                {
                                                    *register = *value;
                                                }
                                            }
                                            process.cold_mut().native_retry = Some(target_pc);
                                            process.native_pc = Some(code_ptr);
                                            break Ok(RunState::Yield);
                                        }
                                        Err(VmError::Dirty(kind)) => {
                                            for (register, value) in
                                                process.x.iter_mut().zip(&saved_x)
                                            {
                                                *register = *value;
                                            }
                                            process.cold_mut().native_retry = Some(target_pc);
                                            process.native_pc = Some(code_ptr);
                                            break Err(VmError::Dirty(kind));
                                        }
                                        Err(VmError::Trap(trap)) => trap,
                                        Err(VmError::Exception { reason, frame }) => {
                                            legacy_exception_trap(process, &reason, &frame)?
                                        }
                                        // Port of erts/emulator/beam/beam_common.c:1568
                                        // (erts_hibernate), OTP-29.1.1: apply(erlang, hibernate, _)
                                        // discarded the stack like a direct call.
                                        Err(VmError::Unsupported(_))
                                            if hibernate_stopped(process) =>
                                        {
                                            if hibernate_resumes_in_place(process) {
                                                hibernate_fetch_collect(process, ctx)?;
                                                process.cold_mut().native_retry = Some(target_pc);
                                                process.native_pc = Some(code_ptr);
                                                break Ok(RunState::Wait { timeout_ms: None });
                                            }
                                            process.native_pc = None;
                                            process.native_continuation_resume = false;
                                            if hibernate_fetch_collect(process, ctx)? {
                                                if let Some(runtime) = process.runtime.clone() {
                                                    runtime.mark_hibernating(ctx.pid(), true);
                                                    // Port of erts `F_HIBERNATE_SCHED` in `p->flags`: the process tests its own flag.
                                                    process.cold_mut().hibernate_sched = true;
                                                }
                                                break Ok(RunState::Wait { timeout_ms: None });
                                            }
                                            self.install_apply(process, ctx)?;
                                            continue;
                                        }
                                        Err(error) => return Err(error),
                                    };
                                    // Port of erts/emulator/beam/beam_common.c:1345-1427
                                    // (apply_bif_error_adjustment), OTP-29.1.1: the applied
                                    // function raised at the apply instruction, which names the
                                    // calling function; its continuation is not another frame.
                                    if call_site_pc != 0
                                        && target_pc != arinsal_beamasm::dispatch::CALL_FUN_UNPORTED
                                    {
                                        // Port of erts/emulator/beam/jit/arm/instr_call.cpp
                                        // (emit_i_apply_last, OTP-29.1.1): a tail apply has
                                        // deallocated its frame, so a BIF failure other than the
                                        // error/exit/throw adjustment is attributed to the
                                        // continuation it returns to, not to the apply site.
                                        let tail_site = call_site_pc
                                            & arinsal_beamasm::module::RETURN_SITE_TAG
                                            == 0;
                                        let bridge =
                                            arinsal_beamasm::rt::arinsal_enter_native_return
                                                as *const ()
                                                as usize;
                                        process.native_error_pc = if tail_site
                                            && resume_pc != bridge
                                            && matches!(
                                                trap.top,
                                                Some(crate::stacktrace::TopFrame::Bif { module, function, .. })
                                                    if !(global_atoms().text(module) == Some("erlang")
                                                        && global_atoms().text(function) == Some("apply"))
                                            ) {
                                            resume_pc | arinsal_beamasm::module::RETURN_SITE_TAG
                                        } else {
                                            call_site_pc
                                        };
                                        if process.heap.stack_get(0).is_some_and(|word| {
                                            word.tagged_word() as usize == resume_pc
                                        }) {
                                            process.heap.release_stack(1);
                                        }
                                    }
                                    if let Some(error) = crate::exceptions::resume(
                                        &mut self.vm,
                                        process,
                                        Some(ctx),
                                        trap,
                                    )? {
                                        process.header.freason = 0;
                                        process.header.fvalue = 0;
                                        break Err(error);
                                    }
                                    process.header.freason = 0;
                                    process.header.fvalue = 0;
                                    if let Some(cold) = process.cold.as_mut() {
                                        cold.exit_reason = None;
                                    }
                                    continue;
                                }
                                if target_pc == crate::bif_traps::bif_export_trap_pc() {
                                    // Port of jit/arm/beam_asm_global.cpp:145
                                    // (emit_bif_export_trap) and instr_bif.cpp:525-536
                                    // (context_switch_simplified), OTP-29.1.1.
                                    let schedule_out = process
                                        .cold
                                        .as_ref()
                                        .and_then(|cold| cold.bif_trap.as_ref())
                                        .is_some_and(|pending| pending.schedule_out);
                                    if schedule_out {
                                        if let Some(pending) = process
                                            .cold
                                            .as_mut()
                                            .and_then(|cold| cold.bif_trap.as_mut())
                                        {
                                            pending.schedule_out = false;
                                            pending.caller_module = process.module;
                                            pending.caller_ip = process.ip;
                                        }
                                        crate::bif_traps::arm_export_trap(process);
                                        process.cold_mut().native_retry = Some(target_pc);
                                        process.native_pc = Some(code_ptr);
                                        break Ok(RunState::Yield);
                                    }
                                    // Port of erts/emulator/beam/beam_bp.c:321-330 and
                                    // erl_bif_trace.c (the bif return trap frame stays on the
                                    // stack across BIF_TRAP), OTP-29.1.1: the call event of a
                                    // traced BIF that trapped was emitted at the first call; the
                                    // return or exception event belongs to the last slice.
                                    let trapped_callee = process
                                        .cold
                                        .as_ref()
                                        .filter(|cold| cold.traced_native_call.is_some())
                                        .and_then(|cold| cold.bif_trap.as_ref())
                                        .and_then(|pending| {
                                            let atoms = global_atoms();
                                            Some((
                                                atoms.text(pending.callee.0)?.to_owned(),
                                                atoms.text(pending.callee.1)?.to_owned(),
                                                pending.arity,
                                            ))
                                        });
                                    let meter = crate::bif_traps::TrapMeter::start_continuation(
                                        process,
                                        Some(&*ctx),
                                    );
                                    let trapped =
                                        crate::bif_traps::run_trapped_export(process, Some(ctx));
                                    if let Some(Ok(crate::bif_traps::ResumeResult::Handler(
                                        result,
                                    ))) = &trapped
                                    {
                                        meter.finish(process, Some(ctx), result.reductions());
                                    }
                                    if let Some((module, function, arity)) = &trapped_callee {
                                        let outcome = match &trapped {
                                            Some(Ok(crate::bif_traps::ResumeResult::Handler(
                                                crate::bif_traps::HandlerResult::Done {
                                                    value, ..
                                                },
                                            ))) => Some(Ok(*value)),
                                            Some(Err(VmError::Trap(trap))) => {
                                                crate::exceptions::trace_class_reason(
                                                    process,
                                                    trap.class,
                                                    trap.reason,
                                                )
                                                .ok()
                                                .map(Err)
                                            }
                                            _ => None,
                                        };
                                        if let Some(outcome) = outcome {
                                            let args = vec![Term::NIL; *arity];
                                            self.vm.trace_native_return_outcome(
                                                process, ctx, module, function, &args, outcome,
                                            );
                                        }
                                    }
                                    match trapped {
                                        Some(Ok(crate::bif_traps::ResumeResult::Handler(
                                            crate::bif_traps::HandlerResult::Yield { .. },
                                        ))) => {
                                            if let Some(pending) = process
                                                .cold
                                                .as_mut()
                                                .and_then(|cold| cold.bif_trap.as_mut())
                                            {
                                                pending.schedule_out = false;
                                            }
                                            crate::bif_traps::arm_export_trap(process);
                                            process.cold_mut().native_retry = Some(target_pc);
                                            process.native_pc = Some(code_ptr);
                                            break Ok(RunState::Yield);
                                        }
                                        // The trapped BIF's continuation is an Erlang export: it is
                                        // called with the saved arguments, and returns to the caller's
                                        // native continuation. Port of erts/emulator/beam/beam_common.c
                                        // (BIF_TRAP), OTP-29.1.1.
                                        Some(Ok(crate::bif_traps::ResumeResult::Export(trap))) => {
                                            process.cold_mut().native_apply = true;
                                            let outcome = self.vm.trap_to_export(
                                                process,
                                                trap,
                                                true,
                                                Some(ctx),
                                            );
                                            process.cold_mut().native_apply = false;
                                            match outcome? {
                                                crate::ImportOutcome::Jump(_) => {
                                                    self.vm.enter_native_at_jump(process)
                                                }
                                                crate::ImportOutcome::Advanced => {}
                                                crate::ImportOutcome::Yield => {
                                                    if process.native_pc.is_some()
                                                        && native_transfer_continues(process, ctx)
                                                    {
                                                        continue;
                                                    }
                                                    break Ok(RunState::Yield);
                                                }
                                                crate::ImportOutcome::Returned(value) => {
                                                    process.x[0] = value;
                                                    if process.native_pc.is_none() {
                                                        break Ok(RunState::Done(value));
                                                    }
                                                }
                                            }
                                            continue;
                                        }
                                        Some(Ok(crate::bif_traps::ResumeResult::Handler(
                                            crate::bif_traps::HandlerResult::Done { value, .. },
                                        ))) => {
                                            process.x[0] = value;
                                            if !resume_after_native_return(process) {
                                                break Ok(RunState::Done(value));
                                            }
                                            continue;
                                        }
                                        Some(Ok(crate::bif_traps::ResumeResult::Handler(
                                            crate::bif_traps::HandlerResult::Failed { .. },
                                        ))) => {
                                            break Err(VmError::Unsupported(
                                                "failed trapping BIF without exception".into(),
                                            ));
                                        }
                                        // The continuation export raised. It is the same BIF
                                        // failure erts reports with ERTS_BIF_ERROR_TRAPPED:
                                        // catch sees it, and the process does not exit.
                                        Some(Err(VmError::Trap(trap))) => {
                                            process.native_error_pc = call_site_pc;
                                            if process.heap.stack_get(0).is_some_and(|word| {
                                                word.tagged_word() as usize == resume_pc
                                            }) {
                                                process.heap.release_stack(1);
                                            }
                                            if let Some(error) = crate::exceptions::resume(
                                                &mut self.vm,
                                                process,
                                                Some(ctx),
                                                trap,
                                            )? {
                                                break Err(error);
                                            }
                                            process.header.freason = 0;
                                            process.header.fvalue = 0;
                                            continue;
                                        }
                                        Some(Err(error)) => return Err(error),
                                        None => {
                                            break Err(VmError::Unsupported(
                                                "missing BIF trap export".into(),
                                            ));
                                        }
                                    }
                                }
                                let Some(export) =
                                    crate::beamasm_integration::export_dispatch(target_pc)
                                else {
                                    if let Some(m) = self.vm.code.modules.get(process.module)
                                        && target_pc < m.code.len()
                                    {
                                        process.ip = target_pc;
                                        process.tick();
                                        continue;
                                    }
                                    return Err(VmError::Unsupported(format!(
                                        "unknown native export entry {target_pc:#x}"
                                    )));
                                };
                                if trace_boot_enabled() && export.module == "prim_file" {
                                    eprintln!(
                                        "arinsal boot: export dispatch {}:{}/{} class={:?}",
                                        export.module, export.function, export.arity, export.class
                                    );
                                }
                                process.gc_live = usize::from(export.arity);
                                // Like call_import_general: code loaded by another scheduler must be
                                // visible to the BIF (function_exported/3, module_loaded/1, ...).
                                self.vm.refresh_code();
                                if matches!(
                                    export.class,
                                    arinsal_loader::ImportClass::Native
                                        | arinsal_loader::ImportClass::Dynamic
                                        | arinsal_loader::ImportClass::Fun
                                ) || crate::bif_traps::traps(
                                    &export.module,
                                    &export.function,
                                    export.arity,
                                ) || (crate::trace_bp::any_pattern()
                                    && crate::beamasm_integration::dispatch_bif(target_pc)
                                        .is_some()
                                    && crate::trace_bp::selects(
                                        process,
                                        &export.module,
                                        &export.function,
                                        export.arity,
                                    ))
                                {
                                    let saved_arguments =
                                        process.x[..usize::from(export.arity)].to_vec();
                                    let collections_before = process.stats.gc.collections;
                                    // BIFs such as load_nif/2 identify their caller through
                                    // `process.module`, which native code does not maintain: the
                                    // caller is the native function holding the return address.
                                    let interpreter_module = process.module;
                                    // A module whose on_load is running is not current yet.
                                    if let Some(caller) = native_caller_module(&self.vm, resume_pc)
                                    {
                                        process.module = caller;
                                    }
                                    // erlang:make_fun/3 is implemented by the VM's call path (funs.rs), not
                                    // by the native BIF table; handle it here like the interpreter does.
                                    // erlang:make_fun/3 and fun_info/1,2, fun_info_mfa/1 are implemented
                                    // by the VM's call path (funs.rs), not by the native BIF table.
                                    let result = if export.class == arinsal_loader::ImportClass::Fun
                                        && export.module == "erlang"
                                        && matches!(
                                            (export.function.as_str(), export.arity),
                                            ("make_fun", 3)
                                                | ("fun_info", 1 | 2)
                                                | ("fun_info_mfa", 1)
                                        ) {
                                        Some(match export.function.as_str() {
                                            "make_fun" => {
                                                let args =
                                                    [process.x[0], process.x[1], process.x[2]];
                                                self.vm.make_export_fun(process, &args)
                                            }
                                            "fun_info" => {
                                                self.vm.fun_info(process, export.arity == 2)
                                            }
                                            _ => self.vm.fun_info_mfa(process),
                                        })
                                    } else {
                                        // Port of erts/emulator/beam/beam_common.c (BIF trap to a
                                        // continuation export), OTP-29.1.1: a trapping BIF keeps
                                        // its state between retries of this native call site.
                                        let trap_args = [
                                            process.x.first().copied().unwrap_or(Term::NIL),
                                            process.x.get(1).copied().unwrap_or(Term::NIL),
                                            process.x.get(2).copied().unwrap_or(Term::NIL),
                                            process.x.get(3).copied().unwrap_or(Term::NIL),
                                        ];
                                        let traps_here = export.trap_entry
                                            || process
                                                .cold
                                                .as_ref()
                                                .is_some_and(|cold| cold.bif_trap.is_some());
                                        // Port of erts/emulator/beam/jit/arm/process_main.cpp
                                        // (context_switch_simplified), OTP-29.1.1: a light BIF
                                        // call that trapped context-switches; the process
                                        // resumes in the continuation when it next runs.
                                        if let Some(pending) = process
                                            .cold
                                            .as_mut()
                                            .and_then(|cold| cold.bif_trap.as_mut())
                                            .filter(|pending| {
                                                pending.schedule_out && pending.import == target_pc
                                            })
                                        {
                                            pending.schedule_out = false;
                                            pending.caller_module = process.module;
                                            pending.caller_ip = process.ip;
                                            process.cold_mut().native_retry = Some(target_pc);
                                            process.native_pc = Some(code_ptr);
                                            crate::native_helpers::debug_assert_native_heap(
                                                process,
                                            );
                                            break Ok(RunState::Yield);
                                        }
                                        // A traced trapping BIF reports its call once, when it is
                                        // first entered, and its return when it finishes.
                                        // Port of erts/emulator/beam/beam_bp.c:321-330
                                        // (erts_export_is_bif_traced), OTP-29.1.1.
                                        let trap_traced = if traps_here
                                            && crate::bif_traps::traps(
                                                &export.module,
                                                &export.function,
                                                export.arity,
                                            ) {
                                            self.vm.trace_native_call_named(
                                                process,
                                                ctx,
                                                &export.module,
                                                &export.function,
                                                usize::from(export.arity),
                                                (usize::MAX, call_site_pc),
                                                crate::trace::StackScan::None,
                                            )
                                        } else {
                                            None
                                        };
                                        let meter = crate::bif_traps::TrapMeter::start_continuation(
                                            process,
                                            Some(&*ctx),
                                        );
                                        if traps_here
                                            && let Some(trapped) = crate::bif_traps::execute_named(
                                                process,
                                                &export.module,
                                                &export.function,
                                                target_pc,
                                                usize::from(export.arity),
                                                trap_args,
                                                Some(ctx),
                                            )
                                        {
                                            if let Ok(result) = &trapped {
                                                meter.finish(
                                                    process,
                                                    Some(ctx),
                                                    result.reductions(),
                                                );
                                            }
                                            let outcome = match trapped {
                                                Ok(crate::bif_traps::HandlerResult::Yield {
                                                    ..
                                                }) => {
                                                    // The continuation export runs on the next
                                                    // schedule-in. This call site is not redone.
                                                    if let Some(pending) = process
                                                        .cold
                                                        .as_mut()
                                                        .and_then(|cold| cold.bif_trap.as_mut())
                                                    {
                                                        pending.schedule_out = false;
                                                    }
                                                    crate::bif_traps::arm_export_trap(process);
                                                    process.cold_mut().native_retry = Some(
                                                        crate::bif_traps::bif_export_trap_pc(),
                                                    );
                                                    process.native_pc = Some(code_ptr);
                                                    break Ok(RunState::Yield);
                                                }
                                                Ok(crate::bif_traps::HandlerResult::Done {
                                                    value,
                                                    ..
                                                }) => {
                                                    process.x[0] = process.gc_after_bif(value)?;
                                                    Some(Ok(process.x[0]))
                                                }
                                                Ok(crate::bif_traps::HandlerResult::Failed {
                                                    ..
                                                }) => Some(Err(VmError::Unsupported(
                                                    "failed trapping BIF without exception".into(),
                                                ))),
                                                Err(error) => Some(Err(error)),
                                            };
                                            if let (Some((module, function, args)), Some(result)) =
                                                (&trap_traced, &outcome)
                                            {
                                                let reduced = match result {
                                                    Ok(value) => Some(Ok(*value)),
                                                    Err(VmError::Exception { reason, frame }) => {
                                                        legacy_exception_trap(
                                                            process, reason, frame,
                                                        )
                                                        .ok()
                                                        .and_then(|trap| {
                                                            crate::exceptions::trace_class_reason(
                                                                process,
                                                                trap.class,
                                                                trap.reason,
                                                            )
                                                            .ok()
                                                        })
                                                        .map(Err)
                                                    }
                                                    Err(VmError::Trap(trap)) => {
                                                        crate::exceptions::trace_class_reason(
                                                            process,
                                                            trap.class,
                                                            trap.reason,
                                                        )
                                                        .ok()
                                                        .map(Err)
                                                    }
                                                    Err(_) => None,
                                                };
                                                if let Some(reduced) = reduced {
                                                    self.vm.trace_native_return_outcome(
                                                        process, ctx, module, function, args,
                                                        reduced,
                                                    );
                                                }
                                            }
                                            outcome
                                        } else {
                                            // The BIF runs at the native call site (erts c_p->i).
                                            let (module_before, ip_before) =
                                                (process.module, process.ip);
                                            process.cold_mut().native_call_pc = call_site_pc;
                                            let traced = self.vm.trace_native_call_named(
                                                process,
                                                ctx,
                                                &export.module,
                                                &export.function,
                                                usize::from(export.arity),
                                                (usize::MAX, call_site_pc),
                                                crate::trace::StackScan::None,
                                            );
                                            // Port of erts/emulator/beam/jit/arm/instr_bif.cpp
                                            // (call_light_bif_shared), OTP-29.1.1: a light BIF
                                            // runs with E at the caller's frame; the return
                                            // address is pushed only when it traps. A heavy BIF
                                            // is entered through its export entry, whose frame
                                            // holds the return address.
                                            let light = process
                                                .cold
                                                .as_ref()
                                                .is_some_and(|cold| cold.native_light_bif_call)
                                                && arinsal_spec::bif_lookup(
                                                    &export.module,
                                                    &export.function,
                                                    export.arity,
                                                )
                                                .is_some_and(|bif| {
                                                    bif.kind != arinsal_spec::BifKind::Hbif
                                                });
                                            let hidden = usize::from(
                                                light
                                                    && process.heap.stack_get(0).is_some_and(
                                                        |word| {
                                                            word.tagged_word() as usize == resume_pc
                                                        },
                                                    ),
                                            );
                                            process.heap.set_bif_hidden_words(hidden);
                                            let result = self.vm.dispatch_native(
                                                process,
                                                ctx,
                                                &export.module,
                                                &export.function,
                                                usize::from(export.arity),
                                                (export.class, export.native_bits),
                                            );
                                            process.heap.set_bif_hidden_words(0);
                                            process.cold_mut().native_call_pc = 0;
                                            // A BIF that traps to an Erlang export (erts BIF_TRAP*)
                                            // context-switches to beam_bif_export_trap, which runs
                                            // the export on schedule-in. Port of erts/emulator/beam/
                                            // jit/arm/instr_bif.cpp (trap to the export), OTP-29.1.1.
                                            let result = match result {
                                                Some(Err(VmError::TrapExport(trap))) => {
                                                    let callee =
                                                        (export.module_atom, export.function_atom);
                                                    crate::bif_traps::install_export_trap(
                                                        process, target_pc, callee, &trap,
                                                    );
                                                    crate::bif_traps::arm_export_trap(process);
                                                    process.cold_mut().native_retry = Some(
                                                        crate::bif_traps::bif_export_trap_pc(),
                                                    );
                                                    process.native_pc = Some(code_ptr);
                                                    break Ok(RunState::Yield);
                                                }
                                                other => other,
                                            };
                                            if let (Some((module, function, args)), Some(result)) =
                                                (&traced, &result)
                                            {
                                                self.vm.trace_native_return(
                                                    process, ctx, module, function, args, result,
                                                );
                                            }
                                            // Port of erts/emulator/beam/beam_bif_load.c:793
                                            // (call_on_load_function_1), OTP-29.1.1: the BIF traps
                                            // into the on_load function like a call; the native
                                            // continuation the trampoline pushed is its CP.
                                            if export.module == "erlang"
                                                && export.function == "call_on_load_function"
                                                && matches!(result, Some(Ok(_)))
                                                && (process.module, process.ip)
                                                    != (module_before, ip_before)
                                            {
                                                process.tick();
                                                continue;
                                            }
                                            result
                                        }
                                    };
                                    process.module = interpreter_module;
                                    let result = result.or_else(|| {
                                        let (bif, arity) =
                                            crate::beamasm_integration::dispatch_bif(target_pc)?;
                                        let arity = usize::from(arity);
                                        let (result, reductions) = self.vm.call_bif_traced_named(
                                            process,
                                            ctx,
                                            &export.module,
                                            &export.function,
                                            bif,
                                            arity,
                                        );
                                        process.reductions_used = process
                                            .reductions_used
                                            .saturating_add(u64::from(reductions));
                                        Some(match result {
                                            Ok(value) => Ok(value),
                                            Err(error) => {
                                                let arguments = process.x[..arity].to_vec();
                                                Err(crate::exceptions::bif_error_with_atoms(
                                                    process,
                                                    &export.module,
                                                    &export.function,
                                                    export.module_atom,
                                                    export.function_atom,
                                                    &arguments,
                                                    error,
                                                ))
                                            }
                                        })
                                    });
                                    // Interpreter-style BIF errors raise like traps, as in
                                    // the interpreter's own call_ext path.
                                    let result = match result {
                                        Some(Err(VmError::Exception { reason, frame })) => {
                                            Some(Err(VmError::Trap(legacy_exception_trap(
                                                process, &reason, &frame,
                                            )?)))
                                        }
                                        other => other,
                                    };
                                    if let Some(result) = result {
                                        let value = match result {
                                            Ok(value) => value,
                                            // A busy port_command suspends the native
                                            // caller and redoes the call when the port is
                                            // no longer busy, like the interpreter.
                                            Err(VmError::Trap(_))
                                                if crate::port::take_busy_suspend() =>
                                            {
                                                for (register, value) in
                                                    process.x.iter_mut().zip(&saved_arguments)
                                                {
                                                    *register = *value;
                                                }
                                                let cold = process.cold_mut();
                                                cold.native_retry = Some(target_pc);
                                                process.native_pc = Some(code_ptr);
                                                break Ok(RunState::Wait { timeout_ms: None });
                                            }
                                            Err(VmError::Trap(mut trap)) => {
                                                // Port of erts/emulator/beam/beam_common.c
                                                // (save_stacktrace: a failing BIF is the top
                                                // frame, the calling function the next one),
                                                // OTP-29.1.1.
                                                // erts omits erlang:error/1,2,3 from the trace
                                                // (beam_common.c save_stacktrace).
                                                if trap.class == arinsal_bifs::Class::Error
                                                    && trap.top.is_none()
                                                    && trap.trace.is_none()
                                                    && !(export.module == "erlang"
                                                        && export.function == "error")
                                                {
                                                    trap.top =
                                                        Some(crate::stacktrace::TopFrame::Bif {
                                                            module: export.module_atom,
                                                            function: export.function_atom,
                                                            // The X registers still hold the arguments, moved
                                                            // by any collection the call ran; the copies taken
                                                            // before it are stale.
                                                            args: crate::stacktrace::BifArgs::from_terms(
                                                                &process.x[..saved_arguments.len()],
                                                            )?,
                                                            info: crate::stacktrace::BifErrorInfo::Plain,
                                                        });
                                                }
                                                process.native_error_pc = call_site_pc;
                                                // The BIF does not return: drop the native
                                                // continuation the trap pushed as its CP, which
                                                // erts never creates for a BIF call.
                                                if process.heap.stack_get(0).is_some_and(|word| {
                                                    word.tagged_word() as usize == resume_pc
                                                }) {
                                                    process.heap.release_stack(1);
                                                }
                                                if let Some(error) = crate::exceptions::resume(
                                                    &mut self.vm,
                                                    process,
                                                    Some(ctx),
                                                    trap,
                                                )? {
                                                    break Err(error);
                                                }
                                                process.header.freason = 0;
                                                process.header.fvalue = 0;
                                                continue;
                                            }
                                            Err(VmError::Unsupported(message))
                                                if crate::signals::is_await_message(&message) =>
                                            {
                                                // The X registers still hold the arguments, moved
                                                // by any collection the call ran (signal handling
                                                // on entry); the copies taken before it are stale.
                                                // They stay live until the call is redone.
                                                process.gc_live = saved_arguments.len();
                                                let cold = process.cold_mut();
                                                cold.native_retry = Some(target_pc);
                                                process.native_pc = Some(code_ptr);
                                                break Ok(RunState::Wait { timeout_ms: None });
                                            }
                                            // ERTS_BIF_YIELD (e.g. a persistent_term updater
                                            // waiting for thread progress): the native call is
                                            // redone when the process is scheduled again.
                                            Err(VmError::Yield) => {
                                                // A collection the call ran (the epilogue of a
                                                // yielding BIF that allocated) moved the
                                                // registers; the copies taken before it are stale.
                                                if process.stats.gc.collections
                                                    == collections_before
                                                {
                                                    for (register, value) in
                                                        process.x.iter_mut().zip(&saved_arguments)
                                                    {
                                                        *register = *value;
                                                    }
                                                }
                                                let cold = process.cold_mut();
                                                cold.native_retry = Some(target_pc);
                                                process.native_pc = Some(code_ptr);
                                                break Ok(RunState::Yield);
                                            }
                                            // A dirty BIF called on a normal scheduler is redone
                                            // on a dirty one (erts_schedule_bif), OTP-29.1.1.
                                            Err(VmError::Dirty(kind)) => {
                                                for (register, value) in
                                                    process.x.iter_mut().zip(&saved_arguments)
                                                {
                                                    *register = *value;
                                                }
                                                let cold = process.cold_mut();
                                                cold.native_retry = Some(target_pc);
                                                process.native_pc = Some(code_ptr);
                                                break Err(VmError::Dirty(kind));
                                            }
                                            // Port of erts/emulator/beam/beam_common.c:1568
                                            // (erts_hibernate), OTP-29.1.1: hibernate/3 discarded
                                            // the stack, so the native caller is gone; the process
                                            // resumes through apply/3 like the interpreter's path.
                                            Err(VmError::Unsupported(_))
                                                if hibernate_stopped(process) =>
                                            {
                                                // hibernate/0 keeps its stack: after the wakeup the
                                                // native call is retried and returns `ok` in place.
                                                if hibernate_resumes_in_place(process) {
                                                    hibernate_fetch_collect(process, ctx)?;
                                                    let cold = process.cold_mut();
                                                    cold.native_retry = Some(target_pc);
                                                    process.native_pc = Some(code_ptr);
                                                    break Ok(RunState::Wait { timeout_ms: None });
                                                }
                                                process.native_pc = None;
                                                process.native_continuation_resume = false;
                                                if hibernate_fetch_collect(process, ctx)? {
                                                    if let Some(runtime) = process.runtime.clone() {
                                                        runtime.mark_hibernating(ctx.pid(), true);
                                                        // Port of erts `F_HIBERNATE_SCHED` in `p->flags`: the process tests its own flag.
                                                        process.cold_mut().hibernate_sched = true;
                                                    }
                                                    break Ok(RunState::Wait { timeout_ms: None });
                                                }
                                                self.install_apply(process, ctx)?;
                                                continue;
                                            }
                                            Err(error) => return Err(error),
                                        };
                                        process.x[0] = value;
                                        if !resume_after_native_return(process) {
                                            break Ok(RunState::Done(value));
                                        }
                                        // Port of erts/emulator/beam/erl_process.c:10190: a
                                        // finished dirty job continues on a normal scheduler.
                                        if ctx.scheduler_type().is_dirty() {
                                            break Ok(RunState::Yield);
                                        }
                                        continue;
                                    }
                                }
                                let module_id = match self
                                    .vm
                                    .code
                                    .loaded
                                    .get(&export.module)
                                    .copied()
                                {
                                    Some(module_id) => module_id,
                                    // Like call_import: a module with -on_load is loaded through
                                    // the error handler and code server, which run its on_load.
                                    None => {
                                        // Port of beam_common.c (call_error_handler): with the code
                                        // server up, the error handler loads the module.
                                        match if self.vm.unloaded_on_load(process, &export.module)
                                            || self.vm.should_autoload(process, &export.module)
                                        {
                                            Err(VmError::Load("module has -on_load".into()))
                                        } else {
                                            self.vm.load_named(&export.module)
                                        } {
                                            Ok(module_id) => module_id,
                                            Err(_) => {
                                                let saved =
                                                    process.x[..usize::from(export.arity)].to_vec();
                                                let outcome = match self.vm.call_undefined_function(
                                                    process,
                                                    &export.module,
                                                    &export.function,
                                                    usize::from(export.arity),
                                                    true,
                                                ) {
                                                    Ok(outcome) => outcome,
                                                    Err(error) => {
                                                        if let Some(error) = raise_undefined_call(
                                                            &mut self.vm,
                                                            process,
                                                            ctx,
                                                            &saved,
                                                            error,
                                                        )? {
                                                            break Err(error);
                                                        }
                                                        continue;
                                                    }
                                                };
                                                match outcome {
                                                    crate::ImportOutcome::Jump(_) => {
                                                        self.vm.enter_native_at_jump(process)
                                                    }
                                                    crate::ImportOutcome::Advanced => {}
                                                    crate::ImportOutcome::Yield => {
                                                        if process.native_pc.is_some()
                                                            && native_transfer_continues(
                                                                process, ctx,
                                                            )
                                                        {
                                                            continue;
                                                        }
                                                        break Ok(RunState::Yield);
                                                    }
                                                    crate::ImportOutcome::Returned(value) => {
                                                        process.x[0] = value;
                                                        if process.native_pc.is_none() {
                                                            break Ok(RunState::Done(value));
                                                        }
                                                        if ctx.scheduler_type().is_dirty() {
                                                            break Ok(RunState::Yield);
                                                        }
                                                    }
                                                }
                                                continue;
                                            }
                                        }
                                    }
                                };
                                let target_ip = crate::beamasm_integration::interpreted_target(
                                    self.vm.code_scope,
                                    &export.module,
                                    &export.function,
                                    export.arity,
                                )
                                .or_else(|| {
                                    self.vm.code.modules[module_id]
                                        .export_slot(&export.function, export.arity)
                                        .map(arinsal_loader::ExportSlot::target)
                                });
                                if let Some(target_ip) = target_ip {
                                    process.gc_live = usize::from(export.arity);
                                    process.module = module_id;
                                    process.ip = target_ip;
                                    process.tick();
                                    self.vm.enter_native_at_jump(process);
                                } else {
                                    let saved = process.x[..usize::from(export.arity)].to_vec();
                                    let outcome = match self.vm.call_undefined_function(
                                        process,
                                        &export.module,
                                        &export.function,
                                        usize::from(export.arity),
                                        true,
                                    ) {
                                        Ok(outcome) => outcome,
                                        Err(error) => {
                                            if let Some(error) = raise_undefined_call(
                                                &mut self.vm,
                                                process,
                                                ctx,
                                                &saved,
                                                error,
                                            )? {
                                                break Err(error);
                                            }
                                            continue;
                                        }
                                    };
                                    match outcome {
                                        crate::ImportOutcome::Jump(_) => {
                                            self.vm.enter_native_at_jump(process)
                                        }
                                        crate::ImportOutcome::Advanced => {}
                                        crate::ImportOutcome::Yield => {
                                            if process.native_pc.is_some()
                                                && native_transfer_continues(process, ctx)
                                            {
                                                continue;
                                            }
                                            break Ok(RunState::Yield);
                                        }
                                        crate::ImportOutcome::Returned(value) => {
                                            process.x[0] = value;
                                            if process.native_pc.is_none() {
                                                break Ok(RunState::Done(value));
                                            }
                                            if ctx.scheduler_type().is_dirty() {
                                                break Ok(RunState::Yield);
                                            }
                                        }
                                    }
                                }
                                continue;
                            }
                            arinsal_beamasm::ExitReason::Returned => {
                                if !resume_after_native_return(process) {
                                    break Ok(RunState::Done(process.x[0]));
                                }
                                continue;
                            }
                            arinsal_beamasm::ExitReason::Unsupported => {
                                return Err(VmError::Unsupported(
                                    "native execution unavailable".into(),
                                ));
                            }
                        }
                    }
                    let remaining = ctx.remaining().min(budget);
                    let result = process.drain(ctx).and_then(|()| {
                        if schedule_in_gc {
                            schedule_in_gc = false;
                            collect_on_schedule_in(process)?;
                        }
                        // Interpreted code keeps no redzone: only a BIF run for a native exit does.
                        process.heap.clear_native_redzone();
                        self.vm.run_slice(process, Some(ctx), remaining)
                    });
                    // erts schedules out only when FCALLS runs out; an interpreted step that
                    // just hands control to native code continues the slice.
                    if matches!(&result, Ok(RunState::Yield))
                        && process.native_pc.is_some()
                        && !process.force_yield
                        && native_transfer_continues(process, ctx)
                    {
                        continue;
                    }
                    if hibernate_stopped(process) {
                        if hibernate_fetch_collect(process, ctx)? {
                            if let Some(runtime) = process.runtime.clone() {
                                runtime.mark_hibernating(ctx.pid(), true);
                                // Port of erts `F_HIBERNATE_SCHED` in `p->flags`: the process tests its own flag.
                                process.cold_mut().hibernate_sched = true;
                            }
                            break Ok(RunState::Wait { timeout_ms: None });
                        }
                        self.install_apply(process, ctx)?;
                        continue;
                    }
                    if matches!(&result, Ok(RunState::Yield))
                        && process.runtime.is_some()
                        && crate::suspend::ctx_suspended(ctx)
                    {
                        break park_suspended(process, ctx);
                    }
                    let trap = match result {
                        // Port of erts/preloaded/src/erts_internal.erl:152 (await_result), OTP-29.1.1.
                        // A cross-process BIF parked this process until the reply signal arrives.
                        Err(VmError::Unsupported(message))
                            if crate::signals::is_await_message(&message) =>
                        {
                            break Ok(RunState::Wait { timeout_ms: None });
                        }
                        Err(VmError::Trap(trap)) => {
                            // g_port_fix: busy port_command suspends the sender and retries the call.
                            if crate::port::take_busy_suspend() {
                                break Ok(RunState::Wait { timeout_ms: None });
                            }
                            trap
                        }
                        Err(VmError::Exception { reason, frame }) => {
                            if trace_boot_enabled() {
                                eprintln!("arinsal boot: exception {reason} at {frame}");
                            }
                            let mut trap = crate::exceptions::from_legacy(&reason)?;
                            if reason == "undef"
                                && let Some((mfa, arity)) = frame.rsplit_once('/')
                                && let Some((module, function)) = mfa.split_once(':')
                                && let Ok(arity) = arity.parse::<usize>()
                                && arity <= process.x.len()
                            {
                                trap.top = Some(crate::stacktrace::TopFrame::Bif {
                                    module: arinsal_term::global_atoms().intern(module).map_err(
                                        |_| VmError::Unsupported("undef module atom".into()),
                                    )?,
                                    function: arinsal_term::global_atoms()
                                        .intern(function)
                                        .map_err(|_| {
                                            VmError::Unsupported("undef function atom".into())
                                        })?,
                                    args: crate::stacktrace::BifArgs::from_terms(
                                        &process.x[..arity],
                                    )?,
                                    info: crate::stacktrace::BifErrorInfo::None,
                                });
                            }
                            trap
                        }
                        Err(VmError::ExceptionInfo {
                            reason,
                            frame,
                            info,
                        }) => {
                            if trace_boot_enabled() {
                                eprintln!("arinsal boot: exception {reason} at {frame}");
                            }
                            let mut trap = crate::exceptions::from_legacy(&reason)?;
                            let arity = self.vm.code.modules[process.module]
                                .function_at(process.ip)
                                .map(|(_, arity)| arity)
                                .unwrap_or(0);
                            trap.top = Some(crate::stacktrace::TopFrame::CurrentArgsWithInfo(
                                Some(Term::small(i64::from(arity)).expect("arity is small")),
                                info,
                            ));
                            trap
                        }
                        other => break other,
                    };
                    if trace_boot_enabled() {
                        eprintln!(
                            "arinsal boot: process {:?} trap in {} at ip {} line {:?} instruction {:?}: {:?} reason {:?}",
                            ctx.pid(),
                            self.vm.frame_name(process),
                            process.ip,
                            self.vm.code.modules[process.module].lines.get(process.ip),
                            self.vm.code.modules[process.module].code.get(process.ip),
                            trap.class,
                            arinsal_term::to_owned(trap.reason)
                        );
                    }
                    let resumed =
                        crate::exceptions::resume(&mut self.vm, process, Some(ctx), trap)?;
                    if let Some(error) = resumed {
                        break Err(error);
                    }
                    // boot_loop2: a caught exit must not survive as a later process exit reason.
                    if let Some(cold) = process.cold.as_mut() {
                        cold.exit_reason = None;
                    }
                }
            }
        })();
        // erts keeps a process whose middle queue holds unhandled signals (ERTS_PSFLG_SIG_Q)
        // scheduled for signal handling even when it waits (erl_process.c:10318-10351, with
        // all reductions since it has no Erlang work); this scheduler only wakes a process for
        // new input, so the rest is handled before it sleeps. Messages it produces end the
        // wait like a new message would.
        let result = match result {
            Ok(RunState::Wait { timeout_ms })
                if !process.sig_cont_empty() || process.delayed_gc_due() =>
            {
                let queued = process.inbox.len();
                match process.handle_local_signals(ctx) {
                    Ok(()) if process.inbox.len() == queued => Ok(RunState::Wait { timeout_ms }),
                    Ok(()) => Ok(RunState::Yield),
                    Err(error) => Err(error),
                }
            }
            other => other,
        };
        if matches!(
            result,
            Ok(RunState::Yield | RunState::Wait { .. }) | Err(VmError::Yield | VmError::Dirty(_))
        ) {
            // Port of erts/emulator/beam/erl_process.c:10550 and beam_common.c (the yield or
            // wait site stores its live X register count in `c_p->arity`, and only those are
            // saved in `c_p->arg_reg`), OTP-29.1.1: a native continuation already holds it in
            // `header.arity`; an interpreted switch-out has it in `gc_live`, the count of its
            // last live operand or call arity (4 from exception handler entry until it runs).
            // A native call the scheduler redoes (BIF trap, traced apply) carries the larger of
            // the two, whichever side stated it. From here on `header.arity` is the one count
            // every reader of the saved file takes.
            let arity_set = process.native_pc.is_some() && process.native_arity_set;
            let call_arity = usize::from(process.header.arity);
            let mut live_x = if arity_set {
                call_arity
            } else if process.native_pc.is_some() {
                process.gc_live.max(call_arity)
            } else {
                process.gc_live
            };
            // A fun call or apply the scheduler redoes reads its operands from the saved file:
            // the arguments and the fun or module and function above them, and nothing else is
            // live. The saved count is that operand count; the retry takes the call's own arity
            // back from it (`retry_call_arity`).
            if !arity_set
                && process.native_pc.is_some()
                && let Some(operands) = process
                    .cold
                    .as_ref()
                    .and_then(|cold| cold.native_retry)
                    .and_then(|target| retry_operand_count(target, call_arity))
            {
                live_x = operands;
            }
            process.header.arity = live_x.min(usize::from(u8::MAX)) as u8;
            process.gc_live = live_x;
            let save_x = live_x;
            if crate::native_bridge::return_trace_enabled() && process.native_pc.is_some() {
                eprintln!(
                    "[sched-save-native] live_x={live_x} x0={:#x} module={} native_pc={:?}",
                    process.x[0].tagged_word(),
                    self.vm.code.modules[process.module].name,
                    process.native_pc
                );
            }
            // Port of erts/emulator/beam/jit/arm/process_main.cpp (copy_out_registers),
            // OTP-29.1.1: the `c_p->arity` registers go from the scheduler array into the
            // process, six of them inline (`def_arg_reg`) so switching out allocates nothing.
            process.x.detach_save(save_x);
        } else {
            process.x.detach_save(0);
            process.x = crate::proc_create::ArgRegs::empty();
        }
        // A waiting process is not collected when it switches out: erts only runs
        // `scheduler_gc_proc` for a process being scheduled in (a yielded process is still
        // active) or handling signals/sys tasks, so a sleeping receiver with on-heap message
        // fragments keeps them until it next runs.
        if matches!(result, Ok(RunState::Yield)) {
            // erts collects a switched-out process rooting only its `c_p->arity` live X
            // registers; the saved register file above that holds dead registers whose
            // pointers may refer to a heap an earlier collection already freed.
            // Port of erts/emulator/beam/erl_process.c:10415 (ERTS_IS_GC_DESIRED ->
            // scheduler_gc_proc, garbage_collect with p->arity), OTP-29.1.1.
            let live = switched_out_live(process);
            process.collect_bin_vheap_if_due(live)?;
        }
        // OTP emits regular `out` only when a process is scheduled out; normal exit uses the
        // separate `out_exiting` event when that flag is enabled.
        // Port of erts/emulator/beam/erl_process.c:10550-10567, OTP-29.1.1.
        if (matches!(result, Ok(RunState::Yield | RunState::Wait { .. }))
            || matches!(result, Err(VmError::Yield | VmError::Dirty(_))))
            && ctx.exit_flags().load(Ordering::Acquire) & proc_flags::TRACE != 0
        {
            let running = crate::trace::running_mfa(process, &self.vm, ctx.pid())?;
            // erl_trace.c:752-760 (trace_sched_session): no current function is reported as 0.
            let running_fields = [running.unwrap_or(Term::small(0).expect("small zero"))];
            // Port of erts/emulator/beam/erl_process.c:10556-10560 (trace_schedule_out).
            if crate::trace::flags(process, ctx.pid()) & crate::trace::CALL != 0 {
                crate::trace_bp::schedule_time_break(process, ctx.pid(), true);
            }
            crate::trace::emit(
                Some(&mut self.vm),
                process,
                ctx,
                ctx.pid(),
                crate::trace::RUNNING,
                "out",
                &running_fields,
            );
        }
        if let Some(schedule_started) = schedule_started {
            crate::natives::erts_debug::after_schedule(
                process,
                schedule_started.elapsed().as_nanos() as u64,
            );
        }
        result
    }

    // g_proc_sched. A suspended process drains its mailbox and does not run.
    // A hibernating process waits until the inbox is non-empty, then continues
    // at `erlang:apply/3`. Port of beam_common.c:1568 (`erts_hibernate`) and
    // erl_process.c:9304 (`erts_process_state2status`), OTP-29.1.1.
    fn sched_preempt(
        &mut self,
        process: &mut Process,
        ctx: &mut RunCtx<'_, Message>,
    ) -> Result<Option<RunState>, VmError> {
        // Nothing to do at most scheduling points: no suspend, no timer pause and no
        // hibernation. Checked before the runtime handle is cloned.
        if process.runtime.is_some()
            && !crate::suspend::ctx_suspended(ctx)
            && !process
                .cold
                .as_ref()
                .is_some_and(|cold| cold.hibernate_sched || cold.timer_pause.is_some())
        {
            return Ok(None);
        }
        let Some(runtime) = process.runtime.clone() else {
            return Ok(None);
        };
        let pid = ctx.pid();
        if runtime.suspend_total_of(pid) > 0 {
            return match park_suspended(process, ctx)? {
                RunState::Yield => Ok(None),
                parked => Ok(Some(parked)),
            };
        }
        if let Some(shift) = runtime.take_pause_shift(process) {
            if let Some(deadline) = process.receive_deadline.as_mut() {
                *deadline += shift;
            }
            if let Some(deadline) = process.receive_deadline_ms.as_mut() {
                *deadline += shift.as_millis() as u64;
            }
        }
        if process
            .cold
            .as_ref()
            .is_some_and(|cold| cold.hibernate_sched)
        {
            process.drain(ctx)?;
            if process.inbox.is_empty() {
                return Ok(Some(RunState::Wait { timeout_ms: None }));
            }
            // elixir_loop1: unlike hibernate/3, hibernate/0 keeps its stack.
            let resume_in_place = process
                .cold
                .as_ref()
                .and_then(|cold| cold.hibernate.as_ref())
                .is_some_and(|cont| cont.resume_in_place);
            if resume_in_place {
                runtime.mark_hibernating(pid, false);
                // Port of erts `F_HIBERNATE_SCHED` in `p->flags`: the process tests its own flag.
                process.cold_mut().hibernate_sched = false;
            } else {
                self.install_apply(process, ctx)?;
            }
        }
        Ok(None)
    }

    // g_proc_sched. Port of bif.c:1402 (`hibernate_3` resumes via apply/3), OTP-29.1.1.
    fn install_apply(
        &mut self,
        process: &mut Process,
        ctx: &mut RunCtx<'_, Message>,
    ) -> Result<(), VmError> {
        let pid = ctx.pid();
        let runtime = process
            .runtime
            .clone()
            .ok_or_else(|| VmError::Unsupported("hibernate without a scheduler".into()))?;
        process
            .cold_mut()
            .hibernate
            .take()
            .ok_or_else(|| VmError::Unsupported("hibernate continuation missing".into()))?;
        runtime.mark_hibernating(pid, false);
        // Port of erts `F_HIBERNATE_SCHED` in `p->flags`: the process tests its own flag.
        process.cold_mut().hibernate_sched = false;
        // hibernate/3 left `apply(M, F, A)` in X0..X2.
        if process.x.len() < 3 {
            return Err(VmError::Unsupported("hibernate registers".into()));
        }
        let (module_id, entry) = erlang_apply_entry(&mut self.vm)?;
        process.module = module_id;
        process.ip = entry;
        process.receive_cursor = 0;
        process.receive_deadline = None;
        process.receive_deadline_ms = None;
        process.receive_infinity = false;
        // erts resumes a hibernated process at the export address of apply/3 too.
        self.vm.enter_native_at_jump(process);
        Ok(())
    }
}

/// Collect when a slice starts and the heap wants it.
///
/// The caller has already drained the outer queue, so a message that woke this
/// process is an inbox root. The new heap is sized from that message, the same
/// way `scheduler_gc_proc` sizes from `mbuf` after `erts_proc_sig_handle_incoming`.
// Port of erts/emulator/beam/erl_process.c:10415-10418 and 9558 (`scheduler_gc_proc`),
// OTP-29.1.1.
fn collect_on_schedule_in(process: &mut Process) -> Result<(), VmError> {
    process.collect_bin_vheap_if_due(switched_out_live(process))
}

/// Registers a redone fun call or apply reads: the arguments and the fun (`call_fun`) or the
/// module and function (`apply_fixed`) above them, `apply/2` and `apply/3`'s own operands.
/// `None` for every other call the scheduler redoes: it takes its `arity` registers.
fn retry_operand_count(target_pc: usize, arity: usize) -> Option<usize> {
    use arinsal_beamasm::dispatch::{
        APPLY_FIXED_UNPORTED, APPLY2_UNPORTED, APPLY3_UNPORTED, CALL_FUN_UNPORTED,
    };
    match target_pc {
        CALL_FUN_UNPORTED => Some(arity + 1),
        APPLY_FIXED_UNPORTED => Some(arity + 2),
        APPLY2_UNPORTED => Some(2),
        APPLY3_UNPORTED => Some(3),
        _ => None,
    }
}

/// The call arity of a redone fun call or apply, from the operand count its switch-out saved
/// (`retry_operand_count` backwards). `None` for every other call the scheduler redoes.
fn retry_call_arity(target_pc: usize, saved: usize) -> Option<u8> {
    use arinsal_beamasm::dispatch::{
        APPLY_FIXED_UNPORTED, APPLY2_UNPORTED, APPLY3_UNPORTED, CALL_FUN_UNPORTED,
    };
    let arity = match target_pc {
        CALL_FUN_UNPORTED => saved.saturating_sub(1),
        APPLY_FIXED_UNPORTED => saved.saturating_sub(2),
        APPLY2_UNPORTED => 2,
        APPLY3_UNPORTED => 3,
        _ => return None,
    };
    u8::try_from(arity).ok()
}

/// Exact live X register count of a switched-out process, erts `c_p->arity`. Every
/// producer of a saved register file stores it in `header.arity`: the native yield
/// sites and trap continuations directly, an interpreted switch-out through the
/// executor epilogue, a spawn or hibernate when it fills the file.
pub(crate) fn switched_out_live(process: &Process) -> usize {
    // A trap whose arguments are GC roots of its own keeps no live X registers.
    if process
        .cold
        .as_ref()
        .and_then(|cold| cold.bif_trap.as_ref())
        .is_some_and(|trap| trap.args_are_roots())
    {
        return 0;
    }
    process.saved_arity()
}

/// Return address, native code generation, code tables generation and the owning module.
type CallerModuleEntry = (usize, u64, u64, Option<usize>);

thread_local! {
    /// Direct-mapped memo of `native_caller_module`, keyed by return address and validated
    /// against the native code generation and the code tables generation.
    static CALLER_MODULE_CACHE: std::cell::RefCell<[CallerModuleEntry; 256]> =
        const { std::cell::RefCell::new([(0, 0, 0, None); 256]) };
}

/// Module that owns the native function holding `resume_pc`; a module whose `-on_load`
/// is running is not current yet.
fn native_caller_module(vm: &Vm, resume_pc: usize) -> Option<usize> {
    let generation = crate::native_bridge::native_registry_generation();
    // A running on_load changes the answer without touching the native code table.
    let memo = vm.code.pending_on_load.is_empty();
    let slot = (resume_pc >> 2) & 255;
    if memo {
        let hit = CALLER_MODULE_CACHE.with(|cache| {
            let entry = cache.borrow()[slot];
            (entry.0 == resume_pc && entry.1 == generation && entry.2 == vm.code_generation())
                .then_some(entry.3)
        });
        if let Some(found) = hit {
            return found;
        }
    }
    let found = crate::native_bridge::with_native_function_at(resume_pc, |caller| {
        // The pc names exactly one code instance: the one being loaded, the old one or the
        // current one (a reload runs the new on_load while the previous code is current).
        [
            vm.code.pending_on_load.get(&caller.module),
            vm.code.loaded.get(&caller.module),
            vm.code.old.get(&caller.module),
        ]
        .into_iter()
        .flatten()
        .copied()
        .find(|id| vm.native_code_contains(*id, resume_pc))
        .or_else(|| vm.code.loaded.get(&caller.module).copied())
    })
    .flatten();
    if memo {
        CALLER_MODULE_CACHE.with(|cache| {
            cache.borrow_mut()[slot] = (resume_pc, generation, vm.code_generation(), found);
        });
    }
    found
}

fn resume_after_native_return(process: &mut Process) -> bool {
    loop {
        let Some(word) = process.heap.stack_get(0) else {
            return false;
        };
        // SAFETY: A live stack slot contains a tagged continuation or a raw native CP.
        let raw = unsafe { word.raw_bits() } as usize;
        if raw == arinsal_beamasm::rt::arinsal_enter_native_return as *const () as usize {
            process.heap.release_stack(1);
            continue;
        }
        if crate::native_bridge::is_native_continuation(raw) {
            process.heap.release_stack(1);
            process.native_continuation_resume = true;
            process.set_native_resume_arity(1);
            process.native_pc = Some(raw);
            return true;
        }
        let Some((handler, module, ip)) = crate::stacktrace::decode_tag(word) else {
            return false;
        };
        if handler {
            return false;
        }
        process.heap.release_stack(1);
        process.module = module;
        process.ip = ip;
        return true;
    }
}

// g_proc_sched. `erlang:apply/3` is the continuation erts installs after
// `erts_hibernate` and the body of `erts_internal:spawn_init/1`.
/// Process-table slot of a local pid; `erlang:processes/0` lists pids in slot order.
///
/// Port of erts/emulator/beam/erl_node_container_utils.h:128 (internal_pid_index), OTP-29.1.1.
pub(crate) fn pid_table_index(pid: Pid) -> u32 {
    arinsal_term::ptab::process_table_layout().data2pix(pid.data())
}

/// Module id of the apply_only start point (erts `beam_run_process`, erl_process.c:12616). A
/// process spawned but not yet run holds it in `module`; no module has this id.
pub(crate) const RUN_PROCESS: usize = usize::MAX;

impl Vm {
    /// First run of a spawned process: erts' apply_only instruction (beam_common.c:1434 `apply`)
    /// on X0..X2 (module, function, argument list). The export is the target when it exists;
    /// otherwise the process starts at erlang:apply/3, so an undefined function fails in the
    /// child with `undef`, as in erts.
    pub(crate) fn resolve_run_process(&mut self, process: &mut Process) -> Result<bool, VmError> {
        let module = process.x[0]
            .as_atom()
            .ok_or_else(|| VmError::Unsupported("run_process module".into()))?;
        let function = process.x[1]
            .as_atom()
            .ok_or_else(|| VmError::Unsupported("run_process function".into()))?;
        let args = crate::signals::list(process.x[2])
            .ok_or_else(|| VmError::Unsupported("run_process arguments".into()))?;
        let (module_id, ip, apply_operands) =
            match self.spawn_export(module, function, args.len() as u8) {
                Ok((module_id, ip)) => {
                    process.x.ensure_x(args.len());
                    for (index, term) in args.iter().enumerate() {
                        process.x[index] = *term;
                    }
                    process.gc_live = args.len();
                    process.header.arity = args.len().min(usize::from(u8::MAX)) as u8;
                    (module_id, ip, false)
                }
                Err(_) => {
                    let (module_id, entry) = erlang_apply_entry(self)?;
                    (module_id, entry, true)
                }
            };
        process.module = module_id;
        process.ip = ip;
        process.initial_call = Some((module_id, ip));
        Ok(apply_operands)
    }
}

pub(crate) fn erlang_apply_entry(vm: &mut Vm) -> Result<(usize, usize), VmError> {
    if let Some(entry) = vm.apply3_entry {
        return Ok(entry);
    }
    let module_id = vm.load_named("erlang")?;
    let entry = vm.code.modules[module_id]
        .functions
        .iter()
        .find(|(_, name, arity)| name == "apply" && *arity == 3)
        .map(|(ip, _, _)| ip + 1)
        .ok_or_else(|| VmError::Unsupported("erlang:apply/3 is not loaded".into()))?;
    vm.apply3_entry = Some((module_id, entry));
    Ok((module_id, entry))
}

// g_proc_sched
fn hibernate_resumes_in_place(process: &Process) -> bool {
    process
        .cold
        .as_ref()
        .and_then(|cold| cold.hibernate.as_ref())
        .is_some_and(|cont| cont.resume_in_place)
}

/// `erts_hibernate`'s message check: fetch, and without messages collect and fetch again.
/// Returns whether the message queue is still empty, so the process stops being active.
// Port of erts/emulator/beam/beam_common.c:1584-1596 (erts_hibernate), OTP-29.1.1.
fn hibernate_fetch_collect(
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
    process.header.arity = live as u8;
    if !process.heap.gc_enabled {
        return Ok(());
    }
    process.garbage_collect_hibernate(live).map(|_| ())
}

// Port of erts/emulator/beam/beam_common.c:1568 (erts_hibernate), OTP-29.1.1: the parked
// continuation is process state (`cold.hibernate`), read and cleared by the process itself.
fn hibernate_stopped(process: &mut Process) -> bool {
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

// Uncaught errors leave `{Reason, Stack}` so links and monitors match erts.
// boot_loop2: OTP sends that pair; other raised classes send the reason alone.
/// The origin entry of a port monitor, as needed to build its `'DOWN'` message.
enum PortObject {
    Local(Option<u64>, Option<arinsal_term::Atom>),
    Dist(arinsal_etf::OwnedTerm),
}

fn exit_reason_from(process: &mut Process, error: &VmError) -> Term {
    if let Some(reason) = process
        .cold
        .as_mut()
        .and_then(|cold| cold.exit_reason.take())
    {
        return reason;
    }
    // An exit signal that reached a running process (kill becomes killed) ends it with its
    // reason (erts/emulator/beam/erl_proc_sig_queue.c, handle_exit_signal), OTP-29.1.1.
    if let VmError::Trap(trap) = error
        && trap.class == arinsal_bifs::Class::Exit
    {
        return trap.reason;
    }
    let VmError::Raised(raised) = error else {
        return crate::signals::atom("error");
    };
    let owned = if raised.class == arinsal_bifs::Class::Error {
        arinsal_etf::OwnedTerm::Tuple(vec![raised.reason.clone(), raised.stack.clone()])
    } else {
        raised.reason.clone()
    };
    let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
    match arinsal_term::from_owned(&owned, &mut heap) {
        Ok(reason) => reason,
        Err(conversion_error) => {
            eprintln!("arinsal: exit reason conversion failed: {conversion_error:?}");
            crate::signals::atom("system_limit")
        }
    }
}

impl Process {
    /// Whether this process has a `max_heap_size` limit. The peak is tracked only then.
    fn max_heap_limited(&self) -> bool {
        self.cold
            .as_ref()
            .is_some_and(|cold| cold.max_heap.size != 0)
    }
}

// g_proc_sched. Port of erl_gc.c:3730 (`has_reached_max_heap_size`) and
// erl_gc.c:3741 (`reached_max_heap_size`), OTP-29.1.1.
#[inline(always)]
fn heap_limit_kills(process: &mut Process, ctx: &mut RunCtx<'_, Message>) -> bool {
    if process
        .cold
        .as_ref()
        .is_none_or(|cold| cold.max_heap.size == 0)
    {
        return false;
    }
    heap_limit_check(process, ctx)
}

#[inline(never)]
fn heap_limit_check(process: &mut Process, ctx: &mut RunCtx<'_, Message>) -> bool {
    let snapshot = {
        // Port of erts/emulator/beam/erl_process.h (`p->max_heap_size`), OTP-29.1.1: the limit
        // is a field of the process itself, so only the process reads or writes it.
        let Some(mut limit) = process.cold.as_ref().map(|cold| cold.max_heap) else {
            return false;
        };
        if limit.size == 0 {
            return false;
        }
        // Only a collection checks the limit (`garbage_collect`), so judge the size seen there.
        let mut used = std::mem::take(&mut process.max_heap_peak) as u64;
        if limit.include_shared_binaries {
            used = used.saturating_add(off_heap_binary_words(process) as u64);
        }
        if used <= limit.size {
            return false;
        }
        let log = limit.log && !limit.reported;
        if log {
            limit.reported = true;
            process.cold_mut().max_heap = limit;
        }
        (log, limit.kill, limit, used)
    };
    let (log, kill, limit, used) = snapshot;
    if log {
        report_max_heap(process, ctx, limit, used);
    }
    kill
}

fn off_heap_binary_words(process: &Process) -> usize {
    let mut seen = HashSet::new();
    let mut bytes = HashMap::<usize, usize>::new();
    let mut stack = Vec::new();
    // Only the `arity` registers a switched-out process saved are roots; a completed process
    // has released its register file.
    for term in process.x[..switched_out_live(process)]
        .iter()
        .copied()
        .chain(process.inbox.iter().copied())
    {
        stack.push(term);
    }
    if let Some(dictionary) = &process.dictionary {
        for (key, value) in dictionary.entries() {
            stack.push(key);
            stack.push(value);
        }
    }
    for index in 0..process.heap.stack_words() {
        if let Some(term) = process.heap.stack_get(index) {
            stack.push(term);
        }
    }
    while let Some(term) = stack.pop() {
        if !term.is_pointer() {
            continue;
        }
        // SAFETY: The term is a live pointer on this process heap. The bit
        // pattern is an identity for the DAG walk, not a dereference.
        let bits = unsafe { term.raw_bits() };
        if !seen.insert(bits) {
            continue;
        }
        // SAFETY: The owning heap stays live for this walk; no collection runs.
        if let Some(binary) = unsafe { term.binary_ref() } {
            if binary.bytes().len() > 64 {
                bytes
                    .entry(binary.bytes().as_ptr() as usize)
                    .or_insert(binary.bytes().len());
            }
            continue;
        }
        // SAFETY: The cons cell borrows this live heap; no collection runs.
        if let Some((head, tail)) = unsafe { term.cons_ref() } {
            stack.push(head);
            stack.push(tail);
            continue;
        }
        // SAFETY: The tuple borrows this live heap; no collection runs.
        if let Some(tuple) = unsafe { term.tuple_ref() } {
            for index in 0..tuple.len() {
                if let Some(element) = tuple.get(index) {
                    stack.push(element);
                }
            }
            continue;
        }
        // SAFETY: The map borrows this live heap; no collection runs.
        if let Some(map) = unsafe { term.flatmap_ref() } {
            for (key, value) in map.iter() {
                stack.push(key);
                stack.push(value);
            }
            continue;
        }
        // SAFETY: The fun borrows this live heap; no collection runs.
        if let Some(fun) = unsafe { term.fun_ref() } {
            for index in 0..fun.num_free() {
                if let Some(value) = fun.free(index) {
                    stack.push(value);
                }
            }
        }
    }
    bytes
        .values()
        .fold(0, |sum, len| sum.saturating_add(len.div_ceil(8)))
}

// g_proc_sched. Port of erl_gc.c:3756 (error_logger report),
// utils.c:802 (`do_send_logger_message`) and utils.c:885
// (`send_error_term_to_logger`), OTP-29.1.1.
fn report_max_heap(
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    limit: MaxHeap,
    used: u64,
) {
    let format = "     Process:            ~p ~n     Context:            maximum heap size reached~n     Max Heap Size:      ~p~n     Total Heap Size:    ~p~n     Kill:               ~p~n     Error Logger:       ~p~n     Message Queue Len:  ~p~n     GC Info:            ~p~n     Stacktrace:         ~p~n";
    eprintln!(
        "     Process:            {:?}\n     Context:            maximum heap size reached\n     Max Heap Size:      {}\n     Total Heap Size:    {used}\n     Kill:               {}\n     Error Logger:       true\n     Message Queue Len:  {}\n     GC Info:            []\n     Stacktrace:         []",
        ctx.pid(),
        limit.size,
        limit.kill,
        process.inbox.len()
    );
    let Some(runtime) = process.runtime.clone() else {
        return;
    };
    let logger = runtime
        .reg
        .whereis_proc_str("logger")
        .or_else(|| runtime.reg.whereis_proc_str("error_logger"));
    let Some(logger) = logger else {
        return;
    };
    let Some(pid) = ctx.pid().to_term() else {
        return;
    };
    let group_leader = process.group_leader.and_then(Pid::to_term);
    let bool_atom = |on: bool| crate::signals::atom(if on { "true" } else { "false" });
    let built = (|| -> Result<Term, VmError> {
        let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
        let mut builder = TermBuilder::new(&mut heap);
        let format = builder
            .list_from_iter(
                format
                    .bytes()
                    .map(|byte| Term::small(i64::from(byte)).unwrap()),
            )
            .map_err(|error| VmError::Unsupported(format!("logger format: {error:?}")))?;
        let args = [
            pid,
            Term::small(limit.size as i64).unwrap_or(Term::NIL),
            Term::small(used as i64).unwrap_or(Term::NIL),
            bool_atom(limit.kill),
            crate::signals::atom("true"),
            Term::small(process.inbox.len() as i64).unwrap_or(Term::NIL),
            Term::NIL,
            Term::NIL,
        ];
        let args = builder
            .list_from_iter(args)
            .map_err(|error| VmError::Unsupported(format!("logger args: {error:?}")))?;
        // Port of erts/emulator/beam/utils.c:773 (`do_send_logger_message`), OTP-29.1.1:
        // `#{error_logger => #{emulator => true, tag => error}, gl => GL, pid => Pid, time => Us}`.
        let micros = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_micros() as i64);
        let el_tag = builder
            .flatmap_from_pairs(&[
                (
                    crate::signals::atom("emulator"),
                    crate::signals::atom("true"),
                ),
                (crate::signals::atom("tag"), crate::signals::atom("error")),
            ])
            .map_err(|error| VmError::Unsupported(format!("logger tag map: {error:?}")))?;
        let mut pairs = vec![
            (crate::signals::atom("error_logger"), el_tag),
            (
                crate::signals::atom("time"),
                Term::small(micros).unwrap_or(Term::NIL),
            ),
        ];
        if let Some(gl) = group_leader {
            pairs.push((crate::signals::atom("gl"), gl));
        }
        pairs.push((crate::signals::atom("pid"), pid));
        let meta = builder
            .flatmap_from_pairs(&pairs)
            .map_err(|error| VmError::Unsupported(format!("logger metadata: {error:?}")))?;
        builder
            .tuple(&[
                crate::signals::atom("log"),
                crate::signals::atom("error"),
                format,
                args,
                meta,
            ])
            .map_err(|error| VmError::Unsupported(format!("logger message: {error:?}")))
    })();
    if let Ok(term) = built
        && let Ok(message) = Message::copy_from(term)
    {
        let _ = ctx.send(logger, message);
    }
}

/// Text and counters returned by a scheduler-backed entry process.
pub struct ScheduledResult {
    /// Printed Erlang result.
    pub text: String,
    /// Owned result for differential tests and callers that need structure.
    pub term: arinsal_etf::OwnedTerm,
    /// Counters collected by the entry process.
    pub stats: crate::Stats,
}

pub(crate) fn register_requirements(beam: &BeamFile) -> (usize, usize) {
    fn scan(operand: &Operand, x: &mut usize, fr: &mut usize) {
        match operand {
            Operand::X(index) => *x = (*x).max(*index as usize + 1),
            Operand::FR(index) => *fr = (*fr).max(*index as usize + 1),
            Operand::List(items) => {
                for item in items {
                    scan(item, x, fr);
                }
            }
            Operand::TypedReg { reg, .. } => scan(reg, x, fr),
            _ => {}
        }
    }
    let mut x = 2;
    let mut fr = 1;
    for instruction in &beam.code.instructions {
        for operand in &instruction.args {
            scan(operand, &mut x, &mut fr);
        }
        let arity = match instruction.op {
            Opcode::FuncInfo => instruction.args.get(2),
            Opcode::Call
            | Opcode::CallLast
            | Opcode::CallOnly
            | Opcode::CallExt
            | Opcode::CallExtLast
            | Opcode::CallExtOnly => instruction.args.first(),
            Opcode::CallFun2 => instruction.args.get(1),
            _ => None,
        };
        if let Some(Operand::U(count)) = arity {
            x = x.max(*count as usize + 1);
        }
    }
    (x.min(1024), fr.min(1024))
}

impl Runtime {
    /// OTP root used by child Arinsal launchers, recovered from the loaded erts path.
    pub(crate) fn otp_root(&self) -> Option<std::path::PathBuf> {
        self.otp_root.clone().or_else(|| {
            self.paths.iter().find_map(|path| {
                if path.ends_with(std::path::Path::new("lib/erts-17.1/ebin")) {
                    path.parent()?
                        .parent()?
                        .parent()
                        .map(std::path::Path::to_path_buf)
                } else {
                    None
                }
            })
        })
    }

    #[inline]
    pub(crate) fn next_ref(&self) -> u64 {
        arinsal_bifs::next_ref_id()
    }

    pub(crate) fn alias_bind(&self, id: u64, target: Option<Pid>) {
        self.alias_bind_prio(id, target, false);
    }

    /// Bind an alias; `priority` enables OTP 28+ priority-message reception on that alias.
    pub(crate) fn alias_bind_prio(&self, id: u64, target: Option<Pid>, priority: bool) {
        self.aliases.store(id, target, priority);
    }

    pub(crate) fn alias_lookup(&self, id: u64) -> Option<Option<Pid>> {
        self.aliases.load(id).map(|(pid, _)| pid)
    }

    /// Lookup including whether the alias accepts priority messages.
    pub(crate) fn alias_lookup_prio(&self, id: u64) -> Option<(Option<Pid>, bool)> {
        self.aliases.load(id)
    }

    pub(crate) fn scheduler(&self) -> Result<&Arc<Scheduler<Process>>, VmError> {
        self.scheduler
            .get()
            .ok_or_else(|| VmError::Unsupported("scheduler has stopped".into()))
    }

    /// Owned handle for the few callers that store the scheduler (ports, deferred replies).
    pub(crate) fn scheduler_arc(&self) -> Result<Arc<Scheduler<Process>>, VmError> {
        self.scheduler().cloned()
    }

    /// Read a suspended task and its active module table under scheduler ownership.
    /// Read a suspended process while its scheduler task cell is locked.
    /// Port of erts/emulator/beam/erl_debugger.c:570-600, OTP-29.1.1.
    pub(crate) fn inspect_suspended<R>(
        &self,
        pid: Pid,
        inspect: impl FnOnce(&Process, &[Arc<arinsal_loader::Module>]) -> R,
    ) -> Option<R> {
        if self.suspend_total_of(pid) == 0 {
            return None;
        }
        let scheduler = self.scheduler().ok()?;
        scheduler.inspect_waiting(pid, |target| {
            if self.suspend_total_of(pid) == 0 {
                return None;
            }
            let code = self.code.active_tables();
            Some(inspect(target, &code.modules))
        })?
    }

    /// `erts_pause_proc_timer`: one more active suspend holds `process`' receive timeout and the
    /// BIF timers aimed at it. The count nests like erts' `pptmr->count` and
    /// `paused_bif_timers->count`.
    // Port of erts/emulator/beam/erl_hl_timer.c:2849 (erts_pause_proc_timer) and :2864
    // (erts_pause_bif_timers), OTP-29.1.1.
    pub(crate) fn erts_pause_proc_timer(&self, process: &mut Process, pid: Pid) {
        let pause = process
            .cold_mut()
            .timer_pause
            .get_or_insert_with(|| TimerPause {
                count: 0,
                since: std::time::Instant::now(),
                since_ms: 0,
                shift: std::time::Duration::ZERO,
            });
        pause.count += 1;
        if pause.count == 1 {
            pause.since = std::time::Instant::now();
            pause.since_ms = self.virtual_ms.load(Ordering::Relaxed);
            if let Ok(scheduler) = self.scheduler() {
                scheduler.pause_target_timers(pid);
            }
        }
    }

    /// `erts_resume_paused_proc_timer`: the last resume re-arms what the pauses held.
    // Port of erts/emulator/beam/erl_hl_timer.c:2919 (erts_resume_paused_proc_timer) and :2949
    // (erts_resume_paused_bif_timers), OTP-29.1.1.
    pub(crate) fn erts_resume_proc_timer(&self, process: &mut Process, pid: Pid) {
        let Some(pause) = process
            .cold
            .as_mut()
            .and_then(|cold| cold.timer_pause.as_mut())
        else {
            return;
        };
        pause.count = pause.count.saturating_sub(1);
        if pause.count == 0 {
            pause.shift += if self.simulated {
                std::time::Duration::from_millis(
                    self.virtual_ms
                        .load(Ordering::Relaxed)
                        .saturating_sub(pause.since_ms),
                )
            } else {
                pause.since.elapsed()
            };
            if let Ok(scheduler) = self.scheduler() {
                scheduler.resume_target_timers(pid);
            }
        }
    }

    /// Time the process spent suspended since it last asked; shifts its receive deadline.
    pub(crate) fn take_pause_shift(&self, process: &mut Process) -> Option<std::time::Duration> {
        let cold = process.cold.as_mut()?;
        let pause = cold.timer_pause.as_ref()?;
        if pause.count != 0 {
            return None;
        }
        cold.timer_pause.take().map(|pause| pause.shift)
    }

    /// Live pids in this runtime's process table.
    ///
    /// Port of erts/emulator/beam/erl_ptab.c:1515 (`erts_ptab_processes_next`), OTP-29.1.1.
    /// The process table is the set; spawn and exit do not maintain a second one.
    pub(crate) fn process_pids(&self) -> Vec<Pid> {
        let Ok(scheduler) = self.scheduler() else {
            return Vec::new();
        };
        let max = arinsal_term::ptab::process_table_layout().max();
        let mut pids = Vec::new();
        let mut index = 0u32;
        loop {
            let (batch, next) = scheduler.pids_in_table_range(index, max, 4096);
            pids.extend(batch);
            if next <= index || next >= max {
                break;
            }
            index = next;
        }
        pids
    }

    /// Whether `pid` is in the process table (`erts_proc_lookup`).
    pub(crate) fn process_alive(&self, pid: Pid) -> bool {
        self.scheduler()
            .is_ok_and(|scheduler| scheduler.lookup(pid))
    }

    /// Publish that `pid` now owns `bit`. False when that process has already finished
    /// exit cleanup of `bit` (erl_process.c tests the word under the process lock; the
    /// caller rolls the table update back).
    pub(crate) fn publish_proc_flag(&self, pid: Pid, bit: u32) -> bool {
        let Ok(scheduler) = self.scheduler() else {
            return false;
        };
        scheduler
            .with_proc_flags(pid, |flags| {
                !proc_flags::finished(flags, bit) && proc_flags::publish(flags, bit)
            })
            .unwrap_or(false)
    }

    /// Sets or clears the HIBERNATED state bit: the process reports it on itself, as erts'
    /// state word does (erl_process.c:9304 erts_process_state2status).
    pub(crate) fn mark_hibernating(&self, pid: Pid, on: bool) {
        let Ok(scheduler) = self.scheduler() else {
            return;
        };
        scheduler.with_proc_flags(pid, |flags| {
            if on {
                proc_flags::set_state(flags, proc_flags::HIBERNATED);
            } else {
                proc_flags::clear_state(flags, proc_flags::HIBERNATED);
            }
        });
    }

    /// Status of another process, derived from its scheduling state when asked.
    // Port of erts/emulator/beam/erl_process.c:9304 (erts_process_state2status), OTP-29.1.1:
    // erts reads the state word instead of having each process publish its status.
    pub(crate) fn remote_status(&self, pid: Pid) -> &'static str {
        if self.suspend_active(pid) {
            return "suspended";
        }
        let state = self
            .scheduler()
            .ok()
            .and_then(|scheduler| {
                scheduler.with_proc_flags(pid, |flags| flags.load(Ordering::Acquire))
            })
            .unwrap_or(0);
        if state & proc_flags::EXITING != 0 {
            return "exiting";
        }
        if state & proc_flags::HIBERNATED != 0 {
            return "waiting";
        }
        match self
            .scheduler()
            .ok()
            .and_then(|scheduler| scheduler.is_active(pid))
        {
            Some(false) => "waiting",
            Some(true) | None => "runnable",
        }
    }

    pub(crate) fn is_hibernating(&self, pid: Pid) -> bool {
        self.scheduler()
            .ok()
            .and_then(|scheduler| {
                scheduler.with_proc_flags(pid, |flags| flags.load(Ordering::Acquire))
            })
            .is_some_and(|state| state & proc_flags::HIBERNATED != 0)
    }

    /// Run `body` against the module table shared by scheduler processes.
    pub(crate) fn with_modules<R>(
        &self,
        body: impl FnOnce(&[Arc<arinsal_loader::Module>]) -> R,
    ) -> R {
        let code = self.code.active_tables();
        body(&code.modules)
    }

    /// Create a distributed child with its remote monitor (and optional link) installed before
    /// it can run.
    // Port of erts/emulator/beam/erl_process.c:12940-13152 (erl_create_process, so->mref
    // monitor insertion), OTP-29.1.1: a spawn_request monitor lives in the child from creation,
    // so a child that exits at once still sends its own exit reason in the DOWN.
    pub(crate) fn spawn_mfa_unscheduled_watched(
        self: &Arc<Self>,
        module: &str,
        function: &str,
        args: &[arinsal_etf::OwnedTerm],
        linker: Option<Pid>,
        monitor: Option<(Pid, u64)>,
        parent: &arinsal_etf::OwnedTerm,
    ) -> Result<Pid, VmError> {
        self.spawn_mfa_scheduled(module, function, args, linker, monitor, Some(parent))
    }

    fn spawn_mfa_scheduled(
        self: &Arc<Self>,
        module: &str,
        function: &str,
        args: &[arinsal_etf::OwnedTerm],
        linker: Option<Pid>,
        monitor: Option<(Pid, u64)>,
        parent: Option<&arinsal_etf::OwnedTerm>,
    ) -> Result<Pid, VmError> {
        let (module_id, ip) = {
            let code = self.code.active_tables();
            let module_id = *code
                .loaded
                .get(module)
                .ok_or_else(|| VmError::Unsupported(format!("spawn: {module} not loaded")))?;
            let ip = code.modules[module_id]
                .export(function, args.len() as u8)
                .ok_or_else(|| {
                    VmError::Unsupported(format!(
                        "spawn: {module}:{function}/{} not exported",
                        args.len()
                    ))
                })?;
            (module_id, ip)
        };
        let mut child = Process::with_spawn_registers(args.len(), 0);
        child.module = module_id;
        child.ip = ip;
        child.set_runtime(Some(Arc::clone(self)));
        child.cold_mut().group_leader = None;
        child.initial_mfa = mfa_atoms(module, function, args.len() as u8);
        // Port of erts/emulator/beam/erl_process.c:12756-12767 (erl_create_process p->parent),
        // OTP-29.1.1: a remote parent is kept as its external pid.
        if let Some(parent) = parent {
            child.cold_mut().parent_external = Some(Box::new(parent.clone()));
        }
        if let Some(linker) = linker {
            child.cold_mut().links.insert(linker, Default::default());
        }
        if let Some((watcher, reference)) = monitor {
            child.insert_target_monitor(
                reference,
                watcher,
                arinsal_sched::SharedPayload(crate::proc_create::default_monitor_data()),
            );
        }
        if let Some(arity) = u8::try_from(args.len()).ok()
            && (arinsal_bifs::lookup(module, function, arity).is_some()
                || arinsal_spec::bif_lookup(module, function, arity).is_some())
        {
            child.cold_mut().initial_bif = Some((module.to_owned(), function.to_owned(), arity));
        }
        for (index, owned) in args.iter().enumerate() {
            let mut heap = arinsal_bifs::ProcessHeapHandle(&mut child.heap);
            child.x[index] = arinsal_term::from_owned(owned, &mut heap)
                .map_err(|_| VmError::Unsupported("spawn argument copy failed".into()))?;
        }
        let scheduler = self.scheduler()?;
        let pid = scheduler
            .spawn_unscheduled(child)
            .map_err(|error| VmError::Unsupported(format!("spawn: {error}")))?;
        Ok(pid)
    }

    /// Schedule a distributed child after its spawn reply was queued.
    pub(crate) fn schedule_spawn(&self, pid: Pid) -> Result<(), VmError> {
        self.scheduler()?
            .schedule_unscheduled(pid)
            .map_err(|error| VmError::Unsupported(format!("spawn schedule: {error}")))
    }
}

impl Process {
    /// Insert the target half a monitor signal carries into this process's monitor tree
    /// (erl_proc_sig_queue.c handle_monitor): a process monitor, or the `ERTS_MON_TYPE_RESOURCE`
    /// monitor of a NIF resource.
    pub(crate) fn insert_target_monitor(
        &mut self,
        reference: u64,
        from: Pid,
        shared: arinsal_sched::SharedPayload,
    ) {
        match shared.0.downcast::<crate::proc_create::MonitorData>() {
            Ok(data) => {
                self.cold_mut().monitored_by.insert(
                    reference,
                    crate::proc_create::TargetHalf { origin: from, data },
                );
            }
            Err(other) => {
                if let Ok(monitor) = other.downcast::<arinsal_nif::ResourceMonitor>() {
                    self.cold_mut().resource_monitors.insert(reference, monitor);
                }
            }
        }
    }

    fn absorb_exit_signals(&mut self, ctx: &mut RunCtx<'_, Message>) {
        // Port of erts/emulator/beam/erl_proc_sig_queue.c:7426 (erts_proc_exit_handle_signal),
        // OTP-29.1.1: the signals left in the inner queue come before the outer queue's.
        let mut unhandled = std::mem::take(&mut self.sig_cont);
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
                Payload::Signal(Signal::Monitor { reference, .. }) => {
                    // Port of erl_proc_sig_queue.c:7426 (erts_proc_exit_handle_signal),
                    // OTP-29.1.1: a monitor arriving after exit has begun is answered as noproc.
                    let _ = ctx.signal(from, Signal::MonitorNoproc(reference));
                }
                Payload::Signal(Signal::Demonitor(reference)) => {
                    if let Some(cold) = self.cold.as_mut() {
                        cold.monitored_by.remove(&reference);
                        cold.resource_monitors.remove(&reference);
                    }
                }
                Payload::Signal(Signal::Link) => {
                    // Port of erts/emulator/beam/erl_proc_sig_queue.c:7426
                    // (erts_proc_exit_handle_signal), OTP-29.1.1: a link reaching an
                    // exiting process is rejected with `noproc`.
                    if let Ok(reason) = Message::copy_from(crate::signals::atom("noproc")) {
                        let _ = ctx.signal(from, Signal::ExitLinked(reason));
                    }
                }
                Payload::Signal(Signal::Unlink(id)) => {
                    if let Some(cold) = self.cold.as_mut() {
                        cold.links.remove(&from);
                    }
                    let _ = ctx.signal(from, Signal::UnlinkAckSignal(id));
                }
                Payload::Signal(Signal::LiteralAreaCopy {
                    request, requester, ..
                }) => {
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
                Payload::Signal(Signal::SyncSuspend {
                    requester,
                    tag,
                    reply,
                    async_,
                }) => {
                    let _ =
                        crate::suspend::sync_reply(self, ctx, requester, tag, reply, async_, true);
                }
                _ => {}
            }
        }
    }

    pub(crate) fn tuple(&mut self, elements: &[Term]) -> Result<Term, VmError> {
        let mut heap = arinsal_bifs::ProcessHeapHandle(&mut self.heap);
        TermBuilder::new(&mut heap)
            .tuple(elements)
            .map_err(|error| VmError::Unsupported(format!("signal tuple: {error:?}")))
    }

    fn notify_exit(&mut self, vm: &mut Vm, ctx: &mut RunCtx<'_, Message>, reason: Term) {
        self.exit_stage1(vm, ctx, reason);
        self.exit_cont = Some(Box::new(crate::proc_create::ExitCont {
            reason,
            garbage: None,
            entry_result: None,
            code: 0,
        }));
        let mut reds = isize::MAX;
        let mut garbage = None;
        self.exit_ets(ctx, &mut reds, &mut garbage);
        self.exit_stage3(ctx, reason);
    }

    /// Process exit up to the release of owned ETS tables.
    ///
    /// Port of erts/emulator/beam/erl_process.c:14290-14430 (`erts_continue_exit_process`),
    /// OTP-29.1.1: each global table is touched only when the process-local word says this
    /// process has that resource.
    fn exit_stage1(&mut self, vm: &mut Vm, ctx: &mut RunCtx<'_, Message>, reason: Term) {
        self.final_exit_reason = Some(reason);
        let resources = proc_flags::resources_to_clean(ctx.exit_flags());
        if resources & proc_flags::CODE_PERM != 0 {
            crate::natives::code::code_mod_permission_process_exit(self, ctx.pid());
        }
        // Port of erts/emulator/beam/beam_bif_load.c:301-320 (commit_code_ix), OTP-29.1.1:
        // the code barrier of a loader commits and releases the code modification permission
        // even when the suspended loader exits.
        if let Some(staged) = self
            .cold
            .as_mut()
            .and_then(|cold| cold.finish_loading_commit.take().map(|boxed| *boxed))
        {
            let barrier_callback = staged.barrier_passed.is_some();
            let barrier_passed = staged
                .barrier_passed
                .as_ref()
                .is_none_or(|passed| passed.load(std::sync::atomic::Ordering::Acquire));
            if barrier_passed {
                vm.commit_staged(staged);
            }
            if !barrier_callback && let Some(runtime) = &self.runtime {
                crate::natives::code::release_code_mod_permission(runtime);
            }
        }
        crate::natives::proc::trace_finish_process_exit(vm, self, ctx);
        // erl_process.c:14221: the exit trace is emitted only when F_TRACE_PROCS is set.
        if resources & proc_flags::TRACE != 0 {
            crate::trace::emit(
                Some(vm),
                self,
                ctx,
                ctx.pid(),
                crate::trace::PROCS,
                "exit",
                &[reason],
            );
        }
        // Port of erts/emulator/beam/erl_process.c:14421-14464, OTP-29.1.1: releasing the
        // registered name is traced after the exit event, and only when p->reg != NULL.
        // The name lives on the process (`p->common.u.alive.reg`), so exit does not scan
        // the table. The table entry itself is released in `exit_stage3`.
        if resources & proc_flags::REG != 0
            && let Some(index) = self
                .runtime
                .as_ref()
                .and_then(|runtime| runtime.scheduler().ok())
                .and_then(|scheduler| scheduler.registered_atom_index(ctx.pid()))
        {
            crate::trace::emit(
                Some(vm),
                self,
                ctx,
                ctx.pid(),
                crate::trace::PROCS,
                "unregister",
                &[Term::atom(Atom(index))],
            );
        }
        // erl_process.c:14200 (erts_trace_check_exiting) matches the system-monitor receiver.
        if resources & proc_flags::SYS_MON != 0 {
            crate::natives::erts_debug::monitor_process_exited(self, ctx.pid());
        }
        // delete_all_trace_refs walks p->common.tracee.first_ref, which is NULL when untraced.
        if resources & proc_flags::TRACE != 0 {
            crate::trace::retain_exiting(self, ctx.pid());
        }
        if resources & proc_flags::TRACER != 0 {
            crate::trace::tracer_exited(self, ctx.pid());
        }
        // Port of erts/emulator/beam/erl_process.c:11039 (cleanup_sys_tasks), OTP-29.1.1:
        // delayed literal-copy requests of an exiting process are answered with `ok`.
        if let Some(cold) = self.cold.as_mut() {
            for task in std::mem::take(&mut cold.delayed_gc) {
                if let crate::proc_create::DelayedGc::Literal {
                    request, requester, ..
                } = task
                {
                    let _ = crate::natives::sys::reply_exiting_literal_area(
                        self, ctx, request, requester,
                    );
                }
            }
        }
        // Port of erts/emulator/beam/erl_process.c:14300-14304, OTP-29.1.1.
        // Timers aimed at this process are canceled only when p->bif_timers != NULL.
        if resources & proc_flags::BIF_TIMERS != 0 {
            ctx.cancel_target_timers(ctx.pid());
        }
        // g_proc_sched: a terminating suspender releases every suspend it acquired.
        // g_port_fix: close owned ports synchronously on the termination path.
        if let Some(runtime) = self.runtime.clone() {
            // Node monitors live in the process monitor tree; the global table is
            // consulted only when this process registered one (dist.c:6732).
            if resources & proc_flags::NODE_MON != 0 {
                crate::node_tables::lock().forget_node_monitors(ctx.pid());
            }
            // Every suspend this process holds is released at its target (erl_process.c:13894).
            crate::suspend::release_on_exit(self, ctx);
            crate::suspend::down_on_exit(self, ctx);
            if let Ok(scheduler) = runtime.scheduler() {
                // Ports are links on the process (erl_process.c:14084). No port list, no scan.
                if resources & proc_flags::PORTS != 0 {
                    crate::port::owner_exit(&runtime, scheduler, ctx.pid(), reason);
                }
                // Port of erts/emulator/beam/erl_process.c:14415-14417 (F_USING_DDLL).
                if resources & proc_flags::DDLL != 0 {
                    crate::ddll::proc_dead(scheduler, ctx.pid());
                }
            }
        }
    }

    /// Release the tables this exiting process owns, `reds` reductions at a time. Returns
    /// whether all of them are released; otherwise the process yields and calls again.
    ///
    /// Port of erts/emulator/beam/erl_db.c:5031 (erts_db_process_exiting), OTP-29.1.1.
    fn exit_ets(
        &mut self,
        ctx: &mut RunCtx<'_, Message>,
        reds: &mut isize,
        interrupted: &mut Option<arinsal_ets::Garbage>,
    ) -> bool {
        // erl_process.c:14362: erts_db_process_exiting runs only when F_USING_DB is set.
        if ctx.exit_flags().load(Ordering::Acquire) & proc_flags::USING_DB == 0 {
            return true;
        }
        let (Some(runtime), Some(owner)) = (self.runtime.clone(), ctx.pid().to_term()) else {
            return true;
        };
        // FREE_OWNED_TABLE: finish the table whose release was interrupted.
        if let Some(mut garbage) = interrupted.take()
            && !garbage.step(reds)
        {
            *interrupted = Some(garbage);
            return false;
        }
        // GET_OWNED_TABLE
        loop {
            if *reds <= 0 {
                return false;
            }
            let Some(tid) = runtime.ets.read().unwrap().first_owned(owner) else {
                break;
            };
            let info = {
                let registry = runtime.ets.read().unwrap();
                registry.get(tid).ok().map(|table| {
                    (
                        table.options.named_table.then_some(table.options.name),
                        table.options.heir,
                    )
                })
            };
            let Some((name, heir)) = info else {
                runtime.ets.write().unwrap().forget_owned(owner, tid);
                continue;
            };
            {
                // Port of erts/emulator/beam/erl_db.c:4898-4900 (give_table_to_heir),
                // OTP-29.1.1: an owner that is its own heir keeps, and so deletes, the table.
                let heir = heir.filter(|heir| heir.pid != owner);
                if let Some(heir) = heir
                    && let Some(pid) = Pid::from_term(heir.pid)
                    && !heir.transfer
                {
                    // Port of erts/emulator/beam/erl_db.c:4910-4930 (give_table_to_heir),
                    // OTP-29.1.1: `{heir, Pid}` hands the table over without a message.
                    let alive = runtime.scheduler().is_ok_and(|scheduler| {
                        scheduler.started_interval(pid) == Some(heir.started_interval)
                    });
                    if alive
                        && runtime.publish_proc_flag(pid, proc_flags::USING_DB)
                        && runtime
                            .ets
                            .write()
                            .unwrap()
                            .give_away(tid, heir.pid)
                            .is_ok()
                    {
                        continue;
                    }
                } else if let Some(heir) = heir
                && let Some(pid) = Pid::from_term(heir.pid)
                // erl_db.c:4908: a heir that died and whose pid was reused keeps nothing.
                && runtime.scheduler().is_ok_and(|scheduler| {
                    scheduler.started_interval(pid) == Some(heir.started_interval)
                }) {
                    let mut heap = arinsal_term::VecHeap::new();
                    // Port of erts/emulator/beam/erl_db.c:4959-4962
                    // (send_ets_transfer_message), OTP-29.1.1.
                    let tab = match name {
                        Some(name) => Ok(Term::atom(name)),
                        None => runtime
                            .ets
                            .read()
                            .unwrap()
                            .tid_term(tid, &mut heap)
                            .map_err(|_| arinsal_term::TermError::BadArg),
                    };
                    let message_term = tab.and_then(|tab| {
                        let from = ctx.pid().to_term().ok_or(arinsal_term::TermError::BadArg)?;
                        arinsal_term::TermBuilder::new(&mut heap).tuple(&[
                            crate::signals::atom("ETS-TRANSFER"),
                            tab,
                            from,
                            heir.data,
                        ])
                    });
                    if let Ok(message_term) = message_term
                        && let Ok(message) = Message::copy_from(message_term)
                    {
                        let mut registry = runtime.ets.write().unwrap();
                        // erl_db.c:4914: the heir's F_USING_DB bit, so its exit releases the table.
                        if runtime.publish_proc_flag(pid, proc_flags::USING_DB)
                            && registry.give_away(tid, heir.pid).is_ok()
                        {
                            drop(registry);
                            if ctx.send(pid, message).is_ok() {
                                continue;
                            }
                        }
                    }
                }
            }
            let detached = runtime.ets.write().unwrap().detach(tid);
            let Ok((mut garbage, fixations)) = detached else {
                runtime.ets.write().unwrap().forget_owned(owner, tid);
                continue;
            };
            // FREE_OWNED_TABLE
            *reds -= fixations as isize;
            if !garbage.step(reds) {
                *interrupted = Some(garbage);
                return false;
            }
        }
        // UNFIX_TABLES
        if runtime.ets.read().unwrap().has_fixations(owner) {
            runtime.ets.write().unwrap().release_fixations(owner);
        }
        true
    }

    /// Process exit after its tables are released: pending signals, names, links and monitors.
    fn exit_stage3(&mut self, ctx: &mut RunCtx<'_, Message>, reason: Term) {
        // delete_all_trace_refs (erl_trace.c:3774) is a no-op when first_ref is NULL.
        if ctx.exit_flags().load(Ordering::Acquire) & proc_flags::TRACE != 0 {
            crate::trace::clear(self, ctx.pid());
        }
        crate::trace::clear_save_calls(self);
        // ERTS_CONTINUE_EXIT_FREE releases the registered name before removing the pid from
        // the process table. The name index is stored on the process-table entry.
        if ctx.exit_flags().load(Ordering::Acquire) & proc_flags::REG != 0
            && let Some(runtime) = &self.runtime
            && let Ok(scheduler) = runtime.scheduler()
            && let Some(index) = scheduler.registered_atom_index(ctx.pid())
        {
            // Port of erts/emulator/beam/erl_process.c:14424-14426
            // (`erts_unregister_name` with `THE_NON_VALUE`), OTP-29.1.1.
            // The registered name is the last Erlang resource released, and only when
            // p->common.u.alive.reg != NULL.
            let name = Atom(index);
            let mut table = runtime.reg.write();
            if matches!(table.fetch(name), Some(crate::register::RegId::Proc(pid)) if pid == ctx.pid())
            {
                table.erase(name);
                scheduler.clear_registered_atom_index(ctx.pid(), index);
            }
        }
        // Port of erts/emulator/beam/erl_process.c:14438-14456
        // (ERTS_CONTINUE_EXIT_FREE), OTP-29.1.1: unregister the name, then mark the pid
        // dead in the process table. Later exit phases process links, monitors and signals.
        ctx.begin_exit();
        // Further publishes fail with `NoProcess` and the watcher synthesizes DOWN.
        // Signals already queued are installed before we notify.
        self.absorb_exit_signals(ctx);
        let Some(cold) = self.cold.take() else {
            return;
        };
        // Port of erts/emulator/beam/erl_process.c:13918 (origin ERTS_MON_TYPE_PORT),
        // OTP-29.1.1: exit demonitors each port the process was watching.
        for (&reference, monitor) in &cold.monitors {
            if let crate::proc_create::OriginMonitor::Port {
                port_id: Some(port_id),
                ..
            } = monitor
            {
                crate::port::demonitor_port(self, ctx.pid(), *port_id, reference);
            }
        }
        for (pid, node) in cold.links {
            if node.unlinking != 0 {
                continue;
            }
            if self.runtime.as_ref().is_some_and(|runtime| {
                crate::dist::forward_link_exit_if_proxy(runtime, pid, ctx.pid(), reason)
            }) {
                continue;
            }
            if let Ok(mut message) = Message::copy_from(reason) {
                // Port of erts/emulator/beam/erl_proc_sig_queue.c:1700-1703 and :1827
                // (send_gen_exit_signal), OTP-29.1.1: the exit signal carries the exiting
                // process's token and counts as a send.
                if crate::seq_trace::has_token(self)
                    && let Some(token) = crate::seq_trace::on_exit_signal(self, ctx, pid, reason)
                {
                    message.attach_seq_token(token);
                }
                let _ = ctx.signal(pid, arinsal_sched::Signal::ExitLinked(message));
            }
        }
        // Port of erts/emulator/beam/erl_process.c:13829 (erts_proc_exit_handle_monitor,
        // ERTS_MON_TYPE_RESOURCE): erts_fire_nif_monitor.
        if !cold.resource_monitors.is_empty()
            && let Some(exiting) = ctx.pid().to_term()
        {
            for monitor in cold.resource_monitors.values() {
                monitor.fire(exiting);
            }
        }
        for (reference, half) in cold.monitored_by {
            let pid = half.origin;
            if let Some(runtime) = self.runtime.as_ref()
                && crate::dist::forward_monitor_down_if_proxy(
                    runtime,
                    pid,
                    ctx.pid(),
                    reference,
                    reason,
                )
            {
                continue;
            }
            // Port of erts/emulator/beam/erl_proc_sig_queue.c:2836-2900 (erts_proc_sig_send_monitor_down),
            // OTP-29.1.1: an immediate reason travels in the signal and the origin builds the DOWN
            // message; any other reason is copied into a DOWN message built here, on the sender.
            if reason.is_pointer() {
                if let Ok(message) =
                    down_message_on_sender(self, reference, &half.data, ctx.pid(), reason)
                {
                    let _ = ctx.signal(
                        pid,
                        arinsal_sched::Signal::MonitorDownMsg { reference, message },
                    );
                }
            } else if let Ok(message) = Message::copy_from(reason) {
                let _ = ctx.signal(
                    pid,
                    arinsal_sched::Signal::MonitorDown {
                        reference,
                        reason: message,
                    },
                );
            }
        }
    }

    /// Place `value` on a waiting on-heap receiver and queue it before the main lock drops.
    ///
    /// Port of erts/emulator/beam/erl_message.c:621 (`erts_try_alloc_message_on_heap`)
    /// and erl_process.h:2878 (`erts_alloc_message_heap_state`), OTP-29.1.1.
    /// `Ok(false)` keeps the existing heap-fragment copy.
    fn try_send_on_receiver_heap(
        &self,
        ctx: Option<&mut RunCtx<'_, Message>>,
        from: Pid,
        to: Pid,
        counted: CountedSend<'_>,
        priority: bool,
        seq_token: &mut SendMeta,
    ) -> Result<bool, VmError> {
        if counted.words + counted.token_words == 0 {
            return Ok(false);
        }
        if ctx.is_none() {
            let mut failure = None;
            let native = arinsal_sched::native_try_send_on_heap::<Message>(
                from,
                to,
                &mut |task: &mut dyn std::any::Any| {
                    let receiver = task.downcast_mut::<Process>()?;
                    match message_on_receiver_heap(receiver, counted, priority, seq_token) {
                        Ok(envelope) => envelope,
                        Err(error) => {
                            failure = Some(error);
                            None
                        }
                    }
                },
            );
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
        let (envelope, words) = if shares_own_term {
            let mut envelope = Message::immediate(value);
            if via_prio_alias {
                envelope = envelope.with_priority();
            }
            envelope.apply_seq_state(std::mem::take(&mut seq_token.seq));
            envelope.alias = seq_token.alias;
            (envelope, 0)
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
            )? {
                self.bump_send_reds(ctx.as_deref_mut(), pid == sender, words);
                return Ok(value);
            }
            let envelope = if let Some(envelope) = on_heap {
                envelope
            } else {
                let token = match &mut seq_token.seq {
                    crate::seq_trace::SeqState::Token(token) => Some(token.as_mut()),
                    _ => None,
                };
                let mut envelope = Message::copy_counted(value, words, token, &literals)?;
                if via_prio_alias {
                    envelope = envelope.with_priority();
                }
                envelope.apply_seq_state(std::mem::take(&mut seq_token.seq));
                envelope.alias = seq_token.alias;
                envelope
            };
            (envelope, words)
        };
        let delivered = match ctx.as_deref_mut() {
            Some(ctx) => {
                let shared = on_own_heap && value.is_pointer();
                let delivered = if pid == sender {
                    ctx.send_self(envelope)
                } else {
                    ctx.send(pid, envelope)
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
                    && let Some(probe) = self
                        .cold
                        .as_ref()
                        .and_then(|cold| cold.signal_probe.as_ref())
                {
                    probe.send_self(pid, envelope)
                } else {
                    match if pid == sender {
                        Err(envelope)
                    } else {
                        arinsal_sched::native_send(sender, pid, envelope)
                    } {
                        Ok(delivered) => delivered,
                        Err(envelope) => self
                            .runtime
                            .as_ref()
                            .ok_or_else(|| {
                                VmError::Unsupported("send requires a scheduler".into())
                            })?
                            .scheduler()?
                            .send(sender, pid, envelope),
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
        let applied = reds.min(self.reductions.max(0));
        self.reductions -= applied;
        if self.heap.native_active() {
            return;
        }
        self.reductions_used = self.reductions_used.saturating_add(applied as u64);
        if let Some(ctx) = ctx {
            ctx.consume(applied as u32);
        }
    }

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
    fn trace_converted_signal(&mut self, ctx: &mut RunCtx<'_, Message>, message: Term, from: Pid) {
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
        let start = self.sig_cont.len();
        ctx.fetch_signals(&mut self.sig_cont);
        if cont
            || self.sig_cont.len() == start
            || (crate::trace::active()
                && crate::trace::flags(self, ctx.pid()) & crate::trace::RECEIVE != 0)
            || !self
                .sig_cont
                .iter()
                .all(|event| Self::is_ordinary_message(&event.payload))
        {
            ctx.set_sig_q(!self.sig_cont_empty());
            return Ok(());
        }
        // The whole batch is one splice onto the message queue in erts (LINK_MESSAGE of the
        // fetched list); a plain message needs no alias, priority or receive-trace handling.
        let count = self.sig_cont.len();
        self.sig_cont_taken += count as u64;
        ctx.consume_fetched_many(count);
        while let Some(Event { from, payload }) = self.sig_cont.pop_front() {
            match payload {
                Payload::Message(message) if message.alias == 0 && !message.is_priority() => {
                    let old_prio_len = self.cold.as_ref().map_or(0, |cold| cold.prio_len);
                    let before = self.message_words_before();
                    let new_prio_len = self.inbox.push_message(message, old_prio_len)?;
                    self.uncount_message_words(before);
                    debug_assert_eq!(new_prio_len, old_prio_len);
                }
                payload => self.move_message(ctx, from, payload)?,
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
            Payload::Message(message) | Payload::TimerMessage { message, .. } => {
                !message.is_altact_msg()
            }
            Payload::Timer { .. } => true,
            Payload::Signal(_) => false,
        }
    }

    /// Whether GC was enabled again with delayed GC tasks saved: erts moves them back to the
    /// system task queue and sets `ERTS_PSFLG_ACTIVE_SYS`, so they run at the next
    /// scheduling point even when the process waits.
    // Port of erts/emulator/beam/erl_process.c:11823-11935 (erts_set_gc_state), OTP-29.1.1.
    pub(crate) fn delayed_gc_due(&self) -> bool {
        self.heap.gc_enabled
            && self
                .cold
                .as_ref()
                .is_some_and(|cold| !cold.delayed_gc.is_empty())
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
            for task in std::mem::take(&mut self.cold_mut().delayed_gc) {
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
                match self.sig_cont.front() {
                    Some(event) if Self::is_ordinary_message(&event.payload) => {
                        let Event { from, payload } =
                            self.sig_cont.pop_front().expect("front checked");
                        self.sig_cont_taken += 1;
                        ctx.consume_fetched();
                        self.move_message(ctx, from, payload)?;
                    }
                    _ => break false,
                }
            };
            if !marker && self.sig_cont.is_empty() {
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
            let Some(Event { from, payload }) = self.sig_cont.pop_front() else {
                break Ok(true);
            };
            self.sig_cont_taken += 1;
            ctx.consume_fetched();
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

    /// Stretch the limit by up to 100 reductions, to at most `abs_lim`, when `receive` has no
    /// message to inspect and handling more signals may make one available.
    // Port of erts/emulator/beam/erl_proc_sig_queue.c:7181-7250 (stretch_limit), OTP-29.1.1.
    fn stretch_limit(&self, abs_lim: i32, limit: &mut i32, msgq_len: usize) -> bool {
        if abs_lim == *limit {
            return false;
        }
        // The save pointer is in the message queue at a message (receive markers are not
        // queue entries here).
        if self.receive_cursor < msgq_len {
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
                if self.inbox.get(self.receive_cursor).is_some() {
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
            if self.inbox.get(self.receive_cursor).is_some() {
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
        let Some(runtime) = self.runtime.clone() else {
            return Ok(true);
        };
        let Some((Some(_), priority)) = runtime.alias_lookup_prio(alias) else {
            return Ok(false);
        };
        let Some(entry) = self
            .cold
            .as_ref()
            .and_then(|cold| cold.monitors.get(&alias))
        else {
            return Ok(false);
        };
        if entry.alias_priority() != priority {
            return Ok(false);
        }
        if entry.alias_mode() == Some(crate::proc_create::AliasMode::ReplyDemonitor) {
            let entry = self.cold_mut().monitors.remove(&alias);
            match entry {
                Some(crate::proc_create::OriginMonitor::Process(half)) => {
                    self.cold_mut().prio_monitors.remove(&alias);
                    let _ = ctx.signal(half.target, arinsal_sched::Signal::Demonitor(alias));
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
                    | crate::proc_create::OriginMonitor::DistPort { .. },
                )
                | None => {}
            }
            runtime.alias_bind(alias, None);
        }
        Ok(true)
    }

    /// Move a message signal into the message queue.
    fn move_message(
        &mut self,
        ctx: &mut RunCtx<'_, Message>,
        from: Pid,
        payload: Payload<Message>,
    ) -> Result<(), VmError> {
        match payload {
            Payload::Message(message) => {
                if !self.alias_message_accepted(ctx, message.alias)? {
                    return Ok(());
                }
                let receive_traced = message.receive_traced;
                let priority = message.is_priority();
                let old_prio_len = self.cold.as_ref().map_or(0, |cold| cold.prio_len);
                let sender = from;
                let before = self.message_words_before();
                let new_prio_len = self.inbox.push_message(message, old_prio_len)?;
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
            Payload::TimerMessage { message, .. } => {
                let priority = message.is_priority();
                let old_prio_len = self.cold.as_ref().map_or(0, |cold| cold.prio_len);
                let before = self.message_words_before();
                let new_prio_len = self.inbox.push_message(message, old_prio_len)?;
                self.uncount_message_words(before);
                self.cold_mut().prio_len = new_prio_len;
                if priority {
                    let priority_term = self.inbox.get(old_prio_len).copied().ok_or_else(|| {
                        VmError::Unsupported("priority message missing after insertion".into())
                    })?;
                    self.priority_item_inserted(old_prio_len, priority_term)?;
                }
            }
            Payload::Timer { reference, message } => {
                let timer_id = message.timer_id;
                let term = message.into_receiver(self)?;
                let id = timer_id.or(reference.ref_key()).unwrap_or(reference.id());
                let reference = crate::signals::reference(self, id)?;
                let tuple = self.tuple(&[crate::signals::atom("timeout"), reference, term])?;
                self.inbox.push_back(tuple);
                self.trace_converted_signal(ctx, tuple, from);
            }
            Payload::Signal(_) => unreachable!("move_message takes message signals"),
        }
        Ok(())
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
        let signal = match payload {
            // ERTS_SIG_Q_OP_ALTACT_MSG: a priority message enters the priority queue.
            payload @ (Payload::Message(_)
            | Payload::TimerMessage { .. }
            | Payload::Timer { .. }) => {
                self.move_message(ctx, from, payload)?;
                return Ok(0);
            }
            Payload::Signal(signal) => signal,
        };
        let cost = match signal {
            arinsal_sched::Signal::Link => {
                // Port of erts/emulator/beam/erl_proc_sig_queue.c:6636-6646 (ERTS_SIG_Q_OP_LINK):
                // the receiver reports getting_linked in signal order, for a new link only.
                if let std::collections::btree_map::Entry::Vacant(slot) =
                    self.cold_mut().links.entry(from)
                {
                    slot.insert(Default::default());
                    self.trace_getting_linked(ctx, from);
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
            arinsal_sched::Signal::Unlink(id) => {
                // Port of erl_proc_sig_queue.c:6693-6713: a pending local unlink keeps its
                // link record until the matching acknowledgement is handled.
                let removed = self
                    .cold
                    .as_mut()
                    .is_some_and(|cold| match cold.links.get(&from) {
                        Some(node) if node.unlinking != 0 => false,
                        Some(_) => cold.links.remove(&from).is_some(),
                        None => false,
                    });
                if removed {
                    self.trace_getting_unlinked(ctx, from);
                }
                let _ = ctx.signal(from, arinsal_sched::Signal::UnlinkAckSignal(id));
                if removed { 4 } else { 0 }
            }
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
            arinsal_sched::Signal::SyncSuspend {
                requester,
                tag,
                reply,
                async_,
            } => {
                crate::suspend::sync_reply(self, ctx, requester, tag, reply, async_, false)?;
                2
            }
            arinsal_sched::Signal::Monitor { reference, shared } => {
                self.insert_target_monitor(reference, from, shared);
                2
            }
            arinsal_sched::Signal::Demonitor(reference) => {
                if let Some(cold) = self.cold.as_mut() {
                    cold.monitored_by.remove(&reference);
                    cold.resource_monitors.remove(&reference);
                }
                2
            }
            signal @ (arinsal_sched::Signal::Exit(_) | arinsal_sched::Signal::ExitLinked(_)) => {
                let (linked_exit, message) = match signal {
                    arinsal_sched::Signal::ExitLinked(message) => (true, message),
                    arinsal_sched::Signal::Exit(message) => (false, message),
                    _ => unreachable!(),
                };
                // Port of erts/emulator/beam/erl_proc_sig_queue.c:4685-4795
                // (handle_exit_signal), OTP-29.1.1: a link exit removes the link and a
                // process that survives it traces getting_unlinked.
                let priority = message.is_priority()
                    || self
                        .cold
                        .as_ref()
                        .is_some_and(|cold| cold.links.get(&from).is_some_and(|node| node.prio));
                let was_linked = linked_exit
                    && self
                        .cold
                        .as_mut()
                        .is_some_and(|cold| cold.links.remove(&from).is_some());
                let mut message = message;
                let seq_token = message.take_seq_token();
                let reason = message.into_receiver(self)?;
                if reason == crate::signals::atom("kill") && !linked_exit {
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
                    let tuple = self.tuple(&[crate::signals::atom("EXIT"), from, reason])?;
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
                    self.note_exit_reason(reason)?;
                    return Err(VmError::Trap(crate::exceptions::Trap::exit(reason)));
                }
                if was_linked {
                    self.trace_getting_unlinked(ctx, from);
                }
                // Ignored: `cnt = 1` plus one for destroying the signal.
                2
            }
            // Port of erts/emulator/beam/io.c:3841-3891 (erts_deliver_port_exit), OTP-29.1.1.
            arinsal_sched::Signal::PortExit { port, reason } => {
                let port = port.into_receiver(self)?;
                let reason = reason.into_receiver(self)?;
                if reason == crate::signals::atom("kill") {
                    return Err(VmError::Trap(crate::exceptions::Trap::killed()));
                }
                if self.trap_exit {
                    let tuple = self.tuple(&[crate::signals::atom("EXIT"), port, reason])?;
                    self.inbox.push_back(tuple);
                    return Ok(1);
                }
                if reason != Term::atom(arinsal_term::atoms::NORMAL) {
                    self.note_exit_reason(reason)?;
                    return Err(VmError::Trap(crate::exceptions::Trap::exit(reason)));
                }
                2
            }
            arinsal_sched::Signal::MonitorNoproc(reference) => {
                let queued = self.inbox.len();
                self.deliver_monitor_down(from, reference, crate::signals::atom("noproc"))?;
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
            arinsal_sched::Signal::MonitorDownMsg { reference, message } => {
                // The sender built the DOWN message (erl_proc_sig_queue.c:2836-2900). The origin
                // still drops it when its monitor is gone (erl_proc_sig_queue.c:6355).
                let queued = self.inbox.len();
                self.deliver_monitor_down_message(reference, message)?;
                self.trace_new_message(ctx, queued, from);
                8
            }
            arinsal_sched::Signal::UnlinkAck(id) => {
                // Port of erts/emulator/beam/erl_proc_sig_queue.c:6794
                // (ERTS_SIG_Q_OP_PROCESS_INFO), OTP-29.1.1.
                // The scheduler signal enum has no request op; a nonzero
                // unlink-ack id is the wakeup for a queued request.
                // handle_process_info (erl_proc_sig_queue.c:5312) costs at least 8.
                if id != 0 {
                    crate::signals::handle_request(self, ctx, id)?;
                    8
                } else {
                    0
                }
            }
            arinsal_sched::Signal::UnlinkAckSignal(id) => {
                // Port of erl_proc_sig_queue.c:6745-6772: removing the link costs 4.
                if let Some(cold) = self.cold.as_mut()
                    && cold
                        .links
                        .get(&from)
                        .is_some_and(|node| node.unlinking == id)
                {
                    cold.links.remove(&from);
                    4
                } else {
                    0
                }
            }
            arinsal_sched::Signal::Alias(_) | arinsal_sched::Signal::Unalias(_) => {
                return Err(VmError::Unsupported("process aliases".into()));
            }
            arinsal_sched::Signal::GarbageCollect => {
                if self.heap.gc_enabled {
                    self.force_gc()?;
                } else {
                    self.cold_mut()
                        .delayed_gc
                        .push(crate::proc_create::DelayedGc::Collect);
                }
                0
            }
            arinsal_sched::Signal::LiteralAreaCopy {
                area_id,
                request,
                how,
                requester,
            } => {
                if !self.heap.gc_enabled && how != arinsal_sched::LiteralCopyHow::Init {
                    self.cold_mut()
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
}

impl Process {
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
                let _ = runtime.result.send(Err(error));
            }
            // `notify_exit` released the cold state; the process stays marked exited.
            self.cold_mut().dirty_exited = true;
        }
        // Replies, exit and DOWN signals must not wait for the dirty job to return.
        ctx.flush_pending();
        done
    }

    /// Whether this process already exited while executing a dirty job.
    pub(crate) fn dirty_exiting(&self) -> bool {
        self.cold.as_ref().is_some_and(|cold| cold.dirty_exited)
    }

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
        crate::natives::sys::after_collection(self, 0, gc.collections, gc.words_reclaimed);
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
        crate::natives::sys::after_collection(self, live, gc.collections, gc.words_reclaimed);
        Ok(())
    }

    pub(crate) fn service_deferred_gc(&mut self) -> Result<(), VmError> {
        if self.heap.gc_enabled && std::mem::take(&mut self.gc_deferred) {
            let live = self.gc_live;
            let stats = self.collect_heap_roots(live, &mut [], 0)?;
            // Port of erts/emulator/beam/erl_gc.c:922-932 (`garbage_collect` updates
            // `esdp->gc_info`), OTP-29.1.1: a collection deferred while GC was disabled
            // is counted when it actually runs.
            crate::natives::sys::after_collection(
                self,
                live,
                stats.collections,
                stats.words_reclaimed,
            );
        }
        Ok(())
    }

    /// Emit a `garbage_collection` trace event with the GC info list and `{wordsize, Size}`.
    /// Port of erts/emulator/beam/erl_trace.c:1439 (`trace_gc`), OTP-29.1.1.
    fn trace_gc(&mut self, pid: arinsal_sched::Pid, tag: &str, size: usize) {
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
        let Some(cold) = self.cold.as_mut() else {
            return Ok(0);
        };
        if !cold.delayed_gc.is_empty() {
            return Ok(0);
        }
        let Some(probe) = cold.signal_probe.take() else {
            return Ok(0);
        };
        let fetched =
            probe.fetch_messages_if(|message| !message.is_altact_msg(), &mut self.sig_cont);
        self.cold_mut().signal_probe = Some(probe);
        while let Some(Event { payload, .. }) = self.sig_cont.pop_front() {
            self.sig_cont_taken += 1;
            let Payload::Message(message) = payload else {
                unreachable!("fetch_messages_if takes messages only");
            };
            let old_prio_len = self.cold.as_ref().map_or(0, |cold| cold.prio_len);
            let before = self.message_words_before();
            let new_prio_len = self.inbox.push_message(message, old_prio_len)?;
            self.uncount_message_words(before);
            self.cold_mut().prio_len = new_prio_len;
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
    fn fetch_outer_queue_for_gc(&mut self) -> Result<(), VmError> {
        if self.message_queue_data() != MessageQueueData::OnHeap {
            return Ok(());
        }
        if self.fetch_messages_in_place()? != 0 {
            return Ok(());
        }
        let Some(probe) = self.cold.as_mut().and_then(|cold| cold.signal_probe.take()) else {
            return Ok(());
        };
        probe.fetch_all(&mut self.sig_cont);
        probe.set_sig_q(!self.sig_cont_empty());
        self.cold_mut().signal_probe = Some(probe);
        Ok(())
    }

    fn sig_cont_message(payload: &Payload<Message>) -> Option<&Message> {
        match payload {
            Payload::Message(message) | Payload::TimerMessage { message, .. } => Some(message),
            _ => None,
        }
    }

    fn sig_cont_message_mut(payload: &mut Payload<Message>) -> Option<&mut Message> {
        match payload {
            Payload::Message(message) | Payload::TimerMessage { message, .. } => Some(message),
            _ => None,
        }
    }

    fn message_words_before(&self) -> Option<i64> {
        self.cold
            .as_ref()
            .is_some_and(|cold| !cold.call_memory.is_empty())
            .then(|| self.allocated_words(0))
    }

    fn uncount_message_words(&mut self, allocated_before: Option<i64>) {
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

    fn collect_roots(
        &mut self,
        live_x: usize,
        extra: &mut [Term],
        min_free: usize,
        hibernate: bool,
    ) -> Result<arinsal_term::GcStats, VmError> {
        let stats = self.collect_roots_inner(live_x, extra, min_free, hibernate)?;
        // A collection moves the young heap. erts keeps HTOP, STOP, HEAP and HEND as the
        // process's own fields, so they are right the moment the collector returns; here the
        // ABI prefix is a copy, and every path that returns to native code after a collection
        // (success, error or trap alike) must find the new heap in it.
        self.sync_native_heap();
        Ok(stats)
    }

    fn collect_roots_inner(
        &mut self,
        live_x: usize,
        extra: &mut [Term],
        min_free: usize,
        hibernate: bool,
    ) -> Result<arinsal_term::GcStats, VmError> {
        if crate::xreg_poison_enabled()
            && let Some(register) = self.x[..live_x.min(self.x.len())]
                .iter()
                .position(|term| *term == crate::XREG_POISON)
        {
            panic!("xreg poison: GC roots dead register x{register} (live_x={live_x})");
        }
        // Port of erts/emulator/beam/erl_gc.c:782-785 (garbage_collect: F_DELAY_GC), OTP-29.1.1.
        if !hibernate && self.delay_gc {
            self.heap.delay_collection(min_free);
            return Ok(arinsal_term::GcStats::default());
        }
        if !hibernate && self.delay_for_dirty_gc(min_free) {
            return Ok(arinsal_term::GcStats::default());
        }
        // An on-heap message installed while this process was queued lives only in
        // the outer signal queue until this fetch. Scanning without it would
        // reclaim that term. Hibernate fetches too (erl_gc.c:1016).
        self.fetch_outer_queue_for_gc()?;
        // Port of erl_gc.c:2616 (`setup_rootset` with no dictionary and an empty message
        // queue): the stack is scanned in place and `extra` is rooted directly, as in
        // `erts_garbage_collect(p, 0, &result, 1)` after a BIF. Building and rewriting
        // an auxiliary root vector is the on-heap message and dictionary case.
        if !hibernate
            && self.inbox.is_empty()
            && self.sig_cont.is_empty()
            && self.dictionary.is_none()
            && !self.seq_token_root.is_pointer()
            && self.apply_inline_len == 0
            && self.cold.as_ref().is_none_or(|cold| {
                cold.persistent_get_all.is_none()
                    && cold.apply_roots.is_empty()
                    && cold.ext_last_released.is_none()
                    && cold.nif_pending.is_none()
                    && cold
                        .ets_insert
                        .as_ref()
                        .is_none_or(|state| state.cursor().is_none())
                    && cold
                        .ets_select
                        .as_ref()
                        .is_none_or(|state| state.saved.is_empty())
                    && cold
                        .bif_trap
                        .as_ref()
                        .is_none_or(|trap| !trap.args_are_roots())
                    && cold.call_memory.is_empty()
            })
            && !self.has_dirty_result_roots()
            && self.max_heap_peak == 0
            && !self.max_heap_limited()
            && self
                .self_pid
                .is_none_or(|pid| crate::trace::flags(self, pid) & crate::trace::GC == 0)
        {
            let stats = self
                .heap
                .collect(&mut self.x[..live_x], extra, min_free)
                .map_err(|error| VmError::Unsupported(format!("process GC: {error:?}")))?;
            self.stats.gc.collections += stats.collections;
            self.stats.gc.nanoseconds += stats.nanoseconds;
            crate::natives::erts_debug::after_collection(self, stats.nanoseconds);
            return Ok(stats);
        }
        // Port of erts/emulator/beam/erl_gc.c:3730 (`has_reached_max_heap_size`) call in
        // `garbage_collect`, OTP-29.1.1: the limit is judged on the pre-collection size.
        if self.max_heap_limited() {
            self.max_heap_peak = self.max_heap_peak.max(self.heap.total_heap_size_words());
        }
        let (indices, mut roots) = self.inbox.gc_root_snapshot();
        let mailbox_len = roots.len();
        let continuation = self
            .cold
            .as_ref()
            .and_then(|cold| cold.persistent_get_all.as_ref())
            .map(|state| state.result);
        if let Some(result) = continuation {
            roots.push(result);
        }
        roots.extend_from_slice(extra);
        let extra_end = roots.len();
        // The process dictionary is rooted on the process heap, like erts' ProcDict.
        // Port of erts/emulator/beam/erl_process_dict.c (erts_dicts_mem_size / GC roots), OTP-29.1.1.
        let dict_len = self
            .dictionary
            .as_ref()
            .map_or(0, |dictionary| dictionary.len());
        if let Some(dictionary) = self.dictionary.as_ref() {
            for (key, value) in dictionary.entries() {
                roots.push(key);
                roots.push(value);
            }
        }
        let dict_end = roots.len();
        let inline_len = usize::from(self.apply_inline_len);
        roots.extend_from_slice(&self.apply_inline[..inline_len]);
        let mut nif_roots_len = 0;
        let mut trap_roots_len = 0;
        let mut bif_trap_state_root = None;
        if let Some(cold) = self.cold.as_mut() {
            roots.extend_from_slice(&cold.apply_roots);
            if let Some(released) = cold.ext_last_released.as_ref() {
                roots.extend_from_slice(&released.words);
            }
            if let Some(pending) = cold.nif_pending.as_mut() {
                nif_roots_len = pending.roots_mut().len();
                roots.extend_from_slice(pending.roots_mut());
            }
            // Port of erts/emulator/beam/bif.h (ERTS_BIF_PREP_TRAPn leaves the arguments in
            // `reg`, the `c_p->arity` live registers of the process while it is trapped),
            // OTP-29.1.1.
            if let Some(trap) = cold.bif_trap.as_ref().filter(|trap| trap.args_are_roots()) {
                trap_roots_len = trap.arity;
                roots.extend_from_slice(&trap.args[..trap.arity]);
            }
            if let Some(term) = cold.bif_trap.as_ref().and_then(|trap| trap.state_term) {
                bif_trap_state_root = Some(roots.len());
                roots.push(term);
            }
        }
        let ets_insert_root = self
            .cold
            .as_ref()
            .and_then(|cold| cold.ets_insert.as_deref())
            .and_then(crate::proc_create::EtsInsert::cursor)
            .map(|cursor| {
                let index = roots.len();
                roots.push(cursor);
                index
            });
        // Port of erts/emulator/beam/erl_db_hash.c (select_chunk_on_trap: the partial result
        // list is a term of the continuation), OTP-29.1.1: the results a trapped `select` has
        // so far are roots until it resumes.
        let ets_select_start = roots.len();
        if let Some(state) = self.cold.as_ref().and_then(|cold| cold.ets_select.as_ref()) {
            roots.extend_from_slice(state.saved.terms());
        }
        let ets_select_end = roots.len();
        // A finished dirty job's result is in erts' argument registers until the call resumes.
        let dirty_start = roots.len();
        roots.extend(self.dirty_result_roots());
        let dirty_end = roots.len();
        // Port of erts/emulator/beam/erl_gc.c:2616 (setup_rootset walks the message queue and
        // the middle signal queue, ERTS_FOREACH_SIG_PRIVQS), OTP-29.1.1: on-heap messages still
        // waiting in the middle queue are roots too.
        let cont_start = roots.len();
        roots.extend(self.sig_cont.iter().filter_map(|event| {
            Self::sig_cont_message(&event.payload)
                .filter(|message| message.is_heap_root())
                .map(|message| message.term)
        }));
        // Port of erts/emulator/beam/erl_gc.c:2616 (setup_rootset roots `p->seq_trace_token` and
        // the token of each queued on-heap message), OTP-29.1.1.
        crate::seq_trace::sync_epoch(self);
        let seq_start = roots.len();
        roots.push(self.seq_token_root);
        roots.extend(self.sig_cont.iter().filter_map(|event| {
            Self::sig_cont_message(&event.payload).and_then(Message::heap_token_root)
        }));
        // Port of erts/emulator/beam/erl_gc.c:832-901 (`trace_gc` around minor/major collections), OTP-29.1.1.
        let traced = self
            .self_pid
            .filter(|&pid| crate::trace::flags(self, pid) & crate::trace::GC != 0);
        if let Some(pid) = traced
            && self.heap.minor_falls_back_to_major()
        {
            // erts traces the minor attempt that returned -1 before the major collection.
            self.trace_gc(pid, "gc_minor_start", min_free);
            self.trace_gc(pid, "gc_minor_end", 0);
        }
        let end_tag = if self.heap.collection_is_major() || self.heap.minor_falls_back_to_major() {
            "gc_major_end"
        } else {
            "gc_minor_end"
        };
        if let Some(pid) = traced {
            let start_tag = if end_tag == "gc_major_end" {
                "gc_major_start"
            } else {
                "gc_minor_start"
            };
            self.trace_gc(pid, start_tag, min_free);
        }
        // Port of erts/emulator/beam/erl_gc.c:823-825 (garbage_collect), OTP-29.1.1: the words
        // allocated so far stay counted by call_memory after the collection resets the heap.
        if self
            .cold
            .as_ref()
            .is_some_and(|cold| !cold.call_memory.is_empty())
        {
            let allocated = self.allocated_words(0);
            crate::trace_bp::adjust_memory_break(self, allocated);
        }
        // Port of erts/emulator/beam/erl_gc.c:1500-1501 and 1947-1948, OTP-29.1.1: with an
        // on-heap message queue the collection moves queued message data onto the heap.
        let (moved_indices, mut moved) =
            if !hibernate && self.message_queue_data() == MessageQueueData::OnHeap {
                self.inbox.take_message_fragments()
            } else {
                (Vec::new(), Vec::new())
            };
        if self.max_heap_limited() {
            if hibernate {
                self.heap.request_full_sweep();
            }
            let limit = self
                .cold
                .as_ref()
                .expect("limited heap has cold data")
                .max_heap;
            let binary_words = (if limit.include_shared_binaries {
                off_heap_binary_words(self)
            } else {
                0
            }) as u64;
            let checks = match self
                .heap
                .max_heap_collection_checks(min_free, moved.iter().map(|(_, _, heap)| heap))
            {
                Ok(checks) => checks,
                Err(error) => {
                    if !moved_indices.is_empty() {
                        self.inbox.restore_moved_messages(&moved_indices, moved);
                    }
                    return Err(VmError::Unsupported(format!("process GC: {error:?}")));
                }
            };
            let exceeded = [Some(checks.0), checks.1]
                .into_iter()
                .flatten()
                .find(|&size| (size as u64).saturating_add(binary_words) > limit.size);
            if let Some(size) = exceeded {
                self.max_heap_peak = self.max_heap_peak.max(size);
                if limit.kill {
                    if !moved_indices.is_empty() {
                        self.inbox.restore_moved_messages(&moved_indices, moved);
                    }
                    return Err(VmError::Unsupported("max_heap_size".into()));
                }
            }
        }
        let stats = if hibernate {
            self.heap
                .collect_hibernate(&mut self.x[..live_x], &mut roots)
        } else {
            self.heap
                .collect_with_messages(&mut self.x[..live_x], &mut roots, min_free, &mut moved)
        };
        if !moved_indices.is_empty() {
            self.inbox.restore_moved_messages(&moved_indices, moved);
        }
        let stats =
            stats.map_err(|error| VmError::Unsupported(format!("process GC: {error:?}")))?;
        if let Some(pid) = traced {
            self.trace_gc(pid, end_tag, stats.words_reclaimed as usize);
        }
        self.stats.gc.collections += stats.collections;
        self.stats.gc.nanoseconds += stats.nanoseconds;
        self.inbox.update_gc_roots(&indices, &roots[..mailbox_len]);
        if continuation.is_some()
            && let Some(state) = self
                .cold
                .as_mut()
                .and_then(|cold| cold.persistent_get_all.as_mut())
        {
            state.result = roots[mailbox_len];
        }
        let extra_start = mailbox_len + usize::from(continuation.is_some());
        extra.copy_from_slice(&roots[extra_start..extra_end]);
        if let Some(dictionary) = self.dictionary.as_mut() {
            let mut index = extra_end;
            dictionary.for_each_mut(|key, value| {
                *key = roots[index];
                *value = roots[index + 1];
                index += 2;
            });
            assert_eq!(index, extra_end + 2 * dict_len, "dictionary GC roots");
        }
        let inline_len = usize::from(self.apply_inline_len);
        self.apply_inline[..inline_len].copy_from_slice(&roots[dict_end..dict_end + inline_len]);
        if let Some(cold) = self.cold.as_mut() {
            let apply_start = dict_end + inline_len;
            let apply_end = apply_start + cold.apply_roots.len();
            cold.apply_roots
                .copy_from_slice(&roots[apply_start..apply_end]);
            let released_end = apply_end
                + cold
                    .ext_last_released
                    .as_ref()
                    .map_or(0, |released| released.words.len());
            if let Some(released) = cold.ext_last_released.as_mut() {
                released
                    .words
                    .copy_from_slice(&roots[apply_end..released_end]);
            }
            if let Some(pending) = cold.nif_pending.as_mut() {
                pending
                    .roots_mut()
                    .copy_from_slice(&roots[released_end..released_end + nif_roots_len]);
            }
            if trap_roots_len != 0
                && let Some(trap) = cold.bif_trap.as_mut()
            {
                let start = released_end + nif_roots_len;
                trap.args[..trap_roots_len].copy_from_slice(&roots[start..start + trap_roots_len]);
            }
            if let Some(index) = bif_trap_state_root
                && let Some(trap) = cold.bif_trap.as_mut()
            {
                trap.state_term = Some(roots[index]);
            }
            if let Some(index) = ets_insert_root
                && let Some(state) = cold.ets_insert.as_mut()
            {
                state.update_cursor(roots[index]);
            }
            if let Some(state) = cold.ets_select.as_mut() {
                state
                    .saved
                    .roots_mut()
                    .copy_from_slice(&roots[ets_select_start..ets_select_end]);
            }
        }
        for (slot, &term) in self
            .dirty_result_roots_mut()
            .into_iter()
            .zip(&roots[dirty_start..dirty_end])
        {
            *slot = term;
        }
        self.seq_token_root = roots[seq_start];
        let mut token_roots = roots[seq_start + 1..].iter();
        for event in &mut self.sig_cont {
            if let Some(message) = Self::sig_cont_message_mut(&mut event.payload)
                && message.heap_token_root().is_some()
            {
                message.set_heap_token_root(*token_roots.next().expect("middle queue token root"));
            }
        }
        let mut cont_roots = roots[cont_start..seq_start].iter();
        for event in &mut self.sig_cont {
            if let Some(message) = Self::sig_cont_message_mut(&mut event.payload)
                && message.is_heap_root()
            {
                message.term = *cont_roots.next().expect("middle queue GC root");
            }
        }
        if self.max_heap_peak != 0 || self.max_heap_limited() {
            self.max_heap_peak = self.max_heap_peak.max(self.heap.total_heap_size_words());
        }
        crate::natives::erts_debug::after_collection(self, stats.nanoseconds);
        Ok(stats)
    }

    /// Hand a potentially long collection to a dirty CPU scheduler: satisfy `need` without
    /// collecting and make the process leave its scheduler at the next reduction check.
    /// Returns whether the collection was delayed.
    // Port of erts/emulator/beam/erl_gc.c:780-792 (garbage_collect), 688-715
    // (check_for_possibly_long_gc) and 500-603 (delay_garbage_collection), OTP-29.1.1.
    fn delay_for_dirty_gc(&mut self, need: usize) -> bool {
        // Only a scheduled process can move to a dirty scheduler; a dirty scheduler collects.
        if self.runtime.is_none() || arinsal_sched::current_scheduler_type().is_dirty() {
            return false;
        }
        // erl_gc.h:26 (ERTS_POTENTIALLY_LONG_GC_HSIZE).
        const POTENTIALLY_LONG_GC_HSIZE: usize = 128 * 1024;
        let mut size = self
            .heap
            .young_gen_usage()
            .saturating_add(self.heap.stack_words());
        // The old generation only counts for a major collection, so a young generation
        // plus old heap below the limit is below it whichever collection runs.
        if size.saturating_add(self.heap.old_used_words()) < POTENTIALLY_LONG_GC_HSIZE {
            return false;
        }
        // A collection that starts as minor is checked on its young generation alone. If
        // that is already long, the dirty scheduler runs the minor attempt and any major
        // collection it falls back to. Otherwise the minor attempt runs here, and a minor
        // that cannot tenure is checked again as a major collection.
        let counted_major = self.heap.collection_is_major();
        let minor_is_long = !counted_major && size >= POTENTIALLY_LONG_GC_HSIZE;
        let failed_minor =
            !counted_major && !minor_is_long && self.heap.minor_falls_back_to_major();
        let major = counted_major || failed_minor;
        if major {
            size = size.saturating_add(self.heap.old_used_words());
        }
        if size < POTENTIALLY_LONG_GC_HSIZE {
            return false;
        }
        if failed_minor {
            let traced = self
                .self_pid
                .filter(|&pid| crate::trace::flags(self, pid) & crate::trace::GC != 0);
            if let Some(pid) = traced {
                self.trace_gc(pid, "gc_minor_start", need);
                self.trace_gc(pid, "gc_minor_end", 0);
            }
        }
        let cold = self.cold_mut();
        cold.dirty_gc = Some(if major {
            crate::proc_create::DirtyGc::Major
        } else {
            crate::proc_create::DirtyGc::Minor
        });
        // erts_schedule_dirty_sys_execution: the process moves to a dirty CPU scheduler
        // when it leaves this one.
        cold.dirty_sys_gc = true;
        self.delay_heap_collection(need);
        // erl_gc.c, delay_garbage_collection (force_reschedule): the remaining reductions
        // are spent, and all but ERTS_ABANDON_HEAP_COST of them are not the process's own
        // work. The interpreter keeps its slice in the scheduler and never charges the rest
        // of it.
        if self.heap.native_active() && self.reductions > ABANDON_HEAP_COST {
            self.virtual_reds = self
                .virtual_reds
                .saturating_add((self.reductions - ABANDON_HEAP_COST) as u32);
        }
        self.force_yield = true;
        true
    }

    /// Run the collection a normal scheduler delayed, on the dirty CPU scheduler.
    // Port of erts/emulator/beam/erl_process.c:11196-11201 (erts_execute_dirty_system_task),
    // OTP-29.1.1: the roots are the `arity` registers the process was scheduled out with.
    fn run_dirty_gc(&mut self) -> Result<(), VmError> {
        let Some(kind) = self.cold.as_mut().and_then(|cold| cold.dirty_gc.take()) else {
            return Ok(());
        };
        if kind == crate::proc_create::DirtyGc::Major {
            // F_NEED_FULLSWEEP.
            self.heap.request_full_sweep();
        }
        let live = switched_out_live(self);
        let stats = self.collect_heap_roots(live, &mut [], 0)?;
        crate::natives::sys::after_collection(self, live, stats.collections, stats.words_reclaimed);
        Ok(())
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
        crate::natives::sys::after_collection(
            self,
            live_x,
            stats.collections,
            stats.words_reclaimed,
        );
        self.charge_gc_stats(&stats);
        Ok(())
    }

    // Port of erts/emulator/beam/beam_bif_load.c:1149 (check_process_code), OTP-29.1.1.
    // A process suspended in native code is checked by its native resume address and the
    // native continuation pointers on its stack; `self.module` is only its interpreter module.
    pub(crate) fn references_code(&self, module: usize, in_native: impl Fn(usize) -> bool) -> bool {
        // While native code runs (a signal handled from a runtime helper), `self.module` is
        // stale and the running function shows up through the native stack instead.
        match self.native_pc {
            Some(pc) if in_native(pc) => return true,
            None if self.module == module && !self.heap.native_active() => return true,
            _ => {}
        }
        // Port of erts/emulator/beam/beam_bif_load.c:1171 and erl_nfunc_sched.h:120
        // (erts_check_nfunc_in_area), OTP-29.1.1: a native call that is redone when the process wakes (a parked BIF, a
        // NIF waiting for a dirty scheduler) keeps its return address outside the stack.
        if let Some(cold) = self.cold.as_deref() {
            let retry = cold
                .native_retry
                .and(cold.native_retry_site)
                .is_some_and(|(resume, site)| in_native(resume) || in_native(site));
            let dirty = cold
                .native_dirty_nif
                .is_some_and(|(_, resume, _)| in_native(resume));
            if retry || dirty {
                return true;
            }
        }
        for index in 0..self.heap.stack_words() {
            let Some(term) = self.heap.stack_get(index) else {
                continue;
            };
            if let Some((false, frame_module, _)) = crate::stacktrace::decode_tag(term)
                && frame_module == module
            {
                return true;
            }
            let word = term.tagged_word() as usize;
            if in_native(word) {
                return true;
            }
            // A native trace frame keeps the traced function's native return address as a small
            // integer, three words below its marker (see `trace::push_native_trace_frame`); the
            // process returns into that code once the traced function exits.
            if word == crate::trace::native_trace_marker()
                && self
                    .heap
                    .stack_get(index + 2)
                    .and_then(Term::as_small)
                    .and_then(|address| usize::try_from(address).ok())
                    .is_some_and(&in_native)
            {
                return true;
            }
        }
        false
    }

    /// Queues a DOWN message the sender built, if the origin monitor is still active.
    /// Port of erts/emulator/beam/erl_proc_sig_queue.c:6355 (ERTS_SIG_Q_OP_MONITOR_DOWN).
    fn deliver_monitor_down_message(
        &mut self,
        reference: u64,
        message: Message,
    ) -> Result<(), VmError> {
        let origin = crate::signals::take_origin_monitor_down(self, reference);
        // erts reads the monitor type from the origin node in the process's own tree
        // (erl_proc_sig_queue.c handle_monitor_down); only a distributed monitor has
        // remote bookkeeping to release.
        let remote = matches!(
            origin,
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

    fn deliver_monitor_down(
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
        let remote = !matches!(entry, Some(crate::proc_create::OriginMonitor::Process(_)))
            && crate::dist::take_monitor(reference).is_some();
        let active = entry.is_some() || remote;
        let priority = self
            .cold
            .as_mut()
            .is_some_and(|cold| cold.prio_monitors.remove(&reference));
        if !active {
            return Ok(());
        }
        let (half, port_object) = match entry {
            Some(crate::proc_create::OriginMonitor::Process(half)) => (Some(half), None),
            Some(crate::proc_create::OriginMonitor::Port { port_id, name, .. }) => {
                (None, Some(PortObject::Local(port_id, name)))
            }
            Some(crate::proc_create::OriginMonitor::DistPort { object, .. }) => {
                (None, Some(PortObject::Dist(*object)))
            }
            _ => (None, None),
        };
        let tag = if let Some(owned) = half.as_ref().and_then(|half| half.data.tag.as_ref()) {
            let mut heap = arinsal_bifs::ProcessHeapHandle(&mut self.heap);
            arinsal_term::from_owned(owned, &mut heap)
                .map_err(|error| VmError::Unsupported(format!("monitor tag: {error:?}")))?
        } else {
            crate::signals::atom("DOWN")
        };
        let name = half.as_ref().and_then(|half| half.data.name.clone());
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
fn down_message_on_sender(
    process: &mut Process,
    reference: u64,
    data: &crate::proc_create::MonitorData,
    target: Pid,
    reason: Term,
) -> Result<Message, VmError> {
    let tag = match data.tag.as_ref() {
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
    let object = crate::signals::monitor_object(process, data.name.as_deref(), from)?;
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

fn report_process_error(process: &mut Process, ctx: &mut RunCtx<'_, Message>, reason: Term) {
    let Some(runtime) = process.runtime.clone() else {
        return;
    };
    let destination = crate::natives::sys::system_logger(process);
    let logger = if destination == crate::signals::atom("undefined") {
        None
    } else if let Some(pid) = Pid::from_term(destination) {
        Some(pid)
    } else {
        runtime
            .reg
            .whereis_proc_str("logger")
            .or_else(|| runtime.reg.whereis_proc_str("error_logger"))
    };
    let Some(logger) = logger else {
        return;
    };
    let Some(pid) = ctx.pid().to_term() else {
        return;
    };
    let node_name = {
        let nodes = crate::node_tables::lock();
        nodes.alive.then(|| nodes.local_identity().0.to_owned())
    };
    let built = (|| -> Result<Term, VmError> {
        let format = if node_name.is_some() {
            "Error in process ~p on node ~p with exit value:~n~p~n"
        } else {
            "Error in process ~p with exit value:~n~p~n"
        };
        let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
        let mut builder = TermBuilder::new(&mut heap);
        let format = builder
            .list_from_iter(
                format
                    .bytes()
                    .map(|byte| Term::small(i64::from(byte)).unwrap()),
            )
            .map_err(|error| VmError::Unsupported(format!("process error format: {error:?}")))?;
        let mut values = vec![pid];
        if let Some(node_name) = node_name {
            values.push(Term::atom(
                arinsal_term::global_atoms()
                    .intern(&node_name)
                    .map_err(|error| VmError::Unsupported(format!("node atom: {error:?}")))?,
            ));
        }
        values.push(reason);
        let args = builder
            .list_from_iter(values)
            .map_err(|error| VmError::Unsupported(format!("process error args: {error:?}")))?;
        let logger_metadata = builder
            .flatmap_from_pairs(&[
                (
                    crate::signals::atom("emulator"),
                    crate::signals::atom("true"),
                ),
                (crate::signals::atom("tag"), crate::signals::atom("error")),
            ])
            .map_err(|error| VmError::Unsupported(format!("logger metadata: {error:?}")))?;
        let group_leader = process
            .group_leader
            .and_then(Pid::to_term)
            .unwrap_or(Term::NIL);
        let time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_micros() as i64)
            .ok()
            .and_then(Term::small)
            .unwrap_or(Term::NIL);
        let metadata = builder
            .flatmap_from_pairs(&[
                (crate::signals::atom("error_logger"), logger_metadata),
                (crate::signals::atom("gl"), group_leader),
                (crate::signals::atom("pid"), pid),
                (crate::signals::atom("time"), time),
            ])
            .map_err(|error| VmError::Unsupported(format!("logger event metadata: {error:?}")))?;
        builder
            .tuple(&[
                crate::signals::atom("log"),
                crate::signals::atom("error"),
                format,
                args,
                metadata,
            ])
            .map_err(|error| VmError::Unsupported(format!("logger event: {error:?}")))
    })();
    if let Ok(term) = built
        && let Ok(message) = Message::copy_from(term)
    {
        let _ = ctx.send(logger, message);
    }
}

thread_local! {
    static TRACER_REPLICAS: std::cell::RefCell<Vec<(usize, Vm)>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

/// Run `f` on a code replica of `runtime` private to this worker, for callers that need a
/// [`Vm`] while the executor's own is borrowed (receive tracing runs inside signal handling,
/// which has only the process). The replica is taken out while `f` runs, so a nested call
/// simply builds another one.
pub(crate) fn with_replica_vm<R>(runtime: &Arc<Runtime>, f: impl FnOnce(&mut Vm) -> R) -> R {
    let key = Arc::as_ptr(runtime) as usize;
    let cached = TRACER_REPLICAS.with(|slot| {
        let mut slot = slot.borrow_mut();
        slot.iter()
            .position(|(cached_key, _)| *cached_key == key)
            .map(|index| slot.swap_remove(index).1)
    });
    let mut vm = cached.unwrap_or_else(|| Vm::shared_replica(runtime.code_scope, &runtime.paths));
    vm.refresh_code();
    let result = f(&mut vm);
    TRACER_REPLICAS.with(|slot| {
        let mut slot = slot.borrow_mut();
        // Runtimes come and go in tests; keep only the most recent replicas.
        if slot.len() >= 4 {
            slot.remove(0);
        }
        slot.push((key, vm));
    });
    result
}

/// Run `f` on this scheduler's executor, creating it for `runtime` on first use.
fn with_executor<R>(
    data: &mut SchedulerData,
    runtime: &Arc<Runtime>,
    f: impl FnOnce(&mut Executor) -> R,
) -> R {
    let executor = data.executor.get_or_insert_with(|| new_executor(runtime));
    f(executor)
}

/// The executor a scheduler creates on its first process turn. Kept out of line: the
/// register file is built once per scheduler, not in the frame of every turn.
// Port of erts/emulator/beam/erl_process.c:5994 (init_scheduler_data allocates
// `esdp->registers` once), OTP-29.1.1.
#[cold]
#[inline(never)]
fn new_executor(runtime: &Arc<Runtime>) -> Box<Executor> {
    arinsal_nif_zlib::set_scheduler_caller(crate::natives::nif::scheduler_caller);
    Box::new(Executor {
        current_process: Default::default(),
        hub_bound: false,
        vm: Vm::shared_replica(runtime.code_scope, &runtime.paths),
        native_registers: SchedulerRegisters::default(),
    })
}

impl arinsal_sched::SignalMessage for Message {
    fn is_altact_msg(&self) -> bool {
        self.priority || self.alias != 0
    }
    fn timer_ref_key(&self) -> Option<u64> {
        self.timer_id
    }
}

impl Message {
    /// The message term for read-only inspection while it waits in a timer.
    pub(crate) fn term(&self) -> Term {
        self.term
    }
}

/// A suspended process that would run on is parked instead. Its queued signals are handled
/// first: a suspended process only handles signals (erts schedules it for them as system
/// tasks), and one parked with unhandled signals in its middle queue would never run again.
/// Returns `Yield` when the drain resumed the process, so it keeps running.
// Port of erts/emulator/beam/erl_process.c:9742 (ERTS_PSFLG_SUSPENDED processes are scheduled for
// ERTS_PSFLG_ACTIVE_SYS signal handling only), OTP-29.1.1.
fn park_suspended(
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
) -> Result<RunState, VmError> {
    let pid = ctx.pid();
    process.cold_mut().sys_task_point = true;
    let drained = process.drain(ctx);
    let executed = drained.and_then(|()| crate::signals::execute_sys_tasks(process, ctx));
    process.cold_mut().sys_task_point = false;
    executed?;
    // The resumer's wake-up signal may have been consumed by the drain above: re-check so a
    // resume racing with this suspension is not lost.
    if process
        .runtime
        .as_ref()
        .is_none_or(|runtime| runtime.suspend_total_of(pid) == 0)
    {
        return Ok(RunState::Yield);
    }
    process.cold_mut().suspend_parked = true;
    Ok(RunState::Wait { timeout_ms: None })
}

impl Task for Process {
    type Message = Message;
    type SchedulerData = SchedulerData;

    fn gc_nanoseconds(&self) -> u64 {
        self.stats.gc.nanoseconds
    }

    fn run(
        &mut self,
        ctx: &mut RunCtx<'_, Message>,
        data: &mut SchedulerData,
        budget: u32,
    ) -> RunOutcome {
        // Port of erts/emulator/beam/erl_trace.c:704-716 (trace_sched), OTP-29.1.1.
        let trace_scheduling = crate::trace::running_procs_enabled();
        if trace_scheduling {
            crate::trace::emit_process(
                None,
                self,
                ctx.pid(),
                crate::trace::RUNNING_PROCS,
                "in",
                &[],
            );
        }
        ctx.set_parallel_signal_buffers(self.message_queue_data() == MessageQueueData::OffHeap);
        // The light BIF path has no scheduler context. A probe is the process-side
        // `sig_inq` flag (`ERTS_PSFLG_MSG_SIG_IN_Q`) it checks before collecting.
        if self
            .cold
            .as_ref()
            .is_none_or(|cold| cold.signal_probe.is_none())
            && let Some(probe) = ctx.signal_probe()
        {
            self.cold_mut().signal_probe = Some(probe);
        }
        // Records built or decoded on this thread use its node's canonical definitions, and
        // export funs built here its export entries. A scheduler thread serves one runtime, so
        // the scopes are selected once; a simulated scheduler shares its thread with others.
        if !data.scopes_selected || ctx.simulated() {
            let scope = self
                .runtime
                .as_ref()
                .map_or(0, |runtime| runtime.code_scope);
            arinsal_term::set_record_scope(scope);
            crate::fun_dispatch::set_thread_code_scope(scope);
            data.scopes_selected = scope != 0;
        }
        // Port of erts/emulator/beam/erl_alloc.c (erts_alloc passes `esdp->no` to the
        // thread-specific allocators), OTP-29.1.1: the process heap allocates on this scheduler's
        // instance without looking the thread up, for the span of this run.
        let alloc_ix = *data
            .alloc_ix
            .get_or_insert_with(arinsal_alloc::thread_alloc_ix);
        self.heap.set_alloc_ix(Some(alloc_ix));
        let outcome = abort_on_worker_panic(|| self.run_task(ctx, data, budget));
        self.heap.set_alloc_ix(None);
        if matches!(outcome, RunOutcome::Exit(_)) {
            self._persistent_terms
                .store()
                .process_exited(&self._persistent_terms);
            // Port of erts/emulator/beam/erl_process.c (delete_process): free the heap and
            // off-heap list. A fresh block would be allocated only to be dropped with the
            // process.
            self.heap = ProcessHeap::with_words(0);
        }
        if trace_scheduling {
            crate::trace::emit_process(
                None,
                self,
                ctx.pid(),
                crate::trace::RUNNING_PROCS,
                "out",
                &[],
            );
        }
        outcome
    }

    fn scheduler_shutdown(&mut self) {
        self._persistent_terms
            .store()
            .process_exited(&self._persistent_terms);
    }

    fn scheduler_profile_event(
        &mut self,
        pid: Pid,
        scheduler_id: u32,
        active: bool,
        active_schedulers: u32,
    ) -> Option<(Pid, Message)> {
        crate::natives::misc::profile_scheduler_event(
            self,
            pid,
            scheduler_id,
            active,
            active_schedulers,
        )
    }

    fn take_dirty_job(
        &mut self,
        kind: arinsal_sched::DirtyKind,
    ) -> Option<arinsal_sched::DirtyJob> {
        if kind == arinsal_sched::DirtyKind::Cpu {
            self.cold_mut().dirty_pickup = Some(std::time::Instant::now());
        }
        Process::take_dirty_job(self, kind)
    }

    fn finish_dirty_job(&mut self, result: Box<dyn std::any::Any>) {
        Process::finish_dirty_job(self, result);
    }

    // Port of erts/emulator/beam/erl_process.c (delete_process), OTP-29.1.1: the heap,
    // off-heap list, message queue, dictionary and the link and monitor state are freed by
    // the exiting scheduler, not when the last reference to the struct goes.
    fn delete_process(&mut self) {
        self.heap = arinsal_term::ProcessHeap::with_words(0);
        self.cold = None;
        self.dictionary = None;
        self.inbox = MessageQueue::default();
        self.sig_cont = std::collections::VecDeque::new();
        self.exit_cont = None;
        self.seq_trace_token = None;
        self.final_exit_reason = None;
    }

    fn reap_signals(&mut self, pid: Pid, events: Vec<Event<Message>>) {
        let mut monitors = Vec::new();
        let mut links = Vec::new();
        let mut unlink_acks = Vec::new();
        let mut literal_replies = Vec::new();
        for event in events {
            match event.payload {
                Payload::Signal(Signal::Monitor { reference, shared }) => {
                    // A resource monitor has no origin process to answer with `noproc`.
                    if shared
                        .0
                        .downcast_ref::<arinsal_nif::ResourceMonitor>()
                        .is_none()
                    {
                        monitors.push((reference, event.from));
                    }
                }
                // Port of erts/emulator/beam/erl_proc_sig_queue.c:7426 (erts_proc_exit_handle_signal),
                // OTP-29.1.1: a link that reaches a process after its exit handling gets `noproc`.
                Payload::Signal(Signal::Link) => links.push(event.from),
                Payload::Signal(Signal::Unlink(id)) => {
                    links.retain(|from| *from != event.from);
                    unlink_acks.push((event.from, id));
                }
                Payload::Signal(Signal::Demonitor(reference)) => {
                    monitors.retain(|(id, _)| *id != reference);
                }
                // Port of erts/emulator/beam/erl_proc_sig_queue.c:7426 (erts_proc_exit_handle_signal),
                // OTP-29.1.1: an exiting process still answers a queued literal-copy request.
                Payload::Signal(Signal::LiteralAreaCopy {
                    request, requester, ..
                }) => {
                    if let Ok(reply) = request.literal_copy_reply(crate::signals::atom("ok")) {
                        literal_replies.push((requester, reply));
                    }
                }
                _ => {}
            }
        }
        if monitors.is_empty()
            && literal_replies.is_empty()
            && links.is_empty()
            && unlink_acks.is_empty()
        {
            return;
        }
        let Ok(scheduler) = self
            .runtime
            .as_ref()
            .map(|runtime| runtime.scheduler())
            .transpose()
        else {
            return;
        };
        let Some(scheduler) = scheduler else {
            return;
        };
        for (requester, reply) in literal_replies {
            let _ = scheduler.send(pid, requester, reply);
        }
        for (requester, id) in unlink_acks {
            let _ = scheduler.signal(pid, requester, Signal::UnlinkAckSignal(id));
        }
        for linker in links {
            if let Ok(reason) = Message::copy_from(crate::signals::atom("noproc")) {
                // A link exit (erts_proc_exit_handle_link), so the linker drops its half.
                let _ = scheduler.signal(pid, linker, Signal::ExitLinked(reason));
            }
        }
        for (reference, watcher) in monitors {
            let reason = self
                .final_exit_reason
                .unwrap_or_else(|| crate::signals::atom("noproc"));
            let Ok(reason) = Message::copy_from(reason) else {
                continue;
            };
            let _ = scheduler.signal(pid, watcher, Signal::MonitorDown { reference, reason });
        }
    }
}

fn abort_on_worker_panic(run: impl FnOnce() -> RunOutcome) -> RunOutcome {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(run)) {
        Ok(outcome) => outcome,
        Err(payload) => {
            let message = payload
                .downcast_ref::<String>()
                .map(String::as_str)
                .or_else(|| payload.downcast_ref::<&str>().copied())
                .unwrap_or("non-string panic payload");
            eprintln!("arinsal: VM panic in scheduler worker: {message}");
            std::process::abort();
        }
    }
}

impl Process {
    /// Terminate the process: everything up to the owned ETS tables now, the tables a slice of
    /// reductions at a time, and the rest once they are released.
    ///
    /// Port of erts/emulator/beam/erl_process.c:14160 (erts_continue_exit_process), OTP-29.1.1.
    fn exit_with(
        &mut self,
        runtime: &Arc<Runtime>,
        ctx: &mut RunCtx<'_, Message>,
        data: &mut SchedulerData,
        reason: Term,
        entry_result: Option<Result<ScheduledResult, VmError>>,
        code: u64,
    ) -> RunOutcome {
        with_executor(data, runtime, |executor| {
            self.exit_stage1(&mut executor.vm, ctx, reason)
        });
        // Port of erts/emulator/beam/erl_process.c (erts_continue_exit_process), OTP-29.1.1:
        // the continuation state lives on the stack and is allocated only when the exit yields.
        let state = crate::proc_create::ExitCont {
            reason,
            garbage: None,
            entry_result,
            code,
        };
        self.continue_exit(runtime, ctx, data, false, state)
    }

    /// Run the interruptible part of process exit; yields with `out_exiting` when the
    /// reductions run out and finishes with `out_exited`.
    fn continue_exit(
        &mut self,
        runtime: &Arc<Runtime>,
        ctx: &mut RunCtx<'_, Message>,
        data: &mut SchedulerData,
        resumed: bool,
        mut state: crate::proc_create::ExitCont,
    ) -> RunOutcome {
        let zero = [Term::small(0).expect("small zero")];
        if resumed {
            with_executor(data, runtime, |executor| {
                crate::trace::emit(
                    Some(&mut executor.vm),
                    self,
                    ctx,
                    ctx.pid(),
                    crate::trace::EXITING,
                    "in_exiting",
                    &zero,
                );
            });
        }
        let initial = ctx.remaining() as isize;
        let mut reds = initial;
        let done = self.exit_ets(ctx, &mut reds, &mut state.garbage);
        ctx.consume((initial - reds).clamp(0, initial) as u32);
        if !done {
            with_executor(data, runtime, |executor| {
                crate::trace::emit(
                    Some(&mut executor.vm),
                    self,
                    ctx,
                    ctx.pid(),
                    crate::trace::EXITING,
                    "out_exiting",
                    &zero,
                );
            });
            self.exit_cont = Some(Box::new(state));
            return RunOutcome::Yield;
        }
        let cont = state;
        with_executor(data, runtime, |executor| {
            crate::trace::emit(
                Some(&mut executor.vm),
                self,
                ctx,
                ctx.pid(),
                crate::trace::EXITING,
                "out_exited",
                &zero,
            );
        });
        self.exit_stage3(ctx, cont.reason);
        if self.entry
            && let Some(result) = cont.entry_result
        {
            let _ = runtime.result.send(result);
        }
        RunOutcome::Exit(cont.code)
    }

    fn run_task(
        &mut self,
        ctx: &mut RunCtx<'_, Message>,
        data: &mut SchedulerData,
        budget: u32,
    ) -> RunOutcome {
        if self.runtime.is_none() {
            return RunOutcome::Exit(1);
        }
        // erts stores the scheduler id on the process. Profiling allocates no side
        // record unless runnable-proc profiling is actually on.
        self.scheduler_id = ctx.scheduler_id().map_or(0, |id| id as u32);
        // Port of erts/emulator/beam/erl_process.c:6978-6992 (schedule_process_sys_task and
        // the enqueue paths test erts_system_profile_flags.runnable_procs before
        // profile_runnable_proc), OTP-29.1.1: without profiling this is one flag test.
        if crate::natives::misc::profile_runnable_procs()
            && !self.cold.as_ref().is_some_and(|cold| cold.profile_active)
        {
            crate::natives::misc::profile_process_event(self, ctx, true);
            self.cold_mut().scheduler_id = self.scheduler_id as usize;
            self.cold_mut().profile_active = true;
        }
        if self.dirty_exiting() {
            // Exited by a dirty signal handler while queued for a dirty scheduler.
            return RunOutcome::Exit(1);
        }
        if let Some(state) = self.exit_cont.take() {
            // Port of erts/emulator/beam/erl_process.c:10528 (in_exiting), OTP-29.1.1: an
            // exiting process only continues its exit when scheduled in.
            let runtime = self.runtime_handle();
            return self.continue_exit(&runtime, ctx, data, true, *state);
        }
        let result = self.run_executor(ctx, data, budget);
        if self.dirty_exiting() {
            // Port of erts/emulator/beam/erl_process.c:10096 (need_forced_exit), OTP-29.1.1:
            // the process already terminated while the job ran; whatever the job returned,
            // only the process structure remains to be released.
            return RunOutcome::Exit(1);
        }
        self.finish_run(ctx, data, result)
    }

    /// The node runtime this process belongs to. A slice only needs a counted reference on
    /// the exit paths, so the scheduler takes it there, not on every turn.
    fn runtime_handle(&self) -> Arc<Runtime> {
        Arc::clone(
            self.runtime
                .as_ref()
                .expect("a scheduled process has a runtime"),
        )
    }

    fn run_executor(
        &mut self,
        ctx: &mut RunCtx<'_, Message>,
        data: &mut SchedulerData,
        budget: u32,
    ) -> Result<RunState, VmError> {
        // Port of erts/emulator/beam/beam_common.c (erts_dirty_process_main), OTP-29.1.1: a
        // dirty CPU scheduler charges the time between picking the process and scheduling
        // again, not what the executed code consumed from FCALLS. This covers the dirty GC
        // system task and dirty CPU NIFs.
        let dirty_cpu = ctx.scheduler_type() == arinsal_sched::SchedulerType::DirtyCpu;
        let dirty_start = dirty_cpu.then(|| {
            self.cold
                .as_mut()
                .and_then(|cold| cold.dirty_pickup.take())
                .unwrap_or_else(std::time::Instant::now)
        });
        let used_before = self.reductions_used;
        let executor = match data.executor {
            Some(ref mut executor) => executor,
            None => {
                let runtime = self.runtime_handle();
                data.executor.insert(new_executor(&runtime))
            }
        };
        let mut result = executor.run(self, ctx, budget);
        if let Some(start) = dirty_start {
            let charged = erts_time2reds(start.elapsed());
            self.reductions_used = used_before.saturating_add(charged);
            ctx.consume(u32::try_from(charged).unwrap_or(u32::MAX));
        }
        // BIF_TRAP context-switches to beam_bif_export_trap. The continuation is an export
        // call, so the caller's CP stays on the stack and the backtrace PC is that trap.
        if matches!(result, Ok(RunState::Yield))
            && self
                .cold
                .as_ref()
                .is_some_and(|cold| cold.bif_trap.is_some())
        {
            crate::bif_traps::note_export_trap(self);
        }
        // A native BIF yield returns before the interpreter's suspend check. erts leaves
        // a suspended process out of the run queue (ERTS_PSFLG_SUSPENDED): the code-permission
        // seize failure is `erts_suspend` plus `ERTS_BIF_YIELD`.
        if matches!(result, Ok(RunState::Yield)) && crate::suspend::ctx_suspended(ctx) {
            result = park_suspended(self, ctx);
        }
        if matches!(result, Ok(RunState::Yield | RunState::Wait { .. }))
            && let Err(error) = crate::signals::reschedule_deferred_sys_tasks(self, ctx)
        {
            result = Err(error);
        }
        if self
            .cold
            .as_ref()
            .and_then(|cold| cold.debug_wait_completion.as_ref())
            .is_some_and(|completed| !completed.load(Ordering::Acquire))
        {
            Ok(RunState::Wait { timeout_ms: None })
        } else {
            result
        }
    }

    fn finish_run(
        &mut self,
        ctx: &mut RunCtx<'_, Message>,
        data: &mut SchedulerData,
        result: Result<RunState, VmError>,
    ) -> RunOutcome {
        if matches!(&result, Ok(RunState::Wait { .. } | RunState::Done(_)))
            && self.cold.as_ref().is_some_and(|cold| cold.profile_active)
        {
            crate::natives::misc::profile_process_event(self, ctx, false);
            self.cold_mut().profile_active = false;
        }
        // g_proc_sched. Port of erts/emulator/beam/erl_gc.c:1197 (max_heap_size kill), OTP-29.1.1.
        if heap_limit_kills(self, ctx) {
            let entry_result = self
                .entry
                .then(|| Err(VmError::Unsupported("max_heap_size".into())));
            let runtime = self.runtime_handle();
            return self.exit_with(
                &runtime,
                ctx,
                data,
                crate::signals::atom("killed"),
                entry_result,
                1,
            );
        }
        // Port of erts/emulator/beam/erl_process.c:6747-6763 (schedule_out_process), OTP-29.1.1:
        // with GC disabled the dirty collection is dropped; the next collection does it.
        if !ctx.scheduler_type().is_dirty()
            && !self.heap.gc_enabled
            && let Some(cold) = self.cold.as_mut()
            && cold.dirty_gc.take().is_some()
            && cold.delayed_gc.is_empty()
        {
            cold.dirty_sys_gc = false;
        }
        match result {
            // Port of erts/emulator/beam/erl_process.c:6695-6840 (schedule_out_process),
            // OTP-29.1.1: a process with ERTS_PSFLG_DIRTY_ACTIVE_SYS is enqueued on the dirty
            // CPU run queue.
            // The schedule-out sets the ACTIVE bit others read (remote_status) instead of
            // publishing a status under the runtime lock.
            Ok(RunState::Yield)
                if !ctx.scheduler_type().is_dirty()
                    && self.cold.as_ref().is_some_and(|cold| cold.dirty_sys_gc) =>
            {
                ctx.set_active(true);
                RunOutcome::Dirty(arinsal_sched::DirtyKind::Cpu)
            }
            Ok(RunState::Yield) => {
                ctx.set_active(true);
                RunOutcome::Yield
            }
            Ok(RunState::Wait { timeout_ms }) => {
                // Port of erts/emulator/beam/erl_process.c:9304 (erts_process_state2status),
                // OTP-29.1.1: suspension keeps ERTS_PSFLG_ACTIVE, so a process resumed while
                // this slice ended is runnable, not waiting.
                let parked = self
                    .cold
                    .as_mut()
                    .is_some_and(|cold| std::mem::take(&mut cold.suspend_parked));
                ctx.set_active(parked);
                RunOutcome::Wait { timeout_ms }
            }
            Ok(RunState::Done(term)) => {
                if trace_boot_enabled() {
                    eprintln!(
                        "arinsal boot: process {:?} done module={} ip={} value={term:?} {:?}",
                        ctx.pid(),
                        self.module,
                        self.ip,
                        arinsal_term::to_owned(term).ok()
                    );
                }
                #[cfg(feature = "pf-mem-counters")]
                if self.entry {
                    eprintln!(
                        "PF_MEM entry_done markers={} monitors={} spawn_constructs={} spawn_construct_ns={} spawn_fun_load_ns={} spawn_fun_setup_ns={} spawn_fun_sched_ns={}",
                        self.cold
                            .as_ref()
                            .and_then(|cold| cold.receive_markers.as_ref())
                            .map_or(0, |markers| markers.len()),
                        self.cold.as_ref().map_or(0, |cold| cold.monitors.len()),
                        crate::PF_SPAWN_CONSTRUCTS.load(Ordering::Relaxed),
                        crate::PF_SPAWN_CONSTRUCT_NS.load(Ordering::Relaxed),
                        crate::signals::PF_SPAWN_FUN_LOAD_NS.load(Ordering::Relaxed),
                        crate::signals::PF_SPAWN_FUN_SETUP_NS.load(Ordering::Relaxed),
                        crate::signals::PF_SPAWN_FUN_SCHED_NS.load(Ordering::Relaxed)
                    );
                }
                crate::signals::process_exiting(self, ctx);
                let entry_result = self.entry.then(|| {
                    self.stats.heap_words = self.heap.capacity_words();
                    let owned = arinsal_term::to_owned(term).map_err(|error| {
                        VmError::Unsupported(format!("result conversion: {error:?}"))
                    });
                    owned.map(|term_owned| ScheduledResult {
                        text: format!("{term_owned}"),
                        term: term_owned,
                        stats: self.stats.snapshot(),
                    })
                });
                let runtime = self.runtime_handle();
                self.exit_with(
                    &runtime,
                    ctx,
                    data,
                    crate::signals::atom("normal"),
                    entry_result,
                    0,
                )
            }
            Err(error) => {
                if matches!(error, VmError::Yield) {
                    return RunOutcome::Yield;
                }
                if let VmError::Dirty(kind) = error {
                    return RunOutcome::Dirty(kind);
                }
                let reason = exit_reason_from(self, &error);
                if matches!(&error, VmError::Raised(raised) if raised.class == arinsal_bifs::Class::Error)
                {
                    report_process_error(self, ctx, reason);
                }
                crate::signals::process_exiting(self, ctx);
                if trace_boot_enabled() {
                    eprintln!("arinsal boot: process {:?} exited: {error}", ctx.pid());
                }
                let entry_result = self.entry.then_some(Err(error));
                let runtime = self.runtime_handle();
                self.exit_with(&runtime, ctx, data, reason, entry_result, 1)
            }
        }
    }
}

impl Vm {
    fn spawn_system_process(
        &mut self,
        scheduler: &Scheduler<Process>,
        runtime: &Arc<Runtime>,
        module: &str,
        function: &str,
    ) -> Result<Pid, VmError> {
        self.spawn_system_process_priority(
            scheduler,
            runtime,
            module,
            function,
            arinsal_sched::Priority::Normal,
        )
    }

    // Port of erts/emulator/beam/erl_init.c:402 (erl_system_process_otp), OTP-29.1.1.
    fn spawn_system_process_priority(
        &mut self,
        scheduler: &Scheduler<Process>,
        runtime: &Arc<Runtime>,
        module: &str,
        function: &str,
        priority: arinsal_sched::Priority,
    ) -> Result<Pid, VmError> {
        let module_id = self.load_named(module)?;
        let ip = self.code.modules[module_id]
            .export(function, 0)
            .ok_or_else(|| VmError::Load(format!("{module}:{function}/0 is not exported")))?;
        let mut process = Process::with_spawn_registers(0, 0);
        process.module = module_id;
        process.ip = ip;
        process.initial_call = Some((module_id, ip));
        process.set_runtime(Some(Arc::clone(runtime)));
        process.initial_mfa = mfa_atoms(module, function, 0);
        if priority != arinsal_sched::Priority::Normal {
            let name = match priority {
                arinsal_sched::Priority::Max => "max",
                arinsal_sched::Priority::High => "high",
                arinsal_sched::Priority::Normal => "normal",
                arinsal_sched::Priority::Low => "low",
            };
            crate::natives::proc::set_flag(&mut process, "priority", crate::signals::atom(name));
        }
        // erl_init creates system processes on the boot scheduler, before other
        // schedulers have left scheduler_wait. Spreading them wakes those
        // schedulers and they steal the first user processes.
        let pid = scheduler
            .spawn_priority_on(process, priority, 0)
            .map_err(|error| VmError::Unsupported(format!("system process {module}: {error}")))?;
        runtime.system_processes.lock().unwrap().insert(pid);
        Ok(pid)
    }

    /// Run `module`'s `-on_load` before `user_ip` when this load did not go through `code_server`.
    fn arm_entry_on_load(
        &mut self,
        process: &mut Process,
        module_id: usize,
        user_ip: usize,
        arity: usize,
    ) -> Result<(), VmError> {
        let Some((function, on_arity)) = self
            .code
            .code_meta
            .get(module_id)
            .and_then(|meta| meta.as_ref())
            .and_then(|meta| meta.on_load.clone())
        else {
            return Ok(());
        };
        let Some(on_ip) = Self::on_load_entry(&self.code.modules[module_id], &function, on_arity)
        else {
            return Ok(());
        };
        if on_ip == user_ip {
            return Ok(());
        }
        let mut heap = arinsal_term::VecHeap::new();
        let mut saved = Vec::with_capacity(arity);
        for &arg in &process.x[..arity] {
            saved.push(
                arinsal_term::copy_term(arg, &mut heap)
                    .map_err(|error| VmError::Load(format!("on_load arguments: {error:?}")))?,
            );
        }
        crate::calls::push_continuation(process, module_id, user_ip, 0)?;
        process.cold_mut().entry_args_after_on_load =
            Some(Box::new(crate::proc_create::EntryArgsAfterOnLoad {
                _heap: heap,
                args: saved,
                module: module_id,
                ip: user_ip,
            }));
        process.ip = on_ip;
        process.native_pc = None;
        Ok(())
    }

    /// Run an exported function with schedulable BEAM processes.
    pub fn eval_scheduled(
        &mut self,
        module: &str,
        function: &str,
        args: &[Term],
        workers: usize,
        simulation_seed: Option<u64>,
    ) -> Result<ScheduledResult, VmError> {
        self.eval_scheduled_reductions(module, function, args, workers, simulation_seed, 4_000)
    }

    /// [`Vm::eval_scheduled`] with an explicit reduction quantum.
    ///
    /// A quantum of 1 yields on `wait` after `loop_rec` has observed an empty
    /// mailbox. The next slice drains the ingress before that `wait` runs.
    pub fn eval_scheduled_reductions(
        &mut self,
        module: &str,
        function: &str,
        args: &[Term],
        workers: usize,
        simulation_seed: Option<u64>,
        reductions: u32,
    ) -> Result<ScheduledResult, VmError> {
        // A booted node gets these from erl_features:init_features/0 during the
        // boot, exactly like erts; seeding them earlier would also give the
        // feature atoms indices erts does not give them.
        if module != "erl_init" {
            initialize_feature_defaults(arinsal_pterm::store_for(self.code_scope))?;
        }
        let child_setup = match &self.child_setup {
            Some(child_setup) => Arc::clone(child_setup),
            None => {
                let child_setup = crate::child_setup::start().map_err(|error| {
                    VmError::Load(format!("cannot start erl_child_setup: {error}"))
                })?;
                self.child_setup = Some(Arc::clone(&child_setup));
                child_setup
            }
        };
        let module_id = self.load_named(module)?;
        let ip = self.code.modules[module_id]
            .export(function, args.len() as u8)
            .ok_or_else(|| {
                VmError::Trap(crate::exceptions::Trap::error(crate::signals::atom(
                    "undef",
                )))
            })?;
        let (sender, receiver) = mpsc::channel();
        let code = Arc::clone(&self.code_ix);
        let port_layout = arinsal_term::ptab::port_table_layout();
        let port_ids = PtabIdRing::new(port_layout.max());
        // erts creates its forker port first and keeps port id zero occupied.
        assert_eq!(port_ids.reserve(), Some(0));
        let named_ets = Arc::new(arinsal_ets::NamedTableIndex::new());
        let runtime = Arc::new(Runtime {
            statistics: crate::natives::sys::StatisticsState::new(self.statistics_origins),
            backtrace_depth: AtomicUsize::new(8),
            code: Arc::clone(&code),
            code_scope: self.code_scope,
            system_processes: Mutex::new(std::collections::HashSet::new()),
            otp_root: self.otp_root.clone(),
            dirty_signal_handlers: Mutex::new(std::collections::HashSet::new()),
            literal_collector: Mutex::new(None),
            paths: self.paths.clone(),
            scheduler: OnceLock::new(),
            reg: crate::register::RegisterTable::new(),
            aliases: AliasTable::new(),
            next_trace_weak_id: AtomicU64::new(0),
            ports: crate::port::PortTable::new(port_layout),
            child_setup,
            system_monitor: Mutex::new(None),
            session_monitors: Mutex::new(Vec::new()),
            system_monitor_flags: AtomicU8::new(0),
            long_message_queues: Mutex::new(Vec::new()),
            port_ids,
            simulated: simulation_seed.is_some(),
            virtual_ms: AtomicU64::new(0),
            named_ets: Arc::clone(&named_ets),
            ets: std::sync::RwLock::new(arinsal_ets::Registry::new_with_named_index(named_ets)),
            result: sender,
            code_mod_permission: Mutex::new(crate::natives::code::CodeModPermission::default()),
            breakpoints: Arc::new(crate::trace_bp::BpNode::new(self.code_scope)),
            debug_wait_active: AtomicBool::new(false),
            system_flags: Mutex::new(crate::natives::sys::SystemFlags::boot()),
            gc_defaults: crate::natives::sys::GcDefaults::boot(),
            persistent_terms: arinsal_pterm::store_for(self.code_scope),
            multi_scheduling: Mutex::new(MultiScheduling::default()),
        });
        let (dirty_cpu_schedulers, dirty_cpu_online, dirty_io_schedulers) =
            crate::natives::sys::dirty_scheduler_defaults(&runtime);
        let scheduler_options = arinsal_args::active_scheduler_options().0;
        let config = Config {
            workers,
            reductions: reductions.max(1),
            dirty_cpu_schedulers,
            dirty_io_schedulers,
            compact_load: scheduler_options.compact_load.unwrap_or(true),
            utilization_balancing: scheduler_options.utilization_balancing.unwrap_or(false),
            busy_wait_thresholds: scheduler_options.busy_wait,
            wakeup_thresholds: scheduler_options.wakeup,
            forced_wakeup_interval: scheduler_options.forced_wakeup_interval,
            port_parallelism: scheduler_options.port_parallelism,
            scheduler_bind_type: scheduler_options.bind_type,
            max_processes: arinsal_term::ptab::process_table_layout().max(),
        };
        // `erts_no_schedulers` is what `system_info(schedulers)` reports; a run with fewer
        // worker threads than that keeps the layout of the reported scheduler count.
        arinsal_bifs::init_unique_scheduler_count(
            config.workers.max(crate::natives::sys::schedulers_total()) as u32,
            config.dirty_cpu_schedulers as u32,
            config.dirty_io_schedulers as u32,
        );
        // Port of erts/emulator/beam/erl_cpu_topology.c:1705-1708 (max_main_threads) and
        // ethr_mutex.c:151-166 (ethr_mutex_lib_late_init): the table locks' spin count grows with
        // the number of main threads, the schedulers on configured CPUs.
        arinsal_ets::rwmtx::set_main_threads(
            config
                .workers
                .min(arinsal_alloc::cpuinfo::cpu_info().configured.max(1)),
        );
        let scheduler = Arc::new(match simulation_seed {
            Some(seed) => Scheduler::simulation(config, seed),
            None => Scheduler::new(config),
        });
        // The runtime owns the scheduler for the VM lifetime; stopping it here releases the
        // processes' runtime references so the cycle is freed.
        let _scheduler_shutdown = SchedulerShutdown(Arc::clone(&scheduler));
        let online = crate::natives::sys::scheduler_online_default(&runtime);
        let _ = scheduler.set_online_schedulers(online.min(workers.max(1)));
        let _ = scheduler.set_dirty_cpu_online(dirty_cpu_online);
        runtime
            .scheduler
            .set(Arc::clone(&scheduler))
            .map_err(|_| VmError::Unsupported("runtime scheduler already set".into()))?;
        if module == "erl_init" && function == "start" && simulation_seed.is_none() {
            crate::natives::env::install_boot_signals(&runtime)?;
        }
        let mut process = Process::with_spawn_registers(args.len(), 0);
        process.module = module_id;
        process.ip = ip;
        // Port of erts/emulator/beam/erl_process.c (erl_create_process: copy_struct of the
        // arguments into the new heap), OTP-29.1.1: the first process owns its arguments, so
        // a collection never meets a term outside its heap and the literal areas.
        let literals = arinsal_term::LiteralAreas::current();
        for (register, &arg) in process.x.iter_mut().zip(args) {
            let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
            *register = arinsal_term::copy_term_litopt(arg, &mut heap, &literals)
                .map_err(|error| VmError::Load(format!("first process arguments: {error:?}")))?;
        }
        process.set_runtime(Some(runtime.clone()));
        process.initial_mfa = mfa_atoms(module, function, args.len() as u8);
        process.entry = true;
        // Port of erts/emulator/beam/beam_bif_load.c:793 (call_on_load_function_1), OTP-29.1.1.
        // A direct `eval_scheduled` has no `code_server` to run `-on_load` before the call.
        // The entry process runs that function first and continues only when it returns `ok`.
        self.arm_entry_on_load(&mut process, module_id, ip, args.len())?;
        // Port of erts/emulator/beam/erl_init.c:2540 (erl_first_process_otp), OTP-29.1.1:
        // the first process gets the first pid; it runs once the system processes
        // exist, as erts starts its schedulers only after spawning them.
        let entry_pid: Pid = scheduler
            .spawn_unscheduled(process)
            .map_err(|error| VmError::Unsupported(format!("spawn: {error}")))?;
        if module == "erl_init" && function == "start" {
            // Port of erts/emulator/beam/erl_init.c:2550 (erl_system_process_otp
            // "erts_code_purger"), OTP-29.1.1. code_server:finish_on_load sends
            // to this registered process; without it the send is badarg and
            // code_server dies during ensure_loaded of an on_load module.
            self.spawn_system_process_priority(
                &scheduler,
                &runtime,
                "erts_code_purger",
                "start",
                arinsal_sched::Priority::High,
            )?;
        }
        // Port of erts/emulator/beam/erl_init.c system-process startup: every
        // runtime needs the preloaded owner of the literal-area release protocol.
        let literal_collector = self.spawn_system_process_priority(
            &scheduler,
            &runtime,
            "erts_literal_area_collector",
            "start",
            arinsal_sched::Priority::High,
        )?;
        // erl 29.1.1 does not register the collector; it is found by initial_call.
        *runtime.literal_collector.lock().unwrap() = Some(literal_collector);
        // Port of erts/emulator/beam/erl_init.c:2570-2597, OTP-29.1.1: normal, high and max
        // priority dirty signal handlers exist even without dirty schedulers.
        let mut handlers = Vec::with_capacity(3);
        for priority in [
            arinsal_sched::Priority::Normal,
            arinsal_sched::Priority::High,
            arinsal_sched::Priority::Max,
        ] {
            let pid = self.spawn_system_process_priority(
                &scheduler,
                &runtime,
                "erts_dirty_process_signal_handler",
                "start",
                priority,
            )?;
            runtime.dirty_signal_handlers.lock().unwrap().insert(pid);
            handlers.push(pid);
        }
        scheduler.set_dirty_signal_handlers(handlers[0], handlers[1], handlers[2], |pid| {
            pid.to_term().and_then(|term| Message::copy_from(term).ok())
        });
        // Port of erts/emulator/beam/erl_init.c:2599 (erl_system_process_otp
        // "erts_trace_cleaner"), OTP-29.1.1.
        self.spawn_system_process(&scheduler, &runtime, "erts_trace_cleaner", "start")?;
        scheduler
            .schedule_unscheduled(entry_pid)
            .map_err(|error| VmError::Unsupported(format!("spawn: {error}")))?;
        if simulation_seed.is_some() {
            loop {
                if let Ok(result) = receiver.try_recv() {
                    while arinsal_pterm::store_for(self.code_scope).has_retired() {
                        if !scheduler.step() {
                            let now = runtime.virtual_ms.fetch_add(1, Ordering::Relaxed) + 1;
                            scheduler.advance_ms(1).map_err(|error| {
                                VmError::Unsupported(format!("simulation clock: {error}"))
                            })?;
                            if now > 60_000 {
                                return Err(VmError::Unsupported(
                                    "literal collector did not finish before simulation timeout"
                                        .into(),
                                ));
                            }
                        }
                    }
                    return result;
                }
                if !scheduler.step() {
                    let now = runtime.virtual_ms.fetch_add(1, Ordering::Relaxed) + 1;
                    scheduler.advance_ms(1).map_err(|error| {
                        VmError::Unsupported(format!("simulation clock: {error}"))
                    })?;
                    if now > 60_000 {
                        return Err(VmError::Unsupported(
                            "simulation has no runnable process or timer".into(),
                        ));
                    }
                }
            }
        }
        let result = receiver
            .recv()
            .map_err(|_| VmError::Unsupported("entry process disappeared".into()))?;
        while arinsal_pterm::store_for(self.code_scope).has_retired() {
            std::thread::park_timeout(std::time::Duration::from_millis(1));
        }
        drop(code);
        self.refresh_code();
        result
    }
}

/// Stops the scheduler when the VM run ends, on every exit path.
struct SchedulerShutdown(Arc<Scheduler<Process>>);

impl Drop for SchedulerShutdown {
    fn drop(&mut self) {
        self.0.release();
    }
}

fn initialize_feature_defaults(store: &arinsal_pterm::Store) -> Result<(), VmError> {
    let mut heap = arinsal_term::VecHeap::new();
    let module = Term::atom(
        arinsal_term::global_atoms()
            .intern("erl_features")
            .map_err(|error| VmError::Load(format!("feature atom: {error:?}")))?,
    );
    for name in ["enabled_features", "keywords"] {
        let key = TermBuilder::new(&mut heap)
            .tuple(&[
                module,
                Term::atom(
                    arinsal_term::global_atoms()
                        .intern(name)
                        .map_err(|error| VmError::Load(format!("feature atom: {error:?}")))?,
                ),
            ])
            .map_err(|error| VmError::Load(format!("feature key: {error:?}")))?;
        store
            .put_new(key, Term::NIL)
            .map_err(|error| VmError::Load(format!("feature default: {error:?}")))?;
    }
    let key = TermBuilder::new(&mut heap)
        .tuple(&[
            module,
            Term::atom(
                arinsal_term::global_atoms()
                    .intern("init_done")
                    .map_err(|error| VmError::Load(format!("feature atom: {error:?}")))?,
            ),
        ])
        .map_err(|error| VmError::Load(format!("feature key: {error:?}")))?;
    store
        .put_new(key, Term::atom(arinsal_term::atoms::TRUE))
        .map(|_| ())
        .map_err(|error| VmError::Load(format!("feature default: {error:?}")))
}

/// Scheduler class of a scheduler type, for matching rescheduled NIF calls.
fn scheduler_class(kind: arinsal_sched::SchedulerType) -> arinsal_bifs::SchedulerClass {
    match kind {
        arinsal_sched::SchedulerType::Normal => arinsal_bifs::SchedulerClass::Normal,
        arinsal_sched::SchedulerType::DirtyCpu => arinsal_bifs::SchedulerClass::DirtyCpu,
        arinsal_sched::SchedulerType::DirtyIo => arinsal_bifs::SchedulerClass::DirtyIo,
    }
}

/// `p->u.initial` for a system or spawned MFA given by name (atoms, as erts keeps them).
fn mfa_atoms(
    module: &str,
    function: &str,
    arity: u8,
) -> Option<(arinsal_term::Atom, arinsal_term::Atom, u8)> {
    let module = crate::signals::atom(module).as_atom()?;
    let function = crate::signals::atom(function).as_atom()?;
    Some((module, function, arity))
}

#[cfg(test)]
mod layout_tests {
    use super::{Message, Process, ProcessHeap, Term, TermBuilder};

    fn envelope() -> Message {
        let mut source = ProcessHeap::with_words(8);
        let term = TermBuilder::new(&mut source)
            .tuple(&[Term::small(17).unwrap()])
            .unwrap();
        Message::copy_from(term).unwrap()
    }

    #[test]
    fn off_heap_message_fragment_stays_outside_gc_roots_until_removed() {
        let mut process = Process::new();
        process.cold_mut().off_heap_msgq = true;
        let heap_words = process.heap.total_heap_size_words();
        let prio_len = 0;
        process.inbox.push_message(envelope(), prio_len).unwrap();

        assert!(process.inbox.gc_root_snapshot().1.is_empty());
        assert_eq!(process.heap.total_heap_size_words(), heap_words);
        process.collect_heap_roots(0, &mut [], 0).unwrap();
        let term = process
            .inbox
            .remove_to_heap(0, &mut process.heap, prio_len)
            .unwrap()
            .0
            .unwrap();
        assert_eq!(
            arinsal_term::to_owned(term).unwrap(),
            arinsal_etf::OwnedTerm::Tuple(vec![arinsal_etf::OwnedTerm::Int(17)])
        );
        assert!(process.heap.total_heap_size_words() > heap_words);
    }

    #[test]
    fn on_heap_message_is_a_gc_root_in_the_process_heap() {
        let mut process = Process::new();
        let prio_len = 0;
        process.inbox.push_message(envelope(), prio_len).unwrap();

        // The fetched message keeps its fragment until a collection moves it onto the heap.
        assert!(process.inbox.gc_root_snapshot().1.is_empty());
        assert!(!process.inbox.is_on_heap(0));
        process.collect_heap_roots(0, &mut [], 0).unwrap();
        assert_eq!(process.inbox.gc_root_snapshot().1.len(), 1);
        assert_eq!(process.inbox.entries.len(), 1);
        assert!(process.inbox.entries[0].fragment.is_none());
        process.collect_heap_roots(0, &mut [], 0).unwrap();
        let term = process
            .inbox
            .remove_to_heap(0, &mut process.heap, prio_len)
            .unwrap()
            .0
            .unwrap();
        assert_eq!(
            arinsal_term::to_owned(term).unwrap(),
            arinsal_etf::OwnedTerm::Tuple(vec![arinsal_etf::OwnedTerm::Int(17)])
        );
    }

    /// Regression for the Elixir `base_test`/`calendar/iso_test` crashes: a collection inside a
    /// native helper that returns an error (or any path without its own header sync) left
    /// `heap`/`hend` of the ABI prefix on the old heap, and the next helper committed cursors of
    /// the new heap against the old base.
    #[test]
    fn collection_publishes_the_new_heap_to_the_native_header() {
        let mut process = Process::new();
        process.sync_native_header();
        let before = (process.header.heap, process.header.hend);
        // Force a collection that grows the young heap.
        process.ensure(1 << 14, 0).unwrap();
        let (heap, hend) = process.heap.heap_bounds();
        let (htop, stop) = process.heap.heap_cursor();
        assert_ne!(
            (heap, hend),
            before,
            "the collection must move or grow the heap"
        );
        assert_eq!(process.header.heap, heap);
        assert_eq!(process.header.hend, hend);
        assert_eq!(process.header.htop, htop);
        assert_eq!(process.header.stop, stop);
    }

    #[test]
    fn partial_cursor_sync_also_publishes_heap_bounds() {
        let mut process = Process::new();
        process.sync_native_header();
        let _ = process.heap.heap_bounds();
        process.heap.delay_collection(0);
        process.header.heap = std::ptr::null_mut();
        process.header.hend = std::ptr::null_mut();
        process.sync_native_cursors();
        assert_eq!(process.header.heap, process.heap.heap_bounds().0);
        assert_eq!(process.header.hend, process.heap.heap_bounds().1);
    }

    #[test]
    fn post_bif_result_root_survives_collection_in_the_fast_arm() {
        let mut process = Process::new();
        let elements = [
            Term::small(1).unwrap(),
            Term::small(2).unwrap(),
            Term::small(3).unwrap(),
        ];
        let result = TermBuilder::new(&mut process.heap)
            .tuple(&elements)
            .unwrap();
        let expected = arinsal_term::to_owned(result).unwrap();
        let mut roots = [result];
        let stats = process.collect_heap_roots(0, &mut roots, 0).unwrap();
        assert_eq!(stats.collections, 1);
        assert_ne!(roots[0], result);
        assert_eq!(arinsal_term::to_owned(roots[0]).unwrap(), expected);
    }

    #[test]
    fn check_process_code_sees_the_return_address_of_a_native_trace_frame() {
        // A traced native function leaves its return address on the stack as a small integer;
        // a purge of the code it returns into has to find it.
        let mut process = Process::new();
        let range = (0x4000_usize, 0x5000_usize);
        let marker = crate::trace::native_trace_marker();
        assert!(process.heap.reserve_stack(4));
        let words = [
            crate::proc_create::native_continuation_term(marker),
            Term::NIL,
            Term::small(0x4468).unwrap(),
            Term::small(0).unwrap(),
        ];
        for (index, word) in words.into_iter().enumerate() {
            process.heap.stack_set(index, word);
        }
        assert!(process.references_code(usize::MAX, |address| {
            range.0 <= address && address < range.1
        }));
        assert!(
            !process.references_code(usize::MAX, |address| (0x8000..0x9000).contains(&address))
        );
        assert!(!process.references_code(usize::MAX, |_| false));
    }

    #[test]
    fn worker_panic_aborts_instead_of_hanging() {
        const TEST_NAME: &str = "process::layout_tests::worker_panic_aborts_instead_of_hanging";
        if std::env::var_os("ARINSAL_TEST_WORKER_PANIC").is_some() {
            super::abort_on_worker_panic(|| panic!("worker panic sentinel"));
            return;
        }
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TEST_NAME, "--nocapture"])
            .env("ARINSAL_TEST_WORKER_PANIC", "1")
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(
            String::from_utf8_lossy(&output.stderr)
                .contains("arinsal: VM panic in scheduler worker: worker panic sentinel")
        );
    }

    #[test]
    fn idle_process_layout_stays_compact() {
        assert_eq!(
            std::mem::size_of::<super::MessageQueue>(),
            std::mem::size_of::<std::collections::VecDeque<Term>>()
        );
        assert!(std::mem::size_of::<arinsal_term::ProcessHeap>() <= 128);
        eprintln!(
            "Process={} ProcessHeap={} VecDeque={} RunOutcome={}",
            std::mem::size_of::<crate::Process>(),
            std::mem::size_of::<arinsal_term::ProcessHeap>(),
            std::mem::size_of::<std::collections::VecDeque<arinsal_term::Term>>(),
            std::mem::size_of::<arinsal_sched::RunOutcome>()
        );
    }
}
