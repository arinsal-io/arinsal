//! Scheduler adapter and message envelopes for BEAM processes.

use crate::{Process, RunState, SharedCode, Vm, VmError};
use arinsal_beam::{BeamFile, Operand};
use arinsal_beamasm::SchedulerRegisters;
use arinsal_pterm::RetiredArea;
use arinsal_sched::{
    Config, Event, Payload, Pid, ReceiveMarker, RunCtx, RunOutcome, Scheduler, Signal, Task,
};
use arinsal_spec::Opcode;
use arinsal_term::{
    ProcessHeap, SharedCopyCache, Term, TermBuilder, copy_term,
    copy_term_preserving_sharing_with_cache, global_atoms, size_object,
};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak, mpsc};

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

fn trace_boot_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| std::env::var_os("ARINSAL_TRACE_BOOT").is_some())
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
    /// The VM reference id of a `start_timer` timeout, so an in-flight expiry keeps its
    /// reference even after the timer was cancelled.
    timer_id: Option<u64>,
}

struct MessageFragment {
    heap: Option<ProcessHeap>,
    seq_token: Option<Box<crate::seq_trace::Token>>,
}

type RemovedMessage = (Term, Option<Box<crate::seq_trace::Token>>);

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
            },
        );
        prio_len + 1
    }

    /// Append a scheduler message while applying the active queue policy.
    // Port of erts/emulator/beam/erl_message.c:698 (erts_send_message), OTP-29.1.1.
    pub(crate) fn push_message(
        &mut self,
        mut message: Message,
        data: MessageQueueData,
        heap: &mut ProcessHeap,
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
                },
            );
            return Ok(new_prio_len);
        }
        match data {
            MessageQueueData::OnHeap => {
                // Port of erts/emulator/beam/erl_message.c:943 (copy_message), OTP-29.1.1.
                let mut target = arinsal_bifs::FragmentingHeap(heap);
                let mut fragment = message.fragment.take().expect("fragment was checked");
                let term = if fragment.heap.is_some() {
                    let literals = arinsal_term::LiteralAreas::current();
                    arinsal_term::copy_term_litopt(message.term, &mut target, &literals).map_err(
                        |error| VmError::Unsupported(format!("on-heap message copy: {error:?}")),
                    )?
                } else {
                    message.term
                };
                fragment.heap = None;
                push(
                    self,
                    QueuedMessage {
                        term,
                        fragment: fragment.seq_token.take().map(|seq_token| {
                            Box::new(MessageFragment {
                                heap: None,
                                seq_token: Some(seq_token),
                            })
                        }),
                    },
                );
            }
            MessageQueueData::OffHeap => {
                // Port of erts/emulator/beam/erl_message.c:1054 (off-heap message fragment), OTP-29.1.1.
                push(
                    self,
                    QueuedMessage {
                        term: message.term,
                        fragment: message.fragment,
                    },
                );
            }
        }
        Ok(new_prio_len)
    }

    pub(crate) fn get(&self, index: usize) -> Option<&Term> {
        self.entries.get(index).map(|entry| &entry.term)
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = &Term> {
        self.entries.iter().map(|entry| &entry.term)
    }

    /// Retain matching messages at or after a receive-marker boundary.
    ///
    /// Splitting first is intentional: flushing a monitor must not walk the
    /// mailbox prefix that predates the monitor's marker.
    pub(crate) fn retain_from(
        &mut self,
        start: usize,
        prio_len: usize,
        mut keep: impl FnMut(&Term) -> bool,
    ) -> (usize, Vec<usize>) {
        let start = start.min(self.entries.len());
        let mut suffix = self.entries.split_off(start);
        let mut index = start;
        let mut new_prio_len = prio_len.min(start);
        let mut removed = Vec::new();
        suffix.retain(|entry| {
            let entry_index = index;
            index += 1;
            if keep(&entry.term) {
                if entry_index < prio_len {
                    new_prio_len += 1;
                }
                true
            } else {
                removed.push(entry_index);
                false
            }
        });
        self.entries.append(&mut suffix);
        (new_prio_len, removed)
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

    pub(crate) fn remove_to_heap_with_token(
        &mut self,
        index: usize,
        heap: &mut ProcessHeap,
        prio_len: usize,
    ) -> Result<(Option<RemovedMessage>, usize), VmError> {
        let mut token = None;
        if let Some(entry) = self.entries.get_mut(index)
            && let Some(fragment) = entry.fragment.as_mut()
        {
            if fragment.seq_token.is_some() {
                token = fragment.seq_token.take();
            }
            if let Some(heap_fragment) = fragment.heap.take() {
                heap.adopt_message_fragment(heap_fragment)
                    .map_err(|error| {
                        VmError::Unsupported(format!("message fragment adoption: {error:?}"))
                    })?;
            }
        }
        let removed = self.entries.remove(index).map(|entry| (entry.term, token));
        let prio_len = prio_len - usize::from(removed.is_some() && index < prio_len);
        Ok((removed, prio_len))
    }

    /// Obtain and later rewrite only the mailbox entries scanned by process GC.
    pub(crate) fn gc_root_snapshot(&self) -> (Vec<usize>, Vec<Term>) {
        let indices = self
            .entries
            .iter()
            .enumerate()
            .filter_map(|(index, entry)| {
                (entry.term.is_pointer()
                    && entry
                        .fragment
                        .as_ref()
                        .is_none_or(|fragment| fragment.heap.is_none()))
                .then_some(index)
            })
            .collect::<Vec<_>>();
        let roots = indices
            .iter()
            .map(|&index| self.entries[index].term)
            .collect();
        (indices, roots)
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
                &mut arinsal_bifs::FragmentingHeap(heap),
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

    pub(crate) fn update_gc_roots(&mut self, indices: &[usize], roots: &[Term]) {
        for (&index, &term) in indices.iter().zip(roots) {
            self.entries[index].term = term;
        }
    }

    /// Return terms copied out of queue-owned storage for `process_info(messages)`.
    pub(crate) fn copied_terms(&self, heap: &mut ProcessHeap) -> Result<Vec<Term>, VmError> {
        let mut target = arinsal_bifs::FragmentingHeap(heap);
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
            return Ok(Self {
                term,
                fragment: None,
                priority: false,
                timer_id: None,
            });
        }
        // Port of erts/emulator/beam/erl_message.c:824 (erts_send_message),
        // OTP-29.1.1. Exact sizing keeps unused words out of long-lived
        // message fragments.
        // Literals outside the collector's purge area stay shared (copy_struct_litopt).
        let literals = arinsal_term::LiteralAreas::current();
        let words = arinsal_term::size_object_litopt(term, &literals);
        if words == 0 {
            return Ok(Self {
                term,
                fragment: None,
                priority: false,
                timer_id: None,
            });
        }
        let mut fragment =
            ProcessHeap::with_words_for_type(words, arinsal_alloc::typed::ErtsAlcType::HEAP_FRAG);
        let term = arinsal_term::copy_term_litopt(term, &mut fragment, &literals)
            .map_err(|error| VmError::Unsupported(format!("message copy: {error:?}")))?;
        Ok(Self {
            term,
            fragment: Some(Box::new(MessageFragment {
                heap: Some(fragment),
                seq_token: None,
            })),
            priority: false,
            timer_id: None,
        })
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

    pub(crate) fn with_timer_id(mut self, id: u64) -> Self {
        self.timer_id = Some(id);
        self
    }

    pub(crate) fn is_priority(&self) -> bool {
        self.priority
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

    fn into_receiver(self, process: &mut Process) -> Result<Term, VmError> {
        if self.fragment.is_none() {
            // Port of erts/emulator/beam/erl_message.c:734 (immediate message term), OTP-29.1.1.
            return Ok(self.term);
        }
        if process.message_queue_data() == MessageQueueData::OnHeap {
            // Port of erts/emulator/beam/erl_message.c:943 (copy_message), OTP-29.1.1.
            // The receiver owns its process lock while draining, so queued terms
            // can be copied directly into its managed heap.
            let mut heap = arinsal_bifs::FragmentingHeap(&mut process.heap);
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

    pub(crate) fn message_queue_data(&self) -> MessageQueueData {
        let Some(value) = self
            .cold
            .as_ref()
            .and_then(|cold| cold.flags.get("message_queue_data"))
        else {
            return MessageQueueData::OnHeap;
        };
        if *value == crate::signals::atom("off_heap") {
            MessageQueueData::OffHeap
        } else {
            MessageQueueData::OnHeap
        }
    }
}

const ALIAS_SLAB: usize = 4096;
const ALIAS_SLABS: usize = 256;
const ALIAS_INACTIVE: u64 = 1;

/// Alias → pid map. Dense reference ids use atomic slabs, so reply sends do
/// not acquire a global mutex after the slab's one-time allocation.
struct AliasTable {
    slabs: Box<[OnceLock<Box<[AtomicU64]>>]>,
    overflow: Mutex<HashMap<u64, (Option<Pid>, bool)>>,
}

impl AliasTable {
    fn new() -> Self {
        Self {
            slabs: (0..ALIAS_SLABS).map(|_| OnceLock::new()).collect(),
            overflow: Mutex::new(HashMap::new()),
        }
    }

    fn encode(target: Option<Pid>, priority: bool) -> u64 {
        match target {
            None => ALIAS_INACTIVE,
            // Index is 28 bits and generation is 32. Bit 60 marks a live alias
            // so the inactive sentinel `1` cannot collide with pid 0. Bit 61
            // marks a priority alias (OTP 28+).
            Some(pid) => {
                const PRESENT: u64 = 1 << 60;
                const PRIORITY: u64 = 1 << 61;
                let mut raw = PRESENT | ((pid.generation as u64) << 28) | u64::from(pid.index);
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
        Some((
            Some(Pid {
                index: (raw & ((1 << 28) - 1)) as u32,
                generation: ((raw >> 28) & 0xffff_ffff) as u32,
            }),
            raw & PRIORITY != 0,
        ))
    }

    fn load(&self, id: u64) -> Option<(Option<Pid>, bool)> {
        if id / ALIAS_SLAB as u64 >= ALIAS_SLABS as u64 {
            return self.overflow.lock().unwrap().get(&id).copied();
        }
        let slab = self.slabs.get((id / ALIAS_SLAB as u64) as usize)?.get()?;
        let slot = (id % ALIAS_SLAB as u64) as usize;
        let raw = slab[slot].load(Ordering::Acquire);
        Self::decode(raw)
    }

    fn store(&self, id: u64, target: Option<Pid>, priority: bool) {
        if id / ALIAS_SLAB as u64 >= ALIAS_SLABS as u64 {
            self.overflow
                .lock()
                .unwrap()
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
    code: Arc<Mutex<SharedCode>>,
    /// The node's code scope, which keys its native code registries.
    pub(crate) code_scope: u64,
    pub(crate) processes: Mutex<std::collections::HashSet<Pid>>,
    pub(crate) system_processes: Mutex<std::collections::HashSet<Pid>>,
    otp_root: Option<std::path::PathBuf>,
    pub(crate) dirty_signal_handlers: Mutex<std::collections::HashSet<Pid>>,
    /// Pid of `erts_literal_area_collector` (an unregistered system process).
    pub(crate) literal_collector: Mutex<Option<Pid>>,
    paths: Vec<std::path::PathBuf>,
    scheduler: Mutex<Weak<Scheduler<Process>>>,
    pub(crate) names: Mutex<HashMap<String, Pid>>,
    pub(crate) port_names: Mutex<HashMap<String, u64>>,
    aliases: AliasTable,
    pub(crate) timers: Mutex<HashMap<u64, arinsal_sched::TimerRef>>,
    pub(crate) timer_owners: Mutex<HashMap<u64, Pid>>,
    pub(crate) next_trace_weak_id: AtomicU64,
    pub(crate) ports: Mutex<HashMap<u64, Arc<crate::port::PortHandle>>>,
    pub(crate) system_monitor: Mutex<Option<crate::natives::erts_debug::SystemMonitorState>>,
    /// `system_monitor` state of dynamic trace sessions, keyed by the session term.
    pub(crate) session_monitors: Mutex<
        Vec<(
            arinsal_etf::OwnedTerm,
            crate::natives::erts_debug::SystemMonitorState,
        )>,
    >,
    pub(crate) system_monitor_flags: AtomicU8,
    pub(crate) long_message_queues: Mutex<HashSet<Pid>>,
    pub(crate) next_port: AtomicU64,
    pub(crate) simulated: bool,
    pub(crate) virtual_ms: AtomicU64,
    pub(crate) ets: std::sync::RwLock<arinsal_ets::Registry>,
    result: mpsc::Sender<Result<ScheduledResult, VmError>>,
    // g_proc_sched: suspend counts and the status other processes can observe.
    pub(crate) suspend_counts: Mutex<HashMap<(Pid, Pid), u32>>,
    /// Asynchronous suspends of a running process that it has not yet acted on.
    // Port of erts/emulator/beam/erl_process.c:9013 (`erts_internal_suspend_process_2` pending suspend), OTP-29.1.1.
    suspend_outstanding: Mutex<HashMap<(Pid, Pid), u32>>,
    pub(crate) suspend_total: Mutex<HashMap<Pid, u32>>,
    pub(crate) ever_suspended: AtomicBool,
    /// Suspend-monitor pauses of receive and BIF timers (`erts_pause_proc_timer`).
    pub(crate) pauses: Mutex<HashMap<Pid, TimerPause>>,
    pub(crate) published: Mutex<HashMap<Pid, Published>>,
    pub(crate) hibernating: Mutex<HashMap<Pid, HibernateCont>>,
    pub(crate) ever_hibernated: AtomicBool,
    pub(crate) max_heaps: Mutex<HashMap<Pid, MaxHeap>>,
    pub(crate) ever_max_heap: AtomicBool,
    pub(crate) debug_wait_active: AtomicBool,
    /// Multi-scheduling block state of this runtime.
    pub(crate) multi_scheduling: Mutex<MultiScheduling>,
}

/// `erlang:system_flag(multi_scheduling, _)` state of one runtime.
///
/// Port of erts/emulator/beam/erl_process.c:8484 (erts_block_multi_scheduling,
/// `schdlr_sspnd.msb` / `schdlr_sspnd.nmsb`), OTP-29.1.1. erts keeps this in the
/// runtime's scheduler suspend state, so a runtime always boots with multi-scheduling
/// enabled; it is never inherited from another runtime sharing the OS process.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct MultiScheduling {
    pub(crate) blocked: bool,
    pub(crate) normal_blocked: bool,
}

impl MultiScheduling {
    /// Port of erts/emulator/beam/erl_bif_info.c (system_info(multi_scheduling)), OTP-29.1.1.
    pub(crate) fn state(self) -> &'static str {
        if self.blocked {
            "blocked"
        } else if self.normal_blocked {
            "blocked_normal"
        } else {
            "enabled"
        }
    }

    pub(crate) fn any_blocked(self) -> bool {
        self.blocked || self.normal_blocked
    }
}

impl Runtime {
    pub(crate) fn cancel_owned_timers(&self, owner: Pid) {
        let ids = {
            let mut owners = self.timer_owners.lock().unwrap();
            let ids = owners
                .iter()
                .filter_map(|(&id, &timer_owner)| (timer_owner == owner).then_some(id))
                .collect::<Vec<_>>();
            for id in &ids {
                owners.remove(id);
            }
            ids
        };
        if ids.is_empty() {
            return;
        }
        let timers = {
            let mut timers = self.timers.lock().unwrap();
            ids.iter()
                .filter_map(|id| timers.remove(id))
                .collect::<Vec<_>>()
        };
        if let Ok(scheduler) = self.scheduler() {
            for timer in timers {
                // Port of erts/emulator/beam/erl_hl_timer.c (erts_cancel_bif_timers), OTP-29.1.1:
                // the owning scheduler's wheel is asked asynchronously.
                scheduler.cancel_timer_async(timer, |_| {});
            }
        }
    }
}

/// Accumulated suspend-monitor pause of one process's timers.
pub(crate) struct TimerPause {
    count: u32,
    since: std::time::Instant,
    shift: std::time::Duration,
}

/// Status another process can read while this one is not running.
///
/// g_proc_sched
#[derive(Clone, Debug)]
pub(crate) struct Published {
    /// `process_info(P, status)` atom, unless a suspend count overrides it.
    pub status: &'static str,
    /// Hibernating processes report `{erlang, hibernate, 3}`.
    pub hibernating: bool,
    pub links: Vec<Pid>,
    pub monitors: Vec<(u64, Pid, Option<arinsal_etf::OwnedTerm>)>,
    pub monitored_by: Vec<(u64, Pid)>,
}

/// Scheduling state of a hibernating process; `apply(M, F, A)` waits in X0..X2.
///
/// g_proc_sched. Port of erts/emulator/beam/beam_common.c:1568 (`erts_hibernate`), OTP-29.1.1.
pub(crate) struct HibernateCont {
    /// The BIF has discarded the stack and the executor must leave the slice.
    pub stop: bool,
    /// elixir_loop1: `hibernate/0` resumes at its call site with the stack intact.
    pub resume_in_place: bool,
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

thread_local! {
    // A scheduler worker runs one runtime, so its executor needs no pid-style map lookup.
    static EXECUTOR: std::cell::RefCell<Option<(usize, Executor)>> =
        const { std::cell::RefCell::new(None) };
}

struct Executor {
    owner: Weak<Runtime>,
    vm: Vm,
    x: Box<[Term]>,
    fr: Box<[f64]>,
    /// Native register backing is scheduler-local, as required by x19.
    native_registers: SchedulerRegisters,
}
/// Error text of a remote send attempted without a scheduler context (native code).
pub(crate) const REMOTE_SEND_NEEDS_CONTEXT: &str = "remote send requires a scheduler context";

impl Executor {
    fn run(
        &mut self,
        process: &mut Process,
        ctx: &mut RunCtx<'_, Message>,
        budget: u32,
    ) -> Result<RunState, VmError> {
        process.header.self_pid = ctx.pid().to_term().expect("valid pid").tagged_word();
        process.self_pid = Some(ctx.pid());
        let schedule_started = std::time::Instant::now();
        let running = crate::trace::running_mfa(process, &self.vm, ctx.pid())?;
        let running_fields = running.as_slice();
        crate::trace::emit(
            Some(&mut self.vm),
            process,
            ctx,
            ctx.pid(),
            crate::trace::RUNNING,
            "in",
            running_fields,
        );
        self.vm.sync_module(process.module);
        if process.native_pc.is_some() && process.reductions <= 0 {
            process.reductions = budget.min(i32::MAX as u32) as i32;
        }
        // The entry process starts its function natively only on its first run; later runs
        // continue wherever its interpreted or native continuation is.
        let first_run = process.entry && !std::mem::replace(&mut process.entry_started, true);
        if first_run
            && process.native_pc.is_none()
            && let Some(module) = self.vm.modules.get(process.module)
            && let Some((function, arity)) = module.function_at(process.ip)
            && let Some(native) =
                crate::native_function_for(self.vm.code_scope, &module.name, function, arity)
        {
            process.native_pc = Some(native.start);
        }
        let (mut need_x, need_fr) = self.vm.registers[process.module];
        if crate::beamasm_integration::enabled() {
            need_x = need_x.max(8);
        }
        if self.x.len() < need_x {
            let mut registers = self.x.to_vec();
            registers.resize(need_x, Term::NIL);
            self.x = registers.into_boxed_slice();
        }
        if self.fr.len() < need_fr {
            let mut registers = self.fr.to_vec();
            registers.resize(need_fr, 0.0);
            self.fr = registers.into_boxed_slice();
        }
        // The scheduler owns the register file during execution. A suspended
        // process retains only the values needed to resume.
        std::mem::swap(&mut process.x, &mut self.x);
        std::mem::swap(&mut process.fr, &mut self.fr);
        if process.x.len() < self.x.len() {
            let mut registers = process.x.to_vec();
            registers.resize(self.x.len(), Term::NIL);
            process.x = registers.into_boxed_slice();
        }
        process.x[..self.x.len()].copy_from_slice(&self.x);
        // The tail still holds the previous run's registers on this executor; those are
        // pointers into another process's heap and must not reach this process's GC roots.
        process.x[self.x.len()..].fill(Term::NIL);
        if process.fr.len() < self.fr.len() {
            let mut registers = process.fr.to_vec();
            registers.resize(self.fr.len(), 0.0);
            process.fr = registers.into_boxed_slice();
        }
        process.fr[..self.fr.len()].copy_from_slice(&self.fr);
        let native_x = process.x.len().min(self.native_registers.x_reg_array.len());
        for (register, term) in self.native_registers.x_reg_array[..native_x]
            .iter_mut()
            .zip(&process.x[..native_x])
        {
            // SAFETY: X registers store immediate or stable heap terms as raw 64-bit words.
            *register = unsafe { term.raw_bits() };
        }
        self.native_registers.f_reg_array[..self.fr.len().min(1024)]
            .copy_from_slice(&process.fr[..self.fr.len().min(1024)]);
        let result = (|| -> Result<RunState, VmError> {
            'execution: {
                // Port of erts/emulator/beam/erl_process.c:12940-13152 (erl_create_process), OTP-29.1.1.
                // A spawned MFA may name a BIF directly; execute it as the process entry so
                // exceptions such as exit/1 retain their BIF class and reason.
                if let Some((module, function, arity)) = process
                    .cold
                    .as_mut()
                    .and_then(|cold| cold.initial_bif.take())
                {
                    let mut args = process.x[..usize::from(arity)].to_vec();
                    let Some(bif) = arinsal_bifs::lookup(&module, &function, arity) else {
                        // A BIF implemented by a VM native (process-aware BIFs such as
                        // erlang:node/1 or register/2) runs through the native table.
                        match self.vm.dispatch_native(
                            process,
                            ctx,
                            &module,
                            &function,
                            usize::from(arity),
                            (arinsal_loader::ImportClass::Dynamic, 0),
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
                    let mut result = crate::calls::call_bif(&mut process.heap, bif, &args);
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
                if ctx.sys_task_run() {
                    process.drain(ctx)?;
                }
                loop {
                    // A caught exception re-enters this loop without replenishing its process slice.
                    if ctx.remaining() == 0 {
                        break Ok(RunState::Yield);
                    }
                    if process.force_yield {
                        process.force_yield = false;
                        break Ok(RunState::Yield);
                    }
                    if let Some(cold) = process.cold.as_mut() {
                        cold.native_transfer = false;
                    }
                    // g_proc_sched: a suspended process is not scheduled; a hibernating
                    // one stays waiting until a message arrives, then continues at apply/3.
                    if let Some(wait) = self.sched_preempt(process, ctx)? {
                        break Ok(wait);
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
                                process.cold_mut().native_continuation_resume = true;
                                process.cold_mut().native_resume_live = 2;
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
                    if let Some(code_ptr) = process.native_pc.take() {
                        crate::beamasm_integration::count_native_call();
                        // Native receives look at the private queue only; fetch what arrived.
                        process.drain(ctx)?;
                        process.header.self_pid =
                            ctx.pid().to_term().expect("valid pid").tagged_word();
                        process.self_pid = Some(ctx.pid());
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
                            // The redone call keeps its return address and call site, so a BIF
                            // that fails after trapping raises at the original call.
                            let (resume_pc, call_site_pc) = process
                                .cold
                                .as_mut()
                                .and_then(|cold| cold.native_retry_site.take())
                                .unwrap_or((0, 0));
                            if call_site_pc != 0 {
                                process.cold_mut().native_error_pc = call_site_pc;
                            }
                            arinsal_beamasm::ExitReason::CallUnported {
                                target_pc,
                                resume_pc,
                            }
                        } else {
                            // Port of erts/emulator/beam/erl_process.c (schedule: reductions
                            // used = CONTEXT_REDS - FCALLS), OTP-29.1.1: native code counts down
                            // FCALLS; the scheduler charges what it used.
                            let fcalls_before = process.reductions;
                            let native =
                                crate::run_native(process, &mut self.native_registers, code_ptr);
                            let consumed = fcalls_before.saturating_sub(process.reductions);
                            ctx.consume(u32::try_from(consumed).unwrap_or(0));
                            // Native `timeout` has no scheduler context to send its trace event.
                            if process
                                .cold
                                .as_mut()
                                .is_some_and(|cold| std::mem::take(&mut cold.native_timeout_trace))
                            {
                                crate::trace::timeout_event(Some(&mut self.vm), process, ctx);
                            }
                            // Port of erts/emulator/beam/erl_process.c (erts_current_reductions),
                            // OTP-29.1.1: the process's reduction count includes what its
                            // native code consumed from FCALLS.
                            process.reductions_used = process
                                .reductions_used
                                .saturating_add(u64::try_from(consumed).unwrap_or(0));
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
                                if let Some(timeout_ms) = process
                                    .cold
                                    .as_mut()
                                    .and_then(|cold| cold.native_wait.take())
                                {
                                    // A native receive found no matching message. Like the
                                    // interpreter's `wait`, sleep only if nothing arrived since the
                                    // slice began; the process resumes at the `loop_rec` label with
                                    // no live X registers.
                                    process.gc_live = 0;
                                    process.cold_mut().native_resume_live = 1;
                                    // A receive without clauses blocks even with messages queued,
                                    // like the interpreter's self-targeting `wait`.
                                    let self_wait =
                                        std::mem::take(&mut process.cold_mut().native_wait_self);
                                    if self_wait {
                                        process.drain(ctx)?;
                                    } else if !Vm::mailbox_ready_to_wait(
                                        process,
                                        &mut Some(&mut *ctx),
                                    )? {
                                        continue;
                                    }
                                    break Ok(RunState::Wait { timeout_ms });
                                }
                                break Ok(RunState::Yield);
                            }
                            arinsal_beamasm::ExitReason::CallUnported {
                                target_pc,
                                resume_pc,
                            } => {
                                crate::beamasm_integration::count_call_unported();
                                // The native call site names the caller only if the called BIF
                                // raises; any other continuation must not inherit it.
                                let call_site_pc = process
                                    .cold
                                    .as_mut()
                                    .map_or(0, |cold| std::mem::take(&mut cold.native_error_pc));
                                process.cold_mut().native_retry_site =
                                    Some((resume_pc, call_site_pc));
                                if target_pc
                                    == arinsal_beamasm::dispatch::RETURN_TO_DISPATCH_IDENTITY
                                {
                                    // A traced native return: its return_from events are out
                                    // and its frame is gone; resume_pc is the caller.
                                    let sessions =
                                        std::mem::take(&mut process.cold_mut().native_return_to);
                                    for session in sessions {
                                        crate::trace::native_return_to_event(
                                            &mut self.vm,
                                            process,
                                            ctx,
                                            session,
                                            resume_pc,
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
                                        process.cold_mut().native_continuation_resume = true;
                                        process.cold_mut().native_resume_live = 2;
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
                                    // The trace callbacks read every argument, including those
                                    // above the X registers synced on exit.
                                    let arity = usize::from(function.arity)
                                        .min(self.native_registers.x_reg_array.len());
                                    if process.x.len() < arity {
                                        let mut x = process.x.to_vec();
                                        x.resize(arity, Term::NIL);
                                        process.x = x.into_boxed_slice();
                                    }
                                    for (destination, raw) in process
                                        .x
                                        .iter_mut()
                                        .zip(self.native_registers.x_reg_array.iter().copied())
                                        .take(arity)
                                    {
                                        *destination = crate::native_hooks::from_raw(raw);
                                    }
                                    crate::trace_bp::increment(
                                        process,
                                        &function.module,
                                        &function.function,
                                        function.arity,
                                        true,
                                    );
                                    let actions = crate::trace::executor_native_call_event(
                                        &mut self.vm,
                                        process,
                                        ctx,
                                        &function,
                                    )?;
                                    crate::trace::push_native_trace_frame(
                                        process, resume_pc, &actions,
                                    )?;
                                    process.cold_mut().native_continuation_resume = true;
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
                                    let value = process.send_message_prio(
                                        Some(&mut self.vm),
                                        Some(ctx),
                                        process.x[0],
                                        process.x[1],
                                        false,
                                    )?;
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
                                    let saved_x = process.x.to_vec();
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
                                                crate::ImportOutcome::Jump(_)
                                                | crate::ImportOutcome::Advanced => {}
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
                                                        for (register, value) in
                                                            process.x.iter_mut().zip(&saved_x)
                                                        {
                                                            *register = *value;
                                                        }
                                                        process.cold_mut().native_retry =
                                                            Some(target_pc);
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
                                            for (register, value) in
                                                process.x.iter_mut().zip(&saved_x)
                                            {
                                                *register = *value;
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
                                        Err(error) => return Err(error),
                                    };
                                    // Port of erts/emulator/beam/beam_common.c:1345-1427
                                    // (apply_bif_error_adjustment), OTP-29.1.1: the applied
                                    // function raised at the apply instruction, which names the
                                    // calling function; its continuation is not another frame.
                                    if call_site_pc != 0
                                        && target_pc != arinsal_beamasm::dispatch::CALL_FUN_UNPORTED
                                    {
                                        process.cold_mut().native_error_pc = call_site_pc;
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
                                let Some(export) =
                                    crate::beamasm_integration::export_dispatch(target_pc)
                                else {
                                    if let Some(m) = self.vm.modules.get(process.module)
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
                                self.vm.sync_code_epoch();
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
                                        &export.module,
                                        &export.function,
                                        export.arity,
                                    ))
                                {
                                    let saved_arguments =
                                        process.x[..usize::from(export.arity)].to_vec();
                                    // BIFs such as load_nif/2 identify their caller through
                                    // `process.module`, which native code does not maintain: the
                                    // caller is the native function holding the return address.
                                    let interpreter_module = process.module;
                                    // A module whose on_load is running is not current yet.
                                    if let Some(caller) = crate::native_function_at(resume_pc)
                                        .and_then(|caller| {
                                            self.vm
                                                .pending_on_load
                                                .get(&caller.module)
                                                .copied()
                                                .filter(|id| {
                                                    self.vm.native_code_contains(*id, resume_pc)
                                                })
                                                .or_else(|| {
                                                    self.vm.loaded.get(&caller.module).copied()
                                                })
                                        })
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
                                        ];
                                        if let Some(trapped) = crate::bif_traps::execute_named(
                                            process,
                                            &export.module,
                                            &export.function,
                                            target_pc,
                                            usize::from(export.arity),
                                            trap_args,
                                            Some(ctx),
                                        ) {
                                            match trapped {
                                                Ok(crate::bif_traps::TrapResult::Yield {
                                                    ..
                                                }) => {
                                                    // The X registers hold the arguments as any collection
                                                    // the BIF ran moved them; the copies are stale.
                                                    process.cold_mut().native_retry =
                                                        Some(target_pc);
                                                    process.native_pc = Some(code_ptr);
                                                    break Ok(RunState::Yield);
                                                }
                                                Ok(crate::bif_traps::TrapResult::Done {
                                                    value,
                                                    ..
                                                }) => {
                                                    process.x[0] = value;
                                                    process.collect_bin_vheap_if_due(0)?;
                                                    Some(Ok(process.x[0]))
                                                }
                                                Ok(crate::bif_traps::TrapResult::Failed {
                                                    ..
                                                }) => Some(Err(VmError::Unsupported(
                                                    "failed trapping BIF without exception".into(),
                                                ))),
                                                Err(error) => Some(Err(error)),
                                            }
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
                                            );
                                            let result = self.vm.dispatch_native(
                                                process,
                                                ctx,
                                                &export.module,
                                                &export.function,
                                                usize::from(export.arity),
                                                (export.class, export.native_bits),
                                            );
                                            process.cold_mut().native_call_pc = 0;
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
                                                            args: crate::stacktrace::BifArgs::from_terms(
                                                                &saved_arguments,
                                                            )?,
                                                            info: crate::stacktrace::BifErrorInfo::Plain,
                                                        });
                                                }
                                                process.cold_mut().native_error_pc = call_site_pc;
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
                                            // ERTS_BIF_YIELD (e.g. a persistent_term updater
                                            // waiting for thread progress): the native call is
                                            // redone when the process is scheduled again.
                                            Err(VmError::Yield) => {
                                                for (register, value) in
                                                    process.x.iter_mut().zip(&saved_arguments)
                                                {
                                                    *register = *value;
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
                                                if hibernate_stopped(process, ctx.pid()) =>
                                            {
                                                // hibernate/0 keeps its stack: after the wakeup the
                                                // native call is retried and returns `ok` in place.
                                                if hibernate_resumes_in_place(process, ctx.pid()) {
                                                    let cold = process.cold_mut();
                                                    cold.native_retry = Some(target_pc);
                                                    process.native_pc = Some(code_ptr);
                                                    break Ok(RunState::Wait { timeout_ms: None });
                                                }
                                                process.native_pc = None;
                                                if let Some(cold) = process.cold.as_mut() {
                                                    cold.native_continuation_resume = false;
                                                }
                                                process.drain(ctx)?;
                                                if process.inbox.is_empty() {
                                                    hibernate_collect(process, ctx.pid())?;
                                                    if let Some(runtime) = process.runtime.clone() {
                                                        runtime.mark_hibernating(ctx.pid(), true);
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
                                let module_id = match self.vm.loaded.get(&export.module).copied() {
                                    Some(module_id) => module_id,
                                    // Like call_import: a module with -on_load is loaded through
                                    // the error handler and code server, which run its on_load.
                                    None => {
                                        match if self.vm.unloaded_on_load(process, &export.module) {
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
                                                    crate::ImportOutcome::Jump(_)
                                                    | crate::ImportOutcome::Advanced => {}
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
                                    self.vm.modules[module_id]
                                        .export_slot(&export.function, export.arity)
                                        .map(arinsal_loader::ExportSlot::target)
                                });
                                if let Some(target_ip) = target_ip {
                                    process.gc_live = usize::from(export.arity);
                                    process.module = module_id;
                                    process.ip = target_ip;
                                    process.tick();
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
                                        crate::ImportOutcome::Jump(_)
                                        | crate::ImportOutcome::Advanced => {}
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
                    let result = process
                        .drain(ctx)
                        .and_then(|()| self.vm.run_slice(process, Some(ctx), remaining));
                    // erts schedules out only when FCALLS runs out; an interpreted step that
                    // just hands control to native code continues the slice.
                    if matches!(&result, Ok(RunState::Yield))
                        && process.native_pc.is_some()
                        && !process.force_yield
                        && native_transfer_continues(process, ctx)
                    {
                        continue;
                    }
                    if hibernate_stopped(process, ctx.pid()) {
                        process.drain(ctx)?;
                        if process.inbox.is_empty() {
                            hibernate_collect(process, ctx.pid())?;
                            if let Some(runtime) = process.runtime.clone() {
                                runtime.mark_hibernating(ctx.pid(), true);
                            }
                            break Ok(RunState::Wait { timeout_ms: None });
                        }
                        self.install_apply(process, ctx)?;
                        continue;
                    }
                    if matches!(&result, Ok(RunState::Yield))
                        && process
                            .runtime
                            .as_ref()
                            .is_some_and(|runtime| runtime.suspend_total_of(ctx.pid()) > 0)
                    {
                        process.cold_mut().suspend_parked = true;
                        break Ok(RunState::Wait { timeout_ms: None });
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
                            let arity = self.vm.modules[process.module]
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
                            self.vm.modules[process.module].lines.get(process.ip),
                            self.vm.modules[process.module].code.get(process.ip),
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
        std::mem::swap(&mut process.x, &mut self.x);
        std::mem::swap(&mut process.fr, &mut self.fr);
        if matches!(
            result,
            Ok(RunState::Yield | RunState::Wait { .. }) | Err(VmError::Yield | VmError::Dirty(_))
        ) {
            let (live_x, live_fr) = self.vm.registers[process.module];
            // A native continuation keeps the live X registers of its yield site, which the
            // interpreted module's register count does not bound.
            let native_live = if process.native_pc.is_some() {
                process
                    .cold
                    .as_ref()
                    .map_or(0, |cold| usize::from(cold.native_resume_live))
            } else {
                0
            };
            let live_x = live_x.max(native_live);
            if crate::native_bridge::return_trace_enabled() && process.native_pc.is_some() {
                eprintln!(
                    "[sched-save-native] live_x={live_x} x_len={} x0={:#x} module={} native_pc={:?}",
                    self.x.len(),
                    self.x.first().map_or(0, |term| term.tagged_word()),
                    self.vm.modules[process.module].name,
                    process.native_pc
                );
            }
            let mut saved_x = process.x.to_vec();
            saved_x.resize(live_x, Term::NIL);
            let copy_x = self.x.len().min(live_x);
            saved_x[..copy_x].copy_from_slice(&self.x[..copy_x]);
            process.x = saved_x.into_boxed_slice();
            let mut saved_fr = process.fr.to_vec();
            saved_fr.resize(live_fr, 0.0);
            let copy_fr = self.fr.len().min(live_fr);
            saved_fr[..copy_fr].copy_from_slice(&self.fr[..copy_fr]);
            process.fr = saved_fr.into_boxed_slice();
        } else {
            process.x = Box::new([]);
            process.fr = Box::new([]);
        }
        let running = crate::trace::running_mfa(process, &self.vm, ctx.pid())?;
        let running_fields = running.as_slice();
        if matches!(result, Ok(RunState::Yield | RunState::Wait { .. })) {
            process.collect_bin_vheap_if_due(process.x.len())?;
        }
        crate::trace::emit(
            Some(&mut self.vm),
            process,
            ctx,
            ctx.pid(),
            crate::trace::RUNNING,
            "out",
            running_fields,
        );
        crate::natives::erts_debug::after_schedule(
            process,
            schedule_started.elapsed().as_nanos() as u64,
        );
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
        let Some(runtime) = process.runtime.clone() else {
            return Ok(None);
        };
        let pid = ctx.pid();
        if runtime.suspend_total_of(pid) > 0 {
            process.drain(ctx)?;
            // The resumer's wake-up signal may have been consumed by the drain above: re-check
            // so a resume racing with this suspension is not lost (otherwise the process
            // waits forever).
            if runtime.suspend_total_of(pid) == 0 {
                return Ok(None);
            }
            runtime.suspends_activated(pid);
            runtime.note_status(pid, "suspended");
            process.cold_mut().suspend_parked = true;
            return Ok(Some(RunState::Wait { timeout_ms: None }));
        }
        if let Some(shift) = runtime.take_pause_shift(pid)
            && let Some(deadline) = process.receive_deadline.as_mut()
        {
            *deadline += shift;
        }
        if runtime.is_hibernating(pid) {
            process.drain(ctx)?;
            if process.inbox.is_empty() {
                runtime.note_status(pid, "waiting");
                return Ok(Some(RunState::Wait { timeout_ms: None }));
            }
            // elixir_loop1: unlike hibernate/3, hibernate/0 keeps its stack.
            let resume_in_place = runtime
                .hibernating
                .lock()
                .unwrap()
                .get(&pid)
                .is_some_and(|cont| cont.resume_in_place);
            if resume_in_place {
                runtime.mark_hibernating(pid, false);
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
        runtime
            .hibernating
            .lock()
            .unwrap()
            .remove(&pid)
            .ok_or_else(|| VmError::Unsupported("hibernate continuation missing".into()))?;
        runtime.mark_hibernating(pid, false);
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
        Ok(())
    }
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
        if crate::native_bridge::is_native_function_at(raw) {
            process.heap.release_stack(1);
            process.cold_mut().native_continuation_resume = true;
            process.cold_mut().native_resume_live = 2;
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
pub(crate) fn erlang_apply_entry(vm: &mut Vm) -> Result<(usize, usize), VmError> {
    let module_id = vm.load_named("erlang")?;
    let entry = vm.modules[module_id]
        .functions
        .iter()
        .find(|(_, name, arity)| name == "apply" && *arity == 3)
        .map(|(ip, _, _)| ip + 1)
        .ok_or_else(|| VmError::Unsupported("erlang:apply/3 is not loaded".into()))?;
    Ok((module_id, entry))
}

// g_proc_sched
fn hibernate_resumes_in_place(process: &Process, pid: Pid) -> bool {
    process.runtime.as_ref().is_some_and(|runtime| {
        runtime
            .hibernating
            .lock()
            .unwrap()
            .get(&pid)
            .is_some_and(|cont| cont.resume_in_place)
    })
}

/// `hibernate/3` with no waiting messages: shrink the heap to the `apply(M, F, A)`
/// arguments in X0..X2. Run after the BIF has unwound so no caller keeps stale terms.
// Port of erts/emulator/beam/beam_common.c:1584-1592 (erts_hibernate), OTP-29.1.1.
fn hibernate_collect(process: &mut Process, pid: Pid) -> Result<(), VmError> {
    if !process.gc_enabled || hibernate_resumes_in_place(process, pid) {
        return Ok(());
    }
    process.garbage_collect_hibernate(3).map(|_| ())
}

fn hibernate_stopped(process: &Process, pid: Pid) -> bool {
    let Some(runtime) = &process.runtime else {
        return false;
    };
    if !runtime.ever_hibernated.load(Ordering::Acquire) {
        return false;
    }
    let mut parked = runtime.hibernating.lock().unwrap();
    let Some(cont) = parked.get_mut(&pid) else {
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
    let mut heap = arinsal_bifs::FragmentingHeap(&mut process.heap);
    match arinsal_term::from_owned(&owned, &mut heap) {
        Ok(reason) => reason,
        Err(conversion_error) => {
            eprintln!("arinsal: exit reason conversion failed: {conversion_error:?}");
            crate::signals::atom("system_limit")
        }
    }
}

// g_proc_sched. Port of erl_gc.c:3730 (`has_reached_max_heap_size`) and
// erl_gc.c:3741 (`reached_max_heap_size`), OTP-29.1.1.
fn heap_limit_kills(process: &mut Process, ctx: &mut RunCtx<'_, Message>) -> bool {
    let Some(runtime) = process.runtime.clone() else {
        return false;
    };
    if !runtime.ever_max_heap.load(Ordering::Acquire) {
        return false;
    }
    let snapshot = {
        let mut heaps = runtime.max_heaps.lock().unwrap();
        let Some(limit) = heaps.get_mut(&ctx.pid()) else {
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
        }
        (log, limit.kill, *limit, used)
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
    // Completed processes release their X register array before the scheduler's
    // final max-heap check, while gc_live still describes the last BEAM frame.
    for term in process.x[..process.gc_live.min(process.x.len())]
        .iter()
        .copied()
        .chain(process.inbox.iter().copied())
    {
        stack.push(term);
    }
    if let Some(cold) = &process.cold {
        for (key, value) in &cold.dictionary {
            stack.push(*key);
            stack.push(*value);
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
    let logger = {
        let names = runtime.names.lock().unwrap();
        names
            .get("logger")
            .or_else(|| names.get("error_logger"))
            .copied()
    };
    let Some(logger) = logger else {
        return;
    };
    let Some(pid) = ctx.pid().to_term() else {
        return;
    };
    let group_leader = process
        .cold
        .as_ref()
        .and_then(|cold| cold.group_leader)
        .and_then(Pid::to_term);
    let bool_atom = |on: bool| crate::signals::atom(if on { "true" } else { "false" });
    let built = (|| -> Result<Term, VmError> {
        let mut heap = arinsal_bifs::FragmentingHeap(&mut process.heap);
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

    pub(crate) fn scheduler(&self) -> Result<Arc<Scheduler<Process>>, VmError> {
        self.scheduler
            .lock()
            .unwrap()
            .upgrade()
            .ok_or_else(|| VmError::Unsupported("scheduler has stopped".into()))
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
            let code = self.code.lock().unwrap();
            Some(inspect(target, &code.modules))
        })?
    }

    // g_proc_sched. Port of erts/emulator/beam/erl_process.c:9013
    // (`erts_internal_suspend_process_2`), OTP-29.1.1.
    pub(crate) fn suspend_total_of(&self, target: Pid) -> u32 {
        if !self.ever_suspended.load(Ordering::Acquire) {
            return 0;
        }
        self.suspend_total
            .lock()
            .unwrap()
            .get(&target)
            .copied()
            .unwrap_or(0)
    }

    /// The target scheduled out with suspends pending: they are all active now.
    pub(crate) fn suspends_activated(&self, target: Pid) {
        if self.ever_suspended.load(Ordering::Acquire) {
            self.suspend_outstanding
                .lock()
                .unwrap()
                .retain(|(_, pending_target), _| *pending_target != target);
        }
    }

    /// `{Suspendee, Active, Outstanding}` rows for `process_info(P, suspending)`.
    pub(crate) fn suspending_of(&self, by: Pid) -> Vec<(Pid, u32, u32)> {
        if !self.ever_suspended.load(Ordering::Acquire) {
            return Vec::new();
        }
        let counts = self.suspend_counts.lock().unwrap();
        let outstanding = self.suspend_outstanding.lock().unwrap();
        let mut rows: Vec<_> = counts
            .iter()
            .filter(|((from, _), count)| *from == by && **count > 0)
            .map(|((_, target), count)| {
                let outstanding = outstanding
                    .get(&(by, *target))
                    .copied()
                    .unwrap_or(0)
                    .min(*count);
                (*target, *count - outstanding, outstanding)
            })
            .collect();
        rows.sort_by_key(|(pid, _, _)| (pid.index, pid.generation));
        rows
    }

    /// Increase the suspend count. `Ok(false)` is `unless_suspending` with no change.
    pub(crate) fn suspend(
        &self,
        by: Pid,
        target: Pid,
        unless_suspending: bool,
        asynchronous: bool,
    ) -> Result<bool, ()> {
        self.ever_suspended.store(true, Ordering::Release);
        // A running target keeps going until it next schedules out.
        let pending = asynchronous
            && by != target
            && self.suspend_total_of(target) == 0
            && self
                .scheduler()
                .is_ok_and(|scheduler| scheduler.is_running(target));
        let mut counts = self.suspend_counts.lock().unwrap();
        let entry = counts.entry((by, target)).or_insert(0);
        if unless_suspending && *entry > 0 {
            return Ok(false);
        }
        if *entry == u32::MAX {
            return Err(());
        }
        *entry += 1;
        drop(counts);
        if pending {
            *self
                .suspend_outstanding
                .lock()
                .unwrap()
                .entry((by, target))
                .or_insert(0) += 1;
        }
        {
            let mut totals = self.suspend_total.lock().unwrap();
            *totals.entry(target).or_insert(0) += 1;
        }
        if by != target {
            self.pause_timers(target, 1);
        }
        self.note_status(target, "suspended");
        Ok(true)
    }

    /// Runtime-internal suspend without a suspend monitor (`erts_suspend`), used for a
    /// process waiting on a pending-purge lambda.
    /// Port of erts/emulator/beam/erl_process.c:9369 (erts_suspend), OTP-29.1.1.
    pub(crate) fn suspend_internal(&self, target: Pid) {
        self.ever_suspended.store(true, Ordering::Release);
        *self
            .suspend_total
            .lock()
            .unwrap()
            .entry(target)
            .or_insert(0) += 1;
        self.note_status(target, "suspended");
    }

    /// Undo [`Runtime::suspend_internal`]; true when the target must be rescheduled.
    /// Port of erts/emulator/beam/erl_process.c:9402 (erts_resume), OTP-29.1.1.
    pub(crate) fn resume_internal(&self, target: Pid) -> bool {
        let wake = {
            let mut totals = self.suspend_total.lock().unwrap();
            let Some(total) = totals.get_mut(&target) else {
                return false;
            };
            *total = total.saturating_sub(1);
            let wake = *total == 0;
            if wake {
                totals.remove(&target);
            }
            wake
        };
        if wake {
            let hibernating = self
                .published
                .lock()
                .unwrap()
                .get(&target)
                .is_some_and(|slot| slot.hibernating);
            self.note_status(target, if hibernating { "waiting" } else { "runnable" });
        }
        wake
    }

    /// Decrease one suspend acquired by `by`. `None` if that caller is not suspending.
    /// `Some(true)` when the target's total count reaches zero and it must be scheduled.
    pub(crate) fn resume(&self, by: Pid, target: Pid) -> Option<bool> {
        if !self.ever_suspended.load(Ordering::Acquire) {
            return None;
        }
        let mut counts = self.suspend_counts.lock().unwrap();
        let entry = counts.get_mut(&(by, target))?;
        if *entry == 0 {
            return None;
        }
        *entry -= 1;
        if *entry == 0 {
            counts.remove(&(by, target));
            self.suspend_outstanding
                .lock()
                .unwrap()
                .remove(&(by, target));
        }
        drop(counts);
        if by != target {
            self.resume_timers(target, 1);
        }
        let wake = {
            let mut totals = self.suspend_total.lock().unwrap();
            let total = totals.entry(target).or_insert(0);
            *total = total.saturating_sub(1);
            let wake = *total == 0;
            if wake {
                totals.remove(&target);
            }
            wake
        };
        if wake {
            let hibernating = self
                .published
                .lock()
                .unwrap()
                .get(&target)
                .is_some_and(|slot| slot.hibernating);
            self.note_status(target, if hibernating { "waiting" } else { "runnable" });
        }
        Some(wake)
    }

    /// Drop every suspend this process acquired. Returns targets whose count hit zero.
    pub(crate) fn release_suspender(&self, by: Pid) -> Vec<Pid> {
        if !self.ever_suspended.load(Ordering::Acquire) {
            return Vec::new();
        }
        let held: Vec<(Pid, u32)> = {
            let mut counts = self.suspend_counts.lock().unwrap();
            let held = counts
                .iter()
                .filter(|((from, _), count)| *from == by && **count > 0)
                .map(|((_, target), count)| (*target, *count))
                .collect();
            counts.retain(|(from, _), _| *from != by);
            held
        };
        if held.is_empty() {
            return Vec::new();
        }
        let mut wake = Vec::new();
        {
            let mut totals = self.suspend_total.lock().unwrap();
            for (target, count) in held {
                if target != by {
                    self.resume_timers(target, count);
                }
                if let Some(total) = totals.get_mut(&target) {
                    *total = total.saturating_sub(count);
                    if *total == 0 {
                        totals.remove(&target);
                        wake.push(target);
                    }
                }
            }
        }
        for target in &wake {
            let hibernating = self
                .published
                .lock()
                .unwrap()
                .get(target)
                .is_some_and(|slot| slot.hibernating);
            self.note_status(*target, if hibernating { "waiting" } else { "runnable" });
        }
        wake
    }

    /// A suspend monitor became active on `target`: its receive timeout and the BIF timers
    /// aimed at it stop counting down.
    /// Port of erts/emulator/beam/erl_process.c:9140 (erts_internal_suspend_process_2) and
    /// erl_hl_timer.c:2849 (erts_pause_proc_timer), OTP-29.1.1.
    fn pause_timers(&self, target: Pid, count: u32) {
        let first = {
            let mut pauses = self.pauses.lock().unwrap();
            let pause = pauses.entry(target).or_insert_with(|| TimerPause {
                count: 0,
                since: std::time::Instant::now(),
                shift: std::time::Duration::ZERO,
            });
            pause.count += count;
            pause.count == count
        };
        if first && let Ok(scheduler) = self.scheduler() {
            scheduler.pause_target_timers(target);
        }
    }

    /// Port of erts/emulator/beam/erl_proc_sig_queue.c:6617 and erl_hl_timer.c:2919
    /// (erts_resume_paused_proc_timer), OTP-29.1.1: the last resume re-arms the timers.
    fn resume_timers(&self, target: Pid, count: u32) {
        let last = {
            let mut pauses = self.pauses.lock().unwrap();
            let Some(pause) = pauses.get_mut(&target) else {
                return;
            };
            pause.count = pause.count.saturating_sub(count);
            if pause.count == 0 {
                pause.shift += pause.since.elapsed();
                true
            } else {
                false
            }
        };
        if last && let Ok(scheduler) = self.scheduler() {
            scheduler.resume_target_timers(target);
        }
    }

    /// Time the process spent suspended since it last asked; shifts its receive deadline.
    pub(crate) fn take_pause_shift(&self, pid: Pid) -> Option<std::time::Duration> {
        if !self.ever_suspended.load(Ordering::Acquire) {
            return None;
        }
        let mut pauses = self.pauses.lock().unwrap();
        let pause = pauses.get_mut(&pid)?;
        if pause.count != 0 {
            return None;
        }
        let shift = pause.shift;
        pauses.remove(&pid);
        Some(shift)
    }

    pub(crate) fn forget_process(&self, pid: Pid) {
        if self.ever_suspended.load(Ordering::Acquire) {
            self.pauses.lock().unwrap().remove(&pid);
        }
        if self.ever_hibernated.load(Ordering::Acquire) {
            self.hibernating.lock().unwrap().remove(&pid);
        }
        if self.ever_max_heap.load(Ordering::Acquire) {
            self.max_heaps.lock().unwrap().remove(&pid);
        }
        self.published.lock().unwrap().remove(&pid);
        if self.ever_suspended.load(Ordering::Acquire) {
            self.suspend_total.lock().unwrap().remove(&pid);
            self.suspend_counts
                .lock()
                .unwrap()
                .retain(|(by, target), _| *by != pid && *target != pid);
        }
    }

    pub(crate) fn note_status(&self, pid: Pid, status: &'static str) {
        let suspended = self.suspend_total_of(pid) > 0;
        let mut published = self.published.lock().unwrap();
        let slot = published.entry(pid).or_insert(Published {
            status,
            hibernating: false,
            links: Vec::new(),
            monitors: Vec::new(),
            monitored_by: Vec::new(),
        });
        if suspended {
            slot.status = "suspended";
        } else if slot.hibernating {
            slot.status = "waiting";
        } else {
            slot.status = status;
        }
    }

    pub(crate) fn mark_hibernating(&self, pid: Pid, on: bool) {
        let suspended = self.suspend_total_of(pid) > 0;
        let mut published = self.published.lock().unwrap();
        let slot = published.entry(pid).or_insert(Published {
            status: "waiting",
            hibernating: on,
            links: Vec::new(),
            monitors: Vec::new(),
            monitored_by: Vec::new(),
        });
        slot.hibernating = on;
        if !suspended {
            slot.status = "waiting";
        }
    }

    pub(crate) fn remote_status(&self, pid: Pid) -> &'static str {
        if self.suspend_total_of(pid) > 0 {
            return "suspended";
        }
        self.published
            .lock()
            .unwrap()
            .get(&pid)
            .map(|slot| {
                if slot.hibernating {
                    "waiting"
                } else {
                    slot.status
                }
            })
            .unwrap_or("runnable")
    }

    fn note_relations(&self, pid: Pid, cold: Option<&crate::proc_create::ProcessCold>) {
        let mut published = self.published.lock().unwrap();
        let slot = published.entry(pid).or_insert(Published {
            status: "runnable",
            hibernating: false,
            links: Vec::new(),
            monitors: Vec::new(),
            monitored_by: Vec::new(),
        });
        if let Some(cold) = cold {
            slot.links = cold.links.iter().copied().collect();
            slot.monitors = cold
                .monitors
                .iter()
                .map(|(&reference, &target)| {
                    (
                        reference,
                        target,
                        cold.monitor_tags.get(&reference).cloned(),
                    )
                })
                .collect();
            slot.monitored_by = cold
                .monitored_by
                .iter()
                .map(|(&reference, &origin)| (reference, origin))
                .collect();
        } else {
            slot.links.clear();
            slot.monitors.clear();
            slot.monitored_by.clear();
        }
    }

    pub(crate) fn is_hibernating(&self, pid: Pid) -> bool {
        self.published
            .lock()
            .unwrap()
            .get(&pid)
            .is_some_and(|slot| slot.hibernating)
    }

    /// Run `body` against the module table shared by scheduler processes.
    pub(crate) fn with_modules<R>(
        &self,
        body: impl FnOnce(&[Arc<arinsal_loader::Module>]) -> R,
    ) -> R {
        let code = self.code.lock().unwrap();
        body(&code.modules)
    }

    /// Create a distributed spawn child without running it before the spawn reply.
    // Port of erts/emulator/beam/erl_process.c:12940-13152 (erl_create_process), OTP-29.1.1.
    pub(crate) fn spawn_mfa_unscheduled(
        self: &Arc<Self>,
        module: &str,
        function: &str,
        args: &[arinsal_etf::OwnedTerm],
    ) -> Result<Pid, VmError> {
        self.spawn_mfa_scheduled(module, function, args, false)
    }

    fn spawn_mfa_scheduled(
        self: &Arc<Self>,
        module: &str,
        function: &str,
        args: &[arinsal_etf::OwnedTerm],
        scheduled: bool,
    ) -> Result<Pid, VmError> {
        let (module_id, ip) = {
            let code = self.code.lock().unwrap();
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
        child.cold_mut().initial_call =
            Some((module.to_owned(), function.to_owned(), args.len() as u8));
        if let Some(arity) = u8::try_from(args.len()).ok()
            && (arinsal_bifs::lookup(module, function, arity).is_some()
                || arinsal_spec::bif_lookup(module, function, arity).is_some())
        {
            child.cold_mut().initial_bif = Some((module.to_owned(), function.to_owned(), arity));
        }
        for (index, owned) in args.iter().enumerate() {
            let mut heap = arinsal_bifs::FragmentingHeap(&mut child.heap);
            child.x[index] = arinsal_term::from_owned(owned, &mut heap)
                .map_err(|_| VmError::Unsupported("spawn argument copy failed".into()))?;
        }
        let scheduler = self.scheduler()?;
        let pid = if scheduled {
            scheduler.spawn(child)
        } else {
            scheduler.spawn_unscheduled(child)
        }
        .map_err(|error| VmError::Unsupported(format!("spawn: {error}")))?;
        self.processes.lock().unwrap().insert(pid);
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
    fn absorb_exit_signals(&mut self, ctx: &mut RunCtx<'_, Message>) {
        while let Some(Event { from, payload }) = ctx.receive() {
            match payload {
                Payload::Signal(Signal::Monitor(reference)) => {
                    self.cold_mut().monitored_by.insert(reference, from);
                }
                Payload::Signal(Signal::Demonitor(reference)) => {
                    if let Some(cold) = self.cold.as_mut() {
                        cold.monitored_by.remove(&reference);
                    }
                }
                Payload::Signal(Signal::Link) => {
                    self.cold_mut().links.insert(from);
                }
                Payload::Signal(Signal::Unlink(_)) => {
                    if let Some(cold) = self.cold.as_mut() {
                        cold.links.remove(&from);
                        cold.prio_links.remove(&from);
                    }
                }
                Payload::Signal(Signal::LiteralAreaCopy {
                    request, requester, ..
                }) => {
                    let _ = crate::natives::sys::reply_exiting_literal_area(
                        self, ctx, request, requester,
                    );
                }
                _ => {}
            }
        }
    }

    fn tuple(&mut self, elements: &[Term]) -> Result<Term, VmError> {
        let mut heap = arinsal_bifs::FragmentingHeap(&mut self.heap);
        TermBuilder::new(&mut heap)
            .tuple(elements)
            .map_err(|error| VmError::Unsupported(format!("signal tuple: {error:?}")))
    }

    fn retire_timer_reference(&self, reference: arinsal_sched::TimerRef) -> Option<u64> {
        let runtime = self.runtime.as_ref()?;
        let mut timers = runtime.timers.lock().unwrap();
        let id = timers
            .iter()
            .find_map(|(&id, &timer)| (timer == reference).then_some(id));
        if let Some(id) = id {
            timers.remove(&id);
            runtime.timer_owners.lock().unwrap().remove(&id);
        }
        id
    }

    fn notify_exit(&mut self, vm: &mut Vm, ctx: &mut RunCtx<'_, Message>, reason: Term) {
        self.final_exit_reason = Some(reason);
        crate::trace::emit(
            Some(vm),
            self,
            ctx,
            ctx.pid(),
            crate::trace::PROCS,
            "exit",
            &[reason],
        );
        // Port of erts/emulator/beam/erl_process.c:14421-14464, OTP-29.1.1: releasing the
        // registered name is traced after the exit event.
        let registered: Vec<String> = self.runtime.as_ref().map_or_else(Vec::new, |runtime| {
            runtime
                .names
                .lock()
                .unwrap()
                .iter()
                .filter(|(_, pid)| **pid == ctx.pid())
                .map(|(name, _)| name.clone())
                .collect()
        });
        for name in registered {
            crate::trace::emit(
                Some(vm),
                self,
                ctx,
                ctx.pid(),
                crate::trace::PROCS,
                "unregister",
                &[crate::signals::atom(&name)],
            );
        }
        crate::natives::erts_debug::monitor_process_exited(self, ctx.pid());
        crate::trace::clear(self, ctx.pid());
        crate::trace::tracer_exited(self, ctx.pid());
        // Further publishes fail with `NoProcess` and the watcher synthesizes
        // DOWN. Signals already queued are installed before we notify.
        ctx.begin_exit();
        self.absorb_exit_signals(ctx);
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
        // Timers aimed at this process are canceled before its other resources.
        ctx.cancel_target_timers(ctx.pid());
        // g_proc_sched: a terminating suspender releases every suspend it acquired.
        // g_port_fix: close owned ports synchronously on the termination path.
        if let Some(runtime) = self.runtime.clone() {
            runtime.cancel_owned_timers(ctx.pid());
            crate::node_tables::lock().forget_node_monitors(ctx.pid());
            let wake = runtime.release_suspender(ctx.pid());
            for pid in wake {
                let _ = ctx.signal(pid, arinsal_sched::Signal::UnlinkAck(u64::MAX));
            }
            if let Ok(scheduler) = runtime.scheduler() {
                crate::port::owner_exit(&runtime, &scheduler, ctx.pid(), reason);
            }
            runtime.forget_process(ctx.pid());
        }
        if let (Some(runtime), Some(owner)) = (&self.runtime, ctx.pid().to_term()) {
            // Port of erts/emulator/beam/erl_db.c:5031 (erts_db_process_exiting), OTP-29.1.1.
            if runtime.ets.read().unwrap().has_fixations(owner) {
                runtime.ets.write().unwrap().release_fixations(owner);
            }
            let owned = {
                let registry = runtime.ets.read().unwrap();
                registry
                    .owned_by(owner)
                    .into_iter()
                    .filter_map(|tid| {
                        let table = registry.get(tid).ok()?;
                        let name = table.options.named_table.then_some(table.options.name);
                        Some((tid, name, table.options.heir))
                    })
                    .collect::<Vec<_>>()
            };
            for (tid, name, heir) in owned {
                // Port of erts/emulator/beam/erl_db.c:4898-4900 (give_table_to_heir),
                // OTP-29.1.1: an owner that is its own heir keeps, and so deletes, the table.
                let heir = heir.filter(|heir| heir.pid != owner);
                if let Some(heir) = heir
                    && let Some(pid) = Pid::from_term(heir.pid)
                    && !heir.transfer
                {
                    // Port of erts/emulator/beam/erl_db.c:4910-4930 (give_table_to_heir),
                    // OTP-29.1.1: `{heir, Pid}` hands the table over without a message.
                    let alive = runtime
                        .scheduler()
                        .is_ok_and(|scheduler| scheduler.lookup(pid));
                    if alive
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
                {
                    let mut heap = arinsal_term::VecHeap::new();
                    // Port of erts/emulator/beam/erl_db.c:4959-4962
                    // (send_ets_transfer_message), OTP-29.1.1.
                    let tab = match name {
                        Some(name) => Ok(Term::atom(name)),
                        None => tid.to_term(&mut heap),
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
                        if registry.give_away(tid, heir.pid).is_ok() {
                            drop(registry);
                            if ctx.send(pid, message).is_ok() {
                                continue;
                            }
                        }
                    }
                }
                let _ = runtime.ets.write().unwrap().delete(tid);
            }
        }
        if let Some(runtime) = &self.runtime {
            // Port of erts/emulator/beam/erl_process.c:14421-14464, OTP-29.1.1.
            // The registered name is the last Erlang resource released, after owned ETS tables.
            runtime
                .names
                .lock()
                .unwrap()
                .retain(|_, registered| *registered != ctx.pid());
        }
        let Some(cold) = self.cold.take() else {
            return;
        };
        for pid in cold.links {
            if self.runtime.as_ref().is_some_and(|runtime| {
                crate::dist::forward_link_exit_if_proxy(runtime, pid, ctx.pid(), reason)
            }) {
                continue;
            }
            if let Ok(message) = Message::copy_from(reason) {
                let _ = ctx.signal(pid, arinsal_sched::Signal::ExitLinked(message));
            }
        }
        for (reference, pid) in cold.monitored_by {
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
            if let Ok(message) = Message::copy_from(reason) {
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

    fn notify_exit_with_executor(&mut self, ctx: &mut RunCtx<'_, Message>, reason: Term) {
        EXECUTOR.with(|slot| {
            let mut slot = slot.borrow_mut();
            if let Some((_, executor)) = slot.as_mut() {
                self.notify_exit(&mut executor.vm, ctx, reason);
            }
        });
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
        mut vm: Option<&mut Vm>,
        mut ctx: Option<&mut RunCtx<'_, Message>>,
        target: Term,
        value: Term,
        want_priority: bool,
    ) -> Result<Term, VmError> {
        let sender = self
            .self_pid
            .ok_or_else(|| VmError::Unsupported("send requires a scheduled process".into()))?;
        if target.as_port().is_some() {
            crate::port::send_message(self, target, value)?;
            return Ok(value);
        }
        // Port of erts/emulator/beam/erl_message.c (`erts_send` / remote_send), OTP-29.1.1.
        let remote = match ctx.as_deref_mut() {
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
        let target = if let Some(name) = crate::dist::local_reg_name(target)? {
            name
        } else {
            target
        };
        if let Some(name) = target
            .as_atom()
            .and_then(|name| arinsal_term::global_atoms().text(name))
            && let Some(id) = self
                .runtime
                .as_ref()
                .and_then(|runtime| runtime.port_names.lock().unwrap().get(name).copied())
            && crate::port::is_live(self, id)
        {
            let port = Term::port(id).ok_or_else(|| {
                VmError::Trap(crate::exceptions::Trap::error(crate::signals::atom(
                    "badarg",
                )))
            })?;
            crate::port::send_message(self, port, value)?;
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
        let mut via_prio_alias = false;
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
                    Some(pid)
                }
                Some((None, _)) => return Ok(value),
                None => {
                    return Err(VmError::Trap(crate::exceptions::Trap::error(
                        crate::signals::atom("badarg"),
                    )));
                }
            }
        } else if let Some(atom) = target.as_atom() {
            let name = arinsal_term::global_atoms()
                .text(atom)
                .ok_or_else(|| VmError::Unsupported("unbound destination atom".into()))?;
            let runtime = self
                .runtime
                .as_ref()
                .ok_or_else(|| VmError::Unsupported("send requires a scheduler".into()))?;
            let mut names = runtime.names.lock().unwrap();
            let pid = names.get(name).copied();
            let pid = if let Some(pid) = pid
                && !runtime.scheduler()?.lookup(pid)
            {
                names.remove(name);
                None
            } else {
                pid
            };
            drop(names);
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
        let event = if crate::trace::active()
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
        self.trace_send(
            vm.as_deref_mut(),
            ctx.as_deref_mut(),
            sender,
            event,
            value,
            target,
        );
        let mut envelope = Message::copy_from(value)?;
        if via_prio_alias {
            envelope = envelope.with_priority();
        }
        if crate::seq_trace::has_token(self)
            && let Some(token) =
                crate::seq_trace::on_send(vm, self, ctx.as_deref_mut(), sender, target, value)
        {
            envelope.attach_seq_token(token);
        }
        let delivered = match ctx {
            Some(ctx) => ctx.send(pid, envelope),
            None => self
                .runtime
                .as_ref()
                .ok_or_else(|| VmError::Unsupported("send requires a scheduler".into()))?
                .scheduler()?
                .send(sender, pid, envelope),
        };
        match delivered {
            Ok(()) | Err(arinsal_sched::Error::NoProcess) => Ok(value),
            Err(error) => Err(VmError::Unsupported(format!("send: {error}"))),
        }
    }

    pub(crate) fn drain(&mut self, ctx: &mut RunCtx<'_, Message>) -> Result<(), VmError> {
        self.drain_until_marker(ctx, None)
    }

    /// Fetch every event before a reserved marker into the VM-owned mailbox.
    pub(crate) fn drain_before_marker(
        &mut self,
        ctx: &mut RunCtx<'_, Message>,
        marker: ReceiveMarker,
    ) -> Result<(), VmError> {
        self.drain_until_marker(ctx, Some(marker))
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

    fn drain_until_marker(
        &mut self,
        ctx: &mut RunCtx<'_, Message>,
        marker: Option<ReceiveMarker>,
    ) -> Result<(), VmError> {
        // Port of erts/emulator/beam/erl_proc_sig_queue.c:6032 (private queue fetch), OTP-29.1.1.
        ctx.fetch_pending();
        if self.gc_enabled
            && self
                .cold
                .as_ref()
                .is_some_and(|cold| !cold.delayed_gc.is_empty())
        {
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
        let mut queue_data = None;
        loop {
            if marker.is_some_and(|marker| !ctx.recv_marker_has_saved_before(marker)) {
                break;
            }
            let Some(Event { from, payload }) = ctx.receive_saved() else {
                break;
            };
            match payload {
                Payload::Message(message) => {
                    let data = *queue_data.get_or_insert_with(|| self.message_queue_data());
                    let priority = message.is_priority();
                    let old_prio_len = self.cold.as_ref().map_or(0, |cold| cold.prio_len);
                    let sender = from;
                    let new_prio_len =
                        self.inbox
                            .push_message(message, data, &mut self.heap, old_prio_len)?;
                    let trace_index = if priority {
                        old_prio_len
                    } else {
                        self.inbox.len().saturating_sub(1)
                    };
                    if let Some(term) = self.inbox.get(trace_index).copied()
                        && crate::trace::flags(self, ctx.pid()) & crate::trace::RECEIVE != 0
                    {
                        crate::trace::receive_event(None, self, ctx, term, Some(sender));
                    }
                    self.cold_mut().prio_len = new_prio_len;
                    if priority {
                        let priority_term =
                            self.inbox.get(old_prio_len).copied().ok_or_else(|| {
                                VmError::Unsupported(
                                    "priority message missing after insertion".into(),
                                )
                            })?;
                        self.priority_item_inserted(old_prio_len, priority_term)?;
                    }
                }
                Payload::TimerMessage { reference, message } => {
                    self.retire_timer_reference(reference);
                    let data = *queue_data.get_or_insert_with(|| self.message_queue_data());
                    let priority = message.is_priority();
                    let old_prio_len = self.cold.as_ref().map_or(0, |cold| cold.prio_len);
                    let new_prio_len =
                        self.inbox
                            .push_message(message, data, &mut self.heap, old_prio_len)?;
                    self.cold_mut().prio_len = new_prio_len;
                    if priority {
                        let priority_term =
                            self.inbox.get(old_prio_len).copied().ok_or_else(|| {
                                VmError::Unsupported(
                                    "priority message missing after insertion".into(),
                                )
                            })?;
                        self.priority_item_inserted(old_prio_len, priority_term)?;
                    }
                }
                Payload::Signal(arinsal_sched::Signal::Link) => {
                    self.cold_mut().links.insert(from);
                    if let Some(linker) = from.to_term() {
                        // Port of erts/emulator/beam/erl_proc_sig_queue.c:8585-8589, OTP-29.1.1.
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
                // Port of erl_bif_info.c:4998-5022 (proc_sig_block), OTP-29.1.1.
                Payload::Signal(arinsal_sched::Signal::ProcSigBlock(milliseconds)) => {
                    if milliseconds > 0 {
                        std::thread::sleep(std::time::Duration::from_millis(milliseconds as u64));
                    }
                }
                Payload::Signal(arinsal_sched::Signal::Unlink(_)) => {
                    if let Some(cold) = self.cold.as_mut() {
                        cold.links.remove(&from);
                        cold.prio_links.remove(&from);
                    }
                    self.trace_getting_unlinked(ctx, from);
                }
                Payload::Signal(arinsal_sched::Signal::Monitor(reference)) => {
                    self.cold_mut().monitored_by.insert(reference, from);
                }
                Payload::Signal(arinsal_sched::Signal::Demonitor(reference)) => {
                    if let Some(cold) = self.cold.as_mut() {
                        cold.monitored_by.remove(&reference);
                    }
                }
                Payload::Signal(
                    signal
                    @ (arinsal_sched::Signal::Exit(_) | arinsal_sched::Signal::ExitLinked(_)),
                ) => {
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
                            .is_some_and(|cold| cold.prio_links.contains(&from));
                    let was_linked = linked_exit
                        && self.cold.as_mut().is_some_and(|cold| {
                            cold.prio_links.remove(&from);
                            cold.links.remove(&from)
                        });
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
                            .ok_or_else(|| {
                                VmError::Unsupported("invalid signal sender pid".into())
                            })?;
                        let tuple = self.tuple(&[crate::signals::atom("EXIT"), from, reason])?;
                        if priority {
                            self.push_priority_message(tuple)?;
                        } else {
                            self.inbox.push_back(tuple);
                        }
                        self.trace_converted_signal(ctx, tuple, sender);
                        if was_linked {
                            self.trace_getting_unlinked(ctx, sender);
                        }
                        continue;
                    }
                    if reason != Term::atom(arinsal_term::atoms::NORMAL) {
                        self.note_exit_reason(reason)?;
                        return Err(VmError::Trap(crate::exceptions::Trap::exit(reason)));
                    }
                    if was_linked {
                        self.trace_getting_unlinked(ctx, from);
                    }
                }
                // Port of erts/emulator/beam/io.c:3841-3891 (erts_deliver_port_exit), OTP-29.1.1.
                Payload::Signal(arinsal_sched::Signal::PortExit { port, reason }) => {
                    let port = port.into_receiver(self)?;
                    let reason = reason.into_receiver(self)?;
                    if reason == crate::signals::atom("kill") {
                        return Err(VmError::Trap(crate::exceptions::Trap::killed()));
                    }
                    if self.trap_exit {
                        let tuple = self.tuple(&[crate::signals::atom("EXIT"), port, reason])?;
                        self.inbox.push_back(tuple);
                        continue;
                    }
                    if reason != Term::atom(arinsal_term::atoms::NORMAL) {
                        self.note_exit_reason(reason)?;
                        return Err(VmError::Trap(crate::exceptions::Trap::exit(reason)));
                    }
                }
                Payload::Signal(arinsal_sched::Signal::MonitorNoproc(reference)) => {
                    let queued = self.inbox.len();
                    self.deliver_monitor_down(from, reference, crate::signals::atom("noproc"))?;
                    self.trace_new_message(ctx, queued, from);
                }
                Payload::Signal(arinsal_sched::Signal::MonitorDown { reference, reason }) => {
                    let reason = reason.into_receiver(self)?;
                    let queued = self.inbox.len();
                    self.deliver_monitor_down(from, reference, reason)?;
                    self.trace_new_message(ctx, queued, from);
                }
                Payload::Timer { reference, message } => {
                    let timer_id = message.timer_id;
                    let term = message.into_receiver(self)?;
                    let retired = self.retire_timer_reference(reference);
                    let id = timer_id.or(retired).unwrap_or(reference.id());
                    let reference = crate::signals::reference(self, id)?;
                    let tuple = self.tuple(&[crate::signals::atom("timeout"), reference, term])?;
                    self.inbox.push_back(tuple);
                    self.trace_converted_signal(ctx, tuple, from);
                }
                Payload::Signal(arinsal_sched::Signal::UnlinkAck(id)) => {
                    // Port of erts/emulator/beam/erl_proc_sig_queue.c:6794
                    // (ERTS_SIG_Q_OP_PROCESS_INFO), OTP-29.1.1.
                    // The scheduler signal enum has no request op; a nonzero
                    // unlink-ack id is the wakeup for a queued request.
                    if id != 0 {
                        crate::signals::handle_request(self, ctx, id)?;
                    }
                }
                Payload::Signal(arinsal_sched::Signal::Alias(_))
                | Payload::Signal(arinsal_sched::Signal::Unalias(_)) => {
                    return Err(VmError::Unsupported("process aliases".into()));
                }
                Payload::Signal(arinsal_sched::Signal::GarbageCollect) => {
                    if self.gc_enabled {
                        self.force_gc()?;
                    } else {
                        self.cold_mut()
                            .delayed_gc
                            .push(crate::proc_create::DelayedGc::Collect);
                    }
                }
                Payload::Signal(arinsal_sched::Signal::LiteralAreaCopy {
                    area_id,
                    request,
                    how,
                    requester,
                }) => {
                    if !self.gc_enabled && how != arinsal_sched::LiteralCopyHow::Init {
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
                }
            }
        }
        crate::natives::erts_debug::after_message_queue_change(self);
        Ok(())
    }
}

impl Process {
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
    pub(crate) fn handle_dirty_signals(&mut self, vm: &mut Vm, ctx: &mut RunCtx<'_, Message>) {
        if self.dirty_exiting() {
            return;
        }
        let gc = self.set_gc_enabled(false);
        let result = self.drain(ctx);
        self.set_gc_enabled(gc);
        if let Err(error) = result {
            // Port of erts/emulator/beam/erl_process.c:10096 (need_forced_exit), OTP-29.1.1:
            // an exiting process is terminated while its dirty job keeps running.
            self.set_dirty_exited();
            crate::signals::process_exiting(self, ctx);
            if let Some(runtime) = self.runtime.clone() {
                runtime.processes.lock().unwrap().remove(&ctx.pid());
            }
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
    }

    /// Whether this process already exited while executing a dirty job.
    pub(crate) fn dirty_exiting(&self) -> bool {
        self.cold.as_ref().is_some_and(|cold| cold.dirty_exited)
    }

    /// Set this process's `F_DISABLE_GC` equivalent and return its previous state.
    /// Port of erts/emulator/beam/erl_process.c:11823 (`erts_set_gc_state`), OTP-29.1.1.
    pub(crate) fn set_gc_enabled(&mut self, enabled: bool) -> bool {
        let previous = self.gc_enabled;
        self.gc_enabled = enabled;
        previous
    }

    /// Collect after a BIF whose heap fragments outgrew the free young area.
    /// Port of erts/emulator/beam/erl_gc.c:418 (`erts_gc_after_bif_call_lhf`), OTP-29.1.1:
    /// the BIF result is the only live register.
    #[inline]
    pub(crate) fn gc_after_bif(&mut self, result: Term) -> Result<Term, VmError> {
        // ERTS_IS_GC_AFTER_BIF_DESIRED: heap fragments or a virtual binary heap over its size;
        // `F_DISABLE_GC` returns before any collection (erl_gc.c:403-415).
        if !(self.heap.gc_desired() || self.heap.bin_vheap_gc_due()) || !self.gc_enabled {
            return Ok(result);
        }
        let mut roots = [result];
        let gc = self.collect_heap_roots(0, &mut roots, 0)?;
        crate::natives::sys::after_collection(self, 0, gc.collections, gc.words_reclaimed);
        // Only X0 survives a call; the dead registers now point into the freed heap and
        // must not be scanned by later literal-area or root walks.
        self.x[1..].fill(Term::NIL);
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
        if !self.gc_enabled {
            self.gc_deferred = true;
            return Ok(());
        }
        let live = live.min(self.x.len());
        let gc = self.collect_heap_roots(live, &mut [], 0)?;
        crate::natives::sys::after_collection(self, live, gc.collections, gc.words_reclaimed);
        Ok(())
    }

    pub(crate) fn service_deferred_gc(&mut self) -> Result<(), VmError> {
        if self.gc_enabled && std::mem::take(&mut self.gc_deferred) {
            self.collect_heap_roots(self.gc_live, &mut [], 0)?;
        }
        Ok(())
    }

    /// Emit a `garbage_collection` trace event with the GC info list and `{wordsize, Size}`.
    /// Port of erts/emulator/beam/erl_trace.c:1439 (`trace_gc`), OTP-29.1.1.
    fn trace_gc(&mut self, pid: arinsal_sched::Pid, tag: &str, size: usize) {
        let entries = [
            ("heap_block_size", self.heap.capacity_words()),
            ("heap_size", self.heap.heap_size_words()),
            ("old_heap_size", self.heap.old_used_words()),
            ("stack_size", self.heap.stack_words()),
            ("wordsize", size),
        ];
        let mut tuples = Vec::with_capacity(entries.len());
        for (name, value) in entries {
            let Some(value) = Term::small(value as i64) else {
                return;
            };
            let Ok(tuple) =
                TermBuilder::new(&mut self.heap).tuple(&[crate::signals::atom(name), value])
            else {
                return;
            };
            tuples.push(tuple);
        }
        let Ok(info) = TermBuilder::new(&mut self.heap).list_from_iter(tuples) else {
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

    fn collect_roots(
        &mut self,
        live_x: usize,
        extra: &mut [Term],
        min_free: usize,
        hibernate: bool,
    ) -> Result<arinsal_term::GcStats, VmError> {
        // Port of erts/emulator/beam/erl_gc.c:3730 (`has_reached_max_heap_size`) call in
        // `garbage_collect`, OTP-29.1.1: the limit is judged on the pre-collection size.
        if self
            .runtime
            .as_ref()
            .is_some_and(|runtime| runtime.ever_max_heap.load(Ordering::Acquire))
        {
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
        if let Some(cold) = self.cold.as_mut() {
            roots.extend_from_slice(&cold.apply_roots);
            if let Some(pending) = cold.nif_pending.as_mut() {
                roots.extend_from_slice(pending.roots_mut());
            }
        }
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
        let stats = if hibernate {
            self.heap
                .collect_hibernate(&mut self.x[..live_x], &mut roots)
        } else {
            self.heap
                .collect(&mut self.x[..live_x], &mut roots, min_free)
        }
        .map_err(|error| VmError::Unsupported(format!("process GC: {error:?}")))?;
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
        if let Some(cold) = self.cold.as_mut() {
            let apply_end = extra_end + cold.apply_roots.len();
            cold.apply_roots
                .copy_from_slice(&roots[extra_end..apply_end]);
            if let Some(pending) = cold.nif_pending.as_mut() {
                pending.roots_mut().copy_from_slice(&roots[apply_end..]);
            }
        }
        if self.max_heap_peak != 0
            || self
                .runtime
                .as_ref()
                .is_some_and(|runtime| runtime.ever_max_heap.load(Ordering::Acquire))
        {
            self.max_heap_peak = self.max_heap_peak.max(self.heap.total_heap_size_words());
        }
        crate::natives::erts_debug::after_collection(self, stats.nanoseconds);
        Ok(stats)
    }

    /// Collect after a BIF left heap fragments larger than the free area or pushed the
    /// virtual binary heap over its limit.
    // Port of erts/emulator/beam/erl_gc.h:132-139 (ERTS_IS_GC_DESIRED), OTP-29.1.1.
    pub(crate) fn collect_bin_vheap_if_due(&mut self, live_x: usize) -> Result<(), VmError> {
        if !(self.heap.gc_desired() || self.heap.bin_vheap_gc_due()) || !self.gc_enabled {
            return Ok(());
        }
        let mut result = [self.x[0]];
        let stats = self.collect_heap_roots(live_x, &mut result, 0)?;
        self.x[0] = result[0];
        crate::natives::sys::after_collection(
            self,
            live_x,
            stats.collections,
            stats.words_reclaimed,
        );
        Ok(())
    }

    // Port of erts/emulator/beam/beam_bif_load.c:1149 (check_process_code), OTP-29.1.1.
    // A process suspended in native code is checked by its native resume address and the
    // native continuation pointers on its stack; `self.module` is only its interpreter module.
    pub(crate) fn references_code(&self, module: usize, native: Option<(usize, usize)>) -> bool {
        let in_native =
            |address: usize| native.is_some_and(|(start, end)| start <= address && address < end);
        // While native code runs (a signal handled from a runtime helper), `self.module` is
        // stale and the running function shows up through the native stack instead.
        match self.native_pc {
            Some(pc) if in_native(pc) => return true,
            None if self.module == module && !self.heap.native_active() => return true,
            _ => {}
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
            if in_native(term.tagged_word() as usize) {
                return true;
            }
        }
        false
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
        let active = self
            .cold
            .as_mut()
            .is_some_and(|cold| cold.monitors.remove(&reference).is_some())
            || crate::dist::take_monitor(reference).is_some();
        let tag_owned = self
            .cold
            .as_mut()
            .and_then(|cold| cold.monitor_tags.remove(&reference));
        let priority = self
            .cold
            .as_mut()
            .is_some_and(|cold| cold.prio_monitors.remove(&reference));
        if !active {
            return Ok(());
        }
        let tag = if let Some(owned) = tag_owned {
            let mut heap = arinsal_bifs::FragmentingHeap(&mut self.heap);
            arinsal_term::from_owned(&owned, &mut heap)
                .map_err(|error| VmError::Unsupported(format!("monitor tag: {error:?}")))?
        } else {
            crate::signals::atom("DOWN")
        };
        if let Some(cold) = self.cold.as_mut() {
            cold.monitors.remove(&reference);
        }
        let name = self
            .cold
            .as_mut()
            .and_then(|cold| cold.monitor_names.remove(&reference));
        let reference = crate::signals::reference(self, reference)?;
        let from = crate::dist::remote_pid_term(self, from)?
            .or_else(|| from.to_term())
            .ok_or_else(|| VmError::Unsupported("invalid monitor sender pid".into()))?;
        let from = crate::signals::monitor_object(self, name.as_deref(), from)?;
        let tuple = self.tuple(&[
            tag,
            reference,
            crate::signals::atom("process"),
            from,
            reason,
        ])?;
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
fn report_process_error(process: &mut Process, ctx: &mut RunCtx<'_, Message>, reason: Term) {
    let Some(runtime) = process.runtime.clone() else {
        return;
    };
    let logger = {
        let names = runtime.names.lock().unwrap();
        names
            .get("logger")
            .or_else(|| names.get("error_logger"))
            .copied()
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
        let mut heap = arinsal_bifs::FragmentingHeap(&mut process.heap);
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
            .cold
            .as_ref()
            .and_then(|cold| cold.group_leader)
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

impl Task for Process {
    type Message = Message;

    fn gc_nanoseconds(&self) -> u64 {
        self.stats.gc.nanoseconds
    }

    fn run(&mut self, ctx: &mut RunCtx<'_, Message>, budget: u32) -> RunOutcome {
        let outcome = abort_on_worker_panic(|| self.run_task(ctx, budget));
        if matches!(outcome, RunOutcome::Exit(_)) {
            self._persistent_terms
                .store()
                .process_exited(&self._persistent_terms);
            // Port of erts/emulator/beam/erl_process.c (erts_continue_exit_process): the exited
            // process frees its heap and off-heap list, dropping its refc binary references.
            self.heap = ProcessHeap::new();
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
        Process::take_dirty_job(self, kind)
    }

    fn finish_dirty_job(&mut self, result: Box<dyn std::any::Any>) {
        Process::finish_dirty_job(self, result);
    }

    fn reap_signals(&mut self, pid: Pid, events: Vec<Event<Message>>) {
        let mut monitors = Vec::new();
        let mut links = Vec::new();
        let mut literal_replies = Vec::new();
        for event in events {
            match event.payload {
                Payload::Signal(Signal::Monitor(reference)) => {
                    monitors.push((reference, event.from));
                }
                // Port of erts/emulator/beam/erl_proc_sig_queue.c:7426 (erts_proc_exit_handle_signal),
                // OTP-29.1.1: a link that reaches a process after its exit handling gets `noproc`.
                Payload::Signal(Signal::Link) => links.push(event.from),
                Payload::Signal(Signal::Unlink(_)) => links.retain(|from| *from != event.from),
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
        if monitors.is_empty() && literal_replies.is_empty() && links.is_empty() {
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
        for linker in links {
            if let Ok(reason) = Message::copy_from(crate::signals::atom("noproc")) {
                let _ = scheduler.signal(pid, linker, Signal::Exit(reason));
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
    fn run_task(&mut self, ctx: &mut RunCtx<'_, Message>, budget: u32) -> RunOutcome {
        let Some(runtime) = self.runtime.clone() else {
            return RunOutcome::Exit(1);
        };
        if !self.cold_mut().profile_active {
            crate::natives::misc::profile_process_event(self, ctx, true);
            self.cold_mut().profile_active = true;
        }
        if self.dirty_exiting() {
            // Exited by a dirty signal handler while queued for a dirty scheduler.
            return RunOutcome::Exit(1);
        }
        let result = self.run_executor(&runtime, ctx, budget);
        if self.dirty_exiting() {
            // Port of erts/emulator/beam/erl_process.c:10096 (need_forced_exit), OTP-29.1.1:
            // the process already terminated while the job ran; whatever the job returned,
            // only the process structure remains to be released.
            return RunOutcome::Exit(1);
        }
        self.finish_run(runtime, ctx, result)
    }

    fn run_executor(
        &mut self,
        runtime: &Arc<Runtime>,
        ctx: &mut RunCtx<'_, Message>,
        budget: u32,
    ) -> Result<RunState, VmError> {
        let result = EXECUTOR.with(|slot| {
            let mut slot = slot.borrow_mut();
            let key = Arc::as_ptr(runtime) as usize;
            let replace = slot.as_ref().is_none_or(|(cached_key, executor)| {
                *cached_key != key || executor.owner.strong_count() == 0
            });
            if replace {
                *slot = Some((
                    key,
                    Executor {
                        owner: Arc::downgrade(runtime),
                        vm: Vm::shared_replica(Arc::clone(&runtime.code), &runtime.paths),
                        x: Box::new([]),
                        fr: Box::new([]),
                        native_registers: SchedulerRegisters::default(),
                    },
                ));
            }
            slot.as_mut()
                .expect("executor slot initialized")
                .1
                .run(self, ctx, budget)
        });
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
        runtime: Arc<Runtime>,
        ctx: &mut RunCtx<'_, Message>,
        result: Result<RunState, VmError>,
    ) -> RunOutcome {
        if matches!(&result, Ok(RunState::Wait { .. } | RunState::Done(_)))
            && self.cold_mut().profile_active
        {
            crate::natives::misc::profile_process_event(self, ctx, false);
            self.cold_mut().profile_active = false;
        }
        // g_proc_sched. Port of erts/emulator/beam/erl_gc.c:1197 (max_heap_size kill), OTP-29.1.1.
        if result.is_ok() && heap_limit_kills(self, ctx) {
            runtime.processes.lock().unwrap().remove(&ctx.pid());
            self.notify_exit_with_executor(ctx, crate::signals::atom("killed"));
            if self.entry {
                let _ = runtime
                    .result
                    .send(Err(VmError::Unsupported("max_heap_size".into())));
            }
            return RunOutcome::Exit(1);
        }
        runtime.note_relations(ctx.pid(), self.cold.as_deref());
        let parked = self
            .cold
            .as_mut()
            .is_some_and(|cold| std::mem::take(&mut cold.suspend_parked));
        match result {
            Ok(RunState::Yield) => {
                runtime.note_status(ctx.pid(), "runnable");
                RunOutcome::Yield
            }
            Ok(RunState::Wait { timeout_ms }) => {
                // Port of erts/emulator/beam/erl_process.c:9304 (erts_process_state2status),
                // OTP-29.1.1: suspension keeps ERTS_PSFLG_ACTIVE, so a process resumed while
                // this slice ended is runnable, not waiting.
                runtime.note_status(ctx.pid(), if parked { "runnable" } else { "waiting" });
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
                runtime.processes.lock().unwrap().remove(&ctx.pid());
                self.notify_exit_with_executor(ctx, crate::signals::atom("normal"));
                if self.entry {
                    self.stats.heap_words = self.heap.capacity_words();
                    let owned = arinsal_term::to_owned(term).map_err(|error| {
                        VmError::Unsupported(format!("result conversion: {error:?}"))
                    });
                    let result = owned.map(|term_owned| ScheduledResult {
                        text: format!("{term_owned}"),
                        term: term_owned,
                        stats: self.stats.snapshot(),
                    });
                    let _ = runtime.result.send(result);
                }
                RunOutcome::Exit(0)
            }
            Err(error) => {
                if matches!(error, VmError::Yield) {
                    runtime.note_status(ctx.pid(), "runnable");
                    return RunOutcome::Yield;
                }
                if let VmError::Dirty(kind) = error {
                    runtime.note_status(ctx.pid(), "runnable");
                    return RunOutcome::Dirty(kind);
                }
                let reason = exit_reason_from(self, &error);
                if matches!(&error, VmError::Raised(raised) if raised.class == arinsal_bifs::Class::Error)
                {
                    report_process_error(self, ctx, reason);
                }
                crate::signals::process_exiting(self, ctx);
                runtime.processes.lock().unwrap().remove(&ctx.pid());
                if trace_boot_enabled() {
                    eprintln!("arinsal boot: process {:?} exited: {error}", ctx.pid());
                }
                self.notify_exit_with_executor(ctx, reason);
                if self.entry {
                    let _ = runtime.result.send(Err(error));
                }
                RunOutcome::Exit(1)
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
        {
            // Executors already running system processes spawned earlier keep the epoch
            // counter they were created with; a fresh counter would leave them comparing
            // against a dead one and re-synchronizing (and copying tables) on every load.
            let mut code = runtime.code.lock().unwrap();
            let epoch = Arc::clone(&code.epoch);
            *code = self.snapshot_shared();
            epoch.fetch_add(1, Ordering::AcqRel);
            code.epoch = epoch;
        }
        let ip = self.modules[module_id]
            .export(function, 0)
            .ok_or_else(|| VmError::Load(format!("{module}:{function}/0 is not exported")))?;
        let mut process = Process::with_spawn_registers(0, 0);
        process.module = module_id;
        process.ip = ip;
        process.initial_call = Some((module_id, ip));
        process.set_runtime(Some(Arc::clone(runtime)));
        process.cold_mut().initial_call = Some((module.to_owned(), function.to_owned(), 0));
        if priority != arinsal_sched::Priority::Normal {
            let name = match priority {
                arinsal_sched::Priority::Max => "max",
                arinsal_sched::Priority::High => "high",
                arinsal_sched::Priority::Normal => "normal",
                arinsal_sched::Priority::Low => "low",
            };
            crate::natives::proc::set_flag(&mut process, "priority", crate::signals::atom(name));
        }
        let pid = scheduler
            .spawn_priority(process, priority)
            .map_err(|error| VmError::Unsupported(format!("system process {module}: {error}")))?;
        runtime.processes.lock().unwrap().insert(pid);
        runtime.system_processes.lock().unwrap().insert(pid);
        Ok(pid)
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
        initialize_feature_defaults(arinsal_pterm::store_for(self.code_scope))?;
        let module_id = self.load_named(module)?;
        let ip = self.modules[module_id]
            .export(function, args.len() as u8)
            .ok_or_else(|| {
                VmError::Trap(crate::exceptions::Trap::error(crate::signals::atom(
                    "undef",
                )))
            })?;
        let (sender, receiver) = mpsc::channel();
        let code = Arc::new(Mutex::new(self.snapshot_shared()));
        let runtime = Arc::new(Runtime {
            code: Arc::clone(&code),
            code_scope: self.code_scope,
            processes: Mutex::new(std::collections::HashSet::new()),
            system_processes: Mutex::new(std::collections::HashSet::new()),
            otp_root: self.otp_root.clone(),
            dirty_signal_handlers: Mutex::new(std::collections::HashSet::new()),
            literal_collector: Mutex::new(None),
            paths: self.paths.clone(),
            scheduler: Mutex::new(Weak::new()),
            names: Mutex::new(HashMap::new()),
            port_names: Mutex::new(HashMap::new()),
            aliases: AliasTable::new(),
            timers: Mutex::new(HashMap::new()),
            timer_owners: Mutex::new(HashMap::new()),
            next_trace_weak_id: AtomicU64::new(0),
            ports: Mutex::new(HashMap::new()),
            system_monitor: Mutex::new(None),
            session_monitors: Mutex::new(Vec::new()),
            system_monitor_flags: AtomicU8::new(0),
            long_message_queues: Mutex::new(HashSet::new()),
            next_port: AtomicU64::new(16),
            simulated: simulation_seed.is_some(),
            virtual_ms: AtomicU64::new(0),
            ets: std::sync::RwLock::new(arinsal_ets::Registry::new()),
            result: sender,
            suspend_counts: Mutex::new(HashMap::new()),
            suspend_outstanding: Mutex::new(HashMap::new()),
            suspend_total: Mutex::new(HashMap::new()),
            ever_suspended: AtomicBool::new(false),
            pauses: Mutex::new(HashMap::new()),
            published: Mutex::new(HashMap::new()),
            hibernating: Mutex::new(HashMap::new()),
            ever_hibernated: AtomicBool::new(false),
            max_heaps: Mutex::new(HashMap::new()),
            ever_max_heap: AtomicBool::new(false),
            debug_wait_active: AtomicBool::new(false),
            multi_scheduling: Mutex::new(MultiScheduling::default()),
        });
        let (dirty_cpu_schedulers, dirty_cpu_online, dirty_io_schedulers) =
            crate::natives::sys::dirty_scheduler_defaults();
        let config = Config {
            workers,
            reductions: reductions.max(1),
            dirty_cpu_schedulers,
            dirty_io_schedulers,
            ..Config::default()
        };
        let scheduler = Arc::new(match simulation_seed {
            Some(seed) => Scheduler::simulation(config, seed),
            None => Scheduler::new(config),
        });
        let online = crate::natives::sys::scheduler_online_default();
        let _ = scheduler.set_online_schedulers(online.min(workers.max(1)));
        let _ = scheduler.set_dirty_cpu_online(dirty_cpu_online);
        *runtime.scheduler.lock().unwrap() = Arc::downgrade(&scheduler);
        if module == "erl_init" && function == "start" {
            // Port of erts/emulator/beam/erl_init.c:2550 (erl_system_process_otp
            // "erts_code_purger"), OTP-29.1.1. code_server:finish_on_load sends
            // to this registered process; without it the send is badarg and
            // code_server dies during ensure_loaded of an on_load module.
            self.spawn_system_process(&scheduler, &runtime, "erts_code_purger", "start")?;
        }
        // Port of erts/emulator/beam/erl_init.c system-process startup: every
        // runtime needs the preloaded owner of the literal-area release protocol.
        let literal_collector = self.spawn_system_process(
            &scheduler,
            &runtime,
            "erts_literal_area_collector",
            "start",
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
        let mut process = Process::with_spawn_registers(args.len(), 0);
        process.module = module_id;
        process.ip = ip;
        process.x[..args.len()].copy_from_slice(args);
        process.set_runtime(Some(runtime.clone()));
        process.cold_mut().initial_call =
            Some((module.to_owned(), function.to_owned(), args.len() as u8));
        process.entry = true;
        process.heap.set_min_heap_size(8192);
        let _entry_pid: Pid = scheduler
            .spawn(process)
            .map_err(|error| VmError::Unsupported(format!("spawn: {error}")))?;
        runtime.processes.lock().unwrap().insert(_entry_pid);
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
        let shared = code.lock().unwrap();
        self.sync_shared(&shared);
        result
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

#[cfg(test)]
mod layout_tests {
    use super::{Message, MessageQueueData, Process, ProcessHeap, Term, TermBuilder};

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
        let heap_words = process.heap.total_heap_size_words();
        let prio_len = 0;
        process
            .inbox
            .push_message(
                envelope(),
                MessageQueueData::OffHeap,
                &mut process.heap,
                prio_len,
            )
            .unwrap();

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
        process
            .inbox
            .push_message(
                envelope(),
                MessageQueueData::OnHeap,
                &mut process.heap,
                prio_len,
            )
            .unwrap();

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
