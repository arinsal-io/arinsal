//! Scheduler adapter and message envelopes for BEAM processes.

use crate::{Process, RunState, SharedCode, Vm, VmError};
use arinsal_beam::{BeamFile, Operand};
use arinsal_beamasm::SchedulerRegisters;
use arinsal_sched::{
    Config, Event, Payload, Pid, ReceiveMarker, RunCtx, RunOutcome, Scheduler, Signal, Task,
};
use arinsal_spec::Opcode;
use arinsal_term::{ProcessHeap, Term, TermBuilder, copy_term, size_object};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak, mpsc};

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
                    copy_term(message.term, &mut target).map_err(|error| {
                        VmError::Unsupported(format!("on-heap message copy: {error:?}"))
                    })?
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
    /// Copy the reachable object graph into an envelope owned by the receiver.
    pub fn copy_from(term: Term) -> Result<Self, VmError> {
        if !term.is_pointer() {
            return Ok(Self {
                term,
                fragment: None,
                priority: false,
            });
        }
        // Port of erts/emulator/beam/erl_message.c:824 (erts_send_message),
        // OTP-29.1.1. Exact sizing keeps unused words out of long-lived
        // message fragments.
        let words = size_object(term);
        if words == 0 {
            return Ok(Self {
                term,
                fragment: None,
                priority: false,
            });
        }
        let mut fragment = ProcessHeap::with_words(words);
        let term = copy_term(term, &mut fragment)
            .map_err(|error| VmError::Unsupported(format!("message copy: {error:?}")))?;
        Ok(Self {
            term,
            fragment: Some(Box::new(MessageFragment {
                heap: Some(fragment),
                seq_token: None,
            })),
            priority: false,
        })
    }

    /// Mark this envelope for priority insertion at the receiver.
    pub(crate) fn with_priority(mut self) -> Self {
        self.priority = true;
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
                copy_term(self.term, &mut heap)
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
    pub(crate) processes: Mutex<std::collections::HashSet<Pid>>,
    pub(crate) system_processes: Mutex<std::collections::HashSet<Pid>>,
    paths: Vec<std::path::PathBuf>,
    scheduler: Mutex<Weak<Scheduler<Process>>>,
    pub(crate) names: Mutex<HashMap<String, Pid>>,
    aliases: AliasTable,
    pub(crate) timers: Mutex<HashMap<u64, arinsal_sched::TimerRef>>,
    pub(crate) ports: Mutex<HashMap<u64, Arc<crate::port::PortHandle>>>,
    pub(crate) system_monitor: Mutex<Option<crate::natives::erts_debug::SystemMonitorState>>,
    pub(crate) system_monitor_flags: AtomicU8,
    pub(crate) long_message_queues: Mutex<HashSet<Pid>>,
    pub(crate) next_port: AtomicU64,
    pub(crate) simulated: bool,
    pub(crate) virtual_ms: AtomicU64,
    pub(crate) ets: Mutex<arinsal_ets::Registry>,
    result: mpsc::Sender<Result<ScheduledResult, VmError>>,
    // g_proc_sched: suspend counts and the status other processes can observe.
    pub(crate) suspend_counts: Mutex<HashMap<(Pid, Pid), u32>>,
    pub(crate) suspend_total: Mutex<HashMap<Pid, u32>>,
    pub(crate) ever_suspended: AtomicBool,
    pub(crate) published: Mutex<HashMap<Pid, Published>>,
    pub(crate) hibernating: Mutex<HashMap<Pid, HibernateCont>>,
    pub(crate) ever_hibernated: AtomicBool,
    pub(crate) max_heaps: Mutex<HashMap<Pid, MaxHeap>>,
    pub(crate) ever_max_heap: AtomicBool,
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

/// Saved `apply(M, F, A)` arguments for a hibernating process.
///
/// g_proc_sched. Port of erts/emulator/beam/beam_common.c:1568 (`erts_hibernate`), OTP-29.1.1.
pub(crate) struct HibernateCont {
    pub module: Term,
    pub function: Term,
    pub args: Term,
    pub heap: arinsal_term::VecHeap,
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
impl Executor {
    fn run(
        &mut self,
        process: &mut Process,
        ctx: &mut RunCtx<'_, Message>,
        budget: u32,
    ) -> Result<RunState, VmError> {
        process.header.self_pid = ctx.pid().to_term().expect("valid pid").tagged_word();
        let schedule_started = std::time::Instant::now();
        crate::trace::emit(
            Some(&mut self.vm),
            process,
            ctx,
            ctx.pid(),
            crate::trace::RUNNING,
            "in",
            &[],
        );
        self.vm.sync_module(process.module);
        if process.native_pc.is_some() && process.reductions <= 0 {
            process.reductions = budget.min(i32::MAX as u32) as i32;
        }
        if process.entry
            && process.native_pc.is_none()
            && let Some(module) = self.vm.modules.get(process.module)
            && let Some((function, arity)) = module.function_at(process.ip)
            && let Some(native) = crate::native_function_for(&module.name, function, arity)
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
                    let args = process.x[..usize::from(arity)].to_vec();
                    let bif = arinsal_bifs::lookup(&module, &function, arity)
                        .expect("spawned BIF entry was resolved before scheduling");
                    match crate::calls::call_bif(&mut process.heap, bif, &args) {
                        Ok(value) => break 'execution Ok(RunState::Done(value)),
                        Err(error) => {
                            break 'execution Err(crate::exceptions::direct_bif_error(
                                process, &module, &function, &args, error,
                            ));
                        }
                    }
                }
                loop {
                    if process.force_yield {
                        process.force_yield = false;
                        break Ok(RunState::Yield);
                    }
                    // g_proc_sched: a suspended process is not scheduled; a hibernating
                    // one stays waiting until a message arrives, then continues at apply/3.
                    if let Some(wait) = self.sched_preempt(process, ctx)? {
                        break Ok(wait);
                    }
                    crate::dist::continue_fragmented_send(process, ctx)?;
                    if process.force_yield {
                        process.force_yield = false;
                        break Ok(RunState::Yield);
                    }
                    if let Some(code_ptr) = process.native_pc.take() {
                        crate::beamasm_integration::count_native_call();
                        process.header.self_pid =
                            ctx.pid().to_term().expect("valid pid").tagged_word();
                        let function = crate::native_function_at(code_ptr);
                        if trace_boot_enabled() {
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
                        let outcome = match crate::run_native(
                            process,
                            &mut self.native_registers,
                            code_ptr,
                        ) {
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
                        };
                        if trace_boot_enabled()
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
                                break Ok(RunState::Yield);
                            }
                            arinsal_beamasm::ExitReason::CallUnported {
                                target_pc,
                                resume_pc: _,
                            } => {
                                crate::beamasm_integration::count_call_unported();
                                if target_pc == arinsal_beamasm::dispatch::SEND_UNPORTED {
                                    let value =
                                        process.send_message(ctx, process.x[0], process.x[1])?;
                                    process.x[0] = value;
                                    if !resume_after_native_return(process) {
                                        break Ok(RunState::Done(value));
                                    }
                                    continue;
                                }
                                if target_pc == arinsal_beamasm::dispatch::CALL_FUN_UNPORTED {
                                    let arity = usize::from(process.header.arity);
                                    let fun = process.x.get(arity).copied().unwrap_or(Term::NIL);
                                    match self.vm.call_fun_term(
                                        process,
                                        fun,
                                        arity,
                                        true,
                                        Some(ctx),
                                    )? {
                                        crate::ImportOutcome::Jump(_)
                                        | crate::ImportOutcome::Advanced => {}
                                        crate::ImportOutcome::Yield => {
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
                                if matches!(
                                    export.class,
                                    arinsal_loader::ImportClass::Native
                                        | arinsal_loader::ImportClass::Dynamic
                                ) {
                                    let result = self.vm.dispatch_native(
                                        process,
                                        ctx,
                                        &export.module,
                                        &export.function,
                                        usize::from(export.arity),
                                        (export.class, export.native_bits),
                                    );
                                    let result = result.or_else(|| {
                                        let (bif, arity) =
                                            crate::beamasm_integration::dispatch_bif(target_pc)?;
                                        let arity = usize::from(arity);
                                        let result = crate::calls::call_bif(
                                            &mut process.heap,
                                            bif,
                                            &process.x[..arity],
                                        );
                                        Some(match result {
                                            Ok(value) => Ok(value),
                                            Err(error) => {
                                                let arguments = process.x[..arity].to_vec();
                                                Err(crate::exceptions::bif_error(
                                                    process,
                                                    &export.module,
                                                    &export.function,
                                                    &arguments,
                                                    error,
                                                ))
                                            }
                                        })
                                    });
                                    if let Some(result) = result {
                                        let value = result?;
                                        process.x[0] = value;
                                        if !resume_after_native_return(process) {
                                            break Ok(RunState::Done(value));
                                        }
                                        continue;
                                    }
                                }
                                let module_id = match self.vm.loaded.get(&export.module).copied() {
                                    Some(module_id) => module_id,
                                    None => match self.vm.load_named(&export.module) {
                                        Ok(module_id) => module_id,
                                        Err(_) => {
                                            match self.vm.call_undefined_function(
                                                process,
                                                &export.module,
                                                &export.function,
                                                usize::from(export.arity),
                                                true,
                                            )? {
                                                crate::ImportOutcome::Jump(_)
                                                | crate::ImportOutcome::Advanced => {}
                                                crate::ImportOutcome::Yield => {
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
                                    },
                                };
                                let target_ip = crate::beamasm_integration::interpreted_target(
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
                                    match self.vm.call_undefined_function(
                                        process,
                                        &export.module,
                                        &export.function,
                                        usize::from(export.arity),
                                        true,
                                    )? {
                                        crate::ImportOutcome::Jump(_)
                                        | crate::ImportOutcome::Advanced => {}
                                        crate::ImportOutcome::Yield => {
                                            break Ok(RunState::Yield);
                                        }
                                        crate::ImportOutcome::Returned(value) => {
                                            process.x[0] = value;
                                            if process.native_pc.is_none() {
                                                break Ok(RunState::Done(value));
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
                    let result = process
                        .drain(ctx)
                        .and_then(|()| self.vm.run_slice(process, Some(ctx), budget));
                    if hibernate_stopped(process, ctx.pid()) {
                        process.drain(ctx)?;
                        if process.inbox.is_empty() {
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
                                let arguments = {
                                    let mut heap = crate::FragmentingHeap(&mut process.heap);
                                    TermBuilder::new(&mut heap)
                                        .list_from_iter(process.x[..arity].iter().copied())
                                        .map_err(|error| {
                                            VmError::Unsupported(format!(
                                                "undef arguments: {error:?}"
                                            ))
                                        })?
                                };
                                trap.top = Some(crate::stacktrace::TopFrame::Bif {
                                    module: module.to_owned(),
                                    function: function.to_owned(),
                                    args: arguments,
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
        if matches!(result, Ok(RunState::Yield | RunState::Wait { .. })) {
            let (live_x, live_fr) = self.vm.registers[process.module];
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
        crate::trace::emit(
            Some(&mut self.vm),
            process,
            ctx,
            ctx.pid(),
            crate::trace::RUNNING,
            "out",
            &[],
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
            runtime.note_status(pid, "suspended");
            return Ok(Some(RunState::Wait { timeout_ms: None }));
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
        let cont = runtime
            .hibernating
            .lock()
            .unwrap()
            .remove(&pid)
            .ok_or_else(|| VmError::Unsupported("hibernate continuation missing".into()))?;
        runtime.mark_hibernating(pid, false);
        // The continuation terms point into `cont.heap`; keep that heap alive.
        let _keep_heap = &cont.heap;
        let (module, function, args) = {
            let mut heap = arinsal_bifs::FragmentingHeap(&mut process.heap);
            (
                copy_term(cont.module, &mut heap).map_err(|error| {
                    VmError::Unsupported(format!("hibernate module: {error:?}"))
                })?,
                copy_term(cont.function, &mut heap).map_err(|error| {
                    VmError::Unsupported(format!("hibernate function: {error:?}"))
                })?,
                copy_term(cont.args, &mut heap)
                    .map_err(|error| VmError::Unsupported(format!("hibernate args: {error:?}")))?,
            )
        };
        if process.x.len() < 3 {
            let mut registers = process.x.to_vec();
            registers.resize(3, Term::NIL);
            process.x = registers.into_boxed_slice();
        }
        process.x[0] = module;
        process.x[1] = function;
        process.x[2] = args;
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
    if let Some(owned) = process
        .cold
        .as_mut()
        .and_then(|cold| cold.exit_reason.take())
    {
        let mut heap = arinsal_bifs::FragmentingHeap(&mut process.heap);
        return match arinsal_term::from_owned(&owned, &mut heap) {
            Ok(reason) => reason,
            Err(conversion_error) => {
                eprintln!("arinsal: exit reason conversion failed: {conversion_error:?}");
                crate::signals::atom("system_limit")
            }
        };
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
        let mut used = process.heap.total_heap_size_words() as u64;
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
    for term in process.x[..process.gc_live]
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

// g_proc_sched. Port of erl_gc.c:3756 (error_logger report) and
// utils.c:885 (`send_error_term_to_logger`), OTP-29.1.1.
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
        builder
            .tuple(&[
                crate::signals::atom("log"),
                crate::signals::atom("error"),
                format,
                args,
                Term::NIL,
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

    /// `{Suspendee, Active, Outstanding}` rows for `process_info(P, suspending)`.
    pub(crate) fn suspending_of(&self, by: Pid) -> Vec<(Pid, u32, u32)> {
        if !self.ever_suspended.load(Ordering::Acquire) {
            return Vec::new();
        }
        let counts = self.suspend_counts.lock().unwrap();
        let mut rows: Vec<_> = counts
            .iter()
            .filter(|((from, _), count)| *from == by && **count > 0)
            .map(|((_, target), count)| (*target, *count, 0))
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
    ) -> Result<bool, ()> {
        self.ever_suspended.store(true, Ordering::Release);
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
        {
            let mut totals = self.suspend_total.lock().unwrap();
            *totals.entry(target).or_insert(0) += 1;
        }
        self.note_status(target, "suspended");
        Ok(true)
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
        }
        drop(counts);
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

    pub(crate) fn forget_process(&self, pid: Pid) {
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
        child.runtime = Some(Arc::clone(self));
        child.cold_mut().group_leader = None;
        if let Some(arity) = u8::try_from(args.len()).ok()
            && arinsal_bifs::lookup(module, function, arity).is_some()
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
        crate::trace::clear(self, ctx.pid());
        // Further publishes fail with `NoProcess` and the watcher synthesizes
        // DOWN. Signals already queued are installed before we notify.
        ctx.begin_exit();
        self.absorb_exit_signals(ctx);
        // g_proc_sched: a terminating suspender releases every suspend it acquired.
        // g_port_fix: close owned ports synchronously on the termination path.
        if let Some(runtime) = self.runtime.clone() {
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
            let owned = {
                let registry = runtime.ets.lock().unwrap();
                registry
                    .owned_by(owner)
                    .into_iter()
                    .filter_map(|tid| {
                        let table = registry.get(tid).ok()?;
                        Some((tid, table.options.heir))
                    })
                    .collect::<Vec<_>>()
            };
            for (tid, heir) in owned {
                if let Some(heir) = heir
                    && let Some(pid) = Pid::from_term(heir.pid)
                {
                    let mut heap = arinsal_term::VecHeap::new();
                    let message_term = tid.to_term(&mut heap).and_then(|tab| {
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
                        let mut registry = runtime.ets.lock().unwrap();
                        if registry.give_away(tid, heir.pid).is_ok() {
                            drop(registry);
                            if ctx.send(pid, message).is_ok() {
                                continue;
                            }
                        }
                    }
                }
                let _ = runtime.ets.lock().unwrap().delete(tid);
            }
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
                let _ = ctx.signal(pid, arinsal_sched::Signal::Exit(message));
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

    pub(crate) fn send_message(
        &mut self,
        ctx: &mut RunCtx<'_, Message>,
        target: Term,
        value: Term,
    ) -> Result<Term, VmError> {
        self.send_message_inner(None, ctx, target, value)
    }

    pub(crate) fn send_message_with_vm(
        &mut self,
        vm: &mut Vm,
        ctx: &mut RunCtx<'_, Message>,
        target: Term,
        value: Term,
    ) -> Result<Term, VmError> {
        self.send_message_inner(Some(vm), ctx, target, value)
    }

    fn send_message_inner(
        &mut self,
        vm: Option<&mut Vm>,
        ctx: &mut RunCtx<'_, Message>,
        target: Term,
        value: Term,
    ) -> Result<Term, VmError> {
        self.send_message_prio(vm, ctx, target, value, false)
    }

    /// Send with an optional OTP 28+ `[priority]` request.
    // Port of erts/emulator/beam/erl_message.c / bif.c send with priority, OTP-29.1.1.
    pub(crate) fn send_message_prio(
        &mut self,
        mut vm: Option<&mut Vm>,
        ctx: &mut RunCtx<'_, Message>,
        target: Term,
        value: Term,
        want_priority: bool,
    ) -> Result<Term, VmError> {
        if target.as_port().is_some() {
            crate::port::send_message(self, ctx, target, value)?;
            return Ok(value);
        }
        // Port of erts/emulator/beam/erl_message.c (`erts_send` / remote_send), OTP-29.1.1.
        if crate::dist::try_remote_send(self, ctx, target, value)? {
            crate::trace::emit(
                vm.as_deref_mut(),
                self,
                ctx,
                ctx.pid(),
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
            let pid = names.get(name.as_ref()).copied();
            if let Some(pid) = pid
                && !runtime.scheduler()?.lookup(pid)
            {
                names.remove(name.as_ref());
                None
            } else {
                pid
            }
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
        crate::trace::emit(
            vm.as_deref_mut(),
            self,
            ctx,
            ctx.pid(),
            crate::trace::SEND,
            "send",
            &[value, target],
        );
        let mut envelope = Message::copy_from(value)?;
        if via_prio_alias {
            envelope = envelope.with_priority();
        }
        if crate::seq_trace::has_token(self)
            && let Some(token) = crate::seq_trace::on_send(vm, self, ctx, ctx.pid(), target, value)
        {
            envelope.attach_seq_token(token);
        }
        match ctx.send(pid, envelope) {
            Ok(()) | Err(arinsal_sched::Error::NoProcess) => Ok(value),
            Err(error) => Err(VmError::Unsupported(format!("send: {error}"))),
        }
    }

    // Port of erts/emulator/beam/erl_bif_info.c:4976-4995, OTP-29.1.1.
    fn handle_multizero_timeout_callback(
        &mut self,
        ctx: &mut RunCtx<'_, Message>,
        term: Term,
    ) -> Result<bool, VmError> {
        let callback = term
            .as_atom()
            .and_then(|name| arinsal_term::global_atoms().text(name));
        let next = match callback.as_deref() {
            Some("multizero_timeout_in_timeout_step1") => {
                Some("multizero_timeout_in_timeout_step2")
            }
            Some("multizero_timeout_in_timeout_step2") => {
                Some("multizero_timeout_in_timeout_step3")
            }
            Some("multizero_timeout_in_timeout_step3") => {
                self.inbox
                    .push_back(crate::signals::atom("multizero_timeout_in_timeout_done"));
                return Ok(true);
            }
            _ => None,
        };
        if let Some(next) = next {
            ctx.send_after(0, Message::copy_from(crate::signals::atom(next))?)
                .map_err(|_| {
                    VmError::Trap(crate::exceptions::Trap::error(crate::signals::atom(
                        "system_limit",
                    )))
                })?;
            return Ok(true);
        }
        Ok(false)
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

    fn drain_until_marker(
        &mut self,
        ctx: &mut RunCtx<'_, Message>,
        marker: Option<ReceiveMarker>,
    ) -> Result<(), VmError> {
        // Port of erts/emulator/beam/erl_proc_sig_queue.c:6032 (private queue fetch), OTP-29.1.1.
        ctx.fetch_pending();
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
                    let multizero_callback = message
                        .term
                        .as_atom()
                        .and_then(|name| arinsal_term::global_atoms().text(name))
                        .is_some_and(|name| {
                            matches!(
                                name.as_ref(),
                                "multizero_timeout_in_timeout_step1"
                                    | "multizero_timeout_in_timeout_step2"
                                    | "multizero_timeout_in_timeout_step3"
                            )
                        });
                    if multizero_callback {
                        let term = message.into_receiver(self)?;
                        self.handle_multizero_timeout_callback(ctx, term)?;
                        continue;
                    }
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
                }
                Payload::Signal(arinsal_sched::Signal::Monitor(reference)) => {
                    self.cold_mut().monitored_by.insert(reference, from);
                }
                Payload::Signal(arinsal_sched::Signal::Demonitor(reference)) => {
                    if let Some(cold) = self.cold.as_mut() {
                        cold.monitored_by.remove(&reference);
                    }
                }
                Payload::Signal(arinsal_sched::Signal::Exit(message)) => {
                    let priority = message.is_priority()
                        || self
                            .cold
                            .as_ref()
                            .is_some_and(|cold| cold.prio_links.contains(&from));
                    let reason = message.into_receiver(self)?;
                    if reason == crate::signals::atom("kill") {
                        // Port of erts/emulator/beam/erl_proc_sig_queue.c:4782
                        // (handle_exit_signal), OTP-29.1.1: `kill` exits without exception dispatch.
                        return Err(VmError::Trap(crate::exceptions::Trap::killed()));
                    }
                    if self.trap_exit {
                        // Port of erts/emulator/beam/external.c:3127-3141, OTP-29.1.1.
                        // A scheduler proxy stands in for a remote PID internally, but
                        // EXIT messages expose the peer's original PID to Erlang code.
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
                        continue;
                    }
                    if reason != Term::atom(arinsal_term::atoms::NORMAL) {
                        self.note_exit_reason(reason)?;
                        return Err(VmError::Trap(crate::exceptions::Trap::exit(reason)));
                    }
                }
                Payload::Signal(arinsal_sched::Signal::MonitorNoproc(reference)) => {
                    self.deliver_monitor_down(from, reference, crate::signals::atom("noproc"))?;
                }
                Payload::Signal(arinsal_sched::Signal::MonitorDown { reference, reason }) => {
                    let reason = reason.into_receiver(self)?;
                    self.deliver_monitor_down(from, reference, reason)?;
                }
                Payload::Timer { reference, message } => {
                    let term = message.into_receiver(self)?;
                    if self.handle_multizero_timeout_callback(ctx, term)? {
                        continue;
                    }
                    let runtime = self
                        .runtime
                        .as_ref()
                        .ok_or_else(|| VmError::Unsupported("timer without runtime".into()))?;
                    let id = {
                        let mut timers = runtime.timers.lock().unwrap();
                        let id = timers
                            .iter()
                            .find_map(|(&id, &timer)| (timer == reference).then_some(id));
                        if let Some(id) = id {
                            timers.remove(&id);
                        }
                        id.unwrap_or(reference.id())
                    };
                    let reference = crate::signals::reference(self, id)?;
                    let tuple = self.tuple(&[crate::signals::atom("timeout"), reference, term])?;
                    self.inbox.push_back(tuple);
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
                    self.force_gc()?;
                }
            }
        }
        crate::natives::erts_debug::after_message_queue_change(self);
        Ok(())
    }
}

impl Process {
    /// Set this process's `F_DISABLE_GC` equivalent and return its previous state.
    /// Port of erts/emulator/beam/erl_process.c:11823 (`erts_set_gc_state`), OTP-29.1.1.
    pub(crate) fn set_gc_enabled(&mut self, enabled: bool) -> bool {
        let previous = self.gc_enabled;
        self.gc_enabled = enabled;
        previous
    }

    /// Force a collection of the running process before the current BIF returns.
    /// Port of erts/emulator/beam/erl_gc.h:152 (`ERTS_FORCE_GC`), OTP-29.1.1.
    pub(crate) fn force_gc(&mut self) -> Result<(), VmError> {
        self.collect_heap_roots(self.x.len(), &mut [], 0)?;
        Ok(())
    }

    /// Collect live registers together with only on-heap mailbox message roots.
    // Port of erts/emulator/beam/erl_proc_sig_queue.c:8257 (message queue GC scan), OTP-29.1.1.
    pub(crate) fn collect_heap_roots(
        &mut self,
        live_x: usize,
        extra: &mut [Term],
        min_free: usize,
    ) -> Result<arinsal_term::GcStats, VmError> {
        let (indices, mut roots) = self.inbox.gc_root_snapshot();
        let mailbox_len = roots.len();
        roots.extend_from_slice(extra);
        let stats = self
            .heap
            .collect(&mut self.x[..live_x], &mut roots, min_free)
            .map_err(|error| VmError::Unsupported(format!("process GC: {error:?}")))?;
        self.stats.gc.collections += stats.collections;
        self.stats.gc.nanoseconds += stats.nanoseconds;
        self.inbox.update_gc_roots(&indices, &roots[..mailbox_len]);
        extra.copy_from_slice(&roots[mailbox_len..]);
        crate::natives::erts_debug::after_collection(self, stats.nanoseconds);
        Ok(stats)
    }

    // Port of erts/emulator/beam/beam_bif_load.c:1149 (check_process_code), OTP-29.1.1.
    pub(crate) fn references_code(&self, module: usize) -> bool {
        if self.module == module {
            return true;
        }
        for index in 0..self.heap.stack_words() {
            let Some(term) = self.heap.stack_get(index) else {
                continue;
            };
            if term.classify() == arinsal_term::TermKind::Catch {
                let bits = term.tagged_word() >> 6;
                if (bits >> 32) as usize == module {
                    return true;
                }
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
        let tag_owned = self
            .cold
            .as_mut()
            .and_then(|cold| cold.monitor_tags.remove(&reference));
        let priority = self
            .cold
            .as_mut()
            .is_some_and(|cold| cold.prio_monitors.remove(&reference));
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
        let reference = crate::signals::reference(self, reference)?;
        let from = crate::dist::remote_pid_term(self, from)?
            .or_else(|| from.to_term())
            .ok_or_else(|| VmError::Unsupported("invalid monitor sender pid".into()))?;
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

impl Task for Process {
    type Message = Message;

    fn gc_nanoseconds(&self) -> u64 {
        self.stats.gc.nanoseconds
    }

    fn run(&mut self, ctx: &mut RunCtx<'_, Message>, budget: u32) -> RunOutcome {
        abort_on_worker_panic(|| self.run_task(ctx, budget))
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

    fn reap_signals(&mut self, pid: Pid, events: Vec<Event<Message>>) {
        let mut monitors = Vec::new();
        for event in events {
            match event.payload {
                Payload::Signal(Signal::Monitor(reference)) => {
                    monitors.push((reference, event.from));
                }
                Payload::Signal(Signal::Demonitor(reference)) => {
                    monitors.retain(|(id, _)| *id != reference);
                }
                _ => {}
            }
        }
        if monitors.is_empty() {
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
        let result = EXECUTOR.with(|slot| {
            let mut slot = slot.borrow_mut();
            let key = Arc::as_ptr(&runtime) as usize;
            let replace = slot.as_ref().is_none_or(|(cached_key, executor)| {
                *cached_key != key || executor.owner.strong_count() == 0
            });
            if replace {
                *slot = Some((
                    key,
                    Executor {
                        owner: Arc::downgrade(&runtime),
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
        match result {
            Ok(RunState::Yield) => {
                runtime.note_status(ctx.pid(), "runnable");
                RunOutcome::Yield
            }
            Ok(RunState::Wait { timeout_ms }) => {
                runtime.note_status(ctx.pid(), "waiting");
                RunOutcome::Wait { timeout_ms }
            }
            Ok(RunState::Done(term)) => {
                if trace_boot_enabled() {
                    eprintln!(
                        "arinsal boot: process {:?} done module={} ip={} value={term:?}",
                        ctx.pid(),
                        self.module,
                        self.ip
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
                crate::signals::process_exiting(self, ctx);
                runtime.processes.lock().unwrap().remove(&ctx.pid());
                if trace_boot_enabled() {
                    eprintln!("arinsal boot: process {:?} exited: {error}", ctx.pid());
                }
                let reason = exit_reason_from(self, &error);
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
    ) -> Result<(), VmError> {
        let module_id = self.load_named(module)?;
        let ip = self.modules[module_id]
            .export(function, 0)
            .ok_or_else(|| VmError::Load(format!("{module}:{function}/0 is not exported")))?;
        let mut process = Process::with_spawn_registers(0, 0);
        process.module = module_id;
        process.ip = ip;
        process.runtime = Some(Arc::clone(runtime));
        let pid = scheduler
            .spawn(process)
            .map_err(|error| VmError::Unsupported(format!("system process {module}: {error}")))?;
        runtime.processes.lock().unwrap().insert(pid);
        runtime.system_processes.lock().unwrap().insert(pid);
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
        initialize_feature_defaults()?;
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
            processes: Mutex::new(std::collections::HashSet::new()),
            system_processes: Mutex::new(std::collections::HashSet::new()),
            paths: self.paths.clone(),
            scheduler: Mutex::new(Weak::new()),
            names: Mutex::new(HashMap::new()),
            aliases: AliasTable::new(),
            timers: Mutex::new(HashMap::new()),
            ports: Mutex::new(HashMap::new()),
            system_monitor: Mutex::new(None),
            system_monitor_flags: AtomicU8::new(0),
            long_message_queues: Mutex::new(HashSet::new()),
            next_port: AtomicU64::new(16),
            simulated: simulation_seed.is_some(),
            virtual_ms: AtomicU64::new(0),
            ets: Mutex::new(arinsal_ets::Registry::new()),
            result: sender,
            suspend_counts: Mutex::new(HashMap::new()),
            suspend_total: Mutex::new(HashMap::new()),
            ever_suspended: AtomicBool::new(false),
            published: Mutex::new(HashMap::new()),
            hibernating: Mutex::new(HashMap::new()),
            ever_hibernated: AtomicBool::new(false),
            max_heaps: Mutex::new(HashMap::new()),
            ever_max_heap: AtomicBool::new(false),
        });
        let config = Config {
            workers,
            reductions: reductions.max(1),
            ..Config::default()
        };
        let scheduler = Arc::new(match simulation_seed {
            Some(seed) => Scheduler::simulation(config, seed),
            None => Scheduler::new(config),
        });
        let (online, blocked) = crate::natives::sys::scheduler_online_default();
        let _ = scheduler.set_online_schedulers(online.min(workers.max(1)));
        scheduler.set_scheduling_blocked(blocked, None);
        *runtime.scheduler.lock().unwrap() = Arc::downgrade(&scheduler);
        if module == "erl_init" && function == "start" {
            // Port of erts/emulator/beam/erl_init.c:2550 (erl_system_process_otp
            // "erts_code_purger"), OTP-29.1.1. code_server:finish_on_load sends
            // to this registered process; without it the send is badarg and
            // code_server dies during ensure_loaded of an on_load module.
            self.spawn_system_process(&scheduler, &runtime, "erts_code_purger", "start")?;
        }
        let mut process = Process::with_spawn_registers(args.len(), 0);
        process.module = module_id;
        process.ip = ip;
        process.x[..args.len()].copy_from_slice(args);
        process.runtime = Some(runtime.clone());
        process.entry = true;
        process.heap.set_min_heap_size(8192);
        let _entry_pid: Pid = scheduler
            .spawn(process)
            .map_err(|error| VmError::Unsupported(format!("spawn: {error}")))?;
        runtime.processes.lock().unwrap().insert(_entry_pid);
        if !scheduler.lookup(_entry_pid) {
            runtime.processes.lock().unwrap().remove(&_entry_pid);
        }
        if simulation_seed.is_some() {
            loop {
                if let Ok(result) = receiver.try_recv() {
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
        let shared = code.lock().unwrap();
        self.sync_shared(&shared);
        result
    }
}

fn initialize_feature_defaults() -> Result<(), VmError> {
    let mut heap = arinsal_term::VecHeap::new();
    let module = Term::atom(
        arinsal_term::global_atoms()
            .intern("erl_features")
            .map_err(|error| VmError::Load(format!("feature atom: {error:?}")))?,
    );
    let store = arinsal_pterm::global_store();
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
