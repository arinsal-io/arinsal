//! Process storage and construction.

use super::*;

#[derive(Default)]
pub(crate) struct ProcessStats {
    pub(crate) instructions: u64,
    pub(crate) gc: GcStats,
    pub(crate) heap_words: usize,
    #[cfg(feature = "instr-count")]
    opcodes: HashMap<&'static str, u64>,
    #[cfg(feature = "instr-count")]
    generic_opcodes: HashMap<&'static str, u64>,
}
impl ProcessStats {
    pub(crate) fn snapshot(&self) -> Stats {
        Stats {
            instructions: self.instructions,
            opcodes: {
                #[cfg(feature = "instr-count")]
                {
                    self.opcodes.clone()
                }
                #[cfg(not(feature = "instr-count"))]
                {
                    HashMap::new()
                }
            },
            generic_opcodes: {
                #[cfg(feature = "instr-count")]
                {
                    self.generic_opcodes.clone()
                }
                #[cfg(not(feature = "instr-count"))]
                {
                    HashMap::new()
                }
            },
            gc: self.gc,
            heap_words: self.heap_words,
        }
    }
}

/// One future schedulable process, with private registers and heap.
#[repr(C)]
pub struct Process {
    /// BeamAsm ABI prefix; interpreter fields remain authoritative outside native execution.
    pub(crate) header: ProcessHeader,
    /// X registers, up to erts MAX_REG.
    pub x: Box<[Term]>,
    /// Float registers.
    pub fr: Box<[f64]>,
    /// Contiguous process heap and Y stack.
    pub heap: ProcessHeap,
    /// The erts process dictionary pointer is part of the hot process structure.
    pub(crate) dictionary: Option<ProcDict>,
    /// Per-process sequential trace token; `None` is the no-token fast path.
    pub(crate) seq_trace_token: Option<Box<crate::seq_trace::Token>>,
    pub(crate) module: usize,
    pub(crate) ip: usize,
    pub(crate) initial_call: Option<(usize, usize)>,
    pub(crate) native_pc: Option<usize>,
    /// The entry process has been scheduled once (its native start is decided then).
    pub(crate) entry_started: bool,
    // Last BEAM live operand or call arity for allocation instructions without one.
    pub(crate) gc_live: usize,
    /// Largest total heap size seen at a collection entry since the last `max_heap_size` check.
    pub(crate) max_heap_peak: usize,
    pub(crate) reductions: i32,
    pub(crate) reductions_used: u64,
    pub(crate) gc_enabled: bool,
    pub(crate) gc_deferred: bool,
    pub(crate) uniq_counter: i64,
    pub(crate) stats: ProcessStats,
    /// Final reason remains on the task until the scheduler reaps late monitors.
    pub(crate) final_exit_reason: Option<Term>,
    // ---- processes and messages ----
    pub(crate) runtime: Option<std::sync::Arc<process::Runtime>>,
    pub(crate) self_pid: Option<arinsal_sched::Pid>,
    /// Saved continuation data for the process's pending `erts_await_result` BIF.
    // Port of erts/emulator/beam/erl_bif_info.c:1480-1500, OTP-29.1.1.
    pub(crate) pending_signal_waiter: Option<crate::signals::Waiter>,
    /// One-based id of the scheduler running this process (0 outside a run), refreshed each slice
    /// like erts' `c_p->scheduler_data`.
    pub(crate) scheduler_id: u32,
    /// `F_HIBERNATED`: the heap holds exactly the live data of a hibernated process.
    pub(crate) hibernated: bool,
    pub(crate) inbox: process::MessageQueue,
    pub(crate) receive_cursor: usize,
    pub(crate) receive_deadline: Option<std::time::Instant>,
    pub(crate) receive_deadline_ms: Option<u64>,
    pub(crate) cold: Option<Box<ProcessCold>>,
    // Retired persistent-term areas are copied out and acknowledged in
    // `natives::sys::after_collection` on every collection.
    pub(crate) _persistent_terms: arinsal_pterm::ProcessRegistration<'static>,
    pub(crate) trap_exit: bool,
    /// Class of the exception currently being handled. `raise/2` re-raises
    /// this after an `after` block, because that block may clobber X registers.
    /// mix_loop1. Port of the freason kept across `i_raise` (beam_emu), OTP-29.1.1.
    pub(crate) exc_class: Option<arinsal_bifs::Class>,
    pub(crate) entry: bool,
    /// A dist send that suspended must yield even if the queue drains before return.
    pub(crate) force_yield: bool,
}
// SAFETY: ProcessHeader pointers refer only to this process's stable heap/code allocations.
// The scheduler transfers exclusive ownership of each Process between workers.
unsafe impl Send for Process {}
const _: () = assert!(std::mem::offset_of!(Process, header) == 0);

/// Empty chain / free-list terminator. A live slot holds a node index.
const NIL_NODE: u32 = u32::MAX;

/// One `{Key,Value}` on a bucket chain. `next == NIL_NODE` is erts' bare tuple;
/// a longer chain is erts' list. Nodes live in one slab so grow/shrink rewire
/// `next` instead of allocating a fresh vector per split or merge.
struct DictNode {
    key: Term,
    value: Term,
    next: u32,
}

/// Linear hash table used by the process dictionary.
/// Port of erts/emulator/beam/erl_process_dict.h:27-40 (`ProcDict`), OTP-29.1.1.
pub(crate) struct ProcDict {
    nodes: Vec<DictNode>,
    free: u32,
    /// Bucket heads, indexed like `ProcDict.data`. Length is `array_size`.
    heads: Vec<u32>,
    size_mask: u32,
    used_slots: u32,
    array_size: u32,
    split_position: u32,
    num_elements: usize,
}

impl Default for ProcDict {
    fn default() -> Self {
        Self {
            nodes: Vec::new(),
            free: NIL_NODE,
            heads: Vec::new(),
            size_mask: 0,
            used_slots: 0,
            array_size: 0,
            split_position: 0,
            num_elements: 0,
        }
    }
}

/// Head-to-tail walk of buckets `0..used_slots`, matching `entries` before reversal.
pub(crate) struct DictEntries<'a> {
    nodes: &'a [DictNode],
    heads: &'a [u32],
    slot: usize,
    used: usize,
    cur: u32,
}

impl Iterator for DictEntries<'_> {
    type Item = (Term, Term);

    fn next(&mut self) -> Option<Self::Item> {
        while self.cur == NIL_NODE {
            if self.slot >= self.used {
                return None;
            }
            self.cur = self.heads[self.slot];
            self.slot += 1;
        }
        let node = &self.nodes[self.cur as usize];
        self.cur = node.next;
        Some((node.key, node.value))
    }
}

impl ProcDict {
    // Port of MAKE_HASH (erl_process_dict.c:58), OTP-29.1.1.
    // `unsigned_val` is a logical shift of the tagged word, not a sign-extended cast.
    #[inline]
    fn hash(key: Term) -> u64 {
        let word = key.tagged_word();
        if word & 15 == 15 {
            word >> 4
        } else if let Some(atom) = key.as_atom() {
            atom.0 as u64
        } else {
            arinsal_term::internal_hash(key)
        }
    }

    // Port of pd_hash_value_to_ix (erl_process_dict.c:1008), OTP-29.1.1.
    #[inline]
    fn bucket_index(&self, key: Term) -> usize {
        let hash = Self::hash(key);
        let high = hash & self.size_mask as u64;
        if high >= self.used_slots as u64 {
            (hash & (self.size_mask >> 1) as u64) as usize
        } else {
            high as usize
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.num_elements
    }

    pub(crate) fn entries(&self) -> DictEntries<'_> {
        DictEntries {
            nodes: &self.nodes,
            heads: &self.heads,
            slot: 0,
            used: self.used_slots as usize,
            cur: NIL_NODE,
        }
    }

    /// `get/0` order: erts conses each pair while scanning, which reverses this walk.
    pub(crate) fn entries_reversed(&self) -> Vec<(Term, Term)> {
        let mut entries: Vec<_> = self.entries().collect();
        entries.reverse();
        entries
    }

    /// Rewrite every live pair. Order matches [`Self::entries`].
    pub(crate) fn for_each_mut(&mut self, mut visit: impl FnMut(&mut Term, &mut Term)) {
        for slot in 0..self.used_slots as usize {
            let mut cur = self.heads[slot];
            while cur != NIL_NODE {
                let next = self.nodes[cur as usize].next;
                let node = &mut self.nodes[cur as usize];
                visit(&mut node.key, &mut node.value);
                cur = next;
            }
        }
    }

    pub(crate) fn assign_entries(&mut self, pairs: &[(Term, Term)]) {
        let mut index = 0;
        self.for_each_mut(|key, value| {
            let (new_key, new_value) = pairs[index];
            *key = new_key;
            *value = new_value;
            index += 1;
        });
        debug_assert_eq!(index, pairs.len());
    }

    fn alloc_node(&mut self, key: Term, value: Term, next: u32) -> u32 {
        if self.free != NIL_NODE {
            let id = self.free;
            self.free = self.nodes[id as usize].next;
            self.nodes[id as usize] = DictNode { key, value, next };
            return id;
        }
        let id = u32::try_from(self.nodes.len()).expect("process dictionary node index");
        self.nodes.push(DictNode { key, value, next });
        id
    }

    fn free_node(&mut self, id: u32) {
        let node = &mut self.nodes[id as usize];
        // Drop the terms so a freed slot is not a GC root if a chain is walked twice.
        node.key = Term::NIL;
        node.value = Term::NIL;
        node.next = self.free;
        self.free = id;
    }

    fn prepend(&mut self, index: usize, key: Term, value: Term) {
        let next = self.heads[index];
        let id = self.alloc_node(key, value, next);
        self.heads[index] = id;
    }

    pub(crate) fn memory_bytes(&self) -> usize {
        // Port of PD_SZ2BYTES (erl_process_dict.c:64), OTP-29.1.1.
        // sizeof(ProcDict) is 32 on 64-bit: four unsigned ints, a Uint, and data[1].
        if self.array_size == 0 {
            return 0;
        }
        32 + (self.array_size as usize - 1) * std::mem::size_of::<Term>()
    }

    // Port of erts/emulator/beam/erl_process_dict.c:1023-1071 (next_array_size), OTP-29.1.1.
    // Needs at or below the first table entry fall out of the search and return `need`
    // itself, so the initial table is 8 words rather than 10.
    fn next_array_size(need: u32) -> u32 {
        const SIZES: [u32; 29] = [
            10,
            20,
            40,
            80,
            160,
            320,
            640,
            1280,
            2560,
            5120,
            10240,
            20480,
            40960,
            81920,
            163840,
            327680,
            655360,
            1310720,
            2621440,
            5242880,
            10485760,
            20971520,
            41943040,
            83886080,
            167772160,
            335544320,
            671088640,
            1342177280,
            2_684_354_560,
        ];
        let mut hi = SIZES.len() as i32 - 1;
        let mut lo = 1_i32;
        let mut cur = 4_i32;
        while hi >= lo {
            let size = SIZES[cur as usize];
            let previous = SIZES[(cur - 1) as usize];
            if size >= need && previous < need {
                return size;
            }
            if size > need {
                hi = cur - 1;
            } else {
                lo = cur + 1;
            }
            cur = (hi + lo) / 2;
        }
        need
    }

    /// Look up a key using the active hash range.
    // Port of erts/emulator/beam/erl_process_dict.c:463-501 (pd_hash_get), OTP-29.1.1.
    #[inline]
    pub(crate) fn get(&self, key: Term) -> Option<Term> {
        if self.used_slots == 0 {
            return None;
        }
        let mut cur = self.heads[self.bucket_index(key)];
        while cur != NIL_NODE {
            let node = &self.nodes[cur as usize];
            if arinsal_term::exact_eq(node.key, key) {
                return Some(node.value);
            }
            cur = node.next;
        }
        None
    }

    /// Insert or replace an entry and return its previous value.
    // Port of erts/emulator/beam/erl_process_dict.c:628-762 (pd_hash_put), OTP-29.1.1.
    #[inline]
    pub(crate) fn put(&mut self, key: Term, value: Term) -> Option<Term> {
        if self.used_slots == 0 {
            // Port of erl_process_dict.c:644-650: ensure_array_size(INITIAL_SIZE),
            // usedSlots = 8, sizeMask = 15, splitPosition = 0. INITIAL_SIZE is 8
            // (erl_init.c), and next_array_size(8) is 8.
            let size = Self::next_array_size(8);
            self.array_size = size;
            self.heads.resize(size as usize, NIL_NODE);
            self.used_slots = 8;
            self.size_mask = 15;
            self.split_position = 0;
        }
        let index = self.bucket_index(key);
        let mut prev = NIL_NODE;
        let mut cur = self.heads[index];
        while cur != NIL_NODE {
            if arinsal_term::exact_eq(self.nodes[cur as usize].key, key) {
                let previous = self.nodes[cur as usize].value;
                // erts writes an immediate value into the existing tuple. A boxed value
                // is a new tuple consed at the head (the old cell is unlinked first).
                self.nodes[cur as usize].key = key;
                self.nodes[cur as usize].value = value;
                if !value.is_immed() && prev != NIL_NODE {
                    let next = self.nodes[cur as usize].next;
                    self.nodes[prev as usize].next = next;
                    self.nodes[cur as usize].next = self.heads[index];
                    self.heads[index] = cur;
                }
                return Some(previous);
            }
            prev = cur;
            cur = self.nodes[cur as usize].next;
        }
        self.prepend(index, key, value);
        self.num_elements += 1;
        if self.used_slots as usize <= self.num_elements {
            self.grow();
        }
        None
    }

    /// Erase a key, return its previous value, and shrink when erts would.
    // Port of erts/emulator/beam/erl_process_dict.c:385-436 (pd_hash_erase), OTP-29.1.1.
    #[inline]
    pub(crate) fn erase(&mut self, key: Term) -> Option<Term> {
        if self.used_slots == 0 {
            return None;
        }
        let index = self.bucket_index(key);
        let mut prev = NIL_NODE;
        let mut cur = self.heads[index];
        let mut result = None;
        while cur != NIL_NODE {
            let next = self.nodes[cur as usize].next;
            if arinsal_term::exact_eq(self.nodes[cur as usize].key, key) {
                if prev == NIL_NODE {
                    self.heads[index] = next;
                } else {
                    self.nodes[prev as usize].next = next;
                }
                result = Some(self.nodes[cur as usize].value);
                self.free_node(cur);
                self.num_elements -= 1;
                break;
            }
            prev = cur;
            cur = next;
        }
        if self.used_slots > 8 && self.used_slots as usize / 2 > self.num_elements {
            self.shrink();
        }
        result
    }

    fn grow(&mut self) {
        // Port of erts/emulator/beam/erl_process_dict.c:852-954 (grow), OTP-29.1.1.
        // Splitting a list prepends onto each side, which reverses that side. A
        // one-element result stays a bare node (`next == NIL_NODE`), matching the
        // tuple unwrap at lines 941-944.
        const MAX_HASH: u32 = 1_342_177_280;
        let steps = ((self.used_slots / 4) & 0xf).max(1);
        if MAX_HASH - steps <= self.used_slots {
            return;
        }
        let needed = self.used_slots + steps;
        if needed > self.array_size {
            let new_size = Self::next_array_size(needed);
            self.heads.resize(new_size as usize, NIL_NODE);
            self.array_size = new_size;
        }
        let mut home_size = self.used_slots - self.split_position;
        for _ in 0..steps {
            if self.split_position == home_size {
                home_size *= 2;
                self.size_mask = home_size * 2 - 1;
                self.split_position = 0;
            }
            let position = self.split_position as usize;
            self.split_position += 1;
            self.used_slots += 1;
            let from = position + home_size as usize;
            let mut low = NIL_NODE;
            let mut high = NIL_NODE;
            let mut cur = self.heads[position];
            while cur != NIL_NODE {
                let next = self.nodes[cur as usize].next;
                let key = self.nodes[cur as usize].key;
                if self.bucket_index(key) == position {
                    self.nodes[cur as usize].next = low;
                    low = cur;
                } else {
                    self.nodes[cur as usize].next = high;
                    high = cur;
                }
                cur = next;
            }
            self.heads[position] = low;
            self.heads[from] = high;
        }
    }

    fn shrink(&mut self) {
        // Port of erts/emulator/beam/erl_process_dict.c:766-850 (shrink), OTP-29.1.1.
        let range = self.used_slots;
        let mut steps = range * 3 / 10;
        if range - steps < 8 {
            steps = range - 8;
        }
        for _ in 0..steps {
            if self.split_position == 0 {
                self.size_mask = self.used_slots - 1;
                self.split_position = self.used_slots / 2;
            }
            self.split_position -= 1;
            let high_index = (self.used_slots - 1) as usize;
            let low_index = self.split_position as usize;
            let hi = self.heads[high_index];
            let lo = self.heads[low_index];
            self.heads[low_index] = self.merge_shrink(lo, hi);
            self.used_slots -= 1;
            self.heads[self.used_slots as usize] = NIL_NODE;
        }
        // Port of erl_process_dict.c:847-849 and array_shrink (960-975): only shrink.
        if self.used_slots <= self.array_size / 4 {
            let siz = Self::next_array_size(self.used_slots * 3 / 2);
            if siz < self.array_size {
                self.array_size = siz;
                self.heads.truncate(self.array_size as usize);
            }
        }
    }

    // Port of erts/emulator/beam/erl_process_dict.c:793-840 (shrink bucket merge), OTP-29.1.1.
    fn merge_shrink(&mut self, lo: u32, hi: u32) -> u32 {
        if hi == NIL_NODE {
            return lo;
        }
        if lo == NIL_NODE {
            return hi;
        }
        let lo_tuple = self.nodes[lo as usize].next == NIL_NODE;
        if lo_tuple {
            // `{Lo,Hi}` or `[Lo|Hi]`: the low tuple is consed in front of hi.
            self.nodes[lo as usize].next = hi;
            return lo;
        }
        if self.nodes[hi as usize].next == NIL_NODE {
            // `[Hi|Lo]`.
            self.nodes[hi as usize].next = lo;
            return hi;
        }
        // Both lists: walk hi head-to-tail, prepending onto lo (hi ends up reversed).
        let mut hi_cur = hi;
        let mut lo_head = lo;
        while hi_cur != NIL_NODE {
            let next = self.nodes[hi_cur as usize].next;
            self.nodes[hi_cur as usize].next = lo_head;
            lo_head = hi_cur;
            hi_cur = next;
        }
        lo_head
    }
}
/// The traced native functions a return left, innermost first with their trace actions, and the
/// returned value.
pub(crate) type NativeReturnEvents = (Vec<(usize, Vec<crate::trace::NativeTraceAction>)>, Term);

#[derive(Default)]
pub(crate) struct ProcessCold {
    /// `process_flag(save_calls, N)` buffer (erts `ERTS_PSD_SAVED_CALLS_BUF`).
    pub(crate) saved_calls: Option<crate::trace::SavedCalls>,
    /// Link halves retained until the matching unlink acknowledgement arrives.
    pub(crate) unlinking: std::collections::BTreeMap<u64, arinsal_sched::Pid>,
    /// The last slice ended because the process is suspended, not because it waits in a
    /// receive: it stays active (runnable once resumed).
    pub(crate) suspend_parked: bool,
    /// The process already exited while its dirty job keeps running.
    /// Port of erl_process.c:10096 (`need_forced_exit`), OTP-29.1.1.
    pub(crate) dirty_exited: bool,
    /// Shared copy of `dirty_exited` for a dirty job running without the process.
    pub(crate) dirty_exit_flag: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    /// A dirty BIF call waiting for its dirty job, or the job's result.
    pub(crate) dirty_bif: Option<crate::dirty::DirtyBif>,
    /// Export of the dirty BIF that is scheduled or running; `current_function` reports it.
    pub(crate) dirty_bif_mfa: Option<(&'static str, &'static str, u8)>,
    /// Result of a static dirty NIF executed as a dirty job.
    pub(crate) static_nif_done: Option<Result<Term, arinsal_bifs::BifError>>,
    /// Completion latch for `erts_debug:set_internal_state(wait, ...)`.
    pub(crate) debug_wait_completion: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    /// Whether this process currently has a runnable profile activation.
    pub(crate) profile_active: bool,
    /// One-based id of the scheduler running this process, like `erts_get_scheduler_id()`
    /// for events raised outside a scheduler context (GC trace).
    pub(crate) scheduler_id: usize,
    /// Number of priority messages at the front of the private mailbox.
    pub(crate) prio_len: usize,
    /// Saved ordinary-message cursor while a newly arrived priority section is scanned.
    pub(crate) priority_resume_cursor: Option<usize>,
    /// The next native entry resumes a raw continuation already on the stack.
    pub(crate) native_continuation_resume: bool,
    /// Live X registers of the resumed native continuation plus one; 0 means the function
    /// arity (yield resume).
    pub(crate) native_resume_live: u8,
    /// A native `wait`/`wait_timeout` asked the scheduler to sleep (timeout in ms, `None` for
    /// `infinity`); the process resumes at the native `loop_rec` label.
    pub(crate) native_wait: Option<Option<u64>>,
    /// Export dispatch to redo after the process wakes from a parked native BIF call.
    pub(crate) native_retry: Option<usize>,
    /// The traced function (by pc), actions and return value of a native trace frame whose
    /// return events the executor emits.
    pub(crate) native_return_events: Option<NativeReturnEvents>,
    /// Sessions whose return_to frame a traced BIF raised through; the exception's catch
    /// reports their return_to events.
    pub(crate) bif_return_to: Vec<u64>,
    /// Pc of the native instruction that raised the exception being dispatched (0 if none).
    pub(crate) native_error_pc: usize,
    /// The current apply comes from native code, whose call site names the caller frame.
    pub(crate) native_apply: bool,
    /// Call site (module, ip) of a traced native BIF whose call event was emitted and which
    /// yielded before finishing, with the trace actions its return events still need.
    /// Native code ran `timeout` while tracing is active; the executor emits the receive event.
    pub(crate) native_timeout_trace: bool,
    pub(crate) traced_native_call: Option<(usize, usize, Vec<crate::trace::CallActions>)>,
    /// Call time and call memory accounting of the process, per trace session.
    // Port of erts/emulator/beam/erl_process.h (ERTS_PSD_CALL_TIME_BP, ERTS_PSD_CALL_MEMORY_BP),
    // OTP-29.1.1.
    pub(crate) call_time: Vec<crate::trace_bp::ProcBpTrace>,
    pub(crate) call_memory: Vec<crate::trace_bp::ProcBpTrace>,
    /// Meta tracers named by return frames on the stack, one entry per frame.
    pub(crate) meta_frames: Vec<std::sync::Arc<crate::trace_bp::MetaTracer>>,
    /// Native call site of the BIF being executed (erts `c_p->i`), 0 outside such a call.
    pub(crate) native_call_pc: usize,
    /// `error_info` of the current native exception (erts keeps it with the stack trace).
    pub(crate) native_error_info: Option<Box<arinsal_etf::OwnedTerm>>,
    /// Remaining time computed by a native `wait_timeout`, consumed by the following wait.
    pub(crate) native_wait_timeout: Option<u64>,
    /// The pending native wait belongs to a receive without clauses.
    pub(crate) native_wait_self: bool,
    /// Native `loop_rec` scheduled out so the scheduler fetches the outer signal queue.
    pub(crate) native_signal_fetch: bool,
    /// The process's outer signal queue: native `loop_rec` probes it and fetches messages.
    pub(crate) signal_probe: Option<arinsal_sched::SignalProbe<crate::process::Message>>,
    /// The scheduler-side private queue was empty when native code was entered, so native
    /// `loop_rec` may fetch messages from the outer queue in place.
    pub(crate) native_inline_fetch: bool,
    /// Static NIF identity, native return point and target scheduler class of a NIF call
    /// (or `enif_schedule_nif` continuation) waiting for a scheduler of that class.
    pub(crate) native_dirty_nif: Option<(usize, usize, arinsal_bifs::SchedulerClass)>,
    /// Return address and call site of the native call that `native_retry` redoes.
    pub(crate) native_retry_site: Option<(usize, usize)>,
    /// The interpreter returned only to hand control to `native_pc`; the slice continues.
    pub(crate) native_transfer: bool,
    /// A system task woke the process while it was executing; it runs at the next scheduling
    /// point instead.
    pub(crate) sys_tasks_deferred: bool,
    /// Native continuation to install after an interpreted external call returns.
    pub(crate) native_resume_after_call: Option<usize>,
    /// The BIF failure behind the current native exception, so the scheduler can name the BIF
    /// and its arguments as the top frame (erts passes the MFA to `raise_exception`).
    pub(crate) native_bif_error: Option<NativeBifError>,
    /// A table BIF failure raised from the direct path with its BIF frame already built, as
    /// erts' BIF returns THE_NON_VALUE with `freason`/`fvalue` set; the call is not redone.
    pub(crate) native_trap: Option<NativeTrap>,
    /// Stable snapshot and cursor for a trapped `persistent_term:get/0` call.
    pub(crate) persistent_get_all: Option<PersistentGetAll>,
    /// Result of a published `persistent_term` update, returned when the yielded
    /// updater runs again (erts resumes the suspended updater after `table_updater`).
    pub(crate) persistent_update_result: Option<Term>,
    /// Modules a suspended `finish_loading/1` staged; they commit when it is rescheduled
    /// after its code barrier, or when the loader exits first.
    pub(crate) finish_loading_commit: Option<crate::load::StagedLoad>,
    /// Breakpoint update a trace BIF caller finishes between code barriers while it holds
    /// the code modification permission.
    pub(crate) trace_finish: Option<crate::trace_bp::TraceFinish>,
    /// Storage of a table being released by a trapped `ets:delete/1` or
    /// `ets:internal_delete_all/2`.
    pub(crate) ets_free: Option<EtsFree>,
    /// Module and instruction of a `call_ext_last` whose frame was already released when its
    /// BIF yielded, so the re-executed instruction does not release it twice.
    pub(crate) ext_last_released: Option<(usize, usize)>,
    /// Exit work (owned ETS tables) that yielded; the process stays scheduled until it ends.
    pub(crate) exit_cont: Option<Box<ExitCont>>,
    /// A process-local BIF trap waiting for its private continuation export.
    pub(crate) bif_trap: Option<BifTrapPending>,
    /// Operand registers of `apply` calls in progress. A callee may collect before it
    /// yields back to re-execute the apply, so these stay GC roots until it returns.
    pub(crate) apply_roots: Vec<Term>,
    /// A NIF call rescheduled to another scheduler class; its arguments are GC roots.
    pub(crate) nif_pending: Option<crate::natives::nif::PendingNif>,
    /// Explicit `exit/1` reason, owned off-heap. The process heap is collected
    /// while the stacktrace is built, so a raw `Term` here would dangle and
    /// monitors would observe a corrupted reason.
    pub(crate) exit_reason: Option<Term>,
    /// Spawned MFA entry that resolves to a runtime BIF export.
    pub(crate) initial_bif: Option<(String, String, u8)>,
    /// Spawn MFA reported by `process_info(Pid, initial_call)`
    /// (erts: `ErtsProcess.u.initial`, set by `erts_create_process`).
    pub(crate) initial_call: Option<(String, String, u8)>,
    /// GC requests received while GC was disabled (`erts_set_gc_state`); replayed
    /// once it is enabled again. Port of erl_process.c:10831 (`save_gc_task`).
    pub(crate) delayed_gc: Vec<DelayedGc>,
    /// Set while the process handles its signals before executing code (erts
    /// `ERTS_PSFLG_RUNNING_SYS`): the only place system tasks execute (erl_process.c
    /// execute_sys_tasks), as no Erlang, native or BIF code is half-way done; a potentially
    /// long GC request there moves the process to a dirty CPU scheduler.
    pub(crate) sys_task_point: bool,
    /// A potentially long GC request waits in `delayed_gc` for a dirty CPU scheduler.
    pub(crate) dirty_sys_gc: bool,
    /// erts `F_DIRTY_MAJOR_GC` / `F_DIRTY_MINOR_GC`: a potentially long collection the
    /// process started itself waits for a dirty CPU scheduler.
    pub(crate) dirty_gc: Option<DirtyGc>,
    /// erts `F_HAVE_BLCKD_MSCHED | F_HAVE_BLCKD_NMSCHED`: this process holds a
    /// multi-scheduling block of its runtime.
    pub(crate) have_blocked_multi_scheduling: bool,
    pub(crate) dictionary_heap: arinsal_term::VecHeap,
    pub(crate) flags: HashMap<String, Term>,
    pub(crate) monitor_nodes: usize,
    pub(crate) group_leader: Option<arinsal_sched::Pid>,
    pub(crate) receive_markers: Option<Box<receive::ReceiveMarkers>>,
    pub(crate) receive_marker_uniq: i64,
    pub(crate) links: std::collections::BTreeSet<arinsal_sched::Pid>,
    /// Links created with `link/2` `[priority]` — EXIT messages from these are priority.
    pub(crate) prio_links: std::collections::BTreeSet<arinsal_sched::Pid>,
    pub(crate) monitors: std::collections::BTreeMap<u64, arinsal_sched::Pid>,
    /// Monitors created with the `priority` option — DOWN messages are priority.
    pub(crate) prio_monitors: std::collections::BTreeSet<u64>,
    pub(crate) monitored_by: std::collections::BTreeMap<u64, arinsal_sched::Pid>,
    pub(crate) aliases: std::collections::HashSet<u64>,
    /// Monitor message tag, owned off-heap. A tuple tag such as
    /// `{'ON_LOAD_DOWN', Mod}` must survive GC until the monitored process exits.
    pub(crate) monitor_tags: std::collections::BTreeMap<u64, arinsal_etf::OwnedTerm>,
    /// Registered name of monitors created by name; their `DOWN` object is `{Name, Node}`.
    pub(crate) monitor_names: std::collections::BTreeMap<u64, String>,
}

pub(crate) struct PersistentGetAll {
    pub(crate) snapshot: arinsal_pterm::Snapshot,
    /// Next hash-table bucket to inspect, matching OTP's trapped iterator.
    pub(crate) cursor: usize,
    pub(crate) remaining: usize,
    pub(crate) result: Term,
}

/// The resumable part of an interrupted BIF call.
pub(crate) struct BifTrapPending {
    pub(crate) caller_module: usize,
    pub(crate) caller_ip: usize,
    /// Set by a light BIF call that trapped: the scheduler still has to context-switch
    /// (erts `context_switch_simplified`) and bind the trap to its native call site.
    pub(crate) schedule_out: bool,
    pub(crate) import: usize,
    pub(crate) continuation: &'static str,
    pub(crate) state: std::sync::Arc<arinsal_term::MagicRef>,
    pub(crate) gc_was_enabled: bool,
    /// The call's arguments, kept with the trap state like the arguments of a BIF_TRAP export:
    /// a retry never reads them back from the X registers.
    pub(crate) args: [Term; 3],
    /// Number of meaningful entries in `args`.
    pub(crate) arity: usize,
    /// The trapped BIF's module and function: an `apply` that trapped is redone as
    /// `apply(Module, Function, Args)` built from the trap state.
    pub(crate) callee: (arinsal_term::Atom, arinsal_term::Atom),
}
impl Process {
    /// Returns the BeamAsm ABI prefix for direct native entry and runtime hooks.
    pub fn native_header(&mut self) -> &mut ProcessHeader {
        &mut self.header
    }

    /// Push a registered native return address onto the Erlang stack.
    pub fn push_native_continuation(&mut self, address: usize) -> Result<(), &'static str> {
        if native_function_at(address).is_none() {
            return Err("native continuation is not registered");
        }
        if !self.heap.reserve_stack(1) {
            return Err("process stack is full");
        }
        let continuation = native_continuation_term(address);
        if !self.heap.stack_set(0, continuation) {
            return Err("process stack update failed");
        }
        self.sync_header();
        Ok(())
    }

    /// Replace the current interpreter continuation with a native continuation.
    pub fn replace_native_continuation(&mut self, address: usize) -> Result<(), &'static str> {
        if native_function_at(address).is_none() {
            return Err("native continuation is not registered");
        }
        if self.heap.stack_get(0).is_none()
            || !self.heap.stack_set(0, native_continuation_term(address))
        {
            return Err("process continuation is missing");
        }
        self.sync_header();
        Ok(())
    }

    /// Attaches the process to its node and registers it with the node's persistent-term
    /// store (its literal-area collector handshake).
    pub(crate) fn set_runtime(&mut self, runtime: Option<std::sync::Arc<crate::process::Runtime>>) {
        let scope = runtime.as_ref().map_or(0, |runtime| runtime.code_scope);
        if let Some(runtime) = runtime.as_deref() {
            // A new process takes `system_flag(min_bin_vheap_size)` of the runtime it joins;
            // explicit spawn options are applied after this.
            self.heap.set_min_bin_vheap_size(
                crate::natives::sys::gc_spawn_defaults(Some(runtime)).min_bin_vheap_size as u64,
            );
        }
        self.runtime = runtime;
        if !std::ptr::eq(
            self._persistent_terms.store(),
            arinsal_pterm::store_for(scope),
        ) {
            self._persistent_terms = arinsal_pterm::store_for(scope).register_process();
        }
    }

    /// Select a registered native function as the process's next entry point.
    pub fn set_native_entry(&mut self, address: usize) -> Result<(), &'static str> {
        if native_function_at(address).is_none() {
            return Err("native entry is not registered");
        }
        self.native_pc = Some(address);
        Ok(())
    }

    /// Copy interpreter-owned state to the ABI prefix at native boundaries.
    // Interpreter fields are authoritative outside native execution. This boundary copy
    // keeps the fixed prefix authoritative while BeamAsm owns the process registers.
    pub(crate) fn sync_header(&mut self) {
        let (htop, stop) = self.heap.heap_cursor();
        let (heap, hend) = self.heap.heap_bounds();
        self.header.htop = htop;
        self.header.stop = stop;
        self.header.heap = heap;
        self.header.hend = hend;
        self.header.high_water = self.heap.high_water_ptr();
        self.header.fcalls = self.reductions;
        self.header.i = std::ptr::null();
        self.header.arity = 0;
        self.header.current = std::ptr::null();
    }

    /// Publishes what a runtime call that did not collect can change: the heap and stack
    /// cursors and FCALLS. The heap bounds move only when the process collects.
    // Port of erts/emulator/beam/jit/arm/beam_asm.hpp:540-601 (emit_leave_runtime with
    // Update::eHeap | eStack | eReductions), OTP-29.1.1.
    pub(crate) fn sync_native_cursors(&mut self) {
        let (htop, stop) = self.heap.heap_cursor();
        self.header.htop = htop;
        self.header.stop = stop;
        self.header.fcalls = self.reductions;
    }

    pub(crate) fn sync_native_header(&mut self) {
        let (htop, stop) = self.heap.heap_cursor();
        let (heap, hend) = self.heap.heap_bounds();
        self.header.htop = htop;
        self.header.stop = stop;
        self.header.heap = heap;
        self.header.hend = hend;
        self.header.high_water = self.heap.high_water_ptr();
        self.header.fcalls = self.reductions;
    }

    /// Words allocated by the process since its last collection, plus `adjustment`.
    // Port of erts/emulator/beam/beam_bp.c:989-992 (get_allocated_words), OTP-29.1.1.
    pub(crate) fn allocated_words(&self, adjustment: i64) -> i64 {
        let info = self.heap.gc_info_words();
        adjustment + info.heap_size as i64 - info.recent_size as i64 + info.mbuf_size as i64
    }

    pub(crate) fn cold_mut(&mut self) -> &mut ProcessCold {
        self.cold
            .get_or_insert_with(|| Box::new(ProcessCold::default()))
    }

    /// Remember an explicit exit reason across the GC that builds its stacktrace.
    pub(crate) fn note_exit_reason(&mut self, reason: Term) -> Result<(), VmError> {
        let cold = self.cold_mut();
        let copied = arinsal_term::copy_term(reason, &mut cold.dictionary_heap)
            .map_err(|error| VmError::Unsupported(format!("exit reason: {error:?}")))?;
        cold.exit_reason = Some(copied);
        Ok(())
    }
    /// Construct a process with the erts minimum heap size.
    pub fn new() -> Self {
        Self::with_registers_and_min_heap(1024, 1024, 233)
    }
    #[cfg(test)]
    pub(crate) fn with_registers(x_registers: usize, float_registers: usize) -> Self {
        Self::with_registers_and_min_heap(x_registers, float_registers, 64)
    }
    pub(crate) fn with_spawn_registers(x_registers: usize, float_registers: usize) -> Self {
        let mut process = Self::with_registers_and_min_heap(x_registers, float_registers, 233);
        // Port of erts/emulator/beam/erl_process.c (erl_create_process: c_p->arity = arg
        // count): a collection before the first run must keep the initial arguments alive.
        process.gc_live = x_registers;
        process
    }
    pub(crate) fn with_registers_and_min_heap(
        x_registers: usize,
        float_registers: usize,
        min_heap: usize,
    ) -> Self {
        #[cfg(feature = "pf-mem-counters")]
        let started = std::time::Instant::now();
        let mut heap = if min_heap == 64 {
            ProcessHeap::with_words(0)
        } else {
            ProcessHeap::with_words(min_heap)
        };
        // Float-heavy BEAM code allocates short-lived boxes between tests.
        // Keeping a modest young generation avoids collecting every few instructions.
        heap.set_min_heap_size(min_heap);
        heap.set_min_bin_vheap_size(
            crate::natives::sys::gc_spawn_defaults(None).min_bin_vheap_size as u64,
        );
        let mut process = Self {
            header: ProcessHeader::default(),
            x: vec![Term::NIL; x_registers].into_boxed_slice(),
            fr: vec![0.0; float_registers].into_boxed_slice(),
            heap,
            dictionary: None,
            seq_trace_token: None,
            module: 0,
            ip: 0,
            initial_call: None,
            native_pc: None,
            entry_started: false,
            gc_live: 0,
            max_heap_peak: 0,
            reductions: 4000,
            reductions_used: 0,
            gc_enabled: true,
            gc_deferred: false,
            uniq_counter: 0,
            stats: ProcessStats::default(),
            final_exit_reason: None,
            runtime: None,
            self_pid: None,
            pending_signal_waiter: None,
            scheduler_id: 0,
            hibernated: false,
            inbox: process::MessageQueue::default(),
            receive_cursor: 0,
            receive_deadline: None,
            receive_deadline_ms: None,
            cold: None,
            _persistent_terms: arinsal_pterm::global_store().register_process(),
            trap_exit: false,
            exc_class: None,
            entry: false,
            force_yield: false,
        };
        process.sync_header();
        #[cfg(feature = "pf-mem-counters")]
        if min_heap == 233 {
            PF_SPAWN_CONSTRUCTS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            PF_SPAWN_CONSTRUCT_NS.fetch_add(
                started.elapsed().as_nanos() as u64,
                std::sync::atomic::Ordering::Relaxed,
            );
        }
        process
    }
    #[cold]
    #[inline(never)]
    pub(crate) fn ensure(&mut self, words: usize, live: usize) -> Result<(), VmError> {
        self.ensure_roots(words, live, true)
    }
    /// Collect with `live` X roots.
    ///
    /// `clear_dead` nils registers outside that prefix after a moving
    /// collection. Allocation sites do this so a later wider scan cannot
    /// follow the evacuated heap. A call passes `false`: erts roots only the
    /// callee arguments and leaves the other X words unchanged.
    #[cold]
    #[inline(never)]
    pub(crate) fn ensure_roots(
        &mut self,
        words: usize,
        live: usize,
        clear_dead: bool,
    ) -> Result<(), VmError> {
        if live > self.x.len() {
            return Err(VmError::Unsupported("live X register count".into()));
        }
        self.gc_live = live;
        let words = words + self.heap.allocation_reserve();
        // Port of erts/emulator/beam/erl_gc.h:132-139 (ERTS_IS_GC_DESIRED), OTP-29.1.1.
        if self.heap.free_words() >= words && !self.heap.bin_vheap_gc_due() && !gc_stress_enabled()
        {
            return Ok(());
        }
        if !self.gc_enabled {
            return Err(VmError::Trap(exceptions::Trap::error(Term::atom(
                arinsal_term::atoms::SYSTEM_LIMIT,
            ))));
        }
        let gc = self.collect_heap_roots(live, &mut [], words)?;
        // Port of erts/emulator/beam/erl_gc.c:2639 (setup_rootset nobj), OTP-29.1.1.
        // The collector rewrites only the live prefix. Nilling the rest is an
        // extra guard for a later scan that roots a wider prefix than this one.
        if clear_dead {
            self.x[live..].fill(Term::NIL);
        }
        natives::sys::after_collection(self, live, gc.collections, gc.words_reclaimed);
        if self.heap.free_words() < words {
            return Err(VmError::Unsupported("heap exhausted after GC".into()));
        }
        Ok(())
    }
    pub(crate) fn read(&self, arg: Arg) -> Result<Term, VmError> {
        let term = match arg.kind() {
            Arg::X => self
                .x
                .get(arg.value() as usize)
                .copied()
                .ok_or_else(|| VmError::Unsupported("X register out of range".into()))?,
            Arg::Y => self
                .heap
                .stack_get(arg.value() as usize)
                .ok_or_else(|| VmError::Unsupported("Y register out of range".into()))?,
            Arg::TERM => arg.term(),
            Arg::U => i64::try_from(arg.value())
                .ok()
                .and_then(Term::small)
                .ok_or_else(|| VmError::Unsupported("large integer operand".into()))?,
            Arg::INT => Term::small(arg.signed())
                .ok_or_else(|| VmError::Unsupported("large integer operand".into()))?,
            Arg::UNSUPPORTED => {
                return Err(VmError::Unsupported(format!("literal {}", arg.value())));
            }
            _ => {
                return Err(VmError::Unsupported(format!(
                    "source operand kind {}",
                    arg.kind()
                )));
            }
        };
        // g_asan
        #[cfg(any(feature = "validate-terms", debug_assertions))]
        arinsal_term::validate::check_if_active(&self.heap, term);
        Ok(term)
    }
    pub(crate) fn write(&mut self, dst: Arg, value: Term) -> Result<(), VmError> {
        match dst.kind() {
            Arg::X => {
                *self
                    .x
                    .get_mut(dst.value() as usize)
                    .ok_or_else(|| VmError::Unsupported("X register out of range".into()))? = value;
                Ok(())
            }
            Arg::Y if self.heap.stack_set(dst.value() as usize, value) => Ok(()),
            _ => Err(VmError::Unsupported("invalid destination".into())),
        }
    }
    pub(crate) fn float(&self, src: Arg) -> Result<f64, VmError> {
        if src.kind() == Arg::FR {
            return self
                .fr
                .get(src.value() as usize)
                .copied()
                .ok_or_else(|| VmError::Unsupported("FR register out of range".into()));
        }
        let term = self.read(src)?;
        floats::number(term).ok_or_else(|| VmError::Exception {
            reason: "badarith".into(),
            frame: "float conversion".into(),
        })
    }
    pub(crate) fn set_float(&mut self, dst: Arg, value: f64) -> Result<(), VmError> {
        if !value.is_finite() {
            return Err(VmError::Exception {
                reason: "badarith".into(),
                frame: "float operation".into(),
            });
        }
        if dst.kind() == Arg::FR {
            *self
                .fr
                .get_mut(dst.value() as usize)
                .ok_or_else(|| VmError::Unsupported("FR register out of range".into()))? = value;
            return Ok(());
        }
        if self.heap.free_words() < 2 {
            self.ensure(2, self.gc_live)?;
        }
        let term = TermBuilder::new(&mut self.heap)
            .float(value)
            .map_err(|e| VmError::Unsupported(format!("float allocation {e:?}")))?;
        self.write(dst, term)
    }
    pub(crate) fn tick(&mut self) {
        self.reductions -= 1;
        if self.reductions == 0 {
            self.reductions = 4000;
        }
    }
}

pub(crate) fn native_continuation_term(address: usize) -> Term {
    // SAFETY: The native range registry establishes that this raw word is a code address.
    unsafe { Term::from_raw_bits(address as u64) }
}
impl Default for Process {
    fn default() -> Self {
        Self::new()
    }
}

/// A table BIF exception with its BIF frame built, kept until the native exit raises it.
pub(crate) struct NativeTrap {
    pub(crate) trap: crate::exceptions::Trap,
    /// The `c_p->freason`/`fvalue` pair this error produced; any other exception ignores it.
    pub(crate) freason: u64,
    pub(crate) fvalue: u64,
}

/// A BIF failure raised from native code, kept until the native exit builds the exception.
pub(crate) struct NativeBifError {
    pub(crate) module: String,
    pub(crate) function: String,
    pub(crate) args: Vec<Term>,
    pub(crate) error: arinsal_bifs::BifError,
    /// The `c_p->freason`/`fvalue` pair this error produced; any other exception ignores it.
    pub(crate) freason: u64,
    pub(crate) fvalue: u64,
}

/// Kind of a collection scheduled on a dirty CPU scheduler.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DirtyGc {
    /// erts `F_DIRTY_MAJOR_GC`.
    Major,
    /// erts `F_DIRTY_MINOR_GC`.
    Minor,
}

/// A garbage-collection request saved while `F_DISABLE_GC` was set.
pub(crate) enum DelayedGc {
    /// Plain `garbage_collect` request.
    Collect,
    /// Asynchronous `garbage_collect/2,3` request whose reply is still owed.
    Request(crate::signals::Pending),
    /// Literal-area copy phase that needs a collection.
    Literal {
        area_id: u64,
        request: crate::process::Message,
        how: arinsal_sched::LiteralCopyHow,
        requester: arinsal_sched::Pid,
    },
}

/// Port of erts/emulator/beam/erl_db.c:3006-3080 (ets_delete_1 continuation) and
/// erl_db.c:3234 (ets_internal_delete_all_2), OTP-29.1.1: what a trapped call still has to free.
pub(crate) struct EtsFree {
    /// Table whose objects were detached by `ets:internal_delete_all/2`; `None` for `ets:delete/1`.
    pub(crate) tid: Option<arinsal_ets::Tid>,
    /// Object count `ets:internal_delete_all/2` returns when done.
    pub(crate) nitems: usize,
    pub(crate) garbage: arinsal_ets::Garbage,
}

/// Port of erts/emulator/beam/erl_process.c:14160 (erts_continue_exit_process trap state),
/// OTP-29.1.1: the part of process exit that is resumed after a yield.
pub(crate) struct ExitCont {
    pub(crate) reason: arinsal_term::Term,
    /// Storage of the owned table whose release was interrupted (`FREE_OWNED_TABLE`).
    pub(crate) garbage: Option<arinsal_ets::Garbage>,
    /// Result the entry process reports once exit completes, and its exit code.
    pub(crate) entry_result: Option<Result<crate::ScheduledResult, crate::VmError>>,
    pub(crate) code: u64,
}

#[cfg(test)]
mod procdict_tests {
    use super::ProcDict;

    #[test]
    fn array_size_matches_erts_search() {
        for (need, expect) in [
            (1, 1),
            (8, 8),
            (9, 9),
            (10, 10),
            (11, 20),
            (20, 20),
            (21, 40),
            (5120, 5120),
            (5121, 10240),
        ] {
            assert_eq!(ProcDict::next_array_size(need), expect, "need {need}");
        }
    }

    #[test]
    fn initial_table_is_eight_slots() {
        let mut dict = ProcDict::default();
        let key = arinsal_term::Term::small(1).unwrap();
        assert_eq!(dict.put(key, key), None);
        assert_eq!(dict.array_size, 8);
        assert_eq!(dict.used_slots, 8);
        assert_eq!(dict.size_mask, 15);
        assert_eq!(dict.split_position, 0);
        // PD_SZ2BYTES(8) = 32 + 7*8.
        assert_eq!(dict.memory_bytes(), 88);
    }

    #[test]
    fn integers_survive_grow_and_shrink() {
        let mut dict = ProcDict::default();
        for n in 1..=2000 {
            let key = arinsal_term::Term::small(n).unwrap();
            assert_eq!(dict.put(key, key), None);
        }
        assert_eq!(dict.len(), 2000);
        for n in 1..=2000 {
            let key = arinsal_term::Term::small(n).unwrap();
            assert_eq!(dict.get(key), Some(key));
        }
        for n in 1..=2000 {
            let key = arinsal_term::Term::small(n).unwrap();
            assert_eq!(dict.erase(key), Some(key));
        }
        assert_eq!(dict.len(), 0);
        assert!(dict.entries().next().is_none());
    }
}
