//! Process storage and construction.

use super::*;

/// Why native code left for the scheduler. One byte of the process, set by the helper that
/// requests the exit, so the exit path is one load and one match.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum NativeExit {
    #[default]
    None,
    /// A traced `timeout` left its event for the scheduler (`ColdState::native_timeout_trace`).
    TimeoutTrace,
    /// `recv_marker_reserve` needs the outer signal queue fetched first.
    ReserveFetch,
    /// `loop_rec` reached the end of the message queue with signals to fetch or handle.
    SignalFetch,
    /// `wait` or `wait_timeout` (`ColdState::native_wait`).
    Wait,
}

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

/// Number of X registers a scheduler array holds (`ERTS_X_REGS_ALLOCATED`, erl_vm.h).
pub const ATTACHED_X_REGS: usize = 1024;

/// `esdp->registers->f_reg_array` length.
pub const ATTACHED_F_REGS: usize = 1024;

/// X registers, in one of two representations.
///
/// Owned (scheduled out): the saved arguments. The first six live in the process, like
/// `def_arg_reg[6]` (erl_process.h:1079); a longer file is a separate block, like `arg_reg`
/// when `max_arg_reg` exceeds `sizeof(def_arg_reg)`. The slice is `arity` registers long.
///
/// Attached (running): a pointer to the scheduler's single X register array
/// (`esdp->registers->x_reg_array`), `ATTACHED_X_REGS` long. The owned storage and its
/// `arity` are kept untouched until `detach_save` copies the live registers back, like
/// `copy_out_registers` at schedule-out.
///
/// An attached file also carries the address of `esdp->registers->f_reg_array`. erts saves no
/// float register across a scheduling point (they are dead there), so that array is the float
/// file for the slice and nothing is copied in or out.
pub struct ArgRegs {
    inline: [Term; 6],
    extra: Box<[Term]>,
    len: usize,
    /// Address of the scheduler array while attached, zero otherwise. An address and not a
    /// pointer so `Process` stays `Sync` without an `unsafe impl`.
    attached: usize,
    /// Address of the scheduler's float register array while attached, zero otherwise.
    f_attached: usize,
}

impl ArgRegs {
    /// `len` registers, all `NIL`. Lengths up to 6 do not allocate.
    pub fn new(len: usize) -> Self {
        if len <= 6 {
            Self {
                inline: [Term::NIL; 6],
                extra: Box::from([]),
                len,
                attached: 0,
                f_attached: 0,
            }
        } else {
            Self {
                inline: [Term::NIL; 6],
                extra: vec![Term::NIL; len].into_boxed_slice(),
                len,
                attached: 0,
                f_attached: 0,
            }
        }
    }

    pub fn empty() -> Self {
        Self::new(0)
    }

    /// True while the registers are the scheduler's array.
    #[inline]
    pub fn is_attached(&self) -> bool {
        self.attached != 0
    }

    /// The saved argument count (`c_p->arity`): the length of the owned file, which an
    /// attached file keeps until `detach_save`.
    #[inline]
    pub fn saved_arity(&self) -> usize {
        self.len
    }

    /// True while the saved registers fit the inline block, `arg_reg == def_arg_reg`. A file
    /// that once grew past six keeps its separate block, as `arg_reg` does until the process
    /// is freed.
    #[inline]
    pub fn is_def_arg_reg(&self) -> bool {
        self.extra.is_empty()
    }

    /// Bytes `erts_process_memory` adds for the saved registers: `arity` words, and only when
    /// `arg_reg` is not the inline default.
    // Port of erts/emulator/beam/erl_process_dump.c (`erts_process_memory`), OTP-29.1.1.
    #[inline]
    pub fn arg_reg_bytes(&self) -> usize {
        if self.is_def_arg_reg() {
            0
        } else {
            self.len * std::mem::size_of::<Term>()
        }
    }

    /// Schedule-in (`copy_in_registers`): copy the `saved_arity` saved registers into
    /// `registers.x_reg_array` and make it the X file. The saved storage and `saved_arity`
    /// stay untouched until `detach_save`.
    ///
    /// # Safety
    /// `registers` must stay alive and at the same address until the matching `detach_save`,
    /// and nothing else may reach `registers.x_reg_array` through a reference that is live
    /// across a use of this file.
    pub unsafe fn attach(&mut self, registers: &mut arinsal_beamasm::SchedulerRegisters) {
        assert!(self.attached == 0, "X registers are already attached");
        assert!(
            self.len <= ATTACHED_X_REGS,
            "saved arity {} exceeds the X array",
            self.len
        );
        let len = self.len;
        let saved: &[Term] = if len <= 6 {
            &self.inline[..len]
        } else {
            &self.extra[..len]
        };
        registers.x_reg_array[..len].copy_from_slice(saved);
        self.attached = registers.x_reg_array.as_mut_ptr() as usize;
        self.f_attached = registers.f_reg_array.as_mut_ptr() as usize;
    }

    /// Schedule-out (`copy_out_registers`): copy the first `arity` array registers into the
    /// owned file, growing it past six like `arg_reg`, record `arity`, and drop the
    /// attachment.
    pub fn detach_save(&mut self, arity: usize) {
        assert!(
            arity <= ATTACHED_X_REGS,
            "arity {arity} exceeds the X array"
        );
        assert!(self.attached != 0, "X registers are not attached");
        if arity <= 6 {
            let mut saved = self.inline;
            saved[..arity].copy_from_slice(&self[..arity]);
            self.inline = saved;
        } else {
            let mut block = std::mem::take(&mut self.extra);
            if block.len() < arity {
                block = vec![Term::NIL; arity].into_boxed_slice();
            }
            block[..arity].copy_from_slice(&self[..arity]);
            self.extra = block;
        }
        self.len = arity;
        self.attached = 0;
        self.f_attached = 0;
    }

    /// The scheduler's float register array while attached (`f_reg_array`, 1024 long), or
    /// null.
    #[inline]
    pub fn float_ptr(&self) -> *mut f64 {
        self.f_attached as *mut f64
    }

    /// The attached float register array, or `None` while the registers are owned.
    #[inline]
    pub fn attached_floats(&mut self) -> Option<&mut [f64]> {
        if self.f_attached == 0 {
            return None;
        }
        // SAFETY: `attach` took the address from the scheduler's live `f_reg_array`, which stays
        // alive and in place until `detach_save`; `&mut self` makes this the only access to it
        // through the process.
        Some(unsafe {
            std::slice::from_raw_parts_mut(self.f_attached as *mut f64, ATTACHED_F_REGS)
        })
    }

    /// Make at least `n` registers addressable. Owned: grow, keeping the registers and
    /// filling the new ones with `NIL`. Attached: nothing to do, the array has
    /// `ATTACHED_X_REGS` registers.
    #[inline]
    pub fn ensure_x(&mut self, n: usize) {
        if self.attached != 0 {
            debug_assert!(n <= ATTACHED_X_REGS);
            return;
        }
        if n > self.len {
            self.grow_owned(n);
        }
    }

    #[cold]
    fn grow_owned(&mut self, n: usize) {
        let len = self.len;
        if n > 6 {
            if self.extra.len() < n {
                let mut grown = vec![Term::NIL; n];
                let old: &[Term] = if len <= 6 {
                    &self.inline[..len]
                } else {
                    &self.extra[..len]
                };
                grown[..len].copy_from_slice(old);
                self.extra = grown.into_boxed_slice();
            } else {
                if len <= 6 {
                    self.extra[..len].copy_from_slice(&self.inline[..len]);
                }
                self.extra[len..n].fill(Term::NIL);
            }
        } else {
            self.inline[len..n].fill(Term::NIL);
        }
        self.len = n;
    }
}

impl From<Vec<Term>> for ArgRegs {
    fn from(values: Vec<Term>) -> Self {
        let len = values.len();
        if len <= 6 {
            let mut inline = [Term::NIL; 6];
            inline[..len].copy_from_slice(&values);
            Self {
                inline,
                extra: Box::from([]),
                len,
                attached: 0,
                f_attached: 0,
            }
        } else {
            Self {
                inline: [Term::NIL; 6],
                extra: values.into_boxed_slice(),
                len,
                attached: 0,
                f_attached: 0,
            }
        }
    }
}

impl std::ops::Deref for ArgRegs {
    type Target = [Term];

    #[inline]
    fn deref(&self) -> &[Term] {
        if self.attached != 0 {
            // SAFETY: `attach` took the address from a live `[Term; ATTACHED_X_REGS]` that the
            // scheduler keeps alive and in place until `detach_save`.
            return unsafe {
                std::slice::from_raw_parts(self.attached as *const Term, ATTACHED_X_REGS)
            };
        }
        if self.len <= 6 {
            &self.inline[..self.len]
        } else {
            &self.extra[..self.len]
        }
    }
}

impl std::ops::DerefMut for ArgRegs {
    #[inline]
    fn deref_mut(&mut self) -> &mut [Term] {
        if self.attached != 0 {
            // SAFETY: as in `deref`; `&mut self` makes this the only access to the array
            // through the process.
            return unsafe {
                std::slice::from_raw_parts_mut(self.attached as *mut Term, ATTACHED_X_REGS)
            };
        }
        if self.len <= 6 {
            &mut self.inline[..self.len]
        } else {
            &mut self.extra[..self.len]
        }
    }
}

/// One future schedulable process, with private registers and heap.
#[repr(C)]
pub struct Process {
    /// BeamAsm ABI prefix; interpreter fields remain authoritative outside native execution.
    pub(crate) header: ProcessHeader,
    /// X registers. Inline for the erts default of six (`def_arg_reg`).
    pub x: ArgRegs,
    /// Float registers of a process that runs outside a scheduler slice (an evaluation on its
    /// own thread). Inside a slice the float file is the scheduler's `f_reg_array`, reached
    /// through `x`, and this stays empty.
    pub fr: Box<[f64]>,
    /// Contiguous process heap and Y stack.
    pub heap: ProcessHeap,
    /// The erts process dictionary pointer is part of the hot process structure.
    pub(crate) dictionary: Option<ProcDict>,
    /// Per-process sequential trace token; `None` is the no-token fast path.
    pub(crate) seq_trace_token: Option<Box<crate::seq_trace::Token>>,
    /// The token tuple that `SEQ_TRACE_TOKEN(p)` names on the young heap: a collection roots
    /// it like erts' `setup_rootset`, so its words stay live. `NIL` when the token has no
    /// heap copy.
    pub(crate) seq_token_root: Term,
    /// `p->seq_trace_clock` and `p->seq_trace_lastcnt` (erl_process.h:1112); the epoch of the
    /// last `seq_trace:reset_trace/0` this process has applied.
    pub(crate) seq_trace_clock: u64,
    pub(crate) seq_trace_lastcnt: u64,
    pub(crate) seq_trace_epoch: u64,
    /// A spawned child whose first action is the spawn reply: the token update of
    /// erl_process.c:12960-12965 happens when it first runs.
    pub(crate) seq_trace_spawn_pending: bool,
    pub(crate) module: usize,
    pub(crate) ip: usize,
    pub(crate) initial_call: Option<(usize, usize)>,
    /// `p->u.initial` (erl_process.c:12693): the MFA the process was spawned with, as atoms.
    pub(crate) initial_mfa: Option<(arinsal_term::Atom, arinsal_term::Atom, u8)>,
    pub(crate) native_pc: Option<usize>,
    /// The entry process has been scheduled once (its native start is decided then).
    pub(crate) entry_started: bool,
    // Last BEAM live operand or call arity for allocation instructions without one.
    pub(crate) gc_live: usize,
    /// Largest total heap size seen at a collection entry since the last `max_heap_size` check.
    pub(crate) max_heap_peak: usize,
    pub(crate) reductions: i32,
    /// `REDS_IN`: FCALLS at the start of the current native slice.
    /// `erts_current_reductions` is this minus the live `c_p->fcalls`.
    pub(crate) native_reds_in: i32,
    /// FCALLS the last trapping BIF handler spent on its own, before the call's charge.
    pub(crate) trap_work: i32,
    /// `esdp->virtual_reds`: reductions the slice gave up through `ERTS_VBUMP_ALL_REDS` since
    /// the scheduler last folded them. They end the slice but are not the process's own work.
    pub(crate) virtual_reds: u32,
    pub(crate) reductions_used: u64,
    pub(crate) gc_deferred: bool,
    /// erts `F_DELAY_GC`: set from `loop_rec` until `remove_message` or the wait, while x0
    /// may refer to a queued message whose data is still in its heap fragment.
    // Port of erts/emulator/beam/erl_process.h:1643, 1728-1736 (F_DELAY_GC), OTP-29.1.1.
    pub(crate) delay_gc: bool,
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
    /// Reference and `unique_integer` counters of the scheduler running this process.
    /// Port of `c_p->scheduler_data` (`ref` and `unique`), OTP-29.1.1.
    pub(crate) scheduler_ref_state: Option<arinsal_bifs::SchedulerRefState>,
    /// `F_HIBERNATED`: the heap holds exactly the live data of a hibernated process.
    pub(crate) hibernated: bool,
    pub(crate) inbox: process::MessageQueue,
    /// `sig_qs.cont`: signals fetched from the outer queue and not handled yet.
    /// Port of erts/emulator/beam/erl_process.h (ErtsSignalInQueue `sig_qs`), OTP-29.1.1.
    pub(crate) sig_cont: arinsal_sched::SignalQueue<arinsal_sched::Event<crate::process::Message>>,
    /// Signals taken from the front of `sig_cont` so far; receive markers inserted into the
    /// middle queue are positioned by it.
    pub(crate) sig_cont_taken: u64,
    pub(crate) receive_cursor: usize,
    pub(crate) receive_deadline: Option<std::time::Instant>,
    pub(crate) receive_deadline_ms: Option<u64>,
    /// `F_TIMO` for `wait_timeout infinity`: the wait is initialised, so a wakeup must not
    /// re-read the operand (erts/emulator/beam/emu/msg_instrs.tab, wait.src).
    pub(crate) receive_infinity: bool,
    pub(crate) cold: Option<Box<ProcessCold>>,
    /// `p->group_leader`. Kept on the process so a spawn does not allocate `ProcessCold`.
    pub(crate) group_leader: Option<arinsal_sched::Pid>,
    /// `p->parent` (erl_process.c:12756): the spawning process, `None` (`undefined`) for the
    /// first process; a remote parent's external pid is `ProcessCold::parent_external`.
    pub(crate) parent: Option<arinsal_sched::Pid>,
    /// `p->u.terminate`. erts reuses the initial-call union; a side `ProcessCold` would
    /// allocate on every exit.
    pub(crate) exit_cont: Option<Box<ExitCont>>,
    /// Outermost `apply` operands that must stay GC roots. Nested applies spill into
    /// `ProcessCold.apply_roots`.
    pub(crate) apply_inline: [Term; 3],
    pub(crate) apply_inline_len: u8,
    // Retired persistent-term areas are copied out and acknowledged in
    // `natives::sys::after_collection` on every collection.
    /// The persistent-term store of the node this process runs in.
    pub(crate) persistent_terms: &'static arinsal_pterm::Store,
    pub(crate) trap_exit: bool,
    /// Class of the exception currently being handled. `raise/2` re-raises
    /// this after an `after` block, because that block may clobber X registers.
    /// mix_loop1. Port of the freason kept across `i_raise` (beam_emu), OTP-29.1.1.
    pub(crate) exc_class: Option<arinsal_bifs::Class>,
    pub(crate) entry: bool,
    /// A dist send that suspended must yield even if the queue drains before return.
    pub(crate) force_yield: bool,
    /// The next native entry resumes a raw continuation already on the stack.
    pub(crate) native_continuation_resume: bool,
    /// `header.arity` already holds the live X register count of the resumed native
    /// continuation. Unset, the next native entry is a call and takes the function's arity.
    pub(crate) native_arity_set: bool,
    /// Pc of the native instruction that raised the exception being dispatched (0 if none).
    pub(crate) native_error_pc: usize,
    /// The request native code left for the scheduler. `None` means no request is pending, so
    /// an ordinary yield reads this one byte instead of cold fields.
    pub(crate) native_exit_kind: NativeExit,
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
pub(crate) type NativeReturnEvents = crate::trace::PoppedNativeFrames;

/// What both halves of a monitor share and never change. The DOWN tag and the name are rare,
/// so they live in a separate box, as erts keeps them only in `ErtsMonitorDataExtended` /
/// `ErtsMonitorDataTagHeap` (erl_monitor_link.h) and a plain monitor stays small.
#[derive(Debug, Default)]
pub(crate) struct MonitorInfo(Option<Box<MonitorExtension>>);

#[derive(Debug)]
struct MonitorExtension {
    tag: Option<arinsal_etf::OwnedTerm>,
    name: Option<String>,
}

impl MonitorInfo {
    /// `tag`: the DOWN tag, owned off-heap so a tuple tag such as `{'ON_LOAD_DOWN', Mod}`
    /// survives GC, `None` for the default `DOWN`. `name`: the registered name of a monitor
    /// created by name; its DOWN object is `{Name, Node}`.
    pub(crate) fn new(tag: Option<arinsal_etf::OwnedTerm>, name: Option<String>) -> Self {
        if tag.is_none() && name.is_none() {
            return Self(None);
        }
        Self(Some(Box::new(MonitorExtension { tag, name })))
    }

    pub(crate) fn tag(&self) -> Option<&arinsal_etf::OwnedTerm> {
        self.0.as_ref()?.tag.as_ref()
    }

    pub(crate) fn name(&self) -> Option<&str> {
        self.0.as_ref()?.name.as_deref()
    }
}

/// One half of a monitor this process holds: an origin entry in `ERTS_P_MONITORS` or a target
/// entry in `ERTS_P_LT_MONITORS` (or, for a remote origin, in `ERTS_P_MONITORS`).
/// The signal value a monitor half is sent in.
pub(crate) type MonitorSignal = arinsal_sched::Event<crate::process::Message>;
pub(crate) type ProcessMonitor =
    crate::monitor_link::Monitor<MonitorInfo, OriginMonitor, MonitorSignal>;
/// The allocation both halves of a monitor share (`ErtsMonitorData`).
pub(crate) type ProcessMonitorData =
    crate::monitor_link::MonitorData<MonitorInfo, OriginMonitor, MonitorSignal>;
/// `ERTS_P_MONITORS`: origin halves, and target halves of remote origins, keyed by reference.
pub(crate) type MonitorTree = crate::monitor_link::MonLnkTree<ProcessMonitor>;
/// `ERTS_P_LT_MONITORS`: target halves of local monitors.
pub(crate) type TargetMonitorList =
    crate::monitor_link::MonitorList<MonitorInfo, OriginMonitor, MonitorSignal>;

/// Both halves of a new monitor of `target` by `origin` (erts `erts_monitor_create`): the
/// origin half's `other` is the target, the target half's the origin.
pub(crate) fn create_monitor(
    reference: u64,
    origin: u64,
    target: u64,
    info: MonitorInfo,
    state: OriginMonitor,
) -> (ProcessMonitor, ProcessMonitor) {
    let kind = state.kind();
    crate::monitor_link::Monitor::create(kind, reference, origin, target, 0, info, state)
}

/// The monitor signal of a remote process monitoring local `target` (erts
/// `ERTS_MON_TYPE_DIST_PROC`): the target half in transit, inserted into the target's monitor
/// tree; the origin side of a remote monitor is kept by the distribution tables.
pub(crate) fn remote_monitor_signal(
    reference: u64,
    watcher: arinsal_sched::Pid,
    target: arinsal_sched::Pid,
) -> arinsal_sched::Signal<crate::process::Message> {
    let (_origin, target_half) = create_monitor(
        reference,
        watcher.data(),
        target.data(),
        MonitorInfo::default(),
        OriginMonitor::Distributed { alias_mode: None },
    );
    arinsal_sched::Signal::Monitor {
        reference,
        shared: arinsal_sched::SharedPayload(target_half.into_shared()),
    }
}

/// An origin entry whose target half no process holds: an alias, or a monitor of a port or a
/// remote process, whose other end keeps its own record.
pub(crate) fn origin_monitor(reference: u64, target: u64, state: OriginMonitor) -> ProcessMonitor {
    let (origin, _target) = create_monitor(reference, 0, target, MonitorInfo::default(), state);
    origin
}

/// Alias lifecycle stored in the origin monitor entry.
// Port of erts/emulator/beam/erl_monitor_link.h (ERTS_ML_STATE_ALIAS_*), OTP-29.1.1.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AliasMode {
    ExplicitUnalias,
    Demonitor,
    ReplyDemonitor,
}

/// An origin-side entry in the per-process monitor tree.
// Port of erts/emulator/beam/erl_monitor_link.c (monitor tree origin entries), OTP-29.1.1.
#[derive(Clone, Debug)]
pub(crate) enum OriginMonitor {
    Process(OriginHalf),
    Distributed {
        alias_mode: Option<AliasMode>,
    },
    /// `ERTS_MON_TYPE_PORT`: the port id (none when `name` is not registered) and the
    /// registered name the monitor was created with.
    Port {
        port_id: Option<u64>,
        alias_mode: Option<AliasMode>,
        name: Option<arinsal_term::Atom>,
    },
    /// `ERTS_MON_TYPE_DIST_PORT`: an external port of an old incarnation of this node.
    DistPort {
        alias_mode: Option<AliasMode>,
        /// Boxed so the common origin entries stay small: the monitor tree allocates a node
        /// per entry sized by its largest variant.
        object: Box<arinsal_etf::OwnedTerm>,
    },
    Alias {
        mode: AliasMode,
        priority: bool,
    },
}

impl OriginMonitor {
    /// The erts monitor type of this entry (`ERTS_MON_TYPE_*`).
    pub(crate) fn kind(&self) -> u32 {
        use crate::monitor_link::node_type;
        match self {
            Self::Process(_) => node_type::MONITOR_PROC,
            Self::Distributed { .. } => node_type::MONITOR_DIST_PROC,
            Self::Port { .. } => node_type::MONITOR_PORT,
            Self::DistPort { .. } => node_type::MONITOR_DIST_PORT,
            Self::Alias { .. } => node_type::MONITOR_ALIAS,
        }
    }

    pub(crate) fn alias_mode(&self) -> Option<AliasMode> {
        match self {
            Self::Process(half) => half.alias_mode,
            Self::Distributed { alias_mode }
            | Self::Port { alias_mode, .. }
            | Self::DistPort { alias_mode, .. } => *alias_mode,
            Self::Alias { mode, .. } => Some(*mode),
        }
    }

    pub(crate) fn alias_priority(&self) -> bool {
        matches!(self, Self::Alias { priority: true, .. })
    }
}

/// `ERTS_P_LINKS`: the local links of a process, keyed by the pid at the other end.
pub(crate) type LinkTree = crate::monitor_link::MonLnkTree<crate::monitor_link::Link>;

/// A new link to `pid` (`erts_link_internal_create(ERTS_LNK_TYPE_PROC, ...)`); `priority` is
/// `ERTS_ML_FLG_PRIO_ML`.
pub(crate) fn process_link(pid: arinsal_sched::Pid, priority: bool) -> crate::monitor_link::Link {
    let flags = if priority {
        crate::monitor_link::node_flag::PRIO_ML
    } else {
        0
    };
    crate::monitor_link::Link::create(crate::monitor_link::node_type::LINK_PROC, pid.data(), flags)
}

/// Origin state of a local process monitor; the target is the half's `other` and the shared
/// data is its [`MonitorInfo`].
#[derive(Clone, Debug)]
pub(crate) struct OriginHalf {
    pub(crate) alias_mode: Option<AliasMode>,
}

#[derive(Default)]
pub(crate) struct ProcessCold {
    /// The parked `erlang:hibernate` continuation (erts keeps it on the process; `F_HIBERNATE_SCHED`).
    pub(crate) hibernate: Option<crate::process::HibernateCont>,
    /// `p->max_heap_size` (erts erl_process.h:1034): the limit and its flags.
    pub(crate) max_heap: crate::process::MaxHeap,
    /// `process_flag(save_calls, N)` buffer (erts `ERTS_PSD_SAVED_CALLS_BUF`).
    pub(crate) saved_calls: Option<crate::trace::SavedCalls>,
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
    /// Catch table the last exception scan saw, see `CodeIndexes::active_catches_cached`.
    pub(crate) catch_cache: Option<crate::code_ix::CatchCache>,
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
    /// A native `wait`/`wait_timeout` asked the scheduler to sleep (timeout in ms, `None` for
    /// `infinity`); the process resumes at the native `loop_rec` label.
    pub(crate) native_wait: Option<Option<u64>>,
    /// Export dispatch to redo after the process wakes from a parked native BIF call.
    pub(crate) native_retry: Option<usize>,
    /// The traced function (by pc), actions and return value of a native trace frame whose
    /// return events the executor emits.
    pub(crate) native_return_events: Option<Box<NativeReturnEvents>>,
    /// Sessions whose return_to frame a traced BIF raised through; the exception's catch
    /// reports their return_to events.
    pub(crate) bif_return_to: Vec<u64>,
    /// The current apply comes from native code, whose call site names the caller frame.
    pub(crate) native_apply: bool,
    /// A tail `apply` has deallocated its caller's frame and runs its callee: a BIF that raises
    /// there has no caller continuation of its own (BeamAsm `emit_i_apply_last` deallocates first).
    // Deviation (interpreter only): erts has no such flag; the interpreter derives a BIF's return
    // address from `ip` instead of an explicit continuation. Remove once interpreter BIF calls
    // carry their return address the way erts does.
    pub(crate) apply_frame_released: u8,
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
    /// The trace flags of the process per session as of trace epoch `.0` (erts reaches them
    /// through the process's tracer reference list, `get_tracer_ref`).
    pub(crate) trace_flags: (u64, Vec<(u64, u64)>),
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
    /// The process's outer signal queue: native `loop_rec` probes it and fetches messages.
    pub(crate) signal_probe: Option<arinsal_sched::SignalProbe<crate::process::Message>>,
    /// The last slice ended because the process is suspended, not because it waits in a
    /// receive: it stays active (runnable once resumed).
    pub(crate) suspend_parked: bool,
    /// Receive-timeout pause of the active suspends (erts `common.timer` as `ErtsPausedProcTimer`).
    pub(crate) timer_pause: Option<crate::process::TimerPause>,
    /// Parked by hibernation until a message arrives (erts `F_HIBERNATE_SCHED`).
    pub(crate) hibernate_sched: bool,
    /// `message_queue_data` is `off_heap` (erts `FS_OFF_HEAP_MSGQ` in `sig_qs.flags`).
    pub(crate) off_heap_msgq: bool,
    /// Static NIF identity, native return point and target scheduler class of a NIF call
    /// (or `enif_schedule_nif` continuation) waiting for a scheduler of that class.
    pub(crate) native_dirty_nif: Option<(usize, usize, arinsal_bifs::SchedulerClass)>,
    /// Return address and call site of the native call that `native_retry` redoes.
    pub(crate) native_retry_site: Option<(usize, usize)>,
    /// The BIF the scheduler runs for native code was called through `call_light_bif_shared`,
    /// not through its export entry, so no return address is on the stack in erts.
    pub(crate) native_light_bif_call: bool,
    /// The interpreter returned only to hand control to `native_pc`; the slice continues.
    pub(crate) native_transfer: bool,
    /// A system task woke the process while it was executing; it runs at the next scheduling
    /// point instead.
    pub(crate) sys_tasks_deferred: bool,
    /// Native continuation to install after an interpreted external call returns.
    pub(crate) native_resume_after_call: Option<usize>,
    /// The BIF failure behind the current native exception, so the scheduler can name the BIF
    /// and its arguments as the top frame (erts passes the MFA to `raise_exception`).
    pub(crate) native_bif_error: Option<Box<NativeBifError>>,
    /// A table BIF failure raised from the direct path with its BIF frame already built, as
    /// erts' BIF returns THE_NON_VALUE with `freason`/`fvalue` set; the call is not redone.
    pub(crate) native_trap: Option<Box<NativeTrap>>,
    /// Stable snapshot and cursor for a trapped `persistent_term:get/0` call.
    pub(crate) persistent_get_all: Option<Box<PersistentGetAll>>,
    /// Result of a published `persistent_term` update, returned when the yielded
    /// updater runs again (erts resumes the suspended updater after `table_updater`).
    pub(crate) persistent_update_result: Option<Term>,
    /// Modules a suspended `finish_loading/1` staged; the thread-progress callback commits
    /// them and releases code-load permission before rescheduling the loader.
    pub(crate) finish_loading_commit: Option<Box<crate::load::StagedLoad>>,
    /// Result of `delete_module/1` retained until its code barrier commits the index.
    pub(crate) delete_module_result: Option<Term>,
    /// Breakpoint update a trace BIF caller finishes between code barriers while it holds
    /// the code modification permission.
    pub(crate) trace_finish: Option<Box<crate::trace_bp::TraceFinish>>,
    /// Storage of a table being released by a trapped `ets:delete/1` or
    /// `ets:internal_delete_all/2`.
    pub(crate) ets_free: Option<Box<EtsFree>>,
    /// Progress of a trapped list `ets:insert/2` or `ets:insert_new/2`.
    pub(crate) ets_insert: Option<Box<EtsInsert>>,
    /// Progress of a trapped `ets:select/2`, `match/2`, `match_object/2` or `select_count/2`.
    pub(crate) ets_select: Option<Box<EtsSelect>>,
    /// The frame of a tail call that was already released when its callee yielded, so the
    /// re-executed instruction does not release it twice. Its words are GC roots.
    pub(crate) ext_last_released: Option<Box<ReleasedFrame>>,
    /// The frames a trapped BIF call holds in erts but the interpreter does not push.
    pub(crate) trap_return: Option<TrapReturn>,
    /// A process-local BIF trap waiting for its private continuation export.
    pub(crate) bif_trap: Option<BifTrapPending>,
    /// Operand registers of `apply` calls in progress. A callee may collect before it
    /// yields back to re-execute the apply, so these stay GC roots until it returns.
    pub(crate) apply_roots: Vec<Term>,
    /// A NIF call rescheduled to another scheduler class; its arguments are GC roots.
    pub(crate) nif_pending: Option<Box<crate::natives::nif::PendingNif>>,
    /// Explicit `exit/1` reason, owned off-heap. The process heap is collected
    /// while the stacktrace is built, so a raw `Term` here would dangle and
    /// monitors would observe a corrupted reason.
    pub(crate) exit_reason: Option<Term>,
    /// Spawned MFA entry that resolves to a runtime BIF export.
    pub(crate) initial_bif: Option<(String, String, u8)>,
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
    /// When the dirty CPU scheduler picked the process (`start_time` of
    /// erts_dirty_process_main); the time until it schedules again is the charge.
    pub(crate) dirty_pickup: Option<std::time::Instant>,
    /// erts `F_DIRTY_MAJOR_GC` / `F_DIRTY_MINOR_GC`: a potentially long collection the
    /// process started itself waits for a dirty CPU scheduler.
    pub(crate) dirty_gc: Option<DirtyGc>,
    /// erts `F_HAVE_BLCKD_MSCHED | F_HAVE_BLCKD_NMSCHED`: this process holds a
    /// multi-scheduling block of its runtime.
    pub(crate) have_blocked_multi_scheduling: bool,
    pub(crate) dictionary_heap: arinsal_term::VecHeap,
    pub(crate) flags: ProcFlags,
    pub(crate) monitor_nodes: usize,
    pub(crate) group_leader: Option<arinsal_sched::Pid>,
    /// `p->parent` when the spawning process is external (a distributed spawn request).
    pub(crate) parent_external: Option<Box<arinsal_etf::OwnedTerm>>,
    pub(crate) receive_markers: Option<Box<receive::ReceiveMarkers>>,
    pub(crate) receive_marker_uniq: i64,
    /// Link nodes keyed by the other end (erts `ERTS_P_LINKS`, a tree of `ErtsILink`).
    pub(crate) links: LinkTree,
    /// Origin entries keyed by reference (erts `ERTS_P_MONITORS`), including standalone aliases,
    /// and the target halves of monitors from remote processes.
    pub(crate) monitors: MonitorTree,
    /// Remote-process monitors. `demonitor` of any other ref does not take the
    /// node-table lock: erts finds `ERTS_MON_TYPE_DIST_PROC` in this process's
    /// own monitor tree (`bif.c` `demonitor`), not in a global scan.
    pub(crate) dist_monitors: std::collections::BTreeSet<u64>,
    /// Monitors created with the `priority` option; their DOWN messages are priority. Kept for
    /// every monitor kind, since the origin decides priority when it receives the DOWN.
    pub(crate) prio_monitors: std::collections::BTreeSet<u64>,
    /// Target half of each local monitor on this process (erts `ERTS_P_LT_MONITORS`).
    pub(crate) lt_monitors: TargetMonitorList,
    /// Target halves of NIF resource monitors (erts `ERTS_MON_TYPE_RESOURCE` in `ERTS_P_LT_MONITORS`).
    pub(crate) resource_monitors:
        std::collections::BTreeMap<u64, std::sync::Arc<arinsal_nif::ResourceMonitor>>,
    /// Suspends this process holds on others, keyed by target (erts `ERTS_P_MONITORS` SUSPEND).
    pub(crate) suspend_monitors: std::collections::BTreeMap<
        arinsal_sched::Pid,
        std::sync::Arc<crate::suspend::SuspendMonitor>,
    >,
    /// Suspend monitors others hold on this process, keyed by suspender (erts `ERTS_P_LT_MONITORS`).
    pub(crate) suspended_by: std::collections::BTreeMap<
        arinsal_sched::Pid,
        std::sync::Arc<crate::suspend::SuspendMonitor>,
    >,
    /// Active suspends of this process (erts `p->rcount`); nonzero exactly when `SUSPENDED` is set.
    pub(crate) suspend_count: u32,
    /// Arguments of an `eval_scheduled` entry, restored when its `-on_load` prelude returns.
    ///
    /// The heap owns the copied terms so a collection inside `-on_load` cannot move them.
    pub(crate) entry_args_after_on_load: Option<Box<EntryArgsAfterOnLoad>>,
    /// BIF MFA of a caught native failure. `save_stacktrace` keeps it as `s->current`
    /// without the uncaught path's `String` box; cleared once the trace is taken.
    pub(crate) pending_trace_top: Option<Box<crate::stacktrace::PendingTop>>,
    /// Stack list from `erlang:raise/3`, keyed by that failure's `freason` and `fvalue`.
    ///
    /// Port of erts/emulator/beam/bif.c:1641-1688 (`raise_3` stores the caller's list
    /// in `c_p->ftrace`), OTP-29.1.1. Native code keeps the register file in
    /// `header.ftrace`, so the list stays here until the catch reads it.
    pub(crate) explicit_raise: Option<Box<(u64, u64, arinsal_etf::OwnedTerm)>>,
}

/// Entry arguments held aside while `-on_load` runs as that process's first function.
pub(crate) struct EntryArgsAfterOnLoad {
    pub(crate) _heap: arinsal_term::VecHeap,
    pub(crate) args: Vec<Term>,
    pub(crate) module: usize,
    pub(crate) ip: usize,
}

pub(crate) struct PersistentGetAll {
    pub(crate) snapshot: arinsal_pterm::Snapshot,
    /// Next hash-table bucket to inspect, matching OTP's trapped iterator.
    pub(crate) cursor: usize,
    pub(crate) remaining: usize,
    pub(crate) result: Term,
}

/// The caller frame of a BIF call that trapped out of the interpreter.
///
/// erts calls a BIF as an ordinary call: the return address into the caller is on the stack
/// while the process waits in the trap, above the caller's frame, which a tail call keeps
/// until the BIF returns. The interpreter re-executes the call instruction on resume instead,
/// so this return address is reported to `process_info` and stack traces without being pushed.
pub(crate) struct TrapReturn {
    /// Module and instruction the BIF returns to.
    pub(crate) module: usize,
    pub(crate) ip: usize,
}

/// A frame the interpreter released before a tail call whose callee then yielded.
pub(crate) struct ReleasedFrame {
    pub(crate) module: usize,
    pub(crate) ip: usize,
    /// `true` when erts keeps the frame while a BIF runs (`call_ext_last`, `apply_last`);
    /// a fun call in tail position releases it before the call.
    pub(crate) kept: bool,
    /// The frame's words, as they were before the release.
    pub(crate) words: Vec<Term>,
}

/// `apply_frame_released` of a tail `apply/3` or fixed apply: erts passes the apply site `I`
/// and a BIF failure other than error/exit/throw is attributed to the continuation.
pub(crate) const TAIL_APPLY: u8 = 1;
/// `apply_frame_released` of a tail fun call, which has no apply-site adjustment at all: the
/// raising BIF's pc is the continuation on top of the stack.
pub(crate) const TAIL_FUN_CALL: u8 = 2;

const SAVED_FRAME_WORDS: usize = 16;

/// What a tail call that releases its frame keeps until it knows whether the callee yields.
pub(crate) struct FrameRelease {
    saved: [Term; SAVED_FRAME_WORDS],
    count: usize,
    dealloc: usize,
    collections: u64,
    again: Option<Vec<Term>>,
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
    /// The live magic-reference thing passed to the continuation export, when erts allocates one.
    pub(crate) state_term: Option<Term>,
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
impl BifTrapPending {
    /// Whether `args` are the trapped call's live registers: they are collection roots, and
    /// the caller's own X registers are dead while the process waits in the trap.
    // Port of erts/emulator/beam/bif.h (ERTS_BIF_PREP_TRAPn: the arguments are `reg[0..n]`),
    // OTP-29.1.1.
    pub(crate) fn args_are_roots(&self) -> bool {
        self.continuation == crate::bif_traps::REVERSE_CONTINUATION
    }
}

impl Process {
    /// Enter a tail apply whose caller frame is already deallocated (see `apply_frame_released`).
    /// Returns whether this call set the flag, for `end_tail_apply`.
    pub(crate) fn begin_tail_apply(&mut self, tail: bool, kind: u8) -> bool {
        if !tail
            || self.apply_frame_released()
            || self.cold.as_ref().is_some_and(|c| c.native_apply)
        {
            return false;
        }
        self.cold_mut().apply_frame_released = kind;
        true
    }
    /// Leave a tail apply. A BIF failure keeps the flag until `exceptions::resume` saves its trace.
    pub(crate) fn end_tail_apply<T>(&mut self, began: bool, result: &Result<T, VmError>) {
        if began && !matches!(result, Err(VmError::Trap(trap)) if trap.is_raw_bif_failure()) {
            self.cold_mut().apply_frame_released = 0;
        }
    }
    /// Whether a running tail `apply` has already deallocated its caller's frame.
    pub(crate) fn apply_frame_released(&self) -> bool {
        self.cold
            .as_ref()
            .is_some_and(|cold| cold.apply_frame_released != 0)
    }
    /// The caller frame of the BIF the process waits in, while it is scheduled out in the
    /// export trap of an interpreter call.
    pub(crate) fn trap_return_frame(&self) -> Option<&TrapReturn> {
        if self.header.i as usize != crate::bif_traps::bif_export_trap_pc() {
            return None;
        }
        self.cold.as_ref()?.trap_return.as_ref()
    }
    /// The words of the caller's frame that a trapped `call_ext_last` released and erts keeps.
    pub(crate) fn trap_frame_words(&self) -> &[Term] {
        let Some(frame) = self.trap_return_frame() else {
            return &[];
        };
        self.cold
            .as_ref()
            .and_then(|cold| cold.ext_last_released.as_ref())
            .filter(|released| {
                released.kept && released.module == frame.module && released.ip + 1 == frame.ip
            })
            .map_or(&[], |released| &released.words)
    }
    /// Words of the Erlang stack as erts counts them, with the frames of a trapped call.
    pub(crate) fn observed_stack_words(&self) -> usize {
        self.heap.stack_words()
            + self
                .trap_return_frame()
                .map_or(0, |_| 1 + self.trap_frame_words().len())
    }
    /// Release the frame of a tail call at `module`:`ip` before its callee runs.
    ///
    /// A callee that yields makes the instruction run again, with the frame already gone:
    /// `again` then holds the words the first run released.
    pub(crate) fn release_tail_frame(
        &mut self,
        module: usize,
        ip: usize,
        dealloc: usize,
    ) -> Result<FrameRelease, VmError> {
        let again = self
            .cold
            .as_mut()
            .and_then(|cold| match cold.ext_last_released.take() {
                Some(released) if released.module == module && released.ip == ip => {
                    Some(released.words)
                }
                other => {
                    cold.ext_last_released = other;
                    None
                }
            });
        let mut release = FrameRelease {
            saved: [Term::NIL; SAVED_FRAME_WORDS],
            count: 0,
            dealloc,
            collections: self.stats.gc.collections,
            again,
        };
        if release.again.is_none() && dealloc > 0 {
            if dealloc <= SAVED_FRAME_WORDS {
                for index in 0..dealloc {
                    release.saved[index] = self.heap.stack_get(index).unwrap_or(Term::NIL);
                }
                release.count = dealloc;
            }
            if !self.heap.release_stack(dealloc) {
                return Err(VmError::Unsupported("stack underflow".into()));
            }
        }
        Ok(release)
    }
    /// The callee of a tail call yielded and will run the instruction again.
    pub(crate) fn note_tail_yield(
        &mut self,
        module: usize,
        ip: usize,
        release: FrameRelease,
        kept: bool,
    ) {
        let words = match release.again {
            Some(words) => words,
            None if release.count == release.dealloc
                && release.collections == self.stats.gc.collections =>
            {
                release.saved[..release.count].to_vec()
            }
            None => vec![Term::NIL; release.dealloc],
        };
        self.cold_mut().ext_last_released = Some(Box::new(ReleasedFrame {
            module,
            ip,
            kept,
            words,
        }));
    }
    /// `true` when `-on_load` did not return `ok` and the entry call must not run.
    ///
    /// A matching continuation that returned `ok` has its saved arguments copied back
    /// into X and stays armed only once.
    pub(crate) fn finish_on_load_prelude(&mut self, module: usize, ip: usize) -> bool {
        let matches = self
            .cold
            .as_ref()
            .and_then(|cold| cold.entry_args_after_on_load.as_ref())
            .is_some_and(|saved| saved.module == module && saved.ip == ip);
        if !matches {
            return false;
        }
        let ok = self.x[0]
            .as_atom()
            .and_then(|atom| arinsal_term::global_atoms().text(atom))
            == Some("ok");
        if !ok {
            if let Some(cold) = self.cold.as_mut() {
                cold.entry_args_after_on_load = None;
            }
            return true;
        }
        let args = self
            .cold
            .as_ref()
            .and_then(|cold| cold.entry_args_after_on_load.as_ref())
            .map(|saved| saved.args.clone())
            .unwrap_or_default();
        self.x.ensure_x(args.len());
        for (index, arg) in args.iter().enumerate() {
            self.x[index] = *arg;
        }
        self.gc_live = args.len();
        self.header.arity = args.len().min(usize::from(u8::MAX)) as u8;
        if let Some(saved) = self
            .cold
            .as_mut()
            .and_then(|cold| cold.entry_args_after_on_load.as_mut())
        {
            // One return into the entry. A later call to the same ip is not the prelude.
            saved.module = usize::MAX;
        }
        false
    }

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
        let store = runtime.as_deref().map_or_else(
            || arinsal_pterm::store_for(0),
            |runtime| runtime.persistent_terms,
        );
        if let Some(runtime) = runtime.as_deref() {
            // A new process takes `system_flag(min_bin_vheap_size)` of the runtime it joins;
            // explicit spawn options are applied after this.
            self.heap.set_min_bin_vheap_size(
                crate::natives::sys::gc_spawn_defaults(Some(runtime)).min_bin_vheap_size as u64,
            );
        }
        self.runtime = runtime;
        self.persistent_terms = store;
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

    /// Records the live X register count a native continuation resumes with.
    // Port of erts/emulator/beam/erl_process.h (`Process.arity`), OTP-29.1.1: the producer of
    // a saved register file states how many registers are live, and every reader of a
    // switched-out process takes that count.
    pub(crate) fn set_native_resume_arity(&mut self, live: u8) {
        self.header.arity = live;
        self.native_arity_set = true;
    }

    /// Live X register count of a switched-out process (`c_p->arity`), bounded by the
    /// saved file.
    #[inline]
    pub(crate) fn saved_arity(&self) -> usize {
        usize::from(self.header.arity).min(self.x.len())
    }

    /// Publishes what a runtime call that did not collect can change: the heap and stack
    /// cursors and FCALLS. The heap bounds move only when the process collects.
    // Port of erts/emulator/beam/jit/arm/beam_asm.hpp:540-601 (emit_leave_runtime with
    // Update::eHeap | eStack | eReductions), OTP-29.1.1.
    pub(crate) fn sync_native_cursors(&mut self) {
        let (htop, stop) = self.heap.heap_cursor();
        self.header.htop = htop;
        self.header.stop = stop;
        // A helper that collected moved the heap: the bounds go out with the cursors, or
        // the next helper commits cursors of the new heap against the old base.
        let (heap, hend) = self.heap.heap_bounds();
        self.header.heap = heap;
        self.header.hend = hend;
        self.header.fcalls = self.reductions;
    }

    /// Publish only the young-heap state (cursors, bounds, high water) to the ABI prefix,
    /// leaving FCALLS alone: the collector uses it, and it may run in a helper that has not
    /// taken over the stored reduction counter.
    pub(crate) fn sync_native_heap(&mut self) {
        let (htop, stop) = self.heap.heap_cursor();
        let (heap, hend) = self.heap.heap_bounds();
        self.header.htop = htop;
        self.header.stop = stop;
        self.header.heap = heap;
        self.header.hend = hend;
        self.header.high_water = self.heap.high_water_ptr();
    }

    /// Publish the heap bounds and cursors to the ABI prefix before entering native code,
    /// as the executor does at every native entry.
    pub fn sync_native_header(&mut self) {
        let (htop, stop) = self.heap.heap_cursor();
        let (heap, hend) = self.heap.heap_bounds();
        self.header.htop = htop;
        self.header.stop = stop;
        self.header.heap = heap;
        self.header.hend = hend;
        self.header.high_water = self.heap.high_water_ptr();
        self.header.fcalls = self.reductions;
    }

    /// Satisfy `need` words in a fresh heap fragment without collecting, keeping the call_memory
    /// accounting of the abandoned heap.
    // Port of erts/emulator/beam/erl_gc.c:500-582 (delay_garbage_collection), OTP-29.1.1.
    pub(crate) fn delay_heap_collection(&mut self, need: usize) {
        if need == 0 {
            return;
        }
        let first_abandon = !self.heap.has_abandoned_heap();
        let used = self.heap.words_since_high_water() as i64;
        self.heap.delay_collection(need);
        if first_abandon
            && self
                .cold
                .as_ref()
                .is_some_and(|cold| !cold.call_memory.is_empty())
        {
            crate::trace_bp::adjust_memory_break(self, used);
        }
    }

    /// Words allocated by the process since its last collection, plus `adjustment`.
    // Port of erts/emulator/beam/beam_bp.c:989-992 (get_allocated_words), OTP-29.1.1.
    pub(crate) fn allocated_words(&self, adjustment: i64) -> i64 {
        let info = self.heap.gc_info_words();
        adjustment + self.heap.words_since_high_water() as i64 + info.mbuf_size as i64
    }

    #[inline]
    pub(crate) fn cold_mut(&mut self) -> &mut ProcessCold {
        if self.cold.is_none() {
            self.allocate_cold();
        }
        self.cold.as_deref_mut().expect("cold part allocated")
    }

    #[cold]
    #[inline(never)]
    fn allocate_cold(&mut self) {
        self.cold = Some(Box::default());
    }

    /// Group leader, or `fallback` when spawn did not record one (`p->group_leader`).
    pub(crate) fn group_leader_pid(&self, fallback: arinsal_sched::Pid) -> arinsal_sched::Pid {
        self.group_leader
            .or_else(|| self.cold.as_ref().and_then(|cold| cold.group_leader))
            .unwrap_or(fallback)
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
        Self::with_spawn_registers_heap(x_registers, float_registers, Self::initial_heap(233))
    }
    /// [`Self::with_spawn_registers`] with the heap `erl_create_process` sized for the
    /// child: erts allocates the initial heap once, at its final size.
    pub(crate) fn with_spawn_registers_heap(
        x_registers: usize,
        float_registers: usize,
        heap: ProcessHeap,
    ) -> Self {
        let mut slot = std::mem::MaybeUninit::uninit();
        Self::write_spawn_registers_heap(&mut slot, x_registers, float_registers, heap);
        // SAFETY: `write_spawn_registers_heap` initialized the slot.
        unsafe { slot.assume_init() }
    }
    /// [`Self::with_spawn_registers_heap`] written straight into `slot`, the task slot of the
    /// allocated process struct (erl_create_process initializes the fields in place).
    pub(crate) fn write_spawn_registers_heap(
        slot: &mut std::mem::MaybeUninit<Self>,
        x_registers: usize,
        float_registers: usize,
        heap: ProcessHeap,
    ) -> &mut Self {
        let process = Self::write_registers_and_heap(slot, x_registers, float_registers, heap);
        // Port of erts/emulator/beam/erl_process.c (erl_create_process: c_p->arity = arg
        // count): a collection before the first run must keep the initial arguments alive.
        process.gc_live = x_registers;
        process.header.arity = x_registers.min(usize::from(u8::MAX)) as u8;
        if !crate::beamasm_integration::enabled() {
            crate::native_bridge::push_exit_bridge(process);
        }
        process
    }
    pub(crate) fn with_registers_and_min_heap(
        x_registers: usize,
        float_registers: usize,
        min_heap: usize,
    ) -> Self {
        Self::with_registers_and_heap(x_registers, float_registers, Self::initial_heap(min_heap))
    }
    /// A heap of `min_heap` words with the boot GC defaults; 64 builds the zero-word heap.
    fn initial_heap(min_heap: usize) -> ProcessHeap {
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
        heap
    }
    fn with_registers_and_heap(
        x_registers: usize,
        float_registers: usize,
        heap: ProcessHeap,
    ) -> Self {
        let mut slot = std::mem::MaybeUninit::uninit();
        Self::write_registers_and_heap(&mut slot, x_registers, float_registers, heap);
        // SAFETY: `write_registers_and_heap` initialized the slot.
        unsafe { slot.assume_init() }
    }
    fn write_registers_and_heap(
        slot: &mut std::mem::MaybeUninit<Self>,
        x_registers: usize,
        float_registers: usize,
        heap: ProcessHeap,
    ) -> &mut Self {
        #[cfg(feature = "pf-mem-counters")]
        let started = std::time::Instant::now();
        #[cfg(feature = "pf-mem-counters")]
        let min_heap = heap.min_heap_size_words();
        let process = slot.write(Self {
            header: ProcessHeader::default(),
            x: ArgRegs::new(x_registers),
            fr: vec![0.0; float_registers].into_boxed_slice(),
            heap,
            dictionary: None,
            seq_trace_token: None,
            seq_token_root: Term::NIL,
            seq_trace_clock: 0,
            seq_trace_lastcnt: 0,
            seq_trace_epoch: crate::seq_trace::current_epoch(),
            seq_trace_spawn_pending: false,
            module: 0,
            ip: 0,
            initial_call: None,
            initial_mfa: None,
            native_pc: None,
            entry_started: false,
            gc_live: 0,
            max_heap_peak: 0,
            reductions: 4000,
            native_reds_in: 4000,
            trap_work: 0,
            virtual_reds: 0,
            reductions_used: 0,
            delay_gc: false,
            gc_deferred: false,
            uniq_counter: 0,
            stats: ProcessStats::default(),
            final_exit_reason: None,
            runtime: None,
            self_pid: None,
            pending_signal_waiter: None,
            scheduler_id: 0,
            scheduler_ref_state: None,
            hibernated: false,
            inbox: process::MessageQueue::default(),
            sig_cont: arinsal_sched::SignalQueue::default(),
            sig_cont_taken: 0,
            receive_cursor: 0,
            receive_deadline: None,
            receive_deadline_ms: None,
            receive_infinity: false,
            cold: None,
            group_leader: None,
            parent: None,
            exit_cont: None,
            apply_inline: [Term::NIL; 3],
            apply_inline_len: 0,
            persistent_terms: arinsal_pterm::global_store(),
            trap_exit: false,
            exc_class: None,
            entry: false,
            force_yield: false,
            native_continuation_resume: false,
            native_arity_set: false,
            native_error_pc: 0,
            native_exit_kind: NativeExit::None,
        });
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
        let cost = self.ensure_roots_cost(words, live)?;
        if cost != 0 {
            self.bump_gc_reds(cost);
        }
        Ok(())
    }
    /// [`Process::ensure`] with the no-collection case inline, for the native entry that runs
    /// once per scheduling turn.
    // Port of erts/emulator/beam/erl_gc.h:132-139 (ERTS_IS_GC_DESIRED), OTP-29.1.1: the
    // entry check only reads the heap cursors unless a collection is wanted.
    #[inline]
    pub(crate) fn ensure_entry(&mut self, words: usize, live: usize) -> Result<(), VmError> {
        if live <= self.x.len()
            && self.heap.free_words() >= words + self.heap.check_reserve()
            && !self.heap.bin_vheap_gc_due()
            && !crate::interp::gc_stress_enabled()
        {
            self.gc_live = live;
            return Ok(());
        }
        self.ensure(words, live)
    }
    /// [`Process::ensure`] that returns the collection's reduction cost instead of charging it,
    /// for `arinsal_beamasm_gc_sync`, whose generated code subtracts the cost from FCALLS.
    #[cold]
    #[inline(never)]
    pub(crate) fn ensure_uncharged(&mut self, words: usize, live: usize) -> Result<u32, VmError> {
        self.ensure_roots_cost(words, live)
    }
    /// Charge `cost` reductions for a collection.
    ///
    /// A process running native code spends its FCALLS counter, which stops at zero. The
    /// interpreter keeps its slice in the scheduler and counts the work as used reductions.
    // Port of erts/emulator/beam/bif.h (BUMP_REDS) as used by erl_gc.c
    // (`erts_gc_after_bif_call_lhf`, `erts_garbage_collect`), OTP-29.1.1.
    pub(crate) fn bump_gc_reds(&mut self, cost: u32) {
        if self.heap.native_active() {
            self.reductions = self
                .reductions
                .saturating_sub(cost.min(i32::MAX as u32) as i32)
                .max(0);
        } else {
            self.reductions_used = self.reductions_used.saturating_add(u64::from(cost));
        }
    }
    /// Charge a collection the epilogue of a BIF ran: its cost, or, when erts postponed it, the
    /// rest of the slice.
    // Port of erts/emulator/beam/erl_gc.c (`delay_garbage_collection` returns `reds_left` from
    // `force_reschedule`, and `erts_gc_after_bif_call_lhf` bumps the process by it),
    // OTP-29.1.1. The part of it that is not the process's own work is already in `virtual_reds`.
    pub(crate) fn charge_gc_stats(&mut self, stats: &arinsal_term::GcStats) {
        if stats.collections == 0 && self.heap.native_active() {
            self.reductions = 0;
            return;
        }
        self.bump_gc_reds(stats.reductions);
    }
    /// Ensure with `live` roots in `self.x`, the scheduler's X register array, without a
    /// collection when the heap has room.
    ///
    /// Port of erts/emulator/beam/erl_bits.c:1769-1840 (`erts_bs_append_checked`), OTP-29.1.1.
    pub(crate) fn ensure_native_roots(
        &mut self,
        words: usize,
        live: usize,
    ) -> Result<bool, VmError> {
        if live > self.x.len() {
            return Err(VmError::Unsupported("live X register count".into()));
        }
        let allocation_words = words + self.heap.check_reserve();
        if self.heap.free_words() >= allocation_words
            && !self.heap.bin_vheap_gc_due()
            && !gc_stress_enabled()
        {
            return Ok(false);
        }
        self.ensure(words, live).map(|()| true)
    }
    /// Collect with `live` X roots; the registers above them are left as they are.
    #[cold]
    #[inline(never)]
    fn ensure_roots_cost(&mut self, words: usize, live: usize) -> Result<u32, VmError> {
        if live > self.x.len() {
            return Err(VmError::Unsupported("live X register count".into()));
        }
        self.gc_live = live;
        let allocation_words = words + self.heap.check_reserve();
        // Port of erts/emulator/beam/erl_gc.h:132-139 (ERTS_IS_GC_DESIRED), OTP-29.1.1.
        if self.heap.free_words() >= allocation_words
            && !self.heap.bin_vheap_gc_due()
            && !gc_stress_enabled()
        {
            return Ok(0);
        }
        if !self.heap.gc_enabled {
            // Port of erts/emulator/beam/erl_gc.c:780-783 (garbage_collect with F_DISABLE_GC):
            // the need is satisfied in a fresh heap fragment and the collection is delayed.
            self.delay_heap_collection(words);
            return Ok(0);
        }
        // Port of erts/emulator/beam/jit/arm/instr_common.cpp:94-99, OTP-29.1.1:
        // the native heap check uses S_RESERVED, but GC receives the raw `need`.
        let gc = self.collect_heap_roots(live, &mut [], words)?;
        // Port of erl_gc.c:501-513 (`delay_garbage_collection`): a zero-need
        // delayed collection forces rescheduling without manufacturing heap space.
        if words == 0 && gc.collections == 0 {
            return Ok(0);
        }
        // Port of erts/emulator/beam/erl_gc.c (setup_rootset nobj), OTP-29.1.1: the collector
        // rewrites only the live prefix and leaves the other X words as they are.
        natives::sys::after_collection(self, gc.collections, gc.words_reclaimed);
        if self.heap.free_words() < allocation_words {
            return Err(VmError::Unsupported("heap exhausted after GC".into()));
        }
        Ok(gc.reductions)
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
    /// The float register file: the scheduler's `f_reg_array` while the registers are
    /// attached, the process's own otherwise.
    fn float_file(&mut self) -> &mut [f64] {
        match self.x.attached_floats() {
            Some(file) => file,
            None => &mut self.fr,
        }
    }
    /// The base of the float register file, for the interpreter's register window.
    pub(crate) fn fr_ptr(&mut self) -> *mut f64 {
        if self.x.is_attached() {
            self.x.float_ptr()
        } else {
            self.fr.as_mut_ptr()
        }
    }
    /// Make `need` float registers addressable. The scheduler's array always is; a process
    /// outside a scheduler slice grows its own.
    pub(crate) fn ensure_fr(&mut self, need: usize) {
        if !self.x.is_attached() && self.fr.len() < need {
            let mut registers = self.fr.to_vec();
            registers.resize(need, 0.0);
            self.fr = registers.into_boxed_slice();
        }
    }
    pub(crate) fn float(&mut self, src: Arg) -> Result<f64, VmError> {
        if src.kind() == Arg::FR {
            return self
                .float_file()
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
                .float_file()
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

/// The BIF frame whose error remains live across a native exit.
pub(crate) enum NativeBifCall {
    /// Native export metadata and the scheduler's register array are the MFA and arguments.
    Export(crate::beamasm_integration::ExportDispatch),
    /// A native operation writes its BIF arguments to X0.. before raising.
    Registers {
        module: arinsal_term::Atom,
        function: arinsal_term::Atom,
        arity: u8,
    },
    /// NIF and legacy helper calls have no export entry to retain.
    Owned {
        module: String,
        function: String,
        args: Vec<Term>,
    },
}

/// A BIF failure raised from native code, kept until the native exit builds the exception.
pub(crate) struct NativeBifError {
    pub(crate) call: NativeBifCall,
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

/// Port of erts/emulator/beam/erl_db_hash.c (select_chunk_on_trap and select_count_on_trap),
/// OTP-29.1.1: the continuation a trapped hash table traversal resumes
/// from (`ets:select_trap/1` and `ets:count_trap/1`).
pub(crate) struct EtsSelect {
    pub(crate) tid: arinsal_ets::Tid,
    pub(crate) program: std::sync::Arc<arinsal_ets::match_spec::MatchProgram>,
    pub(crate) program_owner: std::sync::Arc<arinsal_term::MagicRef>,
    /// `select_count/2` instead of a result list.
    pub(crate) count: bool,
    /// Where the traversal resumes.
    pub(crate) position: arinsal_ets::ScanPosition,
    /// An ordered table is traversed from its last key downward, `select_reverse/2` upward.
    pub(crate) backwards: bool,
    /// Objects counted so far (`select_count/2`).
    pub(crate) got: usize,
    /// Results of the earlier cycles.
    pub(crate) saved: arinsal_ets::SavedMatches,
    pub(crate) safety: arinsal_ets::IterSafety,
    /// The chunk size of `select/3` and its relatives; zero for the calls that return every
    /// result.
    pub(crate) chunk: usize,
    pub(crate) stage: SelectStage,
    /// The end of the key range an ordered table's continuation names.
    pub(crate) end: Option<arinsal_ets::SavedKey>,
}

/// Where a trapped chunked traversal of an ordered table is.
pub(crate) enum SelectStage {
    /// The traversal runs on.
    Scan,
    /// The results wait in `ets:reverse/3`, which has `done` of them behind it; `eot` when no
    /// continuation follows.
    Reverse { done: usize, eot: bool },
}

/// Port of erts/emulator/beam/erl_db.c:2161-2330 (ets_insert_2_list_info), OTP-29.1.1: the state a
/// list insert keeps across traps.
pub(crate) enum EtsInsert {
    /// Objects of the list already seen by the check pass (`ets_insert_2_list_check`).
    Check { cursor: Term, count: usize },
    /// Objects copied into table form so far, before the table is locked.
    Copy {
        cursor: Term,
        prepared: Vec<arinsal_ets::PreparedObject>,
    },
    /// The remaining objects were handed to the busy table; the result lands in the slot.
    Global(arinsal_ets::InsertOutcome),
}

impl EtsInsert {
    pub(crate) fn cursor(&self) -> Option<Term> {
        match self {
            Self::Check { cursor, .. } | Self::Copy { cursor, .. } => Some(*cursor),
            Self::Global(_) => None,
        }
    }

    pub(crate) fn update_cursor(&mut self, term: Term) {
        match self {
            Self::Check { cursor, .. } | Self::Copy { cursor, .. } => *cursor = term,
            Self::Global(_) => unreachable!("global ETS insert has no list cursor"),
        }
    }
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

/// `process_flag/2` values kept on the process: erts stores these as struct fields (`p->flags`, `async_dist`, `p->sig_qs.flags`, `ERTS_PSD_*`), not behind string keys. A field is
/// `None` until the flag is first set; readers then report the erts default.
#[derive(Default)]
pub(crate) struct ProcFlags {
    pub(crate) error_handler: Option<Term>,
    pub(crate) priority: Option<Term>,
    pub(crate) message_queue_data: Option<Term>,
    pub(crate) sensitive: Option<Term>,
    pub(crate) async_dist: Option<Term>,
    pub(crate) priority_messages: Option<Term>,
    pub(crate) save_calls: Option<Term>,
    pub(crate) group_leader: Option<Term>,
    pub(crate) fullsweep_after: Option<Term>,
    pub(crate) min_heap_size: Option<Term>,
    pub(crate) min_bin_vheap_size: Option<Term>,
}

impl ProcFlags {
    fn slot(&mut self, name: &str) -> &mut Option<Term> {
        match name {
            "error_handler" => &mut self.error_handler,
            "priority" => &mut self.priority,
            "message_queue_data" => &mut self.message_queue_data,
            "sensitive" => &mut self.sensitive,
            "async_dist" => &mut self.async_dist,
            "priority_messages" => &mut self.priority_messages,
            "save_calls" => &mut self.save_calls,
            "group_leader" => &mut self.group_leader,
            "fullsweep_after" => &mut self.fullsweep_after,
            "min_heap_size" => &mut self.min_heap_size,
            "min_bin_vheap_size" => &mut self.min_bin_vheap_size,
            other => unreachable!("unknown process flag {other}"),
        }
    }

    /// The value of a flag by name, for the cold `process_info` paths.
    pub(crate) fn get(&self, name: &str) -> Option<Term> {
        match name {
            "error_handler" => self.error_handler,
            "priority" => self.priority,
            "message_queue_data" => self.message_queue_data,
            "sensitive" => self.sensitive,
            "async_dist" => self.async_dist,
            "priority_messages" => self.priority_messages,
            "save_calls" => self.save_calls,
            "group_leader" => self.group_leader,
            "fullsweep_after" => self.fullsweep_after,
            "min_heap_size" => self.min_heap_size,
            "min_bin_vheap_size" => self.min_bin_vheap_size,
            _ => None,
        }
    }

    /// Stores a flag and returns the previous value.
    pub(crate) fn insert(&mut self, name: &str, value: Term) -> Option<Term> {
        self.slot(name).replace(value)
    }
}

#[cfg(test)]
mod arg_regs_tests {
    use super::{ATTACHED_X_REGS, ArgRegs};
    use arinsal_beamasm::SchedulerRegisters;
    use arinsal_term::Term;

    fn int(n: i64) -> Term {
        Term::small(n).unwrap()
    }

    fn registers() -> Box<SchedulerRegisters> {
        Box::<SchedulerRegisters>::default()
    }

    fn attach(regs: &mut ArgRegs, sched: &mut SchedulerRegisters) {
        // SAFETY: every test keeps `sched` alive and in place until it detaches or drops `regs`.
        unsafe { regs.attach(sched) }
    }

    fn owned(values: &[i64]) -> ArgRegs {
        ArgRegs::from(values.iter().map(|&n| int(n)).collect::<Vec<_>>())
    }

    #[test]
    fn owned_len_is_the_arity() {
        let regs = owned(&[1, 2, 3]);
        assert!(!regs.is_attached());
        assert_eq!(regs.len(), 3);
        assert_eq!(regs.saved_arity(), 3);
        let wide = owned(&[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(wide.len(), 8);
        assert_eq!(wide[7], int(8));
    }

    #[test]
    fn attached_floats_are_the_scheduler_float_array_and_nothing_is_saved() {
        let mut sched = registers();
        sched.f_reg_array[5] = 2.5;
        let mut regs = owned(&[1]);
        assert!(regs.attached_floats().is_none());
        assert!(regs.float_ptr().is_null());
        attach(&mut regs, &mut sched);
        assert_eq!(regs.float_ptr(), sched.f_reg_array.as_mut_ptr());
        let file = regs.attached_floats().expect("attached float file");
        assert_eq!(file.len(), super::ATTACHED_F_REGS);
        assert_eq!(file[5], 2.5);
        file[7] = -1.5;
        assert_eq!(sched.f_reg_array[7], -1.5);
        regs.detach_save(1);
        assert!(regs.attached_floats().is_none());
        assert!(regs.float_ptr().is_null());
        assert_eq!(sched.f_reg_array[7], -1.5);
    }

    #[test]
    fn attached_deref_is_the_whole_scheduler_array() {
        let mut sched = registers();
        sched.x_reg_array[3] = int(33);
        let mut regs = owned(&[1, 2]);
        attach(&mut regs, &mut sched);
        assert!(regs.is_attached());
        assert_eq!(regs.len(), ATTACHED_X_REGS);
        assert_eq!(regs.saved_arity(), 2);
        assert_eq!(regs[3], int(33));
        regs[1000] = int(7);
        regs.detach_save(0);
        assert_eq!(sched.x_reg_array[1000], int(7));
    }

    #[test]
    fn attach_copies_exactly_the_saved_registers_into_the_array() {
        let mut sched = registers();
        sched.x_reg_array[0] = int(77);
        sched.x_reg_array[2] = int(78);
        sched.x_reg_array[8] = int(79);
        let mut regs = owned(&[1, 2, 3, 4, 5, 6, 7, 8]);
        attach(&mut regs, &mut sched);
        assert_eq!(sched.x_reg_array[7], int(8));
        assert_eq!(sched.x_reg_array[0], int(1));
        assert_eq!(sched.x_reg_array[8], int(79));
        regs.detach_save(0);
    }

    #[test]
    fn attached_writes_land_in_the_array_and_detach_saves_arity_registers() {
        let mut sched = registers();
        let mut regs = owned(&[9]);
        attach(&mut regs, &mut sched);
        for i in 0..4 {
            regs[i] = int(10 + i as i64);
        }
        assert_eq!(sched.x_reg_array[2], int(12));
        regs.detach_save(3);
        assert!(!regs.is_attached());
        assert_eq!(regs.len(), 3);
        assert_eq!(regs.saved_arity(), 3);
        assert_eq!(&regs[..], &[int(10), int(11), int(12)]);
    }

    #[test]
    fn detach_save_grows_past_the_inline_registers() {
        let mut sched = registers();
        let mut regs = owned(&[1]);
        attach(&mut regs, &mut sched);
        for i in 0..9 {
            regs[i] = int(100 + i as i64);
        }
        regs.detach_save(9);
        assert_eq!(regs.len(), 9);
        let expect: Vec<Term> = (0..9).map(|i| int(100 + i)).collect();
        assert_eq!(&regs[..], &expect[..]);

        attach(&mut regs, &mut sched);
        regs.detach_save(2);
        assert_eq!(&regs[..], &expect[..2]);
        attach(&mut regs, &mut sched);
        regs.detach_save(7);
        assert_eq!(&regs[..], &expect[..7]);
    }

    #[test]
    fn process_memory_counts_the_saved_registers_only_past_the_inline_default() {
        let mut sched = registers();
        let mut regs = owned(&[1, 2, 3]);
        assert!(regs.is_def_arg_reg());
        assert_eq!(regs.arg_reg_bytes(), 0);
        attach(&mut regs, &mut sched);
        regs.detach_save(6);
        assert_eq!(regs.arg_reg_bytes(), 0);
        attach(&mut regs, &mut sched);
        regs.detach_save(9);
        assert!(!regs.is_def_arg_reg());
        assert_eq!(regs.arg_reg_bytes(), 9 * std::mem::size_of::<Term>());
        attach(&mut regs, &mut sched);
        regs.detach_save(2);
        assert!(!regs.is_def_arg_reg());
        assert_eq!(regs.arg_reg_bytes(), 2 * std::mem::size_of::<Term>());
    }

    #[test]
    fn detach_save_is_isolated_from_later_array_changes() {
        let mut sched = registers();
        let mut regs = owned(&[]);
        attach(&mut regs, &mut sched);
        regs[0] = int(1);
        regs[1] = int(2);
        regs.detach_save(2);
        sched.x_reg_array[0] = int(99);
        assert_eq!(&regs[..], &[int(1), int(2)]);
    }

    #[test]
    fn ensure_x_grows_an_owned_file_and_keeps_registers() {
        let mut regs = owned(&[1, 2]);
        regs.ensure_x(1);
        assert_eq!(regs.len(), 2);
        regs.ensure_x(5);
        assert_eq!(regs.len(), 5);
        assert_eq!(&regs[..2], &[int(1), int(2)]);
        assert_eq!(&regs[2..], &[Term::NIL; 3]);
        regs.ensure_x(10);
        assert_eq!(regs.len(), 10);
        assert_eq!(&regs[..2], &[int(1), int(2)]);
        assert_eq!(&regs[2..], &[Term::NIL; 8]);
        regs.ensure_x(12);
        assert_eq!(regs.len(), 12);
        assert_eq!(regs[1], int(2));
        assert_eq!(regs[11], Term::NIL);
        assert_eq!(regs.saved_arity(), 12);
    }

    #[test]
    fn ensure_x_after_a_smaller_save_does_not_resurrect_stale_registers() {
        let mut sched = registers();
        let mut regs = owned(&[]);
        attach(&mut regs, &mut sched);
        for i in 0..8 {
            regs[i] = int(50 + i as i64);
        }
        regs.detach_save(8);
        attach(&mut regs, &mut sched);
        regs.detach_save(2);
        regs.ensure_x(4);
        assert_eq!(&regs[..], &[int(50), int(51), Term::NIL, Term::NIL]);
        regs.ensure_x(8);
        assert_eq!(regs.len(), 8);
        assert_eq!(&regs[2..], &[Term::NIL; 6]);
    }

    #[test]
    fn ensure_x_is_a_no_op_while_attached() {
        let mut sched = registers();
        let mut regs = owned(&[1]);
        attach(&mut regs, &mut sched);
        regs.ensure_x(500);
        assert_eq!(regs.len(), ATTACHED_X_REGS);
        assert_eq!(regs.saved_arity(), 1);
        regs.detach_save(1);
        assert_eq!(regs.len(), 1);
    }

    #[test]
    #[should_panic(expected = "not attached")]
    fn detach_without_attach_panics() {
        owned(&[1]).detach_save(1);
    }
}
