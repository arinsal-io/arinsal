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
#[derive(Default)]
pub(crate) struct ProcessCold {
    /// The process already exited while its dirty job keeps running.
    /// Port of erl_process.c:10096 (`need_forced_exit`), OTP-29.1.1.
    pub(crate) dirty_exited: bool,
    /// Completion latch for `erts_debug:set_internal_state(wait, ...)`.
    pub(crate) debug_wait_completion: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    /// Whether this process currently has a runnable profile activation.
    pub(crate) profile_active: bool,
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
    /// Sessions whose `return_to` event a traced native return handed to the executor.
    pub(crate) native_return_to: Vec<u64>,
    /// Pc of the native instruction that raised the exception being dispatched (0 if none).
    pub(crate) native_error_pc: usize,
    /// The current apply comes from native code, whose call site names the caller frame.
    pub(crate) native_apply: bool,
    /// Call site (module, ip) of a traced native BIF whose call event was emitted and which
    /// yielded before finishing, with the trace actions its return events still need.
    /// Native code ran `timeout` while tracing is active; the executor emits the receive event.
    pub(crate) native_timeout_trace: bool,
    pub(crate) traced_native_call: Option<(usize, usize, Vec<crate::trace::CallActions>)>,
    /// Native call site of the BIF being executed (erts `c_p->i`), 0 outside such a call.
    pub(crate) native_call_pc: usize,
    /// `error_info` of the current native exception (erts keeps it with the stack trace).
    pub(crate) native_error_info: Option<Box<arinsal_etf::OwnedTerm>>,
    /// Remaining time computed by a native `wait_timeout`, consumed by the following wait.
    pub(crate) native_wait_timeout: Option<u64>,
    /// The pending native wait belongs to a receive without clauses.
    pub(crate) native_wait_self: bool,
    /// Static NIF identity, native return point and target scheduler class of a NIF call
    /// (or `enif_schedule_nif` continuation) waiting for a scheduler of that class.
    pub(crate) native_dirty_nif: Option<(usize, usize, arinsal_bifs::SchedulerClass)>,
    /// Return address and call site of the native call that `native_retry` redoes.
    pub(crate) native_retry_site: Option<(usize, usize)>,
    /// The interpreter returned only to hand control to `native_pc`; the slice continues.
    pub(crate) native_transfer: bool,
    /// Native continuation to install after an interpreted external call returns.
    pub(crate) native_resume_after_call: Option<usize>,
    /// The BIF failure behind the current native exception, so the scheduler can name the BIF
    /// and its arguments as the top frame (erts passes the MFA to `raise_exception`).
    pub(crate) native_bif_error: Option<NativeBifError>,
    /// Stable snapshot and cursor for a trapped `persistent_term:get/0` call.
    pub(crate) persistent_get_all: Option<PersistentGetAll>,
    /// Result of a published `persistent_term` update, returned when the yielded
    /// updater runs again (erts resumes the suspended updater after `table_updater`).
    pub(crate) persistent_update_result: Option<Term>,
    /// A process-local BIF trap waiting for its private continuation export.
    pub(crate) bif_trap: Option<BifTrapPending>,
    /// Operand registers of `apply` calls in progress. A callee may collect before it
    /// yields back to re-execute the apply, so these stay GC roots until it returns.
    pub(crate) apply_roots: Vec<Term>,
    /// A NIF call rescheduled to another scheduler class; its arguments are GC roots.
    pub(crate) nif_pending: Option<crate::natives::nif::PendingNif>,
    // Saved continuation addresses for traces still referenced by handler code.
    pub(crate) raw_traces: Vec<stacktrace::RawTrace>,
    /// Reusable slots for raw traces that have been materialized.
    pub(crate) free_raw_trace_slots: Vec<usize>,
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
    pub(crate) dictionary: Vec<(Term, Term)>,
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
    pub(crate) import: usize,
    pub(crate) continuation: &'static str,
    pub(crate) state: std::sync::Arc<arinsal_term::MagicRef>,
    pub(crate) gc_was_enabled: bool,
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
            crate::natives::sys::gc_spawn_defaults().min_bin_vheap_size as u64,
        );
        let mut process = Self {
            header: ProcessHeader::default(),
            x: vec![Term::NIL; x_registers].into_boxed_slice(),
            fr: vec![0.0; float_registers].into_boxed_slice(),
            heap,
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
