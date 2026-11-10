use super::*;

impl Process {
    pub(super) fn collect_roots(
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
            && self.sig_cont().is_empty()
            && self.dictionary.is_none()
            && !self.seq_token_root.is_pointer()
            && self.apply_inline_len == 0
            && self.cold.as_ref().is_none_or(|cold| {
                cold.persistent_get_all.is_none()
                    && cold.apply_roots.is_empty()
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
        crate::seq_trace::sync_epoch(self);
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
        let (moved_indices, moved_fragments) =
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
                .max_heap_collection_checks(min_free, moved_fragments.iter())
            {
                Ok(checks) => checks,
                Err(error) => {
                    if !moved_indices.is_empty() {
                        self.inbox
                            .restore_moved_heaps(&moved_indices, moved_fragments);
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
                        self.inbox
                            .restore_moved_heaps(&moved_indices, moved_fragments);
                    }
                    return Err(VmError::Unsupported("max_heap_size".into()));
                }
            }
        }
        // Port of erts/emulator/beam/erl_gc.c:2616 (`setup_rootset`), OTP-29.1.1:
        // descriptors refer to live term slots; collection rewrites those slots in place.
        // `fvalue` and `ftrace` are roots when they hold a heap pointer.
        // Port of erts/emulator/beam/erl_gc.c:2678-2690 (`setup_rootset`), OTP-29.1.1.
        let mut exc_roots = [
            crate::native_hooks::from_raw(self.heap.abi.exc.fvalue),
            crate::native_hooks::from_raw(self.heap.abi.exc.ftrace),
        ];
        let exc_heap = |word: u64| matches!(word & 3, 1 | 2);
        let exc_rooted = [
            exc_heap(self.heap.abi.exc.fvalue),
            exc_heap(self.heap.abi.exc.ftrace),
        ];
        let mut roots = arinsal_term::GcRootSet::new();
        for (root, rooted) in exc_roots.iter_mut().zip(exc_rooted) {
            if rooted {
                roots.push_term(root);
            }
        }
        roots.push(&mut self.x[..live_x]);
        let mut moved = self.inbox.gc_root_slots_and_moved_messages(
            &moved_indices,
            moved_fragments,
            &mut roots,
        );
        roots.push(extra);
        if let Some(dictionary) = self.dictionary.as_mut() {
            dictionary.append_gc_root_slots(&mut roots);
        }
        let inline_len = usize::from(self.apply_inline_len);
        roots.push(&mut self.apply_inline[..inline_len]);
        if let Some(cold) = self.cold.as_deref_mut() {
            if let Some(state) = cold.persistent_get_all.as_mut() {
                roots.push_term(&mut state.result);
            }
            roots.push(&mut cold.apply_roots);
            if let Some(pending) = cold.nif_pending.as_mut() {
                roots.push(pending.roots_mut());
            }
            if let Some(trap) = cold.work.bif_trap.as_mut() {
                // erts keeps no process-heap pointer in a parked BIF's state that a collection
                // would miss: either the arguments (X registers) carry the terms, or the
                // process is not collectable (`F_DISABLE_GC`). A trap whose state holds
                // heap terms must therefore not be collected unless they are roots.
                debug_assert!(
                    !self.heap.gc_enabled
                        || trap.root_args_len() != 0
                        || trap.target.entry.is_none()
                        || !crate::bif_traps::state_holds_heap_terms(
                            &trap.state,
                            trap.direct_state.is_some()
                        ),
                    "collection with an unrooted heap term in the trap state of {}",
                    trap.continuation
                );
                let root_args = trap.root_args_len();
                if root_args != 0 {
                    roots.push(&mut trap.args[..root_args]);
                }
                if let Some(state) = trap.state_term.as_mut() {
                    roots.push_term(state);
                }
            }
            if let Some(cursor) = cold
                .ets_insert
                .as_deref_mut()
                .and_then(crate::proc_create::EtsInsert::cursor_mut)
            {
                roots.push_term(cursor);
            }
            if let Some(state) = cold.ets_select.as_mut() {
                roots.push(state.saved.roots_mut());
            }
            for root in crate::dirty::dirty_root_slots(
                &mut cold.dirty_bif,
                &mut cold.static_nif_done,
                &mut cold.dirty_bif_trap_target,
                &mut cold.dirty_bif_original,
                &mut cold.dirty_bif_exception_trace,
            ) {
                roots.push_term(root);
            }
        }
        for event in &mut self.sig_cont {
            if let Some(message) = Self::sig_cont_message_mut(&mut event.payload) {
                message.append_heap_roots_mut(&mut roots);
            }
        }
        roots.push_term(&mut self.seq_token_root);
        let mut extra_rootset = arinsal_term::GcRootSet::new();
        let stats = if hibernate {
            self.heap
                .collect_hibernate_root_slots(&mut roots, &mut extra_rootset)
        } else {
            self.heap
                .collect_with_root_slots(&mut roots, &mut extra_rootset, min_free, &mut moved)
        };
        drop((roots, extra_rootset));
        if !moved_indices.is_empty() {
            let heaps = moved
                .iter_mut()
                .map(|message| message.take_heap())
                .collect();
            drop(moved);
            self.inbox.restore_moved_heaps(&moved_indices, heaps);
        }
        if exc_rooted[0] {
            self.heap.abi.exc.fvalue = exc_roots[0].tagged_word();
        }
        if exc_rooted[1] {
            self.heap.abi.exc.ftrace = exc_roots[1].tagged_word();
        }
        let stats =
            stats.map_err(|error| VmError::Unsupported(format!("process GC: {error:?}")))?;
        if let Some(pid) = traced {
            self.trace_gc(pid, end_tag, stats.words_reclaimed as usize);
        }
        self.stats.gc.collections += stats.collections;
        self.stats.gc.nanoseconds += stats.nanoseconds;
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
        const DEFAULT_LIMIT: usize = 128 * 1024;
        // Debug builds take `ARINSAL_TEST_LONG_GC_HSIZE` so that tests reach the dirty
        // collection path with small heaps.
        #[cfg(debug_assertions)]
        let long_gc_hsize: usize = std::env::var("ARINSAL_TEST_LONG_GC_HSIZE")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_LIMIT);
        #[cfg(not(debug_assertions))]
        let long_gc_hsize: usize = DEFAULT_LIMIT;
        let mut size = self
            .heap
            .young_gen_usage()
            .saturating_add(self.heap.stack_words());
        // The old generation only counts for a major collection, so a young generation
        // plus old heap below the limit is below it whichever collection runs.
        if size.saturating_add(self.heap.old_used_words()) < long_gc_hsize {
            return false;
        }
        // A collection that starts as minor is checked on its young generation alone. If
        // that is already long, the dirty scheduler runs the minor attempt and any major
        // collection it falls back to. Otherwise the minor attempt runs here, and a minor
        // that cannot tenure is checked again as a major collection.
        let counted_major = self.heap.collection_is_major();
        let minor_is_long = !counted_major && size >= long_gc_hsize;
        let failed_minor =
            !counted_major && !minor_is_long && self.heap.minor_falls_back_to_major();
        let major = counted_major || failed_minor;
        if major {
            size = size.saturating_add(self.heap.old_used_words());
        }
        if size < long_gc_hsize {
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
        self.slice_mut().dirty_sys_gc = true;
        let cold = self.cold_mut();
        cold.dirty_gc = Some(if major {
            crate::proc_create::DirtyGc::Major
        } else {
            crate::proc_create::DirtyGc::Minor
        });
        // erts_schedule_dirty_sys_execution: the process moves to a dirty CPU scheduler
        // when it leaves this one.
        self.delay_heap_collection(need);
        // erl_gc.c, delay_garbage_collection (force_reschedule): the remaining reductions
        // are spent, and all but ERTS_ABANDON_HEAP_COST of them are not the process's own
        // work. The interpreter keeps its slice in the scheduler and never charges the rest
        // of it.
        if self.heap.native_active() && self.heap.abi.fcalls > ABANDON_HEAP_COST {
            self.virtual_reds = self
                .virtual_reds
                .saturating_add((self.heap.abi.fcalls - ABANDON_HEAP_COST) as u32);
        }
        self.set_force_yield(true);
        true
    }

    /// Run the collection a normal scheduler delayed, on the dirty CPU scheduler.
    // Port of erts/emulator/beam/erl_process.c:11196-11201 (erts_execute_dirty_system_task),
    // OTP-29.1.1: the roots are the `arity` registers the process was scheduled out with.
    pub(super) fn run_dirty_gc(&mut self) -> Result<(), VmError> {
        let Some(kind) = self.cold.as_mut().and_then(|cold| cold.dirty_gc.take()) else {
            return Ok(());
        };
        if kind == crate::proc_create::DirtyGc::Major {
            // F_NEED_FULLSWEEP.
            self.heap.request_full_sweep();
        }
        let live = switched_out_live(self);
        self.verify_dirty_gc_roots(live, "before dirty GC");
        let stats = self.collect_heap_roots(live, &mut [], 0)?;
        self.verify_dirty_gc_roots(live, "after dirty GC");
        crate::natives::sys::after_collection(self, stats.collections, stats.words_reclaimed);
        Ok(())
    }

    /// Check the roots presented to a dirty system task when validation is enabled.
    #[cfg(debug_assertions)]
    pub(crate) fn verify_dirty_gc_roots(&self, live: usize, when: &str) {
        if !arinsal_term::validate::active() {
            return;
        }
        arinsal_term::validate::set_context(when);
        let mut roots: Vec<Term> = self.x[..live.min(self.x.len())].to_vec();
        roots.extend(self.dirty_result_roots());
        arinsal_term::validate::check_roots_if_active(&self.heap, &roots, &[]);
    }

    #[cfg(not(debug_assertions))]
    #[inline(always)]
    pub(crate) fn verify_dirty_gc_roots(&self, _live: usize, _when: &str) {}

    // Port of erts/emulator/beam/beam_bif_load.c:1149 (check_process_code), OTP-29.1.1.
    // A process suspended in native code is checked by its native resume address and the
    // native continuation pointers on its stack; `self.module` is only its interpreter module.
    pub(crate) fn references_code(
        &mut self,
        module: usize,
        in_native: impl Fn(usize) -> bool,
    ) -> bool {
        // While native code runs (a signal handled from a runtime helper), `self.module` is
        // stale and the running function shows up through the native stack instead.
        match self.native_pc() {
            Some(pc) if in_native(pc) => return true,
            None if self.module == module && !self.heap.native_active() => return true,
            _ => {}
        }
        // Port of erts/emulator/beam/beam_bif_load.c:1171 and erl_nfunc_sched.h:120
        // (erts_check_nfunc_in_area), OTP-29.1.1: a native call that is redone when the process wakes (a parked BIF, a
        // NIF waiting for a dirty scheduler) keeps its return address outside the stack.
        let retry = self
            .native_retry()
            .and(self.native_retry_site())
            .is_some_and(|(resume, site)| in_native(resume) || in_native(site));
        let dirty = self
            .cold
            .as_deref()
            .and_then(|cold| cold.native_dirty_nif)
            .is_some_and(|(_, resume, _)| in_native(resume));
        if retry || dirty {
            return true;
        }
        for index in 0..self.heap.stack_words() {
            let Some(term) = self.heap.stack_get(index) else {
                continue;
            };
            let word = term.tagged_word() as usize;
            if in_native(word) {
                return true;
            }
            // A return or exception trace frame names its traced function (erts `&mfa`) by a
            // pc in it, kept as a small integer; the process returns into that function's
            // trace once it exits.
            if let Some((crate::trace::TraceFrame::Return { function_pc, .. }, _)) =
                crate::trace::trace_frame_at(&self.heap, index)
                && in_native(function_pc)
            {
                return true;
            }
        }
        // Port of erts/emulator/beam/beam_bif_load.c:1186-1214 (check_process_code), OTP-29.1.1.
        // Reached only when `i`, the native function and the stack do not use this module.
        // A saved exception dump that names the module is discarded; the process is still
        // not using the code, so the check returns false and a later purge may free it.
        self.discard_ftrace_in_code(module, &in_native);
        false
    }

    /// Drop `freason`, `fvalue` and `ftrace` when the saved stacktrace names `module`.
    // Port of erts/emulator/beam/beam_bif_load.c:1191-1213 (check_process_code), OTP-29.1.1.
    fn discard_ftrace_in_code(&mut self, module: usize, in_native: &impl Fn(usize) -> bool) {
        let word = self.heap.abi.exc.ftrace;
        // erts compares with `NIL`. This ABI stores "no trace" as 0 (every other clear of
        // the slot); `NIL` is `0x3b` and would pass the `!= 0` tests that stand in for `!= NIL`.
        if word == 0 || word == Term::NIL.tagged_word() {
            return;
        }
        let term = crate::native_hooks::from_raw(word);
        if !crate::stacktrace::saved_trace_names_code(term, module, in_native) {
            return;
        }
        self.heap.abi.exc.freason = arinsal_beamasm::exc::EXC_NULL;
        self.heap.abi.exc.fvalue = 0;
        self.heap.abi.exc.ftrace = 0;
    }
}
