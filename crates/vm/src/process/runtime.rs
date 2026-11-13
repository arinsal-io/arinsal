use super::*;

/// Shared interpreter and scheduler handles for a set of local processes.
pub(crate) struct Runtime {
    pub(crate) statistics: crate::natives::sys::StatisticsState,
    /// Node-wide backtrace depth shared by scheduler VM replicas.
    pub(crate) backtrace_depth: AtomicUsize,
    /// The node's code indexes and their code tables.
    pub(super) code: Arc<crate::code_ix::CodeIndexes>,
    /// Runtime-owned stable exports indexed by the target id interned with each continuation.
    /// The entry remains the indirection when a module replaces code, as in erts' export table.
    pub(super) trap_exports:
        [OnceLock<Arc<arinsal_beamasm::bif::ExportEntry>>; crate::bif_traps::TRAP_EXPORT_CAPACITY],
    pub(crate) system_processes: Mutex<std::collections::HashSet<Pid>>,
    pub(super) otp_root: Option<std::path::PathBuf>,
    pub(crate) dirty_signal_handlers: Mutex<std::collections::HashSet<Pid>>,
    /// Pid of `erts_literal_area_collector` (an unregistered system process).
    pub(crate) literal_collector: Mutex<Option<Pid>>,
    pub(super) paths: Vec<std::path::PathBuf>,
    // Set once when the scheduler starts; read without a lock like erts' scheduler data.
    /// Held for the VM lifetime (erts reads its scheduler data through globals / `esdp`, with no
    /// per-process runtime refcount).
    pub(super) scheduler: OnceLock<Arc<Scheduler<Process>>>,
    /// `process_reg` (`regtab_rwmtx`). Names are atom indexes, not strings.
    pub(crate) reg: crate::register::RegisterTable,
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
    /// `meta_name_tab`, read without taking the global ETS registry lock.
    pub(crate) named_ets: Arc<arinsal_ets::NamedTableIndex>,
    pub(crate) ets: std::sync::RwLock<arinsal_ets::Registry>,
    pub(super) result: Mutex<mpsc::Sender<Result<ScheduledResult, VmError>>>,
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
    /// The persistent term store of the node, looked up once.
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

impl Process {
    pub(crate) fn trap_export_entry(
        &self,
        target: &'static crate::bif_traps::ContinuationTarget,
    ) -> Arc<arinsal_beamasm::bif::ExportEntry> {
        self.runtime.map_or_else(
            || {
                Arc::new(arinsal_beamasm::bif::ExportEntry::new(
                    target.module_atom,
                    target.function_atom,
                    target.arity as u8,
                ))
            },
            |runtime| runtime.trap_export_entry(target),
        )
    }
}

impl Runtime {
    // Port of erts/emulator/beam/export.c:200-245 (erts_export_get_or_make_stub), OTP-29.1.1.
    pub(crate) fn trap_export_entry(
        &self,
        target: &'static crate::bif_traps::ContinuationTarget,
    ) -> Arc<arinsal_beamasm::bif::ExportEntry> {
        let mfa = (target.module_atom, target.function_atom, target.arity as u8);
        let export = self
            .trap_exports
            .get(target.trap_export_id)
            .expect("trap export table capacity")
            .get_or_init(|| {
                // A hidden trap export (`erts_init_trap_export`) is a static `Export` that no
                // export table holds, so reloading its module cannot invalidate it.
                let hidden = target.trap_function.is_some();
                let export = if hidden {
                    crate::beamasm_integration::make_export(mfa).map(Arc::clone)
                } else {
                    crate::export::export_get_or_make_stub(mfa)
                };
                export.unwrap_or_else(|| {
                    Arc::new(arinsal_beamasm::bif::ExportEntry::new(mfa.0, mfa.1, mfa.2))
                })
            });
        Arc::clone(export)
    }

    /// Read ranges and module tables from one active code index.
    pub(crate) fn with_active_code<R>(
        &self,
        read: impl FnOnce(&[crate::native_bridge::ModuleRange], &crate::load::CodeTables) -> R,
    ) -> R {
        self.code.with_active_code(read)
    }

    /// Catch table of this node's `erts_active_code_ix()`.
    // Port of erts/emulator/beam/code_ix.h:362 (`erts_active_code_ix` is one atomic, not
    // thread-local) and beam_catches.c:146 (`bccix[erts_active_code_ix()]`), OTP-29.1.1.
    pub(crate) fn code_indexes(&self) -> &Arc<crate::code_ix::CodeIndexes> {
        &self.code
    }

    /// Export slot selected by the process-visible code index.
    pub(crate) fn export_entry(
        &self,
        mfa: (arinsal_term::Atom, arinsal_term::Atom, u8),
        code_ix: usize,
    ) -> Option<&'static arinsal_beamasm::bif::ExportEntry> {
        crate::export::find_export_entry(&self.code, mfa, code_ix)
    }
}

/// Suspend-monitor pause of one process's receive timeout (erts `ErtsPausedProcTimer`): the
/// number of active suspends holding it and the time the timer had left when it was paused.
pub(crate) struct TimerPause {
    count: u32,
    /// `time_left_in_msec`; `None` when no unfired receive timer was set at the first pause
    /// (erts then creates no paused timer and the resume leaves the timer word alone).
    time_left_ms: Option<u64>,
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

    /// The scheduler once it exists; unlike [`Runtime::scheduler`] a missing one builds no error.
    #[inline]
    pub(crate) fn scheduler_if_started(&self) -> Option<&Arc<Scheduler<Process>>> {
        self.scheduler.get()
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
    /// BIF timers aimed at it. The first pause cancels a set receive timer that has not fired
    /// and records the time it had left, so it cannot fire while the process is suspended; a
    /// timer that already fired stays fired. The count nests like erts' `pptmr->count` and
    /// `paused_bif_timers->count`.
    // Port of erts/emulator/beam/erl_hl_timer.c:2849 (erts_pause_proc_timer), :1029
    // (create_paused_proc_timer) and :2864 (erts_pause_bif_timers), OTP-29.1.1.
    pub(crate) fn erts_pause_proc_timer(&self, process: &mut Process, pid: Pid) {
        if let Some(pause) = process.timer_pause_mut() {
            pause.count += 1;
            return;
        }
        // create_paused_proc_timer: only a set timer that is neither NONE nor TIMEDOUT is paused.
        let time_left_ms = match process.receive_timeout_pos {
            Some(pos) if !process.receive_timer_timed_out() => {
                let now = self.receive_clock_now_ms();
                // CANCEL_TIMER: the timer word is cleared, so a fire racing with the pause finds
                // nothing to time out. `receive_timeout_pos` stays set, as erts keeps
                // `common.timer` non-NONE (the paused timer) and the wait does not set it again.
                if let Some(probe) = process.signal_probe() {
                    probe.receive_timer().cancel();
                }
                Some(pos.saturating_sub(now))
            }
            _ => None,
        };
        process.slice_mut().timer_pause = Some(TimerPause {
            count: 1,
            time_left_ms,
        });
        if let Ok(scheduler) = self.scheduler() {
            scheduler.pause_target_timers(pid);
        }
    }

    /// `erts_resume_paused_proc_timer`: the last resume sets the receive timer again with the
    /// time it had left (`erts_set_proc_timer_uword(c_p, time_left)`, a zero left times out at
    /// once), and re-arms the BIF timers the pauses held.
    // Port of erts/emulator/beam/erl_hl_timer.c:2919 (erts_resume_paused_proc_timer) and :2949
    // (erts_resume_paused_bif_timers), OTP-29.1.1.
    pub(crate) fn erts_resume_proc_timer(&self, process: &mut Process, pid: Pid) {
        let Some(pause) = process.timer_pause_mut() else {
            return;
        };
        pause.count = pause.count.saturating_sub(1);
        if pause.count != 0 {
            return;
        }
        let Some(pause) = process.take_work(|work| work.timer_pause.take()) else {
            return;
        };
        if let Some(left) = pause.time_left_ms
            && process.receive_timeout_pos.is_some()
        {
            // The next wait finds the timer word clear and sets the timer at this position.
            process.receive_timeout_pos = Some(self.receive_clock_now_ms().saturating_add(left));
        }
        if let Ok(scheduler) = self.scheduler() {
            scheduler.resume_target_timers(pid);
        }
    }

    /// Current position of the clock receive timeout positions are taken on.
    fn receive_clock_now_ms(&self) -> u64 {
        arinsal_sched::receive_timeout_pos(0)
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
}
