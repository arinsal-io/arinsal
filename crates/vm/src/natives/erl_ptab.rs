//! `erlang:processes/0`, `erlang:ports/0`, and their hidden continuation export.
//!
//! Port of erts/emulator/beam/erl_ptab.c (erts_ptab_list, ptab_list_bif_engine,
//! ptab_list_continue), OTP-29.1.1. Each invocation keeps its table walk in a magic binary and
//! resumes through the ordinary `erlang:ptab_list_continue/2` bif_table export.

use crate::bif_table::{bif_args, set_bif_arg};
use crate::bif_traps::TrapContext;
use crate::natives::bif::bif_ret;
use crate::{ExportTrap, Process, VmError};
use arinsal_beamasm::ProcessHeader;
use arinsal_bifs::{BifError, ProcessHeapHandle};
use arinsal_sched::Scheduler;
use arinsal_term::{MagicBin, Term, TermBuilder};
use std::sync::Arc;

pub(crate) const PTAB_LIST_CONTINUATION: &str = "erlang:ptab_list_continue/2";
const ERTS_PTAB_LIST_STATE_SIZE: usize = 64;
const CHUNK_SIZE: u32 = 1000;
const INDICES_PER_RED: u32 = 25;
const MIN_START_REDS: u32 = CHUNK_SIZE / INDICES_PER_RED;
const CONSES_PER_RED: usize = 75;
const MAX_DELETED_REDS: u32 = CHUNK_SIZE / INDICES_PER_RED;

#[derive(Clone, Copy, Eq, PartialEq)]
enum PtabListBifState {
    Initializing,
    InspectingTable,
    InspectingDeleted,
    BuildingResult,
    ReturnResult,
}

enum PtabListTable {
    Processes(Arc<Scheduler<Process>>),
    Ports {
        runtime: &'static crate::process::Runtime,
        port_zero: Term,
    },
}

enum PtabListSnapshot {
    Processes(arinsal_sched::PtabListSnapshot<Process>),
    Ports(crate::port::PortPtabListSnapshot),
}

/// Per-call `ErtsPTabListBifData` stored in the trapping magic binary.
struct PtabListBifData {
    ptab: Option<PtabListTable>,
    state: PtabListBifState,
    snapshot: Option<PtabListSnapshot>,
    chunk: Vec<u64>,
    tix: u32,
    pid_ix: usize,
    pid_sz: usize,
    pid: Vec<Term>,
}

impl PtabListBifData {
    fn new(ptab: PtabListTable) -> Self {
        Self {
            ptab: Some(ptab),
            state: PtabListBifState::Initializing,
            snapshot: None,
            chunk: Vec::new(),
            tix: 0,
            pid_ix: 0,
            pid_sz: 0,
            pid: Vec::new(),
        }
    }

    fn table_max(&self) -> u32 {
        match self.ptab.as_ref().expect("active ptab list owns its table") {
            PtabListTable::Processes(_) => arinsal_term::ptab::process_table_layout().max(),
            PtabListTable::Ports { .. } => arinsal_term::ptab::port_table_layout().max(),
        }
    }

    /// Initialize the table state and inspect chunk zero without releasing its list lock.
    // Port of erts/emulator/beam/erl_ptab.c (ptab_list_bif_engine, INITIALIZING), OTP-29.1.1.
    fn initialize(&mut self) -> u32 {
        let table_max = self.table_max();
        let end = table_max.min(CHUNK_SIZE);
        let chunk_count = table_max.div_ceil(CHUNK_SIZE) as usize;
        self.chunk.resize(chunk_count, 0);
        let track_deletions = chunk_count > 1;
        let pid = std::cell::RefCell::new(&mut self.pid);

        let (snapshot, invocation_interval, count) =
            match self.ptab.as_ref().expect("active ptab list owns its table") {
                PtabListTable::Processes(scheduler) => {
                    let (snapshot, interval, count) = scheduler.begin_ptab_list_chunk(
                        end,
                        track_deletions,
                        |count| {
                            let mut pid = pid.borrow_mut();
                            let additional = count.saturating_sub(pid.len());
                            pid.reserve_exact(additional);
                        },
                        |process_id| {
                            if let Some(term) = process_id.to_term() {
                                pid.borrow_mut().push(term);
                            }
                        },
                    );
                    (PtabListSnapshot::Processes(snapshot), interval, count)
                }
                PtabListTable::Ports { runtime, port_zero } => {
                    let (snapshot, interval, count) = runtime.ports.begin_ptab_list_chunk(
                        end,
                        track_deletions,
                        |count| {
                            let mut pid = pid.borrow_mut();
                            let additional = count.saturating_add(1).saturating_sub(pid.len());
                            pid.reserve_exact(additional);
                            pid.push(*port_zero);
                        },
                        |id| {
                            if id != 0
                                && let Some(term) = Term::port(id)
                            {
                                pid.borrow_mut().push(term);
                            }
                        },
                    );
                    (PtabListSnapshot::Ports(snapshot), interval, count + 1)
                }
            };

        self.pid_sz = count;
        self.pid_ix = self.pid.len();
        debug_assert!(self.pid_ix <= self.pid_sz);
        self.chunk[0] = invocation_interval;
        self.tix = end;
        self.snapshot = Some(snapshot);
        self.state = if chunk_count == 1 {
            PtabListBifState::BuildingResult
        } else {
            PtabListBifState::InspectingTable
        };
        end / INDICES_PER_RED
    }

    /// Inspect the next full table chunk under the table's list lock.
    // Port of erts/emulator/beam/erl_ptab.c (ptab_list_bif_engine, INSPECTING_TABLE), OTP-29.1.1.
    fn inspect_table_chunk(&mut self, end: u32) -> u32 {
        let first = self.tix;
        let chunk_index = (first / CHUNK_SIZE) as usize;
        let interval = match (
            self.ptab.as_ref().expect("active ptab list owns its table"),
            self.snapshot.as_ref().unwrap(),
        ) {
            (PtabListTable::Processes(_), PtabListSnapshot::Processes(snapshot)) => snapshot
                .scan_chunk_with(first, end, |process_id| {
                    if let Some(term) = process_id.to_term() {
                        self.pid.push(term);
                    }
                }),
            (PtabListTable::Ports { .. }, PtabListSnapshot::Ports(snapshot)) => snapshot
                .scan_chunk_with(first, end, |id| {
                    if id != 0
                        && let Some(term) = Term::port(id)
                    {
                        self.pid.push(term);
                    }
                }),
            _ => unreachable!("ptab list table and snapshot kinds match"),
        };
        self.chunk[chunk_index] = interval;
        self.tix = end;
        self.pid_ix = self.pid.len();
        let table_max = self.table_max();
        if end == table_max {
            self.state = PtabListBifState::InspectingDeleted;
        }
        (end - first) / INDICES_PER_RED
    }

    /// Reconcile elements deleted between their table chunk's interval and the scan.
    // Port of erts/emulator/beam/erl_ptab.c (ptab_list_bif_engine, INSPECTING_DELETED), OTP-29.1.1.
    fn inspect_deleted(&mut self, max_reds: u32) -> (u32, bool) {
        let chunks = &self.chunk;
        let pid = &mut self.pid;
        let (spent, done) = match self.snapshot.as_mut().unwrap() {
            PtabListSnapshot::Processes(snapshot) => {
                snapshot.inspect_deleted_with(chunks, max_reds, |process_id| {
                    if let Some(term) = process_id.to_term() {
                        pid.push(term);
                    }
                })
            }
            PtabListSnapshot::Ports(snapshot) => {
                snapshot.inspect_deleted_with(chunks, max_reds, |id| {
                    if id != 0
                        && let Some(term) = Term::port(id)
                    {
                        pid.push(term);
                    }
                })
            }
        };
        self.pid_ix = self.pid.len();
        if done {
            self.state = PtabListBifState::BuildingResult;
        }
        (spent, done)
    }
}

arinsal_term::magic_payload!(TrapContext<PtabListBifData> => cleanup_ptab_list_bif_data);

/// `processes/0`.
// Port of erts/emulator/beam/bif.c (processes_0), OTP-29.1.1.
pub(crate) extern "C" fn processes_0(c_p: *mut ProcessHeader, reg: *mut u64, i: u64) -> u64 {
    ptab_list(c_p, reg, i, true)
}

/// `ports/0`.
// Port of erts/emulator/beam/bif.c (ports_0), OTP-29.1.1.
pub(crate) extern "C" fn ports_0(c_p: *mut ProcessHeader, reg: *mut u64, i: u64) -> u64 {
    ptab_list(c_p, reg, i, false)
}

/// `erlang:ptab_list_continue/2`.
// Port of erts/emulator/beam/erl_ptab.c (ptab_list_continue), OTP-29.1.1.
pub(crate) extern "C" fn ptab_list_continue_2(
    c_p: *mut ProcessHeader,
    reg: *mut u64,
    i: u64,
) -> u64 {
    let [mut accumulator, mut magic_ref] = bif_args::<2>(reg);
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let reds_left = process.heap.abi.fcalls.max(0) as u32;
    let result = magic_ref.with_magic_payload_mut::<TrapContext<PtabListBifData>, _>(|state| {
        let state = &mut state.0;
        ptab_list_bif_engine(
            process,
            state,
            &mut accumulator,
            Some(&mut magic_ref),
            reds_left,
        )
    });
    let Some(result) = result else {
        return fail(
            c_p,
            reg,
            i,
            process,
            "ptab_list_continue",
            &[accumulator, magic_ref],
            BifError::BADARG,
        );
    };
    set_bif_arg(reg, 0, accumulator);
    set_bif_arg(reg, 1, magic_ref);
    let done = match result {
        Ok(done) => done,
        Err(error) => {
            return fail(
                c_p,
                reg,
                i,
                process,
                "ptab_list_continue",
                &[accumulator, magic_ref],
                error,
            );
        }
    };
    if done {
        return crate::native_hooks::raw(accumulator);
    }

    crate::bif_traps::vbump_all_reds(process);
    let trap = ExportTrap::new(
        process,
        PTAB_LIST_CONTINUATION,
        vec![accumulator, magic_ref],
    );
    bif_ret(c_p, i, Err(VmError::TrapExport(trap)))
}

fn ptab_list(c_p: *mut ProcessHeader, reg: *mut u64, i: u64, processes: bool) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let function = if processes { "processes" } else { "ports" };
    let reds_left = process.heap.abi.fcalls.max(0) as u32;

    let Some(runtime) = process.runtime.as_ref() else {
        if processes {
            return fail(c_p, reg, i, process, function, &[], BifError::BADARG);
        }
        let port = match Term::port(0) {
            Some(port) => port,
            None => return fail(c_p, reg, i, process, function, &[], BifError::SystemLimit),
        };
        return match TermBuilder::new(&mut ProcessHeapHandle(&mut process.heap))
            .list_from_iter([port])
        {
            Ok(value) => crate::native_hooks::raw(value),
            Err(_) => fail(c_p, reg, i, process, function, &[], BifError::SystemLimit),
        };
    };

    let ptab = if processes {
        let scheduler = match runtime.scheduler_arc() {
            Ok(scheduler) => scheduler,
            Err(_) => return fail(c_p, reg, i, process, function, &[], BifError::SystemLimit),
        };
        PtabListTable::Processes(scheduler)
    } else {
        let Some(port_zero) = Term::port(0) else {
            return fail(c_p, reg, i, process, function, &[], BifError::SystemLimit);
        };
        PtabListTable::Ports { runtime, port_zero }
    };
    let state = MagicBin::with_erts_payload_size_and_refn(
        TrapContext::new(PtabListBifData::new(ptab)),
        ERTS_PTAB_LIST_STATE_SIZE,
        arinsal_sched::unique::next_ref_words(),
    );
    let mut accumulator = Term::NIL;
    let done = if reds_left < MIN_START_REDS {
        false
    } else {
        match run_state(process, &state, &mut accumulator, reds_left) {
            Ok(done) => done,
            Err(error) => return fail(c_p, reg, i, process, function, &[], error),
        }
    };
    if done {
        return crate::native_hooks::raw(accumulator);
    }

    let magic_ref = match TermBuilder::new(&mut ProcessHeapHandle(&mut process.heap))
        .magic_ref(MagicBin::clone(&state))
    {
        Ok(magic_ref) => magic_ref,
        Err(_) => return fail(c_p, reg, i, process, function, &[], BifError::SystemLimit),
    };
    crate::bif_traps::vbump_all_reds(process);
    set_bif_arg(reg, 0, accumulator);
    let trap = ExportTrap::new(
        process,
        PTAB_LIST_CONTINUATION,
        vec![accumulator, magic_ref],
    );
    bif_ret(c_p, i, Err(VmError::TrapExport(trap)))
}

fn run_state(
    process: &mut Process,
    state: &MagicBin,
    accumulator: &mut Term,
    reds_left: u32,
) -> Result<bool, BifError> {
    state
        .with_payload_mut::<TrapContext<PtabListBifData>, _>(|state| {
            ptab_list_bif_engine(process, &mut state.0, accumulator, None, reds_left)
        })
        .ok_or(BifError::BADARG)?
}

// Port of erts/emulator/beam/erl_ptab.c (ptab_list_bif_engine), OTP-29.1.1.
fn ptab_list_bif_engine(
    process: &mut Process,
    state: &mut PtabListBifData,
    accumulator: &mut Term,
    magic_ref: Option<&mut Term>,
    reds_left: u32,
) -> Result<bool, BifError> {
    let mut magic_ref = magic_ref;
    let mut have_reds = reds_left;
    let mut charged_reds = 0_u32;
    let mut first_iteration = true;

    loop {
        if !first_iteration && have_reds == 0 && state.state != PtabListBifState::ReturnResult {
            break;
        }
        first_iteration = false;

        let reds = match state.state {
            PtabListBifState::Initializing => state.initialize(),
            PtabListBifState::InspectingTable => {
                let first = state.tix;
                let end = first.saturating_add(CHUNK_SIZE).min(state.table_max());
                let chunk_reds = (end - first) / INDICES_PER_RED;
                if charged_reds != 0 && chunk_reds > have_reds {
                    break;
                }
                state.inspect_table_chunk(end)
            }
            PtabListBifState::InspectingDeleted => {
                let (reds, done) = state.inspect_deleted(have_reds.min(MAX_DELETED_REDS));
                if done {
                    state.state = PtabListBifState::BuildingResult;
                }
                reds
            }
            PtabListBifState::BuildingResult => {
                let (done, reds) = build_ptab_result(
                    process,
                    &mut state.pid,
                    accumulator,
                    magic_ref.as_deref_mut(),
                    have_reds,
                )?;
                state.pid_ix = state.pid.len();
                debug_assert!(state.pid_ix <= state.pid_sz);
                if done {
                    state.state = PtabListBifState::ReturnResult;
                } else {
                    state.pid_sz = state.pid_ix;
                    state.pid.shrink_to_fit();
                }
                reds
            }
            PtabListBifState::ReturnResult => {
                state.snapshot.take();
                state.pid = Vec::new();
                state.chunk = Vec::new();
                state.pid_ix = 0;
                state.pid_sz = 0;
                state.tix = 0;
                state.ptab.take();
                bump_reds(process, charged_reds);
                return Ok(true);
            }
        };

        have_reds = have_reds.saturating_sub(reds);
        charged_reds = charged_reds.saturating_add(reds);
        if state.state == PtabListBifState::InspectingTable {
            let next_len = (state.table_max() - state.tix).min(CHUNK_SIZE);
            let next_reds = next_len / INDICES_PER_RED;
            if next_reds > have_reds {
                have_reds = 0;
            }
        }
    }
    bump_reds(process, charged_reds);
    Ok(false)
}

/// Builds result cons cells from highest table indexes to lowest, as `ptab_list_bif_engine` does.
// Port of erts/emulator/beam/erl_ptab.c (BUILDING_RESULT), OTP-29.1.1.
fn build_ptab_result(
    process: &mut Process,
    terms: &mut Vec<Term>,
    accumulator: &mut Term,
    magic_ref: Option<&mut Term>,
    reds_left: u32,
) -> Result<(bool, u32), BifError> {
    let conses = terms
        .len()
        .min((reds_left as usize).saturating_mul(CONSES_PER_RED));
    if conses == 0 {
        return Ok((terms.is_empty(), 0));
    }
    let mut objv = [
        *accumulator,
        magic_ref.as_deref().copied().unwrap_or(Term::NIL),
    ];
    let live = if magic_ref.is_some() { 2 } else { 1 };
    process.ensure_objv(conses.saturating_mul(2), &mut objv[..live]);
    *accumulator = objv[0];
    if let Some(magic_ref) = magic_ref {
        *magic_ref = objv[1];
    }
    let start = terms.len() - conses;
    let built = TermBuilder::new(&mut ProcessHeapHandle(&mut process.heap))
        .reserve_cons_list(conses)
        .and_then(|builder| {
            builder.prepend_exact_with_tail(terms[start..].iter().rev().copied(), *accumulator)
        })
        .map_err(|_| BifError::SystemLimit)?;
    terms.truncate(start);
    *accumulator = built;
    Ok((terms.is_empty(), (conses / CONSES_PER_RED) as u32))
}

fn bump_reds(process: &mut Process, reductions: u32) {
    process.heap.abi.fcalls = process
        .heap
        .abi
        .fcalls
        .saturating_sub(reductions.min(i32::MAX as u32) as i32)
        .max(0);
}

#[cold]
#[inline(never)]
fn fail(
    c_p: *mut ProcessHeader,
    _reg: *mut u64,
    i: u64,
    process: &mut Process,
    function: &str,
    args: &[Term],
    error: BifError,
) -> u64 {
    let error = crate::exceptions::bif_error(process, "erlang", function, args, error);
    bif_ret(c_p, i, Err(error))
}
