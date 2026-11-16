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

struct ProcessListData {
    snapshot: Option<arinsal_sched::PtabListSnapshot<Process>>,
    scheduler: Arc<Scheduler<Process>>,
    pids: Vec<Term>,
    chunk_intervals: Vec<u64>,
    next_index: u32,
    deleted_done: bool,
}

struct PortListData {
    snapshot: Option<crate::port::PortPtabListSnapshot>,
    runtime: &'static crate::process::Runtime,
    ids: Vec<Term>,
    chunk_intervals: Vec<u64>,
    next_index: u32,
    deleted_done: bool,
}

/// Per-call state held by the `ErtsPTabListBifData` magic binary.
enum PtabListBifData {
    Processes(ProcessListData),
    Ports(PortListData),
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
        let table_max = match &*state {
            PtabListBifData::Processes(_) => arinsal_term::ptab::process_table_layout().max(),
            PtabListBifData::Ports(_) => arinsal_term::ptab::port_table_layout().max(),
        };
        ptab_list_bif_engine(
            process,
            state,
            &mut accumulator,
            Some(&mut magic_ref),
            table_max,
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
    let table_max = if processes {
        arinsal_term::ptab::process_table_layout().max()
    } else {
        arinsal_term::ptab::port_table_layout().max()
    };
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

    let state = if processes {
        let scheduler = match runtime.scheduler_arc() {
            Ok(scheduler) => scheduler,
            Err(_) => return fail(c_p, reg, i, process, function, &[], BifError::SystemLimit),
        };
        let list = ProcessListData {
            snapshot: None,
            scheduler,
            pids: Vec::new(),
            chunk_intervals: Vec::with_capacity(table_max.div_ceil(CHUNK_SIZE) as usize),
            next_index: 0,
            deleted_done: false,
        };
        PtabListBifData::Processes(list)
    } else {
        let Some(port_zero) = Term::port(0) else {
            return fail(c_p, reg, i, process, function, &[], BifError::SystemLimit);
        };
        let list = PortListData {
            snapshot: None,
            runtime,
            ids: vec![port_zero],
            chunk_intervals: Vec::with_capacity(table_max.div_ceil(CHUNK_SIZE) as usize),
            next_index: 0,
            deleted_done: false,
        };
        PtabListBifData::Ports(list)
    };
    let state = MagicBin::with_erts_payload_size_and_refn(
        TrapContext::new(state),
        ERTS_PTAB_LIST_STATE_SIZE,
        arinsal_sched::unique::next_ref_words(),
    );
    let mut accumulator = Term::NIL;
    let done = if reds_left < MIN_START_REDS {
        false
    } else {
        match run_state(process, &state, &mut accumulator, table_max, reds_left) {
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
    table_max: u32,
    reds_left: u32,
) -> Result<bool, BifError> {
    state
        .with_payload_mut::<TrapContext<PtabListBifData>, _>(|state| {
            ptab_list_bif_engine(
                process,
                &mut state.0,
                accumulator,
                None,
                table_max,
                reds_left,
            )
        })
        .ok_or(BifError::BADARG)?
}

/// The Rust table snapshots preserve erts' initial interval and deleted-entry reconciliation.
// Port of erts/emulator/beam/erl_ptab.c (ptab_list_bif_engine), OTP-29.1.1.
fn ptab_list_bif_engine(
    process: &mut Process,
    state: &mut PtabListBifData,
    accumulator: &mut Term,
    magic_ref: Option<&mut Term>,
    table_max: u32,
    reds_left: u32,
) -> Result<bool, BifError> {
    match state {
        PtabListBifData::Processes(list) => {
            run_process_list(process, list, table_max, reds_left, accumulator, magic_ref)
        }
        PtabListBifData::Ports(list) => {
            run_port_list(process, list, table_max, reds_left, accumulator, magic_ref)
        }
    }
}

fn run_process_list(
    process: &mut Process,
    list: &mut ProcessListData,
    table_max: u32,
    reds_left: u32,
    accumulator: &mut Term,
    magic_ref: Option<&mut Term>,
) -> Result<bool, BifError> {
    let (table_done, mut spent) = scan_process_table(list, table_max, reds_left);
    if !table_done {
        bump_reds(process, spent);
        return Ok(false);
    }
    if !list.deleted_done {
        let max_deleted_reds = reds_left.saturating_sub(spent).min(MAX_DELETED_REDS);
        let (deleted_reds, done) = list
            .snapshot
            .as_mut()
            .expect("table scan initialized its snapshot")
            .inspect_deleted_with(&list.chunk_intervals, max_deleted_reds, |pid| {
                if let Some(pid) = pid.to_term() {
                    list.pids.push(pid);
                }
            });
        list.deleted_done = done;
        spent += deleted_reds;
        if !done {
            bump_reds(process, spent);
            return Ok(false);
        }
    }
    let (done, cons_reds) = build_ptab_result(
        process,
        &mut list.pids,
        accumulator,
        magic_ref,
        reds_left.saturating_sub(spent),
    )?;
    bump_reds(process, spent.saturating_add(cons_reds));
    if done {
        list.snapshot.take();
    }
    Ok(done)
}

fn scan_process_table(list: &mut ProcessListData, table_max: u32, reds_left: u32) -> (bool, u32) {
    if list.snapshot.is_none() {
        list.snapshot = Some(list.scheduler.begin_ptab_list());
        let count = list
            .snapshot
            .as_ref()
            .expect("snapshot initialized")
            .count();
        list.pids
            .reserve_exact(count.saturating_sub(list.pids.capacity()));
    }
    let mut spent = 0_u32;
    let mut first_chunk = true;
    while list.next_index < table_max {
        let first = list.next_index;
        let end = (first + CHUNK_SIZE).min(table_max);
        let chunk_reds = (end - first) / INDICES_PER_RED;
        if !first_chunk && (spent >= reds_left || chunk_reds > reds_left - spent) {
            break;
        }
        let interval = list
            .snapshot
            .as_ref()
            .expect("snapshot initialized")
            .scan_chunk_with(first, end, |pid| {
                if let Some(pid) = pid.to_term() {
                    list.pids.push(pid);
                }
            });
        list.chunk_intervals.push(interval);
        list.next_index = end;
        spent += (end - first) / INDICES_PER_RED;
        first_chunk = false;
    }
    (list.next_index >= table_max, spent)
}

fn run_port_list(
    process: &mut Process,
    list: &mut PortListData,
    table_max: u32,
    reds_left: u32,
    accumulator: &mut Term,
    magic_ref: Option<&mut Term>,
) -> Result<bool, BifError> {
    let (table_done, mut spent) = scan_port_table(list, table_max, reds_left);
    if !table_done {
        bump_reds(process, spent);
        return Ok(false);
    }
    if !list.deleted_done {
        let max_deleted_reds = reds_left.saturating_sub(spent).min(MAX_DELETED_REDS);
        let (deleted_reds, done) = list
            .snapshot
            .as_mut()
            .expect("table scan initialized its snapshot")
            .inspect_deleted_with(&list.chunk_intervals, max_deleted_reds, |id| {
                if id != 0
                    && let Some(id) = Term::port(id)
                {
                    list.ids.push(id);
                }
            });
        list.deleted_done = done;
        spent += deleted_reds;
        if !done {
            bump_reds(process, spent);
            return Ok(false);
        }
    }
    let (done, cons_reds) = build_ptab_result(
        process,
        &mut list.ids,
        accumulator,
        magic_ref,
        reds_left.saturating_sub(spent),
    )?;
    bump_reds(process, spent.saturating_add(cons_reds));
    if done {
        list.snapshot.take();
    }
    Ok(done)
}

fn scan_port_table(list: &mut PortListData, table_max: u32, reds_left: u32) -> (bool, u32) {
    if list.snapshot.is_none() {
        list.snapshot = Some(list.runtime.ports.begin_ptab_list());
        let count = list
            .snapshot
            .as_ref()
            .expect("snapshot initialized")
            .count();
        list.ids
            .reserve_exact(count.saturating_sub(list.ids.capacity()));
    }
    let mut spent = 0_u32;
    let mut first_chunk = true;
    while list.next_index < table_max {
        let first = list.next_index;
        let end = (first + CHUNK_SIZE).min(table_max);
        let chunk_reds = (end - first) / INDICES_PER_RED;
        if !first_chunk && (spent >= reds_left || chunk_reds > reds_left - spent) {
            break;
        }
        let interval = list
            .snapshot
            .as_ref()
            .expect("snapshot initialized")
            .scan_chunk_with(first, end, |id| {
                if id != 0
                    && let Some(id) = Term::port(id)
                {
                    list.ids.push(id);
                }
            });
        list.chunk_intervals.push(interval);
        list.next_index = end;
        spent += (end - first) / INDICES_PER_RED;
        first_chunk = false;
    }
    (list.next_index >= table_max, spent)
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
    process
        .ensure_objv(conses.saturating_mul(2), &mut objv[..live])
        .map_err(|_| BifError::SystemLimit)?;
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
