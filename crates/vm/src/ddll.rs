//! Driver list and `erl_ddll` BIFs.
//! Port of erts/emulator/beam/erl_bif_ddll.c, OTP-29.1.1.
//!
//! The list holds the linked-in drivers (no `DE_Handle`) and dynamically loaded
//! ones. Driver library loading and callbacks live in `arinsal_drv`; this module
//! keeps the per-handle process entries, monitors, reference counts and port
//! counts, and the deferred `ddll_no_more_references` operation.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock, Weak};

use arinsal_drv::{Driver, DriverPort};
use arinsal_etf::OwnedTerm as O;
use arinsal_sched::{Pid, RunCtx, Scheduler};
use arinsal_term::{ProcessHeap, Term, TermBuilder, from_owned, global_atoms, to_owned};

use crate::process::Message;
use crate::{Process, VmError};

/// Linked-in drivers in `driver_list` order (head first).
const STATIC_DRIVERS: [&str; 3] = ["ram_file_drv", "udp_inet", "tcp_inet"];

// Port of erts/emulator/beam/global.h:151-167, OTP-29.1.1.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Status {
    Ok,
    Unload,
    ForceUnload,
    Reload,
    ForceReload,
    Permanent,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Awaiting {
    Loaded,
    AwaitUnload,
    AwaitUnloadOnly,
    AwaitLoad,
}

const FL_KILL_PORTS: u32 = 1;
/// `ERL_FL_CONSISTENT_MASK`.
const FL_CONSISTENT_MASK: u32 = FL_KILL_PORTS;

struct ProcEntry {
    pid: Pid,
    awaiting: Awaiting,
    dereferenced: bool,
    /// Monitor reference id for awaiting entries.
    reference: u64,
}

/// `DE_Handle`.
struct DeHandle {
    driver: Option<Arc<Driver>>,
    status: Status,
    /// `procs`, list head first.
    procs: Vec<ProcEntry>,
    port_count: usize,
    refc: i64,
    full_path: String,
    flags: u32,
    reload: Option<(String, String, u32)>,
    ports: Vec<Weak<DriverPort>>,
}

/// `erts_driver_t` in `driver_list`.
struct DriverRow {
    name: String,
    handle: Option<u64>,
}

struct Table {
    drivers: Vec<DriverRow>,
    handles: HashMap<u64, DeHandle>,
    next_handle: u64,
    /// Handles whose `ddll_no_more_references` is scheduled.
    pending: Vec<u64>,
}

/// A monitor message produced under the driver list lock, sent after it.
struct Notice {
    to: Pid,
    kind: &'static str,
    reference: u64,
    name: String,
    tag: &'static str,
    error: Option<i32>,
}

fn table() -> &'static Mutex<Table> {
    static TABLE: OnceLock<Mutex<Table>> = OnceLock::new();
    TABLE.get_or_init(|| {
        Mutex::new(Table {
            drivers: STATIC_DRIVERS
                .iter()
                .map(|name| DriverRow {
                    name: (*name).to_owned(),
                    handle: None,
                })
                .collect(),
            handles: HashMap::new(),
            next_handle: 1,
            pending: Vec::new(),
        })
    })
}

fn atom(name: &str) -> Term {
    Term::atom(global_atoms().intern(name).expect("runtime atom"))
}

fn badarg() -> VmError {
    VmError::Trap(crate::exceptions::Trap::error(atom("badarg")))
}

fn build(process: &mut Process, value: &O) -> Result<Term, VmError> {
    let mut heap = arinsal_bifs::FragmentingHeap(&mut process.heap);
    from_owned(value, &mut heap).map_err(|_| badarg())
}

fn ok_or_error(tag: &str, value: O) -> O {
    O::Tuple(vec![O::Atom(tag.into()), value])
}

fn charlist(text: &str) -> O {
    O::list(text.bytes().map(|b| O::Int(b as i64)).collect())
}

fn flatten_bytes(value: &O, out: &mut Vec<u8>) -> Option<()> {
    match value {
        O::Int(n) if (0..=255).contains(n) => out.push(*n as u8),
        O::Binary(bytes) => out.extend_from_slice(bytes),
        O::Nil => {}
        O::List { elems, tail } => {
            for elem in elems {
                flatten_bytes(elem, out)?;
            }
            match tail.as_ref() {
                O::Nil => {}
                O::Binary(bytes) => out.extend_from_slice(bytes),
                _ => return None,
            }
        }
        _ => return None,
    }
    Some(())
}

/// Port of erl_bif_ddll.c:1795 (pick_list_or_atom).
fn pick_list_or_atom(term: Term) -> Option<String> {
    let owned = to_owned(term).ok()?;
    match &owned {
        O::Atom(name) if !name.is_empty() => Some(name.clone()),
        O::Atom(_) => None,
        O::List { .. } | O::Nil | O::Binary(_) => {
            let mut bytes = Vec::new();
            flatten_bytes(&owned, &mut bytes)?;
            Some(String::from_utf8_lossy(&bytes).into_owned())
        }
        _ => None,
    }
}

fn flatten_chars(value: &O, out: &mut String) -> Option<()> {
    match value {
        O::Int(n) => out.push(char::from_u32(u32::try_from(*n).ok()?)?),
        O::Binary(bytes) => out.push_str(std::str::from_utf8(bytes).ok()?),
        O::Atom(text) => out.push_str(text),
        O::Nil => {}
        O::List { elems, tail } => {
            for elem in elems {
                flatten_chars(elem, out)?;
            }
            flatten_chars(tail, out)?;
        }
        _ => return None,
    }
    Some(())
}

/// `erts_convert_filename_to_encoding` for a UTF-8 native encoding.
fn filename(term: Term) -> Option<String> {
    let owned = to_owned(term).ok()?;
    let mut out = String::new();
    flatten_chars(&owned, &mut out)?;
    Some(out)
}

fn lookup(table: &Table, name: &str) -> Option<usize> {
    table.drivers.iter().position(|row| row.name == name)
}

// Port of erl_bif_ddll.c:1061-1113 (driver reference counting).
fn reference_driver(table: &mut Table, id: u64) {
    let handle = table.handles.get_mut(&id).expect("live handle");
    handle.refc += 1;
    if handle.refc == 1 {
        // Add a reference for the scheduled operation.
        handle.refc += 1;
    }
}

fn dereference_driver(table: &mut Table, id: u64) {
    let handle = table.handles.get_mut(&id).expect("live handle");
    handle.refc -= 1;
    if handle.refc == 0 {
        table.pending.push(id);
    }
}

fn dereference_all_processes(table: &mut Table, id: u64) {
    let handle = table.handles.get_mut(&id).expect("live handle");
    let mut drop = 0;
    for entry in &mut handle.procs {
        if entry.awaiting == Awaiting::Loaded {
            entry.dereferenced = true;
            drop += 1;
        }
    }
    for _ in 0..drop {
        dereference_driver(table, id);
    }
}

fn restore_process_references(handle: &mut DeHandle) {
    for entry in &mut handle.procs {
        if entry.awaiting == Awaiting::Loaded {
            handle.refc += 1;
            entry.dereferenced = false;
        }
    }
}

fn is_last_user(handle: &DeHandle, pid: Pid) -> bool {
    let mut found = false;
    for entry in &handle.procs {
        if entry.awaiting == Awaiting::Loaded {
            if entry.pid != pid || found {
                return false;
            }
            found = true;
        }
    }
    found
}

fn find_proc_entry(handle: &DeHandle, pid: Pid, awaiting: Awaiting) -> Option<usize> {
    handle
        .procs
        .iter()
        .position(|entry| entry.pid == pid && entry.awaiting == awaiting)
}

fn num_procs(handle: &DeHandle, awaiting: Awaiting) -> usize {
    handle
        .procs
        .iter()
        .filter(|entry| entry.awaiting == awaiting)
        .count()
}

fn add_proc(handle: &mut DeHandle, pid: Pid, awaiting: Awaiting, dereferenced: bool) -> u64 {
    let reference = if awaiting == Awaiting::Loaded {
        0
    } else {
        arinsal_bifs::next_ref_id()
    };
    handle.procs.insert(
        0,
        ProcEntry {
            pid,
            awaiting,
            dereferenced,
            reference,
        },
    );
    reference
}

/// Port of erl_bif_ddll.c:1748 (notify_all).
fn notify_all(
    handle: &mut DeHandle,
    name: &str,
    awaiting: Awaiting,
    kind: &'static str,
    tag: &'static str,
    notices: &mut Vec<Notice>,
) {
    handle.procs.retain(|entry| {
        if entry.awaiting != awaiting {
            return true;
        }
        notices.push(Notice {
            to: entry.pid,
            kind,
            reference: entry.reference,
            name: name.to_owned(),
            tag,
            error: None,
        });
        false
    });
}

/// Port of erl_bif_ddll.c:1499 (do_load_driver_entry) adding the driver to the list.
fn do_load_driver_entry(table: &mut Table, id: u64, path: &str, name: &str) -> i32 {
    match Driver::load(path, name) {
        Ok(driver) => {
            let handle = table.handles.get_mut(&id).expect("live handle");
            handle.driver = Some(driver);
            handle.refc = 0;
            handle.port_count = 0;
            handle.full_path = path.to_owned();
            handle.flags = 0;
            handle.status = Status::Ok;
            table.drivers.insert(
                0,
                DriverRow {
                    name: name.to_owned(),
                    handle: Some(id),
                },
            );
            arinsal_drv::ERL_DE_NO_ERROR
        }
        Err(code) => code,
    }
}

/// Port of erl_bif_ddll.c:1569 (do_unload_driver_entry): returns the driver name.
fn do_unload_driver_entry(table: &mut Table, id: u64) -> Option<String> {
    let index = table
        .drivers
        .iter()
        .position(|row| row.handle == Some(id))?;
    let row = table.drivers.remove(index);
    if let Some(driver) = table.handles.get_mut(&id).and_then(|h| h.driver.take()) {
        driver.unload();
    }
    Some(row.name)
}

/// Port of erl_bif_ddll.c:1124 (ddll_no_more_references).
fn no_more_references(table: &mut Table, id: u64, notices: &mut Vec<Notice>) {
    let Some(handle) = table.handles.get_mut(&id) else {
        return;
    };
    let mut x = handle.refc;
    if x > 0 {
        handle.refc -= 1;
        x = handle.refc;
    }
    if x != 0 {
        return;
    }
    let name = do_unload_driver_entry(table, id).unwrap_or_else(|| "undefined".into());
    let handle = table.handles.get_mut(&id).expect("live handle");
    handle.procs.retain(|entry| {
        if matches!(
            entry.awaiting,
            Awaiting::AwaitUnload | Awaiting::AwaitUnloadOnly
        ) {
            notices.push(Notice {
                to: entry.pid,
                kind: "DOWN",
                reference: entry.reference,
                name: name.clone(),
                tag: "unloaded",
                error: None,
            });
            false
        } else {
            true
        }
    });
    if matches!(handle.status, Status::Unload | Status::ForceUnload) {
        table.handles.remove(&id);
        return;
    }
    // Port of erl_bif_ddll.c:1640 (reload_driver_entry).
    let (path, reload_name, flags) = handle.reload.take().expect("reload target");
    handle.full_path.clear();
    let result = do_load_driver_entry(table, id, &path, &reload_name);
    let handle = table.handles.get_mut(&id).expect("live handle");
    if result == arinsal_drv::ERL_DE_NO_ERROR {
        handle.status = Status::Ok;
        handle.flags = flags;
    }
    restore_process_references(handle);
    handle.procs.retain(|entry| {
        if entry.awaiting == Awaiting::AwaitLoad {
            notices.push(Notice {
                to: entry.pid,
                kind: if result == 0 { "UP" } else { "DOWN" },
                reference: entry.reference,
                name: name.clone(),
                tag: if result == 0 {
                    "loaded"
                } else {
                    "load_failure"
                },
                error: (result != 0).then_some(result),
            });
            false
        } else {
            result == 0
        }
    });
    if result != 0 {
        table.handles.remove(&id);
    }
}

fn run_pending(table: &mut Table, notices: &mut Vec<Notice>) {
    while let Some(id) = table.pending.pop() {
        no_more_references(table, id, notices);
    }
}

// Port of erl_bif_ddll.c:1757-1793 (errcode_tab, build_load_error_hp).
const ERRCODE_TAB: [(&str, i32); 9] = [
    ("no_error", arinsal_drv::ERL_DE_NO_ERROR),
    ("no_driver_init", arinsal_drv::ERL_DE_LOAD_ERROR_NO_INIT),
    (
        "driver_init_failed",
        arinsal_drv::ERL_DE_LOAD_ERROR_FAILED_INIT,
    ),
    ("bad_driver_name", arinsal_drv::ERL_DE_LOAD_ERROR_BAD_NAME),
    (
        "driver_name_to_long",
        arinsal_drv::ERL_DE_LOAD_ERROR_NAME_TO_LONG,
    ),
    (
        "driver_incorrect_version",
        arinsal_drv::ERL_DE_LOAD_ERROR_INCORRECT_VERSION,
    ),
    (
        "no_ddll_available",
        arinsal_drv::ERL_DE_ERROR_NO_DDLL_FUNCTIONALITY,
    ),
    ("unspecified_error", arinsal_drv::ERL_DE_ERROR_UNSPECIFIED),
    (
        "symbol_not_found",
        arinsal_drv::ERL_DE_LOOKUP_ERROR_NOT_FOUND,
    ),
];

fn load_error(code: i32) -> O {
    ERRCODE_TAB
        .iter()
        .find(|(_, c)| *c == code)
        .map(|(name, _)| O::Atom((*name).into()))
        .unwrap_or_else(|| O::Tuple(vec![O::Atom("open_error".into()), O::Int(i64::from(code))]))
}

fn notice_term(heap: &mut ProcessHeap, notice: &Notice) -> Option<Term> {
    let reference = TermBuilder::new(heap)
        .local_ref([notice.reference as u32, (notice.reference >> 32) as u32, 0])
        .ok()?;
    let tag = match notice.error {
        None => atom(notice.tag),
        Some(code) => {
            let error = from_owned(&load_error(code), heap).ok()?;
            TermBuilder::new(heap)
                .tuple(&[atom(notice.tag), error])
                .ok()?
        }
    };
    TermBuilder::new(heap)
        .tuple(&[
            atom(notice.kind),
            reference,
            atom("driver"),
            atom(&notice.name),
            tag,
        ])
        .ok()
}

/// Port of erl_bif_ddll.c:1702 (notify_proc).
fn deliver(scheduler: &Scheduler<Process>, notices: Vec<Notice>) {
    for notice in notices {
        let mut heap = ProcessHeap::with_words(64);
        if let Some(message) = notice_term(&mut heap, &notice)
            && let Ok(message) = Message::copy_from(message)
        {
            let _ = scheduler.send(notice.to, notice.to, message);
        }
    }
}

/// Port of erl_bif_ddll.c:123 (kill_ports_driver_unloaded).
fn kill_ports(ports: Vec<Weak<DriverPort>>) {
    for port in ports.iter().filter_map(Weak::upgrade) {
        port.fail_atom("driver_unloaded");
    }
}

fn live_ports(handle: &DeHandle) -> Vec<Weak<DriverPort>> {
    handle.ports.clone()
}

fn scheduler_of(process: &Process) -> Result<Arc<Scheduler<Process>>, VmError> {
    process.runtime.as_ref().ok_or_else(badarg)?.scheduler()
}

/// Port of erl_bif_ddll.c:178 (erl_ddll_try_load_3).
pub(crate) fn try_load(
    process: &mut Process,
    ctx: &RunCtx<'_, Message>,
    args: &[Term],
) -> Result<Term, VmError> {
    let options = to_owned(args[2]).map_err(|_| badarg())?;
    let mut flags = 0;
    let mut monitor = 0u8;
    let mut reload = 0u8;
    let (elems, tail) = match &options {
        O::Nil => (&[][..], &O::Nil),
        O::List { elems, tail } => (elems.as_slice(), tail.as_ref()),
        _ => return Err(badarg()),
    };
    if *tail != O::Nil {
        return Err(badarg());
    }
    for option in elems {
        let O::Tuple(pair) = option else {
            return Err(badarg());
        };
        let [O::Atom(key), value] = pair.as_slice() else {
            return Err(badarg());
        };
        match (key.as_str(), value) {
            ("driver_options", value) => {
                let (items, tail) = match value {
                    O::Nil => (&[][..], &O::Nil),
                    O::List { elems, tail } => (elems.as_slice(), tail.as_ref()),
                    _ => return Err(badarg()),
                };
                if *tail != O::Nil {
                    return Err(badarg());
                }
                for item in items {
                    if *item != O::Atom("kill_ports".into()) {
                        return Err(badarg());
                    }
                    flags |= FL_KILL_PORTS;
                }
            }
            ("monitor", O::Atom(v)) if v == "pending_driver" => monitor = 1,
            ("monitor", O::Atom(v)) if v == "pending" => monitor = 2,
            ("reload", O::Atom(v)) if v == "pending_driver" => reload = 1,
            ("reload", O::Atom(v)) if v == "pending" => reload = 2,
            _ => return Err(badarg()),
        }
    }
    let name = pick_list_or_atom(args[1]).ok_or_else(badarg)?;
    let path = filename(args[0]).ok_or_else(badarg)?;
    let path = format!("{}/{name}", path.trim_end_matches(['/', '\\']));
    let pid = ctx.pid();
    let scheduler = scheduler_of(process)?;
    let mut notices = Vec::new();
    let mut to_kill = Vec::new();
    let result = {
        let mut guard = table().lock().unwrap();
        let table = &mut *guard;
        let outcome = try_load_locked(
            table,
            pid,
            &path,
            &name,
            flags,
            reload,
            &mut monitor,
            &mut notices,
            &mut to_kill,
        );
        match outcome {
            Ok((id, ok_term)) => {
                // The final reference/dereference pair of the BIF; a zero count
                // schedules ddll_no_more_references after the monitor exists.
                reference_driver(table, id);
                dereference_driver(table, id);
                let value = if monitor > 0 {
                    let reference = add_proc(
                        table.handles.get_mut(&id).expect("live handle"),
                        pid,
                        Awaiting::AwaitLoad,
                        false,
                    );
                    Ok((ok_term, Some(reference)))
                } else {
                    Ok((ok_term, None))
                };
                run_pending(table, &mut notices);
                value
            }
            Err(error) => Err(error),
        }
    };
    kill_ports(to_kill);
    deliver(&scheduler, notices);
    match result {
        Ok((ok_term, None)) => build(process, &ok_or_error("ok", ok_term)),
        Ok((ok_term, Some(reference))) => {
            let reference = crate::signals::reference(process, reference)?;
            let ok_term = build(process, &ok_term)?;
            let mut heap = arinsal_bifs::FragmentingHeap(&mut process.heap);
            TermBuilder::new(&mut heap)
                .tuple(&[atom("ok"), ok_term, reference])
                .map_err(|_| badarg())
        }
        Err(error) => build(process, &ok_or_error("error", error)),
    }
}

#[allow(clippy::too_many_arguments)]
fn try_load_locked(
    table: &mut Table,
    pid: Pid,
    path: &str,
    name: &str,
    flags: u32,
    reload: u8,
    monitor: &mut u8,
    notices: &mut Vec<Notice>,
    to_kill: &mut Vec<Weak<DriverPort>>,
) -> Result<(u64, O), O> {
    let soft = |tag: &str| O::Atom(tag.into());
    let Some(index) = lookup(table, name) else {
        if reload != 0 {
            return Err(soft("not_loaded"));
        }
        let id = table.next_handle;
        table.next_handle += 1;
        table.handles.insert(
            id,
            DeHandle {
                driver: None,
                status: Status::Ok,
                procs: Vec::new(),
                port_count: 0,
                refc: 0,
                full_path: String::new(),
                flags: 0,
                reload: None,
                ports: Vec::new(),
            },
        );
        let code = do_load_driver_entry(table, id, path, name);
        if code != arinsal_drv::ERL_DE_NO_ERROR {
            table.handles.remove(&id);
            return Err(load_error(code));
        }
        let handle = table.handles.get_mut(&id).expect("live handle");
        handle.flags = flags;
        add_proc(handle, pid, Awaiting::Loaded, false);
        // first_ddll_reference
        handle.refc = 1;
        *monitor = 0;
        return Ok((id, soft("loaded")));
    };
    let Some(id) = table.drivers[index].handle else {
        return Err(soft("linked_in_driver"));
    };
    let handle = table.handles.get_mut(&id).expect("live handle");
    match handle.status {
        Status::Ok => {
            let is_last = is_last_user(handle, pid);
            if reload == 1 && !is_last {
                return Err(soft("pending_process"));
            }
            if reload != 0 {
                if handle.flags & FL_CONSISTENT_MASK != flags & FL_CONSISTENT_MASK {
                    return Err(soft("inconsistent"));
                }
                let Some(old) = find_proc_entry(handle, pid, Awaiting::Loaded) else {
                    return Err(soft("not_loaded_by_this_process"));
                };
                handle.procs.remove(old);
                dereference_driver(table, id);
                dereference_all_processes(table, id);
                // Port of erl_bif_ddll.c:1475 (set_driver_reloading).
                let handle = table.handles.get_mut(&id).expect("live handle");
                add_proc(handle, pid, Awaiting::Loaded, true);
                handle.status = Status::Reload;
                handle.reload = Some((path.to_owned(), name.to_owned(), flags));
                if handle.flags & FL_KILL_PORTS != 0 {
                    reference_driver(table, id);
                    let handle = table.handles.get_mut(&id).expect("live handle");
                    handle.status = Status::ForceReload;
                    to_kill.extend(live_ports(handle));
                    dereference_driver(table, id);
                }
                Ok((
                    id,
                    soft(if reload == 1 {
                        "pending_driver"
                    } else {
                        "pending_process"
                    }),
                ))
            } else {
                if handle.full_path != path
                    || handle.flags & FL_CONSISTENT_MASK != flags & FL_CONSISTENT_MASK
                {
                    return Err(soft("inconsistent"));
                }
                add_proc(handle, pid, Awaiting::Loaded, false);
                reference_driver(table, id);
                *monitor = 0;
                Ok((id, soft("already_loaded")))
            }
        }
        Status::Unload | Status::ForceUnload => {
            if reload != 0 {
                return Err(soft("not_loaded_by_this_process"));
            }
            if handle.full_path != path
                || handle.flags & FL_CONSISTENT_MASK != flags & FL_CONSISTENT_MASK
            {
                return Err(soft("inconsistent"));
            }
            handle.status = Status::Ok;
            notify_all(
                handle,
                name,
                Awaiting::AwaitUnload,
                "UP",
                "unload_cancelled",
                notices,
            );
            add_proc(handle, pid, Awaiting::Loaded, false);
            reference_driver(table, id);
            *monitor = 0;
            Ok((id, soft("already_loaded")))
        }
        Status::Reload | Status::ForceReload => {
            if reload != 0 {
                return Err(soft("pending_reload"));
            }
            let (reload_path, _, reload_flags) = handle.reload.as_ref().expect("reload target");
            if reload_path != path
                || reload_flags & FL_CONSISTENT_MASK != flags & FL_CONSISTENT_MASK
            {
                return Err(soft("inconsistent"));
            }
            add_proc(handle, pid, Awaiting::Loaded, true);
            *monitor += 1;
            Ok((id, soft("pending_driver")))
        }
        Status::Permanent => Err(soft("permanent")),
    }
}

/// Port of erl_bif_ddll.c:489 (erl_ddll_try_unload_2).
pub(crate) fn try_unload(
    process: &mut Process,
    ctx: &RunCtx<'_, Message>,
    args: &[Term],
) -> Result<Term, VmError> {
    let options = to_owned(args[1]).map_err(|_| badarg())?;
    let mut kill = 0;
    let mut monitor: i32 = 0;
    let (elems, tail) = match &options {
        O::Nil => (&[][..], &O::Nil),
        O::List { elems, tail } => (elems.as_slice(), tail.as_ref()),
        _ => return Err(badarg()),
    };
    if *tail != O::Nil {
        return Err(badarg());
    }
    for option in elems {
        match option {
            O::Atom(a) if a == "kill_ports" => kill = 1,
            O::Tuple(pair) => match pair.as_slice() {
                [O::Atom(k), O::Atom(v)] if k == "monitor" && v == "pending_driver" => monitor = 1,
                [O::Atom(k), O::Atom(v)] if k == "monitor" && v == "pending" => monitor = 2,
                _ => return Err(badarg()),
            },
            _ => return Err(badarg()),
        }
    }
    let name = pick_list_or_atom(args[0]).ok_or_else(badarg)?;
    let pid = ctx.pid();
    let scheduler = scheduler_of(process)?;
    let mut notices = Vec::new();
    let mut to_kill = Vec::new();
    let result: Result<(O, Option<u64>), O> = {
        let mut guard = table().lock().unwrap();
        let table = &mut *guard;
        (|| {
            let soft = |tag: &str| O::Atom(tag.into());
            let index = lookup(table, &name).ok_or_else(|| soft("not_loaded"))?;
            let id = table.drivers[index]
                .handle
                .ok_or_else(|| soft("linked_in_driver"))?;
            let handle = table.handles.get_mut(&id).expect("live handle");
            if handle.status == Status::Permanent {
                return Err(soft("permanent"));
            }
            if handle.flags & FL_KILL_PORTS != 0 {
                kill = 1;
            }
            match find_proc_entry(handle, pid, Awaiting::Loaded) {
                None => {
                    if num_procs(handle, Awaiting::Loaded) > 0 {
                        return Err(soft("not_loaded_by_this_process"));
                    }
                }
                Some(index) => {
                    let entry = handle.procs.remove(index);
                    if !entry.dereferenced {
                        dereference_driver(table, id);
                    }
                }
            }
            let handle = table.handles.get_mut(&id).expect("live handle");
            let ok_term = if num_procs(handle, Awaiting::Loaded) > 0 {
                monitor -= 1;
                "pending_process"
            } else {
                if matches!(handle.status, Status::Reload | Status::ForceReload) {
                    notify_all(
                        handle,
                        &name,
                        Awaiting::AwaitLoad,
                        "DOWN",
                        "load_cancelled",
                        &mut notices,
                    );
                    handle.reload = None;
                }
                if handle.port_count > 0 {
                    kill += 1;
                }
                handle.status = Status::Unload;
                "pending_driver"
            };
            if kill > 1 {
                reference_driver(table, id);
                let handle = table.handles.get_mut(&id).expect("live handle");
                handle.status = Status::ForceUnload;
                to_kill.extend(live_ports(handle));
                dereference_driver(table, id);
            }
            reference_driver(table, id);
            dereference_driver(table, id);
            let reference = (monitor > 0).then(|| {
                add_proc(
                    table.handles.get_mut(&id).expect("live handle"),
                    pid,
                    Awaiting::AwaitUnload,
                    false,
                )
            });
            Ok((soft(ok_term), reference))
        })()
    };
    // Kill ports and run the scheduled unload outside the list lock.
    kill_ports(to_kill);
    {
        let mut guard = table().lock().unwrap();
        run_pending(&mut guard, &mut notices);
    }
    deliver(&scheduler, notices);
    match result {
        Ok((ok_term, None)) => build(process, &ok_or_error("ok", ok_term)),
        Ok((ok_term, Some(reference))) => {
            let reference = crate::signals::reference(process, reference)?;
            let ok_term = build(process, &ok_term)?;
            let mut heap = arinsal_bifs::FragmentingHeap(&mut process.heap);
            TermBuilder::new(&mut heap)
                .tuple(&[atom("ok"), ok_term, reference])
                .map_err(|_| badarg())
        }
        Err(error) => build(process, &ok_or_error("error", error)),
    }
}

/// Port of erl_bif_ddll.c:666 (erl_ddll_loaded_drivers_0).
pub(crate) fn loaded_drivers(process: &mut Process) -> Result<Term, VmError> {
    let names = table()
        .lock()
        .unwrap()
        .drivers
        .iter()
        .rev()
        .map(|row| charlist(&row.name))
        .collect();
    build(process, &ok_or_error("ok", O::list(names)))
}

/// Port of erl_bif_ddll.c:694 (erl_ddll_info_2).
pub(crate) fn info(process: &mut Process, args: &[Term]) -> Result<Term, VmError> {
    let name = pick_list_or_atom(args[0]).ok_or_else(badarg)?;
    let item = args[1]
        .as_atom()
        .and_then(|a| global_atoms().text(a).map(|s| s.to_string()))
        .ok_or_else(badarg)?;
    let value = {
        let table = table().lock().unwrap();
        let index = lookup(&table, &name).ok_or_else(badarg)?;
        let handle = table.drivers[index]
            .handle
            .and_then(|id| table.handles.get(&id));
        let permanent = handle.is_some_and(|h| h.status == Status::Permanent);
        let filter = match item.as_str() {
            "processes" => Awaiting::Loaded,
            "awaiting_load" => Awaiting::AwaitLoad,
            "awaiting_unload" => Awaiting::AwaitUnload,
            "driver_options" => {
                let value = match handle {
                    None => O::Atom("linked_in_driver".into()),
                    Some(h) if h.flags & FL_CONSISTENT_MASK & FL_KILL_PORTS != 0 => {
                        O::list(vec![O::Atom("kill_ports".into())])
                    }
                    Some(_) => O::Nil,
                };
                return build(process, &value);
            }
            "port_count" => {
                let value = match handle {
                    None => O::Atom("linked_in_driver".into()),
                    Some(_) if permanent => O::Atom("permanent".into()),
                    Some(h) => O::Int(h.port_count as i64),
                };
                return build(process, &value);
            }
            "linked_in_driver" => {
                return Ok(atom(if handle.is_none() { "true" } else { "false" }));
            }
            "permanent" => return Ok(atom(if permanent { "true" } else { "false" })),
            _ => return Err(badarg()),
        };
        match handle {
            None => O::Atom("linked_in_driver".into()),
            Some(_) if permanent => O::Atom("permanent".into()),
            Some(h) => {
                // Port of erl_bif_ddll.c:1830 (build_proc_info).
                let mut info: Vec<(Pid, i64)> = Vec::new();
                for entry in &h.procs {
                    let status = if entry.awaiting == Awaiting::AwaitUnloadOnly {
                        Awaiting::AwaitUnload
                    } else {
                        entry.awaiting
                    };
                    if status != filter {
                        continue;
                    }
                    match info.iter_mut().find(|(pid, _)| *pid == entry.pid) {
                        Some((_, count)) => *count += 1,
                        None => info.push((entry.pid, 1)),
                    }
                }
                // The result list is consed in reverse.
                let mut items = Vec::new();
                for (pid, count) in info.into_iter().rev() {
                    items.push((pid, count));
                }
                return pid_counts(process, &items);
            }
        }
    };
    build(process, &value)
}

fn pid_counts(process: &mut Process, items: &[(Pid, i64)]) -> Result<Term, VmError> {
    let mut heap = arinsal_bifs::FragmentingHeap(&mut process.heap);
    let mut list = Term::NIL;
    for (pid, count) in items.iter().rev() {
        let pid = pid.to_term().ok_or_else(badarg)?;
        let count = Term::small(*count).ok_or_else(badarg)?;
        let pair = TermBuilder::new(&mut heap)
            .tuple(&[pid, count])
            .map_err(|_| badarg())?;
        list = TermBuilder::new(&mut heap)
            .cons(pair, list)
            .map_err(|_| badarg())?;
    }
    Ok(list)
}

/// Port of erl_bif_ddll.c:884 (erts_ddll_monitor_driver), with notify_when_loaded
/// and notify_when_unloaded (erl_bif_ddll.c:1219-1300).
pub(crate) fn monitor(
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    args: &[Term],
) -> Result<Term, VmError> {
    if args[0] != atom("driver") {
        return Err(badarg());
    }
    let description = to_owned(args[1]).map_err(|_| badarg())?;
    let O::Tuple(pair) = &description else {
        return Err(badarg());
    };
    let [name_owned, what] = pair.as_slice() else {
        return Err(badarg());
    };
    let name_term = build(process, name_owned)?;
    let name = pick_list_or_atom(name_term).ok_or_else(badarg)?;
    let flag = match what {
        O::Atom(a) if a == "loaded" => Awaiting::AwaitLoad,
        O::Atom(a) if a == "unloaded" => Awaiting::AwaitUnload,
        O::Atom(a) if a == "unloaded_only" => Awaiting::AwaitUnloadOnly,
        _ => return Err(badarg()),
    };
    let pid = ctx.pid();
    let immediate = {
        let mut table = table().lock().unwrap();
        let state = lookup(&table, &name).map(|index| table.drivers[index].handle);
        match state {
            None => Some(("DOWN", "unloaded")),
            Some(None) => Some(("UP", "permanent")),
            Some(Some(id)) => {
                let handle = table.handles.get_mut(&id).expect("live handle");
                match (flag, handle.status) {
                    (_, Status::Permanent) => Some(("UP", "permanent")),
                    (Awaiting::AwaitLoad, Status::Ok) => Some(("UP", "loaded")),
                    (Awaiting::AwaitLoad, Status::Unload | Status::ForceUnload) => {
                        Some(("DOWN", "load_cancelled"))
                    }
                    _ => {
                        let reference = add_proc(handle, pid, flag, false);
                        drop(table);
                        return crate::signals::reference(process, reference);
                    }
                }
            }
        }
    };
    let (kind, tag) = immediate.expect("immediate notification");
    let reference = crate::signals::reference(process, arinsal_bifs::next_ref_id())?;
    let mut heap = arinsal_bifs::FragmentingHeap(&mut process.heap);
    let message = TermBuilder::new(&mut heap)
        .tuple(&[atom(kind), reference, atom("driver"), name_term, atom(tag)])
        .map_err(|_| badarg())?;
    ctx.send(pid, Message::copy_from(message)?)
        .map_err(|_| badarg())?;
    Ok(reference)
}

/// Port of erl_bif_ddll.c:641 (erl_ddll_demonitor_1) and :924 (erts_ddll_remove_monitor).
pub(crate) fn demonitor(ctx: &RunCtx<'_, Message>, reference: Term) -> Result<Term, VmError> {
    let id = crate::signals::ref_id(reference).ok_or_else(badarg)?;
    let pid = ctx.pid();
    let mut table = table().lock().unwrap();
    for handle in table.handles.values_mut() {
        if handle.status == Status::Permanent {
            continue;
        }
        if let Some(index) = handle.procs.iter().position(|entry| {
            entry.pid == pid && entry.awaiting != Awaiting::Loaded && entry.reference == id
        }) {
            handle.procs.remove(index);
            break;
        }
    }
    Ok(atom("true"))
}

/// Port of erl_bif_ddll.c:813 (erl_ddll_format_error_int_1).
pub(crate) fn format_error(process: &mut Process, code: Term) -> Result<Term, VmError> {
    let owned = to_owned(code).map_err(|_| badarg())?;
    let message = match &owned {
        O::Atom(key) => match key.as_str() {
            "inconsistent" => {
                "Driver name and/or driver options are inconsistent with currently loaded driver"
                    .to_owned()
            }
            "linked_in_driver" => {
                "Driver is statically linked and cannot be loaded/unloaded".to_owned()
            }
            "permanent" => "DDLL driver is permanent an cannot be unloaded/loaded".to_owned(),
            "not_loaded" => "DDLL driver is not loaded".to_owned(),
            "not_loaded_by_this_process" => "DDLL driver was not loaded by this process".to_owned(),
            "not_pending" => "DDLL load not pending for this driver name".to_owned(),
            "already_loaded" => "DDLL driver is already loaded successfully".to_owned(),
            "pending_reload" => "Driver reloading is already pending".to_owned(),
            "pending_process" => {
                "Driver is loaded by others when attempting option {reload, pending_driver}"
                    .to_owned()
            }
            other => {
                let code = ERRCODE_TAB
                    .iter()
                    .find(|(name, _)| *name == other)
                    .map(|(_, code)| *code)
                    .ok_or_else(badarg)?;
                arinsal_drv::ddll_error(code)
            }
        },
        O::Tuple(items) => match items.as_slice() {
            [O::Atom(tag), O::Int(code)] if tag == "open_error" => {
                arinsal_drv::ddll_error(i32::try_from(*code).map_err(|_| badarg())?)
            }
            _ => return Err(badarg()),
        },
        _ => return Err(badarg()),
    };
    build(process, &charlist(&message))
}

/// Port of erl_bif_ddll.c:958 (erts_ddll_proc_dead).
pub(crate) fn proc_dead(scheduler: &Scheduler<Process>, pid: Pid) {
    let mut notices = Vec::new();
    let mut to_kill = Vec::new();
    {
        let mut guard = table().lock().unwrap();
        let table = &mut *guard;
        let ids = table
            .drivers
            .iter()
            .filter_map(|row| row.handle)
            .collect::<Vec<_>>();
        for id in ids {
            let Some(handle) = table.handles.get_mut(&id) else {
                continue;
            };
            if handle.status == Status::Permanent {
                continue;
            }
            let kill = handle.flags & FL_KILL_PORTS != 0;
            let mut derefs = 0;
            handle.procs.retain(|entry| {
                if entry.pid != pid {
                    return true;
                }
                if !entry.dereferenced && entry.awaiting == Awaiting::Loaded {
                    derefs += 1;
                }
                false
            });
            let left = num_procs(handle, Awaiting::Loaded);
            if left == 0 {
                if matches!(handle.status, Status::Reload | Status::ForceReload) {
                    let name = table
                        .drivers
                        .iter()
                        .find(|row| row.handle == Some(id))
                        .map(|row| row.name.clone())
                        .unwrap_or_default();
                    let handle = table.handles.get_mut(&id).expect("live handle");
                    notify_all(
                        handle,
                        &name,
                        Awaiting::AwaitLoad,
                        "DOWN",
                        "load_cancelled",
                        &mut notices,
                    );
                    handle.reload = None;
                }
                table.handles.get_mut(&id).expect("live handle").status = Status::Unload;
            }
            for _ in 0..derefs {
                dereference_driver(table, id);
            }
            let handle = table.handles.get_mut(&id).expect("live handle");
            if left == 0 && handle.port_count > 0 && kill {
                reference_driver(table, id);
                let handle = table.handles.get_mut(&id).expect("live handle");
                handle.status = Status::ForceUnload;
                to_kill.extend(live_ports(handle));
                dereference_driver(table, id);
            }
        }
    }
    kill_ports(to_kill);
    {
        let mut guard = table().lock().unwrap();
        run_pending(&mut guard, &mut notices);
    }
    deliver(scheduler, notices);
}

/// Driver found by `open_port` (io.c:542 erts_open_driver name lookup).
pub(crate) enum Found {
    /// A linked-in driver.
    Static,
    /// A dynamically loaded driver and its handle.
    Dynamic(u64, Arc<Driver>),
}

/// Port of io.c:600-625: a driver by name, skipping force-unloading handles
/// (`erts_ddll_driver_ok`).
pub(crate) fn find_driver(name: &str) -> Option<Found> {
    let table = table().lock().unwrap();
    table.drivers.iter().find_map(|row| {
        if row.name != name {
            return None;
        }
        match row.handle {
            None => Some(Found::Static),
            Some(id) => {
                let handle = table.handles.get(&id)?;
                if matches!(handle.status, Status::ForceUnload | Status::ForceReload) {
                    return None;
                }
                Some(Found::Dynamic(id, Arc::clone(handle.driver.as_ref()?)))
            }
        }
    })
}

/// Port of erl_bif_ddll.c:1096 (erts_ddll_reference_referenced_driver): an async job
/// keeps the driver loaded.
pub(crate) fn reference_referenced(driver: &Arc<Driver>) {
    let mut guard = table().lock().unwrap();
    let table = &mut *guard;
    let id = table.handles.iter().find_map(|(id, handle)| {
        handle
            .driver
            .as_ref()
            .is_some_and(|d| Arc::ptr_eq(d, driver))
            .then_some(*id)
    });
    if let Some(id) = id {
        reference_driver(table, id);
    }
}

/// Port of erl_bif_ddll.c:1103 (erts_ddll_dereference_driver): the reference of
/// [`reference_referenced`] ends, which may complete a pending unload.
pub(crate) fn dereference_referenced(scheduler: &Scheduler<Process>, driver: &Arc<Driver>) {
    port_freed(scheduler, driver);
}

/// Port of io.c:646-648 (erts_ddll_increment_port_count, erts_ddll_reference_driver).
pub(crate) fn port_opened(id: u64, port: &Arc<DriverPort>) {
    let mut table = table().lock().unwrap();
    if table.handles.contains_key(&id) {
        reference_driver(&mut table, id);
        let handle = table.handles.get_mut(&id).expect("live handle");
        handle.port_count += 1;
        handle.ports.retain(|port| port.strong_count() > 0);
        handle.ports.push(Arc::downgrade(port));
    }
}

/// Port of io.c:3753 (erts_ddll_decrement_port_count) at `terminate_port` and of
/// io.c:489 (the port-free dereference). erts frees a port after thread progress;
/// here the dereference runs once every scheduler has reached a scheduling point.
pub(crate) fn port_closed(scheduler: &Arc<Scheduler<Process>>, driver: &Arc<Driver>) {
    {
        let mut table = table().lock().unwrap();
        let Some(handle) = table.handles.values_mut().find(|handle| {
            handle
                .driver
                .as_ref()
                .is_some_and(|d| Arc::ptr_eq(d, driver))
        }) else {
            return;
        };
        handle.port_count = handle.port_count.saturating_sub(1);
    }
    // Like erts thread progress: every scheduler, including the one running the
    // closing process, passes a scheduling point before the port is freed.
    let remaining = Arc::new(std::sync::atomic::AtomicUsize::new(
        scheduler.worker_count().max(1),
    ));
    let target = Arc::clone(scheduler);
    let driver = Arc::clone(driver);
    scheduler.request_aux_work_all(move |_| {
        if remaining.fetch_sub(1, std::sync::atomic::Ordering::AcqRel) == 1 {
            port_freed(&target, &driver);
        }
    });
}

fn port_freed(scheduler: &Scheduler<Process>, driver: &Arc<Driver>) {
    let mut notices = Vec::new();
    {
        let mut guard = table().lock().unwrap();
        let table = &mut *guard;
        let id = table.handles.iter().find_map(|(id, handle)| {
            handle
                .driver
                .as_ref()
                .is_some_and(|d| Arc::ptr_eq(d, driver))
                .then_some(*id)
        });
        let Some(id) = id else {
            return;
        };
        dereference_driver(table, id);
        run_pending(table, &mut notices);
    }
    deliver(scheduler, notices);
}
