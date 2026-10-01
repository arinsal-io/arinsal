//! Miscellaneous OTP 29.1.1 BIFs whose state belongs to the VM process layer.

use crate::process::Message;
use crate::{Process, Vm, VmError};
use arinsal_etf::OwnedTerm as O;
use arinsal_sched::RunCtx;
use arinsal_term::{Term, TermBuilder, from_owned, global_atoms, to_owned};
use std::collections::HashSet;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

const DDLL_STATIC: &[&str] = &["tcp_inet", "udp_inet", "ram_file_drv"];

#[derive(Clone, Default)]
struct Profile {
    target: Option<O>,
    flags: Vec<String>,
    timestamp: Timestamp,
}

#[derive(Clone, Copy, Default)]
enum Timestamp {
    #[default]
    Now,
    Monotonic,
    StrictMonotonic,
}

const PROFILE_RUNNABLE_PROCS: u8 = 1;
const PROFILE_SCHEDULER: u8 = 1 << 1;
const PROFILE_RUNNABLE_PORTS: u8 = 1 << 2;
static PROFILE_FLAGS: AtomicU8 = AtomicU8::new(0);
static PROFILE_UNIQUE: AtomicU64 = AtomicU64::new(0);

fn profile() -> &'static Mutex<Profile> {
    static PROFILE: OnceLock<Mutex<Profile>> = OnceLock::new();
    PROFILE.get_or_init(|| Mutex::new(Profile::default()))
}

fn ddll_monitors() -> &'static Mutex<HashSet<u64>> {
    static MONITORS: OnceLock<Mutex<HashSet<u64>>> = OnceLock::new();
    MONITORS.get_or_init(|| Mutex::new(HashSet::new()))
}

pub(crate) const IMPLEMENTED: &[(&str, &str, u8)] = &[
    ("erl_ddll", "demonitor", 1),
    ("erl_ddll", "format_error_int", 1),
    ("erl_ddll", "info", 2),
    ("erl_ddll", "loaded_drivers", 0),
    ("erl_ddll", "monitor", 2),
    ("erl_ddll", "try_load", 3),
    ("erl_ddll", "try_unload", 2),
    ("erlang", "dt_append_vm_tag_data", 1),
    ("erlang", "dt_get_tag", 0),
    ("erlang", "dt_get_tag_data", 0),
    ("erlang", "dt_prepend_vm_tag_data", 1),
    ("erlang", "dt_put_tag", 1),
    ("erlang", "decode_packet", 3),
    ("erlang", "system_profile", 0),
    ("erlang", "system_profile", 2),
    ("error_logger", "warning_map", 0),
    ("erts_debug", "dist_ext_to_term", 2),
    ("net_kernel", "dflag_unicode_io", 1),
    ("string", "list_to_float", 1),
];

pub(crate) fn call(
    _vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    module: &str,
    function: &str,
    args: super::NativeArgs<'_>,
) -> Option<Result<Term, VmError>> {
    args.with_values(process, |process, args| {
        if module == "erlang" && function == "decode_packet" && args.len() == 3 {
            let bif = arinsal_packet::lookup(module, function, 3).expect("registered packet BIF");
            return Some(
                crate::calls::call_bif(&mut process.heap, bif, args).map_err(|error| {
                    crate::exceptions::direct_bif_error(process, module, function, args, error)
                }),
            );
        }
        let result = match (module, function, args.len()) {
            ("erlang", "dt_get_tag" | "dt_get_tag_data", 0) => Ok(atom("undefined")),
            ("erlang", "dt_put_tag", 1) => Ok(atom("undefined")),
            ("erlang", "dt_append_vm_tag_data" | "dt_prepend_vm_tag_data", 1) => Ok(args[0]),
            ("error_logger", "warning_map", 0) => Ok(atom("warning")),
            ("net_kernel", "dflag_unicode_io", 1) => {
                if args[0].as_pid().is_some() {
                    return Some(Ok(atom("true")));
                }
                let identity = match args[0].identity() {
                    Some(arinsal_term::Identity::Pid { node, .. }) => global_atoms().text(node),
                    _ => return Some(Err(badarg())),
                };
                let node = identity.unwrap_or("nonode@nohost");
                Ok(atom(if crate::node_tables::lock().pid_unicode_io(node) {
                    "true"
                } else {
                    "false"
                }))
            }
            ("erlang", "system_profile", 0) => profile_get(process),
            ("erlang", "system_profile", 2) => profile_set(process, args),
            ("erl_ddll", "loaded_drivers", 0) => loaded_drivers(process),
            ("erl_ddll", "info", 2) => ddll_info(process, args),
            ("erl_ddll", "try_load", 3) => ddll_try_load(process, args),
            ("erl_ddll", "try_unload", 2) => ddll_try_unload(process, args),
            ("erl_ddll", "format_error_int", 1) => format_error(process, args[0]),
            ("erl_ddll", "monitor", 2) => ddll_monitor(ctx, process, args),
            ("erl_ddll", "demonitor", 1) => ddll_demonitor(args[0]),
            ("erts_debug", "dist_ext_to_term", 2) => dist_ext_to_term(process, args),
            ("string", "list_to_float", 1) => string_list_to_float(process, args[0]),
            _ => return None,
        };
        let _ = ctx;
        Some(result)
    })
}

fn profile_get(process: &mut Process) -> Result<Term, VmError> {
    // Port of erts/emulator/beam/erl_bif_trace.c:3725 (system_profile_get), OTP-29.1.1.
    let p = profile().lock().unwrap().clone();
    let Some(target) = p.target else {
        return Ok(atom("undefined"));
    };
    let flags = ["exclusive", "scheduler", "runnable_procs", "runnable_ports"]
        .into_iter()
        .filter(|name| p.flags.iter().any(|flag| flag == name))
        .map(|name| O::Atom(name.to_owned()))
        .collect();
    let result = O::Tuple(vec![
        target,
        O::List {
            elems: flags,
            tail: Box::new(O::Nil),
        },
    ]);
    let mut heap = arinsal_bifs::FragmentingHeap(&mut process.heap);
    from_owned(&result, &mut heap).map_err(|_| badarg())
}

fn profile_set(process: &mut Process, args: &[Term]) -> Result<Term, VmError> {
    // Port of erts/emulator/beam/erl_bif_trace.c:3762 (system_profile_2), OTP-29.1.1.
    let target = to_owned(args[0]).map_err(|_| badarg())?;
    let options = to_owned(args[1]).map_err(|_| badarg())?;
    if target == O::Atom("undefined".into()) || options == O::Nil {
        let previous = profile_get(process)?;
        PROFILE_FLAGS.store(0, Ordering::Relaxed);
        *profile().lock().unwrap() = Profile::default();
        return Ok(previous);
    }
    let O::List { elems, tail } = &options else {
        return Err(badarg());
    };
    if **tail != O::Nil || !matches!(target, O::Pid { .. } | O::Port { .. }) {
        return Err(badarg());
    }
    let allowed = [
        "scheduler",
        "runnable_procs",
        "runnable_ports",
        "exclusive",
        "timestamp",
        "strict_monotonic_timestamp",
        "monotonic_timestamp",
    ];
    let mut flags: Vec<String> = Vec::new();
    let mut timestamp = Timestamp::Now;
    for option in elems {
        let O::Atom(name) = option else {
            return Err(badarg());
        };
        if !allowed.contains(&name.as_str()) {
            return Err(badarg());
        }
        if ["scheduler", "runnable_procs", "runnable_ports", "exclusive"].contains(&name.as_str())
            && !flags.contains(name)
        {
            flags.push(name.clone())
        }
        match name.as_str() {
            "timestamp" => timestamp = Timestamp::Now,
            "monotonic_timestamp" => timestamp = Timestamp::Monotonic,
            "strict_monotonic_timestamp" => timestamp = Timestamp::StrictMonotonic,
            _ => {}
        }
    }
    let previous = profile_get(process)?;
    let mut enabled = 0;
    if flags.iter().any(|flag| flag == "runnable_procs") {
        enabled |= PROFILE_RUNNABLE_PROCS;
    }
    if flags.iter().any(|flag| flag == "scheduler") {
        enabled |= PROFILE_SCHEDULER;
    }
    if flags.iter().any(|flag| flag == "runnable_ports") {
        enabled |= PROFILE_RUNNABLE_PORTS;
    }
    *profile().lock().unwrap() = Profile {
        target: Some(target),
        flags,
        timestamp,
    };
    PROFILE_FLAGS.store(enabled, Ordering::Relaxed);
    Ok(previous)
}

/// Build the scheduler transition message for the scheduler's worker hook.
// Port of erts/emulator/beam/erl_trace.c:1957 (profile_scheduler), OTP-29.1.1.
pub(crate) fn profile_scheduler_event(
    process: &mut Process,
    _pid: arinsal_sched::Pid,
    scheduler_id: u32,
    active: bool,
    active_schedulers: u32,
) -> Option<(arinsal_sched::Pid, Message)> {
    let flags = PROFILE_FLAGS.load(Ordering::Relaxed);
    if flags & PROFILE_SCHEDULER == 0 {
        return None;
    }
    let profile = profile().lock().unwrap().clone();
    let target = profile_target(&profile)?;
    let mut heap = arinsal_bifs::FragmentingHeap(&mut process.heap);
    let message = from_owned(
        &O::Tuple(vec![
            O::Atom("profile".into()),
            O::Atom("scheduler".into()),
            O::Int(scheduler_id as i64),
            O::Atom(if active { "active" } else { "inactive" }.into()),
            O::Int(active_schedulers as i64),
            profile_timestamp(profile.timestamp),
        ]),
        &mut heap,
    )
    .ok()?;
    Some((target, Message::copy_from(message).ok()?))
}

/// Emit a port queue transition from the port task's runnable boundary.
// Port of erts/emulator/beam/erl_trace.c:2330 (profile_runnable_port), OTP-29.1.1.
pub(crate) fn profile_port_event(
    scheduler: &arinsal_sched::Scheduler<Process>,
    sender: arinsal_sched::Pid,
    port_id: u64,
    active: bool,
) {
    if PROFILE_FLAGS.load(Ordering::Relaxed) & PROFILE_RUNNABLE_PORTS == 0 {
        return;
    }
    let profile = profile().lock().unwrap().clone();
    let Some(target) = profile_target(&profile) else {
        return;
    };
    let message = O::Tuple(vec![
        O::Atom("profile".into()),
        O::Port {
            node: "nonode@nohost".into(),
            id: port_id,
            creation: 0,
        },
        O::Atom(if active { "active" } else { "inactive" }.into()),
        O::Int(0),
        profile_timestamp(profile.timestamp),
    ]);
    let mut heap = arinsal_term::ProcessHeap::new();
    let Ok(message) = from_owned(&message, &mut arinsal_bifs::FragmentingHeap(&mut heap)) else {
        return;
    };
    if let Ok(message) = Message::copy_from(message) {
        let _ = scheduler.send(sender, target, message);
    }
}

fn profile_target(profile: &Profile) -> Option<arinsal_sched::Pid> {
    let Some(O::Pid {
        node,
        id,
        serial,
        creation,
    }) = profile.target.as_ref()
    else {
        return None;
    };
    let local_name = crate::node_tables::lock().local_name.clone();
    if *creation != 0 || (node != "nonode@nohost" && node != &local_name) {
        return None;
    }
    Term::pid(*id, *serial).and_then(arinsal_sched::Pid::from_term)
}

/// Emit the current process's runnable transition to a local profiler process.
// Port of erts/emulator/beam/erl_trace.c:2357 (profile_runnable_proc), OTP-29.1.1.
pub(crate) fn profile_process_event(
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    active: bool,
) {
    let flags = PROFILE_FLAGS.load(Ordering::Relaxed);
    if flags & PROFILE_RUNNABLE_PROCS == 0 {
        return;
    }
    let profile = profile().lock().unwrap().clone();
    let Some(O::Pid {
        node,
        id,
        serial,
        creation,
    }) = profile.target.as_ref()
    else {
        return;
    };
    let local_name = crate::node_tables::lock().local_name.clone();
    if *creation != 0 || (node != "nonode@nohost" && node != &local_name) {
        return;
    }
    let Some(target) = Term::pid(*id, *serial).and_then(arinsal_sched::Pid::from_term) else {
        return;
    };
    let Some(pid) = ctx.pid().to_term().and_then(|pid| to_owned(pid).ok()) else {
        return;
    };
    let where_mfa = process
        .runtime
        .as_ref()
        .and_then(|runtime| {
            runtime.with_modules(|modules| {
                modules.get(process.module).and_then(|module| {
                    module.function_at(process.ip).map(|(function, arity)| {
                        O::Tuple(vec![
                            O::Atom(module.name.clone()),
                            O::Atom(function.to_owned()),
                            O::Int(arity as i64),
                        ])
                    })
                })
            })
        })
        .unwrap_or(O::Int(0));
    let message = O::Tuple(vec![
        O::Atom("profile".into()),
        pid,
        O::Atom(if active { "active" } else { "inactive" }.into()),
        where_mfa,
        profile_timestamp(profile.timestamp),
    ]);
    let Ok(message) = from_owned(
        &message,
        &mut arinsal_bifs::FragmentingHeap(&mut process.heap),
    ) else {
        return;
    };
    if let Ok(message) = Message::copy_from(message) {
        let _ = ctx.send(target, message);
    }
}

fn profile_timestamp(timestamp: Timestamp) -> O {
    match timestamp {
        Timestamp::Now => {
            let micros = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_micros();
            O::Tuple(vec![
                O::Int((micros / 1_000_000_000_000) as i64),
                O::Int(((micros / 1_000_000) % 1_000_000) as i64),
                O::Int((micros % 1_000_000) as i64),
            ])
        }
        Timestamp::Monotonic | Timestamp::StrictMonotonic => {
            static START: OnceLock<Instant> = OnceLock::new();
            let nanos = START.get_or_init(Instant::now).elapsed().as_nanos() as i64;
            if matches!(timestamp, Timestamp::Monotonic) {
                O::Int(nanos)
            } else {
                O::Tuple(vec![
                    O::Int(nanos),
                    O::Int(PROFILE_UNIQUE.fetch_add(1, Ordering::Relaxed) as i64),
                ])
            }
        }
    }
}

fn loaded_drivers(process: &mut Process) -> Result<Term, VmError> {
    // Port of erts/emulator/beam/erl_bif_ddll.c:666 (erl_ddll_loaded_drivers_0), OTP-29.1.1.
    let values = DDLL_STATIC
        .iter()
        .map(|name| O::list(name.bytes().map(|b| O::Int(b as i64)).collect()))
        .collect();
    let result = O::Tuple(vec![
        O::Atom("ok".into()),
        O::List {
            elems: values,
            tail: Box::new(O::Nil),
        },
    ]);
    let mut heap = arinsal_bifs::FragmentingHeap(&mut process.heap);
    from_owned(&result, &mut heap).map_err(|_| badarg())
}

fn driver_name(term: Term) -> Option<String> {
    let owned = to_owned(term).ok()?;
    match &owned {
        O::Atom(name) => Some(name.clone()),
        O::List { .. } => elems_to_string(&owned),
        _ => None,
    }
}

fn elems_to_string(term: &O) -> Option<String> {
    let O::List { elems, tail } = term else {
        return None;
    };
    if **tail != O::Nil {
        return None;
    }
    let bytes = elems
        .iter()
        .map(|v| match v {
            O::Int(n) if (0..=255).contains(n) => Some(*n as u8),
            _ => None,
        })
        .collect::<Option<Vec<_>>>()?;
    String::from_utf8(bytes).ok()
}

fn ddll_info(process: &mut Process, args: &[Term]) -> Result<Term, VmError> {
    // Port of erts/emulator/beam/erl_bif_ddll.c:694 (erl_ddll_info_2), OTP-29.1.1.
    let name = driver_name(args[0]).ok_or_else(badarg)?;
    let item = atom_text(args[1]).ok_or_else(badarg)?;
    if !DDLL_STATIC.contains(&name.as_str()) {
        return Err(badarg());
    }
    let result = match item.as_str() {
        "processes" | "awaiting_load" | "awaiting_unload" => O::Atom("linked_in_driver".into()),
        "driver_options" => O::Nil,
        "port_count" => O::Atom("linked_in_driver".into()),
        "linked_in_driver" => O::Atom("true".into()),
        "permanent" => O::Atom("false".into()),
        _ => return Err(badarg()),
    };
    let mut heap = arinsal_bifs::FragmentingHeap(&mut process.heap);
    from_owned(&result, &mut heap).map_err(|_| badarg())
}

fn ddll_try_load(process: &mut Process, args: &[Term]) -> Result<Term, VmError> {
    // Port of erts/emulator/beam/erl_bif_ddll.c:178 (erl_ddll_try_load_3), OTP-29.1.1.
    let path = driver_name(args[0]).ok_or_else(badarg)?;
    let name = driver_name(args[1]).ok_or_else(badarg)?;
    let options = to_owned(args[2]).map_err(|_| badarg())?;
    if !proper_list(&options) {
        return Err(badarg());
    }
    let mut reload = false;
    for option in list_items(&options).unwrap_or_default() {
        match &option {
            O::Tuple(items)
                if items.len() == 2
                    && items[0] == O::Atom("monitor".into())
                    && matches!(&items[1], O::Atom(a) if a == "pending" || a == "pending_driver") =>
                {}
            O::Tuple(items)
                if items.len() == 2
                    && items[0] == O::Atom("reload".into())
                    && matches!(&items[1], O::Atom(a) if a == "pending" || a == "pending_driver") =>
            {
                reload = true;
            }
            O::Tuple(items)
                if items.len() == 2
                    && items[0] == O::Atom("driver_options".into())
                    && valid_driver_options(&items[1]) => {}
            _ => return Err(badarg()),
        }
    }
    let err = if DDLL_STATIC.contains(&name.as_str()) {
        tuple(process, &[atom("error"), atom("linked_in_driver")])?
    } else if reload {
        tuple(process, &[atom("error"), atom("not_loaded")])?
    } else {
        let candidate = std::path::Path::new(&path).join(format!("{name}.so"));
        let code = if std::path::Path::new(&path).is_file() || candidate.exists() {
            -11
        } else {
            -10
        };
        let detail = tuple(
            process,
            &[
                atom("open_error"),
                Term::small(code).expect("small driver error code"),
            ],
        )?;
        tuple(process, &[atom("error"), detail])?
    };
    Ok(err)
}

fn valid_driver_options(options: &O) -> bool {
    list_items(options).is_some_and(|items| {
        items
            .iter()
            .all(|item| item == &O::Atom("kill_ports".into()))
    })
}

fn ddll_try_unload(process: &mut Process, args: &[Term]) -> Result<Term, VmError> {
    // Port of erts/emulator/beam/erl_bif_ddll.c:419 (erl_ddll_try_unload_2), OTP-29.1.1.
    let name = driver_name(args[0]).ok_or_else(badarg)?;
    let options = to_owned(args[1]).map_err(|_| badarg())?;
    if !proper_list(&options) {
        return Err(badarg());
    }
    for option in list_items(&options).unwrap_or_default() {
        if option != O::Atom("kill_ports".into())
            && !matches!(option, O::Tuple(ref v) if v.len() == 2 && v[0] == O::Atom("monitor".into()) && matches!(v[1], O::Atom(ref a) if a == "pending" || a == "pending_driver"))
        {
            return Err(badarg());
        }
    }
    tuple(
        process,
        &[
            atom("error"),
            atom(if DDLL_STATIC.contains(&name.as_str()) {
                "linked_in_driver"
            } else {
                "not_loaded"
            }),
        ],
    )
}

fn ddll_monitor(
    ctx: &mut RunCtx<'_, Message>,
    process: &mut Process,
    args: &[Term],
) -> Result<Term, VmError> {
    // Port of erts/emulator/beam/erl_bif_ddll.c:655 (erl_ddll_monitor_2), OTP-29.1.1.
    if atom_text(args[0]).as_deref() != Some("driver") {
        return Err(badarg());
    }
    let owned = to_owned(args[1]).map_err(|_| badarg())?;
    let O::Tuple(description) = &owned else {
        return Err(badarg());
    };
    let [name_term, O::Atom(state)] = description.as_slice() else {
        return Err(badarg());
    };
    if !["loaded", "unloaded", "unloaded_only"].contains(&state.as_str()) {
        return Err(badarg());
    }
    let name = match name_term {
        O::Atom(name) => name.clone(),
        O::List { elems, tail } if **tail == O::Nil => {
            let bytes = elems
                .iter()
                .map(|term| match term {
                    O::Int(n) => u8::try_from(*n).ok(),
                    _ => None,
                })
                .collect::<Option<Vec<_>>>()
                .ok_or_else(badarg)?;
            String::from_utf8(bytes).map_err(|_| badarg())?
        }
        _ => return Err(badarg()),
    };
    static NEXT_DDLL_REF: AtomicU64 = AtomicU64::new(1);
    let id = NEXT_DDLL_REF.fetch_add(1, Ordering::Relaxed);
    let reference = crate::signals::reference(process, id)?;
    ddll_monitors().lock().unwrap().insert(id);
    if DDLL_STATIC.contains(&name.as_str()) {
        let name = TermBuilder::new(&mut arinsal_bifs::FragmentingHeap(&mut process.heap))
            .string_to_list(&name)
            .map_err(|_| badarg())?;
        let message = tuple(
            process,
            &[
                atom("UP"),
                reference,
                atom("driver"),
                name,
                atom("permanent"),
            ],
        )?;
        ddll_notify(ctx, id, message)?;
    } else {
        let name = TermBuilder::new(&mut arinsal_bifs::FragmentingHeap(&mut process.heap))
            .string_to_list(&name)
            .map_err(|_| badarg())?;
        let message = tuple(
            process,
            &[
                atom("DOWN"),
                reference,
                atom("driver"),
                name,
                atom("unloaded"),
            ],
        )?;
        ddll_notify(ctx, id, message)?;
    }
    Ok(reference)
}

fn ddll_notify(ctx: &mut RunCtx<'_, Message>, id: u64, message: Term) -> Result<(), VmError> {
    // A queued driver-state transition consumes its monitor. Demonitor removes
    // the same entry before this transition can publish a notification.
    if ddll_monitors().lock().unwrap().remove(&id) {
        ctx.send(ctx.pid(), Message::copy_from(message)?)
            .map_err(|_| badarg())?;
    }
    Ok(())
}

fn ddll_demonitor(reference: Term) -> Result<Term, VmError> {
    // Port of erts/emulator/beam/erl_bif_ddll.c:641 (erl_ddll_demonitor_1), OTP-29.1.1.
    let id = crate::signals::ref_id(reference).ok_or_else(badarg)?;
    ddll_monitors().lock().unwrap().remove(&id);
    Ok(atom("true"))
}

fn format_error(process: &mut Process, code: Term) -> Result<Term, VmError> {
    // Port of erts/emulator/beam/erl_bif_ddll.c:813 (erl_ddll_format_error_int_1), OTP-29.1.1.
    let owned_code = to_owned(code).map_err(|_| badarg())?;
    let message = match &owned_code {
        O::Tuple(items)
            if items.len() == 2
                && items[0] == O::Atom("open_error".into())
                && matches!(items[1], O::Int(_)) =>
        {
            format!("Driver dynamic loading failed with error code {}", items[1])
        }
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
            _ => return Err(badarg()),
        },
        _ => return Err(badarg()),
    };
    let value = O::list(message.bytes().map(|b| O::Int(b as i64)).collect());
    let mut heap = arinsal_bifs::FragmentingHeap(&mut process.heap);
    from_owned(&value, &mut heap).map_err(|_| badarg())
}

fn dist_ext_to_term(process: &mut Process, args: &[Term]) -> Result<Term, VmError> {
    // Port of erts/emulator/beam/external.c:1340 (erts_debug_dist_ext_to_term_2), OTP-29.1.1.
    let cache_owned = to_owned(args[0]).map_err(|_| badarg())?;
    let O::Tuple(cache) = &cache_owned else {
        return Err(badarg());
    };
    if cache.len() > 255 || cache.iter().any(|v| !matches!(v, O::Atom(_))) {
        return Err(badarg());
    }
    let bytes_owned = to_owned(args[1]).map_err(|_| badarg())?;
    let O::Binary(bytes) = &bytes_owned else {
        return Err(badarg());
    };
    if bytes.is_empty() {
        return Err(badarg());
    }
    let owned = arinsal_etf::decode_dist_ext_with_atom_table(cache, bytes).map_err(|_| badarg())?;
    let mut heap = arinsal_bifs::FragmentingHeap(&mut process.heap);
    from_owned(&owned, &mut heap).map_err(|_| badarg())
}

fn string_list_to_float(process: &mut Process, term: Term) -> Result<Term, VmError> {
    // Port of erts/emulator/beam/bif.c:3517 (string_list_to_float_1), OTP-29.1.1.
    let owned = to_owned(term).map_err(|_| badarg())?;
    if owned == O::Nil
        || matches!(&owned, O::List { elems, tail } if elems.is_empty() && **tail == O::Nil)
    {
        return tuple(process, &[atom("error"), atom("no_float")]);
    }
    let O::List { elems, tail } = &owned else {
        return tuple(process, &[atom("error"), atom("not_a_list")]);
    };
    if **tail != O::Nil {
        return Err(badarg());
    }
    let mut bytes = Vec::with_capacity(elems.len());
    for item in elems {
        let O::Int(n) = item else {
            return Err(badarg());
        };
        let byte = u8::try_from(*n).map_err(|_| badarg())?;
        bytes.push(byte);
    }
    let parsed = (1..=bytes.len()).rev().find_map(|end| {
        arinsal_float::list_to_float(&bytes[..end])
            .ok()
            .map(|number| (number, end))
    });
    let Some((number, end)) = parsed else {
        return tuple(process, &[atom("error"), atom("no_float")]);
    };
    let rest = O::list(bytes[end..].iter().map(|b| O::Int(i64::from(*b))).collect());
    let (rest, float) = {
        let mut heap = arinsal_bifs::FragmentingHeap(&mut process.heap);
        let rest = from_owned(&rest, &mut heap).map_err(|_| badarg())?;
        let float = TermBuilder::new(&mut heap)
            .float(number)
            .map_err(|_| badarg())?;
        (rest, float)
    };
    tuple(process, &[float, rest])
}

fn proper_list(o: &O) -> bool {
    match o {
        O::Nil => true,
        O::List { tail, .. } => **tail == O::Nil,
        _ => false,
    }
}
fn list_items(o: &O) -> Option<Vec<O>> {
    match o {
        O::Nil => Some(vec![]),
        O::List { elems, tail } if **tail == O::Nil => Some(elems.clone()),
        _ => None,
    }
}
fn tuple(process: &mut Process, items: &[Term]) -> Result<Term, VmError> {
    let mut heap = arinsal_bifs::FragmentingHeap(&mut process.heap);
    TermBuilder::new(&mut heap)
        .tuple(items)
        .map_err(|_| badarg())
}
fn atom(name: &str) -> Term {
    Term::atom(global_atoms().intern(name).expect("runtime atom"))
}
fn atom_text(term: Term) -> Option<String> {
    global_atoms().text(term.as_atom()?).map(|s| s.to_string())
}
fn badarg() -> VmError {
    VmError::Trap(crate::exceptions::Trap::error(atom("badarg")))
}
