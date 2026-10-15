//! `arinsal_ns`: namespace management for a multi-tenant node. Everything except `of/1` is
//! root only and raises `notsup` for a process inside a namespace.

use super::NativeArgs;
use crate::process::Message;
use crate::signals::{ErlSpawnOpts, atom, erl_create_process};
use crate::{Process, Vm, VmError};
use arinsal_etf::OwnedTerm as O;
use arinsal_sched::{NS_ID_MASK, Pid, Priority, RunCtx, Signal};
use arinsal_term::{Term, from_owned, to_owned};

pub(crate) const IMPLEMENTED: &[(&str, &str, u8)] = &[
    ("arinsal_ns", "create", 2),
    ("arinsal_ns", "create", 3),
    ("arinsal_ns", "spawn", 4),
    ("arinsal_ns", "spawn", 5),
    ("arinsal_ns", "destroy", 1),
    ("arinsal_ns", "expose", 1),
    ("arinsal_ns", "info", 1),
    ("arinsal_ns", "list", 0),
    ("arinsal_ns", "of", 1),
];

pub(crate) fn recognizes(module: &str, function: &str, arity: u8) -> bool {
    super::listed(IMPLEMENTED, module, function, arity)
}

fn badarg() -> VmError {
    VmError::Trap(crate::exceptions::Trap::error(atom("badarg")))
}

fn notsup() -> VmError {
    VmError::Trap(crate::exceptions::Trap::error(atom("notsup")))
}

fn system_limit() -> VmError {
    VmError::Trap(crate::exceptions::Trap::error(atom("system_limit")))
}

pub(crate) fn call(
    vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    module: &str,
    function: &str,
    args: NativeArgs<'_>,
) -> Option<Result<Term, VmError>> {
    if !recognizes(module, function, args.len() as u8) {
        return None;
    }
    Some(args.with_values(process, |process, values| {
        call_impl(vm, process, ctx, function, values)
    }))
}

fn call_impl(
    vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    function: &str,
    args: &[Term],
) -> Result<Term, VmError> {
    if let ("of", [pid]) = (function, args) {
        return namespace_of(process, *pid);
    }
    if process.ns != 0 {
        return Err(notsup());
    }
    match (function, args) {
        ("create", [tenant, project]) => create(process, *tenant, *project, Term::NIL),
        ("create", [tenant, project, opts]) => create(process, *tenant, *project, *opts),
        ("spawn", [ns, m, f, a]) => spawn(vm, process, ctx, *ns, (*m, *f, *a), Term::NIL),
        ("spawn", [ns, m, f, a, opts]) => spawn(vm, process, ctx, *ns, (*m, *f, *a), *opts),
        ("destroy", [ns]) => destroy(process, ctx, *ns),
        ("expose", [pid]) => expose(process, *pid),
        ("info", [ns]) => info(process, *ns),
        ("list", []) => list(process),
        _ => Err(badarg()),
    }
}

fn heap_term(process: &mut Process, value: &O) -> Result<Term, VmError> {
    from_owned(
        value,
        &mut arinsal_bifs::ProcessHeapHandle(&mut process.heap),
    )
    .map_err(|_| system_limit())
}

fn binary_arg(term: Term) -> Result<Vec<u8>, VmError> {
    match &to_owned(term) {
        Ok(O::Binary(bytes)) => Ok(bytes.clone()),
        _ => Err(badarg()),
    }
}

fn ns_arg(term: Term) -> Result<u32, VmError> {
    let id = term.as_small().ok_or_else(badarg)?;
    u32::try_from(id)
        .ok()
        .filter(|id| *id != 0 && *id & !NS_ID_MASK == 0)
        .ok_or_else(badarg)
}

fn limit_arg(value: &O) -> Result<u64, VmError> {
    match value {
        O::Int(n) if *n >= 0 => Ok(*n as u64),
        O::Atom(name) if name == "infinity" => Ok(crate::namespace::UNLIMITED),
        _ => Err(badarg()),
    }
}

fn create(process: &mut Process, tenant: Term, project: Term, opts: Term) -> Result<Term, VmError> {
    let tenant = binary_arg(tenant)?;
    let project = binary_arg(project)?;
    let mut max_processes = crate::namespace::UNLIMITED;
    let mut max_bytes = crate::namespace::UNLIMITED;
    match &to_owned(opts).map_err(|_| badarg())? {
        O::Nil => {}
        O::Map(entries) => {
            for (key, value) in entries {
                match key {
                    O::Atom(name) if name == "max_processes" => max_processes = limit_arg(value)?,
                    O::Atom(name) if name == "max_bytes" => max_bytes = limit_arg(value)?,
                    _ => {}
                }
            }
        }
        _ => return Err(badarg()),
    }
    let runtime = process.runtime.clone().ok_or_else(badarg)?;
    let scheduler = runtime.scheduler()?;
    let entry = runtime
        .namespaces
        .create(&scheduler, tenant, project, max_processes, max_bytes);
    heap_term(
        process,
        &O::Tuple(vec![O::Atom("ok".into()), O::Int(i64::from(entry.id))]),
    )
}

fn spawn(
    vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    ns: Term,
    mfa: (Term, Term, Term),
    opts: Term,
) -> Result<Term, VmError> {
    let ns = ns_arg(ns)?;
    let runtime = process.runtime.clone().ok_or_else(badarg)?;
    runtime.namespaces.live(ns).ok_or_else(badarg)?;
    let mut group_leader = None;
    for option in crate::signals::list(opts).ok_or_else(badarg)? {
        match &to_owned(option).map_err(|_| badarg())? {
            O::Tuple(items) if items.len() == 2 && items[0] == O::Atom("group_leader".into()) => {
                let leader = heap_term(process, &items[1])?;
                group_leader = Some(Pid::from_term(leader).ok_or_else(badarg)?);
            }
            _ => return Err(badarg()),
        }
    }
    let created = erl_create_process(
        vm,
        process,
        ctx,
        mfa,
        ErlSpawnOpts {
            link: false,
            monitor: None,
            min_heap: None,
            min_bin_vheap: None,
            fullsweep: None,
            max_heap: None,
            off_heap_queue: None,
            scheduler: None,
            priority: Priority::Normal,
            opts: Term::NIL,
            reply: None,
            ns: Some(ns),
            group_leader,
        },
    )?;
    created
        .pid
        .to_term()
        .ok_or_else(|| VmError::Unsupported("pid limit".into()))
}

fn limit_term(value: u64) -> O {
    if value == crate::namespace::UNLIMITED {
        O::Atom("infinity".into())
    } else {
        O::Int(i64::try_from(value).unwrap_or(i64::MAX))
    }
}

/// `#{tenant, project, processes, reductions, heap_words, max_processes, max_bytes}` of `ns`.
/// An unset cap is `infinity`. A destroyed namespace still answers, so its process count
/// can be watched draining.
fn info(process: &mut Process, ns: Term) -> Result<Term, VmError> {
    let ns = ns_arg(ns)?;
    let runtime = process.runtime.clone().ok_or_else(badarg)?;
    let entry = runtime.namespaces.get(ns).ok_or_else(badarg)?;
    let key = |name: &str| O::Atom(name.into());
    let int = |value: u64| O::Int(i64::try_from(value).unwrap_or(i64::MAX));
    let map = O::Map(vec![
        (key("tenant"), O::Binary(entry.tenant.clone())),
        (key("project"), O::Binary(entry.project.clone())),
        (key("processes"), int(entry.counters.processes())),
        (key("reductions"), int(entry.counters.reductions())),
        (
            key("heap_words"),
            O::Int(entry.heap_words.load(std::sync::atomic::Ordering::Relaxed)),
        ),
        (
            key("max_processes"),
            limit_term(entry.counters.max_processes()),
        ),
        (key("max_bytes"), limit_term(entry.max_bytes)),
    ]);
    heap_term(process, &map)
}

/// Ids of the namespaces that are alive, in creation order.
fn list(process: &mut Process) -> Result<Term, VmError> {
    let runtime = process.runtime.clone().ok_or_else(badarg)?;
    let ids = runtime.namespaces.list();
    let value = if ids.is_empty() {
        O::Nil
    } else {
        O::List {
            elems: ids.into_iter().map(|id| O::Int(i64::from(id))).collect(),
            tail: Box::new(O::Nil),
        }
    };
    heap_term(process, &value)
}

/// Mark `ns` destroyed and send `kill` to every process of it. The processes exit shortly
/// after. Spawning into the namespace fails from the moment it is marked, so a second scan
/// finds the children that were created while the first signals were in flight.
fn destroy(
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    ns: Term,
) -> Result<Term, VmError> {
    let ns = ns_arg(ns)?;
    let runtime = process.runtime.clone().ok_or_else(badarg)?;
    runtime.namespaces.get(ns).ok_or_else(badarg)?;
    runtime.namespaces.close(ns);
    let scheduler = runtime.scheduler()?;
    for _ in 0..2 {
        for pid in scheduler.pids_in_ns(ns) {
            let reason = Message::copy_from(atom("kill"))?;
            let _ = ctx.signal(pid, Signal::Exit(reason));
        }
    }
    Ok(atom("ok"))
}

/// Make a root process reachable from every namespace.
fn expose(process: &mut Process, pid: Term) -> Result<Term, VmError> {
    let pid = Pid::from_term(pid).ok_or_else(badarg)?;
    let runtime = process.runtime.clone().ok_or_else(badarg)?;
    let scheduler = runtime.scheduler()?;
    match scheduler.ns_word(pid) {
        Some(word) if word & NS_ID_MASK == 0 => {
            scheduler.set_ns_shared(pid, true);
            Ok(atom("ok"))
        }
        _ => Err(badarg()),
    }
}

/// The namespace of a local process: 0 for root, `undefined` when the process is gone.
fn namespace_of(process: &Process, pid: Term) -> Result<Term, VmError> {
    let pid = Pid::from_term(pid).ok_or_else(badarg)?;
    let runtime = process.runtime.as_ref().ok_or_else(badarg)?;
    let scheduler = runtime.scheduler()?;
    match scheduler.ns_word(pid) {
        Some(word) => Term::small(i64::from(word & NS_ID_MASK)).ok_or_else(badarg),
        None => Ok(atom("undefined")),
    }
}
