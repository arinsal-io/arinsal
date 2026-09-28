//! Process-aware BIFs. These use the running process and scheduler context.

use crate::process::{Message, Runtime};
use crate::{Process, Vm, VmError};
use arinsal_sched::{Pid, RunCtx, Signal};
use arinsal_term::{Atom, FunRef, Term, TermBuilder, TermKind, copy_term, global_atoms};
use std::collections::{BTreeMap, HashMap};
#[cfg(feature = "pf-mem-counters")]
use std::sync::atomic::Ordering;
use std::sync::{Mutex, OnceLock};

#[cfg(feature = "pf-mem-counters")]
pub(crate) static PF_SPAWN_FUN_LOAD_NS: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);
#[cfg(feature = "pf-mem-counters")]
pub(crate) static PF_SPAWN_FUN_SETUP_NS: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);
#[cfg(feature = "pf-mem-counters")]
pub(crate) static PF_SPAWN_FUN_SCHED_NS: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

pub(crate) fn atom(name: &str) -> Term {
    // Predefined OTP atoms. Interning on every monitor/send/demonitor took the
    // atom-table lock on the `gen_server:call` path.
    let known = match name {
        "false" => arinsal_term::atoms::FALSE,
        "true" => arinsal_term::atoms::TRUE,
        "ok" => arinsal_term::atoms::OK,
        "DOWN" => arinsal_term::atoms::DOWN,
        "process" => arinsal_term::atoms::PROCESS,
        "port" => arinsal_term::atoms::PORT,
        "alias" => arinsal_term::atoms::ALIAS,
        "demonitor" => arinsal_term::atoms::DEMONITOR,
        "noconnect" => arinsal_term::atoms::NOCONNECT,
        "nosuspend" => arinsal_term::atoms::NOSUSPEND,
        "flush" => arinsal_term::atoms::FLUSH,
        "info" => arinsal_term::atoms::INFO,
        "badarg" => arinsal_term::atoms::BADARG,
        "noproc" => arinsal_term::atoms::NOPROC,
        "normal" => arinsal_term::atoms::NORMAL,
        "EXIT" => arinsal_term::atoms::EXIT_2,
        "kill" => arinsal_term::atoms::KILL,
        "killed" => arinsal_term::atoms::KILLED,
        "undefined" => arinsal_term::atoms::UNDEFINED,
        "error" => arinsal_term::atoms::ERROR,
        "timeout" => arinsal_term::atoms::TIMEOUT,
        "timeout_value" => arinsal_term::atoms::TIMEOUT_VALUE,
        "infinity" => arinsal_term::atoms::INFINITY,
        "monitor" => arinsal_term::atoms::MONITOR,
        "tag" => arinsal_term::atoms::TAG,
        "min_heap_size" => arinsal_term::atoms::MIN_HEAP_SIZE,
        "explicit_unalias" => arinsal_term::atoms::EXPLICIT_UNALIAS,
        "reply_demonitor" => arinsal_term::atoms::REPLY_DEMONITOR,
        "garbage_collect" => arinsal_term::atoms::GARBAGE_COLLECT,
        "async" => arinsal_term::atoms::ASYNC,
        _ => {
            return Term::atom(global_atoms().intern(name).expect("short built-in atom"));
        }
    };
    Term::atom(known)
}

fn atom_name(term: Term) -> Option<String> {
    global_atoms()
        .text(term.as_atom()?)
        .map(|name| name.to_string())
}

fn badarg(_name: &str) -> VmError {
    VmError::Trap(crate::exceptions::Trap::error(atom("badarg")))
}

fn system_limit() -> VmError {
    VmError::Trap(crate::exceptions::Trap::error(atom("system_limit")))
}

fn local_node(node: Term) -> Result<(), VmError> {
    match atom_name(node).as_deref() {
        Some("nonode@nohost") => Ok(()),
        Some(_) => Err(VmError::Unsupported("distributed spawn".into())),
        None => Err(badarg("spawn node")),
    }
}

fn runtime(process: &Process) -> Result<&Runtime, VmError> {
    process
        .runtime
        .as_deref()
        .ok_or_else(|| VmError::Unsupported("process BIF requires a scheduler".into()))
}

#[cfg(test)]
mod task_latency_tests {
    use arinsal_difftest::RefErl;

    use crate::Vm;

    const SOURCE: &str = concat!(
        "-module(task_latency_probe). -export([run/0]).\n",
        "task() -> Ref=make_ref(), Pid=spawn(fun() -> receive {Alias, Ref} -> Alias ! {Ref, ok} end end),\n",
        "Alias=erlang:monitor(process, Pid, [{alias,demonitor}]), Pid ! {Alias,Ref}, {Pid,Alias,Ref}.\n",
        "await({Pid,Alias,Ref}) -> receive {Ref,ok} -> erlang:demonitor(Alias,[flush]), ok;\n",
        "{'DOWN',Alias,process,Pid,Reason} -> erlang:error(Reason) after 5000 -> erlang:error(timeout) end.\n",
        "round() -> Tasks=[task() || _ <- lists:seq(1,8)], [await(T) || T <- Tasks], ok.\n",
        "run() -> round(), T0=erlang:monotonic_time(microsecond),\n",
        "[round() || _ <- lists:seq(1,20)], T1=erlang:monotonic_time(microsecond),\n",
        "(T1-T0) div 20."
    );

    #[test]
    fn eight_alias_monitor_replies_wake_the_waiter_without_exit_poll_delay() {
        let Ok(reference) = RefErl::start() else {
            eprintln!("erl unavailable; skipping task latency regression test");
            return;
        };
        let beam = reference
            .compile_named("task_latency_probe", SOURCE, &[])
            .expect("compile alias monitor latency probe");
        let mut vm = Vm::new([]);
        vm.load_bytes(&beam)
            .expect("load alias monitor latency probe");
        let elapsed = vm
            .eval_scheduled("task_latency_probe", "run", &[], 1, None)
            .expect("run alias monitor latency probe")
            .term;
        let arinsal_etf::OwnedTerm::Int(micros) = elapsed else {
            panic!("expected elapsed microseconds, got {elapsed:?}");
        };
        assert!(
            micros < 1_000,
            "eight alias monitor replies took {micros} us, expected under 1000 us"
        );
    }

    #[test]
    fn spawn_opt_scheduler_bindings_are_accepted_for_each_online_scheduler() {
        let Ok(reference) = RefErl::start() else {
            eprintln!("erl unavailable; skipping spawn scheduler option differential test");
            return;
        };
        let source = r#"
-module(spawn_scheduler_probe).
-export([run/0]).
run() ->
    Count = erlang:system_info(schedulers_online),
    Processes = [spawn_opt(fun() -> ok end, [{scheduler, I}]) || I <- lists:seq(1, Count)],
    length(Processes).
"#;
        let beam = reference
            .compile_named("spawn_scheduler_probe", source, &[])
            .unwrap();
        reference.load("spawn_scheduler_probe", &beam).unwrap();
        let expected = reference.call("spawn_scheduler_probe", "run", &[]);
        let workers = match reference
            .eval("erlang:system_info(schedulers_online)")
            .unwrap()
        {
            arinsal_etf::OwnedTerm::Int(workers) => workers as usize,
            value => panic!("expected scheduler count, got {value:?}"),
        };
        let mut vm = Vm::new([]);
        vm.load_bytes(&beam).unwrap();
        let actual = vm
            .eval_scheduled("spawn_scheduler_probe", "run", &[], workers, Some(79))
            .unwrap()
            .term;
        assert_eq!(expected, arinsal_difftest::CallResult::Ok(actual));
    }
}

fn list(term: Term) -> Option<Vec<Term>> {
    let mut values = Vec::new();
    let mut current = term;
    while current.classify() == TermKind::List {
        // SAFETY: The source heap remains live during this BIF call.
        let (head, tail) = unsafe { current.cons_ref()? };
        values.push(head);
        current = tail;
    }
    (current == Term::NIL).then_some(values)
}

pub(crate) fn reference(process: &mut Process, id: u64) -> Result<Term, VmError> {
    let mut heap = arinsal_bifs::FragmentingHeap(&mut process.heap);
    Term::local_ref(&mut heap, [id as u32, (id >> 32) as u32, 0])
        .map_err(|error| VmError::Unsupported(format!("reference allocation: {error:?}")))
}

pub(crate) fn ref_id(term: Term) -> Option<u64> {
    match term.identity()? {
        arinsal_term::Identity::Ref { ids, .. } if ids.len() == 3 && ids[2] == 0 => {
            Some(ids[0] as u64 | ((ids[1] as u64) << 32))
        }
        _ => None,
    }
}

fn arm_child_link_monitor(
    child: &mut Process,
    parent: arinsal_sched::Pid,
    linked: bool,
    monitored: bool,
) -> Option<u64> {
    if linked {
        child.cold_mut().links.insert(parent);
    }
    if !monitored {
        return None;
    }
    let id = arinsal_bifs::next_ref_id();
    child.cold_mut().monitored_by.insert(id, parent);
    Some(id)
}

#[allow(clippy::too_many_arguments)] // spawn_opt flags stay positional; packing them hides the monitor race.
fn spawn_mfa(
    vm: &mut Vm,
    parent: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    mfa: (Term, Term, Term),
    linked: bool,
    monitored: bool,
    min_heap_size: Option<usize>,
    monitor_tag: Option<arinsal_etf::OwnedTerm>,
    monitor_alias: bool,
    scheduler_id: Option<usize>,
) -> Result<Term, VmError> {
    let (module, function, args) = mfa;
    let m = module.as_atom().ok_or_else(|| badarg("erlang:spawn/3"))?;
    let f = function.as_atom().ok_or_else(|| badarg("erlang:spawn/3"))?;
    let args = list(args).ok_or_else(|| badarg("erlang:spawn/3"))?;
    if args.len() > 1024 {
        return Err(badarg("erlang:spawn/3"));
    }
    let (module_id, ip) = vm.spawn_export(m, f, args.len() as u8)?;
    let mut child = Process::with_spawn_registers(args.len(), 0);
    if let Some(words) = min_heap_size {
        child.heap = arinsal_term::ProcessHeap::with_words(words.max(64));
    }
    child.module = module_id;
    child.ip = ip;
    child.runtime = parent.runtime.clone();
    child.cold_mut().group_leader = Some(
        parent
            .cold
            .as_ref()
            .and_then(|cold| cold.group_leader)
            .unwrap_or_else(|| ctx.pid()),
    );
    for (index, term) in args.iter().copied().enumerate() {
        let mut heap = arinsal_bifs::FragmentingHeap(&mut child.heap);
        child.x[index] = copy_term(term, &mut heap)
            .map_err(|error| VmError::Unsupported(format!("spawn argument: {error:?}")))?;
    }
    let rt = parent
        .runtime
        .clone()
        .ok_or_else(|| VmError::Unsupported("spawn requires a scheduler".into()))?;
    let scheduler = rt.scheduler()?;
    // The link and monitor must be on the child before enqueue. Another
    // scheduler can run `code_server`'s on_load fun to `exit/1` before a
    // Monitor signal sent after `spawn` is delivered, and the DOWN is then lost.
    // Port of erts/emulator/beam/erl_process.c (spawn_opt monitor before schedule), OTP-29.1.1.
    let monitor_id = arm_child_link_monitor(&mut child, ctx.pid(), linked, monitored);
    let pid = if let Some(scheduler_id) = scheduler_id {
        scheduler.spawn_unscheduled_on(child, scheduler_id)
    } else {
        scheduler.spawn_unscheduled(child)
    }
    .map_err(|error| VmError::Unsupported(format!("spawn: {error}")))?;
    rt.processes.lock().unwrap().insert(pid);
    if linked {
        parent.cold_mut().links.insert(pid);
    }
    let pid_term = pid
        .to_term()
        .ok_or_else(|| VmError::Unsupported("pid limit".into()))?;
    if crate::trace::spawn_interested(parent, ctx.pid()) {
        let arg_list = TermBuilder::new(&mut parent.heap)
            .list_from_iter(args.iter().copied())
            .map_err(|error| VmError::Unsupported(format!("spawn trace args: {error:?}")))?;
        let mfa = TermBuilder::new(&mut parent.heap)
            .tuple(&[module, function, arg_list])
            .map_err(|error| VmError::Unsupported(format!("spawn trace MFA: {error:?}")))?;
        crate::trace::spawned(vm, parent, ctx, pid, mfa);
    }
    if let Some(id) = monitor_id {
        parent.cold_mut().monitors.insert(id, pid);
        if let Some(tag) = monitor_tag {
            parent.cold_mut().monitor_tags.insert(id, tag);
        }
        if monitor_alias {
            parent.cold_mut().aliases.insert(id);
            rt.alias_bind(id, Some(ctx.pid()));
        }
        ctx.schedule_spawn(pid)
            .map_err(|error| VmError::Unsupported(format!("schedule spawn: {error}")))?;
        let ref_term = reference(parent, id)?;
        let mut heap = arinsal_bifs::FragmentingHeap(&mut parent.heap);
        return TermBuilder::new(&mut heap)
            .tuple(&[pid_term, ref_term])
            .map_err(|error| VmError::Unsupported(format!("spawn result: {error:?}")));
    }
    ctx.schedule_spawn(pid)
        .map_err(|error| VmError::Unsupported(format!("schedule spawn: {error}")))?;
    Ok(pid_term)
}

#[allow(clippy::too_many_arguments)] // spawn_opt flags stay positional; packing them hides the monitor race.
fn spawn_fun(
    vm: &mut Vm,
    parent: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    fun: Term,
    linked: bool,
    monitored: bool,
    min_heap_size: Option<usize>,
    monitor_tag: Option<arinsal_etf::OwnedTerm>,
    monitor_alias: bool,
    scheduler_id: Option<usize>,
) -> Result<Term, VmError> {
    #[cfg(feature = "pf-mem-counters")]
    let mut phase = std::time::Instant::now();
    if fun.classify() == TermKind::Tuple {
        // SAFETY: The tuple remains in the caller's live heap for this BIF.
        let tuple = unsafe { fun.tuple_ref() }.ok_or_else(|| badarg("spawn/1"))?;
        if tuple.len() == 2 {
            return spawn_mfa(
                vm,
                parent,
                ctx,
                (
                    tuple.get(0).ok_or_else(|| badarg("spawn/1"))?,
                    tuple.get(1).ok_or_else(|| badarg("spawn/1"))?,
                    Term::NIL,
                ),
                linked,
                monitored,
                min_heap_size,
                monitor_tag,
                monitor_alias,
                scheduler_id,
            );
        }
    }
    // SAFETY: The fun remains rooted in the caller's live process heap.
    let descriptor = unsafe { fun.fun_ref() }.ok_or_else(|| badarg("spawn/1"))?;
    let (module_name, lambda_index, arity) = match descriptor {
        FunRef::Local { entry, .. } => (
            global_atoms()
                .text(entry.module)
                .ok_or_else(|| badarg("spawn/1"))?,
            entry.index,
            entry.arity,
        ),
        FunRef::Export { entry } => {
            let (module, function, arity) = (
                Term::atom(entry.module),
                Term::atom(entry.function),
                entry.arity,
            );
            if arity != 0 {
                return Err(badarg("spawn/1"));
            }
            return spawn_mfa(
                vm,
                parent,
                ctx,
                (module, function, Term::NIL),
                linked,
                monitored,
                min_heap_size,
                monitor_tag,
                monitor_alias,
                scheduler_id,
            );
        }
    };
    if arity != 0 {
        return Err(badarg("spawn/1"));
    }
    let module_id = vm.load_named(&module_name)?;
    #[cfg(feature = "pf-mem-counters")]
    {
        PF_SPAWN_FUN_LOAD_NS.fetch_add(phase.elapsed().as_nanos() as u64, Ordering::Relaxed);
        phase = std::time::Instant::now();
    }
    let lambda = vm.modules[module_id]
        .funs
        .iter()
        .find(|lambda| lambda.entry.index == lambda_index)
        .ok_or_else(|| VmError::Unsupported("spawn lambda target".into()))?;
    let (target, free_count) = (lambda.target, lambda.num_free);
    let mut child = Process::with_spawn_registers(free_count, 0);
    if let Some(words) = min_heap_size {
        child.heap = arinsal_term::ProcessHeap::with_words(words.max(64));
    }
    child.module = module_id;
    child.ip = target;
    child.runtime = parent.runtime.clone();
    child.cold_mut().group_leader = Some(
        parent
            .cold
            .as_ref()
            .and_then(|cold| cold.group_leader)
            .unwrap_or_else(|| ctx.pid()),
    );
    if free_count > 0 {
        let copied = {
            let mut heap = arinsal_bifs::FragmentingHeap(&mut child.heap);
            copy_term(fun, &mut heap)
                .map_err(|error| VmError::Unsupported(format!("spawn fun copy: {error:?}")))?
        };
        // SAFETY: The copied fun is retained by the child's heap.
        let copied = unsafe { copied.fun_ref() }
            .ok_or_else(|| VmError::Unsupported("copied fun invalid".into()))?;
        for index in 0..free_count {
            child.x[index] = copied
                .free(index)
                .ok_or_else(|| VmError::Unsupported("spawn fun environment".into()))?;
        }
    }
    let rt = parent
        .runtime
        .clone()
        .ok_or_else(|| VmError::Unsupported("spawn requires a scheduler".into()))?;
    let monitor_id = arm_child_link_monitor(&mut child, ctx.pid(), linked, monitored);
    #[cfg(feature = "pf-mem-counters")]
    {
        PF_SPAWN_FUN_SETUP_NS.fetch_add(phase.elapsed().as_nanos() as u64, Ordering::Relaxed);
        phase = std::time::Instant::now();
    }
    let scheduler = rt.scheduler()?;
    let pid = if let Some(scheduler_id) = scheduler_id {
        scheduler.spawn_unscheduled_on(child, scheduler_id)
    } else {
        scheduler.spawn_unscheduled(child)
    }
    .map_err(|error| VmError::Unsupported(format!("spawn: {error}")))?;
    #[cfg(feature = "pf-mem-counters")]
    PF_SPAWN_FUN_SCHED_NS.fetch_add(phase.elapsed().as_nanos() as u64, Ordering::Relaxed);
    rt.processes.lock().unwrap().insert(pid);
    if linked {
        parent.cold_mut().links.insert(pid);
    }
    let pid_term = pid.to_term().ok_or_else(|| badarg("spawn/1"))?;
    if let Some(id) = monitor_id {
        parent.cold_mut().monitors.insert(id, pid);
        if let Some(tag) = monitor_tag {
            parent.cold_mut().monitor_tags.insert(id, tag);
        }
        if monitor_alias {
            parent.cold_mut().aliases.insert(id);
            rt.alias_bind(id, Some(ctx.pid()));
        }
        ctx.schedule_spawn(pid)
            .map_err(|error| VmError::Unsupported(format!("schedule spawn: {error}")))?;
        let reference = reference(parent, id)?;
        let mut heap = arinsal_bifs::FragmentingHeap(&mut parent.heap);
        return TermBuilder::new(&mut heap)
            .tuple(&[pid_term, reference])
            .map_err(|error| VmError::Unsupported(format!("spawn result: {error:?}")));
    }
    ctx.schedule_spawn(pid)
        .map_err(|error| VmError::Unsupported(format!("schedule spawn: {error}")))?;
    Ok(pid_term)
}

struct SpawnOpts {
    link: bool,
    monitor: bool,
    monitor_tag: Option<arinsal_etf::OwnedTerm>,
    monitor_alias: bool,
    min_heap_size: Option<usize>,
    scheduler: Option<usize>,
}

fn spawn_options(term: Term) -> Result<SpawnOpts, VmError> {
    let mut opts = SpawnOpts {
        link: false,
        monitor: false,
        monitor_tag: None,
        monitor_alias: false,
        min_heap_size: None,
        scheduler: None,
    };
    for option in list(term).ok_or_else(|| badarg("erlang:spawn_opt"))? {
        if option == atom("link") {
            opts.link = true;
        } else if option == atom("monitor") {
            opts.monitor = true;
        } else if option.classify() == TermKind::Tuple {
            // SAFETY: The option term remains in the caller's live heap.
            let tuple = unsafe { option.tuple_ref() }.ok_or_else(|| badarg("erlang:spawn_opt"))?;
            if tuple.len() == 2 && tuple.get(0) == Some(atom("min_heap_size")) {
                let words = tuple
                    .get(1)
                    .and_then(Term::as_small)
                    .filter(|&words| words >= 0)
                    .ok_or_else(|| badarg("erlang:spawn_opt"))?;
                opts.min_heap_size = Some(words as usize);
            } else if tuple.len() == 2 && tuple.get(0) == Some(atom("monitor")) {
                // code_server:spawn_opt(Fun, [{monitor, [{tag, {'ON_LOAD_DOWN', Mod}}]}]).
                // Port of erl_process.c spawn option `{monitor, MonitorOpts}`, OTP-29.1.1.
                opts.monitor = true;
                let items = list(tuple.get(1).ok_or_else(|| badarg("erlang:spawn_opt"))?)
                    .ok_or_else(|| badarg("erlang:spawn_opt"))?;
                for item in items {
                    // SAFETY: Each option stays rooted in the caller's heap.
                    let item =
                        unsafe { item.tuple_ref() }.ok_or_else(|| badarg("erlang:spawn_opt"))?;
                    if item.len() != 2 {
                        return Err(badarg("erlang:spawn_opt"));
                    }
                    match (item.get(0), item.get(1)) {
                        (Some(key), Some(value)) if key == atom("tag") => {
                            opts.monitor_tag =
                                Some(arinsal_term::to_owned(value).map_err(|error| {
                                    VmError::Unsupported(format!("monitor tag: {error:?}"))
                                })?);
                        }
                        (Some(key), Some(value))
                            if key == atom("alias")
                                && atom_name(value).is_some_and(|name| {
                                    matches!(
                                        name.as_str(),
                                        "explicit_unalias" | "demonitor" | "reply_demonitor"
                                    )
                                }) =>
                        {
                            opts.monitor_alias = true;
                        }
                        _ => return Err(badarg("erlang:spawn_opt")),
                    }
                }
            } else if tuple.len() == 2
                && tuple.get(0).and_then(atom_name).is_some_and(|name| {
                    matches!(
                        name.as_str(),
                        "min_bin_vheap_size"
                            | "max_heap_size"
                            | "fullsweep_after"
                            | "priority"
                            | "message_queue_data"
                            | "async_dist"
                    )
                })
            {
                // Accepted process tuning options. Their effects need scheduler
                // and heap controls outside this task's frozen interfaces.
            } else if tuple.len() == 2 && tuple.get(0) == Some(atom("scheduler")) {
                let scheduler = tuple
                    .get(1)
                    .and_then(Term::as_small)
                    .filter(|&scheduler| scheduler >= 1)
                    .ok_or_else(|| badarg("erlang:spawn_opt"))?;
                opts.scheduler = Some(scheduler as usize);
            } else {
                return Err(badarg("erlang:spawn_opt"));
            }
        } else {
            return Err(badarg("erlang:spawn_opt"));
        }
    }
    Ok(opts)
}

fn timer_start_options(term: Term) -> Result<(), VmError> {
    for option in list(term).ok_or_else(|| badarg("timer options"))? {
        // SAFETY: The option term remains in the caller's live heap.
        let tuple = unsafe { option.tuple_ref() }.ok_or_else(|| badarg("timer options"))?;
        if tuple.len() != 2 || tuple.get(0) != Some(atom("abs")) {
            return Err(badarg("timer options"));
        }
        match tuple.get(1) {
            Some(value) if value == atom("false") => {}
            Some(value) if value == atom("true") => {
                return Err(VmError::Unsupported("absolute timers".into()));
            }
            _ => return Err(badarg("timer options")),
        }
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct TimerQueryOptions {
    asynchronous: bool,
    info: bool,
}

fn timer_query_options(term: Term, cancel: bool) -> Result<TimerQueryOptions, VmError> {
    let mut asynchronous = false;
    let mut info = true;
    for option in list(term).ok_or_else(|| badarg("timer options"))? {
        // SAFETY: The option term remains in the caller's live heap.
        let tuple = unsafe { option.tuple_ref() }.ok_or_else(|| badarg("timer options"))?;
        if tuple.len() != 2 {
            return Err(badarg("timer options"));
        }
        match (tuple.get(0), tuple.get(1)) {
            (Some(name), Some(value)) if name == atom("async") && value == atom("false") => {
                asynchronous = false;
            }
            (Some(name), Some(value)) if name == atom("async") && value == atom("true") => {
                asynchronous = true;
            }
            (Some(name), Some(value)) if cancel && name == atom("info") => {
                if value == atom("false") {
                    info = false;
                } else if value == atom("true") {
                    info = true;
                } else {
                    return Err(badarg("timer options"));
                }
            }
            _ => return Err(badarg("timer options")),
        }
    }
    Ok(TimerQueryOptions { asynchronous, info })
}

// Port of erts/emulator/beam/erl_hl_timer.c:2222 (no_timer_result), OTP-29.1.1.
fn timer_query_result(
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    reference: Term,
    remaining: Option<u64>,
    cancel: bool,
    options: TimerQueryOptions,
) -> Result<Term, VmError> {
    let value = remaining
        .and_then(|ms| Term::small(ms as i64))
        .unwrap_or_else(|| atom("false"));
    if !options.asynchronous {
        return Ok(if options.info { value } else { atom("ok") });
    }
    if options.info {
        let mut heap = arinsal_bifs::FragmentingHeap(&mut process.heap);
        let message = TermBuilder::new(&mut heap)
            .tuple(&[
                atom(if cancel { "cancel_timer" } else { "read_timer" }),
                reference,
                value,
            ])
            .map_err(|error| VmError::Unsupported(format!("timer reply allocation: {error:?}")))?;
        let envelope = Message::copy_from(message)?;
        ctx.send(ctx.pid(), envelope)
            .map_err(|error| VmError::Unsupported(format!("timer reply: {error}")))?;
    }
    Ok(atom("ok"))
}

fn system_process(vm: &Vm, process: &Process, pid: Pid, names: &[&str]) -> bool {
    let registered = process.runtime.as_ref().is_some_and(|runtime| {
        let table = runtime.names.lock().unwrap();
        names
            .iter()
            .any(|name| table.get(*name).copied() == Some(pid))
    });
    if registered {
        return true;
    }
    vm.modules
        .get(process.module)
        .is_some_and(|module| names.iter().any(|name| module.name == *name))
}

// Port of erts/emulator/beam/erl_proc_sig_queue.c:8893
// (erts_internal_dirty_process_handle_signals_1), OTP-29.1.1.
// This VM has no dirty schedulers, so a live process is `normal` and handles
// its own signals. Only the dirty signal-handler processes may call the BIF.
fn dirty_process_handle_signals(
    vm: &Vm,
    process: &Process,
    ctx: &mut RunCtx<'_, Message>,
    target: Term,
) -> Result<Term, VmError> {
    if !system_process(
        vm,
        process,
        ctx.pid(),
        &[
            "erts_dirty_process_signal_handler",
            "erts_dirty_process_signal_handler_high",
            "erts_dirty_process_signal_handler_max",
        ],
    ) {
        return Err(VmError::Trap(crate::exceptions::Trap::error(atom(
            "notsup",
        ))));
    }
    let Some(pid) = Pid::from_term(target) else {
        return Ok(atom("false"));
    };
    if !crate::natives::proc::live(process, pid)? {
        return Ok(atom("noproc"));
    }
    Ok(atom("normal"))
}

fn deliver(
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    to: Pid,
    message: Term,
) -> Result<(), VmError> {
    if to == ctx.pid() {
        process.inbox.push_back(message);
        return Ok(());
    }
    if !crate::natives::proc::live(process, to)? {
        return Ok(());
    }
    ctx.send(to, Message::copy_from(message)?)
        .map_err(|error| VmError::Unsupported(format!("system task reply: {error}")))?;
    Ok(())
}

fn task_tuple(process: &mut Process, values: &[Term]) -> Result<Term, VmError> {
    let mut heap = arinsal_bifs::FragmentingHeap(&mut process.heap);
    TermBuilder::new(&mut heap)
        .tuple(values)
        .map_err(|error| VmError::Unsupported(format!("system task tuple: {error:?}")))
}

// Port of erts/emulator/beam/erl_process.c:11309 (request_system_task), OTP-29.1.1.
// `copy_literals` is not a request type here; the literal-area collector sends
// that work through `send_copy_request/3`.
fn request_system_task(
    vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    args: &[Term],
) -> Result<Term, VmError> {
    let (requester, target, priority, operation) = if args.len() == 3 {
        (ctx.pid(), args[0], args[1], args[2])
    } else {
        let requester = Pid::from_term(args[0]).ok_or_else(|| badarg("request_system_task"))?;
        (requester, args[1], args[2], args[3])
    };
    let priority_name = atom_name(priority).ok_or_else(|| badarg("request_system_task"))?;
    if !matches!(
        priority_name.as_str(),
        "max" | "high" | "normal" | "low" | "inherit"
    ) {
        return Err(badarg("request_system_task"));
    }
    let Some(target_pid) = Pid::from_term(target) else {
        return Err(badarg("request_system_task"));
    };
    // SAFETY: The operation tuple stays rooted in the caller heap.
    let tuple = unsafe { operation.tuple_ref() }.ok_or_else(|| badarg("request_system_task"))?;
    if !(2..=4).contains(&tuple.len()) {
        return Err(badarg("request_system_task"));
    }
    let req_type = tuple.get(0).ok_or_else(|| badarg("request_system_task"))?;
    let mut req_id = tuple.get(1).ok_or_else(|| badarg("request_system_task"))?;
    let arg0 = tuple.get(2);
    let type_name = atom_name(req_type).ok_or_else(|| badarg("request_system_task"))?;
    let alive = crate::natives::proc::live(process, target_pid)?;
    let (tag, result) = match type_name.as_str() {
        "garbage_collect" => {
            let major = match arg0.and_then(atom_name).as_deref() {
                Some("major") => true,
                Some("minor") => false,
                _ => return Err(badarg("request_system_task")),
            };
            if alive && target_pid == ctx.pid() {
                let mut rooted = [req_id];
                crate::natives::proc::collect_heap(process, major, &mut rooted)?;
                req_id = rooted[0];
                ("garbage_collect", true)
            } else if alive {
                let copied = Message::copy_from(req_id)?;
                match submit(
                    process,
                    ctx,
                    target_pid,
                    RemoteOp::Collect {
                        request_id: copied,
                        major,
                    },
                    None,
                )? {
                    Submit::Sent(_) => return Ok(atom("ok")),
                    Submit::Dead => ("garbage_collect", false),
                }
            } else {
                ("garbage_collect", false)
            }
        }
        "check_process_code" => {
            let module = arg0
                .and_then(atom_name)
                .ok_or_else(|| badarg("request_system_task"))?;
            vm.sync_code_epoch();
            let request = Message::copy_from(req_id)?;
            if alive && let Some(&old) = vm.old.get(&module) {
                let op = RemoteOp::CheckProcessCode {
                    module: old,
                    async_request: Some(request),
                    kill: false,
                };
                if matches!(submit(process, ctx, target_pid, op, None)?, Submit::Sent(_)) {
                    return Ok(atom("ok"));
                }
            }
            let message = task_tuple(
                process,
                &[atom("check_process_code"), req_id, atom("false")],
            )?;
            deliver(process, ctx, requester, message)?;
            return Ok(atom("ok"));
        }
        "system_task_test" => {
            if !alive {
                ("system_task_test", false)
            } else {
                ("system_task_test", true)
            }
        }
        _ => return Err(badarg("request_system_task")),
    };
    let message = task_tuple(
        process,
        &[
            atom(tag),
            req_id,
            atom(if result { "true" } else { "false" }),
        ],
    )?;
    deliver(process, ctx, requester, message)?;
    Ok(atom("ok"))
}

/// Process BIFs resolved before the process-independent BIF table.
///
/// [`call`] admits every `erlang` function name in this table at any arity.
/// `erts_internal:spawn_system_process/3` is `spawn/3` for system processes.
pub(crate) const IMPLEMENTED: &[(&str, &str, u8)] = &[
    ("erlang", "self", 0),
    ("erlang", "!", 2),
    ("erlang", "send", 2),
    ("erlang", "send", 3),
    ("erlang", "spawn", 3),
    ("erlang", "spawn_link", 3),
    ("erlang", "spawn_opt", 4),
    ("erlang", "is_process_alive", 1),
    ("erlang", "register", 2),
    ("erlang", "unregister", 1),
    ("erlang", "whereis", 1),
    ("erlang", "registered", 0),
    ("erlang", "link", 1),
    ("erlang", "link", 2),
    ("erlang", "unlink", 1),
    ("erlang", "monitor", 2),
    ("erlang", "monitor", 3),
    ("erlang", "demonitor", 1),
    ("erlang", "demonitor", 2),
    ("erlang", "exit", 1),
    ("erlang", "exit", 2),
    ("erlang", "exit", 3),
    ("erlang", "exit_signal", 2),
    ("erlang", "exit_signal", 3),
    ("erlang", "trace_delivered", 1),
    ("erlang", "send_after", 3),
    ("erlang", "send_after", 4),
    ("erlang", "start_timer", 3),
    ("erlang", "start_timer", 4),
    ("erlang", "cancel_timer", 1),
    ("erlang", "cancel_timer", 2),
    ("erlang", "read_timer", 1),
    ("erlang", "read_timer", 2),
    ("erts_internal", "spawn_system_process", 3),
    ("erts_internal", "dirty_process_handle_signals", 1),
    ("erts_internal", "is_process_alive", 2),
    ("erts_internal", "is_process_executing_dirty", 1),
    ("erts_internal", "request_system_task", 3),
    ("erts_internal", "request_system_task", 4),
    ("erts_trace_cleaner", "check", 0),
    ("erts_trace_cleaner", "send_trace_clean_signal", 1),
];

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn recognizes(module: &str, function: &str, arity: u8) -> bool {
    IMPLEMENTED
        .iter()
        .any(|&(item_module, item_function, item_arity)| {
            item_module == module && item_function == function && item_arity == arity
        })
}

/// Direct load-time entry for `self/0`.
pub(crate) fn native_self(
    _vm: &mut Vm,
    _process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    _args: &[Term],
) -> Result<Term, VmError> {
    ctx.pid().to_term().ok_or_else(|| badarg("self/0"))
}

/// Direct load-time entry for `send/2`.
pub(crate) fn native_send(
    vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    args: &[Term],
) -> Result<Term, VmError> {
    process.send_message_with_vm(vm, ctx, args[0], args[1])
}

/// Direct load-time entry for `send/3`.
pub(crate) fn native_send3(
    vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    args: &[Term],
) -> Result<Term, VmError> {
    let options = list(args[2]).ok_or_else(|| badarg("erlang:send/3"))?;
    let mut want_priority = false;
    for option in &options {
        if *option == atom("priority") {
            want_priority = true;
        } else if *option != atom("nosuspend") && *option != atom("noconnect") {
            return Err(badarg("erlang:send/3"));
        }
    }
    process.send_message_prio(Some(vm), ctx, args[0], args[1], want_priority)?;
    Ok(atom("ok"))
}

/// Direct load-time entry for `is_process_alive/1`.
pub(crate) fn native_is_process_alive(
    _vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    args: &[Term],
) -> Result<Term, VmError> {
    is_process_alive(process, ctx, args[0])
}

#[derive(Clone, Copy)]
enum SignalBif {
    Spawn1,
    Spawn2,
    Spawn3,
    Spawn4,
    SpawnLink1,
    SpawnLink2,
    SpawnLink3,
    SpawnLink4,
    SpawnMonitor1,
    SpawnMonitor2,
    SpawnMonitor3,
    SpawnMonitor4,
    SpawnOpt2,
    SpawnOpt3,
    SpawnOpt4,
    SpawnOpt5,
    Register2,
    Unregister1,
    Whereis1,
    Registered0,
    Link1,
    Link2,
    Unlink1,
    Monitor2,
    Monitor3,
    Demonitor1,
    Demonitor2,
    Exit1,
    Exit2,
    Exit3,
    ExitSignal2,
    ExitSignal3,
    TraceDelivered1,
    SendAfter3,
    SendAfter4,
    StartTimer3,
    StartTimer4,
    CancelTimer1,
    CancelTimer2,
    ReadTimer1,
    ReadTimer2,
    SpawnSystemProcess3,
    DirtyProcessHandleSignals1,
    IsProcessAlive2,
    IsProcessExecutingDirty1,
    RequestSystemTask3,
    RequestSystemTask4,
    TraceCleanerCheck0,
    TraceCleanerSend1,
}

macro_rules! resolved_signal_handler {
    ($name:ident, $entry:ident) => {
        fn $name(
            vm: &mut Vm,
            process: &mut Process,
            ctx: &mut RunCtx<'_, Message>,
            args: crate::natives::NativeArgs<'_>,
        ) -> Option<Result<Term, VmError>> {
            Some(args.with_values(process, |process, args| {
                call_resolved(vm, process, ctx, SignalBif::$entry, args)
            }))
        }
    };
}

resolved_signal_handler!(spawn1, Spawn1);
resolved_signal_handler!(spawn2, Spawn2);
resolved_signal_handler!(spawn3, Spawn3);
resolved_signal_handler!(spawn4, Spawn4);
resolved_signal_handler!(spawn_link1, SpawnLink1);
resolved_signal_handler!(spawn_link2, SpawnLink2);
resolved_signal_handler!(spawn_link3, SpawnLink3);
resolved_signal_handler!(spawn_link4, SpawnLink4);
resolved_signal_handler!(spawn_monitor1, SpawnMonitor1);
resolved_signal_handler!(spawn_monitor2, SpawnMonitor2);
resolved_signal_handler!(spawn_monitor3, SpawnMonitor3);
resolved_signal_handler!(spawn_monitor4, SpawnMonitor4);
resolved_signal_handler!(spawn_opt2, SpawnOpt2);
resolved_signal_handler!(spawn_opt3, SpawnOpt3);
resolved_signal_handler!(spawn_opt4, SpawnOpt4);
resolved_signal_handler!(spawn_opt5, SpawnOpt5);
resolved_signal_handler!(register2, Register2);
resolved_signal_handler!(unregister1, Unregister1);
resolved_signal_handler!(whereis1, Whereis1);
resolved_signal_handler!(registered0, Registered0);
resolved_signal_handler!(link1, Link1);
resolved_signal_handler!(link2, Link2);
resolved_signal_handler!(unlink1, Unlink1);
resolved_signal_handler!(monitor2, Monitor2);
resolved_signal_handler!(monitor3, Monitor3);
resolved_signal_handler!(demonitor1, Demonitor1);
resolved_signal_handler!(demonitor2, Demonitor2);
resolved_signal_handler!(exit1, Exit1);
resolved_signal_handler!(exit2, Exit2);
resolved_signal_handler!(exit3, Exit3);
resolved_signal_handler!(exit_signal2, ExitSignal2);
resolved_signal_handler!(exit_signal3, ExitSignal3);
resolved_signal_handler!(trace_delivered1, TraceDelivered1);
resolved_signal_handler!(send_after3, SendAfter3);
resolved_signal_handler!(send_after4, SendAfter4);
resolved_signal_handler!(start_timer3, StartTimer3);
resolved_signal_handler!(start_timer4, StartTimer4);
resolved_signal_handler!(cancel_timer1, CancelTimer1);
resolved_signal_handler!(cancel_timer2, CancelTimer2);
resolved_signal_handler!(read_timer1, ReadTimer1);
resolved_signal_handler!(read_timer2, ReadTimer2);
resolved_signal_handler!(spawn_system_process3, SpawnSystemProcess3);
resolved_signal_handler!(dirty_process_handle_signals1, DirtyProcessHandleSignals1);
resolved_signal_handler!(is_process_alive2, IsProcessAlive2);
resolved_signal_handler!(is_process_executing_dirty1, IsProcessExecutingDirty1);
resolved_signal_handler!(request_system_task3, RequestSystemTask3);
resolved_signal_handler!(request_system_task4, RequestSystemTask4);
resolved_signal_handler!(trace_cleaner_check0, TraceCleanerCheck0);
resolved_signal_handler!(trace_cleaner_send1, TraceCleanerSend1);

pub(crate) fn handler(
    module: &str,
    function: &str,
    arity: u8,
) -> Option<crate::natives::ResolvedNative> {
    Some(match (module, function, arity) {
        ("erlang", "spawn", 1) => spawn1,
        ("erlang", "spawn", 2) => spawn2,
        ("erlang", "spawn", 3) => spawn3,
        ("erlang", "spawn", 4) => spawn4,
        ("erlang", "spawn_link", 1) => spawn_link1,
        ("erlang", "spawn_link", 2) => spawn_link2,
        ("erlang", "spawn_link", 3) => spawn_link3,
        ("erlang", "spawn_link", 4) => spawn_link4,
        ("erlang", "spawn_monitor", 1) => spawn_monitor1,
        ("erlang", "spawn_monitor", 2) => spawn_monitor2,
        ("erlang", "spawn_monitor", 3) => spawn_monitor3,
        ("erlang", "spawn_monitor", 4) => spawn_monitor4,
        ("erlang", "spawn_opt", 2) => spawn_opt2,
        ("erlang", "spawn_opt", 3) => spawn_opt3,
        ("erlang", "spawn_opt", 4) => spawn_opt4,
        ("erlang", "spawn_opt", 5) => spawn_opt5,
        ("erlang", "register", 2) => register2,
        ("erlang", "unregister", 1) => unregister1,
        ("erlang", "whereis", 1) => whereis1,
        ("erlang", "registered", 0) => registered0,
        ("erlang", "link", 1) => link1,
        ("erlang", "link", 2) => link2,
        ("erlang", "unlink", 1) => unlink1,
        ("erlang", "monitor", 2) => monitor2,
        ("erlang", "monitor", 3) => monitor3,
        ("erlang", "demonitor", 1) => demonitor1,
        ("erlang", "demonitor", 2) => demonitor2,
        ("erlang", "exit", 1) => exit1,
        ("erlang", "exit", 2) => exit2,
        ("erlang", "exit", 3) => exit3,
        ("erlang", "exit_signal", 2) => exit_signal2,
        ("erlang", "exit_signal", 3) => exit_signal3,
        ("erlang", "trace_delivered", 1) => trace_delivered1,
        ("erlang", "send_after", 3) => send_after3,
        ("erlang", "send_after", 4) => send_after4,
        ("erlang", "start_timer", 3) => start_timer3,
        ("erlang", "start_timer", 4) => start_timer4,
        ("erlang", "cancel_timer", 1) => cancel_timer1,
        ("erlang", "cancel_timer", 2) => cancel_timer2,
        ("erlang", "read_timer", 1) => read_timer1,
        ("erlang", "read_timer", 2) => read_timer2,
        ("erts_internal", "spawn_system_process", 3) => spawn_system_process3,
        ("erts_internal", "dirty_process_handle_signals", 1) => dirty_process_handle_signals1,
        ("erts_internal", "is_process_alive", 2) => is_process_alive2,
        ("erts_internal", "is_process_executing_dirty", 1) => is_process_executing_dirty1,
        ("erts_internal", "request_system_task", 3) => request_system_task3,
        ("erts_internal", "request_system_task", 4) => request_system_task4,
        ("erts_trace_cleaner", "check", 0) => trace_cleaner_check0,
        ("erts_trace_cleaner", "send_trace_clean_signal", 1) => trace_cleaner_send1,
        _ => return None,
    })
}

/// Resolve a process-aware BIF from the atom identities carried by apply/3.
/// The table is built once from the same load-time resolver used for imports.
pub(crate) fn handler_atoms(
    module: Atom,
    function: Atom,
    arity: u8,
) -> Option<crate::natives::NativeEntry> {
    static HANDLERS: OnceLock<HashMap<(Atom, Atom, u8), crate::natives::NativeEntry>> =
        OnceLock::new();
    let handlers = HANDLERS.get_or_init(|| {
        let mut handlers: HashMap<_, _> = IMPLEMENTED
            .iter()
            .filter_map(|&(module, function, arity)| {
                let module = global_atoms().intern(module).ok()?;
                let function = global_atoms().intern(function).ok()?;
                let entry = match (module, function, arity) {
                    (m, f, 0) if m == arinsal_term::atoms::ERLANG && f == atom_id("self")? => {
                        crate::natives::NativeEntry::Direct(native_self)
                    }
                    (m, f, 2) if m == arinsal_term::atoms::ERLANG && f == atom_id("send")? => {
                        crate::natives::NativeEntry::Direct(native_send)
                    }
                    (m, f, 3) if m == arinsal_term::atoms::ERLANG && f == atom_id("send")? => {
                        crate::natives::NativeEntry::Direct(native_send3)
                    }
                    (m, f, 1)
                        if m == arinsal_term::atoms::ERLANG
                            && f == atom_id("is_process_alive")? =>
                    {
                        crate::natives::NativeEntry::Direct(native_is_process_alive)
                    }
                    (m, f, 2) if m == arinsal_term::atoms::ERLANG && f == atom_id("!")? => {
                        crate::natives::NativeEntry::Direct(native_send)
                    }
                    (m, f, 2) if m == arinsal_term::atoms::ERLANG && f == atom_id("monitor")? => {
                        crate::natives::NativeEntry::Direct(crate::dist::native_monitor)
                    }
                    (m, f, 3) if m == arinsal_term::atoms::ERLANG && f == atom_id("monitor")? => {
                        crate::natives::NativeEntry::Direct(crate::dist::native_monitor)
                    }
                    (m, f, 1) if m == arinsal_term::atoms::ERLANG && f == atom_id("demonitor")? => {
                        crate::natives::NativeEntry::Direct(crate::dist::native_demonitor)
                    }
                    (m, f, 2) if m == arinsal_term::atoms::ERLANG && f == atom_id("demonitor")? => {
                        crate::natives::NativeEntry::Direct(crate::dist::native_demonitor)
                    }
                    _ => crate::natives::NativeEntry::Resolved(handler(
                        global_atoms().text(module)?.as_ref(),
                        global_atoms().text(function)?.as_ref(),
                        arity,
                    )?),
                };
                Some(((module, function, arity), entry))
            })
            .collect();
        if let (Some(module), Some(function)) = (atom_id("erlang"), atom_id("!")) {
            handlers.insert(
                (module, function, 2),
                crate::natives::NativeEntry::Direct(native_send),
            );
        }
        if let Some(module) = atom_id("erlang") {
            for (function, arity, entry) in [
                (
                    "atom_to_list",
                    1,
                    crate::natives::dynamic_atom_to_list as crate::natives::ResolvedNative,
                ),
                (
                    "list_to_atom",
                    1,
                    crate::natives::dynamic_list_to_atom as crate::natives::ResolvedNative,
                ),
                (
                    "++",
                    2,
                    crate::natives::dynamic_append as crate::natives::ResolvedNative,
                ),
            ] {
                if let Some(function) = atom_id(function) {
                    handlers.insert(
                        (module, function, arity),
                        crate::natives::NativeEntry::Resolved(entry),
                    );
                }
            }
        }
        handlers
    });
    handlers.get(&(module, function, arity)).copied()
}

fn atom_id(name: &str) -> Option<Atom> {
    global_atoms().intern(name).ok()
}

/// Resolve a process BIF before the process-independent BIF table.
pub(crate) fn call(
    _vm: &mut Vm,
    _process: &mut Process,
    _ctx: &mut RunCtx<'_, Message>,
    _module: &str,
    _function: &str,
    _args: &[Term],
) -> Option<Result<Term, VmError>> {
    None
}

fn call_resolved(
    vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    entry: SignalBif,
    args: &[Term],
) -> Result<Term, VmError> {
    match (entry, args) {
        (SignalBif::Spawn1, [fun]) => spawn_fun(
            vm, process, ctx, *fun, false, false, None, None, false, None,
        ),
        (SignalBif::Spawn2, [node, fun]) => local_node(*node).and_then(|()| {
            spawn_fun(
                vm, process, ctx, *fun, false, false, None, None, false, None,
            )
        }),
        (SignalBif::SpawnLink1, [fun]) => {
            spawn_fun(vm, process, ctx, *fun, true, false, None, None, false, None)
        }
        (SignalBif::SpawnLink2, [node, fun]) => local_node(*node)
            .and_then(|()| spawn_fun(vm, process, ctx, *fun, true, false, None, None, false, None)),
        (SignalBif::SpawnMonitor1, [fun]) => {
            spawn_fun(vm, process, ctx, *fun, false, true, None, None, false, None)
        }
        (SignalBif::SpawnMonitor2, [node, fun]) => local_node(*node)
            .and_then(|()| spawn_fun(vm, process, ctx, *fun, false, true, None, None, false, None)),
        (SignalBif::SpawnOpt2, [fun, options]) => spawn_options(*options).and_then(|opts| {
            spawn_fun(
                vm,
                process,
                ctx,
                *fun,
                opts.link,
                opts.monitor,
                opts.min_heap_size,
                opts.monitor_tag,
                opts.monitor_alias,
                opts.scheduler,
            )
        }),
        (SignalBif::Spawn3, [module, function, args]) => spawn_mfa(
            vm,
            process,
            ctx,
            (*module, *function, *args),
            false,
            false,
            None,
            None,
            false,
            None,
        ),
        (SignalBif::Spawn4, [node, module, function, args]) => local_node(*node).and_then(|()| {
            spawn_mfa(
                vm,
                process,
                ctx,
                (*module, *function, *args),
                false,
                false,
                None,
                None,
                false,
                None,
            )
        }),
        (SignalBif::SpawnLink3, [module, function, args]) => spawn_mfa(
            vm,
            process,
            ctx,
            (*module, *function, *args),
            true,
            false,
            None,
            None,
            false,
            None,
        ),
        (SignalBif::SpawnLink4, [node, module, function, args]) => {
            local_node(*node).and_then(|()| {
                spawn_mfa(
                    vm,
                    process,
                    ctx,
                    (*module, *function, *args),
                    true,
                    false,
                    None,
                    None,
                    false,
                    None,
                )
            })
        }
        (SignalBif::SpawnMonitor3, [module, function, args]) => spawn_mfa(
            vm,
            process,
            ctx,
            (*module, *function, *args),
            false,
            true,
            None,
            None,
            false,
            None,
        ),
        (SignalBif::SpawnMonitor4, [node, module, function, args]) => {
            local_node(*node).and_then(|()| {
                spawn_mfa(
                    vm,
                    process,
                    ctx,
                    (*module, *function, *args),
                    false,
                    true,
                    None,
                    None,
                    false,
                    None,
                )
            })
        }
        (SignalBif::SpawnOpt4, [module, function, args, options]) => spawn_options(*options)
            .and_then(|opts| {
                spawn_mfa(
                    vm,
                    process,
                    ctx,
                    (*module, *function, *args),
                    opts.link,
                    opts.monitor,
                    opts.min_heap_size,
                    opts.monitor_tag,
                    opts.monitor_alias,
                    opts.scheduler,
                )
            }),
        (SignalBif::SpawnOpt3, [node, fun, options]) => local_node(*node).and_then(|()| {
            spawn_options(*options).and_then(|opts| {
                spawn_fun(
                    vm,
                    process,
                    ctx,
                    *fun,
                    opts.link,
                    opts.monitor,
                    opts.min_heap_size,
                    opts.monitor_tag,
                    opts.monitor_alias,
                    opts.scheduler,
                )
            })
        }),
        (SignalBif::SpawnOpt5, [node, module, function, args, options]) => local_node(*node)
            .and_then(|()| {
                spawn_options(*options).and_then(|opts| {
                    spawn_mfa(
                        vm,
                        process,
                        ctx,
                        (*module, *function, *args),
                        opts.link,
                        opts.monitor,
                        opts.min_heap_size,
                        opts.monitor_tag,
                        opts.monitor_alias,
                        opts.scheduler,
                    )
                })
            }),
        (SignalBif::Register2, [name, pid]) => {
            let name = atom_name(*name).ok_or_else(|| badarg("register/2"));
            let pid = Pid::from_term(*pid).ok_or_else(|| badarg("register/2"));
            name.and_then(|name| {
                let pid = pid?;
                let rt = runtime(process)?;
                if !rt.scheduler()?.lookup(pid) {
                    return Err(badarg("register/2"));
                }
                let mut names = rt.names.lock().unwrap();
                if names.get(&name).is_some_and(|existing| {
                    rt.scheduler()
                        .is_ok_and(|scheduler| scheduler.lookup(*existing))
                }) {
                    return Err(badarg("register/2"));
                }
                names.insert(name.clone(), pid);
                drop(names);
                crate::trace::emit(
                    Some(vm),
                    process,
                    ctx,
                    ctx.pid(),
                    crate::trace::PROCS,
                    "register",
                    &[atom(&name)],
                );
                Ok(atom("true"))
            })
        }
        (SignalBif::Unregister1, [name]) => {
            let name = atom_name(*name).ok_or_else(|| badarg("unregister/1"));
            name.and_then(|name| {
                let removed = runtime(process)?.names.lock().unwrap().remove(&name);
                removed.ok_or_else(|| badarg("unregister/1"))?;
                crate::trace::emit(
                    Some(vm),
                    process,
                    ctx,
                    ctx.pid(),
                    crate::trace::PROCS,
                    "unregister",
                    &[atom(&name)],
                );
                Ok(atom("true"))
            })
        }
        (SignalBif::Whereis1, [name]) => {
            let name = atom_name(*name).ok_or_else(|| badarg("whereis/1"));
            name.and_then(|name| {
                let rt = runtime(process)?;
                let mut names = rt.names.lock().unwrap();
                let pid = names.get(&name).copied();
                if let Some(pid) = pid
                    && rt.scheduler()?.lookup(pid)
                {
                    Ok(pid.to_term().unwrap_or_else(|| atom("undefined")))
                } else {
                    names.remove(&name);
                    Ok(atom("undefined"))
                }
            })
        }
        (SignalBif::Registered0, []) => {
            let rt = runtime(process)?;
            let names: Vec<_> = rt
                .names
                .lock()
                .unwrap()
                .iter()
                .filter(|(_, pid)| {
                    rt.scheduler()
                        .is_ok_and(|scheduler| scheduler.lookup(**pid))
                })
                .map(|(name, _)| atom(name))
                .collect();
            let mut heap = arinsal_bifs::FragmentingHeap(&mut process.heap);
            TermBuilder::new(&mut heap)
                .list_from_iter(names)
                .map_err(|error| VmError::Unsupported(format!("registered list: {error:?}")))
        }
        (SignalBif::Link1, [target]) => link_opt(vm, process, ctx, *target, Term::NIL),
        (SignalBif::Link2, [target, opts]) => link_opt(vm, process, ctx, *target, *opts),
        (SignalBif::Unlink1, [port]) if port.as_port().is_some() => {
            crate::port::link(process, *port, ctx.pid(), false)?;
            Ok(atom("true"))
        }
        (SignalBif::Unlink1, [pid]) => {
            let pid = Pid::from_term(*pid).ok_or_else(|| badarg("unlink/1"));
            pid.map(|pid| {
                if let Some(cold) = process.cold.as_mut() {
                    cold.links.remove(&pid);
                    cold.prio_links.remove(&pid);
                }
                if let Some(pid_term) = pid.to_term() {
                    crate::trace::emit(
                        Some(vm),
                        process,
                        ctx,
                        ctx.pid(),
                        crate::trace::PROCS,
                        "unlink",
                        &[pid_term],
                    );
                }
                let _ = ctx.signal(pid, Signal::Unlink(0));
                atom("true")
            })
        }
        (SignalBif::Monitor2, [kind, target]) | (SignalBif::Monitor3, [kind, target, _])
            if *kind == atom("process") =>
        {
            let options = if args.len() == 3 {
                list(args[2]).ok_or_else(|| badarg("monitor/3"))?
            } else {
                Vec::new()
            };
            let mut tag = atom("DOWN");
            let mut alias = false;
            let mut priority = false;
            for option in options {
                if option == atom("priority") {
                    priority = true;
                    continue;
                }
                // SAFETY: Each option is rooted in the caller's heap.
                let tuple = unsafe { option.tuple_ref() }.ok_or_else(|| badarg("monitor/3"))?;
                if tuple.len() != 2 {
                    return Err(badarg("monitor/3"));
                }
                match (tuple.get(0), tuple.get(1)) {
                    (Some(key), Some(value)) if key == atom("tag") => tag = value,
                    (Some(key), Some(value))
                        if key == atom("alias")
                            && ["explicit_unalias", "demonitor", "reply_demonitor"]
                                .iter()
                                .any(|name| value == atom(name)) =>
                    {
                        alias = true
                    }
                    _ => return Err(badarg("monitor/3")),
                }
            }
            let rt = process.runtime.clone().ok_or_else(|| badarg("monitor/2"))?;
            // boot_loop1: code_server:call/1 monitors its registered name.
            let name = atom_name(*target);
            let pid = if let Some(pid) = Pid::from_term(*target) {
                Some(pid)
            } else if let Some(name) = name.as_ref() {
                rt.names.lock().unwrap().get(name).copied()
            } else {
                return Err(badarg("monitor/2"));
            };
            let id = rt.next_ref();
            let ref_term = reference(process, id)?;
            // The default `DOWN` tag is implied. Owning it allocates on every
            // `gen_server:call` monitor.
            if tag != atom("DOWN") {
                let owned = arinsal_term::to_owned(tag)
                    .map_err(|error| VmError::Unsupported(format!("monitor tag: {error:?}")))?;
                process.cold_mut().monitor_tags.insert(id, owned);
            }
            if alias {
                process.cold_mut().aliases.insert(id);
                // Monitor aliases with `priority` are priority aliases.
                rt.alias_bind_prio(id, Some(ctx.pid()), priority);
            }
            if priority {
                process.cold_mut().prio_monitors.insert(id);
            }
            if let Some(pid) = pid.filter(|pid| rt.scheduler().is_ok_and(|s| s.lookup(*pid))) {
                process.cold_mut().monitors.insert(id, pid);
                if let Err(error) = ctx.signal(pid, Signal::Monitor(id)) {
                    process.cold_mut().monitors.remove(&id);
                    process.cold_mut().monitor_tags.remove(&id);
                    if error != arinsal_sched::Error::NoProcess {
                        return Err(VmError::Unsupported(format!("monitor: {error}")));
                    }
                    // The target stopped accepting monitor signals before this request.
                    let reason = atom("noproc");
                    let mut heap = arinsal_bifs::FragmentingHeap(&mut process.heap);
                    let down = TermBuilder::new(&mut heap)
                        .tuple(&[tag, ref_term, atom("process"), *target, reason])
                        .map_err(|error| VmError::Unsupported(format!("DOWN tuple: {error:?}")))?;
                    process.inbox.push_back(down);
                }
            } else {
                let mut heap = arinsal_bifs::FragmentingHeap(&mut process.heap);
                let object = if let Some(name) = name {
                    TermBuilder::new(&mut heap)
                        .tuple(&[atom(&name), atom("nonode@nohost")])
                        .map_err(|error| {
                            VmError::Unsupported(format!("monitor object: {error:?}"))
                        })?
                } else {
                    *target
                };
                let down = TermBuilder::new(&mut heap)
                    .tuple(&[tag, ref_term, atom("process"), object, atom("noproc")])
                    .map_err(|error| VmError::Unsupported(format!("DOWN tuple: {error:?}")))?;
                process.inbox.push_back(down);
            }
            Ok(ref_term)
        }
        (SignalBif::Monitor2, [kind, target]) if *kind == atom("port") => {
            let id = target.as_port().ok_or_else(|| badarg("monitor/2"))?;
            let runtime = process.runtime.clone().ok_or_else(|| badarg("monitor/2"))?;
            let reference_id = runtime.next_ref();
            let reference_term = reference(process, reference_id)?;
            if runtime.ports.lock().unwrap().contains_key(&id) {
                crate::port::monitor(process, *target, reference_id, ctx.pid(), true)?;
                Ok(reference_term)
            } else {
                let mut heap = arinsal_bifs::FragmentingHeap(&mut process.heap);
                let down = TermBuilder::new(&mut heap)
                    .tuple(&[
                        atom("DOWN"),
                        reference_term,
                        atom("port"),
                        *target,
                        atom("noproc"),
                    ])
                    .map_err(|error| VmError::Unsupported(format!("port DOWN tuple: {error:?}")))?;
                process.inbox.push_back(down);
                Ok(reference_term)
            }
        }
        (SignalBif::Demonitor1, [reference]) | (SignalBif::Demonitor2, [reference, _]) => {
            let id = ref_id(*reference).ok_or_else(|| badarg("demonitor/1"))?;
            let options = if args.len() == 2 {
                list(args[1]).ok_or_else(|| badarg("demonitor/2"))?
            } else {
                Vec::new()
            };
            if options
                .iter()
                .any(|option| *option != atom("flush") && *option != atom("info"))
            {
                return Err(badarg("demonitor/2"));
            }
            let flush = options.contains(&atom("flush"));
            let mut was_active = if let Some(pid) = process
                .cold
                .as_mut()
                .and_then(|cold| cold.monitors.remove(&id))
            {
                if !flush || !ctx.cancel_pending_monitor(pid, id) {
                    let _ = ctx.signal(pid, Signal::Demonitor(id));
                }
                true
            } else {
                false
            };
            let alias_active = process
                .cold
                .as_mut()
                .is_some_and(|cold| cold.aliases.remove(&id));
            if alias_active && let Some(runtime) = &process.runtime {
                runtime.alias_bind(id, None);
            }
            was_active |= crate::port::demonitor(process, id);
            if flush {
                process.drain(ctx)?;
                let old_prio_len = process.cold.as_ref().map_or(0, |cold| cold.prio_len);
                let new_prio_len = process.inbox.retain(old_prio_len, |message| {
                    // SAFETY: Mailbox terms remain in the receiver's live heap.
                    unsafe { message.tuple_ref() }.is_none_or(|tuple| {
                        tuple.len() != 5
                            || tuple.get(0) != Some(atom("DOWN"))
                            || tuple.get(1).and_then(ref_id) != Some(id)
                    })
                });
                process.cold_mut().prio_len = new_prio_len;
            }
            Ok(atom(if options.contains(&atom("info")) && !was_active {
                "false"
            } else {
                "true"
            }))
        }
        (SignalBif::Exit1, [reason]) => {
            process.note_exit_reason(*reason)?;
            Err(VmError::Trap(crate::exceptions::Trap::exit(*reason)))
        }
        (SignalBif::Exit2, [target, reason]) => {
            send_exit_signal_bif(process, ctx, *target, *reason, Term::NIL, true)
        }
        (SignalBif::Exit3, [target, reason, opts]) => {
            send_exit_signal_bif(process, ctx, *target, *reason, *opts, true)
        }
        (SignalBif::ExitSignal2, [target, reason]) => {
            send_exit_signal_bif(process, ctx, *target, *reason, Term::NIL, false)
        }
        (SignalBif::ExitSignal3, [target, reason, opts]) => {
            send_exit_signal_bif(process, ctx, *target, *reason, *opts, false)
        }
        (SignalBif::TraceDelivered1, [target]) => trace_delivered(process, ctx, *target),
        (SignalBif::IsProcessAlive2, [pid, reference]) => {
            is_process_alive_2(process, ctx, *pid, *reference)
        }
        (SignalBif::IsProcessExecutingDirty1, [pid]) => is_process_executing_dirty(*pid),
        (SignalBif::TraceCleanerCheck0, []) => Ok(atom("false")),
        (SignalBif::TraceCleanerSend1, [to]) => trace_cleaner_send(process, ctx, *to),
        (SignalBif::SendAfter3, [time, target, message])
        | (SignalBif::SendAfter4, [time, target, message, _])
        | (SignalBif::StartTimer3, [time, target, message])
        | (SignalBif::StartTimer4, [time, target, message, _]) => {
            if let Some(options) = args.get(3) {
                timer_start_options(*options)?;
            }
            let ms = time
                .as_small()
                .filter(|&time| time >= 0)
                .ok_or_else(|| badarg("timer/3"))? as u64;
            let pid = Pid::from_term(*target).ok_or_else(|| badarg("timer/3"))?;
            let rt = process.runtime.clone().ok_or_else(|| badarg("timer/3"))?;
            let id = rt.next_ref();
            let message = Message::copy_from(*message)?;
            let scheduler = rt.scheduler()?;
            let timer = if matches!(entry, SignalBif::SendAfter3 | SignalBif::SendAfter4) {
                scheduler.send_after(pid, ms, message)
            } else {
                scheduler.start_timer(pid, ms, message)
            }
            .map_err(|error| VmError::Unsupported(format!("timer: {error}")))?;
            rt.timers.lock().unwrap().insert(id, timer);
            reference(process, id)
        }
        (SignalBif::CancelTimer1, [reference]) | (SignalBif::CancelTimer2, [reference, _]) => {
            let options = if let Some(options) = args.get(1) {
                timer_query_options(*options, true)?
            } else {
                TimerQueryOptions {
                    asynchronous: false,
                    info: true,
                }
            };
            let id = ref_id(*reference).ok_or_else(|| badarg("cancel_timer/1"))?;
            let rt = runtime(process)?;
            let timer = rt.timers.lock().unwrap().remove(&id);
            let remaining = timer.and_then(|timer| rt.scheduler().ok()?.cancel_timer(timer));
            timer_query_result(process, ctx, *reference, remaining, true, options)
        }
        (SignalBif::ReadTimer1, [reference]) | (SignalBif::ReadTimer2, [reference, _]) => {
            let options = if let Some(options) = args.get(1) {
                timer_query_options(*options, false)?
            } else {
                TimerQueryOptions {
                    asynchronous: false,
                    info: true,
                }
            };
            let id = ref_id(*reference).ok_or_else(|| badarg("read_timer/1"))?;
            let rt = runtime(process)?;
            let timer = rt.timers.lock().unwrap().get(&id).copied();
            let remaining = timer.and_then(|timer| rt.scheduler().ok()?.read_timer(timer));
            timer_query_result(process, ctx, *reference, remaining, false, options)
        }
        (SignalBif::SpawnSystemProcess3, [module, function, args]) => {
            let pid = spawn_mfa(
                vm,
                process,
                ctx,
                (*module, *function, *args),
                false,
                false,
                None,
                None,
                false,
                None,
            )?;
            if let (Some(pid), Some(runtime)) = (Pid::from_term(pid), process.runtime.as_ref()) {
                runtime.system_processes.lock().unwrap().insert(pid);
            }
            Ok(pid)
        }
        (SignalBif::DirtyProcessHandleSignals1, [arg]) => {
            dirty_process_handle_signals(vm, process, ctx, *arg)
        }
        (SignalBif::RequestSystemTask3, [_, _, _])
        | (SignalBif::RequestSystemTask4, [_, _, _, _]) => {
            request_system_task(vm, process, ctx, args)
        }
        _ => Err(VmError::Unsupported("resolved signal BIF arity".into())),
    }
}

/// Work a target process runs when it next handles signals.
///
/// Port of the signal-request ops in
/// `erts/emulator/beam/erl_proc_sig_queue.c` (`ERTS_SIG_Q_OP_PROCESS_INFO`,
/// `ERTS_SIG_Q_OP_GROUP_LEADER`, `ERTS_SIG_Q_OP_RPC`, `ERTS_SIG_Q_OP_IS_ALIVE`),
/// OTP-29.1.1. The scheduler `Signal` enum has no request variant, so the
/// payload lives here and [`Signal::UnlinkAck`] carries the id as a wakeup.
pub(crate) enum RemoteOp {
    /// `process_info/1` (`items == None`) or `process_info/2`.
    Info { items: Option<Message> },
    /// `group_leader(Leader, Pid)`.
    GroupLeader { leader: Pid },
    /// `garbage_collect` request. `request_id` is the term in the reply tuple.
    Collect { request_id: Message, major: bool },
    /// `process_display(Pid, backtrace)`.
    Display,
    /// `is_process_alive/1` signal-ordering probe.
    Alive,
    /// Check whether the target still has a direct reference to old module code.
    CheckProcessCode {
        module: usize,
        async_request: Option<Message>,
        kill: bool,
    },
}

/// How the caller extracts the reply once it is in the mailbox.
#[derive(Clone, Copy)]
pub(crate) enum WaitKind {
    /// `{Ref, Result}` and `Result` is the BIF return value.
    Info,
    /// `{Ref, true | badarg}`. Anything but `true` is `badarg`.
    GroupLeader,
    /// `{Ref, true | badarg | badopt}`. Anything but `true` is `badarg`.
    Display,
    /// `{Ref, Bool}`.
    Alive,
}

pub(crate) enum Submit {
    /// The request is in the target's queue. The id is the reply reference.
    Sent(u64),
    /// The target had already exited.
    Dead,
}

struct Pending {
    id: u64,
    from: Pid,
    op: RemoteOp,
}

struct Waiter {
    id: u64,
    kind: WaitKind,
}

/// Runtime address plus pid. Simulations reuse pid numbers, and tests run in parallel.
type Slot = (usize, Pid);

struct Tables {
    requests: BTreeMap<Slot, Vec<Pending>>,
    waiters: BTreeMap<Slot, Waiter>,
}

fn scope(process: &Process) -> usize {
    process
        .runtime
        .as_ref()
        .map(|runtime| std::sync::Arc::as_ptr(runtime) as usize)
        .unwrap_or(0)
}

fn tables() -> &'static Mutex<Tables> {
    static TABLES: std::sync::OnceLock<Mutex<Tables>> = std::sync::OnceLock::new();
    TABLES.get_or_init(|| {
        Mutex::new(Tables {
            requests: BTreeMap::new(),
            waiters: BTreeMap::new(),
        })
    })
}

/// Park the caller until [`poll`] observes the reply. The process retries this BIF.
pub(crate) fn await_reply() -> VmError {
    VmError::Unsupported("AWAIT_SIGNAL_REPLY".into())
}

pub(crate) fn is_await_message(message: &str) -> bool {
    message.contains("AWAIT_SIGNAL_REPLY")
}

pub(crate) fn is_waiting(process: &Process, pid: Pid) -> bool {
    process
        .runtime
        .as_ref()
        .is_some_and(|runtime| runtime.remote_status(pid) == "waiting")
}

/// `Ok(None)` when this process has no outstanding request.
/// `Ok(Some(term))` when the reply has arrived.
/// `Err(await)` when the reply is still pending.
pub(crate) fn poll(process: &mut Process, caller: Pid) -> Result<Option<Term>, VmError> {
    let slot = (scope(process), caller);
    let waiter = {
        let tables = tables().lock().unwrap();
        let Some(waiter) = tables.waiters.get(&slot) else {
            return Ok(None);
        };
        (waiter.id, waiter.kind)
    };
    let (id, kind) = waiter;
    let Some(index) = process
        .inbox
        .iter()
        .position(|term| reply_inner(*term, id, kind).is_some())
    else {
        return Err(await_reply());
    };
    let old_prio_len = process.cold.as_ref().map_or(0, |cold| cold.prio_len);
    let (removed, new_prio_len) =
        process
            .inbox
            .remove_to_heap(index, &mut process.heap, old_prio_len)?;
    process.cold_mut().prio_len = new_prio_len;
    let term = removed.expect("reply index");
    process.message_removed(index);
    tables().lock().unwrap().waiters.remove(&slot);
    let inner = reply_inner(term, id, kind).ok_or_else(|| badarg("request reply"))?;
    interpret(kind, inner).map(Some)
}

fn interpret(kind: WaitKind, inner: Term) -> Result<Term, VmError> {
    match kind {
        WaitKind::Info | WaitKind::Alive => Ok(inner),
        WaitKind::GroupLeader | WaitKind::Display => {
            if inner == atom("true") {
                Ok(atom("true"))
            } else {
                Err(badarg("remote request"))
            }
        }
    }
}

fn reply_inner(term: Term, id: u64, kind: WaitKind) -> Option<Term> {
    // SAFETY: Inbox terms are rooted on the caller's heap for this scan.
    let tuple = unsafe { term.tuple_ref() }?;
    match kind {
        WaitKind::Info | WaitKind::GroupLeader | WaitKind::Display | WaitKind::Alive => {
            if tuple.len() == 2 && tuple.get(0).and_then(ref_id) == Some(id) {
                tuple.get(1)
            } else {
                None
            }
        }
    }
}

/// Enqueue `op` on `target` and, when `wait` is set, park the caller on the reply.
pub(crate) fn submit(
    process: &Process,
    ctx: &mut RunCtx<'_, Message>,
    target: Pid,
    op: RemoteOp,
    wait: Option<WaitKind>,
) -> Result<Submit, VmError> {
    let id = runtime(process)?.next_ref();
    submit_id(process, ctx, target, id, op, wait)
}

/// Like [`submit`], but the reply reference uses `id` (`0` allocates one).
pub(crate) fn submit_id(
    process: &Process,
    ctx: &mut RunCtx<'_, Message>,
    target: Pid,
    id: u64,
    op: RemoteOp,
    wait: Option<WaitKind>,
) -> Result<Submit, VmError> {
    let id = if id == 0 {
        runtime(process)?.next_ref()
    } else {
        id
    };
    let slot_of = scope(process);
    {
        let mut tables = tables().lock().unwrap();
        tables
            .requests
            .entry((slot_of, target))
            .or_default()
            .push(Pending {
                id,
                from: ctx.pid(),
                op,
            });
        if let Some(kind) = wait {
            tables
                .waiters
                .insert((slot_of, ctx.pid()), Waiter { id, kind });
        }
    }
    match ctx.signal(target, Signal::UnlinkAck(id)) {
        Ok(()) => Ok(Submit::Sent(id)),
        Err(arinsal_sched::Error::NoProcess) => {
            let mut tables = tables().lock().unwrap();
            if let Some(queue) = tables.requests.get_mut(&(slot_of, target)) {
                queue.retain(|pending| pending.id != id);
            }
            tables.waiters.remove(&(slot_of, ctx.pid()));
            Ok(Submit::Dead)
        }
        Err(error) => Err(VmError::Unsupported(format!("request signal: {error}"))),
    }
}

/// Run the request whose wakeup is `id`, if it is still queued for this process.
pub(crate) fn handle_request(
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    id: u64,
) -> Result<(), VmError> {
    let pending = {
        let mut tables = tables().lock().unwrap();
        let Some(queue) = tables.requests.get_mut(&(scope(process), ctx.pid())) else {
            return Ok(());
        };
        let Some(index) = queue.iter().position(|pending| pending.id == id) else {
            return Ok(());
        };
        queue.remove(index)
    };
    let reply = crate::natives::proc::fulfill_request(process, ctx, pending.id, pending.op)?;
    let message = Message::copy_from(reply)?;
    match ctx.send(pending.from, message) {
        Ok(()) | Err(arinsal_sched::Error::NoProcess) => Ok(()),
        Err(error) => Err(VmError::Unsupported(format!("request reply: {error}"))),
    }
}

/// Reply `false` / `undefined` / `badarg` for requests this process will never run.
pub(crate) fn process_exiting(process: &mut Process, ctx: &mut RunCtx<'_, Message>) {
    let slot = (scope(process), ctx.pid());
    let pending = {
        let mut tables = tables().lock().unwrap();
        tables.waiters.remove(&slot);
        tables.requests.remove(&slot).unwrap_or_default()
    };
    for pending in pending {
        let Ok(reply) = crate::natives::proc::failure_reply(process, pending.id, pending.op) else {
            continue;
        };
        let Ok(message) = Message::copy_from(reply) else {
            continue;
        };
        let _ = ctx.send(pending.from, message);
    }
}

// Port of erts/emulator/beam/erl_proc_sig_queue.c:3027
// (erts_proc_sig_send_is_alive_request), OTP-29.1.1.
fn is_process_alive(
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    pid: Term,
) -> Result<Term, VmError> {
    if let Some(done) = poll(process, ctx.pid())? {
        return Ok(done);
    }
    let pid = Pid::from_term(pid).ok_or_else(|| badarg("is_process_alive/1"))?;
    if pid == ctx.pid() {
        return Ok(atom("true"));
    }
    if !runtime(process)?.scheduler()?.lookup(pid) {
        return Ok(atom("false"));
    }
    match submit(process, ctx, pid, RemoteOp::Alive, Some(WaitKind::Alive))? {
        Submit::Sent(_) => Err(await_reply()),
        Submit::Dead => Ok(atom("false")),
    }
}

// Port of erts/emulator/beam/bif.c:136 (link_opt) and bif.c:675 (erts_link_opts), OTP-29.1.1.
fn link_opt(
    vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    target: Term,
    opts: Term,
) -> Result<Term, VmError> {
    let priority = parse_priority_opts(opts)?;
    if target.as_port().is_some() {
        crate::port::link(process, target, ctx.pid(), true)?;
        return Ok(atom("true"));
    }
    let pid = Pid::from_term(target).ok_or_else(|| badarg("link"))?;
    if pid == ctx.pid() {
        return Ok(atom("true"));
    }
    if !runtime(process)?.scheduler()?.lookup(pid) {
        let reason = atom("noproc");
        if process.trap_exit {
            let pid_term = pid.to_term().ok_or_else(|| badarg("link"))?;
            let mut heap = arinsal_bifs::FragmentingHeap(&mut process.heap);
            let exit = TermBuilder::new(&mut heap)
                .tuple(&[atom("EXIT"), pid_term, reason])
                .map_err(|_| system_limit())?;
            if priority {
                process.push_priority_message(exit);
            } else {
                process.inbox.push_back(exit);
            }
            return Ok(atom("true"));
        }
        process.note_exit_reason(reason)?;
        return Err(VmError::Trap(crate::exceptions::Trap::error(reason)));
    }
    crate::trace::linked(process, ctx.pid(), pid);
    process.cold_mut().links.insert(pid);
    if priority {
        process.cold_mut().prio_links.insert(pid);
    } else {
        process.cold_mut().prio_links.remove(&pid);
    }
    let linked_term = pid.to_term().ok_or_else(|| badarg("link"))?;
    crate::trace::emit(
        Some(vm),
        process,
        ctx,
        ctx.pid(),
        crate::trace::PROCS,
        "link",
        &[linked_term],
    );
    if let Err(error) = ctx.signal(pid, Signal::Link)
        && error != arinsal_sched::Error::NoProcess
    {
        return Err(match error {
            arinsal_sched::Error::Capacity => system_limit(),
            _ => badarg("link"),
        });
    }
    Ok(atom("true"))
}

// Port of erts/emulator/beam/bif.c:1721 (send_exit_signal_bif), OTP-29.1.1.
fn send_exit_signal_bif(
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    id: Term,
    reason: Term,
    opts: Term,
    exit2: bool,
) -> Result<Term, VmError> {
    let want_priority = parse_priority_opts(opts)?;
    if id.as_port().is_some() {
        crate::port::exit_port(process, ctx, id, reason)?;
        return Ok(atom("true"));
    }
    let mut via_prio_alias = false;
    let pid = if let Some(pid) = Pid::from_term(id) {
        pid
    } else if let Some(alias) = ref_id(id) {
        match runtime(process)?.alias_lookup_prio(alias) {
            Some((Some(pid), alias_prio)) => {
                via_prio_alias = alias_prio && want_priority;
                pid
            }
            Some((None, _)) => return Ok(atom("true")),
            None => return Err(badarg("exit")),
        }
    } else {
        return Err(badarg("exit"));
    };
    let suicide = exit2 && pid == ctx.pid() && (reason == atom("kill") || !process.trap_exit);
    if suicide {
        process.note_exit_reason(reason)?;
        return Err(VmError::Trap(crate::exceptions::Trap::exit(reason)));
    }
    let mut message = Message::copy_from(reason)?;
    if via_prio_alias {
        message = message.with_priority();
    }
    let _ = ctx.signal(pid, Signal::Exit(message));
    Ok(atom("true"))
}

fn parse_priority_opts(opts: Term) -> Result<bool, VmError> {
    let mut priority = false;
    let mut current = opts;
    while current.classify() == TermKind::List {
        // SAFETY: Option list stays rooted for this BIF call.
        let (head, tail) = unsafe { current.cons_ref() }.ok_or_else(|| badarg("badopt"))?;
        if head != atom("priority") {
            return Err(badarg("badopt"));
        }
        priority = true;
        current = tail;
    }
    if current != Term::NIL {
        return Err(badarg("badopt"));
    }
    Ok(priority)
}

// Port of erts/emulator/beam/erl_bif_info.c:4049 (erts_internal_is_process_alive_2), OTP-29.1.1.
fn is_process_alive_2(
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    pid: Term,
    reference: Term,
) -> Result<Term, VmError> {
    let pid = Pid::from_term(pid).ok_or_else(|| badarg("is_process_alive/2"))?;
    let id = ref_id(reference).ok_or_else(|| badarg("is_process_alive/2"))?;
    match submit_id(process, ctx, pid, id, RemoteOp::Alive, None)? {
        Submit::Sent(_) => Ok(atom("ok")),
        Submit::Dead => {
            // Port of erl_proc_sig_queue.c:3065-3070: reply `{Ref, false}` to self.
            let mut heap = arinsal_bifs::FragmentingHeap(&mut process.heap);
            let reply = TermBuilder::new(&mut heap)
                .tuple(&[reference, atom("false")])
                .map_err(|_| system_limit())?;
            process.inbox.push_back(reply);
            Ok(atom("ok"))
        }
    }
}

// Port of erts/emulator/beam/erl_process.c:9216
// (erts_internal_is_process_executing_dirty_1), OTP-29.1.1.
// This build has no dirty schedulers, matching OTP 29.1.1 on this machine.
fn is_process_executing_dirty(pid: Term) -> Result<Term, VmError> {
    if Pid::from_term(pid).is_none() {
        return Err(badarg("is_process_executing_dirty/1"));
    }
    Ok(atom("false"))
}

// Port of erts/emulator/beam/erl_bif_trace.c:3900 (trace_delivered_1), OTP-29.1.1.
fn trace_delivered(
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    target: Term,
) -> Result<Term, VmError> {
    if target != atom("all") && Pid::from_term(target).is_none() {
        return Err(badarg("trace_delivered/1"));
    }
    let id = runtime(process)?.next_ref();
    let reference = reference(process, id)?;
    let mut heap = arinsal_bifs::FragmentingHeap(&mut process.heap);
    let message = TermBuilder::new(&mut heap)
        .tuple(&[atom("trace_delivered"), target, reference])
        .map_err(|_| system_limit())?;
    let envelope = Message::copy_from(message)?;
    match ctx.send(ctx.pid(), envelope) {
        Ok(()) | Err(arinsal_sched::Error::NoProcess) => Ok(reference),
        Err(arinsal_sched::Error::Capacity) => Err(system_limit()),
        Err(_) => Err(badarg("trace_delivered/1")),
    }
}

// Port of erts/emulator/beam/erl_bif_trace.c:650
// (erts_trace_cleaner_send_trace_clean_signal_1), OTP-29.1.1.
fn trace_cleaner_send(
    process: &Process,
    ctx: &RunCtx<'_, Message>,
    to: Term,
) -> Result<Term, VmError> {
    let is_cleaner = process.runtime.as_ref().is_some_and(|runtime| {
        runtime
            .names
            .lock()
            .unwrap()
            .get("erts_trace_cleaner")
            .copied()
            == Some(ctx.pid())
    });
    if !is_cleaner {
        return Err(VmError::Trap(crate::exceptions::Trap::error(atom(
            "notsup",
        ))));
    }
    if Pid::from_term(to).is_some() {
        // No pending clear sessions in this build; a live target would return true.
        return Ok(atom(
            if runtime(process)?
                .scheduler()?
                .lookup(Pid::from_term(to).expect("pid"))
            {
                "true"
            } else {
                "false"
            },
        ));
    }
    if to.as_port().is_some() {
        return Ok(atom("false"));
    }
    Err(badarg("send_trace_clean_signal/1"))
}
