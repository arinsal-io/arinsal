//! Process configuration, dictionary, and introspection BIFs.

use crate::process::Message;
use crate::{Process, Vm, VmError};
use arinsal_sched::{Pid, Priority, RunCtx, Signal};
use arinsal_term::{FunRef, Identity, Term, TermBuilder, TermKind, global_atoms};
use std::sync::atomic::Ordering;

fn atom(name: &str) -> Term {
    Term::atom(global_atoms().intern(name).expect("short built-in atom"))
}

fn atom_name(term: Term) -> Option<String> {
    Some(global_atoms().text(term.as_atom()?)?.to_string())
}

fn badarg() -> VmError {
    VmError::Trap(crate::exceptions::Trap::error(atom("badarg")))
}

fn term_equal(left: Term, right: Term) -> bool {
    arinsal_term::exact_eq(left, right)
}

fn flag_value(process: &Process, name: &str) -> Option<Term> {
    process.cold.as_ref()?.flags.get(name).copied()
}

pub(crate) fn set_flag(process: &mut Process, name: &str, value: Term) -> Option<Term> {
    process.cold_mut().flags.insert(name.to_owned(), value)
}

fn list(term: Term) -> Option<Vec<Term>> {
    let mut result = Vec::new();
    let mut current = term;
    while current.classify() == TermKind::List {
        // SAFETY: The caller's terms stay rooted for this BIF invocation.
        let (head, tail) = unsafe { current.cons_ref()? };
        result.push(head);
        current = tail;
    }
    (current == Term::NIL).then_some(result)
}

fn make_list(
    process: &mut Process,
    values: impl IntoIterator<Item = Term>,
) -> Result<Term, VmError> {
    let mut heap = arinsal_bifs::FragmentingHeap(&mut process.heap);
    TermBuilder::new(&mut heap)
        .list_from_iter(values)
        .map_err(|error| VmError::Unsupported(format!("process list allocation: {error:?}")))
}

fn make_tuple(process: &mut Process, values: &[Term]) -> Result<Term, VmError> {
    let mut heap = arinsal_bifs::FragmentingHeap(&mut process.heap);
    TermBuilder::new(&mut heap)
        .tuple(values)
        .map_err(|error| VmError::Unsupported(format!("process tuple allocation: {error:?}")))
}

/// Scheduler priority named by a `priority` process flag value.
pub(crate) fn scheduler_priority(name: &str) -> Option<Priority> {
    match name {
        "max" => Some(Priority::Max),
        "high" => Some(Priority::High),
        "normal" => Some(Priority::Normal),
        "low" => Some(Priority::Low),
        _ => None,
    }
}

/// The process's user priority (`process_flag(priority, _)`).
pub(crate) fn user_priority(process: &Process) -> Priority {
    flag_value(process, "priority")
        .and_then(atom_name)
        .as_deref()
        .and_then(scheduler_priority)
        .unwrap_or(Priority::Normal)
}

fn flag(process: &mut Process, name: &str, value: Term) -> Result<Term, VmError> {
    let previous = match name {
        "trap_exit" => {
            let enabled = if value == atom("true") {
                true
            } else if value == atom("false") {
                false
            } else {
                return Err(badarg());
            };
            let old = process.trap_exit;
            process.trap_exit = enabled;
            atom(if old { "true" } else { "false" })
        }
        "error_handler" => {
            if value.as_atom().is_none() {
                return Err(badarg());
            }
            set_flag(process, name, value).unwrap_or_else(|| atom("error_handler"))
        }
        "priority" => {
            if !["low", "normal", "high", "max"]
                .iter()
                .any(|n| value == atom(n))
            {
                return Err(badarg());
            }
            set_flag(process, name, value).unwrap_or_else(|| atom("normal"))
        }
        "message_queue_data" => {
            if value != atom("on_heap") && value != atom("off_heap") {
                return Err(badarg());
            }
            // Port of erts/emulator/beam/erl_message.c:1054 (message queue data flag), OTP-29.1.1.
            let previous = flag_value(process, name).unwrap_or_else(|| atom("on_heap"));
            set_flag(process, name, value);
            previous
        }
        "sensitive" => {
            if value != atom("true") && value != atom("false") {
                return Err(badarg());
            }
            // Port of erts/emulator/beam/bif.c:2173 (process_flag sensitive), OTP-29.1.1.
            let pid = process.self_pid.ok_or_else(badarg)?;
            let old = crate::trace::set_sensitive(process, pid, value == atom("true"));
            set_flag(process, name, value);
            atom(if old { "true" } else { "false" })
        }
        "async_dist" => {
            if value != atom("true") && value != atom("false") {
                return Err(badarg());
            }
            set_flag(process, name, value).unwrap_or_else(|| atom("false"))
        }
        "fullsweep_after" | "min_heap_size" | "min_bin_vheap_size" | "save_calls" => {
            let n = value.as_small().filter(|n| *n >= 0).ok_or_else(badarg)?;
            if name == "save_calls" && n > 10_000 {
                return Err(badarg());
            }
            if name == "save_calls" {
                // Port of erts/emulator/beam/bif.c:1907 (process_flag save_calls), OTP-29.1.1.
                let old = crate::trace::set_save_calls(process, n as usize);
                set_flag(process, name, Term::small(n).unwrap());
                return Ok(Term::small(old as i64).unwrap());
            }
            let normalized = match name {
                "fullsweep_after" => n.min(u16::MAX as i64),
                "min_heap_size" => n.max(233),
                "min_bin_vheap_size" => crate::natives::sys::normalize_spawn_heap_minimum(
                    process.runtime.as_deref(),
                    Some(n as usize),
                    true,
                ) as i64,
                _ => n,
            };
            let previous_min_bin_vheap = process.heap.min_bin_vheap_size();
            if name == "fullsweep_after" {
                process.heap.set_fullsweep_after(normalized as u16);
            }
            if name == "min_heap_size" {
                process.heap.set_min_heap_size(normalized as usize);
            }
            if name == "min_bin_vheap_size" {
                process.heap.set_min_bin_vheap_size(normalized as u64);
            }
            set_flag(process, name, Term::small(normalized).unwrap()).unwrap_or_else(|| {
                Term::small(match name {
                    "fullsweep_after" => 65_535,
                    "min_heap_size" => 233,
                    "min_bin_vheap_size" => previous_min_bin_vheap as i64,
                    _ => 0,
                })
                .unwrap()
            })
        }
        // Handled in `call` so the limit is stored on the scheduler runtime.
        "max_heap_size" => return Err(badarg()),
        _ => return Err(badarg()),
    };
    Ok(previous)
}

fn process_info(
    vm: Option<&Vm>,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    item: Option<Term>,
    status: Term,
    drain_inbox: bool,
) -> Result<Term, VmError> {
    // Port of erts/emulator/beam/erl_bif_info.c:794-804 (`process_info`), OTP-29.1.1:
    // report heap counters from one snapshot even though building the result may grow the heap.
    let heap_size = process.heap.heap_size_words();
    let total_heap_size = process.heap.total_heap_size_words();
    // Messages already queued are part of process_info. A request handled from
    // inside drain must not pull signals that were ordered after it.
    if drain_inbox {
        process.drain(ctx)?;
    }
    let pid = ctx.pid();
    let list_form = item.is_some_and(|item| list(item).is_some());
    let all_form = item.is_none();
    let keys = if let Some(item) = item {
        if let Some(items) = list(item) {
            items
        } else {
            vec![item]
        }
    } else {
        // Port of erts/emulator/beam/erl_bif_info.c:1007-1025 (pi_1_keys), OTP-29.1.1.
        [
            "registered_name",
            "current_function",
            "initial_call",
            "status",
            "message_queue_len",
            "links",
            "dictionary",
            "trap_exit",
            "error_handler",
            "priority",
            "group_leader",
            "total_heap_size",
            "heap_size",
            "stack_size",
            "reductions",
            "garbage_collection",
            "suspending",
        ]
        .into_iter()
        .map(atom)
        .collect()
    };
    let mut pairs = Vec::new();
    for key in keys {
        if let Some((lookup_key, selector)) = dictionary_lookup(key) {
            // Port of erts/emulator/beam/erl_bif_info.c:852, OTP-29.1.1.
            let value = process
                .cold
                .as_ref()
                .and_then(|cold| {
                    cold.dictionary
                        .iter()
                        .find(|(candidate, _)| term_equal(*candidate, lookup_key))
                        .map(|(_, value)| *value)
                })
                .unwrap_or_else(|| atom("undefined"));
            // Port of erts/emulator/beam/erl_bif_info.c:2288 (ERTS_PI_IX_DICTIONARY_LOOKUP), OTP-29.1.1.
            let value = if process
                .self_pid
                .is_some_and(|pid| crate::trace::is_sensitive(process, pid))
            {
                atom("undefined")
            } else {
                value
            };
            pairs.push(make_tuple(process, &[selector, value])?);
            continue;
        }
        let name = atom_name(key).ok_or_else(badarg)?;
        let value = match name.as_str() {
            // Port of erts/emulator/beam/erl_proc_sig_queue.c:6768 (message queue info), OTP-29.1.1.
            "message_queue_len" => Term::small(process.inbox.len() as i64).ok_or_else(badarg)?,
            // Port of erts/emulator/beam/erl_proc_sig_queue.c:6794 (messages process info), OTP-29.1.1.
            // Port of erts/emulator/beam/erl_bif_info.c:1692 (ERTS_PI_IX_MESSAGES), OTP-29.1.1.
            "messages" => {
                let sensitive = process
                    .self_pid
                    .is_some_and(|pid| crate::trace::is_sensitive(process, pid));
                let messages = if sensitive {
                    Vec::new()
                } else {
                    process.inbox.copied_terms(&mut process.heap)?
                };
                make_list(process, messages)?
            }
            // Port of erts/emulator/beam/erl_bif_info.c:1964 (ERTS_PI_IX_DICTIONARY), OTP-29.1.1.
            "dictionary" => {
                let sensitive = process
                    .self_pid
                    .is_some_and(|pid| crate::trace::is_sensitive(process, pid));
                let raw = process
                    .cold
                    .as_ref()
                    .filter(|_| !sensitive)
                    .map(|cold| {
                        cold.dictionary
                            .iter()
                            .map(|(k, v)| (*k, *v))
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                let entries = raw
                    .into_iter()
                    .map(|(k, v)| make_tuple(process, &[k, v]))
                    .collect::<Result<Vec<_>, _>>()?;
                make_list(process, entries)?
            }
            "trap_exit" => atom(if process.trap_exit { "true" } else { "false" }),
            "heap_size" => Term::small(heap_size as i64).ok_or_else(badarg)?,
            // Port of erts/emulator/beam/erl_message.c:1006 (message queue data info), OTP-29.1.1.
            "total_heap_size" => Term::small(total_heap_size as i64).ok_or_else(badarg)?,
            "stack_size" => Term::small(process.heap.stack_words() as i64).ok_or_else(badarg)?,
            "memory" => Term::small(
                (std::mem::size_of::<Process>() + process.heap.total_heap_size_words() * 8) as i64,
            )
            .ok_or_else(badarg)?,
            "reductions" => Term::small(process.reductions_used.min(i64::MAX as u64) as i64)
                .ok_or_else(badarg)?,
            "status" => {
                // Suspend count wins over the waiting/runnable/running atom the
                // caller (local BIF or remote request) passed in.
                if let Some(runtime) = process.runtime.as_ref()
                    && runtime.suspend_active(pid)
                {
                    atom(runtime.remote_status(pid))
                } else {
                    status
                }
            }
            "group_leader" => process
                .cold
                .as_ref()
                .and_then(|cold| cold.group_leader)
                .unwrap_or_else(|| ctx.pid())
                .to_term()
                .unwrap_or(Term::NIL),
            "links" => {
                let links = process
                    .cold
                    .as_ref()
                    .map(|cold| {
                        cold.links
                            .iter()
                            .filter_map(|p| p.to_term())
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                let mut links = links;
                links.extend(crate::port::linked_ports(process, pid));
                make_list(process, links)?
            }
            "monitors" => {
                let raw = process
                    .cold
                    .as_ref()
                    .map(|cold| {
                        cold.monitors
                            .values()
                            .filter_map(|p| p.to_term())
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                let vals = raw
                    .into_iter()
                    .map(|p| make_tuple(process, &[atom("process"), p]))
                    .collect::<Result<Vec<_>, _>>()?;
                let port_monitors = crate::port::monitors_by(process, pid);
                let mut heap = arinsal_bifs::FragmentingHeap(&mut process.heap);
                let vals = vals
                    .into_iter()
                    .chain(port_monitors.into_iter().filter_map(|object| {
                        let object = arinsal_term::from_owned(&object, &mut heap).ok()?;
                        TermBuilder::new(&mut heap)
                            .tuple(&[atom("port"), object])
                            .ok()
                    }))
                    .collect::<Vec<_>>();
                make_list(process, vals)?
            }
            "monitored_by" => {
                let vals = process
                    .cold
                    .as_ref()
                    .map(|cold| {
                        cold.monitored_by
                            .values()
                            .filter_map(|p| p.to_term())
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                let mut vals = vals;
                vals.extend(crate::port::driver_monitoring_ports(process, pid));
                make_list(process, vals)?
            }
            "priority" | "message_queue_data" | "error_handler" | "save_calls" | "sensitive"
            | "async_dist" => flag_value(process, &name).unwrap_or_else(|| match name.as_str() {
                "priority" => atom("normal"),
                "message_queue_data" => atom("on_heap"),
                "error_handler" => atom("error_handler"),
                "sensitive" | "async_dist" => atom("false"),
                "save_calls" => atom("false"),
                _ => Term::small(0).unwrap(),
            }),
            "backtrace" => {
                let running = status == atom("running");
                let text = backtrace_text(vm, process, running)?;
                let mut heap = arinsal_bifs::FragmentingHeap(&mut process.heap);
                TermBuilder::new(&mut heap)
                    .binary(&text)
                    .map_err(|e| VmError::Unsupported(format!("backtrace binary: {e:?}")))?
            }
            "binary" => {
                // Port of erts/emulator/beam/erl_bif_info.c:4762-4795, OTP-29.1.1.
                let mut entries = Vec::new();
                for (pointer, bytes, references) in process.heap.off_heap_binary_info() {
                    let values = [
                        Term::small(pointer as i64).ok_or_else(badarg)?,
                        Term::small(bytes as i64).ok_or_else(badarg)?,
                        Term::small(references as i64).ok_or_else(badarg)?,
                    ];
                    entries.push(make_tuple(process, &values)?);
                }
                make_list(process, entries)?
            }
            "catchlevel" => Term::small(0).unwrap(),
            "current_function"
                if process
                    .runtime
                    .as_ref()
                    .is_some_and(|runtime| runtime.is_hibernating(pid)) =>
            {
                // elixir_loop1: OTP reports hibernate/0 while the stack is retained.
                let arity = process
                    .runtime
                    .as_ref()
                    .and_then(|runtime| {
                        runtime
                            .hibernating
                            .lock()
                            .unwrap()
                            .get(&pid)
                            .map(|cont| if cont.resume_in_place { 0 } else { 3 })
                    })
                    .unwrap_or(3);
                make_tuple(
                    process,
                    &[
                        atom("erlang"),
                        atom("hibernate"),
                        Term::small(arity).unwrap(),
                    ],
                )?
            }
            "initial_call" => {
                let (module_name, function, arity) = process
                    .cold
                    .as_ref()
                    .and_then(|cold| cold.initial_call.clone())
                    .map_or_else(|| resolve_mfa(vm, process), Ok)?;
                make_tuple(
                    process,
                    &[
                        Term::atom(global_atoms().intern(&module_name).map_err(|_| badarg())?),
                        atom(&function),
                        Term::small(arity as i64).unwrap(),
                    ],
                )?
            }
            "current_function" => {
                let (module_name, function, arity) = resolve_mfa(vm, process)?;
                make_tuple(
                    process,
                    &[
                        Term::atom(global_atoms().intern(&module_name).map_err(|_| badarg())?),
                        atom(&function),
                        Term::small(arity as i64).unwrap(),
                    ],
                )?
            }
            "current_location" => {
                let (module_name, function, arity) = resolve_mfa(vm, process)?;
                let native = native_call_site(process).map(|(function, pc)| {
                    function
                        .line_at(pc)
                        .map(|(file, line)| (file.to_owned(), u64::from(line)))
                });
                let source = native.flatten().or_else(|| {
                    process.runtime.as_ref().and_then(|runtime| {
                        runtime.with_modules(|modules| {
                            let module = modules.get(process.module)?;
                            module
                                .lines
                                .get(process.ip)
                                .and_then(Option::as_ref)
                                .or_else(|| {
                                    process
                                        .ip
                                        .checked_sub(1)
                                        .and_then(|ip| module.lines.get(ip))
                                        .and_then(Option::as_ref)
                                })
                                .cloned()
                        })
                    })
                });
                let location = if let Some((file, line)) = source {
                    let file = charlist(process, &file)?;
                    let file = make_tuple(process, &[atom("file"), file])?;
                    let line = make_tuple(
                        process,
                        &[atom("line"), Term::small(line as i64).ok_or_else(badarg)?],
                    )?;
                    make_list(process, [file, line])?
                } else {
                    Term::NIL
                };
                make_tuple(
                    process,
                    &[
                        Term::atom(global_atoms().intern(&module_name).map_err(|_| badarg())?),
                        atom(&function),
                        Term::small(arity as i64).unwrap(),
                        location,
                    ],
                )?
            }
            "current_stacktrace" => current_stacktrace(vm, process)?,
            "garbage_collection" => {
                let limit = max_heap_term(process, pid)?;
                // Port of erts/emulator/beam/erl_bif_info.c:2072-2087
                // (ERTS_PI_IX_GARBAGE_COLLECTION), OTP-29.1.1.
                let entries = [
                    ("max_heap_size", limit),
                    (
                        "min_bin_vheap_size",
                        Term::small(process.heap.min_bin_vheap_size() as i64).unwrap(),
                    ),
                    (
                        "min_heap_size",
                        Term::small(process.heap.min_heap_size_words() as i64)
                            .ok_or_else(badarg)?,
                    ),
                    (
                        "fullsweep_after",
                        Term::small(i64::from(process.heap.fullsweep_after())).unwrap(),
                    ),
                    (
                        "minor_gcs",
                        Term::small(i64::from(process.heap.minor_gcs())).unwrap(),
                    ),
                ]
                .into_iter()
                // Port of erts/emulator/beam/erl_bif_info.c (garbage_collection): erts conses
                // the items so the list starts with max_heap_size and ends with minor_gcs.
                .rev()
                .map(|(name, value)| make_tuple(process, &[atom(name), value]))
                .collect::<Result<Vec<_>, _>>()?;
                make_list(process, entries)?
            }
            "garbage_collection_info" => {
                let entries = [
                    ("old_heap_block_size", process.heap.old_heap_block_size()),
                    ("heap_block_size", process.heap.heap_size_words()),
                    ("mbuf_size", process.heap.fragment_words()),
                    ("recent_size", process.heap.recent_words()),
                    ("stack_size", process.heap.stack_words()),
                    ("old_heap_size", process.heap.old_used_words()),
                    ("heap_size", process.heap.used_words()),
                    ("bin_vheap_size", process.heap.bin_vheap_used() as usize),
                    (
                        "bin_vheap_block_size",
                        process.heap.bin_vheap_block_size() as usize,
                    ),
                    (
                        "bin_old_vheap_size",
                        process.heap.bin_old_vheap_used() as usize,
                    ),
                    (
                        "bin_old_vheap_block_size",
                        process.heap.bin_old_vheap_block_size() as usize,
                    ),
                ];
                let rows = entries
                    .into_iter()
                    .map(|(name, value)| {
                        make_tuple(process, &[atom(name), Term::small(value as i64).unwrap()])
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                make_list(process, rows)?
            }
            // Port of erts/emulator/beam/erl_bif_info.c:2183 (ERTS_PI_IX_LAST_CALLS), OTP-29.1.1.
            "last_calls" => match crate::trace::saved_calls(process) {
                None => atom("false"),
                Some(calls) => {
                    // erts conses newest first, so the list starts with the oldest call.
                    let mut terms = Vec::with_capacity(calls.len());
                    for call in calls.iter().rev() {
                        terms.push(match call {
                            crate::trace::SavedCall::Send => atom("send"),
                            crate::trace::SavedCall::Receive => atom("receive"),
                            crate::trace::SavedCall::Timeout => atom("timeout"),
                            crate::trace::SavedCall::Mfa(m, f, a) => make_tuple(
                                process,
                                &[
                                    Term::atom(*m),
                                    Term::atom(*f),
                                    Term::small(i64::from(*a)).ok_or_else(badarg)?,
                                ],
                            )?,
                        });
                    }
                    make_list(process, terms)?
                }
            },
            "sequential_trace_token" => crate::seq_trace::get_token_term(process, pid)?,
            "suspending" => suspending_term(process, pid)?,
            "trace" => Term::small(trace_mask(process, pid) as i64).unwrap(),
            "registered_name" => {
                let name = process
                    .runtime
                    .as_ref()
                    .ok_or_else(badarg)?
                    .names
                    .lock()
                    .unwrap()
                    .iter()
                    .find_map(|(name, registered)| (*registered == pid).then(|| name.clone()));
                name.map(|name| atom(&name)).unwrap_or(Term::NIL)
            }
            "fullsweep_after" => flag_value(process, "fullsweep_after")
                .unwrap_or_else(|| Term::small(65_535).unwrap()),
            "min_heap_size" => {
                flag_value(process, "min_heap_size").unwrap_or_else(|| Term::small(233).unwrap())
            }
            "min_bin_vheap_size" => {
                Term::small(process.heap.min_bin_vheap_size() as i64).ok_or_else(badarg)?
            }
            "max_heap_size" => max_heap_term(process, pid)?,
            "parent" => atom("undefined"),
            // Port of erts/emulator/beam/erl_bif_info.c:2274-2323 (magic_ref, label,
            // priority_messages), OTP-29.1.1. No magic references live on this heap.
            "magic_ref" => Term::NIL,
            "label" => {
                let label_key = atom("$process_label");
                process
                    .cold
                    .as_ref()
                    .and_then(|cold| {
                        cold.dictionary
                            .iter()
                            .find(|(candidate, _)| term_equal(*candidate, label_key))
                            .map(|(_, value)| *value)
                    })
                    .unwrap_or_else(|| atom("undefined"))
            }
            "priority_messages" => {
                flag_value(process, "priority_messages").unwrap_or_else(|| atom("false"))
            }
            _ => return Err(badarg()),
        };
        if name == "registered_name" && value == Term::NIL && !list_form {
            continue;
        }
        pairs.push(make_tuple(process, &[key, value])?);
    }
    if list_form || all_form {
        make_list(process, pairs)
    } else {
        Ok(pairs.into_iter().next().unwrap_or(Term::NIL))
    }
}

fn charlist(process: &mut Process, value: &str) -> Result<Term, VmError> {
    let mut heap = arinsal_bifs::FragmentingHeap(&mut process.heap);
    TermBuilder::new(&mut heap)
        .string_to_list(value)
        .map_err(|error| VmError::Unsupported(format!("charlist allocation: {error:?}")))
}

/// `#Ref<0.ids reversed>`. OTP's first number is the distribution channel.
/// This node has no distribution table, so every ref prints channel 0, which
/// is what `make_ref/0` produces. A magic ref's sentinel third id is omitted.
fn ref_to_list(term: Term) -> Result<String, VmError> {
    let Some(Identity::Ref { ids, .. }) = term.identity() else {
        return Err(badarg());
    };
    let magic = term.header().is_some_and(|header| header & 63 == 0x3c);
    let mut numbers: Vec<u32> = ids;
    if magic && numbers.last() == Some(&u32::MAX) {
        numbers.pop();
    }
    let mut text = String::from("#Ref<0");
    for id in numbers.iter().rev() {
        text.push('.');
        text.push_str(&id.to_string());
    }
    text.push('>');
    Ok(text)
}

/// `#Port<channel.id>`. Local ports use channel 0, matching `pid_to_list`.
fn port_to_list(term: Term) -> Result<String, VmError> {
    if let Some(id) = term.as_port() {
        return Ok(format!("#Port<0.{id}>"));
    }
    match term.identity() {
        Some(Identity::Port { id, .. }) => Ok(format!("#Port<0.{id}>")),
        _ => Err(badarg()),
    }
}

/// Latin-1 integer list to bytes; `None` when longer than `max` or not a proper list.
fn intlist_to_buf(term: Term, max: usize) -> Option<Vec<u8>> {
    let mut buf = Vec::new();
    let mut current = term;
    while current.classify() == TermKind::List {
        if buf.len() >= max {
            return None;
        }
        // SAFETY: The charlist remains on the caller's heap for this BIF.
        let (head, tail) = unsafe { current.cons_ref()? };
        let byte = head.as_small().filter(|&n| (0..=255).contains(&n))? as u8;
        buf.push(byte);
        current = tail;
    }
    (current == Term::NIL).then_some(buf)
}

fn parse_uint(bytes: &[u8], i: &mut usize) -> Option<u64> {
    if *i >= bytes.len() || !bytes[*i].is_ascii_digit() {
        return None;
    }
    let mut value = 0u64;
    while *i < bytes.len() && bytes[*i].is_ascii_digit() {
        value = value
            .checked_mul(10)?
            .checked_add(u64::from(bytes[*i] - b'0'))?;
        *i += 1;
    }
    Some(value)
}

// Port of erts/emulator/beam/bif.c:4525 (list_to_pid_1), OTP-29.1.1.
fn list_to_pid(_process: &mut Process, chars: Term) -> Result<Term, VmError> {
    let buf = intlist_to_buf(chars, 64).ok_or_else(badarg)?;
    let mut i = 0;
    if buf.get(i) != Some(&b'<') {
        return Err(badarg());
    }
    i += 1;
    let a = parse_uint(&buf, &mut i).ok_or_else(badarg)?;
    if buf.get(i) != Some(&b'.') {
        return Err(badarg());
    }
    i += 1;
    let b = parse_uint(&buf, &mut i).ok_or_else(badarg)?;
    if buf.get(i) != Some(&b'.') {
        return Err(badarg());
    }
    i += 1;
    let c = parse_uint(&buf, &mut i).ok_or_else(badarg)?;
    if buf.get(i) != Some(&b'>') || i + 1 != buf.len() {
        return Err(badarg());
    }
    // Channel 0 is this node. Other channels need a connected dist entry.
    if a != 0 {
        return Err(badarg());
    }
    if b >= (1 << 28) || c > u32::MAX as u64 {
        return Err(badarg());
    }
    Term::pid(b as u32, c as u32).ok_or_else(badarg)
}

// Port of erts/emulator/beam/bif.c:4608 (list_to_port_1), OTP-29.1.1.
fn list_to_port(chars: Term) -> Result<Term, VmError> {
    let buf = intlist_to_buf(chars, 6 + 11 + 21 + 1).ok_or_else(badarg)?;
    if !buf.starts_with(b"#Port<") {
        return Err(badarg());
    }
    let mut i = 6;
    let node = parse_uint(&buf, &mut i).ok_or_else(badarg)?;
    if buf.get(i) != Some(&b'.') {
        return Err(badarg());
    }
    i += 1;
    let num = parse_uint(&buf, &mut i).ok_or_else(badarg)?;
    if buf.get(i) != Some(&b'>') || i + 1 != buf.len() {
        return Err(badarg());
    }
    if node != 0 {
        return Err(badarg());
    }
    if num >= (1_u64 << 60) {
        return Err(badarg());
    }
    Term::port(num).ok_or_else(badarg)
}

// Port of erts/emulator/beam/bif.c:4705 (list_to_ref_1), OTP-29.1.1.
fn list_to_ref(process: &mut Process, chars: Term) -> Result<Term, VmError> {
    // `#Ref<` + up to 4×(10 digits + `.`) + `\0` bound from OTP.
    let buf = intlist_to_buf(chars, 5 + 4 * 11 + 1).ok_or_else(badarg)?;
    if !buf.starts_with(b"#Ref<") {
        return Err(badarg());
    }
    let mut i = 5;
    let mut ints = Vec::new();
    loop {
        let value = parse_uint(&buf, &mut i).ok_or_else(badarg)?;
        if value > u32::MAX as u64 {
            return Err(badarg());
        }
        ints.push(value as u32);
        if buf.get(i) == Some(&b'>') {
            break;
        }
        if buf.get(i) != Some(&b'.') {
            return Err(badarg());
        }
        i += 1;
        if ints.len() > 3 {
            return Err(badarg());
        }
    }
    if i + 1 != buf.len() || ints.len() < 2 {
        return Err(badarg());
    }
    let channel = ints[0];
    if channel != 0 {
        return Err(badarg());
    }
    // Print order is reversed; rebuild as `[n0, n1, n2]`.
    let mut refn = [0u32; 3];
    let n = ints.len() - 1;
    if n != 3 {
        return Err(badarg());
    }
    for (slot, value) in ints[1..].iter().rev().enumerate() {
        refn[slot] = *value;
    }
    let mut heap = arinsal_bifs::FragmentingHeap(&mut process.heap);
    Term::local_ref(&mut heap, refn)
        .map_err(|_| VmError::Trap(crate::exceptions::Trap::error(atom("system_limit"))))
}

/// Local `#Fun<Module.old_index.old_uniq>`, export `fun Module:Name/Arity`.
fn fun_to_list(term: Term) -> Result<String, VmError> {
    // SAFETY: the fun remains in the caller heap for this BIF.
    let view = unsafe { term.fun_ref() }.ok_or_else(badarg)?;
    let text = match view {
        FunRef::Local { entry, .. } => {
            let module = global_atoms()
                .text(entry.module)
                .ok_or_else(|| VmError::Unsupported("fun module atom".into()))?;
            // OTP prints these fields as signed words (erl_printf_term.c FUN_DEF).
            format!(
                "#Fun<{}.{}.{}>",
                module, entry.old_index as i32, entry.old_uniq as i32
            )
        }
        FunRef::Export { entry } => {
            let module = global_atoms()
                .text(entry.module)
                .ok_or_else(|| VmError::Unsupported("fun module atom".into()))?;
            let function = global_atoms()
                .text(entry.function)
                .ok_or_else(|| VmError::Unsupported("fun name atom".into()))?;
            format!(
                "fun {}:{}/{}",
                format_fun_atom(module),
                format_fun_atom(function),
                entry.arity
            )
        }
    };
    Ok(text)
}

// Port of erts/emulator/beam/erl_printf_term.c atom printing used by `~p`, OTP-29.1.1.
fn format_fun_atom(name: &str) -> String {
    let bare = name.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'@'))
        && !matches!(
            name,
            "after"
                | "begin"
                | "case"
                | "try"
                | "receive"
                | "when"
                | "end"
                | "of"
                | "catch"
                | "if"
                | "maybe"
                | "else"
        );
    if bare {
        return name.to_owned();
    }
    let mut quoted = String::with_capacity(name.len() + 2);
    quoted.push('\'');
    for ch in name.chars() {
        match ch {
            '\\' => quoted.push_str("\\\\"),
            '\'' => quoted.push_str("\\'"),
            ch if ch.is_control() => {
                use std::fmt::Write;
                let _ = write!(quoted, "\\x{{{:x}}}", ch as u32);
            }
            ch => quoted.push(ch),
        }
    }
    quoted.push('\'');
    quoted
}

/// Process and dictionary BIF entry points for `erlang` and `erts_internal`.
/// Erlang wrappers with neighboring arities must fall through to the loaded BEAM.
/// `spawn_request` and `dist_spawn_request` are the exception: only the
/// `erts_internal` entries are BIFs, so the `erlang` wrappers stay in BEAM.
pub(crate) const IMPLEMENTED: &[(&str, &str, u8)] = &[
    ("erlang", "exit", 1),
    ("erlang", "group_leader", 0),
    ("erts_internal", "group_leader", 2),
    ("erts_internal", "group_leader", 3),
    ("erlang", "processes", 0),
    ("erlang", "processes_next", 1),
    ("erlang", "pid_to_list", 1),  // elixir_loop1
    ("erlang", "ref_to_list", 1),  // mix_loop6
    ("erlang", "port_to_list", 1), // mix_loop6
    ("erlang", "list_to_pid", 1),
    ("erlang", "list_to_port", 1),
    ("erlang", "list_to_ref", 1),
    ("erlang", "fun_to_list", 1), // mix_loop6
    // `i_yield` is an OTP instruction, not an Erlang wrapper interception.
    ("erlang", "yield", 0),
    ("erlang", "process_flag", 2),
    ("erts_internal", "process_flag", 3),
    ("erlang", "process_info", 1),
    ("erlang", "process_info", 2),
    ("erlang", "put", 2),
    ("erlang", "get", 0),
    ("erlang", "get", 1),
    ("erlang", "get_keys", 0),
    ("erlang", "get_keys", 1),
    ("erlang", "erase", 0),
    ("erlang", "erase", 1),
    ("erlang", "alias", 1),
    ("erlang", "unalias", 1),
    ("erlang", "hibernate", 3),
    // `i_hibernate` is an OTP instruction, not an Erlang wrapper interception.
    ("erlang", "hibernate", 0),
    ("erts_internal", "suspend_process", 2),
    ("erlang", "resume_process", 1),
    ("erts_internal", "process_display", 2),
    ("erts_internal", "spawn_request", 4),
    ("erts_internal", "dist_spawn_request", 4),
    ("erlang", "spawn_request_abandon", 1),
    ("erts_internal", "processes_next", 1),
    ("erts_internal", "trace", 3),
    ("erlang", "trace", 3),
    ("erlang", "trace_info", 2),
    ("erts_internal", "trace", 4),
    ("erts_internal", "trace_pattern", 3),
    ("erts_internal", "trace_pattern", 4),
    ("erts_internal", "trace_session_create", 3),
    ("erts_internal", "trace_session_destroy", 1),
    ("erts_internal", "trace_info", 3),
    ("erts_internal", "is_system_process", 1),
    ("erlang", "fun_info_mfa", 1),
];

pub(crate) fn recognizes(module: &str, function: &str, arity: u8) -> bool {
    super::listed(IMPLEMENTED, module, function, arity)
}

fn known_info_item(name: &str) -> bool {
    matches!(
        name,
        "current_function"
            | "initial_call"
            | "status"
            | "messages"
            | "message_queue_len"
            | "links"
            | "dictionary"
            | "trap_exit"
            | "error_handler"
            | "heap_size"
            | "stack_size"
            | "memory"
            | "garbage_collection"
            | "group_leader"
            | "reductions"
            | "priority"
            | "trace"
            | "binary"
            | "sequential_trace_token"
            | "catchlevel"
            | "backtrace"
            | "last_calls"
            | "total_heap_size"
            | "suspending"
            | "min_heap_size"
            | "min_bin_vheap_size"
            | "max_heap_size"
            | "current_location"
            | "current_stacktrace"
            | "message_queue_data"
            | "garbage_collection_info"
            | "fullsweep_after"
            | "parent"
            | "async_dist"
            | "magic_ref"
            | "label"
            | "priority_messages"
            | "monitors"
            | "monitored_by"
            | "registered_name"
            | "save_calls"
            | "sensitive"
    )
}

fn validate_info_item(item: Term) -> Result<(), VmError> {
    if let Some(items) = list(item) {
        for item in items {
            if dictionary_lookup(item).is_some() {
                continue;
            }
            let name = atom_name(item).ok_or_else(badarg)?;
            if !known_info_item(&name) {
                return Err(badarg());
            }
        }
        return Ok(());
    }
    if dictionary_lookup(item).is_some() {
        return Ok(());
    }
    let name = atom_name(item).ok_or_else(badarg)?;
    if known_info_item(&name) {
        Ok(())
    } else {
        Err(badarg())
    }
}

fn dictionary_lookup(selector: Term) -> Option<(Term, Term)> {
    let (tag, key) = tuple2(selector)?;
    (tag == atom("dictionary")).then_some((key, selector))
}

/// The native function and source location a native caller is executing a BIF at.
pub(crate) fn native_call_site(
    process: &Process,
) -> Option<(crate::native_bridge::NativeFunction, usize)> {
    let pc = process.cold.as_ref()?.native_call_pc;
    if pc == 0 {
        return None;
    }
    let tag = arinsal_beamasm::module::RETURN_SITE_TAG;
    let pc = if pc & tag != 0 { (pc & !tag) - 1 } else { pc };
    crate::native_function_at(pc).map(|function| (function, pc))
}

fn resolve_mfa(vm: Option<&Vm>, process: &Process) -> Result<(String, String, u8), VmError> {
    if let Some((module, function, arity)) =
        process.cold.as_ref().and_then(|cold| cold.dirty_bif_mfa)
    {
        return Ok((module.to_owned(), function.to_owned(), arity));
    }
    // A trapped BIF reports its continuation export, as erts does.
    if let Some((module, rest)) = process
        .cold
        .as_ref()
        .and_then(|cold| cold.bif_trap.as_ref())
        .and_then(|pending| pending.continuation.split_once(':'))
        && let Some((function, arity)) = rest.rsplit_once('/')
        && let Ok(arity) = arity.parse::<u8>()
    {
        return Ok((module.to_owned(), function.to_owned(), arity));
    }
    // A send suspended on a busy port yields to the send/2 export (bif.c:2581 SEND_YIELD).
    if process.cold.as_ref().and_then(|cold| cold.native_retry)
        == Some(arinsal_beamasm::dispatch::SEND_DISPATCH_IDENTITY)
    {
        return Ok(("erlang".to_owned(), "send".to_owned(), 2));
    }
    if let Some((function, _)) = native_call_site(process) {
        return Ok((function.module, function.function, function.arity));
    }
    // A process in native code (a receive wait, a yield) is at a native address;
    // `module`/`ip` only describe its interpreter state.
    // A process woken in native code handles its signals before the native entry takes
    // `native_pc`; its position is then still in `c_p->i`, which interpreted slices clear.
    let native_position = process
        .native_pc
        .or_else(|| Some(process.header.i as usize).filter(|&pc| pc != 0));
    if let Some(function) = native_position.and_then(crate::native_bridge::native_function_at) {
        return Ok((function.module, function.function, function.arity));
    }
    if let Some(vm) = vm {
        let module = vm.code.modules.get(process.module).ok_or_else(badarg)?;
        let (function, arity) = module.function_at(process.ip).unwrap_or(("undefined", 0));
        return Ok((module.name.clone(), function.to_owned(), arity));
    }
    let runtime = process.runtime.clone().ok_or_else(badarg)?;
    runtime
        .with_modules(|modules| {
            let module = modules.get(process.module)?;
            let (function, arity) = module.function_at(process.ip).unwrap_or(("undefined", 0));
            Some((module.name.clone(), function.to_owned(), arity))
        })
        .ok_or_else(badarg)
}

/// `module:function/arity + offset` of an interpreter continuation or native address.
fn pc_description(modules: &[std::sync::Arc<crate::Module>], word: Term, native: bool) -> String {
    let address = word.tagged_word() as usize;
    let is_native =
        native || address & 3 == 0 && crate::native_bridge::is_native_function_at(address);
    if is_native && let Some(function) = crate::native_bridge::native_function_at(address) {
        return format!(
            "{}:{}/{} + {}",
            function.module,
            function.function,
            function.arity,
            address - function.start
        );
    }
    if let Some((_, module, ip)) = crate::stacktrace::decode_tag(word)
        && let Some(code) = modules.get(module)
        && let Some((start, name, arity)) = code.functions.iter().rev().find(|(s, _, _)| *s <= ip)
    {
        return format!("{}:{}/{} + {}", code.name, name, arity, ip - start);
    }
    "unknown function".into()
}

/// The text of `process_info(Pid, backtrace)`: program counter and the stack, innermost first.
// Port of erts/emulator/beam/erl_process.c:14896 (erts_stack_dump), :14911
// (erts_program_counter_info), :14970 (stack_element_dump), OTP-29.1.1.
fn backtrace_text(
    vm: Option<&Vm>,
    process: &mut Process,
    running: bool,
) -> Result<Vec<u8>, VmError> {
    if process
        .self_pid
        .is_some_and(|pid| crate::trace::is_sensitive(process, pid))
    {
        return Ok(Vec::new());
    }
    match vm {
        Some(vm) => Ok(backtrace_with(&vm.code.modules, process, running)),
        None => {
            let runtime = process.runtime.clone().ok_or_else(badarg)?;
            Ok(runtime.with_modules(|modules| backtrace_with(modules, process, running)))
        }
    }
}

fn backtrace_with(
    modules: &[std::sync::Arc<crate::Module>],
    process: &Process,
    running: bool,
) -> Vec<u8> {
    use std::fmt::Write as _;
    let print = |word: Term| match arinsal_term::to_owned(word) {
        Ok(owned) => super::sys::print_otp_term(&owned, i32::MAX as usize),
        Err(_) => "<unprintable>".into(),
    };
    let mut text = String::new();
    let native_pc = process
        .native_pc
        .filter(|pc| crate::native_bridge::is_native_function_at(*pc))
        .or_else(|| {
            let pc = process.cold.as_ref()?.native_call_pc;
            let tag = arinsal_beamasm::module::RETURN_SITE_TAG;
            let pc = if pc & tag != 0 { (pc & !tag) - 1 } else { pc };
            (pc != 0 && crate::native_bridge::is_native_function_at(pc)).then_some(pc)
        });
    let (address, description) = match native_pc {
        Some(pc) => (pc, pc_description(modules, Term::NIL, true)),
        None => (process.ip, String::new()),
    };
    let description = if native_pc.is_some() {
        let function = crate::native_bridge::native_function_at(address);
        function.map_or(description, |f| {
            format!(
                "{}:{}/{} + {}",
                f.module,
                f.function,
                f.arity,
                address - f.start
            )
        })
    } else {
        modules
            .get(process.module)
            .and_then(|code| {
                let (start, name, arity) = code
                    .functions
                    .iter()
                    .rev()
                    .find(|(s, _, _)| *s <= process.ip)?;
                Some(format!(
                    "{}:{}/{} + {}",
                    code.name,
                    name,
                    arity,
                    process.ip - start
                ))
            })
            .unwrap_or_else(|| "invalid".into())
    };
    let _ = writeln!(text, "Program counter: {address:#018x} ({description})");
    if !running {
        let arity = if native_pc.is_some() {
            usize::from(process.header.arity)
        } else {
            modules
                .get(process.module)
                .and_then(|code| code.function_at(process.ip))
                .map_or(0, |(_, arity)| usize::from(arity))
        };
        let _ = writeln!(text, "arity = {arity}");
        for argument in process.x.iter().take(arity) {
            let _ = writeln!(text, "   {}", print(*argument));
        }
    }
    let base = process.heap.frame_pointer();
    let mut yreg = 0usize;
    for index in 0..process.heap.stack_words() {
        let Some(word) = process.heap.stack_get(index) else {
            continue;
        };
        let raw = word.tagged_word() as usize;
        let native_return = raw & 3 == 0 && crate::native_bridge::is_native_function_at(raw);
        let continuation = matches!(crate::stacktrace::decode_tag(word), Some((false, _, _)));
        // Port of erts/emulator/beam/erl_process.c:14938-14953
        // (erts_internal_fun_description_from_pc), OTP-29.1.1: the exit bridge is the
        // return address of a process's first call, erts' `beam_normal_exit`.
        let normal_exit = raw == crate::native_bridge::bridge_return_address();
        if native_return || continuation || normal_exit {
            let slot = base.wrapping_add(index * 8);
            let description = if normal_exit {
                "<terminate process normally>".into()
            } else {
                pc_description(modules, word, native_return)
            };
            let _ = writeln!(
                text,
                "\n{slot:#018x} Return addr {raw:#018x} ({description})"
            );
            yreg = 0;
            continue;
        }
        let _ = write!(text, "{:<8} ", format!("y({yreg})"));
        yreg += 1;
        if word.classify() == TermKind::Catch {
            let _ = writeln!(
                text,
                "Catch {raw:#018x} ({})",
                pc_description(modules, word, false)
            );
        } else {
            let _ = writeln!(text, "{}", print(word));
        }
    }
    text.into_bytes()
}

fn current_stacktrace(vm: Option<&Vm>, process: &mut Process) -> Result<Term, VmError> {
    // Port of erts/emulator/beam/erl_bif_info.c:2397-2404 (current_stacktrace), OTP-29.1.1:
    // erts reads the runtime-wide limit, shared by every scheduler.
    let depth = process.runtime.as_ref().map_or_else(
        || vm.map(|vm| vm.backtrace_depth).unwrap_or(8),
        |runtime| runtime.backtrace_depth.load(Ordering::Acquire),
    );
    if let Some(vm) = vm {
        return crate::stacktrace::build(&vm.code.modules, process, None, depth);
    }
    let runtime = process.runtime.clone().ok_or_else(badarg)?;
    runtime.with_modules(|modules| crate::stacktrace::build(modules, process, None, depth))
}

pub(crate) fn live(process: &Process, pid: Pid) -> Result<bool, VmError> {
    Ok(process
        .runtime
        .as_ref()
        .ok_or_else(badarg)?
        .scheduler()?
        .lookup(pid))
}

// Port of erts/emulator/beam/erl_bif_info.c:1555 (process_info_2), OTP-29.1.1.
fn process_info_call(
    vm: &Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    target: Term,
    item: Option<Term>,
) -> Result<Term, VmError> {
    if let Some(done) = crate::signals::poll(process, ctx.pid())? {
        return Ok(done);
    }
    if let Some(item) = item {
        validate_info_item(item)?;
    }
    let pid = Pid::from_term(target).ok_or_else(badarg)?;
    if pid == ctx.pid() {
        return process_info(Some(vm), process, ctx, item, atom("running"), true);
    }
    if !live(process, pid)? {
        return Ok(atom("undefined"));
    }
    let items = match item {
        Some(item) => Some(Message::copy_from(item)?),
        None => None,
    };
    match crate::signals::submit(
        process,
        ctx,
        pid,
        crate::signals::RemoteOp::Info { items },
        Some(crate::signals::WaitKind::Info),
    )? {
        crate::signals::Submit::Sent(_) => Err(crate::signals::await_reply()),
        crate::signals::Submit::Dead => Ok(atom("undefined")),
    }
}

pub(crate) fn collect_heap(
    process: &mut Process,
    major: bool,
    keep: &mut [Term],
) -> Result<(), VmError> {
    if !process.gc_enabled {
        process.gc_deferred = true;
        return Ok(());
    }
    // A requested major sweep must not change the process's own `fullsweep_after`.
    let fullsweep_after = process.heap.fullsweep_after();
    if major {
        process.heap.set_fullsweep_after(0);
    }
    // Port of erts/emulator/beam/erl_proc_sig_queue.c:8257 (message queue GC scan), OTP-29.1.1.
    let collected = process.collect_heap_roots(process.gc_live, keep, 0);
    process.heap.set_fullsweep_after(fullsweep_after);
    collected?;
    Ok(())
}

fn gc_message(process: &mut Process, request_id: Term, ok: bool) -> Result<Term, VmError> {
    make_tuple(
        process,
        &[
            atom("garbage_collect"),
            request_id,
            atom(if ok { "true" } else { "false" }),
        ],
    )
}

fn set_group_leader(process: &mut Process, leader: Pid) -> Result<(), VmError> {
    let term = leader.to_term().ok_or_else(badarg)?;
    set_flag(process, "group_leader", term);
    process.cold_mut().group_leader = Some(leader);
    Ok(())
}

/// Answer a request signal on the target process.
///
/// Port of erts/emulator/beam/erl_proc_sig_queue.c:6794 (handle_process_info)
/// and the group-leader / RPC handlers beside it, OTP-29.1.1.
pub(crate) fn fulfill_request(
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    id: u64,
    op: crate::signals::RemoteOp,
) -> Result<Term, VmError> {
    let reference = crate::signals::reference(process, id)?;
    match op {
        crate::signals::RemoteOp::Info { items } => {
            let item = match items {
                Some(message) => Some(message.decode_into(process)?),
                None => None,
            };
            // Port of erts/emulator/beam/erl_process.c:9305 (erts_process_state2status), OTP-29.1.1:
            // a process executing a dirty job is running, and so is one handling its signals
            // on a dirty scheduler (ERTS_PSFLG_DIRTY_RUNNING_SYS).
            let status = atom(if ctx.dirty_running() || ctx.scheduler_type().is_dirty() {
                "running"
            } else if crate::signals::is_waiting(process, ctx.pid()) {
                "waiting"
            } else {
                "runnable"
            });
            let info = process_info(None, process, ctx, item, status, false)?;
            make_tuple(process, &[reference, info])
        }
        crate::signals::RemoteOp::GroupLeader { leader } => {
            set_group_leader(process, leader)?;
            make_tuple(process, &[reference, atom("true")])
        }
        crate::signals::RemoteOp::Collect { request_id, major } => {
            // The id lives in the signal envelope, not in a GC root. Collect
            // first, then install it on the heap the reply is built in.
            crate::natives::code::code_mod_permission_before_gc(process, ctx.pid());
            let collected = collect_heap(process, major, &mut []);
            crate::natives::code::code_mod_permission_after_gc(process, ctx.pid());
            collected?;
            let request_id = request_id.decode_into(process)?;
            gc_message(process, request_id, true)
        }
        crate::signals::RemoteOp::SystemTaskTest { request_id } => {
            let request_id = request_id.decode_into(process)?;
            make_tuple(
                process,
                &[atom("system_task_test"), request_id, atom("true")],
            )
        }
        crate::signals::RemoteOp::Display => {
            eprintln!("process {:?}: backtrace", ctx.pid());
            make_tuple(process, &[reference, atom("true")])
        }
        crate::signals::RemoteOp::Alive => make_tuple(process, &[reference, atom("true")]),
        crate::signals::RemoteOp::PrioSig => Err(VmError::Unsupported(
            "priority signal task has no reply".into(),
        )),
        crate::signals::RemoteOp::CheckProcessCode {
            module,
            native,
            async_request,
            kill,
        } => {
            // Port of erts/emulator/beam/beam_bif_load.c (erts_check_process_code), OTP-29.1.1:
            // a module without old code is never referenced.
            let references = module.is_some_and(|module| process.references_code(module, native));
            if kill && references {
                let reason = Message::copy_from(atom("kill"))?;
                ctx.signal(ctx.pid(), Signal::Exit(reason))
                    .map_err(|error| VmError::Unsupported(format!("CPC kill signal: {error}")))?;
            }
            let result = atom(if references { "true" } else { "false" });
            if let Some(request) = async_request {
                let request = request.decode_into(process)?;
                make_tuple(process, &[atom("check_process_code"), request, result])
            } else {
                make_tuple(process, &[reference, result])
            }
        }
    }
}

pub(crate) fn failure_reply(
    process: &mut Process,
    id: u64,
    op: crate::signals::RemoteOp,
) -> Result<Term, VmError> {
    let reference = crate::signals::reference(process, id)?;
    match op {
        crate::signals::RemoteOp::Info { .. } => {
            make_tuple(process, &[reference, atom("undefined")])
        }
        crate::signals::RemoteOp::GroupLeader { .. } | crate::signals::RemoteOp::Display => {
            make_tuple(process, &[reference, atom("badarg")])
        }
        crate::signals::RemoteOp::Alive => make_tuple(process, &[reference, atom("false")]),
        crate::signals::RemoteOp::PrioSig => Err(VmError::Unsupported(
            "priority signal task has no reply".into(),
        )),
        crate::signals::RemoteOp::Collect { request_id, .. } => {
            let request_id = request_id.decode_into(process)?;
            gc_message(process, request_id, false)
        }
        crate::signals::RemoteOp::SystemTaskTest { request_id } => {
            let request_id = request_id.decode_into(process)?;
            make_tuple(
                process,
                &[atom("system_task_test"), request_id, atom("false")],
            )
        }
        crate::signals::RemoteOp::CheckProcessCode { async_request, .. } => {
            let result = atom("false");
            if let Some(request) = async_request {
                let request = request.decode_into(process)?;
                make_tuple(process, &[atom("check_process_code"), request, result])
            } else {
                make_tuple(process, &[reference, result])
            }
        }
    }
}

fn processes(process: &mut Process) -> Result<Term, VmError> {
    // Port of erts/emulator/beam/bif.c:4097 (processes_0), OTP-29.1.1.
    let runtime = process.runtime.as_ref().ok_or_else(badarg)?;
    let scheduler = runtime.scheduler()?;
    let pids = runtime
        .processes
        .lock()
        .unwrap()
        .iter()
        .copied()
        .filter(|pid| scheduler.lookup(*pid))
        .filter_map(Pid::to_term)
        .collect::<Vec<_>>();
    make_list(process, pids)
}

// Port of erts/emulator/beam/bif.c:4914 (erts_internal_group_leader_2)
// and erts/preloaded/src/erlang.erl:3328 (group_leader/2), OTP-29.1.1.
fn group_leader_call(
    module: &str,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    leader: Term,
    target: Term,
    signal_ref: Option<Term>,
) -> Result<Term, VmError> {
    if let Some(done) = crate::signals::poll(process, ctx.pid())? {
        return Ok(done);
    }
    let internal = module == "erts_internal";
    let Some(leader) = Pid::from_term(leader) else {
        return if internal {
            Ok(atom("badarg"))
        } else {
            Err(badarg())
        };
    };
    let Some(pid) = Pid::from_term(target) else {
        return if internal {
            Ok(atom("badarg"))
        } else {
            Err(badarg())
        };
    };
    if pid == ctx.pid() {
        set_group_leader(process, leader)?;
        return Ok(atom("true"));
    }
    if !live(process, pid)? {
        if let Some(reference) = signal_ref {
            let reply = make_tuple(process, &[reference, atom("badarg")])?;
            process.inbox.push_back(reply);
            return Ok(atom("ok"));
        }
        return if internal {
            Ok(atom("badarg"))
        } else {
            Err(badarg())
        };
    }
    // erts_internal:group_leader/2 reports the lock as busy and lets the
    // Erlang wrapper send group_leader/3. erlang:group_leader/2 waits here.
    if internal && signal_ref.is_none() {
        return Ok(atom("false"));
    }
    let wait = if signal_ref.is_some() {
        None
    } else {
        Some(crate::signals::WaitKind::GroupLeader)
    };
    let reply_id = match signal_ref {
        Some(reference) => Some(crate::signals::ref_id(reference).ok_or_else(badarg)?),
        None => None,
    };
    match crate::signals::submit_id(
        process,
        ctx,
        pid,
        reply_id.unwrap_or(0),
        crate::signals::RemoteOp::GroupLeader { leader },
        wait,
    )? {
        crate::signals::Submit::Sent(_) if signal_ref.is_some() => Ok(atom("ok")),
        crate::signals::Submit::Sent(_) => Err(crate::signals::await_reply()),
        crate::signals::Submit::Dead if signal_ref.is_some() => {
            let reference = signal_ref.ok_or_else(badarg)?;
            let reply = make_tuple(process, &[reference, atom("badarg")])?;
            process.inbox.push_back(reply);
            Ok(atom("ok"))
        }
        crate::signals::Submit::Dead => Err(badarg()),
    }
}

// Port of erts/emulator/beam/erl_bif_info.c:4133 (erts_internal_process_display_2),
// OTP-29.1.1.
fn process_display_call(
    module: &str,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    target: Term,
    display: Term,
) -> Result<Term, VmError> {
    if let Some(done) = crate::signals::poll(process, ctx.pid())? {
        return Ok(done);
    }
    let internal = module == "erts_internal";
    if display != atom("backtrace") {
        return if internal {
            Ok(atom("badopt"))
        } else {
            Err(badarg())
        };
    }
    let Some(pid) = Pid::from_term(target) else {
        return if internal {
            Ok(atom("badarg"))
        } else {
            Err(badarg())
        };
    };
    if pid == ctx.pid() {
        eprintln!("process {pid:?}: backtrace");
        return Ok(atom("true"));
    }
    if !live(process, pid)? {
        return if internal {
            Ok(atom("badarg"))
        } else {
            Err(badarg())
        };
    }
    let wait = if internal {
        None
    } else {
        Some(crate::signals::WaitKind::Display)
    };
    match crate::signals::submit(process, ctx, pid, crate::signals::RemoteOp::Display, wait)? {
        crate::signals::Submit::Sent(id) if internal => crate::signals::reference(process, id),
        crate::signals::Submit::Sent(_) => Err(crate::signals::await_reply()),
        crate::signals::Submit::Dead => {
            if internal {
                Ok(atom("badarg"))
            } else {
                Err(badarg())
            }
        }
    }
}

/// Dispatch process-local BIFs that use the scheduler context.
pub(crate) fn call(
    vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    module: &str,
    function: &str,
    args: super::NativeArgs<'_>,
) -> Option<Result<Term, VmError>> {
    args.with_values(process, |process, values| {
        call_values(vm, process, ctx, module, function, values)
    })
}

fn call_values(
    vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    module: &str,
    function: &str,
    args: &[Term],
) -> Option<Result<Term, VmError>> {
    if module != "erlang" && module != "erts_internal" {
        return None;
    }
    // `erlang:spawn_request/1..5` is a BEAM wrapper. Only the internal entry
    // is a BIF; claiming the name here would turn `/3` into `badarg`.
    if matches!(function, "spawn_request" | "dist_spawn_request") && module != "erts_internal" {
        return None;
    }
    // Erlang wrappers around these BIFs must keep running as BEAM.
    if function == "trace" && module != "erts_internal" {
        return None;
    }
    if function == "fun_info_mfa" && module != "erlang" {
        return None;
    }
    if !recognizes(module, function, args.len() as u8) {
        return None;
    }
    let result = (|| -> Result<Term, VmError> {
        match (function, args) {
            ("exit", [reason]) => {
                // Port of erts/emulator/beam/bif.c:1536 (exit_1), OTP-29.1.1.
                Err(VmError::Trap(crate::exceptions::Trap::exit(*reason)))
            }
            ("group_leader", []) => Ok(process
                .cold
                .as_ref()
                .and_then(|cold| cold.group_leader)
                .unwrap_or_else(|| ctx.pid())
                .to_term()
                .unwrap_or(Term::NIL)),
            ("group_leader", [leader, pid]) if module == "erts_internal" => {
                group_leader_call(module, process, ctx, *leader, *pid, None)
            }
            ("group_leader", [leader, pid, reference]) if module == "erts_internal" => {
                group_leader_call(module, process, ctx, *leader, *pid, Some(*reference))
            }
            ("processes", []) => processes(process),
            // Port of erts/emulator/beam/erl_bif_info.c:4932-4945,
            // OTP-29.1.1. System processes are tracked when the VM creates them.
            ("is_system_process", [target]) if module == "erts_internal" => {
                let pid = Pid::from_term(*target).ok_or_else(badarg)?;
                let is_system = process
                    .runtime
                    .as_ref()
                    .is_some_and(|runtime| runtime.system_processes.lock().unwrap().contains(&pid));
                Ok(atom(if is_system { "true" } else { "false" }))
            }
            // Port of erts/emulator/beam/bif.c:4505 (pid_to_list_1), OTP-29.1.1.
            ("pid_to_list", [pid]) if module == "erlang" => {
                if pid.classify() != TermKind::Pid {
                    return Err(badarg());
                }
                let Some(Identity::Pid {
                    node,
                    index,
                    serial,
                    ..
                }) = pid.identity()
                else {
                    return Err(badarg());
                };
                let node = if node == arinsal_term::atoms::NONAME {
                    "0".to_owned()
                } else {
                    global_atoms().text(node).ok_or_else(badarg)?.to_string()
                };
                let value = format!("<{node}.{index}.{serial}>");
                let mut heap = arinsal_bifs::FragmentingHeap(&mut process.heap);
                TermBuilder::new(&mut heap)
                    .string_to_list(&value)
                    .map_err(|error| {
                        VmError::Unsupported(format!("pid_to_list allocation: {error:?}"))
                    })
            }
            // Port of erts/emulator/beam/bif.c:4459 (ref_to_list_1), OTP-29.1.1.
            // Print is erl_printf_term.c REF_DEF: `#Ref<channel.n[k]...n[0]>`.
            ("ref_to_list", [reference]) if module == "erlang" => {
                charlist(process, &ref_to_list(*reference)?)
            }
            // Port of erts/emulator/beam/bif.c:4512 (port_to_list_1), OTP-29.1.1.
            ("port_to_list", [port]) if module == "erlang" => {
                charlist(process, &port_to_list(*port)?)
            }
            // Port of erts/emulator/beam/bif.c:4525 (list_to_pid_1), OTP-29.1.1.
            ("list_to_pid", [chars]) if module == "erlang" => list_to_pid(process, *chars),
            // Port of erts/emulator/beam/bif.c:4608 (list_to_port_1), OTP-29.1.1.
            ("list_to_port", [chars]) if module == "erlang" => list_to_port(*chars),
            // Port of erts/emulator/beam/bif.c:4705 (list_to_ref_1), OTP-29.1.1.
            ("list_to_ref", [chars]) if module == "erlang" => list_to_ref(process, *chars),
            // Port of erts/emulator/beam/bif.c:4487 (fun_to_list_1), OTP-29.1.1.
            ("fun_to_list", [fun]) if module == "erlang" => charlist(process, &fun_to_list(*fun)?),
            // Port of erts/emulator/beam/emu/trace_instrs.tab:110 (i_yield), OTP-29.1.1:
            // the process goes to the back of its run queue and returns `true`.
            ("yield", []) if module == "erlang" => {
                process.force_yield = true;
                Ok(atom("true"))
            }
            ("process_flag", [name, value]) => {
                if *name == atom("monitor_nodes") {
                    let enabled = match *value {
                        value if value == atom("true") => true,
                        value if value == atom("false") => false,
                        _ => return Err(badarg()),
                    };
                    let previous = crate::node_tables::lock().monitor_nodes(
                        ctx.pid(),
                        crate::node_tables::NodeMonitorOptions::default(),
                        enabled,
                    );
                    let count = process.cold.as_ref().map_or(0, |cold| cold.monitor_nodes);
                    process.cold_mut().monitor_nodes = if enabled {
                        count.saturating_add(1)
                    } else {
                        count.saturating_sub(1)
                    };
                    return Term::small(previous as i64).ok_or_else(badarg);
                }
                if let Ok(arinsal_etf::OwnedTerm::Tuple(parts)) = &arinsal_term::to_owned(*name)
                    && parts.len() == 2
                    && parts[0] == arinsal_etf::OwnedTerm::atom("monitor_nodes")
                {
                    let enabled = match *value {
                        value if value == atom("true") => true,
                        value if value == atom("false") => false,
                        _ => return Err(badarg()),
                    };
                    let options = crate::node_tables::parse_nodes_monitor_options(&parts[1])
                        .map_err(|_| badarg())?;
                    let previous =
                        crate::node_tables::lock().monitor_nodes(ctx.pid(), options, enabled);
                    let count = process.cold.as_ref().map_or(0, |cold| cold.monitor_nodes);
                    process.cold_mut().monitor_nodes = if enabled {
                        count.saturating_add(1)
                    } else {
                        count.saturating_sub(1)
                    };
                    return Term::small(previous as i64).ok_or_else(badarg);
                }
                let name = atom_name(*name).ok_or_else(badarg)?;
                if name == "max_heap_size" {
                    return max_heap_flag(process, ctx, *value);
                }
                if name == "scheduler" {
                    let scheduler = value
                        .as_small()
                        .filter(|&scheduler| {
                            scheduler >= 0 && scheduler as usize <= ctx.scheduler_count()
                        })
                        .ok_or_else(badarg)? as usize;
                    // Port of erts/emulator/beam/bif.c:2068-2097 (process scheduler binding), OTP-29.1.1.
                    let (previous, should_yield) = ctx.bind_scheduler(scheduler);
                    if should_yield {
                        ctx.consume(ctx.remaining());
                    }
                    return Term::small(previous as i64).ok_or_else(badarg);
                }
                let previous = flag(process, &name, *value)?;
                if name == "message_queue_data" {
                    // Port of erts/emulator/beam/bif.c:process_flag_2, OTP-29.1.1.
                    ctx.set_parallel_signal_buffers(*value == atom("off_heap"));
                }
                if name == "priority" {
                    // Port of erts/emulator/beam/erl_process.c (erts_set_process_priority),
                    // OTP-29.1.1: the scheduler queues the process at the new priority.
                    let priority = atom_name(*value)
                        .as_deref()
                        .and_then(scheduler_priority)
                        .ok_or_else(badarg)?;
                    ctx.set_priority(priority);
                }
                Ok(previous)
            }
            ("process_flag", [target, name, value]) if module == "erts_internal" => {
                if Pid::from_term(*target) != Some(ctx.pid()) {
                    return Err(badarg());
                }
                let name = atom_name(*name).ok_or_else(badarg)?;
                if name != "save_calls" {
                    return Err(badarg());
                }
                flag(process, &name, *value)
            }
            ("process_info", [pid]) => process_info_call(vm, process, ctx, *pid, None),
            ("process_info", [pid, item]) => process_info_call(vm, process, ctx, *pid, Some(*item)),
            ("put", [key, value]) => {
                let cold = process.cold_mut();
                let previous = cold
                    .dictionary
                    .iter()
                    .find_map(|(stored, old)| term_equal(*stored, *key).then_some(*old))
                    .unwrap_or_else(|| atom("undefined"));
                // The dictionary lives on the process heap like erts' ProcDict, so
                // GC roots it and releases off-heap owners (magic refs) once erased.
                // Port of erts/emulator/beam/erl_process_dict.c (pd_hash_put), OTP-29.1.1.
                let (key, value) = (*key, *value);
                if let Some((stored, old)) = cold
                    .dictionary
                    .iter_mut()
                    .find(|(stored, _)| term_equal(*stored, key))
                {
                    *stored = key;
                    *old = value;
                } else {
                    cold.dictionary.push((key, value));
                }
                Ok(previous)
            }
            ("get", []) => {
                let raw = process
                    .cold
                    .as_ref()
                    .map(|c| {
                        c.dictionary
                            .iter()
                            .map(|(k, v)| (*k, *v))
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                let entries = raw
                    .into_iter()
                    .map(|(k, v)| make_tuple(process, &[k, v]))
                    .collect::<Result<Vec<_>, _>>()?;
                make_list(process, entries)
            }
            ("get", [key]) => Ok(process
                .cold
                .as_ref()
                .and_then(|c| {
                    c.dictionary
                        .iter()
                        .find(|(k, _)| term_equal(*k, *key))
                        .map(|(_, v)| *v)
                })
                .unwrap_or(atom("undefined"))),
            ("get_keys", []) => make_list(
                process,
                process
                    .cold
                    .as_ref()
                    .map(|c| c.dictionary.iter().map(|(k, _)| *k).collect::<Vec<_>>())
                    .unwrap_or_default(),
            ),
            ("get_keys", [value]) => make_list(
                process,
                process
                    .cold
                    .as_ref()
                    .map(|c| {
                        c.dictionary
                            .iter()
                            .filter_map(|(k, v)| term_equal(*v, *value).then_some(*k))
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default(),
            ),
            ("erase", []) => {
                let raw = process
                    .cold
                    .as_mut()
                    .map(|c| {
                        std::mem::take(&mut c.dictionary)
                            .into_iter()
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                let entries = raw
                    .into_iter()
                    .map(|(k, v)| make_tuple(process, &[k, v]))
                    .collect::<Result<Vec<_>, _>>()?;
                make_list(process, entries)
            }
            ("erase", [key]) => {
                let Some(dictionary) = process.cold.as_mut().map(|cold| &mut cold.dictionary)
                else {
                    return Ok(atom("undefined"));
                };
                if let Some(index) = dictionary.iter().position(|(k, _)| term_equal(*k, *key)) {
                    Ok(dictionary.remove(index).1)
                } else {
                    Ok(atom("undefined"))
                }
            }
            ("alias", [options]) => create_alias(process, ctx, &list(*options).ok_or_else(badarg)?),
            ("unalias", [reference]) => {
                let id = crate::signals::ref_id(*reference).ok_or_else(badarg)?;
                let owned = process
                    .cold
                    .as_mut()
                    .is_some_and(|cold| cold.aliases.remove(&id));
                if owned && let Some(runtime) = &process.runtime {
                    runtime.alias_bind(id, None);
                }
                Ok(atom(if owned { "true" } else { "false" }))
            }
            ("hibernate", [module, function, args]) => {
                hibernate(process, ctx, *module, *function, *args)
            }
            ("hibernate", []) if module == "erlang" => hibernate_zero(process, ctx),
            ("suspend_process", [pid, options]) if module == "erts_internal" => {
                suspend_process(process, ctx, *pid, *options)
            }
            ("resume_process", [pid]) => resume_process(process, ctx, *pid),
            ("spawn_request", [module, function, args, options]) => {
                spawn_request(vm, process, ctx, *module, *function, *args, *options)
            }
            ("dist_spawn_request", [node, mfa, options, kind]) => {
                dist_spawn_request(vm, process, ctx, *node, *mfa, *options, *kind)
            }
            ("spawn_request_abandon", [id]) => spawn_request_abandon(*id),
            ("process_display", [target, display]) if module == "erts_internal" => {
                process_display_call(module, process, ctx, *target, *display)
            }
            ("processes_next", [cursor]) if module == "erts_internal" => {
                processes_next(process, ctx, *cursor)
            }
            ("processes_next", [iterator]) if module == "erlang" => {
                erlang_processes_next(process, ctx, *iterator)
            }
            // Port of erts/emulator/beam/erl_bif_trace.c:889-918 (erts_internal_trace_3/4),
            // OTP-29.1.1.
            ("trace", [spec, how, flags]) if module == "erts_internal" || module == "erlang" => {
                let (spec, how, flags) = (*spec, *how, *flags);
                with_code_mod_permission(vm, process, ctx, |vm, process, ctx| {
                    trace(vm, process, ctx, 0, spec, how, flags)
                })
            }
            ("trace", [session, spec, how, flags]) if module == "erts_internal" => {
                let (session, spec, how, flags) = (*session, *spec, *how, *flags);
                with_code_mod_permission(vm, process, ctx, |vm, process, ctx| {
                    let session = trace_session_id(process, session).ok_or_else(badarg)?;
                    trace(vm, process, ctx, session, spec, how, flags)
                })
            }
            // Port of erts/emulator/beam/erl_bif_trace.c:302-331 (erts_internal_trace_pattern_3/4),
            // OTP-29.1.1.
            ("trace_pattern", [spec, pattern, flags]) if module == "erts_internal" => {
                let (spec, pattern, flags) = (*spec, *pattern, *flags);
                with_code_mod_permission(vm, process, ctx, |vm, process, ctx| {
                    trace_pattern(vm, process, ctx, 0, spec, pattern, flags)
                })
            }
            ("trace_pattern", [session, spec, pattern, flags]) if module == "erts_internal" => {
                let (session, spec, pattern, flags) = (*session, *spec, *pattern, *flags);
                with_code_mod_permission(vm, process, ctx, |vm, process, ctx| {
                    let session = trace_session_id(process, session).ok_or_else(badarg)?;
                    trace_pattern(vm, process, ctx, session, spec, pattern, flags)
                })
            }
            ("trace_session_create", [name, tracer, options]) if module == "erts_internal" => {
                trace_session_create(vm, process, ctx, *name, *tracer, *options)
            }
            // Port of erts/emulator/beam/erl_bif_trace.c:1278-1322
            // (erts_internal_trace_session_destroy_1), OTP-29.1.1.
            ("trace_session_destroy", [session]) if module == "erts_internal" => {
                let session_term = *session;
                with_code_mod_permission(vm, process, ctx, |vm, process, _| {
                    let session = trace_session_id(process, session_term).ok_or_else(badarg)?;
                    let destroyed = crate::trace::destroy_session(process, session);
                    if destroyed {
                        crate::natives::erts_debug::session_destroyed(process, session_term);
                        crate::trace_bp::clear_session(process, session);
                        vm.refresh_all_trace_breakpoints(process);
                    }
                    Ok(atom(if destroyed { "true" } else { "false" }))
                })
            }
            // Port of erts/emulator/beam/erl_bif_trace.c:1386-1435 (trace_info_2,
            // erts_internal_trace_info_3), OTP-29.1.1.
            ("trace_info", [spec, item]) if module == "erlang" => {
                let (spec, item) = (*spec, *item);
                with_code_mod_permission(vm, process, ctx, |vm, process, ctx| {
                    trace_info(vm, process, ctx, spec, item)
                })
            }
            ("trace_info", [session, spec, item]) if module == "erts_internal" => {
                let (session, spec, item) = (*session, *spec, *item);
                with_code_mod_permission(vm, process, ctx, |vm, process, ctx| {
                    let session = if atom_name(session).as_deref() == Some("any") {
                        0
                    } else {
                        trace_session_id(process, session).ok_or_else(badarg)?
                    };
                    trace_session_info(vm, process, ctx, session, spec, item)
                })
            }
            ("fun_info_mfa", [fun]) if module == "erlang" => fun_info_mfa(vm, process, *fun),
            _ => {
                debug_assert!(
                    !super::listed(IMPLEMENTED, "erlang", function, args.len() as u8)
                        && !super::listed(IMPLEMENTED, "erts_internal", function, args.len() as u8),
                    "process BIF {function}/{} is listed but has no match arm",
                    args.len()
                );
                Err(badarg())
            }
        }
    })();
    Some(result)
}

// Port of erts/emulator/beam/bif.c:1366 (`hibernate_3`) and
// beam_common.c:1568 (`erts_hibernate`), OTP-29.1.1.
fn hibernate(
    process: &mut Process,
    ctx: &RunCtx<'_, Message>,
    module: Term,
    function: Term,
    args: Term,
) -> Result<Term, VmError> {
    if module.as_atom().is_none() || function.as_atom().is_none() {
        return Err(badarg());
    }
    let mut arity = 0u32;
    let mut rest = args;
    while rest.classify() == TermKind::List && arity <= 255 {
        // SAFETY: The argument list stays rooted in the caller's registers.
        let Some((_, tail)) = (unsafe { rest.cons_ref() }) else {
            break;
        };
        rest = tail;
        arity += 1;
    }
    if rest != Term::NIL {
        if arity > 255 {
            return Err(VmError::Trap(crate::exceptions::Trap::error(atom(
                "system_limit",
            ))));
        }
        return Err(badarg());
    }
    let runtime = process
        .runtime
        .clone()
        .ok_or_else(|| VmError::Unsupported("hibernate requires a scheduler".into()))?;
    // Port of erts/emulator/beam/beam_common.c:1568 (erts_hibernate), OTP-29.1.1: the
    // arguments stay in the argument registers (arity 3) as the only roots and the stack
    // is discarded; the executor shrinks the heap once the BIF has unwound.
    if process.x.len() < 3 {
        let mut registers = process.x.to_vec();
        registers.resize(3, Term::NIL);
        process.x = registers.into_boxed_slice();
    }
    process.heap.release_stack(process.heap.stack_words());
    for register in process.x.iter_mut() {
        *register = Term::NIL;
    }
    process.x[0] = module;
    process.x[1] = function;
    process.x[2] = args;
    process.gc_live = 3;
    process.receive_cursor = 0;
    runtime
        .ever_hibernated
        .store(true, std::sync::atomic::Ordering::Release);
    runtime.hibernating.lock().unwrap().insert(
        ctx.pid(),
        crate::process::HibernateCont {
            stop: true,
            resume_in_place: false, // elixir_loop1
        },
    );
    runtime.mark_hibernating(ctx.pid(), true);
    Err(VmError::Unsupported("hibernate".into()))
}

// OTP-29.1.1 `erts/emulator/beam/ops.tab` lowers `hibernate/0` to `i_hibernate`.
fn hibernate_zero(process: &mut Process, ctx: &RunCtx<'_, Message>) -> Result<Term, VmError> {
    let runtime = process
        .runtime
        .clone()
        .ok_or_else(|| VmError::Unsupported("hibernate requires a scheduler".into()))?;
    let pid = ctx.pid();
    runtime
        .ever_hibernated
        .store(true, std::sync::atomic::Ordering::Release);
    let mut parked = runtime.hibernating.lock().unwrap();
    if parked
        .get(&pid)
        .is_some_and(|cont| cont.resume_in_place && !cont.stop)
    {
        parked.remove(&pid);
        return Ok(atom("ok"));
    }
    parked.insert(
        pid,
        crate::process::HibernateCont {
            stop: true,
            resume_in_place: true,
        },
    );
    drop(parked);
    runtime.mark_hibernating(pid, true);
    Err(VmError::Unsupported("hibernate".into()))
}

// Port of erts/emulator/beam/erl_process.c:9013
// (`erts_internal_suspend_process_2`), OTP-29.1.1.
fn suspend_process(
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    target: Term,
    options: Term,
) -> Result<Term, VmError> {
    if Pid::from_term(target) == Some(ctx.pid()) {
        return Ok(atom("badarg"));
    }
    let Some(target_pid) = Pid::from_term(target) else {
        return Ok(atom("badarg"));
    };
    let parsed = match parse_suspend_options(options) {
        None => return Ok(atom("badopt")),
        Some(parsed) => parsed,
    };
    let runtime = process
        .runtime
        .clone()
        .ok_or_else(|| VmError::Unsupported("suspend requires a scheduler".into()))?;
    if !runtime.scheduler()?.lookup(target_pid) {
        if parsed.asynchronous
            && let Some(tag) = parsed.tag
        {
            let message = make_tuple(process, &[tag, atom("badarg")])?;
            // Port of erts/emulator/beam/erl_proc_sig_queue.c:3215 (suspend reply, queued without
            // a send trace), OTP-29.1.1: the reply is not a traced `!`.
            process.inbox.push_back(message);
            return Ok(atom("true"));
        }
        return Ok(atom("badarg"));
    }
    let changed = match runtime.suspend(
        ctx.pid(),
        target_pid,
        parsed.unless_suspending,
        parsed.asynchronous,
    ) {
        Err(()) => return Ok(atom("system_limit")),
        Ok(changed) => changed,
    };
    // Port of erts/emulator/beam/erl_process.c:9061-9163, OTP-29.1.1: a synchronous suspend on a
    // monitor that is not active yet, and every tagged asynchronous suspend, is answered by a
    // reply message once the suspend is active.
    let result = atom(if changed { "true" } else { "false" });
    let sync = !parsed.asynchronous && runtime.suspend_pending(ctx.pid(), target_pid);
    if sync || parsed.tag.is_some() {
        let (tag, ready, exited) = if sync {
            let id = arinsal_bifs::next_ref_id();
            let reference = Term::local_ref(
                &mut arinsal_bifs::FragmentingHeap(&mut process.heap),
                [id as u32, (id >> 32) as u32, 0],
            )
            .map_err(|error| VmError::Unsupported(format!("suspend reference: {error:?}")))?;
            (reference, result, atom("exited"))
        } else {
            (
                parsed.tag.unwrap_or(Term::NIL),
                atom("suspended"),
                atom("badarg"),
            )
        };
        let ready = make_tuple(process, &[tag, ready])?;
        let exited = make_tuple(process, &[tag, exited])?;
        runtime.add_suspend_waiter(crate::process::SuspendWaiter {
            by: ctx.pid(),
            target: target_pid,
            ready: crate::process::Message::copy_from(ready)?,
            exited: crate::process::Message::copy_from(exited)?,
        });
        // Port of erts/emulator/beam/erl_proc_sig_queue.c:3192-3233
        // (`erts_proc_sig_send_sync_suspend`), OTP-29.1.1: prioritize the target after queuing
        // the synchronous or tagged suspend reply request.
        crate::signals::elevate_for_signal_request(process, ctx, target_pid)?;
        if sync {
            return Ok(tag);
        }
    }
    Ok(atom(if changed { "true" } else { "false" }))
}

struct SuspendOptions {
    unless_suspending: bool,
    asynchronous: bool,
    tag: Option<Term>,
}

fn parse_suspend_options(options: Term) -> Option<SuspendOptions> {
    let mut unless_suspending = false;
    let mut asynchronous = false;
    let mut tag = None;
    let mut current = options;
    while current.classify() == TermKind::List {
        // SAFETY: The option list stays rooted for this BIF call.
        let (head, tail) = unsafe { current.cons_ref() }?;
        current = tail;
        if head == atom("unless_suspending") {
            unless_suspending = true;
        } else if head == atom("asynchronous") {
            asynchronous = true;
        } else if let Some((key, value)) = tuple2(head)
            && key == atom("asynchronous")
        {
            asynchronous = true;
            tag = Some(value);
        } else {
            return None;
        }
    }
    if current != Term::NIL {
        return None;
    }
    Some(SuspendOptions {
        unless_suspending,
        asynchronous,
        tag,
    })
}

// Port of erts/emulator/beam/erl_process.c:9181 (`resume_process_1`), OTP-29.1.1.
fn resume_process(
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    target: Term,
) -> Result<Term, VmError> {
    if Pid::from_term(target) == Some(ctx.pid()) {
        return Err(badarg());
    }
    let Some(target_pid) = Pid::from_term(target) else {
        return Err(badarg());
    };
    let runtime = process
        .runtime
        .clone()
        .ok_or_else(|| VmError::Unsupported("resume requires a scheduler".into()))?;
    if !runtime.scheduler()?.lookup(target_pid) {
        return Err(badarg());
    }
    match runtime.resume(ctx.pid(), target_pid) {
        None => Err(badarg()),
        Some(wake) => {
            if wake {
                ctx.signal(target_pid, Signal::UnlinkAck(u64::MAX))
                    .map_err(|error| VmError::Unsupported(format!("resume: {error}")))?;
            }
            Ok(atom("true"))
        }
    }
}

// Port of erts/emulator/beam/bif.c:1078 (`erts_internal_spawn_request_4`),
// erl_process.c:12222 (`erts_parse_spawn_opts`) and
// erl_process.c:13146 (`erts_send_local_spawn_reply`), OTP-29.1.1.
fn spawn_request(
    vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    module: Term,
    function: Term,
    args: Term,
    options: Term,
) -> Result<Term, VmError> {
    if module.as_atom().is_none() || function.as_atom().is_none() || list(args).is_none() {
        return Ok(atom("badarg"));
    }
    let Some(parsed) = parse_spawn_options(process.runtime.as_deref(), options) else {
        return Ok(atom("badopt"));
    };
    let runtime = process
        .runtime
        .clone()
        .ok_or_else(|| VmError::Unsupported("spawn_request requires a scheduler".into()))?;
    let id = runtime.next_ref();
    let reference = crate::signals::reference(process, id)?;
    if parsed.bad {
        if parsed.reply_error {
            let message = make_tuple(
                process,
                &[parsed.tag, reference, atom("error"), atom("badopt")],
            )?;
            let self_pid = ctx.pid().to_term().ok_or_else(badarg)?;
            process.send_message(self_pid, message)?;
        }
        return Ok(reference);
    }
    let mut parsed = parsed;
    if parsed.monitor {
        parsed.monitor_id = Some(id);
    }
    let child = spawn_apply(vm, process, ctx, module, function, args, &parsed)?;
    if parsed.link {
        process.cold_mut().links.insert(child);
        ctx.signal(child, Signal::Link)
            .map_err(|error| VmError::Unsupported(format!("spawn_request link: {error}")))?;
    }
    if parsed.monitor {
        process.cold_mut().monitors.insert(id, child);
        ctx.signal(child, Signal::Monitor(id))
            .map_err(|error| VmError::Unsupported(format!("spawn_request monitor: {error}")))?;
    }
    if parsed.reply_success {
        let pid_term = child.to_term().ok_or_else(badarg)?;
        let message = make_tuple(process, &[parsed.tag, reference, atom("ok"), pid_term])?;
        let envelope = Message::copy_from(message)?;
        runtime
            .scheduler()?
            .send(child, ctx.pid(), envelope)
            .map_err(|error| VmError::Unsupported(format!("spawn_reply: {error}")))?;
    }
    if let Some(limit) = parsed.max_heap {
        runtime
            .ever_max_heap
            .store(true, std::sync::atomic::Ordering::Release);
        runtime.max_heaps.lock().unwrap().insert(child, limit);
    }
    Ok(reference)
}

pub(crate) fn trace_session_id(process: &Process, session: Term) -> Option<u64> {
    let owned = arinsal_term::to_owned(session).ok()?;
    match &owned {
        arinsal_etf::OwnedTerm::Ref { ids, .. } if ids.len() >= 3 && ids[2] == u32::MAX => {
            crate::trace::session_from_magic_ref(
                process,
                u64::from(ids[0]) | (u64::from(ids[1]) << 32),
            )
        }
        arinsal_etf::OwnedTerm::Ref { ids, .. } if ids.len() >= 2 => {
            Some(ids[0] as u64 | (u64::from(ids[1]) << 32))
        }
        arinsal_etf::OwnedTerm::Tuple(fields) => match fields.as_slice() {
            [arinsal_etf::OwnedTerm::Ref { ids, .. }, _]
                if ids.len() >= 3 && ids[2] == u32::MAX =>
            {
                crate::trace::session_from_magic_ref(
                    process,
                    u64::from(ids[0]) | (u64::from(ids[1]) << 32),
                )
            }
            [arinsal_etf::OwnedTerm::Ref { ids, .. }, _] if ids.len() >= 2 => {
                Some(ids[0] as u64 | (u64::from(ids[1]) << 32))
            }
            [
                arinsal_etf::OwnedTerm::Atom(name),
                arinsal_etf::OwnedTerm::Int(weak_id),
            ] => crate::trace::session_id(process, name, *weak_id),
            _ => None,
        },
        _ => None,
    }
}

// Port of erts/emulator/beam/dist.c:5827 (`erts_internal_dist_spawn_request_4`), OTP-29.1.1.
fn dist_spawn_request(
    _vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    node: Term,
    mfa: Term,
    options: Term,
    kind: Term,
) -> Result<Term, VmError> {
    if node.as_atom().is_none() || node == atom("nonode@nohost") {
        return Ok(atom("badarg"));
    }
    // SAFETY: The MFA tuple stays rooted in the caller's registers.
    let Some(tuple) = (unsafe { mfa.tuple_ref() }) else {
        return Ok(atom("badarg"));
    };
    if tuple.len() != 3 {
        return Ok(atom("badarg"));
    }
    let (module, function, args) = (
        tuple.get(0).ok_or_else(badarg)?,
        tuple.get(1).ok_or_else(badarg)?,
        tuple.get(2).ok_or_else(badarg)?,
    );
    if module.as_atom().is_none() || function.as_atom().is_none() || list(args).is_none() {
        return Ok(atom("badarg"));
    }
    let Some(items) = list(options) else {
        return Ok(atom("badarg"));
    };
    let mut tag = atom("spawn_reply");
    let mut reply_error = true;
    let mut bad = false;
    for item in items {
        if let Some((key, value)) = tuple2(item) {
            if key == atom("reply_tag") {
                if kind != atom("spawn_request") {
                    return Ok(atom("badarg"));
                }
                tag = value;
            } else if key == atom("reply") {
                match reply_mode(value) {
                    Some((success, error)) => {
                        let _ = success;
                        reply_error = error;
                    }
                    None if kind == atom("spawn_request") => bad = true,
                    None => return Ok(atom("badarg")),
                }
            }
        }
    }
    let runtime = process
        .runtime
        .clone()
        .ok_or_else(|| VmError::Unsupported("spawn_request requires a scheduler".into()))?;
    let id = runtime.next_ref();
    let reference = crate::signals::reference(process, id)?;
    let reason = atom(if bad { "badopt" } else { "noconnection" });
    if reply_error {
        let message = make_tuple(process, &[tag, reference, atom("error"), reason])?;
        let self_pid = ctx.pid().to_term().ok_or_else(badarg)?;
        process.send_message(self_pid, message)?;
    }
    Ok(reference)
}

// Port of erts/emulator/beam/bif.c:1166 (`spawn_request_abandon_1`), OTP-29.1.1.
fn spawn_request_abandon(id: Term) -> Result<Term, VmError> {
    if id.classify() != TermKind::Ref {
        return Err(badarg());
    }
    // A local request completes before `spawn_request` returns, so it is never
    // still pending. Remote requests are answered with `noconnection` inline.
    Ok(atom("false"))
}

struct LocalSpawn {
    link: bool,
    monitor: bool,
    min_heap: Option<usize>,
    min_bin_vheap: Option<usize>,
    max_heap: Option<crate::process::MaxHeap>,
    priority: Priority,
    fullsweep: Option<u16>,
    tag: Term,
    reply_success: bool,
    reply_error: bool,
    bad: bool,
    monitor_id: Option<u64>,
}

fn parse_spawn_options(
    runtime: Option<&crate::process::Runtime>,
    options: Term,
) -> Option<LocalSpawn> {
    let items = list(options)?;
    let mut parsed = LocalSpawn {
        link: false,
        monitor: false,
        min_heap: None,
        min_bin_vheap: None,
        max_heap: None,
        priority: Priority::Normal,
        fullsweep: None,
        tag: atom("spawn_reply"),
        reply_success: true,
        reply_error: true,
        bad: false,
        monitor_id: None,
    };
    for item in items {
        if item == atom("link") {
            parsed.link = true;
        } else if item == atom("monitor") {
            parsed.monitor = true;
        } else if let Some((key, value)) = tuple2(item) {
            if key == atom("priority") {
                parsed.priority = match atom_name(value).as_deref() {
                    Some("max") => Priority::Max,
                    Some("high") => Priority::High,
                    Some("normal") => Priority::Normal,
                    Some("low") => Priority::Low,
                    _ => {
                        parsed.bad = true;
                        continue;
                    }
                };
            } else if key == atom("min_heap_size") {
                match value.as_small() {
                    Some(n) if n >= 0 => parsed.min_heap = Some((n as usize).max(233)),
                    _ => parsed.bad = true,
                }
            } else if key == atom("max_heap_size") {
                match parse_max_heap_from(
                    value,
                    super::sys::gc_spawn_defaults(runtime).max_heap_size,
                ) {
                    Ok(limit) => parsed.max_heap = Some(limit),
                    Err(()) => parsed.bad = true,
                }
            } else if key == atom("min_bin_vheap_size") {
                match value.as_small() {
                    Some(n) if n >= 0 => parsed.min_bin_vheap = Some(n as usize),
                    _ => parsed.bad = true,
                }
            } else if key == atom("fullsweep_after") {
                match value.as_small() {
                    Some(n) if n >= 0 => parsed.fullsweep = Some(n.min(u16::MAX as i64) as u16),
                    _ => parsed.bad = true,
                }
            } else if key == atom("message_queue_data") {
                if value != atom("on_heap") && value != atom("off_heap") {
                    parsed.bad = true;
                }
            } else if key == atom("async_dist") {
                if value != atom("true") && value != atom("false") {
                    parsed.bad = true;
                }
            } else if key == atom("scheduler") {
                if value.as_small().is_none_or(|n| n < 0) {
                    parsed.bad = true;
                }
            } else if key == atom("reply") {
                match reply_mode(value) {
                    Some((success, error)) => {
                        parsed.reply_success = success;
                        parsed.reply_error = error;
                    }
                    None => parsed.bad = true,
                }
            } else if key == atom("reply_tag") {
                parsed.tag = value;
            } else if key == atom("link") || key == atom("monitor") {
                if list(value).is_none() {
                    parsed.bad = true;
                } else if key == atom("link") {
                    parsed.link = true;
                } else {
                    parsed.monitor = true;
                }
            } else {
                parsed.bad = true;
            }
        } else {
            parsed.bad = true;
        }
    }
    let min_heap =
        crate::natives::sys::normalize_spawn_heap_minimum(runtime, parsed.min_heap, false) as u64;
    if parsed
        .max_heap
        .is_some_and(|limit| limit.size != 0 && limit.size < min_heap)
    {
        parsed.bad = true;
    }
    Some(parsed)
}

fn reply_mode(value: Term) -> Option<(bool, bool)> {
    if value == atom("yes") {
        Some((true, true))
    } else if value == atom("no") {
        Some((false, false))
    } else if value == atom("error_only") {
        Some((false, true))
    } else if value == atom("success_only") {
        Some((true, false))
    } else {
        None
    }
}

fn spawn_apply(
    vm: &mut Vm,
    parent: &mut Process,
    ctx: &RunCtx<'_, Message>,
    module: Term,
    function: Term,
    args: Term,
    options: &LocalSpawn,
) -> Result<Pid, VmError> {
    let (module_id, entry) = crate::process::erlang_apply_entry(vm)?;
    let runtime = parent.runtime.clone();
    let defaults = crate::natives::sys::gc_spawn_defaults(runtime.as_deref());
    let min_heap = crate::natives::sys::normalize_spawn_heap_minimum(
        runtime.as_deref(),
        options.min_heap,
        false,
    );
    let min_bin_vheap = if options.min_bin_vheap.is_some()
        && options.min_heap.is_none()
        && options.max_heap.is_none()
    {
        defaults.min_bin_vheap_size as usize
    } else {
        crate::natives::sys::normalize_spawn_heap_minimum(
            runtime.as_deref(),
            options.min_bin_vheap,
            true,
        )
    };
    let fullsweep_after = options.fullsweep.unwrap_or(defaults.fullsweep_after);
    let max_heap = options.max_heap.unwrap_or(defaults.max_heap_size);
    let mut child = Process::with_spawn_registers(3, 0);
    child.set_runtime(parent.runtime.clone());
    if options.min_heap.is_some() {
        child.heap = arinsal_term::ProcessHeap::with_words(min_heap.max(64));
    }
    child.heap.set_min_heap_size(min_heap);
    child.heap.set_min_bin_vheap_size(min_bin_vheap as u64);
    child.heap.set_fullsweep_after(fullsweep_after);
    child.module = module_id;
    child.ip = entry;
    if let (Some(m), Some(f), Some(arguments)) = (module.as_atom(), function.as_atom(), list(args))
    {
        let names = arinsal_term::global_atoms();
        if let (Some(m), Some(f)) = (names.text(m), names.text(f)) {
            child.cold_mut().initial_call =
                Some((m.to_string(), f.to_string(), arguments.len() as u8));
        }
    } else {
        child.cold_mut().initial_call = Some(("erlang".to_owned(), "apply".to_owned(), 2));
    }
    {
        let flags = &mut child.cold_mut().flags;
        flags.insert(
            "fullsweep_after".to_owned(),
            Term::small(i64::from(fullsweep_after)).unwrap(),
        );
        flags.insert(
            "min_heap_size".to_owned(),
            Term::small(min_heap as i64).unwrap(),
        );
        flags.insert(
            "min_bin_vheap_size".to_owned(),
            Term::small(min_bin_vheap as i64).unwrap(),
        );
    }
    child.cold_mut().group_leader = Some(
        parent
            .cold
            .as_ref()
            .and_then(|cold| cold.group_leader)
            .unwrap_or_else(|| ctx.pid()),
    );
    // The child can exit before it drains the link/monitor signals. Record
    // them now so `notify_exit` still delivers EXIT and DOWN.
    if options.link {
        child.cold_mut().links.insert(ctx.pid());
    }
    if let Some(id) = options.monitor_id {
        child.cold_mut().monitored_by.insert(id, ctx.pid());
    }
    {
        // Port of erts/emulator/beam/erl_process.c:12546,12638 (spawn arguments use
        // copy_struct_litopt), OTP-29.1.1.
        let literals = arinsal_term::LiteralAreas::current();
        let mut heap = arinsal_bifs::FragmentingHeap(&mut child.heap);
        child.x[0] = arinsal_term::copy_term_litopt(module, &mut heap, &literals)
            .map_err(|error| VmError::Unsupported(format!("spawn module: {error:?}")))?;
        child.x[1] = arinsal_term::copy_term_litopt(function, &mut heap, &literals)
            .map_err(|error| VmError::Unsupported(format!("spawn function: {error:?}")))?;
        child.x[2] = arinsal_term::copy_term_litopt(args, &mut heap, &literals)
            .map_err(|error| VmError::Unsupported(format!("spawn args: {error:?}")))?;
    }
    let runtime = parent
        .runtime
        .clone()
        .ok_or_else(|| VmError::Unsupported("spawn_request requires a scheduler".into()))?;
    let scheduler = runtime.scheduler()?;
    let pid = scheduler
        .spawn_priority(child, options.priority)
        .map_err(|error| VmError::Unsupported(format!("spawn_request: {error}")))?;
    runtime.processes.lock().unwrap().insert(pid);
    if !is_default_max_heap(max_heap)
        || runtime
            .ever_max_heap
            .load(std::sync::atomic::Ordering::Acquire)
    {
        runtime
            .ever_max_heap
            .store(true, std::sync::atomic::Ordering::Release);
        runtime.max_heaps.lock().unwrap().insert(pid, max_heap);
    }
    if !scheduler.lookup(pid) {
        runtime.processes.lock().unwrap().remove(&pid);
    }
    Ok(pid)
}

/// Record a spawn-time `max_heap_size` unless it is the system default.
/// Port of erts/emulator/beam/erl_process.c:12222 (`erts_parse_spawn_opts`), OTP-29.1.1.
pub(crate) fn register_spawn_max_heap(
    runtime: &crate::process::Runtime,
    pid: Pid,
    requested: Option<crate::process::MaxHeap>,
) {
    let max_heap =
        requested.unwrap_or(crate::natives::sys::gc_spawn_defaults(Some(runtime)).max_heap_size);
    if !is_default_max_heap(max_heap)
        || runtime
            .ever_max_heap
            .load(std::sync::atomic::Ordering::Acquire)
    {
        runtime
            .ever_max_heap
            .store(true, std::sync::atomic::Ordering::Release);
        runtime.max_heaps.lock().unwrap().insert(pid, max_heap);
    }
}

fn is_default_max_heap(limit: crate::process::MaxHeap) -> bool {
    limit.size == 0 && limit.kill && limit.log && !limit.include_shared_binaries && !limit.reported
}

pub(crate) fn tuple2(term: Term) -> Option<(Term, Term)> {
    if term.classify() != TermKind::Tuple {
        return None;
    }
    // SAFETY: The tuple stays rooted for this BIF call.
    let tuple = unsafe { term.tuple_ref() }?;
    if tuple.len() != 2 {
        return None;
    }
    Some((tuple.get(0)?, tuple.get(1)?))
}

// Port of erts/emulator/beam/erl_gc.c:3824 (`erts_max_heap_size`) and
// erl_gc.c:3807 (`erts_max_heap_size_map`), OTP-29.1.1.
fn max_heap_flag(
    process: &mut Process,
    ctx: &RunCtx<'_, Message>,
    value: Term,
) -> Result<Term, VmError> {
    let limit = parse_max_heap(value).map_err(|()| badarg())?;
    let floor = flag_value(process, "min_heap_size")
        .and_then(|term| term.as_small())
        .filter(|n| *n > 0)
        .unwrap_or(233) as u64;
    if limit.size != 0 && limit.size < floor {
        return Err(badarg());
    }
    let pid = ctx.pid();
    let previous = stored_max_heap(process, pid);
    let runtime = process
        .runtime
        .clone()
        .ok_or_else(|| VmError::Unsupported("max_heap_size requires a scheduler".into()))?;
    runtime
        .ever_max_heap
        .store(true, std::sync::atomic::Ordering::Release);
    runtime.max_heaps.lock().unwrap().insert(pid, limit);
    max_heap_map(process, previous)
}

fn stored_max_heap(process: &Process, pid: Pid) -> crate::process::MaxHeap {
    process
        .runtime
        .as_ref()
        .filter(|runtime| {
            runtime
                .ever_max_heap
                .load(std::sync::atomic::Ordering::Acquire)
        })
        .and_then(|runtime| runtime.max_heaps.lock().unwrap().get(&pid).copied())
        .unwrap_or_default()
}

fn max_heap_term(process: &mut Process, pid: Pid) -> Result<Term, VmError> {
    max_heap_map(process, stored_max_heap(process, pid))
}

fn max_heap_map(process: &mut Process, limit: crate::process::MaxHeap) -> Result<Term, VmError> {
    let size = Term::small(i64::try_from(limit.size).map_err(|_| badarg())?).ok_or_else(badarg)?;
    let pairs = [
        (
            atom("error_logger"),
            atom(if limit.log { "true" } else { "false" }),
        ),
        (
            atom("include_shared_binaries"),
            atom(if limit.include_shared_binaries {
                "true"
            } else {
                "false"
            }),
        ),
        (
            atom("kill"),
            atom(if limit.kill { "true" } else { "false" }),
        ),
        (atom("size"), size),
    ];
    let mut heap = arinsal_bifs::FragmentingHeap(&mut process.heap);
    TermBuilder::new(&mut heap)
        .flatmap_from_pairs(&pairs)
        .map_err(|error| VmError::Unsupported(format!("max_heap_size map: {error:?}")))
}

pub(crate) fn parse_max_heap(value: Term) -> Result<crate::process::MaxHeap, ()> {
    parse_max_heap_from(value, crate::process::MaxHeap::default())
}

/// Parse a `max_heap_size` value; keys absent from a map keep `base`'s settings.
pub(crate) fn parse_max_heap_from(
    value: Term,
    base: crate::process::MaxHeap,
) -> Result<crate::process::MaxHeap, ()> {
    let mut limit = base;
    if let Some(size) = value.as_small() {
        if size < 0 {
            return Err(());
        }
        limit.size = size as u64;
        return Ok(limit);
    }
    if value.classify() != TermKind::Map {
        return Err(());
    }
    // SAFETY: The flag map stays rooted in the caller's registers.
    let map = unsafe { value.flatmap_ref() }.ok_or(())?;
    let size = map.get(atom("size")).ok_or(())?;
    let size = size.as_small().filter(|size| *size >= 0).ok_or(())?;
    limit.size = size as u64;
    let boolean = |key: &str| -> Result<Option<bool>, ()> {
        match map.get(atom(key)) {
            None => Ok(None),
            Some(term) if term == atom("true") => Ok(Some(true)),
            Some(term) if term == atom("false") => Ok(Some(false)),
            Some(_) => Err(()),
        }
    };
    if let Some(kill) = boolean("kill")? {
        limit.kill = kill;
    }
    if let Some(log) = boolean("error_logger")? {
        limit.log = log;
    }
    if let Some(include) = boolean("include_shared_binaries")? {
        limit.include_shared_binaries = include;
    }
    Ok(limit)
}

fn suspending_term(process: &mut Process, pid: Pid) -> Result<Term, VmError> {
    let rows = process
        .runtime
        .as_ref()
        .map(|runtime| runtime.suspending_of(pid))
        .unwrap_or_default();
    let mut tuples = Vec::with_capacity(rows.len());
    for (target, active, outstanding) in rows {
        let target = target.to_term().unwrap_or(Term::NIL);
        let active = Term::small(i64::from(active)).ok_or_else(badarg)?;
        let outstanding = Term::small(i64::from(outstanding)).ok_or_else(badarg)?;
        tuples.push(make_tuple(process, &[target, active, outstanding])?);
    }
    make_list(process, tuples)
}

fn create_alias(
    process: &mut Process,
    ctx: &RunCtx<'_, Message>,
    options: &[Term],
) -> Result<Term, VmError> {
    if options.iter().any(|option| {
        !["explicit_unalias", "reply", "priority"]
            .iter()
            .any(|name| *option == atom(name))
    }) {
        return Err(badarg());
    }
    let priority = options.iter().any(|option| *option == atom("priority"));
    let id = process.runtime.as_ref().ok_or_else(badarg)?.next_ref();
    let reference = crate::signals::reference(process, id)?;
    let pid = ctx.pid();
    process
        .runtime
        .as_ref()
        .ok_or_else(badarg)?
        .alias_bind_prio(id, Some(pid), priority);
    process.cold_mut().aliases.insert(id);
    Ok(reference)
}

fn trace_mask(process: &Process, pid: Pid) -> u64 {
    crate::trace::flags(process, pid)
}

// Port of erts/emulator/beam/erl_process.h:1740 (F_TRACE_FLAG), OTP-29.1.1.
// Timestamp type occupies the low 3 bits (`ERTS_TRACE_TS_TYPE_BITS`).
pub(crate) fn trace_flag_bit(name: &str) -> Option<u64> {
    let bit = |n: u32| 1u64 << (3 + n);
    Some(match name {
        "send" => crate::trace::SEND,
        "receive" => crate::trace::RECEIVE,
        "set_on_spawn" => crate::trace::SET_ON_SPAWN,
        "set_on_first_spawn" => crate::trace::SET_ON_FIRST_SPAWN,
        "set_on_link" => crate::trace::SET_ON_LINK,
        "set_on_first_link" => bit(6),
        "call" => crate::trace::CALL,
        "procs" => crate::trace::PROCS,
        "running" => crate::trace::RUNNING,
        "garbage_collection" => crate::trace::GC,
        "arity" => crate::trace::ARITY,
        "return_to" => crate::trace::RETURN_TO,
        "silent" => crate::trace::SILENT,
        "scheduler_id" => crate::trace::SCHEDULER_ID,
        "running_ports" => crate::trace::RUNNING_PORTS,
        "running_procs" => crate::trace::RUNNING_PROCS,
        "ports" => crate::trace::PORTS,
        "exiting" => bit(21),
        "timestamp" => crate::trace::TIMESTAMP,
        "strict_monotonic_timestamp" => crate::trace::STRICT_MONOTONIC_TIMESTAMP,
        "monotonic_timestamp" => crate::trace::MONOTONIC_TIMESTAMP,
        "all" => {
            crate::trace::SEND
                | crate::trace::RECEIVE
                | crate::trace::SET_ON_SPAWN
                | crate::trace::SET_ON_FIRST_SPAWN
                | crate::trace::SET_ON_LINK
                | bit(6)
                | crate::trace::CALL
                | crate::trace::PROCS
                | crate::trace::RUNNING
                | crate::trace::GC
                | crate::trace::RETURN_TO
                | crate::trace::ARITY
                | crate::trace::SILENT
                | bit(18)
                | crate::trace::SCHEDULER_ID
                | bit(21)
                | crate::trace::RUNNING_PORTS
                | crate::trace::PORTS
                | crate::trace::TIMESTAMP
                | crate::trace::MONOTONIC_TIMESTAMP
                | crate::trace::STRICT_MONOTONIC_TIMESTAMP
        }
        _ => return None,
    })
}

// Port of erts/emulator/beam/erl_bif_trace.c:890 (erts_internal_trace_3), OTP-29.1.1.
fn trace(
    vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    session: u64,
    spec: Term,
    how: Term,
    flags: Term,
) -> Result<Term, VmError> {
    // A tracer module may have been loaded by another scheduler just now.
    vm.refresh_code();
    let on = if how == atom("true") {
        true
    } else if how == atom("false") {
        false
    } else {
        return Err(badarg());
    };
    let mut mask = 0u64;
    let mut tracer = if session == 0 {
        crate::trace::Tracer::Pid(ctx.pid())
    } else {
        match crate::trace::session_tracer(process, session).ok_or_else(badarg)? {
            crate::trace::Tracer::Default => crate::trace::Tracer::Pid(ctx.pid()),
            tracer => tracer,
        }
    };
    for flag in list(flags).ok_or_else(badarg)? {
        if let Some(name) = atom_name(flag) {
            mask |= trace_flag_bit(&name).ok_or_else(badarg)?;
            continue;
        }
        // SAFETY: A `{tracer, _}` option stays rooted in the caller heap.
        let tuple = unsafe { flag.tuple_ref() }.ok_or_else(badarg)?;
        let name = tuple.get(0).and_then(atom_name).ok_or_else(badarg)?;
        if name != "tracer" || !matches!(tuple.len(), 2 | 3) {
            return Err(badarg());
        }
        // Port of erts/emulator/beam/erl_bif_trace.c:1010-1030 (parse_trace_flags): a session's
        // tracer is fixed at creation, so `{tracer, _}` is only valid for the legacy session.
        if session != 0
            && !matches!(
                crate::trace::session_tracer(process, session),
                Some(crate::trace::Tracer::Default)
            )
        {
            return Err(badarg());
        }
        if tuple.len() == 3 {
            tracer = module_tracer(
                vm,
                tuple.get(1).ok_or_else(badarg)?,
                tuple.get(2).ok_or_else(badarg)?,
            )?;
            continue;
        }
        let target = tuple.get(1).ok_or_else(badarg)?;
        if let Some((module, state)) = tuple2(target) {
            tracer = module_tracer(vm, module, state)?;
            continue;
        }
        if let Some(pid) = Pid::from_term(target) {
            if !live(process, pid)? {
                return Err(badarg());
            }
            tracer = crate::trace::Tracer::Pid(pid);
        } else if target.as_port().is_some() {
            let id = target.as_port().unwrap();
            if !process
                .runtime
                .as_ref()
                .is_some_and(|runtime| runtime.ports.lock().unwrap().contains_key(&id))
            {
                return Err(badarg());
            }
            tracer = crate::trace::Tracer::Port(id);
        } else {
            return Err(badarg());
        }
    }
    let process_mask = mask & !(crate::trace::PORTS | crate::trace::RUNNING_PORTS);
    const PORT_FLAGS: u64 = crate::trace::SEND
        | crate::trace::RECEIVE
        | crate::trace::TIMESTAMP
        | crate::trace::STRICT_MONOTONIC_TIMESTAMP
        | crate::trace::MONOTONIC_TIMESTAMP
        | crate::trace::SILENT
        | crate::trace::RUNNING_PORTS
        | crate::trace::PORTS
        | crate::trace::SCHEDULER_ID;
    let port_mask = mask & PORT_FLAGS;
    let had_return_to =
        mask & crate::trace::RETURN_TO != 0 && crate::trace::return_to_enabled(process);
    // Port of erts/emulator/beam/erl_bif_trace.c:853-863 and 1103-1108 (start_trace), OTP-29.1.1:
    // a tracee keeps a live tracer; such tracees are skipped and not counted.
    let apply = |process: &mut Process, pid: Pid| {
        if on && crate::trace::traced_by_other(vm, process, session, pid, &tracer) {
            return false;
        }
        crate::trace::configure_session(process, session, pid, on, process_mask, tracer.clone());
        true
    };
    let matches = if let Some(pid) = Pid::from_term(spec) {
        if !live(process, pid)? {
            return Err(badarg());
        }
        if !apply(process, pid) {
            // Port of erts/emulator/beam/erl_bif_trace.c:1172-1176 (already_traced), OTP-29.1.1.
            // The "** can only have one tracer per process" logger report is not sent yet.
            return Err(badarg());
        }
        1
    } else if spec.as_port().is_some() {
        let id = spec.as_port().unwrap();
        let known = process
            .runtime
            .as_ref()
            .is_some_and(|runtime| id == 0 || runtime.ports.lock().unwrap().contains_key(&id));
        if !known {
            return Err(badarg());
        }
        if on && crate::trace::traced_port_by_other(vm, process, session, id, &tracer) {
            return Err(badarg());
        }
        crate::trace::configure_port(process, session, id, on, port_mask, tracer.clone());
        1
    } else {
        match atom_name(spec).as_deref() {
            Some(spec_name @ ("all" | "processes" | "existing" | "existing_processes")) => {
                // Port of erts/emulator/beam/erl_bif_trace.c:1085-1143 (erts_internal_trace_3),
                // OTP-29.1.1. `all` and `processes` also cover processes created later.
                let pids = live_pids(process)?;
                let mut count = 0;
                for pid in pids {
                    count += usize::from(apply(process, pid));
                }
                if matches!(spec_name, "all" | "processes") {
                    crate::trace::configure_new_processes(
                        process,
                        session,
                        on,
                        process_mask,
                        tracer.clone(),
                    );
                }
                if matches!(spec_name, "all" | "existing") {
                    let mut ports = vec![0];
                    ports.extend(
                        process
                            .runtime
                            .as_ref()
                            .map(|runtime| {
                                runtime
                                    .ports
                                    .lock()
                                    .unwrap()
                                    .keys()
                                    .copied()
                                    .collect::<Vec<_>>()
                            })
                            .unwrap_or_default(),
                    );
                    for port in &ports {
                        crate::trace::configure_port(
                            process,
                            session,
                            *port,
                            on,
                            port_mask,
                            tracer.clone(),
                        );
                    }
                    count += ports.len();
                }
                if spec_name == "all" {
                    crate::trace::configure_new_ports(
                        process,
                        session,
                        on,
                        port_mask,
                        tracer.clone(),
                    );
                }
                count
            }
            Some("new" | "new_processes") => {
                crate::trace::configure_new_processes(
                    process,
                    session,
                    on,
                    process_mask,
                    tracer.clone(),
                );
                if atom_name(spec).as_deref() == Some("new") {
                    crate::trace::configure_new_ports(
                        process,
                        session,
                        on,
                        port_mask,
                        tracer.clone(),
                    );
                }
                0
            }
            Some("ports" | "existing_ports") => {
                let mut ports = vec![0];
                ports.extend(
                    process
                        .runtime
                        .as_ref()
                        .map(|runtime| {
                            runtime
                                .ports
                                .lock()
                                .unwrap()
                                .keys()
                                .copied()
                                .collect::<Vec<_>>()
                        })
                        .unwrap_or_default(),
                );
                for port in &ports {
                    crate::trace::configure_port(
                        process,
                        session,
                        *port,
                        on,
                        port_mask,
                        tracer.clone(),
                    );
                }
                if atom_name(spec).as_deref() == Some("ports") {
                    crate::trace::configure_new_ports(
                        process,
                        session,
                        on,
                        port_mask,
                        tracer.clone(),
                    );
                }
                ports.len()
            }
            Some("new_ports") => {
                crate::trace::configure_new_ports(process, session, on, port_mask, tracer.clone());
                0
            }
            _ => return Err(badarg()),
        }
    };
    // Port of erts/emulator/beam/erl_bif_trace.c:890-1168 (erts_internal_trace_3), OTP-29.1.1.
    // Return instructions read process flags directly in erts; refresh code only when the
    // runtime-wide need for return-to instrumentation changes.
    if mask & crate::trace::RETURN_TO != 0
        && had_return_to != crate::trace::return_to_enabled(process)
    {
        vm.refresh_all_trace_breakpoints(process);
    }
    Term::small(matches as i64).ok_or_else(badarg)
}

// Port of erts/emulator/beam/erl_bif_trace.c:1232-1276 (trace_session_create), OTP-29.1.1.
fn trace_session_create(
    vm: &Vm,
    process: &mut Process,
    _ctx: &RunCtx<'_, Message>,
    name: Term,
    tracer_term: Term,
    options: Term,
) -> Result<Term, VmError> {
    if name.as_atom().is_none() || options != Term::NIL {
        return Err(badarg());
    }
    let tracer = if tracer_term == atom("undefined") {
        crate::trace::Tracer::Default
    } else if let Some(pid) = Pid::from_term(tracer_term) {
        if !live(process, pid)? {
            return Err(badarg());
        }
        crate::trace::Tracer::Pid(pid)
    } else if let Some(id) = tracer_term.as_port() {
        if !process
            .runtime
            .as_ref()
            .is_some_and(|runtime| runtime.ports.lock().unwrap().contains_key(&id))
        {
            return Err(badarg());
        }
        crate::trace::Tracer::Port(id)
    } else if let Some((module, state)) = tuple2(tracer_term) {
        module_tracer(vm, module, state)?
    } else {
        return Err(badarg());
    };
    let name = atom_name(name).ok_or_else(badarg)?;
    let (id, weak_id) = crate::trace::create_session(process, name.clone(), tracer);
    let handle = crate::trace::session_handle(process, id);
    let reference = TermBuilder::new(&mut arinsal_bifs::FragmentingHeap(&mut process.heap))
        .magic_ref(handle)
        .map_err(|_| badarg())?;
    let name = Term::atom(global_atoms().intern(&name).map_err(|_| badarg())?);
    let weak_id = Term::small(weak_id).ok_or_else(badarg)?;
    let weak_ref = make_tuple(process, &[name, weak_id])?;
    make_tuple(process, &[reference, weak_ref])
}

// Port of erts/emulator/beam/erl_trace.c:3017-3060 (load_tracer_nif), OTP-29.1.1.
fn module_tracer(vm: &Vm, module: Term, state: Term) -> Result<crate::trace::Tracer, VmError> {
    let module = atom_name(module).ok_or_else(badarg)?;
    if !crate::natives::nif::has_tracer_nifs(vm, &module) {
        return Err(badarg());
    }
    let state = arinsal_term::to_owned(state).map_err(|_| badarg())?;
    Ok(crate::trace::Tracer::Module { module, state })
}

fn trace_flag_names() -> &'static [(&'static str, u64)] {
    &[
        ("running_procs", crate::trace::RUNNING_PROCS),
        ("running_ports", crate::trace::RUNNING_PORTS),
        ("ports", crate::trace::PORTS),
        ("scheduler_id", crate::trace::SCHEDULER_ID),
        ("silent", crate::trace::SILENT),
        ("return_to", crate::trace::RETURN_TO),
        ("arity", crate::trace::ARITY),
        ("garbage_collection", crate::trace::GARBAGE_COLLECTION),
        ("exiting", crate::trace::EXITING),
        ("running", crate::trace::RUNNING),
        ("set_on_first_link", crate::trace::FIRST_LINK),
        ("set_on_link", crate::trace::SET_ON_LINK),
        ("set_on_first_spawn", crate::trace::SET_ON_FIRST_SPAWN),
        ("procs", crate::trace::PROCS),
        ("call", crate::trace::CALL),
        ("set_on_spawn", crate::trace::SET_ON_SPAWN),
        ("receive", crate::trace::RECEIVE),
        ("send", crate::trace::SEND),
        ("monotonic_timestamp", crate::trace::MONOTONIC_TIMESTAMP),
        (
            "strict_monotonic_timestamp",
            crate::trace::STRICT_MONOTONIC_TIMESTAMP,
        ),
        ("timestamp", crate::trace::TIMESTAMP),
    ]
}

fn process_trace_flag_names() -> impl Iterator<Item = (&'static str, u64)> {
    trace_flag_names()
        .iter()
        .copied()
        .filter(|(_, bit)| *bit & (crate::trace::PORTS | crate::trace::RUNNING_PORTS) == 0)
}

fn port_trace_flag_names() -> impl Iterator<Item = (&'static str, u64)> {
    const PORT_FLAGS: u64 = crate::trace::SEND
        | crate::trace::RECEIVE
        | crate::trace::TIMESTAMP
        | crate::trace::STRICT_MONOTONIC_TIMESTAMP
        | crate::trace::MONOTONIC_TIMESTAMP
        | crate::trace::SILENT
        | crate::trace::RUNNING_PORTS
        | crate::trace::PORTS
        | crate::trace::SCHEDULER_ID;
    trace_flag_names()
        .iter()
        .copied()
        .filter(|(_, bit)| *bit & PORT_FLAGS != 0)
}

fn trace_tracer_term(process: &mut Process, tracer: crate::trace::Tracer) -> Result<Term, VmError> {
    Ok(match tracer {
        crate::trace::Tracer::Default => Term::NIL,
        crate::trace::Tracer::Pid(pid) => pid.to_term().unwrap_or(Term::NIL),
        crate::trace::Tracer::Port(id) => Term::port(id).unwrap_or(Term::NIL),
        crate::trace::Tracer::Module { module, state, .. } => {
            let module = Term::atom(global_atoms().intern(&module).map_err(|_| badarg())?);
            let state = arinsal_term::from_owned(
                &state,
                &mut arinsal_bifs::FragmentingHeap(&mut process.heap),
            )
            .map_err(|_| badarg())?;
            make_tuple(process, &[module, state])?
        }
    })
}

fn trace_session_refs_term(
    process: &mut Process,
    refs: Vec<(String, i64)>,
) -> Result<Term, VmError> {
    let refs = refs
        .into_iter()
        .map(|(name, weak_id)| {
            let name = Term::atom(global_atoms().intern(&name).expect("session name atom"));
            let weak_id = if weak_id < 0 {
                atom("default")
            } else {
                Term::small(weak_id).ok_or_else(badarg)?
            };
            make_tuple(process, &[name, weak_id])
        })
        .collect::<Result<Vec<_>, _>>()?;
    make_list(process, refs)
}

// Port of erts/emulator/beam/erl_bif_trace.c:1403-1465, OTP-29.1.1.
fn trace_session_info(
    vm: &Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    session: u64,
    spec: Term,
    item: Term,
) -> Result<Term, VmError> {
    if atom_name(spec).as_deref() == Some("system") {
        if atom_name(item).as_deref() != Some("all") {
            return Err(badarg());
        }
        let runtime = process.runtime.as_ref().ok_or_else(badarg)?;
        let state = runtime
            .session_monitors
            .lock()
            .unwrap()
            .iter()
            .find(|(owner, _)| *owner == session)
            .map(|(_, state)| state.clone());
        let options = state.map_or_else(Vec::new, |state| {
            crate::natives::erts_debug::monitor_options_for_trace_info(&state.options)
        });
        let options = arinsal_term::from_owned(
            &arinsal_etf::OwnedTerm::list(options),
            &mut arinsal_bifs::FragmentingHeap(&mut process.heap),
        )
        .map_err(|_| badarg())?;
        return make_tuple(process, &[spec, options]);
    }
    if atom_name(spec).as_deref() == Some("on_load") {
        if atom_name(item).as_deref() == Some("session") {
            let refs = crate::trace_bp::on_load_patterns_of(process)
                .into_iter()
                .filter_map(|(session, _)| crate::trace::session_ref(process, session))
                .collect();
            let refs = trace_session_refs_term(process, refs)?;
            return make_tuple(process, &[item, refs]);
        }
        return trace_info_on_load(process, session, item);
    }
    if let Some(event) = atom_name(spec)
        && matches!(event.as_str(), "send" | "receive")
    {
        if atom_name(item).as_deref() == Some("session") {
            let refs = crate::trace::event_session_refs(process, &event);
            let refs = trace_session_refs_term(process, refs)?;
            return make_tuple(process, &[item, refs]);
        }
        if atom_name(item).as_deref() != Some("match_spec") {
            return Err(badarg());
        }
        let (enabled, match_spec) = crate::trace::event_match_spec(process, session, &event);
        let value = if !enabled {
            atom("false")
        } else if let Some(match_spec) = match_spec {
            arinsal_term::from_owned(
                &match_spec,
                &mut arinsal_bifs::FragmentingHeap(&mut process.heap),
            )
            .map_err(|_| badarg())?
        } else {
            atom("true")
        };
        return make_tuple(process, &[item, value]);
    }
    if session == 0
        && atom_name(spec).as_deref() == Some("any")
        && atom_name(item).as_deref() == Some("session")
    {
        // Port of erts/emulator/beam/erl_bif_trace.c:2427-2468
        // (trace_info_sessions), OTP-29.1.1.
        let refs = crate::trace::session_refs(process)
            .into_iter()
            .map(|(name, weak_id)| {
                let name = Term::atom(global_atoms().intern(&name).expect("session name atom"));
                let weak_id = if weak_id < 0 {
                    atom("default")
                } else {
                    Term::small(weak_id).ok_or_else(badarg)?
                };
                make_tuple(process, &[name, weak_id])
            })
            .collect::<Result<Vec<_>, _>>()?;
        let refs = make_list(process, refs)?;
        return make_tuple(process, &[item, refs]);
    }
    if matches!(atom_name(spec).as_deref(), Some("new" | "new_processes")) {
        if atom_name(item).as_deref() == Some("session") {
            let refs = crate::trace::new_process_session_refs(process);
            let refs = trace_session_refs_term(process, refs)?;
            return make_tuple(process, &[item, refs]);
        }
        let flags = crate::trace::new_process_flags(process, session);
        let value = match atom_name(item).as_deref() {
            Some("flags") => make_list(
                process,
                process_trace_flag_names()
                    .filter(|(_, bit)| flags & bit != 0)
                    .map(|(name, _)| atom(name)),
            )?,
            Some("tracer") => crate::trace::new_process_tracer(process, session)
                .map(|tracer| trace_tracer_term(process, tracer))
                .transpose()?
                .unwrap_or(Term::NIL),
            _ => return Ok(atom("undefined")),
        };
        return make_tuple(process, &[item, value]);
    }
    if atom_name(spec).as_deref() == Some("new_ports") {
        if atom_name(item).as_deref() == Some("session") {
            let refs = crate::trace::new_port_session_refs(process);
            let refs = trace_session_refs_term(process, refs)?;
            return make_tuple(process, &[item, refs]);
        }
        let flags = crate::trace::new_port_flags(process, session);
        let value = match atom_name(item).as_deref() {
            Some("flags") => make_list(
                process,
                port_trace_flag_names()
                    .filter(|(_, bit)| flags & bit != 0)
                    .map(|(name, _)| atom(name)),
            )?,
            Some("tracer") => crate::trace::new_port_tracer(process, session)
                .map(|tracer| trace_tracer_term(process, tracer))
                .transpose()?
                .unwrap_or(Term::NIL),
            _ => return Ok(atom("undefined")),
        };
        return make_tuple(process, &[item, value]);
    }
    if let Some(mfa) = trace_mfa(spec) {
        return trace_info_function(vm, process, ctx, session, mfa, item);
    }
    if let Some(port) = spec.as_port() {
        if port != 0 && !crate::port::is_live(process, port) {
            return Ok(atom("undefined"));
        }
        if session == 0 && atom_name(item).as_deref() == Some("session") {
            let refs = crate::trace::port_session_refs(process, port)
                .into_iter()
                .map(|(name, weak_id)| {
                    let name = Term::atom(global_atoms().intern(&name).expect("session name atom"));
                    let weak_id = if weak_id < 0 {
                        atom("default")
                    } else {
                        Term::small(weak_id).ok_or_else(badarg)?
                    };
                    make_tuple(process, &[name, weak_id])
                })
                .collect::<Result<Vec<_>, _>>()?;
            let refs = make_list(process, refs)?;
            return make_tuple(process, &[item, refs]);
        }
        let flags = crate::trace::port_flags(process, session, port);
        let value = match atom_name(item).as_deref() {
            Some("flags") => make_list(
                process,
                port_trace_flag_names()
                    .filter(|(_, bit)| flags & bit != 0)
                    .map(|(name, _)| atom(name)),
            )?,
            Some("tracer") => crate::trace::port_tracer(process, session, port)
                .map(|tracer| trace_tracer_term(process, tracer))
                .transpose()?
                .unwrap_or(Term::NIL),
            _ => return Ok(atom("undefined")),
        };
        return make_tuple(process, &[item, value]);
    }
    let Some(pid) = Pid::from_term(spec) else {
        return Ok(atom("undefined"));
    };
    if !live(process, pid)? {
        return Ok(atom("undefined"));
    }
    if session == 0 && atom_name(item).as_deref() == Some("session") {
        let refs = crate::trace::process_session_refs(process, pid);
        let refs = trace_session_refs_term(process, refs)?;
        return make_tuple(process, &[item, refs]);
    }
    let flags = crate::trace::session_flags(process, session, pid);
    let value = match atom_name(item).as_deref() {
        Some("flags") => make_list(
            process,
            process_trace_flag_names()
                .filter(|(_, bit)| flags & bit != 0)
                .map(|(name, _)| atom(name)),
        )?,
        Some("tracer") => {
            crate::trace::process_tracer(process, session, pid).map_or(Term::NIL, |tracer| {
                match tracer {
                    crate::trace::Tracer::Pid(pid) => {
                        pid.to_term().unwrap_or_else(|| atom("undefined"))
                    }
                    crate::trace::Tracer::Default => Term::NIL,
                    crate::trace::Tracer::Port(id) => {
                        Term::port(id).unwrap_or_else(|| atom("undefined"))
                    }
                    crate::trace::Tracer::Module { module, state, .. } => {
                        let module =
                            Term::atom(global_atoms().intern(&module).expect("tracer module atom"));
                        let state = arinsal_term::from_owned(
                            &state,
                            &mut arinsal_bifs::FragmentingHeap(&mut process.heap),
                        )
                        .unwrap_or_else(|_| atom("undefined"));
                        make_tuple(process, &[module, state]).unwrap_or_else(|_| atom("undefined"))
                    }
                }
            })
        }
        _ => return Ok(atom("undefined")),
    };
    make_tuple(process, &[item, value])
}

fn trace_info(
    vm: &Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    spec: Term,
    item: Term,
) -> Result<Term, VmError> {
    if atom_name(spec).as_deref() == Some("on_load") {
        return trace_info_on_load(process, 0, item);
    }
    if let Some(event) = atom_name(spec)
        && matches!(event.as_str(), "send" | "receive")
    {
        if atom_name(item).as_deref() != Some("match_spec") {
            return Err(badarg());
        }
        let (enabled, match_spec) = crate::trace::event_match_spec(process, 0, &event);
        let value = if !enabled {
            atom("false")
        } else if let Some(match_spec) = match_spec {
            arinsal_term::from_owned(
                &match_spec,
                &mut arinsal_bifs::FragmentingHeap(&mut process.heap),
            )
            .map_err(|_| badarg())?
        } else {
            atom("true")
        };
        return make_tuple(process, &[item, value]);
    }
    if matches!(atom_name(spec).as_deref(), Some("new" | "new_processes")) {
        let flags = crate::trace::new_process_flags(process, 0);
        let value = match atom_name(item).as_deref() {
            Some("flags") => make_list(
                process,
                process_trace_flag_names()
                    .filter(|(_, bit)| flags & bit != 0)
                    .map(|(name, _)| atom(name)),
            )?,
            Some("tracer") => crate::trace::new_process_tracer(process, 0)
                .map(|tracer| trace_tracer_term(process, tracer))
                .transpose()?
                .unwrap_or(Term::NIL),
            _ => return Ok(atom("undefined")),
        };
        return make_tuple(process, &[item, value]);
    }
    if atom_name(spec).as_deref() == Some("new_ports") {
        let flags = crate::trace::new_port_flags(process, 0);
        let value = match atom_name(item).as_deref() {
            Some("flags") => make_list(
                process,
                port_trace_flag_names()
                    .filter(|(_, bit)| flags & bit != 0)
                    .map(|(name, _)| atom(name)),
            )?,
            Some("tracer") => crate::trace::new_port_tracer(process, 0)
                .map(|tracer| trace_tracer_term(process, tracer))
                .transpose()?
                .unwrap_or(Term::NIL),
            _ => return Ok(atom("undefined")),
        };
        return make_tuple(process, &[item, value]);
    }
    if let Some(mfa) = trace_mfa(spec) {
        return trace_info_function(vm, process, ctx, 0, mfa, item);
    }
    if let Some(port) = spec.as_port() {
        if port != 0 && !crate::port::is_live(process, port) {
            return Ok(atom("undefined"));
        }
        if atom_name(item).as_deref() == Some("session") {
            let refs = crate::trace::port_session_refs(process, port)
                .into_iter()
                .map(|(name, weak_id)| {
                    let name = Term::atom(global_atoms().intern(&name).expect("session name atom"));
                    let weak_id = if weak_id < 0 {
                        atom("default")
                    } else {
                        Term::small(weak_id).ok_or_else(badarg)?
                    };
                    make_tuple(process, &[name, weak_id])
                })
                .collect::<Result<Vec<_>, _>>()?;
            let refs = make_list(process, refs)?;
            return make_tuple(process, &[item, refs]);
        }
        let flags = crate::trace::port_flags(process, 0, port);
        let value = match atom_name(item).as_deref() {
            Some("flags") => make_list(
                process,
                port_trace_flag_names()
                    .filter(|(_, bit)| flags & bit != 0)
                    .map(|(name, _)| atom(name)),
            )?,
            Some("tracer") => crate::trace::port_tracer(process, 0, port)
                .map(|tracer| trace_tracer_term(process, tracer))
                .transpose()?
                .unwrap_or(Term::NIL),
            _ => return Ok(atom("undefined")),
        };
        return make_tuple(process, &[item, value]);
    }
    let Some(pid) = Pid::from_term(spec) else {
        return Ok(atom("undefined"));
    };
    if !live(process, pid)? {
        return Ok(atom("undefined"));
    }
    let flags = crate::trace::session_flags(process, 0, pid);
    let value = match atom_name(item).as_deref() {
        Some("flags") => {
            let list = process_trace_flag_names()
                .filter(|(_, bit)| flags & bit != 0)
                .map(|(name, _)| atom(name));
            let list_term = make_list(process, list)?;
            make_tuple(process, &[atom("flags"), list_term])?
        }
        Some("tracer") => {
            let tracer = match crate::trace::tracer(process, pid) {
                Some(crate::trace::Tracer::Pid(pid)) => {
                    pid.to_term().unwrap_or_else(|| atom("undefined"))
                }
                Some(crate::trace::Tracer::Default) => Term::NIL,
                Some(crate::trace::Tracer::Port(id)) => {
                    Term::port(id).unwrap_or_else(|| atom("undefined"))
                }
                Some(crate::trace::Tracer::Module { module, state, .. }) => {
                    let module =
                        Term::atom(global_atoms().intern(&module).expect("tracer module atom"));
                    let state = arinsal_term::from_owned(
                        &state,
                        &mut arinsal_bifs::FragmentingHeap(&mut process.heap),
                    )
                    .unwrap_or_else(|_| atom("undefined"));
                    make_tuple(process, &[module, state]).unwrap_or_else(|_| atom("undefined"))
                }
                None => Term::NIL,
            };
            make_tuple(process, &[atom("tracer"), tracer])?
        }
        _ => return Ok(atom("undefined")),
    };
    Ok(value)
}

/// The tracer of a `{meta, Tracer}` or `{meta, Module, State}` trace_pattern flag.
// Port of erts/emulator/beam/erl_trace.c:3090-3129 (erts_term_to_tracer), OTP-29.1.1.
fn meta_tracer_from_term(vm: &Vm, flag: Term) -> Result<crate::trace::Tracer, VmError> {
    // SAFETY: The flag list stays rooted for this BIF call.
    let tuple = unsafe { flag.tuple_ref() }.ok_or_else(badarg)?;
    let fields = (0..tuple.len())
        .map(|index| tuple.get(index).ok_or_else(badarg))
        .collect::<Result<Vec<_>, _>>()?;
    let from_state = |term: Term| {
        if let Some(pid) = Pid::from_term(term) {
            Ok(crate::trace::Tracer::Pid(pid))
        } else if let Some(id) = term.as_port() {
            Ok(crate::trace::Tracer::Port(id))
        } else {
            Err(badarg())
        }
    };
    match fields.as_slice() {
        [prefix, tracer] if atom_name(*prefix).as_deref() == Some("meta") => from_state(*tracer),
        [prefix, module, state]
            if atom_name(*prefix).as_deref() == Some("meta") && module.as_atom().is_some() =>
        {
            module_tracer(vm, *module, *state)
        }
        _ => Err(badarg()),
    }
}

/// `trace_info({M,F,A}, Key)` of a session.
// Port of erts/emulator/beam/erl_bif_trace.c:1913-1960 (trace_info_func) and 2132-2290
// (trace_info_func_epilogue), OTP-29.1.1.
/// Code barriers `trace_info` waits for (the initial one and one per `trace_info_finisher` phase).
const TRACE_INFO_BARRIERS: usize = 3;

fn trace_info_function(
    vm: &Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    session: u64,
    (module, function, arity): (String, String, u8),
    item: Term,
) -> Result<Term, VmError> {
    use crate::trace_bp::{
        GOT_COUNT, GOT_GLOBAL, GOT_LOCAL, GOT_MEMORY, GOT_META, GOT_TIME, WANT_COUNT, WANT_MEMORY,
        WANT_META, WANT_TIME, WANT_TRACE,
    };
    let key = atom_name(item).unwrap_or_default();
    if key == "session" {
        // Port of erts/emulator/beam/erl_bif_trace.c:2427-2468 (trace_info_sessions), OTP-29.1.1.
        if !function_exists(vm, &module, &function, arity) {
            return make_tuple(process, &[item, atom("undefined")]);
        }
        let refs = crate::trace_bp::sessions_for_function(process, &module, &function, arity)
            .into_iter()
            .filter_map(|session| crate::trace::session_ref(process, session))
            .collect();
        let refs = trace_session_refs_term(process, refs)?;
        return make_tuple(process, &[item, refs]);
    }
    let want = match key.as_str() {
        "traced" | "match_spec" => WANT_TRACE,
        "meta" | "meta_match_spec" => WANT_META,
        "call_count" => WANT_COUNT,
        "call_time" => WANT_TIME,
        "call_memory" => WANT_MEMORY,
        "all" => WANT_TRACE | WANT_META | WANT_COUNT | WANT_TIME | WANT_MEMORY,
        _ => return Err(badarg()),
    };
    // A function that does not exist reports `undefined`, an untraced one `false`.
    if !function_exists(vm, &module, &function, arity) {
        return make_tuple(process, &[item, atom("undefined")]);
    }
    let mut info =
        crate::trace_bp::function_info(process, session, &module, &function, arity, want);
    if info.counters_active {
        // erts stages the breakpoint data without the active counters and waits for a code
        // barrier per phase, so no scheduler updates a counter while it is collected.
        // Port of erts/emulator/beam/erl_bif_trace.c:1960-2070 (trace_info_func,
        // trace_info_finisher phases 0-2), OTP-29.1.1.
        // Resumed after the last barrier, the caller builds the result again
        // (bif_trace_info_finish_trap).
        let waited = process
            .cold
            .as_mut()
            .and_then(|cold| {
                cold.trace_finish
                    .take_if(|finish| finish.stages.is_empty() && finish.result.is_none())
            })
            .is_some();
        if !waited {
            wait_code_barriers(
                process,
                ctx,
                crate::trace_bp::TraceFinish::wait(TRACE_INFO_BARRIERS, None),
            )?;
        }
        info = crate::trace_bp::function_info(process, session, &module, &function, arity, want);
    }
    if info.got == 0 {
        return make_tuple(process, &[item, atom("false")]);
    }
    let owned = |process: &mut Process, term: &arinsal_etf::OwnedTerm| {
        arinsal_term::from_owned(term, &mut arinsal_bifs::FragmentingHeap(&mut process.heap))
            .map_err(|_| badarg())
    };
    let (traced, mut match_spec) = if info.got & GOT_GLOBAL != 0 {
        (atom("global"), Term::NIL)
    } else if info.got & GOT_LOCAL != 0 {
        (atom("local"), Term::NIL)
    } else {
        (atom("false"), atom("false"))
    };
    if let Some(spec) = &info.local_ms {
        match_spec = owned(process, spec)?;
    }
    let tracer_term = |process: &mut Process, tracer: crate::trace::Tracer| match tracer {
        crate::trace::Tracer::Default => Ok(atom("false")),
        tracer => trace_tracer_term(process, tracer),
    };
    let meta_match_spec = |process: &mut Process| -> Result<Term, VmError> {
        if info.got & GOT_META == 0 {
            return Ok(atom("false"));
        }
        match &info.meta_ms {
            Some(spec) => owned(process, spec),
            None => Ok(Term::NIL),
        }
    };
    let call_count = |process: &mut Process| -> Result<Term, VmError> {
        if info.got & GOT_COUNT == 0 {
            return Ok(atom("false"));
        }
        arinsal_term::TermBuilder::new(&mut arinsal_bifs::FragmentingHeap(&mut process.heap))
            .int_from_i64(info.count as i64)
            .map_err(|_| badarg())
    };
    // Port of erts/emulator/beam/beam_bp.c:1664-1736 (erts_build_timem_info).
    let call_time = |process: &mut Process| -> Result<Term, VmError> {
        let Some(entries) = info.time.as_ref().filter(|_| info.got & GOT_TIME != 0) else {
            return Ok(atom("false"));
        };
        let mut tuples = Vec::new();
        for (pid, count, nanos) in entries {
            let micros = nanos / 1000;
            let tuple = make_tuple(
                process,
                &[
                    pid.to_term().ok_or_else(badarg)?,
                    Term::small(*count).ok_or_else(badarg)?,
                    Term::small(micros / 1_000_000).ok_or_else(badarg)?,
                    Term::small(micros % 1_000_000).ok_or_else(badarg)?,
                ],
            )?;
            tuples.push(tuple);
        }
        make_list(process, tuples)
    };
    let call_memory = |process: &mut Process| -> Result<Term, VmError> {
        let Some(entries) = info.memory.as_ref().filter(|_| info.got & GOT_MEMORY != 0) else {
            return Ok(atom("false"));
        };
        let mut tuples = Vec::new();
        for (pid, count, words) in entries {
            let words = arinsal_term::TermBuilder::new(&mut arinsal_bifs::FragmentingHeap(
                &mut process.heap,
            ))
            .int_from_i64(*words)
            .map_err(|_| badarg())?;
            let tuple = make_tuple(
                process,
                &[
                    pid.to_term().ok_or_else(badarg)?,
                    Term::small(*count).ok_or_else(badarg)?,
                    words,
                ],
            )?;
            tuples.push(tuple);
        }
        make_list(process, tuples)
    };
    let value = match key.as_str() {
        "traced" => traced,
        "match_spec" => match_spec,
        "meta" => {
            // Backwards compatibility: no meta tracer is `[]`.
            match tracer_term(process, info.meta.clone())? {
                term if term == atom("false") => Term::NIL,
                term => term,
            }
        }
        "meta_match_spec" => meta_match_spec(process)?,
        "call_count" => call_count(process)?,
        "call_time" => call_time(process)?,
        "call_memory" => call_memory(process)?,
        _ => {
            let meta = tracer_term(process, info.meta.clone())?;
            let meta_match_spec = meta_match_spec(process)?;
            let call_count = call_count(process)?;
            let call_time = call_time(process)?;
            let call_memory = call_memory(process)?;
            let entries = [
                ("traced", traced),
                ("match_spec", match_spec),
                ("meta", meta),
                ("meta_match_spec", meta_match_spec),
                ("call_memory", call_memory),
                ("call_time", call_time),
                ("call_count", call_count),
            ];
            let mut pairs = Vec::new();
            for (key, value) in entries {
                pairs.push(make_tuple(process, &[atom(key), value])?);
            }
            make_list(process, pairs)?
        }
    };
    make_tuple(process, &[item, value])
}

/// Count the functions of the current code of the selected modules.
// Port of erts/emulator/beam/erl_bif_trace.c:1594-1640 (erts_set_trace_pattern), OTP-29.1.1.
fn matched_functions(vm: &Vm, module: &str, function: &str, arity: Option<u8>) -> usize {
    vm.code
        .modules
        .iter()
        .enumerate()
        .filter(|(id, loaded)| {
            (module == "_" || loaded.name == module) && vm.code.loaded.get(&loaded.name) == Some(id)
        })
        .flat_map(|(_, loaded)| loaded.functions.iter())
        .filter(|(_, name, n)| {
            (function == "_" || *name == function) && arity.is_none_or(|a| a == *n)
        })
        .count()
}

fn function_exists(vm: &Vm, module: &str, function: &str, arity: u8) -> bool {
    matched_functions(vm, module, function, Some(arity)) > 0
        || arinsal_bifs::lookup(module, function, arity).is_some()
}

fn trace_mfa(spec: Term) -> Option<(String, String, u8)> {
    let owned = arinsal_term::to_owned(spec).ok()?;
    let arinsal_etf::OwnedTerm::Tuple(fields) = &owned else {
        return None;
    };
    let [
        arinsal_etf::OwnedTerm::Atom(module),
        arinsal_etf::OwnedTerm::Atom(function),
        arity,
    ] = fields.as_slice()
    else {
        return None;
    };
    let arinsal_etf::OwnedTerm::Int(arity) = arity else {
        return None;
    };
    Some((module.clone(), function.clone(), u8::try_from(*arity).ok()?))
}

// Port of erts/emulator/beam/erl_bif_trace.c:303-315 (trace_pattern), OTP-29.1.1.
/// Validate a trace match specification like `db_match_set_compile`.
// Port of erts/emulator/beam/erl_db_util.c:1212-1232 (erts_match_set_compile freason), OTP-29.1.1.
/// `event` is `Some(receive)` for send and receive event patterns, `None` for call patterns.
fn compile_trace_pattern(pattern: Term, event: Option<bool>) -> Result<(), VmError> {
    let compiled = match event {
        Some(receive) => {
            arinsal_ets::match_spec::MatchProgram::compile_trace_event(pattern, receive)
        }
        None => arinsal_ets::match_spec::MatchProgram::compile_trace(pattern),
    };
    match compiled {
        Ok(_) => Ok(()),
        Err(arinsal_ets::EtsError::Term(arinsal_term::TermError::SystemLimit)) => Err(
            VmError::Trap(crate::exceptions::Trap::error(atom("system_limit"))),
        ),
        Err(_) => Err(badarg()),
    }
}

/// `trace_info(on_load, Key)` of a session.
// Port of erts/emulator/beam/erl_bif_trace.c:2292-2420 (trace_info_on_load), OTP-29.1.1.
fn trace_info_on_load(process: &mut Process, session: u64, item: Term) -> Result<Term, VmError> {
    let Some(state) = crate::trace_bp::on_load_pattern(process, session) else {
        return make_tuple(process, &[item, atom("false")]);
    };
    let flags = state.flags;
    let owned = |process: &mut Process, term: &Option<arinsal_etf::OwnedTerm>| match term {
        Some(term) => {
            arinsal_term::from_owned(term, &mut arinsal_bifs::FragmentingHeap(&mut process.heap))
                .map_err(|_| badarg())
        }
        None => Ok(Term::NIL),
    };
    let traced = if !flags.breakpoint {
        atom("global")
    } else if flags.local {
        atom("local")
    } else {
        atom("false")
    };
    let bool_atom = |value: bool| atom(if value { "true" } else { "false" });
    let value = match atom_name(item).as_deref() {
        Some("traced") => traced,
        Some("match_spec") => {
            if !flags.breakpoint || flags.local {
                owned(process, &state.match_spec)?
            } else {
                atom("false")
            }
        }
        Some("meta") => {
            if flags.meta {
                match state.meta_tracer.clone() {
                    crate::trace::Tracer::Default => atom("false"),
                    tracer => trace_tracer_term(process, tracer)?,
                }
            } else {
                atom("false")
            }
        }
        Some("meta_match_spec") => {
            if flags.meta {
                owned(process, &state.meta_match_spec)?
            } else {
                atom("false")
            }
        }
        Some("call_count") => bool_atom(flags.call_count),
        Some("call_time") => bool_atom(flags.call_time),
        Some("call_memory") => bool_atom(flags.call_memory),
        Some("all") => {
            let mut match_spec = if flags.local || !flags.breakpoint {
                Term::NIL
            } else {
                atom("false")
            };
            if state.match_spec.is_some() {
                match_spec = owned(process, &state.match_spec)?;
            }
            let mut meta_match_spec = if flags.meta { Term::NIL } else { atom("false") };
            if state.meta_match_spec.is_some() {
                meta_match_spec = owned(process, &state.meta_match_spec)?;
            }
            let meta = if flags.meta {
                match state.meta_tracer.clone() {
                    crate::trace::Tracer::Default => atom("false"),
                    tracer => trace_tracer_term(process, tracer)?,
                }
            } else {
                atom("false")
            };
            let entries = [
                ("traced", traced),
                ("match_spec", match_spec),
                ("meta", meta),
                ("meta_match_spec", meta_match_spec),
                ("call_count", bool_atom(flags.call_count)),
            ];
            let mut pairs = Vec::new();
            for (key, value) in entries {
                pairs.push(make_tuple(process, &[atom(key), value])?);
            }
            make_list(process, pairs)?
        }
        _ => return Err(badarg()),
    };
    make_tuple(process, &[item, value])
}

/// Runs a trace BIF holding the code modification permission. A caller that is not given
/// the permission is suspended and retries the call once it is handed over; a caller
/// suspended between the code barriers of a breakpoint update continues it instead.
// Port of erts/emulator/beam/erl_bif_trace.c:302-331, 889-918, 1386-1435 (seize, yield and
// release around trace_pattern, trace, trace_info), OTP-29.1.1.
fn with_code_mod_permission(
    vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    body: impl FnOnce(&mut Vm, &mut Process, &mut RunCtx<'_, Message>) -> Result<Term, VmError>,
) -> Result<Term, VmError> {
    let pid = ctx.pid();
    let runtime = process.runtime.clone();
    if let Some(finish) = process
        .cold
        .as_mut()
        .and_then(|cold| cold.trace_finish.take())
    {
        // Resumed by the code barrier: the permission is still ours.
        let finish = advance_trace_finish(vm, process, ctx, finish, true)?;
        if let Some(result) = finish.result {
            if let Some(runtime) = &runtime {
                crate::natives::code::release_code_mod_permission(runtime);
            }
            return Term::small(result).ok_or_else(badarg);
        }
        // bif_trace_info_finish_trap: build the result again, without waiting.
        process.cold_mut().trace_finish = Some(finish);
    } else if let Some(runtime) = &runtime
        && !crate::natives::code::try_seize_code_mod_permission(runtime, pid)
    {
        return Err(VmError::Yield);
    }
    let result = body(vm, process, ctx);
    let pending = match process.cold.as_mut() {
        Some(cold) => {
            if cold
                .trace_finish
                .as_ref()
                .is_some_and(|finish| finish.stages.is_empty() && finish.result.is_none())
            {
                cold.trace_finish = None;
            }
            cold.trace_finish.is_some()
        }
        None => false,
    };
    if !pending && let Some(runtime) = &runtime {
        crate::natives::code::release_code_mod_permission(runtime);
    }
    result
}

/// Waits for a code barrier: the caller is suspended until every scheduler passed thread
/// progress, without blocking this scheduler. Returns false when the wait already happened
/// (no runtime to resume the caller, so it blocks).
// Port of erts/emulator/beam/code_ix.c:556 (erts_schedule_code_barrier) with the caller
// suspended like erl_bif_trace.c:509-516 (trace_pattern) and resumed like :575-581
// (smp_bp_finisher), OTP-29.1.1.
fn suspend_for_code_barrier(process: &Process, ctx: &mut RunCtx<'_, Message>) -> bool {
    let Some(runtime) = process.runtime.clone() else {
        ctx.block_thread_progress(std::time::Duration::ZERO);
        return false;
    };
    let pid = ctx.pid();
    runtime.suspend_internal(pid);
    ctx.thread_progress_later(move || crate::natives::code::resume_suspended(&runtime, pid));
    true
}

/// [`advance_trace_finish`] for an update that only waits for code barriers.
fn wait_code_barriers(
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    mut finish: crate::trace_bp::TraceFinish,
) -> Result<crate::trace_bp::TraceFinish, VmError> {
    debug_assert!(
        finish
            .stages
            .iter()
            .all(|stage| *stage == crate::trace_bp::FinishStage::Wait)
    );
    loop {
        if suspend_for_code_barrier(process, ctx) {
            process.cold_mut().trace_finish = Some(finish);
            return Err(VmError::Yield);
        }
        if finish.stages.pop_front().is_none() {
            return Ok(finish);
        }
    }
}

/// Runs the stages of a breakpoint update, each after a code barrier. Yields with the
/// update parked in the caller while it waits; returns the update once every stage ran and
/// the last barrier passed.
// Port of erts/emulator/beam/erl_bif_trace.c:535-590 (smp_bp_finisher) and 2052-2100
// (trace_info_finisher), OTP-29.1.1.
fn advance_trace_finish(
    vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    mut finish: crate::trace_bp::TraceFinish,
    mut barrier_passed: bool,
) -> Result<crate::trace_bp::TraceFinish, VmError> {
    loop {
        if !barrier_passed && suspend_for_code_barrier(process, ctx) {
            process.cold_mut().trace_finish = Some(finish);
            return Err(VmError::Yield);
        }
        barrier_passed = false;
        let Some(stage) = finish.stages.pop_front() else {
            return Ok(finish);
        };
        run_finish_stage(vm, process, &finish.functions, stage);
    }
}

// Port of erts/emulator/beam/erl_bif_trace.c:2842-2935 (erts_finish_breakpointing), OTP-29.1.1.
fn run_finish_stage(
    vm: &mut Vm,
    process: &Process,
    functions: &[crate::trace_bp::BpFunction],
    stage: crate::trace_bp::FinishStage,
) {
    use crate::trace_bp::FinishStage;
    match stage {
        FinishStage::Install => {
            vm.refresh_code();
            crate::trace_bp::with_install_view(|| vm.refresh_trace_functions(process, functions));
        }
        FinishStage::Commit => crate::trace_bp::commit_staged(process),
        FinishStage::Uninstall => {
            vm.refresh_code();
            vm.refresh_trace_functions(process, functions);
        }
        FinishStage::Consolidate => crate::trace_bp::consolidate_staged(process, functions),
        FinishStage::Wait => {}
    }
}

/// An exiting caller of a trace BIF finishes its breakpoint update, which erts' finisher
/// completes without the caller, and releases the code modification permission.
// Port of erts/emulator/beam/erl_bif_trace.c:535-590 (smp_bp_finisher skips resuming an
// exiting caller) and 2016-2050 (trace_info_trap_destructor), OTP-29.1.1.
pub(crate) fn trace_finish_process_exit(
    vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
) {
    let Some(mut finish) = process
        .cold
        .as_mut()
        .and_then(|cold| cold.trace_finish.take())
    else {
        return;
    };
    // The exit path has no later resume, so the barriers between breakpoint stages block;
    // a caller that only waits (trace_info) just gives up.
    finish
        .stages
        .retain(|stage| *stage != crate::trace_bp::FinishStage::Wait);
    let staged = !finish.stages.is_empty();
    while let Some(stage) = finish.stages.pop_front() {
        ctx.block_thread_progress(std::time::Duration::ZERO);
        run_finish_stage(vm, process, &finish.functions, stage);
    }
    if staged {
        ctx.block_thread_progress(std::time::Duration::ZERO);
    }
    if let Some(runtime) = &process.runtime {
        crate::natives::code::release_code_mod_permission(runtime);
    }
}

fn trace_pattern(
    vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    session: u64,
    spec: Term,
    pattern: Term,
    flags: Term,
) -> Result<Term, VmError> {
    // Patch the current code of every module, including loads this scheduler's VM has not seen.
    vm.refresh_code();
    if let Some(event) = atom_name(spec)
        && matches!(event.as_str(), "send" | "receive")
    {
        // Port of erts/emulator/beam/erl_bif_trace.c:484-502 and 2800-2828,
        // OTP-29.1.1. Event patterns are session state, not MFA breakpoints.
        let owned_flags = arinsal_term::to_owned(flags).map_err(|_| badarg())?;
        let empty_flags = match &owned_flags {
            arinsal_etf::OwnedTerm::Nil => true,
            arinsal_etf::OwnedTerm::List { elems, tail } => {
                elems.is_empty() && **tail == arinsal_etf::OwnedTerm::Nil
            }
            _ => false,
        };
        if !empty_flags {
            return Err(badarg());
        }
        let (enabled, match_spec) = if pattern == atom("false") {
            (false, None)
        } else {
            let mut match_spec = None;
            if pattern != atom("true") && pattern != Term::NIL {
                compile_trace_pattern(pattern, Some(event == "receive"))?;
                let owned = arinsal_term::to_owned(pattern).map_err(|_| badarg())?;
                match_spec = Some(owned);
            }
            (true, match_spec)
        };
        crate::trace::set_event_pattern(process, session, &event, enabled, match_spec);
        // stage_trace_event_pattern is neither local nor global: the commit and consolidate
        // stages wait, plus the initial barrier.
        let finish =
            wait_code_barriers(process, ctx, crate::trace_bp::TraceFinish::wait(3, Some(1)))?;
        return Term::small(finish.result.unwrap_or(1)).ok_or_else(badarg);
    }
    let flag_values = list(flags).ok_or_else(badarg)?;
    // Port of erts/emulator/beam/erl_bif_trace.c:344-420 (trace_pattern flag list), OTP-29.1.1.
    let session_tracer_nil = matches!(
        crate::trace::session_tracer(process, session),
        None | Some(crate::trace::Tracer::Default)
    );
    let mut names: Vec<String> = Vec::new();
    let mut meta_tracer: Option<crate::trace::Tracer> = None;
    let mut is_global = false;
    for flag in flag_values {
        if flag.classify() == TermKind::Tuple && session_tracer_nil {
            meta_tracer = Some(meta_tracer_from_term(vm, flag)?);
            names.push("meta".into());
            continue;
        }
        let name = atom_name(flag).ok_or_else(badarg)?;
        match name.as_str() {
            "local" | "call_count" | "call_time" | "call_memory" if !is_global => {}
            "meta" if !is_global => {
                if meta_tracer.is_none() {
                    meta_tracer = Some(match crate::trace::session_tracer(process, session) {
                        None | Some(crate::trace::Tracer::Default) => {
                            crate::trace::Tracer::Pid(process.self_pid.ok_or_else(badarg)?)
                        }
                        Some(tracer) => tracer,
                    });
                }
            }
            "global" if names.is_empty() => is_global = true,
            _ => return Err(badarg()),
        }
        names.push(name);
    }
    // Port of erts/emulator/beam/erl_bif_trace.c:334-475 (trace_pattern), OTP-29.1.1.
    let trace_flags = crate::trace_bp::TracePatternFlags {
        breakpoint: names.iter().any(|name| name != "global"),
        local: names.iter().any(|name| name == "local"),
        meta: names.iter().any(|name| name == "meta"),
        call_count: names.iter().any(|name| name == "call_count"),
        call_time: names.iter().any(|name| name == "call_time"),
        call_memory: names.iter().any(|name| name == "call_memory"),
    };
    let mut match_spec = None;
    let on = if pattern == atom("false") {
        crate::trace_bp::BreakOp::Nop
    } else if pattern == atom("true") || pattern == Term::NIL {
        crate::trace_bp::BreakOp::Set
    } else if pattern == atom("restart") {
        crate::trace_bp::BreakOp::Restart
    } else if pattern == atom("pause") {
        crate::trace_bp::BreakOp::Pause
    } else {
        compile_trace_pattern(pattern, None)?;
        let owned = arinsal_term::to_owned(pattern).map_err(|_| badarg())?;
        match_spec = Some(owned);
        crate::trace_bp::BreakOp::Set
    };
    if match_spec.is_some()
        && !trace_flags.local
        && !trace_flags.meta
        && (trace_flags.call_count || trace_flags.call_time || trace_flags.call_memory)
    {
        return Err(badarg());
    }
    if atom_name(spec).as_deref() == Some("on_load") {
        // Port of erts/emulator/beam/erl_bif_trace.c:465-468, OTP-29.1.1.
        crate::trace_bp::change_on_load(
            process,
            session,
            on,
            trace_flags,
            match_spec,
            &meta_tracer.unwrap_or_default(),
        );
        return Ok(Term::small(0).expect("zero matches"));
    }
    let owned_spec = arinsal_term::to_owned(spec).map_err(|_| badarg())?;
    let arinsal_etf::OwnedTerm::Tuple(spec_fields) = &owned_spec else {
        return Err(badarg());
    };
    let [
        arinsal_etf::OwnedTerm::Atom(module),
        arinsal_etf::OwnedTerm::Atom(function),
        arity_term,
    ] = spec_fields.as_slice()
    else {
        return Err(badarg());
    };
    // Port of erts/emulator/beam/erl_bif_trace.c:480-488: a wildcard may only be followed by
    // wildcards.
    if (module == "_"
        && (function != "_" || !matches!(arity_term, arinsal_etf::OwnedTerm::Atom(a) if a == "_")))
        || (function == "_" && !matches!(arity_term, arinsal_etf::OwnedTerm::Atom(a) if a == "_"))
    {
        return Err(badarg());
    }
    let module = module.clone();
    let function = function.clone();
    let arity = if matches!(arity_term, arinsal_etf::OwnedTerm::Atom(name) if name == "_") {
        None
    } else {
        let arinsal_etf::OwnedTerm::Int(arity) = arity_term else {
            return Err(badarg());
        };
        Some(u8::try_from(*arity).map_err(|_| badarg())?)
    };
    let functions = bp_functions(vm, &module, &function, arity);
    // Port of erts/emulator/beam/erl_bif_trace.c:2661-2725 (erts_set_trace_pattern): the count
    // is of the matched functions; only clearing, pausing and restarting skip the ones that
    // have no breakpoint.
    let matched = functions.len();
    let matched_exported = functions
        .iter()
        .filter(|function| function.exported)
        .count();
    let functions = if on == crate::trace_bp::BreakOp::Set {
        functions
    } else {
        crate::trace_bp::with_breakpoints(process, functions)
    };
    // Port of erts/emulator/beam/erl_bif_trace.c:507-515, 535-570 and 2842-2925 (trace_pattern,
    // smp_bp_finisher, erts_finish_breakpointing), OTP-29.1.1: the caller stays suspended while
    // the breakpoints are staged, installed, committed, uninstalled and consolidated, with a
    // code barrier before each stage.
    crate::trace_bp::stage_trace_pattern(
        process,
        session,
        &functions,
        match_spec.clone(),
        match_spec,
        on,
        trace_flags,
        &meta_tracer.unwrap_or_default(),
    );
    // Port of erts/emulator/beam/erl_bif_trace.c:2712-2716, OTP-29.1.1: breakpoints count the
    // matched functions, global tracing the matched export entries.
    let count = if trace_flags.breakpoint {
        matched
    } else {
        matched_exported
    };
    let finish = crate::trace_bp::TraceFinish::breakpoints(
        functions,
        on != crate::trace_bp::BreakOp::Nop,
        count as i64,
    );
    let finish = advance_trace_finish(vm, process, ctx, finish, false)?;
    let count = finish.result.unwrap_or(count as i64);
    Term::small(count).ok_or_else(badarg)
}

/// The functions of the current code of the selected modules.
// Port of erts/emulator/beam/beam_bp.c:183-260 (erts_bp_match_functions), OTP-29.1.1.
pub(crate) fn bp_functions(
    vm: &Vm,
    module: &str,
    function: &str,
    arity: Option<u8>,
) -> Vec<crate::trace_bp::BpFunction> {
    vm.code
        .modules
        .iter()
        .enumerate()
        .filter(|(id, loaded)| {
            (module == "_" || loaded.name == module) && vm.code.loaded.get(&loaded.name) == Some(id)
        })
        .flat_map(|(_, loaded)| {
            loaded
                .functions
                .iter()
                .filter(|(_, name, n)| {
                    (function == "_" || *name == function) && arity.is_none_or(|a| a == *n)
                })
                .map(|(entry, name, n)| crate::trace_bp::BpFunction {
                    module: loaded.name.clone(),
                    function: name.clone(),
                    arity: *n,
                    entry: entry + 1,
                    exported: loaded
                        .exports
                        .iter()
                        .any(|export| export.function == *name && export.arity == *n),
                })
        })
        .collect()
}

fn live_pids(process: &Process) -> Result<Vec<Pid>, VmError> {
    let runtime = process.runtime.as_ref().ok_or_else(badarg)?;
    let scheduler = runtime.scheduler()?;
    let mut pids = runtime
        .processes
        .lock()
        .unwrap()
        .iter()
        .copied()
        .filter(|pid| scheduler.lookup(*pid))
        .collect::<Vec<_>>();
    pids.sort_by_key(|pid| crate::process::pid_table_index(*pid));
    Ok(pids)
}

// Port of erts/emulator/beam/bif.c:4107 (erts_internal_processes_next_1)
// and erl_ptab.c:1473 (erts_ptab_processes_next), OTP-29.1.1.
// The cursor is the next process-table index, so exiting processes do not
// invalidate a scan that is already in progress.
fn processes_next(
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    cursor: Term,
) -> Result<Term, VmError> {
    let index = u32::try_from(cursor.as_small().ok_or_else(badarg)?).map_err(|_| badarg())?;
    let max_pids = ctx.remaining().max(1);
    let limit = index
        .saturating_add(max_pids.saturating_mul(25))
        .min(arinsal_term::ptab::process_table_layout().max());
    if index == limit && index != 0 {
        return Ok(atom("none"));
    }
    if index > limit {
        return Err(badarg());
    }
    let runtime = process.runtime.as_ref().ok_or_else(badarg)?;
    let scheduler = runtime.scheduler()?;
    let (mut pids, scan_end) = scheduler.pids_in_table_range(index, limit, max_pids as usize);
    // List only processes registered with this runtime, as erlang:processes/0 does.
    {
        let processes = runtime.processes.lock().unwrap();
        pids.retain(|pid| processes.contains(pid));
    }
    let pid_terms = pids
        .iter()
        .map(|pid| pid.to_term().ok_or_else(badarg))
        .collect::<Result<Vec<_>, _>>()?;
    let scanned = ((scan_end.saturating_sub(index) / 25) + 1).min(ctx.remaining());
    ctx.consume(scanned);
    let next = Term::small(i64::from(scan_end)).ok_or_else(badarg)?;
    let batch = make_list(process, pid_terms)?;
    make_tuple(process, &[next, batch])
}

// Port of erts/preloaded/src/erlang.erl:5655-5665, OTP-29.1.1.
// Port of erts/preloaded/src/erlang.erl:5655 (processes_next/1), OTP-29.1.1: the
// iterator `{Ref, Batch}` is stepped in place; the remaining batch is shared, not copied.
fn erlang_processes_next(
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    iterator: Term,
) -> Result<Term, VmError> {
    fn step(process: &mut Process, reference: Term, batch: Term) -> Result<Term, VmError> {
        // SAFETY: The batch list is rooted in the caller's iterator for this BIF.
        let (pid, rest) = unsafe { batch.cons_ref() }.ok_or_else(badarg)?;
        let mut heap = arinsal_bifs::FragmentingHeap(&mut process.heap);
        let mut builder = TermBuilder::new(&mut heap);
        let next = builder
            .tuple(&[reference, rest])
            .map_err(|error| VmError::Unsupported(format!("process iterator: {error:?}")))?;
        builder
            .tuple(&[pid, next])
            .map_err(|error| VmError::Unsupported(format!("process iterator: {error:?}")))
    }

    let (mut reference, batch) = tuple2(iterator).ok_or_else(badarg)?;
    if batch.classify() == TermKind::List {
        return step(process, reference, batch);
    }
    if batch != Term::NIL {
        return Err(badarg());
    }
    loop {
        let next = processes_next(process, ctx, reference)?;
        if next == atom("none") {
            return Ok(next);
        }
        let (next_reference, batch) = tuple2(next).ok_or_else(badarg)?;
        if batch.classify() == TermKind::List {
            return step(process, next_reference, batch);
        }
        if batch != Term::NIL {
            return Err(badarg());
        }
        reference = next_reference;
    }
}

// Port of erts/emulator/beam/erl_bif_info.c:4011 (fun_info_mfa_1), OTP-29.1.1.
fn fun_info_mfa(vm: &Vm, process: &mut Process, fun: Term) -> Result<Term, VmError> {
    // SAFETY: The fun stays rooted in the caller heap for this BIF.
    let view = unsafe { fun.fun_ref() }.ok_or_else(badarg)?;
    let (module, name, arity) = match view {
        FunRef::Export { entry } => (
            Term::atom(entry.module),
            Term::atom(entry.function),
            i64::from(entry.arity),
        ),
        FunRef::Local { entry, .. } => {
            let module_name = global_atoms()
                .text(entry.module)
                .ok_or_else(badarg)?
                .to_string();
            let function = vm.code.loaded.get(&module_name).and_then(|&id| {
                vm.code.modules[id]
                    .funs
                    .iter()
                    .find(|slot| slot.entry.index == entry.index)
                    .map(|slot| (id, slot.target))
            });
            let name = function
                .and_then(|(id, target)| {
                    vm.code.modules[id]
                        .function_at(target)
                        .map(|(name, _)| name.to_owned())
                })
                .and_then(|name| global_atoms().intern(&name).ok())
                .map(Term::atom)
                .unwrap_or(Term::NIL);
            (Term::atom(entry.module), name, i64::from(entry.arity))
        }
    };
    let arity = Term::small(arity).ok_or_else(badarg)?;
    make_tuple(process, &[module, name, arity])
}

/// Text that `print_process_info` writes for the running process, as returned by the
/// `{process_dump}` trace match specification action.
// Port of erts/emulator/beam/break.c:236-420 (print_process_info) and
// erts/emulator/beam/erl_db_util.c:2756-2765 (matchProcessDump), OTP-29.1.1.
pub(crate) fn process_dump(
    vm: Option<&Vm>,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
) -> Result<Vec<u8>, VmError> {
    use arinsal_etf::OwnedTerm;
    use std::fmt::Write as _;
    let names = [
        "registered_name",
        "current_function",
        "message_queue_len",
        "links",
        "dictionary",
        "reductions",
        "priority",
    ];
    let items = names.iter().map(|name| atom(name)).collect::<Vec<_>>();
    let items = make_list(process, items)?;
    let info = process_info(vm, process, ctx, Some(items), atom("running"), false)?;
    let info = arinsal_term::to_owned(info).map_err(|_| badarg())?;
    let mut values = std::collections::HashMap::new();
    if let OwnedTerm::List { elems, .. } = &info {
        for pair in elems {
            if let OwnedTerm::Tuple(fields) = pair
                && let [OwnedTerm::Atom(key), value] = fields.as_slice()
            {
                values.insert(key.to_string(), value.clone());
            }
        }
    }
    let own = ctx
        .pid()
        .to_term()
        .and_then(|pid| arinsal_term::to_owned(pid).ok());
    let local_node = match &own {
        Some(OwnedTerm::Pid { node, .. }) => node.clone(),
        _ => String::new(),
    };
    // erts_printf `%T` writes local identifiers with node index 0.
    let print = |term: &OwnedTerm| match term {
        OwnedTerm::Pid {
            node, id, serial, ..
        } if *node == local_node => format!("<0.{id}.{serial}>"),
        _ => super::sys::print_otp_term(term, i32::MAX as usize),
    };
    let pid = own.as_ref().map(print).unwrap_or_default();
    let mfa = |term: Option<&OwnedTerm>| match term {
        Some(OwnedTerm::Tuple(fields)) if fields.len() == 3 => {
            format!(
                "{}:{}/{}",
                print(&fields[0]),
                print(&fields[1]),
                print(&fields[2])
            )
        }
        _ => String::new(),
    };
    let mut text = String::new();
    // The process dumps itself while it runs.
    let _ = writeln!(text, "=proc:{pid}");
    let _ = writeln!(text, "State: Running");
    if let Some(name @ OwnedTerm::Atom(_)) = values.get("registered_name") {
        let _ = writeln!(text, "Name: {}", print(name));
    }
    let _ = writeln!(text, "Spawned as: {}", mfa(values.get("current_function")));
    // `process_info(parent)` reports `undefined`, which erts prints as `[]`.
    let parent = "[]";
    let _ = writeln!(text, "Spawned by: {parent}");
    let queue = values
        .get("message_queue_len")
        .map(print)
        .unwrap_or_default();
    let _ = writeln!(text, "Message queue length: {queue}");
    let _ = writeln!(
        text,
        "Number of heap fragments: {}",
        process.heap.fragment_count()
    );
    let _ = writeln!(
        text,
        "Heap fragment data: {}",
        process.heap.fragment_words()
    );
    if let Some(OwnedTerm::List { elems, .. }) = values.get("links")
        && !elems.is_empty()
    {
        let links = elems.iter().map(print).collect::<Vec<_>>().join(", ");
        let _ = writeln!(text, "Link list: [{links}]");
    }
    if let Some(dictionary) = values.get("dictionary")
        && !matches!(dictionary, OwnedTerm::Nil)
    {
        let _ = writeln!(text, "Dictionary: {}", print(dictionary));
    }
    let reductions = values.get("reductions").map(print).unwrap_or_default();
    let _ = writeln!(text, "Reductions: {reductions}");
    let heap = process.heap.heap_size_words();
    let old_heap = process.heap.old_heap_words();
    let _ = writeln!(text, "Stack+heap: {heap}");
    let _ = writeln!(text, "OldHeap: {old_heap}");
    let _ = writeln!(text, "Heap unused: {}", process.heap.free_words());
    let _ = writeln!(
        text,
        "OldHeap unused: {}",
        old_heap.saturating_sub(process.heap.old_used_words())
    );
    let bin_vheap = process.heap.off_heap_binary_bytes() / 8;
    // Port of erts/emulator/beam/erl_process.c (default bin_vheap_sz), OTP-29.1.1.
    const BIN_VHEAP_SIZE: u64 = 46_422;
    let _ = writeln!(text, "BinVHeap: {bin_vheap}");
    let _ = writeln!(text, "OldBinVHeap: 0");
    let _ = writeln!(
        text,
        "BinVHeap unused: {}",
        BIN_VHEAP_SIZE.saturating_sub(bin_vheap)
    );
    let _ = writeln!(text, "OldBinVHeap unused: {BIN_VHEAP_SIZE}");
    let memory = std::mem::size_of::<Process>() + process.heap.total_heap_size_words() * 8;
    let _ = writeln!(text, "Memory: {memory}");
    let _ = writeln!(text, "Stack dump:");
    let _ = writeln!(
        text,
        "Program counter: {:#018x} ({})",
        process.ip,
        mfa(values.get("current_function"))
    );
    let _ = writeln!(text);
    let priority = match values.get("priority") {
        Some(OwnedTerm::Atom(priority)) => priority.to_uppercase(),
        _ => "NORMAL".into(),
    };
    let _ = writeln!(
        text,
        "Internal State: ACT_PRIO_{priority} | USR_PRIO_{priority} | PRQ_PRIO_{priority} | ACTIVE | RUNNING"
    );
    Ok(text.into_bytes())
}
