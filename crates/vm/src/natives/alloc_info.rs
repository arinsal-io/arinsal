//! The reply protocol used by `erlang:alloc_info/1` and `erlang:memory/0,1`.
//!
//! Port of erts/emulator/beam/erl_bif_info.c:2499 and
//! erts/emulator/beam/erl_alloc.c:3102, OTP-29.1.1. Rust allocator counters
//! are exposed through `allocated_areas`; per-allocator carrier statistics
//! are empty because Arinsal does not use erts_alloc.

use super::{MemorySources, Process, RunCtx, Vm, VmError, atom, badarg};
use crate::process::Message;
use arinsal_etf::OwnedTerm;
use arinsal_term::Term;

const ALLOCATORS: &[&str] = &[
    "temp_alloc",
    "sl_alloc",
    "std_alloc",
    "ll_alloc",
    "eheap_alloc",
    "ets_alloc",
    "fix_alloc",
    "literal_alloc",
    "binary_alloc",
    "driver_alloc",
    "alloc_util",
    "mseg_alloc",
    "erts_mmap",
];

/// Handle allocator and internal memory requests made by preloaded `erlang.erl`.
pub(super) fn system_info(
    vm: &Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    selector: Term,
) -> Option<Result<Term, VmError>> {
    let owned = arinsal_term::to_owned(selector).ok()?;
    let OwnedTerm::Tuple(parts) = &owned else {
        return None;
    };
    if let [OwnedTerm::Atom(operation), allocators] = parts.as_slice()
        && operation == "allocator_sizes"
    {
        // Port of erts/emulator/beam/erl_bif_info.c:2508-2513 (info_1_tuple), OTP-29.1.1:
        // the two-element form traps to `erlang:alloc_sizes/1`, which asks every scheduler.
        let argument = arinsal_term::from_owned(
            allocators,
            &mut arinsal_bifs::ProcessHeapHandle(&mut process.heap),
        )
        .map_err(|_| badarg());
        return Some(argument.and_then(|argument| {
            Err(VmError::TrapExport(crate::ExportTrap {
                continuation: "erlang:alloc_sizes/1",
                args: vec![argument],
            }))
        }));
    }
    if let [OwnedTerm::Atom(operation), OwnedTerm::Atom(allocator)] = parts.as_slice()
        && operation == "allocator"
        && allocator == "mseg_alloc"
    {
        // OTP returns `false` when this optional allocator is not present.
        // Arinsal does not use the erts mseg allocator. The call still interns
        // the mseg info atoms (erl_mseg.c:854) on builds where mseg exists.
        super::alloc_atoms::note_mseg();
        return Some(Ok(atom("false")));
    }
    if parts.len() != 3 {
        return None;
    }
    let OwnedTerm::Atom(operation) = &parts[0] else {
        return None;
    };
    let supported = match operation.as_str() {
        "memory_internal" | "allocator" | "allocator_sizes" => request_allocators(
            vm,
            process,
            ctx,
            &parts[1],
            &parts[2],
            operation == "memory_internal",
        ),
        _ => return None,
    };
    Some(supported)
}

fn request_allocators(
    vm: &Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    reference: &OwnedTerm,
    allocators: &OwnedTerm,
    memory_internal: bool,
) -> Result<Term, VmError> {
    let names = validate_request(reference, allocators)?;
    // Port of erl_alloc.c:3102 (reply_alloc_info) atom initialization. Done on
    // the caller before aux workers build replies, so the intern order matches
    // the aux-thread-then-requester order and does not race.
    super::alloc_atoms::note_memory_internal(&names);
    // `allocated_areas` runs after this reply is built and interns its labels then.
    // Intern them first so `atom_space` matches the bytes added to `std_alloc`.
    if memory_internal {
        super::alloc_atoms::note_allocated_areas();
    }
    let sources = MemorySources::gather(vm, process);
    let runtime = process.runtime.ok_or_else(badarg)?;
    let target = ctx.pid();
    let names = names
        .iter()
        .map(|name| (*name).to_owned())
        .collect::<Vec<_>>();
    let reference = reference.clone();
    ctx.request_aux_work_all(move |worker| {
        // Port of erts/emulator/beam/erl_alloc.c (reply_alloc_info), OTP-29.1.1: the counts
        // are read when this scheduler executes the request, not when it was issued.
        let timer_count = runtime
            .scheduler()
            .map_or(0, |scheduler| scheduler.bif_timer_count(worker))
            as u64;
        let data = allocator_data_owned(&names, &sources, worker, timer_count);
        let reply = OwnedTerm::Tuple(vec![
            reference.clone(),
            OwnedTerm::Int(worker as i64 + 1),
            data,
        ]);
        let Ok(message) = super::Message::from_owned(&reply) else {
            return;
        };
        if let Ok(scheduler) = runtime.scheduler() {
            let _ = scheduler.send(target, target, message);
        }
    });
    Ok(atom("true"))
}

fn validate_request<'a>(
    reference: &OwnedTerm,
    allocators: &'a OwnedTerm,
) -> Result<Vec<&'a str>, VmError> {
    if !matches!(reference, OwnedTerm::Ref { .. }) {
        return Err(badarg());
    }
    let OwnedTerm::List { elems, tail } = allocators else {
        return Err(badarg());
    };
    if **tail != OwnedTerm::Nil {
        return Err(badarg());
    }
    let mut names = Vec::with_capacity(elems.len());
    for item in elems {
        let OwnedTerm::Atom(name) = item else {
            return Err(badarg());
        };
        if !ALLOCATORS.contains(&name.as_str()) || names.contains(&name.as_str()) {
            return Err(badarg());
        }
        names.push(name.as_str());
    }
    Ok(names)
}

/// The reply of scheduler `worker` for the requested allocators: the instances that thread
/// reports, as `{Allocator, Instance, SizeInfo}`. The first scheduler also reports the global
/// instance 0 and the dirty instances, which no scheduler owns.
// Port of erts/emulator/beam/erl_alloc.c:3102 (reply_alloc_info with `air->only_sz`), OTP-29.1.1.
fn allocator_data_owned(
    names: &[String],
    sources: &MemorySources,
    worker: usize,
    timer_count: u64,
) -> OwnedTerm {
    let mut entries = Vec::new();
    for name in names {
        let Some(count) = arinsal_alloc::typed::instance_count(name) else {
            // alloc_util, mseg_alloc, erts_mmap: no alloc_util instances to report.
            if worker == 0 {
                entries.push(OwnedTerm::Tuple(vec![
                    OwnedTerm::Atom(name.clone()),
                    OwnedTerm::Int(0),
                    OwnedTerm::Nil,
                ]));
            }
            continue;
        };
        let schedulers = arinsal_alloc::typed::scheduler_instances(name).unwrap_or(0);
        let mut instances = Vec::new();
        if worker == 0 {
            instances.push(0);
        }
        if worker < schedulers {
            instances.push(worker + 1);
        }
        if worker == 0 {
            instances.extend(schedulers + 1..count);
        }
        instances.sort_unstable();
        for instance in instances {
            let external = if instance == 0 {
                sources.blocks_in(name)
            } else {
                0
            };
            entries.push(OwnedTerm::Tuple(vec![
                OwnedTerm::Atom(name.clone()),
                OwnedTerm::Int(instance as i64),
                instance_sizes_owned(name, instance, external, timer_count),
            ]));
        }
    }
    owned_list(entries)
}

/// `erts_alcu_sz_info` of one instance: fixed-size types, then the `mbcs`, `mbcs_pool` and
/// `sbcs` carrier classes with their block and carrier sizes.
// Port of erts/emulator/beam/erl_alloc_util.c:5765 (erts_alcu_sz_info), :4897 (sz_info_fix) and
// :4969 (sz_info_carriers), OTP-29.1.1. `external` are the bytes Arinsal keeps outside this
// allocator that erts allocates from it.
fn instance_sizes_owned(
    allocator: &str,
    instance: usize,
    external: u64,
    timer_count: u64,
) -> OwnedTerm {
    use arinsal_alloc::alloc_util::AllocatorClassInfo;
    let Some(info) = arinsal_alloc::typed::allocator_info(allocator, instance) else {
        return OwnedTerm::Nil;
    };
    let class = |name: &str, class: &AllocatorClassInfo, external: u64| {
        let size = |current: usize, max: usize, max_ever: usize| {
            owned_tuple(vec![
                OwnedTerm::Atom("size".into()),
                OwnedTerm::Int(current as i64 + external as i64),
                OwnedTerm::Int(max as i64 + external as i64),
                OwnedTerm::Int(max_ever as i64 + external as i64),
            ])
        };
        let blocks = if class.blocks_size == 0
            && class.blocks_size_max == 0
            && class.blocks_size_max_ever == 0
            && external == 0
        {
            owned_list(Vec::new())
        } else {
            owned_list(vec![owned_tuple(vec![
                OwnedTerm::Atom(allocator.into()),
                owned_list(vec![size(
                    class.blocks_size,
                    class.blocks_size_max,
                    class.blocks_size_max_ever,
                )]),
            ])])
        };
        let carriers = owned_tuple(vec![
            OwnedTerm::Atom("carriers_size".into()),
            OwnedTerm::Int(class.carriers_size as i64),
            OwnedTerm::Int(class.carriers_size_max as i64),
            OwnedTerm::Int(class.carriers_size_max_ever as i64),
        ]);
        owned_tuple(vec![
            OwnedTerm::Atom(name.into()),
            owned_list(vec![
                owned_tuple(vec![OwnedTerm::Atom("blocks".into()), blocks]),
                carriers,
            ]),
        ])
    };
    let mut sections = Vec::new();
    if allocator == "fix_alloc" {
        sections.push(fix_types_owned(instance, timer_count));
    }
    sections.push(class("mbcs", &info.mbcs, external));
    if let Some(pool) = info.mbcs_pool {
        sections.push(owned_tuple(vec![
            OwnedTerm::Atom("mbcs_pool".into()),
            owned_list(vec![
                owned_tuple(vec![
                    OwnedTerm::Atom("blocks".into()),
                    owned_list(Vec::new()),
                ]),
                owned_tuple(vec![
                    OwnedTerm::Atom("carriers_size".into()),
                    OwnedTerm::Int(pool.carriers_size as i64),
                ]),
            ]),
        ]));
    }
    sections.push(class("sbcs", &info.sbcs, 0));
    owned_list(sections)
}

/// The `fix_types` entry for process blocks, message references, and the BIF timer.
// Port of erts/emulator/beam/erl_alloc_util.c:4897 (`sz_info_fix`) and erl_alloc.c:2464
// (`add_fix_values` for MSG_REF), OTP-29.1.1.
fn fix_types_owned(instance: usize, timer_count: u64) -> OwnedTerm {
    let type_name = if timer_count == 0 {
        "accessor_bif_timer"
    } else {
        "bif_timer"
    };
    let size = OwnedTerm::Int(timer_count.min(i64::MAX as u64) as i64);
    let (allocated, used) =
        arinsal_alloc::typed::fix_bytes(arinsal_alloc::typed::ErtsAlcType::PROC, instance)
            .unwrap_or((0, 0));
    let (msg_ref_allocated, msg_ref_used) =
        arinsal_alloc::typed::fix_bytes(arinsal_alloc::typed::ErtsAlcType::MSG_REF, instance)
            .unwrap_or((0, 0));
    let types = owned_list(vec![
        owned_tuple(vec![
            OwnedTerm::Atom("proc".into()),
            OwnedTerm::Int(allocated as i64),
            OwnedTerm::Int(used as i64),
        ]),
        owned_tuple(vec![
            OwnedTerm::Atom("msg_ref".into()),
            OwnedTerm::Int(msg_ref_allocated as i64),
            OwnedTerm::Int(msg_ref_used as i64),
        ]),
        owned_tuple(vec![OwnedTerm::Atom(type_name.into()), size.clone(), size]),
    ]);
    owned_tuple(vec![OwnedTerm::Atom("fix_types".into()), types])
}

fn owned_tuple(fields: Vec<OwnedTerm>) -> OwnedTerm {
    OwnedTerm::Tuple(fields)
}

fn owned_list(elements: Vec<OwnedTerm>) -> OwnedTerm {
    OwnedTerm::List {
        elems: elements,
        tail: Box::new(OwnedTerm::Nil),
    }
}
