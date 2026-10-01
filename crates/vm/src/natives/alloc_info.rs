//! The reply protocol used by `erlang:alloc_info/1` and `erlang:memory/0,1`.
//!
//! Port of erts/emulator/beam/erl_bif_info.c:2499 and
//! erts/emulator/beam/erl_alloc.c:3102, OTP-29.1.1. Rust allocator counters
//! are exposed through `allocated_areas`; per-allocator carrier statistics
//! are empty because Arinsal does not use erts_alloc.

use super::{Process, RunCtx, Vm, VmError, atom, badarg, memory_values, snapshot_process};
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
    snapshot_process(process, process.gc_live);
    let values = memory_values(vm, process);
    let runtime = process.runtime.as_ref().ok_or_else(badarg)?.clone();
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
            .timers
            .lock()
            .unwrap()
            .values()
            .filter(|timer| timer.worker_id().saturating_sub(1) == worker)
            .count() as u64;
        let data =
            allocator_data_owned(&names, values, !memory_internal || worker == 0, timer_count);
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

fn allocator_data_owned(
    names: &[String],
    values: [(&'static str, u64); 9],
    include_sizes: bool,
    timer_count: u64,
) -> OwnedTerm {
    let value = |key: &str| {
        values
            .iter()
            .find(|(name, _)| *name == key)
            .map(|(_, value)| *value)
            .unwrap_or(0)
    };
    let mut entries = Vec::with_capacity(names.len());
    for name in names {
        let mut info = if name == "fix_alloc" {
            fix_allocator_info_owned(timer_count)
        } else {
            OwnedTerm::Nil
        };
        if include_sizes && name != "fix_alloc" {
            let (allocator, size) = match name.as_str() {
                // These categories are attributed separately by allocated_areas.
                "std_alloc" => (
                    "std_alloc",
                    value("processes")
                        .saturating_add(value("atom"))
                        .saturating_add(value("ets"))
                        .saturating_add(value("code")),
                ),
                "binary_alloc" => ("binary_alloc", value("binary")),
                _ => ("", 0),
            };
            if size != 0 {
                info = allocator_pool_owned(allocator, size);
            }
        }
        entries.push(OwnedTerm::Tuple(vec![
            OwnedTerm::Atom(name.clone()),
            OwnedTerm::Int(0),
            info,
        ]));
    }
    owned_list(entries)
}

fn allocator_pool_owned(allocator: &str, size: u64) -> OwnedTerm {
    let size_entry = owned_tuple(vec![
        OwnedTerm::Atom("size".into()),
        OwnedTerm::Int(size as i64),
    ]);
    let sizes = owned_list(vec![size_entry]);
    let allocation = owned_tuple(vec![OwnedTerm::Atom(allocator.into()), sizes]);
    let allocations = owned_list(vec![allocation]);
    let blocks = owned_tuple(vec![OwnedTerm::Atom("blocks".into()), allocations]);
    let stats = owned_list(vec![blocks]);
    let pool = owned_tuple(vec![OwnedTerm::Atom("mbcs".into()), stats]);
    owned_list(vec![pool])
}

/// Port of the `fix_types` allocator info consumed by `erlang:memory/0`, OTP-29.1.1.
fn fix_allocator_info_owned(timer_count: u64) -> OwnedTerm {
    let type_name = if timer_count == 0 {
        "accessor_bif_timer"
    } else {
        "bif_timer"
    };
    let size = OwnedTerm::Int(timer_count.min(i64::MAX as u64) as i64);
    let type_entry = owned_tuple(vec![OwnedTerm::Atom(type_name.into()), size.clone(), size]);
    let types = owned_list(vec![type_entry]);
    let info = owned_tuple(vec![OwnedTerm::Atom("fix_types".into()), types]);
    owned_list(vec![info])
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
