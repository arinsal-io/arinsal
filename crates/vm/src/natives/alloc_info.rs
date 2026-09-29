//! The reply protocol used by `erlang:alloc_info/1` and `erlang:memory/0,1`.
//!
//! Port of erts/emulator/beam/erl_bif_info.c:2499 and
//! erts/emulator/beam/erl_alloc.c:3102, OTP-29.1.1. Rust allocator counters
//! are exposed through `allocated_areas`; per-allocator carrier statistics
//! are empty because Arinsal does not use erts_alloc.

use super::{
    Process, RunCtx, Vm, VmError, atom, badarg, cons_list, memory_values, snapshot_process, tuple,
};
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
        "memory_internal" | "allocator" | "allocator_sizes" => {
            request_allocators(vm, process, ctx, &parts[1], &parts[2])
        }
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
) -> Result<Term, VmError> {
    let names = validate_request(reference, allocators)?;
    snapshot_process(process, process.gc_live);
    let values = memory_values(vm, process);
    let reference = ref_term(process, reference)?;
    send_replies(process, ctx, reference, &names, values)?;
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

fn ref_term(process: &mut Process, reference: &OwnedTerm) -> Result<Term, VmError> {
    arinsal_term::from_owned(
        reference,
        &mut arinsal_bifs::FragmentingHeap(&mut process.heap),
    )
    .map_err(|_| badarg())
}

fn send_replies(
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    reference: Term,
    names: &[&str],
    values: [(&'static str, u64); 9],
) -> Result<(), VmError> {
    let target = ctx.pid();
    let schedulers = std::thread::available_parallelism().map_or(1, usize::from);
    for scheduler in 1..=schedulers {
        let index = Term::small(scheduler as i64).ok_or_else(badarg)?;
        let data = allocator_data(process, names, values, scheduler == 1)?;
        let reply = tuple(process, &[reference, index, data])?;
        ctx.send(target, Message::copy_from(reply)?)
            .map_err(|_| badarg())?;
    }
    Ok(())
}

fn allocator_data(
    process: &mut Process,
    names: &[&str],
    values: [(&'static str, u64); 9],
    include_sizes: bool,
) -> Result<Term, VmError> {
    let value = |key: &str| {
        values
            .iter()
            .find(|(name, _)| *name == key)
            .map(|(_, value)| *value)
            .unwrap_or(0)
    };
    let mut entries = Vec::with_capacity(names.len());
    for name in names {
        let mut info = Term::NIL;
        if include_sizes {
            let (allocator, size) = match *name {
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
                info = allocator_pool(process, allocator, size)?;
            }
        }
        entries.push(tuple(
            process,
            &[atom(name), Term::small(0).ok_or_else(badarg)?, info],
        )?);
    }
    cons_list(process, &entries)
}

fn allocator_pool(process: &mut Process, allocator: &str, size: u64) -> Result<Term, VmError> {
    let size = super::non_neg(process, size)?;
    let size_entry = tuple(process, &[atom("size"), size])?;
    let sizes = cons_list(process, &[size_entry])?;
    let allocation = tuple(process, &[atom(allocator), sizes])?;
    let allocations = cons_list(process, &[allocation])?;
    let blocks = tuple(process, &[atom("blocks"), allocations])?;
    let stats = cons_list(process, &[blocks])?;
    let pool = tuple(process, &[atom("mbcs"), stats])?;
    cons_list(process, &[pool])
}
