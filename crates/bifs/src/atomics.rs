//! Shared atomic arrays used by `atomics` and `counters`.
//!
//! The registry intentionally retains every array.  OTP releases its magic
//! binary when the last reference is collected; that needs stage-4 resource
//! support and is not available yet.

use std::cell::Cell;
use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex};

use arinsal_maps::from_list;
use arinsal_term::{Identity, Term, TermBuilder, atoms, global_atoms};
use num_bigint::BigInt;
use num_traits::ToPrimitive;

use crate::pure::{Heap, bigint, integer};
use crate::{BifError, BifFn, Ctx};

const BADARG: BifError = BifError::BADARG;
const SIGNED_OPTION: u64 = 1;
const COUNTER_SHARDS: usize = 16;
const REF_KIND: u32 = 0xA710;
static NEXT_ID: AtomicU32 = AtomicU32::new(1);
static ARRAYS: LazyLock<Mutex<HashMap<u32, Arc<Array>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static NEXT_SLOT: AtomicU32 = AtomicU32::new(0);

enum Cells {
    Signed(Vec<AtomicI64>),
    Unsigned(Vec<AtomicU64>),
    Sharded(Vec<Vec<AtomicI64>>),
}

struct Array {
    cells: Cells,
    signed: bool,
}

pub(super) fn lookup(module: &str, name: &str, arity: u8) -> Option<BifFn> {
    let function = match (module, name, arity) {
        ("erts_internal", "atomics_new", 2) => atomics_new,
        ("atomics", "get", 2) => atomics_get,
        ("atomics", "put", 3) => atomics_put,
        ("atomics", "add", 3) => atomics_add,
        ("atomics", "add_get", 3) => atomics_add_get,
        ("atomics", "exchange", 3) => atomics_exchange,
        ("atomics", "compare_exchange", 4) => atomics_compare_exchange,
        ("atomics", "info", 1) => atomics_info,
        ("erts_internal", "counters_new", 1) => counters_new,
        ("erts_internal", "counters_get", 2) => counters_get,
        ("erts_internal", "counters_add", 3) => counters_add,
        ("erts_internal", "counters_put", 3) => counters_put,
        ("erts_internal", "counters_info", 1) => counters_info,
        _ => return None,
    };
    arinsal_spec::bif_lookup(module, name, arity).map(|_| function)
}

fn new_ref(ctx: &mut Ctx<'_>, array: Array) -> Result<Term, BifError> {
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    if id == 0 {
        return Err(BifError::SystemLimit);
    }
    ARRAYS
        .lock()
        .expect("atomics registry poisoned")
        .insert(id, Arc::new(array));
    TermBuilder::new(&mut Heap(ctx.heap))
        .local_ref([REF_KIND, id, 0])
        .map_err(|_| BifError::SystemLimit)
}

fn resolve(term: Term) -> Result<(u32, Arc<Array>), BifError> {
    match term.identity() {
        Some(Identity::Ref { ids, .. }) if ids.len() == 3 && ids[0] == REF_KIND && ids[2] == 0 => {
            let id = ids[1];
            ARRAYS
                .lock()
                .expect("atomics registry poisoned")
                .get(&id)
                .cloned()
                .map(|array| (id, array))
                .ok_or(BADARG)
        }
        _ => Err(BADARG),
    }
}

fn integer_usize(term: Term) -> Result<usize, BifError> {
    bigint(term)?.to_usize().ok_or(BADARG)
}

fn array_size(term: Term) -> Result<usize, BifError> {
    let value = bigint(term)?;
    if value.sign() == num_bigint::Sign::Minus {
        return Err(BADARG);
    }
    value.to_usize().ok_or(BifError::SystemLimit)
}

fn index(array: &Array, term: Term) -> Result<usize, BifError> {
    let value = integer_usize(term)?;
    if value == 0 || value > len(array) {
        return Err(BADARG);
    }
    Ok(value - 1)
}

fn len(array: &Array) -> usize {
    match &array.cells {
        Cells::Signed(cells) => cells.len(),
        Cells::Unsigned(cells) => cells.len(),
        Cells::Sharded(cells) => cells.len(),
    }
}

fn signed_value(term: Term) -> Result<i64, BifError> {
    bigint(term)?.to_i64().ok_or(BADARG)
}

fn unsigned_value(term: Term) -> Result<u64, BifError> {
    bigint(term)?.to_u64().ok_or(BADARG)
}

fn signed_cells(count: usize) -> Result<Vec<AtomicI64>, BifError> {
    let mut cells = Vec::new();
    cells
        .try_reserve_exact(count)
        .map_err(|_| BifError::SystemLimit)?;
    cells.extend((0..count).map(|_| AtomicI64::new(0)));
    Ok(cells)
}

fn unsigned_cells(count: usize) -> Result<Vec<AtomicU64>, BifError> {
    let mut cells = Vec::new();
    cells
        .try_reserve_exact(count)
        .map_err(|_| BifError::SystemLimit)?;
    cells.extend((0..count).map(|_| AtomicU64::new(0)));
    Ok(cells)
}

fn arithmetic_value(term: Term) -> Result<i64, BifError> {
    let value = bigint(term)?;
    if let Some(value) = value.to_i64() {
        return Ok(value);
    }
    value.to_u64().map(|value| value as i64).ok_or(BADARG)
}

fn output(ctx: &mut Ctx<'_>, array: &Array, value: i64) -> Result<Term, BifError> {
    let value = if array.signed {
        BigInt::from(value)
    } else {
        BigInt::from(value as u64)
    };
    TermBuilder::new(&mut Heap(ctx.heap))
        .int_from_bigint(&value)
        .map_err(|_| BifError::SystemLimit)
}

fn atomics_new(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let count = array_size(args[0])?;
    if count == 0 {
        return Err(BADARG);
    }
    let opts = bigint(args[1])?.to_u64().ok_or(BADARG)?;
    let signed = opts & SIGNED_OPTION != 0;
    let cells = if signed {
        Cells::Signed(signed_cells(count)?)
    } else {
        Cells::Unsigned(unsigned_cells(count)?)
    };
    new_ref(ctx, Array { cells, signed })
}

fn atomics_get(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let (_, array) = resolve(args[0])?;
    let i = index(&array, args[1])?;
    let value = match &array.cells {
        Cells::Signed(cells) => cells[i].load(Ordering::SeqCst),
        Cells::Unsigned(cells) => cells[i].load(Ordering::SeqCst) as i64,
        Cells::Sharded(_) => return Err(BADARG),
    };
    output(ctx, &array, value)
}

fn atomics_put(_: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let (_, array) = resolve(args[0])?;
    let i = index(&array, args[1])?;
    match &array.cells {
        Cells::Signed(cells) => cells[i].store(signed_value(args[2])?, Ordering::SeqCst),
        Cells::Unsigned(cells) => cells[i].store(unsigned_value(args[2])?, Ordering::SeqCst),
        Cells::Sharded(_) => return Err(BADARG),
    }
    Ok(Term::atom(atoms::OK))
}

fn atomics_add_common(
    ctx: &mut Ctx<'_>,
    args: &[Term],
    return_value: bool,
    subtract: bool,
) -> Result<Term, BifError> {
    let (_, array) = resolve(args[0])?;
    let i = index(&array, args[1])?;
    let mut increment = arithmetic_value(args[2])?;
    if subtract {
        increment = increment.wrapping_neg();
    }
    let value = match &array.cells {
        Cells::Signed(cells) => cells[i]
            .fetch_add(increment, Ordering::SeqCst)
            .wrapping_add(increment),
        Cells::Unsigned(cells) => cells[i]
            .fetch_add(increment as u64, Ordering::SeqCst)
            .wrapping_add(increment as u64) as i64,
        Cells::Sharded(_) => return Err(BADARG),
    };
    if return_value {
        output(ctx, &array, value)
    } else {
        Ok(Term::atom(atoms::OK))
    }
}

fn atomics_add(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    atomics_add_common(ctx, args, false, false)
}
fn atomics_add_get(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    atomics_add_common(ctx, args, true, false)
}

fn atomics_exchange(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let (_, array) = resolve(args[0])?;
    let i = index(&array, args[1])?;
    let was = match &array.cells {
        Cells::Signed(cells) => cells[i].swap(signed_value(args[2])?, Ordering::SeqCst),
        Cells::Unsigned(cells) => cells[i].swap(unsigned_value(args[2])?, Ordering::SeqCst) as i64,
        Cells::Sharded(_) => return Err(BADARG),
    };
    output(ctx, &array, was)
}

fn atomics_compare_exchange(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let (_, array) = resolve(args[0])?;
    let i = index(&array, args[1])?;
    match &array.cells {
        Cells::Signed(cells) => match cells[i].compare_exchange(
            signed_value(args[2])?,
            signed_value(args[3])?,
            Ordering::SeqCst,
            Ordering::SeqCst,
        ) {
            Ok(_) => Ok(Term::atom(atoms::OK)),
            Err(was) => output(ctx, &array, was),
        },
        Cells::Unsigned(cells) => match cells[i].compare_exchange(
            unsigned_value(args[2])?,
            unsigned_value(args[3])?,
            Ordering::SeqCst,
            Ordering::SeqCst,
        ) {
            Ok(_) => Ok(Term::atom(atoms::OK)),
            Err(was) => output(ctx, &array, was as i64),
        },
        Cells::Sharded(_) => Err(BADARG),
    }
}

fn atomics_info(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let (_, array) = resolve(args[0])?;
    let maximum = if array.signed {
        i64::MAX as u64
    } else {
        u64::MAX
    };
    let minimum = if array.signed { i64::MIN } else { 0 };
    let pairs = [
        (
            Term::atom(global_atoms().intern("size").expect("OTP atom")),
            integer(ctx, len(&array))?,
        ),
        (
            Term::atom(global_atoms().intern("max").expect("OTP atom")),
            int_term(ctx, BigInt::from(maximum))?,
        ),
        (
            Term::atom(global_atoms().intern("min").expect("OTP atom")),
            int_term(ctx, BigInt::from(minimum))?,
        ),
        (
            Term::atom(global_atoms().intern("memory").expect("OTP atom")),
            integer(ctx, len(&array) * 8 + 32)?,
        ),
    ];
    from_list(&pairs, ctx.heap).map_err(|_| BifError::SystemLimit)
}

fn int_term(ctx: &mut Ctx<'_>, value: BigInt) -> Result<Term, BifError> {
    TermBuilder::new(&mut Heap(ctx.heap))
        .int_from_bigint(&value)
        .map_err(|_| BifError::SystemLimit)
}

thread_local! { static THREAD_SLOT: Cell<usize> = Cell::new(NEXT_SLOT.fetch_add(1, Ordering::Relaxed) as usize % COUNTER_SHARDS); }

fn counters_new(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let count = array_size(args[0])?;
    if count == 0 {
        return Err(BADARG);
    }
    let total_cells = count
        .checked_mul(COUNTER_SHARDS)
        .ok_or(BifError::SystemLimit)?;
    if total_cells > usize::MAX / std::mem::size_of::<AtomicI64>() {
        return Err(BifError::SystemLimit);
    }
    let mut cells = Vec::new();
    cells
        .try_reserve_exact(count)
        .map_err(|_| BifError::SystemLimit)?;
    for _ in 0..count {
        cells.push(signed_cells(COUNTER_SHARDS)?);
    }
    new_ref(
        ctx,
        Array {
            cells: Cells::Sharded(cells),
            signed: true,
        },
    )
}

fn counters_get(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let (_, array) = resolve(args[0])?;
    let i = index(&array, args[1])?;
    let Cells::Sharded(cells) = &array.cells else {
        return Err(BADARG);
    };
    let sum = cells[i].iter().fold(0_i64, |sum, cell| {
        sum.wrapping_add(cell.load(Ordering::Relaxed))
    });
    output(ctx, &array, sum)
}

fn counters_add(_: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let (_, array) = resolve(args[0])?;
    let i = index(&array, args[1])?;
    let value = arithmetic_value(args[2])?;
    let Cells::Sharded(cells) = &array.cells else {
        return Err(BADARG);
    };
    THREAD_SLOT.with(|slot| {
        cells[i][slot.get()].fetch_add(value, Ordering::Relaxed);
    });
    Ok(Term::atom(atoms::OK))
}

fn counters_put(_: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let (_, array) = resolve(args[0])?;
    let i = index(&array, args[1])?;
    let value = signed_value(args[2])?;
    let Cells::Sharded(cells) = &array.cells else {
        return Err(BADARG);
    };
    let total_others = cells[i].iter().skip(1).fold(0_i64, |sum, cell| {
        sum.wrapping_add(cell.load(Ordering::Relaxed))
    });
    cells[i][0].store(value.wrapping_sub(total_others), Ordering::Relaxed);
    Ok(Term::atom(atoms::OK))
}

fn counters_info(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let (_, array) = resolve(args[0])?;
    let Cells::Sharded(cells) = &array.cells else {
        return Err(BADARG);
    };
    let size = integer(ctx, cells.len())?;
    let memory = integer(ctx, cells.len() * COUNTER_SHARDS * 8 + 64)?;
    from_list(
        &[
            (Term::atom(global_atoms().intern("size").unwrap()), size),
            (Term::atom(global_atoms().intern("memory").unwrap()), memory),
        ],
        ctx.heap,
    )
    .map_err(|_| BifError::SystemLimit)
}
