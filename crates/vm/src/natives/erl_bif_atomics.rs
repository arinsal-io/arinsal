//! Atomics and write-concurrency counters of erl_bif_atomics.c and erl_bif_counters.c.
//!
//! The arrays live in the payload of their magic-reference binary, and each BIF is a
//! `bif_table[].f` body called with `(c_p, reg, I)`.

use super::bif::{badarg, bif_ret};
use crate::natives::sys::schedulers_total;
use crate::{Process, VmError};
use arinsal_beamasm::ProcessHeader;
use arinsal_bifs::ProcessHeapHandle;
use arinsal_term::{MAGIC_BIN_DATA_OFFSET, MagicBin, Term, TermBuilder, atoms, global_atoms};
use num_bigint::{BigInt, Sign};
use num_traits::ToPrimitive;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};

const ERTS_ATOMIC64_SIZE: usize = 8;
const ERTS_CACHE_LINE_SIZE: usize = 64;
const ATOMICS_PER_CACHE_LINE: usize = ERTS_CACHE_LINE_SIZE / ERTS_ATOMIC64_SIZE;
const OPT_SIGNED: u64 = 1;

enum AtomicCells {
    Signed(Vec<AtomicI64>),
    Unsigned(Vec<AtomicU64>),
}

/// `AtomicsRef { int is_signed; UWord vlen; erts_atomic64_t v[]; }`.
// Port of erts/emulator/beam/erl_bif_atomics.c (AtomicsRef), OTP-29.1.1.
struct AtomicsArray {
    cells: AtomicCells,
    signed: bool,
    len: usize,
    memory: usize,
    #[cfg(test)]
    dropped: Option<std::sync::Arc<std::sync::atomic::AtomicUsize>>,
}

#[cfg(test)]
impl Drop for AtomicsArray {
    fn drop(&mut self) {
        if let Some(dropped) = &self.dropped {
            dropped.fetch_add(1, Ordering::SeqCst);
        }
    }
}

/// One 64-byte `CountersRef.u[i]` cache line.
// Port of erts/emulator/beam/erl_bif_counters.c (CountersRef), OTP-29.1.1.
#[repr(C, align(64))]
struct CounterCacheLine {
    values: [AtomicI64; ATOMICS_PER_CACHE_LINE],
}

/// `CountersRef { UWord arity; union { erts_atomic64_t v[8]; byte cache_line[64]; } u[]; }`.
// Port of erts/emulator/beam/erl_bif_counters.c (CountersRef), OTP-29.1.1.
struct CountersArray {
    lines: Vec<CounterCacheLine>,
    len: usize,
    slots: usize,
    memory: usize,
}

fn system_limit() -> VmError {
    VmError::Trap(crate::exceptions::Trap::error(Term::atom(
        atoms::SYSTEM_LIMIT,
    )))
}

fn integer(term: Term) -> Option<BigInt> {
    term.as_small()
        .map(BigInt::from)
        .or_else(|| arinsal_term::raw::big_value(term))
}

fn unsigned_word(term: Term) -> Option<usize> {
    integer(term)?.to_usize()
}

fn array_size(term: Term) -> Result<usize, VmError> {
    let value = integer(term).ok_or_else(badarg)?;
    if value.sign() == Sign::Minus {
        return Err(badarg());
    }
    value.to_usize().ok_or_else(system_limit)
}

fn signed_value(term: Term) -> Option<i64> {
    integer(term)?.to_i64()
}

fn unsigned_value(term: Term) -> Option<u64> {
    integer(term)?.to_u64()
}

/// `term_to_Sint64(term) || term_to_Uint64(term)`, retaining the 64-bit pattern.
// Port of erts/emulator/beam/erl_bif_atomics.c (get_incr) and erl_bif_counters.c (get_incr),
// OTP-29.1.1.
fn arithmetic_value(term: Term) -> Option<i64> {
    integer(term)?
        .to_i64()
        .or_else(|| integer(term)?.to_u64().map(|v| v as i64))
}

fn new_magic_ref<T: arinsal_term::MagicPayload>(
    process: &mut Process,
    payload: T,
    payload_size: usize,
) -> Result<Term, VmError> {
    let owner = MagicBin::with_erts_payload_size_and_refn(
        payload,
        payload_size,
        arinsal_bifs::next_ref_words(),
    );
    let mut heap = ProcessHeapHandle(&mut process.heap);
    TermBuilder::new(&mut heap)
        .magic_ref(owner)
        .map_err(|_| system_limit())
}

// Port of erts/emulator/beam/erl_bif_atomics.c (erts_internal_atomics_new_2), OTP-29.1.1.
fn atomics_new(process: &mut Process, x: &[Term]) -> Result<Term, VmError> {
    let count = array_size(x[0])?;
    if count == 0 {
        return Err(badarg());
    }
    let opts = unsigned_value(x[1]).ok_or_else(badarg)?;
    let signed = opts & OPT_SIGNED != 0;
    let payload_size = 16_usize
        .checked_add(
            count
                .checked_mul(ERTS_ATOMIC64_SIZE)
                .ok_or_else(system_limit)?,
        )
        .ok_or_else(system_limit)?;
    let cells = if signed {
        let mut cells = Vec::new();
        cells.try_reserve_exact(count).map_err(|_| system_limit())?;
        cells.extend((0..count).map(|_| AtomicI64::new(0)));
        AtomicCells::Signed(cells)
    } else {
        let mut cells = Vec::new();
        cells.try_reserve_exact(count).map_err(|_| system_limit())?;
        cells.extend((0..count).map(|_| AtomicU64::new(0)));
        AtomicCells::Unsigned(cells)
    };
    let array = AtomicsArray {
        cells,
        signed,
        len: count,
        memory: MAGIC_BIN_DATA_OFFSET + payload_size,
        #[cfg(test)]
        dropped: None,
    };
    new_magic_ref(process, array, payload_size)
}

// Port of erts/emulator/beam/erl_bif_atomics.c (atomics_get_2), OTP-29.1.1.
fn atomics_get(process: &mut Process, x: &[Term]) -> Result<Term, VmError> {
    let (reference, index_term) = (x[0], x[1]);
    reference
        .with_magic_payload::<AtomicsArray, _>(|array| {
            let index = unsigned_word(index_term)
                .filter(|&index| index != 0 && index <= array.len)
                .ok_or_else(badarg)?
                - 1;
            let value = match &array.cells {
                AtomicCells::Signed(cells) => cells[index].load(Ordering::SeqCst),
                AtomicCells::Unsigned(cells) => cells[index].load(Ordering::SeqCst) as i64,
            };
            atomic_term(process, array.signed, value)
        })
        .ok_or_else(badarg)?
}

// Port of erts/emulator/beam/erl_bif_atomics.c (atomics_put_3), OTP-29.1.1.
fn atomics_put(_process: &mut Process, x: &[Term]) -> Result<Term, VmError> {
    let (reference, index_term, value_term) = (x[0], x[1], x[2]);
    reference
        .with_magic_payload::<AtomicsArray, _>(|array| {
            let index = unsigned_word(index_term)
                .filter(|&index| index != 0 && index <= array.len)
                .ok_or_else(badarg)?
                - 1;
            match &array.cells {
                AtomicCells::Signed(cells) => cells[index].store(
                    signed_value(value_term).ok_or_else(badarg)?,
                    Ordering::SeqCst,
                ),
                AtomicCells::Unsigned(cells) => cells[index].store(
                    unsigned_value(value_term).ok_or_else(badarg)?,
                    Ordering::SeqCst,
                ),
            }
            Ok(Term::atom(atoms::OK))
        })
        .ok_or_else(badarg)?
}

// Port of erts/emulator/beam/erl_bif_atomics.c (atomics_add_3, atomics_add_get_3), OTP-29.1.1.
fn atomics_add(process: &mut Process, x: &[Term], return_value: bool) -> Result<Term, VmError> {
    let (reference, index_term, increment_term) = (x[0], x[1], x[2]);
    reference
        .with_magic_payload::<AtomicsArray, _>(|array| {
            let index = unsigned_word(index_term)
                .filter(|&index| index != 0 && index <= array.len)
                .ok_or_else(badarg)?
                - 1;
            let increment = arithmetic_value(increment_term).ok_or_else(badarg)?;
            let value = match &array.cells {
                AtomicCells::Signed(cells) => cells[index]
                    .fetch_add(increment, Ordering::SeqCst)
                    .wrapping_add(increment),
                AtomicCells::Unsigned(cells) => cells[index]
                    .fetch_add(increment as u64, Ordering::SeqCst)
                    .wrapping_add(increment as u64)
                    as i64,
            };
            if return_value {
                atomic_term(process, array.signed, value)
            } else {
                Ok(Term::atom(atoms::OK))
            }
        })
        .ok_or_else(badarg)?
}

// Port of erts/emulator/beam/erl_bif_atomics.c (atomics_exchange_3), OTP-29.1.1.
fn atomics_exchange(process: &mut Process, x: &[Term]) -> Result<Term, VmError> {
    let (reference, index_term, value_term) = (x[0], x[1], x[2]);
    reference
        .with_magic_payload::<AtomicsArray, _>(|array| {
            let index = unsigned_word(index_term)
                .filter(|&index| index != 0 && index <= array.len)
                .ok_or_else(badarg)?
                - 1;
            let was = match &array.cells {
                AtomicCells::Signed(cells) => cells[index].swap(
                    signed_value(value_term).ok_or_else(badarg)?,
                    Ordering::SeqCst,
                ),
                AtomicCells::Unsigned(cells) => cells[index].swap(
                    unsigned_value(value_term).ok_or_else(badarg)?,
                    Ordering::SeqCst,
                ) as i64,
            };
            atomic_term(process, array.signed, was)
        })
        .ok_or_else(badarg)?
}

// Port of erts/emulator/beam/erl_bif_atomics.c (atomics_compare_exchange_4), OTP-29.1.1.
fn atomics_compare_exchange(process: &mut Process, x: &[Term]) -> Result<Term, VmError> {
    let (reference, index_term, expected_term, desired_term) = (x[0], x[1], x[2], x[3]);
    reference
        .with_magic_payload::<AtomicsArray, _>(|array| {
            let index = unsigned_word(index_term)
                .filter(|&index| index != 0 && index <= array.len)
                .ok_or_else(badarg)?
                - 1;
            match &array.cells {
                AtomicCells::Signed(cells) => match cells[index].compare_exchange(
                    signed_value(expected_term).ok_or_else(badarg)?,
                    signed_value(desired_term).ok_or_else(badarg)?,
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                ) {
                    Ok(_) => Ok(Term::atom(atoms::OK)),
                    Err(was) => atomic_term(process, array.signed, was),
                },
                AtomicCells::Unsigned(cells) => match cells[index].compare_exchange(
                    unsigned_value(expected_term).ok_or_else(badarg)?,
                    unsigned_value(desired_term).ok_or_else(badarg)?,
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                ) {
                    Ok(_) => Ok(Term::atom(atoms::OK)),
                    Err(was) => atomic_term(process, array.signed, was as i64),
                },
            }
        })
        .ok_or_else(badarg)?
}

// Port of erts/emulator/beam/erl_bif_atomics.c (atomics_info_1), OTP-29.1.1.
fn atomics_info(process: &mut Process, x: &[Term]) -> Result<Term, VmError> {
    let reference = x[0];
    reference
        .with_magic_payload::<AtomicsArray, _>(|array| {
            let (maximum, minimum) = if array.signed {
                (BigInt::from(i64::MAX), BigInt::from(i64::MIN))
            } else {
                (BigInt::from(u64::MAX), BigInt::from(0))
            };
            let maximum = integer_term(process, &maximum)?;
            let minimum = integer_term(process, &minimum)?;
            let size = integer_term(process, &BigInt::from(array.len))?;
            let memory = integer_term(process, &BigInt::from(array.memory))?;
            let mut heap = ProcessHeapHandle(&mut process.heap);
            arinsal_maps::from_list(
                &[
                    (
                        Term::atom(global_atoms().intern("max").expect("OTP atom")),
                        maximum,
                    ),
                    (
                        Term::atom(global_atoms().intern("min").expect("OTP atom")),
                        minimum,
                    ),
                    (
                        Term::atom(global_atoms().intern("size").expect("OTP atom")),
                        size,
                    ),
                    (
                        Term::atom(global_atoms().intern("memory").expect("OTP atom")),
                        memory,
                    ),
                ],
                &mut heap,
            )
            .map_err(|_| system_limit())
        })
        .ok_or_else(badarg)?
}

// Port of erts/emulator/beam/erl_bif_counters.c (erts_internal_counters_new_1), OTP-29.1.1.
fn counters_new(process: &mut Process, x: &[Term]) -> Result<Term, VmError> {
    let count = array_size(x[0])?;
    if count == 0 {
        return Err(badarg());
    }
    let slots = schedulers_total().checked_add(1).ok_or_else(system_limit)?;
    if count > usize::MAX / (ERTS_ATOMIC64_SIZE * 2 * slots) {
        return Err(system_limit());
    }
    let cache_lines = slots
        .checked_mul(count.div_ceil(ATOMICS_PER_CACHE_LINE))
        .ok_or_else(system_limit)?;
    let payload_size = 8_usize
        .checked_add(
            cache_lines
                .checked_mul(ERTS_CACHE_LINE_SIZE)
                .ok_or_else(system_limit)?,
        )
        .ok_or_else(system_limit)?;
    let mut lines = Vec::new();
    lines
        .try_reserve_exact(cache_lines)
        .map_err(|_| system_limit())?;
    lines.extend((0..cache_lines).map(|_| CounterCacheLine {
        values: std::array::from_fn(|_| AtomicI64::new(0)),
    }));
    let array = CountersArray {
        lines,
        len: count,
        slots,
        memory: MAGIC_BIN_DATA_OFFSET + payload_size,
    };
    new_magic_ref(process, array, payload_size)
}

fn counter_cell(array: &CountersArray, index: usize, scheduler: usize) -> &AtomicI64 {
    &array.lines[(index / ATOMICS_PER_CACHE_LINE) * array.slots + scheduler].values
        [index % ATOMICS_PER_CACHE_LINE]
}

// Port of erts/emulator/beam/erl_bif_counters.c (erts_internal_counters_get_2), OTP-29.1.1.
fn counters_get(process: &mut Process, x: &[Term]) -> Result<Term, VmError> {
    let (reference, index_term) = (x[0], x[1]);
    reference
        .with_magic_payload::<CountersArray, _>(|array| {
            let index = unsigned_word(index_term)
                .filter(|&index| index != 0 && index <= array.len)
                .ok_or_else(badarg)?
                - 1;
            let mut sum = 0_i64;
            for slot in 0..array.slots {
                sum = sum.wrapping_add(counter_cell(array, index, slot).load(Ordering::Relaxed));
            }
            integer_term(process, &BigInt::from(sum))
        })
        .ok_or_else(badarg)?
}

// Port of erts/emulator/beam/erl_bif_counters.c (erts_internal_counters_add_3), OTP-29.1.1.
fn counters_add(process: &mut Process, x: &[Term]) -> Result<Term, VmError> {
    let (reference, index_term, increment_term) = (x[0], x[1], x[2]);
    reference
        .with_magic_payload::<CountersArray, _>(|array| {
            let index = unsigned_word(index_term)
                .filter(|&index| index != 0 && index <= array.len)
                .ok_or_else(badarg)?
                - 1;
            let increment = arithmetic_value(increment_term).ok_or_else(badarg)?;
            let slot = process.scheduler_id as usize;
            let cell = counter_cell(array, index, slot);
            let value = cell.load(Ordering::Relaxed).wrapping_add(increment);
            cell.store(value, Ordering::Relaxed);
            Ok(Term::atom(atoms::OK))
        })
        .ok_or_else(badarg)?
}

// Port of erts/emulator/beam/erl_bif_counters.c (erts_internal_counters_put_3), OTP-29.1.1.
fn counters_put(_process: &mut Process, x: &[Term]) -> Result<Term, VmError> {
    let (reference, index_term, value_term) = (x[0], x[1], x[2]);
    reference
        .with_magic_payload::<CountersArray, _>(|array| {
            let index = unsigned_word(index_term)
                .filter(|&index| index != 0 && index <= array.len)
                .ok_or_else(badarg)?
                - 1;
            let value = signed_value(value_term).ok_or_else(badarg)?;
            let mut others = 0_i64;
            for slot in 1..array.slots {
                others =
                    others.wrapping_add(counter_cell(array, index, slot).load(Ordering::Relaxed));
            }
            counter_cell(array, index, 0).store(value.wrapping_sub(others), Ordering::Relaxed);
            Ok(Term::atom(atoms::OK))
        })
        .ok_or_else(badarg)?
}

// Port of erts/emulator/beam/erl_bif_counters.c (erts_internal_counters_info_1), OTP-29.1.1.
fn counters_info(process: &mut Process, x: &[Term]) -> Result<Term, VmError> {
    let reference = x[0];
    reference
        .with_magic_payload::<CountersArray, _>(|array| {
            let size = integer_term(process, &BigInt::from(array.len))?;
            let memory = integer_term(process, &BigInt::from(array.memory))?;
            let mut heap = ProcessHeapHandle(&mut process.heap);
            arinsal_maps::from_list(
                &[
                    (
                        Term::atom(global_atoms().intern("size").expect("OTP atom")),
                        size,
                    ),
                    (
                        Term::atom(global_atoms().intern("memory").expect("OTP atom")),
                        memory,
                    ),
                ],
                &mut heap,
            )
            .map_err(|_| system_limit())
        })
        .ok_or_else(badarg)?
}

fn integer_term(process: &mut Process, value: &BigInt) -> Result<Term, VmError> {
    let mut heap = ProcessHeapHandle(&mut process.heap);
    TermBuilder::new(&mut heap)
        .int_from_bigint(value)
        .map_err(|_| system_limit())
}

fn atomic_term(process: &mut Process, signed: bool, value: i64) -> Result<Term, VmError> {
    let value = if signed {
        BigInt::from(value)
    } else {
        BigInt::from(value as u64)
    };
    integer_term(process, &value)
}

macro_rules! native_bif {
    ($name:ident, $body:ident, $arity:literal) => {
        /// Native BIF body.
        // Port of erts/emulator/beam/erl_bif_atomics.c / erl_bif_counters.c, OTP-29.1.1.
        pub(crate) extern "C" fn $name(c_p: *mut ProcessHeader, reg: *mut u64, i: u64) -> u64 {
            let Some(process) = crate::native_hooks::process_from_header(c_p) else {
                return 0;
            };
            process.heap.note_bif_entry();
            let x = crate::bif_table::bif_args::<$arity>(reg);
            let result = $body(process, &x);
            bif_ret(c_p, i, result)
        }
    };
}

native_bif!(atomics_new_2, atomics_new, 2);
native_bif!(atomics_get_2, atomics_get, 2);
native_bif!(atomics_put_3, atomics_put, 3);
fn atomics_add_only(process: &mut Process, x: &[Term]) -> Result<Term, VmError> {
    atomics_add(process, x, false)
}
native_bif!(atomics_add_3, atomics_add_only, 3);

fn atomics_add_get(process: &mut Process, x: &[Term]) -> Result<Term, VmError> {
    atomics_add(process, x, true)
}
native_bif!(atomics_add_get_3, atomics_add_get, 3);
native_bif!(atomics_exchange_3, atomics_exchange, 3);
native_bif!(atomics_compare_exchange_4, atomics_compare_exchange, 4);
native_bif!(atomics_info_1, atomics_info, 1);
native_bif!(counters_new_1, counters_new, 1);
native_bif!(counters_get_2, counters_get, 2);
native_bif!(counters_add_3, counters_add, 3);
native_bif!(counters_put_3, counters_put, 3);
native_bif!(counters_info_1, counters_info, 1);

#[cfg(test)]
mod tests {
    use super::*;
    use arinsal_term::ProcessHeap;
    use std::sync::Arc;

    #[test]
    fn atomics_array_lifetime_follows_its_magic_ref_heap_owner() {
        let dropped = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut heap = ProcessHeap::with_words(64);
        let reference = {
            let payload = AtomicsArray {
                cells: AtomicCells::Signed(vec![AtomicI64::new(0)]),
                signed: true,
                len: 1,
                memory: MAGIC_BIN_DATA_OFFSET + 24,
                dropped: Some(Arc::clone(&dropped)),
            };
            TermBuilder::new(&mut heap)
                .magic_ref(MagicBin::with_erts_payload_size_and_refn(
                    payload,
                    24,
                    arinsal_bifs::next_ref_words(),
                ))
                .unwrap()
        };
        assert!(reference.is_magic_ref());
        assert_eq!(dropped.load(Ordering::SeqCst), 0);
        heap.collect(&mut [], &mut [], 0).unwrap();
        assert_eq!(dropped.load(Ordering::SeqCst), 1);
    }
}

// erl_bif_atomics.c: atomics_destructor.
arinsal_term::magic_payload!(AtomicsArray => atomics_destructor);

// erl_bif_counters.c: counters_destructor.
arinsal_term::magic_payload!(CountersArray => counters_destructor);
