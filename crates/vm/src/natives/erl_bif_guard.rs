//! The trapping `length/1` of erl_bif_guard.c.
//!
//! Port of erts/emulator/beam/erl_bif_guard.c (length_1, erlang_length_trap,
//! erts_trapping_length_1, min_2, max_2, abs_1, float_1, trunc_1, round_1, ceil_1, floor_1),
//! OTP-29.1.1. Each BIF is `bif_table[].f` with `(c_p, reg, I)`.
//! `length/1` is called from native code and `apply/3`; a list too long for the reductions left
//! traps to the hidden `erlang:length/3` (`erlang_length_export`, installed by
//! `erts_init_trap_export`) with `(List, Length, OriginalList)`.

use crate::natives::bif::{bif_badarg, bif_ret, bif_system_limit};
use arinsal_beamasm::ProcessHeader;
use arinsal_bifs::ProcessHeapHandle;
use arinsal_term::Term;
use arinsal_term::raw::Cons;

/// `erlang:length/1`.
// Port of erts/emulator/beam/erl_bif_guard.c (length_1), OTP-29.1.1.
pub(crate) extern "C" fn length_1(c_p: *mut ProcessHeader, reg: *mut u64, i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    // args[0] = BIF_ARG_1; args[1] = make_small(0); args[2] = BIF_ARG_1 (kept for the error).
    let [list] = crate::bif_table::bif_args::<1>(reg);
    length_run(c_p, reg, i, process, list, 0, list)
}

/// `erlang:length/3`, the hidden trap target of `length_1`.
// Port of erts/emulator/beam/erl_bif_guard.c (erlang_length_trap), OTP-29.1.1.
pub(crate) extern "C" fn erlang_length_trap(c_p: *mut ProcessHeader, reg: *mut u64, i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let [list, acc, original] = crate::bif_table::bif_args::<3>(reg);
    let Some(acc) = acc.as_small().and_then(|acc| usize::try_from(acc).ok()) else {
        return bif_badarg(c_p);
    };
    length_run(c_p, reg, i, process, list, acc, original)
}

/// `erts_trapping_length_1` and the result handling of `erlang_length_trap`: the length,
/// `BIF_TRAP3(&erlang_length_export, ...)`, or `ERTS_BIF_ERROR_TRAPPED1` naming `length/1`
/// with the original argument.
fn length_run(
    c_p: *mut ProcessHeader,
    reg: *mut u64,
    i: u64,
    process: &mut crate::Process,
    list: Term,
    acc: usize,
    original: Term,
) -> u64 {
    let budget = process.heap.abi.fcalls.max(0) as usize * 16;
    let mut cursor = list;
    let mut count = acc;
    let mut scanned = 0usize;
    while scanned < budget {
        let Some(cons) = Cons::try_from(cursor).ok() else {
            break;
        };
        cursor = cons.tail();
        count += 1;
        scanned += 1;
    }
    if Cons::try_from(cursor).is_ok() {
        process.heap.abi.fcalls = 0;
        let Some(acc) = i64::try_from(count).ok().and_then(Term::small) else {
            return bif_system_limit(c_p);
        };
        let trap = crate::natives::erl_bif_lists::bif_trap(
            process,
            "erlang:length/3",
            vec![cursor, acc, original],
        );
        return bif_ret(c_p, i, Err(trap));
    }
    if cursor != Term::NIL {
        crate::bif_table::set_bif_arg(reg, 0, original);
        return bif_badarg(c_p);
    }
    let reds = (scanned / 16).min(i32::MAX as usize) as i32;
    process.heap.abi.fcalls = (process.heap.abi.fcalls - reds).max(0);
    let Some(value) = i64::try_from(count).ok().and_then(Term::small) else {
        return bif_system_limit(c_p);
    };
    crate::native_hooks::raw(value)
}

/// `erlang:min/2`.
// Port of erts/emulator/beam/erl_bif_guard.c (min_2), OTP-29.1.1.
pub(crate) extern "C" fn min_2(_c_p: *mut ProcessHeader, reg: *mut u64, _i: u64) -> u64 {
    let [a, b] = crate::bif_table::bif_args::<2>(reg);
    let min = if arinsal_term::cmp(a, b) == std::cmp::Ordering::Greater {
        b
    } else {
        a
    };
    crate::native_hooks::raw(min)
}

/// `erlang:max/2`.
// Port of erts/emulator/beam/erl_bif_guard.c (max_2), OTP-29.1.1.
pub(crate) extern "C" fn max_2(_c_p: *mut ProcessHeader, reg: *mut u64, _i: u64) -> u64 {
    let [a, b] = crate::bif_table::bif_args::<2>(reg);
    let max = if arinsal_term::cmp(a, b) == std::cmp::Ordering::Less {
        b
    } else {
        a
    };
    crate::native_hooks::raw(max)
}

/// A one-argument number BIF of erl_bif_guard.c: the result on the process heap, or
/// `BIF_ERROR(BIF_P, BADARG)`.
#[inline(always)]
fn number_bif(
    c_p: *mut ProcessHeader,
    reg: *mut u64,
    body: fn(Term, &mut ProcessHeapHandle<'_>) -> arinsal_arith::ArithResult,
) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let [arg] = crate::bif_table::bif_args::<1>(reg);
    match body(arg, &mut ProcessHeapHandle(&mut process.heap)) {
        Ok(value) => crate::native_hooks::raw(value),
        Err(_) => crate::natives::bif::bif_badarg(c_p),
    }
}

/// `erlang:abs/1`.
// Port of erts/emulator/beam/erl_bif_guard.c (abs_1), OTP-29.1.1.
pub(crate) extern "C" fn abs_1(c_p: *mut ProcessHeader, reg: *mut u64, _i: u64) -> u64 {
    number_bif(c_p, reg, |a, heap| arinsal_arith::abs(a, heap))
}

/// `erlang:float/1`.
// Port of erts/emulator/beam/erl_bif_guard.c (float_1), OTP-29.1.1.
pub(crate) extern "C" fn float_1(c_p: *mut ProcessHeader, reg: *mut u64, _i: u64) -> u64 {
    number_bif(c_p, reg, |a, heap| arinsal_arith::to_float(a, heap))
}

/// `erlang:trunc/1`.
// Port of erts/emulator/beam/erl_bif_guard.c (trunc_1), OTP-29.1.1.
pub(crate) extern "C" fn trunc_1(c_p: *mut ProcessHeader, reg: *mut u64, _i: u64) -> u64 {
    number_bif(c_p, reg, |a, heap| arinsal_arith::trunc(a, heap))
}

/// `erlang:round/1`.
// Port of erts/emulator/beam/erl_bif_guard.c (round_1), OTP-29.1.1.
pub(crate) extern "C" fn round_1(c_p: *mut ProcessHeader, reg: *mut u64, _i: u64) -> u64 {
    number_bif(c_p, reg, |a, heap| arinsal_arith::round(a, heap))
}

/// `erlang:ceil/1`.
// Port of erts/emulator/beam/erl_bif_guard.c (ceil_1), OTP-29.1.1.
pub(crate) extern "C" fn ceil_1(c_p: *mut ProcessHeader, reg: *mut u64, _i: u64) -> u64 {
    number_bif(c_p, reg, |a, heap| arinsal_arith::ceil(a, heap))
}

/// `erlang:floor/1`.
// Port of erts/emulator/beam/erl_bif_guard.c (floor_1), OTP-29.1.1.
pub(crate) extern "C" fn floor_1(c_p: *mut ProcessHeader, reg: *mut u64, _i: u64) -> u64 {
    number_bif(c_p, reg, |a, heap| arinsal_arith::floor(a, heap))
}

/// `erlang:byte_size/1`.
// Port of erts/emulator/beam/erl_bif_guard.c (byte_size_1), OTP-29.1.1.
pub(crate) extern "C" fn byte_size_1(c_p: *mut ProcessHeader, reg: *mut u64, i: u64) -> u64 {
    bitstring_size(c_p, reg, i, |bits| bits.div_ceil(8))
}

/// `erlang:bit_size/1`.
// Port of erts/emulator/beam/erl_bif_guard.c (bit_size_1), OTP-29.1.1.
pub(crate) extern "C" fn bit_size_1(c_p: *mut ProcessHeader, reg: *mut u64, i: u64) -> u64 {
    bitstring_size(c_p, reg, i, |bits| bits)
}

fn bitstring_size(
    c_p: *mut ProcessHeader,
    reg: *mut u64,
    i: u64,
    size: impl FnOnce(usize) -> usize,
) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    let [bin] = crate::bif_table::bif_args::<1>(reg);
    let Some(bits) = arinsal_term::erl_bits::bitstring_bit_len(bin) else {
        return bif_ret(c_p, i, Err(crate::natives::bif::badarg()));
    };
    let value = size(bits);
    match Term::small(value as i64) {
        Some(small) => crate::native_hooks::raw(small),
        None => {
            // `erts_make_integer` of a size above the small range.
            process.heap.note_bif_entry();
            let mut heap = ProcessHeapHandle(&mut process.heap);
            let term = arinsal_term::TermBuilder::new(&mut heap)
                .int_from_u64(value as u64)
                .expect("HAlloc");
            crate::native_hooks::raw(term)
        }
    }
}
