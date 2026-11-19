//! The operator and type-test BIFs of erl_bif_op.c.
//!
//! Port of erts/emulator/beam/erl_bif_op.c (and_2, or_2, xor_2, not_1, sgt_2, sge_2, slt_2,
//! sle_2, seq_2, seqeq_2, sneq_2, sneqeq_2, is_atom_1 .. is_map_1, is_function_1,
//! is_boolean_1, is_record_1, is_record_2, is_record_3) and erl_record.c
//! (erl_is_native_record), OTP-29.1.1. Each BIF is
//! `bif_table[].f` with `(c_p, reg, I)`: it reads `BIF_ARG_n` from the register array and
//! returns the term, or `BIF_ERROR(c_p, BADARG)`.

use crate::bif_table::bif_args;
use crate::natives::bif::bif_badarg;
use arinsal_beamasm::ProcessHeader;
use arinsal_term::{Term, TermKind, atoms, cmp, exact_eq, loose_eq};
use std::cmp::Ordering;

/// `am_true` / `am_false`.
#[inline(always)]
fn boolean(value: bool) -> u64 {
    crate::native_hooks::raw(Term::atom(if value { atoms::TRUE } else { atoms::FALSE }))
}

/// `true` / `false` of an atom argument, `None` for any other term.
#[inline(always)]
fn bool_arg(term: Term) -> Option<bool> {
    match term.as_atom() {
        Some(atom) if atom == atoms::TRUE => Some(true),
        Some(atom) if atom == atoms::FALSE => Some(false),
        _ => None,
    }
}

/// A two-boolean operator: the result, or `BIF_ERROR(BIF_P, BADARG)`.
#[inline(always)]
fn boolean_op(c_p: *mut ProcessHeader, reg: *mut u64, op: fn(bool, bool) -> bool) -> u64 {
    let [a, b] = bif_args::<2>(reg);
    match (bool_arg(a), bool_arg(b)) {
        (Some(x), Some(y)) => boolean(op(x, y)),
        _ => bif_badarg(c_p),
    }
}

/// `erlang:'and'/2`.
// Port of erts/emulator/beam/erl_bif_op.c (and_2), OTP-29.1.1.
pub(crate) extern "C" fn and_2(c_p: *mut ProcessHeader, reg: *mut u64, _i: u64) -> u64 {
    boolean_op(c_p, reg, |a, b| a & b)
}

/// `erlang:'or'/2`.
// Port of erts/emulator/beam/erl_bif_op.c (or_2), OTP-29.1.1.
pub(crate) extern "C" fn or_2(c_p: *mut ProcessHeader, reg: *mut u64, _i: u64) -> u64 {
    boolean_op(c_p, reg, |a, b| a | b)
}

/// `erlang:'xor'/2`.
// Port of erts/emulator/beam/erl_bif_op.c (xor_2), OTP-29.1.1.
pub(crate) extern "C" fn xor_2(c_p: *mut ProcessHeader, reg: *mut u64, _i: u64) -> u64 {
    boolean_op(c_p, reg, |a, b| a ^ b)
}

/// `erlang:'not'/1`.
// Port of erts/emulator/beam/erl_bif_op.c (not_1), OTP-29.1.1.
pub(crate) extern "C" fn not_1(c_p: *mut ProcessHeader, reg: *mut u64, _i: u64) -> u64 {
    let [a] = bif_args::<1>(reg);
    match bool_arg(a) {
        Some(value) => boolean(!value),
        None => bif_badarg(c_p),
    }
}

/// A comparison BIF: `BIF_RET(CMP_xx(BIF_ARG_1, BIF_ARG_2) ? am_true : am_false)`.
macro_rules! comparison {
    ($(#[$doc:meta])* $name:ident, $test:expr) => {
        $(#[$doc])*
        pub(crate) extern "C" fn $name(_c_p: *mut ProcessHeader, reg: *mut u64, _i: u64) -> u64 {
            let [a, b] = bif_args::<2>(reg);
            let test: fn(Term, Term) -> bool = $test;
            boolean(test(a, b))
        }
    };
}

comparison!(
    /// `erlang:'>'/2`. Port of erl_bif_op.c (sgt_2).
    sgt_2, |a, b| cmp(a, b) == Ordering::Greater
);
comparison!(
    /// `erlang:'>='/2`. Port of erl_bif_op.c (sge_2).
    sge_2, |a, b| cmp(a, b) != Ordering::Less
);
comparison!(
    /// `erlang:'<'/2`. Port of erl_bif_op.c (slt_2).
    slt_2, |a, b| cmp(a, b) == Ordering::Less
);
comparison!(
    /// `erlang:'=<'/2`. Port of erl_bif_op.c (sle_2).
    sle_2, |a, b| cmp(a, b) != Ordering::Greater
);
comparison!(
    /// `erlang:'=:='/2`. Port of erl_bif_op.c (seq_2: `eq`).
    seq_2, exact_eq
);
comparison!(
    /// `erlang:'=='/2`. Port of erl_bif_op.c (seqeq_2: `CMP_EQ`).
    seqeq_2, loose_eq
);
comparison!(
    /// `erlang:'=/='/2`. Port of erl_bif_op.c (sneq_2).
    sneq_2, |a, b| !exact_eq(a, b)
);

/// `erlang:is_function/2`.
// Port of erts/emulator/beam/erl_bif_op.c (is_function_2, erl_is_function), OTP-29.1.1.
pub(crate) extern "C" fn is_function_2(c_p: *mut ProcessHeader, reg: *mut u64, _i: u64) -> u64 {
    let [function, arity] = bif_args::<2>(reg);
    match function_arity_matches(function, arity) {
        Some(value) => boolean(value),
        None => bif_badarg(c_p),
    }
}

fn function_arity_matches(function: Term, arity: Term) -> Option<bool> {
    use num_bigint::Sign;

    let arity = if let Some(arity) = arity.as_small() {
        if arity < 0 {
            return None;
        }
        Some(u8::try_from(arity).ok())
    } else {
        let arity = crate::natives::raw::integer(arity)?;
        if arity.sign() == Sign::Minus {
            return None;
        }
        return Some(false);
    };
    Some(
        arity
            .flatten()
            .is_some_and(|arity| crate::natives::raw::fun_arity(function) == Some(arity)),
    )
}

/// Dynamic function-arity type check used by x86 BeamAsm.
// Port of erts/emulator/beam/erl_bif_op.c:237-265 (erl_is_function), OTP-29.1.1.
#[unsafe(no_mangle)]
pub extern "C" fn erl_is_function(c_p: *mut ProcessHeader, function: u64, arity: u64) -> u64 {
    let function = crate::native_hooks::from_raw(function);
    let arity = crate::native_hooks::from_raw(arity);
    match function_arity_matches(function, arity) {
        Some(value) => boolean(value),
        None => bif_badarg(c_p),
    }
}
comparison!(
    /// `erlang:'/='/2`. Port of erl_bif_op.c (sneqeq_2).
    sneqeq_2, |a, b| !loose_eq(a, b)
);

/// A one-argument type test: `BIF_RET(is_xxx(BIF_ARG_1) ? am_true : am_false)`.
macro_rules! type_test {
    ($(#[$doc:meta])* $name:ident, $test:expr) => {
        $(#[$doc])*
        pub(crate) extern "C" fn $name(_c_p: *mut ProcessHeader, reg: *mut u64, _i: u64) -> u64 {
            let [a] = bif_args::<1>(reg);
            let test: fn(Term) -> bool = $test;
            boolean(test(a))
        }
    };
}

type_test!(
    /// `erlang:is_atom/1`. Port of erl_bif_op.c (is_atom_1).
    is_atom_1, |t| t.as_atom().is_some()
);
type_test!(
    /// `erlang:is_float/1`. Port of erl_bif_op.c (is_float_1).
    is_float_1, |t| t.float_value().is_some()
);
type_test!(
    /// `erlang:is_integer/1`. Port of erl_bif_op.c (is_integer_1).
    is_integer_1, |t| t.as_small().is_some() || t.bignum_digit_count().is_some()
);
type_test!(
    /// `erlang:is_list/1`. Port of erl_bif_op.c (is_list_1: `is_list || is_nil`).
    is_list_1, |t| matches!(t.classify(), TermKind::List | TermKind::Nil)
);
type_test!(
    /// `erlang:is_number/1`. Port of erl_bif_op.c (is_number_1).
    is_number_1, |t| t.classify() == TermKind::Number
);
type_test!(
    /// `erlang:is_pid/1`. Port of erl_bif_op.c (is_pid_1).
    is_pid_1, |t| t.classify() == TermKind::Pid
);
type_test!(
    /// `erlang:is_port/1`. Port of erl_bif_op.c (is_port_1).
    is_port_1, |t| t.classify() == TermKind::Port
);
type_test!(
    /// `erlang:is_reference/1`. Port of erl_bif_op.c (is_reference_1).
    is_reference_1, |t| t.classify() == TermKind::Ref
);
type_test!(
    /// `erlang:is_tuple/1`. Port of erl_bif_op.c (is_tuple_1).
    is_tuple_1, |t| arinsal_term::raw::Tuple::try_from(t).is_ok()
);
type_test!(
    /// `erlang:is_binary/1`. Port of erl_bif_op.c (is_binary_1: a bitstring of whole bytes).
    is_binary_1, |t| arinsal_term::raw::bif_arg_binary_ref(t)
        .is_some_and(|bin| bin.bit_len().is_multiple_of(8))
);
type_test!(
    /// `erlang:is_bitstring/1`. Port of erl_bif_op.c (is_bitstring_1).
    is_bitstring_1, |t| t.classify() == TermKind::Bitstring
);
type_test!(
    /// `erlang:is_function/1`. Port of erl_bif_op.c (is_function_1: `is_any_fun`).
    is_function_1, |t| t.classify() == TermKind::Fun
);
type_test!(
    /// `erlang:is_boolean/1`. Port of erl_bif_op.c (is_boolean_1).
    is_boolean_1, |t| bool_arg(t).is_some()
);
type_test!(
    /// `erlang:is_record/1`. Port of erl_bif_op.c (is_record_1: a native record).
    is_record_1, |t| t.is_record()
);
type_test!(
    /// `erlang:is_map/1`. Port of erl_bif_op.c (is_map_1).
    is_map_1, |t| t.classify() == TermKind::Map
);

/// Whether `term` is a tuple of arity >= 1 whose first element is `tag`, and its arity.
fn tagged_tuple_arity(term: Term, tag: Term) -> Option<usize> {
    let tuple = arinsal_term::raw::Tuple::try_from(term).ok()?;
    (tuple.get(0)? == tag).then_some(tuple.arity())
}

/// `erlang:is_record/2`.
// Port of erts/emulator/beam/erl_bif_op.c (is_record_2), OTP-29.1.1.
pub(crate) extern "C" fn is_record_2(c_p: *mut ProcessHeader, reg: *mut u64, _i: u64) -> u64 {
    let [term, tag] = bif_args::<2>(reg);
    if tag.as_atom().is_none() {
        return bif_badarg(c_p);
    }
    if tagged_tuple_arity(term, tag).is_some() {
        return boolean(true);
    }
    // A native record: `RECORD_DEF_P(RECORD_INST_P(BIF_ARG_1))->name == BIF_ARG_2`.
    boolean(
        term.record_snapshot()
            .is_some_and(|record| Term::atom(record.name) == tag),
    )
}

/// `erlang:is_record/3`.
// Port of erts/emulator/beam/erl_bif_op.c (is_record_3), OTP-29.1.1.
pub(crate) extern "C" fn is_record_3(c_p: *mut ProcessHeader, reg: *mut u64, _i: u64) -> u64 {
    let [term, tag, size] = bif_args::<3>(reg);
    if tag.as_atom().is_none() {
        return bif_badarg(c_p);
    }
    if size.as_atom().is_some() {
        // Port of erts/emulator/beam/erl_record.c (erl_is_native_record): the definition's
        // module is BIF_ARG_2 and its name BIF_ARG_3.
        return boolean(term.record_snapshot().is_some_and(|record| {
            Term::atom(record.module) == tag && Term::atom(record.name) == size
        }));
    }
    match size.as_small() {
        Some(size) => boolean(
            tagged_tuple_arity(term, tag).is_some_and(|arity| i64::try_from(arity) == Ok(size)),
        ),
        None => bif_badarg(c_p),
    }
}
