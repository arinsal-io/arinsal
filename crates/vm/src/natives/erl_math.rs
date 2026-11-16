//! The math BIFs of erl_math.c.
//!
//! Port of erts/emulator/beam/erl_math.c (math_call_1, math_call_errno_1, math_call_2, and
//! math_*_1/math_*_2), OTP-29.1.1. The BIF entries use the register window passed by the
//! call fragment, convert numbers with the OTP arithmetic conversion, check the result, and
//! allocate the returned float on the process heap.

mod raw;

use super::bif::bif_ret;
use crate::{Process, VmError};
use arinsal_beamasm::ProcessHeader;
use arinsal_term::{Term, TermBuilder, TermKind, atoms};

fn badarg() -> VmError {
    VmError::Trap(crate::exceptions::Trap::error(Term::atom(atoms::BADARG)))
}

fn badarith() -> VmError {
    VmError::Trap(crate::exceptions::Trap::error(Term::atom(atoms::BADARITH)))
}

fn number_to_double(term: Term) -> Result<f64, VmError> {
    if let Some(value) = term.as_small() {
        return Ok(value as f64);
    }
    if let Some(value) = arinsal_term::raw::float_value(term) {
        return Ok(value);
    }
    if term.classify() != TermKind::Number {
        return Err(badarg());
    }
    arinsal_arith::number_to_f64(term).map_err(|_| badarith())
}

fn float_result(process: &mut Process, value: f64) -> Result<Term, VmError> {
    if !value.is_finite() {
        return Err(badarith());
    }
    Ok(TermBuilder::new(&mut process.heap)
        .float(value)
        .expect("process heap follows erts HAlloc"))
}

fn math_call_1(
    process: &mut Process,
    function: fn(f64) -> f64,
    argument: Term,
) -> Result<Term, VmError> {
    let value = number_to_double(argument)?;
    float_result(process, function(value))
}

fn math_call_errno_1(
    process: &mut Process,
    function: fn(f64) -> f64,
    argument: Term,
) -> Result<Term, VmError> {
    let (result, errno_error) = raw::with_errno(|| math_call_1(process, function, argument));
    if result.is_ok() && errno_error {
        return Err(badarith());
    }
    result
}

fn math_call_2(
    process: &mut Process,
    function: fn(f64, f64) -> f64,
    first: Term,
    second: Term,
) -> Result<Term, VmError> {
    let first = number_to_double(first)?;
    let second = number_to_double(second)?;
    float_result(process, function(first, second))
}

macro_rules! unary_bifs {
    ($($rust_name:ident => $c_name:ident, $function:path);+ $(;)?) => {
        $(
            #[doc = concat!(
                "Port of erts/emulator/beam/erl_math.c (",
                stringify!($c_name),
                "), OTP-29.1.1."
            )]
            pub(crate) extern "C" fn $rust_name(
                c_p: *mut ProcessHeader,
                reg: *mut u64,
                i: u64,
            ) -> u64 {
                let Some(process) = crate::native_hooks::process_from_header(c_p) else {
                    return 0;
                };
                process.heap.note_bif_entry();
                let [argument] = crate::bif_table::bif_args::<1>(reg);
                bif_ret(c_p, i, math_call_1(process, $function, argument))
            }
        )+
    };
}

unary_bifs! {
    cos_1 => math_cos_1, raw::cos;
    cosh_1 => math_cosh_1, raw::cosh;
    sin_1 => math_sin_1, raw::sin;
    sinh_1 => math_sinh_1, raw::sinh;
    tan_1 => math_tan_1, raw::tan;
    tanh_1 => math_tanh_1, raw::tanh;
    acosh_1 => math_acosh_1, raw::acosh;
    asinh_1 => math_asinh_1, raw::asinh;
    atan_1 => math_atan_1, raw::atan;
    atanh_1 => math_atanh_1, raw::atanh;
    erf_1 => math_erf_1, raw::erf;
    erfc_1 => math_erfc_1, raw::erfc;
    exp_1 => math_exp_1, raw::exp;
    log_1 => math_log_1, raw::log;
    log2_1 => math_log2_1, raw::log2;
    log10_1 => math_log10_1, raw::log10;
    sqrt_1 => math_sqrt_1, raw::sqrt;
    ceil_1 => math_ceil_1, raw::ceil;
    floor_1 => math_floor_1, raw::floor;
}

macro_rules! unary_errno_bifs {
    ($($rust_name:ident => $c_name:ident, $function:path);+ $(;)?) => {
        $(
            #[doc = concat!(
                "Port of erts/emulator/beam/erl_math.c (",
                stringify!($c_name),
                "), OTP-29.1.1."
            )]
            pub(crate) extern "C" fn $rust_name(
                c_p: *mut ProcessHeader,
                reg: *mut u64,
                i: u64,
            ) -> u64 {
                let Some(process) = crate::native_hooks::process_from_header(c_p) else {
                    return 0;
                };
                process.heap.note_bif_entry();
                let [argument] = crate::bif_table::bif_args::<1>(reg);
                bif_ret(c_p, i, math_call_errno_1(process, $function, argument))
            }
        )+
    };
}

unary_errno_bifs! {
    acos_1 => math_acos_1, raw::acos;
    asin_1 => math_asin_1, raw::asin;
}

macro_rules! binary_bifs {
    ($($rust_name:ident => $c_name:ident, $function:path);+ $(;)?) => {
        $(
            #[doc = concat!(
                "Port of erts/emulator/beam/erl_math.c (",
                stringify!($c_name),
                "), OTP-29.1.1."
            )]
            pub(crate) extern "C" fn $rust_name(
                c_p: *mut ProcessHeader,
                reg: *mut u64,
                i: u64,
            ) -> u64 {
                let Some(process) = crate::native_hooks::process_from_header(c_p) else {
                    return 0;
                };
                process.heap.note_bif_entry();
                let [first, second] = crate::bif_table::bif_args::<2>(reg);
                bif_ret(c_p, i, math_call_2(process, $function, first, second))
            }
        )+
    };
}

binary_bifs! {
    atan2_2 => math_atan2_2, raw::atan2;
    pow_2 => math_pow_2, raw::pow;
    fmod_2 => math_fmod_2, raw::fmod;
}
