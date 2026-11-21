//! Runtime arithmetic symbols called directly by BeamAsm generated code.
//!
//! Port of erts/emulator/beam/erl_arith.c, OTP-29.1.1.

use crate::Process;
use arinsal_arith::{ArithError, ArithResult};
use arinsal_beamasm::ProcessHeader;
use arinsal_term::{Term, exc};

/// Applies an arithmetic operation to a process heap and records its erts failure words.
// erl_arith.c allocates its results with HAlloc: the young heap, or a heap fragment
// (erts_heap_alloc, utils.c) when it is full, so a result never fails for lack of heap.
fn arithmetic(
    process: &mut Process,
    operation: &str,
    args: &[Term],
    f: impl FnOnce(&mut crate::ProcessHeapHandle<'_>) -> ArithResult,
) -> u64 {
    let result = f(&mut crate::ProcessHeapHandle(&mut process.heap));
    let charge = arinsal_arith::reduction_charge(operation, args);
    process.heap.abi.fcalls = process
        .heap
        .abi
        .fcalls
        .saturating_sub(charge.min(i32::MAX as u32) as i32)
        .max(0);
    finish(process, result)
}

fn finish(process: &mut Process, result: ArithResult) -> u64 {
    match result {
        Ok(value) => crate::native_hooks::raw(value),
        Err(ArithError::HeapFull { .. } | ArithError::SystemLimit) => {
            process.heap.abi.exc.freason = exc::EXC_SYSTEM_LIMIT;
            process.heap.abi.exc.fvalue =
                crate::native_hooks::raw(Term::atom(arinsal_term::atoms::SYSTEM_LIMIT));
            Term::NON_VALUE.tagged_word()
        }
        Err(ArithError::Badarith | ArithError::Badarg) => {
            process.heap.abi.exc.freason = exc::EXC_BADARITH;
            process.heap.abi.exc.fvalue =
                crate::native_hooks::raw(Term::atom(arinsal_term::atoms::BADARITH));
            Term::NON_VALUE.tagged_word()
        }
    }
}

fn mixed_plus(process: &mut Process, arg1: Term, arg2: Term) -> u64 {
    arithmetic(process, "+", &[arg1, arg2], |heap| {
        arinsal_arith::add(arg1, arg2, heap)
    })
}

fn mixed_times(process: &mut Process, arg1: Term, arg2: Term) -> u64 {
    let (result, charge) = arinsal_arith::mul_with_charge(
        arg1,
        arg2,
        &mut crate::ProcessHeapHandle(&mut process.heap),
    );
    process.heap.abi.fcalls = process
        .heap
        .abi
        .fcalls
        .saturating_sub(charge.min(i32::MAX as u32) as i32)
        .max(0);
    finish(process, result)
}

fn is_integer(term: Term) -> bool {
    term.as_small().is_some() || term.bignum_digit_count().is_some()
}

/// `Eterm erts_mixed_plus(Process *, Eterm, Eterm)`.
// Port of erts/emulator/beam/erl_arith.c:358-570 (erts_mixed_plus), OTP-29.1.1.
#[unsafe(no_mangle)]
pub extern "C" fn erts_mixed_plus(c_p: *mut ProcessHeader, arg1: u64, arg2: u64) -> u64 {
    let Some(process) = crate::native_hooks::enter_runtime(c_p) else {
        return Term::NON_VALUE.tagged_word();
    };
    let (arg1, arg2) = (
        crate::native_hooks::from_raw(arg1),
        crate::native_hooks::from_raw(arg2),
    );
    mixed_plus(process, arg1, arg2)
}

/// `Eterm erts_mixed_minus(Process *, Eterm, Eterm)`.
// Port of erts/emulator/beam/erl_arith.c:571-715 (erts_mixed_minus), OTP-29.1.1.
#[unsafe(no_mangle)]
pub extern "C" fn erts_mixed_minus(c_p: *mut ProcessHeader, arg1: u64, arg2: u64) -> u64 {
    let Some(process) = crate::native_hooks::enter_runtime(c_p) else {
        return Term::NON_VALUE.tagged_word();
    };
    let (arg1, arg2) = (
        crate::native_hooks::from_raw(arg1),
        crate::native_hooks::from_raw(arg2),
    );
    arithmetic(process, "-", &[arg1, arg2], |heap| {
        arinsal_arith::sub(arg1, arg2, heap)
    })
}

/// `Eterm erts_mixed_times(Process *, Eterm, Eterm)`.
// Port of erts/emulator/beam/erl_arith.c:716-918 (erts_mixed_times), OTP-29.1.1.
#[unsafe(no_mangle)]
pub extern "C" fn erts_mixed_times(c_p: *mut ProcessHeader, arg1: u64, arg2: u64) -> u64 {
    let Some(process) = crate::native_hooks::enter_runtime(c_p) else {
        return Term::NON_VALUE.tagged_word();
    };
    let (arg1, arg2) = (
        crate::native_hooks::from_raw(arg1),
        crate::native_hooks::from_raw(arg2),
    );
    mixed_times(process, arg1, arg2)
}

/// `Eterm erts_mixed_div(Process *, Eterm, Eterm)`.
// Port of erts/emulator/beam/erl_arith.c:1015-1170 (erts_mixed_div), OTP-29.1.1.
#[unsafe(no_mangle)]
pub extern "C" fn erts_mixed_div(c_p: *mut ProcessHeader, arg1: u64, arg2: u64) -> u64 {
    let Some(process) = crate::native_hooks::enter_runtime(c_p) else {
        return Term::NON_VALUE.tagged_word();
    };
    let (arg1, arg2) = (
        crate::native_hooks::from_raw(arg1),
        crate::native_hooks::from_raw(arg2),
    );
    arithmetic(process, "div", &[arg1, arg2], |heap| {
        arinsal_arith::fdiv(arg1, arg2, heap)
    })
}

/// `int erts_int_div_rem(Process *, Eterm, Eterm, Eterm *, Eterm *)`.
// Port of erts/emulator/beam/erl_arith.c:1172-1249 (erts_int_div_rem), OTP-29.1.1.
#[unsafe(no_mangle)]
pub extern "C" fn erts_int_div_rem(
    c_p: *mut ProcessHeader,
    arg1: u64,
    arg2: u64,
    quotient: *mut u64,
    remainder: *mut u64,
) -> i32 {
    let Some(process) = crate::native_hooks::enter_runtime(c_p) else {
        return 0;
    };
    if quotient.is_null() || remainder.is_null() {
        process.heap.abi.exc.freason = exc::EXC_BADARITH;
        return 0;
    }
    let (arg1, arg2) = (
        crate::native_hooks::from_raw(arg1),
        crate::native_hooks::from_raw(arg2),
    );
    let (result, charge) = arinsal_arith::integer_div_rem(
        arg1,
        arg2,
        &mut crate::ProcessHeapHandle(&mut process.heap),
    );
    process.heap.abi.fcalls = process
        .heap
        .abi
        .fcalls
        .saturating_sub(charge.min(i32::MAX as u32) as i32)
        .max(0);
    match result {
        Ok((q, r)) => {
            crate::raw::beam_common_ffi::write_word(quotient, crate::native_hooks::raw(q));
            crate::raw::beam_common_ffi::write_word(remainder, crate::native_hooks::raw(r));
            1
        }
        Err(error) => {
            finish(process, Err(error));
            0
        }
    }
}

/// `Eterm erts_band(Process *, Eterm, Eterm)`.
// Port of erts/emulator/beam/erl_arith.c:1252-1278 (erts_band), OTP-29.1.1.
#[unsafe(no_mangle)]
pub extern "C" fn erts_band(c_p: *mut ProcessHeader, arg1: u64, arg2: u64) -> u64 {
    let Some(process) = crate::native_hooks::enter_runtime(c_p) else {
        return Term::NON_VALUE.tagged_word();
    };
    let (arg1, arg2) = (
        crate::native_hooks::from_raw(arg1),
        crate::native_hooks::from_raw(arg2),
    );
    arithmetic(process, "band", &[arg1, arg2], |heap| {
        arinsal_arith::band(arg1, arg2, heap)
    })
}

/// `Eterm erts_bor(Process *, Eterm, Eterm)`.
// Port of erts/emulator/beam/erl_arith.c:1280-1306 (erts_bor), OTP-29.1.1.
#[unsafe(no_mangle)]
pub extern "C" fn erts_bor(c_p: *mut ProcessHeader, arg1: u64, arg2: u64) -> u64 {
    let Some(process) = crate::native_hooks::enter_runtime(c_p) else {
        return Term::NON_VALUE.tagged_word();
    };
    let (arg1, arg2) = (
        crate::native_hooks::from_raw(arg1),
        crate::native_hooks::from_raw(arg2),
    );
    arithmetic(process, "bor", &[arg1, arg2], |heap| {
        arinsal_arith::bor(arg1, arg2, heap)
    })
}

/// `Eterm erts_bxor(Process *, Eterm, Eterm)`.
// Port of erts/emulator/beam/erl_arith.c:1308-1337 (erts_bxor), OTP-29.1.1.
#[unsafe(no_mangle)]
pub extern "C" fn erts_bxor(c_p: *mut ProcessHeader, arg1: u64, arg2: u64) -> u64 {
    let Some(process) = crate::native_hooks::enter_runtime(c_p) else {
        return Term::NON_VALUE.tagged_word();
    };
    let (arg1, arg2) = (
        crate::native_hooks::from_raw(arg1),
        crate::native_hooks::from_raw(arg2),
    );
    arithmetic(process, "bxor", &[arg1, arg2], |heap| {
        arinsal_arith::bxor(arg1, arg2, heap)
    })
}

/// `Eterm erts_bnot(Process *, Eterm)`.
// Port of erts/emulator/beam/erl_arith.c:1339-1355 (erts_bnot), OTP-29.1.1.
#[unsafe(no_mangle)]
pub extern "C" fn erts_bnot(c_p: *mut ProcessHeader, arg: u64) -> u64 {
    let Some(process) = crate::native_hooks::enter_runtime(c_p) else {
        return Term::NON_VALUE.tagged_word();
    };
    let arg = crate::native_hooks::from_raw(arg);
    arithmetic(process, "bnot", &[arg], |heap| {
        arinsal_arith::bnot(arg, heap)
    })
}

/// `Eterm erts_bsl(Process *, Eterm, Eterm)`.
// Port of erts/emulator/beam/erl_arith.c:311-313 (erts_bsl), OTP-29.1.1.
#[unsafe(no_mangle)]
pub extern "C" fn erts_bsl(c_p: *mut ProcessHeader, arg1: u64, arg2: u64) -> u64 {
    let Some(process) = crate::native_hooks::enter_runtime(c_p) else {
        return Term::NON_VALUE.tagged_word();
    };
    let (arg1, arg2) = (
        crate::native_hooks::from_raw(arg1),
        crate::native_hooks::from_raw(arg2),
    );
    arithmetic(process, "bsl", &[arg1, arg2], |heap| {
        arinsal_arith::bsl(arg1, arg2, heap)
    })
}

/// `Eterm erts_bsr(Process *, Eterm, Eterm)`.
// Port of erts/emulator/beam/erl_arith.c:315-317 (erts_bsr), OTP-29.1.1.
#[unsafe(no_mangle)]
pub extern "C" fn erts_bsr(c_p: *mut ProcessHeader, arg1: u64, arg2: u64) -> u64 {
    let Some(process) = crate::native_hooks::enter_runtime(c_p) else {
        return Term::NON_VALUE.tagged_word();
    };
    let (arg1, arg2) = (
        crate::native_hooks::from_raw(arg1),
        crate::native_hooks::from_raw(arg2),
    );
    arithmetic(process, "bsr", &[arg1, arg2], |heap| {
        arinsal_arith::bsr(arg1, arg2, heap)
    })
}

/// `Eterm erts_unary_minus(Process *, Eterm)`.
// Port of erts/emulator/beam/erl_arith.c:318-338 (erts_unary_minus), OTP-29.1.1.
#[unsafe(no_mangle)]
pub extern "C" fn erts_unary_minus(c_p: *mut ProcessHeader, arg: u64) -> u64 {
    let Some(process) = crate::native_hooks::enter_runtime(c_p) else {
        return Term::NON_VALUE.tagged_word();
    };
    let arg = crate::native_hooks::from_raw(arg);
    arithmetic(process, "-", &[arg], |heap| arinsal_arith::neg(arg, heap))
}

/// `Eterm erts_mul_add(Process *, Eterm, Eterm, Eterm, Eterm *)`.
// Port of erts/emulator/beam/erl_arith.c:919-1013 (erts_mul_add), OTP-29.1.1.
#[unsafe(no_mangle)]
pub extern "C" fn erts_mul_add(
    c_p: *mut ProcessHeader,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    product_out: *mut u64,
) -> u64 {
    let Some(process) = crate::native_hooks::enter_runtime(c_p) else {
        return Term::NON_VALUE.tagged_word();
    };
    let (arg1, arg2, arg3) = (
        crate::native_hooks::from_raw(arg1),
        crate::native_hooks::from_raw(arg2),
        crate::native_hooks::from_raw(arg3),
    );
    if is_integer(arg1) && is_integer(arg2) && is_integer(arg3) {
        let result = arinsal_arith::integer_mul_add(
            arg1,
            arg2,
            arg3,
            &mut crate::ProcessHeapHandle(&mut process.heap),
        );
        let charge = arinsal_arith::mul_add_reduction_charge(arg1, arg2);
        process.heap.abi.fcalls = process
            .heap
            .abi
            .fcalls
            .saturating_sub(charge.min(i32::MAX as u32) as i32)
            .max(0);
        return finish(process, result);
    }
    let product = mixed_times(process, arg1, arg2);
    crate::raw::beam_common_ffi::write_word(product_out, product);
    if product == Term::NON_VALUE.tagged_word() {
        return product;
    }
    let product = crate::native_hooks::from_raw(product);
    mixed_plus(process, product, arg3)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arithmetic_runtime_symbol_signatures_match_otp() {
        let _: extern "C" fn(*mut ProcessHeader, u64, u64) -> u64 = erts_mixed_plus;
        let _: extern "C" fn(*mut ProcessHeader, u64, u64) -> u64 = erts_mixed_minus;
        let _: extern "C" fn(*mut ProcessHeader, u64, u64) -> u64 = erts_mixed_times;
        let _: extern "C" fn(*mut ProcessHeader, u64, u64) -> u64 = erts_mixed_div;
        let _: extern "C" fn(*mut ProcessHeader, u64, u64, *mut u64, *mut u64) -> i32 =
            erts_int_div_rem;
        let _: extern "C" fn(*mut ProcessHeader, u64, u64) -> u64 = erts_band;
        let _: extern "C" fn(*mut ProcessHeader, u64, u64) -> u64 = erts_bor;
        let _: extern "C" fn(*mut ProcessHeader, u64, u64) -> u64 = erts_bxor;
        let _: extern "C" fn(*mut ProcessHeader, u64) -> u64 = erts_bnot;
        let _: extern "C" fn(*mut ProcessHeader, u64, u64) -> u64 = erts_bsl;
        let _: extern "C" fn(*mut ProcessHeader, u64, u64) -> u64 = erts_bsr;
        let _: extern "C" fn(*mut ProcessHeader, u64) -> u64 = erts_unary_minus;
        let _: extern "C" fn(*mut ProcessHeader, u64, u64, u64, *mut u64) -> u64 = erts_mul_add;
    }

    #[test]
    fn arithmetic_runtime_symbols_match_otp_values() {
        let value = (1_i128 << 100) + 123;
        let reference = arinsal_difftest::RefErl::start().expect("OTP 29.1.1 is required");
        let expected = reference
            .eval(&format!(
                "[{value}+17,{value}-17,{value}*17,{value}/17,{value} div 17,{value} rem 17,{value} band 17,{value} bor 17,{value} bxor 17,bnot {value},{value} bsl 17,{value} bsr 17,-{value},{value}*17+{value}]"
            ))
            .unwrap();

        let mut process = Process::new();
        let (lhs, rhs) = {
            let mut heap = crate::ProcessHeapHandle(&mut process.heap);
            let mut builder = arinsal_term::TermBuilder::new(&mut heap);
            (
                builder.int_from_i128(value).unwrap(),
                Term::small(17).unwrap(),
            )
        };
        let lhs = crate::native_hooks::raw(lhs);
        let rhs = crate::native_hooks::raw(rhs);
        let mut actual = vec![
            own(erts_mixed_plus(process.native_header(), lhs, rhs)),
            own(erts_mixed_minus(process.native_header(), lhs, rhs)),
            own(erts_mixed_times(process.native_header(), lhs, rhs)),
            own(erts_mixed_div(process.native_header(), lhs, rhs)),
            own(erts_band(process.native_header(), lhs, rhs)),
            own(erts_bor(process.native_header(), lhs, rhs)),
            own(erts_bxor(process.native_header(), lhs, rhs)),
            own(erts_bnot(process.native_header(), lhs)),
            own(erts_bsl(process.native_header(), lhs, rhs)),
            own(erts_bsr(process.native_header(), lhs, rhs)),
            own(erts_unary_minus(process.native_header(), lhs)),
        ];
        let mut quotient = 0;
        let mut remainder = 0;
        assert_eq!(
            erts_int_div_rem(
                process.native_header(),
                lhs,
                rhs,
                &mut quotient,
                &mut remainder,
            ),
            1
        );
        let mut product = 0;
        actual.push(own(erts_mul_add(
            process.native_header(),
            lhs,
            rhs,
            lhs,
            &mut product,
        )));

        let quotient = own(quotient);
        let remainder = own(remainder);
        let actual = arinsal_etf::OwnedTerm::List {
            elems: vec![
                actual.remove(0),
                actual.remove(0),
                actual.remove(0),
                actual.remove(0),
                quotient,
                remainder,
                actual.remove(0),
                actual.remove(0),
                actual.remove(0),
                actual.remove(0),
                actual.remove(0),
                actual.remove(0),
                actual.remove(0),
                actual.remove(0),
            ],
            tail: Box::new(arinsal_etf::OwnedTerm::Nil),
        };
        similar_asserts::assert_eq!(actual, expected);
    }

    #[test]
    fn fused_arithmetic_paths_match_otp_edge_cases() {
        use num_bigint::BigInt;

        let large_divisor = (BigInt::from(1) << 511usize) + BigInt::from(0x12345);
        let large_dividend = (BigInt::from(1) << 1024usize) + BigInt::from(0x98765);
        let padded_divisor = (BigInt::from(1) << 520usize) + BigInt::from(0xabcde);
        let padded_dividend = (BigInt::from(1) << 1600usize) + BigInt::from(0x54321);
        let cases = vec![
            (
                BigInt::from(arinsal_term::MIN_SMALL),
                BigInt::from(-1),
                BigInt::from(arinsal_term::MAX_SMALL),
            ),
            (
                -((BigInt::from(1) << 130usize) + BigInt::from(17)),
                (BigInt::from(1) << 65usize) + BigInt::from(3),
                -((BigInt::from(1) << 90usize) + BigInt::from(9)),
            ),
            (
                -large_dividend.clone(),
                large_divisor.clone(),
                &large_dividend * &large_divisor,
            ),
            (
                large_dividend.clone(),
                large_divisor.clone(),
                -(&large_dividend * &large_divisor),
            ),
            (
                padded_dividend.clone(),
                padded_divisor.clone(),
                -(&padded_dividend * &padded_divisor),
            ),
            (
                BigInt::from(-987_654_321),
                BigInt::from(987_654_321),
                BigInt::from(7),
            ),
            (
                (BigInt::from(1) << 300usize) + BigInt::from(33),
                (BigInt::from(1) << 301usize) + BigInt::from(5),
                BigInt::from(-11),
            ),
            (
                (BigInt::from(1) << 70usize) + BigInt::from(11),
                (BigInt::from(1) << 69usize) + BigInt::from(3),
                -((BigInt::from(1) << 139usize) + BigInt::from(33)),
            ),
        ];
        let expressions = cases
            .iter()
            .map(|(a, b, c)| format!("[{a} div {b},{a} rem {b},{a}*{b}+{c}]"))
            .collect::<Vec<_>>();
        let reference = arinsal_difftest::RefErl::start().expect("OTP 29.1.1 is required");
        let expected = reference
            .eval(&format!("[{}]", expressions.join(",")))
            .unwrap();

        let mut actual_cases = Vec::with_capacity(cases.len());
        for (a, b, c) in cases {
            let mut process = Process::new();
            let (a_term, b_term, c_term) = {
                let mut heap = crate::ProcessHeapHandle(&mut process.heap);
                let mut builder = arinsal_term::TermBuilder::new(&mut heap);
                (
                    builder.int_from_bigint(&a).unwrap(),
                    builder.int_from_bigint(&b).unwrap(),
                    builder.int_from_bigint(&c).unwrap(),
                )
            };
            let (a_raw, b_raw, c_raw) = (
                crate::native_hooks::raw(a_term),
                crate::native_hooks::raw(b_term),
                crate::native_hooks::raw(c_term),
            );
            let mut quotient = 0;
            let mut remainder = 0;
            similar_asserts::assert_eq!(
                erts_int_div_rem(
                    process.native_header(),
                    a_raw,
                    b_raw,
                    &mut quotient,
                    &mut remainder,
                ),
                1
            );
            if a == BigInt::from(arinsal_term::MIN_SMALL) && b == BigInt::from(-1) {
                assert!(
                    crate::native_hooks::from_raw(quotient)
                        .bignum_digit_count()
                        .is_some()
                );
            }
            let mut product = 0;
            let sum = erts_mul_add(process.native_header(), a_raw, b_raw, c_raw, &mut product);
            if a == BigInt::from(arinsal_term::MIN_SMALL) && b == BigInt::from(-1) {
                assert!(
                    crate::native_hooks::from_raw(sum)
                        .bignum_digit_count()
                        .is_some()
                );
            }
            actual_cases.push(arinsal_etf::OwnedTerm::List {
                elems: vec![
                    own_integer(quotient),
                    own_integer(remainder),
                    own_integer(sum),
                ],
                tail: Box::new(arinsal_etf::OwnedTerm::Nil),
            });
        }
        let actual = arinsal_etf::OwnedTerm::List {
            elems: actual_cases,
            tail: Box::new(arinsal_etf::OwnedTerm::Nil),
        };
        similar_asserts::assert_eq!(actual, expected);
    }

    fn own(bits: u64) -> arinsal_etf::OwnedTerm {
        arinsal_term::to_owned(crate::native_hooks::from_raw(bits)).unwrap()
    }

    fn own_integer(bits: u64) -> arinsal_etf::OwnedTerm {
        use num_traits::ToPrimitive;
        let value = own(bits);
        if let arinsal_etf::OwnedTerm::BigInt(value) = &value
            && let Some(integer) = value.to_i64()
        {
            return arinsal_etf::OwnedTerm::Int(integer);
        }
        value
    }
}
