//! Arithmetic BIFs backed by the process heap.
//!
//! Port of erts/emulator/beam/erl_arith.c and big.c (arithmetic BIF bodies and integer parsers),
//! OTP-29.1.1. Each body uses `(c_p, reg, I)` and allocates through the active process heap.

use super::bif::bif_ret;
use arinsal_beamasm::ProcessHeader;
use arinsal_bifs::{BifCall, BifError, Ctx, ProcessHeapHandle};
use arinsal_term::{Term, TermBuilder, global_atoms};

fn arith_error(error: arinsal_arith::ArithError) -> BifError {
    match error {
        arinsal_arith::ArithError::Badarith => BifError::Badarith,
        arinsal_arith::ArithError::Badarg => BifError::BADARG,
        arinsal_arith::ArithError::SystemLimit => BifError::SystemLimit,
        _ => BifError::SystemLimit,
    }
}

#[allow(clippy::too_many_arguments)] // Carry the C ABI and BIF MFA to the shared error path.
fn finish(
    c_p: *mut ProcessHeader,
    reg: *mut u64,
    i: u64,
    process: &mut crate::Process,
    module: &'static str,
    function: &'static str,
    arity: usize,
    result: Result<Term, BifError>,
) -> u64 {
    match result {
        Ok(value) => crate::native_hooks::raw(value),
        Err(error) => {
            let args = crate::bif_table::bif_arg_vec(reg, arity);
            let error = crate::exceptions::bif_error(process, module, function, &args, error);
            bif_ret(c_p, i, Err(error))
        }
    }
}

fn run_arith(
    process: &mut crate::Process,
    operation: &'static str,
    args: &[Term],
) -> Result<Term, BifError> {
    let mut heap = ProcessHeapHandle(&mut process.heap);
    let mut call = BifCall::default();
    let mut ctx = Ctx::with_fcalls(&mut heap, &mut call);
    let (result, charge) = if operation == "*" {
        let (result, charge) = arinsal_arith::mul_with_charge(args[0], args[1], &mut ctx.heap);
        (result, charge)
    } else {
        (
            match operation {
                "+" => arinsal_arith::add(args[0], args[1], &mut ctx.heap),
                "-" if args.len() == 1 => arinsal_arith::neg(args[0], &mut ctx.heap),
                "-" => arinsal_arith::sub(args[0], args[1], &mut ctx.heap),
                "/" => arinsal_arith::fdiv(args[0], args[1], &mut ctx.heap),
                "div" => arinsal_arith::int_div(args[0], args[1], &mut ctx.heap),
                "rem" => arinsal_arith::rem(args[0], args[1], &mut ctx.heap),
                "band" => arinsal_arith::band(args[0], args[1], &mut ctx.heap),
                "bor" => arinsal_arith::bor(args[0], args[1], &mut ctx.heap),
                "bxor" => arinsal_arith::bxor(args[0], args[1], &mut ctx.heap),
                "bsl" => arinsal_arith::bsl(args[0], args[1], &mut ctx.heap),
                "bsr" => arinsal_arith::bsr(args[0], args[1], &mut ctx.heap),
                "bnot" => arinsal_arith::bnot(args[0], &mut ctx.heap),
                "+1" => arinsal_arith::plus(args[0], &mut ctx.heap),
                _ => unreachable!(),
            },
            arinsal_arith::reduction_charge(operation, args),
        )
    };
    ctx.charge_reductions(charge as usize);
    result.map_err(arith_error)
}

macro_rules! arithmetic_bif {
    ($name:ident, $function:literal, $arity:literal, $operation:literal, $source:literal) => {
        #[doc = concat!("`erlang:", $function, "/", stringify!($arity), "`.")]
        #[doc = concat!("Port of erts/emulator/beam/erl_arith.c (", $source, "), OTP-29.1.1.")]
        pub(crate) extern "C" fn $name(c_p: *mut ProcessHeader, reg: *mut u64, i: u64) -> u64 {
            let Some(process) = crate::native_hooks::process_from_header(c_p) else {
                return 0;
            };
            process.heap.note_bif_entry();
            let args = crate::bif_table::bif_args::<$arity>(reg);
            let result = run_arith(process, $operation, &args);
            finish(c_p, reg, i, process, "erlang", $function, $arity, result)
        }
    };
}

arithmetic_bif!(add_2, "+", 2, "+", "splus_2");
arithmetic_bif!(sub_2, "-", 2, "-", "sminus_2");
arithmetic_bif!(mul_2, "*", 2, "*", "stimes_2");
arithmetic_bif!(fdiv_2, "/", 2, "/", "div_2");
arithmetic_bif!(int_div_2, "div", 2, "div", "intdiv_2");
arithmetic_bif!(rem_2, "rem", 2, "rem", "rem_2");
arithmetic_bif!(band_2, "band", 2, "band", "band_2");
arithmetic_bif!(bor_2, "bor", 2, "bor", "bor_2");
arithmetic_bif!(bxor_2, "bxor", 2, "bxor", "bxor_2");
arithmetic_bif!(bsl_2, "bsl", 2, "bsl", "bsl_2");
arithmetic_bif!(bsr_2, "bsr", 2, "bsr", "bsr_2");
arithmetic_bif!(bnot_1, "bnot", 1, "bnot", "bnot_1");
arithmetic_bif!(neg_1, "-", 1, "-", "sminus_1");
arithmetic_bif!(plus_1, "+", 1, "+1", "splus_1");

fn integer_text_bif(
    c_p: *mut ProcessHeader,
    reg: *mut u64,
    i: u64,
    function: &'static str,
    arity: usize,
) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let args = crate::bif_table::bif_arg_vec(reg, arity);
    let result = {
        let mut heap = ProcessHeapHandle(&mut process.heap);
        if function == "integer_to_list" {
            if arity == 1 {
                arinsal_arith::integer_to_list_decimal(args[0], &mut heap)
            } else {
                arinsal_arith::integer_to_list(args[0], args[1], &mut heap)
            }
        } else if arity == 1 {
            arinsal_arith::integer_to_binary_decimal(args[0], &mut heap)
        } else {
            arinsal_arith::integer_to_binary(args[0], args[1], &mut heap)
        }
        .map_err(arith_error)
    };
    finish(c_p, reg, i, process, "erlang", function, arity, result)
}

/// `erlang:integer_to_list/1`.
// Port of erts/emulator/beam/bif.c (integer_to_list_1), OTP-29.1.1.
pub(crate) extern "C" fn integer_to_list_1(c_p: *mut ProcessHeader, reg: *mut u64, i: u64) -> u64 {
    integer_text_bif(c_p, reg, i, "integer_to_list", 1)
}

/// `erlang:integer_to_list/2`.
// Port of erts/emulator/beam/bif.c (integer_to_list_2), OTP-29.1.1.
pub(crate) extern "C" fn integer_to_list_2(c_p: *mut ProcessHeader, reg: *mut u64, i: u64) -> u64 {
    integer_text_bif(c_p, reg, i, "integer_to_list", 2)
}

/// `erlang:integer_to_binary/2`.
// Port of erts/emulator/beam/binary.c (integer_to_binary_2), OTP-29.1.1.
pub(crate) extern "C" fn integer_to_binary_2(
    c_p: *mut ProcessHeader,
    reg: *mut u64,
    i: u64,
) -> u64 {
    integer_text_bif(c_p, reg, i, "integer_to_binary", 2)
}

fn status(name: &'static str) -> Result<Term, BifError> {
    global_atoms()
        .intern(name)
        .map(Term::atom)
        .map_err(|_| BifError::SystemLimit)
}

fn valid_base(term: Term) -> Option<u32> {
    let base = term.as_small()?;
    (2..=36).contains(&base).then_some(base as u32)
}

fn digit(value: i64, base: u32) -> Option<u32> {
    let value = u8::try_from(value).ok()?;
    let digit = match value {
        b'0'..=b'9' => u32::from(value - b'0'),
        b'A'..=b'Z' => u32::from(value - b'A' + 10),
        b'a'..=b'z' => u32::from(value - b'a' + 10),
        _ => return None,
    };
    (digit < base).then_some(digit)
}

const DIGITS_PER_SMALL: [usize; 35] = [
    59, 37, 29, 25, 22, 21, 19, 18, 17, 17, 16, 15, 15, 15, 14, 14, 14, 13, 13, 13, 13, 13, 12, 12,
    12, 12, 12, 12, 12, 11, 11, 11, 11, 11, 11,
];

fn tuple_result(process: &mut crate::Process, value: Term, rest: Term) -> Result<Term, BifError> {
    let mut heap = ProcessHeapHandle(&mut process.heap);
    TermBuilder::new(&mut heap)
        .tuple(&[value, rest])
        .map_err(|_| BifError::SystemLimit)
}

/// `erts_internal:list_to_integer/2`.
// Port of erts/emulator/beam/big.c (erts_internal_list_to_integer_2), OTP-29.1.1.
pub(crate) extern "C" fn list_to_integer_2(c_p: *mut ProcessHeader, reg: *mut u64, i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let [cursor, base_term] = crate::bif_table::bif_args::<2>(reg);
    let result = if cursor == Term::NIL {
        status("no_integer")
    } else if arinsal_term::raw::Cons::try_from(cursor).is_err() {
        status("not_a_list")
    } else if let Some(base) = valid_base(base_term) {
        list_integer_result(process, cursor, base)
    } else {
        status("badarg")
    };
    match result {
        Ok(value) => crate::native_hooks::raw(value),
        Err(error) => finish(
            c_p,
            reg,
            i,
            process,
            "erts_internal",
            "list_to_integer",
            2,
            Err(error),
        ),
    }
}

fn list_integer_result(
    process: &mut crate::Process,
    mut cursor: Term,
    base: u32,
) -> Result<Term, BifError> {
    let (first, _) = arinsal_term::raw::Cons::try_from(cursor)
        .map_err(|_| BifError::BADARG)?
        .pair();
    let negative = first.as_small() == Some(45);
    if negative || first.as_small() == Some(43) {
        cursor = arinsal_term::raw::Cons::try_from(cursor)
            .map_err(|_| BifError::BADARG)?
            .pair()
            .1;
    }
    let mut zeros = 0;
    while let Ok(cons) = arinsal_term::raw::Cons::try_from(cursor) {
        let (head, tail) = cons.pair();
        if head.as_small() != Some(48) {
            break;
        }
        zeros += 1;
        cursor = tail;
    }
    let limit = DIGITS_PER_SMALL[(base - 2) as usize];
    let mut value = 0_i64;
    let mut digits = 0;
    while digits <= limit {
        let Ok(cons) = arinsal_term::raw::Cons::try_from(cursor) else {
            break;
        };
        let (head, tail) = cons.pair();
        let Some(digit) = head.as_small().and_then(|number| digit(number, base)) else {
            break;
        };
        value = value * i64::from(base) + i64::from(digit);
        digits += 1;
        cursor = tail;
    }
    if digits > limit {
        return status("big");
    }
    if digits == 0 && zeros == 0 {
        return status("no_integer");
    }
    let integer = Term::small(if negative { -value } else { value }).ok_or(BifError::BADARG)?;
    tuple_result(process, integer, cursor)
}

/// `erts_internal:binary_to_integer/2`.
// Port of erts/emulator/beam/big.c (erts_internal_binary_to_integer_2), OTP-29.1.1.
pub(crate) extern "C" fn binary_to_integer_2(
    c_p: *mut ProcessHeader,
    reg: *mut u64,
    i: u64,
) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let [input, base_term] = crate::bif_table::bif_args::<2>(reg);
    let result = if let Some(base) = valid_base(base_term) {
        parse_binary_integer(input, base)
    } else {
        status("badarg")
    };
    match result {
        Ok(value) => crate::native_hooks::raw(value),
        Err(error) => finish(
            c_p,
            reg,
            i,
            process,
            "erts_internal",
            "binary_to_integer",
            2,
            Err(error),
        ),
    }
}

fn parse_binary_integer(input: Term, base: u32) -> Result<Term, BifError> {
    let Some(view) = arinsal_term::raw::bif_arg_binary_ref(input) else {
        return status("badarg");
    };
    if !view.bit_len().is_multiple_of(8) {
        return status("badarg");
    }
    let len = view.bit_len() / 8;
    let start = view.start_bit();
    let bytes = if start.is_multiple_of(8) {
        let start = start / 8;
        &view.bytes()[start..start + len]
    } else {
        let mut aligned = vec![0; len];
        for (index, byte) in aligned.iter_mut().enumerate() {
            let bit = start + index * 8;
            let first = view.bytes()[bit / 8];
            let next = view.bytes().get(bit / 8 + 1).copied().unwrap_or(0);
            *byte = (first << (bit % 8)) | (next >> (8 - bit % 8));
        }
        return parse_binary_digits(&aligned, base);
    };
    parse_binary_digits(bytes, base)
}

fn parse_binary_digits(bytes: &[u8], base: u32) -> Result<Term, BifError> {
    if bytes.is_empty() {
        return status("badarg");
    }
    let (negative, mut text) = match bytes[0] {
        b'-' => (true, &bytes[1..]),
        b'+' => (false, &bytes[1..]),
        _ => (false, bytes),
    };
    if text.is_empty() {
        return status("badarg");
    }
    while text.first() == Some(&b'0') {
        text = &text[1..];
    }
    if text.is_empty() {
        return Ok(Term::small(0).expect("zero is a small integer"));
    }
    if text.len() > DIGITS_PER_SMALL[(base - 2) as usize] {
        return status("big");
    }
    let mut value = 0_i64;
    for &byte in text {
        let Some(digit) = digit(i64::from(byte), base) else {
            return status("badarg");
        };
        value = value * i64::from(base) + i64::from(digit);
    }
    let value = if negative { -value } else { value };
    Ok(Term::small(value).expect("parser limit fits a small integer"))
}
