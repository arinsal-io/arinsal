//! Arithmetic BIF adapters over `arinsal-arith`.

use arinsal_arith::{self, ArithError};
use arinsal_term::{Term, global_atoms};

use crate::{BifError, Ctx};

pub(super) fn lookup<V: crate::BifTableVisitor>(
    module: &str,
    name: &str,
    arity: u8,
    v: &mut V,
) -> Option<V::Output> {
    let f = match (module, name, arity) {
        ("erlang", "+", 2) => v.entry::<bodies::add>(),
        ("erlang", "-", 2) => v.entry::<bodies::sub>(),
        ("erlang", "*", 2) => v.entry::<bodies::mul>(),
        ("erlang", "/", 2) => v.entry::<bodies::fdiv>(),
        ("erlang", "div", 2) => v.entry::<bodies::int_div>(),
        ("erlang", "rem", 2) => v.entry::<bodies::rem>(),
        ("erlang", "band", 2) => v.entry::<bodies::band>(),
        ("erlang", "bor", 2) => v.entry::<bodies::bor>(),
        ("erlang", "bxor", 2) => v.entry::<bodies::bxor>(),
        ("erlang", "bsl", 2) => v.entry::<bodies::bsl>(),
        ("erlang", "bsr", 2) => v.entry::<bodies::bsr>(),
        ("erlang", "bnot", 1) => v.entry::<bodies::bnot>(),
        ("erlang", "-", 1) => v.entry::<bodies::neg>(),
        ("erlang", "+", 1) => v.entry::<bodies::plus>(),
        ("erlang", "abs", 1) => v.entry::<bodies::abs>(),
        ("erlang", "float", 1) => v.entry::<bodies::to_float>(),
        ("erlang", "trunc", 1) => v.entry::<bodies::trunc>(),
        ("erlang", "round", 1) => v.entry::<bodies::round>(),
        ("erlang", "ceil", 1) => v.entry::<bodies::ceil>(),
        ("erlang", "floor", 1) => v.entry::<bodies::floor>(),
        ("erlang", "integer_to_list", 1 | 2) => v.entry::<bodies::integer_to_list>(),
        ("erlang", "integer_to_binary", 1 | 2) => v.entry::<bodies::integer_to_binary>(),
        ("erts_internal", "list_to_integer", 2) => v.entry::<bodies::list_to_integer>(),
        ("erts_internal", "binary_to_integer", 2) => v.entry::<bodies::binary_to_integer>(),
        _ => return None,
    };
    arinsal_spec::bif_lookup(module, name, arity).map(|_| f)
}

fn map_error(error: ArithError) -> BifError {
    match error {
        ArithError::Badarith => BifError::Badarith,
        ArithError::Badarg => BifError::BADARG,
        ArithError::SystemLimit => BifError::SystemLimit,
        ArithError::HeapFull { .. } => panic!("infallible BIF heap returned HeapFull"),
    }
}

macro_rules! binary {
    ($($name:ident => $op:literal),+ $(,)?) => {$ (
        fn $name(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
            let charge = arinsal_arith::reduction_charge($op, args);
            let result = arinsal_arith::$name(args[0], args[1], ctx.heap).map_err(map_error);
            ctx.charge_reductions(charge as usize);
            result
        }
    )+ };
}
binary!(add => "+", sub => "-", mul => "*", fdiv => "/", int_div => "div", rem => "rem", band => "band", bor => "bor", bxor => "bxor", bsl => "bsl", bsr => "bsr");

macro_rules! unary {
    ($($name:ident => $op:literal),+ $(,)?) => {$ (
        fn $name(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
            let charge = arinsal_arith::reduction_charge($op, args);
            let result = arinsal_arith::$name(args[0], ctx.heap).map_err(map_error);
            ctx.charge_reductions(charge as usize);
            result
        }
    )+ };
}
unary!(bnot => "bnot", neg => "-", plus => "+", abs => "abs", to_float => "float", trunc => "trunc", round => "round", ceil => "ceil", floor => "floor");

fn integer_to_list(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    (if args.len() == 1 {
        arinsal_arith::integer_to_list_decimal(args[0], ctx.heap)
    } else {
        arinsal_arith::integer_to_list(args[0], args[1], ctx.heap)
    })
    .map_err(map_error)
}
fn integer_to_binary(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    (if args.len() == 1 {
        arinsal_arith::integer_to_binary_decimal(args[0], ctx.heap)
    } else {
        arinsal_arith::integer_to_binary(args[0], args[1], ctx.heap)
    })
    .map_err(map_error)
}
fn list_to_integer(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    // Port of erts/emulator/beam/big.c:4258 (erts_internal_list_to_integer_2), OTP-29.1.1.
    let mut cursor = args[0];
    if cursor == Term::NIL {
        return Ok(status("no_integer"));
    }
    if cons(cursor).is_none() {
        return Ok(status("not_a_list"));
    }
    let Some(base) = valid_base(args[1]) else {
        return Ok(status("badarg"));
    };
    let (first, _) = cons(cursor).unwrap();
    let negative = first.as_small() == Some(45);
    if negative || first.as_small() == Some(43) {
        cursor = cons(cursor).unwrap().1;
    }
    let mut zeros = 0;
    while let Some((head, tail)) = cons(cursor) {
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
        let Some((head, tail)) = cons(cursor) else {
            break;
        };
        let Some(digit) = head.as_small().and_then(|n| digit(n, base)) else {
            break;
        };
        value = value * base as i64 + digit as i64;
        digits += 1;
        cursor = tail;
    }
    if digits > limit {
        return Ok(status("big"));
    }
    if digits == 0 && zeros == 0 {
        return Ok(status("no_integer"));
    }
    let result = Term::small(if negative { -value } else { value }).expect("small parser limit");
    Ok(crate::pure::tuple_build(ctx, &[result, cursor]))
}
fn binary_to_integer(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    // Port of erts/emulator/beam/big.c:4231 (erts_internal_binary_to_integer_2), OTP-29.1.1.
    let Some(base) = valid_base(args[1]) else {
        return Ok(status("badarg"));
    };
    let Ok(bytes) = crate::pure::binary_bytes(args[0]) else {
        return Ok(status("badarg"));
    };
    if bytes.is_empty() {
        return Ok(status("badarg"));
    }
    let (negative, mut text) = match bytes[0] {
        b'-' => (true, &bytes[1..]),
        b'+' => (false, &bytes[1..]),
        _ => (false, bytes.as_slice()),
    };
    if text.is_empty() {
        return Ok(status("badarg"));
    }
    while text.first() == Some(&b'0') {
        text = &text[1..];
    }
    if text.is_empty() {
        return Ok(Term::small(0).unwrap());
    }
    if text.len() > DIGITS_PER_SMALL[(base - 2) as usize] {
        return Ok(status("big"));
    }
    let mut value = 0_i64;
    for &byte in text {
        let Some(d) = digit(byte as i64, base) else {
            return Ok(status("badarg"));
        };
        value = value * base as i64 + d as i64;
    }
    let value = if negative { -value } else { value };
    let _ = ctx;
    Ok(Term::small(value).expect("small parser limit"))
}

const DIGITS_PER_SMALL: [usize; 35] = [
    59, 37, 29, 25, 22, 21, 19, 18, 17, 17, 16, 15, 15, 15, 14, 14, 14, 13, 13, 13, 13, 13, 12, 12,
    12, 12, 12, 12, 12, 11, 11, 11, 11, 11, 11,
];
fn status(name: &str) -> Term {
    Term::atom(global_atoms().intern(name).expect("OTP status atom"))
}
fn valid_base(term: Term) -> Option<u32> {
    let base = term.as_small()?;
    (2..=36).contains(&base).then_some(base as u32)
}
fn digit(value: i64, base: u32) -> Option<u32> {
    let value = u8::try_from(value).ok()?;
    let digit = match value {
        b'0'..=b'9' => (value - b'0') as u32,
        b'A'..=b'Z' => (value - b'A' + 10) as u32,
        b'a'..=b'z' => (value - b'a' + 10) as u32,
        _ => return None,
    };
    (digit < base).then_some(digit)
}
fn cons(term: Term) -> Option<(Term, Term)> {
    // SAFETY: argument terms keep their owning heap live and stable during the BIF.
    unsafe { term.cons_ref() }
}

crate::bif_bodies!(
    add,
    sub,
    mul,
    fdiv,
    int_div,
    rem,
    band,
    bor,
    bxor,
    bsl,
    bsr,
    bnot,
    neg,
    plus,
    abs,
    to_float,
    trunc,
    round,
    ceil,
    floor,
    integer_to_list,
    integer_to_binary,
    list_to_integer,
    binary_to_integer,
);
