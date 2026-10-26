//! Character conversion BIFs and the encoding paths delegated to `unicode.erl`.

use std::borrow::Cow;

use arinsal_etf::OwnedTerm;
use arinsal_term::{Term, TermBuilder, TermKind, global_atoms};
use smallvec::SmallVec;

use crate::lists::DeferredTrap;
use crate::pure::{Heap, bool_term, tuple_build};
use crate::{BifError, Ctx};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Encoding {
    Latin1,
    Utf8,
    Utf16Be,
    Utf16Le,
    Utf32Be,
    Utf32Le,
}

pub(super) fn lookup<V: crate::BifTableVisitor>(
    module: &str,
    name: &str,
    arity: u8,
    v: &mut V,
) -> Option<V::Output> {
    let f = match (module, name, arity) {
        ("unicode", "characters_to_binary", 2) => v.entry::<word_bodies::characters_to_binary>(),
        ("unicode", "characters_to_list", 2) => v.entry::<word_bodies::characters_to_list>(),
        ("prim_file", "internal_name2native", 1) => v.entry::<word_bodies::internal_name2native>(),
        ("prim_file", "internal_native2name", 1) => v.entry::<word_bodies::internal_native2name>(),
        ("prim_file", "internal_normalize_utf8", 1) => {
            v.entry::<word_bodies::internal_normalize_utf8>()
        }
        ("prim_file", "is_translatable", 1) => v.entry::<word_bodies::is_translatable>(),
        ("file", "native_name_encoding", 0) => v.entry::<word_bodies::native_name_encoding>(),
        ("io", "printable_range", 0) => v.entry::<word_bodies::printable_range>(),
        _ => return None,
    };
    arinsal_spec::bif_lookup(module, name, arity).map(|_| f)
}

fn atom_name(term: Term) -> Option<String> {
    global_atoms()
        .text(term.as_atom()?)
        .map(|name| name.to_string())
}

fn encoding(term: Term) -> Result<Encoding, BifError> {
    if let Some(name) = term.as_atom().and_then(|atom| global_atoms().text(atom)) {
        return match name {
            "latin1" => Ok(Encoding::Latin1),
            "unicode" | "utf8" => Ok(Encoding::Utf8),
            "utf16" => Ok(Encoding::Utf16Be),
            "utf32" => Ok(Encoding::Utf32Be),
            _ => Err(BifError::BADARG),
        };
    }
    // SAFETY: The BIF argument heap remains live for this call.
    let pair = unsafe { term.tuple_ref() }.ok_or(BifError::BADARG)?;
    if pair.len() != 2 {
        return Err(BifError::BADARG);
    }
    match (
        atom_name(pair.get(0).unwrap()),
        atom_name(pair.get(1).unwrap()),
    ) {
        (Some(family), Some(endian)) => match (family.as_str(), endian.as_str()) {
            ("utf16", "big") => Ok(Encoding::Utf16Be),
            ("utf16", "little") => Ok(Encoding::Utf16Le),
            ("utf32", "big") => Ok(Encoding::Utf32Be),
            ("utf32", "little") => Ok(Encoding::Utf32Le),
            _ => Err(BifError::BADARG),
        },
        _ => Err(BifError::BADARG),
    }
}

fn bytes<'a>(term: Term) -> Result<Cow<'a, [u8]>, BifError> {
    // SAFETY: The argument heap and retained binary owner remain live during the BIF.
    let view = unsafe { term.binary_ref() }.ok_or(BifError::BADARG)?;
    if view.bit_len() % 8 != 0 {
        return Err(BifError::BADARG);
    }
    let start = view.start_bit() / 8;
    let len = view.bit_len() / 8;
    if view.start_bit().is_multiple_of(8) {
        // SAFETY: BinaryRef's checked bit range is inside its live backing bytes.
        Ok(Cow::Borrowed(unsafe {
            std::slice::from_raw_parts(view.bytes().as_ptr().add(start), len)
        }))
    } else {
        let shift = view.start_bit() % 8;
        let mut aligned = Vec::with_capacity(len);
        for i in 0..len {
            aligned.push(
                (view.bytes()[start + i] << shift) | (view.bytes()[start + i + 1] >> (8 - shift)),
            );
        }
        Ok(Cow::Owned(aligned))
    }
}

fn binary(ctx: &mut Ctx<'_>, data: &[u8]) -> Term {
    TermBuilder::new(&mut Heap(&mut ctx.heap))
        .binary(data)
        .expect("infallible BIF heap")
}

fn cons(ctx: &mut Ctx<'_>, head: Term, tail: Term) -> Term {
    TermBuilder::new(&mut Heap(&mut ctx.heap))
        .cons(head, tail)
        .expect("infallible BIF heap")
}

fn atom(name: &str) -> Term {
    Term::atom(global_atoms().intern(name).expect("OTP atom"))
}

// Port of erts/emulator/beam/erl_unicode.c:342 (utf8_need), OTP-29.1.1.
// The size pass rejects malformed structure before the conversion pass. A big
// integer stops this pass so the converter can return an error tuple for it.
struct Utf8Need {
    bytes: usize,
    cost: usize,
}

// Port of erts/emulator/beam/erl_unicode.c:313-340
// (latin1_binary_need, aligned_binary_size), OTP-29.1.1.
fn binary_need(term: Term, encoding: Encoding) -> Result<usize, BifError> {
    if encoding == Encoding::Latin1 {
        Ok(bytes(term)?
            .iter()
            .map(|b| if *b < 128 { 1 } else { 2 })
            .sum())
    } else {
        let bits = crate::bitstring_bit_len(term)?;
        if !bits.is_multiple_of(8) {
            return Err(BifError::BADARG);
        }
        Ok(bits / 8)
    }
}

fn check_structure(root: Term, encoding: Encoding) -> Result<Utf8Need, BifError> {
    if root != Term::NIL && !matches!(root.classify(), TermKind::List | TermKind::Bitstring) {
        return Err(BifError::BADARG);
    }
    let mut need = 0_usize;
    let mut cost = 0;
    let mut stack = SmallVec::<[Term; 8]>::new();
    let mut current = root;
    loop {
        match current.classify() {
            TermKind::Nil => {
                if let Some(next) = stack.pop() {
                    current = next;
                } else {
                    break;
                }
            }
            TermKind::List => {
                // SAFETY: The argument heap is live for this BIF call.
                let (head, tail) = unsafe { current.cons_ref() }.ok_or(BifError::BADARG)?;
                match head.classify() {
                    TermKind::Nil => current = tail,
                    TermKind::List => {
                        stack.push(tail);
                        current = head;
                    }
                    TermKind::Bitstring => {
                        let amount = binary_need(head, encoding)?;
                        need += amount;
                        cost += if encoding == Encoding::Latin1 {
                            amount
                        } else {
                            1
                        };
                        current = tail;
                    }
                    TermKind::Number if head.as_small().is_some() => {
                        let cp = head.as_small().unwrap() as u64;
                        cost += 1;
                        need += if cp < 0x80 {
                            1
                        } else if cp < 0x800 {
                            2
                        } else if cp < 0x10000 {
                            3
                        } else {
                            4
                        };
                        current = tail;
                    }
                    TermKind::Number => match arinsal_term::to_owned(head) {
                        Ok(OwnedTerm::BigInt(_)) => return Ok(Utf8Need { bytes: need, cost }),
                        _ => return Err(BifError::BADARG),
                    },
                    _ => return Err(BifError::BADARG),
                }
            }
            TermKind::Bitstring => {
                let amount = binary_need(current, encoding)?;
                need += amount;
                cost += if encoding == Encoding::Latin1 {
                    amount
                } else {
                    1
                };
                current = Term::NIL;
            }
            _ => return Err(BifError::BADARG),
        }
    }
    Ok(Utf8Need { bytes: need, cost })
}

#[derive(Clone, Copy)]
enum Decode {
    Scalar(u32, usize),
    Need,
    Invalid,
}

fn decode(data: &[u8], encoding: Encoding) -> Decode {
    let Some(&first) = data.first() else {
        return Decode::Need;
    };
    match encoding {
        Encoding::Latin1 => Decode::Scalar(u32::from(first), 1),
        Encoding::Utf8 => {
            if first < 0x80 {
                return Decode::Scalar(u32::from(first), 1);
            }
            let width = match first {
                0xc0..=0xdf => 2,
                0xe0..=0xef => 3,
                0xf0..=0xf7 => 4,
                _ => return Decode::Invalid,
            };
            if data.len() < width {
                // OTP defers validation of a truncated sequence to its
                // leftover check, even if an available continuation is bad.
                return Decode::Need;
            }
            let slice = &data[..width];
            match std::str::from_utf8(slice) {
                Ok(s) => Decode::Scalar(s.chars().next().unwrap() as u32, width),
                Err(_) => Decode::Invalid,
            }
        }
        Encoding::Utf16Be | Encoding::Utf16Le => {
            if data.len() < 2 {
                return Decode::Need;
            }
            let first = if encoding == Encoding::Utf16Be {
                u16::from_be_bytes([data[0], data[1]])
            } else {
                u16::from_le_bytes([data[0], data[1]])
            };
            match first {
                0xdc00..=0xdfff => Decode::Invalid,
                0xd800..=0xdbff => {
                    if data.len() < 4 {
                        return Decode::Need;
                    }
                    let second = if encoding == Encoding::Utf16Be {
                        u16::from_be_bytes([data[2], data[3]])
                    } else {
                        u16::from_le_bytes([data[2], data[3]])
                    };
                    if !(0xdc00..=0xdfff).contains(&second) {
                        return Decode::Invalid;
                    }
                    Decode::Scalar(
                        0x10000 + (u32::from(first - 0xd800) << 10) + u32::from(second - 0xdc00),
                        4,
                    )
                }
                _ => Decode::Scalar(u32::from(first), 2),
            }
        }
        Encoding::Utf32Be | Encoding::Utf32Le => {
            if data.len() < 4 {
                return Decode::Need;
            }
            let cp = if encoding == Encoding::Utf32Be {
                u32::from_be_bytes(data[..4].try_into().unwrap())
            } else {
                u32::from_le_bytes(data[..4].try_into().unwrap())
            };
            if valid_cp(cp) {
                Decode::Scalar(cp, 4)
            } else {
                Decode::Invalid
            }
        }
    }
}

fn valid_cp(cp: u32) -> bool {
    cp <= 0x10ffff && !(0xd800..=0xdfff).contains(&cp)
}

// Port of erts/emulator/beam/erl_unicode.c:751 (check_leftovers), OTP-29.1.1.
fn valid_incomplete_utf8(bytes: &[u8]) -> bool {
    match bytes {
        [0xc0..=0xdf] => true,
        [0xe0..=0xef] => true,
        [0xf0..=0xf7] => true,
        [0xe0..=0xef, second] | [0xf0..=0xf7, second] => second & 0xc0 == 0x80,
        [0xf0..=0xf7, second, third] => second & 0xc0 == 0x80 && third & 0xc0 == 0x80,
        _ => false,
    }
}

enum Output {
    Binary(Vec<u8>),
    List(Vec<u32>),
}

impl Output {
    fn push(&mut self, cp: u32) {
        match self {
            Self::Binary(bytes) => {
                let mut buffer = [0; 4];
                bytes.extend_from_slice(
                    char::from_u32(cp)
                        .unwrap()
                        .encode_utf8(&mut buffer)
                        .as_bytes(),
                );
            }
            Self::List(points) => points.push(cp),
        }
    }
    fn term(self, ctx: &mut Ctx<'_>) -> Term {
        match self {
            Self::Binary(bytes) => binary(ctx, &bytes),
            Self::List(points) => {
                let mut heap = Heap(&mut ctx.heap);
                let mut builder = TermBuilder::new(&mut heap);
                let mut tail = Term::NIL;
                for cp in points.into_iter().rev() {
                    tail = builder
                        .cons(Term::small(i64::from(cp)).unwrap(), tail)
                        .expect("infallible BIF heap");
                }
                tail
            }
        }
    }
}

fn wrap(ctx: &mut Ctx<'_>, mut rest: Term, ancestors: &[Term]) -> Term {
    for &tail in ancestors.iter().rev() {
        rest = cons(ctx, rest, tail);
    }
    rest
}

fn make_failure(ctx: &mut Ctx<'_>, output: Output, tag: &str, rest: Term) -> Term {
    let converted = output.term(ctx);
    tuple_build(ctx, &[atom(tag), converted, rest])
}

enum BinaryResult {
    Done,
    Error(Vec<u8>),
    Incomplete(Vec<u8>, usize),
}

// Port of lib/stdlib/src/unicode.erl:931 (cbv), OTP-29.1.1.
fn missing_bytes(encoding: Encoding, bytes: &[u8]) -> Option<usize> {
    match encoding {
        Encoding::Latin1 => None,
        Encoding::Utf8 => match bytes {
            [0xc0..=0xdf] => Some(1),
            [0xe0..=0xef] => Some(2),
            [0xe0..=0xef, b] if b & 0xc0 == 0x80 => Some(1),
            [0xf0..=0xf7] => Some(3),
            [0xf0..=0xf7, b] if b & 0xc0 == 0x80 => Some(2),
            [0xf0..=0xf7, b, c] if b & 0xc0 == 0x80 && c & 0xc0 == 0x80 => Some(1),
            _ => None,
        },
        Encoding::Utf16Be => match bytes {
            [a] if *a <= 0xd7 || *a >= 0xe0 => Some(1),
            [0xd8..=0xdb] => Some(3),
            [0xd8..=0xdb, _] => Some(2),
            [0xd8..=0xdb, _, 0xdc..=0xdf] => Some(1),
            _ => None,
        },
        Encoding::Utf16Le => match bytes {
            [_] => Some(1),
            [_, 0xd8..=0xdb] => Some(2),
            [_, 0xd8..=0xdb, _] => Some(1),
            _ => None,
        },
        Encoding::Utf32Be => match bytes {
            [0] => Some(3),
            [0, 0..=16] => Some(2),
            [0, x @ 0..=16, y] if *x > 0 || *y < 0xd8 || *y >= 0xe0 => Some(1),
            _ => None,
        },
        Encoding::Utf32Le => match bytes {
            [_] => Some(3),
            [_, _] => Some(2),
            [0xfe | 0xff, 0xff, 0] => None,
            [_, y, x @ 0..=16] if *x > 0 || *y < 0xd8 || *y >= 0xe0 => Some(1),
            _ => None,
        },
    }
}

fn decode_binary_part(data: &[u8], encoding: Encoding, points: &mut Vec<u32>) -> BinaryResult {
    let mut pos = 0;
    while pos < data.len() {
        match decode(&data[pos..], encoding) {
            Decode::Scalar(cp, width) => {
                points.push(cp);
                pos += width;
            }
            Decode::Invalid => return BinaryResult::Error(data[pos..].to_vec()),
            Decode::Need => {
                let rest = &data[pos..];
                return match missing_bytes(encoding, rest) {
                    Some(missing) => BinaryResult::Incomplete(rest.to_vec(), missing),
                    None => BinaryResult::Error(rest.to_vec()),
                };
            }
        }
    }
    BinaryResult::Done
}

enum MapResult {
    Done,
    Error(Term),
}

struct MapState {
    points: Vec<u32>,
    pending: Option<(Vec<u8>, usize)>,
}

// Port of lib/stdlib/src/unicode.erl:998 (ml_map), OTP-29.1.1.
fn map_chardata(
    ctx: &mut Ctx<'_>,
    mut current: Term,
    encoding: Encoding,
    state: &mut MapState,
) -> Result<MapResult, BifError> {
    loop {
        match current.classify() {
            TermKind::Nil => return Ok(MapResult::Done),
            TermKind::List => {
                // SAFETY: The source heap is live for the BIF call.
                let (head, tail) = unsafe { current.cons_ref() }.ok_or(BifError::BADARG)?;
                match head.classify() {
                    TermKind::Number => {
                        if matches!(arinsal_term::to_owned(head), Ok(OwnedTerm::Float(_))) {
                            return Err(BifError::BADARG);
                        }
                        if let Some((incomplete, _)) = state.pending.take() {
                            let prefix = binary(ctx, &incomplete);
                            return Ok(MapResult::Error(cons(ctx, prefix, current)));
                        }
                        let cp = head.as_small().and_then(|n| u32::try_from(n).ok());
                        if let Some(cp) = cp.filter(|&cp| {
                            valid_cp(cp) && (encoding != Encoding::Latin1 || cp <= 255)
                        }) {
                            state.points.push(cp);
                        } else {
                            let singleton = cons(ctx, head, Term::NIL);
                            return Ok(MapResult::Error(cons(ctx, singleton, tail)));
                        }
                    }
                    TermKind::Bitstring => {
                        let (error, consumed_tail) =
                            map_binary_head(ctx, head, tail, encoding, state)?;
                        if let Some(error) = error {
                            return Ok(MapResult::Error(error));
                        }
                        if consumed_tail {
                            return Ok(MapResult::Done);
                        }
                    }
                    TermKind::List | TermKind::Nil => {
                        if let MapResult::Error(rest) = map_chardata(ctx, head, encoding, state)? {
                            return Ok(MapResult::Error(cons(ctx, rest, tail)));
                        }
                    }
                    _ => return Err(BifError::BADARG),
                }
                current = tail;
            }
            TermKind::Bitstring => {
                let data = bytes(current)?;
                if let Some((incomplete, missing)) = state.pending.take() {
                    if data.len() < missing {
                        let mut combined = incomplete;
                        combined.extend_from_slice(&data);
                        state.pending = Some((combined, missing - data.len()));
                        return Ok(MapResult::Done);
                    }
                    let first = binary(ctx, &incomplete);
                    let suffix = cons(ctx, current, Term::NIL);
                    let synthetic = cons(ctx, first, suffix);
                    return map_chardata(ctx, synthetic, encoding, state);
                }
                if data.len() > 8192 {
                    let first = binary(ctx, &data[..8192]);
                    let trailing = binary(ctx, &data[8192..]);
                    let suffix = cons(ctx, trailing, Term::NIL);
                    let synthetic = cons(ctx, first, suffix);
                    return map_chardata(ctx, synthetic, encoding, state);
                }
                match decode_binary_part(&data, encoding, &mut state.points) {
                    BinaryResult::Done => return Ok(MapResult::Done),
                    BinaryResult::Error(rest) => return Ok(MapResult::Error(binary(ctx, &rest))),
                    BinaryResult::Incomplete(rest, missing) => {
                        state.pending = Some((rest, missing));
                        return Ok(MapResult::Done);
                    }
                }
            }
            _ => return Err(BifError::BADARG),
        }
    }
}

fn map_binary_head(
    ctx: &mut Ctx<'_>,
    term: Term,
    tail: Term,
    encoding: Encoding,
    state: &mut MapState,
) -> Result<(Option<Term>, bool), BifError> {
    let data = bytes(term)?;
    if let Some((incomplete, missing)) = state.pending.take() {
        if data.len() < missing {
            let mut combined = incomplete;
            combined.extend_from_slice(&data);
            state.pending = Some((combined, missing - data.len()));
            return Ok((None, false));
        }
        let mut combined = incomplete;
        combined.extend_from_slice(&data[..missing]);
        let first = binary(ctx, &combined);
        let trailing = binary(ctx, &data[missing..]);
        let suffix = cons(ctx, trailing, tail);
        let synthetic = cons(ctx, first, suffix);
        return match map_chardata(ctx, synthetic, encoding, state)? {
            MapResult::Done => Ok((None, true)),
            MapResult::Error(rest) => Ok((Some(rest), true)),
        };
    }
    if data.len() > 8192 {
        let first = binary(ctx, &data[..8192]);
        let trailing = binary(ctx, &data[8192..]);
        let suffix = cons(ctx, trailing, tail);
        let synthetic = cons(ctx, first, suffix);
        return match map_chardata(ctx, synthetic, encoding, state)? {
            MapResult::Done => Ok((None, true)),
            MapResult::Error(rest) => Ok((Some(rest), true)),
        };
    }
    match decode_binary_part(&data, encoding, &mut state.points) {
        BinaryResult::Done => Ok((None, false)),
        BinaryResult::Error(rest) => {
            let rest = binary(ctx, &rest);
            Ok((Some(cons(ctx, rest, tail)), false))
        }
        BinaryResult::Incomplete(rest, missing) => {
            state.pending = Some((rest, missing));
            Ok((None, false))
        }
    }
}

fn wrapper_convert(
    ctx: &mut Ctx<'_>,
    args: &[Term],
    list_output: bool,
    encoding: Encoding,
) -> Result<Term, BifError> {
    let mut state = MapState {
        points: Vec::new(),
        pending: None,
    };
    let result = map_chardata(ctx, args[0], encoding, &mut state)?;
    let output = if list_output {
        Output::List(state.points)
    } else {
        let mut bytes = Vec::new();
        for cp in state.points {
            let mut buf = [0; 4];
            bytes.extend_from_slice(char::from_u32(cp).unwrap().encode_utf8(&mut buf).as_bytes());
        }
        Output::Binary(bytes)
    };
    match result {
        MapResult::Error(rest) => Ok(make_failure(ctx, output, "error", rest)),
        MapResult::Done => {
            if let Some((rest, _)) = state.pending {
                let rest = binary(ctx, &rest);
                Ok(make_failure(ctx, output, "incomplete", rest))
            } else {
                Ok(output.term(ctx))
            }
        }
    }
}

// Port of erts/emulator/beam/erl_unicode.c:508 (do_build_utf8), OTP-29.1.1.
// The explicit stack makes a future scheduler work budget straightforward.
fn convert(ctx: &mut Ctx<'_>, args: &[Term], list_output: bool) -> Result<Term, BifError> {
    let encoding = encoding(args[1])?;
    let direct = matches!(encoding, Encoding::Latin1 | Encoding::Utf8);
    if !direct {
        return wrapper_convert(ctx, args, list_output, encoding);
    }
    let mut root = args[0];
    let need = {
        if !list_output && root.classify() == TermKind::List {
            // SAFETY: The argument heap is live for this BIF call.
            if let Some((head, tail)) = unsafe { root.cons_ref() }
                && tail == Term::NIL
                && head.classify() == TermKind::Bitstring
            {
                root = head;
            }
        }
        check_structure(root, encoding)?.bytes
    };
    let mut output = if list_output {
        Output::List(Vec::with_capacity(need))
    } else {
        Output::Binary(Vec::with_capacity(need))
    };
    let mut ancestors = Vec::<Term>::new();
    let mut current = root;
    let mut leftover = Vec::<u8>::new();
    loop {
        match current.classify() {
            TermKind::Nil => {
                if let Some(next) = ancestors.pop() {
                    current = next;
                } else {
                    break;
                }
            }
            TermKind::List => {
                // SAFETY: The argument heap is live for this BIF call.
                let (head, tail) = unsafe { current.cons_ref() }.ok_or(BifError::BADARG)?;
                if head.classify() == TermKind::List {
                    ancestors.push(tail);
                    current = head;
                    continue;
                }
                if head == Term::NIL {
                    current = tail;
                    continue;
                }
                if head.classify() == TermKind::Bitstring {
                    if let Some(rest) = process_binary(
                        ctx,
                        head,
                        Some(tail),
                        &ancestors,
                        encoding,
                        &mut leftover,
                        &mut output,
                    )? {
                        return Ok(rest);
                    }
                } else if head.classify() == TermKind::Number && !leftover.is_empty() {
                    let prior = binary(ctx, &leftover);
                    let rest = wrap(ctx, current, &ancestors);
                    let rest = cons(ctx, rest, Term::NIL);
                    let rest = cons(ctx, prior, rest);
                    return Ok(make_failure(ctx, output, "error", rest));
                } else if let Some(cp) = head.as_small().and_then(|n| u32::try_from(n).ok()) {
                    if !valid_cp(cp) || (encoding == Encoding::Latin1 && cp > 255) {
                        let rest = wrap(ctx, current, &ancestors);
                        return Ok(make_failure(ctx, output, "error", rest));
                    }
                    output.push(cp);
                } else if head.classify() == TermKind::Number {
                    let rest = wrap(ctx, current, &ancestors);
                    return Ok(make_failure(ctx, output, "error", rest));
                } else {
                    return Err(BifError::BADARG);
                }
                current = tail;
            }
            TermKind::Bitstring => {
                if let Some(rest) = process_binary(
                    ctx,
                    current,
                    None,
                    &ancestors,
                    encoding,
                    &mut leftover,
                    &mut output,
                )? {
                    return Ok(rest);
                }
                current = Term::NIL;
            }
            _ => return Err(BifError::BADARG),
        }
    }
    if !leftover.is_empty() {
        let rest = binary(ctx, &leftover);
        let tag = if encoding == Encoding::Utf8 && !valid_incomplete_utf8(&leftover) {
            "error"
        } else {
            "incomplete"
        };
        return Ok(make_failure(ctx, output, tag, rest));
    }
    Ok(output.term(ctx))
}

fn process_binary(
    ctx: &mut Ctx<'_>,
    term: Term,
    tail: Option<Term>,
    ancestors: &[Term],
    encoding: Encoding,
    leftover: &mut Vec<u8>,
    output: &mut Output,
) -> Result<Option<Term>, BifError> {
    let data = bytes(term)?;
    let mut pos = 0;
    if !leftover.is_empty() {
        let needed = match leftover[0] {
            0xc0..=0xdf => 2,
            0xe0..=0xef => 3,
            0xf0..=0xf7 => 4,
            _ => unreachable!(),
        };
        let take = (needed - leftover.len()).min(data.len());
        leftover.extend_from_slice(&data[..take]);
        if leftover.len() < needed {
            return Ok(None);
        }
        match decode(leftover, encoding) {
            Decode::Scalar(cp, _) => output.push(cp),
            _ => {
                let previous = binary(ctx, &leftover[..leftover.len() - take]);
                let rest = if let Some(tail) = tail {
                    cons(ctx, term, tail)
                } else {
                    term
                };
                let rest = wrap(ctx, rest, ancestors);
                let rest = cons(ctx, rest, Term::NIL);
                let rest = cons(ctx, previous, rest);
                return Ok(Some(make_failure(
                    ctx,
                    std::mem::replace(output, Output::Binary(Vec::new())),
                    "error",
                    rest,
                )));
            }
        }
        leftover.clear();
        pos = take;
    }
    while pos < data.len() {
        match decode(&data[pos..], encoding) {
            Decode::Scalar(cp, size) => {
                output.push(cp);
                pos += size;
            }
            Decode::Need => {
                leftover.extend_from_slice(&data[pos..]);
                break;
            }
            Decode::Invalid => {
                let suffix = if pos == 0 {
                    term
                } else {
                    binary(ctx, &data[pos..])
                };
                let rest = if let Some(tail) = tail {
                    cons(ctx, suffix, tail)
                } else {
                    suffix
                };
                let rest = wrap(ctx, rest, ancestors);
                let old = std::mem::replace(output, Output::Binary(Vec::new()));
                return Ok(Some(make_failure(ctx, old, "error", rest)));
            }
        }
    }
    Ok(None)
}

fn characters_to_binary(ctx: &mut Ctx<'_>, args: &[Term]) -> Term {
    match characters_to_binary_result(ctx, args) {
        Ok(_) if ctx.has_deferred() => match *ctx.take_deferred().expect("deferred Unicode trap") {
            DeferredTrap::Unicode(cont) => ctx.trap(DeferredTrap::Unicode(cont)),
            _ => unreachable!("Unicode conversion only defers Unicode traps"),
        },
        Ok(value) => value,
        Err(error) => ctx.fail(error),
    }
}

fn characters_to_binary_result(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    if let Some(binary) = unicode_utf8_binary_fast_path(args)? {
        return Ok(binary);
    }
    let encoding = encoding(args[1])?;
    if matches!(encoding, Encoding::Latin1 | Encoding::Utf8) {
        return characters_to_utf8(ctx, args[0], encoding);
    }
    convert_charged(ctx, args, false)
}

/// The local estack and cursors of one `do_build_utf8` invocation.
struct BinaryBuild {
    current: Term,
    ancestors: SmallVec<[Term; 8]>,
    source_rest: Option<(Term, usize, Option<Term>)>,
    leftover: SmallVec<[u8; 4]>,
    pos: usize,
    encoding: Encoding,
    error: bool,
}

impl BinaryBuild {
    fn new(root: Term, pos: usize, encoding: Encoding) -> Self {
        Self {
            current: root,
            ancestors: SmallVec::new(),
            source_rest: None,
            leftover: SmallVec::new(),
            pos,
            encoding,
            error: false,
        }
    }

    fn append(&mut self, output: &mut [u8], bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        output[self.pos..self.pos + bytes.len()].copy_from_slice(bytes);
        self.pos += bytes.len();
    }

    // Port of erts/emulator/beam/erl_unicode.c:508-750 (do_build_utf8), OTP-29.1.1.
    fn fill(&mut self, output: &mut [u8], left: &mut i64) {
        while *left > 0 && !self.error {
            if let Some((head, tail)) = crate::lists::cons_cell(self.current) {
                if let Some(number) = head.as_small() {
                    let cp = number as u64;
                    if !self.leftover.is_empty()
                        || cp >= 0x110000
                        || (0xd800..=0xdfff).contains(&cp)
                        || self.encoding == Encoding::Latin1 && cp > 255
                    {
                        self.error = true;
                        return;
                    }
                    let mut encoded = [0; 4];
                    self.append(
                        output,
                        char::from_u32(cp as u32)
                            .unwrap()
                            .encode_utf8(&mut encoded)
                            .as_bytes(),
                    );
                    *left -= 1;
                    self.current = tail;
                } else if head == Term::NIL {
                    self.current = tail;
                } else if head.classify() == TermKind::List {
                    self.ancestors.push(tail);
                    self.current = head;
                } else if head.classify() == TermKind::Bitstring {
                    self.fill_binary(head, Some(tail), output, left);
                } else {
                    self.error = true;
                }
            } else if self.current == Term::NIL {
                if let Some(tail) = self.ancestors.pop() {
                    self.current = tail;
                } else {
                    return;
                }
            } else if self.current.classify() == TermKind::Bitstring {
                self.fill_binary(self.current, None, output, left);
            } else {
                self.error = true;
            }
            if self.source_rest.is_some() {
                return;
            }
        }
    }

    // Port of erts/emulator/beam/erl_unicode.c:508-605 (do_build_utf8 binary branch)
    // and :181-297 (copy_utf8_bin), OTP-29.1.1.
    fn fill_binary(&mut self, term: Term, tail: Option<Term>, output: &mut [u8], left: &mut i64) {
        let data = bytes(term).expect("utf8_need checked the binary alignment");
        let mut size = data.len().min(*left as usize);
        if self.encoding == Encoding::Utf8 {
            while size < data.len() && data[size] & 0xc0 == 0x80 {
                size += 1;
            }
        }
        let mut offset = 0;
        if self.encoding == Encoding::Latin1 {
            for byte in &data[..size] {
                if *byte < 128 {
                    self.append(output, &[*byte]);
                } else {
                    self.append(output, &[0xc0 | (*byte >> 6), 0x80 | (*byte & 0x3f)]);
                }
            }
        } else {
            if !self.leftover.is_empty() {
                let width = match self.leftover[0] {
                    0xc0..=0xdf => 2,
                    0xe0..=0xef => 3,
                    _ => 4,
                };
                let previous = self.leftover.len();
                let take = (width - previous).min(size);
                self.leftover.extend_from_slice(&data[..take]);
                if self.leftover.len() == width {
                    if matches!(decode(&self.leftover, Encoding::Utf8), Decode::Scalar(..)) {
                        let mut complete = [0; 4];
                        complete[..width].copy_from_slice(&self.leftover);
                        self.append(output, &complete[..width]);
                        self.leftover.clear();
                        offset = take;
                    } else {
                        self.leftover.truncate(previous);
                        self.source_rest = Some((term, 0, tail));
                        self.error = true;
                        return;
                    }
                } else {
                    offset = size;
                }
            }
            let start = offset;
            while offset < size {
                match decode(&data[offset..size], Encoding::Utf8) {
                    Decode::Scalar(_, count) => offset += count,
                    Decode::Need => {
                        self.leftover.extend_from_slice(&data[offset..size]);
                        break;
                    }
                    Decode::Invalid => {
                        self.append(output, &data[start..offset]);
                        self.source_rest = Some((term, offset, tail));
                        self.error = true;
                        return;
                    }
                }
            }
            self.append(output, &data[start..offset]);
        }
        *left -= size as i64;
        if size < data.len() {
            self.source_rest = Some((term, size, tail));
        } else {
            self.current = tail.unwrap_or(Term::NIL);
        }
    }

    fn done(&self) -> bool {
        self.error
            || self.source_rest.is_none() && self.current == Term::NIL && self.ancestors.is_empty()
    }

    // Port of erts/emulator/beam/erl_unicode.c:733-749 (do_build_utf8 done), OTP-29.1.1.
    fn rest(&self, ctx: &mut Ctx<'_>) -> Term {
        let rest = if let Some((term, offset, tail)) = self.source_rest {
            let suffix = if offset == 0 {
                term
            } else {
                let len = crate::bitstring_bit_len(term).expect("validated binary") / 8;
                TermBuilder::new(&mut Heap(&mut ctx.heap))
                    .sub_binary(term, offset * 8, (len - offset) * 8)
                    .expect("binary suffix remains in bounds")
            };
            tail.map_or(suffix, |tail| cons(ctx, suffix, tail))
        } else {
            self.current
        };
        wrap(ctx, rest, &self.ancestors)
    }
}

// Port of erts/emulator/beam/erl_unicode.c:787-851 (build_utf8_return), OTP-29.1.1.
fn binary_build_return(ctx: &mut Ctx<'_>, output: Term, build: BinaryBuild) -> UnicodeStep {
    if !build.done() {
        let mut rest = build.rest(ctx);
        if !build.leftover.is_empty() {
            let leftover = binary(ctx, &build.leftover);
            rest = cons(ctx, leftover, rest);
        }
        return trap(
            ctx,
            UnicodeCont {
                stage: UnicodeStage::ToBinary,
                result: output,
                work: build.pos,
                chars: 0,
                rest,
                latin1: build.encoding == Encoding::Latin1,
            },
        );
    }
    if !build.error && build.leftover.is_empty() {
        return UnicodeStep::Done(output);
    }
    let (tag, rest) = if build.error {
        let mut rest = build.rest(ctx);
        if !build.leftover.is_empty() {
            let leftover = binary(ctx, &build.leftover);
            rest = cons(ctx, rest, Term::NIL);
            rest = cons(ctx, leftover, rest);
        }
        ("error", rest)
    } else {
        let tag = if valid_incomplete_utf8(&build.leftover) {
            "incomplete"
        } else {
            "error"
        };
        (tag, binary(ctx, &build.leftover))
    };
    UnicodeStep::Done(tuple_build(ctx, &[atom(tag), output, rest]))
}

// Port of erts/emulator/beam/erl_unicode.c:931-1021
// (unicode_characters_to_binary_2), OTP-29.1.1.
fn characters_to_utf8(
    ctx: &mut Ctx<'_>,
    mut root: Term,
    encoding: Encoding,
) -> Result<Term, BifError> {
    if let Some((head, tail)) = crate::lists::cons_cell(root)
        && tail == Term::NIL
        && head.classify() == TermKind::Bitstring
    {
        root = head;
    }
    let need = check_structure(root, encoding)?;
    if encoding == Encoding::Latin1
        && root.classify() == TermKind::Bitstring
        && crate::bitstring_bit_len(root)? / 8 == need.bytes
    {
        cost_to_proc(ctx, need.cost / (LOOP_FACTOR_SIMPLE / LOOP_FACTOR));
        return Ok(root);
    }
    let unlimited = ctx.reduction_budget() == usize::MAX;
    let simple = need.cost / (LOOP_FACTOR_SIMPLE / LOOP_FACTOR);
    cost_to_proc(ctx, simple);
    let mut left = if unlimited {
        i64::MAX
    } else {
        (allowed_iterations(ctx) - simple as i64).max(ERL_ONHEAP_BINARY_LIMIT)
    };
    let initial = left;
    let mut build = BinaryBuild::new(root, 0, encoding);
    let output = if unlimited || need.bytes <= 64 {
        TermBuilder::new(&mut Heap(&mut ctx.heap))
            .binary_from_fn_with_len(need.bytes, |output| {
                build.fill(output, &mut left);
                Ok(build.pos)
            })
            .map_err(|_| BifError::SystemLimit)?
    } else {
        let output = crate::allocate_iolist_binary(&mut ctx.heap, need.bytes)?;
        fill_utf8_binary(output, &mut build, &mut left);
        output
    };
    cost_to_proc(ctx, (initial - left) as usize);
    match binary_build_return(ctx, output, build) {
        UnicodeStep::Done(value) => Ok(value),
        UnicodeStep::More(cont) => {
            ctx.defer_trap(DeferredTrap::Unicode(cont));
            Ok(Term::NIL)
        }
    }
}

fn fill_utf8_binary(output: Term, build: &mut BinaryBuild, left: &mut i64) {
    if crate::bitstring_bit_len(output).expect("conversion retains its binary") <= 64 * 8 {
        // do_build_utf8 may yield with only empty tails or an invalid integer left
        // after consuming exactly 64 units. utf8_need bounds all valid output by
        // 64 bytes, so a resumed heap binary has no payload writes left to perform.
        build.fill(&mut [], left);
        return;
    }
    crate::with_iolist_binary_output(output, |bytes| {
        build.fill(bytes, left);
        Ok(())
    })
    .expect("conversion retains its private binary writer");
    if build.done() {
        assert!(
            arinsal_term::writable_resize_private(output, build.pos * 8)
                .expect("conversion only shrinks its private binary")
        );
        crate::finish_iolist_binary_output(output);
    }
}

/// Return the original subject when it is already a valid UTF-8 binary.
///
/// Port of erts/emulator/beam/erl_unicode.c:931 (unicode_characters_to_binary_2), OTP-29.1.1.
pub fn unicode_utf8_binary_fast_path(args: &[Term]) -> Result<Option<Term>, BifError> {
    let [subject, encoding] = args else {
        return Ok(None);
    };
    let Some(encoding_atom) = encoding.as_atom() else {
        return Ok(None);
    };
    if !matches!(global_atoms().text(encoding_atom), Some("utf8" | "unicode")) {
        return Ok(None);
    }
    let mut subject = *subject;
    if let Some((head, tail)) = crate::lists::cons_cell(subject)
        && tail == Term::NIL
        && head.classify() == TermKind::Bitstring
    {
        subject = head;
    }
    if subject.classify() != TermKind::Bitstring {
        return Ok(None);
    }
    let data = bytes(subject)?;
    Ok(analyze_utf8(&data).then_some(subject))
}

// Port of erts/emulator/beam/erl_unicode.c:1177 (analyze_utf8), OTP-29.1.1.
fn analyze_utf8(mut source: &[u8]) -> bool {
    while !source.is_empty() {
        let first = source[0];
        let size = if first & 0x80 == 0 {
            1
        } else if first & 0xe0 == 0xc0 {
            if source.len() < 2 || source[1] & 0xc0 != 0x80 || first < 0xc2 {
                return false;
            }
            2
        } else if first & 0xf0 == 0xe0 {
            if source.len() < 3
                || source[1] & 0xc0 != 0x80
                || source[2] & 0xc0 != 0x80
                || first == 0xe0 && source[1] < 0xa0
                || first & 0x0f == 0x0d && source[1] & 0x20 != 0
            {
                return false;
            }
            3
        } else if first & 0xf8 == 0xf0 {
            if source.len() < 4
                || source[1] & 0xc0 != 0x80
                || source[2] & 0xc0 != 0x80
                || source[3] & 0xc0 != 0x80
                || first == 0xf0 && source[1] < 0x90
                || first & 0x07 > 0x04
                || first & 0x07 == 0x04 && source[1] & 0x3f > 0x0f
            {
                return false;
            }
            4
        } else {
            return false;
        };
        source = &source[size..];
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use arinsal_term::{ProcessHeap, TermBuilder};

    #[test]
    fn valid_utf8_binary_returns_the_original_term() {
        let mut heap = ProcessHeap::with_words(256);
        let mut allocator = crate::ProcessHeapHandle(&mut heap);
        let binary = TermBuilder::new(&mut allocator)
            .binary(b"X-Request-Id: abc123          ")
            .unwrap();
        let singleton = TermBuilder::new(&mut allocator)
            .cons(binary, Term::NIL)
            .unwrap();
        let utf8 = Term::atom(global_atoms().intern("utf8").unwrap());
        let mut state = crate::BifState::default();
        let mut ctx = Ctx::new(&mut allocator, &mut state);

        similar_asserts::assert_eq!(
            characters_to_binary_result(&mut ctx, &[binary, utf8]).unwrap(),
            binary
        );
        similar_asserts::assert_eq!(
            characters_to_binary_result(&mut ctx, &[singleton, utf8]).unwrap(),
            binary
        );
    }
}

fn characters_to_list(ctx: &mut Ctx<'_>, args: &[Term]) -> Term {
    match convert_charged(ctx, args, true) {
        Ok(_value) if ctx.has_deferred() => {
            match *ctx.take_deferred().expect("deferred Unicode trap") {
                DeferredTrap::Unicode(cont) => ctx.trap(DeferredTrap::Unicode(cont)),
                _ => unreachable!("Unicode conversion only defers Unicode traps"),
            }
        }
        Ok(value) => value,
        Err(error) => ctx.fail(error),
    }
}

/// Iterations of the conversion loops that make up one reduction.
// Port of `LOOP_FACTOR` in erts/emulator/beam/erl_unicode.c, OTP-29.1.1.
const LOOP_FACTOR: usize = 10;

/// Iterations of the counting loops that make up one reduction.
// Port of `LOOP_FACTOR_SIMPLE` in erts/emulator/beam/erl_unicode.c, OTP-29.1.1.
const LOOP_FACTOR_SIMPLE: usize = 50;

/// Iterations of one slice at most (`max_loop_limit`, `CONTEXT_REDS * LOOP_FACTOR`).
const MAX_LOOP_LIMIT: usize = 4000 * LOOP_FACTOR;

/// Largest on-heap binary, which never traps when it is the result.
const ERL_ONHEAP_BINARY_LIMIT: i64 = 64;

/// Where a trapped conversion resumes, one per `erlang:characters_to_*_trap` export.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnicodeStage {
    /// `characters_to_utf8_trap/4`: the rest of `characters_to_binary/2` input.
    ToBinary,
    /// `characters_to_list_trap_1/3`: the rest of the UTF-8 buffer build.
    ListBuild,
    /// `characters_to_list_trap_2/3`: the characters still to put on the list.
    ListFinalize,
    /// `characters_to_list_trap_3/3`: the rest of the analysis of a UTF-8 binary.
    ListAnalyze,
    /// `characters_to_list_trap_4/1`: the characters of an analyzed binary still to build.
    ListFromBinary,
}

/// Resume state of a trapped `unicode:characters_to_binary/2` or `characters_to_list/2`.
///
/// Port of the restart arguments and `RestartContext` that `BIF_TRAP*` passes in
/// erts/emulator/beam/erl_unicode.c, OTP-29.1.1. Binary conversion retains the output,
/// write position, remaining chardata and encoding. List conversion retains its result
/// and the counters of its buffer-build and list-finalization stages.
#[derive(Clone)]
pub struct UnicodeCont {
    stage: UnicodeStage,
    result: Term,
    work: usize,
    chars: usize,
    rest: Term,
    latin1: bool,
}

impl UnicodeCont {
    /// The continuation export this state belongs to.
    pub fn continuation(&self) -> &'static str {
        match self.stage {
            UnicodeStage::ToBinary => "erlang:characters_to_utf8_trap/4",
            UnicodeStage::ListBuild => "erlang:characters_to_list_trap_1/3",
            UnicodeStage::ListFinalize => "erlang:characters_to_list_trap_2/3",
            UnicodeStage::ListAnalyze => "erlang:characters_to_list_trap_3/3",
            UnicodeStage::ListFromBinary => "erlang:characters_to_list_trap_4/1",
        }
    }
}

/// One slice of a conversion.
pub enum UnicodeStep {
    /// The converted value.
    Done(Term),
    /// `BIF_TRAP` to the next slice.
    More(UnicodeCont),
}

/// Work of a conversion: `cost` is `utf8_need`'s cost, `units` the iterations of
/// `do_build_utf8` (one per integer, one per byte of a binary).
struct Measure {
    cost: usize,
    units: usize,
}

// Port of erts/emulator/beam/erl_unicode.c:342 (utf8_need), OTP-29.1.1, for its cost.
fn measure(root: Term, latin1: bool) -> Measure {
    let mut measure = Measure { cost: 0, units: 0 };
    let mut stack = vec![root];
    let binary_work = |measure: &mut Measure, term: Term| -> bool {
        let Ok(data) = bytes(term) else {
            return false;
        };
        measure.units += data.len();
        if latin1 {
            measure.cost += data
                .iter()
                .map(|byte| if *byte < 128 { 1 } else { 2 })
                .sum::<usize>();
        } else {
            measure.cost += 1;
        }
        true
    };
    while let Some(mut current) = stack.pop() {
        loop {
            match current.classify() {
                TermKind::List => {
                    let Some((head, tail)) = crate::lists::cons_cell(current) else {
                        return measure;
                    };
                    match head.classify() {
                        TermKind::Nil => {}
                        TermKind::List => {
                            stack.push(tail);
                            current = head;
                            continue;
                        }
                        TermKind::Bitstring => {
                            if !binary_work(&mut measure, head) {
                                return measure;
                            }
                        }
                        TermKind::Number if head.as_small().is_some() => {
                            measure.cost += 1;
                            measure.units += 1;
                        }
                        _ => return measure,
                    }
                    current = tail;
                }
                TermKind::Bitstring => {
                    if !binary_work(&mut measure, current) {
                        return measure;
                    }
                    break;
                }
                _ => break,
            }
        }
    }
    measure
}

/// Characters in a converted list, or in the converted part of an error tuple.
fn converted_chars(result: Term) -> usize {
    let mut list = result;
    if let Some(items) = crate::pure::tuple_terms(result) {
        list = items.get(1).copied().unwrap_or(Term::NIL);
    }
    let mut count = 0;
    while let Some((_, tail)) = crate::lists::cons_cell(list) {
        count += 1;
        list = tail;
    }
    count
}

/// `allowed_iterations`: iterations of the conversion loops for the reductions left.
// Port of erts/emulator/beam/erl_unicode.c:166 (allowed_iterations), OTP-29.1.1.
fn allowed_iterations(ctx: &Ctx<'_>) -> i64 {
    (ctx.reduction_budget().saturating_mul(LOOP_FACTOR)).min(MAX_LOOP_LIMIT) as i64
}

/// `allowed_iterations` inside a continuation export, whose call costs a reduction first.
fn allowed_iterations_resumed(ctx: &Ctx<'_>) -> i64 {
    (ctx.reduction_budget().saturating_mul(LOOP_FACTOR)).min(MAX_LOOP_LIMIT) as i64
}

/// `cost_to_proc`: reductions for a number of loop iterations.
// Port of erts/emulator/beam/erl_unicode.c:176 (cost_to_proc), OTP-29.1.1.
fn cost_to_proc(ctx: &mut Ctx<'_>, cost: usize) {
    ctx.charge_reductions(cost / LOOP_FACTOR);
}

fn trap(ctx: &mut Ctx<'_>, cont: UnicodeCont) -> UnicodeStep {
    ctx.bump_all_reds();
    UnicodeStep::More(cont)
}

/// The list is built from the UTF-8 buffer `left` characters at a time.
// Port of erts/emulator/beam/erl_unicode.c:1637 (finalize_list_to_list) and
// :1342 (do_utf8_to_list), OTP-29.1.1.
fn list_build_slice(
    ctx: &mut Ctx<'_>,
    stage: UnicodeStage,
    result: Term,
    chars: usize,
    left: i64,
) -> UnicodeStep {
    if chars == 0 {
        return UnicodeStep::Done(result);
    }
    let built = if left < chars as i64 {
        if left > 0 { left as usize } else { 1 }
    } else {
        chars
    };
    cost_to_proc(ctx, built);
    if built != chars {
        return trap(
            ctx,
            UnicodeCont {
                stage,
                result,
                work: 0,
                chars: chars - built,
                rest: Term::NIL,
                latin1: false,
            },
        );
    }
    UnicodeStep::Done(result)
}

/// `characters_to_list/2` of a list or Latin-1 binary after `do_build_utf8` ran.
// Port of erts/emulator/beam/erl_unicode.c:1024 (build_list_return), OTP-29.1.1.
fn list_build_slice_after_buffer(
    ctx: &mut Ctx<'_>,
    result: Term,
    work: usize,
    chars: usize,
    left: i64,
) -> UnicodeStep {
    let consumed = work.min(left.max(0) as usize);
    cost_to_proc(ctx, consumed);
    if consumed < work {
        return trap(
            ctx,
            UnicodeCont {
                stage: UnicodeStage::ListBuild,
                result,
                work: work - consumed,
                chars,
                rest: Term::NIL,
                latin1: false,
            },
        );
    }
    let left = (left - consumed as i64).max(1);
    list_build_slice(ctx, UnicodeStage::ListFinalize, result, chars, left)
}

/// Analyze a UTF-8 binary `left` characters at a time, then build its list.
// Port of erts/emulator/beam/erl_unicode.c:1728 (do_bif_utf8_to_list) and
// :1081 (analyze_utf8), OTP-29.1.1.
fn list_analyze_slice(
    ctx: &mut Ctx<'_>,
    result: Term,
    analyzed: usize,
    chars: usize,
    resumed: bool,
) -> UnicodeStep {
    let mut left = if resumed {
        allowed_iterations_resumed(ctx)
    } else {
        allowed_iterations(ctx)
    };
    let remaining = chars - analyzed;
    let count = if left <= 0 {
        remaining.min(1)
    } else {
        remaining.min(left as usize)
    };
    left -= count as i64;
    cost_to_proc(ctx, count);
    if count < remaining {
        return trap(
            ctx,
            UnicodeCont {
                stage: UnicodeStage::ListAnalyze,
                result,
                work: analyzed + count,
                chars,
                rest: Term::NIL,
                latin1: false,
            },
        );
    }
    list_build_slice(ctx, UnicodeStage::ListFromBinary, result, chars, left)
}

/// Run the slice that follows a trap.
pub fn unicode_resume(ctx: &mut Ctx<'_>, cont: &UnicodeCont) -> UnicodeStep {
    match cont.stage {
        UnicodeStage::ToBinary => {
            // Port of erts/emulator/beam/erl_unicode.c:853-888
            // (characters_to_utf8_trap), OTP-29.1.1.
            let mut left = allowed_iterations_resumed(ctx);
            let initial = left;
            let encoding = if cont.latin1 {
                Encoding::Latin1
            } else {
                Encoding::Utf8
            };
            let mut build = BinaryBuild::new(cont.rest, cont.work, encoding);
            fill_utf8_binary(cont.result, &mut build, &mut left);
            cost_to_proc(ctx, (initial - left) as usize);
            binary_build_return(ctx, cont.result, build)
        }
        UnicodeStage::ListBuild => {
            let left = allowed_iterations_resumed(ctx);
            list_build_slice_after_buffer(ctx, cont.result, cont.work, cont.chars, left)
        }
        UnicodeStage::ListFinalize | UnicodeStage::ListFromBinary => {
            let left = allowed_iterations_resumed(ctx);
            list_build_slice(ctx, cont.stage, cont.result, cont.chars, left)
        }
        UnicodeStage::ListAnalyze => {
            list_analyze_slice(ctx, cont.result, cont.work, cont.chars, true)
        }
    }
}

/// `characters_to_binary/2` and `characters_to_list/2` with erts' loop accounting.
// Port of erts/emulator/beam/erl_unicode.c:931 (unicode_characters_to_binary_2) and
// :1122 (unicode_characters_to_list_2), OTP-29.1.1.
fn convert_charged(ctx: &mut Ctx<'_>, args: &[Term], list_output: bool) -> Result<Term, BifError> {
    let result = convert(ctx, args, list_output)?;
    let Ok(encoding) = encoding(args[1]) else {
        return Ok(result);
    };
    if !matches!(encoding, Encoding::Latin1 | Encoding::Utf8)
        || ctx.reduction_budget() == usize::MAX
    {
        return Ok(result);
    }
    let latin1 = encoding == Encoding::Latin1;
    let subject = args[0];
    let step = if subject.classify() == TermKind::Bitstring && !latin1 {
        let chars = converted_chars(result);
        list_analyze_slice(ctx, result, 0, chars, false)
    } else {
        let work = measure(subject, latin1);
        let simple = work.cost / (LOOP_FACTOR_SIMPLE / LOOP_FACTOR);
        cost_to_proc(ctx, simple);
        let mut left = allowed_iterations(ctx) - simple as i64;
        if left <= 0 {
            left = 1;
        }
        list_build_slice_after_buffer(ctx, result, work.units, converted_chars(result), left)
    };
    match step {
        UnicodeStep::Done(value) => Ok(value),
        UnicodeStep::More(cont) => {
            ctx.defer_trap(DeferredTrap::Unicode(cont));
            Ok(Term::NIL)
        }
    }
}

// Port of erts/emulator/beam/erl_unicode.c:2222 (erts_native_filename_need), OTP-29.1.1.
fn filename_list_bytes(root: Term, encoding: FilenameEncoding) -> Result<Vec<u8>, BifError> {
    if root != Term::NIL && root.classify() != TermKind::List {
        return Err(BifError::BADARG);
    }
    let mut result = Vec::new();
    let mut stack = Vec::new();
    let mut current = root;
    loop {
        match current.classify() {
            TermKind::Nil => {
                if let Some(next) = stack.pop() {
                    current = next;
                } else {
                    break;
                }
            }
            TermKind::List => {
                // SAFETY: The source heap remains live during this BIF call.
                let (head, tail) = unsafe { current.cons_ref() }.ok_or(BifError::BADARG)?;
                match head.classify() {
                    TermKind::Nil => current = tail,
                    TermKind::List => {
                        stack.push(tail);
                        current = head;
                    }
                    TermKind::Number => {
                        let cp = head
                            .as_small()
                            .and_then(|n| u32::try_from(n).ok())
                            .ok_or(BifError::BADARG)?;
                        if cp == 0 || !valid_cp(cp) {
                            return Err(BifError::BADARG);
                        }
                        if encoding == FilenameEncoding::Latin1 {
                            result.push(u8::try_from(cp).map_err(|_| BifError::BADARG)?);
                            current = tail;
                            continue;
                        }
                        let mut buffer = [0; 4];
                        result.extend_from_slice(
                            char::from_u32(cp)
                                .unwrap()
                                .encode_utf8(&mut buffer)
                                .as_bytes(),
                        );
                        current = tail;
                    }
                    _ => return Err(BifError::BADARG),
                }
            }
            _ => return Err(BifError::BADARG),
        }
    }
    Ok(result)
}

// Port of erts/emulator/beam/erl_unicode.c:2629 (prim_file_internal_name2native_1), OTP-29.1.1.
fn internal_name2native(ctx: &mut Ctx<'_>, args: &[Term]) -> Term {
    match internal_name2native_result(ctx, args) {
        Ok(value) => value,
        Err(error) => ctx.fail(error),
    }
}

fn internal_name2native_result(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let mut data = if args[0].classify() == TermKind::Bitstring {
        let data = bytes(args[0])?;
        if data.contains(&0) {
            return Err(BifError::BADARG);
        }
        data.into_owned()
    } else {
        filename_list_bytes(args[0], filename_encoding())?
    };
    data.push(0);
    Ok(binary(ctx, &data))
}

fn codepoint_list(ctx: &mut Ctx<'_>, points: impl IntoIterator<Item = u32>) -> Term {
    Output::List(points.into_iter().collect()).term(ctx)
}

// Port of erts/emulator/beam/erl_unicode.c:2735 (prim_file_internal_native2name_1), OTP-29.1.1.
fn internal_native2name(ctx: &mut Ctx<'_>, args: &[Term]) -> Term {
    match internal_native2name_result(ctx, args) {
        Ok(value) => value,
        Err(error) => ctx.fail(error),
    }
}

fn internal_native2name_result(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let data = bytes(args[0])?;
    if data.is_empty() {
        return Ok(Term::NIL);
    }
    let encoding = filename_encoding();
    if encoding == FilenameEncoding::Latin1 {
        return Ok(codepoint_list(ctx, data.iter().map(|b| u32::from(*b))));
    }
    match std::str::from_utf8(&data) {
        Ok(text) => {
            let points: Vec<u32> = text.chars().map(|c| c as u32).collect();
            let points = if encoding == FilenameEncoding::Utf8Mac {
                normalize_filename(points)
            } else {
                points
            };
            Ok(codepoint_list(ctx, points))
        }
        Err(_) => Ok(tuple_build(ctx, &[atom("error"), atom("warning")])),
    }
}

// Port of erts/emulator/beam/erl_unicode.c:2826 (prim_file_internal_normalize_utf8_1), OTP-29.1.1.
fn internal_normalize_utf8(ctx: &mut Ctx<'_>, args: &[Term]) -> Term {
    match internal_normalize_utf8_result(ctx, args) {
        Ok(value) => value,
        Err(error) => ctx.fail(error),
    }
}

fn internal_normalize_utf8_result(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let data = bytes(args[0])?;
    let text = std::str::from_utf8(&data).map_err(|_| BifError::BADARG)?;
    let points = text.chars().map(|c| c as u32).collect::<Vec<_>>();
    Ok(codepoint_list(ctx, normalize_filename(points)))
}

// Port of erts/emulator/beam/erl_unicode.c:2855 (prim_file_is_translatable_1), OTP-29.1.1.
fn is_translatable(ctx: &mut Ctx<'_>, args: &[Term]) -> Term {
    match is_translatable_result(ctx, args) {
        Ok(value) => value,
        Err(error) => ctx.fail(error),
    }
}

fn is_translatable_result(_: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let data = bytes(args[0])?;
    Ok(bool_term(
        data.is_empty()
            || filename_encoding() == FilenameEncoding::Latin1
            || std::str::from_utf8(&data).is_ok(),
    ))
}

/// How the OS names files, as `erts_get_native_filename_encoding` reports it.
#[derive(Clone, Copy, PartialEq, Eq)]
enum FilenameEncoding {
    Latin1,
    Utf8,
    /// UTF-8 with the decomposed forms macOS stores; names are recomposed on the way in.
    Utf8Mac,
}

/// Whether the environment's locale uses a UTF-8 codeset, as the runtime found out at boot
/// (`erts_init_sys_common_misc`); set once by the VM, which owns the libc locale calls.
static LOCALE_UTF8: std::sync::OnceLock<bool> = std::sync::OnceLock::new();

/// Record the locale's codeset; later calls are ignored.
pub fn set_locale_utf8(utf8: bool) {
    let _ = LOCALE_UTF8.set(utf8);
}

/// Port of erts/emulator/sys/common/erl_sys_common_misc.c (erts_init_sys_common_misc),
/// OTP-29.1.1. The `+fn` flags that override the locale are not honoured. Without a boot
/// (unit tests) the locale environment variables decide, as erts' `PRIMITIVE_UTF8_CHECK`.
fn filename_encoding() -> FilenameEncoding {
    // macOS, Windows and Android default the user-requested encoding to UTF-8.
    if cfg!(target_os = "macos") {
        return FilenameEncoding::Utf8Mac;
    }
    let utf8 = LOCALE_UTF8.get().copied().unwrap_or_else(|| {
        ["LC_ALL", "LC_CTYPE", "LANG"]
            .iter()
            .filter_map(|name| std::env::var(name).ok())
            .find(|value| !value.is_empty())
            .is_some_and(|value| value.contains("UTF-8"))
    });
    if utf8 {
        FilenameEncoding::Utf8
    } else {
        FilenameEncoding::Latin1
    }
}

// Port of erts/emulator/beam/erl_unicode.c (file_native_name_encoding_0), OTP-29.1.1.
fn native_name_encoding(_: &mut Ctx<'_>, _: &[Term]) -> Term {
    atom(match filename_encoding() {
        FilenameEncoding::Latin1 => "latin1",
        FilenameEncoding::Utf8 | FilenameEncoding::Utf8Mac => "utf8",
    })
}

// OTP 29.1.1 defaults without the +pc emulator flag.
fn printable_range(_: &mut Ctx<'_>, _: &[Term]) -> Term {
    atom("latin1")
}

enum Translation {
    No,
    Maybe,
    Yes(u32, usize),
}

fn composition_candidate(cp: u32) -> bool {
    if cp < 768 || (cp > 4023 && cp != 12441 && cp != 12442) {
        return false;
    }
    COMPOSITIONS
        .iter()
        .any(|(key, _, _)| u32::from(key[0]) == cp)
}

fn translate(points: &[u32]) -> Translation {
    let mut maybe = false;
    for (key, len, result) in COMPOSITIONS {
        let common = usize::from(*len).min(points.len());
        if key[..common]
            .iter()
            .map(|cp| u32::from(*cp))
            .eq(points[..common].iter().copied())
        {
            if usize::from(*len) <= points.len() {
                return Translation::Yes(u32::from(*result), usize::from(*len) - 1);
            }
            maybe = true;
        }
    }
    if maybe {
        Translation::Maybe
    } else {
        Translation::No
    }
}

// Port of erts/emulator/beam/erl_unicode.c:1468-1635 (filename normalization), OTP-29.1.1.
fn normalize_filename(points: Vec<u32>) -> Vec<u32> {
    let mut result = Vec::with_capacity(points.len());
    let mut saved = Vec::<u32>::with_capacity(4);
    for cp in points.into_iter().rev() {
        if saved.is_empty() {
            if composition_candidate(cp) {
                saved.push(cp);
            } else {
                result.push(cp);
            }
            continue;
        }
        if cp <= 0xffff {
            saved.push(cp);
            match translate(&saved) {
                Translation::Yes(value, _) => {
                    result.push(value);
                    saved.clear();
                }
                Translation::Maybe => {}
                Translation::No => {
                    result.push(saved[0]);
                    let mut i = 1;
                    while i < saved.len() {
                        if !composition_candidate(saved[i]) {
                            result.push(saved[i]);
                            i += 1;
                            continue;
                        }
                        match translate(&saved[i..]) {
                            Translation::No => {
                                result.push(saved[i]);
                                i += 1;
                            }
                            Translation::Yes(value, consumed) => {
                                result.push(value);
                                i += consumed;
                            }
                            Translation::Maybe => break,
                        }
                    }
                    saved = saved[i..].to_vec();
                }
            }
        } else {
            result.push(saved[0]);
            let mut i = 1;
            while i < saved.len() {
                if composition_candidate(saved[i])
                    && let Translation::Yes(value, consumed) = translate(&saved[i..])
                {
                    result.push(value);
                    i += consumed;
                } else {
                    result.push(saved[i]);
                    i += 1;
                }
            }
            result.push(cp);
            saved.clear();
        }
    }
    if !saved.is_empty() {
        result.push(saved[0]);
        let mut i = 1;
        while i < saved.len() {
            if composition_candidate(saved[i])
                && let Translation::Yes(value, consumed) = translate(&saved[i..])
            {
                result.push(value);
                i += consumed;
            } else {
                result.push(saved[i]);
                i += 1;
            }
        }
    }
    result.reverse();
    result
}

// Generated from erts/emulator/beam/erl_unicode_normalize.h, OTP-29.1.1.
// Source data: Apache-2.0, Copyright Ericsson AB 1999-2025.
const COMPOSITIONS: &[([u16; 4], u8, u16)] = &[
    ([768, 65, 0, 0], 2, 192),
    ([768, 69, 0, 0], 2, 200),
    ([768, 73, 0, 0], 2, 204),
    ([768, 79, 0, 0], 2, 210),
    ([768, 85, 0, 0], 2, 217),
    ([768, 87, 0, 0], 2, 7808),
    ([768, 89, 0, 0], 2, 7922),
    ([768, 97, 0, 0], 2, 224),
    ([768, 101, 0, 0], 2, 232),
    ([768, 105, 0, 0], 2, 236),
    ([768, 111, 0, 0], 2, 242),
    ([768, 117, 0, 0], 2, 249),
    ([768, 119, 0, 0], 2, 7809),
    ([768, 121, 0, 0], 2, 7923),
    ([768, 168, 0, 0], 2, 8173),
    ([768, 770, 65, 0], 3, 7846),
    ([768, 770, 69, 0], 3, 7872),
    ([768, 770, 79, 0], 3, 7890),
    ([768, 770, 97, 0], 3, 7847),
    ([768, 770, 101, 0], 3, 7873),
    ([768, 770, 111, 0], 3, 7891),
    ([768, 772, 69, 0], 3, 7700),
    ([768, 772, 79, 0], 3, 7760),
    ([768, 772, 101, 0], 3, 7701),
    ([768, 772, 111, 0], 3, 7761),
    ([768, 774, 65, 0], 3, 7856),
    ([768, 774, 97, 0], 3, 7857),
    ([768, 776, 85, 0], 3, 475),
    ([768, 776, 117, 0], 3, 476),
    ([768, 776, 953, 0], 3, 8146),
    ([768, 776, 965, 0], 3, 8162),
    ([768, 787, 837, 913], 4, 8074),
    ([768, 787, 837, 919], 4, 8090),
    ([768, 787, 837, 937], 4, 8106),
    ([768, 787, 837, 945], 4, 8066),
    ([768, 787, 837, 951], 4, 8082),
    ([768, 787, 837, 969], 4, 8098),
    ([768, 787, 913, 0], 3, 7946),
    ([768, 787, 917, 0], 3, 7962),
    ([768, 787, 919, 0], 3, 7978),
    ([768, 787, 921, 0], 3, 7994),
    ([768, 787, 927, 0], 3, 8010),
    ([768, 787, 937, 0], 3, 8042),
    ([768, 787, 945, 0], 3, 7938),
    ([768, 787, 949, 0], 3, 7954),
    ([768, 787, 951, 0], 3, 7970),
    ([768, 787, 953, 0], 3, 7986),
    ([768, 787, 959, 0], 3, 8002),
    ([768, 787, 965, 0], 3, 8018),
    ([768, 787, 969, 0], 3, 8034),
    ([768, 788, 837, 913], 4, 8075),
    ([768, 788, 837, 919], 4, 8091),
    ([768, 788, 837, 937], 4, 8107),
    ([768, 788, 837, 945], 4, 8067),
    ([768, 788, 837, 951], 4, 8083),
    ([768, 788, 837, 969], 4, 8099),
    ([768, 788, 913, 0], 3, 7947),
    ([768, 788, 917, 0], 3, 7963),
    ([768, 788, 919, 0], 3, 7979),
    ([768, 788, 921, 0], 3, 7995),
    ([768, 788, 927, 0], 3, 8011),
    ([768, 788, 933, 0], 3, 8027),
    ([768, 788, 937, 0], 3, 8043),
    ([768, 788, 945, 0], 3, 7939),
    ([768, 788, 949, 0], 3, 7955),
    ([768, 788, 951, 0], 3, 7971),
    ([768, 788, 953, 0], 3, 7987),
    ([768, 788, 959, 0], 3, 8003),
    ([768, 788, 965, 0], 3, 8019),
    ([768, 788, 969, 0], 3, 8035),
    ([768, 795, 79, 0], 3, 7900),
    ([768, 795, 85, 0], 3, 7914),
    ([768, 795, 111, 0], 3, 7901),
    ([768, 795, 117, 0], 3, 7915),
    ([768, 837, 945, 0], 3, 8114),
    ([768, 837, 951, 0], 3, 8130),
    ([768, 837, 969, 0], 3, 8178),
    ([768, 913, 0, 0], 2, 8122),
    ([768, 917, 0, 0], 2, 8136),
    ([768, 919, 0, 0], 2, 8138),
    ([768, 921, 0, 0], 2, 8154),
    ([768, 927, 0, 0], 2, 8184),
    ([768, 933, 0, 0], 2, 8170),
    ([768, 937, 0, 0], 2, 8186),
    ([768, 945, 0, 0], 2, 8048),
    ([768, 949, 0, 0], 2, 8050),
    ([768, 951, 0, 0], 2, 8052),
    ([768, 953, 0, 0], 2, 8054),
    ([768, 959, 0, 0], 2, 8056),
    ([768, 965, 0, 0], 2, 8058),
    ([768, 969, 0, 0], 2, 8060),
    ([768, 8127, 0, 0], 2, 8141),
    ([768, 8190, 0, 0], 2, 8157),
    ([769, 65, 0, 0], 2, 193),
    ([769, 67, 0, 0], 2, 262),
    ([769, 69, 0, 0], 2, 201),
    ([769, 71, 0, 0], 2, 500),
    ([769, 73, 0, 0], 2, 205),
    ([769, 75, 0, 0], 2, 7728),
    ([769, 76, 0, 0], 2, 313),
    ([769, 77, 0, 0], 2, 7742),
    ([769, 78, 0, 0], 2, 323),
    ([769, 79, 0, 0], 2, 211),
    ([769, 80, 0, 0], 2, 7764),
    ([769, 82, 0, 0], 2, 340),
    ([769, 83, 0, 0], 2, 346),
    ([769, 85, 0, 0], 2, 218),
    ([769, 87, 0, 0], 2, 7810),
    ([769, 89, 0, 0], 2, 221),
    ([769, 90, 0, 0], 2, 377),
    ([769, 97, 0, 0], 2, 225),
    ([769, 99, 0, 0], 2, 263),
    ([769, 101, 0, 0], 2, 233),
    ([769, 103, 0, 0], 2, 501),
    ([769, 105, 0, 0], 2, 237),
    ([769, 107, 0, 0], 2, 7729),
    ([769, 108, 0, 0], 2, 314),
    ([769, 109, 0, 0], 2, 7743),
    ([769, 110, 0, 0], 2, 324),
    ([769, 111, 0, 0], 2, 243),
    ([769, 112, 0, 0], 2, 7765),
    ([769, 114, 0, 0], 2, 341),
    ([769, 115, 0, 0], 2, 347),
    ([769, 117, 0, 0], 2, 250),
    ([769, 119, 0, 0], 2, 7811),
    ([769, 121, 0, 0], 2, 253),
    ([769, 122, 0, 0], 2, 378),
    ([769, 168, 0, 0], 2, 8174),
    ([769, 198, 0, 0], 2, 508),
    ([769, 216, 0, 0], 2, 510),
    ([769, 230, 0, 0], 2, 509),
    ([769, 248, 0, 0], 2, 511),
    ([769, 770, 65, 0], 3, 7844),
    ([769, 770, 69, 0], 3, 7870),
    ([769, 770, 79, 0], 3, 7888),
    ([769, 770, 97, 0], 3, 7845),
    ([769, 770, 101, 0], 3, 7871),
    ([769, 770, 111, 0], 3, 7889),
    ([769, 771, 79, 0], 3, 7756),
    ([769, 771, 85, 0], 3, 7800),
    ([769, 771, 111, 0], 3, 7757),
    ([769, 771, 117, 0], 3, 7801),
    ([769, 772, 69, 0], 3, 7702),
    ([769, 772, 79, 0], 3, 7762),
    ([769, 772, 101, 0], 3, 7703),
    ([769, 772, 111, 0], 3, 7763),
    ([769, 774, 65, 0], 3, 7854),
    ([769, 774, 97, 0], 3, 7855),
    ([769, 776, 73, 0], 3, 7726),
    ([769, 776, 85, 0], 3, 471),
    ([769, 776, 105, 0], 3, 7727),
    ([769, 776, 117, 0], 3, 472),
    ([769, 776, 953, 0], 3, 8147),
    ([769, 776, 965, 0], 3, 8163),
    ([769, 778, 65, 0], 3, 506),
    ([769, 778, 97, 0], 3, 507),
    ([769, 787, 837, 913], 4, 8076),
    ([769, 787, 837, 919], 4, 8092),
    ([769, 787, 837, 937], 4, 8108),
    ([769, 787, 837, 945], 4, 8068),
    ([769, 787, 837, 951], 4, 8084),
    ([769, 787, 837, 969], 4, 8100),
    ([769, 787, 913, 0], 3, 7948),
    ([769, 787, 917, 0], 3, 7964),
    ([769, 787, 919, 0], 3, 7980),
    ([769, 787, 921, 0], 3, 7996),
    ([769, 787, 927, 0], 3, 8012),
    ([769, 787, 937, 0], 3, 8044),
    ([769, 787, 945, 0], 3, 7940),
    ([769, 787, 949, 0], 3, 7956),
    ([769, 787, 951, 0], 3, 7972),
    ([769, 787, 953, 0], 3, 7988),
    ([769, 787, 959, 0], 3, 8004),
    ([769, 787, 965, 0], 3, 8020),
    ([769, 787, 969, 0], 3, 8036),
    ([769, 788, 837, 913], 4, 8077),
    ([769, 788, 837, 919], 4, 8093),
    ([769, 788, 837, 937], 4, 8109),
    ([769, 788, 837, 945], 4, 8069),
    ([769, 788, 837, 951], 4, 8085),
    ([769, 788, 837, 969], 4, 8101),
    ([769, 788, 913, 0], 3, 7949),
    ([769, 788, 917, 0], 3, 7965),
    ([769, 788, 919, 0], 3, 7981),
    ([769, 788, 921, 0], 3, 7997),
    ([769, 788, 927, 0], 3, 8013),
    ([769, 788, 933, 0], 3, 8029),
    ([769, 788, 937, 0], 3, 8045),
    ([769, 788, 945, 0], 3, 7941),
    ([769, 788, 949, 0], 3, 7957),
    ([769, 788, 951, 0], 3, 7973),
    ([769, 788, 953, 0], 3, 7989),
    ([769, 788, 959, 0], 3, 8005),
    ([769, 788, 965, 0], 3, 8021),
    ([769, 788, 969, 0], 3, 8037),
    ([769, 795, 79, 0], 3, 7898),
    ([769, 795, 85, 0], 3, 7912),
    ([769, 795, 111, 0], 3, 7899),
    ([769, 795, 117, 0], 3, 7913),
    ([769, 807, 67, 0], 3, 7688),
    ([769, 807, 99, 0], 3, 7689),
    ([769, 837, 945, 0], 3, 8116),
    ([769, 837, 951, 0], 3, 8132),
    ([769, 837, 959, 0], 3, 8180),
    ([769, 913, 0, 0], 2, 8123),
    ([769, 917, 0, 0], 2, 8137),
    ([769, 919, 0, 0], 2, 8139),
    ([769, 921, 0, 0], 2, 8155),
    ([769, 927, 0, 0], 2, 8185),
    ([769, 933, 0, 0], 2, 8171),
    ([769, 937, 0, 0], 2, 8187),
    ([769, 945, 0, 0], 2, 8049),
    ([769, 949, 0, 0], 2, 8051),
    ([769, 951, 0, 0], 2, 8053),
    ([769, 953, 0, 0], 2, 8055),
    ([769, 959, 0, 0], 2, 8057),
    ([769, 965, 0, 0], 2, 8059),
    ([769, 969, 0, 0], 2, 8061),
    ([769, 1043, 0, 0], 2, 1027),
    ([769, 1050, 0, 0], 2, 1036),
    ([769, 1075, 0, 0], 2, 1107),
    ([769, 1082, 0, 0], 2, 1116),
    ([769, 8127, 0, 0], 2, 8142),
    ([769, 8190, 0, 0], 2, 8158),
    ([770, 65, 0, 0], 2, 194),
    ([770, 67, 0, 0], 2, 264),
    ([770, 69, 0, 0], 2, 202),
    ([770, 71, 0, 0], 2, 284),
    ([770, 72, 0, 0], 2, 292),
    ([770, 73, 0, 0], 2, 206),
    ([770, 74, 0, 0], 2, 308),
    ([770, 79, 0, 0], 2, 212),
    ([770, 83, 0, 0], 2, 348),
    ([770, 85, 0, 0], 2, 219),
    ([770, 87, 0, 0], 2, 372),
    ([770, 89, 0, 0], 2, 374),
    ([770, 90, 0, 0], 2, 7824),
    ([770, 97, 0, 0], 2, 226),
    ([770, 99, 0, 0], 2, 265),
    ([770, 101, 0, 0], 2, 234),
    ([770, 103, 0, 0], 2, 285),
    ([770, 104, 0, 0], 2, 293),
    ([770, 105, 0, 0], 2, 238),
    ([770, 106, 0, 0], 2, 309),
    ([770, 111, 0, 0], 2, 244),
    ([770, 115, 0, 0], 2, 349),
    ([770, 117, 0, 0], 2, 251),
    ([770, 119, 0, 0], 2, 373),
    ([770, 121, 0, 0], 2, 375),
    ([770, 122, 0, 0], 2, 7825),
    ([770, 803, 65, 0], 3, 7852),
    ([770, 803, 69, 0], 3, 7878),
    ([770, 803, 79, 0], 3, 7896),
    ([770, 803, 97, 0], 3, 7853),
    ([770, 803, 101, 0], 3, 7879),
    ([770, 803, 111, 0], 3, 7897),
    ([771, 65, 0, 0], 2, 195),
    ([771, 69, 0, 0], 2, 7868),
    ([771, 73, 0, 0], 2, 296),
    ([771, 78, 0, 0], 2, 209),
    ([771, 79, 0, 0], 2, 213),
    ([771, 85, 0, 0], 2, 360),
    ([771, 86, 0, 0], 2, 7804),
    ([771, 89, 0, 0], 2, 7928),
    ([771, 97, 0, 0], 2, 227),
    ([771, 101, 0, 0], 2, 7869),
    ([771, 105, 0, 0], 2, 297),
    ([771, 110, 0, 0], 2, 241),
    ([771, 111, 0, 0], 2, 245),
    ([771, 117, 0, 0], 2, 361),
    ([771, 118, 0, 0], 2, 7805),
    ([771, 121, 0, 0], 2, 7929),
    ([771, 770, 65, 0], 3, 7850),
    ([771, 770, 69, 0], 3, 7876),
    ([771, 770, 79, 0], 3, 7894),
    ([771, 770, 97, 0], 3, 7851),
    ([771, 770, 101, 0], 3, 7877),
    ([771, 770, 111, 0], 3, 7895),
    ([771, 774, 65, 0], 3, 7860),
    ([771, 774, 97, 0], 3, 7861),
    ([771, 795, 79, 0], 3, 7904),
    ([771, 795, 85, 0], 3, 7918),
    ([771, 795, 111, 0], 3, 7905),
    ([771, 795, 117, 0], 3, 7919),
    ([772, 65, 0, 0], 2, 256),
    ([772, 69, 0, 0], 2, 274),
    ([772, 71, 0, 0], 2, 7712),
    ([772, 73, 0, 0], 2, 298),
    ([772, 79, 0, 0], 2, 332),
    ([772, 85, 0, 0], 2, 362),
    ([772, 97, 0, 0], 2, 257),
    ([772, 101, 0, 0], 2, 275),
    ([772, 103, 0, 0], 2, 7713),
    ([772, 105, 0, 0], 2, 299),
    ([772, 111, 0, 0], 2, 333),
    ([772, 117, 0, 0], 2, 363),
    ([772, 198, 0, 0], 2, 482),
    ([772, 230, 0, 0], 2, 483),
    ([772, 775, 65, 0], 3, 480),
    ([772, 775, 97, 0], 3, 481),
    ([772, 776, 65, 0], 3, 478),
    ([772, 776, 85, 0], 3, 469),
    ([772, 776, 97, 0], 3, 479),
    ([772, 776, 117, 0], 3, 470),
    ([772, 803, 76, 0], 3, 7736),
    ([772, 803, 82, 0], 3, 7772),
    ([772, 803, 108, 0], 3, 7737),
    ([772, 803, 114, 0], 3, 7773),
    ([772, 808, 79, 0], 3, 492),
    ([772, 808, 111, 0], 3, 493),
    ([772, 913, 0, 0], 2, 8121),
    ([772, 921, 0, 0], 2, 8153),
    ([772, 933, 0, 0], 2, 8169),
    ([772, 945, 0, 0], 2, 8113),
    ([772, 953, 0, 0], 2, 8145),
    ([772, 965, 0, 0], 2, 8161),
    ([772, 1048, 0, 0], 2, 1250),
    ([772, 1059, 0, 0], 2, 1262),
    ([772, 1080, 0, 0], 2, 1251),
    ([772, 1091, 0, 0], 2, 1263),
    ([774, 65, 0, 0], 2, 258),
    ([774, 69, 0, 0], 2, 276),
    ([774, 71, 0, 0], 2, 286),
    ([774, 73, 0, 0], 2, 300),
    ([774, 79, 0, 0], 2, 334),
    ([774, 85, 0, 0], 2, 364),
    ([774, 97, 0, 0], 2, 259),
    ([774, 101, 0, 0], 2, 277),
    ([774, 103, 0, 0], 2, 287),
    ([774, 105, 0, 0], 2, 301),
    ([774, 111, 0, 0], 2, 335),
    ([774, 117, 0, 0], 2, 365),
    ([774, 803, 65, 0], 3, 7862),
    ([774, 803, 97, 0], 3, 7863),
    ([774, 807, 69, 0], 3, 7708),
    ([774, 807, 101, 0], 3, 7709),
    ([774, 913, 0, 0], 2, 8120),
    ([774, 921, 0, 0], 2, 8152),
    ([774, 933, 0, 0], 2, 8168),
    ([774, 945, 0, 0], 2, 8112),
    ([774, 953, 0, 0], 2, 8144),
    ([774, 965, 0, 0], 2, 8160),
    ([774, 1040, 0, 0], 2, 1232),
    ([774, 1045, 0, 0], 2, 1238),
    ([774, 1046, 0, 0], 2, 1217),
    ([774, 1048, 0, 0], 2, 1049),
    ([774, 1059, 0, 0], 2, 1038),
    ([774, 1072, 0, 0], 2, 1233),
    ([774, 1077, 0, 0], 2, 1239),
    ([774, 1078, 0, 0], 2, 1218),
    ([774, 1080, 0, 0], 2, 1081),
    ([774, 1091, 0, 0], 2, 1118),
    ([775, 66, 0, 0], 2, 7682),
    ([775, 67, 0, 0], 2, 266),
    ([775, 68, 0, 0], 2, 7690),
    ([775, 69, 0, 0], 2, 278),
    ([775, 70, 0, 0], 2, 7710),
    ([775, 71, 0, 0], 2, 288),
    ([775, 72, 0, 0], 2, 7714),
    ([775, 73, 0, 0], 2, 304),
    ([775, 77, 0, 0], 2, 7744),
    ([775, 78, 0, 0], 2, 7748),
    ([775, 80, 0, 0], 2, 7766),
    ([775, 82, 0, 0], 2, 7768),
    ([775, 83, 0, 0], 2, 7776),
    ([775, 84, 0, 0], 2, 7786),
    ([775, 87, 0, 0], 2, 7814),
    ([775, 88, 0, 0], 2, 7818),
    ([775, 89, 0, 0], 2, 7822),
    ([775, 90, 0, 0], 2, 379),
    ([775, 98, 0, 0], 2, 7683),
    ([775, 99, 0, 0], 2, 267),
    ([775, 100, 0, 0], 2, 7691),
    ([775, 101, 0, 0], 2, 279),
    ([775, 102, 0, 0], 2, 7711),
    ([775, 103, 0, 0], 2, 289),
    ([775, 104, 0, 0], 2, 7715),
    ([775, 109, 0, 0], 2, 7745),
    ([775, 110, 0, 0], 2, 7749),
    ([775, 112, 0, 0], 2, 7767),
    ([775, 114, 0, 0], 2, 7769),
    ([775, 115, 0, 0], 2, 7777),
    ([775, 116, 0, 0], 2, 7787),
    ([775, 119, 0, 0], 2, 7815),
    ([775, 120, 0, 0], 2, 7819),
    ([775, 121, 0, 0], 2, 7823),
    ([775, 122, 0, 0], 2, 380),
    ([775, 383, 0, 0], 2, 7835),
    ([775, 769, 83, 0], 3, 7780),
    ([775, 769, 115, 0], 3, 7781),
    ([775, 774, 0, 0], 2, 784),
    ([775, 780, 83, 0], 3, 7782),
    ([775, 780, 115, 0], 3, 7783),
    ([775, 803, 83, 0], 3, 7784),
    ([775, 803, 115, 0], 3, 7785),
    ([776, 65, 0, 0], 2, 196),
    ([776, 69, 0, 0], 2, 203),
    ([776, 72, 0, 0], 2, 7718),
    ([776, 73, 0, 0], 2, 207),
    ([776, 79, 0, 0], 2, 214),
    ([776, 85, 0, 0], 2, 220),
    ([776, 87, 0, 0], 2, 7812),
    ([776, 88, 0, 0], 2, 7820),
    ([776, 89, 0, 0], 2, 376),
    ([776, 97, 0, 0], 2, 228),
    ([776, 101, 0, 0], 2, 235),
    ([776, 104, 0, 0], 2, 7719),
    ([776, 105, 0, 0], 2, 239),
    ([776, 111, 0, 0], 2, 246),
    ([776, 116, 0, 0], 2, 7831),
    ([776, 117, 0, 0], 2, 252),
    ([776, 119, 0, 0], 2, 7813),
    ([776, 120, 0, 0], 2, 7821),
    ([776, 121, 0, 0], 2, 255),
    ([776, 399, 0, 0], 2, 1242),
    ([776, 415, 0, 0], 2, 1258),
    ([776, 601, 0, 0], 2, 1243),
    ([776, 629, 0, 0], 2, 1259),
    ([776, 771, 79, 0], 3, 7758),
    ([776, 771, 111, 0], 3, 7759),
    ([776, 772, 85, 0], 3, 7802),
    ([776, 772, 117, 0], 3, 7803),
    ([776, 921, 0, 0], 2, 938),
    ([776, 933, 0, 0], 2, 939),
    ([776, 953, 0, 0], 2, 970),
    ([776, 965, 0, 0], 2, 971),
    ([776, 978, 0, 0], 2, 980),
    ([776, 1030, 0, 0], 2, 1031),
    ([776, 1040, 0, 0], 2, 1234),
    ([776, 1045, 0, 0], 2, 1025),
    ([776, 1046, 0, 0], 2, 1244),
    ([776, 1047, 0, 0], 2, 1246),
    ([776, 1048, 0, 0], 2, 1252),
    ([776, 1054, 0, 0], 2, 1254),
    ([776, 1059, 0, 0], 2, 1264),
    ([776, 1063, 0, 0], 2, 1268),
    ([776, 1067, 0, 0], 2, 1272),
    ([776, 1072, 0, 0], 2, 1235),
    ([776, 1077, 0, 0], 2, 1105),
    ([776, 1078, 0, 0], 2, 1245),
    ([776, 1079, 0, 0], 2, 1247),
    ([776, 1080, 0, 0], 2, 1253),
    ([776, 1086, 0, 0], 2, 1255),
    ([776, 1091, 0, 0], 2, 1265),
    ([776, 1095, 0, 0], 2, 1269),
    ([776, 1099, 0, 0], 2, 1273),
    ([776, 1110, 0, 0], 2, 1111),
    ([777, 65, 0, 0], 2, 7842),
    ([777, 69, 0, 0], 2, 7866),
    ([777, 73, 0, 0], 2, 7880),
    ([777, 79, 0, 0], 2, 7886),
    ([777, 85, 0, 0], 2, 7910),
    ([777, 89, 0, 0], 2, 7926),
    ([777, 97, 0, 0], 2, 7843),
    ([777, 101, 0, 0], 2, 7867),
    ([777, 105, 0, 0], 2, 7881),
    ([777, 111, 0, 0], 2, 7887),
    ([777, 117, 0, 0], 2, 7911),
    ([777, 121, 0, 0], 2, 7927),
    ([777, 770, 65, 0], 3, 7848),
    ([777, 770, 69, 0], 3, 7874),
    ([777, 770, 79, 0], 3, 7892),
    ([777, 770, 97, 0], 3, 7849),
    ([777, 770, 101, 0], 3, 7875),
    ([777, 770, 111, 0], 3, 7893),
    ([777, 774, 65, 0], 3, 7858),
    ([777, 774, 97, 0], 3, 7859),
    ([777, 795, 79, 0], 3, 7902),
    ([777, 795, 85, 0], 3, 7916),
    ([777, 795, 111, 0], 3, 7903),
    ([777, 795, 117, 0], 3, 7917),
    ([778, 65, 0, 0], 2, 197),
    ([778, 85, 0, 0], 2, 366),
    ([778, 97, 0, 0], 2, 229),
    ([778, 117, 0, 0], 2, 367),
    ([778, 119, 0, 0], 2, 7832),
    ([778, 121, 0, 0], 2, 7833),
    ([779, 79, 0, 0], 2, 336),
    ([779, 85, 0, 0], 2, 368),
    ([779, 111, 0, 0], 2, 337),
    ([779, 117, 0, 0], 2, 369),
    ([779, 1059, 0, 0], 2, 1266),
    ([779, 1091, 0, 0], 2, 1267),
    ([780, 65, 0, 0], 2, 461),
    ([780, 67, 0, 0], 2, 268),
    ([780, 68, 0, 0], 2, 270),
    ([780, 69, 0, 0], 2, 282),
    ([780, 71, 0, 0], 2, 486),
    ([780, 73, 0, 0], 2, 463),
    ([780, 75, 0, 0], 2, 488),
    ([780, 76, 0, 0], 2, 317),
    ([780, 78, 0, 0], 2, 327),
    ([780, 79, 0, 0], 2, 465),
    ([780, 82, 0, 0], 2, 344),
    ([780, 83, 0, 0], 2, 352),
    ([780, 84, 0, 0], 2, 356),
    ([780, 85, 0, 0], 2, 467),
    ([780, 90, 0, 0], 2, 381),
    ([780, 97, 0, 0], 2, 462),
    ([780, 99, 0, 0], 2, 269),
    ([780, 100, 0, 0], 2, 271),
    ([780, 101, 0, 0], 2, 283),
    ([780, 103, 0, 0], 2, 487),
    ([780, 105, 0, 0], 2, 464),
    ([780, 106, 0, 0], 2, 496),
    ([780, 107, 0, 0], 2, 489),
    ([780, 108, 0, 0], 2, 318),
    ([780, 110, 0, 0], 2, 328),
    ([780, 111, 0, 0], 2, 466),
    ([780, 114, 0, 0], 2, 345),
    ([780, 115, 0, 0], 2, 353),
    ([780, 116, 0, 0], 2, 357),
    ([780, 117, 0, 0], 2, 468),
    ([780, 122, 0, 0], 2, 382),
    ([780, 439, 0, 0], 2, 494),
    ([780, 658, 0, 0], 2, 495),
    ([780, 776, 85, 0], 3, 473),
    ([780, 776, 117, 0], 3, 474),
    ([781, 168, 0, 0], 2, 901),
    ([781, 776, 953, 0], 3, 912),
    ([781, 776, 965, 0], 3, 944),
    ([781, 913, 0, 0], 2, 902),
    ([781, 917, 0, 0], 2, 904),
    ([781, 919, 0, 0], 2, 905),
    ([781, 921, 0, 0], 2, 906),
    ([781, 927, 0, 0], 2, 908),
    ([781, 933, 0, 0], 2, 910),
    ([781, 937, 0, 0], 2, 911),
    ([781, 945, 0, 0], 2, 940),
    ([781, 949, 0, 0], 2, 941),
    ([781, 951, 0, 0], 2, 942),
    ([781, 953, 0, 0], 2, 943),
    ([781, 959, 0, 0], 2, 972),
    ([781, 965, 0, 0], 2, 973),
    ([781, 969, 0, 0], 2, 974),
    ([781, 978, 0, 0], 2, 979),
    ([783, 65, 0, 0], 2, 512),
    ([783, 69, 0, 0], 2, 516),
    ([783, 73, 0, 0], 2, 520),
    ([783, 79, 0, 0], 2, 524),
    ([783, 82, 0, 0], 2, 528),
    ([783, 85, 0, 0], 2, 532),
    ([783, 97, 0, 0], 2, 513),
    ([783, 101, 0, 0], 2, 517),
    ([783, 105, 0, 0], 2, 521),
    ([783, 111, 0, 0], 2, 525),
    ([783, 114, 0, 0], 2, 529),
    ([783, 117, 0, 0], 2, 533),
    ([783, 1140, 0, 0], 2, 1142),
    ([783, 1141, 0, 0], 2, 1143),
    ([785, 65, 0, 0], 2, 514),
    ([785, 69, 0, 0], 2, 518),
    ([785, 73, 0, 0], 2, 522),
    ([785, 79, 0, 0], 2, 526),
    ([785, 82, 0, 0], 2, 530),
    ([785, 85, 0, 0], 2, 534),
    ([785, 97, 0, 0], 2, 515),
    ([785, 101, 0, 0], 2, 519),
    ([785, 105, 0, 0], 2, 523),
    ([785, 111, 0, 0], 2, 527),
    ([785, 114, 0, 0], 2, 531),
    ([785, 117, 0, 0], 2, 535),
    ([787, 837, 913, 0], 3, 8072),
    ([787, 837, 919, 0], 3, 8088),
    ([787, 837, 937, 0], 3, 8104),
    ([787, 837, 945, 0], 3, 8064),
    ([787, 837, 951, 0], 3, 8080),
    ([787, 837, 969, 0], 3, 8096),
    ([787, 913, 0, 0], 2, 7944),
    ([787, 917, 0, 0], 2, 7960),
    ([787, 919, 0, 0], 2, 7976),
    ([787, 921, 0, 0], 2, 7992),
    ([787, 927, 0, 0], 2, 8008),
    ([787, 937, 0, 0], 2, 8040),
    ([787, 945, 0, 0], 2, 7936),
    ([787, 949, 0, 0], 2, 7952),
    ([787, 951, 0, 0], 2, 7968),
    ([787, 953, 0, 0], 2, 7984),
    ([787, 959, 0, 0], 2, 8000),
    ([787, 961, 0, 0], 2, 8164),
    ([787, 965, 0, 0], 2, 8016),
    ([787, 969, 0, 0], 2, 8032),
    ([788, 837, 913, 0], 3, 8073),
    ([788, 837, 919, 0], 3, 8089),
    ([788, 837, 937, 0], 3, 8105),
    ([788, 837, 945, 0], 3, 8065),
    ([788, 837, 951, 0], 3, 8081),
    ([788, 837, 969, 0], 3, 8097),
    ([788, 913, 0, 0], 2, 7945),
    ([788, 917, 0, 0], 2, 7961),
    ([788, 919, 0, 0], 2, 7977),
    ([788, 921, 0, 0], 2, 7993),
    ([788, 927, 0, 0], 2, 8009),
    ([788, 929, 0, 0], 2, 8172),
    ([788, 933, 0, 0], 2, 8025),
    ([788, 937, 0, 0], 2, 8041),
    ([788, 945, 0, 0], 2, 7937),
    ([788, 949, 0, 0], 2, 7953),
    ([788, 951, 0, 0], 2, 7969),
    ([788, 953, 0, 0], 2, 7985),
    ([788, 959, 0, 0], 2, 8001),
    ([788, 961, 0, 0], 2, 8165),
    ([788, 965, 0, 0], 2, 8017),
    ([788, 969, 0, 0], 2, 8033),
    ([795, 79, 0, 0], 2, 416),
    ([795, 85, 0, 0], 2, 431),
    ([795, 111, 0, 0], 2, 417),
    ([795, 117, 0, 0], 2, 432),
    ([803, 65, 0, 0], 2, 7840),
    ([803, 66, 0, 0], 2, 7684),
    ([803, 68, 0, 0], 2, 7692),
    ([803, 69, 0, 0], 2, 7864),
    ([803, 72, 0, 0], 2, 7716),
    ([803, 73, 0, 0], 2, 7882),
    ([803, 75, 0, 0], 2, 7730),
    ([803, 76, 0, 0], 2, 7734),
    ([803, 77, 0, 0], 2, 7746),
    ([803, 78, 0, 0], 2, 7750),
    ([803, 79, 0, 0], 2, 7884),
    ([803, 82, 0, 0], 2, 7770),
    ([803, 83, 0, 0], 2, 7778),
    ([803, 84, 0, 0], 2, 7788),
    ([803, 85, 0, 0], 2, 7908),
    ([803, 86, 0, 0], 2, 7806),
    ([803, 87, 0, 0], 2, 7816),
    ([803, 89, 0, 0], 2, 7924),
    ([803, 90, 0, 0], 2, 7826),
    ([803, 97, 0, 0], 2, 7841),
    ([803, 98, 0, 0], 2, 7685),
    ([803, 100, 0, 0], 2, 7693),
    ([803, 101, 0, 0], 2, 7865),
    ([803, 104, 0, 0], 2, 7717),
    ([803, 105, 0, 0], 2, 7883),
    ([803, 107, 0, 0], 2, 7731),
    ([803, 108, 0, 0], 2, 7735),
    ([803, 109, 0, 0], 2, 7747),
    ([803, 110, 0, 0], 2, 7751),
    ([803, 111, 0, 0], 2, 7885),
    ([803, 114, 0, 0], 2, 7771),
    ([803, 115, 0, 0], 2, 7779),
    ([803, 116, 0, 0], 2, 7789),
    ([803, 117, 0, 0], 2, 7909),
    ([803, 118, 0, 0], 2, 7807),
    ([803, 119, 0, 0], 2, 7817),
    ([803, 121, 0, 0], 2, 7925),
    ([803, 122, 0, 0], 2, 7827),
    ([803, 795, 79, 0], 3, 7906),
    ([803, 795, 85, 0], 3, 7920),
    ([803, 795, 111, 0], 3, 7907),
    ([803, 795, 117, 0], 3, 7921),
    ([804, 85, 0, 0], 2, 7794),
    ([804, 117, 0, 0], 2, 7795),
    ([805, 65, 0, 0], 2, 7680),
    ([805, 97, 0, 0], 2, 7681),
    ([807, 67, 0, 0], 2, 199),
    ([807, 68, 0, 0], 2, 7696),
    ([807, 71, 0, 0], 2, 290),
    ([807, 72, 0, 0], 2, 7720),
    ([807, 75, 0, 0], 2, 310),
    ([807, 76, 0, 0], 2, 315),
    ([807, 78, 0, 0], 2, 325),
    ([807, 82, 0, 0], 2, 342),
    ([807, 83, 0, 0], 2, 350),
    ([807, 84, 0, 0], 2, 354),
    ([807, 99, 0, 0], 2, 231),
    ([807, 100, 0, 0], 2, 7697),
    ([807, 103, 0, 0], 2, 291),
    ([807, 104, 0, 0], 2, 7721),
    ([807, 107, 0, 0], 2, 311),
    ([807, 108, 0, 0], 2, 316),
    ([807, 110, 0, 0], 2, 326),
    ([807, 114, 0, 0], 2, 343),
    ([807, 115, 0, 0], 2, 351),
    ([807, 116, 0, 0], 2, 355),
    ([808, 65, 0, 0], 2, 260),
    ([808, 69, 0, 0], 2, 280),
    ([808, 73, 0, 0], 2, 302),
    ([808, 79, 0, 0], 2, 490),
    ([808, 85, 0, 0], 2, 370),
    ([808, 97, 0, 0], 2, 261),
    ([808, 101, 0, 0], 2, 281),
    ([808, 105, 0, 0], 2, 303),
    ([808, 111, 0, 0], 2, 491),
    ([808, 117, 0, 0], 2, 371),
    ([813, 68, 0, 0], 2, 7698),
    ([813, 69, 0, 0], 2, 7704),
    ([813, 76, 0, 0], 2, 7740),
    ([813, 78, 0, 0], 2, 7754),
    ([813, 84, 0, 0], 2, 7792),
    ([813, 85, 0, 0], 2, 7798),
    ([813, 100, 0, 0], 2, 7699),
    ([813, 101, 0, 0], 2, 7705),
    ([813, 108, 0, 0], 2, 7741),
    ([813, 110, 0, 0], 2, 7755),
    ([813, 116, 0, 0], 2, 7793),
    ([813, 117, 0, 0], 2, 7799),
    ([814, 72, 0, 0], 2, 7722),
    ([814, 104, 0, 0], 2, 7723),
    ([816, 69, 0, 0], 2, 7706),
    ([816, 73, 0, 0], 2, 7724),
    ([816, 85, 0, 0], 2, 7796),
    ([816, 101, 0, 0], 2, 7707),
    ([816, 105, 0, 0], 2, 7725),
    ([816, 117, 0, 0], 2, 7797),
    ([817, 66, 0, 0], 2, 7686),
    ([817, 68, 0, 0], 2, 7694),
    ([817, 75, 0, 0], 2, 7732),
    ([817, 76, 0, 0], 2, 7738),
    ([817, 78, 0, 0], 2, 7752),
    ([817, 82, 0, 0], 2, 7774),
    ([817, 84, 0, 0], 2, 7790),
    ([817, 90, 0, 0], 2, 7828),
    ([817, 98, 0, 0], 2, 7687),
    ([817, 100, 0, 0], 2, 7695),
    ([817, 104, 0, 0], 2, 7830),
    ([817, 107, 0, 0], 2, 7733),
    ([817, 108, 0, 0], 2, 7739),
    ([817, 110, 0, 0], 2, 7753),
    ([817, 114, 0, 0], 2, 7775),
    ([817, 116, 0, 0], 2, 7791),
    ([817, 122, 0, 0], 2, 7829),
    ([834, 168, 0, 0], 2, 8129),
    ([834, 776, 953, 0], 3, 8151),
    ([834, 776, 965, 0], 3, 8167),
    ([834, 787, 837, 913], 4, 8078),
    ([834, 787, 837, 919], 4, 8094),
    ([834, 787, 837, 937], 4, 8110),
    ([834, 787, 837, 945], 4, 8070),
    ([834, 787, 837, 951], 4, 8086),
    ([834, 787, 837, 969], 4, 8102),
    ([834, 787, 913, 0], 3, 7950),
    ([834, 787, 919, 0], 3, 7982),
    ([834, 787, 921, 0], 3, 7998),
    ([834, 787, 937, 0], 3, 8046),
    ([834, 787, 945, 0], 3, 7942),
    ([834, 787, 951, 0], 3, 7974),
    ([834, 787, 953, 0], 3, 7990),
    ([834, 787, 965, 0], 3, 8022),
    ([834, 787, 969, 0], 3, 8038),
    ([834, 788, 837, 913], 4, 8079),
    ([834, 788, 837, 919], 4, 8095),
    ([834, 788, 837, 937], 4, 8111),
    ([834, 788, 837, 945], 4, 8071),
    ([834, 788, 837, 951], 4, 8087),
    ([834, 788, 837, 969], 4, 8103),
    ([834, 788, 913, 0], 3, 7951),
    ([834, 788, 919, 0], 3, 7983),
    ([834, 788, 921, 0], 3, 7999),
    ([834, 788, 933, 0], 3, 8031),
    ([834, 788, 937, 0], 3, 8047),
    ([834, 788, 945, 0], 3, 7943),
    ([834, 788, 951, 0], 3, 7975),
    ([834, 788, 953, 0], 3, 7991),
    ([834, 788, 965, 0], 3, 8023),
    ([834, 788, 969, 0], 3, 8039),
    ([834, 837, 945, 0], 3, 8119),
    ([834, 837, 951, 0], 3, 8135),
    ([834, 837, 969, 0], 3, 8183),
    ([834, 945, 0, 0], 2, 8118),
    ([834, 951, 0, 0], 2, 8134),
    ([834, 953, 0, 0], 2, 8150),
    ([834, 965, 0, 0], 2, 8166),
    ([834, 969, 0, 0], 2, 8182),
    ([834, 8127, 0, 0], 2, 8143),
    ([834, 8190, 0, 0], 2, 8159),
    ([837, 913, 0, 0], 2, 8124),
    ([837, 919, 0, 0], 2, 8140),
    ([837, 937, 0, 0], 2, 8188),
    ([837, 945, 0, 0], 2, 8115),
    ([837, 951, 0, 0], 2, 8131),
    ([837, 969, 0, 0], 2, 8179),
    ([1463, 1488, 0, 0], 2, 64302),
    ([1463, 1522, 0, 0], 2, 64287),
    ([1464, 1488, 0, 0], 2, 64303),
    ([1465, 1493, 0, 0], 2, 64331),
    ([1468, 1488, 0, 0], 2, 64304),
    ([1468, 1489, 0, 0], 2, 64305),
    ([1468, 1490, 0, 0], 2, 64306),
    ([1468, 1491, 0, 0], 2, 64307),
    ([1468, 1492, 0, 0], 2, 64308),
    ([1468, 1493, 0, 0], 2, 64309),
    ([1468, 1494, 0, 0], 2, 64310),
    ([1468, 1496, 0, 0], 2, 64312),
    ([1468, 1497, 0, 0], 2, 64313),
    ([1468, 1498, 0, 0], 2, 64314),
    ([1468, 1499, 0, 0], 2, 64315),
    ([1468, 1500, 0, 0], 2, 64316),
    ([1468, 1502, 0, 0], 2, 64318),
    ([1468, 1504, 0, 0], 2, 64320),
    ([1468, 1505, 0, 0], 2, 64321),
    ([1468, 1507, 0, 0], 2, 64323),
    ([1468, 1508, 0, 0], 2, 64324),
    ([1468, 1510, 0, 0], 2, 64326),
    ([1468, 1511, 0, 0], 2, 64327),
    ([1468, 1512, 0, 0], 2, 64328),
    ([1468, 1513, 0, 0], 2, 64329),
    ([1468, 1514, 0, 0], 2, 64330),
    ([1471, 1489, 0, 0], 2, 64332),
    ([1471, 1499, 0, 0], 2, 64333),
    ([1471, 1508, 0, 0], 2, 64334),
    ([1473, 1468, 1513, 0], 3, 64300),
    ([1473, 1513, 0, 0], 2, 64298),
    ([1474, 1468, 1513, 0], 3, 64301),
    ([1474, 1513, 0, 0], 2, 64299),
    ([2364, 2325, 0, 0], 2, 2392),
    ([2364, 2326, 0, 0], 2, 2393),
    ([2364, 2327, 0, 0], 2, 2394),
    ([2364, 2332, 0, 0], 2, 2395),
    ([2364, 2337, 0, 0], 2, 2396),
    ([2364, 2338, 0, 0], 2, 2397),
    ([2364, 2344, 0, 0], 2, 2345),
    ([2364, 2347, 0, 0], 2, 2398),
    ([2364, 2351, 0, 0], 2, 2399),
    ([2364, 2352, 0, 0], 2, 2353),
    ([2364, 2355, 0, 0], 2, 2356),
    ([2492, 2465, 0, 0], 2, 2524),
    ([2492, 2466, 0, 0], 2, 2525),
    ([2492, 2476, 0, 0], 2, 2480),
    ([2492, 2479, 0, 0], 2, 2527),
    ([2494, 2503, 0, 0], 2, 2507),
    ([2519, 2503, 0, 0], 2, 2508),
    ([2620, 2582, 0, 0], 2, 2649),
    ([2620, 2583, 0, 0], 2, 2650),
    ([2620, 2588, 0, 0], 2, 2651),
    ([2620, 2593, 0, 0], 2, 2652),
    ([2620, 2603, 0, 0], 2, 2654),
    ([2876, 2849, 0, 0], 2, 2908),
    ([2876, 2850, 0, 0], 2, 2909),
    ([2876, 2863, 0, 0], 2, 2911),
    ([2878, 2887, 0, 0], 2, 2891),
    ([2902, 2887, 0, 0], 2, 2888),
    ([2903, 2887, 0, 0], 2, 2892),
    ([3006, 3014, 0, 0], 2, 3018),
    ([3006, 3015, 0, 0], 2, 3019),
    ([3031, 2962, 0, 0], 2, 2964),
    ([3031, 3014, 0, 0], 2, 3020),
    ([3158, 3142, 0, 0], 2, 3144),
    ([3266, 3270, 0, 0], 2, 3274),
    ([3285, 3263, 0, 0], 2, 3264),
    ([3285, 3266, 3270, 0], 3, 3275),
    ([3285, 3270, 0, 0], 2, 3271),
    ([3286, 3270, 0, 0], 2, 3272),
    ([3390, 3398, 0, 0], 2, 3402),
    ([3390, 3399, 0, 0], 2, 3403),
    ([3415, 3398, 0, 0], 2, 3404),
    ([3634, 3661, 0, 0], 2, 3635),
    ([3762, 3789, 0, 0], 2, 3763),
    ([3953, 3954, 0, 0], 2, 3955),
    ([3953, 3956, 0, 0], 2, 3957),
    ([3953, 3968, 4018, 0], 3, 3959),
    ([3953, 3968, 4019, 0], 3, 3961),
    ([3968, 4018, 0, 0], 2, 3958),
    ([3968, 4019, 0, 0], 2, 3960),
    ([4021, 3904, 0, 0], 2, 3945),
    ([4021, 3984, 0, 0], 2, 4025),
    ([4023, 3906, 0, 0], 2, 3907),
    ([4023, 3916, 0, 0], 2, 3917),
    ([4023, 3921, 0, 0], 2, 3922),
    ([4023, 3926, 0, 0], 2, 3927),
    ([4023, 3931, 0, 0], 2, 3932),
    ([4023, 3986, 0, 0], 2, 3987),
    ([4023, 3996, 0, 0], 2, 3997),
    ([4023, 4001, 0, 0], 2, 4002),
    ([4023, 4006, 0, 0], 2, 4007),
    ([4023, 4011, 0, 0], 2, 4012),
    ([12441, 12358, 0, 0], 2, 12436),
    ([12441, 12363, 0, 0], 2, 12364),
    ([12441, 12365, 0, 0], 2, 12366),
    ([12441, 12367, 0, 0], 2, 12368),
    ([12441, 12369, 0, 0], 2, 12370),
    ([12441, 12371, 0, 0], 2, 12372),
    ([12441, 12373, 0, 0], 2, 12374),
    ([12441, 12375, 0, 0], 2, 12376),
    ([12441, 12377, 0, 0], 2, 12378),
    ([12441, 12379, 0, 0], 2, 12380),
    ([12441, 12381, 0, 0], 2, 12382),
    ([12441, 12383, 0, 0], 2, 12384),
    ([12441, 12385, 0, 0], 2, 12386),
    ([12441, 12388, 0, 0], 2, 12389),
    ([12441, 12390, 0, 0], 2, 12391),
    ([12441, 12392, 0, 0], 2, 12393),
    ([12441, 12399, 0, 0], 2, 12400),
    ([12441, 12402, 0, 0], 2, 12403),
    ([12441, 12405, 0, 0], 2, 12406),
    ([12441, 12408, 0, 0], 2, 12409),
    ([12441, 12411, 0, 0], 2, 12412),
    ([12441, 12445, 0, 0], 2, 12446),
    ([12441, 12454, 0, 0], 2, 12532),
    ([12441, 12459, 0, 0], 2, 12460),
    ([12441, 12461, 0, 0], 2, 12462),
    ([12441, 12463, 0, 0], 2, 12464),
    ([12441, 12465, 0, 0], 2, 12466),
    ([12441, 12467, 0, 0], 2, 12468),
    ([12441, 12469, 0, 0], 2, 12470),
    ([12441, 12471, 0, 0], 2, 12472),
    ([12441, 12473, 0, 0], 2, 12474),
    ([12441, 12475, 0, 0], 2, 12476),
    ([12441, 12477, 0, 0], 2, 12478),
    ([12441, 12479, 0, 0], 2, 12480),
    ([12441, 12481, 0, 0], 2, 12482),
    ([12441, 12484, 0, 0], 2, 12485),
    ([12441, 12486, 0, 0], 2, 12487),
    ([12441, 12488, 0, 0], 2, 12489),
    ([12441, 12495, 0, 0], 2, 12496),
    ([12441, 12498, 0, 0], 2, 12499),
    ([12441, 12501, 0, 0], 2, 12502),
    ([12441, 12504, 0, 0], 2, 12505),
    ([12441, 12507, 0, 0], 2, 12508),
    ([12441, 12527, 0, 0], 2, 12535),
    ([12441, 12528, 0, 0], 2, 12536),
    ([12441, 12529, 0, 0], 2, 12537),
    ([12441, 12530, 0, 0], 2, 12538),
    ([12441, 12541, 0, 0], 2, 12542),
    ([12442, 12399, 0, 0], 2, 12401),
    ([12442, 12402, 0, 0], 2, 12404),
    ([12442, 12405, 0, 0], 2, 12407),
    ([12442, 12408, 0, 0], 2, 12410),
    ([12442, 12411, 0, 0], 2, 12413),
    ([12442, 12495, 0, 0], 2, 12497),
    ([12442, 12498, 0, 0], 2, 12500),
    ([12442, 12501, 0, 0], 2, 12503),
    ([12442, 12504, 0, 0], 2, 12506),
    ([12442, 12507, 0, 0], 2, 12509),
];

crate::word_bif_bodies_in!(word_bodies;
    characters_to_binary,
    characters_to_list,
    internal_name2native,
    internal_native2name,
    internal_normalize_utf8,
    is_translatable,
    native_name_encoding,
    printable_range,
);
