//! The one term printer: the `%T` conversion of `erts_printf`.
//!
//! Port of erts/emulator/beam/erl_printf_term.c (`erts_printf_term`, `print_term`,
//! `print_atom_name`, `is_printable_string`), OTP-29.1.1, and of the `FMTC_T` case of
//! erts/lib_src/common/erl_printf_format.c that maps the printf precision to the print
//! budget. Output is raw bytes (Latin-1 list elements are written as single bytes), pushed
//! to a `Vec<u8>` where erts calls its `fmtfn_t`; truncation to a buffer (`erts_vsnprintf`)
//! is the caller's.

use crate::raw::{self, BinRef, Cons, Tuple};
use crate::{Atom, FunRef, Identity, Term, TermKind, global_atoms, hamt, this_node};

/// `MAX_ATOM_SZ_LIMIT` of erts/emulator/beam/global.h: the temporary budget used to print
/// the module and function of an export fun in one piece.
const MAX_ATOM_SZ_LIMIT: i64 = 255 * 4;

/// `%T` with `precision` as passed to printf: the `FMTC_T` mapping of the precision to the
/// print budget (`-1`, no precision, is 100000; `INT_MAX` is unlimited).
// Port of erts/lib_src/common/erl_printf_format.c (erts_printf_format, FMTC_T), OTP-29.1.1.
pub fn erts_printf_t(out: &mut Vec<u8>, term: Term, precision: i32) {
    let budget = if precision < 0 {
        100_000
    } else if precision == i32::MAX {
        i64::MAX
    } else {
        i64::from(precision)
    };
    erts_printf_term(out, term, budget);
}

/// Print `term` with a budget of `precision` units; an exhausted budget ends the output with
/// `"... "`.
// Port of erts/emulator/beam/erl_printf_term.c (erts_printf_term), OTP-29.1.1.
pub fn erts_printf_term(out: &mut Vec<u8>, term: Term, precision: i64) {
    let mut dcount = precision;
    print_term(out, term, &mut dcount);
    if dcount <= 0 {
        out.extend_from_slice(b"... ");
    }
}

/// `IS_LOWER` with `LATIN1` defined.
fn is_lower(c: u32) -> bool {
    (u32::from(b'a')..=u32::from(b'z')).contains(&c) || ((128 + 95)..=255).contains(&c) && c != 247
}

/// `IS_UPPER` with `LATIN1` defined.
fn is_upper(c: u32) -> bool {
    (u32::from(b'A')..=u32::from(b'Z')).contains(&c)
        || ((128 + 64)..=(128 + 94)).contains(&c) && c != 247 - 32
}

/// `IS_ALNUM`.
fn is_alnum(c: u32) -> bool {
    (u32::from(b'0')..=u32::from(b'9')).contains(&c) || is_lower(c) || is_upper(c)
}

/// Whether `list` is a non-empty flat list of printable Latin-1 characters.
// Port of erts/emulator/beam/erl_printf_term.c (is_printable_string), OTP-29.1.1.
fn is_printable_string(list: Term) -> bool {
    let mut rest = list;
    let mut len = 0usize;
    while let Ok(cons) = Cons::try_from(rest) {
        let Some(c) = cons.head().as_small().and_then(|v| u8::try_from(v).ok()) else {
            return false;
        };
        let cntrl = c < b' ' || c == 127 || (128..128 + 32).contains(&c);
        let space = matches!(c, b' ' | b'\n' | b'\t' | b'\r');
        if cntrl && !space {
            return false;
        }
        len += 1;
        rest = cons.tail();
    }
    rest == Term::NIL && len > 0
}

/// The octet `index` of a bit string that starts `bitoffs` bits into `bytes`.
fn octet_at(bytes: &[u8], bitoffs: usize, index: usize) -> u8 {
    if bitoffs == 0 {
        bytes[index]
    } else {
        (bytes[index] << bitoffs) | (bytes[index + 1] >> (8 - bitoffs))
    }
}

/// `is_printable_ascii` over `bytesize` octets.
// Port of erts/emulator/beam/erl_printf_term.c (is_printable_ascii), OTP-29.1.1.
fn is_printable_ascii(bytes: &[u8], bytesize: usize, bitoffs: usize) -> bool {
    (0..bytesize).all(|i| {
        let octet = octet_at(bytes, bitoffs, i);
        (b' '..127).contains(&octet)
    })
}

/// Print an atom, quoting it if necessary. The budget is charged the atom's byte length.
// Port of erts/emulator/beam/erl_printf_term.c (print_atom_name), OTP-29.1.1.
fn print_atom_name(out: &mut Vec<u8>, atom: Atom, dcount: &mut i64) {
    let Some(text) = global_atoms().text(atom) else {
        out.extend_from_slice(format!("<bad atom index: {}>", atom.0).as_bytes());
        return;
    };
    *dcount -= text.len() as i64;
    let mut chars = text.chars().map(u32::from);
    let Some(first) = chars.next() else {
        out.extend_from_slice(b"''");
        return;
    };
    // Quoting is needed unless the first character is a Latin-1 lowercase letter and the rest
    // are Latin-1 alphanumerics or '_'.
    let need_quote = !is_lower(first) || chars.any(|c| !is_alnum(c) && c != u32::from(b'_'));
    if need_quote {
        out.push(b'\'');
    }
    for c in text.chars() {
        match c {
            '\'' => out.extend_from_slice(b"\\'"),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\n' => out.extend_from_slice(b"\\n"),
            '\u{c}' => out.extend_from_slice(b"\\f"),
            '\t' => out.extend_from_slice(b"\\t"),
            '\r' => out.extend_from_slice(b"\\r"),
            '\u{8}' => out.extend_from_slice(b"\\b"),
            '\u{b}' => out.extend_from_slice(b"\\v"),
            c if u32::from(c) < 32 || (128..=159).contains(&u32::from(c)) => {
                out.extend_from_slice(format!("\\{:03o}", u32::from(c)).as_bytes());
            }
            c => {
                let mut buffer = [0; 4];
                out.extend_from_slice(c.encode_utf8(&mut buffer).as_bytes());
            }
        }
    }
    if need_quote {
        out.push(b'\'');
    }
}

/// `%e` with precision 6, the way C prints a double.
fn print_double(out: &mut Vec<u8>, value: f64) {
    let formatted = format!("{value:.6e}");
    let (mantissa, exponent) = formatted.split_once('e').unwrap_or((&formatted, "0"));
    let exponent: i32 = exponent.parse().unwrap_or(0);
    let text = format!(
        "{mantissa}e{}{:02}",
        if exponent < 0 { '-' } else { '+' },
        exponent.abs()
    );
    out.extend_from_slice(text.as_bytes());
}

/// `dist_entry_channel_no`: 0 for this node (and its earlier incarnations), the atom index of
/// the node name for any other node.
// Port of erts/emulator/beam/erl_node_container_utils.h (dist_entry_channel_no), OTP-29.1.1.
fn channel_no(node: Atom) -> u64 {
    if node == this_node().0 {
        0
    } else {
        u64::from(node.0)
    }
}

/// The work stack items of `print_term` (`PRT_*`).
#[derive(Clone, Copy)]
enum Prt<'h> {
    Bar,
    Comma,
    CloseList,
    CloseTuple,
    Assoc,
    Equals,
    Term(Term),
    OneCons(Term),
    /// `PRT_LAST_ARRAY_ELEMENT + n`: the tuple elements from `next` on.
    Array(Tuple<'h>, usize),
}

/// `L_print_one_cons`: the head of the cell is the next object; the tail is queued.
fn print_one_cons<'h>(stack: &mut Vec<Prt<'h>>, cell: Term) -> Term {
    let Ok(cons) = Cons::try_from(cell) else {
        return Term::NON_VALUE;
    };
    let (head, tail) = cons.pair();
    if tail != Term::NIL {
        if Cons::try_from(tail).is_ok() {
            stack.push(Prt::OneCons(tail));
            stack.push(Prt::Comma);
        } else {
            stack.push(Prt::Term(tail));
            stack.push(Prt::Bar);
        }
    }
    head
}

/// Queue `key => value` pairs so that they pop in the given order, separated by commas.
fn push_assoc_pairs<'h>(stack: &mut Vec<Prt<'h>>, pairs: &[(Term, Term)]) {
    for (index, &(key, value)) in pairs.iter().enumerate().rev() {
        if index + 1 != pairs.len() {
            stack.push(Prt::Comma);
        }
        stack.push(Prt::Term(value));
        stack.push(Prt::Assoc);
        stack.push(Prt::Term(key));
    }
}

/// The body of a HAMT node: the entries of `head[1..n]` in storage order.
fn push_hamt_node<'h>(stack: &mut Vec<Prt<'h>>, node: Term) {
    let children = hamt::hashmap_node_children(node).unwrap_or_default();
    for (index, &child) in children.iter().enumerate().rev() {
        if index + 1 != children.len() {
            stack.push(Prt::Comma);
        }
        if let Ok(cell) = Cons::try_from(child) {
            let (key, value) = cell.pair();
            push_assoc_pairs(stack, &[(key, value)]);
        } else if let Ok(collision) = Tuple::try_from(child) {
            // Collision node: a tuple of key/value cells.
            let mut pairs = Vec::with_capacity(collision.arity());
            for i in 0..collision.arity() {
                if let Some(cell) = collision.get(i).and_then(|c| Cons::try_from(c).ok()) {
                    pairs.push(cell.pair());
                }
            }
            push_assoc_pairs(stack, &pairs);
        } else {
            stack.push(Prt::Term(child));
        }
    }
}

/// Print `obj`, using the budget `dcount`; the walk stops when it is used up.
// Port of erts/emulator/beam/erl_printf_term.c (print_term), OTP-29.1.1.
fn print_term(out: &mut Vec<u8>, obj: Term, dcount: &mut i64) {
    let mut stack: Vec<Prt<'_>> = Vec::new();
    // `L_jump_start` is entered with `Some`; `L_outer_loop` pops the stack.
    let mut next = Some(obj);
    loop {
        let obj = match next.take() {
            Some(obj) => obj,
            None => match stack.pop() {
                None => return,
                Some(Prt::Comma) => {
                    out.push(b',');
                    continue;
                }
                Some(Prt::Bar) => {
                    out.push(b'|');
                    continue;
                }
                Some(Prt::CloseList) => {
                    out.push(b']');
                    continue;
                }
                Some(Prt::CloseTuple) => {
                    out.push(b'}');
                    continue;
                }
                Some(Prt::Assoc) => {
                    out.extend_from_slice(b"=>");
                    continue;
                }
                Some(Prt::Equals) => {
                    out.push(b'=');
                    continue;
                }
                Some(Prt::Term(term)) => term,
                Some(Prt::OneCons(cell)) => print_one_cons(&mut stack, cell),
                Some(Prt::Array(tuple, index)) => {
                    if index + 1 < tuple.arity() {
                        stack.push(Prt::Array(tuple, index + 1));
                        stack.push(Prt::Comma);
                    }
                    tuple.get(index).unwrap_or(Term::NON_VALUE)
                }
            },
        };

        let used = *dcount;
        *dcount -= 1;
        if used <= 0 {
            return;
        }
        if obj.is_non_value() {
            out.extend_from_slice(b"<TNV>");
            return;
        }
        if obj == Term::catch(0) {
            // Missing default value in a native record definition.
            out.extend_from_slice(b"<novalue>");
            continue;
        }
        match obj.classify() {
            TermKind::Nil => out.extend_from_slice(b"[]"),
            TermKind::Atom => {
                if let Some(atom) = obj.as_atom() {
                    print_atom_name(out, atom, dcount);
                    if *dcount <= 0 {
                        return;
                    }
                }
            }
            TermKind::Number => {
                if let Some(small) = obj.as_small() {
                    out.extend_from_slice(small.to_string().as_bytes());
                } else if let Some(big) = raw::big_value(obj) {
                    out.extend_from_slice(big.to_string().as_bytes());
                } else if let Some(float) = raw::float_value(obj) {
                    print_double(out, float);
                }
            }
            TermKind::Ref => {
                let numbers = if raw::boxed_header(obj).is_some_and(|h| h & 63 == crate::REF) {
                    // REF_DEF: the numbers of a magic reference must stay resolvable.
                    obj.save_magic_ref();
                    let internal = obj.local_ref_numbers().or_else(|| obj.magic_ref_numbers());
                    internal.map(|numbers| (0, numbers.to_vec()))
                } else {
                    match obj.identity() {
                        Some(Identity::Ref { node, ids, .. }) => {
                            Some((channel_no(node), ids.to_vec()))
                        }
                        _ => None,
                    }
                };
                let Some((channel, numbers)) = numbers else {
                    out.extend_from_slice(b"<unknown:>");
                    continue;
                };
                out.extend_from_slice(format!("#Ref<{channel}").as_bytes());
                for number in numbers.iter().rev() {
                    out.extend_from_slice(format!(".{number}").as_bytes());
                }
                out.push(b'>');
            }
            TermKind::Pid => {
                let (channel, number, serial) = if let Some((number, serial)) = obj.as_pid() {
                    (0, number, serial)
                } else if let Some(Identity::Pid {
                    node,
                    index,
                    serial,
                    ..
                }) = obj.identity()
                {
                    (channel_no(node), index, serial)
                } else {
                    out.extend_from_slice(b"<unknown:>");
                    continue;
                };
                out.extend_from_slice(format!("<{channel}.{number}.{serial}>").as_bytes());
            }
            TermKind::Port => {
                let (channel, number) = if let Some(number) = obj.as_port() {
                    (0, number)
                } else if let Some(Identity::Port { node, id, .. }) = obj.identity() {
                    (channel_no(node), id)
                } else {
                    out.extend_from_slice(b"<unknown:>");
                    continue;
                };
                out.extend_from_slice(format!("#Port<{channel}.{number}>").as_bytes());
            }
            TermKind::List => {
                if is_printable_string(obj) {
                    out.push(b'"');
                    let mut rest = obj;
                    while let Ok(cons) = Cons::try_from(rest) {
                        let used = *dcount;
                        *dcount -= 1;
                        if used <= 0 {
                            return;
                        }
                        let c = cons.head().as_small().map_or(0, |v| v as u8);
                        if c == b'\n' {
                            out.extend_from_slice(b"\\n");
                        } else {
                            if c == b'"' {
                                out.push(b'\\');
                            }
                            out.push(c);
                        }
                        rest = cons.tail();
                    }
                    out.push(b'"');
                } else {
                    out.push(b'[');
                    stack.push(Prt::CloseList);
                    next = Some(print_one_cons(&mut stack, obj));
                }
            }
            TermKind::Record => {
                if let Some(record) = raw::record_view(obj) {
                    out.push(b'#');
                    print_atom_name(out, record.module(), dcount);
                    if *dcount <= 0 {
                        return;
                    }
                    out.push(b':');
                    print_atom_name(out, record.name(), dcount);
                    if *dcount <= 0 {
                        return;
                    }
                    out.push(b'{');
                    stack.push(Prt::CloseTuple);
                    for index in (0..record.len()).rev() {
                        if index + 1 != record.len() {
                            stack.push(Prt::Comma);
                        }
                        if let Some(value) = record.value(index) {
                            stack.push(Prt::Term(value));
                        }
                        stack.push(Prt::Equals);
                        if let Some(key) = record.key(index) {
                            stack.push(Prt::Term(Term::atom(key)));
                        }
                    }
                }
            }
            TermKind::Tuple => {
                if let Ok(tuple) = Tuple::try_from(obj) {
                    out.push(b'{');
                    stack.push(Prt::CloseTuple);
                    if tuple.arity() > 0 {
                        stack.push(Prt::Array(tuple, 0));
                    }
                }
            }
            TermKind::Bitstring => {
                if print_bitstring(out, obj, dcount) {
                    return;
                }
            }
            TermKind::Fun => {
                if print_fun(out, obj, dcount) {
                    return;
                }
            }
            TermKind::Map => {
                if let Ok(map) = raw::MapRef::try_from(obj) {
                    out.extend_from_slice(b"#{");
                    stack.push(Prt::CloseTuple);
                    let pairs: Vec<(Term, Term)> =
                        (0..map.len()).filter_map(|i| map.pair(i)).collect();
                    push_assoc_pairs(&mut stack, &pairs);
                } else {
                    // A HAMT head prints its braces; an inner node is only its entries.
                    let node_type = raw::boxed_header(obj).map_or(0, |h| (h >> 6) & 3);
                    if node_type >= 2 {
                        out.extend_from_slice(b"#{");
                        stack.push(Prt::CloseTuple);
                    }
                    push_hamt_node(&mut stack, obj);
                }
            }
            TermKind::BinRef => out.extend_from_slice(b"#BinRef"),
            TermKind::Catch | TermKind::Invalid => {
                out.extend_from_slice(format!("<unknown:{:#x}>", obj.word()).as_bytes());
            }
        }
    }
}

/// The `BITSTRING_DEF` case. Returns whether the walk must stop (budget exhausted).
fn print_bitstring(out: &mut Vec<u8>, obj: Term, dcount: &mut i64) -> bool {
    let Ok(bits) = BinRef::try_from(obj) else {
        return false;
    };
    let window = bits.window();
    let bitoffs = bits.start_bit() % 8;
    let bytes = &window[(bits.start_bit() / 8).min(window.len())..];
    let size = bits.bit_len();
    let mut bytesize = size / 8;
    let bitsize = size % 8;
    let mut at = 0usize;
    let spend = |dcount: &mut i64| {
        let used = *dcount;
        *dcount -= 1;
        used <= 0
    };

    if bitsize != 0 || bytesize == 0 || !is_printable_ascii(bytes, bytesize, bitoffs) {
        let mut is_first = true;
        out.extend_from_slice(b"<<");
        while bytesize > 0 {
            if is_first {
                is_first = false;
            } else {
                out.push(b',');
            }
            out.extend_from_slice(octet_at(bytes, bitoffs, at).to_string().as_bytes());
            at += 1;
            bytesize -= 1;
            if spend(dcount) {
                return true;
            }
        }
        if bitsize != 0 {
            let total = bitoffs + bitsize;
            let mut octet = u32::from(bytes[at]);
            if total < 8 {
                octet >>= 8 - total;
            } else if total > 8 {
                let in_last = total - 8;
                octet <<= in_last;
                octet |= u32::from(bytes[at + 1]) >> (8 - in_last);
            }
            let octet = (octet as u8) & (((1u32 << bitsize) - 1) as u8);
            if !is_first {
                out.push(b',');
            }
            out.extend_from_slice(format!("{octet}:{bitsize}").as_bytes());
        }
        out.extend_from_slice(b">>");
    } else {
        out.extend_from_slice(b"<<\"");
        while bytesize > 0 {
            let octet = octet_at(bytes, bitoffs, at);
            if octet == b'"' {
                out.push(b'\\');
            }
            out.push(octet);
            at += 1;
            bytesize -= 1;
            if spend(dcount) {
                return true;
            }
        }
        out.extend_from_slice(b"\">>");
    }
    false
}

/// The `FUN_DEF` case. Returns whether the walk must stop.
fn print_fun(out: &mut Vec<u8>, obj: Term, dcount: &mut i64) -> bool {
    match raw::fun_view(obj) {
        Some(FunRef::Local { entry, .. }) => {
            let module = global_atoms().text(entry.module).unwrap_or_default();
            out.extend_from_slice(b"#Fun<");
            out.extend_from_slice(module.as_bytes());
            out.extend_from_slice(
                format!(
                    ".{}.{}>",
                    i64::from(entry.old_index as i32),
                    i64::from(entry.old_uniq as i32)
                )
                .as_bytes(),
            );
        }
        Some(FunRef::Export { entry }) => {
            out.extend_from_slice(b"fun ");
            // A temporary budget keeps the fun from being split between module and
            // function name; the real one is charged afterwards.
            for (index, atom) in [entry.module, entry.function].into_iter().enumerate() {
                let mut tdcount = MAX_ATOM_SZ_LIMIT;
                print_atom_name(out, atom, &mut tdcount);
                *dcount -= MAX_ATOM_SZ_LIMIT - tdcount;
                if index == 0 {
                    out.push(b':');
                }
            }
            out.extend_from_slice(format!("/{}", entry.arity).as_bytes());
        }
        None => {}
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{TermBuilder, VecHeap};

    fn text(term: Term, precision: i32) -> String {
        let mut out = Vec::new();
        erts_printf_t(&mut out, term, precision);
        String::from_utf8_lossy(&out).into_owned()
    }

    #[test]
    fn budget_ends_output_with_ellipsis() {
        let mut heap = VecHeap::new();
        let mut builder = TermBuilder::new(&mut heap);
        let list = builder
            .list_from_iter((1..=10).map(|n| Term::small(n).unwrap()))
            .unwrap();
        assert_eq!(text(list, i32::MAX), "[1,2,3,4,5,6,7,8,9,10]");
        assert_eq!(text(list, 4), "[1,2,3,... ");
    }

    #[test]
    fn atoms_are_quoted_like_erts() {
        let table = global_atoms();
        let plain = Term::atom(table.intern("hello_World1").unwrap());
        let quoted = Term::atom(table.intern("Hello world").unwrap());
        assert_eq!(text(plain, -1), "hello_World1");
        assert_eq!(text(quoted, -1), "'Hello world'");
    }
}
