//! Term printing for the `%T` conversion of the match-spec compiler messages.
//!
//! Port of erts/emulator/beam/erl_printf_term.c (print_term, print_atom_name,
//! is_printable_string), OTP-29.1.1. The output is capped at `limit` bytes because the only
//! user, `vadd_dmc_err`, formats into a `DMC_ERR_STR_LEN` buffer, so a term deeper than the
//! cap is never walked further than the cap.

use super::{cons, float, integer, tuple_view};
use arinsal_etf::OwnedTerm;
use arinsal_term::{Term, TermKind, global_atoms, to_owned};

/// Whether the output is full; the walk stops at the first `true`.
type Full = bool;

struct Out {
    bytes: Vec<u8>,
    limit: usize,
}

impl Out {
    fn push(&mut self, text: &[u8]) -> Full {
        self.bytes.extend_from_slice(text);
        self.bytes.len() >= self.limit
    }
}

fn is_lower(c: u32) -> bool {
    (u32::from(b'a')..=u32::from(b'z')).contains(&c) || ((128 + 95)..=255).contains(&c) && c != 247
}

fn is_upper(c: u32) -> bool {
    (u32::from(b'A')..=u32::from(b'Z')).contains(&c)
        || ((128 + 64)..=(128 + 94)).contains(&c) && c != 247 - 32
}

fn is_alnum(c: u32) -> bool {
    (u32::from(b'0')..=u32::from(b'9')).contains(&c) || is_lower(c) || is_upper(c)
}

/// A non-empty flat list of printable Latin-1 characters, as its bytes.
// Port of erts/emulator/beam/erl_printf_term.c (is_printable_string), OTP-29.1.1.
fn printable_string(list: Term) -> Option<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut rest = list;
    while let Some((head, tail)) = cons(rest) {
        let c = u8::try_from(head.as_small()?).ok()?;
        let cntrl = c < b' ' || c == 127 || (128..128 + 32).contains(&c);
        let space = matches!(c, b' ' | b'\n' | b'\t' | b'\r');
        if cntrl && !space {
            return None;
        }
        bytes.push(c);
        rest = tail;
    }
    (rest == Term::NIL).then_some(bytes)
}

// Port of erts/emulator/beam/erl_printf_term.c (print_atom_name), OTP-29.1.1.
fn print_atom_name(out: &mut Out, text: &str) -> Full {
    if text.is_empty() {
        return out.push(b"''");
    }
    let mut chars = text.chars().map(u32::from);
    let first = chars.next().unwrap_or(0);
    let need_quote = !is_lower(first) || chars.any(|c| !is_alnum(c) && c != u32::from(b'_'));
    if need_quote && out.push(b"'") {
        return true;
    }
    for c in text.chars() {
        let full = match c {
            '\'' => out.push(b"\\'"),
            '\\' => out.push(b"\\\\"),
            '\n' => out.push(b"\\n"),
            '\u{c}' => out.push(b"\\f"),
            '\t' => out.push(b"\\t"),
            '\r' => out.push(b"\\r"),
            '\u{8}' => out.push(b"\\b"),
            '\u{b}' => out.push(b"\\v"),
            c if u32::from(c) < 32 || (128..=159).contains(&u32::from(c)) => {
                out.push(format!("\\{:03o}", u32::from(c)).as_bytes())
            }
            c => out.push(c.to_string().as_bytes()),
        };
        if full {
            return true;
        }
    }
    need_quote && out.push(b"'")
}

/// `%e` with precision 6, the way C prints a double.
fn print_double(value: f64) -> String {
    let formatted = format!("{value:.6e}");
    let (mantissa, exponent) = formatted.split_once('e').unwrap_or((&formatted, "0"));
    let exponent: i32 = exponent.parse().unwrap_or(0);
    format!(
        "{mantissa}e{}{:02}",
        if exponent < 0 { '-' } else { '+' },
        exponent.abs()
    )
}

/// Terms that are not containers, printed from their heap-independent form. Local
/// identifiers have channel number 0.
fn print_leaf(out: &mut Out, term: Term) -> Full {
    if let Some((number, serial)) = term.as_pid() {
        return out.push(format!("<0.{number}.{serial}>").as_bytes());
    }
    if let Some(number) = term.as_port() {
        return out.push(format!("#Port<0.{number}>").as_bytes());
    }
    if let Some(numbers) = term.local_ref_numbers() {
        let mut text = String::from("#Ref<0");
        for id in numbers.iter().rev() {
            text.push_str(&format!(".{id}"));
        }
        text.push('>');
        return out.push(text.as_bytes());
    }
    let Ok(owned) = to_owned(term) else {
        return out.push(b"<unknown>");
    };
    let text = match &owned {
        OwnedTerm::Pid { id, serial, .. } => format!("<0.{id}.{serial}>"),
        OwnedTerm::Port { id, .. } => format!("#Port<0.{id}>"),
        OwnedTerm::Ref { ids, .. } => {
            let mut text = String::from("#Ref<0");
            for id in ids.iter().rev() {
                text.push_str(&format!(".{id}"));
            }
            text.push('>');
            text
        }
        OwnedTerm::Export {
            module,
            function,
            arity,
        } => {
            // Module and function names are never split by the cap.
            let mut text = String::from("fun ");
            let mut inner = Out {
                bytes: Vec::new(),
                limit: usize::MAX,
            };
            print_atom_name(&mut inner, module);
            inner.bytes.push(b':');
            print_atom_name(&mut inner, function);
            text.push_str(&String::from_utf8_lossy(&inner.bytes));
            text.push_str(&format!("/{arity}"));
            text
        }
        OwnedTerm::Fun {
            module,
            old_index,
            old_uniq,
            ..
        } => format!("#Fun<{module}.{old_index}.{old_uniq}>"),
        OwnedTerm::Binary(_) | OwnedTerm::BitString { .. } => return print_bitstring(out, &owned),
        _ => "<unknown>".to_owned(),
    };
    out.push(text.as_bytes())
}

// Port of erts/emulator/beam/erl_printf_term.c (print_term, BITSTRING_DEF), OTP-29.1.1.
fn print_bitstring(out: &mut Out, term: &OwnedTerm) -> Full {
    let (bytes, bits): (&[u8], u8) = match term {
        OwnedTerm::Binary(bytes) => (bytes, 0),
        OwnedTerm::BitString { bytes, bits } => (bytes, *bits),
        _ => return false,
    };
    let (whole, tail) = if bits == 0 {
        (bytes, None)
    } else {
        let (last, rest) = bytes.split_last().map_or((0, bytes), |(l, r)| (*l, r));
        (rest, Some(last >> (8 - bits)))
    };
    let printable =
        bits == 0 && !whole.is_empty() && whole.iter().all(|byte| (b' '..127).contains(byte));
    if printable {
        if out.push(b"<<\"") {
            return true;
        }
        for &byte in whole {
            if byte == b'"' && out.push(b"\\") {
                return true;
            }
            if out.push(&[byte]) {
                return true;
            }
        }
        return out.push(b"\">>");
    }
    if out.push(b"<<") {
        return true;
    }
    let mut first = true;
    for byte in whole {
        if !first && out.push(b",") {
            return true;
        }
        first = false;
        if out.push(byte.to_string().as_bytes()) {
            return true;
        }
    }
    if let Some(octet) = tail {
        if !first && out.push(b",") {
            return true;
        }
        if out.push(format!("{octet}:{bits}").as_bytes()) {
            return true;
        }
    }
    out.push(b">>")
}

/// Print `term` into `out` as `%T` does and return whether the cap was reached.
// Port of erts/emulator/beam/erl_printf_term.c (print_term), OTP-29.1.1.
fn print(out: &mut Out, term: Term) -> Full {
    match term.classify() {
        TermKind::Nil => out.push(b"[]"),
        TermKind::Atom => match term.as_atom().and_then(|atom| global_atoms().text(atom)) {
            Some(text) => print_atom_name(out, text),
            None => out.push(b"<bad atom index>"),
        },
        TermKind::Number => match integer(term) {
            Some(number) => out.push(number.to_string().as_bytes()),
            None => out.push(print_double(float(term).unwrap_or(0.0)).as_bytes()),
        },
        TermKind::Tuple => {
            if out.push(b"{") {
                return true;
            }
            if let Some(view) = tuple_view(term) {
                for (index, element) in view.iter().enumerate() {
                    if index > 0 && out.push(b",") {
                        return true;
                    }
                    if print(out, element) {
                        return true;
                    }
                }
            }
            out.push(b"}")
        }
        TermKind::List => {
            if let Some(string) = printable_string(term) {
                if out.push(b"\"") {
                    return true;
                }
                for byte in string {
                    let full = match byte {
                        b'\n' => out.push(b"\\n"),
                        b'"' => out.push(b"\\\""),
                        byte => out.push(&[byte]),
                    };
                    if full {
                        return true;
                    }
                }
                return out.push(b"\"");
            }
            if out.push(b"[") {
                return true;
            }
            let mut rest = term;
            let mut first = true;
            while let Some((head, tail)) = cons(rest) {
                if !first && out.push(b",") {
                    return true;
                }
                first = false;
                if print(out, head) {
                    return true;
                }
                rest = tail;
            }
            if rest != Term::NIL && (out.push(b"|") || print(out, rest)) {
                return true;
            }
            out.push(b"]")
        }
        TermKind::Map => {
            if out.push(b"#{") {
                return true;
            }
            let pairs = arinsal_maps::to_list(term).unwrap_or_default();
            for (index, (key, value)) in pairs.into_iter().enumerate() {
                if index > 0 && out.push(b",") {
                    return true;
                }
                if print(out, key) || out.push(b"=>") || print(out, value) {
                    return true;
                }
            }
            out.push(b"}")
        }
        _ => print_leaf(out, term),
    }
}

/// `%T` of `term`, cut at `limit` bytes.
pub(super) fn format_term(term: Term, limit: usize) -> Vec<u8> {
    let mut out = Out {
        bytes: Vec::new(),
        limit,
    };
    print(&mut out, term);
    out.bytes.truncate(limit);
    out.bytes
}
