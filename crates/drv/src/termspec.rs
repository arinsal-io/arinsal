//! `ErlDrvTermData` words and the term specification of `erl_drv_output_term`.
//!
//! Drivers treat the words returned by `driver_mk_atom`, `driver_mk_port`,
//! `driver_connected` and `driver_caller` as opaque and hand them back in a
//! specification. Here an atom is `index << 6 | 0xb` into a table of this crate,
//! a pid is `data << 4 | 3` and a port `id << 4 | 7`; the VM only ever sees the
//! decoded [`OwnedTerm`].

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use arinsal_etf::OwnedTerm;
use num_bigint::BigInt;

use crate::binary::{self, ErlDrvBinary};
use crate::layout;
use crate::mem;

/// `NIL` as an `ErlDrvTermData` (`driver_term_nil`).
pub(crate) const NIL: usize = 0x3b;
/// Node name of local identifiers in an [`OwnedTerm`].
const LOCAL_NODE: &str = "nonode@nohost";
/// Port of erts/emulator/beam/erl_term.h:646 (_PID_NUM_SIZE), OTP-29.1.1.
const PID_NUM_SIZE: u32 = 28;
const ATOM_TAG: usize = 0x0b;

struct Atoms {
    names: Vec<String>,
    index: HashMap<String, usize>,
}

fn atoms() -> &'static Mutex<Atoms> {
    static ATOMS: OnceLock<Mutex<Atoms>> = OnceLock::new();
    ATOMS.get_or_init(|| {
        Mutex::new(Atoms {
            names: Vec::new(),
            index: HashMap::new(),
        })
    })
}

/// `driver_mk_atom`: Latin-1 text to an atom word (io.c erts_atom_put).
pub(crate) fn mk_atom(text: &[u8]) -> usize {
    let name: String = text.iter().map(|&b| char::from(b)).collect();
    let mut atoms = atoms().lock().unwrap();
    let next = atoms.names.len();
    let index = *atoms.index.entry(name.clone()).or_insert(next);
    if index == next {
        atoms.names.push(name);
    }
    index << 6 | ATOM_TAG
}

fn atom_name(word: usize) -> Option<String> {
    if word & 0x3f != ATOM_TAG {
        return None;
    }
    atoms().lock().unwrap().names.get(word >> 6).cloned()
}

/// Pid word of the process-table `data`.
pub(crate) fn mk_pid(data: u64) -> usize {
    (data << 4 | 3) as usize
}

/// Process-table data of a pid word.
pub(crate) fn pid_data(word: usize) -> Option<u64> {
    (word & 15 == 3).then_some(word as u64 >> 4)
}

/// Port word of the port-table number `id`.
pub(crate) fn mk_port(id: u64) -> usize {
    (id << 4 | 7) as usize
}

/// Port-table number of a port word.
pub(crate) fn port_id(word: usize) -> Option<u64> {
    (word & 15 == 7).then_some(word as u64 >> 4)
}

/// The local pid with process-table `data` as a term.
pub(crate) fn pid_term(data: u64) -> OwnedTerm {
    OwnedTerm::Pid {
        node: LOCAL_NODE.into(),
        id: (data & ((1 << PID_NUM_SIZE) - 1)) as u32,
        serial: (data >> PID_NUM_SIZE) as u32,
        creation: 0,
    }
}

fn port_term(id: u64) -> OwnedTerm {
    OwnedTerm::Port {
        node: LOCAL_NODE.into(),
        id,
        creation: 0,
    }
}

/// Elements of a byte string as a list ending in `tail` (io.c buf_to_intlist).
fn int_list(bytes: &[u8], tail: OwnedTerm) -> OwnedTerm {
    if bytes.is_empty() {
        return tail;
    }
    list(
        bytes
            .iter()
            .map(|&b| OwnedTerm::Int(i64::from(b)))
            .collect(),
        tail,
    )
}

/// A list with `tail`, flattened when the tail is itself a list.
fn list(mut elems: Vec<OwnedTerm>, mut tail: OwnedTerm) -> OwnedTerm {
    if let OwnedTerm::List {
        elems: more,
        tail: end,
    } = &mut tail
    {
        elems.append(more);
        let end = std::mem::replace(&mut **end, OwnedTerm::Nil);
        return OwnedTerm::List {
            elems,
            tail: Box::new(end),
        };
    }
    if elems.is_empty() {
        return tail;
    }
    OwnedTerm::List {
        elems,
        tail: Box::new(tail),
    }
}

/// Port of erts/emulator/beam/io.c:5658 (driver_deliver_term), the check and
/// build passes folded into one: `None` is the `-1` of a malformed
/// specification (nothing is delivered).
pub(crate) fn decode(data: &[usize]) -> Option<OwnedTerm> {
    const ERL_DRV_NIL: usize = layout::ERL_DRV_NIL as usize;
    const ERL_DRV_ATOM: usize = layout::ERL_DRV_ATOM as usize;
    const ERL_DRV_INT: usize = layout::ERL_DRV_INT as usize;
    const ERL_DRV_PORT: usize = layout::ERL_DRV_PORT as usize;
    const ERL_DRV_BINARY: usize = layout::ERL_DRV_BINARY as usize;
    const ERL_DRV_STRING: usize = layout::ERL_DRV_STRING as usize;
    const ERL_DRV_TUPLE: usize = layout::ERL_DRV_TUPLE as usize;
    const ERL_DRV_LIST: usize = layout::ERL_DRV_LIST as usize;
    const ERL_DRV_STRING_CONS: usize = layout::ERL_DRV_STRING_CONS as usize;
    const ERL_DRV_PID: usize = layout::ERL_DRV_PID as usize;
    const ERL_DRV_FLOAT: usize = layout::ERL_DRV_FLOAT as usize;
    const ERL_DRV_EXT2TERM: usize = layout::ERL_DRV_EXT2TERM as usize;
    const ERL_DRV_UINT: usize = layout::ERL_DRV_UINT as usize;
    const ERL_DRV_BUF2BINARY: usize = layout::ERL_DRV_BUF2BINARY as usize;
    const ERL_DRV_INT64: usize = layout::ERL_DRV_INT64 as usize;
    const ERL_DRV_UINT64: usize = layout::ERL_DRV_UINT64 as usize;
    const ERL_DRV_MAP: usize = layout::ERL_DRV_MAP as usize;

    let mut stack: Vec<OwnedTerm> = Vec::new();
    let mut at = 0;
    while at < data.len() {
        let tag = data[at];
        at += 1;
        let args = |need: usize| (data.len() - at >= need).then(|| &data[at..at + need]);
        let (term, used) = match tag {
            ERL_DRV_NIL => (OwnedTerm::Nil, 0),
            ERL_DRV_ATOM => (OwnedTerm::Atom(atom_name(args(1)?[0])?), 1),
            ERL_DRV_INT => (OwnedTerm::Int(args(1)?[0] as isize as i64), 1),
            ERL_DRV_UINT => {
                let value = args(1)?[0] as u64;
                (uint(value), 1)
            }
            ERL_DRV_INT64 => {
                let value = *mem::deref(args(1)?[0] as *const i64)?;
                (OwnedTerm::Int(value), 1)
            }
            ERL_DRV_UINT64 => {
                let value = *mem::deref(args(1)?[0] as *const u64)?;
                (uint(value), 1)
            }
            ERL_DRV_PORT => (port_term(port_id(args(1)?[0])?), 1),
            ERL_DRV_PID => (pid_term(pid_data(args(1)?[0])?), 1),
            ERL_DRV_BINARY => {
                let [bin, size, offset] = args(3)? else {
                    return None;
                };
                let bin = *bin as *const ErlDrvBinary;
                let orig = usize::try_from(mem::deref(bin)?.orig_size).ok()?;
                if size.checked_add(*offset)? > orig {
                    return None;
                }
                (
                    OwnedTerm::Binary(binary::read(bin.cast_mut(), *offset, *size)),
                    3,
                )
            }
            ERL_DRV_BUF2BINARY => {
                let [buf, size] = args(2)? else { return None };
                if *buf == 0 && *size > 0 {
                    return None;
                }
                (
                    OwnedTerm::Binary(mem::slice(*buf as *const u8, *size).to_vec()),
                    2,
                )
            }
            ERL_DRV_STRING => {
                let [buf, len] = args(2)? else { return None };
                if *buf == 0 || (*len as i32) < 0 {
                    return None;
                }
                (
                    int_list(mem::slice(*buf as *const u8, *len), OwnedTerm::Nil),
                    2,
                )
            }
            ERL_DRV_STRING_CONS => {
                let [buf, len] = args(2)? else { return None };
                if *buf == 0 || (*len as i32) < 0 || stack.is_empty() {
                    return None;
                }
                let tail = stack.pop()?;
                (int_list(mem::slice(*buf as *const u8, *len), tail), 2)
            }
            ERL_DRV_LIST => {
                let count = args(1)?[0] as i32;
                if count <= 0 || stack.len() < count as usize {
                    return None;
                }
                let tail = stack.pop()?;
                let heads = stack.split_off(stack.len() - (count as usize - 1));
                (list(heads, tail), 1)
            }
            ERL_DRV_TUPLE => {
                let count = args(1)?[0] as i32;
                if count < 0 || stack.len() < count as usize {
                    return None;
                }
                let items = stack.split_off(stack.len() - count as usize);
                (OwnedTerm::Tuple(items), 1)
            }
            ERL_DRV_FLOAT => {
                let value = *mem::deref(args(1)?[0] as *const f64)?;
                if !value.is_finite() {
                    return None;
                }
                (OwnedTerm::Float(value), 1)
            }
            ERL_DRV_EXT2TERM => {
                let [ext, size] = args(2)? else { return None };
                if *ext == 0 || (*size as isize) <= 0 {
                    return None;
                }
                let bytes = mem::slice(*ext as *const u8, *size);
                (arinsal_etf::decode(bytes).ok()?, 2)
            }
            ERL_DRV_MAP => {
                let count = args(1)?[0] as i32;
                if count < 0 || stack.len() < 2 * count as usize {
                    return None;
                }
                let flat = stack.split_off(stack.len() - 2 * count as usize);
                let mut pairs: Vec<(OwnedTerm, OwnedTerm)> = Vec::with_capacity(count as usize);
                let mut flat = flat.into_iter();
                while let (Some(key), Some(value)) = (flat.next(), flat.next()) {
                    // Duplicate keys make the map invalid (erts_validate_and_sort_flatmap).
                    if pairs.iter().any(|(seen, _)| *seen == key) {
                        return None;
                    }
                    pairs.push((key, value));
                }
                (OwnedTerm::Map(pairs), 1)
            }
            _ => return None,
        };
        at += used;
        stack.push(term);
    }
    (stack.len() == 1).then(|| stack.pop()).flatten()
}

fn uint(value: u64) -> OwnedTerm {
    i64::try_from(value).map_or_else(|_| OwnedTerm::BigInt(BigInt::from(value)), OwnedTerm::Int)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tags() -> (usize, usize, usize, usize, usize, usize) {
        (
            layout::ERL_DRV_NIL as usize,
            layout::ERL_DRV_ATOM as usize,
            layout::ERL_DRV_INT as usize,
            layout::ERL_DRV_LIST as usize,
            layout::ERL_DRV_TUPLE as usize,
            layout::ERL_DRV_MAP as usize,
        )
    }

    #[test]
    fn builds_nested_terms() {
        let (nil, atom, int, list, tuple, _) = tags();
        let ok = mk_atom(b"ok");
        let spec = [atom, ok, int, 1, int, 2, nil, list, 3, tuple, 2];
        assert_eq!(
            decode(&spec),
            Some(OwnedTerm::Tuple(vec![
                OwnedTerm::Atom("ok".into()),
                OwnedTerm::List {
                    elems: vec![OwnedTerm::Int(1), OwnedTerm::Int(2)],
                    tail: Box::new(OwnedTerm::Nil),
                },
            ]))
        );
    }

    #[test]
    fn rejects_malformed_specs() {
        let (nil, atom, int, list, tuple, map) = tags();
        assert_eq!(decode(&[]), None);
        assert_eq!(decode(&[nil, nil]), None);
        assert_eq!(decode(&[nil, list, 0]), None);
        assert_eq!(decode(&[nil, tuple, 2]), None);
        assert_eq!(decode(&[atom, 12345]), None);
        assert_eq!(decode(&[int]), None);
        assert_eq!(decode(&[99]), None);
        let k = mk_atom(b"k");
        assert_eq!(decode(&[atom, k, int, 1, atom, k, int, 2, map, 2]), None);
    }

    #[test]
    fn identifiers_round_trip() {
        let pid = mk_pid((7 << 28) | 5);
        assert_eq!(pid_data(pid), Some((7 << 28) | 5));
        assert_eq!(port_id(pid), None);
        assert_eq!(port_id(mk_port(9)), Some(9));
        assert_eq!(
            decode(&[layout::ERL_DRV_PID as usize, pid]),
            Some(OwnedTerm::Pid {
                node: LOCAL_NODE.into(),
                id: 5,
                serial: 7,
                creation: 0,
            })
        );
    }
}
