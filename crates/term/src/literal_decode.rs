//! The decoder of the literal chunk of a BEAM file: external terms built straight onto the
//! literal area, with no intermediate value.
//!
//! erts has one decoder, `erts_decode_ext` (external.c), and `parse_decompressed_literals`
//! (beam_file.c) runs it on every entry of the literal chunk. This is its counterpart for the
//! terms a file can hold; a tag that cannot occur in a file (a compressed term, an atom cache
//! reference, a `LOCAL_EXT` of another node) is an error, as in erts, where the size pass
//! (`erts_decode_ext_size`) or the hash check rejects it.

use crate::{
    Atom, AtomEncoding, ExportEntry, FunEntry, HeapAlloc, MagicRef, Node, Term, TermBuilder,
    TermKind, atoms, global_atoms,
};
use num_bigint::{BigInt, Sign};
use std::sync::Arc;

/// The version byte of the external term format.
const VERSION_MAGIC: u8 = 131;

/// What a tag with children still needs before its term can be built. `start` is the length of
/// `values` when the frame was pushed: the children of the frame are `values[start..]`.
enum Frame {
    /// `left` more elements of a tuple.
    Tuple { start: usize, left: usize },
    /// `left` more items of a list: the elements, then the tail.
    List { start: usize, left: usize },
    /// `left` more keys and values of a map, in stream order.
    Map { start: usize, left: usize },
    /// Module, function and arity of an `EXPORT_EXT`.
    Export { start: usize, left: usize },
    /// Module, old index, old uniq, pid and free variables of a `NEW_FUN_EXT`.
    Fun {
        arity: u8,
        uniq: [u8; 16],
        index: u32,
        free: usize,
        start: usize,
        left: usize,
    },
    /// Module, name, field names and field values of a `RECORD_EXT`.
    Record {
        exported: bool,
        fields: usize,
        start: usize,
        left: usize,
    },
}

/// Decodes one external term of a literal chunk entry onto `heap`: the version byte, then the
/// term, which must end the entry. `None` for anything `erts_decode_ext_size` or
/// `erts_decode_ext` would reject, which fails the load of the module.
// Port of erts/emulator/beam/external.c (erts_decode_ext_size and dec_term) as
// beam_file.c:1373 (parse_decompressed_literals) uses them, OTP-29.1.1: the atoms are put in
// stream order and a container is built after its elements.
pub fn decode_literal<H: HeapAlloc>(bytes: &[u8], heap: &mut H) -> Option<Term> {
    if bytes.first() != Some(&VERSION_MAGIC) {
        return None;
    }
    // The work stacks of one entry are the next entry's: a chunk has a hundred of them.
    let (values, frames) = SCRATCH.with(|scratch| scratch.take());
    let mut decoder = LiteralDecoder {
        bytes,
        at: 1,
        builder: TermBuilder::new(heap),
        values,
        frames,
    };
    let term = decoder.run();
    let (mut values, mut frames) = (decoder.values, decoder.frames);
    values.clear();
    frames.clear();
    SCRATCH.with(|scratch| scratch.set((values, frames)));
    let term = term?;
    (decoder.at == bytes.len()).then_some(term)
}

thread_local! {
    static SCRATCH: std::cell::Cell<(Vec<Term>, Vec<Frame>)> = const {
        std::cell::Cell::new((Vec::new(), Vec::new()))
    };
}

struct LiteralDecoder<'a, 'h, H: HeapAlloc> {
    bytes: &'a [u8],
    at: usize,
    builder: TermBuilder<'h, H>,
    /// The children of the containers under construction.
    values: Vec<Term>,
    frames: Vec<Frame>,
}

impl<H: HeapAlloc> LiteralDecoder<'_, '_, H> {
    fn take(&mut self, n: usize) -> Option<&[u8]> {
        let end = self.at.checked_add(n)?;
        let slice = self.bytes.get(self.at..end)?;
        self.at = end;
        Some(slice)
    }

    fn u8(&mut self) -> Option<u8> {
        let byte = *self.bytes.get(self.at)?;
        self.at += 1;
        Some(byte)
    }

    fn u16(&mut self) -> Option<u16> {
        Some(u16::from_be_bytes(self.take(2)?.try_into().ok()?))
    }

    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_be_bytes(self.take(4)?.try_into().ok()?))
    }

    fn u64(&mut self) -> Option<u64> {
        Some(u64::from_be_bytes(self.take(8)?.try_into().ok()?))
    }

    /// A count of children, each of which takes at least a byte of the input.
    fn count(&self, n: usize) -> Option<usize> {
        (n <= self.bytes.len() - self.at).then_some(n)
    }

    fn atom_bytes(&mut self, len: usize, utf8: bool) -> Option<Atom> {
        let name = self.take(len)?;
        let encoding = if utf8 {
            AtomEncoding::Utf8
        } else {
            AtomEncoding::Latin1
        };
        global_atoms().put(name, encoding, false).ok()
    }

    /// An atom in any of the forms a node name or a module can have.
    // Port of erts/emulator/beam/external.c (dec_atom), OTP-29.1.1.
    fn atom(&mut self) -> Option<Atom> {
        match self.u8()? {
            100 => {
                let len = usize::from(self.u16()?);
                self.atom_bytes(len, false)
            }
            118 => {
                let len = usize::from(self.u16()?);
                self.atom_bytes(len, true)
            }
            115 => {
                let len = usize::from(self.u8()?);
                self.atom_bytes(len, false)
            }
            119 => {
                let len = usize::from(self.u8()?);
                self.atom_bytes(len, true)
            }
            73 => {
                let index = u32::from(self.u16()?);
                self.internal_atom(index)
            }
            75 => {
                let b = self.take(3)?;
                let index = u32::from_be_bytes([0, b[0], b[1], b[2]]);
                self.internal_atom(index)
            }
            _ => None,
        }
    }

    /// An atom named by its index in this node's table.
    fn internal_atom(&self, index: u32) -> Option<Atom> {
        let atom = Atom(index);
        global_atoms().text(atom).map(|_| atom)
    }

    /// Whether a node name and creation name this node.
    // Port of erts/emulator/beam/external.c (dec_is_this_node), OTP-29.1.1.
    fn is_this_node(node: Atom, creation: u32) -> bool {
        (node == atoms::NONAME && creation == 0) || (node, creation) == crate::this_node()
    }

    /// The decode loop: `dec_term` with an explicit stack of the containers being filled.
    fn run(&mut self) -> Option<Term> {
        loop {
            let tag = self.u8()?;
            let leaf = match tag {
                97 => Term::small(i64::from(self.u8()?)),
                98 => Term::small(i64::from(self.u32()? as i32)),
                110 | 111 => {
                    let n = if tag == 110 {
                        usize::from(self.u8()?)
                    } else {
                        self.u32()? as usize
                    };
                    let sign = self.u8()?;
                    if sign > 1 {
                        return None;
                    }
                    let digits = self.take(n)?;
                    let sign = if sign == 0 { Sign::Plus } else { Sign::Minus };
                    let value = BigInt::from_bytes_le(sign, digits);
                    self.builder.int_from_bigint(&value).ok()
                }
                70 => {
                    let value = f64::from_bits(self.u64()?);
                    value.is_finite().then(|| self.builder.float(value).ok())?
                }
                99 => {
                    let raw = self.take(31)?;
                    let end = raw.iter().position(|byte| *byte == 0).unwrap_or(31);
                    let value: f64 = std::str::from_utf8(&raw[..end]).ok()?.parse().ok()?;
                    value.is_finite().then(|| self.builder.float(value).ok())?
                }
                100 | 115 | 118 | 119 | 73 | 75 => {
                    self.at -= 1;
                    Some(Term::atom(self.atom()?))
                }
                106 => Some(Term::NIL),
                104 | 105 => {
                    let n = if tag == 104 {
                        usize::from(self.u8()?)
                    } else {
                        self.u32()? as usize
                    };
                    let n = self.count(n)?;
                    if n == 0 {
                        self.builder.tuple(&[]).ok()
                    } else {
                        let start = self.values.len();
                        self.frames.push(Frame::Tuple { start, left: n });
                        continue;
                    }
                }
                107 => {
                    let n = usize::from(self.u16()?);
                    // The builder borrows the heap, not the input.
                    let bytes = self.bytes;
                    let from = self.at;
                    self.take(n)?;
                    self.builder.byte_string_list(&bytes[from..from + n]).ok()
                }
                108 => {
                    let n = self.u32()? as usize;
                    let left = self.count(n.checked_add(1)?)?;
                    let start = self.values.len();
                    self.frames.push(Frame::List { start, left });
                    continue;
                }
                109 | 77 => {
                    let n = self.u32()? as usize;
                    let bits = if tag == 77 {
                        let bits = usize::from(self.u8()?);
                        if n == 0 || !(1..=8).contains(&bits) {
                            return None;
                        }
                        bits
                    } else {
                        8
                    };
                    let bytes = self.bytes;
                    let from = self.at;
                    self.take(n)?;
                    let bit_len = if tag == 77 {
                        (n - 1).checked_mul(8)?.checked_add(bits)?
                    } else {
                        n.checked_mul(8)?
                    };
                    self.builder.bitstring(&bytes[from..from + n], bit_len).ok()
                }
                116 => {
                    let n = self.u32()? as usize;
                    let left = self.count(n.checked_mul(2)?)?;
                    if left == 0 {
                        self.builder.flatmap_from_pairs(&[]).ok()
                    } else {
                        let start = self.values.len();
                        self.frames.push(Frame::Map { start, left });
                        continue;
                    }
                }
                103 | 88 => self.pid(tag),
                102 | 89 | 120 => self.port(tag),
                101 | 114 | 90 => self.reference(tag),
                113 => {
                    let start = self.values.len();
                    self.frames.push(Frame::Export { start, left: 3 });
                    continue;
                }
                112 => {
                    // The size field is ignored, as dec_term does.
                    self.u32()?;
                    let arity = self.u8()?;
                    let uniq: [u8; 16] = self.take(16)?.try_into().ok()?;
                    let index = self.u32()?;
                    let free = self.u32()? as usize;
                    if free > 255 {
                        return None;
                    }
                    let left = self.count(free + 4)?;
                    let start = self.values.len();
                    self.frames.push(Frame::Fun {
                        arity,
                        uniq,
                        index,
                        free,
                        start,
                        left,
                    });
                    continue;
                }
                67 => {
                    let fields = self.u32()? as usize;
                    if fields > (1 << 24) - 2 {
                        return None;
                    }
                    let exported = match self.u8()? {
                        0 => false,
                        1 => true,
                        _ => return None,
                    };
                    let left = self.count(fields * 2 + 2)?;
                    let start = self.values.len();
                    self.frames.push(Frame::Record {
                        exported,
                        fields,
                        start,
                        left,
                    });
                    continue;
                }
                _ => return None,
            };
            let mut term = leaf?;
            // The term completes the containers whose last child it is.
            loop {
                let Some(frame) = self.frames.last_mut() else {
                    return Some(term);
                };
                self.values.push(term);
                let left = match frame {
                    Frame::Tuple { left, .. }
                    | Frame::List { left, .. }
                    | Frame::Map { left, .. }
                    | Frame::Export { left, .. }
                    | Frame::Fun { left, .. }
                    | Frame::Record { left, .. } => left,
                };
                *left -= 1;
                if *left != 0 {
                    break;
                }
                let frame = self.frames.pop()?;
                term = self.finish(frame)?;
            }
        }
    }

    // Port of erts/emulator/beam/external.c (dec_pid, dec_term NEW_PID_EXT/PID_EXT), OTP-29.1.1.
    fn pid(&mut self, tag: u8) -> Option<Term> {
        let node = self.atom()?;
        let id = self.u32()?;
        let serial = self.u32()?;
        let creation = if tag == 103 {
            let creation = u32::from(self.u8()?);
            if creation > 3 {
                return None;
            }
            creation
        } else {
            self.u32()?
        };
        if Self::is_this_node(node, creation) {
            Term::pid(id, serial)
        } else {
            self.builder
                .external_pid(Node::new(node, creation), id, serial)
                .ok()
        }
    }

    // Port of erts/emulator/beam/external.c (dec_term PORT_EXT/NEW_PORT_EXT/V4_PORT_EXT),
    // OTP-29.1.1.
    fn port(&mut self, tag: u8) -> Option<Term> {
        let node = self.atom()?;
        let id = if tag == 120 {
            self.u64()?
        } else {
            u64::from(self.u32()?)
        };
        let creation = if tag == 102 {
            let creation = u32::from(self.u8()?);
            if creation > 3 {
                return None;
            }
            creation
        } else {
            self.u32()?
        };
        if Self::is_this_node(node, creation) {
            Term::port(id)
        } else {
            self.builder
                .external_port(Node::new(node, creation), id)
                .ok()
        }
    }

    // Port of erts/emulator/beam/external.c (dec_term REFERENCE_EXT/NEW_REFERENCE_EXT/
    // NEWER_REFERENCE_EXT), OTP-29.1.1.
    fn reference(&mut self, tag: u8) -> Option<Term> {
        let count = if tag == 101 {
            1
        } else {
            usize::from(self.u16()?)
        };
        if !(1..=5).contains(&count) {
            return None;
        }
        let node = self.atom()?;
        let creation = if tag == 90 {
            self.u32()?
        } else {
            let creation = u32::from(self.u8()?);
            if creation > 3 {
                return None;
            }
            creation
        };
        let mut ids = [0u32; 5];
        for (index, slot) in ids.iter_mut().take(count).enumerate() {
            let id = self.u32()?;
            if index == 0 && tag != 90 && id >= (1 << 18) {
                return None;
            }
            *slot = id;
        }
        if Self::is_this_node(node, creation) && count <= 3 {
            // A saved magic reference gives that reference again.
            let mut local = [0u32; 3];
            local[..count].copy_from_slice(&ids[..count]);
            let saved = (local[2] == u32::MAX)
                .then(|| MagicRef::lookup_saved(u64::from(local[0]) | (u64::from(local[1]) << 32)))
                .flatten();
            match saved {
                Some(owner) => self.builder.magic_ref(owner).ok(),
                None => self.builder.local_ref(local).ok(),
            }
        } else {
            self.builder
                .external_ref(Node::new(node, creation), &ids[..count])
                .ok()
        }
    }

    /// Builds the container of a completed frame from its children.
    fn finish(&mut self, frame: Frame) -> Option<Term> {
        match frame {
            Frame::Tuple { start, .. } => {
                let tuple = self.builder.tuple(&self.values[start..]).ok();
                self.values.truncate(start);
                tuple
            }
            Frame::List { start, .. } => {
                let end = self.values.len() - 1;
                let mut list = self.values[end];
                for index in (start..end).rev() {
                    list = self.builder.cons(self.values[index], list).ok()?;
                }
                self.values.truncate(start);
                Some(list)
            }
            Frame::Map { start, .. } => {
                let mut pairs: Vec<(Term, Term)> = self.values[start..]
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|pair| (pair[0], pair[1]))
                    .collect();
                self.values.truncate(start);
                self.builder.map_from_decoded_pairs(&mut pairs).ok()
            }
            Frame::Export { start, .. } => {
                let [module, function, arity] = self.values[start..] else {
                    return None;
                };
                self.values.truncate(start);
                let arity = u8::try_from(arity.as_small()?).ok()?;
                let entry = Arc::new(ExportEntry::new(
                    module.as_atom()?,
                    function.as_atom()?,
                    arity,
                ));
                self.builder.export_fun(entry).ok()
            }
            Frame::Fun {
                arity,
                uniq,
                index,
                free,
                start,
                ..
            } => {
                let module = self.values[start].as_atom()?;
                let old_index = u32::try_from(self.values[start + 1].as_small()?).ok()?;
                let old_uniq = u32::try_from(self.values[start + 2].as_small()?).ok()?;
                let pid = self.values[start + 3];
                if pid.classify() != TermKind::Pid {
                    return None;
                }
                let entry = Arc::new(FunEntry {
                    dispatch_target: Default::default(),
                    pend_purge_address: Default::default(),
                    module,
                    arity,
                    index,
                    uniq,
                    old_index,
                    old_uniq,
                    pid,
                    dispatch: Default::default(),
                    dispatch_code: Default::default(),
                    dispatch_epoch: Default::default(),
                });
                // Port of erts/emulator/beam/external.c:5162-5168, OTP-29.1.1.
                let fun = self
                    .builder
                    .local_fun_stub(entry, &self.values[start + 4..start + 4 + free])
                    .ok();
                self.values.truncate(start);
                fun
            }
            Frame::Record {
                exported,
                fields,
                start,
                ..
            } => {
                let module = self.values[start].as_atom()?;
                let name = self.values[start + 1].as_atom()?;
                let mut pairs = Vec::with_capacity(fields);
                for index in 0..fields {
                    let field = self.values[start + 2 + index].as_atom()?;
                    if pairs.iter().any(|(seen, _)| *seen == field) {
                        return None;
                    }
                    pairs.push((field, self.values[start + 2 + fields + index]));
                }
                self.values.truncate(start);
                // Port of erts/emulator/beam/external.c:5257, OTP-29.1.1.
                self.builder
                    .native_record(module, name, exported, &pairs)
                    .ok()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{VecHeap, from_owned, to_owned};
    use arinsal_etf::{EncodeOptions, OwnedTerm, encode};

    fn atom(name: &str) -> OwnedTerm {
        OwnedTerm::Atom(name.to_owned())
    }

    fn decoded(sample: &OwnedTerm) -> OwnedTerm {
        let bytes = encode(sample, EncodeOptions::default());
        let mut heap = VecHeap::new_literal();
        let term = decode_literal(&bytes, &mut heap)
            .unwrap_or_else(|| panic!("the decoder declined {sample:?}"));
        to_owned(term).unwrap()
    }

    /// The decoder builds the terms the general decoder builds, for every kind of term.
    #[test]
    fn matches_the_general_decoder() {
        let samples = vec![
            OwnedTerm::Int(0),
            OwnedTerm::Int(255),
            OwnedTerm::Int(-70_000),
            OwnedTerm::Int(i64::MAX),
            OwnedTerm::BigInt(BigInt::from(1u8) << 100),
            OwnedTerm::BigInt(BigInt::from(-1i8) << 100),
            OwnedTerm::Float(1.5),
            atom("a"),
            atom("h\u{e9}llo"),
            atom("\u{3b1}\u{3b2}"),
            OwnedTerm::Nil,
            OwnedTerm::Binary(b"bytes".to_vec()),
            OwnedTerm::Binary(vec![7; 300]),
            OwnedTerm::BitString {
                bytes: vec![0xff, 0xe0],
                bits: 3,
            },
            OwnedTerm::Tuple(vec![atom("t"), OwnedTerm::Int(1), OwnedTerm::Tuple(vec![])]),
            OwnedTerm::List {
                elems: vec![OwnedTerm::Int(1), atom("b")],
                tail: Box::new(atom("tail")),
            },
            OwnedTerm::List {
                elems: (0..300).map(OwnedTerm::Int).collect(),
                tail: Box::new(OwnedTerm::Nil),
            },
            OwnedTerm::charlist("a string"),
            OwnedTerm::Map(vec![]),
            OwnedTerm::Map(vec![
                (atom("k"), OwnedTerm::Int(1)),
                (OwnedTerm::Int(5), atom("v")),
                (OwnedTerm::Binary(b"x".to_vec()), OwnedTerm::Nil),
            ]),
            OwnedTerm::Map(
                (0..100)
                    .map(|n| (OwnedTerm::Int(n), OwnedTerm::Int(-n)))
                    .collect(),
            ),
            OwnedTerm::Export {
                module: "lists".to_owned(),
                function: "map".to_owned(),
                arity: 2,
            },
            OwnedTerm::Pid {
                node: "other@host".to_owned(),
                id: 12,
                serial: 3,
                creation: 7,
            },
            OwnedTerm::Port {
                node: "other@host".to_owned(),
                id: 99,
                creation: 7,
            },
            OwnedTerm::Ref {
                node: "other@host".to_owned(),
                creation: 7,
                ids: vec![1, 2, 3],
            },
            OwnedTerm::Pid {
                node: "nonode@nohost".to_owned(),
                id: 1,
                serial: 0,
                creation: 0,
            },
            OwnedTerm::Ref {
                node: "nonode@nohost".to_owned(),
                creation: 0,
                ids: vec![5, 6, 7],
            },
            OwnedTerm::Fun {
                arity: 1,
                uniq: [3; 16],
                index: 4,
                module: "m".to_owned(),
                old_index: 5,
                old_uniq: 6,
                pid: Box::new(OwnedTerm::Pid {
                    node: "nonode@nohost".to_owned(),
                    id: 0,
                    serial: 0,
                    creation: 0,
                }),
                free_vars: vec![OwnedTerm::Int(1), atom("free")],
            },
            OwnedTerm::Record {
                exported: true,
                module: "m".to_owned(),
                name: "r".to_owned(),
                fields: vec![
                    ("a".to_owned(), OwnedTerm::Int(1)),
                    ("b".to_owned(), OwnedTerm::Tuple(vec![atom("x")])),
                ],
            },
        ];
        for sample in samples {
            let bytes = encode(&sample, EncodeOptions::default());
            let mut slow_heap = VecHeap::new_literal();
            let slow = from_owned(&arinsal_etf::decode(&bytes).unwrap(), &mut slow_heap).unwrap();
            assert_eq!(decoded(&sample), to_owned(slow).unwrap(), "{sample:?}");
        }
    }

    /// An old-style float (`FLOAT_EXT`).
    #[test]
    fn old_float() {
        let bytes = encode(
            &OwnedTerm::Float(2.25),
            EncodeOptions {
                minor_version: Some(0),
                ..EncodeOptions::default()
            },
        );
        assert_eq!(bytes[1], 99);
        let mut heap = VecHeap::new_literal();
        let term = decode_literal(&bytes, &mut heap).unwrap();
        assert_eq!(to_owned(term).unwrap(), OwnedTerm::Float(2.25));
    }

    /// Nesting has no limit but the memory.
    #[test]
    fn deep_nesting() {
        let mut bytes = vec![131];
        for _ in 0..100_000 {
            bytes.extend_from_slice(&[104, 1]);
        }
        bytes.push(106);
        let mut heap = VecHeap::new_literal();
        assert!(decode_literal(&bytes, &mut heap).is_some());
        let mut list = vec![131];
        for _ in 0..100_000 {
            list.extend_from_slice(&[108, 0, 0, 0, 1, 97, 1]);
        }
        list.push(106);
        assert!(decode_literal(&list, &mut heap).is_some());
    }

    /// What erts rejects when it loads the literal chunk is rejected here.
    #[test]
    fn malformed_input_is_an_error() {
        let mut heap = VecHeap::new_literal();
        let mut bad =
            |bytes: &[u8]| assert!(decode_literal(bytes, &mut heap).is_none(), "{bytes:?}");
        // No version byte, a wrong one, an empty entry.
        bad(&[]);
        bad(&[130, 97, 1]);
        bad(&[97, 1]);
        // Trailing bytes, truncation.
        bad(&[131, 97, 1, 97]);
        bad(&[131, 98, 0, 0]);
        bad(&[131, 108, 0, 0, 0, 5, 97, 1]);
        bad(&[131, 104, 2, 97, 1]);
        // A compressed term, an atom cache reference, an obsolete fun, a LOCAL_EXT.
        bad(&[131, 80, 0, 0, 0, 3, 120, 156, 0]);
        bad(&[131, 82, 0]);
        bad(&[131, 117, 0]);
        bad(&[131, 121, 0, 0, 0, 0, 106]);
        // Bad bignum sign, bad bit-string size, non-finite float, bad tiny creation.
        bad(&[131, 110, 1, 2, 5]);
        bad(&[131, 77, 0, 0, 0, 1, 9, 0]);
        bad(&[131, 77, 0, 0, 0, 0, 3]);
        bad(&[131, 70, 0x7f, 0xf0, 0, 0, 0, 0, 0, 0]);
        bad(&[131, 103, 119, 1, b'n', 0, 0, 0, 1, 0, 0, 0, 0, 4]);
        // A map with a repeated key.
        bad(&[131, 116, 0, 0, 0, 2, 97, 1, 97, 1, 97, 1, 97, 2]);
        // An export with a bad arity, a fun whose creator is not a pid, a record with a
        // repeated field.
        bad(&[131, 113, 119, 1, b'm', 119, 1, b'f', 98, 0, 0, 1, 0]);
        let mut fun = vec![131, 112, 0, 0, 0, 0, 1];
        fun.extend([0u8; 16]);
        fun.extend([0, 0, 0, 0, 0, 0, 0, 0]);
        fun.extend([119, 1, b'm', 97, 0, 97, 0, 119, 1, b'p']);
        bad(&fun);
        bad(&[
            131, 67, 0, 0, 0, 2, 1, 119, 1, b'm', 119, 1, b'r', 119, 1, b'a', 119, 1, b'a', 97, 1,
            97, 2,
        ]);
        // A Latin-1 atom of 256 characters.
        let mut long = vec![131, 100, 1, 0];
        long.extend(std::iter::repeat_n(b'a', 256));
        bad(&long);
    }
}
