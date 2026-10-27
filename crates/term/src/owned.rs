//! Heap-independent ETF values, built without calling ETF encoding or decoding.
use crate::{
    ExportEntry, FLOAT, FunEntry, FunRef, HeapAlloc, Identity, MagicRef, NEG_BIG, Node, POS_BIG,
    Term, TermBuilder, TermError, TermKind, global_atoms,
};
use arinsal_etf::OwnedTerm;
use num_bigint::{BigInt, Sign};
use std::sync::Arc;

/// Build a runtime term from an owned ETF value, using an explicit work stack.
pub fn from_owned<H: HeapAlloc>(input: &OwnedTerm, heap: &mut H) -> Result<Term, TermError> {
    enum Task<'a> {
        Visit(&'a OwnedTerm),
        Tuple(usize),
        List(usize),
        Map(usize),
        Fun(&'a OwnedTerm),
        Record(&'a OwnedTerm),
    }
    let mut tasks = vec![Task::Visit(input)];
    let mut values = Vec::new();
    let mut builder = TermBuilder::new(heap);
    while let Some(task) = tasks.pop() {
        match task {
            Task::Visit(value) => match value {
                OwnedTerm::Int(n) => values.push(builder.int_from_i64(*n)?),
                OwnedTerm::BigInt(n) => values.push(builder.int_from_bigint(n)?),
                OwnedTerm::Float(n) => values.push(builder.float(*n)?),
                OwnedTerm::Atom(name) => values.push(Term::atom(
                    global_atoms()
                        .intern(name)
                        .map_err(|_| TermError::SystemLimit)?,
                )),
                OwnedTerm::Nil => values.push(Term::NIL),
                OwnedTerm::Binary(bytes) => values.push(builder.binary(bytes)?),
                OwnedTerm::BitString { bytes, bits } => {
                    if !(1..=7).contains(bits) || bytes.is_empty() {
                        return Err(TermError::BadArg);
                    }
                    values.push(builder.bitstring(bytes, (bytes.len() - 1) * 8 + *bits as usize)?);
                }
                OwnedTerm::Tuple(items) => {
                    tasks.push(Task::Tuple(items.len()));
                    for item in items.iter().rev() {
                        tasks.push(Task::Visit(item));
                    }
                }
                OwnedTerm::List { elems, tail } => {
                    // Heads before the tail: erts creates atoms in ETF stream order.
                    tasks.push(Task::List(elems.len()));
                    tasks.push(Task::Visit(tail));
                    for item in elems.iter().rev() {
                        tasks.push(Task::Visit(item));
                    }
                }
                OwnedTerm::Map(pairs) => {
                    tasks.push(Task::Map(pairs.len()));
                    for (key, val) in pairs.iter().rev() {
                        tasks.push(Task::Visit(val));
                        tasks.push(Task::Visit(key));
                    }
                }
                OwnedTerm::MagicRef(handle) => {
                    let owner = handle
                        .owner()
                        .and_then(|owner| owner.downcast::<MagicRef>().ok())
                        .ok_or(TermError::BadArg)?;
                    values.push(builder.magic_ref(owner)?);
                }
                OwnedTerm::Pid {
                    node,
                    id,
                    serial,
                    creation,
                } if node == "nonode@nohost" && *creation == 0 => {
                    values.push(Term::pid(*id, *serial).ok_or(TermError::BadArg)?);
                }
                OwnedTerm::Port { node, id, creation }
                    if node == "nonode@nohost" && *creation == 0 =>
                {
                    values.push(Term::port(*id).ok_or(TermError::BadArg)?);
                }
                OwnedTerm::Ref {
                    node,
                    creation,
                    ids,
                } if node == "nonode@nohost" && *creation == 0 && ids.len() <= 3 => {
                    // Port of erts/emulator/beam/external.c (dec_term, NEWER_REFERENCE_EXT),
                    // OTP-29.1.1: numbers of a saved magic reference give that reference.
                    let mut local_ids = [0; 3];
                    local_ids[..ids.len()].copy_from_slice(ids);
                    let saved = (local_ids[2] == u32::MAX)
                        .then(|| {
                            MagicRef::lookup_saved(
                                u64::from(local_ids[0]) | (u64::from(local_ids[1]) << 32),
                            )
                        })
                        .flatten();
                    values.push(match saved {
                        Some(owner) => builder.magic_ref(owner)?,
                        None => builder.local_ref(local_ids)?,
                    });
                }
                OwnedTerm::Pid {
                    node,
                    id,
                    serial,
                    creation,
                } => {
                    let name = global_atoms()
                        .intern(node)
                        .map_err(|_| TermError::SystemLimit)?;
                    values.push(builder.external_pid(Node::new(name, *creation), *id, *serial)?);
                }
                OwnedTerm::Port { node, id, creation } => {
                    let name = global_atoms()
                        .intern(node)
                        .map_err(|_| TermError::SystemLimit)?;
                    values.push(builder.external_port(Node::new(name, *creation), *id)?);
                }
                OwnedTerm::Ref {
                    node,
                    ids,
                    creation,
                } => {
                    let name = global_atoms()
                        .intern(node)
                        .map_err(|_| TermError::SystemLimit)?;
                    values.push(builder.external_ref(Node::new(name, *creation), ids)?);
                }
                OwnedTerm::Export {
                    module,
                    function,
                    arity,
                } => {
                    let module = global_atoms()
                        .intern(module)
                        .map_err(|_| TermError::SystemLimit)?;
                    let function = global_atoms()
                        .intern(function)
                        .map_err(|_| TermError::SystemLimit)?;
                    values.push(
                        builder.export_fun(Arc::new(ExportEntry::new(module, function, *arity)))?,
                    );
                }
                OwnedTerm::Fun { pid, free_vars, .. } => {
                    tasks.push(Task::Fun(value));
                    for free in free_vars.iter().rev() {
                        tasks.push(Task::Visit(free));
                    }
                    tasks.push(Task::Visit(pid));
                }
                OwnedTerm::Record { fields, .. } => {
                    // Port of erts/emulator/beam/external.c:5257, OTP-29.1.1.
                    tasks.push(Task::Record(value));
                    for (_, field_value) in fields.iter().rev() {
                        tasks.push(Task::Visit(field_value));
                    }
                }
                OwnedTerm::Other { .. } => return Err(TermError::Unsupported("ETF other")),
                _ => return Err(TermError::Unsupported("future ETF variant")),
            },
            Task::Fun(OwnedTerm::Fun {
                arity,
                uniq,
                index,
                module,
                old_index,
                old_uniq,
                free_vars,
                ..
            }) => {
                let start = values.len() - free_vars.len() - 1;
                let pid = values[start];
                let module = global_atoms()
                    .intern(module)
                    .map_err(|_| TermError::SystemLimit)?;
                let entry = Arc::new(FunEntry {
                    dispatch_target: Default::default(),
                    pend_purge_address: Default::default(),
                    module,
                    arity: *arity,
                    uniq: *uniq,
                    index: *index,
                    old_index: *old_index,
                    old_uniq: *old_uniq,
                    pid,
                    dispatch: Default::default(),
                    dispatch_code: Default::default(),
                    dispatch_epoch: Default::default(),
                });
                // Port of erts/emulator/beam/external.c:5162-5168, OTP-29.1.1.
                let fun = builder.local_fun_stub(entry, &values[start + 1..])?;
                values.truncate(start);
                values.push(fun);
            }
            Task::Fun(_) => return Err(TermError::BadArg),
            Task::Record(OwnedTerm::Record {
                exported,
                module,
                name,
                fields,
            }) => {
                let start = values.len() - fields.len();
                let module = global_atoms()
                    .intern(module)
                    .map_err(|_| TermError::SystemLimit)?;
                let name = global_atoms()
                    .intern(name)
                    .map_err(|_| TermError::SystemLimit)?;
                let mut record_fields = Vec::with_capacity(fields.len());
                for ((field_name, _), field_value) in
                    fields.iter().zip(values[start..].iter().copied())
                {
                    let field = global_atoms()
                        .intern(field_name)
                        .map_err(|_| TermError::SystemLimit)?;
                    record_fields.push((field, field_value));
                }
                let record = builder.native_record(module, name, *exported, &record_fields)?;
                values.truncate(start);
                values.push(record);
            }
            Task::Record(_) => return Err(TermError::BadArg),
            Task::Tuple(n) => {
                let start = values.len() - n;
                let term = builder.tuple(&values[start..])?;
                values.truncate(start);
                values.push(term);
            }
            Task::List(n) => {
                let start = values.len() - n - 1;
                let mut tail = values[values.len() - 1];
                for i in (start..values.len() - 1).rev() {
                    tail = builder.cons(values[i], tail)?;
                }
                values.truncate(start);
                values.push(tail);
            }
            Task::Map(n) => {
                let start = values.len() - 2 * n;
                let pairs = values[start..]
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|x| (x[0], x[1]))
                    .collect::<Vec<_>>();
                let map = builder.flatmap_from_pairs(&pairs)?;
                values.truncate(start);
                values.push(map);
            }
        }
    }
    values.pop().ok_or(TermError::BadArg)
}

/// Nesting depth beyond which [`decode_literal`] leaves a literal to the general decoder.
const LITERAL_DEPTH_LIMIT: usize = 64;

/// Decodes one external term of the kinds a module literal usually holds (small and big
/// integers, floats, atoms, binaries, tuples, lists and strings) straight onto `heap`, in one
/// pass without an intermediate [`OwnedTerm`]. `None` for anything else, and for any value the
/// general decoder would reject, so the caller falls back to it.
// Port of erts/emulator/beam/external.c (dec_term), OTP-29.1.1, for the tags of a literal:
// the atoms are put in stream order and the cells are built after their elements.
pub fn decode_literal<H: HeapAlloc>(bytes: &[u8], heap: &mut H) -> Option<Term> {
    if bytes.first() != Some(&131) {
        return None;
    }
    let mut decoder = LiteralDecoder {
        bytes,
        at: 1,
        builder: TermBuilder::new(heap),
        values: Vec::new(),
    };
    let term = decoder.term(0)?;
    (decoder.at == bytes.len()).then_some(term)
}

struct LiteralDecoder<'a, 'h, H: HeapAlloc> {
    bytes: &'a [u8],
    at: usize,
    builder: TermBuilder<'h, H>,
    /// The elements of the tuples and lists under construction.
    values: Vec<Term>,
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

    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_be_bytes(self.take(4)?.try_into().ok()?))
    }

    /// A count that cannot exceed the bytes left (every element takes one).
    fn count(&mut self, n: usize) -> Option<usize> {
        (n <= self.bytes.len() - self.at).then_some(n)
    }

    fn atom(&mut self, len: usize, utf8: bool) -> Option<Term> {
        let at = self.at;
        let end = at.checked_add(len)?;
        let name = self.bytes.get(at..end)?;
        self.at = end;
        let encoding = if utf8 {
            crate::AtomEncoding::Utf8
        } else {
            crate::AtomEncoding::Latin1
        };
        global_atoms()
            .put(name, encoding, false)
            .ok()
            .map(Term::atom)
    }

    fn term(&mut self, depth: usize) -> Option<Term> {
        if depth > LITERAL_DEPTH_LIMIT {
            return None;
        }
        match self.u8()? {
            97 => {
                let n = self.u8()?;
                self.builder.int_from_i64(i64::from(n)).ok()
            }
            98 => {
                let n = self.u32()? as i32;
                self.builder.int_from_i64(i64::from(n)).ok()
            }
            70 => {
                let bits = u64::from_be_bytes(self.take(8)?.try_into().ok()?);
                let value = f64::from_bits(bits);
                value.is_finite().then(|| self.builder.float(value).ok())?
            }
            100 | 118 => {
                let len = u16::from_be_bytes(self.take(2)?.try_into().ok()?) as usize;
                self.atom(len, self.bytes[self.at - 3] == 118)
            }
            115 | 119 => {
                let len = self.u8()? as usize;
                self.atom(len, self.bytes[self.at - 2] == 119)
            }
            106 => Some(Term::NIL),
            104 | 105 => {
                let tag = self.bytes[self.at - 1];
                let n = if tag == 104 {
                    usize::from(self.u8()?)
                } else {
                    self.u32()? as usize
                };
                let n = self.count(n)?;
                let start = self.values.len();
                for _ in 0..n {
                    let element = self.term(depth + 1)?;
                    self.values.push(element);
                }
                let tuple = self.builder.tuple(&self.values[start..]).ok();
                self.values.truncate(start);
                tuple
            }
            107 => {
                let n = usize::from(u16::from_be_bytes(self.take(2)?.try_into().ok()?));
                let from = self.at;
                self.take(n)?;
                let mut list = Term::NIL;
                for index in (from..from + n).rev() {
                    let byte = self.bytes[index];
                    let head = self.builder.int_from_i64(i64::from(byte)).ok()?;
                    list = self.builder.cons(head, list).ok()?;
                }
                Some(list)
            }
            108 => {
                let n = self.u32()? as usize;
                let n = self.count(n)?;
                let start = self.values.len();
                for _ in 0..n {
                    let element = self.term(depth + 1)?;
                    self.values.push(element);
                }
                let mut list = self.term(depth + 1)?;
                for index in (start..self.values.len()).rev() {
                    list = self.builder.cons(self.values[index], list).ok()?;
                }
                self.values.truncate(start);
                Some(list)
            }
            109 => {
                let n = self.u32()? as usize;
                let from = self.at;
                self.take(n)?;
                // The builder borrows the heap, not the input.
                let bytes = self.bytes;
                self.builder.binary(&bytes[from..from + n]).ok()
            }
            110 | 111 => {
                let tag = self.bytes[self.at - 1];
                let n = if tag == 110 {
                    usize::from(self.u8()?)
                } else {
                    self.u32()? as usize
                };
                let sign = self.u8()?;
                if sign > 1 {
                    return None;
                }
                let from = self.at;
                self.take(n)?;
                let bytes = self.bytes;
                let value = BigInt::from_bytes_le(
                    if sign == 0 { Sign::Plus } else { Sign::Minus },
                    &bytes[from..from + n],
                );
                match num_traits::ToPrimitive::to_i64(&value) {
                    Some(small) => self.builder.int_from_i64(small).ok(),
                    None => self.builder.int_from_bigint(&value).ok(),
                }
            }
            _ => None,
        }
    }
}

/// Convert a runtime term to its heap-independent form, iteratively.
pub fn to_owned(root: Term) -> Result<OwnedTerm, TermError> {
    enum Task {
        Visit(Term),
        Tuple(usize),
        List(usize),
        Map(usize),
        Fun(FunEntry, usize),
        Record {
            module: String,
            name: String,
            exported: bool,
            fields: Vec<String>,
        },
    }
    let mut tasks = vec![Task::Visit(root)];
    let mut values: Vec<OwnedTerm> = Vec::new();
    while let Some(task) = tasks.pop() {
        match task {
            Task::Visit(term) => match term.classify() {
                TermKind::Number => {
                    if let Some(n) = term.as_small() {
                        values.push(OwnedTerm::Int(n));
                        continue;
                    }
                    let h = term.header().unwrap();
                    // SAFETY: numeric header determines the payload layout.
                    let p = unsafe { term.raw_ptr() };
                    if h & 63 == FLOAT {
                        // SAFETY: float has one payload word.
                        values.push(OwnedTerm::Float(f64::from_bits(unsafe { *p.add(1) })));
                    } else if h & 63 == POS_BIG || h & 63 == NEG_BIG {
                        let mut bytes = Vec::new();
                        for i in 0..(h >> 6) as usize {
                            // SAFETY: bignum header describes its digit count.
                            bytes.extend_from_slice(&unsafe { *p.add(i + 1) }.to_le_bytes());
                        }
                        let sign = if h & 63 == NEG_BIG {
                            Sign::Minus
                        } else {
                            Sign::Plus
                        };
                        values.push(OwnedTerm::BigInt(BigInt::from_bytes_le(sign, &bytes)));
                    }
                }
                TermKind::Atom => values.push(OwnedTerm::Atom(
                    global_atoms()
                        .text(term.as_atom().unwrap())
                        .ok_or(TermError::BadArg)?
                        .to_string(),
                )),
                TermKind::Nil => values.push(OwnedTerm::Nil),
                TermKind::Pid | TermKind::Port | TermKind::Ref => {
                    match term.identity().ok_or(TermError::BadArg)? {
                        Identity::Pid {
                            node,
                            creation,
                            index,
                            serial,
                        } => values.push(OwnedTerm::Pid {
                            node: global_atoms()
                                .text(node)
                                .ok_or(TermError::BadArg)?
                                .to_string(),
                            id: index,
                            serial,
                            creation,
                        }),
                        Identity::Port { node, creation, id } => values.push(OwnedTerm::Port {
                            node: global_atoms()
                                .text(node)
                                .ok_or(TermError::BadArg)?
                                .to_string(),
                            id,
                            creation,
                        }),
                        Identity::Ref { .. } if term.is_magic_ref() => {
                            let owner = term.magic_owner().ok_or(TermError::BadArg)?;
                            values.push(OwnedTerm::MagicRef(arinsal_etf::MagicHandle::strong(
                                owner.id(),
                                owner,
                            )));
                        }
                        Identity::Ref {
                            node,
                            creation,
                            ids,
                        } => values.push(OwnedTerm::Ref {
                            node: global_atoms()
                                .text(node)
                                .ok_or(TermError::BadArg)?
                                .to_string(),
                            creation,
                            ids: ids.to_vec(),
                        }),
                    }
                }
                TermKind::Bitstring => {
                    // SAFETY: source heap and backing bytes remain live.
                    let view = unsafe { term.binary_ref().unwrap() };
                    let mut bytes = vec![0_u8; view.bit_len().div_ceil(8)];
                    if view.start_bit().is_multiple_of(8) && view.bit_len().is_multiple_of(8) {
                        let first = view.start_bit() / 8;
                        bytes.copy_from_slice(&view.bytes()[first..first + view.bit_len() / 8]);
                    } else {
                        for i in 0..view.bit_len() {
                            let bit = (view.bytes()[(view.start_bit() + i) / 8]
                                >> (7 - (view.start_bit() + i) % 8))
                                & 1;
                            bytes[i / 8] |= bit << (7 - i % 8);
                        }
                    }
                    if view.bit_len() % 8 == 0 {
                        values.push(OwnedTerm::Binary(bytes));
                    } else {
                        values.push(OwnedTerm::BitString {
                            bytes,
                            bits: (view.bit_len() % 8) as u8,
                        });
                    }
                }
                TermKind::Fun => {
                    // SAFETY: source heap retains the fun entry.
                    match unsafe { term.fun_ref().unwrap() } {
                        FunRef::Export { entry } => values.push(OwnedTerm::Export {
                            module: global_atoms()
                                .text(entry.module)
                                .ok_or(TermError::BadArg)?
                                .to_string(),
                            function: global_atoms()
                                .text(entry.function)
                                .ok_or(TermError::BadArg)?
                                .to_string(),
                            arity: entry.arity,
                        }),
                        FunRef::Local { entry, free_vars } => {
                            tasks.push(Task::Fun(entry.clone(), free_vars.len()));
                            for value in free_vars.iter().rev() {
                                tasks.push(Task::Visit(Term(*value)));
                            }
                            tasks.push(Task::Visit(entry.pid));
                        }
                    }
                }
                TermKind::Record => {
                    // Port of erts/emulator/beam/external.c:4018, OTP-29.1.1.
                    let snapshot = term.record_snapshot().ok_or(TermError::BadArg)?;
                    let module = global_atoms()
                        .text(snapshot.module)
                        .ok_or(TermError::BadArg)?
                        .to_string();
                    let name = global_atoms()
                        .text(snapshot.name)
                        .ok_or(TermError::BadArg)?
                        .to_string();
                    let fields = snapshot
                        .fields
                        .iter()
                        .map(|field| {
                            global_atoms()
                                .text(*field)
                                .map(|name| name.to_string())
                                .ok_or(TermError::BadArg)
                        })
                        .collect::<Result<Vec<_>, _>>()?;
                    let mut ordered_values = vec![Term::NIL; fields.len()];
                    let mut order: Vec<_> = snapshot.fields.iter().copied().enumerate().collect();
                    order.sort_by_key(|(_, field)| field.0);
                    for (sorted_index, (original_index, _)) in order.into_iter().enumerate() {
                        ordered_values[original_index] = snapshot.values[sorted_index];
                    }
                    tasks.push(Task::Record {
                        module,
                        name,
                        exported: snapshot.is_exported,
                        fields,
                    });
                    for value in ordered_values.into_iter().rev() {
                        tasks.push(Task::Visit(value));
                    }
                }
                TermKind::Tuple => {
                    // SAFETY: source heap remains stable during traversal.
                    let tuple = unsafe { term.tuple_ref().unwrap() };
                    tasks.push(Task::Tuple(tuple.len()));
                    for value in tuple.iter().collect::<Vec<_>>().into_iter().rev() {
                        tasks.push(Task::Visit(value));
                    }
                }
                TermKind::List => {
                    let mut elems = Vec::new();
                    let mut tail = term;
                    while tail.classify() == TermKind::List {
                        // SAFETY: list cells remain stable during traversal.
                        let (head, next) = unsafe { tail.cons_ref().unwrap() };
                        elems.push(head);
                        tail = next;
                    }
                    tasks.push(Task::List(elems.len()));
                    for value in elems.into_iter().rev() {
                        tasks.push(Task::Visit(value));
                    }
                    tasks.push(Task::Visit(tail));
                }
                TermKind::Map => {
                    let pairs = crate::hamt::pairs(term);
                    tasks.push(Task::Map(pairs.len()));
                    for (key, value) in pairs.into_iter().rev() {
                        tasks.push(Task::Visit(value));
                        tasks.push(Task::Visit(key));
                    }
                }
                _ => return Err(TermError::Unsupported("term kind")),
            },
            Task::Fun(entry, n) => {
                let start = values.len() - n - 1;
                let mut parts = values.split_off(start);
                let pid = Box::new(parts.remove(0));
                values.push(OwnedTerm::Fun {
                    arity: entry.arity,
                    uniq: entry.uniq,
                    index: entry.index,
                    module: global_atoms()
                        .text(entry.module)
                        .ok_or(TermError::BadArg)?
                        .to_string(),
                    old_index: entry.old_index,
                    old_uniq: entry.old_uniq,
                    pid,
                    free_vars: parts,
                });
            }
            Task::Record {
                module,
                name,
                exported,
                fields,
            } => {
                let start = values.len() - fields.len();
                let field_values = values.split_off(start);
                values.push(OwnedTerm::Record {
                    exported,
                    module,
                    name,
                    fields: fields.into_iter().zip(field_values).collect(),
                });
            }
            Task::Tuple(n) => {
                let start = values.len() - n;
                let items = values.split_off(start);
                values.push(OwnedTerm::Tuple(items));
            }
            Task::List(n) => {
                let start = values.len() - n - 1;
                let mut tail = values.split_off(start);
                let last = tail.remove(0);
                values.push(OwnedTerm::List {
                    elems: tail,
                    tail: Box::new(last),
                });
            }
            Task::Map(n) => {
                let start = values.len() - n * 2;
                let pairs = values.split_off(start);
                values.push(OwnedTerm::Map(
                    pairs
                        .as_chunks::<2>()
                        .0
                        .iter()
                        .map(|p| (p[0].clone(), p[1].clone()))
                        .collect(),
                ));
            }
        }
    }
    values.pop().ok_or(TermError::BadArg)
}

#[cfg(test)]
mod literal_tests {
    use super::*;
    use crate::VecHeap;
    use arinsal_etf::{EncodeOptions, encode};

    fn atom(name: &str) -> OwnedTerm {
        OwnedTerm::Atom(name.to_owned())
    }

    /// The streaming literal decoder builds the terms the general decoder builds.
    #[test]
    fn decode_literal_matches_the_general_decoder() {
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
            OwnedTerm::Nil,
            OwnedTerm::Binary(b"bytes".to_vec()),
            OwnedTerm::Tuple(vec![atom("t"), OwnedTerm::Int(1), OwnedTerm::Tuple(vec![])]),
            OwnedTerm::List {
                elems: vec![OwnedTerm::Int(1), atom("b")],
                tail: Box::new(atom("tail")),
            },
            OwnedTerm::List {
                elems: (0..300).map(OwnedTerm::Int).collect(),
                tail: Box::new(OwnedTerm::Nil),
            },
        ];
        for sample in samples {
            let bytes = encode(&sample, EncodeOptions::default());
            let mut fast_heap = VecHeap::new_literal();
            let fast = decode_literal(&bytes, &mut fast_heap)
                .unwrap_or_else(|| panic!("fast path declined {sample:?}"));
            let mut slow_heap = VecHeap::new_literal();
            let slow = from_owned(&arinsal_etf::decode(&bytes).unwrap(), &mut slow_heap).unwrap();
            assert_eq!(
                to_owned(fast).unwrap(),
                to_owned(slow).unwrap(),
                "{sample:?}"
            );
        }
    }

    /// Anything outside the common kinds, or malformed, is left to the general decoder.
    #[test]
    fn decode_literal_declines_what_it_does_not_handle() {
        let mut heap = VecHeap::new_literal();
        let map = encode(
            &OwnedTerm::Map(vec![(atom("k"), OwnedTerm::Int(1))]),
            EncodeOptions::default(),
        );
        assert!(decode_literal(&map, &mut heap).is_none());
        assert!(decode_literal(&[131, 108, 0, 0, 0, 5, 97, 1], &mut heap).is_none());
        assert!(decode_literal(&[131, 97, 1, 97], &mut heap).is_none());
        assert!(decode_literal(&[130, 97, 1], &mut heap).is_none());
    }
}
