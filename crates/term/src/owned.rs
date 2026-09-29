//! Heap-independent ETF values, built without calling ETF encoding or decoding.
use crate::{
    ExportEntry, FLOAT, FunEntry, FunRef, HeapAlloc, Identity, NEG_BIG, Node, POS_BIG, Term,
    TermBuilder, TermError, TermKind, global_atoms,
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
                    tasks.push(Task::List(elems.len()));
                    for item in elems.iter().rev() {
                        tasks.push(Task::Visit(item));
                    }
                    tasks.push(Task::Visit(tail));
                }
                OwnedTerm::Map(pairs) => {
                    tasks.push(Task::Map(pairs.len()));
                    for (key, val) in pairs.iter().rev() {
                        tasks.push(Task::Visit(val));
                        tasks.push(Task::Visit(key));
                    }
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
                } if node == "nonode@nohost" && *creation == 0 && ids.len() == 3 => {
                    values.push(builder.local_ref([ids[0], ids[1], ids[2]])?);
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
                    values.push(builder.export_fun(Arc::new(ExportEntry {
                        module,
                        function,
                        arity: *arity,
                    }))?);
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
                let fun = builder.local_fun(entry, &values[start + 1..])?;
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
                let mut tail = values[start];
                for i in (start + 1..values.len()).rev() {
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
                            ids,
                        }),
                    }
                }
                TermKind::Bitstring => {
                    // SAFETY: source heap and backing bytes remain live.
                    let view = unsafe { term.binary_ref().unwrap() };
                    let mut bytes = vec![0_u8; view.bit_len().div_ceil(8)];
                    for i in 0..view.bit_len() {
                        let bit = (view.bytes()[(view.start_bit() + i) / 8]
                            >> (7 - (view.start_bit() + i) % 8))
                            & 1;
                        bytes[i / 8] |= bit << (7 - i % 8);
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
