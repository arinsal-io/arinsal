//! ETF BIFs over live process heap terms.
// Port of erts/emulator/beam/external.c (external term sizing, encoding, and decoding), OTP-29.1.1.

use std::borrow::Cow;
use std::cmp::Ordering;
use std::io::{Read, Write};
use std::sync::Arc;

use arinsal_term::{
    ExportEntry, FunEntry, FunRef, Identity, Node, Term, TermBuilder, TermKind, cmp, global_atoms,
};
use flate2::Compression;
use num_bigint::{BigInt, Sign};
use num_traits::ToPrimitive;

use crate::pure::{Heap, integer, make_list, tuple_build};
use crate::{BifError, BifFn, Ctx};

pub(super) fn lookup(module: &str, name: &str, arity: u8) -> Option<BifFn> {
    let f: BifFn = match (module, name, arity) {
        ("erlang", "term_to_binary", 1 | 2) => term_to_binary,
        ("erlang", "term_to_iovec", 1 | 2) => term_to_iovec,
        ("erlang", "external_size", 1 | 2) => external_size,
        ("erlang", "binary_to_term", 1 | 2) => binary_to_term,
        _ => return None,
    };
    arinsal_spec::bif_lookup(module, name, arity).map(|_| f)
}

#[derive(Default, Clone, Copy)]
struct EncodeOpts {
    minor: u8,
    compressed: Option<u8>,
    deterministic: bool,
    /// `term_to_binary(Term, [local])`. Port of external.c LOCAL_EXT, OTP-29.1.1.
    local: bool,
}

fn atom_name(term: Term) -> Option<String> {
    global_atoms().text(term.as_atom()?).map(|s| s.to_string())
}

fn options(term: Option<Term>) -> Result<EncodeOpts, BifError> {
    let mut opts = EncodeOpts {
        minor: 2,
        ..EncodeOpts::default()
    };
    let Some(mut tail) = term else {
        return Ok(opts);
    };
    while tail != Term::NIL {
        // SAFETY: BIF arguments remain on stable live heaps throughout this call.
        let (head, next) = unsafe { tail.cons_ref() }.ok_or(BifError::BADARG)?;
        tail = next;
        match atom_name(head).as_deref() {
            Some("compressed") => opts.compressed = Some(6),
            Some("deterministic") => opts.deterministic = true,
            // Port of erts/emulator/beam/external.c:3305 (LOCAL_EXT), OTP-29.1.1.
            Some("local") => opts.local = true,
            _ => {
                // SAFETY: BIF arguments remain on stable live heaps throughout this call.
                let tuple = unsafe { head.tuple_ref() }.ok_or(BifError::BADARG)?;
                if tuple.len() != 2 {
                    return Err(BifError::BADARG);
                }
                let name = atom_name(tuple.get(0).unwrap()).ok_or(BifError::BADARG)?;
                let value = tuple.get(1).unwrap().as_small().ok_or(BifError::BADARG)?;
                match (name.as_str(), value) {
                    ("compressed", 0..=9) => opts.compressed = Some(value as u8),
                    ("minor_version", 0..=2) => opts.minor = value as u8,
                    _ => return Err(BifError::BADARG),
                }
            }
        }
    }
    Ok(opts)
}

fn int_bytes(out: &mut Vec<u8>, n: &BigInt) {
    if let Some(n) = n.to_i64() {
        if let Ok(byte) = u8::try_from(n) {
            out.extend_from_slice(&[97, byte]);
            return;
        }
        if let Ok(word) = i32::try_from(n) {
            out.push(98);
            out.extend_from_slice(&word.to_be_bytes());
            return;
        }
    }
    let (sign, digits) = n.to_bytes_le();
    if digits.len() < 256 {
        out.extend_from_slice(&[110, digits.len() as u8]);
    } else {
        out.push(111);
        out.extend_from_slice(&(digits.len() as u32).to_be_bytes());
    }
    out.push(u8::from(sign == Sign::Minus));
    out.extend_from_slice(&digits);
}

fn atom_bytes(out: &mut Vec<u8>, name: &str, minor: u8) {
    // Port of erts/emulator/beam/external.c (ATOM_EXT selection), OTP-29.1.1.
    if minor <= 1 && name.chars().all(|c| (c as u32) <= 255) {
        let latin: Vec<u8> = name.chars().map(|c| c as u8).collect();
        out.push(100);
        out.extend_from_slice(&(latin.len() as u16).to_be_bytes());
        out.extend_from_slice(&latin);
    } else {
        let bytes = name.as_bytes();
        if bytes.len() <= 255 {
            out.extend_from_slice(&[119, bytes.len() as u8]);
        } else {
            out.push(118);
            out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
        }
        out.extend_from_slice(bytes);
    }
}

fn atom_term(out: &mut Vec<u8>, term: Term, minor: u8) -> Result<(), BifError> {
    atom_bytes(out, &atom_name(term).ok_or(BifError::BADARG)?, minor);
    Ok(())
}

fn bit_bytes(term: Term) -> Result<(Vec<u8>, usize), BifError> {
    // SAFETY: the process owns the binary; no writable append occurs in this BIF.
    let view = unsafe { term.binary_ref() }.ok_or(BifError::BADARG)?;
    let mut bytes = vec![0; view.bit_len().div_ceil(8)];
    if view.start_bit().is_multiple_of(8) {
        let start = view.start_bit() / 8;
        let len = bytes.len();
        bytes.copy_from_slice(&view.bytes()[start..start + len]);
    } else {
        for (i, byte) in bytes.iter_mut().enumerate() {
            let at = view.start_bit() + i * 8;
            let first = view.bytes()[at / 8];
            let next = view.bytes().get(at / 8 + 1).copied().unwrap_or(0);
            *byte = (first << (at % 8)) | (next >> (8 - at % 8));
        }
    }
    if view.bit_len() % 8 != 0 {
        let mask = 0xff << (8 - view.bit_len() % 8);
        *bytes.last_mut().unwrap() &= mask;
    }
    Ok((bytes, view.bit_len()))
}

fn exact_key_cmp(left: Term, right: Term) -> Ordering {
    // CMP_TERM in external.c:3217 uses erts_cmp(..., exact=1), OTP-29.1.1.
    let mut pending = vec![(left, right)];
    while let Some((left, right)) = pending.pop() {
        if left == right {
            continue;
        }
        let lk = left.classify();
        let rk = right.classify();
        let order = lk.cmp(&rk);
        if order != Ordering::Equal {
            return order;
        }
        match lk {
            TermKind::Number => {
                let lf = left.header().is_some_and(|h| h & 63 == 0x18);
                let rf = right.header().is_some_and(|h| h & 63 == 0x18);
                let order = lf.cmp(&rf);
                if order != Ordering::Equal {
                    return order;
                }
                let order = if lf {
                    // SAFETY: FLOAT headers above identify live boxed floats.
                    let a = unsafe { left.float_ref() }.unwrap().get();
                    // SAFETY: FLOAT headers above identify live boxed floats.
                    let b = unsafe { right.float_ref() }.unwrap().get();
                    a.total_cmp(&b)
                } else {
                    cmp(left, right)
                };
                if order != Ordering::Equal {
                    return order;
                }
            }
            TermKind::Tuple => {
                // SAFETY: both tuple heaps remain stable for the BIF call.
                let a = unsafe { left.tuple_ref() }.unwrap();
                // SAFETY: both tuple heaps remain stable for the BIF call.
                let b = unsafe { right.tuple_ref() }.unwrap();
                let order = a.len().cmp(&b.len());
                if order != Ordering::Equal {
                    return order;
                }
                for i in (0..a.len()).rev() {
                    pending.push((a.get(i).unwrap(), b.get(i).unwrap()));
                }
            }
            TermKind::List => {
                // SAFETY: live cons cells are stable for the BIF call.
                let (ah, at) = unsafe { left.cons_ref() }.unwrap();
                // SAFETY: live cons cells are stable for the BIF call.
                let (bh, bt) = unsafe { right.cons_ref() }.unwrap();
                pending.push((at, bt));
                pending.push((ah, bh));
            }
            TermKind::Map => {
                let mut a = arinsal_maps::to_list(left).unwrap_or_default();
                let mut b = arinsal_maps::to_list(right).unwrap_or_default();
                let order = a.len().cmp(&b.len());
                if order != Ordering::Equal {
                    return order;
                }
                a.sort_by(|x, y| exact_key_cmp(x.0, y.0));
                b.sort_by(|x, y| exact_key_cmp(x.0, y.0));
                for ((ak, av), (bk, bv)) in a.into_iter().zip(b).rev() {
                    pending.push((av, bv));
                    pending.push((ak, bk));
                }
            }
            _ => {
                let order = cmp(left, right);
                if order != Ordering::Equal {
                    return order;
                }
            }
        }
    }
    Ordering::Equal
}

enum Work {
    Term(Term),
    PatchFun(usize),
}

type EncodedWithSplits = (Vec<u8>, Vec<(usize, usize)>);

fn encode_plain_with_splits(term: Term, opts: EncodeOpts) -> Result<EncodedWithSplits, BifError> {
    let mut out = vec![131];
    if opts.local {
        // Port of erts/emulator/beam/external.c:3305 (encode LOCAL_EXT), OTP-29.1.1.
        // The decoder skips the 4-byte hash. Zero matches what the inet driver reads.
        out.extend_from_slice(&[121, 0, 0, 0, 0]);
    }
    let mut splits = Vec::new();
    let mut work = vec![Work::Term(term)];
    // A scheduler can yield after a bounded number of popped work items here.
    while let Some(item) = work.pop() {
        let term = match item {
            Work::PatchFun(at) => {
                let size = u32::try_from(out.len() - at).map_err(|_| BifError::SystemLimit)?;
                out[at..at + 4].copy_from_slice(&size.to_be_bytes());
                continue;
            }
            Work::Term(term) => term,
        };
        match term.classify() {
            TermKind::Number => {
                if let Some(n) = term.as_small() {
                    int_bytes(&mut out, &BigInt::from(n));
                } else if let Some(header) = term.header() {
                    if header & 63 == 0x18 {
                        // SAFETY: a live boxed FLOAT has one initialized data word.
                        let f = unsafe { term.float_ref() }.ok_or(BifError::BADARG)?.get();
                        if opts.minor == 0 {
                            let s = format!("{f:.20e}");
                            let (mantissa, exponent) = s.split_once('e').unwrap();
                            let exp: i32 = exponent.parse().unwrap();
                            let rendered = format!(
                                "{mantissa}e{}{:02}",
                                if exp < 0 { '-' } else { '+' },
                                exp.abs()
                            );
                            out.push(99);
                            out.extend_from_slice(rendered.as_bytes());
                            out.resize(out.len() + 31 - rendered.len(), 0);
                        } else {
                            out.push(70);
                            out.extend_from_slice(&f.to_bits().to_be_bytes());
                        }
                    } else {
                        // SAFETY: a live boxed integer has initialized magnitude words.
                        let n = unsafe { term.big_ref() }
                            .ok_or(BifError::BADARG)?
                            .to_bigint();
                        int_bytes(&mut out, &n);
                    }
                }
            }
            TermKind::Atom => atom_term(&mut out, term, opts.minor)?,
            TermKind::Nil => out.push(106),
            TermKind::List => {
                let mut heads = Vec::new();
                let mut tail = term;
                while tail.classify() == TermKind::List {
                    // SAFETY: source cons cells remain live and stable during encoding.
                    let (head, next) = unsafe { tail.cons_ref() }.ok_or(BifError::BADARG)?;
                    heads.push(head);
                    tail = next;
                    if heads.len() > u32::MAX as usize {
                        return Err(BifError::SystemLimit);
                    }
                }
                if tail == Term::NIL
                    && heads.len() <= u16::MAX as usize
                    && heads
                        .iter()
                        .all(|h| h.as_small().is_some_and(|n| (0..=255).contains(&n)))
                {
                    out.push(107);
                    out.extend_from_slice(&(heads.len() as u16).to_be_bytes());
                    out.extend(heads.into_iter().map(|h| h.as_small().unwrap() as u8));
                } else {
                    out.push(108);
                    out.extend_from_slice(&(heads.len() as u32).to_be_bytes());
                    work.push(Work::Term(tail));
                    work.extend(heads.into_iter().rev().map(Work::Term));
                }
            }
            TermKind::Tuple => {
                // SAFETY: tuple remains live and stable during encoding.
                let view = unsafe { term.tuple_ref() }.ok_or(BifError::BADARG)?;
                if view.len() <= 255 {
                    out.extend_from_slice(&[104, view.len() as u8]);
                } else {
                    out.push(105);
                    out.extend_from_slice(&(view.len() as u32).to_be_bytes());
                }
                let elements: Vec<_> = view.iter().collect();
                work.extend(elements.into_iter().rev().map(Work::Term));
            }
            TermKind::Map => {
                let mut pairs =
                    arinsal_maps::term_to_binary_pairs(term).map_err(|_| BifError::BADARG)?;
                if opts.deterministic {
                    pairs.sort_by(|a, b| exact_key_cmp(a.0, b.0));
                }
                out.push(116);
                out.extend_from_slice(&(pairs.len() as u32).to_be_bytes());
                for (key, value) in pairs.into_iter().rev() {
                    work.push(Work::Term(value));
                    work.push(Work::Term(key));
                }
            }
            TermKind::Bitstring => {
                // SAFETY: the binary owner remains live and no append runs during encoding.
                let view = unsafe { term.binary_ref() }.ok_or(BifError::BADARG)?;
                let bits = view.bit_len();
                let len = bits.div_ceil(8);
                let n = u32::try_from(len).map_err(|_| BifError::SystemLimit)?;
                if bits.is_multiple_of(8) {
                    out.push(109);
                    out.extend_from_slice(&n.to_be_bytes());
                } else {
                    out.push(77);
                    out.extend_from_slice(&n.to_be_bytes());
                    out.push((bits % 8) as u8);
                }
                let start = out.len();
                if view.start_bit().is_multiple_of(8) {
                    let offset = view.start_bit() / 8;
                    out.extend_from_slice(&view.bytes()[offset..offset + len]);
                } else {
                    let offset = view.start_bit();
                    for i in 0..len {
                        let at = offset + i * 8;
                        let first = view.bytes()[at / 8];
                        let next = view.bytes().get(at / 8 + 1).copied().unwrap_or(0);
                        out.push((first << (at % 8)) | (next >> (8 - at % 8)));
                    }
                }
                if !bits.is_multiple_of(8) {
                    *out.last_mut().unwrap() &= 0xff << (8 - bits % 8);
                }
                if len > 64 {
                    splits.push((start, out.len()));
                }
            }
            TermKind::Pid | TermKind::Port | TermKind::Ref => {
                let identity = term.identity().ok_or(BifError::BADARG)?;
                match identity {
                    Identity::Pid {
                        node,
                        creation,
                        index,
                        serial,
                    } => {
                        out.push(88);
                        // Port of erts/emulator/beam/external.c:3651 (local pid node), OTP-29.1.1.
                        write_node(&mut out, node, opts)?;
                        out.extend_from_slice(&index.to_be_bytes());
                        out.extend_from_slice(&serial.to_be_bytes());
                        out.extend_from_slice(&local_creation(creation, opts).to_be_bytes());
                    }
                    Identity::Port { node, creation, id } => {
                        out.push(120);
                        write_node(&mut out, node, opts)?;
                        out.extend_from_slice(&id.to_be_bytes());
                        out.extend_from_slice(&local_creation(creation, opts).to_be_bytes());
                    }
                    Identity::Ref {
                        node,
                        creation,
                        ids,
                    } => {
                        out.push(90);
                        out.extend_from_slice(&(ids.len() as u16).to_be_bytes());
                        write_node(&mut out, node, opts)?;
                        out.extend_from_slice(&local_creation(creation, opts).to_be_bytes());
                        for id in ids {
                            out.extend_from_slice(&id.to_be_bytes());
                        }
                    }
                }
            }
            TermKind::Fun => {
                // SAFETY: the live source heap retains the entry and its environment.
                match unsafe { term.fun_ref() }.ok_or(BifError::BADARG)? {
                    FunRef::Export { entry } => {
                        out.push(113);
                        atom_term(&mut out, Term::atom(entry.module), opts.minor)?;
                        atom_term(&mut out, Term::atom(entry.function), opts.minor)?;
                        int_bytes(&mut out, &BigInt::from(entry.arity));
                    }
                    FunRef::Local { entry, free_vars } => {
                        out.push(112);
                        let at = out.len();
                        out.extend_from_slice(&[0; 4]);
                        out.push(entry.arity);
                        out.extend_from_slice(&entry.uniq);
                        out.extend_from_slice(&entry.index.to_be_bytes());
                        out.extend_from_slice(&(free_vars.len() as u32).to_be_bytes());
                        atom_term(&mut out, Term::atom(entry.module), opts.minor)?;
                        int_bytes(&mut out, &BigInt::from(entry.old_index));
                        int_bytes(&mut out, &BigInt::from(entry.old_uniq));
                        work.push(Work::PatchFun(at));
                        // SAFETY: the live source heap retains the fun entry and environment.
                        let view = unsafe { term.fun_ref() }.unwrap();
                        for i in (0..view.num_free()).rev() {
                            work.push(Work::Term(view.free(i).unwrap()));
                        }
                        work.push(Work::Term(entry.pid));
                    }
                }
            }
            TermKind::Record => {
                // Port of erts/emulator/beam/external.c:4010-4031, OTP-29.1.1.
                // SAFETY: the live record retains its definition and values.
                let record = unsafe { term.record_ref() }.ok_or(BifError::BADARG)?;
                out.push(67);
                out.extend_from_slice(&(record.len() as u32).to_be_bytes());
                out.push(u8::from(record.is_exported()));
                atom_term(&mut out, Term::atom(record.module()), opts.minor)?;
                atom_term(&mut out, Term::atom(record.name()), opts.minor)?;
                let mut values = Vec::with_capacity(record.len());
                for i in 0..record.len() {
                    let sorted = record.sorted_index(i).ok_or(BifError::BADARG)?;
                    atom_term(
                        &mut out,
                        Term::atom(record.key(sorted).ok_or(BifError::BADARG)?),
                        opts.minor,
                    )?;
                    values.push(record.value(sorted).ok_or(BifError::BADARG)?);
                }
                work.extend(values.into_iter().rev().map(Work::Term));
            }
            _ => return Err(BifError::Unsupported("ETF representation")),
        }
    }
    Ok((out, splits))
}

// Port of erts/emulator/beam/external.c:3651 (NIL_EXT node when encoding local), OTP-29.1.1.
fn write_node(
    out: &mut Vec<u8>,
    node: arinsal_term::Atom,
    opts: EncodeOpts,
) -> Result<(), BifError> {
    if opts.local {
        out.push(106);
        Ok(())
    } else {
        atom_term(out, Term::atom(node), opts.minor)
    }
}

fn local_creation(creation: u32, opts: EncodeOpts) -> u32 {
    if opts.local { 0 } else { creation }
}

fn encode_plain(term: Term, opts: EncodeOpts) -> Result<Vec<u8>, BifError> {
    encode_plain_with_splits(term, opts).map(|(bytes, _)| bytes)
}

fn encode(term: Term, opts: EncodeOpts) -> Result<Vec<u8>, BifError> {
    let plain = encode_plain(term, opts)?;
    if let Some(level) = opts.compressed.filter(|n| *n > 0) {
        let mut z = flate2::write::ZlibEncoder::new(Vec::new(), Compression::new(level as u32));
        z.write_all(&plain[1..])
            .map_err(|_| BifError::SystemLimit)?;
        let bytes = z.finish().map_err(|_| BifError::SystemLimit)?;
        // Port of erts/emulator/beam/external.c:2276-2300, OTP-29.1.1.
        if bytes.len() + 5 < plain.len() {
            let mut compressed = vec![131, 80];
            compressed.extend_from_slice(&((plain.len() - 1) as u32).to_be_bytes());
            compressed.extend_from_slice(&bytes);
            return Ok(compressed);
        }
    }
    Ok(plain)
}

fn result_binary(ctx: &mut Ctx<'_>, bytes: &[u8]) -> Result<Term, BifError> {
    TermBuilder::new(&mut Heap(ctx.heap))
        .binary(bytes)
        .map_err(|_| BifError::SystemLimit)
}

fn term_to_binary(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let opts = options(args.get(1).copied())?;
    let bytes = encode(args[0], opts)?;
    ctx.charge_reductions(bytes.len());
    result_binary(ctx, &bytes)
}

fn external_size(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let mut opts = options(args.get(1).copied())?;
    opts.compressed = None;
    let bytes = encode_plain(args[0], opts)?;
    ctx.charge_reductions(bytes.len());
    integer(ctx, bytes.len())
}

fn term_to_iovec(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let opts = options(args.get(1).copied())?;
    if opts.compressed.is_some_and(|level| level > 0) {
        let bytes = encode(args[0], opts)?;
        ctx.charge_reductions(bytes.len());
        return result_binary(ctx, &bytes);
    }
    let (bytes, splits) = encode_plain_with_splits(args[0], opts)?;
    ctx.charge_reductions(bytes.len());
    let mut at = 0;
    let mut parts = Vec::new();
    for (start, end) in splits {
        if start > at {
            parts.push(result_binary(ctx, &bytes[at..start])?);
        }
        parts.push(result_binary(ctx, &bytes[start..end])?);
        at = end;
    }
    if at < bytes.len() {
        parts.push(result_binary(ctx, &bytes[at..])?);
    }
    Ok(make_list(ctx, parts, Term::NIL))
}

#[derive(Default)]
struct DecodeOpts {
    safe: bool,
    used: bool,
}

fn decode_options(term: Option<Term>) -> Result<DecodeOpts, BifError> {
    let mut opts = DecodeOpts::default();
    let Some(mut tail) = term else {
        return Ok(opts);
    };
    while tail != Term::NIL {
        // SAFETY: the option list remains live and stable during the BIF.
        let (head, next) = unsafe { tail.cons_ref() }.ok_or(BifError::BADARG)?;
        tail = next;
        match atom_name(head).as_deref() {
            Some("safe") => opts.safe = true,
            Some("used") => opts.used = true,
            _ => return Err(BifError::BADARG),
        }
    }
    Ok(opts)
}

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], BifError> {
        let end = self.at.checked_add(n).ok_or(BifError::BADARG)?;
        let part = self.bytes.get(self.at..end).ok_or(BifError::BADARG)?;
        self.at = end;
        Ok(part)
    }
    fn u8(&mut self) -> Result<u8, BifError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, BifError> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn u32(&mut self) -> Result<u32, BifError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> Result<u64, BifError> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn atom(
        &mut self,
        safe: bool,
        ctx: &mut Option<&mut Ctx<'_>>,
    ) -> Result<(Term, String), BifError> {
        let tag = self.u8()?;
        let (len, utf8) = match tag {
            100 => (self.u16()? as usize, false),
            115 => (self.u8()? as usize, false),
            118 => (self.u16()? as usize, true),
            119 => (self.u8()? as usize, true),
            _ => return Err(BifError::BADARG),
        };
        let raw = self.take(len)?;
        let name = if utf8 {
            std::str::from_utf8(raw)
                .map_err(|_| BifError::BADARG)?
                .to_owned()
        } else {
            raw.iter().map(|b| char::from(*b)).collect::<String>()
        };
        if name.chars().count() > 255 {
            return Err(BifError::BADARG);
        }
        let atoms = global_atoms();
        let atom = if safe {
            atoms.get(&name).ok_or(BifError::BADARG)?
        } else if ctx.is_some() {
            atoms.intern(&name).map_err(|_| BifError::SystemLimit)?
        } else {
            atoms.get(&name).unwrap_or(arinsal_term::atoms::NONAME)
        };
        Ok((Term::atom(atom), name))
    }
}

enum Shape {
    Atom(String),
    Int(i64),
    Pid,
    Other,
}

enum FrameKind {
    Tuple,
    List,
    Map,
    Export,
    Fun {
        arity: u8,
        uniq: [u8; 16],
        index: u32,
        free: usize,
    },
    Record {
        exported: bool,
        fields: usize,
    },
}
struct Frame {
    kind: FrameKind,
    left: usize,
    values: Vec<Term>,
    shapes: Vec<Shape>,
}

fn built(
    ctx: &mut Option<&mut Ctx<'_>>,
    f: impl FnOnce(&mut TermBuilder<'_, Heap<'_>>) -> Result<Term, arinsal_term::TermError>,
) -> Result<Term, BifError> {
    if let Some(ctx) = ctx.as_deref_mut() {
        let mut heap = Heap(ctx.heap);
        f(&mut TermBuilder::new(&mut heap)).map_err(|e| match e {
            arinsal_term::TermError::SystemLimit => BifError::SystemLimit,
            _ => BifError::BADARG,
        })
    } else {
        Ok(Term::NIL)
    }
}

fn finish(frame: Frame, ctx: &mut Option<&mut Ctx<'_>>) -> Result<(Term, Shape), BifError> {
    let values = frame.values;
    match frame.kind {
        FrameKind::Tuple => Ok((built(ctx, |b| b.tuple(&values))?, Shape::Other)),
        FrameKind::List => {
            let mut it = values.into_iter().rev();
            let mut tail = it.next().ok_or(BifError::BADARG)?;
            if ctx.is_some() {
                for head in it {
                    tail = built(ctx, |b| b.cons(head, tail))?;
                }
            }
            Ok((tail, Shape::Other))
        }
        FrameKind::Map => {
            // Port of erts/emulator/beam/external.c:5428, OTP-29.1.1.
            let pairs: Vec<_> = values
                .as_chunks::<2>()
                .0
                .iter()
                .map(|p| (p[0], p[1]))
                .collect();
            if ctx.is_some() {
                let ctx = ctx.as_deref_mut().unwrap();
                let map =
                    arinsal_maps::from_pairs(&pairs, ctx.heap).map_err(|_| BifError::BADARG)?;
                if arinsal_maps::size(map).map_err(|_| BifError::BADARG)? != pairs.len() {
                    return Err(BifError::BADARG);
                }
                Ok((map, Shape::Other))
            } else {
                Ok((Term::NIL, Shape::Other))
            }
        }
        FrameKind::Export => {
            if !matches!(
                frame.shapes.as_slice(),
                [Shape::Atom(_), Shape::Atom(_), Shape::Int(0..=255)]
            ) {
                return Err(BifError::BADARG);
            }
            let term = if ctx.is_some() {
                let entry = Arc::new(ExportEntry {
                    module: values[0].as_atom().unwrap(),
                    function: values[1].as_atom().unwrap(),
                    arity: values[2].as_small().ok_or(BifError::BADARG)? as u8,
                });
                built(ctx, |b| b.export_fun(entry))?
            } else {
                Term::NIL
            };
            Ok((term, Shape::Other))
        }
        FrameKind::Fun {
            arity,
            uniq,
            index,
            free,
        } => {
            if !matches!(frame.shapes.first(), Some(Shape::Atom(_)))
                || !matches!(frame.shapes.get(1), Some(Shape::Int(0..=4_294_967_295)))
                || !matches!(frame.shapes.get(2), Some(Shape::Int(0..=4_294_967_295)))
                || !matches!(frame.shapes.get(3), Some(Shape::Pid))
            {
                return Err(BifError::BADARG);
            }
            let term = if ctx.is_some() {
                let entry = Arc::new(FunEntry {
                    dispatch_target: Default::default(),
                    module: values[0].as_atom().unwrap(),
                    arity,
                    index,
                    uniq,
                    old_index: values[1].as_small().ok_or(BifError::BADARG)? as u32,
                    old_uniq: values[2].as_small().ok_or(BifError::BADARG)? as u32,
                    pid: values[3],
                    dispatch: Default::default(),
                    dispatch_code: Default::default(),
                    dispatch_epoch: Default::default(),
                });
                built(ctx, |b| b.local_fun(entry, &values[4..4 + free]))?
            } else {
                Term::NIL
            };
            Ok((term, Shape::Other))
        }
        FrameKind::Record { exported, fields } => {
            if !frame.shapes[..fields + 2]
                .iter()
                .all(|shape| matches!(shape, Shape::Atom(_)))
            {
                return Err(BifError::BADARG);
            }
            let mut names = std::collections::HashSet::new();
            for shape in &frame.shapes[2..fields + 2] {
                if let Shape::Atom(name) = shape
                    && !names.insert(name)
                {
                    return Err(BifError::BADARG);
                }
            }
            let term = if ctx.is_some() {
                let pairs: Vec<_> = (0..fields)
                    .map(|i| (values[i + 2].as_atom().unwrap(), values[i + fields + 2]))
                    .collect();
                built(ctx, |b| {
                    b.native_record(
                        values[0].as_atom().unwrap(),
                        values[1].as_atom().unwrap(),
                        exported,
                        &pairs,
                    )
                })?
            } else {
                Term::NIL
            };
            Ok((term, Shape::Other))
        }
    }
}

fn count_ok(count: usize, remaining: usize) -> Result<(), BifError> {
    if count > remaining {
        Err(BifError::BADARG)
    } else {
        Ok(())
    }
}

fn parse(
    bytes: &[u8],
    safe: bool,
    mut ctx: Option<&mut Ctx<'_>>,
) -> Result<(Term, usize), BifError> {
    let mut r = Reader { bytes, at: 0 };
    let mut stack: Vec<Frame> = Vec::new();
    loop {
        let tag = r.u8()?;
        let result: Option<(Term, Shape)> = match tag {
            97 | 98 => {
                let n = if tag == 97 {
                    r.u8()? as i64
                } else {
                    r.u32()? as i32 as i64
                };
                Some((built(&mut ctx, |b| b.int_from_i64(n))?, Shape::Int(n)))
            }
            110 | 111 => {
                let len = if tag == 110 {
                    r.u8()? as usize
                } else {
                    r.u32()? as usize
                };
                let sign = r.u8()?;
                let number = BigInt::from_bytes_le(
                    if sign == 0 { Sign::Plus } else { Sign::Minus },
                    r.take(len)?,
                );
                let shape = number.to_i64().map_or(Shape::Other, Shape::Int);
                Some((built(&mut ctx, |b| b.int_from_bigint(&number))?, shape))
            }
            70 | 99 => {
                let f = if tag == 70 {
                    f64::from_bits(r.u64()?)
                } else {
                    let raw = r.take(31)?;
                    let end = raw.iter().position(|b| *b == 0).unwrap_or(31);
                    std::str::from_utf8(&raw[..end])
                        .map_err(|_| BifError::BADARG)?
                        .parse::<f64>()
                        .map_err(|_| BifError::BADARG)?
                };
                if !f.is_finite() {
                    return Err(BifError::BADARG);
                }
                Some((built(&mut ctx, |b| b.float(f))?, Shape::Other))
            }
            100 | 115 | 118 | 119 => {
                r.at -= 1;
                let (term, name) = r.atom(safe, &mut ctx)?;
                Some((term, Shape::Atom(name)))
            }
            73 | 75 => {
                // Port of external.c:5177-5190 (internal atom references), OTP-29.1.1.
                let index = if tag == 73 {
                    r.u16()? as u32
                } else {
                    let b = r.take(3)?;
                    u32::from_be_bytes([0, b[0], b[1], b[2]])
                };
                let atom = arinsal_term::Atom(index);
                if global_atoms().text(atom).is_none() {
                    return Err(BifError::BADARG);
                }
                let name = global_atoms().text(atom).unwrap().to_string();
                Some((Term::atom(atom), Shape::Atom(name)))
            }
            106 => Some((Term::NIL, Shape::Other)),
            104 | 105 => {
                let n = if tag == 104 {
                    r.u8()? as usize
                } else {
                    r.u32()? as usize
                };
                count_ok(n, r.bytes.len() - r.at)?;
                if n == 0 {
                    Some((built(&mut ctx, |b| b.tuple(&[]))?, Shape::Other))
                } else {
                    stack.push(Frame {
                        kind: FrameKind::Tuple,
                        left: n,
                        values: Vec::with_capacity(n.min(1024)),
                        shapes: Vec::new(),
                    });
                    None
                }
            }
            107 => {
                let n = r.u16()? as usize;
                let raw = r.take(n)?;
                let mut tail = Term::NIL;
                if ctx.is_some() {
                    for byte in raw.iter().rev() {
                        let head = Term::small(*byte as i64).unwrap();
                        tail = built(&mut ctx, |b| b.cons(head, tail))?;
                    }
                }
                Some((tail, Shape::Other))
            }
            108 | 116 => {
                let n = r.u32()? as usize;
                let count = if tag == 108 {
                    n.checked_add(1)
                } else {
                    n.checked_mul(2)
                }
                .ok_or(BifError::BADARG)?;
                count_ok(count, r.bytes.len() - r.at)?;
                if count == 0 {
                    let t = if let Some(ctx) = ctx.as_deref_mut() {
                        arinsal_maps::from_pairs(&[], ctx.heap).map_err(|_| BifError::BADARG)?
                    } else {
                        Term::NIL
                    };
                    Some((t, Shape::Other))
                } else {
                    stack.push(Frame {
                        kind: if tag == 108 {
                            FrameKind::List
                        } else {
                            FrameKind::Map
                        },
                        left: count,
                        values: Vec::with_capacity(count.min(1024)),
                        shapes: Vec::new(),
                    });
                    None
                }
            }
            109 | 77 => {
                let n = r.u32()? as usize;
                let bits = if tag == 77 { r.u8()? as usize } else { 8 };
                if tag == 77 && (n == 0 || !(1..=8).contains(&bits)) {
                    return Err(BifError::BADARG);
                }
                let raw = r.take(n)?;
                let bit_len = if tag == 109 {
                    n.checked_mul(8)
                } else {
                    n.checked_sub(1)
                        .and_then(|v| v.checked_mul(8))
                        .and_then(|v| v.checked_add(bits))
                }
                .ok_or(BifError::BADARG)?;
                let t = built(&mut ctx, |b| b.bitstring(raw, bit_len))?;
                Some((t, Shape::Other))
            }
            103 | 88 | 102 | 89 | 120 | 101 | 114 | 90 => {
                let count = if tag == 101 {
                    1
                } else if tag == 114 || tag == 90 {
                    r.u16()? as usize
                } else {
                    0
                };
                if matches!(tag, 101 | 114 | 90) && !(1..=5).contains(&count) {
                    return Err(BifError::BADARG);
                }
                let (node_term, node_name) = r.atom(safe, &mut ctx)?;
                let node = node_term.as_atom().unwrap();
                let identity = if tag == 103 || tag == 88 {
                    let id = r.u32()?;
                    let serial = r.u32()?;
                    let creation = if tag == 103 { r.u8()? as u32 } else { r.u32()? };
                    if tag == 103 && creation > 3 {
                        return Err(BifError::BADARG);
                    }
                    (id as u64, serial, creation, Vec::new())
                } else if matches!(tag, 102 | 89 | 120) {
                    let id = if tag == 120 {
                        r.u64()?
                    } else {
                        r.u32()? as u64
                    };
                    let creation = if tag == 102 { r.u8()? as u32 } else { r.u32()? };
                    if tag == 102 && creation > 3 {
                        return Err(BifError::BADARG);
                    }
                    (id, 0, creation, Vec::new())
                } else {
                    let creation = if tag == 90 { r.u32()? } else { r.u8()? as u32 };
                    if tag != 90 && creation > 3 {
                        return Err(BifError::BADARG);
                    }
                    let mut ids = Vec::with_capacity(count);
                    for i in 0..count {
                        let id = r.u32()?;
                        if i == 0 && tag != 90 && id >= (1 << 18) {
                            return Err(BifError::BADARG);
                        }
                        ids.push(id);
                    }
                    (0, 0, creation, ids)
                };
                let (id, serial, creation, ids) = identity;
                if matches!(tag, 101 | 114 | 90)
                    && node_name != "nonode@nohost"
                    && ids.len() != 3
                    && ids.len() != 5
                {
                    return Err(BifError::Unsupported("external reference width"));
                }
                let t = if ctx.is_none() {
                    Term::NIL
                } else if tag == 103 || tag == 88 {
                    if node == arinsal_term::atoms::NONAME && creation == 0 {
                        Term::pid(id as u32, serial).ok_or(BifError::BADARG)?
                    } else {
                        built(&mut ctx, |b| {
                            b.external_pid(Node::new(node, creation), id as u32, serial)
                        })?
                    }
                } else if matches!(tag, 102 | 89 | 120) {
                    if node == arinsal_term::atoms::NONAME && creation == 0 {
                        Term::port(id).ok_or(BifError::BADARG)?
                    } else {
                        built(&mut ctx, |b| b.external_port(Node::new(node, creation), id))?
                    }
                } else if node == arinsal_term::atoms::NONAME && creation == 0 {
                    let mut local = [0; 3];
                    for (slot, value) in local.iter_mut().zip(ids) {
                        *slot = value;
                    }
                    built(&mut ctx, |b| b.local_ref(local))?
                } else {
                    if ids.len() != 3 && ids.len() != 5 {
                        return Err(BifError::Unsupported("external reference width"));
                    }
                    built(&mut ctx, |b| {
                        b.external_ref(Node::new(node, creation), &ids)
                    })?
                };
                Some((
                    t,
                    if tag == 103 || tag == 88 {
                        Shape::Pid
                    } else {
                        Shape::Other
                    },
                ))
            }
            113 => {
                stack.push(Frame {
                    kind: FrameKind::Export,
                    left: 3,
                    values: Vec::new(),
                    shapes: Vec::new(),
                });
                None
            }
            112 => {
                let _size = r.u32()?;
                let arity = r.u8()?;
                let uniq = r.take(16)?.try_into().unwrap();
                let index = r.u32()?;
                let free = r.u32()? as usize;
                count_ok(free.saturating_add(4), r.bytes.len() - r.at)?;
                if free > 255 {
                    return Err(BifError::Unsupported(
                        "fun with more than 255 free variables",
                    ));
                }
                stack.push(Frame {
                    kind: FrameKind::Fun {
                        arity,
                        uniq,
                        index,
                        free,
                    },
                    left: free + 4,
                    values: Vec::new(),
                    shapes: Vec::new(),
                });
                None
            }
            67 => {
                let fields = r.u32()? as usize;
                if fields > (1 << 24) - 2 {
                    return Err(BifError::SystemLimit);
                }
                let exported = match r.u8()? {
                    0 => false,
                    1 => true,
                    _ => return Err(BifError::BADARG),
                };
                let count = fields
                    .checked_mul(2)
                    .and_then(|n| n.checked_add(2))
                    .ok_or(BifError::BADARG)?;
                count_ok(count, r.bytes.len() - r.at)?;
                stack.push(Frame {
                    kind: FrameKind::Record { exported, fields },
                    left: count,
                    values: Vec::new(),
                    shapes: Vec::new(),
                });
                None
            }
            _ => return Err(BifError::BADARG),
        };
        if let Some((mut term, mut shape)) = result {
            loop {
                let Some(frame) = stack.last_mut() else {
                    return Ok((term, r.at));
                };
                frame.values.push(term);
                frame.shapes.push(shape);
                frame.left -= 1;
                if frame.left != 0 {
                    break;
                }
                (term, shape) = finish(stack.pop().unwrap(), &mut ctx)?;
            }
        }
    }
}

fn binary_to_term(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let opts = decode_options(args.get(1).copied())?;
    // SAFETY: the input binary owner is live and stable during the BIF call.
    let view = unsafe { args[0].binary_ref() }.ok_or(BifError::BADARG)?;
    if !view.bit_len().is_multiple_of(8) {
        return Err(BifError::BADARG);
    }
    let bytes: Cow<'_, [u8]> = if view.start_bit().is_multiple_of(8) {
        let start = view.start_bit() / 8;
        Cow::Borrowed(&view.bytes()[start..start + view.bit_len() / 8])
    } else {
        Cow::Owned(bit_bytes(args[0])?.0)
    };
    ctx.charge_reductions(bytes.len());
    if bytes.first() != Some(&131) {
        return Err(BifError::BADARG);
    }
    let (plain, used_prefix, compressed) = if bytes.get(1) == Some(&80) {
        if bytes.len() < 6 {
            return Err(BifError::BADARG);
        }
        let size = u32::from_be_bytes(bytes[2..6].try_into().unwrap()) as usize;
        let mut z = flate2::bufread::ZlibDecoder::new(&bytes[6..]);
        let mut plain = Vec::new();
        (&mut z)
            .take(size as u64 + 1)
            .read_to_end(&mut plain)
            .map_err(|_| BifError::BADARG)?;
        if plain.len() != size {
            return Err(BifError::BADARG);
        }
        let used = 6 + z.total_in() as usize;
        (Cow::Owned(plain), used, true)
    } else {
        (Cow::Borrowed(&bytes[1..]), 1, false)
    };
    let (_, checked) = parse(&plain, opts.safe, None)?;
    if compressed && checked != plain.len() {
        return Err(BifError::BADARG);
    }
    let (term, _) = parse(&plain[..checked], opts.safe, Some(ctx))?;
    if opts.used {
        let used = if compressed {
            used_prefix
        } else {
            used_prefix + checked
        };
        let size = integer(ctx, used)?;
        Ok(tuple_build(ctx, &[term, size]))
    } else {
        Ok(term)
    }
}
