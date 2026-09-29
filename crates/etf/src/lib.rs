//! Owned Erlang External Term Format values for OTP 29.1.1.
//!
//! Decoding normalizes integer tags, Latin-1 atoms, and `STRING_EXT`. Encoding
//! follows `term_to_binary/2`; non-deterministic map entries retain vector order.
//! A large map built independently of erts cannot reproduce its HAMT order.

#![forbid(unsafe_code)]

use std::cmp::Ordering;
use std::io::Read;

use flate2::Compression;
use num_bigint::{BigInt, Sign};
use num_traits::ToPrimitive;

/// A decoded Erlang term independent of the VM heap.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum OwnedTerm {
    /// Any integer in the `i64` range, regardless of source tag.
    Int(i64),
    /// An integer outside the `i64` range.
    BigInt(BigInt),
    /// A finite Erlang float. Compare its bits when negative zero matters.
    Float(f64),
    /// Atom text in UTF-8, including atoms encoded in Latin-1.
    Atom(String),
    /// The empty list.
    Nil,
    /// A list, with `Nil` as the tail for a proper list. `STRING_EXT` becomes this form.
    List {
        /// Consecutive list heads.
        elems: Vec<OwnedTerm>,
        /// The final tail, possibly improper.
        tail: Box<OwnedTerm>,
    },
    /// Tuple elements.
    Tuple(Vec<OwnedTerm>),
    /// Entries in ETF order. Small-map atom keys can follow atom-table index order.
    Map(Vec<(OwnedTerm, OwnedTerm)>),
    /// Whole byte binary.
    Binary(Vec<u8>),
    /// Partial-byte binary, with 1..=7 used high bits in the last byte.
    BitString { bytes: Vec<u8>, bits: u8 },
    /// PID identity.
    Pid {
        node: String,
        id: u32,
        serial: u32,
        creation: u32,
    },
    /// Port identity.
    Port {
        node: String,
        id: u64,
        creation: u32,
    },
    /// Reference identity.
    Ref {
        node: String,
        creation: u32,
        ids: Vec<u32>,
    },
    /// External fun, `fun M:F/A`.
    Export {
        module: String,
        function: String,
        arity: u8,
    },
    /// Local fun (`NEW_FUN_EXT`). The embedded creator PID is retained for ETF fidelity.
    Fun {
        arity: u8,
        uniq: [u8; 16],
        index: u32,
        module: String,
        old_index: u32,
        old_uniq: u32,
        pid: Box<OwnedTerm>,
        free_vars: Vec<OwnedTerm>,
    },
    /// OTP 29 native record (`RECORD_EXT`), introduced after the original contract.
    Record {
        /// Whether the definition is exported.
        exported: bool,
        /// Defining module.
        module: String,
        /// Record name.
        name: String,
        /// Fields in definition order, each with its value.
        fields: Vec<(String, OwnedTerm)>,
    },
    /// An opaque extension, currently used for `LOCAL_EXT` (tag and raw payload).
    Other { tag: u8, raw: Vec<u8> },
}

impl OwnedTerm {
    /// Construct an atom.
    pub fn atom(value: impl Into<String>) -> Self {
        Self::Atom(value.into())
    }
    /// Construct a proper list.
    pub fn list(elems: Vec<Self>) -> Self {
        if elems.is_empty() {
            Self::Nil
        } else {
            Self::List {
                elems,
                tail: Box::new(Self::Nil),
            }
        }
    }
    /// Construct a tuple.
    pub fn tuple(elems: Vec<Self>) -> Self {
        Self::Tuple(elems)
    }
    /// Construct a list of Unicode code points.
    pub fn charlist(value: &str) -> Self {
        Self::list(value.chars().map(|c| Self::Int(c as i64)).collect())
    }
}

/// Options for [`encode`], mirroring `term_to_binary/2`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EncodeOptions {
    /// `{compressed, Level}`; `None` is uncompressed. Level 0..=9.
    pub compressed: Option<u8>,
    /// `{minor_version, N}`; default 2 on OTP 29.
    pub minor_version: Option<u8>,
    /// Sort every map by Erlang term order.
    pub deterministic: bool,
}

/// An ETF decoding error.
#[derive(Debug, thiserror::Error, PartialEq)]
pub enum DecodeError {
    /// First byte is not 131.
    #[error("bad version byte {0}")]
    BadVersion(u8),
    /// Input ended during a term.
    #[error("unexpected end of input at offset {0}")]
    Eof(usize),
    /// Unsupported or invalid tag.
    #[error("unknown tag {tag} at offset {offset}")]
    UnknownTag { tag: u8, offset: usize },
    /// A valid tag contained invalid data.
    #[error("invalid data at offset {offset}: {msg}")]
    Invalid { offset: usize, msg: String },
    /// A full decode found bytes after the term.
    #[error("trailing bytes after term at offset {0}")]
    Trailing(usize),
    /// Invalid zlib stream.
    #[error("zlib: {0}")]
    Zlib(String),
}

/// OTP distribution atom cache, with 8 segments of 256 entries each.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AtomCache {
    entries: Vec<Option<String>>,
    next_slot: usize,
}

impl Default for AtomCache {
    fn default() -> Self {
        Self {
            entries: vec![None; 2048],
            next_slot: 0,
        }
    }
}

impl AtomCache {
    /// Create an empty per-connection cache.
    pub fn new() -> Self {
        Self::default()
    }

    /// Read one cache slot by its 11-bit index.
    pub fn get(&self, slot: usize) -> Option<&str> {
        self.entries.get(slot).and_then(Option::as_deref)
    }

    /// Replace one cache slot by its 11-bit index.
    pub fn set(&mut self, slot: usize, atom: impl Into<String>) -> Result<(), DecodeError> {
        let entry = self
            .entries
            .get_mut(slot)
            .ok_or_else(|| invalid(0, "atom cache slot out of range"))?;
        *entry = Some(atom.into());
        Ok(())
    }

    fn allocate(&mut self, atom: &str) -> (usize, bool) {
        if let Some(slot) = self
            .entries
            .iter()
            .position(|entry| entry.as_deref() == Some(atom))
        {
            return (slot, false);
        }
        let slot = self.next_slot;
        self.next_slot = (self.next_slot + 1) % self.entries.len();
        self.entries[slot] = Some(atom.to_owned());
        (slot, true)
    }
}

/// Per-message mapping from `ATOM_CACHE_REF` indexes to decoded atoms.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AtomTranslationTable {
    atoms: Vec<String>,
}

impl AtomTranslationTable {
    /// Return an atom by its message-local reference index.
    pub fn get(&self, index: usize) -> Option<&str> {
        self.atoms.get(index).map(String::as_str)
    }

    /// Number of message-local references.
    pub fn len(&self) -> usize {
        self.atoms.len()
    }

    /// Whether the table has no entries.
    pub fn is_empty(&self) -> bool {
        self.atoms.is_empty()
    }
}

/// Distribution header metadata. A continuation carries no atom table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DistributionHeader {
    /// A normal `DIST_HEADER` or the first `DIST_FRAG_HEADER` fragment.
    Start {
        sequence_id: Option<u64>,
        fragment_id: Option<u64>,
        translations: AtomTranslationTable,
    },
    /// A `DIST_FRAG_CONT` fragment.
    Continuation { sequence_id: u64, fragment_id: u64 },
}

/// A decoded distribution packet, including its unparsed ETF payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DistributionPacket {
    /// Parsed header and atom translations.
    pub header: DistributionHeader,
    /// ETF bytes after the distribution header.
    pub payload: Vec<u8>,
}

fn invalid(offset: usize, msg: &str) -> DecodeError {
    DecodeError::Invalid {
        offset,
        msg: msg.into(),
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        let end = self.at.checked_add(n).ok_or(DecodeError::Eof(self.at))?;
        let result = self
            .bytes
            .get(self.at..end)
            .ok_or(DecodeError::Eof(self.at))?;
        self.at = end;
        Ok(result)
    }
    fn u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, DecodeError> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn u32(&mut self) -> Result<u32, DecodeError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> Result<u64, DecodeError> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn atom(&mut self, translations: Option<&AtomTranslationTable>) -> Result<String, DecodeError> {
        let offset = self.at;
        let tag = self.u8()?;
        if tag == 82 {
            let index = self.u8()? as usize;
            return translations
                .and_then(|table| table.get(index))
                .map(str::to_owned)
                .ok_or_else(|| invalid(offset, "atom cache reference outside translation table"));
        }
        let (len, utf8) = match tag {
            100 => (self.u16()? as usize, false),
            115 => (self.u8()? as usize, false),
            118 => (self.u16()? as usize, true),
            119 => (self.u8()? as usize, true),
            _ => return Err(invalid(offset, "expected atom")),
        };
        let b = self.take(len)?;
        let s = if utf8 {
            std::str::from_utf8(b)
                .map_err(|_| invalid(offset, "invalid UTF-8 atom"))?
                .to_owned()
        } else {
            b.iter().map(|&x| char::from(x)).collect()
        };
        if s.chars().count() > 255 {
            return Err(invalid(offset, "atom exceeds 255 characters"));
        }
        Ok(s)
    }
}

enum Kind {
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
    Local {
        start: usize,
    },
}
struct Frame {
    kind: Kind,
    left: usize,
    terms: Vec<OwnedTerm>,
}
impl Frame {
    fn finish(self, bytes: &[u8], end: usize) -> Result<OwnedTerm, DecodeError> {
        let mut v = self.terms;
        Ok(match self.kind {
            Kind::Tuple => OwnedTerm::Tuple(v),
            Kind::List => {
                let tail = v.pop().unwrap();
                if v.is_empty() {
                    tail
                } else {
                    OwnedTerm::List {
                        elems: v,
                        tail: Box::new(tail),
                    }
                }
            }
            Kind::Map => {
                let mut iter = v.into_iter();
                let mut pairs = Vec::new();
                while let (Some(key), Some(value)) = (iter.next(), iter.next()) {
                    pairs.push((key, value));
                }
                let mut keys: Vec<_> = pairs.iter().map(|(key, _)| key).collect();
                keys.sort_by(|a, b| erl_cmp(a, b));
                if keys
                    .windows(2)
                    .any(|pair| erl_cmp(pair[0], pair[1]).is_eq())
                {
                    return Err(invalid(end, "duplicate map key"));
                }
                OwnedTerm::Map(pairs)
            }
            Kind::Export => {
                let mut it = v.into_iter();
                let module = expect_atom(it.next().unwrap(), end)?;
                let function = expect_atom(it.next().unwrap(), end)?;
                let arity = expect_int(it.next().unwrap(), end)?;
                if !(0..=255).contains(&arity) {
                    return Err(invalid(end, "invalid export arity"));
                }
                OwnedTerm::Export {
                    module,
                    function,
                    arity: arity as u8,
                }
            }
            Kind::Fun {
                arity,
                uniq,
                index,
                free,
            } => {
                let mut it = v.into_iter();
                let module = expect_atom(it.next().unwrap(), end)?;
                let old_index = expect_int(it.next().unwrap(), end)?;
                let old_uniq = expect_int(it.next().unwrap(), end)?;
                if old_index < 0
                    || old_uniq < 0
                    || old_index > u32::MAX as i64
                    || old_uniq > u32::MAX as i64
                {
                    return Err(invalid(end, "invalid fun index"));
                }
                let pid = it.next().unwrap();
                if !matches!(pid, OwnedTerm::Pid { .. }) {
                    return Err(invalid(end, "invalid fun pid"));
                }
                let free_vars: Vec<_> = it.collect();
                debug_assert_eq!(free_vars.len(), free);
                OwnedTerm::Fun {
                    arity,
                    uniq,
                    index,
                    module,
                    old_index: old_index as u32,
                    old_uniq: old_uniq as u32,
                    pid: Box::new(pid),
                    free_vars,
                }
            }
            Kind::Record { exported, fields } => {
                let mut it = v.into_iter();
                let module = expect_atom(it.next().unwrap(), end)?;
                let name = expect_atom(it.next().unwrap(), end)?;
                let mut names = Vec::with_capacity(fields);
                for _ in 0..fields {
                    names.push(expect_atom(it.next().unwrap(), end)?);
                }
                if names.iter().collect::<std::collections::HashSet<_>>().len() != fields {
                    return Err(invalid(end, "duplicate record field"));
                }
                let values: Vec<_> = it.collect();
                OwnedTerm::Record {
                    exported,
                    module,
                    name,
                    fields: names.into_iter().zip(values).collect(),
                }
            }
            Kind::Local { start } => OwnedTerm::Other {
                tag: 121,
                raw: bytes[start..end].to_vec(),
            },
        })
    }
}
fn expect_atom(mut t: OwnedTerm, at: usize) -> Result<String, DecodeError> {
    if let OwnedTerm::Atom(a) = &mut t {
        let a = std::mem::take(a);
        Ok(a)
    } else {
        Err(invalid(at, "expected atom"))
    }
}
fn expect_int(t: OwnedTerm, at: usize) -> Result<i64, DecodeError> {
    if let OwnedTerm::Int(n) = t {
        Ok(n)
    } else {
        Err(invalid(at, "expected integer"))
    }
}

/// Decode a full ETF binary, including the version byte.
pub fn decode(bytes: &[u8]) -> Result<OwnedTerm, DecodeError> {
    let (term, used) = decode_prefix(bytes)?;
    if used != bytes.len() {
        return Err(DecodeError::Trailing(used));
    }
    Ok(term)
}

/// Decode one distribution external term using a caller-provided atom cache table.
///
/// `erts_debug:dist_ext_to_term/2` receives the already-expanded table and a
/// regular ETF external-term binary whose `ATOM_CACHE_REF` tags index it.
pub fn decode_dist_ext_with_atom_table(
    atoms: &[OwnedTerm],
    bytes: &[u8],
) -> Result<OwnedTerm, DecodeError> {
    // Port of erts/emulator/beam/external.c:1340 (erts_debug_dist_ext_to_term_2), OTP-29.1.1.
    if atoms.len() > 255 {
        return Err(invalid(0, "too many atom cache references"));
    }
    let mut translations = AtomTranslationTable::default();
    for atom in atoms {
        let OwnedTerm::Atom(value) = atom else {
            return Err(invalid(0, "atom cache entry is not an atom"));
        };
        translations.atoms.push(value.clone());
    }
    let mut reader = Reader { bytes, at: 0 };
    let version = reader.u8()?;
    if version != 131 {
        return Err(DecodeError::BadVersion(version));
    }
    let (term, used) = parse(&bytes[reader.at..], Some(&translations))?;
    if reader.at + used != bytes.len() {
        return Err(DecodeError::Trailing(reader.at + used));
    }
    Ok(term)
}

/// Decode one ETF term and return the number of input bytes consumed.
pub fn decode_prefix(bytes: &[u8]) -> Result<(OwnedTerm, usize), DecodeError> {
    let mut r = Reader { bytes, at: 0 };
    let version = r.u8()?;
    if version != 131 {
        return Err(DecodeError::BadVersion(version));
    }
    if r.bytes.get(r.at) == Some(&80) {
        r.at += 1;
        let size = r.u32()? as usize;
        let mut z = flate2::bufread::ZlibDecoder::new(&bytes[r.at..]);
        let mut plain = Vec::new();
        z.read_to_end(&mut plain)
            .map_err(|e| DecodeError::Zlib(e.to_string()))?;
        if plain.len() != size {
            return Err(invalid(r.at, "wrong uncompressed size"));
        }
        let used = r.at + z.total_in() as usize;
        let (term, consumed) = parse(&plain, None)?;
        if consumed != plain.len() {
            return Err(invalid(r.at, "compressed term has trailing bytes"));
        }
        return Ok((term, used));
    }
    let (term, used) = parse(&bytes[r.at..], None)?;
    Ok((term, used + r.at))
}

fn parse(
    bytes: &[u8],
    translations: Option<&AtomTranslationTable>,
) -> Result<(OwnedTerm, usize), DecodeError> {
    let mut r = Reader { bytes, at: 0 };
    let mut stack: Vec<Frame> = Vec::new();
    loop {
        let at = r.at;
        let tag = r.u8()?;
        let term = match tag {
            97 => Some(OwnedTerm::Int(r.u8()? as i64)),
            98 => Some(OwnedTerm::Int(r.u32()? as i32 as i64)),
            99 => {
                let b = r.take(31)?;
                let end = b.iter().position(|x| *x == 0).unwrap_or(31);
                let s =
                    std::str::from_utf8(&b[..end]).map_err(|_| invalid(at, "invalid old float"))?;
                let f: f64 = s.parse().map_err(|_| invalid(at, "invalid old float"))?;
                if !f.is_finite() {
                    return Err(invalid(at, "nonfinite float"));
                }
                Some(OwnedTerm::Float(f))
            }
            70 => {
                let f = f64::from_bits(r.u64()?);
                if !f.is_finite() {
                    return Err(invalid(at, "nonfinite float"));
                }
                Some(OwnedTerm::Float(f))
            }
            100 | 115 | 118 | 119 => {
                r.at -= 1;
                Some(OwnedTerm::Atom(r.atom(translations)?))
            }
            106 => Some(OwnedTerm::Nil),
            104 | 105 => {
                let n = if tag == 104 {
                    r.u8()? as usize
                } else {
                    r.u32()? as usize
                };
                if n == 0 {
                    Some(OwnedTerm::Tuple(Vec::new()))
                } else {
                    check_count(n, r.bytes.len() - r.at, at)?;
                    stack.push(Frame {
                        kind: Kind::Tuple,
                        left: n,
                        terms: Vec::new(),
                    });
                    None
                }
            }
            107 => {
                let n = r.u16()? as usize;
                let b = r.take(n)?;
                if n == 0 {
                    Some(OwnedTerm::Nil)
                } else {
                    Some(OwnedTerm::list(
                        b.iter().map(|&x| OwnedTerm::Int(x as i64)).collect(),
                    ))
                }
            }
            108 => {
                let n = r.u32()? as usize;
                check_count(n + 1, r.bytes.len() - r.at, at)?;
                stack.push(Frame {
                    kind: Kind::List,
                    left: n + 1,
                    terms: Vec::new(),
                });
                None
            }
            109 => {
                let n = r.u32()? as usize;
                Some(OwnedTerm::Binary(r.take(n)?.to_vec()))
            }
            77 => {
                let n = r.u32()? as usize;
                let bits = r.u8()?;
                if n == 0 || !(1..=8).contains(&bits) {
                    return Err(invalid(at, "invalid bitstring size"));
                }
                let mut b = r.take(n)?.to_vec();
                if bits == 8 {
                    Some(OwnedTerm::Binary(b))
                } else {
                    let mask = (1_u8 << (8 - bits)) - 1;
                    b[n - 1] &= !mask;
                    Some(OwnedTerm::BitString { bytes: b, bits })
                }
            }
            110 | 111 => {
                let n = if tag == 110 {
                    r.u8()? as usize
                } else {
                    r.u32()? as usize
                };
                let sign = r.u8()?;
                if sign > 1 {
                    return Err(invalid(at, "invalid bignum sign"));
                }
                let b = r.take(n)?;
                let value =
                    BigInt::from_bytes_le(if sign == 0 { Sign::Plus } else { Sign::Minus }, b);
                Some(
                    value
                        .to_i64()
                        .map(OwnedTerm::Int)
                        .unwrap_or(OwnedTerm::BigInt(value)),
                )
            }
            116 => {
                let n = r.u32()? as usize;
                let count = n
                    .checked_mul(2)
                    .ok_or_else(|| invalid(at, "map too large"))?;
                if count == 0 {
                    Some(OwnedTerm::Map(Vec::new()))
                } else {
                    check_count(count, r.bytes.len() - r.at, at)?;
                    stack.push(Frame {
                        kind: Kind::Map,
                        left: count,
                        terms: Vec::new(),
                    });
                    None
                }
            }
            103 | 88 => {
                let node = r.atom(translations)?;
                let id = r.u32()?;
                let serial = r.u32()?;
                let creation = if tag == 103 {
                    let value = r.u8()? as u32;
                    if value > 3 {
                        return Err(invalid(at, "invalid tiny creation"));
                    }
                    value
                } else {
                    r.u32()?
                };
                Some(OwnedTerm::Pid {
                    node,
                    id,
                    serial,
                    creation,
                })
            }
            102 | 89 | 120 => {
                let node = r.atom(translations)?;
                let id = if tag == 120 {
                    r.u64()?
                } else {
                    r.u32()? as u64
                };
                let creation = if tag == 102 {
                    let value = r.u8()? as u32;
                    if value > 3 {
                        return Err(invalid(at, "invalid tiny creation"));
                    }
                    value
                } else {
                    r.u32()?
                };
                Some(OwnedTerm::Port { node, id, creation })
            }
            101 | 114 | 90 => {
                let n = if tag == 101 { 1 } else { r.u16()? as usize };
                if n == 0 || n > 5 {
                    return Err(invalid(at, "invalid reference length"));
                }
                let node = r.atom(translations)?;
                let creation = if tag == 90 {
                    r.u32()?
                } else {
                    let value = r.u8()? as u32;
                    if value > 3 {
                        return Err(invalid(at, "invalid tiny creation"));
                    }
                    value
                };
                let mut ids = Vec::with_capacity(n);
                for i in 0..n {
                    let id = r.u32()?;
                    if i == 0 && tag != 90 && id >= (1 << 18) {
                        return Err(invalid(at, "invalid legacy reference id"));
                    }
                    ids.push(id);
                }
                Some(OwnedTerm::Ref {
                    node,
                    creation,
                    ids,
                })
            }
            113 => {
                stack.push(Frame {
                    kind: Kind::Export,
                    left: 3,
                    terms: Vec::new(),
                });
                None
            }
            112 => {
                let _size = r.u32()?;
                let arity = r.u8()?;
                let uniq: [u8; 16] = r.take(16)?.try_into().unwrap();
                let index = r.u32()?;
                let free = r.u32()? as usize;
                check_count(free.saturating_add(4), r.bytes.len() - r.at, at)?;
                stack.push(Frame {
                    kind: Kind::Fun {
                        arity,
                        uniq,
                        index,
                        free,
                    },
                    left: free + 4,
                    terms: Vec::new(),
                });
                None
            }
            67 => {
                let n = r.u32()? as usize;
                let exported = match r.u8()? {
                    0 => false,
                    1 => true,
                    _ => return Err(invalid(at, "invalid record flags")),
                };
                check_count(
                    n.saturating_mul(2).saturating_add(2),
                    r.bytes.len() - r.at,
                    at,
                )?;
                stack.push(Frame {
                    kind: Kind::Record {
                        exported,
                        fields: n,
                    },
                    left: n * 2 + 2,
                    terms: Vec::new(),
                });
                None
            }
            121 => {
                let start = r.at;
                r.take(4)?;
                stack.push(Frame {
                    kind: Kind::Local { start },
                    left: 1,
                    terms: Vec::new(),
                });
                None
            }
            82 => {
                // Port of erts/emulator/beam/external.c:3038-3050 (dec_atom), OTP-29.1.1.
                let index = r.u8()? as usize;
                let atom = translations
                    .and_then(|table| table.get(index))
                    .ok_or_else(|| invalid(at, "atom cache reference outside translation table"))?;
                Some(OwnedTerm::Atom(atom.to_owned()))
            }
            117 => return Err(invalid(at, "obsolete fun")),
            _ => return Err(DecodeError::UnknownTag { tag, offset: at }),
        };
        if let Some(mut t) = term {
            loop {
                match stack.last_mut() {
                    None => return Ok((t, r.at)),
                    Some(frame) => {
                        frame.terms.push(t);
                        frame.left -= 1;
                        if frame.left != 0 {
                            break;
                        }
                        t = stack.pop().unwrap().finish(bytes, r.at)?;
                    }
                }
            }
        }
    }
}
fn check_count(count: usize, remaining: usize, at: usize) -> Result<(), DecodeError> {
    if count > remaining {
        Err(invalid(at, "container exceeds input"))
    } else {
        Ok(())
    }
}

fn put_atom(out: &mut Vec<u8>, atom: &str, minor: u8) {
    if minor <= 1 && atom.chars().all(|c| (c as u32) <= 255) {
        let chars: Vec<u8> = atom.chars().map(|c| c as u8).collect();
        if chars.len() <= 255 && minor >= 2 {
            out.extend_from_slice(&[115, chars.len() as u8]);
        } else {
            out.push(100);
            out.extend_from_slice(&(chars.len() as u16).to_be_bytes());
        }
        out.extend_from_slice(&chars);
    } else {
        let b = atom.as_bytes();
        if b.len() <= 255 {
            out.extend_from_slice(&[119, b.len() as u8]);
        } else {
            out.push(118);
            out.extend_from_slice(&(b.len() as u16).to_be_bytes());
        }
        out.extend_from_slice(b);
    }
}

fn put_encoded_atom(
    out: &mut Vec<u8>,
    atom: &str,
    minor: u8,
    atom_refs: Option<&std::collections::HashMap<String, u8>>,
) {
    if let Some(index) = atom_refs.and_then(|refs| refs.get(atom)) {
        out.extend_from_slice(&[82, *index]);
    } else {
        put_atom(out, atom, minor);
    }
}
fn put_big(out: &mut Vec<u8>, n: &BigInt) {
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
fn put_int(out: &mut Vec<u8>, n: i64) {
    if (0..=255).contains(&n) {
        out.extend_from_slice(&[97, n as u8]);
    } else if let Ok(s) = i32::try_from(n) {
        out.push(98);
        out.extend_from_slice(&s.to_be_bytes());
    } else {
        put_big(out, &BigInt::from(n));
    }
}
fn put_old_float(out: &mut Vec<u8>, f: f64) {
    // Port of external.c:3840 and sys/unix/sys_float.c:55, OTP-29.1.1.
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
}

fn flatmap_key_cmp(a: &OwnedTerm, b: &OwnedTerm) -> Ordering {
    // Port of erts/emulator/beam/erl_utils.h:269
    // (erts_cmp_flatmap_keys), OTP-29.1.1. Atom-table order is retained
    // from the vector because atom indexes are unavailable here.
    match (a, b) {
        (OwnedTerm::Atom(_), OwnedTerm::Atom(_)) => Ordering::Equal,
        _ => erl_cmp(a, b),
    }
}

enum Work<'a> {
    Term(&'a OwnedTerm),
    PatchFun(usize),
}

/// Encode an owned term like OTP 29.1.1 `erlang:term_to_binary/2`.
///
/// `Other` retains opaque `LOCAL_EXT` bytes. For non-deterministic large maps,
/// HAMT vector order is emitted verbatim because erts' internal hash cannot be
/// reconstructed here. Small-map non-atom keys are sorted; atom keys retain
/// their vector order because erts sorts those by atom-table index.
pub fn encode(term: &OwnedTerm, opts: EncodeOptions) -> Vec<u8> {
    encode_with_atom_refs(term, opts, None)
}

fn encode_with_atom_refs(
    term: &OwnedTerm,
    opts: EncodeOptions,
    atom_refs: Option<&std::collections::HashMap<String, u8>>,
) -> Vec<u8> {
    encode_terms_with_atom_refs(&[term], opts, atom_refs)
}

fn encode_terms_with_atom_refs(
    terms: &[&OwnedTerm],
    opts: EncodeOptions,
    atom_refs: Option<&std::collections::HashMap<String, u8>>,
) -> Vec<u8> {
    let mut out = vec![131];
    encode_terms_into(terms, opts, atom_refs, &mut out);
    if let Some(level) = opts.compressed.filter(|n| *n > 0) {
        use std::io::Write;
        let plain = &out[1..];
        let mut z = flate2::write::ZlibEncoder::new(Vec::new(), Compression::new(level as u32));
        z.write_all(plain).expect("zlib write");
        let compressed = z.finish().expect("zlib finish");
        // Port of external.c:2276-2300, OTP-29.1.1: a compressed term
        // must be strictly shorter even after its five-byte header.
        if compressed.len() + 5 <= plain.len() {
            let mut result = vec![131, 80];
            result.extend_from_slice(&(plain.len() as u32).to_be_bytes());
            result.extend_from_slice(&compressed);
            return result;
        }
    }
    out
}

fn encode_terms_into(
    terms: &[&OwnedTerm],
    opts: EncodeOptions,
    atom_refs: Option<&std::collections::HashMap<String, u8>>,
    out: &mut Vec<u8>,
) {
    let minor = opts.minor_version.unwrap_or(2);
    assert!(minor <= 2, "minor_version must be 0..=2");
    assert!(
        opts.compressed.is_none_or(|n| n <= 9),
        "compression level must be 0..=9"
    );
    let mut work = Vec::with_capacity(terms.len());
    work.extend(terms.iter().rev().copied().map(Work::Term));
    while let Some(item) = work.pop() {
        let t = match item {
            Work::PatchFun(pos) => {
                let size = (out.len() - pos) as u32;
                out[pos..pos + 4].copy_from_slice(&size.to_be_bytes());
                continue;
            }
            Work::Term(t) => t,
        };
        match t {
            OwnedTerm::Int(n) => put_int(out, *n),
            OwnedTerm::BigInt(n) => put_big(out, n),
            OwnedTerm::Float(f) => {
                if minor == 0 {
                    put_old_float(out, *f);
                } else {
                    out.push(70);
                    out.extend_from_slice(&f.to_bits().to_be_bytes());
                }
            }
            OwnedTerm::Atom(a) => put_encoded_atom(out, a, minor, atom_refs),
            OwnedTerm::Nil => out.push(106),
            OwnedTerm::List { .. } => {
                let mut elems = Vec::new();
                let mut cur = t;
                while let OwnedTerm::List { elems: part, tail } = cur {
                    elems.extend(part.iter());
                    cur = tail;
                }
                if elems.is_empty() {
                    work.push(Work::Term(cur));
                    continue;
                }
                let bytes: Option<Vec<u8>> =
                    if elems.len() <= u16::MAX as usize && matches!(cur, OwnedTerm::Nil) {
                        elems
                            .iter()
                            .map(|x| {
                                if let OwnedTerm::Int(n) = x {
                                    u8::try_from(*n).ok()
                                } else {
                                    None
                                }
                            })
                            .collect()
                    } else {
                        None
                    };
                if let Some(bytes) = bytes {
                    out.push(107);
                    out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
                    out.extend_from_slice(&bytes);
                } else {
                    out.push(108);
                    out.extend_from_slice(&(elems.len() as u32).to_be_bytes());
                    work.push(Work::Term(cur));
                    for e in elems.into_iter().rev() {
                        work.push(Work::Term(e));
                    }
                }
            }
            OwnedTerm::Tuple(v) => {
                if v.len() <= 255 {
                    out.extend_from_slice(&[104, v.len() as u8]);
                } else {
                    out.push(105);
                    out.extend_from_slice(&(v.len() as u32).to_be_bytes());
                }
                for e in v.iter().rev() {
                    work.push(Work::Term(e));
                }
            }
            OwnedTerm::Map(v) => {
                out.push(116);
                out.extend_from_slice(&(v.len() as u32).to_be_bytes());
                let mut pairs: Vec<_> = v.iter().collect();
                if opts.deterministic {
                    pairs.sort_by(|a, b| erl_cmp(&a.0, &b.0));
                } else if v.len() <= 32 {
                    pairs.sort_by(|a, b| flatmap_key_cmp(&a.0, &b.0));
                }
                for (k, val) in pairs.into_iter().rev() {
                    work.push(Work::Term(val));
                    work.push(Work::Term(k));
                }
            }
            OwnedTerm::Binary(b) => {
                out.push(109);
                out.extend_from_slice(&(b.len() as u32).to_be_bytes());
                out.extend_from_slice(b);
            }
            OwnedTerm::BitString { bytes, bits } => {
                out.push(77);
                out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
                out.push(*bits);
                out.extend_from_slice(bytes);
            }
            OwnedTerm::Pid {
                node,
                id,
                serial,
                creation,
            } => {
                out.push(88);
                put_encoded_atom(out, node, minor, atom_refs);
                out.extend_from_slice(&id.to_be_bytes());
                out.extend_from_slice(&serial.to_be_bytes());
                out.extend_from_slice(&creation.to_be_bytes());
            }
            OwnedTerm::Port { node, id, creation } => {
                out.push(120);
                put_encoded_atom(out, node, minor, atom_refs);
                out.extend_from_slice(&id.to_be_bytes());
                out.extend_from_slice(&creation.to_be_bytes());
            }
            OwnedTerm::Ref {
                node,
                creation,
                ids,
            } => {
                out.push(90);
                out.extend_from_slice(&(ids.len() as u16).to_be_bytes());
                put_encoded_atom(out, node, minor, atom_refs);
                out.extend_from_slice(&creation.to_be_bytes());
                for id in ids {
                    out.extend_from_slice(&id.to_be_bytes());
                }
            }
            OwnedTerm::Export {
                module,
                function,
                arity,
            } => {
                out.push(113);
                put_encoded_atom(out, module, minor, atom_refs);
                put_encoded_atom(out, function, minor, atom_refs);
                put_int(out, *arity as i64);
            }
            OwnedTerm::Fun {
                arity,
                uniq,
                index,
                module,
                old_index,
                old_uniq,
                pid,
                free_vars,
            } => {
                out.push(112);
                let pos = out.len();
                out.extend_from_slice(&[0; 4]);
                out.push(*arity);
                out.extend_from_slice(uniq);
                out.extend_from_slice(&index.to_be_bytes());
                out.extend_from_slice(&(free_vars.len() as u32).to_be_bytes());
                put_encoded_atom(out, module, minor, atom_refs);
                put_int(out, *old_index as i64);
                put_int(out, *old_uniq as i64);
                work.push(Work::PatchFun(pos));
                for e in free_vars.iter().rev() {
                    work.push(Work::Term(e));
                }
                work.push(Work::Term(pid));
            }
            OwnedTerm::Record {
                exported,
                module,
                name,
                fields,
            } => {
                out.push(67);
                out.extend_from_slice(&(fields.len() as u32).to_be_bytes());
                out.push(u8::from(*exported));
                put_encoded_atom(out, module, minor, atom_refs);
                put_encoded_atom(out, name, minor, atom_refs);
                for (key, _) in fields {
                    put_encoded_atom(out, key, minor, atom_refs);
                }
                for (_, value) in fields.iter().rev() {
                    work.push(Work::Term(value));
                }
            }
            OwnedTerm::Other { tag, raw } => {
                out.push(*tag);
                out.extend_from_slice(raw);
            }
        }
    }
}

fn collect_atoms(term: &OwnedTerm, atoms: &mut Vec<String>) {
    let mut work = vec![term];
    while let Some(term) = work.pop() {
        match term {
            OwnedTerm::Atom(atom) => atoms.push(atom.clone()),
            OwnedTerm::List { elems, tail } => {
                work.push(tail);
                work.extend(elems.iter().rev());
            }
            OwnedTerm::Tuple(elems) => work.extend(elems.iter().rev()),
            OwnedTerm::Map(entries) => {
                for (key, value) in entries.iter().rev() {
                    work.push(value);
                    work.push(key);
                }
            }
            OwnedTerm::Pid { node, .. }
            | OwnedTerm::Port { node, .. }
            | OwnedTerm::Ref { node, .. } => atoms.push(node.clone()),
            OwnedTerm::Export {
                module, function, ..
            } => {
                atoms.push(module.clone());
                atoms.push(function.clone());
            }
            OwnedTerm::Fun {
                module,
                pid,
                free_vars,
                ..
            } => {
                atoms.push(module.clone());
                work.extend(free_vars.iter().rev());
                work.push(pid);
            }
            OwnedTerm::Record {
                module,
                name,
                fields,
                ..
            } => {
                atoms.push(module.clone());
                atoms.push(name.clone());
                for (key, value) in fields {
                    atoms.push(key.clone());
                    work.push(value);
                }
            }
            _ => {}
        }
    }
}

/// Encode an ETF term in a distribution header, updating the outgoing atom cache.
///
/// `fragment` selects a first fragment header `(sequence_id, fragment_id)`;
/// continuation fragments are emitted with [`encode_dist_continuation`].
pub fn encode_dist_packet(
    term: &OwnedTerm,
    cache: &mut AtomCache,
    fragment: Option<(u64, u64)>,
) -> Vec<u8> {
    encode_dist_packet_terms(&[term], cache, fragment)
}

/// Encode consecutive terms in one distribution packet with one output buffer.
///
/// This is used for control and payload pairs, which are adjacent ETF terms on
/// the wire rather than a tuple.
pub fn encode_dist_packet_terms(
    terms: &[&OwnedTerm],
    cache: &mut AtomCache,
    fragment: Option<(u64, u64)>,
) -> Vec<u8> {
    // Port of erts/emulator/beam/external.c:284-346, 390-489, 763-817,
    // OTP-29.1.1. The allocator is local to this library; OTP chooses cache
    // slots from its atom table's internal cache index.
    let mut ordered = Vec::new();
    for term in terms {
        collect_atoms(term, &mut ordered);
    }
    let mut seen = std::collections::HashSet::new();
    ordered.retain(|atom| seen.insert(atom.clone()));
    ordered.truncate(255);

    let mut refs = std::collections::HashMap::new();
    let mut updates = Vec::with_capacity(ordered.len());
    let mut long_atoms = false;
    for (index, atom) in ordered.iter().enumerate() {
        let (slot, is_new) = cache.allocate(atom);
        refs.insert(atom.clone(), index as u8);
        updates.push((slot, is_new, atom));
        long_atoms |= atom.len() > u8::MAX as usize;
    }

    let mut out = vec![131, if fragment.is_some() { 69 } else { 68 }];
    if let Some((sequence_id, fragment_id)) = fragment {
        out.extend_from_slice(&sequence_id.to_be_bytes());
        out.extend_from_slice(&fragment_id.to_be_bytes());
    }
    out.push(updates.len() as u8);
    if !updates.is_empty() {
        let flag_bytes = (updates.len() + 2) / 2;
        let flags_at = out.len();
        out.resize(out.len() + flag_bytes, 0);
        for (index, (slot, is_new, _)) in updates.iter().enumerate() {
            let nibble = (u8::from(*is_new) << 3) | ((slot >> 8) as u8 & 7);
            out[flags_at + index / 2] |= nibble << ((index % 2) * 4);
        }
        let long_nibble = if long_atoms { 1 } else { 0 };
        out[flags_at + updates.len() / 2] |= long_nibble << ((updates.len() % 2) * 4);
        for (slot, is_new, atom) in updates {
            out.push(slot as u8);
            if is_new {
                if long_atoms {
                    out.extend_from_slice(&(atom.len() as u16).to_be_bytes());
                } else {
                    out.push(atom.len() as u8);
                }
                out.extend_from_slice(atom.as_bytes());
            }
        }
    }
    encode_terms_into(terms, EncodeOptions::default(), Some(&refs), &mut out);
    out
}

/// Encode consecutive terms as normal or 64 KiB fragmented distribution packets.
///
/// The atom cache is updated once for the complete signal, and only the first
/// fragment carries its translation table. Fragment ids descend to one.
/// Port of erts/emulator/beam/external.c:684-704 and :1230-1245,
/// OTP-29.1.1.
pub fn encode_dist_packet_terms_fragmented(
    terms: &[&OwnedTerm],
    cache: &mut AtomCache,
    sequence_id: u64,
    fragment_size: usize,
) -> Result<Vec<Vec<u8>>, DecodeError> {
    if fragment_size == 0 {
        return Err(invalid(0, "zero distribution fragment size"));
    }
    let cache_before = cache.clone();
    let packet = encode_dist_packet_terms(terms, cache, None);
    let mut decode_cache = cache_before;
    let decoded = decode_dist_packet(&packet, &mut decode_cache)?;
    let payload_start = packet.len() - decoded.payload.len();
    if decoded.payload.len() <= fragment_size {
        return Ok(vec![packet]);
    }
    let fragment_count = decoded.payload.len().div_ceil(fragment_size);
    let mut fragments = Vec::with_capacity(fragment_count);
    let mut first = Vec::with_capacity(18 + payload_start + fragment_size);
    first.extend_from_slice(&[131, 69]);
    first.extend_from_slice(&sequence_id.to_be_bytes());
    first.extend_from_slice(&(fragment_count as u64).to_be_bytes());
    first.extend_from_slice(&packet[2..payload_start]);
    first.extend_from_slice(&decoded.payload[..fragment_size]);
    fragments.push(first);
    for (index, payload) in decoded.payload[fragment_size..]
        .chunks(fragment_size)
        .enumerate()
    {
        let fragment_id = fragment_count - index - 1;
        fragments.push(encode_dist_continuation(
            sequence_id,
            fragment_id as u64,
            payload,
        ));
    }
    Ok(fragments)
}

/// Encode one `DIST_FRAG_CONT` packet.
pub fn encode_dist_continuation(sequence_id: u64, fragment_id: u64, payload: &[u8]) -> Vec<u8> {
    // Port of erts_encode_ext_dist_header_fragment, external.c:478-489, OTP-29.1.1.
    let mut out = Vec::with_capacity(18 + payload.len());
    out.extend_from_slice(&[131, 70]);
    out.extend_from_slice(&sequence_id.to_be_bytes());
    out.extend_from_slice(&fragment_id.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// Decode a distribution header and update the incoming per-connection cache.
pub fn decode_dist_packet(
    bytes: &[u8],
    cache: &mut AtomCache,
) -> Result<DistributionPacket, DecodeError> {
    // Port of erts_prepare_dist_ext, external.c:908-1160, OTP-29.1.1.
    let mut r = Reader { bytes, at: 0 };
    let version = r.u8()?;
    if version != 131 {
        return Err(DecodeError::BadVersion(version));
    }
    let tag = r.u8()?;
    if tag == 70 {
        let sequence_id = r.u64()?;
        let fragment_id = r.u64()?;
        return Ok(DistributionPacket {
            header: DistributionHeader::Continuation {
                sequence_id,
                fragment_id,
            },
            payload: bytes[r.at..].to_vec(),
        });
    }
    let (sequence_id, fragment_id) = if tag == 69 {
        (Some(r.u64()?), Some(r.u64()?))
    } else if tag == 68 {
        (None, None)
    } else {
        return Err(DecodeError::UnknownTag { tag, offset: 1 });
    };
    let count = r.u8()? as usize;
    if count > 255 {
        return Err(invalid(r.at - 1, "too many atom cache references"));
    }
    let mut table = AtomTranslationTable::default();
    if count > 0 {
        let flag_len = (count + 2) / 2;
        let flags_at = r.at;
        let flags = r.take(flag_len)?.to_vec();
        let long_nibble = (flags[count / 2] >> ((count % 2) * 4)) & 0x0f;
        let long_atoms = (long_nibble & 1) != 0;
        for index in 0..count {
            let nibble = (flags[index / 2] >> ((index % 2) * 4)) & 0x0f;
            let segment = (nibble & 7) as usize;
            let is_new = (nibble & 8) != 0;
            let internal = r.u8()? as usize;
            let slot = segment * 256 + internal;
            let atom = if is_new {
                let len = if long_atoms {
                    r.u16()? as usize
                } else {
                    r.u8()? as usize
                };
                let raw = r.take(len)?;
                let atom = std::str::from_utf8(raw)
                    .map_err(|_| invalid(r.at - len, "invalid UTF-8 distribution atom"))?
                    .to_owned();
                cache.entries[slot] = Some(atom.clone());
                atom
            } else {
                cache
                    .get(slot)
                    .ok_or_else(|| invalid(flags_at, "reference to empty atom cache slot"))?
                    .to_owned()
            };
            table.atoms.push(atom);
        }
    }
    Ok(DistributionPacket {
        header: DistributionHeader::Start {
            sequence_id,
            fragment_id,
            translations: table,
        },
        payload: bytes[r.at..].to_vec(),
    })
}

/// Decode all ETF terms after a start distribution header.
pub fn decode_dist_payload(packet: &DistributionPacket) -> Result<Vec<OwnedTerm>, DecodeError> {
    let DistributionHeader::Start { translations, .. } = &packet.header else {
        return Err(invalid(1, "continuation fragment has no translation table"));
    };
    let mut terms = Vec::new();
    let mut at = 0;
    while at < packet.payload.len() {
        let (term, used) = parse(&packet.payload[at..], Some(translations))?;
        if used == 0 {
            return Err(invalid(at, "empty distribution term"));
        }
        terms.push(term);
        at += used;
    }
    Ok(terms)
}

fn rank(t: &OwnedTerm) -> u8 {
    match t {
        OwnedTerm::Int(_) | OwnedTerm::BigInt(_) | OwnedTerm::Float(_) => 0,
        OwnedTerm::Atom(_) => 1,
        OwnedTerm::Ref { .. } => 2,
        OwnedTerm::Fun { .. } | OwnedTerm::Export { .. } => 3,
        OwnedTerm::Port { .. } => 4,
        OwnedTerm::Pid { .. } => 5,
        OwnedTerm::Tuple(_) => 6,
        OwnedTerm::Record { .. } => 7,
        OwnedTerm::Map(_) => 8,
        OwnedTerm::Nil => 9,
        OwnedTerm::List { .. } => 10,
        OwnedTerm::Binary(_) | OwnedTerm::BitString { .. } => 11,
        OwnedTerm::Other { .. } => 12,
    }
}
fn num_cmp(a: &OwnedTerm, b: &OwnedTerm) -> Ordering {
    match (a, b) {
        (OwnedTerm::Float(x), OwnedTerm::Float(y)) => x.total_cmp(y),
        (OwnedTerm::Float(_), _) => Ordering::Greater,
        (_, OwnedTerm::Float(_)) => Ordering::Less,
        _ => {
            let ai = match a {
                OwnedTerm::Int(n) => BigInt::from(*n),
                OwnedTerm::BigInt(n) => n.clone(),
                _ => unreachable!(),
            };
            let bi = match b {
                OwnedTerm::Int(n) => BigInt::from(*n),
                OwnedTerm::BigInt(n) => n.clone(),
                _ => unreachable!(),
            };
            ai.cmp(&bi)
        }
    }
}
fn cmp_slices(a: &[OwnedTerm], b: &[OwnedTerm]) -> Ordering {
    for (x, y) in a.iter().zip(b) {
        let c = erl_cmp(x, y);
        if c != Ordering::Equal {
            return c;
        }
    }
    a.len().cmp(&b.len())
}
fn bit_data(t: &OwnedTerm) -> (&[u8], usize) {
    match t {
        OwnedTerm::Binary(b) => (b, b.len() * 8),
        OwnedTerm::BitString { bytes, bits } => (bytes, (bytes.len() - 1) * 8 + *bits as usize),
        _ => unreachable!(),
    }
}

/// Compare terms in Erlang's exact term order, as used for deterministic map keys.
///
/// A map used as a key may differ from erts when its atom keys were ordered by
/// the runtime atom table rather than their names; that table is not present in
/// [`OwnedTerm`]. Other supported variants follow OTP's type and value order.
pub fn erl_cmp(a: &OwnedTerm, b: &OwnedTerm) -> Ordering {
    let ranks = rank(a).cmp(&rank(b));
    if ranks != Ordering::Equal {
        return ranks;
    }
    match (a, b) {
        (OwnedTerm::Int(_) | OwnedTerm::BigInt(_) | OwnedTerm::Float(_), _) => num_cmp(a, b),
        (OwnedTerm::Atom(x), OwnedTerm::Atom(y)) => x.cmp(y),
        (
            OwnedTerm::Ref {
                node: an,
                creation: ac,
                ids: ai,
            },
            OwnedTerm::Ref {
                node: bn,
                creation: bc,
                ids: bi,
            },
        ) => {
            let a_len = ai
                .iter()
                .rposition(|n| *n != 0)
                .map_or(ai.len().min(1), |i| i + 1);
            let b_len = bi
                .iter()
                .rposition(|n| *n != 0)
                .map_or(bi.len().min(1), |i| i + 1);
            an.cmp(bn)
                .then(ac.cmp(bc))
                .then_with(|| ai[..a_len].iter().rev().cmp(bi[..b_len].iter().rev()))
        }
        (
            OwnedTerm::Export {
                module: am,
                function: af,
                arity: aa,
            },
            OwnedTerm::Export {
                module: bm,
                function: bf,
                arity: ba,
            },
        ) => am.cmp(bm).then(af.cmp(bf)).then(aa.cmp(ba)),
        (OwnedTerm::Export { .. }, OwnedTerm::Fun { .. }) => Ordering::Greater,
        (OwnedTerm::Fun { .. }, OwnedTerm::Export { .. }) => Ordering::Less,
        (
            OwnedTerm::Fun {
                module: am,
                index: ai,
                old_uniq: au,
                free_vars: af,
                ..
            },
            OwnedTerm::Fun {
                module: bm,
                index: bi,
                old_uniq: bu,
                free_vars: bf,
                ..
            },
        ) => am
            .cmp(bm)
            .then(ai.cmp(bi))
            .then(au.cmp(bu))
            .then(af.len().cmp(&bf.len()))
            .then_with(|| cmp_slices(af, bf)),
        (
            OwnedTerm::Port {
                node: an,
                id: ai,
                creation: ac,
            },
            OwnedTerm::Port {
                node: bn,
                id: bi,
                creation: bc,
            },
        ) => an.cmp(bn).then(ac.cmp(bc)).then(ai.cmp(bi)),
        (
            OwnedTerm::Pid {
                node: an,
                id: ai,
                serial: aser,
                creation: ac,
            },
            OwnedTerm::Pid {
                node: bn,
                id: bi,
                serial: bser,
                creation: bc,
            },
        ) => aser
            .cmp(bser)
            .then(ai.cmp(bi))
            .then(an.cmp(bn))
            .then(ac.cmp(bc)),
        (OwnedTerm::Tuple(x), OwnedTerm::Tuple(y)) => {
            x.len().cmp(&y.len()).then_with(|| cmp_slices(x, y))
        }
        (OwnedTerm::Map(x), OwnedTerm::Map(y)) => {
            let size = x.len().cmp(&y.len());
            if size != Ordering::Equal {
                return size;
            }
            let mut ax: Vec<_> = x.iter().collect();
            let mut by: Vec<_> = y.iter().collect();
            if x.len() <= 32 {
                ax.sort_by(|l, r| flatmap_key_cmp(&l.0, &r.0));
                by.sort_by(|l, r| flatmap_key_cmp(&l.0, &r.0));
            } else {
                ax.sort_by(|l, r| erl_cmp(&l.0, &r.0));
                by.sort_by(|l, r| erl_cmp(&l.0, &r.0));
            }
            for ((ak, _), (bk, _)) in ax.iter().zip(by.iter()) {
                let c = erl_cmp(ak, bk);
                if c != Ordering::Equal {
                    return c;
                }
            }
            for ((_, av), (_, bv)) in ax.iter().zip(by.iter()) {
                let c = erl_cmp(av, bv);
                if c != Ordering::Equal {
                    return c;
                }
            }
            Ordering::Equal
        }
        (OwnedTerm::Nil, OwnedTerm::Nil) => Ordering::Equal,
        (
            OwnedTerm::List {
                elems: ae,
                tail: at,
            },
            OwnedTerm::List {
                elems: be,
                tail: bt,
            },
        ) => {
            for (x, y) in ae.iter().zip(be) {
                let c = erl_cmp(x, y);
                if c != Ordering::Equal {
                    return c;
                }
            }
            if ae.len() == be.len() {
                erl_cmp(at, bt)
            } else if ae.len() < be.len() {
                erl_cmp(
                    at,
                    &OwnedTerm::List {
                        elems: be[ae.len()..].to_vec(),
                        tail: bt.clone(),
                    },
                )
            } else {
                erl_cmp(
                    &OwnedTerm::List {
                        elems: ae[be.len()..].to_vec(),
                        tail: at.clone(),
                    },
                    bt,
                )
            }
        }
        (OwnedTerm::Binary(_) | OwnedTerm::BitString { .. }, _) => {
            let (ab, al) = bit_data(a);
            let (bb, bl) = bit_data(b);
            let common = al.min(bl);
            for i in 0..common {
                let abit = (ab[i / 8] >> (7 - i % 8)) & 1;
                let bbit = (bb[i / 8] >> (7 - i % 8)) & 1;
                let c = abit.cmp(&bbit);
                if c != Ordering::Equal {
                    return c;
                }
            }
            al.cmp(&bl)
        }
        (
            OwnedTerm::Record {
                module: am,
                name: an,
                fields: af,
                exported: ae,
            },
            OwnedTerm::Record {
                module: bm,
                name: bn,
                fields: bf,
                exported: be,
            },
        ) => {
            let header = am
                .cmp(bm)
                .then(an.cmp(bn))
                .then(ae.cmp(be))
                .then(af.len().cmp(&bf.len()));
            if header != Ordering::Equal {
                return header;
            }
            for ((ak, _), (bk, _)) in af.iter().zip(bf) {
                let c = ak.cmp(bk);
                if c != Ordering::Equal {
                    return c;
                }
            }
            for ((_, av), (_, bv)) in af.iter().zip(bf) {
                let c = erl_cmp(av, bv);
                if c != Ordering::Equal {
                    return c;
                }
            }
            Ordering::Equal
        }
        (OwnedTerm::Other { tag: at, raw: ar }, OwnedTerm::Other { tag: bt, raw: br }) => {
            at.cmp(bt).then(ar.cmp(br))
        }
        _ => Ordering::Equal,
    }
}

impl std::fmt::Display for OwnedTerm {
    /// Formats common terms in `~w` style. Atom quoting, fun identities, and
    /// bit syntax are approximations because `OwnedTerm` has no atom table or
    /// live process identity; this formatter is intended for diagnostics.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use std::fmt::Write;
        match self {
            Self::Int(n) => write!(f, "{n}"),
            Self::BigInt(n) => write!(f, "{n}"),
            Self::Float(n) => write!(f, "{n:?}"),
            Self::Atom(a) => {
                let bare = !a.is_empty()
                    && a.chars().next().is_some_and(|c| c.is_ascii_lowercase())
                    && a.chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '@');
                if bare {
                    f.write_str(a)
                } else {
                    f.write_char('\'')?;
                    for c in a.chars() {
                        if c == '\'' || c == '\\' {
                            f.write_char('\\')?;
                        }
                        f.write_char(c)?;
                    }
                    f.write_char('\'')
                }
            }
            Self::Nil => f.write_str("[]"),
            Self::List { elems, tail } => {
                f.write_char('[')?;
                for (i, e) in elems.iter().enumerate() {
                    if i > 0 {
                        f.write_char(',')?;
                    }
                    write!(f, "{e}")?;
                }
                if !matches!(**tail, Self::Nil) {
                    write!(f, "|{tail}")?;
                }
                f.write_char(']')
            }
            Self::Tuple(v) => {
                f.write_char('{')?;
                for (i, e) in v.iter().enumerate() {
                    if i > 0 {
                        f.write_char(',')?;
                    }
                    write!(f, "{e}")?;
                }
                f.write_char('}')
            }
            Self::Map(v) => {
                f.write_str("#{")?;
                for (i, (k, val)) in v.iter().enumerate() {
                    if i > 0 {
                        f.write_char(',')?;
                    }
                    write!(f, "{k} => {val}")?;
                }
                f.write_char('}')
            }
            Self::Binary(v) => {
                f.write_str("<<")?;
                for (i, b) in v.iter().enumerate() {
                    if i > 0 {
                        f.write_char(',')?;
                    }
                    write!(f, "{b}")?;
                }
                f.write_str(">>")
            }
            Self::BitString { bytes, bits } => {
                f.write_str("<<")?;
                for (i, b) in bytes.iter().enumerate() {
                    if i > 0 {
                        f.write_char(',')?;
                    }
                    if i + 1 == bytes.len() {
                        write!(f, "{}:{bits}", b >> (8 - bits))?;
                    } else {
                        write!(f, "{b}")?;
                    }
                }
                f.write_str(">>")
            }
            Self::Pid {
                node, id, serial, ..
            } => write!(f, "<{}.{id}.{serial}>", node),
            Self::Port { node, id, .. } => write!(f, "#Port<{}.{id}>", node),
            Self::Ref { node, ids, .. } => write!(f, "#Ref<{}.{ids:?}>", node),
            Self::Export {
                module,
                function,
                arity,
            } => write!(f, "fun {module}:{function}/{arity}"),
            Self::Fun { module, index, .. } => write!(f, "#Fun<{module}.{index}>"),
            Self::Record {
                module,
                name,
                fields,
                ..
            } => write!(f, "#record<{module}:{name}/{}>", fields.len()),
            Self::Other { tag, raw } => write!(f, "#etf<{tag}:{} bytes>", raw.len()),
        }
    }
}

impl OwnedTerm {
    fn detach_children(&mut self, pending: &mut Vec<OwnedTerm>) {
        match self {
            Self::List { elems, tail } => {
                pending.extend(std::mem::take(elems));
                if !matches!(**tail, Self::Nil) {
                    pending.push(*std::mem::replace(tail, Box::new(Self::Nil)));
                }
            }
            Self::Tuple(v) => pending.extend(std::mem::take(v)),
            Self::Map(v) => {
                for (key, value) in std::mem::take(v) {
                    pending.push(key);
                    pending.push(value);
                }
            }
            Self::Fun { pid, free_vars, .. } => {
                pending.extend(std::mem::take(free_vars));
                pending.push(*std::mem::replace(pid, Box::new(Self::Nil)));
            }
            Self::Record { fields, .. } => {
                for (_, value) in std::mem::take(fields) {
                    pending.push(value);
                }
            }
            _ => {}
        }
    }
}

impl Drop for OwnedTerm {
    fn drop(&mut self) {
        let mut pending = Vec::new();
        self.detach_children(&mut pending);
        while let Some(mut term) = pending.pop() {
            term.detach_children(&mut pending);
        }
    }
}
