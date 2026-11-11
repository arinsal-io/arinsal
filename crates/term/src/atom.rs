//! Atom table. Port of `erts/emulator/beam/atom.c`, `index.c`, and `hash.c`, OTP-29.1.1.
//!
//! One `IndexTable`: a chained hash (`atom_tab`) plus a segmented index of 1024
//! slots. The name is a global-literal binary (`atom_alloc`). Lookups take the
//! frequent-read side of `ERTS_ATOM_TABLE_LOCK`; insertion takes the write side.

use std::borrow::Cow;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::Term;
use crate::heap::TermBuilder;
use crate::index_table::{
    HashFunctions, IndexEntry, IndexSlot, IndexTable, alloc_entry, init_entry,
};
use arinsal_alloc::typed::ErtsAlcType;

/// Stable atom index. Its value matches the OTP preloaded atom order at startup.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct Atom(pub u32);

/// Atom interning failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AtomError {
    /// More than 255 Unicode scalar values, or more than the UTF-8 byte ceiling.
    TooLong,
    /// Reserved for callers that still surface a table overflow as an error.
    /// `index_put_entry` itself exits the emulator instead.
    SystemLimit,
    /// UTF-8 bytes are not a legal atom encoding.
    BadEncoding,
}

/// Byte encoding accepted by `erts_atom_put` / `erts_atom_get`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AtomEncoding {
    /// 7-bit ASCII. High bytes are rejected by lookup and stored unchanged by insert.
    Ascii,
    /// One byte per character, expanded to UTF-8 before hashing.
    Latin1,
    /// UTF-8, validated on the insert miss path.
    Utf8,
}

/// `hash_get_info` result. Crash dumps print this as `=hash_table:atom_tab`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HashInfo {
    /// Table name (`atom_tab`).
    pub name: &'static str,
    /// Bucket count (`size`).
    pub size: i32,
    /// Buckets that hold at least one atom (`used`).
    pub used: i32,
    /// Atoms in the hash (`objs`).
    pub objs: i32,
    /// Longest bucket chain (`depth`).
    pub depth: i32,
}

/// Memory of the atom table, in bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AtomMemory {
    /// Hash buckets and index slots (`atom_table_sz`).
    pub table: u64,
    /// Atom entry records.
    pub entries: u64,
    /// Atom text (`atom_space`).
    pub text: u64,
}

/// `index_info` counters for the atom index.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IndexInfo {
    /// Allocated index slots, grown by pages of 1024.
    pub size: i32,
    /// Maximum number of atoms (`+t`, default 1_048_576).
    pub limit: i32,
    /// Atoms currently published.
    pub entries: i32,
}

/// Generated constants for all entries in OTP's `atom.names`; `PREDEFINED` is the
/// whole generated `erl_atom_table.c` (`atom.names`, then the `bif.tab` atoms).
pub mod atoms {
    include!(concat!(env!("OUT_DIR"), "/atoms.rs"));
}

const ATOM_TAB: &str = "atom_tab";
const ATOM_SIZE: i32 = 3000;
const MAX_ATOM_CHARACTERS: usize = 255;
const MAX_ATOM_SZ_LIMIT: usize = 4 * MAX_ATOM_CHARACTERS;
/// Default `ATOM_LIMIT` (`1024 * 1024`).
pub const DEFAULT_ATOM_TABLE_LIMIT: usize = 1024 * 1024;

// Port of erts/emulator/beam/atom.h (Atom), OTP-29.1.1: the index slot first, then the name
// length, the Latin-1 character count, the ordinal of the first bytes and `u.bin`, the
// global-literal binary that holds the name. The record is allocated by `atom_alloc` from
// `ERTS_ALC_T_ATOM` and never freed.
#[repr(C)]
struct AtomRec {
    slot: IndexSlot,
    len: u16,
    latin1_chars: i16,
    ord0: i32,
    /// `Atom.u.bin`: the global-literal binary returned by `atom_to_binary`.
    bin: Term,
}

impl IndexEntry for AtomRec {
    #[inline(always)]
    fn slot(&self) -> &IndexSlot {
        &self.slot
    }
}

impl AtomRec {
    /// Port of atom.c:107 (erts_atom_get_name): the UTF-8 bytes inside `u.bin`.
    #[inline(always)]
    fn name(&self) -> &str {
        let view = crate::raw::BinRef::try_from(self.bin).expect("atom literal is a binary");
        let bytes = view.bytes().expect("atom literal is a byte string");
        debug_assert_eq!(bytes.len(), self.len as usize);
        // SAFETY: `atom_alloc` stored only text that passed `analyze_utf8` (or ASCII, or Latin-1
        // converted to UTF-8), and the literal binary is immutable.
        unsafe { std::str::from_utf8_unchecked(bytes) }
    }

    #[inline(always)]
    fn hvalue(&self) -> u64 {
        self.slot.hvalue()
    }
}

/// Template of `erts_atom_put_index`: a stack `Atom` with `len`, `u.name` and `latin1_chars`.
struct AtomTemplate<'a> {
    name: &'a [u8],
    latin1_chars: i16,
}

/// `HashFunctions` of the atom table (atom.c: atom_hash, atom_cmp, atom_alloc, atom_free).
/// `atom_space` is the static `atom_space` of atom.c.
struct AtomFns {
    atom_space: AtomicU64,
}

impl HashFunctions for AtomFns {
    type Entry = AtomRec;
    type Template<'a> = AtomTemplate<'a>;

    fn hash(&self, tmpl: &AtomTemplate<'_>) -> u64 {
        atom_hash(tmpl.name)
    }

    #[inline(always)]
    fn cmp(&self, tmpl: &AtomTemplate<'_>, obj: &AtomRec) -> bool {
        // Port of atom.c:119 (atom_cmp).
        tmpl.name.len() == obj.len as usize && tmpl.name == obj.name().as_bytes()
    }

    fn alloc(&self, tmpl: &AtomTemplate<'_>) -> *mut AtomRec {
        // Port of atom.c:130 (atom_alloc).
        let obj = alloc_entry::<AtomRec>(ErtsAlcType::ATOM);
        let bin = literal_atom(tmpl.name);
        init_entry(
            obj,
            AtomRec {
                slot: IndexSlot::new(),
                len: tmpl.name.len() as u16,
                latin1_chars: tmpl.latin1_chars,
                ord0: ord0_of(tmpl.name),
                bin,
            },
        );
        self.atom_space
            .fetch_add(tmpl.name.len() as u64, Ordering::Relaxed);
        obj
    }

    fn free(&self, _obj: &AtomRec) {
        // Port of atom.c:170 (atom_free): empty, atom names are never freed.
    }
}

/// Global, append-only atom table.
pub struct AtomTable {
    /// `erts_atom_table`, with `atom_table_lock` as its lock.
    index: IndexTable<AtomFns>,
}

impl AtomTable {
    /// Create a table with the given maximum, including predefined atoms.
    ///
    /// `limit` is `erts_atom_table_size` (`+t`). Values above `i32::MAX` clamp to
    /// that maximum, which is `MAX_ATOM_TABLE_SIZE` on this 64-bit build.
    // Port of atom.c:430 (init_atom_table).
    pub fn new(limit: usize) -> Self {
        let limit = i32::try_from(limit).unwrap_or(i32::MAX);
        let table = Self {
            index: IndexTable::new(
                ErtsAlcType::ATOM_TABLE,
                ATOM_TAB,
                ATOM_SIZE,
                limit,
                AtomFns {
                    atom_space: AtomicU64::new(0),
                },
            ),
        };
        for name in atoms::PREDEFINED {
            table.intern(name).expect("predefined atoms fit");
        }
        table
    }

    /// Interns the UTF-8 names of an atom chunk in order. The names the table already has are
    /// found under one read lock; the others are put afterwards, in order. An error names the
    /// position of the atom the table refused.
    // Port of erts/emulator/beam/beam_file.c (parse_atom_chunk: erts_atom_put per entry),
    // OTP-29.1.1; the lock is taken once for the chunk instead of once per entry.
    pub fn intern_all<'a>(
        &self,
        names: impl ExactSizeIterator<Item = &'a str> + Clone,
    ) -> Result<Vec<Atom>, (usize, AtomError)> {
        const MISSING: u32 = u32::MAX;
        let mut atoms = Vec::with_capacity(names.len());
        let mut missing = false;
        {
            let guard = self.index.read();
            for name in names.clone() {
                let found = guard.get(&AtomTemplate {
                    name: name.as_bytes(),
                    latin1_chars: 0,
                });
                missing |= found < 0;
                atoms.push(Atom(if found < 0 { MISSING } else { found as u32 }));
            }
        }
        if missing {
            for (index, (atom, name)) in atoms.iter_mut().zip(names).enumerate() {
                if atom.0 == MISSING {
                    *atom = self.intern(name).map_err(|error| (index, error))?;
                }
            }
        }
        Ok(atoms)
    }

    /// Find an atom without writing to the table. `name` is UTF-8 text.
    pub fn get(&self, name: &str) -> Option<Atom> {
        self.lookup(name.as_bytes())
    }

    /// Intern UTF-8 atom text, preserving the first assigned index.
    ///
    /// Rejects more than 255 characters. Does not truncate.
    pub fn intern(&self, name: &str) -> Result<Atom, AtomError> {
        self.put(name.as_bytes(), AtomEncoding::Utf8, false)
    }

    /// Port of erts/emulator/beam/atom.c:231 (`erts_atom_put_index`), OTP-29.1.1.
    ///
    /// `trunc` keeps the first 255 characters instead of returning [`AtomError::TooLong`].
    pub fn put(&self, name: &[u8], enc: AtomEncoding, trunc: bool) -> Result<Atom, AtomError> {
        let mut bytes = name;
        let latin1_chars;
        match enc {
            AtomEncoding::Ascii => {
                if bytes.len() > MAX_ATOM_CHARACTERS {
                    if !trunc {
                        return Err(AtomError::TooLong);
                    }
                    bytes = &bytes[..MAX_ATOM_CHARACTERS];
                }
                latin1_chars = bytes.len() as i16;
                if let Some(atom) = self.lookup(bytes) {
                    return Ok(atom);
                }
            }
            AtomEncoding::Latin1 => {
                if bytes.len() > MAX_ATOM_CHARACTERS {
                    if !trunc {
                        return Err(AtomError::TooLong);
                    }
                    bytes = &bytes[..MAX_ATOM_CHARACTERS];
                }
                latin1_chars = bytes.len() as i16;
                let converted = latin1_to_utf8(bytes);
                if let Some(atom) = self.lookup(converted.as_ref()) {
                    return Ok(atom);
                }
                return self.insert(converted.as_ref(), latin1_chars);
            }
            AtomEncoding::Utf8 => {
                if bytes.len() > MAX_ATOM_SZ_LIMIT && !trunc {
                    return Err(AtomError::TooLong);
                }
                if let Some(atom) = self.lookup(bytes) {
                    return Ok(atom);
                }
                let scan = analyze_utf8(bytes, MAX_ATOM_CHARACTERS);
                match scan.status {
                    Utf8Status::Ok => latin1_chars = scan.latin1,
                    Utf8Status::MaxChars => {
                        if !trunc {
                            return Err(AtomError::TooLong);
                        }
                        bytes = &bytes[..scan.end];
                        latin1_chars = scan.latin1;
                    }
                    Utf8Status::Bad => return Err(AtomError::BadEncoding),
                }
            }
        }
        self.insert(bytes, latin1_chars)
    }

    /// Port of erts/emulator/beam/atom.c:381 (`erts_atom_get`), OTP-29.1.1.
    ///
    /// A miss, a too-long key, or a non-ASCII byte in an ASCII lookup yields `None`.
    /// UTF-8 is not validated: a malformed key simply fails to match a stored atom.
    pub fn existing(&self, name: &[u8], enc: AtomEncoding) -> Option<Atom> {
        match enc {
            AtomEncoding::Ascii => {
                if name.len() > MAX_ATOM_CHARACTERS || name.iter().any(|byte| byte & 0x80 != 0) {
                    return None;
                }
                self.lookup(name)
            }
            AtomEncoding::Latin1 => {
                if name.len() > MAX_ATOM_CHARACTERS {
                    return None;
                }
                let converted = latin1_to_utf8(name);
                self.lookup(converted.as_ref())
            }
            AtomEncoding::Utf8 => {
                if name.len() > MAX_ATOM_SZ_LIMIT {
                    return None;
                }
                self.lookup(name)
            }
        }
    }

    /// Return immutable atom text for a valid index without taking the table lock.
    // Port of erts/emulator/beam/atom.c:107 (erts_atom_get_name), OTP-29.1.1.
    pub fn text(&self, atom: Atom) -> Option<&str> {
        self.record(atom).map(|rec| rec.name())
    }

    /// The global-literal UTF-8 binary (`Atom.u.bin`).
    ///
    /// `atom_to_binary` with `utf8` returns this term. It is not copied.
    pub fn utf8_literal(&self, atom: Atom) -> Option<Term> {
        Some(self.record(atom)?.bin)
    }

    /// Whether the stored UTF-8 bytes are already the Latin-1 encoding.
    ///
    /// `None` when a character does not fit in Latin-1. `Some(true)` means
    /// `atom_to_binary` with `latin1` returns [`Self::utf8_literal`].
    pub fn latin1_is_stored(&self, atom: Atom) -> Option<bool> {
        let rec = self.record(atom)?;
        if rec.latin1_chars < 0 {
            return None;
        }
        Some(rec.latin1_chars as usize == rec.len as usize)
    }

    /// UTF-8 text and Latin-1 character count of `atom` from one record lookup.
    ///
    /// Port of the `atom_tab(atom_val(atom))` reads in erts/emulator/beam/external.c
    /// (enc_atom, encode_atom_size), OTP-29.1.1.
    #[inline]
    pub fn encoding_info(&self, atom: Atom) -> Option<(&str, Option<usize>)> {
        let rec = self.record(atom)?;
        Some((rec.name(), usize::try_from(rec.latin1_chars).ok()))
    }

    /// Number of Unicode scalar values in Latin-1 for this atom, or `None` if it is not.
    ///
    /// Port of erts/emulator/beam/atom.h (`Atom.latin1_chars`), OTP-29.1.1.
    pub fn latin1_char_count(&self, atom: Atom) -> Option<usize> {
        self.record(atom)
            .and_then(|rec| usize::try_from(rec.latin1_chars).ok())
    }

    /// Low 32 bits of the atom's bucket hash.
    ///
    /// `make_hash2` returns `slot.bucket.hvalue` as a `Uint32`, so this is the
    /// value `phash2` uses for an atom.
    // Port of the direct atom-table slot read in erts/emulator/beam/erl_term_hashing.c:1515,
    // OTP-29.1.1.
    #[inline(always)]
    pub fn hash(&self, atom: Atom) -> Option<u32> {
        self.record(atom).map(|rec| rec.hvalue() as u32)
    }

    /// Full bucket hash (`HashValue`, 64-bit on this build).
    ///
    /// ETS `MAKE_HASH` uses this word for atom keys.
    pub fn hvalue(&self, atom: Atom) -> Option<u64> {
        self.record(atom).map(|rec| rec.hvalue())
    }

    /// Latin-1 bytes of `atom`, or `None` when a character does not fit in Latin-1.
    ///
    /// Port of `atom_to_binary` when the encoding is `latin1`
    /// (`erts/emulator/beam/erl_unicode.c` atom_to_binary), OTP-29.1.1.
    pub fn latin1_bytes(&self, atom: Atom) -> Option<Vec<u8>> {
        let rec = self.record(atom)?;
        if rec.latin1_chars < 0 {
            return None;
        }
        if rec.latin1_chars as usize == rec.len as usize {
            return Some(rec.name().as_bytes().to_vec());
        }
        Some(utf8_to_latin1(rec.name().as_bytes()))
    }

    /// Term order of two atoms. Port of `erl_utils.h:193` (`erts_cmp_atoms`), OTP-29.1.1.
    pub fn cmp_atoms(&self, a: Atom, b: Atom) -> std::cmp::Ordering {
        match (self.record(a), self.record(b)) {
            (Some(left), Some(right)) => cmp_recs(left, right),
            (left, right) => left.is_some().cmp(&right.is_some()),
        }
    }

    /// Port of erts/emulator/beam/hash.c:45 (`hash_get_info`), OTP-29.1.1.
    pub fn hash_info(&self) -> HashInfo {
        let guard = self.index.read();
        let stats = guard.hash().stats();
        HashInfo {
            name: self.index.name(),
            size: stats.size,
            used: stats.used,
            objs: stats.objs,
            depth: stats.depth,
        }
    }

    /// Port of erts/emulator/beam/index.c:32 (`index_info`) counters, OTP-29.1.1.
    pub fn index_info(&self) -> IndexInfo {
        let _guard = self.index.read();
        let (size, limit, entries) = self.index.info();
        IndexInfo {
            size,
            limit,
            entries,
        }
    }

    /// Memory the table holds, split as erts accounts it: the hash and index tables
    /// (`atom_table_sz`), the atom entries, and the atom text (`atom_space`).
    // Port of erts/emulator/beam/atom.c (atom_table_sz, erts_atom_get_text_space_sizes) and
    // index.c (index_table_sz), OTP-29.1.1.
    pub fn memory(&self) -> AtomMemory {
        let guard = self.index.read();
        let table = guard.hash().bucket_bytes() + self.index.seg_bytes();
        let entries = self.index.num_entries() as usize * std::mem::size_of::<AtomRec>();
        AtomMemory {
            table: table as u64,
            entries: entries as u64,
            text: self.index.fun().atom_space.load(Ordering::Relaxed),
        }
    }

    /// Bytes of atom text stored so far (`atom_space` in `atom.c`).
    pub fn text_space(&self) -> u64 {
        let _guard = self.index.read();
        self.index.fun().atom_space.load(Ordering::Relaxed)
    }

    /// Configured maximum, including predefined atoms.
    pub fn limit(&self) -> usize {
        self.index.info().1 as usize
    }

    /// Number of atoms currently interned. Port of atom.c:340 (atom_table_size).
    pub fn len(&self) -> usize {
        let _guard = self.index.read();
        self.index.num_entries() as usize
    }

    /// Whether the table is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Drop atoms with index `from_ix` and above.
    ///
    /// Port of erts/emulator/beam/index.c:119 (`index_erase_latest_from`), OTP-29.1.1.
    /// The atom free callback is empty, so the records stay allocated; they leave
    /// the hash and `entries` moves back. The atom table itself never calls this.
    pub fn erase_latest_from(&self, from_ix: usize) {
        self.index.write().erase_latest_from(from_ix);
    }

    // Port of atom.c:231 (erts_atom_put_index): `atom_read_lock; index_get; atom_read_unlock`.
    fn lookup(&self, bytes: &[u8]) -> Option<Atom> {
        let ix = self.index.read().get(&AtomTemplate {
            name: bytes,
            latin1_chars: 0,
        });
        (ix >= 0).then_some(Atom(ix as u32))
    }

    // Port of atom.c:231 (erts_atom_put_index): `atom_write_lock; index_put; atom_write_unlock`.
    fn insert(&self, bytes: &[u8], latin1_chars: i16) -> Result<Atom, AtomError> {
        let mut guard = self.index.write();
        let ix = guard
            .put_entry(&AtomTemplate {
                name: bytes,
                latin1_chars,
            })
            .slot()
            .index();
        Ok(Atom(ix as u32))
    }

    #[inline(always)]
    fn record(&self, atom: Atom) -> Option<&AtomRec> {
        self.index.lookup(atom.0 as usize)
    }
}

fn literal_atom(bytes: &[u8]) -> Term {
    // Port of atom.c:147 (erts_global_literal_allocate / erts_hfact_new_binary_from_data
    // / erts_global_literal_register), OTP-29.1.1. Atom names are never freed
    // (`atom_free` is empty), so `Atom.u.bin` is the global literal binary.
    // Upper bound of the binary's words: BinRef header plus the on-heap payload.
    let mut build = crate::global_literal_allocate(16 + bytes.len().div_ceil(8));
    let term = TermBuilder::new(&mut build)
        .binary(bytes)
        .expect("atom literal binary");
    build.register(term)
}

fn ord0_of(name: &[u8]) -> i32 {
    // Port of atom.c:173-183. The top bit of the fourth byte is omitted so the
    // signed difference of two ordinals keeps their order.
    let mut bytes = [0_u8; 4];
    let prefix = name.len().min(4);
    bytes[..prefix].copy_from_slice(&name[..prefix]);
    ((bytes[0] as i32) << 23)
        + ((bytes[1] as i32) << 15)
        + ((bytes[2] as i32) << 7)
        + ((bytes[3] as i32) >> 1)
}

fn cmp_recs(left: &AtomRec, right: &AtomRec) -> std::cmp::Ordering {
    let diff = left.ord0 - right.ord0;
    if diff != 0 {
        return if diff < 0 {
            std::cmp::Ordering::Less
        } else {
            std::cmp::Ordering::Greater
        };
    }
    let left_bytes = left.name().as_bytes();
    let right_bytes = right.name().as_bytes();
    let left_tail = left_bytes.get(3..).unwrap_or(&[]);
    let right_tail = right_bytes.get(3..).unwrap_or(&[]);
    let shared = left_tail.len().min(right_tail.len());
    match left_tail[..shared].cmp(&right_tail[..shared]) {
        std::cmp::Ordering::Equal => {
            (left_bytes.len() as i32 - 3).cmp(&(right_bytes.len() as i32 - 3))
        }
        order => order,
    }
}

// Port of erts/emulator/beam/atom.c:83 (atom_hash), OTP-29.1.1.
// `HashValue` is a machine word. The Latin-1 clutch folds a `C2`/`C3` pair back
// into one byte so a UTF-8 atom hashes like the R16 Latin-1 byte.
pub(crate) fn atom_hash(bytes: &[u8]) -> u64 {
    let mut hash = 0_u64;
    let mut len = bytes.len();
    let mut pos = 0;
    while len > 0 {
        len -= 1;
        let mut value = bytes[pos];
        pos += 1;
        if len > 0 && (value & 0xfe) == 0xc2 && bytes[pos] & 0xc0 == 0x80 {
            value = ((value as u16) << 6) as u8 | (bytes[pos] & 0x3f);
            pos += 1;
            len -= 1;
        }
        hash = (hash << 4).wrapping_add(u64::from(value));
        let top = hash & 0xf000_0000;
        if top != 0 {
            hash ^= (top >> 24) ^ top;
        }
    }
    hash
}

/// Low 32 bits of [`atom_hash`], which is what `make_hash2` returns for an atom.
pub(crate) fn otp_atom_hash(text: &str) -> u32 {
    atom_hash(text.as_bytes()) as u32
}

fn latin1_to_utf8(src: &[u8]) -> Cow<'_, [u8]> {
    // Port of atom.c:193 (latin1_to_utf8).
    let Some(first) = src.iter().position(|byte| byte & 0x80 != 0) else {
        return Cow::Borrowed(src);
    };
    let mut dst = Vec::with_capacity(src.len() + (src.len() - first));
    dst.extend_from_slice(&src[..first]);
    for &byte in &src[first..] {
        if byte & 0x80 == 0 {
            dst.push(byte);
        } else {
            dst.push(0xc0 | (byte >> 6));
            dst.push(0x80 | (byte & 0x3f));
        }
    }
    Cow::Owned(dst)
}

fn utf8_to_latin1(source: &[u8]) -> Vec<u8> {
    // Port of erl_unicode.c:2918 (erts_utf8_to_latin1).
    let mut dest = Vec::with_capacity(source.len());
    let mut pos = 0;
    while pos < source.len() {
        if source[pos] & 0x80 == 0 {
            dest.push(source[pos]);
            pos += 1;
        } else {
            dest.push(((source[pos] as u16) << 6) as u8 | (source[pos + 1] & 0x3f));
            pos += 2;
        }
    }
    dest
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Utf8Status {
    Ok,
    MaxChars,
    Bad,
}

struct Utf8Scan {
    status: Utf8Status,
    end: usize,
    latin1: i16,
}

fn analyze_utf8(source: &[u8], max_chars: usize) -> Utf8Scan {
    // Port of erl_unicode.c:1180 (analyze_utf8) via erts_analyze_utf8_x.
    let mut pos = 0;
    let mut err_pos = 0;
    let mut chars = 0_usize;
    let mut latin1_count = 0_usize;
    let mut is_latin1 = true;
    let mut status = Utf8Status::Ok;
    while pos < source.len() {
        let first = source[pos];
        if first & 0x80 == 0 {
            pos += 1;
            latin1_count += 1;
        } else if first & 0xe0 == 0xc0 {
            if source.len() - pos < 2 || source[pos + 1] & 0xc0 != 0x80 || first < 0xc2 {
                status = Utf8Status::Bad;
                break;
            }
            latin1_count += 1;
            if first & 0xfc != 0xc0 {
                is_latin1 = false;
            }
            pos += 2;
        } else if first & 0xf0 == 0xe0 {
            if source.len() - pos < 3
                || source[pos + 1] & 0xc0 != 0x80
                || source[pos + 2] & 0xc0 != 0x80
                || (first == 0xe0 && source[pos + 1] < 0xa0)
                || (first & 0x0f == 0x0d && source[pos + 1] & 0x20 != 0)
            {
                status = Utf8Status::Bad;
                break;
            }
            is_latin1 = false;
            pos += 3;
        } else if first & 0xf8 == 0xf0 {
            if source.len() - pos < 4
                || source[pos + 1] & 0xc0 != 0x80
                || source[pos + 2] & 0xc0 != 0x80
                || source[pos + 3] & 0xc0 != 0x80
                || (first == 0xf0 && source[pos + 1] < 0x90)
                || (first & 0x07 > 0x04)
                || (first & 0x07 == 0x04 && source[pos + 1] & 0x3f > 0x0f)
            {
                status = Utf8Status::Bad;
                break;
            }
            is_latin1 = false;
            pos += 4;
        } else {
            status = Utf8Status::Bad;
            break;
        }
        chars += 1;
        err_pos = pos;
        if max_chars > 0 && pos < source.len() && chars == max_chars {
            status = Utf8Status::MaxChars;
            break;
        }
    }
    Utf8Scan {
        status,
        end: err_pos,
        latin1: if is_latin1 { latin1_count as i16 } else { -1 },
    }
}

static GLOBAL: OnceLock<AtomTable> = OnceLock::new();
static ATOM_TABLE_LIMIT: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(DEFAULT_ATOM_TABLE_LIMIT);

/// Set `+t` before the process-wide table is created.
///
/// Mirrors `erts_atom_table_size`, which `erl` assigns while parsing arguments
/// and which `init_atom_table` then reads. A later call does not resize a table
/// that already exists.
pub fn set_atom_table_limit(limit: usize) {
    ATOM_TABLE_LIMIT.store(limit, Ordering::Relaxed);
}

/// The process-wide atom table. The default limit is 1,048,576 entries.
pub fn global_atoms() -> &'static AtomTable {
    GLOBAL.get_or_init(|| {
        // Port of erl_init.c:260/285: init_global_literals runs before init_atom_table.
        crate::init_global_literals();
        AtomTable::new(ATOM_TABLE_LIMIT.load(Ordering::Relaxed))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_matches_atom_hash_samples() {
        assert_eq!(atom_hash(b"false"), 0x6c_8395);
        assert_eq!(atom_hash(b"erlang"), 0x6c9_2847);
        assert_eq!(atom_hash("å".as_bytes()), 0xe5);
    }

    #[test]
    fn fresh_table_matches_index_and_hash_shape() {
        crate::init_global_literals();
        let table = AtomTable::new(DEFAULT_ATOM_TABLE_LIMIT);
        let index = table.index_info();
        let hash = table.hash_info();
        let entries = atoms::PREDEFINED.len() as i32;
        assert_eq!(index.entries, entries);
        assert_eq!(index.limit, DEFAULT_ATOM_TABLE_LIMIT as i32);
        let pages = (entries as usize).div_ceil(1024);
        assert_eq!(index.size, (pages * 1024) as i32);
        assert_eq!(hash.name, "atom_tab");
        assert_eq!(hash.objs, entries);
        assert_eq!(hash.size, 4096);
        assert!(hash.used > 0 && hash.used <= hash.size);
        assert!(hash.depth >= 1);
        assert_eq!(table.hash(atoms::FALSE), Some(0x6c_8395));
        assert_eq!(table.text(atoms::FALSE), Some("false"));
    }

    #[test]
    fn grow_and_shrink_follow_load_thresholds() {
        crate::init_global_literals();
        let table = AtomTable::new(DEFAULT_ATOM_TABLE_LIMIT);
        let start = table.len();
        let need = 6554_usize.saturating_sub(start);
        for n in 0..need {
            table.intern(&format!("grow_{n}")).unwrap();
        }
        for ix in (0..table.len()).step_by(1024) {
            assert!(table.text(Atom(ix as u32)).is_some(), "atom index {ix}");
        }
        assert_eq!(table.hash_info().size, 8192);
        assert_eq!(table.hash_info().objs, 6554);
        table.erase_latest_from(100);
        let hash = table.hash_info();
        assert_eq!(hash.size, 4096);
        assert_eq!(hash.objs, 100);
        assert_eq!(table.len(), 100);
        assert!(table.text(Atom(0)).is_some());
    }

    #[test]
    fn encodings_and_limit() {
        crate::init_global_literals();
        let table = AtomTable::new(atoms::PREDEFINED.len() + 8);
        let latin = table.put(&[0xe5], AtomEncoding::Latin1, false).unwrap();
        assert_eq!(table.text(latin), Some("å"));
        assert_eq!(table.latin1_bytes(latin).as_deref(), Some(&[0xe5][..]));
        assert_eq!(table.existing(&[0xe5], AtomEncoding::Latin1), Some(latin));
        assert_eq!(
            table.existing("å".as_bytes(), AtomEncoding::Utf8),
            Some(latin)
        );
        assert_eq!(
            table.put(&[0xff], AtomEncoding::Utf8, false),
            Err(AtomError::BadEncoding)
        );
        assert_eq!(
            table.put(&[0xc0, 0x80], AtomEncoding::Utf8, false),
            Err(AtomError::BadEncoding)
        );
        assert_eq!(
            table.put(&vec![b'a'; 256], AtomEncoding::Utf8, false),
            Err(AtomError::TooLong)
        );
        assert_eq!(
            table.put(&vec![0xff; 1021], AtomEncoding::Utf8, false),
            Err(AtomError::TooLong)
        );
        let truncated = table
            .put(&vec![b'z'; 300], AtomEncoding::Utf8, true)
            .unwrap();
        assert_eq!(table.text(truncated).unwrap().chars().count(), 255);
        let emoji = table.intern("😀").unwrap();
        assert_eq!(table.latin1_bytes(emoji), None);
        let literal = table.utf8_literal(latin).unwrap();
        assert!(literal.is_literal());
        assert_eq!(table.latin1_is_stored(latin), Some(false));
        assert!(table.latin1_is_stored(emoji).is_none());
        assert_eq!(table.latin1_is_stored(atoms::FALSE), Some(true));
        assert!(table.cmp_atoms(atoms::FALSE, atoms::TRUE) != std::cmp::Ordering::Equal);
        let left = table.intern("cmp_aaaa").unwrap();
        let right = table.intern("cmp_aaab").unwrap();
        assert_eq!(table.cmp_atoms(left, right), std::cmp::Ordering::Less);

        let limited = AtomTable::new(atoms::PREDEFINED.len());
        assert_eq!(limited.len(), atoms::PREDEFINED.len());
        assert_eq!(limited.limit(), atoms::PREDEFINED.len());
    }
}
