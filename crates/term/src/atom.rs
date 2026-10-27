//! Atom table. Port of `erts/emulator/beam/atom.c`, `index.c`, and `hash.c`, OTP-29.1.1.
//!
//! One `IndexTable`: a chained hash (`atom_tab`) plus a segmented index of 1024
//! slots. The name is a global-literal binary (`atom_alloc`). Lookups take the
//! frequent-read side of `ERTS_ATOM_TABLE_LOCK`; insertion takes the write side.

use crossbeam_utils::atomic::AtomicCell;
use std::borrow::Cow;
use std::sync::atomic::{AtomicI32, AtomicU32, Ordering};
use std::sync::{Mutex, OnceLock};

use crate::Term;
use crate::heap::{TermBuilder, VecHeap};
use crate::rwmutex::FrequentReadRwLock;

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
const MAX_SHIFT: i32 = 64; // ERTS_SIZEOF_TERM * 8
const INDEX_PAGE_SHIFT: usize = 10;
const INDEX_PAGE_SIZE: usize = 1 << INDEX_PAGE_SHIFT;
const INDEX_PAGE_MASK: usize = INDEX_PAGE_SIZE - 1;
const NULL_LINK: u32 = u32::MAX;
const MAX_ATOM_CHARACTERS: usize = 255;
const MAX_ATOM_SZ_LIMIT: usize = 4 * MAX_ATOM_CHARACTERS;
const FIBONACCI: u64 = 11_400_714_819_323_198_485;
/// Default `ATOM_LIMIT` (`1024 * 1024`).
pub const DEFAULT_ATOM_TABLE_LIMIT: usize = 1024 * 1024;

// Port of erts/emulator/beam/hash.h:50 (HashBucket) and index.h:34 (IndexSlot)
// and atom.h:50 (Atom), OTP-29.1.1. `id` is the table slot of this record; erts
// uses the object pointer as that identity.
struct AtomRec {
    id: u32,
    next: AtomicU32,
    hvalue: u64,
    index: AtomicI32,
    latin1_chars: i16,
    ord0: i32,
    /// `Atom.u.bin`: the global-literal binary returned by `atom_to_binary`.
    bin: Term,
    /// UTF-8 name. Same bytes as `bin`. Owned here so lookup does not borrow
    /// the literal heap: a `'static` slice of that chunk is not a safe view.
    name: Box<str>,
}

// Port of erts/emulator/beam/index.c (index_put_entry) and index.h
// (erts_index_lookup), OTP-29.1.1. AtomicCell keeps each pointer-sized slot safe to
// publish while preserving the fixed-page layout and permanent record references.
struct Page {
    slots: [AtomicCell<Option<&'static AtomRec>>; INDEX_PAGE_SIZE],
}

impl Page {
    fn new() -> Self {
        Self {
            slots: std::array::from_fn(|_| AtomicCell::new(None)),
        }
    }
}

struct Inner {
    shift: i32,
    max_shift: i32,
    shrink_threshold: i32,
    grow_threshold: i32,
    nobjs: i32,
    buckets: Vec<u32>,
    atoms: Vec<&'static AtomRec>,
    entries: i32,
    size: i32,
    limit: i32,
    atom_space: u64,
}

/// Global, append-only atom table.
pub struct AtomTable {
    inner: FrequentReadRwLock<Inner>,
    /// Pre-sized pointer table, with fixed 1024-slot pages allocated on demand.
    seg: Box<[AtomicCell<Option<&'static Page>>]>,
}

impl AtomTable {
    /// Create a table with the given maximum, including predefined atoms.
    ///
    /// `limit` is `erts_atom_table_size` (`+t`). Values above `i32::MAX` clamp to
    /// that maximum, which is `MAX_ATOM_TABLE_SIZE` on this 64-bit build.
    pub fn new(limit: usize) -> Self {
        let limit = i32::try_from(limit).unwrap_or(i32::MAX);
        let pages = (limit as usize).div_ceil(INDEX_PAGE_SIZE).max(1);
        let table = Self {
            inner: FrequentReadRwLock::new(Inner::new(limit)),
            seg: (0..pages).map(|_| AtomicCell::new(None)).collect(),
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
            let inner = self.inner.read();
            for name in names.clone() {
                let found = find(&inner, name.as_bytes());
                missing |= found.is_none();
                atoms.push(Atom(found.unwrap_or(MISSING)));
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
        self.record(atom).map(|rec| rec.name.as_ref())
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
        Some(rec.latin1_chars as usize == rec.name.len())
    }

    /// UTF-8 text and Latin-1 character count of `atom` from one record lookup.
    ///
    /// Port of the `atom_tab(atom_val(atom))` reads in erts/emulator/beam/external.c
    /// (enc_atom, encode_atom_size), OTP-29.1.1.
    #[inline]
    pub fn encoding_info(&self, atom: Atom) -> Option<(&str, Option<usize>)> {
        let rec = self.record(atom)?;
        Some((rec.name.as_ref(), usize::try_from(rec.latin1_chars).ok()))
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
    pub fn hash(&self, atom: Atom) -> Option<u32> {
        self.record(atom).map(|rec| rec.hvalue as u32)
    }

    /// Full bucket hash (`HashValue`, 64-bit on this build).
    ///
    /// ETS `MAKE_HASH` uses this word for atom keys.
    pub fn hvalue(&self, atom: Atom) -> Option<u64> {
        self.record(atom).map(|rec| rec.hvalue)
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
        if rec.latin1_chars as usize == rec.name.len() {
            return Some(rec.name.as_bytes().to_vec());
        }
        Some(utf8_to_latin1(rec.name.as_bytes()))
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
        let inner = self.inner.read();
        let mut used = 0;
        let mut depth = 0;
        for &head in &inner.buckets {
            let mut chain = 0;
            let mut link = head;
            while link != NULL_LINK {
                chain += 1;
                link = inner.atoms[link as usize].next.load(Ordering::Relaxed);
            }
            if chain > 0 {
                used += 1;
                depth = depth.max(chain);
            }
        }
        HashInfo {
            name: ATOM_TAB,
            size: inner.buckets.len() as i32,
            used,
            objs: inner.nobjs,
            depth,
        }
    }

    /// Port of erts/emulator/beam/index.c:32 (`index_info`) counters, OTP-29.1.1.
    pub fn index_info(&self) -> IndexInfo {
        let inner = self.inner.read();
        IndexInfo {
            size: inner.size,
            limit: inner.limit,
            entries: inner.entries,
        }
    }

    /// Memory the table holds, split as erts accounts it: the hash and index tables
    /// (`atom_table_sz`), the atom entries, and the atom text (`atom_space`).
    // Port of erts/emulator/beam/atom.c (atom_table_sz, erts_atom_get_text_space_sizes) and
    // index.c (index_table_sz), OTP-29.1.1, for this table's own layout.
    pub fn memory(&self) -> AtomMemory {
        let inner = self.inner.read();
        let pages = self.seg.iter().filter(|page| page.load().is_some()).count();
        let table = inner.buckets.capacity() * std::mem::size_of::<u32>()
            + inner.atoms.capacity() * std::mem::size_of::<&'static AtomRec>()
            + self.seg.len() * std::mem::size_of::<AtomicCell<Option<&'static Page>>>()
            + pages * std::mem::size_of::<Page>();
        // Records are allocated once and never freed, as erts `atom_alloc`.
        let entries = inner.atoms.len() * std::mem::size_of::<AtomRec>();
        AtomMemory {
            table: table as u64,
            entries: entries as u64,
            text: inner.atom_space,
        }
    }

    /// Bytes of atom text stored so far (`atom_space` in `atom.c`).
    pub fn text_space(&self) -> u64 {
        self.inner.read().atom_space
    }

    /// Configured maximum, including predefined atoms.
    pub fn limit(&self) -> usize {
        self.inner.read().limit as usize
    }

    /// Number of atoms currently interned.
    pub fn len(&self) -> usize {
        self.inner.read().entries as usize
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
        let from_ix = i32::try_from(from_ix).unwrap_or(i32::MAX);
        let mut inner = self.inner.write();
        if from_ix >= inner.entries {
            return;
        }
        for ix in from_ix..inner.entries {
            let Some(rec) = self.published(ix as usize) else {
                continue;
            };
            unlink(&mut inner, rec.id);
        }
        inner.entries = from_ix;
    }

    fn lookup(&self, bytes: &[u8]) -> Option<Atom> {
        let inner = self.inner.read();
        find(&inner, bytes).map(Atom)
    }

    fn insert(&self, bytes: &[u8], latin1_chars: i16) -> Result<Atom, AtomError> {
        let mut inner = self.inner.write();
        if let Some(index) = find(&inner, bytes) {
            return Ok(Atom(index));
        }
        // Port of index.c:87: a full index calls erts_exit(ERTS_DUMP_EXIT).
        // The new name is not published. Character overflow is AtomError::TooLong,
        // which the BIFs report as system_limit.
        if inner.entries >= inner.limit {
            let limit = inner.limit;
            drop(inner);
            index_exhausted(limit);
        }
        let id = push_new(&mut inner, bytes, latin1_chars);
        let ix = inner.entries;
        if ix >= inner.size {
            // Port of index.c:85-94: allocate the next index page, then advance `size`.
            inner.size += INDEX_PAGE_SIZE as i32;
        }
        let rec = inner.atoms[id as usize];
        rec.index.store(ix, Ordering::Relaxed);
        let page_ix = (ix as usize) >> INDEX_PAGE_SHIFT;
        let page = match self.seg[page_ix].load() {
            Some(page) => page,
            None => {
                let page: &'static Page = Box::leak(Box::new(Page::new()));
                self.seg[page_ix].store(Some(page));
                page
            }
        };
        page.slots[(ix as usize) & INDEX_PAGE_MASK].store(Some(rec));
        inner.entries = ix + 1;
        Ok(Atom(ix as u32))
    }

    fn record(&self, atom: Atom) -> Option<&AtomRec> {
        self.published(atom.0 as usize)
    }

    fn published(&self, ix: usize) -> Option<&AtomRec> {
        let page = self.seg.get(ix >> INDEX_PAGE_SHIFT)?.load()?;
        page.slots.get(ix & INDEX_PAGE_MASK)?.load()
    }
}

impl Inner {
    // Port of erts/emulator/beam/hash.c:121 (hash_init) and index.c:59
    // (erts_index_init), OTP-29.1.1. The atom table passes `3 * ATOM_SIZE / 4`.
    fn new(limit: i32) -> Self {
        let requested = 3 * ATOM_SIZE / 4;
        let mut pow = 1_i32;
        while (1_i32 << pow) < requested {
            pow += 1;
        }
        let shift = MAX_SHIFT - pow;
        let slots = slot_count(shift) as usize;
        let mut inner = Self {
            shift,
            max_shift: shift,
            shrink_threshold: -1,
            grow_threshold: 0,
            nobjs: 0,
            buckets: vec![NULL_LINK; slots],
            atoms: Vec::new(),
            entries: 0,
            size: 0,
            limit,
            atom_space: 0,
        };
        set_thresholds(&mut inner);
        inner
    }
}

fn slot_count(shift: i32) -> i32 {
    // Port of hash.c:41 (hash_get_slots). The shift stays in `1..63` for atom-table sizes.
    (1_u64 << (MAX_SHIFT - shift)) as i32
}

fn set_thresholds(inner: &mut Inner) {
    // Port of hash.c:108 (set_thresholds): grow at 160% load, shrink at 20%,
    // never below the size `hash_init` chose.
    let slots = slot_count(inner.shift);
    inner.grow_threshold = (8 * slots) / 5;
    inner.shrink_threshold = if inner.shift < inner.max_shift {
        slots / 5
    } else {
        -1
    };
}

fn hash_slot(shift: i32, mut hv: u64) -> usize {
    // Port of hash.h:108 (hash_get_slot), the 64-bit fibonacci mapping.
    let shift = shift as u32;
    hv ^= hv >> shift;
    (FIBONACCI.wrapping_mul(hv) >> shift) as usize
}

fn find(inner: &Inner, bytes: &[u8]) -> Option<u32> {
    // Port of hash.h:133 (hash_fetch) and atom.c:119 (atom_cmp).
    let hvalue = atom_hash(bytes);
    let mut link = inner.buckets[hash_slot(inner.shift, hvalue)];
    while link != NULL_LINK {
        let rec = &inner.atoms[link as usize];
        if rec.hvalue == hvalue && rec.name.as_bytes() == bytes {
            let index = rec.index.load(Ordering::Relaxed);
            if index >= 0 {
                return Some(index as u32);
            }
        }
        link = rec.next.load(Ordering::Relaxed);
    }
    None
}

fn push_new(inner: &mut Inner, bytes: &[u8], latin1_chars: i16) -> u32 {
    // Port of hash.c:235 (hash_put) and atom.c:130 (atom_alloc).
    let hvalue = atom_hash(bytes);
    let slot = hash_slot(inner.shift, hvalue);
    let id = inner.atoms.len() as u32;
    let (bin, name) = literal_atom(bytes);
    let rec = Box::leak(Box::new(AtomRec {
        id,
        next: AtomicU32::new(inner.buckets[slot]),
        hvalue,
        index: AtomicI32::new(-1),
        latin1_chars,
        ord0: ord0_of(bytes),
        bin,
        name,
    }));
    inner.buckets[slot] = id;
    inner.atoms.push(rec);
    inner.nobjs += 1;
    inner.atom_space += bytes.len() as u64;
    if inner.nobjs > inner.grow_threshold {
        rehash(inner, true);
    }
    id
}

fn literal_atom(bytes: &[u8]) -> (Term, Box<str>) {
    // Port of atom.c:147 (erts_global_literal_allocate / erts_hfact_new_binary_from_data
    // / erts_global_literal_register), OTP-29.1.1. The heap is process-lifetime:
    // atom names are never freed (`atom_free` is empty).
    static HEAP: OnceLock<Mutex<VecHeap>> = OnceLock::new();
    let heap = HEAP.get_or_init(|| Mutex::new(VecHeap::new_literal()));
    let mut heap = heap.lock().expect("atom literal heap");
    let term = TermBuilder::new(&mut *heap)
        .binary(bytes)
        .expect("atom literal binary");
    // `bytes` is the UTF-8 just stored in that literal binary (ASCII, Latin-1
    // expanded to UTF-8, or validated UTF-8). Lookup compares `name.as_bytes()`
    // and does not re-read the heap. The chunk's words are not a safe `'static`
    // `&[u8]` while later atoms still append to it.
    let name = std::str::from_utf8(bytes)
        .expect("atom text is utf-8")
        .into();
    (term, name)
}

fn index_exhausted(limit: i32) -> ! {
    // Port of index.c:89 and erl_init.c:2718 (`ERTS_DUMP_EXIT` then exit status 1).
    // erl_crash_dump.c:509 and :697 print the banner. The dump body is left for
    // the crash-dump agent; the message and status match erts on this platform
    // (`erts_fprintf` writes `\r\n`).
    let message = format!(
        "no more index entries in atom_tab (max={limit})\r\n\r\nCrash dump is being written to: erl_crash.dump...done\r\n"
    );
    let _ = std::io::Write::write_all(&mut std::io::stderr(), message.as_bytes());
    let _ = std::io::Write::flush(&mut std::io::stderr());
    std::process::exit(1);
}

fn unlink(inner: &mut Inner, id: u32) {
    // Port of hash.c:262 (hash_erase). `atom_free` is empty, so the record stays.
    let hvalue = inner.atoms[id as usize].hvalue;
    let slot = hash_slot(inner.shift, hvalue);
    let mut link = inner.buckets[slot];
    let mut prev = None;
    while link != NULL_LINK {
        let next = inner.atoms[link as usize].next.load(Ordering::Relaxed);
        if link == id {
            if let Some(previous) = prev {
                inner.atoms[previous as usize]
                    .next
                    .store(next, Ordering::Relaxed);
            } else {
                inner.buckets[slot] = next;
            }
            inner.nobjs -= 1;
            if inner.nobjs < inner.shrink_threshold {
                rehash(inner, false);
            }
            return;
        }
        prev = Some(link);
        link = next;
    }
}

fn rehash(inner: &mut Inner, grow: bool) {
    // Port of hash.c:187 (rehash).
    if grow {
        inner.shift -= 1;
    } else if inner.shift == inner.max_shift {
        return;
    } else {
        inner.shift += 1;
    }
    let slots = slot_count(inner.shift) as usize;
    let old = std::mem::replace(&mut inner.buckets, vec![NULL_LINK; slots]);
    for mut link in old {
        while link != NULL_LINK {
            let next = inner.atoms[link as usize].next.load(Ordering::Relaxed);
            let slot = hash_slot(inner.shift, inner.atoms[link as usize].hvalue);
            inner.atoms[link as usize]
                .next
                .store(inner.buckets[slot], Ordering::Relaxed);
            inner.buckets[slot] = link;
            link = next;
        }
    }
    set_thresholds(inner);
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
    let left_bytes = left.name.as_bytes();
    let right_bytes = right.name.as_bytes();
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
    GLOBAL.get_or_init(|| AtomTable::new(ATOM_TABLE_LIMIT.load(Ordering::Relaxed)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_matches_atom_hash_samples() {
        assert_eq!(atom_hash(b"false"), 0x6c_8395);
        assert_eq!(atom_hash(b"erlang"), 0x6c9_2847);
        assert_eq!(atom_hash("å".as_bytes()), 0xe5);
        assert_eq!(hash_slot(52, atom_hash(b"false")), 3389);
        assert_eq!(hash_slot(52, atom_hash(b"ok")), 3104);
    }

    #[test]
    fn atom_index_slots_are_lock_free_pointer_cells() {
        assert!(AtomicCell::<Option<&'static AtomRec>>::is_lock_free());
        similar_asserts::assert_eq!(
            std::mem::size_of::<AtomicCell<Option<&'static AtomRec>>>(),
            std::mem::size_of::<*const AtomRec>()
        );
    }

    #[test]
    fn fresh_table_matches_index_and_hash_shape() {
        let table = AtomTable::new(DEFAULT_ATOM_TABLE_LIMIT);
        let index = table.index_info();
        let hash = table.hash_info();
        let entries = atoms::PREDEFINED.len() as i32;
        assert_eq!(index.entries, entries);
        assert_eq!(index.limit, DEFAULT_ATOM_TABLE_LIMIT as i32);
        let pages = (entries as usize).div_ceil(INDEX_PAGE_SIZE);
        assert_eq!(index.size, (pages * INDEX_PAGE_SIZE) as i32);
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
        let table = AtomTable::new(DEFAULT_ATOM_TABLE_LIMIT);
        let start = table.len();
        let need = 6554_usize.saturating_sub(start);
        for n in 0..need {
            table.intern(&format!("grow_{n}")).unwrap();
        }
        for ix in (0..table.len()).step_by(INDEX_PAGE_SIZE) {
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
