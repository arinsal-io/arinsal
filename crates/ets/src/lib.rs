//! VM-independent ETS storage. The VM owns access checks and process lifecycle.

mod block_cache;
mod catree;
mod dbterm;
mod hash;
mod hash_select;
pub mod match_spec;
pub use hash_select::{
    Chunk, HASH_SELECT_ITERATIONS, HashScanEnd, HashScanPlan, IterSafety, SavedMatches,
};
pub mod rwmtx;
mod tree;
mod tree_select;
use catree::CATree;
pub(crate) use dbterm::{DbTerm, StoredTerm};
use tree::{InsertResult, Node, TreeRoot};
pub use tree_select::{SavedKey, ScanPosition, TREE_SELECT_ITERATIONS, TreeScanEnd, TreeScanPlan};

use arinsal_term::{
    Atom, ExternalBinary, HeapAlloc, Identity, MagicRef, Node as TermNode, Term, TermBuilder,
    TermError, TermKind, VecHeap, WritableBinary, cmp, copy_term, exact_eq, global_atoms,
    internal_hash, term_sequence,
};
use num_bigint::BigInt;
use num_traits::ToPrimitive;
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet, VecDeque};
#[cfg(not(miri))]
use std::sync::OnceLock;
use std::sync::atomic::{
    AtomicI64, AtomicU8, AtomicU64, AtomicUsize, Ordering as AtomicOrdering, fence,
};
use std::sync::{Arc, Mutex};
#[cfg(not(miri))]
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use hash::{ConcurrentHashStorage, HashGarbage, HashStorage, ets_hash};

/// Table identity. The VM can expose this as a local reference.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Tid(pub u64);

impl Tid {
    fn new(slot: usize, generation: u32) -> Option<Self> {
        let slot = u32::try_from(slot).ok()?;
        Some(Self((u64::from(generation) << 32) | u64::from(slot)))
    }

    fn slot(self) -> Option<usize> {
        usize::try_from(self.0 as u32).ok()
    }

    fn generation(self) -> u32 {
        (self.0 >> 32) as u32
    }
}

impl Tid {
    /// Decode a table handle: the table identity stored in the magic binary a tid reference
    /// points at.
    // Port of erts/emulator/beam/erl_db.c (db_get_table_aux, the `erts_magic_ref2bin` test):
    // a reference that is not the magic reference of an ETS table is not a table handle.
    pub fn from_term(term: Term) -> Option<Self> {
        term.with_magic_payload::<TableLock, _>(|lock| lock.tid)
    }
}

/// ETS table kind.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TableType {
    /// One object per exact key.
    Set,
    /// One object per ordered (loose) key.
    OrderedSet,
    /// Distinct objects per exact key.
    Bag,
    /// Repeated objects per exact key.
    DuplicateBag,
}

/// Access policy recorded for the VM to enforce.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Protection {
    /// Owner may read and write.
    Private,
    /// Anyone may read; owner may write.
    Protected,
    /// Anyone may read and write.
    Public,
}

/// ETS write concurrency request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WriteConcurrency {
    /// No concurrent writer tuning.
    Disabled,
    /// Concurrent writes requested.
    Enabled,
    /// OTP `auto` tuning requested.
    Auto,
    /// OTP debug-only fixed hash lock count.
    Fixed(usize),
}

/// Heir data held until the VM transfers a table on owner death.
#[derive(Clone, Copy, Debug)]
pub struct Heir {
    /// Recipient process identifier.
    pub pid: Term,
    /// Data copied by the VM when ownership changes.
    pub data: Term,
    /// `{heir, Pid, Data}` sends `'ETS-TRANSFER'`; `{heir, Pid}` keeps erts'
    /// non-value heir data and transfers silently (erl_db.c, :4919-4929).
    pub transfer: bool,
    /// Creation order of the heir process when it was set, so a reused pid does not
    /// inherit (erl_db.c, heir_started_interval).
    pub started_interval: u64,
}

/// Validated table creation options.
#[derive(Clone, Copy, Debug)]
pub struct TableOptions {
    /// Table name, whether or not registered by it.
    pub name: Atom,
    /// Register the table under `name`.
    pub named_table: bool,
    /// Storage kind.
    pub table_type: TableType,
    /// One-based tuple position of the key.
    pub keypos: usize,
    /// Access policy for the VM.
    pub protection: Protection,
    /// Owner process identifier.
    pub owner: Term,
    /// Heir, if present.
    pub heir: Option<Heir>,
    /// Read concurrency hint.
    pub read_concurrency: bool,
    /// Write concurrency hint.
    pub write_concurrency: WriteConcurrency,
    /// Counter distribution hint.
    pub decentralized_counters: bool,
    /// Store non-key boxed elements in external term format.
    pub compressed: bool,
}

/// Errors to be translated to BIF exceptions by the VM.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EtsError {
    /// Invalid argument, object, key, or option.
    BadArg,
    /// `badarg` with extended error information: the `cause` erts stores in
    /// `p->fvalue` (`EXI_*` in erts/emulator/beam/erl_db.c, OTP-29.1.1).
    BadArgCause(&'static str),
    /// No table has this identity.
    NoTable,
    /// The name is already registered.
    NameTaken,
    /// The operation is deliberately unavailable.
    Unsupported(&'static str),
    /// Term copy or allocation failed.
    Term(TermError),
    /// The table is busy with a trapped operation; the caller retries after helping it.
    Busy,
}

/// One `update_counter` operation, with an optional threshold reset.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CounterOp {
    /// One-based tuple element position.
    pub position: usize,
    /// Amount to add.
    pub increment: i64,
    /// Reset to the second value when crossing the first value.
    pub threshold: Option<(i64, i64)>,
}

/// Counter operation with arbitrary precision operands.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BigCounterOp {
    /// One-based tuple element position.
    pub position: usize,
    /// Amount to add.
    pub increment: BigInt,
    /// Reset value when the operation crosses this threshold.
    pub threshold: Option<(BigInt, BigInt)>,
}

/// Core table metadata for the VM's `ets:info` conversion.
#[derive(Clone, Copy, Debug)]
pub struct TableInfo {
    /// OTP-compatible reported object count.
    pub size: usize,
    /// Number of distinct keys.
    pub key_count: usize,
    /// Number of active fixations.
    pub fixed: usize,
    /// Creation options, including owner and heir.
    pub options: TableOptions,
}

/// Result of `lookup_element/4` before the VM applies table-specific list shape.
pub enum ElementLookup {
    /// One value for set tables or several for bag tables.
    Values(Vec<Term>),
    /// The key was absent and the caller supplied a default.
    Default(Term),
}

/// One `select/3`, `match/3`, or `match_object/3` page.
pub struct SelectBatch {
    /// Results in the order returned by ETS.
    pub rows: Vec<Term>,
    /// State for the next page, or `None` for `$end_of_table`.
    pub continuation: Option<SelectContinuation>,
}

/// Owned selection state that survives table writes between pages.
pub struct SelectContinuation {
    tid: Tid,
    program_ref: Term,
    limit: usize,
    reverse: bool,
    last_key: Option<Term>,
    slot: usize,
    rest: Vec<Term>,
    started: bool,
    _heap: VecHeap,
}

/// Partial `select_count` result after a bounded traversal cycle.
pub struct CountBatch {
    /// Number of selected objects so far.
    pub count: usize,
    /// State for the next traversal cycle.
    pub continuation: Option<CountContinuation>,
}

/// Owned internal `select_count` trap continuation.
pub struct CountContinuation {
    tid: Tid,
    program_ref: Term,
    total: usize,
    last_key: Option<Term>,
    slot: usize,
    _heap: VecHeap,
}

impl CountContinuation {
    /// Encode the OTP 29 ordered or hash 5-tuple trap continuation.
    pub fn to_term<H: HeapAlloc>(&self, table: &Table, dst: &mut H) -> Result<Term, EtsError> {
        if self.tid != table.tid {
            return Err(EtsError::BadArg);
        }
        let tid = table.tid_term(dst)?;
        let program = copy_term(self.program_ref, dst)?;
        let total = TermBuilder::new(dst).int_from_i128(self.total as i128)?;
        if table.options.table_type == TableType::OrderedSet {
            let key = copy_term(self.last_key.ok_or(EtsError::BadArg)?, dst)?;
            Ok(TermBuilder::new(dst).tuple(&[tid, key, Term::NIL, program, total])?)
        } else {
            let slot = Term::small(if self.slot == usize::MAX {
                -1
            } else {
                self.slot as i64
            })
            .ok_or(EtsError::BadArg)?;
            Ok(TermBuilder::new(dst).tuple(&[
                tid,
                slot,
                program,
                total,
                Term::small(0).unwrap(),
            ])?)
        }
    }

    /// Decode and validate an internal `select_count` continuation.
    pub fn from_term(
        table: &Table,
        program: &match_spec::MatchProgram,
        term: Term,
    ) -> Result<Self, EtsError> {
        // SAFETY: the caller retains the source continuation heap during this copy.
        let tuple = unsafe { term.tuple_ref() }.ok_or(EtsError::BadArg)?;
        let parts = tuple.iter().collect::<Vec<_>>();
        let ordered = table.options.table_type == TableType::OrderedSet;
        if parts.len() != 5
            || Tid::from_term(parts[0]) != Some(table.tid)
            || !program.matches_reference(parts[if ordered { 3 } else { 2 }])
        {
            return Err(EtsError::BadArg);
        }
        let total = integer_value(parts[if ordered { 4 } else { 3 }])
            .and_then(|value| value.to_usize())
            .ok_or(EtsError::BadArg)?;
        let mut heap = VecHeap::new();
        let program_ref = copy_term(parts[if ordered { 3 } else { 2 }], &mut heap)?;
        let (last_key, slot) = if ordered {
            if parts[2] != Term::NIL {
                return Err(EtsError::BadArg);
            }
            (Some(copy_term(parts[1], &mut heap)?), 0)
        } else {
            let slot = parts[1].as_small().ok_or(EtsError::BadArg)?;
            if slot < 0 || parts[4].as_small().is_none() {
                return Err(EtsError::BadArg);
            }
            (None, slot as usize)
        };
        Ok(Self {
            tid: table.tid,
            program_ref,
            total,
            last_key,
            slot,
            _heap: heap,
        })
    }
}

impl SelectContinuation {
    /// Encode the OTP 29 ordered 8-tuple or hash 6-tuple continuation.
    pub fn to_term<H: HeapAlloc>(&self, table: &Table, dst: &mut H) -> Result<Term, EtsError> {
        if self.tid != table.tid {
            return Err(EtsError::BadArg);
        }
        let tid = table.tid_term(dst)?;
        let program = copy_term(self.program_ref, dst)?;
        let limit = Term::small(self.limit as i64).ok_or(EtsError::BadArg)?;
        if table.options.table_type == TableType::OrderedSet {
            let key = copy_term(self.last_key.ok_or(EtsError::BadArg)?, dst)?;
            Ok(TermBuilder::new(dst).tuple(&[
                tid,
                key,
                Term::NIL,
                limit,
                program,
                Term::NIL,
                Term::small(self.reverse as i64).unwrap(),
                Term::small(0).unwrap(),
            ])?)
        } else {
            let rest = self
                .rest
                .iter()
                .map(|&row| copy_term(row, dst))
                .collect::<Result<Vec<_>, _>>()?;
            let rest_len = Term::small(rest.len() as i64).ok_or(EtsError::BadArg)?;
            let rest = TermBuilder::new(dst).list_from_iter(rest)?;
            let slot = Term::small(if self.slot == usize::MAX {
                -1
            } else {
                self.slot as i64
            })
            .ok_or(EtsError::BadArg)?;
            Ok(TermBuilder::new(dst).tuple(&[tid, slot, limit, program, rest, rest_len])?)
        }
    }

    /// Decode a user continuation, validating its table and compiled program.
    pub fn from_term(
        table: &Table,
        program: &match_spec::MatchProgram,
        term: Term,
    ) -> Result<Self, EtsError> {
        // SAFETY: the caller retains the source term heap through this copy.
        let tuple = unsafe { term.tuple_ref() }.ok_or(EtsError::BadArg)?;
        let parts = tuple.iter().collect::<Vec<_>>();
        if Tid::from_term(*parts.first().ok_or(EtsError::BadArg)?) != Some(table.tid) {
            return Err(EtsError::BadArg);
        }
        let ordered = table.options.table_type == TableType::OrderedSet;
        if parts.len() != if ordered { 8 } else { 6 }
            || !program.matches_reference(parts[if ordered { 4 } else { 3 }])
        {
            return Err(EtsError::BadArg);
        }
        let limit = parts[if ordered { 3 } else { 2 }]
            .as_small()
            .ok_or(EtsError::BadArg)?;
        if limit <= 0 {
            return Err(EtsError::BadArg);
        }
        let mut heap = VecHeap::new();
        let program_ref = copy_term(parts[if ordered { 4 } else { 3 }], &mut heap)?;
        let (last_key, slot, rest, reverse) = if ordered {
            let reverse = parts[6].as_small().ok_or(EtsError::BadArg)?;
            if !matches!(reverse, 0 | 1) || parts[7].as_small() != Some(0) || parts[5] != Term::NIL
            {
                return Err(EtsError::BadArg);
            }
            (
                Some(copy_term(parts[1], &mut heap)?),
                0,
                Vec::new(),
                reverse == 1,
            )
        } else {
            let slot = parts[1].as_small().ok_or(EtsError::BadArg)?;
            let rest_len = parts[5].as_small().ok_or(EtsError::BadArg)?;
            if slot < -1 || rest_len < 0 {
                return Err(EtsError::BadArg);
            }
            let mut rest = Vec::new();
            let mut list = parts[4];
            while list != Term::NIL {
                // SAFETY: the caller retains the continuation term heap.
                let (head, tail) = unsafe { list.cons_ref() }.ok_or(EtsError::BadArg)?;
                rest.push(copy_term(head, &mut heap)?);
                list = tail;
            }
            if rest.len() != rest_len as usize {
                return Err(EtsError::BadArg);
            }
            (
                None,
                if slot == -1 {
                    usize::MAX
                } else {
                    slot as usize
                },
                rest,
                false,
            )
        };
        Ok(Self {
            tid: table.tid,
            program_ref,
            limit: limit as usize,
            reverse,
            last_key,
            slot,
            rest,
            started: true,
            _heap: heap,
        })
    }
}

impl From<TermError> for EtsError {
    fn from(value: TermError) -> Self {
        Self::Term(value)
    }
}

fn integer_value(term: Term) -> Option<BigInt> {
    if let Some(small) = term.as_small() {
        return Some(BigInt::from(small));
    }
    // SAFETY: callers retain the source heap while reading the boxed integer.
    unsafe { term.big_ref() }.map(|value| value.to_bigint())
}

/// Whether `bytes` holds only terms [`decode_ets_fast`] builds, as one complete term.
fn ets_fast_supported(bytes: &[u8]) -> bool {
    fn be(bytes: &[u8], pos: usize, count: usize) -> Option<usize> {
        bytes
            .get(pos..pos + count)?
            .iter()
            .try_fold(0_usize, |acc, byte| {
                acc.checked_mul(256)?.checked_add(usize::from(*byte))
            })
    }
    fn scan(bytes: &[u8], pos: &mut usize, depth: u32) -> Option<()> {
        if depth > 256 {
            return None;
        }
        let tag = *bytes.get(*pos)?;
        *pos += 1;
        match tag {
            97 => *pos += 1,
            98 => *pos += 4,
            70 => *pos += 8,
            b'I' => *pos += 2,
            b'K' => *pos += 3,
            106 => {}
            104 => {
                let arity = be(bytes, *pos, 1)?;
                *pos += 1;
                for _ in 0..arity {
                    scan(bytes, pos, depth + 1)?;
                }
            }
            105 => {
                let arity = be(bytes, *pos, 4)?;
                *pos += 4;
                for _ in 0..arity {
                    scan(bytes, pos, depth + 1)?;
                }
            }
            107 => {
                let len = be(bytes, *pos, 2)?;
                *pos += 2 + len;
            }
            108 => {
                let count = be(bytes, *pos, 4)?;
                *pos += 4;
                for _ in 0..count {
                    scan(bytes, pos, depth + 1)?;
                }
                scan(bytes, pos, depth + 1)?;
            }
            109 => {
                let len = be(bytes, *pos, 4)?;
                *pos += 4 + len;
            }
            88 => {
                // Local pid: marker, id, serial, zeroed creation.
                if *bytes.get(*pos)? != 106 {
                    return None;
                }
                *pos += 13;
            }
            90 => {
                let count = be(bytes, *pos, 2)?;
                if count != 3 || *bytes.get(*pos + 2)? != 106 {
                    return None;
                }
                *pos += 2 + 1 + 4 + 4 * count;
            }
            _ => return None,
        }
        (*pos <= bytes.len()).then_some(())
    }
    let mut pos = 0;
    scan(bytes, &mut pos, 0).is_some() && pos == bytes.len()
}

/// Build one ETS-external element straight on `dst`, for the common term shapes (integers,
/// atoms, floats, binaries, strings, lists, tuples, local pids and references). `bytes`
/// must have passed [`ets_fast_supported`].
// Port of erts/emulator/beam/external.c (dec_term, the arms for these tags with the
// ETS local-atom extension), OTP-29.1.1.
fn decode_ets_fast<H: HeapAlloc>(bytes: &[u8], dst: &mut H) -> Result<Term, EtsError> {
    fn be(bytes: &[u8], pos: &mut usize, count: usize) -> u64 {
        let value = bytes[*pos..*pos + count]
            .iter()
            .fold(0_u64, |acc, byte| (acc << 8) | u64::from(*byte));
        *pos += count;
        value
    }
    fn build<H: HeapAlloc>(bytes: &[u8], pos: &mut usize, dst: &mut H) -> Result<Term, EtsError> {
        let tag = bytes[*pos];
        *pos += 1;
        Ok(match tag {
            97 => Term::small(be(bytes, pos, 1) as i64).ok_or(EtsError::BadArg)?,
            98 => {
                let value = be(bytes, pos, 4) as u32 as i32;
                TermBuilder::new(dst).int_from_i64(i64::from(value))?
            }
            70 => {
                let bits = be(bytes, pos, 8);
                TermBuilder::new(dst).float(f64::from_bits(bits))?
            }
            b'I' => Term::atom(Atom(be(bytes, pos, 2) as u32)),
            b'K' => Term::atom(Atom(be(bytes, pos, 3) as u32)),
            106 => Term::NIL,
            104 | 105 => {
                let arity = be(bytes, pos, if tag == 104 { 1 } else { 4 }) as usize;
                let mut elements: smallvec::SmallVec<[Term; 16]> = smallvec::SmallVec::new();
                for _ in 0..arity {
                    elements.push(build(bytes, pos, dst)?);
                }
                TermBuilder::new(dst).tuple(&elements)?
            }
            107 => {
                let len = be(bytes, pos, 2) as usize;
                let chars = &bytes[*pos..*pos + len];
                *pos += len;
                TermBuilder::new(dst).list_from_iter(
                    chars
                        .iter()
                        .map(|&byte| Term::small(i64::from(byte)).unwrap()),
                )?
            }
            108 => {
                let count = be(bytes, pos, 4) as usize;
                let mut elements: smallvec::SmallVec<[Term; 16]> = smallvec::SmallVec::new();
                for _ in 0..count {
                    elements.push(build(bytes, pos, dst)?);
                }
                let mut list = build(bytes, pos, dst)?;
                let mut builder = TermBuilder::new(dst);
                for element in elements.into_iter().rev() {
                    list = builder.cons(element, list)?;
                }
                list
            }
            109 => {
                let len = be(bytes, pos, 4) as usize;
                let data = &bytes[*pos..*pos + len];
                *pos += len;
                TermBuilder::new(dst).binary(data)?
            }
            88 => {
                *pos += 1;
                let id = be(bytes, pos, 4) as u32;
                let serial = be(bytes, pos, 4) as u32;
                *pos += 4;
                Term::pid(id, serial).ok_or(EtsError::BadArg)?
            }
            _ => {
                // 90: local reference with three words.
                *pos += 2 + 1 + 4;
                let ids = [
                    be(bytes, pos, 4) as u32,
                    be(bytes, pos, 4) as u32,
                    be(bytes, pos, 4) as u32,
                ];
                TermBuilder::new(dst).local_ref(ids)?
            }
        })
    }
    let mut pos = 0;
    build(bytes, &mut pos, dst)
}

// Port of erts/emulator/beam/external.c and :810, OTP-29.1.1. The ETS
// external format replaces atom names with local atom-table references.
fn ets_external_atoms(bytes: &[u8], compress: bool) -> Result<Vec<u8>, EtsError> {
    fn take<'a>(bytes: &'a [u8], pos: &mut usize, count: usize) -> Result<&'a [u8], EtsError> {
        let end = pos.checked_add(count).ok_or(EtsError::BadArg)?;
        let value = bytes.get(*pos..end).ok_or(EtsError::BadArg)?;
        *pos = end;
        Ok(value)
    }
    fn number(bytes: &[u8], pos: &mut usize, count: usize) -> Result<usize, EtsError> {
        let mut value = 0_usize;
        for byte in take(bytes, pos, count)? {
            value = value
                .checked_mul(256)
                .and_then(|n| n.checked_add(usize::from(*byte)))
                .ok_or(EtsError::BadArg)?;
        }
        Ok(value)
    }
    fn atom(bytes: &[u8], pos: &mut usize, out: &mut Vec<u8>, tag: u8) -> Result<(), EtsError> {
        let len = if tag == 115 || tag == 119 {
            number(bytes, pos, 1)?
        } else {
            number(bytes, pos, 2)?
        };
        let name = take(bytes, pos, len)?;
        let text = std::str::from_utf8(name).map_err(|_| EtsError::BadArg)?;
        let id = global_atoms().intern(text).map_err(|_| EtsError::BadArg)?.0;
        if id < (1 << 16) {
            out.push(b'I');
            out.extend_from_slice(&(id as u16).to_be_bytes());
        } else if id < (1 << 24) {
            out.push(b'K');
            out.extend_from_slice(&id.to_be_bytes()[1..]);
        } else {
            return Err(EtsError::BadArg);
        }
        Ok(())
    }
    fn local_atom_end(bytes: &[u8], pos: usize) -> Option<usize> {
        let tag = *bytes.get(pos)?;
        let len_pos = pos + 1;
        let (len, data_pos) = if tag == 115 || tag == 119 {
            (usize::from(*bytes.get(len_pos)?), len_pos + 1)
        } else if tag == 100 || tag == 118 {
            (
                usize::from(u16::from_be_bytes(
                    bytes.get(len_pos..len_pos + 2)?.try_into().ok()?,
                )),
                len_pos + 2,
            )
        } else {
            return None;
        };
        (bytes.get(data_pos..data_pos + len)? == b"nonode@nohost").then_some(data_pos + len)
    }
    fn emit_local_atom(out: &mut Vec<u8>) {
        out.push(118);
        out.extend_from_slice(&13_u16.to_be_bytes());
        out.extend_from_slice(b"nonode@nohost");
    }
    fn walk(
        bytes: &[u8],
        pos: &mut usize,
        out: &mut Vec<u8>,
        compress: bool,
    ) -> Result<(), EtsError> {
        let tag = *take(bytes, pos, 1)?.first().unwrap();
        if compress && matches!(tag, 100 | 115 | 118 | 119) {
            return atom(bytes, pos, out, tag);
        }
        if !compress && matches!(tag, b'I' | b'K') {
            let id = number(bytes, pos, if tag == b'I' { 2 } else { 3 })? as u32;
            let name = global_atoms().text(Atom(id)).ok_or(EtsError::BadArg)?;
            out.push(118);
            out.extend_from_slice(&(name.len() as u16).to_be_bytes());
            out.extend_from_slice(name.as_bytes());
            return Ok(());
        }
        out.push(tag);
        match tag {
            97 => out.extend_from_slice(take(bytes, pos, 1)?),
            98 => out.extend_from_slice(take(bytes, pos, 4)?),
            70 => out.extend_from_slice(take(bytes, pos, 8)?),
            99 => out.extend_from_slice(take(bytes, pos, 31)?),
            100 | 115 | 118 | 119 => {
                let count = if tag == 115 || tag == 119 { 1 } else { 2 };
                let len_bytes = take(bytes, pos, count)?;
                out.extend_from_slice(len_bytes);
                let len = len_bytes
                    .iter()
                    .fold(0_usize, |a, b| a * 256 + usize::from(*b));
                out.extend_from_slice(take(bytes, pos, len)?);
            }
            104 => {
                let count = number(bytes, pos, 1)?;
                out.push(count as u8);
                for _ in 0..count {
                    walk(bytes, pos, out, compress)?;
                }
            }
            105 | 116 => {
                let count = number(bytes, pos, 4)?;
                let raw = &bytes[*pos - 4..*pos];
                out.extend_from_slice(raw);
                for _ in 0..count * (if tag == 116 { 2 } else { 1 }) {
                    walk(bytes, pos, out, compress)?;
                }
            }
            106 => {}
            107 => {
                let len = number(bytes, pos, 2)?;
                out.extend_from_slice(&bytes[*pos - 2..*pos]);
                out.extend_from_slice(take(bytes, pos, len)?);
            }
            108 => {
                let count = number(bytes, pos, 4)?;
                out.extend_from_slice(&bytes[*pos - 4..*pos]);
                for _ in 0..count {
                    walk(bytes, pos, out, compress)?;
                }
                walk(bytes, pos, out, compress)?;
            }
            109 => {
                let len = number(bytes, pos, 4)?;
                out.extend_from_slice(&bytes[*pos - 4..*pos]);
                out.extend_from_slice(take(bytes, pos, len)?);
            }
            110 => {
                let len = number(bytes, pos, 1)?;
                out.push(len as u8);
                out.extend_from_slice(take(bytes, pos, len + 1)?);
            }
            111 => {
                let len = number(bytes, pos, 4)?;
                out.extend_from_slice(&bytes[*pos - 4..*pos]);
                out.extend_from_slice(take(bytes, pos, len + 1)?);
            }
            77 => {
                let len = number(bytes, pos, 4)?;
                out.extend_from_slice(&bytes[*pos - 4..*pos]);
                out.extend_from_slice(take(bytes, pos, len + 1)?);
            }
            88 => {
                if compress && let Some(end) = local_atom_end(bytes, *pos) {
                    *pos = end;
                    out.push(106);
                    out.extend_from_slice(take(bytes, pos, 8)?);
                    take(bytes, pos, 4)?;
                    out.extend_from_slice(&[0; 4]);
                } else if !compress && bytes.get(*pos) == Some(&106) {
                    *pos += 1;
                    emit_local_atom(out);
                    out.extend_from_slice(take(bytes, pos, 12)?);
                } else {
                    walk(bytes, pos, out, compress)?;
                    out.extend_from_slice(take(bytes, pos, 12)?);
                }
            }
            120 => {
                if compress && let Some(end) = local_atom_end(bytes, *pos) {
                    *pos = end;
                    out.push(106);
                    out.extend_from_slice(take(bytes, pos, 8)?);
                    take(bytes, pos, 4)?;
                    out.extend_from_slice(&[0; 4]);
                } else if !compress && bytes.get(*pos) == Some(&106) {
                    *pos += 1;
                    emit_local_atom(out);
                    out.extend_from_slice(take(bytes, pos, 12)?);
                } else {
                    walk(bytes, pos, out, compress)?;
                    out.extend_from_slice(take(bytes, pos, 12)?);
                }
            }
            90 => {
                let n = number(bytes, pos, 2)?;
                let raw_count = &bytes[*pos - 2..*pos];
                out.extend_from_slice(raw_count);
                if compress && let Some(end) = local_atom_end(bytes, *pos) {
                    *pos = end;
                    out.push(106);
                    take(bytes, pos, 4)?;
                    out.extend_from_slice(&[0; 4]);
                    out.extend_from_slice(take(bytes, pos, 4 * n)?);
                } else if !compress && bytes.get(*pos) == Some(&106) {
                    *pos += 1;
                    emit_local_atom(out);
                    out.extend_from_slice(take(bytes, pos, 4 + 4 * n)?);
                } else {
                    walk(bytes, pos, out, compress)?;
                    out.extend_from_slice(take(bytes, pos, 4 + 4 * n)?);
                }
            }
            113 => {
                for _ in 0..2 {
                    walk(bytes, pos, out, compress)?;
                }
                walk(bytes, pos, out, compress)?;
            }
            112 => {
                let size = number(bytes, pos, 4)?;
                let size_pos = out.len();
                out.extend_from_slice(&[0; 4]);
                let start = *pos;
                out.extend_from_slice(take(bytes, pos, 1 + 16 + 4 + 4)?);
                walk(bytes, pos, out, compress)?;
                walk(bytes, pos, out, compress)?;
                walk(bytes, pos, out, compress)?;
                let free_count = u32::from_be_bytes(
                    bytes[start + 21..start + 25]
                        .try_into()
                        .map_err(|_| EtsError::BadArg)?,
                ) as usize;
                // NEW_FUN_EXT carries the creator PID before its free variables.
                walk(bytes, pos, out, compress)?;
                for _ in 0..free_count {
                    walk(bytes, pos, out, compress)?;
                }
                // Port of erts/emulator/beam/external.c, OTP-29.1.1.
                // NEW_FUN_EXT's size includes its own four-byte size field.
                if *pos - start + 4 != size {
                    return Err(EtsError::BadArg);
                }
                let new = (out.len() - size_pos) as u32;
                out[size_pos..size_pos + 4].copy_from_slice(&new.to_be_bytes());
            }
            67 => {
                let n = number(bytes, pos, 4)?;
                out.extend_from_slice(&bytes[*pos - 4..*pos]);
                out.extend_from_slice(take(bytes, pos, 1)?);
                for _ in 0..(n + 2) {
                    walk(bytes, pos, out, compress)?;
                }
                for _ in 0..n {
                    walk(bytes, pos, out, compress)?;
                }
            }
            121 => {
                let len = number(bytes, pos, 4)?;
                out.extend_from_slice(&bytes[*pos - 4..*pos]);
                out.extend_from_slice(take(bytes, pos, len)?);
            }
            _ => return Err(EtsError::BadArg),
        }
        Ok(())
    }
    let mut pos = 1;
    if bytes.first() != Some(&131) {
        return Err(EtsError::BadArg);
    }
    let mut out = vec![131];
    walk(bytes, &mut pos, &mut out, compress)?;
    if pos != bytes.len() {
        return Err(EtsError::BadArg);
    }
    Ok(out)
}

#[inline]
fn cmp_ordered_key(left: Term, right: Term) -> Ordering {
    match (left.as_small(), right.as_small()) {
        (Some(left), Some(right)) => left.cmp(&right),
        _ => cmp(left, right),
    }
}

pub(crate) struct Compressed {
    pub(crate) elements: Vec<Option<Vec<u8>>>,
    pub(crate) magic_refs: Vec<Option<Arc<MagicRef>>>,
    pub(crate) bytes: usize,
}

// `copy_term` asks for one allocation after computing `size_object`. An exact
// allocation avoids VecHeap's 1024-word minimum for each small ETS object.
struct ObjectHeap {
    // One allocation per object in the common case: the inline slot avoids a second malloc for
    // the vector holding it.
    words: smallvec::SmallVec<[Box<[u64]>; 1]>,
    off_heap: Option<Box<OffHeap>>,
}

impl Drop for ObjectHeap {
    fn drop(&mut self) {
        self.off_heap = None;
        for block in self.words.drain(..) {
            block_cache::give(block);
        }
    }
}

#[derive(Default)]
pub(crate) struct OffHeap {
    // Per-object DbTerm.first_oh; dropping its tokens ports db_free_term cleanup.
    pub(crate) first_oh: usize,
    pub(crate) binary_refs: Vec<arinsal_term::OwnedBinaryRef>,
    pub(crate) external: Vec<Arc<ExternalBinary>>,
    pub(crate) nodes: Vec<Arc<TermNode>>,
    pub(crate) magic: Vec<Arc<MagicRef>>,
}

impl ObjectHeap {
    fn new() -> Self {
        Self {
            words: smallvec::SmallVec::new(),
            off_heap: None,
        }
    }

    fn off_heap(&mut self) -> &mut OffHeap {
        self.off_heap
            .get_or_insert_with(|| Box::new(OffHeap::default()))
    }

    /// Link the off-heap object at `address` (three words) at the head of the DbTerm's
    /// `first_oh` chain.
    fn chain_first_oh(&mut self, address: usize) -> Result<(), TermError> {
        let Some((allocation_index, word_index)) =
            self.words.iter().enumerate().find_map(|(i, allocation)| {
                let start = allocation.as_ptr() as usize;
                let end = start.checked_add(allocation.len().checked_mul(8)?)?;
                (address >= start && address.checked_add(24).is_some_and(|tail| tail <= end))
                    .then(|| (i, (address - start) / 8))
            })
        else {
            return Err(TermError::BadArg);
        };
        let first_oh = self
            .off_heap
            .as_ref()
            .map_or(0, |off_heap| off_heap.first_oh);
        self.words[allocation_index][word_index + 2] = first_oh as u64;
        self.off_heap().first_oh = address;
        Ok(())
    }
}

impl HeapAlloc for ObjectHeap {
    fn alloc(&mut self, words: usize) -> Option<*mut u64> {
        let mut allocation = block_cache::take(words);
        let ptr = allocation.as_mut_ptr();
        self.words.push(allocation);
        Some(ptr)
    }

    fn retain_binary(&mut self, binary: Arc<arinsal_term::RefcBinary>) {
        drop(binary);
    }
    // Port of erts/emulator/beam/erl_db_util.c (db_store_term), OTP-29.1.1.
    fn link_bin_ref(
        &mut self,
        bin_ref: *mut u64,
        _writable: bool,
        _overhead_words: u64,
        owner: Option<arinsal_term::OwnedBinaryRef>,
    ) -> Result<(), TermError> {
        self.chain_first_oh(bin_ref as usize)?;
        let off_heap = self.off_heap();
        if let Some(mut owner) = owner {
            owner.attach_to_bin_ref(bin_ref);
            off_heap.binary_refs.push(owner);
        }
        Ok(())
    }
    fn retain_writable_binary(&mut self, binary: Arc<WritableBinary>) -> Result<(), TermError> {
        drop(binary);
        Ok(())
    }
    fn supports_writable_binary(&self) -> bool {
        true
    }
    fn link_external_binary(
        &mut self,
        bin_ref: *mut u64,
        binary: Arc<ExternalBinary>,
    ) -> Result<(), TermError> {
        let _ = self.chain_first_oh(bin_ref as usize);
        self.off_heap().external.push(binary);
        Ok(())
    }
    fn supports_external_binary(&self) -> bool {
        true
    }
    // The DbTerm's first_oh chain links the thing; the token stands in for the counted
    // reference the thing holds until db_free_term.
    fn link_node(&mut self, thing: *mut u64, node: Arc<TermNode>) {
        let _ = self.chain_first_oh(thing as usize);
        self.off_heap().nodes.push(node);
    }
    // The DbTerm's first_oh chain links the thing; the token stands in for the counted
    // reference the thing holds until db_free_term.
    fn link_magic_ref(&mut self, thing: *mut u64, owner: Arc<MagicRef>) -> Result<(), TermError> {
        self.chain_first_oh(thing as usize)?;
        self.off_heap().magic.push(owner);
        Ok(())
    }
    fn supports_magic(&self) -> bool {
        true
    }
}

impl StoredTerm {
    fn immediate_pair(term: Term) -> Option<[Term; 2]> {
        // SAFETY: the caller retains the source heap through the copy or update.
        let tuple = unsafe { term.tuple_ref() }?;
        if tuple.len() != 2 {
            return None;
        }
        let pair = [tuple.get(0)?, tuple.get(1)?];
        pair.iter().all(|term| !term.is_pointer()).then_some(pair)
    }

    fn copy(term: Term) -> Result<DbTerm, EtsError> {
        Self::copy_heap(term)
    }

    fn copy_for_table(
        term: Term,
        compressed: bool,
        keypos: usize,
        prefix_words: usize,
    ) -> Result<DbTerm, EtsError> {
        // Port of erts/emulator/beam/erl_db_util.c (db_store_term), OTP-29.1.1:
        // even immediate two-element objects have a table-owned tuple in their DbTerm.
        Self::copy_heap_for_table(term, compressed, keypos, prefix_words)
    }

    // Port of erts/emulator/beam/erl_db_util.c (db_store_term), OTP-29.1.1: the term is sized,
    // one block holds the DbTerm header and the words, and the term is copied into the block.
    fn copy_heap_for_table(
        term: Term,
        compressed: bool,
        keypos: usize,
        prefix_words: usize,
    ) -> Result<DbTerm, EtsError> {
        let object = term;
        if !compressed {
            // Port of erts/emulator/beam/erl_db_util.c (db_store_term, a tuple of immediates):
            // the block is exactly the tuple, so it is neither sized nor scanned.
            // SAFETY: the caller holds the source heap live for this call.
            let flat = unsafe { term.tuple_ref() }
                .filter(|tuple| !tuple.is_empty() && tuple.iter().all(|e| !e.is_pointer()))
                .map(|tuple| tuple.len() + 1);
            if let Some(size) = flat {
                let mut block = dbterm::build_block(size, |heap| {
                    arinsal_term::copy_flat_tuple(term, heap)
                        .unwrap_or(Err(TermError::BadArg))
                        .map_err(EtsError::from)
                })?;
                block.db_size_words = prefix_words + 2 + size;
                block.term_size_words = size;
                block.shallow = true;
                return Ok(block);
            }
            // The object is sized once; the same size serves the accounting and the copy.
            let size = arinsal_term::size_object(term);
            let mut block = dbterm::build_block(size, |heap| {
                arinsal_term::copy_struct(term, heap, size).map_err(EtsError::from)
            })?;
            block.db_size_words = prefix_words + 2 + size;
            block.term_size_words = size;
            block.shallow = block.off_heap.is_none()
                && arinsal_term::shallow_copyable(block.term, &block.words);
            return Ok(block);
        }
        // Port of erts/emulator/beam/erl_db_util.c (copy_to_comp), OTP-29.1.1.
        let tuple = term_sequence(term).ok_or(EtsError::BadArg)?;
        let eligible = |index: usize, element: Term| {
            index != keypos - 1 && element.is_pointer() && element.classify() != TermKind::Bitstring
        };
        // The block holds the stored tuple and the copies of the uncompressed elements; a magic
        // reference is copied once more for the owner link, as the heap accounting always did.
        let nwords = 1
            + tuple.len()
            + tuple
                .iter()
                .enumerate()
                .map(|(index, &element)| {
                    if !eligible(index, element) || element.is_magic_ref() {
                        arinsal_term::size_object(element)
                    } else {
                        0
                    }
                })
                .sum::<usize>();
        let mut compressed_elements = Vec::new();
        let mut compressed_magic_refs = Vec::new();
        let mut compressed_bytes = 0;
        let mut block = dbterm::build_block(nwords, |heap| {
            let mut elements = Vec::with_capacity(tuple.len());
            for (index, &element) in tuple.iter().enumerate() {
                if eligible(index, element) {
                    if element.is_magic_ref() {
                        // Compressed bytes carry the reference identity, while ETS must retain
                        // its magic owner until the stored row is deleted.
                        copy_term(element, heap)?;
                    }
                    compressed_magic_refs.push(element.magic_owner());
                    let owned = arinsal_term::to_owned(element)?;
                    let ext = arinsal_etf::encode(&owned, arinsal_etf::EncodeOptions::default());
                    let mut ext = ets_external_atoms(&ext, true)?;
                    ext.remove(0);
                    compressed_bytes += ext.len();
                    compressed_elements.push(Some(ext));
                    elements.push(Term::NIL);
                } else {
                    compressed_magic_refs.push(None);
                    // Port of erts/emulator/beam/erl_db_util.c,
                    // OTP-29.1.1: ETS external encoding keeps binary refs on
                    // the object's off-heap chain.
                    compressed_elements.push(None);
                    elements.push(copy_term(element, heap)?);
                }
            }
            Ok(TermBuilder::new(heap).tuple(&elements)?)
        })?;
        // A compressed object stores a placeholder tuple; its copy size is that of the stored
        // term, not of the uncompressed source.
        let term_size_words = arinsal_term::size_object(block.term);
        block.shallow = block.off_heap.is_none()
            && nwords == term_size_words
            && arinsal_term::shallow_copyable(block.term, &block.words);
        block.term_size_words = term_size_words;
        block.db_size_words =
            Self::accounted_words(object, keypos, true, prefix_words, compressed_bytes);
        block.compressed = Some(Box::new(Compressed {
            elements: compressed_elements,
            magic_refs: compressed_magic_refs,
            bytes: compressed_bytes,
        }));
        Ok(block)
    }

    fn copy_heap(term: Term) -> Result<DbTerm, EtsError> {
        Self::copy_heap_for_table(term, false, 1, 1)
    }

    pub(crate) fn copy_stored(&self) -> Result<DbTerm, EtsError> {
        if self.compressed_elements().iter().any(Option::is_some) {
            let mut copy = Self::copy_heap(self.term)?;
            copy.compressed = self.compressed.as_ref().map(|c| {
                Box::new(Compressed {
                    elements: c.elements.clone(),
                    magic_refs: c.magic_refs.clone(),
                    bytes: c.bytes,
                })
            });
            copy.db_size_words = self.db_size_words;
            return Ok(copy);
        }
        let size = self.term_size_words;
        let mut copy = dbterm::build_block(size, |heap| {
            arinsal_term::copy_struct(self.term, heap, size).map_err(EtsError::from)
        })?;
        copy.shallow =
            copy.off_heap.is_none() && arinsal_term::shallow_copyable(copy.term, &copy.words);
        copy.db_size_words = self.db_size_words;
        copy.term_size_words = size;
        copy.order = self.order;
        copy.group_order = self.group_order;
        copy.hvalue = self.hvalue;
        Ok(copy)
    }

    pub(crate) fn exact_eq_input(&self, other: Term) -> bool {
        self.exact_eq_term(other)
    }

    fn raw_term(&self) -> Option<Term> {
        if self.compressed_elements().iter().any(Option::is_some) {
            None
        } else {
            Some(self.term)
        }
    }

    fn arity(&self) -> usize {
        term_sequence(self.term).map_or(0, |tuple| tuple.len())
    }

    pub(crate) fn compressed_elements(&self) -> &[Option<Vec<u8>>] {
        self.compressed.as_ref().map_or(&[], |c| &c.elements)
    }

    fn compressed_magic_refs(&self) -> &[Option<Arc<MagicRef>>] {
        self.compressed.as_ref().map_or(&[], |c| &c.magic_refs)
    }

    pub(crate) fn key(&self, keypos: usize) -> Term {
        // SAFETY: this object retains the heap containing its tuple.
        unsafe { self.term.tuple_ref().unwrap().get(keypos - 1).unwrap() }
    }

    /// Overwrite the immediate element at zero-based `index` with another immediate, as
    /// erts writes a counter into the stored tuple when its size does not change.
    ///
    /// Port of erts/emulator/beam/erl_db_util.c (db_do_update_element, the immediate
    /// case), OTP-29.1.1.
    fn set_immediate_element(&mut self, index: usize, value: Term) -> bool {
        if value.is_pointer() || self.tuple_element(index).is_none_or(Term::is_pointer) {
            return false;
        }
        if !self.compressed_elements().is_empty() || !self.term.is_pointer() {
            return false;
        }
        // The tuple lives in this object's own block: find its word by address.
        let header = (self.term.tagged_word() & !7) as usize;
        let word = header + (index + 1) * 8;
        let start = self.words.as_ptr() as usize;
        if (start..start + self.words.len() * 8).contains(&word) {
            self.words[(word - start) / 8] = value.tagged_word();
            return true;
        }
        false
    }

    fn tuple_element(&self, index: usize) -> Option<Term> {
        // SAFETY: this object retains the heap containing its tuple.
        unsafe { self.term.tuple_ref() }.and_then(|tuple| tuple.get(index))
    }

    pub(crate) fn copy_element_out<H: HeapAlloc>(
        &self,
        index: usize,
        dst: &mut H,
    ) -> Result<Term, EtsError> {
        if let Some(bytes) = self
            .compressed_elements()
            .get(index)
            .and_then(Option::as_ref)
        {
            if let Some(owner) = self
                .compressed_magic_refs()
                .get(index)
                .and_then(Option::as_ref)
            {
                return Ok(TermBuilder::new(dst).magic_ref(owner.clone())?);
            }
            let mut ext = Vec::with_capacity(bytes.len() + 1);
            ext.push(131);
            ext.extend_from_slice(bytes);
            let ext = ets_external_atoms(&ext, false)?;
            let owned = arinsal_etf::decode(&ext).map_err(|_| EtsError::BadArg)?;
            return Ok(arinsal_term::from_owned(&owned, dst)?);
        }
        Ok(copy_term(
            self.tuple_element(index).ok_or(EtsError::BadArg)?,
            dst,
        )?)
    }

    fn exact_eq_term(&self, other: Term) -> bool {
        // SAFETY: `self` owns the tuple heap for the duration of this comparison.
        let Some(left) = term_sequence(self.term) else {
            return false;
        };
        let Some(right) = term_sequence(other) else {
            return false;
        };
        left.len() == right.len()
            && left
                .iter()
                .zip(right.iter())
                .enumerate()
                .all(|(index, (stored, value))| {
                    if self
                        .compressed_elements()
                        .get(index)
                        .and_then(Option::as_ref)
                        .is_some()
                    {
                        arinsal_term::to_owned(*value)
                            .ok()
                            .map(|value| {
                                let encoded = arinsal_etf::encode(
                                    &value,
                                    arinsal_etf::EncodeOptions::default(),
                                );
                                let Ok(mut bytes) = ets_external_atoms(&encoded, true) else {
                                    return false;
                                };
                                bytes.remove(0);
                                self.compressed_elements()[index].as_ref() == Some(&bytes)
                            })
                            .unwrap_or(false)
                    } else {
                        exact_eq(*stored, *value)
                    }
                })
    }

    fn exact_eq_stored(&self, other: &StoredTerm) -> bool {
        if self.compressed_elements().iter().any(Option::is_some)
            || other.compressed_elements().iter().any(Option::is_some)
        {
            return self.compressed_elements() == other.compressed_elements()
                && self.copy_equal_uncompressed(other);
        }
        exact_eq(self.term, other.term)
    }

    fn copy_equal_uncompressed(&self, other: &StoredTerm) -> bool {
        // SAFETY: each StoredTerm owns the heap containing its tuple.
        let Some(left) = term_sequence(self.term) else {
            return false;
        };
        let Some(right) = term_sequence(other.term) else {
            return false;
        };
        left.len() == right.len()
            && left
                .iter()
                .zip(right.iter())
                .enumerate()
                .all(|(i, (a, b))| {
                    if self
                        .compressed_elements()
                        .get(i)
                        .and_then(Option::as_ref)
                        .is_some()
                    {
                        self.compressed_elements()[i]
                            == other.compressed_elements().get(i).cloned().unwrap_or(None)
                    } else {
                        exact_eq(*a, *b)
                    }
                })
    }

    fn copy_out<H: HeapAlloc>(&self, dst: &mut H) -> Result<Term, EtsError> {
        if self.shallow && !self.compressed_elements().iter().any(Option::is_some) {
            // Port of erts/emulator/beam/erl_db_util.h (db_copy_object_from_ets): the stored
            // block is copied word by word with the pointers offset.
            return Ok(arinsal_term::copy_shallow(self.term, &self.words, dst)?);
        }
        if !self.compressed_elements().iter().any(Option::is_some) {
            // Port of erts/emulator/beam/erl_db_util.h:425 (db_copy_object_from_ets):
            // DbTerm.size is already known, so do not size the object again before copying it.
            return Ok(arinsal_term::copy_struct(
                self.term,
                dst,
                self.term_size_words,
            )?);
        }
        // SAFETY: this object owns the heap containing its tuple.
        let tuple = term_sequence(self.term).ok_or(EtsError::BadArg)?;
        let mut elements = Vec::with_capacity(tuple.len());
        for (index, element) in tuple.into_iter().enumerate() {
            if let Some(bytes) = self
                .compressed_elements()
                .get(index)
                .and_then(Option::as_ref)
            {
                if let Some(owner) = self
                    .compressed_magic_refs()
                    .get(index)
                    .and_then(Option::as_ref)
                {
                    elements.push(TermBuilder::new(dst).magic_ref(owner.clone())?);
                    continue;
                }
                if ets_fast_supported(bytes) {
                    elements.push(decode_ets_fast(bytes, dst)?);
                    continue;
                }
                let mut ext = Vec::with_capacity(bytes.len() + 1);
                ext.push(131);
                ext.extend_from_slice(bytes);
                let ext = ets_external_atoms(&ext, false)?;
                let owned = arinsal_etf::decode(&ext).map_err(|_| EtsError::BadArg)?;
                elements.push(arinsal_term::from_owned(&owned, dst)?);
            } else {
                elements.push(copy_term(element, dst)?);
            }
        }
        Ok(TermBuilder::new(dst).tuple(&elements)?)
    }

    fn accounted_words(
        term: Term,
        keypos: usize,
        compressed: bool,
        prefix_words: usize,
        compressed_bytes: usize,
    ) -> usize {
        if !compressed {
            return prefix_words + 2 + arinsal_term::size_object(term);
        }
        // SAFETY: callers validate the object tuple and retain its source heap.
        let tuple = term_sequence(term).expect("ETS object is a tuple");
        let key_words =
            arinsal_term::size_object(*tuple.get(keypos - 1).expect("validated key position"));
        let bytes = (prefix_words + 2 + tuple.len() + 2) * 8 + key_words * 8 + compressed_bytes;
        bytes.div_ceil(8)
    }

    pub(crate) fn refc_binaries<H: HeapAlloc>(&self, dst: &mut H) -> Result<Vec<Term>, EtsError> {
        // Port of erts/emulator/beam/erl_bif_info.c (`erts_bld_bin_list`),
        // OTP-29.1.1: report each BinRef from this DbTerm's first_oh chain.
        let Some(off_heap) = self.off_heap.as_ref() else {
            return Ok(Vec::new());
        };
        let mut terms = Vec::with_capacity(off_heap.binary_refs.len());
        for binary in off_heap.binary_refs.iter().rev() {
            let mut builder = TermBuilder::new(dst);
            let address = builder.int_from_i128(binary.header_ptr() as usize as i128)?;
            let size = builder.int_from_i128(binary.capacity().ok_or(EtsError::BadArg)? as i128)?;
            let refc = builder.int_from_i128(binary.ref_count().ok_or(EtsError::BadArg)? as i128)?;
            terms.push(builder.tuple(&[address, size, refc])?);
        }
        Ok(terms)
    }

    fn term_for_match<H: HeapAlloc>(&self, scratch: &mut H) -> Result<Term, EtsError> {
        self.copy_out(scratch)
    }

    fn term_for_filter<H: HeapAlloc>(&self, scratch: &mut H) -> Result<Term, EtsError> {
        self.term_for_filter_with_size(scratch)
            .map(|(term, _size)| term)
    }

    fn term_for_filter_with_size<H: HeapAlloc>(
        &self,
        scratch: &mut H,
    ) -> Result<(Term, Option<match_spec::KnownObject<'_>>), EtsError> {
        if !self.compressed_elements().iter().any(Option::is_some) {
            return Ok((
                self.term,
                Some(match_spec::KnownObject {
                    size: self.term_size_words,
                    block: self.shallow.then(|| &self.words[..]),
                }),
            ));
        }
        Ok((self.term_for_match(scratch)?, None))
    }
}

fn key_of(object: Term, keypos: usize) -> Result<Term, EtsError> {
    // SAFETY: the caller holds the source heap live throughout this call.
    let tuple = unsafe { object.tuple_ref() }.ok_or(EtsError::BadArg)?;
    tuple.get(keypos - 1).ok_or(EtsError::BadArg)
}

/// Next value of a small-integer counter after one operation, when neither the operands nor
/// the result need a bignum.
fn small_counter_step(old: Term, operation: &BigCounterOp) -> Option<i64> {
    let old = old.as_small()?;
    let increment = operation.increment.to_i64()?;
    let mut next = old.checked_add(increment)?;
    if let Some((threshold, reset)) = &operation.threshold {
        let threshold = threshold.to_i64()?;
        if (increment >= 0 && next > threshold) || (increment < 0 && next < threshold) {
            next = reset.to_i64()?;
        }
    }
    Some(next)
}

fn update_counter_object_in_place(
    object: &mut StoredTerm,
    keypos: usize,
    operations: &[CounterOp],
) -> Option<smallvec::SmallVec<[Term; 4]>> {
    if !object.compressed_elements().is_empty() {
        return None;
    }
    let mut updated: smallvec::SmallVec<[(usize, i64); 4]> = smallvec::SmallVec::new();
    let mut results = smallvec::SmallVec::new();
    for operation in operations {
        if operation.position == keypos || operation.position == 0 {
            return None;
        }
        let index = operation.position - 1;
        let old = match updated.iter().rev().find(|(at, _)| *at == index) {
            Some(&(_, value)) => value,
            None => object.tuple_element(index)?.as_small()?,
        };
        let mut next = old.checked_add(operation.increment)?;
        if let Some((threshold, reset)) = operation.threshold
            && (if operation.increment < 0 {
                next < threshold
            } else {
                next > threshold
            })
        {
            next = reset;
        }
        results.push(Term::small(next)?);
        updated.push((index, next));
    }
    for (index, value) in updated {
        if !object.set_immediate_element(index, Term::small(value)?) {
            debug_assert!(false, "verified counter element is not writable in place");
            return None;
        }
    }
    Some(results)
}

fn global_true() -> Atom {
    global_atoms().intern("true").unwrap()
}

#[cfg(any())]
mod _obsolete_ordered_treap {
    use super::*;
    struct Node {
        object: DbTerm,
        priority: u64,
        size: usize,
        left: Option<Box<Node>>,
        right: Option<Box<Node>>,
    }

    impl Node {
        fn new(object: DbTerm, keypos: usize) -> Box<Self> {
            let priority = internal_hash(object.key(keypos));
            Box::new(Self {
                object,
                priority,
                size: 1,
                left: None,
                right: None,
            })
        }

        fn count(node: &Option<Box<Self>>) -> usize {
            node.as_ref().map_or(0, |node| node.size)
        }

        fn refresh(&mut self) {
            self.size = 1 + Self::count(&self.left) + Self::count(&self.right);
        }

        fn rotate_right(mut root: Box<Self>) -> Box<Self> {
            let mut new_root = root.left.take().unwrap();
            root.left = new_root.right.take();
            root.refresh();
            new_root.right = Some(root);
            new_root.refresh();
            new_root
        }

        fn rotate_left(mut root: Box<Self>) -> Box<Self> {
            let mut new_root = root.right.take().unwrap();
            root.right = new_root.left.take();
            root.refresh();
            new_root.left = Some(root);
            new_root.refresh();
            new_root
        }

        fn insert(root: Option<Box<Self>>, object: DbTerm, keypos: usize) -> Box<Self> {
            let Some(mut root) = root else {
                return Self::new(object, keypos);
            };
            match cmp(object.key(keypos), root.object.key(keypos)) {
                Ordering::Equal => root.object = object,
                Ordering::Less => {
                    root.left = Some(Self::insert(root.left.take(), object, keypos));
                    if root.left.as_ref().unwrap().priority < root.priority {
                        root = Self::rotate_right(root);
                    }
                }
                Ordering::Greater => {
                    root.right = Some(Self::insert(root.right.take(), object, keypos));
                    if root.right.as_ref().unwrap().priority < root.priority {
                        root = Self::rotate_left(root);
                    }
                }
            }
            root.refresh();
            root
        }

        fn merge(left: Option<Box<Self>>, right: Option<Box<Self>>) -> Option<Box<Self>> {
            match (left, right) {
                (None, other) | (other, None) => other,
                (Some(mut left), Some(mut right)) => {
                    if left.priority <= right.priority {
                        left.right = Self::merge(left.right.take(), Some(right));
                        left.refresh();
                        Some(left)
                    } else {
                        right.left = Self::merge(Some(left), right.left.take());
                        right.refresh();
                        Some(right)
                    }
                }
            }
        }

        fn remove(root: Option<Box<Self>>, key: Term, keypos: usize) -> Option<Box<Self>> {
            let mut root = root?;
            match cmp(key, root.object.key(keypos)) {
                Ordering::Equal => Self::merge(root.left.take(), root.right.take()),
                Ordering::Less => {
                    root.left = Self::remove(root.left.take(), key, keypos);
                    root.refresh();
                    Some(root)
                }
                Ordering::Greater => {
                    root.right = Self::remove(root.right.take(), key, keypos);
                    root.refresh();
                    Some(root)
                }
            }
        }

        fn get(root: &Option<Box<Self>>, key: Term, keypos: usize) -> Option<&StoredTerm> {
            let mut node = root.as_deref();
            while let Some(current) = node {
                match cmp(key, current.object.key(keypos)) {
                    Ordering::Equal => return Some(&current.object),
                    Ordering::Less => node = current.left.as_deref(),
                    Ordering::Greater => node = current.right.as_deref(),
                }
            }
            None
        }

        fn nth(root: &Option<Box<Self>>, index: usize) -> Option<&StoredTerm> {
            let mut node = root.as_deref()?;
            let mut index = index;
            loop {
                let left = Self::count(&node.left);
                match index.cmp(&left) {
                    Ordering::Less => node = node.left.as_deref()?,
                    Ordering::Equal => return Some(&node.object),
                    Ordering::Greater => {
                        index -= left + 1;
                        node = node.right.as_deref()?;
                    }
                }
            }
        }

        fn walk<'a>(root: &'a Option<Box<Self>>, out: &mut Vec<&'a DbTerm>) {
            if let Some(node) = root {
                Self::walk(&node.left, out);
                out.push(&node.object);
                Self::walk(&node.right, out);
            }
        }

        fn scan_after<F>(
            root: &Option<Box<Self>>,
            cursor: Option<Term>,
            reverse: bool,
            keypos: usize,
            visit: &mut F,
        ) -> Result<bool, EtsError>
        where
            F: FnMut(&StoredTerm) -> Result<bool, EtsError>,
        {
            let Some(node) = root else {
                return Ok(false);
            };
            if let Some(cursor) = cursor {
                let order = cmp(node.object.key(keypos), cursor);
                if !reverse && order != Ordering::Greater {
                    return Self::scan_after(&node.right, Some(cursor), reverse, keypos, visit);
                }
                if reverse && order != Ordering::Less {
                    return Self::scan_after(&node.left, Some(cursor), reverse, keypos, visit);
                }
            }
            let (first, second) = if reverse {
                (&node.right, &node.left)
            } else {
                (&node.left, &node.right)
            };
            if Self::scan_after(first, cursor, reverse, keypos, visit)? {
                return Ok(true);
            }
            if visit(&node.object)? {
                return Ok(true);
            }
            Self::scan_after(second, cursor, reverse, keypos, visit)
        }

        fn select_range<H: HeapAlloc>(
            root: &Option<Box<Self>>,
            state: &mut RangeSelection<'_, '_, H>,
        ) -> Result<(), EtsError> {
            let Some(node) = root else {
                return Ok(());
            };
            let key = node.object.key(state.keypos);
            let below = state.bounds.is_below(key);
            let above = state.bounds.is_above(key);
            let first = if state.reverse {
                &node.right
            } else {
                &node.left
            };
            let second = if state.reverse {
                &node.left
            } else {
                &node.right
            };
            let visit_first = if state.reverse { !above } else { !below };
            let visit_second = if state.reverse { !below } else { !above };
            if visit_first {
                Self::select_range(first, state)?;
            }
            if state.out.len() >= state.limit {
                return Ok(());
            }
            if !below && !above {
                let term = node.object.term_for_filter(state.dst)?;
                if let Some(result) = state.runner.run(term, state.dst)? {
                    state.out.push(result);
                }
            }
            if state.out.len() >= state.limit {
                return Ok(());
            }
            if visit_second {
                Self::select_range(second, state)?;
            }
            Ok(())
        }
    }
}

#[cfg(any())]
mod _obsolete_hashmap_store {
    use super::*;
    struct HashStorage {
        // The hash is for distribution only. Exact key equality resolves collisions.
        buckets: HashMap<u64, Vec<DbTerm>, BuildHasherDefault<PrehashedU64>>,
        next_order: u64,
        size: usize,
        size_bias: isize,
        nactive: usize,
        deleted: Vec<DbTerm>,
    }

    impl HashStorage {
        fn slot_index(&self, hash: u64) -> usize {
            // Port of erl_db_hash.c (hash_to_ix), OTP-29.1.1.
            let mask = self.nactive.next_power_of_two() - 1;
            let index = ((hash >> 1) as usize) & mask;
            if index >= self.nactive {
                index & (mask >> 1)
            } else {
                index
            }
        }

        fn ordered(&self, keypos: usize) -> Vec<&StoredTerm> {
            let mut objects: Vec<_> = self
                .buckets
                .values()
                .flat_map(|bucket| bucket.iter())
                .collect();
            self.sort_ordered(&mut objects, keypos);
            objects
        }

        fn ordered_with_deleted(&self, keypos: usize) -> Vec<&StoredTerm> {
            let mut objects: Vec<_> = self
                .buckets
                .values()
                .flat_map(|bucket| bucket.iter())
                .chain(&self.deleted)
                .collect();
            self.sort_ordered(&mut objects, keypos);
            objects
        }

        fn sort_ordered(&self, objects: &mut Vec<&StoredTerm>, keypos: usize) {
            objects.sort_unstable_by_key(|object| {
                (
                    self.slot_index(internal_hash(object.key(keypos))),
                    object.group_order,
                    u64::MAX - object.order,
                )
            });
        }

        fn objects(&self, key: Term) -> &[DbTerm] {
            self.objects_hash(internal_hash(key))
        }

        fn objects_hash(&self, hash: u64) -> &[DbTerm] {
            self.buckets.get(&hash).map(Vec::as_slice).unwrap_or(&[])
        }

        fn shrink_after_delete(&mut self, keypos: usize) {
            // Port of erts/emulator/beam/erl_db_hash.c,3743 (calc_shrink_limit,
            // shrink), OTP-29.1.1. OTP joins at most five buckets per delete.
            for _ in 0..5 {
                let nslots = if self.nactive <= 256 {
                    256
                } else {
                    256 + (self.nactive - 256).div_ceil(2048) * 2048
                };
                if nslots < 4352 || self.size >= (nslots - 2048) / 2 || self.nactive <= 256 {
                    break;
                }
                let source = self.nactive - 1;
                let destination = source & ((self.nactive.next_power_of_two() - 1) >> 1);
                let ordered = self.ordered(keypos);
                let mut ranks = HashMap::new();
                let mut rank = 0_u64;
                for slot in [source, destination] {
                    let mut last_group = None;
                    for object in ordered
                        .iter()
                        .copied()
                        .filter(|object| self.slot_index(internal_hash(object.key(keypos))) == slot)
                    {
                        if last_group != Some(object.group_order) {
                            rank += 1;
                            last_group = Some(object.group_order);
                        }
                        ranks.insert(object.order, rank);
                    }
                }
                for bucket in self.buckets.values_mut() {
                    for object in bucket {
                        if let Some(&new_rank) = ranks.get(&object.order) {
                            object.group_order = new_rank;
                        }
                    }
                }
                self.nactive -= 1;
            }
        }
    }
}

pub(crate) struct RangeSelection<'a, 'program, H: HeapAlloc> {
    pub(crate) keypos: usize,
    pub(crate) bounds: match_spec::KeyBounds,
    pub(crate) runner: &'a mut match_spec::MatchRunner<'program>,
    pub(crate) reverse: bool,
    pub(crate) limit: usize,
    pub(crate) dst: &'a mut H,
    pub(crate) out: Vec<Term>,
}

struct ConstantRangeSelection<'a, H: HeapAlloc> {
    keypos: usize,
    bounds: match_spec::KeyBounds,
    result: Term,
    reverse: bool,
    limit: usize,
    dst: &'a mut H,
    out: Vec<Term>,
}

fn select_range_constant<H: HeapAlloc>(
    root: &dbterm::Link,
    state: &mut ConstantRangeSelection<'_, H>,
) -> Result<(), EtsError> {
    let Some(node) = root else {
        return Ok(());
    };
    let key = node.key(state.keypos);
    let below = state.bounds.is_below(key);
    let above = state.bounds.is_above(key);
    let (first, second) = if state.reverse {
        (&node.right, &node.next)
    } else {
        (&node.next, &node.right)
    };
    if if state.reverse { !above } else { !below } {
        select_range_constant(first, state)?;
    }
    if state.out.len() >= state.limit {
        return Ok(());
    }
    if !below && !above {
        state.out.push(copy_term(state.result, state.dst)?);
    }
    if state.out.len() >= state.limit {
        return Ok(());
    }
    if if state.reverse { !below } else { !above } {
        select_range_constant(second, state)?;
    }
    Ok(())
}

enum Storage {
    Hash(HashStorage),
    Ordered(TreeRoot),
    CATree(CATree),
}

/// An object already copied into table-owned storage, ready for `Table::insert_prepared`.
pub struct PreparedObject {
    stored: DbTerm,
    hash: u64,
}

/// One ETS table, with table-owned object heaps.
pub struct Table {
    /// Stable table identifier.
    pub tid: Tid,
    /// The magic reference of this table (`tb->common.btid`), set once the table is registered.
    btid: std::sync::OnceLock<std::sync::Weak<arinsal_term::MagicRef>>,
    /// Creation options and owner metadata.
    pub options: TableOptions,
    storage: Storage,
    fixed: usize,
    fixed_system_time: Option<DbTerm>,
    fixed_monotonic_time: Option<DbTerm>,
    fixed_processes: Vec<(DbTerm, usize)>,
    _heir_data: Option<DbTerm>,
    counter_results: Option<Box<VecHeap>>,
    /// Set once the registry has detached the table (`ets:delete/1`); cached handles to it
    /// must then fail like a deleted table.
    detached: bool,
    /// The operation other processes must help finish before they may use the table
    /// (erts `DB_BUSY` with `continuation_ctx`, or a trapping `delete_all_objects`).
    busy: Option<BusyOp>,
    /// Mirror of `busy.is_some()` that can be read without the table lock.
    busy_flag: Arc<std::sync::atomic::AtomicBool>,
}

/// The work a busy table is waiting for helpers to complete.
// Port of erts/emulator/beam/erl_db.c (DB_BUSY in ets_internal_delete_all_2) and
// :2315 (DB_BUSY with the insert_2_list continuation), OTP-29.1.1.
enum BusyOp {
    /// `ets:delete_all_objects/1` released the objects a slice at a time.
    DeleteAll(Garbage),
    /// A list insert whose remaining objects are already copied into table form.
    InsertList(InsertListCtx),
}

/// The remaining objects of a trapping `ets:insert/2` list insert, shared with the process
/// that started it so that it can collect the result whoever finishes the work.
// Port of erts/emulator/beam/erl_db.c (ets_insert_2_list_info), OTP-29.1.1.
pub struct InsertListCtx {
    pending: std::collections::VecDeque<PreparedObject>,
    member_cursor: Option<usize>,
    destroy_copied: bool,
    outcome: Arc<std::sync::atomic::AtomicU8>,
}

/// Result slot of a trapped list insert: 0 not yet known, 1 `true`, 2 `false`.
pub type InsertOutcome = Arc<std::sync::atomic::AtomicU8>;

impl Table {
    /// The table's reference term: the magic reference whose binary owns the table, as erts'
    /// `make_tid` builds from `tb->common.btid`.
    // Port of erts/emulator/beam/erl_db.c (make_tid), OTP-29.1.1.
    pub fn tid_term<H: HeapAlloc>(&self, dst: &mut H) -> Result<Term, EtsError> {
        let owner = self
            .btid
            .get()
            .and_then(std::sync::Weak::upgrade)
            .ok_or(EtsError::NoTable)?;
        Ok(TermBuilder::new(dst).magic_ref(owner)?)
    }

    /// Whether the table was deleted while a cached handle to it was still in use.
    pub fn is_detached(&self) -> bool {
        self.detached
    }

    fn new(tid: Tid, mut options: TableOptions) -> Result<Self, EtsError> {
        if options.keypos == 0 {
            return Err(EtsError::BadArg);
        }
        let storage = if options.table_type == TableType::OrderedSet {
            if options.write_concurrency == WriteConcurrency::Disabled {
                Storage::Ordered(TreeRoot::new())
            } else {
                Storage::CATree(CATree::new(options.keypos, options.read_concurrency))
            }
        } else {
            Storage::Hash(HashStorage::new(
                options.write_concurrency,
                options.decentralized_counters,
                options.read_concurrency,
            ))
        };
        let heir_data = options
            .heir
            .map(|heir| StoredTerm::copy_heap(heir.data))
            .transpose()?;
        if let (Some(heir), Some(data)) = (&mut options.heir, &heir_data) {
            heir.data = data.raw_term().unwrap();
        }
        Ok(Self {
            tid,
            btid: std::sync::OnceLock::new(),
            options,
            storage,
            fixed: 0,
            fixed_system_time: None,
            fixed_monotonic_time: None,
            fixed_processes: Vec::new(),
            _heir_data: heir_data,
            counter_results: None,
            detached: false,
            busy: None,
            busy_flag: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        })
    }

    /// OTP-compatible object count, including hash counter wrap behavior.
    pub fn len(&self) -> usize {
        match &self.storage {
            Storage::Ordered(root) => root.count(),
            Storage::CATree(tree) => tree.count(),
            // An unsigned view of the signed counter: erts reads it as Uint, so a counter pushed
            // below zero by pseudo-deleted siblings (db_take_hash) wraps.
            Storage::Hash(storage) => storage.size.load(AtomicOrdering::Relaxed) as usize,
        }
    }

    /// Whether the table has no objects.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Check ordered storage balance factors and cached subtree sizes.
    #[doc(hidden)]
    pub fn avl_invariants_hold(&self) -> bool {
        match &self.storage {
            Storage::Ordered(root) => Node::validate(root),
            Storage::CATree(tree) => tree.validate(),
            Storage::Hash(_) => true,
        }
    }

    /// Expose CA-tree adaptation state to the port validation harness.
    #[doc(hidden)]
    pub fn catree_debug_base_count(&self) -> Option<usize> {
        match &self.storage {
            Storage::CATree(tree) => Some(tree.base_count()),
            _ => None,
        }
    }

    /// Set the CA-tree test split mode for one ETS table.
    pub fn debug_force_split(&self, on: bool) -> bool {
        if let Storage::CATree(tree) = &self.storage {
            tree.force_split(on);
            true
        } else {
            false
        }
    }

    /// Set the CA-tree randomized split/join test mode for one ETS table.
    pub fn debug_random_split_join(&self, on: bool) -> bool {
        if let Storage::CATree(tree) = &self.storage {
            tree.debug_random_split_join(on);
            true
        } else {
            false
        }
    }

    /// Drive a lock-stat transition deterministically in the port validation harness.
    #[doc(hidden)]
    pub fn catree_debug_adjust_contention(&self, key: Term, amount: i64) -> bool {
        if let Storage::CATree(tree) = &self.storage {
            tree.adjust_contention(key, amount);
            true
        } else {
            false
        }
    }

    /// Return core table metadata. The VM adds memory and scheduler details.
    pub fn info(&self) -> TableInfo {
        let key_count = match &self.storage {
            Storage::Ordered(root) => root.count(),
            Storage::CATree(tree) => tree.count(),
            Storage::Hash(storage) => storage.key_count(self.options.keypos),
        };
        TableInfo {
            size: self.len(),
            key_count,
            fixed: self.fixed,
            options: self.options,
        }
    }

    /// Heap and table allocations, reported in machine words.
    pub fn memory_words(&self) -> usize {
        self.memory_words_for_schedulers(1)
    }

    /// Return the OTP table allocation total for the runtime's scheduler count.
    // `sizeof(DbTable)` depends on the platform's pthread mutex size, see
    // `TABLE_HEADER_SHRINK` / `CATREE_BASE_SHRINK`; the constants below are the macOS values.
    pub fn memory_words_for_schedulers(&self, schedulers: usize) -> usize {
        // Port of erl_db_hash.c and erl_db_tree.c, OTP-29.1.1.
        // OTP's frequent-read rwlocks reserve one cache line per reader group plus
        // two bookkeeping lines. Its decentralized counter array reserves one
        // cache-line counter slot per scheduler plus one spare slot.
        let schedulers = schedulers.max(1);
        let concurrent = schedulers > 1 && self.options.protection != Protection::Private;
        let rwlock_words = 8 * (schedulers + 2);
        match &self.storage {
            Storage::Ordered(root) => {
                let mut objects = Vec::new();
                Node::walk(root, &mut objects);
                let table = (146 - TABLE_HEADER_SHRINK)
                    + usize::from(concurrent && self.options.read_concurrency) * rwlock_words;
                table
                    + objects
                        .iter()
                        .map(|object| object.db_size_words)
                        .sum::<usize>()
            }
            Storage::CATree(tree) => {
                let table = if concurrent {
                    // Port of erl_db_catree.c and erl_flxctr.c,
                    // OTP-29.1.1. This includes the initial base node, its lock,
                    // and (when enabled) the decentralized counter allocation.
                    (93 - TABLE_HEADER_SHRINK - CATREE_BASE_SHRINK)
                        + 8 * schedulers
                        + if self.options.decentralized_counters {
                            18 + 8 * schedulers
                        } else {
                            0
                        }
                        + usize::from(self.options.read_concurrency) * rwlock_words
                } else {
                    146 - TABLE_HEADER_SHRINK
                };
                table + tree.object_memory_words().max(0) as usize
            }
            Storage::Hash(storage) => {
                // The empty hash table reports 312 words on OTP 29.1.1/M1;
                // its initial segment is included in that allocation total.
                // Port of erl_db_hash.c: an extended segment uses
                // 2048 bucket words. The first extension table has 256
                // pointers; later tables grow by 128 pointers at a time.
                let lock_count = match self.options.write_concurrency {
                    WriteConcurrency::Disabled => 0,
                    WriteConcurrency::Enabled => 64,
                    WriteConcurrency::Auto => storage.lock_count(),
                    WriteConcurrency::Fixed(count) => count,
                };
                let nslots = storage.nslots.load(AtomicOrdering::Relaxed);
                let allocated_slots = nslots.max(if lock_count > nslots {
                    nslots + (lock_count - nslots).div_ceil(2048) * 2048
                } else {
                    nslots
                });
                let extra_slots = allocated_slots.saturating_sub(256);
                let ext_segments = extra_slots.div_ceil(2048);
                let ext_capacity = if ext_segments == 0 {
                    0
                } else if ext_segments <= 255 {
                    256
                } else {
                    256 + (ext_segments - 255).div_ceil(128) * 128
                };
                let ext_table = if ext_capacity == 0 {
                    0
                } else {
                    7 + ext_capacity
                };
                let fine_locks = if !concurrent || lock_count == 0 {
                    0
                } else {
                    // Port of erl_db_hash.c and erl_db_hash.h:54-69,
                    // OTP-29.1.1. The cache-line padded lock slots and the
                    // runtime-sized reader arrays are included in the ETS counter.
                    16 * lock_count
                        + rwlock_words
                        + if self.options.read_concurrency {
                            lock_count * rwlock_words
                        } else {
                            0
                        }
                };
                let read_lock = if concurrent
                    && self.options.read_concurrency
                    && self.options.write_concurrency == WriteConcurrency::Disabled
                {
                    rwlock_words
                } else {
                    0
                };
                let decentralized = if self.options.decentralized_counters
                    && self.options.write_concurrency != WriteConcurrency::Disabled
                    && concurrent
                {
                    18 + 8 * schedulers
                } else {
                    0
                };
                (312 - TABLE_HEADER_SHRINK)
                    + extra_slots
                    + ext_table
                    + fine_locks
                    + read_lock
                    + decentralized
                    + storage.object_memory_words().max(0) as usize
            }
        }
    }

    /// Return one `ets:info/2` value. `node` comes from the owning VM.
    pub fn info_item<H: HeapAlloc>(
        &self,
        key: &str,
        node: Term,
        dst: &mut H,
    ) -> Result<Term, EtsError> {
        self.info_item_for_schedulers(key, node, dst, 1)
    }

    /// Return one `ets:info/2` value using the owning runtime's scheduler count.
    pub fn info_item_for_schedulers<H: HeapAlloc>(
        &self,
        key: &str,
        node: Term,
        dst: &mut H,
        schedulers: usize,
    ) -> Result<Term, EtsError> {
        let atom = |name: &str| -> Term { Term::atom(global_atoms().intern(name).unwrap()) };
        let bool_term = |value: bool| atom(if value { "true" } else { "false" });
        let int_term = |value: usize, dst: &mut H| -> Result<Term, EtsError> {
            // Port of erts/emulator/beam/big.c (erts_make_integer), OTP-29.1.1.
            if let Ok(value) = i64::try_from(value)
                && let Some(term) = Term::small(value)
            {
                return Ok(term);
            }
            Ok(TermBuilder::new(dst).int_from_i128(value as i128)?)
        };
        match key {
            "id" => Ok(self.tid_term(dst)?),
            "name" => Ok(Term::atom(self.options.name)),
            "type" => Ok(atom(match self.options.table_type {
                TableType::Set => "set",
                TableType::OrderedSet => "ordered_set",
                TableType::Bag => "bag",
                TableType::DuplicateBag => "duplicate_bag",
            })),
            "keypos" => int_term(self.options.keypos, dst),
            "protection" => Ok(atom(match self.options.protection {
                Protection::Private => "private",
                Protection::Protected => "protected",
                Protection::Public => "public",
            })),
            "owner" => Ok(copy_term(self.options.owner, dst)?),
            // Port of erts/emulator/beam/erl_db.c (table_info), OTP-29.1.1.
            "heir" => match self.options.heir {
                Some(heir) => Ok(copy_term(heir.pid, dst)?),
                None => Ok(atom("none")),
            },
            "size" => int_term(self.len(), dst),
            "memory" => int_term(self.memory_words_for_schedulers(schedulers), dst),
            "node" => Ok(copy_term(node, dst)?),
            "named_table" => Ok(bool_term(self.options.named_table)),
            "read_concurrency" => Ok(bool_term(self.options.read_concurrency)),
            "write_concurrency" if self.options.protection == Protection::Private => {
                Ok(atom("false"))
            }
            "write_concurrency" => Ok(match self.options.write_concurrency {
                WriteConcurrency::Disabled => atom("false"),
                WriteConcurrency::Enabled => atom("true"),
                WriteConcurrency::Auto => atom("auto"),
                WriteConcurrency::Fixed(count) => {
                    let count = int_term(count, dst)?;
                    TermBuilder::new(dst)
                        .tuple(&[atom("debug_hash_fixed_number_of_locks"), count])?
                }
            }),
            "decentralized_counters" => Ok(bool_term(self.options.decentralized_counters)),
            "compressed" => Ok(bool_term(self.options.compressed)),
            "fixed" => Ok(bool_term(self.fixed > 0)),
            "safe_fixed" | "safe_fixed_monotonic_time" if self.fixed == 0 => Ok(atom("false")),
            "safe_fixed" => self.fixation_info(false, dst),
            "safe_fixed_monotonic_time" => self.fixation_info(true, dst),
            "stats" => self.stats_term(dst),
            "data" => Err(EtsError::Unsupported("ets:info data print side effect")),
            _ => Err(EtsError::BadArg),
        }
    }

    fn fixation_info<H: HeapAlloc>(&self, monotonic: bool, dst: &mut H) -> Result<Term, EtsError> {
        // Port of erts/emulator/beam/erl_db.c (safe_fixed info), OTP-29.1.1.
        let time = if monotonic {
            self.fixed_monotonic_time.as_ref()
        } else {
            self.fixed_system_time.as_ref()
        }
        .ok_or(EtsError::BadArg)?
        .copy_out(dst)?;
        let mut processes = Vec::with_capacity(self.fixed_processes.len());
        for (pid, count) in &self.fixed_processes {
            let pid = pid.copy_out(dst)?;
            let count = TermBuilder::new(dst).int_from_i128(*count as i128)?;
            processes.push(TermBuilder::new(dst).tuple(&[pid, count])?);
        }
        let processes = TermBuilder::new(dst).list_from_iter(processes)?;
        Ok(TermBuilder::new(dst).tuple(&[time, processes])?)
    }

    /// Return the `ets:info/1` property list in OTP key order.
    pub fn info_list<H: HeapAlloc>(&self, node: Term, dst: &mut H) -> Result<Term, EtsError> {
        self.info_list_for_schedulers(node, dst, 1)
    }

    /// Return the `ets:info/1` property list using the owning scheduler count.
    pub fn info_list_for_schedulers<H: HeapAlloc>(
        &self,
        node: Term,
        dst: &mut H,
        schedulers: usize,
    ) -> Result<Term, EtsError> {
        let names = [
            "id",
            "decentralized_counters",
            "read_concurrency",
            "write_concurrency",
            "compressed",
            "memory",
            "owner",
            "heir",
            "name",
            "size",
            "node",
            "named_table",
            "type",
            "keypos",
            "protection",
        ];
        let mut items = Vec::with_capacity(names.len());
        for name in names {
            let key = Term::atom(global_atoms().intern(name).unwrap());
            let value = self.info_item_for_schedulers(name, node, dst, schedulers)?;
            items.push(TermBuilder::new(dst).tuple(&[key, value])?);
        }
        Ok(TermBuilder::new(dst).list_from_iter(items)?)
    }

    fn stats_term<H: HeapAlloc>(&self, dst: &mut H) -> Result<Term, EtsError> {
        match &self.storage {
            Storage::Ordered(_) if self.options.write_concurrency == WriteConcurrency::Disabled => {
                Ok(Term::atom(global_atoms().intern("false").unwrap()))
            }
            Storage::Ordered(_) => {
                // Empty and small ordered_set tables with write_concurrency report
                // `{0, 1, 0}` from db_calc_stats_catree (route nodes, base nodes,
                // max depth). This storage is one tree, which matches that shape
                // until a real CA tree would split.
                let one = Term::small(1).unwrap();
                let zero = Term::small(0).unwrap();
                Ok(TermBuilder::new(dst).tuple(&[zero, one, zero])?)
            }
            Storage::CATree(tree) => {
                let bases = Term::small(tree.base_count() as i64).ok_or(EtsError::BadArg)?;
                let routes = Term::small(tree.base_count().saturating_sub(1) as i64)
                    .ok_or(EtsError::BadArg)?;
                let base_count = tree.base_count();
                let depth = Term::small((usize::BITS - (base_count - 1).leading_zeros()) as i64)
                    .ok_or(EtsError::BadArg)?;
                Ok(TermBuilder::new(dst).tuple(&[routes, bases, depth])?)
            }
            Storage::Hash(storage) => {
                let (lengths, kept_items) = storage.chain_lengths();
                let sum: usize = lengths.iter().sum();
                let square_sum: usize = lengths.iter().map(|length| length * length).sum();
                // db_calc_stats_hash stores these moments as C floats, then
                // erts widens them to Erlang floats. The inner chain deviation
                // is float arithmetic; the expected deviation is double sqrt
                // rounded back through float. Port of erl_db_hash.c, OTP-29.1.1.
                let nactive = storage.nactive() as f32;
                let average_f = sum as f32 / nactive;
                let deviation = ((square_sum as f32 - average_f * sum as f32) / nactive) as f64;
                let expected_f = (f64::from(average_f) * (1.0 - 1.0 / f64::from(nactive))).sqrt();
                let average = f64::from(average_f);
                let standard = f64::from(deviation.sqrt() as f32);
                let expected = f64::from(expected_f as f32);
                let mut builder = TermBuilder::new(dst);
                let avg = builder.float(average)?;
                let standard = builder.float(standard)?;
                let expected = builder.float(expected)?;
                // nlocks is 1 without fine locking and DB_HASH_LOCK_CNT (64) when
                // write_concurrency is true or auto. Port of erl_db_hash.c
                // (db_create_hash) and erl_db_hash.h:54, OTP-29.1.1.
                // Chain moments use db_calc_stats_hash's formula over these buckets.
                // Placement can diverge from erts; that numeric gap is D2-style.
                let locks = if self.options.write_concurrency == WriteConcurrency::Disabled {
                    1
                } else {
                    storage.lock_count() as i64
                };
                Ok(builder.tuple(&[
                    Term::small(storage.nactive() as i64).ok_or(EtsError::BadArg)?,
                    avg,
                    standard,
                    expected,
                    Term::small(*lengths.iter().min().unwrap_or(&0) as i64).unwrap(),
                    Term::small(*lengths.iter().max().unwrap_or(&0) as i64).unwrap(),
                    Term::small(kept_items as i64).unwrap(),
                    Term::small(locks).unwrap(),
                ])?)
            }
        }
    }

    /// Build the table-owned copy of one object, which needs no table state beyond the
    /// creation options: callers do it before taking the table's write lock.
    // Port of erts/emulator/beam/erl_db_hash.c (db_put_hash: the term is copied by
    // `new_dbterm` before the bucket lock is taken for set tables), OTP-29.1.1.
    pub fn prepare_object(
        options: &TableOptions,
        object: Term,
    ) -> Result<PreparedObject, EtsError> {
        let key = key_of(object, options.keypos)?;
        let hash = ets_hash(key);
        let stored = StoredTerm::copy_for_table(
            object,
            options.compressed,
            options.keypos,
            if options.table_type == TableType::OrderedSet {
                3
            } else {
                2
            },
        )?;
        Ok(PreparedObject { stored, hash })
    }

    /// Validate an object for this table without copying it into table storage.
    pub fn check_object(options: &TableOptions, object: Term) -> Result<(), EtsError> {
        key_of(object, options.keypos).map(|_| ())
    }

    /// Look up the key in an object without copying the object into table storage.
    pub fn member_object(&self, object: Term) -> Result<bool, EtsError> {
        let key = key_of(object, self.options.keypos)?;
        Ok(self.member(key))
    }

    /// Store a prepared object through a shared reference when the storage synchronizes its own
    /// writers (a CA tree), returning `None`; any other storage hands the object back for
    /// `insert_prepared` under the exclusive table lock.
    // Port of erts/emulator/beam/erl_db_catree.c (db_put_catree: only the route and
    // base-node locks are taken, not the table lock), OTP-29.1.1.
    pub fn insert_shared(&self, prepared: PreparedObject) -> Option<PreparedObject> {
        match &self.storage {
            Storage::CATree(tree) => {
                tree.insert(prepared.stored);
                None
            }
            Storage::Hash(storage)
                if self.options.write_concurrency != WriteConcurrency::Disabled =>
            {
                storage.insert_shared(
                    prepared.stored,
                    prepared.hash,
                    self.options.table_type,
                    self.options.keypos,
                    self.fixed > 0,
                    false,
                );
                None
            }
            _ => Some(prepared),
        }
    }

    /// Delete all objects at a key through the table's hash stripe or CA-tree base lock.
    // Port of erts/emulator/beam/erl_db_hash.c (db_erase_hash) and
    // erl_db_catree.c (db_erase_catree), OTP-29.1.1.
    pub fn delete_key_shared(&self, key: Term) -> bool {
        match &self.storage {
            Storage::Hash(storage) => {
                storage.delete_key_shared(key, ets_hash(key), self.options.keypos, self.fixed > 0);
                true
            }
            Storage::CATree(tree) => {
                tree.delete(key);
                true
            }
            Storage::Ordered(_) => false,
        }
    }

    /// Delete matching copies of one object through the table's hash stripe.
    pub fn delete_object_shared(&self, object: Term) -> Result<bool, EtsError> {
        let key = key_of(object, self.options.keypos)?;
        let Storage::Hash(storage) = &self.storage else {
            return Ok(false);
        };
        storage.delete_object_shared(
            key,
            ets_hash(key),
            self.options.keypos,
            object,
            self.options.table_type,
            self.fixed > 0,
        );
        Ok(true)
    }

    /// Update small tuple counters under the key's hash stripe or CA-tree base lock.
    // Port of erts/emulator/beam/erl_db.c (do_update_counter), OTP-29.1.1.
    pub fn update_counter_in_place_shared(
        &self,
        key: Term,
        operations: &[CounterOp],
    ) -> Option<smallvec::SmallVec<[Term; 4]>> {
        match (&self.storage, self.options.table_type) {
            (Storage::Hash(storage), TableType::Set) => {
                storage.update_counter_shared(key, ets_hash(key), self.options.keypos, operations)
            }
            (Storage::CATree(tree), TableType::OrderedSet) => tree.with_object_mut(key, |object| {
                update_counter_object_in_place(object, self.options.keypos, operations)
            }),
            _ => None,
        }
    }

    /// Apply arbitrary precision counter operations under the hash key's write stripe.
    pub fn update_counter_big_shared<H: HeapAlloc>(
        &self,
        key: Term,
        operations: &[Option<BigCounterOp>],
        default: Option<Term>,
        dst: &mut H,
    ) -> Result<Option<Vec<Term>>, EtsError> {
        if self.options.table_type != TableType::Set {
            return Ok(None);
        }
        let Storage::Hash(storage) = &self.storage else {
            return Ok(None);
        };
        let mut results = None;
        let changed = storage.update_or_insert_shared(
            key,
            ets_hash(key),
            self.options.keypos,
            self.fixed > 0,
            |found| {
                let mut heap = ObjectHeap::new();
                let mut values = if let Some(found) = found {
                    let current = found.term_for_filter(&mut heap)?;
                    // SAFETY: `current` is owned by `heap` until the replacement is copied.
                    let tuple = unsafe { current.tuple_ref() }.ok_or(EtsError::BadArg)?;
                    tuple.iter().collect::<Vec<_>>()
                } else if let Some(default) = default {
                    self.default_object(key, default, &mut heap)?
                } else {
                    return Err(EtsError::BadArgCause("badkey"));
                };
                for operation in operations {
                    let Some(operation) = operation else {
                        return Err(EtsError::BadArg);
                    };
                    if operation.position == self.options.keypos {
                        return Err(EtsError::BadArgCause("keypos"));
                    }
                    if operation.position == 0 || operation.position > values.len() {
                        return Err(EtsError::BadArgCause("position"));
                    }
                    if integer_value(values[operation.position - 1]).is_none() {
                        return Err(EtsError::BadArg);
                    }
                }
                let mut returned = Vec::with_capacity(operations.len());
                for operation in operations.iter().flatten() {
                    let old_term = values[operation.position - 1];
                    if let Some(small) = small_counter_step(old_term, operation)
                        && let Some(next) = Term::small(small)
                    {
                        values[operation.position - 1] = next;
                        returned.push(next);
                        continue;
                    }
                    let old = integer_value(old_term).ok_or(EtsError::BadArg)?;
                    let mut next = old + &operation.increment;
                    if let Some((threshold, set_value)) = &operation.threshold
                        && ((operation.increment >= BigInt::from(0) && next > *threshold)
                            || (operation.increment < BigInt::from(0) && next < *threshold))
                    {
                        next = set_value.clone();
                    }
                    let next = TermBuilder::new(&mut heap).int_from_bigint(&next)?;
                    values[operation.position - 1] = next;
                    returned.push(copy_term(next, dst)?);
                }
                let tuple = TermBuilder::new(&mut heap).tuple(&values)?;
                let replacement = StoredTerm::copy_for_table(
                    tuple,
                    self.options.compressed,
                    self.options.keypos,
                    2,
                )?;
                results = Some(returned);
                Ok(Some(replacement))
            },
        )?;
        Ok(changed.then(|| results.unwrap_or_default()))
    }

    /// Store an object built by [`Table::prepare_object`] like `insert` of a single object.
    pub fn insert_prepared(&mut self, prepared: PreparedObject) {
        self.put_hashed(prepared.stored, prepared.hash, false);
    }

    /// Store one object and return extra reductions spent comparing same-key bag objects.
    // Port of erts/emulator/beam/erl_db_hash.c (db_put_dbterm_hash), OTP-29.1.1.
    pub fn insert_prepared_counted(&mut self, prepared: PreparedObject) -> usize {
        self.put_hashed_counted(prepared.stored, prepared.hash, false)
    }

    /// Look up one already prepared key without copying the object.
    // Port of erts/emulator/beam/erl_db.c (ets_insert_new_2_dbterm_list_has_member), OTP-29.1.1.
    pub fn member_prepared(&self, prepared: &PreparedObject) -> bool {
        self.member_hashed(
            prepared.stored.key(self.options.keypos),
            prepared.hash,
            arinsal_term::current_reader_group(),
        )
    }

    /// Insert a prepared object if its key has no live entry, under its hash stripe.
    // Port of erts/emulator/beam/erl_db.c (ets_insert_new_2) and
    // erl_db_hash.c (db_put_hash with key_clash_fail), OTP-29.1.1.
    pub fn insert_new_prepared(&mut self, prepared: PreparedObject) -> bool {
        if let Storage::Hash(storage) = &mut self.storage {
            return storage.insert_exclusive(
                prepared.stored,
                prepared.hash,
                self.options.table_type,
                self.options.keypos,
                self.fixed > 0,
                true,
            );
        }
        match &mut self.storage {
            Storage::Ordered(root) => {
                let key = prepared.stored.key(self.options.keypos);
                let result = root.insert_with_key(prepared.stored, key, self.options.keypos, true);
                matches!(result, InsertResult::Inserted)
            }
            Storage::CATree(tree) => tree.insert_new(prepared.stored),
            Storage::Hash(_) => unreachable!("hash storage handled above"),
        }
    }

    /// Insert a prepared object if its key has no live entry, under its hash stripe or CA-tree
    /// base-node lock.
    // Port of erts/emulator/beam/erl_db.c (ets_insert_new_2), OTP-29.1.1.
    pub fn insert_new_prepared_shared(&self, prepared: PreparedObject) -> Result<bool, EtsError> {
        match &self.storage {
            Storage::Hash(storage) => Ok(storage.insert_shared(
                prepared.stored,
                prepared.hash,
                self.options.table_type,
                self.options.keypos,
                self.fixed > 0,
                true,
            )),
            Storage::CATree(tree) => Ok(tree.insert_new(prepared.stored)),
            Storage::Ordered(_) => Err(EtsError::BadArg),
        }
    }

    /// Insert one or several objects. Validation and copying finish before mutation.
    pub fn insert(&mut self, objects: &[Term]) -> Result<(), EtsError> {
        if let [object] = objects {
            let key = key_of(*object, self.options.keypos)?;
            let hash = ets_hash(key);
            self.put_hashed(
                StoredTerm::copy_for_table(
                    *object,
                    self.options.compressed,
                    self.options.keypos,
                    if self.options.table_type == TableType::OrderedSet {
                        3
                    } else {
                        2
                    },
                )?,
                hash,
                false,
            );
            return Ok(());
        }
        for &object in objects {
            key_of(object, self.options.keypos)?;
        }
        for &object in objects {
            let hash = ets_hash(key_of(object, self.options.keypos)?);
            self.put_hashed(
                StoredTerm::copy_for_table(
                    object,
                    self.options.compressed,
                    self.options.keypos,
                    if self.options.table_type == TableType::OrderedSet {
                        3
                    } else {
                        2
                    },
                )?,
                hash,
                false,
            );
        }
        Ok(())
    }

    fn put(&mut self, object: DbTerm) {
        let hash = ets_hash(object.key(self.options.keypos));
        self.put_hashed(object, hash, false);
    }

    fn put_hashed(&mut self, object: DbTerm, hash: u64, new_only: bool) {
        let _ = self.put_hashed_counted(object, hash, new_only);
    }

    fn put_hashed_counted(&mut self, object: DbTerm, hash: u64, new_only: bool) -> usize {
        let keypos = self.options.keypos;
        match &mut self.storage {
            Storage::Ordered(root) => {
                root.insert(object, keypos);
                0
            }
            Storage::CATree(tree) => {
                tree.insert(object);
                0
            }
            Storage::Hash(storage) => {
                let (accepted, extra_reds) = storage.insert_exclusive_counted(
                    object,
                    hash,
                    self.options.table_type,
                    keypos,
                    self.fixed > 0,
                    new_only,
                );
                debug_assert!(accepted || new_only);
                extra_reds
            }
        }
    }

    /// Whether another operation must be helped to completion before this table may be used.
    pub fn is_busy(&self) -> bool {
        self.busy.is_some()
    }

    /// The lock-free mirror of [`Table::is_busy`], for readers that do not hold the table lock.
    pub fn busy_flag(&self) -> Arc<std::sync::atomic::AtomicBool> {
        Arc::clone(&self.busy_flag)
    }

    fn set_busy(&mut self, busy: Option<BusyOp>) {
        self.busy_flag
            .store(busy.is_some(), AtomicOrdering::Release);
        self.busy = busy;
    }

    /// Mark the table busy while `garbage` is released by whoever uses it next.
    // Port of erts/emulator/beam/erl_db.c (ets_internal_delete_all_2), OTP-29.1.1.
    pub fn begin_busy_delete_all(&mut self, garbage: Garbage) {
        self.set_busy(Some(BusyOp::DeleteAll(garbage)));
    }

    /// Install the remaining objects of a trapping list insert, which other processes then help
    /// insert. Returns the slot the result is published in.
    // Port of erts/emulator/beam/erl_db.c (ets_insert_2_list_driver installs
    // `continuation_ctx`), OTP-29.1.1.
    pub fn begin_busy_insert_list(
        &mut self,
        pending: std::collections::VecDeque<PreparedObject>,
        member_cursor: Option<usize>,
        destroy_copied: bool,
        outcome: InsertOutcome,
    ) {
        self.set_busy(Some(BusyOp::InsertList(InsertListCtx {
            pending,
            member_cursor,
            destroy_copied,
            outcome,
        })));
    }

    /// Do a slice of the busy operation. `reds` counts down by the work done (a negative value
    /// on return means the slice ran out). Returns whether the table is usable again.
    // Port of erts/emulator/beam/erl_db.c (delete_all_objects_continue) and
    // :2161-2200 (ets_insert_2_list_continuation), OTP-29.1.1.
    pub fn continue_busy(&mut self, reds: &mut isize) -> bool {
        let Some(op) = self.busy.take() else {
            return true;
        };
        match op {
            BusyOp::DeleteAll(mut garbage) => {
                if self.free_garbage(&mut garbage, reds) {
                    self.set_busy(None);
                    true
                } else {
                    self.busy = Some(BusyOp::DeleteAll(garbage));
                    false
                }
            }
            BusyOp::InsertList(mut ctx) => {
                const ITERATIONS_PER_RED: isize = 8;
                let mut loops = (*reds).max(0) * ITERATIONS_PER_RED;
                if let Some(mut index) = ctx.member_cursor {
                    while index < ctx.pending.len() {
                        loops -= 1;
                        if loops <= 0 {
                            ctx.member_cursor = Some(index);
                            *reds = loops / ITERATIONS_PER_RED;
                            self.busy = Some(BusyOp::InsertList(ctx));
                            return false;
                        }
                        if self.member_prepared(&ctx.pending[index]) {
                            ctx.member_cursor = None;
                            ctx.destroy_copied = true;
                            break;
                        }
                        index += 1;
                    }
                    if index == ctx.pending.len() {
                        ctx.member_cursor = None;
                    }
                }
                if ctx.destroy_copied {
                    while !ctx.pending.is_empty() {
                        loops -= 1;
                        if loops <= 0 {
                            *reds = loops / ITERATIONS_PER_RED;
                            self.busy = Some(BusyOp::InsertList(ctx));
                            return false;
                        }
                        drop(ctx.pending.pop_front());
                    }
                    *reds = loops / ITERATIONS_PER_RED;
                    ctx.outcome.store(2, AtomicOrdering::Release);
                    self.set_busy(None);
                    return true;
                }
                while !ctx.pending.is_empty() {
                    loops -= 1;
                    if loops <= 0 {
                        *reds = loops / ITERATIONS_PER_RED;
                        self.busy = Some(BusyOp::InsertList(ctx));
                        return false;
                    }
                    let prepared = ctx.pending.pop_front().unwrap();
                    let extra_reds = self.insert_prepared_counted(prepared);
                    loops -= 1 + extra_reds as isize;
                    if loops <= 0 {
                        *reds = loops / ITERATIONS_PER_RED;
                        self.busy = Some(BusyOp::InsertList(ctx));
                        return false;
                    }
                }
                *reds = loops / ITERATIONS_PER_RED;
                if ctx.pending.is_empty() {
                    ctx.outcome.store(1, AtomicOrdering::Release);
                    self.set_busy(None);
                    true
                } else {
                    *reds = -1;
                    self.busy = Some(BusyOp::InsertList(ctx));
                    false
                }
            }
        }
    }

    /// Whether any of the prepared objects has a key already in the table.
    // Port of erts/emulator/beam/erl_db.c (ets_insert_new_2_dbterm_list_has_member),
    // OTP-29.1.1.
    pub fn any_member_prepared(&self, prepared: &[PreparedObject]) -> bool {
        prepared.iter().any(|object| {
            self.member_hashed(
                object.stored.key(self.options.keypos),
                object.hash,
                arinsal_term::current_reader_group(),
            )
        })
    }

    /// Insert prepared objects in order while `loops` lasts.
    pub fn insert_prepared_batch(
        &mut self,
        pending: &mut std::collections::VecDeque<PreparedObject>,
        loops: &mut isize,
    ) {
        while !pending.is_empty() {
            // YCF consumes the loop reduction before removing the next dbterm.
            *loops -= 1;
            if *loops <= 0 {
                return;
            }
            let prepared = pending.pop_front().unwrap();
            let extra_reds = self.insert_prepared_counted(prepared);
            // db_put_dbterm starts with one consumed reduction. Hash bags add one for each
            // same-key object compared before the match or end of its key run.
            *loops -= 1 + extra_reds as isize;
            if *loops <= 0 {
                return;
            }
        }
    }

    /// Release copied list objects while charging the yieldable destroy loop.
    // Port of erts/emulator/beam/erl_db.c (ets_insert_2_list_destroy_copied_dbterms), OTP-29.1.1.
    pub fn destroy_prepared_batch(
        &mut self,
        pending: &mut std::collections::VecDeque<PreparedObject>,
        loops: &mut isize,
    ) {
        while !pending.is_empty() {
            *loops -= 1;
            if *loops <= 0 {
                return;
            }
            drop(pending.pop_front());
        }
    }

    /// Insert only if every key is absent. Returns `false` without mutation otherwise.
    pub fn insert_new(&mut self, objects: &[Term]) -> Result<bool, EtsError> {
        self.insert_new_mode(objects, objects.len() == 1)
    }

    /// Insert the list form of `ets:insert_new/2`; OTP dispatches a one-element list as one object.
    pub fn insert_new_list(&mut self, objects: &[Term]) -> Result<bool, EtsError> {
        self.insert_new_mode(objects, objects.len() == 1)
    }

    fn insert_new_mode(&mut self, objects: &[Term], single: bool) -> Result<bool, EtsError> {
        // Port of erts/emulator/beam/erl_db.c (ets_insert_new_2), OTP-29.1.1.
        if single {
            let prepared = Self::prepare_object(&self.options, objects[0])?;
            return Ok(self.insert_new_prepared(prepared));
        }
        for &object in objects {
            key_of(object, self.options.keypos)?;
        }
        for &object in objects {
            if self.member(key_of(object, self.options.keypos)?) {
                return Ok(false);
            }
        }
        let mut prepared = Vec::with_capacity(objects.len());
        for &object in objects {
            prepared.push(StoredTerm::copy_for_table(
                object,
                self.options.compressed,
                self.options.keypos,
                if self.options.table_type == TableType::OrderedSet {
                    3
                } else {
                    2
                },
            )?);
        }
        for object in prepared {
            let hash = ets_hash(object.key(self.options.keypos));
            self.put_hashed(object, hash, single);
        }
        Ok(true)
    }

    /// Visit every live object stored under `key` before releasing its bucket lock.
    fn try_for_matching(
        &self,
        key: Term,
        mut visit: impl FnMut(&StoredTerm) -> Result<(), EtsError>,
    ) -> Result<usize, EtsError> {
        let mut count = 0;
        match &self.storage {
            Storage::Ordered(root) => {
                if let Some(object) = Node::get(root, key, self.options.keypos) {
                    visit(object)?;
                    count = 1;
                }
            }
            Storage::CATree(tree) => {
                for object in tree.matching(key)? {
                    visit(&object)?;
                    count += 1;
                }
            }
            Storage::Hash(storage) => {
                let hash = ets_hash(key);
                storage.with_objects_hash(hash, |objects| {
                    for node in objects {
                        if node.hvalue == (hash >> 1)
                            && exact_eq(node.key(self.options.keypos), key)
                        {
                            visit(node)?;
                            count += 1;
                        }
                    }
                    Ok::<_, EtsError>(())
                })?;
            }
        }
        Ok(count)
    }

    /// Visit the newest live object under `key` while its bucket lock is held.
    fn try_matching_first(
        &self,
        key: Term,
        mut visit: impl FnMut(&StoredTerm) -> Result<(), EtsError>,
    ) -> Result<bool, EtsError> {
        let mut found = false;
        match &self.storage {
            Storage::Ordered(root) => {
                if let Some(object) = Node::get(root, key, self.options.keypos) {
                    visit(object)?;
                    found = true;
                }
            }
            Storage::CATree(tree) => {
                if let Some(object) = tree.matching(key)?.first() {
                    visit(object)?;
                    found = true;
                }
            }
            Storage::Hash(storage) => {
                let hash = ets_hash(key);
                storage.with_objects_hash(hash, |objects| {
                    if let Some(node) = objects.into_iter().find(|node| {
                        node.hvalue == (hash >> 1) && exact_eq(node.key(self.options.keypos), key)
                    }) {
                        visit(node)?;
                        found = true;
                    }
                    Ok::<_, EtsError>(())
                })?;
            }
        }
        Ok(found)
    }

    /// Copy all objects at a key into the caller's heap.
    pub fn lookup<H: HeapAlloc>(&self, key: Term, dst: &mut H) -> Result<Vec<Term>, EtsError> {
        let mut objects = Vec::new();
        self.lookup_into(key, dst, &mut objects)?;
        Ok(objects)
    }

    /// Copy objects at a key into caller-owned result storage.
    pub fn lookup_into<H: HeapAlloc>(
        &self,
        key: Term,
        dst: &mut H,
        objects: &mut Vec<Term>,
    ) -> Result<(), EtsError> {
        objects.clear();
        self.lookup_hashed_into(key, ets_hash(key), dst, objects)
    }

    /// Copy all objects at a key into the caller's heap as an ETS result list, consing each
    /// copied object straight onto the list so no intermediate vector is built.
    // Port of erts/emulator/beam/erl_db_hash.c (db_get_hash) and erl_db_tree.c (db_get_tree),
    // OTP-29.1.1: the bucket chain is walked in order and every match is consed in front of
    // the result, which is the reversed chain order `lookup` returns.
    pub fn lookup_list<H: HeapAlloc>(&self, key: Term, dst: &mut H) -> Result<Term, EtsError> {
        self.lookup_list_at(key, arinsal_term::current_reader_group(), dst)
    }

    /// `lookup_list` in reader group `group`, the scheduler id of the caller.
    pub fn lookup_list_at<H: HeapAlloc>(
        &self,
        key: Term,
        group: usize,
        dst: &mut H,
    ) -> Result<Term, EtsError> {
        match &self.storage {
            Storage::Ordered(_) | Storage::CATree(_) => {
                Ok(match self.lookup_one_at(key, group, dst)? {
                    Some(object) => TermBuilder::new(dst)
                        .cons(object, Term::NIL)
                        .map_err(EtsError::Term)?,
                    None => Term::NIL,
                })
            }
            Storage::Hash(storage) => {
                let hash = ets_hash(key);
                storage.with_objects_hash_at(hash, group, |objects| {
                    let mut list = Term::NIL;
                    for object in objects {
                        if object.hvalue == (hash >> 1)
                            && exact_eq(object.key(self.options.keypos), key)
                        {
                            let copied = object.copy_out(dst)?;
                            list = TermBuilder::new(dst)
                                .cons(copied, list)
                                .map_err(EtsError::Term)?;
                        }
                    }
                    Ok(list)
                })
            }
        }
    }

    /// Copy one matching object directly into the caller's heap.
    pub fn lookup_one<H: HeapAlloc>(
        &self,
        key: Term,
        dst: &mut H,
    ) -> Result<Option<Term>, EtsError> {
        self.lookup_one_at(key, arinsal_term::current_reader_group(), dst)
    }

    /// `lookup_one` in reader group `group`.
    pub fn lookup_one_at<H: HeapAlloc>(
        &self,
        key: Term,
        group: usize,
        dst: &mut H,
    ) -> Result<Option<Term>, EtsError> {
        match &self.storage {
            Storage::Ordered(root) => Node::get(root, key, self.options.keypos)
                .map(|object| object.copy_out(dst))
                .transpose(),
            Storage::CATree(tree) => tree.lookup_one_at(key, group, dst),
            Storage::Hash(storage) => {
                let hash = ets_hash(key);
                storage.with_objects_hash_at(hash, group, |mut objects| {
                    objects
                        .find(|object| {
                            object.hvalue == (hash >> 1)
                                && exact_eq(object.key(self.options.keypos), key)
                        })
                        .map(|object| object.copy_out(dst))
                        .transpose()
                })
            }
        }
    }

    fn lookup_hashed<H: HeapAlloc>(
        &self,
        key: Term,
        hash: u64,
        dst: &mut H,
    ) -> Result<Vec<Term>, EtsError> {
        let mut objects = Vec::new();
        self.lookup_hashed_into(key, hash, dst, &mut objects)?;
        Ok(objects)
    }

    fn lookup_hashed_into<H: HeapAlloc>(
        &self,
        key: Term,
        hash: u64,
        dst: &mut H,
        objects: &mut Vec<Term>,
    ) -> Result<(), EtsError> {
        match &self.storage {
            Storage::Ordered(root) => {
                if let Some(object) = Node::get(root, key, self.options.keypos) {
                    objects.push(object.copy_out(dst)?);
                }
            }
            Storage::CATree(tree) => objects.extend(tree.lookup(key, dst)?),
            Storage::Hash(storage) => {
                let first = objects.len();
                storage.with_objects_hash(hash, |bucket| {
                    for object in bucket {
                        if object.hvalue == (hash >> 1)
                            && exact_eq(object.key(self.options.keypos), key)
                        {
                            objects.push(object.copy_out(dst)?);
                        }
                    }
                    Ok::<_, EtsError>(())
                })?;
                objects[first..].reverse();
            }
        }
        Ok(())
    }

    /// Check whether a key is present.
    pub fn member(&self, key: Term) -> bool {
        self.member_at(key, arinsal_term::current_reader_group())
    }

    /// `member` in reader group `group`, the scheduler id of the caller.
    pub fn member_at(&self, key: Term, group: usize) -> bool {
        self.member_hashed(key, ets_hash(key), group)
    }

    fn member_hashed(&self, key: Term, hash: u64, group: usize) -> bool {
        match &self.storage {
            Storage::Ordered(root) => Node::get(root, key, self.options.keypos).is_some(),
            Storage::Hash(storage) => storage.with_objects_hash_at(hash, group, |objects| {
                objects.into_iter().any(|object| {
                    object.hvalue == (hash >> 1) && exact_eq(object.key(self.options.keypos), key)
                })
            }),
            Storage::CATree(tree) => tree.member_at(key, group),
        }
    }

    /// Copy tuple element(s) at a key; bag tables may produce several results.
    pub fn lookup_element<H: HeapAlloc>(
        &self,
        key: Term,
        position: usize,
        dst: &mut H,
    ) -> Result<Vec<Term>, EtsError> {
        if position == 0 {
            return Err(EtsError::BadArg);
        }
        let mut found = Vec::new();
        let count = self.try_for_matching(key, |object| {
            found.push(object.copy_element_out(position - 1, dst)?);
            Ok(())
        })?;
        if count == 0 {
            // Port of erts/emulator/beam/erl_db.c (DB_ERROR_BADKEY), OTP-29.1.1.
            return Err(EtsError::BadArgCause("badkey"));
        }
        // Hash buckets are traversed newest-first; `lookup/2` reverses that
        // order before returning bag entries, and `lookup_element/3` must do
        // the same so callers observe the same clause order.
        if matches!(&self.storage, Storage::Hash(_)) {
            found.reverse();
        }
        Ok(found)
    }

    /// Copy the element at `position` of every object at a key as an ETS result list, consing
    /// straight onto the caller's heap.
    // Port of erts/emulator/beam/erl_db_hash.c (db_get_element_array), OTP-29.1.1: the bucket
    // chain is walked in order and each element is consed in front, which is the reversed chain
    // order `lookup_element` returns for bags.
    pub fn lookup_element_list<H: HeapAlloc>(
        &self,
        key: Term,
        position: usize,
        dst: &mut H,
    ) -> Result<Term, EtsError> {
        self.lookup_element_list_at(key, position, arinsal_term::current_reader_group(), dst)
    }

    /// `lookup_element_list` in reader group `group`.
    pub fn lookup_element_list_at<H: HeapAlloc>(
        &self,
        key: Term,
        position: usize,
        group: usize,
        dst: &mut H,
    ) -> Result<Term, EtsError> {
        if position == 0 {
            return Err(EtsError::BadArg);
        }
        let Storage::Hash(storage) = &self.storage else {
            let values = self.lookup_element(key, position, dst)?;
            return Ok(TermBuilder::new(dst).list_from_iter(values)?);
        };
        let hash = ets_hash(key);
        let mut list = Term::NIL;
        let mut found = false;
        storage.with_objects_hash_at(hash, group, |objects| {
            for object in objects {
                if object.hvalue == (hash >> 1) && exact_eq(object.key(self.options.keypos), key) {
                    found = true;
                    let element = object.copy_element_out(position - 1, dst)?;
                    list = TermBuilder::new(dst).cons(element, list)?;
                }
            }
            Ok::<_, EtsError>(())
        })?;
        if found {
            Ok(list)
        } else {
            // Port of erts/emulator/beam/erl_db.c (DB_ERROR_BADKEY), OTP-29.1.1.
            Err(EtsError::BadArgCause("badkey"))
        }
    }

    /// Copy one element from a set-like table without building an object list.
    ///
    /// Port of erts/emulator/beam/erl_db.c, OTP-29.1.1.
    pub fn lookup_element_one<H: HeapAlloc>(
        &self,
        key: Term,
        position: usize,
        dst: &mut H,
    ) -> Result<Term, EtsError> {
        self.lookup_element_one_at(key, position, arinsal_term::current_reader_group(), dst)
    }

    /// `lookup_element_one` in reader group `group`.
    pub fn lookup_element_one_at<H: HeapAlloc>(
        &self,
        key: Term,
        position: usize,
        group: usize,
        dst: &mut H,
    ) -> Result<Term, EtsError> {
        if position == 0 {
            return Err(EtsError::BadArg);
        }
        match &self.storage {
            Storage::Hash(storage) => {
                let hash = ets_hash(key);
                storage.with_objects_hash_at(hash, group, |mut objects| {
                    objects
                        .find(|object| {
                            object.hvalue == hash >> 1
                                && exact_eq(object.key(self.options.keypos), key)
                        })
                        .ok_or(EtsError::BadArgCause("badkey"))?
                        .copy_element_out(position - 1, dst)
                })
            }
            Storage::Ordered(root) => Node::get(root, key, self.options.keypos)
                .ok_or(EtsError::BadArgCause("badkey"))?
                .copy_element_out(position - 1, dst),
            Storage::CATree(tree) => tree.lookup_element_at(key, position - 1, group, dst),
        }
    }

    /// Copy tuple element(s), or return a copied default when the key is absent.
    pub fn lookup_element_default<H: HeapAlloc>(
        &self,
        key: Term,
        position: usize,
        default: Term,
        dst: &mut H,
    ) -> Result<ElementLookup, EtsError> {
        if position == 0 {
            return Err(EtsError::BadArg);
        }
        if !self.member(key) {
            return Ok(ElementLookup::Default(copy_term(default, dst)?));
        }
        Ok(ElementLookup::Values(
            self.lookup_element(key, position, dst)?,
        ))
    }

    /// Delete every object with this key.
    pub fn delete_key(&mut self, key: Term) {
        let fixed = self.fixed > 0;
        match &mut self.storage {
            Storage::Ordered(root) => drop(root.linkout(key, self.options.keypos)),
            Storage::CATree(tree) => tree.delete(key),
            Storage::Hash(storage) => {
                storage.delete_key_exclusive(key, ets_hash(key), self.options.keypos, fixed);
            }
        }
    }

    /// Delete an exact object, including duplicate copies for `duplicate_bag`.
    pub fn delete_object(&mut self, object: Term) -> Result<(), EtsError> {
        let key = key_of(object, self.options.keypos)?;
        let fixed = self.fixed > 0;
        match &mut self.storage {
            Storage::Ordered(root) => {
                root.remove_matching(key, self.options.keypos, |found| {
                    found.exact_eq_term(object)
                });
            }
            Storage::CATree(tree) => tree.delete_object(key, object),
            Storage::Hash(storage) => storage.delete_object_exclusive(
                key,
                ets_hash(key),
                self.options.keypos,
                object,
                self.options.table_type,
                fixed,
            ),
        }
        Ok(())
    }

    /// Detach every object for incremental release, leaving the table empty. `whole` also
    /// takes the pseudo-deleted objects of a table that is being deleted.
    ///
    /// Port of erts/emulator/beam/erl_db_hash.c (db_delete_all_objects_hash) and
    /// erl_db_tree.c (db_free_table_continue_tree), OTP-29.1.1.
    pub fn take_garbage(&mut self, whole: bool) -> Garbage {
        match &mut self.storage {
            Storage::Ordered(root) => {
                Garbage(GarbageKind::Tree(root.take().0.into_iter().collect()))
            }
            Storage::CATree(tree) => Garbage(GarbageKind::Tree(tree.take_all())),
            Storage::Hash(storage) => {
                // A fixed table keeps its objects pseudo-deleted in place: `free_garbage` marks
                // them a slice at a time (db_mark_all_deleted_hash).
                if !whole && self.fixed > 0 {
                    return Garbage(GarbageKind::Mark { slot: 0 });
                }
                let garbage = storage.take_garbage();
                storage.size.store(0, AtomicOrdering::Relaxed);
                storage.reset_object_memory();
                Garbage(GarbageKind::Hash(garbage))
            }
        }
    }

    /// Release `garbage` taken from this table within `reds` reductions. Returns whether all of
    /// it is released.
    pub fn free_garbage(&mut self, garbage: &mut Garbage, reds: &mut isize) -> bool {
        // Port of erts/emulator/beam/erl_db_hash.c (db_delete_all_objects_hash): the
        // mark-or-free decision is retaken on every continuation, so an unfix in between turns
        // the rest into a plain release.
        if let GarbageKind::Mark { slot } = &mut garbage.0
            && let Storage::Hash(storage) = &mut self.storage
        {
            if self.fixed > 0 {
                const LOOPS_PER_REDUCTION: isize = 8;
                let mut loops = (*reds).max(0) * LOOPS_PER_REDUCTION;
                *slot = storage.mark_deleted_from(*slot, &mut loops);
                if *slot < storage.nactive() {
                    *reds = -1;
                    return false;
                }
                storage.size.store(0, AtomicOrdering::Relaxed);
                storage.reset_object_memory();
                *reds = loops.max(0) / LOOPS_PER_REDUCTION;
                return true;
            }
            let released = storage.take_garbage();
            storage.size.store(0, AtomicOrdering::Relaxed);
            garbage.0 = GarbageKind::Hash(released);
        }
        garbage.step(reds)
    }

    /// Remove every object.
    pub fn delete_all_objects(&mut self) {
        match &mut self.storage {
            Storage::Ordered(root) => drop(root.take()),
            Storage::CATree(tree) => tree.clear(),
            Storage::Hash(storage) => {
                if self.fixed > 0 {
                    storage.mark_all_deleted();
                } else {
                    storage.clear_buckets();
                }
                storage.size.store(0, AtomicOrdering::Relaxed);
                storage.reset_object_memory();
            }
        }
    }

    /// Replace the table access and heir settings used by `ets:setopts/2`.
    ///
    /// Port of erts/emulator/beam/erl_db.c (`ets_setopts_2`), OTP-29.1.1.
    pub fn set_access_options(
        &mut self,
        protection: Option<Protection>,
        heir: Option<Heir>,
    ) -> Result<(), EtsError> {
        if let Some(protection) = protection {
            self.options.protection = protection;
        }
        if let Some(mut heir) = heir {
            let data = StoredTerm::copy(heir.data)?;
            heir.data = data.term;
            self._heir_data = Some(data);
            self.options.heir = Some(heir);
        }
        Ok(())
    }

    /// Raw first key for runtime table walkers that bypass protection checks.
    ///
    /// Port of erts/emulator/beam/erl_db_hash.c and erl_db_tree.c raw-first,
    /// OTP-29.1.1.
    pub fn raw_first<H: HeapAlloc>(&self, dst: &mut H) -> Result<Option<Term>, EtsError> {
        if let Storage::Hash(storage) = &self.storage {
            return storage
                .raw_first(self.options.keypos)
                .map(|key| Ok(copy_term(key, dst)?))
                .transpose();
        }
        self.edge(false, dst)
    }

    /// Raw successor key. A hash table accepts pseudo-deleted keys; tree tables share `next`.
    ///
    /// Port of erts/emulator/beam/erl_db_hash.c (db_raw_next_hash), erl_db_tree.c and
    /// erl_db_catree.c, OTP-29.1.1.
    pub fn raw_next<H: HeapAlloc>(&self, key: Term, dst: &mut H) -> Result<Option<Term>, EtsError> {
        if let Storage::Hash(storage) = &self.storage {
            return storage
                .raw_next(key, self.options.keypos)?
                .map(|key| Ok(copy_term(key, dst)?))
                .transpose();
        }
        // The tree methods use db_next_tree/db_next_catree: a deleted key is not an error.
        self.next(key, dst)
    }

    /// Return ref-counted binary owners retained by objects with this key.
    ///
    /// Port of erts/emulator/beam/erl_db_hash.c and erl_db_tree.c,
    /// OTP-29.1.1.
    pub fn lookup_binary_info<H: HeapAlloc>(
        &self,
        key: Term,
        dst: &mut H,
    ) -> Result<Vec<Term>, EtsError> {
        let mut binaries = Vec::new();
        match &self.storage {
            Storage::Hash(storage) => {
                let hash = ets_hash(key);
                storage.with_raw_objects_hash(hash, |objects| {
                    for object in objects {
                        if object.hvalue == hash >> 1
                            && exact_eq(object.key(self.options.keypos), key)
                        {
                            binaries.extend(object.refc_binaries(dst)?);
                        }
                    }
                    Ok::<_, EtsError>(())
                })?;
            }
            Storage::Ordered(root) => {
                if let Some(object) = Node::get(root, key, self.options.keypos) {
                    binaries.extend(object.refc_binaries(dst)?);
                }
            }
            Storage::CATree(tree) => {
                binaries = tree.binary_info(key, dst)?;
            }
        }
        Ok(binaries)
    }

    /// Return and remove all objects at a key.
    pub fn take<H: HeapAlloc>(&mut self, key: Term, dst: &mut H) -> Result<Vec<Term>, EtsError> {
        let fixed = self.fixed > 0;
        if let Storage::Hash(storage) = &mut self.storage {
            return storage.take_exclusive(
                key,
                ets_hash(key),
                self.options.keypos,
                self.options.table_type,
                fixed,
                dst,
            );
        }
        let result = self.lookup(key, dst)?;
        self.delete_key(key);
        Ok(result)
    }

    /// Copy the objects at a slot as an ETS list.
    pub fn slot<H: HeapAlloc>(&self, index: usize, dst: &mut H) -> Result<Option<Term>, EtsError> {
        match &self.storage {
            Storage::Ordered(root) => {
                // Port of erts/emulator/beam/erl_db_tree.c (db_slot_tree_common), OTP-29.1.1.
                if index > root.count() {
                    return Err(EtsError::BadArg);
                }
                if index == root.count() {
                    return Ok(None);
                }
                match root.slot_search(index + 1) {
                    dbterm::SlotSearch::Found(object) => {
                        let object = object.copy_out(dst)?;
                        Ok(Some(TermBuilder::new(dst).list_from_iter([object])?))
                    }
                    dbterm::SlotSearch::EndOfTable => Ok(None),
                    dbterm::SlotSearch::Out => Err(EtsError::BadArg),
                }
            }
            Storage::CATree(tree) => {
                if index > tree.count() {
                    return Err(EtsError::BadArg);
                }
                let Some(object) = tree.nth(index, dst)? else {
                    return Ok(None);
                };
                Ok(Some(TermBuilder::new(dst).list_from_iter([object])?))
            }
            Storage::Hash(storage) => {
                if !storage.is_valid_slot(index) {
                    return Err(EtsError::BadArg);
                }
                if index == storage.nactive() {
                    return Ok(None);
                }
                let mut objects = Vec::new();
                storage.try_with_slot_ordered(index, false, |object, _| {
                    objects.push(object.copy_out(dst)?);
                    Ok::<_, EtsError>(())
                })?;
                objects.reverse();
                Ok(Some(TermBuilder::new(dst).list_from_iter(objects)?))
            }
        }
    }

    /// Ordered successor of any key. Hash table traversal is not yet supported.
    pub fn next<H: HeapAlloc>(&self, key: Term, dst: &mut H) -> Result<Option<Term>, EtsError> {
        let Storage::Ordered(root) = &self.storage else {
            if let Storage::CATree(tree) = &self.storage {
                return tree.next(key, false, dst);
            }
            return self.hash_next(key, dst);
        };
        let mut node = root.link().as_deref();
        let mut candidate = None;
        while let Some(current) = node {
            let current_key = current.key(self.options.keypos);
            if cmp_ordered_key(key, current_key) == Ordering::Less {
                candidate = Some(current_key);
                node = current.next.as_deref();
            } else {
                node = current.right.as_deref();
            }
        }
        candidate.map(|key| Ok(copy_term(key, dst)?)).transpose()
    }

    fn hash_next<H: HeapAlloc>(&self, key: Term, dst: &mut H) -> Result<Option<Term>, EtsError> {
        let Storage::Hash(storage) = &self.storage else {
            unreachable!();
        };
        let keypos = self.options.keypos;
        let slot = storage.slot_for_key(key);
        let mut found = false;
        let mut next = None;
        storage.try_with_slot_ordered(slot, true, |object, deleted| {
            if !found {
                found = exact_eq(object.key(keypos), key);
            } else if next.is_none() && !deleted && !exact_eq(object.key(keypos), key) {
                next = Some(copy_term(object.key(keypos), dst)?);
            }
            Ok::<_, EtsError>(())
        })?;
        if !found {
            return Err(EtsError::BadArg);
        }
        if let Some(next) = next {
            return Ok(Some(next));
        }
        Ok(storage
            .with_first_from_slot(slot + 1, |object| copy_term(object.key(keypos), dst))
            .transpose()?)
    }

    /// Ordered predecessor of any key.
    pub fn prev<H: HeapAlloc>(&self, key: Term, dst: &mut H) -> Result<Option<Term>, EtsError> {
        let Storage::Ordered(root) = &self.storage else {
            if let Storage::CATree(tree) = &self.storage {
                return tree.next(key, true, dst);
            }
            return self.hash_next(key, dst);
        };
        let mut node = root.link().as_deref();
        let mut candidate = None;
        while let Some(current) = node {
            let current_key = current.key(self.options.keypos);
            if cmp_ordered_key(key, current_key) == Ordering::Greater {
                candidate = Some(current_key);
                node = current.right.as_deref();
            } else {
                node = current.next.as_deref();
            }
        }
        candidate.map(|key| Ok(copy_term(key, dst)?)).transpose()
    }

    /// First or last key in an ordered table.
    pub fn edge<H: HeapAlloc>(&self, last: bool, dst: &mut H) -> Result<Option<Term>, EtsError> {
        let Storage::Ordered(root) = &self.storage else {
            if let Storage::CATree(tree) = &self.storage {
                return tree.edge(last, dst);
            }
            let Storage::Hash(storage) = &self.storage else {
                unreachable!();
            };
            return Ok(storage
                .with_first_from_slot(0, |object| copy_term(object.key(self.options.keypos), dst))
                .transpose()?);
        };
        let mut node = root.link().as_deref();
        let mut found = None;
        while let Some(current) = node {
            found = Some(current.key(self.options.keypos));
            node = if last {
                current.right.as_deref()
            } else {
                current.next.as_deref()
            };
        }
        found.map(|key| Ok(copy_term(key, dst)?)).transpose()
    }

    /// Return the first or last key together with its objects.
    pub fn edge_lookup<H: HeapAlloc>(
        &self,
        last: bool,
        dst: &mut H,
    ) -> Result<Option<(Term, Vec<Term>)>, EtsError> {
        let Some(key) = self.edge(last, dst)? else {
            return Ok(None);
        };
        Ok(Some((key, self.lookup(key, dst)?)))
    }

    /// Return the ordered successor or predecessor and its objects.
    pub fn adjacent_lookup<H: HeapAlloc>(
        &self,
        key: Term,
        previous: bool,
        dst: &mut H,
    ) -> Result<Option<(Term, Vec<Term>)>, EtsError> {
        let found = if previous {
            self.prev(key, dst)?
        } else {
            self.next(key, dst)?
        };
        let Some(found) = found else {
            return Ok(None);
        };
        Ok(Some((found, self.lookup(found, dst)?)))
    }

    /// Copy all table objects. Hash table order is unspecified.
    pub fn tab2list<H: HeapAlloc>(&self, dst: &mut H) -> Result<Vec<Term>, EtsError> {
        if let Storage::CATree(tree) = &self.storage {
            return tree.walk(false, dst);
        }
        if let Storage::Hash(storage) = &self.storage {
            // Port of erts/emulator/beam/erl_db_hash.c (db_select_chunk_hash),
            // reached by ets:tab2list/1 through ets:match_object/2.
            let mut objects = Vec::new();
            storage.try_for_each_value(|object| {
                objects.push(object.copy_out(dst)?);
                Ok::<_, EtsError>(())
            })?;
            objects.reverse();
            return Ok(objects);
        }
        match &self.storage {
            Storage::Ordered(root) => {
                let mut objects = Vec::new();
                Node::walk_each(root, &mut |object| {
                    objects.push(object.copy_out(dst)?);
                    Ok(())
                })?;
                Ok(objects)
            }
            Storage::CATree(_) | Storage::Hash(_) => unreachable!("storage handled above"),
        }
    }

    /// Drop all fixations `pid` holds on this table.
    pub fn release_fixations(&mut self, pid: Term) {
        let count = self
            .fixed_processes
            .iter()
            .find(|(owner, _)| exact_eq(owner.raw_term().unwrap(), pid))
            .map_or(0, |(_, count)| *count);
        for _ in 0..count {
            let _ = self.safe_fixtable_for_at(pid, false, Term::NIL, Term::NIL);
        }
    }

    /// Fix or unfix this table on behalf of its owner.
    pub fn safe_fixtable(&mut self, fixed: bool) -> Result<(), EtsError> {
        self.safe_fixtable_for(self.options.owner, fixed)
    }

    /// Fix or unfix this table on behalf of one process.
    pub fn safe_fixtable_for(&mut self, pid: Term, fixed: bool) -> Result<(), EtsError> {
        if !fixed {
            return self.safe_fixtable_for_at(pid, false, Term::NIL, Term::NIL);
        }
        #[cfg(miri)]
        {
            let mut heap = VecHeap::new();
            let system = TermBuilder::new(&mut heap).tuple(&[
                Term::small(0).unwrap(),
                Term::small(0).unwrap(),
                Term::small(0).unwrap(),
            ])?;
            return self.safe_fixtable_for_at(pid, true, system, Term::small(0).unwrap());
        }
        #[cfg(not(miri))]
        {
            static START: OnceLock<Instant> = OnceLock::new();
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| EtsError::BadArg)?;
            let mut heap = VecHeap::new();
            let system = TermBuilder::new(&mut heap).tuple(&[
                Term::small((now.as_secs() / 1_000_000) as i64).unwrap(),
                Term::small((now.as_secs() % 1_000_000) as i64).unwrap(),
                Term::small(now.subsec_micros() as i64).unwrap(),
            ])?;
            let monotonic = TermBuilder::new(&mut heap)
                .int_from_i128(START.get_or_init(Instant::now).elapsed().as_nanos() as i128)?;
            self.safe_fixtable_for_at(pid, true, system, monotonic)
        }
    }

    /// Fix or unfix with timestamp terms supplied by the VM on the first fixation.
    pub fn safe_fixtable_for_at(
        &mut self,
        pid: Term,
        fixed: bool,
        system_time: Term,
        monotonic_time: Term,
    ) -> Result<(), EtsError> {
        if !matches!(pid.identity(), Some(Identity::Pid { .. })) {
            return Err(EtsError::BadArg);
        }
        if fixed {
            let system_time = if self.fixed == 0 {
                Some(StoredTerm::copy(system_time)?)
            } else {
                None
            };
            let monotonic_time = if self.fixed == 0 {
                Some(StoredTerm::copy(monotonic_time)?)
            } else {
                None
            };
            if let Some(time) = system_time {
                self.fixed_system_time = Some(time);
            }
            if let Some(time) = monotonic_time {
                self.fixed_monotonic_time = Some(time);
            }
            if let Some((_, count)) = self
                .fixed_processes
                .iter_mut()
                .find(|(owner, _)| exact_eq(owner.raw_term().unwrap(), pid))
            {
                *count += 1;
            } else {
                self.fixed_processes.push((StoredTerm::copy(pid)?, 1));
                self.fixed_processes.sort_by(|(left, _), (right, _)| {
                    cmp(left.raw_term().unwrap(), right.raw_term().unwrap())
                });
            }
            self.fixed += 1;
        } else if let Some(index) = self
            .fixed_processes
            .iter()
            .position(|(owner, _)| exact_eq(owner.raw_term().unwrap(), pid))
        {
            self.fixed_processes[index].1 -= 1;
            if self.fixed_processes[index].1 == 0 {
                self.fixed_processes.remove(index);
            }
            self.fixed -= 1;
            if self.fixed == 0
                && let Storage::Hash(storage) = &mut self.storage
            {
                storage.unfix();
            }
            if self.fixed == 0 {
                self.fixed_system_time = None;
                self.fixed_monotonic_time = None;
            }
        }
        Ok(())
    }

    /// Current fixation count.
    pub fn fixation_count(&self) -> usize {
        self.fixed
    }

    /// Apply tuple element replacements to a set object, or to `default` (with the
    /// requested key) when the key is absent. A `None` entry is a malformed
    /// `{Pos, Value}` or list tail. Returns `false` for a missing key without default.
    ///
    /// Port of erts/emulator/beam/erl_db.c (do_update_element), OTP-29.1.1.
    pub fn update_element(
        &mut self,
        key: Term,
        updates: &[Option<(usize, Term)>],
        default: Option<Term>,
    ) -> Result<bool, EtsError> {
        if !matches!(
            self.options.table_type,
            TableType::Set | TableType::OrderedSet
        ) {
            // DB_ERROR_BADPARAM reaches the plain `BIF_ERROR(p, BADARG)` here.
            return Err(EtsError::BadArg);
        }
        let mut heap = VecHeap::new();
        let mut stored_values = None;
        self.try_matching_first(key, |found| {
            let tuple_len = term_sequence(found.term).ok_or(EtsError::BadArg)?.len();
            stored_values = Some(
                (0..tuple_len)
                    .map(|index| found.copy_element_out(index, &mut heap))
                    .collect::<Result<Vec<_>, _>>()?,
            );
            Ok(())
        })?;
        let mut values = if let Some(values) = stored_values {
            values
        } else if let Some(default) = default {
            self.default_object(key, default, &mut heap)?
        } else {
            return Ok(false);
        };
        for update in updates {
            let Some((position, _)) = *update else {
                return Err(EtsError::BadArg);
            };
            if position == self.options.keypos {
                return Err(EtsError::BadArgCause("keypos"));
            }
            if position == 0 || position > values.len() {
                return Err(EtsError::BadArgCause("position"));
            }
        }
        for &(position, value) in updates.iter().flatten() {
            values[position - 1] = copy_term(value, &mut heap)?;
        }
        let result = TermBuilder::new(&mut heap).tuple(&values)?;
        self.insert(&[result])?;
        Ok(true)
    }

    /// Apply tuple element replacements while holding the hash key's write stripe.
    pub fn update_element_shared(
        &self,
        key: Term,
        updates: &[Option<(usize, Term)>],
        default: Option<Term>,
    ) -> Result<bool, EtsError> {
        if self.options.table_type != TableType::Set {
            return Err(EtsError::BadArg);
        }
        let Storage::Hash(storage) = &self.storage else {
            return Err(EtsError::BadArg);
        };
        let mut heap = VecHeap::new();
        storage.update_or_insert_shared(
            key,
            ets_hash(key),
            self.options.keypos,
            self.fixed > 0,
            |found| {
                let mut values = if let Some(found) = found {
                    (0..found.arity())
                        .map(|index| found.copy_element_out(index, &mut heap))
                        .collect::<Result<Vec<_>, _>>()?
                } else if let Some(default) = default {
                    self.default_object(key, default, &mut heap)?
                } else {
                    return Ok(None);
                };
                for update in updates {
                    let Some((position, _)) = *update else {
                        return Err(EtsError::BadArg);
                    };
                    if position == self.options.keypos {
                        return Err(EtsError::BadArgCause("keypos"));
                    }
                    if position == 0 || position > values.len() {
                        return Err(EtsError::BadArgCause("position"));
                    }
                }
                for &(position, value) in updates.iter().flatten() {
                    values[position - 1] = copy_term(value, &mut heap)?;
                }
                let tuple = TermBuilder::new(&mut heap).tuple(&values)?;
                Ok(Some(StoredTerm::copy_for_table(
                    tuple,
                    self.options.compressed,
                    self.options.keypos,
                    2,
                )?))
            },
        )
    }

    /// Return and remove all objects at a key while holding its write stripe.
    pub fn take_shared<H: HeapAlloc>(&self, key: Term, dst: &mut H) -> Result<Vec<Term>, EtsError> {
        let Storage::Hash(storage) = &self.storage else {
            return Err(EtsError::BadArg);
        };
        storage.take_shared(
            key,
            ets_hash(key),
            self.options.keypos,
            self.options.table_type,
            self.fixed > 0,
            dst,
        )
    }

    /// The elements of `default` with the key element replaced, as
    /// `db_lookup_dbterm` inserts it (erl_db_hash.c, erl_db_tree.c), OTP-29.1.1.
    fn default_object<H: HeapAlloc>(
        &self,
        key: Term,
        default: Term,
        heap: &mut H,
    ) -> Result<Vec<Term>, EtsError> {
        // SAFETY: the caller holds the default term heap through insertion.
        let tuple = unsafe { default.tuple_ref() }.ok_or(EtsError::BadArgCause("default"))?;
        if tuple.len() < self.options.keypos {
            return Err(EtsError::BadArgCause("default"));
        }
        let mut values = tuple
            .iter()
            .map(|value| copy_term(value, heap))
            .collect::<Result<Vec<_>, _>>()?;
        values[self.options.keypos - 1] = copy_term(key, heap)?;
        Ok(values)
    }

    /// Atomically apply counter operations to a set tuple. The VM chooses the return shape.
    pub fn update_counter(
        &mut self,
        key: Term,
        operations: &[CounterOp],
        default: Option<Term>,
    ) -> Result<Vec<Term>, EtsError> {
        let operations = operations
            .iter()
            .map(|operation| {
                Some(BigCounterOp {
                    position: operation.position,
                    increment: BigInt::from(operation.increment),
                    threshold: operation
                        .threshold
                        .map(|(threshold, reset)| (BigInt::from(threshold), BigInt::from(reset))),
                })
            })
            .collect::<Vec<_>>();
        self.update_counter_big(key, &operations, default)
    }

    /// Apply counter operations in place when every operand, counter and result is a small
    /// integer, which needs no copy of the object; returns `None`, with the table untouched,
    /// when any operation needs [`Table::update_counter_big`] (a missing key, an error, a
    /// bignum or compressed object).
    ///
    /// Port of erts/emulator/beam/erl_db.c (do_update_counter), OTP-29.1.1.
    pub fn update_counter_in_place(
        &mut self,
        key: Term,
        operations: &[CounterOp],
    ) -> Option<smallvec::SmallVec<[Term; 4]>> {
        if !matches!(
            self.options.table_type,
            TableType::Set | TableType::OrderedSet
        ) {
            return None;
        }
        let keypos = self.options.keypos;
        match &mut self.storage {
            Storage::Hash(storage) => {
                update_counter_object_in_place(storage.find_mut(key, keypos)?, keypos, operations)
            }
            Storage::Ordered(root) => {
                update_counter_object_in_place(root.get_mut(key, keypos)?, keypos, operations)
            }
            Storage::CATree(tree) => tree.with_object_mut(key, |object| {
                update_counter_object_in_place(object, keypos, operations)
            }),
        }
    }

    /// Atomically apply arbitrary precision counter operations. A `None` entry is a
    /// malformed operation or list tail; it fails without extended error information.
    ///
    /// Port of erts/emulator/beam/erl_db.c (do_update_counter), OTP-29.1.1.
    pub fn update_counter_big(
        &mut self,
        key: Term,
        operations: &[Option<BigCounterOp>],
        default: Option<Term>,
    ) -> Result<Vec<Term>, EtsError> {
        if !matches!(
            self.options.table_type,
            TableType::Set | TableType::OrderedSet
        ) {
            return Err(EtsError::BadArgCause("table_type"));
        }
        // ObjectHeap allocates exactly what is asked; a VecHeap would zero a 1024-word chunk
        // for every counter bump.
        let mut heap = ObjectHeap::new();
        let mut stored_values = None;
        self.try_matching_first(key, |found| {
            // erts reads and updates the stored object in place under the write lock
            // (erl_db.c db_lookup_dbterm, erl_db_catree.c). A CA tree hands
            // the visitor a copy that is dropped when the lookup returns, so the elements
            // are copied into the local heap rather than borrowed from `found`.
            let current = found.term_for_match(&mut heap)?;
            // SAFETY: current is owned by the local heap until the replacement is inserted.
            let values = unsafe { current.tuple_ref() }.ok_or(EtsError::BadArg)?;
            // A CA tree hands out a copy that dies with this call, so the elements move to `heap`.
            stored_values = Some(
                values
                    .iter()
                    .map(|value| copy_term(value, &mut heap))
                    .collect::<Result<Vec<_>, _>>()?,
            );
            Ok(())
        })?;
        let mut values = if let Some(values) = stored_values {
            values
        } else if let Some(default) = default {
            self.default_object(key, default, &mut heap)?
        } else {
            return Err(EtsError::BadArgCause("badkey"));
        };
        // Validate everything first: erts never rolls back a partial update.
        for operation in operations {
            let Some(operation) = operation else {
                return Err(EtsError::BadArg);
            };
            if operation.position == self.options.keypos {
                return Err(EtsError::BadArgCause("keypos"));
            }
            if operation.position == 0 || operation.position > values.len() {
                return Err(EtsError::BadArgCause("position"));
            }
            if integer_value(values[operation.position - 1]).is_none() {
                return Err(EtsError::BadArg);
            }
        }
        let mut results = Vec::with_capacity(operations.len());
        for operation in operations.iter().flatten() {
            if let Some(small) = small_counter_step(values[operation.position - 1], operation)
                && let Some(next) = Term::small(small)
            {
                values[operation.position - 1] = next;
                results.push(next);
                continue;
            }
            let old = integer_value(values[operation.position - 1]).ok_or(EtsError::BadArg)?;
            let mut next = old + &operation.increment;
            if let Some((threshold, set_value)) = &operation.threshold
                && ((operation.increment >= BigInt::from(0) && next > *threshold)
                    || (operation.increment < BigInt::from(0) && next < *threshold))
            {
                next = set_value.clone();
            }
            let next = TermBuilder::new(&mut heap).int_from_bigint(&next)?;
            values[operation.position - 1] = next;
            results.push(if next.is_pointer() {
                let heap = self
                    .counter_results
                    .get_or_insert_with(|| Box::new(VecHeap::new()));
                copy_term(next, heap.as_mut())?
            } else {
                next
            });
        }
        let updated = TermBuilder::new(&mut heap).tuple(&values)?;
        self.insert(&[updated])?;
        Ok(results)
    }

    /// Evaluate a compiled match specification on table objects.
    pub fn select<H: HeapAlloc>(
        &self,
        program: &match_spec::MatchProgram,
        reverse: bool,
        dst: &mut H,
    ) -> Result<Vec<Term>, EtsError> {
        self.select_limit(program, reverse, usize::MAX, dst)
    }

    /// Evaluate ETS selection with VM process context for `self` and trace values.
    pub fn select_with_context<H: HeapAlloc, C: match_spec::MatchContext>(
        &self,
        program: &match_spec::MatchProgram,
        reverse: bool,
        dst: &mut H,
        context: &C,
    ) -> Result<Vec<Term>, EtsError> {
        let mut runner = program.runner();
        if let Storage::CATree(tree) = &self.storage {
            let mut results = Vec::new();
            // Port of erts/emulator/beam/erl_db_catree.c (db_select_catree) and
            // erl_db_tree.c (db_select_tree_common): match a stored DbTerm under its
            // base-node read lock and copy only the selected result to the process heap.
            tree.scan_where(reverse, &|_| true, |object| {
                let (term, size) = object.term_for_filter_with_size(dst)?;
                if let Some(result) = runner.run_with_context_sized(term, dst, context, size)? {
                    results.push(result);
                }
                Ok(false)
            })?;
            return Ok(results);
        }
        if let Storage::Hash(storage) = &self.storage {
            // Port of erts/emulator/beam/erl_db_hash.c (db_select_chunk_hash).
            let mut results = Vec::new();
            storage.try_for_each_value(|object| {
                let (term, size) = object.term_for_filter_with_size(dst)?;
                if let Some(result) = runner.run_with_context_sized(term, dst, context, size)? {
                    results.push(result);
                }
                Ok::<_, EtsError>(())
            })?;
            results.reverse();
            return Ok(results);
        }
        let mut results = Vec::new();
        match &self.storage {
            Storage::Ordered(root) => {
                Node::scan_where(
                    root,
                    reverse,
                    &|_| true,
                    self.options.keypos,
                    &mut |object| {
                        let (term, size) = object.term_for_filter_with_size(dst)?;
                        if let Some(result) =
                            runner.run_with_context_sized(term, dst, context, size)?
                        {
                            results.push(result);
                        }
                        Ok(false)
                    },
                )?;
            }
            Storage::Hash(_) | Storage::CATree(_) => unreachable!("storage handled above"),
        }
        Ok(results)
    }

    /// Return variable bindings for each object matching a pattern.
    pub fn match_pattern<H: HeapAlloc>(
        &self,
        pattern: Term,
        dst: &mut H,
    ) -> Result<Vec<Term>, EtsError> {
        let program = match_spec::MatchProgram::from_pattern(pattern, false)?;
        self.select(&program, false, dst)
    }

    /// Return objects matching a pattern.
    pub fn match_object<H: HeapAlloc>(
        &self,
        pattern: Term,
        dst: &mut H,
    ) -> Result<Vec<Term>, EtsError> {
        let program = match_spec::MatchProgram::from_pattern(pattern, true)?;
        self.select(&program, false, dst)
    }

    /// Start a limited selection; the page can be resumed after table writes.
    pub fn select_chunk<H: HeapAlloc>(
        &self,
        program: &match_spec::MatchProgram,
        reverse: bool,
        limit: usize,
        dst: &mut H,
    ) -> Result<SelectBatch, EtsError> {
        self.select_chunk_with_context(program, reverse, limit, dst, &match_spec::EmptyContext)
    }

    /// Start chunked selection with VM process context.
    pub fn select_chunk_with_context<H: HeapAlloc, C: match_spec::MatchContext>(
        &self,
        program: &match_spec::MatchProgram,
        reverse: bool,
        limit: usize,
        dst: &mut H,
        context: &C,
    ) -> Result<SelectBatch, EtsError> {
        if limit == 0 || limit > i64::MAX as usize {
            return Err(EtsError::BadArg);
        }
        let mut heap = VecHeap::new();
        let program_ref = program.reference(&mut heap)?;
        self.select_chunk_continue_with_context(
            program,
            SelectContinuation {
                tid: self.tid,
                program_ref,
                limit,
                reverse,
                last_key: None,
                slot: 0,
                rest: Vec::new(),
                started: false,
                _heap: heap,
            },
            dst,
            context,
        )
    }

    /// Start `select_reverse/3` with ordered tables traversed backwards.
    pub fn select_reverse_chunk<H: HeapAlloc>(
        &self,
        program: &match_spec::MatchProgram,
        limit: usize,
        dst: &mut H,
    ) -> Result<SelectBatch, EtsError> {
        self.select_chunk(program, true, limit, dst)
    }

    /// Compile a `match/3` pattern and return its first page with the program.
    pub fn match_chunk<H: HeapAlloc>(
        &self,
        pattern: Term,
        limit: usize,
        dst: &mut H,
    ) -> Result<(match_spec::MatchProgram, SelectBatch), EtsError> {
        let program = match_spec::MatchProgram::from_pattern(pattern, false)?;
        let page = self.select_chunk(&program, false, limit, dst)?;
        Ok((program, page))
    }

    /// Compile a `match_object/3` pattern and return its first page with the program.
    pub fn match_object_chunk<H: HeapAlloc>(
        &self,
        pattern: Term,
        limit: usize,
        dst: &mut H,
    ) -> Result<(match_spec::MatchProgram, SelectBatch), EtsError> {
        let program = match_spec::MatchProgram::from_pattern(pattern, true)?;
        let page = self.select_chunk(&program, false, limit, dst)?;
        Ok((program, page))
    }

    /// Resume a limited selection using an owned or decoded continuation.
    pub fn select_chunk_continue<H: HeapAlloc>(
        &self,
        program: &match_spec::MatchProgram,
        continuation: SelectContinuation,
        dst: &mut H,
    ) -> Result<SelectBatch, EtsError> {
        self.select_chunk_continue_with_context(
            program,
            continuation,
            dst,
            &match_spec::EmptyContext,
        )
    }

    /// Resume chunked selection with VM process context.
    pub fn select_chunk_continue_with_context<H: HeapAlloc, C: match_spec::MatchContext>(
        &self,
        program: &match_spec::MatchProgram,
        mut continuation: SelectContinuation,
        dst: &mut H,
        context: &C,
    ) -> Result<SelectBatch, EtsError> {
        if continuation.tid != self.tid
            || !program.matches_reference(continuation.program_ref)
            || continuation.limit == 0
        {
            return Err(EtsError::BadArg);
        }
        let limit = continuation.limit;
        let mut runner = program.runner();
        let mut rows = Vec::with_capacity(limit.min(1024));
        match &self.storage {
            Storage::Ordered(root) => {
                let cursor = continuation.last_key;
                Node::scan_after(
                    root,
                    cursor,
                    continuation.reverse,
                    self.options.keypos,
                    &mut |object| {
                        let key = object.key(self.options.keypos);
                        continuation.last_key = Some(copy_term(key, &mut continuation._heap)?);
                        let (term, size) = object.term_for_filter_with_size(dst)?;
                        if let Some(result) =
                            runner.run_with_context_sized(term, dst, context, size)?
                        {
                            rows.push(result);
                        }
                        Ok(rows.len() == limit)
                    },
                )?;
                Ok(SelectBatch {
                    continuation: (rows.len() == limit).then_some(continuation),
                    rows,
                })
            }
            Storage::CATree(tree) => {
                let cursor = continuation.last_key;
                tree.scan_after(cursor, continuation.reverse, |object| {
                    let key = object.key(self.options.keypos);
                    continuation.last_key = Some(copy_term(key, &mut continuation._heap)?);
                    let term = object.term_for_filter(dst)?;
                    if let Some(result) = runner.run_with_context(term, dst, context)? {
                        rows.push(result);
                    }
                    Ok(rows.len() == limit)
                })?;
                Ok(SelectBatch {
                    continuation: (rows.len() == limit).then_some(continuation),
                    rows,
                })
            }
            Storage::Hash(storage) => {
                let mut match_list: VecDeque<_> = std::mem::take(&mut continuation.rest).into();
                if continuation.started
                    && continuation.slot != usize::MAX
                    && continuation.slot >= storage.nactive()
                    && match_list.len() < limit
                {
                    return Err(EtsError::BadArg);
                }
                let mut next_slot = continuation.slot;
                while match_list.len() < limit && next_slot < storage.nactive() {
                    storage.try_with_slot_ordered(next_slot, false, |object, _| {
                        let term = object.copy_out(&mut continuation._heap)?;
                        if let Some(result) =
                            runner.run_with_context(term, &mut continuation._heap, context)?
                        {
                            match_list.push_front(result);
                        }
                        Ok::<_, EtsError>(())
                    })?;
                    next_slot += 1;
                }
                let excess = match_list.len().saturating_sub(limit);
                let mut rest = match_list.drain(..excess).collect::<Vec<_>>();
                if continuation.started {
                    rest.reverse();
                }
                for &result in &match_list {
                    rows.push(copy_term(result, dst)?);
                }
                continuation.rest = rest;
                continuation.slot = if next_slot >= storage.nactive() {
                    usize::MAX
                } else {
                    next_slot
                };
                continuation.started = true;
                let more = !continuation.rest.is_empty() || next_slot < storage.nactive();
                Ok(SelectBatch {
                    continuation: (more && !rows.is_empty()).then_some(continuation),
                    rows,
                })
            }
        }
    }

    /// Return up to `limit` match results, stopping ordered range traversal early.
    pub fn select_limit<H: HeapAlloc>(
        &self,
        program: &match_spec::MatchProgram,
        reverse: bool,
        limit: usize,
        dst: &mut H,
    ) -> Result<Vec<Term>, EtsError> {
        if limit == 0 {
            return Err(EtsError::BadArg);
        }
        let mut runner = program.runner();
        if let Storage::Ordered(root) = &self.storage
            && let Some(bounds) = program.key_bounds(self.options.keypos)
        {
            if let Some(result) = program.range_result(self.options.keypos) {
                let mut state = ConstantRangeSelection {
                    keypos: self.options.keypos,
                    bounds,
                    result,
                    reverse,
                    limit,
                    dst,
                    out: Vec::new(),
                };
                select_range_constant(root.link(), &mut state)?;
                return Ok(state.out);
            }
            let mut state = RangeSelection {
                keypos: self.options.keypos,
                bounds,
                runner: &mut runner,
                reverse,
                limit,
                dst,
                out: Vec::new(),
            };
            Node::select_range(root, &mut state)?;
            return Ok(state.out);
        }
        if let Storage::CATree(tree) = &self.storage
            && let Some(bounds) = program.key_bounds(self.options.keypos)
        {
            let mut state = RangeSelection {
                keypos: self.options.keypos,
                bounds,
                runner: &mut runner,
                reverse,
                limit,
                dst,
                out: Vec::new(),
            };
            tree.select_range(&mut state)?;
            return Ok(state.out);
        }
        if let Storage::CATree(tree) = &self.storage {
            let mut results = Vec::new();
            // Port of erts/emulator/beam/erl_db_catree.c (db_select_catree), OTP-29.1.1.
            tree.scan_where(reverse, &|_| true, |object| {
                let (term, size) = object.term_for_filter_with_size(dst)?;
                if let Some(result) = runner.run_sized(term, dst, size)? {
                    results.push(result);
                }
                Ok(results.len() >= limit)
            })?;
            return Ok(results);
        }
        if let Storage::Hash(storage) = &self.storage {
            // Port of erts/emulator/beam/erl_db_hash.c (db_select_chunk_hash).
            let mut results = Vec::new();
            storage.try_for_each_value_while(|object| {
                let (candidate, size) = object.term_for_filter_with_size(dst)?;
                if let Some(result) = runner.run_sized(candidate, dst, size)? {
                    results.push(result);
                }
                Ok::<_, EtsError>(results.len() < limit)
            })?;
            results.reverse();
            return Ok(results);
        }
        match &self.storage {
            Storage::Ordered(root) => {
                let mut results = Vec::new();
                Node::scan_where(
                    root,
                    reverse,
                    &|_| true,
                    self.options.keypos,
                    &mut |object| {
                        let (candidate, size) = object.term_for_filter_with_size(dst)?;
                        if let Some(result) = runner.run_sized(candidate, dst, size)? {
                            results.push(result);
                        }
                        Ok(results.len() >= limit)
                    },
                )?;
                Ok(results)
            }
            Storage::Hash(_) | Storage::CATree(_) => unreachable!("storage handled above"),
        }
    }

    /// Count objects selected by a match specification.
    pub fn select_count_chunk(
        &self,
        program: &match_spec::MatchProgram,
        budget: usize,
    ) -> Result<CountBatch, EtsError> {
        if budget == 0 {
            return Err(EtsError::BadArg);
        }
        let mut heap = VecHeap::new();
        let program_ref = program.reference(&mut heap)?;
        self.select_count_continue(
            program,
            CountContinuation {
                tid: self.tid,
                program_ref,
                total: 0,
                last_key: None,
                slot: 0,
                _heap: heap,
            },
            budget,
        )
    }

    /// Resume an internal `select_count` traversal cycle.
    pub fn select_count_continue(
        &self,
        program: &match_spec::MatchProgram,
        mut continuation: CountContinuation,
        budget: usize,
    ) -> Result<CountBatch, EtsError> {
        if budget == 0
            || continuation.tid != self.tid
            || !program.matches_reference(continuation.program_ref)
        {
            return Err(EtsError::BadArg);
        }
        let true_atom = Term::atom(global_true());
        let mut scratch = VecHeap::new();
        let mut runner = program.runner();
        let mut visited = 0;
        let more = match &self.storage {
            Storage::Ordered(root) => {
                let cursor = continuation.last_key;
                Node::scan_after(root, cursor, false, self.options.keypos, &mut |object| {
                    let key = object.key(self.options.keypos);
                    continuation.last_key = Some(copy_term(key, &mut continuation._heap)?);
                    let (term, size) = object.term_for_filter_with_size(&mut scratch)?;
                    if runner
                        .run_sized(term, &mut scratch, size)?
                        .is_some_and(|value| exact_eq(value, true_atom))
                    {
                        continuation.total += 1;
                    }
                    visited += 1;
                    Ok(visited >= budget)
                })?
            }
            Storage::CATree(tree) => {
                let cursor = continuation.last_key;
                tree.scan_after(cursor, false, |object| {
                    let key = object.key(self.options.keypos);
                    continuation.last_key = Some(copy_term(key, &mut continuation._heap)?);
                    let (term, size) = object.term_for_filter_with_size(&mut scratch)?;
                    if runner
                        .run_sized(term, &mut scratch, size)?
                        .is_some_and(|value| exact_eq(value, true_atom))
                    {
                        continuation.total += 1;
                    }
                    visited += 1;
                    Ok(visited >= budget)
                })?
            }
            Storage::Hash(storage) => {
                if continuation.slot >= storage.nactive() {
                    return Err(EtsError::BadArg);
                }
                while continuation.slot < storage.nactive() {
                    storage.try_with_slot_ordered(continuation.slot, false, |object, _| {
                        let (term, size) = object.term_for_filter_with_size(&mut scratch)?;
                        if runner
                            .run_sized(term, &mut scratch, size)?
                            .is_some_and(|value| exact_eq(value, true_atom))
                        {
                            continuation.total += 1;
                        }
                        visited += 1;
                        Ok::<_, EtsError>(())
                    })?;
                    continuation.slot += 1;
                    if visited >= budget {
                        break;
                    }
                }
                continuation.slot < storage.nactive()
            }
        };
        let count = continuation.total;
        Ok(CountBatch {
            count,
            continuation: more.then_some(continuation),
        })
    }

    /// Count objects selected by a match specification.
    // Port of erts/emulator/beam/erl_db_hash.c (db_select_count_hash),
    // erl_db_tree.c (db_select_count_tree), OTP-29.1.1.
    pub fn select_count(&self, program: &match_spec::MatchProgram) -> Result<usize, EtsError> {
        let mut heap = VecHeap::new();
        let mut runner = program.runner();
        let true_atom = Term::atom(global_true());
        let mut count = 0;
        {
            let mut visit = |object: &StoredTerm| -> Result<(), EtsError> {
                let (term, size) = object.term_for_filter_with_size(&mut heap)?;
                if runner
                    .run_sized(term, &mut heap, size)?
                    .is_some_and(|result| exact_eq(result, true_atom))
                {
                    count += 1;
                }
                Ok(())
            };
            if let Some(key) = program.exact_key_pattern(self.options.keypos) {
                self.try_for_matching(key, &mut visit)?;
            } else {
                match &self.storage {
                    Storage::Hash(storage) => storage.try_for_each_value(&mut visit)?,
                    Storage::Ordered(root) => Node::walk_each(root, &mut visit)?,
                    Storage::CATree(tree) => {
                        tree.scan_where(false, &|_| true, |object| {
                            visit(object)?;
                            Ok(false)
                        })?;
                    }
                }
            }
        }
        Ok(count)
    }

    /// Delete objects selected by a match specification and return the count.
    // Port of erts/emulator/beam/erl_db_hash.c (db_select_delete_hash),
    // erl_db_tree.c (db_select_delete_tree), OTP-29.1.1.
    pub fn select_delete(&mut self, program: &match_spec::MatchProgram) -> Result<usize, EtsError> {
        let mut heap = VecHeap::new();
        let mut selected = Vec::new();
        let true_atom = Term::atom(global_true());
        if let Some(key) = program.exact_key_pattern(self.options.keypos) {
            self.try_for_matching(key, |object| {
                let term = object.term_for_filter(&mut heap)?;
                if program
                    .run(term, &mut heap)?
                    .is_some_and(|result| exact_eq(result, true_atom))
                {
                    selected.push(copy_term(term, &mut heap)?);
                }
                Ok(())
            })?;
            for object in selected.iter().copied() {
                self.delete_object(object)?;
            }
            return Ok(selected.len());
        }
        if self.fixed == 0
            && let Storage::Hash(storage) = &mut self.storage
        {
            let removed = storage.delete_where(|object| {
                let term = object.term_for_filter(&mut heap)?;
                Ok::<_, EtsError>(
                    program
                        .run(term, &mut heap)?
                        .is_some_and(|result| exact_eq(result, true_atom)),
                )
            });
            storage.shrink_after_delete(self.options.keypos);
            return removed;
        }
        match &self.storage {
            Storage::Hash(storage) => {
                storage.try_for_each_value(|object| {
                    let term = object.term_for_filter(&mut heap)?;
                    if program
                        .run(term, &mut heap)?
                        .is_some_and(|result| exact_eq(result, true_atom))
                    {
                        selected.push(copy_term(term, &mut heap)?);
                    }
                    Ok::<_, EtsError>(())
                })?;
            }
            Storage::Ordered(root) => {
                let mut objects = Vec::new();
                Node::walk(root, &mut objects);
                for object in objects {
                    let term = object.term_for_filter(&mut heap)?;
                    if program
                        .run(term, &mut heap)?
                        .is_some_and(|result| exact_eq(result, true_atom))
                    {
                        selected.push(copy_term(term, &mut heap)?);
                    }
                }
            }
            Storage::CATree(tree) => {
                for term in tree.walk(false, &mut heap)? {
                    if program
                        .run(term, &mut heap)?
                        .is_some_and(|result| exact_eq(result, true_atom))
                    {
                        selected.push(term);
                    }
                }
            }
        }
        let count = selected.len();
        for object in selected {
            self.delete_object(object)?;
        }
        Ok(count)
    }

    /// Replace each selected object in place; the match specification must keep keys.
    ///
    /// Port of erts/emulator/beam/erl_db.c (ets_select_replace_2) and
    /// erl_db_hash.c (select_replace_on_match_res), OTP-29.1.1.
    pub fn select_replace(
        &mut self,
        program: &match_spec::MatchProgram,
    ) -> Result<usize, EtsError> {
        if self.options.table_type == TableType::Bag {
            return Err(EtsError::BadArgCause("table_type"));
        }
        // `analyze_pattern` rejects specifications whose result may change the key
        // (db_match_keeps_key), so replacement never moves an object.
        if !program.keeps_key(self.options.keypos) {
            return Err(EtsError::BadArg);
        }
        let keypos = self.options.keypos;
        let compressed = self.options.compressed;
        if let Storage::Hash(storage) = &mut self.storage {
            let count = storage.replace_each(|object| {
                let mut heap = VecHeap::new();
                let current = object.copy_out(&mut heap)?;
                let Some(replacement) = program.run(current, &mut heap)? else {
                    return Ok(None);
                };
                let replacement = StoredTerm::copy_for_table(replacement, compressed, keypos, 2)?;
                Ok(Some(replacement))
            })?;
            return Ok(count);
        }
        let mut heap = VecHeap::new();
        let mut replacements = Vec::new();
        for object in self.tab2list(&mut heap)? {
            let Some(replacement) = program.run(object, &mut heap)? else {
                continue;
            };
            replacements.push(StoredTerm::copy_for_table(
                replacement,
                compressed,
                keypos,
                3,
            )?);
        }
        let count = replacements.len();
        for object in replacements {
            self.put(object);
        }
        Ok(count)
    }

    /// Replace matches for one exact key while holding its hash stripe.
    pub fn select_replace_key_shared(
        &self,
        program: &match_spec::MatchProgram,
    ) -> Result<Option<usize>, EtsError> {
        if self.options.table_type == TableType::Bag {
            return Err(EtsError::BadArgCause("table_type"));
        }
        if !program.keeps_key(self.options.keypos) {
            return Err(EtsError::BadArg);
        }
        let Some(key) = program.exact_key_pattern(self.options.keypos) else {
            return Ok(None);
        };
        let Storage::Hash(storage) = &self.storage else {
            return Ok(None);
        };
        let keypos = self.options.keypos;
        let compressed = self.options.compressed;
        let count = storage.replace_key_shared(key, ets_hash(key), keypos, |object| {
            let mut heap = VecHeap::new();
            let current = object.copy_out(&mut heap)?;
            let Some(replacement) = program.run(current, &mut heap)? else {
                return Ok::<Option<DbTerm>, EtsError>(None);
            };
            let replacement = StoredTerm::copy_for_table(replacement, compressed, keypos, 2)?;
            Ok(Some(replacement))
        })?;
        Ok(Some(count))
    }
}

/// Storage detached from a table, released a slice of reductions at a time.
pub struct Garbage(GarbageKind);

enum GarbageKind {
    /// Hash buckets.
    Hash(HashGarbage),
    /// A fixed hash table whose objects are being pseudo-deleted, from `slot` on.
    Mark { slot: usize },
    /// Tree nodes still to be freed.
    Tree(Vec<DbTerm>),
}

impl Garbage {
    /// Nothing left to release.
    pub fn empty() -> Self {
        Self(GarbageKind::Tree(Vec::new()))
    }

    /// Release up to `reds` reductions of work, counting down below zero when it ran out.
    /// Returns whether everything is released.
    ///
    /// Port of erts/emulator/beam/erl_db_tree.c (do_free_tree_continue) and
    /// erl_db_hash.c (db_free_table_continue_hash), OTP-29.1.1.
    pub fn step(&mut self, reds: &mut isize) -> bool {
        match &mut self.0 {
            GarbageKind::Hash(garbage) => garbage.step(reds),
            // Marked by `Table::free_garbage`, which owns the table.
            GarbageKind::Mark { .. } => true,
            GarbageKind::Tree(stack) => {
                while let Some(mut node) = stack.pop() {
                    stack.extend(node.next.take());
                    stack.extend(node.right.take());
                    drop(node);
                    *reds -= 1;
                    if *reds < 0 {
                        return false;
                    }
                }
                true
            }
        }
    }
}

/// Registry for named and unnamed tables.
pub struct Registry {
    tables: Vec<TableSlot>,
    free_slots: Vec<usize>,
    names: HashMap<Atom, Tid>,
    named_tables: Arc<NamedTableIndex>,
    owned_tables: HashMap<Term, HashSet<Tid>>,
    /// Tables each process has fixed (erts `ERTS_P_FIXED_TABLES`).
    fixed_tables: HashMap<Term, HashSet<Tid>>,
    match_programs: std::sync::RwLock<HashMap<u64, Arc<match_spec::MatchProgram>>>,
}

struct TableSlot {
    generation: u32,
    table: Option<SharedTable>,
}

/// `sizeof(pthread_mutex_t)` in words. erts' `ethr_mutex` wraps a pthread mutex, and the
/// queue lock inside every own-implementation `ethr_rwmutex` is one too (erts/include/
/// internal/ethr_mutex.h: `ETHR_MTX_QLOCK_TYPE__`, ethread.h: `ETHR_USE_OWN_RWMTX_IMPL__`).
/// macOS: 64 bytes; glibc aarch64: 48; glibc x86_64: 40.
const PTHREAD_MUTEX_WORDS: usize = if cfg!(target_os = "macos") {
    8
} else if cfg!(target_arch = "aarch64") {
    6
} else {
    5
};
/// Words one pthread mutex is smaller than on macOS, where the constants in
/// `memory_words_for_schedulers` were measured.
const MUTEX_SHRINK: usize = 8 - PTHREAD_MUTEX_WORDS;
/// `DbTableCommon` (erl_db_util.h) holds two such locks: `rwlock` and `fixlock`.
const TABLE_HEADER_SHRINK: usize = 2 * MUTEX_SHRINK;
/// A CA tree base node (erl_db_catree.h) adds one more: its `erts_rwmtx_t lock`.
const CATREE_BASE_SHRINK: usize = MUTEX_SHRINK;
const META_NAME_TAB_BUCKET_COUNT: usize = 8192;
const META_NAME_TAB_LOCK_COUNT: usize = 256;

#[derive(Clone)]
struct NamedTableEntry {
    name: Atom,
    table: SharedTable,
}

struct NamedTableEntries {
    data: Vec<NamedTableEntry>,
}

/// Lock-free read index for named tables, matching OTP's `meta_name_tab` buckets.
pub struct NamedTableIndex {
    mask: usize,
    buckets: Box<[arc_swap::ArcSwap<NamedTableEntries>]>,
    empty: Arc<NamedTableEntries>,
    locks: [parking_lot::Mutex<()>; META_NAME_TAB_LOCK_COUNT],
}

impl NamedTableIndex {
    /// Create an empty erts-sized name index.
    pub fn new() -> Self {
        let empty = Arc::new(NamedTableEntries { data: Vec::new() });
        Self {
            mask: META_NAME_TAB_BUCKET_COUNT - 1,
            buckets: (0..META_NAME_TAB_BUCKET_COUNT)
                .map(|_| arc_swap::ArcSwap::from(Arc::clone(&empty)))
                .collect(),
            empty,
            locks: std::array::from_fn(|_| parking_lot::Mutex::new(())),
        }
    }

    /// Resolve an atom without acquiring the ETS registry lock or allocating.
    // Port of erts/emulator/beam/erl_db.c (db_get_table_aux), OTP-29.1.1.
    // Readers scan the atom-hashed immutable bucket snapshot.
    pub fn lookup(&self, name: Atom) -> Option<SharedTable> {
        let bucket = name.0 as usize & self.mask;
        let entries = self.buckets[bucket].load();
        entries
            .data
            .iter()
            .find(|entry| entry.name == name)
            .map(|entry| entry.table.clone())
    }

    /// Use the table in an atom-hashed name snapshot without cloning its shared handle.
    ///
    /// The snapshot guard keeps the table alive until `use_table` returns, including while the
    /// caller holds the table lock.
    // Port of erts/emulator/beam/erl_db.c (meta_name_tab_bucket, db_get_table_aux), OTP-29.1.1.
    pub fn with_table<R>(
        &self,
        name: Atom,
        use_table: impl FnOnce(&SharedTable) -> R,
    ) -> Option<R> {
        let bucket = name.0 as usize & self.mask;
        let entries = self.buckets[bucket].load();
        let entry = entries.data.iter().find(|entry| entry.name == name)?;
        Some(use_table(&entry.table))
    }

    fn insert(&self, name: Atom, table: SharedTable) -> bool {
        // Port of erts/emulator/beam/erl_db.c (insert_named_tab), OTP-29.1.1.
        let bucket_index = name.0 as usize & self.mask;
        let _lock = self.locks[bucket_index % META_NAME_TAB_LOCK_COUNT].lock();
        let current = self.buckets[bucket_index].load_full();
        if current.data.iter().any(|entry| entry.name == name) {
            return false;
        }

        let size = current.data.len() + 1;
        let old_capacity = current.data.capacity();
        let capacity = old_capacity.max(named_entries_capacity(size));
        let mut data = Vec::with_capacity(capacity);
        data.extend(current.data.iter().cloned());
        data.push(NamedTableEntry { name, table });
        self.buckets[bucket_index].store(Arc::new(NamedTableEntries { data }));
        true
    }

    fn remove(&self, name: Atom, table: &SharedTable) -> bool {
        // Port of erts/emulator/beam/erl_db.c (remove_named_tab), OTP-29.1.1.
        let bucket_index = name.0 as usize & self.mask;
        let _lock = self.locks[bucket_index % META_NAME_TAB_LOCK_COUNT].lock();
        let current = self.buckets[bucket_index].load_full();
        let Some(index) = current
            .data
            .iter()
            .position(|entry| entry.name == name && SharedTable::ptr_eq(&entry.table, table))
        else {
            return false;
        };

        let size = current.data.len() - 1;
        if size == 0 {
            self.buckets[bucket_index].store(Arc::clone(&self.empty));
        } else {
            let mut data = Vec::with_capacity(named_entries_capacity(size));
            data.extend(current.data[..index].iter().cloned());
            data.extend(current.data[index + 1..].iter().cloned());
            self.buckets[bucket_index].store(Arc::new(NamedTableEntries { data }));
        }
        true
    }
}

fn named_entries_capacity(size: usize) -> usize {
    size.max(8).checked_next_power_of_two().unwrap_or(size)
}

impl Default for NamedTableIndex {
    fn default() -> Self {
        Self::new()
    }
}

/// A table behind its own lock, so operations on different tables never serialize.
///
/// Port of erts/emulator/beam/erl_db.c (db_lock/db_unlock), OTP-29.1.1: each table
/// carries its own `rwlock`; reads take it shared and writes exclusive. The registry lock
/// only guards the identity and name maps (erts `meta_main_tab` and `meta_name_tab`).
#[derive(Clone)]
pub struct SharedTable(Arc<arinsal_term::MagicRef>);

impl SharedTable {
    /// Wrap a table lock in its magic binary and register the table's own reference.
    // Port of erts/emulator/beam/erl_db.c (db_create_table: erts_create_magic_binary with the
    // DbTable as its data and `tb->common.btid`), OTP-29.1.1.
    fn new(lock: TableLock) -> Self {
        let size = std::mem::size_of::<Table>();
        let magic = arinsal_term::MagicRef::with_erts_payload_size(lock, size);
        let shared = Self(magic);
        let _ = shared.read().btid.set(Arc::downgrade(&shared.0));
        shared
    }

    /// The table's reference term.
    pub fn to_term<H: HeapAlloc>(&self, dst: &mut H) -> Result<Term, TermError> {
        TermBuilder::new(dst).magic_ref(Arc::clone(&self.0))
    }

    /// Whether both handles are the same table.
    pub fn ptr_eq(a: &Self, b: &Self) -> bool {
        Arc::ptr_eq(&a.0, &b.0)
    }
}

impl std::ops::Deref for SharedTable {
    type Target = TableLock;

    fn deref(&self) -> &TableLock {
        self.0
            .downcast_ref::<TableLock>()
            .expect("a table handle holds its table lock")
    }
}

/// A table rwmutex. erts selects its frequent-reader implementation when either
/// `DB_FINE_LOCKED` or `DB_FREQ_READ` is set.
///
/// Port of erts/emulator/beam/erl_db.c (`db_init_lock`) and :446-500 (`db_lock`),
/// OTP-29.1.1.
pub struct TableLock {
    lock: rwmtx::RwMtxLock<Table>,
    busy: Arc<std::sync::atomic::AtomicBool>,
    tid: Tid,
    /// The options the table was created with, readable without taking the table lock. The
    /// type, key position, compression and write concurrency never change; the name and the
    /// protection do, so callers needing those read the table itself.
    creation: TableOptions,
}

/// Shared access to a live table.
pub type TableReadGuard<'a, T> = rwmtx::RwMtxReadGuard<'a, T>;

/// Exclusive access to a live table.
pub type TableWriteGuard<'a, T> = rwmtx::RwMtxWriteGuard<'a, T>;

impl TableLock {
    /// The creation options (see the field note for which of them may be stale).
    pub fn options(&self) -> TableOptions {
        self.creation
    }

    /// Whether the table is waiting for its users to finish a trapped operation; readable
    /// without taking the table lock.
    pub fn is_busy(&self) -> bool {
        self.busy.load(AtomicOrdering::Acquire)
    }

    fn new(table: Table, frequent_read: bool) -> Self {
        Self {
            busy: table.busy_flag(),
            tid: table.tid,
            creation: table.options,
            lock: if frequent_read {
                rwmtx::RwMtxLock::new_freq_read(table)
            } else {
                rwmtx::RwMtxLock::new(table)
            },
        }
    }

    /// Lock the table for reading, in the calling thread's reader group.
    pub fn read(&self) -> TableReadGuard<'_, Table> {
        self.lock.read()
    }

    /// Lock the table for reading in reader group `group`, the scheduler id of the caller.
    #[inline]
    pub fn read_at(&self, group: usize) -> TableReadGuard<'_, Table> {
        self.lock.read_at(group)
    }

    /// Lock the table for writing.
    pub fn write(&self) -> TableWriteGuard<'_, Table> {
        self.lock.write()
    }
}

impl Registry {
    /// Start an empty registry.
    pub fn new() -> Self {
        Self::new_with_named_index(Arc::new(NamedTableIndex::new()))
    }

    /// Start an empty registry using a name index shared with the VM runtime.
    pub fn new_with_named_index(named_tables: Arc<NamedTableIndex>) -> Self {
        Self {
            tables: vec![TableSlot {
                generation: 0,
                table: None,
            }],
            free_slots: Vec::new(),
            names: HashMap::new(),
            named_tables,
            owned_tables: HashMap::new(),
            fixed_tables: HashMap::new(),
            match_programs: std::sync::RwLock::new(HashMap::new()),
        }
    }

    /// Return the number of live tables in this registry.
    pub fn table_count(&self) -> usize {
        self.tables
            .iter()
            .filter(|slot| slot.table.is_some())
            .count()
    }

    /// Count external pid, port, and reference terms retained by all table objects.
    pub fn external_identity_counts(&self) -> HashMap<(Atom, u32), usize> {
        let mut counts = HashMap::new();
        for slot in &self.tables {
            let Some(table) = &slot.table else {
                continue;
            };
            let table = table.write();
            let mut heap = VecHeap::new();
            if let Ok(objects) = table.tab2list(&mut heap) {
                for object in objects {
                    count_external_identities(object, &mut counts);
                }
            }
        }
        counts
    }

    /// Count external identities retained by compiled match programs.
    pub fn match_program_identity_counts(&self) -> HashMap<(Atom, u32), usize> {
        let mut counts = HashMap::new();
        for program in self.match_programs.read().unwrap().values() {
            for (node, count) in program.external_identity_counts() {
                *counts.entry(node).or_default() += count;
            }
        }
        counts
    }

    /// Create a table and reserve its name if requested.
    pub fn create(&mut self, options: TableOptions) -> Result<Tid, EtsError> {
        if options.named_table && self.names.contains_key(&options.name) {
            return Err(EtsError::NameTaken);
        }
        let index = if let Some(&index) = self.free_slots.last() {
            index
        } else {
            self.tables.len()
        };
        let generation = if index < self.tables.len() {
            self.tables[index].generation
        } else {
            1
        };
        let tid = Tid::new(index, generation).ok_or(EtsError::BadArg)?;
        let table = Table::new(tid, options)?;
        if self.free_slots.last() == Some(&index) {
            self.free_slots.pop();
        }
        if index == self.tables.len() {
            self.tables.push(TableSlot {
                generation,
                table: None,
            });
        }
        let shared = SharedTable::new(TableLock::new(
            table,
            options.read_concurrency || options.write_concurrency != WriteConcurrency::Disabled,
        ));
        self.tables[index].table = Some(shared.clone());
        self.owned_tables
            .entry(options.owner)
            .or_default()
            .insert(tid);
        if options.named_table {
            if !self.named_tables.insert(options.name, shared.clone()) {
                self.remove_owned_table(options.owner, tid);
                self.tables[index].table = None;
                self.free_slots.push(index);
                return Err(EtsError::NameTaken);
            }
            self.names.insert(options.name, tid);
        }
        Ok(tid)
    }

    /// The shared handle of a live table.
    pub fn shared(&self, tid: Tid) -> Result<&SharedTable, EtsError> {
        let index = tid.slot().ok_or(EtsError::NoTable)?;
        let slot = self
            .tables
            .get(index)
            .filter(|slot| slot.generation == tid.generation())
            .ok_or(EtsError::NoTable)?;
        slot.table.as_ref().ok_or(EtsError::NoTable)
    }

    /// The reference term of a live table (erts `make_tid`).
    pub fn tid_term<H: HeapAlloc>(&self, tid: Tid, dst: &mut H) -> Result<Term, EtsError> {
        Ok(self.shared(tid)?.to_term(dst)?)
    }

    /// Lock a table exclusively while ETS hash storage is stripe-owned.
    pub fn get(&self, tid: Tid) -> Result<TableWriteGuard<'_, Table>, EtsError> {
        Ok(self.shared(tid)?.write())
    }

    /// Lock a table for a fine-grained key read.
    // Port of erts/emulator/beam/erl_db.c (db_lock read mode), OTP-29.1.1.
    pub fn get_shared(&self, tid: Tid) -> Result<TableReadGuard<'_, Table>, EtsError> {
        let table = self.shared(tid)?.read();
        // Port of erts/emulator/beam/erl_db.c (handle_lacking_permission, DB_BUSY).
        if table.is_busy() {
            return Err(EtsError::Busy);
        }
        Ok(table)
    }

    /// Lock a table for writing.
    pub fn get_mut(&self, tid: Tid) -> Result<TableWriteGuard<'_, Table>, EtsError> {
        let table = self.shared(tid)?.write();
        if table.is_busy() {
            return Err(EtsError::Busy);
        }
        Ok(table)
    }

    /// Set CA-tree internal state for a table identity.
    pub fn debug_set_catree_mode(&self, tid: Tid, random: bool, on: bool) -> bool {
        self.get(tid).is_ok_and(|table| {
            if random {
                table.debug_random_split_join(on)
            } else {
                table.debug_force_split(on)
            }
        })
    }

    /// Resolve a registered table name.
    pub fn whereis(&self, name: Atom) -> Option<Tid> {
        self.names.get(&name).copied()
    }

    /// Enumerate live table identities.
    pub fn all(&self) -> Vec<Tid> {
        self.tables
            .iter()
            .filter_map(|slot| slot.table.as_ref().map(|table| table.read().tid))
            .collect()
    }

    /// Retain a compiled match program while a user continuation may refer to it.
    pub fn retain_match_program(&self, program: match_spec::MatchProgram) {
        self.match_programs
            .write()
            .unwrap()
            .insert(program.id(), Arc::new(program));
    }

    /// Keep a compiled program that a continuation returned to the caller refers to.
    pub fn retain_shared_match_program(&self, program: Arc<match_spec::MatchProgram>) {
        self.match_programs
            .write()
            .unwrap()
            .insert(program.id(), program);
    }

    /// Resolve a compiled program from an ETS continuation reference.
    pub fn match_program(&self, reference: Term) -> Option<Arc<match_spec::MatchProgram>> {
        self.match_programs
            .read()
            .unwrap()
            .get(&match_spec::MatchProgram::reference_id(reference)?)
            .cloned()
    }

    /// Release a compiled match program after its last continuation is consumed.
    pub fn release_match_program(&self, reference: Term) -> bool {
        match_spec::MatchProgram::reference_id(reference)
            .is_some_and(|id| self.match_programs.write().unwrap().remove(&id).is_some())
    }

    /// Remove a table from the registry.
    pub fn delete(&mut self, tid: Tid) -> Result<(), EtsError> {
        self.detach(tid).map(|_| ())
    }

    /// Remove a table from the registry and return its storage, to be released incrementally,
    /// with the number of fixations it dropped.
    ///
    /// Port of erts/emulator/beam/erl_db.c (ets_delete_1: DB_DELETE status, name removal,
    /// free_fixations_locked) up to the free_table_continue call, OTP-29.1.1.
    pub fn detach(&mut self, tid: Tid) -> Result<(Garbage, usize), EtsError> {
        let index = tid.slot().ok_or(EtsError::NoTable)?;
        let slot = self
            .tables
            .get_mut(index)
            .filter(|slot| slot.generation == tid.generation())
            .ok_or(EtsError::NoTable)?;
        let shared = slot.table.take().ok_or(EtsError::NoTable)?;
        slot.generation = slot.generation.wrapping_add(1).max(1);
        self.free_slots.push(index);
        let mut table = shared.write();
        table.detached = true;
        self.remove_owned_table(table.options.owner, tid);
        if table.options.named_table {
            self.names.remove(&table.options.name);
            assert!(self.named_tables.remove(table.options.name, &shared));
        }
        let mut fixations = 0;
        for (pid, count) in &table.fixed_processes {
            fixations += count;
            let pid = pid.raw_term().unwrap();
            if let Some(tables) = self.fixed_tables.get_mut(&pid) {
                tables.remove(&tid);
                if tables.is_empty() {
                    self.fixed_tables.remove(&pid);
                }
            }
        }
        Ok((table.take_garbage(true), fixations))
    }

    /// Any table `owner` still owns (head of erts `ERTS_PSD_ETS_OWNED_TABLES`).
    // Port of erts/emulator/beam/erl_db.c (GET_OWNED_TABLE), OTP-29.1.1.
    pub fn first_owned(&self, owner: Term) -> Option<Tid> {
        self.owned_tables.get(&owner)?.iter().next().copied()
    }

    /// Drop a stale ownership entry whose table no longer exists.
    pub fn forget_owned(&mut self, owner: Term, tid: Tid) {
        self.remove_owned_table(owner, tid);
    }

    /// Return the tables owned by one process without inspecting unrelated tables.
    // Port of erts/emulator/beam/erl_db.c (owned table list), OTP-29.1.1.
    pub fn owned_by(&self, owner: Term) -> Vec<Tid> {
        self.owned_tables
            .get(&owner)
            .map(|tables| tables.iter().copied().collect())
            .unwrap_or_default()
    }

    fn remove_owned_table(&mut self, owner: Term, tid: Tid) {
        if let Some(tables) = self.owned_tables.get_mut(&owner) {
            tables.remove(&tid);
            if tables.is_empty() {
                self.owned_tables.remove(&owner);
            }
        }
    }

    /// Rename a table, updating the named-table index.
    ///
    /// Unnamed tables only change the name reported by `ets:info/2`. They are
    /// not registered, so the new name may collide with another table's name.
    pub fn rename(&mut self, tid: Tid, name: Atom) -> Result<(), EtsError> {
        let shared = self.shared(tid)?.clone();
        let mut table = shared.write();
        let named = table.options.named_table;
        if named {
            // Port of erts/emulator/beam/erl_db.c (insert_named_tab), OTP-29.1.1:
            // any registered name fails, including the table's own.
            if self.names.contains_key(&name) {
                return Err(EtsError::NameTaken);
            }
            let old = table.options.name;
            if !self.named_tables.insert(name, shared.clone()) {
                return Err(EtsError::NameTaken);
            }
            assert!(self.named_tables.remove(old, &shared));
            self.names.remove(&old);
            self.names.insert(name, tid);
        }
        table.options.name = name;
        Ok(())
    }

    /// Remember that `pid` fixed `tid`, so its exit can release the fixation.
    pub fn note_fixation(&mut self, pid: Term, tid: Tid) {
        self.fixed_tables.entry(pid).or_default().insert(tid);
    }

    /// Whether `pid` has fixed any table.
    pub fn has_fixations(&self, pid: Term) -> bool {
        self.fixed_tables.contains_key(&pid)
    }

    /// Release every fixation held by an exiting process.
    ///
    /// Port of erts/emulator/beam/erl_db.c (free_fixations_op), OTP-29.1.1.
    pub fn release_fixations(&mut self, pid: Term) {
        let Some(tables) = self.fixed_tables.remove(&pid) else {
            return;
        };
        for tid in tables {
            // Not `get_mut`: erts frees the fixations without the busy check (free_fixations_op).
            if let Ok(mut table) = self.get(tid) {
                table.release_fixations(pid);
            }
        }
    }

    /// Record the new owner after the VM sends its transfer message.
    // Port of erts/emulator/beam/erl_db.c (owned table transfer), OTP-29.1.1.
    pub fn give_away(&mut self, tid: Tid, new_owner: Term) -> Result<(), EtsError> {
        let old_owner = self.get(tid)?.options.owner;
        if old_owner == new_owner {
            return Ok(());
        }
        self.remove_owned_table(old_owner, tid);
        self.owned_tables.entry(new_owner).or_default().insert(tid);
        self.get_mut(tid)?.options.owner = new_owner;
        Ok(())
    }
}

fn count_external_identities(term: Term, counts: &mut HashMap<(Atom, u32), usize>) {
    let mut pending = vec![term];
    while let Some(term) = pending.pop() {
        match term.classify() {
            TermKind::Pid | TermKind::Port | TermKind::Ref => match term.identity() {
                Some(Identity::Pid { node, creation, .. })
                | Some(Identity::Port { node, creation, .. })
                | Some(Identity::Ref { node, creation, .. })
                    if node != arinsal_term::atoms::NONAME =>
                {
                    *counts.entry((node, creation)).or_default() += 1;
                }
                _ => {}
            },
            TermKind::Tuple | TermKind::Record | TermKind::List => {
                if let Some(elements) = term_sequence(term) {
                    pending.extend(elements);
                }
            }
            TermKind::Map => {
                if let Some(pairs) = arinsal_term::record_map_pairs(term) {
                    pending.extend(pairs.into_iter().flat_map(|(key, value)| [key, value]));
                }
            }
            _ => {}
        }
    }
}

impl Default for Registry {
    fn default() -> Self {
        Self::new()
    }
}

/// Concurrent table with key-sharded writers and optimistic integer-pair reads.
///
/// The caller can hold it in an `Arc`. Every object at a key maps to one shard;
/// multi-object insertion locks all shards before mutating any of them.
pub struct ConcurrentTable {
    /// Creation options and owner metadata.
    pub options: TableOptions,
    shards: Vec<ConcurrentShard>,
    multi_epoch: AtomicU64,
    concurrent_catree: Option<CATree>,
    concurrent_hash: Option<ConcurrentHashStorage>,
    _heir_data: Option<DbTerm>,
}

// The fast slots own integer pairs directly. A writer holds `table` and marks
// `version` odd before changing any slot; readers only touch atomic fields.
struct PairSlot {
    state: AtomicU8, // 0 = empty, 1 = live, 2 = deleted
    key: AtomicI64,
    other: AtomicI64,
}

impl PairSlot {
    fn new() -> Self {
        Self {
            state: AtomicU8::new(0),
            key: AtomicI64::new(0),
            other: AtomicI64::new(0),
        }
    }
}

#[repr(align(64))]
struct CachePadded<T>(T);

impl<T> std::ops::Deref for CachePadded<T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.0
    }
}

#[repr(align(64))]
struct ConcurrentShard {
    version: CachePadded<AtomicU64>,
    table: CachePadded<Mutex<Table>>,
    pairs: Vec<PairSlot>,
    pair_count: AtomicUsize,
}

impl ConcurrentShard {
    fn pair_slot(&self, key: i64) -> (Option<usize>, Option<usize>) {
        let start = ((key as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15) >> 8) as usize
            & (self.pairs.len() - 1);
        let mut vacant = None;
        for offset in 0..self.pairs.len() {
            let index = (start + offset) & (self.pairs.len() - 1);
            let slot = &self.pairs[index];
            match slot.state.load(AtomicOrdering::Relaxed) {
                1 if slot.key.load(AtomicOrdering::Relaxed) == key => {
                    return (Some(index), vacant);
                }
                0 => return (None, Some(vacant.unwrap_or(index))),
                2 if vacant.is_none() => vacant = Some(index),
                _ => {}
            }
        }
        (None, vacant)
    }

    fn read_pair(&self, key: i64, multi_epoch: &AtomicU64) -> Option<i64> {
        for _ in 0..4 {
            let multi = multi_epoch.load(AtomicOrdering::Acquire);
            let version = self.version.load(AtomicOrdering::Acquire);
            if multi & 1 != 0 || version & 1 != 0 {
                std::hint::spin_loop();
                continue;
            }
            let (found, _) = self.pair_slot(key);
            let value = found.map(|index| self.pairs[index].other.load(AtomicOrdering::Relaxed));
            fence(AtomicOrdering::SeqCst);
            if self.version.load(AtomicOrdering::Acquire) == version
                && multi_epoch.load(AtomicOrdering::Acquire) == multi
            {
                return value;
            }
        }
        None
    }

    fn write_pair(&self, key: i64, other: i64, table: &mut Table) -> bool {
        let (found, vacant) = self.pair_slot(key);
        if let Some(index) = found {
            self.pairs[index]
                .other
                .store(other, AtomicOrdering::Relaxed);
            return true;
        }
        let Some(index) = vacant else {
            return false;
        };
        // General objects can be replaced by an inline pair at the same key.
        table.delete_key(Term::small(key).unwrap());
        let slot = &self.pairs[index];
        slot.key.store(key, AtomicOrdering::Relaxed);
        slot.other.store(other, AtomicOrdering::Relaxed);
        slot.state.store(1, AtomicOrdering::Relaxed);
        self.pair_count.fetch_add(1, AtomicOrdering::Relaxed);
        true
    }

    fn remove_pair(&self, key: i64) {
        if let (Some(index), _) = self.pair_slot(key) {
            self.pairs[index].state.store(2, AtomicOrdering::Relaxed);
            self.pair_count.fetch_sub(1, AtomicOrdering::Relaxed);
        }
    }
}

impl ConcurrentTable {
    /// Create a table with at least one shard.
    pub fn new(mut options: TableOptions, stripes: usize) -> Result<Self, EtsError> {
        if stripes == 0 {
            return Err(EtsError::BadArg);
        }
        let heir_data = options
            .heir
            .map(|heir| StoredTerm::copy_heap(heir.data))
            .transpose()?;
        if let (Some(heir), Some(data)) = (&mut options.heir, &heir_data) {
            heir.data = data.raw_term().unwrap();
        }
        let mut shards = Vec::with_capacity(stripes);
        let slots_per_shard = (2048 / stripes).max(4).next_power_of_two();
        for index in 0..stripes {
            shards.push(ConcurrentShard {
                version: CachePadded(AtomicU64::new(0)),
                table: CachePadded(Mutex::new(Table::new(Tid(index as u64), options)?)),
                pairs: if options.table_type == TableType::Set {
                    (0..slots_per_shard).map(|_| PairSlot::new()).collect()
                } else {
                    Vec::new()
                },
                pair_count: AtomicUsize::new(0),
            });
        }
        Ok(Self {
            options,
            shards,
            multi_epoch: AtomicU64::new(0),
            concurrent_catree: (options.table_type == TableType::OrderedSet
                && options.write_concurrency != WriteConcurrency::Disabled)
                .then(|| CATree::new(options.keypos, options.read_concurrency)),
            concurrent_hash: (options.table_type != TableType::OrderedSet)
                .then(|| ConcurrentHashStorage::new(options.write_concurrency)),
            _heir_data: heir_data,
        })
    }

    /// Return adaptation counters to the CA-tree validation and benchmark harness.
    #[doc(hidden)]
    pub fn catree_debug_adaptation_counts(
        &self,
    ) -> Option<(usize, usize, usize, usize, usize, Vec<i64>)> {
        self.concurrent_catree.as_ref().map(|tree| {
            let (splits, joins, low_joins, gravity_joins, stats) = tree.adaptation_counts();
            (
                tree.base_count(),
                splits,
                joins,
                low_joins,
                gravity_joins,
                stats,
            )
        })
    }

    fn pair(object: Term, keypos: usize) -> Option<(i64, i64)> {
        let pair = StoredTerm::immediate_pair(object)?;
        Some((pair[keypos - 1].as_small()?, pair[2 - keypos].as_small()?))
    }

    fn pair_hash(key: i64) -> u64 {
        (key as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15)
    }

    fn pair_result<H: HeapAlloc>(
        &self,
        key: i64,
        other: i64,
        dst: &mut H,
    ) -> Result<Vec<Term>, EtsError> {
        let key = Term::small(key).unwrap();
        let other = Term::small(other).unwrap();
        let pair = if self.options.keypos == 1 {
            [key, other]
        } else {
            [other, key]
        };
        Ok(vec![TermBuilder::new(dst).tuple(&pair)?])
    }

    fn stripe(&self, key: Term) -> usize {
        if self.options.table_type == TableType::OrderedSet {
            // Equal numeric keys must share a stripe even when their exact types differ.
            // Complex keys use one stripe because loose equality may be nested within them.
            let hash = if key.classify() == arinsal_term::TermKind::Number {
                let number = if let Some(integer) = integer_value(key) {
                    integer.to_f64().unwrap_or(if integer < BigInt::from(0) {
                        f64::NEG_INFINITY
                    } else {
                        f64::INFINITY
                    })
                } else {
                    // SAFETY: the caller retains the key heap while routing it.
                    unsafe { key.float_ref() }.map_or(0.0, |value| value.get())
                };
                let bits = if number == 0.0 { 0 } else { number.to_bits() };
                let mut mixed = bits ^ (bits >> 30);
                mixed = mixed.wrapping_mul(0xbf58_476d_1ce4_e5b9);
                mixed ^= mixed >> 27;
                mixed = mixed.wrapping_mul(0x94d0_49bb_1331_11eb);
                mixed ^ (mixed >> 31)
            } else if key.classify() == arinsal_term::TermKind::Atom {
                internal_hash(key)
            } else {
                0
            };
            hash as usize % self.shards.len()
        } else {
            let hash = key
                .as_small()
                .map_or_else(|| internal_hash(key), Self::pair_hash);
            (hash >> 32) as usize % self.shards.len()
        }
    }

    /// Insert one object under its shard lock.
    pub fn insert_one(&self, object: Term) -> Result<(), EtsError> {
        let key = key_of(object, self.options.keypos)?;
        if let Some(tree) = &self.concurrent_catree {
            tree.insert(StoredTerm::copy_for_table(
                object,
                self.options.compressed,
                self.options.keypos,
                3,
            )?);
            return Ok(());
        }
        if self.options.table_type == TableType::OrderedSet {
            return self.shards[self.stripe(key)]
                .table
                .lock()
                .unwrap()
                .insert(&[object]);
        }
        if let Some(storage) = &self.concurrent_hash {
            storage.insert(
                StoredTerm::copy_for_table(
                    object,
                    self.options.compressed,
                    self.options.keypos,
                    2,
                )?,
                ets_hash(key),
                self.options.table_type,
                self.options.keypos,
            );
            return Ok(());
        }
        let index = self.stripe(key);
        let shard = &self.shards[index];
        let pair = if self.options.table_type == TableType::Set {
            Self::pair(object, self.options.keypos)
        } else {
            None
        };
        let prepared = if pair.is_none() {
            Some(StoredTerm::copy_for_table(
                object,
                self.options.compressed,
                self.options.keypos,
                2,
            )?)
        } else {
            None
        };
        let mut table = shard.table.lock().unwrap();
        shard.version.fetch_add(1, AtomicOrdering::AcqRel);
        let result = if !pair.is_some_and(|(key, other)| shard.write_pair(key, other, &mut table)) {
            if let Some(key) = key.as_small() {
                shard.remove_pair(key);
            }
            let hash = ets_hash(key);
            prepared
                .map_or_else(
                    || {
                        StoredTerm::copy_for_table(
                            object,
                            self.options.compressed,
                            self.options.keypos,
                            2,
                        )
                    },
                    Ok,
                )
                .map(|object| {
                    table.put_hashed(object, hash, false);
                })
        } else {
            Ok(())
        };
        shard.version.fetch_add(1, AtomicOrdering::Release);
        result
    }

    /// Insert several objects atomically with respect to other table operations.
    pub fn insert(&self, objects: &[Term]) -> Result<(), EtsError> {
        if let Some(tree) = &self.concurrent_catree {
            let prepared = objects
                .iter()
                .map(|&object| {
                    key_of(object, self.options.keypos)?;
                    StoredTerm::copy_for_table(
                        object,
                        self.options.compressed,
                        self.options.keypos,
                        3,
                    )
                })
                .collect::<Result<Vec<_>, _>>()?;
            tree.insert_many(prepared);
            return Ok(());
        }
        if let [object] = objects {
            return self.insert_one(*object);
        }
        if let Some(storage) = &self.concurrent_hash {
            let prepared = objects
                .iter()
                .map(|&object| {
                    key_of(object, self.options.keypos)?;
                    StoredTerm::copy_for_table(
                        object,
                        self.options.compressed,
                        self.options.keypos,
                        2,
                    )
                })
                .collect::<Result<Vec<_>, _>>()?;
            for object in prepared {
                let hash = ets_hash(object.key(self.options.keypos));
                storage.insert(object, hash, self.options.table_type, self.options.keypos);
            }
            return Ok(());
        }
        let prepared = objects
            .iter()
            .map(|&object| -> Result<_, EtsError> {
                key_of(object, self.options.keypos)?;
                Ok((
                    (self.options.table_type == TableType::Set)
                        .then(|| Self::pair(object, self.options.keypos))
                        .flatten(),
                    StoredTerm::copy_for_table(
                        object,
                        self.options.compressed,
                        self.options.keypos,
                        2,
                    )?,
                ))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut guards = self
            .shards
            .iter()
            .map(|shard| shard.table.lock().unwrap())
            .collect::<Vec<_>>();
        self.multi_epoch.fetch_add(1, AtomicOrdering::AcqRel);
        for ((pair, object), &input) in prepared.into_iter().zip(objects) {
            let key = key_of(input, self.options.keypos).unwrap();
            let stripe = self.stripe(key);
            let shard = &self.shards[stripe];
            shard.version.fetch_add(1, AtomicOrdering::AcqRel);
            if !pair.is_some_and(|(key, other)| shard.write_pair(key, other, &mut guards[stripe])) {
                if let Some(key) = key.as_small() {
                    shard.remove_pair(key);
                }
                guards[stripe].put(object);
            }
            shard.version.fetch_add(1, AtomicOrdering::Release);
        }
        self.multi_epoch.fetch_add(1, AtomicOrdering::Release);
        Ok(())
    }

    /// Copy all objects at a key, reading inline pairs optimistically.
    pub fn lookup<H: HeapAlloc>(&self, key: Term, dst: &mut H) -> Result<Vec<Term>, EtsError> {
        if let Some(tree) = &self.concurrent_catree {
            return tree.lookup(key, dst);
        }
        if self.options.table_type == TableType::OrderedSet {
            self.shards[self.stripe(key)]
                .table
                .lock()
                .unwrap()
                .lookup(key, dst)
        } else {
            if let Some(storage) = &self.concurrent_hash {
                return storage.lookup(key, ets_hash(key), self.options.keypos, dst);
            }
            let shard = &self.shards[self.stripe(key)];
            if self.options.table_type == TableType::Set
                && let Some(key) = key.as_small()
                && let Some(other) = shard.read_pair(key, &self.multi_epoch)
            {
                return self.pair_result(key, other, dst);
            }
            let table = shard.table.lock().unwrap();
            if self.options.table_type == TableType::Set
                && let Some(key) = key.as_small()
                && let (Some(index), _) = shard.pair_slot(key)
            {
                let other = shard.pairs[index].other.load(AtomicOrdering::Relaxed);
                return self.pair_result(key, other, dst);
            }
            table.lookup_hashed(key, ets_hash(key), dst)
        }
    }

    /// Check for a key, reading inline pairs optimistically.
    pub fn member(&self, key: Term) -> bool {
        if let Some(tree) = &self.concurrent_catree {
            return tree.member(key);
        }
        if self.options.table_type == TableType::OrderedSet {
            self.shards[self.stripe(key)]
                .table
                .lock()
                .unwrap()
                .member(key)
        } else {
            if let Some(storage) = &self.concurrent_hash {
                return storage.member(key, ets_hash(key), self.options.keypos);
            }
            let shard = &self.shards[self.stripe(key)];
            if self.options.table_type == TableType::Set
                && let Some(key) = key.as_small()
                && shard.read_pair(key, &self.multi_epoch).is_some()
            {
                return true;
            }
            let table = shard.table.lock().unwrap();
            if self.options.table_type == TableType::Set
                && let Some(key) = key.as_small()
                && shard.pair_slot(key).0.is_some()
            {
                return true;
            }
            table.member_hashed(key, ets_hash(key), arinsal_term::current_reader_group())
        }
    }

    /// Delete all objects at a key under its shard lock.
    pub fn delete_key(&self, key: Term) {
        if let Some(tree) = &self.concurrent_catree {
            tree.delete(key);
            return;
        }
        if let Some(storage) = &self.concurrent_hash {
            storage.delete(key, ets_hash(key), self.options.keypos);
            return;
        }
        let shard = &self.shards[self.stripe(key)];
        let mut table = shard.table.lock().unwrap();
        shard.version.fetch_add(1, AtomicOrdering::AcqRel);
        if let Some(key) = key.as_small() {
            shard.remove_pair(key);
        }
        table.delete_key(key);
        shard.version.fetch_add(1, AtomicOrdering::Release);
    }

    /// Count the objects across all stripes.
    pub fn len(&self) -> usize {
        if let Some(tree) = &self.concurrent_catree {
            return tree.count();
        }
        if let Some(storage) = &self.concurrent_hash {
            return storage.len();
        }
        let guards = self
            .shards
            .iter()
            .map(|shard| shard.table.lock().unwrap())
            .collect::<Vec<_>>();
        guards
            .iter()
            .zip(&self.shards)
            .map(|(table, shard)| table.len() + shard.pair_count.load(AtomicOrdering::Relaxed))
            .sum()
    }

    /// Whether the table is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod registry_tests {
    use super::*;

    fn options() -> TableOptions {
        TableOptions {
            name: global_atoms().intern("registry_test").unwrap(),
            named_table: false,
            table_type: TableType::Set,
            keypos: 1,
            protection: Protection::Protected,
            owner: Term::NIL,
            heir: None,
            read_concurrency: false,
            write_concurrency: WriteConcurrency::Disabled,
            decentralized_counters: false,
            compressed: false,
        }
    }

    #[test]
    fn reuses_slots_and_rejects_stale_ids() {
        let mut registry = Registry::new();
        let stale = registry.create(options()).unwrap();
        registry.delete(stale).unwrap();
        for _ in 0..1_000_000 {
            let tid = registry.create(options()).unwrap();
            registry.delete(tid).unwrap();
        }
        assert!(registry.tables.len() <= 2);
        assert!(matches!(registry.get(stale), Err(EtsError::NoTable)));
    }

    #[test]
    fn named_bucket_collisions_survive_rename_and_delete() {
        let index = Arc::new(NamedTableIndex::new());
        let mut registry = Registry::new_with_named_index(Arc::clone(&index));
        let first_name = Atom(0x1234);
        let second_name = Atom(0x1234 + META_NAME_TAB_BUCKET_COUNT as u32);
        let renamed_name = Atom(0x1234 + 2 * META_NAME_TAB_BUCKET_COUNT as u32);
        let mut first_options = options();
        first_options.named_table = true;
        first_options.name = first_name;
        let mut second_options = first_options;
        second_options.name = second_name;

        let first = registry.create(first_options).unwrap();
        let second = registry.create(second_options).unwrap();
        assert!(SharedTable::ptr_eq(
            registry.shared(first).unwrap(),
            &index.lookup(first_name).unwrap()
        ));
        assert!(SharedTable::ptr_eq(
            registry.shared(second).unwrap(),
            &index.lookup(second_name).unwrap()
        ));

        registry.rename(first, renamed_name).unwrap();
        assert!(index.lookup(first_name).is_none());
        assert!(SharedTable::ptr_eq(
            registry.shared(first).unwrap(),
            &index.lookup(renamed_name).unwrap()
        ));
        assert!(SharedTable::ptr_eq(
            registry.shared(second).unwrap(),
            &index.lookup(second_name).unwrap()
        ));

        registry.delete(first).unwrap();
        assert!(index.lookup(renamed_name).is_none());
        assert!(index.lookup(second_name).is_some());
    }
}

#[cfg(test)]
mod stored_size_tests {
    use super::*;

    /// A compressed object without compressed elements is copied out with the size of its
    /// stored tuple. A zero size under-reserves the destination heap and the copy overruns it.
    #[test]
    fn compressed_object_copy_out_reserves_stored_size() {
        let mut source = VecHeap::new();
        let object = TermBuilder::new(&mut source)
            .tuple(&[
                Term::small(0).unwrap(),
                Term::small(7).unwrap(),
                Term::small(1).unwrap(),
            ])
            .unwrap();
        let stored = StoredTerm::copy_for_table(object, true, 2, 1).unwrap();
        let mut out = ObjectHeap::new();
        let copy = stored.copy_out(&mut out).unwrap();
        let reserved: usize = out.words.iter().map(|words| words.len()).sum();
        assert_eq!(reserved, arinsal_term::size_object(copy));
    }

    /// `copy_shallow` of a stored block equals the structural copy for every plain term kind,
    /// and objects that need owner links (reference-counted binaries, magic references) are
    /// not shallow-copied.
    #[test]
    fn shallow_copy_out_matches_structural_copy() {
        use arinsal_term::{ExportEntry, FunEntry};
        let module = global_atoms().intern("erlang").unwrap();
        let function = global_atoms().intern("length").unwrap();
        let fun_entry = Arc::new(FunEntry {
            dispatch_target: Default::default(),
            pend_purge_address: Default::default(),
            module,
            arity: 1,
            index: 3,
            uniq: [7; 16],
            old_uniq: 9,
            old_index: 2,
            pid: Term::pid(4, 0).unwrap(),
            dispatch: Default::default(),
            dispatch_code: Default::default(),
            dispatch_epoch: Default::default(),
        });
        let key = Term::small(1).unwrap();
        let mut source = VecHeap::new();
        let mut cases: Vec<(&str, Term, bool)> = Vec::new();
        macro_rules! object {
            ($name:expr, $shallow:expr, |$b:ident| $element:expr) => {{
                let element = {
                    let mut $b = TermBuilder::new(&mut source);
                    $element
                };
                let object = TermBuilder::new(&mut source)
                    .tuple(&[key, element])
                    .unwrap();
                cases.push(($name, object, $shallow));
            }};
        }
        object!("immediates", true, |b| b
            .tuple(&[Term::small(7).unwrap(), Term::NIL])
            .unwrap());
        object!("list", true, |b| b
            .list_from_slice(&[Term::small(1).unwrap(), Term::small(2).unwrap()])
            .unwrap());
        object!("float", true, |b| b.float(1.5).unwrap());
        object!("bignum", true, |b| b.int_from_i128(1 << 100).unwrap());
        object!("heap binary", true, |b| b.binary(b"abc").unwrap());
        object!("refc binary", false, |b| b.binary(&[7u8; 200]).unwrap());
        object!("ordinary reference", true, |b| b
            .local_ref([1, 2, 3])
            .unwrap());
        object!("flatmap", true, |b| {
            let inner = b.tuple(&[Term::small(5).unwrap()]).unwrap();
            b.flatmap_from_pairs(&[(Term::small(1).unwrap(), inner)])
                .unwrap()
        });
        object!("nested", true, |b| {
            let inner = b.tuple(&[Term::small(5).unwrap(), Term::NIL]).unwrap();
            let list = b
                .list_from_slice(&[inner, Term::small(9).unwrap()])
                .unwrap();
            b.tuple(&[list, inner]).unwrap()
        });
        object!("empty tuple", true, |b| b.tuple(&[]).unwrap());
        object!("local fun", true, |b| b
            .local_fun(&fun_entry, &[Term::small(42).unwrap()])
            .unwrap());
        object!("export fun", true, |b| b
            .export_fun(Arc::new(ExportEntry::new(module, function, 1)))
            .unwrap());
        for (name, object, shallow) in cases {
            let stored = StoredTerm::copy_for_table(object, false, 1, 1).unwrap();
            assert_eq!(stored.shallow, shallow, "{name}: shallow flag");
            let mut out = VecHeap::new();
            let copy = stored.copy_out(&mut out).unwrap();
            assert_eq!(
                arinsal_term::to_owned(copy).unwrap(),
                arinsal_term::to_owned(object).unwrap(),
                "{name}"
            );
            assert!(exact_eq(copy, object), "{name}: exact equality");
            if shallow {
                let mut reserved = ObjectHeap::new();
                stored.copy_out(&mut reserved).unwrap();
                let words: usize = reserved.words.iter().map(|w| w.len()).sum();
                assert_eq!(words, stored.term_size_words, "{name}: reserved words");
            }
        }
    }
}
