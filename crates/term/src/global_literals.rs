//! Global literals: terms that are never modified or deleted, built once in shared literal
//! chunks (the empty tuple, the bitstring of every atom name, `os_type`, `os_version`, the
//! distribution flag record and the `".erl"` suffix).
//!
//! Port of erts/emulator/beam/erl_global_literals.c and .h, OTP-29.1.1. One lock,
//! `global_literal_lock`, is taken in [`global_literal_allocate`] and released in
//! [`GlobalLiteralBuild::register`]; it protects the bump pointer of the newest chunk while a
//! literal is built. Readers of the `ERTS_GLOBAL_LIT_*` slots take no lock, and the words of a
//! chunk are written without any lock through the stable chunk pointer.
use crate::bits::RefcBinary;
use crate::heap::{HeapAlloc, store};
use crate::literal::{LiteralChunk, allocate_chunk};
use crate::{ARITY, Term, TermError};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, Once};

/// `GLOBAL_LITERAL_INITIAL_SIZE`, in words.
const GLOBAL_LITERAL_INITIAL_SIZE: usize = 1 << 16;
/// `GLOBAL_LITERAL_EXPAND_SIZE`, in words.
const GLOBAL_LITERAL_EXPAND_SIZE: usize = 512;

// The global constant literals (`ERTS_WRITE_UNLIKELY(ERTS_GLOBAL_LIT_*)`); 0 is THE_NON_VALUE.
static ERTS_GLOBAL_LIT_OS_TYPE: AtomicU64 = AtomicU64::new(0);
static ERTS_GLOBAL_LIT_OS_VERSION: AtomicU64 = AtomicU64::new(0);
static ERTS_GLOBAL_LIT_DFLAGS_RECORD: AtomicU64 = AtomicU64::new(0);
static ERTS_GLOBAL_LIT_ERL_FILE_SUFFIX: AtomicU64 = AtomicU64::new(0);
static ERTS_GLOBAL_LIT_EMPTY_TUPLE: AtomicU64 = AtomicU64::new(0);

/// One `struct global_literal_chunk`: `area.start`/`area.end`/`area.off_heap` live in the two
/// header words of the literal chunk, `end` mirrors `area.end` as a word offset.
struct GlobalLiteralChunk {
    chunk: LiteralChunk,
    end: usize,
}

impl GlobalLiteralChunk {
    fn new(words: usize) -> Self {
        let chunk = allocate_chunk(words).expect("global literal area");
        #[cfg(any(feature = "validate-terms", debug_assertions, test))]
        crate::validate::note_stable_range(chunk.as_ptr() as usize, chunk.capacity() * 8);
        let this = Self { chunk, end: 0 };
        this.publish_end();
        this
    }

    /// `area.end = &area.start[end]`.
    fn publish_end(&self) {
        store(
            self.chunk.as_ptr().wrapping_sub(1),
            self.chunk.as_ptr().wrapping_add(self.end) as u64,
        );
    }

    fn off_heap_slot(&self) -> *mut u64 {
        self.chunk.as_ptr().wrapping_sub(2)
    }
}

/// `global_literal_chunk` list, newest last, behind `global_literal_lock`.
static GLOBAL_LITERAL_LOCK: Mutex<Vec<GlobalLiteralChunk>> = Mutex::new(Vec::new());

/// A literal under construction: the words reserved by [`global_literal_allocate`] with the
/// lock held. Implements [`HeapAlloc`] so terms are built with the ordinary builders.
pub struct GlobalLiteralBuild {
    chunks: MutexGuard<'static, Vec<GlobalLiteralChunk>>,
    reserved: usize,
    used: usize,
}

/// Allocate space for a global literal of at most `heap_size` words; the caller must call
/// [`GlobalLiteralBuild::register`] when done.
// Port of erl_global_literals.c (erts_global_literal_allocate, expand_shared_global_literal_area).
pub fn global_literal_allocate(heap_size: usize) -> GlobalLiteralBuild {
    let mut chunks = GLOBAL_LITERAL_LOCK.lock().expect("global literal lock");
    let current = chunks.last().expect("init_global_literals ran");
    if current.chunk.capacity() - current.end < heap_size {
        chunks.push(GlobalLiteralChunk::new(
            heap_size + GLOBAL_LITERAL_EXPAND_SIZE,
        ));
    }
    GlobalLiteralBuild {
        chunks,
        reserved: heap_size,
        used: 0,
    }
}

impl GlobalLiteralBuild {
    /// Register `term`, built in this allocation, as a global literal and release the lock.
    // Port of erl_global_literals.c (erts_global_literal_register). Arinsal literals are
    // recognised by address range, so there is no tag to set; the build size is the words
    // actually used.
    pub fn register(mut self, term: Term) -> Term {
        let chunk = self.chunks.last_mut().expect("global literal chunk");
        let start = chunk.chunk.as_ptr().wrapping_add(chunk.end) as u64;
        debug_assert!(
            term.is_immed()
                || (term.bits() & !7 >= start
                    && (term.bits() & !7) < start + (self.used as u64) * 8)
        );
        chunk.end += self.used;
        chunk.publish_end();
        term
    }
}

impl HeapAlloc for GlobalLiteralBuild {
    fn alloc(&mut self, words: usize) -> Option<*mut u64> {
        let needed = self.used.checked_add(words)?;
        if needed > self.reserved {
            return None;
        }
        let chunk = self.chunks.last()?;
        let ptr = chunk.chunk.as_ptr().wrapping_add(chunk.end + self.used);
        self.used = needed;
        Some(ptr)
    }

    fn retain_binary(&mut self, binary: Arc<RefcBinary>) {
        drop(binary);
    }

    fn link_bin_ref(
        &mut self,
        bin_ref: *mut u64,
        _writable: bool,
        _overhead_words: u64,
        owner: Option<arinsal_alloc::raw::OwnedBinaryRef>,
    ) -> Result<(), TermError> {
        // `literal_ohp = &area.off_heap`: the chunk's own off-heap list.
        let slot = self
            .chunks
            .last()
            .ok_or(TermError::SystemLimit)?
            .off_heap_slot();
        store(bin_ref.wrapping_add(2), crate::heap::load(slot));
        store(slot, bin_ref as u64);
        if let Some(owner) = owner {
            owner.transfer_to_bin_ref(bin_ref);
        }
        Ok(())
    }

    fn link_node(&mut self, thing: *mut u64, node: Arc<crate::Node>) {
        let slot = self
            .chunks
            .last()
            .expect("global literal chunk")
            .off_heap_slot();
        let mut head = crate::heap::load(slot) as usize;
        crate::heap::link_node_thing(&mut head, thing, node);
        store(slot, head as u64);
    }
}

/// Iterate the global literal areas newest first as `(start, end)` word addresses; pass the
/// `start` of the previous area, `None` to begin. For crash dumps.
// Port of erl_global_literals.c (erts_global_literal_iterate_area).
pub fn global_literal_iterate_area(prev: Option<usize>) -> Option<(usize, usize)> {
    let chunks = GLOBAL_LITERAL_LOCK.lock().expect("global literal lock");
    let at = match prev {
        None => chunks.len(),
        Some(start) => chunks
            .iter()
            .position(|chunk| chunk.chunk.as_ptr() as usize == start)?,
    };
    let chunk = chunks.get(at.checked_sub(1)?)?;
    let start = chunk.chunk.as_ptr() as usize;
    Some((start, start + chunk.end * 8))
}

static INIT: Once = Once::new();

/// Create the first global literal chunk and the empty tuple.
///
/// erts runs `init_global_literals` once from `erl_init`, before `init_atom_table`. Here the
/// atom table setup (`global_atoms`) calls it, and so must any code that runs without it (a
/// test building its own atom table); the `Once` is the process-lifetime guard of a VM that
/// can boot more than once in one process. Readers of a slot never call it.
// Port of erl_global_literals.c (init_global_literals, init_empty_tuple), OTP-29.1.1.
pub fn init_global_literals() {
    INIT.call_once(|| {
        GLOBAL_LITERAL_LOCK
            .lock()
            .expect("global literal lock")
            .push(GlobalLiteralChunk::new(GLOBAL_LITERAL_INITIAL_SIZE));
        let mut build = global_literal_allocate(2);
        let hp = build.alloc(2).expect("empty tuple words");
        store(hp, ARITY);
        store(hp.wrapping_add(1), ARITY);
        let tuple = build.register(Term::from_ptr(hp, 2));
        ERTS_GLOBAL_LIT_EMPTY_TUPLE.store(tuple.bits(), Ordering::Relaxed);
    });
}

#[inline(always)]
fn read(slot: &AtomicU64) -> Term {
    crate::raw::term_from_bits(slot.load(Ordering::Relaxed))
}

/// `ERTS_GLOBAL_LIT_EMPTY_TUPLE`.
#[inline(always)]
pub fn global_empty_tuple() -> Term {
    read(&ERTS_GLOBAL_LIT_EMPTY_TUPLE)
}

/// `ERTS_GLOBAL_LIT_ERL_FILE_SUFFIX`: the list `".erl"`.
#[inline(always)]
pub fn global_erl_file_suffix() -> Term {
    read(&ERTS_GLOBAL_LIT_ERL_FILE_SUFFIX)
}

/// `ERTS_GLOBAL_LIT_OS_TYPE`.
#[inline(always)]
pub fn global_os_type() -> Term {
    read(&ERTS_GLOBAL_LIT_OS_TYPE)
}

/// `ERTS_GLOBAL_LIT_OS_VERSION`.
#[inline(always)]
pub fn global_os_version() -> Term {
    read(&ERTS_GLOBAL_LIT_OS_VERSION)
}

/// `ERTS_GLOBAL_LIT_DFLAGS_RECORD`.
#[inline(always)]
pub fn global_dflags_record() -> Term {
    read(&ERTS_GLOBAL_LIT_DFLAGS_RECORD)
}

/// `ERTS_GLOBAL_LIT_ERL_FILE_SUFFIX = suffix` (`beamfile_init`).
pub fn set_global_erl_file_suffix(term: Term) {
    ERTS_GLOBAL_LIT_ERL_FILE_SUFFIX.store(term.bits(), Ordering::Relaxed);
}

/// `ERTS_GLOBAL_LIT_OS_TYPE = tuple` (`os_info_init`).
pub fn set_global_os_type(term: Term) {
    ERTS_GLOBAL_LIT_OS_TYPE.store(term.bits(), Ordering::Relaxed);
}

/// `ERTS_GLOBAL_LIT_OS_VERSION = tuple` (`os_info_init`).
pub fn set_global_os_version(term: Term) {
    ERTS_GLOBAL_LIT_OS_VERSION.store(term.bits(), Ordering::Relaxed);
}

/// `ERTS_GLOBAL_LIT_DFLAGS_RECORD = tuple` (`init_dist`).
pub fn set_global_dflags_record(term: Term) {
    ERTS_GLOBAL_LIT_DFLAGS_RECORD.store(term.bits(), Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::global_atoms;

    #[test]
    fn slots_live_in_the_literal_range_and_atom_names_point_into_it() {
        let _ = global_atoms();
        let empty = global_empty_tuple();
        assert!(crate::literal::is_literal_address(
            (empty.bits() & !7) as usize
        ));
        let (start, end) = global_literal_iterate_area(None).unwrap();
        assert!(start < end);
        let name = global_atoms().intern("global_literals_probe_atom").unwrap();
        let bin = global_atoms().utf8_literal(name).unwrap();
        let bytes = crate::raw::BinRef::try_from(bin).unwrap().bytes().unwrap();
        assert!(crate::literal::is_literal_address(bytes.as_ptr() as usize));
        assert_eq!(bytes, b"global_literals_probe_atom");
    }
}
