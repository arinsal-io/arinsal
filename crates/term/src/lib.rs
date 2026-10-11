//! OTP 29 tagged words and heap-backed runtime terms.
mod atom;
mod bits;
mod copy;
mod fun;
mod gc;
mod hamt;
mod hamt_yield;
mod hash;
mod heap;
mod identity;
mod internal_hash;
mod literal;
mod magic;
mod ops;
mod owned;
pub mod ptab;
mod record;
mod record_table;
mod region;
pub mod validate;
mod views;

mod native_code;

pub use atom::{Atom, AtomError, AtomTable, atoms, global_atoms};
pub use bits::{
    ExternalBinary, RefcBinary, SUB_BITS_MUTABLE, SUB_BITS_VOLATILE, WritableBinary,
    binary_memory_bytes, binary_offset_adjustment, erts_bs_private_append_checked,
    erts_bs_private_append_fast, install_private_append_overhead, is_match_context,
    is_writable_binary, match_position, set_match_position, sub_bits_flags, writable_bytes_mut,
    writable_capacity, writable_extend_private, writable_finalize, writable_gc_visit,
};
pub use copy::{
    SharedCopyCache, copy_shared, copy_term, copy_term_litopt, copy_term_preserving_sharing,
    copy_term_preserving_sharing_with_cache,
};
pub use fun::{
    ERTS_ADDRESSV_SIZE, ERTS_NUM_CODE_IX, ERTS_SAVE_CALLS_CODE_IX, EXPORT_INFO_OFFSET,
    ErtsDispatchable, ExportEntry, ExportStubFn, FunEntry, FunRef, beam_unloaded_fun,
    export_get_or_make_stub, set_export_stub_hook, set_fun_dispatch_fragments,
};
pub use gc::{
    FragmentAlloc, FragmentIndex, GcStats, set_gc_clock_for_long_gc, set_gc_clock_for_msacc,
};
pub use hamt::{
    HxNode, alloc_terms, boxed_object_words, build_hamt_from_unique, flatmap_keys,
    hashmap_from_ks_and_vs, hashmap_from_ks_and_vs_extra, hashmap_from_unsorted_array,
    hashmap_key_hash, hashmap_leaves, hashmap_leaves_hashed, hashmap_node_children,
    swizzle_map_hash,
};
pub use hamt_yield::{HashmapBuild, MapReverseIter};
pub use hash::{make_hash, make_hash2, phash, phash2, phash2_range};
pub use heap::{
    AdoptError, BinaryRef, CP_WORDS, ConsHeapBuilder, ConsHeapChain, FrameLayout, HeapAlloc,
    HeapReservation, LiteralArea, ProcessHeap, S_REDZONE, S_RESERVED, StackWord, TermBuilder,
    Tuple3Chain, VecHeap, flat_key_cmp,
};
pub use identity::{Identity, Node};
pub use internal_hash::{immediate_internal_hash, internal_hash, internal_salted_hash};
pub use literal::{LiteralAreas, set_literal_purge_area};
pub use magic::MagicRef;
pub use native_code::{
    is_native_code_pointer, may_be_native_code_pointer, register_native_code_range,
    unregister_native_code_range,
};
pub use ops::{
    cmp, cmp_exact, exact_eq, flat_size, integer_magnitude_cmp, loose_eq, size_object,
    size_object_litopt, size_object_preserving_sharing, size_object_preserving_sharing_after,
    size_shared, small_add, small_mul, small_sub,
};
pub use owned::{from_owned, to_owned};
pub use record::{RecordRef, RecordSnapshot, record_map_pairs, term_sequence};
pub use record_table::{
    delete_module_record_definitions, drop_record_scope, find_record_definition_in,
    put_record_definition, set_record_scope,
};
pub use region::{
    BuiltList, DEFAULT_REGION_LIST_CONS, GrowingList, RegionBuilder, RegionRoots,
    SEND_COPY_LIMIT_WORDS, SharedRoot, is_region_term, region_owner, seal_for_send,
};
pub use views::{BigRef, FlatMapRef, FloatRef, ListIter};

use std::fmt;

/// A runtime term is exactly one 64-bit tagged word. Pointer-bearing terms are
/// valid only while their owning heap remains alive and unmoved.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Term(pub(crate) u64);

/// Small integer lower bound (60-bit signed payload).
pub const MIN_SMALL: i64 = -(1_i64 << 59);
/// Small integer upper bound (60-bit signed payload).
pub const MAX_SMALL: i64 = (1_i64 << 59) - 1;
/// Reserved header subtag for a future shared term (ADR 0003).
pub const SHARED_SUBTAG: u64 = 0x04;

pub(crate) const ARITY: u64 = 0x00;
pub(crate) static EMPTY_TUPLE: u64 = 0;

/// The global literal empty tuple (erts `ERTS_GLOBAL_LIT_EMPTY_TUPLE`). Collections treat
/// it as a literal, so every empty tuple shared outside a heap must be this one.
// Port of erts/emulator/beam/erl_global_literals.h (ERTS_GLOBAL_LIT_EMPTY_TUPLE), OTP-29.1.1.
pub fn global_empty_tuple() -> Term {
    Term::from_ptr(std::ptr::from_ref(&EMPTY_TUPLE).cast_mut(), 2)
}
pub(crate) const POS_BIG: u64 = 0x08;
pub(crate) const NEG_BIG: u64 = 0x0c;
pub(crate) const REF: u64 = 0x10;
pub(crate) const FUN: u64 = 0x14;
pub(crate) const FLOAT: u64 = 0x18;
pub(crate) const RECORD: u64 = 0x1c;
pub(crate) const HEAP_BITS: u64 = 0x20;
pub(crate) const SUB_BITS: u64 = 0x24;
pub(crate) const BIN_REF: u64 = 0x28;
pub(crate) const MAP: u64 = 0x2c;
pub(crate) const EXTERNAL_PID: u64 = 0x30;
pub(crate) const EXTERNAL_PORT: u64 = 0x34;
pub(crate) const EXTERNAL_REF: u64 = 0x38;
/// `ERTS_REF_THING_HEADER`: ordinary and magic refs share this header on 64-bit little endian.
// Port of erts/emulator/beam/erl_term.h:998 (ERTS_REF_THING_HEADER), OTP-29.1.1.
pub(crate) const REF_THING_HEADER: u64 = (2 << 6) | REF;
// Port of erts/emulator/beam/erl_term.h:794 (ERTS_ORDINARY_REF_MARKER), OTP-29.1.1.
pub(crate) const ORDINARY_REF_MARKER: u32 = u32::MAX;

/// Whether a REF thing is an `ErtsMRefThing`: the low half of word one is the ordinary
/// marker or the low bits of the aligned magic binary pointer.
// Port of erts/emulator/beam/erl_term.h:1017-1019 (is_magic_ref_thing_with_hdr), OTP-29.1.1.
#[inline]
pub(crate) const fn is_magic_ref_thing_with_hdr(header: u64, word1: u64) -> bool {
    header == REF_THING_HEADER && word1 as u32 != ORDINARY_REF_MARKER
}

/// Coarse type tag, ordered according to Erlang term order.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum TermKind {
    /// Integer or float.
    Number,
    /// Atom.
    Atom,
    /// Reference.
    Ref,
    /// Function.
    Fun,
    /// Port.
    Port,
    /// Process identifier.
    Pid,
    /// Tuple.
    Tuple,
    /// Native record.
    Record,
    /// Map.
    Map,
    /// Empty list.
    Nil,
    /// Cons cell.
    List,
    /// Bitstring.
    Bitstring,
    /// Internal bin ref, never exposed as an Erlang value.
    BinRef,
    /// Catch tag used by the interpreter.
    Catch,
    /// Header or invalid word.
    Invalid,
}

/// Construction failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TermError {
    /// The heap has no space; the interpreter can trigger collection.
    HeapFull,
    /// The value or encoding exceeds a runtime limit.
    SystemLimit,
    /// A value is invalid for this constructor.
    BadArg,
    /// A representation belongs to a future task.
    Unsupported(&'static str),
}

impl Term {
    /// The empty list immediate.
    pub const NIL: Self = Self(0x3b);
    /// Tagged small integer if the 60-bit payload is in range.
    #[inline]
    pub const fn small(value: i64) -> Option<Self> {
        if value < MIN_SMALL || value > MAX_SMALL {
            None
        } else {
            Some(Self(((value as u64) << 4) | 0x0f))
        }
    }
    /// Tagged atom index.
    #[inline]
    pub const fn atom(atom: Atom) -> Self {
        Self(((atom.0 as u64) << 6) | 0x0b)
    }
    /// Tagged catch stack entry.
    #[inline]
    pub const fn catch(index: u64) -> Self {
        Self((index << 6) | 0x1b)
    }
    /// Local pid from its number (28 bits) and serial (32 bits).
    ///
    /// Port of erts/emulator/beam/erl_node_container_utils.h:123 (make_internal_pid)
    /// and erl_term.h:655 (make_pid_data), OTP-29.1.1.
    #[inline]
    pub fn pid(number: u32, serial: u32) -> Option<Self> {
        if number > ptab::MAX_INTERNAL_PID_NUMBER {
            None
        } else {
            Some(Self::pid_from_data(
                ((serial as u64) << ptab::PID_NUM_SIZE) | number as u64,
            ))
        }
    }
    /// Local pid from its 60-bit process-table data.
    #[inline]
    pub fn pid_from_data(data: u64) -> Self {
        let pixdata = ptab::process_table_layout().data2pixdata(data & ptab::PTAB_ID_DATA_MASK);
        Self((pixdata << 4) | 3)
    }
    /// Local port from its 60-bit port number (port-table data).
    ///
    /// Port of erts/emulator/beam/erl_node_container_utils.h:250 (make_internal_port), OTP-29.1.1.
    #[inline]
    pub fn port(id: u64) -> Option<Self> {
        if id > ptab::PTAB_ID_DATA_MASK {
            None
        } else {
            Some(Self((ptab::port_table_layout().data2pixdata(id) << 4) | 7))
        }
    }
    /// Return the tagged bits inside this crate.
    #[inline]
    pub(crate) const fn bits(self) -> u64 {
        self.0
    }
    /// Return the tagged word as an opaque integer.
    ///
    /// Pointer-bearing values still require their heap to remain alive before
    /// the word is passed to code that may dereference it.
    #[inline]
    pub const fn tagged_word(self) -> u64 {
        self.0
    }
    /// Expose the raw tagged word, which may contain a heap address.
    ///
    /// # Safety
    /// Pointer-bearing terms must not outlive their heap or be reused as an
    /// address without ensuring the heap stays alive and unmoved.
    #[inline]
    pub const unsafe fn raw_bits(self) -> u64 {
        self.0
    }
    /// Reconstruct a term from its raw 64-bit representation.
    ///
    /// # Safety
    /// Pointer-bearing terms must refer to live storage owned by the caller.
    #[inline]
    pub const unsafe fn from_raw_bits(bits: u64) -> Self {
        Self(bits)
    }
    /// Extract a small integer.
    #[inline]
    pub const fn as_small(self) -> Option<i64> {
        if self.0 & 15 == 15 {
            Some((self.0 as i64) >> 4)
        } else {
            None
        }
    }
    /// Extract an atom index.
    #[inline]
    pub const fn as_atom(self) -> Option<Atom> {
        if self.0 & 63 == 11 {
            Some(Atom((self.0 >> 6) as u32))
        } else {
            None
        }
    }
    /// Extract a local pid's number and serial.
    ///
    /// Port of erts/emulator/beam/erl_node_container_utils.h:134 (internal_pid_number,
    /// internal_pid_serial), OTP-29.1.1.
    #[inline]
    pub fn as_pid(self) -> Option<(u32, u32)> {
        let data = self.as_pid_data()?;
        Some((
            (data & ptab::MAX_INTERNAL_PID_NUMBER as u64) as u32,
            (data >> ptab::PID_NUM_SIZE) as u32,
        ))
    }
    /// Extract a local pid's 60-bit process-table data.
    #[inline]
    pub fn as_pid_data(self) -> Option<u64> {
        if self.0 & 15 == 3 {
            Some(ptab::process_table_layout().pixdata2data(self.0 >> 4))
        } else {
            None
        }
    }
    /// Extract a local port number.
    ///
    /// Port of erts/emulator/beam/erl_node_container_utils.h:205 (internal_port_number), OTP-29.1.1.
    #[inline]
    pub fn as_port(self) -> Option<u64> {
        if self.0 & 15 == 7 {
            Some(ptab::port_table_layout().pixdata2data(self.0 >> 4))
        } else {
            None
        }
    }
    /// Whether this is an immediate (primary tag 3).
    ///
    /// Port of erts/emulator/beam/erl_term.h:179 (is_immed), OTP-29.1.1.
    #[inline]
    pub const fn is_immed(self) -> bool {
        self.0 & 3 == 3
    }
    /// Whether this is a heap pointer, including a cons pointer.
    #[inline]
    pub const fn is_pointer(self) -> bool {
        self.0 & 3 == 1 || self.0 & 3 == 2
    }
    /// Whether this is a hashmap head (reserved for the HAMT task).
    pub fn is_hashmap(self) -> bool {
        self.header()
            .is_some_and(|h| h & 63 == MAP && h & 0xc0 != 0)
    }
    /// Classify a valid term without allocating.
    pub fn classify(self) -> TermKind {
        if self.as_small().is_some() {
            return TermKind::Number;
        }
        if self.as_atom().is_some() {
            return TermKind::Atom;
        }
        match self.0 & 3 {
            1 => TermKind::List,
            2 => match self.header().unwrap_or(0) & 63 {
                ARITY => TermKind::Tuple,
                POS_BIG | NEG_BIG | FLOAT => TermKind::Number,
                REF | EXTERNAL_REF => TermKind::Ref,
                FUN => TermKind::Fun,
                EXTERNAL_PORT => TermKind::Port,
                EXTERNAL_PID => TermKind::Pid,
                RECORD => TermKind::Record,
                MAP => TermKind::Map,
                HEAP_BITS | SUB_BITS => TermKind::Bitstring,
                BIN_REF => TermKind::BinRef,
                _ => TermKind::Invalid,
            },
            3 => match self.0 & 63 {
                0x3b => TermKind::Nil,
                0x1b => TermKind::Catch,
                _ if self.0 & 15 == 3 => TermKind::Pid,
                _ if self.0 & 15 == 7 => TermKind::Port,
                _ => TermKind::Invalid,
            },
            _ => TermKind::Invalid,
        }
    }
    /// Read a boxed header. The term must still belong to a live, stable heap.
    #[inline]
    pub fn header(self) -> Option<u64> {
        if self.0 & 3 != 2 {
            return None;
        }
        // SAFETY: TermBuilder creates boxed terms from allocated, aligned words.
        Some(unsafe { *self.raw_ptr() })
    }
    /// Return the number of 64-bit digits in a boxed bignum.
    #[inline]
    pub fn bignum_digit_count(self) -> Option<usize> {
        let header = self.header()?;
        match header & 63 {
            POS_BIG | NEG_BIG => Some((header >> 6) as usize),
            _ => None,
        }
    }
    /// Whether a boxed term is an internal magic reference.
    #[inline]
    pub fn is_magic_ref(self) -> bool {
        self.header() == Some(REF_THING_HEADER) && {
            // SAFETY: a REF thing of arity two has an initialized word one.
            let word1 = unsafe { *self.raw_ptr().add(1) };
            is_magic_ref_thing_with_hdr(REF_THING_HEADER, word1)
        }
    }
    /// Access a raw heap pointer. Caller must ensure its owner is live and
    /// prevent concurrent mutation or movement for the duration of access.
    ///
    /// # Safety
    /// The pointer must belong to a live, stable heap allocation.
    #[inline]
    pub unsafe fn raw_ptr(self) -> *const u64 {
        (self.0 & !7) as *const u64
    }
    /// The tuple's elements, valid for the lifetime of the owning heap.
    ///
    /// # Safety
    /// The heap must outlive the returned view and must not move.
    #[inline]
    pub unsafe fn tuple_ref<'a>(self) -> Option<TupleRef<'a>> {
        let h = self.header()?;
        if h & 63 != ARITY {
            return None;
        }
        let len = (h >> 6) as usize;
        // SAFETY: Header arity describes this live allocation; caller holds heap stable.
        let elements = unsafe { std::slice::from_raw_parts(self.raw_ptr().add(1), len) };
        Some(TupleRef { elements })
    }
    /// The cons cell's head and tail.
    ///
    /// # Safety
    /// The heap must remain live and unmoved.
    #[inline]
    pub unsafe fn cons_ref(self) -> Option<(Term, Term)> {
        if self.0 & 3 != 1 {
            return None;
        }
        // SAFETY: A list pointer denotes two initialized words on a live heap.
        let p = unsafe { self.raw_ptr() };
        // SAFETY: See the cell invariant above.
        Some(unsafe { (Term(*p), Term(*p.add(1))) })
    }
    pub(crate) fn from_ptr(ptr: *mut u64, tag: u64) -> Self {
        Self((ptr as u64) | tag)
    }
}

/// A borrowed tuple element array.
pub struct TupleRef<'a> {
    elements: &'a [u64],
}
impl TupleRef<'_> {
    /// Number of elements.
    pub fn len(&self) -> usize {
        self.elements.len()
    }
    /// Whether empty.
    pub fn is_empty(&self) -> bool {
        self.elements.is_empty()
    }
    /// Read an element.
    #[inline]
    pub fn get(&self, index: usize) -> Option<Term> {
        self.elements.get(index).copied().map(Term)
    }
    /// Read a tuple element without copying the tuple's element array.
    #[inline]
    pub fn element(&self, index: usize) -> Option<Term> {
        self.get(index)
    }
    /// Iterate elements in order.
    pub fn iter(&self) -> impl Iterator<Item = Term> + '_ {
        self.elements.iter().copied().map(Term)
    }
}

impl fmt::Debug for Term {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(n) = self.as_small() {
            return write!(f, "{n}");
        }
        if let Some(atom) = self.as_atom() {
            return write!(
                f,
                "{}",
                global_atoms().text(atom).unwrap_or("<unknown atom>")
            );
        }
        if *self == Term::NIL {
            return write!(f, "[]");
        }
        write!(f, "<{:?}:0x{:x}>", self.classify(), self.0)
    }
}
impl fmt::Display for Term {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}
