//! Pure BIFs implemented against stable heap terms.

use std::cmp::Ordering;
use std::sync::Arc;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

use arinsal_term::{
    AtomEncoding, AtomError, BinaryRef, ExternalBinary, HeapAlloc, MagicRef, Node, Term,
    TermBuilder, TermError, TermKind, atoms, cmp, copy_term, exact_eq, flat_size, global_atoms,
    loose_eq, phash,
};
use num_bigint::{BigInt, Sign};
use num_traits::{FromPrimitive, ToPrimitive};
use smallvec::{SmallVec, smallvec};

use crate::{BifError, Class, Ctx};

#[path = "binary_bifs.rs"]
mod binary_bifs;
pub use binary_bifs::{
    BinarySearchKind, BinarySearchWalk, BinaryToListWalk, IolistCopyWalk, IolistVecWalk,
    allocate_iolist_binary, binary_part_2, finish_iolist_binary_output, iolist_to_iovec_shortcut,
    iolist_yield_reductions, with_iolist_binary_output,
};

const BADARG: BifError = BifError::BADARG;

use crate::unique::next_ref_words;
pub use crate::unique::{next_ref_id, next_unique_monotonic};

pub(super) struct Heap<'a, H: HeapAlloc + ?Sized>(pub(super) &'a mut H);
impl<H: HeapAlloc + ?Sized> HeapAlloc for Heap<'_, H> {
    fn alloc(&mut self, words: usize) -> Option<*mut u64> {
        self.0.alloc(words)
    }
    fn alloc_with_extra(&mut self, words: usize, extra: usize) -> Option<*mut u64> {
        self.0.alloc_with_extra(words, extra)
    }
    fn alloc_fragment_only(&mut self, words: usize) -> Option<*mut u64> {
        self.0.alloc_fragment_only(words)
    }
    fn words_left(&self) -> Option<usize> {
        self.0.words_left()
    }
    fn release(&mut self, end: *mut u64, start: *mut u64) {
        self.0.release(end, start)
    }
    fn release_needs_filler(&self, end: *mut u64, start: *mut u64) -> bool {
        self.0.release_needs_filler(end, start)
    }
    fn retain_binary(&mut self, value: Arc<arinsal_term::RefcBinary>) {
        self.0.retain_binary(value)
    }
    fn link_bin_ref(
        &mut self,
        bin_ref: *mut u64,
        writable: bool,
        overhead_words: u64,
        owner: Option<arinsal_term::OwnedBinaryRef>,
    ) -> Result<(), TermError> {
        HeapAlloc::link_bin_ref(self.0, bin_ref, writable, overhead_words, owner)
    }
    fn add_bin_vheap(&mut self, words: u64) {
        HeapAlloc::add_bin_vheap(self.0, words)
    }
    fn retain_writable_binary(
        &mut self,
        value: Arc<arinsal_term::WritableBinary>,
    ) -> Result<(), arinsal_term::TermError> {
        self.0.retain_writable_binary(value)
    }
    fn retain_writable_binary_with_apparent_size(
        &mut self,
        value: Arc<arinsal_term::WritableBinary>,
        apparent_size_bits: usize,
    ) -> Result<(), arinsal_term::TermError> {
        self.0
            .retain_writable_binary_with_apparent_size(value, apparent_size_bits)
    }
    fn update_writable_binary_overhead(
        &mut self,
        source: Term,
        old_size_bits: usize,
        new_size_bits: usize,
    ) {
        self.0
            .update_writable_binary_overhead(source, old_size_bits, new_size_bits)
    }
    fn supports_writable_binary(&self) -> bool {
        self.0.supports_writable_binary()
    }
    fn link_node(&mut self, thing: *mut u64, value: Arc<Node>) {
        self.0.link_node(thing, value)
    }
    fn link_external_binary(
        &mut self,
        bin_ref: *mut u64,
        value: Arc<ExternalBinary>,
    ) -> Result<(), arinsal_term::TermError> {
        self.0.link_external_binary(bin_ref, value)
    }
    fn supports_external_binary(&self) -> bool {
        self.0.supports_external_binary()
    }
    fn link_magic_ref(
        &mut self,
        thing: *mut u64,
        owner: Arc<MagicRef>,
    ) -> Result<(), arinsal_term::TermError> {
        self.0.link_magic_ref(thing, owner)
    }
    fn supports_magic(&self) -> bool {
        self.0.supports_magic()
    }
}

// Consecutive cons cells must not request a fresh heap fragment per element.
// Each BIF reserves its output cells once and hands them to TermBuilder.
struct ConsBlock<'a, H: HeapAlloc + ?Sized> {
    backing: &'a mut H,
    next: *mut u64,
    remaining: usize,
}

impl<'a, H: HeapAlloc + ?Sized> ConsBlock<'a, H> {
    fn new(backing: &'a mut H, cells: usize) -> Self {
        let words = cells
            .checked_mul(2)
            .expect("list size exceeds address space");
        let next = backing.alloc(words).expect("infallible BIF heap");
        Self {
            backing,
            next,
            remaining: words,
        }
    }
}

impl<H: HeapAlloc + ?Sized> HeapAlloc for ConsBlock<'_, H> {
    fn alloc(&mut self, words: usize) -> Option<*mut u64> {
        if words > self.remaining {
            return self.backing.alloc(words);
        }
        let result = self.next;
        // SAFETY: `next` points into the single reservation and `remaining`
        // proves that advancing by `words` stays inside it.
        self.next = unsafe { self.next.add(words) };
        self.remaining -= words;
        Some(result)
    }
    fn alloc_with_extra(&mut self, words: usize, extra: usize) -> Option<*mut u64> {
        if words <= self.remaining / 8 {
            self.alloc(words)
        } else {
            self.backing.alloc_with_extra(words, extra)
        }
    }
    fn alloc_fragment_only(&mut self, words: usize) -> Option<*mut u64> {
        self.backing.alloc_fragment_only(words)
    }
    fn release(&mut self, end: *mut u64, start: *mut u64) {
        self.backing.release(end, start)
    }
    fn release_needs_filler(&self, end: *mut u64, start: *mut u64) -> bool {
        self.backing.release_needs_filler(end, start)
    }
    fn retain_binary(&mut self, value: Arc<arinsal_term::RefcBinary>) {
        self.backing.retain_binary(value)
    }
    fn link_bin_ref(
        &mut self,
        bin_ref: *mut u64,
        writable: bool,
        overhead_words: u64,
        owner: Option<arinsal_term::OwnedBinaryRef>,
    ) -> Result<(), TermError> {
        HeapAlloc::link_bin_ref(self.backing, bin_ref, writable, overhead_words, owner)
    }
    fn add_bin_vheap(&mut self, words: u64) {
        HeapAlloc::add_bin_vheap(self.backing, words)
    }
    fn retain_writable_binary(
        &mut self,
        value: Arc<arinsal_term::WritableBinary>,
    ) -> Result<(), TermError> {
        self.backing.retain_writable_binary(value)
    }
    fn retain_writable_binary_with_apparent_size(
        &mut self,
        binary: Arc<arinsal_term::WritableBinary>,
        apparent_size_bits: usize,
    ) -> Result<(), TermError> {
        self.backing
            .retain_writable_binary_with_apparent_size(binary, apparent_size_bits)
    }
    fn update_writable_binary_overhead(
        &mut self,
        source: Term,
        old_size_bits: usize,
        new_size_bits: usize,
    ) {
        self.backing
            .update_writable_binary_overhead(source, old_size_bits, new_size_bits)
    }
    fn supports_writable_binary(&self) -> bool {
        self.backing.supports_writable_binary()
    }
    fn link_external_binary(
        &mut self,
        bin_ref: *mut u64,
        value: Arc<ExternalBinary>,
    ) -> Result<(), TermError> {
        self.backing.link_external_binary(bin_ref, value)
    }
    fn supports_external_binary(&self) -> bool {
        self.backing.supports_external_binary()
    }
    fn link_node(&mut self, thing: *mut u64, value: Arc<Node>) {
        self.backing.link_node(thing, value)
    }
    fn link_magic_ref(
        &mut self,
        thing: *mut u64,
        value: Arc<MagicRef>,
    ) -> Result<(), arinsal_term::TermError> {
        self.backing.link_magic_ref(thing, value)
    }
    fn supports_magic(&self) -> bool {
        self.backing.supports_magic()
    }
}

pub(super) fn lookup<V: crate::BifTableVisitor>(
    module: &str,
    name: &str,
    arity: u8,
    v: &mut V,
) -> Option<V::Output> {
    if let Some(bif) = binary_bifs::lookup(module, name, arity, v) {
        return Some(bif);
    }
    let f = match (module, name, arity) {
        ("erlang", "abs", 1) => v.entry::<bodies::abs>(),
        ("erlang", "float", 1) => v.entry::<bodies::to_float>(),
        ("erlang", "trunc", 1) => v.entry::<bodies::trunc>(),
        ("erlang", "round", 1) => v.entry::<bodies::round>(),
        ("erlang", "ceil", 1) => v.entry::<bodies::ceil>(),
        ("erlang", "floor", 1) => v.entry::<bodies::floor>(),
        ("erlang", "hd", 1) => v.entry::<process_bodies::hd>(),
        ("erlang", "tl", 1) => v.entry::<process_bodies::tl>(),
        ("erlang", "element", 2) => v.entry::<process_bodies::element>(),
        ("erlang", "setelement", 3) => v.entry::<process_bodies::setelement>(),
        ("erlang", "tuple_size", 1) => v.entry::<process_bodies::tuple_size>(),
        ("erlang", "size", 1) => v.entry::<bodies::size>(),
        ("erlang", "node", 0 | 1) => v.entry::<bodies::node>(),
        ("erlang", "self", 0) => v.entry::<bodies::self_bif>(),
        ("erlang", "min", 2) => v.entry::<bodies::min>(),
        ("erlang", "max", 2) => v.entry::<bodies::max>(),
        ("erlang", "not", 1) => v.entry::<bodies::not>(),
        ("erlang", "and", 2) => v.entry::<bodies::and>(),
        ("erlang", "or", 2) => v.entry::<bodies::or>(),
        ("erlang", "xor", 2) => v.entry::<bodies::xor>(),
        ("erlang", "==", 2) => v.entry::<bodies::eq>(),
        ("erlang", "/=", 2) => v.entry::<bodies::ne>(),
        ("erlang", "=:=", 2) => v.entry::<bodies::exact_eq_bif>(),
        ("erlang", "=/=", 2) => v.entry::<bodies::exact_ne>(),
        ("erlang", "<", 2) => v.entry::<bodies::lt>(),
        ("erlang", "=<", 2) => v.entry::<bodies::le>(),
        ("erlang", ">", 2) => v.entry::<bodies::gt>(),
        ("erlang", ">=", 2) => v.entry::<bodies::ge>(),
        ("erlang", "phash2", 1 | 2) => v.entry::<bodies::phash2_bif>(),
        ("erlang", "phash", 2) => v.entry::<bodies::phash_bif>(),
        ("erlang", "make_ref", 0) => v.entry::<bodies::make_ref>(),
        ("erlang", "unique_integer", 0 | 1) => v.entry::<bodies::unique_integer>(),
        ("erlang" | "os", "system_time", 0 | 1) => v.entry::<bodies::system_time>(),
        ("erts_internal", "time_unit" | "perf_counter_unit", 0) => v.entry::<bodies::time_unit>(),
        ("erlang", "tuple_to_list", 1) => v.entry::<process_bodies::tuple_to_list>(),
        ("erlang", "list_to_tuple", 1) => v.entry::<process_bodies::list_to_tuple>(),
        ("erlang", "make_tuple", 2 | 3) => v.entry::<process_bodies::make_tuple>(),
        ("erlang", "append_element", 2) => v.entry::<process_bodies::append_element>(),
        ("erlang", "delete_element", 2) => v.entry::<process_bodies::delete_element>(),
        ("erlang", "insert_element", 3) => v.entry::<process_bodies::insert_element>(),
        ("erlang", "atom_to_list", 1) => v.entry::<process_bodies::atom_to_list>(),
        ("erlang", "list_to_atom", 1) => v.entry::<process_bodies::list_to_atom>(),
        ("erlang", "list_to_existing_atom", 1) => {
            v.entry::<process_bodies::list_to_existing_atom>()
        }
        ("erlang", "atom_to_binary", 2) => v.entry::<bodies::atom_to_binary>(),
        ("erlang", "binary_to_atom", 2) => v.entry::<bodies::binary_to_atom>(),
        ("erlang", "binary_to_existing_atom", 2) => v.entry::<bodies::binary_to_existing_atom>(),
        ("erlang", "float_to_list", 1 | 2) => v.entry::<bodies::float_to_list>(),
        ("erlang", "float_to_binary", 1 | 2) => v.entry::<bodies::float_to_binary>(),
        ("erlang", "list_to_float", 1) => v.entry::<bodies::list_to_float>(),
        ("erlang", "binary_to_float", 1) => v.entry::<bodies::binary_to_float>(),
        ("erlang", "integer_to_binary", 1 | 2) => v.entry::<bodies::integer_to_binary>(),
        ("erlang", "is_atom", 1) => v.entry::<bodies::is_atom>(),
        ("erlang", "is_list", 1) => v.entry::<bodies::is_list>(),
        ("erlang", "is_tuple", 1) => v.entry::<bodies::is_tuple>(),
        ("erlang", "is_float", 1) => v.entry::<bodies::is_float>(),
        ("erlang", "is_integer", 1) => v.entry::<bodies::is_integer>(),
        ("erlang", "is_integer", 3) => v.entry::<bodies::is_integer_range>(),
        ("erlang", "is_number", 1) => v.entry::<bodies::is_number>(),
        ("erlang", "is_pid", 1) => v.entry::<bodies::is_pid>(),
        ("erlang", "is_port", 1) => v.entry::<bodies::is_port>(),
        ("erlang", "is_reference", 1) => v.entry::<bodies::is_reference>(),
        ("erlang", "is_binary", 1) => v.entry::<bodies::is_binary>(),
        ("erlang", "is_bitstring", 1) => v.entry::<bodies::is_bitstring>(),
        ("erlang", "is_function", 1 | 2) => v.entry::<bodies::is_function>(),
        ("erlang", "is_record", 1..=3) => v.entry::<bodies::is_record>(),
        ("erlang", "is_boolean", 1) => v.entry::<bodies::is_boolean>(),
        ("erlang", "is_map", 1) => v.entry::<bodies::is_map>(),
        ("erlang", "is_map_key", 2) => v.entry::<bodies::is_map_key>(),
        ("erlang", "map_get", 2) => v.entry::<bodies::map_get>(),
        ("erlang", "map_size", 1) => v.entry::<bodies::map_size>(),
        ("erlang", "is_builtin", 3) => v.entry::<bodies::is_builtin>(),
        ("erlang", "error", 1..=3) => v.entry::<bodies::error>(),
        ("erlang", "exit", 1) => v.entry::<bodies::exit>(),
        ("erlang", "throw", 1) => v.entry::<bodies::throw>(),
        ("erlang", "raise", 3) => v.entry::<bodies::raise>(),
        ("erts_internal", "cmp_term", 2) => v.entry::<bodies::cmp_term>(),
        ("erts_debug", "copy_shared", 2) => v.entry::<bodies::debug_copy_shared>(),
        ("erts_debug", "flat_size", 1) => v.entry::<bodies::debug_flat_size>(),
        ("erts_debug", "same", 2) => v.entry::<bodies::debug_same>(),
        ("unicode", "bin_is_7bit", 1) => v.entry::<bodies::bin_is_7bit>(),
        ("math", "cos", 1) => v.entry::<bodies::math_cos>(),
        ("math", "cosh", 1) => v.entry::<bodies::math_cosh>(),
        ("math", "sin", 1) => v.entry::<bodies::math_sin>(),
        ("math", "sinh", 1) => v.entry::<bodies::math_sinh>(),
        ("math", "tan", 1) => v.entry::<bodies::math_tan>(),
        ("math", "tanh", 1) => v.entry::<bodies::math_tanh>(),
        ("math", "acos", 1) => v.entry::<bodies::math_acos>(),
        ("math", "acosh", 1) => v.entry::<bodies::math_acosh>(),
        ("math", "asin", 1) => v.entry::<bodies::math_asin>(),
        ("math", "asinh", 1) => v.entry::<bodies::math_asinh>(),
        ("math", "atan", 1) => v.entry::<bodies::math_atan>(),
        ("math", "atanh", 1) => v.entry::<bodies::math_atanh>(),
        ("math", "erf", 1) => v.entry::<bodies::math_erf>(),
        ("math", "erfc", 1) => v.entry::<bodies::math_erfc>(),
        ("math", "exp", 1) => v.entry::<bodies::math_exp>(),
        ("math", "log", 1) => v.entry::<bodies::math_log>(),
        ("math", "log2", 1) => v.entry::<bodies::math_log2>(),
        ("math", "log10", 1) => v.entry::<bodies::math_log10>(),
        ("math", "sqrt", 1) => v.entry::<bodies::math_sqrt>(),
        ("math", "floor", 1) => v.entry::<bodies::math_floor>(),
        ("math", "ceil", 1) => v.entry::<bodies::math_ceil>(),
        ("math", "atan2", 2) => v.entry::<bodies::math_atan2>(),
        ("math", "pow", 2) => v.entry::<bodies::math_pow>(),
        ("math", "fmod", 2) => v.entry::<bodies::math_fmod>(),
        _ => return None,
    };
    // A registry entry must correspond to the supported OTP release.
    arinsal_spec::bif_lookup(module, name, arity).map(|_| f)
}

pub(super) fn bool_term(value: bool) -> Term {
    Term::atom(if value { atoms::TRUE } else { atoms::FALSE })
}

fn bool_value(term: Term) -> Result<bool, BifError> {
    match term.as_atom() {
        Some(atom) if atom == atoms::TRUE => Ok(true),
        Some(atom) if atom == atoms::FALSE => Ok(false),
        _ => Err(BADARG),
    }
}

pub(super) fn integer(ctx: &mut Ctx<'_>, value: usize) -> Result<Term, BifError> {
    if let Some(small) = i64::try_from(value).ok().and_then(Term::small) {
        return Ok(small);
    }
    TermBuilder::new(&mut Heap(&mut ctx.heap))
        .int_from_i128(value as i128)
        .map_err(|_| BifError::SystemLimit)
}

fn tuple_view(term: &Term) -> Result<arinsal_term::TupleRef<'_>, BifError> {
    // SAFETY: BIF arguments remain rooted in the live process heap for this call.
    unsafe { term.tuple_ref() }.ok_or(BADARG)
}

pub(super) fn tuple_arity(term: Term) -> Result<usize, BifError> {
    Ok(tuple_view(&term)?.len())
}

pub(super) fn tuple_element(term: Term, index: usize) -> Result<Term, BifError> {
    tuple_view(&term)?.element(index).ok_or(BADARG)
}

/// The elements of a proper list, `None` for any other term.
pub fn proper_list_terms(term: Term) -> Option<Vec<Term>> {
    list(term).ok()
}

/// Visit the elements of a proper list in order without collecting them. A non-list or an
/// improper list is `badarg`, after the elements before the bad tail were visited.
pub fn for_each_list_term(
    term: Term,
    visit: impl FnMut(Term) -> Result<(), BifError>,
) -> Result<(), BifError> {
    for_each_cons(term, visit)
}

/// The two elements of a 2-tuple, `None` for any other term.
pub fn tuple_pair(term: Term) -> Option<(Term, Term)> {
    let view = tuple_view(&term).ok()?;
    if view.len() != 2 {
        return None;
    }
    Some((view.element(0)?, view.element(1)?))
}

/// The elements of a tuple, `None` for any other term.
pub fn tuple_terms(term: Term) -> Option<Vec<Term>> {
    let view = tuple_view(&term).ok()?;
    Some(view.iter().collect())
}

pub(super) fn list(term: Term) -> Result<Vec<Term>, BifError> {
    list_with_limit(term, usize::MAX)
}

fn list_with_limit(term: Term, limit: usize) -> Result<Vec<Term>, BifError> {
    let mut out = Vec::new();
    for_each_cons(term, |head| {
        if out.len() == limit {
            return Err(BADARG);
        }
        out.push(head);
        Ok(())
    })?;
    Ok(out)
}

/// The head and tail of a cons cell, `None` for any other term.
#[inline(always)]
fn next_cons(list: Term) -> Option<(Term, Term)> {
    // SAFETY: The source heap remains live and stable for the call.
    unsafe { list.cons_ref() }
}

/// Walk a proper list without allocating, as `unique_integer_1` walks `modlist`.
fn for_each_cons(
    mut tail: Term,
    mut visit: impl FnMut(Term) -> Result<(), BifError>,
) -> Result<(), BifError> {
    while let Some((head, next)) = next_cons(tail) {
        visit(head)?;
        tail = next;
    }
    if tail != Term::NIL {
        Err(BADARG)
    } else {
        Ok(())
    }
}

const MAX_TUPLE_SIZE: usize = (1 << 24) - 1;

fn check_tuple_arity(size: usize) -> Result<(), BifError> {
    if size <= MAX_TUPLE_SIZE {
        Ok(())
    } else {
        Err(BADARG)
    }
}

pub(super) fn make_list(
    ctx: &mut Ctx<'_>,
    items: impl IntoIterator<Item = Term>,
    tail: Term,
) -> Term {
    let mut result = tail;
    let items: Vec<_> = items.into_iter().collect();
    if items.is_empty() {
        return result;
    }
    let mut heap = ConsBlock::new(&mut ctx.heap, items.len());
    let mut builder = TermBuilder::new(&mut heap);
    for item in items.into_iter().rev() {
        result = builder.cons(item, result).expect("infallible BIF heap");
    }
    result
}

// Port of erts/emulator/beam/erl_map.c:1207-1241 and :2262-2298, OTP-29.1.1.
pub(super) fn make_list_from_reverse_exact_iter(
    ctx: &mut Ctx<'_>,
    items: impl DoubleEndedIterator<Item = Term> + ExactSizeIterator,
    tail: Term,
) -> Term {
    let count = items.len();
    if count == 0 {
        return tail;
    }
    let mut heap = Heap(&mut ctx.heap);
    let mut builder = TermBuilder::new(&mut heap);
    let list = builder
        .reserve_cons_list(count)
        .expect("infallible BIF heap");
    list.prepend_exact_with_tail(items.rev(), tail)
        .expect("reserved list length")
}

pub(super) fn tuple_build(ctx: &mut Ctx<'_>, values: &[Term]) -> Term {
    TermBuilder::new(&mut Heap(&mut ctx.heap))
        .tuple(values)
        .expect("infallible BIF heap")
}

fn hd(_: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    // Port of erts/emulator/beam/bif.c:2918-2930 (hd_1), OTP-29.1.1.
    // SAFETY: The input heap is live and stable.
    unsafe { args[0].cons_ref() }
        .map(|(head, _)| head)
        .ok_or(BADARG)
}
fn tl(_: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    // Port of erts/emulator/beam/bif.c:2931-2943 (tl_1), OTP-29.1.1.
    // SAFETY: The input heap is live and stable.
    unsafe { args[0].cons_ref() }
        .map(|(_, tail)| tail)
        .ok_or(BADARG)
}
fn element(_: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let index = args[0].as_small().ok_or(BADARG)?;
    if index < 1 {
        return Err(BADARG);
    }
    // Port of erts/emulator/beam/bif.c:2944-2963 (element_2), OTP-29.1.1.
    tuple_view(&args[1])?
        .element(index as usize - 1)
        .ok_or(BADARG)
}
fn setelement(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    // Port of erts/emulator/beam/bif.c:2976-3003 (setelement_3), OTP-29.1.1:
    // one `HAlloc` of `arity + 1` words, `sys_memcpy` of the tuple, then the
    // replaced element. No per-element closure.
    let index = args[0].as_small().ok_or(BADARG)?;
    if index < 1 {
        return Err(BADARG);
    }
    let source = tuple_view(&args[1])?;
    let arity = source.len();
    if index as usize > arity {
        return Err(BADARG);
    }
    let replacement = args[2];
    TermBuilder::new(&mut Heap(&mut ctx.heap))
        .tuple_from_fn(arity, |slot, _| {
            if slot + 1 == index as usize {
                replacement
            } else {
                source
                    .element(slot)
                    .expect("tuple arity was read from source")
            }
        })
        .map_err(|_| BifError::SystemLimit)
}
fn tuple_size(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    // Port of erts/emulator/beam/bif.c:2963-2973 (tuple_size_1), OTP-29.1.1.
    let arity = tuple_view(&args[0])?.len();
    integer(ctx, arity)
}
fn size(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    match args[0].classify() {
        TermKind::Tuple | TermKind::Record => tuple_size(ctx, args),
        TermKind::Bitstring => {
            // SAFETY: The source binary and owner remain live for this call.
            let view = unsafe { args[0].binary_ref() }.ok_or(BADARG)?;
            integer(ctx, view.bit_len() / 8)
        }
        _ => Err(BADARG),
    }
}
fn node(_: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    if args.is_empty() {
        return Ok(Term::atom(atoms::NONAME));
    }
    let identity = args[0].identity().ok_or(BADARG)?;
    let name = match identity {
        arinsal_term::Identity::Pid { node, .. }
        | arinsal_term::Identity::Port { node, .. }
        | arinsal_term::Identity::Ref { node, .. } => node,
    };
    Ok(Term::atom(name))
}
fn self_bif(_: &mut Ctx<'_>, _: &[Term]) -> Result<Term, BifError> {
    Err(BifError::Unsupported("self requires the calling process"))
}
fn min(_: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    Ok(if cmp(args[0], args[1]) == Ordering::Greater {
        args[1]
    } else {
        args[0]
    })
}
fn max(_: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    Ok(if cmp(args[0], args[1]) == Ordering::Less {
        args[1]
    } else {
        args[0]
    })
}
fn not(_: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    Ok(bool_term(!bool_value(args[0])?))
}
fn and(_: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    Ok(bool_term(bool_value(args[0])? & bool_value(args[1])?))
}
fn or(_: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    Ok(bool_term(bool_value(args[0])? | bool_value(args[1])?))
}
fn xor(_: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    Ok(bool_term(bool_value(args[0])? ^ bool_value(args[1])?))
}

macro_rules! compare {
    ($name:ident, $body:expr) => {
        fn $name(_: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
            Ok(bool_term($body(args[0], args[1])))
        }
    };
}
compare!(eq, loose_eq);
compare!(exact_eq_bif, exact_eq);
compare!(ne, |a, b| !loose_eq(a, b));
compare!(exact_ne, |a, b| !exact_eq(a, b));
compare!(lt, |a, b| cmp(a, b) == Ordering::Less);
compare!(le, |a, b| cmp(a, b) != Ordering::Greater);
compare!(gt, |a, b| cmp(a, b) == Ordering::Greater);
compare!(ge, |a, b| cmp(a, b) != Ordering::Less);

/// Resume state of `erlang:phash2/1,2`.
///
/// Port of the trap state `trapping_make_hash2` hands back in
/// erts/emulator/beam/erl_term_hashing.c, OTP-29.1.1.
pub struct Phash2Cont {
    run: arinsal_term::Hash2Run,
    range: Option<u64>,
}

impl Phash2Cont {
    /// The continuation export this state belongs to.
    pub fn continuation(&self) -> &'static str {
        if self.range.is_some() {
            "erlang:phash2_trap/2"
        } else {
            "erlang:phash2_trap/1"
        }
    }
}

/// A started `phash2`: finished, or the state to trap with.
pub enum Phash2Step {
    /// The finished value.
    Done(Term),
    /// The saved hash state.
    More(Box<Phash2Cont>),
}

/// Run `run` for the reductions left, then charge them.
// Port of erts/emulator/beam/bif.c (phash2_1, phash2_2), OTP-29.1.1, over `trapping_make_hash2`.
pub fn phash2_slice(ctx: &mut Ctx<'_>, cont: &mut Phash2Cont) -> Result<Option<Term>, BifError> {
    let budget = ctx.reduction_budget();
    let iterations = (budget != usize::MAX).then(|| {
        i64::try_from(budget)
            .unwrap_or(i64::MAX / arinsal_term::HASH2_ITERATIONS_PER_RED)
            .saturating_mul(arinsal_term::HASH2_ITERATIONS_PER_RED)
    });
    match cont.run.run(iterations) {
        arinsal_term::Hash2Progress::Yield => {
            ctx.bump_all_reds();
            Ok(None)
        }
        arinsal_term::Hash2Progress::Done { hash, used } => {
            if iterations.is_some() {
                ctx.charge_reductions(
                    (used / arinsal_term::HASH2_ITERATIONS_PER_RED).max(0) as usize
                );
            }
            let value = match cont.range {
                None => u64::from(hash & ((1 << 27) - 1)),
                Some(range) if range == 1_u64 << 32 => u64::from(hash),
                Some(range) => u64::from(hash % range as u32),
            };
            Ok(Some(integer(ctx, value as usize)?))
        }
    }
}

/// The range argument of `phash2/2`.
pub fn phash2_range_arg(term: Term) -> Result<u64, BifError> {
    let range: u64 = term
        .as_small()
        .ok_or(BADARG)?
        .try_into()
        .map_err(|_| BADARG)?;
    if range == 0 || range > (1_u64 << 32) {
        return Err(BADARG);
    }
    Ok(range)
}

/// Start `phash2/1` or `phash2/2`.
pub fn phash2_start(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Phash2Step, BifError> {
    let range = if args.len() == 2 {
        Some(phash2_range_arg(args[1])?)
    } else {
        None
    };
    let mut cont = Phash2Cont {
        run: arinsal_term::Hash2Run::new(args[0]),
        range,
    };
    Ok(match phash2_slice(ctx, &mut cont)? {
        Some(value) => Phash2Step::Done(value),
        None => Phash2Step::More(Box::new(cont)),
    })
}

fn phash2_bif(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    // Port of erts/emulator/beam/bif.c (phash2_1, phash2_2) over `trapping_make_hash2`: a term
    // that hashes without a work stack never builds the resumable state.
    let range = match args.get(1) {
        Some(range) => Some(phash2_range_arg(*range)?),
        None => None,
    };
    if let Some(hash) = arinsal_term::hash2_immediate(args[0]) {
        let value = match range {
            None => u64::from(hash & ((1 << 27) - 1)),
            Some(range) if range == 1_u64 << 32 => u64::from(hash),
            Some(range) => u64::from(hash % range as u32),
        };
        return integer(ctx, value as usize);
    }
    match phash2_start(ctx, args)? {
        Phash2Step::Done(value) => Ok(value),
        Phash2Step::More(cont) => {
            ctx.defer_trap(crate::lists::DeferredTrap::Phash2(cont));
            Ok(Term::NIL)
        }
    }
}
fn phash_bif(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let range = args[1].as_small().ok_or(BADARG)?;
    let value = phash(args[0], range.try_into().map_err(|_| BADARG)?).ok_or(BADARG)?;
    integer(ctx, value as usize)
}
pub fn make_ref(ctx: &mut Ctx<'_>, _: &[Term]) -> Result<Term, BifError> {
    // Port of erts/emulator/beam/erl_bif_unique.c:821-833 (make_ref_0), OTP-29.1.1.
    // `erts_sched_make_ref_in_buffer` writes the three words straight into the
    // heap buffer; the id is not packed and unpacked on the way.
    Term::local_ref(&mut ctx.heap, next_ref_words()).map_err(|_| BifError::SystemLimit)
}

/// `erlang:unique_integer/0` and `/1` counter step, before the term is built.
// Port of erts/emulator/beam/erl_bif_unique.c:835-871 (unique_integer_0/1), OTP-29.1.1.
pub fn eval_unique_integer(args: &[Term]) -> Result<crate::unique::UniqueInt, BifError> {
    let mut positive = false;
    let mut monotonic = false;
    if let Some(options) = args.first() {
        let positive_atom = unique_flag_atom("positive");
        let monotonic_atom = unique_flag_atom("monotonic");
        // The option list is walked in place. Building a `Vec` for `[positive]`
        // is not what `unique_integer_1` does.
        for_each_cons(*options, |option| match option.as_atom() {
            Some(atom) if atom == positive_atom => {
                positive = true;
                Ok(())
            }
            Some(atom) if atom == monotonic_atom => {
                monotonic = true;
                Ok(())
            }
            _ => Err(BADARG),
        })?;
    }
    if monotonic {
        return if positive {
            let value = crate::unique::next_unique_monotonic_positive();
            if let Ok(small) = i64::try_from(value) {
                Ok(crate::unique::UniqueInt::Small(small))
            } else {
                Ok(crate::unique::UniqueInt::Big(BigInt::from(value)))
            }
        } else {
            Ok(crate::unique::UniqueInt::Small(next_unique_monotonic()))
        };
    }
    Ok(crate::unique::next_unique_integer(positive))
}

fn unique_flag_atom(name: &'static str) -> arinsal_term::Atom {
    static POSITIVE: OnceLock<arinsal_term::Atom> = OnceLock::new();
    static MONOTONIC: OnceLock<arinsal_term::Atom> = OnceLock::new();
    let slot = if name == "positive" {
        &POSITIVE
    } else {
        &MONOTONIC
    };
    *slot.get_or_init(|| global_atoms().intern(name).expect("unique_integer flag"))
}

pub fn unique_integer(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    // Port of erts/emulator/beam/erl_bif_unique.c:835-871 (unique_integer_0/1), OTP-29.1.1.
    match eval_unique_integer(args)? {
        crate::unique::UniqueInt::Small(value) => {
            Ok(Term::small(value).expect("unique integer small"))
        }
        crate::unique::UniqueInt::Big(value) => TermBuilder::new(&mut Heap(&mut ctx.heap))
            .int_from_bigint(&value)
            .map_err(|_| BifError::SystemLimit),
    }
}
fn system_time(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let units_per_second = if let Some(unit) = args.first() {
        if let Some(name) = atom_name(*unit) {
            // Port of erts/emulator/beam/erl_time_sup.c:2277 (time_unit_conversion), OTP-29.1.1.
            // Plural atoms (`nano_seconds` and the rest) are aliases of the singular units.
            BigInt::from(match name {
                "native" | "nanosecond" | "nano_seconds" => 1_000_000_000,
                "microsecond" | "micro_seconds" => 1_000_000,
                "millisecond" | "milli_seconds" => 1_000,
                "second" | "seconds" => 1,
                _ => return Err(BADARG),
            })
        } else {
            let value = bigint(*unit)?;
            if value.sign() != Sign::Plus {
                return Err(BADARG);
            }
            value
        }
    } else {
        BigInt::from(1_000_000_000)
    };
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| BifError::SystemLimit)?;
    let value = BigInt::from(elapsed.as_nanos()) * units_per_second / 1_000_000_000_u64;
    TermBuilder::new(&mut Heap(&mut ctx.heap))
        .int_from_bigint(&value)
        .map_err(|_| BifError::SystemLimit)
}
fn time_unit(_: &mut Ctx<'_>, _: &[Term]) -> Result<Term, BifError> {
    Ok(Term::small(1_000_000_000).expect("small time unit"))
}

fn tuple_to_list(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    // Port of erts/emulator/beam/bif.c:3762-3777 (tuple_to_list_1), OTP-29.1.1.
    let values = tuple_view(&args[0])?;
    Ok(make_list(ctx, values.iter(), Term::NIL))
}
fn list_to_tuple(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    // Port of erts/emulator/beam/bif.c:3789-3808 (list_to_tuple_1), OTP-29.1.1.
    let mut len = 0usize;
    for_each_cons(args[0], |_| {
        if len == MAX_TUPLE_SIZE {
            return Err(BADARG);
        }
        len += 1;
        Ok(())
    })?;
    if len == 0 {
        return Ok(TermBuilder::new(&mut ctx.heap)
            .tuple_from_fn(0, |_, _| unreachable!())
            .expect("empty tuple is static"));
    }
    // The list was walked above, so every cell is there: the tuple is filled in one pass.
    let mut tail = args[0];
    TermBuilder::new(&mut ctx.heap)
        .tuple_from_fn(len, |_, _| {
            let (head, next) = next_cons(tail).expect("validated list");
            tail = next;
            head
        })
        .map_err(|_| BifError::SystemLimit)
}
fn make_tuple(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    // Port of erts/emulator/beam/bif.c:3006-3076 (make_tuple_2/3), OTP-29.1.1.
    let n = args[0].as_small().ok_or(BADARG)?;
    if n < 0 || check_tuple_arity(n as usize).is_err() {
        return Err(BADARG);
    }
    let arity = n as usize;
    if arity == 0 {
        if args.len() == 3 {
            for_each_cons(args[2], |entry| {
                if tuple_arity(entry)? != 2 {
                    return Err(BADARG);
                }
                let index = tuple_element(entry, 0)?.as_small().ok_or(BADARG)?;
                if index < 1 || index > n {
                    return Err(BADARG);
                }
                Ok(())
            })?;
        }
        return Ok(TermBuilder::new(&mut ctx.heap)
            .tuple_from_fn(0, |_, _| unreachable!())
            .expect("empty tuple is static"));
    }
    let mut builder = TermBuilder::new(&mut ctx.heap);
    let mut tuple = builder
        .reserve_tuple(arity, args[1])
        .map_err(|_| BifError::SystemLimit)?;
    if args.len() == 3 {
        for_each_cons(args[2], |entry| {
            if tuple_arity(entry)? != 2 {
                return Err(BADARG);
            }
            let index = tuple_element(entry, 0)?.as_small().ok_or(BADARG)?;
            if index < 1 || index > n {
                return Err(BADARG);
            }
            tuple
                .set(index as usize - 1, tuple_element(entry, 1)?)
                .expect("tuple index was validated");
            Ok(())
        })?;
    }
    Ok(tuple.finish())
}
fn append_element(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    // Port of erts/emulator/beam/bif.c:3083 (append_element_2), OTP-29.1.1.
    let source = tuple_view(&args[0])?;
    let arity = source.len();
    check_tuple_arity(arity + 1)?;
    let appended = args[1];
    TermBuilder::new(&mut Heap(&mut ctx.heap))
        .tuple_from_fn(arity + 1, |slot, _| {
            if slot == arity {
                appended
            } else {
                source
                    .element(slot)
                    .expect("tuple arity was read from source")
            }
        })
        .map_err(|_| BifError::SystemLimit)
}
fn delete_element(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    // Port of erts/emulator/beam/bif.c:3144-3178 (delete_element_2), OTP-29.1.1.
    let index = args[0].as_small().ok_or(BADARG)?;
    if index < 1 {
        return Err(BADARG);
    }
    let source = tuple_view(&args[1])?;
    let arity = source.len();
    if index as usize > arity {
        return Err(BADARG);
    }
    TermBuilder::new(&mut Heap(&mut ctx.heap))
        .tuple_from_fn(arity - 1, |slot, _| {
            source
                .element(if slot + 1 < index as usize {
                    slot
                } else {
                    slot + 1
                })
                .expect("tuple index was validated")
        })
        .map_err(|_| BifError::SystemLimit)
}
fn insert_element(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    // Port of erts/emulator/beam/bif.c:3110-3141 (insert_element_3), OTP-29.1.1.
    let index = args[0].as_small().ok_or(BADARG)?;
    if index < 1 {
        return Err(BADARG);
    }
    let source = tuple_view(&args[1])?;
    let arity = source.len();
    if index as usize > arity + 1 {
        return Err(BADARG);
    }
    let inserted = args[2];
    TermBuilder::new(&mut Heap(&mut ctx.heap))
        .tuple_from_fn(arity + 1, |slot, _| {
            if slot + 1 == index as usize {
                inserted
            } else {
                source
                    .element(if slot + 1 < index as usize {
                        slot
                    } else {
                        slot - 1
                    })
                    .expect("tuple index was validated")
            }
        })
        .map_err(|_| BifError::SystemLimit)
}

#[cfg(test)]
mod tuple_limit_tests {
    use super::{MAX_TUPLE_SIZE, check_tuple_arity};

    #[test]
    fn tuple_arity_limit_matches_erts_header_capacity() {
        assert!(check_tuple_arity(MAX_TUPLE_SIZE).is_ok());
        assert!(check_tuple_arity(MAX_TUPLE_SIZE + 1).is_err());
    }
}
pub(super) fn atom_name(term: Term) -> Option<&'static str> {
    global_atoms().text(term.as_atom()?)
}
fn atom_to_list(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    // Port of erts/emulator/beam/bif.c:3186-3210 (atom_to_list_1), OTP-29.1.1.
    atom_to_list_term(&mut ctx.heap, args[0])
}

/// `atom_to_list/1`. ASCII names are consed straight from the atom bytes.
// Port of erts/emulator/beam/bif.c:3186-3210 (atom_to_list_1), OTP-29.1.1:
// the list is built on the process heap from the atom text. No intermediate
// character vector.
pub fn atom_to_list_term<H: HeapAlloc + ?Sized>(heap: &mut H, arg: Term) -> Result<Term, BifError> {
    let text = atom_name(arg).ok_or(BADARG)?;
    let bytes = text.as_bytes();
    if bytes.is_empty() {
        return Ok(Term::NIL);
    }
    if bytes.iter().all(|byte| *byte < 0x80) {
        return cons_units(
            heap,
            bytes.len(),
            bytes.iter().rev().map(|byte| i64::from(*byte)),
        );
    }
    let points: SmallVec<[i64; 16]> = text.chars().map(|point| point as i64).collect();
    cons_units(heap, points.len(), points.into_iter().rev())
}

fn cons_units<H: HeapAlloc + ?Sized>(
    heap: &mut H,
    count: usize,
    units: impl Iterator<Item = i64>,
) -> Result<Term, BifError> {
    let mut block = ConsBlock::new(heap, count);
    let mut builder = TermBuilder::new(&mut block);
    let mut result = Term::NIL;
    for unit in units {
        let head = Term::small(unit).ok_or(BADARG)?;
        result = builder
            .cons(head, result)
            .map_err(|_| BifError::SystemLimit)?;
    }
    Ok(result)
}
fn list_to_atom(_: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    // Port of erts/emulator/beam/bif.c:3217 (list_to_atom_1) and
    // erts/emulator/beam/utils.c:2862 (erts_unicode_list_to_buf),
    // OTP-29.1.1. The bytes land in a fixed buffer, then erts_atom_put.
    let mut buf = [0u8; MAX_ATOM_SZ_LIMIT];
    let written = unicode_list_to_buf(args[0], &mut buf)?;
    let atom = global_atoms()
        .put(&buf[..written], AtomEncoding::Utf8, true)
        .map_err(|error| match error {
            AtomError::TooLong | AtomError::SystemLimit => BifError::SystemLimit,
            AtomError::BadEncoding => BADARG,
        })?;
    Ok(Term::atom(atom))
}
fn list_to_existing_atom(_: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    // Port of bif.c:3239. Every conversion failure, including a too-long list, is badarg.
    let mut buf = [0u8; MAX_ATOM_SZ_LIMIT];
    let Ok(written) = unicode_list_to_buf(args[0], &mut buf) else {
        return Err(BADARG);
    };
    let atom = global_atoms()
        .existing(&buf[..written], AtomEncoding::Utf8)
        .ok_or(BADARG)?;
    Ok(Term::atom(atom))
}

const MAX_ATOM_CHARACTERS: usize = 255;
const MAX_ATOM_SZ_LIMIT: usize = 4 * MAX_ATOM_CHARACTERS;

/// Fill `buf` with the UTF-8 of a unicode list.
///
/// Port of utils.c:2862. `Ok` is 0, [`BifError::SystemLimit`] is -2, [`BADARG`] is -1.
fn unicode_list_to_buf(list: Term, buf: &mut [u8]) -> Result<usize, BifError> {
    let mut written = 0usize;
    let mut chars = 0usize;
    let mut too_long = false;
    let walk = for_each_cons(list, |head| {
        if chars >= MAX_ATOM_CHARACTERS {
            too_long = true;
            return Err(BADARG);
        }
        let Some(value) = head.as_small() else {
            return Err(BADARG);
        };
        let Ok(val) = u32::try_from(value) else {
            return Err(BADARG);
        };
        let width = if val < 0x80 {
            1
        } else if val < 0x800 {
            2
        } else if val < 0x1_0000 {
            if (0xD800..=0xDFFF).contains(&val) {
                return Err(BADARG);
            }
            3
        } else if val < 0x11_0000 {
            4
        } else {
            return Err(BADARG);
        };
        if written + width > buf.len() {
            too_long = true;
            return Err(BADARG);
        }
        encode_utf8(&mut buf[written..], val, width);
        written += width;
        chars += 1;
        Ok(())
    });
    match walk {
        Ok(()) => Ok(written),
        Err(_) if too_long => Err(BifError::SystemLimit),
        Err(error) => Err(error),
    }
}

fn encode_utf8(buf: &mut [u8], val: u32, width: usize) {
    match width {
        1 => buf[0] = val as u8,
        2 => {
            buf[0] = 0xC0 | (val >> 6) as u8;
            buf[1] = 0x80 | (val & 0x3F) as u8;
        }
        3 => {
            buf[0] = 0xE0 | (val >> 12) as u8;
            buf[1] = 0x80 | ((val >> 6) & 0x3F) as u8;
            buf[2] = 0x80 | (val & 0x3F) as u8;
        }
        _ => {
            buf[0] = 0xF0 | (val >> 18) as u8;
            buf[1] = 0x80 | ((val >> 12) & 0x3F) as u8;
            buf[2] = 0x80 | ((val >> 6) & 0x3F) as u8;
            buf[3] = 0x80 | (val & 0x3F) as u8;
        }
    }
}
fn encoding(term: Term) -> Result<&'static str, BifError> {
    match atom_name(term) {
        Some("utf8" | "unicode") => Ok("utf8"),
        Some("latin1") => Ok("latin1"),
        _ => Err(BADARG),
    }
}
fn atom_to_binary(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let atom = args[0].as_atom().ok_or(BADARG)?;
    let table = global_atoms();
    match encoding(args[1])? {
        // Port of erl_unicode.c:1954: utf8 returns Atom.u.bin, the literal.
        "utf8" => table.utf8_literal(atom).ok_or(BADARG),
        // Port of erl_unicode.c:1938. Latin-1 that is already the stored bytes
        // returns the same literal; anything else is a fresh binary.
        _ => match table.latin1_is_stored(atom) {
            None => Err(BADARG),
            Some(true) => table.utf8_literal(atom).ok_or(BADARG),
            Some(false) => {
                let bytes = table.latin1_bytes(atom).ok_or(BADARG)?;
                Ok(TermBuilder::new(&mut Heap(&mut ctx.heap))
                    .binary(&bytes)
                    .expect("infallible BIF heap"))
            }
        },
    }
}
/// Copy a byte-aligned binary's significant bytes for a VM continuation.
pub fn binary_bytes(term: Term) -> Result<Vec<u8>, BifError> {
    let bits = bitstring_bit_len(term)?;
    if !bits.is_multiple_of(8) {
        return Err(BADARG);
    }
    let mut bytes = vec![0; bits / 8];
    copy_binary_range(term, 0, &mut bytes)?;
    Ok(bytes)
}

/// Copy a bounded byte range from a live, byte-aligned bitstring.
pub fn copy_binary_range(term: Term, start: usize, output: &mut [u8]) -> Result<(), BifError> {
    let bits = output.len().checked_mul(8).ok_or(BADARG)?;
    let start_bit = start.checked_mul(8).ok_or(BADARG)?;
    copy_bitstring_range(term, start_bit, output, bits)
}

/// Copy significant bits into a most-significant-bit-first packed byte slice.
// Port of erts/emulator/beam/erl_bits.c:2389-2515 (erts_copy_bits_fwd), OTP-29.1.1.
pub fn copy_bitstring_range(
    term: Term,
    start: usize,
    output: &mut [u8],
    bit_count: usize,
) -> Result<(), BifError> {
    let output_bits = output.len().checked_mul(8).ok_or(BADARG)?;
    with_binary_bytes(term, |view| {
        if bit_count > output_bits
            || start
                .checked_add(bit_count)
                .is_none_or(|end| end > view.bit_len())
        {
            return Err(BADARG);
        }
        let source_start = view.start_bit().checked_add(start).ok_or(BADARG)?;
        if source_start.is_multiple_of(8) && bit_count.is_multiple_of(8) {
            let source_start = source_start / 8;
            let byte_count = bit_count / 8;
            let source_end = source_start.checked_add(byte_count).ok_or(BADARG)?;
            output[..byte_count]
                .copy_from_slice(view.bytes().get(source_start..source_end).ok_or(BADARG)?);
            output[byte_count..].fill(0);
        } else {
            output.fill(0);
            for index in 0..bit_count {
                let source = source_start + index;
                let bit = (view.bytes()[source / 8] >> (7 - source % 8)) & 1;
                output[index / 8] |= bit << (7 - index % 8);
            }
        }
        Ok(())
    })?
}

/// Run a read-only operation while the term's backing bytes remain borrowed.
///
/// The callback cannot retain the view beyond the term's live interval.
pub fn with_binary_bytes<R>(term: Term, f: impl FnOnce(BinaryRef<'_>) -> R) -> Result<R, BifError> {
    // SAFETY: The view cannot escape `f`, and the caller keeps the term and its owner live.
    let view = unsafe { term.binary_ref() }.ok_or(BADARG)?;
    Ok(f(view))
}
fn binary_to_atom_inner(args: &[Term], existing: bool) -> Result<Term, BifError> {
    let encoding = match encoding(args[1])? {
        "utf8" => AtomEncoding::Utf8,
        _ => AtomEncoding::Latin1,
    };
    binary_bifs::with_binary_input(args[0], |bytes| {
        // Port of erl_unicode.c:1963 (binary_to_atom), OTP-29.1.1.
        let table = global_atoms();
        let atom = if existing {
            table.existing(bytes, encoding).ok_or(BADARG)?
        } else {
            table
                .put(bytes, encoding, false)
                .map_err(|error| match error {
                    AtomError::TooLong => BifError::SystemLimit,
                    AtomError::SystemLimit => BifError::SystemLimit,
                    AtomError::BadEncoding => BADARG,
                })?
        };
        Ok(Term::atom(atom))
    })
}
fn binary_to_atom(_: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    binary_to_atom_inner(args, false)
}
fn binary_to_existing_atom(_: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    binary_to_atom_inner(args, true)
}
fn float_opts(args: &[Term]) -> Result<arinsal_float::FloatFormatOpts, BifError> {
    let mut opts = arinsal_float::FloatFormatOpts::default();
    if args.len() == 1 {
        return Ok(opts);
    }
    for entry in list(args[1])? {
        if let Some(name) = atom_name(entry) {
            match name {
                "compact" => opts.compact = true,
                "short" => opts.notation = arinsal_float::FloatNotation::Short,
                _ => return Err(BADARG),
            }
        } else {
            if tuple_arity(entry)? != 2 {
                return Err(BADARG);
            }
            let option = tuple_element(entry, 1)?;
            let count = option
                .as_small()
                .and_then(|n| u16::try_from(n).ok())
                .ok_or(BADARG)?;
            opts.notation = match atom_name(tuple_element(entry, 0)?) {
                Some("decimals") => arinsal_float::FloatNotation::Decimals(count),
                Some("scientific") => arinsal_float::FloatNotation::Scientific(count),
                _ => return Err(BADARG),
            };
        }
    }
    Ok(opts)
}
fn formatted_float(args: &[Term]) -> Result<String, BifError> {
    // SAFETY: The float's heap remains live during this BIF.
    let value = unsafe { args[0].float_ref() }.ok_or(BADARG)?.get();
    arinsal_float::float_to_list(value, &float_opts(args)?).map_err(|_| BADARG)
}
fn float_to_list(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let text = formatted_float(args)?;
    Ok(make_list(
        ctx,
        text.bytes().map(|b| Term::small(b as i64).unwrap()),
        Term::NIL,
    ))
}
fn float_to_binary(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let text = formatted_float(args)?;
    Ok(TermBuilder::new(&mut Heap(&mut ctx.heap))
        .binary(text.as_bytes())
        .expect("infallible BIF heap"))
}
fn list_to_float(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let bytes = list(args[0])?
        .into_iter()
        .map(|t| {
            t.as_small()
                .and_then(|n| u8::try_from(n).ok())
                .ok_or(BADARG)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let value = arinsal_float::list_to_float(&bytes).map_err(|_| BADARG)?;
    Ok(TermBuilder::new(&mut Heap(&mut ctx.heap))
        .float(value)
        .expect("infallible BIF heap"))
}
fn binary_to_float(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    binary_bifs::with_binary_input(args[0], |bytes| {
        let value = arinsal_float::list_to_float(bytes).map_err(|_| BADARG)?;
        Ok(TermBuilder::new(&mut Heap(&mut ctx.heap))
            .float(value)
            .expect("infallible BIF heap"))
    })
}
fn integer_text(args: &[Term]) -> Result<String, BifError> {
    let base = if args.len() == 2 {
        args[1].as_small().ok_or(BADARG)?
    } else {
        10
    };
    if !(2..=36).contains(&base) {
        return Err(BADARG);
    }
    Ok(bigint(args[0])?.to_str_radix(base as u32).to_uppercase())
}
fn integer_to_binary(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let text = integer_text(args)?;
    Ok(TermBuilder::new(&mut Heap(&mut ctx.heap))
        .binary(text.as_bytes())
        .expect("infallible BIF heap"))
}
pub(super) fn iolist_bytes(root: Term) -> Result<Vec<u8>, BifError> {
    binary_bifs::iolist_bytes(root)
}

/// Return the sole bitstring in a singleton list when its length satisfies `unit`.
// Port of erts/emulator/beam/erl_iolist.c:865-879, OTP-29.1.1.
pub fn singleton_bitstring(root: Term, unit: usize) -> Result<Option<Term>, BifError> {
    if root.classify() != TermKind::List {
        return Ok(None);
    }
    let (head, tail) = iolist_cons(root)?;
    if tail != Term::NIL || head.classify() != TermKind::Bitstring {
        return Ok(None);
    }
    let bits = bitstring_bit_len(head)?;
    Ok(bits.is_multiple_of(unit).then_some(head))
}

/// Return the significant bit count for a live bitstring term.
pub fn bitstring_bit_len(term: Term) -> Result<usize, BifError> {
    with_binary_bytes(term, |view| view.bit_len())
}

/// Stateful iolist size calculation used by the VM continuation export.
// Port of erts/emulator/beam/erl_iolist.c:1013-1070, OTP-29.1.1.
pub struct IolistSizeWalk {
    current: Term,
    tails: SmallVec<[Term; 8]>,
    size: usize,
    unit: usize,
}

impl IolistSizeWalk {
    /// Start traversing an iolist rooted in a stable process heap.
    pub fn new(root: Term) -> Self {
        Self {
            current: root,
            tails: SmallVec::new(),
            size: 0,
            unit: 8,
        }
    }

    /// Start a walk that accepts bitstrings of any size, for `list_to_bitstring/1`.
    pub fn new_bits(root: Term) -> Self {
        Self {
            unit: 1,
            ..Self::new(root)
        }
    }

    /// Whether this walk was started by `new_bits`.
    pub fn is_bits(&self) -> bool {
        self.unit == 1
    }

    /// Return the accumulated bit count after a complete traversal.
    pub fn take_bits(&mut self) -> usize {
        std::mem::take(&mut self.size)
    }

    /// Count at most `budget - 1` yield counts of list cells and leaves like `generic_iolist_size`.
    ///
    /// Returns whether the walk finished and the yield counts used; a walk that ran out of
    /// budget reports all of it.
    // Port of erts/emulator/beam/erl_iolist.c (generic_iolist_size), OTP-29.1.1.
    pub fn step(&mut self, budget: usize) -> Result<(bool, usize), (BifError, usize)> {
        let mut consumed = 0;
        loop {
            while self.current.classify() == TermKind::List {
                if consumed + 1 >= budget {
                    return Ok((false, budget));
                }
                consumed += 1;
                let (head, tail) = iolist_cons(self.current).map_err(|error| (error, consumed))?;
                if head.classify() == TermKind::List {
                    self.tails.push(tail);
                    self.current = head;
                    continue;
                }
                self.add(head, true).map_err(|error| (error, consumed))?;
                self.current = tail;
            }

            if consumed + 1 >= budget {
                return Ok((false, budget));
            }
            consumed += 1;
            self.add(self.current, false)
                .map_err(|error| (error, consumed))?;
            match self.tails.pop() {
                Some(tail) => self.current = tail,
                None => return Ok((true, consumed)),
            }
        }
    }

    /// Return the accumulated byte count after a complete traversal.
    pub fn take_size(&mut self) -> usize {
        std::mem::take(&mut self.size) / 8
    }

    fn add(&mut self, term: Term, byte_allowed: bool) -> Result<(), BifError> {
        match term.classify() {
            TermKind::Nil => Ok(()),
            TermKind::Bitstring => {
                let bits = bitstring_bit_len(term)?;
                if !bits.is_multiple_of(self.unit) {
                    return Err(BADARG);
                }
                // Port of erts/emulator/beam/erl_iolist.c:139-191
                // (generic_iolist_size), OTP-29.1.1. ERTS keeps a Uint accumulator.
                self.size = self.size.checked_add(bits).ok_or(BifError::SystemLimit)?;
                Ok(())
            }
            TermKind::Number if byte_allowed => {
                if !term
                    .as_small()
                    .is_some_and(|number| (0..=255).contains(&number))
                {
                    return Err(BADARG);
                }
                self.size = self.size.checked_add(8).ok_or(BifError::SystemLimit)?;
                Ok(())
            }
            _ => Err(BADARG),
        }
    }
}

pub(crate) fn iolist_cons(term: Term) -> Result<(Term, Term), BifError> {
    // SAFETY: The source heap remains live throughout the BIF call.
    unsafe { term.cons_ref() }.ok_or(BADARG)
}
trait BitBuffer {
    fn push_byte(&mut self, byte: u8);
    fn last_byte_mut(&mut self) -> Option<&mut u8>;
}

impl BitBuffer for Vec<u8> {
    fn push_byte(&mut self, byte: u8) {
        self.push(byte);
    }

    fn last_byte_mut(&mut self) -> Option<&mut u8> {
        self.last_mut()
    }
}

impl<A> BitBuffer for SmallVec<A>
where
    A: smallvec::Array<Item = u8>,
{
    fn push_byte(&mut self, byte: u8) {
        self.push(byte);
    }

    fn last_byte_mut(&mut self) -> Option<&mut u8> {
        self.last_mut()
    }
}

fn append_term_bitstring<B: BitBuffer>(
    bytes: &mut B,
    length: &mut usize,
    term: Term,
) -> Result<(), BifError> {
    let bit_len = bitstring_bit_len(term)?;
    let mut data = SmallVec::<[u8; 64]>::new();
    data.resize(bit_len.div_ceil(8), 0);
    copy_bitstring_range(term, 0, &mut data, bit_len)?;
    for i in 0..bit_len {
        append_bit(bytes, length, (data[i / 8] >> (7 - i % 8)) & 1);
    }
    Ok(())
}
fn append_bit(bytes: &mut impl BitBuffer, length: &mut usize, bit: u8) {
    if (*length).is_multiple_of(8) {
        bytes.push_byte(0);
    }
    *bytes.last_byte_mut().expect("byte") |= bit << (7 - *length % 8);
    *length += 1;
}
pub(super) fn bigint(term: Term) -> Result<BigInt, BifError> {
    if let Some(n) = term.as_small() {
        return Ok(BigInt::from(n));
    }
    // SAFETY: The number heap remains live for this call.
    unsafe { term.big_ref() }
        .map(|view| view.to_bigint())
        .ok_or(BADARG)
}
macro_rules! predicate {
    ($name:ident, $body:expr) => {
        fn $name(_: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
            Ok(bool_term($body(args[0])))
        }
    };
}
predicate!(is_atom, |t: Term| t.classify() == TermKind::Atom);
predicate!(is_list, |t: Term| matches!(
    t.classify(),
    TermKind::List | TermKind::Nil
));
predicate!(is_tuple, |t: Term| matches!(
    t.classify(),
    TermKind::Tuple | TermKind::Record
));
predicate!(is_float, |t: Term| t.classify() == TermKind::Number
    && t.as_small().is_none()
    && {
        // SAFETY: A live boxed number can be queried through its typed view.
        unsafe { t.float_ref() }.is_some()
    });
predicate!(is_integer, |t: Term| t.as_small().is_some() || {
    // SAFETY: A live boxed number can be queried through its typed view.
    unsafe { t.big_ref() }.is_some()
});
predicate!(is_number, |t: Term| t.classify() == TermKind::Number);
predicate!(is_pid, |t: Term| t.classify() == TermKind::Pid);
predicate!(is_port, |t: Term| t.classify() == TermKind::Port);
predicate!(is_reference, |t: Term| t.classify() == TermKind::Ref);
predicate!(is_bitstring, |t: Term| t.classify() == TermKind::Bitstring);
predicate!(is_binary, |t: Term| {
    // SAFETY: The source heap and binary owner remain live.
    unsafe { t.binary_ref() }.is_some_and(|b| b.bit_len() % 8 == 0)
});
predicate!(
    is_boolean,
    |t: Term| matches!(t.as_atom(), Some(a) if a == atoms::TRUE || a == atoms::FALSE)
);
predicate!(is_map, |t: Term| t.classify() == TermKind::Map);

fn is_integer_range(_: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    // Port of erts/emulator/beam/erl_bif_guard.c:337 (is_integer_3), OTP-29.1.1.
    let lower = bigint(args[1])?;
    let upper = bigint(args[2])?;
    Ok(bool_term(
        bigint(args[0]).is_ok_and(|value| lower <= value && value <= upper),
    ))
}
fn is_function(_: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    if args.len() == 1 {
        return Ok(bool_term(args[0].classify() == TermKind::Fun));
    }
    let arity = args[1].as_small().ok_or(BADARG)?;
    if !(0..=255).contains(&arity) {
        return Err(BADARG);
    }
    if args[0].classify() != TermKind::Fun {
        return Ok(bool_term(false));
    }
    // SAFETY: The source fun and its retained entry remain live for the call.
    let view = unsafe { args[0].fun_ref() }.ok_or(BADARG)?;
    let actual = match view {
        arinsal_term::FunRef::Local { entry, .. } => entry.arity,
        arinsal_term::FunRef::Export { entry } => entry.arity,
    };
    Ok(bool_term(actual as i64 == arity))
}
fn is_record(_: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    if args.len() == 1 {
        return Ok(bool_term(args[0].classify() == TermKind::Record));
    }
    if args[1].as_atom().is_none() {
        return Err(BADARG);
    }
    let arity = if args.len() == 3 {
        if args[2].classify() == TermKind::Number && args[2].as_small().is_none() {
            return Err(BADARG);
        }
        Some(args[2].as_small())
    } else {
        None
    };
    let Ok(tuple_size) = tuple_arity(args[0]) else {
        return Ok(bool_term(false));
    };
    if tuple_size == 0 || tuple_element(args[0], 0)? != args[1] {
        return Ok(bool_term(false));
    }
    Ok(bool_term(
        arity.is_none_or(|n| n == Some(tuple_size as i64)),
    ))
}
fn cmp_term(_: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    // Port of erts/emulator/beam/bif.c:5417-5427 and erl_utils.h:122, OTP-29.1.1.
    let order = arinsal_term::cmp_exact(args[0], args[1]);
    let n = match order {
        Ordering::Less => -1,
        Ordering::Equal => 0,
        Ordering::Greater => 1,
    };
    Ok(Term::small(n).expect("small comparison"))
}
/// Port of erts/emulator/beam/beam_debug.c:170-193 (erts_debug_copy_shared_2), OTP-29.1.1.
fn debug_copy_shared(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    if args[1] != Term::atom(global_atoms().intern("true").expect("built-in atom"))
        && args[1] != Term::atom(global_atoms().intern("false").expect("built-in atom"))
    {
        return Err(BifError::BADARG);
    }
    copy_term(args[0], &mut ctx.heap).map_err(|_| BifError::SystemLimit)
}
fn debug_flat_size(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    integer(ctx, flat_size(args[0]))
}
fn debug_same(_: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    Ok(bool_term(args[0] == args[1]))
}
fn bin_is_7bit(_: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    Ok(bool_term(
        binary_bifs::with_binary_input(args[0], |bytes| Ok(bytes.iter().all(u8::is_ascii)))
            .is_ok_and(|is_ascii| is_ascii),
    ))
}
fn map_entries(ctx: &mut Ctx<'_>, term: Term) -> Result<Vec<(Term, Term)>, BifError> {
    if term.classify() != TermKind::Map {
        let reason = tuple_build(
            ctx,
            &[
                Term::atom(global_atoms().intern("badmap").expect("atom")),
                term,
            ],
        );
        return Err(BifError::Error(reason));
    }
    // SAFETY: The source map heap remains live and stable.
    unsafe { term.flatmap_ref() }
        .map(|map| map.iter().collect())
        .ok_or(BADARG)
}
fn map_size(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let len = map_entries(ctx, args[0])?.len();
    integer(ctx, len)
}
fn is_map_key(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    Ok(bool_term(
        map_entries(ctx, args[1])?
            .iter()
            .any(|(k, _)| exact_eq(*k, args[0])),
    ))
}
fn map_get(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    match map_entries(ctx, args[1])?
        .into_iter()
        .find(|(k, _)| exact_eq(*k, args[0]))
    {
        Some((_, value)) => Ok(value),
        None => Err(BifError::Error(tuple_build(
            ctx,
            &[
                Term::atom(global_atoms().intern("badkey").expect("atom")),
                args[0],
            ],
        ))),
    }
}
fn is_builtin(_: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let module = atom_name(args[0]).ok_or(BADARG)?;
    let name = atom_name(args[1]).ok_or(BADARG)?;
    let arity = args[2].as_small().ok_or(BADARG)?;
    if arity < 0 {
        return Err(BADARG);
    }
    // Port of erts/emulator/beam/beam_common.c:2359-2380 (erts_is_builtin), OTP-29.1.1.
    let instruction_bif = module == "erlang"
        && ((name == "apply" && matches!(arity, 2 | 3)) || (name == "yield" && arity == 0));
    Ok(bool_term(
        instruction_bif
            || u8::try_from(arity)
                .ok()
                .and_then(|n| arinsal_spec::bif_lookup(module, name, n))
                .is_some(),
    ))
}
fn error(_: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    Err(BifError::Raise {
        class: Class::Error,
        reason: args[0],
        stacktrace: None,
    })
}
fn exit(_: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    Err(BifError::Raise {
        class: Class::Exit,
        reason: args[0],
        stacktrace: None,
    })
}
fn throw(_: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    Err(BifError::Raise {
        class: Class::Throw,
        reason: args[0],
        stacktrace: None,
    })
}
fn raise(_: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let invalid = || Term::atom(global_atoms().intern("badarg").expect("atom"));
    let class = match atom_name(args[0]) {
        Some("error") => Class::Error,
        Some("exit") => Class::Exit,
        Some("throw") => Class::Throw,
        _ => return Ok(invalid()),
    };
    if !valid_raise_stacktrace(args[2]) {
        return Ok(invalid());
    }
    Err(BifError::Raise {
        class,
        reason: args[1],
        stacktrace: Some(args[2]),
    })
}

// Port of erts/emulator/beam/bif.c (raise_3 stacktrace validation), OTP-29.1.1.
fn valid_raise_stacktrace(stacktrace: Term) -> bool {
    for_each_cons(stacktrace, |frame| {
        let Some(fields) = tuple_terms(frame) else {
            return Err(BADARG);
        };
        let valid_location =
            |location: Term| matches!(location.classify(), TermKind::List | TermKind::Nil);
        let valid = match fields.as_slice() {
            [fun, _args] if fun.classify() == TermKind::Fun => true,
            [fun, _args, location] if fun.classify() == TermKind::Fun => valid_location(*location),
            [module, function, _arity_or_args] => {
                module.classify() == TermKind::Atom && function.classify() == TermKind::Atom
            }
            [module, function, _arity_or_args, location] => {
                module.classify() == TermKind::Atom
                    && function.classify() == TermKind::Atom
                    && valid_location(*location)
            }
            _ => false,
        };
        if valid { Ok(()) } else { Err(BADARG) }
    })
    .is_ok()
}

fn numeric_float(term: Term) -> Result<f64, BifError> {
    if let Some(n) = term.as_small() {
        return Ok(n as f64);
    }
    // SAFETY: The source number's heap remains live during this call.
    if let Some(view) = unsafe { term.float_ref() } {
        return Ok(view.get());
    }
    // SAFETY: The source number's heap remains live during this call.
    if let Some(view) = unsafe { term.big_ref() } {
        return view.to_bigint().to_f64().ok_or(BifError::Badarith);
    }
    Err(BADARG)
}
fn abs(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    // SAFETY: The source float heap remains live during this call.
    if let Some(view) = unsafe { args[0].float_ref() } {
        return Ok(TermBuilder::new(&mut Heap(&mut ctx.heap))
            .float(view.get().abs())
            .expect("infallible BIF heap"));
    }
    let value = bigint(args[0])?;
    let positive = if value.sign() == Sign::Minus {
        -value
    } else {
        value
    };
    TermBuilder::new(&mut Heap(&mut ctx.heap))
        .int_from_bigint(&positive)
        .map_err(|_| BifError::SystemLimit)
}
fn to_float(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    // SAFETY: The source float heap remains live during this call.
    if unsafe { args[0].float_ref() }.is_some() {
        return Ok(args[0]);
    }
    let value = bigint(args[0])?.to_f64().ok_or(BADARG)?;
    Ok(TermBuilder::new(&mut Heap(&mut ctx.heap))
        .float(value)
        .expect("infallible BIF heap"))
}
fn float_integer(ctx: &mut Ctx<'_>, term: Term, op: fn(f64) -> f64) -> Result<Term, BifError> {
    // SAFETY: The source float heap remains live during this call.
    let Some(view) = (unsafe { term.float_ref() }) else {
        bigint(term)?;
        return Ok(term);
    };
    let value = BigInt::from_f64(op(view.get())).ok_or(BADARG)?;
    TermBuilder::new(&mut Heap(&mut ctx.heap))
        .int_from_bigint(&value)
        .map_err(|_| BifError::SystemLimit)
}
fn trunc(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    float_integer(ctx, args[0], f64::trunc)
}
fn round(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    float_integer(ctx, args[0], f64::round)
}
fn ceil(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    float_integer(ctx, args[0], f64::ceil)
}
fn floor(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    float_integer(ctx, args[0], f64::floor)
}
fn math_result(ctx: &mut Ctx<'_>, result: f64) -> Result<Term, BifError> {
    if !result.is_finite() {
        return Err(BifError::Badarith);
    }
    Ok(TermBuilder::new(&mut Heap(&mut ctx.heap))
        .float(result)
        .expect("infallible BIF heap"))
}
macro_rules! math_unary {
    ($($name:ident => $method:expr),* $(,)?) => {$(
        fn $name(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
            math_result(ctx, $method(numeric_float(args[0])?))
        }
    )*};
}
// OTP's math BIFs call the platform libm. These three Rust/libm-crate
// implementations round differently on macOS, including observable last bits.
#[link(name = "m")]
unsafe extern "C" {
    fn atanh(x: f64) -> f64;
    fn erf(x: f64) -> f64;
    fn erfc(x: f64) -> f64;
}
fn c_atanh(x: f64) -> f64 {
    // SAFETY: The C math function accepts and returns a plain IEEE 754 double.
    unsafe { atanh(x) }
}
fn c_erf(x: f64) -> f64 {
    // SAFETY: The C math function accepts and returns a plain IEEE 754 double.
    unsafe { erf(x) }
}
fn c_erfc(x: f64) -> f64 {
    // SAFETY: The C math function accepts and returns a plain IEEE 754 double.
    unsafe { erfc(x) }
}
math_unary!(
    math_cos => f64::cos,
    math_cosh => f64::cosh,
    math_sin => f64::sin,
    math_sinh => f64::sinh,
    math_tan => f64::tan,
    math_tanh => f64::tanh,
    math_acos => f64::acos,
    math_acosh => f64::acosh,
    math_asin => f64::asin,
    math_asinh => f64::asinh,
    math_atan => f64::atan,
    math_atanh => c_atanh,
    math_erf => c_erf,
    math_erfc => c_erfc,
    math_exp => f64::exp,
    math_log => f64::ln,
    math_log2 => f64::log2,
    math_log10 => f64::log10,
    math_sqrt => f64::sqrt,
    math_floor => f64::floor,
    math_ceil => f64::ceil,
);
macro_rules! math_binary {
    ($($name:ident => $method:expr),* $(,)?) => {$(
        fn $name(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
            math_result(ctx, $method(numeric_float(args[0])?, numeric_float(args[1])?))
        }
    )*};
}
math_binary!(
    math_atan2 => f64::atan2,
    math_pow => f64::powf,
    math_fmod => |x: f64, y: f64| x % y,
);

crate::bif_bodies!(
    abs,
    to_float,
    trunc,
    round,
    ceil,
    floor,
    size,
    node,
    self_bif,
    min,
    max,
    not,
    and,
    or,
    xor,
    eq,
    ne,
    exact_eq_bif,
    exact_ne,
    lt,
    le,
    gt,
    ge,
    phash2_bif,
    phash_bif,
    make_ref,
    unique_integer,
    system_time,
    time_unit,
    atom_to_binary,
    binary_to_atom,
    binary_to_existing_atom,
    float_to_list,
    float_to_binary,
    list_to_float,
    binary_to_float,
    integer_to_binary,
    is_atom,
    is_list,
    is_tuple,
    is_float,
    is_integer,
    is_integer_range,
    is_number,
    is_pid,
    is_port,
    is_reference,
    is_binary,
    is_bitstring,
    is_function,
    is_record,
    is_boolean,
    is_map,
    is_map_key,
    map_get,
    map_size,
    is_builtin,
    error,
    exit,
    throw,
    raise,
    cmp_term,
    debug_copy_shared,
    debug_flat_size,
    debug_same,
    bin_is_7bit,
    math_cos,
    math_cosh,
    math_sin,
    math_sinh,
    math_tan,
    math_tanh,
    math_acos,
    math_acosh,
    math_asin,
    math_asinh,
    math_atan,
    math_atanh,
    math_erf,
    math_erfc,
    math_exp,
    math_log,
    math_log2,
    math_log10,
    math_sqrt,
    math_floor,
    math_ceil,
    math_atan2,
    math_pow,
    math_fmod,
);

crate::process_bif_bodies_in!(process_bodies;
    hd, tl, element, setelement, tuple_size, tuple_to_list, list_to_tuple, make_tuple,
    append_element, delete_element, insert_element, atom_to_list, list_to_atom,
    list_to_existing_atom,
);
