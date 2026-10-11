//! `maps:merge/2`, `maps:from_list/1` and `maps:from_keys/2` as erts builds
//! them: single-pass flatmap merge, structural HAMT merge with node reuse and
//! reduction-bounded yielding, and hash-sorted bulk HAMT construction.

use super::{
    LIMIT, MAP, MAP_HEADER_FLATMAP, MapError, MapResult, bits, boxed, check, exact_cmp, key_cmp,
    term,
};
use arinsal_term::{HeapAlloc, Term, TermError, exact_eq};
use smallvec::SmallVec;
use std::cmp::Ordering;
use std::mem::MaybeUninit;

// Port of erts/emulator/beam/erl_map.h:220 (HAMT_MAX_LEVEL), OTP-29.1.1.
const HAMT_MAX_LEVEL: usize = 16;
const HEAD_ARRAY: u64 = 2;
const HEAD_BITMAP: u64 = 3;
const NODE_BITMAP: u64 = 1;
// Port of erts/emulator/beam/erl_map.c:112 (HALLOC_EXTRA), OTP-29.1.1.
const HALLOC_EXTRA: usize = 200;

// Port of erts_write_heap_filler (erl_term.h:1500), OTP-29.1.1.
fn heap_filler_header(words: usize) -> u64 {
    debug_assert!(words > 0);
    ((words as u64 - 1) << 6) | 0x08
}

/// Fresh, uninitialized heap words (`HAlloc`).
#[inline(always)]
pub(crate) fn produce<'a, H: HeapAlloc + ?Sized>(
    heap: &mut H,
    words: usize,
) -> Result<(&'a mut [MaybeUninit<u64>], *mut u64), TermError> {
    let ptr = heap.alloc(words).ok_or(TermError::HeapFull)?;
    Ok((uninitialized_words(ptr, words), ptr))
}

/// Fresh words allocated with ERTS's merge-node fragment reserve.
fn produce_with_extra<'a, H: HeapAlloc + ?Sized>(
    heap: &mut H,
    words: usize,
    extra: usize,
) -> Result<(&'a mut [MaybeUninit<u64>], *mut u64), TermError> {
    let ptr = heap
        .alloc_with_extra(words, extra)
        .ok_or(TermError::HeapFull)?;
    Ok((uninitialized_words(ptr, words), ptr))
}

fn uninitialized_words<'a>(ptr: *mut u64, words: usize) -> &'a mut [MaybeUninit<u64>] {
    // SAFETY: the allocator returned `words` writable words that nothing else
    // references; MaybeUninit admits their uninitialized contents.
    unsafe { std::slice::from_raw_parts_mut(ptr.cast::<MaybeUninit<u64>>(), words) }
}

/// The words of a live boxed object: header plus `len - 1` payload words.
pub(crate) fn boxed_words<'a>(object: Term, len: usize) -> &'a [u64] {
    // SAFETY: callers pass a live boxed object of at least `len` words; heap
    // objects are not moved or freed while a BIF reads them.
    unsafe { std::slice::from_raw_parts(object.raw_ptr(), len) }
}

/// Key and value of a HAMT leaf cons.
pub(crate) fn leaf(cons: Term) -> (Term, Term) {
    // SAFETY: HAMT leaves are live conses.
    unsafe { cons.cons_ref() }.expect("HAMT leaf")
}

fn is_leaf(node: Term) -> bool {
    bits(node) & 3 == 1
}

/// A HAMT node: its header and its words (children start after the head size).
pub(crate) enum NodeView<'a> {
    /// Bitmap or array node: child terms in slot order.
    Bitmap(&'a [u64]),
    /// Collision tuple of leaves in `CMP_TERM` order.
    Collision(&'a [u64]),
}

/// Decode a HAMT head, bitmap node or collision tuple.
///
/// Port of erts/emulator/beam/erl_map.h:178-205 (HAMT headers), OTP-29.1.1.
pub(crate) fn node_view<'a>(node: Term) -> NodeView<'a> {
    let header = node.header().expect("HAMT node");
    if header & 63 == MAP {
        let bitmap = ((header >> 16) & 0xffff) as u32;
        let (skip, count) = match (header >> 6) & 3 {
            HEAD_ARRAY => (2, 16),
            HEAD_BITMAP => (2, bitmap.count_ones() as usize),
            NODE_BITMAP => (1, bitmap.count_ones() as usize),
            _ => unreachable!("flatmap is not a HAMT node"),
        };
        NodeView::Bitmap(&boxed_words(node, skip + count)[skip..])
    } else {
        let arity = (header >> 6) as usize;
        NodeView::Collision(&boxed_words(node, 1 + arity)[1..])
    }
}

/// Size word of a HAMT head.
fn hashmap_size(map: Term) -> usize {
    boxed_words(map, 2)[1] as usize
}

/// Flatmap keys and values.
pub(crate) fn flatmap_kv<'a>(map: Term) -> (&'a [u64], &'a [u64], Term) {
    let n = boxed_words(map, 2)[1] as usize;
    flatmap_kv_with_size(map, n)
}

/// Flatmap key and value words when the caller already has its checked size.
#[inline(always)]
pub(crate) fn flatmap_kv_with_size<'a>(map: Term, n: usize) -> (&'a [u64], &'a [u64], Term) {
    let words = boxed_words(map, 3 + n);
    let keys = term(words[2]);
    (&boxed_words(keys, 1 + n)[1..], &words[3..], keys)
}

// Port of erts/emulator/beam/erl_map.c:1858-1865 (hashmap_subtree_size), OTP-29.1.1.
fn hashmap_subtree_size(node: Term) -> usize {
    let mut stack: SmallVec<[(Term, usize); 8]> = SmallVec::new();
    stack.push((node, 0));
    let mut size = 0;
    while let Some((parent, index)) = stack.last().copied() {
        let children = match node_view(parent) {
            NodeView::Bitmap(children) | NodeView::Collision(children) => children,
        };
        if index == children.len() {
            stack.pop();
            continue;
        }
        stack.last_mut().expect("subtree stack").1 += 1;
        let child = term(children[index]);
        if is_leaf(child) {
            size += 1;
        } else {
            stack.push((child, 0));
        }
    }
    size
}

/// Map a fallible heap construction to the public map error type. Runtime BIFs
/// use `FragmentingHeap`, so heap exhaustion is only possible for callers that
/// deliberately supply a finite standalone heap.
pub(crate) fn allocation_result<T>(result: Result<T, TermError>) -> MapResult<T> {
    match result {
        Ok(value) => Ok(value),
        Err(TermError::HeapFull) => Err(MapError::HeapFull { need_words: 0 }),
        Err(error) => unreachable!("map construction failed: {error:?}"),
    }
}

/// Build a flatmap from key/value arrays already in flatmap key order.
pub(crate) fn flatmap_from_sorted<H: HeapAlloc + ?Sized>(
    ks: &[Term],
    vs: &[Term],
    heap: &mut H,
) -> Result<Term, TermError> {
    // Port of erts/emulator/beam/erl_map.c:379-457 (heap layout), OTP-29.1.1.
    let n = ks.len();
    if n == 0 {
        return super::empty_flatmap(heap);
    }
    let (slice, ptr) = produce(heap, 4 + 2 * n)?;
    slice[0].write((n as u64) << 6);
    for (slot, key) in slice[1..=n].iter_mut().zip(ks) {
        slot.write(bits(*key));
    }
    slice[1 + n].write(MAP_HEADER_FLATMAP);
    slice[2 + n].write(n as u64);
    slice[3 + n].write(ptr as u64 | 2);
    for (slot, value) in slice[4 + n..].iter_mut().zip(vs) {
        slot.write(bits(*value));
    }
    Ok(term(ptr.wrapping_add(1 + n) as u64 | 2))
}

/// Hash-sorted HAMT from unique (or later-wins) key/value arrays.
fn hashmap_from_pairs<H: HeapAlloc + ?Sized>(
    pairs: impl ExactSizeIterator<Item = (Term, Term)>,
    heap: &mut H,
) -> Result<Term, TermError> {
    let mut hxns = arinsal_term::hashmap_leaves(pairs, heap)?;
    Ok(
        arinsal_term::hashmap_from_unsorted_array(&mut hxns, false, heap)?
            .expect("duplicates accepted"),
    )
}

// Port of erts/emulator/beam/erl_map.c:1286-1423 (flatmap_merge), OTP-29.1.1.
fn flatmap_merge<H: HeapAlloc + ?Sized>(
    map1: Term,
    map2: Term,
    heap: &mut H,
) -> Result<Term, TermError> {
    let (ks1, vs1, keys1) = flatmap_kv(map1);
    let (ks2, vs2, keys2) = flatmap_kv(map2);
    let (n1, n2) = (ks1.len(), ks2.len());
    if n1 == 0 {
        return Ok(map2);
    }
    if n2 == 0 {
        return Ok(map1);
    }
    let capacity = n1 + n2;
    let words_needed = 4 + 2 * capacity;
    let (output, output_ptr) = produce(heap, words_needed)?;
    let values_start = 3;
    let keys_tuple_start = values_start + capacity;
    let keys_start = keys_tuple_start + 1;
    output[0].write(MAP_HEADER_FLATMAP);
    output[1].write(0);
    output[2].write(bits(boxed(output_ptr.wrapping_add(keys_tuple_start))));
    output[keys_tuple_start].write(0);
    let (mut i1, mut i2, mut unused_size) = (0, 0, 0);
    let mut n = 0;
    while i1 < n1 && i2 < n2 {
        let c = if ks1[i1] == ks2[i2] {
            Ordering::Equal
        } else {
            key_cmp(term(ks1[i1]), term(ks2[i2]))
        };
        match c {
            Ordering::Equal => {
                output[keys_start + n].write(ks2[i2]);
                output[values_start + n].write(vs2[i2]);
                i1 += 1;
                i2 += 1;
                unused_size += 1;
            }
            Ordering::Less => {
                output[keys_start + n].write(ks1[i1]);
                output[values_start + n].write(vs1[i1]);
                i1 += 1;
            }
            Ordering::Greater => {
                output[keys_start + n].write(ks2[i2]);
                output[values_start + n].write(vs2[i2]);
                i2 += 1;
            }
        }
        n += 1;
    }
    while i1 < n1 {
        output[keys_start + n].write(ks1[i1]);
        output[values_start + n].write(vs1[i1]);
        i1 += 1;
        n += 1;
    }
    while i2 < n2 {
        output[keys_start + n].write(ks2[i2]);
        output[values_start + n].write(vs2[i2]);
        i2 += 1;
        n += 1;
    }
    output[1].write(n as u64);
    output[keys_tuple_start].write((n as u64) << 6);
    if unused_size > 0 {
        if n == n2 {
            // Reuse all of map2; adopt map1's literal key tuple when map2's is not.
            if n == n1 && keys1.is_literal() && !keys2.is_literal() {
                map2.flatmap_replace_keys(keys1);
            }
            output[0].write(heap_filler_header(words_needed));
            heap.release(output_ptr.wrapping_add(words_needed), output_ptr);
            return Ok(map2);
        } else if n == n1 {
            output[2].write(bits(keys1));
            let release_from = values_start + n;
            output[release_from].write(heap_filler_header(words_needed - release_from));
            heap.release(
                output_ptr.wrapping_add(words_needed),
                output_ptr.wrapping_add(release_from),
            );
            return Ok(boxed(output_ptr));
        } else {
            output[values_start + n].write(heap_filler_header(unused_size));
            let release_from = keys_start + n;
            output[release_from].write(heap_filler_header(words_needed - release_from));
            heap.release(
                output_ptr.wrapping_add(words_needed),
                output_ptr.wrapping_add(release_from),
            );
        }
    }
    let merged = boxed(output_ptr);
    if n > LIMIT {
        let (ks, vs, _) = flatmap_kv(merged);
        return hashmap_from_pairs(
            ks.iter()
                .copied()
                .zip(vs.iter().copied())
                .map(|(key, value)| (term(key), term(value))),
            heap,
        );
    }
    Ok(merged)
}

/// One level of the parallel HAMT walk (`struct HashmapMergePStackType`).
///
/// Port of erts/emulator/beam/erl_map.c:1467-1476, OTP-29.1.1. `srcA`/`srcB`
/// are pointers into the parent's child words in erts; here they are a node
/// and a word index, or the root term held by the frame itself.
#[derive(Clone, Copy)]
struct Frame {
    node_a: Term,
    node_b: Term,
    src_a: Src,
    src_b: Src,
    abm: u32,
    bbm: u32,
    rbm: u32,
    /// `&1`: unique A content in this node; `&2`: unique B content.
    mix: u8,
    ix: usize,
    array: [u64; 16],
}

#[derive(Clone, Copy)]
enum Src {
    /// The root map term.
    Root(Term),
    /// Remaining child words, corresponding to ERTS's advancing `Eterm*`.
    Slots(&'static [u64]),
}
impl Src {
    fn get(self) -> Term {
        match self {
            Self::Root(t) => t,
            Self::Slots(words) => term(*words.first().expect("merge source slot")),
        }
    }
    // Port of `*srcA++` / `*srcB++` in erl_map.c:1758-1763, OTP-29.1.1.
    fn next(&mut self) -> Term {
        match self {
            Self::Root(t) => *t,
            Self::Slots(words) => {
                let (word, remaining) = words.split_first().expect("merge source slot");
                *words = remaining;
                term(*word)
            }
        }
    }
    fn advance(&mut self) {
        if let Self::Slots(words) = self
            && let Some((_, remaining)) = words.split_first()
        {
            *words = remaining;
        }
    }
    fn get_at(self, offset: usize) -> Term {
        match self {
            Self::Root(t) => {
                debug_assert_eq!(offset, 0);
                t
            }
            Self::Slots(words) => term(words[offset]),
        }
    }
}

/// Saved state of a yielding HAMT merge (`HashmapMergeContext`).
///
/// Port of erts/emulator/beam/erl_map.c:1478-1486, OTP-29.1.1. It holds heap
/// terms, so the owning process must not collect garbage while it is saved
/// (erts clears the GC state while trapped).
pub struct HashmapMergeContext {
    size: usize,
    lvl: usize,
    stack: SmallVec<[Frame; 4]>,
    started: bool,
}
impl std::fmt::Debug for HashmapMergeContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HashmapMergeContext")
            .field("size", &self.size)
            .field("lvl", &self.lvl)
            .field("depth", &self.stack.len())
            .finish()
    }
}

impl HashmapMergeContext {
    // Port of erts/emulator/beam/erl_map.c:1592-1606 (first call setup), OTP-29.1.1.
    fn new(map_a: Term, map_b: Term, swap_args: bool) -> Self {
        let (src_a, src_b) = if swap_args {
            (map_b, map_a)
        } else {
            (map_a, map_b)
        };
        let mut stack = SmallVec::new();
        stack.push(Frame {
            node_a: Term::NIL,
            node_b: Term::NIL,
            src_a: Src::Root(src_a),
            src_b: Src::Root(src_b),
            abm: 0,
            bbm: 0,
            rbm: 0,
            mix: 0,
            ix: 0,
            array: [0; 16],
        });
        Self {
            size: hashmap_size(map_a) + hashmap_size(map_b),
            lvl: 0,
            stack,
            started: false,
        }
    }
}

// Port of erts/emulator/beam/erl_map.c:1510-1555 (merge_collision_node), OTP-29.1.1.
fn merge_collision_node<H: HeapAlloc + ?Sized>(
    src_a: Src,
    sz_a: usize,
    src_b: Src,
    sz_b: usize,
    map_size: &mut usize,
    heap: &mut H,
) -> Result<Term, TermError> {
    debug_assert!(sz_a >= 1 && sz_b >= 1);
    let capacity = 1 + sz_a + sz_b;
    let (words, ptr) = produce(heap, capacity)?;
    let mut out = 1;
    let (mut ia, mut ib) = (0, 0);
    while ia < sz_a && ib < sz_b {
        let a = src_a.get_at(ia);
        let b = src_b.get_at(ib);
        let key_a = leaf(a).0;
        let key_b = leaf(b).0;
        match exact_cmp(key_a, key_b, false) {
            Ordering::Less => {
                words[out].write(bits(a));
                out += 1;
                ia += 1;
            }
            order => {
                words[out].write(bits(b));
                out += 1;
                ib += 1;
                if order == Ordering::Equal {
                    ia += 1;
                    *map_size -= 1;
                }
            }
        }
    }
    while ia < sz_a {
        words[out].write(bits(src_a.get_at(ia)));
        out += 1;
        ia += 1;
    }
    while ib < sz_b {
        words[out].write(bits(src_b.get_at(ib)));
        out += 1;
        ib += 1;
    }
    let arity = out - 1;
    debug_assert!(arity >= 2);
    words[0].write((arity as u64) << 6);
    if out < capacity {
        words[out].write(heap_filler_header(capacity - out));
        heap.release(ptr.wrapping_add(capacity), ptr.wrapping_add(out));
    }
    Ok(boxed(ptr))
}

/// Decode one side of a node pair for the walk: its bitmap at `lvl` (or its
/// collision run length at the last level) and where its children start.
fn open_node(node: Term, src: &mut Src, lvl: usize, bm: &mut u32, coll_sz: &mut usize) {
    if is_leaf(node) {
        if lvl < HAMT_MAX_LEVEL {
            // hashmap_restore_hash + hashmap_index
            let hx = arinsal_term::internal_hash(leaf(node).0) >> (4 * lvl);
            *bm = 1 << (hx & 0xf);
        } else {
            *coll_sz = 1;
        }
        // src keeps pointing at the leaf.
        return;
    }
    let header = node.header().expect("HAMT node");
    if header & 63 == MAP {
        debug_assert!(lvl < HAMT_MAX_LEVEL);
        match (header >> 6) & 3 {
            HEAD_ARRAY => {
                *src = Src::Slots(&boxed_words(node, 18)[2..]);
                *bm = 0xffff;
            }
            HEAD_BITMAP => {
                *bm = ((header >> 16) & 0xffff) as u32;
                *src = Src::Slots(&boxed_words(node, 2 + bm.count_ones() as usize)[2..]);
            }
            _ => {
                *bm = ((header >> 16) & 0xffff) as u32;
                *src = Src::Slots(&boxed_words(node, 1 + bm.count_ones() as usize)[1..]);
            }
        }
    } else {
        debug_assert_eq!(lvl, HAMT_MAX_LEVEL);
        *coll_sz = (header >> 6) as usize;
        *src = Src::Slots(&boxed_words(node, 1 + *coll_sz)[1..]);
        debug_assert!(*coll_sz >= 2);
    }
}

/// Reductions-to-work factor of the HAMT merge.
///
/// Port of erts/emulator/beam/erl_map.c:1508 (MAP_MERGE_LOOP_FACTOR), OTP-29.1.1.
pub const MAP_MERGE_LOOP_FACTOR: isize = 8;

/// Continue a HAMT merge with `reds` loop iterations of budget. Returns the
/// merged map, or `None` when the budget ran out and the call must trap.
///
/// Port of erts/emulator/beam/erl_map.c:1558-1861 (hashmap_merge), OTP-29.1.1.
/// The heap must not fail (erts allocates with `HAlloc`): a `HeapFull` error
/// carries no size and leaves the context unusable. Use [`merge`] with a
/// fallible heap.
pub fn hashmap_merge<H: HeapAlloc + ?Sized>(
    ctx: &mut HashmapMergeContext,
    reds: &mut isize,
    heap: &mut H,
) -> MapResult<Option<Term>> {
    hashmap_merge_loop(ctx, reds, heap).map_err(|_| MapError::HeapFull { need_words: 0 })
}

fn hashmap_merge_loop<H: HeapAlloc + ?Sized>(
    ctx: &mut HashmapMergeContext,
    reds: &mut isize,
    heap: &mut H,
) -> Result<Option<Term>, TermError> {
    let mut res: Option<Term> = None;
    let (mut coll_sz_a, mut coll_sz_b) = (0, 0);
    let mut resume_saved = ctx.started;
    ctx.started = true;
    'traverse: loop {
        if !resume_saved {
            // Port of the `recurse` label in erl_map.c:1608-1679, OTP-29.1.1.
            let lvl = ctx.lvl;
            let sp = ctx.stack.last_mut().expect("merge stack");
            sp.node_a = sp.src_a.get();
            sp.node_b = sp.src_b.get();
            if sp.node_a == sp.node_b {
                res = Some(sp.node_a);
                ctx.size -= if is_leaf(sp.node_b) {
                    1
                } else {
                    hashmap_subtree_size(sp.node_b)
                };
            } else if is_leaf(sp.node_a) && is_leaf(sp.node_b) {
                let key_a = leaf(sp.node_a).0;
                let key_b = leaf(sp.node_b).0;
                if exact_eq(key_a, key_b) {
                    ctx.size -= 1;
                    res = Some(sp.node_b);
                    // Values are assumed to differ; comparing them could be costly.
                    sp.mix = 2;
                } else {
                    let (node_a, node_b) = (sp.node_a, sp.node_b);
                    open_node(node_a, &mut sp.src_a, lvl, &mut sp.abm, &mut coll_sz_a);
                    open_node(node_b, &mut sp.src_b, lvl, &mut sp.bbm, &mut coll_sz_b);
                }
            } else {
                let (node_a, node_b) = (sp.node_a, sp.node_b);
                open_node(node_a, &mut sp.src_a, lvl, &mut sp.abm, &mut coll_sz_a);
                open_node(node_b, &mut sp.src_b, lvl, &mut sp.bbm, &mut coll_sz_b);
            }
        }

        let mut skip_merge_nodes = resume_saved;
        resume_saved = false;
        loop {
            if !skip_merge_nodes {
                // Port of the `merge_nodes` label in erl_map.c:1682-1724.
                if let Some(child) = res.take() {
                    if ctx.lvl == 0 {
                        debug_assert_eq!(hashmap_size(child), ctx.size);
                        return Ok(Some(child));
                    }
                    ctx.lvl -= 1;
                    let child_mix = ctx.stack.pop().expect("merge stack").mix;
                    let sp = ctx.stack.last_mut().expect("merge stack");
                    sp.array[sp.ix] = bits(child);
                    sp.ix += 1;
                    sp.mix |= child_mix;
                    if sp.rbm != 0 {
                        sp.src_a.advance();
                        sp.src_b.advance();
                    }
                } else if ctx.lvl < HAMT_MAX_LEVEL {
                    let sp = ctx.stack.last_mut().expect("merge stack");
                    sp.ix = 0;
                    sp.rbm = sp.abm | sp.bbm;
                    debug_assert!(!(sp.rbm == 0 && ctx.lvl > 0));
                } else {
                    let sp = ctx.stack.last_mut().expect("merge stack");
                    res = Some(merge_collision_node(
                        sp.src_a,
                        coll_sz_a,
                        sp.src_b,
                        coll_sz_b,
                        &mut ctx.size,
                        heap,
                    )?);
                    sp.mix = 3;
                    coll_sz_a = 0;
                    coll_sz_b = 0;
                    continue;
                }
                *reds -= 1;
                if *reds <= 0 {
                    debug_assert!(coll_sz_a == 0 && coll_sz_b == 0);
                    return Ok(None);
                }
            }
            skip_merge_nodes = false;

            // Port of the `resume_from_trap` label in erl_map.c:1727-1804.
            let lvl = ctx.lvl;
            let sp = ctx.stack.last_mut().expect("merge stack");
            let mut clash = false;
            while sp.rbm != 0 {
                let next = sp.rbm & (sp.rbm - 1);
                let bit = sp.rbm ^ next;
                sp.rbm = next;
                if sp.abm & bit != 0 {
                    if sp.bbm & bit != 0 {
                        clash = true;
                        break;
                    }
                    sp.array[sp.ix] = bits(sp.src_a.next());
                    sp.ix += 1;
                    sp.mix |= 1;
                } else {
                    debug_assert!(sp.bbm & bit != 0);
                    sp.array[sp.ix] = bits(sp.src_b.next());
                    sp.ix += 1;
                    sp.mix |= 2;
                }
            }
            if clash {
                let (src_a, src_b) = (sp.src_a, sp.src_b);
                ctx.lvl += 1;
                ctx.stack.push(Frame {
                    node_a: Term::NIL,
                    node_b: Term::NIL,
                    src_a,
                    src_b,
                    abm: 0,
                    bbm: 0,
                    rbm: 0,
                    mix: 0,
                    ix: 0,
                    array: [0; 16],
                });
                continue 'traverse;
            }
            res = Some(match sp.mix {
                0 | 1 => sp.node_a,
                2 => sp.node_b,
                3 => {
                    debug_assert_eq!(sp.ix, (sp.abm | sp.bbm).count_ones() as usize);
                    let bitmap = u64::from(sp.abm | sp.bbm);
                    let header_words = if lvl == 0 { 2 } else { 1 };
                    // Port of HAllocX(..., HALLOC_EXTRA) in erl_map.c:1783-1790.
                    let (words, ptr) =
                        produce_with_extra(heap, header_words + sp.ix, HALLOC_EXTRA)?;
                    if lvl == 0 {
                        words[0].write(if sp.ix == 16 {
                            super::header(HEAD_ARRAY, 0xffff)
                        } else {
                            super::header(HEAD_BITMAP, bitmap as u16)
                        });
                        words[1].write(ctx.size as u64);
                    } else {
                        words[0].write(super::header(NODE_BITMAP, bitmap as u16));
                    }
                    // Port of sys_memcpy(hp, sp->array, sp->ix * sizeof(Eterm)),
                    // erl_map.c:1793, OTP-29.1.1.
                    words[header_words..header_words + sp.ix]
                        .write_copy_of_slice(&sp.array[..sp.ix]);
                    boxed(ptr)
                }
                mix => unreachable!("strange mix {mix}"),
            });
        }
    }
}

/// Outcome of the non-yielding part of `maps:merge/2`.
// The inline stack is OTP's `PSTACK_DECLARE(s, 4)`; boxing it would allocate per merge.
#[allow(clippy::large_enum_variant)]
pub enum MergeStart {
    /// The merged map.
    Done(Term),
    /// Both maps are (or became) HAMTs; continue with [`hashmap_merge`].
    Hashmap(HashmapMergeContext),
}

/// Dispatch `maps:merge/2`: flatmap pairs merge immediately, HAMT pairs return
/// a context for the yielding structural merge.
///
/// Port of erts/emulator/beam/erl_map.c:1257-1284 (maps_merge_2) and
/// 1428-1465 (map_merge_mixed), OTP-29.1.1.
pub fn merge_start<H: HeapAlloc + ?Sized>(
    left: Term,
    right: Term,
    heap: &mut H,
) -> MapResult<MergeStart> {
    if left == right {
        check(left)?;
        return Ok(MergeStart::Done(left));
    }
    check(left)?;
    check(right)?;
    allocation_result(merge_start_checked(left, right, heap))
}

fn merge_start_checked<H: HeapAlloc + ?Sized>(
    left: Term,
    right: Term,
    heap: &mut H,
) -> Result<MergeStart, TermError> {
    match (left.is_hashmap(), right.is_hashmap()) {
        (false, false) => flatmap_merge(left, right, heap).map(MergeStart::Done),
        (false, true) => map_merge_mixed(left, right, false, heap),
        (true, false) => map_merge_mixed(right, left, true, heap),
        (true, true) => Ok(MergeStart::Hashmap(HashmapMergeContext::new(
            left, right, false,
        ))),
    }
}

fn map_merge_mixed<H: HeapAlloc + ?Sized>(
    flat: Term,
    tree: Term,
    swap_args: bool,
    heap: &mut H,
) -> Result<MergeStart, TermError> {
    let (ks, vs, _) = flatmap_kv(flat);
    if ks.is_empty() {
        return Ok(MergeStart::Done(tree));
    }
    let pairs = ks.iter().zip(vs).map(|(&k, &v)| (term(k), term(v)));
    let res = hashmap_from_pairs(pairs, heap)?;
    Ok(MergeStart::Hashmap(HashmapMergeContext::new(
        res, tree, swap_args,
    )))
}

/// `maps:merge/2` without yielding; right values win.
pub fn merge<H: HeapAlloc + ?Sized>(left: Term, right: Term, heap: &mut H) -> MapResult<Term> {
    if left == right {
        check(left)?;
        return Ok(left);
    }
    check(left)?;
    check(right)?;
    allocation_result((|| match merge_start_checked(left, right, heap)? {
        MergeStart::Done(map) => Ok(map),
        MergeStart::Hashmap(mut ctx) => {
            let mut reds = isize::MAX;
            Ok(hashmap_merge_loop(&mut ctx, &mut reds, heap)?.expect("unbounded merge completes"))
        }
    })())
}

// Port of erts/emulator/beam/erl_map.c:367-472 (flatmap_from_validated_list), OTP-29.1.1.
// `allocated` is the validated list length (`size` before the sort shrinks it).
// HAlloc `3 + 1 + 2 * allocated` words, insertion-sort into that block, then
// HRelease duplicate value slots and write a heap filler over unused key slots.
fn flatmap_from_validated_list<H: HeapAlloc + ?Sized>(
    allocated: usize,
    pairs: impl Iterator<Item = (Term, Term)>,
    heap: &mut H,
) -> Result<Term, TermError> {
    if allocated == 0 {
        return super::empty_flatmap(heap);
    }
    // erl_map.c:376-393. ks starts just after the key-tuple arity word; the
    // flatmap header is `MAP_HEADER_FLATMAP_SZ` (3) words; vs follows it.
    let words = 3 + 1 + 2 * allocated;
    let (block, ptr) = arinsal_term::alloc_terms(heap, words)?;
    block[0] = term((allocated as u64) << 6);
    let map_at = 1 + allocated;
    let vs = map_at + 3;
    block[map_at] = term(MAP_HEADER_FLATMAP);
    block[map_at + 1] = term(allocated as u64);
    block[map_at + 2] = term(ptr as u64 | 2);

    // erl_map.c:399-408, first entry, then size becomes 1.
    let mut pairs = pairs;
    let (key, value) = pairs
        .next()
        .expect("validated list length matches the iterator");
    // ks[0] is block[1]; vs[0] is block[vs].
    block[1] = key;
    block[vs] = value;
    let mut size = 1usize;
    let mut unused_size = 0usize;

    // erl_map.c:411-458, insertion sort in the HAlloc block.
    for (key, value) in pairs {
        // erl_map.c:432-436. `idx` is the hole. ks[idx - 1] is block[idx]
        // because ks[0] is block[1]. Stop on equal or greater.
        let mut idx = size;
        let mut ordering = Ordering::Less;
        while idx > 0 {
            ordering = key_cmp(key, block[idx]);
            if ordering != Ordering::Less {
                break;
            }
            idx -= 1;
        }
        if ordering == Ordering::Equal {
            // erl_map.c:438-445.
            block[idx] = key;
            block[vs + idx - 1] = value;
            unused_size += 1;
        } else {
            // erl_map.c:446-455. `ordering` is Less when the scan reached 0.
            let mut i = size;
            while i > idx {
                block[1 + i] = block[i];
                block[vs + i] = block[vs + i - 1];
                i -= 1;
            }
            block[1 + idx] = key;
            block[vs + idx] = value;
            size += 1;
        }
    }

    // erl_map.c:460-471.
    if unused_size > 0 {
        block[1 + size] = term(heap_filler_header(unused_size));
        let end = ptr.wrapping_add(vs + size + unused_size);
        let start = ptr.wrapping_add(vs + size);
        heap.release(end, start);
    }
    block[0] = term((size as u64) << 6);
    block[map_at + 1] = term(size as u64);
    Ok(boxed(ptr.wrapping_add(map_at)))
}

// Port of erts/emulator/beam/erl_map.c:482-591 (hashmap_from_validated_list), OTP-29.1.1.
fn hashmap_from_validated_list<H: HeapAlloc + ?Sized>(
    pairs: impl ExactSizeIterator<Item = (Term, Term)>,
    heap: &mut H,
) -> Result<Term, TermError> {
    let res = hashmap_from_pairs(pairs, heap)?;
    flatmap_if_small(res, heap)
}

/// Duplicates may have shrunk a built HAMT to a flatmap's size (erts_validate_and_sort_flatmap).
///
/// Port of erts/emulator/beam/erl_map.c:555-588 (tail of hashmap_from_validated_list),
/// OTP-29.1.1.
fn flatmap_if_small<H: HeapAlloc + ?Sized>(res: Term, heap: &mut H) -> Result<Term, TermError> {
    if hashmap_size(res) > LIMIT {
        return Ok(res);
    }
    let mut entries = Vec::with_capacity(hashmap_size(res));
    super::collect(res, &mut entries);
    entries.sort_by(|a, b| key_cmp(a.0, b.0));
    let ks: SmallVec<[Term; LIMIT]> = entries.iter().map(|p| p.0).collect();
    let vs: SmallVec<[Term; LIMIT]> = entries.iter().map(|p| p.1).collect();
    flatmap_from_sorted(&ks, &vs, heap)
}

/// Yielding `hashmap_from_validated_list` from the point where the input list has been walked
/// into hashed entries.
///
/// Port of erts/emulator/beam/erl_map.c:482-591 as transformed by YCF, OTP-29.1.1.
pub struct HashmapFromPairs {
    build: arinsal_term::HashmapBuild,
}

impl HashmapFromPairs {
    /// Allocate the `[Key | Value]` leaves of `entries` (swizzled hash, key, value).
    pub fn new<H: HeapAlloc + ?Sized>(
        entries: &[(u64, Term, Term)],
        heap: &mut H,
    ) -> MapResult<Self> {
        let hxns =
            arinsal_term::hashmap_leaves_hashed(entries, heap).map_err(|_| MapError::HeapFull {
                need_words: 2 * entries.len(),
            })?;
        Ok(Self {
            build: arinsal_term::HashmapBuild::new(hxns),
        })
    }

    /// Continue with `reds` reductions left; the finished map, or `None` after a yield.
    pub fn step<H: HeapAlloc + ?Sized>(
        &mut self,
        reds: &mut i64,
        heap: &mut H,
    ) -> MapResult<Option<Term>> {
        // The process heap grows by fragments, so exhaustion is not expected here.
        let heap_full = |_| MapError::HeapFull { need_words: 0 };
        let Some(res) = self.build.step(reds, heap).map_err(heap_full)? else {
            return Ok(None);
        };
        flatmap_if_small(res, heap).map(Some).map_err(heap_full)
    }
}

/// `maps:from_list/1` over validated pairs; later duplicates win.
///
/// Port of erts/emulator/beam/erl_map.c:317-366 (maps_from_list_1_helper), OTP-29.1.1.
pub fn from_list<H: HeapAlloc + ?Sized>(pairs: &[(Term, Term)], heap: &mut H) -> MapResult<Term> {
    allocation_result(if pairs.len() > LIMIT {
        hashmap_from_validated_list(pairs.iter().copied(), heap)
    } else {
        flatmap_from_validated_list(pairs.len(), pairs.iter().copied(), heap)
    })
}

/// The flatmap branch of `maps:from_list/1` and `maps:from_keys/2` over at most
/// `MAP_SMALL_MAP_LIMIT` validated pairs; later duplicates win.
///
/// `size` is the validated list length (erl_map.c:367 `size`, before duplicates
/// shrink the map). `pairs` yields exactly `size` elements.
///
/// Port of erts/emulator/beam/erl_map.c:367-472 (flatmap_from_validated_list), OTP-29.1.1.
pub fn from_small_pairs<H: HeapAlloc + ?Sized>(
    size: usize,
    pairs: impl Iterator<Item = (Term, Term)>,
    heap: &mut H,
) -> MapResult<Term> {
    allocation_result(flatmap_from_validated_list(size, pairs, heap))
}

/// `maps:from_keys/2`.
///
/// Port of erts/emulator/beam/erl_map.c:278-309 (maps_from_keys_2_helper), OTP-29.1.1.
pub fn from_keys<H: HeapAlloc + ?Sized>(
    keys: &[Term],
    value: Term,
    heap: &mut H,
) -> MapResult<Term> {
    allocation_result({
        let pairs = keys.iter().map(|&key| (key, value));
        if keys.len() > LIMIT {
            hashmap_from_validated_list(pairs, heap)
        } else {
            flatmap_from_validated_list(keys.len(), pairs, heap)
        }
    })
}
