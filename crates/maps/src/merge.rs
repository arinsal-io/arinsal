//! `maps:merge/2`, `maps:from_list/1` and `maps:from_keys/2` as erts builds
//! them: single-pass flatmap merge, structural HAMT merge with node reuse and
//! reduction-bounded yielding, and hash-sorted bulk HAMT construction.

use super::{LIMIT, MAP, MapError, MapResult, bits, check, exact_cmp, key_cmp, term};
use arinsal_term::{HeapAlloc, Term, TermError, exact_eq};
use smallvec::SmallVec;
use std::cmp::Ordering;
use std::mem::MaybeUninit;

// Port of erts/emulator/beam/erl_map.h:220 (HAMT_MAX_LEVEL), OTP-29.1.1.
const HAMT_MAX_LEVEL: usize = 16;
const HEAD_ARRAY: u64 = 2;
const HEAD_BITMAP: u64 = 3;
const NODE_BITMAP: u64 = 1;

/// Fresh, uninitialized heap words (`HAlloc`).
pub(crate) fn produce<'a, H: HeapAlloc + ?Sized>(
    heap: &mut H,
    words: usize,
) -> Result<(&'a mut [MaybeUninit<u64>], *mut u64), TermError> {
    let ptr = heap.alloc(words).ok_or(TermError::HeapFull)?;
    // SAFETY: the allocator returned `words` writable words that nothing else
    // references; MaybeUninit admits their uninitialized contents.
    let slice = unsafe { std::slice::from_raw_parts_mut(ptr.cast::<MaybeUninit<u64>>(), words) };
    Ok((slice, ptr))
}

/// Allocate a boxed object holding exactly `words`.
fn produce_boxed<H: HeapAlloc + ?Sized>(heap: &mut H, words: &[u64]) -> Result<Term, TermError> {
    let (slice, ptr) = produce(heap, words.len())?;
    for (slot, word) in slice.iter_mut().zip(words) {
        slot.write(*word);
    }
    Ok(term(ptr as u64 | 2))
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
    let words = boxed_words(map, 3 + n);
    let keys = term(words[2]);
    (&boxed_words(keys, 1 + n)[1..], &words[3..], keys)
}

// Port of erts/emulator/beam/erl_map.c:1863 (hashmap_subtree_size), OTP-29.1.1.
fn hashmap_subtree_size(node: Term) -> usize {
    match node_view(node) {
        NodeView::Collision(leaves) => leaves.len(),
        NodeView::Bitmap(children) => children
            .iter()
            .map(|&child| {
                let child = term(child);
                if is_leaf(child) {
                    1
                } else {
                    hashmap_subtree_size(child)
                }
            })
            .sum(),
    }
}

/// Scratch heap that measures a construction. erts grows its heap factory
/// with fragments and never fails; Arinsal's fallible-heap callers instead
/// collect once and retry, so a failed construction reports its exact size.
#[derive(Default)]
struct CountingHeap {
    words: usize,
    chunks: Vec<Box<[u64]>>,
}
impl HeapAlloc for CountingHeap {
    fn alloc(&mut self, words: usize) -> Option<*mut u64> {
        self.words += words;
        let mut chunk = vec![0; words].into_boxed_slice();
        let ptr = chunk.as_mut_ptr();
        self.chunks.push(chunk);
        Some(ptr)
    }
    fn retain_binary(&mut self, _binary: std::sync::Arc<arinsal_term::RefcBinary>) {}
    fn retain_node(&mut self, _node: std::sync::Arc<arinsal_term::Node>) {}
    fn retain_fun(&mut self, _entry: std::sync::Arc<arinsal_term::FunEntry>) {}
    fn retain_export(&mut self, _entry: std::sync::Arc<arinsal_term::ExportEntry>) {}
}

/// Run a construction. On heap exhaustion, measure the complete run and try
/// once more inside a single block of exactly that size; if the heap cannot
/// provide it either, report the size so the caller can collect and retry.
pub(crate) fn sized<T, H: HeapAlloc + ?Sized>(
    heap: &mut H,
    f: impl Fn(&mut dyn HeapAlloc) -> Result<T, TermError>,
) -> MapResult<T> {
    match f(&mut HeapRef(heap)) {
        Ok(value) => Ok(value),
        Err(TermError::HeapFull) => {
            let mut counting = CountingHeap::default();
            f(&mut counting).map_err(|error| unreachable!("measuring run failed: {error:?}"))?;
            let need_words = counting.words;
            drop(counting);
            let Some(block) = heap.alloc(need_words) else {
                return Err(MapError::HeapFull { need_words });
            };
            let mut bump = BlockHeap {
                inner: HeapRef(heap),
                next: block,
                left: need_words,
            };
            Ok(f(&mut bump).map_err(|error| unreachable!("exact block exhausted: {error:?}"))?)
        }
        Err(other) => unreachable!("map construction only fails on heap exhaustion: {other:?}"),
    }
}

/// Bump allocator over one heap block measured by [`CountingHeap`].
struct BlockHeap<'a, H: HeapAlloc + ?Sized> {
    inner: HeapRef<'a, H>,
    next: *mut u64,
    left: usize,
}
impl<H: HeapAlloc + ?Sized> HeapAlloc for BlockHeap<'_, H> {
    fn alloc(&mut self, words: usize) -> Option<*mut u64> {
        if words > self.left {
            return None;
        }
        let ptr = self.next;
        self.next = ptr.wrapping_add(words);
        self.left -= words;
        Some(ptr)
    }
    fn retain_binary(&mut self, binary: std::sync::Arc<arinsal_term::RefcBinary>) {
        self.inner.retain_binary(binary);
    }
    fn retain_node(&mut self, node: std::sync::Arc<arinsal_term::Node>) {
        self.inner.retain_node(node);
    }
    fn retain_fun(&mut self, entry: std::sync::Arc<arinsal_term::FunEntry>) {
        self.inner.retain_fun(entry);
    }
    fn retain_export(&mut self, entry: std::sync::Arc<arinsal_term::ExportEntry>) {
        self.inner.retain_export(entry);
    }
}

/// `&mut H` as a `dyn HeapAlloc` for unsized `H`.
struct HeapRef<'a, H: HeapAlloc + ?Sized>(&'a mut H);
impl<H: HeapAlloc + ?Sized> HeapAlloc for HeapRef<'_, H> {
    fn alloc(&mut self, words: usize) -> Option<*mut u64> {
        self.0.alloc(words)
    }
    fn retain_binary(&mut self, binary: std::sync::Arc<arinsal_term::RefcBinary>) {
        self.0.retain_binary(binary);
    }
    fn retain_node(&mut self, node: std::sync::Arc<arinsal_term::Node>) {
        self.0.retain_node(node);
    }
    fn retain_fun(&mut self, entry: std::sync::Arc<arinsal_term::FunEntry>) {
        self.0.retain_fun(entry);
    }
    fn retain_export(&mut self, entry: std::sync::Arc<arinsal_term::ExportEntry>) {
        self.0.retain_export(entry);
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
    slice[1 + n].write(MAP);
    slice[2 + n].write(n as u64);
    slice[3 + n].write(ptr as u64 | 2);
    for (slot, value) in slice[4 + n..].iter_mut().zip(vs) {
        slot.write(bits(*value));
    }
    Ok(term(ptr.wrapping_add(1 + n) as u64 | 2))
}

/// Build a flatmap that shares `keys` (a key tuple of `vs.len()` keys).
fn flatmap_with_keys<H: HeapAlloc + ?Sized>(
    keys: Term,
    vs: &[Term],
    heap: &mut H,
) -> Result<Term, TermError> {
    let n = vs.len();
    let (slice, ptr) = produce(heap, 3 + n)?;
    slice[0].write(MAP);
    slice[1].write(n as u64);
    slice[2].write(bits(keys));
    for (slot, value) in slice[3..].iter_mut().zip(vs) {
        slot.write(bits(*value));
    }
    Ok(term(ptr as u64 | 2))
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
// erts writes into an oversized heap block and releases the tail; Arinsal has
// no HRelease, so the merged arrays are staged (at most 2 * MAP_SMALL_MAP_LIMIT
// entries) and the exact block is allocated afterwards.
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
    let mut ks: SmallVec<[Term; 64]> = SmallVec::with_capacity(n1 + n2);
    let mut vs: SmallVec<[Term; 64]> = SmallVec::with_capacity(n1 + n2);
    let (mut i1, mut i2, mut unused_size) = (0, 0, 0);
    while i1 < n1 && i2 < n2 {
        let c = if ks1[i1] == ks2[i2] {
            Ordering::Equal
        } else {
            key_cmp(term(ks1[i1]), term(ks2[i2]))
        };
        match c {
            Ordering::Equal => {
                ks.push(term(ks2[i2]));
                vs.push(term(vs2[i2]));
                i1 += 1;
                i2 += 1;
                unused_size += 1;
            }
            Ordering::Less => {
                ks.push(term(ks1[i1]));
                vs.push(term(vs1[i1]));
                i1 += 1;
            }
            Ordering::Greater => {
                ks.push(term(ks2[i2]));
                vs.push(term(vs2[i2]));
                i2 += 1;
            }
        }
    }
    ks.extend(ks1[i1..].iter().map(|&k| term(k)));
    vs.extend(vs1[i1..].iter().map(|&v| term(v)));
    ks.extend(ks2[i2..].iter().map(|&k| term(k)));
    vs.extend(vs2[i2..].iter().map(|&v| term(v)));
    let n = ks.len();
    if unused_size > 0 {
        if n == n2 {
            // Reuse all of map2; adopt map1's literal key tuple when map2's is not.
            if n == n1 && keys1.is_literal() && !keys2.is_literal() {
                map2.flatmap_replace_keys(keys1);
            }
            return Ok(map2);
        } else if n == n1 {
            return flatmap_with_keys(keys1, &vs, heap);
        }
    }
    if n > LIMIT {
        return hashmap_from_pairs(ks.iter().copied().zip(vs.iter().copied()), heap);
    }
    flatmap_from_sorted(&ks, &vs, heap)
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
    array: [Term; 16],
}

#[derive(Clone, Copy)]
enum Src {
    /// The root map term.
    Root(Term),
    /// Word `index` of the boxed node.
    Slot(Term, usize),
}
impl Src {
    fn get(self) -> Term {
        match self {
            Self::Root(t) => t,
            Self::Slot(node, index) => term(boxed_words(node, index + 1)[index]),
        }
    }
    fn advance(&mut self) {
        if let Self::Slot(_, index) = self {
            *index += 1;
        }
    }
    /// `len` consecutive terms from this position.
    fn run(self, len: usize) -> SmallVec<[u64; 16]> {
        match self {
            Self::Root(t) => SmallVec::from_slice(&[bits(t)]),
            Self::Slot(node, index) => {
                SmallVec::from_slice(&boxed_words(node, index + len)[index..index + len])
            }
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
    stack: Vec<Frame>,
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
        let mut stack = Vec::with_capacity(HAMT_MAX_LEVEL + 1);
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
            array: [Term::NIL; 16],
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
    let a = src_a.run(sz_a);
    let b = src_b.run(sz_b);
    let mut words: SmallVec<[u64; 18]> = SmallVec::with_capacity(1 + sz_a + sz_b);
    words.push(0);
    let (mut ia, mut ib) = (0, 0);
    while ia < a.len() && ib < b.len() {
        let key_a = leaf(term(a[ia])).0;
        let key_b = leaf(term(b[ib])).0;
        match exact_cmp(key_a, key_b, false) {
            Ordering::Less => {
                words.push(a[ia]);
                ia += 1;
            }
            order => {
                words.push(b[ib]);
                ib += 1;
                if order == Ordering::Equal {
                    ia += 1;
                    *map_size -= 1;
                }
            }
        }
    }
    words.extend_from_slice(&a[ia..]);
    words.extend_from_slice(&b[ib..]);
    let arity = words.len() - 1;
    debug_assert!(arity >= 2);
    words[0] = (arity as u64) << 6;
    produce_boxed(heap, &words)
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
                *src = Src::Slot(node, 2);
                *bm = 0xffff;
            }
            HEAD_BITMAP => {
                *src = Src::Slot(node, 2);
                *bm = ((header >> 16) & 0xffff) as u32;
            }
            _ => {
                *src = Src::Slot(node, 1);
                *bm = ((header >> 16) & 0xffff) as u32;
            }
        }
    } else {
        debug_assert_eq!(lvl, HAMT_MAX_LEVEL);
        *src = Src::Slot(node, 1);
        *coll_sz = (header >> 6) as usize;
        debug_assert!(*coll_sz >= 2);
    }
}

/// Reductions-to-work factor of the HAMT merge.
///
/// Port of erts/emulator/beam/erl_map.c:1508 (MAP_MERGE_LOOP_FACTOR), OTP-29.1.1.
pub const MAP_MERGE_LOOP_FACTOR: isize = 8;

#[derive(Clone, Copy)]
enum Step {
    Recurse,
    MergeNodes,
    Resume,
}

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
    let mut step = if ctx.started {
        Step::Resume
    } else {
        Step::Recurse
    };
    ctx.started = true;
    loop {
        match step {
            Step::Recurse => {
                let lvl = ctx.lvl;
                let sp = ctx.stack.last_mut().expect("merge stack");
                sp.node_a = sp.src_a.get();
                sp.node_b = sp.src_b.get();
                step = Step::MergeNodes;
                if sp.node_a == sp.node_b {
                    res = Some(sp.node_a);
                    ctx.size -= if is_leaf(sp.node_b) {
                        1
                    } else {
                        hashmap_subtree_size(sp.node_b)
                    };
                    continue;
                }
                if is_leaf(sp.node_a) && is_leaf(sp.node_b) {
                    let key_a = leaf(sp.node_a).0;
                    let key_b = leaf(sp.node_b).0;
                    if exact_eq(key_a, key_b) {
                        ctx.size -= 1;
                        res = Some(sp.node_b);
                        // Values are assumed to differ; comparing them could be costly.
                        sp.mix = 2;
                        continue;
                    }
                }
                let (node_a, node_b) = (sp.node_a, sp.node_b);
                open_node(node_a, &mut sp.src_a, lvl, &mut sp.abm, &mut coll_sz_a);
                open_node(node_b, &mut sp.src_b, lvl, &mut sp.bbm, &mut coll_sz_b);
            }
            Step::MergeNodes => {
                if let Some(child) = res {
                    if ctx.lvl == 0 {
                        debug_assert_eq!(hashmap_size(child), ctx.size);
                        return Ok(Some(child));
                    }
                    // Pop and continue building the parent node.
                    ctx.lvl -= 1;
                    let child_mix = ctx.stack.pop().expect("merge stack").mix;
                    let sp = ctx.stack.last_mut().expect("merge stack");
                    sp.array[sp.ix] = child;
                    sp.ix += 1;
                    sp.mix |= child_mix;
                    res = None;
                    if sp.rbm != 0 {
                        sp.src_a.advance();
                        sp.src_b.advance();
                    }
                } else if ctx.lvl < HAMT_MAX_LEVEL {
                    // Start building a node.
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
                step = Step::Resume;
            }
            Step::Resume => {
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
                        sp.array[sp.ix] = sp.src_a.get();
                        sp.ix += 1;
                        sp.src_a.advance();
                        sp.mix |= 1;
                    } else {
                        debug_assert!(sp.bbm & bit != 0);
                        sp.array[sp.ix] = sp.src_b.get();
                        sp.ix += 1;
                        sp.src_b.advance();
                        sp.mix |= 2;
                    }
                }
                if clash {
                    // Bit clash: push and resolve by recursive merge.
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
                        array: [Term::NIL; 16],
                    });
                    step = Step::Recurse;
                    continue;
                }
                res = Some(match sp.mix {
                    // Exactly the same subtrees, or only unique A content: reuse node A.
                    0 | 1 => sp.node_a,
                    // Only unique B content: reuse node B.
                    2 => sp.node_b,
                    // A mix: build a new node.
                    3 => {
                        debug_assert_eq!(sp.ix, (sp.abm | sp.bbm).count_ones() as usize);
                        let bitmap = u64::from(sp.abm | sp.bbm);
                        let mut words: SmallVec<[u64; 18]> = SmallVec::new();
                        if lvl == 0 {
                            words.push(if sp.ix == 16 {
                                super::header(HEAD_ARRAY, 0xffff)
                            } else {
                                super::header(HEAD_BITMAP, bitmap as u16)
                            });
                            words.push(ctx.size as u64);
                        } else {
                            words.push(super::header(NODE_BITMAP, bitmap as u16));
                        }
                        words.extend(sp.array[..sp.ix].iter().map(|t| bits(*t)));
                        produce_boxed(heap, &words)?
                    }
                    mix => unreachable!("strange mix {mix}"),
                });
                step = Step::MergeNodes;
            }
        }
    }
}

/// Outcome of the non-yielding part of `maps:merge/2`.
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
    sized(heap, |heap| merge_start_checked(left, right, heap))
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
    sized(heap, |heap| match merge_start_checked(left, right, heap)? {
        MergeStart::Done(map) => Ok(map),
        MergeStart::Hashmap(mut ctx) => {
            let mut reds = isize::MAX;
            Ok(hashmap_merge_loop(&mut ctx, &mut reds, heap)?.expect("unbounded merge completes"))
        }
    })
}

// Port of erts/emulator/beam/erl_map.c:368-468 (flatmap_from_validated_list), OTP-29.1.1.
fn flatmap_from_validated_list<H: HeapAlloc + ?Sized>(
    pairs: impl Iterator<Item = (Term, Term)>,
    heap: &mut H,
) -> Result<Term, TermError> {
    let mut ks: SmallVec<[Term; LIMIT]> = SmallVec::new();
    let mut vs: SmallVec<[Term; LIMIT]> = SmallVec::new();
    for (key, value) in pairs {
        // Insertion sort, comparing backwards from the end.
        let mut idx = ks.len();
        let mut c = Ordering::Less;
        while idx > 0 {
            c = key_cmp(key, ks[idx - 1]);
            if c != Ordering::Less {
                break;
            }
            idx -= 1;
        }
        if idx > 0 && c == Ordering::Equal {
            ks[idx - 1] = key;
            vs[idx - 1] = value;
        } else {
            ks.insert(idx, key);
            vs.insert(idx, value);
        }
    }
    flatmap_from_sorted(&ks, &vs, heap)
}

// Port of erts/emulator/beam/erl_map.c:482-591 (hashmap_from_validated_list), OTP-29.1.1.
fn hashmap_from_validated_list<H: HeapAlloc + ?Sized>(
    pairs: impl ExactSizeIterator<Item = (Term, Term)>,
    heap: &mut H,
) -> Result<Term, TermError> {
    let res = hashmap_from_pairs(pairs, heap)?;
    if hashmap_size(res) > LIMIT {
        return Ok(res);
    }
    // Duplicates shrank it to a flatmap (erts_validate_and_sort_flatmap).
    let mut entries = Vec::with_capacity(hashmap_size(res));
    super::collect(res, &mut entries);
    entries.sort_by(|a, b| key_cmp(a.0, b.0));
    let ks: SmallVec<[Term; LIMIT]> = entries.iter().map(|p| p.0).collect();
    let vs: SmallVec<[Term; LIMIT]> = entries.iter().map(|p| p.1).collect();
    flatmap_from_sorted(&ks, &vs, heap)
}

/// `maps:from_list/1` over validated pairs; later duplicates win.
///
/// Port of erts/emulator/beam/erl_map.c:317-366 (maps_from_list_1_helper), OTP-29.1.1.
pub fn from_list<H: HeapAlloc + ?Sized>(pairs: &[(Term, Term)], heap: &mut H) -> MapResult<Term> {
    sized(heap, |heap| {
        if pairs.len() > LIMIT {
            hashmap_from_validated_list(pairs.iter().copied(), heap)
        } else {
            flatmap_from_validated_list(pairs.iter().copied(), heap)
        }
    })
}

/// `maps:from_keys/2`.
///
/// Port of erts/emulator/beam/erl_map.c:278-309 (maps_from_keys_2_helper), OTP-29.1.1.
pub fn from_keys<H: HeapAlloc + ?Sized>(
    keys: &[Term],
    value: Term,
    heap: &mut H,
) -> MapResult<Term> {
    sized(heap, |heap| {
        let pairs = keys.iter().map(|&key| (key, value));
        if keys.len() > LIMIT {
            hashmap_from_validated_list(pairs, heap)
        } else {
            flatmap_from_validated_list(pairs, heap)
        }
    })
}
