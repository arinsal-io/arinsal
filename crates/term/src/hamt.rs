//! Read-only HAMT traversal and the shared term-level bulk constructor.
use crate::{HeapAlloc, MAP, Term, TermError, TermKind, internal_hash};
use smallvec::SmallVec;
use std::mem::MaybeUninit;

/// Number of words in a boxed object whose header is at `ptr`.
///
/// The caller must pass a live, initialized boxed object. Tuple and collision
/// tuple payloads (words 1..) are terms. Record words 1.. are terms. Bignum
/// digits, float payloads, heap-bit length/data, ref payloads, bin-ref
/// ownership, and external identity payloads are raw. A fun has a raw entry
/// pointer in word 1 and term captures from word 2. Sub-bits has its original
/// term in word 4; words 1..3 are raw base/flags and bit offsets. A flatmap
/// has a raw size in word 1, its key-tuple term in word 2, and term values
/// from word 3. HAMT heads have a raw size in word 1 and child terms from word
/// 2; bitmap nodes have child terms from word 1. Leaf cons cells have two term
/// words and no header. Fun entry, external node, and binary owner pointers
/// must be retained separately when the GC copies these raw words.
///
/// # Safety
/// `ptr` must address a live boxed object with its complete payload initialized.
pub unsafe fn boxed_object_words(header: u64, ptr: *const u64) -> usize {
    // Port of erts/emulator/beam/erl_map.c:198-237, OTP-29.1.1.
    match header & 63 {
        MAP => match (header >> 6) & 3 {
            0 => {
                // SAFETY: a live flatmap has its size in word 1.
                3 + unsafe { *ptr.add(1) } as usize
            }
            1 => 1 + ((header >> 16) as u16).count_ones() as usize,
            2 => 18,
            3 => 2 + ((header >> 16) as u16).count_ones() as usize,
            _ => unreachable!(),
        },
        crate::FUN => 2 + ((header >> 16) & 255) as usize,
        crate::ARITY
        | crate::POS_BIG
        | crate::NEG_BIG
        | crate::REF
        | crate::FLOAT
        | crate::RECORD
        | crate::HEAP_BITS
        | crate::SUB_BITS
        | crate::BIN_REF
        | crate::EXTERNAL_PID
        | crate::EXTERNAL_PORT
        | crate::EXTERNAL_REF => 1 + (header >> 6) as usize,
        other => panic!("invalid boxed subtag {other:#x}"),
    }
}

/// Range of tagged term words in a boxed object. All other words are raw.
/// The flatmap key tuple is word 2; HAMT heads and bitmap nodes contain
/// children, while collision tuples use the ordinary tuple layout.
///
/// # Safety
/// `ptr` must address a live, completely initialized boxed object.
pub(crate) unsafe fn boxed_term_range(header: u64, ptr: *const u64) -> std::ops::Range<usize> {
    // SAFETY: The caller provides a live, initialized boxed object.
    let words = unsafe { boxed_object_words(header, ptr) };
    match header & 63 {
        crate::ARITY | crate::RECORD => 1..words,
        MAP => child_range(header, words),
        crate::FUN => 2..words,
        crate::SUB_BITS => 4..5,
        crate::POS_BIG
        | crate::NEG_BIG
        | crate::REF
        | crate::FLOAT
        | crate::HEAP_BITS
        | crate::BIN_REF
        | crate::EXTERNAL_PID
        | crate::EXTERNAL_PORT
        | crate::EXTERNAL_REF => 0..0,
        other => panic!("invalid boxed subtag {other:#x}"),
    }
}

/// Size stored in the head of a map.
pub(crate) fn len(map: Term) -> usize {
    // SAFETY: map heads have a raw size in word 1.
    unsafe { *map.raw_ptr().add(1) as usize }
}

/// Term-bearing child slots in a map node (excluding the flatmap key tuple).
pub(crate) fn child_range(header: u64, words: usize) -> std::ops::Range<usize> {
    // Port of erts/emulator/beam/erl_map.c:238-267, OTP-29.1.1.
    match (header >> 6) & 3 {
        0 | 2 | 3 => 2..words,
        1 => 1..words,
        _ => unreachable!(),
    }
}

/// Iterate map entries without materializing a pair array.
pub(crate) struct PairIter {
    map: Term,
    flat_index: usize,
    nodes: SmallVec<[(Term, usize); 20]>,
    mode: PairIterMode,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum PairIterMode {
    Pairs,
    RootChildren,
}
impl PairIter {
    // Port of erts/emulator/beam/erl_map.c:2320-2410, OTP-29.1.1.
    pub(crate) fn new(map: Term) -> Self {
        let mut result = Self {
            map,
            flat_index: 0,
            nodes: SmallVec::new(),
            mode: PairIterMode::Pairs,
        };
        if map.is_hashmap() {
            result.push_node(map);
        }
        result
    }
    fn root_children(map: Term) -> Self {
        let mut result = Self {
            map,
            flat_index: 0,
            nodes: SmallVec::new(),
            mode: PairIterMode::RootChildren,
        };
        result.push_node(map);
        result
    }
    fn push_node(&mut self, node: Term) {
        let header = node.header().unwrap();
        let first = if header & 63 == MAP {
            child_range(header, 0).start
        } else {
            1
        };
        self.nodes.push((node, first));
    }
}

// Port of the direct flatmap key/value arrays used by erts_cmp_compound
// (erts/emulator/beam/utils.c:2030-2104), OTP-29.1.1.
pub(crate) fn with_flatmap_arrays<R>(
    map: Term,
    body: impl for<'a> FnOnce(&'a [u64], &'a [u64]) -> R,
) -> Option<R> {
    // SAFETY: callers retain the source map and its owning heap for the callback.
    let view = unsafe { map.flatmap_ref()? };
    Some(view.with_arrays(body))
}

impl Iterator for PairIter {
    type Item = (Term, Term);
    // Port of erts/emulator/beam/erl_map.c:2337-2376 (hashmap_iterator_next), OTP-29.1.1.
    fn next(&mut self) -> Option<Self::Item> {
        if !self.map.is_hashmap() && self.mode == PairIterMode::Pairs {
            let index = self.flat_index;
            let pair = with_flatmap_arrays(self.map, |keys, values| {
                (index < keys.len()).then(|| (Term(keys[index]), Term(values[index])))
            })?;
            let pair = pair?;
            self.flat_index += 1;
            return Some(pair);
        }
        loop {
            let (node, next) = *self.nodes.last()?;
            let header = node.header().unwrap();
            // SAFETY: node is a live HAMT branch or collision tuple.
            let ptr = unsafe { node.raw_ptr() };
            // SAFETY: the node header describes all initialized child slots.
            let end = unsafe { boxed_object_words(header, ptr) };
            if next == end {
                self.nodes.pop();
                continue;
            }
            self.nodes.last_mut().unwrap().1 += 1;
            // SAFETY: next is an initialized child slot below end.
            let child = Term(unsafe { *ptr.add(next) });
            if self.mode == PairIterMode::RootChildren && node == self.map {
                return Some((child, Term::NIL));
            }
            if child.classify() == TermKind::List {
                // SAFETY: HAMT leaves are two-word cons cells.
                return unsafe { child.cons_ref() };
            }
            self.push_node(child);
        }
    }
}

/// Collect pairs in `maps:to_list/1` order.
pub(crate) fn pairs(map: Term) -> Vec<(Term, Term)> {
    if !map.is_hashmap() {
        // SAFETY: the caller keeps the source heap live during traversal.
        return unsafe { map.flatmap_ref().unwrap() }.iter().collect();
    }
    let mut result = Vec::with_capacity(len(map));
    result.extend(PairIter::new(map));
    result
}

/// Return the direct child terms of an OTP-layout hashmap node in storage order.
///
/// Flatmaps have no HAMT children and return `None`.
pub fn hashmap_node_children(node: Term) -> Option<Vec<Term>> {
    let is_map_node = node.is_hashmap();
    let is_collision = node
        .header()
        .is_some_and(|header| header & 63 == crate::ARITY);
    if !is_map_node && !is_collision {
        return None;
    }
    Some(
        PairIter::root_children(node)
            .map(|(child, _)| child)
            .collect(),
    )
}

/// Return the stored flatmap keys in their tuple order.
pub fn flatmap_keys(map: Term) -> Option<Vec<Term>> {
    if map.is_hashmap() || map.classify() != TermKind::Map {
        return None;
    }
    Some(PairIter::new(map).map(|(key, _)| key).collect())
}

// Port of erts/emulator/beam/erl_map.h:178-220 (HAMT headers, HAMT_MAX_LEVEL), OTP-29.1.1.
pub(crate) const HAMT_MAX_LEVEL: usize = 16;
pub(crate) const fn node_bitmap_header(bitmap: u64) -> u64 {
    MAP | (1 << 6) | (bitmap << 16)
}
pub(crate) const fn head_bitmap_header(bitmap: u64) -> u64 {
    MAP | (3 << 6) | (1 << 8) | (bitmap << 16)
}
pub(crate) const HEAD_ARRAY_HEADER: u64 = MAP | (2 << 6) | (1 << 8) | (0xffff << 16);

/// Temporary hash/leaf record of the bulk HAMT constructors.
///
/// Port of erts/emulator/beam/erl_map.c:80 (hxnode_t), OTP-29.1.1.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct HxNode {
    /// Swizzled hash (path slots from the most significant nibble).
    pub hx: u64,
    /// Number of array entries this node stands for (collision runs).
    pub skip: usize,
    /// Input position; the highest position wins among duplicate keys.
    pub i: usize,
    /// Leaf cons `[Key | Value]`, or a collision node after chunking.
    pub val: Term,
}
impl HxNode {
    /// Record for the leaf `val` (a `[Key | Value]` cons) at input position `i`.
    pub fn new(key: Term, val: Term, i: usize) -> Self {
        Self {
            hx: swizzle_map_hash(internal_hash(key)),
            skip: 1,
            i,
            val,
        }
    }
}

/// Reverse the 4-bit path slots of `hash` so that sorting orders by HAMT path.
///
/// Port of erts/emulator/beam/erl_map.c:4170 (swizzle_map_hash), OTP-29.1.1.
#[inline(always)]
pub fn swizzle_map_hash(hash: u64) -> u64 {
    const MASK: u64 = 0xF0F0_F0F0_F0F0_F0F0;
    let result = hash.swap_bytes();
    ((result & MASK) >> 4) | ((result & (MASK >> 4)) << 4)
}

// Port of erts/emulator/beam/erl_map.c:108-109 (cdepth, maskval), OTP-29.1.1.
pub(crate) fn cdepth(v1: u64, v2: u64) -> usize {
    ((v1 ^ v2).leading_zeros() >> 2) as usize
}
pub(crate) fn maskval(v: u64, level: usize) -> u64 {
    (v >> (((HAMT_MAX_LEVEL - 1) - level) * 4)) & 0xF
}

/// Fresh heap words (`erts_produce_heap` / `HAlloc`).
///
/// `T` is `MaybeUninit<u64>` or [`Term`] (`repr(transparent)` over one word).
fn alloc_words<'a, T, H: HeapAlloc + ?Sized>(
    heap: &mut H,
    words: usize,
) -> Result<(&'a mut [T], *mut u64), TermError> {
    let ptr = heap.alloc(words).ok_or(TermError::HeapFull)?;
    const {
        assert!(std::mem::size_of::<T>() == 8);
        assert!(std::mem::align_of::<T>() == 8);
    }
    // SAFETY: `HeapAlloc::alloc` returned `words` exclusive, aligned machine words
    // (HAlloc, erl_map.c:376). This is the one slice view of that block. A `Term`
    // slot is an Eterm: the caller stores it before loading it (erl_map.c:399-455).
    let slice = unsafe { std::slice::from_raw_parts_mut(ptr.cast::<T>(), words) };
    Ok((slice, ptr))
}

/// Fresh, uninitialized heap words (`erts_produce_heap`).
fn produce<'a, H: HeapAlloc + ?Sized>(
    heap: &mut H,
    words: usize,
) -> Result<(&'a mut [MaybeUninit<u64>], *mut u64), TermError> {
    alloc_words(heap, words)
}

/// `HAlloc` `words` machine words and view them as `Eterm` slots.
///
/// Port of `Eterm *hp = HAlloc(p, words)` in erts/emulator/beam/erl_map.c:376,
/// OTP-29.1.1. The slice is that block. Each slot is stored before it is loaded,
/// as `flatmap_from_validated_list` does at erl_map.c:399-455.
pub fn alloc_terms<'a, H: HeapAlloc + ?Sized>(
    heap: &mut H,
    words: usize,
) -> Result<(&'a mut [Term], *mut u64), TermError> {
    alloc_words(heap, words)
}

/// Allocate one node holding exactly `words`.
pub(crate) fn produce_words<H: HeapAlloc + ?Sized>(
    heap: &mut H,
    words: &[u64],
) -> Result<Term, TermError> {
    let (slice, ptr) = produce(heap, words.len())?;
    for (slot, word) in slice.iter_mut().zip(words) {
        slot.write(*word);
    }
    Ok(Term::from_ptr(ptr, 2))
}

/// Swizzled hash of a map key, as stored in [`HxNode::hx`].
///
/// Port of erts/emulator/beam/erl_map.c:731-732 (hashmap_make_hash, swizzle_map_hash),
/// OTP-29.1.1.
#[inline(always)]
pub fn hashmap_key_hash(key: Term) -> u64 {
    swizzle_map_hash(internal_hash(key))
}

/// Allocate the `[Key | Value]` leaf conses of `ks`/`vs` in one block and
/// return their hash records, as the callers of `hashmap_from_unsorted_array` do.
///
/// Port of erts/emulator/beam/erl_map.c:720-747 (leaf setup of
/// erts_hashmap_from_ks_and_vs_extra), OTP-29.1.1.
pub fn hashmap_leaves<H: HeapAlloc + ?Sized>(
    pairs: impl ExactSizeIterator<Item = (Term, Term)>,
    heap: &mut H,
) -> Result<Vec<HxNode>, TermError> {
    let entries: Vec<_> = pairs
        .map(|(key, value)| (hashmap_key_hash(key), key, value))
        .collect();
    hashmap_leaves_hashed(&entries, heap)
}

/// [`hashmap_leaves`] for entries whose swizzled hash is already known (the yielding
/// constructors hash while they walk the input list).
///
/// Port of erts/emulator/beam/erl_map.c:506-531 (leaf setup of hashmap_from_validated_list),
/// OTP-29.1.1.
pub fn hashmap_leaves_hashed<H: HeapAlloc + ?Sized>(
    entries: &[(u64, Term, Term)],
    heap: &mut H,
) -> Result<Vec<HxNode>, TermError> {
    let n = entries.len();
    let (slice, ptr) = produce(heap, 2 * n)?;
    let mut hxns = Vec::with_capacity(n);
    for (i, &(hx, key, value)) in entries.iter().enumerate() {
        slice[2 * i].write(key.bits());
        slice[2 * i + 1].write(value.bits());
        hxns.push(HxNode {
            hx,
            skip: 1,
            i,
            val: Term::from_ptr(ptr.wrapping_add(2 * i), 1),
        });
    }
    Ok(hxns)
}

pub(crate) fn leaf_key(leaf: Term) -> Term {
    // SAFETY: hash records hold live leaf conses until chunking replaces them.
    unsafe { leaf.cons_ref() }.expect("HAMT leaf").0
}

/// Build a HAMT from unsorted leaf records. Returns `None` when
/// `reject_dupkeys` is set and two leaves have equal keys; otherwise the leaf
/// with the highest input position wins.
///
/// Port of erts/emulator/beam/erl_map.c:774-855 (hashmap_from_unsorted_array), OTP-29.1.1.
pub fn hashmap_from_unsorted_array<H: HeapAlloc + ?Sized>(
    hxns: &mut [HxNode],
    reject_dupkeys: bool,
    heap: &mut H,
) -> Result<Option<Term>, TermError> {
    let n = hxns.len();
    assert!(n > 0);
    crate::hamt_yield::qsort_nodes(hxns, false);
    let mut ix = 0;
    let mut cx = 0;
    while ix < n - 1 {
        if hxns[ix].hx == hxns[ix + 1].hx {
            let mut jx = ix + 2;
            while jx < n && hxns[ix].hx == hxns[jx].hx {
                jx += 1;
            }
            crate::hamt_yield::qsort_nodes(&mut hxns[ix..jx], true);
            while ix < jx {
                let mut lx = ix;
                loop {
                    ix += 1;
                    if !(ix < jx && crate::exact_eq(leaf_key(hxns[ix].val), leaf_key(hxns[lx].val)))
                    {
                        break;
                    }
                    if reject_dupkeys {
                        return Ok(None);
                    }
                    if hxns[ix].i > hxns[lx].i {
                        lx = ix;
                    }
                }
                hxns[cx].hx = hxns[lx].hx;
                hxns[cx].val = hxns[lx].val;
                cx += 1;
            }
            ix = jx;
            continue;
        }
        if ix > cx {
            hxns[cx].hx = hxns[ix].hx;
            hxns[cx].val = hxns[ix].val;
        }
        cx += 1;
        ix += 1;
    }
    if ix < n {
        hxns[cx].hx = hxns[ix].hx;
        hxns[cx].val = hxns[ix].val;
        cx += 1;
    }
    if cx > 1 {
        return hashmap_from_sorted_unique_array(&mut hxns[..cx], heap).map(Some);
    }
    // One item: the swizzled hash keeps the root slot in its top nibble.
    let slot = hxns[0].hx >> ((HAMT_MAX_LEVEL - 1) * 4);
    produce_words(
        heap,
        &[head_bitmap_header(1 << slot), 1, hxns[0].val.bits()],
    )
    .map(Some)
}

// Port of erts/emulator/beam/erl_map.c:857-911 (hashmap_from_sorted_unique_array), OTP-29.1.1.
fn hashmap_from_sorted_unique_array<H: HeapAlloc + ?Sized>(
    hxns: &mut [HxNode],
    heap: &mut H,
) -> Result<Term, TermError> {
    let n = hxns.len();
    let mut ix = 0;
    let mut elems = 1;
    while ix < n - 1 {
        if hxns[ix].hx == hxns[ix + 1].hx {
            let mut jx = ix + 2;
            while jx < n && hxns[ix].hx == hxns[jx].hx {
                jx += 1;
            }
            let n_colliders = jx - ix;
            let mut words: SmallVec<[u64; 8]> = SmallVec::with_capacity(1 + n_colliders);
            words.push((n_colliders as u64) << 6);
            words.extend(hxns[ix..jx].iter().map(|node| node.val.bits()));
            hxns[ix].val = produce_words(heap, &words)?;
            hxns[ix].skip = n_colliders;
            ix = jx;
            if ix < n {
                elems += 1;
            }
            continue;
        }
        hxns[ix].skip = 1;
        elems += 1;
        ix += 1;
    }
    hashmap_from_chunked_array(hxns, elems, n, heap)
}

/// Wrap `res` in single-child bitmap nodes from level `HAMT_MAX_LEVEL - 1` down to `stop + 1`.
fn collision_chain<H: HeapAlloc + ?Sized>(
    mut res: Term,
    v: u64,
    stop: usize,
    heap: &mut H,
) -> Result<Term, TermError> {
    let mut dc = HAMT_MAX_LEVEL - 1;
    while dc > stop {
        res = produce_words(heap, &[node_bitmap_header(1 << maskval(v, dc)), res.bits()])?;
        dc -= 1;
    }
    Ok(res)
}

/// Pop `sz - 1` siblings from `stack` behind `res` into a node with `header`.
fn stack_node<H: HeapAlloc + ?Sized>(
    header: &[u64],
    res: Term,
    sz: usize,
    stack: &mut SmallVec<[u64; 16]>,
    heap: &mut H,
) -> Result<Term, TermError> {
    let mut words: SmallVec<[u64; 18]> = SmallVec::new();
    words.extend_from_slice(header);
    words.push(res.bits());
    for _ in 1..sz {
        words.push(stack.pop().expect("HAMT build stack"));
    }
    produce_words(heap, &words)
}

// Port of erts/emulator/beam/erl_map.c:919-1158 (hashmap_from_chunked_array), OTP-29.1.1.
fn hashmap_from_chunked_array<H: HeapAlloc + ?Sized>(
    hxns: &[HxNode],
    n: usize,
    size: usize,
    heap: &mut H,
) -> Result<Term, TermError> {
    let mut stack: SmallVec<[u64; 16]> = SmallVec::new();
    if n == 1 {
        // Every key shares all HAMT_MAX_LEVEL hash slots.
        let v = hxns[0].hx;
        let res = collision_chain(hxns[0].val, v, 0, heap)?;
        let slot = maskval(v, 0);
        return produce_words(
            heap,
            &[head_bitmap_header(1 << slot), size as u64, res.bits()],
        );
    }

    let mut ix = 0;
    let mut d = 0;
    let mut vp = hxns[ix].hx;
    let mut v = hxns[ix + hxns[ix].skip].hx;
    debug_assert!(vp > v);
    let mut slot = maskval(vp, d);
    while slot == maskval(v, d) {
        stack.push(1 << slot);
        d += 1;
        slot = maskval(vp, d);
    }
    let mut res = hxns[ix].val;
    if hxns[ix].skip > 1 {
        res = collision_chain(res, vp, d, heap)?;
    }
    stack.push(res.bits());
    stack.push(1 << slot);

    for _ in 0..n - 2 {
        let mut hdr = stack.pop().expect("HAMT build stack");
        ix += hxns[ix].skip;
        let vn = hxns[ix + hxns[ix].skip].hx;
        let dn = cdepth(v, vn);
        debug_assert!(v > vn);
        res = hxns[ix].val;
        if hxns[ix].skip > 1 {
            res = collision_chain(res, v, d.max(dn), heap)?;
        }
        if d < dn {
            while d < dn {
                stack.push(hdr | 1 << maskval(v, d));
                d += 1;
                hdr = 0;
            }
            stack.push(res.bits());
            stack.push(1 << maskval(v, d));
        } else if d == dn {
            stack.push(res.bits());
            stack.push(hdr | 1 << maskval(v, d));
        } else {
            while dn != d {
                hdr |= 1 << maskval(v, d);
                let sz = (hdr as u16).count_ones() as usize;
                res = stack_node(&[node_bitmap_header(hdr)], res, sz, &mut stack, heap)?;
                hdr = stack.pop().expect("HAMT build stack");
                d -= 1;
            }
            stack.push(res.bits());
            stack.push(hdr);
        }
        vp = v;
        v = vn;
        d = dn;
    }

    let mut dn = cdepth(vp, v);
    ix += hxns[ix].skip;
    res = hxns[ix].val;
    if hxns[ix].skip > 1 {
        res = collision_chain(res, v, dn, heap)?;
    }
    let mut hdr = stack.pop().expect("HAMT build stack");
    while dn > 0 {
        hdr |= 1 << maskval(v, dn);
        let sz = (hdr as u16).count_ones() as usize;
        res = stack_node(&[node_bitmap_header(hdr)], res, sz, &mut stack, heap)?;
        hdr = stack.pop().expect("HAMT build stack");
        dn -= 1;
    }
    hdr |= 1 << maskval(v, dn);
    let sz = (hdr as u16).count_ones() as usize;
    let header = if hdr == 0xffff {
        HEAD_ARRAY_HEADER
    } else {
        head_bitmap_header(hdr)
    };
    let root = stack_node(&[header, size as u64], res, sz, &mut stack, heap)?;
    debug_assert!(stack.is_empty());
    Ok(root)
}

/// Build a HAMT from parallel key and value arrays (more than `MAP_SMALL_MAP_LIMIT`
/// entries), plus an optional extra pair. Returns `None` if `reject_dupkeys` is set
/// and a key repeats; otherwise later entries win.
///
/// Port of erts/emulator/beam/erl_map.c:712-759 (erts_hashmap_from_ks_and_vs_extra), OTP-29.1.1.
pub fn hashmap_from_ks_and_vs_extra<H: HeapAlloc + ?Sized>(
    ks: &[Term],
    vs: &[Term],
    extra: Option<(Term, Term)>,
    reject_dupkeys: bool,
    heap: &mut H,
) -> Result<Option<Term>, TermError> {
    debug_assert_eq!(ks.len(), vs.len());
    let pairs = ks.iter().copied().zip(vs.iter().copied()).chain(extra);
    let mut hxns = hashmap_leaves(
        ExactPairs(pairs, ks.len() + usize::from(extra.is_some())),
        heap,
    )?;
    hashmap_from_unsorted_array(&mut hxns, reject_dupkeys, heap)
}

/// `erts_hashmap_from_ks_and_vs`: later duplicates win.
///
/// Port of erts/emulator/beam/erl_map.h:122, OTP-29.1.1.
pub fn hashmap_from_ks_and_vs<H: HeapAlloc + ?Sized>(
    ks: &[Term],
    vs: &[Term],
    heap: &mut H,
) -> Result<Term, TermError> {
    Ok(hashmap_from_ks_and_vs_extra(ks, vs, None, false, heap)?.expect("duplicates accepted"))
}

struct ExactPairs<I>(I, usize);
impl<I: Iterator<Item = (Term, Term)>> Iterator for ExactPairs<I> {
    type Item = (Term, Term);
    fn next(&mut self) -> Option<Self::Item> {
        let item = self.0.next()?;
        self.1 -= 1;
        Some(item)
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.1, Some(self.1))
    }
}
impl<I: Iterator<Item = (Term, Term)>> ExactSizeIterator for ExactPairs<I> {}

/// Construct an OTP-layout HAMT from distinct pairs; callers handle duplicate keys.
/// This is the shared bulk-construction entry point for `arinsal-maps`.
pub fn build_hamt_from_unique<H: HeapAlloc + ?Sized>(
    entries: &[(Term, Term)],
    heap: &mut H,
) -> Result<Term, TermError> {
    let mut hxns = hashmap_leaves(entries.iter().copied(), heap)?;
    Ok(hashmap_from_unsorted_array(&mut hxns, false, heap)?.expect("duplicates accepted"))
}
