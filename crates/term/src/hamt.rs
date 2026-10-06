//! Read-only HAMT traversal and the shared term-level bulk constructor.
use crate::{HeapAlloc, MAP, Term, TermError, TermKind, internal_hash};
use smallvec::SmallVec;

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
        | crate::MAGIC_REF
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
        | crate::MAGIC_REF
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
impl Iterator for PairIter {
    type Item = (Term, Term);
    fn next(&mut self) -> Option<Self::Item> {
        if !self.map.is_hashmap() && self.mode == PairIterMode::Pairs {
            // SAFETY: the map and its key tuple remain live during iteration.
            unsafe {
                let ptr = self.map.raw_ptr();
                let len = *ptr.add(1) as usize;
                if self.flat_index == len {
                    return None;
                }
                let keys = Term(*ptr.add(2));
                let i = self.flat_index;
                self.flat_index += 1;
                return Some((Term(*keys.raw_ptr().add(i + 1)), Term(*ptr.add(i + 3))));
            }
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

fn slot(key: Term, level: usize) -> usize {
    ((internal_hash(key) >> (level * 4)) & 15) as usize
}

enum Tree {
    Leaf(Term, Term),
    Branch {
        root: bool,
        size: usize,
        children: Vec<(usize, Tree)>,
    },
    Collision(Vec<Tree>),
}
impl Tree {
    fn words(&self) -> usize {
        match self {
            Self::Leaf(_, _) => 2,
            Self::Branch { root, children, .. } => {
                1 + usize::from(*root)
                    + children.len()
                    + children
                        .iter()
                        .map(|(_, child)| child.words())
                        .sum::<usize>()
            }
            Self::Collision(children) => {
                1 + children.len() + children.iter().map(Self::words).sum::<usize>()
            }
        }
    }
    // Port of erts/emulator/beam/erl_map.c:857-1158, OTP-29.1.1.
    unsafe fn emit(&self, next: &mut *mut u64) -> Term {
        match self {
            Self::Leaf(key, value) => {
                let ptr = *next;
                // SAFETY: words() reserves two words for this leaf.
                unsafe {
                    *ptr = key.bits();
                    *ptr.add(1) = value.bits();
                    *next = ptr.add(2);
                }
                Term::from_ptr(ptr, 1)
            }
            Self::Branch {
                root,
                size,
                children,
            } => {
                let terms: Vec<_> = children
                    .iter()
                    .map(|(_, child)| {
                        // SAFETY: the tree's total word count was reserved.
                        unsafe { child.emit(next) }
                    })
                    .collect();
                let ptr = *next;
                let bitmap = children.iter().fold(0u16, |mask, (i, _)| mask | 1 << i);
                let kind = if *root && bitmap == u16::MAX {
                    2
                } else if *root {
                    3
                } else {
                    1
                };
                let offset = 1 + usize::from(*root);
                // SAFETY: this branch's header and child slots were reserved.
                unsafe {
                    *ptr = MAP | (kind << 6) | (u64::from(*root) << 8) | ((bitmap as u64) << 16);
                    if *root {
                        *ptr.add(1) = *size as u64;
                    }
                    for (i, child) in terms.iter().enumerate() {
                        *ptr.add(offset + i) = child.bits();
                    }
                    *next = ptr.add(offset + terms.len());
                }
                Term::from_ptr(ptr, 2)
            }
            Self::Collision(children) => {
                let terms: Vec<_> = children
                    .iter()
                    .map(|child| {
                        // SAFETY: the tree's total word count was reserved.
                        unsafe { child.emit(next) }
                    })
                    .collect();
                let ptr = *next;
                // SAFETY: this collision tuple's words were reserved.
                unsafe {
                    *ptr = (terms.len() as u64) << 6;
                    for (i, child) in terms.iter().enumerate() {
                        *ptr.add(1 + i) = child.bits();
                    }
                    *next = ptr.add(1 + terms.len());
                }
                Term::from_ptr(ptr, 2)
            }
        }
    }
}

fn build(entries: &[(Term, Term)], level: usize, root: bool) -> Tree {
    // Port of erts/emulator/beam/erl_map.c:857-1158, OTP-29.1.1.
    if level == 16 {
        let mut sorted = entries.to_vec();
        sorted.sort_by(|a, b| crate::heap::exact_flat_key_cmp(a.0, b.0, false));
        return Tree::Collision(
            sorted
                .into_iter()
                .map(|(key, value)| Tree::Leaf(key, value))
                .collect(),
        );
    }
    let mut buckets: [Vec<(Term, Term)>; 16] = std::array::from_fn(|_| Vec::new());
    for &entry in entries {
        buckets[slot(entry.0, level)].push(entry);
    }
    let children = buckets
        .into_iter()
        .enumerate()
        .filter_map(|(i, bucket)| match bucket.len() {
            0 => None,
            1 => Some((i, Tree::Leaf(bucket[0].0, bucket[0].1))),
            _ => Some((i, build(&bucket, level + 1, false))),
        })
        .collect();
    Tree::Branch {
        root,
        size: entries.len(),
        children,
    }
}

/// Construct an OTP-layout HAMT from distinct pairs; callers handle duplicate keys.
/// This is the shared bulk-construction entry point for `arinsal-maps`.
pub fn build_hamt_from_unique<H: HeapAlloc + ?Sized>(
    entries: &[(Term, Term)],
    heap: &mut H,
) -> Result<Term, TermError> {
    let tree = build(entries, 0, true);
    let ptr = heap.alloc(tree.words()).ok_or(TermError::HeapFull)?;
    let mut next = ptr;
    // SAFETY: the allocation covers exactly tree.words() words.
    Ok(unsafe { tree.emit(&mut next) })
}
