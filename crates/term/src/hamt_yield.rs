//! Yielding HAMT constructors and the reverse map iterator behind `maps:from_list/1`,
//! `maps:from_keys/2`, `maps:keys/1` and `maps:values/1`.
//!
//! erts builds these with functions transformed by YCF (Yielding C Fun,
//! erts/lib_src/yielding_c_fun): every loop body costs one unit of the `ycf_nr_of_reductions`
//! counter and the function yields when the counter reaches zero or below. Rust has no stackful
//! coroutines, so each YCF function is an explicit state machine whose phases are the loop
//! tests and bodies; a `tick!` is the generated `YCF_CONSUME_REDS(1)` plus yield check.

use crate::hamt::{
    HAMT_MAX_LEVEL, HEAD_ARRAY_HEADER, HxNode, boxed_object_words, cdepth, child_range,
    head_bitmap_header, leaf_key, maskval, node_bitmap_header, produce_words,
};
use crate::{HeapAlloc, Term, TermError, TermKind};
use std::cell::Cell;
use std::cmp::Ordering;

/// Consume `$n` reductions and leave the machine in phase `$next`; yields when the budget is
/// used up. Port of the code YCF generates for `YCF_CONSUME_REDS` (ycf_yield_fun.c:592-610).
macro_rules! tick {
    ($self:ident, $reds:ident, $n:expr, $next:expr) => {{
        $self.ph = $next;
        *$reds -= $n as i64;
        if *$reds <= 0 {
            return Ok(None);
        }
        continue;
    }};
}

thread_local! {
    /// `esdp->rand_state`: per-scheduler counter hashed by `erts_sched_local_random`.
    static RAND_STATE: Cell<u64> = const { Cell::new(0) };
}

// Port of erts/emulator/beam/erl_process.h:3038 (erts_sched_local_random_hash_64_to_32_shift),
// OTP-29.1.1.
fn random_hash_64_to_32(mut key: u64) -> u32 {
    key = (!key).wrapping_add(key << 18);
    key ^= key >> 31;
    key = key.wrapping_add(key << 2).wrapping_add(key << 4);
    key ^= key >> 11;
    key = key.wrapping_add(key << 6);
    key ^= key >> 22;
    key as u32
}

// Port of erts/emulator/beam/erl_process.h:3054 (erts_sched_local_random), OTP-29.1.1.
fn sched_local_random(additional_seed: u64) -> u32 {
    RAND_STATE.with(|state| {
        let mut value = state.get();
        if value == 0 {
            // erl_process.c:6083 seeds from the scheduler's own address.
            let address = std::ptr::from_ref(state) as usize as u64;
            value = address.wrapping_add(address << 32);
        }
        state.set(value.wrapping_add(1));
        random_hash_64_to_32(value.wrapping_add(additional_seed))
    })
}

/// Which `erts_qsort` comparison a sort uses.
#[derive(Clone, Copy)]
enum SortKey {
    /// `hxnodecmp`: descending swizzled hash.
    Hash,
    /// `hxnodecmpkey`: `CMP_TERM` order of the leaf keys.
    Key,
}

// Port of erts/emulator/beam/erl_map.c:1160-1186 (hxnodecmpkey, hxnodecmp), OTP-29.1.1.
fn node_cmp(kind: SortKey, a: &HxNode, b: &HxNode) -> i32 {
    match kind {
        SortKey::Hash => match a.hx.cmp(&b.hx) {
            Ordering::Less => 1,
            Ordering::Equal => 0,
            Ordering::Greater => -1,
        },
        SortKey::Key => {
            match crate::heap::exact_flat_key_cmp(leaf_key(a.val), leaf_key(b.val), false) {
                Ordering::Less => -1,
                Ordering::Equal => 0,
                Ordering::Greater => 1,
            }
        }
    }
}

/// One pending `erts_qsort_helper(base, n, seed)` call.
#[derive(Clone, Copy)]
struct Frame {
    base: usize,
    n: usize,
    seed: u32,
}

#[derive(Clone, Copy)]
enum PartPhase {
    FastTest,
    FastBody,
    SlowTest,
    SlowBody,
}

/// `erts_qsort_partion_array` in flight.
struct Partition {
    frame: Frame,
    /// Absolute index of the first item of the greater-than-pivot part.
    second_part_start: usize,
    curr: usize,
    pivot_part_start: usize,
    pivot_part_end: usize,
    last_part_start: usize,
    ph: PartPhase,
}

/// Yielding `erts_qsort` over the hash records.
///
/// Port of erts/emulator/beam/utils.c:3459-3690 (erts_qsort, erts_qsort_helper,
/// erts_qsort_partion_array, erts_qsort_insertion_sort), OTP-29.1.1, as yielded by YCF
/// (erts/emulator/Makefile.in UTILS_YCF_FLAGS: `-f` on erts_qsort, erts_qsort_helper and
/// erts_qsort_partion_array; the swap and the insertion sort do not yield).
///
/// Recursion is an explicit stack of pending helper calls, run depth first in the order of the
/// two recursive calls. The pivot hash of utils.c:3523 mixes the addresses of the comparison
/// function and the array; here the array offset and the comparison kind stand in for them.
struct Qsort {
    kind: SortKey,
    stack: Vec<Frame>,
    part: Option<Partition>,
}

impl Qsort {
    fn new(kind: SortKey, n: usize) -> Self {
        // utils.c:3687: the improved seed is only worth its cost for big arrays.
        let seed = if n > 128 { sched_local_random(0) } else { 1 };
        Self {
            kind,
            stack: vec![Frame { base: 0, n, seed }],
            part: None,
        }
    }

    /// Run until sorted (`true`) or out of reductions (`false`).
    fn step(&mut self, nodes: &mut [HxNode], reds: &mut i64) -> bool {
        loop {
            if self.part.is_some() {
                match self.partition_step(nodes, reds) {
                    None => return false,
                    Some((start, end)) => {
                        let part = self.part.take().expect("partition in flight");
                        let frame = part.frame;
                        let first = Frame {
                            base: frame.base,
                            n: start - frame.base,
                            seed: frame.seed.wrapping_add(1),
                        };
                        let second = Frame {
                            base: end,
                            n: frame.base + frame.n - end,
                            seed: frame.seed.wrapping_add(1),
                        };
                        // The first recursive call runs first.
                        self.stack.push(second);
                        self.stack.push(first);
                    }
                }
                continue;
            }
            let Some(frame) = self.stack.pop() else {
                return true;
            };
            if frame.n <= 16 {
                insertion_sort(self.kind, &mut nodes[frame.base..frame.base + frame.n]);
                // YCF_CONSUME_REDS(nr_of_items * erts_fit_in_bits_int64(nr_of_items) * 2)
                let bits = (u64::BITS - (frame.n as u64).leading_zeros()) as i64;
                *reds -= frame.n as i64 * bits * 2;
                if *reds <= 0 {
                    return false;
                }
                continue;
            }
            self.part = Some(self.partition_start(nodes, frame));
        }
    }

    // utils.c:3495-3530: pick the pivot, move it first and enter the fast path.
    fn partition_start(&self, nodes: &mut [HxNode], frame: Frame) -> Partition {
        let tag = match self.kind {
            SortKey::Hash => 1,
            SortKey::Key => 2,
        };
        let pivot_index = (random_hash_64_to_32(
            u64::from(frame.seed)
                .wrapping_add(tag)
                .wrapping_add(frame.base as u64)
                .wrapping_sub(frame.n as u64),
        ) as usize)
            % frame.n;
        swap(nodes, frame.base, frame.base + pivot_index);
        Partition {
            frame,
            second_part_start: frame.base + frame.n,
            curr: frame.base + 1,
            pivot_part_start: 0,
            pivot_part_end: 0,
            last_part_start: 0,
            ph: PartPhase::FastTest,
        }
    }

    /// Returns the pivot part `[start, end)` when the partition is done, `None` on a yield.
    fn partition_step(&mut self, nodes: &mut [HxNode], reds: &mut i64) -> Option<(usize, usize)> {
        let kind = self.kind;
        let p = self.part.as_mut().expect("partition in flight");
        let base = p.frame.base;
        loop {
            match p.ph {
                PartPhase::FastTest => {
                    if p.curr != p.second_part_start {
                        p.ph = PartPhase::FastBody;
                        *reds -= 1;
                        if *reds <= 0 {
                            return None;
                        }
                    } else {
                        // Fast path succeeded: no item equals the pivot.
                        let start = p.second_part_start - 1;
                        swap(nodes, base, start);
                        return Some((start, p.second_part_start));
                    }
                }
                PartPhase::FastBody => {
                    let c = node_cmp(kind, &nodes[p.curr], &nodes[base]);
                    if c < 0 {
                        p.curr += 1;
                        p.ph = PartPhase::FastTest;
                    } else if c == 0 {
                        // More than one pivot item: slow path (utils.c:3556).
                        p.pivot_part_start = p.curr - 1;
                        p.pivot_part_end = p.curr + 1;
                        p.last_part_start = p.second_part_start;
                        swap(nodes, base, p.pivot_part_start);
                        p.ph = PartPhase::SlowTest;
                    } else {
                        p.second_part_start -= 1;
                        swap(nodes, p.curr, p.second_part_start);
                        p.ph = PartPhase::FastTest;
                    }
                }
                PartPhase::SlowTest => {
                    if p.pivot_part_end != p.last_part_start {
                        p.ph = PartPhase::SlowBody;
                        *reds -= 1;
                        if *reds <= 0 {
                            return None;
                        }
                    } else {
                        return Some((p.pivot_part_start, p.pivot_part_end));
                    }
                }
                PartPhase::SlowBody => {
                    let c = node_cmp(kind, &nodes[p.pivot_part_end], &nodes[p.pivot_part_end - 1]);
                    if c == 0 {
                        p.pivot_part_end += 1;
                    } else if c < 0 {
                        swap(nodes, p.pivot_part_start, p.pivot_part_end);
                        p.pivot_part_start += 1;
                        p.pivot_part_end += 1;
                    } else {
                        p.last_part_start -= 1;
                        swap(nodes, p.pivot_part_end, p.last_part_start);
                    }
                    p.ph = PartPhase::SlowTest;
                }
            }
        }
    }
}

// Port of erts/emulator/beam/utils.c:3466-3484 (erts_qsort_swap), OTP-29.1.1.
fn swap(nodes: &mut [HxNode], i: usize, j: usize) {
    if i != j {
        nodes.swap(i, j);
    }
}

// Port of erts/emulator/beam/utils.c:3590-3618 (erts_qsort_insertion_sort), OTP-29.1.1.
fn insertion_sort(kind: SortKey, nodes: &mut [HxNode]) {
    if nodes.len() < 2 {
        return;
    }
    let end = nodes.len() - 1;
    let mut unsorted_start = 0;
    while unsorted_start < end {
        let mut smallest_so_far = unsorted_start;
        let mut curr = smallest_so_far + 1;
        while curr <= end {
            if node_cmp(kind, &nodes[curr], &nodes[smallest_so_far]) < 0 {
                smallest_so_far = curr;
            }
            curr += 1;
        }
        if smallest_so_far != unsorted_start {
            swap(nodes, unsorted_start, smallest_so_far);
        }
        unsorted_start += 1;
    }
}

/// Phases of `hashmap_from_unsorted_array` (loop tests and bodies).
#[derive(Clone, Copy)]
enum UnsortedPhase {
    Sort1,
    OuterTest,
    OuterBody,
    JxTest,
    JxBody,
    Sort2,
    RegionTest,
    RegionBody,
    DupTest,
    DupBody,
    RegionEnd,
}

/// `hashmap_from_unsorted_array` with `reject_dupkeys == 0`, the only form the yielding
/// constructors use.
///
/// Port of erts/emulator/beam/erl_map.c:774-855 (hashmap_from_unsorted_array), OTP-29.1.1.
struct Unsorted {
    ph: UnsortedPhase,
    sort: Option<Qsort>,
    ix: usize,
    jx: usize,
    lx: usize,
    cx: usize,
}

enum UnsortedOut {
    Yield,
    /// Number of unique records left in the array prefix.
    Unique(usize),
}

impl Unsorted {
    fn step(&mut self, hxns: &mut [HxNode], reds: &mut i64) -> UnsortedOut {
        let n = hxns.len();
        loop {
            match self.ph {
                UnsortedPhase::Sort1 => {
                    let sort = self
                        .sort
                        .get_or_insert_with(|| Qsort::new(SortKey::Hash, n));
                    if !sort.step(hxns, reds) {
                        return UnsortedOut::Yield;
                    }
                    self.sort = None;
                    self.ix = 0;
                    self.cx = 0;
                    self.ph = UnsortedPhase::OuterTest;
                }
                UnsortedPhase::OuterTest => {
                    if self.ix < n - 1 {
                        self.ph = UnsortedPhase::OuterBody;
                        *reds -= 1;
                        if *reds <= 0 {
                            return UnsortedOut::Yield;
                        }
                    } else {
                        if self.ix < n {
                            hxns[self.cx].hx = hxns[self.ix].hx;
                            hxns[self.cx].val = hxns[self.ix].val;
                            self.cx += 1;
                        }
                        return UnsortedOut::Unique(self.cx);
                    }
                }
                UnsortedPhase::OuterBody => {
                    let ix = self.ix;
                    if hxns[ix].hx == hxns[ix + 1].hx {
                        // Find the region of equal hash values.
                        self.jx = ix + 2;
                        self.ph = UnsortedPhase::JxTest;
                    } else {
                        if ix > self.cx {
                            hxns[self.cx].hx = hxns[ix].hx;
                            hxns[self.cx].val = hxns[ix].val;
                        }
                        self.cx += 1;
                        self.ix += 1;
                        self.ph = UnsortedPhase::OuterTest;
                    }
                }
                UnsortedPhase::JxTest => {
                    if self.jx < n && hxns[self.ix].hx == hxns[self.jx].hx {
                        self.ph = UnsortedPhase::JxBody;
                        *reds -= 1;
                        if *reds <= 0 {
                            return UnsortedOut::Yield;
                        }
                    } else {
                        self.ph = UnsortedPhase::Sort2;
                    }
                }
                UnsortedPhase::JxBody => {
                    self.jx += 1;
                    self.ph = UnsortedPhase::JxTest;
                }
                UnsortedPhase::Sort2 => {
                    // Resort the region by key instead of hash value.
                    let (ix, jx) = (self.ix, self.jx);
                    let sort = self
                        .sort
                        .get_or_insert_with(|| Qsort::new(SortKey::Key, jx - ix));
                    if !sort.step(&mut hxns[ix..jx], reds) {
                        return UnsortedOut::Yield;
                    }
                    self.sort = None;
                    self.ph = UnsortedPhase::RegionTest;
                }
                UnsortedPhase::RegionTest => {
                    if self.ix < self.jx {
                        self.ph = UnsortedPhase::RegionBody;
                        *reds -= 1;
                        if *reds <= 0 {
                            return UnsortedOut::Yield;
                        }
                    } else {
                        self.ix = self.jx;
                        self.ph = UnsortedPhase::OuterTest;
                    }
                }
                UnsortedPhase::RegionBody => {
                    self.lx = self.ix;
                    self.ph = UnsortedPhase::DupTest;
                }
                UnsortedPhase::DupTest => {
                    self.ix += 1;
                    if self.ix < self.jx
                        && crate::exact_eq(leaf_key(hxns[self.ix].val), leaf_key(hxns[self.lx].val))
                    {
                        self.ph = UnsortedPhase::DupBody;
                        *reds -= 1;
                        if *reds <= 0 {
                            return UnsortedOut::Yield;
                        }
                    } else {
                        self.ph = UnsortedPhase::RegionEnd;
                    }
                }
                UnsortedPhase::DupBody => {
                    if hxns[self.ix].i > hxns[self.lx].i {
                        self.lx = self.ix;
                    }
                    self.ph = UnsortedPhase::DupTest;
                }
                UnsortedPhase::RegionEnd => {
                    hxns[self.cx].hx = hxns[self.lx].hx;
                    hxns[self.cx].val = hxns[self.lx].val;
                    self.cx += 1;
                    self.ph = UnsortedPhase::RegionTest;
                }
            }
        }
    }
}

#[derive(Clone, Copy)]
enum SortedPhase {
    OutTest,
    OutBody,
    JTest,
    JBody,
    ForTest,
    ForBody,
    ForEnd,
}

/// `hashmap_from_sorted_unique_array`: collision nodes and skip counts.
///
/// Port of erts/emulator/beam/erl_map.c:857-911, OTP-29.1.1.
struct SortedUnique {
    ph: SortedPhase,
    ix: usize,
    jx: usize,
    elems: usize,
    i: usize,
    n_colliders: usize,
    words: Vec<u64>,
}

impl SortedUnique {
    fn new() -> Self {
        Self {
            ph: SortedPhase::OutTest,
            ix: 0,
            jx: 0,
            elems: 1,
            i: 0,
            n_colliders: 0,
            words: Vec::new(),
        }
    }

    /// Returns the element count for the chunked stage once the array is annotated.
    fn step<H: HeapAlloc + ?Sized>(
        &mut self,
        hxns: &mut [HxNode],
        reds: &mut i64,
        heap: &mut H,
    ) -> Result<Option<usize>, TermError> {
        let n = hxns.len();
        loop {
            match self.ph {
                SortedPhase::OutTest => {
                    if self.ix < n - 1 {
                        self.ph = SortedPhase::OutBody;
                        *reds -= 1;
                        if *reds <= 0 {
                            return Ok(None);
                        }
                    } else {
                        return Ok(Some(self.elems));
                    }
                }
                SortedPhase::OutBody => {
                    let ix = self.ix;
                    if hxns[ix].hx == hxns[ix + 1].hx {
                        self.jx = ix + 2;
                        self.ph = SortedPhase::JTest;
                    } else {
                        hxns[ix].skip = 1;
                        self.elems += 1;
                        self.ix += 1;
                        self.ph = SortedPhase::OutTest;
                    }
                }
                SortedPhase::JTest => {
                    if self.jx < n && hxns[self.ix].hx == hxns[self.jx].hx {
                        tick!(self, reds, 1, SortedPhase::JBody);
                    }
                    self.n_colliders = self.jx - self.ix;
                    self.words.clear();
                    self.words.push((self.n_colliders as u64) << 6);
                    self.i = 0;
                    self.ph = SortedPhase::ForTest;
                }
                SortedPhase::JBody => {
                    self.jx += 1;
                    self.ph = SortedPhase::JTest;
                }
                SortedPhase::ForTest => {
                    if self.i < self.n_colliders {
                        tick!(self, reds, 1, SortedPhase::ForBody);
                    }
                    self.ph = SortedPhase::ForEnd;
                }
                SortedPhase::ForBody => {
                    self.words.push(hxns[self.ix + self.i].val.bits());
                    self.i += 1;
                    self.ph = SortedPhase::ForTest;
                }
                SortedPhase::ForEnd => {
                    hxns[self.ix].val = produce_words(heap, &self.words)?;
                    hxns[self.ix].skip = self.n_colliders;
                    self.ix = self.jx;
                    if self.ix < n {
                        self.elems += 1;
                    }
                    self.ph = SortedPhase::OutTest;
                }
            }
        }
    }
}

#[derive(Clone, Copy)]
enum ChunkPhase {
    Init,
    OneTest,
    OneBody,
    L1Test,
    L1Body,
    AfterL1,
    L2Test,
    L2Body,
    PushFirst,
    ElemsTest,
    ElemsBody,
    L4Test,
    L4Body,
    Branch,
    L5Test,
    L5Body,
    L6Test,
    L6Body,
    L7Test,
    L7Body,
    L6End,
    ElemEnd,
    AfterElems,
    L8Test,
    L8Body,
    AfterL8,
    L9Test,
    L9Body,
    L10Test,
    L10Body,
    L9End,
    RootStart,
    L11Test,
    L11Body,
    RootEnd,
}

/// `hashmap_from_chunked_array`: builds the trie bottom-up on an explicit stack.
///
/// Port of erts/emulator/beam/erl_map.c:919-1158, OTP-29.1.1. Where C allocates a node and then
/// fills it inside a `while (sz--)` loop that can yield, the words are gathered first and the
/// node is allocated when the loop ends (nothing else allocates in between).
struct Chunked {
    ph: ChunkPhase,
    /// Records in the annotated array.
    n: usize,
    /// Number of leaves, stored in the root.
    size: usize,
    ix: usize,
    d: usize,
    dn: usize,
    dc: usize,
    wat: usize,
    slot: u64,
    v: u64,
    vp: u64,
    vn: u64,
    hdr: u64,
    sz: usize,
    elems: usize,
    res: Term,
    stack: Vec<u64>,
    words: Vec<u64>,
}

impl Chunked {
    fn new(n: usize, size: usize) -> Self {
        Self {
            ph: ChunkPhase::Init,
            n,
            size,
            ix: 0,
            d: 0,
            dn: 0,
            dc: 0,
            wat: 0,
            slot: 0,
            v: 0,
            vp: 0,
            vn: 0,
            hdr: 0,
            sz: 0,
            elems: 0,
            res: Term::NIL,
            stack: Vec::new(),
            words: Vec::new(),
        }
    }

    fn collision_node<H: HeapAlloc + ?Sized>(
        heap: &mut H,
        level_hash: u64,
        dc: usize,
        res: Term,
    ) -> Result<Term, TermError> {
        produce_words(
            heap,
            &[node_bitmap_header(1 << maskval(level_hash, dc)), res.bits()],
        )
    }

    fn pop(&mut self) -> u64 {
        self.stack.pop().expect("HAMT build stack")
    }

    fn step<H: HeapAlloc + ?Sized>(
        &mut self,
        hxns: &[HxNode],
        reds: &mut i64,
        heap: &mut H,
    ) -> Result<Option<Term>, TermError> {
        use ChunkPhase as C;
        let max_level = HAMT_MAX_LEVEL;
        loop {
            match self.ph {
                C::Init => {
                    if self.n == 1 {
                        // Every key shares all HAMT_MAX_LEVEL hash slots.
                        self.res = hxns[0].val;
                        self.v = hxns[0].hx;
                        self.d = max_level - 1;
                        self.ph = C::OneTest;
                    } else {
                        self.ix = 0;
                        self.d = 0;
                        self.vp = hxns[0].hx;
                        self.v = hxns[hxns[0].skip].hx;
                        debug_assert!(self.vp > self.v);
                        self.slot = maskval(self.vp, self.d);
                        self.ph = C::L1Test;
                    }
                }
                C::OneTest => {
                    if self.d > 0 {
                        tick!(self, reds, 1, C::OneBody);
                    }
                    let slot = maskval(self.v, 0);
                    let root = produce_words(
                        heap,
                        &[
                            head_bitmap_header(1 << slot),
                            self.size as u64,
                            self.res.bits(),
                        ],
                    )?;
                    return Ok(Some(root));
                }
                C::OneBody => {
                    self.res = Self::collision_node(heap, self.v, self.d, self.res)?;
                    self.d -= 1;
                    self.ph = C::OneTest;
                }
                C::L1Test => {
                    if self.slot == maskval(self.v, self.d) {
                        tick!(self, reds, 1, C::L1Body);
                    }
                    self.ph = C::AfterL1;
                }
                C::L1Body => {
                    self.stack.push(1 << self.slot);
                    self.d += 1;
                    self.slot = maskval(self.vp, self.d);
                    self.ph = C::L1Test;
                }
                C::AfterL1 => {
                    self.res = hxns[self.ix].val;
                    if hxns[self.ix].skip > 1 {
                        self.dc = max_level - 1;
                        self.ph = C::L2Test;
                    } else {
                        self.ph = C::PushFirst;
                    }
                }
                C::L2Test => {
                    if self.dc > self.d {
                        tick!(self, reds, 1, C::L2Body);
                    }
                    self.ph = C::PushFirst;
                }
                C::L2Body => {
                    self.res = Self::collision_node(heap, self.vp, self.dc, self.res)?;
                    self.dc -= 1;
                    self.ph = C::L2Test;
                }
                C::PushFirst => {
                    self.stack.push(self.res.bits());
                    self.stack.push(1 << self.slot);
                    // Remove first and last elements.
                    self.elems = self.n - 2;
                    self.ph = C::ElemsTest;
                }
                C::ElemsTest => {
                    if self.elems != 0 {
                        self.elems -= 1;
                        tick!(self, reds, 1, C::ElemsBody);
                    }
                    self.ph = C::AfterElems;
                }
                C::ElemsBody => {
                    self.hdr = self.pop();
                    self.ix += hxns[self.ix].skip;
                    // Look at the next value to decide whether a node or subtree is built.
                    self.vn = hxns[self.ix + hxns[self.ix].skip].hx;
                    self.dn = cdepth(self.v, self.vn);
                    debug_assert!(self.v > self.vn);
                    self.res = hxns[self.ix].val;
                    if hxns[self.ix].skip > 1 {
                        self.wat = self.d.max(self.dn);
                        self.dc = max_level - 1;
                        self.ph = C::L4Test;
                    } else {
                        self.ph = C::Branch;
                    }
                }
                C::L4Test => {
                    if self.dc > self.wat {
                        tick!(self, reds, 1, C::L4Body);
                    }
                    self.ph = C::Branch;
                }
                C::L4Body => {
                    self.res = Self::collision_node(heap, self.v, self.dc, self.res)?;
                    self.dc -= 1;
                    self.ph = C::L4Test;
                }
                C::Branch => {
                    if self.d < self.dn {
                        // Next depth is higher (implies collision).
                        self.ph = C::L5Test;
                    } else if self.d == self.dn {
                        // No collisions at all.
                        let bp = 1 << maskval(self.v, self.d);
                        self.stack.push(self.res.bits());
                        self.stack.push(self.hdr | bp);
                        self.ph = C::ElemEnd;
                    } else {
                        // A drop: build nodes and subtree.
                        self.ph = C::L6Test;
                    }
                }
                C::L5Test => {
                    if self.d < self.dn {
                        tick!(self, reds, 1, C::L5Body);
                    }
                    self.slot = maskval(self.v, self.d);
                    self.stack.push(self.res.bits());
                    self.stack.push(1 << self.slot);
                    self.ph = C::ElemEnd;
                }
                C::L5Body => {
                    self.slot = maskval(self.v, self.d);
                    self.stack.push(self.hdr | (1 << self.slot));
                    self.d += 1;
                    self.hdr = 0;
                    self.ph = C::L5Test;
                }
                C::L6Test => {
                    if self.dn != self.d {
                        tick!(self, reds, 1, C::L6Body);
                    }
                    self.stack.push(self.res.bits());
                    self.stack.push(self.hdr);
                    self.ph = C::ElemEnd;
                }
                C::L6Body => {
                    self.slot = maskval(self.v, self.d);
                    // OR the bit position before the size calculation to handle redundant
                    // collisions.
                    self.hdr |= 1 << self.slot;
                    self.sz = (self.hdr as u16).count_ones() as usize;
                    self.words.clear();
                    self.words.push(node_bitmap_header(self.hdr));
                    self.words.push(self.res.bits());
                    self.sz -= 1;
                    self.ph = C::L7Test;
                }
                C::L7Test => {
                    if self.sz != 0 {
                        self.sz -= 1;
                        tick!(self, reds, 1, C::L7Body);
                    }
                    self.ph = C::L6End;
                }
                C::L7Body => {
                    let word = self.pop();
                    self.words.push(word);
                    self.ph = C::L7Test;
                }
                C::L6End => {
                    self.res = produce_words(heap, &self.words)?;
                    // Pop the next hdr; it is pushed back if it is not needed.
                    self.hdr = self.pop();
                    self.d -= 1;
                    self.ph = C::L6Test;
                }
                C::ElemEnd => {
                    self.vp = self.v;
                    self.v = self.vn;
                    self.d = self.dn;
                    self.ph = C::ElemsTest;
                }
                C::AfterElems => {
                    self.dn = cdepth(self.vp, self.v);
                    self.ix += hxns[self.ix].skip;
                    self.res = hxns[self.ix].val;
                    if hxns[self.ix].skip > 1 {
                        self.dc = max_level - 1;
                        self.ph = C::L8Test;
                    } else {
                        self.ph = C::AfterL8;
                    }
                }
                C::L8Test => {
                    if self.dc > self.dn {
                        tick!(self, reds, 1, C::L8Body);
                    }
                    self.ph = C::AfterL8;
                }
                C::L8Body => {
                    self.res = Self::collision_node(heap, self.v, self.dc, self.res)?;
                    self.dc -= 1;
                    self.ph = C::L8Test;
                }
                C::AfterL8 => {
                    self.hdr = self.pop();
                    self.ph = C::L9Test;
                }
                C::L9Test => {
                    if self.dn != 0 {
                        tick!(self, reds, 1, C::L9Body);
                    }
                    self.ph = C::RootStart;
                }
                C::L9Body => {
                    self.slot = maskval(self.v, self.dn);
                    self.hdr |= 1 << self.slot;
                    self.sz = (self.hdr as u16).count_ones() as usize;
                    self.words.clear();
                    self.words.push(node_bitmap_header(self.hdr));
                    self.words.push(self.res.bits());
                    self.sz -= 1;
                    self.ph = C::L10Test;
                }
                C::L10Test => {
                    if self.sz != 0 {
                        self.sz -= 1;
                        tick!(self, reds, 1, C::L10Body);
                    }
                    self.ph = C::L9End;
                }
                C::L10Body => {
                    let word = self.pop();
                    self.words.push(word);
                    self.ph = C::L10Test;
                }
                C::L9End => {
                    self.res = produce_words(heap, &self.words)?;
                    self.hdr = self.pop();
                    self.dn -= 1;
                    self.ph = C::L9Test;
                }
                C::RootStart => {
                    // And finally the root.
                    self.slot = maskval(self.v, self.dn);
                    self.hdr |= 1 << self.slot;
                    self.sz = (self.hdr as u16).count_ones() as usize;
                    self.words.clear();
                    self.words.push(if self.hdr == 0xffff {
                        HEAD_ARRAY_HEADER
                    } else {
                        head_bitmap_header(self.hdr)
                    });
                    self.words.push(self.size as u64);
                    self.words.push(self.res.bits());
                    self.sz -= 1;
                    self.ph = C::L11Test;
                }
                C::L11Test => {
                    if self.sz != 0 {
                        self.sz -= 1;
                        tick!(self, reds, 1, C::L11Body);
                    }
                    self.ph = C::RootEnd;
                }
                C::L11Body => {
                    let word = self.pop();
                    self.words.push(word);
                    self.ph = C::L11Test;
                }
                C::RootEnd => {
                    let root = produce_words(heap, &self.words)?;
                    debug_assert!(self.stack.is_empty());
                    return Ok(Some(root));
                }
            }
        }
    }
}

enum Stage {
    Unsorted(Unsorted),
    SortedUnique(SortedUnique),
    Chunked(Chunked),
}

/// Yielding `hashmap_from_unsorted_array`: sort, compact, annotate collisions, chunk.
///
/// Port of erts/emulator/beam/erl_map.c:774-1158 as transformed by YCF, OTP-29.1.1. All four
/// functions are `-f` (automatic) yielders and cost nothing for the calls between them.
pub struct HashmapBuild {
    hxns: Vec<HxNode>,
    stage: Stage,
}

impl HashmapBuild {
    /// Start building from the leaf records created by [`crate::hashmap_leaves_hashed`].
    pub fn new(hxns: Vec<HxNode>) -> Self {
        assert!(!hxns.is_empty());
        Self {
            hxns,
            stage: Stage::Unsorted(Unsorted {
                ph: UnsortedPhase::Sort1,
                sort: None,
                ix: 0,
                jx: 0,
                lx: 0,
                cx: 0,
            }),
        }
    }

    /// Run with `reds` reductions of budget left (the `ycf_nr_of_reductions` counter, which
    /// may end up negative). Returns the map once complete, `None` after a yield.
    pub fn step<H: HeapAlloc + ?Sized>(
        &mut self,
        reds: &mut i64,
        heap: &mut H,
    ) -> Result<Option<Term>, TermError> {
        loop {
            match &mut self.stage {
                Stage::Unsorted(unsorted) => match unsorted.step(&mut self.hxns, reds) {
                    UnsortedOut::Yield => return Ok(None),
                    UnsortedOut::Unique(cx) if cx > 1 => {
                        self.hxns.truncate(cx);
                        self.stage = Stage::SortedUnique(SortedUnique::new());
                    }
                    UnsortedOut::Unique(_) => {
                        // One item, either because n was 1 or because every key repeats. The
                        // swizzled hash keeps the root slot in its top nibble.
                        let slot = self.hxns[0].hx >> ((HAMT_MAX_LEVEL - 1) * 4);
                        return produce_words(
                            heap,
                            &[head_bitmap_header(1 << slot), 1, self.hxns[0].val.bits()],
                        )
                        .map(Some);
                    }
                },
                Stage::SortedUnique(sorted) => match sorted.step(&mut self.hxns, reds, heap)? {
                    None => return Ok(None),
                    Some(elems) => {
                        let size = self.hxns.len();
                        self.stage = Stage::Chunked(Chunked::new(elems, size));
                    }
                },
                Stage::Chunked(chunked) => return chunked.step(&self.hxns, reds, heap),
            }
        }
    }
}

/// Backwards walk over a hashmap's entries, so that consing each one onto a list yields the
/// entries in `maps:to_list/1` order.
///
/// Port of erts/emulator/beam/erl_map.c:2337-2420 (hashmap_iterator_init with `reverse`,
/// hashmap_iterator_prev), OTP-29.1.1.
pub struct MapReverseIter {
    /// Node and the index of the child visited last (one past the first child to visit).
    nodes: Vec<(Term, usize)>,
}

impl MapReverseIter {
    /// Start at the end of a hashmap; `None` for any other term.
    pub fn new(map: Term) -> Option<Self> {
        if map.classify() != TermKind::Map || !map.is_hashmap() {
            return None;
        }
        let mut iter = Self { nodes: Vec::new() };
        iter.push_node(map);
        Some(iter)
    }

    fn push_node(&mut self, node: Term) {
        // SAFETY: the map and its nodes stay live while the call is trapped (GC is disabled).
        let end = unsafe {
            let header = node.header().expect("HAMT node");
            boxed_object_words(header, node.raw_ptr())
        };
        self.nodes.push((node, end));
    }
}

impl Iterator for MapReverseIter {
    type Item = (Term, Term);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let (node, idx) = *self.nodes.last()?;
            let header = node.header().expect("HAMT node");
            let first = child_range(header, 0).start;
            if idx <= first {
                self.nodes.pop();
                continue;
            }
            self.nodes.last_mut().expect("node").1 = idx - 1;
            // SAFETY: idx - 1 is an initialized child slot of a live node.
            let child = Term(unsafe { *node.raw_ptr().add(idx - 1) });
            if child.classify() == TermKind::List {
                // SAFETY: HAMT leaves are two-word cons cells.
                return unsafe { child.cons_ref() };
            }
            self.push_node(child);
        }
    }
}
